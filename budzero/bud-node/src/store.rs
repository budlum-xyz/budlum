//! B.U.D. Content Store - content-addressed storage layer.
//!
//! Implements the `ContentStore` trait for storing and retrieving
//! content chunks by their `ContentId`. `MemoryContentStore` remains the
//! bounded test backend; `FileContentStore` is the durable backend used by a
//! node. Both implementations verify the content address, enforce the same
//! chunk and byte limits, and expose the same Bitswap surface.
//!
//! # Data Sovereignty Rule (plan §0.5)
//!
//! Any node can independently compute `ContentId` from raw chunk
//! bytes. No "Budlum Inc. indexer" or centralized service is
//! required. The store is fully permissionless.

use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// A content identifier - 32-byte hash of the chunk data.
/// Mirrors `budlum_core::storage::content_id::ContentId` but is
/// Self-contained so this crate can be used independently.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    /// Compute the `ContentId` of a chunk. Same definition as
    /// `budlum-core`: SHA-256 over length-prefixed fields. Each field is
    /// a u64 little-endian length, then the bytes. Fields: the
    /// `BDLM_CONTENT_V1` tag, then the chunk.
    pub fn of(chunk: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::default();
        for field in [&b"BDLM_CONTENT_V1"[..], chunk] {
            hasher.update((field.len() as u64).to_le_bytes());
            hasher.update(field);
        }
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        ContentId(id)
    }

    /// Hex representation for logging and DHT keys.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for ContentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cid:{}", &self.to_hex()[..16])
    }
}

/// Errors from the content store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("content not found: {0}")]
    NotFound(ContentId),
    #[error("content integrity mismatch: expected {expected}, got {actual}")]
    IntegrityMismatch {
        expected: ContentId,
        actual: ContentId,
    },
    #[error("store is read-only")]
    ReadOnly,
    #[error("response cid does not match the requested cid: wanted {wanted}, got {got}")]
    UnexpectedCid { wanted: ContentId, got: ContentId },
    #[error("chunk of {len} bytes exceeds the limit of {max} bytes")]
    TooLarge { len: usize, max: usize },
    #[error("internal error: {0}")]
    Internal(String),
}

/// Trait for content-addressed storage backends.
///
/// All implementations MUST verify content integrity on `put`:
/// The provided `ContentId` must match `ContentId::of(data)`.
/// A malicious peer must not store data under a wrong CID.
pub trait ContentStore: Send + Sync {
    /// Store a chunk. Returns `Err(StoreError::IntegrityMismatch)` if
    /// The data does not match the claimed CID.
    fn put(&self, id: ContentId, data: Vec<u8>) -> Result<(), StoreError>;

    /// Retrieve a chunk by CID. Returns `Err(StoreError::NotFound)` if
    /// The chunk is not in the store.
    fn get(&self, id: &ContentId) -> Result<Vec<u8>, StoreError>;

    /// Physically delete a chunk from the store (Constitution).
    fn delete(&self, id: &ContentId) -> Result<(), StoreError>;

    /// Check if a chunk exists in the store.
    fn has(&self, id: &ContentId) -> bool;

    /// List all CIDs in the store (for DHT provider announcements).
    fn list_cids(&self) -> Vec<ContentId>;

    /// Total number of chunks stored.
    fn len(&self) -> usize;

    /// Total bytes of chunk data stored.
    fn bytes(&self) -> usize;

    /// Whether the store is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Largest chunk the store accepts: 16 MiB, the `MAX_CHUNK_SIZE` of
/// `storage_params.rs` and the bitswap message limit.
const MAX_CHUNK_BYTES: usize = 16 * 1024 * 1024;

/// Default chunk size (256 KiB), used to derive the default byte budget.
const DEFAULT_CHUNK_BYTES: usize = 256 * 1024;

/// What the memory store holds. One lock covers all three fields, so the byte
/// count and the eviction order never disagree with the map.
#[derive(Default)]
struct StoreState {
    chunks: BTreeMap<ContentId, Vec<u8>>,
    /// Insertion order, oldest first. Eviction pops from the front.
    order: VecDeque<ContentId>,
    /// Sum of the chunk lengths in `chunks`.
    bytes: usize,
}

/// In-memory content store.
///
/// Suitable for testing, devnet, and short-lived nodes. Data is lost
/// on process exit. Production nodes use [`FileContentStore`] instead.
///
/// Thread-safe via `RwLock`. Read operations (`get`, `has`) acquire
/// A shared lock; writes (`put`) acquire an exclusive lock.
///
/// The store is bounded in chunks and in bytes. A chunk larger than
/// `MAX_CHUNK_BYTES` is refused, and when either bound is reached the
/// oldest inserted chunks are evicted first.
#[derive(Clone)]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring wave.
pub struct MemoryContentStore {
    inner: Arc<RwLock<StoreState>>,
    /// Maximum number of chunks to store.
    max_capacity: usize,
    /// Maximum total bytes of chunk data.
    max_bytes: usize,
}

impl MemoryContentStore {
    /// Create a new empty store with the given chunk capacity. The byte budget
    /// is that many default-size (256 KiB) chunks.
    pub fn new(max_capacity: usize) -> Self {
        // An overflow means "more than any machine has": no byte bound.
        let max_bytes = max_capacity.saturating_mul(DEFAULT_CHUNK_BYTES);
        Self::with_limits(max_capacity, max_bytes)
    }

    /// Create a new empty store bounded by chunk count and total bytes.
    fn with_limits(max_capacity: usize, max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(StoreState::default())),
            max_capacity,
            max_bytes,
        }
    }

    /// Create a store with default capacity (10,000 chunks, at most 2.5 GiB
    /// of data: 256 KiB per chunk on average).
    /// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring wave.
    pub fn with_default_capacity() -> Self {
        Self::new(10_000)
    }

    /// The largest single chunk this store accepts.
    fn chunk_limit(&self) -> usize {
        MAX_CHUNK_BYTES.min(self.max_bytes)
    }

    /// Would adding `len` bytes break the chunk or byte bound?
    fn over_budget(&self, state: &StoreState, len: usize) -> bool {
        if state.chunks.len() >= self.max_capacity {
            return true;
        }
        match state.bytes.checked_add(len) {
            Some(total) => total > self.max_bytes,
            None => true,
        }
    }
}

/// Remove a chunk and keep the byte count right.
fn remove_chunk(state: &mut StoreState, id: &ContentId) -> bool {
    match state.chunks.remove(id) {
        Some(data) => {
            // The count is the sum of the stored lengths, so it cannot go
            // below zero; a mismatch resets to zero instead of wrapping.
            state.bytes = state.bytes.saturating_sub(data.len());
            state.order.retain(|queued| queued != id);
            true
        }
        None => false,
    }
}

impl ContentStore for MemoryContentStore {
    fn put(&self, id: ContentId, data: Vec<u8>) -> Result<(), StoreError> {
        // Integrity check: the CID must match the data.
        let computed = ContentId::of(&data);
        if computed != id {
            return Err(StoreError::IntegrityMismatch {
                expected: id,
                actual: computed,
            });
        }
        let limit = self.chunk_limit();
        if data.len() > limit {
            return Err(StoreError::TooLarge {
                len: data.len(),
                max: limit,
            });
        }

        let mut state = self
            .inner
            .write()
            .map_err(|e| StoreError::Internal(e.to_string()))?;

        // The same CID is the same bytes: nothing to store, and the chunk
        // keeps its place in the eviction order.
        if state.chunks.contains_key(&id) {
            return Ok(());
        }

        // Evict the oldest inserted chunks until the new one fits.
        while self.over_budget(&state, data.len()) {
            let Some(oldest) = state.order.pop_front() else {
                break;
            };
            if let Some(old) = state.chunks.remove(&oldest) {
                state.bytes = state.bytes.saturating_sub(old.len());
                tracing::debug!(%oldest, "evicted oldest chunk (capacity reached)");
            }
        }

        state.bytes = state.bytes.saturating_add(data.len());
        state.order.push_back(id);
        state.chunks.insert(id, data);
        Ok(())
    }

    fn get(&self, id: &ContentId) -> Result<Vec<u8>, StoreError> {
        let state = self
            .inner
            .read()
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        state
            .chunks
            .get(id)
            .cloned()
            .ok_or(StoreError::NotFound(*id))
    }

    fn delete(&self, id: &ContentId) -> Result<(), StoreError> {
        let mut state = self
            .inner
            .write()
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        if remove_chunk(&mut state, id) {
            tracing::info!(cid = %id, "content physically deleted from store");
            Ok(())
        } else {
            Err(StoreError::NotFound(*id))
        }
    }

    fn has(&self, id: &ContentId) -> bool {
        self.inner
            .read()
            .map(|state| state.chunks.contains_key(id))
            .unwrap_or(false)
    }

    fn list_cids(&self) -> Vec<ContentId> {
        self.inner
            .read()
            .map(|state| state.chunks.keys().copied().collect())
            .unwrap_or_default()
    }

    fn len(&self) -> usize {
        self.inner
            .read()
            .map(|state| state.chunks.len())
            .unwrap_or(0)
    }

    fn bytes(&self) -> usize {
        self.inner.read().map(|state| state.bytes).unwrap_or(0)
    }
}

/// The on-disk index is rebuilt from the content files at startup. Keeping
/// only sizes in memory avoids a second metadata database and makes a copied
/// store self-describing: a file named by a CID is the complete record.
#[derive(Default)]
struct PersistentState {
    chunks: BTreeMap<ContentId, usize>,
    bytes: usize,
}

/// A content-addressed store backed by one file per chunk.
///
/// The directory is deliberately boring: each file name is the lower-case
/// hexadecimal CID and its contents are the bytes that CID names. Writes go
/// through a temporary file and a rename, so a process stop cannot expose a
/// partially written chunk. On startup the index is rebuilt and every stored
/// file is subject to the same capacity limits as the memory backend.
///
/// The store never evicts: its chunks may back active storage deals. When
/// the budget is reached it refuses new chunks until the operator deletes
/// some.
#[derive(Clone)]
pub struct FileContentStore {
    root: Arc<PathBuf>,
    inner: Arc<RwLock<PersistentState>>,
    max_capacity: usize,
    max_bytes: usize,
}

impl FileContentStore {
    /// Open or create a durable content store.
    ///
    /// # Errors
    ///
    /// Refuses an unreadable directory, an unexpected entry, an invalid CID
    /// file name, a file larger than the protocol limit, or a store that
    /// cannot be indexed.
    pub fn open<P: AsRef<Path>>(
        path: P,
        max_capacity: usize,
        max_bytes: usize,
    ) -> Result<Self, StoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(&root)
            .map_err(|error| StoreError::Internal(format!("create content store: {error}")))?;

        let mut state = PersistentState::default();
        let entries = fs::read_dir(&root)
            .map_err(|error| StoreError::Internal(format!("read content store: {error}")))?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                StoreError::Internal(format!("read content store entry: {error}"))
            })?;
            let entry_path = entry.path();
            let file_type = entry.file_type().map_err(|error| {
                StoreError::Internal(format!("inspect content store entry: {error}"))
            })?;
            if !file_type.is_file() {
                return Err(StoreError::Internal(format!(
                    "content store contains a non-file entry: {}",
                    entry_path.display()
                )));
            }

            let name = entry.file_name().into_string().map_err(|_| {
                StoreError::Internal("content store contains a non-UTF-8 file name".into())
            })?;
            // A crash between writing and renaming leaves only a temporary
            // file. It is not content and is safe to discard on the next open.
            if name.starts_with('.') && name.ends_with(".tmp") {
                fs::remove_file(&entry_path).map_err(|error| {
                    StoreError::Internal(format!("remove stale content temp file: {error}"))
                })?;
                continue;
            }
            let id = parse_content_id(&name).ok_or_else(|| {
                StoreError::Internal(format!(
                    "content store entry has an invalid CID file name: {name}"
                ))
            })?;
            if id.to_hex() != name {
                return Err(StoreError::Internal(format!(
                    "content store CID file name is not canonical lowercase hex: {name}"
                )));
            }
            let length = entry
                .metadata()
                .map_err(|error| {
                    StoreError::Internal(format!("inspect stored content {name}: {error}"))
                })?
                .len();
            let length = usize::try_from(length).map_err(|_| {
                StoreError::Internal(format!("stored content {name} is too large to index"))
            })?;
            if length > MAX_CHUNK_BYTES {
                return Err(StoreError::TooLarge {
                    len: length,
                    max: MAX_CHUNK_BYTES,
                });
            }
            if state.chunks.insert(id, length).is_some() {
                return Err(StoreError::Internal(format!(
                    "duplicate content CID while indexing: {name}"
                )));
            }
            state.bytes = state
                .bytes
                .checked_add(length)
                .ok_or_else(|| StoreError::Internal("content store byte count overflow".into()))?;
        }

        // A store above its budget (the budget was lowered) keeps every
        // chunk: they may back active storage deals. It refuses new chunks
        // until deletions bring it under the budget again.
        Ok(Self {
            root: Arc::new(root),
            inner: Arc::new(RwLock::new(state)),
            max_capacity,
            max_bytes,
        })
    }

    /// Open a durable store with the same default budget as the memory
    /// backend: 10,000 chunks and 2.5 GiB of content.
    pub fn with_default_capacity_at<P: AsRef<Path>>(path: P) -> Result<Self, StoreError> {
        Self::open(
            path,
            10_000,
            10_000usize.saturating_mul(DEFAULT_CHUNK_BYTES),
        )
    }

    fn path_for(&self, id: &ContentId) -> PathBuf {
        self.root.join(id.to_hex())
    }

    fn chunk_limit(&self) -> usize {
        if self.max_capacity == 0 {
            0
        } else {
            MAX_CHUNK_BYTES.min(self.max_bytes)
        }
    }

    fn remove_indexed(
        &self,
        state: &mut PersistentState,
        id: &ContentId,
    ) -> Result<bool, StoreError> {
        let Some(length) = state.chunks.remove(id) else {
            return Ok(false);
        };
        let path = self.path_for(id);
        match fs::remove_file(&path) {
            Ok(()) => {
                state.bytes = state.bytes.saturating_sub(length);
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                state.bytes = state.bytes.saturating_sub(length);
                Ok(true)
            }
            Err(error) => {
                // Put the index row back when deletion did not happen. The
                // caller can retry without believing the bytes disappeared.
                state.chunks.insert(*id, length);
                Err(StoreError::Internal(format!(
                    "remove stored content {}: {error}",
                    id.to_hex()
                )))
            }
        }
    }

    /// Whether `length` more bytes in a new chunk would break the budget.
    fn would_exceed(&self, state: &PersistentState, id: &ContentId, length: usize) -> bool {
        let old = state.chunks.get(id).copied();
        let chunks = state.chunks.len() + usize::from(old.is_none());
        let bytes = state
            .bytes
            .saturating_sub(old.unwrap_or(0))
            .saturating_add(length);
        chunks > self.max_capacity || bytes > self.max_bytes
    }
}

fn parse_content_id(name: &str) -> Option<ContentId> {
    if name.len() != 64 {
        return None;
    }
    let bytes = hex::decode(name).ok()?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Some(ContentId(id))
}

impl ContentStore for FileContentStore {
    fn put(&self, id: ContentId, data: Vec<u8>) -> Result<(), StoreError> {
        let computed = ContentId::of(&data);
        if computed != id {
            return Err(StoreError::IntegrityMismatch {
                expected: id,
                actual: computed,
            });
        }
        let limit = self.chunk_limit();
        if data.len() > limit {
            return Err(StoreError::TooLarge {
                len: data.len(),
                max: limit,
            });
        }

        let mut state = self
            .inner
            .write()
            .map_err(|error| StoreError::Internal(error.to_string()))?;
        // A full store refuses rather than evicts: the chunks it holds may
        // back active storage deals, and dropping one would make its operator
        // fail the next challenge. The node operator frees space by deleting.
        if self.would_exceed(&state, &id, data.len()) {
            return Err(StoreError::Internal(format!(
                "content store full: {} chunks, {} bytes; budget {} chunks, {} bytes",
                state.chunks.len(),
                state.bytes,
                self.max_capacity,
                self.max_bytes
            )));
        }
        let target = self.path_for(&id);
        let temporary = self.root.join(format!(".{}.tmp", id.to_hex()));
        let mut file = File::create(&temporary)
            .map_err(|error| StoreError::Internal(format!("create content temp file: {error}")))?;
        if let Err(error) = file.write_all(&data).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(&temporary);
            return Err(StoreError::Internal(format!(
                "write content temp file: {error}"
            )));
        }
        drop(file);
        if let Err(error) = fs::rename(&temporary, &target) {
            let _ = fs::remove_file(&temporary);
            return Err(StoreError::Internal(format!(
                "commit content file: {error}"
            )));
        }

        let old_length = state.chunks.insert(id, data.len());
        state.bytes = state
            .bytes
            .saturating_sub(old_length.unwrap_or(0))
            .saturating_add(data.len());
        Ok(())
    }

    fn get(&self, id: &ContentId) -> Result<Vec<u8>, StoreError> {
        let path = self.path_for(id);
        let data = fs::read(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(*id)
            } else {
                StoreError::Internal(format!("read stored content {}: {error}", id.to_hex()))
            }
        })?;
        let actual = ContentId::of(&data);
        if actual != *id {
            return Err(StoreError::IntegrityMismatch {
                expected: *id,
                actual,
            });
        }
        Ok(data)
    }

    fn delete(&self, id: &ContentId) -> Result<(), StoreError> {
        let mut state = self
            .inner
            .write()
            .map_err(|error| StoreError::Internal(error.to_string()))?;
        if self.remove_indexed(&mut state, id)? {
            tracing::info!(cid = %id, "content physically deleted from store");
            Ok(())
        } else {
            Err(StoreError::NotFound(*id))
        }
    }

    fn has(&self, id: &ContentId) -> bool {
        self.inner
            .read()
            .map(|state| state.chunks.contains_key(id) && self.path_for(id).is_file())
            .unwrap_or(false)
    }

    fn list_cids(&self) -> Vec<ContentId> {
        self.inner
            .read()
            .map(|state| state.chunks.keys().copied().collect())
            .unwrap_or_default()
    }

    fn len(&self) -> usize {
        self.inner
            .read()
            .map(|state| state.chunks.len())
            .unwrap_or(0)
    }

    fn bytes(&self) -> usize {
        self.inner.read().map(|state| state.bytes).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_id_is_deterministic() {
        let data = b"hello B.U.D.";
        let id1 = ContentId::of(data);
        let id2 = ContentId::of(data);
        assert_eq!(id1, id2);
    }

    #[test]
    fn content_id_differs_for_different_data() {
        let id1 = ContentId::of(b"chunk A");
        let id2 = ContentId::of(b"chunk B");
        assert_ne!(id1, id2);
    }

    #[test]
    fn memory_store_put_get_roundtrip() {
        let store = MemoryContentStore::with_default_capacity();
        let data = b"B.U.D. storage test data".to_vec();
        let id = ContentId::of(&data);

        store.put(id, data.clone()).unwrap();
        assert!(store.has(&id));
        assert_eq!(store.get(&id).unwrap(), data);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn memory_store_rejects_integrity_mismatch() {
        let store = MemoryContentStore::with_default_capacity();
        let data = b"real data".to_vec();
        let wrong_id = ContentId::of(b"wrong data");

        let result = store.put(wrong_id, data);
        assert!(matches!(result, Err(StoreError::IntegrityMismatch { .. })));
    }

    #[test]
    fn memory_store_not_found() {
        let store = MemoryContentStore::with_default_capacity();
        let id = ContentId::of(b"nonexistent");
        assert!(!store.has(&id));
        assert!(matches!(store.get(&id), Err(StoreError::NotFound(_))));
    }

    #[test]
    fn memory_store_evicts_oldest_at_capacity() {
        let store = MemoryContentStore::new(3);

        let chunks: Vec<(ContentId, Vec<u8>)> = (0..4)
            .map(|i| {
                let data = format!("chunk {i}").into_bytes();
                (ContentId::of(&data), data)
            })
            .collect();

        for (id, data) in &chunks[..3] {
            store.put(*id, data.clone()).unwrap();
        }
        assert_eq!(store.len(), 3);

        // 4th chunk triggers eviction of the oldest inserted chunk.
        store.put(chunks[3].0, chunks[3].1.clone()).unwrap();
        assert_eq!(store.len(), 3);

        // The 4th chunk is present, the first one is gone.
        assert!(store.has(&chunks[3].0));
        assert!(!store.has(&chunks[0].0));
        assert!(store.has(&chunks[1].0));
    }

    /// Eviction follows insertion order, not the CID order: a chunk with the
    /// lowest CID that was inserted last must survive.
    #[test]
    fn eviction_follows_insertion_order_not_cid_order() {
        let store = MemoryContentStore::new(2);
        let mut chunks: Vec<(ContentId, Vec<u8>)> = (0..3)
            .map(|i| {
                let data = format!("order {i}").into_bytes();
                (ContentId::of(&data), data)
            })
            .collect();
        // Insert the highest CID first, the lowest CID last.
        chunks.sort_by_key(|chunk| std::cmp::Reverse(chunk.0));
        store.put(chunks[0].0, chunks[0].1.clone()).unwrap();
        store.put(chunks[1].0, chunks[1].1.clone()).unwrap();
        store.put(chunks[2].0, chunks[2].1.clone()).unwrap();
        assert!(!store.has(&chunks[0].0), "the first inserted is evicted");
        assert!(store.has(&chunks[1].0));
        assert!(store.has(&chunks[2].0), "the lowest CID was not evicted");
    }

    /// The byte budget bounds the store, not only the chunk count.
    #[test]
    fn the_byte_budget_evicts_old_chunks() {
        let store = MemoryContentStore::with_limits(100, 10);
        let a = vec![1u8; 6];
        let b = vec![2u8; 6];
        store.put(ContentId::of(&a), a.clone()).unwrap();
        store.put(ContentId::of(&b), b.clone()).unwrap();
        assert!(!store.has(&ContentId::of(&a)));
        assert!(store.has(&ContentId::of(&b)));
        assert_eq!(store.len(), 1);
    }

    /// A chunk over the per-chunk limit is refused.
    #[test]
    fn an_oversized_chunk_is_refused() {
        let store = MemoryContentStore::with_limits(100, 10);
        let big = vec![3u8; 11];
        let err = store.put(ContentId::of(&big), big).expect_err("too large");
        assert!(matches!(err, StoreError::TooLarge { len: 11, max: 10 }));
        assert!(store.is_empty());
        let huge = vec![4u8; MAX_CHUNK_BYTES + 1];
        let big_store = MemoryContentStore::with_default_capacity();
        assert!(matches!(
            big_store.put(ContentId::of(&huge), huge),
            Err(StoreError::TooLarge { .. })
        ));
    }

    /// Deleting frees the byte budget.
    #[test]
    fn delete_frees_bytes() {
        let store = MemoryContentStore::with_limits(100, 10);
        let a = vec![1u8; 6];
        let b = vec![2u8; 6];
        store.put(ContentId::of(&a), a.clone()).unwrap();
        store.delete(&ContentId::of(&a)).unwrap();
        store.put(ContentId::of(&b), b.clone()).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.has(&ContentId::of(&b)));
    }

    #[test]
    fn memory_store_list_cids() {
        let store = MemoryContentStore::with_default_capacity();
        let data1 = b"alpha".to_vec();
        let data2 = b"beta".to_vec();
        let id1 = ContentId::of(&data1);
        let id2 = ContentId::of(&data2);

        store.put(id1, data1).unwrap();
        store.put(id2, data2).unwrap();

        let cids = store.list_cids();
        assert_eq!(cids.len(), 2);
        assert!(cids.contains(&id1));
        assert!(cids.contains(&id2));
    }

    fn seeded_bytes(len: usize) -> Vec<u8> {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn content_id_golden_vectors_match_core() {
        let cases: [(Vec<u8>, &str); 3] = [
            (
                vec![],
                "b9c2e41839278bfe0711bbdfb660ed31087513891bc2fa80c84f2bb6fa160104",
            ),
            (
                vec![0u8],
                "ae6ac769b38f211a1ee7d8c3bf7b17ea2e905d99a5ae515e46b55192a22b7ed1",
            ),
            (
                seeded_bytes(65_536),
                "09dd6421a5383e6d54fde97f523c6ad9ca6b33ffa8838801818f2992fbb7ab94",
            ),
        ];
        for (data, want) in &cases {
            assert_eq!(ContentId::of(data).to_hex(), *want, "len {}", data.len());
        }
    }

    fn scratch_store_path(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bud-node-content-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    #[test]
    fn file_store_survives_reopen() {
        let path = scratch_store_path("reopen");
        let data = b"durable B.U.D. content".to_vec();
        let id = ContentId::of(&data);
        {
            let store = FileContentStore::open(&path, 4, 1024).unwrap();
            store.put(id, data.clone()).unwrap();
            assert_eq!(store.get(&id).unwrap(), data);
        }
        let reopened = FileContentStore::open(&path, 4, 1024).unwrap();
        assert!(reopened.has(&id));
        assert_eq!(reopened.list_cids(), vec![id]);
        assert_eq!(reopened.get(&id).unwrap(), data);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn file_store_refuses_corrupt_bytes_after_reopen() {
        let path = scratch_store_path("integrity");
        let data = b"original".to_vec();
        let id = ContentId::of(&data);
        let store = FileContentStore::open(&path, 4, 1024).unwrap();
        store.put(id, data).unwrap();
        std::fs::write(path.join(id.to_hex()), b"tampered").unwrap();
        let reopened = FileContentStore::open(&path, 4, 1024).unwrap();
        assert!(matches!(
            reopened.get(&id),
            Err(StoreError::IntegrityMismatch { expected, .. }) if expected == id
        ));
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn a_full_file_store_refuses_instead_of_evicting() {
        let path = scratch_store_path("full");
        let entries: Vec<(ContentId, Vec<u8>)> = (0..3)
            .map(|index| {
                let data = format!("persistent chunk {index}").into_bytes();
                (ContentId::of(&data), data)
            })
            .collect();
        let store = FileContentStore::open(&path, 2, 1024).unwrap();
        store.put(entries[0].0, entries[0].1.clone()).unwrap();
        store.put(entries[1].0, entries[1].1.clone()).unwrap();
        // The third chunk would break the budget: refused, nothing evicted.
        assert!(store.put(entries[2].0, entries[2].1.clone()).is_err());
        assert_eq!(store.len(), 2);
        // Writing a chunk the store already holds is not growth.
        store.put(entries[1].0, entries[1].1.clone()).unwrap();
        drop(store);
        // A lowered budget at reopen keeps every chunk and refuses new ones.
        let reopened = FileContentStore::open(&path, 1, 1024).unwrap();
        assert_eq!(reopened.len(), 2);
        assert!(reopened.put(entries[2].0, entries[2].1.clone()).is_err());
        reopened.delete(&entries[0].0).unwrap();
        reopened.delete(&entries[1].0).unwrap();
        reopened.put(entries[2].0, entries[2].1.clone()).unwrap();
        std::fs::remove_dir_all(path).unwrap();
    }
}
