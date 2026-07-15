//! B.U.D. Content Store — content-addressed storage layer.
//!
//! Implements the `ContentStore` trait for storing and retrieving
//! content chunks by their `ContentId`. The primary implementation
//! is `MemoryContentStore` (in-memory, suitable for testing and
//! devnet). A disk-backed implementation (`SledContentStore`) is
//! planned for mainnet.
//!
//! # Data Sovereignty Rule (Tur 14.5 plan §0.5)
//!
//! Any node can independently compute `ContentId` from raw chunk
//! bytes. No "Budlum Inc. indexer" or centralized service is
//! required. The store is fully permissionless.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// A content identifier — 32-byte hash of the chunk data.
/// Mirrors `budlum_core::storage::content_id::ContentId` but is
/// self-contained so this crate can be used independently.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    /// Compute the `ContentId` of a chunk using the same domain-separated
    /// SHA-256 as `budlum-core` (`BDLM_CONTENT_V1` tag).
    pub fn of(chunk: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_CONTENT_V1");
        hasher.update(chunk);
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
    #[error("internal error: {0}")]
    Internal(String),
}

/// Trait for content-addressed storage backends.
///
/// All implementations MUST verify content integrity on `put`:
/// the provided `ContentId` must match `ContentId::of(data)`.
/// This is a hard security requirement — a malicious peer must not be
/// able to store data under a wrong CID.
pub trait ContentStore: Send + Sync {
    /// Store a chunk. Returns `Err(StoreError::IntegrityMismatch)` if
    /// the data does not match the claimed CID.
    fn put(&self, id: ContentId, data: Vec<u8>) -> Result<(), StoreError>;

    /// Retrieve a chunk by CID. Returns `Err(StoreError::NotFound)` if
    /// the chunk is not in the store.
    fn get(&self, id: &ContentId) -> Result<Vec<u8>, StoreError>;

    /// Check if a chunk exists in the store.
    fn has(&self, id: &ContentId) -> bool;

    /// List all CIDs in the store (for DHT provider announcements).
    fn list_cids(&self) -> Vec<ContentId>;

    /// Total number of chunks stored.
    fn len(&self) -> usize;

    /// Whether the store is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// In-memory content store backed by a `BTreeMap`.
///
/// Suitable for testing, devnet, and short-lived nodes. Data is lost
/// on process exit. For persistent storage, use `SledContentStore`
/// (planned for a future commit).
///
/// Thread-safe via `RwLock`. Read operations (`get`, `has`) acquire
/// a shared lock; writes (`put`) acquire an exclusive lock.
#[derive(Clone)]
pub struct MemoryContentStore {
    inner: Arc<RwLock<BTreeMap<ContentId, Vec<u8>>>>,
    /// Maximum number of chunks to store. When exceeded, the oldest
    /// chunk (lowest CID) is evicted. Prevents unbounded memory growth.
    max_capacity: usize,
}

impl MemoryContentStore {
    /// Create a new empty store with the given capacity.
    pub fn new(max_capacity: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(BTreeMap::new())),
            max_capacity,
        }
    }

    /// Create a store with default capacity (10,000 chunks ≈ 2.5 GiB
    /// at 256 KiB per chunk).
    pub fn with_default_capacity() -> Self {
        Self::new(10_000)
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

        let mut map = self
            .inner
            .write()
            .map_err(|e| StoreError::Internal(e.to_string()))?;

        // Evict oldest if at capacity.
        if map.len() >= self.max_capacity && !map.contains_key(&id) {
            if let Some(oldest) = map.keys().next().copied() {
                map.remove(&oldest);
                tracing::debug!(%oldest, "evicted oldest chunk (capacity reached)");
            }
        }

        map.insert(id, data);
        Ok(())
    }

    fn get(&self, id: &ContentId) -> Result<Vec<u8>, StoreError> {
        let map = self
            .inner
            .read()
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        map.get(id).cloned().ok_or(StoreError::NotFound(*id))
    }

    fn has(&self, id: &ContentId) -> bool {
        self.inner
            .read()
            .map(|map| map.contains_key(id))
            .unwrap_or(false)
    }

    fn list_cids(&self) -> Vec<ContentId> {
        self.inner
            .read()
            .map(|map| map.keys().copied().collect())
            .unwrap_or_default()
    }

    fn len(&self) -> usize {
        self.inner.read().map(|map| map.len()).unwrap_or(0)
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
                let data = format!("chunk {}", i).into_bytes();
                (ContentId::of(&data), data)
            })
            .collect();

        for (id, data) in &chunks[..3] {
            store.put(*id, data.clone()).unwrap();
        }
        assert_eq!(store.len(), 3);

        // 4th chunk triggers eviction of the oldest (lowest CID).
        store.put(chunks[3].0, chunks[3].1.clone()).unwrap();
        assert_eq!(store.len(), 3);

        // The 4th chunk is present.
        assert!(store.has(&chunks[3].0));
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
}
