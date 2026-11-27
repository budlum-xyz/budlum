//! The Garden content store.
//!
//! Messages, posts and images are content addressed with Budlum's one
//! content id (`storage::content_id::ContentId`). The Garden chain carries
//! the content id; the bytes live here. Every reader recomputes the id from
//! the bytes it got, so a holder cannot hand out other bytes under the same
//! id.
//!
//! This is the storage seam of a Garden. The object encoding of B.U.D. 3.0 is
//! not on `main` yet, so the store keeps each object as one chunk under its
//! content id and writes no encoder of its own. When the object layer lands,
//! it replaces the inside of this module and nothing else moves.
//!
//! A file name is always the 64 hex digits of a content id that was computed
//! here from the bytes. No caller-provided string reaches the file system.

use crate::domain::types::Hash32;
use crate::storage::bud3::fountain::Symbol;
use crate::storage::bud3::limits::{Bud3Limits, Profile};
use crate::storage::bud3::pipeline::{
    prepare_public_upload, view_public, ObjectRecord, PipelineError, MAX_SYMBOLS_PER_SEGMENT,
};
use crate::storage::content_id::ContentId;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Default local disk ceiling for one Garden content store (16 GiB).
/// Joining a Garden adopts the host's per-object cap only up to this local
/// budget so a hostile host cannot fill a joiner's disk via genesis limits.
pub const MAX_LOCAL_GARDEN_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// What one object of `len` bytes costs against the local ceiling.
///
/// The ceiling is a budget on disk, and every object is one file: a one-byte
/// publication still costs an inode and a directory entry, and a whole
/// filesystem block where the filesystem does not inline small files.
/// Charging the floor the genesis share already charges keeps the local
/// budget an upper bound on a Garden's disk use instead of a count of the
/// bytes it declares.
const fn charged_bytes(len: u64) -> u64 {
    if len > super::types::MIN_PUBLICATION_CHARGE {
        len
    } else {
        super::types::MIN_PUBLICATION_CHARGE
    }
}

/// How many times each B.U.D. 3.0 part ran on this node's production path.
///
/// A Garden that merely links the object layer proves nothing: the question
/// is whether the bytes people publish actually travel through it. Each
/// field counts one part doing its work for a real publication or a real
/// read, so a test can read the counts instead of trusting a call graph.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Bud3PartCounts {
    /// Objects encoded by BOF-1 and committed (`bof1`, `segment`).
    pub objects_coded: u64,
    /// Segments the object was cut into (`segment`).
    pub segments_coded: u64,
    /// RFC 6330 symbols produced (`fountain`).
    pub symbols_made: u64,
    /// Per-segment symbol roots built (`custody`).
    pub symbol_roots: u64,
    /// Objects read back through the view path (`pipeline::view_public`).
    pub objects_viewed: u64,
    /// Symbols consumed to decode those reads (`fountain` decode).
    pub symbols_used: u64,
}

/// How many bytes of coded symbols this node keeps in memory.
///
/// Symbols are the object layer's own form of the content, and keeping them
/// lets a read come back through B.U.D. 3.0 rather than through the byte
/// cache. The budget is deliberately small: the plain bytes are the durable
/// copy, so forgetting symbols costs a node nothing but the shortcut.
const CODED_SYMBOL_BUDGET: u64 = 8 * 1024 * 1024;

/// What B.U.D. 3.0 made of one object.
#[derive(Debug)]
struct CodedObject {
    record: ObjectRecord,
    segments: Vec<Vec<Symbol>>,
    /// Bytes the symbols occupy, for the memory budget.
    footprint: u64,
}

/// A count as a `u64`, saturating instead of casting.
fn count_of(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Where the objects of one Garden live on this node.
#[derive(Debug)]
pub struct GardenContentStore {
    root: Option<PathBuf>,
    memory: BTreeMap<Hash32, Vec<u8>>,
    max_object_bytes: usize,
    max_total_bytes: u64,
    total_bytes: u64,
    /// The B.U.D. 3.0 coding of the objects this node accepted, bounded by
    /// `CODED_SYMBOL_BUDGET` and dropped oldest first.
    coded: BTreeMap<Hash32, CodedObject>,
    /// Coding order, so the budget evicts the oldest symbols first.
    coded_order: VecDeque<Hash32>,
    /// Bytes the kept symbols occupy.
    coded_bytes: u64,
    /// What the parts did, for `bud_gardenStatus`.
    parts: Bud3PartCounts,
}

fn scan_disk_bytes(root: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.file_type().is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some((prefix, _)) = name.split_once(".tmp.") {
                if hex::decode(prefix).is_ok_and(|bytes| bytes.len() == 32) {
                    let _ = fs::remove_file(&path);
                }
                continue;
            }
            if hex::decode(name).is_ok_and(|bytes| bytes.len() == 32) {
                total = total.saturating_add(charged_bytes(meta.len()));
            }
        }
    }
    total
}

impl GardenContentStore {
    /// Open a store under `root` using the default local byte ceiling
    /// (`MAX_LOCAL_GARDEN_BYTES`). `None` keeps the objects in memory only.
    #[cfg(test)]
    pub fn open(root: Option<&Path>, max_object_bytes: usize) -> Result<Self, String> {
        Self::open_with_limit(root, max_object_bytes, MAX_LOCAL_GARDEN_BYTES)
    }

    /// Open a store under `root` with an explicit total-bytes ceiling enforced
    /// locally regardless of what a Garden's genesis claims.
    pub fn open_with_limit(
        root: Option<&Path>,
        max_object_bytes: usize,
        max_total_bytes: u64,
    ) -> Result<Self, String> {
        let total_bytes = if let Some(root) = root {
            fs::create_dir_all(root)
                .map_err(|e| format!("garden content directory cannot be created: {e}"))?;
            scan_disk_bytes(root)
        } else {
            0
        };
        Ok(Self {
            root: root.map(Path::to_path_buf),
            memory: BTreeMap::new(),
            max_object_bytes,
            max_total_bytes,
            total_bytes,
            coded: BTreeMap::new(),
            coded_order: VecDeque::new(),
            coded_bytes: 0,
            parts: Bud3PartCounts::default(),
        })
    }

    /// Total object bytes currently held in this store.
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// True when storing an object of `size` bytes fits within the local cap.
    pub const fn can_fit(&self, size: u64) -> bool {
        self.total_bytes.saturating_add(charged_bytes(size)) <= self.max_total_bytes
    }

    fn path_of(&self, content_id: &Hash32) -> Option<PathBuf> {
        self.root
            .as_ref()
            .map(|root| root.join(hex::encode(content_id)))
    }

    /// Store `bytes` and return their content id.
    pub fn put(&mut self, bytes: &[u8]) -> Result<Hash32, String> {
        if bytes.is_empty() || bytes.len() > self.max_object_bytes {
            return Err(format!(
                "object size {} is outside 1..={} bytes",
                bytes.len(),
                self.max_object_bytes
            ));
        }
        let content_id = ContentId::of(bytes).0;
        // Code the object with B.U.D. 3.0 before a single byte is written.
        // The Garden keeps the plain bytes as its cache, but the object it
        // claims to hold is the coded one: if BOF-1 cannot represent it,
        // this node does not get to say it stored it.
        self.code_and_count(content_id, bytes)?;
        // A node that cannot keep the bytes must not keep the coding
        // either: `get_coded` would otherwise answer for an object this
        // node does not hold.
        match self.store_bytes(content_id, bytes) {
            Ok(()) => Ok(content_id),
            Err(e) => {
                self.drop_coding(&content_id);
                Err(e)
            }
        }
    }

    /// Write the bytes themselves, once the object layer has accepted them.
    fn store_bytes(&mut self, content_id: Hash32, bytes: &[u8]) -> Result<(), String> {
        let len = charged_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        match self.path_of(&content_id) {
            Some(path) => {
                if !path.is_file() {
                    if !self.can_fit(len) {
                        return Err(format!(
                            "garden local storage limit of {} bytes reached",
                            self.max_total_bytes
                        ));
                    }
                    let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
                    let tmp = path.with_extension(format!("tmp.{}.{seq}", std::process::id()));
                    let write_res = (|| -> std::io::Result<()> {
                        let mut file = fs::File::create(&tmp)?;
                        file.write_all(bytes)?;
                        file.sync_all()?;
                        fs::rename(&tmp, &path)?;
                        Ok(())
                    })();
                    if let Err(e) = write_res {
                        let _ = fs::remove_file(&tmp);
                        return Err(format!("garden object cannot be written: {e}"));
                    }
                    self.total_bytes = self.total_bytes.saturating_add(len);
                }
            }
            None => {
                if !self.memory.contains_key(&content_id) {
                    if !self.can_fit(len) {
                        return Err(format!(
                            "garden local storage limit of {} bytes reached",
                            self.max_total_bytes
                        ));
                    }
                    self.memory.insert(content_id, bytes.to_vec());
                    self.total_bytes = self.total_bytes.saturating_add(len);
                }
            }
        }
        Ok(())
    }

    /// Reserve local byte budget and return a standalone blocking writer closure
    /// target `(path, charged_len)` so a caller can run disk create/fsync in a
    /// background task while continuing to process consensus events.
    pub fn reserve_background_write(
        &mut self,
        content_id: Hash32,
        bytes: &[u8],
    ) -> Result<Option<(PathBuf, u64)>, String> {
        if bytes.is_empty() || bytes.len() > self.max_object_bytes {
            return Err(format!(
                "object size {} is outside 1..={} bytes",
                bytes.len(),
                self.max_object_bytes
            ));
        }
        // A deposit pushed by a peer takes the same road as a local one: it
        // is coded by B.U.D. 3.0 before the node reserves room for it, so a
        // background write cannot smuggle an object past the object layer.
        self.code_and_count(content_id, bytes)?;
        // Same rule as `put`: a reservation that fails leaves no coding
        // behind for an object this node will not hold.
        match self.reserve_room(content_id, bytes) {
            Ok(room) => Ok(room),
            Err(e) => {
                self.drop_coding(&content_id);
                Err(e)
            }
        }
    }

    /// Account for the bytes of a deposit and say where they go.
    fn reserve_room(
        &mut self,
        content_id: Hash32,
        bytes: &[u8],
    ) -> Result<Option<(PathBuf, u64)>, String> {
        let len = charged_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if let Some(path) = self.path_of(&content_id) {
            if self.contains(&content_id) {
                return Ok(None);
            }
            if !self.can_fit(len) {
                return Err(format!(
                    "garden local storage limit of {} bytes reached",
                    self.max_total_bytes
                ));
            }
            self.total_bytes = self.total_bytes.saturating_add(len);
            Ok(Some((path, len)))
        } else {
            if !self.memory.contains_key(&content_id) {
                if !self.can_fit(len) {
                    return Err(format!(
                        "garden local storage limit of {} bytes reached",
                        self.max_total_bytes
                    ));
                }
                self.memory.insert(content_id, bytes.to_vec());
                self.total_bytes = self.total_bytes.saturating_add(len);
            }
            Ok(None)
        }
    }

    /// Release a previously reserved background write charge (on write failure
    /// or when the target file already existed on disk).
    pub const fn release_background_charge(&mut self, charged_len: u64) {
        self.total_bytes = self.total_bytes.saturating_sub(charged_len);
    }

    /// Write `bytes` atomically to `path` on a blocking thread. Returns
    /// `Ok(true)` when a new file was materialized, `Ok(false)` when `path`
    /// already existed (using atomic `hard_link` so two concurrent writers for
    /// the same content id never both claim `Ok(true)` and double-charge the
    /// store's byte ceiling).
    pub fn write_object_file_blocking(path: PathBuf, bytes: Vec<u8>) -> Result<bool, String> {
        if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_file()) {
            return Ok(false);
        }
        let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!("tmp.{}.{seq}", std::process::id()));
        let write_res = (|| -> std::io::Result<bool> {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            match fs::hard_link(&tmp, &path) {
                Ok(()) => {
                    let _ = fs::remove_file(&tmp);
                    Ok(true)
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = fs::remove_file(&tmp);
                    Ok(false)
                }
                Err(e) => Err(e),
            }
        })();
        match write_res {
            Ok(created) => Ok(created),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                Err(format!("garden object cannot be written: {e}"))
            }
        }
    }

    /// Store bytes received from a peer, but only under the id they hash to.
    pub fn put_verified(&mut self, expected: &Hash32, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() > self.max_object_bytes {
            return Err(format!(
                "object size {} is outside 1..={} bytes",
                bytes.len(),
                self.max_object_bytes
            ));
        }
        if ContentId::of(bytes).0 != *expected {
            return Err("received bytes do not hash to the requested content id".into());
        }
        self.put(bytes).map(|_| ())
    }

    /// Code an object once and record what the parts did.
    fn code_and_count(&mut self, content_id: Hash32, bytes: &[u8]) -> Result<(), String> {
        if self.coded.contains_key(&content_id) {
            return Ok(());
        }
        let coded = Self::code_object(bytes)?;
        let segments = count_of(coded.segments.len());
        let symbols = coded
            .segments
            .iter()
            .map(|segment| count_of(segment.len()))
            .fold(0u64, u64::saturating_add);
        let roots = count_of(coded.record.symbol_roots.len());
        self.parts.objects_coded = self.parts.objects_coded.saturating_add(1);
        self.parts.segments_coded = self.parts.segments_coded.saturating_add(segments);
        self.parts.symbols_made = self.parts.symbols_made.saturating_add(symbols);
        self.parts.symbol_roots = self.parts.symbol_roots.saturating_add(roots);
        self.coded_bytes = self.coded_bytes.saturating_add(coded.footprint);
        self.coded.insert(content_id, coded);
        self.coded_order.push_back(content_id);
        // Keep the newest coding even when it alone exceeds the budget: a
        // node that just coded an object should be able to serve it once.
        while self.coded_bytes > CODED_SYMBOL_BUDGET && self.coded_order.len() > 1 {
            let Some(old) = self.coded_order.pop_front() else {
                break;
            };
            self.forget_coding(&old);
        }
        Ok(())
    }

    /// Drop one coding entirely, symbols and its place in the order.
    fn drop_coding(&mut self, content_id: &Hash32) {
        self.forget_coding(content_id);
        self.coded_order.retain(|id| id != content_id);
    }

    /// Drop the symbols of one object, keeping the counters as they are.
    fn forget_coding(&mut self, content_id: &Hash32) {
        if let Some(old) = self.coded.remove(content_id) {
            self.coded_bytes = self.coded_bytes.saturating_sub(old.footprint);
        }
    }

    /// Run the bytes through the B.U.D. 3.0 upload pipeline.
    ///
    /// The Garden uses profile P0 and the testnet limits, and asks for one
    /// segment's worth of symbols, because a Garden object is small by
    /// construction: the ceiling is `max_object_bytes`, far under the
    /// segment capacity, so the usual result is a single segment.
    fn code_object(bytes: &[u8]) -> Result<CodedObject, String> {
        let profile = Profile::P0;
        let limits = Bud3Limits::TESTNET_DEFAULT;
        // The pipeline does not code the content, it codes the object built
        // from it: a codec may shrink the bytes and a header grows them, so
        // the source-symbol count `k` is only known inside. Guess from the
        // content, and when the guess is short the error carries the real
        // `k`; the second call is then exact. The pipeline wants at least
        // `k + 2` so every segment also carries repair symbols.
        let guess = u32::try_from(bytes.len().div_ceil(usize::from(profile.symbol_size)))
            .unwrap_or(profile.k_max)
            .saturating_add(2);
        let prepared = match prepare_public_upload(bytes, &profile, &limits, guess) {
            Err(PipelineError::TooFewSymbols { k, .. }) => prepare_public_upload(
                bytes,
                &profile,
                &limits,
                k.saturating_add(2).min(MAX_SYMBOLS_PER_SEGMENT),
            ),
            first => first,
        }
        .map_err(|e| format!("garden object cannot be coded by B.U.D. 3.0: {e:?}"))?;
        let footprint = prepared
            .segments
            .iter()
            .flatten()
            .map(|symbol| count_of(symbol.data.len()))
            .fold(0u64, u64::saturating_add);
        Ok(CodedObject {
            record: prepared.record,
            segments: prepared.segments,
            footprint,
        })
    }

    /// Rebuild an object from its B.U.D. 3.0 symbols instead of from the
    /// cached bytes.
    ///
    /// This is the read that proves the object layer is real: it ignores the
    /// stored copy, decodes the symbols that `put` produced, and checks the
    /// result against the content id the chain carries.
    pub fn get_coded(&mut self, content_id: &Hash32) -> Option<Vec<u8>> {
        let coded = self.coded.get(content_id)?;
        let symbols: Vec<Symbol> = coded.segments.iter().flatten().cloned().collect();
        let used = count_of(symbols.len());
        let bytes = view_public(&coded.record, symbols).ok()?;
        if ContentId::of(&bytes).0 != *content_id {
            return None;
        }
        self.parts.objects_viewed = self.parts.objects_viewed.saturating_add(1);
        self.parts.symbols_used = self.parts.symbols_used.saturating_add(used);
        Some(bytes)
    }

    /// The B.U.D. 3.0 record and symbols of a held object, ready to send.
    ///
    /// A validator that wants another validator to hold an object hands
    /// over what the coder made, not the bytes it started from. The
    /// receiver rebuilds the object from these and keeps it only if the
    /// result hashes to the id it was promised.
    #[must_use]
    pub fn coded_parts(&self, content_id: &Hash32) -> Option<(ObjectRecord, Vec<Symbol>)> {
        let coded = self.coded.get(content_id)?;
        Some((
            coded.record.clone(),
            coded.segments.iter().flatten().cloned().collect(),
        ))
    }

    /// Rebuild an object from B.U.D. 3.0 parts a peer sent, without
    /// storing it.
    ///
    /// The decode is the check. Parts that do not rebuild, or rebuild into
    /// something with another content id, are refused before anything is
    /// written, so a peer cannot deposit rubbish under a name it chose.
    pub fn rebuild_coded(
        &mut self,
        expected: &Hash32,
        record: &ObjectRecord,
        symbols: Vec<Symbol>,
    ) -> Result<Vec<u8>, String> {
        // The record carries a B.U.D. 3.0 content id, which is a digest
        // over the object the pipeline built. The Garden names content by
        // its own rule, so the id to satisfy is the Garden's, taken from
        // the rebuilt bytes.
        let used = count_of(symbols.len());
        let bytes = view_public(record, symbols)
            .map_err(|e| format!("these B.U.D. 3.0 parts do not rebuild an object: {e:?}"))?;
        if ContentId::of(&bytes).0 != *expected {
            return Err("rebuilt object does not match the content id it was sent under".into());
        }
        self.parts.objects_viewed = self.parts.objects_viewed.saturating_add(1);
        self.parts.symbols_used = self.parts.symbols_used.saturating_add(used);
        Ok(bytes)
    }

    /// Take an object as B.U.D. 3.0 parts and keep it if it rebuilds.
    pub fn put_coded(
        &mut self,
        expected: &Hash32,
        record: &ObjectRecord,
        symbols: Vec<Symbol>,
    ) -> Result<Hash32, String> {
        let bytes = self.rebuild_coded(expected, record, symbols)?;
        self.put(&bytes)
    }

    /// The B.U.D. 3.0 record of a held object, if this node coded it.
    #[must_use]
    pub fn record_of(&self, content_id: &Hash32) -> Option<&ObjectRecord> {
        self.coded.get(content_id).map(|c| &c.record)
    }

    /// What the B.U.D. 3.0 parts have done on this node.
    #[must_use]
    pub const fn part_counts(&self) -> Bud3PartCounts {
        self.parts
    }

    /// Read an object and check it against its content id.
    pub fn get(&self, content_id: &Hash32) -> Option<Vec<u8>> {
        let bytes = match self.path_of(content_id) {
            Some(path) => fs::read(path).ok()?,
            None => self.memory.get(content_id)?.clone(),
        };
        (ContentId::of(&bytes).0 == *content_id).then_some(bytes)
    }

    pub fn contains(&self, content_id: &Hash32) -> bool {
        self.path_of(content_id).map_or_else(
            || self.memory.contains_key(content_id),
            |path| path.is_file(),
        )
    }

    /// The byte length of a stored object, without reading it.
    pub fn stored_len(&self, content_id: &Hash32) -> Option<u64> {
        self.path_of(content_id).map_or_else(
            || {
                self.memory
                    .get(content_id)
                    .and_then(|bytes| u64::try_from(bytes.len()).ok())
            },
            |path| {
                fs::metadata(path)
                    .ok()
                    .filter(fs::Metadata::is_file)
                    .map(|meta| meta.len())
            },
        )
    }

    /// Drop one object, when this node no longer holds it.
    pub fn remove(&mut self, content_id: &Hash32) {
        // The coding goes with the object. The counters do not move: they
        // record work this node did, and dropping the result later does not
        // undo it.
        self.drop_coding(content_id);
        match self.path_of(content_id) {
            Some(path) => {
                let len = fs::metadata(&path)
                    .ok()
                    .filter(fs::Metadata::is_file)
                    .map_or(0, |meta| charged_bytes(meta.len()));
                if fs::remove_file(path).is_ok() {
                    self.total_bytes = self.total_bytes.saturating_sub(len);
                }
            }
            None => {
                if let Some(bytes) = self.memory.remove(content_id) {
                    let len = charged_bytes(u64::try_from(bytes.len()).unwrap_or(0));
                    self.total_bytes = self.total_bytes.saturating_sub(len);
                }
            }
        }
    }

    /// Remove every stored object whose content id is not in `keep`.
    /// Called on startup so orphaned files left from earlier runs cannot
    /// linger unaccounted on disk.
    pub(crate) fn prune_unaccounted(&mut self, keep: &BTreeSet<Hash32>) -> usize {
        let mut removed = 0usize;
        let before = self.memory.len();
        self.memory.retain(|id, _| keep.contains(id));
        let dropped: Vec<Hash32> = self
            .coded
            .keys()
            .filter(|id| !keep.contains(*id))
            .copied()
            .collect();
        for id in dropped {
            self.forget_coding(&id);
        }
        self.coded_order.retain(|id| keep.contains(id));
        removed = removed.saturating_add(before.saturating_sub(self.memory.len()));
        if let Some(root) = &self.root {
            if let Ok(entries) = fs::read_dir(root) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }
                    let known = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .and_then(|s| hex::decode(s).ok())
                        .and_then(|bytes| Hash32::try_from(bytes.as_slice()).ok())
                        .is_some_and(|id| keep.contains(&id));
                    if !known && fs::remove_file(&path).is_ok() {
                        removed = removed.saturating_add(1);
                    }
                }
            }
            self.total_bytes = scan_disk_bytes(root);
        } else {
            self.total_bytes = self
                .memory
                .values()
                .map(|bytes| charged_bytes(u64::try_from(bytes.len()).unwrap_or(0)))
                .fold(0u64, u64::saturating_add);
        }
        removed
    }

    /// Delete every object and the directory itself.
    pub fn wipe(&mut self) -> Result<(), String> {
        self.memory.clear();
        self.coded.clear();
        self.coded_order.clear();
        self.coded_bytes = 0;
        self.total_bytes = 0;
        if let Some(root) = &self.root {
            if root.exists() {
                fs::remove_dir_all(root)
                    .map_err(|e| format!("garden content directory cannot be removed: {e}"))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garden_store_reads_back_what_it_stored_under_the_budlum_content_id() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("garden");
        let mut store = GardenContentStore::open(Some(&root), 1024).unwrap();
        let id = store.put(b"hello garden").unwrap();
        assert_eq!(id, ContentId::of(b"hello garden").0);
        assert_eq!(store.get(&id).unwrap(), b"hello garden");
        assert!(store.contains(&id));
        assert_eq!(store.stored_len(&id), Some(12));
        assert_eq!(store.stored_len(&[0u8; 32]), None);
        assert!(store.put(&[0u8; 2048]).is_err());
        assert!(store.put(&[]).is_err());
    }

    #[test]
    fn garden_store_refuses_bytes_that_do_not_match_the_content_id() {
        let mut store = GardenContentStore::open(None, 1024).unwrap();
        let id = ContentId::of(b"real").0;
        assert!(store.put_verified(&id, b"fake").is_err());
        assert!(!store.contains(&id));
        store.put_verified(&id, b"real").unwrap();
        assert_eq!(store.get(&id).unwrap(), b"real");
    }

    #[test]
    fn garden_store_detects_bytes_changed_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("garden");
        let mut store = GardenContentStore::open(Some(&root), 1024).unwrap();
        let id = store.put(b"original").unwrap();
        fs::write(root.join(hex::encode(id)), b"tampered").unwrap();
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn garden_store_wipe_leaves_nothing_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("garden");
        let mut store = GardenContentStore::open(Some(&root), 1024).unwrap();
        let id = store.put(b"gone soon").unwrap();
        store.wipe().unwrap();
        assert!(!root.exists());
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn garden_store_prunes_unaccounted_files_on_startup() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("garden");
        let mut store = GardenContentStore::open(Some(&root), 1024).unwrap();
        let kept = store.put(b"published").unwrap();
        let orphan = store.put(b"unaccounted").unwrap();
        let stale_tmp = root.join(format!("{}.tmp.1.0", hex::encode(kept)));
        fs::write(&stale_tmp, b"partial").unwrap();
        let mut keep = BTreeSet::new();
        keep.insert(kept);
        let removed = store.prune_unaccounted(&keep);
        assert_eq!(removed, 2);
        assert!(store.contains(&kept));
        assert!(!store.contains(&orphan));
        assert!(!stale_tmp.exists());
    }

    #[test]
    fn garden_store_put_verified_checks_size_before_hashing() {
        let mut store = GardenContentStore::open(None, 8).unwrap();
        let oversized = vec![7u8; 16];
        let id = ContentId::of(&oversized).0;
        let err = store.put_verified(&id, &oversized).unwrap_err();
        assert!(err.contains("outside 1..=8"), "{err}");
        assert!(!store.contains(&id));
    }

    #[test]
    fn garden_store_enforces_local_total_byte_ceiling_and_reclaims_on_remove() {
        let floor = crate::garden::types::MIN_PUBLICATION_CHARGE;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("garden");
        let mut store = GardenContentStore::open_with_limit(Some(&root), 16, floor + 1024).unwrap();
        let a = store.put(&[1u8; 12]).unwrap();
        assert_eq!(store.total_bytes(), floor);
        // Re-putting identical bytes is idempotent and does not double-count.
        assert_eq!(store.put(&[1u8; 12]).unwrap(), a);
        assert_eq!(store.total_bytes(), floor);
        // A second 12-byte object still costs `floor` bytes on disk, exceeding
        // `floor + 1024`, so tiny-object amplification is refused.
        let err = store.put(&[2u8; 12]).unwrap_err();
        assert!(err.contains("local storage limit"), "{err}");
        assert_eq!(store.total_bytes(), floor);
        // Atomic `write_object_file_blocking` claims `Ok(true)` once and `Ok(false)` on duplicate,
        // and stale `<64hex>.tmp.*` files are purged on reopen without inflating quota.
        let dup_id = ContentId::of(&[9u8; 12]).0;
        let dup_path = root.join(hex::encode(dup_id));
        assert!(
            GardenContentStore::write_object_file_blocking(dup_path.clone(), vec![9u8; 12])
                .unwrap()
        );
        assert!(
            !GardenContentStore::write_object_file_blocking(dup_path.clone(), vec![9u8; 12])
                .unwrap()
        );
        let stale = root.join(format!("{}.tmp.99999.0", hex::encode([0xABu8; 32])));
        fs::write(&stale, b"partial").unwrap();
        let reopened = GardenContentStore::open_with_limit(Some(&root), 16, floor * 4).unwrap();
        assert!(
            !stale.exists(),
            "orphan .tmp.* file must be cleaned on open"
        );
        assert_eq!(reopened.total_bytes(), floor * 2);
        fs::remove_file(&dup_path).unwrap();
        // Removing `a` reclaims the full floor charge so the new object fits.
        store.remove(&a);
        assert_eq!(store.total_bytes(), 0);
        let b = store.put(&[2u8; 12]).unwrap();
        assert_eq!(store.total_bytes(), floor);
        assert!(store.contains(&b));
        // Re-opening from disk recovers the accurate floor-charged byte count.
        let reopened = GardenContentStore::open_with_limit(Some(&root), 16, 2 * floor).unwrap();
        assert_eq!(reopened.total_bytes(), floor);
        assert!(reopened.can_fit(1));
        assert!(reopened.can_fit(floor));
        assert!(!reopened.can_fit(floor + 1));
    }

    #[test]
    fn reserve_background_write_is_idempotent_when_object_already_on_disk() {
        let floor = crate::garden::types::MIN_PUBLICATION_CHARGE;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("garden");
        // Budget fits one object plus spare headroom, not two full charges.
        let mut store = GardenContentStore::open_with_limit(Some(&root), 64, floor + 512).unwrap();
        let payload = [0x42u8; 24];
        let id = store.put(&payload).unwrap();
        assert_eq!(store.total_bytes(), floor);

        // Re-reserving the exact already-stored object must succeed without
        // charging a second slot or pushing total_bytes past the cap.
        let reservation = store
            .reserve_background_write(id, &payload)
            .expect("idempotent background deposit for an existing object must fit");
        assert!(
            reservation.is_none(),
            "existing valid object need not schedule another disk write"
        );
        assert_eq!(store.total_bytes(), floor);
    }

    #[test]
    fn put_codes_the_object_and_get_coded_rebuilds_it_from_symbols() {
        let mut store = GardenContentStore::open(None, 1024 * 1024).unwrap();
        // Not a round number of symbols, and compressible, so the coded
        // object is genuinely a different length from the content.
        let payload: Vec<u8> = (0..9_001u32)
            .map(|i| u8::try_from(i % 7).unwrap_or(0))
            .collect();
        let id = store.put(&payload).unwrap();

        let parts = store.part_counts();
        assert_eq!(parts.objects_coded, 1, "put must code the object once");
        assert!(parts.segments_coded >= 1, "the object must be segmented");
        assert!(
            parts.symbols_made > parts.segments_coded,
            "every segment must carry repair symbols beyond its source ones"
        );
        assert_eq!(
            parts.symbol_roots, parts.segments_coded,
            "custody must build one symbol root per segment"
        );

        let record = store.record_of(&id).expect("a coded object has a record");
        assert_eq!(
            record.content_id.len,
            u64::try_from(payload.len()).unwrap(),
            "the record must name the content length"
        );

        // The read goes through the fountain decoder, not the cached bytes.
        let seen = store.get_coded(&id).expect("the symbols must decode");
        assert_eq!(seen, payload, "B.U.D. 3.0 must return the original bytes");
        let after = store.part_counts();
        assert_eq!(after.objects_viewed, 1, "the view path must be counted");
        assert_eq!(
            after.symbols_used, parts.symbols_made,
            "the decode must consume the symbols the upload produced"
        );

        // Dropping the object drops its coding, but not the record of work.
        store.remove(&id);
        assert!(store.get_coded(&id).is_none(), "the coding must go too");
        assert_eq!(
            store.part_counts().objects_coded,
            1,
            "counters record work done, so removal must not rewind them"
        );
    }
}
