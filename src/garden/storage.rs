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
use crate::storage::content_id::ContentId;
use std::collections::{BTreeMap, BTreeSet};
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

/// Where the objects of one Garden live on this node.
#[derive(Debug)]
pub struct GardenContentStore {
    root: Option<PathBuf>,
    memory: BTreeMap<Hash32, Vec<u8>>,
    max_object_bytes: usize,
    max_total_bytes: u64,
    total_bytes: u64,
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
        Ok(content_id)
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
        let len = charged_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        match self.path_of(&content_id) {
            Some(path) => {
                if !self.can_fit(len) {
                    return Err(format!(
                        "garden local storage limit of {} bytes reached",
                        self.max_total_bytes
                    ));
                }
                self.total_bytes = self.total_bytes.saturating_add(len);
                Ok(Some((path, len)))
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
                Ok(None)
            }
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
}
