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
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Where the objects of one Garden live on this node.
#[derive(Debug)]
pub struct GardenContentStore {
    root: Option<PathBuf>,
    memory: BTreeMap<Hash32, Vec<u8>>,
    max_object_bytes: usize,
}

impl GardenContentStore {
    /// Open a store under `root`. `None` keeps the objects in memory only.
    pub fn open(root: Option<&Path>, max_object_bytes: usize) -> Result<Self, String> {
        if let Some(root) = root {
            fs::create_dir_all(root)
                .map_err(|e| format!("garden content directory cannot be created: {e}"))?;
        }
        Ok(Self {
            root: root.map(Path::to_path_buf),
            memory: BTreeMap::new(),
            max_object_bytes,
        })
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
        match self.path_of(&content_id) {
            Some(path) => fs::write(&path, bytes)
                .map_err(|e| format!("garden object cannot be written: {e}"))?,
            None => {
                self.memory.insert(content_id, bytes.to_vec());
            }
        }
        Ok(content_id)
    }

    /// Store bytes received from a peer, but only under the id they hash to.
    pub fn put_verified(&mut self, expected: &Hash32, bytes: &[u8]) -> Result<(), String> {
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
        match self.path_of(content_id) {
            Some(path) => path.is_file(),
            None => self.memory.contains_key(content_id),
        }
    }

    /// Drop one object, when this node no longer holds it.
    pub fn remove(&mut self, content_id: &Hash32) {
        match self.path_of(content_id) {
            Some(path) => {
                let _ = fs::remove_file(path);
            }
            None => {
                self.memory.remove(content_id);
            }
        }
    }

    /// Delete every object and the directory itself.
    pub fn wipe(&mut self) -> Result<(), String> {
        self.memory.clear();
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
}
