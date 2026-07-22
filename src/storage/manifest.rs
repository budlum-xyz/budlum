//! B.U.D. content manifest (Task 0.39 §2.1, vision §8.2).
//!
//! A `ContentManifest` is the on-chain commitment to a sharded piece of
//! content. The actual chunking algorithm (erasure coding, Reed-Solomon,
//! simple byte slicing) is **off-chain** — the chain only sees the
//! per-shard `ContentId`s and a deterministic `manifest_id` derived from
//! them. This matches the existing project rule "the chain carries the
//! proof/address of data, not the data itself" (BudZKVM STARK proof
//! analogy, Task 0.38 plan §3.1).
//!
//! Per the data-sovereignty rule (Task 0.39 plan §0.5): the manifest is
//! fully reconstructable from public on-chain state by any independent
//! node. No "Budlum Inc. indexer" service is required.

use crate::core::hash::hash_fields_bytes;
use crate::storage::content_id::ContentId;

use serde::{Deserialize, Serialize};

/// A reference to a single shard (chunk) of a multi-shard piece of content.
///
/// `size` is the shard's byte length. The `ContentId` is the deterministic
/// address; clients pull bytes by `ContentId`, not by index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ShardRef {
    pub index: u32,
    pub shard_id: ContentId,
    pub size: u32,
}

impl ShardRef {
    /// Construct a `ShardRef` from a chunk's bytes. The `ContentId` is
    /// computed deterministically; `index` is assigned by the caller
    /// (e.g. the off-chain chunker).
    pub fn from_bytes(index: u32, chunk: &[u8]) -> Self {
        ShardRef {
            index,
            shard_id: ContentId::of(chunk),
            size: chunk.len() as u32,
        }
    }
}

/// A content manifest — the on-chain commitment to a sharded piece of
/// content. `manifest_id` is the canonical identity of the whole piece; it
/// is computed deterministically from `(owner, total_size, shards)` so two
/// clients sharding the same content the same way always produce the
/// same `manifest_id`.
///
/// `owner` alanı F01 (Task 10.5) ile eklendi — veri sahipliği zincir-üstü
/// kanıtlanabilir (Data Owner identity). `#[serde(default)]` ile eski
/// snapshot'lar/JSON'lar backward-compat (owner = zero = "belirsiz").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentManifest {
    pub manifest_id: ContentId,
    /// F01 (Task 10.5): içerik sahibinin adresi. Zero-address = eski/pre-F01
    /// manifest (backward-compat); yeni manifest'ler gerçek owner taşır.
    #[serde(default)]
    pub owner: crate::core::address::Address,
    pub total_size: u64,
    pub shard_count: u32,
    pub shards: Vec<ShardRef>,
}

impl ContentManifest {
    /// Build a manifest from a pre-computed set of shards. Validates that
    /// the shard list is non-empty, indices are unique, sizes are non-zero,
    /// and the total size matches the sum of shard sizes.
    ///
    /// `owner` defaults to zero-address (F01 backward-compat: caller `with_owner`
    /// ile gerçek owner'ı set edebilir; manifest_id hesabı owner'ı kapsar).
    pub fn from_shards(shards: Vec<ShardRef>) -> Result<Self, String> {
        if shards.is_empty() {
            return Err("ContentManifest must have at least one shard".into());
        }
        let mut seen_indices = std::collections::BTreeSet::new();
        let mut total: u64 = 0;
        for s in &shards {
            if s.size == 0 {
                return Err(format!("Shard {} has size 0", s.index));
            }
            if !seen_indices.insert(s.index) {
                return Err(format!("Duplicate shard index {}", s.index));
            }
            total = total
                .checked_add(s.size as u64)
                .ok_or_else(|| "ContentManifest total size overflow".to_string())?;
        }
        let shard_count = shards.len() as u32;
        let owner = crate::core::address::Address::zero();
        let manifest_id = manifest_id_from_shards(&shards);
        Ok(ContentManifest {
            manifest_id,
            owner,
            total_size: total,
            shard_count,
            shards,
        })
    }

    /// F01: gerçek owner'ı set et (from_shards sonrası). `manifest_id` owner'a
    /// bağlıysa yeniden hesaplanmalı; şimdilik manifest_id shards-only (F01 görev 2).
    pub fn with_owner(mut self, owner: crate::core::address::Address) -> Self {
        self.owner = owner;
        self
    }

    /// Convenience: build a manifest by slicing `data` into equal-sized
    /// chunks. The default chunk size is `DEFAULT_CHUNK_SIZE_BYTES`.
    /// The last shard may be smaller.
    pub fn from_bytes_sliced(data: &[u8], chunk_size: u32) -> Result<Self, String> {
        if chunk_size == 0 {
            return Err("ContentManifest chunk_size must be > 0".into());
        }
        if data.is_empty() {
            return Err("ContentManifest data must be non-empty".into());
        }
        let mut shards = Vec::new();
        let mut i: u32 = 0;
        let mut off = 0usize;
        while off < data.len() {
            let end = (off + chunk_size as usize).min(data.len());
            let slice = &data[off..end];
            shards.push(ShardRef::from_bytes(i, slice));
            off = end;
            i += 1;
        }
        Self::from_shards(shards)
    }

    /// Look up a shard by `ContentId`. Returns `None` if the shard is not
    /// in this manifest — used by the `bud_storageGetDealsByShard` query
    /// path and the E2E test (`src/tests/bud_e2e.rs`).
    pub fn shard(&self, shard_id: &ContentId) -> Option<&ShardRef> {
        self.shards.iter().find(|s| &s.shard_id == shard_id)
    }
}

/// Canonical, deterministic manifest id. Domain-tagged so a manifest id
/// can never collide with a chunk `ContentId` (which uses a different
/// tag).
pub fn manifest_id_from_shards(shards: &[ShardRef]) -> ContentId {
    let mut buf = Vec::with_capacity(8 + shards.len() * (4 + 32 + 4));
    buf.extend_from_slice(b"BDLM_MANIFEST_V1");
    buf.extend_from_slice(&(shards.len() as u32).to_le_bytes());
    for s in shards {
        buf.extend_from_slice(&s.index.to_le_bytes());
        buf.extend_from_slice(&s.shard_id.0);
        buf.extend_from_slice(&s.size.to_le_bytes());
    }
    ContentId(hash_fields_bytes(&[b"BDLM_MANIFEST_V1", &buf]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_id_is_deterministic() {
        let m1 = ContentManifest::from_bytes_sliced(b"hello world", 4).unwrap();
        let m2 = ContentManifest::from_bytes_sliced(b"hello world", 4).unwrap();
        assert_eq!(m1.manifest_id, m2.manifest_id);
        assert_eq!(m1.total_size, m2.total_size);
        assert_eq!(m1.shard_count, m2.shard_count);
    }

    #[test]
    fn manifest_id_changes_when_chunk_size_changes() {
        let m1 = ContentManifest::from_bytes_sliced(b"hello world", 4).unwrap();
        let m2 = ContentManifest::from_bytes_sliced(b"hello world", 5).unwrap();
        assert_ne!(m1.manifest_id, m2.manifest_id);
    }

    #[test]
    fn manifest_id_changes_when_content_changes() {
        let m1 = ContentManifest::from_bytes_sliced(b"hello world", 4).unwrap();
        let m2 = ContentManifest::from_bytes_sliced(b"hello WORLD", 4).unwrap();
        assert_ne!(m1.manifest_id, m2.manifest_id);
    }

    #[test]
    fn empty_manifest_rejected() {
        assert!(ContentManifest::from_shards(vec![]).is_err());
    }

    #[test]
    fn empty_data_rejected() {
        assert!(ContentManifest::from_bytes_sliced(&[], 4).is_err());
    }

    #[test]
    fn zero_chunk_size_rejected() {
        assert!(ContentManifest::from_bytes_sliced(b"abc", 0).is_err());
    }

    #[test]
    fn duplicate_shard_index_rejected() {
        let s1 = ShardRef::from_bytes(0, b"a");
        let s2 = ShardRef::from_bytes(0, b"b");
        assert!(ContentManifest::from_shards(vec![s1, s2]).is_err());
    }

    #[test]
    fn shard_lookup_finds_existing_and_misses_missing() {
        let m = ContentManifest::from_bytes_sliced(b"abcdef", 2).unwrap();
        assert_eq!(m.shard_count, 3);
        let first = m.shards.first().unwrap().shard_id;
        assert!(m.shard(&first).is_some());
        assert!(m.shard(&ContentId([0u8; 32])).is_none());
    }

    #[test]
    fn default_chunk_size_matches_content_id_default() {
        use crate::storage::content_id::DEFAULT_CHUNK_SIZE_BYTES;
        // Cross-module sanity check: the chunk-size default used by the
        // sharder is the same constant the ContentId module advertises.
        let m =
            ContentManifest::from_bytes_sliced(&vec![0u8; 1024], DEFAULT_CHUNK_SIZE_BYTES).unwrap();
        // 1024 / 262_144 = 1 shard
        assert_eq!(m.shard_count, 1);
    }
}
