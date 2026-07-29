//! B.U.D. content manifest.
//!
//! A `ContentManifest` is the on-chain commitment to a sharded piece of
//! Content. The actual chunking algorithm (erasure coding, Reed-Solomon,
//! Simple byte slicing) is **off-chain** — the chain only sees the
//! Per-shard `ContentId`s and a deterministic `manifest_id` derived from
//! Them. This matches the existing project rule "the chain carries the
//! Proof/address of data, not the data itself" (BudZKVM STARK proof
//! Analogy, plan §3.1).
//!
//! Per the data-sovereignty rule (plan §0.5): the manifest is
//! Fully reconstructable from public on-chain state by any independent
//! Node. No "Budlum Inc. indexer" service is required.

use crate::core::hash::hash_fields_bytes;
use crate::storage::content_id::ContentId;

use serde::{Deserialize, Serialize};

/// A reference to a single shard (chunk) of a multi-shard piece of content.
///
/// `size` is the shard's byte length. The `ContentId` is the deterministic
/// Address; clients pull bytes by `ContentId`, not by index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ShardRef {
    pub index: u32,
    pub shard_id: ContentId,
    pub size: u32,
    /// Whether this shard carries content or redundancy.
    ///
    /// Defaults to `Data`, so manifests written before erasure coding
    /// deserialize unchanged and keep behaving as pure replication.
    #[serde(default)]
    pub kind: ShardKind,
}

/// What a shard contributes to an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum ShardKind {
    /// A slice of the object itself.
    #[default]
    Data,
    /// Redundancy computed over the data shards. Any `k` of the `n` total
    /// shards reconstruct the object, whichever `k` survive.
    Parity,
}

impl ShardRef {
    /// Construct a `ShardRef` from a chunk's bytes. The `ContentId` is
    /// Computed deterministically; `index` is assigned by the caller
    /// (e.g. the off-chain chunker).
    pub fn from_bytes(index: u32, chunk: &[u8]) -> Self {
        ShardRef {
            kind: ShardKind::Data,
            index,
            shard_id: ContentId::of(chunk),
            size: chunk.len() as u32,
        }
    }
}

/// A content manifest — the on-chain commitment to a sharded piece of
/// Content. `manifest_id` is the canonical identity of the whole piece; it
/// Is computed deterministically from `(owner, total_size, shards)` so two
/// Clients sharding the same content the same way always produce the
/// Same `manifest_id`.
///
/// `owner` alanı F01 ile eklendi — veri sahipliği zincir-üstü
/// Kanıtlanabilir (Data Owner identity). `#[serde(default)]` ile eski
/// Snapshot'lar/JSON'lar backward-compat (owner = zero = "belirsiz").
/// Redundancy scheme for an object: any `k` of `n` shards reconstruct it.
///
/// Replication is the degenerate case `k = n = shard_count`, where losing one
/// shard loses part of the object and durability has to come from storing the
/// whole thing again. Erasure coding reaches the same durability at a fraction
/// of the stored bytes, which is the point of `docs/BUD_STORAGE_ROADMAP.md`
/// Gap 3 — and it is what makes Gap 4 expressible at all, because a repair
/// trigger needs something to reconstruct *from*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureScheme {
    /// Shards required to reconstruct. Must be at least 1 and at most `n`.
    pub k: u32,
    /// Total shards written, data plus parity.
    pub n: u32,
}

impl ErasureScheme {
    /// Plain replication: every shard is data, nothing reconstructs anything.
    pub fn replication(shard_count: u32) -> Self {
        Self {
            k: shard_count,
            n: shard_count,
        }
    }

    pub fn parity_count(&self) -> u32 {
        self.n.saturating_sub(self.k)
    }

    /// How many shards may be lost before the object is unrecoverable.
    pub fn loss_tolerance(&self) -> u32 {
        self.parity_count()
    }

    /// Bytes stored per byte of content, as a ratio scaled by 1000 to stay in
    /// integer arithmetic. Replication of 3 is 3000; a (4,6) code is 1500.
    pub fn overhead_per_mille(&self) -> u32 {
        if self.k == 0 {
            return u32::MAX;
        }
        (self.n.saturating_mul(1000)) / self.k
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.k == 0 {
            return Err("erasure scheme k must be at least 1".into());
        }
        if self.n < self.k {
            return Err(format!(
                "erasure scheme n {} is below k {}; n counts data plus parity",
                self.n, self.k
            ));
        }
        Ok(())
    }
}

impl Default for ErasureScheme {
    fn default() -> Self {
        // A manifest written before erasure coding has no scheme field; the
        // serde default has to mean "replication", which is what those
        // manifests actually were.
        Self { k: 1, n: 1 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentManifest {
    pub manifest_id: ContentId,
    /// F01: içerik sahibinin adresi. Zero-address = eski/pre-F01
    /// Manifest (backward-compat); yeni manifest'ler gerçek owner taşır.
    #[serde(default)]
    pub owner: crate::core::address::Address,
    pub total_size: u64,
    pub shard_count: u32,
    pub shards: Vec<ShardRef>,
    /// Redundancy scheme. Absent in manifests written before erasure coding;
    /// those deserialize to replication and behave exactly as they did.
    #[serde(default)]
    pub erasure: ErasureScheme,
    /// Length of the *object*, as opposed to `total_size`, which is the sum
    /// of the stored shard sizes.
    ///
    /// Under replication the two are the same number and nothing needed to
    /// tell them apart. Erasure coding separates them twice over: parity
    /// shards are stored bytes that are not object bytes, and the last data
    /// stripe is zero-padded to keep the shards equal-length, which
    /// Reed-Solomon requires. A reconstructor holds only the manifest, so
    /// without this field it cannot know where the object ends and the
    /// padding begins — it would hand back trailing zeroes as content.
    ///
    /// Zero means "not recorded", which is how every manifest written before
    /// this field deserializes; [`ContentManifest::content_size`] reads it as
    /// `total_size` in that case, which is what those manifests meant.
    #[serde(default)]
    pub content_size: u64,
}

impl ContentManifest {
    /// Build a manifest from a pre-computed set of shards. Validates that
    /// The shard list is non-empty, indices are unique, sizes are non-zero,
    /// And the total size matches the sum of shard sizes.
    ///
    /// `owner` defaults to zero-address (F01 backward-compat: caller `with_owner`
    /// Ile gerçek owner'ı set edebilir; manifest_id hesabı owner'ı kapsar).
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
        let erasure = ErasureScheme::replication(shard_count);
        let manifest_id = manifest_id_from_parts(&shards, &erasure);
        Ok(ContentManifest {
            manifest_id,
            owner,
            total_size: total,
            shard_count,
            erasure,
            content_size: total,
            shards,
        })
    }

    /// The object's byte length.
    ///
    /// Falls back to `total_size` for manifests written before
    /// `content_size` existed. Those were replication-only, where the two are
    /// the same number, so the fallback is their actual meaning rather than a
    /// guess.
    pub fn content_size(&self) -> u64 {
        if self.content_size == 0 {
            self.total_size
        } else {
            self.content_size
        }
    }

    /// Record the object's byte length, for manifests whose stored bytes
    /// exceed their content (erasure coding, or a padded tail stripe).
    ///
    /// Refuses a length larger than the stored bytes: an object cannot be
    /// bigger than the shards holding it, and a reconstructor trusting such a
    /// claim would read past the data it recovered.
    pub fn with_content_size(mut self, content_size: u64) -> Result<Self, String> {
        if content_size == 0 {
            return Err("content_size must be greater than zero".into());
        }
        if content_size > self.total_size {
            return Err(format!(
                "content_size {content_size} exceeds the {} bytes stored across shards",
                self.total_size
            ));
        }
        self.content_size = content_size;
        self.manifest_id = manifest_id_from_parts(&self.shards, &self.erasure);
        Ok(self)
    }

    /// Recompute the canonical id and check it against the one carried.
    ///
    /// `manifest_id` is the key every registry, deal and challenge indexes
    /// by, and it arrives over RPC inside a caller-supplied struct. Nothing
    /// recomputed it, so a caller could register a manifest under any id it
    /// liked — including one already meaningful to someone else, or one
    /// chosen so a later honest registration of the real content collides
    /// with a squatted entry that `register_manifest` would then keep,
    /// because registration is idempotent and first-writer-wins.
    pub fn verify_id(&self) -> Result<(), String> {
        let expected = manifest_id_from_parts(&self.shards, &self.erasure);
        if expected != self.manifest_id {
            return Err(format!(
                "manifest_id {} does not match the {} its contents derive",
                hex::encode(self.manifest_id.0),
                hex::encode(expected.0)
            ));
        }
        Ok(())
    }

    /// Full structural check: the id matches, the shard list is coherent, and
    /// the declared erasure scheme is one the shard list can deliver.
    ///
    /// This is what an untrusted manifest has to pass before the chain stores
    /// it. The individual checks already existed on the construction paths;
    /// what was missing was anything applying them to a manifest that arrived
    /// fully formed instead of being built locally.
    pub fn validate_untrusted(&self) -> Result<(), String> {
        if self.shards.is_empty() {
            return Err("ContentManifest must have at least one shard".into());
        }
        if self.shards.len() as u32 != self.shard_count {
            return Err(format!(
                "shard_count {} does not match the {} shards present",
                self.shard_count,
                self.shards.len()
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut total: u64 = 0;
        for s in &self.shards {
            if s.size == 0 {
                return Err(format!("Shard {} has size 0", s.index));
            }
            if !seen.insert(s.index) {
                return Err(format!("Duplicate shard index {}", s.index));
            }
            total = total
                .checked_add(s.size as u64)
                .ok_or_else(|| "ContentManifest total size overflow".to_string())?;
        }
        if total != self.total_size {
            return Err(format!(
                "total_size {} does not match the {total} bytes the shards sum to",
                self.total_size
            ));
        }
        if self.content_size > self.total_size {
            return Err(format!(
                "content_size {} exceeds the {} bytes stored across shards",
                self.content_size, self.total_size
            ));
        }
        self.erasure.validate()?;
        if self.erasure.n != self.shard_count {
            return Err(format!(
                "erasure n {} does not match shard_count {}",
                self.erasure.n, self.shard_count
            ));
        }
        let data = self
            .shards
            .iter()
            .filter(|s| s.kind == ShardKind::Data)
            .count() as u32;
        if data != self.erasure.k {
            return Err(format!(
                "erasure k {} does not match the {data} data shards present",
                self.erasure.k
            ));
        }
        self.verify_id()
    }

    /// Attach an erasure scheme, validating it against the shard list.
    ///
    /// The counts have to line up: `n` is every shard, `k` is the data shards,
    /// and the difference is the parity shards actually present. A manifest
    /// that claims a tolerance it cannot deliver is worse than one that claims
    /// none, because a repair trigger would read the claim and conclude the
    /// object is still safe.
    pub fn with_erasure(mut self, erasure: ErasureScheme) -> Result<Self, String> {
        erasure.validate()?;
        if erasure.n != self.shard_count {
            return Err(format!(
                "erasure n {} does not match shard_count {}",
                erasure.n, self.shard_count
            ));
        }
        let data = self
            .shards
            .iter()
            .filter(|s| s.kind == ShardKind::Data)
            .count() as u32;
        let parity = self
            .shards
            .iter()
            .filter(|s| s.kind == ShardKind::Parity)
            .count() as u32;
        if data != erasure.k {
            return Err(format!(
                "erasure k {} does not match the {data} data shards present",
                erasure.k
            ));
        }
        if parity != erasure.parity_count() {
            return Err(format!(
                "erasure declares {} parity shards but {parity} are present",
                erasure.parity_count()
            ));
        }
        self.erasure = erasure;
        self.manifest_id = manifest_id_from_parts(&self.shards, &self.erasure);
        Ok(self)
    }

    /// Whether an object is still reconstructible with `live` shards left.
    pub fn is_recoverable(&self, live: u32) -> bool {
        live >= self.erasure.k
    }

    /// Whether redundancy has fallen far enough to start a repair.
    ///
    /// Repair has to begin *before* the object becomes unrecoverable —
    /// waiting until `live == k` means the next loss is fatal and there is no
    /// time to rebuild. `margin` is how much headroom to keep; Storj triggers
    /// on a safety threshold above `k` for the same reason.
    ///
    /// Returns false once the object is already unrecoverable: there is
    /// nothing to reconstruct from, and a repair deal opened then would just
    /// burn an operator bond.
    pub fn needs_repair(&self, live: u32, margin: u32) -> bool {
        if live < self.erasure.k {
            return false;
        }
        live < self.erasure.k.saturating_add(margin)
    }

    /// F01: gerçek owner'ı set et (from_shards sonrası). `manifest_id` owner'a
    /// Bağlıysa yeniden hesaplanmalı; şimdilik manifest_id shards-only (F01 görev 2).
    pub fn with_owner(mut self, owner: crate::core::address::Address) -> Self {
        self.owner = owner;
        self
    }

    /// Convenience: build a manifest by slicing `data` into equal-sized
    /// Chunks. The default chunk size is `DEFAULT_CHUNK_SIZE_BYTES`.
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
    /// In this manifest — used by the `bud_storageGetDealsByShard` query
    /// Path and the E2E test (`src/tests/bud_e2e.rs`).
    pub fn shard(&self, shard_id: &ContentId) -> Option<&ShardRef> {
        self.shards.iter().find(|s| &s.shard_id == shard_id)
    }
}

/// Canonical, deterministic manifest id. Domain-tagged so a manifest id
/// Can never collide with a chunk `ContentId` (which uses a different
/// Tag).
///
/// Kept for manifests that predate erasure coding, where every shard was
/// data and the scheme was replication. New code should call
/// [`manifest_id_from_parts`], which also binds the redundancy claim.
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

/// Canonical manifest id covering the redundancy claim as well as the shards.
///
/// V1 hashed `(index, shard_id, size)` per shard and nothing else. That was
/// complete while replication was the only scheme, but erasure coding added
/// two fields that change what the manifest *means* without changing any
/// byte V1 hashed:
///
/// * `kind` — relabelling a data shard as parity, or the reverse, alters
///   which shards a reconstructor treats as content and which it treats as
///   redundancy.
/// * `erasure` — `k` is the number a repair trigger compares against. A
///   manifest claiming `k = 1` when four shards are needed reads as safe at
///   one surviving shard, so no repair opens and the object is lost quietly.
///
/// Both were outside the commitment, so two manifests with the same id could
/// disagree about them, and whichever registered first would define the
/// entry. Binding them makes the id mean the whole claim.
pub fn manifest_id_from_parts(shards: &[ShardRef], erasure: &ErasureScheme) -> ContentId {
    let mut buf = Vec::with_capacity(32 + shards.len() * (4 + 32 + 4 + 1));
    buf.extend_from_slice(b"BDLM_MANIFEST_V2");
    buf.extend_from_slice(&(shards.len() as u32).to_le_bytes());
    for s in shards {
        buf.extend_from_slice(&s.index.to_le_bytes());
        buf.extend_from_slice(&s.shard_id.0);
        buf.extend_from_slice(&s.size.to_le_bytes());
        buf.push(match s.kind {
            ShardKind::Data => 0u8,
            ShardKind::Parity => 1u8,
        });
    }
    buf.extend_from_slice(&erasure.k.to_le_bytes());
    buf.extend_from_slice(&erasure.n.to_le_bytes());
    ContentId(hash_fields_bytes(&[b"BDLM_MANIFEST_V2", &buf]))
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
        // Sharder is the same constant the ContentId module advertises.
        let m =
            ContentManifest::from_bytes_sliced(&vec![0u8; 1024], DEFAULT_CHUNK_SIZE_BYTES).unwrap();
        // 1024 / 262_144 = 1 shard
        assert_eq!(m.shard_count, 1);
    }

    fn shard(index: u32, kind: ShardKind) -> ShardRef {
        ShardRef {
            index,
            shard_id: ContentId::of(&index.to_le_bytes()),
            size: 64,
            kind,
        }
    }

    /// Erasure coding stores less than replication for the same loss
    /// tolerance. That is the whole reason for Gap 3.
    #[test]
    fn erasure_costs_less_than_replication_for_the_same_tolerance() {
        // Replication of 3: tolerate 2 losses, store 3x.
        let repl = ErasureScheme { k: 1, n: 3 };
        // A (4,6) code: tolerate 2 losses, store 1.5x.
        let coded = ErasureScheme { k: 4, n: 6 };

        assert_eq!(repl.loss_tolerance(), coded.loss_tolerance());
        assert_eq!(repl.overhead_per_mille(), 3000);
        assert_eq!(coded.overhead_per_mille(), 1500);
        assert!(coded.overhead_per_mille() < repl.overhead_per_mille());
    }

    /// A scheme that claims more tolerance than its shards can deliver must
    /// be rejected. A false claim is worse than none: a repair trigger reads
    /// it and concludes the object is safe.
    #[test]
    fn a_manifest_cannot_claim_parity_it_does_not_have() {
        let shards = vec![
            shard(0, ShardKind::Data),
            shard(1, ShardKind::Data),
            shard(2, ShardKind::Data),
        ];
        let m = ContentManifest::from_shards(shards).unwrap();
        // Three data shards, no parity. Claiming k=2 means claiming one
        // parity shard that is not there; the mismatch is caught on the data
        // count first, which is the same disagreement seen from the other
        // side.
        let err = m
            .with_erasure(ErasureScheme { k: 2, n: 3 })
            .expect_err("claiming tolerance with no parity shards must fail");
        assert!(
            err.contains("data shards present") || err.contains("parity"),
            "the error must name the count that disagrees, got: {err}"
        );

        // And the honest description of the same shards is accepted.
        let m2 = ContentManifest::from_shards(vec![
            shard(0, ShardKind::Data),
            shard(1, ShardKind::Data),
            shard(2, ShardKind::Data),
        ])
        .unwrap();
        m2.with_erasure(ErasureScheme { k: 3, n: 3 })
            .expect("three data shards, no tolerance claimed");
    }

    /// And the counts have to agree with the shard list.
    #[test]
    fn erasure_counts_must_match_the_shards() {
        let shards = vec![
            shard(0, ShardKind::Data),
            shard(1, ShardKind::Data),
            shard(2, ShardKind::Parity),
        ];
        let m = ContentManifest::from_shards(shards).unwrap();
        assert!(m
            .clone()
            .with_erasure(ErasureScheme { k: 2, n: 4 })
            .is_err());
        assert!(m
            .clone()
            .with_erasure(ErasureScheme { k: 3, n: 3 })
            .is_err());
        m.with_erasure(ErasureScheme { k: 2, n: 3 })
            .expect("2 data + 1 parity out of 3 is consistent");
    }

    #[test]
    fn a_degenerate_scheme_is_rejected() {
        assert!(ErasureScheme { k: 0, n: 3 }.validate().is_err());
        assert!(ErasureScheme { k: 4, n: 3 }.validate().is_err());
        ErasureScheme { k: 3, n: 3 }.validate().unwrap();
    }

    /// Recovery is possible while at least `k` shards survive.
    #[test]
    fn recoverability_tracks_k() {
        let shards = vec![
            shard(0, ShardKind::Data),
            shard(1, ShardKind::Data),
            shard(2, ShardKind::Parity),
        ];
        let m = ContentManifest::from_shards(shards)
            .unwrap()
            .with_erasure(ErasureScheme { k: 2, n: 3 })
            .unwrap();
        assert!(m.is_recoverable(3));
        assert!(m.is_recoverable(2));
        assert!(!m.is_recoverable(1));
    }

    /// Repair has to start before the object becomes unrecoverable. Waiting
    /// until `live == k` means the next loss is fatal with nothing in flight.
    #[test]
    fn repair_triggers_with_headroom_not_at_the_edge() {
        let shards = vec![
            shard(0, ShardKind::Data),
            shard(1, ShardKind::Data),
            shard(2, ShardKind::Parity),
            shard(3, ShardKind::Parity),
        ];
        let m = ContentManifest::from_shards(shards)
            .unwrap()
            .with_erasure(ErasureScheme { k: 2, n: 4 })
            .unwrap();

        // Full redundancy: nothing to do.
        assert!(!m.needs_repair(4, 1));
        // One parity gone, one left: still above k + margin.
        assert!(!m.needs_repair(3, 1));
        // At k: the next loss is fatal, so repair now.
        assert!(m.needs_repair(2, 1));
    }

    /// Once the object is already gone, a repair deal has nothing to rebuild
    /// from and would only burn an operator bond.
    #[test]
    fn no_repair_is_triggered_for_an_unrecoverable_object() {
        let shards = vec![
            shard(0, ShardKind::Data),
            shard(1, ShardKind::Data),
            shard(2, ShardKind::Parity),
        ];
        let m = ContentManifest::from_shards(shards)
            .unwrap()
            .with_erasure(ErasureScheme { k: 2, n: 3 })
            .unwrap();
        assert!(!m.is_recoverable(1));
        assert!(
            !m.needs_repair(1, 1),
            "there is nothing left to reconstruct from"
        );
    }

    /// A manifest written before erasure coding must keep working, and must
    /// read as plain replication rather than as a scheme with tolerance.
    #[test]
    fn a_manifest_without_a_scheme_reads_as_replication() {
        let shards = vec![shard(0, ShardKind::Data), shard(1, ShardKind::Data)];
        let m = ContentManifest::from_shards(shards).unwrap();
        assert_eq!(m.erasure, ErasureScheme::replication(2));
        assert_eq!(
            m.erasure.loss_tolerance(),
            0,
            "replication tolerates nothing"
        );
        assert!(m.is_recoverable(2));
        assert!(!m.is_recoverable(1));
    }

    /// Old serialised manifests have no `kind` or `erasure` field at all.
    #[test]
    fn legacy_json_deserialises_without_the_new_fields() {
        let json = r#"{
            "manifest_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                           0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "owner":"0x0000000000000000000000000000000000000000000000000000000000000000",
            "total_size":64,
            "shard_count":1,
            "shards":[{"index":0,
                       "shard_id":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                       "size":64}]
        }"#;
        let m: ContentManifest =
            serde_json::from_str(json).expect("a pre-erasure manifest must still parse");
        assert_eq!(m.shards[0].kind, ShardKind::Data);
        assert_eq!(m.erasure, ErasureScheme::default());
        assert_eq!(m.erasure.loss_tolerance(), 0);
    }
}
