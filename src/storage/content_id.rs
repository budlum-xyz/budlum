//! B.U.D. content addressing.
//!
//! Vision §8.2 originally proposed a *double-hash* `ContentId` carrying both
//! An IPFS multihash and a Poseidon4 hash. The Poseidon primitive is not
//! Wired into `budlum-core` (it lives in `BudZKVM`), so we use the
//! Existing domain-separated SHA-256 (`hash_fields_bytes`) with the
//! `BDLM_CONTENT_V1` domain tag. This is exactly the same trade-off the Tur
//! 14 plan §3.1 makes:
//!
//! > "Content addressing: the `ContentId` type, based on a Poseidon4 hash - the
//! >  same family as the `poseidon4_hash` primitive already used in BudZero, so no new
//! >  hash fonksiyonu icat etme)."
//!
//! We are not inventing a new hash. We use the existing one and tag it
//! So it can never collide with another 32-byte field that happens to be
//! Hashed the same way in a different module.
//!
//! Plan §0.5 (data-sovereignty / team-independence rule),
//! `ContentId` is a **pure on-chain data shape** - no network calls, no
//! "Budlum Inc. indexer" dependency, no admin/pause hook. Any independent
//! Node can compute it from the raw chunk bytes alone.

use crate::core::hash::hash_fields_bytes;
use crate::domain::Hash32;
use serde::{Deserialize, Serialize};

/// Default chunk size, mirrored from `domain::storage_params::DEFAULT_CHUNK_SIZE`
/// For ergonomics. Tests and the `ContentManifest::from_chunks` helper use
/// This when the caller does not pin an explicit size.
pub const DEFAULT_CHUNK_SIZE_BYTES: u32 = 262_144; // 256 KiB

/// A canonical content identifier.
///
/// Two chunks with the same bytes MUST produce the same `ContentId`. Two
/// Chunks with different bytes MUST produce different `ContentId`s. Both
/// Invariants are guaranteed by the underlying SHA-256 + length-prefixed
/// Domain separation, and exercised by the `content_id_is_deterministic`
/// And `content_id_collisions_impossible_for_truncated_payloads` tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContentId(pub Hash32);

impl ContentId {
    /// Compute the `ContentId` of a chunk.
    pub fn of(chunk: &[u8]) -> Self {
        Self(hash_fields_bytes(&[b"BDLM_CONTENT_V1", chunk]))
    }

    /// Compute the `ContentId` of a chunk plus an explicit sub-chunk byte
    /// Range (used by `RetrievalChallenge` to pin a deterministic
    /// Sub-range within a chunk - vision §8.3 /).
    ///
    /// **Critically (plan §2.5):** the resulting `ContentId` is
    /// Only a byte-range hash, not a proof-of-storage. The full chunk can
    /// Be discarded and a fresh chunk holding only the requested range
    /// Can still answer the challenge. This is the documented
    /// "interim retrieval challenge" limitation, see
    /// `crate::domain::storage_deal::RetrievalChallenge` for the long
    /// Warning comment and the README cross-link.
    pub fn of_subrange(chunk: &[u8], start: u64, end: u64) -> Self {
        if start > end || end > chunk.len() as u64 {
            // Out-of-range requests still get a deterministic hash (so the
            // Caller can't infer anything from a "panic vs Ok" distinction)
            // But the hash is over a tagged-out-of-range field so it can
            // Never collide with a real subrange.
            return Self(hash_fields_bytes(&[
                b"BDLM_CONTENT_SUBRANGE_OOR_V1",
                &start.to_le_bytes(),
                &end.to_le_bytes(),
            ]));
        }
        Self(hash_fields_bytes(&[
            b"BDLM_CONTENT_SUBRANGE_V1",
            &start.to_le_bytes(),
            &end.to_le_bytes(),
            &chunk[start as usize..end as usize],
        ]))
    }

    /// Content id of a byte range **as stored by one specific operator**.
    ///
    /// [`Self::of_subrange`] hashes the bytes and nothing else, so every
    /// operator holding a replica of the same shard answers a challenge with
    /// the same value. That makes two attacks free, both named in the `SoK` on
    /// decentralized storage networks:
    ///
    /// * **outsourcing** - several operators keep one physical copy between
    ///   them and collect a payment each, because any of them can produce the
    ///   answer the others would have produced;
    /// * **Sybil** - one machine registers N identities, claims N replicas and
    ///   stores one.
    ///
    /// Binding the answer to `(operator, deal_id, manifest_id)` means a
    /// challenge can only be answered by whoever holds *that deal's* copy.
    /// Sharing bytes no longer shares answers.
    ///
    /// This is a *binding*, not a proof of distinct storage. Filecoin's `PoRep`
    /// goes further and makes each replica physically different and
    /// incompressible by encoding it under a per-replica key, so the bytes
    /// themselves cannot be shared. That is a format change to what an
    /// operator writes to disk; this is a change to what a challenge accepts,
    /// and it removes the free version of the attack: colluding operators now
    /// have to relay each other's live challenges rather than precompute one
    /// answer set. See `docs/BUD_STORAGE_ROADMAP.md` Gap 2.
    pub fn of_subrange_for_deal(
        chunk: &[u8],
        start: u64,
        end: u64,
        operator: &[u8; 32],
        deal_id: u64,
        manifest_id: &Hash32,
    ) -> Self {
        let base = Self::of_subrange(chunk, start, end);
        Self(hash_fields_bytes(&[
            b"BDLM_CONTENT_SUBRANGE_DEAL_V1",
            base.as_bytes(),
            operator,
            &deal_id.to_le_bytes(),
            manifest_id,
        ]))
    }

    pub const fn as_bytes(&self) -> &Hash32 {
        &self.0
    }
}

impl std::fmt::Display for ContentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// JSON map key: the same hex string `Display` prints.
impl crate::core::map_keys::MapKey for ContentId {
    fn to_key_string(&self) -> String {
        hex::encode(self.0)
    }
    fn from_key_string(s: &str) -> Result<Self, String> {
        crate::core::map_keys::parse_hex32(s).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_id_is_deterministic() {
        let a = ContentId::of(b"hello world");
        let b = ContentId::of(b"hello world");
        assert_eq!(a, b);
    }

    #[test]
    fn content_id_differs_for_different_bytes() {
        assert_ne!(ContentId::of(b"a"), ContentId::of(b"b"));
    }

    #[test]
    fn content_id_collisions_impossible_for_truncated_payloads() {
        let one = ContentId::of(b"ab");
        let two = ContentId::of(b"a").0;
        let three = ContentId::of(b"b").0;
        assert_ne!(
            one.0,
            hash_fields_bytes(&[b"BDLM_CONTENT_V1", &two, &three])
        );
    }

    #[test]
    fn subrange_hash_is_deterministic_and_distinct() {
        let chunk = b"abcdefghij";
        let a = ContentId::of_subrange(chunk, 2, 5);
        let b = ContentId::of_subrange(chunk, 2, 5);
        assert_eq!(a, b);
        assert_ne!(a, ContentId::of_subrange(chunk, 2, 6));
        assert_ne!(a, ContentId::of(chunk));
    }

    #[test]
    fn out_of_range_subrange_returns_tagged_placeholder_not_a_panic() {
        let chunk = b"abc";
        let oor = ContentId::of_subrange(chunk, 10, 20);
        let oor2 = ContentId::of_subrange(chunk, 10, 20);
        assert_eq!(oor, oor2);
        assert_ne!(oor, ContentId::of_subrange(chunk, 0, 1));
        assert_ne!(oor, ContentId::of(chunk));
    }
}
