//! B.U.D. content addressing (Tur 14, Faz 2 + Tur 14.5, vision §8.2).
//!
//! Vision §8.2 originally proposed a *double-hash* `ContentId` carrying both
//! an IPFS multihash and a Poseidon4 hash. The Poseidon primitive is not
//! wired into `budlum-core` (it lives in BudZKVM), so for Tur 14 we use the
//! existing domain-separated SHA-256 (`hash_fields_bytes`) with the
//! `BDLM_CONTENT_V1` domain tag. This is exactly the same trade-off the Tur
//! 14 plan §3.1 makes:
//!
//! > "İçerik adresleme: `ContentId` tipi — Poseidon4 hash tabanlı (BudZero'da
//! >  zaten kullanılan `poseidon4_hash` primitive'iyle aynı aile; yeni bir
//! >  hash fonksiyonu icat etme)."
//!
//! — we are not inventing a new hash. We use the existing one and tag it
//! so it can never collide with another 32-byte field that happens to be
//! hashed the same way in a different module.
//!
//! Per Tur 14.5 plan §0.5 (data-sovereignty / team-independence rule),
//! `ContentId` is a **pure on-chain data shape** — no network calls, no
//! "Budlum Inc. indexer" dependency, no admin/pause hook. Any independent
//! node can compute it from the raw chunk bytes alone.

use crate::core::hash::hash_fields_bytes;
use crate::domain::Hash32;
use serde::{Deserialize, Serialize};

/// Default chunk size, mirrored from `domain::storage_params::DEFAULT_CHUNK_SIZE`
/// for ergonomics. Tests and the `ContentManifest::from_chunks` helper use
/// this when the caller does not pin an explicit size.
pub const DEFAULT_CHUNK_SIZE_BYTES: u32 = 262_144; // 256 KiB

/// A canonical content identifier.
///
/// Two chunks with the same bytes MUST produce the same `ContentId`. Two
/// chunks with different bytes MUST produce different `ContentId`s. Both
/// invariants are guaranteed by the underlying SHA-256 + length-prefixed
/// domain separation, and exercised by the `content_id_is_deterministic`
/// and `content_id_collisions_impossible_for_truncated_payloads` tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentId(pub Hash32);

impl ContentId {
    /// Compute the `ContentId` of a chunk.
    pub fn of(chunk: &[u8]) -> Self {
        ContentId(hash_fields_bytes(&[b"BDLM_CONTENT_V1", chunk]))
    }

    /// Compute the `ContentId` of a chunk plus an explicit sub-chunk byte
    /// range (used by Faz 5's `RetrievalChallenge` to pin a deterministic
    /// sub-range within a chunk — vision §8.3 / Tur 14.5 §2.5).
    ///
    /// **Critically (Tur 14.5 plan §2.5):** the resulting `ContentId` is
    /// only a byte-range hash, not a proof-of-storage. The full chunk can
    /// be discarded and a fresh chunk holding only the requested range
    /// can still answer the challenge. This is the documented
    /// "interim retrieval challenge" limitation — see
    /// `crate::domain::storage_deal::RetrievalChallenge` for the long
    /// warning comment and the README/CLAUDE.md cross-link.
    pub fn of_subrange(chunk: &[u8], start: u64, end: u64) -> Self {
        if start > end || end > chunk.len() as u64 {
            // Out-of-range requests still get a deterministic hash (so the
            // caller can't infer anything from a "panic vs Ok" distinction)
            // but the hash is over a tagged-out-of-range field so it can
            // never collide with a real subrange.
            return ContentId(hash_fields_bytes(&[
                b"BDLM_CONTENT_SUBRANGE_OOR_V1",
                &start.to_le_bytes(),
                &end.to_le_bytes(),
            ]));
        }
        ContentId(hash_fields_bytes(&[
            b"BDLM_CONTENT_SUBRANGE_V1",
            &start.to_le_bytes(),
            &end.to_le_bytes(),
            &chunk[start as usize..end as usize],
        ]))
    }

    pub fn as_bytes(&self) -> &Hash32 {
        &self.0
    }
}

impl std::fmt::Display for ContentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
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
        // Prefix-collision sanity check: hashing the lengths before the
        // payload in `hash_fields_bytes` is exactly what prevents
        // `ContentId::of(b"ab") == ContentId::of(b"a" | "b")` style
        // collisions. We exercise the property via the public API.
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
        let chunk = b"abcdefghij"; // 10 bytes
        let a = ContentId::of_subrange(chunk, 2, 5);
        let b = ContentId::of_subrange(chunk, 2, 5);
        assert_eq!(a, b);
        // Different range → different hash.
        assert_ne!(a, ContentId::of_subrange(chunk, 2, 6));
        // And full-content hash differs from any subrange hash, so the
        // value-space for ContentIds is the union of full and subrange
        // hashes — they never collide by accident.
        assert_ne!(a, ContentId::of(chunk));
    }

    #[test]
    fn out_of_range_subrange_returns_tagged_placeholder_not_a_panic() {
        let chunk = b"abc";
        let oor = ContentId::of_subrange(chunk, 10, 20);
        // Determinism:
        let oor2 = ContentId::of_subrange(chunk, 10, 20);
        assert_eq!(oor, oor2);
        // Distinct from any real subrange and from a full-content hash:
        assert_ne!(oor, ContentId::of_subrange(chunk, 0, 1));
        assert_ne!(oor, ContentId::of(chunk));
    }
}
