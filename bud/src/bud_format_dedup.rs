//! B.U.D. 2.0 - K20: tenant-local dedup + PoW ownership
//!
//! S.30/S.72 (privacy-preserving dedup, PM-Dedup and ase-PoW), DECISION 71
//! (convergent-encryption attacks cannot be closed -> tenant-local dedup +
//! encrypted dict + PoW ownership).
//! This core: a tenant-local dedup index (cryptographic chunk hashes) plus a
//! proof-of-ownership challenge (SHA3 preimage work). Cross-tenant convergent dedup is NOT done,
//! for privacy.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};
use std::collections::HashSet;

/// Tenant-local dedup index. The same chunk of the same tenant collapses to one.
#[derive(Debug, Clone, Default)]
pub struct TenantDedup {
    chunks: HashSet<[u8; 32]>,
    saved_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DedupOutcome {
    Stored,       // yeni chunk, saklandi
    Deduplicated, // mevcut, tasarruf
}

impl TenantDedup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, chunk: &[u8]) -> DedupOutcome {
        let cid = crate::bud_format_container::content_id(chunk);
        if self.chunks.contains(&cid) {
            self.saved_bytes += chunk.len() as u64;
            DedupOutcome::Deduplicated
        } else {
            self.chunks.insert(cid);
            DedupOutcome::Stored
        }
    }

    pub fn saved_bytes(&self) -> u64 {
        self.saved_bytes
    }

    pub fn unique_chunks(&self) -> usize {
        self.chunks.len()
    }
}

/// PoW ownership challenge: whoever holds the chunk can solve the challenge.
/// The first `difficulty` bits of SHA3(chunk_id || nonce) have to be zero.
#[derive(Debug, Clone)]
pub struct PowChallenge {
    pub chunk_id: [u8; 32],
    pub difficulty: u32,
}

impl PowChallenge {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_POW_V1";

    pub fn new(chunk_id: [u8; 32], difficulty: u32) -> Self {
        PowChallenge {
            chunk_id,
            difficulty,
        }
    }

    fn hash_with_nonce(&self, nonce: u64) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(self.chunk_id);
        h.update(nonce.to_le_bytes());
        h.finalize().into()
    }

    /// Coz: difficulty biti sifir olan nonce bul (deterministik: nonce 0'dan basla).
    pub fn solve(&self, limit: u64) -> Option<u64> {
        for nonce in 0..limit {
            let h = self.hash_with_nonce(nonce);
            if Self::leading_zero_bits(&h) >= self.difficulty {
                return Some(nonce);
            }
        }
        None
    }

    /// Verifies whether the nonce satisfies the difficulty condition.
    pub fn verify(&self, nonce: u64) -> bool {
        Self::leading_zero_bits(&self.hash_with_nonce(nonce)) >= self.difficulty
    }

    fn leading_zero_bits(h: &[u8; 32]) -> u32 {
        let mut count = 0u32;
        for &byte in h.iter() {
            if byte == 0 {
                count += 8;
            } else {
                count += byte.leading_zeros();
                break;
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_saves_duplicate_chunks() {
        let mut dd = TenantDedup::new();
        assert_eq!(dd.insert(b"same blok"), DedupOutcome::Stored);
        assert_eq!(dd.insert(b"same blok"), DedupOutcome::Deduplicated);
        assert_eq!(dd.insert(b"other"), DedupOutcome::Stored);
        assert_eq!(dd.saved_bytes(), 9); // the length of "same blok"
        assert_eq!(dd.unique_chunks(), 2);
    }

    #[test]
    fn pow_solve_and_verify() {
        let cid = crate::bud_format_container::content_id(b"chunk-data");
        let ch = PowChallenge::new(cid, 12);
        let nonce = ch
            .solve(100_000)
            .expect("a solution has to be found at difficulty 12");
        assert!(ch.verify(nonce));
    }

    #[test]
    fn pow_wrong_nonce_rejected() {
        let cid = crate::bud_format_container::content_id(b"chunk-data");
        let ch = PowChallenge::new(cid, 16);
        let nonce = ch.solve(1_000_000).expect("a solution has to be found");
        assert!(!ch.verify(nonce + 1), "a wrong nonce is REFUSED");
    }

    #[test]
    fn pow_impossible_difficulty_returns_none() {
        let cid = crate::bud_format_container::content_id(b"chunk-data");
        let ch = PowChallenge::new(cid, 256); // every bit zero - impossible in practice
        assert!(
            ch.solve(1000).is_none(),
            "with no solution inside the limit the answer is None"
        );
    }
}
