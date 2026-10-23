//! B.U.D. 2.0 invention - direction 5: the PoR core (Proof-of-Retrievability)
//! (2026-08-16).
//!
//! A simple, cryptographic realisation of the private-verifiability version
//! (S.93/S.149): every block carries a PRF/MAC-based tag; the verifier
//! re-tags the blocks named in the challenge and checks the response. Lossless,
//! deterministic, no unsafe.
//!
//! Code: `#![forbid(unsafe_code)]`. Tag = SHA3-256(key || index || block),
//! domain-labelled. This is not a skeleton: the separation between a right tag
//! and a wrong tag is proven by the chaos tests. (BLS-based public
//! verifiability plus EVENODD and LRC-DPoR integration are the next steps.)

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

/// The PoR key (the secret shared with the verifier). Private verifiability.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PorKey(pub [u8; 32]);

/// The key is a secret: the debug form never prints its bytes.
impl std::fmt::Debug for PorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PorKey(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PorTag(pub [u8; 32]);

#[derive(Debug, Clone)]
pub struct PorChallenge {
    pub indices: Vec<u64>, // the challenged block indices
    pub nonce: [u8; 32],   // fresh on every challenge (prevents replay)
}

#[derive(Debug, Clone)]
pub struct PorResponse {
    pub tags: Vec<PorTag>, // in the same order as indices
}

impl PorKey {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_POR_V1";

    pub fn new(seed: [u8; 32]) -> Self {
        PorKey(seed)
    }

    /// The response tag: SHA3(domain || key || nonce || index || block). The challenge
    /// nonce is inside, so a tag from an earlier challenge answers no later one and
    /// the prover needs the block bytes for every challenge.
    pub fn tag(&self, block: &[u8], index: u64, nonce: &[u8; 32]) -> PorTag {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(self.0);
        h.update(nonce);
        h.update(index.to_le_bytes());
        h.update(block);
        PorTag(h.finalize().into())
    }

    /// Produce a challenge: a random index set (seeded, so tests stay
    /// deterministic). In a real deployment the indices come from chain
    /// randomness (VRF/VDF, S.104).
    pub fn challenge(block_count: u64, k: usize, seed: u64) -> PorChallenge {
        // Simple and deterministic: k distinct indices by shifting the seed.
        let mut indices = Vec::with_capacity(k);
        for i in 0..k {
            indices.push((seed.wrapping_add(i as u64)) % block_count.max(1));
        }
        let mut nonce = [0u8; 32];
        nonce[0..8].copy_from_slice(&seed.to_le_bytes());
        nonce[8..16].copy_from_slice(&block_count.to_le_bytes());
        PorChallenge { indices, nonce }
    }

    /// Produce a response (the prover side): a tag for every block in the
    /// challenge. Bounds-safe: if any index exceeds the block count it returns
    /// None (NO PANIC, the K38 mini-fuzz philosophy), so a malicious or
    /// corrupt challenge cannot crash the prover.
    pub fn respond(&self, blocks: &[Vec<u8>], challenge: &PorChallenge) -> Option<PorResponse> {
        let mut tags = Vec::with_capacity(challenge.indices.len());
        for &idx in &challenge.indices {
            if idx as usize >= blocks.len() {
                return None; // an out-of-bounds index -> an invalid response
            }
            tags.push(self.tag(&blocks[idx as usize], idx, &challenge.nonce));
        }
        Some(PorResponse { tags })
    }

    /// Verify (the verifier side): every (index, block, tag) must match the
    /// recomputed one. The challenge nonce is bound into every tag, so a replayed
    /// or precomputed response fails under a fresh nonce. This private-key scheme
    /// still needs the verifier to hold the blocks.
    pub fn verify(
        &self,
        blocks: &[Vec<u8>],
        challenge: &PorChallenge,
        response: &PorResponse,
    ) -> bool {
        if challenge.indices.len() != response.tags.len() {
            return false;
        }
        for (i, &idx) in challenge.indices.iter().enumerate() {
            if idx as usize >= blocks.len() {
                return false;
            }
            let expected = self.tag(&blocks[idx as usize], idx, &challenge.nonce);
            if expected != response.tags[i] {
                return false; // the block or the tag was changed
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_debug_form_does_not_print_the_key() {
        let key = PorKey::new([0xAB; 32]);
        let shown = format!("{key:?}");
        assert!(!shown.contains("171") && !shown.contains("ab"), "{shown}");
    }

    fn blocks() -> Vec<Vec<u8>> {
        (0..8u64).map(|i| vec![i as u8; 16]).collect()
    }

    #[test]
    fn honest_prover_verified() {
        let key = PorKey::new([7u8; 32]);
        let blk = blocks();
        let ch = PorKey::challenge(8, 3, 42);
        let resp = key
            .respond(&blk, &ch)
            .expect("an honest prover produces a response");
        assert!(key.verify(&blk, &ch, &resp), "an honest prover verifies");
    }

    #[test]
    fn tampered_block_rejected() {
        let key = PorKey::new([7u8; 32]);
        let mut blk = blocks();
        let ch = PorKey::challenge(8, 3, 42);
        let resp = key
            .respond(&blk, &ch)
            .expect("an honest prover produces a response");
        // corrupt the first index in the challenge
        let bad_idx = ch.indices[0] as usize;
        blk[bad_idx][0] ^= 0xFF;
        assert!(!key.verify(&blk, &ch, &resp), "a changed block is REFUSED");
    }

    #[test]
    fn wrong_key_rejected() {
        let k1 = PorKey::new([7u8; 32]);
        let k2 = PorKey::new([8u8; 32]);
        let blk = blocks();
        let ch = PorKey::challenge(8, 3, 42);
        let resp = k1
            .respond(&blk, &ch)
            .expect("an honest prover produces a response");
        assert!(!k2.verify(&blk, &ch, &resp), "a wrong key is REFUSED");
    }

    #[test]
    fn response_is_bound_to_the_challenge_nonce() {
        let key = PorKey::new([7u8; 32]);
        let blk = blocks();
        let ch = PorKey::challenge(8, 3, 42);
        let resp = key.respond(&blk, &ch).expect("response");
        // The same indices under a fresh nonce: the old tags must not verify.
        let fresh = PorChallenge {
            indices: ch.indices.clone(),
            nonce: [9u8; 32],
        };
        assert!(
            !key.verify(&blk, &fresh, &resp),
            "a replayed response is REFUSED"
        );
        let again = key.respond(&blk, &fresh).expect("response");
        assert!(key.verify(&blk, &fresh, &again));
    }

    #[test]
    fn tampered_response_rejected() {
        let key = PorKey::new([7u8; 32]);
        let blk = blocks();
        let ch = PorKey::challenge(8, 3, 42);
        let mut resp = key
            .respond(&blk, &ch)
            .expect("an honest prover produces a response");
        resp.tags[0].0[0] ^= 0xFF;
        assert!(!key.verify(&blk, &ch, &resp), "a changed tag is REFUSED");
    }

    #[test]
    fn challenge_bounds_safe() {
        let key = PorKey::new([1u8; 32]);
        let blk = blocks();
        let ch = PorKey::challenge(8, 8, 0); // 8 indices, 8 blocks
        assert!(key.verify(&blk, &ch, &key.respond(&blk, &ch).expect("response")));
        // if a block behind an index is missing, REFUSE (the bounds check)
        let mut bad = blocks();
        bad.clear();
        assert!(!key.verify(&bad, &ch, &key.respond(&blk, &ch).expect("response")));
        // a challenge with an out-of-bounds index -> respond returns None, NO
        // PANIC (K38)
        let ch_bad = PorChallenge {
            indices: vec![999_999],
            nonce: [0u8; 32],
        };
        assert!(
            key.respond(&blk, &ch_bad).is_none(),
            "an out-of-bounds index has to return None"
        );
        assert!(
            !key.verify(
                &blk,
                &ch_bad,
                &PorResponse {
                    tags: vec![PorTag([0u8; 32])]
                }
            ),
            "an out-of-bounds index is REFUSED by verify"
        );
    }
}
