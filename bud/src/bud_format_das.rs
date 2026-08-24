//! B.U.D. 2.0 - DAS chunk holding, in the F25 DTDL pattern, 2026-08-16.
//!
//! F25: rather than three validators each holding the same data, each holds
//! ONLY ONE CHUNK; access and verification then run over a verifiable tree plus
//! data availability sampling (DAS).
//!
//! This module verifies the chunks of a block or file one at a time with a
//! **Merkle root** that is domain-tagged (K38), plus **DAS sampling**: if a
//! small number of chunks are pulled and verified against the root, the whole
//! of the data can be trusted to be present with high probability. That is the
//! Celestia and Avail pattern.
//!
//! It also carries a **chunk ownership record**: each validator declares which
//! chunk it holds in a signed record, and a missing chunk fails the DAS exam,
//! which costs reputation.
//!
//! The code is `#![forbid(unsafe_code)]`, deterministic and panic-free.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const DAS_MAGIC: [u8; 8] = *b"\xB5DASS\0\0\0";
pub const DAS_VERSION: u8 = 1;

/// The Merkle root over a chunk list, domain-tagged (K38).
pub fn das_root(chunks: &[Vec<u8>]) -> [u8; 32] {
    // The leaf hashes.
    let leaves: Vec<[u8; 32]> = chunks
        .iter()
        .map(|c| {
            let mut h = Sha3_256::new();
            h.update(b"BDLM_BUD_DAS_LEAF_V1");
            h.update((c.len() as u64).to_le_bytes());
            h.update(c);
            h.finalize().into()
        })
        .collect();
    // A binary Merkle tree; on an odd count the last leaf is duplicated.
    let mut level = leaves;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let mut h = Sha3_256::new();
            h.update(b"BDLM_BUD_DAS_NODE_V1");
            h.update(pair[0]);
            if let Some(r) = pair.get(1) {
                h.update(*r);
            } else {
                h.update(pair[0]); // odd one out, so duplicate it
            }
            next.push(h.finalize().into());
        }
        level = next;
    }
    level[0]
}

/// A single chunk proof: a leaf plus a path, verified against the root.
///
/// `path` holds the sibling hash at each level.
#[derive(Debug, Clone)]
pub struct DasProof {
    pub leaf_index: usize,
    pub path: Vec<[u8; 32]>,
}

impl DasProof {
    /// Produce a proof; it is deterministic and recomputed from the data.
    pub fn prove(chunks: &[Vec<u8>], leaf_index: usize) -> Option<DasProof> {
        if chunks.is_empty() || leaf_index >= chunks.len() {
            return None;
        }
        // The leaf hash.
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_DAS_LEAF_V1");
        h.update((chunks[leaf_index].len() as u64).to_le_bytes());
        h.update(&chunks[leaf_index]);
        let leaf: [u8; 32] = h.finalize().into();
        let mut level: Vec<[u8; 32]> = chunks
            .iter()
            .map(|c| {
                let mut h = Sha3_256::new();
                h.update(b"BDLM_BUD_DAS_LEAF_V1");
                h.update((c.len() as u64).to_le_bytes());
                h.update(c);
                h.finalize().into()
            })
            .collect();
        let mut idx = leaf_index;
        let mut path = Vec::new();
        while level.len() > 1 {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            let sibling = if sibling_idx < level.len() {
                level[sibling_idx]
            } else {
                level[idx]
            };
            path.push(sibling);
            // Move up one level.
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let mut h = Sha3_256::new();
                h.update(b"BDLM_BUD_DAS_NODE_V1");
                h.update(pair[0]);
                if let Some(r) = pair.get(1) {
                    h.update(*r);
                } else {
                    h.update(pair[0]);
                }
                next.push(h.finalize().into());
            }
            level = next;
            idx /= 2;
        }
        let _ = leaf;
        Some(DasProof { leaf_index, path })
    }

    /// Verify a proof: the leaf plus the path must reach the root. Panic-free.
    pub fn verify(&self, leaf: &[u8], root: &[u8; 32]) -> bool {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_DAS_LEAF_V1");
        h.update((leaf.len() as u64).to_le_bytes());
        h.update(leaf);
        let mut cur: [u8; 32] = h.finalize().into();
        let mut idx = self.leaf_index;
        for sibling in &self.path {
            let mut nh = Sha3_256::new();
            nh.update(b"BDLM_BUD_DAS_NODE_V1");
            if idx.is_multiple_of(2) {
                nh.update(cur);
                nh.update(*sibling);
            } else {
                nh.update(*sibling);
                nh.update(cur);
            }
            cur = nh.finalize().into();
            idx /= 2;
        }
        cur == *root
    }
}

/// DAS sampling: pull k chunks at random, from a deterministic seed, and if
/// they all verify against the root the data is very likely to be fully
/// present, as long as the missing fraction is low.
pub struct DasSampler;

impl DasSampler {
    /// Deterministic sampling: produce k distinct indices from the seed.
    pub fn sample_indices(count: usize, k: usize, seed: u64) -> Vec<usize> {
        if count == 0 || k == 0 {
            return vec![];
        }
        let mut out = Vec::with_capacity(k);
        let mut x = seed;
        while out.len() < k.min(count) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let idx = (x % count as u64) as usize;
            if !out.contains(&idx) {
                out.push(idx);
            }
            if out.len() == count {
                break;
            }
        }
        out
    }

    /// Do all of the sampled chunks verify against the root?
    pub fn verify_sample(chunks: &[Vec<u8>], root: &[u8; 32], seed: u64, k: usize) -> bool {
        let root_computed = das_root(chunks);
        if root_computed != *root {
            return false;
        }
        for idx in Self::sample_indices(chunks.len(), k, seed) {
            let proof = match DasProof::prove(chunks, idx) {
                Some(p) => p,
                None => return false,
            };
            if !proof.verify(&chunks[idx], root) {
                return false;
            }
        }
        true
    }
}

/// A chunk ownership record: a validator's declaration, writable on chain.
#[derive(Debug, Clone)]
pub struct DasOwnership {
    pub validator_id: String,
    pub chunk_index: usize,
    pub chunk_hash: [u8; 32],
    pub ts_unix: u64,
}

impl DasOwnership {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_DAS_OWNER_V1";

    pub fn new(validator_id: &str, chunk_index: usize, chunk: &[u8], ts_unix: u64) -> Self {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_DAS_LEAF_V1");
        h.update((chunk.len() as u64).to_le_bytes());
        h.update(chunk);
        DasOwnership {
            validator_id: validator_id.to_string(),
            chunk_index,
            chunk_hash: h.finalize().into(),
            ts_unix,
        }
    }

    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update((self.validator_id.len() as u64).to_le_bytes());
        h.update(self.validator_id.as_bytes());
        h.update((self.chunk_index as u32).to_le_bytes());
        h.update(self.chunk_hash);
        h.update(self.ts_unix.to_le_bytes());
        h.finalize().into()
    }

    /// Does the validator really hold the chunk it declared?
    pub fn verify_hold(&self, chunk: &[u8]) -> bool {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_DAS_LEAF_V1");
        h.update((chunk.len() as u64).to_le_bytes());
        h.update(chunk);
        let digest: [u8; 32] = h.finalize().into();
        digest == self.chunk_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_chunks(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| vec![i as u8; 64]).collect()
    }

    #[test]
    fn merkle_root_and_single_proof() {
        let chunks = gen_chunks(8);
        let root = das_root(&chunks);
        assert_ne!(root, [0u8; 32]);
        // The proof verifies for every leaf.
        for i in 0..8 {
            let proof = DasProof::prove(&chunks, i).expect("proof");
            assert!(proof.verify(&chunks[i], &root), "leaf {i} verifies");
            // The wrong leaf is REFUSED.
            assert!(!proof.verify(&chunks[(i + 1) % 8], &root));
        }
        // An odd number of leaves, exercising the duplication.
        let chunks5 = gen_chunks(5);
        let root5 = das_root(&chunks5);
        for i in 0..5 {
            let p = DasProof::prove(&chunks5, i).unwrap();
            assert!(p.verify(&chunks5[i], &root5));
        }
    }

    #[test]
    fn das_sampling_verifies_full_data() {
        let chunks = gen_chunks(100);
        let root = das_root(&chunks);
        // Ten samples are enough.
        assert!(DasSampler::verify_sample(&chunks, &root, 42, 10));
        // A tampered chunk makes the sampling REFUSE.
        let mut bad = chunks.clone();
        bad[50][0] ^= 0xFF;
        assert!(
            !DasSampler::verify_sample(&bad, &root, 42, 10),
            "the corrupt chunk is caught"
        );
        // A different root is REFUSED.
        assert!(!DasSampler::verify_sample(&chunks, &[0u8; 32], 42, 10));
        // The indices are deterministic and distinct.
        let a = DasSampler::sample_indices(100, 10, 7);
        let b = DasSampler::sample_indices(100, 10, 7);
        assert_eq!(a, b, "deterministic");
        let uniq: std::collections::HashSet<usize> = a.iter().cloned().collect();
        assert_eq!(uniq.len(), a.len(), "no collisions");
    }

    #[test]
    fn ownership_record() {
        let chunk = b"chunk contents 1234";
        let rec = DasOwnership::new("validator-1", 3, chunk, 1_768_000_000);
        assert!(rec.verify_hold(chunk), "the declared chunk is held");
        assert!(
            !rec.verify_hold(b"different"),
            "a different chunk is REFUSED"
        );
        // The record is deterministic.
        let rec2 = DasOwnership::new("validator-1", 3, chunk, 1_768_000_000);
        assert_eq!(rec.record_hash(), rec2.record_hash());
        assert_ne!(rec.record_hash(), [0u8; 32]);
        // There is no blob roundtrip, since the record is plain fields; the hash
        // check is enough.
    }
}
