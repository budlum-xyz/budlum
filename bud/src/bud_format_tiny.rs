//! B.U.D. 2.0 - THE SMALL OBJECT CLASS + DICTIONARY GUARDIANSHIP
//! (ideas 3.0, Y5/Y4).
//!
//! Y5: a PACT record is about 100-128 B, so for objects under 1 KB the record
//! overhead approaches the object itself. Hence the "directly in the block"
//! class: small objects travel inline (with dedup plus delta), and anything
//! above the threshold uses a PACT. The threshold is the
//! `tiny_object_threshold` governance parameter. There is NO dedup for
//! encrypted inline objects (the tenant key), which is the strict Pollen
//! rule.
//!
//! Y4: the cohort dictionary lives on the chain like a PACT; the "dictionary
//! guardian" is the guardian running the cohort's audit round; the dictionary
//! bytes are stored nowhere (COVER(cohort_commitment, seed) - retraining is
//! CPU work, inside the I4 budget).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const TINY_MAGIC: [u8; 8] = *b"\xB5TNY1\0\0\0";

/// The Y5 default threshold (governance can vote on it): 1 KB.
pub const TINY_OBJECT_THRESHOLD: usize = 1024;

/// Y5: is the object small? (the inline in-block class)
pub fn is_tiny(size: usize, threshold: usize) -> bool {
    threshold > 0 && size <= threshold
}

/// Y5: an inline object record (written into the block body; compressed with
/// dedup plus delta).
#[derive(Debug, Clone)]
pub struct TinyInline {
    pub content_id: [u8; 32],
    pub data: Vec<u8>,
    pub encrypted: bool, // Pollen strict: NO cross-tenant dedup for encrypted inline
}

/// Y5: inline object packing - how many objects fit in a 128 KB block (the
/// ceiling guard).
pub fn fits_in_block(tiny: &[TinyInline], block_capacity: usize) -> bool {
    let total: usize = tiny.iter().map(|t| 32 + t.data.len() + 1).sum();
    total <= block_capacity
}

/// Y4: dictionary guardianship - COVER(cohort_commitment, seed).
/// cohort_commitment = H(ordered object hashes); the dictionary bytes are not
/// stored.
pub fn cover(cohort_commitment: &[u8; 32], seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_DICT_COVER_V1");
    h.update(cohort_commitment);
    h.update(seed);
    h.finalize().into()
}

/// Y4: the cohort commitment - from the ordered object hashes
/// (deterministic).
pub fn cohort_commitment(object_hashes: &[[u8; 32]]) -> Option<[u8; 32]> {
    if object_hashes.is_empty() {
        return None;
    }
    let mut h = Sha3_256::new();
    h.update(b"BDLM_DICT_COHORT_V1");
    h.update((object_hashes.len() as u32).to_le_bytes());
    for o in object_hashes {
        h.update(o);
    }
    Some(h.finalize().into())
}

/// Y4: dictionary retraining determinism - the same cohort gives the same
/// COVER (on a different machine; under the version + parameter + input
/// pinning condition, I5).
pub fn dict_reproducible(c1: &[u8; 32], c2: &[u8; 32]) -> bool {
    c1 == c2
}

pub fn tiny_digest(t: &TinyInline) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(TINY_MAGIC);
    h.update(t.content_id);
    h.update(&t.data);
    h.update([t.encrypted as u8]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Digest;

    fn hof(b: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b);
        h.finalize().into()
    }

    #[test]
    fn y5_tiny_threshold_and_packing() {
        assert!(is_tiny(500, TINY_OBJECT_THRESHOLD));
        assert!(!is_tiny(5000, TINY_OBJECT_THRESHOLD));
        assert!(
            !is_tiny(100, 0),
            "threshold 0 means the class does not exist"
        );
        let objects = vec![
            TinyInline {
                content_id: hof(b"a"),
                data: vec![0u8; 100],
                encrypted: false,
            },
            TinyInline {
                content_id: hof(b"b"),
                data: vec![0u8; 200],
                encrypted: true,
            },
        ];
        assert!(fits_in_block(&objects, 1024));
        assert!(!fits_in_block(&objects, 200));
    }

    #[test]
    fn y4_cover_and_cohort() {
        let hashes: Vec<[u8; 32]> = vec![hof(b"n1"), hof(b"n2"), hof(b"n3")];
        let cc = cohort_commitment(&hashes).unwrap();
        let c1 = cover(&cc, &[1u8; 32]);
        let c2 = cover(&cc, &[1u8; 32]);
        assert!(
            dict_reproducible(&c1, &c2),
            "the same cohort gives the same COVER"
        );
        // a different order gives a different commitment (the ordered hash rule)
        let mut rev = hashes.clone();
        rev.reverse();
        assert_ne!(cohort_commitment(&rev).unwrap(), cc);
        assert!(cohort_commitment(&[]).is_none());
    }

    #[test]
    fn tiny_deterministik() {
        let t = TinyInline {
            content_id: [1u8; 32],
            data: b"data".to_vec(),
            encrypted: false,
        };
        assert_eq!(tiny_digest(&t), tiny_digest(&t));
    }
}
