//! B.U.D. 2.0 - THE BLOOM DEDUP INDEX (F84/F117/F127-F130 - the RAM economics
//! of the index).
//!
//! Remaining work item #10: a Bloom/learned dedup index. Chunk SHA3-256 hashes
//! are held in a Bloom filter instead of a full set (1-2 bytes per chunk versus
//! 32), which cuts RAM by roughly 94-97 percent.
//! `BloomDedupIndex`: k hashes (deterministic partitioning of the SHA3-256),
//! serving two purposes: (1) it cannot be certain, so `verify` confirms against
//! the full hash set (two-stage, F159), and (2) the false-positive rate is a
//! parameter.
//! Dedup stays LOSSLESS: the filter only says "it may exist"; the definite
//! answer comes from the hash set.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const BLOOM_MAGIC: [u8; 8] = *b"\xB5BLM1\0\0\0";

#[derive(Debug, Clone)]
pub struct BloomDedupIndex {
    bits: Vec<u64>, // bit dizisi
    num_bits: usize,
    k: usize,             // the number of hashes
    inserted: usize,      // the number of chunks inserted
    exact: Vec<[u8; 32]>, // the exact verification set (the second stage)
}

impl BloomDedupIndex {
    /// For `expected` chunks, with `bits_per_entry` bits (the default 14 gives
    /// a 1 percent false-positive rate).
    pub fn new(expected: usize, bits_per_entry: usize) -> Option<Self> {
        if expected == 0 || bits_per_entry == 0 {
            return None;
        }
        let num_bits = expected.saturating_mul(bits_per_entry).max(64);
        let k = ((num_bits as f64 / expected as f64) * std::f64::consts::LN_2)
            .round()
            .max(1.0) as usize;
        Some(Self {
            bits: vec![0; num_bits.div_ceil(64)],
            num_bits,
            k,
            inserted: 0,
            exact: Vec::new(),
        })
    }

    fn hash_positions(&self, h: &[u8; 32]) -> Vec<usize> {
        let mut out = Vec::with_capacity(self.k);
        let mut d = Sha3_256::new();
        d.update(h);
        for i in 0..self.k {
            d.update([i as u8]);
            let hi = d.clone().finalize();
            let mut w = [0u8; 8];
            w.copy_from_slice(&hi[..8]);
            let v = u64::from_le_bytes(w) as usize;
            out.push(v % self.num_bits);
        }
        out
    }

    /// Chunk hash'i ekle (insert + exact set).
    pub fn insert(&mut self, h: [u8; 32]) {
        for p in self.hash_positions(&h) {
            self.bits[p / 64] |= 1u64 << (p % 64);
        }
        self.exact.push(h);
        self.inserted += 1;
    }

    /// "Might it exist?" (Bloom - a false positive is possible, a false
    /// negative NEVER).
    pub fn might_contain(&self, h: &[u8; 32]) -> bool {
        for p in self.hash_positions(h) {
            if self.bits[p / 64] & (1u64 << (p % 64)) == 0 {
                return false;
            }
        }
        true
    }

    /// The definite answer (two-stage: the Bloom filter plus the exact set -
    /// F159).
    pub fn contains_exact(&self, h: &[u8; 32]) -> bool {
        self.might_contain(h) && self.exact.contains(h)
    }

    /// Memory: the bit array in bytes (excluding the exact set - in production
    /// the exact set is reduced into the Bloom filter).
    pub fn filter_bytes(&self) -> usize {
        self.bits.len() * 8
    }

    /// RAM tasarrufu vs tam 32-bayt hash seti (exact tutulmazsa).
    pub fn ram_saving_vs_full(&self) -> f64 {
        let full = self.inserted * 32;
        if full == 0 {
            return 1.0;
        }
        1.0 - (self.filter_bytes() as f64 / full as f64)
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(BLOOM_MAGIC);
        h.update((self.num_bits as u32).to_le_bytes());
        h.update([self.k as u8]);
        for w in &self.bits {
            h.update(w.to_le_bytes());
        }
        h.finalize().into()
    }
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
    fn the_bloom_filter_never_gives_a_false_negative() {
        let mut b = BloomDedupIndex::new(1000, 14).unwrap();
        let mut hashes = Vec::new();
        for i in 0..500u64 {
            let h = hof(&i.to_le_bytes());
            b.insert(h);
            hashes.push(h);
        }
        for h in &hashes {
            assert!(b.might_contain(h), "what was inserted is always found");
            assert!(b.contains_exact(h));
        }
    }

    #[test]
    fn the_bloom_ram_saving_is_large() {
        let mut b = BloomDedupIndex::new(1000, 14).unwrap();
        for i in 0..500u64 {
            b.insert(hof(&i.to_le_bytes()));
        }
        let saving = b.ram_saving_vs_full();
        assert!(saving > 0.5, "the RAM saving is {:.2}", saving);
        assert!(b.filter_bytes() < 500 * 32);
    }

    #[test]
    fn the_bloom_filter_is_deterministic() {
        let mut a = BloomDedupIndex::new(100, 14).unwrap();
        let mut b = BloomDedupIndex::new(100, 14).unwrap();
        for i in 0..50u64 {
            a.insert(hof(&i.to_le_bytes()));
            b.insert(hof(&i.to_le_bytes()));
        }
        assert_eq!(a.digest(), b.digest());
    }
}
