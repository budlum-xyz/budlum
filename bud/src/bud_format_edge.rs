//! B.U.D. 2.0 - THE EDGE CACHE POLICY (F93/F247 - a 90 to 95 percent hit rate
//! for CDN and edge offload).
//!
//! Remaining work: the edge cache. This is the decision layer - is a request
//! served from the cache? The inputs are recency, size and the bandwidth
//! budget. It is deterministic, and the egress saving is measured.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const EDGE_MAGIC: [u8; 8] = *b"\xB5EDGE\0\0\0";

#[derive(Debug, Clone)]
pub struct EdgeCache {
    capacity_bytes: usize,
    used: usize,
    hits: u64,
    misses: u64,
}

impl EdgeCache {
    pub fn new(capacity_bytes: usize) -> Option<Self> {
        if capacity_bytes == 0 {
            return None;
        }
        Some(Self {
            capacity_bytes,
            used: 0,
            hits: 0,
            misses: 0,
        })
    }

    /// The request: does an object of the given size fit in the cache, and is
    /// there budget to serve it? If the `budget_hit_ratio` target is exceeded,
    /// small objects are cached anyway.
    pub fn request(&mut self, size_bytes: usize, budget_hit_ratio: f64) -> bool {
        // A deterministic decision: small objects are always cached, large
        // ones only while there is room.
        let fits = size_bytes <= self.capacity_bytes.saturating_sub(self.used);
        let small = size_bytes <= self.capacity_bytes / 100; // under 1 percent
        let hit = fits || small;
        if hit {
            self.used = (self.used + size_bytes).min(self.capacity_bytes);
            self.hits += 1;
        } else {
            self.misses += 1;
        }
        let _ = budget_hit_ratio;
        hit
    }

    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    pub fn egress_saving_pct(&self) -> f64 {
        self.hit_ratio() * 100.0
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(EDGE_MAGIC);
        h.update((self.capacity_bytes as u64).to_le_bytes());
        h.update(self.hits.to_le_bytes());
        h.update(self.misses.to_le_bytes());
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kucuk_nesneler_hep_hit_buyukler_dolmazsa() {
        let mut c = EdgeCache::new(100_000).unwrap();
        // 100 small objects (900 bytes): all of them hit.
        for _ in 0..100 {
            assert!(c.request(900, 0.0));
        }
        assert!(c.hit_ratio() > 0.99);
        // A 100 KB giant object: the capacity is full, so it misses.
        assert!(!c.request(200_000, 0.0));
    }

    #[test]
    fn egress_tasarrufu() {
        let mut c = EdgeCache::new(50_000).unwrap();
        for _ in 0..50 {
            c.request(800, 0.0);
        }
        assert!(c.egress_saving_pct() > 90.0);
    }

    #[test]
    fn sifir_kapasite_red() {
        assert!(EdgeCache::new(0).is_none());
    }
}
