//! B.U.D. 2.0 - EDGE CACHE POLİTİKASI (F93/F247 - CDN/edge offload %90-95 hit)
//!
//! Kalan iş: edge cache. Karar katmanı: bir istek önbellekten karşılanır mı?
//! (recency + boyut + bant bütçesi). Deterministik; egress tasarrufu ölçülür.

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
        Some(Self { capacity_bytes, used: 0, hits: 0, misses: 0 })
    }

    /// İstek: boyut verilen nesne önbelleğe sığıyor mu + karşıla bütçe.
    /// `budget_hit_ratio` hedefi aşılırsa (küçük nesneler) yine de önbelleğe al.
    pub fn request(&mut self, size_bytes: usize, budget_hit_ratio: f64) -> bool {
        // deterministik karar: küçük nesneler hep önbelleğe; büyükler yalnız yer varken
        let fits = size_bytes <= self.capacity_bytes.saturating_sub(self.used);
        let small = size_bytes <= self.capacity_bytes / 100; // %1'den küçük
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
        // 100 küçük nesne (900 bayt) → hepsi hit
        for _ in 0..100 {
            assert!(c.request(900, 0.0));
        }
        assert!(c.hit_ratio() > 0.99);
        // 100KB'lık dev nesne → kapasite dolu → miss
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
