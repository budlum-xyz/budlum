//! B.U.D. 2.0 - ERİŞİM TELEMETRİSİ (culling akışı - K106 tamamlama)
//!
//! Kalan iş #2: "Culling telemetri akışı - runner/üretimden erişim sayacı besleme."
//! Bu modül, `engine_store_tiered`'i besleyen ERİŞİM SAYACI katmanıdır:
//! - `AccessTracker`: cluster başına erişim sayar, zamanla söndürür (decay),
//!   erişim desenini CullingPlan::from_access'a uygun `&[u64]` olarak verir.
//! - Üretim tarafı (runner/API) her okumada `tracker.record(cluster_id)` çağırır;
//!   periyodik `tracker.plan(hot, cold, ts)` ile tier planı üretilir.
//! - Deterministik, panik'siz, no unsafe.

#![forbid(unsafe_code)]

use crate::bud_format_culling::CullingPlan;
use sha3::{Digest, Sha3_256};

pub const TELEMETRY_MAGIC: [u8; 8] = *b"\xB5TELM\0\0\0";
pub const TELEMETRY_VERSION: u8 = 1;
pub const MAX_CLUSTERS: usize = 1_000_000;

/// Erişim sayacı: cluster_id → erişim sayısı (sıcaklık).
#[derive(Debug, Clone)]
pub struct AccessTracker {
    counts: Vec<u64>,
    touches: Vec<u64>, // son görülen zaman (decay için)
    capacity: usize,
}

impl AccessTracker {
    /// `capacity` cluster için boş sayaç (0 = tümü soğuk).
    pub fn new(capacity: usize) -> Option<Self> {
        if capacity == 0 || capacity > MAX_CLUSTERS {
            return None;
        }
        Some(Self {
            counts: vec![0; capacity],
            touches: vec![0; capacity],
            capacity,
        })
    }

    /// Bir erişim kaydet (cluster_id sınır dışıysa yok sayılır - panik yok).
    pub fn record(&mut self, cluster_id: usize, ts_unix: u64) {
        if cluster_id < self.capacity {
            self.counts[cluster_id] = self.counts[cluster_id].saturating_add(1);
            self.touches[cluster_id] = ts_unix;
        }
    }

    /// Zaman-sönümleme (decay): `half_life_sec` içinde yarı yarıya düşür.
    /// Eski erişimler soğur → culling fırsatı (soğuk veri önce budanır, ilham-2 A).
    pub fn decay(&mut self, now: u64, half_life_sec: u64) {
        if half_life_sec == 0 {
            return;
        }
        for i in 0..self.capacity {
            let age = now.saturating_sub(self.touches[i]);
            if age > 0 {
                let halvings = (age / half_life_sec).min(63) as u32;
                self.counts[i] >>= halvings.min(63); // 2^-halvings
            }
        }
    }

    /// Sayaç dizisi (CullingPlan::from_access girdisi).
    pub fn snapshot(&self) -> &[u64] {
        &self.counts
    }

    /// Tier planı üret (culling entegrasyonu - engine_store_tiered ile aynı eşikler).
    pub fn plan(&self, hot_threshold: u64, cold_threshold: u64, ts: u64) -> Option<CullingPlan> {
        CullingPlan::from_access(&self.counts, hot_threshold, cold_threshold, ts)
    }

    /// Toplam erişim (tanı).
    pub fn total_access(&self) -> u64 {
        self.counts.iter().sum()
    }

    /// Deterministik kayıt özeti (zincire yazılabilir - telemetri kanıtı).
    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(TELEMETRY_MAGIC);
        h.update([TELEMETRY_VERSION]);
        h.update((self.capacity as u32).to_le_bytes());
        for &c in &self.counts {
            h.update(c.to_le_bytes());
        }
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_sayar_ve_plan_uretir() {
        let mut t = AccessTracker::new(10).unwrap();
        for i in 0..10 {
            for _ in 0..(i as u64 * 5) {
                t.record(i, 1);
            }
        }
        assert_eq!(t.total_access(), 225);
        let plan = t.plan(10, 1, 2).unwrap();
        let (h, w, _c, cu) = plan.tier_summary();
        // i=2..9 → ≥10 erişim → Hot; i=1 → 5 → Warm; i=0 → 0 → Culled
        assert_eq!(h, 8);
        assert_eq!(w, 1);
        assert_eq!(cu, 1);
        assert!(plan.culling_ratio() > 0.0);
    }

    #[test]
    fn decay_sonrasi_soguk_veri_budanir() {
        let mut t = AccessTracker::new(4).unwrap();
        t.record(0, 100);
        t.record(0, 101);
        t.record(1, 100);
        t.decay(100_000, 50); // çok yaşlı → neredeyse sıfır
        assert_eq!(t.snapshot()[0], 0);
        assert_eq!(t.snapshot()[1], 0);
    }

    #[test]
    fn sinir_disari_yok_sayilir_panik_yok() {
        let mut t = AccessTracker::new(2).unwrap();
        t.record(5, 1); // sınır dışı
        t.record(0, 1);
        assert_eq!(t.total_access(), 1);
        assert!(AccessTracker::new(0).is_none());
        assert!(AccessTracker::new(MAX_CLUSTERS + 1).is_none());
    }

    #[test]
    fn telemetri_hash_deterministik() {
        let mut t = AccessTracker::new(3).unwrap();
        t.record(1, 5);
        let h1 = t.record_hash();
        let mut t2 = AccessTracker::new(3).unwrap();
        t2.record(1, 5);
        assert_eq!(h1, t2.record_hash());
    }
}
