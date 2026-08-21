//! Lubot metrikleri - sorgu/verifier/operator istatistik takibi.
//!
//! Lubot katmanının çalışma durumunu izler: toplam sorgu, başarılı doğrulama,
//! Slash edilen operator, aktif model sayısı. Monitoring + dashboard için.

use std::sync::atomic::{AtomicU64, Ordering};

/// Lubot katmanı metrikleri (thread-safe atomic sayaçlar).
#[derive(Debug, Default)]
pub struct LubotMetrics {
    /// Toplam çıkarım sorgusu.
    pub total_queries: AtomicU64,
    /// Başarıyla doğrulanmış çıkarım.
    pub verified_inferences: AtomicU64,
    /// Slash edilen operator sayısı (hatalı çıkarım/eğitim).
    pub slashed_operators: AtomicU64,
    /// Aktif (kayıtlı) model sayısı.
    pub active_models: AtomicU64,
    /// Toplam çıkarım fee hacmi (token).
    pub total_fee_volume: AtomicU64,
}

impl LubotMetrics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_query(&self) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_verified(&self) {
        self.verified_inferences.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_slash(&self) {
        self.slashed_operators.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_active_models(&self, count: u64) {
        self.active_models.store(count, Ordering::Relaxed);
    }

    pub fn record_fee(&self, fee: u64) {
        self.total_fee_volume.fetch_add(fee, Ordering::Relaxed);
    }

    /// Metrik özeti (debug/monitoring).
    #[must_use]
    pub fn summary(&self) -> LubotMetricsSnapshot {
        LubotMetricsSnapshot {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            verified_inferences: self.verified_inferences.load(Ordering::Relaxed),
            slashed_operators: self.slashed_operators.load(Ordering::Relaxed),
            active_models: self.active_models.load(Ordering::Relaxed),
            total_fee_volume: self.total_fee_volume.load(Ordering::Relaxed),
        }
    }
}

/// Metrik anlık görüntüsü (snapshot - Clone + Display).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LubotMetricsSnapshot {
    pub total_queries: u64,
    pub verified_inferences: u64,
    pub slashed_operators: u64,
    pub active_models: u64,
    pub total_fee_volume: u64,
}

impl std::fmt::Display for LubotMetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Lubot{{queries={}, verified={}, slashed={}, models={}, fee_volume={}}}",
            self.total_queries,
            self.verified_inferences,
            self.slashed_operators,
            self.active_models,
            self.total_fee_volume
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn metrics_track_queries_and_fees() {
        let m = LubotMetrics::new();
        m.record_query();
        m.record_query();
        m.record_verified();
        m.record_fee(100);
        m.record_fee(50);
        m.set_active_models(3);
        let s = m.summary();
        assert_eq!(s.total_queries, 2);
        assert_eq!(s.verified_inferences, 1);
        assert_eq!(s.active_models, 3);
        assert_eq!(s.total_fee_volume, 150);
        assert!(s.to_string().contains("queries=2"));
    }
}
