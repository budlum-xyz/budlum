//! Agent metrikleri - sorgu/verifier/operator istatistik takibi.
//!
//! Tracks the running state of the Agent layer: total queries, successful
//! verifications, slashed operators and the number of active models. Intended
//! for monitoring and dashboards.

use std::sync::atomic::{AtomicU64, Ordering};

/// The metrics of the Agent layer, as thread-safe atomic counters.
#[derive(Debug, Default)]
pub struct AgentMetrics {
    /// Total inference queries.
    pub total_queries: AtomicU64,
    /// Inferences that verified successfully.
    pub verified_inferences: AtomicU64,
    /// The number of slashed operators (a faulty inference or training run).
    pub slashed_operators: AtomicU64,
    /// The number of active, registered models.
    pub active_models: AtomicU64,
    /// The total inference fee volume, in tokens.
    pub total_fee_volume: AtomicU64,
}

impl AgentMetrics {
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

    /// A summary of the metrics, for debugging and monitoring.
    #[must_use]
    pub fn summary(&self) -> AgentMetricsSnapshot {
        AgentMetricsSnapshot {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            verified_inferences: self.verified_inferences.load(Ordering::Relaxed),
            slashed_operators: self.slashed_operators.load(Ordering::Relaxed),
            active_models: self.active_models.load(Ordering::Relaxed),
            total_fee_volume: self.total_fee_volume.load(Ordering::Relaxed),
        }
    }
}

/// A snapshot of the metrics (Clone plus Display).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMetricsSnapshot {
    pub total_queries: u64,
    pub verified_inferences: u64,
    pub slashed_operators: u64,
    pub active_models: u64,
    pub total_fee_volume: u64,
}

impl std::fmt::Display for AgentMetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Agent{{queries={}, verified={}, slashed={}, models={}, fee_volume={}}}",
            self.total_queries,
            self.verified_inferences,
            self.slashed_operators,
            self.active_models,
            self.total_fee_volume
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_track_queries_and_fees() {
        let m = AgentMetrics::new();
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
