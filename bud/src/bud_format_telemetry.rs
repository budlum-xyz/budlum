//! B.U.D. 2.0 - ACCESS TELEMETRY (the culling stream - completing K106).
//!
//! Remaining work item #2: "the culling telemetry stream - feeding the access
//! counter from the runner/production side."
//! This module is the ACCESS COUNTER layer that feeds `engine_store_tiered`:
//! - `AccessTracker`: counts accesses per cluster, decays them over time, and
//!   hands the access pattern out as a `&[u64]` suited to
//!   CullingPlan::from_access.
//! - The production side (runner/API) calls `tracker.record(cluster_id)` on
//!   every read; a periodic `tracker.plan(hot, cold, ts)` produces the tier
//!   plan.
//! - Deterministik, panik'siz, no unsafe.

#![forbid(unsafe_code)]

use crate::bud_format_culling::CullingPlan;
use sha3::{Digest, Sha3_256};

pub const TELEMETRY_MAGIC: [u8; 8] = *b"\xB5TELM\0\0\0";
pub const TELEMETRY_VERSION: u8 = 1;
pub const MAX_CLUSTERS: usize = 1_000_000;

/// The access counter: cluster_id -> access count (its temperature).
#[derive(Debug, Clone)]
pub struct AccessTracker {
    counts: Vec<u64>,
    touches: Vec<u64>, // the last time seen (for the decay)
    capacity: usize,
}

impl AccessTracker {
    /// An empty counter for `capacity` clusters (0 means everything is
    /// cold).
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

    /// Record one access (an out-of-bounds cluster_id is ignored, no
    /// panic).
    pub fn record(&mut self, cluster_id: usize, ts_unix: u64) {
        if cluster_id < self.capacity {
            self.counts[cluster_id] = self.counts[cluster_id].saturating_add(1);
            self.touches[cluster_id] = ts_unix;
        }
    }

    /// Time decay: halve the counts within `half_life_sec`. Old accesses cool
    /// down, which creates the culling opportunity (cold data is pruned first,
    /// inspiration 2 A).
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

    /// The counter array (the input to CullingPlan::from_access).
    pub fn snapshot(&self) -> &[u64] {
        &self.counts
    }

    /// Produce the tier plan (the culling integration - the same thresholds
    /// as engine_store_tiered).
    pub fn plan(&self, hot_threshold: u64, cold_threshold: u64, ts: u64) -> Option<CullingPlan> {
        CullingPlan::from_access(&self.counts, hot_threshold, cold_threshold, ts)
    }

    /// Total accesses (a diagnostic).
    pub fn total_access(&self) -> u64 {
        self.counts.iter().sum()
    }

    /// A deterministic record digest (writable to the chain - the telemetry
    /// proof).
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
    fn the_tracker_counts_and_produces_a_plan() {
        let mut t = AccessTracker::new(10).unwrap();
        for i in 0..10 {
            for _ in 0..(i as u64 * 5) {
                t.record(i, 1);
            }
        }
        assert_eq!(t.total_access(), 225);
        let plan = t.plan(10, 1, 2).unwrap();
        let (h, w, _c, cu) = plan.tier_summary();
        // i=2..9 -> at least 10 accesses -> Hot; i=1 -> 5 -> Warm; i=0 -> 0
        // -> Culled
        assert_eq!(h, 8);
        assert_eq!(w, 1);
        assert_eq!(cu, 1);
        assert!(plan.culling_ratio() > 0.0);
    }

    #[test]
    fn cold_data_is_pruned_after_the_decay() {
        let mut t = AccessTracker::new(4).unwrap();
        t.record(0, 100);
        t.record(0, 101);
        t.record(1, 100);
        t.decay(100_000, 50); // very old -> almost zero
        assert_eq!(t.snapshot()[0], 0);
        assert_eq!(t.snapshot()[1], 0);
    }

    #[test]
    fn out_of_bounds_is_ignored_without_a_panic() {
        let mut t = AccessTracker::new(2).unwrap();
        t.record(5, 1); // out of bounds
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
