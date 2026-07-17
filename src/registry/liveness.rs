//! Consensus liveness (downtime) fault detection.
//!
//! `SlashingProof::Liveness` was defined in the previous turn but nothing
//! produced it. This module closes that gap: it tracks, per validator, the
//! number of *consecutive* epochs in which the validator failed to show the
//! expected consensus participation. When that count crosses
//! [`RegistryParams::liveness_max_missed_epochs`], a canonical
//! [`SlashingReport`] (proof = `Liveness`, provenance = `ConsensusVerified`) is
//! emitted so the *existing* report→slash flow can act on it — no new slashing
//! path is introduced.
//!
//! ## Counting semantics (consecutive, not cumulative)
//! The counter is incremented for every epoch a validator misses and **reset to
//! zero the moment it participates again**. This deliberately avoids a
//! cumulative penalty, which would disproportionately punish validators for
//! scattered, transient misses (e.g. brief restarts).

use crate::core::address::Address;
use crate::registry::evidence::SlashingReport;
use crate::registry::params::RegistryParams;
use crate::registry::role::roles;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Per-validator consecutive-miss tracker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LivenessTracker {
    /// validator -> consecutive missed epochs (only present while > 0).
    missed: BTreeMap<Address, u64>,
    /// Epoch at which each validator's current miss-streak began (for the
    /// window fields of the emitted proof).
    streak_start_epoch: BTreeMap<Address, u64>,
    /// Once a validator has been reported at the current streak, we suppress
    /// re-reporting until it participates again (avoids repeated slashing every
    /// epoch while still down).
    reported: BTreeMap<Address, ()>,
}

impl LivenessTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current consecutive-miss count for a validator.
    pub fn missed_count(&self, validator: &Address) -> u64 {
        self.missed.get(validator).copied().unwrap_or(0)
    }

    /// Record one epoch's worth of participation.
    ///
    /// * `epoch` — the epoch that just completed.
    /// * `expected` — validators that were expected to participate this epoch
    ///   (typically the active validator set).
    /// * `participated` — a predicate returning `true` if the given validator
    ///   showed the expected participation this epoch.
    /// * `params` — governs the threshold and is embedded in emitted proofs.
    ///
    /// Returns a [`SlashingReport`] for every validator whose consecutive-miss
    /// count reached the threshold this epoch (and had not already been
    /// reported for the current streak).
    pub fn record_epoch<F>(
        &mut self,
        epoch: u64,
        expected: &[Address],
        mut participated: F,
        params: &RegistryParams,
    ) -> Vec<SlashingReport>
    where
        F: FnMut(&Address) -> bool,
    {
        let mut reports = Vec::new();
        let threshold = params.liveness_max_missed_epochs;

        for validator in expected {
            if participated(validator) {
                // Reset on participation (consecutive, not cumulative).
                self.missed.remove(validator);
                self.streak_start_epoch.remove(validator);
                self.reported.remove(validator);
                continue;
            }

            let count = self.missed.entry(*validator).or_insert(0);
            if *count == 0 {
                self.streak_start_epoch.insert(*validator, epoch);
            }
            *count += 1;
            let current = *count;

            // Threshold of 0 disables liveness slashing entirely.
            if threshold > 0 && current >= threshold && !self.reported.contains_key(validator) {
                let start = self
                    .streak_start_epoch
                    .get(validator)
                    .copied()
                    .unwrap_or(epoch);
                reports.push(SlashingReport::consensus_liveness(
                    *validator,
                    roles::VALIDATOR,
                    start,
                    epoch,
                    current,
                    current,
                    None,
                ));
                self.reported.insert(*validator, ());
            }
        }

        reports
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::evidence::SlashingProof;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    fn params(threshold: u64) -> RegistryParams {
        RegistryParams {
            liveness_max_missed_epochs: threshold,
            ..RegistryParams::default()
        }
    }

    #[test]
    fn triggers_after_threshold_consecutive_misses() {
        let mut t = LivenessTracker::new();
        let p = params(3);
        let v = addr(1);
        // Two misses: no report yet.
        assert!(t.record_epoch(1, &[v], |_| false, &p).is_empty());
        assert!(t.record_epoch(2, &[v], |_| false, &p).is_empty());
        // Third consecutive miss crosses threshold.
        let reports = t.record_epoch(3, &[v], |_| false, &p);
        assert_eq!(reports.len(), 1);
        match &reports[0].proof {
            SlashingProof::Liveness {
                missed,
                window_start_epoch,
                window_end_epoch,
                ..
            } => {
                assert_eq!(*missed, 3);
                assert_eq!(*window_start_epoch, 1);
                assert_eq!(*window_end_epoch, 3);
            }
            other => panic!("expected liveness proof, got {other:?}"),
        }
    }

    #[test]
    fn resets_on_participation() {
        let mut t = LivenessTracker::new();
        let p = params(3);
        let v = addr(1);
        t.record_epoch(1, &[v], |_| false, &p);
        t.record_epoch(2, &[v], |_| false, &p);
        assert_eq!(t.missed_count(&v), 2);
        // Participates: counter resets.
        t.record_epoch(3, &[v], |_| true, &p);
        assert_eq!(t.missed_count(&v), 0);
        // Fresh streak needs the full threshold again.
        assert!(t.record_epoch(4, &[v], |_| false, &p).is_empty());
        assert!(t.record_epoch(5, &[v], |_| false, &p).is_empty());
        assert_eq!(t.record_epoch(6, &[v], |_| false, &p).len(), 1);
    }

    #[test]
    fn does_not_re_report_same_streak() {
        let mut t = LivenessTracker::new();
        let p = params(2);
        let v = addr(1);
        t.record_epoch(1, &[v], |_| false, &p);
        assert_eq!(t.record_epoch(2, &[v], |_| false, &p).len(), 1);
        // Still down at epoch 3 — no duplicate report.
        assert!(t.record_epoch(3, &[v], |_| false, &p).is_empty());
    }

    #[test]
    fn threshold_zero_disables() {
        let mut t = LivenessTracker::new();
        let p = params(0);
        let v = addr(1);
        for e in 1..=20 {
            assert!(t.record_epoch(e, &[v], |_| false, &p).is_empty());
        }
    }
}

impl LivenessTracker {
    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_LIVENESS_TRACKER_V1");
        for (addr, count) in &self.missed {
            hasher.update(addr.0);
            hasher.update(count.to_le_bytes());
        }
        hasher.finalize().into()
    }
}
