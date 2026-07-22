//! Repeated invalid-signature vote tracking (Task 0.40, Görev 2).
//!
//! Task 0.38 Fix 2 rejects every cryptographically-invalid finality vote at ingest
//! (closing a single-signature DoS). But a rejected vote never enters the
//! aggregate, so the sender paid nothing — a validator could spam garbage
//! signatures forever. This module closes that gap with the SAME pattern as
//! [`LivenessTracker`](crate::registry::LivenessTracker): a persisted per-epoch
//! counter that, once it crosses [`RegistryParams::max_invalid_votes_per_epoch`],
//! emits a canonical [`SlashingReport`] (proof = `InvalidSignatureSpam`,
//! provenance = `ConsensusVerified`) for the *existing* report→slash flow — no
//! second slashing path is introduced.
//!
//! ## Design decisions (Task 0.40, user-approved)
//! * **Epoch-scoped counter** (Seçenek A+): the count resets at each new epoch,
//!   mirroring `LivenessTracker`'s consecutive-epoch semantics. A validator that
//!   spams within one epoch is caught; scattered single misjabs across epochs
//!   are not disproportionately punished.
//! * **Persisted, standalone tracker** (NOT inside `FinalityAggregator`): the
//!   aggregator is recreated every checkpoint (`FINALITY_CHECKPOINT_INTERVAL`
//!   blocks) and dropped after each certificate, while an epoch spans
//!   `EPOCH_LEN` blocks — so an epoch-scoped counter cannot live in the
//!   aggregator. It lives in `AccountState` and round-trips via `StateSnapshotV2`.
//! * **Provenance `ConsensusVerified`**: the node's own consensus layer
//!   cryptographically rejected each vote at ingest; "how many were rejected" is
//!   the node's first-hand observation, not an external accusation.

use crate::core::address::Address;
use crate::registry::evidence::SlashingReport;
use crate::registry::params::RegistryParams;
use crate::registry::role::roles;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Per-validator, per-epoch invalid-signature-vote counter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvalidVoteTracker {
    /// The epoch the current counts belong to. Counts are reset when a vote for
    /// a newer epoch is recorded.
    current_epoch: u64,
    /// validator -> invalid votes seen this epoch (only present while > 0).
    counts: BTreeMap<Address, u64>,
    /// Validators already reported this epoch, to avoid re-slashing every extra
    /// invalid vote after the threshold is crossed.
    reported: BTreeMap<Address, ()>,
}

impl InvalidVoteTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current invalid-vote count for a validator in the tracker's active epoch.
    pub fn invalid_count(&self, validator: &Address) -> u64 {
        self.counts.get(validator).copied().unwrap_or(0)
    }

    /// The epoch the current counts belong to.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Record one rejected (cryptographically-invalid) vote from `validator` in
    /// `epoch`. Returns `Some(report)` exactly once — on the vote that crosses
    /// [`RegistryParams::max_invalid_votes_per_epoch`] for this validator this
    /// epoch. A threshold of 0 disables spam slashing entirely.
    pub fn record_invalid_vote(
        &mut self,
        epoch: u64,
        validator: Address,
        params: &RegistryParams,
    ) -> Option<SlashingReport> {
        // New epoch: reset all per-epoch state.
        if epoch != self.current_epoch {
            self.current_epoch = epoch;
            self.counts.clear();
            self.reported.clear();
        }

        let count = self.counts.entry(validator).or_insert(0);
        *count += 1;
        let current = *count;

        let threshold = params.max_invalid_votes_per_epoch;
        if threshold > 0 && current >= threshold && !self.reported.contains_key(&validator) {
            self.reported.insert(validator, ());
            return Some(SlashingReport::consensus_invalid_signature_spam(
                validator,
                roles::VALIDATOR,
                epoch,
                current,
                threshold,
                None,
            ));
        }
        None
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
            max_invalid_votes_per_epoch: threshold,
            ..RegistryParams::default()
        }
    }

    #[test]
    fn triggers_after_threshold_in_one_epoch() {
        let mut t = InvalidVoteTracker::new();
        let p = params(3);
        let v = addr(1);
        assert!(t.record_invalid_vote(5, v, &p).is_none());
        assert!(t.record_invalid_vote(5, v, &p).is_none());
        let report = t
            .record_invalid_vote(5, v, &p)
            .expect("threshold crossed on 3rd invalid vote");
        match &report.proof {
            SlashingProof::InvalidSignatureSpam {
                epoch,
                count,
                threshold,
            } => {
                assert_eq!(*epoch, 5);
                assert_eq!(*count, 3);
                assert_eq!(*threshold, 3);
            }
            other => panic!("expected InvalidSignatureSpam, got {other:?}"),
        }
    }

    #[test]
    fn does_not_re_report_same_epoch() {
        let mut t = InvalidVoteTracker::new();
        let p = params(2);
        let v = addr(1);
        assert!(t.record_invalid_vote(1, v, &p).is_none());
        assert!(t.record_invalid_vote(1, v, &p).is_some());
        // Further invalid votes in the same epoch do not re-report.
        assert!(t.record_invalid_vote(1, v, &p).is_none());
        assert!(t.record_invalid_vote(1, v, &p).is_none());
    }

    #[test]
    fn resets_across_epochs() {
        let mut t = InvalidVoteTracker::new();
        let p = params(3);
        let v = addr(1);
        t.record_invalid_vote(1, v, &p);
        t.record_invalid_vote(1, v, &p);
        assert_eq!(t.invalid_count(&v), 2);
        // New epoch resets the count; a single invalid vote does not trigger.
        assert!(t.record_invalid_vote(2, v, &p).is_none());
        assert_eq!(t.invalid_count(&v), 1);
    }

    #[test]
    fn threshold_zero_disables() {
        let mut t = InvalidVoteTracker::new();
        let p = params(0);
        let v = addr(1);
        for _ in 0..50 {
            assert!(t.record_invalid_vote(1, v, &p).is_none());
        }
    }

    #[test]
    fn independent_validators_counted_separately() {
        let mut t = InvalidVoteTracker::new();
        let p = params(2);
        let a = addr(1);
        let b = addr(2);
        assert!(t.record_invalid_vote(1, a, &p).is_none());
        assert!(t.record_invalid_vote(1, b, &p).is_none());
        // Each needs its own threshold.
        assert!(t.record_invalid_vote(1, a, &p).is_some());
        assert!(t.record_invalid_vote(1, b, &p).is_some());
    }
}
