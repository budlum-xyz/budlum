//! Repeated invalid-signature vote tracking.
//!
//! Rejects every cryptographically-invalid finality vote at ingest
//! (closing a single-signature DoS). But a rejected vote never enters the
//! Aggregate, so the sender paid nothing - a validator could spam garbage
//! Signatures forever. This module closes that gap with the SAME pattern as
//! [`LivenessTracker`](crate::registry::LivenessTracker): a persisted per-epoch
//! Counter that, once it crosses [`RegistryParams::max_invalid_votes_per_epoch`],
//! Emits a canonical [`SlashingReport`] (proof = `InvalidSignatureSpam`,
//! Provenance = `ConsensusVerified`) for the *existing* report→slash flow - no
//! Second slashing path is introduced.
//!
//! ## Design decisions
//! * **Epoch-scoped counter** (option A+): the count resets at each new epoch,
//!   Mirroring `LivenessTracker`'s consecutive-epoch semantics. A validator that
//!   Spams within one epoch is caught; scattered single misjabs across epochs
//!   Are not disproportionately punished.
//! * **Persisted, standalone tracker** (NOT inside `FinalityAggregator`): the
//!   Aggregator is recreated every checkpoint (`FINALITY_CHECKPOINT_INTERVAL`
//!   Blocks) and dropped after each certificate, while an epoch spans
//!   `EPOCH_LEN` blocks - so an epoch-scoped counter cannot live in the
//!   Aggregator. It lives in `AccountState` and round-trips via `StateSnapshotV2`.
//! * **Provenance `ConsensusVerified`**: the node's own consensus layer
//!   Cryptographically rejected each vote at ingest; "how many were rejected" is
//!   The node's first-hand observation, not an external accusation.

use crate::core::address::Address;
use crate::registry::evidence::SlashingReport;
use crate::registry::params::RegistryParams;
use crate::registry::role::roles;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

type InvalidVoteSample = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Maximum independently verifiable samples in one spam report. With the
/// finality ingress bounds below, even 24 worst-case JSON-encoded samples fit
/// the 65,536-byte report limit. Governance uses this same ceiling: accepting
/// a larger threshold but verifying only a truncated sample set would allow
/// slashing before the configured threshold was actually proved.
pub const MAX_SPAM_REPORT_SAMPLES: usize = 24;

/// Samples come only from BLS finality votes, not the PQ signature table. The
/// ingress refuses larger signatures before authentication or pairing.
const MAX_VOTE_PREIMAGE_BYTES: usize = crate::chain::finality::MAX_VOTE_PREIMAGE_BYTES;
const MAX_VOTE_SIGNATURE_BYTES: usize = crate::chain::finality::BLS_VOTE_SIGNATURE_BYTES;
const MAX_SAMPLES_BYTES_PER_VALIDATOR: usize = 16 * 1_024;

/// Per-validator, per-epoch invalid-signature-vote counter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvalidVoteTracker {
    /// The epoch the current counts belong to. Counts are reset when a vote for
    /// A newer epoch is recorded.
    current_epoch: u64,
    /// Validator -> invalid votes seen this epoch (only present while > 0).
    counts: BTreeMap<Address, u64>,
    /// Validators already reported this epoch, to avoid re-slashing every extra
    /// Invalid vote after the threshold is crossed.
    reported: BTreeMap<Address, ()>,
    /// Self-authenticated invalid vote samples `(auth_msg, auth_sig, vote_msg, bad_sig)`
    /// retained locally so an emitted report carries cryptographic proof checkable
    /// inside `apply_block_effects` by any validating peer.
    #[serde(skip)]
    samples: BTreeMap<Address, Vec<InvalidVoteSample>>,
}

impl InvalidVoteTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.current_epoch == 0 && self.counts.is_empty() && self.reported.is_empty()
    }

    /// Current invalid-vote count for a validator in the tracker's active epoch.
    pub fn invalid_count(&self, validator: &Address) -> u64 {
        self.counts.get(validator).copied().unwrap_or(0)
    }

    #[must_use]
    pub fn tracked_validator_count(&self) -> usize {
        let mut validators = BTreeSet::new();
        validators.extend(self.counts.keys().copied());
        validators.extend(self.reported.keys().copied());
        validators.extend(self.samples.keys().copied());
        validators.len()
    }

    /// The epoch the current counts belong to.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Record one rejected (cryptographically-invalid) vote from `validator` in
    /// `epoch`. Returns `Some(report)` exactly once, on the vote that crosses
    /// [`RegistryParams::max_invalid_votes_per_epoch`] for this validator this
    /// Epoch. A threshold of 0 disables spam slashing entirely.
    pub fn record_invalid_vote(
        &mut self,
        epoch: u64,
        validator: Address,
        params: &RegistryParams,
    ) -> Option<SlashingReport> {
        self.record_invalid_vote_inner(epoch, validator, params, false)
    }

    fn record_invalid_vote_inner(
        &mut self,
        epoch: u64,
        validator: Address,
        params: &RegistryParams,
        require_samples: bool,
    ) -> Option<SlashingReport> {
        // A stale epoch must not move the tracker: recording under it
        // would reset the current epoch's counters and reported set, and a
        // spammer could dodge the threshold forever by interleaving old
        // votes. Only the current or a newer epoch is recorded.
        if epoch < self.current_epoch {
            return None;
        }
        // New epoch: reset all per-epoch state.
        if epoch != self.current_epoch {
            self.current_epoch = epoch;
            self.counts.clear();
            self.reported.clear();
            self.samples.clear();
        }

        let count = self.counts.entry(validator).or_insert(0);
        *count = count.saturating_add(1);
        let current = *count;

        let threshold = params.max_invalid_votes_per_epoch;
        let enough_samples = !require_samples
            || self.samples.get(&validator).is_some_and(|samples| {
                (samples.len() as u64) >= threshold
            });
        if threshold > 0
            && current >= threshold
            && enough_samples
            && !self.reported.contains_key(&validator)
        {
            self.reported.insert(validator, ());
            let collected = self.samples.remove(&validator).unwrap_or_default();
            return Some(
                SlashingReport::consensus_invalid_signature_spam_with_samples(
                    validator,
                    roles::VALIDATOR,
                    epoch,
                    current,
                    threshold,
                    collected,
                    None,
                ),
            );
        }
        None
    }

    /// Record a self-authenticated invalid vote sample alongside incrementing the
    /// per-epoch counter so emitted spam reports carry cryptographic evidence checkable
    /// inside `apply_block_effects`.
    pub fn record_invalid_vote_with_sample(
        &mut self,
        epoch: u64,
        validator: Address,
        sample: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
        params: &RegistryParams,
    ) -> Option<SlashingReport> {
        if epoch < self.current_epoch
            || sample.2.len() > MAX_VOTE_PREIMAGE_BYTES
            || sample.3.len() > MAX_VOTE_SIGNATURE_BYTES
            || sample.1.len() > MAX_VOTE_SIGNATURE_BYTES
            || sample.0.len() > MAX_VOTE_PREIMAGE_BYTES + MAX_VOTE_SIGNATURE_BYTES + 64
            || params.max_invalid_votes_per_epoch > MAX_SPAM_REPORT_SAMPLES as u64
        {
            return None;
        }
        if crate::chain::finality::vote_auth_signing_message(&sample.2, &sample.3) != sample.0 {
            return None;
        }
        if crate::chain::finality::vote_message_epoch(&sample.2) != Some(epoch) {
            return None;
        }
        if epoch != self.current_epoch {
            self.current_epoch = epoch;
            self.counts.clear();
            self.reported.clear();
            self.samples.clear();
        }
        let entry = self.samples.entry(validator).or_default();
        if entry
            .iter()
            .any(|existing| existing.2 == sample.2 && existing.3 == sample.3)
        {
            return None;
        }
        let sample_cap = params
            .max_invalid_votes_per_epoch
            .min(MAX_SPAM_REPORT_SAMPLES as u64) as usize;
        if entry.len() < sample_cap {
            let retained: usize = entry
                .iter()
                .map(|(auth_msg, auth_sig, vote_msg, bad_sig)| {
                    auth_msg.len() + auth_sig.len() + vote_msg.len() + bad_sig.len()
                })
                .fold(0usize, usize::saturating_add);
            let incoming = sample.0.len() + sample.1.len() + sample.2.len() + sample.3.len();
            if retained.saturating_add(incoming) > MAX_SAMPLES_BYTES_PER_VALIDATOR {
                // Never mark an offence as reported without retainable proof.
                return None;
            }
            entry.push(sample);
        }
        self.record_invalid_vote_inner(epoch, validator, params, true)
    }
}

impl InvalidVoteTracker {
    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        // V2: each map carries its count, so an entry cannot slide from
        // the counts into the reported set.
        //
        // Migration policy: see `BnsRegistry::root` (BDLM_BNS_REGISTRY_V2)
        // for the shared rule - the V-bumped roots activate with the USL
        // genesis, there is no pre-launch mainnet state to migrate, and a
        // post-launch bump needs its migration recorded in the same commit.
        hasher.update(b"BDLM_INVALID_VOTE_TRACKER_V2");
        hasher.update(self.current_epoch.to_le_bytes());
        hasher.update((self.counts.len() as u64).to_le_bytes());
        for (addr, count) in &self.counts {
            hasher.update(addr.0);
            hasher.update(count.to_le_bytes());
        }
        hasher.update((self.reported.len() as u64).to_le_bytes());
        for addr in self.reported.keys() {
            hasher.update(addr.0);
        }
        hasher.finalize().into()
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

    /// A vote from an old epoch is ignored outright: it must not reset the
    /// current epoch's counters, which would let interleaved stale votes
    /// keep a spammer under the threshold forever.
    #[test]
    fn a_stale_epoch_vote_cannot_reset_the_counters() {
        let mut t = InvalidVoteTracker::new();
        let p = params(3);
        for _ in 0..2 {
            assert!(t.record_invalid_vote(5, addr(1), &p).is_none());
        }
        // Stale vote: ignored, and the two recorded votes survive it.
        assert!(t.record_invalid_vote(2, addr(1), &p).is_none());
        assert_eq!(t.current_epoch, 5);
        assert_eq!(t.counts.get(&addr(1)), Some(&2));
        // The third current-epoch vote still trips the threshold.
        assert!(t.record_invalid_vote(5, addr(1), &p).is_some());
    }

    /// The counts map and the reported set are counted, so an address
    /// cannot slide from one into the other without moving the root.
    #[test]
    fn root_commits_each_map_count() {
        let mut a = InvalidVoteTracker::new();
        a.counts.insert(addr(1), 1);
        let mut b = InvalidVoteTracker::new();
        b.reported.insert(addr(1), ());
        assert_ne!(a.root(), b.root());
        let mut c = a.clone();
        c.reported.insert(addr(1), ());
        assert_ne!(a.root(), c.root());
        assert_ne!(InvalidVoteTracker::new().root(), a.root());
    }

    #[test]
    fn oversized_or_duplicate_samples_cannot_create_a_false_report() {
        let mut t = InvalidVoteTracker::new();
        let p = params(3);
        let v = addr(1);
        let vote = crate::chain::finality::checkpoint_signing_message(45261, 7, 10, "hash");
        let padded = vec![0xAB; MAX_VOTE_SIGNATURE_BYTES + 1];
        let auth = crate::chain::finality::vote_auth_signing_message(&vote, &padded);
        assert!(t
            .record_invalid_vote_with_sample(7, v, (auth, vec![1; 48], vote.clone(), padded), &p)
            .is_none());
        assert_eq!(t.invalid_count(&v), 0);

        let sig = vec![2u8; 48];
        let auth = crate::chain::finality::vote_auth_signing_message(&vote, &sig);
        let sample = (auth, vec![3; 48], vote.clone(), sig);
        assert!(t
            .record_invalid_vote_with_sample(7, v, sample.clone(), &p)
            .is_none());
        for _ in 0..10 {
            assert!(t
                .record_invalid_vote_with_sample(7, v, sample.clone(), &p)
                .is_none());
        }
        assert_eq!(
            t.invalid_count(&v),
            1,
            "replays are not independent evidence"
        );
        for byte in [4u8, 5] {
            let sig = vec![byte; 48];
            let auth = crate::chain::finality::vote_auth_signing_message(&vote, &sig);
            let report = t.record_invalid_vote_with_sample(
                7,
                v,
                (auth, vec![3; 48], vote.clone(), sig),
                &p,
            );
            if byte == 4 {
                assert!(report.is_none());
            } else {
                match report
                    .expect("three distinct samples cross the threshold")
                    .proof
                {
                    SlashingProof::InvalidSignatureSpam { samples, .. } => {
                        assert_eq!(samples.len(), 3);
                    }
                    other => panic!("expected InvalidSignatureSpam, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn a_restored_counter_waits_until_the_full_evidence_is_available() {
        let mut t = InvalidVoteTracker::new();
        let p = params(3);
        let v = addr(1);
        t.current_epoch = 7;
        t.counts.insert(v, 3);
        for height in 0..3 {
            let vote = crate::chain::finality::checkpoint_signing_message(45261, 7, height, "hash");
            let sig = vec![2u8; 48];
            let auth = crate::chain::finality::vote_auth_signing_message(&vote, &sig);
            let report = t.record_invalid_vote_with_sample(
                7,
                v,
                (auth, vec![3; 48], vote, sig),
                &p,
            );
            assert_eq!(report.is_some(), height == 2);
        }
    }

    #[test]
    fn maximum_configured_report_fits_json_limit_and_proves_every_vote() {
        let mut tracker = InvalidVoteTracker::new();
        let threshold = MAX_SPAM_REPORT_SAMPLES as u64;
        let p = params(threshold);
        assert!(p.validate().is_ok());
        let mut report = None;
        for i in 0..threshold {
            let vote = crate::chain::finality::checkpoint_signing_message(
                u64::MAX,
                u64::MAX,
                u64::MAX - i,
                &"f".repeat(128),
            );
            let sig = vec![255; MAX_VOTE_SIGNATURE_BYTES];
            let auth = crate::chain::finality::vote_auth_signing_message(&vote, &sig);
            let next = tracker.record_invalid_vote_with_sample(
                u64::MAX,
                addr(255),
                (auth, vec![255; 48], vote, sig),
                &p,
            );
            if next.is_some() {
                assert_eq!(i + 1, threshold);
                report = next;
            }
        }
        let report = report.expect("the whole threshold is retained");
        assert!(serde_json::to_vec(&report).unwrap().len() <= 65_536);
        match report.proof {
            SlashingProof::InvalidSignatureSpam { samples, .. } => {
                assert_eq!(samples.len() as u64, threshold);
            }
            other => panic!("expected InvalidSignatureSpam, got {other:?}"),
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
                ..
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
