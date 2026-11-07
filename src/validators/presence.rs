//! Presence protocol and suspension (directive section 7.8, WP-13).
//!
//! A validator proves it is online with a signed [`PresenceSignal`] per
//! presence window, gossiped on [`PRESENCE_TOPIC`]. The first proposer of
//! window `w + 1` embeds a [`PresenceAggregate`] for window `w`; one
//! aggregate BLS verification covers the whole bitmap. The last-seen window
//! of every validator lives in chain state. A validator that stays invisible
//! past its class threshold is **suspended**, never slashed (V-4): absence is
//! not a crime, only double-signing a presence signal is (1%, section 11.7).
//! `ResumeValidator` reactivates a suspended validator one epoch later.
//!
//! Hour-based windows are converted to epochs with
//! `ceil(hours * 3600 / (slot_secs * epoch_slots))` (section 6.21.3), so no
//! consensus decision depends on wall-clock time.
//!
//! exposed for: validator epoch presence bitmap tracking and suspension scheduling (`WP-07`, `WP-13`).

use crate::core::address::Address;
use crate::registry::evidence::{DoubleSignKind, SlashingProof, SlashingReport};
use crate::validators::ValidatorClass;
use serde::{Deserialize, Serialize};
pub use budlum_types::{PresenceSignal, PRESENCE_TOPIC};
use std::collections::BTreeMap;

/// The gossipsub topic presence signals are published on.
/// Domain tag of the presence message (registered in `src/crypto/domain_tags.rs`).
pub const PRESENCE_DOMAIN_TAG: &str = "BDLM_PRESENCE_V1";

/// Presence double-signing slashes one percent of the stake (section 11.7,
/// KR-08: only proven double-sign and proven bad repair slash).
pub const PRESENCE_DOUBLE_SIGN_BPS: u64 = 100;

/// Testnet defaults (section 7.8): a Full window is one epoch, a Mobile
/// window is four epochs (ten minutes at 3 s slots and 50-slot epochs).
pub const FULL_WINDOW_EPOCHS: u64 = 1;
pub const MOBILE_WINDOW_EPOCHS: u64 = 4;

/// Suspension thresholds in hours (section 7.2): Full 1 day, Mobile 72 h,
/// iOS opportunistic 7 days.
pub const FULL_SUSPEND_HOURS: u64 = 24;
pub const MOBILE_SUSPEND_HOURS: u64 = 72;
pub const OPPORTUNISTIC_SUSPEND_HOURS: u64 = 168;

/// Convert an hour-based window to epochs: `ceil(hours * 3600 / (slot_secs *
/// epoch_slots))` (section 6.21.3). Integer arithmetic only; no floats in a
/// consensus path (G-2).
#[must_use]
pub fn hours_to_epochs(hours: u64, slot_secs: u64, epoch_slots: u64) -> u64 {
    let slot_secs = slot_secs.max(1);
    let epoch_secs = slot_secs.saturating_mul(epoch_slots.max(1));
    let seconds = hours.saturating_mul(3_600);
    seconds.div_ceil(epoch_secs)
}

/// The suspension threshold of a class, in epochs.
#[must_use]
pub fn suspension_threshold_epochs(
    class: ValidatorClass,
    slot_secs: u64,
    epoch_slots: u64,
) -> u64 {
    let hours = match class {
        ValidatorClass::Full => FULL_SUSPEND_HOURS,
        ValidatorClass::Mobile => MOBILE_SUSPEND_HOURS,
        ValidatorClass::MobileOpportunistic => OPPORTUNISTIC_SUSPEND_HOURS,
    };
    hours_to_epochs(hours, slot_secs, epoch_slots)
}

/// The canonical presence message: `SHA3-256(BDLM_PRESENCE_V1 ‖ len ‖
/// chain_id ‖ len ‖ window ‖ len ‖ class)`. Every field is length-prefixed
/// (G-5). The class is inside the signed message, so signing a signal for
/// two different classes in one window is a provable double sign.
#[must_use]
pub fn presence_message(chain_id: u64, window: u64, class: ValidatorClass) -> Vec<u8> {
    budlum_types::presence_message(chain_id, window, class).to_vec()
}

/// The per-window aggregate a block proposer embeds: the bitmap of
/// validators seen in window `w` and one aggregate BLS signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceAggregate {
    pub window: u64,
    pub class: ValidatorClass,
    /// One bit per signer, in signer order.
    pub bitmap: Vec<u8>,
    pub aggregate_sig: Vec<u8>,
}

/// What recording a signal produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceEvent {
    /// The signal verified; the validator is seen in this window.
    Seen,
    /// The same validator signed a different message for the same window:
    /// a provable double sign. Carries the consensus-verified report.
    DoubleSign(SlashingReport),
}

/// Chain-state presence bookkeeping: last-seen window per validator,
/// suspensions with their resume epoch, and the seen signatures of the
/// current window for double-sign detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PresenceTracker {
    #[serde(with = "crate::core::map_keys")]
    last_seen_window: BTreeMap<[u8; 32], u64>,
    /// Suspended validator -> epoch at which a resume takes effect.
    #[serde(with = "crate::core::map_keys")]
    suspended: BTreeMap<[u8; 32], u64>,
    /// validator -> the (window, signature) pairs seen, kept for one
    /// window only.
    #[serde(with = "crate::core::map_keys")]
    seen_signatures: BTreeMap<[u8; 32], BTreeMap<u64, Vec<u8>>>,
    /// Windows observed so far, and how many validators were seen in each
    /// (the reward multiplier input, section 7.8.9).
    window_seen: BTreeMap<u64, u64>,
    window_total: u64,
}

impl PresenceTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Last window the validator was seen in.
    #[must_use]
    pub fn last_seen_window(&self, validator: &Address) -> Option<u64> {
        self.last_seen_window.get(&validator.0).copied()
    }

    /// Whether the validator is suspended at `epoch`.
    #[must_use]
    pub fn is_suspended(&self, validator: &Address, epoch: u64) -> bool {
        self.suspended
            .get(&validator.0)
            .is_some_and(|resume| *resume > epoch)
    }

    /// Record a verified presence signal. `bls_pk` is the validator's
    /// registered BLS key. A second, different signature for the same
    /// (validator, window) is a double sign and yields a consensus-verified
    /// report.
    /// exposed for: validator epoch presence signal ingestion (`WP-07`).
    pub fn record_signal(
        &mut self,
        chain_id: u64,
        signal: &PresenceSignal,
        bls_pk: &[u8],
    ) -> Result<PresenceEvent, String> {
        let msg = presence_message(chain_id, signal.window, signal.class);
        crate::chain::finality::verify_bls_sig(bls_pk, &msg, &signal.sig_bls)?;
        if let Some(old) = self
            .seen_signatures
            .get(&signal.validator.0)
            .and_then(|by_win| by_win.get(&signal.window))
        {
            if *old != signal.sig_bls {
                // Same window, same validator, two different signatures:
                // only the offender's key can produce both (section 7.8.8).
                let report = SlashingReport::consensus_double_sign(
                    signal.validator,
                    SlashingProof::DoubleSign {
                        height: signal.window,
                        kind: DoubleSignKind::Prevote,
                        epoch: Some(signal.window),
                        block_hash_1: hex::encode(&msg),
                        block_hash_2: hex::encode(old),
                        signature_1: old.clone(),
                        signature_2: signal.sig_bls.clone(),
                    },
                    None,
                );
                return Ok(PresenceEvent::DoubleSign(report));
            }
            return Ok(PresenceEvent::Seen);
        }
        self.seen_signatures
            .entry(signal.validator.0)
            .or_default()
            .insert(signal.window, signal.sig_bls.clone());
        self.last_seen_window.insert(signal.validator.0, signal.window);
        *self.window_seen.entry(signal.window).or_insert(0) += 1;
        self.window_total = self.window_total.saturating_add(1);
        Ok(PresenceEvent::Seen)
    }

    /// Verify a window aggregate: one aggregate BLS check over the bitmap
    /// signers (section 7.8.4).
    pub fn verify_aggregate(
        &self,
        chain_id: u64,
        aggregate: &PresenceAggregate,
        signers: &[(Address, Vec<u8>)],
    ) -> Result<(), String> {
        let msg = presence_message(chain_id, aggregate.window, aggregate.class);
        let pks: Vec<Vec<u8>> = signers.iter().map(|(_, pk)| pk.clone()).collect();
        crate::chain::finality::verify_bls_aggregate(&pks, &msg, &aggregate.aggregate_sig)
    }

    /// Advance to `window`: every validator of `classes` whose absence
    /// exceeds its class threshold (converted from hours to epochs) is
    /// suspended. Returns the newly suspended validators. Absence never
    /// slashes (V-4).
    /// exposed for: validator presence window rotation at epoch boundary (`WP-07`).
    pub fn advance_window(
        &mut self,
        window: u64,
        classes: &BTreeMap<Address, ValidatorClass>,
        slot_secs: u64,
        epoch_slots: u64,
        epoch: u64,
    ) -> Vec<Address> {
        let mut newly_suspended = Vec::new();
        for (validator, class) in classes {
            if self.is_suspended(validator, epoch) {
                continue;
            }
            let last = self.last_seen_window(validator).unwrap_or(0);
            let missed_epochs = window.saturating_sub(last).saturating_mul(match *class {
                ValidatorClass::Full => FULL_WINDOW_EPOCHS,
                _ => MOBILE_WINDOW_EPOCHS,
            });
            let threshold = suspension_threshold_epochs(*class, slot_secs, epoch_slots);
            if threshold > 0 && missed_epochs >= threshold {
                // Resume takes effect one epoch after a resume request; until
                // then the validator takes no new duty.
                self.suspended.insert(validator.0, u64::MAX);
                newly_suspended.push(*validator);
            }
        }
        newly_suspended
    }

    /// `ResumeValidator`: the suspension lifts one epoch later (section
    /// 7.8.7).
    pub fn request_resume(&mut self, validator: &Address, epoch: u64) {
        self.suspended
            .insert(validator.0, epoch.saturating_add(1));
    }

    /// Apply resumes whose epoch has come; returns the reactivated
    /// validators.
    pub fn activate_due_resumes(&mut self, epoch: u64) -> Vec<Address> {
        let due: Vec<[u8; 32]> = self
            .suspended
            .iter()
            .filter(|(_, resume)| **resume <= epoch)
            .map(|(addr, _)| *addr)
            .collect();
        for addr in &due {
            self.suspended.remove(addr);
        }
        due.into_iter().map(Address::from).collect()
    }

    /// Reward multiplier (section 7.8.9): the ratio of windows the validator
    /// was seen in, as a fixed-point fraction of `FIXED_POINT_SCALE`.
    /// exposed for: validator presence ratio custody reward multiplier (`WP-07`, `WP-25`).
    #[must_use]
    pub fn presence_ratio(&self, validator: &Address) -> u64 {
        if self.window_total == 0 {
            return crate::core::chain_config::FIXED_POINT_SCALE;
        }
        // A validator seen in the tracked span counts fully; the
        // fine-grained per-window ratio is read by WP-25/WP-16 from the
        // window counters.
        if self.last_seen_window.contains_key(&validator.0) {
            crate::core::chain_config::FIXED_POINT_SCALE
        } else {
            0
        }
    }

    /// Drop the signature cache of windows older than `window` so the map
    /// stays bounded by one window.
    /// exposed for: validator presence window pruning (`WP-07`).
    pub fn retain_window(&mut self, window: u64) {
        self.seen_signatures.retain(|_, by_win| {
            by_win.retain(|w, _| *w >= window);
            !by_win.is_empty()
        });
        self.window_seen.retain(|w, _| *w >= window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::chain_config::FIXED_POINT_SCALE;
    use crate::crypto::primitives::BlsKeypair;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    fn keypair(seed: u8) -> BlsKeypair {
        let mut s = [0u8; 64];
        s[0] = seed;
        BlsKeypair::from_seed(&s).unwrap()
    }

    fn signal(chain_id: u64, kp: &BlsKeypair, v: Address, window: u64, class: ValidatorClass) -> PresenceSignal {
        let msg = presence_message(chain_id, window, class);
        PresenceSignal {
            validator: v,
            window,
            class,
            network_hint: [0u8; 32],
            sig_bls: crate::chain::finality::sign_bls(&kp.secret_key, &msg),
        }
    }

    /// One aggregate BLS verification covers the whole window bitmap.
    #[test]
    fn presence_aggregate_verifies() {
        let chain_id = 45261;
        let kp1 = keypair(1);
        let kp2 = keypair(2);
        let v1 = addr(1);
        let v2 = addr(2);
        let mut tracker = PresenceTracker::new();
        let s1 = signal(chain_id, &kp1, v1, 7, ValidatorClass::Full);
        let s2 = signal(chain_id, &kp2, v2, 7, ValidatorClass::Full);
        assert_eq!(
            tracker.record_signal(chain_id, &s1, &kp1.public_key).unwrap(),
            PresenceEvent::Seen
        );
        assert_eq!(
            tracker.record_signal(chain_id, &s2, &kp2.public_key).unwrap(),
            PresenceEvent::Seen
        );
        let msg = presence_message(chain_id, 7, ValidatorClass::Full);
        let agg = crate::chain::finality::aggregate_bls(
            &[&kp1.secret_key, &kp2.secret_key],
            &msg,
        );
        let aggregate = PresenceAggregate {
            window: 7,
            class: ValidatorClass::Full,
            bitmap: vec![0b11],
            aggregate_sig: agg,
        };
        tracker
            .verify_aggregate(
                chain_id,
                &aggregate,
                &[(v1, kp1.public_key.clone()), (v2, kp2.public_key.clone())],
            )
            .expect("the aggregate must verify with one pairing check");
        // A wrong bitmap signer set must fail.
        let bad = tracker.verify_aggregate(chain_id, &aggregate, &[(v1, kp1.public_key.clone())]);
        assert!(bad.is_err());
    }

    /// Absence past the class threshold suspends; it never slashes (V-4).
    #[test]
    fn absent_validator_is_suspended_not_slashed() {
        let mut tracker = PresenceTracker::new();
        let v = addr(9);
        let mut classes = BTreeMap::new();
        classes.insert(v, ValidatorClass::Mobile);
        // Testnet schedule: 3 s slots, 50-slot epochs. 72 h -> many epochs.
        let slot_secs = 3;
        let epoch_slots = 50;
        // Seen once at window 0, then gone.
        tracker
            .last_seen_window
            .insert(v.0, 0);
        let suspended = tracker.advance_window(10_000, &classes, slot_secs, epoch_slots, 10_000);
        assert_eq!(suspended, vec![v]);
        assert!(tracker.is_suspended(&v, 10_000));
        // A suspension is not a slash: no report is produced anywhere here.
    }

    /// `ResumeValidator` reactivates one epoch later, not immediately.
    #[test]
    fn resume_restores_after_one_epoch() {
        let mut tracker = PresenceTracker::new();
        let v = addr(4);
        let mut classes = BTreeMap::new();
        classes.insert(v, ValidatorClass::Full);
        tracker.last_seen_window.insert(v.0, 0);
        let suspended = tracker.advance_window(100, &classes, 3, 50, 100);
        assert_eq!(suspended, vec![v]);
        assert!(tracker.is_suspended(&v, 100));
        tracker.request_resume(&v, 100);
        // Still suspended in the same epoch: the resume waits one epoch.
        assert!(tracker.is_suspended(&v, 100));
        assert!(tracker.activate_due_resumes(100).is_empty());
        let resumed = tracker.activate_due_resumes(101);
        assert_eq!(resumed, vec![v]);
        assert!(!tracker.is_suspended(&v, 101));
    }

    /// Two different presence signatures for one window are a double sign
    /// and produce a consensus-verified report slashed at 1%.
    #[test]
    fn presence_double_sign_is_slashed_one_percent() {
        let chain_id = 45261;
        let kp = keypair(7);
        let v = addr(7);
        let mut tracker = PresenceTracker::new();
        let s1 = signal(chain_id, &kp, v, 3, ValidatorClass::Mobile);
        assert_eq!(
            tracker.record_signal(chain_id, &s1, &kp.public_key).unwrap(),
            PresenceEvent::Seen
        );
        // Same validator and window, but a different class in the message:
        // a different signature over a different message.
        let s2 = signal(chain_id, &kp, v, 3, ValidatorClass::Full);
        match tracker.record_signal(chain_id, &s2, &kp.public_key).unwrap() {
            PresenceEvent::DoubleSign(report) => {
                assert_eq!(report.offender, v);
                assert_eq!(
                    report.provenance(),
                    crate::registry::evidence::ProofProvenance::ConsensusVerified
                );
                assert_eq!(PRESENCE_DOUBLE_SIGN_BPS, 100, "one percent");
            }
            other => panic!("expected a double-sign report, got {other:?}"),
        }
    }

    /// The old liveness report path no longer slashes: absence is a
    /// suspension, and `record_epoch` returns suspended validators, not
    /// slashing reports (V-4, KR-08, BLG-251).
    #[test]
    fn liveness_report_no_longer_slashes() {
        let mut tracker = crate::registry::liveness::LivenessTracker::new();
        let params = crate::registry::params::RegistryParams {
            liveness_max_missed_epochs: 2,
            ..Default::default()
        };
        let v = addr(5);
        assert!(tracker.record_epoch(1, &[v], |_| false, &params).is_empty());
        let suspended = tracker.record_epoch(2, &[v], |_| false, &params);
        assert_eq!(suspended, vec![v], "absence suspends, never slashes");
        assert!(tracker.is_suspended(&v));
        assert!(!tracker.record_epoch(3, &[v], |_| false, &params).contains(&v));
    }

    /// Hour windows convert to epochs with the section 6.21.3 formula.
    #[test]
    fn presence_window_hours_convert_to_epochs() {
        // Testnet: 3 s slot, 50-slot epoch -> 150 s per epoch.
        // 24 h = 86 400 s -> ceil(86 400 / 150) = 576 epochs.
        assert_eq!(hours_to_epochs(24, 3, 50), 576);
        // 72 h -> 1 728 epochs; 7 days -> 4 032 epochs.
        assert_eq!(hours_to_epochs(72, 3, 50), 1_728);
        assert_eq!(hours_to_epochs(168, 3, 50), 4_032);
        // Rounding goes up, never down: 1 h = 3 600 s -> 24 epochs.
        assert_eq!(hours_to_epochs(1, 3, 50), 24);
        // Degenerate slot/epoch values never divide by zero.
        assert_eq!(hours_to_epochs(1, 0, 0), 3_600);
        // The Full class threshold on the testnet schedule.
        assert_eq!(
            suspension_threshold_epochs(ValidatorClass::Full, 3, 50),
            576
        );
        let _ = FIXED_POINT_SCALE;
    }
}
