//! Deterministic, admin-keyless circuit breaker and contradiction tombstone
//! book for the consensus-resident external-domain intake.
//!
//! No administrator key, privileged multisig, or wall-clock input exists in
//! this module. Every transition is a pure function of local block height,
//! verified contradiction slashings, and consensus quorum outcomes:
//!
//! 1. **Contradiction tombstones.** When an accepted attestation is withdrawn
//!    and slashed for a cryptographic contradiction, both its exact
//!    [`FinalityAttestation::claim_digest`](super::spec::FinalityAttestation::claim_digest)
//!    and its `(height, evidence_version)` claim record are retained (up to
//!    `MAX_CONTRADICTED_CLAIMS_PER_DOMAIN`) so a dishonest prover cannot
//!    replay the withdrawn claim after the domain is later readmitted.
//! 2. **Exponential cooldown without admin override.** Every proven
//!    contradiction or repeated adverse-round burst increments `strike_count`
//!    and opens a deterministic block-height cooldown
//!    `min(BASE_COOLDOWN_BLOCKS << (strike_count - 1), MAX_COOLDOWN_BLOCKS)`.
//!    While `local_height < cooldown_until_block`, both new evidence intake
//!    and domain readmission refuse fail-closed.
//! 3. **Sliding-window adverse-round circuit breaker.** If a vote-based domain
//!    accumulates `ANOMALY_TRIP_THRESHOLD` `Disputed` or `AgreedRefusal`
//!    rounds within `ANOMALY_WINDOW_BLOCKS` local blocks, the guard trips
//!    automatically and reports `true` so the intake freezes the domain.

use crate::cross_domain::external::spec::DomainKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;

/// Maximum contradicted claim tombstones retained per external domain.
const MAX_CONTRADICTED_CLAIMS_PER_DOMAIN: usize = 64;

/// Maximum adverse-round block timestamps retained per external domain.
const MAX_ADVERSE_EVENTS_PER_DOMAIN: usize = 64;

/// Sliding local-block window over which adverse quorum rounds are counted.
const ANOMALY_WINDOW_BLOCKS: u64 = 720;

/// Number of adverse quorum rounds inside `ANOMALY_WINDOW_BLOCKS` that
/// automatically trips the domain cooldown.
const ANOMALY_TRIP_THRESHOLD: usize = 4;

/// Initial block-height cooldown imposed on the first strike.
///
/// WIRING: read by [`DomainGuardRecord::arm_cooldown`] on contradiction and
/// adverse-round burst trips inside `IntakeState`.
pub(crate) const BASE_COOLDOWN_BLOCKS: u64 = 360;

/// Hard upper ceiling on exponential strike cooldown.
const MAX_COOLDOWN_BLOCKS: u64 = 14_400;

/// Local-block horizon after which an idle, non-cooled record drops aged
/// adverse timestamps.
const GUARD_SWEEP_RETENTION_BLOCKS: u64 = 28_800;

/// One cryptographically contradicted claim permanently barred from replay
/// while retained in the bounded per-domain tombstone ring.
///
/// WIRING: serialized inside [`DomainGuardRecord`] and inspected via
/// `IntakeState::guard` by external-domain RPC status queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContradictedClaim {
    /// External chain height of the contradicted attestation.
    pub height: u64,
    /// Evidence format version of the contradicted attestation.
    pub evidence_version: u32,
    /// Canonical [`super::spec::FinalityAttestation::claim_digest`] of the
    /// withdrawn attestation.
    pub claim_digest: [u8; 32],
    /// Local chain height at which the contradiction was proven.
    pub recorded_at_block: u64,
}

/// Deterministic guard state for a single registered external domain.
///
/// WIRING: returned by [`IntakeGuard::record_of`] on `IntakeState::submit_evidence`
/// and surfaced to external-domain RPC status readers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainGuardRecord {
    /// Cumulative count of proven contradictions or burst circuit-breaker trips.
    pub strike_count: u32,
    /// Local block height before which intake and readmission are refused.
    pub cooldown_until_block: u64,
    /// Bounded FIFO ring of contradicted attestation claims.
    pub contradicted_claims: Vec<ContradictedClaim>,
    /// Bounded sliding window of local block heights where an adverse quorum
    /// outcome (`Disputed` or `AgreedRefusal`) closed.
    pub adverse_round_blocks: Vec<u64>,
}

impl DomainGuardRecord {
    fn arm_cooldown(&mut self, local_height: u64) {
        self.strike_count = self.strike_count.saturating_add(1);
        let shift = self.strike_count.saturating_sub(1).min(16);
        let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        let span = BASE_COOLDOWN_BLOCKS
            .saturating_mul(factor)
            .min(MAX_COOLDOWN_BLOCKS);
        let candidate = local_height.saturating_add(span);
        if candidate > self.cooldown_until_block {
            self.cooldown_until_block = candidate;
        }
    }
}

/// Refusal returned when [`IntakeGuard`] blocks submission or readmission.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntakeGuardError {
    /// The domain is inside a mandatory post-contradiction or post-burst cooldown.
    #[error(
        "domain intake guard cooldown active at block {current_block} until block {cooldown_until} (strikes: {strikes})"
    )]
    CooldownActive {
        current_block: u64,
        cooldown_until: u64,
        strikes: u32,
    },
    /// The attestation matches a previously contradicted and withdrawn claim.
    #[error(
        "claim at external height {height} (version {evidence_version}) matches a previously contradicted attestation"
    )]
    ContradictedClaimReplay { height: u64, evidence_version: u32 },
}

/// Consensus-resident circuit breaker owned by [`super::intake::IntakeState`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntakeGuard {
    /// Per-domain deterministic cooldown, strike, and tombstone records.
    #[serde(with = "crate::core::map_keys")]
    pub domains: BTreeMap<DomainKey, DomainGuardRecord>,
}

impl IntakeGuard {
    /// Inspects the guard record for `domain`, if any fault or adverse round
    /// has ever been recorded.
    ///
    /// Convenience: exposed for RPC/telemetry inspection and domain intake tests.
    #[must_use]
    pub fn record_of(&self, domain: &DomainKey) -> Option<&DomainGuardRecord> {
        self.domains.get(domain)
    }

    /// Refuses evidence intake or readmission while the domain's deterministic
    /// fault cooldown is active.
    ///
    /// # Errors
    ///
    /// Returns [`IntakeGuardError::CooldownActive`] when
    /// `local_height < cooldown_until_block`.
    pub fn check_submission(
        &self,
        domain: &DomainKey,
        local_height: u64,
    ) -> Result<(), IntakeGuardError> {
        if let Some(rec) = self.domains.get(domain) {
            if local_height < rec.cooldown_until_block {
                return Err(IntakeGuardError::CooldownActive {
                    current_block: local_height,
                    cooldown_until: rec.cooldown_until_block,
                    strikes: rec.strike_count,
                });
            }
        }
        Ok(())
    }

    /// Refuses any attestation whose `(height, evidence_version, claim_digest)`
    /// matches a previously contradicted claim in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`IntakeGuardError::ContradictedClaimReplay`] on a tombstone hit.
    pub fn check_claim_allowed(
        &self,
        domain: &DomainKey,
        height: u64,
        evidence_version: u32,
        claim_digest: &[u8; 32],
    ) -> Result<(), IntakeGuardError> {
        if let Some(rec) = self.domains.get(domain) {
            let mut matched = false;
            for entry in &rec.contradicted_claims {
                if entry.height == height
                    && entry.evidence_version == evidence_version
                    && bool::from(entry.claim_digest.ct_eq(claim_digest))
                {
                    matched = true;
                }
            }
            if matched {
                return Err(IntakeGuardError::ContradictedClaimReplay {
                    height,
                    evidence_version,
                });
            }
        }
        Ok(())
    }

    /// Records a cryptographically proven contradiction for `domain`, stores a
    /// bounded tombstone for `claim_digest`, and arms the exponential cooldown.
    /// Returns the resulting `cooldown_until_block`.
    pub fn record_contradiction(
        &mut self,
        domain: DomainKey,
        height: u64,
        evidence_version: u32,
        claim_digest: [u8; 32],
        local_height: u64,
    ) -> u64 {
        let rec = self.domains.entry(domain).or_default();
        let already_recorded = rec.contradicted_claims.iter().any(|c| {
            c.height == height
                && c.evidence_version == evidence_version
                && bool::from(c.claim_digest.ct_eq(&claim_digest))
        });
        if !already_recorded {
            if rec.contradicted_claims.len() >= MAX_CONTRADICTED_CLAIMS_PER_DOMAIN {
                rec.contradicted_claims.remove(0);
            }
            rec.contradicted_claims.push(ContradictedClaim {
                height,
                evidence_version,
                claim_digest,
                recorded_at_block: local_height,
            });
        }
        rec.arm_cooldown(local_height);
        rec.cooldown_until_block
    }

    /// Records an adverse quorum outcome (`Disputed` or `AgreedRefusal`) at
    /// `local_height` and returns `true` when the sliding window hits
    /// `ANOMALY_TRIP_THRESHOLD`, arming an automatic cooldown with zero
    /// operator intervention.
    pub fn record_adverse_round(&mut self, domain: DomainKey, local_height: u64) -> bool {
        let rec = self.domains.entry(domain).or_default();
        rec.adverse_round_blocks
            .retain(|b| local_height.saturating_sub(*b) <= ANOMALY_WINDOW_BLOCKS);
        if rec.adverse_round_blocks.len() >= MAX_ADVERSE_EVENTS_PER_DOMAIN {
            rec.adverse_round_blocks.remove(0);
        }
        rec.adverse_round_blocks.push(local_height);
        if rec.adverse_round_blocks.len() >= ANOMALY_TRIP_THRESHOLD {
            rec.adverse_round_blocks.clear();
            rec.arm_cooldown(local_height);
            return true;
        }
        false
    }

    /// Deterministic block-commit maintenance: prunes stale adverse-round
    /// timestamps while preserving active cooldowns, strike counts, and
    /// contradicted-claim tombstones.
    pub fn sweep(&mut self, local_height: u64) {
        for rec in self.domains.values_mut() {
            rec.adverse_round_blocks
                .retain(|b| local_height.saturating_sub(*b) <= ANOMALY_WINDOW_BLOCKS);
        }
        self.domains.retain(|_, rec| {
            rec.strike_count > 0
                || !rec.contradicted_claims.is_empty()
                || !rec.adverse_round_blocks.is_empty()
                || (rec.cooldown_until_block > 0
                    && local_height
                        <= rec
                            .cooldown_until_block
                            .saturating_add(GUARD_SWEEP_RETENTION_BLOCKS))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::spec::AdapterId;

    fn sample_domain() -> DomainKey {
        DomainKey::from_parts(&AdapterId::from_name("guard-test-v1"), "testnet")
    }

    #[test]
    fn contradiction_tombstones_claim_arms_exponential_cooldown_and_auto_recovers() {
        let mut guard = IntakeGuard::default();
        let domain = sample_domain();
        let bad_claim = [0xC1; 32];

        guard
            .check_submission(&domain, 100)
            .expect("open initially");
        let until_1 = guard.record_contradiction(domain, 42, 1, bad_claim, 100);
        assert_eq!(until_1, 100 + BASE_COOLDOWN_BLOCKS);

        // Blocked while local_height < until_1, zero admin keys involved.
        assert!(matches!(
            guard.check_submission(&domain, until_1 - 1),
            Err(IntakeGuardError::CooldownActive { .. })
        ));
        // Automatically reopens at exact block height `until_1`.
        guard
            .check_submission(&domain, until_1)
            .expect("auto-reopens after deterministic block window");

        // Even after cooldown expires, the withdrawn false claim stays permanently tombstoned.
        assert!(matches!(
            guard.check_claim_allowed(&domain, 42, 1, &bad_claim),
            Err(IntakeGuardError::ContradictedClaimReplay {
                height: 42,
                evidence_version: 1,
            })
        ));
        // A distinct honest claim at the same height is permitted once cooldown ends.
        guard
            .check_claim_allowed(&domain, 42, 1, &[0xC2; 32])
            .expect("honest replacement claim allowed");

        // Second strike doubles the cooldown window.
        let until_2 = guard.record_contradiction(domain, 43, 1, [0xC3; 32], 1_000);
        assert_eq!(until_2, 1_000 + BASE_COOLDOWN_BLOCKS * 2);
        assert_eq!(guard.record_of(&domain).expect("recorded").strike_count, 2);
    }

    #[test]
    fn adverse_round_burst_trips_cooldown_while_spaced_events_sweep_cleanly() {
        let mut guard = IntakeGuard::default();
        let domain = sample_domain();

        // Spaced events outside ANOMALY_WINDOW_BLOCKS never trip a healthy domain.
        assert!(!guard.record_adverse_round(domain, 10));
        assert!(!guard.record_adverse_round(domain, 20));
        guard.sweep(10 + ANOMALY_WINDOW_BLOCKS + 50);
        assert!(guard.record_of(&domain).is_none());

        // ANOMALY_TRIP_THRESHOLD adverse rounds inside one window trip cooldown.
        for step in 0..(ANOMALY_TRIP_THRESHOLD - 1) {
            let h = 2_000 + u64::try_from(step).expect("fits");
            assert!(!guard.record_adverse_round(domain, h));
        }
        assert!(guard.record_adverse_round(domain, 2_010));
        assert!(matches!(
            guard.check_submission(&domain, 2_011),
            Err(IntakeGuardError::CooldownActive { .. })
        ));
    }
}
