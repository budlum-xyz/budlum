//! Bonded aggregator admission and segment fraud-proof slashing (`STRIX-AGG-01`).
//!
//! `StarkBackend` (`AggFoldAir`) proves the postfix merge tree over
//! `(tick_pi, merge_pi, master_pi)` and requires an ML-DSA-87 ownership
//! attestation (`SegmentAttestation`) from each `segment.aggregator`, while leaf
//! witness verification (`ObjectKind::{Signature, StarkProof, PcsOpening}`) runs
//! outside the fold AIR until recursive leaf verification lands. To eliminate
//! unbonded claim forgery in `AggMode::On`:
//!
//! 1. `Mainnet` and `Testnet` reject `AggMode::On` unconditionally in both
//!    `validate_params` and `check_block_with_backend_and_airs`.
//! 2. Every segment verified by an attestation-backed backend (`StarkBackend`)
//!    must be signed by an active, unslashed, unjailed validator holding at
//!    least its class bond floor (`verify_bonded_segment_aggregators`).
//! 3. Any attested segment whose claims are unbacked by valid witness envelopes
//!    or paired with a conflicting segment attestation from the same aggregator
//!    is cryptographically attributable under `ctx::AGG_SEGMENT_V1` and slashes
//!    100% of the Byzantine aggregator's validator bond (`slash_unbacked_segment`,
//!    `slash_conflicting_segment_attestation`), immediately revoking its seat.
//!
//! WIRING: `verify_bonded_segment_aggregators` is enforced by consensus block
//! validation in `aggregation::chain::check_block_with_backend_and_airs`;
//! `verify_bonded_segment_aggregators`, `is_authorized_segment_aggregator`,
//! `verify_segment_backing`, `slash_unbacked_segment`,
//! `slash_conflicting_segment_attestation`, `UnbackedSegmentChallenge`,
//! `SegmentFraudReason`, and `SegmentFraudReport` provide the consensus,
//! watchtower, and fraud-proof slashing doors exercised by
//! `aggregation::tests::phase5`.

use std::collections::BTreeSet;

use super::backend::AggError;
use super::chain::WIRE_FRAME_LIMITS;
use super::envelope::Envelope;
use super::frame::{verify_segment_attestations, ClaimFrame, Segment};
use super::object::derive_claim;
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::domain::types::{DomainId, Hash32};

/// Whistleblower share (in basis points) paid from a slashed aggregator bond.
/// The remaining `10_000 - WHISTLEBLOWER_REWARD_BPS` (90%) is permanently burned.
const WHISTLEBLOWER_REWARD_BPS: u64 = 1_000;

/// Specific violation proven against an attested aggregation [`Segment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentFraudReason {
    /// Fewer witness envelopes were supplied than claims committed in the segment.
    MissingBackingEnvelope,
    /// A witness envelope belongs to a different claim domain than the segment.
    WrongEnvelopeDomain,
    /// A witness envelope failed cryptographic signature, STARK, or PCS verification.
    InvalidBackingEnvelope,
    /// A witness envelope verified to a claim not committed in the attested segment.
    DerivedClaimMismatch,
    /// Two witness envelopes derived the same claim digest instead of distinct claims.
    DuplicateBackingClaim,
    /// The same aggregator signed two distinct conflicting segment roots.
    ConflictingSegmentAttestation,
}

/// Deterministic accounting record returned when a Byzantine segment aggregator is slashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentFraudReport {
    /// Slashed validator / aggregator address.
    pub aggregator: Address,
    /// Index of the fraudulent segment (0 for standalone conflicting attestations).
    pub segment_index: usize,
    /// Index of the first unbacked claim within the segment.
    pub claim_index: usize,
    /// Fraud condition that triggered the slash.
    pub reason: SegmentFraudReason,
    /// Total validator stake confiscated from `aggregator`.
    pub slashed_atoms: u64,
    /// Portion credited to the whistleblower (`10%`).
    pub whistleblower_reward_atoms: u64,
    /// Portion permanently removed from circulation (`90%`).
    pub burned_atoms: u64,
}

/// Returns the required minimum validator bond for `aggregator` on `chain_id`.
#[must_use]
fn required_aggregator_floor(state: &AccountState, chain_id: u64, aggregator: &Address) -> u64 {
    let is_full = state
        .get_validator(aggregator)
        .is_some_and(|v| v.filiz.is_some());
    if is_full {
        state.full_validator_stake_floor(chain_id)
    } else {
        state.validator_stake_floor(chain_id)
    }
}

/// Returns `true` iff `aggregator` is an active, unslashed, unjailed consensus
/// validator holding at least its class bond floor on `chain_id`.
#[must_use]
pub fn is_authorized_segment_aggregator(
    state: &AccountState,
    chain_id: u64,
    aggregator: &Address,
) -> bool {
    let Some(validator) = state.get_validator(aggregator) else {
        return false;
    };
    let floor = required_aggregator_floor(state, chain_id, aggregator);
    validator.active && !validator.slashed && !validator.jailed && validator.stake >= floor
}

/// Verifies that every [`Segment`] in `frame` is attested by an active,
/// unslashed, unjailed validator bonded at or above its class stake floor on
/// `chain_id`.
///
/// # Errors
///
/// Returns [`AggError::UnauthorizedSegmentAggregator`] naming the first segment
/// whose `aggregator` is missing, inactive, slashed, jailed, or below floor.
pub fn verify_bonded_segment_aggregators(
    state: &AccountState,
    chain_id: u64,
    frame: &ClaimFrame,
) -> Result<(), AggError> {
    for (idx, segment) in frame.segments.iter().enumerate() {
        if !is_authorized_segment_aggregator(state, chain_id, &segment.aggregator) {
            return Err(AggError::UnauthorizedSegmentAggregator(idx));
        }
    }
    Ok(())
}

/// Extracts the claim sub-slice `[start..end]` belonging to `segment_index`.
fn segment_claim_slice(
    frame: &ClaimFrame,
    segment_index: usize,
) -> Result<(&Segment, &[super::claim::Claim]), String> {
    let segment = frame
        .segments
        .get(segment_index)
        .ok_or_else(|| format!("segment index {segment_index} out of bounds"))?;
    let mut offset = 0usize;
    for prior in frame.segments.iter().take(segment_index) {
        let len = usize::try_from(prior.count).map_err(|_| "segment count overflow".to_string())?;
        offset = offset
            .checked_add(len)
            .ok_or_else(|| "segment claim offset overflow".to_string())?;
    }
    let len = usize::try_from(segment.count).map_err(|_| "segment count overflow".to_string())?;
    let end = offset
        .checked_add(len)
        .ok_or_else(|| "segment claim end overflow".to_string())?;
    let claims = frame
        .claims
        .get(offset..end)
        .ok_or_else(|| "segment claims slice out of bounds".to_string())?;
    Ok((segment, claims))
}

/// Checks whether `backing_envelopes` cryptographically derive every single
/// claim committed in `frame.segments[segment_index]` after authenticating the
/// frame structure and ML-DSA-87 segment attestations.
///
/// Returns `Ok(Ok(()))` when every claim in the segment is validly backed,
/// `Ok(Err((claim_idx, reason)))` when the segment is genuinely signed by
/// `segment.aggregator` yet carries an unbacked claim, or `Err(msg)` when the
/// frame itself is malformed or its `SegmentAttestation` is forged (preventing
/// bogus challenges against innocent validators).
///
/// # Errors
///
/// Returns `Err` if `frame` fails structural checks, any ML-DSA-87 segment
/// attestation is invalid, or `segment_index` is out of range.
pub fn verify_segment_backing(
    registry: &SchemeStatusRegistry,
    domain: DomainId,
    frame: &ClaimFrame,
    segment_index: usize,
    backing_envelopes: &[Envelope],
) -> Result<Result<(), (usize, SegmentFraudReason)>, String> {
    frame
        .check_structure(domain, &WIRE_FRAME_LIMITS)
        .map_err(|e| format!("invalid frame structure: {e}"))?;
    verify_segment_attestations(registry, domain, &frame.segments)
        .map_err(|e| format!("invalid segment attestation: {e}"))?;
    let (_segment, seg_claims) = segment_claim_slice(frame, segment_index)?;
    let expected: BTreeSet<Hash32> = seg_claims.iter().map(|c| c.digest(domain)).collect();
    if backing_envelopes.len() != seg_claims.len() {
        return Ok(Err((
            backing_envelopes.len().min(seg_claims.len()),
            SegmentFraudReason::MissingBackingEnvelope,
        )));
    }
    let mut proven = BTreeSet::new();
    for (idx, env) in backing_envelopes.iter().enumerate() {
        if env.domain != domain {
            return Ok(Err((idx, SegmentFraudReason::WrongEnvelopeDomain)));
        }
        let Ok(derived) = derive_claim(registry, env) else {
            return Ok(Err((idx, SegmentFraudReason::InvalidBackingEnvelope)));
        };
        let digest = derived.digest(domain);
        if !expected.contains(&digest) {
            return Ok(Err((idx, SegmentFraudReason::DerivedClaimMismatch)));
        }
        if !proven.insert(digest) {
            return Ok(Err((idx, SegmentFraudReason::DuplicateBackingClaim)));
        }
    }
    for (idx, claim) in seg_claims.iter().enumerate() {
        if !proven.contains(&claim.digest(domain)) {
            return Ok(Err((idx, SegmentFraudReason::MissingBackingEnvelope)));
        }
    }
    Ok(Ok(()))
}

/// Applies atomic 100% bond confiscation, deactivation, registry sync, and
/// whistleblower payout (10% reward, 90% burned) against `aggregator`.
fn apply_aggregator_slash(
    state: &mut AccountState,
    chain_id: u64,
    aggregator: Address,
    whistleblower: Address,
    segment_index: usize,
    claim_index: usize,
    reason: SegmentFraudReason,
) -> Result<SegmentFraudReport, String> {
    if whistleblower == aggregator {
        return Err("aggregator fraud: self-challenge is prohibited".into());
    }
    let floor = required_aggregator_floor(state, chain_id, &aggregator);
    let slashed_atoms = {
        let validator = state.get_validator_mut(&aggregator).ok_or_else(|| {
            "aggregator fraud: aggregator is not a registered validator".to_string()
        })?;
        if validator.slashed || validator.stake == 0 {
            return Err("aggregator fraud: validator already slashed or zero-bonded".into());
        }
        let stake = validator.stake;
        validator.stake = 0;
        validator.active = false;
        validator.slashed = true;
        stake
    };
    state.sync_validator_registration_with_floor(&aggregator, floor);
    let reward =
        u64::try_from(u128::from(slashed_atoms) * u128::from(WHISTLEBLOWER_REWARD_BPS) / 10_000)
            .unwrap_or(0);
    let burned = slashed_atoms.saturating_sub(reward);
    if reward > 0 {
        state.add_balance(&whistleblower, reward);
    }
    Ok(SegmentFraudReport {
        aggregator,
        segment_index,
        claim_index,
        reason,
        slashed_atoms,
        whistleblower_reward_atoms: reward,
        burned_atoms: burned,
    })
}

/// Evidence bundle challenging an attested segment whose claims lack valid
/// backing witness envelopes.
pub struct UnbackedSegmentChallenge<'a> {
    /// Chain id against which the validator bond floor is evaluated.
    pub chain_id: u64,
    /// Claim domain of `frame`.
    pub domain: DomainId,
    /// Attested claim frame containing the challenged segment.
    pub frame: &'a ClaimFrame,
    /// Index of the challenged segment inside `frame.segments`.
    pub segment_index: usize,
    /// Candidate backing witness envelopes supplied for the segment.
    pub backing_envelopes: &'a [Envelope],
    /// Recipient of the 10% whistleblower reward (must differ from `aggregator`).
    pub whistleblower: Address,
}

/// Verifies that `challenge.frame.segments[challenge.segment_index]` is
/// genuinely signed by a bonded validator yet unbacked by
/// `challenge.backing_envelopes`, and atomically slashes 100% of its stake.
///
/// # Errors
///
/// Returns `Err` if the frame/attestation is invalid, the segment is validly
/// backed by `backing_envelopes`, `whistleblower == aggregator`, or the
/// aggregator is unbonded / already slashed.
pub fn slash_unbacked_segment(
    state: &mut AccountState,
    registry: &SchemeStatusRegistry,
    challenge: &UnbackedSegmentChallenge<'_>,
) -> Result<SegmentFraudReport, String> {
    let outcome = verify_segment_backing(
        registry,
        challenge.domain,
        challenge.frame,
        challenge.segment_index,
        challenge.backing_envelopes,
    )?;
    let Err((claim_index, reason)) = outcome else {
        return Err("aggregator fraud: segment is validly backed by witness envelopes".into());
    };
    let (segment, _) = segment_claim_slice(challenge.frame, challenge.segment_index)?;
    apply_aggregator_slash(
        state,
        challenge.chain_id,
        segment.aggregator,
        challenge.whistleblower,
        challenge.segment_index,
        claim_index,
        reason,
    )
}

/// Statelessly verifies two conflicting ML-DSA-87 [`Segment`] attestations
/// signed by the same `aggregator` on `domain` (same claim `count`, distinct
/// non-zero `claims_root`) and atomically slashes 100% of its validator stake.
///
/// # Errors
///
/// Returns `Err` if either ML-DSA-87 attestation is invalid, the two segments
/// belong to different aggregators, carry different counts, commit to the same
/// `claims_root`, or fail validator slashing preconditions.
pub fn slash_conflicting_segment_attestation(
    state: &mut AccountState,
    registry: &SchemeStatusRegistry,
    chain_id: u64,
    domain: DomainId,
    first: &Segment,
    second: &Segment,
    whistleblower: Address,
) -> Result<SegmentFraudReport, String> {
    if first.aggregator != second.aggregator {
        return Err("aggregator fraud: segments were attested by different aggregators".into());
    }
    if first.count == 0 || first.count != second.count {
        return Err("aggregator fraud: conflicting segments must share a non-zero count".into());
    }
    if first.claims_root == second.claims_root {
        return Err("aggregator fraud: segments commit to the identical claims_root".into());
    }
    verify_segment_attestations(registry, domain, &[first.clone(), second.clone()])
        .map_err(|e| format!("aggregator fraud: invalid segment attestation: {e}"))?;
    apply_aggregator_slash(
        state,
        chain_id,
        first.aggregator,
        whistleblower,
        0,
        0,
        SegmentFraudReason::ConflictingSegmentAttestation,
    )
}
