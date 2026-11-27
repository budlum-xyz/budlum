//! Bonded aggregator admission and segment fraud-proof slashing.
//!
//! `StarkBackend` (`AggFoldAir`) proves the postfix merge tree over
//! `(tick_pi, merge_pi, master_pi)` and requires an ML-DSA-87 ownership
//! attestation (`SegmentAttestation`) from each `segment.aggregator`, while leaf
//! witness verification (`ObjectKind::{Signature, StarkProof, PcsOpening}`) runs
//! outside the fold AIR until recursive leaf verification lands. To eliminate
//! both unbonded claim forgery AND griefing slashes against honest aggregators:
//!
//! 1. `Mainnet` and `Testnet` reject `AggMode::On` unconditionally in both
//!    `validate_params` and `check_block_with_backend_and_airs`.
//! 2. Every segment verified by an attestation-backed backend (`StarkBackend`)
//!    must be signed by an active, unslashed, unjailed validator holding at
//!    least its class bond floor (`verify_bonded_segment_aggregators`).
//! 3. Stateless slashing (`slash_unbacked_segment`) requires an ML-DSA-87
//!    `response_signature` produced by `segment.aggregator` over the exact
//!    submitted `backing_envelopes`, so an attacker cannot slash an honest
//!    aggregator by submitting an empty or tampered witness list.
//! 4. Silent/withholding Byzantine aggregators are slashed through the bonded
//!    two-step [`SegmentChallengeBook`]: challengers lock a `10%` floor bond,
//!    honest aggregators defend within [`SEGMENT_CHALLENGE_WINDOW_BLOCKS`] and
//!    earn `50%` of the frivolous bond (remaining `50%` burned), while silent
//!    timeout or cryptographically invalid backing slashes `100%` of the
//!    aggregator's stake + pending unbonding queue and refunds the challenger.
//! 5. Stateless equivocation slashing (`slash_conflicting_segment_attestation`)
//!    requires Merkle-opened contradictory deterministic claims (`Claim::Prog`
//!    with equal `(program_hash, input_hash)` and distinct `output_hash`, or
//!    `Claim::Poly` with equal `(poly_hash, point)` and distinct `value`), so
//!    ordinary back-to-back disjoint ticks of equal claim count are never
//!    misclassified as fraud.
//! 6. Every slash delegates through [`AccountState::slash_validator`] at
//!    `FIXED_POINT_SCALE`, sweeping active stake, pending `unbonding_queue`
//!    exits, active governance vote weights, registry mirrors, and exact
//!    `total_bud_committed + burned_total` conservation.
//!
//! WIRING: `verify_bonded_segment_aggregators` is enforced by consensus block
//! validation in `aggregation::chain::check_block_with_backend_and_airs`;
//! `is_authorized_segment_aggregator`, `verify_segment_backing`,
//! `sign_backing_response`, `slash_unbacked_segment`,
//! `slash_conflicting_segment_attestation`, `ContradictingSegmentEvidence`,
//! `SegmentChallengeBook`, `SegmentChallengeRequest`, `RespondChallengeRequest`,
//! `ChallengeOutcome`, `UnbackedSegmentChallenge`, `SegmentFraudReason`, and
//! `SegmentFraudReport` provide the watchtower and consensus fraud-proof doors.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use zeroize::Zeroizing;

use super::backend::AggError;
use super::chain::WIRE_FRAME_LIMITS;
use super::claim::Claim;
use super::envelope::Envelope;
use super::frame::{tick_pi, verify_segment_attestations, ClaimFrame, FrameError, Segment};
use super::hash::{h, TAG_AGG_BACKING_ENV, TAG_AGG_BACKING_RESP, TAG_AGG_CHALLENGE};
use super::merkle::{verify_claim_inclusion, ClaimMerkleProof};
use super::object::derive_claim;
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::chain_config::FIXED_POINT_SCALE;
use crate::crypto::ctx;
use crate::crypto::pq;
use crate::crypto::primitives::ML_DSA_87_SIGNATURE_LEN;
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};
use crate::domain::types::{DomainId, Hash32};

/// Whistleblower share (in basis points) paid from a slashed aggregator bond.
/// The remaining `10_000 - WHISTLEBLOWER_REWARD_BPS` (90%) is permanently burned.
const WHISTLEBLOWER_REWARD_BPS: u64 = 1_000;

/// Challenger bond required to open a segment-backing challenge (`10%` of the
/// aggregator's class bond floor, at least `1` atom).
pub const CHALLENGER_BOND_BPS: u64 = 1_000;

/// Honest aggregator compensation share (`50%`) from a forfeited frivolous
/// challenger bond; the remaining `50%` is permanently destroyed.
const DEFENDER_REWARD_BPS: u64 = 5_000;

/// Blocks an aggregator has to publish a signed backing response after a
/// challenge opens before timeout slashing becomes eligible.
pub const SEGMENT_CHALLENGE_WINDOW_BLOCKS: u64 = 64;

/// Maximum simultaneously open challenges in [`SegmentChallengeBook`].
pub const MAX_OPEN_SEGMENT_CHALLENGES: usize = 4_096;

/// Maximum settled challenge IDs retained in [`SegmentChallengeBook`] before
/// deterministic FIFO eviction bounds resident memory.
pub const MAX_SETTLED_SEGMENT_CHALLENGES: usize = 65_536;

/// Maximum witness envelopes accepted in a single backing-response payload
/// before hashing or cryptographic verification runs.
pub const MAX_BACKING_ENVELOPES_PER_RESPONSE: usize = WIRE_FRAME_LIMITS.max_claims;

/// Maximum cumulative payload bytes across `backing_envelopes` in a single
/// backing response.
pub const MAX_BACKING_RESPONSE_BYTES: usize = WIRE_FRAME_LIMITS.max_proof_bytes;

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
    /// The aggregator failed to answer a bonded backing challenge before expiry.
    ChallengeResponseTimeout,
    /// The same aggregator signed two segments committing contradictory deterministic claims.
    ConflictingSegmentAttestation,
}

/// Deterministic accounting record returned when a Byzantine segment aggregator is slashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentFraudReport {
    /// Slashed validator / aggregator address.
    pub aggregator: Address,
    /// Index of the fraudulent segment (`0` for standalone conflicting attestations).
    pub segment_index: usize,
    /// Index of the first unbacked or contradicting claim within the segment.
    pub claim_index: usize,
    /// Fraud condition that triggered the slash.
    pub reason: SegmentFraudReason,
    /// Total validator stake + unbonding atoms confiscated from `aggregator`.
    pub slashed_atoms: u64,
    /// Portion credited to the whistleblower (`10%`, `0` if uncreditable).
    pub whistleblower_reward_atoms: u64,
    /// Portion permanently recorded in `burned_total` (exact remainder).
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

/// Required challenger escrow bond for challenging `aggregator` on `chain_id`.
#[must_use]
pub fn required_challenger_bond(state: &AccountState, chain_id: u64, aggregator: &Address) -> u64 {
    let floor = required_aggregator_floor(state, chain_id, aggregator);
    u64::try_from(u128::from(floor) * u128::from(CHALLENGER_BOND_BPS) / 10_000)
        .unwrap_or(u64::MAX)
        .max(1)
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
) -> Result<(&Segment, &[Claim]), String> {
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

/// Collision-resistant digest over an ordered slice of witness [`Envelope`]s.
#[must_use]
pub fn backing_envelopes_digest(envelopes: &[Envelope]) -> Hash32 {
    let mut folded = [0u8; 32];
    for (idx, env) in envelopes.iter().enumerate() {
        let payload_len = u64::try_from(env.payload.len()).unwrap_or(u64::MAX);
        let idx_u64 = u64::try_from(idx).unwrap_or(u64::MAX);
        let item_hash = h(&[
            TAG_AGG_BACKING_ENV,
            &idx_u64.to_be_bytes(),
            &[env.kind.to_byte()],
            &env.scheme.0.to_be_bytes(),
            &env.domain.to_be_bytes(),
            &env.tx_hash,
            &payload_len.to_be_bytes(),
            &env.payload,
        ]);
        folded = h(&[TAG_AGG_BACKING_ENV, &folded, &item_hash]);
    }
    let count = u64::try_from(envelopes.len()).unwrap_or(u64::MAX);
    h(&[TAG_AGG_BACKING_ENV, &count.to_be_bytes(), &folded])
}

/// Rejects oversized witness envelope slices before hashing or leaf
/// verification so an unauthenticated caller cannot trigger CPU/memory DoS.
fn validate_backing_envelopes_bounds(backing_envelopes: &[Envelope]) -> Result<(), String> {
    if backing_envelopes.len() > MAX_BACKING_ENVELOPES_PER_RESPONSE {
        return Err(format!(
            "aggregator fraud: backing_envelopes count {} exceeds limit {MAX_BACKING_ENVELOPES_PER_RESPONSE}",
            backing_envelopes.len()
        ));
    }
    let mut total_bytes = 0usize;
    for env in backing_envelopes {
        total_bytes = total_bytes
            .checked_add(env.payload.len())
            .ok_or_else(|| "aggregator fraud: backing_envelopes byte size overflow".to_string())?;
        if total_bytes > MAX_BACKING_RESPONSE_BYTES {
            return Err(format!(
                "aggregator fraud: backing_envelopes payload bytes {total_bytes} exceed limit {MAX_BACKING_RESPONSE_BYTES}"
            ));
        }
    }
    Ok(())
}

/// Canonical 32-byte message signed by `segment.aggregator` when answering a
/// backing challenge over `(chain_id, domain, segment)`.
#[must_use]
pub fn backing_response_message(
    chain_id: u64,
    domain: DomainId,
    segment: &Segment,
    backing_envelopes: &[Envelope],
) -> Hash32 {
    let pi = tick_pi(domain, segment);
    let env_digest = backing_envelopes_digest(backing_envelopes);
    h(&[
        TAG_AGG_BACKING_RESP,
        &chain_id.to_be_bytes(),
        &domain.to_be_bytes(),
        &pi,
        &env_digest,
    ])
}

/// Signs `backing_envelopes` as `aggregator`'s official backing response for
/// `(chain_id, domain, segment)` under [`ctx::AGG_SEGMENT_V1`].
///
/// # Errors
///
/// Returns [`FrameError::InvalidAttestation`] if ML-DSA-87 signing fails.
pub fn sign_backing_response(
    signer_seed: &[u8; 32],
    chain_id: u64,
    domain: DomainId,
    segment: &Segment,
    backing_envelopes: &[Envelope],
) -> Result<Box<[u8; ML_DSA_87_SIGNATURE_LEN]>, FrameError> {
    let msg = backing_response_message(chain_id, domain, segment, backing_envelopes);
    let mut rnd = Zeroizing::new([0u8; 32]);
    if rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng, rnd.as_mut_slice()).is_err() {
        rnd.copy_from_slice(&[0u8; 32]);
    }
    let sig_vec = pq::ml_dsa_sign(
        SchemeId::ML_DSA_87,
        signer_seed,
        &msg,
        ctx::AGG_SEGMENT_V1,
        &rnd,
    )
    .map_err(|_| FrameError::InvalidAttestation)?;
    let sig_arr: [u8; ML_DSA_87_SIGNATURE_LEN] = sig_vec
        .try_into()
        .map_err(|_| FrameError::InvalidAttestation)?;
    Ok(Box::new(sig_arr))
}

/// Verifies that `response_signature` was produced by `segment.attestation.public_key`
/// over `(chain_id, domain, segment, backing_envelopes)` under [`ctx::AGG_SEGMENT_V1`].
fn verify_backing_response_signature(
    registry: &SchemeStatusRegistry,
    chain_id: u64,
    domain: DomainId,
    segment: &Segment,
    backing_envelopes: &[Envelope],
    response_signature: &[u8; ML_DSA_87_SIGNATURE_LEN],
) -> Result<(), String> {
    let msg = backing_response_message(chain_id, domain, segment, backing_envelopes);
    pq::verify_in(
        registry,
        SchemeId::ML_DSA_87,
        segment.attestation.public_key.as_slice(),
        &msg,
        ctx::AGG_SEGMENT_V1,
        response_signature.as_slice(),
    )
    .map_err(|_| "aggregator fraud: invalid aggregator backing-response signature".to_string())
}

/// Checks whether `backing_envelopes` prove every claim in `frame.segments[segment_index]`.
///
/// Authenticates frame structure and ML-DSA-87 segment attestations before
/// evaluating witness envelopes against the committed claim slice.
///
/// # Errors
///
/// Returns `Err` if `frame` fails structural checks, any ML-DSA-87 segment
/// attestation is invalid, `backing_envelopes` exceeds wire bounds, or
/// `segment_index` is out of range.
pub fn verify_segment_backing(
    registry: &SchemeStatusRegistry,
    domain: DomainId,
    frame: &ClaimFrame,
    segment_index: usize,
    backing_envelopes: &[Envelope],
) -> Result<Result<(), (usize, SegmentFraudReason)>, String> {
    validate_backing_envelopes_bounds(backing_envelopes)?;
    frame
        .check_structure(domain, &WIRE_FRAME_LIMITS)
        .map_err(|e| format!("invalid frame structure: {e}"))?;
    verify_segment_attestations(registry, domain, &frame.segments)
        .map_err(|e| format!("invalid segment attestation: {e}"))?;
    let (_segment, seg_claims) = segment_claim_slice(frame, segment_index)?;
    Ok(evaluate_claim_backing(
        registry,
        domain,
        seg_claims,
        backing_envelopes,
    ))
}

fn evaluate_claim_backing(
    registry: &SchemeStatusRegistry,
    domain: DomainId,
    seg_claims: &[Claim],
    backing_envelopes: &[Envelope],
) -> Result<(), (usize, SegmentFraudReason)> {
    let expected: BTreeSet<Hash32> = seg_claims.iter().map(|c| c.digest(domain)).collect();
    if backing_envelopes.len() != seg_claims.len() {
        return Err((
            backing_envelopes.len().min(seg_claims.len()),
            SegmentFraudReason::MissingBackingEnvelope,
        ));
    }
    let mut proven = BTreeSet::new();
    for (idx, env) in backing_envelopes.iter().enumerate() {
        if env.domain != domain {
            return Err((idx, SegmentFraudReason::WrongEnvelopeDomain));
        }
        let Ok(derived) = derive_claim(registry, env) else {
            return Err((idx, SegmentFraudReason::InvalidBackingEnvelope));
        };
        let digest = derived.digest(domain);
        if !expected.contains(&digest) {
            return Err((idx, SegmentFraudReason::DerivedClaimMismatch));
        }
        if !proven.insert(digest) {
            return Err((idx, SegmentFraudReason::DuplicateBackingClaim));
        }
    }
    for (idx, claim) in seg_claims.iter().enumerate() {
        if !proven.contains(&claim.digest(domain)) {
            return Err((idx, SegmentFraudReason::MissingBackingEnvelope));
        }
    }
    Ok(())
}

/// Credits an already-debited bond or slash redistribution to `recipient` iff
/// `recipient` is neither zero nor the burn reserve and crediting cannot
/// overflow `u64::MAX`. Never creates supply.
fn try_credit_escrow_redistribution(
    state: &mut AccountState,
    recipient: &Address,
    amount: u64,
) -> bool {
    if amount == 0
        || *recipient == Address::zero()
        || state.burn_reserve_address == Some(*recipient)
        || state.get_balance(recipient).checked_add(amount).is_none()
    {
        return false;
    }
    state.add_balance(recipient, amount);
    true
}

fn refund_challenger_bond(state: &mut AccountState, challenger: &Address, bond: u64) {
    if bond > 0 && !try_credit_escrow_redistribution(state, challenger, bond) {
        state.record_destroyed(u128::from(bond));
    }
}

/// Applies atomic 100% stake + unbonding confiscation, governance-weight
/// zeroing, registry sync, and supply-conserving whistleblower payout (`10%`
/// reward, `90%` permanently destroyed) against `aggregator`.
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
    if whistleblower == Address::zero() || state.burn_reserve_address == Some(whistleblower) {
        return Err("aggregator fraud: invalid or burn-reserve whistleblower is prohibited".into());
    }
    let has_unbonding = state
        .unbonding_queue
        .iter()
        .any(|entry| entry.address == aggregator && entry.amount > 0);
    let validator = state
        .get_validator(&aggregator)
        .ok_or_else(|| "aggregator fraud: aggregator is not a registered validator".to_string())?;
    if validator.slashed || (validator.stake == 0 && !has_unbonding) {
        return Err("aggregator fraud: validator already slashed or zero-bonded".into());
    }
    let floor = required_aggregator_floor(state, chain_id, &aggregator);
    let burned_before = state.burned_total;
    let penalty = state
        .slash_validator(
            &aggregator,
            FIXED_POINT_SCALE,
            "aggregator segment fraud-proof slash",
        )
        .ok_or_else(|| "aggregator fraud: validator missing during slash".to_string())?;
    state.sync_validator_registration_with_floor(&aggregator, floor);
    let destroyed = state.burned_total.saturating_sub(burned_before);
    let slashed_atoms = destroyed.max(penalty);
    if slashed_atoms == 0 {
        return Err("aggregator fraud: validator already slashed or zero-bonded".into());
    }
    let candidate_reward =
        u64::try_from(u128::from(destroyed) * u128::from(WHISTLEBLOWER_REWARD_BPS) / 10_000)
            .unwrap_or(0)
            .min(destroyed);
    let reward = if try_credit_escrow_redistribution(state, &whistleblower, candidate_reward) {
        // Redirect `candidate_reward` out of `burned_total` into `whistleblower`
        // so `total_bud_committed + burned_total` stays bit-for-bit conserved.
        state.burned_total = state.burned_total.saturating_sub(candidate_reward);
        candidate_reward
    } else {
        0
    };
    let burned = destroyed.saturating_sub(reward);
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

/// Stateless evidence bundle slashing an aggregator that signed an invalid or
/// incomplete backing response for one of its attested segments.
///
/// For silent aggregators that withhold responses altogether, open a bonded
/// challenge in [`SegmentChallengeBook`] and settle after
/// [`SEGMENT_CHALLENGE_WINDOW_BLOCKS`].
pub struct UnbackedSegmentChallenge<'a> {
    /// Chain id against which the validator bond floor is evaluated.
    pub chain_id: u64,
    /// Claim domain of `frame`.
    pub domain: DomainId,
    /// Attested claim frame containing the challenged segment.
    pub frame: &'a ClaimFrame,
    /// Index of the challenged segment inside `frame.segments`.
    pub segment_index: usize,
    /// Backing witness envelopes committed in `aggregator_response_sig`.
    pub backing_envelopes: &'a [Envelope],
    /// ML-DSA-87 signature by `segment.aggregator` over `backing_envelopes`.
    pub aggregator_response_sig: &'a [u8; ML_DSA_87_SIGNATURE_LEN],
    /// Recipient of the 10% whistleblower reward (must differ from `aggregator`).
    pub whistleblower: Address,
}

/// Slashes an aggregator that signed an invalid backing response for a segment.
///
/// Because the aggregator's own ML-DSA-87 signature binds `backing_envelopes`,
/// no third party can frame an honest aggregator by omitting or mutating items.
///
/// # Errors
///
/// Returns `Err` if the frame, segment attestation, or `aggregator_response_sig`
/// fails verification, the segment is validly backed, `whistleblower == aggregator`,
/// or the validator cannot be slashed.
pub fn slash_unbacked_segment(
    state: &mut AccountState,
    registry: &SchemeStatusRegistry,
    challenge: &UnbackedSegmentChallenge<'_>,
) -> Result<SegmentFraudReport, String> {
    if challenge.whistleblower == Address::zero()
        || state.burn_reserve_address == Some(challenge.whistleblower)
    {
        return Err("aggregator fraud: invalid or burn-reserve whistleblower is prohibited".into());
    }
    validate_backing_envelopes_bounds(challenge.backing_envelopes)?;
    let (segment, _) = segment_claim_slice(challenge.frame, challenge.segment_index)?;
    if challenge.whistleblower == segment.aggregator {
        return Err("aggregator fraud: self-challenge is prohibited".into());
    }
    verify_backing_response_signature(
        registry,
        challenge.chain_id,
        challenge.domain,
        segment,
        challenge.backing_envelopes,
        challenge.aggregator_response_sig,
    )?;
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

/// Returns `true` iff two deterministic claims assert mathematically
/// incompatible outputs for the exact same input (`Claim::Prog` with equal
/// `(program_hash, input_hash)` and distinct `output_hash`, or `Claim::Poly`
/// with equal `(poly_hash, point)` and distinct `value`).
#[must_use]
fn claims_contradict(first: &Claim, second: &Claim) -> bool {
    match (first, second) {
        (
            Claim::Prog {
                program_hash: prog_a,
                input_hash: in_a,
                output_hash: out_a,
            },
            Claim::Prog {
                program_hash: prog_b,
                input_hash: in_b,
                output_hash: out_b,
            },
        ) => prog_a == prog_b && in_a == in_b && out_a != out_b,
        (
            Claim::Poly {
                poly_hash: poly_a,
                point: pt_a,
                value: val_a,
            },
            Claim::Poly {
                poly_hash: poly_b,
                point: pt_b,
                value: val_b,
            },
        ) => poly_a == poly_b && pt_a == pt_b && val_a != val_b,
        _ => false,
    }
}

/// Cryptographic proof that one aggregator signed two segments committing
/// contradictory deterministic claims.
pub struct ContradictingSegmentEvidence<'a> {
    /// First ML-DSA-87 attested segment.
    pub first_segment: &'a Segment,
    /// Claim committed inside `first_segment.claims_root`.
    pub first_claim: &'a Claim,
    /// `O(log C)` Merkle opening of `first_claim` under `first_segment.claims_root`.
    pub first_proof: &'a ClaimMerkleProof,
    /// Second ML-DSA-87 attested segment signed by the same `aggregator`.
    pub second_segment: &'a Segment,
    /// Contradicting claim committed inside `second_segment.claims_root`.
    pub second_claim: &'a Claim,
    /// `O(log C)` Merkle opening of `second_claim` under `second_segment.claims_root`.
    pub second_proof: &'a ClaimMerkleProof,
}

/// Slashes an aggregator that attested two segments with contradictory claims.
///
/// Verifies both ML-DSA-87 segment attestations and both `O(log C)` Merkle
/// openings for contradicting deterministic `Claim::Prog` or `Claim::Poly` leaves.
///
/// Ordinary back-to-back ticks covering disjoint valid transactions (even when
/// `first.count == second.count`) never contradict and can never be slashed.
///
/// # Errors
///
/// Returns `Err` if the segments belong to different aggregators, either
/// ML-DSA-87 attestation or Merkle opening is invalid, the opened claims do not
/// contradict, or validator slashing preconditions fail.
pub fn slash_conflicting_segment_attestation(
    state: &mut AccountState,
    registry: &SchemeStatusRegistry,
    chain_id: u64,
    domain: DomainId,
    evidence: &ContradictingSegmentEvidence<'_>,
    whistleblower: Address,
) -> Result<SegmentFraudReport, String> {
    let first = evidence.first_segment;
    let second = evidence.second_segment;
    if first.aggregator != second.aggregator {
        return Err("aggregator fraud: segments were attested by different aggregators".into());
    }
    if first.count == 0 || second.count == 0 {
        return Err("aggregator fraud: empty segment cannot carry a contradicting claim".into());
    }
    if evidence.first_proof.segment_count != first.count
        || evidence.second_proof.segment_count != second.count
    {
        return Err("aggregator fraud: claim proof count does not match attested segment".into());
    }
    if !claims_contradict(evidence.first_claim, evidence.second_claim) {
        return Err(
            "aggregator fraud: opened claims are disjoint or identical, not contradictory".into(),
        );
    }
    let first_digest = evidence.first_claim.digest(domain);
    let second_digest = evidence.second_claim.digest(domain);
    if !verify_claim_inclusion(&first_digest, evidence.first_proof, &first.claims_root) {
        return Err("aggregator fraud: first claim Merkle proof invalid".into());
    }
    if !verify_claim_inclusion(&second_digest, evidence.second_proof, &second.claims_root) {
        return Err("aggregator fraud: second claim Merkle proof invalid".into());
    }
    verify_segment_attestations(registry, domain, &[first.clone(), second.clone()])
        .map_err(|e| format!("aggregator fraud: invalid segment attestation: {e}"))?;
    let claim_idx = usize::try_from(evidence.first_proof.claim_index).unwrap_or(0);
    apply_aggregator_slash(
        state,
        chain_id,
        first.aggregator,
        whistleblower,
        0,
        claim_idx,
        SegmentFraudReason::ConflictingSegmentAttestation,
    )
}

/// Parameters for opening a bonded two-step segment-backing challenge.
pub struct SegmentChallengeRequest<'a> {
    /// Chain id against which bond floors are computed.
    pub chain_id: u64,
    /// Aggregation claim domain of `frame`.
    pub domain: DomainId,
    /// Attested claim frame containing the challenged segment.
    pub frame: &'a ClaimFrame,
    /// Index of the challenged segment within `frame.segments`.
    pub segment_index: usize,
    /// Bonded challenger opening the dispute (must differ from `aggregator`).
    pub challenger: Address,
    /// Current consensus block height at which the challenge opens.
    pub opened_height: u64,
}

/// Parameters for an aggregator's signed answer to a pending challenge.
pub struct RespondChallengeRequest<'a> {
    /// Deterministic challenge identifier returned by [`SegmentChallengeBook::open_challenge`].
    pub challenge_id: Hash32,
    /// Current consensus block height (must be `<= deadline_height`).
    pub current_height: u64,
    /// Backing witness envelopes proving every claim in the challenged segment.
    pub backing_envelopes: &'a [Envelope],
    /// ML-DSA-87 response signature produced by [`sign_backing_response`].
    pub response_signature: &'a [u8; ML_DSA_87_SIGNATURE_LEN],
}

/// Outcome of resolving a challenge inside [`SegmentChallengeBook`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeOutcome {
    /// Aggregator proved valid backing in time; frivolous challenger bond was
    /// split between `defender_reward_atoms` and `burned_atoms`.
    Defended {
        aggregator: Address,
        challenger: Address,
        defender_reward_atoms: u64,
        burned_atoms: u64,
    },
    /// Aggregator supplied invalid backing or missed `deadline_height`;
    /// challenger bond returned and aggregator slashed 100%.
    Slashed(SegmentFraudReport),
    /// Target validator was already slashed before resolution; challenger bond
    /// refunded without double-slashing.
    RefundedAlreadySlashed { challenger: Address, bond: u64 },
}

#[derive(Debug, Clone)]
struct PendingSegmentChallenge {
    chain_id: u64,
    domain: DomainId,
    segment_index: usize,
    segment: Segment,
    claims: Vec<Claim>,
    aggregator: Address,
    challenger: Address,
    challenger_bond_atoms: u64,
    opened_height: u64,
    deadline_height: u64,
}

/// Bonded challenge-response ledger protecting honest aggregators from
/// unbonded griefing while slashing silent or fraudulent aggregators 100%.
#[derive(Debug, Clone, Default)]
pub struct SegmentChallengeBook {
    open: BTreeMap<Hash32, PendingSegmentChallenge>,
    settled: BTreeSet<Hash32>,
    settled_order: VecDeque<Hash32>,
}

impl SegmentChallengeBook {
    /// Creates an empty challenge book.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of currently pending challenges.
    #[cfg(test)]
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.open.len()
    }

    /// Number of currently retained settled challenge identifiers.
    #[cfg(test)]
    #[must_use]
    pub fn settled_len(&self) -> usize {
        self.settled.len()
    }

    /// Records a settled challenge ID while enforcing [`MAX_SETTLED_SEGMENT_CHALLENGES`]
    /// via deterministic FIFO eviction.
    fn record_settled(&mut self, id: Hash32) {
        if self.settled.insert(id) {
            self.settled_order.push_back(id);
            while self.settled.len() > MAX_SETTLED_SEGMENT_CHALLENGES {
                if let Some(oldest) = self.settled_order.pop_front() {
                    self.settled.remove(&oldest);
                } else {
                    break;
                }
            }
        }
    }

    /// Deterministic identifier for a segment challenge `(chain_id, domain, tick_pi)`.
    #[must_use]
    pub fn challenge_id_of(chain_id: u64, domain: DomainId, segment: &Segment) -> Hash32 {
        let pi = tick_pi(domain, segment);
        h(&[
            TAG_AGG_CHALLENGE,
            &chain_id.to_be_bytes(),
            &domain.to_be_bytes(),
            &pi,
        ])
    }

    /// Opens a bonded challenge against `req.frame.segments[req.segment_index]`,
    /// escrowing [`required_challenger_bond`] from `req.challenger`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the book is full, the frame/attestation is invalid,
    /// the challenge is duplicate/settled, `challenger == aggregator`, the
    /// aggregator is not slashable, `opened_height` overflows the deadline, or
    /// `challenger` cannot cover the required bond.
    pub fn open_challenge(
        &mut self,
        state: &mut AccountState,
        registry: &SchemeStatusRegistry,
        req: &SegmentChallengeRequest<'_>,
    ) -> Result<Hash32, String> {
        if self.open.len() >= MAX_OPEN_SEGMENT_CHALLENGES {
            return Err("aggregator fraud: challenge book is at capacity".into());
        }
        req.frame
            .check_structure(req.domain, &WIRE_FRAME_LIMITS)
            .map_err(|e| format!("aggregator fraud: invalid frame structure: {e}"))?;
        verify_segment_attestations(registry, req.domain, &req.frame.segments)
            .map_err(|e| format!("aggregator fraud: invalid segment attestation: {e}"))?;
        let (segment, seg_claims) = segment_claim_slice(req.frame, req.segment_index)?;
        if req.challenger == Address::zero()
            || req.challenger == segment.aggregator
            || state.burn_reserve_address == Some(req.challenger)
        {
            return Err("aggregator fraud: invalid, burn-reserve, or self challenger".into());
        }
        let has_unbonding = state
            .unbonding_queue
            .iter()
            .any(|e| e.address == segment.aggregator && e.amount > 0);
        let validator = state
            .get_validator(&segment.aggregator)
            .ok_or_else(|| "aggregator fraud: target is not a registered validator".to_string())?;
        if validator.slashed || (validator.stake == 0 && !has_unbonding) {
            return Err("aggregator fraud: target validator already slashed or zero-bonded".into());
        }
        let deadline_height = req
            .opened_height
            .checked_add(SEGMENT_CHALLENGE_WINDOW_BLOCKS)
            .ok_or_else(|| "aggregator fraud: challenge deadline overflow".to_string())?;
        let id = Self::challenge_id_of(req.chain_id, req.domain, segment);
        if self.open.contains_key(&id) || self.settled.contains(&id) {
            return Err("aggregator fraud: segment already challenged".into());
        }
        let bond = required_challenger_bond(state, req.chain_id, &segment.aggregator);
        if state.spendable_balance(&req.challenger) < bond {
            return Err(
                "aggregator fraud: challenger has insufficient spendable balance for bond".into(),
            );
        }
        let challenger_acct = state.get_or_create(&req.challenger);
        challenger_acct.balance = challenger_acct
            .balance
            .checked_sub(bond)
            .ok_or_else(|| "aggregator fraud: challenger balance underflow".to_string())?;
        self.open.insert(
            id,
            PendingSegmentChallenge {
                chain_id: req.chain_id,
                domain: req.domain,
                segment_index: req.segment_index,
                segment: segment.clone(),
                claims: seg_claims.to_vec(),
                aggregator: segment.aggregator,
                challenger: req.challenger,
                challenger_bond_atoms: bond,
                opened_height: req.opened_height,
                deadline_height,
            },
        );
        Ok(id)
    }

    /// Processes an aggregator's ML-DSA-87 signed backing response before
    /// `deadline_height`.
    ///
    /// Convenience: kept for the CLI and aggregator challenge settlement handler.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `challenge_id` is unknown, `current_height` lies outside
    /// `[opened_height, deadline_height]`, `backing_envelopes` exceeds wire bounds,
    /// or `response_signature` does not verify under the challenged segment's
    /// ML-DSA-87 public key (leaving the challenge open so forged third-party
    /// responses cannot close or prematurely slash it).
    pub fn respond_challenge(
        &mut self,
        state: &mut AccountState,
        registry: &SchemeStatusRegistry,
        req: &RespondChallengeRequest<'_>,
    ) -> Result<ChallengeOutcome, String> {
        let entry = self
            .open
            .get(&req.challenge_id)
            .cloned()
            .ok_or_else(|| "aggregator fraud: unknown challenge id".to_string())?;
        if req.current_height < entry.opened_height {
            return Err("aggregator fraud: response height precedes challenge opening".into());
        }
        if req.current_height > entry.deadline_height {
            return Err("aggregator fraud: challenge response window expired".into());
        }
        validate_backing_envelopes_bounds(req.backing_envelopes)?;
        verify_backing_response_signature(
            registry,
            entry.chain_id,
            entry.domain,
            &entry.segment,
            req.backing_envelopes,
            req.response_signature,
        )?;
        // Past every refusal: commit removal and settlement atomically.
        self.open.remove(&req.challenge_id);
        self.record_settled(req.challenge_id);
        match evaluate_claim_backing(registry, entry.domain, &entry.claims, req.backing_envelopes) {
            Ok(()) => {
                let candidate = u64::try_from(
                    u128::from(entry.challenger_bond_atoms) * u128::from(DEFENDER_REWARD_BPS)
                        / 10_000,
                )
                .unwrap_or(0)
                .min(entry.challenger_bond_atoms);
                let reward =
                    if try_credit_escrow_redistribution(state, &entry.aggregator, candidate) {
                        candidate
                    } else {
                        0
                    };
                let burned = entry.challenger_bond_atoms.saturating_sub(reward);
                if burned > 0 {
                    state.record_destroyed(u128::from(burned));
                }
                Ok(ChallengeOutcome::Defended {
                    aggregator: entry.aggregator,
                    challenger: entry.challenger,
                    defender_reward_atoms: reward,
                    burned_atoms: burned,
                })
            }
            Err((claim_index, reason)) => {
                refund_challenger_bond(state, &entry.challenger, entry.challenger_bond_atoms);
                if let Ok(report) = apply_aggregator_slash(
                    state,
                    entry.chain_id,
                    entry.aggregator,
                    entry.challenger,
                    entry.segment_index,
                    claim_index,
                    reason,
                ) {
                    Ok(ChallengeOutcome::Slashed(report))
                } else {
                    Ok(ChallengeOutcome::RefundedAlreadySlashed {
                        challenger: entry.challenger,
                        bond: entry.challenger_bond_atoms,
                    })
                }
            }
        }
    }

    /// Settles an unanswered challenge strictly after `deadline_height`,
    /// refunding the challenger's bond and slashing the silent aggregator 100%.
    ///
    /// Convenience: kept for the CLI and end-of-block challenge expiry handler.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `challenge_id` is unknown or `current_height <= deadline_height`.
    pub fn expire_challenge(
        &mut self,
        state: &mut AccountState,
        challenge_id: &Hash32,
        current_height: u64,
    ) -> Result<ChallengeOutcome, String> {
        let entry = self
            .open
            .get(challenge_id)
            .cloned()
            .ok_or_else(|| "aggregator fraud: unknown challenge id".to_string())?;
        if current_height <= entry.deadline_height {
            return Err("aggregator fraud: challenge window is still open".into());
        }
        // Past every refusal: commit removal and settlement atomically.
        self.open.remove(challenge_id);
        self.record_settled(*challenge_id);
        refund_challenger_bond(state, &entry.challenger, entry.challenger_bond_atoms);
        if let Ok(report) = apply_aggregator_slash(
            state,
            entry.chain_id,
            entry.aggregator,
            entry.challenger,
            entry.segment_index,
            0,
            SegmentFraudReason::ChallengeResponseTimeout,
        ) {
            Ok(ChallengeOutcome::Slashed(report))
        } else {
            Ok(ChallengeOutcome::RefundedAlreadySlashed {
                challenger: entry.challenger,
                bond: entry.challenger_bond_atoms,
            })
        }
    }
}

#[cfg(test)]
mod segment_challenge_hardening_tests {
    use super::*;
    use crate::aggregation::claim::Claim;
    use crate::aggregation::envelope::{Envelope, ObjectKind};
    use crate::aggregation::frame::{aggregator_address_from_seed, SegmentAttestation, SHAPE_TICK};
    use crate::aggregation::hash::segment_auth_message;
    use crate::aggregation::merkle::claims_root;
    use crate::core::chain_config::Network;

    fn make_attested_frame(
        seed: &[u8; 32],
        domain: DomainId,
        tag_byte: u8,
    ) -> (ClaimFrame, Address) {
        let aggregator = aggregator_address_from_seed(seed).expect("aggregator addr");
        let pk_vec = pq::ml_dsa_public_key(SchemeId::ML_DSA_87, seed).expect("ml-dsa pk");
        let pk: Box<[u8; crate::crypto::primitives::ML_DSA_87_PUBLIC_KEY_LEN]> =
            Box::new(pk_vec.try_into().expect("pk len"));
        let claim = Claim::Prog {
            program_hash: [tag_byte; 32],
            input_hash: [tag_byte.wrapping_add(1); 32],
            output_hash: [tag_byte.wrapping_add(2); 32],
        };
        let digest = claim.digest(domain);
        let root = claims_root(&[digest]).expect("claims root");
        let pi = super::super::frame::tick_pi_of(domain, &root, 1, &aggregator);
        let msg = segment_auth_message(&pi);
        let rnd = [0u8; 32];
        let sig_vec = pq::ml_dsa_sign(SchemeId::ML_DSA_87, seed, &msg, ctx::AGG_SEGMENT_V1, &rnd)
            .expect("segment sig");
        let sig: Box<[u8; ML_DSA_87_SIGNATURE_LEN]> =
            Box::new(sig_vec.try_into().expect("sig len"));
        let segment = Segment {
            claims_root: root,
            count: 1,
            aggregator,
            attestation: SegmentAttestation {
                public_key: pk,
                signature: sig,
            },
        };
        let frame = ClaimFrame {
            segments: vec![segment],
            shape: vec![SHAPE_TICK],
            claims: vec![claim],
            proof: vec![1u8],
        };
        (frame, aggregator)
    }

    #[test]
    fn rejects_burn_reserve_as_challenger_and_whistleblower() {
        let registry = SchemeStatusRegistry::genesis();
        let chain_id = Network::Devnet.chain_id().value();
        let domain: DomainId = 7;
        let agg_seed = [0x41u8; 32];
        let (frame, aggregator) = make_attested_frame(&agg_seed, domain, 0x10);

        let mut state = AccountState::new();
        let floor = state.validator_stake_floor(chain_id);
        state.add_validator_with_floor(aggregator, floor, floor);
        let burn_reserve = Address::from([0xBB; 32]);
        state.burn_reserve_address = Some(burn_reserve);
        let bond = required_challenger_bond(&state, chain_id, &aggregator);
        state.add_balance(&burn_reserve, bond * 10);
        let reserve_before = state.get_balance(&burn_reserve);

        let mut book = SegmentChallengeBook::new();
        assert!(
            book.open_challenge(
                &mut state,
                &registry,
                &SegmentChallengeRequest {
                    chain_id,
                    domain,
                    frame: &frame,
                    segment_index: 0,
                    challenger: burn_reserve,
                    opened_height: 100,
                },
            )
            .is_err(),
            "burn_reserve_address must never be debited as a challenger (refund destroys its bond)"
        );
        assert_eq!(
            state.get_balance(&burn_reserve),
            reserve_before,
            "rejected burn_reserve challenger must not lose balance"
        );

        let seg0 = frame.segments.first().expect("segment 0");
        let empty_sig = sign_backing_response(&agg_seed, chain_id, domain, seg0, &[])
            .expect("empty response sig");
        assert!(
            slash_unbacked_segment(
                &mut state,
                &registry,
                &UnbackedSegmentChallenge {
                    chain_id,
                    domain,
                    frame: &frame,
                    segment_index: 0,
                    backing_envelopes: &[],
                    aggregator_response_sig: &empty_sig,
                    whistleblower: burn_reserve,
                },
            )
            .is_err(),
            "burn_reserve_address must be refused as whistleblower"
        );
    }

    #[test]
    fn rejects_pre_opening_height_and_oversized_backing_envelopes() {
        let registry = SchemeStatusRegistry::genesis();
        let chain_id = Network::Devnet.chain_id().value();
        let domain: DomainId = 7;
        let agg_seed = [0x42u8; 32];
        let (frame, aggregator) = make_attested_frame(&agg_seed, domain, 0x20);

        let mut state = AccountState::new();
        let floor = state.validator_stake_floor(chain_id);
        state.add_validator_with_floor(aggregator, floor, floor);
        let challenger = Address::from([0xCC; 32]);
        let bond = required_challenger_bond(&state, chain_id, &aggregator);
        state.add_balance(&challenger, bond * 4);

        let mut book = SegmentChallengeBook::new();
        let cid = book
            .open_challenge(
                &mut state,
                &registry,
                &SegmentChallengeRequest {
                    chain_id,
                    domain,
                    frame: &frame,
                    segment_index: 0,
                    challenger,
                    opened_height: 100,
                },
            )
            .expect("open challenge");

        let seg0 = frame.segments.first().expect("segment 0");
        let empty_sig =
            sign_backing_response(&agg_seed, chain_id, domain, seg0, &[]).expect("empty sig");
        // Responding at height 50 < opened_height 100 must be refused while keeping challenge open.
        assert!(
            book.respond_challenge(
                &mut state,
                &registry,
                &RespondChallengeRequest {
                    challenge_id: cid,
                    current_height: 50,
                    backing_envelopes: &[],
                    response_signature: &empty_sig,
                },
            )
            .is_err(),
            "respond_challenge must refuse current_height < opened_height"
        );
        assert_eq!(book.pending_len(), 1);

        // Oversized backing_envelopes exceeding WIRE_FRAME_LIMITS.max_claims must be rejected
        // BEFORE hashing / verifying signature.
        let dummy_env = Envelope {
            kind: ObjectKind::Signature,
            scheme: SchemeId::ML_DSA_87,
            domain,
            tx_hash: [0u8; 32],
            payload: Vec::new(),
        };
        let huge = vec![dummy_env; WIRE_FRAME_LIMITS.max_claims + 1];
        let bogus_sig = [0u8; ML_DSA_87_SIGNATURE_LEN];
        let err = book
            .respond_challenge(
                &mut state,
                &registry,
                &RespondChallengeRequest {
                    challenge_id: cid,
                    current_height: 105,
                    backing_envelopes: &huge,
                    response_signature: &bogus_sig,
                },
            )
            .expect_err("oversized backing_envelopes must be refused");
        assert!(
            err.contains("limit") || err.contains("too many"),
            "expected cap error before sig verify, got: {err}"
        );
    }

    #[test]
    fn cross_chain_backing_response_replay_is_isolated() {
        let domain: DomainId = 7;
        let agg_seed = [0x43u8; 32];
        let (frame, _aggregator) = make_attested_frame(&agg_seed, domain, 0x30);
        let seg = frame.segments.first().expect("segment 0");
        let registry = SchemeStatusRegistry::genesis();

        let devnet_id = Network::Devnet.chain_id().value();
        let mainnet_id = Network::Mainnet.chain_id().value();
        assert_ne!(devnet_id, mainnet_id);

        // Aggregator signs an empty response on Devnet; replaying that signature on Mainnet
        // MUST fail signature verification.
        let devnet_sig =
            sign_backing_response(&agg_seed, devnet_id, domain, seg, &[]).expect("devnet sig");
        let mut mainnet_state = AccountState::new();
        let floor = mainnet_state.validator_stake_floor(mainnet_id);
        mainnet_state.add_validator_with_floor(seg.aggregator, floor, floor);
        let watcher = Address::from([0xDD; 32]);
        let res = slash_unbacked_segment(
            &mut mainnet_state,
            &registry,
            &UnbackedSegmentChallenge {
                chain_id: mainnet_id,
                domain,
                frame: &frame,
                segment_index: 0,
                backing_envelopes: &[],
                aggregator_response_sig: &devnet_sig,
                whistleblower: watcher,
            },
        );
        assert!(
            res.is_err(),
            "Devnet backing-response signature MUST NOT slash aggregator on Mainnet"
        );
        // Same signature DOES slash on the intended Devnet chain.
        let mut devnet_state = AccountState::new();
        let dev_floor = devnet_state.validator_stake_floor(devnet_id);
        devnet_state.add_validator_with_floor(seg.aggregator, dev_floor, dev_floor);
        assert!(
            slash_unbacked_segment(
                &mut devnet_state,
                &registry,
                &UnbackedSegmentChallenge {
                    chain_id: devnet_id,
                    domain,
                    frame: &frame,
                    segment_index: 0,
                    backing_envelopes: &[],
                    aggregator_response_sig: &devnet_sig,
                    whistleblower: watcher,
                },
            )
            .is_ok(),
            "matching chain_id signature must still slash validly"
        );
    }

    #[test]
    fn settled_challenge_book_remains_bounded() {
        let mut book = SegmentChallengeBook::new();
        for i in 0u64..70_000 {
            let mut id = [0u8; 32];
            if let Some(prefix) = id.get_mut(..8) {
                prefix.copy_from_slice(&i.to_le_bytes());
            }
            book.record_settled(id);
        }
        assert_eq!(
            book.settled_len(),
            MAX_SETTLED_SEGMENT_CHALLENGES,
            "SegmentChallengeBook::settled must cap at MAX_SETTLED_SEGMENT_CHALLENGES"
        );
        // Oldest entry (0) evicted; newest entry (69_999) retained.
        assert!(!book.settled.contains(&[0u8; 32]));
        let mut latest = [0u8; 32];
        if let Some(prefix) = latest.get_mut(..8) {
            prefix.copy_from_slice(&69_999u64.to_le_bytes());
        }
        assert!(book.settled.contains(&latest));
    }
}
