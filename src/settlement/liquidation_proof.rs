//! `ProofCarryingLiquidation`: oracle-free AMM/TWAP state-root-proven
//! cross-domain liquidation engine.
//!
//! WIRING: wired - `SettlementTx::Liquidate` reaches
//! [`execute_proven_cross_domain_liquidation`] through
//! `domains::execute_liquidation_request`, which intersects the sender's
//! claimed roots with the chain's `external_roots` before the engine sees them.
//! The RPC submission endpoint is still out of tree; the chain door is not.
//!
//! This module implements a liquidation mechanism that does not depend on
//! any external price oracle. Instead, it uses a Time-Weighted Average Price
//! (TWAP) computed from state-root-verified AMM reserves, proven via a
//! carrying proof that the reserves were correctly extracted from the
//! canonical state root.
//!
//! The key security properties:
//!
//! 1. **Oracle-free pricing**: price is derived from on-chain AMM reserves
//!    (`x * y = k` constant product), TWAP'd over `MIN_TWAP_EPOCHS` to
//!    resist single-block manipulation.
//! 2. **State-root provenance**: the AMM reserves used for pricing carry a
//!    Merkle proof that they exist in the canonical state root. No oracle
//!    can lie about reserves it cannot prove.
//! 3. **Collateral seize bounds**: when a position is liquidated, the
//!    seized collateral is computed as `debt * (1 + LIQUIDATION_PENALTY_BPS)`
//!    converted through the TWAP price, clamped to the position's available
//!    collateral. Over-seizing is impossible.
//! 4. **Deterministic**: same inputs always produce the same liquidation
//!    outcome. No randomness, no external state reads.
//!
//! WIRING: used by the settlement domain to process cross-domain
//! liquidation transactions against positions backed by external collateral.

use serde::{Deserialize, Serialize};

use crate::domain::types::Hash32;

/// Minimum TWAP observation epochs. Prevents single-block manipulation
/// by requiring at least 3 distinct observations.
pub const MIN_TWAP_EPOCHS: u64 = 3;
/// Maximum TWAP observation epochs.
pub const MAX_TWAP_EPOCHS: u64 = 100;
/// Liquidation penalty in basis points (5%).
pub const LIQUIDATION_PENALTY_BPS: u64 = 500;
/// BPS denominator.
const BPS_DEN: u64 = 10_000;
/// Maximum position count in a batch liquidation.
pub const MAX_BATCH_SIZE: usize = 64;
/// Maximum TWAP observations per position.
pub const MAX_OBSERVATIONS: usize = 128;

/// An AMM reserve snapshot at a specific state root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmmReserveSnapshot {
    /// State root this snapshot was extracted from.
    pub state_root: [u8; 32],
    /// Epoch of this observation.
    pub epoch: u64,
    /// Token X reserve (base asset).
    pub reserve_x: u128,
    /// Token Y reserve (quote/collateral asset).
    pub reserve_y: u128,
    /// Merkle proof that `(reserve_x, reserve_y)` exists at the expected
    /// slot in the state root.
    pub proof: Vec<[u8; 32]>,
}

impl AmmReserveSnapshot {
    /// Canonical digest of this snapshot.
    #[must_use]
    pub fn digest(&self) -> Hash32 {
        let epoch = self.epoch.to_le_bytes();
        let reserve_x = self.reserve_x.to_le_bytes();
        let reserve_y = self.reserve_y.to_le_bytes();
        let mut fields: Vec<&[u8]> = vec![
            b"BDLM_LIQ_RESERVE_V1",
            &self.state_root,
            &epoch,
            &reserve_x,
            &reserve_y,
        ];
        for node in &self.proof {
            fields.push(node);
        }
        crate::core::hash::hash_fields_bytes(&fields)
    }
}

/// A position eligible for liquidation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationPosition {
    /// Unique position identifier.
    pub position_id: u64,
    /// Debt in token X (base asset denomination).
    pub debt_x: u128,
    /// Available collateral in token Y.
    pub collateral_y: u128,
    /// Minimum health factor threshold (in BPS, 10000 = 1.0x).
    pub maintenance_threshold_bps: u64,
}

/// The result of a successful liquidation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationOutcome {
    /// The position that was liquidated.
    pub position_id: u64,
    /// Amount of collateral seized (in token Y).
    pub seized_collateral_y: u128,
    /// Amount of debt repaid (in token X).
    pub debt_repaid_x: u128,
    /// TWAP price used (Y per X, scaled by 1e18).
    pub twap_price_scaled: u128,
    /// Epoch at which the TWAP was computed.
    pub twap_epoch: u64,
    /// Remaining collateral returned to the position owner.
    pub remainder_y: u128,
}

/// Errors from the liquidation engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiquidationError {
    /// Insufficient TWAP observations.
    InsufficientObservations { got: usize, min: u64 },
    /// Too many observations.
    TooManyObservations { got: usize, max: usize },
    /// Observations not in strictly ascending epoch order.
    NonMonotonicEpochs { prev: u64, current: u64 },
    /// Zero reserve in an AMM snapshot (would cause division by zero).
    ZeroReserve { epoch: u64 },
    /// Position has no debt.
    NoDebt { position_id: u64 },
    /// Position is healthy (not eligible for liquidation).
    PositionHealthy { position_id: u64, health_bps: u64 },
    /// Batch too large.
    BatchTooLarge { got: usize, max: usize },
    /// Price overflow (TWAP price exceeds u128 max).
    PriceOverflow,
    /// Collateral underflow (impossible, defensive).
    CollateralUnderflow,
    /// State-root Merkle inclusion proof for an AMM reserve snapshot failed verification.
    InvalidReserveProof { domain_id: u32, epoch: u64 },
    /// Liquidation bonus exceeded `LIQ_BONUS_MAX_BPS`.
    BonusExceedsCap { got_bps: u64, max_bps: u64 },
    /// Requested debt repayment is zero or exceeds the close-factor ceiling.
    InvalidCloseAmount { requested: u128, max_repay: u128 },
    /// Missing delivery proof or collateral custody root for cross-domain seizure.
    MissingProofAnchor(String),
}

impl core::fmt::Display for LiquidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InsufficientObservations { got, min } => {
                write!(f, "need at least {min} TWAP observations, got {got}")
            }
            Self::TooManyObservations { got, max } => {
                write!(f, "too many observations: {got} > {max}")
            }
            Self::NonMonotonicEpochs { prev, current } => {
                write!(f, "epochs not monotonic: {prev} >= {current}")
            }
            Self::ZeroReserve { epoch } => {
                write!(f, "zero reserve at epoch {epoch}")
            }
            Self::NoDebt { position_id } => {
                write!(f, "position {position_id} has no debt")
            }
            Self::PositionHealthy {
                position_id,
                health_bps,
            } => {
                write!(f, "position {position_id} healthy at {health_bps} bps")
            }
            Self::BatchTooLarge { got, max } => {
                write!(f, "batch size {got} exceeds max {max}")
            }
            Self::PriceOverflow => write!(f, "TWAP price overflow"),
            Self::CollateralUnderflow => write!(f, "collateral underflow"),
            Self::InvalidReserveProof { domain_id, epoch } => {
                write!(
                    f,
                    "AMM reserve Merkle proof failed for domain {domain_id} at epoch {epoch}"
                )
            }
            Self::BonusExceedsCap { got_bps, max_bps } => {
                write!(
                    f,
                    "liquidation bonus {got_bps} bps exceeds cap {max_bps} bps"
                )
            }
            Self::InvalidCloseAmount {
                requested,
                max_repay,
            } => {
                write!(
                    f,
                    "liquidation close amount {requested} must be within 1..={max_repay}"
                )
            }
            Self::MissingProofAnchor(reason) => {
                write!(f, "missing cross-domain liquidation proof anchor: {reason}")
            }
        }
    }
}

/// Validate that a TWAP observation sequence is well-formed.
fn validate_observations(observations: &[AmmReserveSnapshot]) -> Result<(), LiquidationError> {
    let n = observations.len();
    if (n as u64) < MIN_TWAP_EPOCHS {
        return Err(LiquidationError::InsufficientObservations {
            got: n,
            min: MIN_TWAP_EPOCHS,
        });
    }
    if n > MAX_OBSERVATIONS {
        return Err(LiquidationError::TooManyObservations {
            got: n,
            max: MAX_OBSERVATIONS,
        });
    }
    for w in observations.windows(2) {
        if w[1].epoch <= w[0].epoch {
            return Err(LiquidationError::NonMonotonicEpochs {
                prev: w[0].epoch,
                current: w[1].epoch,
            });
        }
    }
    for obs in observations {
        if obs.reserve_x == 0 || obs.reserve_y == 0 {
            return Err(LiquidationError::ZeroReserve { epoch: obs.epoch });
        }
    }
    Ok(())
}

/// Compute the instantaneous price from a constant-product AMM.
/// Returns price as `reserve_y / reserve_x` scaled by `1e18`.
fn instant_price_scaled(reserve_x: u128, reserve_y: u128) -> Result<u128, LiquidationError> {
    // price = reserve_y / reserve_x, scaled by 1e18
    // = (reserve_y * 1e18) / reserve_x
    let scale: u128 = 1_000_000_000_000_000_000; // 1e18
    reserve_y
        .checked_mul(scale)
        .and_then(|num| num.checked_div(reserve_x))
        .ok_or(LiquidationError::PriceOverflow)
}

/// Validate that the TWAP price is a rational number (non-zero reserves).
fn validate_twap_rational_price(
    observations: &[AmmReserveSnapshot],
) -> Result<(), LiquidationError> {
    for obs in observations {
        if obs.reserve_x == 0 || obs.reserve_y == 0 {
            return Err(LiquidationError::ZeroReserve { epoch: obs.epoch });
        }
    }
    Ok(())
}

/// Compute the TWAP price from a sequence of AMM observations.
/// Uses time-weighted arithmetic mean of instantaneous prices.
fn compute_twap_price(observations: &[AmmReserveSnapshot]) -> Result<u128, LiquidationError> {
    validate_twap_rational_price(observations)?;

    // Time-weighted average: sum(price_i * duration_i) / sum(duration_i)
    // Duration of each observation is (next_epoch - this_epoch), except the
    // last which has duration 1 (it's the current price).
    let mut weighted_sum: u128 = 0;
    let mut total_duration: u128 = 0;

    for (i, obs) in observations.iter().enumerate() {
        let price = instant_price_scaled(obs.reserve_x, obs.reserve_y)?;
        let duration = observations.get(i + 1).map_or(1u128, |next| {
            u128::from(next.epoch.saturating_sub(obs.epoch))
        });
        weighted_sum = weighted_sum.saturating_add(
            price
                .checked_mul(duration)
                .ok_or(LiquidationError::PriceOverflow)?,
        );
        total_duration = total_duration.saturating_add(duration);
    }

    if total_duration == 0 {
        return Err(LiquidationError::InsufficientObservations {
            got: 0,
            min: MIN_TWAP_EPOCHS,
        });
    }

    Ok(weighted_sum / total_duration)
}

/// Compute the amount of collateral to seize for a liquidation.
/// Returns (seized, `debt_repaid`, remainder).
fn compute_seized_collateral(
    debt_x: u128,
    collateral_y: u128,
    twap_price_scaled: u128,
) -> (u128, u128, u128) {
    let scale: u128 = 1_000_000_000_000_000_000; // 1e18
    let penalty_multiplier = BPS_DEN + LIQUIDATION_PENALTY_BPS; // 10500

    // debt_in_y = debt_x * price * (1 + penalty) / scale / BPS_DEN
    // = debt_x * twap_price_scaled * penalty_multiplier / (scale * BPS_DEN)
    let debt_in_y = debt_x
        .saturating_mul(twap_price_scaled)
        .saturating_mul(u128::from(penalty_multiplier))
        / (scale * u128::from(BPS_DEN));

    let seized = debt_in_y.min(collateral_y);
    let remainder = collateral_y.saturating_sub(seized);
    (seized, debt_x, remainder)
}

/// Validate the liquidation parameters are well-formed.
fn validate_liquidation_params(
    observations: &[AmmReserveSnapshot],
    positions: &[LiquidationPosition],
) -> Result<(), LiquidationError> {
    if positions.is_empty() {
        return Ok(());
    }
    if positions.len() > MAX_BATCH_SIZE {
        return Err(LiquidationError::BatchTooLarge {
            got: positions.len(),
            max: MAX_BATCH_SIZE,
        });
    }
    validate_observations(observations)?;
    Ok(())
}

/// Execute a cross-domain liquidation.
///
/// Given a TWAP observation sequence and a set of positions, computes
/// which positions are eligible for liquidation and returns the outcomes.
///
/// A position is eligible when its health factor is below its maintenance
/// threshold. Health factor is `collateral_value / debt` in BPS.
///
/// # Errors
///
/// Returns [`LiquidationError`] if the observation sequence is malformed,
/// a position has no debt, or the batch exceeds [`MAX_BATCH_SIZE`].
pub fn execute_liquidation(
    observations: &[AmmReserveSnapshot],
    positions: &[LiquidationPosition],
) -> Result<Vec<LiquidationOutcome>, LiquidationError> {
    validate_liquidation_params(observations, positions)?;

    if positions.is_empty() {
        return Ok(Vec::new());
    }

    let twap_price = compute_twap_price(observations)?;
    let twap_epoch = observations.last().map_or(0, |o| o.epoch);

    let mut outcomes = Vec::new();
    let scale: u128 = 1_000_000_000_000_000_000; // 1e18

    for pos in positions {
        if pos.debt_x == 0 {
            return Err(LiquidationError::NoDebt {
                position_id: pos.position_id,
            });
        }

        // Health factor = (collateral_y * scale / twap_price) / debt_x * 10000
        // = collateral_y * scale * 10000 / (twap_price * debt_x)
        let collateral_value_x = pos.collateral_y.saturating_mul(scale) / twap_price.max(1);

        // health_bps = collateral_value_x * 10000 / debt_x
        let health_bps = collateral_value_x
            .saturating_mul(u128::from(BPS_DEN))
            .checked_div(pos.debt_x)
            .unwrap_or(u128::from(u64::MAX));

        if health_bps > u128::from(pos.maintenance_threshold_bps) {
            // Position is healthy, skip.
            continue;
        }

        let (seized, repaid, remainder) =
            compute_seized_collateral(pos.debt_x, pos.collateral_y, twap_price);

        outcomes.push(LiquidationOutcome {
            position_id: pos.position_id,
            seized_collateral_y: seized,
            debt_repaid_x: repaid,
            twap_price_scaled: twap_price,
            twap_epoch,
            remainder_y: remainder,
        });
    }

    Ok(outcomes)
}

/// Domain separation tag for AMM reserve Merkle leaves inside a certified domain
/// state root.
pub const LIQ_RESERVE_LEAF_TAG: &[u8] = b"BDLM_LIQ_RESERVE_LEAF_V1";

/// Maximum debt fraction repayable in one liquidation call (50% = 5,000 bps).
pub const LIQ_CLOSE_FACTOR_MAX_BPS: u64 = 5_000;

/// Maximum liquidation incentive bonus over debt repaid (15% = 1,500 bps).
pub const LIQ_BONUS_MAX_BPS: u64 = 1_500;

/// Maximum collateral legs seized across external domains in one liquidation.
const MAX_COLLATERAL_LEGS: usize = 16;

/// State-root-anchored AMM reserve observation carrying its Merkle inclusion
/// coordinates against a finalized domain state root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenReserveObservation {
    pub domain_id: u32,
    pub snapshot: AmmReserveSnapshot,
    pub leaf_index: usize,
    pub leaf_count: usize,
}

/// Compute the deterministic Merkle leaf committing an AMM reserve observation
/// inside `domain_id`'s state tree.
///
/// Convenience: shared by state-root provers and verifiers building oracle-free
/// TWAP reserve proofs.
#[must_use]
pub fn reserve_observation_leaf(
    domain_id: u32,
    epoch: u64,
    reserve_x: u128,
    reserve_y: u128,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        LIQ_RESERVE_LEAF_TAG,
        &domain_id.to_le_bytes(),
        &epoch.to_le_bytes(),
        &reserve_x.to_le_bytes(),
        &reserve_y.to_le_bytes(),
    ])
}

/// Compute the Merkle root committing reserve observation leaves at one epoch.
///
/// Convenience: constructs certified domain state roots for oracle-free TWAP
/// verification and tests.
#[must_use]
pub fn build_reserve_state_root(leaves: &[Hash32]) -> Hash32 {
    crate::unification::unification_merkle_root(LIQ_RESERVE_LEAF_TAG, leaves)
}

/// Build a Merkle inclusion proof for `leaf_index` in an epoch reserve tree.
///
/// Convenience: builds inclusion proofs verified by [`ProvenReserveObservation::verify_against_state_root`].
#[must_use]
pub fn build_reserve_inclusion_proof(leaves: &[Hash32], leaf_index: usize) -> Option<Vec<Hash32>> {
    crate::unification::build_merkle_proof(LIQ_RESERVE_LEAF_TAG, leaves, leaf_index)
}

impl ProvenReserveObservation {
    /// Cryptographically verify that this AMM reserve snapshot is included in
    /// `certified_domain_state_root` (from a finalized domain checkpoint).
    ///
    /// Convenience: enforces oracle-free state-root provenance for every TWAP
    /// price observation.
    ///
    /// # Errors
    ///
    /// Returns [`LiquidationError::InvalidReserveProof`] if the root is zero,
    /// disagrees with `snapshot.state_root`, or fails Merkle verification.
    pub fn verify_against_state_root(
        &self,
        certified_domain_state_root: &Hash32,
    ) -> Result<(), LiquidationError> {
        if *certified_domain_state_root == [0u8; 32]
            || self.snapshot.state_root != *certified_domain_state_root
        {
            return Err(LiquidationError::InvalidReserveProof {
                domain_id: self.domain_id,
                epoch: self.snapshot.epoch,
            });
        }
        let leaf = reserve_observation_leaf(
            self.domain_id,
            self.snapshot.epoch,
            self.snapshot.reserve_x,
            self.snapshot.reserve_y,
        );
        if !crate::unification::verify_merkle_proof(
            LIQ_RESERVE_LEAF_TAG,
            certified_domain_state_root,
            self.leaf_index,
            self.leaf_count,
            &leaf,
            &self.snapshot.proof,
        ) {
            return Err(LiquidationError::InvalidReserveProof {
                domain_id: self.domain_id,
                epoch: self.snapshot.epoch,
            });
        }
        Ok(())
    }
}

/// Proof-carrying health verdict derived exclusively from state-root-verified
/// AMM reserves (no price oracle dependency).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCarryingHealth {
    pub position_id: u64,
    pub debt_domain_id: u32,
    pub twap_price_scaled: u128,
    pub twap_epoch: u64,
    pub health_bps: u64,
    pub maintenance_threshold_bps: u64,
    pub liquidatable: bool,
    pub observations_commitment: Hash32,
    pub health_proof_digest: Hash32,
}

/// One cross-domain collateral leg held in object-layer custody or a Budlum-proven
/// remote account (debt on domain A, collateral spread across domains B, C, ...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralLegSpec {
    pub domain_id: u32,
    pub asset_id: Hash32,
    /// Non-zero custody or remote-account proof root anchoring this leg.
    pub custody_or_remote_root: Hash32,
    pub available_y: u128,
}

/// Deterministic collateral seizure outcome on one external domain leg.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainSeizureLeg {
    pub domain_id: u32,
    pub asset_id: Hash32,
    pub seized_y: u128,
    pub remainder_y: u128,
}

/// Complete proof-carrying cross-domain liquidation result binding the proven
/// health verdict, close-factor-bounded debt repayment, bonus cap, delivery
/// proof anchor on the debt domain, and deterministic collateral seizures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenLiquidationResult {
    pub health: ProofCarryingHealth,
    pub debt_repaid_x: u128,
    pub bonus_bps: u64,
    pub seized_legs: Vec<CrossDomainSeizureLeg>,
    pub delivery_proof_root: Hash32,
}

/// Derive a [`ProofCarryingHealth`] verdict for `position` after verifying every
/// [`ProvenReserveObservation`] against `certified_roots` keyed by `(domain_id, epoch)`.
///
/// Convenience: produces an oracle-free, state-root-proven health statement
/// usable by cross-domain liquidation gates and light verifiers.
///
/// # Errors
///
/// Returns [`LiquidationError`] if `position.debt_x == 0`, any observation fails
/// Merkle proof verification against `certified_roots`, or the TWAP sequence is
/// malformed.
pub fn prove_position_health(
    position: &LiquidationPosition,
    debt_domain_id: u32,
    certified_roots: &std::collections::BTreeMap<(u32, u64), Hash32>,
    observations: &[ProvenReserveObservation],
) -> Result<ProofCarryingHealth, LiquidationError> {
    if position.debt_x == 0 {
        return Err(LiquidationError::NoDebt {
            position_id: position.position_id,
        });
    }

    let mut snapshots = Vec::with_capacity(observations.len());
    let mut obs_digests = Vec::with_capacity(observations.len());
    for obs in observations {
        let Some(certified_root) = certified_roots.get(&(obs.domain_id, obs.snapshot.epoch)) else {
            return Err(LiquidationError::InvalidReserveProof {
                domain_id: obs.domain_id,
                epoch: obs.snapshot.epoch,
            });
        };
        obs.verify_against_state_root(certified_root)?;
        obs_digests.push(obs.snapshot.digest());
        snapshots.push(obs.snapshot.clone());
    }

    validate_observations(&snapshots)?;
    let twap_price_scaled = compute_twap_price(&snapshots)?;
    let twap_epoch = snapshots.last().map_or(0, |s| s.epoch);

    let scale: u128 = 1_000_000_000_000_000_000;
    let collateral_value_x = position.collateral_y.saturating_mul(scale) / twap_price_scaled.max(1);
    let health_bps_u128 = collateral_value_x
        .saturating_mul(u128::from(BPS_DEN))
        .checked_div(position.debt_x)
        .unwrap_or(u128::from(u64::MAX));
    let health_bps = u64::try_from(health_bps_u128).unwrap_or(u64::MAX);
    let liquidatable = health_bps <= position.maintenance_threshold_bps;

    let observations_commitment =
        crate::unification::unification_merkle_root(b"BDLM_LIQ_OBSERVATIONS_V1", &obs_digests);
    let health_proof_digest = crate::core::hash::hash_fields_bytes(&[
        b"BDLM_LIQ_HEALTH_PROOF_V1",
        &position.position_id.to_le_bytes(),
        &debt_domain_id.to_le_bytes(),
        &twap_price_scaled.to_le_bytes(),
        &twap_epoch.to_le_bytes(),
        &health_bps.to_le_bytes(),
        &position.maintenance_threshold_bps.to_le_bytes(),
        &[u8::from(liquidatable)],
        &observations_commitment,
    ]);

    Ok(ProofCarryingHealth {
        position_id: position.position_id,
        debt_domain_id,
        twap_price_scaled,
        twap_epoch,
        health_bps,
        maintenance_threshold_bps: position.maintenance_threshold_bps,
        liquidatable,
        observations_commitment,
        health_proof_digest,
    })
}

/// Parameters binding a cross-domain liquidation execution request to its debt
/// domain, close amount, capped incentive bonus, and debt-domain delivery proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainLiquidationParams {
    pub debt_domain_id: u32,
    pub repay_debt_x: u128,
    pub bonus_bps: u64,
    pub delivery_proof_root: Hash32,
}

/// Execute an oracle-free, proof-carrying, close-factor- and bonus-capped
/// cross-domain liquidation (debt on `params.debt_domain_id`, collateral legs
/// across arbitrary domains anchored by custody or remote-account proof roots).
///
/// Rejects fail-closed if:
/// - Any AMM reserve observation fails Merkle verification against `certified_roots`.
/// - The position is healthy (`!health.liquidatable`).
/// - `params.bonus_bps > LIQ_BONUS_MAX_BPS` or `params.repay_debt_x` is zero /
///   exceeds the 50% close-factor ceiling (`LIQ_CLOSE_FACTOR_MAX_BPS`).
/// - `params.delivery_proof_root` or any collateral leg `custody_or_remote_root`
///   is all-zero.
/// - Collateral legs are empty or exceed `MAX_COLLATERAL_LEGS`, or their sum
///   disagrees with `position.collateral_y`.
///
/// Convenience: unified oracle-free cross-domain liquidation coordinator
/// combining state-root reserve provenance with close-factor and bonus bounds.
///
/// # Errors
///
/// Returns [`LiquidationError`] on any failed proof, health, bound, or anchor check.
pub fn execute_proven_cross_domain_liquidation(
    position: &LiquidationPosition,
    certified_roots: &std::collections::BTreeMap<(u32, u64), Hash32>,
    observations: &[ProvenReserveObservation],
    collateral_legs: &[CollateralLegSpec],
    params: &CrossDomainLiquidationParams,
) -> Result<ProvenLiquidationResult, LiquidationError> {
    if params.bonus_bps > LIQ_BONUS_MAX_BPS {
        return Err(LiquidationError::BonusExceedsCap {
            got_bps: params.bonus_bps,
            max_bps: LIQ_BONUS_MAX_BPS,
        });
    }
    if params.delivery_proof_root == [0u8; 32] {
        return Err(LiquidationError::MissingProofAnchor(String::from(
            "debt-domain delivery_proof_root must be non-zero",
        )));
    }
    if collateral_legs.is_empty() || collateral_legs.len() > MAX_COLLATERAL_LEGS {
        return Err(LiquidationError::MissingProofAnchor(format!(
            "collateral_legs count must be within 1..={MAX_COLLATERAL_LEGS}"
        )));
    }

    let mut total_leg_collateral = 0u128;
    for leg in collateral_legs {
        if leg.custody_or_remote_root == [0u8; 32] {
            return Err(LiquidationError::MissingProofAnchor(format!(
                "collateral leg on domain {} missing non-zero custody/remote root",
                leg.domain_id
            )));
        }
        total_leg_collateral = total_leg_collateral
            .checked_add(leg.available_y)
            .ok_or(LiquidationError::PriceOverflow)?;
    }
    if total_leg_collateral != position.collateral_y {
        return Err(LiquidationError::MissingProofAnchor(format!(
            "sum of collateral legs ({total_leg_collateral}) disagrees with position.collateral_y ({})",
            position.collateral_y
        )));
    }

    let health = prove_position_health(
        position,
        params.debt_domain_id,
        certified_roots,
        observations,
    )?;
    if !health.liquidatable {
        return Err(LiquidationError::PositionHealthy {
            position_id: position.position_id,
            health_bps: health.health_bps,
        });
    }

    let max_repay = (position
        .debt_x
        .saturating_mul(u128::from(LIQ_CLOSE_FACTOR_MAX_BPS))
        / u128::from(BPS_DEN))
    .max(1)
    .min(position.debt_x);
    if params.repay_debt_x == 0 || params.repay_debt_x > max_repay {
        return Err(LiquidationError::InvalidCloseAmount {
            requested: params.repay_debt_x,
            max_repay,
        });
    }

    let scale: u128 = 1_000_000_000_000_000_000;
    let bonus_mult = u128::from(BPS_DEN.saturating_add(params.bonus_bps));
    let mut target_seize_y = params
        .repay_debt_x
        .saturating_mul(health.twap_price_scaled)
        .saturating_mul(bonus_mult)
        / (scale * u128::from(BPS_DEN));
    target_seize_y = target_seize_y.min(position.collateral_y);

    // Deterministic canonical ordering by `(domain_id, asset_id)` so seizure is
    // caller-order-independent across multi-domain collateral legs.
    let mut sorted_legs = collateral_legs.to_vec();
    sorted_legs.sort_by_key(|l| (l.domain_id, l.asset_id));

    let mut remaining_to_seize = target_seize_y;
    let mut seized_legs = Vec::with_capacity(sorted_legs.len());
    for leg in sorted_legs {
        let take = remaining_to_seize.min(leg.available_y);
        let remainder = leg.available_y.saturating_sub(take);
        remaining_to_seize = remaining_to_seize.saturating_sub(take);
        if take > 0 {
            seized_legs.push(CrossDomainSeizureLeg {
                domain_id: leg.domain_id,
                asset_id: leg.asset_id,
                seized_y: take,
                remainder_y: remainder,
            });
        }
    }

    Ok(ProvenLiquidationResult {
        health,
        debt_repaid_x: params.repay_debt_x,
        bonus_bps: params.bonus_bps,
        seized_legs,
        delivery_proof_root: params.delivery_proof_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_observations(prices: &[(u64, u128, u128)]) -> Vec<AmmReserveSnapshot> {
        prices
            .iter()
            .map(|(epoch, rx, ry)| AmmReserveSnapshot {
                state_root: [0xAA; 32],
                epoch: *epoch,
                reserve_x: *rx,
                reserve_y: *ry,
                proof: vec![[0x01; 32]],
            })
            .collect()
    }

    #[test]
    fn valid_liquidation_seizes_correct_collateral() {
        // price Y/X = 2.0 (reserve_y=200, reserve_x=100); debt_x=1000 costs 2000 Y,
        // so collateral_y=2500 has health factor 12_500 bps (< 15_000 bps threshold).
        let obs = make_observations(&[(1, 100, 200), (2, 100, 200), (3, 100, 200)]);
        let positions = vec![LiquidationPosition {
            position_id: 1,
            debt_x: 1000,
            collateral_y: 2500,
            maintenance_threshold_bps: 15_000, // 1.5x
        }];
        let outcomes = execute_liquidation(&obs, &positions).expect("liquidation");
        assert_eq!(outcomes.len(), 1);
        let o = &outcomes[0];
        assert_eq!(o.position_id, 1);
        // debt_in_y = 1000 * 2e18 * 10500 / (1e18 * 10000) = 1000 * 2 * 1.05 = 2100
        assert_eq!(o.debt_repaid_x, 1000);
        assert_eq!(o.seized_collateral_y, 2100);
        assert_eq!(o.remainder_y, 2500 - 2100);
    }

    #[test]
    fn healthy_position_is_not_liquidated() {
        let obs = make_observations(&[
            (1, 100, 100), // price = 1.0
            (2, 100, 100),
            (3, 100, 100),
        ]);
        let positions = vec![LiquidationPosition {
            position_id: 1,
            debt_x: 100,
            collateral_y: 1000, // health = 1000/100 = 10x, well above 1.5x
            maintenance_threshold_bps: 15_000,
        }];
        let outcomes = execute_liquidation(&obs, &positions).expect("no crash");
        assert!(
            outcomes.is_empty(),
            "healthy position should not be liquidated"
        );
    }

    #[test]
    fn too_few_observations_is_refused() {
        let obs = make_observations(&[(1, 100, 200), (2, 100, 200)]);
        let positions = vec![LiquidationPosition {
            position_id: 1,
            debt_x: 100,
            collateral_y: 50,
            maintenance_threshold_bps: 15_000,
        }];
        let err = execute_liquidation(&obs, &positions).unwrap_err();
        assert!(matches!(
            err,
            LiquidationError::InsufficientObservations { got: 2, min: 3 }
        ));
    }

    #[test]
    fn non_monotonic_epochs_are_refused() {
        let obs = make_observations(&[(1, 100, 200), (3, 100, 200), (2, 100, 200)]);
        let positions = vec![LiquidationPosition {
            position_id: 1,
            debt_x: 100,
            collateral_y: 50,
            maintenance_threshold_bps: 15_000,
        }];
        let err = execute_liquidation(&obs, &positions).unwrap_err();
        assert!(matches!(
            err,
            LiquidationError::NonMonotonicEpochs {
                prev: 3,
                current: 2
            }
        ));
    }

    #[test]
    fn zero_reserve_is_refused() {
        let obs = make_observations(&[(1, 100, 200), (2, 0, 200), (3, 100, 200)]);
        let positions = vec![LiquidationPosition {
            position_id: 1,
            debt_x: 100,
            collateral_y: 50,
            maintenance_threshold_bps: 15_000,
        }];
        let err = execute_liquidation(&obs, &positions).unwrap_err();
        assert!(matches!(err, LiquidationError::ZeroReserve { epoch: 2 }));
    }

    #[test]
    fn zero_debt_position_is_refused() {
        let obs = make_observations(&[(1, 100, 200), (2, 100, 200), (3, 100, 200)]);
        let positions = vec![LiquidationPosition {
            position_id: 1,
            debt_x: 0,
            collateral_y: 5000,
            maintenance_threshold_bps: 15_000,
        }];
        let err = execute_liquidation(&obs, &positions).unwrap_err();
        assert!(matches!(err, LiquidationError::NoDebt { position_id: 1 }));
    }

    #[test]
    fn batch_too_large_is_refused() {
        let obs = make_observations(&[(1, 100, 200), (2, 100, 200), (3, 100, 200)]);
        let positions = (0..=MAX_BATCH_SIZE)
            .map(|i| LiquidationPosition {
                position_id: i as u64,
                debt_x: 100,
                collateral_y: 50,
                maintenance_threshold_bps: 15_000,
            })
            .collect::<Vec<_>>();
        let err = execute_liquidation(&obs, &positions).unwrap_err();
        assert!(matches!(err, LiquidationError::BatchTooLarge { .. }));
    }

    #[test]
    fn collateral_capped_at_position_balance() {
        // debt=1000, price=2.0, penalty=5% => debt_in_y = 2100
        // but collateral_y = 1500 < 2100, so seize only 1500
        let obs = make_observations(&[(1, 100, 200), (2, 100, 200), (3, 100, 200)]);
        let positions = vec![LiquidationPosition {
            position_id: 1,
            debt_x: 1000,
            collateral_y: 1500, // less than 2100
            maintenance_threshold_bps: 15_000,
        }];
        let outcomes = execute_liquidation(&obs, &positions).expect("ok");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].seized_collateral_y, 1500); // capped
        assert_eq!(outcomes[0].remainder_y, 0);
    }

    #[test]
    fn twap_price_varies_with_reserves() {
        // Epoch 1: price = 200/100 = 2.0
        // Epoch 2: price = 400/100 = 4.0
        // Epoch 3: price = 300/100 = 3.0
        // TWAP = (2.0 * 1 + 4.0 * 1 + 3.0) / 3 = (2 + 4 + 3) / 3 = 3.0
        let obs = make_observations(&[(1, 100, 200), (2, 100, 400), (3, 100, 300)]);
        let positions = vec![LiquidationPosition {
            position_id: 1,
            debt_x: 100,
            collateral_y: 100, // very low collateral, will be unhealthy
            maintenance_threshold_bps: 15_000,
        }];
        let outcomes = execute_liquidation(&obs, &positions).expect("ok");
        assert_eq!(outcomes.len(), 1);
        // TWAP should be 3.0e18
        assert_eq!(outcomes[0].twap_price_scaled, 3_000_000_000_000_000_000);
    }

    #[test]
    fn empty_positions_returns_empty() {
        let obs = make_observations(&[(1, 100, 200), (2, 100, 200), (3, 100, 200)]);
        let outcomes = execute_liquidation(&obs, &[]).expect("ok");
        assert!(outcomes.is_empty());
    }
    #[test]
    fn liquidation_request_certified_roots_serialize_as_string_keys() {
        let mut roots = std::collections::BTreeMap::new();
        roots.insert((7u32, 12u64), [0xabu8; 32]);
        let request = LiquidationRequest {
            position: LiquidationPosition {
                position_id: 1,
                debt_x: 1_000,
                collateral_y: 2_000,
                maintenance_threshold_bps: 8_000,
            },
            certified_roots: roots,
            observations: Vec::new(),
            collateral_legs: Vec::new(),
            params: CrossDomainLiquidationParams {
                debt_domain_id: 7,
                repay_debt_x: 500,
                bonus_bps: 100,
                delivery_proof_root: [0u8; 32],
            },
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(
            json.contains("\"7:12\""),
            "certified_roots must key by string: {json}"
        );
        let back: LiquidationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.certified_roots, request.certified_roots);
    }
}

/// A liquidation as it arrives on chain: everything the engine needs, in one
/// object, so the door does not have to invent a wire format.
///
/// The fields are the engine's five inputs verbatim. Nothing is derived here:
/// a request that lies about a root, a reserve or a leg is caught by
/// `execute_proven_cross_domain_liquidation`, and the door's only extra work is
/// to drop claimed roots this chain never accepted (see
/// `domains::execute_liquidation_request`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationRequest {
    /// The position being liquidated.
    pub position: LiquidationPosition,
    /// Roots the sender claims are final, keyed by `(domain, epoch)`.
    ///
    /// The sender supplies these because only it knows which epochs its
    /// observations cite; the chain then intersects them with what it has
    /// accepted, which is why an invented root here is harmless rather than
    /// exploitable.
    #[serde(with = "crate::core::map_keys")]
    pub certified_roots: std::collections::BTreeMap<(u32, u64), Hash32>,
    /// Reserve observations, each carrying its own inclusion proof.
    pub observations: Vec<ProvenReserveObservation>,
    /// The collateral legs the position claims, one per source domain.
    pub collateral_legs: Vec<CollateralLegSpec>,
    /// Caps and the delivery anchor.
    pub params: CrossDomainLiquidationParams,
}

impl LiquidationRequest {
    /// Whether the request carries any evidence at all.
    ///
    /// A request with no observations cannot prove health, so it is refused
    /// before the engine's heavier checks run - and, more importantly, before
    /// any caller could mistake "the engine returned nothing" for "nothing was
    /// wrong".
    #[must_use]
    pub fn has_evidence(&self) -> bool {
        !self.certified_roots.is_empty() && !self.observations.is_empty()
    }


}
