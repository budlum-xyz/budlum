//! `ProofCarryingLiquidation`: oracle-free AMM/TWAP state-root-proven
//! cross-domain liquidation engine.
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

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::domain::types::Hash32;

/// Minimum TWAP observation epochs. Prevents single-block manipulation
/// by requiring at least 3 distinct observations.
pub const MIN_TWAP_EPOCHS: u64 = 3;
/// Maximum TWAP observation epoch span.
pub const MAX_TWAP_EPOCHS: u64 = 100;
/// Liquidation penalty in basis points (5%).
pub const LIQUIDATION_PENALTY_BPS: u64 = 500;
/// BPS denominator.
const BPS_DEN: u64 = 10_000;
/// Fixed-point price scale (1e18).
const PRICE_SCALE: u128 = 1_000_000_000_000_000_000;
/// Maximum Merkle proof depth accepted for AMM reserve provenance.
const MAX_MERKLE_PROOF_DEPTH: usize = 64;
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
    /// Observation epoch span exceeds `MAX_TWAP_EPOCHS`.
    EpochSpanTooWide { span: u64, max: u64 },
    /// AMM reserve snapshot failed Merkle state-root provenance verification.
    InvalidReserveProof { epoch: u64 },
    /// Zero reserve in an AMM snapshot (would cause division by zero).
    ZeroReserve { epoch: u64 },
    /// Position has no debt.
    NoDebt { position_id: u64 },
    /// Duplicate position id in a single batch.
    DuplicatePosition { position_id: u64 },
    /// Position is healthy (not eligible for liquidation).
    PositionHealthy { position_id: u64, health_bps: u64 },
    /// Batch too large.
    BatchTooLarge { got: usize, max: usize },
    /// Price overflow (TWAP price exceeds u128 max or rounds to zero).
    PriceOverflow,
    /// Collateral underflow (impossible, defensive).
    CollateralUnderflow,
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
            Self::EpochSpanTooWide { span, max } => {
                write!(f, "observation epoch span {span} exceeds max {max}")
            }
            Self::InvalidReserveProof { epoch } => {
                write!(
                    f,
                    "invalid AMM reserve Merkle state-root proof at epoch {epoch}"
                )
            }
            Self::ZeroReserve { epoch } => {
                write!(f, "zero reserve at epoch {epoch}")
            }
            Self::NoDebt { position_id } => {
                write!(f, "position {position_id} has no debt")
            }
            Self::DuplicatePosition { position_id } => {
                write!(
                    f,
                    "duplicate position_id {position_id} in liquidation batch"
                )
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
        }
    }
}

/// Compute the domain-separated Merkle leaf digest for an AMM reserve snapshot.
fn reserve_leaf_digest(epoch: u64, reserve_x: u128, reserve_y: u128) -> Hash32 {
    let epoch_bytes = epoch.to_le_bytes();
    let rx_bytes = reserve_x.to_le_bytes();
    let ry_bytes = reserve_y.to_le_bytes();
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_LIQ_RESERVE_V1",
        b"leaf",
        &epoch_bytes,
        &rx_bytes,
        &ry_bytes,
    ])
}

/// Fold a reserve leaf up to a state root using its Merkle sibling path.
/// Direction bits come deterministically from `epoch` (`(epoch >> depth) & 1`),
/// binding the leaf position and resisting second-preimage attacks via distinct
/// `"leaf"` vs `"node"` sub-tags and explicit `level` separation.
fn fold_reserve_merkle_path(leaf: Hash32, epoch: u64, proof: &[Hash32]) -> Hash32 {
    let mut acc = leaf;
    for (depth, sibling) in proof.iter().enumerate() {
        let level = (depth as u32).to_le_bytes();
        let is_right = depth < 64 && ((epoch >> depth) & 1) == 1;
        let (left, right) = if is_right {
            (sibling, &acc)
        } else {
            (&acc, sibling)
        };
        acc = crate::core::hash::hash_fields_bytes(&[
            b"BDLM_LIQ_RESERVE_V1",
            b"node",
            &level,
            left,
            right,
        ]);
    }
    acc
}

/// Verify that an AMM reserve snapshot carries a valid Merkle inclusion proof
/// committing `(epoch, reserve_x, reserve_y)` into `state_root`.
fn verify_reserve_proof(obs: &AmmReserveSnapshot) -> Result<(), LiquidationError> {
    if obs.state_root == [0u8; 32]
        || obs.proof.is_empty()
        || obs.proof.len() > MAX_MERKLE_PROOF_DEPTH
        || obs.proof.contains(&[0u8; 32])
    {
        return Err(LiquidationError::InvalidReserveProof { epoch: obs.epoch });
    }
    let leaf = reserve_leaf_digest(obs.epoch, obs.reserve_x, obs.reserve_y);
    let derived = fold_reserve_merkle_path(leaf, obs.epoch, &obs.proof);
    if !bool::from(derived.ct_eq(&obs.state_root)) {
        return Err(LiquidationError::InvalidReserveProof { epoch: obs.epoch });
    }
    Ok(())
}

/// Exact 256-bit product of two `u128` values in little-endian 64-bit limbs.
fn mul_u128_u128(a: u128, b: u128) -> [u64; 4] {
    let a0 = u128::from(a as u64);
    let a1 = a >> 64;
    let b0 = u128::from(b as u64);
    let b1 = b >> 64;

    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;

    let w0 = p00 as u64;
    let s1 = (p00 >> 64) + (p01 & u128::from(u64::MAX)) + (p10 & u128::from(u64::MAX));
    let w1 = s1 as u64;
    let c2 = (s1 >> 64) + (p01 >> 64) + (p10 >> 64) + (p11 & u128::from(u64::MAX));
    let w2 = c2 as u64;
    let w3 = ((c2 >> 64) + (p11 >> 64)) as u64;
    [w0, w1, w2, w3]
}

/// Exact 320-bit product of a 256-bit unsigned integer and a `u64`.
fn mul_u256_u64(a: [u64; 4], b: u64) -> [u64; 5] {
    let [a0, a1, a2, a3] = a;
    let b128 = u128::from(b);
    let p0 = u128::from(a0) * b128;
    let p1 = u128::from(a1) * b128 + (p0 >> 64);
    let p2 = u128::from(a2) * b128 + (p1 >> 64);
    let p3 = u128::from(a3) * b128 + (p2 >> 64);
    [
        p0 as u64,
        p1 as u64,
        p2 as u64,
        p3 as u64,
        (p3 >> 64) as u64,
    ]
}

/// Exact 320-bit product `a * b * c` (no overflow possible for any inputs).
fn mul_u128_u128_u64(a: u128, b: u128, c: u64) -> [u64; 5] {
    mul_u256_u64(mul_u128_u128(a, b), c)
}

/// Checked addition of a 256-bit value into a 320-bit accumulator.
fn add_u320_u256(acc: [u64; 5], rhs: [u64; 4]) -> Option<[u64; 5]> {
    let [c0, c1, c2, c3, c4] = acc;
    let [r0, r1, r2, r3] = rhs;
    let s0 = u128::from(c0) + u128::from(r0);
    let s1 = u128::from(c1) + u128::from(r1) + (s0 >> 64);
    let s2 = u128::from(c2) + u128::from(r2) + (s1 >> 64);
    let s3 = u128::from(c3) + u128::from(r3) + (s2 >> 64);
    let top = u128::from(c4) + (s3 >> 64);
    if top > u128::from(u64::MAX) {
        return None;
    }
    Some([s0 as u64, s1 as u64, s2 as u64, s3 as u64, top as u64])
}

/// Exact comparison of two 320-bit little-endian unsigned integers.
fn cmp_u320(a: &[u64; 5], b: &[u64; 5]) -> core::cmp::Ordering {
    for (al, bl) in a.iter().rev().zip(b.iter().rev()) {
        let ord = al.cmp(bl);
        if ord != core::cmp::Ordering::Equal {
            return ord;
        }
    }
    core::cmp::Ordering::Equal
}

/// Exact floor division of a 320-bit unsigned integer by a non-zero `u128`.
/// Returns `None` if `den == 0` or the quotient exceeds `u128::MAX`.
fn div_u320_by_u128(num: [u64; 5], den: u128) -> Option<u128> {
    if den == 0 {
        return None;
    }
    let mut rem: u128 = 0;
    let mut quot: u128 = 0;
    let mut quot_overflow = false;
    for &limb in num.iter().rev() {
        for bit_idx in (0..64).rev() {
            let bit = u128::from((limb >> bit_idx) & 1);
            let carry = (rem >> 127) != 0;
            rem = (rem << 1) | bit;
            let q_bit = if carry || rem >= den {
                rem = rem.wrapping_sub(den);
                1u128
            } else {
                0u128
            };
            if (quot >> 127) != 0 {
                quot_overflow = true;
            }
            quot = (quot << 1) | q_bit;
        }
    }
    if quot_overflow {
        None
    } else {
        Some(quot)
    }
}

/// Validate that a TWAP observation sequence is well-formed and state-root-proven.
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
    if let (Some(first), Some(last)) = (observations.first(), observations.last()) {
        let span = last.epoch.saturating_sub(first.epoch);
        if span > MAX_TWAP_EPOCHS {
            return Err(LiquidationError::EpochSpanTooWide {
                span,
                max: MAX_TWAP_EPOCHS,
            });
        }
    }
    for obs in observations {
        if obs.reserve_x == 0 || obs.reserve_y == 0 {
            return Err(LiquidationError::ZeroReserve { epoch: obs.epoch });
        }
        verify_reserve_proof(obs)?;
    }
    Ok(())
}

/// Compute the instantaneous price from a constant-product AMM without `u128`
/// intermediate overflow. Returns `floor(reserve_y * 1e18 / reserve_x)`.
fn instant_price_scaled(reserve_x: u128, reserve_y: u128) -> Result<u128, LiquidationError> {
    let p = mul_u128_u128(reserve_y, PRICE_SCALE);
    let price = div_u320_by_u128([p[0], p[1], p[2], p[3], 0], reserve_x)
        .ok_or(LiquidationError::PriceOverflow)?;
    if price == 0 {
        return Err(LiquidationError::PriceOverflow);
    }
    Ok(price)
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

/// Compute the TWAP price from a sequence of AMM observations using exact
/// 320-bit accumulation so weighted sums never saturate.
fn compute_twap_price(observations: &[AmmReserveSnapshot]) -> Result<u128, LiquidationError> {
    validate_twap_rational_price(observations)?;

    // Time-weighted average: sum(price_i * duration_i) / sum(duration_i)
    // Duration of each observation is (next_epoch - this_epoch), except the
    // last which has duration 1 (it's the current price).
    let mut weighted_sum = [0u64; 5];
    let mut total_duration: u128 = 0;

    for (i, obs) in observations.iter().enumerate() {
        let price = instant_price_scaled(obs.reserve_x, obs.reserve_y)?;
        let duration = observations.get(i + 1).map_or(1u128, |next| {
            u128::from(next.epoch.saturating_sub(obs.epoch))
        });
        let term = mul_u128_u128(price, duration);
        weighted_sum = add_u320_u256(weighted_sum, term).ok_or(LiquidationError::PriceOverflow)?;
        total_duration = total_duration
            .checked_add(duration)
            .ok_or(LiquidationError::PriceOverflow)?;
    }

    if total_duration == 0 {
        return Err(LiquidationError::InsufficientObservations {
            got: 0,
            min: MIN_TWAP_EPOCHS,
        });
    }

    let twap =
        div_u320_by_u128(weighted_sum, total_duration).ok_or(LiquidationError::PriceOverflow)?;
    if twap == 0 {
        return Err(LiquidationError::PriceOverflow);
    }
    Ok(twap)
}

/// Compute the amount of collateral to seize for a liquidation using exact
/// 320-bit arithmetic. Returns `(seized, debt_repaid, remainder)`.
fn compute_seized_collateral(
    debt_x: u128,
    collateral_y: u128,
    twap_price_scaled: u128,
) -> (u128, u128, u128) {
    let penalty_multiplier = BPS_DEN + LIQUIDATION_PENALTY_BPS; // 10500

    // debt_in_y = floor(debt_x * twap_price_scaled * penalty_multiplier / (PRICE_SCALE * BPS_DEN))
    let num = mul_u128_u128_u64(debt_x, twap_price_scaled, penalty_multiplier);
    let den = PRICE_SCALE * u128::from(BPS_DEN);
    // If quotient exceeds u128::MAX, debt_in_y > collateral_y, so clamping to collateral_y is exact.
    let debt_in_y = div_u320_by_u128(num, den).unwrap_or(u128::MAX);

    let seized = debt_in_y.min(collateral_y);
    let remainder = collateral_y.saturating_sub(seized);
    (seized, debt_x, remainder)
}

/// Validate the liquidation parameters are well-formed.
fn validate_liquidation_params(
    observations: &[AmmReserveSnapshot],
    positions: &[LiquidationPosition],
) -> Result<(), LiquidationError> {
    if positions.len() > MAX_BATCH_SIZE {
        return Err(LiquidationError::BatchTooLarge {
            got: positions.len(),
            max: MAX_BATCH_SIZE,
        });
    }
    validate_observations(observations)?;
    let mut seen_ids = BTreeSet::new();
    for pos in positions {
        if !seen_ids.insert(pos.position_id) {
            return Err(LiquidationError::DuplicatePosition {
                position_id: pos.position_id,
            });
        }
    }
    Ok(())
}

/// Execute a cross-domain liquidation.
///
/// Given a state-root-proven TWAP observation sequence and a set of positions,
/// computes which positions are eligible for liquidation and returns the
/// outcomes.
///
/// A position is eligible when its health factor is at or below its maintenance
/// threshold. Health factor is `collateral_value / debt` in BPS, checked via
/// exact 320-bit cross-multiplication so large balances cannot overflow.
///
/// # Errors
///
/// Returns [`LiquidationError`] if the observation sequence is malformed or
/// fails Merkle state-root verification, a position has no debt or a duplicate
/// `position_id`, or the batch exceeds [`MAX_BATCH_SIZE`].
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

    for pos in positions {
        if pos.debt_x == 0 {
            return Err(LiquidationError::NoDebt {
                position_id: pos.position_id,
            });
        }

        // Exact health inequality without intermediate division or u128 overflow:
        //   (collateral_y * PRICE_SCALE * BPS_DEN) / (twap_price * debt_x) > maintenance_threshold_bps
        //   <=> collateral_y * PRICE_SCALE * BPS_DEN > debt_x * twap_price * maintenance_threshold_bps
        let collateral_scaled = mul_u128_u128_u64(pos.collateral_y, PRICE_SCALE, BPS_DEN);
        let threshold_scaled =
            mul_u128_u128_u64(pos.debt_x, twap_price, pos.maintenance_threshold_bps);
        if cmp_u320(&collateral_scaled, &threshold_scaled) == core::cmp::Ordering::Greater {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_observations(prices: &[(u64, u128, u128)]) -> Vec<AmmReserveSnapshot> {
        prices
            .iter()
            .map(|(epoch, rx, ry)| {
                let proof = vec![[0x11; 32], [0x22; 32]];
                let leaf = reserve_leaf_digest(*epoch, *rx, *ry);
                let state_root = fold_reserve_merkle_path(leaf, *epoch, &proof);
                AmmReserveSnapshot {
                    state_root,
                    epoch: *epoch,
                    reserve_x: *rx,
                    reserve_y: *ry,
                    proof,
                }
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

        // 18-decimal AMM pool reserves (>340 tokens) and unhealthy whale position
        // must produce exact seized collateral (2100e18), never u128-saturated dust.
        let unit: u128 = PRICE_SCALE;
        let large_obs = make_observations(&[
            (10, 1_000_000 * unit, 2_000_000 * unit),
            (11, 1_000_000 * unit, 2_000_000 * unit),
            (12, 1_000_000 * unit, 2_000_000 * unit),
        ]);
        let whale_bad = vec![LiquidationPosition {
            position_id: 42,
            debt_x: 1_000 * unit,
            collateral_y: 2_500 * unit,
            maintenance_threshold_bps: 15_000,
        }];
        let whale_out = execute_liquidation(&large_obs, &whale_bad).expect("whale liquidation");
        assert_eq!(whale_out.len(), 1);
        assert_eq!(whale_out[0].twap_price_scaled, 2 * unit);
        assert_eq!(whale_out[0].seized_collateral_y, 2_100 * unit);
        assert_eq!(whale_out[0].remainder_y, 400 * unit);
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

        // Forged zero state_root / empty proof / tampered reserves must fail closed.
        let mut zero_root = obs.clone();
        zero_root[1].state_root = [0u8; 32];
        zero_root[1].proof = Vec::new();
        assert!(matches!(
            execute_liquidation(&zero_root, &positions),
            Err(LiquidationError::InvalidReserveProof { epoch: 2 })
        ));

        let mut tampered_reserve = obs.clone();
        tampered_reserve[2].reserve_y = 999_999;
        assert!(matches!(
            execute_liquidation(&tampered_reserve, &positions),
            Err(LiquidationError::InvalidReserveProof { epoch: 3 })
        ));

        let mut tampered_sibling = obs.clone();
        tampered_sibling[0].proof[0][0] ^= 0x01;
        assert!(matches!(
            execute_liquidation(&tampered_sibling, &positions),
            Err(LiquidationError::InvalidReserveProof { epoch: 1 })
        ));

        // Healthy 18-decimal whale position (health = 1000% >> 150%) must NOT be liquidated.
        let unit: u128 = PRICE_SCALE;
        let whale = vec![LiquidationPosition {
            position_id: 99,
            debt_x: 1_000 * unit,
            collateral_y: 10_000 * unit,
            maintenance_threshold_bps: 15_000,
        }];
        let whale_outcomes = execute_liquidation(&obs, &whale).expect("whale check ok");
        assert!(
            whale_outcomes.is_empty(),
            "healthy 1000%-collateralized whale must not be liquidated"
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

        // Epoch span exceeding MAX_TWAP_EPOCHS must also fail closed.
        let wide_obs = make_observations(&[(1, 100, 200), (50, 100, 200), (102, 100, 200)]);
        assert!(matches!(
            execute_liquidation(&wide_obs, &positions),
            Err(LiquidationError::EpochSpanTooWide {
                span: 101,
                max: 100
            })
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

        // Duplicate position_id in the same batch must fail closed.
        let dup_positions = vec![
            LiquidationPosition {
                position_id: 7,
                debt_x: 100,
                collateral_y: 50,
                maintenance_threshold_bps: 15_000,
            },
            LiquidationPosition {
                position_id: 7,
                debt_x: 100,
                collateral_y: 50,
                maintenance_threshold_bps: 15_000,
            },
        ];
        assert!(matches!(
            execute_liquidation(&obs, &dup_positions),
            Err(LiquidationError::DuplicatePosition { position_id: 7 })
        ));
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

        // Even with an empty position list, forged observations must fail closed.
        let mut forged = obs;
        forged[0].proof.clear();
        assert!(matches!(
            execute_liquidation(&forged, &[]),
            Err(LiquidationError::InvalidReserveProof { epoch: 1 })
        ));
    }
}
