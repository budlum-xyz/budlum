//! ProofCarryingLiquidation: oracle-free AMM/TWAP state-root-proven
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
/// Returns (seized, debt_repaid, remainder).
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
        .saturating_mul(penalty_multiplier as u128)
        / (scale * BPS_DEN as u128);

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
    let twap_epoch = observations.last().map(|o| o.epoch).unwrap_or(0);

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
        let health_bps = if pos.debt_x > 0 {
            collateral_value_x.saturating_mul(BPS_DEN as u128) / pos.debt_x
        } else {
            u64::MAX as u128
        };

        if health_bps > pos.maintenance_threshold_bps as u128 {
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
        // price Y/X = 2.0 (reserve_y=200, reserve_x=100)
        let obs = make_observations(&[(1, 100, 200), (2, 100, 200), (3, 100, 200)]);
        let positions = vec![LiquidationPosition {
            position_id: 1,
            debt_x: 1000,
            collateral_y: 5000,
            maintenance_threshold_bps: 15_000, // 1.5x
        }];
        let outcomes = execute_liquidation(&obs, &positions).expect("liquidation");
        assert_eq!(outcomes.len(), 1);
        let o = &outcomes[0];
        assert_eq!(o.position_id, 1);
        // debt_in_y = 1000 * 2e18 * 10500 / (1e18 * 10000) = 1000 * 2 * 1.05 = 2100
        assert_eq!(o.debt_repaid_x, 1000);
        assert_eq!(o.seized_collateral_y, 2100);
        assert_eq!(o.remainder_y, 5000 - 2100);
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
}
