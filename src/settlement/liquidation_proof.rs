//! `ProofCarryingLiquidation`: oracle-free AMM/TWAP state-root-proven
//! cross-domain liquidation engine.
//!
//! WIRING: unwired - oracle-free AMM/TWAP cross-domain liquidation proof
//! verifier awaits its dedicated settlement transaction door and RPC submission
//! endpoint in a subsequent integration step.
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
//!    (`x * y = k` constant product), TWAP'd over `MIN_TWAP_EPOCHS` with
//!    minimum geometric liquidity (`MIN_POOL_LIQUIDITY`) and bounded
//!    consecutive-observation price jumps (`MAX_CONSECUTIVE_PRICE_JUMP_BPS`)
//!    to resist dust-pool and sandwich manipulation.
//! 2. **Overflow-free 256-bit arithmetic (`O-H.5`)**: instantaneous prices,
//!    TWAP accumulation, health factors, and collateral seizure amounts use
//!    exact 256-bit (`U256`) multiply-divide arithmetic so 18-decimal (`1e18`)
//!    token amounts never saturate `u128`.
//! 3. **State-root provenance**: the AMM reserves used for pricing carry a
//!    Merkle proof that they exist in the canonical state root, all belonging
//!    to a single consistent AMM domain.
//! 4. **Collateral seize bounds**: when a position is strictly unhealthy
//!    (`health_bps < maintenance_threshold_bps`), seized collateral is
//!    clamped to available collateral across unique `(domain_id, asset_id)` legs.
//!
//! WIRING: used by the settlement domain to process cross-domain
//! liquidation transactions against positions backed by external collateral.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::domain::types::Hash32;

/// Minimum TWAP observation epochs. Prevents single-block manipulation
/// by requiring at least 3 distinct observations.
pub const MIN_TWAP_EPOCHS: u64 = 3;
/// Maximum TWAP observation epochs.
pub const MAX_TWAP_EPOCHS: u64 = 100;
/// Minimum elapsed epoch span (`last.epoch - first.epoch`) across a TWAP window.
pub const MIN_TWAP_EPOCH_SPAN: u64 = 2;
/// Minimum geometric AMM pool liquidity (`reserve_x * reserve_y >= MIN_POOL_LIQUIDITY^2`)
/// required so 1-wei dust pools cannot dictate liquidation TWAPs (`O-H.4`).
pub const MIN_POOL_LIQUIDITY: u128 = 50;
/// Maximum allowed instantaneous price ratio between two consecutive TWAP
/// observations in basis points (`50_000 bps` = `5.0x`, `O-H.4`).
pub const MAX_CONSECUTIVE_PRICE_JUMP_BPS: u64 = 50_000;
/// Liquidation penalty in basis points (5%).
pub const LIQUIDATION_PENALTY_BPS: u64 = 500;
/// BPS denominator.
const BPS_DEN: u64 = 10_000;
/// Fixed-point price scale (`1e18`).
const PRICE_SCALE: u128 = 1_000_000_000_000_000_000;
/// Maximum position count in a batch liquidation.
pub const MAX_BATCH_SIZE: usize = 64;
/// Maximum TWAP observations per position.
pub const MAX_OBSERVATIONS: usize = 128;

/// Exact 256-bit unsigned integer (`hi * 2^128 + lo`) for overflow-free
/// 18-decimal AMM price, TWAP, health-factor, and seizure calculations (`O-H.5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct U256 {
    hi: u128,
    lo: u128,
}

impl U256 {
    const ZERO: Self = Self { hi: 0, lo: 0 };

    const fn from_u128(v: u128) -> Self {
        Self { hi: 0, lo: v }
    }

    /// Exact 256-bit product `a * b` of two `u128` operands (never overflows).
    const fn mul_u128(a: u128, b: u128) -> Self {
        let mask64: u128 = 0xFFFF_FFFF_FFFF_FFFF;
        let a_lo = a & mask64;
        let a_hi = a >> 64;
        let b_lo = b & mask64;
        let b_hi = b >> 64;

        let p0 = a_lo * b_lo;
        let p1 = a_lo * b_hi;
        let p2 = a_hi * b_lo;
        let p3 = a_hi * b_hi;

        let mid1 = (p0 >> 64) + (p1 & mask64) + (p2 & mask64);
        let lo = (p0 & mask64) | ((mid1 & mask64) << 64);
        let hi = p3 + (p1 >> 64) + (p2 >> 64) + (mid1 >> 64);
        Self { hi, lo }
    }

    fn checked_add(self, rhs: Self) -> Option<Self> {
        let (lo, carry) = self.lo.overflowing_add(rhs.lo);
        let hi = self
            .hi
            .checked_add(rhs.hi)?
            .checked_add(u128::from(carry))?;
        Some(Self { hi, lo })
    }

    fn checked_mul_u128(self, rhs: u128) -> Option<Self> {
        if rhs == 0 || self == Self::ZERO {
            return Some(Self::ZERO);
        }
        let low_part = Self::mul_u128(self.lo, rhs);
        let high_part = Self::mul_u128(self.hi, rhs);
        if high_part.hi != 0 {
            return None;
        }
        let hi = low_part.hi.checked_add(high_part.lo)?;
        Some(Self {
            hi,
            lo: low_part.lo,
        })
    }

    fn shl1_with_bit(self, bit: u128) -> Self {
        let hi = (self.hi << 1) | (self.lo >> 127);
        let lo = (self.lo << 1) | (bit & 1);
        Self { hi, lo }
    }

    fn sub_assign(&mut self, rhs: Self) {
        let (lo, borrow) = self.lo.overflowing_sub(rhs.lo);
        let hi = self
            .hi
            .wrapping_sub(rhs.hi)
            .wrapping_sub(u128::from(borrow));
        self.lo = lo;
        self.hi = hi;
    }

    fn bit_at(self, bit_index: u32) -> u128 {
        if bit_index < 128 {
            (self.lo >> bit_index) & 1
        } else {
            (self.hi >> (bit_index - 128)) & 1
        }
    }

    fn set_bit(&mut self, bit_index: u32) {
        if bit_index < 128 {
            self.lo |= 1u128 << bit_index;
        } else {
            self.hi |= 1u128 << (bit_index - 128);
        }
    }

    /// Exact unsigned 256-bit floor division `self / divisor` (`None` iff `divisor == 0`).
    fn checked_div(self, divisor: Self) -> Option<Self> {
        if divisor == Self::ZERO {
            return None;
        }
        if self < divisor {
            return Some(Self::ZERO);
        }
        if self.hi == 0 && divisor.hi == 0 {
            return Some(Self::from_u128(self.lo / divisor.lo));
        }
        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;
        let mut bit = 256u32;
        while bit > 0 {
            bit -= 1;
            let b = self.bit_at(bit);
            // If `remainder`'s top bit (bit 255) was 1 before shifting, `2 * remainder + b >= 2^256 > divisor`.
            let overflow_256 = (remainder.hi >> 127) != 0;
            remainder = remainder.shl1_with_bit(b);
            if overflow_256 || remainder >= divisor {
                remainder.sub_assign(divisor);
                quotient.set_bit(bit);
            }
        }
        Some(quotient)
    }

    const fn to_u128_checked(self) -> Option<u128> {
        if self.hi == 0 {
            Some(self.lo)
        } else {
            None
        }
    }

    const fn to_u128_saturating(self) -> u128 {
        if self.hi == 0 {
            self.lo
        } else {
            u128::MAX
        }
    }
}

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
    /// Missing delivery proof, custody root, or TWAP pool/leg invariant violation.
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

/// Validate that a TWAP observation sequence is well-formed, carries minimum
/// geometric pool liquidity, spans at least `MIN_TWAP_EPOCH_SPAN` epochs, and
/// exhibits no extreme single-step sandwich jump (`O-H.4`).
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
        let Some(prev) = w.first() else {
            continue;
        };
        let Some(curr) = w.get(1) else {
            continue;
        };
        if curr.epoch <= prev.epoch {
            return Err(LiquidationError::NonMonotonicEpochs {
                prev: prev.epoch,
                current: curr.epoch,
            });
        }
    }
    if let (Some(first), Some(last)) = (observations.first(), observations.last()) {
        let span = last.epoch.saturating_sub(first.epoch);
        if span < MIN_TWAP_EPOCH_SPAN {
            return Err(LiquidationError::MissingProofAnchor(format!(
                "TWAP epoch window span {span} is below minimum {MIN_TWAP_EPOCH_SPAN}"
            )));
        }
        if span > MAX_TWAP_EPOCHS {
            return Err(LiquidationError::MissingProofAnchor(format!(
                "TWAP epoch window span {span} exceeds maximum {MAX_TWAP_EPOCHS}"
            )));
        }
    }
    let min_k = U256::mul_u128(MIN_POOL_LIQUIDITY, MIN_POOL_LIQUIDITY);
    let mut prev_price: Option<u128> = None;
    for obs in observations {
        if obs.reserve_x == 0 || obs.reserve_y == 0 {
            return Err(LiquidationError::ZeroReserve { epoch: obs.epoch });
        }
        let k = U256::mul_u128(obs.reserve_x, obs.reserve_y);
        if k < min_k {
            return Err(LiquidationError::MissingProofAnchor(format!(
                "insufficient AMM pool liquidity at epoch {}: sqrt(k) < {MIN_POOL_LIQUIDITY}",
                obs.epoch
            )));
        }
        let price = instant_price_scaled(obs.reserve_x, obs.reserve_y)?;
        if price == 0 {
            return Err(LiquidationError::PriceOverflow);
        }
        if let Some(prev) = prev_price {
            let (hi, lo) = if price >= prev {
                (price, prev)
            } else {
                (prev, price)
            };
            let max_allowed = U256::mul_u128(lo, u128::from(MAX_CONSECUTIVE_PRICE_JUMP_BPS))
                .checked_div(U256::from_u128(u128::from(BPS_DEN)))
                .unwrap_or(U256::ZERO);
            if U256::from_u128(hi) > max_allowed {
                return Err(LiquidationError::MissingProofAnchor(format!(
                    "excessive consecutive AMM price deviation at epoch {} (> {MAX_CONSECUTIVE_PRICE_JUMP_BPS} bps)",
                    obs.epoch
                )));
            }
        }
        prev_price = Some(price);
    }
    Ok(())
}

/// Compute the instantaneous price from a constant-product AMM using 256-bit
/// intermediate multiplication so 18-decimal reserves never overflow (`O-H.5`).
/// Returns price as `(reserve_y * 1e18) / reserve_x`.
fn instant_price_scaled(reserve_x: u128, reserve_y: u128) -> Result<u128, LiquidationError> {
    if reserve_x == 0 {
        return Err(LiquidationError::PriceOverflow);
    }
    let numerator = U256::mul_u128(reserve_y, PRICE_SCALE);
    let quotient = numerator
        .checked_div(U256::from_u128(reserve_x))
        .ok_or(LiquidationError::PriceOverflow)?;
    quotient
        .to_u128_checked()
        .ok_or(LiquidationError::PriceOverflow)
}

/// Compute the TWAP price from a sequence of AMM observations using 256-bit
/// weighted accumulation (`O-H.5`).
fn compute_twap_price(observations: &[AmmReserveSnapshot]) -> Result<u128, LiquidationError> {
    let mut weighted_sum = U256::ZERO;
    let mut total_duration: u128 = 0;

    for (i, obs) in observations.iter().enumerate() {
        if obs.reserve_x == 0 || obs.reserve_y == 0 {
            return Err(LiquidationError::ZeroReserve { epoch: obs.epoch });
        }
        let price = instant_price_scaled(obs.reserve_x, obs.reserve_y)?;
        let duration = observations.get(i + 1).map_or(1u128, |next| {
            u128::from(next.epoch.saturating_sub(obs.epoch))
        });
        let term = U256::mul_u128(price, duration);
        weighted_sum = weighted_sum
            .checked_add(term)
            .ok_or(LiquidationError::PriceOverflow)?;
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

    let avg = weighted_sum
        .checked_div(U256::from_u128(total_duration))
        .ok_or(LiquidationError::PriceOverflow)?;
    avg.to_u128_checked().ok_or(LiquidationError::PriceOverflow)
}

/// Exact 256-bit health factor in BPS:
/// `floor((collateral_y * 1e18 * 10_000) / (twap_price_scaled * debt_x))`.
fn compute_health_bps(collateral_y: u128, debt_x: u128, twap_price_scaled: u128) -> u64 {
    if debt_x == 0 || twap_price_scaled == 0 {
        return u64::MAX;
    }
    let scale_times_bps = PRICE_SCALE.saturating_mul(u128::from(BPS_DEN)); // 1e22 fits in u128
    let numerator = U256::mul_u128(collateral_y, scale_times_bps);
    let denominator = U256::mul_u128(twap_price_scaled, debt_x);
    let Some(q) = numerator.checked_div(denominator) else {
        return u64::MAX;
    };
    match q.to_u128_checked() {
        Some(v) => u64::try_from(v).unwrap_or(u64::MAX),
        None => u64::MAX,
    }
}

/// Exact 256-bit collateral seizure amount:
/// `min(collateral_y, floor((repay_debt_x * twap_price_scaled * (10_000 + bonus_bps)) / (1e18 * 10_000)))`.
fn compute_seize_amount_y(
    repay_debt_x: u128,
    collateral_y: u128,
    twap_price_scaled: u128,
    bonus_bps: u64,
) -> Result<u128, LiquidationError> {
    let bonus_mult = u128::from(BPS_DEN.saturating_add(bonus_bps));
    let scale_times_bps = PRICE_SCALE.saturating_mul(u128::from(BPS_DEN)); // 1e22 fits in u128
                                                                           // Evaluate `(repay_debt_x * twap_price_scaled)` in U256, then if `* bonus_mult` fits in U256
                                                                           // divide directly; otherwise divide `(repay_debt_x * bonus_mult)` first when that fits in u128.
    let base = U256::mul_u128(repay_debt_x, twap_price_scaled);
    let debt_in_y = if let Some(num) = base.checked_mul_u128(bonus_mult) {
        num.checked_div(U256::from_u128(scale_times_bps))
            .ok_or(LiquidationError::PriceOverflow)?
            .to_u128_saturating()
    } else {
        // Fallback when `repay_debt_x * twap_price_scaled * bonus_mult >= 2^256`:
        // divide `base` by `PRICE_SCALE` first (exact up to 1e-18), then multiply by `bonus_mult / BPS_DEN`.
        let scaled_down = base
            .checked_div(U256::from_u128(PRICE_SCALE))
            .ok_or(LiquidationError::PriceOverflow)?;
        scaled_down
            .checked_mul_u128(bonus_mult)
            .ok_or(LiquidationError::PriceOverflow)?
            .checked_div(U256::from_u128(u128::from(BPS_DEN)))
            .ok_or(LiquidationError::PriceOverflow)?
            .to_u128_saturating()
    };
    Ok(debt_in_y.min(collateral_y))
}

/// Compute the amount of collateral to seize for a batch liquidation.
/// Returns `(seized, debt_repaid, remainder)`.
fn compute_seized_collateral(
    debt_x: u128,
    collateral_y: u128,
    twap_price_scaled: u128,
) -> Result<(u128, u128, u128), LiquidationError> {
    let seized = compute_seize_amount_y(
        debt_x,
        collateral_y,
        twap_price_scaled,
        LIQUIDATION_PENALTY_BPS,
    )?;
    let remainder = collateral_y.saturating_sub(seized);
    Ok((seized, debt_x, remainder))
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
/// A position is eligible when its health factor is strictly below its
/// maintenance threshold (`health_bps < maintenance_threshold_bps`).
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

    for pos in positions {
        if pos.debt_x == 0 {
            return Err(LiquidationError::NoDebt {
                position_id: pos.position_id,
            });
        }

        let health_bps = compute_health_bps(pos.collateral_y, pos.debt_x, twap_price);
        if health_bps >= pos.maintenance_threshold_bps {
            // Position meets or exceeds its maintenance requirement, skip.
            continue;
        }

        let (seized, repaid, remainder) =
            compute_seized_collateral(pos.debt_x, pos.collateral_y, twap_price)?;

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
/// Returns [`LiquidationError`] if `position.debt_x == 0`, observations span
/// multiple AMM domains, any observation fails Merkle proof verification against
/// `certified_roots`, or the TWAP sequence is malformed.
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

    let mut expected_amm_domain: Option<u32> = None;
    let mut snapshots = Vec::with_capacity(observations.len());
    let mut obs_digests = Vec::with_capacity(observations.len());
    for obs in observations {
        if let Some(first_domain) = expected_amm_domain {
            if obs.domain_id != first_domain {
                return Err(LiquidationError::MissingProofAnchor(format!(
                    "TWAP observations mix distinct AMM source domains ({first_domain} vs {})",
                    obs.domain_id
                )));
            }
        } else {
            expected_amm_domain = Some(obs.domain_id);
        }
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

    let health_bps = compute_health_bps(position.collateral_y, position.debt_x, twap_price_scaled);
    let liquidatable = health_bps < position.maintenance_threshold_bps;

    let amm_domain_id = expected_amm_domain.unwrap_or(0);
    let observations_commitment =
        crate::unification::unification_merkle_root(b"BDLM_LIQ_OBSERVATIONS_V1", &obs_digests);
    let health_proof_digest = crate::core::hash::hash_fields_bytes(&[
        b"BDLM_LIQ_HEALTH_PROOF_V1",
        &position.position_id.to_le_bytes(),
        &debt_domain_id.to_le_bytes(),
        &amm_domain_id.to_le_bytes(),
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
/// Convenience: unified oracle-free cross-domain liquidation coordinator
/// combining state-root reserve provenance with close-factor and bonus bounds.
///
/// # Errors
///
/// Returns [`LiquidationError`] on any failed proof, health, bound, duplicate-leg, or anchor check.
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

    let mut seen_leg_keys = BTreeSet::new();
    let mut total_leg_collateral = 0u128;
    for leg in collateral_legs {
        if leg.custody_or_remote_root == [0u8; 32] {
            return Err(LiquidationError::MissingProofAnchor(format!(
                "collateral leg on domain {} missing non-zero custody/remote root",
                leg.domain_id
            )));
        }
        if !seen_leg_keys.insert((leg.domain_id, leg.asset_id)) {
            return Err(LiquidationError::MissingProofAnchor(format!(
                "duplicate collateral leg for domain {} and asset",
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

    let max_repay = U256::mul_u128(position.debt_x, u128::from(LIQ_CLOSE_FACTOR_MAX_BPS))
        .checked_div(U256::from_u128(u128::from(BPS_DEN)))
        .and_then(U256::to_u128_checked)
        .unwrap_or(position.debt_x)
        .max(1)
        .min(position.debt_x);
    if params.repay_debt_x == 0 || params.repay_debt_x > max_repay {
        return Err(LiquidationError::InvalidCloseAmount {
            requested: params.repay_debt_x,
            max_repay,
        });
    }

    let target_seize_y = compute_seize_amount_y(
        params.repay_debt_x,
        position.collateral_y,
        health.twap_price_scaled,
        params.bonus_bps,
    )?;

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
}
