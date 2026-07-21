//! Phase 11.8 — EIP-1559-style fee market primitives.
//!
//! This module is intentionally pure: the functions here do not mutate chain
//! state. Block production / executor wiring can call these helpers and keep the
//! consensus-critical arithmetic covered by small deterministic unit tests.

use serde::{Deserialize, Serialize};

/// Default target gas for a block (Phase 11.6 EIP-1559 spec).
pub const DEFAULT_TARGET_GAS: u64 = 10_000_000;
/// EIP-1559 maximum base-fee delta denominator: 1/8 = 12.5% per block.
pub const DEFAULT_BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8;
pub const DEFAULT_ELASTICITY_MULTIPLIER: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeMarketParams {
    pub target_gas: u64,
    pub elasticity_multiplier: u64,
    pub base_fee_max_change_denominator: u64,
    pub min_base_fee: u64,
}

impl Default for FeeMarketParams {
    fn default() -> Self {
        Self {
            target_gas: DEFAULT_TARGET_GAS,
            elasticity_multiplier: DEFAULT_ELASTICITY_MULTIPLIER,
            base_fee_max_change_denominator: DEFAULT_BASE_FEE_MAX_CHANGE_DENOMINATOR,
            min_base_fee: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeBid {
    /// Legacy fee or max total fee cap per gas unit.
    pub max_fee: u64,
    /// Validator/proposer tip cap per gas unit.
    pub priority_fee: u64,
}

impl FeeBid {
    /// Backward-compatible migration for legacy `Transaction::fee`.
    pub const fn legacy(fee: u64) -> Self {
        Self {
            max_fee: fee,
            priority_fee: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveFee {
    pub base_fee_burned: u64,
    pub priority_fee_paid: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeeError {
    MaxFeeBelowBaseFee { max_fee: u64, base_fee: u64 },
    InvalidParams,
}

/// Compute next block base fee using EIP-1559 bounded adjustment.
///
/// The return value is clamped to `min_base_fee`; invalid zero-valued params are
/// treated fail-closed by returning the parent fee unchanged but not below the
/// minimum.
pub fn next_base_fee(parent_base_fee: u64, parent_gas_used: u64, params: FeeMarketParams) -> u64 {
    if params.target_gas == 0 || params.base_fee_max_change_denominator == 0 {
        return parent_base_fee.max(params.min_base_fee);
    }

    let parent = parent_base_fee as i128;
    let gas_delta = parent_gas_used as i128 - params.target_gas as i128;
    let denom = params.target_gas as i128 * params.base_fee_max_change_denominator as i128;
    let adjustment = parent.saturating_mul(gas_delta) / denom.max(1);
    let next = parent
        .saturating_add(adjustment)
        .max(params.min_base_fee as i128);
    next.min(u64::MAX as i128) as u64
}

/// Split a fee bid into burned base fee and proposer priority fee.
///
/// A bid that cannot cover the block base fee is rejected. This is the key
/// semantic difference from `min(max_fee, base_fee)`, which would silently accept
/// underpriced transactions and weaken the base-fee mechanism.
pub fn effective_fee(bid: FeeBid, block_base_fee: u64) -> Result<EffectiveFee, FeeError> {
    if bid.max_fee < block_base_fee {
        return Err(FeeError::MaxFeeBelowBaseFee {
            max_fee: bid.max_fee,
            base_fee: block_base_fee,
        });
    }
    let tip_cap = bid.max_fee.saturating_sub(block_base_fee);
    Ok(EffectiveFee {
        base_fee_burned: block_base_fee,
        priority_fee_paid: bid.priority_fee.min(tip_cap),
    })
}

/// Full fee distribution: base fee burn + proposer tip + treasury split.
///
/// `treasury_rate` is a fraction in parts-per-million (ppm): e.g. 10_000 = 1%.
/// The treasury takes a cut of the priority fee before the proposer receives
/// the remainder. This makes the burn/treasury/proposer split explicit and
/// auditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeDistribution {
    pub base_fee_burned: u64,
    pub priority_fee_to_proposer: u64,
    pub treasury_fee: u64,
}

/// Distribute a fee bid into burn / proposer / treasury.
///
/// `gas_used` is the actual gas consumed by the transaction.
/// `treasury_rate_ppm` is the treasury cut in parts-per-million (0 = no treasury).
pub fn distribute_fee(
    bid: FeeBid,
    block_base_fee: u64,
    gas_used: u64,
    treasury_rate_ppm: u64,
) -> Result<FeeDistribution, FeeError> {
    let effective = effective_fee(bid, block_base_fee)?;

    let base_fee_burned = block_base_fee.saturating_mul(gas_used);
    let total_priority = effective.priority_fee_paid.saturating_mul(gas_used);

    // Treasury cut (saturating to prevent overflow)
    let treasury_fee = total_priority
        .saturating_mul(treasury_rate_ppm)
        .saturating_div(1_000_000);

    let priority_fee_to_proposer = total_priority.saturating_sub(treasury_fee);

    Ok(FeeDistribution {
        base_fee_burned,
        priority_fee_to_proposer,
        treasury_fee,
    })
}

/// Default treasury rate: 1% (10_000 ppm).
pub const DEFAULT_TREASURY_RATE_PPM: u64 = 10_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase11_8_base_fee_increase_is_bounded() {
        let params = FeeMarketParams::default();
        let next = next_base_fee(800, params.target_gas * 2, params);
        assert_eq!(next, 900, "full block raises by 12.5%");
    }

    #[test]
    fn phase11_8_base_fee_decrease_is_bounded() {
        let params = FeeMarketParams::default();
        let next = next_base_fee(800, 0, params);
        assert_eq!(next, 700, "empty block lowers by 12.5%");
    }

    #[test]
    fn phase11_8_min_base_fee_is_respected() {
        let params = FeeMarketParams {
            min_base_fee: 10,
            ..Default::default()
        };
        assert_eq!(next_base_fee(10, 0, params), 10);
    }

    #[test]
    fn phase11_8_max_fee_below_base_fee_rejected() {
        let err = effective_fee(
            FeeBid {
                max_fee: 9,
                priority_fee: 1,
            },
            10,
        )
        .unwrap_err();
        assert_eq!(
            err,
            FeeError::MaxFeeBelowBaseFee {
                max_fee: 9,
                base_fee: 10,
            }
        );
    }

    #[test]
    fn phase11_8_effective_tip_cannot_exceed_priority_or_cap() {
        let fee = effective_fee(
            FeeBid {
                max_fee: 15,
                priority_fee: 10,
            },
            10,
        )
        .unwrap();
        assert_eq!(fee.base_fee_burned, 10);
        assert_eq!(fee.priority_fee_paid, 5);

        let fee = effective_fee(
            FeeBid {
                max_fee: 30,
                priority_fee: 7,
            },
            10,
        )
        .unwrap();
        assert_eq!(fee.priority_fee_paid, 7);
    }

    #[test]
    fn phase11_8_legacy_fee_maps_to_zero_tip() {
        let fee = effective_fee(FeeBid::legacy(10), 10).unwrap();
        assert_eq!(fee.base_fee_burned, 10);
        assert_eq!(fee.priority_fee_paid, 0);
    }

    #[test]
    fn phase11_8_fee_distribution_burns_base_fee_and_pays_proposer() {
        let bid = FeeBid {
            max_fee: 15,
            priority_fee: 5,
        };
        let dist = distribute_fee(bid, 10, 1_000, 0).unwrap();
        assert_eq!(dist.base_fee_burned, 10_000); // 10 * 1_000
        assert_eq!(dist.priority_fee_to_proposer, 5_000); // 5 * 1_000
        assert_eq!(dist.treasury_fee, 0); // no treasury
    }

    #[test]
    fn phase11_8_fee_distribution_treasury_split_is_deterministic() {
        let bid = FeeBid {
            max_fee: 20,
            priority_fee: 10,
        };
        // 1% treasury rate (10_000 ppm)
        let dist = distribute_fee(bid, 10, 1_000, 10_000).unwrap();
        assert_eq!(dist.base_fee_burned, 10_000);
        assert_eq!(dist.treasury_fee, 100); // 1% of 10_000
        assert_eq!(dist.priority_fee_to_proposer, 9_900); // 99% of 10_000
    }

    #[test]
    fn phase11_8_fee_distribution_rejects_underpriced() {
        let bid = FeeBid {
            max_fee: 5,
            priority_fee: 1,
        };
        let err = distribute_fee(bid, 10, 1_000, 0).unwrap_err();
        assert_eq!(
            err,
            FeeError::MaxFeeBelowBaseFee {
                max_fee: 5,
                base_fee: 10,
            }
        );
    }

    #[test]
    fn phase11_8_fee_distribution_zero_treasury_rate() {
        let bid = FeeBid {
            max_fee: 15,
            priority_fee: 5,
        };
        let dist = distribute_fee(bid, 10, 1_000, 0).unwrap();
        assert_eq!(dist.treasury_fee, 0);
        assert_eq!(dist.priority_fee_to_proposer, 5_000);
    }

    #[test]
    fn phase11_8_fee_distribution_large_fee_exercises_treasury() {
        // Large priority_fee so treasury cut is non-zero (integer floor)
        // max_fee must cover base_fee + priority_fee: 10 + 1_000_000 = 1_000_010
        let bid = FeeBid {
            max_fee: 1_000_010,
            priority_fee: 1_000_000,
        };
        let dist = distribute_fee(bid, 10, 1, 10_000).unwrap();
        assert_eq!(dist.base_fee_burned, 10);
        assert_eq!(dist.treasury_fee, 10_000); // 1% of 1_000_000
        assert_eq!(dist.priority_fee_to_proposer, 990_000);
    }

    #[test]
    fn phase11_8_fee_distribution_full_treasury_rate() {
        let bid = FeeBid {
            max_fee: 15,
            priority_fee: 5,
        };
        // 100% treasury rate (1_000_000 ppm)
        let dist = distribute_fee(bid, 10, 1_000, 1_000_000).unwrap();
        assert_eq!(dist.treasury_fee, 5_000);
        assert_eq!(dist.priority_fee_to_proposer, 0);
    }
}
