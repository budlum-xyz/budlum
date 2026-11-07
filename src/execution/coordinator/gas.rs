//! Budlum Gas Unit (BGU) budgets, soft per-EE limits, and EIP-1559 fee split.
//!
//! Implements section 8.9 and section 11.3:
//! - Block limit: `60_000_000` BGU (TESTNET-DEFAULT).
//! - Soft per-environment limits: EVM `30_000_000`, WASM `24_000_000`,
//!   SVM `24_000_000`, Move `24_000_000` (`1 Move unit = 100 BGU`),
//!   BudZero `MAX_BLOCK_CONTRACT_GAS`.
//! - EIP-1559 base fee in attoBUD per BGU: 50% target (`30_000_000` BGU),
//!   max 12.5% (`1/8`) adjustment per block.
//! - Base fee split: 10% burned, 90% credited to the Network Security Pool
//!   (`reward_pool_account`). Priority fee: 100% credited to block proposer.

use crate::core::account::{AccountState, BudEnvUnit, ATTOS_PER_ATOM};
use crate::core::address::Address;
use crate::execution::zkvm::MAX_BLOCK_CONTRACT_GAS;
use crate::tokenomics::reward_pool::reward_pool_account;
use budlum_uel_abi::EeId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Hard block-wide BGU ceiling (section 8.9 item 2).
pub const BLOCK_BGU_LIMIT: u64 = 60_000_000;
/// Target block utilization (50% of `BLOCK_BGU_LIMIT`).
pub const TARGET_BLOCK_BGU: u64 = BLOCK_BGU_LIMIT / 2;
/// Maximum EIP-1559 base-fee step denominator (`1/8` = 12.5%).
pub const BASE_FEE_MAX_CHANGE_DENOM: u128 = 8;
/// Genesis floor for UEL base fee: 1,000,000 attoBUD/BGU (`10^-6` atom/BGU).
pub const MIN_UEL_BASE_FEE_ATTOS: u128 = 1_000_000;

/// Soft per-environment BGU limits within a single block (section 8.9 item 3).
pub const EVM_SOFT_BGU_LIMIT: u64 = 30_000_000;
pub const WASM_SOFT_BGU_LIMIT: u64 = 24_000_000;
pub const SVM_SOFT_BGU_LIMIT: u64 = 24_000_000;
pub const MOVE_SOFT_BGU_LIMIT: u64 = 24_000_000;

/// Initial native-unit to BGU conversion factor for Move (`1 unit = 100 BGU`).
pub const MOVE_GAS_TO_BGU: u64 = 100;

/// Returns the soft per-block BGU limit for environment `ee`.
#[must_use]
pub const fn soft_limit_for_ee(ee: EeId) -> Option<u64> {
    match ee {
        EeId::EVM => Some(EVM_SOFT_BGU_LIMIT),
        EeId::WASM => Some(WASM_SOFT_BGU_LIMIT),
        EeId::SVM => Some(SVM_SOFT_BGU_LIMIT),
        EeId::MOVE => Some(MOVE_SOFT_BGU_LIMIT),
        EeId::BUDZERO => Some(MAX_BLOCK_CONTRACT_GAS),
        _ => None,
    }
}

/// Converts environment-native gas units to BGU (section 8.9 item 3).
///
/// exposed for: UEL environment adapters and gas calibration (`WP-27`..`WP-35`).
pub fn native_gas_to_bgu(ee: EeId, native_units: u64) -> Result<u64, String> {
    match ee {
        EeId::EVM | EeId::WASM | EeId::SVM | EeId::BUDZERO => Ok(native_units),
        EeId::MOVE => native_units
            .checked_mul(MOVE_GAS_TO_BGU)
            .ok_or_else(|| String::from("Move gas to BGU conversion overflow")),
        other => Err(format!("unsupported execution environment 0x{:02x}", other.0)),
    }
}

/// Tracks cumulative BGU consumption across a block against both the hard
/// `60_000_000` ceiling and each environment's soft cap.
#[derive(Debug, Clone, Default)]
pub struct BlockBguMeter {
    total_used: u64,
    per_ee_used: BTreeMap<u8, u64>,
}

impl BlockBguMeter {
    /// Creates a fresh block BGU meter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total BGU consumed in the block so far.
    #[must_use]
    pub const fn total_used(&self) -> u64 {
        self.total_used
    }

    /// Checks whether a call in `ee` requesting up to `gas_limit_bgu` fits inside
    /// both `ee`'s soft cap and the block's hard `BLOCK_BGU_LIMIT`.
    pub fn check_admissible(&self, ee: EeId, gas_limit_bgu: u64) -> Result<(), String> {
        let soft = soft_limit_for_ee(ee)
            .ok_or_else(|| format!("unsupported execution environment 0x{:02x}", ee.0))?;
        let ee_used = self.per_ee_used.get(&ee.0).copied().unwrap_or(0);
        if ee_used.saturating_add(gas_limit_bgu) > soft {
            return Err(format!(
                "environment 0x{:02x} soft BGU limit {soft} exceeded ({ee_used} + {gas_limit_bgu})",
                ee.0
            ));
        }
        if self.total_used.saturating_add(gas_limit_bgu) > BLOCK_BGU_LIMIT {
            return Err(format!(
                "block BGU limit {BLOCK_BGU_LIMIT} exceeded ({} + {gas_limit_bgu})",
                self.total_used
            ));
        }
        Ok(())
    }

    /// Commits `gas_used_bgu` spent by a finalized transaction in `ee`.
    pub fn record_used(&mut self, ee: EeId, gas_used_bgu: u64) -> Result<(), String> {
        self.check_admissible(ee, gas_used_bgu)?;
        self.total_used = self.total_used.saturating_add(gas_used_bgu);
        let entry = self.per_ee_used.entry(ee.0).or_insert(0);
        *entry = entry.saturating_add(gas_used_bgu);
        Ok(())
    }
}

/// Computes the next block's UEL base fee in attoBUD per BGU (section 8.9 item 5).
#[must_use]
pub fn next_uel_base_fee_attos(current_base_fee_attos: u128, block_gas_used_bgu: u64) -> u128 {
    let base = current_base_fee_attos.max(MIN_UEL_BASE_FEE_ATTOS);
    let used = u128::from(block_gas_used_bgu.min(BLOCK_BGU_LIMIT));
    let target = u128::from(TARGET_BLOCK_BGU);
    if used == target {
        return base;
    }
    if used > target {
        let excess = used - target;
        let num = base.saturating_mul(excess);
        let den = target.saturating_mul(BASE_FEE_MAX_CHANGE_DENOM);
        let delta = (num / den).max(1);
        base.saturating_add(delta)
    } else {
        let deficit = target - used;
        let num = base.saturating_mul(deficit);
        let den = target.saturating_mul(BASE_FEE_MAX_CHANGE_DENOM);
        let delta = num / den;
        base.saturating_sub(delta).max(MIN_UEL_BASE_FEE_ATTOS)
    }
}

/// Effective priority fee per BGU (`min(max_priority_fee_per_bgu, max_fee_per_bgu - base_fee)`).
pub fn effective_priority_fee_attos(
    base_fee_attos: u128,
    max_fee_per_bgu_attos: u128,
    max_priority_fee_per_bgu_attos: u128,
) -> Result<u128, String> {
    let base = base_fee_attos.max(MIN_UEL_BASE_FEE_ATTOS);
    if max_fee_per_bgu_attos < base {
        return Err(format!(
            "max_fee_per_bgu ({max_fee_per_bgu_attos}) is below base_fee ({base})"
        ));
    }
    let headroom = max_fee_per_bgu_attos - base;
    Ok(max_priority_fee_per_bgu_attos.min(headroom))
}

/// Breakdown of settled UEL fees in attoBUD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UelFeeSettlement {
    pub gas_used_bgu: u64,
    pub burned_attos: u128,
    pub security_pool_attos: u128,
    pub proposer_tip_attos: u128,
}

/// Settles `gas_used_bgu` for `payer` against `state`:
/// - Base fee (`gas_used * base_fee`): 10% burned, 90% to `reward_pool_account()`.
/// - Priority fee (`gas_used * effective_tip`): 100% to `proposer`.
///
/// Whole burned atoms increment `state.burned_total`; sub-atom burned dust is
/// routed to `burn_reserve_address` when configured or else to `reward_pool_account()`
/// so `Account` balances never leak unaccounted fractional supply.
pub fn settle_uel_fee_attos(
    state: &mut AccountState,
    payer: &Address,
    proposer: &Address,
    gas_used_bgu: u64,
    base_fee_attos: u128,
    max_fee_per_bgu_attos: u128,
    max_priority_fee_per_bgu_attos: u128,
) -> Result<UelFeeSettlement, String> {
    let base = base_fee_attos.max(MIN_UEL_BASE_FEE_ATTOS);
    let tip = effective_priority_fee_attos(
        base,
        max_fee_per_bgu_attos,
        max_priority_fee_per_bgu_attos,
    )?;
    let gas = u128::from(gas_used_bgu);
    let base_total = gas
        .checked_mul(base)
        .ok_or_else(|| String::from("UEL base fee overflow"))?;
    let tip_total = gas
        .checked_mul(tip)
        .ok_or_else(|| String::from("UEL priority fee overflow"))?;
    let total_charge = base_total
        .checked_add(tip_total)
        .ok_or_else(|| String::from("UEL total fee overflow"))?;

    if state.spendable_attos(payer) < total_charge {
        return Err(format!(
            "insufficient spendable attoBUD for UEL fee: need {total_charge}"
        ));
    }

    let ten_percent = base_total / 10;
    let pool_share = base_total - ten_percent;
    let atom_q = u128::from(ATTOS_PER_ATOM);
    let whole_burn_atoms = u64::try_from(ten_percent / atom_q)
        .map_err(|_| String::from("UEL burn atom overflow"))?;
    let burn_dust_attos = ten_percent % atom_q;

    let pool_addr = reward_pool_account();
    let pool_plus_dust = if let Some(burn_reserve) = state.burn_reserve_address {
        if burn_dust_attos > 0 {
            state.transfer_attos_in_unit(
                payer,
                &burn_reserve,
                burn_dust_attos,
                BudEnvUnit::EvmWei,
            )?;
        }
        pool_share
    } else {
        pool_share.saturating_add(burn_dust_attos)
    };

    if pool_plus_dust > 0 {
        state.transfer_attos_in_unit(payer, &pool_addr, pool_plus_dust, BudEnvUnit::EvmWei)?;
    }
    if tip_total > 0 {
        state.transfer_attos_in_unit(payer, proposer, tip_total, BudEnvUnit::EvmWei)?;
    }
    if whole_burn_atoms > 0 {
        let exact_burn_attos = u128::from(whole_burn_atoms).saturating_mul(atom_q);
        let acct = state
            .accounts
            .get_mut(payer)
            .ok_or_else(|| String::from("payer account missing during burn"))?;
        let current = acct.checked_total_attos()?;
        let after = current
            .checked_sub(exact_burn_attos)
            .ok_or_else(|| String::from("payer attoBUD underflow during burn"))?;
        acct.set_from_total_attos(after)?;
        state.dirty_accounts.insert(*payer);
        state.burned_total = state.burned_total.saturating_add(whole_burn_atoms);
    }

    let burned_recorded = if state.burn_reserve_address.is_some() {
        ten_percent
    } else {
        u128::from(whole_burn_atoms).saturating_mul(atom_q)
    };
    Ok(UelFeeSettlement {
        gas_used_bgu,
        burned_attos: burned_recorded,
        security_pool_attos: base_total.saturating_sub(burned_recorded),
        proposer_tip_attos: tip_total,
    })
}
