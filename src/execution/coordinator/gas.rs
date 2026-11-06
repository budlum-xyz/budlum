//! Universal gas model (`BGU`) and EIP-1559 fee split for UEL execution.
//!
//! Section 8.9 defines a single consensus gas unit (`1 BGU`) across all five
//! execution environments, deterministic host-operation gas schedules, the
//! EIP-150 `63/64` cross-environment call stipend, and an exact integer
//! EIP-1559 fee split (50% base fee burned, 50% base fee to `reward_pool`,
//! 100% priority fee to the block proposer).

use std::fmt;

use budlum_uel_abi::{EeId, OutOfGas};

/// Maximum nesting depth for `universal_call` (`depth` 0..=8; `> 8` refused).
pub const MAX_UNIVERSAL_CALL_DEPTH: u32 = 8;

/// Target BGU per block for EIP-1559 elasticity (`15M BGU`).
///
/// Convenience: exposed for block producer gas accounting and fee updates.
pub const BLOCK_BGU_TARGET: u64 = 15_000_000;

/// Hard maximum BGU per block (`30M BGU`).
///
/// Convenience: exposed for block validation and coordinator admission.
pub const BLOCK_BGU_LIMIT: u64 = 30_000_000;

/// Hard maximum BGU per single transaction (`15M BGU`).
///
/// Convenience: exposed for mempool and coordinator transaction admission.
pub const TX_BGU_LIMIT: u64 = 15_000_000;

/// Base BGU cost of `HostRead::read`.
pub const BGU_READ_BASE: u64 = 200;
/// Additional BGU per 32-byte chunk read.
pub const BGU_READ_PER_32B: u64 = 3;

/// Base BGU cost of inserting a brand-new state key (`HostApi::write`).
pub const BGU_WRITE_NEW_BASE: u64 = 20_000;
/// Additional BGU per 32-byte chunk when inserting a new state key.
pub const BGU_WRITE_NEW_PER_32B: u64 = 640;

/// Base BGU cost of updating or deleting an existing state key.
pub const BGU_WRITE_UPDATE_BASE: u64 = 5_000;
/// Additional BGU per 32-byte chunk when updating an existing state key.
pub const BGU_WRITE_UPDATE_PER_32B: u64 = 160;

/// Base BGU cost of `HostApi::universal_call`.
pub const BGU_UNIVERSAL_CALL_BASE: u64 = 2_600;
/// Extra BGU on first access to a target contract in the transaction.
pub const BGU_UNIVERSAL_CALL_COLD_EXTRA: u64 = 2_500;
/// Extra BGU on warm access to a target contract in the transaction.
pub const BGU_UNIVERSAL_CALL_WARM_EXTRA: u64 = 100;

/// BGU cost of `HostApi::bud_transfer`.
pub const BGU_BUD_TRANSFER: u64 = 9_000;

/// Base BGU cost of `HostApi::emit_log`.
pub const BGU_LOG_BASE: u64 = 375;
/// Additional BGU per indexed log topic.
pub const BGU_LOG_PER_TOPIC: u64 = 375;
/// Additional BGU per byte of log payload.
pub const BGU_LOG_PER_BYTE: u64 = 8;

/// EIP-1559 maximum base-fee change denominator per block (`1/8 = 12.5%`).
const BASE_FEE_MAX_CHANGE_DENOM: u128 = 8;

/// Convert `native_units` of `ee`'s internal gas/fuel/cycle meter into `BGU`.
///
/// Convenience: exposed for EE adapters and coordinator gas accounting.
pub fn native_units_to_bgu(ee: EeId, native_units: u64) -> Result<u64, OutOfGas> {
    match ee {
        EeId::EVM | EeId::SVM | EeId::BUDZERO => Ok(native_units),
        EeId::WASM => Ok(native_units / 10 + u64::from(!native_units.is_multiple_of(10))),
        EeId::MOVE => native_units.checked_mul(100).ok_or(OutOfGas),
        _ => Err(OutOfGas),
    }
}

/// Number of 32-byte words needed to cover `byte_len` (ceiling division).
#[must_use]
pub const fn words_32(byte_len: usize) -> u64 {
    let n = byte_len as u64;
    n / 32 + (if n.is_multiple_of(32) { 0 } else { 1 })
}

/// Deterministic BGU cost of `HostRead::read` for `key_len + val_len` bytes.
#[must_use]
pub fn read_cost_bgu(key_len: usize, val_len: usize) -> u64 {
    let chunks = words_32(key_len.saturating_add(val_len));
    BGU_READ_BASE.saturating_add(chunks.saturating_mul(BGU_READ_PER_32B))
}

/// Deterministic BGU cost of `HostApi::write`.
#[must_use]
pub fn write_cost_bgu(is_new_key: bool, key_len: usize, val_len: usize) -> u64 {
    let chunks = words_32(key_len.saturating_add(val_len));
    if is_new_key {
        BGU_WRITE_NEW_BASE.saturating_add(chunks.saturating_mul(BGU_WRITE_NEW_PER_32B))
    } else {
        BGU_WRITE_UPDATE_BASE.saturating_mul(1).saturating_add(
            chunks.saturating_mul(BGU_WRITE_UPDATE_PER_32B),
        )
    }
}

/// Deterministic BGU cost of `HostApi::emit_log`.
#[must_use]
pub fn log_cost_bgu(topics: usize, data_len: usize) -> u64 {
    BGU_LOG_BASE
        .saturating_add((topics as u64).saturating_mul(BGU_LOG_PER_TOPIC))
        .saturating_add((data_len as u64).saturating_mul(BGU_LOG_PER_BYTE))
}

/// EIP-150 `63/64` stipend cap for `universal_call` (Section 8.7 item 4).
#[must_use]
pub const fn callee_gas_stipend(remaining_bgu: u64, requested_bgu: u64) -> u64 {
    let max_forward = remaining_bgu - (remaining_bgu / 64);
    if requested_bgu < max_forward {
        requested_bgu
    } else {
        max_forward
    }
}

/// Pure-integer EIP-1559 next-block base fee in attoBUD per BGU.
///
/// Convenience: exposed for block header base-fee updates on UEL gas usage.
#[must_use]
pub fn next_block_base_fee_atto(parent_base_fee_atto: u128, block_bgu_used: u64) -> u128 {
    let used = u128::from(block_bgu_used);
    let target = u128::from(BLOCK_BGU_TARGET);
    if used == target {
        return parent_base_fee_atto;
    }
    if used > target {
        let delta_gas = used - target;
        let num = parent_base_fee_atto.saturating_mul(delta_gas);
        let denom = target.saturating_mul(BASE_FEE_MAX_CHANGE_DENOM);
        let step = (num / denom).max(1);
        parent_base_fee_atto.saturating_add(step)
    } else {
        let delta_gas = target - used;
        let num = parent_base_fee_atto.saturating_mul(delta_gas);
        let denom = target.saturating_mul(BASE_FEE_MAX_CHANGE_DENOM);
        let step = num / denom;
        parent_base_fee_atto.saturating_sub(step).max(1)
    }
}

/// Exact attoBUD distribution of one UEL transaction's gas payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UelFeeSplit {
    /// Total attoBUD charged to the payer (`burned + reward_pool + proposer_tip`).
    pub total_charged_atto: u128,
    /// 50% of base fee burned permanently.
    pub burned_atto: u128,
    /// 50% of base fee routed to `reward_pool`.
    pub reward_pool_atto: u128,
    /// 100% of priority fee routed to the block proposer.
    pub proposer_tip_atto: u128,
}

/// Arithmetic refusal when computing a UEL fee split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GasFeeError {
    /// Fee multiplication overflowed `u128` or gas exceeded `TX_BGU_LIMIT`.
    OverflowOrLimitExceeded,
}

impl fmt::Display for GasFeeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverflowOrLimitExceeded => write!(f, "UEL gas fee overflow or tx limit exceeded"),
        }
    }
}

impl std::error::Error for GasFeeError {}

/// Compute the exact Section 8.9.3 EIP-1559 fee split in attoBUD:
/// 50% base fee burned, 50% base fee to `reward_pool`, 100% tip to proposer.
///
/// Convenience: called by coordinator settlement and fee-split audits.
pub fn settle_bgu_fee_split(
    bgu_used: u64,
    base_fee_atto: u128,
    priority_fee_atto: u128,
) -> Result<UelFeeSplit, GasFeeError> {
    if bgu_used > TX_BGU_LIMIT {
        return Err(GasFeeError::OverflowOrLimitExceeded);
    }
    let used = u128::from(bgu_used);
    let base_total = used
        .checked_mul(base_fee_atto)
        .ok_or(GasFeeError::OverflowOrLimitExceeded)?;
    let tip_total = used
        .checked_mul(priority_fee_atto)
        .ok_or(GasFeeError::OverflowOrLimitExceeded)?;
    let total = base_total
        .checked_add(tip_total)
        .ok_or(GasFeeError::OverflowOrLimitExceeded)?;

    let burned_atto = base_total / 2;
    let reward_pool_atto = base_total - burned_atto;
    Ok(UelFeeSplit {
        total_charged_atto: total,
        burned_atto,
        reward_pool_atto,
        proposer_tip_atto: tip_total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bgu_conversions_and_eip1559_fee_split_conserve_every_atto() {
        assert_eq!(native_units_to_bgu(EeId::EVM, 21_000).unwrap(), 21_000);
        assert_eq!(native_units_to_bgu(EeId::WASM, 25).unwrap(), 3);
        assert_eq!(native_units_to_bgu(EeId::SVM, 500).unwrap(), 500);
        assert_eq!(native_units_to_bgu(EeId::MOVE, 7).unwrap(), 700);
        assert_eq!(native_units_to_bgu(EeId::BUDZERO, 999).unwrap(), 999);

        assert_eq!(callee_gas_stipend(64_000, 100_000), 63_000);
        assert_eq!(callee_gas_stipend(64_000, 10_000), 10_000);

        // Odd base_total_atto still conserves burned + reward_pool == base_total.
        let split = settle_bgu_fee_split(21_001, 1_000_000_001, 50_000).unwrap();
        assert_eq!(
            split
                .burned_atto
                .checked_add(split.reward_pool_atto)
                .unwrap()
                .checked_add(split.proposer_tip_atto)
                .unwrap(),
            split.total_charged_atto
        );

        let base = 1_000_000_000u128;
        assert!(next_block_base_fee_atto(base, BLOCK_BGU_LIMIT) > base);
        assert!(next_block_base_fee_atto(base, 0) < base);
        assert_eq!(next_block_base_fee_atto(base, BLOCK_BGU_TARGET), base);
    }
}
