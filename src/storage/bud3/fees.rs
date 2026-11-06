//! Storage fees, the Custody Endowment, and per-epoch custody rewards.
//! exposed for `Bud3Registry`, `Bud3RpcService`, and fee estimation tools.
//!
//! Every stored object is priced strictly from its placed physical bytes
//! (`object_bytes * redundancy`), never from a recipe or zero-held-bytes
//! exemption. At registration (or lifetime renewal), 95% of the storage fee
//! enters the keyless Custody Endowment and 5% credits the upload gateway.
//! Across the paid lifetime of the object, each epoch unlocks
//! `remaining_endowment / remaining_epochs` and distributes it across confirmed,
//! passing custody shares in proportion to audited symbol bytes scaled by the
//! holder's presence ratio. Missed audit windows or declined content forfeit
//! that window's payout to the Network Security Pool without slashing stake and
//! without minting new supply.
//!
//! Convenience: pure quote helpers (`storage_fee_for_days`,
//! `shared_public_reference_fee_epochs`, `same_owner_sealed_dedup_fee`,
//! `replace_object_refund`) are also exposed for RPC and wallet callers.

use super::pipeline::ObjectRecord;
use super::placement::Share;
use crate::core::address::Address as ChainAddress;
use crate::core::hash::hash_fields_bytes;
use crate::tokenomics::reward_pool::reward_pool_account;
use crate::tokenomics::{epoch_storage_reward_share, BUD_UNIT};
use std::collections::BTreeMap;

/// Domain-separation tag for the keyless Custody Endowment account.
pub const CUSTODY_ENDOWMENT_TAG: &[u8] = b"BDLM_BUD3_CUSTODY_ENDOWMENT_V1";

/// Bytes in one GiB (`2^30`).
pub const GIB_BYTES: u128 = 1 << 30;

/// Days in one pricing year.
pub const DAYS_PER_YEAR: u128 = 365;

/// TESTNET-DEFAULT storage price `P_s`: `1 BUD / GiB / year` in base units.
pub const DEFAULT_PRICE_PER_GIB_YEAR_BUD: u64 = BUD_UNIT;

/// Minimum storage fee per paid storage action: `0.001 BUD` (`1_000` base units).
pub const MIN_STORAGE_FEE_BUD: u64 = BUD_UNIT / 1_000;

/// TESTNET-DEFAULT epochs per day (`86_400s / (3s * 50 slots) = 576`).
pub const DEFAULT_EPOCHS_PER_DAY: u64 = 576;

/// Basis-point denominator for fee splits.
pub const FEE_SPLIT_BPS_SCALE: u64 = 10_000;

/// Share of every storage fee deposited into the Custody Endowment (`95%`).
pub const ENDOWMENT_SHARE_BPS: u64 = 9_500;

/// Share of every storage fee paid to the upload gateway (`5%`).
pub const GATEWAY_SHARE_BPS: u64 = 500;

/// Parts-per-million scale for the validator presence multiplier (`0..=1_000_000`).
pub const PRESENCE_PPM_SCALE: u32 = 1_000_000;

const _: () = assert!(ENDOWMENT_SHARE_BPS + GATEWAY_SHARE_BPS == FEE_SPLIT_BPS_SCALE);
const _: () = assert!(MIN_STORAGE_FEE_BUD == 1_000);

/// Deterministic keyless account holding the Custody Endowment.
///
/// Convenience: exposed for RPC inspection and settlement verification.
#[must_use]
pub fn custody_endowment_account() -> ChainAddress {
    ChainAddress::from(hash_fields_bytes(&[CUSTODY_ENDOWMENT_TAG]))
}

/// Governance-tunable storage fee parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FeeParams {
    /// Price `P_s` in base units per GiB-year of `user_physical_bytes`.
    pub price_per_gib_year: u64,
    /// Minimum storage fee in base units (`0.001 BUD` on testnet).
    pub min_fee: u64,
    /// Epochs per pricing day (`576` on testnet).
    pub epochs_per_day: u64,
}

impl FeeParams {
    /// TESTNET-DEFAULT storage pricing schedule.
    pub const TESTNET_DEFAULT: Self = Self {
        price_per_gib_year: DEFAULT_PRICE_PER_GIB_YEAR_BUD,
        min_fee: MIN_STORAGE_FEE_BUD,
        epochs_per_day: DEFAULT_EPOCHS_PER_DAY,
    };
}

impl Default for FeeParams {
    fn default() -> Self {
        Self::TESTNET_DEFAULT
    }
}

/// Why a storage fee computation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeError {
    /// Physical bytes must be non-zero for a billable placement.
    ZeroPhysicalBytes,
    /// Paid lifetime must be at least one epoch / day.
    ZeroLifetime,
    /// Epochs-per-day parameter cannot be zero.
    ZeroEpochsPerDay,
    /// Reference count must be at least one when splitting a shared public object.
    ZeroReferences,
    /// Integer fee computation overflowed `u64`.
    ArithmeticOverflow,
}

/// Physical-byte accounting split between the user's minimum non-floored
/// redundancy and the extra redundancy added by the Mobile decentralization floor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FeeRecord {
    /// Physical bytes billed to the user (`object_bytes * min_redundancy`).
    pub user_physical_bytes: u64,
    /// Extra physical bytes induced by the Mobile decentralization floor and
    /// subsidized by the Network Security Pool.
    pub decentralization_physical_bytes: u64,
}

impl FeeRecord {
    /// Compute physical bytes from placed shares when all placed symbols belong
    /// to the user's baseline redundancy (`decentralization_physical_bytes = 0`).
    #[must_use]
    pub fn from_placed_shares(record: &ObjectRecord, shares: &[(u64, Share)]) -> Self {
        let symbol_bytes = u64::from(record.profile.symbol_size);
        let total = shares.iter().fold(0u64, |acc, (_, s)| {
            acc.saturating_add(u64::from(s.symbols).saturating_mul(symbol_bytes))
        });
        Self {
            user_physical_bytes: total,
            decentralization_physical_bytes: 0,
        }
    }

    /// Convenience: split placed physical bytes against the unfloored symbol
    /// count per segment so any Mobile-floor excess is recorded in
    /// `decentralization_physical_bytes`.
    #[must_use]
    pub fn with_unfloored_symbols(
        record: &ObjectRecord,
        shares: &[(u64, Share)],
        unfloored_symbols_per_segment: u64,
    ) -> Self {
        let symbol_bytes = u64::from(record.profile.symbol_size);
        let total_symbols = shares
            .iter()
            .fold(0u64, |acc, (_, s)| acc.saturating_add(u64::from(s.symbols)));
        let segments = record.symbol_roots.len() as u64;
        let baseline_symbols = segments
            .saturating_mul(unfloored_symbols_per_segment)
            .min(total_symbols);
        let floor_symbols = total_symbols.saturating_sub(baseline_symbols);
        Self {
            user_physical_bytes: baseline_symbols.saturating_mul(symbol_bytes),
            decentralization_physical_bytes: floor_symbols.saturating_mul(symbol_bytes),
        }
    }

    /// Total physical bytes held across all shares (`user + decentralization`).
    #[must_use]
    pub const fn total_physical_bytes(&self) -> u64 {
        self.user_physical_bytes
            .saturating_add(self.decentralization_physical_bytes)
    }
}

/// Exact 95% / 5% storage fee split between the Custody Endowment and upload gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FeeSplit {
    /// Total storage fee charged to the payer.
    pub total_fee: u64,
    /// 95% share credited to the Custody Endowment.
    pub endowment_share: u64,
    /// 5% share credited to the upload gateway.
    pub gateway_share: u64,
}

/// Split `total_fee` into 95% Custody Endowment and 5% upload gateway with zero
/// rounding loss (`endowment_share + gateway_share == total_fee`).
#[must_use]
pub const fn split_storage_fee(total_fee: u64) -> FeeSplit {
    let gateway_share =
        ((total_fee as u128) * (GATEWAY_SHARE_BPS as u128) / (FEE_SPLIT_BPS_SCALE as u128)) as u64;
    let endowment_share = total_fee.saturating_sub(gateway_share);
    FeeSplit {
        total_fee,
        endowment_share,
        gateway_share,
    }
}

/// Convenience: compute the storage fee for `user_physical_bytes` over `lifetime_days`:
/// `max(min_fee, ceil(user_physical_bytes * lifetime_days * P_s / (2^30 * 365)))`.
///
/// # Errors
///
/// Returns [`FeeError`] if `user_physical_bytes == 0`, `lifetime_days == 0`, or
/// the result overflows `u64`.
pub fn storage_fee_for_days(
    user_physical_bytes: u64,
    lifetime_days: u64,
    params: &FeeParams,
) -> Result<u64, FeeError> {
    if user_physical_bytes == 0 {
        return Err(FeeError::ZeroPhysicalBytes);
    }
    if lifetime_days == 0 {
        return Err(FeeError::ZeroLifetime);
    }
    let num = u128::from(user_physical_bytes)
        .checked_mul(u128::from(lifetime_days))
        .and_then(|v| v.checked_mul(u128::from(params.price_per_gib_year)))
        .ok_or(FeeError::ArithmeticOverflow)?;
    let den = GIB_BYTES * DAYS_PER_YEAR;
    let raw = u64::try_from(num.div_ceil(den)).map_err(|_| FeeError::ArithmeticOverflow)?;
    Ok(raw.max(params.min_fee))
}

/// Compute the storage fee for `user_physical_bytes` over `lifetime_epochs`:
/// `max(min_fee, ceil(user_physical_bytes * lifetime_epochs * P_s / (2^30 * 365 * epochs_per_day)))`.
///
/// When `lifetime_epochs == lifetime_days * epochs_per_day`, integer ceiling
/// division makes this identical to [`storage_fee_for_days`].
///
/// # Errors
///
/// Returns [`FeeError`] on zero inputs or integer overflow.
pub fn storage_fee_for_epochs(
    user_physical_bytes: u64,
    lifetime_epochs: u64,
    params: &FeeParams,
) -> Result<u64, FeeError> {
    if user_physical_bytes == 0 {
        return Err(FeeError::ZeroPhysicalBytes);
    }
    if lifetime_epochs == 0 {
        return Err(FeeError::ZeroLifetime);
    }
    if params.epochs_per_day == 0 {
        return Err(FeeError::ZeroEpochsPerDay);
    }
    let num = u128::from(user_physical_bytes)
        .checked_mul(u128::from(lifetime_epochs))
        .and_then(|v| v.checked_mul(u128::from(params.price_per_gib_year)))
        .ok_or(FeeError::ArithmeticOverflow)?;
    let den = (GIB_BYTES * DAYS_PER_YEAR)
        .checked_mul(u128::from(params.epochs_per_day))
        .ok_or(FeeError::ArithmeticOverflow)?;
    let raw = u64::try_from(num.div_ceil(den)).map_err(|_| FeeError::ArithmeticOverflow)?;
    Ok(raw.max(params.min_fee))
}

/// Convenience: compute a new NFT reference's share of a shared public object's
/// physical bytes (`ceil(user_physical_bytes / total_references_after_bind)`).
/// Earlier NFT holders receive no refund.
///
/// # Errors
///
/// Returns [`FeeError`] on zero inputs or overflow.
pub fn shared_public_reference_fee_epochs(
    total_user_physical_bytes: u64,
    total_references_after_bind: u64,
    remaining_epochs: u64,
    params: &FeeParams,
) -> Result<u64, FeeError> {
    if total_references_after_bind == 0 {
        return Err(FeeError::ZeroReferences);
    }
    if total_user_physical_bytes == 0 {
        return Err(FeeError::ZeroPhysicalBytes);
    }
    let share_bytes = total_user_physical_bytes.div_ceil(total_references_after_bind);
    storage_fee_for_epochs(share_bytes, remaining_epochs, params)
}

/// Convenience: second and subsequent bindings by the same owner to the same
/// sealed content incur zero additional storage fee.
#[must_use]
pub const fn same_owner_sealed_dedup_fee() -> u64 {
    0
}

/// Compute the storage fee for `RenewObject` over `extra_epochs` using the
/// exact physical-byte formula.
///
/// # Errors
///
/// Returns [`FeeError`] on zero inputs or overflow.
pub fn renewal_fee_epochs(
    user_physical_bytes: u64,
    extra_epochs: u64,
    params: &FeeParams,
) -> Result<u64, FeeError> {
    storage_fee_for_epochs(user_physical_bytes, extra_epochs, params)
}

/// Convenience: replacing or burning an object never refunds prior storage fees;
/// any unspent difference stays with the Custody Endowment / Network Security Pool.
#[must_use]
pub const fn replace_object_refund() -> u64 {
    0
}

/// Per-object Custody Endowment state tracked inside `Bud3Registry`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObjectEndowment {
    /// Physical-byte breakdown recorded for this object.
    pub fee_record: FeeRecord,
    /// Cumulative 95% endowment deposits from registration, shared bindings, and renewals.
    pub total_deposited: u64,
    /// Undistributed endowment balance remaining for future epochs.
    pub remaining_balance: u64,
    /// Cumulative 5% gateway fees booked for this object.
    pub gateway_paid: u64,
    /// Cumulative missed-audit / declined-share rewards forfeited to the Network Security Pool.
    pub forfeited_to_security_pool: u64,
}

impl ObjectEndowment {
    /// Create a fresh endowment record from a `FeeRecord` and its initial `FeeSplit`.
    #[must_use]
    pub const fn new(fee_record: FeeRecord, split: FeeSplit) -> Self {
        Self {
            fee_record,
            total_deposited: split.endowment_share,
            remaining_balance: split.endowment_share,
            gateway_paid: split.gateway_share,
            forfeited_to_security_pool: 0,
        }
    }

    /// Top up an existing object endowment (on renewal or shared public NFT bind).
    pub fn deposit(&mut self, split: FeeSplit) {
        self.total_deposited = self.total_deposited.saturating_add(split.endowment_share);
        self.remaining_balance = self.remaining_balance.saturating_add(split.endowment_share);
        self.gateway_paid = self.gateway_paid.saturating_add(split.gateway_share);
    }
}

/// Per-share input to epoch custody reward settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareRewardInput {
    /// Validator owner address holding the share.
    pub validator: [u8; 32],
    /// Placed symbol bytes in this share (`symbols * profile.symbol_size`).
    pub symbol_bytes: u64,
    /// True iff the share is confirmed, not lost, not declined, and passed its audit window.
    pub eligible: bool,
    /// Validator presence ratio for the epoch in parts per million (`0..=1_000_000`).
    pub presence_ppm: u32,
}

/// Deterministic outcome of settling custody rewards for an epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochCustodySettlement {
    /// Base units earned by each eligible share holder (`validator -> amount`).
    pub holder_payouts: BTreeMap<[u8; 32], u64>,
    /// Unpaid endowment base units forfeited to the Network Security Pool.
    pub forfeited_to_security_pool: u64,
    /// Keyless Network Security Pool recipient for forfeited amounts.
    pub security_pool_account: ChainAddress,
    /// 50% custody budget read from the Network Security Pool epoch budget `P_e`.
    pub pool_storage_budget: u64,
}

/// Settle one epoch of an object's Custody Endowment across its shares.
///
/// Unlocks `remaining_balance / max(1, remaining_epochs)` out of `endowment`.
/// Each eligible share earns `floor(epoch_unlock * (symbol_bytes * presence_ppm) /
/// (total_symbol_bytes * 1_000_000))`. Unpaid shares (missed audit, unconfirmed,
/// lost, declined, or reduced presence) never slash stake; their unpaid portion
/// is routed to `reward_pool_account()` so `sum(holder_payouts) + forfeited == epoch_unlock`
/// and zero supply is created or destroyed.
pub fn distribute_object_endowment_epoch(
    endowment: &mut ObjectEndowment,
    remaining_epochs: u64,
    shares: &[ShareRewardInput],
    epoch_pool_budget: u64,
) -> EpochCustodySettlement {
    let denom_epochs = remaining_epochs.max(1);
    let epoch_unlock = endowment.remaining_balance / denom_epochs;
    endowment.remaining_balance = endowment.remaining_balance.saturating_sub(epoch_unlock);

    let mut holder_payouts: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    let total_symbol_bytes = shares
        .iter()
        .fold(0u128, |acc, s| acc.saturating_add(u128::from(s.symbol_bytes)));
    let total_weight = total_symbol_bytes.saturating_mul(u128::from(PRESENCE_PPM_SCALE));

    let mut paid_total = 0u64;
    if epoch_unlock > 0 && total_weight > 0 {
        for share in shares {
            if !share.eligible || share.symbol_bytes == 0 {
                continue;
            }
            let presence = u128::from(share.presence_ppm.min(PRESENCE_PPM_SCALE));
            if presence == 0 {
                continue;
            }
            let share_weight = u128::from(share.symbol_bytes).saturating_mul(presence);
            let payout_u128 =
                u128::from(epoch_unlock).saturating_mul(share_weight) / total_weight;
            let payout = u64::try_from(payout_u128).unwrap_or(0);
            if payout > 0 {
                let entry = holder_payouts.entry(share.validator).or_insert(0);
                *entry = entry.saturating_add(payout);
                paid_total = paid_total.saturating_add(payout);
            }
        }
    }

    let forfeited = epoch_unlock.saturating_sub(paid_total);
    endowment.forfeited_to_security_pool = endowment
        .forfeited_to_security_pool
        .saturating_add(forfeited);

    EpochCustodySettlement {
        holder_payouts,
        forfeited_to_security_pool: forfeited,
        security_pool_account: reward_pool_account(),
        pool_storage_budget: epoch_storage_reward_share(epoch_pool_budget),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_gib_for_one_year_costs_one_bud_and_tiny_objects_pay_minimum() {
        let params = FeeParams::TESTNET_DEFAULT;
        let one_gib = 1u64 << 30;
        let fee_year = storage_fee_for_days(one_gib, 365, &params).unwrap();
        assert_eq!(fee_year, BUD_UNIT);

        let fee_epochs =
            storage_fee_for_epochs(one_gib, 365 * params.epochs_per_day, &params).unwrap();
        assert_eq!(fee_epochs, BUD_UNIT);

        // A 4 KiB object for 30 days rounds below 0.001 BUD, so the 0.001 BUD floor applies.
        let tiny = storage_fee_for_days(4096, 30, &params).unwrap();
        assert_eq!(tiny, MIN_STORAGE_FEE_BUD);
        assert_eq!(tiny, 1_000);
    }

    #[test]
    fn zero_bytes_or_zero_lifetime_refuses() {
        let params = FeeParams::TESTNET_DEFAULT;
        assert_eq!(
            storage_fee_for_days(0, 30, &params),
            Err(FeeError::ZeroPhysicalBytes)
        );
        assert_eq!(
            storage_fee_for_days(1024, 0, &params),
            Err(FeeError::ZeroLifetime)
        );
        assert_eq!(
            storage_fee_for_epochs(0, 100, &params),
            Err(FeeError::ZeroPhysicalBytes)
        );
        assert_eq!(
            storage_fee_for_epochs(1024, 0, &params),
            Err(FeeError::ZeroLifetime)
        );
    }

    #[test]
    fn fee_split_is_exact_ninety_five_five_with_zero_loss() {
        for total in [1_000u64, 1_001, 19_999, 1_000_000, u64::MAX / 2] {
            let split = split_storage_fee(total);
            assert_eq!(split.endowment_share + split.gateway_share, total);
        }
        let one_bud = split_storage_fee(BUD_UNIT);
        assert_eq!(one_bud.endowment_share, 950_000);
        assert_eq!(one_bud.gateway_share, 50_000);
    }

    #[test]
    fn shared_public_object_splits_physical_bytes_and_sealed_dedup_is_free() {
        let params = FeeParams::TESTNET_DEFAULT;
        let two_gib = 2u64 << 30;
        let full_year_epochs = 365 * params.epochs_per_day;
        // Second NFT binding to a 2 GiB public object pays for 1 GiB (ceil(2 GiB / 2)).
        let second_nft_fee =
            shared_public_reference_fee_epochs(two_gib, 2, full_year_epochs, &params).unwrap();
        assert_eq!(second_nft_fee, BUD_UNIT);
        assert_eq!(same_owner_sealed_dedup_fee(), 0);
        assert_eq!(replace_object_refund(), 0);
    }

    #[test]
    fn endowment_epoch_distribution_pays_passing_shares_and_forfeits_missed_to_pool() {
        let split = split_storage_fee(1_000_000);
        let mut endowment = ObjectEndowment::new(
            FeeRecord {
                user_physical_bytes: 30_000,
                decentralization_physical_bytes: 0,
            },
            split,
        );
        // 10 epochs lifetime -> 95_000 unlocked on epoch 1.
        // Holder 1 holds 20_000 bytes and passed; Holder 2 holds 10_000 bytes and missed audit.
        let shares = [
            ShareRewardInput {
                validator: [1u8; 32],
                symbol_bytes: 20_000,
                eligible: true,
                presence_ppm: PRESENCE_PPM_SCALE,
            },
            ShareRewardInput {
                validator: [2u8; 32],
                symbol_bytes: 10_000,
                eligible: false,
                presence_ppm: PRESENCE_PPM_SCALE,
            },
        ];
        let settlement = distribute_object_endowment_epoch(&mut endowment, 10, &shares, 100 * BUD_UNIT);
        let paid_h1 = *settlement.holder_payouts.get(&[1u8; 32]).unwrap();
        assert!(!settlement.holder_payouts.contains_key(&[2u8; 32]));
        // 95_000 * 2 / 3 = 63_333; forfeited = 95_000 - 63_333 = 31_667.
        assert_eq!(paid_h1, 63_333);
        assert_eq!(settlement.forfeited_to_security_pool, 31_667);
        assert_eq!(paid_h1 + settlement.forfeited_to_security_pool, 95_000);
        assert_eq!(settlement.security_pool_account, reward_pool_account());
        assert_eq!(settlement.pool_storage_budget, 50 * BUD_UNIT);
    }

    #[test]
    fn endowment_drains_completely_over_full_lifetime() {
        let mut endowment = ObjectEndowment::new(
            FeeRecord {
                user_physical_bytes: 10_000,
                decentralization_physical_bytes: 0,
            },
            split_storage_fee(12_345),
        );
        let initial = endowment.remaining_balance;
        let shares = [ShareRewardInput {
            validator: [9u8; 32],
            symbol_bytes: 10_000,
            eligible: true,
            presence_ppm: PRESENCE_PPM_SCALE,
        }];
        let mut accounted = 0u64;
        for rem in (1..=7u64).rev() {
            let s = distribute_object_endowment_epoch(&mut endowment, rem, &shares, 0);
            let paid: u64 = s.holder_payouts.values().copied().sum();
            accounted += paid + s.forfeited_to_security_pool;
        }
        assert_eq!(endowment.remaining_balance, 0);
        assert_eq!(accounted, initial);
    }
}
