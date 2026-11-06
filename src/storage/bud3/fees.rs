//! The storage fee and the endowment (section 6.18 and 11.5).
//!
//! `fee = ceil(user_physical_bytes x lifetime_days x P_s / (2^30 x 365))`,
//! with `P_s` = 1 BUD per GiB per year of physical bytes (TESTNET-DEFAULT), a
//! floor of 0.001 BUD, 95 percent to the endowment and 5 percent to the
//! uploading gateway.
//!
//! # Physical bytes, not content bytes
//!
//! The input is the object's **physical** bytes: the BOF-1 object length, not
//! the content length. A codec that halves the payload halves the network's
//! bill, and a sealed object pays for its padding because the padding is what
//! a validator holds. `user_physical_bytes` and
//! `decentralization_physical_bytes` (the extra bytes the mobile floor of
//! section 6.9.5 adds) are separate inputs, because only the first one is the
//! payer's bill (WP-25 item 4).
//!
//! # Conservation
//!
//! Every split is a partition of the paid amount with the remainder assigned
//! once, so `endowment + gateway == fee` exactly and no wei is invented or
//! lost. [`FeeSplit::conserves`] states it, and the tests assert it for a
//! range of inputs rather than one.
//!
//! # Units
//!
//! BUD has 6 decimals in this tree (`tokenomics::BUD_UNIT` = 1e6). The
//! formula is stated in whole BUD, so a fractional result is rounded **up**
//! to the next base unit: a fee that rounds to zero would be free storage the
//! validator still has to serve and answer audits for (the lesson of
//! `storage_priced`).
//!
//! WIRING: unwired - the block executor charges it once `StorageTx` v3
//! `RegisterObject` takes its fee (WP-25 lands with the endowment account);
//! until then the arithmetic is exercised by its tests.

use super::limits::GIB;
use crate::tokenomics::BUD_UNIT;

/// Base units in one whole BUD.
pub const BUD_BASE_UNITS: u128 = BUD_UNIT as u128;

/// Days in the pricing year of the formula.
pub const DAYS_PER_YEAR: u128 = 365;

/// `P_s`: base units of one physical GiB held for one year, TESTNET-DEFAULT.
/// 1 BUD = `BUD_UNIT` base units.
pub const PHYSICAL_GIB_YEAR_UNITS: u128 = BUD_BASE_UNITS;

/// The floor of section 11.5 item 3: 0.001 BUD.
pub const MIN_FEE_UNITS: u128 = BUD_BASE_UNITS / 1_000;

/// The endowment's share, in percent (item 4).
pub const ENDOWMENT_SHARE_PERCENT: u128 = 95;

/// The uploading gateway's share, in percent (item 6).
pub const GATEWAY_SHARE_PERCENT: u128 = 5;

/// Refusal of the pricing step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeError {
    /// The lifetime is outside the admitted range, or zero.
    LifetimeOutOfRange {
        /// The days asked for.
        days: u32,
    },
    /// The physical byte count does not fit the arithmetic.
    Overflow,
}

/// A priced upload: what the payer owes and how it splits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSplit {
    /// The whole fee in base units.
    pub total: u128,
    /// The endowment's part, 95 percent.
    pub endowment: u128,
    /// The gateway's part, 5 percent.
    pub gateway: u128,
    /// The physical bytes the fee was computed from.
    pub physical_bytes: u64,
    /// The lifetime in days.
    pub lifetime_days: u32,
}

impl FeeSplit {
    /// Whether the split is a partition of the fee: nothing invented, nothing
    /// lost.
    #[must_use]
    pub const fn conserves(&self) -> bool {
        self.endowment + self.gateway == self.total
    }

    /// The gateway's share in parts per million, for the metrics surface.
    #[must_use]
    pub const fn gateway_ppm(&self) -> u32 {
        if self.total == 0 {
            return 0;
        }
        // The share is a constant 5 percent; the ppm form is reported so a
        // dashboard reads the same unit as the other fee gauges.
        (GATEWAY_SHARE_PERCENT as u32) * 10_000
    }
}

/// The unrounded fee in base units at `rate_per_gib_year`, before the floor
/// and the rounding rule.
fn fee_at_rate(
    physical_bytes: u64,
    lifetime_days: u32,
    rate_per_gib_year: u128,
) -> Result<u128, FeeError> {
    if lifetime_days == 0 {
        return Err(FeeError::LifetimeOutOfRange { days: 0 });
    }
    // ceil(bytes x days x P_s / (2^30 x 365)) evaluated in base units.
    let numerator = u128::from(physical_bytes)
        .checked_mul(u128::from(lifetime_days))
        .and_then(|v| v.checked_mul(rate_per_gib_year))
        .ok_or(FeeError::Overflow)?;
    let denominator = (GIB as u128)
        .checked_mul(DAYS_PER_YEAR)
        .ok_or(FeeError::Overflow)?;
    Ok(numerator.div_ceil(denominator))
}

/// Price one upload (section 11.5 item 1 to 3).
///
/// # Errors
///
/// [`FeeError::LifetimeOutOfRange`] for a zero lifetime, [`FeeError::Overflow`]
/// when the product leaves `u128`.
pub fn storage_fee(physical_bytes: u64, lifetime_days: u32) -> Result<u128, FeeError> {
    let raw = fee_at_rate(physical_bytes, lifetime_days, PHYSICAL_GIB_YEAR_UNITS)?;
    Ok(raw.max(MIN_FEE_UNITS))
}

/// Price one upload and split it. The endowment takes 95 percent and the
/// gateway 5 percent; the floor is applied before the split, so a minimum fee
/// still reaches both parties.
///
/// # Errors
///
/// The [`storage_fee`] refusals.
pub fn price_upload(physical_bytes: u64, lifetime_days: u32) -> Result<FeeSplit, FeeError> {
    quote(physical_bytes, lifetime_days, PHYSICAL_GIB_YEAR_UNITS)
}

/// Price one upload at an explicit physical-byte rate. This is the one shape
/// the tests and the governance parameter read, so a rate change is a
/// argument, not an edit in the middle of the formula.
///
/// # Errors
///
/// The [`storage_fee`] refusals.
pub fn quote(
    physical_bytes: u64,
    lifetime_days: u32,
    rate_per_gib_year: u128,
) -> Result<FeeSplit, FeeError> {
    let total = fee_at_rate(physical_bytes, lifetime_days, rate_per_gib_year)?.max(MIN_FEE_UNITS);
    let gateway = total * GATEWAY_SHARE_PERCENT / 100;
    let endowment = total - gateway;
    Ok(FeeSplit {
        total,
        endowment,
        gateway,
        physical_bytes,
        lifetime_days,
    })
}

/// Price an object shared by `references` NFTs (section 11.5 item 7): the
/// physical bytes divide between the NFTs that reference the object, so a
/// second NFT pays only its own share and the earlier ones are not refunded.
/// The bytes are rounded **up**, so the parts never sum to less than the
/// whole.
///
/// # Errors
///
/// [`FeeError::LifetimeOutOfRange`] for a zero lifetime or zero references.
pub fn shared_physical_bytes(physical_bytes: u64, references: u32) -> Result<u64, FeeError> {
    if references == 0 {
        return Err(FeeError::LifetimeOutOfRange { days: 0 });
    }
    Ok(physical_bytes.div_ceil(u64::from(references)))
}

/// Price one epoch of endowment distribution for `object_physical_bytes`
/// held under `lifetime_epochs` (section 11.5 item 4): the endowment pays out
/// `endowment x epoch / lifetime` each epoch, rounded down, and the last epoch
/// carries the remainder so the sum is exactly the endowment.
///
/// `epoch` is zero based.
#[must_use]
pub fn epoch_payout(endowment: u128, epoch: u64, lifetime_epochs: u64) -> u128 {
    if epoch >= lifetime_epochs || lifetime_epochs == 0 {
        return 0;
    }
    let per = endowment / u128::from(lifetime_epochs);
    if epoch + 1 == lifetime_epochs {
        endowment - per * u128::from(lifetime_epochs - 1)
    } else {
        per
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_fee_formula_matches_section_11_5() {
        // 1 GiB for one year is exactly P_s = 1 BUD.
        assert_eq!(storage_fee(GIB, 365).unwrap(), BUD_BASE_UNITS);
        // Half a year of half a GiB is a quarter of that.
        assert_eq!(storage_fee(GIB / 2, 365).unwrap(), BUD_BASE_UNITS / 2);
        // The formula rounds up: the smallest nonzero content is never free.
        assert_eq!(storage_fee(1, 1).unwrap(), MIN_FEE_UNITS);
        // The floor is 0.001 BUD and it binds below the raw value.
        assert_eq!(MIN_FEE_UNITS, 1_000);
        assert_eq!(storage_fee(0, 30).unwrap(), MIN_FEE_UNITS);
        // A zero lifetime is not a free lease.
        assert_eq!(
            storage_fee(GIB, 0).unwrap_err(),
            FeeError::LifetimeOutOfRange { days: 0 }
        );
        // The input is physical bytes: doubling the bytes doubles the fee.
        let a = storage_fee(GIB, 30).unwrap();
        let b = storage_fee(2 * GIB, 30).unwrap();
        assert_eq!(b, a * 2);
    }

    #[test]
    fn gateway_share_is_five_percent() {
        let split = price_upload(GIB, 365).unwrap();
        assert!(split.conserves());
        assert_eq!(split.total, BUD_BASE_UNITS);
        assert_eq!(split.gateway, BUD_BASE_UNITS * 5 / 100);
        assert_eq!(split.endowment, BUD_BASE_UNITS * 95 / 100);
        assert_eq!(split.gateway_ppm(), 50_000);
        // Every input the tests use partitions exactly, floor included.
        for (bytes, days) in [
            (0u64, 30u32),
            (1, 1),
            (GIB, 30),
            (GIB, 3650),
            (16 * GIB, 3650),
            (12_345, 7),
        ] {
            let s = price_upload(bytes, days).unwrap();
            assert!(s.conserves(), "{bytes} bytes / {days} days: {s:?}");
            assert!(s.total >= MIN_FEE_UNITS);
        }
    }

    #[test]
    fn storage_rewards_conserve_supply() {
        // Over a hundred-epoch lease every epoch's payout sums to exactly the
        // endowment, so no base unit is invented and none is lost.
        let split = price_upload(GIB, 365).unwrap();
        let lifetime = 100u64;
        let paid: u128 = (0..lifetime)
            .map(|e| epoch_payout(split.endowment, e, lifetime))
            .sum();
        assert_eq!(paid, split.endowment);
        // Past the lease the endowment pays nothing.
        assert_eq!(epoch_payout(split.endowment, lifetime, lifetime), 0);
        // The gateway's part never enters the distribution.
        assert_eq!(split.endowment + split.gateway, split.total);
    }

    #[test]
    fn shared_physical_bytes_split_between_references() {
        // Two NFTs on one object each pay half, rounded up.
        assert_eq!(shared_physical_bytes(1_000, 2).unwrap(), 500);
        assert_eq!(shared_physical_bytes(1_001, 2).unwrap(), 501);
        assert_eq!(shared_physical_bytes(1_001, 1).unwrap(), 1_001);
        // The parts never sum to less than the object.
        let per = shared_physical_bytes(1_001, 3).unwrap();
        assert!(per * 3 >= 1_001);
        assert_eq!(
            shared_physical_bytes(1, 0).unwrap_err(),
            FeeError::LifetimeOutOfRange { days: 0 }
        );
    }

    #[test]
    fn an_unpayable_fee_saturates_rather_than_wrapping() {
        // A physical byte count near u64::MAX with the maximum lifetime leaves
        // u128 or is refused; it never wraps to a small number.
        assert_eq!(
            fee_at_rate(u64::MAX, u32::MAX, PHYSICAL_GIB_YEAR_UNITS).unwrap_err(),
            FeeError::Overflow
        );
        // A rate of ten times P_s costs ten times as much, and the split still
        // partitions the whole.
        let ten = quote(GIB, 365, PHYSICAL_GIB_YEAR_UNITS * 10).unwrap();
        assert_eq!(ten.total, BUD_BASE_UNITS * 10);
        assert!(ten.conserves());
        // The formula is read from the argument, not from a copy of the rate.
        let rate = PHYSICAL_GIB_YEAR_UNITS / 2;
        let half = quote(GIB, 365, rate).unwrap();
        assert_eq!(half.total, BUD_BASE_UNITS / 2);
        assert!(storage_fee(16 * GIB, 3650).is_ok());
    }
}
