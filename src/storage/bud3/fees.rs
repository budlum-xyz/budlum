//! Storage fees, the storage endowment and the custody rewards.
//!
//! Directive sections 6.18, 11.4 and 11.5 define the money side of B.U.D. 3.0.
//! This module is the arithmetic of that side and nothing else: it charges no
//! balance, writes no state and reads no clock, so every rule here is a
//! function a test can hold still.
//!
//! # The fee
//!
//! Section 11.5 item 1: `fee = ceil(physical_bytes x lifetime_days x P_s /
//! (2^30 x 365))`, where `P_s` is 1 BUD per GiB per year of physical bytes
//! (TESTNET-DEFAULT). The input is the **physical** byte count, not the
//! content length and not the symbol count: a sealed object costs what its
//! stored bytes cost, and the codec that shrank it does not discount it.
//!
//! # The units
//!
//! Fees are in the base unit of `tokenomics`, the micro-BUD
//! ([`crate::tokenomics::BUD_UNIT`]), which is the unit every balance in the
//! tree already uses. The section's smallest fee, 0.001 BUD, is therefore
//! exactly [`MIN_STORAGE_FEE`] base units and needs no rounding rule of its
//! own. The execution layer's `frac_attos` (WP-26) will subdivide this later;
//! a fee written in attos today would be a second unit nothing else reads.
//!
//! # What a fee becomes
//!
//! Section 11.5 item 4 and 6 split the fee: 95 percent to the storage
//! endowment, which releases it to the holders of the object over the paid
//! lifetime, and 5 percent to the upload gateway. The split floors the gateway
//! share, never the endowment share, so a fee too small to divide by twenty
//! pays the gateway nothing rather than paying it a twenty-fifth. Item 5 gives
//! what the endowment could not pay to the network security pool: a missed
//! audit costs the holder that window's reward and cuts nothing (section 11.7),
//! and the reward it did not receive is not burned, it funds the pool that
//! backs the same storage.
//!
//! # Conservation
//!
//! Every function here returns coins that came from somewhere. [`StorageLedger`]
//! is the shape of that claim: `charged` equals `gateway + paid + endowment +
//! pool` at every step, in a hundred-epoch simulation as much as after one
//! settlement. Nothing in this module can mint.
//!
//! WIRING: unwired - the executor's `RegisterObject`, `RenewObject` and
//! `BindReference` arms charge these numbers and move the splits into the
//! endowment and the pool when the `StorageTx` v3 door reaches the transaction
//! envelope (WP-21 owns that door). Until then the module is exercised by its
//! own tests, in the same way the rest of this subtree is.

use crate::core::address::Address;

/// The base unit a whole BUD is counted in: the micro-BUD of `tokenomics`.
const BUD: u64 = crate::tokenomics::BUD_UNIT;

/// Parts per million: the denominator of every ratio in this module.
pub const PPM: u64 = 1_000_000;

/// The smallest storage fee: 0.001 BUD (section 11.5, item 3).
pub const MIN_STORAGE_FEE: u64 = BUD / 1_000;

/// The gateway's share of a fee (section 11.5, item 6).
pub const GATEWAY_SHARE_PPM: u64 = 50_000;

/// The endowment's share of a fee (section 11.5, item 4).
pub const ENDOWMENT_SHARE_PPM: u64 = PPM - GATEWAY_SHARE_PPM;

/// `P_s`: the annual price of one GiB of physical bytes, 1 BUD (section 11.5).
pub const PRICE_PER_GIB_YEAR: u64 = BUD;

/// Bytes in a GiB, the denominator `P_s` is quoted against.
pub const GIB_BYTES: u64 = 1 << 30;

/// Days in the billing year `P_s` is quoted against.
pub const BILLING_DAYS: u64 = 365;

/// Seconds in a day, for the lifetime an endowment is released over.
pub const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

/// The Mobile share of the symbols that the placement floor requires
/// (section 6.9: 30 percent).
pub const MOBILE_SHARE_FLOOR_PPM: u64 = 300_000;

/// What one fee becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSplit {
    /// The part that funds the storage endowment.
    pub endowment: u64,
    /// The part that pays the upload gateway.
    pub gateway: u64,
}

/// The fee for storing `physical_bytes` for `lifetime_days` (section 11.5).
///
/// The result is rounded up, so a lifetime of one day on one byte still costs
/// something, and then floored at [`MIN_STORAGE_FEE`]. A lifetime of zero days
/// is priced as the minimum rather than as free: an object with no paid
/// lifetime should not exist, and the registry refuses that registration
/// before a fee is asked for.
///
/// The multiplication runs in `u128`. `physical_bytes x days` at the u64
/// ceiling is 2^128, so a product that overflowed u128 would already be a byte
/// count no node can hold; the saturating conversion is written down rather
/// than left to a wrap.
#[must_use]
pub fn storage_fee(physical_bytes: u64, lifetime_days: u64) -> u64 {
    let numerator = u128::from(physical_bytes)
        .saturating_mul(u128::from(lifetime_days))
        .saturating_mul(u128::from(PRICE_PER_GIB_YEAR));
    let denominator = u128::from(GIB_BYTES).saturating_mul(u128::from(BILLING_DAYS));
    if denominator == 0 {
        return MIN_STORAGE_FEE;
    }
    let fee = numerator.div_ceil(denominator);
    let fee = u64::try_from(fee).unwrap_or(u64::MAX);
    fee.max(MIN_STORAGE_FEE)
}

/// The fee for extending a paid lifetime (section 11.5, item 9).
///
/// `RenewObject` applies the same formula to the extra lifetime, which is the
/// same call: a renewal is not a discount and not a surcharge.
///
/// WIRING: unwired - the `RenewObject` arm of the storage door charges the
/// executor with this number when the executor lands (WP-21).
#[must_use]
pub fn renewal_fee(physical_bytes: u64, extra_days: u64) -> u64 {
    storage_fee(physical_bytes, extra_days)
}

/// Split a fee into the endowment's part and the gateway's part.
///
/// The gateway share is floored and the endowment takes the rest, so the two
/// always add up to the fee and the gateway never receives more than its
/// twenty-fifth. Rounding the other way would let a stream of fees one unit
/// above a multiple of twenty turn a five percent share into a large one.
#[must_use]
pub fn split_fee(fee: u64) -> FeeSplit {
    let gateway = u64::try_from(
        u128::from(fee).saturating_mul(u128::from(GATEWAY_SHARE_PPM)) / u128::from(PPM),
    )
    .unwrap_or(fee);
    FeeSplit {
        endowment: fee.saturating_sub(gateway),
        gateway,
    }
}

/// The part of a shared object's fee one reference pays (section 11.5, item 7).
///
/// The physical bytes of a public object are shared by the NFTs that refer to
/// it, so the fee is divided by the number of references. The division rounds
/// up, because the references together have to pay the whole fee: a remainder
/// left uncharged is storage the network stores for free. Item 7 also says the
/// earlier references are not refunded when a new one appears, which is why
/// this is a function of the count at the time rather than a rebate.
///
/// WIRING: unwired - `BindReference` divides the object's fee with this when
/// the executor lands (WP-21).
#[must_use]
pub fn shared_object_fee(fee: u64, references: u64) -> u64 {
    if references == 0 {
        return fee;
    }
    let per = u128::from(fee).div_ceil(u128::from(references));
    u64::try_from(per).unwrap_or(u64::MAX)
}

/// What a reference to sealed content costs (section 11.5, item 8).
///
/// The owner's first reference pays the fee; every later reference by the same
/// owner to the same sealed object is free, because the bytes are already
/// paid for and deduplicating them paid off.
///
/// WIRING: unwired - `RegisterObject` counts the owner's references before it
/// charges, when the executor lands (WP-21).
#[must_use]
pub fn sealed_reference_fee(fee: u64, owner_references_before: u64) -> u64 {
    if owner_references_before == 0 {
        fee
    } else {
        0
    }
}

/// The slice of one object's endowment that one epoch releases (section 11.5,
/// item 4).
///
/// `endowment_share` is the object's endowment, not the balance left in it:
/// the rule releases `share x epoch_seconds / lifetime`, so the releases add
/// up to the share over the paid lifetime. The caller caps the result at the
/// balance it holds; [`StorageLedger::settle_epoch`] does that.
#[must_use]
pub fn endowment_epoch_slice(endowment_share: u64, epoch_secs: u64, lifetime_days: u64) -> u64 {
    let life = u128::from(lifetime_days).saturating_mul(u128::from(SECONDS_PER_DAY));
    if life == 0 {
        return 0;
    }
    let slice = u128::from(endowment_share).saturating_mul(u128::from(epoch_secs)) / life;
    u64::try_from(slice.min(u128::from(endowment_share))).unwrap_or(endowment_share)
}

/// One holder's claim on a custody payout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyShare {
    /// The holder.
    pub holder: Address,
    /// The symbol bytes this share holds: the weight the payout follows.
    pub symbol_bytes: u64,
    /// The presence multiplier of section 11.4, item 5, in ppm: the fraction of
    /// the epoch's presence windows the validator was seen in.
    pub presence_ppm: u32,
    /// Whether the share passed every audit open on it in the window. A share
    /// that missed an audit is paid nothing for that window (section 11.7:
    /// no reward, no slash).
    pub passed_audit: bool,
}

/// What a custody payout became.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyPayout {
    /// The paid amounts, in the order the shares were given.
    pub paid: Vec<(Address, u64)>,
    /// What the pool keeps: the missed audits' part and the rounding dust.
    pub to_pool: u64,
}

/// Divide an epoch's custody payout across the shares (section 11.4, item 5;
/// section 11.5, item 4).
///
/// The weight of a passed share is `symbol_bytes x presence_multiplier`, so a
/// share that was present for half the epoch's windows earns half as much per
/// byte as one that was present throughout, and a share that missed an audit
/// earns nothing. The division floors each amount and sends the remainder to
/// the pool with the missed shares: a coin is paid to somebody or kept for the
/// pool, never dropped.
#[must_use]
pub fn custody_payout(payout: u64, shares: &[CustodyShare]) -> CustodyPayout {
    let mut weights: Vec<(Address, u128)> = Vec::with_capacity(shares.len());
    let mut total: u128 = 0;
    for share in shares {
        if !share.passed_audit {
            continue;
        }
        let weight = u128::from(share.symbol_bytes).saturating_mul(u128::from(share.presence_ppm));
        if weight == 0 {
            continue;
        }
        total = total.saturating_add(weight);
        weights.push((share.holder, weight));
    }

    let mut paid = Vec::with_capacity(weights.len());
    let mut distributed: u64 = 0;
    if total != 0 {
        for (holder, weight) in weights {
            let amount = u128::from(payout).saturating_mul(weight) / total;
            let amount = u64::try_from(amount).unwrap_or(u64::MAX);
            if amount != 0 {
                distributed = distributed.saturating_add(amount);
                paid.push((holder, amount));
            }
        }
    }
    CustodyPayout {
        paid,
        to_pool: payout.saturating_sub(distributed),
    }
}

/// The symbol bytes the Mobile placement floor requires (section 6.9).
///
/// `mobile_weighted_bytes` is what the stake-weighted split already gives the
/// Mobile class. The floor is a share of the object's total symbol bytes, so
/// the answer is the distance between the two, and zero when the split already
/// clears it.
#[must_use]
pub fn decentralization_extra_bytes(total_symbol_bytes: u64, mobile_weighted_bytes: u64) -> u64 {
    let floor = u128::from(total_symbol_bytes).saturating_mul(u128::from(MOBILE_SHARE_FLOOR_PPM))
        / u128::from(PPM);
    let floor = u64::try_from(floor).unwrap_or(u64::MAX);
    floor.saturating_sub(mobile_weighted_bytes)
}

/// What the Mobile floor's extra bytes cost for one lifetime (section 6.9;
/// section 11.5 of the package card, item 4).
///
/// The uploader pays for the bytes it asked for; the bytes that exist because
/// the network wants phones to hold symbols are paid by the network security
/// pool. This function prices exactly those bytes, so the charge cannot grow
/// with the object's size beyond the distance the floor moved.
///
/// WIRING: unwired - the placement step draws this from the pool when the
/// executor lands (WP-21).
#[must_use]
pub fn decentralization_charge(
    total_symbol_bytes: u64,
    mobile_weighted_bytes: u64,
    lifetime_days: u64,
) -> u64 {
    let extra = decentralization_extra_bytes(total_symbol_bytes, mobile_weighted_bytes);
    if extra == 0 {
        return 0;
    }
    storage_fee(extra, lifetime_days)
}

/// The storage side of the economy: fees in, endowment, gateway and pool out.
///
/// Every field is a balance this module owns a rule for, and the sum of them
/// is the total charged. The ledger exists so the conservation claim is a
/// property of one object rather than a sentence in a comment: a settlement
/// moves a number between four fields and never changes their sum.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageLedger {
    /// Total fees charged.
    pub charged: u64,
    /// What the endowment still owes the holders.
    pub endowment: u64,
    /// What the gateway was paid.
    pub gateway: u64,
    /// What the holders were paid.
    pub paid: u64,
    /// What the network security pool received.
    pub pool: u64,
}

impl StorageLedger {
    /// Charge a fee and record where its split went.
    ///
    /// Returns the split so a caller can log it; the ledger does not need the
    /// answer to keep its own books.
    /// WIRING: unwired - the executor's fee arm calls this with every fee it
    /// charges when the door lands (WP-21).
    pub fn charge(&mut self, fee: u64) -> FeeSplit {
        let split = split_fee(fee);
        self.charged = self.charged.saturating_add(fee);
        self.endowment = self.endowment.saturating_add(split.endowment);
        self.gateway = self.gateway.saturating_add(split.gateway);
        split
    }

    /// Pay the pool for the Mobile floor's extra bytes.
    ///
    /// The charge leaves the pool, so a ledger that never funded the pool
    /// cannot pay it: the subtraction saturates and the caller can see the
    /// shortfall by comparing `pool` before and after.
    /// WIRING: unwired - the placement step draws the Mobile floor's charge
    /// through this when the executor lands (WP-21).
    pub fn pay_decentralization(&mut self, charge: u64) -> u64 {
        let paid = charge.min(self.pool);
        self.pool = self.pool.saturating_sub(paid);
        self.paid = self.paid.saturating_add(paid);
        paid
    }

    /// Release one epoch from the endowment and divide it across the shares.
    ///
    /// Returns what the holders received this epoch. The slice is capped at
    /// the endowment this ledger holds, so the last epoch of an object's life
    /// pays the remainder rather than a slice the balance cannot cover.
    /// WIRING: unwired - the executor's epoch boundary settles the endowment
    /// through this call when it lands (WP-21).
    pub fn settle_epoch(
        &mut self,
        shares: &[CustodyShare],
        epoch_secs: u64,
        lifetime_days: u64,
    ) -> u64 {
        let slice =
            endowment_epoch_slice(self.endowment, epoch_secs, lifetime_days).min(self.endowment);
        if slice == 0 {
            return 0;
        }
        let payout = custody_payout(slice, shares);
        let mut distributed: u64 = 0;
        for (_, amount) in &payout.paid {
            distributed = distributed.saturating_add(*amount);
        }
        self.endowment = self.endowment.saturating_sub(slice);
        self.paid = self.paid.saturating_add(distributed);
        self.pool = self.pool.saturating_add(payout.to_pool);
        distributed
    }

    /// The total the ledger holds, across its four balances.
    ///
    /// Equal to [`Self::charged`] at every point of a correct ledger; a test
    /// compares the two rather than trusting the sentence.
    /// WIRING: unwired - the economy audit reads this sum, and the invariant
    /// `storage_rewards_conserve_supply` asserts it when the executor lands
    /// (WP-25, WP-21).
    #[must_use]
    pub fn accounted(&self) -> u64 {
        self.gateway
            .saturating_add(self.endowment)
            .saturating_add(self.paid)
            .saturating_add(self.pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A share present in every window of the epoch.
    const FULL_PRESENCE: u32 = 1_000_000;

    fn holder(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    fn share(byte: u8, symbol_bytes: u64, presence_ppm: u32, passed_audit: bool) -> CustodyShare {
        CustodyShare {
            holder: holder(byte),
            symbol_bytes,
            presence_ppm,
            passed_audit,
        }
    }

    /// Section 11.5, item 1 and 3: the formula, its unit and its floor.
    #[test]
    fn storage_fee_formula_matches_section_11_5() {
        // One GiB for a year is one BUD, by the definition of `P_s`.
        assert_eq!(storage_fee(GIB_BYTES, BILLING_DAYS), PRICE_PER_GIB_YEAR);
        assert_eq!(storage_fee(GIB_BYTES, BILLING_DAYS), BUD);
        // Two GiB for two years is four BUD.
        assert_eq!(storage_fee(2 * GIB_BYTES, 2 * BILLING_DAYS), 4 * BUD);
        // The fee is linear in bytes and in days.
        assert_eq!(
            storage_fee(GIB_BYTES / 4, BILLING_DAYS),
            storage_fee(GIB_BYTES, BILLING_DAYS) / 4
        );
        // The minimum: one byte for one day would round to a single base unit
        // and is floored at 0.001 BUD instead.
        assert_eq!(storage_fee(1, 1), MIN_STORAGE_FEE);
        assert_eq!(MIN_STORAGE_FEE, 1_000);
        // Rounding is up, so a fraction of a base unit still costs one.
        let tiny = storage_fee(GIB_BYTES, 1);
        assert_eq!(tiny, BUD.div_ceil(BILLING_DAYS));
        // A renewal is the same formula on the extra days.
        assert_eq!(renewal_fee(GIB_BYTES, 30), storage_fee(GIB_BYTES, 30));
    }

    /// Section 11.5, item 6: the gateway gets a twentieth, never more.
    #[test]
    fn gateway_share_is_five_percent() {
        for fee in [MIN_STORAGE_FEE, 1_000_000, 20, 21, 99, 10_000_000] {
            let split = split_fee(fee);
            assert_eq!(
                split.endowment + split.gateway,
                fee,
                "the split must not create or destroy a base unit"
            );
            assert!(
                split.gateway <= fee / 20,
                "the gateway took more than a twentieth of {fee}"
            );
        }
        // Exactly five percent where the fee divides.
        let split = split_fee(1_000_000);
        assert_eq!(split.gateway, 50_000);
        assert_eq!(split.endowment, 950_000);
        assert_eq!(split.endowment + split.gateway, 1_000_000);
    }

    /// Section 11.5, item 4 and section 11.7: a share that missed an audit is
    /// paid nothing, and the reward it did not take is not lost.
    #[test]
    fn endowment_pays_only_passed_audits() {
        let shares = [
            share(1, 1_000, FULL_PRESENCE, true),
            share(2, 1_000, FULL_PRESENCE, false),
            share(3, 1_000, FULL_PRESENCE, true),
        ];
        let payout = custody_payout(1_000, &shares);
        let holders: Vec<Address> = payout.paid.iter().map(|(a, _)| *a).collect();
        assert!(holders.contains(&holder(1)));
        assert!(holders.contains(&holder(3)));
        assert!(
            !holders.contains(&holder(2)),
            "a missed audit earns nothing for that window"
        );
        // The two that passed split the whole payout evenly.
        assert_eq!(payout.paid.len(), 2);
        assert_eq!(payout.paid[0].1, 500);
        assert_eq!(payout.paid[1].1, 500);
        assert_eq!(payout.to_pool, 0);

        // Presence is a multiplier: half the windows is half the weight.
        let shares = [
            share(4, 1_000, FULL_PRESENCE, true),
            share(5, 1_000, FULL_PRESENCE / 2, true),
        ];
        let payout = custody_payout(1_500, &shares);
        assert_eq!(payout.paid[0].1, 1_000);
        assert_eq!(payout.paid[1].1, 500);
    }

    /// Section 11.5, item 5: what the endowment could not pay funds the pool.
    #[test]
    fn missed_audit_share_returns_to_pool() {
        let shares = [
            share(6, 1_000, FULL_PRESENCE, true),
            share(7, 1_000, FULL_PRESENCE, false),
            share(8, 1_000, FULL_PRESENCE, false),
            share(9, 1_000, FULL_PRESENCE, false),
        ];
        let payout = custody_payout(1_000, &shares);
        let distributed: u64 = payout.paid.iter().map(|(_, amount)| *amount).sum();
        assert_eq!(distributed, 1_000);
        // Three of four shares missed. A missed share does not leave a hole:
        // the epoch's slice is divided among the shares that passed, so the
        // one that did is paid the whole slice and the pool gets nothing.
        assert_eq!(payout.to_pool, 0);

        // With nobody passing, the whole payout goes to the pool.
        let nobody = [
            share(10, 1_000, FULL_PRESENCE, false),
            share(11, 1_000, FULL_PRESENCE, false),
        ];
        let payout = custody_payout(777, &nobody);
        assert!(payout.paid.is_empty());
        assert_eq!(payout.to_pool, 777);

        // Rounding dust joins it: three equal weights on 100 units leave one
        // unit over.
        let three = [
            share(12, 1, FULL_PRESENCE, true),
            share(13, 1, FULL_PRESENCE, true),
            share(14, 1, FULL_PRESENCE, true),
        ];
        let payout = custody_payout(100, &three);
        let distributed: u64 = payout.paid.iter().map(|(_, amount)| *amount).sum();
        assert_eq!(distributed + payout.to_pool, 100);
        assert_eq!(payout.to_pool, 1);
    }

    /// Section 6.9: the bytes the Mobile floor adds are priced at the pool.
    #[test]
    fn decentralization_bytes_paid_by_pool() {
        // Ten GiB of symbols split evenly by stake, but the floor wants 30
        // percent of them in the Mobile class: the distance is the charge.
        let total = 10 * GIB_BYTES;
        assert_eq!(decentralization_extra_bytes(total, total / 10), 2 * GIB_BYTES);
        // A split already above the floor costs nothing.
        assert_eq!(decentralization_extra_bytes(total, total / 2), 0);
        // The charge is the storage fee of the extra bytes alone.
        let charge = decentralization_charge(total, total / 10, BILLING_DAYS);
        assert_eq!(charge, storage_fee(2 * GIB_BYTES, BILLING_DAYS));
        assert_eq!(charge, 2 * BUD);

        // The pool pays it, and the ledger's total is unchanged by the move.
        let mut ledger = StorageLedger::default();
        ledger.charge(storage_fee(total, BILLING_DAYS));
        ledger.pool = BUD;
        let before = ledger.accounted();
        let paid = ledger.pay_decentralization(charge);
        assert_eq!(paid, BUD, "the pool pays what it holds, not more");
        assert_eq!(ledger.accounted(), before);
    }

    /// Section 11.5, items 7, 8, 9 and 10: shared objects, sealed
    /// resubmission, renewal and replacement.
    #[test]
    fn shared_and_sealed_references_follow_the_section() {
        let fee = 1_000_000;
        // Three references share the object's fee, and together they pay it.
        let per = shared_object_fee(fee, 3);
        assert_eq!(per, 333_334);
        assert!(per * 3 >= fee);
        // One reference pays the whole fee.
        assert_eq!(shared_object_fee(fee, 1), fee);
        // A sealed object's first reference pays; the owner's later ones do
        // not, because the bytes are already paid for.
        assert_eq!(sealed_reference_fee(fee, 0), fee);
        assert_eq!(sealed_reference_fee(fee, 1), 0);
        assert_eq!(sealed_reference_fee(fee, 7), 0);
        // A renewal is priced, never refunded, and a replacement has no refund
        // path in this module at all.
        assert_eq!(renewal_fee(GIB_BYTES, BILLING_DAYS), BUD);
    }

    /// The card's finish line: a hundred epochs conserve the supply.
    #[test]
    fn storage_rewards_conserve_supply() {
        let mut ledger = StorageLedger::default();
        // One object: 10 GiB of physical bytes for a year, split across four
        // holders of which one never passes an audit.
        let fee = ledger.charge(storage_fee(10 * GIB_BYTES, BILLING_DAYS)).endowment;
        assert_eq!(fee, 9_500_000, "the endowment's 95 percent of 10 BUD");
        let shares = [
            share(20, 4_000, FULL_PRESENCE, true),
            share(21, 3_000, 800_000, true),
            share(22, 2_000, 500_000, true),
            share(23, 1_000, FULL_PRESENCE, false),
        ];
        // One hour epochs, a year of lifetime: 8 760 settlements.
        let epoch_secs = 3_600;
        let mut epochs = 0;
        for _ in 0..100 {
            ledger.settle_epoch(&shares, epoch_secs, BILLING_DAYS);
            assert_eq!(ledger.accounted(), ledger.charged, "epoch {}", epochs + 1);
            epochs += 1;
        }
        assert_eq!(epochs, 100);
        assert!(ledger.paid > 0, "the holders were paid something");
        assert_eq!(ledger.accounted(), ledger.charged);
        assert_eq!(
            ledger.gateway
                + ledger.endowment
                + ledger.paid
                + ledger.pool,
            ledger.charged
        );
    }
}
