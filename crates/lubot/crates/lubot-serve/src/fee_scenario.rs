//! The published fee schedule, as arithmetic.
//!
//! Fees are quoted in USD, the unit an operator shows a user. Three axes:
//!
//! * **Chain transactions** — a base plus an ad-valorem cut, by class:
//!   transfer `$0.01 + 0.2%`, swap `$0.01 + 0.4%`, bridge `$0.01 + 0.8%`.
//! * **B.U.D. storage, by version** — 1.0 charges only the share NFT's
//!   transaction fee (content stays on the user's device, so there is no
//!   storage cost to charge); 2.0 bills `$0.016/TB` monthly for the held
//!   body; 3.0's recipe fits inside the `$0.01` upload base, so nothing
//!   monthly, and only if the ten-year cost exceeds that cent is the excess
//!   charged. Uploaded content stays alive ten years; on expiry the owner may
//!   delete it, and if they do not, it moves to an open auction and
//!   transfers after one month.
//! * **Lubot serving** — token-metered like an API: every prompt debits its
//!   tokens at the serving rate from the wallet as it runs, using the rates
//!   [`crate::cost_forecast`] measures. No terabyte is priced here; serving
//!   costs scale with tokens, not with stored bytes.

/// Basis points: 10_000 bp = 100%.
const BPS: f64 = 10_000.0;

/// The class of a chain transaction, which sets its ad-valorem cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxClass {
    /// Plain value transfer.
    Transfer,
    /// An exchange that routes through liquidity.
    Swap,
    /// A cross-chain move.
    Bridge,
}

impl TxClass {
    /// The flat part of the fee, charged even on a zero amount.
    #[must_use]
    pub const fn base_usd(self) -> f64 {
        0.01
    }

    /// The ad-valorem part, in basis points.
    #[must_use]
    pub const fn rate_bps(self) -> u32 {
        match self {
            TxClass::Transfer => 20,
            TxClass::Swap => 40,
            TxClass::Bridge => 80,
        }
    }
}

/// Fee in dollars for a transaction of `amount_usd`: base plus the cut.
#[must_use]
pub fn transaction_fee_usd(class: TxClass, amount_usd: f64) -> f64 {
    class.base_usd() + amount_usd * f64::from(class.rate_bps()) / BPS
}

/// The upload transaction's base fee, already paid by the uploader. In 3.0 it
/// covers ten-year custody of the recipe, because a recipe is a fixed-size
/// commitment, not the terabytes of content it describes.
pub const BUD_UPLOAD_BASE_USD: f64 = 0.01;

/// A 3.0 recipe is fixed-size, no matter how large the content was: the
/// sealed commitment is 40 bytes and the public recipe 74 bytes.
pub const BUD_RECIPE_SEALED_BYTES: u64 = 40;
pub const BUD_RECIPE_PUBLIC_BYTES: u64 = 74;

/// 3.0 keeps uploaded content alive this many years.
///
/// User decision 2026-08-31 (final): ten years. The economics measured it:
/// a recipe's network cost is one-time capital, so the $0.01 upload base
/// covers ten-year recipe custody of a terabyte for any item >= 512 KiB
/// (worst measured case: $0.0092 per TB); smaller items are covered by the
/// excess rule, never by extending the promise.
pub const BUD_CUSTODY_YEARS: u32 = 10;

/// Expired but undeleted content transfers by open auction lasting one month.
pub const BUD_EXPIRY_AUCTION_DAYS: u32 = 30;

/// 2.0 monthly price per terabyte held, measured.
pub const BUD_2_MONTHLY_USD_PER_TB: f64 = 0.016;

/// Which B.U.D. version a piece of content is stored under, which sets its fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudVersion {
    /// 1.0: a share. The NFT is the charge (a plain transaction fee); the
    /// content bytes stay on the user's device, so nothing is billed monthly.
    V1_0,
    /// 2.0: a held body, billed monthly per terabyte.
    V2_0,
    /// 3.0: a recipe, carried inside the upload base fee.
    V3_0,
}

impl BudVersion {
    /// Monthly storage fee for `tb` terabytes, in dollars.
    ///
    /// 1.0 holds nothing (the bytes are the user's own), 2.0 bills the
    /// measured per-terabyte rate, and 3.0's fixed-size recipe already fits
    /// inside the `$0.01` upload base so it bills nothing monthly.
    #[must_use]
    pub fn monthly_storage_fee_usd(self, tb: f64) -> f64 {
        match self {
            BudVersion::V1_0 => 0.0,
            BudVersion::V2_0 => tb * BUD_2_MONTHLY_USD_PER_TB,
            BudVersion::V3_0 => 0.0,
        }
    }
}

/// Extra fee per terabyte on upload: the ten-year custody cost above the base
/// fee already paid. Zero while the cost fits inside $0.01, which is always
/// the case for a recipe; it fires only when the ten-year cost of the terabyte
/// really exceeds a cent.
#[must_use]
pub fn bud_upload_extra_fee_usd_per_tb(ten_year_storage_cost_usd: f64) -> f64 {
    (ten_year_storage_cost_usd - BUD_UPLOAD_BASE_USD).max(0.0)
}

/// One terabyte of content, in bytes (decimal TB, the unit the fee schedule
/// quotes in).
pub const BYTES_PER_TB: u64 = 1_000_000_000_000;

/// How many fixed-size recipes cover `content_bytes` of 3.0 content when the
/// average item is `item_bytes`. The network object of 3.0 is the recipe, so
/// this count - not the terabytes - is what the network holds. Zero item size
/// addresses nothing and returns zero rather than dividing by it.
#[must_use]
pub const fn recipes_for_content(content_bytes: u64, item_bytes: u64) -> u64 {
    if item_bytes == 0 {
        return 0;
    }
    content_bytes / item_bytes
}

/// Network bytes held for one terabyte of 3.0 content: recipes only, no body.
/// In 3.0 nobody holds the body - not the network, not the user: the content
/// is generated from its recipe on demand, so a terabyte of 3.0 content costs
/// storage nowhere and the recipe records are the entire network footprint.
#[must_use]
pub const fn three_network_bytes_per_tb(item_bytes: u64) -> u64 {
    recipes_for_content(BYTES_PER_TB, item_bytes).saturating_mul(BUD_RECIPE_PUBLIC_BYTES)
}

/// Network cost of holding one terabyte of 3.0 content for the custody
/// period, in dollars.
///
/// Priced as the NVMe capital upper bound of the recipe bytes (the same
/// measure [`crate::validator_cost::nvme_custody_usd`] uses for a single
/// recipe): the capital is one-time and covers the whole custody period,
/// whatever its length. Drive-level idle energy is a validator capital line
/// ([`crate::validator_cost::storage_layer`]), not a per-recipe one, so it is
/// deliberately not attributed here; at these byte counts it would not move
/// the third decimal of a cent.
#[must_use]
pub fn three_network_custody_usd_per_tb(
    item_bytes: u64,
    p: crate::validator_cost::HardwarePricelist,
) -> f64 {
    crate::validator_cost::nvme_custody_usd(three_network_bytes_per_tb(item_bytes), p)
}

/// Monthly network cost of one terabyte of 3.0 content: the custody-period
/// capital amortized over the custody months. This is the number to put next
/// to 2.0's `BUD_2_MONTHLY_USD_PER_TB`.
#[must_use]
pub fn three_network_monthly_usd_per_tb(
    item_bytes: u64,
    p: crate::validator_cost::HardwarePricelist,
) -> f64 {
    three_network_custody_usd_per_tb(item_bytes, p) / f64::from(BUD_CUSTODY_YEARS * 12)
}

/// Where a piece of uploaded content sits in its custody lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyPhase {
    /// Within its custody period, owner holding.
    Live,
    /// The owner deleted it.
    Deleted,
    /// Expired and undeleted: inside the one-month open auction.
    Auctioning,
    /// The auction closed; custody transferred to the winner.
    Transferred,
}

/// The custody phase from three facts: has the owner deleted it, has the
/// custody period elapsed, and has the one-month auction elapsed.
#[must_use]
pub fn custody_phase(owner_deleted: bool, expired: bool, auction_over: bool) -> CustodyPhase {
    match (owner_deleted, expired, auction_over) {
        (true, _, _) => CustodyPhase::Deleted,
        (false, false, _) => CustodyPhase::Live,
        (false, true, false) => CustodyPhase::Auctioning,
        (false, true, true) => CustodyPhase::Transferred,
    }
}

/// Whether an expired item enters the open auction at all.
///
/// User decision 2026-08-31: the auction is for **non-confidential** content
/// only. Confidential (sealed) content is never offered to bidders: an
/// expired sealed item leaves the auction path entirely, so no sealed recipe
/// or its bytes can change hands through it.
#[must_use]
pub const fn enters_open_auction(confidential: bool, owner_deleted: bool, expired: bool) -> bool {
    !confidential && !owner_deleted && expired
}

/// Start price of the open auction, per terabyte: the ten-year body custody
/// cost (user decision 2026-08-31: the auction starts at the ten-year cost
/// price and proceeds from there). The buyer takes over the body's real
/// long-horizon cost, not a nominal cent.
#[must_use]
pub fn auction_start_usd_per_tb(p: crate::validator_cost::HardwarePricelist) -> f64 {
    crate::validator_cost::ten_year_storage_cost_usd_per_tb(p)
}

/// A Lubot wallet, debited token by token as prompts run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PromptWallet {
    pub balance_usd: f64,
}

impl PromptWallet {
    #[must_use]
    pub const fn new(balance_usd: f64) -> Self {
        Self { balance_usd }
    }

    /// Charge `tokens` at a measured serving rate, in dollars per million
    /// tokens, and debit the wallet. Returns the charged amount, or the
    /// shortfall when the balance cannot cover the prompt.
    pub fn charge(
        &mut self,
        tokens: u64,
        dollars_per_million_tokens: f64,
    ) -> Result<f64, InsufficientBalance> {
        let fee = tokens as f64 / 1_000_000.0 * dollars_per_million_tokens;
        if fee > self.balance_usd {
            return Err(InsufficientBalance {
                needed_usd: fee,
                balance_usd: self.balance_usd,
            });
        }
        self.balance_usd -= fee;
        Ok(fee)
    }
}

/// A prompt that would cost more than the wallet holds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InsufficientBalance {
    pub needed_usd: f64,
    pub balance_usd: f64,
}

#[cfg(test)]
mod fee_scenario_tests {
    use super::*;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn transfer_swap_bridge_are_base_plus_their_cut() {
        // $100 through each class: 0.21 / 0.41 / 0.81.
        assert!(approx(
            transaction_fee_usd(TxClass::Transfer, 100.0),
            0.01 + 100.0 * 0.002
        ));
        assert!(approx(
            transaction_fee_usd(TxClass::Swap, 100.0),
            0.01 + 100.0 * 0.004
        ));
        assert!(approx(
            transaction_fee_usd(TxClass::Bridge, 100.0),
            0.01 + 100.0 * 0.008
        ));
        // The classes are strictly ordered.
        let t = transaction_fee_usd(TxClass::Transfer, 100.0);
        let s = transaction_fee_usd(TxClass::Swap, 100.0);
        let b = transaction_fee_usd(TxClass::Bridge, 100.0);
        assert!(t < s && s < b);
    }

    #[test]
    fn the_base_is_charged_even_on_a_zero_amount() {
        for class in [TxClass::Transfer, TxClass::Swap, TxClass::Bridge] {
            assert!(
                approx(transaction_fee_usd(class, 0.0), 0.01),
                "a zero-amount {class:?} still pays the base"
            );
        }
    }

    #[test]
    fn bud_upload_extra_fee_is_the_excess_over_the_base_cent() {
        assert!(approx(bud_upload_extra_fee_usd_per_tb(0.005), 0.0));
        assert!(approx(bud_upload_extra_fee_usd_per_tb(0.01), 0.0));
        assert!(approx(bud_upload_extra_fee_usd_per_tb(0.02), 0.01));
        assert!(approx(bud_upload_extra_fee_usd_per_tb(112.52), 112.51));
    }

    #[test]
    fn the_base_cent_covers_a_recipe_but_not_a_full_body() {
        use crate::validator_cost::{
            market_pricelist, nvme_custody_usd, ten_year_storage_cost_usd_per_tb,
        };
        // The 3.0 held unit is the fixed-size recipe, not the terabytes.
        let recipe = nvme_custody_usd(BUD_RECIPE_PUBLIC_BYTES, market_pricelist());
        let body = ten_year_storage_cost_usd_per_tb(market_pricelist());
        assert!(
            recipe < BUD_UPLOAD_BASE_USD,
            "a recipe ({BUD_RECIPE_PUBLIC_BYTES} B) fits inside the base cent: {recipe}"
        );
        assert!(
            body > BUD_UPLOAD_BASE_USD,
            "a full terabyte over ten years does not fit inside a cent: {body}"
        );
        // So a recipe upload charges nothing extra, a held body charges the excess.
        assert!(approx(bud_upload_extra_fee_usd_per_tb(recipe), 0.0));
        assert!(bud_upload_extra_fee_usd_per_tb(body) > 0.0);
    }

    #[test]
    fn version_monthly_fees_follow_the_published_schedule() {
        // 1.0: the NFT's transaction fee only; no storage charge at any size.
        assert!(approx(BudVersion::V1_0.monthly_storage_fee_usd(100.0), 0.0));
        // 2.0: measured $0.016 per TB per month.
        assert!(approx(BudVersion::V2_0.monthly_storage_fee_usd(1.0), 0.016));
        assert!(approx(BudVersion::V2_0.monthly_storage_fee_usd(10.0), 0.16));
        // 3.0: recipe rides the upload base; nothing monthly.
        assert!(approx(BudVersion::V3_0.monthly_storage_fee_usd(100.0), 0.0));
    }

    #[test]
    fn bud_custody_is_ten_years_and_the_auction_one_month() {
        // User decision 2026-08-31 (final): custody is ten years and the
        // $0.01 base covers a terabyte of ten-year recipe custody; the
        // expiry auction runs one month.
        assert_eq!(BUD_CUSTODY_YEARS, 10);
        assert_eq!(BUD_EXPIRY_AUCTION_DAYS, 30);
        // The covering claim, measured: for items >= 512 KiB the recipe
        // capital of a whole terabyte stays under the base cent.
        use crate::validator_cost::market_pricelist;
        let p = market_pricelist();
        assert!(three_network_custody_usd_per_tb(512 * 1024, p) < BUD_UPLOAD_BASE_USD);
        assert!(three_network_custody_usd_per_tb(4 << 20, p) < BUD_UPLOAD_BASE_USD / 8.0);
    }

    /// The auction rule, measured (user decision 2026-08-31): it starts at
    /// the ten-year body cost, and confidential content never enters it.
    #[test]
    fn the_auction_starts_at_the_ten_year_cost_and_skips_confidential() {
        use crate::validator_cost::{market_pricelist, ten_year_storage_cost_usd_per_tb};
        let p = market_pricelist();
        let start = auction_start_usd_per_tb(p);
        assert!(
            (start - ten_year_storage_cost_usd_per_tb(p)).abs() < 1e-12,
            "the start price is the ten-year body cost"
        );
        assert!(start > 100.0, "start price: {start}");

        // Non-confidential, expired, undeleted -> auction.
        assert!(enters_open_auction(false, false, true));
        // Confidential never enters, whatever the flags.
        assert!(!enters_open_auction(true, false, true));
        // Owner-deleted or still live -> no auction.
        assert!(!enters_open_auction(false, true, true));
        assert!(!enters_open_auction(false, false, false));
    }

    #[test]
    fn custody_phases_follow_deleted_expired_auction() {
        assert_eq!(custody_phase(false, false, false), CustodyPhase::Live);
        assert_eq!(custody_phase(true, false, false), CustodyPhase::Deleted);
        assert_eq!(custody_phase(true, true, true), CustodyPhase::Deleted);
        assert_eq!(custody_phase(false, true, false), CustodyPhase::Auctioning);
        assert_eq!(custody_phase(false, true, true), CustodyPhase::Transferred);
    }

    /// The 3.0 network cost of a terabyte, measured: the network holds
    /// recipes only, so the TB/month and TB/10-year figures are the capital
    /// of those recipe bytes - orders of magnitude under 2.0's held-body
    /// schedule, and under the $0.01 upload base for any realistic item size.
    #[test]
    fn three_network_cost_per_tb_is_measured_against_the_body_schedule() {
        use crate::validator_cost::market_pricelist;
        let p = market_pricelist();
        const MIB: u64 = 1 << 20;
        const GIB: u64 = 1 << 30;

        // Item-count math: the network holds one 74-byte recipe per item.
        assert_eq!(recipes_for_content(BYTES_PER_TB, 4 * MIB), 238_418);
        assert_eq!(
            three_network_bytes_per_tb(4 * MIB),
            238_418 * BUD_RECIPE_PUBLIC_BYTES
        );
        // A zero item size addresses nothing instead of dividing by zero.
        assert_eq!(recipes_for_content(BYTES_PER_TB, 0), 0);

        // Ten-year and monthly network cost per TB of 3.0 content.
        let custody_4mib = three_network_custody_usd_per_tb(4 * MIB, p);
        let monthly_4mib = three_network_monthly_usd_per_tb(4 * MIB, p);
        assert!(
            approx(monthly_4mib * 120.0, custody_4mib),
            "monthly must amortize over the ten-year custody period"
        );
        // Measured magnitudes: ~$0.00115 one-time capital per TB, ~$9.6e-6
        // per month at the ten-year amortization.
        assert!(
            (0.0005..0.005).contains(&custody_4mib),
            "recipe custody capital per TB: {custody_4mib}"
        );
        assert!(monthly_4mib < 0.000_1, "monthly: {monthly_4mib}");

        // Smaller items, same terabyte: more recipes, still under a cent at
        // 1 MiB, and a thousandth of a cent at 1 GiB.
        assert!(three_network_custody_usd_per_tb(MIB, p) < BUD_UPLOAD_BASE_USD);
        assert!(three_network_custody_usd_per_tb(GIB, p) < 0.000_1);

        // The honest break-even: below roughly 470 KiB per item the recipe
        // bytes alone exceed the $0.01 base over ten years, and the upload
        // excess rule (bud_upload_extra_fee_usd_per_tb) is what covers it.
        assert!(three_network_custody_usd_per_tb(512 * 1024, p) < BUD_UPLOAD_BASE_USD);
        assert!(three_network_custody_usd_per_tb(256 * 1024, p) > BUD_UPLOAD_BASE_USD);

        // Against the 2.0 held-body schedule: three orders of magnitude.
        let ratio = BUD_2_MONTHLY_USD_PER_TB / monthly_4mib;
        assert!(
            ratio > 1000.0,
            "3.0 must undercut 2.0 per TB per month by 1000x, got {ratio}x"
        );

        // The body itself is the user's device under the 1.0 contract; the
        // device-side ten-year cost of the same terabyte, for contrast, is
        // the HDD line (capital + continuous energy), not a network bill.
        let device_tb = crate::validator_cost::ten_year_storage_cost_usd_per_tb(p);
        assert!(device_tb > 100.0, "ten-year body custody: {device_tb}");
    }

    #[test]
    fn lubot_charge_debits_tokens_times_rate() {
        let mut wallet = PromptWallet::new(1.0);
        let fee = wallet.charge(1_000, 38.2).unwrap();
        assert!(approx(fee, 1_000.0 / 1_000_000.0 * 38.2));
        assert!(approx(wallet.balance_usd, 1.0 - fee));
    }

    #[test]
    fn lubot_charge_fails_when_the_balance_is_short() {
        let mut wallet = PromptWallet::new(0.001);
        let err = wallet.charge(1_000, 38.2).unwrap_err();
        assert!(err.needed_usd > err.balance_usd);
        assert!(approx(wallet.balance_usd, 0.001), "a failed charge debits nothing");
    }

    #[test]
    fn a_full_user_story_costs_the_published_numbers() {
        // Transfer $100, swap $100, bridge $100.
        let chain = transaction_fee_usd(TxClass::Transfer, 100.0)
            + transaction_fee_usd(TxClass::Swap, 100.0)
            + transaction_fee_usd(TxClass::Bridge, 100.0);
        assert!(approx(chain, 0.21 + 0.41 + 0.81));

        // Upload 1 TB whose ten-year custody cost is $4.50: $4.49 over the
        // $0.01 base.
        assert!(approx(bud_upload_extra_fee_usd_per_tb(4.5), 4.49));

        // A 2 000-token prompt at the measured $38.2/M serving rate.
        let mut wallet = PromptWallet::new(10.0);
        let prompt = wallet.charge(2_000, 38.2).unwrap();
        assert!(approx(prompt, 0.0764));
        assert!(approx(wallet.balance_usd, 10.0 - 0.0764));
    }
}
