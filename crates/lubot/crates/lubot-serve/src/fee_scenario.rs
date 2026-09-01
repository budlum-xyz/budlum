//! The published fee schedule, as arithmetic.
//!
//! Fees are quoted in USD, the unit an operator shows a user. Three axes:
//!
//! * **Chain transactions** - a base plus an ad-valorem cut, by class:
//!   transfer `$0.01 + 0.2%`, swap `$0.01 + 0.4%`, bridge `$0.01 + 0.8%`.
//! * **B.U.D. storage, by version** - 1.0 charges only the share NFT's
//!   transaction fee (content stays on the user's device, so there is no
//!   storage cost to charge); 2.0 bills `$0.016/TB` monthly for the held
//!   body; 3.0 charges the `$0.01` upload base plus the ten-year recipe
//!   custody cost on top of it (user decision 2026-08-31: the base is a
//!   transaction fee, custody is priced separately and added). The uploader
//!   chooses the custody duration: ten years is the floor, a hundred is the
//!   ceiling, and every year above ten adds one tenth of the ten-year cost.
//!   Nothing is billed monthly. Uploaded content stays alive for the chosen
//!   duration; on expiry the owner may delete it, and if they do not, it
//!   moves to an open auction and transfers after one month.
//! * **Lubot serving** - token-metered like an API: every prompt debits its
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

/// The upload transaction's base fee, paid by the uploader on every upload.
/// It is a transaction fee only: the ten-year recipe custody cost is charged
/// on top of it (see [`bud_upload_extra_fee_usd_per_tb`]), never inside it.
pub const BUD_UPLOAD_BASE_USD: f64 = 0.01;

/// A 3.0 recipe is fixed-size, no matter how large the content was: the
/// sealed commitment is 40 bytes and the public recipe 74 bytes.
pub const BUD_RECIPE_SEALED_BYTES: u64 = 40;
pub const BUD_RECIPE_PUBLIC_BYTES: u64 = 74;

/// 3.0 keeps uploaded content alive at least this many years: the floor of
/// the duration the uploader picks.
///
/// User decision 2026-08-31 (updated): ten years is the base promise, and
/// its measured cost is charged on top of the `$0.01` upload base (worst
/// measured case $0.0092 per TB at 512 KiB items). The uploader may choose a
/// longer custody, up to [`BUD_MAX_CUSTODY_YEARS`], priced pro rata.
pub const BUD_CUSTODY_YEARS: u32 = 10;

/// The ceiling of the custody duration an uploader may choose, in years.
///
/// User decision 2026-08-31: nobody can buy more than a hundred years of
/// custody in one upload; a request outside `10..=100` is refused, never
/// silently clamped.
pub const BUD_MAX_CUSTODY_YEARS: u32 = 100;

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
    /// 3.0: a recipe. The upload base plus the ten-year custody cost are
    /// charged once at upload; nothing is billed monthly.
    V3_0,
}

impl BudVersion {
    /// Monthly storage fee for `tb` terabytes, in dollars.
    ///
    /// 1.0 holds nothing (the bytes are the user's own), 2.0 bills the
    /// measured per-terabyte rate, and 3.0 bills nothing monthly: its
    /// custody was paid once, at upload, on top of the base fee.
    #[must_use]
    pub fn monthly_storage_fee_usd(self, tb: f64) -> f64 {
        match self {
            BudVersion::V1_0 => 0.0,
            BudVersion::V2_0 => tb * BUD_2_MONTHLY_USD_PER_TB,
            BudVersion::V3_0 => 0.0,
        }
    }
}

/// Extra fee per terabyte on upload: the full ten-year custody cost, added
/// on top of the `$0.01` base (user decision 2026-08-31: the base is a
/// transaction fee and no longer absorbs custody; the old "excess above the
/// cent" rule is gone with the decision it belonged to).
#[must_use]
pub fn bud_upload_extra_fee_usd_per_tb(ten_year_storage_cost_usd: f64) -> f64 {
    ten_year_storage_cost_usd.max(0.0)
}

/// Total upload fee per terabyte: the base plus the ten-year custody cost.
#[must_use]
pub fn bud_upload_fee_usd_per_tb(ten_year_storage_cost_usd: f64) -> f64 {
    BUD_UPLOAD_BASE_USD + bud_upload_extra_fee_usd_per_tb(ten_year_storage_cost_usd)
}

/// Price of extending custody from the ten-year floor to `custody_years`,
/// per terabyte, given the measured ten-year custody cost.
///
/// Pro rata: each year above ten adds one tenth of the ten-year cost, so a
/// hundred years costs nine times the ten-year figure on top of it. A
/// duration outside `10..=100` is a refusal ([`None`]), never a clamp: the
/// schedule does not sell what the user did not ask for.
///
/// # Errors
///
/// `None` when `custody_years` is below [`BUD_CUSTODY_YEARS`] or above
/// [`BUD_MAX_CUSTODY_YEARS`].
#[must_use]
pub fn bud_extension_fee_usd_per_tb(ten_year_storage_cost_usd: f64, custody_years: u32) -> Option<f64> {
    if !(BUD_CUSTODY_YEARS..=BUD_MAX_CUSTODY_YEARS).contains(&custody_years) {
        return None;
    }
    let extra_years = f64::from(custody_years - BUD_CUSTODY_YEARS);
    Some(ten_year_storage_cost_usd.max(0.0) * extra_years / f64::from(BUD_CUSTODY_YEARS))
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
    fn the_extra_fee_is_the_full_ten_year_cost_on_top_of_the_base() {
        // 2026-08-31 (updated): custody is added to the base, never absorbed
        // by it. The extra is the whole ten-year cost.
        assert!(approx(bud_upload_extra_fee_usd_per_tb(0.005), 0.005));
        assert!(approx(bud_upload_extra_fee_usd_per_tb(0.01), 0.01));
        assert!(approx(bud_upload_extra_fee_usd_per_tb(112.52), 112.52));
        // The total the uploader pays per terabyte is base plus that cost.
        assert!(approx(bud_upload_fee_usd_per_tb(0.0092), 0.01 + 0.0092));
        assert!(approx(bud_upload_fee_usd_per_tb(0.0), BUD_UPLOAD_BASE_USD));
    }

    #[test]
    fn custody_extension_is_pro_rata_and_capped_at_a_hundred_years() {
        let ten_year = 0.0092f64;
        // The floor itself adds nothing.
        assert!(approx(bud_extension_fee_usd_per_tb(ten_year, 10).unwrap(), 0.0));
        // Each year above ten is one tenth of the ten-year cost.
        assert!(approx(bud_extension_fee_usd_per_tb(ten_year, 20).unwrap(), ten_year));
        assert!(approx(bud_extension_fee_usd_per_tb(ten_year, 55).unwrap(), ten_year * 4.5));
        // The ceiling is a hundred years: nine times the ten-year cost extra.
        assert!(approx(bud_extension_fee_usd_per_tb(ten_year, 100).unwrap(), ten_year * 9.0));
        // Outside the schedule: refused, not clamped.
        assert!(bud_extension_fee_usd_per_tb(ten_year, 9).is_none());
        assert!(bud_extension_fee_usd_per_tb(ten_year, 101).is_none());
        assert!(bud_extension_fee_usd_per_tb(ten_year, 0).is_none());
    }

    #[test]
    fn a_recipe_costs_less_than_a_cent_and_a_body_costs_more() {
        use crate::validator_cost::{
            market_pricelist, nvme_custody_usd, ten_year_storage_cost_usd_per_tb,
        };
        // The 3.0 held unit is the fixed-size recipe, not the terabytes.
        let recipe = nvme_custody_usd(BUD_RECIPE_PUBLIC_BYTES, market_pricelist());
        let body = ten_year_storage_cost_usd_per_tb(market_pricelist());
        assert!(
            recipe < BUD_UPLOAD_BASE_USD,
            "a recipe ({BUD_RECIPE_PUBLIC_BYTES} B) costs less than the base cent: {recipe}"
        );
        assert!(
            body > BUD_UPLOAD_BASE_USD,
            "a full terabyte body over ten years costs more than a cent: {body}"
        );
        // Both are charged on top of the base now; the recipe simply stays
        // under a cent while the body dwarfs it.
        assert!(approx(bud_upload_extra_fee_usd_per_tb(recipe), recipe));
        assert!(approx(bud_upload_extra_fee_usd_per_tb(body), body));
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
        // User decision 2026-08-31 (updated): the ten-year floor, a hundred
        // year ceiling, and the expiry auction runs one month. Custody cost
        // is charged on top of the base, not covered by it.
        assert_eq!(BUD_CUSTODY_YEARS, 10);
        assert_eq!(BUD_MAX_CUSTODY_YEARS, 100);
        assert_eq!(BUD_EXPIRY_AUCTION_DAYS, 30);
        // Measured scale of what gets added: for items >= 512 KiB the recipe
        // capital of a whole terabyte stays under a cent even at the floor.
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
        // the $0.01 base: custody is added on top, in full.
        assert!(approx(bud_upload_extra_fee_usd_per_tb(4.5), 4.5));
        assert!(approx(bud_upload_fee_usd_per_tb(4.5), 4.51));

        // A 2 000-token prompt at the measured $38.2/M serving rate.
        let mut wallet = PromptWallet::new(10.0);
        let prompt = wallet.charge(2_000, 38.2).unwrap();
        assert!(approx(prompt, 0.0764));
        assert!(approx(wallet.balance_usd, 10.0 - 0.0764));
    }
}
