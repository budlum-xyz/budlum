//! The published fee schedule, as arithmetic.
//!
//! Fees are quoted in USD, the unit an operator shows a user. Three axes:
//!
//! * **Chain transactions** — a base plus an ad-valorem cut, by class:
//!   transfer `$0.01 + 0.2%`, swap `$0.01 + 0.4%`, bridge `$0.01 + 0.8%`.
//! * **B.U.D. storage** — the upload transaction's $0.01 base fee covers
//!   ten-year custody of the recipe (a fixed-size commitment, ~74 bytes).
//!   If the ten-year cost of a terabyte exceeds that cent, the excess is
//!   charged with the transaction fee. Uploaded content stays alive ten
//!   years; on expiry the owner may delete it, and if they do not, it moves
//!   to an open auction and transfers after one month.
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
pub const BUD_CUSTODY_YEARS: u32 = 10;

/// Expired but undeleted content transfers by open auction lasting one month.
pub const BUD_EXPIRY_AUCTION_DAYS: u32 = 30;

/// Extra fee per terabyte on upload: the ten-year custody cost above the base
/// fee already paid. Zero while the cost fits inside $0.01, which is always
/// the case for a recipe; it fires only when the ten-year cost of the terabyte
/// really exceeds a cent.
#[must_use]
pub fn bud_upload_extra_fee_usd_per_tb(ten_year_storage_cost_usd: f64) -> f64 {
    (ten_year_storage_cost_usd - BUD_UPLOAD_BASE_USD).max(0.0)
}

/// Where a piece of uploaded content sits in its custody lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyPhase {
    /// Within its ten years, owner holding.
    Live,
    /// The owner deleted it.
    Deleted,
    /// Expired and undeleted: inside the one-month open auction.
    Auctioning,
    /// The auction closed; custody transferred to the winner.
    Transferred,
}

/// The custody phase from three facts: has the owner deleted it, has the
/// ten years elapsed, and has the one-month auction elapsed.
#[must_use]
pub fn custody_phase(owner_deleted: bool, expired: bool, auction_over: bool) -> CustodyPhase {
    match (owner_deleted, expired, auction_over) {
        (true, _, _) => CustodyPhase::Deleted,
        (false, false, _) => CustodyPhase::Live,
        (false, true, false) => CustodyPhase::Auctioning,
        (false, true, true) => CustodyPhase::Transferred,
    }
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
    fn bud_custody_is_ten_years_and_the_auction_one_month() {
        assert_eq!(BUD_CUSTODY_YEARS, 10);
        assert_eq!(BUD_EXPIRY_AUCTION_DAYS, 30);
    }

    #[test]
    fn custody_phases_follow_deleted_expired_auction() {
        assert_eq!(custody_phase(false, false, false), CustodyPhase::Live);
        assert_eq!(custody_phase(true, false, false), CustodyPhase::Deleted);
        assert_eq!(custody_phase(true, true, true), CustodyPhase::Deleted);
        assert_eq!(custody_phase(false, true, false), CustodyPhase::Auctioning);
        assert_eq!(custody_phase(false, true, true), CustodyPhase::Transferred);
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

        // Upload 1 TB whose ten-year cost is $4.50: $4.49 over the $0.01 base.
        assert!(approx(bud_upload_extra_fee_usd_per_tb(4.5), 4.49));

        // A 2 000-token prompt at the measured $38.2/M serving rate.
        let mut wallet = PromptWallet::new(10.0);
        let prompt = wallet.charge(2_000, 38.2).unwrap();
        assert!(approx(prompt, 0.0764));
        assert!(approx(wallet.balance_usd, 10.0 - 0.0764));
    }
}
