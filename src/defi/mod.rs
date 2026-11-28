//! Native Deterministic DeFi Layer-1 Suite (`AMM` + `BatchAuction` + `Lending`
//! + `Options` + `OrderBook`).
//!
//! Strict consensus properties:
//! - Pure integer arithmetic with overflow protection (`zero f64/f32`).
//! - Canonical `BTreeMap` / `BTreeSet` deterministic state ordering.
//! - Anti-manipulation `MIN_TWAP_EPOCHS` & `LIQUIDATION_PENALTY_BPS` inherited directly
//!   from [`crate::settlement::liquidation_proof`].

#![forbid(unsafe_code)]

pub mod amm;
pub mod batch_auction;
pub mod lending;
pub mod options;
pub mod orderbook;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::core::address::Address;
use amm::AmmRegistry;
use batch_auction::{AuctionSide, BatchAuctionRegistry};
use lending::LendingRegistry;
use options::{OptionKind, OptionsRegistry};
use orderbook::{BookSide, OrderBookRegistry};

/// Combined consensus state across all 5 native DeFi primitives.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeFiEngine {
    pub amm: AmmRegistry,
    pub auctions: BatchAuctionRegistry,
    pub lending: LendingRegistry,
    pub options: OptionsRegistry,
    pub orderbooks: OrderBookRegistry,
}

impl DeFiEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            amm: AmmRegistry::new(),
            auctions: BatchAuctionRegistry::new(),
            lending: LendingRegistry::new(),
            options: OptionsRegistry::new(),
            orderbooks: OrderBookRegistry::new(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.amm.pools.is_empty()
            && self.auctions.batches.is_empty()
            && self.lending.markets.is_empty()
            && self.options.series.is_empty()
            && self.orderbooks.books.is_empty()
    }

    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        if self.is_empty() {
            return [0u8; 32];
        }
        let mut h = Sha3_256::new();
        h.update(b"BDLM_DEFI_ENGINE_V1");
        let len_prefix = 32u64.to_le_bytes();
        h.update(len_prefix);
        h.update(self.amm.state_root());
        h.update(len_prefix);
        h.update(self.auctions.state_root());
        h.update(len_prefix);
        h.update(self.lending.state_root());
        h.update(len_prefix);
        h.update(self.options.state_root());
        h.update(len_prefix);
        h.update(self.orderbooks.state_root());
        h.finalize().into()
    }
}

/// Canonical state-transition enum routed via `TransactionType::DeFi`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeFiTx {
    CreateAmmPool {
        pool_id: [u8; 32],
        asset_a: [u8; 32],
        asset_b: [u8; 32],
        amount_a: u128,
        amount_b: u128,
        fee_bps: u64,
    },
    AddAmmLiquidity {
        pool_id: [u8; 32],
        amount_a: u128,
        amount_b: u128,
    },
    RemoveAmmLiquidity {
        pool_id: [u8; 32],
        shares: u128,
    },
    SwapAmm {
        pool_id: [u8; 32],
        a_to_b: bool,
        amount_in: u128,
        min_amount_out: u128,
    },
    OpenBatchAuction {
        batch_id: [u8; 32],
        asset_base: [u8; 32],
        asset_quote: [u8; 32],
    },
    SubmitBatchOrder {
        batch_id: [u8; 32],
        side: AuctionSide,
        limit_price: u128,
        quantity: u128,
    },
    ClearBatchAuction {
        batch_id: [u8; 32],
    },
    CreateLendingMarket {
        market_id: [u8; 32],
        borrow_collateral_ratio_bps: u64,
        liquidation_threshold_bps: u64,
        base_rate_bps: u64,
    },
    SupplyLending {
        market_id: [u8; 32],
        amount: u128,
    },
    BorrowLendingFromAmmTwap {
        market_id: [u8; 32],
        twap_pool_id: [u8; 32],
        collateral_added: u128,
        borrow_amount: u128,
    },
    LiquidateLendingFromAmmTwap {
        borrower: Address,
        market_id: [u8; 32],
        twap_pool_id: [u8; 32],
        repay_debt: u128,
    },
    WriteOption {
        series_id: [u8; 32],
        kind: OptionKind,
        strike_price: u128,
        size: u128,
        premium: u128,
        expiry_epoch: u64,
    },
    BuyOption {
        series_id: [u8; 32],
    },
    SettleOptionFromAmmTwap {
        series_id: [u8; 32],
        twap_pool_id: [u8; 32],
    },
    PlaceBookOrder {
        book_id: [u8; 32],
        side: BookSide,
        price: u128,
        quantity: u128,
    },
    CancelBookOrder {
        book_id: [u8; 32],
        order_id: u64,
    },
}

/// Apply one [`DeFiTx`] atomically onto `engine` using staging rollback semantics.
///
/// # Errors
/// Returns an error string without mutating `engine` if any check fails.
pub fn execute_defi_on_engine(
    engine: &mut DeFiEngine,
    sender: Address,
    epoch: u64,
    tx: &DeFiTx,
) -> Result<u128, String> {
    let mut staged = engine.clone();
    let res = match tx {
        DeFiTx::CreateAmmPool {
            pool_id,
            asset_a,
            asset_b,
            amount_a,
            amount_b,
            fee_bps,
        } => staged.amm.create_pool(
            sender,
            amm::CreatePoolParams {
                pool_id: *pool_id,
                asset_a: *asset_a,
                asset_b: *asset_b,
                amount_a: *amount_a,
                amount_b: *amount_b,
                fee_bps: *fee_bps,
            },
            epoch,
        )?,
        DeFiTx::AddAmmLiquidity {
            pool_id,
            amount_a,
            amount_b,
        } => staged
            .amm
            .add_liquidity(sender, pool_id, *amount_a, *amount_b, epoch)?,
        DeFiTx::RemoveAmmLiquidity { pool_id, shares } => {
            let (a, b) = staged
                .amm
                .remove_liquidity(sender, pool_id, *shares, epoch)?;
            a.saturating_add(b)
        }
        DeFiTx::SwapAmm {
            pool_id,
            a_to_b,
            amount_in,
            min_amount_out,
        } => staged
            .amm
            .swap(pool_id, *a_to_b, *amount_in, *min_amount_out, epoch)?,
        DeFiTx::OpenBatchAuction {
            batch_id,
            asset_base,
            asset_quote,
        } => {
            staged
                .auctions
                .open_batch(*batch_id, *asset_base, *asset_quote)?;
            1
        }
        DeFiTx::SubmitBatchOrder {
            batch_id,
            side,
            limit_price,
            quantity,
        } => u128::from(staged.auctions.submit_order(
            sender,
            batch_id,
            *side,
            *limit_price,
            *quantity,
        )?),
        DeFiTx::ClearBatchAuction { batch_id } => {
            staged.auctions.clear_batch(batch_id)?.matched_volume
        }
        DeFiTx::CreateLendingMarket {
            market_id,
            borrow_collateral_ratio_bps,
            liquidation_threshold_bps,
            base_rate_bps,
        } => {
            staged.lending.create_market(
                *market_id,
                *borrow_collateral_ratio_bps,
                *liquidation_threshold_bps,
                *base_rate_bps,
            )?;
            1
        }
        DeFiTx::SupplyLending { market_id, amount } => {
            staged.lending.supply(sender, market_id, *amount)?;
            *amount
        }
        DeFiTx::BorrowLendingFromAmmTwap {
            market_id,
            twap_pool_id,
            collateral_added,
            borrow_amount,
        } => {
            let twap = staged.amm.twap_b_per_a_scaled(twap_pool_id)?;
            staged.lending.deposit_collateral_and_borrow(
                sender,
                market_id,
                *collateral_added,
                *borrow_amount,
                twap,
            )?;
            *borrow_amount
        }
        DeFiTx::LiquidateLendingFromAmmTwap {
            borrower,
            market_id,
            twap_pool_id,
            repay_debt,
        } => {
            let twap = staged.amm.twap_b_per_a_scaled(twap_pool_id)?;
            staged
                .lending
                .liquidate(*borrower, market_id, *repay_debt, twap)?
        }
        DeFiTx::WriteOption {
            series_id,
            kind,
            strike_price,
            size,
            premium,
            expiry_epoch,
        } => staged.options.write_series(
            sender,
            options::WriteOptionParams {
                series_id: *series_id,
                kind: *kind,
                strike_price: *strike_price,
                size: *size,
                premium: *premium,
                expiry_epoch: *expiry_epoch,
            },
        )?,
        DeFiTx::BuyOption { series_id } => staged.options.buy_series(sender, series_id)?,
        DeFiTx::SettleOptionFromAmmTwap {
            series_id,
            twap_pool_id,
        } => {
            let twap = staged.amm.twap_b_per_a_scaled(twap_pool_id)?;
            staged.options.settle_at_expiry(series_id, epoch, twap)?
        }
        DeFiTx::PlaceBookOrder {
            book_id,
            side,
            price,
            quantity,
        } => {
            let (_id, matched) = staged
                .orderbooks
                .place_limit_order(sender, *book_id, *side, *price, *quantity)?;
            matched
        }
        DeFiTx::CancelBookOrder { book_id, order_id } => {
            staged.orderbooks.cancel_order(sender, book_id, *order_id)?
        }
    };
    *engine = staged;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    #[test]
    fn full_defi_suite_amm_twap_lending_batch_options_clob_are_deterministic() {
        let mut engine = DeFiEngine::new();
        let alice = addr(1);
        let bob = addr(2);
        let pool_id = [0x11; 32];
        let a = [0xAA; 32];
        let b = [0xBB; 32];

        // Epoch 1..3 TWAP buildup + constant-product swap k preservation
        execute_defi_on_engine(
            &mut engine,
            alice,
            1,
            &DeFiTx::CreateAmmPool {
                pool_id,
                asset_a: a,
                asset_b: b,
                amount_a: 1_000_000,
                amount_b: 2_000_000,
                fee_bps: 30,
            },
        )
        .unwrap();
        // Second epoch swap
        let out = execute_defi_on_engine(
            &mut engine,
            bob,
            2,
            &DeFiTx::SwapAmm {
                pool_id,
                a_to_b: true,
                amount_in: 10_000,
                min_amount_out: 19_000,
            },
        )
        .unwrap();
        assert!(out > 19_000);
        // Too few TWAP epochs must fail lending borrow before epoch 3!
        let mkt = [0x22; 32];
        execute_defi_on_engine(
            &mut engine,
            alice,
            2,
            &DeFiTx::CreateLendingMarket {
                market_id: mkt,
                borrow_collateral_ratio_bps: 15_000,
                liquidation_threshold_bps: 12_000,
                base_rate_bps: 400,
            },
        )
        .unwrap();
        execute_defi_on_engine(
            &mut engine,
            alice,
            2,
            &DeFiTx::SupplyLending {
                market_id: mkt,
                amount: 50_000,
            },
        )
        .unwrap();
        assert!(execute_defi_on_engine(
            &mut engine,
            bob,
            2,
            &DeFiTx::BorrowLendingFromAmmTwap {
                market_id: mkt,
                twap_pool_id: pool_id,
                collateral_added: 10_000,
                borrow_amount: 1_000,
            },
        )
        .is_err());

        // Epoch 3 swap satisfies MIN_TWAP_EPOCHS = 3 -> borrow succeeds!
        execute_defi_on_engine(
            &mut engine,
            bob,
            3,
            &DeFiTx::SwapAmm {
                pool_id,
                a_to_b: false,
                amount_in: 5_000,
                min_amount_out: 1,
            },
        )
        .unwrap();
        execute_defi_on_engine(
            &mut engine,
            bob,
            3,
            &DeFiTx::BorrowLendingFromAmmTwap {
                market_id: mkt,
                twap_pool_id: pool_id,
                collateral_added: 10_000,
                borrow_amount: 1_000,
            },
        )
        .unwrap();

        // Batch auction uniform clearing price
        let batch_id = [0x33; 32];
        execute_defi_on_engine(
            &mut engine,
            alice,
            3,
            &DeFiTx::OpenBatchAuction {
                batch_id,
                asset_base: a,
                asset_quote: b,
            },
        )
        .unwrap();
        execute_defi_on_engine(
            &mut engine,
            alice,
            3,
            &DeFiTx::SubmitBatchOrder {
                batch_id,
                side: AuctionSide::Bid,
                limit_price: 105,
                quantity: 50,
            },
        )
        .unwrap();
        execute_defi_on_engine(
            &mut engine,
            bob,
            3,
            &DeFiTx::SubmitBatchOrder {
                batch_id,
                side: AuctionSide::Ask,
                limit_price: 95,
                quantity: 40,
            },
        )
        .unwrap();
        let matched_batch = execute_defi_on_engine(
            &mut engine,
            alice,
            3,
            &DeFiTx::ClearBatchAuction { batch_id },
        )
        .unwrap();
        assert_eq!(matched_batch, 40);

        // CLOB crossing match
        let book_id = [0x44; 32];
        execute_defi_on_engine(
            &mut engine,
            alice,
            3,
            &DeFiTx::PlaceBookOrder {
                book_id,
                side: BookSide::Ask,
                price: 100,
                quantity: 25,
            },
        )
        .unwrap();
        let clob_fill = execute_defi_on_engine(
            &mut engine,
            bob,
            3,
            &DeFiTx::PlaceBookOrder {
                book_id,
                side: BookSide::Bid,
                price: 105,
                quantity: 10,
            },
        )
        .unwrap();
        assert_eq!(clob_fill, 10);

        // Cash-secured put settled after expiry against TWAP
        let opt_id = [0x55; 32];
        let locked = execute_defi_on_engine(
            &mut engine,
            alice,
            3,
            &DeFiTx::WriteOption {
                series_id: opt_id,
                kind: OptionKind::CashSecuredPut,
                strike_price: 3 * crate::defi::amm::PRICE_SCALE,
                size: 10,
                premium: 5,
                expiry_epoch: 4,
            },
        )
        .unwrap();
        assert_eq!(locked, 30 * crate::defi::amm::PRICE_SCALE);
        execute_defi_on_engine(
            &mut engine,
            bob,
            3,
            &DeFiTx::BuyOption { series_id: opt_id },
        )
        .unwrap();
        let opt_payout = execute_defi_on_engine(
            &mut engine,
            bob,
            4,
            &DeFiTx::SettleOptionFromAmmTwap {
                series_id: opt_id,
                twap_pool_id: pool_id,
            },
        )
        .unwrap();
        assert!(opt_payout > 0);
        assert_ne!(engine.state_root(), [0u8; 32]);
    }
}
