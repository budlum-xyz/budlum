//! MEV-resistant Uniform Clearing-Price Batch Auctions (`BatchAuction`).
//! Orders within a batch settle at ONE uniform clearing price maximizing
//! matched volume, preventing front-running and sandwich extraction.
//!
//! WIRING: wired through `src/defi/mod.rs` (`DeFiTx`) into `TransactionType::DeFi`
//! and `AccountState::defi`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::core::address::Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuctionSide {
    Bid,
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchOrder {
    pub order_id: u64,
    pub trader: Address,
    pub side: AuctionSide,
    pub limit_price: u128,
    pub quantity: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchClearingResult {
    pub batch_id: [u8; 32],
    pub clearing_price: u128,
    pub matched_volume: u128,
    pub filled_orders: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionBatch {
    pub batch_id: [u8; 32],
    pub asset_base: [u8; 32],
    pub asset_quote: [u8; 32],
    pub next_order_id: u64,
    pub settled: Option<BatchClearingResult>,
    pub orders: Vec<BatchOrder>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAuctionRegistry {
    #[serde(with = "crate::core::map_keys")]
    pub batches: BTreeMap<[u8; 32], AuctionBatch>,
}

impl BatchAuctionRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            batches: BTreeMap::new(),
        }
    }

    pub fn open_batch(
        &mut self,
        batch_id: [u8; 32],
        asset_base: [u8; 32],
        asset_quote: [u8; 32],
    ) -> Result<(), String> {
        if batch_id == [0u8; 32] || asset_base == asset_quote {
            return Err(String::from("invalid batch_id or identical assets"));
        }
        if self.batches.contains_key(&batch_id) {
            return Err(String::from("batch already exists"));
        }
        self.batches.insert(
            batch_id,
            AuctionBatch {
                batch_id,
                asset_base,
                asset_quote,
                next_order_id: 1,
                settled: None,
                orders: Vec::new(),
            },
        );
        Ok(())
    }

    pub fn submit_order(
        &mut self,
        trader: Address,
        batch_id: &[u8; 32],
        side: AuctionSide,
        limit_price: u128,
        quantity: u128,
    ) -> Result<u64, String> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| String::from("unknown batch"))?;
        if batch.settled.is_some() {
            return Err(String::from("batch already cleared"));
        }
        if limit_price == 0 || quantity == 0 {
            return Err(String::from("price and quantity must be positive"));
        }
        let id = batch.next_order_id;
        batch.next_order_id = batch
            .next_order_id
            .checked_add(1)
            .ok_or_else(|| String::from("order_id overflow"))?;
        batch.orders.push(BatchOrder {
            order_id: id,
            trader,
            side,
            limit_price,
            quantity,
        });
        Ok(id)
    }

    /// Clear `batch_id` at the unique uniform price maximizing matched base quantity.
    pub fn clear_batch(&mut self, batch_id: &[u8; 32]) -> Result<BatchClearingResult, String> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| String::from("unknown batch"))?;
        if batch.settled.is_some() {
            return Err(String::from("batch already cleared"));
        }
        let mut candidate_prices: Vec<u128> = batch.orders.iter().map(|o| o.limit_price).collect();
        candidate_prices.sort_unstable();
        candidate_prices.dedup();

        let mut best_price: u128 = 0;
        let mut best_volume: u128 = 0;
        for &p in &candidate_prices {
            let demand: u128 = batch
                .orders
                .iter()
                .filter(|o| o.side == AuctionSide::Bid && o.limit_price >= p)
                .fold(0u128, |acc, o| acc.saturating_add(o.quantity));
            let supply: u128 = batch
                .orders
                .iter()
                .filter(|o| o.side == AuctionSide::Ask && o.limit_price <= p)
                .fold(0u128, |acc, o| acc.saturating_add(o.quantity));
            let matched = demand.min(supply);
            if matched > best_volume {
                best_volume = matched;
                best_price = p;
            }
        }
        if best_volume == 0 {
            return Err(String::from("no crossing demand/supply in batch"));
        }
        let filled_orders = batch
            .orders
            .iter()
            .filter(|o| match o.side {
                AuctionSide::Bid => o.limit_price >= best_price,
                AuctionSide::Ask => o.limit_price <= best_price,
            })
            .count();
        let res = BatchClearingResult {
            batch_id: batch.batch_id,
            clearing_price: best_price,
            matched_volume: best_volume,
            filled_orders,
        };
        batch.settled = Some(res.clone());
        Ok(res)
    }

    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_DEFI_BATCH_AUCTION_V1");
        for (id, b) in &self.batches {
            h.update(id);
            h.update((b.orders.len() as u64).to_le_bytes());
            if let Some(res) = &b.settled {
                h.update([1]);
                h.update(res.clearing_price.to_le_bytes());
                h.update(res.matched_volume.to_le_bytes());
            } else {
                h.update([0]);
            }
        }
        h.finalize().into()
    }
}
