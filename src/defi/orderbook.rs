//! Deterministic On-Chain Central Limit Order Book (`OrderBookRegistry`)
//! using strict `BTreeMap` price-time priority ordering and zero-drift integer fills.
//!
//! WIRING: wired through `src/defi/mod.rs` (`DeFiTx`) into `TransactionType::DeFi`
//! and `AccountState::defi`.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::core::address::Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BookSide {
    Bid,
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitOrder {
    pub order_id: u64,
    pub owner: Address,
    pub side: BookSide,
    pub price: u128,
    pub remaining: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderBook {
    pub book_id: [u8; 32],
    pub next_order_id: u64,
    pub bids: BTreeMap<u128, VecDeque<LimitOrder>>,
    pub asks: BTreeMap<u128, VecDeque<LimitOrder>>,
    pub fills_count: u64,
    pub total_matched_qty: u128,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderBookRegistry {
    #[serde(with = "crate::core::map_keys")]
    pub books: BTreeMap<[u8; 32], OrderBook>,
}

impl OrderBookRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            books: BTreeMap::new(),
        }
    }

    pub fn place_limit_order(
        &mut self,
        owner: Address,
        book_id: [u8; 32],
        side: BookSide,
        price: u128,
        quantity: u128,
    ) -> Result<(u64, u128), String> {
        if book_id == [0u8; 32] || price == 0 || quantity == 0 {
            return Err(String::from("invalid book order parameters"));
        }
        let book = self.books.entry(book_id).or_insert(OrderBook {
            book_id,
            next_order_id: 1,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            fills_count: 0,
            total_matched_qty: 0,
        });
        let order_id = book.next_order_id;
        book.next_order_id = book
            .next_order_id
            .checked_add(1)
            .ok_or_else(|| String::from("order_id overflow"))?;

        let mut remaining = quantity;
        let mut matched: u128 = 0;

        match side {
            BookSide::Bid => {
                while remaining > 0 {
                    let Some((&best_ask, _)) = book.asks.first_key_value() else {
                        break;
                    };
                    if best_ask > price {
                        break;
                    }
                    let queue = book.asks.get_mut(&best_ask);
                    let Some(q) = queue else { break };
                    while remaining > 0 {
                        let Some(front) = q.front_mut() else { break };
                        let fill = remaining.min(front.remaining);
                        remaining -= fill;
                        front.remaining -= fill;
                        matched = matched.saturating_add(fill);
                        book.fills_count = book.fills_count.saturating_add(1);
                        book.total_matched_qty = book.total_matched_qty.saturating_add(fill);
                        if front.remaining == 0 {
                            q.pop_front();
                        }
                    }
                    if book.asks.get(&best_ask).is_some_and(VecDeque::is_empty) {
                        book.asks.remove(&best_ask);
                    }
                }
                if remaining > 0 {
                    book.bids.entry(price).or_default().push_back(LimitOrder {
                        order_id,
                        owner,
                        side,
                        price,
                        remaining,
                    });
                }
            }
            BookSide::Ask => {
                while remaining > 0 {
                    let Some((&best_bid, _)) = book.bids.last_key_value() else {
                        break;
                    };
                    if best_bid < price {
                        break;
                    }
                    let Some(q) = book.bids.get_mut(&best_bid) else {
                        break;
                    };
                    while remaining > 0 {
                        let Some(front) = q.front_mut() else { break };
                        let fill = remaining.min(front.remaining);
                        remaining -= fill;
                        front.remaining -= fill;
                        matched = matched.saturating_add(fill);
                        book.fills_count = book.fills_count.saturating_add(1);
                        book.total_matched_qty = book.total_matched_qty.saturating_add(fill);
                        if front.remaining == 0 {
                            q.pop_front();
                        }
                    }
                    if book.bids.get(&best_bid).is_some_and(VecDeque::is_empty) {
                        book.bids.remove(&best_bid);
                    }
                }
                if remaining > 0 {
                    book.asks.entry(price).or_default().push_back(LimitOrder {
                        order_id,
                        owner,
                        side,
                        price,
                        remaining,
                    });
                }
            }
        }
        Ok((order_id, matched))
    }

    pub fn cancel_order(
        &mut self,
        caller: Address,
        book_id: &[u8; 32],
        order_id: u64,
    ) -> Result<u128, String> {
        let book = self
            .books
            .get_mut(book_id)
            .ok_or_else(|| String::from("unknown orderbook"))?;
        for q in book.bids.values_mut() {
            if let Some(pos) = q.iter().position(|o| o.order_id == order_id) {
                if !q.get(pos).is_some_and(|o| o.owner == caller) {
                    return Err(String::from("only order owner may cancel"));
                }
                let removed = q.remove(pos).map_or(0, |o| o.remaining);
                book.bids.retain(|_, v| !v.is_empty());
                return Ok(removed);
            }
        }
        for q in book.asks.values_mut() {
            if let Some(pos) = q.iter().position(|o| o.order_id == order_id) {
                if !q.get(pos).is_some_and(|o| o.owner == caller) {
                    return Err(String::from("only order owner may cancel"));
                }
                let removed = q.remove(pos).map_or(0, |o| o.remaining);
                book.asks.retain(|_, v| !v.is_empty());
                return Ok(removed);
            }
        }
        Err(String::from("order_id not found"))
    }

    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_DEFI_CLOB_V1");
        for (id, book) in &self.books {
            h.update(id);
            h.update(book.fills_count.to_le_bytes());
            h.update(book.total_matched_qty.to_le_bytes());
        }
        h.finalize().into()
    }
}
