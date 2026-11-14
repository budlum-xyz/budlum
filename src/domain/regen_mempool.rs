//! The regeneration mempool: transactions that a
//! reversion gave up are kept, not dropped, and offered again once the node
//! has grown back.
//!
//! WIRING: wired - the node runtime stashes the transactions of the heights a
//! `TickOutcome::Reverted` gave up (`Node::regen_health_tick` in
//! `src/network/node.rs`) and, on the first healthy tick after the ledger is
//! back at the adult stage, takes the ones the canonical chain did not include
//! and re-submits and re-broadcasts them. Rules are pinned by this file's
//! tests.
//!
//! A reversion rolls the node's view back to a sealed stage. Every
//! transaction that sat in the heights above it would be lost with the view if
//! nobody kept it, and a user whose transfer was confirmed on this node would
//! see it vanish. The store is bounded in count, bytes and age, deduplicated
//! by hash, and it re-offers only what the canonical chain does not contain:
//! it never decides validity, the mempool door and the executor do that again.

use std::collections::BTreeMap;

use crate::core::transaction::Transaction;

/// Transactions kept at most.
pub const MAX_STASHED_TXS: usize = 10_000;
/// Bytes kept at most, over the transport measure of a transaction.
pub const MAX_STASHED_BYTES: usize = 64 * 1024 * 1024;
/// Heights after which a stashed transaction is dropped as stale.
pub const STASH_TTL_HEIGHTS: u64 = 10_000;

#[derive(Debug, Clone)]
struct Stashed {
    tx: Transaction,
    height: u64,
    bytes: usize,
}

/// The store of transactions a reversion gave up.
#[derive(Debug, Clone, Default)]
pub struct RegenMempool {
    entries: BTreeMap<String, Stashed>,
    bytes: usize,
}

impl RegenMempool {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many transactions are kept.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is kept.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The bytes kept.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Keep the transactions of a height the reversion gave up. `bytes_of` is
    /// the transport measure of one transaction. A transaction already kept is
    /// not kept twice; when the store is full the oldest height makes room, and
    /// a transaction larger than the whole budget is refused. Returns how many
    /// were kept.
    pub fn stash(
        &mut self,
        txs: &[Transaction],
        height: u64,
        bytes_of: &dyn Fn(&Transaction) -> usize,
    ) -> usize {
        let mut kept = 0;
        for tx in txs {
            if tx.hash.is_empty() || self.entries.contains_key(&tx.hash) {
                continue;
            }
            let bytes = bytes_of(tx);
            if bytes > MAX_STASHED_BYTES {
                continue;
            }
            while self.entries.len() >= MAX_STASHED_TXS
                || self.bytes.saturating_add(bytes) > MAX_STASHED_BYTES
            {
                if !self.evict_oldest() {
                    break;
                }
            }
            self.bytes += bytes;
            self.entries.insert(
                tx.hash.clone(),
                Stashed {
                    tx: tx.clone(),
                    height,
                    bytes,
                },
            );
            kept += 1;
        }
        kept
    }

    fn evict_oldest(&mut self) -> bool {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.height)
            .map(|(hash, _)| hash.clone());
        match oldest.and_then(|hash| self.entries.remove(&hash)) {
            Some(entry) => {
                self.bytes = self.bytes.saturating_sub(entry.bytes);
                true
            }
            None => false,
        }
    }

    /// Empty the store for re-broadcast at `current_height`: the transactions
    /// the canonical chain does not contain (`is_confirmed` says which it
    /// does) and that are not older than [`STASH_TTL_HEIGHTS`]. Everything
    /// else is dropped.
    pub fn take_unconfirmed(
        &mut self,
        current_height: u64,
        is_confirmed: &dyn Fn(&str) -> bool,
    ) -> Vec<Transaction> {
        let entries = std::mem::take(&mut self.entries);
        self.bytes = 0;
        entries
            .into_values()
            .filter(|entry| {
                current_height.saturating_sub(entry.height) <= STASH_TTL_HEIGHTS
                    && !is_confirmed(&entry.tx.hash)
            })
            .map(|entry| entry.tx)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(hash: &str) -> Transaction {
        let mut tx = Transaction::genesis();
        tx.hash = hash.to_string();
        tx
    }

    fn size(_: &Transaction) -> usize {
        100
    }

    #[test]
    fn a_transaction_is_kept_once_and_returned_when_unconfirmed() {
        let mut store = RegenMempool::new();
        assert_eq!(store.stash(&[tx("a"), tx("b"), tx("a")], 50, &size), 2);
        assert_eq!(store.len(), 2);
        assert_eq!(store.bytes(), 200);
        let back = store.take_unconfirmed(60, &|hash| hash == "a");
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].hash, "b");
        assert!(store.is_empty());
        assert_eq!(store.bytes(), 0);
    }

    #[test]
    fn a_stale_transaction_is_dropped() {
        let mut store = RegenMempool::new();
        store.stash(&[tx("old")], 10, &size);
        assert!(store
            .take_unconfirmed(10 + STASH_TTL_HEIGHTS + 1, &|_| false)
            .is_empty());
        store.stash(&[tx("fresh")], 10, &size);
        assert_eq!(
            store
                .take_unconfirmed(10 + STASH_TTL_HEIGHTS, &|_| false)
                .len(),
            1
        );
    }

    #[test]
    fn the_count_bound_evicts_the_oldest_height() {
        let mut store = RegenMempool::new();
        let first: Vec<Transaction> = (0..MAX_STASHED_TXS).map(|i| tx(&format!("o{i}"))).collect();
        store.stash(&first, 1, &size);
        assert_eq!(store.len(), MAX_STASHED_TXS);
        store.stash(&[tx("new")], 2, &size);
        assert_eq!(store.len(), MAX_STASHED_TXS);
        let back = store.take_unconfirmed(3, &|_| false);
        assert!(back.iter().any(|t| t.hash == "new"));
    }

    #[test]
    fn the_byte_bound_refuses_an_oversize_transaction_and_evicts_for_room() {
        let mut store = RegenMempool::new();
        assert_eq!(store.stash(&[tx("huge")], 1, &|_| MAX_STASHED_BYTES + 1), 0);
        assert_eq!(store.stash(&[tx("a")], 1, &|_| MAX_STASHED_BYTES), 1);
        assert_eq!(store.stash(&[tx("b")], 2, &|_| 10), 1);
        assert_eq!(store.len(), 1, "the old one made room");
        assert!(store.bytes() <= MAX_STASHED_BYTES);
    }

    #[test]
    fn a_transaction_without_a_hash_is_not_kept() {
        let mut store = RegenMempool::new();
        assert_eq!(store.stash(&[tx("")], 1, &size), 0);
    }
}
