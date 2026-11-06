//! The mobile duty lane: the free, rate limited pool lane for validator duty
//! batches.
//!
//! Directive section 7.3 item 6 defines the lane. A Mobile validator's duty
//! transactions, the batch of `CustodyAck`, `CustodyProofBatch` and the
//! presence aggregate, are free, are limited to one batch per validator per
//! window, and may fill at most 20 percent of a block's bytes (TESTNET-DEFAULT,
//! section 11.10). Section 8.6.3 lists the lane beside the envelope lanes of
//! the pool, and section 11.6 repeats the stake rule the lane belongs to.
//!
//! # Why the rule counts batches and not items
//!
//! The directive limits "one batch per validator per window", not one custody
//! acknowledgement and one proof batch. A batch is the unit, because a phone
//! that answers three audits and signals presence once is doing one piece of
//! duty work in one window, and splitting it across three transactions would
//! spend three slots of a lane whose whole purpose is to stay small. Nothing
//! here therefore counts or limits items per kind: the classification below
//! answers "is this a duty transaction", and the window answers "which one".
//!
//! The presence aggregate is the third item of the batch. It reaches the pool
//! with the rest of the batch when its carrier lands (WP-13 defines the
//! presence protocol); the lane's accounting does not change when it does,
//! because the rule is per validator and per window.
//!
//! # Whose batch it is
//!
//! A batch is identified by the transaction's sender, which is the validator's
//! own account: the operator signature inside the batch is the executor's
//! check, and the pool cannot read it, so the pool counts what it can see and
//! leaves the rest to the door that applies the transaction. One consequence
//! is deliberate: a batch cannot be relayed by a third party, because a relayed
//! batch would be a different sender and would take a second slot in the
//! window.
//!
//! # Why the free rule is safe
//!
//! A free transaction class is a spam door unless something bounds it, and two
//! things bound this one. The rate limit caps a validator at one batch per
//! window, so the number of free transactions is bounded by the number of
//! registered Mobile validators, and the block share caps how much of a block
//! the lane can occupy however many batches are pending. The stake floor of
//! the class (section 11.6) is what makes registering a validator a cost.
//!
//! WIRING: [`is_duty`], [`window_at`] and [`block_share_bytes`] are called from
//! `mempool::pool::Mempool::admit_at` and `Mempool::get_sorted_transactions`,
//! which are the production doors for every admitted transaction and for every
//! block the producer builds. [`block_bytes`] is the measure both use, and it
//! is the block validator's own: `serde_json` of the transaction plus the one
//! byte that separates array entries in `validate_block_size`.

use crate::core::transaction::{Transaction, TransactionType};
use crate::storage::bud3::tx::StorageTxV3;

/// The share of a block's bytes the duty lane may occupy (section 7.3, item
/// 6: 20 percent, TESTNET-DEFAULT).
const DUTY_LANE_BLOCK_SHARE_PERCENT: usize = 20;

/// The mobile presence window in milliseconds.
///
/// Section 7.8 writes the Mobile window as four epochs, which the testnet
/// clock makes ten minutes, and section 11.10 lists the same window as a
/// parameter. The lane reads the window off the wall clock at admission, in
/// the same way the pool already reads it for `tx_ttl_secs`: this is an
/// admission rule, never a consensus rule, so a node's clock cannot change
/// what a block means.
const MOBILE_DUTY_WINDOW_MS: u64 = 10 * 60 * 1000;

/// Why the lane refused a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DutyRefusal {
    /// The validator already holds a batch for this window.
    ///
    /// A replacement of the pending batch reuses its nonce and is admitted;
    /// a second batch does not.
    SecondBatchInWindow {
        /// The window the batch was offered for.
        window: u64,
        /// The nonce of the batch already in the pool.
        open_nonce: u64,
    },
    /// The batch would push the lane past its pool byte ceiling.
    ///
    /// The ceiling is a few blocks of the lane's share. A pool that held a
    /// whole window of batches could not clear them in one block anyway, and
    /// an unbounded lane would move the spam door from the fee floor to the
    /// pool byte budget.
    LaneBytesFull {
        /// The bytes the lane would hold.
        lane_bytes: usize,
        /// The ceiling it would cross.
        cap: usize,
    },
}

impl std::fmt::Display for DutyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DutyRefusal::SecondBatchInWindow { window, open_nonce } => write!(
                f,
                "a duty batch for window {window} is already pending at nonce {open_nonce}"
            ),
            DutyRefusal::LaneBytesFull { lane_bytes, cap } => write!(
                f,
                "the duty lane would hold {lane_bytes} bytes against its {cap} byte ceiling"
            ),
        }
    }
}

/// The bytes of a block the duty lane may fill.
///
/// The caller passes the block's byte budget, so the share follows a block
/// budget that changes rather than a constant copied beside it.
#[must_use]
pub const fn block_share_bytes(block_byte_budget: usize) -> usize {
    block_byte_budget.saturating_mul(DUTY_LANE_BLOCK_SHARE_PERCENT) / 100
}

/// The presence window a wall-clock instant falls in.
///
/// Windows are numbered from the Unix epoch, so every node reading the same
/// clock agrees, and the number is the `window` field of the presence signal
/// (section 7.8). The conversion saturates rather than wrapping: a clock far
/// in the future puts the transaction in the last window instead of in a
/// window that repeats an earlier number.
#[must_use]
pub fn window_at(now_ms: u128) -> u64 {
    u64::try_from(now_ms / u128::from(MOBILE_DUTY_WINDOW_MS)).unwrap_or(u64::MAX)
}

/// Whether a transaction is a duty transaction, that is, a member of a
/// validator's duty batch.
///
/// The batch carries the two items that already have a transaction envelope:
/// a custody acknowledgement and a custody proof batch. Anything else,
/// including the legacy `Storage` transaction and every envelope that is not a
/// `StorageTx` v3, is an ordinary transaction and pays the fee floor.
#[must_use]
pub fn is_duty(tx: &Transaction) -> bool {
    let TransactionType::StorageV3(payload) = &tx.tx_type else {
        return false;
    };
    matches!(
        payload.as_ref(),
        StorageTxV3::CustodyAck { .. } | StorageTxV3::CustodyProofBatch { .. }
    )
}

/// The bytes a transaction costs a block, by the block validator's own
/// measure.
///
/// `validate_block_size` serializes the block with `serde_json` and refuses it
/// past `consensus::MAX_BLOCK_SIZE`, and the producer charges each transaction
/// the length of its own `serde_json` encoding plus the one byte that
/// separates array entries. Measuring the duty share any other way would
/// enforce a fraction of a quantity the block validator does not look at. A
/// transaction that cannot be serialized can never enter a valid block, so it
/// counts as infinitely large here, exactly as the producer treats it.
#[must_use]
pub fn block_bytes(tx: &Transaction) -> usize {
    serde_json::to_vec(tx).map_or(usize::MAX, |bytes| bytes.len().saturating_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_share_is_one_fifth_of_the_budget() {
        assert_eq!(block_share_bytes(1_000_000), 200_000);
        assert_eq!(block_share_bytes(1_000_000), 1_000_000 / 5);
        assert_eq!(block_share_bytes(0), 0);
        assert_eq!(block_share_bytes(4), 0);
    }

    #[test]
    fn windows_are_numbered_from_the_epoch() {
        assert_eq!(window_at(0), 0);
        assert_eq!(window_at(599_999), 0);
        assert_eq!(window_at(600_000), 1);
        assert_eq!(window_at(4_200_005), 7);
        assert_eq!(window_at(u128::MAX), u64::MAX);
    }

    #[test]
    fn only_the_two_duty_items_are_duty_transactions() {
        let keypair = crate::crypto::primitives::KeyPair::from_seed(&[31u8; 32]).unwrap();
        let from = crate::core::address::Address::from(keypair.public_key_bytes());
        let build = |tx_type: TransactionType| {
            let mut tx = Transaction::new_with_chain_id(
                from,
                crate::core::address::Address::zero(),
                0,
                0,
                0,
                Vec::new(),
                crate::core::transaction::DEFAULT_CHAIN_ID,
                tx_type,
            );
            tx.hash = tx.calculate_hash();
            tx.sign(&keypair);
            tx
        };

        let ack = build(TransactionType::StorageV3(Box::new(StorageTxV3::CustodyAck {
            object: [1u8; 32],
        })));
        assert!(is_duty(&ack));
        assert!(block_bytes(&ack) > 1);

        let batch = build(TransactionType::StorageV3(Box::new(
            StorageTxV3::CustodyProofBatch { proofs: Vec::new() },
        )));
        assert!(is_duty(&batch));

        let plain = build(TransactionType::Transfer);
        assert!(!is_duty(&plain));
    }
}
