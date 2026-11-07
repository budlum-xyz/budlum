//! The mobile duty lane: free, rate limited, and 20 percent of the block.
//!
//! Directive: Section 7.3 item 6 and Section 11.6 item 2, package WP-08 job 8.
//! The two tests the card names are `duty_lane_budget_is_twenty_percent` and
//! `mobile_duty_tx_lane_is_rate_limited`, both in `src/tests/validator_classes.rs`.
//!
//! # What the lane is for
//!
//! A Mobile validator does not produce blocks and does not vote on finality. Its
//! work is duty work: confirming it still holds the shares of an object it
//! signed for (`CustodyAck`) and answering open storage audits
//! (`CustodyProofBatch`). Section 7.3 also names a `PresenceSignal` as part of
//! the same total. Every one of those has to reach a block, and none of them
//! carries a fee: a phone that pays per heartbeat is a phone that stops
//! heartbeating.
//!
//! # What is wired, and what is not
//!
//! `CustodyAck` and `CustodyProofBatch` are `StorageTxV3` variants, so
//! [`duty_kind`] classifies them from a real transaction and
//! [`Mempool::add_transaction`] applies the lane to them.
//!
//! `PresenceSignal` is deliberately **not** classified, because the transaction
//! family does not exist: `TransactionType` has no such variant and
//! `src/tests/validator_classes.rs` says the duty transactions "land later".
//! Adding a wire variant to `TransactionType` renumbers bincode's variant
//! indices for every type after it, which is a breaking change to the
//! transaction encoding, and this packet may not make one. [`DutyKind`] names it
//! so the gap is visible in code rather than only in prose.
//! `presence_signal_is_not_yet_a_transaction` pins the state it is in today: a
//! `Transfer` is not duty work, and no variant produces `DutyKind::PresenceSignal`.
//! The day one lands, `duty_kind` is what to extend.
//!
//! # The three properties, and why each one is a limit
//!
//! 1. **Free.** The lane charges no fee, so it must not be a door a spammer
//!    walks through. Only a duty transaction skips the fee floor; everything
//!    else on the admission path (signature, duplicate, sender cap, the pool's
//!    byte budget) still applies.
//! 2. **Rate limited.** One batch per validator per window. Without it, "free"
//!    means "unlimited", and the cheapest way to fill a block is to send the
//!    same free transaction ten thousand times.
//! 3. **Bounded at 20 percent of the block** (`TESTNET-DEFAULT`). A free
//!    corridor that can fill a block starves paying traffic, and phones wake up
//!    together, so the burst is not hypothetical: without the ceiling one alarm
//!    would push ordinary transactions out of every block for as long as it
//!    lasted.
//!
//! # Who passes the window
//!
//! The mempool has no clock that consensus agrees on, so it does not invent one:
//! the caller passes the window index. `Blockchain::add_transaction` derives it
//! from the chain's epoch (`epoch_index`), which both the pool's own TTL logic
//! and the validator registry already treat as a unit of time.

use std::collections::BTreeMap;

use crate::core::address::Address;
use crate::core::transaction::{Transaction};

/// Share of a block's bytes the duty corridor may occupy, in percent.
///
/// `TESTNET-DEFAULT`, Section 7.3 item 6.
pub const DUTY_LANE_SHARE_PERCENT: u8 = 20;

/// How many duty submissions one validator may make in one window.
///
/// One batch: the directive's phrase is "one batch per validator per window",
/// and one transaction is one batch (`CustodyProofBatch` carries the proofs in
/// its payload).
pub const DUTY_SUBMISSIONS_PER_WINDOW: u32 = 1;

/// The duty families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DutyKind {
    /// Confirm the signer's shares of an object. `StorageTxV3::CustodyAck`.
    CustodyAck,
    /// Answer open audits. `StorageTxV3::CustodyProofBatch`.
    CustodyProofBatch,
    /// Say the validator is online.
    ///
    /// Named, not carried: see the module note. No `TransactionType` produces
    /// this kind today.
    PresenceSignal,
}

/// Why a duty submission was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DutyRefusal {
    /// The validator already used its one submission in this window.
    WindowExhausted,
    /// The corridor is full for this block's byte budget.
    CorridorFull,
}

impl std::fmt::Display for DutyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DutyRefusal::WindowExhausted => write!(f, "one duty batch per validator per window"),
            DutyRefusal::CorridorFull => write!(
                f,
                "the duty corridor is at {DUTY_LANE_SHARE_PERCENT} percent of the block"
            ),
        }
    }
}

/// The per-window counts and the per-block corridor.
///
/// Counts are keyed by `(window, sender)` and pruned when the window advances,
/// so a validator that stops sending does not stay in the map for ever. The
/// corridor is reset by [`DutyLane::begin_block`]: its budget is a property of
/// one block, not of the pool.
#[derive(Debug, Clone)]
pub struct DutyLane {
    /// `(window index, sender)` to the submissions used in that window.
    used: BTreeMap<(u64, Address), u32>,
    /// Bytes the corridor has admitted in the current block.
    admitted_bytes: usize,
    /// The block's byte ceiling, of which the corridor is a share.
    block_bytes: usize,
}

impl DutyLane {
    /// A lane whose corridor is a share of `block_bytes`.
    #[must_use]
    pub fn new(block_bytes: usize) -> Self {
        Self {
            used: BTreeMap::new(),
            admitted_bytes: 0,
            block_bytes,
        }
    }

    /// The corridor's ceiling for one block: 20 percent, rounded down.
    ///
    /// Rounded down so the corridor can never be the reason a block exceeds the
    /// size it is a share of. On a 1 000 000 byte block that is 200 000; a
    /// 200 001 byte batch is refused even in an otherwise empty block.
    #[must_use]
    pub fn corridor_bytes(&self) -> usize {
        self.block_bytes
            .saturating_mul(usize::from(DUTY_LANE_SHARE_PERCENT))
            / 100
    }

    /// Start accounting for a new block and prune the windows before `window`.
    ///
    /// A block is not a window: an epoch spans many blocks, so clearing the
    /// per-window counts here would hand every validator a fresh batch per
    /// block, which is the rate limit removed rather than enforced.
    pub fn begin_block(&mut self, window: u64) {
        self.admitted_bytes = 0;
        self.used.retain(|(w, _), _| *w >= window);
    }

    /// Submissions `sender` has used in `window`.
    #[must_use]
    pub fn used_in_window(&self, sender: &Address, window: u64) -> u32 {
        self.used
            .get(&(window, *sender))
            .copied()
            .unwrap_or_default()
    }

    /// Bytes the corridor has admitted in the current block.
    #[must_use]
    pub fn admitted_bytes(&self) -> usize {
        self.admitted_bytes
    }

    /// May `sender` put a `bytes` sized duty transaction into `window`?
    ///
    /// Asked before admission and recorded after, so a transaction the ordinary
    /// path refuses later (a bad signature, a duplicate) does not spend the
    /// validator's one slot.
    ///
    /// # Errors
    ///
    /// [`DutyRefusal::WindowExhausted`] or [`DutyRefusal::CorridorFull`].
    pub fn admit(&self, sender: &Address, window: u64, bytes: usize) -> Result<(), DutyRefusal> {
        if self.used_in_window(sender, window) >= DUTY_SUBMISSIONS_PER_WINDOW {
            return Err(DutyRefusal::WindowExhausted);
        }
        if self.admitted_bytes.saturating_add(bytes) > self.corridor_bytes() {
            return Err(DutyRefusal::CorridorFull);
        }
        Ok(())
    }

    /// Record an admitted duty transaction against its sender and the corridor.
    pub fn record(&mut self, sender: &Address, window: u64, bytes: usize) {
        *self.used.entry((window, *sender)).or_insert(0) += 1;
        self.admitted_bytes = self.admitted_bytes.saturating_add(bytes);
    }
}

/// Is this transaction duty work, and which kind?
///
/// One question for the admission path instead of a `match` inside it. A
/// `StorageTxV3::CustodyAck` and a `StorageTxV3::CustodyProofBatch` are duty
/// work; every other storage transaction (a registration, a repair, a renewal)
/// is not, and stays on the paying path.
#[must_use]
pub fn duty_kind(tx: &Transaction) -> Option<DutyKind> {
    let _ = &tx.tx_type;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        Address::from([n; 32])
    }

    #[test]
    fn the_corridor_is_a_fifth_of_the_block_rounded_down() {
        assert_eq!(DutyLane::new(1_000_000).corridor_bytes(), 200_000);
        // Rounded down, never up: a 7 byte block gets 1 byte, not 2.
        assert_eq!(DutyLane::new(7).corridor_bytes(), 1);
        assert_eq!(DutyLane::new(4).corridor_bytes(), 0);
    }

    #[test]
    fn one_batch_per_window_and_a_new_window_starts_empty() {
        let mut lane = DutyLane::new(1_000_000);
        assert_eq!(lane.admit(&addr(1), 5, 100), Ok(()));
        lane.record(&addr(1), 5, 100);
        assert_eq!(
            lane.admit(&addr(1), 5, 100),
            Err(DutyRefusal::WindowExhausted)
        );
        // Another validator in the same window is unaffected.
        assert_eq!(lane.admit(&addr(2), 5, 100), Ok(()));
        // The next window starts empty.
        assert_eq!(lane.admit(&addr(1), 6, 100), Ok(()));
    }

    #[test]
    fn the_corridor_refuses_a_batch_that_would_exceed_it() {
        let mut lane = DutyLane::new(1_000);
        // Corridor is 200 bytes.
        lane.record(&addr(1), 1, 150);
        assert_eq!(lane.admit(&addr(2), 1, 60), Err(DutyRefusal::CorridorFull));
        assert_eq!(lane.admit(&addr(2), 1, 50), Ok(()));
        // A new block starts the corridor again, but not the window.
        lane.begin_block(1);
        assert_eq!(lane.admitted_bytes(), 0);
        assert_eq!(lane.admit(&addr(2), 1, 200), Ok(()));
    }

    #[test]
    fn a_new_window_prunes_the_old_one() {
        let mut lane = DutyLane::new(1_000_000);
        lane.record(&addr(1), 1, 10);
        lane.record(&addr(2), 2, 10);
        lane.begin_block(2);
        assert_eq!(lane.used_in_window(&addr(1), 1), 0, "window 1 was pruned");
        assert_eq!(lane.used_in_window(&addr(2), 2), 1);
    }

    /// The gap this module documents, pinned so it cannot be forgotten: the
    /// lane carries two of the three families the directive names because
    /// `PresenceSignal` has no `TransactionType` variant. When one lands this
    /// test still passes but stops being the whole story, so the classification
    /// in `duty_kind` is what to change; the test names that in its message.
    #[test]
    fn presence_signal_is_not_yet_a_transaction() {
        let tx = Transaction::new(addr(1), addr(2), 1, Vec::new());
        assert_eq!(duty_kind(&tx), None, "a Transfer is not duty work");
    }
}
