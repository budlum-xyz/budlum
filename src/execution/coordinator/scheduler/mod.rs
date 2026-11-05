//! Deterministic parallel scheduling of a block's transactions.
//!
//! WIRING: the coordinator calls [`plan`] for every block and runs
//! the waves on its EE workers; until it lands, the block executor stays
//! sequential and this module is exercised by the equality tests below.
//!
//! # Rule
//!
//! Every transaction gets an [`AccessSet`]: the state keys it may read and
//! write. Two transactions conflict when one writes a key the other reads
//! or writes. [`plan`] puts each transaction in the first wave after the
//! last wave holding an earlier transaction it conflicts with, so
//!
//! * transactions in one wave touch disjoint state and may run in any
//!   order, or at the same time, and
//! * any two conflicting transactions keep their block order.
//!
//! The result is therefore byte-equal to sequential execution
//! (`parallel_schedule_equals_sequential_root`).
//!
//! # Fallback
//!
//! A transaction whose effects are not known key by key gets
//! [`AccessSet::global`], which conflicts with everything: it sits in a
//! wave of its own, after everything before it and before everything after
//! it. A block of such transactions is scheduled exactly sequentially. Only
//! `Transfer` is derived key by key today; every other type falls back.
//!
//! # Determinism
//!
//! [`plan`] is a pure function of the access sets in block order. It uses
//! ordered collections only and no thread, clock or hash seed, so every
//! architecture produces the same waves
//! (`parallel_scheduler_is_deterministic_across_arch`).

use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use std::collections::{BTreeMap, BTreeSet};

/// One unit of state a transaction can touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StateKey {
    /// An account record: balance, nonce, and the account's vesting entry.
    Account(Address),
}

/// What one transaction may read and write.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessSet {
    pub reads: BTreeSet<StateKey>,
    pub writes: BTreeSet<StateKey>,
    /// Touches state that is not described key by key. Conflicts with
    /// every transaction.
    pub global: bool,
}

impl AccessSet {
    /// The fallback: conflicts with everything.
    #[must_use]
    pub fn global() -> Self {
        Self {
            global: true,
            ..Self::default()
        }
    }

    /// Whether the two transactions must keep their relative order.
    #[must_use]
    pub fn conflicts_with(&self, other: &Self) -> bool {
        if self.global || other.global {
            return true;
        }
        !self.writes.is_disjoint(&other.writes)
            || !self.writes.is_disjoint(&other.reads)
            || !self.reads.is_disjoint(&other.writes)
    }
}

/// The access set of one transaction, conservatively.
///
/// `Transfer` debits the sender (balance, nonce, after reading its vesting
/// entry) and credits the recipient; nothing else. Fees are distributed at
/// block end, outside the per-transaction path. Every other type falls back
/// to [`AccessSet::global`] until its effects are written out here.
#[must_use]
pub fn access_set(tx: &Transaction) -> AccessSet {
    match tx.tx_type {
        TransactionType::Transfer if tx.from != Address::zero() => {
            let mut writes = BTreeSet::new();
            writes.insert(StateKey::Account(tx.from));
            writes.insert(StateKey::Account(tx.to));
            AccessSet {
                reads: BTreeSet::new(),
                writes,
                global: false,
            }
        }
        _ => AccessSet::global(),
    }
}

/// A schedule: waves of transaction indexes, in block order inside a wave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub waves: Vec<Vec<usize>>,
}

impl Plan {
    /// Every index exactly once.
    #[must_use]
    pub fn len(&self) -> usize {
        self.waves.iter().map(Vec::len).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.waves.is_empty()
    }
}

/// Schedule `sets` (one per transaction, in block order) into waves.
///
/// Runs in `O(n * k)` for `n` transactions touching `k` keys each: per key
/// it remembers the last wave that wrote it and the last wave that read it,
/// and a global transaction raises a floor that every later transaction
/// starts above.
#[must_use]
pub fn plan(sets: &[AccessSet]) -> Plan {
    let mut last_write: BTreeMap<StateKey, usize> = BTreeMap::new();
    let mut last_read: BTreeMap<StateKey, usize> = BTreeMap::new();
    // The wave of the most recent global transaction, and the highest wave
    // used so far (a global transaction must follow all of them).
    let mut global_floor: Option<usize> = None;
    let mut highest: Option<usize> = None;
    let mut waves: Vec<Vec<usize>> = Vec::new();

    for (index, set) in sets.iter().enumerate() {
        let after = |wave: Option<usize>| wave.map_or(0, |w| w + 1);
        let mut wave = after(global_floor);
        if set.global {
            wave = wave.max(after(highest));
        } else {
            for key in &set.writes {
                wave = wave
                    .max(after(last_write.get(key).copied()))
                    .max(after(last_read.get(key).copied()));
            }
            for key in &set.reads {
                wave = wave.max(after(last_write.get(key).copied()));
            }
        }
        if waves.len() <= wave {
            waves.resize_with(wave + 1, Vec::new);
        }
        if let Some(slot) = waves.get_mut(wave) {
            slot.push(index);
        }
        highest = Some(highest.map_or(wave, |h| h.max(wave)));
        if set.global {
            global_floor = Some(wave);
        } else {
            for key in &set.writes {
                last_write.insert(*key, wave);
            }
            for key in &set.reads {
                let slot = last_read.entry(*key).or_insert(wave);
                *slot = (*slot).max(wave);
            }
        }
    }
    Plan { waves }
}

#[cfg(test)]
mod tests;
