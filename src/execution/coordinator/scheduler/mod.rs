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

use crate::core::account::{Account, AccountState};
use crate::core::address::Address;
use crate::core::error::BudlumResult;
use crate::core::transaction::{Transaction, TransactionType};
use crate::execution::executor::Executor;
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

/// Runtime switches for parallel wave execution and intra-environment Block-STM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParallelExecutionConfig {
    /// Enable wave-parallel execution across disjoint `AccessSet` waves.
    pub enabled: bool,
    /// Separate feature gate for optimistic Block-STM validation with conflict fallback.
    pub block_stm_enabled: bool,
    /// Worker thread cap per wave (`>= 1`).
    pub worker_threads: usize,
}

impl Default for ParallelExecutionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_stm_enabled: false,
            worker_threads: 4,
        }
    }
}

/// Deterministic summary of a scheduled block execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScheduleReport {
    pub wave_count: usize,
    pub parallel_txs: usize,
    pub sequential_txs: usize,
    pub block_stm_fallbacks: usize,
}

fn isolated_transfer_state(base: &AccountState, tx: &Transaction) -> AccountState {
    let mut local = AccountState::new();
    local.burn_reserve_address = base.burn_reserve_address;
    local.team_vesting = base.team_vesting.clone();
    local.epoch_index = base.epoch_index;
    local.base_fee = base.base_fee;
    local.current_block_height = base.current_block_height;
    local.current_block_unix_secs = base.current_block_unix_secs;
    if let Some(sender) = base.accounts.get(&tx.from) {
        local.accounts.insert(tx.from, sender.clone());
    }
    if let Some(receiver) = base.accounts.get(&tx.to) {
        local.accounts.insert(tx.to, receiver.clone());
    }
    local
}

type TransferDelta = (Address, Account, Address, Account);

fn run_isolated_transfer(base: &AccountState, tx: &Transaction) -> BudlumResult<TransferDelta> {
    let mut local = isolated_transfer_state(base, tx);
    Executor::apply_transaction_checked(&mut local, tx)?;
    let sender = local
        .accounts
        .get(&tx.from)
        .cloned()
        .unwrap_or_else(|| Account::new(tx.from));
    let receiver = local
        .accounts
        .get(&tx.to)
        .cloned()
        .unwrap_or_else(|| Account::new(tx.to));
    Ok((tx.from, sender, tx.to, receiver))
}

/// Execute `transactions` against `state` using deterministic `AccessSet` waves,
/// scoped worker threads, and sequential fallback on conflicts or global barriers.
///
/// Failure-atomic (`G-4`): on any transaction error, `state` is left untouched.
pub fn execute_block_checked(
    state: &mut AccountState,
    transactions: &[Transaction],
    block_producer: Option<&Address>,
    config: &ParallelExecutionConfig,
) -> BudlumResult<ScheduleReport> {
    Executor::check_block_contract_gas(transactions)?;
    let mut candidate = state.clone();
    let sets: Vec<AccessSet> = transactions.iter().map(access_set).collect();
    let schedule = plan(&sets);
    let mut report = ScheduleReport {
        wave_count: schedule.waves.len(),
        ..ScheduleReport::default()
    };

    for wave in &schedule.waves {
        let wave_txs: Vec<&Transaction> = wave
            .iter()
            .filter_map(|&idx| transactions.get(idx))
            .collect();
        let all_disjoint_transfers = config.enabled
            && wave_txs.len() > 1
            && wave_txs
                .iter()
                .all(|tx| tx.tx_type == TransactionType::Transfer && tx.from != Address::zero());

        if !all_disjoint_transfers {
            for tx in wave_txs {
                Executor::apply_transaction_checked(&mut candidate, tx)?;
                report.sequential_txs = report.sequential_txs.saturating_add(1);
            }
            continue;
        }

        let workers = config.worker_threads.max(1).min(wave_txs.len());
        let chunk_size = wave_txs.len().div_ceil(workers);
        let snapshot = &candidate;
        let chunk_results: Vec<Vec<BudlumResult<TransferDelta>>> = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for chunk in wave_txs.chunks(chunk_size) {
                handles.push(scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|tx| run_isolated_transfer(snapshot, tx))
                        .collect::<Vec<_>>()
                }));
            }
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_default())
                .collect()
        });

        let mut touched_in_wave: BTreeSet<Address> = BTreeSet::new();
        for (tx, outcome) in wave_txs
            .iter()
            .zip(chunk_results.into_iter().flatten())
        {
            if config.block_stm_enabled
                && (touched_in_wave.contains(&tx.from) || touched_in_wave.contains(&tx.to))
            {
                report.block_stm_fallbacks = report.block_stm_fallbacks.saturating_add(1);
                Executor::apply_transaction_checked(&mut candidate, tx)?;
                report.sequential_txs = report.sequential_txs.saturating_add(1);
                continue;
            }
            let (from, updated_from, to, updated_to) = outcome?;
            touched_in_wave.insert(from);
            touched_in_wave.insert(to);
            *candidate.get_or_create(&from) = updated_from;
            if from != to {
                *candidate.get_or_create(&to) = updated_to;
            }
            report.parallel_txs = report.parallel_txs.saturating_add(1);
        }
    }

    Executor::finalize_block_checked(&mut candidate, transactions, block_producer)?;
    *state = candidate;
    Ok(report)
}

#[cfg(test)]
mod tests;
