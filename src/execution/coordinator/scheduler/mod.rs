//! Deterministic parallel scheduling of a block's transactions.
//!
//! WIRING: unwired - staged until coordinator parallel worker dispatch is enabled.
//! The coordinator calls [`plan`] for every block and runs
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

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::execution::coordinator::assets::BUDLUM_TESTNET_CHAIN_ID;
use crate::execution::executor::Executor;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

/// Activation and intra-EE (`Block-STM`) policy for deterministic parallel block
/// scheduling (`Section 1.5`).
///
/// Convenience: passed to `execute_block_with_policy` by coordinator and benchmarks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParallelSchedulerPolicy {
    pub chain_id: u64,
    pub block_height: u64,
    pub activation_height: Option<u64>,
    pub intra_ee_block_stm_enabled: bool,
    pub intra_ee_equality_verified: bool,
}

impl Default for ParallelSchedulerPolicy {
    fn default() -> Self {
        Self::testnet_launch()
    }
}

impl ParallelSchedulerPolicy {
    /// Default `T-Acilis` launch policy on testnet `45261` (closed at launch).
    ///
    /// Convenience: default policy before  height activation.
    #[must_use]
    pub const fn testnet_launch() -> Self {
        Self {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            block_height: 0,
            activation_height: None,
            intra_ee_block_stm_enabled: false,
            intra_ee_equality_verified: false,
        }
    }

    /// Returns `true` when cross-tx access-set wave scheduling is active.
    ///
    /// Convenience: queried by `execute_block_with_policy` and readiness probes.
    #[must_use]
    pub const fn scheduler_active(&self) -> bool {
        match self.activation_height {
            Some(h) => self.block_height >= h,
            None => self.chain_id != BUDLUM_TESTNET_CHAIN_ID,
        }
    }

    /// Intra-EE (`Block-STM`) parallelism requires its own explicit flag **and**
    /// passing state-root equality verification (`IP-59`).
    ///
    /// Convenience: queried before enabling intra-EE parallel worker lanes.
    #[must_use]
    pub const fn intra_ee_parallelism_active(&self) -> bool {
        self.scheduler_active()
            && self.intra_ee_block_stm_enabled
            && self.intra_ee_equality_verified
    }
}

/// Non-consensus timing and wave summary emitted by [`execute_block_with_policy`].
///
/// Convenience: consumed by calibration reports (`IP-59`) and equality tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockExecutionReport {
    pub tx_count: usize,
    pub wave_count: usize,
    pub sequential_fallback_waves: usize,
    pub used_parallel_waves: bool,
    pub intra_ee_parallelism: bool,
    pub elapsed_micros: u64,
    pub state_root: String,
}


/// One unit of state a transaction can touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StateKey {
    /// An account record: balance, nonce, and the account's vesting entry.
    Account(Address),
    /// A canonical UEL namespace slot `(ee_id, key_digest)` for cross-EE wave planning.
    UelSlot { ee_id: u8, slot: [u8; 32] },
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
        TransactionType::Transfer if tx.from != Address::zero() && tx.authorization.is_none() => {
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

/// Derive an [`AccessSet`] combining the sender/recipient account keys with
/// declared UEL namespace read/write slot digests.
///
/// Convenience: used by UEL wave planners when transactions declare explicit
/// namespace access lists; falls back to [`AccessSet::global`] if both hints
/// are empty on a non-transfer transaction.
#[must_use]
pub fn access_set_with_uel_hint(
    tx: &Transaction,
    uel_reads: &[(u8, [u8; 32])],
    uel_writes: &[(u8, [u8; 32])],
) -> AccessSet {
    if uel_reads.is_empty() && uel_writes.is_empty() {
        return access_set(tx);
    }
    if tx.from == Address::zero() {
        return AccessSet::global();
    }
    let mut reads = BTreeSet::new();
    let mut writes = BTreeSet::new();
    writes.insert(StateKey::Account(tx.from));
    if tx.to != Address::zero() {
        writes.insert(StateKey::Account(tx.to));
    }
    for (ee_id, slot) in uel_reads {
        reads.insert(StateKey::UelSlot {
            ee_id: *ee_id,
            slot: *slot,
        });
    }
    for (ee_id, slot) in uel_writes {
        writes.insert(StateKey::UelSlot {
            ee_id: *ee_id,
            slot: *slot,
        });
    }
    AccessSet {
        reads,
        writes,
        global: false,
    }
}

/// Intra-environment speculative execution flag ( Block-STM).
///
/// Disabled by default (`enabled = false`); may only be enabled when the
/// sequential-root equality property suite passes.
/// WIRING: consumed by the coordinator block executor when parallel wave dispatch is enabled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockStmConfig {
    pub enabled: bool,
}

/// Deterministic execution telemetry for a scheduled block.
/// WIRING: reported by the coordinator block executor alongside block execution metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScheduleStats {
    pub tx_count: usize,
    pub wave_count: usize,
    pub max_wave_width: usize,
    pub fallback_barriers: usize,
    pub block_stm_replays: usize,
}

type AccountVersion = (Option<(u64, u64)>, u64, bool);

fn account_snapshot(state: &AccountState, addr: &Address) -> AccountVersion {
    (
        state
            .accounts
            .get(addr)
            .map(|acct| (acct.balance, acct.nonce)),
        state.spendable_balance(addr),
        state.burn_reserve_address == Some(*addr),
    )
}

fn touched_addresses(set: &AccessSet) -> BTreeSet<Address> {
    set.reads
        .iter()
        .chain(set.writes.iter())
        .filter_map(|key| match key {
            StateKey::Account(address) => Some(*address),
            StateKey::UelSlot { .. } => None,
        })
        .collect()
}

/// Execute `txs` against `state` using deterministic access-set waves and,
/// when `block_stm.enabled` is set, optimistic snapshot validation with
/// deterministic sequential fallback on any conflict.
///
/// The resulting `AccountState` is byte-identical to sequential block-order
/// execution.
/// WIRING: entry point for the coordinator's parallel block execution path.
pub fn execute_planned_block(
    state: &mut AccountState,
    txs: &[Transaction],
    block_stm: BlockStmConfig,
) -> ScheduleStats {
    let sets: Vec<AccessSet> = txs.iter().map(access_set).collect();
    let schedule = plan(&sets);
    let fallback_barriers = sets.iter().filter(|s| s.global).count();
    let max_wave_width = schedule.waves.iter().map(Vec::len).max().unwrap_or(0);
    let mut block_stm_replays = 0usize;

    if !block_stm.enabled {
        for wave in &schedule.waves {
            for &idx in wave {
                if let Some(tx) = txs.get(idx) {
                    let _ = Executor::apply_transaction(state, tx);
                }
            }
        }
        return ScheduleStats {
            tx_count: txs.len(),
            wave_count: schedule.waves.len(),
            max_wave_width,
            fallback_barriers,
            block_stm_replays: 0,
        };
    }

    // Block-STM mode: speculatively evaluate against the pre-batch snapshot
    // and validate read/write versions against the committed prefix; any
    // conflict discards the speculative clone and falls back to sequential
    // execution on `state`.
    let base_snapshot = state.clone();
    let mut speculative: Vec<(usize, AccountState, BTreeMap<Address, AccountVersion>)> =
        Vec::with_capacity(txs.len());

    for (idx, tx) in txs.iter().enumerate() {
        let Some(set) = sets.get(idx) else {
            continue;
        };
        if set.global {
            continue;
        }
        let mut pre_versions = BTreeMap::new();
        for addr in touched_addresses(set) {
            pre_versions.insert(addr, account_snapshot(&base_snapshot, &addr));
        }
        let mut local = base_snapshot.clone();
        let _ = Executor::apply_transaction(&mut local, tx);
        speculative.push((idx, local, pre_versions));
    }

    let mut spec_map: BTreeMap<usize, (AccountState, BTreeMap<Address, AccountVersion>)> =
        speculative
            .into_iter()
            .map(|(i, st, ver)| (i, (st, ver)))
            .collect();

    for (idx, tx) in txs.iter().enumerate() {
        let Some((spec_state, expected_versions)) = spec_map.remove(&idx) else {
            let _ = Executor::apply_transaction(state, tx);
            continue;
        };
        let conflict = expected_versions
            .iter()
            .any(|(addr, &ver)| account_snapshot(state, addr) != ver);
        if conflict {
            block_stm_replays += 1;
            let _ = Executor::apply_transaction(state, tx);
        } else {
            for (addr, _) in expected_versions {
                if let Some(updated) = spec_state.accounts.get(&addr) {
                    state.accounts.insert(addr, updated.clone());
                } else {
                    state.accounts.remove(&addr);
                }
            }
        }
    }

    ScheduleStats {
        tx_count: txs.len(),
        wave_count: schedule.waves.len(),
        max_wave_width,
        fallback_barriers,
        block_stm_replays,
    }
}


/// Execute a block under the activation policy and report deterministic
/// scheduling telemetry. Inactive chains always use block order.
pub fn execute_block_with_policy(
    state: &mut AccountState,
    txs: &[Transaction],
    policy: ParallelSchedulerPolicy,
) -> BlockExecutionReport {
    let started = Instant::now();
    if !policy.scheduler_active() {
        for tx in txs {
            let _ = Executor::apply_transaction(state, tx);
        }
        return BlockExecutionReport {
            tx_count: txs.len(),
            wave_count: txs.len(),
            sequential_fallback_waves: txs.len(),
            used_parallel_waves: false,
            intra_ee_parallelism: false,
            elapsed_micros: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            state_root: state.calculate_state_root(),
        };
    }

    let intra_ee_parallelism = policy.intra_ee_parallelism_active();
    let stats = execute_planned_block(
        state,
        txs,
        BlockStmConfig {
            enabled: intra_ee_parallelism,
        },
    );
    BlockExecutionReport {
        tx_count: stats.tx_count,
        wave_count: stats.wave_count,
        sequential_fallback_waves: stats.fallback_barriers,
        used_parallel_waves: stats.max_wave_width > 1,
        intra_ee_parallelism,
        elapsed_micros: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        state_root: state.calculate_state_root(),
    }
}

#[cfg(test)]
mod tests;
