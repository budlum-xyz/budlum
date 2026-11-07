//! Per-block IPC read cache and nested transaction/universal-call overlays.
//!
//! Implements sections 8.3.3 item 2, 8.3.4, and 8.7.3:
//! - `BlockReadCache` caches committed `(namespace, key)` reads for one block
//!   and invalidates keys touched by committed writes or universal calls (BLG-260).
//! - `TxOverlay` stacks one root transaction frame plus up to 8 cross-EE
//!   `UniversalCall` frames, rolling back failed frames without leaving state
//!   mutations behind (G-4).
//! WIRING: Nested call-frame overlay depth bounds wired into UEL coordinator.

use crate::core::account::{AccountState, BudEnvUnit};
use crate::core::address::Address;
use crate::execution::coordinator::state::{ExecutionState, RootGroup};
use budlum_uel_abi::{EeId, EeLog, HostError};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

/// Maximum cross-environment `UniversalCall` nesting depth (section 8.7.3 item 5).
pub const MAX_UNIVERSAL_CALL_DEPTH: usize = 8;

/// Block-scoped read cache in front of committed `ExecutionState` (BLG-260).
#[derive(Debug, Clone, Default)]
pub struct BlockReadCache {
    entries: RefCell<BTreeMap<(String, String), Option<Vec<u8>>>>,
}

impl BlockReadCache {
    /// Creates an empty per-block read cache.
    #[must_use]
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads `(ns, key)` through the cache, populating from `committed` on miss.
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn read(
        &self,
        committed: &ExecutionState,
        ns: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, HostError> {
        if RootGroup::for_namespace(ns).is_none() {
            return Err(HostError::Denied(format!("unknown UEL namespace `{ns}`")));
        }
        let cache_key = (ns.to_string(), hex::encode(key));
        if let Some(hit) = self.entries.borrow().get(&cache_key) {
            return Ok(hit.clone());
        }
        let val = committed.read(ns, key).map_err(HostError::Denied)?;
        self.entries.borrow_mut().insert(cache_key, val.clone());
        Ok(val)
    }

    /// Invalidates every cached `(ns, hex_key)` in `keys`.
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn invalidate<'a, I>(&self, keys: I)
    where
        I: IntoIterator<Item = &'a (String, String)>,
    {
        let mut guard = self.entries.borrow_mut();
        for k in keys {
            guard.remove(k);
        }
    }
}

#[derive(Debug, Clone)]
struct FrameSnapshot {
    ee: EeId,
    is_static: bool,
    writes: BTreeMap<(String, String), Option<Vec<u8>>>,
    touched_keys: BTreeSet<(String, String)>,
    accounts_snapshot: BTreeMap<Address, (u64, u64)>,
    logs_len: usize,
}

/// Nested overlay for a single UEL transaction and its `UniversalCall` stack.
pub struct TxOverlay {
    frames: Vec<FrameSnapshot>,
    logs: Vec<(EeId, EeLog)>,
    gas_limit_bgu: u64,
    gas_used_bgu: u64,
}

impl TxOverlay {
    /// Opens a root transaction overlay for `root_ee` with `gas_limit_bgu`.
    #[must_use]
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn new(state: &AccountState, root_ee: EeId, gas_limit_bgu: u64) -> Self {
        let accounts_snapshot = state
            .accounts
            .iter()
            .map(|(addr, a)| (*addr, (a.balance, a.frac_attos)))
            .collect();
        Self {
            frames: vec![FrameSnapshot {
                ee: root_ee,
                is_static: false,
                writes: BTreeMap::new(),
                touched_keys: BTreeSet::new(),
                accounts_snapshot,
                logs_len: 0,
            }],
            logs: Vec::new(),
            gas_limit_bgu,
            gas_used_bgu: 0,
        }
    }

    /// Current cross-EE universal-call depth (`0` in the root frame).
    #[must_use]
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn universal_depth(&self) -> usize {
        self.frames.len().saturating_sub(1)
    }

    /// Currently active execution environment at the top of the frame stack.
    #[must_use]
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn current_ee(&self) -> EeId {
        self.frames.last().map_or(EeId::BUDZERO, |f| f.ee)
    }

    /// Returns `true` when the active frame (or an ancestor) is read-only (`static`).
    #[must_use]
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn is_static(&self) -> bool {
        self.frames.last().is_some_and(|f| f.is_static)
    }

    /// Total BGU charged so far across the transaction.
    #[must_use]
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub const fn gas_used_bgu(&self) -> u64 {
        self.gas_used_bgu
    }

    /// Remaining BGU budget in the transaction.
    #[must_use]
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub const fn remaining_bgu(&self) -> u64 {
        self.gas_limit_bgu.saturating_sub(self.gas_used_bgu)
    }

    /// Charges `bgu` against the transaction gas limit.
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn charge_bgu(&mut self, bgu: u64) -> Result<(), budlum_uel_abi::OutOfGas> {
        let next = self
            .gas_used_bgu
            .checked_add(bgu)
            .ok_or(budlum_uel_abi::OutOfGas)?;
        if next > self.gas_limit_bgu {
            self.gas_used_bgu = self.gas_limit_bgu;
            return Err(budlum_uel_abi::OutOfGas);
        }
        self.gas_used_bgu = next;
        Ok(())
    }

    /// Opens a child `UniversalCall` frame, enforcing depth `<= 8` and
    /// cross-EE non-reentrancy (`ReentrancyForbidden`).
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn push_universal_frame(
        &mut self,
        state: &AccountState,
        target_ee: EeId,
        call_static: bool,
    ) -> Result<(), HostError> {
        if self.universal_depth() >= MAX_UNIVERSAL_CALL_DEPTH {
            return Err(HostError::DepthExceeded);
        }
        if self.frames.iter().any(|f| f.ee == target_ee) {
            return Err(HostError::Denied(String::from("ReentrancyForbidden")));
        }
        let parent_writes = self
            .frames
            .last()
            .map_or_else(BTreeMap::new, |f| f.writes.clone());
        let inherited_static = self.is_static() || call_static;
        let accounts_snapshot = state
            .accounts
            .iter()
            .map(|(addr, a)| (*addr, (a.balance, a.frac_attos)))
            .collect();
        self.frames.push(FrameSnapshot {
            ee: target_ee,
            is_static: inherited_static,
            writes: parent_writes,
            touched_keys: BTreeSet::new(),
            accounts_snapshot,
            logs_len: self.logs.len(),
        });
        Ok(())
    }

    /// Merges a succeeded child frame into its parent and invalidates touched
    /// keys in `cache`.
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn commit_universal_frame(&mut self, cache: &BlockReadCache) {
        if self.frames.len() <= 1 {
            return;
        }
        if let Some(child) = self.frames.pop() {
            cache.invalidate(&child.touched_keys);
            if let Some(parent) = self.frames.last_mut() {
                parent.writes = child.writes;
                parent.touched_keys.extend(child.touched_keys);
            }
        }
    }

    /// Discards a failed child frame, restoring parent writes, account balances
    /// and log tail while keeping gas spent.
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn rollback_universal_frame(&mut self, state: &mut AccountState) {
        if self.frames.len() <= 1 {
            return;
        }
        if let Some(child) = self.frames.pop() {
            restore_accounts(state, &child.accounts_snapshot);
            self.logs.truncate(child.logs_len);
        }
    }

    /// Rolls back the root transaction frame (`G-4`: zero state or balance mutations).
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn rollback_root(&mut self, state: &mut AccountState) {
        while self.frames.len() > 1 {
            let _ = self.frames.pop();
        }
        if let Some(root) = self.frames.first() {
            restore_accounts(state, &root.accounts_snapshot);
        }
        if let Some(root) = self.frames.first_mut() {
            root.writes.clear();
            root.touched_keys.clear();
        }
        self.logs.clear();
    }

    /// Reads `(ns, key)` through the active overlay frame, falling back to `cache`.
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn read(
        &self,
        committed: &ExecutionState,
        cache: &BlockReadCache,
        ns: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, HostError> {
        if RootGroup::for_namespace(ns).is_none() {
            return Err(HostError::Denied(format!("unknown UEL namespace `{ns}`")));
        }
        let lookup = (ns.to_string(), hex::encode(key));
        if let Some(top) = self.frames.last() {
            if let Some(staged) = top.writes.get(&lookup) {
                return Ok(staged.clone());
            }
        }
        cache.read(committed, ns, key)
    }

    /// Stages a write (`Some`) or deletion (`None`) in the active overlay frame.
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn write(&mut self, ns: &str, key: &[u8], value: Option<&[u8]>) -> Result<(), HostError> {
        if self.is_static() {
            return Err(HostError::Denied(String::from(
                "static call cannot write state",
            )));
        }
        if RootGroup::for_namespace(ns).is_none() {
            return Err(HostError::Denied(format!("unknown UEL namespace `{ns}`")));
        }
        let entry_key = (ns.to_string(), hex::encode(key));
        if let Some(top) = self.frames.last_mut() {
            top.writes
                .insert(entry_key.clone(), value.map(<[u8]>::to_vec));
            top.touched_keys.insert(entry_key);
        }
        Ok(())
    }

    /// Moves `attos` attoBUD in `state` under `unit`, guarded against static frames.
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn transfer_attos(
        &self,
        state: &mut AccountState,
        from: &Address,
        to: &Address,
        attos: u128,
        unit: BudEnvUnit,
    ) -> Result<(), HostError> {
        if self.is_static() && attos > 0 {
            return Err(HostError::Denied(String::from(
                "static call cannot transfer BUD",
            )));
        }
        state
            .transfer_attos_in_unit(from, to, attos, unit)
            .map_err(HostError::Denied)
    }

    /// Appends a log tagged with the emitting environment.
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn emit_log(&mut self, log: EeLog) -> Result<(), HostError> {
        if self.is_static() {
            return Err(HostError::Denied(String::from(
                "static call cannot emit logs",
            )));
        }
        let ee = self.current_ee();
        self.logs.push((ee, log));
        Ok(())
    }

    /// Flushes a succeeded root transaction's staged writes into `committed`
    /// and invalidates `cache`, returning emitted `(EeId, EeLog)` pairs.
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn commit_root(
        mut self,
        committed: &mut ExecutionState,
        cache: &BlockReadCache,
    ) -> Result<Vec<(EeId, EeLog)>, String> {
        while self.frames.len() > 1 {
            self.commit_universal_frame(cache);
        }
        if let Some(root) = self.frames.pop() {
            cache.invalidate(&root.touched_keys);
            for ((ns, hex_key), val) in root.writes {
                let raw_key = hex::decode(&hex_key)
                    .map_err(|e| format!("corrupt overlay key hex `{hex_key}`: {e}"))?;
                committed.write(&ns, &raw_key, val.as_deref())?;
            }
        }
        Ok(self.logs)
    }
}

fn restore_accounts(state: &mut AccountState, snap: &BTreeMap<Address, (u64, u64)>) {
    state.accounts.retain(|addr, _| snap.contains_key(addr));
    for (addr, (bal, frac)) in snap {
        if let Some(acct) = state.accounts.get_mut(addr) {
            acct.balance = *bal;
            acct.frac_attos = *frac;
        }
    }
    state.keys_dirty = true;
}
