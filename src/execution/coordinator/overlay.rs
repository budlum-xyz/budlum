//! Nested transactional state overlay and block-level read cache (`BLG-260`).
//!
//! Every UEL call executes against an [`OverlayCore`] + [`ExecutionOverlay`]
//! backed by [`AccountState`] and a block-scoped [`BlockReadCache`]:
//!
//! 1. Reads check the overlay frame stack from top to bottom, then the block
//!    read cache, then `AccountState::uel_state` (caching clean hits for later
//!    transactions in the same block, closing `BLG-260`).
//! 2. Writes, `EeLog` emissions, and `bud_transfer` entries accumulate in the
//!    top frame.
//! 3. `universal_call` pushes a child frame with an EIP-150 `63/64` gas stipend
//!    up to [`MAX_UNIVERSAL_CALL_DEPTH`] (`8`). If the child fails, its frame
//!    is discarded (`pop_revert`) while its spent `BGU` is charged to the
//!    caller.
//! 4. On root transaction success, `commit_root` replays all surviving attoBUD
//!    transfers through [`AccountState::transfer_atto_bud`] and applies all
//!    surviving namespace writes, updating [`BlockReadCache`].

use std::collections::{BTreeMap, BTreeSet};
use std::cell::RefCell;

use budlum_uel_abi::{
    BudAmount, EeId, EeIdentity, EeLog, HostApi, HostError, HostRead, Namespace, OutOfGas,
    UniversalCall, UniversalResult,
};

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::execution::coordinator::accounts::{
    derive_contract_account, derive_foreign_account, ForeignScheme,
};
use crate::execution::coordinator::bud_unit::{account_bud_amount, unit_scale_atto};
use crate::execution::coordinator::commitment::{
    UelSubTree, NS_BUDZERO_PROGRAM, NS_BUDZERO_STORAGE, NS_EVM_ACCOUNT, NS_EVM_CODE,
    NS_EVM_STORAGE, NS_MOVE_STATE, NS_SVM_ACCOUNT, NS_UEL_ALIAS, NS_WASM_CODE, NS_WASM_CONTRACT,
    NS_WASM_STORE,
};
use crate::execution::coordinator::gas::{
    callee_gas_stipend, log_cost_bgu, read_cost_bgu, write_cost_bgu, BGU_BUD_TRANSFER,
    BGU_UNIVERSAL_CALL_BASE, BGU_UNIVERSAL_CALL_COLD_EXTRA, BGU_UNIVERSAL_CALL_WARM_EXTRA,
    MAX_UNIVERSAL_CALL_DEPTH,
};

/// Block-scoped clean read cache across transactions in the same block (`BLG-260`).
#[derive(Debug, Clone, Default)]
pub struct BlockReadCache {
    entries: BTreeMap<(String, Vec<u8>), Option<Vec<u8>>>,
    hits: u64,
    misses: u64,
}

impl BlockReadCache {
    /// Create a fresh empty block read cache at block open.
    ///
    /// Convenience: instantiated per block by the execution coordinator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of cache hits served in the current block.
    ///
    /// Convenience: exposed for coordinator telemetry and `BLG-260` verification.
    #[must_use]
    pub const fn hits(&self) -> u64 {
        self.hits
    }

    /// Number of cache misses populated from `AccountState` in the current block.
    ///
    /// Convenience: exposed for coordinator telemetry and `BLG-260` verification.
    #[must_use]
    pub const fn misses(&self) -> u64 {
        self.misses
    }

    /// Read `(ns, key)` through the cache, populating from `state` on a miss.
    pub fn get_or_load(&mut self, state: &AccountState, ns: &str, key: &[u8]) -> Option<Vec<u8>> {
        let lookup_key = (ns.to_string(), key.to_vec());
        if let Some(cached) = self.entries.get(&lookup_key) {
            self.hits = self.hits.saturating_add(1);
            return cached.clone();
        }
        self.misses = self.misses.saturating_add(1);
        let loaded = state.uel_state.read(ns, key).map(<[u8]>::to_vec);
        self.entries.insert(lookup_key, loaded.clone());
        loaded
    }

    /// Update a key upon root transaction commit so later txs read the fresh value.
    pub fn record_committed_write(&mut self, ns: &str, key: &[u8], val: Option<&[u8]>) {
        self.entries
            .insert((ns.to_string(), key.to_vec()), val.map(<[u8]>::to_vec));
    }

    /// Drop all cached entries at block close.
    ///
    /// Convenience: called by the block executor once a block finishes sealing.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.hits = 0;
        self.misses = 0;
    }
}

/// Callback invoked by [`ExecutionOverlay`] to run a nested `universal_call`.
pub trait UniversalDispatcher {
    /// Execute `call` against `core` (whose top frame is the newly pushed child frame).
    fn dispatch_universal(
        &mut self,
        core: &mut OverlayCore<'_>,
        call: &UniversalCall,
        next_depth: u32,
        stipend_bgu: u64,
    ) -> Result<UniversalResult, HostError>;
}

/// No-op dispatcher used by read-only queries or standalone single-EE tests.
#[derive(Debug, Default)]
pub struct NoopDispatcher;

impl UniversalDispatcher for NoopDispatcher {
    fn dispatch_universal(
        &mut self,
        _core: &mut OverlayCore<'_>,
        _call: &UniversalCall,
        _next_depth: u32,
        _stipend_bgu: u64,
    ) -> Result<UniversalResult, HostError> {
        Err(HostError::Denied(
            "universal_call dispatcher is not attached".into(),
        ))
    }
}

#[derive(Debug, Clone)]
struct OverlayFrame {
    active_ee: EeId,
    depth: u32,
    gas_limit: u64,
    gas_used: u64,
    writes: BTreeMap<(String, Vec<u8>), Option<Vec<u8>>>,
    shadow_balances: BTreeMap<Address, u128>,
    transfers: Vec<(Address, Address, u128)>,
    logs: Vec<EeLog>,
    warm_targets: BTreeSet<(u8, Vec<u8>)>,
}

impl OverlayFrame {
    fn new(active_ee: EeId, depth: u32, gas_limit: u64) -> Self {
        Self {
            active_ee,
            depth,
            gas_limit,
            gas_used: 0,
            writes: BTreeMap::new(),
            shadow_balances: BTreeMap::new(),
            transfers: Vec::new(),
            logs: Vec::new(),
            warm_targets: BTreeSet::new(),
        }
    }
}

/// Resolve an [`EeIdentity`] to its canonical 32-byte Budlum [`Address`].
///
/// Convenience: shared by coordinator overlays and RPC balance/call resolvers.
pub fn resolve_ee_identity(state: &AccountState, who: &EeIdentity) -> Result<Address, HostError> {
    if who.id.is_empty() {
        return Err(HostError::Invalid("empty EeIdentity".into()));
    }
    if let Some(local_addr) = lookup_local_by_alias(state, who.ee, &who.id) {
        return Ok(local_addr);
    }
    match who.ee {
        EeId::BUDZERO => {
            let bytes: [u8; 32] = who
                .id
                .as_slice()
                .try_into()
                .map_err(|_| HostError::Invalid("BudZero identity must be 32 bytes".into()))?;
            Ok(Address(bytes))
        }
        EeId::EVM => {
            if who.id.len() == 20 {
                derive_foreign_account(ForeignScheme::EvmSecp256k1, &who.id)
                    .map_err(|e| HostError::Invalid(e.to_string()))
            } else {
                derive_contract_account(EeId::EVM, &who.id)
                    .map_err(|e| HostError::Invalid(e.to_string()))
            }
        }
        EeId::SVM => {
            if who.id.len() == 32 {
                derive_foreign_account(ForeignScheme::SvmEd25519, &who.id)
                    .map_err(|e| HostError::Invalid(e.to_string()))
            } else {
                derive_contract_account(EeId::SVM, &who.id)
                    .map_err(|e| HostError::Invalid(e.to_string()))
            }
        }
        EeId::MOVE => {
            if who.id.len() == 32 {
                derive_foreign_account(ForeignScheme::AptosAuth, &who.id)
                    .map_err(|e| HostError::Invalid(e.to_string()))
            } else {
                derive_contract_account(EeId::MOVE, &who.id)
                    .map_err(|e| HostError::Invalid(e.to_string()))
            }
        }
        EeId::WASM => derive_contract_account(EeId::WASM, &who.id)
            .map_err(|e| HostError::Invalid(e.to_string())),
        other => Err(HostError::Invalid(format!(
            "unknown environment 0x{:02x}",
            other.0
        ))),
    }
}

fn lookup_local_by_alias(state: &AccountState, ee: EeId, native_id: &[u8]) -> Option<Address> {
    for addr in state.accounts.keys() {
        let mut key = [0u8; 33];
        if let Some((prefix, tail)) = key.split_at_mut_checked(32) {
            prefix.copy_from_slice(&addr.0);
            if let Some(slot) = tail.first_mut() {
                *slot = ee.0;
            }
        }
        if state.uel_state.read(NS_UEL_ALIAS, &key) == Some(native_id) {
            return Some(*addr);
        }
    }
    None
}

fn ee_may_write_namespace(ee: EeId, ns: &str) -> bool {
    match ee {
        EeId::EVM => matches!(ns, NS_EVM_ACCOUNT | NS_EVM_CODE | NS_EVM_STORAGE),
        EeId::WASM => matches!(ns, NS_WASM_CODE | NS_WASM_CONTRACT | NS_WASM_STORE),
        EeId::SVM => ns == NS_SVM_ACCOUNT,
        EeId::MOVE => ns == NS_MOVE_STATE,
        EeId::BUDZERO => matches!(ns, NS_BUDZERO_PROGRAM | NS_BUDZERO_STORAGE),
        _ => false,
    }
}

/// Frame-stack state of an in-flight UEL transaction.
pub struct OverlayCore<'a> {
    state: &'a AccountState,
    read_cache: RefCell<&'a mut BlockReadCache>,
    frames: Vec<OverlayFrame>,
}

impl<'a> OverlayCore<'a> {
    /// Open a root transaction overlay frame (`depth = 0`).
    ///
    /// Convenience: created by the execution coordinator for each UEL call/query.
    pub fn new(
        state: &'a AccountState,
        read_cache: &'a mut BlockReadCache,
        root_ee: EeId,
        gas_limit: u64,
    ) -> Self {
        Self {
            state,
            read_cache: RefCell::new(read_cache),
            frames: vec![OverlayFrame::new(root_ee, 0, gas_limit)],
        }
    }

    /// Total BGU consumed by the current top frame.
    ///
    /// Convenience: read by the coordinator when building transaction receipts.
    #[must_use]
    pub fn gas_used(&self) -> u64 {
        self.frames.last().map_or(0, |f| f.gas_used)
    }

    /// Remaining BGU in the current top frame.
    #[must_use]
    pub fn remaining_gas(&self) -> u64 {
        self.frames
            .last()
            .map_or(0, |f| f.gas_limit.saturating_sub(f.gas_used))
    }

    /// Push a nested child frame for `universal_call`.
    pub fn push_frame(&mut self, ee: EeId, depth: u32, gas_limit: u64) -> Result<(), HostError> {
        if depth > MAX_UNIVERSAL_CALL_DEPTH {
            return Err(HostError::DepthExceeded);
        }
        self.frames.push(OverlayFrame::new(ee, depth, gas_limit));
        Ok(())
    }

    /// Pop the top child frame on revert/fault, returning its `gas_used` and discarding mutations.
    pub fn pop_revert(&mut self) -> u64 {
        if self.frames.len() <= 1 {
            return self.gas_used();
        }
        self.frames.pop().map_or(0, |child| child.gas_used)
    }

    /// Pop the top child frame on success, merging its writes, transfers, and logs into its parent.
    pub fn pop_commit(&mut self) -> u64 {
        if self.frames.len() <= 1 {
            return self.gas_used();
        }
        let Some(child) = self.frames.pop() else {
            return 0;
        };
        let child_gas = child.gas_used;
        if let Some(parent) = self.frames.last_mut() {
            for (k, v) in child.writes {
                parent.writes.insert(k, v);
            }
            for (addr, bal) in child.shadow_balances {
                parent.shadow_balances.insert(addr, bal);
            }
            parent.transfers.extend(child.transfers);
            parent.logs.extend(child.logs);
            parent.warm_targets.extend(child.warm_targets);
        }
        child_gas
    }

    /// Charge `bgu` against the current top frame without mutating on `OutOfGas`.
    pub fn charge_frame(&mut self, bgu: u64) -> Result<(), OutOfGas> {
        let Some(top) = self.frames.last_mut() else {
            return Err(OutOfGas);
        };
        let next = top.gas_used.checked_add(bgu).ok_or(OutOfGas)?;
        if next > top.gas_limit {
            return Err(OutOfGas);
        }
        top.gas_used = next;
        Ok(())
    }

    /// Commit the root transaction frame into `AccountState` and update `BlockReadCache`.
    ///
    /// Convenience: called by the execution coordinator upon `OutcomeStatus::Success`.
    pub fn commit_root(mut self, state: &mut AccountState) -> Result<(u64, Vec<EeLog>), String> {
        if self.frames.len() != 1 {
            return Err("root overlay commit requires exactly one remaining frame".into());
        }
        let Some(root) = self.frames.first().cloned() else {
            return Err("missing root overlay frame".into());
        };
        for (from, to, attos) in &root.transfers {
            state.transfer_atto_bud(from, to, *attos)?;
        }
        let cache = self.read_cache.get_mut();
        for ((ns, key), val) in root.writes {
            cache.record_committed_write(&ns, &key, val.as_deref());
            state
                .uel_state
                .write(&ns, key, val)
                .map_err(|e| e.to_string())?;
        }
        Ok((root.gas_used, root.logs))
    }

    fn lookup_value(&self, ns: &str, key: &[u8]) -> Option<Vec<u8>> {
        let lookup = (ns.to_string(), key.to_vec());
        for frame in self.frames.iter().rev() {
            if let Some(entry) = frame.writes.get(&lookup) {
                return entry.clone();
            }
        }
        self.read_cache.borrow_mut().get_or_load(self.state, ns, key)
    }

    fn resolve_shadow_balance(&self, addr: &Address) -> Result<u128, HostError> {
        for frame in self.frames.iter().rev() {
            if let Some(bal) = frame.shadow_balances.get(addr) {
                return Ok(*bal);
            }
        }
        match self.state.accounts.get(addr) {
            Some(acc) => account_bud_amount(acc)
                .map(|b| b.0)
                .map_err(|e| HostError::Invalid(e.to_string())),
            None => Ok(0),
        }
    }

    fn is_target_warm(&self, ee: EeId, target: &[u8]) -> bool {
        let key = (ee.0, target.to_vec());
        self.frames.iter().any(|f| f.warm_targets.contains(&key))
    }

    fn record_transfer(
        &mut self,
        from: &EeIdentity,
        to: &EeIdentity,
        attos: u128,
        enforce_ee_scale: bool,
    ) -> Result<(), HostError> {
        if attos == 0 {
            return Ok(());
        }
        if enforce_ee_scale {
            let active_ee = self
                .frames
                .last()
                .map(|f| f.active_ee)
                .ok_or_else(|| HostError::Invalid("empty overlay stack".into()))?;
            let scale =
                unit_scale_atto(active_ee).map_err(|e| HostError::Invalid(e.to_string()))?;
            if !attos.is_multiple_of(scale) {
                return Err(HostError::Invalid(format!(
                    "transfer {attos} attoBUD is not a multiple of environment unit {scale}"
                )));
            }
        }
        let from_addr = resolve_ee_identity(self.state, from)?;
        let to_addr = resolve_ee_identity(self.state, to)?;
        if from_addr == to_addr {
            return Ok(());
        }
        let sender_bal = self.resolve_shadow_balance(&from_addr)?;
        let new_sender = sender_bal
            .checked_sub(attos)
            .ok_or_else(|| HostError::Insufficient("insufficient attoBUD balance".into()))?;
        let recipient_bal = self.resolve_shadow_balance(&to_addr)?;
        let new_recipient = recipient_bal
            .checked_add(attos)
            .ok_or_else(|| HostError::Invalid("recipient attoBUD overflow".into()))?;

        if let Some(top) = self.frames.last_mut() {
            top.shadow_balances.insert(from_addr, new_sender);
            top.shadow_balances.insert(to_addr, new_recipient);
            top.transfers.push((from_addr, to_addr, attos));
        }
        Ok(())
    }
}

impl HostRead for OverlayCore<'_> {
    fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
        if UelSubTree::from_namespace(ns.as_str()).is_none() {
            return Err(HostError::Denied(format!(
                "unknown namespace `{}`",
                ns.as_str()
            )));
        }
        Ok(self.lookup_value(ns.as_str(), key))
    }

    fn bud_balance(&self, who: &EeIdentity) -> Result<BudAmount, HostError> {
        let addr = resolve_ee_identity(self.state, who)?;
        self.resolve_shadow_balance(&addr).map(BudAmount)
    }
}

/// Host handle pairing an [`OverlayCore`] with a [`UniversalDispatcher`].
pub struct ExecutionOverlay<'a, 'd, D: UniversalDispatcher = NoopDispatcher> {
    pub core: &'d mut OverlayCore<'a>,
    pub dispatcher: &'d mut D,
}

impl<'a, 'd, D: UniversalDispatcher> ExecutionOverlay<'a, 'd, D> {
    /// Bind `core` and `dispatcher` into a [`HostApi`] adapter.
    ///
    /// Convenience: constructed by the coordinator and nested `universal_call` frames.
    pub fn new(core: &'d mut OverlayCore<'a>, dispatcher: &'d mut D) -> Self {
        Self { core, dispatcher }
    }
}

impl<D: UniversalDispatcher> HostRead for ExecutionOverlay<'_, '_, D> {
    fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
        HostRead::read(&*self.core, ns, key)
    }

    fn bud_balance(&self, who: &EeIdentity) -> Result<BudAmount, HostError> {
        HostRead::bud_balance(&*self.core, who)
    }
}

impl<D: UniversalDispatcher> HostApi for ExecutionOverlay<'_, '_, D> {
    fn write(&mut self, ns: &Namespace, key: &[u8], value: Option<&[u8]>) -> Result<(), HostError> {
        let ns_str = ns.as_str();
        if UelSubTree::from_namespace(ns_str).is_none() {
            return Err(HostError::Denied(format!("unknown namespace `{ns_str}`")));
        }
        let active_ee = self
            .core
            .frames
            .last()
            .map(|f| f.active_ee)
            .ok_or_else(|| HostError::Invalid("empty overlay stack".into()))?;
        if !ee_may_write_namespace(active_ee, ns_str) {
            return Err(HostError::Denied(format!(
                "environment 0x{:02x} cannot write namespace `{ns_str}`",
                active_ee.0
            )));
        }

        let existing = self.core.lookup_value(ns_str, key);
        let cost = write_cost_bgu(existing.is_none(), key.len(), value.map_or(0, <[u8]>::len));
        self.core.charge_frame(cost)?;

        if let Some(top) = self.core.frames.last_mut() {
            top.writes
                .insert((ns_str.to_string(), key.to_vec()), value.map(<[u8]>::to_vec));
        }
        Ok(())
    }

    fn universal_call(&mut self, call: UniversalCall) -> Result<UniversalResult, HostError> {
        let current_depth = self.core.frames.last().map_or(0, |f| f.depth);
        let next_depth = current_depth.saturating_add(1);
        if next_depth > MAX_UNIVERSAL_CALL_DEPTH {
            return Err(HostError::DepthExceeded);
        }
        // Section 8.7.3 item 6: cross-environment reentrancy into an EE already
        // on the active call stack is forbidden in Phase 1.
        if self.core.frames.iter().any(|f| f.active_ee == call.to_ee) {
            return Err(HostError::Denied("ReentrancyForbidden".into()));
        }

        let warm = self.core.is_target_warm(call.to_ee, &call.target.id);
        let overhead = BGU_UNIVERSAL_CALL_BASE.saturating_add(if warm {
            BGU_UNIVERSAL_CALL_WARM_EXTRA
        } else {
            BGU_UNIVERSAL_CALL_COLD_EXTRA
        });
        self.core.charge_frame(overhead)?;

        if let Some(top) = self.core.frames.last_mut() {
            top.warm_targets
                .insert((call.to_ee.0, call.target.id.clone()));
        }

        let stipend = callee_gas_stipend(self.core.remaining_gas(), call.gas_limit);
        self.core.push_frame(call.to_ee, next_depth, stipend)?;

        if call.value.0 > 0
            && self
                .core
                .record_transfer(&call.from, &call.target, call.value.0, false)
                .is_err()
        {
            let _ = self.core.pop_revert();
            return Ok(UniversalResult {
                success: false,
                output: Vec::new(),
                gas_used: 0,
            });
        }

        match self
            .dispatcher
            .dispatch_universal(self.core, &call, next_depth, stipend)
        {
            Ok(res) => {
                let child_spent = if res.success {
                    self.core.pop_commit().max(res.gas_used).min(stipend)
                } else {
                    self.core.pop_revert().max(res.gas_used).min(stipend)
                };
                self.core.charge_frame(child_spent)?;
                Ok(UniversalResult {
                    success: res.success,
                    output: res.output,
                    gas_used: child_spent,
                })
            }
            Err(err) => {
                let _ = self.core.pop_revert();
                Err(err)
            }
        }
    }

    fn emit_log(&mut self, log: EeLog) -> Result<(), HostError> {
        let cost = log_cost_bgu(log.topics.len(), log.data.len());
        self.core.charge_frame(cost)?;
        if let Some(top) = self.core.frames.last_mut() {
            top.logs.push(log);
        }
        Ok(())
    }

    fn charge(&mut self, bgu: u64) -> Result<(), OutOfGas> {
        self.core.charge_frame(bgu)
    }

    fn bud_transfer(
        &mut self,
        from: &EeIdentity,
        to: &EeIdentity,
        attos: u128,
    ) -> Result<(), HostError> {
        self.core.charge_frame(BGU_BUD_TRANSFER)?;
        self.core.record_transfer(from, to, attos, true)
    }
}

/// Charge read gas for an explicit metered read against `OverlayCore`.
///
/// Convenience: exposed for worker adapters that meter host reads explicitly.
pub fn metered_overlay_read(
    core: &mut OverlayCore<'_>,
    ns: &Namespace,
    key: &[u8],
) -> Result<Option<Vec<u8>>, HostError> {
    let val = HostRead::read(core, ns, key)?;
    let cost = read_cost_bgu(key.len(), val.as_ref().map_or(0, Vec::len));
    core.charge_frame(cost)?;
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::account::{Account, ATTO_PER_ATOM};

    struct ScriptedDispatcher;

    impl UniversalDispatcher for ScriptedDispatcher {
        fn dispatch_universal(
            &mut self,
            core: &mut OverlayCore<'_>,
            call: &UniversalCall,
            _next_depth: u32,
            _stipend_bgu: u64,
        ) -> Result<UniversalResult, HostError> {
            let mut child_overlay = ExecutionOverlay::new(core, self);
            match call.input.first().copied().unwrap_or(0) {
                // 0x01 = write to WASM store and succeed
                1 => {
                    let ns = Namespace::new(NS_WASM_STORE).unwrap();
                    child_overlay
                        .write(&ns, b"child_key", Some(b"ok"))
                        .unwrap();
                    Ok(UniversalResult {
                        success: true,
                        output: b"done".to_vec(),
                        gas_used: child_overlay.core.gas_used(),
                    })
                }
                // 0x02 = write to WASM store and revert
                2 => {
                    let ns = Namespace::new(NS_WASM_STORE).unwrap();
                    child_overlay
                        .write(&ns, b"reverted_key", Some(b"nope"))
                        .unwrap();
                    Ok(UniversalResult {
                        success: false,
                        output: b"revert".to_vec(),
                        gas_used: child_overlay.core.gas_used(),
                    })
                }
                // 0x03 = recurse across distinct environment ids until depth limit
                3 => {
                    let mut next_call = call.clone();
                    next_call.to_ee = EeId(call.to_ee.0.saturating_add(1));
                    next_call.value = BudAmount(0);
                    let inner = child_overlay.universal_call(next_call)?;
                    Ok(inner)
                }
                _ => Ok(UniversalResult {
                    success: true,
                    output: Vec::new(),
                    gas_used: 0,
                }),
            }
        }
    }

    #[test]
    fn block_read_cache_serves_repeated_reads_and_updates_on_commit() {
        let mut state = AccountState::new();
        state
            .uel_state
            .write(NS_EVM_STORAGE, b"slot0".to_vec(), Some(vec![0x11]))
            .unwrap();

        let mut cache = BlockReadCache::new();
        let ns = Namespace::new(NS_EVM_STORAGE).unwrap();

        {
            let core = OverlayCore::new(&state, &mut cache, EeId::EVM, 500_000);
            assert_eq!(HostRead::read(&core, &ns, b"slot0").unwrap(), Some(vec![0x11]));
            assert_eq!(HostRead::read(&core, &ns, b"slot0").unwrap(), Some(vec![0x11]));
        }
        assert_eq!(cache.misses(), 1);
        assert_eq!(cache.hits(), 1);

        // Second tx updates slot0 and commits; third tx reads updated value from cache.
        {
            let mut disp = NoopDispatcher;
            let mut core = OverlayCore::new(&state, &mut cache, EeId::EVM, 500_000);
            {
                let mut host = ExecutionOverlay::new(&mut core, &mut disp);
                host.write(&ns, b"slot0", Some(&[0x22])).unwrap();
            }
            core.commit_root(&mut state).unwrap();
        }
        {
            let core = OverlayCore::new(&state, &mut cache, EeId::EVM, 500_000);
            assert_eq!(HostRead::read(&core, &ns, b"slot0").unwrap(), Some(vec![0x22]));
        }
        assert_eq!(cache.misses(), 1);
        assert!(cache.hits() >= 2);
    }

    #[test]
    fn coordinator_overlay_rolls_back_frame() {
        let mut state = AccountState::new();
        let alice = Address([0xA1; 32]);
        let mut acc = Account::new(alice);
        acc.balance = 1_000;
        state.accounts.insert(alice, acc);
        let alice_evm = state
            .uel_state
            .ensure_alias_registered(&alice, EeId::EVM)
            .unwrap();
        let supply_before = state.total_atto_bud_committed();

        let mut cache = BlockReadCache::new();
        let mut disp = ScriptedDispatcher;
        let caller_id = EeIdentity::new(EeId::EVM, alice_evm).unwrap();
        let target_id = EeIdentity::new(EeId::WASM, b"bud1contract".to_vec()).unwrap();

        let mut core = OverlayCore::new(&state, &mut cache, EeId::EVM, 5_000_000);
        {
            let mut host = ExecutionOverlay::new(&mut core, &mut disp);
            // 1. Reverted child call: its write and value transfer must vanish!
            let rev = host
                .universal_call(UniversalCall {
                    from: caller_id.clone(),
                    to_ee: EeId::WASM,
                    target: target_id.clone(),
                    value: BudAmount(10 * ATTO_PER_ATOM),
                    input: vec![2],
                    gas_limit: 200_000,
                })
                .unwrap();
            assert!(!rev.success);
            assert!(rev.gas_used > 0);
            let wasm_ns = Namespace::new(NS_WASM_STORE).unwrap();
            assert_eq!(host.read(&wasm_ns, b"reverted_key").unwrap(), None);
            assert_eq!(
                host.bud_balance(&caller_id).unwrap(),
                BudAmount(1_000 * ATTO_PER_ATOM)
            );

            // 2. Successful child call: its write and value transfer survive!
            let ok = host
                .universal_call(UniversalCall {
                    from: caller_id.clone(),
                    to_ee: EeId::WASM,
                    target: target_id.clone(),
                    value: BudAmount(5 * ATTO_PER_ATOM),
                    input: vec![1],
                    gas_limit: 200_000,
                })
                .unwrap();
            assert!(ok.success);
            assert_eq!(
                host.read(&wasm_ns, b"child_key").unwrap(),
                Some(b"ok".to_vec())
            );

            // 3. Recursion beyond MAX_UNIVERSAL_CALL_DEPTH (8) returns DepthExceeded!
            let deep = host.universal_call(UniversalCall {
                from: caller_id,
                to_ee: EeId::WASM,
                target: target_id,
                value: BudAmount(0),
                input: vec![3],
                gas_limit: 2_000_000,
            });
            assert_eq!(deep, Err(HostError::DepthExceeded));
        }
        core.commit_root(&mut state).unwrap();
        assert_eq!(state.total_atto_bud_committed(), supply_before);
        assert_eq!(state.get_balance(&alice), 995);
    }
}
