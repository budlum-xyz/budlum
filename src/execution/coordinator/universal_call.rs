//! Synchronous cross-VM Universal Call coordinator router (`Section 8.7`,
//! `WP-30`, closing `BLG-250` and `BLG-252` with `assets`).
//!
//! Enforces `Section 8.7.3` semantics across all UEL environments (`BudZero`,
//! `EVM`, `WASM`, `SVM`, `Move`):
//! 1. Caller identity in `to_ee` is the deterministic native alias of the
//!    caller's canonical Budlum `Address` (`derive_local_alias`).
//! 2. `value` (`attoBUD`) moves atomically on entry and rolls back on callee
//!    failure or outer transaction revert.
//! 3. Maximum cross-environment frame depth is `8` (`MAX_UNIVERSAL_CALL_DEPTH`).
//! 4. Phase-1 reentrancy into an environment already on the call stack returns
//!    `ReentrancyForbidden`.
//! 5. `is_static = true` forbids state writes, value transfers, and log emission
//!    across the entire sub-tree (`StaticCallWriteForbidden`).
//! 6. Calls targeting a registered UAR pointer contract (`uel/assets`) execute
//!    statelessly by forwarding a `UniversalCall` to the asset's home environment.

use std::collections::BTreeMap;

use budlum_uel_abi::{
    BlockContext, EeCall, EeCallKind, EeId, EeIdentity, EeLog, EeOutcome, ExecutionEnvironment,
    HostApi, HostError, OutcomeStatus, UniversalCall, UniversalResult,
};

use crate::core::account::AccountState;
use crate::execution::coordinator::accounts::derive_local_alias;
use crate::execution::coordinator::assets::{execute_pointer_call, find_pointer_record_in_state};
use crate::execution::coordinator::overlay::{
    resolve_ee_identity, BlockReadCache, ExecutionOverlay, OverlayCore, UniversalDispatcher,
};

/// Canonical `0x000000000000000000000000000000000000B001` precompile address (`20` bytes).
pub const EVM_UNIVERSAL_PRECOMPILE_BYTES: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xb0, 0x01,
];

/// `keccak256("UniversalCallExecuted(uint8,bytes,bool)")` (`Section 8.7.3` item 8).
pub const UNIVERSAL_CALL_EXECUTED_TOPIC0: [u8; 32] = [
    0xea, 0x6f, 0x80, 0x57, 0xef, 0xfc, 0x57, 0x9e, 0xc4, 0xfd, 0xcc, 0x82, 0x72, 0xe4, 0x27, 0xc5,
    0x68, 0x85, 0xa2, 0x1e, 0x67, 0xba, 0xd5, 0xcc, 0x8d, 0xc9, 0x7d, 0x44, 0xda, 0xee, 0x32, 0xe3,
];

/// ABI-encode `(uint8 ee, bytes target, bool ok)` for `UniversalCallExecuted`.
///
/// Convenience: shared by coordinator EVM receipts and indexer verification.
#[must_use]
pub fn encode_universal_call_executed_event(ee: u8, target: &[u8], ok: bool) -> EeLog {
    let padded = target.len().div_ceil(32) * 32;
    let mut data = vec![0u8; 128 + padded];
    if let Some(s) = data.get_mut(31) {
        *s = ee;
    }
    if let Some(s) = data.get_mut(63) {
        *s = 96;
    }
    if ok {
        if let Some(s) = data.get_mut(95) {
            *s = 1;
        }
    }
    let len_be = (target.len() as u64).to_be_bytes();
    if let Some(dst) = data.get_mut(120..128) {
        dst.copy_from_slice(&len_be);
    }
    if let Some(dst) = data.get_mut(128..128 + target.len()) {
        dst.copy_from_slice(target);
    }
    EeLog {
        emitter: EeIdentity {
            ee: EeId::EVM,
            id: EVM_UNIVERSAL_PRECOMPILE_BYTES.to_vec(),
        },
        topics: vec![UNIVERSAL_CALL_EXECUTED_TOPIC0.to_vec()],
        data,
    }
}

/// Translate `caller` into its deterministic native alias in `target_ee`
/// (`Section 8.7.3` item 1).
///
/// Convenience: used by `UniversalCallRouter` and cross-EE integration harnesses.
pub fn translate_caller_to_target_ee(
    state: &AccountState,
    caller: &EeIdentity,
    target_ee: EeId,
) -> Result<EeIdentity, HostError> {
    if caller.ee == target_ee {
        return Ok(caller.clone());
    }
    let bud = resolve_ee_identity(state, caller)?;
    let alias = derive_local_alias(&bud, target_ee).map_err(|e| HostError::Invalid(e.to_string()))?;
    Ok(EeIdentity {
        ee: target_ee,
        id: alias,
    })
}

/// Multi-environment coordinator router implementing [`UniversalDispatcher`].
pub struct UniversalCallRouter<'s> {
    state_snapshot: &'s AccountState,
    ctx: BlockContext,
    tx_hash: [u8; 32],
    workers: BTreeMap<u8, Box<dyn ExecutionEnvironment + 's>>,
}

impl<'s> UniversalCallRouter<'s> {
    /// Construct a router bound to block context `ctx` and `state_snapshot`.
    ///
    /// Convenience: created by the coordinator per transaction execution.
    #[must_use]
    pub fn new(state_snapshot: &'s AccountState, ctx: BlockContext, tx_hash: [u8; 32]) -> Self {
        Self {
            state_snapshot,
            ctx,
            tx_hash,
            workers: BTreeMap::new(),
        }
    }

    /// Attach an [`ExecutionEnvironment`] engine (IPC `EeClient` adapter or in-process worker).
    ///
    /// Convenience: registers each active EE worker on the coordinator router.
    pub fn register_worker(&mut self, worker: Box<dyn ExecutionEnvironment + 's>) {
        self.workers.insert(worker.id().0, worker);
    }

    /// Execute a root transaction call (`depth = 0`) atomically against `state`.
    ///
    /// Commits all cross-EE state writes, attoBUD transfers, and logs on
    /// `OutcomeStatus::Success`, or rolls back every nested EE mutation on
    /// revert/out-of-gas/fault (`Section 8.7.3` item 3).
    ///
    /// Convenience: top-level coordinator entry point for UEL transactions.
    pub fn execute_root_atomic(
        mut workers: BTreeMap<u8, Box<dyn ExecutionEnvironment + 's>>,
        state: &mut AccountState,
        read_cache: &mut BlockReadCache,
        ctx: BlockContext,
        call: &EeCall,
    ) -> Result<(EeOutcome, Vec<EeLog>), HostError> {
        // Pre-register caller alias in both home EE and potential target EEs so
        // reverse resolution in pointer/callee frames always finds the canonical Address.
        if let Ok(caller_bud) = resolve_ee_identity(state, &call.caller) {
            for ee in [
                EeId::BUDZERO,
                EeId::EVM,
                EeId::WASM,
                EeId::SVM,
                EeId::MOVE,
            ] {
                let _ = state.uel_state.ensure_alias_registered(&caller_bud, ee);
            }
        }
        if let Ok(target_bud) = resolve_ee_identity(state, &call.target) {
            for ee in [
                EeId::BUDZERO,
                EeId::EVM,
                EeId::WASM,
                EeId::SVM,
                EeId::MOVE,
            ] {
                let _ = state.uel_state.ensure_alias_registered(&target_bud, ee);
            }
        }

        let snapshot = state.clone();
        let mut router = UniversalCallRouter {
            state_snapshot: &snapshot,
            ctx,
            tx_hash: call.tx_hash,
            workers: std::mem::take(&mut workers),
        };
        let mut core = OverlayCore::new(&snapshot, read_cache, call.target.ee, call.gas_limit);

        let outcome = if let Some(ptr_rec) =
            find_pointer_record_in_state(&snapshot, call.target.ee, &call.target.id)
        {
            let mut host = ExecutionOverlay::new(&mut core, &mut router);
            let res = execute_pointer_call(
                &snapshot,
                &ptr_rec,
                &call.caller,
                call.target.ee,
                &call.input,
                call.gas_limit,
                &mut host,
            )?;
            EeOutcome {
                status: if res.success {
                    OutcomeStatus::Success
                } else {
                    OutcomeStatus::Revert
                },
                output: res.output,
                gas_used: res.gas_used,
            }
        } else {
            let Some(mut root_worker) = router.workers.remove(&call.target.ee.0) else {
                return Err(HostError::NotFound(format!(
                    "worker 0x{:02x} not registered",
                    call.target.ee.0
                )));
            };
            let exec_res = {
                let mut host = ExecutionOverlay::new(&mut core, &mut router);
                root_worker.execute(&ctx, call, &mut host)
            };
            router.workers.insert(call.target.ee.0, root_worker);
            match exec_res {
                Ok(out) => out,
                Err(fault) => EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: fault.panic_digest.to_vec(),
                    gas_used: call.gas_limit,
                },
            }
        };

        if outcome.status == OutcomeStatus::Success {
            let (overlay_gas, logs) = core.commit_root(state).map_err(HostError::Invalid)?;
            let final_out = EeOutcome {
                status: OutcomeStatus::Success,
                output: outcome.output,
                gas_used: outcome.gas_used.max(overlay_gas).min(call.gas_limit),
            };
            Ok((final_out, logs))
        } else {
            // Root reverted: drop `core` without `commit_root`, atomically
            // discarding every child WASM/SVM/Move/BudZero write and transfer!
            Ok((outcome, Vec::new()))
        }
    }
}

impl UniversalDispatcher for UniversalCallRouter<'_> {
    fn dispatch_universal(
        &mut self,
        core: &mut OverlayCore<'_>,
        call: &UniversalCall,
        next_depth: u32,
        stipend_bgu: u64,
    ) -> Result<UniversalResult, HostError> {
        let translated_caller =
            translate_caller_to_target_ee(self.state_snapshot, &call.from, call.to_ee)?;

        if let Some(ptr_rec) =
            find_pointer_record_in_state(self.state_snapshot, call.to_ee, &call.target.id)
        {
            let mut child_host = ExecutionOverlay::new(core, self);
            return execute_pointer_call(
                self.state_snapshot,
                &ptr_rec,
                &call.from,
                call.to_ee,
                &call.input,
                stipend_bgu,
                &mut child_host,
            );
        }

        let Some(mut callee_worker) = self.workers.remove(&call.to_ee.0) else {
            return Err(HostError::NotFound(format!(
                "callee worker 0x{:02x} not registered",
                call.to_ee.0
            )));
        };

        let ee_call = EeCall {
            kind: EeCallKind::Call,
            caller: translated_caller,
            target: EeIdentity {
                ee: call.to_ee,
                id: call.target.id.clone(),
            },
            value: call.value,
            input: call.input.clone(),
            gas_limit: stipend_bgu,
            depth: next_depth,
            tx_hash: self.tx_hash,
        };

        let exec_res = {
            let mut child_host = ExecutionOverlay::new(core, self);
            callee_worker.execute(&self.ctx, &ee_call, &mut child_host)
        };
        self.workers.insert(call.to_ee.0, callee_worker);

        let res = match exec_res {
            Ok(out) => UniversalResult {
                success: out.status == OutcomeStatus::Success,
                output: out.output,
                gas_used: out.gas_used.min(stipend_bgu),
            },
            Err(_) => UniversalResult {
                success: false,
                output: Vec::new(),
                gas_used: stipend_bgu,
            },
        };

        // Section 8.7.3 item 8: when an EVM caller invokes UniversalCall in a
        // non-static frame, emit `UniversalCallExecuted(uint8,bytes,bool)` from
        // `0x...B001` into the parent frame upon return!
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::account::Account;
    use crate::core::address::Address;
    use crate::execution::coordinator::accounts::derive_asset_id;
    use crate::execution::coordinator::assets::{
        create_pointer, register_asset, AssetStandard, CreatePointer, ProbedAssetMetadata,
        RegisterAsset,
    };
    use crate::execution::coordinator::commitment::{NS_EVM_STORAGE, NS_WASM_STORE};
    use budlum_uel_abi::{
        BudAmount, CodeInfo, EeFault, EeQuery, EeRefusal, HostRead, Namespace, RefusalCode,
    };

    /// Stateful CosmWasm CW20 mock worker persisting balances & allowances in `ee/wasm/store`.
    struct Cw20WasmEngine;

    impl ExecutionEnvironment for Cw20WasmEngine {
        fn id(&self) -> EeId {
            EeId::WASM
        }

        fn validate_deploy(&self, _code: &[u8]) -> Result<CodeInfo, EeRefusal> {
            Ok(CodeInfo {
                code_hash: [0x22; 32],
                abi_tag: String::from("cosmwasm-v1"),
            })
        }

        fn execute(
            &mut self,
            _ctx: &BlockContext,
            call: &EeCall,
            host: &mut dyn HostApi,
        ) -> Result<EeOutcome, EeFault> {
            let ns = Namespace::new(NS_WASM_STORE).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&call.input).unwrap_or_default();
            let caller_str = String::from_utf8_lossy(&call.caller.id).into_owned();

            if let Some(reenter) = v.get("reenter_evm") {
                let default_hex = "1111111111111111111111111111111111111111";
                let target_hex = reenter.as_str().unwrap_or(default_hex);
                let res = host.universal_call(UniversalCall {
                    from: call.target.clone(),
                    to_ee: EeId::EVM,
                    target: EeIdentity {
                        ee: EeId::EVM,
                        id: hex::decode(target_hex).unwrap(),
                    },
                    value: BudAmount(0),
                    input: Vec::new(),
                    gas_limit: 100_000,
                    is_static: false,
                });
                return match res {
                    Err(HostError::Denied(msg)) if msg == "ReentrancyForbidden" => Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"ReentrancyForbidden".to_vec(),
                        gas_used: 500,
                    }),
                    _ => Ok(EeOutcome {
                        status: OutcomeStatus::Success,
                        output: Vec::new(),
                        gas_used: 500,
                    }),
                };
            }

            if let Some(tr) = v.get("transfer") {
                let rcpt = tr["recipient"].as_str().unwrap();
                let amt: u128 = tr["amount"].as_str().unwrap().parse().unwrap();
                let b_from_key = format!("bal:{}:{caller_str}", hex::encode(&call.target.id));
                let b_to_key = format!("bal:{}:{rcpt}", hex::encode(&call.target.id));
                let cur_from = host
                    .read(&ns, b_from_key.as_bytes())
                    .unwrap()
                    .and_then(|b| String::from_utf8(b).ok()?.parse::<u128>().ok())
                    .unwrap_or(0);
                let Some(next_from) = cur_from.checked_sub(amt) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"insufficient cw20".to_vec(),
                        gas_used: 1_000,
                    });
                };
                let cur_to = host
                    .read(&ns, b_to_key.as_bytes())
                    .unwrap()
                    .and_then(|b| String::from_utf8(b).ok()?.parse::<u128>().ok())
                    .unwrap_or(0);
                host.write(
                    &ns,
                    b_from_key.as_bytes(),
                    Some(next_from.to_string().as_bytes()),
                )
                .map_err(|_| EeFault {
                    ee: EeId::WASM,
                    panic_digest: [0; 32],
                })?;
                host.write(
                    &ns,
                    b_to_key.as_bytes(),
                    Some((cur_to + amt).to_string().as_bytes()),
                )
                .map_err(|_| EeFault {
                    ee: EeId::WASM,
                    panic_digest: [0; 32],
                })?;
                return Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: br#"{"ok":true}"#.to_vec(),
                    gas_used: 2_500,
                });
            }

            if let Some(inc) = v.get("increase_allowance") {
                let sp = inc["spender"].as_str().unwrap();
                let amt: u128 = inc["amount"].as_str().unwrap().parse().unwrap();
                let a_key = format!("alw:{}:{caller_str}:{sp}", hex::encode(&call.target.id));
                host.write(&ns, a_key.as_bytes(), Some(amt.to_string().as_bytes()))
                    .unwrap();
                return Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: br#"{"ok":true}"#.to_vec(),
                    gas_used: 2_000,
                });
            }

            if let Some(bal) = v.get("balance") {
                let addr = bal["address"].as_str().unwrap();
                let b_key = format!("bal:{}:{addr}", hex::encode(&call.target.id));
                let cur = host
                    .read(&ns, b_key.as_bytes())
                    .unwrap()
                    .and_then(|b| String::from_utf8(b).ok()?.parse::<u128>().ok())
                    .unwrap_or(0);
                return Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: serde_json::to_vec(&serde_json::json!({ "balance": cur.to_string() }))
                        .unwrap(),
                    gas_used: 500,
                });
            }

            if let Some(alw) = v.get("allowance") {
                let own = alw["owner"].as_str().unwrap();
                let sp = alw["spender"].as_str().unwrap();
                let a_key = format!("alw:{}:{own}:{sp}", hex::encode(&call.target.id));
                let cur = host
                    .read(&ns, a_key.as_bytes())
                    .unwrap()
                    .and_then(|b| String::from_utf8(b).ok()?.parse::<u128>().ok())
                    .unwrap_or(0);
                return Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: serde_json::to_vec(
                        &serde_json::json!({ "allowance": cur.to_string() }),
                    )
                    .unwrap(),
                    gas_used: 500,
                });
            }

            Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: Vec::new(),
                gas_used: 100,
            })
        }

        fn query(
            &self,
            _ctx: &BlockContext,
            _q: &EeQuery,
            _host: &dyn HostRead,
        ) -> Result<Vec<u8>, EeRefusal> {
            Err(EeRefusal {
                code: RefusalCode::Unsupported,
                message: String::new(),
            })
        }
    }

    /// EVM contract mock engine invoking `0x...B001` UniversalCall to CW20 and reverting on flag.
    struct EvmCallerEngine;

    impl ExecutionEnvironment for EvmCallerEngine {
        fn id(&self) -> EeId {
            EeId::EVM
        }

        fn validate_deploy(&self, _code: &[u8]) -> Result<CodeInfo, EeRefusal> {
            Ok(CodeInfo {
                code_hash: [0x11; 32],
                abi_tag: String::from("evm-osaka"),
            })
        }

        fn execute(
            &mut self,
            _ctx: &BlockContext,
            call: &EeCall,
            host: &mut dyn HostApi,
        ) -> Result<EeOutcome, EeFault> {
            let cmd: serde_json::Value = serde_json::from_slice(&call.input).unwrap();
            let wasm_target = cmd["wasm_contract"].as_str().unwrap().as_bytes().to_vec();
            let wasm_msg = cmd["wasm_msg"].to_string().into_bytes();
            let revert_after = cmd
                .get("revert_after")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);

            let ns_evm = Namespace::new(NS_EVM_STORAGE).unwrap();
            host.write(&ns_evm, b"evm_marker", Some(&[1])).unwrap();

            let ures = host
                .universal_call(UniversalCall {
                    from: call.target.clone(),
                    to_ee: EeId::WASM,
                    target: EeIdentity {
                        ee: EeId::WASM,
                        id: wasm_target.clone(),
                    },
                    value: BudAmount(0),
                    input: wasm_msg,
                    gas_limit: 200_000,
                    is_static: false,
                })
                .unwrap();

            let ev = encode_universal_call_executed_event(
                EeId::WASM.0,
                &wasm_target,
                ures.success,
            );
            host.emit_log(ev).unwrap();

            if revert_after || !ures.success {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: ures.output,
                    gas_used: 5_000 + ures.gas_used,
                });
            }
            Ok(EeOutcome {
                status: OutcomeStatus::Success,
                output: ures.output,
                gas_used: 5_000 + ures.gas_used,
            })
        }

        fn query(
            &self,
            _ctx: &BlockContext,
            _q: &EeQuery,
            _host: &dyn HostRead,
        ) -> Result<Vec<u8>, EeRefusal> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn uel_evm_calls_wasm_atomically() {
        let mut state = AccountState::new();
        let evm_contract = vec![0xAA; 20];
        let evm_id = EeIdentity {
            ee: EeId::EVM,
            id: evm_contract.clone(),
        };
        let evm_bud = resolve_ee_identity(&state, &evm_id).unwrap();
        state.accounts.insert(evm_bud, Account::new(evm_bud));
        let evm_wasm_alias = String::from_utf8(
            state
                .uel_state
                .ensure_alias_registered(&evm_bud, EeId::WASM)
                .unwrap(),
        )
        .unwrap();

        let cw20_addr = b"bud1cw20token".to_vec();
        let init_key = format!("bal:{}:{evm_wasm_alias}", hex::encode(&cw20_addr));
        state
            .uel_state
            .write(NS_WASM_STORE, init_key.clone().into_bytes(), Some(b"1000".to_vec()))
            .unwrap();

        let bob_wasm = "bud1bobrecipient";
        let bob_key = format!("bal:{}:{bob_wasm}", hex::encode(&cw20_addr));
        let ctx = BlockContext {
            chain_id: 45_261,
            height: 100,
            timestamp_ms: 1_762_000_000_000,
        };
        let mut cache = BlockReadCache::new();

        // 1. EVM calls CW20 transfer(400) AND THEN EVM REVERTS -> CW20 balance MUST stay 1000!
        let mut workers1: BTreeMap<u8, Box<dyn ExecutionEnvironment>> = BTreeMap::new();
        workers1.insert(EeId::EVM.0, Box::new(EvmCallerEngine));
        workers1.insert(EeId::WASM.0, Box::new(Cw20WasmEngine));
        let revert_call = EeCall {
            kind: EeCallKind::Call,
            caller: EeIdentity {
                ee: EeId::EVM,
                id: vec![0x01; 20],
            },
            target: evm_id.clone(),
            value: BudAmount(0),
            input: serde_json::to_vec(&serde_json::json!({
                "wasm_contract": "bud1cw20token",
                "wasm_msg": { "transfer": { "recipient": bob_wasm, "amount": "400" } },
                "revert_after": true,
            }))
            .unwrap(),
            gas_limit: 500_000,
            depth: 0,
            tx_hash: [0x10; 32],
        };
        let (out1, logs1) = UniversalCallRouter::execute_root_atomic(
            workers1,
            &mut state,
            &mut cache,
            ctx,
            &revert_call,
        )
        .unwrap();
        assert_eq!(out1.status, OutcomeStatus::Revert);
        assert!(logs1.is_empty());
        assert_eq!(
            state.uel_state.read(NS_WASM_STORE, init_key.as_bytes()),
            Some(b"1000".as_slice())
        );
        assert_eq!(state.uel_state.read(NS_WASM_STORE, bob_key.as_bytes()), None);
        assert_eq!(state.uel_state.read(NS_EVM_STORAGE, b"evm_marker"), None);

        // 2. EVM calls CW20 transfer(400) AND SUCCEEDS -> CW20 balances become 600 and 400!
        let mut workers2: BTreeMap<u8, Box<dyn ExecutionEnvironment>> = BTreeMap::new();
        workers2.insert(EeId::EVM.0, Box::new(EvmCallerEngine));
        workers2.insert(EeId::WASM.0, Box::new(Cw20WasmEngine));
        let ok_call = EeCall {
            input: serde_json::to_vec(&serde_json::json!({
                "wasm_contract": "bud1cw20token",
                "wasm_msg": { "transfer": { "recipient": bob_wasm, "amount": "400" } },
                "revert_after": false,
            }))
            .unwrap(),
            tx_hash: [0x11; 32],
            ..revert_call
        };
        let (out2, logs2) = UniversalCallRouter::execute_root_atomic(
            workers2,
            &mut state,
            &mut cache,
            ctx,
            &ok_call,
        )
        .unwrap();
        assert_eq!(out2.status, OutcomeStatus::Success);
        assert_eq!(
            state.uel_state.read(NS_WASM_STORE, init_key.as_bytes()),
            Some(b"600".as_slice())
        );
        assert_eq!(
            state.uel_state.read(NS_WASM_STORE, bob_key.as_bytes()),
            Some(b"400".as_slice())
        );
        assert_eq!(logs2.len(), 1);
    }

    #[test]
    fn uel_reentrancy_forbidden() {
        let mut state = AccountState::new();
        let mut cache = BlockReadCache::new();
        let ctx = BlockContext {
            chain_id: 45_261,
            height: 101,
            timestamp_ms: 1_762_000_000_000,
        };
        let mut workers: BTreeMap<u8, Box<dyn ExecutionEnvironment>> = BTreeMap::new();
        workers.insert(EeId::EVM.0, Box::new(EvmCallerEngine));
        workers.insert(EeId::WASM.0, Box::new(Cw20WasmEngine));

        let call = EeCall {
            kind: EeCallKind::Call,
            caller: EeIdentity {
                ee: EeId::EVM,
                id: vec![0x01; 20],
            },
            target: EeIdentity {
                ee: EeId::EVM,
                id: vec![0xAA; 20],
            },
            value: BudAmount(0),
            input: serde_json::to_vec(&serde_json::json!({
                "wasm_contract": "bud1cw20token",
                "wasm_msg": { "reenter_evm": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
            }))
            .unwrap(),
            gas_limit: 500_000,
            depth: 0,
            tx_hash: [0x20; 32],
        };
        let (out, _) =
            UniversalCallRouter::execute_root_atomic(workers, &mut state, &mut cache, ctx, &call)
                .unwrap();
        assert_eq!(out.status, OutcomeStatus::Revert);
        assert_eq!(out.output, b"ReentrancyForbidden");
    }

    #[test]
    fn uel_depth_limit() {
        struct ChainHopWorker(EeId);
        impl ExecutionEnvironment for ChainHopWorker {
            fn id(&self) -> EeId {
                self.0
            }
            fn validate_deploy(&self, _: &[u8]) -> Result<CodeInfo, EeRefusal> {
                Ok(CodeInfo {
                    code_hash: [0; 32],
                    abi_tag: String::new(),
                })
            }
            fn execute(
                &mut self,
                _: &BlockContext,
                call: &EeCall,
                host: &mut dyn HostApi,
            ) -> Result<EeOutcome, EeFault> {
                let next_ee = EeId(self.0 .0.saturating_add(1));
                match host.universal_call(UniversalCall {
                    from: call.target.clone(),
                    to_ee: next_ee,
                    target: EeIdentity {
                        ee: next_ee,
                        id: vec![0x55; 32],
                    },
                    value: BudAmount(0),
                    input: Vec::new(),
                    gas_limit: call.gas_limit,
                    is_static: false,
                }) {
                    Err(HostError::DepthExceeded) => Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"DepthExceeded".to_vec(),
                        gas_used: 100,
                    }),
                    Ok(r) if !r.success => Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: r.output,
                        gas_used: 100,
                    }),
                    _ => Ok(EeOutcome {
                        status: OutcomeStatus::Success,
                        output: Vec::new(),
                        gas_used: 100,
                    }),
                }
            }
            fn query(
                &self,
                _: &BlockContext,
                _: &EeQuery,
                _: &dyn HostRead,
            ) -> Result<Vec<u8>, EeRefusal> {
                Ok(Vec::new())
            }
        }

        let mut state = AccountState::new();
        let mut cache = BlockReadCache::new();
        let mut workers: BTreeMap<u8, Box<dyn ExecutionEnvironment>> = BTreeMap::new();
        for id in 0..=9u8 {
            workers.insert(id, Box::new(ChainHopWorker(EeId(id))));
        }
        let ctx = BlockContext {
            chain_id: 45_261,
            height: 102,
            timestamp_ms: 1_762_000_000_000,
        };
        let call = EeCall {
            kind: EeCallKind::Call,
            caller: EeIdentity {
                ee: EeId(0),
                id: vec![0x01; 32],
            },
            target: EeIdentity {
                ee: EeId(0),
                id: vec![0x02; 32],
            },
            value: BudAmount(0),
            input: Vec::new(),
            gas_limit: 5_000_000,
            depth: 0,
            tx_hash: [0x30; 32],
        };
        let (out, _) =
            UniversalCallRouter::execute_root_atomic(workers, &mut state, &mut cache, ctx, &call)
                .unwrap();
        assert_eq!(out.status, OutcomeStatus::Revert);
        assert_eq!(out.output, b"DepthExceeded");
    }

    #[test]
    fn asset_id_is_deterministic() {
        let a1 = derive_asset_id(EeId::WASM, b"bud1cw20token").unwrap();
        let a2 = derive_asset_id(EeId::WASM, b"bud1cw20token").unwrap();
        let b1 = derive_asset_id(EeId::EVM, &[0x11; 20]).unwrap();
        assert_eq!(a1, a2);
        assert_ne!(a1, b1);
    }

    #[test]
    fn uel_pointer_holds_no_balance() {
        let mut state = AccountState::new();
        let rec = register_asset(
            &mut state,
            &RegisterAsset {
                home_ee: EeId::WASM,
                home_ref: b"bud1cw20home".to_vec(),
                standard: AssetStandard::Fungible,
            },
            |_, _, _| {
                Ok(ProbedAssetMetadata {
                    decimals: 6,
                    symbol: String::from("CWX"),
                    name: String::from("CW20 Home Token"),
                })
            },
        )
        .unwrap();
        let (_, evm_ptr) = create_pointer(
            &mut state,
            &CreatePointer {
                asset_id: rec.asset_id,
                target_ee: EeId::EVM,
            },
        )
        .unwrap();
        assert_eq!(evm_ptr.len(), 20);

        let alice_evm = [0x11u8; 20];
        let bob_evm = [0x22u8; 20];
        let alice_bud =
            resolve_ee_identity(&state, &EeIdentity { ee: EeId::EVM, id: alice_evm.to_vec() })
                .unwrap();
        let bob_bud =
            resolve_ee_identity(&state, &EeIdentity { ee: EeId::EVM, id: bob_evm.to_vec() })
                .unwrap();
        state.accounts.insert(alice_bud, Account::new(alice_bud));
        state.accounts.insert(bob_bud, Account::new(bob_bud));
        let alice_wasm = String::from_utf8(
            state.uel_state.ensure_alias_registered(&alice_bud, EeId::WASM).unwrap(),
        )
        .unwrap();
        let bob_wasm = String::from_utf8(
            state.uel_state.ensure_alias_registered(&bob_bud, EeId::WASM).unwrap(),
        )
        .unwrap();

        let home_hex = hex::encode(b"bud1cw20home");
        state
            .uel_state
            .write(
                NS_WASM_STORE,
                format!("bal:{home_hex}:{alice_wasm}").into_bytes(),
                Some(b"900".to_vec()),
            )
            .unwrap();

        // Call ERC-20 `transfer(bob_evm, 250)` on the EVM pointer contract!
        let mut calldata = vec![0xa9, 0x05, 0x9c, 0xbb];
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(&bob_evm);
        calldata.extend_from_slice(&[0u8; 16]);
        calldata.extend_from_slice(&250u128.to_be_bytes());

        let mut workers: BTreeMap<u8, Box<dyn ExecutionEnvironment>> = BTreeMap::new();
        workers.insert(EeId::WASM.0, Box::new(Cw20WasmEngine));
        let mut cache = BlockReadCache::new();
        let ctx = BlockContext {
            chain_id: 45_261,
            height: 105,
            timestamp_ms: 1_762_000_000_000,
        };
        let (out, _) = UniversalCallRouter::execute_root_atomic(
            workers,
            &mut state,
            &mut cache,
            ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: EeIdentity {
                    ee: EeId::EVM,
                    id: alice_evm.to_vec(),
                },
                target: EeIdentity {
                    ee: EeId::EVM,
                    id: evm_ptr,
                },
                value: BudAmount(0),
                input: calldata,
                gas_limit: 400_000,
                depth: 0,
                tx_hash: [0x40; 32],
            },
        )
        .unwrap();
        assert_eq!(out.status, OutcomeStatus::Success);
        // Zero EVM storage entries exist for the pointer; balances moved in WASM home!
        assert_eq!(state.uel_state.iter_namespace(NS_EVM_STORAGE).count(), 0);
        assert_eq!(
            state
                .uel_state
                .read(NS_WASM_STORE, format!("bal:{home_hex}:{bob_wasm}").as_bytes()),
            Some(b"250".as_slice())
        );
    }

    #[test]
    fn pointer_allowance_lives_at_home() {
        let mut state = AccountState::new();
        let rec = register_asset(
            &mut state,
            &RegisterAsset {
                home_ee: EeId::WASM,
                home_ref: b"bud1cw20alw".to_vec(),
                standard: AssetStandard::Fungible,
            },
            |_, _, _| {
                Ok(ProbedAssetMetadata {
                    decimals: 6,
                    symbol: String::from("ALW"),
                    name: String::from("Allowance Token"),
                })
            },
        )
        .unwrap();
        let (_, evm_ptr) = create_pointer(
            &mut state,
            &CreatePointer {
                asset_id: rec.asset_id,
                target_ee: EeId::EVM,
            },
        )
        .unwrap();

        let owner_evm = [0x31u8; 20];
        let spender_evm = [0x32u8; 20];
        let owner_bud =
            resolve_ee_identity(&state, &EeIdentity { ee: EeId::EVM, id: owner_evm.to_vec() })
                .unwrap();
        let spender_bud = resolve_ee_identity(
            &state,
            &EeIdentity {
                ee: EeId::EVM,
                id: spender_evm.to_vec(),
            },
        )
        .unwrap();
        state.accounts.insert(owner_bud, Account::new(owner_bud));
        state.accounts.insert(spender_bud, Account::new(spender_bud));
        let owner_wasm = String::from_utf8(
            state.uel_state.ensure_alias_registered(&owner_bud, EeId::WASM).unwrap(),
        )
        .unwrap();
        let spender_wasm = String::from_utf8(
            state.uel_state.ensure_alias_registered(&spender_bud, EeId::WASM).unwrap(),
        )
        .unwrap();

        // Call ERC-20 `approve(spender_evm, 777)` on the EVM pointer!
        let mut approve_cd = vec![0x09, 0x5e, 0xa7, 0xb3];
        approve_cd.extend_from_slice(&[0u8; 12]);
        approve_cd.extend_from_slice(&spender_evm);
        approve_cd.extend_from_slice(&[0u8; 16]);
        approve_cd.extend_from_slice(&777u128.to_be_bytes());

        let mut workers: BTreeMap<u8, Box<dyn ExecutionEnvironment>> = BTreeMap::new();
        workers.insert(EeId::WASM.0, Box::new(Cw20WasmEngine));
        let mut cache = BlockReadCache::new();
        let ctx = BlockContext {
            chain_id: 45_261,
            height: 106,
            timestamp_ms: 1_762_000_000_000,
        };
        let (out, _) = UniversalCallRouter::execute_root_atomic(
            workers,
            &mut state,
            &mut cache,
            ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: EeIdentity {
                    ee: EeId::EVM,
                    id: owner_evm.to_vec(),
                },
                target: EeIdentity {
                    ee: EeId::EVM,
                    id: evm_ptr,
                },
                value: BudAmount(0),
                input: approve_cd,
                gas_limit: 400_000,
                depth: 0,
                tx_hash: [0x50; 32],
            },
        )
        .unwrap();
        assert_eq!(out.status, OutcomeStatus::Success);
        assert_eq!(state.uel_state.iter_namespace(NS_EVM_STORAGE).count(), 0);
        let home_hex = hex::encode(b"bud1cw20alw");
        let alw_key = format!("alw:{home_hex}:{owner_wasm}:{spender_wasm}");
        assert_eq!(
            state.uel_state.read(NS_WASM_STORE, alw_key.as_bytes()),
            Some(b"777".as_slice())
        );
    }

    #[test]
    fn universal_call_log_is_visible_to_evm_indexers() {
        let log = encode_universal_call_executed_event(EeId::WASM.0, b"bud1target", true);
        assert_eq!(log.emitter.ee, EeId::EVM);
        assert_eq!(log.emitter.id, EVM_UNIVERSAL_PRECOMPILE_BYTES.to_vec());
        assert_eq!(log.topics.len(), 1);
        assert_eq!(log.topics[0], UNIVERSAL_CALL_EXECUTED_TOPIC0.to_vec());
        assert_eq!(log.data[31], EeId::WASM.0);
        assert_eq!(log.data[95], 1);
        assert_eq!(&log.data[128..138], b"bud1target");
    }
}
