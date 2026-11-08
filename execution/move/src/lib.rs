//! Standalone Move (Aptos) out-of-process Execution Environment worker
//! (`EeId::MOVE = 0x04`,  Aptos leg).
//!
//! Enforces:
//! - Block-STM disabled (`BLOCK_STM_ENABLED = false`): strictly sequential execution
//!   within the out-of-process worker (`IP-32` item 1).
//! - Reserved `0xBD` local-alias authentication-key scheme byte verified unused in the
//!   pinned `aptos-core` commit (`move_alias_scheme_byte_is_unused`, Section 8.4.2 rule 2).
//! - `0x1` staking and governance modules disabled; `0x1::randomness` bound to Budlum
//!   `BlockContext` (`IP-32` item 3, Section 8.15).
//! - Native module `0x1::budlum_universal::call` bridging `octa` (`10^10` attoBUD) value
//!   transfers and `BGU` budgets into UEL `HostApi::universal_call` (`IP-32` item 6).

#![forbid(unsafe_code)]

pub mod framework;
pub mod pointer;

use std::any::Any;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use budlum_uel_abi::transport::panic_digest;
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostError, HostRead, Namespace,
    OutcomeStatus, RefusalCode, UniversalCall,
};

use crate::framework::{
    bcs_encode_bool_and_bytes, derive_move_randomness, is_disabled_framework_module,
    verify_move_module_bytes, CompiledMoveModule, MoveOp, FRAMEWORK_ADDRESS,
};

/// Canonical UEL namespace for Move modules and account resources (Section 8.10).
pub const NS_MOVE_STATE: &str = "ee/move/state";

/// `Block-STM` parallel scheduler flag -- permanently `false` on Budlum (`IP-32` item 1).
pub const BLOCK_STM_ENABLED: bool = false;

/// Conversion factor from 1 Aptos internal gas unit to BGU (`Section 8.9`).
pub const APTOS_GAS_TO_BGU: u64 = 100;

/// Environment soft gas cap in BGU (`Section 8.9`: `24,000,000` BGU).
pub const MOVE_SOFT_GAS_LIMIT_BGU: u64 = 24_000_000;

/// AttoBUD per Move `octa` (`10^-8` BUD = `10^10` attoBUD).
pub const ATTO_PER_OCTA: u128 = 10_000_000_000;

/// Maximum published Move module size (`256 KiB`).
pub const MAX_MOVE_MODULE_BYTES: usize = 256 * 1024;

const KEY_TAG_MODULE: u8 = 0x01;
const KEY_TAG_RESOURCE: u8 = 0x02;

/// Transactions accepted by `budlum-ee-move` via [`EeCall::input`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MovePayload {
    /// Publish one or more Move modules under the signer's 32-byte Move address
    /// (`aptos move publish` / `0x1::code::publish_package_txn`).
    PublishPackage {
        metadata_serialized: Vec<u8>,
        modules: Vec<Vec<u8>>,
    },
    /// Execute a Move entry function (`aptos move run`).
    EntryFunction {
        module_address: [u8; 32],
        module_name: String,
        function_name: String,
        ty_args: Vec<String>,
        args: Vec<Vec<u8>>,
    },
    /// Execute an inline Move script (`Vec<MoveOp>`).
    Script {
        ops: Vec<MoveOp>,
        args: Vec<Vec<u8>>,
    },
}

/// Read-only queries accepted by `budlum-ee-move` via [`EeQuery::input`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveQuery {
    /// Read a raw Move resource under `(account, resource_tag)`.
    Resource {
        account: [u8; 32],
        resource_tag: String,
    },
    /// Read a published Move module bytecode blob under `(account, module_name)`.
    Module {
        account: [u8; 32],
        module_name: String,
    },
    /// Execute a `@[view]` function without mutating Move state (`/v1/view`).
    View {
        module_address: [u8; 32],
        module_name: String,
        function_name: String,
        ty_args: Vec<String>,
        args: Vec<Vec<u8>>,
    },
}

/// Out-of-process sequential Move execution worker (`EeId::MOVE`).
#[derive(Debug, Default)]
pub struct MoveWorker;

impl MoveWorker {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[derive(Default)]
struct MoveJournal {
    original_keys: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl MoveJournal {
    fn write(
        &mut self,
        host: &mut dyn HostApi,
        ns: &Namespace,
        key: &[u8],
        val: &[u8],
    ) -> Result<(), HostError> {
        if !self.original_keys.contains_key(key) {
            let prev = host.read(ns, key)?;
            self.original_keys.insert(key.to_vec(), prev);
        }
        host.write(ns, key, Some(val))
    }

    fn rollback(&self, host: &mut dyn HostApi, ns: &Namespace) {
        for (key, orig) in &self.original_keys {
            let _ = host.write(ns, key, orig.as_deref());
        }
    }
}

enum StepErr {
    OutOfGas,
    Revert(String),
}

fn module_state_key(address: &[u8; 32], module_name: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32 + module_name.len());
    k.push(KEY_TAG_MODULE);
    k.extend_from_slice(address);
    k.extend_from_slice(module_name.as_bytes());
    k
}

fn resource_state_key(address: &[u8; 32], resource_tag: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32 + resource_tag.len());
    k.push(KEY_TAG_RESOURCE);
    k.extend_from_slice(address);
    k.extend_from_slice(resource_tag.as_bytes());
    k
}

fn caller_address32(caller: &EeIdentity) -> Result<[u8; 32], String> {
    caller
        .id
        .as_slice()
        .try_into()
        .map_err(|_| "Move signer identity must be 32 bytes".to_string())
}

fn move_identity(address: [u8; 32]) -> EeIdentity {
    EeIdentity {
        ee: EeId::MOVE,
        id: address.to_vec(),
    }
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        String::from("unknown Move worker panic")
    }
}

fn decode_u64_le(bytes: &[u8], label: &str) -> Result<u64, String> {
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| format!("{label} expects 8-byte little-endian u64"))?;
    Ok(u64::from_le_bytes(arr))
}

fn decode_addr32(bytes: &[u8], label: &str) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{label} expects 32-byte Move address"))
}

fn decode_bcs_bytes(bytes: &[u8], label: &str) -> Result<Vec<u8>, String> {
    let mut idx = 0usize;
    let mut len = 0usize;
    let mut shift = 0u32;
    loop {
        let Some(&b) = bytes.get(idx) else {
            return Err(format!("{label}: truncated BCS length"));
        };
        idx += 1;
        len |= usize::from(b & 0x7F) << shift;
        if (b & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift > 28 {
            return Err(format!("{label}: BCS ULEB128 overflow"));
        }
    }
    let Some(slice) = bytes.get(idx..idx.saturating_add(len)) else {
        return Err(format!("{label}: truncated BCS vector payload"));
    };
    if idx + len != bytes.len() {
        return Err(format!("{label}: trailing bytes after BCS vector"));
    }
    Ok(slice.to_vec())
}

fn charge_bgu(
    host: &mut dyn HostApi,
    gas_used: &mut u64,
    delta: u64,
    cap: u64,
) -> Result<(), StepErr> {
    let next = gas_used.saturating_add(delta);
    if next > cap {
        return Err(StepErr::OutOfGas);
    }
    host.charge(delta).map_err(|_| StepErr::OutOfGas)?;
    *gas_used = next;
    Ok(())
}

fn map_host_err(err: HostError) -> StepErr {
    match err {
        HostError::OutOfGas => StepErr::OutOfGas,
        other => StepErr::Revert(other.to_string()),
    }
}

impl MoveWorker {
    #[allow(clippy::too_many_arguments)]
    fn execute_framework_entry(
        &self,
        signer: [u8; 32],
        module_name: &str,
        function_name: &str,
        args: &[Vec<u8>],
        ctx: &BlockContext,
        ns: &Namespace,
        journal: &mut MoveJournal,
        logs: &mut Vec<EeLog>,
        gas_used: &mut u64,
        cap: u64,
        host: &mut dyn HostApi,
    ) -> Result<Option<Vec<u8>>, StepErr> {
        if is_disabled_framework_module(&FRAMEWORK_ADDRESS, module_name) {
            return Err(StepErr::Revert(format!(
                "Aptos module 0x1::{module_name} is disabled on Budlum (Section 8.15)"
            )));
        }
        match (module_name, function_name) {
            ("aptos_account", "transfer")
            | ("aptos_account", "transfer_coins")
            | ("coin", "transfer") => {
                charge_bgu(host, gas_used, 5 * APTOS_GAS_TO_BGU, cap)?;
                let recipient = args
                    .first()
                    .ok_or_else(|| StepErr::Revert("missing recipient argument".to_string()))
                    .and_then(|b| decode_addr32(b, "recipient").map_err(StepErr::Revert))?;
                let octas = args
                    .get(1)
                    .ok_or_else(|| StepErr::Revert("missing octas amount argument".to_string()))
                    .and_then(|b| decode_u64_le(b, "octas").map_err(StepErr::Revert))?;
                if octas > 0 {
                    let attos = u128::from(octas).saturating_mul(ATTO_PER_OCTA);
                    host.bud_transfer(&move_identity(signer), &move_identity(recipient), attos)
                        .map_err(map_host_err)?;
                }
                logs.push(EeLog {
                    emitter: move_identity(FRAMEWORK_ADDRESS),
                    topics: vec![b"0x1::coin::TransferEvent".to_vec(), recipient.to_vec()],
                    data: octas.to_le_bytes().to_vec(),
                });
                Ok(Some(Vec::new()))
            }
            ("code", "publish_package_txn") => {
                let raw_mod = args.get(1).ok_or_else(|| {
                    StepErr::Revert("publish_package_txn missing module bytes".to_string())
                })?;
                self.publish_single_module(
                    signer,
                    raw_mod,
                    ns,
                    journal,
                    logs,
                    gas_used,
                    cap,
                    host,
                )?;
                Ok(Some(Vec::new()))
            }
            ("randomness", "bytes_32") | ("randomness", "u64_integer") => {
                charge_bgu(host, gas_used, 2 * APTOS_GAS_TO_BGU, cap)?;
                let seed = derive_move_randomness(ctx, &signer, *gas_used);
                if function_name == "u64_integer" {
                    Ok(Some(seed.get(0..8).unwrap_or_default().to_vec()))
                } else {
                    Ok(Some(seed.to_vec()))
                }
            }
            ("budlum_universal", "call") => {
                // Signature (Section 8.7.2 Move):
                // call(caller: &signer, ee: u8, target: vector<u8>, input: vector<u8>,
                //      value_octas: u64, gas_bgu: u64): (bool, vector<u8>)
                charge_bgu(host, gas_used, 8 * APTOS_GAS_TO_BGU, cap)?;
                let to_ee = EeId(
                    args.first()
                        .and_then(|b| b.first().copied())
                        .ok_or_else(|| {
                            StepErr::Revert("budlum_universal::call missing ee u8".to_string())
                        })?,
                );
                let target_bytes = args
                    .get(1)
                    .ok_or_else(|| {
                        StepErr::Revert("budlum_universal::call missing target".to_string())
                    })
                    .and_then(|b| decode_bcs_bytes(b, "target").or_else(|_| Ok(b.clone())))?;
                let target = EeIdentity::new(to_ee, target_bytes)
                    .map_err(|e| StepErr::Revert(e.to_string()))?;
                let input = args
                    .get(2)
                    .ok_or_else(|| {
                        StepErr::Revert("budlum_universal::call missing input".to_string())
                    })
                    .and_then(|b| decode_bcs_bytes(b, "input").or_else(|_| Ok(b.clone())))?;
                let value_octas = args
                    .get(3)
                    .ok_or_else(|| {
                        StepErr::Revert("budlum_universal::call missing value_octas".to_string())
                    })
                    .and_then(|b| decode_u64_le(b, "value_octas").map_err(StepErr::Revert))?;
                let call_gas_bgu = args
                    .get(4)
                    .ok_or_else(|| {
                        StepErr::Revert("budlum_universal::call missing gas_bgu".to_string())
                    })
                    .and_then(|b| decode_u64_le(b, "gas_bgu").map_err(StepErr::Revert))?;
                let value_attos = u128::from(value_octas).saturating_mul(ATTO_PER_OCTA);
                let resp = host
                    .universal_call(UniversalCall {
                        from: move_identity(signer),
                        to_ee,
                        target,
                        value: BudAmount(value_attos),
                        input,
                        gas_limit: call_gas_bgu,
                        is_static: false,
                    })
                    .map_err(map_host_err)?;
                *gas_used = gas_used.saturating_add(resp.gas_used);
                if *gas_used > cap {
                    return Err(StepErr::OutOfGas);
                }
                Ok(Some(bcs_encode_bool_and_bytes(resp.success, &resp.output)))
            }
            _ => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_single_module(
        &self,
        signer: [u8; 32],
        raw_mod: &[u8],
        ns: &Namespace,
        journal: &mut MoveJournal,
        logs: &mut Vec<EeLog>,
        gas_used: &mut u64,
        cap: u64,
        host: &mut dyn HostApi,
    ) -> Result<CompiledMoveModule, StepErr> {
        if raw_mod.len() > MAX_MOVE_MODULE_BYTES {
            return Err(StepErr::Revert(format!(
                "Move module length {} exceeds cap {MAX_MOVE_MODULE_BYTES}",
                raw_mod.len()
            )));
        }
        let publish_cost = (raw_mod.len() as u64).saturating_mul(10).saturating_add(500);
        charge_bgu(host, gas_used, publish_cost, cap)?;
        let verified = verify_move_module_bytes(raw_mod, Some(&signer)).map_err(StepErr::Revert)?;
        let key = module_state_key(&signer, &verified.name);
        journal
            .write(host, ns, &key, raw_mod)
            .map_err(map_host_err)?;
        logs.push(EeLog {
            emitter: move_identity(signer),
            topics: vec![
                b"0x1::code::PublishModule".to_vec(),
                verified.name.as_bytes().to_vec(),
            ],
            data: Sha256::digest(raw_mod).to_vec(),
        });
        Ok(verified)
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_ops(
        &self,
        signer: [u8; 32],
        ops: &[MoveOp],
        args: &[Vec<u8>],
        ns: &Namespace,
        journal: &mut MoveJournal,
        logs: &mut Vec<EeLog>,
        gas_used: &mut u64,
        cap: u64,
        host: &mut dyn HostApi,
    ) -> Result<Vec<u8>, StepErr> {
        let mut last_ret = Vec::new();
        for op in ops {
            charge_bgu(host, gas_used, APTOS_GAS_TO_BGU, cap)?;
            match op {
                MoveOp::WriteResource {
                    resource_tag,
                    value,
                } => {
                    let key = resource_state_key(&signer, resource_tag);
                    journal.write(host, ns, &key, value).map_err(map_host_err)?;
                }
                MoveOp::WriteResourceFromArg {
                    resource_tag,
                    arg_index,
                } => {
                    let val = args.get(*arg_index).ok_or_else(|| {
                        StepErr::Revert(format!("missing Move argument at index {arg_index}"))
                    })?;
                    let key = resource_state_key(&signer, resource_tag);
                    journal.write(host, ns, &key, val).map_err(map_host_err)?;
                }
                MoveOp::ReadResource {
                    owner,
                    resource_tag,
                } => {
                    let target_owner = owner.unwrap_or(signer);
                    let key = resource_state_key(&target_owner, resource_tag);
                    last_ret = host
                        .read(ns, &key)
                        .map_err(map_host_err)?
                        .unwrap_or_default();
                }
                MoveOp::TransferOctas { recipient, octas } => {
                    if *octas > 0 {
                        let attos = u128::from(*octas).saturating_mul(ATTO_PER_OCTA);
                        host.bud_transfer(
                            &move_identity(signer),
                            &move_identity(*recipient),
                            attos,
                        )
                        .map_err(map_host_err)?;
                    }
                }
                MoveOp::UniversalCall {
                    target_ee,
                    target,
                    input,
                    value_octas,
                    gas_bgu,
                } => {
                    let to_ee = EeId(*target_ee);
                    let target_id = EeIdentity::new(to_ee, target.clone())
                        .map_err(|e| StepErr::Revert(e.to_string()))?;
                    let value_attos = u128::from(*value_octas).saturating_mul(ATTO_PER_OCTA);
                    let resp = host
                        .universal_call(UniversalCall {
                            from: move_identity(signer),
                            to_ee,
                            target: target_id,
                            value: BudAmount(value_attos),
                            input: input.clone(),
                            gas_limit: *gas_bgu,
                            is_static: false,
                        })
                        .map_err(map_host_err)?;
                    *gas_used = gas_used.saturating_add(resp.gas_used);
                    if *gas_used > cap {
                        return Err(StepErr::OutOfGas);
                    }
                    last_ret = bcs_encode_bool_and_bytes(resp.success, &resp.output);
                }
                MoveOp::EmitEvent {
                    event_type,
                    payload,
                } => {
                    logs.push(EeLog {
                        emitter: move_identity(signer),
                        topics: vec![event_type.as_bytes().to_vec()],
                        data: payload.clone(),
                    });
                }
                MoveOp::Abort { code } => {
                    return Err(StepErr::Revert(format!("Move abort code {code}")));
                }
                MoveOp::ReturnConst { bytes } => {
                    last_ret.clone_from(bytes);
                }
            }
        }
        Ok(last_ret)
    }

    fn execute_inner(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> EeOutcome {
        debug_assert!(!BLOCK_STM_ENABLED, "Block-STM must remain disabled on Budlum");
        let cap = call.gas_limit.min(MOVE_SOFT_GAS_LIMIT_BGU);
        let Ok(ns) = Namespace::new(NS_MOVE_STATE) else {
            return EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"invalid Move namespace".to_vec(),
                gas_used: 0,
            };
        };
        let signer = match caller_address32(&call.caller) {
            Ok(s) => s,
            Err(msg) => {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: msg.into_bytes(),
                    gas_used: 0,
                };
            }
        };

        let mut journal = MoveJournal::default();
        let mut logs = Vec::new();
        let mut gas_used = 0u64;

        if call.kind == EeCallKind::Deploy {
            return match self.publish_single_module(
                signer,
                &call.input,
                &ns,
                &mut journal,
                &mut logs,
                &mut gas_used,
                cap,
                host,
            ) {
                Ok(verified) => {
                    for log in logs {
                        let _ = host.emit_log(log);
                    }
                    EeOutcome {
                        status: OutcomeStatus::Success,
                        output: verified.address.to_vec(),
                        gas_used,
                    }
                }
                Err(StepErr::OutOfGas) => {
                    journal.rollback(host, &ns);
                    EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: cap,
                    }
                }
                Err(StepErr::Revert(msg)) => {
                    journal.rollback(host, &ns);
                    EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: msg.into_bytes(),
                        gas_used,
                    }
                }
            };
        }

        let payload: MovePayload = match serde_json::from_slice(&call.input) {
            Ok(p) => p,
            Err(e) => {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: format!("invalid MovePayload: {e}").into_bytes(),
                    gas_used: 0,
                };
            }
        };

        // Transfer any attached call value in octas/attoBUD before running entry logic.
        if call.value.0 > 0 {
            if let Err(err) = host.bud_transfer(&call.caller, &call.target, call.value.0) {
                return match map_host_err(err) {
                    StepErr::OutOfGas => EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: cap,
                    },
                    StepErr::Revert(msg) => EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: msg.into_bytes(),
                        gas_used: 0,
                    },
                };
            }
        }

        let res = match &payload {
            MovePayload::PublishPackage { modules, .. } => {
                if modules.is_empty() {
                    Err(StepErr::Revert(
                        "PublishPackage must include at least one module".to_string(),
                    ))
                } else {
                    let mut out = Ok(Vec::new());
                    for raw_mod in modules {
                        if let Err(e) = self.publish_single_module(
                            signer,
                            raw_mod,
                            &ns,
                            &mut journal,
                            &mut logs,
                            &mut gas_used,
                            cap,
                            host,
                        ) {
                            out = Err(e);
                            break;
                        }
                    }
                    out
                }
            }
            MovePayload::EntryFunction {
                module_address,
                module_name,
                function_name,
                args,
                ..
            } => {
                if *module_address == FRAMEWORK_ADDRESS {
                    match self.execute_framework_entry(
                        signer,
                        module_name,
                        function_name,
                        args,
                        ctx,
                        &ns,
                        &mut journal,
                        &mut logs,
                        &mut gas_used,
                        cap,
                        host,
                    ) {
                        Ok(Some(bytes)) => Ok(bytes),
                        Ok(None) => Err(StepErr::Revert(format!(
                            "unknown framework function 0x1::{module_name}::{function_name}"
                        ))),
                        Err(e) => Err(e),
                    }
                } else {
                    let key = module_state_key(module_address, module_name);
                    match host.read(&ns, &key) {
                        Ok(Some(bytes)) => {
                            match verify_move_module_bytes(&bytes, Some(module_address)) {
                                Ok(compiled) => {
                                    if let Some(func) = compiled
                                        .functions
                                        .iter()
                                        .find(|f| f.name == *function_name && f.is_entry)
                                    {
                                        self.execute_ops(
                                            signer,
                                            &func.code,
                                            args,
                                            &ns,
                                            &mut journal,
                                            &mut logs,
                                            &mut gas_used,
                                            cap,
                                            host,
                                        )
                                    } else {
                                        let m = format!(
                                            "entry function {module_name}::{function_name} missing"
                                        );
                                        Err(StepErr::Revert(m))
                                    }
                                }
                                Err(msg) => Err(StepErr::Revert(msg)),
                            }
                        }
                        Ok(None) => Err(StepErr::Revert(format!(
                            "Move module {module_name} not found"
                        ))),
                        Err(err) => Err(map_host_err(err)),
                    }
                }
            }
            MovePayload::Script { ops, args } => self.execute_ops(
                signer,
                ops,
                args,
                &ns,
                &mut journal,
                &mut logs,
                &mut gas_used,
                cap,
                host,
            ),
        };

        match res {
            Ok(output) => {
                for log in logs {
                    if host.emit_log(log).is_err() {
                        journal.rollback(host, &ns);
                        return EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"emit_log refused".to_vec(),
                            gas_used,
                        };
                    }
                }
                EeOutcome {
                    status: OutcomeStatus::Success,
                    output,
                    gas_used,
                }
            }
            Err(StepErr::OutOfGas) => {
                journal.rollback(host, &ns);
                EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: cap,
                }
            }
            Err(StepErr::Revert(reason)) => {
                journal.rollback(host, &ns);
                EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: reason.into_bytes(),
                    gas_used,
                }
            }
        }
    }
}

impl ExecutionEnvironment for MoveWorker {
    fn id(&self) -> EeId {
        EeId::MOVE
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        if code.is_empty() {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: "Move module bytecode cannot be empty".to_string(),
            });
        }
        if code.len() > MAX_MOVE_MODULE_BYTES {
            return Err(EeRefusal {
                code: RefusalCode::TooLarge,
                message: format!(
                    "Move module length {} exceeds cap {MAX_MOVE_MODULE_BYTES}",
                    code.len()
                ),
            });
        }
        verify_move_module_bytes(code, None).map_err(|message| EeRefusal {
            code: RefusalCode::InvalidCode,
            message,
        })?;
        Ok(CodeInfo {
            code_hash: Sha256::digest(code).into(),
            abi_tag: "aptos-move-v7".to_string(),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        catch_unwind(AssertUnwindSafe(|| self.execute_inner(ctx, call, host))).map_err(|payload| {
            let msg = panic_message(payload);
            EeFault {
                ee: EeId::MOVE,
                panic_digest: panic_digest(EeId::MOVE, &msg),
            }
        })
    }

    fn query(
        &self,
        ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let ns = Namespace::new(NS_MOVE_STATE).map_err(|e| EeRefusal {
            code: RefusalCode::Denied,
            message: e.to_string(),
        })?;
        let parsed: MoveQuery = serde_json::from_slice(&q.input).map_err(|e| EeRefusal {
            code: RefusalCode::Unsupported,
            message: format!("invalid MoveQuery: {e}"),
        })?;
        match parsed {
            MoveQuery::Resource {
                account,
                resource_tag,
            } => {
                let key = resource_state_key(&account, &resource_tag);
                let data = host
                    .read(&ns, &key)
                    .map_err(|e| EeRefusal {
                        code: RefusalCode::Denied,
                        message: e.to_string(),
                    })?
                    .unwrap_or_default();
                Ok(data)
            }
            MoveQuery::Module {
                account,
                module_name,
            } => {
                let key = module_state_key(&account, &module_name);
                let data = host
                    .read(&ns, &key)
                    .map_err(|e| EeRefusal {
                        code: RefusalCode::Denied,
                        message: e.to_string(),
                    })?
                    .unwrap_or_default();
                Ok(data)
            }
            MoveQuery::View {
                module_address,
                module_name,
                function_name,
                ..
            } => {
                if module_address == FRAMEWORK_ADDRESS && module_name == "randomness" {
                    return Ok(derive_move_randomness(ctx, &[0u8; 32], 0).to_vec());
                }
                if is_disabled_framework_module(&module_address, &module_name) {
                    return Err(EeRefusal {
                        code: RefusalCode::Denied,
                        message: format!("0x1::{module_name} is disabled on Budlum"),
                    });
                }
                let key = module_state_key(&module_address, &module_name);
                let bytes = host
                    .read(&ns, &key)
                    .map_err(|e| EeRefusal {
                        code: RefusalCode::Denied,
                        message: e.to_string(),
                    })?
                    .ok_or_else(|| EeRefusal {
                        code: RefusalCode::Unsupported,
                        message: format!("Move module {module_name} not found"),
                    })?;
                let compiled =
                    verify_move_module_bytes(&bytes, Some(&module_address)).map_err(|message| {
                        EeRefusal {
                            code: RefusalCode::InvalidCode,
                            message,
                        }
                    })?;
                let func = compiled
                    .functions
                    .iter()
                    .find(|f| f.name == function_name && f.is_view)
                    .ok_or_else(|| EeRefusal {
                        code: RefusalCode::Unsupported,
                        message: format!("view function {module_name}::{function_name} not found"),
                    })?;
                let mut out = Vec::new();
                for op in &func.code {
                    match op {
                        MoveOp::ReadResource {
                            owner,
                            resource_tag,
                        } => {
                            let target_owner = owner.unwrap_or(module_address);
                            let rkey = resource_state_key(&target_owner, resource_tag);
                            out = host
                                .read(&ns, &rkey)
                                .map_err(|e| EeRefusal {
                                    code: RefusalCode::Denied,
                                    message: e.to_string(),
                                })?
                                .unwrap_or_default();
                        }
                        MoveOp::ReturnConst { bytes } => out.clone_from(bytes),
                        _ => {
                            return Err(EeRefusal {
                                code: RefusalCode::Denied,
                                message: "mutating MoveOp forbidden in #[view] query".to_string(),
                            });
                        }
                    }
                }
                Ok(out)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::{
        derive_move_alias, encode_move_module, is_scheme_byte_unused_in_pinned_aptos,
        MoveFunctionDef, APTOS_PINNED_COMMIT, APTOS_USED_SCHEME_BYTES,
        BUDLUM_MOVE_ALIAS_SCHEME_BYTE,
    };
    use budlum_uel_abi::mock::MemoryHost;
    use budlum_uel_abi::transport::{serve_connection, EeClient};
    use budlum_uel_abi::UniversalResult;
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    fn sample_ctx() -> BlockContext {
        BlockContext {
            chain_id: 45_261,
            height: 77,
            timestamp_ms: 1_793_923_200_000,
        }
    }

    fn make_call(caller: [u8; 32], target: [u8; 32], input: Vec<u8>) -> EeCall {
        EeCall {
            kind: EeCallKind::Call,
            caller: move_identity(caller),
            target: move_identity(target),
            value: BudAmount(0),
            input,
            gas_limit: 2_000_000,
            depth: 0,
            tx_hash: [0xAB; 32],
        }
    }

    /// Directive IP-32 gate: `move_alias_scheme_byte_is_unused` (Section 8.4.2 rule 2).
    #[test]
    fn move_alias_scheme_byte_is_unused() {
        assert_eq!(BUDLUM_MOVE_ALIAS_SCHEME_BYTE, 0xBD);
        assert_eq!(APTOS_PINNED_COMMIT.len(), 40);
        assert!(is_scheme_byte_unused_in_pinned_aptos(BUDLUM_MOVE_ALIAS_SCHEME_BYTE));
        for &used in APTOS_USED_SCHEME_BYTES {
            assert_ne!(used, 0xBD);
            assert!(!is_scheme_byte_unused_in_pinned_aptos(used));
        }

        let local = [0x42u8; 32];
        let alias = derive_move_alias(&local);
        let mut ed_hasher = sha3::Sha3_256::new();
        sha3::Digest::update(&mut ed_hasher, local);
        sha3::Digest::update(&mut ed_hasher, [0x00u8]);
        let ed_auth: [u8; 32] = sha3::Digest::finalize(ed_hasher).into();
        assert_ne!(alias, ed_auth);
    }

    #[test]
    fn block_stm_is_disabled_and_execution_is_sequential() {
        assert!(!BLOCK_STM_ENABLED);
    }

    #[test]
    fn staking_and_governance_modules_are_disabled() {
        let mut worker = MoveWorker::new();
        let mut host = MemoryHost::new(2_000_000);
        let ctx = sample_ctx();
        for module_name in ["stake", "staking_contract", "aptos_governance", "voting"] {
            let payload = MovePayload::EntryFunction {
                module_address: FRAMEWORK_ADDRESS,
                module_name: module_name.to_string(),
                function_name: "initialize".to_string(),
                ty_args: Vec::new(),
                args: Vec::new(),
            };
            let Ok(input) = serde_json::to_vec(&payload) else {
                panic!("serialize payload");
            };
            let call = make_call([0x11u8; 32], FRAMEWORK_ADDRESS, input);
            let Ok(res) = worker.execute(&ctx, &call, &mut host) else {
                panic!("execute should return revert outcome");
            };
            assert_eq!(res.status, OutcomeStatus::Revert);
            assert!(String::from_utf8_lossy(&res.output).contains("disabled"));
        }
    }

    #[test]
    fn randomness_binds_to_budlum_block_context() {
        let mut worker = MoveWorker::new();
        let mut host = MemoryHost::new(2_000_000);
        let payload = MovePayload::EntryFunction {
            module_address: FRAMEWORK_ADDRESS,
            module_name: "randomness".to_string(),
            function_name: "bytes_32".to_string(),
            ty_args: Vec::new(),
            args: Vec::new(),
        };
        let Ok(input) = serde_json::to_vec(&payload) else {
            panic!("serialize");
        };
        let ctx_a = sample_ctx();
        let mut ctx_b = sample_ctx();
        ctx_b.height += 1;

        let call = make_call([0x22u8; 32], FRAMEWORK_ADDRESS, input);
        let Ok(res_a) = worker.execute(&ctx_a, &call, &mut host) else {
            panic!("exec a");
        };
        let Ok(res_b) = worker.execute(&ctx_b, &call, &mut host) else {
            panic!("exec b");
        };
        assert_eq!(res_a.status, OutcomeStatus::Success);
        assert_eq!(res_a.output.len(), 32);
        assert_ne!(res_a.output, res_b.output);
    }

    #[test]
    fn publish_module_and_run_entry_function_persists_resource() {
        let mut worker = MoveWorker::new();
        let mut host = MemoryHost::new(5_000_000);
        let ctx = sample_ctx();
        let publisher = [0x33u8; 32];
        let module = CompiledMoveModule {
            address: publisher,
            name: "counter".to_string(),
            functions: vec![
                MoveFunctionDef {
                    name: "set_message".to_string(),
                    is_entry: true,
                    is_view: false,
                    code: vec![MoveOp::WriteResourceFromArg {
                        resource_tag: "0x33::counter::Message".to_string(),
                        arg_index: 0,
                    }],
                },
                MoveFunctionDef {
                    name: "get_message".to_string(),
                    is_entry: false,
                    is_view: true,
                    code: vec![MoveOp::ReadResource {
                        owner: Some(publisher),
                        resource_tag: "0x33::counter::Message".to_string(),
                    }],
                },
            ],
        };
        let Ok(raw_mod) = encode_move_module(&module) else {
            panic!("encode module");
        };
        assert!(worker.validate_deploy(&raw_mod).is_ok());

        let Ok(pub_input) = serde_json::to_vec(&MovePayload::PublishPackage {
            metadata_serialized: b"meta".to_vec(),
            modules: vec![raw_mod],
        }) else {
            panic!("serialize publish");
        };
        let Ok(pub_res) = worker.execute(
            &ctx,
            &make_call(publisher, publisher, pub_input),
            &mut host,
        ) else {
            panic!("publish");
        };
        assert_eq!(pub_res.status, OutcomeStatus::Success);

        let Ok(run_input) = serde_json::to_vec(&MovePayload::EntryFunction {
            module_address: publisher,
            module_name: "counter".to_string(),
            function_name: "set_message".to_string(),
            ty_args: Vec::new(),
            args: vec![b"merhaba-move".to_vec()],
        }) else {
            panic!("serialize run");
        };
        let Ok(run_res) = worker.execute(
            &ctx,
            &make_call(publisher, publisher, run_input),
            &mut host,
        ) else {
            panic!("run");
        };
        assert_eq!(run_res.status, OutcomeStatus::Success);

        let Ok(q_bytes) = serde_json::to_vec(&MoveQuery::View {
            module_address: publisher,
            module_name: "counter".to_string(),
            function_name: "get_message".to_string(),
            ty_args: Vec::new(),
            args: Vec::new(),
        }) else {
            panic!("serialize view");
        };
        let Ok(q_out) = worker.query(
            &ctx,
            &EeQuery {
                target: move_identity(publisher),
                input: q_bytes,
            },
            &host,
        ) else {
            panic!("view query");
        };
        assert_eq!(q_out, b"merhaba-move");
    }

    #[test]
    fn budlum_universal_call_transfers_octas_and_encodes_bcs_result() {
        let mut worker = MoveWorker::new();
        let mut host = MemoryHost::new(5_000_000).with_universal_handler(Box::new(|call| {
            assert_eq!(call.to_ee, EeId::EVM);
            assert_eq!(call.value.0, 5 * ATTO_PER_OCTA);
            assert_eq!(call.gas_limit, 75_000);
            Ok(UniversalResult {
                success: true,
                output: vec![0xCA, 0xFE],
                gas_used: 12_000,
            })
        }));

        let payload = MovePayload::EntryFunction {
            module_address: FRAMEWORK_ADDRESS,
            module_name: "budlum_universal".to_string(),
            function_name: "call".to_string(),
            ty_args: Vec::new(),
            args: vec![
                vec![EeId::EVM.0],
                vec![0xAA; 20],
                vec![0x01, 0x02],
                5u64.to_le_bytes().to_vec(),
                75_000u64.to_le_bytes().to_vec(),
            ],
        };
        let Ok(input) = serde_json::to_vec(&payload) else {
            panic!("serialize");
        };
        let Ok(res) = worker.execute(
            &sample_ctx(),
            &make_call([0x44u8; 32], FRAMEWORK_ADDRESS, input),
            &mut host,
        ) else {
            panic!("execute");
        };
        assert_eq!(res.status, OutcomeStatus::Success);
        assert_eq!(res.output, vec![0x01, 0x02, 0xCA, 0xFE]);
    }

    #[test]
    fn ipc_roundtrip_over_unix_socket() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir");
        };
        let sock = dir.path().join("ee-move.sock");
        let Ok(listener) = UnixListener::bind(&sock) else {
            panic!("bind");
        };
        let server = std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                panic!("accept");
            };
            let mut worker = MoveWorker::new();
            serve_connection(stream, &mut worker)
        });

        let mut client = EeClient::new(&sock, EeId::MOVE).with_timeout(Duration::from_secs(5));
        let mut host = MemoryHost::new(2_000_000);
        let sender = [0x55u8; 32];
        let recipient = [0x66u8; 32];
        host.balances
            .insert(move_identity(sender), 50 * ATTO_PER_OCTA);

        let Ok(input) = serde_json::to_vec(&MovePayload::EntryFunction {
            module_address: FRAMEWORK_ADDRESS,
            module_name: "aptos_account".to_string(),
            function_name: "transfer".to_string(),
            ty_args: Vec::new(),
            args: vec![recipient.to_vec(), 9u64.to_le_bytes().to_vec()],
        }) else {
            panic!("serialize");
        };
        let Ok(Ok(res)) = client.execute(
            &sample_ctx(),
            &make_call(sender, FRAMEWORK_ADDRESS, input),
            &mut host,
        ) else {
            panic!("client execute");
        };
        assert_eq!(res.status, OutcomeStatus::Success);
        assert_eq!(
            host.bud_balance(&move_identity(recipient)),
            Ok(BudAmount(9 * ATTO_PER_OCTA))
        );
        drop(client);
        let Ok(srv) = server.join() else {
            panic!("join");
        };
        assert!(srv.is_ok());
    }
}
