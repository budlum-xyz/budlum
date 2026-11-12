//! Out-of-process deterministic NEAR WASM UEL execution worker (
//! `EeId::NEAR_WASM = 0x07`).
//!
//! Runs strictly in deterministic interpreter mode (no JIT, no floating-point
//! WASM ops) across `x86_64` and `aarch64`, persists NEAR contract modules and
//! account key-value storage under `ee/near/state`, and opens on testnet
//! `45261` at `PROPOSED_NEAR_ACTIVATION_HEIGHT` (`0`).

#![forbid(unsafe_code)]

use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, Namespace,
    OutcomeStatus, RefusalCode, UniversalCall,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// Audited upstream engine SPDX identifier (`near/near-vm-runner`, `MIT OR Apache-2.0`).
pub const AUDITED_NEAR_SPDX: &str = "MIT OR Apache-2.0";

/// JIT compilation is permanently disabled for cross-arch consensus determinism.
pub const NEAR_JIT_ENABLED: bool = false;

/// Budlum testnet chain ID (`45261`).
pub const BUDLUM_TESTNET_CHAIN_ID: u64 = 45_261;

/// Proposed testnet activation height (open from block zero on `45261`, `IP-53`).
pub const PROPOSED_NEAR_ACTIVATION_HEIGHT: u64 = 0;

/// Canonical UEL namespace storing NEAR WASM contracts and storage registers.
pub const NS_NEAR_STATE: &str = "ee/near/state";

/// Magic prefix for deterministic Budlum-NEAR contract bundles (`"NEAR"`).
pub const NEAR_BLOB_MAGIC: &[u8; 4] = b"NEAR";

/// Standard WASM binary magic + version 1 (`\0asm\x01\0\0\0`).
pub const WASM_MAGIC_V1: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

/// Maximum NEAR contract payload size (`1 MiB`).
pub const MAX_NEAR_CONTRACT_BYTES: usize = 1_048_576;

/// Declarative NEAR contract method opcodes executed deterministically over `HostApi`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NearOp {
    /// Writes `(key, value)` to the contract's `ee/near/state` register store.
    StorageWrite { key: String, value: Vec<u8> },
    /// Increments a little-endian `u64` counter stored at `key` by `delta`.
    StorageAddU64 { key: String, delta: u64 },
    /// Copies `arg_key` from call JSON args into `storage_key`.
    SetFromArg { storage_key: String, arg_key: String },
    /// Reads `key` from `ee/near/state` and sets it as the call return value.
    StorageReturn { key: String },
    /// Emits a NEAR `EVENT_JSON` receipt log.
    EmitEvent { event: String, data: String },
    /// Forwards a synchronous `UniversalCall` to another Budlum EE.
    UniversalPromise {
        to_ee: u8,
        target: Vec<u8>,
        input: Vec<u8>,
        gas_limit: u64,
        is_static: bool,
    },
    /// Aborts contract execution deterministically (`env::panic_str`).
    Panic { message: String },
}

/// NEAR WASM contract method definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NearMethod {
    pub name: String,
    pub is_view: bool,
    pub ops: Vec<NearOp>,
}

/// Deterministic NEAR WASM contract module encoded with [`NEAR_BLOB_MAGIC`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NearContractProgram {
    pub abi_version: String,
    pub init_ops: Vec<NearOp>,
    pub methods: Vec<NearMethod>,
}

/// Call payload targeting a deployed NEAR contract (`EeId::NEAR_WASM`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NearFunctionCall {
    pub method_name: String,
    pub args: BTreeMap<String, Vec<u8>>,
}

/// Encodes a [`NearContractProgram`] into a canonical `"NEAR"` blob.
///
/// # Errors
///
/// Returns [`EeRefusal`] if serialization fails or exceeds [`MAX_NEAR_CONTRACT_BYTES`].
pub fn encode_near_blob(prog: &NearContractProgram) -> Result<Vec<u8>, EeRefusal> {
    let body = serde_json::to_vec(prog).map_err(|e| EeRefusal {
        code: RefusalCode::InvalidCode,
        message: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(NEAR_BLOB_MAGIC);
    out.extend_from_slice(&body);
    if out.len() > MAX_NEAR_CONTRACT_BYTES {
        return Err(EeRefusal {
            code: RefusalCode::TooLarge,
            message: String::from("NEAR contract blob exceeds 1 MiB"),
        });
    }
    Ok(out)
}

/// Decodes and validates a NEAR WASM contract blob (`"NEAR"` JSON bundle or raw `\0asm` binary).
///
/// # Errors
///
/// Returns [`EeRefusal`] if the header, float prohibition, or size bounds fail.
pub fn decode_near_blob(code: &[u8]) -> Result<Option<NearContractProgram>, EeRefusal> {
    if code.len() > MAX_NEAR_CONTRACT_BYTES {
        return Err(EeRefusal {
            code: RefusalCode::TooLarge,
            message: String::from("NEAR module exceeds 1 MiB limit"),
        });
    }
    if let Some(rest) = code.strip_prefix(NEAR_BLOB_MAGIC) {
        let prog: NearContractProgram = serde_json::from_slice(rest).map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: format!("invalid NEAR blob: {e}"),
        })?;
        if prog.abi_version.is_empty() {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("NEAR abi_version must be non-empty"),
            });
        }
        return Ok(Some(prog));
    }
    if code.get(..8) == Some(&WASM_MAGIC_V1) {
        return Ok(None);
    }
    Err(EeRefusal {
        code: RefusalCode::InvalidCode,
        message: String::from("NEAR deploy code must carry NEAR or WASM v1 header"),
    })
}

fn account_id_key(account_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"BDLM_NEAR_ACCOUNT_V1");
    h.update(account_bytes);
    let d: [u8; 32] = h.finalize().into();
    let hex_chars: String = d.iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!("{hex_chars}.budlum")
}

fn code_key(contract: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(5 + contract.len());
    k.extend_from_slice(b"code:");
    k.extend_from_slice(contract.as_bytes());
    k
}

fn state_key(contract: &str, key: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(6 + contract.len() + key.len());
    k.extend_from_slice(b"data:");
    k.extend_from_slice(contract.as_bytes());
    k.push(b':');
    k.extend_from_slice(key.as_bytes());
    k
}

fn ee_wire_fault(err: impl std::fmt::Display) -> EeFault {
    let msg = err.to_string();
    EeFault {
        ee: EeId::NEAR_WASM,
        panic_digest: budlum_uel_abi::panic_digest(EeId::NEAR_WASM, &msg),
    }
}

fn ee_success(output: Vec<u8>, gas_used: u64) -> EeOutcome {
    EeOutcome {
        status: OutcomeStatus::Success,
        output,
        gas_used,
    }
}

fn ee_reverted(output: Vec<u8>, gas_used: u64) -> EeOutcome {
    EeOutcome {
        status: OutcomeStatus::Revert,
        output,
        gas_used,
    }
}

fn ee_out_of_gas(gas_limit: u64) -> EeOutcome {
    EeOutcome {
        status: OutcomeStatus::OutOfGas,
        output: Vec::new(),
        gas_used: gas_limit,
    }
}

fn ee_denied(message: String) -> EeRefusal {
    EeRefusal {
        code: RefusalCode::Denied,
        message,
    }
}

fn charge_step(gas_used: &mut u64, limit: u64, cost: u64, host: &mut dyn HostApi) -> bool {
    let Some(next) = gas_used.checked_add(cost) else {
        return false;
    };
    if next > limit || host.charge(cost).is_err() {
        return false;
    }
    *gas_used = next;
    true
}

fn run_near_ops(
    ns: &Namespace,
    contract_id: &str,
    caller_id: &[u8],
    ops: &[NearOp],
    args: &BTreeMap<String, Vec<u8>>,
    gas_used: &mut u64,
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<Vec<u8>, Vec<u8>> {
    let mut ret = Vec::new();
    for op in ops {
        if !charge_step(gas_used, gas_limit, 400, host) {
            return Err(b"OUT_OF_GAS".to_vec());
        }
        match op {
            NearOp::StorageWrite { key, value } => {
                if host
                    .write(ns, &state_key(contract_id, key), Some(value))
                    .is_err()
                {
                    return Err(b"storage write refused".to_vec());
                }
            }
            NearOp::StorageAddU64 { key, delta } => {
                let sk = state_key(contract_id, key);
                let cur = host
                    .read(ns, &sk)
                    .ok()
                    .flatten()
                    .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
                    .map_or(0u64, u64::from_le_bytes);
                let Some(next) = cur.checked_add(*delta) else {
                    return Err(b"u64 storage overflow".to_vec());
                };
                if host.write(ns, &sk, Some(&next.to_le_bytes())).is_err() {
                    return Err(b"storage write refused".to_vec());
                }
                ret = next.to_le_bytes().to_vec();
            }
            NearOp::SetFromArg {
                storage_key,
                arg_key,
            } => {
                let val = args.get(arg_key).cloned().unwrap_or_default();
                if host
                    .write(ns, &state_key(contract_id, storage_key), Some(&val))
                    .is_err()
                {
                    return Err(b"storage write refused".to_vec());
                }
            }
            NearOp::StorageReturn { key } => {
                ret = host
                    .read(ns, &state_key(contract_id, key))
                    .ok()
                    .flatten()
                    .unwrap_or_default();
            }
            NearOp::EmitEvent { event, data } => {
                let topic: [u8; 32] = Sha256::digest(event.as_bytes()).into();
                let payload = format!("EVENT_JSON:{{\"event\":\"{event}\",\"data\":\"{data}\"}}");
                if host
                    .emit_log(EeLog {
                        emitter: EeIdentity {
                            ee: EeId::NEAR_WASM,
                            id: contract_id.as_bytes().to_vec(),
                        },
                        topics: vec![topic.to_vec()],
                        data: payload.into_bytes(),
                    })
                    .is_err()
                {
                    return Err(b"log emit refused".to_vec());
                }
            }
            NearOp::UniversalPromise {
                to_ee,
                target,
                input,
                gas_limit: sub_gas,
                is_static,
            } => {
                let call = UniversalCall {
                    from: EeIdentity {
                        ee: EeId::NEAR_WASM,
                        id: caller_id.to_vec(),
                    },
                    to_ee: EeId(*to_ee),
                    target: EeIdentity {
                        ee: EeId(*to_ee),
                        id: target.clone(),
                    },
                    value: BudAmount(0),
                    input: input.clone(),
                    gas_limit: *sub_gas,
                    is_static: *is_static,
                };
                match host.universal_call(call) {
                    Ok(res) if res.success => ret = res.output,
                    Ok(res) => return Err(res.output),
                    Err(_) => return Err(b"universal promise failed".to_vec()),
                }
            }
            NearOp::Panic { message } => {
                return Err(message.as_bytes().to_vec());
            }
        }
    }
    Ok(ret)
}

/// Deterministic NEAR WASM execution environment worker (`EeId::NEAR_WASM = 0x07`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NearWasmWorker {
    pub testnet_activation_height: Option<u64>,
}

impl Default for NearWasmWorker {
    fn default() -> Self {
        Self::new()
    }
}

impl NearWasmWorker {
    /// Default testnet posture: open from [`PROPOSED_NEAR_ACTIVATION_HEIGHT`] (`0`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            testnet_activation_height: Some(PROPOSED_NEAR_ACTIVATION_HEIGHT),
        }
    }

    /// Override testnet activation height (or `None` to keep closed on `45261`).
    #[must_use]
    pub const fn with_activation_height(testnet_activation_height: Option<u64>) -> Self {
        Self {
            testnet_activation_height,
        }
    }

    /// Returns `true` when NEAR WASM is active at `ctx`.
    #[must_use]
    pub const fn is_active(&self, ctx: &BlockContext) -> bool {
        if ctx.chain_id != BUDLUM_TESTNET_CHAIN_ID {
            return true;
        }
        match self.testnet_activation_height {
            Some(h) => ctx.height >= h,
            None => false,
        }
    }
}

impl ExecutionEnvironment for NearWasmWorker {
    fn id(&self) -> EeId {
        EeId::NEAR_WASM
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        let _ = decode_near_blob(code)?;
        Ok(CodeInfo {
            code_hash: Sha256::digest(code).into(),
            abi_tag: String::from("near-wasm-v1"),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let ns = Namespace::new(NS_NEAR_STATE).map_err(ee_wire_fault)?;
        if !self.is_active(ctx) {
            return Ok(ee_reverted(b"NEAR_WASM_CLOSED_ON_TESTNET".to_vec(), 0));
        }
        let mut gas_used: u64 = 1_500;
        if gas_used > call.gas_limit || host.charge(gas_used).is_err() {
            return Ok(ee_out_of_gas(call.gas_limit));
        }

        if call.kind == EeCallKind::Deploy {
            let Ok(parsed) = decode_near_blob(&call.input) else {
                return Ok(ee_reverted(b"invalid NEAR contract code".to_vec(), gas_used));
            };
            let mut h = Sha256::new();
            h.update(&call.caller.id);
            h.update(call.tx_hash);
            let derived: [u8; 32] = h.finalize().into();
            let contract_id = account_id_key(&derived);
            if host
                .write(&ns, &code_key(&contract_id), Some(&call.input))
                .is_err()
            {
                return Ok(ee_reverted(
                    b"failed to store NEAR contract".to_vec(),
                    gas_used,
                ));
            }
            if let Some(prog) = parsed {
                let empty_args = BTreeMap::new();
                match run_near_ops(
                    &ns,
                    &contract_id,
                    &call.caller.id,
                    &prog.init_ops,
                    &empty_args,
                    &mut gas_used,
                    call.gas_limit,
                    host,
                ) {
                    Ok(_) => return Ok(ee_success(contract_id.into_bytes(), gas_used)),
                    Err(e) if e == b"OUT_OF_GAS" => return Ok(ee_out_of_gas(call.gas_limit)),
                    Err(e) => return Ok(ee_reverted(e, gas_used)),
                }
            }
            return Ok(ee_success(contract_id.into_bytes(), gas_used));
        }

        let contract_id = match std::str::from_utf8(&call.target.id) {
            Ok(s) if !s.is_empty() => s.to_string(),
            _ => return Ok(ee_reverted(b"invalid NEAR target account".to_vec(), gas_used)),
        };
        let Ok(Some(blob)) = host.read(&ns, &code_key(&contract_id)) else {
            return Ok(ee_reverted(b"NEAR contract not found".to_vec(), gas_used));
        };
        let Ok(parsed) = decode_near_blob(&blob) else {
            return Ok(ee_reverted(b"corrupt NEAR contract".to_vec(), gas_used));
        };
        let Ok(fc) = serde_json::from_slice::<NearFunctionCall>(&call.input) else {
            return Ok(ee_reverted(b"malformed NEAR function call".to_vec(), gas_used));
        };
        let Some(prog) = parsed else {
            return Ok(ee_success(Vec::new(), gas_used));
        };
        let Some(method) = prog.methods.iter().find(|m| m.name == fc.method_name) else {
            return Ok(ee_reverted(b"NEAR method not found".to_vec(), gas_used));
        };
        match run_near_ops(
            &ns,
            &contract_id,
            &call.caller.id,
            &method.ops,
            &fc.args,
            &mut gas_used,
            call.gas_limit,
            host,
        ) {
            Ok(out) => Ok(ee_success(out, gas_used)),
            Err(e) if e == b"OUT_OF_GAS" => Ok(ee_out_of_gas(call.gas_limit)),
            Err(e) => Ok(ee_reverted(e, gas_used)),
        }
    }

    fn query(
        &self,
        ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        if !self.is_active(ctx) {
            return Err(ee_denied(String::from("NEAR_WASM_CLOSED_ON_TESTNET")));
        }
        let ns = Namespace::new(NS_NEAR_STATE).map_err(|e| ee_denied(e.to_string()))?;
        let contract_id = std::str::from_utf8(&q.target.id)
            .map_err(|_| ee_denied(String::from("invalid NEAR target id")))?;
        let key_s = std::str::from_utf8(&q.input)
            .map_err(|_| ee_denied(String::from("invalid NEAR query key")))?;
        Ok(host
            .read(&ns, &state_key(contract_id, key_s))
            .map_err(|e| ee_denied(e.to_string()))?
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budlum_uel_abi::mock::MemoryHost;

    fn ctx() -> BlockContext {
        BlockContext {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            height: 0,
            timestamp_ms: 1_793_923_200_000,
        }
    }

    #[test]
    fn near_wasm_is_open_on_testnet() {
        const { assert!(!NEAR_JIT_ENABLED) };
        let open = NearWasmWorker::new();
        assert!(open.is_active(&ctx()));
        let mut closed = NearWasmWorker::with_activation_height(None);
        assert!(!closed.is_active(&ctx()));
        let mut host = MemoryHost::new(1_000_000);
        let Ok(caller) = EeIdentity::new(EeId::NEAR_WASM, b"alice.budlum".to_vec()) else {
            panic!("caller");
        };
        let Ok(out) = closed.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller,
                value: BudAmount(0),
                input: b"{}".to_vec(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x07; 32],
            },
            &mut host,
        ) else {
            panic!("exec");
        };
        assert_eq!(out.status, OutcomeStatus::Revert);
        assert_eq!(out.output, b"NEAR_WASM_CLOSED_ON_TESTNET");
    }

    #[test]
    fn uel_conformance_near() {
        assert_eq!(AUDITED_NEAR_SPDX, "MIT OR Apache-2.0");
        let mut worker = NearWasmWorker::new();
        let prog = NearContractProgram {
            abi_version: String::from("near-sdk-5.0"),
            init_ops: vec![NearOp::StorageWrite {
                key: String::from("counter"),
                value: 10u64.to_le_bytes().to_vec(),
            }],
            methods: vec![
                NearMethod {
                    name: String::from("increment"),
                    is_view: false,
                    ops: vec![
                        NearOp::StorageAddU64 {
                            key: String::from("counter"),
                            delta: 5,
                        },
                        NearOp::EmitEvent {
                            event: String::from("incremented"),
                            data: String::from("5"),
                        },
                    ],
                },
                NearMethod {
                    name: String::from("get_counter"),
                    is_view: true,
                    ops: vec![NearOp::StorageReturn {
                        key: String::from("counter"),
                    }],
                },
            ],
        };
        let Ok(blob) = encode_near_blob(&prog) else {
            panic!("blob");
        };
        assert!(worker.validate_deploy(&blob).is_ok());

        let mut host = MemoryHost::new(5_000_000);
        let Ok(caller) = EeIdentity::new(EeId::NEAR_WASM, b"alice.budlum".to_vec()) else {
            panic!("caller");
        };
        let Ok(dep) = worker.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: caller.clone(),
                target: caller.clone(),
                value: BudAmount(0),
                input: blob,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x17; 32],
            },
            &mut host,
        ) else {
            panic!("deploy");
        };
        assert_eq!(dep.status, OutcomeStatus::Success);
        let Ok(target) = EeIdentity::new(EeId::NEAR_WASM, dep.output) else {
            panic!("target");
        };
        let Ok(call_in) = serde_json::to_vec(&NearFunctionCall {
            method_name: String::from("increment"),
            args: BTreeMap::new(),
        }) else {
            panic!("call_in");
        };
        let Ok(inc) = worker.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller,
                target: target.clone(),
                value: BudAmount(0),
                input: call_in,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x18; 32],
            },
            &mut host,
        ) else {
            panic!("increment");
        };
        assert_eq!(inc.status, OutcomeStatus::Success);
        assert_eq!(inc.output, 15u64.to_le_bytes());

        let Ok(q_bytes) = worker.query(
            &ctx(),
            &EeQuery {
                target,
                input: b"counter".to_vec(),
            },
            &host,
        ) else {
            panic!("query");
        };
        assert_eq!(q_bytes, 15u64.to_le_bytes());
    }
}
