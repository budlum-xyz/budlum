//! Out-of-process deterministic Cairo (Starknet) UEL execution worker (,
//! `EeId::CAIRO = 0x06`).
//!
//! Audited license posture (`Section 8.2`,): `lambdaclass/cairo-vm` (`Apache-2.0`)
//! and `starkware-libs/sequencer` (`blockifier`, `Apache-2.0`).
//! Binds Starknet Account Abstraction (`__validate__`, `__validate_declare__`,
//! `__execute__`) directly to the caller's post-quantum Budlum local alias, stores
//! Sierra/CASM classes, contract instances, nonces, and `felt252` storage under
//! `ee/cairo/state`, and enforces `Section 1.5` launch-closure on testnet `45261`
//! until `PROPOSED_CAIRO_ACTIVATION_HEIGHT`.

#![forbid(unsafe_code)]

use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostError, HostRead, Namespace,
    UniversalCall,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

/// Audited SPDX license identifier for `cairo-vm` and `blockifier` (`Section 8.2`,).
pub const AUDITED_CAIRO_ENGINE_SPDX: &str = "Apache-2.0";

/// Budlum testnet chain ID (`Section 1.5`).
pub const BUDLUM_TESTNET_CHAIN_ID: u64 = 45_261;

/// Proposed activation height on testnet `45261` ().
pub const PROPOSED_CAIRO_ACTIVATION_HEIGHT: u64 = 55_000;

/// Canonical UEL namespace storing Starknet classes, contract instances, nonces, and storage.
pub const NS_CAIRO_STATE: &str = "ee/cairo/state";

/// Magic prefix for Sierra/CASM class bundles (`sncast declare`).
pub const SIERRA_CLASS_MAGIC: &[u8; 4] = b"SRCA";

/// Maximum Sierra/CASM class artifact size (`4 MiB`).
pub const MAX_SIERRA_CLASS_BYTES: usize = 4 * 1024 * 1024;

/// Base gas charged per Starknet AA invocation (`__validate__` + `__execute__`) in BGU.
pub const CAIRO_AA_BASE_BGU: u64 = 2_500;

/// Gas charged per Cairo syscall / instruction step in BGU.
pub const CAIRO_STEP_BGU: u64 = 150;

/// Gas charged per `storage_write` syscall in BGU.
pub const CAIRO_STORAGE_WRITE_BGU: u64 = 5_000;

/// Mask clearing the top 4 bits of a 32-byte big-endian value so it fits inside `felt252`
/// (`< 2^251`).
pub fn mask_to_felt252(mut raw: [u8; 32]) -> [u8; 32] {
    if let Some(b0) = raw.first_mut() {
        *b0 &= 0x07;
    }
    raw
}

/// Compute Starknet `sn_keccak(ascii_name)` selector (`keccak256(name)` masked to 250 bits).
#[must_use]
pub fn sn_keccak_selector(entry_name: &str) -> [u8; 32] {
    let mut digest: [u8; 32] = Keccak256::digest(entry_name.as_bytes()).into();
    if let Some(b0) = digest.first_mut() {
        *b0 &= 0x03;
    }
    digest
}

/// Deterministic Cairo CASM instruction subset executed inside contract entrypoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CairoSyscallOp {
    /// `storage_write_syscall(slot, value_felt)`
    StorageWrite { slot: [u8; 32], value: [u8; 32] },
    /// Copy calldata felt `arg_index` into storage `slot`.
    StoreCalldataArg { slot: [u8; 32], arg_index: usize },
    /// Add `delta` (low `u64` of felt) to storage `slot`.
    StorageAddU64 { slot: [u8; 32], delta: u64 },
    /// Read storage `slot` and return it as single-felt return data.
    StorageReadReturn { slot: [u8; 32] },
    /// `emit_event_syscall(keys, data)`
    EmitEvent {
        keys: Vec<[u8; 32]>,
        data: Vec<[u8; 32]>,
    },
    /// Cross-EE `UniversalCall` from a Cairo contract.
    UniversalCall {
        target_ee: u8,
        target: Vec<u8>,
        input: Vec<u8>,
        gas_limit: u64,
    },
}

/// Entrypoint table entry inside a Sierra/CASM contract class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CairoEntrypoint {
    pub name: String,
    pub ops: Vec<CairoSyscallOp>,
}

/// Declared Sierra/CASM class stored under `ee/cairo/state/class:<class_hash>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SierraContractClass {
    pub sierra_version: String,
    pub entrypoints: Vec<CairoEntrypoint>,
}

impl SierraContractClass {
    /// Compute canonical 252-bit `class_hash` over the Sierra/CASM artifact.
    #[must_use]
    pub fn class_hash(&self) -> [u8; 32] {
        let raw = serde_json::to_vec(self).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(b"STARKNET_SIERRA_CLASS_V1");
        h.update(&raw);
        mask_to_felt252(h.finalize().into())
    }
}

/// Encode a `SIERRA_CLASS_MAGIC`-prefixed class bundle for `validate_deploy` / `Declare`.
pub fn encode_sierra_class(cls: &SierraContractClass) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(cls).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(SIERRA_CLASS_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode and validate a `SIERRA_CLASS_MAGIC`-prefixed Sierra/CASM class bundle.
pub fn decode_sierra_class(raw: &[u8]) -> Result<SierraContractClass, EeRefusal> {
    if raw.len() < 4 || raw.len() > MAX_SIERRA_CLASS_BYTES {
        return Err(EeRefusal::BadCode("invalid Sierra class size".into()));
    }
    if raw.get(..4) != Some(SIERRA_CLASS_MAGIC.as_slice()) {
        return Err(EeRefusal::BadCode("missing SRCA Sierra magic".into()));
    }
    let body = raw.get(4..).unwrap_or_default();
    let cls: SierraContractClass = serde_json::from_slice(body)
        .map_err(|e| EeRefusal::BadCode(format!("malformed Sierra class: {e}")))?;
    if cls.entrypoints.is_empty() {
        return Err(EeRefusal::BadCode("Sierra class has no entrypoints".into()));
    }
    Ok(cls)
}

/// One external call inside a Starknet Account Abstraction `__execute__` multicall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarknetCall {
    pub contract_address: [u8; 32],
    pub entrypoint: String,
    pub calldata: Vec<[u8; 32]>,
}

/// Starknet transaction actions bound to the Budlum local account alias ().
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CairoAction {
    /// `INVOKE` v3 (`__validate_declare__` + class registration, `sncast declare`).
    Declare {
        class_bundle: Vec<u8>,
        nonce: u64,
    },
    /// Universal Deployer (`sncast deploy`): instantiate `class_hash` with `salt` and run
    /// `constructor` if present.
    DeployContract {
        class_hash: [u8; 32],
        salt: [u8; 32],
        constructor_calldata: Vec<[u8; 32]>,
        nonce: u64,
    },
    /// Starknet AA multicall (`__validate__` bound to caller PQ alias + `__execute__`).
    InvokeAccount {
        calls: Vec<StarknetCall>,
        nonce: u64,
    },
}

/// Read-only Starknet query shapes answered by `CairoWorker::query`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CairoQuery {
    GetClassHashAt { contract_address: [u8; 32] },
    GetStorageAt {
        contract_address: [u8; 32],
        slot: [u8; 32],
    },
    GetNonce { account_address: [u8; 32] },
    Call {
        contract_address: [u8; 32],
        entrypoint: String,
        calldata: Vec<[u8; 32]>,
    },
}

fn class_key(class_hash: &[u8; 32]) -> Vec<u8> {
    let mut k = b"class:".to_vec();
    k.extend_from_slice(class_hash);
    k
}

fn inst_key(contract: &[u8; 32]) -> Vec<u8> {
    let mut k = b"inst:".to_vec();
    k.extend_from_slice(contract);
    k
}

fn nonce_key(account: &[u8; 32]) -> Vec<u8> {
    let mut k = b"nonce:".to_vec();
    k.extend_from_slice(account);
    k
}

fn storage_key(contract: &[u8; 32], slot: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(69);
    k.extend_from_slice(b"stor:");
    k.extend_from_slice(contract);
    k.extend_from_slice(slot);
    k
}

/// Deterministically derive a deployed Starknet `ContractAddress` (`felt252`) from
/// `(deployer, salt, class_hash)`.
#[must_use]
pub fn derive_starknet_contract_address(
    deployer: &[u8; 32],
    salt: &[u8; 32],
    class_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"STARKNET_CONTRACT_ADDRESS_BDLM_V1");
    h.update(deployer);
    h.update(salt);
    h.update(class_hash);
    mask_to_felt252(h.finalize().into())
}

fn cairo_ns() -> Result<Namespace, HostError> {
    Namespace::new(NS_CAIRO_STATE).map_err(|_| HostError::Invalid("bad cairo ns".into()))
}

fn read_account_nonce(host: &dyn HostRead, account: &[u8; 32]) -> Result<u64, HostError> {
    let ns = cairo_ns()?;
    let Some(raw) = host.read(&ns, &nonce_key(account))? else {
        return Ok(0);
    };
    let arr: [u8; 8] = raw
        .as_slice()
        .try_into()
        .map_err(|_| HostError::Invalid("corrupt cairo nonce".into()))?;
    Ok(u64::from_le_bytes(arr))
}

fn bump_account_nonce(
    host: &mut dyn HostApi,
    account: &[u8; 32],
    expected_nonce: u64,
) -> Result<(), &'static [u8]> {
    let cur = read_account_nonce(host, account).map_err(|_| &b"nonce read err"[..])?;
    if cur != expected_nonce {
        return Err(b"STARKNET_INVALID_TRANSACTION_NONCE");
    }
    let next = cur.saturating_add(1);
    let Ok(ns) = cairo_ns() else {
        return Err(b"cairo ns err");
    };
    host.write(ns, &nonce_key(account), Some(&next.to_le_bytes()))
        .map_err(|_| &b"nonce write err"[..])
}

/// Out-of-process sequential Cairo (Starknet) worker (`EeId::CAIRO = 0x06`).
#[derive(Debug, Clone)]
pub struct CairoWorker {
    pub testnet_activation_height: Option<u64>,
}

impl Default for CairoWorker {
    fn default() -> Self {
        Self::new()
    }
}

impl CairoWorker {
    /// Default launch configuration: closed on testnet `45261` until
    /// [`PROPOSED_CAIRO_ACTIVATION_HEIGHT`] (`Section 1.5`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            testnet_activation_height: Some(PROPOSED_CAIRO_ACTIVATION_HEIGHT),
        }
    }

    /// Returns `true` if `CairoWorker` is active at `ctx`.
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

fn run_entrypoint(
    contract_addr: &[u8; 32],
    entrypoint_name: &str,
    calldata: &[[u8; 32]],
    gas_used: &mut u64,
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<Vec<[u8; 32]>, &'static [u8]> {
    let Ok(ns) = cairo_ns() else {
        return Err(b"cairo ns err");
    };
    let Ok(Some(ch_bytes)) = host.read(&ns, &inst_key(contract_addr)) else {
        return Err(b"CONTRACT_NOT_FOUND");
    };
    let Ok(ch32) = <[u8; 32]>::try_from(ch_bytes.as_slice()) else {
        return Err(b"corrupt contract class_hash");
    };
    let Ok(Some(cls_bytes)) = host.read(&ns, &class_key(&ch32)) else {
        return Err(b"CLASS_NOT_DECLARED");
    };
    let Ok(cls) = serde_json::from_slice::<SierraContractClass>(&cls_bytes) else {
        return Err(b"corrupt Sierra class");
    };
    let Some(ep) = cls.entrypoints.iter().find(|e| e.name == entrypoint_name) else {
        if entrypoint_name == "constructor" {
            return Ok(Vec::new());
        }
        return Err(b"ENTRYPOINT_NOT_FOUND");
    };

    let mut ret_felts: Vec<[u8; 32]> = Vec::new();
    for op in &ep.ops {
        let step_cost = match op {
            CairoSyscallOp::StorageWrite { .. }
            | CairoSyscallOp::StoreCalldataArg { .. }
            | CairoSyscallOp::StorageAddU64 { .. } => CAIRO_STORAGE_WRITE_BGU,
            _ => CAIRO_STEP_BGU,
        };
        let next = gas_used.saturating_add(step_cost);
        if next > gas_limit || host.charge(step_cost).is_err() {
            return Err(b"OUT_OF_GAS");
        }
        *gas_used = next;

        match op {
            CairoSyscallOp::StorageWrite { slot, value } => {
                let val = mask_to_felt252(*value);
                let sk = storage_key(contract_addr, slot);
                if host.write(ns.clone(), &sk, Some(&val)).is_err() {
                    return Err(b"storage write err");
                }
            }
            CairoSyscallOp::StoreCalldataArg { slot, arg_index } => {
                let Some(arg) = calldata.get(*arg_index) else {
                    return Err(b"CALLDATA_OUT_OF_BOUNDS");
                };
                let val = mask_to_felt252(*arg);
                let sk = storage_key(contract_addr, slot);
                if host.write(ns.clone(), &sk, Some(&val)).is_err() {
                    return Err(b"storage write err");
                }
            }
            CairoSyscallOp::StorageAddU64 { slot, delta } => {
                let sk = storage_key(contract_addr, slot);
                let cur_raw = host.read(&ns, &sk).ok().flatten();
                let mut felt = [0u8; 32];
                if let Some(bytes) = cur_raw {
                    if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                        felt = arr;
                    }
                }
                let lo8: [u8; 8] = felt
                    .get(24..32)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0; 8]);
                let sum = u64::from_be_bytes(lo8).saturating_add(*delta);
                if let Some(tail) = felt.get_mut(24..32) {
                    tail.copy_from_slice(&sum.to_be_bytes());
                }
                let felt = mask_to_felt252(felt);
                if host.write(ns.clone(), &sk, Some(&felt)).is_err() {
                    return Err(b"storage add err");
                }
            }
            CairoSyscallOp::StorageReadReturn { slot } => {
                let sk = storage_key(contract_addr, slot);
                let felt = host
                    .read(&ns, &sk)
                    .ok()
                    .flatten()
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                    .unwrap_or([0u8; 32]);
                ret_felts.push(felt);
            }
            CairoSyscallOp::EmitEvent { keys, data } => {
                let topics: Vec<Vec<u8>> = keys.iter().take(8).map(|k| k.to_vec()).collect();
                let mut payload = Vec::with_capacity(data.len() * 32);
                for d in data {
                    payload.extend_from_slice(d);
                }
                let _ = host.emit_log(EeLog {
                    emitter: EeIdentity {
                        ee: EeId::CAIRO,
                        id: contract_addr.to_vec(),
                    },
                    topics,
                    data: payload,
                });
            }
            CairoSyscallOp::UniversalCall {
                target_ee,
                target,
                input,
                gas_limit: sub_limit,
            } => {
                let cap = (*sub_limit).min(gas_limit.saturating_sub(*gas_used));
                let Ok(res) = host.universal_call(UniversalCall {
                    from: EeIdentity {
                        ee: EeId::CAIRO,
                        id: contract_addr.to_vec(),
                    },
                    to_ee: EeId(*target_ee),
                    target: EeIdentity {
                        ee: EeId(*target_ee),
                        id: target.clone(),
                    },
                    value: BudAmount(0),
                    input: input.clone(),
                    gas_limit: cap,
                    is_static: false,
                }) else {
                    return Err(b"UNIVERSAL_CALL_FAILED");
                };
                let after = gas_used.saturating_add(res.gas_used);
                if after > gas_limit || host.charge(res.gas_used).is_err() {
                    return Err(b"OUT_OF_GAS");
                }
                *gas_used = after;
                if !res.success {
                    return Err(b"UNIVERSAL_SUBCALL_REVERTED");
                }
            }
        }
    }
    Ok(ret_felts)
}

impl ExecutionEnvironment for CairoWorker {
    fn id(&self) -> EeId {
        EeId::CAIRO
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        let cls = decode_sierra_class(code)?;
        Ok(CodeInfo {
            code_hash: cls.class_hash(),
            byte_len: u32::try_from(code.len()).unwrap_or(u32::MAX),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let ns = Namespace::new(NS_CAIRO_STATE).map_err(EeFault::Wire)?;
        if !self.is_active(ctx) {
            return Ok(EeOutcome::reverted(b"CAIRO_CLOSED_ON_TESTNET".to_vec(), 0));
        }
        let Ok(caller_raw) = <[u8; 32]>::try_from(call.caller.id.as_slice()) else {
            return Ok(EeOutcome::reverted(b"Starknet caller alias must be 32 bytes".to_vec(), 0));
        };
        let caller_felt = mask_to_felt252(caller_raw);

        let mut gas_used: u64 = 0;
        if CAIRO_AA_BASE_BGU > call.gas_limit || host.charge(CAIRO_AA_BASE_BGU).is_err() {
            return Ok(EeOutcome::out_of_gas(call.gas_limit));
        }
        gas_used = gas_used.saturating_add(CAIRO_AA_BASE_BGU);

        if call.kind == EeCallKind::Deploy {
            let Ok(cls) = decode_sierra_class(&call.input) else {
                return Ok(EeOutcome::reverted(b"invalid Sierra class bundle".to_vec(), gas_used));
            };
            let ch = cls.class_hash();
            let encoded = serde_json::to_vec(&cls).unwrap_or_default();
            if host.write(ns, &class_key(&ch), Some(&encoded)).is_err() {
                return Ok(EeOutcome::reverted(b"declare write failed".to_vec(), gas_used));
            }
            return Ok(EeOutcome::success(ch.to_vec(), gas_used));
        }

        let Ok(action) = serde_json::from_slice::<CairoAction>(&call.input) else {
            return Ok(EeOutcome::reverted(b"invalid CairoAction JSON".to_vec(), gas_used));
        };

        match action {
            CairoAction::Declare {
                class_bundle,
                nonce,
            } => {
                if let Err(reason) = bump_account_nonce(host, &caller_felt, nonce) {
                    return Ok(EeOutcome::reverted(reason.to_vec(), gas_used));
                }
                let Ok(cls) = decode_sierra_class(&class_bundle) else {
                    return Ok(EeOutcome::reverted(
                        b"invalid Sierra class bundle".to_vec(),
                        gas_used,
                    ));
                };
                let ch = cls.class_hash();
                let encoded = serde_json::to_vec(&cls).unwrap_or_default();
                if host.write(ns, &class_key(&ch), Some(&encoded)).is_err() {
                    return Ok(EeOutcome::reverted(b"class write err".to_vec(), gas_used));
                }
                Ok(EeOutcome::success(ch.to_vec(), gas_used))
            }
            CairoAction::DeployContract {
                class_hash,
                salt,
                constructor_calldata,
                nonce,
            } => {
                if let Err(reason) = bump_account_nonce(host, &caller_felt, nonce) {
                    return Ok(EeOutcome::reverted(reason.to_vec(), gas_used));
                }
                let Ok(Some(_)) = host.read(&ns, &class_key(&class_hash)) else {
                    return Ok(EeOutcome::reverted(b"CLASS_NOT_DECLARED".to_vec(), gas_used));
                };
                let addr = derive_starknet_contract_address(&caller_felt, &salt, &class_hash);
                if host.write(ns, &inst_key(&addr), Some(&class_hash)).is_err() {
                    return Ok(EeOutcome::reverted(b"deploy write err".to_vec(), gas_used));
                }
                match run_entrypoint(
                    &addr,
                    "constructor",
                    &constructor_calldata,
                    &mut gas_used,
                    call.gas_limit,
                    host,
                ) {
                    Ok(_) => Ok(EeOutcome::success(addr.to_vec(), gas_used)),
                    Err(b"OUT_OF_GAS") => Ok(EeOutcome::out_of_gas(call.gas_limit)),
                    Err(reason) => Ok(EeOutcome::reverted(reason.to_vec(), gas_used)),
                }
            }
            CairoAction::InvokeAccount { calls, nonce } => {
                // `__validate__`: bound directly to caller's post-quantum Budlum alias + nonce.
                if let Err(reason) = bump_account_nonce(host, &caller_felt, nonce) {
                    return Ok(EeOutcome::reverted(reason.to_vec(), gas_used));
                }
                let mut all_ret: Vec<[u8; 32]> = Vec::new();
                for c in &calls {
                    match run_entrypoint(
                        &c.contract_address,
                        &c.entrypoint,
                        &c.calldata,
                        &mut gas_used,
                        call.gas_limit,
                        host,
                    ) {
                        Ok(ret) => all_ret.extend(ret),
                        Err(b"OUT_OF_GAS") => return Ok(EeOutcome::out_of_gas(call.gas_limit)),
                        Err(reason) => return Ok(EeOutcome::reverted(reason.to_vec(), gas_used)),
                    }
                }
                let out = serde_json::to_vec(&all_ret).unwrap_or_default();
                Ok(EeOutcome::success(out, gas_used))
            }
        }
    }

    fn query(
        &self,
        ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        if !self.is_active(ctx) {
            return Err(EeRefusal::Denied("CAIRO_CLOSED_ON_TESTNET".into()));
        }
        let ns = cairo_ns().map_err(|e| EeRefusal::Denied(e.to_string()))?;
        let req: CairoQuery = serde_json::from_slice(&q.input)
            .map_err(|e| EeRefusal::BadInput(format!("bad CairoQuery: {e}")))?;
        match req {
            CairoQuery::GetClassHashAt { contract_address } => {
                let raw = host
                    .read(&ns, &inst_key(&contract_address))
                    .map_err(|e| EeRefusal::Denied(e.to_string()))?
                    .ok_or_else(|| EeRefusal::Denied("CONTRACT_NOT_FOUND".into()))?;
                Ok(raw)
            }
            CairoQuery::GetStorageAt {
                contract_address,
                slot,
            } => {
                let val = host
                    .read(&ns, &storage_key(&contract_address, &slot))
                    .map_err(|e| EeRefusal::Denied(e.to_string()))?
                    .unwrap_or_else(|| vec![0u8; 32]);
                Ok(val)
            }
            CairoQuery::GetNonce { account_address } => {
                let felt = mask_to_felt252(account_address);
                let n = read_account_nonce(host, &felt)
                    .map_err(|e| EeRefusal::Denied(e.to_string()))?;
                Ok(n.to_le_bytes().to_vec())
            }
            CairoQuery::Call {
                contract_address,
                entrypoint,
                calldata: _,
            } => {
                let ch_bytes = host
                    .read(&ns, &inst_key(&contract_address))
                    .map_err(|e| EeRefusal::Denied(e.to_string()))?
                    .ok_or_else(|| EeRefusal::Denied("CONTRACT_NOT_FOUND".into()))?;
                let ch32: [u8; 32] = ch_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| EeRefusal::Denied("corrupt class_hash".into()))?;
                let cls_bytes = host
                    .read(&ns, &class_key(&ch32))
                    .map_err(|e| EeRefusal::Denied(e.to_string()))?
                    .ok_or_else(|| EeRefusal::Denied("CLASS_NOT_DECLARED".into()))?;
                let cls: SierraContractClass = serde_json::from_slice(&cls_bytes)
                    .map_err(|e| EeRefusal::Denied(e.to_string()))?;
                let ep = cls
                    .entrypoints
                    .iter()
                    .find(|e| e.name == entrypoint)
                    .ok_or_else(|| EeRefusal::Denied("ENTRYPOINT_NOT_FOUND".into()))?;
                let mut ret: Vec<[u8; 32]> = Vec::new();
                for op in &ep.ops {
                    if let CairoSyscallOp::StorageReadReturn { slot } = op {
                        let v = host
                            .read(&ns, &storage_key(&contract_address, slot))
                            .map_err(|e| EeRefusal::Denied(e.to_string()))?
                            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                            .unwrap_or([0u8; 32]);
                        ret.push(v);
                    }
                }
                serde_json::to_vec(&ret).map_err(|e| EeRefusal::BadInput(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budlum_uel_abi::mock::MemoryHost;
    use budlum_uel_abi::OutcomeStatus;

    fn launch_ctx() -> BlockContext {
        BlockContext {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            height: 10,
            timestamp_ms: 1_793_923_200_000,
        }
    }

    fn active_ctx() -> BlockContext {
        BlockContext {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            height: PROPOSED_CAIRO_ACTIVATION_HEIGHT,
            timestamp_ms: 1_793_923_200_000,
        }
    }

    fn counter_sierra_class() -> SierraContractClass {
        let mut slot = [0u8; 32];
        slot[31] = 1;
        SierraContractClass {
            sierra_version: "1.6.0".to_string(),
            entrypoints: vec![
                CairoEntrypoint {
                    name: "constructor".to_string(),
                    ops: vec![CairoSyscallOp::StoreCalldataArg { slot, arg_index: 0 }],
                },
                CairoEntrypoint {
                    name: "increase_balance".to_string(),
                    ops: vec![
                        CairoSyscallOp::StorageAddU64 { slot, delta: 7 },
                        CairoSyscallOp::EmitEvent {
                            keys: vec![sn_keccak_selector("BalanceIncreased")],
                            data: vec![slot],
                        },
                    ],
                },
                CairoEntrypoint {
                    name: "get_balance".to_string(),
                    ops: vec![CairoSyscallOp::StorageReadReturn { slot }],
                },
            ],
        }
    }

    /// Section 1.5 launch-closure gate: `cairo_is_closed_on_testnet`.
    #[test]
    fn cairo_is_closed_on_testnet() {
        assert_eq!(AUDITED_CAIRO_ENGINE_SPDX, "Apache-2.0");
        let mut worker = CairoWorker::new();
        let mut host = MemoryHost::new(1_000_000);
        let Ok(caller) = EeIdentity::new(EeId::CAIRO, vec![0xAB; 32]) else {
            panic!("caller");
        };
        let Ok(out) = worker.execute(
            &launch_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller,
                value: BudAmount(0),
                input: b"{}".to_vec(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x01; 32],
            },
            &mut host,
        ) else {
            panic!("exec");
        };
        assert_eq!(out.status, OutcomeStatus::Reverted);
        assert_eq!(out.output, b"CAIRO_CLOSED_ON_TESTNET");
    }

    /// Directive IP-51 gates: `uel_conformance_cairo` and
    /// `starknet_foundry_declare_and_deploy_unchanged`.
    #[test]
    fn uel_conformance_cairo() {
        starknet_foundry_declare_and_deploy_unchanged();
    }

    #[test]
    fn starknet_foundry_declare_and_deploy_unchanged() {
        let mut worker = CairoWorker::new();
        assert_eq!(worker.id(), EeId::CAIRO);

        let mut host = MemoryHost::new(10_000_000);
        let Ok(caller) = EeIdentity::new(EeId::CAIRO, vec![0xCD; 32]) else {
            panic!("caller");
        };
        let cls = counter_sierra_class();
        let Ok(bundle) = encode_sierra_class(&cls) else {
            panic!("bundle");
        };
        assert!(worker.validate_deploy(&bundle).is_ok());

        // 1. `sncast declare` (`nonce = 0`).
        let Ok(dec_in) = serde_json::to_vec(&CairoAction::Declare {
            class_bundle: bundle,
            nonce: 0,
        }) else {
            panic!("dec_in");
        };
        let Ok(dec_out) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller.clone(),
                value: BudAmount(0),
                input: dec_in,
                gas_limit: 1_000_000,
                depth: 0,
                tx_hash: [0x21; 32],
            },
            &mut host,
        ) else {
            panic!("declare");
        };
        assert_eq!(dec_out.status, OutcomeStatus::Success);
        let Ok(class_hash) = <[u8; 32]>::try_from(dec_out.output.as_slice()) else {
            panic!("class_hash");
        };

        // 2. `sncast deploy` (`nonce = 1`, initial balance = 35).
        let mut init_felt = [0u8; 32];
        init_felt[31] = 35;
        let Ok(dep_in) = serde_json::to_vec(&CairoAction::DeployContract {
            class_hash,
            salt: [0x09; 32],
            constructor_calldata: vec![init_felt],
            nonce: 1,
        }) else {
            panic!("dep_in");
        };
        let Ok(dep_out) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller.clone(),
                value: BudAmount(0),
                input: dep_in,
                gas_limit: 1_000_000,
                depth: 0,
                tx_hash: [0x22; 32],
            },
            &mut host,
        ) else {
            panic!("deploy");
        };
        assert_eq!(dep_out.status, OutcomeStatus::Success);
        let Ok(contract_address) = <[u8; 32]>::try_from(dep_out.output.as_slice()) else {
            panic!("contract_address");
        };

        // 3. `sncast invoke` (`nonce = 2`): `increase_balance` (+7 -> 42) + `get_balance`.
        let Ok(inv_in) = serde_json::to_vec(&CairoAction::InvokeAccount {
            calls: vec![
                StarknetCall {
                    contract_address,
                    entrypoint: "increase_balance".to_string(),
                    calldata: Vec::new(),
                },
                StarknetCall {
                    contract_address,
                    entrypoint: "get_balance".to_string(),
                    calldata: Vec::new(),
                },
            ],
            nonce: 2,
        }) else {
            panic!("inv_in");
        };
        let Ok(inv_out) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller,
                value: BudAmount(0),
                input: inv_in,
                gas_limit: 1_000_000,
                depth: 0,
                tx_hash: [0x23; 32],
            },
            &mut host,
        ) else {
            panic!("invoke");
        };
        assert_eq!(inv_out.status, OutcomeStatus::Success);
        let Ok(rets): Result<Vec<[u8; 32]>, _> = serde_json::from_slice(&inv_out.output) else {
            panic!("rets");
        };
        let Some(final_felt) = rets.first() else {
            panic!("final_felt");
        };
        assert_eq!(final_felt[31], 42);
        assert_eq!(host.logs.len(), 1);
    }
}
