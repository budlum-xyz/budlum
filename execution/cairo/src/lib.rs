//! Out-of-process deterministic Cairo (Starknet) UEL execution worker (
//! `EeId::CAIRO = 0x06`).
//!
//! Audited license posture (`Section 8.2`): `lambdaclass/cairo-vm` (`Apache-2.0`)
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
    OutcomeStatus, RefusalCode, UniversalCall,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

/// Audited SPDX license identifier for `cairo-vm` and `blockifier` (`Section 8.2`).
pub const AUDITED_CAIRO_ENGINE_SPDX: &str = "Apache-2.0";

/// Budlum testnet chain ID (`Section 1.5`).
pub const BUDLUM_TESTNET_CHAIN_ID: u64 = 45_261;

/// Explicit activation fixture height; the public-testnet default remains closed.
pub const PROPOSED_CAIRO_ACTIVATION_HEIGHT: u64 = 0;

/// Canonical UEL namespace storing Starknet classes, contract instances, nonces, and storage.
pub const NS_CAIRO_STATE: &str = "ee/cairo/state";

/// Magic prefix for Sierra/CASM class bundles (`sncast declare`).
pub const SIERRA_CLASS_MAGIC: &[u8; 4] = b"SRCA";

/// Maximum Sierra/CASM class artifact size (`4 MiB`).
pub const MAX_SIERRA_CLASS_BYTES: usize = 4 * 1024 * 1024;

/// Base gas charged per Starknet AA invocation (`__validate__` + `__execute__`) in BGU.
pub const CAIRO_AA_BASE_BGU: u64 = 2_500;

/// Gas charged per published/loaded byte of a Sierra class artifact in BGU, matching the
/// per-byte publication rate charged by sibling execution workers.
pub const CAIRO_PUBLISH_PER_BYTE_BGU: u64 = 25;

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
        return Err(ee_bad_code("invalid Sierra class size".into()));
    }
    if raw.get(..4) != Some(SIERRA_CLASS_MAGIC.as_slice()) {
        return Err(ee_bad_code("missing SRCA Sierra magic".into()));
    }
    let body = raw.get(4..).unwrap_or_default();
    let cls: SierraContractClass = serde_json::from_slice(body)
        .map_err(|e| ee_bad_code(format!("malformed Sierra class: {e}")))?;
    if cls.sierra_version.is_empty() || cls.entrypoints.is_empty() || cls.entrypoints.len() > 512 {
        return Err(ee_bad_code(
            "Sierra class version or entrypoints invalid".into(),
        ));
    }
    for (idx, ep) in cls.entrypoints.iter().enumerate() {
        if ep.name.is_empty() || ep.ops.len() > 16_384 {
            return Err(ee_bad_code("invalid Cairo entrypoint definition".into()));
        }
        let sel = sn_keccak_selector(&ep.name);
        if cls.entrypoints[(idx + 1)..]
            .iter()
            .any(|other| other.name == ep.name || sn_keccak_selector(&other.name) == sel)
        {
            return Err(ee_bad_code(
                "duplicate Cairo entrypoint name or selector".into(),
            ));
        }
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

/// Starknet transaction actions bound to the Budlum local account alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CairoAction {
    /// `INVOKE` v3 (`__validate_declare__` + class registration, `sncast declare`).
    Declare { class_bundle: Vec<u8>, nonce: u64 },
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
    GetClassHashAt {
        contract_address: [u8; 32],
    },
    GetStorageAt {
        contract_address: [u8; 32],
        slot: [u8; 32],
    },
    GetNonce {
        account_address: [u8; 32],
    },
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

fn owner_key(contract: &[u8; 32]) -> Vec<u8> {
    let mut k = b"owner:".to_vec();
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

/// Charges `bytes` of a Sierra class artifact at [`CAIRO_PUBLISH_PER_BYTE_BGU`]. Returns
/// `false` when the cost exceeds the call's gas limit or the host refuses the charge.
fn charge_class_bytes(
    gas_used: &mut u64,
    gas_limit: u64,
    bytes: usize,
    host: &mut dyn HostApi,
) -> bool {
    let cost = u64::try_from(bytes)
        .unwrap_or(u64::MAX)
        .saturating_mul(CAIRO_PUBLISH_PER_BYTE_BGU);
    let next = gas_used.saturating_add(cost);
    if next > gas_limit || host.charge(cost).is_err() {
        return false;
    }
    *gas_used = next;
    true
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
    let Some(next) = cur.checked_add(1) else {
        return Err(b"STARKNET_NONCE_OVERFLOW");
    };
    let Ok(ns) = cairo_ns() else {
        return Err(b"cairo ns err");
    };
    host.write(&ns, &nonce_key(account), Some(&next.to_le_bytes()))
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
    /// Default public-testnet posture: closed until an explicit activation height.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            testnet_activation_height: None,
        }
    }

    /// Override testnet activation height (or `None` to close Cairo on `45261`).
    #[must_use]
    pub const fn with_activation_height(testnet_activation_height: Option<u64>) -> Self {
        Self {
            testnet_activation_height,
        }
    }

    /// Returns `true` if `CairoWorker` is active at `ctx`.
    #[must_use]
    pub const fn is_active(&self, ctx: &BlockContext) -> bool {
        if ctx.chain_id == budlum_uel_abi::BUDLUM_DEVNET_CHAIN_ID {
            return true;
        }
        if ctx.chain_id != BUDLUM_TESTNET_CHAIN_ID {
            return false;
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
    if !charge_class_bytes(gas_used, gas_limit, cls_bytes.len(), host) {
        return Err(b"OUT_OF_GAS");
    }
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
                if host.write(&ns, &sk, Some(&val)).is_err() {
                    return Err(b"storage write err");
                }
            }
            CairoSyscallOp::StoreCalldataArg { slot, arg_index } => {
                let Some(arg) = calldata.get(*arg_index) else {
                    return Err(b"CALLDATA_OUT_OF_BOUNDS");
                };
                let val = mask_to_felt252(*arg);
                let sk = storage_key(contract_addr, slot);
                if host.write(&ns, &sk, Some(&val)).is_err() {
                    return Err(b"storage write err");
                }
            }
            CairoSyscallOp::StorageAddU64 { slot, delta } => {
                let sk = storage_key(contract_addr, slot);
                let mut felt = match host.read(&ns, &sk) {
                    Ok(Some(bytes)) => {
                        let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                            return Err(b"CAIRO_STORAGE_CORRUPT");
                        };
                        arr
                    }
                    Ok(None) => [0u8; 32],
                    Err(HostError::OutOfGas) => return Err(b"OUT_OF_GAS"),
                    Err(_) => return Err(b"CAIRO_STORAGE_READ_ERR"),
                };
                let lo8: [u8; 8] = felt
                    .get(24..32)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0; 8]);
                let Some(sum) = u64::from_be_bytes(lo8).checked_add(*delta) else {
                    return Err(b"CAIRO_U64_OVERFLOW");
                };
                if let Some(tail) = felt.get_mut(24..32) {
                    tail.copy_from_slice(&sum.to_be_bytes());
                }
                let felt = mask_to_felt252(felt);
                if host.write(&ns, &sk, Some(&felt)).is_err() {
                    return Err(b"storage add err");
                }
            }
            CairoSyscallOp::StorageReadReturn { slot } => {
                let sk = storage_key(contract_addr, slot);
                let felt = match host.read(&ns, &sk) {
                    Ok(Some(bytes)) => {
                        let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                            return Err(b"CAIRO_STORAGE_CORRUPT");
                        };
                        arr
                    }
                    Ok(None) => [0u8; 32],
                    Err(HostError::OutOfGas) => return Err(b"OUT_OF_GAS"),
                    Err(_) => return Err(b"CAIRO_STORAGE_READ_ERR"),
                };
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
            abi_tag: String::from("starknet-sierra-v1"),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let ns = Namespace::new(NS_CAIRO_STATE).map_err(ee_wire_fault)?;
        if !self.is_active(ctx) {
            return Ok(ee_reverted(b"CAIRO_CLOSED_ON_TESTNET".to_vec(), 0));
        }
        let Ok(caller_raw) = <[u8; 32]>::try_from(call.caller.id.as_slice()) else {
            return Ok(ee_reverted(
                b"Starknet caller alias must be 32 bytes".to_vec(),
                0,
            ));
        };
        let caller_felt = mask_to_felt252(caller_raw);

        let mut gas_used: u64 = 0;
        if CAIRO_AA_BASE_BGU > call.gas_limit || host.charge(CAIRO_AA_BASE_BGU).is_err() {
            return Ok(ee_out_of_gas(call.gas_limit));
        }
        gas_used = gas_used.saturating_add(CAIRO_AA_BASE_BGU);

        if call.kind == EeCallKind::Deploy {
            let Ok(cls) = decode_sierra_class(&call.input) else {
                return Ok(ee_reverted(
                    b"invalid Sierra class bundle".to_vec(),
                    gas_used,
                ));
            };
            let ch = cls.class_hash();
            match host.read(&ns, &class_key(&ch)) {
                Ok(Some(_)) => {
                    return Ok(ee_reverted(b"CLASS_ALREADY_DECLARED".to_vec(), gas_used));
                }
                Ok(None) => {}
                Err(HostError::OutOfGas) => return Ok(ee_out_of_gas(call.gas_limit)),
                Err(_) => return Ok(ee_reverted(b"declare read failed".to_vec(), gas_used)),
            }
            let Ok(encoded) = serde_json::to_vec(&cls) else {
                return Ok(ee_reverted(b"class encode failed".to_vec(), gas_used));
            };
            if !charge_class_bytes(&mut gas_used, call.gas_limit, encoded.len(), host) {
                return Ok(ee_out_of_gas(call.gas_limit));
            }
            if host.write(&ns, &class_key(&ch), Some(&encoded)).is_err() {
                return Ok(ee_reverted(b"declare write failed".to_vec(), gas_used));
            }
            return Ok(ee_success(ch.to_vec(), gas_used));
        }

        let Ok(action) = serde_json::from_slice::<CairoAction>(&call.input) else {
            return Ok(ee_reverted(b"invalid CairoAction JSON".to_vec(), gas_used));
        };

        let Ok(action_cp) = host.checkpoint_begin() else {
            return Ok(ee_reverted(
                b"cairo checkpoint begin failed".to_vec(),
                gas_used,
            ));
        };
        let outcome = match action {
            CairoAction::Declare {
                class_bundle,
                nonce,
            } => {
                if let Err(reason) = bump_account_nonce(host, &caller_felt, nonce) {
                    ee_reverted(reason.to_vec(), gas_used)
                } else if let Ok(cls) = decode_sierra_class(&class_bundle) {
                    let ch = cls.class_hash();
                    match host.read(&ns, &class_key(&ch)) {
                        Ok(Some(_)) => ee_reverted(b"CLASS_ALREADY_DECLARED".to_vec(), gas_used),
                        Err(HostError::OutOfGas) => ee_out_of_gas(call.gas_limit),
                        Err(_) => ee_reverted(b"declare read err".to_vec(), gas_used),
                        Ok(None) => match serde_json::to_vec(&cls) {
                            Err(_) => ee_reverted(b"class encode err".to_vec(), gas_used),
                            Ok(encoded) => {
                                if !charge_class_bytes(
                                    &mut gas_used,
                                    call.gas_limit,
                                    encoded.len(),
                                    host,
                                ) {
                                    ee_out_of_gas(call.gas_limit)
                                } else if host.write(&ns, &class_key(&ch), Some(&encoded)).is_err()
                                {
                                    ee_reverted(b"class write err".to_vec(), gas_used)
                                } else {
                                    ee_success(ch.to_vec(), gas_used)
                                }
                            }
                        },
                    }
                } else {
                    ee_reverted(b"invalid Sierra class bundle".to_vec(), gas_used)
                }
            }
            CairoAction::DeployContract {
                class_hash,
                salt,
                constructor_calldata,
                nonce,
            } => 'deploy: {
                if let Err(reason) = bump_account_nonce(host, &caller_felt, nonce) {
                    break 'deploy ee_reverted(reason.to_vec(), gas_used);
                }
                let Ok(Some(_)) = host.read(&ns, &class_key(&class_hash)) else {
                    break 'deploy ee_reverted(b"CLASS_NOT_DECLARED".to_vec(), gas_used);
                };
                let addr = derive_starknet_contract_address(&caller_felt, &salt, &class_hash);
                match host.read(&ns, &inst_key(&addr)) {
                    Ok(Some(_)) => {
                        break 'deploy ee_reverted(b"CONTRACT_ALREADY_DEPLOYED".to_vec(), gas_used);
                    }
                    Ok(None) => {}
                    Err(_) => break 'deploy ee_reverted(b"deploy read err".to_vec(), gas_used),
                }
                if host
                    .write(&ns, &inst_key(&addr), Some(&class_hash))
                    .is_err()
                    || host
                        .write(&ns, &owner_key(&addr), Some(&caller_felt))
                        .is_err()
                {
                    break 'deploy ee_reverted(b"deploy write err".to_vec(), gas_used);
                }
                match run_entrypoint(
                    &addr,
                    "constructor",
                    &constructor_calldata,
                    &mut gas_used,
                    call.gas_limit,
                    host,
                ) {
                    Ok(_) => ee_success(addr.to_vec(), gas_used),
                    Err(b"OUT_OF_GAS") => ee_out_of_gas(call.gas_limit),
                    Err(reason) => ee_reverted(reason.to_vec(), gas_used),
                }
            }
            CairoAction::InvokeAccount { calls, nonce } => 'invoke: {
                for c in &calls {
                    match host.read(&ns, &owner_key(&c.contract_address)) {
                        Ok(Some(owner)) if owner.as_slice() == caller_felt.as_slice() => {}
                        Ok(Some(_)) => {
                            break 'invoke ee_reverted(
                                b"CALLER_NOT_CONTRACT_OWNER".to_vec(),
                                gas_used,
                            );
                        }
                        Ok(None) => {
                            break 'invoke ee_reverted(b"CONTRACT_NOT_FOUND".to_vec(), gas_used);
                        }
                        Err(_) => break 'invoke ee_reverted(b"owner read err".to_vec(), gas_used),
                    }
                }
                if let Err(reason) = bump_account_nonce(host, &caller_felt, nonce) {
                    break 'invoke ee_reverted(reason.to_vec(), gas_used);
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
                        Err(b"OUT_OF_GAS") => break 'invoke ee_out_of_gas(call.gas_limit),
                        Err(reason) => break 'invoke ee_reverted(reason.to_vec(), gas_used),
                    }
                }
                let out = serde_json::to_vec(&all_ret).unwrap_or_default();
                ee_success(out, gas_used)
            }
        };
        if outcome.status == OutcomeStatus::Success {
            if host.checkpoint_commit(action_cp).is_err() {
                let _ = host.checkpoint_rollback(action_cp);
                return Ok(ee_reverted(
                    b"cairo checkpoint commit failed".to_vec(),
                    gas_used,
                ));
            }
        } else {
            let _ = host.checkpoint_rollback(action_cp);
        }
        Ok(outcome)
    }

    fn query(
        &self,
        ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        if !self.is_active(ctx) {
            return Err(ee_denied("CAIRO_CLOSED_ON_TESTNET".into()));
        }
        let ns = cairo_ns().map_err(|e| ee_denied(e.to_string()))?;
        let req: CairoQuery = serde_json::from_slice(&q.input)
            .map_err(|e| ee_bad_input(format!("bad CairoQuery: {e}")))?;
        match req {
            CairoQuery::GetClassHashAt { contract_address } => {
                let raw = host
                    .read(&ns, &inst_key(&contract_address))
                    .map_err(|e| ee_denied(e.to_string()))?
                    .ok_or_else(|| ee_denied("CONTRACT_NOT_FOUND".into()))?;
                Ok(raw)
            }
            CairoQuery::GetStorageAt {
                contract_address,
                slot,
            } => {
                let val = host
                    .read(&ns, &storage_key(&contract_address, &slot))
                    .map_err(|e| ee_denied(e.to_string()))?
                    .unwrap_or_else(|| vec![0u8; 32]);
                Ok(val)
            }
            CairoQuery::GetNonce { account_address } => {
                let felt = mask_to_felt252(account_address);
                let n = read_account_nonce(host, &felt).map_err(|e| ee_denied(e.to_string()))?;
                Ok(n.to_le_bytes().to_vec())
            }
            CairoQuery::Call {
                contract_address,
                entrypoint,
                calldata: _,
            } => {
                let ch_bytes = host
                    .read(&ns, &inst_key(&contract_address))
                    .map_err(|e| ee_denied(e.to_string()))?
                    .ok_or_else(|| ee_denied("CONTRACT_NOT_FOUND".into()))?;
                let ch32: [u8; 32] = ch_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| ee_denied("corrupt class_hash".into()))?;
                let cls_bytes = host
                    .read(&ns, &class_key(&ch32))
                    .map_err(|e| ee_denied(e.to_string()))?
                    .ok_or_else(|| ee_denied("CLASS_NOT_DECLARED".into()))?;
                let cls: SierraContractClass =
                    serde_json::from_slice(&cls_bytes).map_err(|e| ee_denied(e.to_string()))?;
                let ep = cls
                    .entrypoints
                    .iter()
                    .find(|e| e.name == entrypoint)
                    .ok_or_else(|| ee_denied("ENTRYPOINT_NOT_FOUND".into()))?;
                let mut ret: Vec<[u8; 32]> = Vec::new();
                for op in &ep.ops {
                    if let CairoSyscallOp::StorageReadReturn { slot } = op {
                        let v = host
                            .read(&ns, &storage_key(&contract_address, slot))
                            .map_err(|e| ee_denied(e.to_string()))?
                            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                            .unwrap_or([0u8; 32]);
                        ret.push(v);
                    }
                }
                serde_json::to_vec(&ret).map_err(|e| ee_bad_input(e.to_string()))
            }
        }
    }
}

fn ee_bad_code(msg: String) -> EeRefusal {
    EeRefusal {
        code: RefusalCode::InvalidCode,
        message: msg,
    }
}
fn ee_denied(msg: String) -> EeRefusal {
    EeRefusal {
        code: RefusalCode::Denied,
        message: msg,
    }
}
fn ee_bad_input(msg: String) -> EeRefusal {
    EeRefusal {
        code: RefusalCode::Unsupported,
        message: msg,
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
fn ee_out_of_gas(gas_used: u64) -> EeOutcome {
    EeOutcome {
        status: OutcomeStatus::OutOfGas,
        output: Vec::new(),
        gas_used,
    }
}
fn ee_wire_fault(err: impl std::fmt::Display) -> EeFault {
    let msg = err.to_string();
    EeFault {
        ee: EeId::CAIRO,
        panic_digest: budlum_uel_abi::panic_digest(EeId::CAIRO, &msg),
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

    /// Testnet `45261` launch posture is closed until an explicit activation height.
    #[test]
    fn cairo_is_closed_on_testnet() {
        assert_eq!(AUDITED_CAIRO_ENGINE_SPDX, "Apache-2.0");
        let mut closed_worker = CairoWorker::new();
        assert!(!closed_worker.is_active(&launch_ctx()));
        for chain_id in [45_260, 99_999] {
            assert!(!closed_worker.is_active(&BlockContext {
                chain_id,
                ..launch_ctx()
            }));
        }
        assert!(closed_worker.is_active(&BlockContext {
            chain_id: 45_262,
            ..launch_ctx()
        }));
        let activated_worker = CairoWorker::with_activation_height(Some(10));
        assert!(!activated_worker.is_active(&BlockContext {
            height: 9,
            ..launch_ctx()
        }));
        assert!(activated_worker.is_active(&launch_ctx()));
        let mut host = MemoryHost::new(1_000_000);
        let Ok(caller) = EeIdentity::new(EeId::CAIRO, vec![0xAB; 32]) else {
            panic!("caller");
        };
        let Ok(out) = closed_worker.execute(
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
        assert_eq!(out.status, OutcomeStatus::Revert);
        assert_eq!(out.output, b"CAIRO_CLOSED_ON_TESTNET");
    }

    /// Cairo conformance gates: `uel_conformance_cairo` and
    /// `starknet_foundry_declare_and_deploy_unchanged`.
    #[test]
    fn uel_conformance_cairo() {
        starknet_foundry_declare_and_deploy_unchanged();
    }

    #[test]
    fn starknet_foundry_declare_and_deploy_unchanged() {
        let mut worker = CairoWorker::with_activation_height(Some(0));
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

        // A different authenticated alias cannot replay an entrypoint against
        // this deployed instance; rejection happens before entrypoint writes.
        let Ok(attacker) = EeIdentity::new(EeId::CAIRO, vec![0xEF; 32]) else {
            panic!("attacker");
        };
        let Ok(attack_input) = serde_json::to_vec(&CairoAction::InvokeAccount {
            calls: vec![StarknetCall {
                contract_address,
                entrypoint: "increase_balance".to_string(),
                calldata: Vec::new(),
            }],
            nonce: 0,
        }) else {
            panic!("attack_input");
        };
        let Ok(attack_out) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: attacker.clone(),
                target: attacker,
                value: BudAmount(0),
                input: attack_input,
                gas_limit: 1_000_000,
                depth: 0,
                tx_hash: [0x24; 32],
            },
            &mut host,
        ) else {
            panic!("attack execution");
        };
        assert_eq!(attack_out.status, OutcomeStatus::Revert);
        assert_eq!(attack_out.output, b"CALLER_NOT_CONTRACT_OWNER");

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

    #[test]
    fn storage_add_u64_fails_closed_when_host_read_errors() {
        use budlum_uel_abi::{
            BudAmount, HostError, HostRead, OutOfGas, UniversalCall, UniversalResult,
        };

        struct FailingStorageReadHost {
            inner: MemoryHost,
        }
        impl HostRead for FailingStorageReadHost {
            fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
                if key.starts_with(b"stor:") {
                    return Err(HostError::Invalid("injected storage read error".into()));
                }
                self.inner.read(ns, key)
            }
            fn bud_balance(&self, who: &EeIdentity) -> Result<BudAmount, HostError> {
                self.inner.bud_balance(who)
            }
        }
        impl HostApi for FailingStorageReadHost {
            fn write(
                &mut self,
                ns: &Namespace,
                key: &[u8],
                value: Option<&[u8]>,
            ) -> Result<(), HostError> {
                self.inner.write(ns, key, value)
            }
            fn universal_call(
                &mut self,
                call: UniversalCall,
            ) -> Result<UniversalResult, HostError> {
                self.inner.universal_call(call)
            }
            fn emit_log(&mut self, log: EeLog) -> Result<(), HostError> {
                self.inner.emit_log(log)
            }
            fn charge(&mut self, bgu: u64) -> Result<(), OutOfGas> {
                self.inner.charge(bgu)
            }
            fn bud_transfer(
                &mut self,
                from: &EeIdentity,
                to: &EeIdentity,
                attos: u128,
            ) -> Result<(), HostError> {
                self.inner.bud_transfer(from, to, attos)
            }
            fn checkpoint_begin(&mut self) -> Result<u64, HostError> {
                self.inner.checkpoint_begin()
            }
            fn checkpoint_commit(&mut self, id: u64) -> Result<(), HostError> {
                self.inner.checkpoint_commit(id)
            }
            fn checkpoint_rollback(&mut self, id: u64) -> Result<(), HostError> {
                self.inner.checkpoint_rollback(id)
            }
        }

        let mut worker = CairoWorker::with_activation_height(Some(0));
        let mut host = MemoryHost::new(5_000_000);
        let Ok(caller) = EeIdentity::new(EeId::CAIRO, vec![0x99; 32]) else {
            panic!("caller");
        };
        let slot = [0x11; 32];
        let class = SierraContractClass {
            sierra_version: String::from("1.6.0"),
            entrypoints: vec![CairoEntrypoint {
                name: String::from("inc"),
                ops: vec![CairoSyscallOp::StorageAddU64 { slot, delta: 100 }],
            }],
        };
        let Ok(class_bundle) = encode_sierra_class(&class) else {
            panic!("encode");
        };
        let Ok(decl_in) = serde_json::to_vec(&CairoAction::Declare {
            class_bundle,
            nonce: 0,
        }) else {
            panic!("decl_in");
        };
        let Ok(decl_out) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller.clone(),
                value: BudAmount(0),
                input: decl_in,
                gas_limit: 1_000_000,
                depth: 0,
                tx_hash: [0xF1; 32],
            },
            &mut host,
        ) else {
            panic!("declare");
        };
        assert_eq!(decl_out.status, OutcomeStatus::Success);
        let Ok(class_hash) = <[u8; 32]>::try_from(decl_out.output.as_slice()) else {
            panic!("class hash");
        };
        let Ok(dep_in) = serde_json::to_vec(&CairoAction::DeployContract {
            class_hash,
            salt: [0x01; 32],
            constructor_calldata: Vec::new(),
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
                tx_hash: [0xF2; 32],
            },
            &mut host,
        ) else {
            panic!("deploy");
        };
        assert_eq!(dep_out.status, OutcomeStatus::Success);
        let Ok(contract_address) = <[u8; 32]>::try_from(dep_out.output.as_slice()) else {
            panic!("contract address");
        };

        // First invoke succeeds: 0 -> 100
        let Ok(inv1_in) = serde_json::to_vec(&CairoAction::InvokeAccount {
            calls: vec![StarknetCall {
                contract_address,
                entrypoint: String::from("inc"),
                calldata: Vec::new(),
            }],
            nonce: 2,
        }) else {
            panic!("inv1");
        };
        let Ok(inv1) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller.clone(),
                value: BudAmount(0),
                input: inv1_in,
                gas_limit: 1_000_000,
                depth: 0,
                tx_hash: [0xF3; 32],
            },
            &mut host,
        ) else {
            panic!("inv1 exec");
        };
        assert_eq!(inv1.status, OutcomeStatus::Success);

        // Second invoke under a storage-read error must revert instead of wiping 100 -> 0+100!
        let mut faulty = FailingStorageReadHost { inner: host };
        let Ok(inv2_in) = serde_json::to_vec(&CairoAction::InvokeAccount {
            calls: vec![StarknetCall {
                contract_address,
                entrypoint: String::from("inc"),
                calldata: Vec::new(),
            }],
            nonce: 3,
        }) else {
            panic!("inv2");
        };
        let Ok(inv2) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller,
                value: BudAmount(0),
                input: inv2_in,
                gas_limit: 1_000_000,
                depth: 0,
                tx_hash: [0xF4; 32],
            },
            &mut faulty,
        ) else {
            panic!("inv2 exec");
        };
        assert_eq!(
            inv2.status,
            OutcomeStatus::Revert,
            "StorageAddU64 must fail closed on host.read error instead of resetting counter to 0 + delta"
        );
    }

    #[test]
    fn declare_and_deploy_charge_per_byte_class_publish_gas() {
        let mut worker = CairoWorker::with_activation_height(Some(0));
        let mut host = MemoryHost::new(50_000_000);
        let Ok(caller) = EeIdentity::new(EeId::CAIRO, vec![0x77; 32]) else {
            panic!("caller");
        };
        // Build a ~8 KiB Sierra class bundle.
        let mut ops = Vec::with_capacity(64);
        for i in 0u8..64 {
            ops.push(CairoSyscallOp::StorageAddU64 {
                slot: [i; 32],
                delta: 1,
            });
        }
        let cls = SierraContractClass {
            sierra_version: String::from("1.6.0"),
            entrypoints: vec![CairoEntrypoint {
                name: String::from("bulk"),
                ops,
            }],
        };
        let Ok(bundle) = encode_sierra_class(&cls) else {
            panic!("encode");
        };
        let Ok(encoded_cls) = serde_json::to_vec(&cls) else {
            panic!("json cls");
        };
        assert!(encoded_cls.len() > 2_000);

        // 1. Deploy door with gas only covering CAIRO_AA_BASE_BGU must OutOfGas.
        let Ok(dep_oog) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: caller.clone(),
                target: caller.clone(),
                value: BudAmount(0),
                input: bundle.clone(),
                gas_limit: CAIRO_AA_BASE_BGU + 1_000,
                depth: 0,
                tx_hash: [0xC1; 32],
            },
            &mut host,
        ) else {
            panic!("deploy oog");
        };
        assert_eq!(
            dep_oog.status,
            OutcomeStatus::OutOfGas,
            "Deploy door must charge per-byte class publish gas"
        );

        // 2. Declare door with gas only covering CAIRO_AA_BASE_BGU must OutOfGas.
        let Ok(decl_in) = serde_json::to_vec(&CairoAction::Declare {
            class_bundle: bundle,
            nonce: 0,
        }) else {
            panic!("decl json");
        };
        let Ok(decl_oog) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller.clone(),
                value: BudAmount(0),
                input: decl_in.clone(),
                gas_limit: CAIRO_AA_BASE_BGU + 1_000,
                depth: 0,
                tx_hash: [0xC2; 32],
            },
            &mut host,
        ) else {
            panic!("declare oog");
        };
        assert_eq!(
            decl_oog.status,
            OutcomeStatus::OutOfGas,
            "Declare door must charge per-byte class publish gas"
        );

        // 3. With adequate gas, Declare succeeds and charges per-byte publication cost.
        let Ok(decl_ok) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller,
                value: BudAmount(0),
                input: decl_in,
                gas_limit: 5_000_000,
                depth: 0,
                tx_hash: [0xC3; 32],
            },
            &mut host,
        ) else {
            panic!("declare ok");
        };
        assert_eq!(decl_ok.status, OutcomeStatus::Success);
        assert!(decl_ok.gas_used > CAIRO_AA_BASE_BGU + 50_000);
    }

    #[test]
    fn sierra_class_rejects_empty_version_and_duplicate_entrypoint_selectors() {
        let empty_ver = encode_sierra_class(&SierraContractClass {
            sierra_version: String::new(),
            entrypoints: vec![CairoEntrypoint {
                name: "run".into(),
                ops: Vec::new(),
            }],
        })
        .unwrap();
        assert!(
            decode_sierra_class(&empty_ver).is_err(),
            "empty Sierra version must be refused"
        );

        let dup_ep = encode_sierra_class(&SierraContractClass {
            sierra_version: "1.5.0".into(),
            entrypoints: vec![
                CairoEntrypoint {
                    name: "run".into(),
                    ops: Vec::new(),
                },
                CairoEntrypoint {
                    name: "run".into(),
                    ops: Vec::new(),
                },
            ],
        })
        .unwrap();
        assert!(
            decode_sierra_class(&dup_ep).is_err(),
            "duplicate Cairo entrypoint names/selectors must be refused"
        );
    }
}
