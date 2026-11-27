//! Move (Aptos) execution environment (`EeId::MOVE` = `0x04`) over `HostApi`.
//!
//! Implements  items 1, 3, & 6:
//! - Strictly sequential Move execution (`block_stm_parallel = false`).
//! - Move state persisted in `ee/move/state` keyed by canonical `StateKey` bytes.
//! - Framework subset: `0x1::aptos_account`, `0x1::coin`, `0x1::fungible_asset`,
//!   `0x1::randomness` (domain-separated length-prefixed hash over `BlockContext`,
//!   `EeCall::tx_hash`, `EeCall::depth`, `signer`, `target`, `function_name`, and `args`),
//!   and native `0x1::budlum_universal::call` (`1 octa = 10^10 attoBUD`).
//! - Aptos staking and governance modules are explicitly refused (section 8.15).
//!
//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.

use crate::core::hash::hash_fields_bytes;
use crate::execution::coordinator::assets::{
    is_pointer_bytecode_prefixed, resolve_pointer_party_for_home,
    verify_canonical_pointer_bytecode, MovePointerFlavor, MovePointerOp, PointerDescriptor,
    SplPointerOp,
};
use crate::execution::coordinator::evm_ee::solidity_selector;
use crate::execution::coordinator::state::NS_MOVE_STATE;
use crate::execution::coordinator::universal_call::{
    unwrap_static_universal_input, wrap_static_universal_input,
};
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, Namespace,
    OutcomeStatus, RefusalCode, UniversalCall,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Move binary module magic (`0xa11ceb0b` little-endian `[0xa1, 0x1c, 0xeb, 0x0b]`).
pub const MOVE_BINARY_MAGIC: [u8; 4] = [0xa1, 0x1c, 0xeb, 0x0b];
/// Maximum Move module bundle size (256 KiB).
pub const MAX_MOVE_BUNDLE_BYTES: usize = 256 * 1024;
/// Conversion factor from Aptos Move gas units to BGU (`1 Move unit = 100 BGU`, 8.9.3).
pub const BGU_PER_MOVE_GAS_UNIT: u64 = 100;
/// Number of attoBUD per Aptos octa (`10^10`, section 8.5).
pub const ATTOS_PER_OCTA: u128 = 10_000_000_000;

/// Forbidden Aptos staking and governance modules refused on Budlum (section 8.15).
pub const FORBIDDEN_MOVE_MODULES: &[&str] = &[
    "0x1::stake",
    "0x1::staking_contract",
    "0x1::staking_config",
    "0x1::delegation_pool",
    "0x1::aptos_governance",
    "0x1::voting",
];

/// Runtime configuration for `budlum-ee-move` (Block-STM parallel engine disabled).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveRuntimeConfig {
    pub block_stm_parallel: bool,
    pub max_value_nest_depth: usize,
}

impl Default for MoveRuntimeConfig {
    fn default() -> Self {
        Self {
            block_stm_parallel: false,
            max_value_nest_depth: 128,
        }
    }
}

impl MoveRuntimeConfig {
    /// Verifies Block-STM parallel execution is disabled ( item 1).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn ensure_sequential(&self) -> Result<(), String> {
        if self.block_stm_parallel {
            return Err(String::from(
                "Move Block-STM parallel execution is disabled; sequential mode is required",
            ));
        }
        Ok(())
    }
}

/// Entry-function / module invocation payload for `EeId::MOVE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveCallEnvelope {
    PublishModule {
        module_name: String,
        bytecode: Vec<u8>,
    },
    EntryFunction {
        module_id: String,
        function_name: String,
        args: Vec<String>,
    },
    BudlumUniversalCall {
        target_ee: u8,
        target: Vec<u8>,
        input: Vec<u8>,
        value_octas: u64,
        gas_bgu: u64,
        is_static: bool,
    },
}

/// Stateless Move execution environment (`budlum-ee-move`).
#[derive(Debug, Clone)]
pub struct MoveEe {
    config: MoveRuntimeConfig,
}

impl Default for MoveEe {
    fn default() -> Self {
        Self::new()
    }
}

impl MoveEe {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: MoveRuntimeConfig::default(),
        }
    }

    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn with_config(config: MoveRuntimeConfig) -> Result<Self, String> {
        config.ensure_sequential()?;
        Ok(Self { config })
    }
}

pub(crate) fn state_key_module(addr: &[u8; 32], mod_name: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(40 + mod_name.len());
    k.extend_from_slice(b"mod:");
    k.extend_from_slice(addr);
    k.push(b':');
    k.extend_from_slice(mod_name.as_bytes());
    k
}

pub(crate) fn state_key_resource(addr: &[u8; 32], resource_tag: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(40 + resource_tag.len());
    k.extend_from_slice(b"res:");
    k.extend_from_slice(addr);
    k.push(b':');
    k.extend_from_slice(resource_tag.as_bytes());
    k
}

fn coerce_addr32(raw: &[u8]) -> [u8; 32] {
    if let Ok(arr) = <[u8; 32]>::try_from(raw) {
        return arr;
    }
    Sha3_256::digest(raw).into()
}

fn abi_word_addr20(addr: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    if let (Some(tail), Some(dst)) = (addr.get(..20), w.get_mut(12..32)) {
        dst.copy_from_slice(tail);
    }
    w
}

fn abi_word_u128_be(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    if let Some(dst) = w.get_mut(16..32) {
        dst.copy_from_slice(&v.to_be_bytes());
    }
    w
}

fn decode_u256_be_to_u128(raw: &[u8]) -> u128 {
    let Some(lo) = raw.get(16..32) else {
        return 0;
    };
    <[u8; 16]>::try_from(lo).map_or(0, u128::from_be_bytes)
}

fn read_move_u128(host: &dyn HostRead, ns: &Namespace, key: &[u8]) -> u128 {
    let Ok(Some(raw)) = host.read(ns, key) else {
        return 0;
    };
    <[u8; 16]>::try_from(raw.as_slice()).map_or(0, u128::from_le_bytes)
}

fn execute_move_pointer(
    ptr: &PointerDescriptor,
    signer32: &[u8; 32],
    raw_input: &[u8],
    is_static: bool,
    gas_budget: u64,
    host: &mut dyn HostApi,
) -> EeOutcome {
    let base_bgu = 100 * BGU_PER_MOVE_GAS_UNIT;
    let Ok(op) = serde_json::from_slice::<MovePointerOp>(raw_input) else {
        return EeOutcome {
            status: OutcomeStatus::Revert,
            output: b"invalid MovePointerOp payload".to_vec(),
            gas_used: base_bgu,
        };
    };
    let read_only_op = matches!(
        op,
        MovePointerOp::Balance { .. } | MovePointerOp::Allowance { .. }
    );
    if is_static && !read_only_op {
        return EeOutcome {
            status: OutcomeStatus::Revert,
            output: b"static frame forbids Move pointer mutation".to_vec(),
            gas_used: base_bgu,
        };
    }

    let home_ee = EeId(ptr.home_ee);
    let forward_payload = match home_ee {
        EeId::EVM => match &op {
            MovePointerOp::Transfer { to, amount, .. } => {
                let to_id = resolve_pointer_party_for_home(host, to, EeId::EVM);
                let mut cd = solidity_selector("transfer(address,uint256)").to_vec();
                cd.extend_from_slice(&abi_word_addr20(&to_id));
                cd.extend_from_slice(&abi_word_u128_be(*amount));
                cd
            }
            MovePointerOp::Approve {
                spender, amount, ..
            } => {
                let sp_id = resolve_pointer_party_for_home(host, spender, EeId::EVM);
                let mut cd = solidity_selector("approve(address,uint256)").to_vec();
                cd.extend_from_slice(&abi_word_addr20(&sp_id));
                cd.extend_from_slice(&abi_word_u128_be(*amount));
                cd
            }
            MovePointerOp::TransferFrom {
                owner, to, amount, ..
            } => {
                let ow_id = resolve_pointer_party_for_home(host, owner, EeId::EVM);
                let to_id = resolve_pointer_party_for_home(host, to, EeId::EVM);
                let mut cd = solidity_selector("transferFrom(address,address,uint256)").to_vec();
                cd.extend_from_slice(&abi_word_addr20(&ow_id));
                cd.extend_from_slice(&abi_word_addr20(&to_id));
                cd.extend_from_slice(&abi_word_u128_be(*amount));
                cd
            }
            MovePointerOp::Balance { owner, .. } => {
                let ow_id = resolve_pointer_party_for_home(host, owner, EeId::EVM);
                let mut cd = solidity_selector("balanceOf(address)").to_vec();
                cd.extend_from_slice(&abi_word_addr20(&ow_id));
                cd
            }
            MovePointerOp::Allowance { owner, spender, .. } => {
                let ow_id = resolve_pointer_party_for_home(host, owner, EeId::EVM);
                let sp_id = resolve_pointer_party_for_home(host, spender, EeId::EVM);
                let mut cd = solidity_selector("allowance(address,address)").to_vec();
                cd.extend_from_slice(&abi_word_addr20(&ow_id));
                cd.extend_from_slice(&abi_word_addr20(&sp_id));
                cd
            }
        },
        EeId::WASM => {
            let val = match &op {
                MovePointerOp::Transfer { to, amount, .. } => {
                    let to_s = String::from_utf8_lossy(&resolve_pointer_party_for_home(
                        host,
                        to,
                        EeId::WASM,
                    ))
                    .into_owned();
                    serde_json::json!({
                        "execute": {
                            "transfer": { "recipient": to_s, "amount": amount.to_string() }
                        }
                    })
                }
                MovePointerOp::Approve {
                    spender, amount, ..
                } => {
                    let sp_s = String::from_utf8_lossy(&resolve_pointer_party_for_home(
                        host,
                        spender,
                        EeId::WASM,
                    ))
                    .into_owned();
                    serde_json::json!({
                        "execute": {
                            "set_allowance": { "spender": sp_s, "amount": amount.to_string() }
                        }
                    })
                }
                MovePointerOp::TransferFrom {
                    owner, to, amount, ..
                } => {
                    let ow_s = String::from_utf8_lossy(&resolve_pointer_party_for_home(
                        host,
                        owner,
                        EeId::WASM,
                    ))
                    .into_owned();
                    let to_s = String::from_utf8_lossy(&resolve_pointer_party_for_home(
                        host,
                        to,
                        EeId::WASM,
                    ))
                    .into_owned();
                    serde_json::json!({
                        "execute": {
                            "transfer_from": {
                                "owner": ow_s,
                                "recipient": to_s,
                                "amount": amount.to_string()
                            }
                        }
                    })
                }
                MovePointerOp::Balance { owner, .. } => {
                    let ow_s = String::from_utf8_lossy(&resolve_pointer_party_for_home(
                        host,
                        owner,
                        EeId::WASM,
                    ))
                    .into_owned();
                    serde_json::json!({ "query": { "balance": { "address": ow_s } } })
                }
                MovePointerOp::Allowance { owner, spender, .. } => {
                    let ow_s = String::from_utf8_lossy(&resolve_pointer_party_for_home(
                        host,
                        owner,
                        EeId::WASM,
                    ))
                    .into_owned();
                    let sp_s = String::from_utf8_lossy(&resolve_pointer_party_for_home(
                        host,
                        spender,
                        EeId::WASM,
                    ))
                    .into_owned();
                    serde_json::json!({
                        "query": { "allowance": { "owner": ow_s, "spender": sp_s } }
                    })
                }
            };
            serde_json::to_vec(&val).unwrap_or_default()
        }
        EeId::SVM => {
            let spl_op = match &op {
                MovePointerOp::Transfer { to, amount, .. } => SplPointerOp::Transfer {
                    to: coerce_addr32(&resolve_pointer_party_for_home(host, to, EeId::SVM)),
                    amount: *amount,
                },
                MovePointerOp::Approve {
                    spender, amount, ..
                } => SplPointerOp::Approve {
                    delegate: coerce_addr32(&resolve_pointer_party_for_home(
                        host,
                        spender,
                        EeId::SVM,
                    )),
                    amount: *amount,
                },
                MovePointerOp::TransferFrom {
                    owner, to, amount, ..
                } => SplPointerOp::TransferFrom {
                    owner: coerce_addr32(&resolve_pointer_party_for_home(host, owner, EeId::SVM)),
                    to: coerce_addr32(&resolve_pointer_party_for_home(host, to, EeId::SVM)),
                    amount: *amount,
                },
                MovePointerOp::Balance { owner, .. } => SplPointerOp::BalanceOf {
                    owner: coerce_addr32(&resolve_pointer_party_for_home(host, owner, EeId::SVM)),
                },
                MovePointerOp::Allowance { owner, spender, .. } => SplPointerOp::Allowance {
                    owner: coerce_addr32(&resolve_pointer_party_for_home(host, owner, EeId::SVM)),
                    delegate: coerce_addr32(&resolve_pointer_party_for_home(
                        host,
                        spender,
                        EeId::SVM,
                    )),
                },
            };
            serde_json::to_vec(&spl_op).unwrap_or_default()
        }
        _ => {
            return EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"unsupported home_ee for Move pointer".to_vec(),
                gas_used: base_bgu,
            };
        }
    };

    let final_in = if read_only_op {
        wrap_static_universal_input(&forward_payload)
    } else {
        forward_payload
    };
    match host.universal_call(UniversalCall {
        from: EeIdentity {
            ee: EeId::MOVE,
            id: signer32.to_vec(),
        },
        to_ee: home_ee,
        target: EeIdentity {
            ee: home_ee,
            id: ptr.home_ref.clone(),
        },
        value: BudAmount(0),
        input: final_in,
        gas_limit: gas_budget / 2 + 10_000,
        is_static: read_only_op,
    }) {
        Ok(r) => {
            let output = if r.success && read_only_op && home_ee == EeId::EVM {
                decode_u256_be_to_u128(&r.output).to_le_bytes().to_vec()
            } else if r.success && read_only_op && home_ee == EeId::WASM {
                let parsed = serde_json::from_slice::<serde_json::Value>(&r.output).ok();
                let num = parsed
                    .as_ref()
                    .and_then(|v| v.get("balance").or_else(|| v.get("allowance")))
                    .and_then(|s| s.as_str())
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or(0);
                num.to_le_bytes().to_vec()
            } else {
                r.output
            };
            EeOutcome {
                status: if r.success {
                    OutcomeStatus::Success
                } else {
                    OutcomeStatus::Revert
                },
                output,
                gas_used: base_bgu,
            }
        }
        Err(e) => EeOutcome {
            status: OutcomeStatus::Revert,
            output: e.to_string().into_bytes(),
            gas_used: base_bgu,
        },
    }
}

fn execute_move_home_asset_op(
    host: &mut dyn HostApi,
    move_ns: &Namespace,
    home32: &[u8; 32],
    signer32: &[u8; 32],
    op: &MovePointerOp,
    is_static: bool,
    base_bgu: u64,
) -> EeOutcome {
    let flavor_tag = match op {
        MovePointerOp::Transfer { flavor, .. }
        | MovePointerOp::Approve { flavor, .. }
        | MovePointerOp::TransferFrom { flavor, .. }
        | MovePointerOp::Balance { flavor, .. }
        | MovePointerOp::Allowance { flavor, .. } => match flavor {
            MovePointerFlavor::FungibleAsset => "fa",
            MovePointerFlavor::Coin => "coin",
        },
    };
    let read_only = matches!(
        op,
        MovePointerOp::Balance { .. } | MovePointerOp::Allowance { .. }
    );
    if is_static && !read_only {
        return EeOutcome {
            status: OutcomeStatus::Revert,
            output: b"static frame forbids Move asset mutation".to_vec(),
            gas_used: base_bgu,
        };
    }
    match op {
        MovePointerOp::Balance { owner, .. } => {
            let k = state_key_resource(home32, &format!("{flavor_tag}:bal:{}", hex::encode(owner)));
            let bal = read_move_u128(host, move_ns, &k);
            EeOutcome {
                status: OutcomeStatus::Success,
                output: bal.to_le_bytes().to_vec(),
                gas_used: base_bgu,
            }
        }
        MovePointerOp::Allowance { owner, spender, .. } => {
            let k = state_key_resource(
                home32,
                &format!(
                    "{flavor_tag}:alw:{}:{}",
                    hex::encode(owner),
                    hex::encode(spender)
                ),
            );
            let alw = read_move_u128(host, move_ns, &k);
            EeOutcome {
                status: OutcomeStatus::Success,
                output: alw.to_le_bytes().to_vec(),
                gas_used: base_bgu,
            }
        }
        MovePointerOp::Approve {
            spender, amount, ..
        } => {
            let k = state_key_resource(
                home32,
                &format!(
                    "{flavor_tag}:alw:{}:{}",
                    hex::encode(signer32),
                    hex::encode(spender)
                ),
            );
            if host
                .write(move_ns, &k, Some(&amount.to_le_bytes()))
                .is_err()
            {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"failed writing Move asset allowance".to_vec(),
                    gas_used: base_bgu,
                };
            }
            EeOutcome {
                status: OutcomeStatus::Success,
                output: amount.to_le_bytes().to_vec(),
                gas_used: base_bgu,
            }
        }
        MovePointerOp::Transfer { to, amount, .. } => {
            let src_k = state_key_resource(
                home32,
                &format!("{flavor_tag}:bal:{}", hex::encode(signer32)),
            );
            let dst_k =
                state_key_resource(home32, &format!("{flavor_tag}:bal:{}", hex::encode(to)));
            let src_bal = read_move_u128(host, move_ns, &src_k);
            if src_bal < *amount {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"insufficient Move asset balance".to_vec(),
                    gas_used: base_bgu,
                };
            }
            if src_k == dst_k {
                return EeOutcome {
                    status: OutcomeStatus::Success,
                    output: amount.to_le_bytes().to_vec(),
                    gas_used: base_bgu,
                };
            }
            let dst_bal = read_move_u128(host, move_ns, &dst_k);
            let Some(new_dst) = dst_bal.checked_add(*amount) else {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"Move asset balance overflow".to_vec(),
                    gas_used: base_bgu,
                };
            };
            if host
                .write(move_ns, &src_k, Some(&(src_bal - *amount).to_le_bytes()))
                .is_err()
                || host
                    .write(move_ns, &dst_k, Some(&new_dst.to_le_bytes()))
                    .is_err()
            {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"failed writing Move asset transfer state".to_vec(),
                    gas_used: base_bgu,
                };
            }
            EeOutcome {
                status: OutcomeStatus::Success,
                output: amount.to_le_bytes().to_vec(),
                gas_used: base_bgu,
            }
        }
        MovePointerOp::TransferFrom {
            owner, to, amount, ..
        } => {
            let alw_k = state_key_resource(
                home32,
                &format!(
                    "{flavor_tag}:alw:{}:{}",
                    hex::encode(owner),
                    hex::encode(signer32)
                ),
            );
            let cur_alw = read_move_u128(host, move_ns, &alw_k);
            if cur_alw < *amount {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"insufficient Move asset allowance".to_vec(),
                    gas_used: base_bgu,
                };
            }
            let src_k =
                state_key_resource(home32, &format!("{flavor_tag}:bal:{}", hex::encode(owner)));
            let dst_k =
                state_key_resource(home32, &format!("{flavor_tag}:bal:{}", hex::encode(to)));
            let src_bal = read_move_u128(host, move_ns, &src_k);
            if src_bal < *amount {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"insufficient Move owner balance".to_vec(),
                    gas_used: base_bgu,
                };
            }
            if src_k == dst_k {
                if host
                    .write(move_ns, &alw_k, Some(&(cur_alw - *amount).to_le_bytes()))
                    .is_err()
                {
                    return EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"failed writing Move asset allowance".to_vec(),
                        gas_used: base_bgu,
                    };
                }
                return EeOutcome {
                    status: OutcomeStatus::Success,
                    output: amount.to_le_bytes().to_vec(),
                    gas_used: base_bgu,
                };
            }
            let dst_bal = read_move_u128(host, move_ns, &dst_k);
            let Some(new_dst) = dst_bal.checked_add(*amount) else {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"Move asset balance overflow".to_vec(),
                    gas_used: base_bgu,
                };
            };
            if host
                .write(move_ns, &alw_k, Some(&(cur_alw - *amount).to_le_bytes()))
                .is_err()
                || host
                    .write(move_ns, &src_k, Some(&(src_bal - *amount).to_le_bytes()))
                    .is_err()
                || host
                    .write(move_ns, &dst_k, Some(&new_dst.to_le_bytes()))
                    .is_err()
            {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"failed writing Move asset transfer_from state".to_vec(),
                    gas_used: base_bgu,
                };
            }
            EeOutcome {
                status: OutcomeStatus::Success,
                output: amount.to_le_bytes().to_vec(),
                gas_used: base_bgu,
            }
        }
    }
}

impl ExecutionEnvironment for MoveEe {
    fn id(&self) -> EeId {
        EeId::MOVE
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        self.config
            .ensure_sequential()
            .map_err(|message| EeRefusal {
                code: RefusalCode::Denied,
                message,
            })?;
        if is_pointer_bytecode_prefixed(code) {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("system pointer bytecode prefix is reserved for uel/assets"),
            });
        }
        if code.len() < 4 || code.get(..4) != Some(&MOVE_BINARY_MAGIC) {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("Move module must start with 0xa11ceb0b magic"),
            });
        }
        if code.len() > MAX_MOVE_BUNDLE_BYTES {
            return Err(EeRefusal {
                code: RefusalCode::TooLarge,
                message: String::from("Move module bundle exceeds 256 KiB"),
            });
        }
        Ok(CodeInfo {
            code_hash: Sha3_256::digest(code).into(),
            abi_tag: String::from("aptos-move-v1"),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        if let Err(m) = self.config.ensure_sequential() {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: m.into_bytes(),
                gas_used: 0,
            });
        }
        let base_bgu = 100 * BGU_PER_MOVE_GAS_UNIT;
        if host.charge(base_bgu).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        }
        let Ok(move_ns) = Namespace::new(NS_MOVE_STATE) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: Vec::new(),
                gas_used: base_bgu,
            });
        };
        let signer32 = coerce_addr32(&call.caller.id);
        let target32 = coerce_addr32(&call.target.id);

        match call.kind {
            EeCallKind::Deploy => {
                if let Err(r) = self.validate_deploy(&call.input) {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: r.message.into_bytes(),
                        gas_used: base_bgu,
                    });
                }
                let k = state_key_module(&target32, "default");
                let ptr_k = state_key_module(&target32, "pointer");
                let admin_k = state_key_resource(&target32, "admin");
                if matches!(host.read(&move_ns, &k), Ok(Some(_)))
                    || matches!(host.read(&move_ns, &ptr_k), Ok(Some(_)))
                    || matches!(host.read(&move_ns, &admin_k), Ok(Some(_)))
                {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"Move module already deployed at target".to_vec(),
                        gas_used: base_bgu,
                    });
                }
                if host.write(&move_ns, &k, Some(&call.input)).is_err()
                    || host.write(&move_ns, &admin_k, Some(&signer32)).is_err()
                {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"failed storing Move module".to_vec(),
                        gas_used: base_bgu,
                    });
                }
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: target32.to_vec(),
                    gas_used: base_bgu,
                })
            }
            EeCallKind::Call => {
                let (is_static, clean_input) = unwrap_static_universal_input(&call.input);
                let ptr_key = state_key_module(&target32, "pointer");
                if let Ok(Some(code)) = host.read(&move_ns, &ptr_key) {
                    match verify_canonical_pointer_bytecode(&code, EeId::MOVE, &target32) {
                        Err(reason) => {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: reason.into_bytes(),
                                gas_used: base_bgu,
                            });
                        }
                        Ok(Some(ptr)) => {
                            return Ok(execute_move_pointer(
                                &ptr,
                                &signer32,
                                clean_input,
                                is_static,
                                call.gas_limit,
                                host,
                            ));
                        }
                        Ok(None) => {}
                    }
                }
                if let Ok(ptr_op) = serde_json::from_slice::<MovePointerOp>(clean_input) {
                    return Ok(execute_move_home_asset_op(
                        host, &move_ns, &target32, &signer32, &ptr_op, is_static, base_bgu,
                    ));
                }
                let Ok(env) = serde_json::from_slice::<MoveCallEnvelope>(clean_input) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"invalid MoveCallEnvelope".to_vec(),
                        gas_used: base_bgu,
                    });
                };
                if is_static {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"static call forbids Move state mutation".to_vec(),
                        gas_used: base_bgu,
                    });
                }
                match env {
                    MoveCallEnvelope::PublishModule {
                        module_name,
                        bytecode,
                    } => {
                        if module_name == "pointer" {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: b"Move module name 'pointer' is reserved for uel/assets"
                                    .to_vec(),
                                gas_used: base_bgu,
                            });
                        }
                        if let Err(r) = self.validate_deploy(&bytecode) {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::InvalidCode,
                                output: r.message.into_bytes(),
                                gas_used: base_bgu,
                            });
                        }
                        let k = state_key_module(&signer32, &module_name);
                        if matches!(host.read(&move_ns, &k), Ok(Some(_))) {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: b"Move module already published at signer address".to_vec(),
                                gas_used: base_bgu,
                            });
                        }
                        if host.write(&move_ns, &k, Some(&bytecode)).is_err() {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: b"failed writing published Move module".to_vec(),
                                gas_used: base_bgu,
                            });
                        }
                        let admin_k = state_key_resource(&signer32, "admin");
                        if !matches!(host.read(&move_ns, &admin_k), Ok(Some(_)))
                            && host.write(&move_ns, &admin_k, Some(&signer32)).is_err()
                        {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: b"failed writing Move module admin".to_vec(),
                                gas_used: base_bgu,
                            });
                        }
                        Ok(EeOutcome {
                            status: OutcomeStatus::Success,
                            output: k,
                            gas_used: base_bgu,
                        })
                    }
                    MoveCallEnvelope::EntryFunction {
                        module_id,
                        function_name,
                        args,
                    } => {
                        if FORBIDDEN_MOVE_MODULES.contains(&module_id.as_str()) {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: format!("Move module `{module_id}` is disabled on Budlum")
                                    .into_bytes(),
                                gas_used: base_bgu,
                            });
                        }
                        if module_id == "0x1::randomness" {
                            let args_json = serde_json::to_vec(&args).unwrap_or_default();
                            let chain_le = ctx.chain_id.to_le_bytes();
                            let height_le = ctx.height.to_le_bytes();
                            let ts_le = ctx.timestamp_ms.to_le_bytes();
                            let depth_le = call.depth.to_le_bytes();
                            let rbytes = hash_fields_bytes(&[
                                b"BDLM_MOVE_RANDOMNESS_V1",
                                &chain_le,
                                &height_le,
                                &ts_le,
                                &call.tx_hash,
                                &depth_le,
                                &signer32,
                                &target32,
                                function_name.as_bytes(),
                                &args_json,
                            ]);
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Success,
                                output: rbytes.to_vec(),
                                gas_used: base_bgu,
                            });
                        }
                        if (module_id == "0x1::fungible_asset" || module_id == "0x1::coin")
                            && function_name == "mint"
                        {
                            let admin_k = state_key_resource(&target32, "admin");
                            let auth_ok = match host.read(&move_ns, &admin_k) {
                                Ok(Some(adm)) => adm.as_slice() == signer32,
                                _ => signer32 == target32,
                            };
                            if !auth_ok {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"caller is not Move asset mint authority".to_vec(),
                                    gas_used: base_bgu,
                                });
                            }
                            let Some(dst_hex) = args.first() else {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"missing Move mint recipient".to_vec(),
                                    gas_used: base_bgu,
                                });
                            };
                            let Some(amount) = args.get(1).and_then(|s| s.parse::<u128>().ok())
                            else {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"invalid Move mint amount".to_vec(),
                                    gas_used: base_bgu,
                                });
                            };
                            let Ok(dst_vec) = hex::decode(dst_hex.trim_start_matches("0x")) else {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"bad Move mint recipient hex".to_vec(),
                                    gas_used: base_bgu,
                                });
                            };
                            let dst32 = coerce_addr32(&dst_vec);
                            let tag_prefix = if module_id == "0x1::coin" {
                                "coin"
                            } else {
                                "fa"
                            };
                            let sup_k =
                                state_key_resource(&target32, &format!("{tag_prefix}:supply"));
                            let cur_sup = read_move_u128(host, &move_ns, &sup_k);
                            let Some(next_sup) = cur_sup.checked_add(amount) else {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"Move mint total supply overflow".to_vec(),
                                    gas_used: base_bgu,
                                });
                            };
                            let bal_k = state_key_resource(
                                &target32,
                                &format!("{tag_prefix}:bal:{}", hex::encode(dst32)),
                            );
                            let cur = read_move_u128(host, &move_ns, &bal_k);
                            let Some(next) = cur.checked_add(amount) else {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"Move mint balance overflow".to_vec(),
                                    gas_used: base_bgu,
                                });
                            };
                            if host
                                .write(&move_ns, &sup_k, Some(&next_sup.to_le_bytes()))
                                .is_err()
                                || host
                                    .write(&move_ns, &bal_k, Some(&next.to_le_bytes()))
                                    .is_err()
                            {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"failed writing Move mint state".to_vec(),
                                    gas_used: base_bgu,
                                });
                            }
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Success,
                                output: next.to_le_bytes().to_vec(),
                                gas_used: base_bgu,
                            });
                        }
                        if (module_id == "0x1::aptos_account" || module_id == "0x1::coin")
                            && function_name == "transfer"
                        {
                            let Some(dst_hex) = args.first() else {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"missing transfer recipient".to_vec(),
                                    gas_used: base_bgu,
                                });
                            };
                            let Some(octas) = args.get(1).and_then(|s| s.parse::<u64>().ok())
                            else {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"invalid Move transfer octas amount".to_vec(),
                                    gas_used: base_bgu,
                                });
                            };
                            let Ok(dst_vec) = hex::decode(dst_hex.trim_start_matches("0x")) else {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"bad recipient hex".to_vec(),
                                    gas_used: base_bgu,
                                });
                            };
                            let attos = u128::from(octas).saturating_mul(ATTOS_PER_OCTA);
                            if let Err(e) = host.bud_transfer(
                                &EeIdentity {
                                    ee: EeId::MOVE,
                                    id: signer32.to_vec(),
                                },
                                &EeIdentity {
                                    ee: EeId::MOVE,
                                    id: dst_vec,
                                },
                                attos,
                            ) {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: e.to_string().into_bytes(),
                                    gas_used: base_bgu,
                                });
                            }
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Success,
                                output: octas.to_le_bytes().to_vec(),
                                gas_used: base_bgu,
                            });
                        }
                        let tag = format!("{module_id}::{function_name}");
                        let res_k = state_key_resource(&signer32, &tag);
                        let payload = args.join(",").into_bytes();
                        if host.write(&move_ns, &res_k, Some(&payload)).is_err() {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: b"failed writing Move entry state".to_vec(),
                                gas_used: base_bgu,
                            });
                        }
                        let topic_arr: [u8; 32] = Sha3_256::digest(module_id.as_bytes()).into();
                        let _ = host.emit_log(EeLog {
                            emitter: EeIdentity {
                                ee: EeId::MOVE,
                                id: signer32.to_vec(),
                            },
                            topics: vec![topic_arr.to_vec()],
                            data: payload.clone(),
                        });
                        Ok(EeOutcome {
                            status: OutcomeStatus::Success,
                            output: payload,
                            gas_used: base_bgu,
                        })
                    }
                    MoveCallEnvelope::BudlumUniversalCall {
                        target_ee,
                        target,
                        input,
                        value_octas,
                        gas_bgu,
                        is_static,
                    } => {
                        let payload = if is_static {
                            wrap_static_universal_input(&input)
                        } else {
                            input
                        };
                        let attos = u128::from(value_octas).saturating_mul(ATTOS_PER_OCTA);
                        match host.universal_call(UniversalCall {
                            from: EeIdentity {
                                ee: EeId::MOVE,
                                id: signer32.to_vec(),
                            },
                            to_ee: EeId(target_ee),
                            target: EeIdentity {
                                ee: EeId(target_ee),
                                id: target,
                            },
                            value: BudAmount(attos),
                            input: payload,
                            gas_limit: gas_bgu,
                            is_static,
                        }) {
                            Ok(r) => Ok(EeOutcome {
                                status: if r.success {
                                    OutcomeStatus::Success
                                } else {
                                    OutcomeStatus::Revert
                                },
                                output: r.output,
                                gas_used: base_bgu,
                            }),
                            Err(e) => Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: e.to_string().into_bytes(),
                                gas_used: base_bgu,
                            }),
                        }
                    }
                }
            }
        }
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let move_ns = Namespace::new(NS_MOVE_STATE).map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: e.to_string(),
        })?;
        host.read(&move_ns, &q.input)
            .map(Option::unwrap_or_default)
            .map_err(|e| EeRefusal {
                code: RefusalCode::Denied,
                message: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budlum_uel_abi::{HostError, OutOfGas, UniversalResult};
    use std::collections::BTreeMap;

    struct MemHost {
        kv: BTreeMap<(String, Vec<u8>), Vec<u8>>,
        writes: usize,
        fail_on_write: Option<usize>,
    }

    impl MemHost {
        fn new() -> Self {
            Self {
                kv: BTreeMap::new(),
                writes: 0,
                fail_on_write: None,
            }
        }
    }

    impl HostRead for MemHost {
        fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
            Ok(self
                .kv
                .get(&(ns.as_str().to_string(), key.to_vec()))
                .cloned())
        }

        fn bud_balance(&self, _who: &EeIdentity) -> Result<BudAmount, HostError> {
            Ok(BudAmount(0))
        }
    }

    impl HostApi for MemHost {
        fn write(
            &mut self,
            ns: &Namespace,
            key: &[u8],
            value: Option<&[u8]>,
        ) -> Result<(), HostError> {
            self.writes += 1;
            if self.fail_on_write == Some(self.writes) {
                return Err(HostError::Denied(String::from("injected write failure")));
            }
            let k = (ns.as_str().to_string(), key.to_vec());
            match value {
                Some(v) => {
                    self.kv.insert(k, v.to_vec());
                }
                None => {
                    self.kv.remove(&k);
                }
            }
            Ok(())
        }

        fn universal_call(&mut self, _call: UniversalCall) -> Result<UniversalResult, HostError> {
            Err(HostError::Denied(String::from("unexpected universal_call")))
        }

        fn emit_log(&mut self, _log: EeLog) -> Result<(), HostError> {
            Ok(())
        }

        fn charge(&mut self, _bgu: u64) -> Result<(), OutOfGas> {
            Ok(())
        }

        fn bud_transfer(
            &mut self,
            _from: &EeIdentity,
            _to: &EeIdentity,
            _attos: u128,
        ) -> Result<(), HostError> {
            Ok(())
        }
    }

    fn test_ctx() -> BlockContext {
        BlockContext {
            height: 10,
            timestamp_ms: 1_700_000_000_000,
            chain_id: 1,
        }
    }

    fn move_call(caller: [u8; 32], target: [u8; 32], input: Vec<u8>) -> EeCall {
        EeCall {
            kind: EeCallKind::Call,
            caller: EeIdentity {
                ee: EeId::MOVE,
                id: caller.to_vec(),
            },
            target: EeIdentity {
                ee: EeId::MOVE,
                id: target.to_vec(),
            },
            value: BudAmount(0),
            input,
            gas_limit: 200_000,
            depth: 0,
            tx_hash: [0x11; 32],
        }
    }

    fn read_u128_out(out: &EeOutcome) -> u128 {
        assert_eq!(out.status, OutcomeStatus::Success);
        let bytes: [u8; 16] = out.output.as_slice().try_into().expect("16-byte u128");
        u128::from_le_bytes(bytes)
    }

    fn deploy_and_mint(
        ee: &mut MoveEe,
        host: &mut MemHost,
        admin: [u8; 32],
        home: [u8; 32],
        to: [u8; 32],
        amount: u128,
    ) {
        let mut mod_bytes = MOVE_BINARY_MAGIC.to_vec();
        mod_bytes.extend_from_slice(&[1, 0, 0, 0]);
        let deploy = EeCall {
            kind: EeCallKind::Deploy,
            caller: EeIdentity {
                ee: EeId::MOVE,
                id: admin.to_vec(),
            },
            target: EeIdentity {
                ee: EeId::MOVE,
                id: home.to_vec(),
            },
            value: BudAmount(0),
            input: mod_bytes,
            gas_limit: 200_000,
            depth: 0,
            tx_hash: [0x01; 32],
        };
        assert_eq!(
            ee.execute(&test_ctx(), &deploy, host)
                .expect("deploy")
                .status,
            OutcomeStatus::Success
        );
        let mint_payload = serde_json::to_vec(&MoveCallEnvelope::EntryFunction {
            module_id: String::from("0x1::fungible_asset"),
            function_name: String::from("mint"),
            args: vec![hex::encode(to), amount.to_string()],
        })
        .expect("mint json");
        let res = ee
            .execute(&test_ctx(), &move_call(admin, home, mint_payload), host)
            .expect("mint");
        assert_eq!(res.status, OutcomeStatus::Success);
    }

    #[test]
    fn move_home_self_transfer_preserves_balance_and_avoids_u128_overflow() {
        let mut ee = MoveEe::new();
        let mut host = MemHost::new();
        let alice = [0xAA; 32];
        let bob = [0xBB; 32];
        let home = [0x44; 32];
        deploy_and_mint(&mut ee, &mut host, alice, home, alice, 500);

        let self_xfer = serde_json::to_vec(&MovePointerOp::Transfer {
            flavor: MovePointerFlavor::FungibleAsset,
            to: alice,
            amount: 200,
        })
        .expect("json");
        let r = ee
            .execute(&test_ctx(), &move_call(alice, home, self_xfer), &mut host)
            .expect("self transfer");
        assert_eq!(r.status, OutcomeStatus::Success);

        let bal_q = serde_json::to_vec(&MovePointerOp::Balance {
            flavor: MovePointerFlavor::FungibleAsset,
            owner: alice,
        })
        .expect("json");
        let bal_out = ee
            .execute(&test_ctx(), &move_call(alice, home, bal_q), &mut host)
            .expect("balance");
        assert_eq!(
            read_u128_out(&bal_out),
            500,
            "self-transfer must not mint additional Move home assets"
        );

        // Self-transfer at u128::MAX must succeed rather than falsely overflowing.
        let ns = Namespace::new(NS_MOVE_STATE).expect("ns");
        let alice_k = state_key_resource(&home, &format!("fa:bal:{}", hex::encode(alice)));
        host.write(&ns, &alice_k, Some(&u128::MAX.to_le_bytes()))
            .expect("set max");
        let max_self = serde_json::to_vec(&MovePointerOp::Transfer {
            flavor: MovePointerFlavor::FungibleAsset,
            to: alice,
            amount: 1,
        })
        .expect("json");
        let max_r = ee
            .execute(&test_ctx(), &move_call(alice, home, max_self), &mut host)
            .expect("max self transfer");
        assert_eq!(max_r.status, OutcomeStatus::Success);
        assert_eq!(read_move_u128(&host, &ns, &alice_k), u128::MAX);

        // Distinct recipient transfer continues to debit and credit normally.
        host.write(&ns, &alice_k, Some(&500u128.to_le_bytes()))
            .expect("reset");
        let xfer_bob = serde_json::to_vec(&MovePointerOp::Transfer {
            flavor: MovePointerFlavor::FungibleAsset,
            to: bob,
            amount: 150,
        })
        .expect("json");
        let r_bob = ee
            .execute(&test_ctx(), &move_call(alice, home, xfer_bob), &mut host)
            .expect("transfer bob");
        assert_eq!(r_bob.status, OutcomeStatus::Success);
        let bob_k = state_key_resource(&home, &format!("fa:bal:{}", hex::encode(bob)));
        assert_eq!(read_move_u128(&host, &ns, &alice_k), 350);
        assert_eq!(read_move_u128(&host, &ns, &bob_k), 150);
    }

    #[test]
    fn move_home_self_transfer_from_preserves_balance_debits_allowance_and_avoids_overflow() {
        let mut ee = MoveEe::new();
        let mut host = MemHost::new();
        let alice = [0xA1; 32];
        let bob = [0xB2; 32];
        let carol = [0xC3; 32];
        let home = [0x55; 32];
        deploy_and_mint(&mut ee, &mut host, alice, home, alice, 500);

        let approve_bob = serde_json::to_vec(&MovePointerOp::Approve {
            flavor: MovePointerFlavor::Coin,
            spender: bob,
            amount: 300,
        })
        .expect("json");
        let coin_mint = serde_json::to_vec(&MoveCallEnvelope::EntryFunction {
            module_id: String::from("0x1::coin"),
            function_name: String::from("mint"),
            args: vec![hex::encode(alice), String::from("500")],
        })
        .expect("json");
        assert_eq!(
            ee.execute(&test_ctx(), &move_call(alice, home, coin_mint), &mut host)
                .expect("coin mint")
                .status,
            OutcomeStatus::Success
        );
        assert_eq!(
            ee.execute(&test_ctx(), &move_call(alice, home, approve_bob), &mut host)
                .expect("approve")
                .status,
            OutcomeStatus::Success
        );

        let self_from = serde_json::to_vec(&MovePointerOp::TransferFrom {
            flavor: MovePointerFlavor::Coin,
            owner: alice,
            to: alice,
            amount: 120,
        })
        .expect("json");
        let r = ee
            .execute(&test_ctx(), &move_call(bob, home, self_from), &mut host)
            .expect("self transfer_from");
        assert_eq!(r.status, OutcomeStatus::Success);

        let ns = Namespace::new(NS_MOVE_STATE).expect("ns");
        let alice_k = state_key_resource(&home, &format!("coin:bal:{}", hex::encode(alice)));
        let alw_k = state_key_resource(
            &home,
            &format!("coin:alw:{}:{}", hex::encode(alice), hex::encode(bob)),
        );
        assert_eq!(
            read_move_u128(&host, &ns, &alice_k),
            500,
            "TransferFrom to owner == to must not mint balance"
        );
        assert_eq!(read_move_u128(&host, &ns, &alw_k), 180);

        // At u128::MAX balance, TransferFrom(owner -> owner) must succeed and decrement allowance.
        host.write(&ns, &alice_k, Some(&u128::MAX.to_le_bytes()))
            .expect("set max");
        let max_self_from = serde_json::to_vec(&MovePointerOp::TransferFrom {
            flavor: MovePointerFlavor::Coin,
            owner: alice,
            to: alice,
            amount: 10,
        })
        .expect("json");
        let max_r = ee
            .execute(&test_ctx(), &move_call(bob, home, max_self_from), &mut host)
            .expect("max self transfer_from");
        assert_eq!(max_r.status, OutcomeStatus::Success);
        assert_eq!(read_move_u128(&host, &ns, &alice_k), u128::MAX);
        assert_eq!(read_move_u128(&host, &ns, &alw_k), 170);

        // Normal TransferFrom to distinct recipient works as expected.
        host.write(&ns, &alice_k, Some(&500u128.to_le_bytes()))
            .expect("reset");
        let to_carol = serde_json::to_vec(&MovePointerOp::TransferFrom {
            flavor: MovePointerFlavor::Coin,
            owner: alice,
            to: carol,
            amount: 70,
        })
        .expect("json");
        assert_eq!(
            ee.execute(&test_ctx(), &move_call(bob, home, to_carol), &mut host)
                .expect("transfer_from carol")
                .status,
            OutcomeStatus::Success
        );
        let carol_k = state_key_resource(&home, &format!("coin:bal:{}", hex::encode(carol)));
        assert_eq!(read_move_u128(&host, &ns, &alice_k), 430);
        assert_eq!(read_move_u128(&host, &ns, &carol_k), 70);
        assert_eq!(read_move_u128(&host, &ns, &alw_k), 100);
    }

    #[test]
    fn move_home_ops_propagate_host_write_failures_without_reporting_success() {
        let mut ee = MoveEe::new();
        let mut host = MemHost::new();
        let alice = [0xA2; 32];
        let bob = [0xB3; 32];
        let home = [0x66; 32];
        deploy_and_mint(&mut ee, &mut host, alice, home, alice, 500);

        // 1. Failing host write during Approve must revert, not claim Success.
        host.fail_on_write = Some(host.writes + 1);
        let approve = serde_json::to_vec(&MovePointerOp::Approve {
            flavor: MovePointerFlavor::FungibleAsset,
            spender: bob,
            amount: 100,
        })
        .expect("json");
        let r_apv = ee
            .execute(&test_ctx(), &move_call(alice, home, approve), &mut host)
            .expect("approve");
        assert_eq!(r_apv.status, OutcomeStatus::Revert);

        // 2. Failing second write (dst credit) during Transfer must revert, not claim Success.
        host.fail_on_write = Some(host.writes + 2);
        let xfer = serde_json::to_vec(&MovePointerOp::Transfer {
            flavor: MovePointerFlavor::FungibleAsset,
            to: bob,
            amount: 50,
        })
        .expect("json");
        let r_xfer = ee
            .execute(&test_ctx(), &move_call(alice, home, xfer), &mut host)
            .expect("transfer");
        assert_eq!(r_xfer.status, OutcomeStatus::Revert);

        // 3. Failing supply write during EntryFunction mint must revert, not claim Success.
        host.fail_on_write = Some(host.writes + 1);
        let mint = serde_json::to_vec(&MoveCallEnvelope::EntryFunction {
            module_id: String::from("0x1::fungible_asset"),
            function_name: String::from("mint"),
            args: vec![hex::encode(bob), String::from("25")],
        })
        .expect("json");
        let r_mint = ee
            .execute(&test_ctx(), &move_call(alice, home, mint), &mut host)
            .expect("mint");
        assert_eq!(r_mint.status, OutcomeStatus::Revert);
    }
}
