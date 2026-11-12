//! Move (Aptos) execution environment (`EeId::MOVE` = `0x04`) over `HostApi`.
//!
//! Implements  items 1, 3, & 6:
//! - Strictly sequential Move execution (`block_stm_parallel = false`).
//! - Move state persisted in `ee/move/state` keyed by canonical `StateKey` bytes.
//! - Framework subset: `0x1::aptos_account`, `0x1::coin`, `0x1::fungible_asset`,
//!   `0x1::randomness` (bound to `BlockContext.randao`, Budlum epoch randomness),
//!   and native `0x1::budlum_universal::call` (`1 octa = 10^10 attoBUD`).
//! - Aptos staking and governance modules are explicitly refused (section 8.15).
//!
//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.

use crate::execution::coordinator::assets::{
    decode_pointer_bytecode, resolve_pointer_party_for_home, MovePointerFlavor, MovePointerOp,
    PointerDescriptor, SplPointerOp,
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

fn state_key_module(addr: &[u8; 32], mod_name: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(40 + mod_name.len());
    k.extend_from_slice(b"mod:");
    k.extend_from_slice(addr);
    k.push(b':');
    k.extend_from_slice(mod_name.as_bytes());
    k
}

fn state_key_resource(addr: &[u8; 32], resource_tag: &str) -> Vec<u8> {
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
            let _ = host.write(move_ns, &k, Some(&amount.to_le_bytes()));
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
            let dst_bal = read_move_u128(host, move_ns, &dst_k);
            let Some(new_dst) = dst_bal.checked_add(*amount) else {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"Move asset balance overflow".to_vec(),
                    gas_used: base_bgu,
                };
            };
            let _ = host.write(move_ns, &src_k, Some(&(src_bal - *amount).to_le_bytes()));
            let _ = host.write(move_ns, &dst_k, Some(&new_dst.to_le_bytes()));
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
            let dst_bal = read_move_u128(host, move_ns, &dst_k);
            let Some(new_dst) = dst_bal.checked_add(*amount) else {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"Move asset balance overflow".to_vec(),
                    gas_used: base_bgu,
                };
            };
            let _ = host.write(move_ns, &alw_k, Some(&(cur_alw - *amount).to_le_bytes()));
            let _ = host.write(move_ns, &src_k, Some(&(src_bal - *amount).to_le_bytes()));
            let _ = host.write(move_ns, &dst_k, Some(&new_dst.to_le_bytes()));
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
                if host.write(&move_ns, &k, Some(&call.input)).is_err() {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"failed storing Move module".to_vec(),
                        gas_used: base_bgu,
                    });
                }
                let admin_k = state_key_resource(&target32, "admin");
                if !matches!(host.read(&move_ns, &admin_k), Ok(Some(_))) {
                    let _ = host.write(&move_ns, &admin_k, Some(&signer32));
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
                    if let Some(ptr) = decode_pointer_bytecode(&code) {
                        return Ok(execute_move_pointer(
                            &ptr,
                            &signer32,
                            clean_input,
                            is_static,
                            call.gas_limit,
                            host,
                        ));
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
                        if let Err(r) = self.validate_deploy(&bytecode) {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::InvalidCode,
                                output: r.message.into_bytes(),
                                gas_used: base_bgu,
                            });
                        }
                        let k = state_key_module(&signer32, &module_name);
                        let _ = host.write(&move_ns, &k, Some(&bytecode));
                        let admin_k = state_key_resource(&signer32, "admin");
                        if !matches!(host.read(&move_ns, &admin_k), Ok(Some(_))) {
                            let _ = host.write(&move_ns, &admin_k, Some(&signer32));
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
                            let mut h = Sha3_256::new();
                            h.update(ctx.chain_id.to_le_bytes());
                            h.update(ctx.height.to_le_bytes());
                            h.update(ctx.timestamp_ms.to_le_bytes());
                            h.update(signer32);
                            h.update(function_name.as_bytes());
                            let rbytes: [u8; 32] = h.finalize().into();
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
                            let amount: u128 =
                                args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
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
                            let _ = host.write(&move_ns, &bal_k, Some(&next.to_le_bytes()));
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
                            let octas: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
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
                        let _ = host.write(&move_ns, &res_k, Some(&payload));
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
