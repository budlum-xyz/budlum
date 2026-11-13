//! Out-of-process deterministic TVM (TON FunC/Tact/Tolk) UEL execution worker (
//! `EeId::TVM = 0x09`).
//!
//! Executes deterministic TON Virtual Machine cell/stack bytecode in interpreter
//! mode across `x86_64` and `aarch64`, persists contract cells and persistent `c4`
//! data registers under `ee/tvm/state`, and opens at block zero on testnet `45261`
//! (`PROPOSED_TVM_ACTIVATION_HEIGHT = 0`).

#![forbid(unsafe_code)]

use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog, EeOutcome,
    EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, Namespace, OutcomeStatus,
    RefusalCode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Audited upstream engine SPDX (`ton-blockchain/tycho-vm`, `MIT OR Apache-2.0`).
pub const AUDITED_TVM_SPDX: &str = "MIT OR Apache-2.0";

/// Budlum testnet chain ID (`45261`).
pub const BUDLUM_TESTNET_CHAIN_ID: u64 = 45_261;

/// Proposed testnet activation height (open from block zero on `45261`, `IP-53`).
pub const PROPOSED_TVM_ACTIVATION_HEIGHT: u64 = 0;

/// Canonical UEL namespace storing TVM code cells and persistent `c4` contract data.
pub const NS_TVM_STATE: &str = "ee/tvm/state";

/// Bag-of-Cells deterministic Budlum TVM container prefix (`"TVM\0"`).
pub const TVM_BLOB_MAGIC: &[u8; 4] = b"TVM\0";

/// Maximum TVM cell container size (`512 KiB`).
pub const MAX_TVM_CELL_BYTES: usize = 524_288;

/// Deterministic TVM stack / cell VM instructions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TvmInsn {
    PushInt(i128),
    PushMsgWord(usize),
    Add,
    Sub,
    Mul,
    Equal,
    ThrowIfZero(u16),
    LoadC4Word { key: String },
    StoreC4Word { key: String },
    HashC4Cell { key: String },
    EmitExtOut { topic: [u8; 32] },
    AcceptRetTop,
}

/// TVM internal message handler keyed by 32-bit CRC/FunC op selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TvmMethod {
    pub op: u32,
    pub body: Vec<TvmInsn>,
}

/// Deterministic TVM contract package (init `c4` data + `recv_internal` handlers).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TvmContract {
    pub init: Vec<TvmInsn>,
    pub handlers: Vec<TvmMethod>,
}

/// Inbound TVM internal message payload (`op` + 128-bit integer arguments).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TvmInternalMsg {
    pub op: u32,
    pub args: Vec<i128>,
}

/// Encodes a [`TvmContract`] with [`TVM_BLOB_MAGIC`].
///
/// # Errors
///
/// Returns [`EeRefusal`] on encoding error or size overflow.
pub fn encode_tvm_blob(contract: &TvmContract) -> Result<Vec<u8>, EeRefusal> {
    let body = serde_json::to_vec(contract).map_err(|e| EeRefusal {
        code: RefusalCode::InvalidCode,
        message: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(TVM_BLOB_MAGIC);
    out.extend_from_slice(&body);
    if out.len() > MAX_TVM_CELL_BYTES {
        return Err(EeRefusal {
            code: RefusalCode::TooLarge,
            message: String::from("TVM cell blob exceeds 512 KiB"),
        });
    }
    Ok(out)
}

/// Decodes a [`TvmContract`] from `bytes`.
///
/// # Errors
///
/// Returns [`EeRefusal`] when magic, bounds, or payload fails validation.
pub fn decode_tvm_blob(bytes: &[u8]) -> Result<TvmContract, EeRefusal> {
    if bytes.len() > MAX_TVM_CELL_BYTES {
        return Err(EeRefusal {
            code: RefusalCode::TooLarge,
            message: String::from("TVM cell blob exceeds 512 KiB"),
        });
    }
    let Some(rest) = bytes.strip_prefix(TVM_BLOB_MAGIC) else {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("TVM blob missing TVM\\0 header"),
        });
    };
    serde_json::from_slice(rest).map_err(|e| EeRefusal {
        code: RefusalCode::InvalidCode,
        message: format!("invalid TVM cell package: {e}"),
    })
}

fn code_key(addr32: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(37);
    k.extend_from_slice(b"code:");
    k.extend_from_slice(addr32);
    k
}

fn c4_key(addr32: &[u8; 32], slot: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(36 + slot.len());
    k.extend_from_slice(b"c4:");
    k.extend_from_slice(addr32);
    k.push(b':');
    k.extend_from_slice(slot.as_bytes());
    k
}

fn derive_tvm_addr(caller: &[u8], tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"BDLM_TVM_ADDR_V1");
    h.update(caller);
    h.update(tx_hash);
    h.finalize().into()
}

fn ee_wire_fault(err: impl std::fmt::Display) -> EeFault {
    let msg = err.to_string();
    EeFault {
        ee: EeId::TVM,
        panic_digest: budlum_uel_abi::panic_digest(EeId::TVM, &msg),
    }
}

fn run_tvm_body(
    ns: &Namespace,
    addr32: &[u8; 32],
    insns: &[TvmInsn],
    args: &[i128],
    gas_used: &mut u64,
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<Vec<u8>, Vec<u8>> {
    let mut stack: Vec<i128> = Vec::new();
    for insn in insns {
        let Some(next) = gas_used.checked_add(300) else {
            return Err(b"OUT_OF_GAS".to_vec());
        };
        if next > gas_limit || host.charge(300).is_err() {
            return Err(b"OUT_OF_GAS".to_vec());
        }
        *gas_used = next;
        match insn {
            TvmInsn::PushInt(v) => stack.push(*v),
            TvmInsn::PushMsgWord(idx) => {
                let Some(v) = args.get(*idx) else {
                    return Err(b"TVM msg underflow".to_vec());
                };
                stack.push(*v);
            }
            TvmInsn::Add => {
                let (Some(b), Some(a)) = (stack.pop(), stack.pop()) else {
                    return Err(b"TVM stack underflow".to_vec());
                };
                let Some(s) = a.checked_add(b) else {
                    return Err(b"TVM integer overflow".to_vec());
                };
                stack.push(s);
            }
            TvmInsn::Sub => {
                let (Some(b), Some(a)) = (stack.pop(), stack.pop()) else {
                    return Err(b"TVM stack underflow".to_vec());
                };
                let Some(s) = a.checked_sub(b) else {
                    return Err(b"TVM integer underflow".to_vec());
                };
                stack.push(s);
            }
            TvmInsn::Mul => {
                let (Some(b), Some(a)) = (stack.pop(), stack.pop()) else {
                    return Err(b"TVM stack underflow".to_vec());
                };
                let Some(s) = a.checked_mul(b) else {
                    return Err(b"TVM integer overflow".to_vec());
                };
                stack.push(s);
            }
            TvmInsn::Equal => {
                let (Some(b), Some(a)) = (stack.pop(), stack.pop()) else {
                    return Err(b"TVM stack underflow".to_vec());
                };
                stack.push(if a == b { -1 } else { 0 });
            }
            TvmInsn::ThrowIfZero(code) => {
                let Some(cond) = stack.pop() else {
                    return Err(b"TVM stack underflow".to_vec());
                };
                if cond == 0 {
                    return Err(format!("TVM_EXIT_{code}").into_bytes());
                }
            }
            TvmInsn::LoadC4Word { key } => {
                let raw = host
                    .read(ns, &c4_key(addr32, key))
                    .ok()
                    .flatten()
                    .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
                    .map_or(0i128, i128::from_le_bytes);
                stack.push(raw);
            }
            TvmInsn::StoreC4Word { key } => {
                let Some(val) = stack.pop() else {
                    return Err(b"TVM stack underflow".to_vec());
                };
                if host
                    .write(ns, &c4_key(addr32, key), Some(&val.to_le_bytes()))
                    .is_err()
                {
                    return Err(b"TVM c4 write failed".to_vec());
                }
            }
            TvmInsn::HashC4Cell { key } => {
                let raw = host
                    .read(ns, &c4_key(addr32, key))
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let d: [u8; 32] = Sha256::digest(&raw).into();
                let mut head = [0u8; 16];
                if let Some(src) = d.get(..16) {
                    head.copy_from_slice(src);
                }
                stack.push(i128::from_le_bytes(head));
            }
            TvmInsn::EmitExtOut { topic } => {
                let top = stack.last().copied().unwrap_or(0);
                if host
                    .emit_log(EeLog {
                        emitter: EeIdentity {
                            ee: EeId::TVM,
                            id: addr32.to_vec(),
                        },
                        topics: vec![topic.to_vec()],
                        data: top.to_le_bytes().to_vec(),
                    })
                    .is_err()
                {
                    return Err(b"TVM log failed".to_vec());
                }
            }
            TvmInsn::AcceptRetTop => {
                let top = stack.pop().unwrap_or(0);
                return Ok(top.to_le_bytes().to_vec());
            }
        }
    }
    Ok(stack
        .pop()
        .map_or_else(Vec::new, |v| v.to_le_bytes().to_vec()))
}

/// Deterministic TVM execution environment worker (`EeId::TVM = 0x09`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TvmWorker {
    pub testnet_activation_height: Option<u64>,
}

impl Default for TvmWorker {
    fn default() -> Self {
        Self::new()
    }
}

impl TvmWorker {
    /// Open on testnet `45261` from [`PROPOSED_TVM_ACTIVATION_HEIGHT`] (`0`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            testnet_activation_height: Some(PROPOSED_TVM_ACTIVATION_HEIGHT),
        }
    }

    /// Override testnet activation height (or `None` to close TVM on `45261`).
    #[must_use]
    pub const fn with_activation_height(testnet_activation_height: Option<u64>) -> Self {
        Self {
            testnet_activation_height,
        }
    }

    /// Returns `true` when TVM is active at `ctx`.
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

impl ExecutionEnvironment for TvmWorker {
    fn id(&self) -> EeId {
        EeId::TVM
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        let _ = decode_tvm_blob(code)?;
        Ok(CodeInfo {
            code_hash: Sha256::digest(code).into(),
            abi_tag: String::from("tvm-cell-v1"),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let ns = Namespace::new(NS_TVM_STATE).map_err(ee_wire_fault)?;
        if !self.is_active(ctx) {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"TVM_CLOSED_ON_TESTNET".to_vec(),
                gas_used: 0,
            });
        }
        let mut gas_used = 1_000u64;
        if gas_used > call.gas_limit || host.charge(gas_used).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        }

        if call.kind == EeCallKind::Deploy {
            let Ok(contract) = decode_tvm_blob(&call.input) else {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"invalid TVM cell package".to_vec(),
                    gas_used,
                });
            };
            let addr = derive_tvm_addr(&call.caller.id, &call.tx_hash);
            if host
                .write(&ns, &code_key(&addr), Some(&call.input))
                .is_err()
            {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"TVM code write error".to_vec(),
                    gas_used,
                });
            }
            match run_tvm_body(
                &ns,
                &addr,
                &contract.init,
                &[],
                &mut gas_used,
                call.gas_limit,
                host,
            ) {
                Ok(_) => Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: addr.to_vec(),
                    gas_used,
                }),
                Err(e) if e == b"OUT_OF_GAS" => Ok(EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                }),
                Err(e) => Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: e,
                    gas_used,
                }),
            }
        } else {
            let Ok(target32) = <[u8; 32]>::try_from(call.target.id.as_slice()) else {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"TVM target must be 32 bytes".to_vec(),
                    gas_used,
                });
            };
            let Ok(Some(blob)) = host.read(&ns, &code_key(&target32)) else {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"TVM contract missing".to_vec(),
                    gas_used,
                });
            };
            let Ok(contract) = decode_tvm_blob(&blob) else {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"corrupt TVM blob".to_vec(),
                    gas_used,
                });
            };
            let Ok(msg) = serde_json::from_slice::<TvmInternalMsg>(&call.input) else {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"malformed TVM internal message".to_vec(),
                    gas_used,
                });
            };
            let Some(handler) = contract.handlers.iter().find(|h| h.op == msg.op) else {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"unknown TVM op".to_vec(),
                    gas_used,
                });
            };
            match run_tvm_body(
                &ns,
                &target32,
                &handler.body,
                &msg.args,
                &mut gas_used,
                call.gas_limit,
                host,
            ) {
                Ok(out) => Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: out,
                    gas_used,
                }),
                Err(e) if e == b"OUT_OF_GAS" => Ok(EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                }),
                Err(e) => Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: e,
                    gas_used,
                }),
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
            return Err(EeRefusal {
                code: RefusalCode::Denied,
                message: String::from("TVM_CLOSED_ON_TESTNET"),
            });
        }
        let ns = Namespace::new(NS_TVM_STATE).map_err(|e| EeRefusal {
            code: RefusalCode::Denied,
            message: e.to_string(),
        })?;
        let target32 = <[u8; 32]>::try_from(q.target.id.as_slice()).map_err(|_| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("TVM target must be 32 bytes"),
        })?;
        let slot = std::str::from_utf8(&q.input).map_err(|_| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("invalid c4 key"),
        })?;
        Ok(host
            .read(&ns, &c4_key(&target32, slot))
            .map_err(|e| EeRefusal {
                code: RefusalCode::Denied,
                message: e.to_string(),
            })?
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
    fn tvm_is_open_on_testnet() {
        let open = TvmWorker::new();
        assert!(open.is_active(&ctx()));
        let mut closed = TvmWorker::with_activation_height(None);
        assert!(!closed.is_active(&ctx()));
        let mut host = MemoryHost::new(1_000_000);
        let Ok(caller) = EeIdentity::new(EeId::TVM, vec![0x09; 32]) else {
            panic!("caller");
        };
        let Ok(out) = closed.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller,
                value: budlum_uel_abi::BudAmount(0),
                input: b"{}".to_vec(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x09; 32],
            },
            &mut host,
        ) else {
            panic!("exec");
        };
        assert_eq!(out.status, OutcomeStatus::Revert);
        assert_eq!(out.output, b"TVM_CLOSED_ON_TESTNET");
    }

    #[test]
    fn uel_conformance_tvm() {
        assert_eq!(AUDITED_TVM_SPDX, "MIT OR Apache-2.0");
        let mut worker = TvmWorker::new();
        let contract = TvmContract {
            init: vec![
                TvmInsn::PushInt(42),
                TvmInsn::StoreC4Word {
                    key: String::from("balance"),
                },
            ],
            handlers: vec![TvmMethod {
                op: 0x01,
                body: vec![
                    TvmInsn::LoadC4Word {
                        key: String::from("balance"),
                    },
                    TvmInsn::PushMsgWord(0),
                    TvmInsn::Add,
                    TvmInsn::StoreC4Word {
                        key: String::from("balance"),
                    },
                    TvmInsn::LoadC4Word {
                        key: String::from("balance"),
                    },
                    TvmInsn::EmitExtOut { topic: [0x77; 32] },
                    TvmInsn::AcceptRetTop,
                ],
            }],
        };
        let Ok(blob) = encode_tvm_blob(&contract) else {
            panic!("blob");
        };
        assert!(worker.validate_deploy(&blob).is_ok());

        let mut host = MemoryHost::new(5_000_000);
        let Ok(caller) = EeIdentity::new(EeId::TVM, vec![0x29; 32]) else {
            panic!("caller");
        };
        let Ok(dep) = worker.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: caller.clone(),
                target: caller.clone(),
                value: budlum_uel_abi::BudAmount(0),
                input: blob,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x21; 32],
            },
            &mut host,
        ) else {
            panic!("deploy");
        };
        assert_eq!(dep.status, OutcomeStatus::Success);
        let Ok(target) = EeIdentity::new(EeId::TVM, dep.output) else {
            panic!("target");
        };
        let Ok(msg) = serde_json::to_vec(&TvmInternalMsg {
            op: 0x01,
            args: vec![8],
        }) else {
            panic!("msg");
        };
        let Ok(res) = worker.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller,
                target: target.clone(),
                value: budlum_uel_abi::BudAmount(0),
                input: msg,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x22; 32],
            },
            &mut host,
        ) else {
            panic!("call");
        };
        assert_eq!(res.status, OutcomeStatus::Success);
        assert_eq!(res.output, 50i128.to_le_bytes());

        let Ok(q_bytes) = worker.query(
            &ctx(),
            &EeQuery {
                target,
                input: b"balance".to_vec(),
            },
            &host,
        ) else {
            panic!("query");
        };
        assert_eq!(q_bytes, 50i128.to_le_bytes());
    }
}
