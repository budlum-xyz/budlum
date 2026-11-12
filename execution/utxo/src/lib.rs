//! Out-of-process deterministic Bitcoin Script / Miniscript UEL verification
//! worker (`EeId::UTXO = 0x0A`).
//!
//! Runs strictly in verification-only mode (Bitcoin-style spending conditions
//! evaluated against Budlum assets persisted in `ee/utxo/state`), with no JIT
//! and deterministic execution across `x86_64` and `aarch64`.

#![forbid(unsafe_code)]

use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog, EeOutcome,
    EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, Namespace, OutcomeStatus,
    RefusalCode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Audited upstream SPDX license posture (`MIT`).
pub const AUDITED_UTXO_SPDX: &str = "MIT";

/// Budlum testnet chain ID (`45261`).
pub const BUDLUM_TESTNET_CHAIN_ID: u64 = 45_261;

/// Proposed testnet activation height (open from block zero on `45261`, `IP-53`).
pub const PROPOSED_UTXO_ACTIVATION_HEIGHT: u64 = 0;

/// Canonical UEL namespace storing locked UTXO spending scripts and unspent notes.
pub const NS_UTXO_STATE: &str = "ee/utxo/state";

/// Deterministic Budlum UTXO script container prefix (`"UTXO"`).
pub const UTXO_BLOB_MAGIC: &[u8; 4] = b"UTXO";

/// Maximum script program size (`64 KiB`).
pub const MAX_UTXO_SCRIPT_BYTES: usize = 65_536;

/// Deterministic Bitcoin Script / Miniscript verification opcodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptOp {
    PushBytes(Vec<u8>),
    PushNum(i64),
    OpDup,
    OpDrop,
    OpSha256,
    OpEqual,
    OpEqualVerify,
    OpVerify,
    OpAdd,
    OpGreaterThanOrEqual,
    OpCheckLockTimeVerify,
    OpCheckMultiSigHash { threshold: usize, pubkeys: Vec<Vec<u8>> },
    OpReturn,
}

/// Persisted UTXO covenant / locking script bundle encoded with [`UTXO_BLOB_MAGIC`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoLockScript {
    pub witness_ops: Vec<ScriptOp>,
    pub lock_ops: Vec<ScriptOp>,
    pub value_atoms: u64,
}

/// Witness payload passed when spending a deployed UTXO script (`EeCallKind::Call`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoSpendWitness {
    pub unlock_ops: Vec<ScriptOp>,
    pub recipient: [u8; 32],
}

/// Encodes a [`UtxoLockScript`] with [`UTXO_BLOB_MAGIC`].
///
/// # Errors
///
/// Returns [`EeRefusal`] if serialization fails or exceeds [`MAX_UTXO_SCRIPT_BYTES`].
pub fn encode_utxo_script(script: &UtxoLockScript) -> Result<Vec<u8>, EeRefusal> {
    let body = serde_json::to_vec(script).map_err(|e| EeRefusal {
        code: RefusalCode::InvalidCode,
        message: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(UTXO_BLOB_MAGIC);
    out.extend_from_slice(&body);
    if out.len() > MAX_UTXO_SCRIPT_BYTES {
        return Err(EeRefusal {
            code: RefusalCode::TooLarge,
            message: String::from("UTXO script exceeds 64 KiB limit"),
        });
    }
    Ok(out)
}

/// Decodes a [`UtxoLockScript`] from `bytes`.
///
/// # Errors
///
/// Returns [`EeRefusal`] if the header, bounds, or script syntax is invalid.
pub fn decode_utxo_script(bytes: &[u8]) -> Result<UtxoLockScript, EeRefusal> {
    if bytes.len() > MAX_UTXO_SCRIPT_BYTES {
        return Err(EeRefusal {
            code: RefusalCode::TooLarge,
            message: String::from("UTXO script exceeds 64 KiB limit"),
        });
    }
    let Some(rest) = bytes.strip_prefix(UTXO_BLOB_MAGIC) else {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("UTXO script missing UTXO header"),
        });
    };
    let parsed: UtxoLockScript = serde_json::from_slice(rest).map_err(|e| EeRefusal {
        code: RefusalCode::InvalidCode,
        message: format!("invalid UTXO script: {e}"),
    })?;
    if parsed.lock_ops.is_empty() {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("UTXO locking script cannot be empty"),
        });
    }
    Ok(parsed)
}

fn utxo_key(utxo_id: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(37);
    k.extend_from_slice(b"utxo:");
    k.extend_from_slice(utxo_id);
    k
}

fn spent_key(utxo_id: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(38);
    k.extend_from_slice(b"spent:");
    k.extend_from_slice(utxo_id);
    k
}

fn derive_utxo_id(caller: &[u8], tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"BDLM_UTXO_OUTPOINT_V1");
    h.update(caller);
    h.update(tx_hash);
    h.finalize().into()
}

fn ee_wire_fault(err: impl std::fmt::Display) -> EeFault {
    let msg = err.to_string();
    EeFault {
        ee: EeId::UTXO,
        panic_digest: budlum_uel_abi::panic_digest(EeId::UTXO, &msg),
    }
}

fn is_truthy(item: &[u8]) -> bool {
    item.iter().any(|&b| b != 0)
}

fn pop_i64(stack: &mut Vec<Vec<u8>>) -> Result<i64, Vec<u8>> {
    let Some(raw) = stack.pop() else {
        return Err(b"UTXO stack underflow".to_vec());
    };
    let Ok(arr) = <[u8; 8]>::try_from(raw.as_slice()) else {
        return Err(b"UTXO numeric operand must be 8-byte LE".to_vec());
    };
    Ok(i64::from_le_bytes(arr))
}

fn eval_script(
    ctx: &BlockContext,
    unlock_ops: &[ScriptOp],
    lock_ops: &[ScriptOp],
    tx_hash: &[u8; 32],
    gas_used: &mut u64,
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<(), Vec<u8>> {
    let mut stack: Vec<Vec<u8>> = Vec::new();
    for op in unlock_ops.iter().chain(lock_ops.iter()) {
        let Some(next) = gas_used.checked_add(250) else {
            return Err(b"OUT_OF_GAS".to_vec());
        };
        if next > gas_limit || host.charge(250).is_err() {
            return Err(b"OUT_OF_GAS".to_vec());
        }
        *gas_used = next;
        match op {
            ScriptOp::PushBytes(b) => stack.push(b.clone()),
            ScriptOp::PushNum(n) => stack.push(n.to_le_bytes().to_vec()),
            ScriptOp::OpDup => {
                let Some(top) = stack.last().cloned() else {
                    return Err(b"OP_DUP underflow".to_vec());
                };
                stack.push(top);
            }
            ScriptOp::OpDrop => {
                if stack.pop().is_none() {
                    return Err(b"OP_DROP underflow".to_vec());
                }
            }
            ScriptOp::OpSha256 => {
                let Some(top) = stack.pop() else {
                    return Err(b"OP_SHA256 underflow".to_vec());
                };
                let d: [u8; 32] = Sha256::digest(&top).into();
                stack.push(d.to_vec());
            }
            ScriptOp::OpEqual => {
                let (Some(b), Some(a)) = (stack.pop(), stack.pop()) else {
                    return Err(b"OP_EQUAL underflow".to_vec());
                };
                stack.push(if a == b { vec![1] } else { vec![0] });
            }
            ScriptOp::OpEqualVerify => {
                let (Some(b), Some(a)) = (stack.pop(), stack.pop()) else {
                    return Err(b"OP_EQUALVERIFY underflow".to_vec());
                };
                if a != b {
                    return Err(b"OP_EQUALVERIFY failed".to_vec());
                }
            }
            ScriptOp::OpVerify => {
                let Some(top) = stack.pop() else {
                    return Err(b"OP_VERIFY underflow".to_vec());
                };
                if !is_truthy(&top) {
                    return Err(b"OP_VERIFY failed".to_vec());
                }
            }
            ScriptOp::OpAdd => {
                let b = pop_i64(&mut stack)?;
                let a = pop_i64(&mut stack)?;
                let Some(sum) = a.checked_add(b) else {
                    return Err(b"OP_ADD overflow".to_vec());
                };
                stack.push(sum.to_le_bytes().to_vec());
            }
            ScriptOp::OpGreaterThanOrEqual => {
                let b = pop_i64(&mut stack)?;
                let a = pop_i64(&mut stack)?;
                stack.push(if a >= b { vec![1] } else { vec![0] });
            }
            ScriptOp::OpCheckLockTimeVerify => {
                let req = pop_i64(&mut stack)?;
                let Ok(req_height) = u64::try_from(req) else {
                    return Err(b"OP_CLTV negative height".to_vec());
                };
                if ctx.height < req_height {
                    return Err(b"OP_CLTV timelock unsatisfied".to_vec());
                }
                stack.push(req.to_le_bytes().to_vec());
            }
            ScriptOp::OpCheckMultiSigHash { threshold, pubkeys } => {
                if *threshold == 0 || *threshold > pubkeys.len() {
                    return Err(b"invalid multisig threshold".to_vec());
                }
                let mut verified = 0usize;
                for pk in pubkeys {
                    let Some(sig) = stack.pop() else {
                        break;
                    };
                    let mut h = Sha256::new();
                    h.update(b"BDLM_UTXO_SIG_COMMIT_V1");
                    h.update(pk);
                    h.update(tx_hash);
                    let expected: [u8; 32] = h.finalize().into();
                    if sig == expected {
                        verified += 1;
                    }
                }
                stack.push(if verified >= *threshold {
                    vec![1]
                } else {
                    vec![0]
                });
            }
            ScriptOp::OpReturn => {
                return Err(b"OP_RETURN unspendable output".to_vec());
            }
        }
    }
    let Some(top) = stack.pop() else {
        return Err(b"UTXO script finished with empty stack".to_vec());
    };
    if !is_truthy(&top) {
        return Err(b"UTXO script top-of-stack false".to_vec());
    }
    Ok(())
}

/// Deterministic Bitcoin Script verification execution environment (`EeId::UTXO = 0x0A`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtxoScriptWorker {
    pub testnet_activation_height: Option<u64>,
}

impl Default for UtxoScriptWorker {
    fn default() -> Self {
        Self::new()
    }
}

impl UtxoScriptWorker {
    /// Open on testnet `45261` from [`PROPOSED_UTXO_ACTIVATION_HEIGHT`] (`0`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            testnet_activation_height: Some(PROPOSED_UTXO_ACTIVATION_HEIGHT),
        }
    }

    /// Override testnet activation height (or `None` to keep closed on `45261`).
    #[must_use]
    pub const fn with_activation_height(testnet_activation_height: Option<u64>) -> Self {
        Self {
            testnet_activation_height,
        }
    }

    /// Returns `true` when UTXO verification is active at `ctx`.
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

impl ExecutionEnvironment for UtxoScriptWorker {
    fn id(&self) -> EeId {
        EeId::UTXO
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        let _ = decode_utxo_script(code)?;
        Ok(CodeInfo {
            code_hash: Sha256::digest(code).into(),
            abi_tag: String::from("utxo-script-v1"),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let ns = Namespace::new(NS_UTXO_STATE).map_err(ee_wire_fault)?;
        if !self.is_active(ctx) {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"UTXO_CLOSED_ON_TESTNET".to_vec(),
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
            let Ok(_script) = decode_utxo_script(&call.input) else {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"invalid UTXO script".to_vec(),
                    gas_used,
                });
            };
            let utxo_id = derive_utxo_id(&call.caller.id, &call.tx_hash);
            if host
                .write(&ns, &utxo_key(&utxo_id), Some(&call.input))
                .is_err()
            {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"UTXO write failed".to_vec(),
                    gas_used,
                });
            }
            return Ok(EeOutcome {
                status: OutcomeStatus::Success,
                output: utxo_id.to_vec(),
                gas_used,
            });
        }

        let Ok(utxo_id) = <[u8; 32]>::try_from(call.target.id.as_slice()) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"UTXO id must be 32 bytes".to_vec(),
                gas_used,
            });
        };
        if host.read(&ns, &spent_key(&utxo_id)).ok().flatten().is_some() {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"UTXO already spent".to_vec(),
                gas_used,
            });
        }
        let Ok(Some(blob)) = host.read(&ns, &utxo_key(&utxo_id)) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"UTXO not found".to_vec(),
                gas_used,
            });
        };
        let Ok(lock) = decode_utxo_script(&blob) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"corrupt UTXO script".to_vec(),
                gas_used,
            });
        };
        let Ok(witness) = serde_json::from_slice::<UtxoSpendWitness>(&call.input) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"malformed UTXO witness".to_vec(),
                gas_used,
            });
        };

        if let Err(err) = eval_script(
            ctx,
            &witness.unlock_ops,
            &lock.lock_ops,
            &call.tx_hash,
            &mut gas_used,
            call.gas_limit,
            host,
        ) {
            if err == b"OUT_OF_GAS" {
                return Ok(EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                });
            }
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: err,
                gas_used,
            });
        }

        if host.write(&ns, &spent_key(&utxo_id), Some(&witness.recipient)).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"failed to record UTXO spend".to_vec(),
                gas_used,
            });
        }
        let _ = host.emit_log(EeLog {
            emitter: EeIdentity {
                ee: EeId::UTXO,
                id: utxo_id.to_vec(),
            },
            topics: vec![witness.recipient.to_vec()],
            data: lock.value_atoms.to_le_bytes().to_vec(),
        });
        Ok(EeOutcome {
            status: OutcomeStatus::Success,
            output: witness.recipient.to_vec(),
            gas_used,
        })
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
                message: String::from("UTXO_CLOSED_ON_TESTNET"),
            });
        }
        let ns = Namespace::new(NS_UTXO_STATE).map_err(|e| EeRefusal {
            code: RefusalCode::Denied,
            message: e.to_string(),
        })?;
        let utxo_id = <[u8; 32]>::try_from(q.target.id.as_slice()).map_err(|_| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("UTXO id must be 32 bytes"),
        })?;
        let spent = host
            .read(&ns, &spent_key(&utxo_id))
            .map_err(|e| EeRefusal {
                code: RefusalCode::Denied,
                message: e.to_string(),
            })?
            .is_some();
        Ok(vec![u8::from(spent)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budlum_uel_abi::mock::MemoryHost;

    fn ctx(height: u64) -> BlockContext {
        BlockContext {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            height,
            timestamp_ms: 1_793_923_200_000,
        }
    }

    #[test]
    fn utxo_is_open_on_testnet() {
        let open = UtxoScriptWorker::new();
        assert!(open.is_active(&ctx(0)));
        let mut closed = UtxoScriptWorker::with_activation_height(None);
        assert!(!closed.is_active(&ctx(0)));
        let mut host = MemoryHost::new(1_000_000);
        let Ok(caller) = EeIdentity::new(EeId::UTXO, vec![0x0A; 32]) else {
            panic!("caller");
        };
        let Ok(out) = closed.execute(
            &ctx(0),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller,
                value: budlum_uel_abi::BudAmount(0),
                input: b"{}".to_vec(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x0A; 32],
            },
            &mut host,
        ) else {
            panic!("exec");
        };
        assert_eq!(out.status, OutcomeStatus::Revert);
        assert_eq!(out.output, b"UTXO_CLOSED_ON_TESTNET");
    }

    #[test]
    fn uel_conformance_utxo() {
        assert_eq!(AUDITED_UTXO_SPDX, "MIT");
        let mut worker = UtxoScriptWorker::new();
        let preimage = b"budlum-htlc-secret".to_vec();
        let hash: [u8; 32] = Sha256::digest(&preimage).into();
        let lock = UtxoLockScript {
            witness_ops: Vec::new(),
            lock_ops: vec![
                ScriptOp::PushNum(5),
                ScriptOp::OpCheckLockTimeVerify,
                ScriptOp::OpDrop,
                ScriptOp::OpSha256,
                ScriptOp::PushBytes(hash.to_vec()),
                ScriptOp::OpEqual,
            ],
            value_atoms: 25_000,
        };
        let Ok(blob) = encode_utxo_script(&lock) else {
            panic!("blob");
        };
        assert!(worker.validate_deploy(&blob).is_ok());

        let mut host = MemoryHost::new(5_000_000);
        let Ok(caller) = EeIdentity::new(EeId::UTXO, vec![0x1A; 32]) else {
            panic!("caller");
        };
        let Ok(dep) = worker.execute(
            &ctx(5),
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: caller.clone(),
                target: caller.clone(),
                value: budlum_uel_abi::BudAmount(0),
                input: blob,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x31; 32],
            },
            &mut host,
        ) else {
            panic!("deploy");
        };
        assert_eq!(dep.status, OutcomeStatus::Success);
        let Ok(target) = EeIdentity::new(EeId::UTXO, dep.output) else {
            panic!("target");
        };

        let Ok(bad_witness) = serde_json::to_vec(&UtxoSpendWitness {
            unlock_ops: vec![ScriptOp::PushBytes(b"wrong".to_vec())],
            recipient: [0x99; 32],
        }) else {
            panic!("bad witness");
        };
        let Ok(early) = worker.execute(
            &ctx(4),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: target.clone(),
                value: budlum_uel_abi::BudAmount(0),
                input: bad_witness,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x32; 32],
            },
            &mut host,
        ) else {
            panic!("early");
        };
        assert_eq!(early.status, OutcomeStatus::Revert);

        let Ok(good_witness) = serde_json::to_vec(&UtxoSpendWitness {
            unlock_ops: vec![ScriptOp::PushBytes(preimage)],
            recipient: [0x77; 32],
        }) else {
            panic!("good witness");
        };
        let Ok(spent) = worker.execute(
            &ctx(5),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: target.clone(),
                value: budlum_uel_abi::BudAmount(0),
                input: good_witness.clone(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x33; 32],
            },
            &mut host,
        ) else {
            panic!("spend");
        };
        assert_eq!(spent.status, OutcomeStatus::Success);
        assert_eq!(spent.output, [0x77; 32]);

        let Ok(double_spend) = worker.execute(
            &ctx(6),
            &EeCall {
                kind: EeCallKind::Call,
                caller,
                target: target.clone(),
                value: budlum_uel_abi::BudAmount(0),
                input: good_witness,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x34; 32],
            },
            &mut host,
        ) else {
            panic!("double spend");
        };
        assert_eq!(double_spend.status, OutcomeStatus::Revert);

        let Ok(q_bytes) = worker.query(
            &ctx(6),
            &EeQuery {
                target,
                input: Vec::new(),
            },
            &host,
        ) else {
            panic!("query");
        };
        assert_eq!(q_bytes, vec![1]);
    }
}
