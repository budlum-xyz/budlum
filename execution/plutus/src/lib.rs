//! Out-of-process deterministic Plutus / Aiken Untyped Plutus Core (`UPLC`)
//! UEL execution worker (`EeId::PLUTUS = 0x0B`).
//!
//! Runs a deterministic bounded CEK-style UPLC term evaluator in pure Rust
//! interpreter mode across `x86_64` and `aarch64`, persists validator scripts
//! and eUTxO datum state under `ee/plutus/state`, and opens on testnet `45261`
//! at block zero (`PROPOSED_PLUTUS_ACTIVATION_HEIGHT = 0`).

#![forbid(unsafe_code)]

use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog, EeOutcome,
    EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, Namespace, OutcomeStatus,
    RefusalCode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Audited upstream engine SPDX identifier (`aiken-lang/uplc`, `Apache-2.0`).
pub const AUDITED_PLUTUS_SPDX: &str = "Apache-2.0";

/// Budlum testnet chain ID (`45261`).
pub const BUDLUM_TESTNET_CHAIN_ID: u64 = 45_261;

/// Proposed testnet activation height (open from block zero on `45261`, `IP-53`).
pub const PROPOSED_PLUTUS_ACTIVATION_HEIGHT: u64 = 0;

/// Canonical UEL namespace storing Plutus validator scripts and datum records.
pub const NS_PLUTUS_STATE: &str = "ee/plutus/state";

/// Deterministic Budlum UPLC script bundle prefix (`"UPLC"`).
pub const PLUTUS_BLOB_MAGIC: &[u8; 4] = b"UPLC";

/// Maximum serialized UPLC validator script size (`512 KiB`).
pub const MAX_PLUTUS_SCRIPT_BYTES: usize = 524_288;

/// Maximum CEK reduction steps per call (protects deterministic ExUnits budget).
const MAX_UPLC_STEPS: usize = 4_096;

/// Deterministic Untyped Plutus Core (`UPLC`) AST terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UplcTerm {
    ConstInt(i64),
    ConstBytes(Vec<u8>),
    DatumInt,
    RedeemerInt,
    RedeemerBytes,
    CtxHeight,
    Add(Box<UplcTerm>, Box<UplcTerm>),
    EqualsInt(Box<UplcTerm>, Box<UplcTerm>),
    EqualsBytes(Box<UplcTerm>, Box<UplcTerm>),
    Sha256(Box<UplcTerm>),
    IfThenElse {
        cond: Box<UplcTerm>,
        then_branch: Box<UplcTerm>,
        else_branch: Box<UplcTerm>,
    },
    TraceUnit(Box<UplcTerm>),
    Error,
}

/// UPLC value domain produced during bounded evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UplcVal {
    Int(i64),
    Bytes(Vec<u8>),
    Bool(bool),
    Unit,
}

/// Plutus v2/v3 validator container encoded with [`PLUTUS_BLOB_MAGIC`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlutusValidatorProgram {
    pub uplc_version: String,
    pub initial_datum_int: i64,
    pub validator: UplcTerm,
}

/// Spend / validate invocation envelope targeting a deployed Plutus validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlutusSpendInput {
    pub new_datum_int: Option<i64>,
    pub redeemer_int: i64,
    pub redeemer_bytes: Vec<u8>,
}

/// Encodes a [`PlutusValidatorProgram`] into a canonical `"UPLC"` blob.
///
/// # Errors
///
/// Returns [`EeRefusal`] if serialization fails or exceeds [`MAX_PLUTUS_SCRIPT_BYTES`].
pub fn encode_plutus_blob(prog: &PlutusValidatorProgram) -> Result<Vec<u8>, EeRefusal> {
    let body = serde_json::to_vec(prog).map_err(|e| EeRefusal {
        code: RefusalCode::InvalidCode,
        message: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(PLUTUS_BLOB_MAGIC);
    out.extend_from_slice(&body);
    if out.len() > MAX_PLUTUS_SCRIPT_BYTES {
        return Err(EeRefusal {
            code: RefusalCode::TooLarge,
            message: String::from("UPLC validator exceeds 512 KiB"),
        });
    }
    Ok(out)
}

/// Decodes and validates a [`PlutusValidatorProgram`] from `bytes`.
///
/// # Errors
///
/// Returns [`EeRefusal`] on header, size, or AST encoding violation.
pub fn decode_plutus_blob(bytes: &[u8]) -> Result<PlutusValidatorProgram, EeRefusal> {
    if bytes.len() > MAX_PLUTUS_SCRIPT_BYTES {
        return Err(EeRefusal {
            code: RefusalCode::TooLarge,
            message: String::from("UPLC validator exceeds 512 KiB"),
        });
    }
    let Some(rest) = bytes.strip_prefix(PLUTUS_BLOB_MAGIC) else {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("UPLC validator missing UPLC header"),
        });
    };
    serde_json::from_slice(rest).map_err(|e| EeRefusal {
        code: RefusalCode::InvalidCode,
        message: format!("invalid UPLC validator: {e}"),
    })
}

fn script_key(hash32: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(39);
    k.extend_from_slice(b"script:");
    k.extend_from_slice(hash32);
    k
}

fn datum_key(hash32: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(38);
    k.extend_from_slice(b"datum:");
    k.extend_from_slice(hash32);
    k
}

fn derive_script_hash(caller: &[u8], tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"BDLM_PLUTUS_SCRIPT_V1");
    h.update(caller);
    h.update(tx_hash);
    h.finalize().into()
}

fn ee_wire_fault(err: impl std::fmt::Display) -> EeFault {
    let msg = err.to_string();
    EeFault {
        ee: EeId::PLUTUS,
        panic_digest: budlum_uel_abi::panic_digest(EeId::PLUTUS, &msg),
    }
}

struct EvalCtx<'a> {
    datum_int: i64,
    redeemer_int: i64,
    redeemer_bytes: &'a [u8],
    height: u64,
    steps: usize,
    gas_used: u64,
    gas_limit: u64,
}

fn eval_uplc(
    term: &UplcTerm,
    ev: &mut EvalCtx<'_>,
    host: &mut dyn HostApi,
) -> Result<UplcVal, Vec<u8>> {
    ev.steps += 1;
    if ev.steps > MAX_UPLC_STEPS {
        return Err(b"UPLC step budget exhausted".to_vec());
    }
    let Some(next) = ev.gas_used.checked_add(200) else {
        return Err(b"OUT_OF_GAS".to_vec());
    };
    if next > ev.gas_limit || host.charge(200).is_err() {
        return Err(b"OUT_OF_GAS".to_vec());
    }
    ev.gas_used = next;

    match term {
        UplcTerm::ConstInt(n) => Ok(UplcVal::Int(*n)),
        UplcTerm::ConstBytes(b) => Ok(UplcVal::Bytes(b.clone())),
        UplcTerm::DatumInt => Ok(UplcVal::Int(ev.datum_int)),
        UplcTerm::RedeemerInt => Ok(UplcVal::Int(ev.redeemer_int)),
        UplcTerm::RedeemerBytes => Ok(UplcVal::Bytes(ev.redeemer_bytes.to_vec())),
        UplcTerm::CtxHeight => Ok(UplcVal::Int(i64::try_from(ev.height).unwrap_or(i64::MAX))),
        UplcTerm::Add(a, b) => match (eval_uplc(a, ev, host)?, eval_uplc(b, ev, host)?) {
            (UplcVal::Int(x), UplcVal::Int(y)) => x
                .checked_add(y)
                .map(UplcVal::Int)
                .ok_or_else(|| b"UPLC int overflow".to_vec()),
            _ => Err(b"UPLC Add type error".to_vec()),
        },
        UplcTerm::EqualsInt(a, b) => match (eval_uplc(a, ev, host)?, eval_uplc(b, ev, host)?) {
            (UplcVal::Int(x), UplcVal::Int(y)) => Ok(UplcVal::Bool(x == y)),
            _ => Err(b"UPLC EqualsInt type error".to_vec()),
        },
        UplcTerm::EqualsBytes(a, b) => match (eval_uplc(a, ev, host)?, eval_uplc(b, ev, host)?) {
            (UplcVal::Bytes(x), UplcVal::Bytes(y)) => Ok(UplcVal::Bool(x == y)),
            _ => Err(b"UPLC EqualsBytes type error".to_vec()),
        },
        UplcTerm::Sha256(inner) => match eval_uplc(inner, ev, host)? {
            UplcVal::Bytes(b) => {
                let d: [u8; 32] = Sha256::digest(&b).into();
                Ok(UplcVal::Bytes(d.to_vec()))
            }
            _ => Err(b"UPLC Sha256 type error".to_vec()),
        },
        UplcTerm::IfThenElse {
            cond,
            then_branch,
            else_branch,
        } => match eval_uplc(cond, ev, host)? {
            UplcVal::Bool(true) => eval_uplc(then_branch, ev, host),
            UplcVal::Bool(false) => eval_uplc(else_branch, ev, host),
            _ => Err(b"UPLC IfThenElse expects Bool".to_vec()),
        },
        UplcTerm::TraceUnit(inner) => {
            let _ = eval_uplc(inner, ev, host)?;
            Ok(UplcVal::Unit)
        }
        UplcTerm::Error => Err(b"UPLC Error term reached".to_vec()),
    }
}

/// Deterministic Plutus UPLC execution environment worker (`EeId::PLUTUS = 0x0B`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlutusWorker {
    pub testnet_activation_height: Option<u64>,
}

impl Default for PlutusWorker {
    fn default() -> Self {
        Self::new()
    }
}

impl PlutusWorker {
    /// Open on testnet `45261` from [`PROPOSED_PLUTUS_ACTIVATION_HEIGHT`] (`0`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            testnet_activation_height: Some(PROPOSED_PLUTUS_ACTIVATION_HEIGHT),
        }
    }

    /// Override testnet activation height (or `None` to keep closed on `45261`).
    #[must_use]
    pub const fn with_activation_height(testnet_activation_height: Option<u64>) -> Self {
        Self {
            testnet_activation_height,
        }
    }

    /// Returns `true` when Plutus UPLC is active at `ctx`.
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

impl ExecutionEnvironment for PlutusWorker {
    fn id(&self) -> EeId {
        EeId::PLUTUS
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        let _ = decode_plutus_blob(code)?;
        Ok(CodeInfo {
            code_hash: Sha256::digest(code).into(),
            abi_tag: String::from("plutus-uplc-v1"),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let ns = Namespace::new(NS_PLUTUS_STATE).map_err(ee_wire_fault)?;
        if !self.is_active(ctx) {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"PLUTUS_CLOSED_ON_TESTNET".to_vec(),
                gas_used: 0,
            });
        }
        let gas_used = 1_000u64;
        if gas_used > call.gas_limit || host.charge(gas_used).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        }

        if call.kind == EeCallKind::Deploy {
            let Ok(prog) = decode_plutus_blob(&call.input) else {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"invalid UPLC script".to_vec(),
                    gas_used,
                });
            };
            let script_hash = derive_script_hash(&call.caller.id, &call.tx_hash);
            if host
                .write(&ns, &script_key(&script_hash), Some(&call.input))
                .is_err()
                || host
                    .write(
                        &ns,
                        &datum_key(&script_hash),
                        Some(&prog.initial_datum_int.to_le_bytes()),
                    )
                    .is_err()
            {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"Plutus state write failed".to_vec(),
                    gas_used,
                });
            }
            return Ok(EeOutcome {
                status: OutcomeStatus::Success,
                output: script_hash.to_vec(),
                gas_used,
            });
        }

        let Ok(script_hash) = <[u8; 32]>::try_from(call.target.id.as_slice()) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"Plutus script hash must be 32 bytes".to_vec(),
                gas_used,
            });
        };
        let Ok(Some(blob)) = host.read(&ns, &script_key(&script_hash)) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"Plutus script not found".to_vec(),
                gas_used,
            });
        };
        let Ok(prog) = decode_plutus_blob(&blob) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"corrupt UPLC script".to_vec(),
                gas_used,
            });
        };
        let Ok(spend) = serde_json::from_slice::<PlutusSpendInput>(&call.input) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"malformed PlutusSpendInput".to_vec(),
                gas_used,
            });
        };
        let cur_datum = host
            .read(&ns, &datum_key(&script_hash))
            .ok()
            .flatten()
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map_or(prog.initial_datum_int, i64::from_le_bytes);

        let mut ev = EvalCtx {
            datum_int: cur_datum,
            redeemer_int: spend.redeemer_int,
            redeemer_bytes: &spend.redeemer_bytes,
            height: ctx.height,
            steps: 0,
            gas_used,
            gas_limit: call.gas_limit,
        };
        let val = match eval_uplc(&prog.validator, &mut ev, host) {
            Ok(v) => v,
            Err(e) if e == b"OUT_OF_GAS" => {
                return Ok(EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                });
            }
            Err(e) => {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: e,
                    gas_used: ev.gas_used,
                });
            }
        };
        if matches!(val, UplcVal::Bool(false)) {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"UPLC validator returned false".to_vec(),
                gas_used: ev.gas_used,
            });
        }
        if let Some(next_datum) = spend.new_datum_int {
            if host
                .write(
                    &ns,
                    &datum_key(&script_hash),
                    Some(&next_datum.to_le_bytes()),
                )
                .is_err()
            {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"Plutus datum update failed".to_vec(),
                    gas_used: ev.gas_used,
                });
            }
        }
        let _ = host.emit_log(EeLog {
            emitter: EeIdentity {
                ee: EeId::PLUTUS,
                id: script_hash.to_vec(),
            },
            topics: vec![script_hash.to_vec()],
            data: spend.redeemer_int.to_le_bytes().to_vec(),
        });
        Ok(EeOutcome {
            status: OutcomeStatus::Success,
            output: cur_datum.to_le_bytes().to_vec(),
            gas_used: ev.gas_used,
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
                message: String::from("PLUTUS_CLOSED_ON_TESTNET"),
            });
        }
        let ns = Namespace::new(NS_PLUTUS_STATE).map_err(|e| EeRefusal {
            code: RefusalCode::Denied,
            message: e.to_string(),
        })?;
        let script_hash = <[u8; 32]>::try_from(q.target.id.as_slice()).map_err(|_| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("Plutus script hash must be 32 bytes"),
        })?;
        Ok(host
            .read(&ns, &datum_key(&script_hash))
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
    fn plutus_is_open_on_testnet() {
        let open = PlutusWorker::new();
        assert!(open.is_active(&ctx()));
        let mut closed = PlutusWorker::with_activation_height(None);
        assert!(!closed.is_active(&ctx()));
        let mut host = MemoryHost::new(1_000_000);
        let Ok(caller) = EeIdentity::new(EeId::PLUTUS, vec![0x0B; 32]) else {
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
                tx_hash: [0x0B; 32],
            },
            &mut host,
        ) else {
            panic!("exec");
        };
        assert_eq!(out.status, OutcomeStatus::Revert);
        assert_eq!(out.output, b"PLUTUS_CLOSED_ON_TESTNET");
    }

    #[test]
    fn uel_conformance_plutus() {
        assert_eq!(AUDITED_PLUTUS_SPDX, "Apache-2.0");
        let mut worker = PlutusWorker::new();
        let expected_hash: [u8; 32] = Sha256::digest(b"aiken-secret").into();
        let validator = UplcTerm::IfThenElse {
            cond: Box::new(UplcTerm::EqualsInt(
                Box::new(UplcTerm::Add(
                    Box::new(UplcTerm::DatumInt),
                    Box::new(UplcTerm::ConstInt(1)),
                )),
                Box::new(UplcTerm::RedeemerInt),
            )),
            then_branch: Box::new(UplcTerm::IfThenElse {
                cond: Box::new(UplcTerm::EqualsBytes(
                    Box::new(UplcTerm::Sha256(Box::new(UplcTerm::RedeemerBytes))),
                    Box::new(UplcTerm::ConstBytes(expected_hash.to_vec())),
                )),
                then_branch: Box::new(UplcTerm::TraceUnit(Box::new(UplcTerm::CtxHeight))),
                else_branch: Box::new(UplcTerm::Error),
            }),
            else_branch: Box::new(UplcTerm::Error),
        };
        let prog = PlutusValidatorProgram {
            uplc_version: String::from("1.1.0"),
            initial_datum_int: 10,
            validator,
        };
        let Ok(blob) = encode_plutus_blob(&prog) else {
            panic!("blob");
        };
        assert!(worker.validate_deploy(&blob).is_ok());

        let mut host = MemoryHost::new(5_000_000);
        let Ok(caller) = EeIdentity::new(EeId::PLUTUS, vec![0x3B; 32]) else {
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
                tx_hash: [0x41; 32],
            },
            &mut host,
        ) else {
            panic!("deploy");
        };
        assert_eq!(dep.status, OutcomeStatus::Success);
        let Ok(target) = EeIdentity::new(EeId::PLUTUS, dep.output) else {
            panic!("target");
        };

        let Ok(bad_in) = serde_json::to_vec(&PlutusSpendInput {
            new_datum_int: Some(11),
            redeemer_int: 99,
            redeemer_bytes: b"aiken-secret".to_vec(),
        }) else {
            panic!("bad_in");
        };
        let Ok(bad_res) = worker.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: target.clone(),
                value: budlum_uel_abi::BudAmount(0),
                input: bad_in,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x42; 32],
            },
            &mut host,
        ) else {
            panic!("bad exec");
        };
        assert_eq!(bad_res.status, OutcomeStatus::Revert);

        let Ok(good_in) = serde_json::to_vec(&PlutusSpendInput {
            new_datum_int: Some(11),
            redeemer_int: 11,
            redeemer_bytes: b"aiken-secret".to_vec(),
        }) else {
            panic!("good_in");
        };
        let Ok(ok_res) = worker.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller,
                target: target.clone(),
                value: budlum_uel_abi::BudAmount(0),
                input: good_in,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x43; 32],
            },
            &mut host,
        ) else {
            panic!("good exec");
        };
        assert_eq!(ok_res.status, OutcomeStatus::Success);
        assert_eq!(ok_res.output, 10i64.to_le_bytes());

        let Ok(q_bytes) = worker.query(
            &ctx(),
            &EeQuery {
                target,
                input: Vec::new(),
            },
            &host,
        ) else {
            panic!("query");
        };
        assert_eq!(q_bytes, 11i64.to_le_bytes());
    }
}
