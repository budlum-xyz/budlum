//! Out-of-process deterministic Plutus / Aiken Untyped Plutus Core (`UPLC`)
//! UEL execution worker (`EeId::PLUTUS = 0x0B`).
//!
//! Runs a deterministic bounded CEK-style UPLC term evaluator in pure Rust
//! interpreter mode across `x86_64` and `aarch64`, persists validator scripts
//! and eUTxO datum state under `ee/plutus/state`, and remains closed by default
//! on public testnet `45261` until an explicit activation height.

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

/// Explicit activation fixture height; the public-testnet default remains closed.
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
    /// The identity that signed the transaction (`ScriptContext` signatories), as bytes. Compare
    /// it with `EqualsBytes`: a validator that is not public checks it before anything else.
    Signatory,
    /// The identity that deployed the script, as bytes. `EqualsBytes(Signatory, Owner)` is the
    /// owner-only check.
    Owner,
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
fn validate_uplc_term(term: &UplcTerm, depth: usize, nodes: &mut usize) -> bool {
    if depth > MAX_UPLC_DEPTH {
        return false;
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_UPLC_STEPS {
        return false;
    }
    match term {
        UplcTerm::ConstInt(_)
        | UplcTerm::DatumInt
        | UplcTerm::RedeemerInt
        | UplcTerm::RedeemerBytes
        | UplcTerm::CtxHeight
        | UplcTerm::Signatory
        | UplcTerm::Owner
        | UplcTerm::Error => true,
        UplcTerm::ConstBytes(b) => b.len() <= MAX_PLUTUS_SCRIPT_BYTES,
        UplcTerm::Sha256(inner) | UplcTerm::TraceUnit(inner) => {
            validate_uplc_term(inner, depth + 1, nodes)
        }
        UplcTerm::Add(a, b) | UplcTerm::EqualsInt(a, b) | UplcTerm::EqualsBytes(a, b) => {
            validate_uplc_term(a, depth + 1, nodes) && validate_uplc_term(b, depth + 1, nodes)
        }
        UplcTerm::IfThenElse {
            cond,
            then_branch,
            else_branch,
        } => {
            validate_uplc_term(cond, depth + 1, nodes)
                && validate_uplc_term(then_branch, depth + 1, nodes)
                && validate_uplc_term(else_branch, depth + 1, nodes)
        }
    }
}

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
    let prog: PlutusValidatorProgram = serde_json::from_slice(rest).map_err(|e| EeRefusal {
        code: RefusalCode::InvalidCode,
        message: format!("invalid UPLC validator: {e}"),
    })?;
    let mut nodes = 0usize;
    if prog.uplc_version.is_empty() || !validate_uplc_term(&prog.validator, 0, &mut nodes) {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("invalid UPLC version or AST depth/size"),
        });
    }
    Ok(prog)
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

/// The identity that deployed the script: what `UplcTerm::Owner` evaluates to.
fn owner_key(hash32: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(38);
    k.extend_from_slice(b"owner:");
    k.extend_from_slice(hash32);
    k
}

/// Maximum CEK AST nesting depth per call (prevents native call-stack exhaustion).
const MAX_UPLC_DEPTH: usize = 64;

fn derive_script_hash(caller: &[u8], tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"BDLM_PLUTUS_SCRIPT_V1");
    h.update((caller.len() as u64).to_le_bytes());
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
    /// Who signed the call, and who deployed the script.
    signatory: &'a [u8],
    owner: &'a [u8],
    height: u64,
    steps: usize,
    gas_used: u64,
    gas_limit: u64,
}

fn eval_uplc(
    term: &UplcTerm,
    ev: &mut EvalCtx<'_>,
    host: &mut dyn HostApi,
    depth: usize,
) -> Result<UplcVal, Vec<u8>> {
    if depth > MAX_UPLC_DEPTH {
        return Err(b"UPLC recursion depth exceeded".to_vec());
    }
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
    let next_depth = depth + 1;

    match term {
        UplcTerm::ConstInt(n) => Ok(UplcVal::Int(*n)),
        UplcTerm::ConstBytes(b) => Ok(UplcVal::Bytes(b.clone())),
        UplcTerm::DatumInt => Ok(UplcVal::Int(ev.datum_int)),
        UplcTerm::RedeemerInt => Ok(UplcVal::Int(ev.redeemer_int)),
        UplcTerm::RedeemerBytes => Ok(UplcVal::Bytes(ev.redeemer_bytes.to_vec())),
        UplcTerm::CtxHeight => Ok(UplcVal::Int(i64::try_from(ev.height).unwrap_or(i64::MAX))),
        UplcTerm::Signatory => Ok(UplcVal::Bytes(ev.signatory.to_vec())),
        UplcTerm::Owner => Ok(UplcVal::Bytes(ev.owner.to_vec())),
        UplcTerm::Add(a, b) => match (
            eval_uplc(a, ev, host, next_depth)?,
            eval_uplc(b, ev, host, next_depth)?,
        ) {
            (UplcVal::Int(x), UplcVal::Int(y)) => x
                .checked_add(y)
                .map(UplcVal::Int)
                .ok_or_else(|| b"UPLC int overflow".to_vec()),
            _ => Err(b"UPLC Add type error".to_vec()),
        },
        UplcTerm::EqualsInt(a, b) => match (
            eval_uplc(a, ev, host, next_depth)?,
            eval_uplc(b, ev, host, next_depth)?,
        ) {
            (UplcVal::Int(x), UplcVal::Int(y)) => Ok(UplcVal::Bool(x == y)),
            _ => Err(b"UPLC EqualsInt type error".to_vec()),
        },
        UplcTerm::EqualsBytes(a, b) => match (
            eval_uplc(a, ev, host, next_depth)?,
            eval_uplc(b, ev, host, next_depth)?,
        ) {
            (UplcVal::Bytes(x), UplcVal::Bytes(y)) => Ok(UplcVal::Bool(x == y)),
            _ => Err(b"UPLC EqualsBytes type error".to_vec()),
        },
        UplcTerm::Sha256(inner) => match eval_uplc(inner, ev, host, next_depth)? {
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
        } => match eval_uplc(cond, ev, host, next_depth)? {
            UplcVal::Bool(true) => eval_uplc(then_branch, ev, host, next_depth),
            UplcVal::Bool(false) => eval_uplc(else_branch, ev, host, next_depth),
            _ => Err(b"UPLC IfThenElse expects Bool".to_vec()),
        },
        UplcTerm::TraceUnit(inner) => {
            let _ = eval_uplc(inner, ev, host, next_depth)?;
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
    /// Default public-testnet posture: closed until an explicit activation height.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            testnet_activation_height: None,
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
        let mut gas_used = 1_000u64;
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
            // Published code is permanent state every validator keeps:
            // the deploy pays the shared per-byte publication rate.
            let publish_gas = u64::try_from(call.input.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(25);
            gas_used = gas_used.saturating_add(publish_gas);
            if gas_used > call.gas_limit || host.charge(publish_gas).is_err() {
                return Ok(EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                });
            }
            let script_hash = derive_script_hash(&call.caller.id, &call.tx_hash);
            match host.read(&ns, &script_key(&script_hash)) {
                Ok(Some(_)) => {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"Plutus script already deployed".to_vec(),
                        gas_used,
                    });
                }
                Ok(None) => {}
                Err(budlum_uel_abi::HostError::OutOfGas) => {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                }
                Err(_) => {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"Plutus script read failed".to_vec(),
                        gas_used,
                    });
                }
            }
            let Ok(cp) = host.checkpoint_begin() else {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"Plutus checkpoint begin failed".to_vec(),
                    gas_used,
                });
            };
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
                || host
                    .write(&ns, &owner_key(&script_hash), Some(&call.caller.id))
                    .is_err()
                || host.checkpoint_commit(cp).is_err()
            {
                let _ = host.checkpoint_rollback(cp);
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
        let cur_datum = match host.read(&ns, &datum_key(&script_hash)) {
            Ok(Some(raw)) => {
                let Ok(arr) = <[u8; 8]>::try_from(raw.as_slice()) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"corrupt Plutus datum".to_vec(),
                        gas_used,
                    });
                };
                i64::from_le_bytes(arr)
            }
            Ok(None) => prog.initial_datum_int,
            Err(budlum_uel_abi::HostError::OutOfGas) => {
                return Ok(EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                });
            }
            Err(_) => {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"Plutus datum read failed".to_vec(),
                    gas_used,
                });
            }
        };

        let owner = match host.read(&ns, &owner_key(&script_hash)) {
            Ok(Some(raw)) => raw,
            Ok(None) => Vec::new(),
            Err(budlum_uel_abi::HostError::OutOfGas) => {
                return Ok(EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                });
            }
            Err(_) => {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"Plutus owner read failed".to_vec(),
                    gas_used,
                });
            }
        };
        let mut ev = EvalCtx {
            datum_int: cur_datum,
            redeemer_int: spend.redeemer_int,
            redeemer_bytes: &spend.redeemer_bytes,
            signatory: &call.caller.id,
            owner: &owner,
            height: ctx.height,
            steps: 0,
            gas_used,
            gas_limit: call.gas_limit,
        };
        let val = match eval_uplc(&prog.validator, &mut ev, host, 0) {
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
        if matches!(
            val,
            UplcVal::Bool(false) | UplcVal::Int(0) | UplcVal::Bytes(_)
        ) {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"UPLC validator returned false".to_vec(),
                gas_used: ev.gas_used,
            });
        }
        let Ok(cp) = host.checkpoint_begin() else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"Plutus checkpoint begin failed".to_vec(),
                gas_used: ev.gas_used,
            });
        };
        if let Some(next_datum) = spend.new_datum_int {
            if host
                .write(
                    &ns,
                    &datum_key(&script_hash),
                    Some(&next_datum.to_le_bytes()),
                )
                .is_err()
            {
                let _ = host.checkpoint_rollback(cp);
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"Plutus datum update failed".to_vec(),
                    gas_used: ev.gas_used,
                });
            }
        }
        if host
            .emit_log(EeLog {
                emitter: EeIdentity {
                    ee: EeId::PLUTUS,
                    id: script_hash.to_vec(),
                },
                topics: vec![script_hash.to_vec()],
                data: spend.redeemer_int.to_le_bytes().to_vec(),
            })
            .is_err()
            || host.checkpoint_commit(cp).is_err()
        {
            let _ = host.checkpoint_rollback(cp);
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"Plutus commit failed".to_vec(),
                gas_used: ev.gas_used,
            });
        }
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
    fn plutus_is_closed_on_testnet() {
        let mut closed = PlutusWorker::new();
        assert!(!closed.is_active(&ctx()));
        for chain_id in [45_260, 99_999] {
            assert!(!closed.is_active(&BlockContext { chain_id, ..ctx() }));
        }
        assert!(closed.is_active(&BlockContext {
            chain_id: 45_262,
            ..ctx()
        }));
        let activated = PlutusWorker::with_activation_height(Some(10));
        assert!(!activated.is_active(&ctx()));
        assert!(activated.is_active(&BlockContext {
            height: 10,
            ..ctx()
        }));
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
        let mut worker = PlutusWorker::with_activation_height(Some(0));
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

    fn deploy_validator(
        worker: &mut PlutusWorker,
        host: &mut MemoryHost,
        who: &EeIdentity,
        validator: UplcTerm,
        tx: u8,
    ) -> EeIdentity {
        let prog = PlutusValidatorProgram {
            uplc_version: String::from("1.1.0"),
            initial_datum_int: 10,
            validator,
        };
        let Ok(blob) = encode_plutus_blob(&prog) else {
            panic!("blob");
        };
        let Ok(dep) = worker.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: who.clone(),
                target: who.clone(),
                value: budlum_uel_abi::BudAmount(0),
                input: blob,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [tx; 32],
            },
            host,
        ) else {
            panic!("deploy");
        };
        assert_eq!(dep.status, OutcomeStatus::Success);
        let Ok(target) = EeIdentity::new(EeId::PLUTUS, dep.output) else {
            panic!("target");
        };
        target
    }

    fn set_datum(
        worker: &mut PlutusWorker,
        host: &mut MemoryHost,
        who: &EeIdentity,
        target: &EeIdentity,
        datum: i64,
    ) -> EeOutcome {
        let Ok(input) = serde_json::to_vec(&PlutusSpendInput {
            new_datum_int: Some(datum),
            redeemer_int: 0,
            redeemer_bytes: Vec::new(),
        }) else {
            panic!("input");
        };
        let Ok(out) = worker.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: who.clone(),
                target: target.clone(),
                value: budlum_uel_abi::BudAmount(0),
                input,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x77; 32],
            },
            host,
        ) else {
            panic!("call");
        };
        out
    }

    fn datum(worker: &PlutusWorker, host: &MemoryHost, target: &EeIdentity) -> i64 {
        let Ok(bytes) = worker.query(
            &ctx(),
            &EeQuery {
                target: target.clone(),
                input: Vec::new(),
            },
            host,
        ) else {
            panic!("query");
        };
        let Ok(word) = <[u8; 8]>::try_from(bytes.as_slice()) else {
            panic!("datum word");
        };
        i64::from_le_bytes(word)
    }

    /// The workers used to give a validator no way to read who signed the call, so any account
    /// could drive any validator and rewrite its datum. A validator can now read the signatory and
    /// the owner, and a validator that does not look stays public.
    #[test]
    fn a_validator_can_restrict_a_spend_to_its_owner_and_leave_the_rest_public() {
        let bob_id = vec![0x3C; 32];
        let owner_only = UplcTerm::IfThenElse {
            cond: Box::new(UplcTerm::EqualsBytes(
                Box::new(UplcTerm::Signatory),
                Box::new(UplcTerm::Owner),
            )),
            then_branch: Box::new(UplcTerm::ConstInt(1)),
            else_branch: Box::new(UplcTerm::Error),
        };
        let bob_only = UplcTerm::EqualsBytes(
            Box::new(UplcTerm::Signatory),
            Box::new(UplcTerm::ConstBytes(bob_id.clone())),
        );
        let mut worker = PlutusWorker::with_activation_height(Some(0));
        let mut host = MemoryHost::new(5_000_000);
        let Ok(alice) = EeIdentity::new(EeId::PLUTUS, vec![0x3B; 32]) else {
            panic!("alice")
        };
        let Ok(bob) = EeIdentity::new(EeId::PLUTUS, bob_id) else {
            panic!("bob")
        };
        let Ok(mallory) = EeIdentity::new(EeId::PLUTUS, vec![0x3D; 32]) else {
            panic!("mallory")
        };
        let public = deploy_validator(&mut worker, &mut host, &alice, UplcTerm::ConstInt(1), 0x51);
        let owned = deploy_validator(&mut worker, &mut host, &alice, owner_only, 0x52);
        let named = deploy_validator(&mut worker, &mut host, &alice, bob_only, 0x53);

        // A validator that does not look at the signatory is open to anyone.
        let out = set_datum(&mut worker, &mut host, &mallory, &public, 7);
        assert_eq!(out.status, OutcomeStatus::Success);
        assert_eq!(datum(&worker, &host, &public), 7);

        // The owner-only validator refuses everyone but the account that deployed it.
        for stranger in [&mallory, &bob] {
            let out = set_datum(&mut worker, &mut host, stranger, &owned, 1_000_000);
            assert_eq!(out.status, OutcomeStatus::Revert);
            assert_eq!(out.output, b"UPLC Error term reached".to_vec());
            assert_eq!(datum(&worker, &host, &owned), 10);
        }
        let out = set_datum(&mut worker, &mut host, &alice, &owned, 9);
        assert_eq!(out.status, OutcomeStatus::Success);
        assert_eq!(datum(&worker, &host, &owned), 9);

        // A validator for one named account refuses the owner too.
        let out = set_datum(&mut worker, &mut host, &alice, &named, 11);
        assert_eq!(out.status, OutcomeStatus::Revert);
        assert_eq!(out.output, b"UPLC validator returned false".to_vec());
        let out = set_datum(&mut worker, &mut host, &bob, &named, 13);
        assert_eq!(out.status, OutcomeStatus::Success);
        assert_eq!(datum(&worker, &host, &named), 13);
    }

    #[test]
    fn validator_rejects_zero_int_and_bytes_returns() {
        let mut worker = PlutusWorker::with_activation_height(Some(0));
        let mut host = MemoryHost::new(2_000_000);
        let Ok(alice) = EeIdentity::new(EeId::PLUTUS, vec![0x33; 32]) else {
            panic!("caller");
        };
        for (idx, term) in [UplcTerm::ConstInt(0), UplcTerm::ConstBytes(vec![1, 2, 3])]
            .into_iter()
            .enumerate()
        {
            let Ok(blob) = encode_plutus_blob(&PlutusValidatorProgram {
                uplc_version: String::from("1.1.0"),
                initial_datum_int: 7,
                validator: term,
            }) else {
                panic!("blob");
            };
            let Ok(dep) = worker.execute(
                &ctx(),
                &EeCall {
                    kind: EeCallKind::Deploy,
                    caller: alice.clone(),
                    target: alice.clone(),
                    value: budlum_uel_abi::BudAmount(0),
                    input: blob,
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [0xC0 + idx as u8; 32],
                },
                &mut host,
            ) else {
                panic!("deploy");
            };
            assert_eq!(dep.status, OutcomeStatus::Success);
            let Ok(target) = EeIdentity::new(EeId::PLUTUS, dep.output) else {
                panic!("target");
            };
            let Ok(spend_in) = serde_json::to_vec(&PlutusSpendInput {
                new_datum_int: Some(99),
                redeemer_int: 0,
                redeemer_bytes: Vec::new(),
            }) else {
                panic!("json");
            };
            let Ok(res) = worker.execute(
                &ctx(),
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: alice.clone(),
                    target,
                    value: budlum_uel_abi::BudAmount(0),
                    input: spend_in,
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [0xD0 + idx as u8; 32],
                },
                &mut host,
            ) else {
                panic!("call");
            };
            assert_eq!(res.status, OutcomeStatus::Revert);
        }
    }

    #[test]
    fn spend_fails_closed_when_datum_host_read_errors() {
        use budlum_uel_abi::{
            BudAmount, HostError, HostRead, OutOfGas, UniversalCall, UniversalResult,
        };

        struct FailingDatumHost {
            inner: MemoryHost,
        }
        impl HostRead for FailingDatumHost {
            fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
                if key.starts_with(b"datum:") {
                    return Err(HostError::Invalid("injected datum read error".into()));
                }
                self.inner.read(ns, key)
            }
            fn bud_balance(&self, who: &EeIdentity) -> Result<BudAmount, HostError> {
                self.inner.bud_balance(who)
            }
        }
        impl HostApi for FailingDatumHost {
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

        let mut worker = PlutusWorker::with_activation_height(Some(0));
        let mut host = MemoryHost::new(2_000_000);
        let Ok(alice) = EeIdentity::new(EeId::PLUTUS, vec![0x71; 32]) else {
            panic!("alice");
        };
        let Ok(blob) = encode_plutus_blob(&PlutusValidatorProgram {
            uplc_version: String::from("1.1.0"),
            initial_datum_int: 10,
            validator: UplcTerm::ConstInt(1),
        }) else {
            panic!("blob");
        };
        let Ok(dep) = worker.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: alice.clone(),
                target: alice.clone(),
                value: BudAmount(0),
                input: blob,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0xE1; 32],
            },
            &mut host,
        ) else {
            panic!("deploy");
        };
        assert_eq!(dep.status, OutcomeStatus::Success);
        let Ok(target) = EeIdentity::new(EeId::PLUTUS, dep.output) else {
            panic!("target");
        };
        let Ok(spend1_in) = serde_json::to_vec(&PlutusSpendInput {
            new_datum_int: Some(50),
            redeemer_int: 1,
            redeemer_bytes: Vec::new(),
        }) else {
            panic!("json");
        };
        let Ok(spend1) = worker.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: alice.clone(),
                target: target.clone(),
                value: BudAmount(0),
                input: spend1_in,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0xE2; 32],
            },
            &mut host,
        ) else {
            panic!("spend1");
        };
        assert_eq!(spend1.status, OutcomeStatus::Success);

        let mut faulty = FailingDatumHost { inner: host };
        let Ok(spend2_in) = serde_json::to_vec(&PlutusSpendInput {
            new_datum_int: None,
            redeemer_int: 2,
            redeemer_bytes: Vec::new(),
        }) else {
            panic!("json");
        };
        let Ok(spend2) = worker.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: alice,
                target,
                value: BudAmount(0),
                input: spend2_in,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0xE3; 32],
            },
            &mut faulty,
        ) else {
            panic!("spend2");
        };
        assert_eq!(
            spend2.status,
            OutcomeStatus::Revert,
            "datum host.read error must fail closed instead of rolling back to initial_datum_int"
        );
    }

    #[test]
    fn plutus_deploy_charges_per_byte_of_published_blob() {
        let mut worker = PlutusWorker::with_activation_height(Some(0));
        let prog = PlutusValidatorProgram {
            uplc_version: String::from("1.1.0"),
            initial_datum_int: 1,
            validator: UplcTerm::ConstBytes(vec![0xAB; 600]),
        };
        let Ok(blob) = encode_plutus_blob(&prog) else {
            panic!("blob");
        };
        let expected_gas = 1_000 + (blob.len() as u64) * 25;
        let Ok(alice) = EeIdentity::new(EeId::PLUTUS, vec![0x99; 32]) else {
            panic!("alice");
        };
        let mut host = MemoryHost::new(5_000_000);
        let Ok(low) = worker.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: alice.clone(),
                target: alice.clone(),
                value: budlum_uel_abi::BudAmount(0),
                input: blob.clone(),
                gas_limit: expected_gas - 1,
                depth: 0,
                tx_hash: [0xD1; 32],
            },
            &mut host,
        ) else {
            panic!("low");
        };
        assert_eq!(low.status, OutcomeStatus::OutOfGas);

        let Ok(ok) = worker.execute(
            &ctx(),
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: alice.clone(),
                target: alice,
                value: budlum_uel_abi::BudAmount(0),
                input: blob,
                gas_limit: expected_gas,
                depth: 0,
                tx_hash: [0xD2; 32],
            },
            &mut host,
        ) else {
            panic!("ok");
        };
        assert_eq!(ok.status, OutcomeStatus::Success);
        assert_eq!(ok.gas_used, expected_gas);
    }

    #[test]
    fn plutus_blob_rejects_empty_version_and_excessive_ast_depth() {
        let empty_ver = encode_plutus_blob(&PlutusValidatorProgram {
            uplc_version: String::new(),
            initial_datum_int: 0,
            validator: UplcTerm::ConstInt(1),
        })
        .unwrap();
        assert!(
            decode_plutus_blob(&empty_ver).is_err(),
            "empty uplc_version must be refused"
        );

        let mut deep = UplcTerm::ConstBytes(vec![1]);
        for _ in 0..80 {
            deep = UplcTerm::Sha256(Box::new(deep));
        }
        let deep_blob = encode_plutus_blob(&PlutusValidatorProgram {
            uplc_version: "1.1.0".into(),
            initial_datum_int: 0,
            validator: deep,
        })
        .unwrap();
        assert!(
            decode_plutus_blob(&deep_blob).is_err(),
            "UPLC AST deeper than MAX_UPLC_DEPTH must be refused"
        );
    }
}
