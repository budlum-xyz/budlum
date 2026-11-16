//! A worker declares who it speaks for, and the host must not take its word.
//!
//! Gas, namespace and balance checks confine what a worker can touch. Two
//! identities still leave a worker as plain claims: the `from` of a
//! cross-environment call and the `emitter` of a log. Both carry no value, so
//! the debit check never looks at them. These tests run a worker that lies
//! about both and read what the host let through.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::execution::coordinator::gas::MIN_UEL_BASE_FEE_ATTOS;
use crate::execution::coordinator::worker::WorkerEndpoint;
use crate::execution::coordinator::{ExecutionCoordinator, UelAction, UelReceiptStatus, UelTx};
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeFault, EeId, EeIdentity, EeLog, EeOutcome,
    EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostError, HostRead, OutcomeStatus,
    RefusalCode, UniversalCall,
};
use std::sync::{Arc, Mutex};

/// What the lying worker tries on its one call.
#[derive(Clone)]
enum Act {
    /// Call `target` as `from`, with no value.
    CallAs {
        from: EeIdentity,
        target: EeIdentity,
    },
    /// Emit a log attributed to `emitter`.
    LogAs { emitter: EeIdentity },
}

struct LyingWorker {
    ee: EeId,
    act: Act,
}

fn refusal() -> EeRefusal {
    EeRefusal {
        code: RefusalCode::Unsupported,
        message: String::from("test worker"),
    }
}

impl ExecutionEnvironment for LyingWorker {
    fn id(&self) -> EeId {
        self.ee
    }

    fn validate_deploy(&self, _code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        Err(refusal())
    }

    fn execute(
        &mut self,
        _ctx: &BlockContext,
        _call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let verdict = match &self.act {
            Act::CallAs { from, target } => host
                .universal_call(UniversalCall {
                    from: from.clone(),
                    to_ee: target.ee,
                    target: target.clone(),
                    value: BudAmount(0),
                    input: Vec::new(),
                    gas_limit: 10_000,
                    is_static: false,
                })
                .map(|_| ()),
            Act::LogAs { emitter } => host.emit_log(EeLog {
                emitter: emitter.clone(),
                topics: Vec::new(),
                data: Vec::new(),
            }),
        };
        let output: &[u8] = match verdict {
            Ok(()) => b"allowed",
            Err(HostError::Denied(_)) => b"denied",
            Err(_) => b"other",
        };
        Ok(EeOutcome {
            status: OutcomeStatus::Success,
            output: output.to_vec(),
            gas_used: 1,
        })
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        _q: &EeQuery,
        _host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        Err(refusal())
    }
}

/// Records the caller of every call it receives.
struct Recorder {
    ee: EeId,
    seen: Arc<Mutex<Vec<EeIdentity>>>,
}

impl ExecutionEnvironment for Recorder {
    fn id(&self) -> EeId {
        self.ee
    }

    fn validate_deploy(&self, _code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        Err(refusal())
    }

    fn execute(
        &mut self,
        _ctx: &BlockContext,
        call: &EeCall,
        _host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(call.caller.clone());
        }
        Ok(EeOutcome {
            status: OutcomeStatus::Success,
            output: Vec::new(),
            gas_used: 1,
        })
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        _q: &EeQuery,
        _host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        Err(refusal())
    }
}

fn identity(ee: EeId, byte: u8) -> EeIdentity {
    EeIdentity {
        ee,
        id: vec![byte; 32],
    }
}

/// What a lying worker in `worker_ee` got away with.
struct Outcome {
    /// `allowed`, `denied` or `other`: what the host answered the worker.
    verdict: Vec<u8>,
    /// The callers the recording worker in the target environment saw.
    callers_seen: Vec<EeIdentity>,
}

fn run_lie(worker_ee: EeId, act: Act, recorder_ee: EeId) -> Outcome {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sender = Address::from([0x91u8; 32]);
    let proposer = Address::from([0x92u8; 32]);
    let mut state = AccountState::new();
    state.credit_account(&sender, 500);

    let mut coord = ExecutionCoordinator::new();
    coord.register_worker(WorkerEndpoint::in_process(move || {
        Box::new(LyingWorker {
            ee: worker_ee,
            act: act.clone(),
        })
    }));
    let recorded = Arc::clone(&seen);
    coord.register_worker(WorkerEndpoint::in_process(move || {
        Box::new(Recorder {
            ee: recorder_ee,
            seen: Arc::clone(&recorded),
        })
    }));

    let ctx = BlockContext {
        height: 1,
        timestamp_ms: 1_762_000_002_000,
        chain_id: 45_261,
    };
    let receipts = state
        .execute_uel_block(
            &mut coord,
            ctx,
            proposer,
            &[UelTx {
                tx_hash: [0xA1u8; 32],
                sender,
                nonce: 0,
                ee: worker_ee,
                action: UelAction::Call {
                    target: vec![0u8; 32],
                    input: Vec::new(),
                },
                value_attos: 0,
                gas_limit_bgu: 50_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 0,
            }],
        )
        .expect("the block executes");
    let receipt = receipts.first().expect("one receipt");
    assert_eq!(
        receipt.status,
        UelReceiptStatus::Success,
        "the lying worker's own call succeeds; only its claim is in question"
    );
    let callers_seen = seen.lock().expect("recorder lock").clone();
    Outcome {
        verdict: receipt.output.clone(),
        callers_seen,
    }
}

/// A worker in one environment names a contract in a second environment as the
/// caller of a call into a third. Nothing the host knows about this frame
/// supports that claim.
#[test]
fn a_worker_cannot_name_a_caller_in_a_third_environment() {
    let victim = identity(EeId::EVM, 0xE1);
    let out = run_lie(
        EeId::SVM,
        Act::CallAs {
            from: victim.clone(),
            target: identity(EeId::MOVE, 0xB2),
        },
        EeId::MOVE,
    );
    assert_eq!(
        out.verdict, b"denied",
        "a zero-value call must not adopt a caller the worker made up"
    );
    assert!(
        !out.callers_seen.contains(&victim),
        "the callee must never see the forged caller: {:?}",
        out.callers_seen
    );
}

/// The real workers translate a caller into the callee's own namespace before
/// they call across (EVM to WASM, WASM to EVM). That stays allowed.
#[test]
fn a_worker_may_name_a_caller_in_the_callee_environment() {
    let translated = identity(EeId::MOVE, 0xC3);
    let out = run_lie(
        EeId::SVM,
        Act::CallAs {
            from: translated.clone(),
            target: identity(EeId::MOVE, 0xB2),
        },
        EeId::MOVE,
    );
    assert_eq!(out.verdict, b"allowed");
    assert_eq!(out.callers_seen, vec![translated]);
}

/// A worker may act for contracts in its own environment: it already holds
/// that environment's state.
#[test]
fn a_worker_may_name_a_caller_in_its_own_environment() {
    let own = identity(EeId::SVM, 0xD4);
    let out = run_lie(
        EeId::SVM,
        Act::CallAs {
            from: own.clone(),
            target: identity(EeId::MOVE, 0xB2),
        },
        EeId::MOVE,
    );
    assert_eq!(out.verdict, b"allowed");
    assert_eq!(out.callers_seen.len(), 1);
}

/// A log is recorded as fact. A worker may not author one for a contract in
/// another environment.
#[test]
fn a_worker_cannot_emit_a_log_for_another_environment() {
    let out = run_lie(
        EeId::SVM,
        Act::LogAs {
            emitter: identity(EeId::EVM, 0xE1),
        },
        EeId::MOVE,
    );
    assert_eq!(
        out.verdict, b"denied",
        "a log attributed to another environment must be refused"
    );
}

#[test]
fn a_worker_may_emit_a_log_for_its_own_environment() {
    let out = run_lie(
        EeId::SVM,
        Act::LogAs {
            emitter: identity(EeId::SVM, 0xD4),
        },
        EeId::MOVE,
    );
    assert_eq!(out.verdict, b"allowed");
}
