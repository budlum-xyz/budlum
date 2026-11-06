//! Out-of-process `budlum-ee-move` worker binary (`EeId::MOVE`, sequential VM).

use budlum_uel_abi::transport::{run_worker_stdio_loop, EeWorkerConfig};
use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeOutcome, EeQuery, EeRefusal,
    ExecutionEnvironment, HostApi, HostRead, Namespace, OutcomeStatus, RefusalCode,
};
use sha3::{Digest, Sha3_256};

const MOVE_MAGIC: [u8; 4] = [0xa1, 0x1c, 0xeb, 0x0b];

#[derive(Default)]
struct MoveWorker;

impl ExecutionEnvironment for MoveWorker {
    fn id(&self) -> EeId {
        EeId::MOVE
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        if code.get(..4) != Some(&MOVE_MAGIC) {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("expected Move 0xa11ceb0b binary magic"),
            });
        }
        Ok(CodeInfo {
            code_hash: Sha3_256::digest(code).into(),
            abi_tag: String::from("aptos-move-v1"),
        })
    }

    fn execute(
        &mut self,
        _ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        if host.charge(10_000).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        }
        let Ok(ns) = Namespace::new("ee/move/state") else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: Vec::new(),
                gas_used: 10_000,
            });
        };
        match call.kind {
            EeCallKind::Deploy => {
                if let Err(r) = self.validate_deploy(&call.input) {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: r.message.into_bytes(),
                        gas_used: 10_000,
                    });
                }
                let _ = host.write(&ns, &call.target.id, Some(&call.input));
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: call.target.id.clone(),
                    gas_used: 10_000,
                })
            }
            EeCallKind::Call => Ok(EeOutcome {
                status: OutcomeStatus::Success,
                output: call.input.clone(),
                gas_used: 10_000,
            }),
        }
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let ns = Namespace::new("ee/move/state").map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: e.to_string(),
        })?;
        host.read(&ns, &q.input)
            .map(Option::unwrap_or_default)
            .map_err(|e| EeRefusal {
                code: RefusalCode::Denied,
                message: e.to_string(),
            })
    }
}

fn main() {
    let mut ee = MoveWorker;
    let cfg = EeWorkerConfig {
        ee_id: EeId::MOVE,
        version: String::from("budlum-ee-move/0.1.0"),
        features: 0,
    };
    if let Err(e) = run_worker_stdio_loop(&mut ee, &cfg) {
        eprintln!("budlum-ee-move worker exited with error: {e}");
        std::process::exit(1);
    }
}
