//! Out-of-process `budlum-ee-svm` worker binary (`EeId::SVM`, JIT disabled).

use budlum_uel_abi::transport::{run_worker_stdio_loop, EeWorkerConfig};
use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeOutcome, EeQuery, EeRefusal,
    ExecutionEnvironment, HostApi, HostRead, Namespace, OutcomeStatus, RefusalCode,
};
use sha2::{Digest, Sha256};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

#[derive(Default)]
struct SvmWorker {
    jit_enabled: bool,
}

impl ExecutionEnvironment for SvmWorker {
    fn id(&self) -> EeId {
        EeId::SVM
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        if self.jit_enabled {
            return Err(EeRefusal {
                code: RefusalCode::Denied,
                message: String::from("SVM JIT is permanently disabled"),
            });
        }
        if code.get(..4) != Some(&ELF_MAGIC) {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("expected \\x7fELF SBPF binary"),
            });
        }
        Ok(CodeInfo {
            code_hash: Sha256::digest(code).into(),
            abi_tag: String::from("sbpf-interp-v1"),
        })
    }

    fn execute(
        &mut self,
        _ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        if host.charge(5_000).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        }
        let Ok(ns) = Namespace::new("ee/svm/account") else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: Vec::new(),
                gas_used: 5_000,
            });
        };
        match call.kind {
            EeCallKind::Deploy => {
                if let Err(r) = self.validate_deploy(&call.input) {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: r.message.into_bytes(),
                        gas_used: 5_000,
                    });
                }
                let _ = host.write(&ns, &call.target.id, Some(&call.input));
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: call.target.id.clone(),
                    gas_used: 15_000,
                })
            }
            EeCallKind::Call => Ok(EeOutcome {
                status: OutcomeStatus::Success,
                output: call.input.clone(),
                gas_used: 5_000,
            }),
        }
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let ns = Namespace::new("ee/svm/account").map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: e.to_string(),
        })?;
        host.read(&ns, &q.target.id)
            .map(Option::unwrap_or_default)
            .map_err(|e| EeRefusal {
                code: RefusalCode::Denied,
                message: e.to_string(),
            })
    }
}

fn main() {
    let mut ee = SvmWorker::default();
    let cfg = EeWorkerConfig {
        ee_id: EeId::SVM,
        version: String::from("budlum-ee-svm/0.1.0"),
        features: 0,
    };
    if let Err(e) = run_worker_stdio_loop(&mut ee, &cfg) {
        eprintln!("budlum-ee-svm worker exited with error: {e}");
        std::process::exit(1);
    }
}
