//! Out-of-process `budlum-ee-budzero` worker binary (`EeId::BUDZERO`).

use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeOutcome, EeQuery, EeRefusal,
    ExecutionEnvironment, HostApi, HostRead, Namespace, OutcomeStatus, RefusalCode,
};
use sha3::{Digest, Sha3_256};
use std::process::ExitCode;

#[derive(Default)]
struct BudZeroWorker;

impl ExecutionEnvironment for BudZeroWorker {
    fn id(&self) -> EeId {
        EeId::BUDZERO
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        if code.is_empty() {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("empty BudZero bytecode"),
            });
        }
        Ok(CodeInfo {
            code_hash: Sha3_256::digest(code).into(),
            abi_tag: String::from("budzero-v1"),
        })
    }

    fn execute(
        &mut self,
        _ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        if host.charge(1_000).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        }
        let Ok(ns) = Namespace::new("ee/budzero/state") else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: Vec::new(),
                gas_used: 1_000,
            });
        };
        match call.kind {
            EeCallKind::Deploy => {
                if let Err(r) = self.validate_deploy(&call.input) {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: r.message.into_bytes(),
                        gas_used: 1_000,
                    });
                }
                let _ = host.write(&ns, &call.target.id, Some(&call.input));
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: call.target.id.clone(),
                    gas_used: 1_000,
                })
            }
            EeCallKind::Call => Ok(EeOutcome {
                status: OutcomeStatus::Success,
                output: call.input.clone(),
                gas_used: 1_000,
            }),
        }
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let ns = Namespace::new("ee/budzero/state").map_err(|e| EeRefusal {
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

#[cfg(unix)]
fn run_unix() -> ExitCode {
    use budlum_uel_abi::transport::{serve_connection, ServeEnd};
    use std::os::unix::net::UnixListener;

    let Some(socket_path) = std::env::args().nth(1) else {
        eprintln!("usage: budlum-ee-budzero <socket-path>");
        return ExitCode::from(2);
    };
    let _ = std::fs::remove_file(&socket_path);
    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(err) => {
            eprintln!("failed to bind `{socket_path}`: {err}");
            return ExitCode::from(1);
        }
    };
    let mut env = BudZeroWorker;
    for incoming in listener.incoming() {
        let Ok(stream) = incoming else {
            return ExitCode::from(1);
        };
        match serve_connection(stream, &mut env) {
            Ok(ServeEnd::Closed) => {}
            Ok(ServeEnd::Faulted) => return ExitCode::from(70),
            Err(_) => return ExitCode::from(1),
        }
    }
    ExitCode::SUCCESS
}

#[cfg(not(unix))]
fn run_unix() -> ExitCode {
    eprintln!("budlum-ee-budzero requires Unix domain sockets");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    run_unix()
}
