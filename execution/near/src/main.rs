//! Out-of-process `budlum-ee-near` height-gated T-Expansion worker binary (`EeId::NEAR`).

use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeOutcome, EeQuery, EeRefusal,
    ExecutionEnvironment, HostApi, HostRead, Namespace, OutcomeStatus, RefusalCode,
};
use sha2::{Digest, Sha256};
use std::process::ExitCode;

/// Public testnet chain id where T-Expansion workers stay height-gated closed (`u64::MAX`).
pub const PUBLIC_TESTNET_CHAIN_ID: u64 = 45_261;

/// Default post-launch activation height (`u64::MAX` = closed on public testnet).
pub const DEFAULT_ACTIVATION_HEIGHT: u64 = u64::MAX;

struct Worker {
    activation_height: u64,
}

impl Default for Worker {
    fn default() -> Self {
        Self {
            activation_height: DEFAULT_ACTIVATION_HEIGHT,
        }
    }
}

impl ExecutionEnvironment for Worker {
    fn id(&self) -> EeId {
        EeId::NEAR
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        if code.len() < 4 || &code[..4] != b"\x00asm" {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("bytecode header magic mismatch for budlum-ee-near"),
            });
        }
        Ok(CodeInfo {
            code_hash: Sha256::digest(code).into(),
            abi_tag: String::from("near-wasm-v1"),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        if ctx.chain_id == PUBLIC_TESTNET_CHAIN_ID && ctx.height < self.activation_height {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"budlum-ee-near_closed_on_testnet".to_vec(),
                gas_used: call.gas_limit.min(1_000),
            });
        }
        if host.charge(5_000).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        }
        let Ok(ns) = Namespace::new("ee/near/storage") else {
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
                output: Sha256::digest(&call.input).to_vec(),
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
        let ns = Namespace::new("ee/near/storage").map_err(|e| EeRefusal {
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
        eprintln!("usage: budlum-ee-near <socket-path>");
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
    let mut env = Worker::default();
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
    eprintln!("budlum-ee-near requires Unix domain sockets");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    run_unix()
}
