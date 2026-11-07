//! Standalone Unix-socket worker binary `budlum-ee-evm` (`EeId::EVM` = `0x01`).
//!
//! Compiled with `panic = "unwind"` and `overflow-checks = true` so engine panics
//! become deterministic `EeFault` receipts over the UEL socket boundary (BLG-250).

pub mod precompile_universal;

use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeOutcome, EeQuery, EeRefusal,
    ExecutionEnvironment, HostApi, HostRead, Namespace, OutcomeStatus, RefusalCode,
};
use precompile_universal::{run_precompile_call, EVM_UNIVERSAL_PRECOMPILE};
use sha3::{Digest, Keccak256};
use std::process::ExitCode;

const MAX_INITCODE_BYTES: usize = 49_152;
const NS_EVM_CODE: &str = "ee/evm/code";
const NS_EVM_STORAGE: &str = "ee/evm/storage";

/// Standalone EVM worker environment served over Unix domain socket.
#[derive(Debug, Default)]
pub struct WorkerEvmEe;

impl ExecutionEnvironment for WorkerEvmEe {
    fn id(&self) -> EeId {
        EeId::EVM
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        if code.is_empty() {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("EVM deploy code must not be empty"),
            });
        }
        if code.len() > MAX_INITCODE_BYTES {
            return Err(EeRefusal {
                code: RefusalCode::TooLarge,
                message: String::from("EVM initcode exceeds 48 KiB EIP-3860 limit"),
            });
        }
        Ok(CodeInfo {
            code_hash: Keccak256::digest(code).into(),
            abi_tag: String::from("evm-prague-v1"),
        })
    }

    fn execute(
        &mut self,
        _ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        if host.charge(21_000).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        }
        let caller20: [u8; 20] = call.caller.id.as_slice().try_into().unwrap_or([0u8; 20]);
        let target20: [u8; 20] = call.target.id.as_slice().try_into().unwrap_or([0u8; 20]);

        match call.kind {
            EeCallKind::Deploy => {
                let Ok(code_ns) = Namespace::new(NS_EVM_CODE) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used: 21_000,
                    });
                };
                let ch: [u8; 32] = Keccak256::digest(&call.input).into();
                if host.write(&code_ns, &ch, Some(&call.input)).is_err() {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used: 21_000,
                    });
                }
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: target20.to_vec(),
                    gas_used: 21_000,
                })
            }
            EeCallKind::Call => {
                if target20 == EVM_UNIVERSAL_PRECOMPILE {
                    return match run_precompile_call(&caller20, &call.input, host) {
                        Ok(ret) => Ok(EeOutcome {
                            status: OutcomeStatus::Success,
                            output: ret,
                            gas_used: 25_000,
                        }),
                        Err(reason) => Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: reason.into_bytes(),
                            gas_used: 25_000,
                        }),
                    };
                }
                if let (Some(slot), Some(val)) = (call.input.get(..32), call.input.get(32..64)) {
                    let Ok(store_ns) = Namespace::new(NS_EVM_STORAGE) else {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: Vec::new(),
                            gas_used: 25_000,
                        });
                    };
                    let mut k = [0u8; 52];
                    if let Some(a) = k.get_mut(..20) {
                        a.copy_from_slice(&target20);
                    }
                    if let Some(s) = k.get_mut(20..52) {
                        s.copy_from_slice(slot);
                    }
                    let _ = host.write(&store_ns, &k, Some(val));
                }
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: Vec::new(),
                    gas_used: 25_000,
                })
            }
        }
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let store_ns = Namespace::new(NS_EVM_STORAGE).map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: e.to_string(),
        })?;
        let mut k = Vec::with_capacity(q.target.id.len() + q.input.len());
        k.extend_from_slice(&q.target.id);
        k.extend_from_slice(&q.input);
        host.read(&store_ns, &k)
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
        eprintln!("usage: budlum-ee-evm <socket-path>");
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
    let mut env = WorkerEvmEe;
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
    eprintln!("budlum-ee-evm requires Unix domain sockets");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    run_unix()
}
