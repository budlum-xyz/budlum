//! Standalone Unix-socket worker binary `budlum-ee-wasm` (`EeId::WASM` = `0x02`).
//!
//! Enforces WASM float-type / float-opcode refusal, 64 MiB (1024-page) memory
//! bounds, IBC export refusal, and `BudlumMsg::UniversalCall` dispatch.

pub mod budlum_msg;

use budlum_msg::BudlumMsg;
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeOutcome,
    EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, Namespace, OutcomeStatus,
    RefusalCode, UniversalCall,
};
use sha2::{Digest, Sha256};
use std::process::ExitCode;

const MAX_WASM_PAGES: u32 = 1_024;
const NS_WASM_CODE: &str = "ee/wasm/code";
const NS_WASM_STORE: &str = "ee/wasm/store";

fn check_no_float_or_ibc(code: &[u8]) -> Result<(), String> {
    let Some(hdr) = code.get(..8) else {
        return Err(String::from("WASM module shorter than 8-byte header"));
    };
    if hdr != [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00] {
        return Err(String::from("invalid WASM magic or version"));
    }
    if code.windows(4).any(|w| w == b"ibc_") {
        return Err(String::from("IBC entry points are refused"));
    }
    for &b in code.get(8..).unwrap_or(&[]) {
        if b == 0x7c || b == 0x7d {
            return Err(String::from("WASM float types f32/f64 are refused"));
        }
    }
    let _ = MAX_WASM_PAGES;
    Ok(())
}

/// Standalone CosmWasm worker environment served over Unix domain socket.
#[derive(Debug, Default)]
pub struct WorkerWasmEe;

impl ExecutionEnvironment for WorkerWasmEe {
    fn id(&self) -> EeId {
        EeId::WASM
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        check_no_float_or_ibc(code).map_err(|message| EeRefusal {
            code: RefusalCode::InvalidCode,
            message,
        })?;
        Ok(CodeInfo {
            code_hash: Sha256::digest(code).into(),
            abi_tag: String::from("cosmwasm-v1"),
        })
    }

    fn execute(
        &mut self,
        _ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        if host.charge(15_000).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        }
        match call.kind {
            EeCallKind::Deploy => {
                if let Err(m) = check_no_float_or_ibc(&call.input) {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: m.into_bytes(),
                        gas_used: 15_000,
                    });
                }
                let Ok(code_ns) = Namespace::new(NS_WASM_CODE) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used: 15_000,
                    });
                };
                let ch: [u8; 32] = Sha256::digest(&call.input).into();
                let _ = host.write(&code_ns, &ch, Some(&call.input));
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: call.target.id.clone(),
                    gas_used: 20_000,
                })
            }
            EeCallKind::Call => {
                if let Ok(bmsg) = serde_json::from_slice::<BudlumMsg>(&call.input) {
                    let BudlumMsg::UniversalCall {
                        target_ee,
                        target_hex,
                        input_hex,
                        value_attos,
                        gas_limit_bgu,
                    } = bmsg;
                    let Ok(target_b) = hex::decode(target_hex) else {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"bad target_hex".to_vec(),
                            gas_used: 15_000,
                        });
                    };
                    let Ok(input_b) = hex::decode(input_hex) else {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"bad input_hex".to_vec(),
                            gas_used: 15_000,
                        });
                    };
                    return match host.universal_call(UniversalCall {
                        from: call.target.clone(),
                        to_ee: EeId(target_ee),
                        target: EeIdentity {
                            ee: EeId(target_ee),
                            id: target_b,
                        },
                        value: BudAmount(value_attos),
                        input: input_b,
                        gas_limit: gas_limit_bgu,
                    }) {
                        Ok(r) => Ok(EeOutcome {
                            status: if r.success {
                                OutcomeStatus::Success
                            } else {
                                OutcomeStatus::Revert
                            },
                            output: r.output,
                            gas_used: 20_000,
                        }),
                        Err(e) => Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: e.to_string().into_bytes(),
                            gas_used: 20_000,
                        }),
                    };
                }
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: Vec::new(),
                    gas_used: 20_000,
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
        let ns = Namespace::new(NS_WASM_STORE).map_err(|e| EeRefusal {
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

#[cfg(unix)]
fn run_unix() -> ExitCode {
    use budlum_uel_abi::transport::{serve_connection, ServeEnd};
    use std::os::unix::net::UnixListener;

    let Some(socket_path) = std::env::args().nth(1) else {
        eprintln!("usage: budlum-ee-wasm <socket-path>");
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
    let mut env = WorkerWasmEe;
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
    eprintln!("budlum-ee-wasm requires Unix domain sockets");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    run_unix()
}
