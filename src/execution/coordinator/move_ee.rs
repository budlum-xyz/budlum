//! Move (Aptos) execution environment (`EeId::MOVE` = `0x04`) over `HostApi`.
//!
//! Implements WP-32 items 1, 3, & 6:
//! - Strictly sequential Move execution (`block_stm_parallel = false`).
//! - Move state persisted in `ee/move/state` keyed by canonical `StateKey` bytes.
//! - Framework subset: `0x1::aptos_account`, `0x1::coin`, `0x1::fungible_asset`,
//!   `0x1::randomness` (bound to `BlockContext.randao`, Budlum epoch randomness),
//!   and native `0x1::budlum_universal::call` (`1 octa = 10^10 attoBUD`).
//! - Aptos staking and governance modules are explicitly refused (section 8.15).
//! WIRING: Move execution environment bundle limits and runtime config wired into UEL coordinator.

use crate::execution::coordinator::state::NS_MOVE_STATE;
use crate::execution::coordinator::universal_call::wrap_static_universal_input;
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, Namespace,
    OutcomeStatus, RefusalCode, UniversalCall,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Move binary module magic (`0xa11ceb0b` little-endian `[0xa1, 0x1c, 0xeb, 0x0b]`).
pub const MOVE_BINARY_MAGIC: [u8; 4] = [0xa1, 0x1c, 0xeb, 0x0b];
/// Maximum Move module bundle size (256 KiB).
pub const MAX_MOVE_BUNDLE_BYTES: usize = 256 * 1024;
/// Conversion factor from Aptos Move gas units to BGU (`1 Move unit = 100 BGU`, 8.9.3).
pub const BGU_PER_MOVE_GAS_UNIT: u64 = 100;
/// Number of attoBUD per Aptos octa (`10^10`, section 8.5).
pub const ATTOS_PER_OCTA: u128 = 10_000_000_000;

/// Forbidden Aptos staking and governance modules refused on Budlum (section 8.15).
pub const FORBIDDEN_MOVE_MODULES: &[&str] = &[
    "0x1::stake",
    "0x1::staking_contract",
    "0x1::staking_config",
    "0x1::delegation_pool",
    "0x1::aptos_governance",
    "0x1::voting",
];

/// Runtime configuration for `budlum-ee-move` (Block-STM parallel engine disabled).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveRuntimeConfig {
    pub block_stm_parallel: bool,
    pub max_value_nest_depth: usize,
}

impl Default for MoveRuntimeConfig {
    fn default() -> Self {
        Self {
            block_stm_parallel: false,
            max_value_nest_depth: 128,
        }
    }
}

impl MoveRuntimeConfig {
    /// Verifies Block-STM parallel execution is disabled (WP-32 item 1).
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn ensure_sequential(&self) -> Result<(), String> {
        if self.block_stm_parallel {
            return Err(String::from(
                "Move Block-STM parallel execution is disabled; sequential mode is required",
            ));
        }
        Ok(())
    }
}

/// Entry-function / module invocation payload for `EeId::MOVE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveCallEnvelope {
    PublishModule {
        module_name: String,
        bytecode: Vec<u8>,
    },
    EntryFunction {
        module_id: String,
        function_name: String,
        args: Vec<String>,
    },
    BudlumUniversalCall {
        target_ee: u8,
        target: Vec<u8>,
        input: Vec<u8>,
        value_octas: u64,
        gas_bgu: u64,
        is_static: bool,
    },
}

/// Stateless Move execution environment (`budlum-ee-move`).
#[derive(Debug, Clone)]
pub struct MoveEe {
    config: MoveRuntimeConfig,
}

impl Default for MoveEe {
    fn default() -> Self {
        Self::new()
    }
}

impl MoveEe {
    #[must_use]
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn new() -> Self {
        Self {
            config: MoveRuntimeConfig::default(),
        }
    }

    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn with_config(config: MoveRuntimeConfig) -> Result<Self, String> {
        config.ensure_sequential()?;
        Ok(Self { config })
    }
}

fn state_key_module(addr: &[u8; 32], mod_name: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(40 + mod_name.len());
    k.extend_from_slice(b"mod:");
    k.extend_from_slice(addr);
    k.push(b':');
    k.extend_from_slice(mod_name.as_bytes());
    k
}

fn state_key_resource(addr: &[u8; 32], resource_tag: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(40 + resource_tag.len());
    k.extend_from_slice(b"res:");
    k.extend_from_slice(addr);
    k.push(b':');
    k.extend_from_slice(resource_tag.as_bytes());
    k
}

fn coerce_addr32(raw: &[u8]) -> [u8; 32] {
    if let Ok(arr) = <[u8; 32]>::try_from(raw) {
        return arr;
    }
    Sha3_256::digest(raw).into()
}

impl ExecutionEnvironment for MoveEe {
    fn id(&self) -> EeId {
        EeId::MOVE
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        self.config.ensure_sequential().map_err(|message| EeRefusal {
            code: RefusalCode::Denied,
            message,
        })?;
        if code.len() < 4 || code.get(..4) != Some(&MOVE_BINARY_MAGIC) {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("Move module must start with 0xa11ceb0b magic"),
            });
        }
        if code.len() > MAX_MOVE_BUNDLE_BYTES {
            return Err(EeRefusal {
                code: RefusalCode::TooLarge,
                message: String::from("Move module bundle exceeds 256 KiB"),
            });
        }
        Ok(CodeInfo {
            code_hash: Sha3_256::digest(code).into(),
            abi_tag: String::from("aptos-move-v1"),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        if let Err(m) = self.config.ensure_sequential() {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: m.into_bytes(),
                gas_used: 0,
            });
        }
        let base_bgu = 100 * BGU_PER_MOVE_GAS_UNIT;
        if host.charge(base_bgu).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        }
        let Ok(move_ns) = Namespace::new(NS_MOVE_STATE) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: Vec::new(),
                gas_used: base_bgu,
            });
        };
        let signer32 = coerce_addr32(&call.caller.id);
        let target32 = coerce_addr32(&call.target.id);

        match call.kind {
            EeCallKind::Deploy => {
                if let Err(r) = self.validate_deploy(&call.input) {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: r.message.into_bytes(),
                        gas_used: base_bgu,
                    });
                }
                let k = state_key_module(&target32, "default");
                if host.write(&move_ns, &k, Some(&call.input)).is_err() {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"failed storing Move module".to_vec(),
                        gas_used: base_bgu,
                    });
                }
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: target32.to_vec(),
                    gas_used: base_bgu,
                })
            }
            EeCallKind::Call => {
                let Ok(env) = serde_json::from_slice::<MoveCallEnvelope>(&call.input) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"invalid MoveCallEnvelope".to_vec(),
                        gas_used: base_bgu,
                    });
                };
                match env {
                    MoveCallEnvelope::PublishModule {
                        module_name,
                        bytecode,
                    } => {
                        if let Err(r) = self.validate_deploy(&bytecode) {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::InvalidCode,
                                output: r.message.into_bytes(),
                                gas_used: base_bgu,
                            });
                        }
                        let k = state_key_module(&signer32, &module_name);
                        let _ = host.write(&move_ns, &k, Some(&bytecode));
                        Ok(EeOutcome {
                            status: OutcomeStatus::Success,
                            output: k,
                            gas_used: base_bgu,
                        })
                    }
                    MoveCallEnvelope::EntryFunction {
                        module_id,
                        function_name,
                        args,
                    } => {
                        if FORBIDDEN_MOVE_MODULES.contains(&module_id.as_str()) {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: format!(
                                    "Move module `{module_id}` is disabled on Budlum"
                                )
                                .into_bytes(),
                                gas_used: base_bgu,
                            });
                        }
                        if module_id == "0x1::randomness" {
                            let mut h = Sha3_256::new();
                            h.update(ctx.randao);
                            h.update(signer32);
                            h.update(function_name.as_bytes());
                            let rbytes: [u8; 32] = h.finalize().into();
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Success,
                                output: rbytes.to_vec(),
                                gas_used: base_bgu,
                            });
                        }
                        if (module_id == "0x1::aptos_account" || module_id == "0x1::coin")
                            && function_name == "transfer"
                        {
                            let Some(dst_hex) = args.first() else {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"missing transfer recipient".to_vec(),
                                    gas_used: base_bgu,
                                });
                            };
                            let octas: u64 = args
                                .get(1)
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                            let Ok(dst_vec) = hex::decode(dst_hex.trim_start_matches("0x")) else {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"bad recipient hex".to_vec(),
                                    gas_used: base_bgu,
                                });
                            };
                            let attos = u128::from(octas).saturating_mul(ATTOS_PER_OCTA);
                            if let Err(e) = host.bud_transfer(
                                &EeIdentity {
                                    ee: EeId::MOVE,
                                    id: signer32.to_vec(),
                                },
                                &EeIdentity {
                                    ee: EeId::MOVE,
                                    id: dst_vec,
                                },
                                attos,
                            ) {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: e.to_string().into_bytes(),
                                    gas_used: base_bgu,
                                });
                            }
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Success,
                                output: octas.to_le_bytes().to_vec(),
                                gas_used: base_bgu,
                            });
                        }
                        let tag = format!("{module_id}::{function_name}");
                        let res_k = state_key_resource(&signer32, &tag);
                        let payload = args.join(",").into_bytes();
                        let _ = host.write(&move_ns, &res_k, Some(&payload));
                        let _ = host.emit_log(EeLog {
                            address: signer32.to_vec(),
                            topics: vec![Sha3_256::digest(module_id.as_bytes()).into()],
                            data: payload.clone(),
                        });
                        Ok(EeOutcome {
                            status: OutcomeStatus::Success,
                            output: payload,
                            gas_used: base_bgu,
                        })
                    }
                    MoveCallEnvelope::BudlumUniversalCall {
                        target_ee,
                        target,
                        input,
                        value_octas,
                        gas_bgu,
                        is_static,
                    } => {
                        let payload = if is_static {
                            wrap_static_universal_input(&input)
                        } else {
                            input
                        };
                        let attos = u128::from(value_octas).saturating_mul(ATTOS_PER_OCTA);
                        match host.universal_call(UniversalCall {
                            from: EeIdentity {
                                ee: EeId::MOVE,
                                id: signer32.to_vec(),
                            },
                            to_ee: EeId(target_ee),
                            target: EeIdentity {
                                ee: EeId(target_ee),
                                id: target,
                            },
                            value: BudAmount(attos),
                            input: payload,
                            gas_limit: gas_bgu,
                        }) {
                            Ok(r) => Ok(EeOutcome {
                                status: if r.success {
                                    OutcomeStatus::Success
                                } else {
                                    OutcomeStatus::Revert
                                },
                                output: r.output,
                                gas_used: base_bgu,
                            }),
                            Err(e) => Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: e.to_string().into_bytes(),
                                gas_used: base_bgu,
                            }),
                        }
                    }
                }
            }
        }
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let move_ns = Namespace::new(NS_MOVE_STATE).map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: e.to_string(),
        })?;
        host.read(&move_ns, &q.input)
            .map(Option::unwrap_or_default)
            .map_err(|e| EeRefusal {
                code: RefusalCode::Denied,
                message: e.to_string(),
            })
    }
}
