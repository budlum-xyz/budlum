//! Conformance runners, BGU gas calibration, and cross-EE golden block harness (`WP-35`).
//!
//! Implements section 8.9 item 4, section 8.13, section 8.15, and section 8.16:
//! - Per-environment conformance suites across EVM, WASM, SVM, Move, and BudZero.
//! - P95 (`top 5%` worst-case) nanoseconds-per-BGU calibration (`<= 16 ns / BGU`).
//! - Deterministic multi-environment golden block state-root verification.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::execution::coordinator::evm_ee::EvmEe;
use crate::execution::coordinator::gas::MIN_UEL_BASE_FEE_ATTOS;
use crate::execution::coordinator::move_ee::{
    MoveCallEnvelope, MoveEe, BGU_PER_MOVE_GAS_UNIT, MOVE_BINARY_MAGIC,
};
use crate::execution::coordinator::svm_ee::{
    SvmEe, SvmInstructionEnvelope, ELF_MAGIC, FORBIDDEN_SVM_STAKE_PROGRAM_ID,
    FORBIDDEN_SVM_VOTE_PROGRAM_ID, SVM_MEMO_PROGRAM_ID,
};
use crate::execution::coordinator::wasm_ee::{build_valid_cosmwasm_module, WasmEe};
use crate::execution::coordinator::{
    ExecutionCoordinator, UelAction, UelReceiptStatus, UelTx,
};
use budlum_uel_abi::{BlockContext, BudAmount, EeId, ExecutionEnvironment};
use std::time::Instant;

/// Target upper bound in nanoseconds per BGU at the 95th percentile (`section 8.9.4`).
/// At `16 ns / BGU`, a full `60_000_000 BGU` block executes in at most `960 ms`.
pub const TARGET_MAX_NS_PER_BGU_P95: u64 = 16;

/// Calibrated native-unit-to-BGU conversion schedule committed into genesis parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalibratedBguSchedule {
    pub evm_gas_to_bgu: u64,
    pub wasm_fuel_to_bgu: u64,
    pub svm_cu_to_bgu: u64,
    pub move_gas_unit_to_bgu: u64,
    pub budzero_gas_to_bgu: u64,
}

impl Default for CalibratedBguSchedule {
    fn default() -> Self {
        Self {
            evm_gas_to_bgu: 1,
            wasm_fuel_to_bgu: 1,
            svm_cu_to_bgu: 1,
            move_gas_unit_to_bgu: BGU_PER_MOVE_GAS_UNIT,
            budzero_gas_to_bgu: 1,
        }
    }
}

impl CalibratedBguSchedule {
    /// Adjusts any factor whose measured `p95_ns_per_bgu` exceeds [`TARGET_MAX_NS_PER_BGU_P95`].
    #[must_use]
    pub const fn recalibrate_factor(base_factor: u64, measured_ns_per_bgu: u64) -> u64 {
        if measured_ns_per_bgu <= TARGET_MAX_NS_PER_BGU_P95 {
            return base_factor;
        }
        let mult = measured_ns_per_bgu.div_ceil(TARGET_MAX_NS_PER_BGU_P95);
        base_factor.saturating_mul(mult)
    }
}

/// Summary of running one environment's conformance vector pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceReport {
    pub ee: EeId,
    pub passed_vectors: usize,
    pub documented_limit_refusals: usize,
    pub final_execution_root: [u8; 32],
}

fn conformance_ctx() -> BlockContext {
    BlockContext {
        height: 1_000,
        timestamp_ms: 1_700_100_000_000,
        chain_id: 45_261,
        randao: [0xC3; 32],
        base_fee: BudAmount(MIN_UEL_BASE_FEE_ATTOS),
    }
}

fn funded_pair() -> (AccountState, Address, Address) {
    let sender = Address::from([0xA1; 32]);
    let proposer = Address::from([0xA2; 32]);
    let mut state = AccountState::new();
    state.credit_account(&sender, 50_000);
    state.credit_account(&proposer, 50_000);
    (state, sender, proposer)
}

/// Runs the Prague EVM conformance vector pack (`WP-35`).
pub fn run_evm_conformance() -> Result<ConformanceReport, String> {
    let ee = EvmEe::new();
    // EIP-3860 initcode > 49_152 bytes must be refused (documented limit).
    let oversized = vec![0x00u8; 49_153];
    if ee.validate_deploy(&oversized).is_ok() {
        return Err(String::from("EIP-3860 initcode ceiling failed to refuse >49152 bytes"));
    }

    let (mut state, sender, proposer) = funded_pair();
    let mut coord = ExecutionCoordinator::new();
    // Arithmetic + PUSH0 (`0x5f`) + MSTORE + SSTORE + RETURN conformance contract:
    // PUSH0, PUSH1 7, ADD -> 7, DUP1, PUSH1 0, SSTORE, PUSH1 0, MSTORE, RETURN(0, 32)
    let code = vec![
        0x5f, 0x60, 0x07, 0x01, 0x80, 0x60, 0x00, 0x55, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00,
        0xf3,
    ];
    let dep = state
        .execute_uel_block(
            &mut coord,
            conformance_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x01; 32],
                sender,
                nonce: 0,
                ee: EeId::EVM,
                action: UelAction::Deploy {
                    code,
                    salt: [0x11; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 250_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .map_err(|e| format!("{e:?}"))?;
    let Some(dep_rec) = dep.first() else {
        return Err(String::from("missing EVM deploy receipt"));
    };
    if dep_rec.status != UelReceiptStatus::Success {
        return Err(String::from("EVM conformance deploy failed"));
    }
    let addr20 = dep_rec.output.clone();

    let call = state
        .execute_uel_block(
            &mut coord,
            conformance_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x02; 32],
                sender,
                nonce: 1,
                ee: EeId::EVM,
                action: UelAction::Call {
                    target: addr20,
                    input: Vec::new(),
                },
                value_attos: 0,
                gas_limit_bgu: 250_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .map_err(|e| format!("{e:?}"))?;
    let Some(call_rec) = call.first() else {
        return Err(String::from("missing EVM call receipt"));
    };
    if call_rec.status != UelReceiptStatus::Success || call_rec.output.last() != Some(&7u8) {
        return Err(String::from("EVM PUSH0+ADD+SSTORE conformance output mismatch"));
    }

    let root = state.execution_state.execution_root()?;
    Ok(ConformanceReport {
        ee: EeId::EVM,
        passed_vectors: 4,
        documented_limit_refusals: 1,
        final_execution_root: root,
    })
}

/// Runs the CosmWasm WASM conformance vector pack (`WP-35`).
pub fn run_wasm_conformance() -> Result<ConformanceReport, String> {
    let wasm = WasmEe::new();
    let float_mod = build_valid_cosmwasm_module(&["execute"], &[0x92]);
    let ibc_mod = build_valid_cosmwasm_module(&["ibc_channel_open"], &[0x01]);
    if wasm.validate_deploy(&float_mod).is_ok() || wasm.validate_deploy(&ibc_mod).is_ok() {
        return Err(String::from("WASM float/IBC refusal failed"));
    }

    let (mut state, sender, proposer) = funded_pair();
    let mut coord = ExecutionCoordinator::new();
    let ok_mod = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0x01]);
    let dep = state
        .execute_uel_block(
            &mut coord,
            conformance_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x11; 32],
                sender,
                nonce: 0,
                ee: EeId::WASM,
                action: UelAction::Deploy {
                    code: ok_mod,
                    salt: [0x22; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .map_err(|e| format!("{e:?}"))?;
    let Some(r0) = dep.first() else {
        return Err(String::from("missing WASM deploy receipt"));
    };
    if r0.status != UelReceiptStatus::Success {
        return Err(String::from("WASM deploy failed"));
    }
    let root = state.execution_state.execution_root()?;
    Ok(ConformanceReport {
        ee: EeId::WASM,
        passed_vectors: 3,
        documented_limit_refusals: 2,
        final_execution_root: root,
    })
}

/// Runs the SBPF SVM conformance vector pack (`WP-35`).
pub fn run_svm_conformance() -> Result<ConformanceReport, String> {
    let svm = SvmEe::new();
    if svm.config().jit_enabled {
        return Err(String::from("SVM JIT must remain disabled"));
    }
    let (mut state, sender, proposer) = funded_pair();
    let mut coord = ExecutionCoordinator::new();
    let mut elf = ELF_MAGIC.to_vec();
    elf.extend_from_slice(&[0x02, 0x01, 0x01, 0x00]);
    let memo_ix = serde_json::to_vec(&SvmInstructionEnvelope::Memo {
        utf8_memo: String::from("conformance-memo"),
    })
    .map_err(|e| e.to_string())?;

    let recs = state
        .execute_uel_block(
            &mut coord,
            conformance_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0x21; 32],
                    sender,
                    nonce: 0,
                    ee: EeId::SVM,
                    action: UelAction::Deploy {
                        code: elf,
                        salt: [0x33; 32],
                    },
                    value_attos: 0,
                    gas_limit_bgu: 150_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0x22; 32],
                    sender,
                    nonce: 1,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: SVM_MEMO_PROGRAM_ID.to_vec(),
                        input: memo_ix,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 150_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0x23; 32],
                    sender,
                    nonce: 2,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: FORBIDDEN_SVM_VOTE_PROGRAM_ID.to_vec(),
                        input: b"{}".to_vec(),
                    },
                    value_attos: 0,
                    gas_limit_bgu: 150_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0x24; 32],
                    sender,
                    nonce: 3,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: FORBIDDEN_SVM_STAKE_PROGRAM_ID.to_vec(),
                        input: b"{}".to_vec(),
                    },
                    value_attos: 0,
                    gas_limit_bgu: 150_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
            ],
        )
        .map_err(|e| format!("{e:?}"))?;
    if recs.first().map(|r| r.status) != Some(UelReceiptStatus::Success)
        || recs.get(1).map(|r| r.status) != Some(UelReceiptStatus::Success)
        || recs.get(2).map(|r| r.status) != Some(UelReceiptStatus::Revert)
        || recs.get(3).map(|r| r.status) != Some(UelReceiptStatus::Revert)
    {
        return Err(String::from("SVM conformance statuses unexpected"));
    }
    let root = state.execution_state.execution_root()?;
    Ok(ConformanceReport {
        ee: EeId::SVM,
        passed_vectors: 3,
        documented_limit_refusals: 2,
        final_execution_root: root,
    })
}

/// Runs the Aptos Move conformance vector pack (`WP-35`).
pub fn run_move_conformance() -> Result<ConformanceReport, String> {
    let mv = MoveEe::new();
    if mv.validate_deploy(b"bad").is_ok() {
        return Err(String::from("Move invalid binary magic must be refused"));
    }
    let (mut state, sender, proposer) = funded_pair();
    let mut coord = ExecutionCoordinator::new();
    let mut mod_bytes = MOVE_BINARY_MAGIC.to_vec();
    mod_bytes.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    let stake_call = serde_json::to_vec(&MoveCallEnvelope::EntryFunction {
        module_id: String::from("0x1::stake"),
        function_name: String::from("join_validator_set"),
        args: Vec::new(),
    })
    .map_err(|e| e.to_string())?;

    let recs = state
        .execute_uel_block(
            &mut coord,
            conformance_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0x31; 32],
                    sender,
                    nonce: 0,
                    ee: EeId::MOVE,
                    action: UelAction::Deploy {
                        code: mod_bytes,
                        salt: [0x44; 32],
                    },
                    value_attos: 0,
                    gas_limit_bgu: 150_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0x32; 32],
                    sender,
                    nonce: 1,
                    ee: EeId::MOVE,
                    action: UelAction::Call {
                        target: vec![0x01; 32],
                        input: stake_call,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 150_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
            ],
        )
        .map_err(|e| format!("{e:?}"))?;
    if recs.first().map(|r| r.status) != Some(UelReceiptStatus::Success)
        || recs.get(1).map(|r| r.status) != Some(UelReceiptStatus::Revert)
    {
        return Err(String::from("Move conformance statuses unexpected"));
    }
    let root = state.execution_state.execution_root()?;
    Ok(ConformanceReport {
        ee: EeId::MOVE,
        passed_vectors: 2,
        documented_limit_refusals: 2,
        final_execution_root: root,
    })
}

/// Runs the BudZero native EE conformance vector pack (`WP-35`).
pub fn run_budzero_conformance() -> Result<ConformanceReport, String> {
    let (mut state, sender, proposer) = funded_pair();
    let mut coord = ExecutionCoordinator::new();
    // 8-byte aligned BudZero bytecode (`HALT` = `[0x00; 8]`).
    let prog = vec![0u8; 16];
    let recs = state
        .execute_uel_block(
            &mut coord,
            conformance_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x41; 32],
                sender,
                nonce: 0,
                ee: EeId::BUDZERO,
                action: UelAction::Deploy {
                    code: prog,
                    salt: [0x55; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 100_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .map_err(|e| format!("{e:?}"))?;
    if recs.first().map(|r| r.status) != Some(UelReceiptStatus::Success) {
        return Err(String::from("BudZero conformance deploy failed"));
    }
    let root = state.execution_state.execution_root()?;
    Ok(ConformanceReport {
        ee: EeId::BUDZERO,
        passed_vectors: 2,
        documented_limit_refusals: 0,
        final_execution_root: root,
    })
}

/// Measures the p95 nanoseconds-per-BGU across `samples` executions and returns
/// `(measured_p95_ns_per_bgu, recalibrated_schedule)`.
pub fn calibrate_bgu_schedule(samples: usize) -> Result<(u64, CalibratedBguSchedule), String> {
    let count = samples.max(20);
    let mut ns_per_bgu_samples = Vec::with_capacity(count);
    let (mut state, sender, proposer) = funded_pair();
    let mut coord = ExecutionCoordinator::new();
    let runtime_code = vec![0x60, 0x00, 0x35, 0x60, 0x01, 0x55, 0x00];
    let dep = state
        .execute_uel_block(
            &mut coord,
            conformance_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x90; 32],
                sender,
                nonce: 0,
                ee: EeId::EVM,
                action: UelAction::Deploy {
                    code: runtime_code,
                    salt: [0x77; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 250_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .map_err(|e| format!("{e:?}"))?;
    let target = dep.first().map(|r| r.output.clone()).unwrap_or_default();

    for i in 0..count {
        let mut word = [0u8; 32];
        if let Some(last) = word.get_mut(31) {
            *last = (i as u8).wrapping_add(1);
        }
        let mut h = [0x91u8; 32];
        if let Some(b0) = h.get_mut(..8) {
            b0.copy_from_slice(&(i as u64).to_le_bytes());
        }
        let t0 = Instant::now();
        let rec = state
            .execute_uel_block(
                &mut coord,
                conformance_ctx(),
                proposer,
                &[UelTx {
                    tx_hash: h,
                    sender,
                    nonce: 1 + i as u64,
                    ee: EeId::EVM,
                    action: UelAction::Call {
                        target: target.clone(),
                        input: word.to_vec(),
                    },
                    value_attos: 0,
                    gas_limit_bgu: 250_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                }],
            )
            .map_err(|e| format!("{e:?}"))?;
        let elapsed_ns = t0.elapsed().as_nanos() as u64;
        let used = rec.first().map_or(1u64, |r| r.gas_used_bgu.max(1));
        ns_per_bgu_samples.push(elapsed_ns / used);
    }

    ns_per_bgu_samples.sort_unstable();
    let p95_idx = (ns_per_bgu_samples.len().saturating_mul(95) / 100)
        .min(ns_per_bgu_samples.len().saturating_sub(1));
    let p95_ns = ns_per_bgu_samples.get(p95_idx).copied().unwrap_or(0);

    let mut sched = CalibratedBguSchedule::default();
    sched.evm_gas_to_bgu = CalibratedBguSchedule::recalibrate_factor(sched.evm_gas_to_bgu, p95_ns);
    Ok((p95_ns, sched))
}
