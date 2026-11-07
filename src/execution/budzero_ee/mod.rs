//! BudZero execution-environment adapter (`EeId::BUDZERO = 0x00`, ).
//!
//! Runs BudZero bytecode in execution-only mode against the UEL [`HostApi`]
//! (`ee/budzero/program` and `ee/budzero/storage`), populating all four 64-bit
//! words of `sender_words` (`256-bit` caller identity,  execution leg)
//! and holding `VerifyMerkle` and `VerifyInference` closed (, ).
//!
//! WIRING: exposed for in-process testing and paired with the out-of-process
//! `budlum-ee-budzero` worker binary (`execution/budzero/`).

use bud_isa::{Instruction, MainnetActivation};
use bud_vm::Vm;
use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeLog, EeOutcome, EeQuery,
    EeRefusal, ExecutionEnvironment, HostApi, HostError, HostRead, Namespace, OutcomeStatus,
    RefusalCode,
};

use crate::core::hash::calculate_hash_bytes;
use crate::execution::coordinator::commitment::{NS_BUDZERO_PROGRAM, NS_BUDZERO_STORAGE};

/// Maximum deployable BudZero bytecode size (`1 MiB`).
pub const MAX_BUDZERO_CODE_BYTES: usize = 1024 * 1024;
const BUDZERO_VM_MEMORY_BYTES: usize = 8192;
const MAX_CALL_SLOTS: usize = 256;

/// Call payload header:
/// `[declared_count_u32_le, slot_u64_le..., input_count_u32_le, (slot, val)...]`.
/// When `input` is empty, runs with zero pre-declared slots.
///
/// Convenience: used by SDK callers and `BudZeroEe` integration tests.
#[must_use]
pub fn encode_budzero_call_input(declared_slots: &[u64], inputs: &[(u64, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(declared_slots.len() as u32).to_le_bytes());
    for s in declared_slots {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
    for (s, v) in inputs {
        out.extend_from_slice(&s.to_le_bytes());
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

fn decode_budzero_call_input(mut cur: &[u8]) -> Result<(Vec<u64>, Vec<(u64, u64)>), String> {
    if cur.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let decl_len = take_u32(&mut cur)? as usize;
    if decl_len > MAX_CALL_SLOTS {
        return Err("too many declared BudZero slots".into());
    }
    let mut declared = Vec::with_capacity(decl_len);
    for _ in 0..decl_len {
        declared.push(take_u64(&mut cur)?);
    }
    let in_len = take_u32(&mut cur)? as usize;
    if in_len > MAX_CALL_SLOTS {
        return Err("too many BudZero call input pairs".into());
    }
    let mut pairs = Vec::with_capacity(in_len);
    for _ in 0..in_len {
        let s = take_u64(&mut cur)?;
        let v = take_u64(&mut cur)?;
        pairs.push((s, v));
    }
    if !cur.is_empty() {
        return Err("trailing bytes in BudZero call input".into());
    }
    Ok((declared, pairs))
}

fn take_u32(cur: &mut &[u8]) -> Result<u32, String> {
    let Some((h, t)) = cur.split_at_checked(4) else {
        return Err("truncated u32 in BudZero input".into());
    };
    let arr: [u8; 4] = h.try_into().map_err(|_| "bad u32".to_string())?;
    *cur = t;
    Ok(u32::from_le_bytes(arr))
}

fn take_u64(cur: &mut &[u8]) -> Result<u64, String> {
    let Some((h, t)) = cur.split_at_checked(8) else {
        return Err("truncated u64 in BudZero input".into());
    };
    let arr: [u8; 8] = h.try_into().map_err(|_| "bad u64".to_string())?;
    *cur = t;
    Ok(u64::from_le_bytes(arr))
}

fn decode_gated_program(code: &[u8]) -> Result<Vec<u64>, EeRefusal> {
    if code.is_empty() {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: "empty BudZero bytecode".into(),
        });
    }
    if code.len() > MAX_BUDZERO_CODE_BYTES {
        return Err(EeRefusal {
            code: RefusalCode::TooLarge,
            message: "BudZero bytecode exceeds 1 MiB".into(),
        });
    }
    if !code.len().is_multiple_of(8) {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: "BudZero bytecode must be 8-byte aligned".into(),
        });
    }
    let mut words = Vec::with_capacity(code.len() / 8);
    for chunk in code.chunks_exact(8) {
        let arr: [u8; 8] = chunk.try_into().map_err(|_| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: "bad instruction slice".into(),
        })?;
        let raw = u64::from_le_bytes(arr);
        Instruction::decode_for_mainnet(raw, MainnetActivation::default()).map_err(|e| {
            EeRefusal {
                code: RefusalCode::InvalidCode,
                message: e.to_string(),
            }
        })?;
        words.push(raw);
    }
    Ok(words)
}

fn storage_key(target_id: &[u8], slot: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(target_id.len() + 8);
    key.extend_from_slice(target_id);
    key.extend_from_slice(&slot.to_le_bytes());
    key
}

fn apply_caller_words(vm: &mut Vm, caller_id: &[u8]) {
    let mut padded = [0u8; 32];
    let copy_len = caller_id.len().min(32);
    if let (Some(dst), Some(src)) = (padded.get_mut(..copy_len), caller_id.get(..copy_len)) {
        dst.copy_from_slice(src);
    }
    vm.context.set_sender_bytes(&padded);
}

/// Execution-only BudZero environment implementing [`ExecutionEnvironment`].
#[derive(Debug, Default, Clone, Copy)]
pub struct BudZeroEe;

impl BudZeroEe {
    /// Construct a new execution-only BudZero environment.
    ///
    /// Convenience: instantiated by UEL worker hosts and integration tests.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ExecutionEnvironment for BudZeroEe {
    fn id(&self) -> EeId {
        EeId::BUDZERO
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        let _ = decode_gated_program(code)?;
        Ok(CodeInfo {
            code_hash: calculate_hash_bytes(code),
            abi_tag: "budzero-v1".into(),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let Ok(prog_ns) = Namespace::new(NS_BUDZERO_PROGRAM) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: Vec::new(),
                gas_used: 0,
            });
        };
        let Ok(store_ns) = Namespace::new(NS_BUDZERO_STORAGE) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: Vec::new(),
                gas_used: 0,
            });
        };

        match call.kind {
            EeCallKind::Deploy => {
                if decode_gated_program(&call.input).is_err() {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                }
                match host.write(&prog_ns, &call.target.id, Some(&call.input)) {
                    Ok(()) => Ok(EeOutcome {
                        status: OutcomeStatus::Success,
                        output: call.target.id.clone(),
                        gas_used: 0,
                    }),
                    Err(HostError::OutOfGas) => Ok(EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    }),
                    Err(e) => Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: e.to_string().into_bytes(),
                        gas_used: 0,
                    }),
                }
            }
            EeCallKind::Call => {
                let code_bytes = match host.read(&prog_ns, &call.target.id) {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"program not found".to_vec(),
                            gas_used: 0,
                        });
                    }
                    Err(e) => {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: e.to_string().into_bytes(),
                            gas_used: 0,
                        });
                    }
                };
                let Ok(program) = decode_gated_program(&code_bytes) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                };
                let Ok((declared, inputs)) = decode_budzero_call_input(&call.input) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"malformed BudZero call input".to_vec(),
                        gas_used: 0,
                    });
                };

                let mut vm = Vm::with_mainnet_mode(BUDZERO_VM_MEMORY_BYTES, call.gas_limit, true);
                apply_caller_words(&mut vm, &call.caller.id);
                vm.context.block_height = ctx.height;

                for slot in declared {
                    let key = storage_key(&call.target.id, slot);
                    if let Ok(Some(raw)) = host.read(&store_ns, &key) {
                        if let Ok(arr) = raw.as_slice().try_into() {
                            vm.storage.insert(slot, u64::from_le_bytes(arr));
                        }
                    }
                }
                for (slot, val) in inputs {
                    vm.storage.insert(slot, val);
                }

                let receipt = vm.run_receipt(&program);
                if host.charge(receipt.gas_used).is_err() {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                }
                if !receipt.success {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used: receipt.gas_used,
                    });
                }

                for (slot, val) in &vm.state_writes {
                    let key = storage_key(&call.target.id, *slot);
                    if let Err(err) = host.write(&store_ns, &key, Some(&val.to_le_bytes())) {
                        let status = if matches!(err, HostError::OutOfGas) {
                            OutcomeStatus::OutOfGas
                        } else {
                            OutcomeStatus::Revert
                        };
                        return Ok(EeOutcome {
                            status,
                            output: Vec::new(),
                            gas_used: call.gas_limit,
                        });
                    }
                }
                for ev in &receipt.events {
                    let _ = host.emit_log(EeLog {
                        emitter: call.target.clone(),
                        topics: Vec::new(),
                        data: ev.to_le_bytes().to_vec(),
                    });
                }

                let mut out = Vec::with_capacity(receipt.events.len() * 8);
                for ev in &receipt.events {
                    out.extend_from_slice(&ev.to_le_bytes());
                }
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: out,
                    gas_used: receipt.gas_used,
                })
            }
        }
    }

    fn query(
        &self,
        ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let prog_ns = Namespace::new(NS_BUDZERO_PROGRAM).map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: e.to_string(),
        })?;
        let store_ns = Namespace::new(NS_BUDZERO_STORAGE).map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: e.to_string(),
        })?;
        let code_bytes = host
            .read(&prog_ns, &q.target.id)
            .map_err(|e| EeRefusal {
                code: RefusalCode::Denied,
                message: e.to_string(),
            })?
            .ok_or_else(|| EeRefusal {
                code: RefusalCode::InvalidCode,
                message: "program not found".into(),
            })?;
        let program = decode_gated_program(&code_bytes)?;
        let (declared, inputs) =
            decode_budzero_call_input(&q.input).map_err(|message| EeRefusal {
                code: RefusalCode::InvalidCode,
                message,
            })?;

        let mut vm = Vm::with_mainnet_mode(BUDZERO_VM_MEMORY_BYTES, 1_000_000, true);
        vm.context.block_height = ctx.height;
        for slot in declared {
            let key = storage_key(&q.target.id, slot);
            if let Ok(Some(raw)) = host.read(&store_ns, &key) {
                if let Ok(arr) = raw.as_slice().try_into() {
                    vm.storage.insert(slot, u64::from_le_bytes(arr));
                }
            }
        }
        for (slot, val) in inputs {
            vm.storage.insert(slot, val);
        }
        let receipt = vm.run_receipt(&program);
        if !receipt.success {
            return Err(EeRefusal {
                code: RefusalCode::Denied,
                message: "query execution reverted".into(),
            });
        }
        let mut out = Vec::with_capacity(receipt.events.len() * 8);
        for ev in &receipt.events {
            out.extend_from_slice(&ev.to_le_bytes());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bud_isa::Opcode;
    use budlum_uel_abi::mock::InMemoryHost;
    use budlum_uel_abi::{BudAmount, EeIdentity};

    fn encode_instrs(instrs: &[Instruction]) -> Vec<u8> {
        let mut out = Vec::with_capacity(instrs.len() * 8);
        for ins in instrs {
            out.extend_from_slice(&ins.encode().to_le_bytes());
        }
        out
    }

    #[test]
    fn verify_merkle_is_closed_on_testnet() {
        let ee = BudZeroEe::new();
        let bad = encode_instrs(&[
            Instruction {
                opcode: Opcode::VerifyMerkle,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
        ]);
        let err = ee.validate_deploy(&bad).unwrap_err();
        assert_eq!(err.code, RefusalCode::InvalidCode);
    }

    #[test]
    fn verify_inference_is_closed_on_testnet() {
        let ee = BudZeroEe::new();
        let bad = encode_instrs(&[
            Instruction {
                opcode: Opcode::VerifyInference,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
        ]);
        let err = ee.validate_deploy(&bad).unwrap_err();
        assert_eq!(err.code, RefusalCode::InvalidCode);
    }

    #[test]
    fn budzero_ee_stateful_program_persists() {
        let mut ee = BudZeroEe::new();
        let mut host = InMemoryHost::new(5_000_000);
        let ctx = BlockContext {
            chain_id: 45261,
            height: 77,
            timestamp_ms: 1_700_000_000_000,
        };
        let caller = EeIdentity::new(EeId::BUDZERO, vec![0xAA; 32]).unwrap();
        let contract = EeIdentity::new(EeId::BUDZERO, vec![0xCC; 32]).unwrap();

        // Program: slot[0] = slot[0] + 1; Log(slot[0]); Halt
        let code = encode_instrs(&[
            Instruction {
                opcode: Opcode::Load,
                rd: 5,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::SRead,
                rd: 1,
                rs1: 5,
                rs2: 0,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::Load,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 1,
            },
            Instruction {
                opcode: Opcode::Add,
                rd: 3,
                rs1: 1,
                rs2: 2,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::SWrite,
                rd: 0,
                rs1: 5,
                rs2: 3,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::Log,
                rd: 0,
                rs1: 3,
                rs2: 0,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
        ]);

        let deploy_out = ee
            .execute(
                &ctx,
                &EeCall {
                    kind: EeCallKind::Deploy,
                    caller: caller.clone(),
                    target: contract.clone(),
                    value: BudAmount(0),
                    input: code,
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [1u8; 32],
                },
                &mut host,
            )
            .unwrap();
        assert_eq!(deploy_out.status, OutcomeStatus::Success);

        let call_in = encode_budzero_call_input(&[0], &[]);
        let c1 = ee
            .execute(
                &ctx,
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: caller.clone(),
                    target: contract.clone(),
                    value: BudAmount(0),
                    input: call_in.clone(),
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [2u8; 32],
                },
                &mut host,
            )
            .unwrap();
        assert_eq!(c1.status, OutcomeStatus::Success);
        assert_eq!(c1.output, 1u64.to_le_bytes());

        let c2 = ee
            .execute(
                &ctx,
                &EeCall {
                    kind: EeCallKind::Call,
                    caller,
                    target: contract,
                    value: BudAmount(0),
                    input: call_in,
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [3u8; 32],
                },
                &mut host,
            )
            .unwrap();
        assert_eq!(c2.status, OutcomeStatus::Success);
        assert_eq!(c2.output, 2u64.to_le_bytes());
    }

    #[test]
    fn budzero_sender_is_four_words() {
        let mut ee = BudZeroEe::new();
        let mut host = InMemoryHost::new(5_000_000);
        let ctx = BlockContext {
            chain_id: 45261,
            height: 88,
            timestamp_ms: 1_700_000_000_000,
        };
        let mut sender32 = [0u8; 32];
        sender32[0..8].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        sender32[8..16].copy_from_slice(&0x1112_1314_1516_1718u64.to_le_bytes());
        sender32[16..24].copy_from_slice(&0x2122_2324_2526_2728u64.to_le_bytes());
        sender32[24..32].copy_from_slice(&0x3132_3334_3536_3738u64.to_le_bytes());

        let caller = EeIdentity::new(EeId::BUDZERO, sender32.to_vec()).unwrap();
        let contract = EeIdentity::new(EeId::BUDZERO, vec![0xDD; 32]).unwrap();

        let code = encode_instrs(&[
            Instruction {
                opcode: Opcode::Syscall,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 10,
            },
            Instruction {
                opcode: Opcode::Log,
                rd: 0,
                rs1: 1,
                rs2: 0,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::Syscall,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 11,
            },
            Instruction {
                opcode: Opcode::Log,
                rd: 0,
                rs1: 2,
                rs2: 0,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::Syscall,
                rd: 3,
                rs1: 0,
                rs2: 0,
                imm: 12,
            },
            Instruction {
                opcode: Opcode::Log,
                rd: 0,
                rs1: 3,
                rs2: 0,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::Syscall,
                rd: 4,
                rs1: 0,
                rs2: 0,
                imm: 13,
            },
            Instruction {
                opcode: Opcode::Log,
                rd: 0,
                rs1: 4,
                rs2: 0,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
        ]);

        ee.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: caller.clone(),
                target: contract.clone(),
                value: BudAmount(0),
                input: code,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [4u8; 32],
            },
            &mut host,
        )
        .unwrap();

        let out = ee
            .execute(
                &ctx,
                &EeCall {
                    kind: EeCallKind::Call,
                    caller,
                    target: contract,
                    value: BudAmount(0),
                    input: Vec::new(),
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [5u8; 32],
                },
                &mut host,
            )
            .unwrap();
        assert_eq!(out.status, OutcomeStatus::Success);
        assert_eq!(out.output, sender32);
    }
}
