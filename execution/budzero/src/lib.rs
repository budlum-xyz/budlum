//! Out-of-process BudZero UEL worker library (`budlum-ee-budzero`).

#![forbid(unsafe_code)]

use bud_isa::{Instruction, MainnetActivation, Opcode};
use bud_vm::Vm;
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostError, HostRead, Namespace,
    OutcomeStatus, RefusalCode, UniversalCall,
};
use sha2::{Digest as _, Sha256};

/// Canonical BudZero program namespace.
pub const NS_BUDZERO_PROGRAM: &str = "ee/budzero/program";
/// Canonical BudZero contract storage namespace.
pub const NS_BUDZERO_STORAGE: &str = "ee/budzero/storage";
/// BudZero UEL Universal Call syscall number (`Section 8.7.2` BudZero row: `0x40`).
pub const SYSCALL_UNIVERSAL_CALL: i32 = 0x40;

const MAX_CODE_BYTES: usize = 1024 * 1024;
const WORKER_VM_MEMORY_BYTES: usize = 8192;
const MAX_SLOTS_PER_CALL: usize = 256;

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn decode_gated(code: &[u8]) -> Result<Vec<u64>, EeRefusal> {
    if code.is_empty() {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: "empty BudZero bytecode".into(),
        });
    }
    if code.len() > MAX_CODE_BYTES {
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
            message: "invalid word slice".into(),
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

fn take_u32(cur: &mut &[u8]) -> Result<u32, String> {
    let Some((h, t)) = cur.split_at_checked(4) else {
        return Err("truncated u32".into());
    };
    let arr: [u8; 4] = h.try_into().map_err(|_| "bad u32".to_string())?;
    *cur = t;
    Ok(u32::from_le_bytes(arr))
}

fn take_u64(cur: &mut &[u8]) -> Result<u64, String> {
    let Some((h, t)) = cur.split_at_checked(8) else {
        return Err("truncated u64".into());
    };
    let arr: [u8; 8] = h.try_into().map_err(|_| "bad u64".to_string())?;
    *cur = t;
    Ok(u64::from_le_bytes(arr))
}

type ParsedCallPayload = (Vec<u64>, Vec<(u64, u64)>);

fn parse_call_payload(mut cur: &[u8]) -> Result<ParsedCallPayload, String> {
    if cur.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let decl_count = take_u32(&mut cur)? as usize;
    if decl_count > MAX_SLOTS_PER_CALL {
        return Err("declared slot limit exceeded".into());
    }
    let mut declared = Vec::with_capacity(decl_count);
    for _ in 0..decl_count {
        declared.push(take_u64(&mut cur)?);
    }
    let input_count = take_u32(&mut cur)? as usize;
    if input_count > MAX_SLOTS_PER_CALL {
        return Err("input slot limit exceeded".into());
    }
    let mut pairs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let s = take_u64(&mut cur)?;
        let v = take_u64(&mut cur)?;
        pairs.push((s, v));
    }
    if !cur.is_empty() {
        return Err("trailing bytes in call payload".into());
    }
    Ok((declared, pairs))
}

fn slot_key(contract: &[u8], slot: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(contract.len() + 8);
    key.extend_from_slice(contract);
    key.extend_from_slice(&slot.to_le_bytes());
    key
}

fn set_caller_256(vm: &mut Vm, caller_id: &[u8]) {
    let buf: [u8; 32] = if let Ok(exact) = caller_id.try_into() {
        exact
    } else {
        let mut h = Sha256::new();
        let tag = b"bud-ee-budzero-caller-v1";
        h.update((tag.len() as u64).to_le_bytes());
        h.update(tag);
        h.update((caller_id.len() as u64).to_le_bytes());
        h.update(caller_id);
        h.finalize().into()
    };
    vm.context.set_sender_bytes(&buf);
}

fn read_packed_bytes(
    storage: &std::collections::HashMap<u64, u64>,
    base: u64,
    len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let words = len.div_ceil(8);
    for idx in 0..words {
        let w = storage
            .get(&(base.saturating_add(idx as u64)))
            .copied()
            .unwrap_or(0);
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn program_has_universal_syscall(program: &[u64]) -> bool {
    program.iter().any(|&raw| {
        Instruction::decode_for_mainnet(raw, MainnetActivation::default())
            .is_ok_and(|inst| inst.opcode == Opcode::Syscall && inst.imm == SYSCALL_UNIVERSAL_CALL)
    })
}

/// Execution-only BudZero worker engine (`panic = "unwind"`).
#[derive(Debug, Default, Clone, Copy)]
pub struct BudZeroWorker;

impl ExecutionEnvironment for BudZeroWorker {
    fn id(&self) -> EeId {
        EeId::BUDZERO
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        let _ = decode_gated(code)?;
        Ok(CodeInfo {
            code_hash: sha256_bytes(code),
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
                if decode_gated(&call.input).is_err() {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                }
                if matches!(host.read(&prog_ns, &call.target.id), Ok(Some(_))) {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"program already deployed".to_vec(),
                        gas_used: 0,
                    });
                }
                let Ok(cp) = host.checkpoint_begin() else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                };
                if host
                    .write(&prog_ns, &call.target.id, Some(&call.input))
                    .is_err()
                    || host
                        .write(
                            &prog_ns,
                            &[b"owner:", call.target.id.as_slice()].concat(),
                            Some(&call.caller.id),
                        )
                        .is_err()
                    || host.checkpoint_commit(cp).is_err()
                {
                    let _ = host.checkpoint_rollback(cp);
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                }
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: call.target.id.clone(),
                    gas_used: 0,
                })
            }
            EeCallKind::Call => {
                let Some(code_bytes) = host.read(&prog_ns, &call.target.id).ok().flatten() else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"program not found".to_vec(),
                        gas_used: 0,
                    });
                };
                let Ok(program) = decode_gated(&code_bytes) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                };
                let Ok((declared, pairs)) = parse_call_payload(&call.input) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"malformed call payload".to_vec(),
                        gas_used: 0,
                    });
                };

                // Gas is not a bound on the trace: a one-gas loop records one row
                // per step. The chain's own cap keeps a call at 2^14 rows.
                let mut vm = Vm::with_mainnet_mode(WORKER_VM_MEMORY_BYTES, call.gas_limit, true)
                    .with_step_limit(bud_vm::MAX_CONTRACT_TRACE_STEPS);
                set_caller_256(&mut vm, &call.caller.id);
                vm.context.block_height = ctx.height;

                for &slot in &declared {
                    let key = slot_key(&call.target.id, slot);
                    match host.read(&store_ns, &key) {
                        Ok(Some(raw)) => {
                            let Ok(arr) = <[u8; 8]>::try_from(raw.as_slice()) else {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"corrupt committed storage word".to_vec(),
                                    gas_used: 0,
                                });
                            };
                            let word = u64::from_le_bytes(arr);
                            if word >= bud_vm::GOLDILOCKS_P {
                                return Ok(EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: b"non-canonical committed storage word".to_vec(),
                                    gas_used: 0,
                                });
                            }
                            vm.storage.insert(slot, word);
                        }
                        Ok(None) => {}
                        Err(HostError::OutOfGas) => {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::OutOfGas,
                                output: Vec::new(),
                                gas_used: call.gas_limit,
                            });
                        }
                        Err(_) => {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: b"committed storage read failed".to_vec(),
                                gas_used: 0,
                            });
                        }
                    }
                }
                for (slot, val) in pairs {
                    if val >= bud_vm::GOLDILOCKS_P {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"non-canonical field element in call input".to_vec(),
                            gas_used: 0,
                        });
                    }
                    let key = slot_key(&call.target.id, slot);
                    let has_committed = match host.read(&store_ns, &key) {
                        Ok(Some(_)) => true,
                        Ok(None) => false,
                        Err(HostError::OutOfGas) => {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::OutOfGas,
                                output: Vec::new(),
                                gas_used: call.gas_limit,
                            });
                        }
                        Err(_) => {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: b"committed storage read failed".to_vec(),
                                gas_used: 0,
                            });
                        }
                    };
                    if declared.contains(&slot) || has_committed {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"call input slot collides with declared storage".to_vec(),
                            gas_used: 0,
                        });
                    }
                    vm.storage.insert(slot, val);
                }

                let Ok(call_cp) = host.checkpoint_begin() else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                };

                let mut ucall_gas = 0u64;
                if program_has_universal_syscall(&program) {
                    let is_owner_or_self = call.caller.id == call.target.id
                        || matches!(
                            host.read(&prog_ns, &[b"owner:", call.target.id.as_slice()].concat()),
                            Ok(Some(ref owner)) if owner.as_slice() == call.caller.id.as_slice()
                        );
                    if !is_owner_or_self {
                        let _ = host.checkpoint_rollback(call_cp);
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"unauthorized budzero universal syscall".to_vec(),
                            gas_used: 0,
                        });
                    }
                    let meta = vm.storage.get(&0x4000).copied().unwrap_or(0);
                    let to_ee = EeId((meta & 0xff) as u8);
                    let is_static = ((meta >> 8) & 1) != 0;
                    let req_gas = vm.storage.get(&0x4001).copied().unwrap_or(call.gas_limit);
                    let val_lo = u128::from(vm.storage.get(&0x4002).copied().unwrap_or(0));
                    let val_hi = u128::from(vm.storage.get(&0x4003).copied().unwrap_or(0));
                    let t_len = (vm.storage.get(&0x4004).copied().unwrap_or(0) as usize).min(64);
                    let i_len =
                        (vm.storage.get(&0x4005).copied().unwrap_or(0) as usize).min(16_384);
                    let target_bytes = read_packed_bytes(&vm.storage, 0x4010, t_len);
                    let input_bytes = read_packed_bytes(&vm.storage, 0x4100, i_len);
                    let ucall = UniversalCall {
                        from: call.target.clone(),
                        to_ee,
                        target: EeIdentity {
                            ee: to_ee,
                            id: target_bytes,
                        },
                        value: BudAmount((val_hi << 64) | val_lo),
                        input: input_bytes,
                        gas_limit: req_gas.min(call.gas_limit),
                        is_static,
                    };
                    match host.universal_call(ucall) {
                        Ok(ures) => {
                            ucall_gas = ures.gas_used;
                            vm.storage.insert(0x4006, u64::from(ures.success));
                        }
                        Err(HostError::OutOfGas) => {
                            let _ = host.checkpoint_rollback(call_cp);
                            return Ok(EeOutcome {
                                status: OutcomeStatus::OutOfGas,
                                output: Vec::new(),
                                gas_used: call.gas_limit,
                            });
                        }
                        Err(_) => {
                            let _ = host.checkpoint_rollback(call_cp);
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: Vec::new(),
                                gas_used: 0,
                            });
                        }
                    }
                }

                let receipt = vm.run_receipt(&program);
                let total_gas = receipt.gas_used.saturating_add(ucall_gas);
                if host.charge(total_gas).is_err() {
                    let _ = host.checkpoint_rollback(call_cp);
                    return Ok(EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                }
                if !receipt.success {
                    let _ = host.checkpoint_rollback(call_cp);
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used: total_gas,
                    });
                }
                let ordered_writes: std::collections::BTreeMap<u64, u64> =
                    vm.state_writes.iter().copied().collect();
                for (slot, val) in ordered_writes {
                    let key = slot_key(&call.target.id, slot);
                    if let Err(err) = host.write(&store_ns, &key, Some(&val.to_le_bytes())) {
                        let _ = host.checkpoint_rollback(call_cp);
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
                    if let Err(err) = host.emit_log(EeLog {
                        emitter: call.target.clone(),
                        topics: Vec::new(),
                        data: ev.to_le_bytes().to_vec(),
                    }) {
                        let _ = host.checkpoint_rollback(call_cp);
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
                if host.checkpoint_commit(call_cp).is_err() {
                    let _ = host.checkpoint_rollback(call_cp);
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                }
                let mut out = Vec::with_capacity(receipt.events.len() * 8);
                for ev in &receipt.events {
                    out.extend_from_slice(&ev.to_le_bytes());
                }
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: out,
                    gas_used: total_gas,
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
        let program = decode_gated(&code_bytes)?;
        let (declared, pairs) = parse_call_payload(&q.input).map_err(|message| EeRefusal {
            code: RefusalCode::InvalidCode,
            message,
        })?;

        // The read-only path charges no fee, so it needs the same trace cap.
        let mut vm = Vm::with_mainnet_mode(WORKER_VM_MEMORY_BYTES, 1_000_000, true)
            .with_step_limit(bud_vm::MAX_CONTRACT_TRACE_STEPS);
        vm.context.block_height = ctx.height;
        for &slot in &declared {
            let key = slot_key(&q.target.id, slot);
            let raw_opt = host.read(&store_ns, &key).map_err(|e| EeRefusal {
                code: RefusalCode::Denied,
                message: e.to_string(),
            })?;
            if let Some(raw) = raw_opt {
                let arr = <[u8; 8]>::try_from(raw.as_slice()).map_err(|_| EeRefusal {
                    code: RefusalCode::Denied,
                    message: "corrupt committed storage word".into(),
                })?;
                let word = u64::from_le_bytes(arr);
                if word >= bud_vm::GOLDILOCKS_P {
                    return Err(EeRefusal {
                        code: RefusalCode::Denied,
                        message: "non-canonical committed storage word".into(),
                    });
                }
                vm.storage.insert(slot, word);
            }
        }
        for (slot, val) in pairs {
            if val >= bud_vm::GOLDILOCKS_P {
                return Err(EeRefusal {
                    code: RefusalCode::InvalidCode,
                    message: "non-canonical field element in call input".into(),
                });
            }
            let key = slot_key(&q.target.id, slot);
            let has_committed = host
                .read(&store_ns, &key)
                .map_err(|e| EeRefusal {
                    code: RefusalCode::Denied,
                    message: e.to_string(),
                })?
                .is_some();
            if declared.contains(&slot) || has_committed {
                return Err(EeRefusal {
                    code: RefusalCode::Denied,
                    message: "call input slot collides with committed storage".into(),
                });
            }
            vm.storage.insert(slot, val);
        }
        let receipt = vm.run_receipt(&program);
        if !receipt.success {
            return Err(EeRefusal {
                code: RefusalCode::Denied,
                message: "query reverted".into(),
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
    use budlum_uel_abi::mock::MemoryHost;
    use budlum_uel_abi::{BudAmount, EeIdentity};

    #[test]
    fn worker_rejects_closed_opcodes_and_executes_four_word_sender() {
        let mut worker = BudZeroWorker;
        let merkle_code = Instruction {
            opcode: Opcode::VerifyMerkle,
            rd: 1,
            rs1: 0,
            rs2: 0,
            imm: 0,
        }
        .encode()
        .to_le_bytes();
        assert!(worker.validate_deploy(&merkle_code).is_err());

        let inf_code = Instruction {
            opcode: Opcode::VerifyInference,
            rd: 1,
            rs1: 0,
            rs2: 0,
            imm: 0,
        }
        .encode()
        .to_le_bytes();
        assert!(worker.validate_deploy(&inf_code).is_err());

        assert!(bud_isa::Instruction::decode_for_mainnet(
            Instruction {
                opcode: Opcode::VerifyMerkle,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0,
            }
            .encode(),
            bud_isa::MainnetActivation::closed(),
        )
        .is_err());

        let mut code = Vec::new();
        for (idx, imm) in [10i32, 11, 12, 13].into_iter().enumerate() {
            let r = (idx + 1) as u8;
            code.extend_from_slice(
                &Instruction {
                    opcode: Opcode::Syscall,
                    rd: r,
                    rs1: 0,
                    rs2: 0,
                    imm,
                }
                .encode()
                .to_le_bytes(),
            );
            code.extend_from_slice(
                &Instruction {
                    opcode: Opcode::Log,
                    rd: 0,
                    rs1: r,
                    rs2: 0,
                    imm: 0,
                }
                .encode()
                .to_le_bytes(),
            );
        }
        code.extend_from_slice(
            &Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            }
            .encode()
            .to_le_bytes(),
        );

        let mut host = MemoryHost::new(2_000_000);
        let Ok(caller) = EeIdentity::new(EeId::BUDZERO, vec![0xAB; 32]) else {
            panic!("caller");
        };
        let Ok(target) = EeIdentity::new(EeId::BUDZERO, vec![0xCD; 32]) else {
            panic!("target");
        };
        let ctx = BlockContext {
            chain_id: 45261,
            height: 1,
            timestamp_ms: 1_000,
        };
        let Ok(dep) = worker.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: caller.clone(),
                target: target.clone(),
                value: BudAmount(0),
                input: code,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [1u8; 32],
            },
            &mut host,
        ) else {
            panic!("deploy");
        };
        assert_eq!(dep.status, OutcomeStatus::Success);

        let Ok(res) = worker.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller,
                target,
                value: BudAmount(0),
                input: Vec::new(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [2u8; 32],
            },
            &mut host,
        ) else {
            panic!("call");
        };
        assert_eq!(res.status, OutcomeStatus::Success);
        assert_eq!(res.output, vec![0xAB; 32]);
    }

    /// A counter loop: `r1 = iterations`, then `r1 -= 1` until it is zero.
    /// It records `3 + 2 * iterations` trace rows and costs about as much gas.
    fn counter_loop(iterations: i32) -> Vec<u8> {
        let steps = [
            Instruction {
                opcode: Opcode::Load,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: iterations,
            },
            Instruction {
                opcode: Opcode::Load,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 1,
            },
            Instruction {
                opcode: Opcode::Sub,
                rd: 1,
                rs1: 1,
                rs2: 2,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::Jnz,
                rd: 0,
                rs1: 1,
                rs2: 0,
                imm: -1,
            },
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
        ];
        steps
            .iter()
            .flat_map(|ins| ins.encode().to_le_bytes())
            .collect()
    }

    /// One worker, one in-memory host, one deployed-or-not contract.
    struct Fixture {
        worker: BudZeroWorker,
        host: MemoryHost,
        ctx: BlockContext,
        caller: EeIdentity,
        target: EeIdentity,
    }

    impl Fixture {
        fn new() -> Self {
            let Ok(caller) = EeIdentity::new(EeId::BUDZERO, vec![0xAB; 32]) else {
                panic!("caller");
            };
            let Ok(target) = EeIdentity::new(EeId::BUDZERO, vec![0xCD; 32]) else {
                panic!("target");
            };
            Self {
                worker: BudZeroWorker,
                host: MemoryHost::new(5_000_000),
                ctx: BlockContext {
                    chain_id: 45261,
                    height: 1,
                    timestamp_ms: 1_000,
                },
                caller,
                target,
            }
        }

        fn deploy(&mut self, code: Vec<u8>) {
            let Ok(out) = self.worker.execute(
                &self.ctx,
                &EeCall {
                    kind: EeCallKind::Deploy,
                    caller: self.caller.clone(),
                    target: self.target.clone(),
                    value: BudAmount(0),
                    input: code,
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [1u8; 32],
                },
                &mut self.host,
            ) else {
                panic!("deploy");
            };
            assert_eq!(out.status, OutcomeStatus::Success);
        }

        fn call(&mut self, gas_limit: u64) -> EeOutcome {
            let Ok(out) = self.worker.execute(
                &self.ctx,
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: self.caller.clone(),
                    target: self.target.clone(),
                    value: BudAmount(0),
                    input: Vec::new(),
                    gas_limit,
                    depth: 0,
                    tx_hash: [2u8; 32],
                },
                &mut self.host,
            ) else {
                panic!("call");
            };
            out
        }

        fn query(&self) -> Result<Vec<u8>, EeRefusal> {
            let q = EeQuery {
                target: self.target.clone(),
                input: Vec::new(),
            };
            self.worker.query(&self.ctx, &q, &self.host)
        }
    }

    /// About 20,000 rows: over the cap, and far under a million gas.
    fn over_the_cap() -> Vec<u8> {
        let rows = bud_vm::MAX_CONTRACT_TRACE_STEPS as i32;
        counter_loop(rows / 2 + rows / 8)
    }

    /// Gas is not a bound on the trace. With a million gas, a loop that costs
    /// one gas a step would record a million rows for every validator.
    #[test]
    fn a_call_is_cut_off_at_the_trace_cap_whatever_its_gas() {
        let mut fx = Fixture::new();
        fx.deploy(over_the_cap());
        let out = fx.call(1_000_000);
        assert_eq!(
            out.status,
            OutcomeStatus::Revert,
            "a call that needs more rows than the cap is refused"
        );
    }

    /// The read-only path charges no fee, so it is the cheaper way to spend a
    /// validator's memory. It gets the same cap.
    #[test]
    fn a_query_is_cut_off_at_the_trace_cap() {
        let mut fx = Fixture::new();
        fx.deploy(over_the_cap());
        let refused = fx.query();
        assert!(
            matches!(&refused, Err(r) if r.code == RefusalCode::Denied),
            "a query past the trace cap must be refused: {refused:?}"
        );
    }

    #[test]
    fn a_call_and_a_query_under_the_trace_cap_still_run() {
        let mut fx = Fixture::new();
        fx.deploy(counter_loop(1_000));
        assert_eq!(fx.call(1_000_000).status, OutcomeStatus::Success);
        assert!(fx.query().is_ok());
    }

    #[test]
    fn short_caller_ids_with_trailing_zeros_remain_distinct_and_redeploy_refuses() {
        let mut vm_a = Vm::new(256);
        let mut vm_b = Vm::new(256);
        set_caller_256(&mut vm_a, &[0x42]);
        set_caller_256(&mut vm_b, &[0x42, 0x00]);
        assert_ne!(
            vm_a.context.sender, vm_b.context.sender,
            "distinct variable-length caller ids must not collide under zero-padding"
        );
        let exact = [0x5Au8; 32];
        let mut vm_c = Vm::new(256);
        set_caller_256(&mut vm_c, &exact);
        assert_eq!(vm_c.context.sender, u64::from_le_bytes([0x5Au8; 8]));

        let mut fx = Fixture::new();
        let code = counter_loop(4);
        fx.deploy(code.clone());
        let second = BudZeroWorker
            .execute(
                &BlockContext {
                    chain_id: 1,
                    height: 2,
                    timestamp_ms: 0,
                },
                &EeCall {
                    kind: EeCallKind::Deploy,
                    caller: EeIdentity {
                        ee: EeId::BUDZERO,
                        id: vec![9; 32],
                    },
                    target: fx.target.clone(),
                    value: BudAmount(0),
                    input: code,
                    gas_limit: 100_000,
                    depth: 0,
                    tx_hash: [0xAB; 32],
                },
                &mut fx.host,
            )
            .expect("no fault");
        assert_eq!(second.status, OutcomeStatus::Revert);
    }

    fn encode_call_payload(declared: &[u64], pairs: &[(u64, u64)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(declared.len() as u32).to_le_bytes());
        for &slot in declared {
            out.extend_from_slice(&slot.to_le_bytes());
        }
        out.extend_from_slice(&(pairs.len() as u32).to_le_bytes());
        for &(slot, val) in pairs {
            out.extend_from_slice(&slot.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        out
    }

    fn read_slot_and_log_program(slot: i32) -> Vec<u8> {
        let steps = [
            Instruction {
                opcode: Opcode::SRead,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: slot,
            },
            Instruction {
                opcode: Opcode::Log,
                rd: 0,
                rs1: 1,
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
        ];
        steps
            .iter()
            .flat_map(|ins| ins.encode().to_le_bytes())
            .collect()
    }

    #[test]
    fn query_refuses_call_input_colliding_with_committed_or_declared_storage() {
        let mut fx = Fixture::new();
        fx.deploy(read_slot_and_log_program(7));

        let Ok(store_ns) = Namespace::new(NS_BUDZERO_STORAGE) else {
            panic!("storage namespace");
        };
        let key = slot_key(&fx.target.id, 7);
        assert!(fx
            .host
            .write(&store_ns, &key, Some(&42u64.to_le_bytes()))
            .is_ok());

        // Legitimate read-only query returns the committed storage value.
        let ok = fx.worker.query(
            &fx.ctx,
            &EeQuery {
                target: fx.target.clone(),
                input: encode_call_payload(&[7], &[]),
            },
            &fx.host,
        );
        assert_eq!(ok, Ok(42u64.to_le_bytes().to_vec()));

        // Passing an input pair for a declared slot must be refused.
        let collide_declared = fx.worker.query(
            &fx.ctx,
            &EeQuery {
                target: fx.target.clone(),
                input: encode_call_payload(&[7], &[(7, 999)]),
            },
            &fx.host,
        );
        assert!(
            matches!(&collide_declared, Err(r) if r.code == RefusalCode::Denied),
            "query must refuse input colliding with declared slot: {collide_declared:?}"
        );

        // Omitting the slot from `declared` while it is already committed in storage must also be refused.
        let collide_committed = fx.worker.query(
            &fx.ctx,
            &EeQuery {
                target: fx.target.clone(),
                input: encode_call_payload(&[], &[(7, 999)]),
            },
            &fx.host,
        );
        assert!(
            matches!(&collide_committed, Err(r) if r.code == RefusalCode::Denied),
            "query must refuse input colliding with committed storage: {collide_committed:?}"
        );
    }

    #[test]
    fn execute_and_query_refuse_non_canonical_goldilocks_input_words() {
        let mut fx = Fixture::new();
        fx.deploy(read_slot_and_log_program(9));

        for bad_word in [bud_vm::GOLDILOCKS_P, u64::MAX] {
            let Ok(call_res) = fx.worker.execute(
                &fx.ctx,
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: fx.caller.clone(),
                    target: fx.target.clone(),
                    value: BudAmount(0),
                    input: encode_call_payload(&[], &[(9, bad_word)]),
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [3u8; 32],
                },
                &mut fx.host,
            ) else {
                panic!("call faulted unexpectedly");
            };
            assert_eq!(
                call_res.status,
                OutcomeStatus::Revert,
                "execute must refuse non-canonical word {bad_word}"
            );

            let query_res = fx.worker.query(
                &fx.ctx,
                &EeQuery {
                    target: fx.target.clone(),
                    input: encode_call_payload(&[], &[(9, bad_word)]),
                },
                &fx.host,
            );
            assert!(
                query_res.is_err(),
                "query must refuse non-canonical word {bad_word}: {query_res:?}"
            );
        }

        let max_canonical = bud_vm::GOLDILOCKS_P - 1;
        let Ok(ok_call) = fx.worker.execute(
            &fx.ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: fx.caller.clone(),
                target: fx.target.clone(),
                value: BudAmount(0),
                input: encode_call_payload(&[], &[(9, max_canonical)]),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [4u8; 32],
            },
            &mut fx.host,
        ) else {
            panic!("call faulted unexpectedly");
        };
        assert_eq!(ok_call.status, OutcomeStatus::Success);
        assert_eq!(ok_call.output, max_canonical.to_le_bytes().to_vec());

        let ok_query = fx.worker.query(
            &fx.ctx,
            &EeQuery {
                target: fx.target.clone(),
                input: encode_call_payload(&[], &[(9, max_canonical)]),
            },
            &fx.host,
        );
        assert_eq!(ok_query, Ok(max_canonical.to_le_bytes().to_vec()));
    }

    #[test]
    fn execute_and_query_refuse_corrupt_or_non_canonical_committed_storage_word() {
        let mut fx = Fixture::new();
        fx.deploy(read_slot_and_log_program(11));

        let Ok(store_ns) = Namespace::new(NS_BUDZERO_STORAGE) else {
            panic!("storage namespace");
        };
        assert!(fx
            .host
            .write(&store_ns, &slot_key(&fx.target.id, 11), Some(&[1, 2, 3, 4]))
            .is_ok());
        assert!(fx
            .host
            .write(
                &store_ns,
                &slot_key(&fx.target.id, 12),
                Some(&bud_vm::GOLDILOCKS_P.to_le_bytes()),
            )
            .is_ok());

        for bad_slot in [11u64, 12u64] {
            let Ok(call_res) = fx.worker.execute(
                &fx.ctx,
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: fx.caller.clone(),
                    target: fx.target.clone(),
                    value: BudAmount(0),
                    input: encode_call_payload(&[bad_slot], &[]),
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [5u8; 32],
                },
                &mut fx.host,
            ) else {
                panic!("call faulted unexpectedly");
            };
            assert_eq!(
                call_res.status,
                OutcomeStatus::Revert,
                "execute must fail closed on corrupt/non-canonical committed slot {bad_slot}"
            );

            let query_res = fx.worker.query(
                &fx.ctx,
                &EeQuery {
                    target: fx.target.clone(),
                    input: encode_call_payload(&[bad_slot], &[]),
                },
                &fx.host,
            );
            assert!(
                query_res.is_err(),
                "query must fail closed on corrupt/non-canonical committed slot {bad_slot}: {query_res:?}"
            );
        }
    }
}
