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

fn parse_call_payload(mut cur: &[u8]) -> Result<(Vec<u64>, Vec<(u64, u64)>), String> {
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
    let mut buf = [0u8; 32];
    let n = caller_id.len().min(32);
    if let (Some(dst), Some(src)) = (buf.get_mut(..n), caller_id.get(..n)) {
        dst.copy_from_slice(src);
    }
    vm.context.set_sender_bytes(&buf);
}

fn read_packed_bytes(
    storage: &std::collections::BTreeMap<u64, u64>,
    base: u64,
    len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let words = len.div_ceil(8);
    for idx in 0..words {
        let w = storage.get(&(base.saturating_add(idx as u64))).copied().unwrap_or(0);
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
                    Err(err) => Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: err.to_string().into_bytes(),
                        gas_used: 0,
                    }),
                }
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

                let mut vm = Vm::with_mainnet_mode(WORKER_VM_MEMORY_BYTES, call.gas_limit, true);
                set_caller_256(&mut vm, &call.caller.id);
                vm.context.block_height = ctx.height;

                for slot in declared {
                    let key = slot_key(&call.target.id, slot);
                    if let Ok(Some(raw)) = host.read(&store_ns, &key) {
                        if let Ok(arr) = raw.as_slice().try_into() {
                            vm.storage.insert(slot, u64::from_le_bytes(arr));
                        }
                    }
                }
                for (slot, val) in pairs {
                    vm.storage.insert(slot, val);
                }

                let mut ucall_gas = 0u64;
                if program_has_universal_syscall(&program) {
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
                            return Ok(EeOutcome {
                                status: OutcomeStatus::OutOfGas,
                                output: Vec::new(),
                                gas_used: call.gas_limit,
                            });
                        }
                        Err(_) => {
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
                        gas_used: total_gas,
                    });
                }
                for (slot, val) in &vm.state_writes {
                    let key = slot_key(&call.target.id, *slot);
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

        let mut vm = Vm::with_mainnet_mode(WORKER_VM_MEMORY_BYTES, 1_000_000, true);
        vm.context.block_height = ctx.height;
        for slot in declared {
            let key = slot_key(&q.target.id, slot);
            if let Ok(Some(raw)) = host.read(&store_ns, &key) {
                if let Ok(arr) = raw.as_slice().try_into() {
                    vm.storage.insert(slot, u64::from_le_bytes(arr));
                }
            }
        }
        for (slot, val) in pairs {
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
}
