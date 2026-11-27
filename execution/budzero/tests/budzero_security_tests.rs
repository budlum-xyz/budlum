//! Security regression tests for `budlum-ee-budzero`:
//! 1. `EeCallKind::Deploy` fails closed on `host.read` error instead of
//!    proceeding past the existing-program check, and propagates `OutOfGas`.
//! 2. `EeCallKind::Call` propagates `HostError::OutOfGas` on program reads,
//!    enforces `total_gas <= call.gas_limit` (including `UniversalCall` gas),
//!    and reports `OutcomeStatus::OutOfGas` on VM `OutOfGas`.
//! 3. Static `SYSCALL_UNIVERSAL_CALL` refuses non-zero value.
//! 4. Duplicate input slots in call payload fail closed.

use bud_isa::{Instruction, Opcode};
use budlum_ee_budzero::{BudZeroWorker, SYSCALL_UNIVERSAL_CALL};
use budlum_uel_abi::mock::MemoryHost;
use budlum_uel_abi::{
    BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity, EeLog, ExecutionEnvironment,
    HostApi, HostError, HostRead, Namespace, OutOfGas, OutcomeStatus, UniversalCall,
    UniversalResult,
};

fn ctx() -> BlockContext {
    BlockContext {
        chain_id: 45_261,
        height: 10,
        timestamp_ms: 1_700_000_000_000,
    }
}

fn enc(opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32) -> [u8; 8] {
    Instruction {
        opcode,
        rd,
        rs1,
        rs2,
        imm,
    }
    .encode()
    .to_le_bytes()
}

fn encode_call_payload(declared: &[u64], pairs: &[(u64, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(declared.len() as u32).to_le_bytes());
    for &s in declared {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out.extend_from_slice(&(pairs.len() as u32).to_le_bytes());
    for &(s, v) in pairs {
        out.extend_from_slice(&s.to_le_bytes());
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

struct FailProgReadHost {
    inner: MemoryHost,
}

impl HostRead for FailProgReadHost {
    fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
        if ns.as_str() == "ee/budzero/program" {
            return Err(HostError::OutOfGas);
        }
        self.inner.read(ns, key)
    }
    fn bud_balance(&self, id: &EeIdentity) -> Result<BudAmount, HostError> {
        self.inner.bud_balance(id)
    }
}

impl HostApi for FailProgReadHost {
    fn write(&mut self, ns: &Namespace, key: &[u8], value: Option<&[u8]>) -> Result<(), HostError> {
        self.inner.write(ns, key, value)
    }
    fn emit_log(&mut self, log: EeLog) -> Result<(), HostError> {
        self.inner.emit_log(log)
    }
    fn charge(&mut self, amount: u64) -> Result<(), OutOfGas> {
        self.inner.charge(amount)
    }
    fn universal_call(&mut self, call: UniversalCall) -> Result<UniversalResult, HostError> {
        self.inner.universal_call(call)
    }
    fn bud_transfer(
        &mut self,
        from: &EeIdentity,
        to: &EeIdentity,
        amount: u128,
    ) -> Result<(), HostError> {
        self.inner.bud_transfer(from, to, amount)
    }
    fn checkpoint_begin(&mut self) -> Result<u64, HostError> {
        self.inner.checkpoint_begin()
    }
    fn checkpoint_commit(&mut self, id: u64) -> Result<(), HostError> {
        self.inner.checkpoint_commit(id)
    }
    fn checkpoint_rollback(&mut self, id: u64) -> Result<(), HostError> {
        self.inner.checkpoint_rollback(id)
    }
}

#[test]
fn deploy_and_call_propagate_program_read_out_of_gas() {
    let mut worker = BudZeroWorker;
    let mut host = FailProgReadHost {
        inner: MemoryHost::new(2_000_000),
    };
    let code = enc(Opcode::Halt, 0, 0, 0, 0).to_vec();
    let deploy = EeCall {
        kind: EeCallKind::Deploy,
        caller: EeIdentity {
            ee: EeId::BUDZERO,
            id: vec![0xAA; 32],
        },
        target: EeIdentity {
            ee: EeId::BUDZERO,
            id: vec![0x11; 32],
        },
        value: BudAmount(0),
        input: code,
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x11; 32],
    };
    let Ok(r_dep) = worker.execute(&ctx(), &deploy, &mut host) else {
        panic!("exec");
    };
    assert_eq!(
        r_dep.status,
        OutcomeStatus::OutOfGas,
        "Deploy must fail closed with OutOfGas when program existence read errors"
    );

    let call = EeCall {
        kind: EeCallKind::Call,
        input: Vec::new(),
        tx_hash: [0x12; 32],
        ..deploy
    };
    let Ok(r_call) = worker.execute(&ctx(), &call, &mut host) else {
        panic!("exec");
    };
    assert_eq!(
        r_call.status,
        OutcomeStatus::OutOfGas,
        "Call must propagate HostError::OutOfGas on program read"
    );
}

#[test]
fn universal_call_enforces_combined_gas_limit_and_refuses_static_with_value() {
    let mut worker = BudZeroWorker;
    let mut host = MemoryHost::new(5_000_000).with_universal_handler(Box::new(|_uc| {
        Ok(UniversalResult {
            success: true,
            output: vec![],
            gas_used: 4_900,
        })
    }));
    let mut code = Vec::new();
    // Run a few ops (~100+ gas) + UniversalCall syscall + Halt.
    for _ in 0..20 {
        code.extend_from_slice(&enc(Opcode::Load, 1, 0, 0, 1));
    }
    code.extend_from_slice(&enc(Opcode::Syscall, 2, 0, 0, SYSCALL_UNIVERSAL_CALL));
    code.extend_from_slice(&enc(Opcode::Halt, 0, 0, 0, 0));

    let owner = vec![0xAA; 32];
    let target = vec![0x22; 32];
    let deploy = EeCall {
        kind: EeCallKind::Deploy,
        caller: EeIdentity {
            ee: EeId::BUDZERO,
            id: owner.clone(),
        },
        target: EeIdentity {
            ee: EeId::BUDZERO,
            id: target.clone(),
        },
        value: BudAmount(0),
        input: code,
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x21; 32],
    };
    assert_eq!(
        worker
            .execute(&ctx(), &deploy, &mut host)
            .ok()
            .map(|o| o.status),
        Some(OutcomeStatus::Success)
    );

    // 1. Static universal call carrying non-zero value -> MUST revert!
    // meta = to_ee(1) | (is_static=1 << 8) = 0x101, val_lo = 100
    let static_val_payload = encode_call_payload(&[], &[(0x4000, 0x101), (0x4002, 100)]);
    let call_static_val = EeCall {
        kind: EeCallKind::Call,
        caller: EeIdentity {
            ee: EeId::BUDZERO,
            id: owner.clone(),
        },
        target: EeIdentity {
            ee: EeId::BUDZERO,
            id: target.clone(),
        },
        value: BudAmount(0),
        input: static_val_payload,
        gas_limit: 100_000,
        depth: 0,
        tx_hash: [0x22; 32],
    };
    let Ok(r_sv) = worker.execute(&ctx(), &call_static_val, &mut host) else {
        panic!("exec");
    };
    assert_eq!(
        r_sv.status,
        OutcomeStatus::Revert,
        "static universal call with non-zero value must revert"
    );

    // 2. Combined gas (ucall_gas 4_900 + VM execution > 100) exceeds call.gas_limit 4_920 -> MUST return OutOfGas!
    let tight_payload = encode_call_payload(&[], &[(0x4000, 0x01), (0x4001, 4_920)]);
    let call_tight = EeCall {
        input: tight_payload,
        gas_limit: 4_920,
        tx_hash: [0x23; 32],
        ..call_static_val.clone()
    };
    let Ok(r_tight) = worker.execute(&ctx(), &call_tight, &mut host) else {
        panic!("exec");
    };
    assert_eq!(
        r_tight.status,
        OutcomeStatus::OutOfGas,
        "combined ucall_gas + vm gas exceeding call.gas_limit must return OutOfGas"
    );

    // 3. Duplicate input slots in call payload must revert.
    let dup_payload = encode_call_payload(&[], &[(0x5000, 1), (0x5000, 2)]);
    let call_dup = EeCall {
        input: dup_payload,
        gas_limit: 100_000,
        tx_hash: [0x24; 32],
        ..call_static_val
    };
    let Ok(r_dup) = worker.execute(&ctx(), &call_dup, &mut host) else {
        panic!("exec");
    };
    assert_eq!(
        r_dup.status,
        OutcomeStatus::Revert,
        "duplicate input slots in call payload must revert"
    );
}
