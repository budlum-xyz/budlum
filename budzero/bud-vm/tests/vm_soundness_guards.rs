//! Soundness and determinism regression tests for `bud-vm`:
//! 1. `SRead` and `SWrite` refusals halt the VM and populate `vm.error`.
//! 2. Negative jump/call targets fail immediately with `InvalidPc` without
//!    wrapping `next_pc` to `usize::MAX` in the trace or mutating the stack.
//! 3. `VerifyMerkle` refuses non-canonical Goldilocks memory words (`>= P`)
//!    rather than emitting a trace that diverges from the AIR.

use bud_isa::{Instruction, Opcode};
use bud_vm::{Vm, VmError, GOLDILOCKS_P};

fn enc(opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32) -> u64 {
    Instruction {
        opcode,
        rd,
        rs1,
        rs2,
        imm,
    }
    .encode()
}

#[test]
fn sread_and_swrite_non_canonical_refusal_halts_vm_and_sets_error() {
    // SRead from a non-canonical slot in rs2 (imm = -1).
    let prog_read = vec![
        enc(Opcode::SRead, 1, 0, 2, -1),
        enc(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(64);
    vm.registers[2] = GOLDILOCKS_P;
    let err = vm.step(&prog_read).expect_err("non-canonical slot refused");
    assert_eq!(err, VmError::InvalidMemoryAccess);
    assert!(vm.halted, "SRead error must set vm.halted = true");
    assert_eq!(
        vm.error,
        Some(VmError::InvalidMemoryAccess),
        "SRead error must record vm.error"
    );

    // SRead of a non-canonical stored value.
    let prog_read_val = vec![
        enc(Opcode::SRead, 1, 0, 0, 0),
        enc(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm2 = Vm::new(64);
    vm2.storage.insert(0, GOLDILOCKS_P);
    let err2 = vm2
        .step(&prog_read_val)
        .expect_err("non-canonical stored value refused");
    assert_eq!(err2, VmError::InvalidMemoryAccess);
    assert!(vm2.halted, "SRead value error must set vm.halted = true");
    assert_eq!(vm2.error, Some(VmError::InvalidMemoryAccess));

    // SWrite of a non-canonical value in rs1.
    let prog_write = vec![
        enc(Opcode::SWrite, 0, 1, 0, 0),
        enc(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm3 = Vm::new(64);
    vm3.registers[1] = GOLDILOCKS_P;
    let err3 = vm3
        .step(&prog_write)
        .expect_err("non-canonical SWrite value refused");
    assert_eq!(err3, VmError::InvalidMemoryAccess);
    assert!(vm3.halted, "SWrite error must set vm.halted = true");
    assert_eq!(vm3.error, Some(VmError::InvalidMemoryAccess));
}

#[test]
fn negative_jmp_jnz_and_call_refuse_immediately_without_corrupt_trace_or_stack() {
    // Negative Jmp at pc=0 must fail on the first step with empty trace (no usize::MAX next_pc).
    let jmp_prog = vec![enc(Opcode::Jmp, 0, 0, 0, -5), enc(Opcode::Halt, 0, 0, 0, 0)];
    let mut vm = Vm::new(64);
    let err = vm
        .step(&jmp_prog)
        .expect_err("negative Jmp must fail immediately");
    assert_eq!(err, VmError::InvalidPc);
    assert!(vm.halted);
    assert_eq!(vm.error, Some(VmError::InvalidPc));
    assert!(
        vm.trace.is_empty(),
        "negative Jmp must not push a wrapped usize::MAX next_pc row into trace"
    );

    // Negative Jnz when branch is taken must fail immediately without corrupt trace.
    let jnz_prog = vec![enc(Opcode::Jnz, 0, 1, 0, -1), enc(Opcode::Halt, 0, 0, 0, 0)];
    let mut vm2 = Vm::new(64);
    vm2.registers[1] = 1;
    let err2 = vm2
        .step(&jnz_prog)
        .expect_err("negative taken Jnz must fail immediately");
    assert_eq!(err2, VmError::InvalidPc);
    assert!(vm2.halted);
    assert!(vm2.trace.is_empty());

    // Negative Call must fail immediately without pushing onto the return stack.
    let call_prog = vec![
        enc(Opcode::Call, 0, 0, 0, -2),
        enc(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm3 = Vm::new(64);
    let err3 = vm3
        .step(&call_prog)
        .expect_err("negative Call must fail immediately");
    assert_eq!(err3, VmError::InvalidPc);
    assert!(vm3.halted);
    assert!(
        vm3.stack.is_empty(),
        "refused negative Call must not mutate return stack"
    );
    assert!(vm3.trace.is_empty());
}

#[test]
fn verify_merkle_refuses_non_canonical_goldilocks_memory_words() {
    let program = vec![
        enc(Opcode::VerifyMerkle, 1, 0, 0, 256),
        enc(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(8192);
    // Write a non-canonical word (`GOLDILOCKS_P`) into the first leaf word (offset 256 + 8).
    vm.memory[264..272].copy_from_slice(&GOLDILOCKS_P.to_le_bytes());

    let err = vm
        .step(&program)
        .expect_err("non-canonical Merkle word must fail closed instead of diverging from AIR");
    assert_eq!(err, VmError::InvalidMemoryAccess);
    assert!(vm.halted);
    assert_eq!(vm.error, Some(VmError::InvalidMemoryAccess));
    assert!(vm.trace.is_empty());
}
