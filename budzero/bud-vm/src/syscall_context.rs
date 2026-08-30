//! Canonical syscall-context verification program.
//!
//! The fourth canonical program: it exercises every context syscall
//! (`Syscall` with `imm` 1 = sender, 2 = block height, 3 = nonce) in one
//! stream and logs the three values, so the AIR rows that bind syscall
//! results to the transaction context are attested by the regeneration gate
//! like the storage challenge, the matmul guest and the private-transfer
//! check.
//!
//! The instruction stream is canonical (the immediates and registers are
//! fixed); the *values* come from the `Context` the VM is run with, which is
//! exactly the point - the same program, run over a different context, proves
//! a different context in the trace.

use bud_isa::{Instruction, Opcode};

/// Version of the canonical schema. Bump when the instruction stream changes;
/// the pinned hash in the regeneration gate must be re-measured with it.
pub const SYSCALL_CONTEXT_PROGRAM_VERSION: u32 = 1;

/// The number of instructions in the canonical program (kept exact: the
/// builder asserts the emitted length equals this).
pub const SYSCALL_CONTEXT_PROGRAM_OPS: usize = 7;

/// The syscall numbers the stream exercises, in order (sender, height, nonce).
pub const SYSCALL_SENDER: i32 = 1;
pub const SYSCALL_BLOCK_HEIGHT: i32 = 2;
pub const SYSCALL_NONCE: i32 = 3;

fn inst(opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32) -> u64 {
    Instruction {
        opcode,
        rd,
        rs1,
        rs2,
        imm,
    }
    .encode()
}

/// Build the canonical syscall-context verification program.
///
/// Stream: read sender, block height and nonce into r1..r3, log all three,
/// halt. Register allocation is part of the schema.
pub fn build_syscall_context_check_program() -> Result<Vec<u64>, String> {
    let mut prog: Vec<u64> = Vec::with_capacity(SYSCALL_CONTEXT_PROGRAM_OPS);
    prog.push(inst(Opcode::Syscall, 1, 0, 0, SYSCALL_SENDER));
    prog.push(inst(Opcode::Syscall, 2, 0, 0, SYSCALL_BLOCK_HEIGHT));
    prog.push(inst(Opcode::Syscall, 3, 0, 0, SYSCALL_NONCE));
    prog.push(inst(Opcode::Log, 0, 1, 0, 0));
    prog.push(inst(Opcode::Log, 0, 2, 0, 0));
    prog.push(inst(Opcode::Log, 0, 3, 0, 0));
    prog.push(inst(Opcode::Halt, 0, 0, 0, 0));

    let emitted = prog.len();
    if emitted != SYSCALL_CONTEXT_PROGRAM_OPS {
        return Err(format!(
            "syscall context program emitted {emitted} ops != canonical {SYSCALL_CONTEXT_PROGRAM_OPS}"
        ));
    }
    Ok(prog)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vm;

    #[test]
    fn canonical_program_logs_the_context_values() {
        let program = build_syscall_context_check_program().expect("canonical build");
        let mut vm = Vm::new(64);
        vm.context.sender = 0xDEAD_BEEF_CAFE_F00D;
        vm.context.block_height = 12_345;
        vm.context.nonce = 7;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the canonical program must reach Halt");
        assert_eq!(vm.registers[1], vm.context.sender);
        assert_eq!(vm.registers[2], vm.context.block_height);
        assert_eq!(vm.registers[3], vm.context.nonce);
        assert_eq!(
            receipt.events,
            vec![vm.context.sender, vm.context.block_height, vm.context.nonce],
            "the three logged values must be sender, height, nonce in order"
        );
    }

    #[test]
    fn canonical_program_is_convergent() {
        let a = build_syscall_context_check_program().unwrap();
        let b = build_syscall_context_check_program().unwrap();
        assert_eq!(a, b, "two builds must give the same instruction stream");
        assert_eq!(a.len(), SYSCALL_CONTEXT_PROGRAM_OPS);
    }

    #[test]
    fn canonical_stream_is_pinned() {
        // The instruction stream is the canonical identity; the regeneration
        // gate reproduces it independently and pins its Keccak-256 to a value
        // measured from this builder.
        let prog = build_syscall_context_check_program().unwrap();
        let hexs: Vec<String> = prog.iter().map(|w| format!("{w:016x}")).collect();
        assert_eq!(
            hexs,
            vec![
                "000000000080011d", // Syscall r1 ← sender (imm 1)
                "000000000100021d", // Syscall r2 ← block height (imm 2)
                "000000000180031d", // Syscall r3 ← nonce (imm 3)
                "000000000000201a", // Log r1 (rs1 = 1)
                "000000000000401a", // Log r2 (rs1 = 2)
                "000000000000601a", // Log r3 (rs1 = 3)
                "0000000000000000", // Halt
            ],
            "the canonical stream drifted; re-measure the pinned hash in the \
             regeneration gate and update both sides together"
        );
    }
}
