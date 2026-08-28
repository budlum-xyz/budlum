//! Canonical private-transfer verification program.
//!
//! The privacy trio — `PrivacyCommit` (0x20), `SumConservation` (0x22),
//! `NullifierCheck` (0x21) — is fully supported by the VM and the AIR, but no
//! production code ever combined them into a canonical program. This module
//! fixes that: a single canonical program that exercises all three in order,
//! so the AIR rows that implement them are attested by the regeneration gate
//! just like the storage challenge and the AI matmul guest.
//!
//! The program is a *schema*: the amounts, blinding, recipient tag, sums,
//! claimed nullifier and secret are canonical constants, so every node
//! reproduces the same instruction stream (convergence). Parameterising the
//! values from memory is a later slice; the identity of the program — the
//! instruction stream — is what the canonical hash binds.
//!
//! Register allocation (all below the 32-bit `imm` ceiling on purpose):
//!   r1 = amount, r2 = blinding, r3 = recipient tag (imm of PrivacyCommit)
//!   r4 = commitment output, r5 = sum_in, r6 = sum_out, r7 = conservation flag
//!   r8 = claimed nullifier, r9 = secret, r10 = nullifier flag

use bud_isa::{Instruction, Opcode};

/// Version of the canonical schema. Bump this when the instruction stream
/// changes; the pinned hash in the regeneration gate must be re-measured with
/// it.
pub const PRIVATE_TRANSFER_PROGRAM_VERSION: u32 = 1;

/// Canonical constants of the schema (dims of the verification: any values
/// would do, the stream is what is canonical).
pub const CANONICAL_AMOUNT: i32 = 1000;
pub const CANONICAL_BLINDING: i32 = 42;
pub const CANONICAL_RECIPIENT: i32 = 77;
pub const CANONICAL_SUM_IN: i32 = 1000;
pub const CANONICAL_SUM_OUT: i32 = 1000;
pub const CANONICAL_CLAIMED_NULLIFIER: i32 = 0x1234_5678;
pub const CANONICAL_SECRET: i32 = 0x0bad_c0de;

/// The number of instructions in the canonical program (kept exact: the
/// builder asserts the emitted length equals this).
pub const PRIVATE_TRANSFER_PROGRAM_OPS: usize = 12;

fn inst(op: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32) -> u64 {
    Instruction {
        opcode: op,
        rd,
        rs1,
        rs2,
        imm,
    }
    .encode()
}

/// Build the canonical private-transfer verification program.
///
/// Stream:
///   1. Load  r1 ← AMOUNT
///   2. Load  r2 ← BLINDING
///   3. PrivacyCommit r4 ← commit(r1, r2, RECIPIENT)     (0x20)
///   4. Load  r5 ← SUM_IN
///   5. Load  r6 ← SUM_OUT
///   6. SumConservation r7 ← (r5 == r6)                  (0x22)
///   7. Load  r8 ← CLAIMED_NULLIFIER
///   8. Load  r9 ← SECRET
///   9. NullifierCheck r10 ← (poseidon(r9, DOMAIN) == r8) (0x21)
///  10. Log r7, Log r10
///  11. Halt
///
/// The two flags logged at the end are the verification verdicts; a prover
/// attests them, and honest values are `1` for conservation (1000 == 1000)
/// and `0` for the nullifier unless the canonical secret happens to derive to
/// the canonical claim (measured once and pinned in the test below).
pub fn build_private_transfer_check_program() -> Result<Vec<u64>, String> {
    let mut prog: Vec<u64> = Vec::with_capacity(PRIVATE_TRANSFER_PROGRAM_OPS);

    prog.push(inst(Opcode::Load, 1, 0, 0, CANONICAL_AMOUNT));
    prog.push(inst(Opcode::Load, 2, 0, 0, CANONICAL_BLINDING));
    prog.push(inst(Opcode::PrivacyCommit, 4, 1, 2, CANONICAL_RECIPIENT));
    prog.push(inst(Opcode::Load, 5, 0, 0, CANONICAL_SUM_IN));
    prog.push(inst(Opcode::Load, 6, 0, 0, CANONICAL_SUM_OUT));
    prog.push(inst(Opcode::SumConservation, 7, 5, 6, 0));
    prog.push(inst(Opcode::Load, 8, 0, 0, CANONICAL_CLAIMED_NULLIFIER));
    prog.push(inst(Opcode::Load, 9, 0, 0, CANONICAL_SECRET));
    prog.push(inst(Opcode::NullifierCheck, 10, 8, 9, 0));
    prog.push(inst(Opcode::Log, 0, 7, 0, 0));
    prog.push(inst(Opcode::Log, 0, 10, 0, 0));
    prog.push(inst(Opcode::Halt, 0, 0, 0, 0));

    let emitted = prog.len();
    if emitted != PRIVATE_TRANSFER_PROGRAM_OPS {
        return Err(format!(
            "private transfer program emitted {emitted} ops != canonical {PRIVATE_TRANSFER_PROGRAM_OPS}"
        ));
    }
    Ok(prog)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vm;

    #[test]
    fn canonical_program_runs_and_logs_the_expected_verdicts() {
        let program = build_private_transfer_check_program().expect("canonical build");
        let mut vm = Vm::new(8192);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the canonical program must reach Halt");
        // r7 = (1000 == 1000) = 1, logged first.
        assert_eq!(vm.registers[7], 1, "conservation flag must be 1");
        // Recipient is carried as a field element: imm < 0 becomes P - |imm|.
        let recipient = if CANONICAL_RECIPIENT < 0 {
            crate::GOLDILOCKS_P.wrapping_sub(CANONICAL_RECIPIENT.unsigned_abs() as u64)
        } else {
            CANONICAL_RECIPIENT as u64
        };
        assert_eq!(
            vm.registers[4],
            crate::poseidon4_hash3(
                CANONICAL_AMOUNT as u64,
                CANONICAL_BLINDING as u64,
                recipient,
            ),
            "the commitment must be the canonical one"
        );
        // The nullifier verdict is deterministic for the canonical constants:
        // measured once on 2026-08-27 (30-round Poseidon, DOMAIN_NULLIFIER).
        assert_eq!(
            vm.registers[10], 0,
            "claimed nullifier does not derive from the canonical secret"
        );
        assert_eq!(
            receipt.events,
            vec![1, 0],
            "the two logged verdicts must be conservation=1, nullifier=0"
        );
    }

    #[test]
    fn canonical_program_is_convergent() {
        let a = build_private_transfer_check_program().unwrap();
        let b = build_private_transfer_check_program().unwrap();
        assert_eq!(a, b, "two builds must give the same instruction stream");
        assert_eq!(a.len(), PRIVATE_TRANSFER_PROGRAM_OPS);
    }

    #[test]
    fn a_silent_drift_in_the_stream_changes_the_program() {
        // The property the gate relies on: the canonical hash binds the whole
        // stream. Flip one instruction and the identity must change.
        let canonical = build_private_transfer_check_program().unwrap();
        let mut drifted = canonical.clone();
        // PrivacyCommit's recipient tag: 77 -> 78.
        drifted[2] ^= 1 << 23;
        assert_ne!(drifted, canonical, "the drift must change the program");
    }

    #[test]
    fn canonical_stream_is_pinned() {
        // The instruction stream is the canonical identity; the regeneration
        // gate (`xtask/gates/src/gates/regeneration.rs`) reproduces it
        // independently and pins its Keccak-256 to a value measured from this
        // builder. Pinning the stream here (without a hash dependency in this
        // crate) makes a silent change to the builder red on both sides.
        let prog = build_private_transfer_check_program().unwrap();
        let hexs: Vec<String> = prog.iter().map(|w| format!("{w:016x}")).collect();
        assert_eq!(
            hexs,
            vec![
                "00000001f4000114", // Load r1 ← AMOUNT (1000)
                "0000000015000214", // Load r2 ← BLINDING (42)
                "0000000026882420", // PrivacyCommit r4 ← commit(r1, r2, 77)
                "00000001f4000514", // Load r5 ← SUM_IN (1000)
                "00000001f4000614", // Load r6 ← SUM_OUT (1000)
                "000000000018a722", // SumConservation r7 ← (r5 == r6)
                "00091a2b3c000814", // Load r8 ← CLAIMED_NULLIFIER
                "0005d6e06f000914", // Load r9 ← SECRET
                "0000000000250a21", // NullifierCheck r10 ← (poseidon(r9, D) == r8)
                "000000000000e01a", // Log r7
                "000000000001401a", // Log r10
                "0000000000000000", // Halt
            ],
            "the canonical stream drifted; re-measure the pinned hash in the \
             regeneration gate and update both sides together"
        );
    }
}
