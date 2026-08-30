//! Boot-time cross-check of the canonical check programs (the prover-side
//! half of the bit-for-bit story).
//!
//! The regeneration gate (budlum `xtask/gates`) independently reproduces the
//! canonical programs and pins their Keccak-256 hashes; the ZKVM verifier
//! holds the same pin table in `canonical_set`. This module closes the third
//! corner: a bud-zero process that proves or verifies attests the agreement
//! itself, at boot, before it touches a proof. Any drift refuses the run.
//!
//! The check is deliberately duplicated logic, not shared code. The `bud-vm`
//! builder walks the schema from the register allocation up; this module
//! walks it from the pinned operand values down; the gate carries its own
//! copy. Three independent derivations that agree are the property - a
//! shared helper would be one point of failure restated three times.

use crate::canonical_set::{program_hash_of, CANONICAL_PROGRAM_HASHES};
use bud_isa::{Instruction, Opcode};
use bud_vm::private_transfer::{
    build_private_transfer_check_program, CANONICAL_AMOUNT, CANONICAL_BLINDING,
    CANONICAL_CLAIMED_NULLIFIER, CANONICAL_RECIPIENT, CANONICAL_SECRET, CANONICAL_SUM_IN,
    CANONICAL_SUM_OUT, PRIVATE_TRANSFER_PROGRAM_OPS, PRIVATE_TRANSFER_PROGRAM_VERSION,
};
use bud_vm::syscall_context::{
    build_syscall_context_check_program, SYSCALL_BLOCK_HEIGHT, SYSCALL_CONTEXT_PROGRAM_OPS,
    SYSCALL_CONTEXT_PROGRAM_VERSION, SYSCALL_NONCE, SYSCALL_SENDER,
};

/// One canonical program as the boot check saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalCheckProgram {
    /// Stable program label.
    pub name: &'static str,
    /// The schema version the builder declares; it must be the version the
    /// pin was measured under.
    pub schema_version: u32,
    /// The instruction count the stream must have.
    pub ops: usize,
    /// Hex Keccak-256 of the little-endian instruction words.
    pub hash_hex: String,
}

/// The pinned shape of one instruction slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slot {
    opcode: Opcode,
    rd: u8,
    rs1: u8,
    rs2: u8,
    imm: i32,
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compare every emitted word against its pinned slot. The words are decoded
/// here, in the checking crate, so a builder that quietly changes an operand
/// is caught as data, not as text.
///
/// # Errors
///
/// Names the position and both renderings when a slot drifts or a word does
/// not decode.
fn check_slots(label: &str, stream: &[u64], slots: &[Slot]) -> Result<(), String> {
    if stream.len() != slots.len() {
        return Err(format!(
            "{label}: the program carries {} instructions, the pinned schema has {}",
            stream.len(),
            slots.len()
        ));
    }
    for (pos, (word, want)) in stream.iter().zip(slots.iter()).enumerate() {
        let got = Instruction::decode_any(*word)
            .map_err(|e| format!("{label}: instruction {pos} does not decode: {e:?}"))?;
        if got.opcode != want.opcode
            || got.rd != want.rd
            || got.rs1 != want.rs1
            || got.rs2 != want.rs2
            || got.imm != want.imm
        {
            return Err(format!(
                "{label}: instruction {pos} drifted: emitted {:?}, the pinned schema expects {:?}",
                got, want
            ));
        }
    }
    Ok(())
}

/// Length, hash and pin agreement for one stream.
///
/// # Errors
///
/// When the emitted length is not the canonical count, or the recomputed
/// hash is not the pinned hex.
fn check_against_pin(
    label: &'static str,
    schema_version: u32,
    ops: usize,
    stream: &[u64],
    pin: &str,
) -> Result<CanonicalCheckProgram, String> {
    if stream.len() != ops {
        return Err(format!(
            "{label}: emitted {} instructions, the canonical count is {ops}",
            stream.len()
        ));
    }
    let hash = hex32(&program_hash_of(stream));
    if hash != pin {
        return Err(format!(
            "{label}: the recomputed program hash {hash} does not match the pinned {pin}"
        ));
    }
    Ok(CanonicalCheckProgram {
        name: label,
        schema_version,
        ops,
        hash_hex: hash,
    })
}

/// Attest the private-transfer canonical program against its pin.
///
/// # Errors
///
/// Propagates a builder refusal, a slot drift or a hash that is not the pin.
fn verify_private_transfer_program() -> Result<CanonicalCheckProgram, String> {
    let stream = build_private_transfer_check_program()?;
    let slots = [
        Slot {
            opcode: Opcode::Load,
            rd: 1,
            rs1: 0,
            rs2: 0,
            imm: CANONICAL_AMOUNT,
        },
        Slot {
            opcode: Opcode::Load,
            rd: 2,
            rs1: 0,
            rs2: 0,
            imm: CANONICAL_BLINDING,
        },
        Slot {
            opcode: Opcode::PrivacyCommit,
            rd: 4,
            rs1: 1,
            rs2: 2,
            imm: CANONICAL_RECIPIENT,
        },
        Slot {
            opcode: Opcode::Load,
            rd: 5,
            rs1: 0,
            rs2: 0,
            imm: CANONICAL_SUM_IN,
        },
        Slot {
            opcode: Opcode::Load,
            rd: 6,
            rs1: 0,
            rs2: 0,
            imm: CANONICAL_SUM_OUT,
        },
        Slot {
            opcode: Opcode::SumConservation,
            rd: 7,
            rs1: 5,
            rs2: 6,
            imm: 0,
        },
        Slot {
            opcode: Opcode::Load,
            rd: 8,
            rs1: 0,
            rs2: 0,
            imm: CANONICAL_CLAIMED_NULLIFIER,
        },
        Slot {
            opcode: Opcode::Load,
            rd: 9,
            rs1: 0,
            rs2: 0,
            imm: CANONICAL_SECRET,
        },
        Slot {
            opcode: Opcode::NullifierCheck,
            rd: 10,
            rs1: 8,
            rs2: 9,
            imm: 0,
        },
        Slot {
            opcode: Opcode::Log,
            rd: 0,
            rs1: 7,
            rs2: 0,
            imm: 0,
        },
        Slot {
            opcode: Opcode::Log,
            rd: 0,
            rs1: 10,
            rs2: 0,
            imm: 0,
        },
        Slot {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        },
    ];
    check_slots("private-transfer-check", &stream, &slots)?;
    check_against_pin(
        "private-transfer-check",
        PRIVATE_TRANSFER_PROGRAM_VERSION,
        PRIVATE_TRANSFER_PROGRAM_OPS,
        &stream,
        CANONICAL_PROGRAM_HASHES[2],
    )
}

/// Attest the syscall-context canonical program against its pin.
///
/// # Errors
///
/// Propagates a builder refusal, a slot drift or a hash that is not the pin.
fn verify_syscall_context_program() -> Result<CanonicalCheckProgram, String> {
    let stream = build_syscall_context_check_program()?;
    let slots = [
        Slot {
            opcode: Opcode::Syscall,
            rd: 1,
            rs1: 0,
            rs2: 0,
            imm: SYSCALL_SENDER,
        },
        Slot {
            opcode: Opcode::Syscall,
            rd: 2,
            rs1: 0,
            rs2: 0,
            imm: SYSCALL_BLOCK_HEIGHT,
        },
        Slot {
            opcode: Opcode::Syscall,
            rd: 3,
            rs1: 0,
            rs2: 0,
            imm: SYSCALL_NONCE,
        },
        Slot {
            opcode: Opcode::Log,
            rd: 0,
            rs1: 1,
            rs2: 0,
            imm: 0,
        },
        Slot {
            opcode: Opcode::Log,
            rd: 0,
            rs1: 2,
            rs2: 0,
            imm: 0,
        },
        Slot {
            opcode: Opcode::Log,
            rd: 0,
            rs1: 3,
            rs2: 0,
            imm: 0,
        },
        Slot {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        },
    ];
    check_slots("syscall-context-check", &stream, &slots)?;
    check_against_pin(
        "syscall-context-check",
        SYSCALL_CONTEXT_PROGRAM_VERSION,
        SYSCALL_CONTEXT_PROGRAM_OPS,
        &stream,
        CANONICAL_PROGRAM_HASHES[3],
    )
}

/// The boot-time attestation: both check programs, re-derived from the
/// pinned operand values and cross-checked against the pin table. A `Vec` of
/// two on success; a `String` naming the first drift on failure.
///
/// # Errors
///
/// Any slot drift, length drift or hash mismatch in either program.
pub fn check_canonical_programs() -> Result<Vec<CanonicalCheckProgram>, String> {
    if CANONICAL_PROGRAM_HASHES.len() != 4 {
        return Err(format!(
            "the pin table holds {} entries, the boot check expects 4",
            CANONICAL_PROGRAM_HASHES.len()
        ));
    }
    Ok(vec![
        verify_private_transfer_program()?,
        verify_syscall_context_program()?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_check_accepts_the_canonical_tree() {
        let got = check_canonical_programs().expect("the checked-out tree must attest");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "private-transfer-check");
        assert_eq!(got[0].ops, PRIVATE_TRANSFER_PROGRAM_OPS);
        assert_eq!(got[1].schema_version, SYSCALL_CONTEXT_PROGRAM_VERSION);
    }

    #[test]
    fn boot_check_refuses_a_slot_whose_imm_drifted() {
        let stream = build_private_transfer_check_program().expect("canonical build");
        let wrong = [Slot {
            opcode: Opcode::Load,
            rd: 1,
            rs1: 0,
            rs2: 0,
            imm: CANONICAL_AMOUNT + 1,
        }];
        let r = check_slots("x", &[stream[0]], &wrong);
        assert!(
            r.is_err(),
            "a drifted immediate must not pass the slot check"
        );
    }

    #[test]
    fn boot_check_refuses_a_hash_outside_the_pin_table() {
        let r = check_against_pin("x", 1, 1, &[0u64], "not-a-hash");
        assert!(
            r.is_err(),
            "a stream whose hash is not the pin must not pass"
        );
    }

    #[test]
    fn boot_check_refuses_a_stream_with_one_instruction_missing() {
        let stream = build_syscall_context_check_program().expect("canonical build");
        let short = &stream[..stream.len() - 1];
        let r = check_against_pin(
            "syscall-context-check",
            SYSCALL_CONTEXT_PROGRAM_VERSION,
            SYSCALL_CONTEXT_PROGRAM_OPS,
            short,
            CANONICAL_PROGRAM_HASHES[3],
        );
        assert!(r.is_err(), "a truncated stream must not attest");
    }
}
