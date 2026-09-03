// Integration test: an unwrap here is how the test reports a broken
// invariant, so the workspace-wide panic gate does not apply.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use bud_isa::{Instruction, Opcode};
use bud_proof::adapter::{ExecutionPublicInputs, ProverAdapter};
use bud_proof::DefaultAdapter as Prover;
use bud_vm::Vm;
use tiny_keccak::{Hasher, Keccak};

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

// -- The real soundness measurement (2026-08-23) --------------------------
//
// The tests here replaced a `tampered_check_fails` harness. That harness was
// measured and it **never measured a constraint**: `p3_air::check_constraints`
// panics on the very first row for this AIR for two reasons -
//
//   1. `num_public_values()` returned 56 while the harness passed an array of
//      length 48 -> "index out of bounds: the len is 48 but the index is 48".
//   2. even after that is fixed the AIR wants permutation (lookup) data ->
//      "permutation() called on a builder created without permutation data".
//
// `catch_unwind(...).is_err()` did not tell those panics apart from a
// constraint violation, so it returned `true` **even when no tampering had been
// applied at all** (measured). All five negative tests were therefore green for
// the wrong reason and provided no assurance about the AIR.
//
// `bud_stark::prover` had already reached the same conclusion: the
// `check_constraints` call there stands behind both `#[cfg(debug_assertions)]`
// and `if !has_aux_trace` - that API is not enough for this AIR.
//
// So the tests below measure through **prove + verify** rather than the AIR
// directly: a valid proof is produced, then a single thing is changed and the
// verifier is expected to refuse it. That is the attack surface the chain is
// really exposed to - the claim presented to the verifier.

/// A valid proof and everything needed to verify it.
type WorkingProof = (
    bud_proof::adapter::ProofEnvelope,
    ExecutionPublicInputs,
    Vec<u64>,
);

/// A function that tampers with a single public input field.
type Corruptor = fn(&mut ExecutionPublicInputs);

fn working_proof() -> WorkingProof {
    let bytecode = vec![
        inst(Opcode::Add, 1, 2, 3, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(65536);
    vm.registers[2] = 10;
    vm.registers[3] = 20;
    let receipt = vm.run_receipt(&bytecode);

    let mut bytecode_bytes = Vec::with_capacity(bytecode.len() * 8);
    for w in &bytecode {
        bytecode_bytes.extend_from_slice(&w.to_le_bytes());
    }
    let mut program_hash = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(&bytecode_bytes);
    k.finalize(&mut program_hash);

    let initial_state_root = bud_proof::initial_state_root_of(
        bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(&vm.trace)),
        bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
            &vm.trace,
        )),
    );

    let pi = ExecutionPublicInputs {
        chain_id: 1,
        program_hash,
        initial_state_root,
        final_state_root: [0u8; 32],
        sender: vm.context.sender,
        nonce: vm.context.nonce,
        block_height: vm.context.block_height,
        gas_limit: vm.gas_limit,
        gas_used: vm.gas_used,
        exit_code: 0,
        trace_len: vm.trace.len() as u64,
        event_digest: bud_proof::event_digest_from_events(&receipt.events),
        state_writes_digest: [0u8; 32],
    };

    let envelope =
        Prover::prove(&vm.trace, &pi, &bytecode).expect("the proof could not be produced");
    (envelope, pi, bytecode)
}

/// A control group: an untampered proof must be **accepted**.
///
/// Without this test the refusal tests below mean nothing - the old harness left
/// five tests green for the wrong reason precisely because this control was missing.
#[test]
fn an_untampered_proof_is_accepted() {
    let (envelope, pi, bytecode) = working_proof();
    Prover::verify(&envelope, &pi, &bytecode).expect("a clean proof was refused");
}

/// A proof must be valid only for the program it was produced for.
///
/// Being able to present the same proof as the output of a different program
/// would make the claim "I ran this program" entirely worthless.
#[test]
fn a_proof_presented_for_another_program_is_refused() {
    let (envelope, pi, _) = working_proof();
    let other = vec![
        inst(Opcode::Sub, 1, 2, 3, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    assert!(
        Prover::verify(&envelope, &pi, &other).is_err(),
        "the proof was accepted for another program; there is no program binding"
    );
}

/// If the public input fields are tampered with one by one the proof must be invalid.
///
/// Each field is asserted **separately**: a single bulk `assert` would hide one field
/// being unbound under the success of the others. This is exactly the class of the
/// SP1 `committed_value_digest` under-constraint and the Aleo/snarkVM missing
/// absorb finding - the verifier has to check, in its own code, the areas the
/// proof system does not constrain.
#[test]
fn a_tampered_public_input_is_refused() {
    let (envelope, clean, bytecode) = working_proof();

    let corruptions: Vec<(&str, Corruptor)> = vec![
        ("chain_id", |p| p.chain_id ^= 1),
        ("program_hash", |p| p.program_hash[0] ^= 1),
        ("initial_state_root", |p| p.initial_state_root[0] ^= 1),
        ("final_state_root", |p| p.final_state_root[0] ^= 1),
        ("sender", |p| p.sender ^= 1),
        ("nonce", |p| p.nonce ^= 1),
        ("block_height", |p| p.block_height ^= 1),
        ("gas_used", |p| p.gas_used ^= 1),
        ("exit_code", |p| p.exit_code ^= 1),
        ("trace_len", |p| p.trace_len ^= 1),
        ("event_digest", |p| p.event_digest[0] ^= 1),
        ("state_writes_digest", |p| p.state_writes_digest[0] ^= 1),
    ];

    for (name, corrupt) in corruptions {
        let mut pi = clean.clone();
        corrupt(&mut pi);
        assert!(
            Prover::verify(&envelope, &pi, &bytecode).is_err(),
            "`{name}` was tampered with but the proof was still counted valid; this field is not bound to the proof"
        );
    }
}

/// A storage-writing program whose public input claims a **wrong** write
/// digest must be refused, even when the wrong value is baked in before
/// proving.
///
/// The tamper test above changes a public input *after* proving, so the
/// refusal it measures comes from Fiat-Shamir: the verifier absorbs the
/// public values and any change breaks the transcript. That test passes even
/// for a field the AIR never constrains. Constraint (2b) is the only thing
/// that refuses a digest chosen before proving, and it was measured
/// (2026-09-03) to be a copy of the `final_state_root` binding, so a
/// storage program with an all-zero digest proved and verified. This test
/// bakes the wrong value in before proving and expects the AIR to refuse it.
#[test]
fn a_wrong_state_writes_digest_baked_in_before_proving_is_refused() {
    let bytecode = vec![
        inst(Opcode::Load, 1, 0, 0, 99),
        inst(Opcode::SWrite, 0, 1, 0, 5),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(1024);
    let receipt = vm.run_receipt(&bytecode);
    assert!(receipt.success, "the honest storage program must run");
    assert_ne!(
        receipt.state_writes_digest, [0u8; 32],
        "a program that writes storage must produce a non-zero digest, or this \
         test proves nothing"
    );

    let mut bytecode_bytes = Vec::with_capacity(bytecode.len() * 8);
    for w in &bytecode {
        bytecode_bytes.extend_from_slice(&w.to_le_bytes());
    }
    let mut program_hash = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(&bytecode_bytes);
    k.finalize(&mut program_hash);

    let initial_state_root = bud_proof::initial_state_root_of(
        bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(&vm.trace)),
        bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
            &vm.trace,
        )),
    );

    let honest = ExecutionPublicInputs {
        chain_id: 1,
        program_hash,
        initial_state_root,
        final_state_root: [0u8; 32],
        sender: vm.context.sender,
        nonce: vm.context.nonce,
        block_height: vm.context.block_height,
        gas_limit: vm.gas_limit,
        gas_used: vm.gas_used,
        exit_code: 0,
        trace_len: vm.trace.len() as u64,
        event_digest: bud_proof::event_digest_from_events(&receipt.events),
        state_writes_digest: receipt.state_writes_digest,
    };

    // Control group: the honest digest proves and verifies.
    let envelope = Prover::prove(&vm.trace, &honest, &bytecode)
        .expect("the honest proof could not be produced");
    Prover::verify(&envelope, &honest, &bytecode).expect("the honest storage proof was refused");

    // A digest that says "no writes happened", chosen before proving.
    let mut denies_writes = honest.clone();
    denies_writes.state_writes_digest = [0u8; 32];
    let refused = match Prover::prove(&vm.trace, &denies_writes, &bytecode) {
        Err(_) => true,
        Ok(envelope) => Prover::verify(&envelope, &denies_writes, &bytecode).is_err(),
    };
    assert!(
        refused,
        "a storage-writing program proved and verified with an all-zero write digest; \
         the AIR does not bind `state_writes_digest`"
    );

    // A digest that is one bit away from the truth, chosen before proving.
    let mut one_bit_off = honest.clone();
    one_bit_off.state_writes_digest[0] ^= 1;
    let refused = match Prover::prove(&vm.trace, &one_bit_off, &bytecode) {
        Err(_) => true,
        Ok(envelope) => Prover::verify(&envelope, &one_bit_off, &bytecode).is_err(),
    };
    assert!(
        refused,
        "a storage-writing program proved and verified with a wrong write digest baked \
         in before proving; the AIR does not bind `state_writes_digest`"
    );
}
