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
/// being unbound under the success of the others. This enforces complete coverage for
/// public inputs and prevents missing absorb bugs in the verifier.
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
        ("gas_limit", |p| p.gas_limit ^= 1),
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
        // The AIR ties the final root to the storage-writes fold, so the
        // honest final root for a writing program is its write digest.
        final_state_root: receipt.state_writes_digest,
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

// ---------------------------------------------------------------------------
// Four-category soundness & under-constraint test taxonomy:
//   Category 1: VM-step trace mutation -> real prover -> verifier REFUSED
//   Category 2: Direct AIR-witness & independent LogUp / arithmetic mutations
//               (Register LogUp, Memory+Storage LogUp, Program LogUp, Div/Inv/r0/padding)
//               -> prove_matrix_envelope -> verifier REFUSED
//   Category 3: Public-input, program & private-witness binding (above + E2E witness)
//   Category 4: Serialized proof corruption & hiding-class strict ZK policy
// ---------------------------------------------------------------------------

fn build_pi_for_vm(
    vm: &Vm,
    bytecode: &[u64],
    events: &[u64],
    writes_digest: [u8; 32],
) -> ExecutionPublicInputs {
    let mut bytecode_bytes = Vec::with_capacity(bytecode.len() * 8);
    for w in bytecode {
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

    ExecutionPublicInputs {
        chain_id: 1,
        program_hash,
        initial_state_root,
        final_state_root: writes_digest,
        sender: vm.context.sender,
        nonce: vm.context.nonce,
        block_height: vm.context.block_height,
        gas_limit: vm.gas_limit,
        gas_used: vm.gas_used,
        exit_code: 0,
        trace_len: vm.trace.len() as u64,
        event_digest: bud_proof::event_digest_from_events(events),
        state_writes_digest: writes_digest,
    }
}

/// Category 1: VM-step execution trace mutation passed through the real prover
/// must be rejected by the verifier.
#[test]
fn category1_vm_step_mutation_through_real_prover_is_refused() {
    let bytecode = vec![
        inst(Opcode::Load, 1, 0, 0, 12),
        inst(Opcode::Load, 2, 0, 0, 30),
        inst(Opcode::Add, 3, 1, 2, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(8192);
    let receipt = vm.run_receipt(&bytecode);
    assert!(receipt.success);
    let pi = build_pi_for_vm(&vm, &bytecode, &receipt.events, receipt.state_writes_digest);

    // Control: untampered trace verifies.
    let honest = Prover::prove(&vm.trace, &pi, &bytecode).expect("honest prove");
    Prover::verify(&honest, &pi, &bytecode).expect("honest verify");

    // Mutate the Add step's destination register output before trace matrix construction.
    let mut forged_trace = vm.trace.clone();
    forged_trace[2].dst_val = 999;
    forged_trace[2].registers[3] = 999;

    let refused = match Prover::prove(&forged_trace, &pi, &bytecode) {
        Err(_) => true,
        Ok(env) => Prover::verify(&env, &pi, &bytecode).is_err(),
    };
    assert!(refused, "mutated VM step output must not prove and verify");
}

/// Category 2a: Direct AIR-witness Register LogUp mutation (bypassing `Vm::step`)
/// passed straight through `prove_matrix_envelope` -> verifier REFUSED.
#[test]
fn category2a_direct_air_register_logup_mutation_is_refused() {
    use bud_proof::plonky3_air::{COL_RD_IDX_INV, COL_REG_ACTIVE, COL_REG_VAL, TRACE_WIDTH};
    use bud_proof::plonky3_prover::{prove_matrix_envelope, trace_matrix};
    use p3_field::PrimeField64;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;

    let bytecode = vec![
        inst(Opcode::Load, 1, 0, 0, 10),
        inst(Opcode::Add, 2, 1, 1, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(8192);
    let receipt = vm.run_receipt(&bytecode);
    assert!(receipt.success);
    let pi = build_pi_for_vm(&vm, &bytecode, &receipt.events, receipt.state_writes_digest);

    let (mut mat, trace_len) = trace_matrix(&vm.trace, &bytecode, &pi).expect("trace matrix");
    let rows = mat.values.len() / TRACE_WIDTH;
    // Flip a register table row value directly in the AIR witness without altering CPU steps.
    let mut mutated_reg = false;
    for r in 0..rows {
        let base = r * TRACE_WIDTH;
        if mat.values[base + COL_REG_ACTIVE].as_canonical_u64() == 1
            && mat.values[base + COL_REG_VAL].as_canonical_u64() == 20
        {
            mat.values[base + COL_REG_VAL] = Goldilocks::new(777);
            mutated_reg = true;
            break;
        }
    }
    assert!(mutated_reg, "expected active register row with value 20");
    let forged = prove_matrix_envelope(
        RowMajorMatrix::new(mat.values, TRACE_WIDTH),
        trace_len,
        &pi,
        &bytecode,
    )
    .expect("prove mutated matrix");
    assert!(
        Prover::verify(&forged, &pi, &bytecode).is_err(),
        "direct Register LogUp witness tampering must fail verification"
    );

    // Also test tampering `COL_RD_IDX_INV` on a real write step.
    let (mut mat2, trace_len2) = trace_matrix(&vm.trace, &bytecode, &pi).expect("trace matrix 2");
    mat2.values[TRACE_WIDTH + COL_RD_IDX_INV] = Goldilocks::new(0);
    let forged2 = prove_matrix_envelope(
        RowMajorMatrix::new(mat2.values, TRACE_WIDTH),
        trace_len2,
        &pi,
        &bytecode,
    )
    .expect("prove mutated matrix 2");
    assert!(
        Prover::verify(&forged2, &pi, &bytecode).is_err(),
        "forged COL_RD_IDX_INV on non-r0 write must fail verification"
    );
}

/// Category 2b: Direct AIR-witness Memory + Storage LogUp mutation passed through
/// `prove_matrix_envelope` -> verifier REFUSED.
#[test]
fn category2b_direct_air_memory_storage_logup_mutation_is_refused() {
    use bud_proof::plonky3_air::{COL_MEM_ACTIVE, COL_MEM_SAME, COL_MEM_VAL, TRACE_WIDTH};
    use bud_proof::plonky3_prover::{prove_matrix_envelope, trace_matrix};
    use p3_field::PrimeField64;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;

    let bytecode = vec![
        inst(Opcode::Load, 1, 0, 0, 42),
        inst(Opcode::Store, 0, 0, 1, 64),
        inst(Opcode::SWrite, 0, 1, 0, 3),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(8192);
    let receipt = vm.run_receipt(&bytecode);
    assert!(receipt.success);
    let pi = build_pi_for_vm(&vm, &bytecode, &receipt.events, receipt.state_writes_digest);

    // Control: honest memory/storage proof verifies.
    let honest = Prover::prove(&vm.trace, &pi, &bytecode).expect("honest store/swrite prove");
    Prover::verify(&honest, &pi, &bytecode).expect("honest store/swrite verify");

    let (mut mat, trace_len) = trace_matrix(&vm.trace, &bytecode, &pi).expect("trace matrix");
    let rows = mat.values.len() / TRACE_WIDTH;
    let mut mutated_mem = false;
    for r in 0..rows {
        let base = r * TRACE_WIDTH;
        if mat.values[base + COL_MEM_ACTIVE].as_canonical_u64() == 1
            && mat.values[base + COL_MEM_VAL].as_canonical_u64() == 42
        {
            mat.values[base + COL_MEM_VAL] = Goldilocks::new(1337);
            mat.values[base + COL_MEM_SAME] = Goldilocks::new(0);
            mutated_mem = true;
            break;
        }
    }
    assert!(
        mutated_mem,
        "expected active memory/storage row with value 42"
    );
    let forged = prove_matrix_envelope(
        RowMajorMatrix::new(mat.values, TRACE_WIDTH),
        trace_len,
        &pi,
        &bytecode,
    )
    .expect("prove mutated memory matrix");
    assert!(
        Prover::verify(&forged, &pi, &bytecode).is_err(),
        "direct Memory+Storage LogUp witness tampering must fail verification"
    );
}

/// Category 2c: Direct AIR-witness Program LogUp multiplicity mutation passed through
/// `prove_matrix_envelope` -> verifier REFUSED.
#[test]
fn category2c_direct_air_program_logup_mutation_is_refused() {
    use bud_proof::plonky3_air::{COL_PROG_MULT, TRACE_WIDTH};
    use bud_proof::plonky3_prover::{prove_matrix_envelope, trace_matrix};
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;

    let bytecode = vec![
        inst(Opcode::Load, 1, 0, 0, 5),
        inst(Opcode::Load, 2, 0, 0, 7),
        inst(Opcode::Add, 3, 1, 2, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(8192);
    let receipt = vm.run_receipt(&bytecode);
    assert!(receipt.success);
    let pi = build_pi_for_vm(&vm, &bytecode, &receipt.events, receipt.state_writes_digest);

    let (mut mat, trace_len) = trace_matrix(&vm.trace, &bytecode, &pi).expect("trace matrix");
    // Corrupt Program LogUp multiplicity at row 0 (forges instruction execution count).
    mat.values[COL_PROG_MULT] = Goldilocks::new(2);
    let forged = prove_matrix_envelope(
        RowMajorMatrix::new(mat.values, TRACE_WIDTH),
        trace_len,
        &pi,
        &bytecode,
    )
    .expect("prove mutated program mult");
    assert!(
        Prover::verify(&forged, &pi, &bytecode).is_err(),
        "direct Program LogUp COL_PROG_MULT tampering must fail verification"
    );
}

/// Category 2d: Direct AIR arithmetic edge-cases (`Div` by zero, `Inv(0)`, and
/// inactive padding row opcode injection) -> `prove_matrix_envelope` -> verifier REFUSED.
#[test]
fn category2d_direct_air_div_inv_zero_and_padding_mutation_is_refused() {
    use bud_proof::plonky3_air::{COL_CPU_ACTIVE, COL_IS_ADD, COL_RD_VAL_NEW, TRACE_WIDTH};
    use bud_proof::plonky3_prover::{prove_matrix_envelope, trace_matrix};
    use p3_field::PrimeField64;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;

    // 1. Div(10, 0) yields 0 in canonical execution; forging rd_val_new = 99 must fail.
    let div_zero = vec![
        inst(Opcode::Load, 1, 0, 0, 10),
        inst(Opcode::Load, 2, 0, 0, 0),
        inst(Opcode::Div, 3, 1, 2, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm_div = Vm::new(8192);
    let r_div = vm_div.run_receipt(&div_zero);
    assert!(r_div.success);
    let pi_div = build_pi_for_vm(&vm_div, &div_zero, &r_div.events, r_div.state_writes_digest);
    let (mut mat_div, len_div) =
        trace_matrix(&vm_div.trace, &div_zero, &pi_div).expect("div trace matrix");
    mat_div.values[2 * TRACE_WIDTH + COL_RD_VAL_NEW] = Goldilocks::new(99);
    let forged_div = prove_matrix_envelope(
        RowMajorMatrix::new(mat_div.values, TRACE_WIDTH),
        len_div,
        &pi_div,
        &div_zero,
    )
    .expect("prove forged div");
    assert!(
        Prover::verify(&forged_div, &pi_div, &div_zero).is_err(),
        "forged non-zero output on Div(_, 0) must fail verification"
    );

    // 2. Inv(0) yields 0; forging rd_val_new = 55 must fail.
    let inv_zero = vec![
        inst(Opcode::Load, 1, 0, 0, 0),
        inst(Opcode::Inv, 2, 1, 0, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm_inv = Vm::new(8192);
    let r_inv = vm_inv.run_receipt(&inv_zero);
    assert!(r_inv.success);
    let pi_inv = build_pi_for_vm(&vm_inv, &inv_zero, &r_inv.events, r_inv.state_writes_digest);
    let (mut mat_inv, len_inv) =
        trace_matrix(&vm_inv.trace, &inv_zero, &pi_inv).expect("inv trace matrix");
    mat_inv.values[TRACE_WIDTH + COL_RD_VAL_NEW] = Goldilocks::new(55);
    let forged_inv = prove_matrix_envelope(
        RowMajorMatrix::new(mat_inv.values, TRACE_WIDTH),
        len_inv,
        &pi_inv,
        &inv_zero,
    )
    .expect("prove forged inv");
    assert!(
        Prover::verify(&forged_inv, &pi_inv, &inv_zero).is_err(),
        "forged non-zero output on Inv(0) must fail verification"
    );

    // 3. Injecting an active opcode selector onto an inactive padding row must fail.
    let (mut mat_pad, len_pad) =
        trace_matrix(&vm_inv.trace, &inv_zero, &pi_inv).expect("pad trace matrix");
    let rows = mat_pad.values.len() / TRACE_WIDTH;
    let pad_row = (0..rows)
        .find(|&r| mat_pad.values[r * TRACE_WIDTH + COL_CPU_ACTIVE].as_canonical_u64() == 0)
        .expect("trace must contain at least one inactive padding row");
    mat_pad.values[pad_row * TRACE_WIDTH + COL_IS_ADD] = Goldilocks::new(1);
    let forged_pad = prove_matrix_envelope(
        RowMajorMatrix::new(mat_pad.values, TRACE_WIDTH),
        len_pad,
        &pi_inv,
        &inv_zero,
    )
    .expect("prove forged padding row");
    assert!(
        Prover::verify(&forged_pad, &pi_inv, &inv_zero).is_err(),
        "injecting opcode selector onto inactive padding row must fail verification"
    );
}

/// Category 3 extension: Compiled `BudL` contract using `witness { secret: u64 }`
/// binds host private inputs into `initial_state_root` through the Memory LogUp.
#[test]
fn category3_compiled_budl_private_witness_binds_initial_state_root() {
    let source = r#"
        contract SecretCheck {
            witness {
                secret: u64,
            }
            storage {
                verified: u64,
            }
            pub fn main() {
                let doubled = witness::secret * 2;
                constrain(doubled == 84);
                storage::verified = 1;
            }
        }
    "#;
    let bytecode =
        bud_compiler::compile(source, bud_isa::IsaProfile::Production).expect("compile witness");
    let mut vm = Vm::new(bud_compiler::MIN_VM_MEMORY_BYTES);
    vm.set_witness_words(&[42]).expect("stage witness");
    let receipt = vm.run_receipt(&bytecode);
    assert!(receipt.success, "valid witness 42 must succeed");

    let pi = build_pi_for_vm(&vm, &bytecode, &receipt.events, receipt.state_writes_digest);
    let envelope = Prover::prove(&vm.trace, &pi, &bytecode).expect("prove witness contract");
    Prover::verify(&envelope, &pi, &bytecode).expect("verify witness contract");

    // Presenting the same proof against a public input whose initial_state_root
    // corresponds to a different witness word must be refused.
    let mut vm_other = Vm::new(bud_compiler::MIN_VM_MEMORY_BYTES);
    vm_other.set_witness_words(&[42]).expect("stage witness");
    let mut wrong_pi = pi;
    wrong_pi.initial_state_root[0] ^= 1;
    assert!(Prover::verify(&envelope, &wrong_pi, &bytecode).is_err());

    // And an invalid witness fails VM assertion before any valid execution succeeds.
    let mut vm_bad = Vm::new(bud_compiler::MIN_VM_MEMORY_BYTES);
    vm_bad
        .set_witness_words(&[41])
        .expect("stage wrong witness");
    let bad_receipt = vm_bad.run_receipt(&bytecode);
    assert!(!bad_receipt.success, "wrong witness 41 must fail constrain");
}

/// Category 4: Serialized proof corruption (truncation, trailing garbage, stripped
/// auxiliary commitment, degree mismatch) must be refused cleanly.
#[test]
fn category4_serialized_proof_corruption_is_refused() {
    let (envelope, pi, bytecode) = working_proof();

    let mut truncated = envelope.clone();
    truncated
        .proof_bytes
        .truncate(truncated.proof_bytes.len() / 2);
    assert!(Prover::verify(&truncated, &pi, &bytecode).is_err());

    let mut trailing = envelope.clone();
    trailing.proof_bytes.push(0xAA);
    assert!(Prover::verify(&trailing, &pi, &bytecode).is_err());

    let mut wrong_degree = envelope.clone();
    wrong_degree.degree_bits += 1;
    assert!(Prover::verify(&wrong_degree, &pi, &bytecode).is_err());

    let mut decoded: bud_proof::bud_stark::Proof<bud_proof::plonky3_prover::ChipStarkConfig> =
        postcard::from_bytes(&envelope.proof_bytes).expect("decode postcard proof");
    decoded.commitments.aux_trace = None;
    let mut stripped = envelope;
    stripped.proof_bytes = postcard::to_allocvec(&decoded).expect("encode stripped proof");
    assert!(
        Prover::verify(&stripped, &pi, &bytecode).is_err(),
        "stripping aux_trace LogUp commitment must be refused"
    );
}
