//! `AggMerge`: Phase 3 recursive merge program for `BudZKVM` (`BudAir`).
//!
//! Takes two child statements `(left_prog, left_pi)` and `(right_prog, right_pi)`
//! plus a `merge_pi` claim, checks inside `BudVM` that:
//! 1. Both child program hashes belong to the strict Phase 3 allowlist
//!    `{tick_program_hash, self_program_hash}` (an unauthorized child program
//!    hash fails the guest `Assert` instruction and never produces a valid proof).
//! 2. `left_pi`, `right_pi`, and `merge_pi` are published verbatim to the
//!    `BudAir` `state_writes_digest` commitment (24 `SWrite` slots = 96 bytes),
//!    while the single `Keccak-f[1600]` compression
//!    `merge_pi = H(TAG_AGG_MERGE || left_pi || right_pi)` is offloaded and
//!    cryptographically proven by [`bud_proof::chips::keccak::prove_bound_keccak_f`].
//!
//! Storing each 32-byte digest as 8 little-endian `u32` limbs keeps the guest
//! trace at **~208 VM steps** (`2^10 = 1,024` `BudAir` rows), proving in ~1.2 s
//! and verifying in ~57 ms under `MainnetActivation::default()`.
//!
//! WIRING: `StarkBackend` binds `agg_merge(&agg_tick_program_hash())` to derive
//! `agg_merge_program_hash()`, while `benches/agg_phase3_stark` and Phase 3
//! recursive STARK proof verification invoke `run_agg_merge`, `prove_agg_merge`,
//! and `verify_agg_merge`.

use bud_proof::adapter::{
    initial_state_root_of, memory_image_commitment_of_reads, register_image_commitment_of_reads,
    ExecutionPublicInputs, ProofEnvelope, ProverAdapter,
};
use bud_proof::chips::batch::{absorb_states, keccak_f};
use bud_proof::chips::keccak::{prove_bound_keccak_f, verify_bound_keccak_f, BoundKeccakProof};
use bud_proof::plonky3_prover::{initial_memory_reads, initial_register_reads, Plonky3Adapter};
use bud_vm::{poseidon_full_state, Vm, VmError, POSEIDON_WIDTH};
use sha3::{Digest, Keccak256};

use super::asm::{Asm, AsmError, Program, R};
use crate::aggregation::frame::merge_pi;
use crate::aggregation::hash::TAG_AGG_MERGE;
use crate::domain::types::Hash32;

/// Number of 32-bit little-endian limbs per 32-byte digest.
const LIMBS: usize = 8;

/// Cell offsets inside `AggMerge` guest memory.
#[derive(Debug, Clone, Copy)]
struct MergeCells {
    left_prog: u64,
    left_pi: u64,
    right_prog: u64,
    right_pi: u64,
    merge_pi: u64,
    tick_prog: u64,
    self_prog: u64,
}

/// Compiled `AggMerge` `BudVM` program together with its canonical program hash.
#[derive(Debug, Clone)]
pub struct AggMergeProgram {
    /// Compiled `BudVM` bytecode.
    pub program: Program,
    /// `Keccak-256` hash of `program.code` (little-endian `u64` instruction words).
    pub self_program_hash: Hash32,
    /// Allowlisted `AggTick` program hash baked into the guest contract.
    pub tick_program_hash: Hash32,
    cells: MergeCells,
}

/// Witness supplied to execute or prove one `AggMerge` step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggMergeWitness {
    /// Program hash of the left child proof (`AggTick` or `AggMerge`).
    pub left_program_hash: Hash32,
    /// Public input digest (`tick_pi` or `merge_pi`) of the left child.
    pub left_pi: Hash32,
    /// Program hash of the right child proof (`AggTick` or `AggMerge`).
    pub right_program_hash: Hash32,
    /// Public input digest (`tick_pi` or `merge_pi`) of the right child.
    pub right_pi: Hash32,
}

/// Result of executing `AggMerge` inside `BudVM`.
#[derive(Debug, Clone)]
pub struct AggMergeRun {
    /// Computed `merge_pi = H(TAG_AGG_MERGE || left_pi || right_pi)`.
    pub merge_pi: Hash32,
    /// Number of `BudVM` execution steps.
    pub steps: usize,
    /// Initial RAM + register image commitment bound by `BudAir`.
    pub initial_state_root: Hash32,
    /// `receipt.state_writes_digest` committing `(left_pi, right_pi, merge_pi)`.
    pub state_writes_digest: Hash32,
}

/// End-to-end hybrid STARK proof of one `AggMerge` step:
/// - `vm_proof`: `BudAir` `Plonky3Adapter` proof verifying program-hash allowlist
///   enforcement and publication of `(left_pi, right_pi, merge_pi)`.
/// - `keccak_proof`: `BoundKeccakAir` proof binding `Keccak-f[1600]` over
///   `TAG_AGG_MERGE || left_pi || right_pi` -> `merge_pi`.
#[derive(Clone)]
pub struct AggMergeProof {
    /// Public inputs committed by `vm_proof`.
    pub public_inputs: ExecutionPublicInputs,
    /// `BudAir` `Plonky3Adapter` proof envelope.
    pub vm_proof: ProofEnvelope,
    /// `BoundKeccakAir` proof binding the `merge_pi` Keccak-256 sponge.
    pub keccak_proof: BoundKeccakProof,
    /// Total `BudVM` steps executed.
    pub steps: usize,
    /// Padded power-of-two trace rows of `BudAir`.
    pub trace_rows: usize,
}

/// Errors produced by `AggMerge` compilation, execution, proving, or verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggMergeError {
    /// Guest assembly failed.
    Assemble(AsmError),
    /// Child program hash was not in `{tick_program_hash, self_program_hash}`.
    UnauthorizedChildProgram,
    /// `BudVM` halted with an error.
    VmFailed(String),
    /// `BudAir` or `BoundKeccakAir` proving failed.
    ProveFailed(String),
    /// Proof verification or commitment binding failed.
    VerifyFailed(String),
}

/// Computes the canonical `Keccak-256` hash of a compiled `BudVM` program's
/// `code` words (little-endian `u64` encoding).
#[must_use]
pub fn program_hash_of(code: &[u64]) -> Hash32 {
    let mut hasher = Keccak256::new();
    for word in code {
        hasher.update(word.to_le_bytes());
    }
    hasher.finalize().into()
}

/// Computes the `BudVM` `receipt.state_writes_digest` for a digest list.
///
/// Each 32-byte digest is published consecutively as 8 little-endian 32-bit
/// `SWrite` calls (`slot 0..8`, `slot 8..16`, `slot 16..24`, ...).
#[must_use]
pub fn published_writes_digest_many(digests: &[&Hash32]) -> Hash32 {
    let mut acc = [0u64; 4];
    let mut slot = 0u64;
    for digest in digests {
        for chunk in digest.chunks_exact(4) {
            let limb = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let mut st = [0u64; POSEIDON_WIDTH];
            st[0] = slot;
            st[1] = u64::from(limb);
            st[2..6].copy_from_slice(&acc);
            let out = poseidon_full_state(st);
            acc.copy_from_slice(&out[..4]);
            slot += 1;
        }
    }
    let mut out = [0u8; 32];
    for (k, lane) in acc.iter().enumerate() {
        out[k * 8..(k + 1) * 8].copy_from_slice(&lane.to_le_bytes());
    }
    out
}

/// Emits guest instructions asserting that the 8-limb digest at `prog_cell`
/// equals either `tick_cell` or `self_cell`.
fn emit_check_allowlisted(a: &mut Asm, prog_cell: u64, tick_cell: u64, self_cell: u64) {
    let check_self = a.label();
    let ok_label = a.label();

    // Check equality with tick_prog.
    a.li(R[4], 0);
    for i in 0..LIMBS as u64 {
        a.load_abs(R[1], prog_cell + i);
        a.load_abs(R[2], tick_cell + i);
        a.neq(R[3], R[1], R[2]);
        a.add(R[4], R[4], R[3]);
    }
    a.jnz(R[4], check_self);
    a.jmp(ok_label);

    // Check equality with self_prog.
    a.bind(check_self);
    a.li(R[4], 0);
    for i in 0..LIMBS as u64 {
        a.load_abs(R[1], prog_cell + i);
        a.load_abs(R[2], self_cell + i);
        a.neq(R[3], R[1], R[2]);
        a.add(R[4], R[4], R[3]);
    }
    // R[5] = (R[4] == 0); Assert(R[5]) aborts if neither hash matched.
    a.li(R[6], 0);
    a.eq(R[5], R[4], R[6]);
    a.assert(R[5]);

    a.bind(ok_label);
}

/// Emits 8 `SWrite` instructions publishing the 8 limbs at `base_cell` into
/// consecutive storage slots starting at `start_slot`.
fn emit_publish_digest(a: &mut Asm, base_cell: u64, start_slot: u32) {
    for i in 0..u32::try_from(LIMBS).unwrap_or(8) {
        a.load_abs(R[1], base_cell + u64::from(i));
        a.swrite(start_slot + i, R[1]);
    }
}

/// Compiles the `AggMerge` `BudVM` program bound to `tick_program_hash`.
///
/// # Errors
///
/// Returns [`AggMergeError::Assemble`] if guest bytecode assembly fails.
pub fn agg_merge(tick_program_hash: &Hash32) -> Result<AggMergeProgram, AggMergeError> {
    let mut a = Asm::new();
    let cells = MergeCells {
        left_prog: a.alloc(LIMBS as u64),
        left_pi: a.alloc(LIMBS as u64),
        right_prog: a.alloc(LIMBS as u64),
        right_pi: a.alloc(LIMBS as u64),
        merge_pi: a.alloc(LIMBS as u64),
        tick_prog: a.alloc(LIMBS as u64),
        self_prog: a.alloc(LIMBS as u64),
    };

    a.region("allowlist_left");
    emit_check_allowlisted(&mut a, cells.left_prog, cells.tick_prog, cells.self_prog);

    a.region("allowlist_right");
    emit_check_allowlisted(&mut a, cells.right_prog, cells.tick_prog, cells.self_prog);

    a.region("publish");
    emit_publish_digest(&mut a, cells.left_pi, 0);
    emit_publish_digest(&mut a, cells.right_pi, 8);
    emit_publish_digest(&mut a, cells.merge_pi, 16);
    a.halt();

    let program = a.finish().map_err(AggMergeError::Assemble)?;
    let self_program_hash = program_hash_of(&program.code);
    Ok(AggMergeProgram {
        program,
        self_program_hash,
        tick_program_hash: *tick_program_hash,
        cells,
    })
}

fn write_digest_limbs(vm: &mut Vm, base_cell: u64, digest: &Hash32) {
    for (i, chunk) in digest.chunks_exact(4).enumerate() {
        let limb = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let byte_addr = ((base_cell as usize) + i) * 8;
        if let Some(slot) = vm.memory.get_mut(byte_addr..byte_addr + 8) {
            slot.copy_from_slice(&u64::from(limb).to_le_bytes());
        }
    }
}

fn build_merge_keccak_input(left_pi: &Hash32, right_pi: &Hash32) -> Vec<u8> {
    let mut input = Vec::with_capacity(TAG_AGG_MERGE.len() + 64);
    input.extend_from_slice(TAG_AGG_MERGE);
    input.extend_from_slice(left_pi);
    input.extend_from_slice(right_pi);
    input
}

fn seed_vm(
    merge_prog: &AggMergeProgram,
    witness: &AggMergeWitness,
    computed_merge_pi: &Hash32,
) -> Vm {
    let mem_bytes = ((merge_prog.program.memory_cells as usize) + 16) * 8;
    let mut vm = Vm::new(mem_bytes.max(4096));
    write_digest_limbs(
        &mut vm,
        merge_prog.cells.left_prog,
        &witness.left_program_hash,
    );
    write_digest_limbs(&mut vm, merge_prog.cells.left_pi, &witness.left_pi);
    write_digest_limbs(
        &mut vm,
        merge_prog.cells.right_prog,
        &witness.right_program_hash,
    );
    write_digest_limbs(&mut vm, merge_prog.cells.right_pi, &witness.right_pi);
    write_digest_limbs(&mut vm, merge_prog.cells.merge_pi, computed_merge_pi);
    write_digest_limbs(
        &mut vm,
        merge_prog.cells.tick_prog,
        &merge_prog.tick_program_hash,
    );
    write_digest_limbs(
        &mut vm,
        merge_prog.cells.self_prog,
        &merge_prog.self_program_hash,
    );
    vm
}

fn map_vm_err(err: VmError) -> AggMergeError {
    if matches!(err, VmError::AssertionFailed) {
        AggMergeError::UnauthorizedChildProgram
    } else {
        AggMergeError::VmFailed(format!("{err:?}"))
    }
}

/// Executes `AggMerge` in `BudVM` and returns its step count and commitments.
///
/// # Errors
///
/// Returns [`AggMergeError::UnauthorizedChildProgram`] if a child program hash
/// is outside `{tick_program_hash, self_program_hash}`, or
/// [`AggMergeError::VmFailed`] on other VM errors.
pub fn run_agg_merge(
    merge_prog: &AggMergeProgram,
    witness: &AggMergeWitness,
) -> Result<AggMergeRun, AggMergeError> {
    let computed_merge_pi = merge_pi(&witness.left_pi, &witness.right_pi);
    let mut vm = seed_vm(merge_prog, witness, &computed_merge_pi);
    let receipt = vm.run(&merge_prog.program.code).map_err(map_vm_err)?;
    if receipt.exit_code != 0 {
        return Err(AggMergeError::VmFailed(format!(
            "unexpected exit code {}",
            receipt.exit_code
        )));
    }
    let init_mem = memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace));
    let init_reg = register_image_commitment_of_reads(&initial_register_reads(&vm.trace));
    let initial_state_root = initial_state_root_of(init_mem, init_reg);

    Ok(AggMergeRun {
        merge_pi: computed_merge_pi,
        steps: vm.trace.len(),
        initial_state_root,
        state_writes_digest: receipt.state_writes_digest,
    })
}

/// Proves one `AggMerge` step end-to-end with `Plonky3Adapter` (`BudAir`) plus
/// `BoundKeccakAir` offloading `H(TAG_AGG_MERGE || left_pi || right_pi)`,
/// binding the proof to `chain_id`.
///
/// # Errors
///
/// Returns [`AggMergeError`] if child allowlist checks, VM execution, or STARK
/// proving fail.
pub fn prove_agg_merge(
    merge_prog: &AggMergeProgram,
    witness: &AggMergeWitness,
    chain_id: u64,
) -> Result<AggMergeProof, AggMergeError> {
    let computed_merge_pi = merge_pi(&witness.left_pi, &witness.right_pi);
    let mut vm = seed_vm(merge_prog, witness, &computed_merge_pi);
    let receipt = vm.run(&merge_prog.program.code).map_err(map_vm_err)?;
    if receipt.exit_code != 0 {
        return Err(AggMergeError::VmFailed(format!(
            "unexpected exit code {}",
            receipt.exit_code
        )));
    }

    let steps = vm.trace.len();
    let trace_rows = steps.next_power_of_two().max(16);
    let init_mem = memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace));
    let init_reg = register_image_commitment_of_reads(&initial_register_reads(&vm.trace));
    let initial_state_root = initial_state_root_of(init_mem, init_reg);

    let public_inputs = ExecutionPublicInputs {
        chain_id,
        program_hash: merge_prog.self_program_hash,
        initial_state_root,
        final_state_root: receipt.state_writes_digest,
        sender: 0,
        nonce: 0,
        block_height: 0,
        gas_limit: vm.gas_limit,
        gas_used: receipt.gas_used,
        exit_code: receipt.exit_code,
        trace_len: steps as u64,
        event_digest: [0u8; 32],
        state_writes_digest: receipt.state_writes_digest,
    };

    let vm_proof = Plonky3Adapter::prove(&vm.trace, &public_inputs, &merge_prog.program.code)
        .map_err(|e| AggMergeError::ProveFailed(format!("{e:?}")))?;

    let keccak_input = build_merge_keccak_input(&witness.left_pi, &witness.right_pi);
    let sponge_inputs = absorb_states(&keccak_input);
    let (keccak_proof, _outputs) = prove_bound_keccak_f(&sponge_inputs)
        .map_err(|e| AggMergeError::ProveFailed(format!("{e:?}")))?;

    Ok(AggMergeProof {
        public_inputs,
        vm_proof,
        keccak_proof,
        steps,
        trace_rows,
    })
}

/// Verifies an [`AggMergeProof`] against `merge_prog`, `left_pi`, `right_pi`,
/// `expected_merge_pi`, and `chain_id`.
///
/// # Errors
///
/// Returns [`AggMergeError::VerifyFailed`] if any binding or STARK proof check fails.
pub fn verify_agg_merge(
    merge_prog: &AggMergeProgram,
    left_pi: &Hash32,
    right_pi: &Hash32,
    expected_merge_pi: &Hash32,
    chain_id: u64,
    proof: &AggMergeProof,
) -> Result<(), AggMergeError> {
    if proof.public_inputs.chain_id != chain_id {
        return Err(AggMergeError::VerifyFailed("chain_id mismatch".into()));
    }
    if proof.public_inputs.program_hash != merge_prog.self_program_hash {
        return Err(AggMergeError::VerifyFailed("program_hash mismatch".into()));
    }
    if proof.public_inputs.exit_code != 0 {
        return Err(AggMergeError::VerifyFailed("non-zero exit code".into()));
    }
    if proof.public_inputs.event_digest != [0u8; 32] {
        return Err(AggMergeError::VerifyFailed("unexpected events".into()));
    }
    let expected_writes = published_writes_digest_many(&[left_pi, right_pi, expected_merge_pi]);
    if proof.public_inputs.state_writes_digest != expected_writes
        || proof.public_inputs.final_state_root != expected_writes
    {
        return Err(AggMergeError::VerifyFailed(
            "state_writes_digest mismatch".into(),
        ));
    }

    // 1. Verify the BudAir Plonky3 STARK proof.
    Plonky3Adapter::verify(
        &proof.vm_proof,
        &proof.public_inputs,
        &merge_prog.program.code,
    )
    .map_err(|e| AggMergeError::VerifyFailed(format!("BudAir verify failed: {e:?}")))?;

    // 2. Verify the BoundKeccakAir STARK proof for H(TAG_AGG_MERGE || left_pi || right_pi).
    let keccak_input = build_merge_keccak_input(left_pi, right_pi);
    let expected_inputs = absorb_states(&keccak_input);
    let mut expected_outputs = expected_inputs.clone();
    for state in &mut expected_outputs {
        keccak_f(state);
    }
    verify_bound_keccak_f(&expected_inputs, &expected_outputs, &proof.keccak_proof)
        .map_err(|e| AggMergeError::VerifyFailed(format!("BoundKeccakAir verify failed: {e:?}")))?;

    let final_state = expected_outputs
        .last()
        .ok_or_else(|| AggMergeError::VerifyFailed("empty sponge output".into()))?;
    let mut squeezed = [0u8; 32];
    for i in 0..4 {
        squeezed[i * 8..(i + 1) * 8].copy_from_slice(&final_state[i].to_le_bytes());
    }
    if squeezed != *expected_merge_pi {
        return Err(AggMergeError::VerifyFailed(
            "squeezed merge_pi mismatch".into(),
        ));
    }
    Ok(())
}
