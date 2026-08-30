//! STARK verification and proof-production helpers (bud-proof `DefaultAdapter`).
//!
//! **This module is NOT the production path, but saying "verification is not
//! wired" is no longer true either.** On-chain inference verification does not
//! go through this file; the transaction path calls
//! `verify_execution_proof_full` in `src/ai/execution/verify.rs`, which reaches
//! `verify_execution_proof_stark` in `src/ai/execution/stark.rs`, and really
//! does verify the STARK (`src/execution/executor.rs`, for models with
//! `require_execution_proof`). The `ai_exec_verifier_unavailable` refusal has
//! been removed: the model records `execution_program_hash`,
//! `AiExecutionProof::public_inputs` carries the inputs the proof was produced
//! over, and the node rebuilds the guest program with
//! `guest_program_for_model`. The behaviour is still fail-closed, but it now
//! names what is missing from the proof rather than what is missing from the
//! node (`ai_exec_no_public_inputs`, `ai_exec_no_program_hash`,
//! `ai_exec_program_hash`, `ai_exec_exit_code`, `ai_exec_stark`).
//!
//! The two functions here are the **helper/scaffold** counterparts of that
//! path and are deliberately uncalled;
//! `src/tests/ai_verification_status_locks.rs`
//! (`stark_verification_helpers_have_no_production_callers`) breaks if a call
//! is added. The current table is in `docs/AI_VERIFICATION_STATUS.md`.
//!
//! **The two paths are not interchangeable.** Before wiring one to the other:
//!
//! - **Serialization differs:** `ProofEnvelope` is decoded here with `bincode`,
//!   while the production path uses `postcard`. The same byte string does not
//!   decode under both.
//! - **`program_hash` differs:** production uses
//!   `stark_program_hash_from_words` (untagged Keccak-256), whereas
//!   `program_hash_from_words` (SHA3-256 with the `BDLM_AI_GUEST_PROGRAM_V1`
//!   tag) is only a registry identity. Confusing the two makes verification
//!   fail every time.
//! - **`build_public_inputs` is not safe for consensus:** it writes state roots
//!   and digests as zero. It holds only for this file's tests; the transaction
//!   path takes the inputs from the proof and binds them against the record.
//!
//! # Why `chain_id` is a parameter now
//!
//! This function used to write `chain_id` as a hard-coded `1`. The chain's real
//! identity is what binds a proof to the chain it was produced on. Fixing it
//! does two things: the proof produced belongs to no real chain, and any proof
//! carrying `chain_id = 1` matches the input expected here. That is exactly the
//! "public input bound to the wrong thing" class in the threat model; in
//! Aleo/snarkVM the same class came out as full transaction forgery.
//!
//! The helper path has no production caller today, but a hard-coded field goes
//! silently wrong the day it is wired. The field is now a parameter the caller
//! has to supply, and the `no-hardcoded-chain-id` gate stops it coming back.

use bud_proof::{DefaultAdapter, ExecutionPublicInputs, ProofEnvelope, ProverAdapter};
use bud_vm::Vm;
use sha3::{Digest, Keccak256};

/// Verifies a Lubot inference proof with a real plonky3 STARK (verify only).
pub fn verify_inference_stark(
    proof_bytes: &[u8],
    expected_inputs: &ExecutionPublicInputs,
    program: &[u64],
) -> Result<(), String> {
    let envelope: ProofEnvelope = bincode::deserialize(proof_bytes)
        .map_err(|e| format!("Lubot STARK: ProofEnvelope deserialize failed: {e}"))?;
    DefaultAdapter::verify(&envelope, expected_inputs, program)
        .map_err(|e| format!("Lubot STARK: verification failed: {e:?}"))
}

/// Builds `ExecutionPublicInputs` from the VM and program (Keccak-256 `program_hash`).
///
/// `chain_id` comes from the caller: the field that binds a proof to a chain cannot be fixed.
fn build_public_inputs(vm: &Vm, program: &[u64], chain_id: u64) -> ExecutionPublicInputs {
    let program_bytes: Vec<u8> = program.iter().flat_map(|&i| i.to_le_bytes()).collect();
    let mut hasher = Keccak256::new();
    hasher.update(&program_bytes);
    let program_hash: [u8; 32] = hasher.finalize().into();
    ExecutionPublicInputs {
        chain_id,
        program_hash,
        initial_state_root: [0u8; 32],
        final_state_root: [0u8; 32],
        sender: vm.context.sender,
        nonce: vm.context.nonce,
        block_height: vm.context.block_height,
        gas_limit: vm.gas_limit,
        gas_used: vm.gas_used,
        exit_code: 0,
        trace_len: vm.trace.len() as u64,
        event_digest: [0u8; 32],
        state_writes_digest: [0u8; 32],
    }
}

/// Produces and verifies a Lubot inference proof: a real plonky3 STARK prove/verify round trip.
///
/// Runs `program` on `vm`, produces a STARK proof from the trace, then verifies
/// that proof. Returns a `ProofEnvelope`.
pub fn generate_and_verify_proof(
    vm: &mut Vm,
    program: &[u64],
    chain_id: u64,
) -> Result<ProofEnvelope, String> {
    let receipt = vm.run_receipt(program);
    if !receipt.success {
        return Err("Lubot STARK: program execution failed".into());
    }
    let pi = build_public_inputs(vm, program, chain_id);
    let envelope = DefaultAdapter::prove(&vm.trace, &pi, program)
        .map_err(|e| format!("Lubot STARK: prove failed: {e:?}"))?;
    DefaultAdapter::verify(&envelope, &pi, program)
        .map_err(|e| format!("Lubot STARK: verify failed: {e:?}"))?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::DEFAULT_CHAIN_ID;
    use bud_proof::ExecutionPublicInputs;

    fn inputs() -> ExecutionPublicInputs {
        ExecutionPublicInputs {
            chain_id: 0,
            program_hash: [0; 32],
            initial_state_root: [0; 32],
            final_state_root: [0; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: 0,
            gas_used: 0,
            exit_code: 0,
            trace_len: 0,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        }
    }

    /// The real STARK verifier is called; an invalid proof is rejected.
    #[test]
    fn stark_verify_rejects_invalid_proof() {
        let envelope = ProofEnvelope {
            proof_format_version: 1,
            backend: "plonky3".to_string(),
            p3_version: "0.6".to_string(),
            fri_params_id: "default".to_string(),
            public_inputs_hash: inputs().hash(),
            proof_bytes: vec![0u8; 8],
            degree_bits: 4,
        };
        let bytes = bincode::serialize(&envelope).expect("serialize envelope");
        let res = verify_inference_stark(&bytes, &inputs(), &[]);
        assert!(res.is_err(), "invalid proof must be rejected");
    }

    /// Garbage bytes are rejected at deserialization.
    #[test]
    fn stark_verify_rejects_garbage_bytes() {
        let res = verify_inference_stark(&[0xFF; 10], &inputs(), &[]);
        assert!(res.is_err(), "garbage bytes must fail");
    }

    /// A real plonky3 STARK prove/verify round trip, on a Halt program.
    #[test]
    fn lubot_stark_prove_and_verify_roundtrip() {
        let mut vm = Vm::new(64);
        // Halt = opcode 0x00 → minimal program, tek instruction.
        let envelope =
            generate_and_verify_proof(&mut vm, &[0u64], DEFAULT_CHAIN_ID).expect("prove+verify");
        assert!(
            !envelope.proof_bytes.is_empty(),
            "proof bytes must be non-empty after real STARK prove"
        );
    }

    /// Does `chain_id` actually reach the public input?
    ///
    /// This test could not have been written while the value was hard-coded:
    /// two different chains produced the same input, and one chain's proof
    /// matched the input expected on the other.
    #[test]
    fn the_chain_id_reaches_the_public_inputs() {
        let vm = Vm::new(64);
        let a = build_public_inputs(&vm, &[0u64], DEFAULT_CHAIN_ID);
        let b = build_public_inputs(&vm, &[0u64], 1);
        assert_eq!(a.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(b.chain_id, 1);
        assert_ne!(
            a.hash(),
            b.hash(),
            "two chains must not produce the same public-input hash"
        );
    }
}
