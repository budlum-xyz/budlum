//! The STARK half of execution-proof verification.
//!
//! This sits beside [`verify_execution_proof_full`] rather than inside it on
//! purpose. The bundle is the entry point the transaction path calls, and a
//! helper that only its own file ever names is a helper nobody outside can see
//! being used: an idle-code scan, a reader looking for the security boundary,
//! and a later refactor that wants the cryptographic check on its own all have
//! to find it behind a public path instead of in a private corner of the file
//! that happens to call it.

use crate::ai::types::AiExecutionProof;
use bud_proof::{DefaultAdapter as Prover, ExecutionPublicInputs, ProofEnvelope, ProverAdapter};

/// Deserialize the postcard [`ProofEnvelope`] the proof carries and verify it
/// against the rebuilt guest program and the expected public inputs.
///
/// Every refusal is a bound the caller cannot negotiate: the envelope has to fit
/// [`MAX_PROOF_BYTES`] before it is decoded, its `public_inputs_hash` has to be
/// the hash of the inputs the caller derived rather than the ones the prover
/// claims, its `program_hash` has to be the registered program, and the STARK
/// has to verify. The size bound is first because decoding is the work a hostile
/// envelope exists to make the node pay for.
///
/// [`MAX_PROOF_BYTES`]: crate::execution::proof_verifier::MAX_PROOF_BYTES
pub fn verify_execution_proof_stark(
    proof: &AiExecutionProof,
    program: &[u64],
    expected_inputs: &ExecutionPublicInputs,
) -> Result<(), String> {
    if proof.proof_bytes.len() > crate::execution::proof_verifier::MAX_PROOF_BYTES {
        return Err("execution proof_bytes exceed MAX_PROOF_BYTES".into());
    }
    let envelope: ProofEnvelope = postcard::from_bytes(&proof.proof_bytes)
        .map_err(|e| format!("execution proof deserialize: {e}"))?;
    if envelope.public_inputs_hash != expected_inputs.hash() {
        return Err("execution proof public_inputs_hash mismatch".into());
    }
    if expected_inputs.program_hash != proof.program_hash {
        return Err("execution proof program_hash != public_inputs.program_hash".into());
    }
    Prover::verify(&envelope, expected_inputs, program)
        .map_err(|e| format!("execution STARK verify failed: {e:?}"))?;
    Ok(())
}
