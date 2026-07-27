//! Structural + cryptographic verification of AI execution proofs.

use crate::ai::types::{AiExecutionProof, AiInferenceRequest, AiInferenceResult, AiModelSpec};
use bud_proof::{DefaultAdapter as Prover, ExecutionPublicInputs, ProofEnvelope, ProverAdapter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionVerifyReport {
    pub commitments_ok: bool,
    pub model_bound: bool,
    pub has_proof_bytes: bool,
    pub program_hash_nonzero: bool,
    pub program_hash_matches_model: bool,
    pub stark_ok: Option<bool>,
}

impl ExecutionVerifyReport {
    pub fn is_structurally_valid(&self) -> bool {
        self.commitments_ok
            && self.model_bound
            && self.has_proof_bytes
            && self.program_hash_nonzero
            && self.program_hash_matches_model
    }

    /// Structural + STARK (when attempted).
    pub fn is_fully_valid(&self) -> bool {
        self.is_structurally_valid() && self.stark_ok != Some(false)
    }
}

/// Structural checks (no STARK). Used when guest bytecode is not available.
pub fn verify_execution_proof_structural(
    proof: &AiExecutionProof,
    request: &AiInferenceRequest,
    result: &AiInferenceResult,
) -> ExecutionVerifyReport {
    verify_execution_proof_structural_with_model(proof, request, result, None)
}

pub fn verify_execution_proof_structural_with_model(
    proof: &AiExecutionProof,
    request: &AiInferenceRequest,
    result: &AiInferenceResult,
    model: Option<&AiModelSpec>,
) -> ExecutionVerifyReport {
    let program_hash_matches_model = match model.and_then(|m| m.execution_program_hash) {
        Some(expected) => expected == proof.program_hash,
        // If model requires execution proof,
        // Program_hash must be registered. None bypass only allowed
        // When require_execution_proof is false or no model registered.
        None => model.is_none_or(|m| !m.require_execution_proof),
    };
    ExecutionVerifyReport {
        commitments_ok: proof.commitments_match(request, result),
        model_bound: proof.model_id == request.model_id,
        has_proof_bytes: !proof.proof_bytes.is_empty(),
        program_hash_nonzero: proof.program_hash != [0u8; 32],
        program_hash_matches_model,
        stark_ok: None,
    }
}

/// Deserialize postcard `bud_proof::ProofEnvelope` and STARK-verify against
/// `program` words. Public inputs are taken from the envelope hash check via
/// Adapter (expected_inputs must match what was proven).
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

/// Full L1 path: structural + optional STARK when `program` is provided.
pub fn verify_execution_proof_full(
    proof: &AiExecutionProof,
    request: &AiInferenceRequest,
    result: &AiInferenceResult,
    model: Option<&AiModelSpec>,
    program_and_pi: Option<(&[u64], &ExecutionPublicInputs)>,
) -> ExecutionVerifyReport {
    let mut rep = verify_execution_proof_structural_with_model(proof, request, result, model);
    if let Some((program, pi)) = program_and_pi {
        match verify_execution_proof_stark(proof, program, pi) {
            Ok(()) => rep.stark_ok = Some(true),
            Err(_) => rep.stark_ok = Some(false),
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::types::*;
    use crate::core::address::Address;

    fn sample_req_res() -> (AiInferenceRequest, AiInferenceResult, AiModelId) {
        let owner = Address::from([1u8; 32]);
        let mid = AiModelId::of(&owner, &[9u8; 32], 1);
        let req = AiInferenceRequest {
            request_id: AiRequestId([2u8; 32]),
            requester: owner,
            model_id: mid,
            input_commitment: [3u8; 32],
            input_ref: BoundedBytes::empty(),
            max_fee: 0,
            callback: None,
            submitted_at_block: 0,
            deadline_block: 10,
        };
        let res = AiInferenceResult {
            request_id: req.request_id,
            verifier: owner,
            output_commitment: [4u8; 32],
            output_ref: BoundedBytes::empty(),
            result_nonce: 0,
            signature: vec![],
            submitted_at_block: 1,
        };
        (req, res, mid)
    }

    #[test]
    fn structural_fail_on_empty_proof() {
        let (req, res, mid) = sample_req_res();
        let proof = AiExecutionProof {
            model_id: mid,
            input_commitment: req.input_commitment,
            output_commitment: res.output_commitment,
            program_hash: [5u8; 32],
            proof_bytes: vec![],
            steps: 0,
            gas_used: 0,
        };
        let rep = verify_execution_proof_structural(&proof, &req, &res);
        assert!(!rep.is_structurally_valid());
    }

    #[test]
    fn structural_fail_on_model_program_hash_mismatch() {
        let (req, res, mid) = sample_req_res();
        let mut spec = AiModelSpec {
            model_id: mid,
            model_hash: [9u8; 32],
            owner: req.requester,
            min_verifier_count: 1,
            agreement_threshold: 1,
            max_input_ref_bytes: 1024,
            max_output_ref_bytes: 1024,
            request_deadline_blocks: 10,
            result_deadline_blocks: 10,
            version: 1,
            active: true,
            require_execution_proof: true,
            execution_program_hash: Some([7u8; 32]),
            execution_class: 1,
        };
        let proof = AiExecutionProof {
            model_id: mid,
            input_commitment: req.input_commitment,
            output_commitment: res.output_commitment,
            program_hash: [5u8; 32],
            proof_bytes: vec![1, 2, 3],
            steps: 1,
            gas_used: 1,
        };
        let rep = verify_execution_proof_structural_with_model(&proof, &req, &res, Some(&spec));
        assert!(!rep.program_hash_matches_model);
        assert!(!rep.is_structurally_valid());
        spec.execution_program_hash = Some(proof.program_hash);
        let rep2 = verify_execution_proof_structural_with_model(&proof, &req, &res, Some(&spec));
        assert!(rep2.program_hash_matches_model);
    }
}
