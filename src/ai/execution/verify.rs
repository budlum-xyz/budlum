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
    /// The proof carries the weights digest the model registered.
    ///
    /// `program_hash_matches_model` only binds the guest program, which for
    /// the fixed-point MLP depends on the architecture alone — the weights
    /// live in a memory image the STARK does not constrain. Without this
    /// field a prover could run the registered program over any weights.
    pub weights_bound: bool,
    pub stark_ok: Option<bool>,
}

impl ExecutionVerifyReport {
    pub fn is_structurally_valid(&self) -> bool {
        self.commitments_ok
            && self.model_bound
            && self.has_proof_bytes
            && self.program_hash_nonzero
            && self.program_hash_matches_model
            && self.weights_bound
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
    // The weights digest is checked on the same terms as the program hash: if
    // the model registered one, the proof has to carry exactly that value; if
    // it did not, only a model that does not require an execution proof may
    // pass. Two models with the same architecture share a program hash, so
    // without this a proof for one of them verifies against the other.
    let weights_bound = match model.and_then(|m| m.execution_weights_digest) {
        Some(expected) => proof.weights_digest == Some(expected),
        None => model.is_none_or(|m| !m.require_execution_proof),
    };
    ExecutionVerifyReport {
        commitments_ok: proof.commitments_match(request, result),
        model_bound: proof.model_id == request.model_id,
        has_proof_bytes: !proof.proof_bytes.is_empty(),
        program_hash_nonzero: proof.program_hash != [0u8; 32],
        program_hash_matches_model,
        weights_bound,
        stark_ok: None,
    }
}

/// Deserialize postcard `bud_proof::ProofEnvelope` and STARK-verify against
/// `program` words. Public inputs are taken from the envelope hash check via
/// Adapter (expected_inputs must match what was proven).
/// Re-derive `initial_state_root` for a fixed-point MLP inference.
///
/// This is what makes the AIR's initial-memory commitment worth having. The
/// AIR proves the trace folds to whatever `initial_state_root` says, but the
/// fold uses fixed constants — a prover that wants a particular accumulator
/// can solve for a set of reads that reaches it and run on different weights.
/// Demonstrated: for reads `[(16,2),(24,3),(32,1)]` a forged set
/// `[(16,9),(24,-9),(32,x)]` hits the same accumulator with one modular
/// multiplication.
///
/// The defence is not to make the fold collision-resistant — that needs a hash
/// in the AIR and the trace cannot afford one — but to stop trusting the
/// prover's value. The verifier holds the registered model, so it can rebuild
/// the memory image, replay the reads and compute the commitment itself. A
/// proof whose public input disagrees is rejected before the STARK is even
/// checked.
pub fn expected_initial_state_root(
    spec: &crate::ai::execution::FixedPointMlpSpec,
    input: &[i32],
) -> Result<[u8; 32], String> {
    use crate::ai::execution::{
        build_matmul_guest_program, setup_guest_memory, GUEST_MEMORY_BYTES,
    };
    let program = build_matmul_guest_program(spec)?;
    let mut vm = bud_vm::Vm::with_gas_limit(GUEST_MEMORY_BYTES, u64::MAX);
    setup_guest_memory(&mut vm.memory, spec, input)?;
    let receipt = vm.run_receipt(&program);
    if !receipt.success {
        return Err(format!("guest re-execution failed: {:?}", receipt.error));
    }
    Ok(bud_proof::memory_image_commitment_of_reads(
        &bud_proof::initial_memory_reads(&vm.trace),
    ))
}

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
            weights_digest: None,
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
            execution_weights_digest: None,
        };
        let proof = AiExecutionProof {
            model_id: mid,
            input_commitment: req.input_commitment,
            output_commitment: res.output_commitment,
            program_hash: [5u8; 32],
            proof_bytes: vec![1, 2, 3],
            steps: 1,
            gas_used: 1,
            weights_digest: None,
        };
        let rep = verify_execution_proof_structural_with_model(&proof, &req, &res, Some(&spec));
        assert!(!rep.program_hash_matches_model);
        assert!(!rep.is_structurally_valid());
        spec.execution_program_hash = Some(proof.program_hash);
        let rep2 = verify_execution_proof_structural_with_model(&proof, &req, &res, Some(&spec));
        assert!(rep2.program_hash_matches_model);
    }

    /// The finding this field exists for: two models with the same layer shape
    /// compile to the same guest program, because the fixed-point MLP guest
    /// reads its weights from memory rather than baking them into immediates.
    /// The STARK does not bind that memory either. So without a weights digest
    /// a proof produced for one model verifies against the other.
    #[test]
    fn program_hash_alone_does_not_separate_two_models_of_the_same_shape() {
        use crate::ai::execution::{matmul_program_hash, weights_digest, FixedPointMlpSpec};

        let honest = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![0],
        };
        let swapped = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![9, -9],
            biases: vec![0],
        };

        assert_eq!(
            matmul_program_hash(&honest).unwrap(),
            matmul_program_hash(&swapped).unwrap(),
            "same architecture must produce the same program — this is the gap"
        );
        assert_ne!(
            weights_digest(&honest),
            weights_digest(&swapped),
            "the weights digest is what tells them apart"
        );
    }

    /// A registered model must reject a proof carrying a different weights
    /// digest, even when every other structural check passes.
    #[test]
    fn structural_check_rejects_a_proof_for_different_weights() {
        use crate::ai::execution::{weights_digest, FixedPointMlpSpec};

        let honest = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![0],
        };
        let swapped = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![9, -9],
            biases: vec![0],
        };

        let (req, res, mid) = sample_req_res();
        let spec = AiModelSpec {
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
            execution_program_hash: Some([5u8; 32]),
            execution_class: 1,
            execution_weights_digest: Some(weights_digest(&honest)),
        };

        // A proof that is correct in every other respect but claims the
        // swapped weights.
        let attacker = AiExecutionProof {
            model_id: mid,
            input_commitment: req.input_commitment,
            output_commitment: res.output_commitment,
            program_hash: [5u8; 32],
            proof_bytes: vec![1, 2, 3],
            steps: 1,
            gas_used: 1,
            weights_digest: Some(weights_digest(&swapped)),
        };
        let rep = verify_execution_proof_structural_with_model(&attacker, &req, &res, Some(&spec));
        assert!(
            rep.program_hash_matches_model,
            "the program hash still matches — that is exactly why it is not enough"
        );
        assert!(!rep.weights_bound, "the weights digest must not match");
        assert!(!rep.is_structurally_valid());

        // The same proof with the registered digest passes.
        let honest_proof = AiExecutionProof {
            weights_digest: Some(weights_digest(&honest)),
            ..attacker.clone()
        };
        let rep =
            verify_execution_proof_structural_with_model(&honest_proof, &req, &res, Some(&spec));
        assert!(rep.weights_bound);
        assert!(
            rep.is_structurally_valid(),
            "the honest proof must still pass — the gate cannot just reject everything"
        );
    }

    /// A proof-required model that registered a digest must not accept a proof
    /// that simply omits one.
    #[test]
    fn missing_weights_digest_does_not_bypass_a_registered_one() {
        use crate::ai::execution::{weights_digest, FixedPointMlpSpec};

        let honest = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![0],
        };
        let (req, res, mid) = sample_req_res();
        let spec = AiModelSpec {
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
            execution_program_hash: Some([5u8; 32]),
            execution_class: 1,
            execution_weights_digest: Some(weights_digest(&honest)),
        };
        let proof = AiExecutionProof {
            model_id: mid,
            input_commitment: req.input_commitment,
            output_commitment: res.output_commitment,
            program_hash: [5u8; 32],
            proof_bytes: vec![1, 2, 3],
            steps: 1,
            gas_used: 1,
            weights_digest: None,
        };
        let rep = verify_execution_proof_structural_with_model(&proof, &req, &res, Some(&spec));
        assert!(!rep.weights_bound, "omitting the digest must not bypass it");
        assert!(!rep.is_structurally_valid());
    }

    /// A model that does not require an execution proof keeps working without
    /// a digest — the binding is a requirement of the proof path, not a new
    /// obligation on every model.
    #[test]
    fn attestation_only_models_are_unaffected() {
        let (req, res, mid) = sample_req_res();
        let spec = AiModelSpec {
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
            require_execution_proof: false,
            execution_program_hash: None,
            execution_class: 0,
            execution_weights_digest: None,
        };
        let proof = AiExecutionProof {
            model_id: mid,
            input_commitment: req.input_commitment,
            output_commitment: res.output_commitment,
            program_hash: [5u8; 32],
            proof_bytes: vec![1, 2, 3],
            steps: 1,
            gas_used: 1,
            weights_digest: None,
        };
        let rep = verify_execution_proof_structural_with_model(&proof, &req, &res, Some(&spec));
        assert!(rep.weights_bound);
        assert!(rep.is_structurally_valid());
    }

    /// The digest must survive a round trip through the wire format,
    /// otherwise the check silently degrades to "absent" on every relayed
    /// transaction.
    #[test]
    fn weights_digest_survives_proto_round_trip() {
        use crate::ai::execution::{weights_digest, FixedPointMlpSpec};
        use crate::core::transaction::{Transaction, TransactionType};
        use crate::network::proto_conversions::pb;

        let spec = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![0],
        };
        let digest = weights_digest(&spec);
        let (req, res, mid) = sample_req_res();

        let proof = AiExecutionProof {
            model_id: mid,
            input_commitment: req.input_commitment,
            output_commitment: res.output_commitment,
            program_hash: [5u8; 32],
            proof_bytes: vec![1, 2, 3],
            steps: 1,
            gas_used: 1,
            weights_digest: Some(digest),
        };
        let mut tx = Transaction::new(req.requester, req.requester, 0, Vec::new());
        tx.tx_type = TransactionType::AiAttachExecutionProof {
            request_id: res.request_id,
            proof: proof.clone(),
        };
        let proto = pb::ProtoTransaction::from(&tx);
        let back = Transaction::try_from(proto).expect("round trip");
        match back.tx_type {
            TransactionType::AiAttachExecutionProof { proof: p, .. } => {
                assert_eq!(
                    p.weights_digest,
                    Some(digest),
                    "the digest must survive encoding; losing it turns the \
                     check into a no-op for every relayed proof"
                );
            }
            other => panic!("wrong tx type: {other:?}"),
        }
    }

    /// The fold the AIR uses is solvable, and this shows it.
    ///
    /// `acc' = acc * BETA + addr * GAMMA + val` with fixed constants is a
    /// polynomial evaluated at a known point. Given an honest accumulator, a
    /// prover can pick the first reads freely and solve the last one to land
    /// on the same value — one modular multiplication, no search.
    #[test]
    fn the_constant_fold_can_be_collided() {
        const P: u128 = 18_446_744_069_414_584_321;
        const BETA: u128 = 0x9E37_79B9_7F4A_7C15;
        const GAMMA: u128 = 0xC2B2_AE3D_27D4_EB4F;

        let fold = |reads: &[(u64, u64)]| -> u64 {
            let mut acc: u128 = 0;
            for (i, (a, v)) in reads.iter().enumerate() {
                let t = ((*a as u128) * GAMMA + *v as u128) % P;
                acc = if i == 0 { t } else { (acc * BETA + t) % P };
            }
            acc as u64
        };

        let honest = [(16u64, 2u64), (24, 3), (32, 1)];
        let target = fold(&honest);

        // Choose two different weights, solve for the third value.
        let (a0, v0) = (16u64, 9u64);
        let (a1, v1) = (24u64, (P - 9) as u64);
        let a2 = 32u64;
        let t0 = ((a0 as u128) * GAMMA + v0 as u128) % P;
        let t1 = ((a1 as u128) * GAMMA + v1 as u128) % P;
        let partial = (t0 * BETA + t1) % P;
        let t2 = (target as u128 + P - (partial * BETA) % P) % P;
        let v2 = (t2 + P - ((a2 as u128) * GAMMA) % P) % P;

        let forged = [(a0, v0), (a1, v1), (a2, v2 as u64)];
        assert_eq!(
            fold(&forged),
            target,
            "the collision must land exactly; if this stops holding the fold \
             changed and the defence below has to be re-argued"
        );
        assert_ne!(honest, forged, "the reads really are different");
    }

    /// Which is why the verifier does not trust the prover's value.
    ///
    /// It holds the registered model, so it rebuilds the image, replays the
    /// reads and computes the commitment itself.
    #[test]
    fn the_verifier_derives_the_commitment_itself() {
        use crate::ai::execution::FixedPointMlpSpec;

        let spec = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![1],
        };
        let root = expected_initial_state_root(&spec, &[4, 5]).unwrap();
        assert_ne!(root, [0u8; 32], "a seeded guest must commit to something");
        // Deterministic: the same model and input give the same root.
        assert_eq!(root, expected_initial_state_root(&spec, &[4, 5]).unwrap());
    }

    /// Different weights must give a different expected root, so a proof
    /// produced for one model cannot be presented for another.
    #[test]
    fn different_weights_give_a_different_expected_root() {
        use crate::ai::execution::FixedPointMlpSpec;

        let a = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![1],
        };
        let b = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![9, -9],
            biases: vec![1],
        };
        assert_ne!(
            expected_initial_state_root(&a, &[4, 5]).unwrap(),
            expected_initial_state_root(&b, &[4, 5]).unwrap()
        );
    }

    /// And a different input too — the input is part of the seeded image.
    #[test]
    fn different_inputs_give_a_different_expected_root() {
        use crate::ai::execution::FixedPointMlpSpec;

        let spec = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![1],
        };
        assert_ne!(
            expected_initial_state_root(&spec, &[4, 5]).unwrap(),
            expected_initial_state_root(&spec, &[6, 7]).unwrap()
        );
    }

    /// The re-derived root must equal what the prover actually produced,
    /// otherwise the check would reject every honest proof.
    #[test]
    fn the_expected_root_matches_a_real_proof() {
        use crate::ai::execution::{
            build_matmul_guest_program, setup_guest_memory, words_to_bytecode, FixedPointMlpSpec,
            GUEST_MEMORY_BYTES,
        };

        let spec = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![1],
        };
        let input = [4i32, 5];
        let words = build_matmul_guest_program(&spec).unwrap();
        let (_, pi, _) = crate::execution::zkvm::prove_bytecode_with_memory(
            &words_to_bytecode(&words),
            10_000_000,
            |mem| setup_guest_memory(mem, &spec, &input).map(|_| ()),
        )
        .expect("the honest path must prove");
        let _ = GUEST_MEMORY_BYTES;

        assert_eq!(
            pi.initial_state_root,
            expected_initial_state_root(&spec, &input).unwrap(),
            "the verifier's independent derivation must agree with the prover \
             on an honest proof"
        );
    }
}
