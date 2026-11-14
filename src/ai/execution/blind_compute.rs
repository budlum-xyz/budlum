//! Confidential Data Market computation (`ComputeWithoutSeeing`, IP-60 step 8).
//!
//! Combines a sealed B.U.D. 3.0 object manifest (`CipherProfile::Aead` or
//! `CipherProfile::FieldNative`), a zero-knowledge [`ConsentProof`] bound to a
//! `DeletionSet` tombstone check, and full Plonky3 STARK verification of the
//! AI execution proof without ever exposing the sealed dataset plaintext.
//!
//! WIRING: unwired - no production transaction admits a
//! ComputeWithoutSeeingBundle. The verifier remains a helper, not an active
//! authorization check, until the confidential inference transaction exists.

use crate::ai::execution::verify::{verify_execution_proof_full, ExecutionVerifyReport};
use crate::ai::types::{
    AiExecutionProof, AiInferenceRequest, AiInferenceResult, AiModelId, AiModelSpec,
};
use crate::core::hash::hash_fields_bytes;
use crate::storage::bud3::delete::DeletionSet;
use crate::storage::bud3::registry::ObjectKey;
use crate::storage::bud3::seal::{ConsentProof, SealedObjectManifest};
use bud_proof::ExecutionPublicInputs;

/// Domain tag binding blind-compute permits to `(model_id, request.input_commitment)`.
const BLIND_COMPUTE_SCOPE_TAG: &[u8] = b"BDLM_BLIND_COMPUTE_SCOPE_V1";

/// Compute the canonical scope digest linking a sealed dataset consent grant
/// to a target AI model and its quantized inference input commitment.
#[must_use]
pub fn blind_compute_scope_tag(
    model_id: &AiModelId,
    request_input_commitment: &[u8; 32],
) -> [u8; 32] {
    hash_fields_bytes(&[
        BLIND_COMPUTE_SCOPE_TAG,
        &model_id.0,
        request_input_commitment,
    ])
}

/// Verifiable authorization granting one-time or epoch-bounded blind inference
/// rights over a sealed B.U.D. 3.0 dataset (`ComputeWithoutSeeing`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComputeWithoutSeeingPermit {
    /// Commitment of the sealed object holding the dataset (`object_commitment`).
    pub sealed_object: ObjectKey,
    /// Committed plaintext root of the sealed dataset.
    pub plaintext_root: [u8; 32],
    /// Key commitment authorizing operator-scoped decryption / field key access.
    pub key_commitment: [u8; 32],
    /// Registered AI model authorized by the dataset owner.
    pub model_id: AiModelId,
    /// STARK-backed consent proof over `blind_compute_scope_tag(model_id, input_commitment)`.
    pub consent_proof: ConsentProof,
}

/// Complete confidential inference package pairing dataset manifest, blind-compute
/// permit, inference request/result, and BudZero STARK execution proof.
#[derive(Debug, Clone)]
pub struct ComputeWithoutSeeingBundle {
    /// Sealed object manifest committing to ciphertext, plaintext, and key.
    pub manifest: SealedObjectManifest,
    /// Authorization permit and STARK consent proof from the data owner.
    pub permit: ComputeWithoutSeeingPermit,
    /// Inference request bound to the approved `model_id` and `input_commitment`.
    pub request: AiInferenceRequest,
    /// Output commitment returned by the compute operator.
    pub result: AiInferenceResult,
    /// BudZero Plonky3 execution proof over the guest forward pass.
    pub proof: AiExecutionProof,
}

/// Reserved blind-inference verification boundary. It refuses while the
/// proof-required AI gate is closed; even after opening, a caller must supply
/// a STARK program/public-input pair and verify the full proof. Structural
/// checks alone are never sufficient to authorize access to sealed data.
///
/// # Errors
///
/// Returns a descriptive failure if proof verification is gated or missing,
/// consent is revoked/invalid, the scope is wrong, or the STARK is invalid.
pub fn verify_compute_without_seeing(
    bundle: &ComputeWithoutSeeingBundle,
    deletion_set: &DeletionSet,
    model: &AiModelSpec,
    program_and_pi: Option<(&[u64], &ExecutionPublicInputs)>,
    current_epoch: u64,
) -> Result<ExecutionVerifyReport, String> {
    if !crate::ai::FULL_AI_STARK_VERIFICATION_LIVE {
        return Err("ComputeWithoutSeeing is closed until the AI proof opening gates pass".into());
    }
    let program_and_pi = program_and_pi
        .ok_or("ComputeWithoutSeeing requires a full STARK program and public inputs")?;
    if bundle.request.input_commitment
        != crate::ai::types::canonical_input_commitment(bundle.request.input_ref.as_slice())
        || bundle.result.output_commitment
            != crate::ai::types::canonical_output_commitment(bundle.result.output_ref.as_slice())
    {
        return Err("ComputeWithoutSeeing request/result payload commitment mismatch".into());
    }
    if bundle.manifest.object_commitment != bundle.permit.sealed_object
        || bundle.manifest.plaintext_root != bundle.permit.plaintext_root
        || bundle.manifest.key_commitment != bundle.permit.key_commitment
    {
        return Err("ComputeWithoutSeeing manifest mismatch".into());
    }
    if bundle.request.model_id != bundle.permit.model_id
        || bundle.request.model_id != model.model_id
    {
        return Err("ComputeWithoutSeeing model mismatch".into());
    }
    let expected_scope =
        blind_compute_scope_tag(&bundle.request.model_id, &bundle.request.input_commitment);
    if bundle.permit.consent_proof.scope_tag != expected_scope {
        return Err("ComputeWithoutSeeing scope_tag does not bind request input".into());
    }
    bundle
        .permit
        .consent_proof
        .verify(
            deletion_set,
            &bundle.manifest.object_commitment,
            &bundle.manifest.plaintext_root,
            current_epoch,
        )
        .map_err(|err| format!("ComputeWithoutSeeing consent denied: {err:?}"))?;

    let report = verify_execution_proof_full(
        &bundle.proof,
        &bundle.request,
        &bundle.result,
        Some(model),
        Some(program_and_pi),
    );
    if !report.is_fully_valid() {
        return Err(format!(
            "ComputeWithoutSeeing full execution STARK verification failed: {:?}",
            report.stark_error
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::execution::{
        encode_input_limbs, encode_output_limbs, guest_program_for_model, matmul_program_hash,
        prove_mlp_inference, verify_execution_proof_structural_with_model, weights_digest,
        FixedPointMlpSpec,
    };
    use crate::ai::types::{
        canonical_output_commitment, AiModelId, AiModelSpec, AiRequestId, BoundedBytes,
    };
    use crate::core::address::Address;
    use crate::core::hash::hash_fields_bytes;
    use crate::storage::bud3::content_id::ContentKey;
    use crate::storage::bud3::seal::{
        seal_object_with_profile, CipherProfile, ObjectVisibility, SealBud3Error, SEAL_SALT_LEN,
    };
    use bud_proof::predicates::{prove_predicate, PredicateKind, PredicateStatement};

    #[test]
    fn compute_without_seeing_refuses_unbound_consent_even_with_valid_unrelated_stark() {
        let mlp = FixedPointMlpSpec {
            dims: vec![2, 2, 1],
            weights: vec![1, -1, -1, 1, 1, 1],
            biases: vec![0, 0, 0],
        };
        let private_input = vec![5i32, 10i32];
        let raw_dataset = b"sealed medical features [5, 10]";
        let owner_key = ContentKey([0x24u8; 32]);
        let owner_secret = [0x91u8; 32];

        let (_sealed_obj, manifest) = seal_object_with_profile(
            raw_dataset,
            &owner_key,
            &owner_secret,
            ObjectVisibility::Consented,
            CipherProfile::FieldNative,
            [0x55u8; SEAL_SALT_LEN],
        )
        .expect("sealing succeeds");

        let requester = Address::from([0x10u8; 32]);
        let model_id = AiModelId::of(&requester, &[0x77u8; 32], 1);
        let (proof, output) =
            prove_mlp_inference(&mlp, model_id, &private_input, 5_000_000).expect("prove MLP");

        let model = AiModelSpec {
            model_id,
            model_hash: [0x77u8; 32],
            owner: requester,
            min_verifier_count: 1,
            agreement_threshold: 1,
            max_input_ref_bytes: 1024,
            max_output_ref_bytes: 1024,
            request_deadline_blocks: 10,
            result_deadline_blocks: 10,
            version: 1,
            active: true,
            require_execution_proof: true,
            execution_program_hash: Some(matmul_program_hash(&mlp).unwrap()),
            execution_class: 1,
            execution_weights_digest: Some(weights_digest(&mlp)),
            execution_dims: Some(mlp.dims.clone()),
            modalities: crate::ai_inference::perception::ModalitySet::text_only(),
        };

        let input_ref = encode_input_limbs(&private_input);
        let req = AiInferenceRequest {
            request_id: AiRequestId([0x31u8; 32]),
            requester,
            model_id,
            input_commitment: crate::ai::types::canonical_input_commitment(&input_ref),
            input_ref: BoundedBytes::try_new(input_ref).unwrap(),
            max_fee: 0,
            callback: None,
            submitted_at_block: 0,
            deadline_block: 10,
            effort: crate::ai_inference::effort::EffortTier::default(),
            perception: None,
        };
        let res = AiInferenceResult {
            request_id: req.request_id,
            verifier: requester,
            output_commitment: proof.output_commitment,
            output_ref: BoundedBytes::try_new(encode_output_limbs(&output)).unwrap(),
            result_nonce: 1,
            signature: vec![],
            submitted_at_block: 1,
        };

        let scope = blind_compute_scope_tag(&model_id, &req.input_commitment);
        let grant_tag = hash_fields_bytes(&[b"BDLM_BUD3_GRANT_V1", &manifest.object_commitment]);
        let testnet_chain = crate::core::chain_config::Network::Testnet
            .chain_id()
            .value();
        assert_eq!(
            ConsentProof::issue(
                &manifest,
                grant_tag,
                *requester.as_bytes(),
                scope,
                testnet_chain,
                2_000,
            )
            .unwrap_err(),
            SealBud3Error::ConsentDenied,
            "an unsigned owner claim must not mint blind-compute consent"
        );
        let unrelated = prove_predicate(&PredicateStatement {
            kind: PredicateKind::Yk6ThresholdQuorum,
            lhs: 4,
            rhs: 4,
            aux: 1,
            chain_id: testnet_chain,
        })
        .expect("independent quorum STARK");
        let consent = ConsentProof {
            grant_tag,
            object_commitment: manifest.object_commitment,
            plaintext_root: manifest.plaintext_root,
            key_commitment: manifest.key_commitment,
            grantee_commitment: *requester.as_bytes(),
            scope_tag: scope,
            chain_id: testnet_chain,
            expires_at_epoch: 2_000,
            predicate_proof: unrelated,
        };

        let bundle = ComputeWithoutSeeingBundle {
            manifest: manifest.clone(),
            permit: ComputeWithoutSeeingPermit {
                sealed_object: manifest.object_commitment,
                plaintext_root: manifest.plaintext_root,
                key_commitment: manifest.key_commitment,
                model_id,
                consent_proof: consent,
            },
            request: req,
            result: res,
            proof: proof.clone(),
        };

        let program = guest_program_for_model(&model).expect("guest program");
        let pi = proof
            .public_inputs
            .as_ref()
            .expect("public inputs")
            .to_execution_inputs();
        let mut deletions = DeletionSet::default();
        assert_eq!(bundle.request.input_commitment, proof.input_commitment);
        assert_eq!(bundle.result.output_commitment, proof.output_commitment);
        let structural = verify_execution_proof_structural_with_model(
            &proof,
            &bundle.request,
            &bundle.result,
            Some(&model),
        );
        assert!(structural.is_structurally_valid());
        // Structural consistency does not prove the sealed input or owner
        // authorization. An unrelated *valid* STARK cannot open this door.
        assert_eq!(
            bundle.permit.consent_proof.verify(
                &deletions,
                &manifest.object_commitment,
                &manifest.plaintext_root,
                1_000,
            ),
            Err(SealBud3Error::ConsentDenied)
        );
        for inputs in [Some((program.as_slice(), &pi)), None] {
            let err = verify_compute_without_seeing(&bundle, &deletions, &model, inputs, 1_000)
                .expect_err("gated blind compute must not authorize access");
            assert!(err.contains("closed"), "{err}");
        }

        let mut bad_output = bundle.clone();
        bad_output.result.output_commitment = canonical_output_commitment(&[99u8; 8]);
        assert!(
            !verify_execution_proof_structural_with_model(
                &proof,
                &bad_output.request,
                &bad_output.result,
                Some(&model),
            )
            .commitments_ok
        );
        deletions.tombstone_grant(grant_tag);
        assert!(deletions.is_revoked(&grant_tag, &manifest.object_commitment));
        assert!(verify_compute_without_seeing(
            &bundle,
            &deletions,
            &model,
            Some((&program, &pi)),
            1_000,
        )
        .is_err());
    }
}
