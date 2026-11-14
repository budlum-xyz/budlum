//! WIRING: unwired - this IP-60 T-Expansion proof path waits for IP-56 and activation after M7.
//!
//! Confidential Data Market computation (`ComputeWithoutSeeing`, IP-60 step 8).
//!
//! Combines a sealed B.U.D. 3.0 object manifest (`CipherProfile::Aead` or
//! `CipherProfile::FieldNative`), a zero-knowledge [`ConsentProof`] bound to a
//! `DeletionSet` tombstone check, and full Plonky3 STARK verification of the
//! AI execution proof without ever exposing the sealed dataset plaintext.

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

/// Verify consent, `DeletionSet` non-revocation, sealed-object manifest binding,
/// model/input commitments, and the full Plonky3 STARK proof for blind inference.
///
/// # Errors
///
/// Returns a descriptive failure string if the permit does not match the
/// manifest, the `ConsentProof` is revoked/expired/invalid, the request does
/// not match the permitted scope, or STARK verification fails.
pub fn verify_compute_without_seeing(
    bundle: &ComputeWithoutSeeingBundle,
    deletion_set: &DeletionSet,
    model: &AiModelSpec,
    program_and_pi: Option<(&[u64], &ExecutionPublicInputs)>,
    current_epoch: u64,
) -> Result<ExecutionVerifyReport, String> {
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
        program_and_pi,
    );
    if !report.is_structurally_valid() || report.stark_ok == Some(false) {
        return Err(format!(
            "ComputeWithoutSeeing execution verification failed: {:?}",
            report.stark_error
        ));
    }
    if program_and_pi.is_some() && !report.is_fully_valid() {
        return Err("ComputeWithoutSeeing STARK did not verify cleanly".into());
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::execution::{
        guest_program_for_model, input_commitment, matmul_program_hash, prove_mlp_inference,
        weights_digest, FixedPointMlpSpec,
    };
    use crate::ai::types::{
        canonical_output_commitment, AiModelId, AiModelSpec, AiRequestId, BoundedBytes,
    };
    use crate::core::address::Address;
    use crate::core::hash::hash_fields_bytes;
    use crate::storage::bud3::content_id::ContentKey;
    use crate::storage::bud3::seal::{
        seal_object_with_profile, CipherProfile, ObjectVisibility, SEAL_SALT_LEN,
    };

    #[test]
    fn compute_without_seeing_verifies_field_native_consent_and_stark_and_blocks_revoked() {
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
        let (proof, _output) =
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

        let req = AiInferenceRequest {
            request_id: AiRequestId([0x31u8; 32]),
            requester,
            model_id,
            input_commitment: input_commitment(&private_input),
            input_ref: BoundedBytes::empty(),
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
            output_ref: BoundedBytes::empty(),
            result_nonce: 1,
            signature: vec![],
            submitted_at_block: 1,
        };

        let scope = blind_compute_scope_tag(&model_id, &req.input_commitment);
        let grant_tag = hash_fields_bytes(&[b"BDLM_BUD3_GRANT_V1", &manifest.object_commitment]);
        let testnet_chain = crate::core::chain_config::Network::Testnet
            .chain_id()
            .value();
        let consent = ConsentProof::issue(
            &manifest,
            grant_tag,
            *requester.as_bytes(),
            scope,
            testnet_chain,
            2_000,
        )
        .expect("consent proof");

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

        let report = verify_compute_without_seeing(
            &bundle,
            &deletions,
            &model,
            Some((&program, &pi)),
            1_000,
        )
        .expect("valid ComputeWithoutSeeing bundle verifies end-to-end");
        assert!(report.is_fully_valid());

        // Tampering output commitment fails verification.
        let mut bad_output = bundle.clone();
        bad_output.result.output_commitment = canonical_output_commitment(&[99u8; 8]);
        assert!(verify_compute_without_seeing(
            &bad_output,
            &deletions,
            &model,
            Some((&program, &pi)),
            1_000,
        )
        .is_err());

        // Revoking the grant in DeletionSet fails closed.
        deletions.tombstone_grant(grant_tag);
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
