//! Runtime - the Lubot inference flow (over the real `AiRegistry`).
//!
//! The end-to-end flow of a Lubot query through the real budlum-core AI layer:
//! model registration -> operator compute bond -> building the request with a
//! closed-circuit input_ref (canonical request_id) -> `submit_request` ->
//! `AiInferenceResult` -> `submit_result`.
//! No mocks; real types and real registry methods.

use crate::ai::types::{
    AiInferenceRequest, AiInferenceResult, AiModelId, AiModelSpec, AiRequestId, BoundedBytes,
};
use crate::ai::AiRegistry;
use crate::core::address::Address;
use crate::pollen::data_rights::AccessGrant;
use sha2::{Digest, Sha256};

/// Register a Lubot model on chain (AiModelSpec + register_model).
pub fn register_lubot_model(
    registry: &mut AiRegistry,
    owner: Address,
    model_hash: [u8; 32],
) -> Result<AiModelId, String> {
    let spec = AiModelSpec {
        model_id: AiModelId(model_hash),
        model_hash,
        owner,
        min_verifier_count: 1,
        agreement_threshold: 1,
        max_input_ref_bytes: 1024,
        max_output_ref_bytes: 1024,
        request_deadline_blocks: 1000,
        result_deadline_blocks: 1000,
        version: 1,
        active: true,
        require_execution_proof: false,
        execution_program_hash: None,
        execution_class: 0,
        execution_dims: None,
        execution_weights_digest: None,
        modalities: crate::lubot::perception::ModalitySet::text_only(),
    };
    registry.register_model(spec)
}

/// Build a closed-circuit Lubot inference request (with a canonical request_id).
///
/// `input_ref` = the reference to the data used (an AiDataInputRef encoding or
/// an opaque value).
///
/// `grant` = the requester's authority to read that data. It is a mandatory
/// argument, because letting an unauthorized inference request be built at all
/// - even if it is rejected later - turns the authority from an admission
/// condition into a check that depends on the next layer remembering it. This
/// file's own comment used to say verification was "done separately", while
/// [`crate::lubot::validate_inference_grant`] was called from nowhere in
/// production; that was the gap between what was said and what was done.
///
/// # Errors
///
/// A message naming the condition that failed if the authority is not valid, or
/// the rejection from `BoundedBytes` if `input_ref` exceeds the bound.
#[allow(clippy::too_many_arguments)]
pub fn build_lubot_request(
    requester: Address,
    model_id: AiModelId,
    input_ref: Vec<u8>,
    max_fee: u64,
    submitted_at_block: u64,
    deadline_block: u64,
    grant: &AccessGrant,
    perception: Option<crate::lubot::perception::PerceptionRequest>,
) -> Result<AiInferenceRequest, String> {
    // Authority first. Even before the bound check, because someone without
    // permission learning why their request was rejected must not reveal
    // information about the shape of the request.
    crate::lubot::validate_inference_grant(grant, &requester, submitted_at_block)?;
    let bounded = BoundedBytes::try_new(input_ref.clone())?;
    // The canonical commitment: the admission gate verifies with the same
    // function (see crate::ai::types::canonical_input_commitment).
    let input_commitment = crate::ai::types::canonical_input_commitment(&input_ref);
    let mut req = AiInferenceRequest {
        request_id: AiRequestId([0; 32]),
        requester,
        model_id,
        input_commitment,
        input_ref: bounded,
        max_fee,
        callback: None,
        submitted_at_block,
        deadline_block,
        effort: crate::lubot::effort::EffortTier::default(),
        perception,
    };
    // Compute the canonical request_id -> verify_id passes.
    req.request_id = req.calculate_id();
    Ok(req)
}

/// Build a Lubot inference result (the operator's answer).
pub fn build_lubot_result(
    request_id: AiRequestId,
    verifier: Address,
    output: Vec<u8>,
    nonce: u64,
    submitted_at_block: u64,
) -> Result<AiInferenceResult, String> {
    let output_ref = BoundedBytes::try_new(output.clone())?;
    let mut hasher = Sha256::new();
    hasher.update(b"LUBOT_OUTPUT_COMMIT_V1");
    hasher.update(&output);
    let output_commitment: [u8; 32] = hasher.finalize().into();
    Ok(AiInferenceResult {
        request_id,
        verifier,
        output_commitment,
        output_ref,
        result_nonce: nonce,
        signature: Vec::new(),
        submitted_at_block,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{operator_bond, operator_eligible, register_operator, MIN_OPERATOR_BOND};
    use super::*;

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    /// The end-to-end Lubot inference flow over the real AiRegistry.
    #[test]
    fn lubot_full_inference_flow_on_real_registry() {
        let mut registry = AiRegistry::new();
        let owner = addr(1);
        let operator = addr(2);
        let requester = addr(3);
        let model_hash = [9u8; 32];

        // (1) Register the model on chain.
        let model_id =
            register_lubot_model(&mut registry, owner, model_hash).expect("model register");

        // (2) Operator compute-bond (AI-layer-first).
        register_operator(&mut registry, &operator, MIN_OPERATOR_BOND).expect("operator bond");
        assert!(operator_eligible(&registry, &operator));
        assert_eq!(operator_bond(&registry, &operator), MIN_OPERATOR_BOND);

        // (3) Build the closed-circuit request and submit it.
        let grant = test_grant(requester, 1);
        let req = build_lubot_request(
            requester,
            model_id,
            b"lubot-input".to_vec(),
            1,
            1,
            1000,
            &grant,
            None,
        )
        .expect("build request");
        assert!(req.verify_id(), "canonical request_id must verify");
        // (after Strix #359 the verifier stake is mandatory)
        let _ = registry.lock_verifier_stake(&operator, crate::ai::registry::MIN_VERIFIER_STAKE);
        let req_id = registry.submit_request(req, 1).expect("submit request");

        // (4) Build the result and submit it.
        let res = build_lubot_result(req_id, operator, b"lubot-output".to_vec(), 1, 2)
            .expect("build result");
        let outcome = registry.submit_result(res, 2);
        assert!(
            outcome.is_ok(),
            "result submission should succeed: {outcome:?}"
        );
    }

    /// A grant that is live for `consumer` at `block`.
    fn test_grant(consumer: Address, block: u64) -> AccessGrant {
        AccessGrant::new_unsigned(
            crate::pollen::AssetId([9; 32]),
            Address([8; 32]),
            consumer,
            consumer,
            0,
            block,
            block + 10_000,
            100,
            [0; 32],
        )
    }

    /// A request cannot be built without a live grant.
    ///
    /// The refusal has to happen here rather than at the executor: an
    /// unauthorised request object that exists and looks valid until some
    /// later layer remembers to check it is a permission rule that depends on
    /// being remembered.
    #[test]
    fn a_request_without_a_live_grant_is_refused() {
        let requester = Address([1; 32]);
        let model_id = AiModelId([2; 32]);

        // Issued to somebody else.
        let other = test_grant(Address([7; 32]), 1);
        let err = build_lubot_request(
            requester,
            model_id,
            b"input".to_vec(),
            1,
            1,
            1000,
            &other,
            None,
        )
        .expect_err("a grant issued to another consumer must not build a request");
        assert!(err.contains("consumer"), "got: {err}");

        // Expired.
        let mut expired = test_grant(requester, 1);
        expired.expires_at_block = 5;
        let err = build_lubot_request(
            requester,
            model_id,
            b"input".to_vec(),
            1,
            50,
            1000,
            &expired,
            None,
        )
        .expect_err("an expired grant must not build a request");
        assert!(err.contains("expired"), "got: {err}");

        // Quota spent.
        let mut spent = test_grant(requester, 1);
        spent.reads_used = spent.max_reads;
        let err = build_lubot_request(
            requester,
            model_id,
            b"input".to_vec(),
            1,
            1,
            1000,
            &spent,
            None,
        )
        .expect_err("an exhausted grant must not build a request");
        assert!(err.contains("quota"), "got: {err}");

        // The canary: a live grant still builds, or the three refusals above
        // could be satisfied by a function that refuses everything.
        let live = test_grant(requester, 1);
        build_lubot_request(
            requester,
            model_id,
            b"input".to_vec(),
            1,
            1,
            1000,
            &live,
            None,
        )
        .expect("a live grant must still build a request");
    }
}
