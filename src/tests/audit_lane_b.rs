//! Lane B live-verification regression tests (WP-01 to WP-04).
//!
//! Only "previously fixed" findings live here: each test is green and stays
//! permanent (directive section 14.1 rule 7). Repro tests for findings that are
//! still open live on the `audit/repro-b` branch and do not merge.

use crate::ai::types::{
    AiExecutionProof, AiInferenceRequest, AiInferenceResult, AiModelId, AiModelSpec, AiRequestId,
    AiVerifierQos, BoundedBytes,
};
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::execution::executor::Executor;

fn lane_b_model(owner: Address) -> AiModelSpec {
    let model_hash = [0xB1; 32];
    AiModelSpec {
        model_id: AiModelId::of(&owner, &model_hash, 1),
        model_hash,
        owner,
        min_verifier_count: 1,
        agreement_threshold: 1,
        max_input_ref_bytes: 1_024,
        max_output_ref_bytes: 1_024,
        request_deadline_blocks: 100,
        result_deadline_blocks: 100,
        version: 1,
        active: true,
        require_execution_proof: false,
        execution_program_hash: None,
        execution_class: 0,
        execution_dims: None,
        execution_weights_digest: None,
        modalities: crate::ai_inference::perception::ModalitySet::text_only(),
    }
}

fn lane_b_request(requester: Address, model_id: AiModelId) -> AiInferenceRequest {
    let mut request = AiInferenceRequest {
        request_id: AiRequestId::default(),
        requester,
        model_id,
        input_commitment: crate::ai::types::canonical_input_commitment(&[]),
        input_ref: BoundedBytes::empty(),
        max_fee: 100,
        callback: None,
        submitted_at_block: 0,
        deadline_block: 100,
        effort: crate::ai_inference::effort::EffortTier::default(),
        perception: Some(crate::ai_inference::perception::PerceptionRequest {
            asset_id: crate::pollen::AssetId([0xAB; 32]),
            content_id: crate::storage::content_id::ContentId([0xBC; 32]),
            kind: crate::ai_inference::perception::PerceptionKind::Text,
            declared_units: 100,
        }),
    };
    request.request_id = request.calculate_id();
    request
}

fn lane_b_result(request: &AiInferenceRequest, verifier: Address) -> AiInferenceResult {
    AiInferenceResult {
        request_id: request.request_id,
        verifier,
        output_commitment: crate::ai::types::canonical_output_commitment(&[]),
        output_ref: BoundedBytes::empty(),
        result_nonce: 1,
        signature: vec![1],
        submitted_at_block: 0,
    }
}

/// BLG-106: an oversize `execution_dims` vector is refused before any buffer
/// sized from it exists.
#[test]
fn audit_lane_b_blg_106_oversize_execution_dims_refused_without_allocating() {
    let owner = Address::from([0x61; 32]);
    let mut spec = lane_b_model(owner);
    spec.execution_dims = Some(vec![1u16; 33]);
    assert!(spec.validate().is_err(), "more than 32 layers must be refused");
    spec.execution_dims = Some(vec![4, 0, 4]);
    assert!(spec.validate().is_err(), "zero-width layer must be refused");
    spec.execution_dims = Some(vec![u16::MAX; 5]);
    assert!(crate::ai::execution::guest_program_for_model(&spec).is_err());
    spec.execution_dims = Some(vec![4]);
    assert!(spec.validate().is_err());
}

