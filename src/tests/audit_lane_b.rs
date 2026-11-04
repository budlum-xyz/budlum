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

/// BLG-062: registry leaves commit to behaviour-controlling spec fields and
/// the QoS running average cannot overflow.
#[test]
fn audit_lane_b_blg_062_registry_leaves_commit_spec_fields_and_qos_is_overflow_safe() {
    let owner = Address::from([0x62; 32]);
    let base = lane_b_model(owner);
    let base_leaf = base.calculate_leaf();

    let mut dims = base.clone();
    dims.execution_dims = Some(vec![2, 1]);
    assert_ne!(base_leaf, dims.calculate_leaf(), "execution_dims must be committed");
    let mut dims_longer = dims.clone();
    dims_longer.execution_dims = Some(vec![2, 1, 1]);
    assert_ne!(dims.calculate_leaf(), dims_longer.calculate_leaf());

    let mut modalities = base.clone();
    modalities.modalities = crate::ai_inference::perception::ModalitySet::text_only()
        .with_modality(crate::ai_inference::perception::PerceptionKind::Image);
    assert_ne!(base_leaf, modalities.calculate_leaf(), "modalities must be committed");

    let mut weights_a = base.clone();
    weights_a.execution_weights_digest = Some([1u8; 32]);
    let mut weights_b = base.clone();
    weights_b.execution_weights_digest = Some([2u8; 32]);
    assert_ne!(base_leaf, weights_a.calculate_leaf());
    assert_ne!(weights_a.calculate_leaf(), weights_b.calculate_leaf());

    let mut qos = AiVerifierQos::new(owner);
    qos.avg_response_blocks = u64::MAX;
    qos.total_results_submitted = u64::MAX - 1;
    qos.record_result(u64::MAX, 7);
    assert_eq!(qos.avg_response_blocks, u64::MAX);
}

/// BLG-059: a proof is bound to request/result commitments, the registered
/// program hash and the registered weights digest.
#[test]
fn audit_lane_b_blg_059_execution_proof_binds_commitments_and_weights() {
    let owner = Address::from([0x59; 32]);
    let mut spec = lane_b_model(owner);
    spec.execution_program_hash = Some([5u8; 32]);
    spec.execution_weights_digest = Some([7u8; 32]);
    let request = lane_b_request(owner, spec.model_id);
    let result = lane_b_result(&request, owner);
    let mut proof = AiExecutionProof {
        model_id: spec.model_id,
        input_commitment: request.input_commitment,
        output_commitment: result.output_commitment,
        program_hash: [5u8; 32],
        proof_bytes: vec![1, 2, 3],
        steps: 1,
        gas_used: 1,
        weights_digest: Some([7u8; 32]),
        public_inputs: None,
    };
    let check = |p: &AiExecutionProof| {
        crate::ai::execution::verify_execution_proof_structural_with_model(
            p,
            &request,
            &result,
            Some(&spec),
        )
    };
    assert!(check(&proof).is_structurally_valid());

    proof.weights_digest = Some([8u8; 32]);
    let wrong_weights = check(&proof);
    assert!(!wrong_weights.weights_bound && !wrong_weights.is_structurally_valid());

    proof.weights_digest = Some([7u8; 32]);
    proof.output_commitment = [0xEE; 32];
    let wrong_output = check(&proof);
    assert!(!wrong_output.commitments_ok && !wrong_output.is_structurally_valid());

    proof.output_commitment = result.output_commitment;
    proof.program_hash = [6u8; 32];
    assert!(!check(&proof).program_hash_matches_model);
}

/// BLG-060: `AiFeeReclaim` checks the requester before marking the fee
/// reclaimed, so a stranger cannot lock the real requester out.
#[test]
fn audit_lane_b_blg_060_fee_reclaim_by_stranger_leaves_no_mark() {
    let mut state = AccountState::new();
    let requester = Address::from([0x60; 32]);
    let stranger = Address::from([0x61; 32]);
    let spec = lane_b_model(requester);
    let request = lane_b_request(requester, spec.model_id);
    state.ai_registry.register_model(spec).expect("model");
    state.ai_registry.submit_request(request.clone(), 0).expect("request");
    state.current_block_height = 10_000;
    state.add_balance(&stranger, 10);
    state.add_balance(&requester, 10);
    let reclaim = |from: Address| {
        Transaction::new_with_chain_id(
            from,
            Address::zero(),
            0,
            1,
            0,
            vec![],
            DEFAULT_CHAIN_ID,
            TransactionType::AiFeeReclaim(request.request_id),
        )
    };
    let err = Executor::apply_transaction_checked(&mut state, &reclaim(stranger))
        .expect_err("a stranger must not reclaim");
    assert_eq!(err.code(), "ai_fee_reclaim_unauthorized");
    assert!(!state.ai_registry.reclaimed_fees.contains(&request.request_id));
    Executor::apply_transaction_checked(&mut state, &reclaim(requester)).expect("requester");
    assert!(state.ai_registry.reclaimed_fees.contains(&request.request_id));
}

/// BLG-060: a proof attached after cancellation cannot reopen the request.
#[test]
fn audit_lane_b_blg_060_attach_after_cancel_is_refused() {
    let mut state = AccountState::new();
    let requester = Address::from([0x62; 32]);
    let spec = lane_b_model(requester);
    let request = lane_b_request(requester, spec.model_id);
    state.ai_registry.register_model(spec.clone()).expect("model");
    state.ai_registry.submit_request(request.clone(), 0).expect("request");
    state
        .ai_registry
        .cancel_request(&request.request_id, &requester, 0)
        .expect("cancel");
    let proof = AiExecutionProof {
        model_id: spec.model_id,
        input_commitment: request.input_commitment,
        output_commitment: [0u8; 32],
        program_hash: [5u8; 32],
        proof_bytes: vec![1],
        steps: 1,
        gas_used: 1,
        weights_digest: None,
        public_inputs: None,
    };
    let err = state
        .ai_registry
        .attach_execution_proof(&request.request_id, &requester, proof, false)
        .expect_err("attach after cancel");
    assert!(err.contains("cancelled"), "{err}");
}

/// BLG-110 (fixed part): `BnsRegistry::default()` has the same non-zero base
/// cost as `new()`, and an expiry overflow is an error, not an abort.
#[test]
fn audit_lane_b_blg_110_bns_default_cost_and_expiry_overflow_are_safe() {
    use crate::bns::registry::BnsRegistry;
    let default_registry = BnsRegistry::default();
    assert_eq!(default_registry.base_cost, BnsRegistry::new().base_cost);
    assert_ne!(default_registry.base_cost, 0);
    let mut registry = BnsRegistry::new();
    let owner = Address::from([0x10; 32]);
    assert!(registry.register("alice".into(), owner, 1, u64::MAX).is_err());
}

/// BLG-126 (fixed part): admission refuses a request without a perception
/// declaration and one whose declaration names another asset than the Pollen
/// reference; a result must commit canonically to its output bytes.
#[test]
fn audit_lane_b_blg_126_admission_requires_matching_perception() {
    let mut registry = crate::ai::AiRegistry::new();
    let owner = Address::from([0x26; 32]);
    let spec = lane_b_model(owner);
    registry.register_model(spec.clone()).expect("model");

    let mut without = lane_b_request(owner, spec.model_id);
    without.perception = None;
    assert!(crate::ai_inference::admit_inference_request(&registry, &without).is_err());

    let reference = crate::pollen::AiDataInputRef {
        asset_id: crate::pollen::AssetId([0x01; 32]),
        grant_id: crate::pollen::GrantId::from([0x02; 32]),
    }
    .encode();
    let mut mismatched = lane_b_request(owner, spec.model_id);
    mismatched.input_commitment = crate::ai::types::canonical_input_commitment(&reference);
    mismatched.input_ref = BoundedBytes::try_new(reference).expect("bounded");
    assert!(crate::ai_inference::admit_inference_request(&registry, &mismatched).is_err());

    let request = lane_b_request(owner, spec.model_id);
    registry
        .lock_verifier_stake(&owner, crate::ai::registry::MIN_VERIFIER_STAKE)
        .expect("stake");
    registry.submit_request(request.clone(), 0).expect("request");
    let mut bad = lane_b_result(&request, owner);
    bad.output_ref = BoundedBytes::try_new(b"real bytes".to_vec()).expect("bounded");
    let err = registry.submit_result(bad, 0).expect_err("non-canonical commitment");
    assert!(err.contains("does not commit to output_ref"), "{err}");
}

/// BLG-025: the quantum-account registry refuses duplicate guardian keys and a
/// `guardian_root` that does not match the guardian list.
#[test]
fn audit_lane_b_blg_025_registry_refuses_duplicate_guardians_and_bad_root() {
    use crate::account_abstraction::quantum_account::QuantumAccount;
    use crate::account_abstraction::{QuantumAccountRegistry, QuantumAccountRegistryError};
    use crate::crypto::primitives::ML_DSA_87_PUBLIC_KEY_LEN;

    let mut pq = [0u8; ML_DSA_87_PUBLIC_KEY_LEN];
    pq[0] = 1;
    let mut other = [0u8; ML_DSA_87_PUBLIC_KEY_LEN];
    other[0] = 2;
    let build = |guardians: Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]>| QuantumAccount {
        address: QuantumAccount::address_from_public_key(&pq),
        pq_public_key: pq,
        storage_root: [0u8; 32],
        pact_root: [0u8; 32],
        guardian_root: QuantumAccount::guardian_root(&guardians),
        guardians,
        multisig_threshold: 2,
        recovery_threshold: 2,
        timelock_blocks: 0,
        nonce: 0,
        balance: 0,
        storage_bytes: 0,
    };
    let mut registry = QuantumAccountRegistry::new();
    assert!(matches!(
        registry.register(build(vec![pq, pq, other])),
        Err(QuantumAccountRegistryError::InvalidAccount { .. })
    ));
    let mut bad_root = build(vec![pq, other]);
    bad_root.guardian_root[0] ^= 0xFF;
    assert!(matches!(
        registry.register(bad_root),
        Err(QuantumAccountRegistryError::InvalidAccount { .. })
    ));
    registry.register(build(vec![pq, other])).expect("a clean account registers");
}

/// BLG-215: a QR video decodes back to the object (the old ledger said there
/// was no extraction path).
#[test]
fn audit_lane_b_blg_215_qr_video_decodes_back_to_the_object() {
    use crate::storage::qr_payload::PayloadKind;
    let content = b"lane-b-round-trip-object".repeat(10);
    let enc = crate::storage::three_pipe::encode_qr_video(&content, 64, None).expect("encode");
    assert!(enc.video_blob.starts_with(b"BDLV"));
    let (kind, raw, _video) =
        crate::storage::three_pipe::decode_qr_video(&enc.video_blob).expect("decode");
    assert_eq!(kind, PayloadKind::ContentBytes);
    assert_eq!(raw, content);
}

/// BLG-048: a recipe over an entropy-class body re-emits the exact video.
#[test]
fn audit_lane_b_blg_048_recipe_reemits_entropy_class_body_bit_equal() {
    use crate::storage::qr_video::DEFAULT_FPS;
    use crate::storage::three_pipe::{encode_qr_video, PIPE_DEFAULT_BLOCK_LEN};
    use crate::storage::three_recipe::{RecipeTransform, VideoRecipe};
    use crate::storage::transformed::TransformOpts;
    let mut content = vec![0xff, 0xd8, 0xff, 0xe0];
    content.extend_from_slice(&[0xabu8; 4096]);
    let produced = encode_qr_video(&content, PIPE_DEFAULT_BLOCK_LEN, None).expect("video");
    let recipe = VideoRecipe::from_encoded(
        &content,
        RecipeTransform::pin_from(TransformOpts::default(), &content),
        1,
        PIPE_DEFAULT_BLOCK_LEN,
        crate::storage::qr_carousel::ONESHOT_REPAIR_PERMILLAGE,
        DEFAULT_FPS,
        &produced,
    );
    let again = recipe.reemit(&content).expect("re-emit");
    assert_eq!(again.video_blob, produced.video_blob);
}

/// BLG-137: the stream check uses the full 32-byte commitment.
#[test]
fn audit_lane_b_blg_137_stream_commitment_is_full_width() {
    use crate::storage::three_pipe::{decode_frames, encode_qr_video};
    let enc = encode_qr_video(b"lane-b-stream-commitment".repeat(8).as_slice(), 64, None)
        .expect("video");
    let frames = &enc.pipe.frames;
    assert!(decode_frames(&enc.pipe.stream_commitment, frames).is_ok());
    let mut wrong = enc.pipe.stream_commitment;
    wrong[31] ^= 1;
    assert!(decode_frames(&wrong, frames).is_err());
}

