//! Phase 10 (§1): AI Inference & Compute Layer.
//!
//! Provides deterministic model registration, request/result attestation tracking,
//! and threshold consensus finalization (`AiVerifier`).

pub mod registry;
pub mod types;

pub use registry::AiRegistry;
pub use types::{
    AiInferenceOutcome, AiInferenceRequest, AiInferenceResult, AiModelId, AiModelSpec, AiRequestId,
    AiResultId, BoundedBytes, MAX_INFERENCE_REF_BYTES,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;

    #[test]
    fn test_ai_model_registration_and_validation() {
        let mut registry = AiRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.state_root(), [0u8; 32]);

        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        let spec = AiModelSpec {
            model_id,
            model_hash: [1u8; 32],
            owner,
            min_verifier_count: 3,
            agreement_threshold: 2,
            max_input_ref_bytes: 1024,
            max_output_ref_bytes: 2048,
            request_deadline_blocks: 100,
            result_deadline_blocks: 50,
            version: 1,
            active: true,
        };

        assert!(registry.register_model(spec.clone()).is_ok());
        assert!(!registry.is_empty());
        assert_ne!(registry.state_root(), [0u8; 32]);
    }

    #[test]
    fn test_ai_inference_lifecycle_threshold_agreement() {
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        let spec = AiModelSpec {
            model_id,
            model_hash: [1u8; 32],
            owner,
            min_verifier_count: 3,
            agreement_threshold: 2,
            max_input_ref_bytes: 1024,
            max_output_ref_bytes: 2048,
            request_deadline_blocks: 100,
            result_deadline_blocks: 50,
            version: 1,
            active: true,
        };
        registry.register_model(spec).unwrap();

        let requester =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"prompt: hello ai".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();

        let req_id = registry.submit_request(req, 5).unwrap();

        // Submit first result from verifier 1
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let res1 = AiInferenceResult {
            request_id: req_id,
            verifier: v1,
            output_commitment: [9u8; 32],
            output_ref: BoundedBytes::try_new(b"response: hi".to_vec()).unwrap(),
            result_nonce: 1,
            signature: vec![1, 2, 3],
            submitted_at_block: 15,
        };
        let outcome1 = registry.submit_result(res1, 15).unwrap();
        assert!(outcome1.is_none()); // Threshold not reached yet (needs 2)

        // Submit second matching result from verifier 2
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();
        let res2 = AiInferenceResult {
            request_id: req_id,
            verifier: v2,
            output_commitment: [9u8; 32],
            output_ref: BoundedBytes::try_new(b"response: hi".to_vec()).unwrap(),
            result_nonce: 2,
            signature: vec![4, 5, 6],
            submitted_at_block: 16,
        };
        let outcome2 = registry.submit_result(res2, 16).unwrap();
        assert!(outcome2.is_some());
        let finalized = outcome2.unwrap();
        assert_eq!(finalized.agreeing_verifiers.len(), 2);
        assert_eq!(finalized.output_commitment, [9u8; 32]);
    }

    #[test]
    fn test_ai_soft_incentive_reward_distribution() {
        // Phase 10 §1: Soft incentive verifies majority gets max_fee share
        // and minority verifiers get zero reward without stake slashing.
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 3,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();
        let v_minority =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000013")
                .unwrap();

        // Minority verifier submits different commitment
        registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v_minority,
                    output_commitment: [88u8; 32],
                    output_ref: BoundedBytes::try_new(b"wrong".to_vec()).unwrap(),
                    result_nonce: 1,
                    signature: vec![1],
                    submitted_at_block: 15,
                },
                15,
            )
            .unwrap();

        // Majority verifiers submit consensus commitment
        registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v1,
                    output_commitment: [99u8; 32],
                    output_ref: BoundedBytes::try_new(b"correct".to_vec()).unwrap(),
                    result_nonce: 2,
                    signature: vec![2],
                    submitted_at_block: 16,
                },
                16,
            )
            .unwrap();

        let outcome = registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v2,
                    output_commitment: [99u8; 32],
                    output_ref: BoundedBytes::try_new(b"correct".to_vec()).unwrap(),
                    result_nonce: 3,
                    signature: vec![3],
                    submitted_at_block: 17,
                },
                17,
            )
            .unwrap();

        let finalized = outcome.expect("Should finalize after two matching results");
        assert_eq!(finalized.agreeing_verifiers, vec![v1, v2]);
        assert!(!finalized.agreeing_verifiers.contains(&v_minority));
    }

    // ===================== P5 — Deadline, Dispute, Robustness Tests =====================

    #[test]
    fn test_p5_request_deadline_rejected_after_expiry() {
        // P5 Bulgu 1: Request with deadline_block already passed must be rejected.
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();

        // current_block=200 > deadline_block=110 → MUST REJECT
        let result = registry.submit_request(req, 200);
        assert!(result.is_err(), "Request after deadline should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("deadline exceeded"),
            "Error should mention deadline: {err}"
        );
    }

    #[test]
    fn test_p5_result_deadline_rejected_after_expiry() {
        // P5 Bulgu 1: Result submitted after request or result deadline must be rejected.
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();

        // current_block=200 > deadline_block=110 → MUST REJECT
        let result = registry.submit_result(
            AiInferenceResult {
                request_id: req_id,
                verifier: v1,
                output_commitment: [9u8; 32],
                output_ref: BoundedBytes::try_new(b"result".to_vec()).unwrap(),
                result_nonce: 1,
                signature: vec![1],
                submitted_at_block: 200,
            },
            200,
        );
        assert!(result.is_err(), "Result after deadline should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("deadline"),
            "Error should mention deadline: {err}"
        );
    }

    #[test]
    fn test_p5_result_deadline_rejected_after_result_window() {
        // P5 Bulgu 1: Result submitted after result_deadline_blocks window.
        // submitted_at_block=10 + result_deadline_blocks=50 = result_deadline=60
        // current_block=70 > 60 → MUST REJECT (even though deadline_block=110 not yet reached)
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();

        // current_block=70 > submitted_at_block(10) + result_deadline_blocks(50) = 60
        let result = registry.submit_result(
            AiInferenceResult {
                request_id: req_id,
                verifier: v1,
                output_commitment: [9u8; 32],
                output_ref: BoundedBytes::try_new(b"result".to_vec()).unwrap(),
                result_nonce: 1,
                signature: vec![1],
                submitted_at_block: 70,
            },
            70,
        );
        assert!(
            result.is_err(),
            "Result after result_deadline_blocks window should be rejected"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("Result deadline"),
            "Error should mention Result deadline: {err}"
        );
    }

    #[test]
    fn test_p5_equivocation_detected() {
        // P5 Bulgu 3: Same verifier submitting conflicting commitments = equivocation.
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();

        // First result: commitment A
        registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v1,
                    output_commitment: [1u8; 32],
                    output_ref: BoundedBytes::try_new(b"a".to_vec()).unwrap(),
                    result_nonce: 1,
                    signature: vec![1],
                    submitted_at_block: 15,
                },
                15,
            )
            .unwrap();

        // Second result from SAME verifier: commitment B (DIFFERENT)
        let equiv = registry.submit_result(
            AiInferenceResult {
                request_id: req_id,
                verifier: v1,
                output_commitment: [2u8; 32],
                output_ref: BoundedBytes::try_new(b"b".to_vec()).unwrap(),
                result_nonce: 2,
                signature: vec![2],
                submitted_at_block: 16,
            },
            16,
        );
        assert!(equiv.is_err(), "Equivocation must be detected");
        let err = equiv.unwrap_err();
        assert!(
            err.contains("EQUIVOCATION"),
            "Error should mention EQUIVOCATION: {err}"
        );
    }

    #[test]
    fn test_p5_duplicate_same_commitment_rejected() {
        // Same verifier submitting same commitment = duplicate (not equivocation).
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();

        // First submission
        registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v1,
                    output_commitment: [9u8; 32],
                    output_ref: BoundedBytes::try_new(b"same".to_vec()).unwrap(),
                    result_nonce: 1,
                    signature: vec![1],
                    submitted_at_block: 15,
                },
                15,
            )
            .unwrap();

        // Duplicate same commitment
        let dup = registry.submit_result(
            AiInferenceResult {
                request_id: req_id,
                verifier: v1,
                output_commitment: [9u8; 32],
                output_ref: BoundedBytes::try_new(b"same".to_vec()).unwrap(),
                result_nonce: 2,
                signature: vec![2],
                submitted_at_block: 16,
            },
            16,
        );
        assert!(dup.is_err(), "Duplicate result should be rejected");
        let err = dup.unwrap_err();
        assert!(
            err.contains("already submitted"),
            "Error should mention already submitted: {err}"
        );
    }

    #[test]
    fn test_p5_request_accepted_before_deadline() {
        // Happy path: request accepted when current_block < deadline_block.
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 50,
            deadline_block: 150,
        };
        req.request_id = req.calculate_id();

        // current_block=100 < deadline_block=150 → ACCEPTED
        assert!(registry.submit_request(req, 100).is_ok());
    }

    // ===================== P5 — Fee Escrow + Nonce Tests =====================

    #[test]
    fn test_p5_fee_reclaim_after_deadline_no_outcome() {
        // P5 Bulgu 4: Requester can reclaim max_fee when request expires
        // without reaching agreement threshold.
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let requester =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 500,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        // Only one verifier submitted (below threshold of 2) — no finalization
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v1,
                    output_commitment: [9u8; 32],
                    output_ref: BoundedBytes::try_new(b"result".to_vec()).unwrap(),
                    result_nonce: 1,
                    signature: vec![1],
                    submitted_at_block: 15,
                },
                15,
            )
            .unwrap();

        // Deadline has passed (current_block=200 > deadline_block=110, result_deadline=60)
        let result = registry.reclaim_fee(&req_id, 200);
        assert!(
            result.is_ok(),
            "Should be able to reclaim fee after deadline"
        );
        let (reclaimed_requester, max_fee) = result.unwrap();
        assert_eq!(reclaimed_requester, requester);
        assert_eq!(max_fee, 500);
    }

    #[test]
    fn test_p5_fee_reclaim_rejected_before_deadline() {
        // Cannot reclaim fee before deadline expires.
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 500,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        // current_block=50 < deadline_block=110 → cannot reclaim yet
        let result = registry.reclaim_fee(&req_id, 50);
        assert!(result.is_err(), "Should not reclaim before deadline");
        let err = result.unwrap_err();
        assert!(
            err.contains("not yet expired"),
            "Error should mention not yet expired: {err}"
        );
    }

    #[test]
    fn test_p5_fee_reclaim_rejected_if_finalized() {
        // Cannot reclaim fee if request was already finalized (verifiers earned it).
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 500,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        // Both verifiers agree → finalization
        registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v1,
                    output_commitment: [9u8; 32],
                    output_ref: BoundedBytes::try_new(b"result".to_vec()).unwrap(),
                    result_nonce: 1,
                    signature: vec![1],
                    submitted_at_block: 15,
                },
                15,
            )
            .unwrap();
        registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v2,
                    output_commitment: [9u8; 32],
                    output_ref: BoundedBytes::try_new(b"result".to_vec()).unwrap(),
                    result_nonce: 2,
                    signature: vec![2],
                    submitted_at_block: 16,
                },
                16,
            )
            .unwrap();

        // Finalized → cannot reclaim even after deadline
        let result = registry.reclaim_fee(&req_id, 200);
        assert!(result.is_err(), "Should not reclaim finalized request");
        let err = result.unwrap_err();
        assert!(
            err.contains("finalized"),
            "Error should mention finalized: {err}"
        );
    }

    #[test]
    fn test_p5_fee_double_reclaim_prevented() {
        // Cannot reclaim fee twice for the same request.
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 500,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        // First reclaim succeeds
        let result1 = registry.reclaim_fee(&req_id, 200);
        assert!(result1.is_ok());

        // Second reclaim fails
        let result2 = registry.reclaim_fee(&req_id, 200);
        assert!(result2.is_err(), "Double reclaim should be prevented");
        let err = result2.unwrap_err();
        assert!(
            err.contains("already reclaimed"),
            "Error should mention already reclaimed: {err}"
        );
    }

    #[test]
    fn test_p5_result_nonce_zero_rejected() {
        // P5 Bulgu 5: result_nonce=0 must be rejected.
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();

        // result_nonce=0 → MUST REJECT
        let result = registry.submit_result(
            AiInferenceResult {
                request_id: req_id,
                verifier: v1,
                output_commitment: [9u8; 32],
                output_ref: BoundedBytes::try_new(b"result".to_vec()).unwrap(),
                result_nonce: 0,
                signature: vec![1],
                submitted_at_block: 15,
            },
            15,
        );
        assert!(result.is_err(), "result_nonce=0 should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("result_nonce must be >= 1"),
            "Error should mention result_nonce >= 1: {err}"
        );
    }

    #[test]
    fn test_p5_fee_reclaim_no_results_at_all() {
        // Request submitted but zero results → reclaim should work after deadline.
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 3,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 250,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        // No results at all, deadline passed → reclaim
        let result = registry.reclaim_fee(&req_id, 200);
        assert!(result.is_ok(), "Should reclaim when no results at all");
        let (_, max_fee) = result.unwrap();
        assert_eq!(max_fee, 250);
    }

    // ===================== P5 — Model Deactivation + Callback Tests =====================

    #[test]
    fn test_p5_model_deactivation_by_owner() {
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        assert!(registry.deactivate_model(&model_id, &owner).is_ok());
        assert!(!registry.models.get(&model_id).unwrap().active);

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let result = registry.submit_request(req, 5);
        assert!(
            result.is_err(),
            "Request to inactive model should be rejected"
        );
        assert!(result.unwrap_err().contains("inactive"));
    }

    #[test]
    fn test_p5_model_deactivation_non_owner_rejected() {
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let other =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let result = registry.deactivate_model(&model_id, &other);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("owner"));
    }

    #[test]
    fn test_p5_model_reactivation() {
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        registry.deactivate_model(&model_id, &owner).unwrap();
        assert!(!registry.models.get(&model_id).unwrap().active);

        registry.reactivate_model(&model_id, &owner).unwrap();
        assert!(registry.models.get(&model_id).unwrap().active);

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        assert!(registry.submit_request(req, 5).is_ok());
    }

    #[test]
    fn test_p5_callback_carried_to_outcome() {
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let callback_addr =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000099")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: Some(callback_addr),
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v1,
                    output_commitment: [9u8; 32],
                    output_ref: BoundedBytes::try_new(b"result".to_vec()).unwrap(),
                    result_nonce: 1,
                    signature: vec![1],
                    submitted_at_block: 15,
                },
                15,
            )
            .unwrap();
        let outcome = registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v2,
                    output_commitment: [9u8; 32],
                    output_ref: BoundedBytes::try_new(b"result".to_vec()).unwrap(),
                    result_nonce: 2,
                    signature: vec![2],
                    submitted_at_block: 16,
                },
                16,
            )
            .unwrap()
            .expect("Should finalize");

        assert_eq!(outcome.callback, Some(callback_addr));
        assert_eq!(
            registry.get_outcome(&req_id).unwrap().callback,
            Some(callback_addr)
        );
    }

    #[test]
    fn test_p5_callback_none_when_no_callback() {
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v1,
                    output_commitment: [9u8; 32],
                    output_ref: BoundedBytes::try_new(b"result".to_vec()).unwrap(),
                    result_nonce: 1,
                    signature: vec![1],
                    submitted_at_block: 15,
                },
                15,
            )
            .unwrap();
        let outcome = registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v2,
                    output_commitment: [9u8; 32],
                    output_ref: BoundedBytes::try_new(b"result".to_vec()).unwrap(),
                    result_nonce: 2,
                    signature: vec![2],
                    submitted_at_block: 16,
                },
                16,
            )
            .unwrap()
            .expect("Should finalize");

        assert_eq!(outcome.callback, None);
    }

    // ===================== P5 — Update, Transfer, Pruning, MinFee Tests =====================

    #[test]
    fn test_p5_update_model_spec_by_owner() {
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        registry
            .update_model_spec(
                &model_id, &owner, 5,    // min_verifier_count: 2 → 5
                3,    // agreement_threshold: 2 → 3
                2048, // max_input_ref_bytes
                4096, // max_output_ref_bytes
                200,  // request_deadline_blocks
                100,  // result_deadline_blocks
            )
            .unwrap();

        let spec = registry.models.get(&model_id).unwrap();
        assert_eq!(spec.min_verifier_count, 5);
        assert_eq!(spec.agreement_threshold, 3);
        assert_eq!(spec.max_input_ref_bytes, 2048);
        assert_eq!(spec.result_deadline_blocks, 100);
    }

    #[test]
    fn test_p5_update_model_spec_non_owner_rejected() {
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let other =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let result = registry.update_model_spec(&model_id, &other, 5, 3, 2048, 4096, 200, 100);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("owner"));
    }

    #[test]
    fn test_p5_transfer_model_ownership() {
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let new_owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000099")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        registry
            .transfer_model_ownership(&model_id, &owner, new_owner)
            .unwrap();
        assert_eq!(registry.models.get(&model_id).unwrap().owner, new_owner);

        // Old owner can no longer deactivate
        let result = registry.deactivate_model(&model_id, &owner);
        assert!(result.is_err());

        // New owner can deactivate
        assert!(registry.deactivate_model(&model_id, &new_owner).is_ok());
    }

    #[test]
    fn test_p5_prune_expired_requests() {
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        // Create a request that expires at block 110 (deadline) + 50 (result_deadline) = 110
        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 5).unwrap();

        // Not pruned: within retention window
        let pruned = registry.prune_expired(200, 100);
        assert_eq!(pruned, 0, "Should not prune within retention window");

        // Pruned: past retention window (effective_deadline=110, retention=100, current=300)
        let pruned = registry.prune_expired(300, 100);
        assert!(pruned > 0, "Should prune expired requests past retention");
        assert!(!registry.requests.contains_key(&req_id));
    }

    #[test]
    fn test_p5_max_fee_zero_rejected() {
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count: 2,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 0, // Zero fee
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let result = registry.submit_request(req, 5);
        assert!(result.is_err(), "Zero max_fee should be rejected");
        assert!(result.unwrap_err().contains("max_fee must be >= 1"));
    }
}
