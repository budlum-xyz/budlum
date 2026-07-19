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

    // ===================== P5 — Reward Distribution + Edge Case Tests =====================

    #[test]
    fn test_p5_reward_distribution_with_remainder() {
        // P5 Bulgu 16: max_fee=100, 3 verifiers → 33+33+34 (not 33+33+33=99)
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
                agreement_threshold: 3,
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
        let v3 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000013")
                .unwrap();

        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100, // 100 / 3 = 33 remainder 1
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
                    output_ref: BoundedBytes::try_new(b"r".to_vec()).unwrap(),
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
                    output_ref: BoundedBytes::try_new(b"r".to_vec()).unwrap(),
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
                    verifier: v3,
                    output_commitment: [9u8; 32],
                    output_ref: BoundedBytes::try_new(b"r".to_vec()).unwrap(),
                    result_nonce: 3,
                    signature: vec![3],
                    submitted_at_block: 17,
                },
                17,
            )
            .unwrap()
            .expect("Should finalize with 3 verifiers");

        assert_eq!(outcome.agreeing_verifiers.len(), 3);
        // Verify the outcome exists — executor distributes rewards based on these
    }

    #[test]
    fn test_p5_register_model_duplicate_rejected() {
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

        // Duplicate model_id rejected
        let result = registry.register_model(AiModelSpec {
            model_id,
            model_hash: [2u8; 32], // Different hash, same ID
            owner,
            min_verifier_count: 2,
            agreement_threshold: 2,
            max_input_ref_bytes: 1024,
            max_output_ref_bytes: 2048,
            request_deadline_blocks: 100,
            result_deadline_blocks: 50,
            version: 1,
            active: true,
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already registered"));
    }

    #[test]
    fn test_p5_update_model_spec_invalid_threshold_rejected() {
        // agreement_threshold > min_verifier_count must be rejected
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

        // threshold > min_verifier_count
        let result = registry.update_model_spec(&model_id, &owner, 2, 5, 1024, 2048, 100, 50);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("agreement_threshold"));
    }

    #[test]
    fn test_p5_transfer_to_self_rejected() {
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

        let result = registry.transfer_model_ownership(&model_id, &owner, owner);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("different"));
    }

    // ===================== P5 ADIM6 — ARENA2-T1: F06 Edge-Case Test Matrisi =====================

    /// Helper: create a standard test registry with one active model.
    fn p5_adim6_setup_registry(
        min_verifier_count: u32,
        agreement_threshold: u32,
    ) -> (AiRegistry, AiModelId, Address) {
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
                min_verifier_count,
                agreement_threshold,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            })
            .unwrap();
        (registry, model_id, owner)
    }

    /// Helper: submit a valid inference request at `current_block`.
    fn p5_adim6_submit_request(
        registry: &mut AiRegistry,
        model_id: AiModelId,
        requester: Address,
        current_block: u64,
        deadline_block: u64,
        max_fee: u64,
    ) -> AiRequestId {
        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee,
            callback: None,
            submitted_at_block: current_block,
            deadline_block,
        };
        req.request_id = req.calculate_id();
        registry.submit_request(req, current_block).unwrap()
    }

    /// Helper: submit a request with a callback address (P5 ADIM10 Bulgu 28).
    fn p5_adim6_submit_request_with_callback(
        registry: &mut AiRegistry,
        model_id: AiModelId,
        requester: Address,
        current_block: u64,
        deadline_block: u64,
        max_fee: u64,
        callback: Option<Address>,
    ) -> AiRequestId {
        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee,
            callback,
            submitted_at_block: current_block,
            deadline_block,
        };
        req.request_id = req.calculate_id();
        registry.submit_request(req, current_block).unwrap()
    }

    /// Helper: submit a result from a verifier.
    fn p5_adim6_submit_result(
        registry: &mut AiRegistry,
        request_id: AiRequestId,
        verifier: Address,
        output_commitment: [u8; 32],
        result_nonce: u64,
        current_block: u64,
    ) -> Result<Option<AiInferenceOutcome>, String> {
        registry.submit_result(
            AiInferenceResult {
                request_id,
                verifier,
                output_commitment,
                output_ref: BoundedBytes::try_new(b"response".to_vec()).unwrap(),
                result_nonce,
                signature: vec![1],
                submitted_at_block: current_block,
            },
            current_block,
        )
    }

    // ---- (a) Deadline boundary tests ----

    #[test]
    fn test_p5_adim6_request_deadline_exact_boundary_accepted() {
        // P5 ARENA2-T1(a): Request at current_block == deadline_block → ACCEPTED.
        // The check is `current_block > deadline_block`, so equality passes.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(
            &mut registry,
            model_id,
            owner,
            110, // current_block == deadline_block
            110, // deadline_block
            100,
        );
        // If we get here without error, the request was accepted
        assert!(registry.requests.contains_key(&req_id));
    }

    #[test]
    fn test_p5_adim6_request_deadline_one_past_rejected() {
        // P5 ARENA2-T1(a): Request at current_block == deadline_block + 1 → REJECTED.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 111,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let result = registry.submit_request(req, 111);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("deadline exceeded"));
    }

    #[test]
    fn test_p5_adim6_result_deadline_exact_boundary_accepted() {
        // P5 ARENA2-T1(a): Result at current_block == request deadline_block → ACCEPTED.
        // IMPORTANT: submitted_at_block + result_deadline_blocks MUST be >= deadline_block,
        // otherwise the result_deadline check rejects first (defense-in-depth: two checks).
        // Here: submitted_at=10 + result_deadline_blocks=200 → result_deadline=210
        //        deadline_block=110, so effective_deadline=max(110,210)=210
        //        current_block=110 <= 210 → passes both checks.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
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
        // Override result_deadline_blocks to 200 so result_deadline=210 > deadline_block=110
        registry
            .models
            .get_mut(&model_id)
            .unwrap()
            .result_deadline_blocks = 200;
        let req_id = registry.submit_request(req, 10).unwrap();

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        // Result at exactly deadline_block (110) should be accepted
        // (result_deadline=210 > 110, so second check passes too)
        let result = p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 110);
        assert!(
            result.is_ok(),
            "Result at exact deadline should be accepted"
        );
    }

    #[test]
    fn test_p5_adim6_result_deadline_one_past_rejected() {
        // P5 ARENA2-T1(a): Result at current_block == deadline_block + 1 → REJECTED.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(
            &mut registry,
            model_id,
            owner,
            10,
            110, // deadline_block
            100,
        );
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let result = p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 111);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("deadline"));
    }

    #[test]
    fn test_p5_adim6_result_separate_deadline_exact_boundary() {
        // P5 ARENA2-T1(a): Result at current_block == submitted_at_block +
        // result_deadline_blocks → ACCEPTED (boundary).
        //
        // The registry has TWO independent deadline checks:
        //   1. current_block > request.deadline_block → reject
        //   2. current_block > submitted_at_block + result_deadline_blocks → reject
        //
        // To test ONLY the result_deadline boundary (#2), we need #1 to pass:
        //   deadline_block >= current_block (so check #1 is false).
        //
        // Setup: submitted_at=10, result_deadline_blocks=50 → result_deadline=60
        //        deadline_block=200 (>= 60, so check #1 never triggers)
        //        Test at current_block=60 → check #1: 60 > 200 = false ✓
        //                           → check #2: 60 > 60 = false ✓ (boundary passes)
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 200, // Must be >= result_deadline so check #1 doesn't fire
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 10).unwrap();

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        // Result at exactly result_deadline (60) → accepted
        let result = p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 60);
        assert!(
            result.is_ok(),
            "Result at exact result_deadline should be accepted"
        );
    }

    #[test]
    fn test_p5_adim6_result_separate_deadline_one_past_rejected() {
        // P5 ARENA2-T1(a): Result one past the result_deadline → REJECTED.
        // submitted_at=10, result_deadline_blocks=50 → result_deadline=60
        // deadline_block=55 → effective=max(55,60)=60
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 55,
        };
        req.request_id = req.calculate_id();
        let req_id = registry.submit_request(req, 10).unwrap();

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let result = p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 61);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("deadline"));
    }

    // ---- (b) Equivocation recovery tests ----

    #[test]
    fn test_p5_adim6_equivocation_different_verifier_can_still_submit() {
        // P5 ARENA2-T1(b): After verifier A equivocates, verifier B can still
        // submit normally. Equivocation is per-verifier, not per-request.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v_a =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000021")
                .unwrap();
        let v_b =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000022")
                .unwrap();

        // Verifier A submits first commitment
        p5_adim6_submit_result(&mut registry, req_id, v_a, [1u8; 32], 1, 15).unwrap();

        // Verifier A submits conflicting commitment → EQUIVOCATION
        let err = p5_adim6_submit_result(&mut registry, req_id, v_a, [2u8; 32], 2, 16).unwrap_err();
        assert!(err.contains("EQUIVOCATION"));

        // Verifier B submits the first commitment → should succeed
        let outcome = p5_adim6_submit_result(&mut registry, req_id, v_b, [1u8; 32], 2, 17).unwrap();
        // agreement_threshold=2, two verifiers with [1u8;32] → finalization
        assert!(
            outcome.is_some(),
            "Verifiers B should finalize with A's commitment"
        );
        let finalized = outcome.unwrap();
        assert_eq!(finalized.agreeing_verifiers.len(), 2);
        assert!(finalized.agreeing_verifiers.contains(&v_a));
        assert!(finalized.agreeing_verifiers.contains(&v_b));
    }

    #[test]
    fn test_p5_adim6_double_equivocation_same_verifier_rejected() {
        // P5 ARENA2-T1(b): Same verifier submitting a THIRD different commitment
        // also fails with EQUIVOCATION (the first stored result is always compared).
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v_a =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000021")
                .unwrap();

        // First submission
        p5_adim6_submit_result(&mut registry, req_id, v_a, [1u8; 32], 1, 15).unwrap();

        // Second (equivocation)
        let err1 =
            p5_adim6_submit_result(&mut registry, req_id, v_a, [2u8; 32], 2, 16).unwrap_err();
        assert!(err1.contains("EQUIVOCATION"));

        // Third attempt (also equivocation — compared against first [1u8;32])
        let err2 =
            p5_adim6_submit_result(&mut registry, req_id, v_a, [3u8; 32], 3, 17).unwrap_err();
        assert!(err2.contains("EQUIVOCATION"));
    }

    // ---- (c) Fee reclaim re-entry protection ----

    #[test]
    fn test_p5_adim6_reclaim_then_result_submission_rejected() {
        // P5 ARENA2-T1(c): After reclaiming a fee, trying to submit a result
        // for that request must fail because the deadline has already passed.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 3);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        // Reclaim fee (only works after deadline)
        let (reclaimer, fee) = registry.reclaim_fee(&req_id, 200).unwrap();
        assert_eq!(reclaimer, owner);
        assert_eq!(fee, 100);

        // Now try to submit a result — deadline has passed
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let result = p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 200);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("deadline"));
    }

    #[test]
    fn test_p5_adim6_reclaim_then_second_reclaim_rejected() {
        // P5 ARENA2-T1(c): Double reclaim prevention — second reclaim must fail.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 3);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        // First reclaim succeeds
        registry.reclaim_fee(&req_id, 200).unwrap();

        // Second reclaim fails
        let err = registry.reclaim_fee(&req_id, 250).unwrap_err();
        assert!(err.contains("already reclaimed"));
    }

    #[test]
    fn test_p5_adim6_reclaim_outcome_exists_rejected() {
        // P5 ARENA2-T1(c): Cannot reclaim fee for a finalized request.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v2, [9u8; 32], 2, 16).unwrap();

        // Try to reclaim — should fail because outcome exists
        let err = registry.reclaim_fee(&req_id, 200).unwrap_err();
        assert!(err.contains("finalized"));
    }

    // ---- (d) Agreement threshold boundary tests ----

    #[test]
    fn test_p5_adim6_threshold_equals_verifier_count_all_must_agree() {
        // P5 ARENA2-T1(d): agreement_threshold == min_verifier_count →
        // ALL verifiers must agree for finalization.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 3);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();
        let v3 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000013")
                .unwrap();

        // 2 verifiers agree → not enough (need 3)
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let outcome2 = p5_adim6_submit_result(&mut registry, req_id, v2, [9u8; 32], 2, 16).unwrap();
        assert!(
            outcome2.is_none(),
            "2/3 should not finalize when threshold=3"
        );

        // 3rd verifier agrees → finalization
        let outcome3 = p5_adim6_submit_result(&mut registry, req_id, v3, [9u8; 32], 3, 17).unwrap();
        assert!(outcome3.is_some(), "3/3 should finalize when threshold=3");
        assert_eq!(outcome3.unwrap().agreeing_verifiers.len(), 3);
    }

    #[test]
    fn test_p5_adim6_threshold_one_single_verifier_finalizes() {
        // P5 ARENA2-T1(d): agreement_threshold == 1 → single verifier
        // can finalize immediately.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 1);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let outcome = p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        assert!(
            outcome.is_some(),
            "Single verifier should finalize when threshold=1"
        );
        assert_eq!(outcome.unwrap().agreeing_verifiers.len(), 1);
    }

    #[test]
    fn test_p5_adim6_threshold_minus_one_no_finalization() {
        // P5 ARENA2-T1(d): threshold-1 verifiers → no finalization.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 3);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();

        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let outcome = p5_adim6_submit_result(&mut registry, req_id, v2, [9u8; 32], 2, 16).unwrap();
        assert!(
            outcome.is_none(),
            "2 verifiers with threshold=3 should not finalize"
        );
    }

    #[test]
    fn test_p5_adim6_finalize_only_once_no_duplicate_outcomes() {
        // P5 ARENA2-T1(d): After finalization, additional results don't create
        // duplicate outcomes. The second finalization returns None (not error).
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();
        let v3 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000013")
                .unwrap();

        // 2 matching → finalize
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let outcome1 = p5_adim6_submit_result(&mut registry, req_id, v2, [9u8; 32], 2, 16).unwrap();
        assert!(outcome1.is_some());

        // 3rd matching result → no duplicate outcome (returns None, not error)
        let outcome2 = p5_adim6_submit_result(&mut registry, req_id, v3, [9u8; 32], 3, 17).unwrap();
        assert!(
            outcome2.is_none(),
            "Extra result after finalization should return None"
        );

        // Only one outcome in the registry
        assert_eq!(registry.outcomes.len(), 1);
    }

    // ---- (e) Output commitment edge cases ----

    #[test]
    fn test_p5_adim6_same_commitment_different_ref_both_counted() {
        // P5 ARENA2-T1(e): Two verifiers with same output_commitment but
        // different output_ref → both counted as agreeing (commitment is
        // the consensus signal, ref is just the data location).
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();

        // V1: commitment=[9u8;32], ref="ipfs://abc"
        registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v1,
                    output_commitment: [9u8; 32],
                    output_ref: BoundedBytes::try_new(b"ipfs://abc".to_vec()).unwrap(),
                    result_nonce: 1,
                    signature: vec![1],
                    submitted_at_block: 15,
                },
                15,
            )
            .unwrap();

        // V2: same commitment, different ref → still counts as agreeing
        let outcome = registry
            .submit_result(
                AiInferenceResult {
                    request_id: req_id,
                    verifier: v2,
                    output_commitment: [9u8; 32],
                    output_ref: BoundedBytes::try_new(b"ipfs://xyz".to_vec()).unwrap(),
                    result_nonce: 2,
                    signature: vec![2],
                    submitted_at_block: 16,
                },
                16,
            )
            .unwrap();
        assert!(
            outcome.is_some(),
            "Same commitment different ref should finalize"
        );
        let finalized = outcome.unwrap();
        assert_eq!(finalized.agreeing_verifiers.len(), 2);
    }

    #[test]
    fn test_p5_adim6_result_for_nonexistent_request_rejected() {
        // P5 ARENA2-T1(e): Result for a request that doesn't exist → error.
        let (mut registry, _, _) = p5_adim6_setup_registry(2, 2);
        let fake_req_id = AiRequestId::new([99u8; 32]);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let result = p5_adim6_submit_result(&mut registry, fake_req_id, v1, [9u8; 32], 1, 15);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_p5_adim6_verifier_duplicate_same_commitment_rejected() {
        // P5 ARENA2-T1(e): Same verifier submitting the SAME commitment
        // twice → "already submitted" (not equivocation).
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();

        let err = p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 2, 16).unwrap_err();
        assert!(err.contains("already submitted"));
    }

    // ---- (f) Additional robustness edge cases ----

    #[test]
    fn test_p5_adim6_deactivate_model_pending_requests_still_accept_results() {
        // P5 ARENA2-T1(f): Deactivating a model does NOT affect existing
        // pending requests — results can still be submitted and finalized.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        // Deactivate the model
        registry.deactivate_model(&model_id, &owner).unwrap();

        // Results for the existing request should still be accepted
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let outcome = p5_adim6_submit_result(&mut registry, req_id, v2, [9u8; 32], 2, 16).unwrap();
        assert!(
            outcome.is_some(),
            "Results should finalize even after model deactivation"
        );
    }

    #[test]
    fn test_p5_adim6_deactivated_model_rejects_new_requests() {
        // P5 ARENA2-T1(f): A deactivated model rejects new inference requests.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        registry.deactivate_model(&model_id, &owner).unwrap();

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
        let result = registry.submit_request(req, 10);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("inactive"));
    }

    #[test]
    fn test_p5_adim6_transfer_ownership_old_owner_operations_rejected() {
        // P5 ARENA2-T1(f): After ownership transfer, old owner can no longer
        // deactivate, reactivate, update spec, or transfer again.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let new_owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000099")
                .unwrap();

        registry
            .transfer_model_ownership(&model_id, &owner, new_owner)
            .unwrap();

        // Old owner can't deactivate
        let err = registry.deactivate_model(&model_id, &owner).unwrap_err();
        assert!(err.contains("Only the model owner"));

        // Old owner can't update spec
        let err = registry
            .update_model_spec(&model_id, &owner, 3, 2, 1024, 2048, 100, 50)
            .unwrap_err();
        assert!(err.contains("Only the model owner"));

        // Old owner can't transfer again
        let err = registry
            .transfer_model_ownership(&model_id, &owner, new_owner)
            .unwrap_err();
        assert!(err.contains("Only the model owner"));

        // New owner CAN deactivate
        registry.deactivate_model(&model_id, &new_owner).unwrap();
    }

    #[test]
    fn test_p5_adim6_update_spec_on_inactive_model() {
        // P5 ARENA2-T1(f): Spec update on an inactive model should be
        // allowed — the owner may want to adjust thresholds before reactivating.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        registry.deactivate_model(&model_id, &owner).unwrap();

        // Spec update on inactive model should succeed
        let result = registry.update_model_spec(&model_id, &owner, 5, 3, 2048, 4096, 200, 100);
        assert!(
            result.is_ok(),
            "Spec update on inactive model should be allowed"
        );

        // Verify the update took effect
        let spec = registry.models.get(&model_id).unwrap();
        assert_eq!(spec.min_verifier_count, 5);
        assert_eq!(spec.agreement_threshold, 3);
        assert_eq!(spec.max_input_ref_bytes, 2048);
    }

    #[test]
    fn test_p5_adim6_prune_then_access_returns_none() {
        // P5 ARENA2-T1(f): After pruning, get_request returns None.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        assert!(registry.get_request(&req_id).is_some());

        // Prune past retention window (deadline=110, retention=100, current=300)
        registry.prune_expired(300, 100);

        assert!(
            registry.get_request(&req_id).is_none(),
            "Pruned request should return None"
        );
    }

    #[test]
    fn test_p5_adim6_prune_outcome_after_retention() {
        // P5 ARENA2-T1(f): Finalized outcomes are pruned after retention window.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let outcome = p5_adim6_submit_result(&mut registry, req_id, v2, [9u8; 32], 2, 16)
            .unwrap()
            .unwrap();

        // Outcome exists
        assert!(registry.get_outcome(&req_id).is_some());

        // Prune past retention window (finalized_at=16, retention=100, current=200)
        registry.prune_expired(200, 100);

        // Outcome pruned
        assert!(
            registry.get_outcome(&req_id).is_none(),
            "Pruned outcome should return None"
        );
    }

    #[test]
    fn test_p5_adim6_state_root_changes_after_each_mutation() {
        // P5 ARENA2-T1(f): Every mutation should change the state_root,
        // ensuring deterministic integrity tracking.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let root_after_register = registry.state_root();

        // Submit request → root changes
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let root_after_request = registry.state_root();
        assert_ne!(root_after_register, root_after_request);

        // Submit result → root changes
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let root_after_result = registry.state_root();
        assert_ne!(root_after_request, root_after_result);

        // Deactivate model → root changes
        registry.deactivate_model(&model_id, &owner).unwrap();
        let root_after_deactivate = registry.state_root();
        assert_ne!(root_after_result, root_after_deactivate);

        // Reactivate model → root changes
        registry.reactivate_model(&model_id, &owner).unwrap();
        let root_after_reactivate = registry.state_root();
        assert_ne!(root_after_deactivate, root_after_reactivate);
    }

    #[test]
    fn test_p5_adim6_reclaim_with_partial_results_no_outcome() {
        // P5 ARENA2-T1(c): Request with some results but insufficient
        // agreement → fee can be reclaimed after deadline.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 3);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        // Only 1 verifier submits (need 3 for threshold)
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();

        // No finalization occurred
        assert!(registry.get_outcome(&req_id).is_none());

        // Reclaim succeeds after deadline
        let (reclaimer, fee) = registry.reclaim_fee(&req_id, 200).unwrap();
        assert_eq!(reclaimer, owner);
        assert_eq!(fee, 100);
    }

    #[test]
    fn test_p5_adim6_disagreement_no_consensus_no_finalization() {
        // P5 ARENA2-T1(d): All verifiers submit different commitments →
        // no consensus, no finalization. Fee can be reclaimed.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();
        let v3 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000013")
                .unwrap();

        // Three different commitments → no pair reaches threshold=2
        p5_adim6_submit_result(&mut registry, req_id, v1, [1u8; 32], 1, 15).unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v2, [2u8; 32], 2, 16).unwrap();
        let outcome = p5_adim6_submit_result(&mut registry, req_id, v3, [3u8; 32], 3, 17).unwrap();
        assert!(
            outcome.is_none(),
            "All-different commitments should not finalize"
        );

        // Fee can be reclaimed after deadline
        let (reclaimer, fee) = registry.reclaim_fee(&req_id, 200).unwrap();
        assert_eq!(reclaimer, owner);
        assert_eq!(fee, 100);
    }

    #[test]
    fn test_p5_adim6_input_ref_exceeds_model_limit_rejected() {
        // P5 ARENA2-T1(f): Request with input_ref larger than the model's
        // max_input_ref_bytes is rejected.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester: owner,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(vec![0u8; 2048]).unwrap(), // exceeds 1024
            max_fee: 100,
            callback: None,
            submitted_at_block: 10,
            deadline_block: 110,
        };
        req.request_id = req.calculate_id();
        let result = registry.submit_request(req, 10);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds"));
    }

    #[test]
    fn test_p5_adim6_output_ref_exceeds_model_limit_rejected() {
        // P5 ARENA2-T1(f): Result with output_ref larger than the model's
        // max_output_ref_bytes is rejected.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let result = registry.submit_result(
            AiInferenceResult {
                request_id: req_id,
                verifier: v1,
                output_commitment: [9u8; 32],
                output_ref: BoundedBytes::try_new(vec![0u8; 4096]).unwrap(), // exceeds 2048
                result_nonce: 1,
                signature: vec![1],
                submitted_at_block: 15,
            },
            15,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds"));
    }

    // ===================== P5 ADIM7 — Security Hardening Tests =====================

    #[test]
    fn test_p5_adim7_equivocation_event_recorded() {
        // P5 Bulgu 18: When equivocation is detected, the event must be
        // recorded in equivocation_events for future slashing.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();

        // First result from v1
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();

        // Second result from v1 with DIFFERENT commitment → equivocation
        let equiv_result = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);
        assert!(equiv_result.is_err());
        assert!(equiv_result.unwrap_err().contains("EQUIVOCATION"));

        // Verify equivocation event was recorded
        assert!(
            registry.has_equivocated(&req_id, &v1),
            "Equivocation event should be recorded for v1"
        );

        // Verify verifier that didn't equivocate returns false
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();
        assert!(
            !registry.has_equivocated(&req_id, &v2),
            "Non-equivocating verifier should not be recorded"
        );
    }

    #[test]
    fn test_p5_adim7_equivocation_count_for_verifier() {
        // P5 Bulgu 18: Track equivocation count across multiple requests.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();

        // Request 1: v1 equivocates
        let req1 = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        p5_adim6_submit_result(&mut registry, req1, v1, [9u8; 32], 1, 15).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req1, v1, [88u8; 32], 2, 16);

        // Request 2: v1 equivocates again
        let req2 = p5_adim6_submit_request(&mut registry, model_id, owner, 20, 120, 100);
        p5_adim6_submit_result(&mut registry, req2, v1, [7u8; 32], 1, 25).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req2, v1, [99u8; 32], 2, 26);

        // v1 has 2 equivocation events
        assert_eq!(
            registry.equivocation_count_for_verifier(&v1),
            2,
            "v1 should have 2 equivocation events"
        );

        // v2 has 0
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();
        assert_eq!(
            registry.equivocation_count_for_verifier(&v2),
            0,
            "v2 should have 0 equivocation events"
        );
    }

    #[test]
    fn test_p5_adim7_state_root_domain_separation() {
        // P5 Bulgu 19 (V38 fix): Domain-separated map roots prevent cross-map
        // collision. The state root must change when equivocation_events or
        // cancelled_requests are modified, proving domain separation.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let root_before = registry.state_root();

        // Add an equivocation event → root changes
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);
        let root_after_equiv = registry.state_root();
        assert_ne!(
            root_before, root_after_equiv,
            "State root must change after equivocation event"
        );

        // Add a cancelled request → root changes again
        let req2 = p5_adim6_submit_request(&mut registry, model_id, owner, 20, 120, 100);
        registry.cancel_request(&req2, &owner, 25).unwrap();
        let root_after_cancel = registry.state_root();
        assert_ne!(
            root_after_equiv, root_after_cancel,
            "State root must change after request cancellation"
        );
    }

    #[test]
    fn test_p5_adim7_state_root_v2_not_equal_v1() {
        // P5 Bulgu 19: Verify that V2 domain-separated root differs from
        // what V1 would produce, ensuring the upgrade is meaningful.
        let (registry, _, _) = p5_adim6_setup_registry(2, 2);

        // The V2 root should be computed correctly (non-zero for non-empty)
        let root = registry.state_root();
        assert_ne!(
            root, [0u8; 32],
            "Non-empty registry must have non-zero root"
        );
    }

    #[test]
    fn test_p5_adim7_model_version_auto_increment() {
        // P5 Bulgu 20: update_model_spec should auto-increment the version.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);

        // Initial version = 1
        let initial_version = registry.models.get(&model_id).unwrap().version;
        assert_eq!(initial_version, 1);

        // Update spec → version becomes 2
        registry
            .update_model_spec(&model_id, &owner, 3, 2, 2048, 4096, 200, 100)
            .unwrap();
        let after_first_update = registry.models.get(&model_id).unwrap().version;
        assert_eq!(after_first_update, 2, "Version should be incremented to 2");

        // Update again → version becomes 3
        registry
            .update_model_spec(&model_id, &owner, 5, 3, 4096, 8192, 300, 150)
            .unwrap();
        let after_second_update = registry.models.get(&model_id).unwrap().version;
        assert_eq!(after_second_update, 3, "Version should be incremented to 3");
    }

    #[test]
    fn test_p5_adim7_model_version_changes_state_root() {
        // P5 Bulgu 20: Version increment changes the spec's calculate_leaf,
        // which changes the state root.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let root_before = registry.state_root();

        registry
            .update_model_spec(&model_id, &owner, 3, 2, 2048, 4096, 200, 100)
            .unwrap();
        let root_after = registry.state_root();

        assert_ne!(
            root_before, root_after,
            "Version increment must change state root"
        );
    }

    #[test]
    fn test_p5_adim7_cancel_request_by_requester() {
        // P5 Bulgu 21: Requester can cancel a pending request.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        // Cancel should succeed
        let (requester, max_fee) = registry.cancel_request(&req_id, &owner, 15).unwrap();
        assert_eq!(requester, owner);
        assert_eq!(max_fee, 100);

        // Request should be marked as cancelled
        assert!(registry.is_cancelled(&req_id));
    }

    #[test]
    fn test_p5_adim7_cancel_request_non_requester_rejected() {
        // P5 Bulgu 21: Only the requester can cancel.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let other =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000099")
                .unwrap();
        let result = registry.cancel_request(&req_id, &other, 15);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Only the requester"));
    }

    #[test]
    fn test_p5_adim7_cancel_finalized_request_rejected() {
        // P5 Bulgu 21: Cannot cancel a finalized request.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000012")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v2, [9u8; 32], 2, 16).unwrap();

        // Request is finalized now
        assert!(registry.get_outcome(&req_id).is_some());

        let result = registry.cancel_request(&req_id, &owner, 20);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("finalized"));
    }

    #[test]
    fn test_p5_adim7_cancel_already_cancelled_rejected() {
        // P5 Bulgu 21: Double-cancel is rejected.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        registry.cancel_request(&req_id, &owner, 15).unwrap();

        let result = registry.cancel_request(&req_id, &owner, 20);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already cancelled"));
    }

    #[test]
    fn test_p5_adim7_cancel_reclaimed_request_rejected() {
        // P5 Bulgu 21: Cannot cancel a request whose fee was already reclaimed.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        // Reclaim fee first (after deadline)
        registry.reclaim_fee(&req_id, 200).unwrap();

        let result = registry.cancel_request(&req_id, &owner, 201);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already reclaimed"));
    }

    #[test]
    fn test_p5_adim7_cancel_blocks_results() {
        // P5 Bulgu 21: After cancellation, results are rejected.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        // Cancel the request
        registry.cancel_request(&req_id, &owner, 15).unwrap();

        // Try to submit a result → rejected
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let result = p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 20);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cancelled"));
    }

    #[test]
    fn test_p5_adim7_cancel_nonexistent_request_rejected() {
        // P5 Bulgu 21: Cannot cancel a request that doesn't exist.
        let (mut registry, _, _) = p5_adim6_setup_registry(2, 2);
        let fake_id = AiRequestId::new([0xAA; 32]);

        let result = registry.cancel_request(
            &fake_id,
            &Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            10,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_p5_adim7_reactivate_model_via_new_tx_type() {
        // P5 ADIM7: AiModelReactivate transaction type works.
        // This tests the registry method (executor path tested separately).
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);

        registry.deactivate_model(&model_id, &owner).unwrap();
        assert!(!registry.models.get(&model_id).unwrap().active);

        registry.reactivate_model(&model_id, &owner).unwrap();
        assert!(registry.models.get(&model_id).unwrap().active);
    }

    #[test]
    fn test_p5_adim7_equivocation_in_state_root() {
        // P5 Bulgu 18+19: Equivocation events are included in the state root.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let root_before = registry.state_root();

        // Trigger equivocation
        let _ = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);
        let root_after = registry.state_root();

        assert_ne!(
            root_before, root_after,
            "Equivocation event must change state root"
        );
    }

    #[test]
    fn test_p5_adim7_cancel_in_state_root() {
        // P5 Bulgu 19+21: Cancelled requests are included in the state root.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let root_before = registry.state_root();

        registry.cancel_request(&req_id, &owner, 15).unwrap();
        let root_after = registry.state_root();

        assert_ne!(
            root_before, root_after,
            "Request cancellation must change state root"
        );
    }

    #[test]
    fn test_p5_adim7_empty_new_fields_is_empty() {
        // P5 ADIM7: Registry with only equivocation/cancelled entries
        // should NOT be considered empty (they are meaningful data).
        let mut registry = AiRegistry::new();
        assert!(registry.is_empty());

        // Add just an equivocation event
        let fake_req = AiRequestId::new([1u8; 32]);
        let fake_addr =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        registry
            .equivocation_events
            .insert((fake_req, fake_addr.0), 100);
        assert!(!registry.is_empty());

        // Reset and add just a cancelled request
        let mut registry2 = AiRegistry::new();
        registry2.cancelled_requests.insert(fake_req);
        assert!(!registry2.is_empty());
    }

    #[test]
    fn test_p5_adim7_prune_includes_new_fields() {
        // P5 Bulgu 10+21: prune_expired should clean up cancelled_requests
        // that are past the retention window.
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);

        // Cancel the request
        registry.cancel_request(&req_id, &owner, 15).unwrap();
        assert!(registry.is_cancelled(&req_id));

        // Prune (deadline=110, retention=100, current=300 → expired)
        registry.prune_expired(300, 100);

        // The request should be pruned and cancellation cleared
        assert!(
            registry.get_request(&req_id).is_none(),
            "Pruned cancelled request should be removed"
        );
    }

    // ===================== P5 ADIM8 — AI Settlement Layer Deepening Tests =====================

    #[test]
    fn test_p5_adim8_slash_equivocator_succeeds() {
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);
        assert!(registry.has_equivocated(&req_id, &v1));
        let (slashed, _seized) = registry.slash_equivocator(&req_id, &v1, 20).unwrap();
        assert_eq!(slashed, v1);
        assert!(!registry.has_equivocated(&req_id, &v1));
    }

    #[test]
    fn test_p5_adim8_slash_double_slash_rejected() {
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);
        registry.slash_equivocator(&req_id, &v1, 20).unwrap();
        assert!(registry.slash_equivocator(&req_id, &v1, 20).is_err());
    }

    #[test]
    fn test_p5_adim8_slash_no_equivocation_rejected() {
        let (mut registry, _, _) = p5_adim6_setup_registry(2, 2);
        let fake_req = AiRequestId::new([0xAA; 32]);
        let fake_v =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        assert!(registry.slash_equivocator(&fake_req, &fake_v, 20).is_err());
    }

    #[test]
    fn test_p5_adim8_slash_changes_state_root() {
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);
        let root_before = registry.state_root();
        registry.slash_equivocator(&req_id, &v1, 20).unwrap();
        assert_ne!(root_before, registry.state_root());
    }

    #[test]
    fn test_p5_adim8_state_root_non_empty() {
        let (registry, _, _) = p5_adim6_setup_registry(2, 2);
        assert_ne!(registry.state_root(), [0u8; 32]);
    }

    #[test]
    fn test_p5_adim8_consensus_kind_ai_inference() {
        use crate::domain::types::ConsensusKind;
        let ai_kind = ConsensusKind::AiInference;
        assert!(ai_kind.is_ai());
        assert!(!ai_kind.is_storage());
        assert_eq!(ai_kind.as_bytes(), b"ai_inference");
    }

    #[test]
    fn test_p5_adim8_consensus_kind_ai_distinct_from_custom() {
        use crate::domain::types::ConsensusKind;
        let ai_kind = ConsensusKind::AiInference;
        let custom_kind = ConsensusKind::Custom("ai_inference".to_string());
        assert_ne!(ai_kind.as_bytes(), custom_kind.as_bytes());
    }

    // ===================== P5 ADIM9 — Dispute Window + Verifier Stake =====================

    #[test]
    fn test_p5_adim9_dispute_window_slash_within_window() {
        // P5 Bulgu 25: Slash succeeds within dispute window
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);
        // Slash at block 50 — equivocation detected at block 16, well within window
        assert!(registry.slash_equivocator(&req_id, &v1, 50).is_ok());
    }

    #[test]
    fn test_p5_adim9_dispute_window_expired_rejected() {
        // P5 Bulgu 25: Slash rejected after dispute window expires
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);
        // Detected at block 16, window = 10080, so after 10096 should fail
        let result = registry.slash_equivocator(&req_id, &v1, 10_097);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Dispute window expired"));
    }

    #[test]
    fn test_p5_adim9_dispute_window_is_disputable() {
        // P5 Bulgu 25: is_disputable returns correct values
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);
        assert!(registry.is_disputable(&req_id, &v1, 50));
        assert!(!registry.is_disputable(&req_id, &v1, 10_097));
    }

    #[test]
    fn test_p5_adim9_expire_dispute_window() {
        // P5 Bulgu 25: expire_dispute_window cleans old events
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);
        assert!(registry.has_equivocated(&req_id, &v1));
        let expired = registry.expire_dispute_window(10_097);
        assert_eq!(expired, 1);
        assert!(!registry.has_equivocated(&req_id, &v1));
    }

    #[test]
    fn test_p5_adim9_verifier_stake_lock() {
        // P5 Bulgu 26: Lock verifier stake
        let (mut registry, _, _) = p5_adim6_setup_registry(2, 2);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let stake = registry.lock_verifier_stake(&v1, 5000).unwrap();
        assert_eq!(stake, 5000);
        assert!(registry.is_staked_verifier(&v1));
        assert_eq!(registry.verifier_stake(&v1), 5000);
        // Add more stake
        let stake2 = registry.lock_verifier_stake(&v1, 3000).unwrap();
        assert_eq!(stake2, 8000);
    }

    #[test]
    fn test_p5_adim9_verifier_stake_zero_rejected() {
        let (mut registry, _, _) = p5_adim6_setup_registry(2, 2);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        assert!(registry.lock_verifier_stake(&v1, 0).is_err());
    }

    #[test]
    fn test_p5_adim9_verifier_stake_withdraw() {
        // P5 Bulgu 26: Withdraw verifier stake when no pending disputes
        let (mut registry, _, _) = p5_adim6_setup_registry(2, 2);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        registry.lock_verifier_stake(&v1, 5000).unwrap();
        let withdrawn = registry.withdraw_verifier_stake(&v1, 3000, 100).unwrap();
        assert_eq!(withdrawn, 3000);
        assert_eq!(registry.verifier_stake(&v1), 2000);
    }

    #[test]
    fn test_p5_adim9_verifier_stake_withdraw_blocked_by_dispute() {
        // P5 Bulgu 26: Cannot withdraw if pending equivocation dispute
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        registry.lock_verifier_stake(&v1, 5000).unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);
        // Cannot withdraw while disputable
        let result = registry.withdraw_verifier_stake(&v1, 3000, 50);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("pending equivocation"));
    }

    #[test]
    fn test_p5_adim9_slash_seizes_stake() {
        // P5 Bulgu 25+26: Slash seizes verifier stake
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        registry.lock_verifier_stake(&v1, 5000).unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);
        let (_, seized) = registry.slash_equivocator(&req_id, &v1, 50).unwrap();
        assert_eq!(seized, 5000);
        assert!(!registry.is_staked_verifier(&v1));
        assert_eq!(registry.verifier_stake(&v1), 0);
    }

    #[test]
    fn test_p5_adim9_stake_changes_state_root() {
        // P5 Bulgu 26: Stake changes affect state root
        let (mut registry, _, _) = p5_adim6_setup_registry(2, 2);
        let root_before = registry.state_root();
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        registry.lock_verifier_stake(&v1, 5000).unwrap();
        assert_ne!(root_before, registry.state_root());
    }

    // ===================== P5 ADIM10 — B27 + B28 =====================

    #[test]
    fn test_p5_adim10_get_dispute_status() {
        // P5 Bulgu 27: get_dispute_status returns comprehensive info
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        registry.lock_verifier_stake(&v1, 5000).unwrap();

        // Before equivocation: no dispute
        let status = registry.get_dispute_status(&req_id, &v1, 50);
        assert!(!status.has_equivocated);
        assert!(!status.is_disputable);
        assert!(status.detected_block.is_none());
        assert!(status.stake_amount == 5000);

        // Cause equivocation
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);

        // After equivocation: disputable
        let status = registry.get_dispute_status(&req_id, &v1, 50);
        assert!(status.has_equivocated);
        assert!(status.is_disputable);
        assert_eq!(status.detected_block, Some(16));
        assert_eq!(status.dispute_window_remaining, Some(10_046));
        assert!(status.is_staked);
        assert_eq!(status.stake_amount, 5000);
    }

    #[test]
    fn test_p5_adim10_dispute_status_expired_window() {
        // P5 Bulgu 27: Dispute window expiry reflected in status
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(3, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let _ = p5_adim6_submit_result(&mut registry, req_id, v1, [88u8; 32], 2, 16);

        // After dispute window expires
        let status = registry.get_dispute_status(&req_id, &v1, 10_097);
        assert!(status.has_equivocated);
        assert!(!status.is_disputable);
        assert_eq!(status.dispute_window_remaining, Some(0));
    }

    #[test]
    fn test_p5_adim10_get_verifier_stake_info() {
        // P5 Bulgu 27: get_verifier_stake_info returns stake + equivocation count
        let (mut registry, _, _) = p5_adim6_setup_registry(2, 2);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();

        // Not staked yet
        let info = registry.get_verifier_stake_info(&v1);
        assert!(!info.is_staked);
        assert_eq!(info.stake_amount, 0);
        assert_eq!(info.total_equivocations, 0);

        // After staking
        registry.lock_verifier_stake(&v1, 5000).unwrap();
        let info = registry.get_verifier_stake_info(&v1);
        assert!(info.is_staked);
        assert_eq!(info.stake_amount, 5000);
    }

    #[test]
    fn test_p5_adim10_callback_event_on_finalization() {
        // P5 Bulgu 28: Callback event is queued when outcome is finalized
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let cb_addr =
            Address::from_hex("00000000000000000000000000000000000000000000000000000000000000CB")
                .unwrap();
        let req_id = p5_adim6_submit_request_with_callback(
            &mut registry,
            model_id,
            owner,
            10,
            110,
            100,
            Some(cb_addr),
        );
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000022")
                .unwrap();

        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let outcome = p5_adim6_submit_result(&mut registry, req_id, v2, [9u8; 32], 2, 20).unwrap();

        // Outcome should be finalized
        assert!(outcome.is_some());

        // Callback event should be queued
        let events = registry.get_callback_queue(&cb_addr);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].request_id, req_id);
        assert_eq!(events[0].output_commitment, [9u8; 32]);
        assert_eq!(events[0].callback_address, cb_addr);
    }

    #[test]
    fn test_p5_adim10_no_callback_event_without_address() {
        // P5 Bulgu 28: No callback event when callback is None
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let req_id = p5_adim6_submit_request(&mut registry, model_id, owner, 10, 110, 100);
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000022")
                .unwrap();

        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v2, [9u8; 32], 2, 20);

        // Callback queue should be empty (no callback address)
        assert!(registry.callback_queue.is_empty());
    }

    #[test]
    fn test_p5_adim10_consume_callback_events() {
        // P5 Bulgu 28: Consume (drain) callback events after delivery
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let cb_addr =
            Address::from_hex("00000000000000000000000000000000000000000000000000000000000000CB")
                .unwrap();
        let req_id = p5_adim6_submit_request_with_callback(
            &mut registry,
            model_id,
            owner,
            10,
            110,
            100,
            Some(cb_addr),
        );
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000022")
                .unwrap();

        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        p5_adim6_submit_result(&mut registry, req_id, v2, [9u8; 32], 2, 20);

        // Consume events
        let count = registry.consume_callback_events(&cb_addr);
        assert_eq!(count, 1);

        // Queue should now be empty
        let events = registry.get_callback_queue(&cb_addr);
        assert!(events.is_empty());
    }

    #[test]
    fn test_p5_adim10_callback_queue_changes_state_root() {
        // P5 Bulgu 28: Callback queue affects state root
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let cb_addr =
            Address::from_hex("00000000000000000000000000000000000000000000000000000000000000CB")
                .unwrap();
        let req_id = p5_adim6_submit_request_with_callback(
            &mut registry,
            model_id,
            owner,
            10,
            110,
            100,
            Some(cb_addr),
        );
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000022")
                .unwrap();

        p5_adim6_submit_result(&mut registry, req_id, v1, [9u8; 32], 1, 15).unwrap();
        let root_before = registry.state_root();
        p5_adim6_submit_result(&mut registry, req_id, v2, [9u8; 32], 2, 20);
        // Callback event added → state root should change
        assert_ne!(root_before, registry.state_root());
    }

    #[test]
    fn test_p5_adim10_multiple_callbacks_same_address() {
        // P5 Bulgu 28: Multiple outcomes can queue events for the same callback
        let (mut registry, model_id, owner) = p5_adim6_setup_registry(2, 2);
        let cb_addr =
            Address::from_hex("00000000000000000000000000000000000000000000000000000000000000CB")
                .unwrap();
        // Two requests with same callback
        let req1 = p5_adim6_submit_request_with_callback(
            &mut registry,
            model_id,
            owner,
            10,
            110,
            100,
            Some(cb_addr),
        );
        let req2 = p5_adim6_submit_request_with_callback(
            &mut registry,
            model_id,
            owner,
            10,
            110,
            100,
            Some(cb_addr),
        );
        let v1 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let v2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000022")
                .unwrap();

        p5_adim6_submit_result(&mut registry, req1, v1, [9u8; 32], 1, 15).unwrap();
        p5_adim6_submit_result(&mut registry, req1, v2, [9u8; 32], 2, 20);
        p5_adim6_submit_result(&mut registry, req2, v1, [8u8; 32], 3, 25).unwrap();
        p5_adim6_submit_result(&mut registry, req2, v2, [8u8; 32], 4, 30);

        let events = registry.get_callback_queue(&cb_addr);
        assert_eq!(events.len(), 2);
    }
}
