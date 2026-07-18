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

        let req_id = registry.submit_request(req).unwrap();

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
        let outcome1 = registry.submit_result(res1).unwrap();
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
        let outcome2 = registry.submit_result(res2).unwrap();
        assert!(outcome2.is_some());
        let finalized = outcome2.unwrap();
        assert_eq!(finalized.agreeing_verifiers.len(), 2);
        assert_eq!(finalized.output_commitment, [9u8; 32]);
    }
}
