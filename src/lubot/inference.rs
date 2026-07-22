//! Görev A runtime — Lubot çıkarım akışı (gerçek `AiRegistry` üzerinde).
//!
//! Lubot sorgusunun gerçek budlum-core AI katmanında uçtan-uca akışı:
//! model kaydı → operator compute-bond → kapalı-devre input_ref ile request
//! inşası (canonical request_id) → `submit_request` → `AiInferenceResult` → `submit_result`.
//! Mock yok; gerçek tipler + gerçek registry metotları.

use crate::ai::types::{
    AiInferenceRequest, AiInferenceResult, AiModelId, AiModelSpec, AiRequestId, BoundedBytes,
};
use crate::ai::AiRegistry;
use crate::core::address::Address;
use sha2::{Digest, Sha256};

/// Bir Lubot modelini on-chain kaydet (AiModelSpec + register_model).
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
    };
    registry.register_model(spec)
}

/// Kapalı-devre Lubot çıkarım talebini inşa et (canonical request_id ile).
/// `input_ref` = kullanılan veri referansı (AiDataInputRef encode'u veya opaque);
/// kapalı-devre grant doğrulaması `validate_inference_grant` ile ayrıca yapılır.
pub fn build_lubot_request(
    requester: Address,
    model_id: AiModelId,
    input_ref: Vec<u8>,
    max_fee: u64,
    submitted_at_block: u64,
    deadline_block: u64,
) -> Result<AiInferenceRequest, String> {
    let bounded = BoundedBytes::try_new(input_ref.clone())?;
    let mut hasher = Sha256::new();
    hasher.update(b"LUBOT_INPUT_COMMIT_V1");
    hasher.update(&input_ref);
    let input_commitment: [u8; 32] = hasher.finalize().into();
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
    };
    // Canonical request_id'yi hesapla → verify_id geçer.
    req.request_id = req.calculate_id();
    Ok(req)
}

/// Lubot çıkarım sonucunu inşa et (operator'ün yanıtı).
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
    use super::super::{operator_bond, operator_eligible, register_operator};
    use super::*;

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    /// Gerçek AiRegistry üzerinde uçtan-uca Lubot çıkarım akışı.
    #[test]
    fn lubot_full_inference_flow_on_real_registry() {
        let mut registry = AiRegistry::new();
        let owner = addr(1);
        let operator = addr(2);
        let requester = addr(3);
        let model_hash = [9u8; 32];

        // (1) Modeli on-chain kaydet.
        let model_id =
            register_lubot_model(&mut registry, owner, model_hash).expect("model register");

        // (2) Operator compute-bond (AI-layer-first).
        register_operator(&mut registry, &operator, 500).expect("operator bond");
        assert!(operator_eligible(&registry, &operator));
        assert_eq!(operator_bond(&registry, &operator), 500);

        // (3) Kapalı-devre request inşa + submit.
        let req = build_lubot_request(requester, model_id, b"lubot-input".to_vec(), 1, 1, 1000)
            .expect("build request");
        assert!(req.verify_id(), "canonical request_id must verify");
        let req_id = registry.submit_request(req, 1).expect("submit request");

        // (4) Result inşa + submit.
        let res = build_lubot_result(req_id, operator, b"lubot-output".to_vec(), 1, 2)
            .expect("build result");
        let outcome = registry.submit_result(res, 2);
        assert!(
            outcome.is_ok(),
            "result submission should succeed: {outcome:?}"
        );
    }
}
