//! Faz A — Executor/Transaction entegrasyon.
//!
//! Lubot çıkarım talebi, `TransactionType::AiInferenceRequest` olarak executor'a
//! taşınır. Executor (src/execution/executor.rs:723) zaten tam akışı işler:
//! Pollen grant doğrulaması → balance kontrolü → ai_registry.submit_request →
//! grant tüketimi → fee kesintisi. Bu modül, kullanıcının göndermesi gereken
//! Transaction'ı inşa eder.

use crate::ai::types::{AiInferenceRequest, AiModelId, AiRequestId, BoundedBytes};
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};

use super::inference;

/// Executor'a gönderilecek Lubot transaction request'i (metadata seam).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LubotExecutorRequest {
    pub request_id: AiRequestId,
    pub requester: Address,
    pub max_fee: u64,
    pub deadline_block: u64,
}

impl LubotExecutorRequest {
    /// Bir AiInferenceRequest'ten executor-ready form oluştur.
    #[must_use]
    pub fn from_inference_request(req: &AiInferenceRequest) -> Self {
        Self {
            request_id: req.request_id,
            requester: req.requester,
            max_fee: req.max_fee,
            deadline_block: req.deadline_block,
        }
    }
}

/// Bir Lubot çıkarım transaction'ı inşa et (executor'a gönderilecek form).
///
/// Executor bu transaction'ı `TransactionType::AiInferenceRequest` olarak işler:
/// (1) Pollen grant doğrulaması (kapalı-devre), (2) balance kontrolü, (3) ai_registry
/// submit, (4) grant tüketimi, (5) fee + max_fee kesintisi.
#[allow(clippy::too_many_arguments)]
pub fn build_lubot_transaction(
    from: Address,
    to: Address,
    model_id: AiModelId,
    input_data: Vec<u8>,
    fee: u64,
    max_fee: u64,
    nonce: u64,
    chain_id: u64,
    current_block: u64,
    deadline_block: u64,
) -> Result<Transaction, String> {
    let req = inference::build_lubot_request(
        from,
        model_id,
        input_data.clone(),
        max_fee,
        current_block,
        deadline_block,
    )?;
    Ok(Transaction::new_with_chain_id(
        from,
        to,
        0, // value transfer = 0 (AI query, not payment)
        fee,
        nonce,
        input_data,
        chain_id,
        TransactionType::AiInferenceRequest(req),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_lubot_tx_produces_ai_inference_type() {
        let tx = build_lubot_transaction(
            Address([1; 32]),
            Address([2; 32]),
            AiModelId([3; 32]),
            b"input".to_vec(),
            10,
            100,
            0,
            1337,
            1,
            1000,
        )
        .expect("build tx");
        // Transaction type must be AiInferenceRequest.
        assert!(matches!(tx.tx_type, TransactionType::AiInferenceRequest(_)));
    }

    #[test]
    fn executor_request_from_inference_request() {
        let req = AiInferenceRequest {
            request_id: AiRequestId([1; 32]),
            requester: Address([2; 32]),
            model_id: AiModelId([3; 32]),
            input_commitment: [4; 32],
            input_ref: BoundedBytes::empty(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 1,
            deadline_block: 1000,
        };
        let exec = LubotExecutorRequest::from_inference_request(&req);
        assert_eq!(exec.request_id, AiRequestId([1; 32]));
        assert_eq!(exec.max_fee, 100);
    }
}
