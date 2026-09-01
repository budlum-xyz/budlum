//! The executor and transaction integration.
//!
//! An AI inference layer inference request is carried to the executor as a
//! `TransactionType::AiInferenceRequest`. The executor
//! (src/execution/executor.rs:723) already handles the whole flow: Pollen
//! grant verification, the balance check, ai_registry.submit_request, grant
//! consumption and the fee deduction. This module builds the transaction the
//! user has to send.

use crate::ai::types::{AiInferenceRequest, AiModelId, AiRequestId};
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};

use super::inference;

/// The AI inference layer transaction request to be sent to the executor (the metadata
/// seam).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AiExecutorRequest {
    pub request_id: AiRequestId,
    pub requester: Address,
    pub max_fee: u64,
    pub deadline_block: u64,
}

impl AiExecutorRequest {
    /// Build the executor-ready form from an AiInferenceRequest.
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

/// Build an AI inference layer inference transaction (the form to send to the executor).
///
/// The executor handles this transaction as a
/// `TransactionType::AiInferenceRequest`: (1) Pollen grant verification
/// (closed-circuit), (2) the balance check, (3) the ai_registry submit,
/// (4) grant consumption, (5) the fee plus max_fee deduction.
///
/// The first item now holds here as well: `grant` is a mandatory argument and
/// it is verified before the request is built. Previously this sentence only
/// described work the executor would do, and an unauthorised request object
/// looked valid until it got there.
///
/// # Errors
///
/// A message saying which condition failed when the authorisation is not
/// valid.
#[allow(clippy::too_many_arguments)]
pub fn build_ai_transaction(
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
    grant: &crate::pollen::data_rights::AccessGrant,
    perception: Option<crate::ai_inference::perception::PerceptionRequest>,
) -> Result<Transaction, String> {
    let req = inference::build_ai_request(
        from,
        model_id,
        input_data.clone(),
        max_fee,
        current_block,
        deadline_block,
        grant,
        perception,
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
    use crate::ai::types::BoundedBytes;

    #[test]
    fn build_ai_tx_produces_ai_inference_type() {
        let from = Address([1; 32]);
        let grant = crate::pollen::data_rights::AccessGrant::new_unsigned(
            crate::pollen::AssetId([9; 32]),
            Address([8; 32]),
            from,
            from,
            0,
            1,
            10_000,
            100,
            [0; 32],
        );
        let tx = build_ai_transaction(
            from,
            Address([2; 32]),
            AiModelId([3; 32]),
            b"input".to_vec(),
            10,
            100,
            0,
            45262,
            1,
            1000,
            &grant,
            None,
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
            effort: crate::ai_inference::effort::EffortTier::default(),
            perception: None,
        };
        let exec = AiExecutorRequest::from_inference_request(&req);
        assert_eq!(exec.request_id, AiRequestId([1; 32]));
        assert_eq!(exec.max_fee, 100);
    }
}
