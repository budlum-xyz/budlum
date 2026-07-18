//! Canonical AI Inference Layer Types (`Phase 10`, `Bölüm 1`).
//!
//! Provides deterministic model registry specifications, bounded execution reference
//! payloads, attestation request/result primitives, and consensus agreement outcomes.

use crate::core::address::Address;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum allowed byte size for `input_ref` or `output_ref` payloads (`64 KiB`).
/// Prevents state/mempool/snapshot DoS vectors via oversize inference references.
pub const MAX_INFERENCE_REF_BYTES: usize = 65_536;

/// Domain-separated AI Model Identifier (`[u8; 32]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AiModelId(pub [u8; 32]);

impl AiModelId {
    pub fn new(id: [u8; 32]) -> Self {
        Self(id)
    }

    /// Compute canonical model id given owner address and model hash/preimage bytes.
    pub fn of(owner: &Address, model_hash: &[u8; 32], version: u32) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_AI_MODEL_V1");
        hasher.update(owner.as_bytes());
        hasher.update(model_hash);
        hasher.update(version.to_le_bytes());
        AiModelId(hasher.finalize().into())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Default for AiModelId {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

/// Canonical AI Inference Request Identifier (`[u8; 32]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AiRequestId(pub [u8; 32]);

impl AiRequestId {
    pub fn new(id: [u8; 32]) -> Self {
        Self(id)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Default for AiRequestId {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

/// Canonical AI Inference Result Identifier (`[u8; 32]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AiResultId(pub [u8; 32]);

impl AiResultId {
    pub fn new(id: [u8; 32]) -> Self {
        Self(id)
    }
}

impl Default for AiResultId {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

/// Bounded byte wrapper verifying length bounds (`<= MAX_INFERENCE_REF_BYTES`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BoundedBytes(pub Vec<u8>);

impl BoundedBytes {
    pub fn try_new(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() > MAX_INFERENCE_REF_BYTES {
            return Err(format!(
                "Payload length {} exceeds maximum allowed {}",
                bytes.len(),
                MAX_INFERENCE_REF_BYTES
            ));
        }
        Ok(Self(bytes))
    }

    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Default for BoundedBytes {
    fn default() -> Self {
        Self::empty()
    }
}

/// AI Model Specification registered on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiModelSpec {
    pub model_id: AiModelId,
    pub model_hash: [u8; 32],
    pub owner: Address,
    pub min_verifier_count: u32,
    pub agreement_threshold: u32,
    pub max_input_ref_bytes: u64,
    pub max_output_ref_bytes: u64,
    pub request_deadline_blocks: u64,
    pub result_deadline_blocks: u64,
    pub version: u32,
    pub active: bool,
}

impl AiModelSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.min_verifier_count == 0 {
            return Err("min_verifier_count must be >= 1".into());
        }
        if self.agreement_threshold == 0 || self.agreement_threshold > self.min_verifier_count {
            return Err("agreement_threshold must be between 1 and min_verifier_count".into());
        }
        if self.max_input_ref_bytes > MAX_INFERENCE_REF_BYTES as u64 {
            return Err(format!(
                "max_input_ref_bytes exceeds allowed maximum {}",
                MAX_INFERENCE_REF_BYTES
            ));
        }
        if self.max_output_ref_bytes > MAX_INFERENCE_REF_BYTES as u64 {
            return Err(format!(
                "max_output_ref_bytes exceeds allowed maximum {}",
                MAX_INFERENCE_REF_BYTES
            ));
        }
        if self.request_deadline_blocks == 0 || self.result_deadline_blocks == 0 {
            return Err("Deadlines must be >= 1 block".into());
        }
        Ok(())
    }

    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_AI_SPEC_LEAF_V1");
        hasher.update(self.model_id.0);
        hasher.update(self.model_hash);
        hasher.update(self.owner.as_bytes());
        hasher.update(self.min_verifier_count.to_le_bytes());
        hasher.update(self.agreement_threshold.to_le_bytes());
        hasher.update(self.max_input_ref_bytes.to_le_bytes());
        hasher.update(self.max_output_ref_bytes.to_le_bytes());
        hasher.update(self.request_deadline_blocks.to_le_bytes());
        hasher.update(self.result_deadline_blocks.to_le_bytes());
        hasher.update(self.version.to_le_bytes());
        hasher.update([u8::from(self.active)]);
        hasher.finalize().into()
    }
}

/// AI Inference Request submitted by a user/contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiInferenceRequest {
    pub request_id: AiRequestId,
    pub requester: Address,
    pub model_id: AiModelId,
    pub input_commitment: [u8; 32],
    pub input_ref: BoundedBytes,
    pub max_fee: u64,
    pub callback: Option<Address>,
    pub submitted_at_block: u64,
    pub deadline_block: u64,
}

impl AiInferenceRequest {
    pub fn calculate_id(&self) -> AiRequestId {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_AI_REQUEST_ID_V1");
        hasher.update(self.requester.as_bytes());
        hasher.update(self.model_id.0);
        hasher.update(self.input_commitment);
        hasher.update(self.input_ref.as_slice());
        hasher.update(self.max_fee.to_le_bytes());
        if let Some(ref cb) = self.callback {
            hasher.update(b"cb");
            hasher.update(cb.as_bytes());
        } else {
            hasher.update(b"no_cb");
        }
        hasher.update(self.submitted_at_block.to_le_bytes());
        hasher.update(self.deadline_block.to_le_bytes());
        AiRequestId(hasher.finalize().into())
    }

    pub fn verify_id(&self) -> bool {
        self.request_id == self.calculate_id()
    }

    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_AI_REQUEST_LEAF_V1");
        hasher.update(self.request_id.0);
        hasher.update(self.calculate_id().0);
        hasher.finalize().into()
    }
}

/// AI Inference Attestation Result submitted by a registered `RoleId::AiVerifier`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiInferenceResult {
    pub request_id: AiRequestId,
    pub verifier: Address,
    pub output_commitment: [u8; 32],
    pub output_ref: BoundedBytes,
    pub result_nonce: u64,
    pub signature: Vec<u8>,
    pub submitted_at_block: u64,
}

impl AiInferenceResult {
    pub fn calculate_signing_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_AI_RESULT_SIG_V1");
        hasher.update(self.request_id.0);
        hasher.update(self.verifier.as_bytes());
        hasher.update(self.output_commitment);
        hasher.update(self.output_ref.as_slice());
        hasher.update(self.result_nonce.to_le_bytes());
        hasher.update(self.submitted_at_block.to_le_bytes());
        hasher.finalize().into()
    }

    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_AI_RESULT_LEAF_V1");
        hasher.update(self.request_id.0);
        hasher.update(self.verifier.as_bytes());
        hasher.update(self.output_commitment);
        hasher.update(self.output_ref.as_slice());
        hasher.update(self.result_nonce.to_le_bytes());
        hasher.update(self.submitted_at_block.to_le_bytes());
        hasher.finalize().into()
    }
}

/// Finalized Consensus Outcome reaching agreement threshold among verifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiInferenceOutcome {
    pub request_id: AiRequestId,
    pub output_commitment: [u8; 32],
    pub output_ref: BoundedBytes,
    pub agreeing_verifiers: Vec<Address>,
    pub finalized_at_block: u64,
    /// P5 Bulgu 7: Callback address from the original request.
    /// Set during finalization so consumers (RPC, event listeners) know
    /// who to notify about the completed inference.
    pub callback: Option<Address>,
}

impl AiInferenceOutcome {
    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_AI_OUTCOME_LEAF_V1");
        hasher.update(self.request_id.0);
        hasher.update(self.output_commitment);
        hasher.update(self.output_ref.as_slice());
        for verifier in &self.agreeing_verifiers {
            hasher.update(verifier.as_bytes());
        }
        hasher.update(self.finalized_at_block.to_le_bytes());
        if let Some(ref cb) = self.callback {
            hasher.update(b"cb");
            hasher.update(cb.as_bytes());
        } else {
            hasher.update(b"no_cb");
        }
        hasher.finalize().into()
    }
}
