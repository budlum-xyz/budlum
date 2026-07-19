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

/// P5 ADIM10 Bulgu 28: Callback event recorded when an outcome is finalized
/// with a non-empty callback address. These events are queued in the registry
/// and queryable via `bud_aiCallbackQueue` RPC. Off-chain systems poll the
/// queue to deliver inference results to the registered callback address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiCallbackEvent {
    /// The request that was finalized.
    pub request_id: AiRequestId,
    /// The output commitment (hash of the inference result).
    pub output_commitment: [u8; 32],
    /// Block at which the outcome was finalized.
    pub finalized_at_block: u64,
    /// The callback address that should be notified.
    pub callback_address: Address,
}

/// P5 ADIM10 Bulgu 27: Dispute status info for a (request, verifier) pair.
/// Returned by `bud_aiSlashingStatus` RPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiDisputeStatusInfo {
    /// Whether the verifier has an equivocation record for this request.
    pub has_equivocated: bool,
    /// Whether the equivocation is still within the dispute window (slashable).
    pub is_disputable: bool,
    /// The block number when equivocation was detected, if any.
    pub detected_block: Option<u64>,
    /// Remaining blocks until the dispute window expires.
    pub dispute_window_remaining: Option<u64>,
    /// Whether the verifier has staked in the AI verifier stake registry.
    pub is_staked: bool,
    /// The verifier's current staked amount (0 if not staked).
    pub stake_amount: u64,
}

/// P5 ADIM10 Bulgu 27: Verifier stake info for a single address.
/// Returned by `bud_aiVerifierStake` RPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiVerifierStakeInfo {
    /// The verifier address.
    pub verifier: Address,
    /// Whether the verifier has staked.
    pub is_staked: bool,
    /// The current staked amount.
    pub stake_amount: u64,
    /// Total equivocation events for this verifier across all requests.
    pub total_equivocations: usize,
}

/// P5 ADIM11 Bulgu 29: AI Execution Proof — ZKVM-based verifiable inference.
///
/// When a verifier submits a result, they can optionally attach a ZKVM execution
/// proof that cryptographically verifies the inference output was produced by
/// the claimed model on the claimed input. This bridges the gap between "verifier
/// says so" (trust-based) and "mathematics prove it" (trustless) — the core
/// paradigm shift needed for Agentic Economy.
///
/// The proof binds three things:
/// 1. **Model identity** — `model_id` is embedded in the ZKVM program_hash
/// 2. **Input commitment** — `input_commitment` is a public input to the proof
/// 3. **Output commitment** — `output_commitment` is derived from the proof
///
/// Verification: `verify(model_id, input_commitment, output_commitment, proof)`
/// returns true only if the output was produced by the model on the input.
///
/// This is the "AI Execution Layer" that the whitepaper describes as mainnet
/// blocker #5: "Primitiflerin ötesinde AI yürütme katmanı — araştırma/
/// entegrasyon aşamasında."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiExecutionProof {
    /// The model that produced this inference. The ZKVM program_hash must
    /// match this model's registered `model_hash` — this is the cryptographic
    /// binding between the proof and the model.
    pub model_id: AiModelId,
    /// The input commitment that was the preimage to this proof.
    /// This must match the AiInferenceRequest's `input_commitment`.
    pub input_commitment: [u8; 32],
    /// The output commitment derived from the proof execution.
    /// This must match the AiInferenceResult's `output_commitment`.
    pub output_commitment: [u8; 32],
    /// The ZKVM program hash — keccak256 of the model's bytecode.
    /// This binds the proof to a specific model implementation.
    pub program_hash: [u8; 32],
    /// The STARK proof envelope bytes produced by BudZKVM.
    /// Contains the actual mathematical proof that can be verified.
    pub proof_bytes: Vec<u8>,
    /// Number of execution steps in the ZKVM trace.
    pub steps: u64,
    /// Gas used during ZKVM execution.
    pub gas_used: u64,
}

impl AiExecutionProof {
    /// Verify that this proof's commitments match the given request and result.
    /// This is a structural check — cryptographic verification happens in
    /// ZkVmExecutor::verify_proof.
    pub fn commitments_match(
        &self,
        request: &AiInferenceRequest,
        result: &AiInferenceResult,
    ) -> bool {
        self.input_commitment == request.input_commitment
            && self.output_commitment == result.output_commitment
            && self.model_id == request.model_id
    }

    /// Calculate domain-separated hash of this proof for state root inclusion.
    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_AI_EXEC_PROOF_V1");
        hasher.update(self.model_id.0);
        hasher.update(self.input_commitment);
        hasher.update(self.output_commitment);
        hasher.update(self.program_hash);
        hasher.update(self.steps.to_le_bytes());
        hasher.update(self.gas_used.to_le_bytes());
        // Note: proof_bytes is NOT hashed (too large, and the
        // program_hash + commitments already uniquely identify the proof).
        hasher.finalize().into()
    }
}

/// P5 ADIM11 Bulgu 30: Verifier Quality of Service (QoS) reputation.
///
/// In the Agentic Economy paradigm, verifier stake is not just a slashing
/// deposit — it's also a service quality guarantee. Agents selecting verifiers
/// need to know which verifiers are reliable. This struct tracks per-verifier
/// performance metrics that enable QoS-aware verifier selection.
///
/// Future work: verifier selection algorithms will use these metrics to
/// prioritize high-reputation verifiers, creating a market for quality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiVerifierQos {
    /// The verifier address.
    pub verifier: Address,
    /// Total number of inference results submitted.
    pub total_results_submitted: u64,
    /// Number of results that contributed to successful finalization.
    pub successful_finalizations: u64,
    /// Number of equivocation events (slashing events).
    pub equivocation_count: u64,
    /// Average response time in blocks (request submission to result submission).
    /// Computed as sum_of_response_blocks / total_results_submitted.
    pub avg_response_blocks: u64,
    /// Last block at which this verifier submitted a result.
    pub last_active_block: u64,
}

impl AiVerifierQos {
    /// Create a new QoS record with zero metrics.
    pub fn new(verifier: Address) -> Self {
        Self {
            verifier,
            total_results_submitted: 0,
            successful_finalizations: 0,
            equivocation_count: 0,
            avg_response_blocks: 0,
            last_active_block: 0,
        }
    }

    /// Record a successful result submission.
    pub fn record_result(&mut self, response_blocks: u64, current_block: u64) {
        let total = self.total_results_submitted;
        // Running average: new_avg = (old_avg * old_count + new_value) / (old_count + 1)
        self.avg_response_blocks = if total == 0 {
            response_blocks
        } else {
            (self.avg_response_blocks * total + response_blocks) / (total + 1)
        };
        self.total_results_submitted = total + 1;
        self.last_active_block = current_block;
    }

    /// Record participation in a successful finalization.
    pub fn record_finalization(&mut self) {
        self.successful_finalizations = self.successful_finalizations.saturating_add(1);
    }

    /// Record an equivocation event (slashing).
    pub fn record_equivocation(&mut self) {
        self.equivocation_count = self.equivocation_count.saturating_add(1);
    }

    /// Calculate a reliability score (0.0 - 1.0).
    /// Higher is better. Factors in:
    /// - Finalization rate (successful / total)
    /// - Equivocation penalty
    /// - Response time efficiency
    pub fn reliability_score(&self) -> f64 {
        if self.total_results_submitted == 0 {
            return 0.0;
        }
        let finalization_rate =
            self.successful_finalizations as f64 / self.total_results_submitted as f64;
        let equivocation_penalty = (self.equivocation_count as f64 * 0.1).min(1.0);
        (finalization_rate * (1.0 - equivocation_penalty)).max(0.0)
    }

    /// Calculate domain-separated hash for state root inclusion.
    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_AI_VERIFIER_QOS_V1");
        hasher.update(self.verifier.as_bytes());
        hasher.update(self.total_results_submitted.to_le_bytes());
        hasher.update(self.successful_finalizations.to_le_bytes());
        hasher.update(self.equivocation_count.to_le_bytes());
        hasher.update(self.avg_response_blocks.to_le_bytes());
        hasher.update(self.last_active_block.to_le_bytes());
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

/// P5 ADIM11 Bulgu 31: Agent-to-Agent Payment — trustless value transfer
/// between AI agents in the Agentic Economy.
///
/// In the paradigm shift #5 (AI + Blockchain Konverjansı), the core problem
/// is: "AI ajanlarının birbirleriyle ve insanlarla güvenli value transfer
/// yapamaması." This type enables:
///
/// 1. **Inference-linked payments** — agent pays for inference results
///    (request_id binds the payment to a specific AI inference outcome)
/// 2. **Autonomous agent payments** — agent-to-agent value transfer without
///    human intervention (the foundation of Agentic Economy)
/// 3. **Escrow-gated** — payments can be escrowed until a condition is met
///    (e.g., outcome finalization, execution proof verification)
///
/// The payment is atomic: either the full payment succeeds (recipient gets
/// amount, sender loses amount + fee) or it fails (no state change).
///
/// Future: ZKVM verification gate — payment only releases if an
/// AiExecutionProof is attached and verified (trustless settlement).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiAgentPayment {
    /// Unique payment identifier.
    pub payment_id: [u8; 32],
    /// The agent sending the payment.
    pub from_agent: Address,
    /// The agent receiving the payment.
    pub to_agent: Address,
    /// Payment amount in base units.
    pub amount: u64,
    /// Optional: Link to an AI inference request that triggers this payment.
    /// If set, payment is escrowed until the outcome is finalized.
    pub request_id: Option<AiRequestId>,
    /// Optional: Require execution proof for payment release.
    /// If true, the recipient must attach an AiExecutionProof before
    /// the escrowed payment is released — this is the "trustless" path.
    pub require_proof: bool,
    /// Block when this payment was submitted.
    pub submitted_at_block: u64,
    /// Block after which the payment expires (if escrowed and not claimed).
    /// The sender can reclaim expired payments.
    pub expiry_block: u64,
}

impl AiAgentPayment {
    /// Calculate domain-separated hash for state root inclusion.
    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_AI_AGENT_PAYMENT_V1");
        hasher.update(&self.payment_id);
        hasher.update(self.from_agent.as_bytes());
        hasher.update(self.to_agent.as_bytes());
        hasher.update(self.amount.to_le_bytes());
        if let Some(ref rid) = self.request_id {
            hasher.update(b"rid");
            hasher.update(rid.0);
        } else {
            hasher.update(b"no_rid");
        }
        hasher.update(if self.require_proof { [1u8] } else { [0u8] });
        hasher.update(self.submitted_at_block.to_le_bytes());
        hasher.update(self.expiry_block.to_le_bytes());
        hasher.finalize().into()
    }

    /// Check if this payment is escrowed (linked to a request).
    pub fn is_escrowed(&self) -> bool {
        self.request_id.is_some()
    }

    /// Check if this payment has expired.
    pub fn is_expired(&self, current_block: u64) -> bool {
        current_block > self.expiry_block
    }
}

/// P5 ADIM11 Bulgu 34: Agent Reputation Score — Agentic Economy primitive.
///
/// In the paradigm shift #5, agents need to build trust through verifiable
/// track records. This struct tracks an agent's reputation across multiple
/// dimensions: payment reliability, inference quality, and uptime.
///
/// Reputation is the currency of trust in the Agentic Economy — an agent
/// with high reputation can command higher fees and attract more requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiAgentReputation {
    /// The agent's address.
    pub agent: Address,
    /// Total successful payments (as payer).
    pub payments_completed: u64,
    /// Total payments defaulted/expired.
    pub payments_defaulted: u64,
    /// Total inference requests submitted.
    pub requests_submitted: u64,
    /// Total inference results submitted (as verifier).
    pub results_submitted: u64,
    /// Total results that contributed to finalization.
    pub results_finalized: u64,
    /// Total equivocations detected.
    pub equivocations: u64,
    /// Total blocks active (from first to last activity).
    pub active_block_span: u64,
    /// First block with activity.
    pub first_active_block: u64,
    /// Last block with activity.
    pub last_active_block: u64,
}

impl AiAgentReputation {
    /// Create a new reputation record.
    pub fn new(agent: Address) -> Self {
        Self {
            agent,
            payments_completed: 0,
            payments_defaulted: 0,
            requests_submitted: 0,
            results_submitted: 0,
            results_finalized: 0,
            equivocations: 0,
            active_block_span: 0,
            first_active_block: 0,
            last_active_block: 0,
        }
    }

    /// Record a completed payment.
    pub fn record_payment_completed(&mut self, current_block: u64) {
        self.payments_completed = self.payments_completed.saturating_add(1);
        self.update_activity(current_block);
    }

    /// Record a defaulted/expired payment.
    pub fn record_payment_defaulted(&mut self, current_block: u64) {
        self.payments_defaulted = self.payments_defaulted.saturating_add(1);
        self.update_activity(current_block);
    }

    /// Record an inference request submission.
    pub fn record_request(&mut self, current_block: u64) {
        self.requests_submitted = self.requests_submitted.saturating_add(1);
        self.update_activity(current_block);
    }

    /// Update activity tracking.
    fn update_activity(&mut self, current_block: u64) {
        if self.first_active_block == 0 {
            self.first_active_block = current_block;
        }
        self.last_active_block = current_block;
        self.active_block_span = current_block.saturating_sub(self.first_active_block);
    }

    /// Calculate the agent's trust score (0.0 - 1.0).
    /// Factors in payment reliability, inference quality, and equivocation rate.
    pub fn trust_score(&self) -> f64 {
        if self.payments_completed + self.payments_defaulted == 0 && self.results_submitted == 0 {
            return 0.0;
        }

        // Payment reliability (0.0 - 1.0)
        let total_payments = self.payments_completed + self.payments_defaulted;
        let payment_reliability = if total_payments > 0 {
            self.payments_completed as f64 / total_payments as f64
        } else {
            1.0 // no payments → no data → neutral
        };

        // Inference quality (0.0 - 1.0)
        let inference_quality = if self.results_submitted > 0 {
            let finalization_rate = self.results_finalized as f64 / self.results_submitted as f64;
            let equivocation_penalty = (self.equivocations as f64 * 0.15).min(1.0);
            finalization_rate * (1.0 - equivocation_penalty)
        } else {
            1.0 // no results → neutral
        };

        // Weighted combination: 40% payment, 60% inference
        (payment_reliability * 0.4 + inference_quality * 0.6)
            .max(0.0)
            .min(1.0)
    }

    /// Calculate domain-separated hash for state root inclusion.
    pub fn calculate_leaf(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_AI_AGENT_REPUTATION_V1");
        hasher.update(self.agent.as_bytes());
        hasher.update(self.payments_completed.to_le_bytes());
        hasher.update(self.payments_defaulted.to_le_bytes());
        hasher.update(self.requests_submitted.to_le_bytes());
        hasher.update(self.results_submitted.to_le_bytes());
        hasher.update(self.results_finalized.to_le_bytes());
        hasher.update(self.equivocations.to_le_bytes());
        hasher.update(self.active_block_span.to_le_bytes());
        hasher.finalize().into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiPaymentEscrowStatus {
    /// Payment is escrowed, waiting for condition (outcome finalization / proof).
    Pending,
    /// Payment released to recipient (condition met).
    Released,
    /// Payment reclaimed by sender (expired or cancelled).
    Reclaimed,
}
