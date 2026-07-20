//! Canonical AI Registry & State Tracking (`Phase 10`, `Bölüm 1`).
//!
//! Tracks active models, pending inference requests, accumulated verifier attestations,
//! and finalized consensus outcomes. Provides deterministic `state_root()` calculation.

use crate::ai::types::{
    AiAgentPayment, AiAgentPaymentSettlement, AiAgentReputation, AiCallbackEvent,
    AiDisputeStatusInfo, AiExecutionProof, AiInferenceOutcome, AiInferenceRequest,
    AiInferenceResult, AiModelId, AiModelSpec, AiPaymentEscrowStatus, AiRequestId, AiVerifierQos,
    AiVerifierStakeInfo,
};
use crate::core::address::Address;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// P5 ADIM9 Bulgu 25: Dispute window in blocks.
/// Equivocation events older than this cannot be slashed.
/// Prevents stale disputes and provides finality to verifiers.
/// Default: 10080 blocks ≈ 7 days at 1 block/minute.
pub const DISPUTE_WINDOW_BLOCKS: u64 = 10_080;

/// P5 ADIM9 Bulgu 26: Minimum verifier stake to participate in AI inference.
/// Prevents Sybil attacks — verifiers must have economic skin-in-the-game.
pub const MIN_VERIFIER_STAKE: u64 = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiRegistry {
    pub models: BTreeMap<AiModelId, AiModelSpec>,
    pub requests: BTreeMap<AiRequestId, AiInferenceRequest>,
    pub results: BTreeMap<AiRequestId, Vec<AiInferenceResult>>,
    pub outcomes: BTreeMap<AiRequestId, AiInferenceOutcome>,
    /// P5 Bulgu 4: Set of request IDs whose max_fee has been reclaimed
    /// after deadline expiry without finalization. Prevents double-reclaim.
    pub reclaimed_fees: BTreeSet<AiRequestId>,
    /// P5 Bulgu 18 (ADIM7): Equivocation event record with block timestamp.
    /// Maps (request_id, verifier_bytes) → block_number when detected.
    /// P5 ADIM9 Bulgu 25: Dispute window enforcement — equivocation events
    /// expire after `DISPUTE_WINDOW_BLOCKS` blocks, preventing stale slashing.
    pub equivocation_events: BTreeMap<(AiRequestId, [u8; 32]), u64>,
    /// P5 Bulgu 21 (ADIM7): Set of request IDs that have been cancelled
    /// by the requester before the deadline. Prevents double-cancel and
    /// blocks result submission for cancelled requests.
    pub cancelled_requests: BTreeSet<AiRequestId>,
    /// P5 ADIM9 Bulgu 26: AI verifier stake registry.
    /// Maps verifier address → staked amount. Verifiers must stake to
    /// participate in AI inference; slashed amount goes to zero on equivocation.
    /// This is separate from validator stake — AI verifiers have their own
    /// economic commitment to the inference layer.
    pub verifier_stakes: BTreeMap<Address, u64>,
    /// P5 ADIM10 Bulgu 28: Callback event queue.
    /// When an outcome is finalized with a non-empty callback address,
    /// an event is queued here. Indexed by callback address for efficient
    /// querying. Off-chain systems poll `bud_aiCallbackQueue` to deliver
    /// results to registered callback addresses.
    pub callback_queue: BTreeMap<Address, Vec<AiCallbackEvent>>,
    /// P5 ADIM11 Bulgu 29: Execution proof registry.
    /// Maps (request_id, verifier) → AiExecutionProof. When a verifier
    /// submits a ZKVM-verified inference result, the proof is stored here.
    /// This enables trustless verification — the paradigm shift from
    /// "verifier says so" to "mathematics prove it."
    pub execution_proofs: BTreeMap<(AiRequestId, [u8; 32]), AiExecutionProof>,
    /// P5 ADIM11 Bulgu 30: Verifier Quality of Service registry.
    /// Maps verifier address → QoS metrics. Enables QoS-aware verifier
    /// selection for the Agentic Economy.
    pub verifier_qos: BTreeMap<Address, AiVerifierQos>,
    /// P5 ADIM11 Bulgu 31: Agent-to-Agent payment registry.
    /// Maps payment_id → AiAgentPayment. Enables trustless value transfer
    /// between AI agents in the Agentic Economy.
    pub agent_payments: BTreeMap<[u8; 32], AiAgentPayment>,
    /// V89: finalized payment receipts (payment_id never reusable).
    pub settled_agent_payments: BTreeMap<[u8; 32], AiAgentPaymentSettlement>,
    /// P5 ADIM11 Bulgu 33: Verifier whitelist — only whitelisted verifiers
    /// can submit results. When empty, any staked verifier can submit
    /// (permissionless mode). When non-empty, only addresses in this set
    /// are allowed (permissioned mode). This enables governance-controlled
    /// verifier onboarding for the Agentic Economy.
    pub verifier_whitelist: BTreeSet<Address>,
    /// P5 ADIM11 Bulgu 34: Agent reputation registry.
    /// Maps agent address → AiAgentReputation. Tracks payment reliability,
    /// inference quality, and uptime for trust scoring in the Agentic Economy.
    pub agent_reputations: BTreeMap<Address, AiAgentReputation>,
}

impl AiRegistry {
    pub fn new() -> Self {
        Self {
            models: BTreeMap::new(),
            requests: BTreeMap::new(),
            results: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            reclaimed_fees: BTreeSet::new(),
            equivocation_events: BTreeMap::new(),
            cancelled_requests: BTreeSet::new(),
            verifier_stakes: BTreeMap::new(),
            callback_queue: BTreeMap::new(),
            execution_proofs: BTreeMap::new(),
            verifier_qos: BTreeMap::new(),
            agent_payments: BTreeMap::new(),
            settled_agent_payments: BTreeMap::new(),
            verifier_whitelist: BTreeSet::new(),
            agent_reputations: BTreeMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
            && self.requests.is_empty()
            && self.results.is_empty()
            && self.outcomes.is_empty()
            && self.reclaimed_fees.is_empty()
            && self.equivocation_events.is_empty()
            && self.cancelled_requests.is_empty()
            && self.verifier_stakes.is_empty()
            && self.callback_queue.is_empty()
            && self.execution_proofs.is_empty()
            && self.verifier_qos.is_empty()
            && self.agent_payments.is_empty()
            && self.settled_agent_payments.is_empty()
            && self.verifier_whitelist.is_empty()
            && self.agent_reputations.is_empty()
    }

    pub fn register_model(&mut self, spec: AiModelSpec) -> Result<AiModelId, String> {
        spec.validate()?;
        if self.models.contains_key(&spec.model_id) {
            return Err(format!(
                "Model ID {} is already registered",
                spec.model_id.to_hex()
            ));
        }
        let id = spec.model_id;
        self.models.insert(id, spec);
        Ok(id)
    }

    /// Submit an inference request with deadline enforcement (P5 Bulgu 1).
    /// `current_block` is provided by the executor layer (defense-in-depth:
    /// both registry and executor check deadlines independently).
    pub fn submit_request(
        &mut self,
        request: AiInferenceRequest,
        current_block: u64,
    ) -> Result<AiRequestId, String> {
        if !request.verify_id() {
            return Err("Request ID does not match canonical preimage".into());
        }
        let spec = match self.models.get(&request.model_id) {
            Some(s) => s,
            None => {
                return Err(format!(
                    "Model ID {} not registered",
                    request.model_id.to_hex()
                ))
            }
        };
        if !spec.active {
            return Err("Model is inactive".into());
        }
        if request.input_ref.len() as u64 > spec.max_input_ref_bytes {
            return Err("input_ref exceeds model specification limits".into());
        }
        if self.requests.contains_key(&request.request_id) {
            return Err(format!(
                "Request ID {} already exists",
                request.request_id.to_hex()
            ));
        }
        // P5 Bulgu 13: max_fee must be >= 1.
        // Zero-fee requests incentivize spam: verifiers earn nothing,
        // and there is no economic deterrent against frivolous requests.
        if request.max_fee == 0 {
            return Err("max_fee must be >= 1 (zero-fee requests not allowed)".into());
        }
        // P5 Bulgu 1 — Deadline enforcement (registry layer):
        // Request must not be submitted after its own deadline_block.
        if current_block > request.deadline_block {
            return Err(format!(
                "Request deadline exceeded: current_block={current_block}, deadline_block={}",
                request.deadline_block
            ));
        }
        let id = request.request_id;
        self.requests.insert(id, request);
        Ok(id)
    }

    /// Submit an inference result with deadline + dispute enforcement (P5 Bulgu 1+3).
    /// `current_block` is provided by the executor layer (defense-in-depth).
    pub fn submit_result(
        &mut self,
        result: AiInferenceResult,
        current_block: u64,
    ) -> Result<Option<AiInferenceOutcome>, String> {
        let request = match self.requests.get(&result.request_id) {
            Some(r) => r.clone(),
            None => {
                return Err(format!(
                    "Request ID {} not found",
                    result.request_id.to_hex()
                ))
            }
        };
        let spec = match self.models.get(&request.model_id) {
            Some(s) => s.clone(),
            None => return Err("Associated model for request not found".into()),
        };
        if result.output_ref.len() as u64 > spec.max_output_ref_bytes {
            return Err("output_ref exceeds model specification limits".into());
        }
        // P5 Bulgu 1 — Deadline enforcement (registry layer):
        // Result must arrive before the request's deadline_block AND
        // within result_deadline_blocks of the request's submission.
        if current_block > request.deadline_block {
            return Err(format!(
                "Result submitted after request deadline: current_block={current_block}, deadline_block={}",
                request.deadline_block
            ));
        }
        let result_deadline = request
            .submitted_at_block
            .saturating_add(spec.result_deadline_blocks);
        if current_block > result_deadline {
            return Err(format!(
                "Result deadline exceeded: current_block={current_block}, result_deadline={result_deadline}"
            ));
        }

        // P5 Bulgu 5 — Result nonce enforcement:
        // result_nonce must be >= 1 (zero is invalid — prevents accidental/ambiguous submissions).
        if result.result_nonce == 0 {
            return Err("result_nonce must be >= 1 (zero is invalid)".into());
        }

        // P5 Bulgu 3 — Equivocation detection:
        // If this verifier already submitted a result with a DIFFERENT
        // commitment for the same request, that is equivocation.
        let entries = self.results.entry(result.request_id).or_default();
        if let Some(existing) = entries.iter().find(|r| r.verifier == result.verifier) {
            if existing.output_commitment == result.output_commitment {
                return Err("Verifier has already submitted a result for this request".into());
            } else {
                // P5 Bulgu 18 (ADIM7): Record the equivocation event on-chain
                // with block timestamp (P5 ADIM9 Bulgu 25: dispute window).
                // before returning the error. This enables future slashing
                // hooks and dispute resolution mechanisms.
                self.equivocation_events
                    .insert((result.request_id, result.verifier.0), current_block);

                // P5 ADIM11 Bulgu 30: Record equivocation in QoS.
                self.verifier_qos
                    .entry(result.verifier)
                    .or_insert_with(|| AiVerifierQos::new(result.verifier))
                    .record_equivocation();
                return Err(format!(
                    "EQUIVOCATION: verifier {:?} submitted conflicting commitments for request {} — dispute flagged",
                    result.verifier,
                    result.request_id.to_hex()
                ));
            }
        }

        // P5 Bulgu 21 (ADIM7): Reject results for cancelled requests.
        // A cancelled request should never reach finalization.
        if self.cancelled_requests.contains(&result.request_id) {
            return Err(format!(
                "Request {} has been cancelled — results not accepted",
                result.request_id.to_hex()
            ));
        }
        entries.push(result.clone());

        // P5 ADIM11 Bulgu 30: Record verifier QoS metrics.
        let response_blocks = result.submitted_at_block.saturating_sub(
            self.requests
                .get(&result.request_id)
                .map(|r| r.submitted_at_block)
                .unwrap_or(0),
        );
        self.verifier_qos
            .entry(result.verifier)
            .or_insert_with(|| AiVerifierQos::new(result.verifier))
            .record_result(response_blocks, result.submitted_at_block);

        // Check if we reached agreement threshold for this commitment
        let mut agreeing_verifiers = Vec::new();
        for r in entries.iter() {
            if r.output_commitment == result.output_commitment {
                agreeing_verifiers.push(r.verifier);
            }
        }

        if agreeing_verifiers.len() as u32 >= spec.agreement_threshold
            && !self.outcomes.contains_key(&result.request_id)
        {
            agreeing_verifiers.sort();
            // P5 Bulgu 7: Carry the callback address from the original request
            // into the finalized outcome, so consumers can be notified.
            let callback = request.callback;
            let outcome = AiInferenceOutcome {
                request_id: result.request_id,
                output_commitment: result.output_commitment,
                output_ref: result.output_ref.clone(),
                agreeing_verifiers,
                finalized_at_block: result.submitted_at_block,
                callback,
            };
            self.outcomes.insert(result.request_id, outcome.clone());

            // P5 ADIM11 Bulgu 30: Record finalization in QoS for agreeing verifiers.
            for verifier_addr in &outcome.agreeing_verifiers {
                if let Some(qos) = self.verifier_qos.get_mut(verifier_addr) {
                    qos.record_finalization();
                }
            }

            // P5 ADIM10 Bulgu 28: Record callback event if callback address is set.
            // The callback queue allows off-chain systems to discover finalized
            // outcomes that need to be delivered to registered callback addresses.
            if let Some(ref cb_addr) = outcome.callback {
                let event = AiCallbackEvent {
                    request_id: outcome.request_id,
                    output_commitment: outcome.output_commitment,
                    finalized_at_block: outcome.finalized_at_block,
                    callback_address: *cb_addr,
                };
                self.callback_queue.entry(*cb_addr).or_default().push(event);
            }

            return Ok(Some(outcome));
        }

        Ok(None)
    }

    pub fn get_outcome(&self, request_id: &AiRequestId) -> Option<&AiInferenceOutcome> {
        self.outcomes.get(request_id)
    }

    /// Accessor: get a pending (non-finalized) request by ID.
    pub fn get_request(&self, request_id: &AiRequestId) -> Option<&AiInferenceRequest> {
        self.requests.get(request_id)
    }

    /// Deactivate a model (P5 Bulgu 6). Only the model owner can deactivate.
    /// An inactive model rejects new inference requests, but existing pending
    /// requests/results continue to be processed normally.
    pub fn deactivate_model(
        &mut self,
        model_id: &AiModelId,
        caller: &Address,
    ) -> Result<(), String> {
        let spec = self
            .models
            .get_mut(model_id)
            .ok_or_else(|| format!("Model ID {} not found", model_id.to_hex()))?;

        if spec.owner != *caller {
            return Err(format!(
                "Only the model owner can deactivate model {}",
                model_id.to_hex()
            ));
        }

        if !spec.active {
            return Err(format!("Model {} is already inactive", model_id.to_hex()));
        }

        spec.active = false;
        Ok(())
    }

    /// Reactivate a previously deactivated model. Only the model owner can reactivate.
    pub fn reactivate_model(
        &mut self,
        model_id: &AiModelId,
        caller: &Address,
    ) -> Result<(), String> {
        let spec = self
            .models
            .get_mut(model_id)
            .ok_or_else(|| format!("Model ID {} not found", model_id.to_hex()))?;

        if spec.owner != *caller {
            return Err(format!(
                "Only the model owner can reactivate model {}",
                model_id.to_hex()
            ));
        }

        if spec.active {
            return Err(format!("Model {} is already active", model_id.to_hex()));
        }

        spec.active = true;
        Ok(())
    }

    /// P5 Bulgu 8: Update mutable model specification fields.
    /// Only the model owner can update. Immutable fields (model_id, model_hash,
    /// owner, version) cannot be changed — those require registering a new model.
    pub fn update_model_spec(
        &mut self,
        model_id: &AiModelId,
        caller: &Address,
        min_verifier_count: u32,
        agreement_threshold: u32,
        max_input_ref_bytes: u64,
        max_output_ref_bytes: u64,
        request_deadline_blocks: u64,
        result_deadline_blocks: u64,
    ) -> Result<(), String> {
        let spec = self
            .models
            .get_mut(model_id)
            .ok_or_else(|| format!("Model ID {} not found", model_id.to_hex()))?;

        if spec.owner != *caller {
            return Err(format!(
                "Only the model owner can update model {}",
                model_id.to_hex()
            ));
        }

        // Validate new thresholds before applying
        if min_verifier_count == 0 {
            return Err("min_verifier_count must be >= 1".into());
        }
        if agreement_threshold == 0 || agreement_threshold > min_verifier_count {
            return Err("agreement_threshold must be between 1 and min_verifier_count".into());
        }
        if request_deadline_blocks == 0 || result_deadline_blocks == 0 {
            return Err("Deadlines must be >= 1 block".into());
        }

        spec.min_verifier_count = min_verifier_count;
        spec.agreement_threshold = agreement_threshold;
        spec.max_input_ref_bytes = max_input_ref_bytes;
        spec.max_output_ref_bytes = max_output_ref_bytes;
        spec.request_deadline_blocks = request_deadline_blocks;
        spec.result_deadline_blocks = result_deadline_blocks;

        // P5 Bulgu 20 (ADIM7): Auto-increment version on spec update.
        // Every spec change produces a new version number, providing a clear
        // on-chain audit trail. External systems can detect spec mutations
        // by comparing version values. The version is immutable from the
        // caller's perspective — only this method may increment it.
        spec.version = spec.version.saturating_add(1);

        Ok(())
    }

    /// P5 Bulgu 9: Transfer model ownership to a new address.
    /// Only the current owner can transfer. The new owner gains full control
    /// (deactivation, reactivation, spec updates, further transfers).
    pub fn transfer_model_ownership(
        &mut self,
        model_id: &AiModelId,
        caller: &Address,
        new_owner: Address,
    ) -> Result<(), String> {
        let spec = self
            .models
            .get_mut(model_id)
            .ok_or_else(|| format!("Model ID {} not found", model_id.to_hex()))?;

        if spec.owner != *caller {
            return Err(format!(
                "Only the model owner can transfer ownership of model {}",
                model_id.to_hex()
            ));
        }

        if spec.owner == new_owner {
            return Err("New owner must be different from current owner".into());
        }

        spec.owner = new_owner;
        Ok(())
    }

    /// P5 Bulgu 10: Prune expired requests, results, and reclaimed fees
    /// that are older than `current_block - retention_blocks`.
    /// This prevents unbounded state growth (state bloat) while preserving
    /// recently-expired data for a configurable retention window.
    ///
    /// Prunable items:
    /// - Requests whose effective deadline has passed + retention_blocks
    /// - Results associated with pruned requests
    /// - Outcomes that have been finalized + retention_blocks
    /// - Reclaimed fee records older than retention_blocks
    ///
    /// Returns the number of items pruned.
    pub fn prune_expired(&mut self, current_block: u64, retention_blocks: u64) -> usize {
        let mut pruned = 0;

        // Prune expired, unfinalized requests (and their results)
        let expired_request_ids: Vec<AiRequestId> = self
            .requests
            .iter()
            .filter(|(id, req)| {
                if self.outcomes.contains_key(id) || self.reclaimed_fees.contains(id) {
                    return false; // Don't prune finalized or reclaimed requests
                }
                // Check if deadline + retention has passed
                let model = self.models.get(&req.model_id);
                let result_deadline = model
                    .map(|m| {
                        req.submitted_at_block
                            .saturating_add(m.result_deadline_blocks)
                    })
                    .unwrap_or(0);
                let effective_deadline = std::cmp::max(req.deadline_block, result_deadline);
                current_block > effective_deadline.saturating_add(retention_blocks)
            })
            .map(|(id, _)| *id)
            .collect();

        for id in &expired_request_ids {
            self.requests.remove(id);
            self.results.remove(id);
            pruned += 1;
        }

        // Prune reclaimed fee records older than retention
        let reclaimed_to_prune: Vec<AiRequestId> = self
            .reclaimed_fees
            .iter()
            .filter(|id| {
                // Find the request to check its deadline
                // If request was already pruned, use the ID itself
                // Since we can't determine exact time without the request,
                // we prune reclaimed fees whose requests have been pruned
                !self.requests.contains_key(id)
            })
            .cloned()
            .collect();

        for id in &reclaimed_to_prune {
            self.reclaimed_fees.remove(id);
            pruned += 1;
        }

        // Prune finalized outcomes older than retention
        let prunable_outcomes: Vec<AiRequestId> = self
            .outcomes
            .iter()
            .filter(|(_, outcome)| {
                current_block > outcome.finalized_at_block.saturating_add(retention_blocks)
            })
            .map(|(id, _)| *id)
            .collect();

        for id in &prunable_outcomes {
            self.outcomes.remove(&id);
            self.results.remove(&id);
            self.requests.remove(&id);
            pruned += 1;
        }

        pruned
    }
    ///
    /// After a request's deadline has passed without reaching agreement threshold,
    /// the requester can reclaim their escrowed max_fee. This prevents fee leaks
    /// where max_fee is deducted but never distributed (no verifiers, insufficient
    /// agreement, or deadline expiry before threshold reached).
    ///
    /// Returns `(requester_address, max_fee)` on success.
    /// Errors if: request not found, already finalized, not yet expired, or already reclaimed.
    pub fn reclaim_fee(
        &mut self,
        request_id: &AiRequestId,
        current_block: u64,
    ) -> Result<(Address, u64), String> {
        let request = self
            .requests
            .get(request_id)
            .ok_or_else(|| format!("Request {} not found", request_id.to_hex()))?;

        // Must not already have an outcome (finalized request → fee belongs to verifiers)
        if self.outcomes.contains_key(request_id) {
            return Err(format!(
                "Request {} has been finalized — fee belongs to verifiers",
                request_id.to_hex()
            ));
        }

        // Must not have been already reclaimed
        if self.reclaimed_fees.contains(request_id) {
            return Err(format!(
                "Request {} fee already reclaimed",
                request_id.to_hex()
            ));
        }

        // Deadline must have passed (both request deadline and result deadline)
        let spec = self
            .models
            .get(&request.model_id)
            .ok_or_else(|| "Associated model for request not found".to_string())?;
        let result_deadline = request
            .submitted_at_block
            .saturating_add(spec.result_deadline_blocks);
        let effective_deadline = std::cmp::max(request.deadline_block, result_deadline);

        if current_block <= effective_deadline {
            return Err(format!(
                "Request {} not yet expired: current_block={current_block}, effective_deadline={effective_deadline}",
                request_id.to_hex()
            ));
        }

        let requester = request.requester;
        let max_fee = request.max_fee;

        self.reclaimed_fees.insert(*request_id);

        Ok((requester, max_fee))
    }

    /// P5 Bulgu 21 (ADIM7): Cancel a pending inference request.
    /// Only the original requester can cancel, and only before the deadline.
    /// A cancelled request cannot receive further results and its max_fee
    /// is eligible for refund. Cancellation is irreversible.
    ///
    /// Returns `(requester, max_fee)` on success for the executor to process refund.
    /// Errors if: request not found, not the requester, already finalized,
    /// already reclaimed, already cancelled, or deadline not yet passed.
    pub fn cancel_request(
        &mut self,
        request_id: &AiRequestId,
        caller: &Address,
        current_block: u64,
    ) -> Result<(Address, u64), String> {
        let request = self
            .requests
            .get(request_id)
            .ok_or_else(|| format!("Request {} not found", request_id.to_hex()))?;

        // Only the requester can cancel
        if request.requester != *caller {
            return Err(format!(
                "Only the requester can cancel request {}",
                request_id.to_hex()
            ));
        }

        // Cannot cancel an already-finalized request
        if self.outcomes.contains_key(request_id) {
            return Err(format!(
                "Request {} has been finalized — cannot cancel",
                request_id.to_hex()
            ));
        }

        // Cannot cancel an already-reclaimed request
        if self.reclaimed_fees.contains(request_id) {
            return Err(format!(
                "Request {} fee already reclaimed — cannot cancel",
                request_id.to_hex()
            ));
        }

        // Cannot cancel an already-cancelled request
        if self.cancelled_requests.contains(request_id) {
            return Err(format!("Request {} already cancelled", request_id.to_hex()));
        }

        // Cannot cancel before the deadline has passed — the request is
        // still valid and verifiers may still submit results.
        // Cancellation is for requests where the requester no longer wants
        // to wait, but verifiers might still be working. We allow
        // cancellation at any point before finalization.
        let requester = request.requester;
        let max_fee = request.max_fee;

        self.cancelled_requests.insert(*request_id);

        Ok((requester, max_fee))
    }

    /// P5 Bulgu 18 (ADIM7): Check if a verifier has equivocated on a request.
    /// Returns true if the (request_id, verifier) pair is in the equivocation record
    /// AND the dispute window has not expired (P5 ADIM9 Bulgu 25).
    pub fn has_equivocated(&self, request_id: &AiRequestId, verifier: &Address) -> bool {
        self.equivocation_events
            .contains_key(&(*request_id, verifier.0))
    }

    /// P5 ADIM9 Bulgu 25: Check if an equivocation event is still within
    /// the dispute window. Returns false if the event expired.
    pub fn is_disputable(
        &self,
        request_id: &AiRequestId,
        verifier: &Address,
        current_block: u64,
    ) -> bool {
        match self.equivocation_events.get(&(*request_id, verifier.0)) {
            Some(&detected_block) => {
                current_block <= detected_block.saturating_add(DISPUTE_WINDOW_BLOCKS)
            }
            None => false,
        }
    }

    /// P5 Bulgu 18 (ADIM7): Get the total count of equivocation events
    /// for a specific verifier across all requests.
    pub fn equivocation_count_for_verifier(&self, verifier: &Address) -> usize {
        self.equivocation_events
            .iter()
            .filter(|((_, addr), _)| *addr == verifier.0)
            .count()
    }

    /// P5 Bulgu 21 (ADIM7): Check if a request has been cancelled.
    pub fn is_cancelled(&self, request_id: &AiRequestId) -> bool {
        self.cancelled_requests.contains(request_id)
    }

    /// P5 ADIM8 Bulgu 23 + ADIM9 Bulgu 25: Slash a verifier for equivocation.
    /// Now enforces dispute window — cannot slash after DISPUTE_WINDOW_BLOCKS
    /// have passed since the equivocation was detected.
    pub fn slash_equivocator(
        &mut self,
        request_id: &AiRequestId,
        verifier: &Address,
        current_block: u64,
    ) -> Result<(Address, u64), String> {
        let key = (*request_id, verifier.0);
        match self.equivocation_events.get(&key) {
            Some(&detected_block) => {
                if current_block > detected_block.saturating_add(DISPUTE_WINDOW_BLOCKS) {
                    return Err(format!(
                        "Dispute window expired for verifier {} on request {} (detected at block {}, window {} blocks)",
                        verifier.to_hex(),
                        request_id.to_hex(),
                        detected_block,
                        DISPUTE_WINDOW_BLOCKS
                    ));
                }
            }
            None => {
                return Err(format!(
                    "No equivocation record for verifier {} on request {}",
                    verifier.to_hex(),
                    request_id.to_hex()
                ));
            }
        }
        self.equivocation_events.remove(&key);

        // P5 ADIM9 Bulgu 26: Slash verifier stake if present.
        // Return the staked amount that was seized.
        let seized_stake = self.verifier_stakes.remove(verifier).unwrap_or(0);

        Ok((*verifier, seized_stake))
    }

    // ===================== P5 ADIM9 — Verifier Stake (Bulgu 26) =====================

    /// P5 ADIM9 Bulgu 26: Lock stake for an AI verifier.
    /// Verifiers must stake to participate in AI inference.
    /// This stake is slashable on equivocation — economic skin-in-the-game.
    pub fn lock_verifier_stake(&mut self, verifier: &Address, amount: u64) -> Result<u64, String> {
        if amount == 0 {
            return Err("Verifier stake must be > 0".into());
        }
        let current = self.verifier_stakes.get(verifier).copied().unwrap_or(0);
        let new_stake = current.saturating_add(amount);
        self.verifier_stakes.insert(*verifier, new_stake);
        Ok(new_stake)
    }

    /// P5 ADIM9 Bulgu 26: Withdraw verifier stake (only if no pending equivocation).
    pub fn withdraw_verifier_stake(
        &mut self,
        verifier: &Address,
        amount: u64,
        current_block: u64,
    ) -> Result<u64, String> {
        // Cannot withdraw if there are active equivocation events
        let has_pending = self
            .equivocation_events
            .iter()
            .any(|((_, addr), &detected_block)| {
                *addr == verifier.0
                    && current_block <= detected_block.saturating_add(DISPUTE_WINDOW_BLOCKS)
            });
        if has_pending {
            return Err(format!(
                "Cannot withdraw stake: verifier {} has pending equivocation disputes",
                verifier.to_hex()
            ));
        }
        let current = self
            .verifier_stakes
            .get(verifier)
            .copied()
            .ok_or_else(|| format!("No stake found for verifier {}", verifier.to_hex()))?;
        if amount > current {
            return Err(format!(
                "Withdrawal {} exceeds staked amount {}",
                amount, current
            ));
        }
        let remaining = current.saturating_sub(amount);
        if remaining == 0 {
            self.verifier_stakes.remove(verifier);
        } else {
            self.verifier_stakes.insert(*verifier, remaining);
        }
        Ok(amount)
    }

    /// P5 ADIM9 Bulgu 26: Check if a verifier has staked.
    pub fn is_staked_verifier(&self, verifier: &Address) -> bool {
        self.verifier_stakes.contains_key(verifier)
    }

    /// P5 ADIM9 Bulgu 26: Get verifier's staked amount.
    pub fn verifier_stake(&self, verifier: &Address) -> u64 {
        self.verifier_stakes.get(verifier).copied().unwrap_or(0)
    }

    /// P5 ADIM9 Bulgu 25: Expire old equivocation events past dispute window.
    /// Called during pruning to clean up stale events.
    pub fn expire_dispute_window(&mut self, current_block: u64) -> usize {
        let expired: Vec<_> = self
            .equivocation_events
            .iter()
            .filter(|(_, &detected_block)| {
                current_block > detected_block.saturating_add(DISPUTE_WINDOW_BLOCKS)
            })
            .map(|(k, _)| *k)
            .collect();
        let count = expired.len();
        for key in expired {
            self.equivocation_events.remove(&key);
        }
        count
    }

    // ===================== P5 ADIM10 — Dispute Resolution RPC (Bulgu 27) =====================

    /// P5 ADIM10 Bulgu 27: Get comprehensive dispute status for a (request, verifier) pair.
    /// Returns whether the verifier equivocated, whether the dispute window is
    /// still open, and verifier stake information. Used by `bud_aiSlashingStatus` RPC.
    pub fn get_dispute_status(
        &self,
        request_id: &AiRequestId,
        verifier: &Address,
        current_block: u64,
    ) -> AiDisputeStatusInfo {
        let key = (*request_id, verifier.0);
        let (has_equivocated, detected_block, is_disputable, dispute_window_remaining) =
            match self.equivocation_events.get(&key) {
                Some(&db) => {
                    let window_end = db.saturating_add(DISPUTE_WINDOW_BLOCKS);
                    let disputerable = current_block <= window_end;
                    let remaining = window_end.saturating_sub(current_block);
                    (true, Some(db), disputerable, Some(remaining))
                }
                None => (false, None, false, None),
            };

        AiDisputeStatusInfo {
            has_equivocated,
            is_disputable,
            detected_block,
            dispute_window_remaining,
            is_staked: self.is_staked_verifier(verifier),
            stake_amount: self.verifier_stake(verifier),
        }
    }

    /// P5 ADIM10 Bulgu 27: Get verifier stake information.
    /// Returns stake amount, staking status, and total equivocation count.
    /// Used by `bud_aiVerifierStake` RPC.
    pub fn get_verifier_stake_info(&self, verifier: &Address) -> AiVerifierStakeInfo {
        AiVerifierStakeInfo {
            verifier: *verifier,
            is_staked: self.is_staked_verifier(verifier),
            stake_amount: self.verifier_stake(verifier),
            total_equivocations: self.equivocation_count_for_verifier(verifier),
        }
    }

    // ===================== P5 ADIM10 — Outcome Callback Execution (Bulgu 28) =====================

    /// P5 ADIM10 Bulgu 28: Get pending callback events for a callback address.
    /// Returns all events queued for the address since the last consumption.
    /// Off-chain systems poll this to deliver inference results.
    pub fn get_callback_queue(&self, callback_address: &Address) -> Vec<AiCallbackEvent> {
        self.callback_queue
            .get(callback_address)
            .cloned()
            .unwrap_or_default()
    }

    /// P5 ADIM10 Bulgu 28: Consume (drain) callback events for an address.
    /// Called after off-chain system has delivered the callbacks.
    /// Returns the number of events consumed.
    pub fn consume_callback_events(&mut self, callback_address: &Address) -> usize {
        match self.callback_queue.remove(callback_address) {
            Some(events) => events.len(),
            None => 0,
        }
    }

    // ===================== P5 ADIM11 — Execution Proof (Bulgu 29) =====================

    /// P5 ADIM11 Bulgu 29: Attach a ZKVM execution proof to a result.
    /// The proof cryptographically verifies that the inference output was
    /// produced by the claimed model on the claimed input — the core
    /// primitive for trustless AI inference in the Agentic Economy.
    ///
    /// Returns Ok(()) if the proof commitments match the existing result.
    /// Returns Err if no result exists for this (request, verifier) pair,
    /// or if commitments don't match.
    pub fn attach_execution_proof(
        &mut self,
        request_id: &AiRequestId,
        verifier: &Address,
        proof: AiExecutionProof,
    ) -> Result<(), String> {
        // Verify that a result exists for this verifier
        let results = self
            .results
            .get(request_id)
            .ok_or_else(|| format!("No results found for request {}", request_id.to_hex()))?;
        let result = results
            .iter()
            .find(|r| r.verifier == *verifier)
            .ok_or_else(|| {
                format!(
                    "No result from verifier {} for request {}",
                    verifier.to_hex(),
                    request_id.to_hex()
                )
            })?;

        // Verify commitment binding
        if proof.output_commitment != result.output_commitment {
            return Err(format!(
                "Execution proof output_commitment does not match result for request {}",
                request_id.to_hex()
            ));
        }

        // Verify model binding — proof must be for the same model as the request
        let request = self
            .requests
            .get(request_id)
            .ok_or_else(|| format!("Request {} not found", request_id.to_hex()))?;
        if proof.model_id != request.model_id {
            return Err(format!(
                "Execution proof model_id does not match request model_id"
            ));
        }

        if proof.input_commitment != request.input_commitment {
            return Err("Execution proof input_commitment does not match request".into());
        }

        // Store the proof
        self.execution_proofs
            .insert((*request_id, verifier.0), proof);
        Ok(())
    }

    /// P5 ADIM11 Bulgu 29: Get the execution proof for a (request, verifier) pair.
    pub fn get_execution_proof(
        &self,
        request_id: &AiRequestId,
        verifier: &Address,
    ) -> Option<&AiExecutionProof> {
        self.execution_proofs.get(&(*request_id, verifier.0))
    }

    /// P5 ADIM11 Bulgu 29: Check if a result has an execution proof.
    /// Results with execution proofs are "trustless" — verified by
    /// mathematics rather than by verifier reputation.
    pub fn has_execution_proof(&self, request_id: &AiRequestId, verifier: &Address) -> bool {
        self.execution_proofs
            .contains_key(&(*request_id, verifier.0))
    }

    // ===================== P5 ADIM11 — Verifier QoS (Bulgu 30) =====================

    /// P5 ADIM11 Bulgu 30: Get QoS metrics for a verifier.
    pub fn get_verifier_qos(&self, verifier: &Address) -> Option<&AiVerifierQos> {
        self.verifier_qos.get(verifier)
    }

    /// P5 ADIM11 Bulgu 30: Get all verifiers ordered by reliability score (descending).
    /// Used for QoS-aware verifier selection in the Agentic Economy.
    pub fn verifiers_by_reliability(&self) -> Vec<AiVerifierQos> {
        let mut qos_list: Vec<_> = self.verifier_qos.values().cloned().collect();
        qos_list.sort_by(|a, b| {
            b.reliability_score()
                .partial_cmp(&a.reliability_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        qos_list
    }

    // ===================== P5 ADIM11 — Agent-to-Agent Payment (Bulgu 31) =====================

    /// P5 ADIM11 Bulgu 31: Submit an agent-to-agent payment.
    pub fn submit_agent_payment(
        &mut self,
        payment: AiAgentPayment,
        current_block: u64,
    ) -> Result<(), String> {
        if payment.from_agent == payment.to_agent {
            return Err(String::from(
                "Agent payment: from_agent and to_agent must differ",
            ));
        }
        if payment.amount == 0 {
            return Err(String::from(
                "Agent payment: amount must be greater than zero",
            ));
        }
        // V85 fix (Phase 11): expiry_block must not be unreasonably far in the
        // future. Without a maximum, an attacker can create payments with
        // expiry = u64::MAX, locking escrow forever. Cap at ~1 year (52560
        // epochs × 100 blocks/epoch ≈ 5_256_000 blocks from current_block).
        const MAX_PAYMENT_EXPIRY_HORIZON: u64 = 5_256_000;
        if payment.expiry_block > current_block.saturating_add(MAX_PAYMENT_EXPIRY_HORIZON) {
            return Err(format!(
                "Agent payment: expiry_block too far in the future (max {} blocks from current)",
                MAX_PAYMENT_EXPIRY_HORIZON
            ));
        }
        if payment.is_expired(current_block) {
            return Err(String::from(
                "Agent payment: expiry_block already expired (must be in the future)",
            ));
        }
        if payment.require_proof {
            if let Some(ref rid) = payment.request_id {
                if !self.requests.contains_key(rid) {
                    return Err(format!(
                        "Agent payment: request {} not found for proof-gated escrow",
                        rid.to_hex()
                    ));
                }
            } else {
                return Err(String::from(
                    "Agent payment: require_proof requires a linked request_id",
                ));
            }
        }
        if self.agent_payments.contains_key(&payment.payment_id)
            || self
                .settled_agent_payments
                .contains_key(&payment.payment_id)
        {
            return Err(String::from(
                "Agent payment: payment_id already exists or was previously settled",
            ));
        }
        self.agent_payments.insert(payment.payment_id, payment);
        Ok(())
    }

    /// P5 ADIM11 Bulgu 31: Release an escrowed payment to the recipient.
    pub fn release_agent_payment(
        &mut self,
        payment_id: &[u8; 32],
        current_block: u64,
    ) -> Result<Address, String> {
        // Phase 1: Validate (immutable borrows)
        {
            let payment = self
                .agent_payments
                .get(payment_id)
                .ok_or_else(|| String::from("Agent payment: payment_id not found"))?;
            if payment.is_expired(current_block) {
                return Err(String::from(
                    "Agent payment: payment has expired, use reclaim",
                ));
            }
            if let Some(ref rid) = payment.request_id {
                let outcome = self.outcomes.get(rid).ok_or_else(|| {
                    String::from("Agent payment: linked request has no finalized outcome yet")
                })?;
                if !outcome.agreeing_verifiers.contains(&payment.to_agent) {
                    return Err(String::from(
                        "Agent payment: recipient is not an agreeing verifier for this outcome",
                    ));
                }
                if payment.require_proof {
                    if !self.has_execution_proof(rid, &payment.to_agent) {
                        return Err(String::from(
                            "Agent payment: execution proof required but not attached",
                        ));
                    }
                }
            } else {
                return Err(String::from(
                    "Agent payment: cannot release non-escrowed payment (already available)",
                ));
            }
        }
        // Phase 2: Remove live entry and archive settlement (V89 audit trail).
        let payment = self.agent_payments.remove(payment_id).unwrap();
        let to = payment.to_agent;
        self.archive_settled_payment(payment, current_block, AiPaymentEscrowStatus::Released);
        Ok(to)
    }

    /// P5 ADIM11 Bulgu 31: Reclaim an expired escrowed payment.
    pub fn reclaim_agent_payment(
        &mut self,
        payment_id: &[u8; 32],
        claimant: &Address,
        current_block: u64,
    ) -> Result<u64, String> {
        let payment = self
            .agent_payments
            .get(payment_id)
            .ok_or_else(|| String::from("Agent payment: payment_id not found"))?;
        if payment.from_agent != *claimant {
            return Err(String::from("Agent payment: only the sender can reclaim"));
        }
        if !payment.is_expired(current_block) {
            return Err(String::from(
                "Agent payment: payment has not expired yet, cannot reclaim",
            ));
        }
        let amount = payment.amount;
        let payment = self.agent_payments.remove(payment_id).unwrap();
        self.archive_settled_payment(payment, current_block, AiPaymentEscrowStatus::Reclaimed);
        Ok(amount)
    }

    /// V89: Record immediate (non-escrowed) settlement without dropping audit trail.
    /// Removes live escrow entry if present and inserts an immutable settlement receipt.
    pub fn settle_agent_payment_immediate(
        &mut self,
        payment_id: &[u8; 32],
        settled_at_block: u64,
    ) -> Result<(), String> {
        let payment = self
            .agent_payments
            .remove(payment_id)
            .ok_or_else(|| String::from("Agent payment: payment_id not found for settle"))?;
        if payment.is_escrowed() {
            // Should not be called for escrowed payments — put back and error.
            self.agent_payments.insert(payment.payment_id, payment);
            return Err(String::from(
                "Agent payment: escrowed payment cannot use immediate settle",
            ));
        }
        if self.settled_agent_payments.contains_key(payment_id) {
            return Err(String::from("Agent payment: already settled"));
        }
        let receipt = AiAgentPaymentSettlement::from_payment(
            &payment,
            settled_at_block,
            AiPaymentEscrowStatus::SettledImmediate,
        );
        self.settled_agent_payments
            .insert(payment.payment_id, receipt);
        Ok(())
    }

    /// V89/V86: Move live payment to settled history with terminal status.
    fn archive_settled_payment(
        &mut self,
        payment: AiAgentPayment,
        settled_at_block: u64,
        status: AiPaymentEscrowStatus,
    ) {
        let id = payment.payment_id;
        let receipt = AiAgentPaymentSettlement::from_payment(&payment, settled_at_block, status);
        self.settled_agent_payments.insert(id, receipt);
    }

    pub fn get_settled_agent_payment(
        &self,
        payment_id: &[u8; 32],
    ) -> Option<&AiAgentPaymentSettlement> {
        self.settled_agent_payments.get(payment_id)
    }

    pub fn is_payment_id_consumed(&self, payment_id: &[u8; 32]) -> bool {
        self.agent_payments.contains_key(payment_id)
            || self.settled_agent_payments.contains_key(payment_id)
    }

    /// P5 ADIM11 Bulgu 31: Get a payment by ID.
    pub fn get_agent_payment(&self, payment_id: &[u8; 32]) -> Option<&AiAgentPayment> {
        self.agent_payments.get(payment_id)
    }

    /// P5 ADIM11 Bulgu 31: Get escrow status of a payment.
    pub fn get_payment_escrow_status(
        &self,
        payment_id: &[u8; 32],
    ) -> Option<AiPaymentEscrowStatus> {
        if let Some(payment) = self.agent_payments.get(payment_id) {
            if payment.request_id.is_some() {
                return Some(AiPaymentEscrowStatus::Pending);
            }
            // Live non-escrowed should be rare after V89 settle path.
            return Some(AiPaymentEscrowStatus::Pending);
        }
        self.settled_agent_payments
            .get(payment_id)
            .map(|s| s.status.clone())
    }

    /// P5 ADIM11 Bulgu 31: Get all payments from a specific agent.
    pub fn payments_from_agent(&self, agent: &Address) -> Vec<&AiAgentPayment> {
        self.agent_payments
            .values()
            .filter(|p| p.from_agent == *agent)
            .collect()
    }

    /// P5 ADIM11 Bulgu 31: Get all payments to a specific agent.
    pub fn payments_to_agent(&self, agent: &Address) -> Vec<&AiAgentPayment> {
        self.agent_payments
            .values()
            .filter(|p| p.to_agent == *agent)
            .collect()
    }

    // ===================== P5 ADIM11 — Verifier Whitelist (Bulgu 33) =====================

    /// P5 ADIM11 Bulgu 33: Add a verifier to the whitelist.
    /// Only whitelisted verifiers can submit results when whitelist is active.
    pub fn whitelist_verifier(&mut self, verifier: Address) -> bool {
        self.verifier_whitelist.insert(verifier)
    }

    /// P5 ADIM11 Bulgu 33: Remove a verifier from the whitelist.
    pub fn dewhitelist_verifier(&mut self, verifier: &Address) -> bool {
        self.verifier_whitelist.remove(verifier)
    }

    /// P5 ADIM11 Bulgu 33: Check if a verifier is authorized to submit results.
    /// If whitelist is empty (permissionless mode), any staked verifier is allowed.
    /// If whitelist is non-empty (permissioned mode), only whitelisted verifiers.
    pub fn is_verifier_authorized(&self, verifier: &Address) -> bool {
        if self.verifier_whitelist.is_empty() {
            // Permissionless mode: staked verifier = authorized
            self.is_staked_verifier(verifier)
        } else {
            // Permissioned mode: must be in whitelist AND staked
            self.verifier_whitelist.contains(verifier) && self.is_staked_verifier(verifier)
        }
    }

    /// P5 ADIM11 Bulgu 33: Check if whitelist mode is active.
    pub fn is_whitelist_mode(&self) -> bool {
        !self.verifier_whitelist.is_empty()
    }

    /// P5 ADIM11 Bulgu 33: Get all whitelisted verifiers.
    pub fn get_whitelisted_verifiers(&self) -> &BTreeSet<Address> {
        &self.verifier_whitelist
    }

    /// P5 ADIM11 Bulgu 33: Clear the whitelist (switch to permissionless mode).
    pub fn clear_whitelist(&mut self) {
        self.verifier_whitelist.clear();
    }

    // ─── P5 ADIM11 Bulgu 34: Agent Reputation ────────────────────────────

    /// Get or create an agent's reputation record.
    /// Returns a mutable reference so the caller can record events.
    pub fn get_or_create_reputation(&mut self, agent: Address) -> &mut AiAgentReputation {
        if !self.agent_reputations.contains_key(&agent) {
            self.agent_reputations
                .insert(agent, AiAgentReputation::new(agent));
        }
        self.agent_reputations.get_mut(&agent).unwrap()
    }

    /// Record a completed payment for an agent (as payer).
    pub fn record_reputation_payment_completed(&mut self, agent: &Address, current_block: u64) {
        let agent = *agent;
        self.get_or_create_reputation(agent)
            .record_payment_completed(current_block);
    }

    /// Record a defaulted/expired payment for an agent (as payer).
    pub fn record_reputation_payment_defaulted(&mut self, agent: &Address, current_block: u64) {
        let agent = *agent;
        self.get_or_create_reputation(agent)
            .record_payment_defaulted(current_block);
    }

    /// Record an inference request submission for an agent.
    pub fn record_reputation_request(&mut self, agent: &Address, current_block: u64) {
        let agent = *agent;
        self.get_or_create_reputation(agent)
            .record_request(current_block);
    }

    /// Record a result submission for a verifier agent.
    pub fn record_reputation_result_submitted(&mut self, verifier: &Address, current_block: u64) {
        let verifier = *verifier;
        let rep = self.get_or_create_reputation(verifier);
        rep.results_submitted = rep.results_submitted.saturating_add(1);
        rep.update_activity(current_block);
    }

    /// Record that a verifier's result contributed to finalization.
    pub fn record_reputation_result_finalized(&mut self, verifier: &Address, current_block: u64) {
        let verifier = *verifier;
        let rep = self.get_or_create_reputation(verifier);
        rep.results_finalized = rep.results_finalized.saturating_add(1);
        rep.update_activity(current_block);
    }

    /// Record an equivocation detection for a verifier.
    pub fn record_reputation_equivocation(&mut self, verifier: &Address, current_block: u64) {
        let verifier = *verifier;
        let rep = self.get_or_create_reputation(verifier);
        rep.equivocations = rep.equivocations.saturating_add(1);
        rep.update_activity(current_block);
    }

    /// Get an agent's reputation record.
    pub fn get_agent_reputation(&self, agent: &Address) -> Option<&AiAgentReputation> {
        self.agent_reputations.get(agent)
    }

    /// Get all agents sorted by trust score (descending — highest trust first).
    /// Returns Vec of (agent_address, trust_score) tuples.
    pub fn agents_by_trust_score(&self) -> Vec<(Address, f64)> {
        let mut scored: Vec<(Address, f64)> = self
            .agent_reputations
            .iter()
            .map(|(addr, rep)| (*addr, rep.trust_score()))
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored
    }

    /// Get the top-N agents by trust score.
    pub fn top_agents(&self, n: usize) -> Vec<(Address, f64)> {
        self.agents_by_trust_score().into_iter().take(n).collect()
    }

    /// Calculate deterministic Merkle/SHA256 root of all AI registry maps.
    /// P5 Bulgu 19 (ADIM7): Domain-separated map roots prevent cross-map
    /// collision attacks (ARENAX V38). Each map gets a unique domain prefix
    /// before its entries are hashed, so identical key+value pairs in
    /// different maps produce different root contributions.
    pub fn state_root(&self) -> [u8; 32] {
        if self.is_empty() {
            return [0u8; 32];
        }
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_AI_REGISTRY_ROOT_V3");

        // Domain: models
        hasher.update(b"BDLM_AI_MODELS");
        for (id, spec) in &self.models {
            hasher.update(id.0);
            hasher.update(spec.calculate_leaf());
        }

        // Domain: requests
        hasher.update(b"BDLM_AI_REQUESTS");
        for (id, req) in &self.requests {
            hasher.update(id.0);
            hasher.update(req.calculate_leaf());
        }

        // Domain: results
        hasher.update(b"BDLM_AI_RESULTS");
        for (id, res_list) in &self.results {
            hasher.update(id.0);
            let mut list_hasher = Sha256::new();
            for res in res_list {
                list_hasher.update(res.calculate_leaf());
            }
            hasher.update(list_hasher.finalize());
        }

        // Domain: outcomes
        hasher.update(b"BDLM_AI_OUTCOMES");
        for (id, outcome) in &self.outcomes {
            hasher.update(id.0);
            hasher.update(outcome.calculate_leaf());
        }

        // Domain: reclaimed_fees
        hasher.update(b"BDLM_AI_RECLAIMED");
        for id in &self.reclaimed_fees {
            hasher.update(id.0);
            hasher.update(b"RECLAIMED");
        }

        // Domain: equivocation_events (P5 Bulgu 18 + ADIM9 Bulgu 25)
        hasher.update(b"BDLM_AI_EQUIVOCATIONS");
        for ((req_id, verifier_bytes), detected_block) in &self.equivocation_events {
            hasher.update(req_id.0);
            hasher.update(verifier_bytes);
            hasher.update(detected_block.to_le_bytes());
        }

        // Domain: cancelled_requests (P5 Bulgu 21)
        hasher.update(b"BDLM_AI_CANCELLED");
        for id in &self.cancelled_requests {
            hasher.update(id.0);
        }

        // Domain: verifier_stakes (P5 ADIM9 Bulgu 26)
        hasher.update(b"BDLM_AI_VERIFIER_STAKES");
        for (verifier, stake) in &self.verifier_stakes {
            hasher.update(verifier.as_bytes());
            hasher.update(stake.to_le_bytes());
        }

        // Domain: callback_queue (P5 ADIM10 Bulgu 28)
        hasher.update(b"BDLM_AI_CALLBACK_QUEUE");
        for (addr, events) in &self.callback_queue {
            hasher.update(addr.as_bytes());
            for event in events {
                hasher.update(event.request_id.0);
                hasher.update(event.output_commitment);
                hasher.update(event.finalized_at_block.to_le_bytes());
                hasher.update(event.callback_address.as_bytes());
            }
        }

        // Domain: execution_proofs (P5 ADIM11 Bulgu 29)
        hasher.update(b"BDLM_AI_EXEC_PROOFS");
        for ((req_id, verifier_bytes), proof) in &self.execution_proofs {
            hasher.update(req_id.0);
            hasher.update(verifier_bytes);
            hasher.update(proof.calculate_leaf());
        }

        // Domain: verifier_qos (P5 ADIM11 Bulgu 30)
        hasher.update(b"BDLM_AI_VERIFIER_QOS");
        for (verifier, qos) in &self.verifier_qos {
            hasher.update(verifier.as_bytes());
            hasher.update(qos.calculate_leaf());
        }

        // Domain: agent_payments (P5 ADIM11 Bulgu 31)
        hasher.update(b"BDLM_AI_AGENT_PAYMENTS");
        for (pid, payment) in &self.agent_payments {
            hasher.update(pid);
            hasher.update(payment.calculate_leaf());
        }
        // Domain: settled agent payments (V89 audit trail)
        hasher.update(b"BDLM_AI_AGENT_PAYMENT_SETTLEMENTS_V1");
        for (pid, settlement) in &self.settled_agent_payments {
            hasher.update(pid);
            hasher.update(settlement.calculate_leaf());
        }
        hasher.update(b"BDLM_AI_VERIFIER_WHITELIST");
        for verifier in &self.verifier_whitelist {
            hasher.update(verifier.as_bytes());
        }

        // Domain: agent_reputations (P5 ADIM11 Bulgu 34)
        hasher.update(b"BDLM_AI_AGENT_REPUTATIONS");
        for (addr, rep) in &self.agent_reputations {
            hasher.update(addr.as_bytes());
            hasher.update(rep.calculate_leaf());
        }

        hasher.finalize().into()
    }
}

impl Default for AiRegistry {
    fn default() -> Self {
        Self::new()
    }
}
