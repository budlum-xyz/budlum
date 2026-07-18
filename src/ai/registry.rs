//! Canonical AI Registry & State Tracking (`Phase 10`, `Bölüm 1`).
//!
//! Tracks active models, pending inference requests, accumulated verifier attestations,
//! and finalized consensus outcomes. Provides deterministic `state_root()` calculation.

use crate::ai::types::{
    AiInferenceOutcome, AiInferenceRequest, AiInferenceResult, AiModelId, AiModelSpec, AiRequestId,
};
use crate::core::address::Address;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiRegistry {
    pub models: BTreeMap<AiModelId, AiModelSpec>,
    pub requests: BTreeMap<AiRequestId, AiInferenceRequest>,
    pub results: BTreeMap<AiRequestId, Vec<AiInferenceResult>>,
    pub outcomes: BTreeMap<AiRequestId, AiInferenceOutcome>,
    /// P5 Bulgu 4: Set of request IDs whose max_fee has been reclaimed
    /// after deadline expiry without finalization. Prevents double-reclaim.
    pub reclaimed_fees: BTreeSet<AiRequestId>,
}

impl AiRegistry {
    pub fn new() -> Self {
        Self {
            models: BTreeMap::new(),
            requests: BTreeMap::new(),
            results: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            reclaimed_fees: BTreeSet::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
            && self.requests.is_empty()
            && self.results.is_empty()
            && self.outcomes.is_empty()
            && self.reclaimed_fees.is_empty()
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
                return Err(format!(
                    "EQUIVOCATION: verifier {:?} submitted conflicting commitments for request {} — dispute flagged",
                    result.verifier,
                    result.request_id.to_hex()
                ));
            }
        }
        entries.push(result.clone());

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

    /// Calculate deterministic Merkle/SHA256 root of all AI registry maps.
    pub fn state_root(&self) -> [u8; 32] {
        if self.is_empty() {
            return [0u8; 32];
        }
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_AI_REGISTRY_ROOT_V1");

        for (id, spec) in &self.models {
            hasher.update(id.0);
            hasher.update(spec.calculate_leaf());
        }
        for (id, req) in &self.requests {
            hasher.update(id.0);
            hasher.update(req.calculate_leaf());
        }
        for (id, res_list) in &self.results {
            hasher.update(id.0);
            let mut list_hasher = Sha256::new();
            for res in res_list {
                list_hasher.update(res.calculate_leaf());
            }
            hasher.update(list_hasher.finalize());
        }
        for (id, outcome) in &self.outcomes {
            hasher.update(id.0);
            hasher.update(outcome.calculate_leaf());
        }
        for id in &self.reclaimed_fees {
            hasher.update(id.0);
            hasher.update(b"RECLAIMED");
        }

        hasher.finalize().into()
    }
}

impl Default for AiRegistry {
    fn default() -> Self {
        Self::new()
    }
}
