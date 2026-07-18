//! Canonical AI Registry & State Tracking (`Phase 10`, `Bölüm 1`).
//!
//! Tracks active models, pending inference requests, accumulated verifier attestations,
//! and finalized consensus outcomes. Provides deterministic `state_root()` calculation.

use crate::ai::types::{
    AiInferenceOutcome, AiInferenceRequest, AiInferenceResult, AiModelId, AiModelSpec, AiRequestId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiRegistry {
    pub models: BTreeMap<AiModelId, AiModelSpec>,
    pub requests: BTreeMap<AiRequestId, AiInferenceRequest>,
    pub results: BTreeMap<AiRequestId, Vec<AiInferenceResult>>,
    pub outcomes: BTreeMap<AiRequestId, AiInferenceOutcome>,
}

impl AiRegistry {
    pub fn new() -> Self {
        Self {
            models: BTreeMap::new(),
            requests: BTreeMap::new(),
            results: BTreeMap::new(),
            outcomes: BTreeMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
            && self.requests.is_empty()
            && self.results.is_empty()
            && self.outcomes.is_empty()
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

    pub fn submit_request(&mut self, request: AiInferenceRequest) -> Result<AiRequestId, String> {
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
        let id = request.request_id;
        self.requests.insert(id, request);
        Ok(id)
    }

    pub fn submit_result(
        &mut self,
        result: AiInferenceResult,
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

        let entries = self.results.entry(result.request_id).or_default();
        if entries.iter().any(|r| r.verifier == result.verifier) {
            return Err("Verifier has already submitted a result for this request".into());
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
            let outcome = AiInferenceOutcome {
                request_id: result.request_id,
                output_commitment: result.output_commitment,
                output_ref: result.output_ref.clone(),
                agreeing_verifiers,
                finalized_at_block: result.submitted_at_block,
            };
            self.outcomes.insert(result.request_id, outcome.clone());
            return Ok(Some(outcome));
        }

        Ok(None)
    }

    pub fn get_outcome(&self, request_id: &AiRequestId) -> Option<&AiInferenceOutcome> {
        self.outcomes.get(request_id)
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

        hasher.finalize().into()
    }
}

impl Default for AiRegistry {
    fn default() -> Self {
        Self::new()
    }
}
