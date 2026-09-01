//! The the AI inference layer query API layer - the model list, the stats and query
//! preparation.
//!
//! AI inference layer layer helpers, to be called from RPC and the CLI.

use super::metrics::AiInferenceMetricsSnapshot;

/// A the AI inference layer model summary, for an RPC or CLI response.
#[derive(Debug, Clone)]
pub struct AiInferenceModelInfo {
    pub model_id_bytes: [u8; 32],
    pub owner_bytes: [u8; 32],
    pub active: bool,
}

/// A summary of a the AI inference layer query response.
#[derive(Debug, Clone)]
pub struct AiInferenceQueryResponse {
    pub active_models: Vec<AiInferenceModelInfo>,
    pub eligible_operators: u32,
    pub metrics: AiInferenceMetricsSnapshot,
}

/// Prepares the summary of the the AI inference layer layer, for the `bud_ai_inferenceStats` RPC.
/// The caller (RPC or CLI) supplies the model list and the operator count.
pub fn prepare_ai_inference_overview(
    active_models: Vec<AiInferenceModelInfo>,
    eligible_operators: u32,
    metrics: &AiInferenceMetricsSnapshot,
) -> AiInferenceQueryResponse {
    AiInferenceQueryResponse {
        active_models,
        eligible_operators,
        metrics: metrics.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_inference::metrics::AiInferenceMetrics;

    #[test]
    fn prepare_overview_returns_data() {
        let m = AiInferenceMetrics::new();
        m.record_query();
        let snap = m.summary();

        let models = vec![AiInferenceModelInfo {
            model_id_bytes: [1; 32],
            owner_bytes: [2; 32],
            active: true,
        }];
        let resp = prepare_ai_inference_overview(models, 3, &snap);
        assert_eq!(resp.active_models.len(), 1);
        assert_eq!(resp.eligible_operators, 3);
        assert_eq!(resp.metrics.total_queries, 1);
    }
}
