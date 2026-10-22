//! The AI inference layer query API layer - the model list, the stats and query
//! preparation.
//!
//! AI inference layer helpers, to be called from RPC and the CLI.

use super::metrics::AiMetricsSnapshot;

/// An AI inference layer model summary, for an RPC or CLI response.
#[derive(Debug, Clone)]
pub struct AiModelInfo {
    pub model_id_bytes: [u8; 32],
    pub owner_bytes: [u8; 32],
    pub active: bool,
}

/// A summary of an AI inference layer query response.
#[derive(Debug, Clone)]
pub struct AiQueryResponse {
    pub active_models: Vec<AiModelInfo>,
    pub eligible_operators: u32,
    pub metrics: AiMetricsSnapshot,
}

/// Prepares the summary of the AI inference layer, for the `bud_aiInferenceStats` RPC.
/// The caller (RPC or CLI) supplies the model list and the operator count.
pub fn prepare_ai_overview(
    active_models: Vec<AiModelInfo>,
    eligible_operators: u32,
    metrics: &AiMetricsSnapshot,
) -> AiQueryResponse {
    AiQueryResponse {
        active_models,
        eligible_operators,
        metrics: metrics.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_inference::metrics::AiMetrics;

    #[test]
    fn prepare_overview_returns_data() {
        let m = AiMetrics::new();
        m.record_query();
        let snap = m.summary();

        let models = vec![AiModelInfo {
            model_id_bytes: [1; 32],
            owner_bytes: [2; 32],
            active: true,
        }];
        let resp = prepare_ai_overview(models, 3, &snap);
        assert_eq!(resp.active_models.len(), 1);
        assert_eq!(resp.eligible_operators, 3);
        assert_eq!(resp.metrics.total_queries, 1);
    }
}
