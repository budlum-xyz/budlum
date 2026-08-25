//! The Lubot query API layer - the model list, the stats and query
//! preparation.
//!
//! Lubot layer helpers, to be called from RPC and the CLI.

use super::metrics::LubotMetricsSnapshot;

/// A Lubot model summary, for an RPC or CLI response.
#[derive(Debug, Clone)]
pub struct LubotModelInfo {
    pub model_id_bytes: [u8; 32],
    pub owner_bytes: [u8; 32],
    pub active: bool,
}

/// A summary of a Lubot query response.
#[derive(Debug, Clone)]
pub struct LubotQueryResponse {
    pub active_models: Vec<LubotModelInfo>,
    pub eligible_operators: u32,
    pub metrics: LubotMetricsSnapshot,
}

/// Prepares the summary of the Lubot layer, for the `bud_lubotStats` RPC.
/// The caller (RPC or CLI) supplies the model list and the operator count.
pub fn prepare_lubot_overview(
    active_models: Vec<LubotModelInfo>,
    eligible_operators: u32,
    metrics: &LubotMetricsSnapshot,
) -> LubotQueryResponse {
    LubotQueryResponse {
        active_models,
        eligible_operators,
        metrics: metrics.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lubot::metrics::LubotMetrics;

    #[test]
    fn prepare_overview_returns_data() {
        let m = LubotMetrics::new();
        m.record_query();
        let snap = m.summary();

        let models = vec![LubotModelInfo {
            model_id_bytes: [1; 32],
            owner_bytes: [2; 32],
            active: true,
        }];
        let resp = prepare_lubot_overview(models, 3, &snap);
        assert_eq!(resp.active_models.len(), 1);
        assert_eq!(resp.eligible_operators, 3);
        assert_eq!(resp.metrics.total_queries, 1);
    }
}
