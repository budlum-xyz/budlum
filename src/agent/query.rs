//! The Agent query API layer - the model list, the stats and query
//! preparation.
//!
//! Agent layer helpers, to be called from RPC and the CLI.

use super::metrics::AgentMetricsSnapshot;

/// A Agent model summary, for an RPC or CLI response.
#[derive(Debug, Clone)]
pub struct AgentModelInfo {
    pub model_id_bytes: [u8; 32],
    pub owner_bytes: [u8; 32],
    pub active: bool,
}

/// A summary of a Agent query response.
#[derive(Debug, Clone)]
pub struct AgentQueryResponse {
    pub active_models: Vec<AgentModelInfo>,
    pub eligible_operators: u32,
    pub metrics: AgentMetricsSnapshot,
}

/// Prepares the summary of the Agent layer, for the `bud_agentStats` RPC.
/// The caller (RPC or CLI) supplies the model list and the operator count.
pub fn prepare_agent_overview(
    active_models: Vec<AgentModelInfo>,
    eligible_operators: u32,
    metrics: &AgentMetricsSnapshot,
) -> AgentQueryResponse {
    AgentQueryResponse {
        active_models,
        eligible_operators,
        metrics: metrics.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::metrics::AgentMetrics;

    #[test]
    fn prepare_overview_returns_data() {
        let m = AgentMetrics::new();
        m.record_query();
        let snap = m.summary();

        let models = vec![AgentModelInfo {
            model_id_bytes: [1; 32],
            owner_bytes: [2; 32],
            active: true,
        }];
        let resp = prepare_agent_overview(models, 3, &snap);
        assert_eq!(resp.active_models.len(), 1);
        assert_eq!(resp.eligible_operators, 3);
        assert_eq!(resp.metrics.total_queries, 1);
    }
}
