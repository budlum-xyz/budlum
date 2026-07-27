//! Lubot sorgu API katmanı — model listesi, stats, sorgu hazırlığı.
//!
//! RPC/CLI tarafından çağrılacak Lubot katmanı yardımcıları.

use super::metrics::LubotMetricsSnapshot;

/// Lubot model özeti (RPC/CLI yanıtı için).
#[derive(Debug, Clone)]
pub struct LubotModelInfo {
    pub model_id_bytes: [u8; 32],
    pub owner_bytes: [u8; 32],
    pub active: bool,
}

/// Lubot sorgu yanıtı özeti.
#[derive(Debug, Clone)]
pub struct LubotQueryResponse {
    pub active_models: Vec<LubotModelInfo>,
    pub eligible_operators: u32,
    pub metrics: LubotMetricsSnapshot,
}

/// Lubot katmanı özetini hazırla (RPC `bud_lubotStats` için).
/// Çağıran (RPC/CLI) model listesini + operator sayısını sağlar.
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
