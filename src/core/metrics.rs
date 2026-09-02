use prometheus::{Encoder, Histogram, HistogramOpts, IntCounter, IntGauge, Registry, TextEncoder};
use std::sync::Arc;

#[derive(Clone)]
pub struct Metrics {
    pub registry: Arc<Registry>,
    pub chain_height: IntGauge,
    pub mempool_size: IntGauge,
    /// Bytes of transaction bodies resident in the mempool.
    ///
    /// Exported beside the entry count rather than instead of it. The two can
    /// diverge by four orders of magnitude - the same 20 000 entries are 20 MB
    /// of ordinary transactions or 1.95 GB of maximum-size ones - and an
    /// operator watching only the count cannot tell which of those is
    /// happening until the process is killed.
    pub mempool_bytes: IntGauge,
    /// Peers holding a gossip score record.
    ///
    /// Separate from `p2p_peers_connected`: the score table deliberately outlives a
    /// connection so that reconnecting does not clear a bad record, so this
    /// gauge is expected to sit above the connected count. What it makes
    /// visible is the gap - a table climbing toward `MAX_SCORED_PEERS` while
    /// the connected count stays flat is peer-id churn.
    pub gossip_scored_peers: IntGauge,
    pub blocks_produced: IntCounter,
    pub transactions_processed: IntCounter,
    pub reorgs_total: IntCounter,
    pub finalized_height: IntGauge,
    pub block_propagation_seconds: Histogram,
    pub mempool_sender_count: IntGauge,
    pub peer_connection_quality: IntGauge,
    pub consensus_round_seconds: Histogram,
    pub finality_lag: IntGauge,
    pub storage_db_size_bytes: IntGauge,
    pub storage_write_seconds: Histogram,
    pub storage_read_seconds: Histogram,
    pub settlement_commitments_total: IntCounter,
    pub settlement_frozen_domains: IntGauge,
    pub settlement_global_headers_sealed: IntCounter,
    pub settlement_equivocations_detected: IntCounter,
    /// Connected P2P peers.
    ///
    /// This is the single live peer-count gauge. A second `peer_count` field
    /// used to export the same number under `budlum_peer_count` and was never
    /// written in production, so scrapes saw a permanent zero next to a real
    /// connected count. The duplicate was deleted rather than bound.
    pub p2p_peers_connected: IntGauge,
    pub p2p_messages_received: IntCounter,
    pub p2p_gossip_duplicates: IntCounter,
    pub p2p_sync_requests: IntCounter,
    pub mempool_evictions: IntCounter,
    pub mempool_expired_cleanups: IntCounter,
    pub rpc_request_duration_seconds: Histogram,
    pub rpc_requests_total: IntCounter,
    pub rpc_rate_limited_total: IntCounter,
    pub bridge_transfers_total: IntCounter,
    pub bridge_amount_locked: IntGauge,
    /// Rows in the bridge transfer table. Settled rows leave it after
    /// `SETTLED_RETENTION_BLOCKS`; a gauge that only ever rises means the
    /// sweep is not running.
    pub bridge_transfer_rows: IntGauge,
    pub ai_requests_total: IntCounter,
    pub ai_outcomes_finalized: IntCounter,
    pub bns_names_registered: IntCounter,
    pub slashing_events_total: IntCounter,
}

impl Metrics {
    /// Build the metric set.
    ///
    /// Every name and help string below is a literal in this file, so the
    /// only way `prometheus` refuses one is a malformed name we wrote
    /// ourselves - a build-time mistake, not something a peer can trigger.
    /// It still returns `Result` rather than panicking: this runs inside node
    /// startup, the release profile aborts on panic, and a metrics registry
    /// is not a reason to take a validator down. The caller decides.
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let chain_height = IntGauge::new("budlum_chain_height", "Current chain height")?;
        let mempool_size = IntGauge::new("budlum_mempool_size", "Pending transactions")?;
        let mempool_bytes = IntGauge::new(
            "budlum_mempool_bytes",
            "Resident bytes of pending transaction bodies",
        )?;
        let gossip_scored_peers = IntGauge::new(
            "budlum_gossip_scored_peers",
            "Peers holding a gossip score record",
        )?;
        let blocks_produced = IntCounter::new("budlum_blocks_produced", "Total blocks produced")?;
        let transactions_processed =
            IntCounter::new("budlum_transactions_processed", "Total transactions")?;
        let reorgs_total = IntCounter::new("budlum_reorgs_total", "Total chain reorgs")?;
        let finalized_height = IntGauge::new("budlum_finalized_height", "Finalized block height")?;
        let block_propagation_seconds = Histogram::with_opts(HistogramOpts::new(
            "budlum_block_propagation_seconds",
            "Observed block propagation time in seconds",
        ))?;
        let mempool_sender_count =
            IntGauge::new("budlum_mempool_sender_count", "Distinct senders in mempool")?;
        let peer_connection_quality = IntGauge::new(
            "budlum_peer_connection_quality",
            "Aggregate peer quality score",
        )?;
        let consensus_round_seconds = Histogram::with_opts(HistogramOpts::new(
            "budlum_consensus_round_seconds",
            "Consensus round duration in seconds",
        ))?;
        let finality_lag =
            IntGauge::new("budlum_finality_lag", "Head height minus finalized height")?;
        let storage_db_size_bytes = IntGauge::new(
            "budlum_storage_db_size_bytes",
            "Approximate storage size in bytes",
        )?;
        let storage_write_seconds = Histogram::with_opts(HistogramOpts::new(
            "budlum_storage_write_seconds",
            "Storage write latency in seconds",
        ))?;
        let storage_read_seconds = Histogram::with_opts(HistogramOpts::new(
            "budlum_storage_read_seconds",
            "Storage read latency in seconds",
        ))?;
        let settlement_commitments_total = IntCounter::new(
            "budlum_settlement_commitments_total",
            "Total settlement commitments processed",
        )?;
        let settlement_frozen_domains = IntGauge::new(
            "budlum_settlement_frozen_domains",
            "Frozen settlement domains",
        )?;
        let settlement_global_headers_sealed = IntCounter::new(
            "budlum_settlement_global_headers_sealed",
            "Total sealed settlement global headers",
        )?;
        let settlement_equivocations_detected = IntCounter::new(
            "budlum_settlement_equivocations_detected",
            "Total settlement equivocations detected",
        )?;
        let p2p_peers_connected = IntGauge::new(
            "budlum_p2p_peers_connected",
            "Currently connected P2P peers",
        )?;
        let p2p_messages_received = IntCounter::new(
            "budlum_p2p_messages_received",
            "Total P2P messages received",
        )?;
        let p2p_gossip_duplicates = IntCounter::new(
            "budlum_p2p_gossip_duplicates",
            "Duplicate gossip messages observed",
        )?;
        let p2p_sync_requests = IntCounter::new(
            "budlum_p2p_sync_requests",
            "P2P sync requests sent or handled",
        )?;
        let mempool_evictions = IntCounter::new(
            "budlum_mempool_evictions",
            "Transactions evicted from mempool",
        )?;
        let mempool_expired_cleanups = IntCounter::new(
            "budlum_mempool_expired_cleanups",
            "Expired mempool cleanup runs",
        )?;
        let rpc_request_duration_seconds = Histogram::with_opts(HistogramOpts::new(
            "budlum_rpc_request_duration_seconds",
            "RPC request latency in seconds",
        ))?;
        let rpc_requests_total =
            IntCounter::new("budlum_rpc_requests_total", "Total RPC requests received")?;
        //: Domain metrics.
        let bridge_transfers_total = IntCounter::new(
            "budlum_bridge_transfers_total",
            "Total bridge transfers processed",
        )?;
        let bridge_amount_locked = IntGauge::new(
            "budlum_bridge_amount_locked",
            "Assets currently locked in bridge",
        )?;
        let bridge_transfer_rows = IntGauge::new(
            "budlum_bridge_transfer_rows",
            "Rows in the bridge transfer table (settled rows are swept after the retention window)",
        )?;
        let ai_requests_total = IntCounter::new(
            "budlum_ai_requests_total",
            "Total AI inference requests submitted",
        )?;
        let ai_outcomes_finalized = IntCounter::new(
            "budlum_ai_outcomes_finalized",
            "Total AI outcomes finalized",
        )?;
        let bns_names_registered =
            IntCounter::new("budlum_bns_names_registered", "Total BNS names registered")?;
        let slashing_events_total = IntCounter::new(
            "budlum_slashing_events_total",
            "Total slashing events executed",
        )?;

        let rpc_rate_limited_total = IntCounter::new(
            "budlum_rpc_rate_limited_total",
            "Total RPC requests rejected due to rate limiting",
        )?;

        registry.register(Box::new(chain_height.clone()))?;
        registry.register(Box::new(mempool_size.clone()))?;
        registry.register(Box::new(mempool_bytes.clone()))?;
        registry.register(Box::new(gossip_scored_peers.clone()))?;
        registry.register(Box::new(blocks_produced.clone()))?;
        registry.register(Box::new(transactions_processed.clone()))?;
        registry.register(Box::new(reorgs_total.clone()))?;
        registry.register(Box::new(finalized_height.clone()))?;
        registry.register(Box::new(block_propagation_seconds.clone()))?;
        registry.register(Box::new(mempool_sender_count.clone()))?;
        registry.register(Box::new(peer_connection_quality.clone()))?;
        registry.register(Box::new(consensus_round_seconds.clone()))?;
        registry.register(Box::new(finality_lag.clone()))?;
        registry.register(Box::new(storage_db_size_bytes.clone()))?;
        registry.register(Box::new(storage_write_seconds.clone()))?;
        registry.register(Box::new(storage_read_seconds.clone()))?;
        registry.register(Box::new(settlement_commitments_total.clone()))?;
        registry.register(Box::new(settlement_frozen_domains.clone()))?;
        registry.register(Box::new(settlement_global_headers_sealed.clone()))?;
        registry.register(Box::new(settlement_equivocations_detected.clone()))?;
        registry.register(Box::new(p2p_peers_connected.clone()))?;
        registry.register(Box::new(p2p_messages_received.clone()))?;
        registry.register(Box::new(p2p_gossip_duplicates.clone()))?;
        registry.register(Box::new(p2p_sync_requests.clone()))?;
        registry.register(Box::new(mempool_evictions.clone()))?;
        registry.register(Box::new(mempool_expired_cleanups.clone()))?;
        registry.register(Box::new(rpc_request_duration_seconds.clone()))?;
        registry.register(Box::new(rpc_requests_total.clone()))?;
        registry.register(Box::new(bridge_transfers_total.clone()))?;
        registry.register(Box::new(bridge_amount_locked.clone()))?;
        registry.register(Box::new(bridge_transfer_rows.clone()))?;
        registry.register(Box::new(ai_requests_total.clone()))?;
        registry.register(Box::new(ai_outcomes_finalized.clone()))?;
        registry.register(Box::new(bns_names_registered.clone()))?;
        registry.register(Box::new(slashing_events_total.clone()))?;
        registry.register(Box::new(rpc_rate_limited_total.clone()))?;

        Ok(Metrics {
            registry: Arc::new(registry),
            chain_height,
            mempool_size,
            mempool_bytes,
            gossip_scored_peers,
            blocks_produced,
            transactions_processed,
            reorgs_total,
            finalized_height,
            block_propagation_seconds,
            mempool_sender_count,
            peer_connection_quality,
            consensus_round_seconds,
            finality_lag,
            storage_db_size_bytes,
            storage_write_seconds,
            storage_read_seconds,
            settlement_commitments_total,
            settlement_frozen_domains,
            settlement_global_headers_sealed,
            settlement_equivocations_detected,
            p2p_peers_connected,
            p2p_messages_received,
            p2p_gossip_duplicates,
            p2p_sync_requests,
            mempool_evictions,
            mempool_expired_cleanups,
            rpc_request_duration_seconds,
            rpc_requests_total,
            rpc_rate_limited_total,
            bridge_transfers_total,
            bridge_amount_locked,
            bridge_transfer_rows,
            ai_requests_total,
            ai_outcomes_finalized,
            bns_names_registered,
            slashing_events_total,
        })
    }

    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        // Serving metrics is an observability concern; failing to render them
        // must not abort the node. Both failures are impossible for the
        // encoder we construct here, so an empty body is the honest answer:
        // the scrape reports nothing rather than the process dying.
        if encoder.encode(&metric_families, &mut buffer).is_err() {
            return String::new();
        }
        String::from_utf8(buffer).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_initialization_and_encoding() {
        let metrics = Metrics::new().expect("metric names are literals in this file");
        metrics.chain_height.set(42);
        metrics.blocks_produced.inc();
        metrics.rpc_request_duration_seconds.observe(0.125);

        let encoded = metrics.encode();
        assert!(encoded.contains("budlum_chain_height 42"));
        assert!(encoded.contains("budlum_blocks_produced 1"));
        assert!(encoded.contains("budlum_rpc_request_duration_seconds"));
    }

    /// Every series bound in the metrics-are-written pass must appear in a
    /// live Prometheus scrape body. A gauge that exists only on the struct and
    /// never in `encode()` is still a dashboard lie.
    #[test]
    fn prometheus_scrape_lists_every_bound_series() {
        let metrics = Metrics::new().expect("metric names are literals in this file");
        let scrape = metrics.encode();
        assert!(
            !scrape.is_empty(),
            "encode must produce a body after registration"
        );
        for name in [
            "budlum_chain_height",
            "budlum_mempool_size",
            "budlum_mempool_bytes",
            "budlum_mempool_sender_count",
            "budlum_bridge_amount_locked",
            "budlum_bridge_transfer_rows",
            "budlum_storage_db_size_bytes",
            "budlum_p2p_peers_connected",
            "budlum_p2p_gossip_duplicates",
            "budlum_p2p_sync_requests",
            "budlum_peer_connection_quality",
            "budlum_bns_names_registered",
            "budlum_ai_requests_total",
            "budlum_ai_outcomes_finalized",
            "budlum_slashing_events_total",
            "budlum_settlement_equivocations_detected",
            "budlum_bridge_transfers_total",
        ] {
            assert!(
                scrape.contains(name),
                "scrape missing series {name}; body starts: {}",
                scrape.chars().take(200).collect::<String>()
            );
        }
        assert!(
            !scrape.contains("budlum_peer_count"),
            "deleted duplicate gauge must not reappear in scrapes"
        );
    }
}
