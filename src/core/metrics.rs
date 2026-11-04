use prometheus::{Encoder, Histogram, HistogramOpts, IntCounter, IntGauge, Registry, TextEncoder};
use std::sync::Arc;

#[derive(Clone)]
pub struct Metrics {
    pub registry: Arc<Registry>,
    pub chain_height: IntGauge,
    /// Accounts retained in the state-rooted account map.
    pub account_rows: IntGauge,
    /// Unbonding entries retained in account state.
    pub unbonding_rows: IntGauge,
    /// Testnet/governance transfer protocol fee in parts per million.
    pub transfer_fee_ppm: IntGauge,
    /// Testnet/governance swap protocol fee in parts per million.
    pub swap_fee_ppm: IntGauge,
    /// Testnet/governance outbound bridge protocol fee in parts per million.
    pub bridge_fee_ppm: IntGauge,
    /// Application share of eligible protocol fees in parts per million.
    pub app_fee_share_ppm: IntGauge,
    /// Relayer share of inbound bridge amounts in parts per million.
    pub bridge_relayer_fee_ppm: IntGauge,
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
    /// Active PoS validators in the rooted validator set.
    pub active_validators: IntGauge,
    /// Finality certificates waiting for checkpoint processing.
    pub pending_finality_certificates: IntGauge,
    /// Validators with retained liveness-tracker state.
    pub liveness_tracked_validators: IntGauge,
    /// Validators with retained invalid-vote tracker state.
    pub invalid_vote_tracked_validators: IntGauge,
    /// PoA onboarding applications and decisions retained in the audit log.
    pub poa_onboarding_audit_rows: IntGauge,
    /// PoA membership records retained in onboarding state.
    pub poa_onboarding_membership_rows: IntGauge,
    /// PoA admin records retained in onboarding state.
    pub poa_onboarding_admin_rows: IntGauge,
    /// Governance domain-unfreeze requests waiting for block-end application.
    pub pending_domain_unfreeze_rows: IntGauge,
    /// Governance PoA freeze requests waiting for block-end application.
    pub pending_poa_freeze_rows: IntGauge,
    /// Governance PoA unfreeze requests waiting for block-end application.
    pub pending_poa_unfreeze_rows: IntGauge,
    /// B.U.D. boost share waiting for storage-operator distribution.
    pub pending_bud_boost_atoms: IntGauge,
    pub block_propagation_seconds: Histogram,
    pub mempool_sender_count: IntGauge,
    pub peer_connection_quality: IntGauge,
    pub consensus_round_seconds: Histogram,
    pub finality_lag: IntGauge,
    pub storage_db_size_bytes: IntGauge,
    /// Content chunks retained by the durable B.U.D. content store.
    pub content_store_chunks: IntGauge,
    /// Bytes retained by the durable B.U.D. content store.
    pub content_store_bytes: IntGauge,
    pub storage_write_seconds: Histogram,
    pub storage_read_seconds: Histogram,
    pub settlement_commitments_total: IntCounter,
    /// Consensus-domain registrations retained in settlement state.
    pub settlement_domain_rows: IntGauge,
    /// Domain commitments retained in settlement state.
    pub settlement_commitment_rows: IntGauge,
    /// Sovereign-domain templates retained in settlement state.
    pub settlement_sovereign_template_rows: IntGauge,
    pub settlement_frozen_domains: IntGauge,
    pub settlement_global_headers_sealed: IntCounter,
    pub settlement_equivocations_detected: IntCounter,
    /// Graft settlement-door writes accepted in committed blocks.
    pub graft_transactions_total: IntCounter,
    /// BudZKVM contract calls in committed blocks.
    pub contract_calls_total: IntCounter,
    /// Mikoriza restaked validator rows in account state.
    pub restaked_validator_rows: IntGauge,
    /// Active proof-market tasks retained in account state.
    pub proof_market_active_tasks: IntGauge,
    /// Pending proof-market receipts retained in account state.
    pub proof_market_pending_receipts: IntGauge,
    /// Creator accounts with proof-market escrow balances.
    pub proof_market_escrow_accounts: IntGauge,
    pub reward_pool_balance: IntGauge,
    pub delegation_positions: IntGauge,
    pub delegation_unbonding_positions: IntGauge,
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
    /// Cross-domain messages retained in the state-rooted message registry.
    pub cross_domain_message_rows: IntGauge,
    /// External-domain registrations retained in the settlement intake.
    pub external_domain_rows: IntGauge,
    /// Accepted external attestations retained by registered domains.
    pub external_attestations_accepted: IntGauge,
    /// Open external quorum rounds retained by the intake.
    pub external_quorum_rounds: IntGauge,
    /// Accounts with external-domain bond escrow retained in account state.
    pub external_bond_escrow_rows: IntGauge,
    /// External-domain bond atoms retained in account state.
    pub external_bond_escrow_atoms: IntGauge,
    /// Pending cross-domain relay requests retained in settlement state.
    pub relayer_pending_rows: IntGauge,
    /// Successful relay records retained for replay protection and audit.
    pub relayer_ledger_rows: IntGauge,
    /// Outbound relayer intents retained in settlement state.
    pub relayer_intent_rows: IntGauge,
    /// Solver bids retained across outbound relayer intents.
    pub relayer_bid_rows: IntGauge,
    /// Maximum-fee escrow retained for outbound relayer intents.
    pub relayer_escrowed_atoms: IntGauge,
    /// Permissionless role-bond registrations retained in account state.
    pub role_bond_rows: IntGauge,
    /// Active RELAYER role bonds.
    pub active_relayer_rows: IntGauge,
    /// Active PROVER role bonds.
    pub active_prover_rows: IntGauge,
    /// Slashing records retained in the permissionless registry.
    pub registry_slashing_rows: IntGauge,
    /// Validator commission schedules retained in the permissionless registry.
    pub registry_commission_rows: IntGauge,
    /// PoA domains with admission records.
    pub poa_admission_domains: IntGauge,
    /// Authorities admitted to PoA domains.
    pub poa_admitted_authorities: IntGauge,
    /// Accounts frozen by the PoA compliance registry.
    pub poa_compliance_frozen_accounts: IntGauge,
    /// Rows in the storage reallocation ticket map. Settled tickets leave it
    /// after `REALLOCATION_RECORD_RETENTION_EPOCHS`; a gauge that only ever
    /// rises means the sweep is not running.
    pub storage_reallocation_rows: IntGauge,
    /// Content manifests retained in the B.U.D. storage registry.
    pub storage_manifest_rows: IntGauge,
    /// Storage deals retained in the B.U.D. storage registry.
    pub storage_deal_rows: IntGauge,
    /// Retrieval challenges retained in the B.U.D. storage registry.
    pub storage_challenge_rows: IntGauge,
    /// Challenge results retained in the B.U.D. storage registry.
    pub storage_result_rows: IntGauge,
    pub ai_requests_total: IntCounter,
    pub ai_outcomes_finalized: IntCounter,
    /// AI models retained in the state-rooted registry.
    pub ai_model_rows: IntGauge,
    /// Pending AI requests retained in the state-rooted registry.
    pub ai_request_rows: IntGauge,
    /// AI result attestations retained in the state-rooted registry.
    pub ai_result_rows: IntGauge,
    /// Finalized AI outcomes retained in the state-rooted registry.
    pub ai_outcome_rows: IntGauge,
    /// Verifier stake records retained in the state-rooted registry.
    pub ai_verifier_stake_rows: IntGauge,
    /// Undelivered AI callback events retained in the state-rooted registry.
    pub ai_callback_event_rows: IntGauge,
    /// Governance proposals retained in account state.
    pub governance_proposal_rows: IntGauge,
    /// Active governance proposals retained in account state.
    pub governance_active_proposal_rows: IntGauge,
    /// Constitution parameters retained in account state.
    pub constitution_parameter_rows: IntGauge,
    /// Live privacy note commitments retained in account state.
    pub privacy_live_note_rows: IntGauge,
    /// Spent privacy note nullifiers retained in account state.
    pub privacy_spent_nullifier_rows: IntGauge,
    /// Privacy note commitments permanently marked spent.
    pub privacy_spent_commitment_rows: IntGauge,
    /// Lifetime BUD burned from account state.
    pub tokenomics_burned_total: IntGauge,
    /// Annual reserve burns completed in account state.
    pub tokenomics_years_burned: IntGauge,
    /// Cumulative BUD removed by timed reserve burns.
    pub tokenomics_timed_burned_total: IntGauge,
    /// Team allocation still locked by the rooted vesting schedule.
    pub tokenomics_team_locked: IntGauge,
    pub bns_names_registered: IntCounter,
    /// BNS name rows retained in account state.
    pub bns_name_rows: IntGauge,
    /// Minted SocialFi NFTs retained in account state.
    pub nft_rows: IntGauge,
    /// Vault folders retained in account state.
    pub vault_folder_rows: IntGauge,
    /// Vault membership edges retained in account state.
    pub vault_membership_rows: IntGauge,
    /// Pollen data offers retained in account state.
    pub pollen_offer_rows: IntGauge,
    /// Pollen data assets retained in account state.
    pub pollen_asset_rows: IntGauge,
    /// Pollen access grants retained in account state.
    pub pollen_grant_rows: IntGauge,
    /// Pollen purchase receipts retained in account state.
    pub pollen_purchase_rows: IntGauge,
    /// Stored objects bound to Pollen paywalls.
    pub pollen_protected_content_rows: IntGauge,
    /// Budlumxyz app records retained in account state.
    pub budlumxyz_app_rows: IntGauge,
    /// DID identity records retained in account state.
    pub identity_record_rows: IntGauge,
    /// Identity credential commitments retained in account state.
    pub identity_credential_rows: IntGauge,
    /// Revoked identity credentials retained in account state.
    pub identity_revoked_rows: IntGauge,
    pub slashing_events_total: IntCounter,
    /// Times the two ML-DSA verifiers disagreed.
    ///
    /// Any value above zero is an incident: one library accepted a signature
    /// the other refused, and the signature was treated as invalid. The
    /// counter lives in the facade (it has no dependency on the node), and
    /// [`Metrics::encode`] folds it into this series before every scrape.
    pub pq_verifier_disagreement: IntCounter,
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
        let account_rows = IntGauge::new(
            "budlum_account_rows",
            "Accounts retained in the state-rooted account map",
        )?;
        let unbonding_rows = IntGauge::new(
            "budlum_unbonding_rows",
            "Unbonding entries retained in account state",
        )?;
        let transfer_fee_ppm = IntGauge::new(
            "budlum_transfer_fee_ppm",
            "Transfer protocol fee in parts per million",
        )?;
        let swap_fee_ppm = IntGauge::new(
            "budlum_swap_fee_ppm",
            "Swap protocol fee in parts per million",
        )?;
        let bridge_fee_ppm = IntGauge::new(
            "budlum_bridge_fee_ppm",
            "Outbound bridge protocol fee in parts per million",
        )?;
        let app_fee_share_ppm = IntGauge::new(
            "budlum_app_fee_share_ppm",
            "Application share of eligible protocol fees in parts per million",
        )?;
        let bridge_relayer_fee_ppm = IntGauge::new(
            "budlum_bridge_relayer_fee_ppm",
            "Relayer share of inbound bridge amounts in parts per million",
        )?;
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
        let active_validators = IntGauge::new(
            "budlum_active_validators",
            "Active PoS validators in the rooted validator set",
        )?;
        let pending_finality_certificates = IntGauge::new(
            "budlum_pending_finality_certificates",
            "Finality certificates waiting for checkpoint processing",
        )?;
        let liveness_tracked_validators = IntGauge::new(
            "budlum_liveness_tracked_validators",
            "Validators with retained liveness-tracker state",
        )?;
        let invalid_vote_tracked_validators = IntGauge::new(
            "budlum_invalid_vote_tracked_validators",
            "Validators with retained invalid-vote tracker state",
        )?;
        let poa_onboarding_audit_rows = IntGauge::new(
            "budlum_poa_onboarding_audit_rows",
            "PoA onboarding applications and decisions retained in the audit log",
        )?;
        let poa_onboarding_membership_rows = IntGauge::new(
            "budlum_poa_onboarding_membership_rows",
            "PoA membership records retained in onboarding state",
        )?;
        let poa_onboarding_admin_rows = IntGauge::new(
            "budlum_poa_onboarding_admin_rows",
            "PoA admin records retained in onboarding state",
        )?;
        let pending_domain_unfreeze_rows = IntGauge::new(
            "budlum_pending_domain_unfreeze_rows",
            "Governance domain-unfreeze requests waiting for block-end application",
        )?;
        let pending_poa_freeze_rows = IntGauge::new(
            "budlum_pending_poa_freeze_rows",
            "Governance PoA freeze requests waiting for block-end application",
        )?;
        let pending_poa_unfreeze_rows = IntGauge::new(
            "budlum_pending_poa_unfreeze_rows",
            "Governance PoA unfreeze requests waiting for block-end application",
        )?;
        let pending_bud_boost_atoms = IntGauge::new(
            "budlum_pending_bud_boost_atoms",
            "B.U.D. boost share waiting for storage-operator distribution",
        )?;
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
        let content_store_chunks = IntGauge::new(
            "budlum_content_store_chunks",
            "Content chunks retained by the durable B.U.D. content store",
        )?;
        let content_store_bytes = IntGauge::new(
            "budlum_content_store_bytes",
            "Bytes retained by the durable B.U.D. content store",
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
        let settlement_domain_rows = IntGauge::new(
            "budlum_settlement_domain_rows",
            "Consensus-domain registrations retained in settlement state",
        )?;
        let settlement_commitment_rows = IntGauge::new(
            "budlum_settlement_commitment_rows",
            "Domain commitments retained in settlement state",
        )?;
        let settlement_sovereign_template_rows = IntGauge::new(
            "budlum_settlement_sovereign_template_rows",
            "Sovereign-domain templates retained in settlement state",
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
        let graft_transactions_total = IntCounter::new(
            "budlum_graft_transactions_total",
            "Total Graft settlement-door transactions processed",
        )?;
        let contract_calls_total = IntCounter::new(
            "budlum_contract_calls_total",
            "Total BudZKVM contract calls in committed blocks",
        )?;
        let restaked_validator_rows = IntGauge::new(
            "budlum_restaked_validator_rows",
            "Mikoriza restaked validator rows retained in account state",
        )?;
        let proof_market_active_tasks = IntGauge::new(
            "budlum_proof_market_active_tasks",
            "Active proof-market tasks retained in account state",
        )?;
        let proof_market_pending_receipts = IntGauge::new(
            "budlum_proof_market_pending_receipts",
            "Pending proof-market receipts retained in account state",
        )?;
        let proof_market_escrow_accounts = IntGauge::new(
            "budlum_proof_market_escrow_accounts",
            "Creator accounts with proof-market escrow balances",
        )?;
        let reward_pool_balance = IntGauge::new(
            "budlum_reward_pool_balance",
            "Current validation reward-pool balance",
        )?;
        let delegation_positions = IntGauge::new(
            "budlum_delegation_positions",
            "Active validator delegation positions",
        )?;
        let delegation_unbonding_positions = IntGauge::new(
            "budlum_delegation_unbonding_positions",
            "Pending delegation exits",
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
        // Domain metrics.
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
        let cross_domain_message_rows = IntGauge::new(
            "budlum_cross_domain_message_rows",
            "Rows in the state-rooted cross-domain message registry",
        )?;
        let external_domain_rows = IntGauge::new(
            "budlum_external_domain_rows",
            "Registered external domains in the settlement intake",
        )?;
        let external_attestations_accepted = IntGauge::new(
            "budlum_external_attestations_accepted",
            "Accepted external attestations retained by registered domains",
        )?;
        let external_quorum_rounds = IntGauge::new(
            "budlum_external_quorum_rounds",
            "Open external quorum rounds in the settlement intake",
        )?;
        let external_bond_escrow_rows = IntGauge::new(
            "budlum_external_bond_escrow_rows",
            "Accounts with external-domain bond escrow retained in account state",
        )?;
        let external_bond_escrow_atoms = IntGauge::new(
            "budlum_external_bond_escrow_atoms",
            "External-domain bond atoms retained in account state",
        )?;
        let relayer_pending_rows = IntGauge::new(
            "budlum_relayer_pending_rows",
            "Pending cross-domain relay requests in settlement state",
        )?;
        let relayer_ledger_rows = IntGauge::new(
            "budlum_relayer_ledger_rows",
            "Successful relay records retained for replay protection",
        )?;
        let relayer_intent_rows = IntGauge::new(
            "budlum_relayer_intent_rows",
            "Outbound relayer intents in settlement state",
        )?;
        let relayer_bid_rows = IntGauge::new(
            "budlum_relayer_bid_rows",
            "Solver bids retained across outbound relayer intents",
        )?;
        let relayer_escrowed_atoms = IntGauge::new(
            "budlum_relayer_escrowed_atoms",
            "Maximum-fee escrow retained for outbound relayer intents",
        )?;
        let role_bond_rows = IntGauge::new(
            "budlum_role_bond_rows",
            "Permissionless role-bond registrations in account state",
        )?;
        let active_relayer_rows =
            IntGauge::new("budlum_active_relayer_rows", "Active RELAYER role bonds")?;
        let active_prover_rows =
            IntGauge::new("budlum_active_prover_rows", "Active PROVER role bonds")?;
        let registry_slashing_rows = IntGauge::new(
            "budlum_registry_slashing_rows",
            "Slashing records retained in the permissionless registry",
        )?;
        let registry_commission_rows = IntGauge::new(
            "budlum_registry_commission_rows",
            "Validator commission schedules retained in the permissionless registry",
        )?;
        let poa_admission_domains = IntGauge::new(
            "budlum_poa_admission_domains",
            "PoA domains with admission records",
        )?;
        let poa_admitted_authorities = IntGauge::new(
            "budlum_poa_admitted_authorities",
            "Authorities admitted to PoA domains",
        )?;
        let poa_compliance_frozen_accounts = IntGauge::new(
            "budlum_poa_compliance_frozen_accounts",
            "Accounts frozen by the PoA compliance registry",
        )?;
        let storage_reallocation_rows = IntGauge::new(
            "budlum_storage_reallocation_rows",
            "Rows in the storage reallocation ticket map (settled tickets are swept after the retention window)",
        )?;
        let storage_manifest_rows = IntGauge::new(
            "budlum_storage_manifest_rows",
            "Content manifests retained in the B.U.D. storage registry",
        )?;
        let storage_deal_rows = IntGauge::new(
            "budlum_storage_deal_rows",
            "Storage deals retained in the B.U.D. storage registry",
        )?;
        let storage_challenge_rows = IntGauge::new(
            "budlum_storage_challenge_rows",
            "Retrieval challenges retained in the B.U.D. storage registry",
        )?;
        let storage_result_rows = IntGauge::new(
            "budlum_storage_result_rows",
            "Challenge results retained in the B.U.D. storage registry",
        )?;
        let ai_requests_total = IntCounter::new(
            "budlum_ai_requests_total",
            "Total AI inference requests submitted",
        )?;
        let ai_outcomes_finalized = IntCounter::new(
            "budlum_ai_outcomes_finalized",
            "Total AI outcomes finalized",
        )?;
        let ai_model_rows = IntGauge::new(
            "budlum_ai_model_rows",
            "AI models retained in the state-rooted registry",
        )?;
        let ai_request_rows = IntGauge::new(
            "budlum_ai_request_rows",
            "Pending AI requests retained in the state-rooted registry",
        )?;
        let ai_result_rows = IntGauge::new(
            "budlum_ai_result_rows",
            "AI result attestations retained in the state-rooted registry",
        )?;
        let ai_outcome_rows = IntGauge::new(
            "budlum_ai_outcome_rows",
            "Finalized AI outcomes retained in the state-rooted registry",
        )?;
        let ai_verifier_stake_rows = IntGauge::new(
            "budlum_ai_verifier_stake_rows",
            "Verifier stake records retained in the state-rooted registry",
        )?;
        let ai_callback_event_rows = IntGauge::new(
            "budlum_ai_callback_event_rows",
            "Undelivered AI callback events retained in the state-rooted registry",
        )?;
        let governance_proposal_rows = IntGauge::new(
            "budlum_governance_proposal_rows",
            "Governance proposals retained in account state",
        )?;
        let governance_active_proposal_rows = IntGauge::new(
            "budlum_governance_active_proposal_rows",
            "Active governance proposals retained in account state",
        )?;
        let constitution_parameter_rows = IntGauge::new(
            "budlum_constitution_parameter_rows",
            "Constitution parameters retained in account state",
        )?;
        let privacy_live_note_rows = IntGauge::new(
            "budlum_privacy_live_note_rows",
            "Live privacy note commitments retained in account state",
        )?;
        let privacy_spent_nullifier_rows = IntGauge::new(
            "budlum_privacy_spent_nullifier_rows",
            "Spent privacy note nullifiers retained in account state",
        )?;
        let privacy_spent_commitment_rows = IntGauge::new(
            "budlum_privacy_spent_commitment_rows",
            "Privacy note commitments permanently marked spent",
        )?;
        let tokenomics_burned_total = IntGauge::new(
            "budlum_tokenomics_burned_total",
            "Lifetime BUD burned from account state",
        )?;
        let tokenomics_years_burned = IntGauge::new(
            "budlum_tokenomics_years_burned",
            "Annual reserve burns completed in account state",
        )?;
        let tokenomics_timed_burned_total = IntGauge::new(
            "budlum_tokenomics_timed_burned_total",
            "Cumulative BUD removed by timed reserve burns",
        )?;
        let tokenomics_team_locked = IntGauge::new(
            "budlum_tokenomics_team_locked",
            "Team allocation still locked by the rooted vesting schedule",
        )?;
        let bns_names_registered =
            IntCounter::new("budlum_bns_names_registered", "Total BNS names registered")?;
        let bns_name_rows = IntGauge::new(
            "budlum_bns_name_rows",
            "BNS name rows retained in account state",
        )?;
        let nft_rows = IntGauge::new(
            "budlum_nft_rows",
            "Minted SocialFi NFTs retained in account state",
        )?;
        let vault_folder_rows = IntGauge::new(
            "budlum_vault_folder_rows",
            "Vault folders retained in account state",
        )?;
        let vault_membership_rows = IntGauge::new(
            "budlum_vault_membership_rows",
            "Vault membership edges retained in account state",
        )?;
        let pollen_offer_rows = IntGauge::new(
            "budlum_pollen_offer_rows",
            "Pollen data offers retained in account state",
        )?;
        let pollen_asset_rows = IntGauge::new(
            "budlum_pollen_asset_rows",
            "Pollen data assets retained in account state",
        )?;
        let pollen_grant_rows = IntGauge::new(
            "budlum_pollen_grant_rows",
            "Pollen access grants retained in account state",
        )?;
        let pollen_purchase_rows = IntGauge::new(
            "budlum_pollen_purchase_rows",
            "Pollen purchase receipts retained in account state",
        )?;
        let pollen_protected_content_rows = IntGauge::new(
            "budlum_pollen_protected_content_rows",
            "Stored objects bound to Pollen paywalls",
        )?;
        let budlumxyz_app_rows = IntGauge::new(
            "budlum_budlumxyz_app_rows",
            "Budlumxyz app records retained in account state",
        )?;
        let identity_record_rows = IntGauge::new(
            "budlum_identity_record_rows",
            "DID identity records retained in account state",
        )?;
        let identity_credential_rows = IntGauge::new(
            "budlum_identity_credential_rows",
            "Identity credential commitments retained in account state",
        )?;
        let identity_revoked_rows = IntGauge::new(
            "budlum_identity_revoked_rows",
            "Revoked identity credentials retained in account state",
        )?;
        let slashing_events_total = IntCounter::new(
            "budlum_slashing_events_total",
            "Total slashing events executed",
        )?;

        let pq_verifier_disagreement = IntCounter::new(
            "budlum_pq_verifier_disagreement",
            "Times the two ML-DSA verifiers (ml-dsa and libcrux) disagreed; the signature was treated as invalid",
        )?;

        let rpc_rate_limited_total = IntCounter::new(
            "budlum_rpc_rate_limited_total",
            "Total RPC requests rejected due to rate limiting",
        )?;

        registry.register(Box::new(chain_height.clone()))?;
        registry.register(Box::new(account_rows.clone()))?;
        registry.register(Box::new(unbonding_rows.clone()))?;
        registry.register(Box::new(transfer_fee_ppm.clone()))?;
        registry.register(Box::new(swap_fee_ppm.clone()))?;
        registry.register(Box::new(bridge_fee_ppm.clone()))?;
        registry.register(Box::new(app_fee_share_ppm.clone()))?;
        registry.register(Box::new(bridge_relayer_fee_ppm.clone()))?;
        registry.register(Box::new(mempool_size.clone()))?;
        registry.register(Box::new(mempool_bytes.clone()))?;
        registry.register(Box::new(gossip_scored_peers.clone()))?;
        registry.register(Box::new(blocks_produced.clone()))?;
        registry.register(Box::new(transactions_processed.clone()))?;
        registry.register(Box::new(reorgs_total.clone()))?;
        registry.register(Box::new(finalized_height.clone()))?;
        registry.register(Box::new(active_validators.clone()))?;
        registry.register(Box::new(pending_finality_certificates.clone()))?;
        registry.register(Box::new(liveness_tracked_validators.clone()))?;
        registry.register(Box::new(invalid_vote_tracked_validators.clone()))?;
        registry.register(Box::new(poa_onboarding_audit_rows.clone()))?;
        registry.register(Box::new(poa_onboarding_membership_rows.clone()))?;
        registry.register(Box::new(poa_onboarding_admin_rows.clone()))?;
        registry.register(Box::new(pending_domain_unfreeze_rows.clone()))?;
        registry.register(Box::new(pending_poa_freeze_rows.clone()))?;
        registry.register(Box::new(pending_poa_unfreeze_rows.clone()))?;
        registry.register(Box::new(pending_bud_boost_atoms.clone()))?;
        registry.register(Box::new(block_propagation_seconds.clone()))?;
        registry.register(Box::new(mempool_sender_count.clone()))?;
        registry.register(Box::new(peer_connection_quality.clone()))?;
        registry.register(Box::new(consensus_round_seconds.clone()))?;
        registry.register(Box::new(finality_lag.clone()))?;
        registry.register(Box::new(storage_db_size_bytes.clone()))?;
        registry.register(Box::new(content_store_chunks.clone()))?;
        registry.register(Box::new(content_store_bytes.clone()))?;
        registry.register(Box::new(storage_write_seconds.clone()))?;
        registry.register(Box::new(storage_read_seconds.clone()))?;
        registry.register(Box::new(settlement_commitments_total.clone()))?;
        registry.register(Box::new(settlement_domain_rows.clone()))?;
        registry.register(Box::new(settlement_commitment_rows.clone()))?;
        registry.register(Box::new(settlement_sovereign_template_rows.clone()))?;
        registry.register(Box::new(settlement_frozen_domains.clone()))?;
        registry.register(Box::new(settlement_global_headers_sealed.clone()))?;
        registry.register(Box::new(settlement_equivocations_detected.clone()))?;
        registry.register(Box::new(graft_transactions_total.clone()))?;
        registry.register(Box::new(contract_calls_total.clone()))?;
        registry.register(Box::new(restaked_validator_rows.clone()))?;
        registry.register(Box::new(proof_market_active_tasks.clone()))?;
        registry.register(Box::new(proof_market_pending_receipts.clone()))?;
        registry.register(Box::new(proof_market_escrow_accounts.clone()))?;
        registry.register(Box::new(reward_pool_balance.clone()))?;
        registry.register(Box::new(delegation_positions.clone()))?;
        registry.register(Box::new(delegation_unbonding_positions.clone()))?;
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
        registry.register(Box::new(cross_domain_message_rows.clone()))?;
        registry.register(Box::new(external_domain_rows.clone()))?;
        registry.register(Box::new(external_attestations_accepted.clone()))?;
        registry.register(Box::new(external_quorum_rounds.clone()))?;
        registry.register(Box::new(external_bond_escrow_rows.clone()))?;
        registry.register(Box::new(external_bond_escrow_atoms.clone()))?;
        registry.register(Box::new(relayer_pending_rows.clone()))?;
        registry.register(Box::new(relayer_ledger_rows.clone()))?;
        registry.register(Box::new(relayer_intent_rows.clone()))?;
        registry.register(Box::new(relayer_bid_rows.clone()))?;
        registry.register(Box::new(relayer_escrowed_atoms.clone()))?;
        registry.register(Box::new(role_bond_rows.clone()))?;
        registry.register(Box::new(active_relayer_rows.clone()))?;
        registry.register(Box::new(active_prover_rows.clone()))?;
        registry.register(Box::new(registry_slashing_rows.clone()))?;
        registry.register(Box::new(registry_commission_rows.clone()))?;
        registry.register(Box::new(poa_admission_domains.clone()))?;
        registry.register(Box::new(poa_admitted_authorities.clone()))?;
        registry.register(Box::new(poa_compliance_frozen_accounts.clone()))?;
        registry.register(Box::new(storage_reallocation_rows.clone()))?;
        registry.register(Box::new(storage_manifest_rows.clone()))?;
        registry.register(Box::new(storage_deal_rows.clone()))?;
        registry.register(Box::new(storage_challenge_rows.clone()))?;
        registry.register(Box::new(storage_result_rows.clone()))?;
        registry.register(Box::new(ai_requests_total.clone()))?;
        registry.register(Box::new(ai_outcomes_finalized.clone()))?;
        registry.register(Box::new(ai_model_rows.clone()))?;
        registry.register(Box::new(ai_request_rows.clone()))?;
        registry.register(Box::new(ai_result_rows.clone()))?;
        registry.register(Box::new(ai_outcome_rows.clone()))?;
        registry.register(Box::new(ai_verifier_stake_rows.clone()))?;
        registry.register(Box::new(ai_callback_event_rows.clone()))?;
        registry.register(Box::new(governance_proposal_rows.clone()))?;
        registry.register(Box::new(governance_active_proposal_rows.clone()))?;
        registry.register(Box::new(constitution_parameter_rows.clone()))?;
        registry.register(Box::new(privacy_live_note_rows.clone()))?;
        registry.register(Box::new(privacy_spent_nullifier_rows.clone()))?;
        registry.register(Box::new(privacy_spent_commitment_rows.clone()))?;
        registry.register(Box::new(tokenomics_burned_total.clone()))?;
        registry.register(Box::new(tokenomics_years_burned.clone()))?;
        registry.register(Box::new(tokenomics_timed_burned_total.clone()))?;
        registry.register(Box::new(tokenomics_team_locked.clone()))?;
        registry.register(Box::new(bns_names_registered.clone()))?;
        registry.register(Box::new(bns_name_rows.clone()))?;
        registry.register(Box::new(nft_rows.clone()))?;
        registry.register(Box::new(vault_folder_rows.clone()))?;
        registry.register(Box::new(vault_membership_rows.clone()))?;
        registry.register(Box::new(pollen_offer_rows.clone()))?;
        registry.register(Box::new(pollen_asset_rows.clone()))?;
        registry.register(Box::new(pollen_grant_rows.clone()))?;
        registry.register(Box::new(pollen_purchase_rows.clone()))?;
        registry.register(Box::new(pollen_protected_content_rows.clone()))?;
        registry.register(Box::new(budlumxyz_app_rows.clone()))?;
        registry.register(Box::new(identity_record_rows.clone()))?;
        registry.register(Box::new(identity_credential_rows.clone()))?;
        registry.register(Box::new(identity_revoked_rows.clone()))?;
        registry.register(Box::new(slashing_events_total.clone()))?;
        registry.register(Box::new(pq_verifier_disagreement.clone()))?;
        registry.register(Box::new(rpc_rate_limited_total.clone()))?;

        Ok(Metrics {
            registry: Arc::new(registry),
            chain_height,
            account_rows,
            unbonding_rows,
            transfer_fee_ppm,
            swap_fee_ppm,
            bridge_fee_ppm,
            app_fee_share_ppm,
            bridge_relayer_fee_ppm,
            mempool_size,
            mempool_bytes,
            gossip_scored_peers,
            blocks_produced,
            transactions_processed,
            reorgs_total,
            finalized_height,
            active_validators,
            pending_finality_certificates,
            liveness_tracked_validators,
            invalid_vote_tracked_validators,
            poa_onboarding_audit_rows,
            poa_onboarding_membership_rows,
            poa_onboarding_admin_rows,
            pending_domain_unfreeze_rows,
            pending_poa_freeze_rows,
            pending_poa_unfreeze_rows,
            pending_bud_boost_atoms,
            block_propagation_seconds,
            mempool_sender_count,
            peer_connection_quality,
            consensus_round_seconds,
            finality_lag,
            storage_db_size_bytes,
            content_store_chunks,
            content_store_bytes,
            storage_write_seconds,
            storage_read_seconds,
            settlement_commitments_total,
            settlement_domain_rows,
            settlement_commitment_rows,
            settlement_sovereign_template_rows,
            settlement_frozen_domains,
            settlement_global_headers_sealed,
            settlement_equivocations_detected,
            graft_transactions_total,
            contract_calls_total,
            restaked_validator_rows,
            proof_market_active_tasks,
            proof_market_pending_receipts,
            proof_market_escrow_accounts,
            reward_pool_balance,
            delegation_positions,
            delegation_unbonding_positions,
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
            cross_domain_message_rows,
            external_domain_rows,
            external_attestations_accepted,
            external_quorum_rounds,
            external_bond_escrow_rows,
            external_bond_escrow_atoms,
            relayer_pending_rows,
            relayer_ledger_rows,
            relayer_intent_rows,
            relayer_bid_rows,
            relayer_escrowed_atoms,
            role_bond_rows,
            active_relayer_rows,
            active_prover_rows,
            registry_slashing_rows,
            registry_commission_rows,
            poa_admission_domains,
            poa_admitted_authorities,
            poa_compliance_frozen_accounts,
            storage_reallocation_rows,
            storage_manifest_rows,
            storage_deal_rows,
            storage_challenge_rows,
            storage_result_rows,
            ai_requests_total,
            ai_outcomes_finalized,
            ai_model_rows,
            ai_request_rows,
            ai_result_rows,
            ai_outcome_rows,
            ai_verifier_stake_rows,
            ai_callback_event_rows,
            governance_proposal_rows,
            governance_active_proposal_rows,
            constitution_parameter_rows,
            privacy_live_note_rows,
            privacy_spent_nullifier_rows,
            privacy_spent_commitment_rows,
            tokenomics_burned_total,
            tokenomics_years_burned,
            tokenomics_timed_burned_total,
            tokenomics_team_locked,
            bns_names_registered,
            bns_name_rows,
            nft_rows,
            vault_folder_rows,
            vault_membership_rows,
            pollen_offer_rows,
            pollen_asset_rows,
            pollen_grant_rows,
            pollen_purchase_rows,
            pollen_protected_content_rows,
            budlumxyz_app_rows,
            identity_record_rows,
            identity_credential_rows,
            identity_revoked_rows,
            slashing_events_total,
            pq_verifier_disagreement,
        })
    }

    pub fn encode(&self) -> String {
        // The facade counts disagreements in a process-wide atomic; bring the
        // series up to it. `get` and `inc_by` race only with another scrape,
        // and the saturating difference keeps that harmless.
        let seen = crate::crypto::pq::verifier_disagreements();
        self.pq_verifier_disagreement
            .inc_by(seen.saturating_sub(self.pq_verifier_disagreement.get()));
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
            "budlum_account_rows",
            "budlum_unbonding_rows",
            "budlum_transfer_fee_ppm",
            "budlum_swap_fee_ppm",
            "budlum_bridge_fee_ppm",
            "budlum_app_fee_share_ppm",
            "budlum_bridge_relayer_fee_ppm",
            "budlum_active_validators",
            "budlum_pending_finality_certificates",
            "budlum_liveness_tracked_validators",
            "budlum_invalid_vote_tracked_validators",
            "budlum_poa_onboarding_audit_rows",
            "budlum_poa_onboarding_membership_rows",
            "budlum_poa_onboarding_admin_rows",
            "budlum_pending_domain_unfreeze_rows",
            "budlum_pending_poa_freeze_rows",
            "budlum_pending_poa_unfreeze_rows",
            "budlum_pending_bud_boost_atoms",
            "budlum_mempool_size",
            "budlum_mempool_bytes",
            "budlum_mempool_sender_count",
            "budlum_bridge_amount_locked",
            "budlum_bridge_transfer_rows",
            "budlum_cross_domain_message_rows",
            "budlum_external_domain_rows",
            "budlum_external_attestations_accepted",
            "budlum_external_quorum_rounds",
            "budlum_external_bond_escrow_rows",
            "budlum_external_bond_escrow_atoms",
            "budlum_relayer_pending_rows",
            "budlum_relayer_ledger_rows",
            "budlum_relayer_intent_rows",
            "budlum_relayer_bid_rows",
            "budlum_relayer_escrowed_atoms",
            "budlum_role_bond_rows",
            "budlum_active_relayer_rows",
            "budlum_active_prover_rows",
            "budlum_registry_slashing_rows",
            "budlum_registry_commission_rows",
            "budlum_poa_admission_domains",
            "budlum_poa_admitted_authorities",
            "budlum_poa_compliance_frozen_accounts",
            "budlum_storage_reallocation_rows",
            "budlum_storage_manifest_rows",
            "budlum_storage_deal_rows",
            "budlum_storage_challenge_rows",
            "budlum_storage_result_rows",
            "budlum_storage_db_size_bytes",
            "budlum_content_store_chunks",
            "budlum_content_store_bytes",
            "budlum_p2p_peers_connected",
            "budlum_p2p_gossip_duplicates",
            "budlum_p2p_sync_requests",
            "budlum_peer_connection_quality",
            "budlum_bns_names_registered",
            "budlum_bns_name_rows",
            "budlum_nft_rows",
            "budlum_vault_folder_rows",
            "budlum_vault_membership_rows",
            "budlum_pollen_offer_rows",
            "budlum_pollen_asset_rows",
            "budlum_pollen_grant_rows",
            "budlum_pollen_purchase_rows",
            "budlum_pollen_protected_content_rows",
            "budlum_budlumxyz_app_rows",
            "budlum_identity_record_rows",
            "budlum_identity_credential_rows",
            "budlum_identity_revoked_rows",
            "budlum_ai_requests_total",
            "budlum_ai_outcomes_finalized",
            "budlum_ai_model_rows",
            "budlum_ai_request_rows",
            "budlum_ai_result_rows",
            "budlum_ai_outcome_rows",
            "budlum_ai_verifier_stake_rows",
            "budlum_ai_callback_event_rows",
            "budlum_governance_proposal_rows",
            "budlum_governance_active_proposal_rows",
            "budlum_constitution_parameter_rows",
            "budlum_privacy_live_note_rows",
            "budlum_privacy_spent_nullifier_rows",
            "budlum_privacy_spent_commitment_rows",
            "budlum_tokenomics_burned_total",
            "budlum_tokenomics_years_burned",
            "budlum_tokenomics_timed_burned_total",
            "budlum_tokenomics_team_locked",
            "budlum_slashing_events_total",
            "budlum_pq_verifier_disagreement",
            "budlum_settlement_equivocations_detected",
            "budlum_proof_market_active_tasks",
            "budlum_proof_market_pending_receipts",
            "budlum_proof_market_escrow_accounts",
            "budlum_settlement_domain_rows",
            "budlum_settlement_commitment_rows",
            "budlum_settlement_sovereign_template_rows",
            "budlum_reward_pool_balance",
            "budlum_delegation_positions",
            "budlum_delegation_unbonding_positions",
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

    /// A split verdict between the two ML-DSA libraries reaches the scrape.
    #[test]
    fn pq_verifier_disagreement_is_exported() {
        let metrics = Metrics::new().expect("metrics build");
        let before = crate::crypto::pq::verifier_disagreements();
        assert!(crate::crypto::pq::combine_verdicts(true, false).is_err());
        assert!(crate::crypto::pq::verifier_disagreements() > before);
        let scrape = metrics.encode();
        assert!(
            metrics.pq_verifier_disagreement.get() >= 1,
            "the series must follow the facade counter"
        );
        assert!(scrape.contains("budlum_pq_verifier_disagreement"));
    }
}
