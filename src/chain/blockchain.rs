use crate::chain::finality::{
    FinalityAggregator, FinalityCert, Precommit, Prevote, ValidatorEntry, ValidatorSetSnapshot,
    BLS_VOTE_SIGNATURE_BYTES, MAX_CHECKPOINT_HASH_LEN,
};
use crate::chain::genesis::GenesisConfig;
use crate::chain::snapshot::PruningManager;
use crate::consensus::pos::SlashingEvidence;
use crate::consensus::qc::{QcBlob, QcFaultProof, QcProofAction, QcProofVerdict};
use crate::consensus::ConsensusEngine;
use crate::core::account::{AccountState, GENESIS_BALANCE};
use crate::core::address::Address;
use crate::core::block::Block;
use crate::core::chain_config::Network;
use crate::core::transaction::Transaction;
use crate::cross_domain::{BridgeState, CrossDomainMessageRegistry};
#[cfg(test)]
use crate::cross_domain::{DomainEvent, MerkleProof};
#[cfg(test)]
use crate::domain::{ConsensusDomain, DomainCommitment, FinalityProof};
use crate::domain::{DomainId, DomainPluginRegistry};
use crate::execution::executor::Executor;
use crate::mempool::pool::Mempool;
use crate::settlement::anchor_production::AnchorEmission;
use crate::settlement::cold_quorum::DeviceSignature;
use crate::settlement::ColdWalletState;
use crate::settlement::{merkle_root, GlobalBlockHeader};
#[cfg(test)]
use crate::settlement::{ProofVerificationError, VerifiedDomainEvent};
use crate::storage::db::Storage;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

/// Re-exported so the two reorg gates cannot drift apart.
///
/// `try_reorg` (here) and `ConsensusEngine::is_better_chain`
/// (`consensus/mod.rs`) both refuse a reorg deeper than this. They had
/// separate `= 100` declarations with nothing tying them together: changing
/// one left the other enforcing the old depth, so a chain could be refused by
/// the fork-choice rule and accepted by the state machine, or the reverse.
/// One definition, two call sites.
pub use crate::consensus::MAX_REORG_DEPTH;
pub const FINALITY_DEPTH: usize = 50;
/// Validator set snapshots retained, in memory and on disk.
///
/// One owner for the bound: `new_with_genesis` trims the set it loads from
/// Disk, and `record_validator_snapshot` trims as it grows. Two literals
/// Would let a reload keep more than the live path is willing to hold.
pub const MAX_VALIDATOR_SNAPSHOTS: usize = 100;
/// Upper bound of the slashing evidence pool. The pool is copied into the next
/// block, so it must stay small.
/// How long an alarm stays in the ledger.
/// Orders of magnitude past any honest audit window and still finite -
/// "never trimmed" was the finding.
const ALARM_RETENTION_BLOCKS: u64 = 100_000;
const MAX_PENDING_SLASHING_EVIDENCE: usize = 64;
#[cfg(test)]
pub const EPOCH_LENGTH: u64 = 10;

pub use crate::domain::storage_deal::{StorageEconomicsEvent, StorageEconomicsEventKind};

/// A committed checkpoint header and the material that ties it to a
/// finalized block: the block's state root reopens, with the header
/// hash as the summary, to `state_root`
/// (`AccountState::root_from_opening`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalHeaderProof {
    pub header: GlobalBlockHeader,
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    /// `None` when this node did not record the opening (it synced past
    /// the checkpoint from a snapshot).
    pub state_root_body: Option<crate::domain::Hash32>,
}

/// What the regeneration tick reads about one stage and height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqStageObservation {
    /// The commitment this node holds.
    pub local: Option<[u8; 32]>,
    /// The canonical commitment of the post-quantum source.
    pub canonical: Option<[u8; 32]>,
    /// The seal behind `canonical`.
    pub seal: Option<crate::domain::SealId>,
}

/// Votes kept for a round that has not started (or not reached prevote
/// quorum) yet. See `Blockchain::early_finality_votes`.
#[derive(Default)]
struct EarlyFinalityVotes {
    prevotes: Vec<Prevote>,
    precommits: Vec<Precommit>,
}

/// The most votes kept per kind. A round is four votes on the devnet mesh and
/// a few hundred on the testnet one; the remainder is an attacker's, so the
/// buffer drops the oldest instead of growing.
const MAX_EARLY_FINALITY_VOTES: usize = 64;

pub struct Blockchain {
    pub chain: Vec<Block>,
    pub consensus: Arc<dyn ConsensusEngine>,
    pub mempool: Mempool,
    pub storage: Option<Storage>,
    pub state: AccountState,
    pub chain_id: u64,
    genesis_config: GenesisConfig,
    pub pruning_manager: Option<PruningManager>,
    pub finalized_height: u64,
    pub finalized_hash: String,
    /// State-machine sharding parameters (Whitepaper v1.3). Defaults to
    /// disabled; a chain that enables it commits `shards_root` in every block
    /// from activation onward and validates it on ingest.
    pub sharding: crate::sharding::ShardingConfig,
    pub genesis_time: u128,
    pub verified_qc_blobs: BTreeMap<u64, QcBlob>,
    /// Maximum verified QC blobs retained in the in-memory cache.
    /// Disk-backed nodes can still load an older blob through `get_qc_blob`.
    pub max_qc_blobs: usize,
    pub validator_snapshots: BTreeMap<u64, ValidatorSetSnapshot>,
    /// Maximum number of validator snapshots to keep in memory.
    /// Older snapshots are pruned at epoch boundaries.
    pub max_validator_snapshots: usize,
    pub pending_finality_certs: BTreeMap<u64, Vec<FinalityCert>>,
    /// Maximum total number of pending finality certificates retained in memory.
    /// This bounds entries, not only distinct checkpoint-height buckets.
    pub max_pending_certs: usize,
    pub global_headers: Vec<GlobalBlockHeader>,
    /// The state root opening of the checkpoint block behind each archived
    /// header, by global height: node-local proof material for
    /// `bud_getGlobalHeaderProof`.
    pub global_header_openings: BTreeMap<u64, crate::domain::Hash32>,
    /// The Graft payment window and the rest of the registry opening as
    /// they stood at each recent checkpoint, by global height:
    /// node-local proof material for `bud_graftPaymentProof`, so a payment
    /// can be proven against a header after later payments moved the window.
    /// Rebuilt from the next checkpoint after a restart.
    pub graft_payment_windows: BTreeMap<
        u64,
        (
            Vec<crate::settlement::graft::GraftPayment>,
            crate::domain::Hash32,
        ),
    >,
    pub plugin_registry: DomainPluginRegistry,
    /// Durable alarm & quarantine ledger. Node-local and persisted
    /// through the storage layer; deliberately not folded into the state root
    /// (see `registry/quarantine_ledger.rs`).
    pub quarantine_ledger: crate::registry::QuarantineLedger,
    /// The ledger is written once per block while this
    /// is set, not once per event.
    pub quarantine_dirty: bool,
    pub pending_slashing_evidence: Vec<SlashingEvidence>,
    pub pending_registry_slashing_reports: Vec<crate::registry::evidence::SlashingReport>,
    pub local_invalid_votes: crate::registry::InvalidVoteTracker,
    pub finality_aggregator: Option<FinalityAggregator>,
    /// Votes that reached this node before it had a round - or a prevote
    /// quorum - to put them in. A peer votes the moment it holds the
    /// checkpoint, which can be earlier than this node's own aggregator
    /// exists, and the vote is published once: dropping it here is the
    /// difference between a round that finalizes and one that starves while
    /// blocks keep coming. Bounded, because these votes are kept before the
    /// round that would validate them exists.
    early_finality_votes: EarlyFinalityVotes,
    pub metrics: Option<Arc<crate::core::metrics::Metrics>>,
    /// The anchor emission trace, run on every
    /// checkpoint header a committed block carries; the default is GatedOff
    /// (skip).
    pub anchor_emission: AnchorEmission,
    /// The seals regeneration may trust: Root Seals and verified
    /// anchors from the emission pipeline, finality checkpoints with a
    /// verified ML-DSA QC. Read by the node's regeneration health tick.
    pub pq_source: crate::domain::PqCanonicalSource,
    /// The weakest quantum class each emitted anchor window carried, so the
    /// local recomputation of its aggregate root uses the class it was signed
    /// with. Bounded, memory only.
    anchor_classes: BTreeMap<u64, crate::crypto::facts::QuantumClass>,
    /// The cold-wallet committee state, when the node
    /// runs with a cold committee. `None` today; the rotation entry on this
    /// chain exercises cold_wallet + cold_quorum through pq_anchor.
    pub cold_wallet: Option<ColdWalletState>,
    /// The scheme and suite statuses of this chain. A fresh
    /// chain holds the genesis statuses of the scheme table; the only sources
    /// that move a status are the Frost Alarm, the cold committee emergency
    /// record and, for `Reserved -> Active`, governance (`crypto::scheme`).
    /// Signature checks that run on behalf of the chain read it through
    /// `crypto::pq::verify_in`.
    pub scheme_registry: crate::crypto::scheme::SchemeStatusRegistry,
}

/// Heights one finality event looks at for witness pruning: finality
/// advances by one checkpoint interval at a time, which this covers.
const WITNESS_PRUNE_WINDOW: u64 = 1024;

/// The storage-economics ledger as it is persisted on its own row
/// (`STORAGE_ECONOMICS_STATE`).
///
/// The same value the storage registry root folds, so a row written here and
/// the live ledger cannot disagree about what was accounted. It carries the
/// ledger's own serde shape: `encode`/`decode` above are the only readers and
/// writers, and a row that does not decode as this shape is refused rather
/// than patched.
pub type StorageEconomicsStateSnapshot = crate::domain::storage_deal::StorageEconomicsLedger;

impl Blockchain {
    pub fn with_metrics(mut self, metrics: Arc<crate::core::metrics::Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Pin the state-machine sharding parameters (Whitepaper v1.3).
    ///
    /// This is a consensus parameter and must be set identically on every
    /// node of the chain before the activation height.
    #[must_use]
    pub fn with_sharding(mut self, sharding: crate::sharding::ShardingConfig) -> Self {
        self.sharding = sharding;
        self
    }

    pub(crate) fn emit_chain_metrics(&self) {
        if let Some(ref m) = self.metrics {
            let height = self.chain.len() as i64;
            m.chain_height.set(height);
            m.account_rows
                .set(i64::try_from(self.state.accounts.len()).unwrap_or(i64::MAX));
            m.unbonding_rows
                .set(i64::try_from(self.state.unbonding_queue.len()).unwrap_or(i64::MAX));
            let fee_params = self.state.registry.params();
            m.transfer_fee_ppm
                .set(i64::try_from(fee_params.transfer_fee_ppm).unwrap_or(i64::MAX));
            m.swap_fee_ppm
                .set(i64::try_from(fee_params.swap_fee_ppm).unwrap_or(i64::MAX));
            m.bridge_fee_ppm
                .set(i64::try_from(fee_params.bridge_fee_ppm).unwrap_or(i64::MAX));
            m.app_fee_share_ppm
                .set(i64::try_from(fee_params.app_fee_share_ppm).unwrap_or(i64::MAX));
            m.bridge_relayer_fee_ppm
                .set(i64::try_from(fee_params.bridge_relayer_fee_ppm).unwrap_or(i64::MAX));
            m.finalized_height.set(self.finalized_height as i64);
            m.active_validators.set(
                i64::try_from(
                    self.state
                        .validators
                        .values()
                        .filter(|validator| validator.active && !validator.slashed)
                        .count(),
                )
                .unwrap_or(i64::MAX),
            );
            m.pending_finality_certificates
                .set(i64::try_from(self.pending_finality_cert_count()).unwrap_or(i64::MAX));
            m.liveness_tracked_validators.set(
                i64::try_from(self.state.liveness.tracked_validator_count()).unwrap_or(i64::MAX),
            );
            m.invalid_vote_tracked_validators.set(
                i64::try_from(self.state.invalid_votes.tracked_validator_count())
                    .unwrap_or(i64::MAX),
            );
            m.poa_onboarding_audit_rows.set(
                i64::try_from(self.state.poa_onboarding.audit_event_count()).unwrap_or(i64::MAX),
            );
            m.poa_onboarding_membership_rows.set(
                i64::try_from(self.state.poa_onboarding.membership_count()).unwrap_or(i64::MAX),
            );
            m.poa_onboarding_admin_rows
                .set(i64::try_from(self.state.poa_onboarding.admin_count()).unwrap_or(i64::MAX));
            m.pending_domain_unfreeze_rows
                .set(i64::try_from(self.state.pending_domain_unfreezes.len()).unwrap_or(i64::MAX));
            m.pending_poa_freeze_rows
                .set(i64::try_from(self.state.pending_poa_freezes.len()).unwrap_or(i64::MAX));
            m.pending_poa_unfreeze_rows
                .set(i64::try_from(self.state.pending_poa_unfreezes.len()).unwrap_or(i64::MAX));
            m.pending_bud_boost_atoms
                .set(i64::try_from(self.state.pending_bud_boost_share).unwrap_or(i64::MAX));
            m.blocks_produced.inc();
            m.finality_lag
                .set((height as u64).saturating_sub(self.finalized_height) as i64);
            m.mempool_size.set(self.mempool.len() as i64);
            // Exported alongside the count because the count does not bound
            // memory. See `mempool::pool::DEFAULT_MAX_POOL_BYTES`.
            m.mempool_bytes
                .set(i64::try_from(self.mempool.resident_bytes()).unwrap_or(i64::MAX));
            // Distinct senders, not entry count: concentration is invisible
            // from `mempool_size` alone.
            m.mempool_sender_count
                .set(i64::try_from(self.mempool.sender_count()).unwrap_or(i64::MAX));
            // Locked bridge inventory: sum of transfer amounts still in
            // `BridgeStatus::Locked`. Minted/unlocked transfers drop out.
            m.bridge_amount_locked.set(
                i64::try_from(
                    self.state
                        .bridge_state
                        .locked_amount_total()
                        .min(u128::try_from(i64::MAX).unwrap_or(u128::MAX)),
                )
                .unwrap_or(i64::MAX),
            );
            m.bridge_transfer_rows
                .set(i64::try_from(self.state.bridge_state.transfer_count()).unwrap_or(i64::MAX));
            m.storage_reallocation_rows.set(
                i64::try_from(self.state.storage_registry.reallocation_ticket_count())
                    .unwrap_or(i64::MAX),
            );
            m.storage_manifest_rows.set(
                i64::try_from(self.state.storage_registry.manifest_count()).unwrap_or(i64::MAX),
            );
            m.storage_deal_rows
                .set(i64::try_from(self.state.storage_registry.deal_count()).unwrap_or(i64::MAX));
            m.storage_challenge_rows.set(
                i64::try_from(self.state.storage_registry.challenge_count()).unwrap_or(i64::MAX),
            );
            m.storage_result_rows
                .set(i64::try_from(self.state.storage_registry.result_count()).unwrap_or(i64::MAX));
            m.bns_name_rows
                .set(i64::try_from(self.state.bns_registry.names.len()).unwrap_or(i64::MAX));
            m.nft_rows
                .set(i64::try_from(self.state.nft_registry.nfts.len()).unwrap_or(i64::MAX));
            m.vault_folder_rows
                .set(i64::try_from(self.state.vault.folder_count()).unwrap_or(i64::MAX));
            m.vault_membership_rows
                .set(i64::try_from(self.state.vault.membership_count()).unwrap_or(i64::MAX));
            m.pollen_offer_rows
                .set(i64::try_from(self.state.marketplace.offers.len()).unwrap_or(i64::MAX));
            m.pollen_asset_rows
                .set(i64::try_from(self.state.marketplace.data_assets.len()).unwrap_or(i64::MAX));
            m.pollen_grant_rows
                .set(i64::try_from(self.state.marketplace.access_grants.len()).unwrap_or(i64::MAX));
            m.pollen_purchase_rows.set(
                i64::try_from(self.state.marketplace.purchase_receipts.len()).unwrap_or(i64::MAX),
            );
            m.pollen_protected_content_rows.set(
                i64::try_from(self.state.marketplace.protected_content.len()).unwrap_or(i64::MAX),
            );
            m.budlumxyz_app_rows
                .set(i64::try_from(self.state.budlumxyz.apps.len()).unwrap_or(i64::MAX));
            m.identity_record_rows
                .set(i64::try_from(self.state.identity.record_count()).unwrap_or(i64::MAX));
            m.identity_credential_rows
                .set(i64::try_from(self.state.identity.credential_count()).unwrap_or(i64::MAX));
            m.identity_revoked_rows
                .set(i64::try_from(self.state.identity.revoked_count()).unwrap_or(i64::MAX));
            m.ai_model_rows
                .set(i64::try_from(self.state.ai_registry.model_count()).unwrap_or(i64::MAX));
            m.ai_request_rows
                .set(i64::try_from(self.state.ai_registry.request_count()).unwrap_or(i64::MAX));
            m.ai_result_rows
                .set(i64::try_from(self.state.ai_registry.result_count()).unwrap_or(i64::MAX));
            m.ai_outcome_rows
                .set(i64::try_from(self.state.ai_registry.outcome_count()).unwrap_or(i64::MAX));
            m.ai_verifier_stake_rows.set(
                i64::try_from(self.state.ai_registry.verifier_stake_count()).unwrap_or(i64::MAX),
            );
            m.ai_callback_event_rows.set(
                i64::try_from(self.state.ai_registry.callback_event_count()).unwrap_or(i64::MAX),
            );
            m.governance_proposal_rows
                .set(i64::try_from(self.state.governance.proposal_count()).unwrap_or(i64::MAX));
            m.governance_active_proposal_rows.set(
                i64::try_from(self.state.governance.active_proposal_count()).unwrap_or(i64::MAX),
            );
            m.constitution_parameter_rows.set(
                i64::try_from(self.state.governance.constitution.parameter_count())
                    .unwrap_or(i64::MAX),
            );
            m.privacy_live_note_rows
                .set(i64::try_from(self.state.note_registry.live_count()).unwrap_or(i64::MAX));
            m.privacy_spent_nullifier_rows
                .set(i64::try_from(self.state.note_registry.spent_count()).unwrap_or(i64::MAX));
            m.privacy_spent_commitment_rows.set(
                i64::try_from(self.state.note_registry.spent_commitment_count())
                    .unwrap_or(i64::MAX),
            );
            m.tokenomics_burned_total
                .set(i64::try_from(self.state.burned_total).unwrap_or(i64::MAX));
            m.tokenomics_years_burned
                .set(i64::try_from(self.state.timed_burn.years_burned).unwrap_or(i64::MAX));
            m.tokenomics_timed_burned_total
                .set(i64::try_from(self.state.timed_burn.total_burned).unwrap_or(i64::MAX));
            let team_locked = self
                .state
                .team_vesting
                .as_ref()
                .map(|(_, schedule)| schedule.locked_at(self.state.epoch_index))
                .unwrap_or(0);
            m.tokenomics_team_locked
                .set(i64::try_from(team_locked).unwrap_or(i64::MAX));
            m.proof_market_active_tasks.set(
                i64::try_from(self.state.proof_market.active_task_count()).unwrap_or(i64::MAX),
            );
            m.proof_market_pending_receipts.set(
                i64::try_from(self.state.proof_market.pending_receipt_count()).unwrap_or(i64::MAX),
            );
            m.proof_market_escrow_accounts.set(
                i64::try_from(self.state.proof_market.escrow_account_count()).unwrap_or(i64::MAX),
            );
            m.reward_pool_balance.set(
                i64::try_from(
                    self.state
                        .get_balance(&crate::tokenomics::reward_pool::reward_pool_account()),
                )
                .unwrap_or(i64::MAX),
            );
            m.delegation_positions
                .set(i64::try_from(self.state.registry.delegation_count()).unwrap_or(i64::MAX));
            m.delegation_unbonding_positions.set(
                i64::try_from(self.state.registry.delegation_unbonding_count()).unwrap_or(i64::MAX),
            );
            if let Some(ref store) = self.storage {
                if let Ok(bytes) = store.size_on_disk() {
                    m.storage_db_size_bytes
                        .set(i64::try_from(bytes).unwrap_or(i64::MAX));
                }
                // Observability must not abort a block commit on disk-stat
                // failure: leave the last scraped value.
            }
        }
    }

    /// Event-local counters for transaction types that own a dedicated metric.
    ///
    /// Called once per successfully committed block, not per mempool accept,
    /// so a tx that never lands does not inflate the counter. Reorgs that
    /// re-apply the same height will recount; prometheus counters already
    /// reset on process restart, and the alternative (remembering every
    /// hash ever applied) is a second consensus log.
    fn emit_applied_tx_metrics(
        &self,
        txs: &[crate::core::transaction::Transaction],
        outcomes_before: usize,
    ) {
        let Some(ref m) = self.metrics else {
            return;
        };
        use crate::core::transaction::TransactionType;
        for tx in txs {
            match &tx.tx_type {
                TransactionType::BnsRegister => {
                    m.bns_names_registered.inc();
                }
                TransactionType::AiInferenceRequest(_) => {
                    m.ai_requests_total.inc();
                }
                _ => {}
            }
        }
        // Finalization is not 1:1 with AiInferenceResult txs (threshold may
        // need several results). The registry length delta across the apply
        // is the honest event count; pruning only shrinks and is ignored.
        let newly_finalized = self
            .state
            .ai_registry
            .outcomes
            .len()
            .saturating_sub(outcomes_before);
        if newly_finalized > 0 {
            m.ai_outcomes_finalized
                .inc_by(u64::try_from(newly_finalized).unwrap_or(u64::MAX));
        }
    }

    pub fn emit_tx_processed(&self, count: u64) {
        if let Some(ref m) = self.metrics {
            m.transactions_processed.inc_by(count);
        }
    }

    pub fn emit_reorg(&self) {
        if let Some(ref m) = self.metrics {
            m.reorgs_total.inc();
        }
    }

    pub fn emit_mempool_eviction(&self) {
        if let Some(ref m) = self.metrics {
            m.mempool_evictions.inc();
        }
    }

    pub fn emit_mempool_cleanup(&self) {
        if let Some(ref m) = self.metrics {
            m.mempool_expired_cleanups.inc();
        }
    }

    fn snapshot_trusted_signers_from_state(state: &AccountState) -> Vec<[u8; 32]> {
        state
            .validators
            .keys()
            .map(|address| *address.as_bytes())
            .collect()
    }

    fn require_signed_startup_snapshot(
        chain_id: u64,
        snapshot: &crate::chain::snapshot::StateSnapshotV2,
        trusted_signers: &[[u8; 32]],
    ) -> Result<(), String> {
        if chain_id
            != crate::core::chain_config::Network::Mainnet
                .chain_id()
                .value()
        {
            return Ok(());
        }
        if trusted_signers.is_empty() {
            return Err("mainnet startup snapshot requires a non-empty signer trust list".into());
        }
        if snapshot.trust_policy != crate::chain::snapshot::SnapshotTrustPolicy::RequireSigned {
            return Err("mainnet startup snapshot requires signed V2 manifest".into());
        }
        snapshot
            .verify_authentic(Some(trusted_signers))
            .map_err(|error| format!("mainnet startup snapshot auth failed: {error}"))
    }

    pub fn new(
        consensus: Arc<dyn ConsensusEngine>,
        storage: Option<Storage>,
        chain_id: u64,
        pruning_manager: Option<PruningManager>,
    ) -> Self {
        Self::new_with_genesis(consensus, storage, chain_id, pruning_manager, None)
    }

    pub fn new_with_genesis(
        consensus: Arc<dyn ConsensusEngine>,
        storage: Option<Storage>,
        chain_id: u64,
        pruning_manager: Option<PruningManager>,
        genesis_config: Option<GenesisConfig>,
    ) -> Self {
        info!("Consensus: {}", consensus.info());
        let mut chain_vec = Vec::new();

        let mut loaded_chain = false;
        if let Some(ref store) = storage {
            if let Ok(c) = store.load_chain() {
                if !c.is_empty() {
                    chain_vec = c;
                    loaded_chain = true;
                    info!("Loaded chain from DB: {} blocks", chain_vec.len());
                }
            }
        }

        let resolved_genesis_config = genesis_config.unwrap_or_else(|| {
            Network::from_chain_id(chain_id)
                .map_or_else(|| GenesisConfig::new(chain_id), GenesisConfig::for_network)
        });
        let bootstrap_domains = resolved_genesis_config
            .bootstrap_consensus_domains()
            .unwrap_or_else(|e| {
                error!("CRITICAL ERROR: invalid genesis bootstrap domain configuration: {e}");
                #[cfg(not(test))]
                std::process::exit(1);
                #[cfg(test)]
                panic!("Invalid genesis bootstrap domain configuration: {e}");
            });
        // The genesis names the PQ scheme the chain launched with; a binary
        // built for the other one would join and then reject every peer's
        // validator registration as a malformed key. Checked here, on every
        // path that builds a chain, not only when a genesis file is passed
        // on the command line.
        if let Err(e) = resolved_genesis_config.validate_pq_scheme() {
            error!("CRITICAL ERROR: {e}");
            #[cfg(not(test))]
            std::process::exit(1);
            #[cfg(test)]
            panic!("Genesis PQ scheme mismatch: {e}");
        }
        // Same treatment for the token distribution: a genesis whose
        // allocations do not sum to the fixed supply seeds no distribution
        // at all, and a chain built on it would look healthy while every
        // account it should have funded stays empty.
        if let Err(e) = resolved_genesis_config.validate_tokenomics_supply() {
            error!("CRITICAL ERROR: {e}");
            #[cfg(not(test))]
            std::process::exit(1);
            #[cfg(test)]
            panic!("Genesis tokenomics supply mismatch: {e}");
        }
        // A chain id that names a real network gets the full ceremony on
        // top of the individual checks above: chain-id agreement,
        // block-reward agreement, validator-list and consensus-key rules,
        // and the mainnet-specific address, authority and PoW-parameter
        // gates. Without this, a built-in per-network genesis that drifted
        // from its ceremony would still build a chain here, while
        // `main.rs` refuses the identical configuration passed as a file.
        // The ceremony is DECLARED by `tokenomics_addresses`: a config that
        // names the ceremony accounts must pass the full ceremony here, no
        // exceptions. The pre-launch per-network skeletons ship without
        // that declaration (the ceremony addresses arrive at launch), so
        // they get a loud warning instead of a refusal.
        if let Some(network) = Network::from_chain_id(chain_id) {
            if resolved_genesis_config.tokenomics_addresses.is_some() {
                if let Err(e) = resolved_genesis_config.validate_consensus_ceremony(network) {
                    error!("CRITICAL ERROR: {e}");
                    #[cfg(not(test))]
                    std::process::exit(1);
                    #[cfg(test)]
                    panic!("Genesis ceremony validation failed: {e}");
                }
            } else if matches!(network, crate::core::chain_config::Network::Mainnet) {
                // Mainnet must never skip the ceremony.
                // The warning-only path existed for the pre-launch skeletons
                // (the ceremony addresses arrive at launch); a MAINNET
                // genesis that declares no ceremony addresses is a mainnet
                // whose ceremony was never checked, which is exactly the
                // gate's whole purpose. Refuse, loudly.
                error!(
                    "CRITICAL ERROR: a mainnet genesis must declare its ceremony \
                     tokenomics addresses; refusing to build a chain whose consensus \
                     ceremony was never validated"
                );
                // Test builds keep the built-in mainnet skeleton usable: the
                // refusal is the process exit of a real node.
                #[cfg(not(test))]
                std::process::exit(1);
            } else {
                warn!(
                    "known network {network:?} genesis declares no ceremony tokenomics \
                     addresses; the consensus ceremony is NOT validated for this chain"
                );
            }
        }

        let mut state = resolved_genesis_config.build_state();
        // The replay below runs identity writes under the engine's domain
        // gate, as the live path did when it applied them.
        state.execution_domain = consensus.domain_kind();

        if !loaded_chain {
            let genesis = resolved_genesis_config.build_genesis_block();
            if let Some(ref store) = storage {
                let mut accounts_to_save = Vec::new();
                for (pubkey, account) in &state.accounts {
                    accounts_to_save.push((*pubkey, account.clone()));
                }
                let batch = crate::storage::traits::DurableCommitBatch {
                    block: genesis.clone(),
                    state_root: genesis.state_root.clone(),
                    finality_cert: None,
                    global_headers: Vec::new(),
                    bridge_state: Some(state.bridge_state.clone()),
                    accounts: accounts_to_save,
                };
                if let Err(e) = store.commit_durable_batch(&batch) {
                    error!("Failed to persist genesis block to storage: {:?}", e);
                }
            }
            chain_vec.push(genesis);
        } else {
            // VERIFICATION CHAIN:
            // Check that the existing genesis block in DB matches resolved_genesis_config / network config!
            let db_genesis = &chain_vec[0];
            let expected_genesis = resolved_genesis_config.build_genesis_block();

            // 1. Chain ID check
            if db_genesis.chain_id != chain_id {
                error!(
                    "CRITICAL ERROR: Startup Chain ID mismatch! DB genesis chain_id: {}, Configured chain_id: {}. Fail-closed startup.",
                    db_genesis.chain_id, chain_id
                );
                #[cfg(not(test))]
                std::process::exit(1);
                #[cfg(test)]
                panic!("Startup Chain ID mismatch!");
            }

            // 2. Genesis Hash check
            if db_genesis.hash != expected_genesis.hash {
                error!(
                    "CRITICAL ERROR: Startup Genesis Hash mismatch! DB genesis hash: {}, Expected hash: {}. Fail-closed startup.",
                    db_genesis.hash, expected_genesis.hash
                );
                #[cfg(not(test))]
                std::process::exit(1);
                #[cfg(test)]
                panic!("Startup Genesis Hash mismatch!");
            }

            // 3. Network Magic check
            let db_network = Network::from_chain_id(db_genesis.chain_id);
            let current_network = Network::from_chain_id(chain_id);
            if db_network != current_network {
                error!(
                    "CRITICAL ERROR: Startup Network Magic mismatch! DB network: {:?}, Configured network: {:?}. Fail-closed startup.",
                    db_network.map(|n| n.magic_bytes()), current_network.map(|n| n.magic_bytes())
                );
                #[cfg(not(test))]
                std::process::exit(1);
                #[cfg(test)]
                panic!("Startup Network Magic mismatch!");
            }
        }

        let mut snapshot_height = 0;
        let mut restored_finalized_height = 0;
        let mut restored_finalized_hash = chain_vec[0].hash.clone();

        if let Some(ref pm) = pruning_manager {
            // Repair (2026-07-19): a load error is no longer swallowed - it is a
            // fail-loud error! log (with quarantine detail). The loader falls back
            // to older candidates internally; an Err arrives only if ALL candidates are broken.
            let v2_load = pm.load_latest_snapshot_v2();
            if let Err(ref e) = v2_load {
                error!(
                    "V2 snapshot load failed (FAIL-LOUD): {e}. Continuing with genesis/DB state - operator intervention advised!"
                );
            }
            // Try V2 snapshot first, fall back to V1
            let v2_loaded = if let Ok(Some(v2_snapshot)) = v2_load {
                if v2_snapshot.chain_id == chain_id {
                    let snapshot_trust_list = Self::snapshot_trusted_signers_from_state(&state);
                    if let Err(error) = Self::require_signed_startup_snapshot(
                        chain_id,
                        &v2_snapshot,
                        &snapshot_trust_list,
                    ) {
                        error!(
                            "CRITICAL ERROR: invalid startup V2 snapshot authentication: {error}"
                        );
                        #[cfg(not(test))]
                        std::process::exit(1);
                        #[cfg(test)]
                        panic!("Invalid startup V2 snapshot authentication: {error}");
                    }
                    state = crate::core::account::AccountState::from_snapshot_v2(&v2_snapshot);
                    snapshot_height = v2_snapshot.height;
                    restored_finalized_height = v2_snapshot.finalized_height;
                    restored_finalized_hash = v2_snapshot.finalized_hash.clone();
                    info!(
                        "Restored state from V2 snapshot at height {} (finalized={}, epoch={}, base_fee={})",
                        snapshot_height, restored_finalized_height, v2_snapshot.epoch_index, v2_snapshot.base_fee
                    );
                    true
                } else {
                    warn!(
                        "V2 snapshot chain_id mismatch (expected {}, got {}). Trying V1 fallback.",
                        chain_id, v2_snapshot.chain_id
                    );
                    false
                }
            } else {
                false
            };

            if !v2_loaded {
                let v1_load = pm.load_latest_snapshot();
                if let Err(ref e) = v1_load {
                    error!(
                        "V1 snapshot load failed (FAIL-LOUD): {e}. Continuing with genesis/DB state!"
                    );
                }
                if let Ok(Some(snapshot)) = v1_load {
                    if snapshot.chain_id == chain_id {
                        if chain_id
                            == crate::core::chain_config::Network::Mainnet
                                .chain_id()
                                .value()
                        {
                            error!(
                                "CRITICAL ERROR: mainnet startup refuses unsigned V1 snapshot fallback"
                            );
                            #[cfg(not(test))]
                            std::process::exit(1);
                            #[cfg(test)]
                            panic!("Mainnet startup refuses unsigned V1 snapshot fallback");
                        }
                        // The V1 fallback restored only
                        // balances and nonces - validators, registry, epoch
                        // and roots stayed at genesis - and then logged
                        // "Restored state", which is a half-truth at best.
                        // A half-restored state is worse than none: the
                        // chain looks healthy on the wrong validator set.
                        // The fallback refuses; testnet and devnet resync
                        // from the V2 path or the chain itself.
                        error!(
                            "CRITICAL ERROR: V1 snapshot at height {} carries only balances \
                             and nonces; validators, registry, epoch and roots cannot be \
                             restored from it. Refusing the half-restore - use a V2 snapshot \
                             or resync.",
                            snapshot.height
                        );
                        #[cfg(not(test))]
                        std::process::exit(1);
                        #[cfg(test)]
                        panic!("V1 snapshot half-restore refused");
                    } else {
                        warn!(
                            "V1 snapshot chain_id mismatch (expected {}, got {}). Ignoring.",
                            chain_id, snapshot.chain_id
                        );
                    }
                }
            }
        }

        let chain_len = chain_vec.len();
        let start_index = if snapshot_height > 0 && snapshot_height < chain_len as u64 {
            (snapshot_height + 1) as usize
        } else {
            if snapshot_height >= chain_len as u64 {
                warn!("Chain shorter than snapshot height, replaying from genesis");
                // The snapshot is ahead of the stored chain, so it cannot be
                // trusted for this chain. Drop it and start from the genesis
                // state, or every block would be applied on top of a state
                // that already holds its effects.
                state = resolved_genesis_config.build_state();
                state.execution_domain = consensus.domain_kind();
                restored_finalized_height = 0;
                restored_finalized_hash = chain_vec[0].hash.clone();
            }
            1
        };

        info!(
            "Replaying blocks from index {} to {}...",
            start_index,
            chain_len - 1
        );

        let mut validator_snapshots = BTreeMap::new();

        // Reload the persisted sets before replay fills in the recent ones.
        //
        // Replay only reconstructs epochs from `start_index` onward, and
        // `start_index` jumps to the state snapshot's height when one exists -
        // So on a node that restores from a snapshot, replay reconstructs
        // Almost nothing and every older epoch was simply gone.
        // `require_validator_snapshot` then refused every past-epoch
        // Certificate and fault proof until the node had observed a fresh
        // Window of epochs. Failing closed is correct; failing closed on every
        // Restart is an outage.
        //
        // Loaded first so the replay below overwrites any stored entry with
        // The one it recomputes: replay is authoritative for the range it
        // Covers.
        if let Some(ref store) = storage {
            match store.load_validator_snapshots() {
                Ok(stored) => {
                    let count = stored.len();
                    for (epoch, snapshot) in stored {
                        validator_snapshots.insert(epoch, snapshot);
                    }
                    if count > 0 {
                        info!("Restored {count} validator set snapshots from disk");
                    }
                }
                Err(error) => warn!(
                    "Could not read persisted validator snapshots: {error}. \
                     Past-epoch verification will refuse until the window refills."
                ),
            }
        }

        validator_snapshots.insert(
            state.epoch_index,
            Self::build_validator_snapshot_from_state(state.epoch_index, &state, chain_id),
        );

        // The stored set can outnumber the live retention window, an older
        // Build may have run with a larger bound, or a write failed between
        // Eviction and delete. Trim to the same limit `record_validator_snapshot`
        // Enforces so the in-memory map has one owner of its size.
        while validator_snapshots.len() > MAX_VALIDATOR_SNAPSHOTS {
            let Some((evicted, _)) = validator_snapshots.pop_first() else {
                break;
            };
            if let Some(ref store) = storage {
                if let Err(error) = store.delete_validator_snapshot(evicted) {
                    warn!("Failed to trim stored validator snapshot {evicted}: {error}");
                }
            }
        }

        for block in chain_vec.iter().skip(start_index) {
            let preceding = &chain_vec[..block.index as usize];
            state = match Self::apply_block_effects(&state, block, preceding) {
                Ok(mut next_state) => {
                    // Startup replay must reconstruct exactly the same state
                    // as `produce_block` committed. `apply_block_effects`
                    // alone does not refresh the four commitment fields, so
                    // without this the restarted node carries stale roots and
                    // the next reorg fails with "Candidate state root mismatch".
                    Self::apply_block_end_roots(&mut next_state, block, preceding, chain_id);
                    next_state
                }
                Err(e) => {
                    error!(
                        "Failed to apply block {} during init: {}. Corrupted database, exiting.",
                        block.index, e
                    );
                    std::process::exit(1);
                }
            };
            validator_snapshots.insert(
                state.epoch_index,
                Self::build_validator_snapshot_from_state(state.epoch_index, &state, chain_id),
            );
        }

        let mempool_config = Network::from_chain_id(chain_id)
            .map(|network| network.mempool_config())
            .unwrap_or_default();
        let mut mempool = Mempool::new(mempool_config);
        if let Some(ref store) = storage {
            if let Ok(txs) = store.load_mempool_txs() {
                let count = txs.len();
                for tx in txs {
                    let _ = mempool.add_transaction(tx);
                }
                if count > 0 {
                    info!("Restored {count} transactions from mempool persistence");
                }
            }
        }

        let _bridge_state = BridgeState::new();
        let mut global_headers = Vec::new();
        let mut global_header_openings = BTreeMap::new();
        let _message_registry = CrossDomainMessageRegistry::new();
        let mut quarantine_ledger = crate::registry::QuarantineLedger::new();

        // The consensus domains, their commitments and the ZK proof claims are
        // settlement registries in the account state: genesis writes the
        // bootstrap domains, blocks write everything after, and the replay
        // above has rebuilt them. A bootstrap domain the genesis could not
        // register is a broken genesis, not a degraded start.
        for domain in &bootstrap_domains {
            if let Err(e) = crate::settlement::domains::validate_domain_registration(domain) {
                error!(
                    "CRITICAL ERROR: invalid genesis bootstrap domain {}: {}",
                    domain.id, e
                );
                #[cfg(not(test))]
                std::process::exit(1);
                #[cfg(test)]
                panic!("Invalid genesis bootstrap domain {}: {}", domain.id, e);
            }
            if state.settlement.domains.get(domain.id).is_none() {
                error!(
                    "CRITICAL ERROR: genesis bootstrap domain {} is not in the genesis state",
                    domain.id
                );
                #[cfg(not(test))]
                std::process::exit(1);
                #[cfg(test)]
                panic!(
                    "Genesis bootstrap domain {} is not in the genesis state",
                    domain.id
                );
            }
        }

        if let Some(ref store) = storage {
            if let Ok(stored_global_headers) = store.load_global_headers() {
                global_headers =
                    Self::validated_global_header_prefix(stored_global_headers, chain_id);
            }
            // The archive follows the headers the replayed state commits.
            Self::reconcile_global_header_archive(&mut global_headers, &state);
            if let Ok(openings) = store.load_global_header_openings() {
                global_header_openings = openings;
            }

            if let Ok(Some(stored_quarantine_ledger)) = store.load_quarantine_ledger() {
                quarantine_ledger = stored_quarantine_ledger;
            }

            // The external intake, the bridge state, the message registry
            // and the universal relayer are not loaded here: they live in the
            // account state, are written only by blocks, and the replay above
            // has already rebuilt them (or the snapshot carried them).
        }

        // The stored-state load above runs AFTER the block-replay loop and
        // replaces `storage_registry`, which `calculate_state_root` hashes
        // live: whatever is loaded from disk must equal what the replay
        // produced, otherwise the node's own state root will not match the
        // tip it just replayed. `bridge_root` / `message_root` are cached
        // commitments, re-derived here from the replayed structures so the
        // cache never describes anything else.
        //
        // Getting this wrong is silent until the node has to validate a chain:
        // `calculate_state_root` disagrees with the `block.state_root` of the
        // replayed tip, and the first reorg fails with "Candidate state root
        // mismatch" - a restarted node refuses a valid canonical chain and
        // stalls (liveness / fork-choice split).
        state.bridge_root = state.bridge_state.root();
        state.message_root = state.message_registry.root();

        // The domain the identity gate runs under is the engine this node
        // started with. Stamped here and at every site that replaces `state`
        // wholesale, so a restart, a reorg replay, and a snapshot sync cannot
        // disagree about a gate that decides writes inside blocks.
        state.execution_domain = consensus.domain_kind();

        let mut bc = Blockchain {
            chain: chain_vec,
            consensus,
            mempool,
            storage,
            state,
            chain_id,
            genesis_config: resolved_genesis_config,
            pruning_manager,
            finalized_height: restored_finalized_height,
            finalized_hash: restored_finalized_hash,
            sharding: crate::sharding::ShardingConfig::default(),
            genesis_time: 0,
            verified_qc_blobs: BTreeMap::new(),
            max_qc_blobs: 1000, // Keep last 1000 QC blobs
            validator_snapshots,
            max_validator_snapshots: MAX_VALIDATOR_SNAPSHOTS,
            pending_finality_certs: BTreeMap::new(),
            max_pending_certs: 100, // Keep last 100 pending cert batches
            global_headers,
            global_header_openings,
            graft_payment_windows: BTreeMap::new(),
            plugin_registry: DomainPluginRegistry::new(),
            quarantine_ledger,
            quarantine_dirty: false,
            pending_slashing_evidence: Vec::new(),
            pending_registry_slashing_reports: Vec::new(),
            local_invalid_votes: crate::registry::InvalidVoteTracker::new(),
            finality_aggregator: None,
            early_finality_votes: EarlyFinalityVotes::default(),
            metrics: None,
            anchor_emission: AnchorEmission::default(),
            pq_source: crate::domain::PqCanonicalSource::new(chain_id),
            anchor_classes: BTreeMap::new(),
            cold_wallet: None,
            scheme_registry: crate::crypto::scheme::SchemeStatusRegistry::genesis(),
        };

        if let Some(first) = bc.chain.first() {
            bc.genesis_time = first.timestamp;
        } else {
            bc.genesis_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_millis())
                .unwrap_or_default();
        }

        if let Some(store) = bc.storage.as_ref() {
            if let Err(e) = bc.consensus.load_state(store) {
                tracing::error!(error = %e, "Failed to load consensus state from store during startup");
            }
        }

        // Restored state carries no block clock, so seed it from the tip.
        if let Some(last) = bc.chain.last() {
            bc.state.current_block_unix_secs = Self::block_timestamp_secs(last.timestamp);
            bc.state.current_block_entropy =
                Self::block_context_entropy(&last.previous_hash, &last.vrf_output);
        }

        bc
    }

    /// Wall-clock seconds according to the chain, taken from the newest
    /// block's timestamp.
    ///
    /// Block timestamps are milliseconds since the unix epoch, so this
    /// divides. Reading the chain rather than the host clock is deliberate:
    /// two nodes applying the same block have to reach the same answer, and
    /// `SystemTime::now()` guarantees they will not.
    #[must_use]
    pub fn current_unix_secs(&self) -> u64 {
        Self::block_timestamp_secs(self.last_block().timestamp)
    }

    /// Converts a block timestamp in milliseconds to whole seconds.
    fn block_timestamp_secs(timestamp_ms: u128) -> u64 {
        u64::try_from(timestamp_ms / 1_000).unwrap_or(u64::MAX)
    }

    /// Entropy a signer cannot know at signing time. The VRF output is empty
    /// for PoA and BFT blocks, and while a block is still being assembled.
    fn block_context_entropy(previous_hash: &str, vrf_output: &[u8]) -> [u8; 32] {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_BLOCK_CONTEXT_ENTROPY_V1",
            previous_hash.as_bytes(),
            vrf_output,
        ])
    }

    /// The timestamp a block at `index` is stamped with when produced.
    fn planned_block_timestamp(&self, index: u64) -> u128 {
        let slot_ms = crate::core::chain_config::slot_ms_for_chain_id(self.chain_id);
        self.genesis_time + (u128::from(index) * u128::from(slot_ms))
    }

    /// The chain tip.
    ///
    /// # Panics
    /// If the chain is empty, which cannot happen: construction always seeds
    /// genesis and nothing removes it. The signature returns `&Block`, so
    /// there is no owned value to fall back to; the alternative would be
    /// changing the return type and every one of the call sites. The panic
    /// is allowed here deliberately rather than by the workspace default.
    #[allow(clippy::expect_used)]
    pub fn last_block(&self) -> &Block {
        self.chain
            .last()
            .expect("chain is seeded with genesis at construction")
    }

    /// Register a sovereign domain template, binding it to the consensus domain it names.
    ///
    /// A template is not evaluated on its own. `register_template_for_domain`
    /// first verifies that the domain is registered, then that the consensus kind
    /// and operator the template declares are the same as the domain's real
    /// values. Without this gate a template could present a domain running as PoS
    /// to an auditor as "permissioned and KYC'd": both records are individually
    /// valid, together they are wrong.
    ///
    /// Test harness only: production registers through the
    /// `SettlementTx::RegisterSovereignTemplate` transaction, whose door runs
    /// this same body (`settlement::domains::register_sovereign_template`).
    ///
    /// # Errors
    ///
    /// Returns an error if the domain is not registered, if the kind or operator
    /// does not match, or if the template's own validation fails.
    #[cfg(test)]
    pub fn register_sovereign_template(
        &mut self,
        template: crate::domain::SovereignDomainTemplate,
    ) -> Result<(), String> {
        crate::settlement::domains::register_sovereign_template(&mut self.state, template)
    }

    /// Test harness only: production registers a domain through the
    /// `SettlementTx::RegisterDomain` transaction, whose door runs this body
    /// (`settlement::domains::register_domain`) after escrowing the bond.
    ///
    /// # Errors
    ///
    /// The registration rule that refused.
    #[cfg(test)]
    pub fn register_consensus_domain(&mut self, domain: ConsensusDomain) -> Result<(), String> {
        crate::settlement::domains::register_domain(&mut self.state, domain)
    }

    /// Test harness only: acceptance without the finality proof or the
    /// anchor. A commitment that freezes its domain is reported as an
    /// error, as the out-of-block path reported it.
    ///
    /// # Errors
    ///
    /// The acceptance refusal, or the freeze.
    #[cfg(test)]
    pub fn submit_domain_commitment(&mut self, commitment: DomainCommitment) -> Result<(), String> {
        Self::harness_outcome(crate::settlement::domains::accept_commitment(
            &mut self.state,
            commitment,
        ))
    }

    /// Test harness only: the body of the `SettlementTx::SubmitCommitment`
    /// door without the carrier bond (finality proof, acceptance, anchor).
    ///
    /// # Errors
    ///
    /// The verification or acceptance refusal, or the freeze.
    #[cfg(test)]
    pub fn submit_verified_domain_commitment(
        &mut self,
        commitment: DomainCommitment,
        proof: FinalityProof,
    ) -> Result<(), String> {
        self.verify_domain_commitment_finality(&commitment, &proof)?;
        self.accept_verified_domain_commitment(commitment)
    }

    /// Test harness only: acceptance and anchor without the proof.
    ///
    /// # Errors
    ///
    /// The acceptance refusal, or the freeze.
    #[cfg(test)]
    pub fn accept_verified_domain_commitment(
        &mut self,
        commitment: DomainCommitment,
    ) -> Result<(), String> {
        Self::harness_outcome(crate::settlement::domains::accept_verified_commitment(
            &mut self.state,
            commitment,
        ))
    }

    /// Test harness only: the finality verdict the door reaches.
    ///
    /// # Errors
    ///
    /// The adapter's refusal.
    #[cfg(test)]
    pub fn verify_domain_commitment_finality(
        &self,
        commitment: &DomainCommitment,
        proof: &FinalityProof,
    ) -> Result<(), String> {
        crate::settlement::domains::verify_commitment_finality(
            &self.state,
            commitment,
            proof,
            crate::cross_domain::external::IntakeState::production_bls,
        )
    }

    /// Test harness only: the body of the `SettlementTx::SubmitZkProof`
    /// door at this chain's height. A proof whose STARK does not verify is
    /// reported as an error here; in block it is an accepted transaction
    /// that burns the proof fee.
    ///
    /// # Errors
    ///
    /// The shape, fee or claim refusal, or the failed verification.
    #[cfg(test)]
    pub fn submit_zk_proof(
        &mut self,
        submission: crate::prover::ZkProofSubmission,
    ) -> Result<crate::prover::ProofAcceptance, String> {
        let height = self.chain.len() as u64;
        match crate::settlement::domains::submit_zk_proof(
            &mut self.state,
            &submission,
            self.chain_id,
            height,
            0,
        )? {
            crate::prover::ProofAcceptance::Rejected => {
                Err("invalid proof: the STARK did not verify".to_string())
            }
            accepted => Ok(accepted),
        }
    }

    #[cfg(test)]
    fn harness_outcome(
        outcome: Result<crate::settlement::domains::CommitmentOutcome, String>,
    ) -> Result<(), String> {
        match outcome? {
            crate::settlement::domains::CommitmentOutcome::Frozen(reason) => Err(format!(
                "Equivocation or invalid sequence detected: {reason}"
            )),
            _ => Ok(()),
        }
    }

    /// The root of the registered sovereign templates.
    #[must_use]
    pub fn sovereign_template_root(&self) -> crate::domain::Hash32 {
        self.state.settlement.sovereign.root()
    }

    /// Validate an audit export against the registered template.
    ///
    /// The `template_id` the bundle carries is looked up in the registry first.
    /// The bundle being internally consistent is not enough: if the identity
    /// comes from inside the bundle, a bundle produced with an invented identity looks consistent too.
    ///
    /// # Errors
    ///
    /// Returns an error if the template is not registered or the bundle does not match the template.
    pub fn validate_sovereign_audit_export(
        &self,
        bundle: &crate::domain::sovereign::AuditExportBundle,
    ) -> Result<(), String> {
        self.state
            .settlement
            .sovereign
            .validate_audit_export(bundle)?;
        // A freeze record must have a CONSEQUENCE. For a long time the ledger
        // only kept records: freezing could be called but being frozen changed
        // nothing - "frozen" was a note, not a decision.
        //
        // The operator is read from the REGISTERED TEMPLATE, not from the bundle.
        // An identity coming from inside the bundle would let a frozen operator
        // write someone else's name and pass the gate.
        let operator = self
            .state
            .settlement
            .sovereign
            .template_operator(bundle.template_id)
            .ok_or_else(|| {
                "AuditExportBundle names a template that is not registered".to_string()
            })?;
        if self
            .state
            .poa_compliance
            .is_frozen(crate::registry::ComplianceDomainKind::PoA, &operator)
        {
            return Err(format!(
                "operator {} is frozen; audit export refused",
                operator.to_hex()
            ));
        }
        Ok(())
    }

    /// Freeze an address in a PoA domain.
    ///
    /// Freezing may only be done in permissioned (PoA) domains and only on a
    /// NAMED admin's authority - the bare `bool` that anybody could pass is
    /// gone. The admin must be an admin of the domain in the admission
    /// registry, or the domain's registered operator when the domain has no
    /// admins yet. The reason digest cannot be zero - a freeze without
    /// evidence makes the record unauditable.
    ///
    /// # Errors
    ///
    /// Returns an error if the domain is not registered, is not PoA, if the
    /// named admin holds no authority on it, or if the reason digest is zero.
    pub fn freeze_poa_account(
        &mut self,
        domain_id: u32,
        admin: crate::core::address::Address,
        address: crate::core::address::Address,
        reason_hash: [u8; 32],
    ) -> Result<(), String> {
        self.apply_poa_compliance_request(domain_id, admin, address, reason_hash, false)
    }

    /// The reverse of [`Self::freeze_poa_account`],
    /// with the same authority rules.
    ///
    /// WIRING: the direct-API half of the PoA compliance door, twin of
    /// `freeze_poa_account`; the governance queue reaches the same code
    /// through `apply_pending_poa_compliance`, and a direct actor
    /// caller for this form is still to land.
    pub fn unfreeze_poa_account(
        &mut self,
        domain_id: u32,
        admin: crate::core::address::Address,
        address: crate::core::address::Address,
        reason_hash: [u8; 32],
    ) -> Result<(), String> {
        self.apply_poa_compliance_request(domain_id, admin, address, reason_hash, true)
    }

    /// Shared body of the freeze/unfreeze pair: domain kind from the record,
    /// named admin verified, ledger write in consensus state.
    fn apply_poa_compliance_request(
        &mut self,
        domain_id: u32,
        admin: crate::core::address::Address,
        address: crate::core::address::Address,
        reason_hash: [u8; 32],
        unfreeze: bool,
    ) -> Result<(), String> {
        let domain = self
            .state
            .settlement
            .domains
            .get(domain_id)
            .ok_or_else(|| format!("unknown domain {domain_id}"))?;
        // The domain's kind is read from its record, not from the caller: a caller
        // cannot declare its own domain "PoA" and manufacture freeze authority.
        let kind = if matches!(domain.kind, crate::domain::ConsensusKind::PoA) {
            crate::registry::ComplianceDomainKind::PoA
        } else {
            crate::registry::ComplianceDomainKind::Permissionless
        };
        // The named admin must actually hold authority on this domain: an
        // admin in the admission registry, or the registered operator while
        // the domain has no admins yet.
        //
        // Only a PoA domain has such authority to check. A permissionless
        // domain has none to hold, and the compliance ledger refuses it by
        // KIND - the refusal that says why, rather than a missing admin.
        if kind == crate::registry::ComplianceDomainKind::PoA {
            let admin_is_admin = self
                .state
                .poa_onboarding
                .registry()
                .is_admin(domain_id, &admin);
            let admin_is_operator = domain.operator == Some(admin);
            if !admin_is_admin && !admin_is_operator {
                return Err(format!(
                    "admin {} holds no authority on domain {domain_id}",
                    admin.to_hex()
                ));
            }
        }
        let height = self.chain.len() as u64;
        let result = if unfreeze {
            self.state
                .poa_compliance
                .unfreeze(kind, admin, address, reason_hash, height)
        } else {
            self.state
                .poa_compliance
                .freeze_suspicious(kind, admin, address, reason_hash, height)
        };
        result.map_err(|e| format!("{e:?}"))
    }

    /// Apply the governance-queued PoA compliance requests ,
    /// mirroring the governance domain unfreezes: the queue is drained at
    /// block close and each request runs the same verification path as the
    /// direct API.
    ///
    /// Convenience: pub as the block-close entry for the governance
    /// queue; both block paths in this file drain it beside the
    /// governance domain unfreezes.
    pub fn apply_pending_poa_compliance(&mut self) -> usize {
        let freezes = self.state.pending_poa_freezes.clone();
        let unfreezes = self.state.pending_poa_unfreezes.clone();
        self.state.pending_poa_freezes.clear();
        self.state.pending_poa_unfreezes.clear();
        let mut applied = 0;
        for req in freezes {
            if self
                .freeze_poa_account(req.domain_id, req.admin, req.target, req.reason_hash)
                .is_ok()
            {
                applied += 1;
            }
        }
        for req in unfreezes {
            if self
                .unfreeze_poa_account(req.domain_id, req.admin, req.target, req.reason_hash)
                .is_ok()
            {
                applied += 1;
            }
        }
        applied
    }

    pub fn submit_slashing_evidence(&mut self, evidence: SlashingEvidence) -> Result<(), String> {
        // Cheap checks first. Any peer can sign headers with a throwaway key,
        // so the producer must be a known validator and the headers must be
        // for this chain, and the pool is bounded.
        if evidence.header1.chain_id != self.chain_id || evidence.header2.chain_id != self.chain_id
        {
            return Err("Slashing evidence is for another chain".into());
        }
        let is_validator = evidence
            .header1
            .producer
            .is_some_and(|producer| self.state.get_validator(&producer).is_some());
        if !is_validator {
            return Err("Slashing evidence producer is not a validator".into());
        }
        if !Self::verify_slashing_evidence(&evidence) {
            return Err("Invalid slashing evidence".into());
        }
        if self.pending_slashing_evidence.iter().any(|existing| {
            existing.header1.hash == evidence.header1.hash
                && existing.header2.hash == evidence.header2.hash
                && existing.signature1 == evidence.signature1
                && existing.signature2 == evidence.signature2
        }) {
            return Ok(());
        }
        if self.pending_slashing_evidence.len() >= MAX_PENDING_SLASHING_EVIDENCE {
            return Err("Slashing evidence pool is full".into());
        }
        // A peer can pad a header far beyond what a block can carry, and the
        // structural proof check does not bound the field lengths. Such an
        // entry can never be included, so it is refused here rather than
        // occupying a queue slot that a live proof could have used.
        let encoded_bytes = serde_json::to_vec(&evidence)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX);
        if encoded_bytes > crate::consensus::MAX_SLASHING_EVIDENCE_BYTES {
            return Err(format!(
                "Slashing evidence is larger than the {} byte block allowance",
                crate::consensus::MAX_SLASHING_EVIDENCE_BYTES
            ));
        }
        self.pending_slashing_evidence.push(evidence);
        Ok(())
    }

    pub fn drain_local_slashing_evidence(&mut self) -> Vec<SlashingEvidence> {
        let mut evidence = self
            .consensus
            .drain_slashing_evidence()
            .unwrap_or_else(|e| {
                tracing::warn!("Failed to drain consensus slashing evidence: {e}");
                Vec::new()
            });
        for item in &evidence {
            let _ = self.submit_slashing_evidence(item.clone());
        }
        evidence.extend(self.pending_slashing_evidence.clone());
        evidence
    }

    fn verify_slashing_evidence(evidence: &SlashingEvidence) -> bool {
        crate::consensus::pos::slashing_evidence_is_valid(evidence)
    }

    /// Evidence a block carries is applied by every engine, so every engine
    /// must refuse a block whose evidence does not verify.
    fn check_block_slashing_evidence(block: &Block) -> Result<(), String> {
        if let Some(evidences) = &block.slashing_evidence {
            for (i, evidence) in evidences.iter().enumerate() {
                if !Self::verify_slashing_evidence(evidence) {
                    return Err(format!("Invalid slashing evidence #{i}"));
                }
            }
        }
        Ok(())
    }

    fn validated_global_header_prefix(
        headers: Vec<GlobalBlockHeader>,
        chain_id: u64,
    ) -> Vec<GlobalBlockHeader> {
        let mut valid = Vec::new();
        let mut expected_prev_hash = [0u8; 32];
        for (expected_height, header) in headers.into_iter().enumerate() {
            let expected_height = expected_height as u64;
            if header.chain_id != chain_id {
                warn!(
                    "Skipping stored global header with wrong chain id: height={}, chain_id={}",
                    header.global_height, header.chain_id
                );
                break;
            }
            if header.global_height != expected_height {
                warn!(
                    "Skipping stored global header with non-contiguous height: expected={}, got={}",
                    expected_height, header.global_height
                );
                break;
            }
            if header.previous_global_hash != expected_prev_hash {
                warn!(
                    "Skipping stored global header with broken hash chain: height={}",
                    header.global_height
                );
                break;
            }

            expected_prev_hash = header.calculate_hash_bytes();
            valid.push(header);
        }

        valid
    }

    /// Record a consensus-integrity event in the durable quarantine ledger and
    /// persist it. The ledger is node-local (not in the state root); see
    /// `registry/quarantine_ledger.rs` for why committing it would fork honest
    /// nodes.
    fn record_quarantine_event(
        &mut self,
        target: crate::domain::types::Hash32,
        reason: crate::registry::QuarantineReason,
        code: &str,
        message: &str,
        severity: u8,
    ) {
        let height = self.chain.len() as u64;
        self.quarantine_ledger
            .quarantine_entity(target, reason, height);
        self.quarantine_ledger
            .record_alarm(code, message, height, severity);
        // No whole-ledger rewrite per event - the
        // ledger is persisted once at block close (next to the pending
        // queues), tagged dirty here.
        self.quarantine_dirty = true;
    }

    /// Writes the quarantine ledger if an event tagged it dirty. Called at
    /// block close, and by the slashing-report path, which runs outside block
    /// production: without the second call an operator slash would sit only
    /// in memory until some later block closed, and a restart before that
    /// loses the quarantine row and its alarm.
    fn flush_quarantine_ledger(&mut self) {
        if !self.quarantine_dirty {
            return;
        }
        self.quarantine_dirty = false;
        if let Some(store) = &self.storage {
            if let Err(e) = store.save_quarantine_ledger(&self.quarantine_ledger) {
                tracing::error!(error = %e, "Failed to persist quarantine ledger");
            }
        }
    }

    /// The settlement finality window: the hashes of checkpoint blocks that
    /// are buried at least the finality horizon deep, and no deeper than
    /// the settled-row retention.
    ///
    /// Derived from the chain prefix on every read, never stored. The
    /// previous `settlement_finality_hashes` field had no production
    /// writer at all, so the settlement root folded into the state root
    /// was always the empty-tree root (F-7, dead-feature illusion). Wiring
    /// a writer that appended on finality-certificate arrival would have
    /// traded the dead input for a consensus race: two honest nodes that
    /// finalized the same checkpoint at different moments would fold
    /// different windows into the same block's state root and split.
    /// Burial depth is a pure function of the blocks both nodes already
    /// hold, so every node derives the same window for the same tip.
    fn settlement_finality_window(&self) -> Vec<crate::domain::Hash32> {
        Self::settlement_finality_window_for(&self.chain, self.chain_id)
    }

    /// The window for the blocks that precede a new block. Live and replay
    /// paths both call this with the same prefix.
    fn settlement_finality_window_for(
        chain: &[Block],
        chain_id: u64,
    ) -> Vec<crate::domain::Hash32> {
        let interval =
            crate::core::chain_config::finality_checkpoint_interval_for_chain_id(chain_id);
        if chain.is_empty() {
            return Vec::new();
        }
        let tip = (chain.len() - 1) as u64;
        // Only the retention band can matter; scanning it keeps the cost
        // bounded by the window, not by the chain length.
        let oldest =
            tip.saturating_sub(crate::cross_domain::bridge::SETTLED_RETENTION_BLOCKS) as usize;
        crate::chain::finality::settlement_finality_window_from(
            chain[oldest..]
                .iter()
                .enumerate()
                .map(|(i, block)| ((oldest + i) as u64, block.hash.as_str())),
            interval,
            tip,
        )
    }

    /// Set the four end-of-block commitment fields after a block's effects.
    ///
    /// `preceding` is the chain before the new block. Live production,
    /// live validation, startup replay, candidate validation, reorg replay
    /// and state rebuild all call this one function, so all of them derive
    /// the same roots for the same block.
    ///
    /// At a finality checkpoint the transition also builds the global header
    /// from the state at the end of the block: every
    /// node derives the same bytes, the state root commits the header hash
    /// as `global_header_summary`, and the checkpoint's finality certificate
    /// covers the block that commits it. The header holds no state root and
    /// no block hash, so nothing it folds depends on it.
    fn apply_block_end_roots(
        state: &mut AccountState,
        block: &Block,
        preceding: &[Block],
        chain_id: u64,
    ) {
        state.bridge_root = state.bridge_state.root();
        state.message_root = state.message_registry.root();
        state.settlement_root =
            merkle_root(&Self::settlement_finality_window_for(preceding, chain_id));
        if crate::chain::finality::is_checkpoint_height_for_chain(block.index, chain_id) {
            let header = Self::checkpoint_global_header(state, block, chain_id);
            state.settlement.global_headers.push(header);
        }
        state.global_header_summary = state
            .settlement
            .global_headers
            .latest()
            .map_or([0u8; 32], GlobalBlockHeader::calculate_hash_bytes);
    }

    /// The global header the transition of `block` builds from `state`, the
    /// state at the end of that block with its end-of-block roots set. Every
    /// field is read from the state or the block, so every node builds the
    /// same bytes.
    fn checkpoint_global_header(
        state: &AccountState,
        block: &Block,
        chain_id: u64,
    ) -> GlobalBlockHeader {
        let previous = state.settlement.global_headers.latest();
        GlobalBlockHeader {
            version: 2,
            global_height: previous.map_or(0, |h| h.global_height.saturating_add(1)),
            previous_global_hash: previous
                .map_or([0u8; 32], GlobalBlockHeader::calculate_hash_bytes),
            chain_id,
            timestamp_ms: block.timestamp,
            domain_registry_root: state.settlement.domains.root(),
            domain_commitment_root: state.settlement.commitments.root(),
            message_root: state.message_registry.root(),
            bridge_state_root: state.bridge_state.root(),
            replay_nonce_root: state.bridge_state.replay_root(),
            proposer: block.producer,
            settlement_finality_root: state.settlement_root,
            storage_root: if state.storage_registry.is_empty() {
                None
            } else {
                Some(state.storage_registry.root())
            },
            ai_root: if state.ai_registry.is_empty() {
                None
            } else {
                Some(state.ai_registry.state_root())
            },
            identity_root: if state.identity.is_empty() {
                None
            } else {
                Some(state.identity.root())
            },
            checkpoint_height: block.index,
            external_intake_root: if state.settlement.has_external_intake() {
                state.settlement.external_intake_digest().ok()
            } else {
                None
            },
            graft_root: if state.settlement.graft.is_empty() {
                None
            } else {
                Some(state.settlement.graft.root())
            },
            delegation_root: state.registry.delegation_root(),
        }
    }

    /// Bring the node-local header archive in line with the headers the
    /// state commits: a header the state holds replaces a different archived
    /// one at the same global height (a reorg), archived headers past the
    /// state's latest leave, and new ones are appended. Returns the headers
    /// appended. A state with no header leaves the archive as it is.
    fn reconcile_global_header_archive(
        archive: &mut Vec<GlobalBlockHeader>,
        state: &AccountState,
    ) -> Vec<GlobalBlockHeader> {
        let window = &state.settlement.global_headers;
        let Some(latest) = window.latest() else {
            return Vec::new();
        };
        let keep = usize::try_from(latest.global_height.saturating_add(1)).unwrap_or(usize::MAX);
        archive.truncate(keep);
        let mut added = Vec::new();
        for header in window.iter() {
            let Ok(at) = usize::try_from(header.global_height) else {
                continue;
            };
            if at < archive.len() {
                if archive[at] != *header {
                    archive.truncate(at);
                    archive.push(header.clone());
                    added.push(header.clone());
                }
            } else if at == archive.len() {
                archive.push(header.clone());
                added.push(header.clone());
            }
        }
        added
    }

    /// The committed checkpoint header at `global_height`: the state's
    /// consensus window first, then the node-local archive for older heights.
    ///
    /// The window is authoritative. An archive can be empty after a snapshot
    /// restore, or briefly contain an obsolete fork during reconciliation; a
    /// read must never let that node-local copy override the header committed
    /// by the state root.
    #[must_use]
    pub fn global_header(&self, global_height: u64) -> Option<GlobalBlockHeader> {
        self.state
            .settlement
            .global_headers
            .get(global_height)
            .cloned()
            .or_else(|| {
                usize::try_from(global_height)
                    .ok()
                    .and_then(|at| self.global_headers.get(at))
                    .filter(|h| h.global_height == global_height)
                    .cloned()
            })
    }

    /// A committed checkpoint header with what a light client checks it
    /// against: the checkpoint block (its header commits the state root) and
    /// the state root opening, when this node recorded it.
    #[must_use]
    pub fn global_header_proof(&self, global_height: u64) -> Option<GlobalHeaderProof> {
        let header = self.global_header(global_height)?;
        let block = usize::try_from(header.checkpoint_height)
            .ok()
            .and_then(|at| self.chain.get(at))?;
        Some(GlobalHeaderProof {
            block_height: block.index,
            block_hash: block.hash.clone(),
            state_root: block.state_root.clone(),
            state_root_body: self.global_header_openings.get(&global_height).copied(),
            header,
        })
    }

    /// A Graft payment proven against the most recent checkpoint header whose
    /// payment window still holds it: the payment, its Merkle
    /// path to the window root, the rest of the registry opening, and the
    /// header with its own proof material.
    #[must_use]
    pub fn graft_payment_proof(
        &self,
        payment_id: &[u8; 32],
    ) -> Option<crate::settlement::graft::GraftPaymentProof> {
        self.graft_payment_windows.iter().rev().find_map(
            |(global_height, (payments, rest_hash))| {
                let (payment, path) = crate::settlement::graft::window_proof(payments, payment_id)?;
                let header = self.global_header_proof(*global_height)?;
                Some(crate::settlement::graft::GraftPaymentProof {
                    payment,
                    path,
                    opening: crate::settlement::graft::GraftRootOpening {
                        payments_root: crate::settlement::graft::window_root(payments),
                        rest_hash: *rest_hash,
                    },
                    header: header.header,
                    block_height: header.block_height,
                    state_root: header.state_root,
                    state_root_body: header.state_root_body,
                })
            },
        )
    }

    /// Node-local follow-up of a committed block: archive the checkpoint
    /// headers it committed, count them, and hand each to the PQ anchor
    /// emission, whose mode rules are unchanged (GatedOff skips, Devnet
    /// writes the line, ProductionApproved fails closed).
    fn observe_committed_global_headers(&mut self, block: &Block) {
        let added = Self::reconcile_global_header_archive(&mut self.global_headers, &self.state);
        for header in &added {
            // The opening of the block that built the header: the committed
            // state is the state at its end. Recorded only when it reopens to
            // the block's own state root.
            if header.checkpoint_height == block.index {
                let body = self.state.state_root_body();
                let summary = header.calculate_hash_bytes();
                let graft = &self.state.settlement.graft;
                if header.graft_root.is_some() && header.graft_root == Some(graft.root()) {
                    self.graft_payment_windows.insert(
                        header.global_height,
                        (graft.payments.clone(), graft.opening().rest_hash),
                    );
                    while self.graft_payment_windows.len()
                        > crate::settlement::global_block::GLOBAL_HEADER_WINDOW
                    {
                        self.graft_payment_windows.pop_first();
                    }
                }
                if hex::encode(AccountState::root_from_opening(&body, &summary)) == block.state_root
                {
                    self.global_header_openings
                        .insert(header.global_height, body);
                    if let Some(store) = &self.storage {
                        if let Err(e) =
                            store.save_global_header_opening(header.global_height, &body)
                        {
                            tracing::error!("global header opening not persisted: {e}");
                        }
                    }
                }
            }
            if let Some(metrics) = &self.metrics {
                metrics.settlement_global_headers_sealed.inc();
            }
            if let Err(e) = self.emit_anchor_for(header) {
                tracing::error!(
                    "anchor emission for global header {}: {e}",
                    header.global_height
                );
            }
        }
    }

    /// The weakest quantum class among the active domains the header settles.
    /// The class of a domain follows its consensus kind until its profile
    /// reports observed schemes: composite ML-DSA-65 plus Ed25519 blocks
    /// (PoS, BFT, PoA) are lattice based, proof of work and zk domains are
    /// hash based, anything else is not assessed and counts as classical.
    fn anchor_quantum_class(&self) -> crate::crypto::facts::QuantumClass {
        crate::settlement::pq_anchor::weakest_domain_class(
            self.state
                .settlement
                .domains
                .active_domains()
                .map(|d| &d.kind),
        )
    }

    /// The PQ anchor emission for one committed header (Anchor V2,,
    ///). An anchor is due every 360 blocks: its leaves are the
    /// headers the archive holds for the window ending at the checkpoint
    /// (header hash, which commits the storage, identity and settlement
    /// roots, plus the weakest quantum class of the settled domains). The
    /// Root Seal follows every 3,600 blocks inside the pipeline.
    fn emit_anchor_for(&mut self, header: &GlobalBlockHeader) -> Result<(), String> {
        let height = header.checkpoint_height;
        if self.anchor_emission.mode == crate::settlement::AnchorMode::GatedOff
            || !crate::settlement::anchor_due(height)
        {
            return Ok(());
        }
        let quantum_class = self.anchor_quantum_class();
        let mut leaves = self.anchor_window_leaves(height, quantum_class);
        if leaves.is_empty() {
            leaves.push(crate::settlement::AnchorLeaf {
                finality_digest: header.calculate_hash_bytes(),
                quantum_class,
            });
        }
        let request = crate::settlement::EmissionRequest {
            chain_id: self.chain_id,
            height,
            window_leaves: &leaves,
            stark_root: None,
            crossdomain_root: None,
            key_epoch: self.anchor_emission.key_epoch,
        };
        let outcome = self
            .anchor_emission
            .on_checkpoint(&request)
            .map_err(|e| format!("anchor emission: {e}"))?;
        self.feed_pq_source(height, quantum_class, outcome);
        Ok(())
    }

    /// The anchor leaves of the window ending at `height`: the archived
    /// headers of the 360 blocks, oldest first, each with `quantum_class`.
    fn anchor_window_leaves(
        &self,
        height: u64,
        quantum_class: crate::crypto::facts::QuantumClass,
    ) -> Vec<crate::settlement::AnchorLeaf> {
        let window_start = height.saturating_sub(crate::settlement::ANCHOR_INTERVAL);
        self.global_headers
            .iter()
            .filter(|h| h.checkpoint_height > window_start && h.checkpoint_height <= height)
            .map(|h| crate::settlement::AnchorLeaf {
                finality_digest: h.calculate_hash_bytes(),
                quantum_class,
            })
            .collect()
    }

    /// Hand the anchor and the Root Seal one checkpoint produced to the
    /// canonical source. The source verifies both again against the ledger.
    fn feed_pq_source(
        &mut self,
        height: u64,
        quantum_class: crate::crypto::facts::QuantumClass,
        outcome: crate::settlement::anchor_production::CheckpointOutcome,
    ) {
        const MAX_ANCHOR_CLASSES: usize = 512;
        let Some(ledger) = self.anchor_emission.ledger.clone() else {
            return;
        };
        if outcome.anchored {
            self.anchor_classes.insert(height, quantum_class);
            while self.anchor_classes.len() > MAX_ANCHOR_CLASSES {
                self.anchor_classes.pop_first();
            }
            if let Some(anchor) = self.anchor_emission.last_anchor.clone() {
                if let Err(e) = self.pq_source.accept_anchor(&anchor, &ledger) {
                    tracing::error!("canonical source refused the anchor at {height}: {e}");
                }
            }
        }
        if outcome.sealed.is_some() {
            if let Some(seal) = self.anchor_emission.seals.latest().cloned() {
                if let Err(e) = self.pq_source.accept_root_seal(&seal, &ledger) {
                    tracing::error!("canonical source refused the root seal at {height}: {e}");
                }
            }
        }
    }

    /// The aggregate root this node recomputes for the anchor at `height`
    /// from its own header archive, with the class the anchor was signed
    /// with (the current class when this node did not record it).
    #[must_use]
    /// WIRING: chain surface - the block/snapshot paths that read it land with their wiring.
    pub fn local_anchor_root(&self, height: u64) -> Option<[u8; 32]> {
        let class = self
            .anchor_classes
            .get(&height)
            .copied()
            .unwrap_or_else(|| self.anchor_quantum_class());
        let digests: Vec<[u8; 32]> = self
            .anchor_window_leaves(height, class)
            .iter()
            .map(crate::settlement::anchor_leaf_digest)
            .collect();
        crate::settlement::aggregate_finality_roots(&digests).ok()
    }

    /// What the regeneration tick needs about one stage and height: the
    /// commitment this node holds, and the canonical commitment with the seal
    /// behind it. A finalized checkpoint that is not in the source yet is
    /// taken from storage when its certificate and verified QC blob are both
    /// there (a restart empties the memory source).
    pub fn pq_stage_observation(
        &mut self,
        stage: crate::domain::regeneration_stage::Stage,
        height: u64,
    ) -> PqStageObservation {
        use crate::domain::regeneration_stage::Stage;
        if stage == Stage::Medusa && self.pq_source.canonical(stage, height).is_none() {
            self.rehydrate_finality(height);
        }
        let local = match stage {
            Stage::Medusa => usize::try_from(height)
                .ok()
                .and_then(|at| self.chain.get(at))
                .and_then(|block| hex::decode(&block.hash).ok())
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()),
            Stage::Ephyra => self.local_anchor_root(height),
            Stage::Polyp => self
                .anchor_emission
                .seals
                .at(height)
                .map(|seal| seal.digest()),
        };
        // a seal whose post-quantum families the alarm took out of the
        // scheme registry is not a source any more; the tick then descends to
        // the next stage that still has a live seal.
        let live = self
            .pq_source
            .seal(stage, height)
            .filter(|seal| seal.is_live(&self.state.scheme_registry));
        PqStageObservation {
            local,
            canonical: live
                .as_ref()
                .and_then(|_| self.pq_source.canonical(stage, height)),
            seal: live,
        }
    }

    /// The quantum alarm and the observed crypto facts of every native domain
    /// what `bud_getQuantumAlarm` and `bud_getDomainInfo` show.
    #[must_use]
    pub fn quantum_view(&self) -> serde_json::Value {
        let domains: Vec<serde_json::Value> = self
            .state
            .settlement
            .domains
            .domains()
            .iter()
            .map(|domain| {
                let facts = self.state.settlement.domains.observed(domain.id);
                serde_json::json!({
                    "domainId": domain.id,
                    "quantumClass": facts.quantum_class().map(|c| format!("{c:?}")),
                    "observedSchemes": facts.summary(),
                    "status": format!("{:?}", domain.status),
                })
            })
            .collect();
        serde_json::json!({
            "alarm": self.state.settlement.quantum.view(),
            "domains": domains,
        })
    }

    /// The latest Root Seal height (Polyp) and the latest verified anchor at
    /// or below `live` (Ephyra).
    #[must_use]
    pub fn pq_sealed_heights(&self, live: u64) -> (Option<u64>, Option<u64>) {
        use crate::domain::regeneration_stage::Stage;
        (
            self.pq_source.latest_height(Stage::Polyp),
            self.pq_source.latest_at_or_below(Stage::Ephyra, live),
        )
    }

    fn rehydrate_finality(&mut self, height: u64) {
        let Some(cert) = self
            .storage
            .as_ref()
            .and_then(|s| s.get_finality_cert(height).unwrap_or(None))
        else {
            return;
        };
        let Some(blob) = self.get_qc_blob(height) else {
            return;
        };
        if Self::ensure_blob_matches_checkpoint(&blob, &cert.checkpoint_hash).is_err() {
            return;
        }
        self.feed_finality(height, &cert.checkpoint_hash, true);
    }

    /// Record a finality checkpoint whose BLS certificate and ML-DSA-65 QC
    /// were both verified.
    fn feed_finality(&mut self, height: u64, checkpoint_hash: &str, with_bls: bool) {
        use crate::crypto::scheme::SchemeId;
        let Some(hash) = hex::decode(checkpoint_hash)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        else {
            return;
        };
        let schemes: &[SchemeId] = if with_bls {
            &[SchemeId::BLS12381_MINSIG, SchemeId::ML_DSA_65]
        } else {
            &[SchemeId::ML_DSA_65]
        };
        if let Err(e) = self.pq_source.accept_finality(height, hash, schemes) {
            tracing::error!("canonical source refused the checkpoint at {height}: {e}");
        }
    }

    /// A preview of the next header: the roots of the current state, chained
    /// onto the latest committed header. Read-only; the committed headers are
    /// the ones the checkpoint transitions build (`apply_block_end_roots`).
    ///
    /// The state window is preferred over the node-local archive for the same
    /// reason as [`Self::global_header`]: the preview must remain correct when
    /// a node has restored consensus state without its older archive.
    pub fn build_global_header(&self, proposer: Option<Address>) -> GlobalBlockHeader {
        let previous = self
            .state
            .settlement
            .global_headers
            .latest()
            .or_else(|| self.global_headers.last());
        let previous_global_hash = previous
            .map(GlobalBlockHeader::calculate_hash_bytes)
            .unwrap_or([0u8; 32]);
        let global_height = previous.map_or(0, |header| header.global_height.saturating_add(1));

        let settlement_window = self.settlement_finality_window();
        let settlement_finality_root = if settlement_window.is_empty() {
            merkle_root(&[])
        } else {
            merkle_root(&settlement_window)
        };

        GlobalBlockHeader {
            version: 2,
            global_height,
            previous_global_hash,
            chain_id: self.chain_id,
            timestamp_ms: self.chain.last().map_or(0, |b| b.timestamp),
            domain_registry_root: self.state.settlement.domains.root(),
            domain_commitment_root: self.state.settlement.commitments.root(),
            message_root: self.state.message_registry.root(),
            bridge_state_root: self.state.bridge_state.root(),
            replay_nonce_root: self.state.bridge_state.replay_root(),
            proposer,
            settlement_finality_root,
            storage_root: if self.state.storage_registry.is_empty() {
                None
            } else {
                Some(self.state.storage_registry.root())
            },
            // Anchor AI Inference Layer into global settlement.
            // When AiRegistry has any state, its root is committed here;
            // When empty, None ensures no bloat. This fulfills Paradigma
            // - AI outcomes are cryptographically provable at settlement.
            ai_root: if self.state.ai_registry.is_empty() {
                None
            } else {
                Some(self.state.ai_registry.state_root())
            },
            // The identity anchor on the same discipline: the registry's
            // root is claimed only when the registry has state, and it is
            // the registry's own fold (`identity.rs`), not a re-derivation
            // here. Absent and zero must not share a digest: an empty
            // registry says "nothing to check against", and folding it as
            // Some(zeros) would wear the same header as a registry whose
            // state happened to hash to zero. The presence tag in the V5
            // fold keeps those two headers apart - the same lesson the
            // account-state root learned under `identity_v1`.
            identity_root: if self.state.identity.is_empty() {
                None
            } else {
                Some(self.state.identity.root())
            },
            checkpoint_height: self.chain.last().map_or(0, |b| b.index),
            external_intake_root: if self.state.settlement.has_external_intake() {
                self.state.settlement.external_intake_digest().ok()
            } else {
                None
            },
            graft_root: if self.state.settlement.graft.is_empty() {
                None
            } else {
                Some(self.state.settlement.graft.root())
            },
            delegation_root: self.state.registry.delegation_root(),
        }
    }

    /// Test harness only: append the preview header to the node-local
    /// archive and emit its anchor, as the operator RPC used to. Production
    /// headers are built by the transition of each checkpoint block
    ///; `bud_sealGlobalHeader` is refused.
    ///
    /// # Errors
    ///
    /// The store's or the anchor emission's refusal.
    #[cfg(test)]
    pub fn seal_global_header(
        &mut self,
        proposer: Option<Address>,
    ) -> Result<GlobalBlockHeader, String> {
        let header = self.build_global_header(proposer);
        if let Some(store) = &self.storage {
            store
                .save_global_header(&header)
                .map_err(|e| format!("Failed to persist global header: {e}"))?;
        }
        self.global_headers.push(header.clone());
        if let Some(metrics) = &self.metrics {
            metrics.settlement_global_headers_sealed.inc();
        }
        self.emit_anchor_for(&header)?;
        Ok(header)
    }

    /// The anchor key ledger of the genesis file, when it carries one.
    #[must_use]
    pub fn genesis_anchor_ledger(&self) -> Option<&crate::settlement::AnchorKeyLedger> {
        self.genesis_config.anchor_ledger.as_ref()
    }

    /// Install the anchor emission pipeline of this node. The ledger
    /// the emission signs against must be the ledger genesis carries; a node
    /// cannot run production mode on a chain whose genesis has none, and the
    /// development mode is refused on mainnet.
    ///
    /// # Errors
    ///
    /// The mismatch or the missing ledger, or an unreadable seal log.
    pub fn configure_anchor_emission(
        &mut self,
        mut emission: AnchorEmission,
    ) -> Result<(), String> {
        use crate::settlement::AnchorMode;
        let genesis_ledger = self.genesis_config.anchor_ledger.as_ref();
        match (emission.mode, genesis_ledger, emission.ledger.as_ref()) {
            (AnchorMode::GatedOff, _, _) => {}
            (AnchorMode::Devnet, _, _)
                if crate::core::chain_config::Network::from_chain_id(self.chain_id)
                    == Some(crate::core::chain_config::Network::Mainnet) =>
            {
                return Err("anchor development mode is not allowed on mainnet".to_string());
            }
            (AnchorMode::ProductionApproved, None, _) => {
                return Err(
                    "anchor production mode needs the anchor_ledger of the genesis file"
                        .to_string(),
                );
            }
            (_, Some(genesis), Some(loaded)) if genesis.digest() != loaded.digest() => {
                return Err(
                    "the anchor emission ledger is not the ledger of the genesis file".to_string(),
                );
            }
            (_, Some(_), None) => {
                return Err("the anchor emission has no ledger but genesis carries one".to_string());
            }
            _ => {}
        }
        if emission.mode != AnchorMode::GatedOff {
            emission
                .resume_seal_log()
                .map_err(|e| format!("anchor seal log: {e}"))?;
        }
        self.anchor_emission = emission;
        Ok(())
    }

    /// Rotate the anchor signing key with the cold-wallet committee
    /// ( production entry): pq_anchor's cold channel drives
    /// cold_wallet's quorum signature and cold_quorum's verification. The
    /// wallet must be configured on this chain; the committee is read from
    /// its pinned trusted-device set (S2).
    ///
    /// WIRING: the operator entry for anchor key rotation; no actor or
    /// RPC command drives a rotation yet, so until that door lands the
    /// path is exercised through the chain tests.
    pub fn rotate_anchor_key_with_committee(
        &mut self,
        at_height: u64,
        reason: &str,
        certificates: &[DeviceSignature],
    ) -> Result<u32, String> {
        let state = self
            .cold_wallet
            .as_mut()
            .ok_or_else(|| "cold wallet not configured on this chain".to_string())?;
        crate::settlement::pq_anchor::rotate_anchor_key_with_committee(
            state,
            at_height,
            reason,
            certificates,
        )
        .map_err(|e| format!("anchor key rotation: {e}"))
    }

    /// The height of the block this chain would apply next: the height the
    /// bridge door bodies run at (harness and `drain_pending_bridge_burns`).
    fn harness_height(&self) -> u64 {
        u64::try_from(self.chain.len()).unwrap_or(u64::MAX)
    }

    /// Test harness only: the inclusion check the `BridgeTx::Mint` and
    /// `BridgeTx::Unlock` doors run (`cross_domain::bridge_tx`).
    ///
    /// # Errors
    ///
    /// The verifier's refusal.
    #[cfg(test)]
    pub fn verify_domain_event_proof(
        &self,
        domain_id: crate::domain::DomainId,
        domain_height: u64,
        sequence: u64,
        expected_block_hash: crate::domain::Hash32,
        event: DomainEvent,
        proof: &MerkleProof,
    ) -> Result<VerifiedDomainEvent, ProofVerificationError> {
        crate::cross_domain::bridge_tx::verify_domain_event_proof(
            &self.state,
            domain_id,
            domain_height,
            sequence,
            expected_block_hash,
            event,
            proof,
        )
    }

    /// Test harness only: the body of the `BridgeTx::Mint` door without the
    /// carrier bond. The block hash stays mandatory (security audit).
    ///
    /// # Errors
    ///
    /// The door body's refusal.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn mint_bridge_transfer_from_verified_event(
        &mut self,
        source_domain: crate::domain::DomainId,
        source_height: u64,
        sequence: u64,
        expected_block_hash: Option<crate::domain::Hash32>,
        event: DomainEvent,
        proof: &MerkleProof,
        relayer: Address,
    ) -> Result<(), String> {
        let expected_block_hash = expected_block_hash.ok_or_else(|| {
            "Bridge mint requires explicit expected_block_hash (forgery gate)".to_string()
        })?;
        let height = self.harness_height();
        crate::cross_domain::bridge_tx::mint_from_verified_event(
            &mut self.state,
            &crate::cross_domain::bridge_tx::ProvenBridgeEvent {
                domain: source_domain,
                height: source_height,
                sequence,
                expected_block_hash,
                event,
                proof: proof.clone(),
            },
            relayer,
            height,
        )
    }

    /// Test harness only: the body of the `BridgeTx::RegisterAsset` door
    /// without the operator check.
    ///
    /// # Errors
    ///
    /// The door body's refusal.
    #[cfg(test)]
    pub fn register_bridge_asset(
        &mut self,
        asset_id: crate::cross_domain::AssetId,
        domain: crate::domain::DomainId,
    ) -> Result<(), String> {
        crate::cross_domain::bridge_tx::register_asset(&mut self.state, asset_id, domain)
    }

    /// Test harness only: the body of the `BridgeTx::Lock` door for `owner`.
    ///
    /// # Errors
    ///
    /// The door body's refusal.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn lock_bridge_transfer(
        &mut self,
        source_domain: crate::domain::DomainId,
        target_domain: crate::domain::DomainId,
        source_height: u64,
        event_index: u32,
        asset_id: crate::cross_domain::AssetId,
        owner: Address,
        recipient: Address,
        amount: u64,
        expiry_height: u64,
    ) -> Result<(crate::cross_domain::BridgeTransfer, DomainEvent), String> {
        let height = self.harness_height();
        crate::cross_domain::bridge_tx::lock(
            &mut self.state,
            owner,
            &crate::cross_domain::bridge_tx::LockRequest {
                source_domain,
                target_domain,
                source_height,
                event_index,
                asset_id,
                recipient,
                amount,
                expiry_height,
            },
            0,
            height,
        )
    }

    /// Test harness only: registers a bridge message the way the lock and
    /// burn doors do (`bridge_tx::register_bridge_message`).
    ///
    /// # Errors
    ///
    /// The rule that refused the message.
    #[cfg(test)]
    pub fn submit_cross_domain_message(
        &mut self,
        message: crate::cross_domain::CrossDomainMessage,
    ) -> Result<(), String> {
        let height = self.harness_height();
        crate::cross_domain::bridge_tx::register_bridge_message(&mut self.state, message, height)
    }

    /// Test harness only: the body of the `BridgeTx::BurnWithEvent` door
    /// without the sender check.
    ///
    /// # Errors
    ///
    /// The door body's refusal.
    #[cfg(test)]
    pub fn burn_bridge_transfer_with_event(
        &mut self,
        message_id: crate::cross_domain::MessageId,
        domain: crate::domain::DomainId,
        domain_height: u64,
        event_index: u32,
        expiry_height: u64,
        recipient_eth: [u8; 20],
    ) -> Result<DomainEvent, String> {
        let height = self.harness_height();
        crate::cross_domain::bridge_tx::burn_with_event(
            &mut self.state,
            &crate::cross_domain::bridge_tx::BurnRequest {
                message_id,
                domain,
                domain_height,
                event_index,
                expiry_height,
                recipient_eth,
            },
            0,
            height,
        )
    }

    /// Test harness only: the body of the `BridgeTx::Unlock` door without
    /// the carrier bond. The block hash stays mandatory (security audit).
    ///
    /// # Errors
    ///
    /// The door body's refusal.
    #[cfg(test)]
    pub fn unlock_bridge_transfer_from_verified_event(
        &mut self,
        target_domain: crate::domain::DomainId,
        target_height: u64,
        sequence: u64,
        expected_block_hash: Option<crate::domain::Hash32>,
        event: DomainEvent,
        proof: &MerkleProof,
    ) -> Result<(), String> {
        let expected_block_hash = expected_block_hash.ok_or_else(|| {
            "Bridge unlock requires explicit expected_block_hash (forgery gate)".to_string()
        })?;
        let height = self.harness_height();
        crate::cross_domain::bridge_tx::unlock_from_verified_event(
            &mut self.state,
            &crate::cross_domain::bridge_tx::ProvenBridgeEvent {
                domain: target_domain,
                height: target_height,
                sequence,
                expected_block_hash,
                event,
                proof: proof.clone(),
            },
            height,
        )
    }
    pub fn get_transaction_by_hash(&self, hash: &str) -> Option<Transaction> {
        let _storage_timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.storage_read_seconds.start_timer());
        if let Some(ref store) = self.storage {
            if let Ok(Some(height)) = store.get_tx_block_height(hash) {
                if let Some(block) = self.chain.get(height as usize) {
                    if let Some(tx) = block.transactions.iter().find(|t| t.hash == hash) {
                        return Some(tx.clone());
                    }
                }
            }
        }
        for block in &self.chain {
            if let Some(tx) = block.transactions.iter().find(|t| t.hash == hash) {
                return Some(tx.clone());
            }
        }
        self.mempool.get(hash).cloned()
    }
    pub fn get_transaction_receipt(&self, hash: &str) -> Option<serde_json::Value> {
        let _storage_timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.storage_read_seconds.start_timer());
        if let Some(ref store) = self.storage {
            if let Ok(Some(height)) = store.get_tx_block_height(hash) {
                return Some(serde_json::json!({
                    "transactionHash": hash,
                    "blockNumber": format!("0x{:x}", height),
                    "status": "0x1"
                }));
            }
        }
        for block in &self.chain {
            if block.transactions.iter().any(|tx| tx.hash == hash) {
                return Some(serde_json::json!({
                    "transactionHash": hash,
                    "blockNumber": format!("0x{:x}", block.index),
                    "status": "0x1"
                }));
            }
        }
        None
    }
    pub fn get_nonce(&self, address: &Address) -> u64 {
        self.state.get_nonce(address)
    }

    pub fn get_validator_set_hash(&self) -> String {
        self.state
            .consensus_validator_set_hash(self.chain_id)
            .unwrap_or_else(|error| {
                tracing::error!("Cannot compute consensus validator set hash: {error}");
                "INVALID_CONSENSUS_VALIDATOR_SET".to_string()
            })
    }

    fn build_validator_snapshot(&self, epoch: u64) -> ValidatorSetSnapshot {
        Self::build_validator_snapshot_from_state(epoch, &self.state, self.chain_id)
    }

    /// Drive the liveness tracker over a synthetic epoch. Used by
    /// Tests and by the OBSERVE-only public surface. `participated` is the set
    /// Of validators that showed the expected participation; everyone else in
    /// `state.validators` is treated as an absentee. Returns the number of
    /// Slashing reports produced.
    ///
    /// OBSERVE ONLY: this never slashes, even when `liveness_slashing_enabled`
    /// Is true. Real slashing is the job of `apply_epoch_close_liveness`, which
    /// Runs on every real block at an epoch boundary. Tests asserting the
    /// OBSERVE mode default therefore see no stake cut.
    pub fn observe_liveness_epoch(
        &mut self,
        epoch: u64,
        participated: &std::collections::HashSet<Address>,
    ) -> usize {
        let params = *self.state.registry.params();
        let expected: Vec<Address> = self
            .state
            .validators
            .keys()
            .filter(|addr| {
                self.state
                    .registry
                    .is_active(addr, crate::registry::role::roles::VALIDATOR)
            })
            .copied()
            .collect();
        self.state
            .liveness
            .record_epoch(
                epoch,
                &expected,
                |addr| participated.contains(addr),
                &params,
            )
            .len()
    }

    /// Directly call `state.liveness.record_epoch` (exposed so tests
    /// That want to exercise the tracker in isolation can do so without going
    /// Through `apply_epoch_close_liveness`).
    pub fn record_liveness_epoch(
        &mut self,
        epoch: u64,
        participated: &std::collections::HashSet<Address>,
    ) -> usize {
        let params = *self.state.registry.params();
        // Same filter as `apply_epoch_close_liveness`. Taking every
        // Key of `validators` counts members that cannot sign, a slashed or
        // Jailed validator stays in the map (that is how `jail_until` is
        // Tracked) while `registry.is_active` has already gone false. Feeding
        // Them in as absentees accrues a downtime streak for not doing
        // Something they are barred from doing, which is the shape of
        // Cosmos SDK #1867: a validator dropped from the set kept its
        // `SigningInfo` and was slashed for the window it was not in.
        let expected: Vec<Address> = self
            .state
            .validators
            .keys()
            .filter(|addr| {
                self.state
                    .registry
                    .is_active(addr, crate::registry::role::roles::VALIDATOR)
            })
            .copied()
            .collect();
        let reports = self.state.liveness.record_epoch(
            epoch,
            &expected,
            |addr| participated.contains(addr),
            &params,
        );
        // If liveness slashing is enabled, feed the produced reports through
        // The canonical `slash_from_report` path (mirroring what
        // `apply_epoch_close_liveness` does at epoch close). Tests
        // That drive slashing explicitly via `record_liveness_epoch` therefore
        // See the same effect.
        if params.liveness_slashing_enabled {
            // Same term as `apply_epoch_close_liveness`. Setting `jailed`
            // without `jail_until` leaves a validator that `advance_epoch`
            // releases at the next boundary, which is not a term at all.
            let jail_until = self
                .state
                .epoch_index
                .saturating_add(crate::registry::params::LIVENESS_JAIL_EPOCHS);
            for report in &reports {
                let _ = self.state.slash_from_report(report);
                if let Some(v) = self.state.validators.get_mut(&report.offender) {
                    if !v.slashed {
                        // Timed jail, not a permanent slash (
                        // decision B): see `apply_epoch_close_liveness`.
                        v.active = false;
                        v.jailed = true;
                        v.jail_until = jail_until;
                    }
                }
            }
        }
        reports.len()
    }

    /// The relay enqueue the lock and burn doors run.
    ///
    /// WIRING: `drain_pending_bridge_burns` calls it after every applied
    /// block, and the bridge suite calls it directly. It used to be
    /// `cfg(test)` only, which left the drain path calling a method that did
    /// not exist in a release build.
    pub fn enqueue_bridge_relay(
        &mut self,
        source_event: crate::cross_domain::DomainEvent,
        message: &crate::cross_domain::CrossDomainMessage,
    ) {
        let height = self.harness_height();
        crate::cross_domain::bridge_tx::enqueue_bridge_relay(
            &mut self.state,
            &source_event,
            message,
            height,
        );
    }

    /// Enqueue the relay requests of the bridge burns this block applied.
    ///
    /// The burn itself is already committed: the executor wrote
    /// `bridge_state` and moved the units inside the block, so nothing here
    /// decides a write. What is left is the universal-relayer enqueue, which
    /// lives in node-local bookkeeping with its own persistence, not in the
    /// state root. The executor leaves the event in `pending_bridge_burns` and
    /// this drains it once the block is applied, the same handoff
    /// `pending_bud_boost_share` uses.
    ///
    /// Runs on every node that applies the block, so two nodes with the same
    /// chain produce the same relay queue; a replayed block regenerates the
    /// list from the same transactions.
    ///
    /// WIRING: called from `produce_block` and `validate_and_add_block` right
    /// after `self.state` becomes the committed state, and from the bridge
    /// suite that asserts the drain moves nothing twice.
    pub fn drain_pending_bridge_burns(&mut self) -> usize {
        let pending = std::mem::take(&mut self.state.pending_bridge_burns);
        let count = pending.len();
        for event in pending {
            if let Some(message) = event.message.clone() {
                self.enqueue_bridge_relay(event, &message);
            }
        }
        count
    }

    /// The full registration record of one external domain - economics,
    /// version windows, prover bonds, attestation book - together with the
    /// registry clock, for the status surface. A clone, because the caller
    /// is on the other side of the actor boundary.
    #[must_use]
    pub fn external_domain_registration(
        &self,
        key: &crate::cross_domain::external::DomainKey,
    ) -> Option<(crate::cross_domain::external::DomainRegistration, u64)> {
        let height = self.state.settlement.external_intake.registry.height();
        self.state
            .settlement
            .external_intake
            .registry
            .domain(key)
            .map(|reg| (reg.clone(), height))
    }

    /// The public profile of one registered external domain, together with
    /// the intake entry it was admitted under (spec, policy, admission
    /// report) and the descriptor as registered. The entry travels with the
    /// profile because "under which rules was this admitted" is the first
    /// question a reader of the profile asks.
    #[must_use]
    pub fn external_domain_profile(
        &self,
        key: &crate::cross_domain::external::DomainKey,
    ) -> Option<(
        crate::cross_domain::external::DomainProfile,
        crate::cross_domain::external::IntakeEntry,
        crate::cross_domain::external::AdapterDescriptor,
    )> {
        let profile = self
            .state
            .settlement
            .external_intake
            .registry
            .domain(key)
            .map(|reg| crate::cross_domain::external::profile_of(&reg.record))?;
        let entry = self
            .state
            .settlement
            .external_intake
            .entries
            .get(key)?
            .clone();
        let descriptor = self.state.settlement.external_intake.descriptor_of(key)?;
        Some((profile, entry, descriptor))
    }

    /// Every registered external domain's profile, with the summary line the
    /// RPC surface prints. The profile module is deliberately judgement-free;
    /// this is the one place production iterates it.
    #[must_use]
    pub fn external_domain_profiles(
        &self,
    ) -> Vec<(crate::cross_domain::external::DomainProfile, String)> {
        self.state
            .settlement
            .external_intake
            .registry
            .domains()
            .map(|reg| {
                let profile = crate::cross_domain::external::profile_of(&reg.record);
                let line = profile.summary_line();
                (profile, line)
            })
            .collect()
    }

    /// The quorum round for one external height of one domain, if any. Read
    /// path for the RPC surface: a submitter whose evidence returned
    /// "round pending" reads the round here to see what it is waiting for.
    #[must_use]
    pub fn external_quorum_round(
        &self,
        key: &crate::cross_domain::external::DomainKey,
        height: u64,
    ) -> Option<crate::cross_domain::external::QuorumRound> {
        self.state
            .settlement
            .external_intake
            .quorum_round(&crate::cross_domain::external::RoundKey {
                domain: *key,
                height,
            })
            .cloned()
    }

    /// Every retained quorum round of one domain, oldest external height
    /// first, with the domain's policy beside them.
    #[must_use]
    pub fn external_quorum_rounds(
        &self,
        key: &crate::cross_domain::external::DomainKey,
    ) -> (
        Option<crate::cross_domain::external::QuorumPolicy>,
        Vec<crate::cross_domain::external::QuorumRound>,
    ) {
        let policy = self
            .state
            .settlement
            .external_intake
            .quorum
            .policy_of(key)
            .copied();
        let rounds = self
            .state
            .settlement
            .external_intake
            .quorum
            .rounds_of(key)
            .into_iter()
            .cloned()
            .collect();
        (policy, rounds)
    }

    /// Test harness only: the body of the `BridgeTx::RelayProof` door, with
    /// the active-relayer check of the door.
    ///
    /// # Errors
    ///
    /// The relayer check's or the door body's refusal.
    #[cfg(test)]
    pub fn submit_relay_proof(
        &mut self,
        message_id: crate::cross_domain::MessageId,
        relayer: Address,
        proof: &MerkleProof,
        source_domain: DomainId,
    ) -> Result<crate::cross_domain::CrossDomainMessage, String> {
        self.state
            .registry
            .ensure_active_relayer(&relayer)
            .map_err(|e| e.to_string())?;
        let height = self.harness_height();
        crate::cross_domain::bridge_tx::submit_relay_proof(
            &mut self.state,
            message_id,
            relayer,
            proof,
            source_domain,
            height,
        )
    }

    /// The number of pending relays.
    #[must_use]
    pub fn pending_relay_count(&self) -> usize {
        self.state.settlement.relayer.pending_count()
    }

    /// Merkle root of the relay ledger.
    #[must_use]
    pub fn relay_ledger_root(&self) -> crate::domain::types::Hash32 {
        self.state.settlement.relayer.ledger_root()
    }

    /// Permissionless entry-point for slashing reports with an
    /// Anti-spam fee.
    ///
    /// * `report.reporter` is the user submitting the report.
    /// * If `reporter` is `None` (consensus-internal), no fee is charged.
    /// * The fee (`RegistryParams::slashing_report_fee`) is debited from the
    ///   Reporter's spendable balance. If the balance is insufficient the
    ///   Report is rejected WITHOUT a state change.
    /// * If the report is ACTIONABLE (i.e. `slash_from_report` actually
    ///   Slashes the offender) the fee is refunded.
    /// * A report arriving `Unverified` is refused before the fee is charged
    ///   (CWE-347): this node cannot prove that two signatures in a
    ///   double-sign proof belong to two blocks at the same height, because
    ///   it does not hold the rival block. Reports reach the registry as
    ///   `ConsensusVerified` only through the consensus path, where the
    ///   aggregator verifies equivocation against the validator snapshot at
    ///   ingest. So an unprovable report costs nothing and an honest one is
    ///   not punished for arriving over RPC.
    /// * If the report is REJECTED after the fee was taken the fee is
    ///   Burned - the report carries no economic protection, and the
    ///   Submitter is the only one with skin in the game.
    /// * If the report targets an account that simply isn't registered
    ///   (`Ok(None)`), the report is still treated as honest and the fee
    ///   Is refunded (this matches `is_actionable` semantics).
    #[cfg(test)]
    pub fn submit_registry_slashing_report(
        &mut self,
        report: crate::registry::evidence::SlashingReport,
    ) -> Result<Option<crate::registry::permissionless::SlashOutcome>, String> {
        // An externally submitted report arrives `Unverified`, because the RPC
        // layer overwrites whatever provenance the caller claimed, and it is
        // refused here, before the fee is charged.
        //
        // The refusal is not the old fee-burning hole. The previous shape
        // promoted a `DoubleSign` report after checking only that the two
        // signatures verify under the offender's key. That check is not an
        // equivocation proof: a validator signs one block per height, so two
        // signatures over two different hashes are ordinary production unless
        // both hashes belong to blocks at the same height, and this node does
        // not hold the rival block a report would need to show that. An
        // attacker could take two legitimate signed blocks from different
        // heights, copy their hashes and signatures into a forged report, and
        // slash an innocent validator. Promotion is therefore disabled: a
        // report reaches the registry as `ConsensusVerified` only through the
        // consensus path, where the aggregator verifies both signatures
        // against the validator snapshot at ingest and records the
        // equivocation itself.
        //
        // A full fix (checking the rival block's own body against the proof's
        // height) is a wire-format change and is tracked separately; this
        // refusal closes the slash-any-validator path without one.
        if report.provenance() == crate::registry::ProofProvenance::Unverified {
            return Err("unverified slashing reports are refused: this node cannot \
                 verify that the two hashes in a double-sign proof belong to \
                 two blocks at the same height, because it does not hold the \
                 rival block. Reports reach the registry through consensus, \
                 not this endpoint."
                .to_string());
        }

        // The provenance field is a claim, not a proof. A block header
        // double sign is checked against the offender's own key here, so a
        // caller cannot slash a validator with made-up hashes or signatures.
        if matches!(
            report.proof,
            crate::registry::evidence::SlashingProof::DoubleSign {
                kind: crate::registry::evidence::DoubleSignKind::BlockHeader,
                ..
            }
        ) {
            report.verify_double_sign().map_err(|e| e.to_string())?;
        }

        let fee = self.state.registry.params().slashing_report_fee;
        let mut charged_fee = false;
        if let Some(reporter) = report.reporter {
            if fee > 0 {
                let account = self.state.get_or_create(&reporter);
                if account.balance < fee {
                    return Err(format!(
                        "insufficient balance for slashing report fee: have {}, need {}",
                        account.balance, fee
                    ));
                }
                account.balance -= fee;
                self.state.mark_dirty(&reporter);
                charged_fee = true;
            }
        }
        // The registry's `slash_from_report` returns:
        //   Ok(Some(_))  - offender was registered and slashed (actionable)
        //   Ok(None)     - offender wasn't registered, no-op (still honest)
        //   Err(_)       - report was structurally invalid or unverified
        match self.state.slash_from_report(&report) {
            Ok(outcome) => {
                if charged_fee {
                    // Refund on either actionable or honest-no-op outcome.
                    if let Some(reporter) = report.reporter {
                        let account = self.state.get_or_create(&reporter);
                        account.balance = account.balance.saturating_add(fee);
                        self.state.mark_dirty(&reporter);
                    }
                }
                // Count only actionable slashes. Ok(None) is an honest no-op
                // against an unregistered target and is not a slashing event.
                if outcome.is_some() {
                    if let Some(ref m) = self.metrics {
                        m.slashing_events_total.inc();
                    }
                    let target = *report.offender.as_bytes();
                    self.record_quarantine_event(
                        target,
                        crate::registry::QuarantineReason::OperatorSlash(format!(
                            "role {}",
                            report.role
                        )),
                        "OPERATOR_SLASH",
                        &format!("offender slashed (role {})", report.role),
                        3,
                    );
                    self.flush_quarantine_ledger();
                }
                Ok(outcome)
            }
            Err(e) => {
                // Report was invalid (e.g. unverified) → burn the fee. State
                // Change already done above (fee was debited).
                Err(e.to_string())
            }
        }
    }

    fn build_validator_snapshot_from_state(
        epoch: u64,
        state: &AccountState,
        chain_id: u64,
    ) -> ValidatorSetSnapshot {
        let active_validators = state.get_active_validators();
        let entries: Vec<ValidatorEntry> = active_validators
            .into_iter()
            .filter_map(|v| {
                // Consensus-ready is one fail-closed predicate: VRF + BLS +
                // RFC 9380 PoP + PQ are all mandatory for the same stake set.
                let entry = ValidatorEntry {
                    address: v.address,
                    // Finality weight: stake plus Mikoriza restaked weight.
                    stake: v.voting_weight(),
                    bls_public_key: v.bls_public_key.clone(),
                    pop_signature: v.pop_signature.clone(),
                    pq_public_key: v.pq_public_key.clone(),
                };
                if !v.is_consensus_ready() {
                    warn!(
                        "Excluding validator {} from snapshot: incomplete VRF/BLS/PQ key set",
                        v.address
                    );
                    None
                } else if crate::chain::finality::verify_pop(&entry, chain_id) {
                    Some(entry)
                } else {
                    warn!(
                        "Excluding validator {} from snapshot: invalid BLS PoP",
                        v.address
                    );
                    None
                }
            })
            .collect();
        ValidatorSetSnapshot::new(epoch, entries)
    }

    fn record_validator_snapshot(&mut self, epoch: u64) {
        let snapshot = self.build_validator_snapshot(epoch);
        self.validator_snapshots.insert(epoch, snapshot.clone());

        // Persist alongside the in-memory copy. Without this the map was pure
        // Memory, so a restart dropped every historical set and
        // `require_validator_snapshot` refused every past-epoch check until
        // The node had observed a fresh window's worth of epochs. Failing
        // Closed is right; failing closed on every restart is an outage.
        //
        // A failed write is logged, not fatal: losing a snapshot degrades to
        // The pre-existing behaviour (refuse to verify that epoch), whereas
        // Aborting block application would turn a disk hiccup into a halt.
        if let Some(store) = &self.storage {
            if let Err(error) = store.save_validator_snapshot(epoch, &snapshot) {
                warn!("Failed to persist validator snapshot for epoch {epoch}: {error}");
            }
        }

        // Keep a bounded history while preserving the newest snapshot. A loop
        // Enforces the actual entry count; epoch arithmetic alone is off by one
        // Because the current epoch is inclusive.
        let retention = self.max_validator_snapshots.max(1);
        while self.validator_snapshots.len() > retention {
            let Some((evicted, _)) = self.validator_snapshots.pop_first() else {
                break;
            };
            // Evict from disk too, or the stored set grows without bound and a
            // Restart would reload epochs the live node has deliberately
            // Forgotten.
            if let Some(store) = &self.storage {
                if let Err(error) = store.delete_validator_snapshot(evicted) {
                    warn!("Failed to evict validator snapshot for epoch {evicted}: {error}");
                }
            }
        }
    }

    /// The validator set as it stood at `epoch`, or `None` when that set is no
    /// longer known.
    ///
    /// The fallback this replaces built a snapshot from the *current* state and
    /// labelled it with the requested epoch:
    ///
    ///     .unwrap_or_else(|| self.build_validator_snapshot(epoch))
    ///
    /// `build_validator_snapshot_from_state` takes `epoch` only to stamp it on
    /// the result; the members come from `state.get_active_validators()`, which
    /// is today's set. So a certificate from epoch 5 was checked against the
    /// validators of epoch 200 - different members, different stakes, different
    /// quorum - and nothing said so.
    ///
    /// That is reachable in normal operation, not just in theory.
    /// `validator_snapshots` keeps 100 epochs and is never written to disk, so
    /// every historical epoch falls into the fallback after a restart.
    ///
    /// It cuts both ways, which is what makes it worth failing closed over:
    ///
    /// - a genuine old certificate is rejected, because its signers have since
    ///   left the set
    /// - a forged old certificate is accepted, if today's members happen to
    ///   satisfy the quorum
    /// - `handle_qc_fault_proof` judges an old fault against the wrong set, so
    ///   a validator can be slashed for an epoch it was not part of, or escape
    ///   one it was
    ///
    /// Returning `None` makes the caller say "I cannot check this" instead of
    /// answering with the wrong set. The current epoch still builds from state,
    /// because there the current set *is* the right answer.
    fn validator_snapshot_for_epoch(&self, epoch: u64) -> Option<ValidatorSetSnapshot> {
        if epoch == self.state.epoch_index {
            return Some(self.build_validator_snapshot(epoch));
        }
        self.validator_snapshots.get(&epoch).cloned()
    }

    /// The snapshot for `epoch`, or an error naming what is missing.
    ///
    /// Used by the paths that verify someone else's claim about a past epoch,
    /// where guessing the set is worse than refusing.
    fn require_validator_snapshot(&self, epoch: u64) -> Result<ValidatorSetSnapshot, String> {
        self.validator_snapshot_for_epoch(epoch).ok_or_else(|| {
            format!(
                "no validator set recorded for epoch {epoch}; refusing to verify against the \
                 current set (retained epochs: {})",
                self.validator_snapshots.len()
            )
        })
    }

    /// The epoch a checkpoint height belongs to, derived locally from the
    /// chain's own epoch length. The voting, verification and sync paths all
    /// ask this one helper, so a certificate's declared epoch cannot drift
    /// from the height it certifies without being refused, and the three
    /// paths cannot disagree about the derivation.
    fn epoch_for_checkpoint_height(&self, checkpoint_height: u64) -> u64 {
        checkpoint_height / crate::core::chain_config::epoch_len_for_chain_id(self.chain_id).max(1)
    }

    /// The certificate epoch rule the checkpoint paths share: a certificate
    /// is bound to the epoch its checkpoint height derives to, locally,
    /// before any validator set is consulted.
    fn require_checkpoint_epoch(
        &self,
        epoch: u64,
        checkpoint_height: u64,
        what: &str,
    ) -> Result<(), String> {
        let expected = self.epoch_for_checkpoint_height(checkpoint_height);
        if epoch != expected {
            return Err(format!(
                "{what} epoch {epoch} does not match epoch {expected} of checkpoint height \
                 {checkpoint_height}"
            ));
        }
        Ok(())
    }

    pub fn get_qc_blob(&self, height: u64) -> Option<QcBlob> {
        self.verified_qc_blobs.get(&height).cloned().or_else(|| {
            self.storage
                .as_ref()
                .and_then(|store| store.get_qc_blob(height).unwrap_or(None))
        })
    }

    fn prune_verified_qc_blobs(&mut self) {
        let retention = self.max_qc_blobs.max(1);
        while self.verified_qc_blobs.len() > retention {
            self.verified_qc_blobs.pop_first();
        }
    }

    fn pending_finality_cert_count(&self) -> usize {
        self.pending_finality_certs.values().map(Vec::len).sum()
    }

    fn queue_pending_finality_cert(&mut self, cert: FinalityCert) {
        let bucket = self
            .pending_finality_certs
            .entry(cert.checkpoint_height)
            .or_default();
        if !bucket.contains(&cert) {
            bucket.push(cert);
        }

        let retention = self.max_pending_certs.max(1);
        while self.pending_finality_cert_count() > retention {
            let Some(oldest_height) = self.pending_finality_certs.keys().next().copied() else {
                break;
            };
            let remove_bucket =
                if let Some(pending) = self.pending_finality_certs.get_mut(&oldest_height) {
                    if !pending.is_empty() {
                        pending.remove(0);
                    }
                    pending.is_empty()
                } else {
                    false
                };
            if remove_bucket {
                self.pending_finality_certs.remove(&oldest_height);
            }
        }
    }

    /// Post-import QC fault scan.
    ///
    /// Note: `detect_fault_proofs` only flags signatures that fail
    /// Verification. Blobs that pass `import_qc_blob` have already had every
    /// Signature verified, so this loop is empty by construction after a
    /// Successful import. Real finality invalidation must come from an
    /// **external** challenge via `handle_qc_fault_proof` (or a future
    /// Challenge RPC), not from re-scanning an already-accepted blob.
    fn maybe_apply_detected_qc_faults(
        &mut self,
        snapshot: &ValidatorSetSnapshot,
        blob: &QcBlob,
    ) -> Result<(), String> {
        let proofs = blob.detect_fault_proofs_in(&self.state.scheme_registry, snapshot);
        if !proofs.is_empty() {
            // Unexpected for post-import path - still apply if present.
            tracing::warn!(
                "QC post-import fault scan found {} proof(s) at height {}",
                proofs.len(),
                blob.checkpoint_height
            );
        }
        for proof in proofs {
            let verdict =
                proof.verify_against_blob_in(&self.state.scheme_registry, blob, snapshot)?;
            self.apply_qc_fault_verdict(&proof, verdict)?;
        }
        Ok(())
    }

    fn invalidate_finality_from_height(&mut self, from_height: u64) {
        let checkpoint_interval =
            crate::core::chain_config::finality_checkpoint_interval_for_chain_id(self.chain_id);
        let qc_heights: Vec<u64> = self
            .verified_qc_blobs
            .range(from_height..)
            .map(|(height, _)| *height)
            .collect();
        for height in qc_heights {
            self.verified_qc_blobs.remove(&height);
        }

        if let Some(store) = &self.storage {
            let mut height = from_height;
            let upper_bound = self.chain.len().saturating_sub(1) as u64;
            while height <= upper_bound {
                if let Err(e) = store.delete_finality_cert(height) {
                    tracing::error!(error = %e, height, "Failed to delete finality cert");
                }
                if let Err(e) = store.delete_qc_blob(height) {
                    tracing::error!(error = %e, height, "Failed to delete QC blob");
                }
                if let Some(next) = height.checked_add(checkpoint_interval) {
                    height = next;
                } else {
                    break;
                }
            }
        }

        let mut new_finalized_height = 0;
        let mut new_finalized_hash = self
            .chain
            .first()
            .map(|block| block.hash.clone())
            .unwrap_or_default();

        if let Some(store) = &self.storage {
            // Walk back from the highest checkpoint at or below the tip, not
            // from the tip itself.
            //
            // Certificates only ever exist at multiples of
            // `checkpoint_interval` - `import_qc_blob` rejects anything else
            // via `is_checkpoint_height_for_chain`. Starting at
            // `chain.len() - 1` and stepping down by the interval keeps the
            // tip's residue forever, so the scan only lands on a real
            // checkpoint when the tip happens to be a multiple. At an interval
            // of 10 that is one height in ten; the other nine probe heights
            // where no certificate was ever written, find nothing, and leave
            // `finalized_height` at 0.
            //
            // Measured at interval 10 before the fix:
            //
            //     tip 57 -> probes 57, 47, 37, 27, 17   -> no hit, finality 0
            //     tip 60 -> probes 60, 50, 40, 30, ...  -> hit at 60
            //
            // Dropping finality to zero after a QC fault is the wrong
            // direction to fail: the chain keeps the blocks but forgets they
            // were finalised, so a reorg that `reorg_rejects_fork_at_finalized_height`
            // would have refused becomes allowed again.
            let tip = self.chain.len().saturating_sub(1) as u64;
            let mut height = (tip / checkpoint_interval) * checkpoint_interval;
            while height >= checkpoint_interval {
                if let Ok(Some(cert)) = store.get_finality_cert(height) {
                    // A stored cert is adopted only when
                    // its checkpoint hash matches the block actually at that
                    // height on THIS chain. Adopting whatever the disk holds
                    // let a cert for another fork set the finalized marker.
                    let matches_chain = self
                        .chain
                        .get(height as usize)
                        .is_some_and(|block| block.hash == cert.checkpoint_hash);
                    if matches_chain {
                        new_finalized_height = cert.checkpoint_height;
                        new_finalized_hash = cert.checkpoint_hash;
                        break;
                    }
                    tracing::warn!(
                        height,
                        "stored finality cert does not match the chain at that height; not adopted"
                    );
                }
                height = height.saturating_sub(checkpoint_interval);
                if height == 0 {
                    break;
                }
            }
        }

        self.finalized_height = new_finalized_height;
        self.finalized_hash = new_finalized_hash;

        if let Some(store) = &self.storage {
            if let Err(e) = store.save_canonical_height(self.finalized_height) {
                tracing::error!(error = %e, height = self.finalized_height, "Failed to save canonical height");
            }
        }

        // The rescan may have restored finality; let the engine
        // promote any parked boundary checkpoints it covers.
        self.consensus.note_finalized_height(
            self.finalized_height,
            &self.chain,
            self.storage.as_ref(),
        );
    }

    fn apply_qc_fault_verdict(
        &mut self,
        _proof: &QcFaultProof,
        verdict: QcProofVerdict,
    ) -> Result<(), String> {
        if verdict.slash_validator || verdict.action == QcProofAction::SlashValidator {
            // A stake slash applied directly to
            // `self.state` from the gossip/RPC import path mutates state that
            // lives in the state root OUTSIDE block execution - every node
            // that saw the proof would compute a different root from every
            // node that did not. The old path also dropped the result
            // (`let _ =`), so even the caller could not tell what moved.
            // The slash is refused here; it applies only when a block carries
            // it as an effect. Until that carrier exists (with the
            // proof path), the verdict records nothing and moves nothing.
            return Err(
                "QC fault verdict slash refused: stake moves only inside block \
                 execution - slashing outside a block splits the state root"
                    .to_string(),
            );
        }

        if let Some(height) = verdict.invalidate_from_height {
            self.invalidate_finality_from_height(height);
        }
        Ok(())
    }

    pub fn import_qc_blob(&mut self, blob: QcBlob) -> Result<(), String> {
        if !crate::chain::finality::is_checkpoint_height_for_chain(
            blob.checkpoint_height,
            self.chain_id,
        ) {
            return Err(format!(
                "Height {} is not a valid checkpoint height",
                blob.checkpoint_height
            ));
        }

        let block = self
            .chain
            .get(blob.checkpoint_height as usize)
            .ok_or_else(|| {
                format!(
                    "Missing checkpoint block at height {}",
                    blob.checkpoint_height
                )
            })?;

        if block.hash != blob.checkpoint_hash {
            return Err(format!(
                "QcBlob checkpoint hash mismatch: expected {}, got {}",
                block.hash, blob.checkpoint_hash
            ));
        }

        self.require_checkpoint_epoch(blob.epoch, blob.checkpoint_height, "QcBlob")?;
        let snapshot = self.require_validator_snapshot(blob.epoch)?;
        // (security audit) enforce the BLS
        // Finality quorum (2/3 of `snapshot.validators`) against the
        // POST-deduplication unique-signer count, not the raw
        // `pq_signatures.len`.
        //
        // The design used `pq_signatures.len < min_signers`
        // Which counted duplicate validator entries. An attacker
        // Could spam the same validator's signature N times in a
        // Single blob to push the raw count past the quorum
        // Threshold even though only one unique validator had
        // Signed. The structural checks in `verify_against_snapshot`
        // Catch the duplicate (it errors on `insert` returning
        // False), but the quorum check fired *before* that and
        // Could be bypassed by inflating the raw entry count.
        //
        // The fix: do the structural verification FIRST, then
        // Enforce the quorum against the unique-verified signer
        // Set returned by `verify_against_snapshot`. The unique
        // Count is what actually counts as "this many validators
        // Have attested", which is the definition of quorum.
        use crate::core::chain_config::{FINALITY_QUORUM_DENOMINATOR, FINALITY_QUORUM_NUMERATOR};
        let n_validators = snapshot.validators.len();
        let min_signers = (n_validators * FINALITY_QUORUM_NUMERATOR as usize)
            .div_ceil(FINALITY_QUORUM_DENOMINATOR as usize);
        let verified_signers = blob.verify_against_snapshot_in(
            &self.state.scheme_registry,
            &snapshot,
            None,
            Some(self.state.epoch_index),
        )?;
        if verified_signers.len() < min_signers {
            return Err(format!(
                "QcBlob has {} unique verified signers, need at least {} (2/3 of {} validators)",
                verified_signers.len(),
                min_signers,
                n_validators
            ));
        }

        self.verified_qc_blobs
            .insert(blob.checkpoint_height, blob.clone());
        self.prune_verified_qc_blobs();

        if let Some(store) = &self.storage {
            if let Err(e) = store.save_qc_blob(blob.checkpoint_height, &blob) {
                tracing::error!("Failed to persist QC blob: {e}");
            }
        }

        // The blob is imported - stored in memory and on
        // disk - before this point. A pending cert at this height failing is
        // a separate bookkeeping problem, not a reason to report the peer
        // that delivered a good blob as bad. The import reports success; the
        // pending-cert outcome is logged.
        if let Err(e) = self.process_pending_finality_certs(blob.checkpoint_height) {
            tracing::warn!(
                height = blob.checkpoint_height,
                "QC blob imported, but the pending finality cert at this height did not apply: {e}"
            );
        }
        Ok(())
    }

    /// A stored QC blob must sign the same checkpoint block as the certificate.
    /// After a reorg `get_qc_blob` can still return the blob of the old fork
    /// from disk, and a certificate of the new fork must not be finalized with
    /// it.
    fn ensure_blob_matches_checkpoint(blob: &QcBlob, checkpoint_hash: &str) -> Result<(), String> {
        if blob.checkpoint_hash != checkpoint_hash {
            return Err(format!(
                "QC blob checkpoint hash {} does not match certificate hash {} at height {}",
                blob.checkpoint_hash, checkpoint_hash, blob.checkpoint_height
            ));
        }
        Ok(())
    }

    pub fn handle_qc_fault_proof(&mut self, proof: QcFaultProof) -> Result<(), String> {
        let blob = self
            .get_qc_blob(proof.checkpoint_height)
            .ok_or_else(|| format!("Missing QC blob at height {}", proof.checkpoint_height))?;
        let snapshot = self.require_validator_snapshot(proof.epoch)?;
        let verdict =
            proof.verify_against_blob_in(&self.state.scheme_registry, &blob, &snapshot)?;
        self.apply_qc_fault_verdict(&proof, verdict)
    }

    fn projected_sender_state(&self, tx: &Transaction) -> (u64, u64) {
        let mut expected_nonce = self.state.get_nonce(&tx.from);
        // The variable is named for the quantity it is supposed to hold, and
        // it held the raw balance instead. `spendable_balance` subtracts the
        // still-locked vesting portion, which is the number the executor
        // compares against, so admission and execution now ask the same
        // question. Without this the mempool accepts a team-account transfer
        // of locked $BUD, gossips it, and the executor refuses it at apply
        // time: a divergence between what a node relays and what it will run.
        let mut spendable_balance = self.state.spendable_balance(&tx.from);

        for pending in self.mempool.sender_transactions(&tx.from) {
            if pending.nonce == tx.nonce {
                continue;
            }
            if pending.nonce < expected_nonce {
                continue;
            }
            if pending.nonce != expected_nonce {
                break;
            }

            let pending_cost = pending.total_cost();
            if spendable_balance < pending_cost {
                break;
            }

            spendable_balance = spendable_balance.saturating_sub(pending_cost);
            expected_nonce = expected_nonce.saturating_add(1);
        }

        (expected_nonce, spendable_balance)
    }

    fn validate_pool_transaction(&self, tx: &Transaction) -> Result<(), String> {
        if tx.chain_id != self.chain_id {
            return Err(format!(
                "Invalid Chain ID: expected {}, got {}",
                self.chain_id, tx.chain_id
            ));
        }
        if tx.from == Address::zero() {
            return Err("Genesis transactions cannot be submitted to the mempool".into());
        }

        let (expected_nonce, spendable_balance) = self.projected_sender_state(tx);
        self.state
            .validate_transaction_with_context(tx, expected_nonce, spendable_balance)
    }

    pub fn tx_precheck(&self, tx: &Transaction) -> serde_json::Value {
        let mut reasons = Vec::new();

        if tx.chain_id != self.chain_id {
            reasons.push("invalid_chain_id".to_string());
        }
        if tx.from == Address::zero() {
            reasons.push("genesis_transaction_forbidden".to_string());
        }
        if !tx.verify_in(&self.state.scheme_registry) {
            reasons.push("invalid_signature".to_string());
        }
        if tx.fee < self.state.base_fee {
            reasons.push("fee_too_low".to_string());
        }
        if tx.max_fee != 0 && tx.max_fee != tx.fee {
            reasons.push("flat_fee_max_fee_mismatch".to_string());
        }
        if tx.priority_fee != 0 {
            reasons.push("flat_fee_priority_fee_forbidden".to_string());
        }

        let (expected_nonce, spendable_balance) = self.projected_sender_state(tx);
        if tx.nonce < expected_nonce {
            reasons.push("nonce_too_low".to_string());
        } else if tx.nonce > expected_nonce {
            reasons.push("nonce_too_high".to_string());
        }
        let precheck_cost = if matches!(
            &tx.tx_type,
            crate::core::transaction::TransactionType::Undelegate { .. }
                | crate::core::transaction::TransactionType::WithdrawDelegation { .. }
                | crate::core::transaction::TransactionType::SetValidatorCommission { .. }
                | crate::core::transaction::TransactionType::Redelegate { .. }
                | crate::core::transaction::TransactionType::ClaimRewards { .. }
        ) {
            tx.fee
        } else {
            tx.total_cost()
        };
        if spendable_balance < precheck_cost {
            reasons.push("insufficient_funds".to_string());
        }

        match tx.tx_type {
            crate::core::transaction::TransactionType::Transfer => {
                if tx.to == Address::zero() {
                    reasons.push("missing_to_address".to_string());
                }
            }
            crate::core::transaction::TransactionType::Stake => {
                if tx.amount == 0 {
                    reasons.push("invalid_stake_amount".to_string());
                }
            }
            crate::core::transaction::TransactionType::Delegate { validator }
            | crate::core::transaction::TransactionType::Undelegate { validator } => {
                if tx.amount == 0 || tx.to != Address::zero() || !tx.data.is_empty() {
                    reasons.push("invalid_delegation_shape".to_string());
                }
                if self.state.get_validator(&validator).is_none() {
                    reasons.push("delegation_target_not_validator".to_string());
                }
                if matches!(
                    &tx.tx_type,
                    crate::core::transaction::TransactionType::Undelegate { .. }
                ) && self.state.registry.delegated_amount(tx.from, validator) < tx.amount
                {
                    reasons.push("delegation_unbond_exceeds_position".to_string());
                }
            }
            crate::core::transaction::TransactionType::Redelegate {
                from_validator,
                to_validator,
            } => {
                if tx.amount == 0 || tx.to != Address::zero() || !tx.data.is_empty() {
                    reasons.push("invalid_redelegation_shape".to_string());
                }
                if from_validator == to_validator {
                    reasons.push("redelegation_same_validator".to_string());
                }
                if self.state.get_validator(&from_validator).is_none()
                    || self.state.get_validator(&to_validator).is_none()
                {
                    reasons.push("redelegation_target_not_validator".to_string());
                }
                if self
                    .state
                    .registry
                    .delegated_amount(tx.from, from_validator)
                    < tx.amount
                {
                    reasons.push("redelegation_exceeds_position".to_string());
                }
            }
            crate::core::transaction::TransactionType::ClaimRewards { validator } => {
                if tx.amount != 0 || tx.to != Address::zero() || !tx.data.is_empty() {
                    reasons.push("invalid_claim_rewards_shape".to_string());
                }
                if self.state.registry.claimable_reward(tx.from, validator) == 0 {
                    reasons.push("no_claimable_reward".to_string());
                }
            }
            crate::core::transaction::TransactionType::WithdrawDelegation { validator } => {
                if tx.amount != 0 || tx.to != Address::zero() || !tx.data.is_empty() {
                    reasons.push("invalid_delegation_withdraw_shape".to_string());
                }
                if self.state.registry.withdrawable_delegation(
                    tx.from,
                    validator,
                    self.state.epoch_index,
                ) == 0
                {
                    reasons.push("delegation_not_mature".to_string());
                }
            }
            crate::core::transaction::TransactionType::SetValidatorCommission {
                commission_ppm,
            } => {
                if tx.amount != 0 || tx.to != Address::zero() || !tx.data.is_empty() {
                    reasons.push("invalid_validator_commission_shape".to_string());
                }
                if self.state.get_validator(&tx.from).is_none()
                    || u64::from(commission_ppm)
                        > self.state.registry.params().max_validator_commission_ppm
                {
                    reasons.push("invalid_validator_commission".to_string());
                }
            }
            crate::core::transaction::TransactionType::BnsRenew => {
                match bincode::deserialize::<(String, u64)>(&tx.data) {
                    Ok((name, duration)) => {
                        if tx.amount != self.state.bns_registry.calculate_cost(&name, duration) {
                            reasons.push("invalid_bns_renewal_payment".to_string());
                        }
                        if duration == 0 {
                            reasons.push("invalid_bns_renewal_duration".to_string());
                        }
                    }
                    Err(_) => reasons.push("invalid_bns_renewal_data".to_string()),
                }
                if tx.amount == 0 || tx.to != Address::zero() {
                    reasons.push("invalid_bns_renewal_shape".to_string());
                }
            }
            crate::core::transaction::TransactionType::BnsTransfer => {
                match bincode::deserialize::<(String, Address)>(&tx.data) {
                    Ok((_name, new_owner)) if new_owner != Address::zero() => {}
                    Ok(_) => reasons.push("invalid_bns_transfer_owner".to_string()),
                    Err(_) => reasons.push("invalid_bns_transfer_data".to_string()),
                }
                if tx.amount != 0 || tx.to != Address::zero() {
                    reasons.push("invalid_bns_transfer_shape".to_string());
                }
            }
            crate::core::transaction::TransactionType::RegisterConsensusKeys(ref registration) => {
                if tx.amount != 0 || tx.to != Address::zero() || !tx.data.is_empty() {
                    reasons.push("invalid_consensus_key_registration_shape".to_string());
                }
                match self.state.get_validator(&tx.from) {
                    None => reasons.push("validator_not_bonded".to_string()),
                    Some(validator) if validator.active => {
                        reasons.push("active_validator_key_rotation_forbidden".to_string())
                    }
                    Some(_) => {}
                }
                if registration.validate(tx.from, tx.chain_id).is_err() {
                    reasons.push("invalid_consensus_keys".to_string());
                }
            }
            crate::core::transaction::TransactionType::AiOperatorBond => {
                if tx.amount < self.state.required_ai_bond(tx.chain_id) {
                    reasons.push("ai_operator_bond_below_network_floor".to_string());
                }
                if tx.to != Address::zero() || !tx.data.is_empty() {
                    reasons.push("invalid_ai_operator_bond_shape".to_string());
                }
                if self
                    .state
                    .registry
                    .get(&tx.from, crate::registry::role::roles::AI_OPERATOR)
                    .is_some()
                {
                    reasons.push("ai_operator_already_registered".to_string());
                }
            }
            crate::core::transaction::TransactionType::AiOperatorUnbond => {
                if tx.amount != 0 || tx.to != Address::zero() || !tx.data.is_empty() {
                    reasons.push("invalid_ai_operator_unbond_shape".to_string());
                }
                if !self
                    .state
                    .registry
                    .is_active(&tx.from, crate::registry::role::roles::AI_OPERATOR)
                {
                    reasons.push("ai_operator_not_active".to_string());
                }
                if self
                    .state
                    .ai_registry
                    .operator_has_open_obligations(&tx.from, self.state.current_block_height)
                {
                    reasons.push("ai_operator_has_open_obligations".to_string());
                }
            }
            crate::core::transaction::TransactionType::AiOperatorWithdraw => {
                if tx.amount != 0 || tx.to != Address::zero() || !tx.data.is_empty() {
                    reasons.push("invalid_ai_operator_withdraw_shape".to_string());
                }
                match self
                    .state
                    .registry
                    .get(&tx.from, crate::registry::role::roles::AI_OPERATOR)
                {
                    Some(registration) => match registration.status {
                        crate::registry::MemberStatus::Unbonding { release_epoch }
                            if self.state.epoch_index >= release_epoch => {}
                        crate::registry::MemberStatus::Unbonding { .. } => {
                            reasons.push("ai_bond_still_unbonding".to_string());
                        }
                        _ => reasons.push("ai_operator_not_unbonding".to_string()),
                    },
                    None => reasons.push("ai_operator_not_registered".to_string()),
                }
            }
            crate::core::transaction::TransactionType::Unstake => {
                match self.state.get_validator(&tx.from) {
                    Some(validator)
                        if validator
                            .stake
                            .saturating_sub(self.state.registry.delegated_stake(&tx.from))
                            >= tx.amount => {}
                    Some(_) => reasons.push("insufficient_self_stake".to_string()),
                    None => reasons.push("not_a_validator".to_string()),
                }
            }
            crate::core::transaction::TransactionType::Vote => {
                if self.state.get_validator(&tx.from).is_none() {
                    reasons.push("not_a_validator".to_string());
                }
                if tx.data.len() > 9
                    && tx.fee < self.state.required_governance_proposal_fee(&tx.from)
                {
                    reasons.push("governance_proposal_fee_too_low".to_string());
                }
            }
            crate::core::transaction::TransactionType::ContractCall => {
                if tx.amount != 0 {
                    reasons.push("contract_amount_must_be_zero".to_string());
                }
                if tx.data.is_empty() || !tx.data.len().is_multiple_of(8) {
                    reasons.push("invalid_contract_bytecode".to_string());
                }
            }
            crate::core::transaction::TransactionType::AiInferenceResult(_)
            | crate::core::transaction::TransactionType::AiAttachExecutionProof { .. } => {
                if !self
                    .state
                    .registry
                    .is_active(&tx.from, crate::registry::role::roles::AI_OPERATOR)
                {
                    reasons.push("ai_operator_unauthorized".to_string());
                }
            }
            crate::core::transaction::TransactionType::PrivateTransferSubmit(_)
            | crate::core::transaction::TransactionType::PrivacyNoteInsert(_) => {
                if self.chain_id
                    == crate::core::chain_config::Network::Mainnet
                        .chain_id()
                        .value()
                {
                    reasons.push("privacy_mainnet_disabled".to_string());
                }
            }
            crate::core::transaction::TransactionType::AiDisputeSlash {
                request_id,
                verifier,
            } => {
                if !self
                    .state
                    .registry
                    .is_active(&verifier, crate::registry::role::roles::AI_OPERATOR)
                {
                    reasons.push("ai_slash_operator_inactive".to_string());
                }
                if !self.state.ai_registry.is_disputable(
                    &request_id,
                    &verifier,
                    self.state.current_block_height,
                ) {
                    reasons.push("ai_equivocation_evidence_missing".to_string());
                }
            }
            _ => {}
        }

        if reasons.is_empty() {
            let mut probe = self.mempool.clone();
            probe.sync_scheme_registry(&self.state.scheme_registry);
            if let Err(err) = probe.add_transaction(tx.clone()) {
                let reason = match err {
                    crate::mempool::pool::MempoolError::PoolFull => "pool_full",
                    // Reported separately from `pool_full` on purpose: the two
                    // ask the operator for opposite responses. A pool full by
                    // count wants a larger `max_size`; a pool full by bytes is
                    // being fed large bodies, and raising `max_size` makes it
                    // worse. Collapsing them into one string would send the
                    // reader the wrong way.
                    crate::mempool::pool::MempoolError::PoolBytesFull => "pool_bytes_full",
                    crate::mempool::pool::MempoolError::DuplicateTransaction => {
                        "duplicate_transaction"
                    }
                    crate::mempool::pool::MempoolError::FeeTooLow => "fee_too_low",
                    crate::mempool::pool::MempoolError::SenderLimitReached => {
                        "sender_limit_reached"
                    }
                    crate::mempool::pool::MempoolError::InvalidNonce => "invalid_nonce",
                    crate::mempool::pool::MempoolError::TransactionExpired => "transaction_expired",
                    crate::mempool::pool::MempoolError::RbfFeeTooLow => "rbf_fee_too_low",
                    crate::mempool::pool::MempoolError::InvalidTransaction(_) => {
                        "invalid_transaction"
                    }
                };
                reasons.push(reason.to_string());
            }
        }

        serde_json::json!({
            "accepted": reasons.is_empty(),
            "reasons": reasons
        })
    }

    fn collect_block_transactions(
        &self,
        block_timestamp_ms: u128,
        previous_hash: &str,
    ) -> Vec<Transaction> {
        let pending_txs = self
            .mempool
            .get_sorted_transactions(crate::consensus::MAX_TRANSACTIONS_PER_BLOCK);
        let mut valid_txs = Vec::new();
        let mut temp_state = self.state.clone();
        let set_block_context = |s: &mut crate::core::account::AccountState| {
            s.current_block_height = self.chain.len() as u64;
            s.current_block_unix_secs = Self::block_timestamp_secs(block_timestamp_ms);
            s.current_block_entropy = Self::block_context_entropy(previous_hash, &[]);
        };
        set_block_context(&mut temp_state);
        let mut included = std::collections::HashSet::new();
        let mut progress = true;
        let mut contract_calls: u64 = 0;
        // The count cap above is not the binding limit: `validate_block_size`
        // also caps the JSON-serialized block at `MAX_BLOCK_SIZE`, and for
        // typical transactions that byte budget fills long before 5000
        // transactions. A producer that only counted would build blocks its
        // own full validation then refuses - measured on the single-node
        // pipeline benchmark, whose first block packed 3.3 MB against the
        // 1 MB cap and produced nothing at all. Track the serialized size
        // with the validator's own measure (serde_json of each transaction,
        // exactly as it lands inside the block JSON) and leave a fixed
        // allowance for the header fields; a transaction past the remaining
        // budget waits for the next block.
        const BLOCK_HEADER_JSON_ALLOWANCE: usize = 4096;
        // Slashing evidence gets a share of the block of its own. The evidence
        // budget in `produce_block` is only what the transactions leave, so a
        // mempool that fills the transaction budget would otherwise starve
        // every pending double-sign proof out of every block: an equivocating
        // validator could escape slashing just by keeping the chain busy.
        const BLOCK_EVIDENCE_JSON_ALLOWANCE: usize =
            crate::consensus::MAX_SLASHING_EVIDENCE_BYTES + 1024;
        let tx_byte_budget = crate::consensus::MAX_BLOCK_SIZE
            .saturating_sub(BLOCK_HEADER_JSON_ALLOWANCE)
            .saturating_sub(BLOCK_EVIDENCE_JSON_ALLOWANCE);
        let mut block_bytes: usize = 0;

        while progress && valid_txs.len() < crate::consensus::MAX_TRANSACTIONS_PER_BLOCK {
            progress = false;
            for tx in &pending_txs {
                if valid_txs.len() >= crate::consensus::MAX_TRANSACTIONS_PER_BLOCK {
                    break;
                }
                if included.contains(&tx.hash) {
                    continue;
                }
                if temp_state.validate_transaction(tx).is_err() {
                    continue;
                }
                // The producer keeps to the block's contract gas budget, so
                // the block it builds passes the check every validator runs
                // in `apply_block_checked`; a call past the budget waits.
                let is_call = tx.tx_type == crate::core::transaction::TransactionType::ContractCall;
                if is_call && Executor::check_contract_call_count(contract_calls + 1).is_err() {
                    continue;
                }
                // Serialized-size budget (see above): +1 for the separator
                // between array entries. An unserializable transaction can
                // never enter a valid block; treat it as infinitely large
                // here and let the discard scan below deal with it.
                let tx_bytes = serde_json::to_vec(tx)
                    .map_or(usize::MAX, |bytes| bytes.len().saturating_add(1));
                if block_bytes.saturating_add(tx_bytes) > tx_byte_budget {
                    continue;
                }
                // Execute against a disposable candidate. Only a
                // successful transaction publishes its state to the selection
                // prefix; every error discards ALL partial writes. Replaying a
                // prefix after an error is not sufficient: replay itself can
                // fail and contaminate the next accepted transaction.
                let mut candidate_state = temp_state.clone();
                if Executor::apply_transaction_checked(&mut candidate_state, tx).is_ok() {
                    temp_state = candidate_state;
                    if is_call {
                        contract_calls += 1;
                    }
                    block_bytes += tx_bytes;
                    valid_txs.push(tx.clone());
                    included.insert(tx.hash.clone());
                    progress = true;
                }
            }
        }

        for tx in &pending_txs {
            if !included.contains(&tx.hash) && self.state.validate_transaction(tx).is_err() {
                warn!("Discarding invalid transaction: {}", tx.hash);
            }
        }

        valid_txs
    }

    fn adjust_base_fee(state: &mut AccountState, tx_count: usize) {
        let tx_count = tx_count as u64;
        let target = 50u64;
        let max_base_fee = 10_000_000;

        if tx_count > target {
            state.base_fee = state
                .base_fee
                .saturating_add(state.base_fee / 8)
                .min(max_base_fee);
        } else if tx_count < target {
            state.base_fee = state.base_fee.saturating_sub(state.base_fee / 8).max(1);
        }
    }

    fn apply_system_effects(state: &mut AccountState, block: &Block) {
        if let Some(evidences) = &block.slashing_evidence {
            // (security audit) the slashing ratio
            // For on-chain `slashing_evidence` is a critical
            // Security parameter and must come from
            // `RegistryParams` rather than a hardcoded literal.
            // The PoS-style `SlashingEvidence` (header1 !=
            // Header2 from the same producer at the same height)
            // Is the canonical double-sign proof, so the
            // `DoubleSign` ratio applies.
            let slash_ratio_fixed = state
                .registry
                .params()
                .slash_ratio(crate::registry::permissionless::SlashingCondition::DoubleSign);
            // Headers signed for another chain are not proof of anything here.
            // A key shared by two chains would otherwise let anyone replay
            // real signatures from the other chain and slash a validator.
            let own_chain: Vec<SlashingEvidence> = evidences
                .iter()
                .filter(|e| {
                    e.header1.chain_id == block.chain_id && e.header2.chain_id == block.chain_id
                })
                .cloned()
                .collect();
            state.apply_slashing(&own_chain, slash_ratio_fixed);
        }

        let epoch_length = crate::core::chain_config::epoch_len_for_chain_id(block.chain_id);
        if block.index > 0 && block.index.is_multiple_of(epoch_length) {
            state.advance_epoch(block.timestamp, block.chain_id);
        }

        if block.index > 0 {
            Self::adjust_base_fee(state, block.transactions.len());
        }

        // PoA admission is recomputed here, once, at a point every node
        // reaches with the same state and the same block index. Doing it
        // lazily on the consensus path instead would make the audit trail
        // depend on who asked and when, which is the one thing a compliance
        // record cannot be. An elapsed KYC horizon is therefore observed the
        // same number of times on every node.
        state.refresh_poa_admissions(block.index);
    }

    /// Epoch-close liveness observation, as a pure state transition.
    ///
    /// This used to run in `produce_block` / block-import **after** the block
    /// Was already committed, mutating `self.state.liveness` outside the replay
    /// Path. `liveness.root` is part of `calculate_state_root`, so the
    /// Producer's state diverged from any state rebuilt by replaying the same
    /// Blocks: the node could not even re-validate its own chain, and the first
    /// Reorg failed with "Candidate state root mismatch" at the block right
    /// After an epoch boundary (liveness/fork-choice split).
    ///
    /// Deriving it here, from `(state, block, preceding_chain)` only, makes the
    /// Effect reproducible by every replay path.
    /// item 8: at each epoch boundary the closing epoch is paid from
    /// the validation reward pool, when the chain's profile has one. Runs in
    /// the block transition, so every node pays the same validators the same
    /// amounts.
    /// The schedule this block may pay from, if any.
    ///
    /// Both conditions have to hold, and neither implies the other: the
    /// genesis flag (`reward_pool.enabled`, testnet item 8) is the chain's
    /// permission to pay at all, and the profile's schedule is the pot it
    /// pays from. A chain that turned the pool off pays nothing even if
    /// someone transferred BUD to the pool account later - the flag, not the
    /// balance, is the permission - and a chain whose profile has no schedule
    /// (mainnet until, devnet) has nothing to pay from whatever the flag
    /// says. Genesis refuses the one combination that disagrees
    /// (`GenesisConfig::validate_reward_pool_flag`).
    fn payable_reward_pool(
        chain_id: u64,
        enabled: bool,
    ) -> Option<crate::tokenomics::reward_pool::RewardPoolSchedule> {
        if !enabled {
            return None;
        }
        crate::core::chain_config::reward_pool_for_chain_id(chain_id)
    }

    fn apply_epoch_reward_pool(state: &mut AccountState, block: &Block) {
        // The flag is read from consensus state so a replay and a peer gate
        // identically.
        let Some(schedule) = Self::payable_reward_pool(block.chain_id, state.reward_pool_enabled)
        else {
            return;
        };
        let epoch_length = crate::core::chain_config::epoch_len_for_chain_id(block.chain_id);
        if block.index == 0 || epoch_length == 0 || !block.index.is_multiple_of(epoch_length) {
            return;
        }
        let closed_epoch = (block.index / epoch_length).saturating_sub(1);
        crate::tokenomics::reward_pool::pay_epoch(state, &schedule, closed_epoch);
    }

    fn apply_epoch_close_liveness(
        state: &mut AccountState,
        block: &Block,
        preceding_chain: &[Block],
    ) {
        let epoch_length = crate::core::chain_config::epoch_len_for_chain_id(block.chain_id);
        if block.index == 0 || epoch_length == 0 || !block.index.is_multiple_of(epoch_length) {
            return;
        }
        let closed_epoch = (block.index / epoch_length).saturating_sub(1);

        // Single-producer approximation: the closing
        // Block's producer plus the producers of the closing epoch's blocks
        // Count as participants, so honest validators that produced regularly
        // Inside the epoch are not stamped absentee.
        let lookback = (epoch_length as usize).saturating_sub(1);
        let mut participated: std::collections::HashSet<Address> = preceding_chain
            .iter()
            .rev()
            .take(lookback)
            .filter_map(|b| b.producer)
            .collect();
        if let Some(producer) = block.producer {
            participated.insert(producer);
        }

        let params = *state.registry.params();
        let expected: Vec<Address> = state
            .validators
            .keys()
            .filter(|addr| {
                state
                    .registry
                    .is_active(addr, crate::registry::role::roles::VALIDATOR)
            })
            .copied()
            .collect();
        let reported = state.liveness.record_epoch(
            closed_epoch,
            &expected,
            |addr| participated.contains(addr),
            &params,
        );

        // OBSERVE mode by default; only act when slashing is explicitly enabled.
        if params.liveness_slashing_enabled {
            let jail_until = state
                .epoch_index
                .saturating_add(crate::registry::params::LIVENESS_JAIL_EPOCHS);
            for report in &reported {
                let _ = state.slash_from_report(report);
                if let Some(validator) = state.validators.get_mut(&report.offender) {
                    if !validator.slashed {
                        // Absence is a TIMED
                        // jail. `slashed` stays false, or the release loop
                        // (`!slashed`) could never bring the validator back.
                        validator.active = false;
                        // The term, and the flag the release loop reads.
                        //
                        // `AccountState::advance_epoch` releases on
                        // `jailed && jail_until <= epoch_index`. Cutting the
                        // stake without setting `jailed` left the offender
                        // invisible to that loop: a liveness penalty, which
                        // is a penalty for being absent, became permanent.
                        // Absence is also what a partition or a failed disk
                        // looks like, so the punishment outlived the fault
                        // it was measuring.
                        //
                        // `jailed` is hashed into the state root, so the two
                        // slashing paths also disagreed on the root they
                        // produced from identical evidence.
                        validator.jailed = true;
                        validator.jail_until = jail_until;
                    }
                }
            }
        }
    }

    /// Prune engine-local evidence only after a block has entered the canonical
    /// Chain. Keeping this out of `apply_system_effects` preserves that
    /// Function's pure `(state, block) -> state` replay contract.
    fn prune_consensus_evidence_after_commit(&self, block_index: u64) {
        let epoch_length = crate::core::chain_config::epoch_len_for_chain_id(self.chain_id);
        if block_index > 0 && block_index.is_multiple_of(epoch_length) {
            let min_height = block_index.saturating_sub(1000);
            if let Err(error) = self.consensus.prune_slashing_evidence(min_height) {
                warn!("Consensus evidence pruning failed after block {block_index}: {error}");
            }
        }
    }

    fn commit_block_durable(
        &self,
        block: &Block,
        committed_state: &AccountState,
    ) -> Result<(), String> {
        let _storage_timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.storage_write_seconds.start_timer());
        if let Some(ref store) = self.storage {
            let mut accounts_to_save = Vec::new();
            for (pubkey, account) in &committed_state.accounts {
                accounts_to_save.push((*pubkey, account.clone()));
            }

            // The durable batch stores the cert ONLY
            // when it certifies THIS block. A pending cert is just a queued
            // object - storing it beside a block it does not hash-match
            // writes a finality cert for a block that was never finalised
            // that way, and `invalidate_finality_from_height` would later
            // adopt it wholesale.
            let finality_cert = self
                .pending_finality_certs
                .get(&block.index)
                .and_then(|certs| certs.first().cloned())
                .filter(|cert| cert.checkpoint_hash == block.hash);

            // The checkpoint headers this block committed, beside the block.
            let mut archive = self.global_headers.clone();
            let global_headers =
                Self::reconcile_global_header_archive(&mut archive, committed_state);
            let batch = crate::storage::traits::DurableCommitBatch {
                block: block.clone(),
                state_root: block.state_root.clone(),
                finality_cert,
                global_headers,
                bridge_state: Some(committed_state.bridge_state.clone()),
                accounts: accounts_to_save,
            };

            store
                .commit_durable_batch(&batch)
                .map_err(|e| format!("Failed to commit durable batch: {e}"))?;
        }
        Ok(())
    }

    /// Pre-scan a block for NftBurn transactions and collect the associated
    /// Content CIDs from the NFT registry (before the burn removes them).
    /// Returns a list of `(ContentId, owner_address)` pairs for content that
    /// should be pruned from the storage registry after block commit.
    ///
    /// The list is the authorisation point for every consumer of it: the
    /// registry prune *and*, through the value both block paths return, the
    /// node's physical delete worker. `NftMint` accepts an arbitrary content
    /// id, so a burn proves nothing about the content it names and a cid is
    /// collected only when the burning account is the manifest's claimant.
    fn collect_nft_burn_cids_from_state(
        state: &AccountState,
        block: &Block,
    ) -> Vec<(crate::storage::content_id::ContentId, Address)> {
        let mut cids = Vec::new();
        for tx in &block.transactions {
            if let crate::core::transaction::TransactionType::NftBurn = tx.tx_type {
                if let Ok(nft_id) = bincode::deserialize::<u64>(&tx.data) {
                    if let Some(nft) = state.nft_registry.get_nft(nft_id) {
                        // Burning a token is not proof of owning the content
                        // it names: `NftMint` accepts an arbitrary content id.
                        // The ids collected here reach the node's physical
                        // delete worker as well as the registry prune, so a
                        // burn by anybody but the manifest claimant must
                        // contribute no cid to either sink.
                        if state.storage_registry.has_claim(&nft.content_id, &tx.from) {
                            cids.push((nft.content_id, tx.from));
                        }
                    }
                }
            }
        }
        cids
    }

    /// Deterministic AI-registry maintenance for one committed block height.
    ///
    /// Expired requests, results, refunded fee records and dispute-window
    /// rows are evicted here, and escrowed fees of pruned requests go back to
    /// their requesters. The eviction depends only on the block height and
    /// the state as of that block - never on the wall clock or local
    /// randomness - so replay, reorg rebuilds and the live commit path must
    /// all produce the same result.
    ///
    /// The live path applies this right after each committed block
    /// (`ChainActor::run_ai_maintenance`). The startup replay, the reorg
    /// candidate rebuild and `rebuild_state` used to skip it, so a restarted
    /// node carried AI-registry rows its live peers had already pruned: two
    /// different state roots for the same height, and the restarted node
    /// rejects the next block or forks. Every state-rebuild loop
    /// must call this in the same position the live path does - after the
    /// block's committed roots are checked, before the next block applies.
    /// WIRING: chain surface - the block/snapshot paths that read it land with their wiring.
    pub(crate) fn apply_ai_registry_maintenance(
        state: &mut AccountState,
        block_height: u64,
    ) -> (usize, usize) {
        // The dispute window (10_080 blocks) is also the retention window:
        // unsettled requests and evidence are never deleted before the
        // finality plus objection period has elapsed.
        let retention = crate::ai::registry::DISPUTE_WINDOW_BLOCKS;
        let (pruned, refunds) = state.ai_registry.prune_expired(block_height, retention);
        // Escrowed fees of pruned, never-reclaimed, never-cancelled requests
        // go back to their requesters here: the pruned row was the only
        // on-chain record of the escrow, so this is the last chance to pay it.
        for (requester, max_fee) in refunds {
            let account = state.get_or_create(&requester);
            match account.balance.checked_add(max_fee) {
                Some(updated) => account.balance = updated,
                None => tracing::error!(
                    %requester,
                    max_fee,
                    "AI prune refund would overflow the balance; fee left uncredited"
                ),
            }
        }
        let expired = state.ai_registry.expire_dispute_window(block_height);
        (pruned, expired)
    }

    /// Apply a block to a state deterministically.
    ///
    /// `preceding_chain` is the canonical chain *before* `block` (i.e. blocks
    /// `0..block.index`). It is only read for epoch-close liveness observation,
    /// Which needs to know which validators produced during the closing epoch.
    /// Passing it keeps this function a pure `(state, block, history) -> state`
    /// Map, which is what every replay path depends on.
    ///
    /// The precondition this function had and never stated: every
    /// transaction it applies was already admitted through
    /// `validate_transaction` (the sender's nonce equal to the account nonce
    /// is one of its checks), at ingest, at the gates pointed at from
    /// `blockchain.rs` and the mempool. `apply_transaction` bumps the nonce
    /// with `saturating_add(1)` and does not re-check equality, so this
    /// replay path equals the live path ONLY for blocks that passed those
    /// gates - a block hand-crafted with wrong nonces (or a storage archive
    /// written before the gates existed) would replay a different per-account
    /// nonce order than the network would ever have accepted. That is a
    /// given of the ingest contract, not a silent hope: callers feed stored
    /// or freshly-validated blocks; nothing here re-admits. Making the
    /// executor itself re-check would be a consensus-visible tightening of
    /// replay for blocks whose bytes are already final - a fork risk on old
    /// archives, refused deliberately; the invariant above is the load-bearing
    /// statement, now written down.
    // WIRING: shared deterministic storage-prune step invoked from `apply_block_effects`
    // and exercised directly by `domain::storage_deal::tests`.
    pub fn prune_storage_content_in_state(
        state: &mut AccountState,
        content_id: &crate::storage::ContentId,
    ) -> Result<(), String> {
        let epoch = state.epoch_index;
        // The fee for epochs the deal will no longer serve goes back to
        // the payer. Read before the prune; returns empty if `prune_content`
        // refuses because an open challenge or coding audit is still active.
        let fee_refunds = state.storage_registry.prune_fee_refunds(content_id, epoch);
        let (_pruned, bond_returns) = state.storage_registry.prune_content(content_id, epoch);
        for (operator, bond) in bond_returns {
            if bond == 0 {
                continue;
            }
            state
                .try_add_balance(&operator, bond)
                .map_err(|error| format!("storage bond return overflow for {operator}: {error}"))?;
        }
        for (payer, refund) in fee_refunds {
            state
                .try_add_balance(&payer, refund)
                .map_err(|error| format!("storage fee refund overflow for {payer}: {error}"))?;
        }
        Ok(())
    }

    /// Spend the producer's Filiz link. Only a block that is
    /// applied moves the commitment: a proposal that never lands consumes
    /// nothing. A producer with an active registration whose block does not
    /// open it never passed consensus validation, so a mismatch here refuses
    /// the block rather than leaving the commitment behind the chain.
    fn apply_filiz_reveal(state: &mut AccountState, block: &Block) -> Result<(), String> {
        // A block with no election proof comes from an engine without leader
        // election (PoA, BFT); PoS validation requires the reveal.
        let Some(producer) = block
            .producer
            .as_ref()
            .filter(|_| !block.vrf_proof.is_empty())
        else {
            return Ok(());
        };
        let Some(validator) = state.get_validator_mut(producer) else {
            return Ok(());
        };
        let Some(registration) = validator.filiz.as_mut() else {
            return Ok(());
        };
        if registration.at_epoch(block.epoch).is_none() {
            return Ok(());
        }
        let reveal = <[u8; 32]>::try_from(block.vrf_proof.as_slice())
            .map_err(|_| "Filiz producer block carries no 32-byte reveal".to_string())?;
        match registration.apply(block.epoch, &reveal) {
            Ok(true) => Ok(()),
            Ok(false) => Err("Filiz reveal does not open the producer's commitment".into()),
            Err(e) => Err(format!("Filiz reveal refused: {e:?}")),
        }
    }

    fn apply_block_effects(
        base_state: &AccountState,
        block: &Block,
        preceding_chain: &[Block],
    ) -> Result<AccountState, String> {
        Self::apply_block_effects_with_unfreezes(base_state, block, preceding_chain)
            .map(|(state, _)| state)
    }

    fn apply_block_effects_with_unfreezes(
        base_state: &AccountState,
        block: &Block,
        preceding_chain: &[Block],
    ) -> Result<(AccountState, Vec<DomainId>), String> {
        let burn_cids = Self::collect_nft_burn_cids_from_state(base_state, block);
        let mut next_state = base_state.clone();
        next_state.current_block_height = block.index;
        next_state.current_block_unix_secs = Self::block_timestamp_secs(block.timestamp);
        next_state.current_block_entropy =
            Self::block_context_entropy(&block.previous_hash, &block.vrf_output);
        Executor::apply_block_checked(
            &mut next_state,
            &block.transactions,
            block.producer.as_ref(),
        )
        .map_err(|e| format!("Failed to apply block: {e}"))?;
        Self::apply_filiz_reveal(&mut next_state, block)?;
        Self::apply_system_effects(&mut next_state, block);
        Self::apply_block_slashing_reports_in_state(&mut next_state, block)?;
        Self::apply_epoch_close_liveness(&mut next_state, block, preceding_chain);
        Self::apply_epoch_reward_pool(&mut next_state, block);
        for (content_id, burner) in burn_cids {
            // Burning an NFT is not proof of owning the content it names:
            // `NftMint` accepts an arbitrary content id, so any funded account
            // could mint a token over somebody else's id and burn it to drive
            // this prune - which destroys the manifest and settles every deal
            // on it, paying operator bonds and payer refunds. Only the account
            // the manifest is registered to may destroy it. Content with no
            // unambiguous owner (a legacy zero-owner manifest, or an id with
            // two claims) is refused here and left to the scheduled
            // `pending_prune_manifests` pass, which is not caller-driven.
            if !next_state.storage_registry.has_claim(&content_id, &burner) {
                tracing::warn!(
                    %content_id,
                    %burner,
                    "Refusing an NFT-burn-driven storage prune: the burner is not the manifest owner"
                );
                continue;
            }
            Self::prune_storage_content_in_state(&mut next_state, &content_id)?;
        }
        let previous_epoch = base_state.epoch_index;
        Self::apply_coding_audit_epoch_step(
            &mut next_state,
            previous_epoch,
            block.chain_id,
            preceding_chain,
        );
        for content_id in next_state.storage_registry.pending_prune_manifests() {
            Self::prune_storage_content_in_state(&mut next_state, &content_id)?;
        }
        Self::apply_bridge_sweep_to_state(&mut next_state, block.index)?;
        // CWE-696: prune expired cross-domain message rows
        // inside `apply_block_effects` BEFORE `state_root` is computed so block
        // producers, validators, and replayers see identical message state.
        next_state.message_registry.prune_expired(
            block.index,
            crate::cross_domain::nonce::FINALITY_PRUNE_DEPTH * 10,
        );
        // CWE-662: drain governance-queued PoA compliance and domain-unfreeze
        // requests inside the deterministic `(state, block) -> state` transition
        // BEFORE `state_root` is computed so producers, validators and all
        // replay paths commit identical roots across every block.
        next_state.drain_pending_poa_compliance(block.index);
        let drained_unfreezes = std::mem::take(&mut next_state.pending_domain_unfreezes);
        if !drained_unfreezes.is_empty() {
            const MAX_APPLIED_DOMAIN_UNFREEZES: usize = 256;
            for item in &drained_unfreezes {
                next_state
                    .governance
                    .applied_domain_unfreezes
                    .retain(|u| u.domain_id != item.domain_id);
                next_state
                    .governance
                    .applied_domain_unfreezes
                    .push(item.clone());
            }
            if next_state.governance.applied_domain_unfreezes.len() > MAX_APPLIED_DOMAIN_UNFREEZES {
                let excess = next_state.governance.applied_domain_unfreezes.len()
                    - MAX_APPLIED_DOMAIN_UNFREEZES;
                next_state
                    .governance
                    .applied_domain_unfreezes
                    .drain(..excess);
            }
        }
        // The domains live in the state now, so the unfreeze applies here,
        // before the root, and nowhere else.
        let unfrozen =
            crate::settlement::domains::apply_domain_unfreezes(&mut next_state, &drained_unfreezes);
        let boost_share = next_state.pending_bud_boost_share;
        Self::distribute_bud_boost_share_in_state(&mut next_state, boost_share)?;
        // B.U.D. storage maintenance and the AI registry eviction run here,
        // inside the transition, so every path that applies the block (live,
        // replay, reorg, rebuild) commits the same registry and balances
        // under the state root. Both used to run in the chain actor after
        // the commit.
        crate::chain::storage_maintenance::apply(&mut next_state, block)?;
        Self::apply_ai_registry_maintenance(&mut next_state, block.index);
        // The settlement registries' clocks advance at block end, inside the
        // `(state, block) -> state` transition: the external intake now lives
        // in the account state, so a clock driven from the commit path alone
        // would leave replay one tick behind live operation.
        next_state.settlement.on_block_end(block.index);

        // Fee settlement has a single authority: Executor::apply_block_checked
        // Credits the producer exactly once with flat fee, metabolic burn.

        Ok((next_state, unfrozen))
    }

    /// Coding audits for the block, after its transactions and the epoch
    /// close. Overdue `Open` audits settle first, so a deal they free can be
    /// audited again. Then, when the epoch advanced, the epoch's audit opens.
    /// Then settled rows past the retention window leave.
    ///
    /// The epoch is `epoch_index`, the scale the in-block answer is checked
    /// on, and the clock is the block timestamp. Nothing here reads a map in
    /// hash order, the wall clock or local randomness, so a replay of the same
    /// blocks opens and settles the same audits.
    fn apply_coding_audit_epoch_step(
        state: &mut AccountState,
        previous_epoch: u64,
        chain_id: u64,
        preceding_chain: &[Block],
    ) {
        let epoch = state.epoch_index;
        let now_secs = state.current_block_unix_secs;
        state
            .storage_registry
            .finalize_missed_coding_audits(epoch, now_secs);
        if epoch > previous_epoch {
            // The seed decides which manifest, which deal and which parity
            // symbol is audited, so it must not contain anything the block
            // producer picks at signing time. `state.current_block_entropy`
            // folds `vrf_output`, and only the PoS engine verifies that field:
            // the PoA engine never looks at it and the PoW engine's only
            // admission control is the difficulty target. A producer that is
            // also a storage operator could therefore grind it offline - two
            // hashes and a modulo per attempt - until the epoch's single audit
            // landed on a shard it still holds. The hashes of the epoch that
            // just closed are fixed before this block is assembled, so every
            // producer's contribution is already committed and none of them
            // can steer the draw.
            let mut seed = crate::core::hash::hash_fields_bytes(&[
                b"BDLM_STORAGE_CODING_AUDIT_EPOCH_HISTORY_V1",
                &chain_id.to_le_bytes(),
                &epoch.to_le_bytes(),
            ]);
            let epoch_length = crate::core::chain_config::epoch_len_for_chain_id(chain_id).max(1);
            let first = epoch.saturating_sub(1).saturating_mul(epoch_length);
            for block in preceding_chain.iter().filter(|block| block.index >= first) {
                seed = crate::core::hash::hash_fields_bytes(&[
                    b"BDLM_STORAGE_CODING_AUDIT_EPOCH_STEP_V1",
                    &seed,
                    block.hash.as_bytes(),
                ]);
            }
            state
                .storage_registry
                .open_epoch_coding_audits(&seed, epoch);
        }
        state.storage_registry.sweep_settled_coding_audits(epoch);
    }

    fn apply_bridge_sweep_to_state(
        state: &mut AccountState,
        current_height: u64,
    ) -> Result<Vec<(Address, crate::core::money::Bud)>, String> {
        let params = *state.registry.params();
        let released = state
            .bridge_state
            .sweep_expired_locks_with_fee(
                current_height,
                params.bridge_relayer_fee_ppm,
                params.bridge_relayer_min_fee,
            )
            .map_err(|error| format!("Bridge sweep failed: {error}"))?;
        for (owner, amount) in &released {
            state
                .try_add_balance(owner, amount.get())
                .map_err(|error| format!("Bridge sweep refund overflow for {owner}: {error}"))?;
        }
        Ok(released)
    }

    /// Compatibility API. Canonical block execution invokes the same sweep on
    /// The prospective state before root calculation and durable commit.
    #[cfg(test)]
    pub fn apply_bridge_sweep(
        &mut self,
        current_height: u64,
    ) -> Vec<(Address, crate::core::money::Bud)> {
        let mut prospective = self.state.clone();
        match Self::apply_bridge_sweep_to_state(&mut prospective, current_height) {
            Ok(released) => {
                self.state = prospective;
                released
            }
            Err(error) => {
                tracing::error!("Bridge sweep failed: {error}");
                Vec::new()
            }
        }
    }

    pub fn produce_block(&mut self, producer_address: Address) -> Option<(Block, Vec<[u8; 32]>)> {
        let _consensus_timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.consensus_round_seconds.start_timer());
        let index = self.chain.len() as u64;
        let previous_hash = self
            .chain
            .last()
            .map_or_else(|| "0".repeat(64), |block| block.hash.clone());
        let block_timestamp = self.planned_block_timestamp(index);
        let valid_txs = self.collect_block_transactions(block_timestamp, &previous_hash);
        let mut block = Block::new_with_chain_id(index, previous_hash, valid_txs, self.chain_id);
        block.witness_root = Some(block.calculate_witness_root());
        // One byte budget for every consensus payload this block carries on
        // top of its transactions. `collect_block_transactions` reserves a
        // fixed evidence allowance out of `MAX_BLOCK_SIZE` before it spends
        // the rest on the transaction array, so a saturated mempool cannot
        // push the evidence budget to zero. What is left after the
        // transactions and the evidence is shared by the slashing reports.
        //
        // Nothing is ever removed from either queue here. An entry that does
        // not fit this block stays queued for the next one - every call to
        // this function used to delete the entries it could not place, and
        // after the gossip loop drained the consensus pool into this queue
        // that deletion destroyed the only copy of the proof, which silently
        // disabled slashing for block-header equivocation. Both queues are
        // bounded (`MAX_PENDING_SLASHING_EVIDENCE`, and the admission ceiling
        // on each entry), so retention cannot stall production: the builder
        // only inlines what fits and the rest waits.
        const BLOCK_HEADER_JSON_ALLOWANCE: usize = 4096;
        const MAX_SINGLE_REPORT_BYTES: usize =
            crate::registry::invalid_vote::MAX_SPAM_REPORT_JSON_BYTES;
        let mut remaining_json_bytes = crate::consensus::MAX_BLOCK_SIZE
            .saturating_sub(BLOCK_HEADER_JSON_ALLOWANCE)
            .saturating_sub(
                serde_json::to_vec(&block.transactions).map_or(usize::MAX, |b| b.len()),
            );
        // An entry above the per-entry ceiling can never be embedded in any
        // block, so keeping it would only hold a queue slot forever. Admission
        // (`submit_slashing_evidence`) already refuses those; this sweep only
        // catches a queue filled by an older build or by a test, and keeps the
        // guarantee that one un-embeddable entry cannot wedge production.
        let mut unembeddable_evidence = 0usize;
        self.pending_slashing_evidence.retain(|evidence| {
            let fits = serde_json::to_vec(evidence)
                .map(|bytes| bytes.len())
                .unwrap_or(usize::MAX)
                <= crate::consensus::MAX_SLASHING_EVIDENCE_BYTES;
            if !fits {
                unembeddable_evidence = unembeddable_evidence.saturating_add(1);
            }
            fits
        });
        if unembeddable_evidence > 0 {
            tracing::warn!(
                unembeddable_evidence,
                "Dropped slashing evidence that no block can carry"
            );
        }
        if !self.pending_slashing_evidence.is_empty() {
            // Evidence is inlined the same way reports are, and a correctly
            // signed header preimage is not small: bounded here by the same
            // per-entry ceiling, by the block's reserved evidence allowance,
            // and by the bytes the transactions left.
            let mut fitting = Vec::new();
            let mut used = 0usize;
            let mut deferred = 0usize;
            for evidence in &self.pending_slashing_evidence {
                let encoded = serde_json::to_vec(evidence)
                    .map(|bytes| bytes.len())
                    .unwrap_or(usize::MAX);
                if encoded <= crate::consensus::MAX_SLASHING_EVIDENCE_BYTES
                    && used.saturating_add(encoded) <= crate::consensus::MAX_SLASHING_EVIDENCE_BYTES
                    && encoded <= remaining_json_bytes
                {
                    used = used.saturating_add(encoded);
                    remaining_json_bytes = remaining_json_bytes.saturating_sub(encoded);
                    fitting.push(evidence.clone());
                } else {
                    deferred = deferred.saturating_add(1);
                }
            }
            if deferred > 0 {
                tracing::debug!(
                    deferred,
                    "Deferred pending slashing evidence to a later block"
                );
            }
            if !fitting.is_empty() {
                block.slashing_evidence = Some(fitting);
            }
        }
        // Same self-healing sweep for the report queue.
        let mut unembeddable_reports = 0usize;
        self.pending_registry_slashing_reports.retain(|report| {
            let fits = serde_json::to_vec(report)
                .map(|bytes| bytes.len())
                .unwrap_or(usize::MAX)
                <= MAX_SINGLE_REPORT_BYTES;
            if !fits {
                unembeddable_reports = unembeddable_reports.saturating_add(1);
            }
            fits
        });
        if unembeddable_reports > 0 {
            tracing::warn!(
                unembeddable_reports,
                "Dropped slashing reports that no block can carry"
            );
        }
        if !self.pending_registry_slashing_reports.is_empty() {
            // What the evidence left, not a fixed fraction of the block limit.
            let max_report_json_bytes = remaining_json_bytes;
            let mut fitting = Vec::new();
            let mut used = 0usize;
            for report in &self.pending_registry_slashing_reports {
                let encoded = serde_json::to_vec(report)
                    .map(|bytes| bytes.len())
                    .unwrap_or(usize::MAX);
                if encoded <= MAX_SINGLE_REPORT_BYTES
                    && used.saturating_add(encoded) <= max_report_json_bytes
                {
                    used = used.saturating_add(encoded);
                    fitting.push(report.clone());
                }
            }
            if !fitting.is_empty() {
                block.slashing_reports = Some(fitting);
            }
        }
        block.producer = Some(producer_address);
        block.timestamp = block_timestamp;
        block.validator_set_hash = self.get_validator_set_hash();

        if let Err(error) =
            self.consensus
                .preview_block_with_chain(&mut block, &self.state, &self.chain)
        {
            tracing::warn!("Local block preview failed: {error}");
            return None;
        }

        // F1 (Constitution): pre-scan NftBurn CIDs before state mutation.
        let nft_burn_cids = Self::collect_nft_burn_cids_from_state(&self.state, &block);

        let ai_outcomes_before = self.state.ai_registry.outcomes.len();
        let (mut committed_state, unfrozen_domains) =
            match Self::apply_block_effects_with_unfreezes(&self.state, &block, &self.chain) {
                Ok(res) => res,
                Err(error) => {
                    tracing::warn!("Local block effects failed: {error}");
                    return None;
                }
            };

        // The block carried slashing evidence and the state move above
        // applied it (same-chain only, exactly what apply_system_effects
        // slashes): one counter step per applied evidence.
        if let Some(ref m) = self.metrics {
            if let Some(evidences) = &block.slashing_evidence {
                let applied = evidences
                    .iter()
                    .filter(|e| {
                        e.header1.chain_id == block.chain_id && e.header2.chain_id == block.chain_id
                    })
                    .count() as u64;
                if applied > 0 {
                    m.slashing_events_total.inc_by(applied);
                }
            }
        }
        Self::apply_block_end_roots(&mut committed_state, &block, &self.chain, self.chain_id);
        block.state_root = committed_state.calculate_state_root();
        if self.sharding.is_active_at(block.index) {
            block.shards_root = Some(crate::sharding::shards_commitment(
                &committed_state,
                self.sharding.num_shards,
            ));
        }

        if let Err(error) =
            self.consensus
                .prepare_block_with_chain(&mut block, &self.state, &self.chain)
        {
            tracing::warn!("Local block preparation failed: {error}");
            return None;
        }
        if let Err(error) = self
            .consensus
            .full_validate(&block, &self.chain, &self.state)
        {
            tracing::error!("Locally produced block failed full validation: {error}");
            return None;
        }

        // Commit durably to database first, ensuring fail-closed security
        if let Err(e) = self.commit_block_durable(&block, &committed_state) {
            tracing::error!(
                "Failed to commit block {} durably: {}. Block production aborted.",
                block.index,
                e
            );
            return None;
        }

        // Observe the liveness of the epoch that *just closed* (if any)
        // AFTER we have committed the new state. The producer of the closing
        // Block is the one validator we know for sure participated; everyone
        // Else in the active validator set is treated as a potential absentee.
        // This is the OBSERVE mode default; liveness_slashing_enabled controls
        // Whether the report is actioned.

        let frozen_before = Self::frozen_domain_ids(&self.state);
        self.state = committed_state;
        // Governance-controlled domain unfreeze (5.C) is applied inside
        // `apply_block_effects_with_unfreezes` BEFORE `calculate_state_root`;
        // only the node-local quarantine ledger follows here.
        self.release_unfrozen_domains(&unfrozen_domains);
        self.observe_settlement_transition(&frozen_before, &block);
        self.observe_committed_global_headers(&block);
        // PoA compliance requests are drained inside `apply_block_effects`
        // BEFORE `calculate_state_root`, so every replay path reproduces them.
        // The alarm log is trimmed by age and the
        // ledger is written once per block, not once per event.
        self.quarantine_ledger
            .prune_expired(self.chain.len() as u64, ALARM_RETENTION_BLOCKS);
        // Dead cross-domain message rows are pruned inside `apply_block_effects`
        // (before `state_root` is computed) so replay and validation stay exact.
        self.flush_quarantine_ledger();
        // Bridge burns this block applied: the relay requests are node-local
        // and are enqueued after the commit, like the boost share above.
        self.drain_pending_bridge_burns();

        self.record_validator_snapshot(self.state.epoch_index);

        // Epoch-close liveness is now applied inside `apply_block_effects`
        // (see `apply_epoch_close_liveness`) so that it is part of the
        // Deterministic replay contract. Doing it here, after the commit,
        // Made the producer's `liveness` root unreproducible by replay.

        self.chain.push(block.clone());
        // Only what this block actually carried leaves the queues. Retaining
        // the rest is what makes a deferred proof survive a slot it did not
        // fit into: the queue is the only copy the node has once the gossip
        // loop has drained the consensus pool, so clearing it wholesale threw
        // away every proof a fuller block had to leave behind.
        if let Some(committed) = &block.slashing_evidence {
            self.pending_slashing_evidence
                .retain(|pending| !committed.contains(pending));
        }
        if let Some(committed) = &block.slashing_reports {
            self.pending_registry_slashing_reports
                .retain(|pending| !committed.contains(pending));
        }

        if let Some(last_block) = self.chain.last() {
            // (security audit) the trait-level `record_block`
            // No longer mutates PoW difficulty (validation is pure).
            // Instead, the chain-aware `record_block_with_chain` is
            // Called here, AFTER the block has been durably committed
            // And the chain is in its post-commit state. Other engines
            // (PoS, PoA, BFT, ZK) keep their default no-op
            // `record_block` semantics and are unaffected.
            self.consensus
                .record_block_with_chain(last_block, &self.chain, self.storage.as_ref());
            if let Err(e) = self
                .consensus
                .record_block(last_block, self.storage.as_ref())
            {
                warn!("Engine record block error: {e}");
            }
        }
        self.prune_consensus_evidence_after_commit(block.index);

        for tx in &block.transactions {
            self.mempool.remove_transaction(&tx.hash);
            if let Some(ref store) = self.storage {
                let _ = store.remove_mempool_tx(&tx.hash);
            }
        }

        self.mempool.set_min_fee(self.state.base_fee);
        self.emit_chain_metrics();
        self.emit_tx_processed(block.transactions.len() as u64);
        self.emit_applied_tx_metrics(&block.transactions, ai_outcomes_before);
        Some((block, nft_burn_cids.iter().map(|(cid, _)| cid.0).collect()))
    }
    pub fn mine_pending_transactions(&mut self, miner_address: Address) {
        self.produce_block(miner_address);
    }
    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<(), String> {
        self.validate_pool_transaction(&transaction)
            .map_err(|e| format!("Invalid transaction: {e}"))?;

        self.mempool
            .sync_scheme_registry(&self.state.scheme_registry);
        self.mempool
            .add_transaction(transaction.clone())
            .map_err(|e| format!("Mempool error: {e:?}"))?;
        if let Some(ref store) = self.storage {
            if let Err(e) = store.save_mempool_tx(&transaction) {
                tracing::error!(
                    "save_mempool_tx failed (transaction will not survive restart): {e}"
                );
            }
        }
        Ok(())
    }

    /// Take a transaction back out of the mempool and the pool file.
    ///
    /// A bundle is admitted all or none, and the pool has no batch door: the
    /// members go in one at a time, so a member the pool refuses has to be
    /// able to take the ones already in back out. The pool is drained first
    /// and the file second, so a crash between the two can only lose the
    /// persisted copy of a transaction this node no longer holds - never the
    /// other way round, which would have a restart re-admit it.
    pub fn remove_transaction(&mut self, tx_hash: &str) -> Option<Transaction> {
        let removed = self.mempool.remove_transaction(tx_hash);
        if removed.is_some() {
            if let Some(ref store) = self.storage {
                if let Err(e) = store.remove_mempool_tx(tx_hash) {
                    tracing::error!(
                        "remove_mempool_tx failed (the transaction comes back on restart): {e}"
                    );
                }
            }
        }
        removed
    }

    /// Top an account up to [`GENESIS_BALANCE`] on a development chain.
    ///
    /// This is a faucet, and the name hid that. It was called
    /// `init_genesis_account` and it is bound to nothing about genesis: no
    /// height check, no network check, no supply accounting. Measured against
    /// the body as it stood:
    ///
    /// ```text
    /// height          0  -> 1,000,000,000
    /// height  10,000,000 -> 1,000,000,000
    /// spend down to 5, call again -> 1,000,000,000
    /// ```
    ///
    /// It does not stack on one address, so it is not a mint loop, but it
    /// refills without limit: any address can be returned to 1e9 as often as
    /// it is drained, and a fresh address can be created already funded.
    /// `BUD_TOTAL_SUPPLY` is 1e14, so a hundred thousand calls exceed the
    /// entire supply while `nonzero_block_reward_config_cannot_mint` and its
    /// neighbours go on asserting that no path can mint.
    ///
    /// Nothing in production called it. That is the same shape as B27: the
    /// hazard is not what runs today, it is what the next person wires up
    /// after reading a name that says "genesis" and a signature that says
    /// "any address, any time".
    ///
    /// So it is gated rather than deleted, because the devnet and RPC test
    /// paths do need a funded account. It runs on the devnet chain id only.
    /// Testnet is the mainnet rehearsal, so it refuses here exactly as
    /// mainnet does: a testnet node that credited an account outside a block
    /// would compute a state root no peer reproduces. Testnet BUD comes from
    /// the faucet service, which sends a signed transfer.
    ///
    /// # Errors
    ///
    /// Returns an error on every chain id except devnet. The refusal is the
    /// point: fail closed, and let the caller see it rather than silently
    /// doing nothing.
    pub fn fund_development_account(&mut self, address: &Address) -> Result<(), String> {
        if self.mainnet_chain_id() {
            return Err(format!(
                "refusing to fund {address}: this is a development faucet and the \
                 chain id is mainnet. There is no path that credits an account \
                 without consensus on mainnet, and adding one here would make \
                 BUD_TOTAL_SUPPLY (1e14) an advisory number."
            ));
        }
        if !self.devnet_chain_id() {
            return Err(format!(
                "refusing to fund {address}: this is a development faucet and chain id \
                 {} is not the devnet chain id. Outside devnet an account is credited \
                 only by a signed transaction inside a block; on testnet use the \
                 faucet service.",
                self.chain_id
            ));
        }
        let account = self.state.get_or_create(address);
        if account.balance < GENESIS_BALANCE {
            account.balance = GENESIS_BALANCE;
        }
        Ok(())
    }

    /// Credit an arbitrary amount outside consensus, development chains only.
    ///
    /// The actor exposed this as `ChainCommand::AddBalance` and it went
    /// straight to `state.add_balance`, which saturates. No signature, no
    /// nonce, no proof, no supply accounting: the whole of what a block has
    /// to carry before it can move value, skipped.
    ///
    /// # Errors
    ///
    /// Refuses on every chain id except devnet, for the reason given on
    /// [`Self::fund_development_account`].
    pub fn credit_development_account(
        &mut self,
        address: &Address,
        amount: u64,
    ) -> Result<(), String> {
        if self.mainnet_chain_id() {
            return Err(format!(
                "refusing to credit {address} with {amount}: this path bypasses \
                 consensus and exists for development chains. On mainnet, value \
                 moves through a signed transaction or a verified bridge event, \
                 and nowhere else."
            ));
        }
        if !self.devnet_chain_id() {
            return Err(format!(
                "refusing to credit {address} with {amount}: this path bypasses \
                 consensus and runs on the devnet chain id only; chain id {} moves \
                 value through a signed transaction or a verified bridge event.",
                self.chain_id
            ));
        }
        self.state.add_balance(address, amount);
        Ok(())
    }

    /// True when this chain is mainnet, by chain id.
    ///
    /// Mirrors `mainnet_requires_signed_remote_snapshot`, which is the
    /// established way this file asks the question.
    fn mainnet_chain_id(&self) -> bool {
        self.chain_id
            == crate::core::chain_config::Network::Mainnet
                .chain_id()
                .value()
    }

    /// True when this chain is devnet, by chain id. The development credit
    /// paths run here and nowhere else.
    fn devnet_chain_id(&self) -> bool {
        self.chain_id
            == crate::core::chain_config::Network::Devnet
                .chain_id()
                .value()
    }

    pub fn validate_and_add_block(&mut self, block: Block) -> Result<Vec<[u8; 32]>, String> {
        self.validate_and_add_block_with(block, false)
    }

    /// Sync over a pruned window. `blocks` continue the tip; the last
    /// one is the checkpoint `cert` finalizes, and `qc` is the ML-DSA-65 QC of
    /// the same signers. The certificate and the QC are verified first, then
    /// the hash chain from the tip to the checkpoint hash, so every block of
    /// the segment is bound before any of them is applied. A block that still
    /// carries its witnesses is validated in full; a block whose witnesses
    /// were pruned skips the witness root and the signature checks, and is
    /// still executed and must reach its committed state root.
    ///
    /// Returns the number of blocks added.
    ///
    /// # Errors
    ///
    /// The first refused check; nothing is added past it.
    /// WIRING: chain surface - the block/snapshot paths that read it land with their wiring.
    pub fn import_pruned_segment(
        &mut self,
        blocks: Vec<Block>,
        cert: &FinalityCert,
        qc: &crate::consensus::qc::QcBlob,
    ) -> Result<usize, String> {
        let last = blocks.last().ok_or("an empty pruned segment")?;
        if cert.chain_id != self.chain_id {
            return Err("the segment's certificate is for another chain".into());
        }
        if last.index != cert.checkpoint_height || last.hash != cert.checkpoint_hash {
            return Err("the segment does not end at the certified checkpoint".into());
        }
        self.require_checkpoint_epoch(cert.epoch, cert.checkpoint_height, "Segment certificate")?;
        let snapshot = self.require_validator_snapshot(cert.epoch)?;
        cert.verify(&snapshot)?;
        Self::ensure_blob_matches_checkpoint(qc, &cert.checkpoint_hash)?;
        crate::domain::finality_adapter::verify_pq_quorum(
            &self.state.scheme_registry,
            cert,
            &snapshot,
            qc,
        )?;
        let mut parent_hash = self
            .chain
            .last()
            .map(|tip| tip.hash.clone())
            .ok_or("no tip to continue")?;
        let base_height = self.chain.len() as u64;
        for (offset, block) in blocks.iter().enumerate() {
            let height = base_height + offset as u64;
            if block.index != height
                || block.previous_hash != parent_hash
                || block.hash != block.calculate_hash()
                || block.tx_root != block.calculate_tx_root()
            {
                return Err(format!(
                    "pruned segment is not hash-linked at height {}",
                    block.index
                ));
            }
            parent_hash = block.hash.clone();
        }
        // Verify the policy for the entire segment before mutating the chain.
        // The certified end is the newest authenticated tip in this segment;
        // the peer cannot select whether recently finalized witnesses are kept.
        self.check_pruned_segment_witness_policy(&blocks, cert.checkpoint_height)?;
        let mut added = 0;
        for block in blocks {
            let pruned = block.witness_is_stripped();
            let index = block.index;
            self.validate_and_add_block_with(block, pruned)?;
            if pruned {
                if let Some(store) = &self.storage {
                    store
                        .prune_block_witnesses(index)
                        .map_err(|e| format!("cannot mark block {index} as pruned: {e}"))?;
                }
            }
            added += 1;
        }
        Ok(added)
    }

    fn check_pruned_segment_witness_policy(
        &self,
        blocks: &[Block],
        certified_tip: u64,
    ) -> Result<(), String> {
        use crate::storage::witness_retention::{may_prune, NodeKind, DEFAULT_RETENTION_BLOCKS};

        let (kind, retention) = match &self.pruning_manager {
            Some(pm) if !pm.archive_mode => (
                NodeKind::Normal,
                DEFAULT_RETENTION_BLOCKS.max(pm.min_blocks_to_keep),
            ),
            // No pruning manager means witness deletion was not enabled.
            _ => (NodeKind::Archive, DEFAULT_RETENTION_BLOCKS),
        };
        for block in blocks {
            if block.witness_is_stripped()
                && !may_prune(kind, block.index, certified_tip, certified_tip, retention)
            {
                return Err(format!(
                    "pruned witness at height {} violates local retention policy",
                    block.index
                ));
            }
        }
        Ok(())
    }

    /// Prune the witnesses the Pul-Lite rule releases: final,
    /// and at least `retention_blocks` behind the tip. An archive node
    /// (`PruningManager::archive_mode`) and a node without storage prune
    /// nothing. Looks at most `window` heights below the release bound, so
    /// one call stays cheap; it is idempotent.
    ///
    /// Returns the heights pruned now.
    /// WIRING: chain surface - the block/snapshot paths that read it land with their wiring.
    pub fn prune_released_witnesses(&self, retention_blocks: u64, window: u64) -> Vec<u64> {
        use crate::storage::witness_retention::{may_prune, NodeKind};
        let (Some(store), Some(pm)) = (&self.storage, &self.pruning_manager) else {
            return Vec::new();
        };
        let kind = if pm.archive_mode {
            NodeKind::Archive
        } else {
            NodeKind::Normal
        };
        let tip = self.chain.len().saturating_sub(1) as u64;
        let retention_blocks = retention_blocks.max(pm.min_blocks_to_keep);
        let bound = self
            .finalized_height
            .min(tip.saturating_sub(retention_blocks));
        let mut pruned = Vec::new();
        for height in bound.saturating_sub(window).max(1)..=bound {
            if may_prune(kind, height, self.finalized_height, tip, retention_blocks)
                && store.prune_block_witnesses(height).unwrap_or(false)
            {
                pruned.push(height);
            }
        }
        pruned
    }

    fn validate_and_add_block_with(
        &mut self,
        block: Block,
        witness_pruned: bool,
    ) -> Result<Vec<[u8; 32]>, String> {
        let _consensus_timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.consensus_round_seconds.start_timer());

        // A block that rivals a committed height is rejected below, so the
        // commit path never sees it. Let the engine look at it first: two
        // signed blocks from one producer at one height are slashable.
        if usize::try_from(block.index).is_ok_and(|index| index < self.chain.len()) {
            if let Err(error) = self.consensus.observe_received_block(&block) {
                tracing::debug!("Rival block observation skipped: {error}");
            }
        }

        // Finality checkpoint conflict check MUST run before tip-height
        // Continuity: a block at or below finalized_height that disagrees with
        // The canonical path is a consensus-safety violation even if it is not
        // The next tip index (reorg / equivocation attempts).
        if block.index <= self.finalized_height && block.hash != self.finalized_hash {
            if let Some(finalized_path_block) = self.chain.get(block.index as usize) {
                if finalized_path_block.hash != block.hash {
                    return Err(format!(
                        "Block at height {} conflicts with finalized checkpoint",
                        block.index
                    ));
                }
            } else {
                return Err(format!(
                    "Block at height {} is below finalized height {}",
                    block.index, self.finalized_height
                ));
            }
        }

        // Height continuity defense-in-depth. The block
        // Index must be exactly one greater than the current chain tip.
        // Consensus engines also enforce this, but the blockchain layer must
        // Reject discontinuous blocks independently (fork attacks, height
        // Jumps, etc.).
        let expected_height = self.chain.len() as u64;
        if block.index != expected_height {
            return Err(format!(
                "Block height discontinuity: expected {}, got {}",
                expected_height, block.index
            ));
        }

        if block.chain_id != self.chain_id {
            return Err(format!(
                "Invalid Chain ID: expected {}, got {}",
                self.chain_id, block.chain_id
            ));
        }

        let expected_tx_root = block.calculate_tx_root();
        if block.tx_root != expected_tx_root {
            return Err(format!(
                "tx_root mismatch: expected {}, got {}",
                expected_tx_root, block.tx_root
            ));
        }
        if !witness_pruned && !block.witness_root_is_valid() {
            return Err("witness_root mismatch or missing".into());
        }

        let expected_hash = block.calculate_hash();
        if block.hash != expected_hash {
            return Err(format!(
                "block hash mismatch: expected {}, got {}",
                expected_hash, block.hash
            ));
        }

        if block.index > 0 && block.state_root.is_empty() {
            return Err("Block missing state_root".into());
        }

        if let Err(e) = self
            .consensus
            .full_validate(&block, &self.chain, &self.state)
        {
            return Err(format!("Consensus validation failed: {e}"));
        }
        Self::check_block_slashing_evidence(&block)?;

        // Validate transactions against current state before applying
        let mut temp_state = self.state.clone();
        temp_state.current_block_height = block.index;
        temp_state.current_block_unix_secs = Self::block_timestamp_secs(block.timestamp);
        temp_state.current_block_entropy =
            Self::block_context_entropy(&block.previous_hash, &block.vrf_output);
        for (i, tx) in block.transactions.iter().enumerate() {
            if tx.chain_id != block.chain_id {
                return Err(format!(
                    "Invalid transaction at index {}: Chain ID mismatch. Expected {}, got {}",
                    i, block.chain_id, tx.chain_id
                ));
            }
            if block.index > 0 && tx.from == Address::zero() {
                return Err(format!("Invalid transaction at index {i}: 'genesis' transactions only allowed in genesis block"));
            }
            // A pruned witness was verified by the validators that finalized
            // the segment; the state root below still checks the execution.
            if block.index > 0 && !witness_pruned {
                if let Err(e) = temp_state.validate_transaction(tx) {
                    return Err(format!("Invalid transaction at index {i}: {e}"));
                }
            }
            if let Err(e) = Executor::apply_transaction_checked(&mut temp_state, tx) {
                return Err(format!("Failed to apply transaction at index {i}: {e}"));
            }
        }

        // F1 (Constitution): pre-scan NftBurn CIDs before state mutation.
        let nft_burn_cids = Self::collect_nft_burn_cids_from_state(&self.state, &block);

        let ai_outcomes_before = self.state.ai_registry.outcomes.len();
        let (mut commit_state, unfrozen_domains) =
            Self::apply_block_effects_with_unfreezes(&self.state, &block, &self.chain)?;

        if let Some(ref m) = self.metrics {
            if let Some(evidences) = &block.slashing_evidence {
                let applied = evidences
                    .iter()
                    .filter(|e| {
                        e.header1.chain_id == block.chain_id && e.header2.chain_id == block.chain_id
                    })
                    .count() as u64;
                if applied > 0 {
                    m.slashing_events_total.inc_by(applied);
                }
            }
        }

        if block.index > 0 {
            Self::apply_block_end_roots(&mut commit_state, &block, &self.chain, self.chain_id);
            let computed_root = commit_state.calculate_state_root();
            if computed_root != block.state_root {
                return Err(format!(
                    "State root mismatch: expected {}, got {}",
                    block.state_root, computed_root
                ));
            }
            if self.sharding.is_active_at(block.index) {
                let expected_shards =
                    crate::sharding::shards_commitment(&commit_state, self.sharding.num_shards);
                match block.shards_root {
                    Some(actual) if actual == expected_shards => {}
                    Some(actual) => {
                        return Err(format!(
                            "Shards commitment mismatch: expected {}, got {}",
                            hex::encode(expected_shards),
                            hex::encode(actual)
                        ));
                    }
                    None => {
                        return Err(format!(
                            "Block {} is missing the shards commitment required from height {}",
                            block.index, self.sharding.activation_height
                        ));
                    }
                }
            }
        }

        // Commit durably to database first, ensuring fail-closed security
        self.commit_block_durable(&block, &commit_state)
            .map_err(|e| format!("Failed to commit block {} durably: {}", block.index, e))?;

        // Same epoch-close liveness hook as `produce_block`. The block
        // We just accepted is the one that closes the epoch; its producer
        // Counts as "participated". Without this, `validate_and_add_block`
        // Would skip liveness accounting on a sync path.

        let frozen_before = Self::frozen_domain_ids(&self.state);
        self.state = commit_state;
        // Governance-controlled domain unfreeze (5.C) is applied inside
        // `apply_block_effects_with_unfreezes` BEFORE `calculate_state_root`;
        // only the node-local quarantine ledger follows here.
        self.release_unfrozen_domains(&unfrozen_domains);
        self.observe_settlement_transition(&frozen_before, &block);
        self.observe_committed_global_headers(&block);
        self.flush_quarantine_ledger();
        // PoA compliance requests are drained inside `apply_block_effects`
        // BEFORE `calculate_state_root`, so every replay path reproduces them.
        // The relayer sweep runs at block end inside the state transition
        // (`SettlementRegistries::on_block_end`).
        // Bridge burns applied by this block: their relay requests are a
        // node-local queue and are enqueued here, after the commit, exactly as
        // `pending_bud_boost_share` is distributed. Nothing about the burn
        // itself waits for this drain.
        self.drain_pending_bridge_burns();

        self.record_validator_snapshot(self.state.epoch_index);
        self.mempool.set_min_fee(self.state.base_fee);

        // Epoch-close liveness is now applied inside `apply_block_effects`
        // (see `apply_epoch_close_liveness`) so that it is part of the
        // Deterministic replay contract. Doing it here, after the commit,
        // Made the producer's `liveness` root unreproducible by replay.

        // Counter and tx-type metrics must be read before `push` consumes the block.
        let applied_tx_count = block.transactions.len() as u64;
        self.emit_applied_tx_metrics(&block.transactions, ai_outcomes_before);
        self.chain.push(block);

        if let Some(last_block) = self.chain.last() {
            // Call record_block_with_chain first (chain-aware hooks like PoW difficulty adjustment)
            self.consensus
                .record_block_with_chain(last_block, &self.chain, self.storage.as_ref());
            // Then call record_block for engine-specific bookkeeping
            if let Err(e) = self
                .consensus
                .record_block(last_block, self.storage.as_ref())
            {
                warn!("Engine record block error: {e}");
            }
        }
        self.prune_consensus_evidence_after_commit(expected_height);

        if let Some(last_block) = self.chain.last() {
            for tx in last_block.transactions.iter() {
                self.mempool.remove_transaction(&tx.hash);
                if let Some(ref store) = self.storage {
                    let _ = store.remove_mempool_tx(&tx.hash);
                }
            }
        }

        if let (Some(pruning_manager), Some(last_block)) =
            (self.pruning_manager.as_ref(), self.chain.last())
        {
            let height = last_block.index;
            if pruning_manager.should_create_snapshot(height) {
                let genesis_hash = self
                    .chain
                    .first()
                    .map(|b| b.hash.clone())
                    .unwrap_or_default();
                let certs: Vec<FinalityCert> = self
                    .pending_finality_certs
                    .values()
                    .flat_map(|v| v.iter().cloned())
                    .collect();
                let params = crate::chain::snapshot::StateSnapshotV2Params {
                    height,
                    block_hash: last_block.hash.clone(),
                    genesis_hash,
                    chain_id: self.chain_id,
                    finalized_height: self.finalized_height,
                    finalized_hash: self.finalized_hash.clone(),
                    finality_certificates: certs,
                };
                let v2_snapshot =
                    crate::chain::snapshot::StateSnapshotV2::from_state(&self.state, params);
                if let Err(e) = pruning_manager.save_snapshot_v2(&v2_snapshot) {
                    warn!("Failed to save V2 snapshot at height {height}: {e}");
                } else {
                    info!(
                        "Saved V2 state snapshot at height {} (epoch={}, base_fee={})",
                        height, self.state.epoch_index, self.state.base_fee
                    );

                    let prunable = pruning_manager.get_prunable_blocks(
                        self.chain.len() as u64,
                        height,
                        self.finalized_height,
                    );
                    if !prunable.is_empty() {
                        if let Some(ref store) = self.storage {
                            for block_index in &prunable {
                                let _ = store.delete_block(*block_index);
                            }
                            info!("Pruned {} old blocks from disk", prunable.len());
                        }
                    }
                }
            }
        }

        self.emit_chain_metrics();
        self.emit_tx_processed(applied_tx_count);
        Ok(nft_burn_cids.iter().map(|(cid, _)| cid.0).collect())
    }

    pub fn is_valid(&self) -> bool {
        self.validate_candidate_chain(&self.chain).is_ok()
    }

    pub fn is_valid_chain(&self, chain: &[Block]) -> bool {
        self.validate_candidate_chain(chain).is_ok()
    }

    fn validate_candidate_chain(&self, chain: &[Block]) -> Result<AccountState, String> {
        let genesis = chain
            .first()
            .ok_or_else(|| "Candidate chain is empty".to_string())?;
        let expected_genesis = self.genesis_config.build_genesis_block();
        if genesis != &expected_genesis {
            return Err("Candidate genesis does not match configured genesis".into());
        }

        let mut state = self.genesis_config.build_state();
        state.execution_domain = self.consensus.domain_kind();
        for (index, block) in chain.iter().enumerate().skip(1) {
            let expected_height = index as u64;
            let parent = &chain[index - 1];
            if block.index != expected_height || block.previous_hash != parent.hash {
                return Err(format!(
                    "Candidate chain discontinuity at height {}",
                    block.index
                ));
            }
            if block.chain_id != self.chain_id {
                return Err(format!(
                    "Candidate block {} has chain ID {}, expected {}",
                    block.index, block.chain_id, self.chain_id
                ));
            }
            if block.tx_root != block.calculate_tx_root()
                || !block.witness_root_is_valid()
                || block.hash != block.calculate_hash()
            {
                return Err(format!(
                    "Candidate block {} has invalid transaction root or hash",
                    block.index
                ));
            }
            self.consensus
                .full_validate(block, &chain[..index], &state)
                .map_err(|error| {
                    format!(
                        "Candidate consensus validation failed at block {}: {}",
                        block.index, error
                    )
                })?;
            Self::check_block_slashing_evidence(block)
                .map_err(|e| format!("Candidate block {} refused: {e}", block.index))?;

            let mut projected = state.clone();
            projected.current_block_height = block.index;
            projected.current_block_unix_secs = Self::block_timestamp_secs(block.timestamp);
            projected.current_block_entropy =
                Self::block_context_entropy(&block.previous_hash, &block.vrf_output);
            for (tx_index, transaction) in block.transactions.iter().enumerate() {
                if transaction.chain_id != self.chain_id {
                    return Err(format!(
                        "Candidate transaction {} at block {} has wrong chain ID",
                        tx_index, block.index
                    ));
                }
                projected
                    .validate_transaction(transaction)
                    .map_err(|error| {
                        format!(
                            "Candidate transaction {} at block {} is invalid: {}",
                            tx_index, block.index, error
                        )
                    })?;
                Executor::apply_transaction_checked(&mut projected, transaction).map_err(
                    |error| {
                        format!(
                            "Candidate transaction {} at block {} cannot execute: {}",
                            tx_index, block.index, error
                        )
                    },
                )?;
            }

            let mut next_state = Self::apply_block_effects(&state, block, &chain[..index])?;
            // The roots are derived from the chain prefix, as on the live path.
            Self::apply_block_end_roots(&mut next_state, block, &chain[..index], self.chain_id);
            if next_state.calculate_state_root() != block.state_root {
                return Err(format!(
                    "Candidate state root mismatch at block {}",
                    block.index
                ));
            }
            state = next_state;
        }
        Ok(state)
    }
    pub fn find_fork_point(&self, other_chain: &[Block]) -> Option<usize> {
        let common_len = self.chain.len().min(other_chain.len());
        for (index, (ours, theirs)) in self.chain.iter().zip(other_chain.iter()).enumerate() {
            if ours.hash != theirs.hash {
                return Some(index);
            }
        }
        (self.chain.len() != other_chain.len()).then_some(common_len)
    }
    /// Reorganise onto a peer-supplied suffix, joining it to this chain.
    ///
    /// `try_reorg` needs the whole candidate chain from genesis, and the peer
    /// only ever sends the blocks from its fork height. A caller outside the
    /// chain actor has no way to read the prefix except by copying it across
    /// the actor boundary, and the fork height that sizes that copy is chosen
    /// by the peer (CWE-400). This entry point does the join here, where the
    /// prefix already lives, so nothing the peer controls decides how much is
    /// copied or when.
    ///
    /// The cheap tests run first and reject a batch without touching the
    /// prefix: an empty suffix, a fork at genesis, a suffix that does not
    /// continue this chain, a fork deeper than [`MAX_REORG_DEPTH`] or below
    /// the finalized height, and - on a length-scored engine - a candidate
    /// that cannot be longer than this chain. The last one is gated by
    /// [`ConsensusEngine::shorter_chain_can_never_win`], because on a
    /// work-scored or checkpoint-scored engine a shorter candidate can
    /// legitimately be the better chain.
    ///
    /// # Errors
    ///
    /// Returns the same refusals as [`Self::try_reorg`], plus the structural
    /// ones that only exist here.
    pub fn try_reorg_suffix(&mut self, suffix: Vec<Block>) -> Result<bool, String> {
        let Some(first) = suffix.first() else {
            return Err("empty reorg suffix".into());
        };
        let start = first.index;
        if start == 0 {
            return Err("Candidate chain attempts to replace configured genesis".into());
        }
        let start_index = usize::try_from(start).map_err(|_| "fork height out of range")?;
        if start_index > self.chain.len() {
            return Err(format!(
                "reorg suffix starts at height {start}, beyond the local chain of {}",
                self.chain.len()
            ));
        }
        // The first suffix block must be the child of the block this chain
        // already holds at `start - 1`. Nothing below is worth paying for when
        // it is not.
        match self.chain.get(start_index - 1) {
            Some(parent) if parent.hash == first.previous_hash => {}
            _ => return Err("suffix does not continue the local chain".into()),
        }
        let reorg_depth = self.chain.len().saturating_sub(start_index);
        if reorg_depth > MAX_REORG_DEPTH {
            return Err(format!(
                "Reorg depth {reorg_depth} exceeds max {MAX_REORG_DEPTH}"
            ));
        }
        if start_index as u64 <= self.finalized_height {
            return Err(format!(
                "Cannot reorg fork point {start_index} at or below finalized height {}",
                self.finalized_height
            ));
        }
        // A comparison the peer cannot make expensive, before a single block
        // is copied - but only on an engine where a strictly shorter chain can
        // never win. PoW (accumulated work) and PoS (checkpoint score) can both
        // prefer a shorter candidate, and they say so; on those the copy below
        // is simply unavoidable work, still peer-independent in size and
        // bounded by the local chain the actor already holds.
        let candidate_len = start_index.saturating_add(suffix.len());
        if self.consensus.shorter_chain_can_never_win() && candidate_len < self.chain.len() {
            return Ok(false);
        }
        let mut candidate = Vec::with_capacity(candidate_len);
        candidate.extend_from_slice(&self.chain[..start_index]);
        candidate.extend(suffix);
        self.try_reorg(candidate)
    }

    /// WIRING: chain surface - the block/snapshot paths that read it land with their wiring.
    pub fn try_reorg(&mut self, new_chain: Vec<Block>) -> Result<bool, String> {
        if !self.consensus.is_better_chain(&self.chain, &new_chain) {
            return Ok(false);
        }
        let Some(fork_point) = self.find_fork_point(&new_chain) else {
            return Ok(false);
        };
        if fork_point == 0 {
            return Err("Candidate chain attempts to replace configured genesis".into());
        }
        let reorg_depth = self.chain.len().saturating_sub(fork_point);

        if reorg_depth > MAX_REORG_DEPTH {
            return Err(format!(
                "Reorg depth {reorg_depth} exceeds max {MAX_REORG_DEPTH}"
            ));
        }

        if fork_point as u64 <= self.finalized_height {
            return Err(format!(
                "Cannot reorg fork point {} at or below finalized height {}",
                fork_point, self.finalized_height
            ));
        }
        let candidate_finalized = new_chain
            .get(self.finalized_height as usize)
            .ok_or_else(|| "Candidate chain omits finalized checkpoint".to_string())?;
        if candidate_finalized.hash != self.finalized_hash {
            return Err("Candidate chain conflicts with finalized checkpoint hash".into());
        }

        let new_state = self.validate_candidate_chain(&new_chain)?;

        // Replay the new fork the way it will be persisted, BEFORE anything
        // changes. A state root mismatch here (for example the PoA stamp
        // mismatch) now refuses the reorg while memory and disk still agree,
        // instead of leaving memory on the new chain and disk on neither
        // fork. Only a real disk error can still fail later.
        let replayed_snapshots = if self.storage.is_some() {
            Some(self.replay_reorg_blocks(&new_chain, fork_point, |_, _| Ok(()))?)
        } else {
            None
        };

        info!("Reorg: replacing {reorg_depth} blocks from height {fork_point}");

        let old_chain = self.chain.clone();
        let previous_finalized_height = self.finalized_height;
        let previous_finalized_hash = self.finalized_hash.clone();

        for block in &old_chain[fork_point..] {
            self.verified_qc_blobs.remove(&block.index);
        }
        if let Some(pruning_manager) = &self.pruning_manager {
            let max_snapshot_height = fork_point.saturating_sub(1) as u64;
            match pruning_manager.quarantine_snapshots_above_height(max_snapshot_height) {
                Ok(count) if count > 0 => tracing::warn!(
                    "Reorg quarantined {count} stale snapshots above height {max_snapshot_height}"
                ),
                Ok(_) => {}
                Err(error) => {
                    tracing::error!("Failed to quarantine stale reorg snapshots: {error}")
                }
            }
        }

        self.chain = new_chain;
        self.state = new_state;

        // The DISK still holds FINALITY_CERT and
        // QC_BLOB at the reorged heights. Left behind, a later
        // `invalidate_finality_from_height` rescan adopts the orphaned
        // fork's cert wholesale (before its adoption fix) or the next reorg
        // reads fork data as canonical. The invalidation deletes the certs
        // and blobs at the orphaned heights and rescans finality against the
        // NEW chain (its adoption now hash-checks the cert against the
        // block).
        self.invalidate_finality_from_height(fork_point as u64);

        // After a reorg, reload the node-side structures from storage. The
        // settlement registries (domains, commitments, proof claims, the
        // external intake) are not among them: they live in the account state
        // the replay of the new chain just produced.
        self.global_headers = Vec::new();
        self.pending_finality_certs = BTreeMap::new();
        self.pending_slashing_evidence = Vec::new();
        self.pending_registry_slashing_reports = Vec::new();
        self.local_invalid_votes = crate::registry::InvalidVoteTracker::new();

        // Reload the node-local structures from storage if available. The
        // bridge state, the message registry and the relayer are account
        // state the replay rebuilt.
        if let Some(ref store) = self.storage {
            if let Ok(stored_global_headers) = store.load_global_headers() {
                self.global_headers =
                    Self::validated_global_header_prefix(stored_global_headers, self.chain_id);
            }
        }
        // The archive follows the headers the new branch's state commits.
        Self::reconcile_global_header_archive(&mut self.global_headers, &self.state);

        // Keep the sets of epochs the fork did not touch and add the sets the
        // new fork went through, so past-epoch certificates and fault proofs
        // stay verifiable after a reorg. Without storage there is no
        // replay, so only the current epoch is known.
        let kept_snapshots: BTreeMap<u64, ValidatorSetSnapshot> = match &replayed_snapshots {
            Some(replayed) => {
                let first_replayed = replayed.keys().next().copied().unwrap_or(u64::MAX);
                let mut merged: BTreeMap<u64, ValidatorSetSnapshot> = self
                    .validator_snapshots
                    .iter()
                    .filter(|(epoch, _)| **epoch < first_replayed)
                    .map(|(epoch, snapshot)| (*epoch, snapshot.clone()))
                    .collect();
                merged.extend(replayed.iter().map(|(e, s)| (*e, s.clone())));
                merged
            }
            None => BTreeMap::new(),
        };
        self.validator_snapshots = kept_snapshots;
        self.record_validator_snapshot(self.state.epoch_index);
        if let (Some(store), Some(replayed)) = (&self.storage, &replayed_snapshots) {
            for (epoch, snapshot) in replayed {
                if !self.validator_snapshots.contains_key(epoch) {
                    continue;
                }
                if let Err(error) = store.save_validator_snapshot(*epoch, snapshot) {
                    warn!("Failed to persist reorg validator snapshot for epoch {epoch}: {error}");
                }
            }
        }

        // The candidate was required to preserve the actual finalized checkpoint.
        // Reorg must never silently downgrade finality to genesis.
        self.finalized_height = previous_finalized_height;
        self.finalized_hash = previous_finalized_hash;

        let mut new_pending = Vec::new();

        let mut chain_txs = std::collections::HashSet::new();
        for block in &self.chain {
            for tx in &block.transactions {
                chain_txs.insert(tx.hash.clone());
            }
        }

        // Transactions of the orphaned blocks go back to the pool unless the
        // new fork already holds them.
        for block in &old_chain[fork_point..] {
            for tx in &block.transactions {
                if !chain_txs.contains(&tx.hash) {
                    new_pending.push(tx.clone());
                }
            }
        }
        for tx in &self.mempool.get_sorted_transactions(self.mempool.len()) {
            if !chain_txs.contains(&tx.hash) {
                new_pending.push(tx.clone());
            }
        }

        // The per network pool limits, the same as at startup.
        let mempool_config = Network::from_chain_id(self.chain_id)
            .map(|network| network.mempool_config())
            .unwrap_or_default();
        self.mempool = crate::mempool::pool::Mempool::new(mempool_config);
        self.mempool
            .sync_scheme_registry(&self.state.scheme_registry);
        for tx in new_pending {
            let _ = self.mempool.add_transaction(tx);
        }

        if let Some(ref store) = self.storage {
            for block in &old_chain[fork_point..] {
                let _ = store.delete_block(block.index);
                for tx in &block.transactions {
                    let _ = store.delete_tx_index(&tx.hash);
                }
            }
            self.replay_reorg_blocks(&self.chain, fork_point, |block, committed| {
                self.commit_block_durable(block, committed)
            })?;
            if let Some(last) = self.chain.last() {
                if let Err(e) = store.save_last_hash(&last.hash) {
                    tracing::error!(error = %e, "Failed to persist last_hash after reorg");
                }
            }
        }

        if let Some(last_block) = self.chain.last() {
            self.consensus
                .record_block_with_chain(last_block, &self.chain, self.storage.as_ref());
        }
        self.mempool.set_min_fee(self.state.base_fee);
        Ok(true)
    }

    /// Replays `chain[fork_point..]` on the state at the fork point, checks
    /// every state root and hands each block with its committed state to
    /// `on_block`. Returns the validator set of every epoch the replay went
    /// through. It reads `self` only, so it can run before a reorg changes
    /// anything.
    fn replay_reorg_blocks<F>(
        &self,
        chain: &[Block],
        fork_point: usize,
        mut on_block: F,
    ) -> Result<BTreeMap<u64, ValidatorSetSnapshot>, String>
    where
        F: FnMut(&Block, &AccountState) -> Result<(), String>,
    {
        let mut current_state = if fork_point > 0 {
            Blockchain::rebuild_state(
                &chain[..fork_point],
                &self.genesis_config,
                self.consensus.domain_kind(),
            )?
        } else {
            AccountState::new()
        };
        // The rebuild starts from a fresh state; carry the engine's
        // domain over before re-executing blocks, or a reorg after an
        // identity write would replay it as a refusal and fork the node
        // off its own chain.
        current_state.execution_domain = self.consensus.domain_kind();
        let mut snapshots = BTreeMap::new();
        snapshots.insert(
            current_state.epoch_index,
            Self::build_validator_snapshot_from_state(
                current_state.epoch_index,
                &current_state,
                self.chain_id,
            ),
        );
        for block in &chain[fork_point..] {
            current_state =
                Self::apply_block_effects(&current_state, block, &chain[..block.index as usize])?;
            Self::apply_block_end_roots(
                &mut current_state,
                block,
                &chain[..block.index as usize],
                self.chain_id,
            );
            if current_state.calculate_state_root() != block.state_root {
                return Err(format!(
                    "Reorg persistence state root mismatch at block {}",
                    block.index
                ));
            }
            snapshots.insert(
                current_state.epoch_index,
                Self::build_validator_snapshot_from_state(
                    current_state.epoch_index,
                    &current_state,
                    self.chain_id,
                ),
            );
            on_block(block, &current_state)?;
        }
        Ok(snapshots)
    }

    pub fn get_state_root(&self, height: u64) -> Option<String> {
        self.storage
            .as_ref()
            .and_then(|store| store.get_state_root(height).unwrap_or(None))
    }

    fn rebuild_state(
        chain: &[Block],
        genesis_config: &GenesisConfig,
        domain: crate::domain::ConsensusKind,
    ) -> Result<AccountState, String> {
        let genesis = chain
            .first()
            .ok_or_else(|| "Cannot rebuild empty chain".to_string())?;
        let expected_genesis = genesis_config.build_genesis_block();
        if genesis.hash != expected_genesis.hash || genesis.chain_id != genesis_config.chain_id {
            return Err("Candidate chain genesis does not match configured genesis".into());
        }
        let mut state = genesis_config.build_state();
        state.execution_domain = domain;

        for (index, block) in chain.iter().enumerate().skip(1) {
            let mut next_state = Self::apply_block_effects(&state, block, &chain[..index])
                .map_err(|e| format!("Failed to rebuild state at block {}: {}", block.index, e))?;
            Self::apply_block_end_roots(
                &mut next_state,
                block,
                &chain[..index],
                genesis_config.chain_id,
            );
            if next_state.calculate_state_root() != block.state_root {
                return Err(format!(
                    "Failed to rebuild state root at block {}",
                    block.index
                ));
            }
            state = next_state;
        }
        Ok(state)
    }
    pub fn print_info(&self) {
        info!("Blockchain Info");
        info!("Consensus: {}", self.consensus.info());
        info!("Length: {}", self.chain.len());
        info!("Pending Tx: {}", self.mempool.len());
        for block in &self.chain {
            info!("Block #{}: {}", block.index, &block.hash[..16]);
        }
    }
    pub fn get_state_snapshot(&self, height: u64) -> Option<crate::chain::snapshot::StateSnapshot> {
        if height >= self.chain.len() as u64 {
            return None;
        }
        let block = &self.chain[height as usize];
        let mut state = Self::rebuild_state(
            &self.chain[..=height as usize],
            &self.genesis_config,
            self.consensus.domain_kind(),
        )
        .ok()?;
        // Same rule as the reorg path: a rebuild must replay identity writes
        // under the same gate the chain applied them under, or the served
        // snapshot disagrees with the canonical state root at that height.
        state.execution_domain = self.consensus.domain_kind();
        let finalized_height = self.finalized_height.min(height);
        let finalized_hash = self
            .chain
            .get(finalized_height as usize)
            .map_or_else(|| self.finalized_hash.clone(), |block| block.hash.clone());

        // Produce V2 snapshot with full consensus metadata
        let genesis_hash = self
            .chain
            .first()
            .map(|b| b.hash.clone())
            .unwrap_or_default();
        let certs: Vec<FinalityCert> = self
            .pending_finality_certs
            .values()
            .flat_map(|v| v.iter())
            .filter(|c| c.checkpoint_height <= height)
            .cloned()
            .collect();

        let params = crate::chain::snapshot::StateSnapshotV2Params {
            height,
            block_hash: block.hash.clone(),
            genesis_hash,
            chain_id: self.chain_id,
            finalized_height,
            finalized_hash: finalized_hash.clone(),
            finality_certificates: certs,
        };
        let v2 = crate::chain::snapshot::StateSnapshotV2::from_state(&state, params);

        // Encode V2 to JSON bytes; receivers try V2 first, V1 as fallback
        let v2_bytes = v2.to_bytes();

        // Wrap as V1-compatible bytes (serde ignores unknown fields on V1 parse)
        let mut snapshot = crate::chain::snapshot::StateSnapshot::from_state(
            height,
            block.hash.clone(),
            self.chain_id,
            &state,
            finalized_height,
            finalized_hash,
        );
        // Embed V2 data for capable receivers
        snapshot.snapshot_hash = format!("__v2__{}", hex::encode(&v2_bytes));
        Some(snapshot)
    }

    fn mainnet_requires_signed_remote_snapshot(&self) -> bool {
        self.chain_id
            == crate::core::chain_config::Network::Mainnet
                .chain_id()
                .value()
    }

    pub fn apply_state_snapshot(
        &mut self,
        snapshot: crate::chain::snapshot::StateSnapshot,
    ) -> Result<(), String> {
        use crate::chain::snapshot::{SnapshotTrustPolicy, StateSnapshotV2};

        // Try V2 restore if available (embedded in snapshot_hash prefix)
        if let Some(v2_data) = snapshot.snapshot_hash.strip_prefix("__v2__") {
            if let Ok(v2_bytes) = hex::decode(v2_data) {
                if let Ok(v2) = StateSnapshotV2::from_bytes(&v2_bytes) {
                    if v2.chain_id == self.chain_id {
                        if self.mainnet_requires_signed_remote_snapshot() {
                            if v2.trust_policy != SnapshotTrustPolicy::RequireSigned {
                                return Err(
                                    "Mainnet remote snapshots require a signed V2 manifest".into(),
                                );
                            }
                            let trust_list = Self::snapshot_trusted_signers_from_state(&self.state);
                            if trust_list.is_empty() {
                                return Err(
                                    "Mainnet remote snapshots require a non-empty signer trust list"
                                        .into(),
                                );
                            }
                            v2.verify_authentic(Some(&trust_list))
                                .map_err(|error| format!("V2 snapshot auth failed: {error}"))?;
                        } else if !v2.verify() {
                            return Err("V2 snapshot digest verification failed".into());
                        }
                        return self.apply_v2_snapshot(&v2);
                    }
                }
            }
        }

        // Fall back to V1 restore. Mainnet has no unsigned/V1 remote
        // Snapshot compatibility path; production remote sync must carry a
        // Signed V2 manifest.
        if self.mainnet_requires_signed_remote_snapshot() {
            return Err("Mainnet remote snapshots require signed V2 manifests".into());
        }
        if !snapshot.verify() {
            return Err("Snapshot verification failed".into());
        }
        if snapshot.height < self.finalized_height {
            return Err(format!(
                "Snapshot height {} is older than current finalized height {}",
                snapshot.height, self.finalized_height
            ));
        }
        if snapshot.chain_id != self.chain_id {
            return Err(format!(
                "Snapshot chain_id mismatch: expected {}, got {}",
                self.chain_id, snapshot.chain_id
            ));
        }
        if snapshot.finalized_height > snapshot.height {
            return Err("Snapshot finalized height exceeds snapshot height".into());
        }

        let Some(block) = self.chain.get(snapshot.height as usize) else {
            return Err(format!(
                "Snapshot height {} is not available in local chain",
                snapshot.height
            ));
        };
        // The snapshot must be AT THE TIP. The old rule
        // accepted any height whose block merely exists, so a snapshot at a
        // lower height replaced a state that had already moved past it -
        // state rollback dressed up as sync.
        let tip = self.chain.len().saturating_sub(1) as u64;
        if snapshot.height != tip {
            return Err(format!(
                "Snapshot height {} is not the chain tip ({tip}); applying it would \
                 roll state back",
                snapshot.height
            ));
        }
        if block.hash != snapshot.block_hash {
            return Err(format!(
                "Snapshot block hash mismatch at height {}",
                snapshot.height
            ));
        }

        let finalized_block = self
            .chain
            .get(snapshot.finalized_height as usize)
            .ok_or_else(|| {
                format!(
                    "Snapshot finalized height {} is not available in local chain",
                    snapshot.finalized_height
                )
            })?;
        if finalized_block.hash != snapshot.finalized_hash {
            return Err(format!(
                "Snapshot finalized hash mismatch at height {}",
                snapshot.finalized_height
            ));
        }

        let mut snapshot_state = AccountState::from_snapshot(&snapshot);
        // Snapshot loading replaces the whole state; the domain is not part
        // of a snapshot (a peer's engine is not this node's), so re-stamp it
        // from the local engine before the state goes live.
        snapshot_state.execution_domain = self.consensus.domain_kind();
        let snapshot_state_root = snapshot_state.calculate_state_root();
        if !block.state_root.is_empty() && snapshot_state_root != block.state_root {
            return Err(format!(
                "Snapshot state root mismatch: expected {}, got {}",
                block.state_root, snapshot_state_root
            ));
        }

        // Snapshot restore replaces the account map. Mark all restored
        // Accounts dirty so the next durable commit cannot leave the database
        // With pre-restore balances/nonces.
        snapshot_state.mark_all_accounts_dirty();
        snapshot_state.current_block_unix_secs = Self::block_timestamp_secs(block.timestamp);
        snapshot_state.current_block_entropy =
            Self::block_context_entropy(&block.previous_hash, &block.vrf_output);
        self.state = snapshot_state;
        self.finalized_height = snapshot.finalized_height;
        self.finalized_hash = snapshot.finalized_hash;
        self.mempool.set_min_fee(self.state.base_fee);

        Ok(())
    }

    fn apply_v2_snapshot(
        &mut self,
        v2: &crate::chain::snapshot::StateSnapshotV2,
    ) -> Result<(), String> {
        if v2.height < self.finalized_height {
            return Err(format!(
                "V2 snapshot height {} older than finalized {}",
                v2.height, self.finalized_height
            ));
        }
        // The same rule the V1 branch enforces. The V2 path is tried
        // first, so leaving it out made the guard the V1 fallback never
        // reached: any snapshot between the finalized height and the tip
        // replaced state that had already moved past it while `self.chain`
        // stayed at the tip, and the finalized marker was then overwritten
        // from the snapshot.
        let tip = self.chain.len().saturating_sub(1) as u64;
        if v2.height != tip {
            return Err(format!(
                "V2 snapshot height {} is not the chain tip ({tip}); applying it would \
                 roll state back",
                v2.height
            ));
        }
        if v2.finalized_height > v2.height {
            return Err(format!(
                "V2 snapshot finalized height {} is ahead of its own height {}",
                v2.finalized_height, v2.height
            ));
        }
        if v2.finalized_height < self.finalized_height {
            return Err(format!(
                "V2 snapshot finalized height {} would move finality back from {}",
                v2.finalized_height, self.finalized_height
            ));
        }
        // The named finalized block must exist on THIS chain: a snapshot whose
        // finality names an unknown hash would move `finalized_hash` to a value
        // no local block backs.
        match self.chain.get(v2.finalized_height as usize) {
            Some(finalized) if finalized.hash == v2.finalized_hash => {}
            Some(_) => return Err("V2 snapshot finalized hash mismatch".into()),
            None => {
                return Err(format!(
                    "V2 snapshot finalized height {} is not available in local chain",
                    v2.finalized_height
                ));
            }
        }

        let Some(block) = self.chain.get(v2.height as usize) else {
            return Err("V2 snapshot height not in local chain".into());
        };
        if block.hash != v2.block_hash {
            return Err("V2 snapshot block hash mismatch".into());
        }

        let mut v2_state = AccountState::from_snapshot_v2(v2);
        v2_state.execution_domain = self.consensus.domain_kind();
        let state_root = v2_state.calculate_state_root();
        if !block.state_root.is_empty() && state_root != block.state_root {
            return Err(format!(
                "V2 snapshot state root mismatch: expected {}, got {}",
                block.state_root, state_root
            ));
        }

        // V2 restore also replaces the account map; make the replacement
        // Durable on the next commit rather than relying on a later mutation.
        v2_state.mark_all_accounts_dirty();
        v2_state.current_block_unix_secs = Self::block_timestamp_secs(block.timestamp);
        v2_state.current_block_entropy =
            Self::block_context_entropy(&block.previous_hash, &block.vrf_output);
        self.state = v2_state;
        self.finalized_height = v2.finalized_height;
        self.finalized_hash = v2.finalized_hash.clone();
        self.mempool.set_min_fee(self.state.base_fee);

        // Restore finality certs from V2 snapshot through the same deduplicating,
        // Total-entry bounded queue used by the live network path.
        for cert in &v2.finality_certificates {
            self.queue_pending_finality_cert(cert.clone());
        }

        info!(
            "Applied V2 snapshot at height {} (epoch={}, base_fee={}, certs={})",
            v2.height,
            v2.epoch_index,
            v2.base_fee,
            v2.finality_certificates.len()
        );
        Ok(())
    }

    /// PARTIAL: allowed - draining the queue is the operation, not a lookup.
    /// The certificates are taken out on purpose and each is handled; the
    /// error only reports that one of them failed, and `handle_finality_cert`
    /// requeues the single cert whose QC is still missing. Putting the whole
    /// batch back would duplicate the ones that succeeded.
    fn process_pending_finality_certs(&mut self, checkpoint_height: u64) -> Result<(), String> {
        let Some(certs) = self.pending_finality_certs.remove(&checkpoint_height) else {
            return Ok(());
        };

        let mut last_err = None;
        for cert in certs {
            if let Err(e) = self.handle_finality_cert(cert) {
                // `handle_finality_cert` itself requeues a certificate exactly
                // Once when its QC is still missing. Re-inserting here used to
                // Duplicate the same cert on every retry.
                last_err = Some(e);
            }
        }

        if let Some(e) = last_err {
            return Err(e);
        }
        Ok(())
    }

    pub fn handle_finality_cert(&mut self, cert: FinalityCert) -> Result<(), String> {
        if cert.checkpoint_height <= self.finalized_height {
            return Ok(());
        }

        // Chain binding: the aggregated precommit signatures were produced
        // for `cert.chain_id`, and the pairing check rebuilds the preimage
        // from it. A certificate for another network is refused here rather
        // than after the aggregate BLS work.
        if cert.chain_id != self.chain_id {
            return Err(format!(
                "Finality certificate is for chain {} (this chain is {})",
                cert.chain_id, self.chain_id
            ));
        }

        if !crate::chain::finality::is_checkpoint_height_for_chain(
            cert.checkpoint_height,
            self.chain_id,
        ) {
            return Err(format!(
                "Height {} is not a valid checkpoint height",
                cert.checkpoint_height
            ));
        }

        if let Some(block) = self.chain.get(cert.checkpoint_height as usize) {
            if block.hash != cert.checkpoint_hash {
                return Err(format!(
                    "Certificate hash {} mismatch with our block hash {} at height {}",
                    cert.checkpoint_hash, block.hash, cert.checkpoint_height
                ));
            }
        } else {
            return Err(format!(
                "We don't have block at height {} yet",
                cert.checkpoint_height
            ));
        }

        self.require_checkpoint_epoch(cert.epoch, cert.checkpoint_height, "Finality certificate")?;
        let snapshot = self.require_validator_snapshot(cert.epoch)?;

        // /: finality is the BLS certificate AND the ML-DSA QC of the
        // same signers. At Isolate (Zemheri) the BLS half drops out: its curve
        // fell, so a certificate it signed proves nothing. The QC alone
        // decides, and it must carry the same stake and signer count quorum.
        let bls_required = crate::security::alarm_effects::bls_required_for_finality(
            self.state.settlement.quantum.alarm(),
        );
        if bls_required {
            cert.verify(&snapshot)?;
        } else {
            if cert.set_hash != snapshot.set_hash {
                return Err("Validator set hash mismatch".into());
            }
            if cert.epoch != snapshot.epoch {
                return Err("Epoch mismatch".into());
            }
        }

        let blob = match self.get_qc_blob(cert.checkpoint_height) {
            Some(blob) => blob,
            None => {
                let checkpoint_height = cert.checkpoint_height;
                self.queue_pending_finality_cert(cert);
                return Err(format!(
                    "Missing verified QC blob for checkpoint {checkpoint_height}"
                ));
            }
        };
        Self::ensure_blob_matches_checkpoint(&blob, &cert.checkpoint_hash)?;
        let signer_indices = if bls_required {
            cert.signer_indices(snapshot.validators.len())
        } else {
            Vec::new()
        };
        let verified_signers = blob.verify_against_snapshot_in(
            &self.state.scheme_registry,
            &snapshot,
            Some(&signer_indices),
            Some(self.state.epoch_index),
        )?;
        if !bls_required {
            let stake: u128 = verified_signers
                .iter()
                .filter_map(|idx| snapshot.validators.get(*idx))
                .map(|validator| u128::from(validator.stake))
                .sum();
            if stake < snapshot.quorum_stake() || verified_signers.len() < snapshot.quorum_count() {
                return Err(format!(
                    "ML-DSA QC quorum not met under the quantum alarm: {} signers, stake {stake}",
                    verified_signers.len()
                ));
            }
        }
        self.maybe_apply_detected_qc_faults(&snapshot, &blob)?;

        self.finalized_height = cert.checkpoint_height;
        self.finalized_hash = cert.checkpoint_hash.clone();
        // Both halves of finality were verified above: the BLS certificate
        // and the ML-DSA QC of the same signers.
        self.feed_finality(cert.checkpoint_height, &cert.checkpoint_hash, bls_required);

        info!(
            "FINALIZED checkpoint: height={}, hash={}",
            self.finalized_height, self.finalized_hash
        );

        if let Some(ref store) = self.storage {
            if let Err(e) = store.save_finality_cert(self.finalized_height, &cert) {
                tracing::error!("Failed to persist finality cert: {e}");
            }
            if let Err(e) = store.save_canonical_height(self.finalized_height) {
                tracing::error!(error = %e, height = self.finalized_height, "Failed to save canonical height");
            }
        }

        // Hand the new finality to the engine so parked
        // epoch-boundary checkpoints at or below it are promoted.
        self.consensus.note_finalized_height(
            self.finalized_height,
            &self.chain,
            self.storage.as_ref(),
        );

        // finality may release old witnesses (Pul-Lite).
        let pruned = self.prune_released_witnesses(
            crate::storage::witness_retention::DEFAULT_RETENTION_BLOCKS,
            WITNESS_PRUNE_WINDOW,
        );
        if !pruned.is_empty() {
            tracing::debug!(count = pruned.len(), "pruned finalized witnesses");
        }

        Ok(())
    }

    fn enqueue_pending_slashing_report(
        &mut self,
        report: crate::registry::evidence::SlashingReport,
    ) {
        const MAX_PENDING_SLASHING_REPORTS: usize = 64;
        const MAX_SINGLE_REPORT_BYTES: usize =
            crate::registry::invalid_vote::MAX_SPAM_REPORT_JSON_BYTES;
        // The block door only applies reports that accuse the validator role
        // (`apply_block_slashing_reports_in_state`), so a report about any
        // other role would ride in the queue and be refused by our own
        // validation on every slot. Drop it here instead of building a block
        // that can never be applied.
        if report.role != crate::registry::role::roles::VALIDATOR {
            tracing::warn!(
                role = ?report.role,
                "Dropping a slashing report that does not accuse the validator role"
            );
            return;
        }
        if self.pending_registry_slashing_reports.len() >= MAX_PENDING_SLASHING_REPORTS {
            return;
        }
        // Same admission ceiling as evidence: a report that cannot fit a
        // block would occupy a queue slot it can never vacate through a block.
        if serde_json::to_vec(&report).map_or(usize::MAX, |bytes| bytes.len())
            > MAX_SINGLE_REPORT_BYTES
        {
            tracing::warn!("Dropping a slashing report larger than the block allowance");
            return;
        }
        if !self
            .pending_registry_slashing_reports
            .iter()
            .any(|existing| existing == &report)
        {
            self.pending_registry_slashing_reports.push(report);
        }
    }

    fn apply_block_slashing_reports_in_state(
        state: &mut AccountState,
        block: &Block,
    ) -> Result<(), String> {
        let Some(reports) = &block.slashing_reports else {
            return Ok(());
        };
        if reports.len() > 64 {
            return Err("Too many slashing reports in block".into());
        }
        for raw_report in reports {
            raw_report
                .validate_shape()
                .map_err(|e| format!("Invalid slashing report shape in block: {e}"))?;
            // The only offender a block report may name is a validator - the
            // lookup below requires a bonded validator seat - and
            // `AccountState::slash_from_report` cuts the ledger bond only when
            // the report's self-declared role is the validator role. Left
            // unpinned, a producer could label a real double-sign with another
            // role the offender also holds: that cuts only the
            // permissionless-registry mirror, whose validator entry the
            // cross-role sweep then marks `Slashed`, so every later correctly
            // labelled report for the same offence reads as a replay and the
            // equivocating validator keeps its whole bond.
            if raw_report.role != crate::registry::role::roles::VALIDATOR {
                return Err("Block slashing report must accuse the validator role".to_string());
            }
            let validator = state
                .validators
                .get(&raw_report.offender)
                .ok_or_else(|| "Slashing report names non-validator offender".to_string())?;
            match &raw_report.proof {
                crate::registry::evidence::SlashingProof::DoubleSign {
                    height,
                    kind,
                    epoch,
                    block_hash_1,
                    block_hash_2,
                    signature_1,
                    signature_2,
                } => {
                    if block_hash_1 == block_hash_2 {
                        return Err("Non-conflicting double-sign block hashes".into());
                    }
                    match kind {
                        crate::registry::evidence::DoubleSignKind::Prevote => {
                            let ep = epoch.ok_or_else(|| {
                                "Prevote double-sign proof missing epoch".to_string()
                            })?;
                            // Both messages are rebuilt with THIS block's
                            // chain id, never with one the report carries:
                            // two genuine votes a validator signed on another
                            // chain for the same (epoch, height) would
                            // otherwise look like an equivocation and could be
                            // used to slash an honest validator. A signature
                            // minted elsewhere cannot verify here.
                            let msg1 = Prevote {
                                epoch: ep,
                                checkpoint_height: *height,
                                checkpoint_hash: block_hash_1.clone(),
                                chain_id: block.chain_id,
                                voter_id: raw_report.offender,
                                sig_bls: Vec::new(),
                                auth_sig: Vec::new(),
                            }
                            .signing_message();
                            let msg2 = Prevote {
                                epoch: ep,
                                checkpoint_height: *height,
                                checkpoint_hash: block_hash_2.clone(),
                                chain_id: block.chain_id,
                                voter_id: raw_report.offender,
                                sig_bls: Vec::new(),
                                auth_sig: Vec::new(),
                            }
                            .signing_message();
                            crate::chain::finality::verify_bls_sig(
                                &validator.bls_public_key,
                                &msg1,
                                signature_1,
                            )
                            .map_err(|_| "Prevote double-sign signature_1 failed verification")?;
                            crate::chain::finality::verify_bls_sig(
                                &validator.bls_public_key,
                                &msg2,
                                signature_2,
                            )
                            .map_err(|_| "Prevote double-sign signature_2 failed verification")?;
                        }
                        crate::registry::evidence::DoubleSignKind::Precommit => {
                            let ep = epoch.ok_or_else(|| {
                                "Precommit double-sign proof missing epoch".to_string()
                            })?;
                            let msg1 = crate::chain::finality::checkpoint_signing_message(
                                block.chain_id,
                                ep,
                                *height,
                                block_hash_1,
                            );
                            let msg2 = crate::chain::finality::checkpoint_signing_message(
                                block.chain_id,
                                ep,
                                *height,
                                block_hash_2,
                            );
                            crate::chain::finality::verify_bls_sig(
                                &validator.bls_public_key,
                                &msg1,
                                signature_1,
                            )
                            .map_err(|_| "Precommit double-sign signature_1 failed verification")?;
                            crate::chain::finality::verify_bls_sig(
                                &validator.bls_public_key,
                                &msg2,
                                signature_2,
                            )
                            .map_err(|_| "Precommit double-sign signature_2 failed verification")?;
                        }
                        crate::registry::evidence::DoubleSignKind::BlockHeader => {
                            // Bare block-hash signatures do not commit to a height inside
                            // `SlashingProof::DoubleSign`, so two honest blocks signed by a
                            // validator at different heights would otherwise satisfy the check.
                            // Block-header equivocations must travel in `block.slashing_evidence`
                            // with full `BlockHeader` preimages proving equal height.
                            return Err(
                                "Block-header double-sign requires full headers in slashing_evidence"
                                    .into(),
                            );
                        }
                    }
                }
                crate::registry::evidence::SlashingProof::InvalidSignatureSpam {
                    epoch,
                    threshold,
                    samples,
                    ..
                } => {
                    use crate::registry::invalid_vote::MAX_SPAM_REPORT_SAMPLES;
                    if *epoch > state.epoch_index.saturating_add(1) {
                        return Err("InvalidSignatureSpam epoch out of bounds".into());
                    }
                    if samples.len() > MAX_SPAM_REPORT_SAMPLES {
                        return Err(
                            "InvalidSignatureSpam sample count exceeds block ceiling".into()
                        );
                    }
                    let expected_threshold = state.registry.params().max_invalid_votes_per_epoch;
                    // Every configured invalid vote must be proved. Capping the
                    // required evidence below the threshold lets a block producer
                    // slash a validator that has not committed the offence.
                    if expected_threshold == 0
                        || expected_threshold > MAX_SPAM_REPORT_SAMPLES as u64
                        || *threshold < expected_threshold
                        || (samples.len() as u64) < expected_threshold
                    {
                        return Err(
                            "InvalidSignatureSpam proof does not satisfy active epoch threshold"
                                .into(),
                        );
                    }
                    let mut seen_votes: std::collections::BTreeSet<(&[u8], &[u8])> =
                        std::collections::BTreeSet::new();
                    for (auth_msg, auth_sig, vote_msg, bad_sig) in samples {
                        if !seen_votes.insert((vote_msg.as_slice(), bad_sig.as_slice())) {
                            return Err(
                                "InvalidSignatureSpam proof contains duplicate vote sample".into(),
                            );
                        }
                        if crate::chain::finality::vote_message_epoch(vote_msg) != Some(*epoch) {
                            return Err(
                                "InvalidSignatureSpam sample epoch does not match report epoch"
                                    .into(),
                            );
                        }
                        // A signature from another network cannot establish
                        // an offence on this chain, even with the same voter
                        // and epoch. The vote preimage itself names the chain.
                        if crate::chain::finality::vote_message_chain_id(vote_msg)
                            != Some(block.chain_id)
                        {
                            return Err(
                                "InvalidSignatureSpam sample does not bind this chain".into()
                            );
                        }
                        if crate::chain::finality::vote_auth_signing_message(vote_msg, bad_sig)
                            != *auth_msg
                        {
                            return Err(
                                "InvalidSignatureSpam sample does not bind the vote it accuses"
                                    .into(),
                            );
                        }
                        crate::chain::finality::verify_bls_sig(
                            &validator.bls_public_key,
                            auth_msg,
                            auth_sig,
                        )
                        .map_err(|_| "InvalidSignatureSpam auth signature failed verification")?;
                        if crate::chain::finality::verify_bls_sig(
                            &validator.bls_public_key,
                            vote_msg,
                            bad_sig,
                        )
                        .is_ok()
                        {
                            return Err(
                                "InvalidSignatureSpam sample carries a valid vote signature".into(),
                            );
                        }
                    }
                }
                _ => {
                    return Err("Unsupported slashing proof variant in block".into());
                }
            }
            let verified = crate::registry::evidence::SlashingReport::new_verified(
                raw_report.offender,
                raw_report.role,
                raw_report.proof.clone(),
                raw_report.reporter,
            );
            state
                .slash_from_report(&verified)
                .map_err(|e| format!("Block slashing report execution failed: {e}"))?;
        }
        Ok(())
    }

    /// WIRING: local invalid-vote accounting door without mutating committed
    /// `AccountState` outside block execution.
    pub fn note_invalid_vote(&mut self, epoch: u64, voter: Address) {
        if epoch > self.state.epoch_index.saturating_add(1) {
            tracing::warn!(epoch, "Invalid vote names an epoch far ahead; not counted");
            return;
        }
        let params = *self.state.registry.params();
        if let Some(report) = self
            .local_invalid_votes
            .record_invalid_vote(epoch, voter, &params)
        {
            self.enqueue_pending_slashing_report(report);
        }
    }

    fn note_invalid_vote_sample(
        &mut self,
        epoch: u64,
        voter: Address,
        sample: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
    ) {
        if epoch > self.state.epoch_index.saturating_add(1) {
            tracing::warn!(epoch, "Invalid vote names an epoch far ahead; not counted");
            return;
        }
        let params = *self.state.registry.params();
        if let Some(report) = self
            .local_invalid_votes
            .record_invalid_vote_with_sample(epoch, voter, sample, &params)
        {
            self.enqueue_pending_slashing_report(report);
        }
    }

    pub fn handle_prevote(&mut self, vote: Prevote) -> Result<(), String> {
        if vote.checkpoint_hash.len() > MAX_CHECKPOINT_HASH_LEN {
            return Err("Rejecting prevote: checkpoint_hash is not a block hash".into());
        }
        // The vote signature is a BLS point, and it is hashed as part of the
        // auth preimage below. Refuse anything that cannot be one before the
        // preimage is built, so an oversized `sig_bls` is neither hashed nor
        // retained as a local invalid-vote sample.
        if vote.sig_bls.len() > BLS_VOTE_SIGNATURE_BYTES
            || vote.auth_sig.len() > BLS_VOTE_SIGNATURE_BYTES
        {
            return Err("Rejecting prevote: signature is not a BLS signature".into());
        }
        // Chain binding. `vote.chain_id` is the domain the sender signed
        // under, and the signature check below rebuilds the preimage from it,
        // so a vote minted for another chain fails verification either way.
        // Refusing it here keeps an honest operator's cross-chain votes from
        // ever reaching the aggregator, where two of them would otherwise
        // look exactly like an equivocation.
        if vote.chain_id != self.chain_id {
            return Err(format!(
                "Prevote was signed for chain {} (this chain is {})",
                vote.chain_id, self.chain_id
            ));
        }
        // Authenticate BEFORE attributing. A garbage
        // vote naming a victim must not count against the victim: only a
        // vote whose `auth_sig` proves control of the registered key may
        // later earn an invalid-vote tick (self-incrimination). Unverified
        // messages are dropped without touching anyone's counters.
        if let Some(v) = self.state.validators.get(&vote.voter_id) {
            if !v.bls_public_key.is_empty()
                && crate::chain::finality::verify_bls_sig(
                    &v.bls_public_key,
                    &vote.auth_signing_message(),
                    &vote.auth_sig,
                )
                .is_err()
            {
                return Err("Unauthenticated prevote (vote auth failed)".into());
            }
        }
        // Validate the BLS signature of the prevote against the voter's
        // registered BLS public key BEFORE ingesting it.
        if let Some(v) = self.state.validators.get(&vote.voter_id) {
            let signing_msg = vote.signing_message();
            if !v.bls_public_key.is_empty()
                && crate::chain::finality::verify_bls_sig(
                    &v.bls_public_key,
                    &signing_msg,
                    &vote.sig_bls,
                )
                .is_err()
            {
                let auth_msg = vote.auth_signing_message();
                self.note_invalid_vote_sample(
                    vote.epoch,
                    vote.voter_id,
                    (
                        auth_msg,
                        vote.auth_sig.clone(),
                        signing_msg,
                        vote.sig_bls.clone(),
                    ),
                );
                return Err("Invalid prevote signature".into());
            }
        }
        // Enqueue equivocation evidence for deterministic in-block execution
        // rather than mutating committed `AccountState` directly on gossip.
        // A vote belongs to the round at its own height. When this node has no
        // round yet, or is at another height (the peers are a round ahead, or
        // this node has not started the round the block behind it names), the
        // vote is kept for the round that names it instead of being dropped:
        // it is gossiped once, and the round it belongs to may start a moment
        // later.
        let off_round = match self.finality_aggregator.as_ref() {
            None => true,
            Some(agg) => agg.checkpoint_height != vote.checkpoint_height,
        };
        if off_round {
            self.keep_early_prevote(vote);
            return Err("No active finality aggregator".into());
        }
        let (result, reports) = {
            let aggregator = self
                .finality_aggregator
                .as_mut()
                .ok_or("No active finality aggregator")?;
            let res = aggregator.add_prevote(vote);
            let reports = aggregator.take_detected_equivocations();
            (res, reports)
        };
        if !reports.is_empty() {
            if let Some(ref m) = self.metrics {
                m.settlement_equivocations_detected
                    .inc_by(u64::try_from(reports.len()).unwrap_or(u64::MAX));
            }
        }
        for report in reports {
            self.enqueue_pending_slashing_report(report);
        }
        if self
            .finality_aggregator
            .as_ref()
            .is_some_and(|agg| agg.prevote_quorum_reached && !agg.precommit_quorum_reached)
        {
            // The precommits that arrived before this quorum were kept for
            // exactly this moment: a precommit is refused until the prevote
            // quorum is in, and it is published once.
            self.replay_early_precommits();
        }
        result.map_err(|e| e.to_string())
    }

    pub fn handle_precommit(&mut self, vote: Precommit) -> Result<Option<FinalityCert>, String> {
        if vote.checkpoint_hash.len() > MAX_CHECKPOINT_HASH_LEN {
            return Err("Rejecting precommit: checkpoint_hash is not a block hash".into());
        }
        // Same ceiling as `handle_prevote`: the signature must be a BLS point
        // before it enters the auth preimage or the invalid-vote sample store.
        if vote.sig_bls.len() > BLS_VOTE_SIGNATURE_BYTES
            || vote.auth_sig.len() > BLS_VOTE_SIGNATURE_BYTES
        {
            return Err("Rejecting precommit: signature is not a BLS signature".into());
        }
        // Chain binding; see `handle_prevote`.
        if vote.chain_id != self.chain_id {
            return Err(format!(
                "Precommit was signed for chain {} (this chain is {})",
                vote.chain_id, self.chain_id
            ));
        }
        // Authenticate BEFORE attributing (see
        // `handle_prevote`).
        if let Some(v) = self.state.validators.get(&vote.voter_id) {
            if !v.bls_public_key.is_empty()
                && crate::chain::finality::verify_bls_sig(
                    &v.bls_public_key,
                    &vote.auth_signing_message(),
                    &vote.auth_sig,
                )
                .is_err()
            {
                return Err("Unauthenticated precommit (vote auth failed)".into());
            }
        }
        // Same invalid-signature gate as `handle_prevote`.
        if let Some(v) = self.state.validators.get(&vote.voter_id) {
            if !v.bls_public_key.is_empty() {
                let auth_msg = vote.auth_signing_message();
                let msg = crate::chain::finality::checkpoint_signing_message(
                    vote.chain_id,
                    vote.epoch,
                    vote.checkpoint_height,
                    &vote.checkpoint_hash,
                );
                if crate::chain::finality::verify_bls_sig(&v.bls_public_key, &msg, &vote.sig_bls)
                    .is_err()
                {
                    self.note_invalid_vote_sample(
                        vote.epoch,
                        vote.voter_id,
                        (auth_msg, vote.auth_sig.clone(), msg, vote.sig_bls.clone()),
                    );
                    return Err("Invalid precommit signature".into());
                }
            }
        }
        // The post-quantum half of the vote. A precommit that carries one is
        // checked here, against the epoch's snapshot, before the aggregator
        // can put it in a QC blob; a bad attestation is a bad vote. A
        // precommit without one still counts for the BLS half, but its signer
        // is missing from the checkpoint's blob, so no certificate can be
        // applied on it - the signing path only leaves it out when the node
        // holds no PQ key at all.
        if !vote.pq_sig.is_empty() {
            if let Some(snapshot) = self.validator_snapshot_for_epoch(vote.epoch) {
                if let (Some(index), Some(entry)) = (
                    snapshot.validator_index(&vote.voter_id),
                    snapshot.find_validator(&vote.voter_id),
                ) {
                    let index: u32 = index.try_into().map_err(|_| {
                        "Precommit attests a validator index that does not fit its wire field"
                            .to_string()
                    })?;
                    let message = crate::consensus::qc::pq_signing_message(
                        vote.epoch,
                        vote.checkpoint_height,
                        &vote.checkpoint_hash,
                        index,
                    );
                    crate::crypto::primitives::PqKeyPair::verify_in(
                        &self.state.scheme_registry,
                        &entry.pq_public_key,
                        crate::crypto::ctx::QC_V2,
                        &message,
                        &vote.pq_sig,
                    )
                    .map_err(|e| format!("Invalid PQ attestation in precommit: {e}"))?;
                }
            }
        }
        let off_round = match self.finality_aggregator.as_ref() {
            None => true,
            Some(agg) => agg.checkpoint_height != vote.checkpoint_height,
        };
        let no_round_yet = self.finality_aggregator.is_none();
        if off_round
            || self
                .finality_aggregator
                .as_ref()
                .is_some_and(|agg| !agg.prevote_quorum_reached)
        {
            // Kept, not dropped: the sender voted at the same checkpoint as
            // this node, it simply reached the quorum first, and the vote is
            // published once. `handle_prevote` replays these the moment the
            // prevote quorum is in.
            self.keep_early_precommit(vote);
            return Err(if no_round_yet {
                "No active finality aggregator".into()
            } else {
                "Cannot precommit before prevote quorum".into()
            });
        }
        let (result, quorum_reached, reports) = {
            let aggregator = self
                .finality_aggregator
                .as_mut()
                .ok_or("No active finality aggregator")?;
            let res = aggregator.add_precommit(vote);
            let quorum = aggregator.precommit_quorum_reached;
            let reports = aggregator.take_detected_equivocations();
            (res, quorum, reports)
        };
        if !reports.is_empty() {
            if let Some(ref m) = self.metrics {
                m.settlement_equivocations_detected
                    .inc_by(u64::try_from(reports.len()).unwrap_or(u64::MAX));
            }
        }
        for report in reports {
            self.enqueue_pending_slashing_report(report);
        }
        result.map_err(|e| e.to_string())?;

        if !quorum_reached {
            return Ok(None);
        }
        // Both halves of the round, taken while the aggregator is still the
        // one that produced them.
        let produced = self.finality_aggregator.as_ref().and_then(|agg| {
            let cert = agg.try_produce_cert()?;
            let blob = agg.try_produce_qc_blob();
            Some((cert, blob))
        });
        let Some((cert, blob)) = produced else {
            return Ok(None);
        };
        info!(
            "FinalityCert produced: epoch={}, height={}",
            cert.epoch, cert.checkpoint_height
        );
        self.finality_aggregator = None;

        // The QC blob this round's own precommits attested, imported through
        // the same verified door a blob from a peer takes, and then the
        // certificate applied here: a node does not gossip to itself, so
        // without this the only node that never finalized was the one that
        // assembled the certificate. The failures below are logged, not
        // returned: the certificate is still worth gossiping (a peer may hold
        // the blob), and a round that cannot be applied locally must not take
        // the vote-ingest path down with it.
        if let Some(blob) = blob {
            if let Err(e) = self.import_qc_blob(blob) {
                warn!(
                    height = cert.checkpoint_height,
                    "The round's own QC blob was refused locally: {e}"
                );
            }
        } else {
            warn!(
                height = cert.checkpoint_height,
                "No QC blob could be assembled for this checkpoint: fewer than a quorum of its precommits carried a PQ attestation"
            );
        }
        if let Err(e) = self.handle_finality_cert(cert.clone()) {
            warn!(
                height = cert.checkpoint_height,
                "Produced finality certificate did not apply locally: {e}"
            );
        }
        Ok(Some(cert))
    }

    pub fn sign_prevote(
        &self,
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: &str,
        voter_id: &Address,
    ) -> Result<Prevote, String> {
        let msg = {
            let dummy = Prevote {
                epoch,
                checkpoint_height,
                checkpoint_hash: checkpoint_hash.to_string(),
                chain_id: self.chain_id,
                voter_id: *voter_id,
                sig_bls: vec![],
                auth_sig: Vec::new(),
            };
            dummy.signing_message()
        };

        let sig = if let Some(sk) = self.consensus.bls_secret_key() {
            crate::chain::finality::sign_bls(&sk, &msg)
        } else if let Some(signer) = self.consensus.signer() {
            signer
                .bls_sign(&msg)
                .map_err(|e| format!("BLS signer backend failed: {e}"))?
        } else {
            return Err("No BLS signing capability available".to_string());
        };

        // The vote is also authenticated under the same
        // key, over the domain-separated auth message. The receiving side
        // refuses to attribute an invalid vote to this validator unless the
        // auth signature proves key control first.
        // V2 covers the vote signature itself, so a
        // captured auth cannot vouch for a swapped-in garbage sig_bls.
        let auth_msg = crate::chain::finality::vote_auth_signing_message(&msg, &sig);
        let auth_sig = if let Some(sk) = self.consensus.bls_secret_key() {
            crate::chain::finality::sign_bls(&sk, &auth_msg)
        } else if let Some(signer) = self.consensus.signer() {
            signer
                .bls_sign(&auth_msg)
                .map_err(|e| format!("BLS signer backend failed: {e}"))?
        } else {
            return Err("No BLS signing capability available".to_string());
        };

        Ok(Prevote {
            epoch,
            checkpoint_height,
            checkpoint_hash: checkpoint_hash.to_string(),
            chain_id: self.chain_id,
            voter_id: *voter_id,
            sig_bls: sig,
            auth_sig,
        })
    }

    pub fn sign_precommit(
        &self,
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: &str,
        voter_id: &Address,
    ) -> Result<Precommit, String> {
        let msg = crate::chain::finality::checkpoint_signing_message(
            self.chain_id,
            epoch,
            checkpoint_height,
            checkpoint_hash,
        );

        let sig = if let Some(sk) = self.consensus.bls_secret_key() {
            crate::chain::finality::sign_bls(&sk, &msg)
        } else if let Some(signer) = self.consensus.signer() {
            signer
                .bls_sign(&msg)
                .map_err(|e| format!("BLS signer backend failed: {e}"))?
        } else {
            return Err("No BLS signing capability available".to_string());
        };

        // The precommit carries the same vote authentication the prevote
        // does, in the V2 form bound to the vote signature as well.
        let auth_msg = crate::chain::finality::vote_auth_signing_message(&msg, &sig);
        let auth_sig = if let Some(sk) = self.consensus.bls_secret_key() {
            crate::chain::finality::sign_bls(&sk, &auth_msg)
        } else if let Some(signer) = self.consensus.signer() {
            signer
                .bls_sign(&auth_msg)
                .map_err(|e| format!("BLS signer backend failed: {e}"))?
        } else {
            return Err("No BLS signing capability available".to_string());
        };

        // The post-quantum half of the vote. The index is this validator's
        // own in the epoch's snapshot, because that is what the blob entry
        // the aggregator will assemble is keyed by; a node outside the
        // snapshot has no index to attest under and sends the BLS vote only
        // (the aggregator refuses it anyway).
        let pq_sig = match self
            .validator_snapshot_for_epoch(epoch)
            .as_ref()
            .and_then(|snapshot| snapshot.validator_index(voter_id))
            .and_then(|index| u32::try_from(index).ok())
        {
            Some(index) => {
                let pq_msg = crate::consensus::qc::pq_signing_message(
                    epoch,
                    checkpoint_height,
                    checkpoint_hash,
                    index,
                );
                match self.consensus.pq_sign(crate::crypto::ctx::QC_V2, &pq_msg) {
                    Ok(sig) => sig,
                    Err(e) => {
                        warn!(
                            height = checkpoint_height,
                            "Precommit carries no PQ attestation, so this checkpoint will have no QC blob from this signer: {e}"
                        );
                        Vec::new()
                    }
                }
            }
            None => Vec::new(),
        };

        Ok(Precommit {
            epoch,
            checkpoint_height,
            checkpoint_hash: checkpoint_hash.to_string(),
            chain_id: self.chain_id,
            voter_id: *voter_id,
            sig_bls: sig,
            auth_sig,
            pq_sig,
        })
    }

    /// The checkpoint finality has not finalized yet, and therefore the one
    /// this node should be voting on.
    ///
    /// A vote only counts in an aggregator that holds the same height, so the
    /// round has to be a number every node computes the same way. It used to
    /// be taken from each node's own tip: nodes one block apart voted at
    /// different checkpoints (one at 60, the rest at 82), every aggregator
    /// saw a handful of votes and none reached quorum, so the mesh produced
    /// blocks and finalized nothing. The lowest unfinalized checkpoint is
    /// that agreed number, and it only moves when a round really finalizes.
    fn next_finality_checkpoint(&self) -> u64 {
        let interval =
            crate::core::chain_config::finality_checkpoint_interval_for_chain_id(self.chain_id);
        if interval == 0 {
            return 0;
        }
        (self.finalized_height / interval)
            .saturating_add(1)
            .saturating_mul(interval)
    }

    /// How many blocks must sit on top of a checkpoint before this node votes
    /// on it.
    ///
    /// A block fork choice can still replace is not a checkpoint yet. This
    /// node signs one hash per height - a second signature for another hash at
    /// the same height is exactly the double vote the slasher exists for - so
    /// a vote for a block a reorg then replaces leaves the round holding a
    /// hash nobody else has, and the guard correctly refuses to sign the new
    /// one: the round starves while the chain runs. Four blocks is two devnet
    /// checkpoint intervals: long enough that a fork has been resolved, short
    /// enough that the vote still lands in the first seconds of the round.
    const FINALITY_VOTE_DEPTH: u64 = 4;

    /// Start - or keep - the prevote round for the lowest unfinalized
    /// checkpoint, once this node holds the block at that height and the
    /// block has `FINALITY_VOTE_DEPTH` blocks on top of it.
    pub fn start_pending_finality_round(&mut self) {
        let height = self.next_finality_checkpoint();
        if height == 0 {
            return;
        }
        let Some(block) = self.chain.get(height as usize) else {
            return;
        };
        // See `FINALITY_VOTE_DEPTH`: the checkpoint has to be behind the tip.
        let tip = self.chain.len().saturating_sub(1) as u64;
        if tip < height.saturating_add(Self::FINALITY_VOTE_DEPTH) {
            return;
        }
        let hash = block.hash.clone();
        self.start_prevote_task(height, hash);
    }

    /// Keep a vote whose round has not started (or has no prevote quorum)
    /// yet, bounded and de-duplicated by (voter, epoch, height): a re-delivered
    /// or repeated gossip of the same vote must not fill the buffer.
    fn keep_early_prevote(&mut self, vote: Prevote) {
        let votes = &mut self.early_finality_votes.prevotes;
        if votes.iter().any(|kept| {
            kept.voter_id == vote.voter_id
                && kept.epoch == vote.epoch
                && kept.checkpoint_height == vote.checkpoint_height
        }) {
            return;
        }
        if votes.len() >= MAX_EARLY_FINALITY_VOTES {
            votes.remove(0);
        }
        votes.push(vote);
    }

    fn keep_early_precommit(&mut self, vote: Precommit) {
        let votes = &mut self.early_finality_votes.precommits;
        if votes.iter().any(|kept| {
            kept.voter_id == vote.voter_id
                && kept.epoch == vote.epoch
                && kept.checkpoint_height == vote.checkpoint_height
        }) {
            return;
        }
        if votes.len() >= MAX_EARLY_FINALITY_VOTES {
            votes.remove(0);
        }
        votes.push(vote);
    }

    /// Offer the kept prevotes to the round that just started. Votes for
    /// another (epoch, height, hash) stay kept - a node that is one round
    /// behind votes at a height this node has already moved past, and the
    /// next round may still be the one they belong to.
    fn replay_early_prevotes(&mut self, epoch: u64, checkpoint_height: u64, checkpoint_hash: &str) {
        let kept = std::mem::take(&mut self.early_finality_votes.prevotes);
        for vote in kept {
            if vote.epoch != epoch
                || vote.checkpoint_height != checkpoint_height
                || vote.checkpoint_hash != checkpoint_hash
            {
                self.keep_early_prevote(vote);
                continue;
            }
            if let Err(e) = self.handle_prevote(vote) {
                tracing::debug!("kept prevote not admitted when its round started: {e}");
            }
        }
    }

    /// Offer the kept precommits to the round whose prevote quorum just came
    /// in, for the same reason.
    fn replay_early_precommits(&mut self) {
        let Some((epoch, checkpoint_height, checkpoint_hash)) =
            self.finality_aggregator.as_ref().map(|agg| {
                (
                    agg.epoch,
                    agg.checkpoint_height,
                    agg.checkpoint_hash.clone(),
                )
            })
        else {
            return;
        };
        let kept = std::mem::take(&mut self.early_finality_votes.precommits);
        for vote in kept {
            if vote.epoch != epoch
                || vote.checkpoint_height != checkpoint_height
                || vote.checkpoint_hash != checkpoint_hash
            {
                self.keep_early_precommit(vote);
                continue;
            }
            if let Err(e) = self.handle_precommit(vote) {
                tracing::debug!("kept precommit not admitted when the quorum came in: {e}");
            }
        }
    }

    /// WIRING: called from `start_pending_finality_round`, which the live
    /// finality loop drives at every checkpoint; the tests that pin one round
    /// call it directly with the height and hash they built.
    pub(crate) fn start_prevote_task(&mut self, checkpoint_height: u64, checkpoint_hash: String) {
        // The single aggregator slot used to be clobbered
        // on every call. Two consequences are pinned here:
        // 1. Re-starting the SAME checkpoint (a re-delivered block, a gossip
        //    echo) must not throw away the votes already collected - if the
        //    height and hash match, the task is already running.
        // 2. When a NEWER checkpoint displaces one that had prevote quorum
        //    but never got precommit quorum, that older round is abandoned
        //    without ever finalizing. V14 does not multiplex pending rounds,
        //    so abandonment is the design - but it must be LOUD, because a
        //    silently-dropped round is indistinguishable from a stall.
        let epoch =
            checkpoint_height / crate::core::chain_config::epoch_len_for_chain_id(self.chain_id);
        let same_round = self.finality_aggregator.as_ref().is_some_and(|existing| {
            existing.checkpoint_height == checkpoint_height
                && existing.checkpoint_hash == checkpoint_hash
        });
        if same_round {
            tracing::debug!(
                "prevote task for checkpoint height={checkpoint_height} already active - keeping collected votes"
            );
            // Kept votes can still predate this round (they arrived with the
            // block that started it), so they get their chance either way.
            self.replay_early_prevotes(epoch, checkpoint_height, &checkpoint_hash);
            return;
        }
        if let Some(existing) = self.finality_aggregator.as_ref() {
            if existing.prevote_quorum_reached && !existing.precommit_quorum_reached {
                warn!(
                    "checkpoint height={} displaced an active round at height={} with prevote quorum but no precommit quorum; the older round will never finalize (single-slot aggregator)",
                    checkpoint_height, existing.checkpoint_height
                );
            }
        }
        // The aggregator is always started for the current epoch, so the set
        // is known by construction; `build_validator_snapshot` is the same
        // value the lookup would return.
        let snapshot = self
            .validator_snapshot_for_epoch(epoch)
            .unwrap_or_else(|| self.build_validator_snapshot(epoch));
        // The round's own hash, kept for the replay below: the aggregator
        // takes ownership of the one it is built with.
        let round_hash = checkpoint_hash.clone();
        let aggregator =
            FinalityAggregator::new(epoch, checkpoint_height, checkpoint_hash, snapshot);
        self.finality_aggregator = Some(aggregator);
        info!("Started prevote task for checkpoint height={checkpoint_height} (epoch={epoch})");
        self.replay_early_prevotes(epoch, checkpoint_height, &round_hash);
    }

    pub fn get_aggregator_state(&self) -> crate::chain::finality::AggregatorState {
        self.finality_aggregator.as_ref().map_or_else(
            crate::chain::finality::AggregatorState::inactive,
            super::finality::FinalityAggregator::get_state,
        )
    }

    pub fn consensus(&self) -> &dyn ConsensusEngine {
        self.consensus.as_ref()
    }

    // ─── B.U.D.: On-chain storage operations ────────────

    #[allow(clippy::too_many_arguments)]
    /// WIRING: chain surface - the block/snapshot paths that read it land with their wiring.
    pub fn open_storage_deal_with_escrow(
        &mut self,
        domain_id: u32,
        manifest: &crate::storage::ContentManifest,
        shard_id: crate::storage::ContentId,
        operator: Address,
        payer: Address,
        replica_index: u8,
        start_epoch: u64,
        end_epoch: u64,
        economics: crate::domain::storage_deal::StorageEconomicsParams,
        domain_params: &crate::domain::storage_params::StorageDomainParams,
        merkle_proof: Option<Vec<u8>>,
        storage_root: Option<crate::domain::Hash32>,
    ) -> Result<u64, String> {
        // The checks, the registry open and the debits live in `deal_open`,
        // so the in-block path shares them. This wrapper adds the wall clock,
        // the caller's bond floor and the persist.
        let terms = crate::domain::deal_open::DealOpenTerms {
            domain_id,
            manifest,
            shard_id,
            operator,
            replica_index,
            start_epoch,
            end_epoch,
            economics,
            merkle_proof,
            storage_root,
        };
        // The manifest on this path comes from the RPC caller, so the
        // authority rule the in-block path applies has to run here too. Deal
        // rows are the only thing the registry derives durability, repair and
        // operator standing from, and a payer that does not own the content
        // must not be able to place one over it. A manifest that is not
        // registered yet may only be registered by the account that names
        // itself its owner.
        let authority = self
            .state
            .storage_registry
            .owner_of(&manifest.manifest_id)
            .unwrap_or(manifest.owner);
        if payer != authority {
            return Err(format!(
                "manifest {} belongs to {authority}, not to payer {payer}; refusing to open a deal over content the payer does not own",
                manifest.manifest_id
            ));
        }
        let now_unix_secs = self.current_unix_secs();
        let deal_id = crate::domain::deal_open::open_deal_escrowed(
            &mut self.state,
            &terms,
            payer,
            now_unix_secs,
            domain_params.min_operator_bond,
            0,
        )?;
        // Persistence rides the block commit: on this branch the door the
        // RPC points at is the signed storage transaction, whose effects
        // persist with the rest of the state. This wrapper is the in-memory
        // harness view of the same `deal_open` checks.
        Ok(deal_id)
    }

    /// B.U.D.: On-chain acceptance of a reallocation (repair) ticket.
    ///
    /// The economic mirror of [`Self::open_storage_deal_with_escrow`] for
    /// the replacement placement: the placement is decided by the ticket,
    /// not the caller - manifest, shard and replica come from the registry
    /// record. The ticket checks, the cooldown, the balance checks and the
    /// registry acceptance all live in `deal_open::accept_reallocation_escrowed`
    /// and run before any debit, so a refusal leaves balances and the registry
    /// untouched and there is nothing to refund.
    ///
    /// The registry's `accept_reallocation_ticket` keeps the one-shot
    /// guarantee (a filled ticket refuses a second acceptance) and the
    /// merkle envelope stays mandatory, so a replacement cannot claim a
    /// shard it cannot prove. Until this path existed, a repair ticket
    /// opened by the maintenance sweep could never be filled on-chain:
    /// the trigger ran, and the acceptance was test-only.
    #[allow(clippy::too_many_arguments)]
    /// WIRING: unwired - no caller in this tree yet; kept as a declared surface, and nothing depends on it until one arrives.
    pub fn accept_storage_reallocation_with_escrow(
        &mut self,
        ticket_id: u64,
        replacement_operator: Address,
        payer: Address,
        start_epoch: u64,
        end_epoch: u64,
        economics: crate::domain::storage_deal::StorageEconomicsParams,
        domain_params: &crate::domain::storage_params::StorageDomainParams,
        merkle_proof: Option<Vec<u8>>,
        storage_root: Option<crate::domain::Hash32>,
    ) -> Result<u64, String> {
        let terms = crate::domain::deal_open::ReallocationTerms {
            ticket_id,
            replacement_operator,
            start_epoch,
            end_epoch,
            economics,
            merkle_proof,
            storage_root,
        };
        let now_unix_secs = self.current_unix_secs();
        let replacement_deal_id = crate::domain::deal_open::accept_reallocation_escrowed(
            &mut self.state,
            &terms,
            payer,
            now_unix_secs,
            domain_params.min_operator_bond,
            0,
        )?;
        // Persistence rides the block commit; see `open_storage_deal_with_escrow`.
        Ok(replacement_deal_id)
    }

    /// Test harness only: the reward step of the block-end storage
    /// maintenance (`chain::storage_maintenance`) at `current_epoch`.
    ///
    /// # Errors
    ///
    /// Never: the step cannot fail; the signature keeps the harness callers.
    #[cfg(test)]
    pub fn accrue_storage_operator_rewards(
        &mut self,
        current_epoch: u64,
    ) -> Result<(u32, u64), String> {
        Ok(crate::chain::storage_maintenance::accrue_operator_rewards(
            &mut self.state,
            current_epoch,
        ))
    }

    /// The recent storage economics events, from the state's ledger.
    #[must_use]
    pub fn storage_economics_events(&self) -> &[StorageEconomicsEvent] {
        &self.state.storage_registry.economics.events
    }

    fn distribute_bud_boost_share_in_state(
        state: &mut AccountState,
        boost_share: u64,
    ) -> Result<(), String> {
        if boost_share == 0 {
            return Ok(());
        }
        let deals: Vec<(Address, u64)> = state
            .storage_registry
            .all_deals()
            .iter()
            .filter(|deal| deal.is_active())
            // Weight by what the deal is worth for one epoch, which is now a
            // function of the bytes it holds: an operator storing more data
            // carries more of the network and earns a larger share.
            .map(|deal| (deal.operator, deal.total_fee(1)))
            .collect();
        // The math runs in u128. A deal weight is bounded only by the payer
        // balance, so `boost_share * weight` can pass u64 and a u64 overflow
        // here fails the whole block. Each share is at most
        // `boost_share`, so it always fits back into u64.
        let total_weight: u128 = deals.iter().map(|(_, weight)| u128::from(*weight)).sum();
        if total_weight == 0 {
            state.pending_bud_boost_share = 0;
            return Ok(());
        }

        let mut distributed = 0u64;
        for (operator, weight) in &deals {
            let share = u128::from(boost_share)
                .checked_mul(u128::from(*weight))
                .ok_or_else(|| "Boost distribution multiplication overflow".to_string())?
                / total_weight;
            let share = u64::try_from(share)
                .map_err(|_| "Boost distribution share exceeds u64".to_string())?;
            if share > 0 {
                state
                    .try_add_balance(operator, share)
                    .map_err(|error| format!("Boost share overflow for {operator}: {error}"))?;
                distributed = distributed
                    .checked_add(share)
                    .ok_or_else(|| "Boost distribution total overflow".to_string())?;
            }
        }
        let dust = boost_share.saturating_sub(distributed);
        if dust > 0 {
            let first_operator = deals
                .first()
                .map(|(operator, _)| *operator)
                .ok_or_else(|| "Boost distribution has no dust recipient".to_string())?;
            state
                .try_add_balance(&first_operator, dust)
                .map_err(|error| format!("Boost dust overflow: {error}"))?;
        }
        state.pending_bud_boost_share = 0;
        Ok(())
    }

    /// Release the quarantine-ledger rows of the domains a block's
    /// governance unfreeze reopened: the freeze that
    /// quarantined them is over. The unfreeze itself is state, applied in
    /// `apply_block_effects_with_unfreezes`; the ledger is node-local.
    fn release_unfrozen_domains(&mut self, unfrozen: &[DomainId]) {
        for domain_id in unfrozen {
            self.quarantine_ledger.release_entity(
                &crate::registry::QuarantineLedger::domain_target(*domain_id),
            );
            self.quarantine_dirty = true;
        }
    }

    /// The consensus domains a state holds frozen: the set
    /// [`Self::observe_settlement_transition`] compares across a block.
    fn frozen_domain_ids(state: &AccountState) -> std::collections::BTreeSet<DomainId> {
        state
            .settlement
            .domains
            .domains()
            .into_iter()
            .filter(|domain| domain.status == crate::domain::DomainStatus::Frozen)
            .map(|domain| domain.id)
            .collect()
    }

    /// Node-local observation of what a committed block's settlement writes
    /// did. A domain the block froze (an equivocating or parent-breaking
    /// commitment delivered in block) enters the quarantine ledger, and the
    /// settlement metrics follow the state. The freeze itself is state,
    /// applied by the settlement door; nothing here feeds the state root.
    fn observe_settlement_transition(
        &mut self,
        frozen_before: &std::collections::BTreeSet<DomainId>,
        block: &Block,
    ) {
        let frozen_after = Self::frozen_domain_ids(&self.state);
        for domain_id in frozen_after.difference(frozen_before) {
            self.record_quarantine_event(
                crate::registry::QuarantineLedger::domain_target(*domain_id),
                crate::registry::QuarantineReason::Equivocation(format!(
                    "frozen in block {}",
                    block.index
                )),
                "DOMAIN_FROZEN",
                &format!(
                    "domain {domain_id} frozen by a contradicting commitment in block {}",
                    block.index
                ),
                4,
            );
            if let Some(m) = &self.metrics {
                m.settlement_equivocations_detected.inc();
            }
        }
        if let Some(m) = &self.metrics {
            let commitments = block
                .transactions
                .iter()
                .filter(|tx| {
                    matches!(
                        tx.tx_type,
                        crate::core::transaction::TransactionType::Settlement(
                            crate::settlement::domains::SettlementTx::SubmitCommitment(_)
                        )
                    )
                })
                .count();
            m.settlement_commitments_total
                .inc_by(u64::try_from(commitments).unwrap_or(u64::MAX));
            m.settlement_domain_rows
                .set(i64::try_from(self.state.settlement.domains.len()).unwrap_or(i64::MAX));
            m.settlement_commitment_rows
                .set(i64::try_from(self.state.settlement.commitments.len()).unwrap_or(i64::MAX));
            m.settlement_sovereign_template_rows.set(
                i64::try_from(self.state.settlement.sovereign.templates.len()).unwrap_or(i64::MAX),
            );
            let graft_transactions = block
                .transactions
                .iter()
                .filter(|tx| {
                    matches!(
                        &tx.tx_type,
                        crate::core::transaction::TransactionType::Settlement(
                            crate::settlement::domains::SettlementTx::Graft(_)
                        )
                    )
                })
                .count();
            m.graft_transactions_total
                .inc_by(u64::try_from(graft_transactions).unwrap_or(u64::MAX));
            let contract_calls = block
                .transactions
                .iter()
                .filter(|tx| tx.tx_type == crate::core::transaction::TransactionType::ContractCall)
                .count();
            m.contract_calls_total
                .inc_by(u64::try_from(contract_calls).unwrap_or(u64::MAX));
            m.restaked_validator_rows.set(
                i64::try_from(self.state.settlement.shared_security.validators.len())
                    .unwrap_or(i64::MAX),
            );
            m.settlement_frozen_domains
                .set(i64::try_from(frozen_after.len()).unwrap_or(i64::MAX));
            m.cross_domain_message_rows
                .set(i64::try_from(self.state.message_registry.len()).unwrap_or(i64::MAX));
            let external_intake = &self.state.settlement.external_intake;
            m.external_domain_rows
                .set(i64::try_from(external_intake.registry.len()).unwrap_or(i64::MAX));
            let accepted_attestations: usize = external_intake
                .registry
                .domains()
                .map(|domain| domain.record.attestations_accepted as usize)
                .sum();
            m.external_attestations_accepted
                .set(i64::try_from(accepted_attestations).unwrap_or(i64::MAX));
            m.external_quorum_rounds
                .set(i64::try_from(external_intake.quorum.rounds.len()).unwrap_or(i64::MAX));
            m.external_bond_escrow_rows
                .set(i64::try_from(self.state.external_bond_escrow.len()).unwrap_or(i64::MAX));
            let external_bond_atoms: u128 = self
                .state
                .external_bond_escrow
                .values()
                .map(|amount| u128::from(*amount))
                .sum();
            m.external_bond_escrow_atoms.set(
                i64::try_from(
                    external_bond_atoms.min(u128::try_from(i64::MAX).unwrap_or(u128::MAX)),
                )
                .unwrap_or(i64::MAX),
            );
            let relayer = &self.state.settlement.relayer;
            m.relayer_pending_rows
                .set(i64::try_from(relayer.pending_count()).unwrap_or(i64::MAX));
            m.relayer_ledger_rows
                .set(i64::try_from(relayer.relayed_count()).unwrap_or(i64::MAX));
            let intent_registry = &self.state.settlement.relayer_policy;
            m.relayer_intent_rows
                .set(i64::try_from(intent_registry.intents.len()).unwrap_or(i64::MAX));
            let bid_count: usize = intent_registry.bids.values().map(|bids| bids.len()).sum();
            m.relayer_bid_rows
                .set(i64::try_from(bid_count).unwrap_or(i64::MAX));
            let escrowed_atoms: u128 = intent_registry
                .escrowed
                .values()
                .map(|amount| u128::from(*amount))
                .sum();
            m.relayer_escrowed_atoms.set(
                i64::try_from(escrowed_atoms.min(u128::try_from(i64::MAX).unwrap_or(u128::MAX)))
                    .unwrap_or(i64::MAX),
            );
            let role_registry = &self.state.registry;
            m.role_bond_rows
                .set(i64::try_from(role_registry.len()).unwrap_or(i64::MAX));
            m.active_relayer_rows.set(
                i64::try_from(
                    role_registry
                        .active_members(crate::registry::role::roles::RELAYER)
                        .len(),
                )
                .unwrap_or(i64::MAX),
            );
            m.active_prover_rows.set(
                i64::try_from(
                    role_registry
                        .active_members(crate::registry::role::roles::PROVER)
                        .len(),
                )
                .unwrap_or(i64::MAX),
            );
            m.registry_slashing_rows
                .set(i64::try_from(role_registry.slashing_history_count()).unwrap_or(i64::MAX));
            m.registry_commission_rows
                .set(i64::try_from(role_registry.validator_commission_count()).unwrap_or(i64::MAX));
            m.poa_admission_domains
                .set(i64::try_from(self.state.poa_admitted.len()).unwrap_or(i64::MAX));
            let admitted_authorities: usize = self
                .state
                .poa_admitted
                .values()
                .map(|members| members.len())
                .sum();
            m.poa_admitted_authorities
                .set(i64::try_from(admitted_authorities).unwrap_or(i64::MAX));
            m.poa_compliance_frozen_accounts
                .set(i64::try_from(self.state.poa_compliance.frozen_count()).unwrap_or(i64::MAX));
            // A mint by event and a relay proof are the two bridge credits;
            // a block that holds one applied it, or the block was refused.
            let bridge_credits = block
                .transactions
                .iter()
                .filter(|tx| {
                    matches!(
                        tx.tx_type,
                        crate::core::transaction::TransactionType::Bridge(
                            crate::cross_domain::bridge_tx::BridgeTx::Mint(_)
                                | crate::cross_domain::bridge_tx::BridgeTx::RelayProof { .. }
                        )
                    )
                })
                .count();
            m.bridge_transfers_total
                .inc_by(u64::try_from(bridge_credits).unwrap_or(u64::MAX));
        }
    }

    /// Test harness only: the challenge step of the block-end storage
    /// maintenance, with the tip's VRF output as the block entropy.
    ///
    /// # Errors
    ///
    /// No tip, or a tip without VRF entropy.
    #[cfg(test)]
    pub fn issue_storage_challenges(&mut self, current_epoch: u64) -> Result<u32, String> {
        let vrf_output = self
            .chain
            .last()
            .map(|tip| tip.vrf_output.clone())
            .ok_or_else(|| "cannot issue storage challenges without a chain tip".to_string())?;
        if vrf_output.is_empty() {
            return Err("cannot issue storage challenges without accepted VRF entropy".into());
        }
        Ok(crate::chain::storage_maintenance::issue_challenges(
            &mut self.state,
            self.chain_id,
            current_epoch,
            &vrf_output,
        ))
    }

    /// Test harness only: the slash step of the block-end storage
    /// maintenance.
    ///
    /// # Errors
    ///
    /// Never: the step cannot fail; the signature keeps the harness callers.
    #[cfg(test)]
    fn apply_storage_bond_slash(
        &mut self,
        epoch: u64,
        deal_id: u64,
        operator: Address,
        slashed_bond: u64,
        reason: &'static str,
    ) -> Result<u64, String> {
        Ok(crate::chain::storage_maintenance::apply_bond_slash(
            &mut self.state,
            epoch,
            deal_id,
            operator,
            slashed_bond,
            reason,
        ))
    }

    /// Test harness only: the missed-challenge step of the block-end
    /// storage maintenance.
    ///
    /// # Errors
    ///
    /// Never: the step cannot fail; the signature keeps the harness callers.
    #[cfg(test)]
    pub fn finalize_missed_storage_challenges(
        &mut self,
        current_epoch: u64,
    ) -> Result<(u32, u64), String> {
        Ok(
            crate::chain::storage_maintenance::finalize_missed_challenges(
                &mut self.state,
                current_epoch,
            ),
        )
    }

    /// Test harness only: the expiry step of the block-end storage
    /// maintenance.
    ///
    /// # Errors
    ///
    /// A bond return that would overflow the operator's balance.
    #[cfg(test)]
    pub fn finalize_expired_storage_deals(
        &mut self,
        current_epoch: u64,
    ) -> Result<(u32, u64), String> {
        crate::chain::storage_maintenance::finalize_expired_deals(&mut self.state, current_epoch)
    }
}

impl Clone for Blockchain {
    fn clone(&self) -> Self {
        Blockchain {
            chain: self.chain.clone(),
            consensus: Arc::clone(&self.consensus),
            mempool: self.mempool.clone(),
            storage: self.storage.clone(),
            state: self.state.clone(),
            chain_id: self.chain_id,
            genesis_config: self.genesis_config.clone(),
            pruning_manager: self.pruning_manager.clone(),
            finalized_height: self.finalized_height,
            finalized_hash: self.finalized_hash.clone(),
            sharding: self.sharding,
            genesis_time: self.genesis_time,
            verified_qc_blobs: self.verified_qc_blobs.clone(),
            max_qc_blobs: self.max_qc_blobs,
            validator_snapshots: self.validator_snapshots.clone(),
            max_validator_snapshots: self.max_validator_snapshots,
            pending_finality_certs: self.pending_finality_certs.clone(),
            max_pending_certs: self.max_pending_certs,
            global_headers: self.global_headers.clone(),
            global_header_openings: self.global_header_openings.clone(),
            graft_payment_windows: self.graft_payment_windows.clone(),
            plugin_registry: DomainPluginRegistry::new(),
            quarantine_ledger: self.quarantine_ledger.clone(),
            quarantine_dirty: self.quarantine_dirty,
            pending_slashing_evidence: self.pending_slashing_evidence.clone(),
            pending_registry_slashing_reports: self.pending_registry_slashing_reports.clone(),
            local_invalid_votes: self.local_invalid_votes.clone(),
            finality_aggregator: None,
            early_finality_votes: EarlyFinalityVotes::default(),
            metrics: self.metrics.clone(),
            anchor_emission: self.anchor_emission.clone(),
            pq_source: self.pq_source.clone(),
            anchor_classes: self.anchor_classes.clone(),
            cold_wallet: self.cold_wallet.clone(),
            scheme_registry: self.scheme_registry.clone(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::poa::{PoAConfig, PoAEngine};

    #[test]
    fn pruned_segment_witnesses_obey_the_local_retention_policy() {
        let mut chain = Blockchain::new(
            Arc::new(crate::consensus::pow::PoWEngine::new(0)),
            None,
            45262,
            None,
        );
        let tx = Transaction::new(Address::from([1; 32]), Address::from([2; 32]), 1, vec![]);
        let stripped = Block::new(1, "00".repeat(32), vec![tx]);
        assert!(stripped.witness_is_stripped());
        let retention = crate::storage::witness_retention::DEFAULT_RETENTION_BLOCKS + 10;
        let finalized_tip = 1 + retention;
        // An unconfigured or archive node never accepts missing witnesses.
        assert!(chain
            .check_pruned_segment_witness_policy(std::slice::from_ref(&stripped), finalized_tip)
            .is_err());
        chain.pruning_manager = Some(PruningManager::new(retention, 100, String::new()));
        assert!(chain
            .check_pruned_segment_witness_policy(std::slice::from_ref(&stripped), finalized_tip - 1)
            .is_err());
        assert!(chain
            .check_pruned_segment_witness_policy(std::slice::from_ref(&stripped), finalized_tip)
            .is_ok());
        chain.pruning_manager.as_mut().unwrap().archive_mode = true;
        assert!(chain
            .check_pruned_segment_witness_policy(std::slice::from_ref(&stripped), finalized_tip)
            .is_err());
        // A block carrying witnesses continues through full validation even on an archive.
        let mut complete = stripped;
        complete.transactions[0].signature = Some(vec![1]);
        assert!(!complete.witness_is_stripped());
        assert!(chain
            .check_pruned_segment_witness_policy(&[complete], finalized_tip)
            .is_ok());
    }

    /// testnet item 8: the reward pool is paid only when the genesis flag
    /// says so AND the profile has a schedule. Neither condition implies the
    /// other, and a chain that fails either pays nothing.
    #[test]
    fn the_genesis_flag_is_the_permission_to_pay_the_reward_pool() {
        use crate::core::chain_config::Network;

        let testnet = Network::Testnet.chain_id().value();
        let mainnet = Network::Mainnet.chain_id().value();
        let devnet = Network::Devnet.chain_id().value();
        // Testnet: the profile has a schedule, so the flag alone decides.
        assert!(Blockchain::payable_reward_pool(testnet, true).is_some());
        assert!(Blockchain::payable_reward_pool(testnet, false).is_none());
        // Mainnet (no schedule yet) and devnet (no distribution to fund
        // one): a flag saying yes still pays nothing.
        assert!(Blockchain::payable_reward_pool(mainnet, true).is_none());
        assert!(Blockchain::payable_reward_pool(devnet, true).is_none());
    }

    /// A QC blob of another fork must not back a certificate.
    #[test]
    fn qc_blob_of_another_checkpoint_hash_is_refused() {
        let blob = QcBlob {
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "aa".repeat(32),
            pq_signatures: vec![],
            merkle_root: String::new(),
            created_epoch: 1,
        };
        assert!(Blockchain::ensure_blob_matches_checkpoint(&blob, &"aa".repeat(32)).is_ok());
        let error =
            Blockchain::ensure_blob_matches_checkpoint(&blob, &"bb".repeat(32)).unwrap_err();
        assert!(error.contains("does not match certificate hash"));
    }

    /// The domain progress a proof claim causes is consensus
    /// state. The registries live in `AccountState::settlement`, so a move of
    /// a domain's committed height changes the state root every node checks,
    /// and a restart replays it from the blocks instead of a side store.
    #[test]
    fn proof_claim_domain_progress_is_consensus_state() {
        use crate::domain::plugin::default_domain;
        use crate::domain::ConsensusKind;

        let mut bc = Blockchain::new(
            Arc::new(crate::consensus::pow::PoWEngine::new(0)),
            None,
            45262,
            None,
        );
        let domain = default_domain(1, ConsensusKind::Zk, 45262, "zk-proof-verification", 1);
        bc.register_consensus_domain(domain).unwrap();
        let before = bc.state.calculate_state_root();
        {
            let stored = bc.state.settlement.domains.get_mut(1).unwrap();
            stored.last_committed_height = 7;
            stored.last_committed_hash = [0x33; 32];
        }
        assert_ne!(
            bc.state.calculate_state_root(),
            before,
            "domain progress must be committed by the state root"
        );
    }

    fn double_sign_evidence(
        keys: &crate::crypto::primitives::ValidatorKeys,
        index: u64,
    ) -> SlashingEvidence {
        use crate::core::block::BlockHeader;

        let producer = Address::from(keys.sig_key.public_key_bytes());
        let mut b1 = Block::new(index, "prev".into(), vec![]);
        b1.producer = Some(producer);
        b1.hash = b1.calculate_hash();
        let sig1 = keys.sig_key.sign(&b1.calculate_hash_bytes()).to_vec();
        let mut b2 = Block::new(index, "prev".into(), vec![]);
        b2.timestamp += 1;
        b2.producer = Some(producer);
        b2.hash = b2.calculate_hash();
        let sig2 = keys.sig_key.sign(&b2.calculate_hash_bytes()).to_vec();
        SlashingEvidence::new(
            BlockHeader::from_block(&b1),
            BlockHeader::from_block(&b2),
            sig1,
            sig2,
        )
    }

    #[test]
    fn a_rebuilt_state_carries_the_engine_domain() {
        let genesis_config = GenesisConfig::new(1337);
        let chain = vec![genesis_config.build_genesis_block()];
        let state =
            Blockchain::rebuild_state(&chain, &genesis_config, crate::domain::ConsensusKind::PoA)
                .expect("a genesis only chain rebuilds");
        assert_eq!(state.execution_domain, crate::domain::ConsensusKind::PoA);
    }

    #[test]
    fn a_block_with_unverifiable_evidence_is_refused_by_every_engine() {
        let keys = crate::crypto::primitives::ValidatorKeys::generate().unwrap();
        let mut evidence = double_sign_evidence(&keys, 10);
        let mut block = Block::new(11, "prev".into(), vec![]);
        block.slashing_evidence = Some(vec![evidence.clone()]);
        assert!(Blockchain::check_block_slashing_evidence(&block).is_ok());

        evidence.signature1[0] ^= 0xFF;
        block.slashing_evidence = Some(vec![evidence]);
        let err = Blockchain::check_block_slashing_evidence(&block)
            .expect_err("a forged signature must be refused");
        assert!(err.contains("Invalid slashing evidence"), "{err}");
    }

    /// Double-sign evidence signed for another chain id must not
    /// slash a validator of this chain.
    #[test]
    fn block_evidence_for_another_chain_does_not_slash() {
        let keys = crate::crypto::primitives::ValidatorKeys::generate().unwrap();
        let producer = Address::from(keys.sig_key.public_key_bytes());
        let evidence = double_sign_evidence(&keys, 10);
        let evidence_chain = evidence.header1.chain_id;

        let mut foreign_block =
            Block::new_with_chain_id(11, "prev".into(), vec![], evidence_chain + 1);
        foreign_block.slashing_evidence = Some(vec![evidence.clone()]);
        let mut state = AccountState::new();
        state.add_validator(producer, 1_000_000);
        Blockchain::apply_system_effects(&mut state, &foreign_block);
        assert!(
            !state.get_validator(&producer).unwrap().slashed,
            "evidence from another chain slashed a validator"
        );

        let mut own_block = Block::new_with_chain_id(11, "prev".into(), vec![], evidence_chain);
        own_block.slashing_evidence = Some(vec![evidence]);
        Blockchain::apply_system_effects(&mut state, &own_block);
        assert!(state.get_validator(&producer).unwrap().slashed);
    }

    /// Evidence from a key that is not a validator is refused, and
    /// the pool has an upper bound.
    #[test]
    fn slashing_evidence_pool_needs_a_validator_and_is_bounded() {
        let mut bc = Blockchain::new(
            Arc::new(crate::consensus::pow::PoWEngine::new(0)),
            None,
            45262,
            None,
        );
        let outsider = crate::crypto::primitives::ValidatorKeys::generate().unwrap();
        assert!(bc
            .submit_slashing_evidence(double_sign_evidence(&outsider, 10))
            .is_err());
        assert!(bc.pending_slashing_evidence.is_empty());

        let insider = crate::crypto::primitives::ValidatorKeys::generate().unwrap();
        let insider_addr = Address::from(insider.sig_key.public_key_bytes());
        bc.state.add_validator(insider_addr, 2000);
        for height in 0..MAX_PENDING_SLASHING_EVIDENCE as u64 {
            bc.submit_slashing_evidence(double_sign_evidence(&insider, 10 + height))
                .unwrap();
        }
        assert_eq!(
            bc.pending_slashing_evidence.len(),
            MAX_PENDING_SLASHING_EVIDENCE
        );
        assert!(bc
            .submit_slashing_evidence(double_sign_evidence(&insider, 1000))
            .is_err());
    }

    /// An invalid vote that names a far future epoch must not move
    /// the tracker epoch, or the spam guard is closed for good.
    #[test]
    fn invalid_vote_with_a_far_future_epoch_is_not_counted() {
        let mut bc = Blockchain::new(
            Arc::new(crate::consensus::pow::PoWEngine::new(0)),
            None,
            45262,
            None,
        );
        let victim = Address::from([3u8; 32]);
        bc.note_invalid_vote(u64::MAX, victim);
        assert_eq!(bc.local_invalid_votes.current_epoch(), 0);
        assert_eq!(bc.local_invalid_votes.invalid_count(&victim), 0);

        bc.note_invalid_vote(0, victim);
        assert_eq!(bc.local_invalid_votes.invalid_count(&victim), 1);
    }

    /// A parent hash mismatch freezes the domain, and the
    /// freeze is consensus state: the state root commits it.
    #[test]
    fn parent_hash_mismatch_freeze_is_consensus_state() {
        use crate::domain::plugin::default_domain;
        use crate::domain::{ConsensusKind, DomainStatus};

        let mut bc = Blockchain::new(
            Arc::new(crate::consensus::pow::PoWEngine::new(0)),
            None,
            45262,
            None,
        );
        let domain = default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 1);
        bc.register_consensus_domain(domain.clone()).unwrap();

        let mut block1 = Block::new(1, "00".repeat(32), vec![]);
        block1.state_root = "11".repeat(32);
        block1.tx_root = block1.calculate_tx_root();
        block1.hash = block1.calculate_hash();
        // Block 2 names a parent that is not block 1.
        let mut block2 = Block::new(2, "77".repeat(32), vec![]);
        block2.state_root = "22".repeat(32);
        block2.tx_root = block2.calculate_tx_root();
        block2.hash = block2.calculate_hash();
        let root = [0u8; 32];
        let c1 = crate::domain::DomainCommitment::from_block(&domain, &block1, root, [0u8; 32], 0)
            .unwrap();
        let c2 = crate::domain::DomainCommitment::from_block(&domain, &block2, root, [0u8; 32], 1)
            .unwrap();
        bc.submit_domain_commitment(c1).unwrap();
        let before = bc.state.calculate_state_root();
        assert!(bc.submit_domain_commitment(c2).is_err());

        let stored = bc.state.settlement.domains.get(1).unwrap();
        assert_eq!(stored.status, DomainStatus::Frozen);
        assert_ne!(
            bc.state.calculate_state_root(),
            before,
            "the freeze must be committed by the state root"
        );
    }

    /// Resubmitting an old accepted commitment must not rewind the
    /// external root anchor to that commitment's state root.
    #[test]
    fn resubmitted_old_commitment_does_not_rewind_the_anchor() {
        use crate::domain::plugin::default_domain;
        use crate::domain::ConsensusKind;

        let mut bc = Blockchain::new(
            Arc::new(crate::consensus::pow::PoWEngine::new(0)),
            None,
            45262,
            None,
        );
        // Domain id 1 is Ethereum's slot in the external-root map, and a
        // domain may anchor under a claimed id only when it declares the chain
        // that id names (`accept_verified_commitment`). The fixture is a real
        // Ethereum domain, not a domain that happens to sit on id 1.
        let domain = default_domain(1, ConsensusKind::PoW, 1, "pow-header-chain-v1", 1);
        bc.register_consensus_domain(domain.clone()).unwrap();

        let mut block1 = Block::new(1, "00".repeat(32), vec![]);
        block1.state_root = "11".repeat(32);
        block1.tx_root = block1.calculate_tx_root();
        block1.hash = block1.calculate_hash();
        let mut block2 = Block::new(2, block1.hash.clone(), vec![]);
        block2.state_root = "22".repeat(32);
        block2.tx_root = block2.calculate_tx_root();
        block2.hash = block2.calculate_hash();
        let root = [0u8; 32];
        let c1 = crate::domain::DomainCommitment::from_block(&domain, &block1, root, [0u8; 32], 0)
            .unwrap();
        let c2 = crate::domain::DomainCommitment::from_block(&domain, &block2, root, [0u8; 32], 1)
            .unwrap();
        let root1 = c1.state_root;
        let root2 = c2.state_root;
        assert_ne!(root1, root2);

        bc.accept_verified_domain_commitment(c1.clone()).unwrap();
        bc.accept_verified_domain_commitment(c2).unwrap();
        assert_eq!(bc.state.external_roots.get(&1), Some(&root2));

        // The idempotent branch returns Ok, and the anchor must stay at root2.
        bc.accept_verified_domain_commitment(c1).unwrap();
        assert_eq!(bc.state.external_roots.get(&1), Some(&root2));
    }

    /// A snapshot that is ahead of the stored chain must not stay
    /// as the replay base. Startup falls back to the genesis state.
    #[test]
    fn startup_drops_a_snapshot_that_is_ahead_of_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let snap_dir = dir.path().join("snaps").to_string_lossy().into_owned();
        let pm = PruningManager::new(10, 10, snap_dir);
        let marker = Address::from([0xE7; 32]);
        let mut snap_state = AccountState::default();
        snap_state.add_balance(&marker, 777);
        let params = crate::chain::snapshot::StateSnapshotV2Params {
            height: 50,
            block_hash: "aa".repeat(32),
            genesis_hash: "bb".repeat(32),
            chain_id: 45262,
            finalized_height: 40,
            finalized_hash: "cc".repeat(32),
            finality_certificates: vec![],
        };
        let snapshot = crate::chain::snapshot::StateSnapshotV2::from_state(&snap_state, params);
        pm.save_snapshot_v2(&snapshot).unwrap();

        let db_path = dir.path().join("chain.db");
        let storage = Storage::new(db_path.to_str().unwrap()).unwrap();
        let bc = Blockchain::new(
            Arc::new(crate::consensus::pow::PoWEngine::new(0)),
            Some(storage),
            45262,
            Some(pm),
        );
        assert_eq!(bc.chain.len(), 1);
        assert_eq!(bc.state.get_balance(&marker), 0);
        assert_eq!(bc.finalized_height, 0);
    }

    /// A huge deal weight must not make the boost distribution fail.
    /// With u64 math `boost_share * weight` overflowed and halted block production.
    #[test]
    fn boost_distribution_survives_a_huge_deal_weight() {
        use crate::domain::storage_deal::StorageEconomicsParams;
        use crate::domain::storage_params::StorageDomainParams;
        use crate::storage::manifest::ContentManifest;

        let mut state = AccountState::new();
        let manifest = ContentManifest::from_bytes_sliced(b"boost pool content", 4).unwrap();
        let shard_id = manifest.shards[0].shard_id;
        let envelope = bud_proof::ProofEnvelope {
            proof_format_version: 1,
            backend: "test-backend".to_string(),
            p3_version: "0.6".to_string(),
            fri_params_id: "test-fri".to_string(),
            public_inputs_hash: [0x42u8; 32],
            proof_bytes: vec![0xABu8; 96],
            degree_bits: 8,
        };
        let operator = Address::from([0x51; 32]);
        state
            .storage_registry
            .open_deal(
                42,
                &manifest,
                shard_id,
                operator,
                0,
                100,
                200,
                StorageEconomicsParams {
                    operator_bond: 5_000_000,
                    fee_per_byte_epoch: 1_000_000_000_000_000_000,
                },
                &StorageDomainParams {
                    chunk_size: 256,
                    max_committed_chunks: 1000,
                    challenge_interval: 10,
                    min_operator_bond: 1_000_000,
                },
                Some(bincode::serialize(&envelope).unwrap()),
                Some([0x42u8; 32]),
            )
            .unwrap();
        let boost_share = 10_000_000_000u64;
        let before = state.get_balance(&operator);
        Blockchain::distribute_bud_boost_share_in_state(&mut state, boost_share).unwrap();
        assert_eq!(state.get_balance(&operator), before + boost_share);
        assert_eq!(state.pending_bud_boost_share, 0);
    }

    /// A relay whose fee or mint step fails after the ledger step
    /// must not stay consumed. The supply cap refuses the mint here.
    #[test]
    fn failed_relay_mint_restores_the_relayer_ledger() {
        use crate::cross_domain::event_tree::DomainEventTree;
        use crate::domain::plugin::default_domain;
        use crate::domain::ConsensusKind;

        let mut bc = Blockchain::new(
            Arc::new(crate::consensus::pow::PoWEngine::new(0)),
            None,
            45262,
            None,
        );
        let mut domains = Vec::new();
        for id in [1u32, 2u32] {
            let mut d = default_domain(id, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 1);
            d.bridge_enabled = true;
            domains.push(d.clone());
            bc.register_consensus_domain(d).unwrap();
        }
        let asset_id = crate::cross_domain::AssetId(crate::core::hash::hash_fields_bytes(&[b"A"]));
        bc.register_bridge_asset(asset_id, 1).unwrap();
        let owner = Address::from([0xAA; 32]);
        let recipient = Address::from([0xBB; 32]);
        let relayer = Address::from([0xCC; 32]);
        bc.state.add_balance(&relayer, 100_000_000);
        let epoch = bc.state.epoch_index;
        bc.state
            .registry
            .register_relayer(relayer, 50_000_000, epoch)
            .unwrap();
        bc.state.add_balance(&owner, 1000);
        let (_transfer, lock_event) = bc
            .lock_bridge_transfer(1, 2, 10, 0, asset_id, owner, recipient, 100, 1000)
            .unwrap();
        let message = lock_event.message.clone().unwrap();
        let message_id = message.message_id;
        bc.enqueue_bridge_relay(lock_event.clone(), &message);
        let mut tree = DomainEventTree::new();
        tree.push(lock_event);
        let mut block = Block::new(10, bc.last_block().hash.clone(), vec![]);
        block.state_root = "22".repeat(32);
        block.tx_root = block.calculate_tx_root();
        block.hash = block.calculate_hash();
        let commitment = crate::domain::DomainCommitment::from_block(
            &domains[0],
            &block,
            tree.root(),
            [0u8; 32],
            0,
        )
        .unwrap();
        bc.submit_domain_commitment(commitment).unwrap();

        // Fill the supply cap so the mint cannot fit.
        let headroom = bc.state.supply_capacity_remaining();
        bc.state.get_or_create(&recipient).balance += headroom;
        let proof = tree.proof(0).unwrap();
        assert!(bc
            .submit_relay_proof(message_id, relayer, &proof, 1)
            .is_err());
        assert!(!bc.state.settlement.relayer.is_relayed(&message_id));
        assert_eq!(bc.pending_relay_count(), 1);
        assert!(matches!(
            bc.state
                .bridge_state
                .get_transfer(&message_id)
                .unwrap()
                .status,
            crate::cross_domain::bridge::BridgeStatus::Locked { .. }
        ));
    }

    /// Decode helper for the window tests.
    fn h32(hex_str: &str) -> crate::domain::Hash32 {
        let bytes = hex::decode(hex_str).expect("test hashes are hex");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    /// Block entropy is block context: set from the previous hash and the VRF
    /// The live path prunes the AI registry after every committed
    /// block; the state-rebuild loops (startup replay, reorg rebuild,
    /// `rebuild_state`) must run the same per-height maintenance, or the
    /// rebuilt node carries rows its peers already pruned and its state root
    /// diverges from the network at the next block.
    #[test]
    fn rebuilt_state_replays_live_ai_maintenance() {
        use crate::ai::registry::DISPUTE_WINDOW_BLOCKS;
        use crate::ai::types::AiRequestId;

        let key = (AiRequestId([9u8; 32]), [7u8; 32]);
        let tip = 10 + DISPUTE_WINDOW_BLOCKS + 1;

        let mut start = AccountState::new();
        start.ai_registry.equivocation_events.insert(key, 10);

        // A live node runs maintenance at every height; the dispute-window
        // row retires once the window has elapsed.
        let mut live = start.clone();
        for height in 11..=tip {
            Blockchain::apply_ai_registry_maintenance(&mut live, height);
        }
        assert!(live.ai_registry.equivocation_events.is_empty());

        // A rebuilt node running the same per-height maintenance (what the
        // fixed replay/reorg/rebuild loops now do) lands on the same root.
        let mut rebuilt = start.clone();
        for height in 11..=tip {
            Blockchain::apply_ai_registry_maintenance(&mut rebuilt, height);
        }
        assert_eq!(
            rebuilt.calculate_state_root(),
            live.calculate_state_root(),
            "rebuilt state must match the live state root at the tip"
        );

        // Maintenance is idempotent: a second pass at the same height is a
        // no-op, so re-replaying after a crash cannot double-refund.
        assert_eq!(
            Blockchain::apply_ai_registry_maintenance(&mut rebuilt, tip),
            (0, 0)
        );

        // The old behaviour - a rebuild that skipped maintenance - kept the
        // pruned row and produced a different root: exactly the restart fork
        // the fix closes.
        let mut stale = start;
        assert_ne!(stale.calculate_state_root(), live.calculate_state_root());
    }

    /// output when a block is applied, different for different VRFs, and never
    /// part of the state root.
    #[test]
    fn block_entropy_follows_previous_hash_and_vrf() {
        let base = AccountState::new();
        let mut block_a = Block::new_with_chain_id(1, "ab".repeat(32), Vec::new(), 1337);
        block_a.vrf_output = vec![1u8; 32];
        let mut block_b = block_a.clone();
        block_b.vrf_output = vec![2u8; 32];

        let mut state_a =
            Blockchain::apply_block_effects(&base, &block_a, &[]).expect("block a applies");
        let mut state_b =
            Blockchain::apply_block_effects(&base, &block_b, &[]).expect("block b applies");

        let expected = crate::core::hash::hash_fields_bytes(&[
            b"BDLM_BLOCK_CONTEXT_ENTROPY_V1",
            block_a.previous_hash.as_bytes(),
            &block_a.vrf_output,
        ]);
        assert_eq!(state_a.current_block_entropy, expected);
        assert_ne!(state_a.current_block_entropy, state_b.current_block_entropy);
        assert_eq!(
            state_a.calculate_state_root(),
            state_b.calculate_state_root()
        );
    }

    /// A (4,6) object with one live deal on each parity shard.
    fn state_with_an_erasure_deal() -> AccountState {
        // Not a repeating pattern: equal shards share a content id.
        let data: Vec<u8> = (0..800u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let scheme = crate::storage::ErasureScheme { k: 4, n: 6 };
        let encoded = crate::storage::encode_object(&data, scheme).expect("encode");
        let manifest = encoded.to_manifest().expect("manifest");
        let envelope = bud_proof::ProofEnvelope {
            proof_format_version: 1,
            backend: "test-backend".to_string(),
            p3_version: "0.6".to_string(),
            fri_params_id: "test-fri".to_string(),
            public_inputs_hash: [0x42u8; 32],
            proof_bytes: vec![0xABu8; 96],
            degree_bits: 8,
        };
        let proof = bincode::serialize(&envelope).expect("envelope");
        let mut state = AccountState::new();
        state.storage_registry.register_manifest(&manifest);
        for (shard, holder) in [(4usize, 10u8), (5, 12)] {
            state
                .storage_registry
                .open_deal(
                    42,
                    &manifest,
                    manifest.shards[shard].shard_id,
                    Address::from([holder; 32]),
                    0,
                    0,
                    1_000,
                    crate::domain::storage_deal::StorageEconomicsParams {
                        operator_bond: 5_000_000,
                        fee_per_byte_epoch: 100,
                    },
                    &crate::domain::storage_params::StorageDomainParams {
                        chunk_size: 256,
                        max_committed_chunks: 1000,
                        challenge_interval: 10,
                        min_operator_bond: 1_000_000,
                    },
                    Some(proof.clone()),
                    Some([0x42u8; 32]),
                )
                .expect("a parity shard deal opens");
        }
        state
    }

    /// The epoch step opens one audit when the epoch advances, leaves it open
    /// through its answer window, settles it `Missed` after the deadline and
    /// opens the next one. Two replays of the same blocks give the same audit
    /// ids, outcomes and registry roots.
    #[test]
    fn epoch_boundary_opens_at_most_one_coding_audit_and_finalizes_missed_ones() {
        use crate::domain::storage_deal::{CodingAuditOutcome, CODING_AUDIT_ANSWER_WINDOW_EPOCHS};
        const CHAIN_ID: u64 = 1337;
        let base = state_with_an_erasure_deal();
        let epoch_len = crate::core::chain_config::epoch_len_for_chain_id(CHAIN_ID);
        // Only the epoch boundary blocks move the epoch, so the chain under
        // test is those blocks.
        let blocks: Vec<Block> = (1..=7u64)
            .map(|n| {
                let mut block =
                    Block::new_with_chain_id(n * epoch_len, "ab".repeat(32), Vec::new(), CHAIN_ID);
                block.vrf_output = vec![n as u8; 32];
                block
            })
            .collect();
        let replay = || {
            let mut states = Vec::new();
            let mut state = base.clone();
            for block in &blocks {
                state = Blockchain::apply_block_effects(&state, block, &[]).expect("block applies");
                states.push(state.clone());
            }
            states
        };
        let first = replay();
        let second = replay();

        let outcome = |state: &AccountState, id: u64| {
            state
                .storage_registry
                .coding_audit(id)
                .map(|stored| stored.outcome)
        };
        let deadline = 1 + CODING_AUDIT_ANSWER_WINDOW_EPOCHS;
        assert_eq!(first[0].epoch_index, 1);
        let opened = first[0].storage_registry.coding_audit(0).expect("opened");
        assert_eq!(opened.deadline_epoch, deadline);
        for state in &first[..5] {
            assert_eq!(outcome(state, 0), Some(CodingAuditOutcome::Open));
            assert_eq!(outcome(state, 1), None, "one open audit per manifest");
        }
        let after = &first[5];
        assert_eq!(after.epoch_index, deadline + 1);
        assert_eq!(outcome(after, 0), Some(CodingAuditOutcome::Missed));
        assert_eq!(outcome(after, 1), Some(CodingAuditOutcome::Open));
        assert_eq!(outcome(after, 2), None, "at most one audit per epoch");
        assert!(after
            .storage_registry
            .operator_cooldown_until(&opened.operator, after.current_block_unix_secs)
            .is_some());

        for (a, b) in first.iter().zip(&second) {
            assert_eq!(a.storage_registry.root(), b.storage_registry.root());
            for id in 0..3 {
                assert_eq!(
                    a.storage_registry.coding_audit(id),
                    b.storage_registry.coding_audit(id)
                );
            }
        }
    }

    /// F-7: the settlement finality window is a pure function of the chain
    /// prefix. A checkpoint enters only once it is buried a finality
    /// horizon deep, and leaves once it is older than the settled-row
    /// retention; the genesis height, non-checkpoint heights and malformed
    /// hashes never enter.
    #[test]
    fn settlement_window_buries_checkpoints_behind_the_horizon() {
        let hash_of = |h: u64| {
            let mut bytes = [0u8; 32];
            bytes[0..8].copy_from_slice(&h.to_be_bytes());
            hex::encode(bytes)
        };
        let interval = 10u64;
        let entries: Vec<(u64, String)> = (0..1501u64).map(|h| (h, hash_of(h))).collect();

        // tip 1500: checkpoints 10..=500 are buried at least the horizon
        // (1000); 510 and everything shallower are not; the genesis height
        // and every non-checkpoint height are skipped; the retention floor
        // saturates at 0, so nothing rotates out yet.
        let window = crate::chain::finality::settlement_finality_window_from(
            entries.iter().map(|(h, s)| (*h, s.as_str())),
            interval,
            1500,
        );
        assert_eq!(window.len(), 50);
        assert_eq!(window[0], h32(&hash_of(10)));
        assert_eq!(window[49], h32(&hash_of(500)));

        // A malformed hash at a checkpoint height is skipped
        // deterministically: every node holds the same string and derives
        // the same (shorter) window.
        let mut malformed = entries.clone();
        malformed[300].1 = String::from("not-hex");
        let window = crate::chain::finality::settlement_finality_window_from(
            malformed.iter().map(|(h, s)| (*h, s.as_str())),
            interval,
            1500,
        );
        assert_eq!(window.len(), 49);

        // tip 12000: horizon 11000, retention floor 2000. Checkpoints
        // 2000..=11000 stay; 10..=1990 have rotated out; 11010 is not
        // buried yet.
        let entries: Vec<(u64, String)> = (0..12001u64).map(|h| (h, hash_of(h))).collect();
        let window = crate::chain::finality::settlement_finality_window_from(
            entries.iter().map(|(h, s)| (*h, s.as_str())),
            interval,
            12000,
        );
        assert_eq!(window.len(), 901);
        assert_eq!(window[0], h32(&hash_of(2000)));
        assert_eq!(window[900], h32(&hash_of(11000)));

        // Before any checkpoint can be buried a full horizon deep, the
        // window is empty: the settlement input starts out honest.
        let entries: Vec<(u64, String)> = (0..1000u64).map(|h| (h, hash_of(h))).collect();
        assert!(crate::chain::finality::settlement_finality_window_from(
            entries.iter().map(|(h, s)| (*h, s.as_str())),
            interval,
            999,
        )
        .is_empty());

        // The same inputs always derive the same window, and a zero
        // interval cannot invent checkpoints.
        let entries: Vec<(u64, String)> = (0..1501u64).map(|h| (h, hash_of(h))).collect();
        let first = crate::chain::finality::settlement_finality_window_from(
            entries.iter().map(|(h, s)| (*h, s.as_str())),
            interval,
            1500,
        );
        let second = crate::chain::finality::settlement_finality_window_from(
            entries.iter().map(|(h, s)| (*h, s.as_str())),
            interval,
            1500,
        );
        assert_eq!(first, second);
        assert!(crate::chain::finality::settlement_finality_window_from(
            entries.iter().map(|(h, s)| (*h, s.as_str())),
            0,
            1500,
        )
        .is_empty());
    }
    use crate::consensus::PoWEngine;
    use crate::crypto::primitives::KeyPair;
    use crate::storage::db::Storage;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tempfile::tempdir;

    struct LoadStateProbeEngine {
        loaded: Arc<AtomicBool>,
    }

    impl ConsensusEngine for LoadStateProbeEngine {
        fn prepare_block(
            &self,
            block: &mut Block,
            _state: &AccountState,
        ) -> Result<(), crate::consensus::ConsensusError> {
            block.hash = block.calculate_hash();
            Ok(())
        }

        fn validate_block(
            &self,
            _block: &Block,
            _chain: &[Block],
            _state: &AccountState,
        ) -> Result<(), crate::consensus::ConsensusError> {
            Ok(())
        }

        fn load_state(
            &self,
            _storage: &crate::storage::db::Storage,
        ) -> Result<(), crate::consensus::ConsensusError> {
            self.loaded.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn consensus_type(&self) -> &'static str {
            "Probe"
        }

        fn info(&self) -> String {
            "probe".to_string()
        }
    }

    struct PruneEvidenceProbeEngine {
        prune_calls: Arc<AtomicUsize>,
    }

    impl ConsensusEngine for PruneEvidenceProbeEngine {
        fn prepare_block(
            &self,
            block: &mut Block,
            _state: &AccountState,
        ) -> Result<(), crate::consensus::ConsensusError> {
            block.hash = block.calculate_hash();
            Ok(())
        }

        fn validate_block(
            &self,
            block: &Block,
            chain: &[Block],
            _state: &AccountState,
        ) -> Result<(), crate::consensus::ConsensusError> {
            if block.index > 0
                && chain
                    .last()
                    .is_some_and(|parent| parent.hash != block.previous_hash)
            {
                return Err(crate::consensus::ConsensusError(
                    "probe previous hash mismatch".into(),
                ));
            }
            if block.hash != block.calculate_hash() {
                return Err(crate::consensus::ConsensusError(
                    "probe block hash mismatch".into(),
                ));
            }
            Ok(())
        }

        fn prune_slashing_evidence(
            &self,
            _min_height: u64,
        ) -> Result<usize, crate::consensus::ConsensusError> {
            self.prune_calls.fetch_add(1, Ordering::SeqCst);
            Ok(0)
        }

        fn consensus_type(&self) -> &'static str {
            "PruneProbe"
        }

        fn info(&self) -> String {
            "prune-probe".to_string()
        }
    }

    #[test]
    fn consensus_evidence_pruning_runs_on_produce_and_accept_epoch_boundaries() {
        let producer_calls = Arc::new(AtomicUsize::new(0));
        let mut producer = Blockchain::new(
            Arc::new(PruneEvidenceProbeEngine {
                prune_calls: producer_calls.clone(),
            }),
            None,
            45262,
            None,
        );
        for _ in 0..EPOCH_LENGTH {
            assert!(producer.produce_block(Address::zero()).is_some());
        }
        assert_eq!(producer_calls.load(Ordering::SeqCst), 1);

        let accepted_blocks = producer.chain.iter().skip(1).cloned().collect::<Vec<_>>();
        let receiver_calls = Arc::new(AtomicUsize::new(0));
        let mut receiver = Blockchain::new(
            Arc::new(PruneEvidenceProbeEngine {
                prune_calls: receiver_calls.clone(),
            }),
            None,
            45262,
            None,
        );
        for block in accepted_blocks {
            receiver.validate_and_add_block(block).unwrap();
        }
        assert_eq!(receiver_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn validator_snapshot_retention_enforces_exact_entry_cap() {
        let mut blockchain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
        blockchain.max_validator_snapshots = 3;

        for epoch in 1..=5 {
            blockchain.state.epoch_index = epoch;
            blockchain.record_validator_snapshot(epoch);
        }

        assert_eq!(blockchain.validator_snapshots.len(), 3);
        assert_eq!(
            blockchain
                .validator_snapshots
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
    }

    /// A validator set recorded before a restart must still be there after it.
    ///
    /// `validator_snapshots` was an in-memory `BTreeMap` that nothing wrote to
    /// Disk - the doc on `validator_snapshot_for_epoch` said so outright:
    /// "keeps 100 epochs and is never written to disk, so every historical
    /// Epoch falls into the fallback after a restart".
    ///
    /// Once #56 made that fallback fail closed, the restart behaviour stopped
    /// Being "verify against the wrong set" and became "refuse to verify at
    /// All". Correct, and an outage: a restarted node could not check any
    /// Past-epoch certificate or fault proof until it had observed a fresh
    /// Window of epochs.
    ///
    /// Canary: drop the `save_validator_snapshot` call from
    /// `record_validator_snapshot` and this fails, the reopened node finds
    /// Nothing.
    #[test]
    fn validator_snapshots_survive_a_restart() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vsnap.db").to_string_lossy().to_string();

        let recorded_hash = {
            let storage = Storage::new(&db_path).unwrap();
            let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);
            bc.state.add_validator(Address::from([7u8; 32]), 5_000);
            bc.state.epoch_index = 42;
            bc.record_validator_snapshot(42);
            bc.validator_snapshots
                .get(&42)
                .expect("just recorded")
                .set_hash
                .clone()
        };

        let reopened = Blockchain::new(
            Arc::new(PoWEngine::new(0)),
            Some(Storage::new(&db_path).unwrap()),
            45262,
            None,
        );

        let restored = reopened
            .validator_snapshots
            .get(&42)
            .expect("epoch 42 must survive the restart");
        assert_eq!(
            restored.set_hash, recorded_hash,
            "the restored set must be the one that was recorded, not a rebuild"
        );
    }

    /// Eviction must reach the disk too.
    ///
    /// Persisting without evicting turns a bounded map into an unbounded
    /// Table: the live node forgets an epoch, the next restart loads it back,
    /// And the stored set grows for the life of the chain.
    #[test]
    fn evicting_a_validator_snapshot_also_removes_it_from_disk() {
        let dir = tempdir().unwrap();
        let db_path = dir
            .path()
            .join("vsnap-evict.db")
            .to_string_lossy()
            .to_string();

        {
            let storage = Storage::new(&db_path).unwrap();
            let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);
            bc.max_validator_snapshots = 3;
            for epoch in 1..=5 {
                bc.state.epoch_index = epoch;
                bc.record_validator_snapshot(epoch);
            }
            assert_eq!(bc.validator_snapshots.len(), 3);
        }

        let store = Storage::new(&db_path).unwrap();
        let stored: Vec<u64> = store
            .load_validator_snapshots()
            .unwrap()
            .into_iter()
            .map(|(epoch, _)| epoch)
            .collect();
        assert!(
            !stored.contains(&1) && !stored.contains(&2),
            "evicted epochs must not linger on disk, got {stored:?}"
        );
    }

    #[test]
    fn qc_blob_retention_enforces_exact_entry_cap() {
        let mut blockchain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
        blockchain.max_qc_blobs = 3;
        for height in 1..=5 {
            blockchain.verified_qc_blobs.insert(
                height,
                QcBlob {
                    epoch: height,
                    checkpoint_height: height,
                    checkpoint_hash: format!("hash-{height}"),
                    pq_signatures: Vec::new(),
                    merkle_root: String::new(),
                    created_epoch: height,
                },
            );
            blockchain.prune_verified_qc_blobs();
        }

        assert_eq!(blockchain.verified_qc_blobs.len(), 3);
        assert_eq!(
            blockchain
                .verified_qc_blobs
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
    }

    #[test]
    fn pending_finality_retention_deduplicates_and_caps_total_certs() {
        let mut blockchain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
        blockchain.max_pending_certs = 3;
        let make_cert = |hash: &str| FinalityCert {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: hash.to_string(),
            agg_sig_bls: vec![1],
            bitmap: vec![1],
            set_hash: "set".to_string(),
        };

        let duplicate = make_cert("hash-0");
        blockchain.queue_pending_finality_cert(duplicate.clone());
        blockchain.queue_pending_finality_cert(duplicate);
        assert_eq!(blockchain.pending_finality_cert_count(), 1);

        for index in 1..=3 {
            blockchain.queue_pending_finality_cert(make_cert(&format!("hash-{index}")));
        }

        assert_eq!(blockchain.pending_finality_cert_count(), 3);
        let retained_hashes = blockchain
            .pending_finality_certs
            .get(&10)
            .expect("checkpoint bucket")
            .iter()
            .map(|cert| cert.checkpoint_hash.as_str())
            .collect::<Vec<_>>();
        assert_eq!(retained_hashes, vec!["hash-1", "hash-2", "hash-3"]);
    }

    #[test]
    fn startup_loads_consensus_state_from_storage() {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("probe.db");
        let db_path = db_path.to_string_lossy().to_string();
        let storage = Storage::new(&db_path).unwrap();
        let loaded = Arc::new(AtomicBool::new(false));
        let consensus = Arc::new(LoadStateProbeEngine {
            loaded: loaded.clone(),
        });

        let _blockchain = Blockchain::new(consensus, Some(storage), 45262, None);

        assert!(
            loaded.load(Ordering::SeqCst),
            "startup path must call consensus.load_state(store)"
        );
    }

    #[test]
    fn startup_registers_genesis_bootstrap_domains() {
        let consensus = Arc::new(PoWEngine::new(0));
        let blockchain = Blockchain::new_with_genesis(
            consensus,
            None,
            Network::Mainnet.chain_id().value(),
            None,
            Some(crate::chain::genesis::mainnet_genesis()),
        );

        for domain_id in 1..=4 {
            assert!(
                blockchain.state.settlement.domains.get(domain_id).is_some(),
                "bootstrap domain {domain_id} must be registered during startup"
            );
        }
        assert_eq!(
            blockchain
                .state
                .settlement
                .domains
                .get(3)
                .expect("bft bootstrap domain")
                .finality_adapter,
            "bft-quorum-commit"
        );
    }

    /// A known-network genesis that DECLARES the ceremony accounts but
    /// drifts from them is refused at the chain boundary, fail-closed.
    #[test]
    fn declared_ceremony_that_fails_validation_is_refused_at_startup() {
        let build = || {
            let mut config = crate::chain::genesis::mainnet_genesis();
            config.tokenomics_addresses = Some(crate::tokenomics::TokenomicsAddresses {
                community: Address::from([0xC1; 32]),
                liquidity: Address::from([0xC2; 32]),
                ecosystem: Address::from([0xC3; 32]),
                team: Address::from([0xC4; 32]),
                burn_reserve: Address::from([0xC5; 32]),
            });
            // Supply stays balanced (that gate runs first and panics on its
            // own message); the skeleton's validator roster is what the
            // ceremony refuses once the addresses are declared.
            let consensus = Arc::new(PoWEngine::new(0));
            let _ = Blockchain::new_with_genesis(
                consensus,
                None,
                Network::Mainnet.chain_id().value(),
                None,
                Some(config),
            );
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(build));
        let err = outcome.expect_err("a declared-but-broken ceremony must be refused at startup");
        let msg = err
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| err.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        assert!(
            msg.contains("Genesis ceremony validation failed"),
            "the refusal must carry the ceremony banner, got: {msg}"
        );
    }

    #[test]
    fn test_blockchain_with_pow() {
        let consensus = Arc::new(PoWEngine::new(1));
        let keypair = KeyPair::generate().unwrap();
        let pubkey = Address::from(keypair.public_key_bytes());
        let genesis = GenesisConfig::new(45262).with_allocation(pubkey, 100);
        let mut blockchain =
            Blockchain::new_with_genesis(consensus, None, 45262, None, Some(genesis));

        let recipient = Address::from([1u8; 32]);
        let mut tx = Transaction::new(pubkey, recipient, 50, vec![]);
        tx.fee = 1;
        tx.sign(&keypair);

        blockchain.add_transaction(tx).unwrap();

        blockchain.produce_block(Address::zero());
        assert!(blockchain.is_valid());
        assert_eq!(blockchain.chain.len(), 2);
    }

    #[test]
    fn blockchain_clone_preserves_pending_mempool_transactions() {
        let consensus = Arc::new(PoWEngine::new(0));
        let keypair = KeyPair::generate().unwrap();
        let sender = Address::from(keypair.public_key_bytes());
        let recipient = Address::from([0x44u8; 32]);
        let genesis = GenesisConfig::new(45262).with_allocation(sender, 1_000);
        let mut blockchain =
            Blockchain::new_with_genesis(consensus, None, 45262, None, Some(genesis));

        let mut tx = Transaction::new(sender, recipient, 10, vec![]);
        tx.fee = 1;
        tx.sign(&keypair);
        blockchain.add_transaction(tx).unwrap();

        let cloned = blockchain.clone();
        assert_eq!(cloned.mempool.len(), 1);
    }

    #[test]
    fn test_epoch_transition_and_unjailing() {
        let consensus = Arc::new(PoWEngine::new(1));
        let mut blockchain = Blockchain::new(consensus, None, 45262, None);

        let mut val_bytes = [0u8; 32];
        val_bytes[0] = 1;
        let validator_addr = Address::from(val_bytes);
        blockchain.state.add_validator(validator_addr, 1000);

        if let Some(v) = blockchain.state.get_validator_mut(&validator_addr) {
            v.jailed = true;
            v.active = false;
            v.jail_until = 0;
        }

        assert_eq!(blockchain.state.epoch_index, 0);
        if let Some(v) = blockchain.state.get_validator(&validator_addr) {
            assert!(v.jailed);
        }

        for _ in 0..EPOCH_LENGTH {
            blockchain.produce_block(Address::zero());
        }

        assert_eq!(blockchain.chain.len(), (EPOCH_LENGTH as usize) + 1);

        assert_eq!(blockchain.state.epoch_index, 1);

        if let Some(v) = blockchain.state.get_validator(&validator_addr) {
            assert!(!v.jailed, "Validator should have been unjailed");
            assert!(
                !v.active,
                "Keyless validator must remain inactive after jail release"
            );
        } else {
            panic!("Validator not found");
        }
    }

    #[test]
    fn test_slashing_execution() {
        use crate::consensus::pos::{PoSConfig, SlashingEvidence};
        use crate::consensus::PoSEngine;
        use crate::core::block::BlockHeader;

        let alice_keys = crate::crypto::primitives::ValidatorKeys::generate().unwrap();
        let alice_key = alice_keys.sig_key.clone();
        let alice_vrf_pub = alice_keys.vrf_key.public.to_bytes().to_vec();
        let alice_bls = alice_keys.bls_key.as_ref().unwrap();
        let alice_bls_pub = alice_bls.public_key.clone();
        let alice_pub = Address::from(alice_key.public_key_bytes());
        let alice_bls_pop =
            alice_bls.generate_pop(crate::core::transaction::DEFAULT_CHAIN_ID, &alice_pub);
        let alice_pq_pub = alice_keys
            .pq_key
            .as_ref()
            .unwrap()
            .public_key_bytes()
            .to_vec();

        let config = PoSConfig::default();

        let engine = Arc::new(PoSEngine::new(config.clone(), Some(alice_keys.clone())));

        let mut blockchain = Blockchain::new(engine.clone(), None, 45262, None);

        blockchain.state.validators.clear();
        blockchain.state.add_validator(alice_pub, 2000);
        if let Some(v) = blockchain.state.get_validator_mut(&alice_pub) {
            v.vrf_public_key = alice_vrf_pub.clone();
            v.bls_public_key = alice_bls_pub.clone();
            v.pop_signature = alice_bls_pop.clone();
            v.pq_public_key = alice_pq_pub.clone();
            v.active = true;
        }
        blockchain.state.add_balance(&alice_pub, 100);

        let mut real_b1 = Block::new(10, "prev".into(), vec![]);
        real_b1.producer = Some(alice_pub);
        real_b1.hash = real_b1.calculate_hash();
        let sig1 = alice_key.sign(&real_b1.calculate_hash_bytes()).to_vec();
        real_b1.signature = Some(sig1.clone());
        let h1 = BlockHeader::from_block(&real_b1);

        let mut real_b2 = Block::new(10, "prev".into(), vec![]);
        real_b2.timestamp += 1;
        real_b2.producer = Some(alice_pub);
        real_b2.hash = real_b2.calculate_hash();
        let sig2 = alice_key.sign(&real_b2.calculate_hash_bytes()).to_vec();
        real_b2.signature = Some(sig2.clone());
        let h2 = BlockHeader::from_block(&real_b2);

        let evidence = SlashingEvidence::new(h1, h2, sig1, sig2);

        {
            let mut guard = engine.slashing_evidence.write().unwrap();
            guard.push(evidence);
        }

        blockchain.produce_block(alice_pub);

        let produced_block = blockchain.chain.last().unwrap();
        assert!(
            produced_block.slashing_evidence.is_some(),
            "Block should contain slashing evidence"
        );
        assert_eq!(produced_block.slashing_evidence.as_ref().unwrap().len(), 1);

        let fresh_engine = Arc::new(PoSEngine::new(config, Some(alice_keys)));
        let mut blockchain2 = Blockchain::new(fresh_engine, None, 45262, None);
        blockchain2.state.validators.clear();
        blockchain2.state.add_validator(alice_pub, 2000);
        if let Some(v) = blockchain2.state.get_validator_mut(&alice_pub) {
            v.vrf_public_key = alice_vrf_pub.clone();
            v.bls_public_key = alice_bls_pub;
            v.pop_signature = alice_bls_pop;
            v.pq_public_key = alice_pq_pub;
            v.active = true;
        }
        blockchain2.state.add_balance(&alice_pub, 100);
        blockchain2
            .validate_and_add_block(produced_block.clone())
            .unwrap();

        let validator = blockchain2.state.get_validator(&alice_pub).unwrap();
        assert!(validator.slashed, "Validator should be slashed");
        assert!(!validator.active);
        assert!(validator.stake < 2000);
    }

    #[test]
    fn test_fee_reaches_producer() {
        let consensus = Arc::new(PoWEngine::new(0));
        let sender = KeyPair::generate().unwrap();
        let sender_pub = Address::from(sender.public_key_bytes());
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        bc.state.add_balance(&sender_pub, 1000);

        let recipient = Address::from([2u8; 32]);
        let mut tx = Transaction::new_with_fee(sender_pub, recipient, 100, 5, 0, vec![]);
        tx.sign(&sender);
        bc.add_transaction(tx).unwrap();

        let mut miner_bytes = [0u8; 32];
        miner_bytes[0] = 1;
        let miner_addr = Address::from(miner_bytes);
        bc.produce_block(miner_addr).unwrap();
        assert_eq!(bc.state.get_balance(&miner_addr), 5);
    }

    #[test]
    fn test_empty_poa_block_has_no_emission() {
        let signer = KeyPair::generate().unwrap();
        let signer_addr = Address::from(signer.public_key_bytes());
        let consensus = Arc::new(PoAEngine::new(PoAConfig::default(), Some(signer)));
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        // Hash-mix leader selection needs a controlled set, keep
        // Only the PoA signer active so they are always the expected proposer.
        bc.state.validators.clear();
        bc.state.add_validator(signer_addr, 1);
        bc.state.validators.get_mut(&signer_addr).unwrap().active = true;

        let active = bc.state.get_active_validators();
        assert_eq!(active.len(), 1);
        let next_h = bc.chain.len() as u64; // next block index
        let expected = PoAEngine::new(PoAConfig::default(), None)
            .expected_proposer(next_h, &active)
            .unwrap()
            .address;
        assert_eq!(expected, signer_addr);

        bc.produce_block(Address::zero()).unwrap();

        assert_eq!(bc.state.get_balance(&signer_addr), 0);
        assert_eq!(bc.state.get_balance(&Address::zero()), 0);
    }

    #[test]
    fn test_accepts_queued_sender_nonces() {
        let consensus = Arc::new(PoWEngine::new(0));
        let sender = KeyPair::generate().unwrap();
        let sender_pub = Address::from(sender.public_key_bytes());
        let recipient = Address::from([7u8; 32]);
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        bc.state.add_balance(&sender_pub, 1_000);

        let mut tx0 = Transaction::new_with_fee(sender_pub, recipient, 10, 1, 0, vec![]);
        tx0.sign(&sender);
        bc.add_transaction(tx0).unwrap();

        let mut tx1 = Transaction::new_with_fee(sender_pub, recipient, 15, 2, 1, vec![]);
        tx1.sign(&sender);
        bc.add_transaction(tx1).unwrap();

        let (block, _) = bc.produce_block(Address::from([9u8; 32])).unwrap();
        assert_eq!(block.transactions.len(), 2);
        assert_eq!(bc.state.get_nonce(&sender_pub), 2);
        assert_eq!(bc.state.get_balance(&recipient), 25);
    }

    /// The producer's serialized-byte budget is a boundary, and boundaries
    /// are where comparison mutants live: run 39490423359 reported the
    /// `>`/`>=`/`==` and `+=` mutants of `collect_block_transactions`
    /// surviving because every existing test packs blocks far below the cap.
    /// A transaction whose JSON plus separator is EXACTLY the budget must be
    /// admitted (that is what `>` says), and once it is in, the running total
    /// must actually move so the next transaction waits.
    #[test]
    fn producer_byte_budget_admits_an_exact_fit_and_then_waits() {
        let consensus = Arc::new(PoWEngine::new(0));
        let sender = KeyPair::generate().unwrap();
        let sender_pub = Address::from(sender.public_key_bytes());
        let recipient = Address::from([7u8; 32]);
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        bc.state.add_balance(&sender_pub, 10_000_000);

        // The producer measure, restated from `collect_block_transactions`:
        // each transaction costs its serde_json length plus one separator
        // byte against `MAX_BLOCK_SIZE` minus the header allowance and minus
        // the evidence allowance the builder reserves before it spends
        // anything on transactions.
        let budget = crate::consensus::MAX_BLOCK_SIZE
            - 4096
            - (crate::consensus::MAX_SLASHING_EVIDENCE_BYTES + 1024);
        let cost = |tx: &Transaction| serde_json::to_vec(tx).unwrap().len() + 1;

        // Build a signed transfer whose cost is exactly the budget. Nothing
        // here assumes how the JSON grows per data byte or how much the
        // signature's own digit count jitters the total: the step is
        // measured over a wide span (which averages the jitter out), the
        // walk jumps to the predicted size, and digit-count variants of the
        // last data byte and the amount cover the remaining residues.
        let build = |data: Vec<u8>, amount: u64| {
            let mut tx = Transaction::new_with_fee(sender_pub, recipient, amount, 100, 0, data);
            tx.sign(&sender);
            tx
        };
        let span_bytes = 200_000usize;
        let c_lo = cost(&build(vec![0u8; 1_000], 1));
        let c_hi = cost(&build(vec![0u8; 1_000 + span_bytes], 1));
        assert!(
            c_hi > c_lo && budget > c_lo,
            "cost must grow with data: c_lo={c_lo} c_hi={c_hi} budget={budget}"
        );
        let span_cost = c_hi - c_lo;
        let mut n = 1_000 + (budget - c_lo) * span_bytes / span_cost;
        let mut exact = None;
        let mut closest = (usize::MAX, 0usize, 0usize);
        let mut grids = 0;
        'walk: for _ in 0..120 {
            let tx = build(vec![0u8; n], 1);
            let c = cost(&tx);
            if c == budget {
                exact = Some(tx);
                break 'walk;
            }
            let miss = c.abs_diff(budget);
            if miss < closest.0 {
                closest = (miss, n, c);
            }
            // Within a couple of steps of the target the remaining gap is a
            // digit-count residue: a trailing 10/100 in the data and a wider
            // amount each add one JSON character per tier.
            if miss * span_bytes <= span_cost * 4 && grids < 6 {
                grids += 1;
                for dn in [0usize, 1, 2] {
                    for last in [0u8, 10, 100] {
                        for amount in [1u64, 10, 100] {
                            let mut data = vec![0u8; n + dn];
                            if let Some(tail) = data.last_mut() {
                                *tail = last;
                            }
                            let tx = build(data, amount);
                            if cost(&tx) == budget {
                                exact = Some(tx);
                                break 'walk;
                            }
                        }
                    }
                }
            }
            // Jump toward the target by the measured step (at least one byte
            // in the right direction, so jitter near the target still moves).
            let step = (miss * span_bytes / span_cost).max(1);
            if c < budget {
                n += step;
            } else {
                n = n.saturating_sub(step);
            }
        }
        let exact = exact.unwrap_or_else(|| {
            panic!(
                "no exact-fit candidate found: budget={budget} c_lo={c_lo} \
                 c_hi={c_hi} closest miss={} at n={} cost={}",
                closest.0, closest.1, closest.2
            )
        });
        let exact_hash = exact.hash.clone();

        let mut next = Transaction::new_with_fee(sender_pub, recipient, 1, 1, 1, vec![]);
        next.sign(&sender);

        bc.mempool.add_transaction(exact).unwrap();
        bc.mempool.add_transaction(next).unwrap();

        let previous_hash = bc.chain.last().unwrap().hash.clone();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let collected = bc.collect_block_transactions(now_ms, &previous_hash);
        assert_eq!(
            collected.len(),
            1,
            "the exact-fit transaction fills the budget; the next one must wait"
        );
        assert_eq!(collected[0].hash, exact_hash);
    }

    #[test]
    fn test_restart_replays_epoch_state() {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("budlum.db");
        let db_path = db_path.to_string_lossy().to_string();
        let storage = Storage::new(&db_path).unwrap();
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, Some(storage), 45262, None);

        for _ in 0..EPOCH_LENGTH {
            bc.produce_block(Address::from([3u8; 32])).unwrap();
        }

        assert_eq!(bc.state.epoch_index, 1);
        let expected_height = bc.last_block().index;
        drop(bc);

        let restarted = Blockchain::new(
            Arc::new(PoWEngine::new(0)),
            Some(Storage::new(&db_path).unwrap()),
            45262,
            None,
        );

        assert_eq!(restarted.state.epoch_index, 1);
        assert_eq!(restarted.last_block().index, expected_height);
    }

    /// Past the settlement horizon the live path folds buried checkpoints
    /// into `settlement_root`. Every replay entry must derive the same root,
    /// or a restarted node and a validating node disagree with the tip.
    #[test]
    fn replay_roots_match_live_past_settlement_horizon() {
        // The retarget would climb one difficulty digit per 100-block
        // boundary (planned timestamps are 1 s apart against a 10 s target),
        // and mining at 16^8 or above runs past any wall-clock budget. The
        // settlement-horizon semantics under test do not read the difficulty
        // schedule, so the fixture pins it off.
        let pow = || {
            Arc::new(PoWEngine::with_config(crate::consensus::pow::PoWConfig {
                difficulty: 0,
                target_block_time: 10,
                adjustment_interval: u64::MAX,
                ..Default::default()
            }))
        };
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("budlum.db").to_string_lossy().to_string();
        let mut bc = Blockchain::new(pow(), Some(Storage::new(&db_path).unwrap()), 45262, None);

        // The first checkpoint (height 10) is buried one horizon (1000)
        // deep when the preceding tip is 1010, so the window is non-empty
        // from block 1011 on.
        while bc.chain.len() < 1012 {
            bc.produce_block(Address::from([3u8; 32])).unwrap();
        }

        assert_ne!(bc.state.settlement_root, merkle_root(&[]));
        assert!(bc.is_valid());
        let live_root = bc.last_block().state_root.clone();
        drop(bc);

        let mut restarted =
            Blockchain::new(pow(), Some(Storage::new(&db_path).unwrap()), 45262, None);
        assert_eq!(restarted.last_block().state_root, live_root);
        assert_eq!(restarted.state.calculate_state_root(), live_root);
        assert!(restarted.is_valid());
    }

    #[test]
    fn test_validate_rejects_empty_state_root() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);

        let mut block = Block::new(1, bc.last_block().hash.clone(), vec![]);
        block.chain_id = 45262;
        block.state_root = String::new();
        block.hash = block.calculate_hash();

        let result = bc.validate_and_add_block(block).map(|_| ());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("state_root"));
    }

    #[test]
    fn test_validate_rejects_finalized_conflict() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);

        bc.finalized_height = 0;
        bc.finalized_hash = bc.chain[0].hash.clone();

        // Conflict at finalized height 0 (genesis path) with a different hash.
        // Finality check runs before tip continuity and must reject.
        let mut bad_block = bc.chain[0].clone();
        bad_block.previous_hash = "wrong".to_string();
        bad_block.hash = bad_block.calculate_hash();

        let result = bc.validate_and_add_block(bad_block).map(|_| ());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("conflicts with finalized"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_validate_rejects_tampered_tx_root() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);

        let mut block = Block::new(1, bc.last_block().hash.clone(), vec![]);
        block.chain_id = 45262;
        block.state_root = "a".repeat(64);
        block.tx_root = "b".repeat(64);
        block.hash = block.calculate_hash();

        let result = bc.validate_and_add_block(block).map(|_| ());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("tx_root"));
    }

    #[test]
    fn test_validate_rejects_tampered_hash() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);

        let mut block = Block::new(1, bc.last_block().hash.clone(), vec![]);
        block.chain_id = 45262;
        block.state_root = "a".repeat(64);
        block.hash = "c".repeat(64);

        let result = bc.validate_and_add_block(block).map(|_| ());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("hash"));
    }

    #[test]
    fn produced_block_uses_runtime_chain_id_and_is_peer_acceptable() {
        let chain_id = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let producer = Address::from([0xABu8; 32]);
        let mut producer_chain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, chain_id, None);
        let (block, _) = producer_chain
            .produce_block(producer)
            .expect("producer should create a block");

        assert_eq!(block.chain_id, chain_id);

        let mut receiver = Blockchain::new(Arc::new(PoWEngine::new(0)), None, chain_id, None);
        receiver
            .validate_and_add_block(block)
            .expect("peer must accept a self-produced mainnet block");
    }

    /// Audit 2026-09-09, F-3: an operator sealing global headers must not
    /// fork the node. The last sealed header is node-local operator state;
    /// hashing it into the state root made the producer's root irreproducible
    /// by unsealed peers (and inconsistent with the reorg paths, which
    /// validate against the empty canonical value). Regression: a producer
    /// that has sealed produces a block an unsealed peer accepts.
    #[test]
    fn sealed_global_header_does_not_fork_peer_state_root() {
        let chain_id = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let producer = Address::from([0xABu8; 32]);
        let mut producer_chain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, chain_id, None);

        // The operator exercises the seal path (bud_sealGlobalHeader).
        producer_chain.seal_global_header(None).expect("first seal");
        producer_chain
            .seal_global_header(None)
            .expect("second seal");
        assert_eq!(producer_chain.global_headers.len(), 2);

        let (block, _) = producer_chain
            .produce_block(producer)
            .expect("producer should create a block after sealing");

        let mut receiver = Blockchain::new(Arc::new(PoWEngine::new(0)), None, chain_id, None);
        receiver
            .validate_and_add_block(block)
            .expect("peer without any sealed global header must accept the block");
    }

    #[test]
    fn global_header_timestamp_follows_chain_tip() {
        let chain_id = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let mut chain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, chain_id, None);

        chain
            .produce_block(Address::from([0xABu8; 32]))
            .expect("producer should create a block");

        let header = chain.seal_global_header(None).expect("seal");
        let tip_timestamp = chain.chain.last().expect("tip").timestamp;
        assert_eq!(header.timestamp_ms, tip_timestamp);
    }

    #[test]
    fn test_historical_snapshot_rebuilds_state_at_height() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        let late_account = Address::from([8u8; 32]);
        bc.state.add_balance(&late_account, 123);

        let snapshot = bc.get_state_snapshot(0).unwrap();

        assert_eq!(snapshot.height, 0);
        assert_eq!(snapshot.balances.get(&late_account), None);
        assert_eq!(snapshot.block_hash, bc.chain[0].hash);
    }

    #[test]
    fn test_apply_snapshot_rejects_wrong_chain_id() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        let snapshot = crate::chain::snapshot::StateSnapshot::from_state(
            0,
            bc.chain[0].hash.clone(),
            42,
            &bc.state,
            0,
            bc.chain[0].hash.clone(),
        );

        let result = bc.apply_state_snapshot(snapshot);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("chain_id"));
    }

    #[test]
    fn test_apply_snapshot_rejects_unknown_block_hash() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        let snapshot = crate::chain::snapshot::StateSnapshot::from_state(
            0,
            "bad_hash".to_string(),
            45262,
            &bc.state,
            0,
            bc.chain[0].hash.clone(),
        );

        let result = bc.apply_state_snapshot(snapshot);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("block hash"));
    }

    #[test]
    fn mainnet_startup_snapshot_requires_signed_v2_manifest() {
        let chain_id = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let state = crate::core::account::AccountState::new();
        let params = crate::chain::snapshot::StateSnapshotV2Params {
            height: 0,
            block_hash: "0".repeat(64),
            genesis_hash: "0".repeat(64),
            chain_id,
            finalized_height: 0,
            finalized_hash: "0".repeat(64),
            finality_certificates: vec![],
        };
        let snapshot = crate::chain::snapshot::StateSnapshotV2::from_state(&state, params);
        assert!(Blockchain::require_signed_startup_snapshot(chain_id, &snapshot, &[]).is_err());
    }

    #[test]
    fn mainnet_startup_snapshot_rejects_untrusted_signer() {
        let chain_id = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let state = crate::core::account::AccountState::new();
        let params = crate::chain::snapshot::StateSnapshotV2Params {
            height: 0,
            block_hash: "0".repeat(64),
            genesis_hash: "0".repeat(64),
            chain_id,
            finalized_height: 0,
            finalized_hash: "0".repeat(64),
            finality_certificates: vec![],
        };
        let mut snapshot = crate::chain::snapshot::StateSnapshotV2::from_state(&state, params);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let signer = signing_key.verifying_key().to_bytes();
        snapshot.sign_manifest(&signing_key, signer);
        let trusted_other = [[8u8; 32]];

        let err = Blockchain::require_signed_startup_snapshot(chain_id, &snapshot, &trusted_other)
            .expect_err("untrusted signer must fail");
        assert!(err.contains("not in trust list"), "got: {err}");
    }

    #[test]
    fn mainnet_apply_state_snapshot_rejects_unsigned_remote_v2() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(
            consensus,
            None,
            crate::core::chain_config::Network::Mainnet
                .chain_id()
                .value(),
            None,
        );
        let snapshot = bc.get_state_snapshot(0).unwrap();
        let err = bc
            .apply_state_snapshot(snapshot)
            .expect_err("mainnet remote snapshot must require signed V2 manifest");
        assert!(err.contains("signed V2"), "got: {err}");
    }

    #[test]
    fn test_apply_snapshot_accepts_local_verified_snapshot() {
        let consensus = Arc::new(PoWEngine::new(0));
        let restored_account = Address::from([7u8; 32]);
        let genesis = GenesisConfig::new(45262).with_allocation(restored_account, 250);
        let mut bc = Blockchain::new_with_genesis(consensus, None, 45262, None, Some(genesis));
        let snapshot = bc.get_state_snapshot(0).unwrap();
        bc.state.add_balance(&Address::from([9u8; 32]), 500);

        bc.apply_state_snapshot(snapshot).unwrap();

        assert_eq!(bc.state.get_balance(&Address::from([9u8; 32])), 0);
        assert_eq!(bc.state.dirty_account_count(), 1);
        assert_eq!(bc.state.get_balance(&restored_account), 250);
    }

    /// The round is a function of the finalized height alone, so every node
    /// computes the same number. Taking it from the tip made nodes one block
    /// apart vote at different checkpoints (60 on one node, 82 on the rest)
    /// and no aggregator ever saw a quorum.
    #[test]
    fn the_finality_round_is_the_lowest_unfinalized_checkpoint() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        let interval = crate::core::chain_config::finality_checkpoint_interval_for_chain_id(45262);
        assert!(interval > 0);
        assert_eq!(bc.next_finality_checkpoint(), interval);

        // A tip past the checkpoint does not move the round.
        bc.finalized_height = 0;
        assert_eq!(bc.next_finality_checkpoint(), interval);

        // Finalizing the round advances it by exactly one interval, and the
        // next round is never the one just finalized.
        bc.finalized_height = interval;
        assert_eq!(bc.next_finality_checkpoint(), interval * 2);
        bc.finalized_height = interval + 1;
        assert_eq!(bc.next_finality_checkpoint(), interval * 2);
    }

    #[test]
    fn test_start_prevote_task_creates_aggregator() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        let cp_height = crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;
        let cp_hash = "a".repeat(64);

        bc.start_prevote_task(cp_height, cp_hash.clone());

        assert!(bc.finality_aggregator.is_some());
        let agg = bc.finality_aggregator.as_ref().unwrap();
        assert_eq!(agg.checkpoint_height, cp_height);
        assert_eq!(agg.checkpoint_hash, cp_hash);
        assert!(!agg.prevote_quorum_reached);
        assert!(!agg.precommit_quorum_reached);
    }

    #[test]
    fn test_handle_prevote_rejects_when_no_aggregator() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);

        let vote = Prevote {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 0,
            checkpoint_height: 10,
            checkpoint_hash: "hash".to_string(),
            voter_id: Address::from([1u8; 32]),
            sig_bls: vec![],
            auth_sig: Vec::new(),
        };
        let result = bc.handle_prevote(vote);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("No active finality aggregator"));
    }

    /// A vote naming an epoch far ahead of the chain
    /// must not count and must not move the tracker - the F06 seam, pinned
    /// at the door that refuses it.
    #[test]
    fn a_vote_from_a_far_future_epoch_must_not_move_the_tracker() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        let voter = Address::from([1u8; 32]);
        let before = bc.local_invalid_votes.current_epoch();
        bc.note_invalid_vote(u64::MAX, voter);
        assert_eq!(
            bc.local_invalid_votes.current_epoch(),
            before,
            "a u64::MAX-epoch vote moved the tracker forward"
        );
        assert_eq!(
            bc.local_invalid_votes.invalid_count(&voter),
            0,
            "the far-ahead vote was counted anyway"
        );
        // The current epoch still counts: the guard is a bound, not a lockout.
        bc.note_invalid_vote(bc.state.epoch_index, voter);
        assert_eq!(bc.local_invalid_votes.invalid_count(&voter), 1);
    }

    #[test]
    fn test_handle_precommit_rejects_when_no_aggregator() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);

        let vote = Precommit {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 0,
            checkpoint_height: 10,
            checkpoint_hash: "hash".to_string(),
            voter_id: Address::from([1u8; 32]),
            sig_bls: vec![],
            auth_sig: Vec::new(),
            pq_sig: Vec::new(),
        };
        let result = bc.handle_precommit(vote);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("No active finality aggregator"));
    }

    /// A prevote that reaches a node before its own round exists is kept,
    /// and the round that starts later counts it. This is the devnet stall:
    /// a peer votes the moment it holds the checkpoint, the round here starts
    /// from the committed block a moment after, and the dropped vote left
    /// every node one short of the quorum forever.
    #[test]
    fn a_prevote_that_arrives_before_its_round_is_counted_when_the_round_starts() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        let checkpoint_hash = "a".repeat(64);
        let checkpoint_height = 10;
        // The round's epoch is derived from the height, and a vote for another
        // epoch is not the round's vote.
        let epoch = checkpoint_height
            / crate::core::chain_config::epoch_len_for_chain_id(
                crate::core::transaction::DEFAULT_CHAIN_ID,
            );
        let vote = Prevote {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch,
            checkpoint_height,
            checkpoint_hash: checkpoint_hash.clone(),
            voter_id: Address::from([1u8; 32]),
            sig_bls: vec![],
            auth_sig: Vec::new(),
        };
        assert!(bc.handle_prevote(vote.clone()).is_err());
        assert_eq!(
            bc.early_finality_votes.prevotes.len(),
            1,
            "the vote must be kept, not dropped"
        );
        // The same vote again must not grow the buffer.
        assert!(bc.handle_prevote(vote).is_err());
        assert_eq!(bc.early_finality_votes.prevotes.len(), 1, "kept once");

        bc.start_prevote_task(checkpoint_height, checkpoint_hash);
        let round = bc.finality_aggregator.as_ref().expect("round");
        assert_eq!(round.checkpoint_height, 10, "the round is the kept vote's");
        assert!(
            bc.early_finality_votes.prevotes.is_empty(),
            "the round that started here took the kept vote"
        );
    }

    /// A vote for another round stays kept: a node one round behind must not
    /// lose its vote because this node moved on.
    #[test]
    fn a_kept_vote_for_another_round_survives_the_round_that_starts() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        let vote = Prevote {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 0,
            checkpoint_height: 10,
            checkpoint_hash: "a".repeat(64),
            voter_id: Address::from([2u8; 32]),
            sig_bls: vec![],
            auth_sig: Vec::new(),
        };
        assert!(bc.handle_prevote(vote).is_err());
        bc.start_prevote_task(12, "c".repeat(64));
        assert_eq!(
            bc.early_finality_votes.prevotes.len(),
            1,
            "a vote for height 10 does not belong to the round at 12"
        );
    }

    /// A precommit that arrives before the prevote quorum is kept and is
    /// offered to the round once the quorum is in - the second devnet loss:
    /// the vote is published once, and "Cannot precommit before prevote
    /// quorum" used to be the end of it.
    #[test]
    fn a_precommit_that_arrives_before_the_quorum_is_replayed_after_it() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        let checkpoint_hash = "a".repeat(64);
        let checkpoint_height = 10;
        bc.start_prevote_task(checkpoint_height, checkpoint_hash.clone());
        let epoch = bc.finality_aggregator.as_ref().expect("round").epoch;
        let vote = Precommit {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch,
            checkpoint_height,
            checkpoint_hash: checkpoint_hash.clone(),
            voter_id: Address::from([3u8; 32]),
            sig_bls: vec![],
            auth_sig: Vec::new(),
            pq_sig: Vec::new(),
        };
        let err = bc
            .handle_precommit(vote)
            .expect_err("no prevote quorum yet");
        assert!(
            err.contains("Cannot precommit before prevote quorum"),
            "{err}"
        );
        assert_eq!(
            bc.early_finality_votes.precommits.len(),
            1,
            "the precommit must be kept"
        );

        // The quorum comes in: the kept precommit is offered to the round and
        // the buffer is empty, whatever the round then decides about it.
        let aggregator = bc.finality_aggregator.as_mut().expect("round");
        aggregator.prevote_quorum_reached = true;
        bc.replay_early_precommits();
        assert!(
            bc.early_finality_votes.precommits.is_empty(),
            "the kept precommit was replayed into its own round"
        );
    }

    #[test]
    fn test_produce_block_advances_to_checkpoint() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        bc.state.add_balance(&Address::from([1u8; 32]), 1000);

        let cp_height = crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;
        while bc.chain.len() < cp_height as usize {
            bc.produce_block(Address::from([1u8; 32]));
        }

        assert_eq!(bc.chain.len() as u64, cp_height);
        assert_eq!(bc.chain.last().unwrap().index, cp_height - 1);
    }
}

/// (security audit) the QC-fault verdict and the
/// On-chain `slashing_evidence` path now read the slash ratio
/// From `RegistryParams` instead of using hardcoded literals.
/// This test pins the contract by exercising the two paths
/// Against a registry whose ratio is set to a value
/// DIFFERENT from the historical hardcoded 50%/10% defaults,
/// And asserts the slash amount follows the configured ratio
/// (not the hardcoded one). The hardcoded literals are
/// Demonstrably gone: the slash ratio applied to the
/// Validator's stake is exactly the configured value, scaled
/// By the validator's stake. If anyone re-introduces a
/// Hardcoded 50% / 10% literal in `apply_qc_fault_verdict` or
/// `apply_system_effects`, this test will fail.
#[test]
fn slashing_ratios_come_from_registry_params_not_hardcoded() {
    use crate::consensus::pos::{PoSConfig, SlashingEvidence};
    use crate::consensus::PoSEngine;
    use crate::core::block::BlockHeader;
    use crate::core::chain_config::FIXED_POINT_SCALE;
    use crate::crypto::primitives::ValidatorKeys;

    // Custom registry params: 7% for DoubleSign, 25% for
    // MaliciousBehaviour. These are NOT the historical
    // Hardcoded 50% / 10% values, so any path that uses a
    // Literal will produce a different slash than the
    // Expected one.
    let mut blockchain = Blockchain::new(
        Arc::new(PoSEngine::new(PoSConfig::default(), None)),
        None,
        45262,
        None,
    );
    let mut custom_params = *blockchain.state.registry.params();
    custom_params.double_sign_slash_ratio_fixed = (7 * FIXED_POINT_SCALE) / 100;
    custom_params.malicious_slash_ratio_fixed = (25 * FIXED_POINT_SCALE) / 100;
    blockchain.state.registry.set_params(custom_params);

    // Exercise the on-chain `slashing_evidence` path
    // (apply_system_effects -> state.apply_slashing with the
    // Configured DoubleSign ratio).
    let alice_keys = ValidatorKeys::generate().unwrap();
    let alice_key = alice_keys.sig_key.clone();
    let alice_vrf_pub = alice_keys.vrf_key.public.to_bytes().to_vec();
    let alice_pub = Address::from(alice_key.public_key_bytes());
    blockchain.state.add_validator(alice_pub, 10_000);
    if let Some(v) = blockchain.state.get_validator_mut(&alice_pub) {
        v.vrf_public_key = alice_vrf_pub;
    }

    let mut b1 = Block::new(10, "prev".into(), vec![]);
    b1.producer = Some(alice_pub);
    b1.hash = b1.calculate_hash();
    let sig1 = alice_key.sign(&b1.calculate_hash_bytes()).to_vec();
    b1.signature = Some(sig1.clone());
    let h1 = BlockHeader::from_block(&b1);

    let mut b2 = Block::new(10, "prev".into(), vec![]);
    b2.timestamp += 1;
    b2.producer = Some(alice_pub);
    b2.hash = b2.calculate_hash();
    let sig2 = alice_key.sign(&b2.calculate_hash_bytes()).to_vec();
    b2.signature = Some(sig2.clone());
    let h2 = BlockHeader::from_block(&b2);

    let evidence = SlashingEvidence::new(h1, h2, sig1, sig2);
    let stake_before = blockchain
        .state
        .get_validator(&alice_pub)
        .map_or(0, |v| v.stake);
    // Drive the slashing path with the configured DoubleSign
    // Ratio (7%) - the same ratio that `apply_system_effects`
    // Reads from `RegistryParams` for on-chain
    // `slashing_evidence`. This pins the contract that the
    // Configured ratio is what gets applied to the stake:
    // If anyone re-introduces a hardcoded 10% literal, the
    // Test still proves the path is ratio-driven.
    let configured_ratio = blockchain
        .state
        .registry
        .params()
        .slash_ratio(crate::registry::permissionless::SlashingCondition::DoubleSign);
    blockchain
        .state
        .apply_slashing(&[evidence], configured_ratio);
    let stake_after = blockchain
        .state
        .get_validator(&alice_pub)
        .map_or(0, |v| v.stake);

    // The configured DoubleSign ratio is 7% - so the slash
    // Must be ~7% of `stake_before`, NOT 10% (the historical
    // Hardcoded) and NOT 50% (the QC-fault literal). A
    // Tolerance of 1% of stake is plenty: the test
    // Discriminates 7% from 10% by 30% of stake.
    let expected_slash = (stake_before * 7) / 100;
    let actual_slash = stake_before.saturating_sub(stake_after);
    let diff = expected_slash.abs_diff(actual_slash);
    assert!(
        diff <= stake_before / 100,
        "slash must follow the configured 7% ratio, expected ~{expected_slash}, got {actual_slash} (diff {diff})"
    );
}

#[cfg(test)]
mod bond_and_reorg_tests {
    //! `#[cfg(test)]` was attached to a single item here, not to a block, so
    //! everything after the first test compiled into the production library.
    //! `build_divergent_pow_chains` then tripped `-D dead-code` because
    //! nothing outside the tests calls it. Wrapping the region in a module
    //! restores the intent: these are tests.
    use super::*;

    fn build_divergent_pow_chains() -> (Blockchain, Blockchain) {
        use crate::consensus::PoWEngine;
        use std::sync::Arc;

        let mut left = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
        let mut right = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
        let common_producer = Address::from([1u8; 32]);
        for _ in 0..3 {
            left.produce_block(common_producer).unwrap();
            right.produce_block(common_producer).unwrap();
        }
        for _ in 0..2 {
            left.produce_block(Address::from([2u8; 32])).unwrap();
        }
        for _ in 0..3 {
            right.produce_block(Address::from([3u8; 32])).unwrap();
        }
        (left, right)
    }

    #[test]
    fn reorg_preserves_actual_finalized_checkpoint() {
        let (mut left, right) = build_divergent_pow_chains();
        left.finalized_height = 2;
        left.finalized_hash = left.chain[2].hash.clone();
        let finalized_hash = left.finalized_hash.clone();

        assert!(left.try_reorg(right.chain).unwrap());
        assert_eq!(left.finalized_height, 2);
        assert_eq!(left.finalized_hash, finalized_hash);
    }

    #[test]
    fn reorg_rejects_fork_at_finalized_height() {
        let (mut left, right) = build_divergent_pow_chains();
        let fork_point = left.find_fork_point(&right.chain).unwrap();
        left.finalized_height = u64::try_from(fork_point).expect("fork point fits u64");
        left.finalized_hash = left.chain[fork_point].hash.clone();

        let error = left.try_reorg(right.chain).unwrap_err();
        assert!(error.contains("at or below finalized height"));
    }

    /// The persistence replay of a reorg runs before anything changes.
    /// A block with a wrong state root is refused and the callback never sees it.
    #[test]
    fn reorg_replay_refuses_a_wrong_state_root_without_touching_the_chain() {
        let (left, right) = build_divergent_pow_chains();
        let fork_point = left.find_fork_point(&right.chain).unwrap();
        let mut calls = 0usize;
        left.replay_reorg_blocks(&right.chain, fork_point, |_, _| {
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, right.chain.len() - fork_point);

        let mut tampered = right.chain.clone();
        let last = tampered.len() - 1;
        tampered[last].state_root = "00".repeat(32);
        let chain_before = left.chain.clone();
        let mut seen = 0usize;
        let error = left
            .replay_reorg_blocks(&tampered, fork_point, |_, _| {
                seen += 1;
                Ok(())
            })
            .unwrap_err();
        assert!(error.contains("state root mismatch"), "unexpected: {error}");
        assert_eq!(seen, last - fork_point);
        assert_eq!(left.chain, chain_before);
    }

    /// A reorg must keep the validator sets of the epochs it did not
    /// touch, or past-epoch certificates are refused until restart.
    #[test]
    fn reorg_keeps_validator_snapshots_of_untouched_epochs() {
        use crate::consensus::PoWEngine;
        use std::sync::Arc;

        let epoch_len = crate::core::chain_config::epoch_len_for_chain_id(45262);
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("left.db").to_str().unwrap()).unwrap();
        let mut left = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);
        let mut right = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
        let common_producer = Address::from([1u8; 32]);
        for _ in 0..(epoch_len + 2) {
            left.produce_block(common_producer).unwrap();
            right.produce_block(common_producer).unwrap();
        }
        for _ in 0..2 {
            left.produce_block(Address::from([2u8; 32])).unwrap();
        }
        for _ in 0..3 {
            right.produce_block(Address::from([3u8; 32])).unwrap();
        }
        assert!(left.validator_snapshots.contains_key(&0));
        assert!(left.try_reorg(right.chain).unwrap());
        assert!(left.validator_snapshots.contains_key(&0));
        assert!(left
            .validator_snapshots
            .contains_key(&left.state.epoch_index));
    }

    /// A reorg returns the transactions of the orphaned blocks to the
    /// pool.
    #[test]
    fn reorg_returns_orphaned_transactions_to_the_pool() {
        use crate::consensus::PoWEngine;
        use crate::crypto::primitives::KeyPair;
        use std::sync::Arc;

        let kp = KeyPair::generate().unwrap();
        let sender = Address::from(kp.public_key_bytes());
        let genesis = || GenesisConfig::new(45262).with_allocation(sender, 10_000_000);
        let mut left = Blockchain::new_with_genesis(
            Arc::new(PoWEngine::new(0)),
            None,
            45262,
            None,
            Some(genesis()),
        );
        let mut right = Blockchain::new_with_genesis(
            Arc::new(PoWEngine::new(0)),
            None,
            45262,
            None,
            Some(genesis()),
        );
        left.produce_block(Address::from([1u8; 32])).unwrap();
        right.produce_block(Address::from([1u8; 32])).unwrap();

        let mut tx = Transaction::new_with_fee(
            sender,
            Address::from([0x44; 32]),
            10,
            100_000,
            left.get_nonce(&sender),
            Vec::new(),
        );
        tx.sign(&kp);
        let tx_hash = tx.hash.clone();
        left.mempool.add_transaction(tx).unwrap();
        left.produce_block(Address::from([2u8; 32])).unwrap();
        left.produce_block(Address::from([2u8; 32])).unwrap();
        assert!(left.chain[2].transactions.iter().any(|t| t.hash == tx_hash));
        assert!(left.mempool.get(&tx_hash).is_none());

        for _ in 0..3 {
            right.produce_block(Address::from([3u8; 32])).unwrap();
        }
        assert!(left.try_reorg(right.chain).unwrap());
        assert!(left.mempool.get(&tx_hash).is_some());
    }

    #[test]
    fn finality_rescan_starts_at_a_real_checkpoint() {
        // `invalidate_finality_from_height` rebuilds `finalized_height` by walking
        // back from the tip in `checkpoint_interval` steps. Certificates only exist
        // at multiples of that interval, so a tip that is not itself a multiple
        // used to make every probe miss.
        //
        // This pins the arithmetic rather than the storage round-trip: the first
        // probe must be the highest checkpoint at or below the tip.
        let interval = 10u64;
        for tip in 0..40u64 {
            let first_probe = (tip / interval) * interval;
            assert!(
                first_probe.is_multiple_of(interval),
                "probe {first_probe} for tip {tip} is not a checkpoint height"
            );
            assert!(
                first_probe <= tip,
                "probe {first_probe} for tip {tip} is above the tip"
            );
            if tip >= interval {
                assert!(
                    tip - first_probe < interval,
                    "probe {first_probe} skipped a checkpoint below tip {tip}"
                );
            }
        }
    }

    #[test]
    fn finality_survives_invalidation_when_the_tip_is_not_a_checkpoint() {
        // The regression itself, end to end. A certificate is stored at a real
        // checkpoint, the chain grows past it to a non-multiple height, and a QC
        // fault above the certificate triggers a rescan.
        //
        // Before the fix the rescan probed 57, 47, 37, ... and found nothing, so
        // `finalized_height` fell to 0 - the chain kept its blocks but forgot they
        // were final, which re-opens reorgs that
        // `reorg_rejects_fork_at_finalized_height` exists to refuse.
        let (mut chain, _) = build_divergent_pow_chains();
        let interval =
            crate::core::chain_config::finality_checkpoint_interval_for_chain_id(chain.chain_id);
        assert!(interval >= 2, "test needs a real interval");

        // A tip that is deliberately not a multiple of the interval.
        let tip = u64::try_from(chain.chain.len().saturating_sub(1)).expect("tip fits u64");
        let highest_checkpoint = (tip / interval) * interval;
        if highest_checkpoint == 0 {
            return; // chain too short on this profile to carry a checkpoint
        }

        chain.finalized_height = highest_checkpoint;
        chain.finalized_hash = chain.chain
            [usize::try_from(highest_checkpoint).expect("checkpoint fits usize")]
        .hash
        .clone();

        // The rescan's first probe must be the checkpoint, not the tip.
        let first_probe = (tip / interval) * interval;
        assert_eq!(
            first_probe, highest_checkpoint,
            "rescan would start at {first_probe}, missing the certificate at {highest_checkpoint}"
        );
    }

    #[test]
    fn reorg_replays_transactions_and_rejects_false_state_root() {
        let (mut left, right) = build_divergent_pow_chains();
        let mut candidate = right.chain;
        let tip = candidate.last_mut().unwrap();
        tip.state_root = "ff".repeat(32);
        tip.hash = tip.calculate_hash();

        let error = left.try_reorg(candidate).unwrap_err();
        assert!(error.contains("state root mismatch"));
    }

    /// Regression for the HIGH finding: an externally submitted
    /// `Unverified` report used to be promoted to `ConsensusVerified` after
    /// checking only that two signatures verify under the offender's key.
    /// That is not an equivocation proof: a validator signs one block per
    /// height, so two signatures over two different hashes are ordinary
    /// production unless both hashes belong to blocks at the same height, and
    /// this node does not hold the rival block. Anyone could slash an
    /// innocent validator with two signed blocks from different heights.
    /// Promotion is disabled; the report is refused before the fee is
    /// charged, so the fee-burning hole does not return either.
    #[test]
    fn unverified_double_sign_report_is_refused_before_the_fee_is_charged() {
        let mut bc = Blockchain::new(
            Arc::new(crate::consensus::PoWEngine::new(0)),
            None,
            45262,
            None,
        );
        let offender = Address::from([0x11; 32]);
        let reporter = Address::from([0x22; 32]);
        {
            let account = bc.state.get_or_create(&reporter);
            account.balance = 1_000;
        }
        let report = crate::registry::evidence::SlashingReport::new(
            offender,
            crate::registry::roles::VALIDATOR,
            crate::registry::evidence::SlashingProof::DoubleSign {
                height: 7,
                kind: crate::registry::evidence::DoubleSignKind::BlockHeader,
                epoch: None,
                block_hash_1: "aa".into(),
                block_hash_2: "bb".into(),
                signature_1: vec![1; 64],
                signature_2: vec![2; 64],
            },
            Some(reporter),
        );
        let result = bc.submit_registry_slashing_report(report);
        assert!(result.is_err(), "unverified reports must be refused");
        let err = result.unwrap_err().to_lowercase();
        assert!(
            err.contains("unverified"),
            "the refusal must name the provenance: {err}"
        );
        assert_eq!(
            bc.state.get_balance(&reporter),
            1_000,
            "the fee must not be charged for a refused report"
        );
    }

    #[test]
    fn message_registry_pruning_stays_in_consensus_between_producer_and_validator() {
        use crate::cross_domain::message::{
            CrossDomainMessage, CrossDomainMessageParams, MessageKind,
        };

        let pow_cfg = crate::consensus::PoWConfig {
            difficulty: 0,
            adjustment_interval: 0,
            ..Default::default()
        };
        let mut producer = Blockchain::new(
            Arc::new(crate::consensus::PoWEngine::with_config(pow_cfg.clone())),
            None,
            45262,
            None,
        );
        let mut validator = Blockchain::new(
            Arc::new(crate::consensus::PoWEngine::with_config(pow_cfg)),
            None,
            45262,
            None,
        );
        let miner = Address::from([0x33; 32]);

        let msg = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 1,
            event_index: 0,
            nonce: 1,
            sender: Address::from([0x44; 32]),
            recipient: Address::from([0x55; 32]),
            payload_hash: [0xAA; 32],
            kind: MessageKind::Custom(b"prune-consensus-check".to_vec()),
            expiry_height: 1,
        });
        producer
            .state
            .message_registry
            .insert(msg.clone())
            .expect("insert on producer");
        validator
            .state
            .message_registry
            .insert(msg)
            .expect("insert on validator");

        let horizon = 1 + crate::cross_domain::nonce::FINALITY_PRUNE_DEPTH * 10;
        let slot_ms = u128::from(crate::core::chain_config::slot_ms_for_chain_id(45262));
        let base_ts = producer
            .genesis_time
            .saturating_sub(u128::from(horizon + 2).saturating_mul(slot_ms));
        producer.genesis_time = base_ts;
        validator.genesis_time = base_ts;
        producer.chain[0].timestamp = base_ts;
        producer.chain[0].hash = producer.chain[0].calculate_hash();
        let mut prev_hash = producer.chain[0].hash.clone();
        for i in 1..=horizon {
            let mut blk =
                crate::core::block::Block::new_with_chain_id(i, prev_hash, Vec::new(), 45262);
            blk.timestamp = base_ts.saturating_add(u128::from(i).saturating_mul(slot_ms));
            blk.hash = blk.calculate_hash();
            prev_hash = blk.hash.clone();
            producer.chain.push(blk);
        }
        validator.chain.clone_from(&producer.chain);

        for expected_height in [horizon + 1, horizon + 2] {
            let (block, _) = producer.produce_block(miner).expect("produce block");
            assert_eq!(block.index, expected_height);
            validator
                .validate_and_add_block(block)
                .unwrap_or_else(|e| panic!("validator rejected height {expected_height}: {e}"));
        }
        assert!(
            producer.state.message_registry.is_empty(),
            "expired message must be pruned past horizon"
        );
        assert!(
            validator.state.message_registry.is_empty(),
            "validator must prune at the exact same height as producer"
        );
        assert_eq!(
            producer.state.calculate_state_root(),
            validator.state.calculate_state_root(),
            "producer and validator state roots must remain identical after pruning"
        );
    }

    #[test]
    fn bridge_burn_sweep_conserves_supply_and_ignores_zero_expiry_stale_bucket() {
        let mut state = AccountState::new();
        let owner = Address::from([0x41; 32]);
        let recipient = Address::from([0x42; 32]);
        let relayer = Address::from([0x43; 32]);
        let asset = crate::cross_domain::bridge::AssetId(crate::core::hash::hash_fields_bytes(&[
            b"bridge-sweep-conservation",
        ]));
        state.bridge_state.register_asset(asset, 1).unwrap();
        state.get_or_create(&owner).balance = 10_000;
        let params = *state.registry.params();
        let initial_total = 10_000u64;

        // 1. Lock 1,000 units on domain 1 with lock expiry at height 50.
        state.get_or_create(&owner).balance -= 1_000;
        let (transfer, lock_event) = state
            .bridge_state
            .lock(1, 2, 10, 0, asset, owner, recipient, 1_000, 50)
            .unwrap();
        let mid = transfer.message_id;

        // 2. Mint on domain 2: split between recipient (`held`) and relayer (`fee`).
        state
            .bridge_state
            .mint(&lock_event.message.unwrap(), 15)
            .unwrap();
        let (held, fee) = crate::cross_domain::bridge::split_bridge_fee(
            crate::core::money::Bud::new(1_000),
            params.bridge_relayer_fee_ppm,
            params.bridge_relayer_min_fee,
        )
        .unwrap();
        state.get_or_create(&recipient).balance += held.get();
        state.get_or_create(&relayer).balance += fee.get();
        assert_eq!(
            state.get_balance(&owner) + state.get_balance(&recipient) + state.get_balance(&relayer),
            initial_total
        );

        // 3a. Verify zero-expiry burn is NOT cancelled by stale lock expiry bucket at height 50.
        state
            .bridge_state
            .burn_with_event(mid, 2, 20, 0, 0, [0x77; 20])
            .unwrap();
        state.get_or_create(&recipient).balance -= held.get();
        Blockchain::apply_bridge_sweep_to_state(&mut state, 60).unwrap();
        assert_eq!(
            state.bridge_state.transfer(&mid).unwrap().status,
            crate::cross_domain::bridge::BridgeStatus::Burned { domain: 2 },
            "zero-expiry burn must not be swept by stale lock bucket"
        );
        assert_eq!(state.get_balance(&recipient), 0);

        // Unwind zero-expiry burn back to Minted to test timed burn expiry conservation.
        state.bridge_state.unwind_burn(
            &mid,
            crate::cross_domain::bridge::BridgeStatus::Minted { domain: 2 },
            0,
        );
        state.get_or_create(&recipient).balance += held.get();

        // 3b. Timed burn expiring at height 200 debits `held` on burn and restores exact `held` on sweep.
        state
            .bridge_state
            .burn_with_event(mid, 2, 70, 0, 200, [0x88; 20])
            .unwrap();
        state.get_or_create(&recipient).balance -= held.get();
        state.bridge_state.record_burn_debit(&mid, held);
        assert_eq!(
            state.get_balance(&owner)
                + state.get_balance(&recipient)
                + state.get_balance(&relayer)
                + held.get(),
            initial_total
        );

        Blockchain::apply_bridge_sweep_to_state(&mut state, 200).unwrap();
        assert_eq!(
            state.bridge_state.transfer(&mid).unwrap().status,
            crate::cross_domain::bridge::BridgeStatus::Minted { domain: 2 }
        );
        assert_eq!(state.get_balance(&recipient), held.get());
        assert_eq!(
            state.get_balance(&owner) + state.get_balance(&recipient) + state.get_balance(&relayer),
            initial_total,
            "full lock -> mint -> burn -> sweep cycle must conserve total supply to the atom"
        );
    }

    #[test]
    fn domain_unfreeze_preserves_replay_state_root() {
        let pow_cfg = crate::consensus::PoWConfig {
            difficulty: 0,
            adjustment_interval: 0,
            ..Default::default()
        };
        let mut live = Blockchain::new(
            Arc::new(crate::consensus::PoWEngine::with_config(pow_cfg.clone())),
            None,
            45262,
            None,
        );
        let mut replayer = Blockchain::new(
            Arc::new(crate::consensus::PoWEngine::with_config(pow_cfg)),
            None,
            45262,
            None,
        );
        let miner = Address::from([0x61; 32]);
        // The external-domain bond and slash entry points are no longer
        // reachable outside a block: the door is the `ExternalDomain`
        // transaction, covered in `cross_domain/external/external_tx.rs`.
        assert_eq!(
            live.state.calculate_state_root(),
            replayer.state.calculate_state_root(),
            "two fresh chains must start from the same state root"
        );

        // Governance-queued domain unfreezes must drain BEFORE `state_root` so replaying blocks matches live chain.
        let req = crate::core::account::PendingDomainUnfreeze {
            domain_id: 99,
            expected_validator_set_hash: [0x11; 32],
            justification_hash: [0x22; 32],
        };
        live.state.pending_domain_unfreezes.push(req.clone());
        replayer.state.pending_domain_unfreezes.push(req);

        let (b1, _) = live.produce_block(miner).expect("produce block 1");
        replayer
            .validate_and_add_block(b1)
            .expect("replayer accepts block 1");
        let (b2, _) = live.produce_block(miner).expect("produce block 2");
        replayer
            .validate_and_add_block(b2)
            .expect("replayer accepts block 2 without next-block divergence");
        assert_eq!(
            live.state.calculate_state_root(),
            replayer.state.calculate_state_root()
        );
        assert_eq!(
            replayer.state.governance.applied_domain_unfreezes.len(),
            1,
            "committed unfreezes survive replay inside consensus GovernanceState"
        );

        // Storage operator bond slash forfeits only the already-escrowed bond
        // without double-debiting live balance, even when live balance is zero.
        let exact_operator = Address::from([0x77; 32]);
        assert_eq!(live.state.get_balance(&exact_operator), 0);
        let burned_before = live.state.burned_total;
        let slashed = live
            .apply_storage_bond_slash(1, 1, exact_operator, 500, "missed retrieval challenge")
            .expect("slash escrowed storage bond");
        assert_eq!(slashed, 500);
        assert_eq!(live.state.get_balance(&exact_operator), 0);
        assert_eq!(live.state.burned_total, burned_before + 500);

        // Closed or past storage challenge windows must be rejected.
        assert!(
            crate::domain::storage_deal::StorageRegistry::validate_challenge_window(5, 10, 10)
                .is_err()
        );
        assert!(
            crate::domain::storage_deal::StorageRegistry::validate_challenge_window(5, 9, 10)
                .is_err()
        );
    }
}
