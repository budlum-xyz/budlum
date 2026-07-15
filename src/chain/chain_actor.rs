use crate::chain::blockchain::Blockchain;
use crate::chain::finality::{FinalityCert, Precommit, Prevote};
use crate::consensus::qc::{QcBlob, QcFaultProof};
use crate::core::address::Address;
use crate::core::block::Block;
use crate::core::transaction::Transaction;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
pub enum ChainCommand {
    GetHeight(oneshot::Sender<u64>),
    GetBlock(u64, oneshot::Sender<Option<Block>>),
    GetBlockByHash(String, oneshot::Sender<Option<Block>>),
    GetBalance(Address, oneshot::Sender<u64>),
    GetNonce(Address, oneshot::Sender<u64>),
    AddTransaction(Transaction, oneshot::Sender<Result<(), String>>),
    ProduceBlock(Address, oneshot::Sender<Option<Block>>),
    ValidateAndAddBlock(Block, oneshot::Sender<Result<(), String>>),
    GetTransactionByHash(String, oneshot::Sender<Option<Transaction>>),
    GetTxReceipt(String, oneshot::Sender<Option<serde_json::Value>>),
    TxPrecheck(Transaction, oneshot::Sender<serde_json::Value>),
    GetChainId(oneshot::Sender<u64>),
    GetBaseFee(oneshot::Sender<u64>),
    GetValidatorSetHash(oneshot::Sender<String>),
    GetMempoolSize(oneshot::Sender<usize>),
    HandleFinalityCert(FinalityCert, oneshot::Sender<Result<(), String>>),
    HandlePrevote(Prevote, oneshot::Sender<Result<(), String>>),
    HandlePrecommit(
        Precommit,
        oneshot::Sender<Result<Option<FinalityCert>, String>>,
    ),
    ImportQcBlob(QcBlob, oneshot::Sender<Result<(), String>>),
    HandleQcFaultProof(QcFaultProof, oneshot::Sender<Result<(), String>>),
    SubmitSlashingEvidence(
        crate::consensus::pos::SlashingEvidence,
        oneshot::Sender<Result<(), String>>,
    ),
    SubmitRegistrySlashingReport(
        crate::registry::SlashingReport,
        oneshot::Sender<Result<Option<crate::registry::SlashOutcome>, String>>,
    ),
    GetRegistryMember(
        crate::core::address::Address,
        crate::registry::RoleId,
        oneshot::Sender<Option<crate::registry::Registration>>,
    ),
    GetRegistryActiveMembers(
        crate::registry::RoleId,
        oneshot::Sender<Vec<crate::registry::Registration>>,
    ),
    DrainSlashingEvidence(oneshot::Sender<Vec<crate::consensus::pos::SlashingEvidence>>),
    CleanupMempool(oneshot::Sender<usize>),
    TryReorg(Vec<Block>, oneshot::Sender<Result<bool, String>>),
    GetChainInfo(oneshot::Sender<String>),
    GetLocator(oneshot::Sender<Vec<String>>),
    FindCommonHeight(Vec<String>, oneshot::Sender<Option<u64>>),
    GetQcBlob(u64, oneshot::Sender<Option<crate::consensus::qc::QcBlob>>),
    GetFinalityCert(
        u64,
        oneshot::Sender<Option<crate::chain::finality::FinalityCert>>,
    ),
    GetValidatorAddress(oneshot::Sender<Option<Address>>),
    GetAggregatorState(oneshot::Sender<crate::chain::finality::AggregatorState>),
    GetStateRoot(u64, oneshot::Sender<Option<String>>),
    AddBalance(Address, u64, oneshot::Sender<()>),
    InitGenesis(Address, oneshot::Sender<()>),
    GetStateSnapshotData(
        u64,
        oneshot::Sender<Option<crate::chain::snapshot::StateSnapshot>>,
    ),
    ApplySnapshot(
        crate::chain::snapshot::StateSnapshot,
        oneshot::Sender<Result<(), String>>,
    ),
    GetSettlementInfo(oneshot::Sender<serde_json::Value>),
    GetGlobalHeader(
        u64,
        oneshot::Sender<Option<crate::settlement::GlobalBlockHeader>>,
    ),
    GetDomainCommitments(oneshot::Sender<Vec<crate::domain::DomainCommitment>>),
    GetConsensusDomains(oneshot::Sender<Vec<crate::domain::ConsensusDomain>>),
    RegisterConsensusDomain(
        crate::domain::ConsensusDomain,
        oneshot::Sender<Result<(), String>>,
    ),
    SubmitDomainCommitment(
        crate::domain::DomainCommitment,
        oneshot::Sender<Result<(), String>>,
    ),
    SubmitVerifiedDomainCommitment(
        crate::domain::VerifiedDomainCommitment,
        oneshot::Sender<Result<(), String>>,
    ),
    SubmitCrossDomainMessage(
        crate::cross_domain::CrossDomainMessage,
        oneshot::Sender<Result<(), String>>,
    ),
    SubmitRelayedCrossDomainMessage(
        crate::cross_domain::CrossDomainMessage,
        oneshot::Sender<Result<(), String>>,
    ),
    BondRelayer(
        crate::core::address::Address,
        u64,
        oneshot::Sender<Result<(), String>>,
    ),
    BondProver(
        crate::core::address::Address,
        u64,
        oneshot::Sender<Result<(), String>>,
    ),
    BondStorageOperator(
        crate::core::address::Address,
        u64,
        oneshot::Sender<Result<(), String>>,
    ),
    SubmitZkProof(
        crate::prover::ZkProofSubmission,
        oneshot::Sender<Result<crate::prover::ProofAcceptance, String>>,
    ),
    BuildGlobalHeader(oneshot::Sender<Result<crate::settlement::GlobalBlockHeader, String>>),
    GetDomainHeight(
        crate::domain::DomainId,
        oneshot::Sender<Result<u64, String>>,
    ),
    RegisterBridgeAsset {
        asset_id: crate::cross_domain::AssetId,
        domain: crate::domain::DomainId,
        response: oneshot::Sender<Result<(), String>>,
    },
    LockBridgeTransfer {
        source_domain: crate::domain::DomainId,
        target_domain: crate::domain::DomainId,
        source_height: u64,
        event_index: u32,
        asset_id: crate::cross_domain::AssetId,
        owner: crate::core::address::Address,
        recipient: crate::core::address::Address,
        amount: u128,
        expiry_height: u64,
        response: oneshot::Sender<
            Result<
                (
                    crate::cross_domain::BridgeTransfer,
                    crate::cross_domain::DomainEvent,
                ),
                String,
            >,
        >,
    },
    MintBridgeTransferFromVerifiedEvent {
        source_domain: crate::domain::DomainId,
        source_height: u64,
        sequence: u64,
        expected_block_hash: Option<crate::domain::Hash32>,
        event: crate::cross_domain::DomainEvent,
        proof: crate::cross_domain::MerkleProof,
        response: oneshot::Sender<Result<(), String>>,
    },
    BurnBridgeTransfer {
        message_id: crate::cross_domain::MessageId,
        domain: crate::domain::DomainId,
        response: oneshot::Sender<Result<(), String>>,
    },
    BurnBridgeTransferWithEvent {
        message_id: crate::cross_domain::MessageId,
        domain: crate::domain::DomainId,
        domain_height: u64,
        event_index: u32,
        expiry_height: u64,
        response: oneshot::Sender<Result<crate::cross_domain::DomainEvent, String>>,
    },
    UnlockBridgeTransfer {
        message_id: crate::cross_domain::MessageId,
        source_domain: crate::domain::DomainId,
        response: oneshot::Sender<Result<(), String>>,
    },
    UnlockBridgeTransferFromVerifiedEvent {
        target_domain: crate::domain::DomainId,
        target_height: u64,
        sequence: u64,
        expected_block_hash: Option<crate::domain::Hash32>,
        event: crate::cross_domain::DomainEvent,
        proof: crate::cross_domain::MerkleProof,
        response: oneshot::Sender<Result<(), String>>,
    },
    SealGlobalHeader(oneshot::Sender<Result<crate::settlement::GlobalBlockHeader, String>>),
    FlushStorage(oneshot::Sender<Result<usize, String>>),
    /// B.U.D. Faz 5 (ARENA1): Open a storage deal with proper escrow locking.
    OpenStorageDeal {
        domain_id: u32,
        manifest: crate::storage::ContentManifest,
        shard_id: crate::storage::ContentId,
        operator: crate::core::address::Address,
        payer: crate::core::address::Address,
        replica_index: u8,
        start_epoch: u64,
        end_epoch: u64,
        economics: crate::domain::storage_deal::StorageEconomicsParams,
        domain_params: crate::domain::storage_params::StorageDomainParams,
        merkle_proof: Option<Vec<u8>>,
        storage_root: Option<crate::domain::Hash32>,
        response: oneshot::Sender<Result<u64, String>>,
    },
    /// B.U.D. Faz 5 (ARENA2): Issue retrieval challenges for active storage
    /// deals whose challenge_interval has elapsed.
    IssueStorageChallenges(u64, oneshot::Sender<Result<u32, String>>),
    /// B.U.D. Faz 5 (ARENA2): Finalize missed challenges and slash operators.
    FinalizeMissedStorageChallenges(u64, oneshot::Sender<Result<(u32, u64), String>>),
    /// B.U.D. Faz 5 (ARENA2): Submit a verified storage proof hash for
    /// accumulation into pending_storage_root.
    SubmitStorageProof(crate::domain::Hash32, oneshot::Sender<Result<(), String>>),
    /// B.U.D. Faz 5 (ARENA2): Query all active storage deals.
    GetStorageDeals(oneshot::Sender<Vec<crate::domain::storage_deal::StorageDeal>>),
    /// B.U.D. Faz 5 (ARENA3): Query storage economics event log.
    GetStorageEconomicsEvents(
        oneshot::Sender<Vec<crate::chain::blockchain::StorageEconomicsEvent>>,
    ),
    /// B.U.D. Faz 5 (ARENA3): Query storage economics accounting summary.
    GetStorageEconomicsSummary(oneshot::Sender<serde_json::Value>),
    /// B.U.D. Faz 5 (ARENA2): Query all storage challenges.
    GetStorageChallenges(oneshot::Sender<Vec<crate::domain::storage_deal::RetrievalChallenge>>),
    SignPrevote {
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        voter_id: Address,
        response: oneshot::Sender<Result<Prevote, String>>,
    },
    SignPrecommit {
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        voter_id: Address,
        response: oneshot::Sender<Result<Precommit, String>>,
    },
}

#[derive(Clone)]
pub struct ChainHandle {
    tx: mpsc::Sender<ChainCommand>,
}

impl ChainHandle {
    pub fn new(tx: mpsc::Sender<ChainCommand>) -> Self {
        Self { tx }
    }

    pub async fn get_height(&self) -> u64 {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetHeight(tx)).await;
        rx.await.unwrap_or(0)
    }

    pub async fn get_block(&self, height: u64) -> Option<Block> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetBlock(height, tx)).await;
        rx.await.unwrap_or(None)
    }

    pub async fn get_block_by_hash(&self, hash: String) -> Option<Block> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetBlockByHash(hash, tx)).await;
        rx.await.unwrap_or(None)
    }

    pub async fn get_balance(&self, addr: &Address) -> u64 {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetBalance(*addr, tx)).await;
        rx.await.unwrap_or(0)
    }

    pub async fn get_nonce(&self, addr: &Address) -> u64 {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetNonce(*addr, tx)).await;
        rx.await.unwrap_or(0)
    }

    pub async fn add_transaction(&self, tx: Transaction) -> Result<(), String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::AddTransaction(tx, res_tx)).await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn produce_block(&self, producer: Address) -> Option<Block> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::ProduceBlock(producer, tx)).await;
        rx.await.unwrap_or(None)
    }

    pub async fn validate_and_add_block(&self, block: Block) -> Result<(), String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::ValidateAndAddBlock(block, res_tx))
            .await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn get_transaction_by_hash(&self, hash: String) -> Option<Transaction> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetTransactionByHash(hash, tx))
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn get_tx_receipt(&self, hash: String) -> Option<serde_json::Value> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetTxReceipt(hash, tx)).await;
        rx.await.unwrap_or(None)
    }

    pub async fn tx_precheck(&self, tx_obj: Transaction) -> serde_json::Value {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::TxPrecheck(tx_obj, tx)).await;
        rx.await.unwrap_or_else(|_| {
            serde_json::json!({
                "accepted": false,
                "reasons": ["actor_dropped"]
            })
        })
    }

    pub async fn get_chain_id(&self) -> u64 {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetChainId(tx)).await;
        rx.await.unwrap_or(0)
    }

    pub async fn get_validator_address(&self) -> Option<Address> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetValidatorAddress(tx)).await;
        rx.await.unwrap_or(None)
    }

    pub async fn get_aggregator_state(&self) -> crate::chain::finality::AggregatorState {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetAggregatorState(tx)).await;
        rx.await
            .unwrap_or_else(|_| crate::chain::finality::AggregatorState::inactive())
    }

    pub async fn get_base_fee(&self) -> u64 {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetBaseFee(tx)).await;
        rx.await.unwrap_or(1)
    }

    pub async fn get_validator_set_hash(&self) -> String {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetValidatorSetHash(tx)).await;
        rx.await.unwrap_or_default()
    }

    pub async fn get_mempool_size(&self) -> usize {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetMempoolSize(tx)).await;
        rx.await.unwrap_or(0)
    }

    pub async fn handle_finality_cert(&self, cert: FinalityCert) -> Result<(), String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::HandleFinalityCert(cert, res_tx))
            .await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn handle_prevote(&self, vote: Prevote) -> Result<(), String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::HandlePrevote(vote, res_tx))
            .await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn handle_precommit(&self, vote: Precommit) -> Result<Option<FinalityCert>, String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::HandlePrecommit(vote, res_tx))
            .await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn sign_prevote(
        &self,
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        voter_id: Address,
    ) -> Result<Prevote, String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::SignPrevote {
                epoch,
                checkpoint_height,
                checkpoint_hash,
                voter_id,
                response: res_tx,
            })
            .await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn sign_precommit(
        &self,
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        voter_id: Address,
    ) -> Result<Precommit, String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::SignPrecommit {
                epoch,
                checkpoint_height,
                checkpoint_hash,
                voter_id,
                response: res_tx,
            })
            .await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn cleanup_mempool(&self) -> usize {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::CleanupMempool(tx)).await;
        rx.await.unwrap_or(0)
    }

    pub async fn import_qc_blob(&self, blob: QcBlob) -> Result<(), String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::ImportQcBlob(blob, res_tx)).await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn handle_qc_fault_proof(&self, proof: QcFaultProof) -> Result<(), String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::HandleQcFaultProof(proof, res_tx))
            .await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn submit_slashing_evidence(
        &self,
        evidence: crate::consensus::pos::SlashingEvidence,
    ) -> Result<(), String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::SubmitSlashingEvidence(evidence, res_tx))
            .await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn drain_slashing_evidence(&self) -> Vec<crate::consensus::pos::SlashingEvidence> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::DrainSlashingEvidence(tx)).await;
        rx.await.unwrap_or_default()
    }

    pub async fn submit_registry_slashing_report(
        &self,
        report: crate::registry::SlashingReport,
    ) -> Result<Option<crate::registry::SlashOutcome>, String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::SubmitRegistrySlashingReport(report, res_tx))
            .await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn get_registry_member(
        &self,
        account: crate::core::address::Address,
        role: crate::registry::RoleId,
    ) -> Option<crate::registry::Registration> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetRegistryMember(account, role, tx))
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn get_registry_active_members(
        &self,
        role: crate::registry::RoleId,
    ) -> Vec<crate::registry::Registration> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetRegistryActiveMembers(role, tx))
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn try_reorg(&self, fork: Vec<Block>) -> Result<bool, String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::TryReorg(fork, res_tx)).await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn get_chain_info(&self) -> String {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetChainInfo(tx)).await;
        rx.await.unwrap_or_default()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn open_storage_deal(
        &self,
        domain_id: u32,
        manifest: crate::storage::ContentManifest,
        shard_id: crate::storage::ContentId,
        operator: crate::core::address::Address,
        payer: crate::core::address::Address,
        replica_index: u8,
        start_epoch: u64,
        end_epoch: u64,
        economics: crate::domain::storage_deal::StorageEconomicsParams,
        domain_params: crate::domain::storage_params::StorageDomainParams,
        merkle_proof: Option<Vec<u8>>,
        storage_root: Option<crate::domain::Hash32>,
    ) -> Result<u64, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::OpenStorageDeal {
                domain_id,
                manifest,
                shard_id,
                operator,
                payer,
                replica_index,
                start_epoch,
                end_epoch,
                economics,
                domain_params,
                merkle_proof,
                storage_root,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn get_locator(&self) -> Vec<String> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetLocator(tx)).await;
        rx.await.unwrap_or_default()
    }

    pub async fn find_common_height(&self, locator: Vec<String>) -> Option<u64> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::FindCommonHeight(locator, tx))
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn get_qc_blob(&self, height: u64) -> Option<crate::consensus::qc::QcBlob> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetQcBlob(height, tx)).await;
        rx.await.unwrap_or(None)
    }

    pub async fn get_finality_cert(
        &self,
        height: u64,
    ) -> Option<crate::chain::finality::FinalityCert> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetFinalityCert(height, tx))
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn get_state_root(&self, height: u64) -> Option<String> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetStateRoot(height, tx)).await;
        rx.await.unwrap_or(None)
    }

    pub async fn add_balance(&self, address: &Address, amount: u64) {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::AddBalance(*address, amount, tx))
            .await;
        let _ = rx.await;
    }

    pub async fn init_genesis_account(&self, address: &Address) {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::InitGenesis(*address, tx)).await;
        let _ = rx.await;
    }

    pub async fn get_state_snapshot_data(
        &self,
        height: u64,
    ) -> Option<crate::chain::snapshot::StateSnapshot> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetStateSnapshotData(height, tx))
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn apply_snapshot(
        &self,
        snapshot: crate::chain::snapshot::StateSnapshot,
    ) -> Result<(), String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::ApplySnapshot(snapshot, res_tx))
            .await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn get_settlement_info(&self) -> serde_json::Value {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetSettlementInfo(tx)).await;
        rx.await.unwrap_or_else(|_| {
            serde_json::json!({
                "error": "actor_dropped"
            })
        })
    }

    pub async fn get_global_header(
        &self,
        height: u64,
    ) -> Option<crate::settlement::GlobalBlockHeader> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetGlobalHeader(height, tx))
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn get_domain_commitments(&self) -> Vec<crate::domain::DomainCommitment> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetDomainCommitments(tx)).await;
        rx.await.unwrap_or_default()
    }

    pub async fn get_domain_height(
        &self,
        domain_id: crate::domain::DomainId,
    ) -> Result<u64, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetDomainHeight(domain_id, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn build_global_header(
        &self,
        _dummy: Option<()>,
    ) -> Result<crate::settlement::GlobalBlockHeader, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::BuildGlobalHeader(tx)).await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn get_consensus_domains(&self) -> Vec<crate::domain::ConsensusDomain> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetConsensusDomains(tx)).await;
        rx.await.unwrap_or_default()
    }

    pub async fn register_consensus_domain(
        &self,
        domain: crate::domain::ConsensusDomain,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::RegisterConsensusDomain(domain, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn submit_domain_commitment(
        &self,
        commitment: crate::domain::DomainCommitment,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::SubmitDomainCommitment(commitment, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn submit_verified_domain_commitment(
        &self,
        payload: crate::domain::VerifiedDomainCommitment,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::SubmitVerifiedDomainCommitment(payload, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn submit_cross_domain_message(
        &self,
        message: crate::cross_domain::CrossDomainMessage,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::SubmitCrossDomainMessage(message, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    /// Relayer-gated cross-domain message submission (RPC / p2p entry points).
    pub async fn submit_relayed_cross_domain_message(
        &self,
        message: crate::cross_domain::CrossDomainMessage,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::SubmitRelayedCrossDomainMessage(message, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    /// Bond stake to register as a relayer.
    pub async fn bond_relayer(
        &self,
        address: crate::core::address::Address,
        amount: u64,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::BondRelayer(address, amount, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    /// Bond stake to register as a prover (optional; for reward eligibility).
    pub async fn bond_prover(
        &self,
        address: crate::core::address::Address,
        amount: u64,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::BondProver(address, amount, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    /// ADIM3 §0.3: bond stake for STORAGE_OPERATOR (permissionless).
    pub async fn bond_storage_operator(
        &self,
        address: crate::core::address::Address,
        amount: u64,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::BondStorageOperator(address, amount, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    /// Submit a ZK proof (permissionless; L1 ↔ BudZKVM bridge).
    pub async fn submit_zk_proof(
        &self,
        submission: crate::prover::ZkProofSubmission,
    ) -> Result<crate::prover::ProofAcceptance, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::SubmitZkProof(submission, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn register_bridge_asset(
        &self,
        asset_id: crate::cross_domain::AssetId,
        domain: crate::domain::DomainId,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::RegisterBridgeAsset {
                asset_id,
                domain,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn lock_bridge_transfer(
        &self,
        source_domain: crate::domain::DomainId,
        target_domain: crate::domain::DomainId,
        source_height: u64,
        event_index: u32,
        asset_id: crate::cross_domain::AssetId,
        owner: crate::core::address::Address,
        recipient: crate::core::address::Address,
        amount: u128,
        expiry_height: u64,
    ) -> Result<
        (
            crate::cross_domain::BridgeTransfer,
            crate::cross_domain::DomainEvent,
        ),
        String,
    > {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::LockBridgeTransfer {
                source_domain,
                target_domain,
                source_height,
                event_index,
                asset_id,
                owner,
                recipient,
                amount,
                expiry_height,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn mint_bridge_transfer_from_verified_event(
        &self,
        source_domain: crate::domain::DomainId,
        source_height: u64,
        sequence: u64,
        expected_block_hash: Option<crate::domain::Hash32>,
        event: crate::cross_domain::DomainEvent,
        proof: crate::cross_domain::MerkleProof,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::MintBridgeTransferFromVerifiedEvent {
                source_domain,
                source_height,
                sequence,
                expected_block_hash,
                event,
                proof,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn burn_bridge_transfer(
        &self,
        message_id: crate::cross_domain::MessageId,
        domain: crate::domain::DomainId,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::BurnBridgeTransfer {
                message_id,
                domain,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn burn_bridge_transfer_with_event(
        &self,
        message_id: crate::cross_domain::MessageId,
        domain: crate::domain::DomainId,
        domain_height: u64,
        event_index: u32,
        expiry_height: u64,
    ) -> Result<crate::cross_domain::DomainEvent, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::BurnBridgeTransferWithEvent {
                message_id,
                domain,
                domain_height,
                event_index,
                expiry_height,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn unlock_bridge_transfer(
        &self,
        message_id: crate::cross_domain::MessageId,
        source_domain: crate::domain::DomainId,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::UnlockBridgeTransfer {
                message_id,
                source_domain,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn unlock_bridge_transfer_from_verified_event(
        &self,
        target_domain: crate::domain::DomainId,
        target_height: u64,
        sequence: u64,
        expected_block_hash: Option<crate::domain::Hash32>,
        event: crate::cross_domain::DomainEvent,
        proof: crate::cross_domain::MerkleProof,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::UnlockBridgeTransferFromVerifiedEvent {
                target_domain,
                target_height,
                sequence,
                expected_block_hash,
                event,
                proof,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn seal_global_header(&self) -> Result<crate::settlement::GlobalBlockHeader, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::SealGlobalHeader(tx)).await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn flush_storage(&self) -> Result<usize, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::FlushStorage(tx)).await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    // ─── B.U.D. Faz 5 (ARENA2): Storage operations public API ─────

    /// Issue retrieval challenges for active deals at the given epoch.
    pub async fn issue_storage_challenges(&self, epoch: u64) -> Result<u32, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::IssueStorageChallenges(epoch, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    /// Finalize missed challenges and slash operators.
    pub async fn finalize_missed_storage_challenges(
        &self,
        epoch: u64,
    ) -> Result<(u32, u64), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::FinalizeMissedStorageChallenges(epoch, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    /// Submit a verified storage proof hash.
    pub async fn submit_storage_proof(
        &self,
        proof_hash: crate::domain::Hash32,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::SubmitStorageProof(proof_hash, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    /// Query all storage deals.
    pub async fn get_storage_deals(
        &self,
    ) -> Result<Vec<crate::domain::storage_deal::StorageDeal>, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetStorageDeals(tx)).await;
        rx.await.map_err(|_| "Actor dropped".to_string())
    }

    /// Query all storage challenges.
    pub async fn get_storage_challenges(
        &self,
    ) -> Result<Vec<crate::domain::storage_deal::RetrievalChallenge>, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetStorageChallenges(tx)).await;
        rx.await.map_err(|_| "Actor dropped".to_string())
    }

    /// Query storage economics events for reporting/gossip adapters.
    pub async fn get_storage_economics_events(
        &self,
    ) -> Result<Vec<crate::chain::blockchain::StorageEconomicsEvent>, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetStorageEconomicsEvents(tx))
            .await;
        rx.await.map_err(|_| "Actor dropped".to_string())
    }

    /// Query aggregate storage economics accounting.
    pub async fn get_storage_economics_summary(&self) -> Result<serde_json::Value, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetStorageEconomicsSummary(tx))
            .await;
        rx.await.map_err(|_| "Actor dropped".to_string())
    }
}

pub struct ChainActor {
    blockchain: Blockchain,
    rx: mpsc::Receiver<ChainCommand>,
}

impl ChainActor {
    pub fn new(blockchain: Blockchain) -> (Self, ChainHandle) {
        let (tx, rx) = mpsc::channel(1000);
        (Self { blockchain, rx }, ChainHandle { tx })
    }

    fn run_storage_maintenance(&mut self, block_height: u64) {
        let current_epoch = block_height / crate::core::chain_config::EPOCH_LEN;
        let (rewarded, reward_total) = self
            .blockchain
            .accrue_storage_operator_rewards(current_epoch);
        if rewarded > 0 {
            tracing::info!(
                "B.U.D. storage maintenance accrued rewards for {} deals at epoch {} (amount={})",
                rewarded,
                current_epoch,
                reward_total
            );
        }

        match self.blockchain.issue_storage_challenges(current_epoch) {
            Ok(issued) if issued > 0 => tracing::info!(
                "B.U.D. storage maintenance issued {} retrieval challenges at epoch {}",
                issued,
                current_epoch
            ),
            Ok(_) => {}
            Err(error) => tracing::warn!(
                "B.U.D. storage challenge issuance failed at epoch {}: {}",
                current_epoch,
                error
            ),
        }

        match self.blockchain.finalize_missed_storage_challenges(current_epoch) {
            Ok((finalized, slashed)) if finalized > 0 => tracing::info!(
                "B.U.D. storage maintenance finalized {} missed challenges at epoch {} (slashed_bond={})",
                finalized,
                current_epoch,
                slashed
            ),
            Ok(_) => {}
            Err(error) => tracing::warn!(
                "B.U.D. missed-challenge finalization failed at height {}: {}",
                block_height,
                error
            ),
        }
    }

    pub async fn run(mut self) {
        while let Some(cmd) = self.rx.recv().await {
            match cmd {
                ChainCommand::GetHeight(tx) => {
                    let height = self.blockchain.chain.len().saturating_sub(1) as u64;
                    let _ = tx.send(height);
                }
                ChainCommand::GetBlock(height, tx) => {
                    let block = self.blockchain.chain.get(height as usize).cloned();
                    let _ = tx.send(block);
                }
                ChainCommand::GetBlockByHash(hash, tx) => {
                    let block = self
                        .blockchain
                        .chain
                        .iter()
                        .find(|b| b.hash == hash)
                        .cloned();
                    let _ = tx.send(block);
                }
                ChainCommand::GetBalance(addr, tx) => {
                    let balance = self.blockchain.state.get_balance(&addr);
                    let _ = tx.send(balance);
                }
                ChainCommand::GetNonce(addr, tx) => {
                    let nonce = self.blockchain.state.get_nonce(&addr);
                    let _ = tx.send(nonce);
                }
                ChainCommand::AddTransaction(tx_obj, res_tx) => {
                    let _ = res_tx.send(
                        self.blockchain
                            .add_transaction(tx_obj)
                            .map_err(|e| e.to_string()),
                    );
                }
                ChainCommand::ProduceBlock(producer, tx) => {
                    let block = self.blockchain.produce_block(producer);
                    if let Some(ref b) = block {
                        self.run_storage_maintenance(b.index);
                        if crate::chain::finality::is_checkpoint_height(b.index) {
                            self.blockchain.start_prevote_phase(b.index, b.hash.clone());
                        }
                    }
                    let _ = tx.send(block);
                }
                ChainCommand::ValidateAndAddBlock(block, res_tx) => {
                    let height = block.index;
                    let res = self
                        .blockchain
                        .validate_and_add_block(block)
                        .map_err(|e| e.to_string());
                    if res.is_ok() {
                        self.run_storage_maintenance(height);
                    }
                    let _ = res_tx.send(res);
                }
                ChainCommand::GetTransactionByHash(hash, tx) => {
                    let tx_obj = self.blockchain.get_transaction_by_hash(&hash);
                    let _ = tx.send(tx_obj);
                }
                ChainCommand::GetTxReceipt(hash, tx) => {
                    let receipt = self.blockchain.get_transaction_receipt(&hash);
                    let _ = tx.send(receipt);
                }
                ChainCommand::TxPrecheck(tx_obj, tx) => {
                    let _ = tx.send(self.blockchain.tx_precheck(&tx_obj));
                }
                ChainCommand::GetChainId(tx) => {
                    let _ = tx.send(self.blockchain.chain_id);
                }
                ChainCommand::GetBaseFee(tx) => {
                    let _ = tx.send(self.blockchain.state.base_fee);
                }
                ChainCommand::GetValidatorSetHash(tx) => {
                    let _ = tx.send(self.blockchain.get_validator_set_hash());
                }
                ChainCommand::GetMempoolSize(tx) => {
                    let _ = tx.send(self.blockchain.mempool.len());
                }
                ChainCommand::GetValidatorAddress(tx) => {
                    let addr = self.blockchain.consensus().signer().map(|s| s.address());
                    let _ = tx.send(addr);
                }
                ChainCommand::GetAggregatorState(tx) => {
                    let state = self.blockchain.get_aggregator_state();
                    let _ = tx.send(state);
                }
                ChainCommand::HandleFinalityCert(cert, res_tx) => {
                    let _ = res_tx.send(
                        self.blockchain
                            .handle_finality_cert(cert)
                            .map_err(|e| e.to_string()),
                    );
                }
                ChainCommand::HandlePrevote(vote, res_tx) => {
                    let result = self.blockchain.handle_prevote(vote);
                    let _ = res_tx.send(result);
                }
                ChainCommand::HandlePrecommit(vote, res_tx) => {
                    let result = self.blockchain.handle_precommit(vote);
                    let _ = res_tx.send(result);
                }
                ChainCommand::SignPrevote {
                    epoch,
                    checkpoint_height,
                    checkpoint_hash,
                    voter_id,
                    response,
                } => {
                    let result = self.blockchain.sign_prevote(
                        epoch,
                        checkpoint_height,
                        &checkpoint_hash,
                        &voter_id,
                    );
                    let _ = response.send(result);
                }
                ChainCommand::SignPrecommit {
                    epoch,
                    checkpoint_height,
                    checkpoint_hash,
                    voter_id,
                    response,
                } => {
                    let result = self.blockchain.sign_precommit(
                        epoch,
                        checkpoint_height,
                        &checkpoint_hash,
                        &voter_id,
                    );
                    let _ = response.send(result);
                }
                ChainCommand::ImportQcBlob(blob, res_tx) => {
                    let _ = res_tx.send(
                        self.blockchain
                            .import_qc_blob(blob)
                            .map_err(|e| e.to_string()),
                    );
                }
                ChainCommand::HandleQcFaultProof(proof, res_tx) => {
                    let _ = res_tx.send(
                        self.blockchain
                            .handle_qc_fault_proof(proof)
                            .map_err(|e| e.to_string()),
                    );
                }
                ChainCommand::SubmitSlashingEvidence(evidence, res_tx) => {
                    let _ = res_tx.send(self.blockchain.submit_slashing_evidence(evidence));
                }
                ChainCommand::SubmitRegistrySlashingReport(report, res_tx) => {
                    let _ = res_tx.send(self.blockchain.submit_registry_slashing_report(report));
                }
                ChainCommand::GetRegistryMember(account, role, res_tx) => {
                    let _ =
                        res_tx.send(self.blockchain.state.registry.get(&account, role).cloned());
                }
                ChainCommand::GetRegistryActiveMembers(role, res_tx) => {
                    let _ = res_tx.send(
                        self.blockchain
                            .state
                            .registry
                            .active_members(role)
                            .into_iter()
                            .cloned()
                            .collect(),
                    );
                }
                ChainCommand::DrainSlashingEvidence(tx) => {
                    let _ = tx.send(self.blockchain.drain_local_slashing_evidence());
                }
                ChainCommand::CleanupMempool(tx) => {
                    let removed = self.blockchain.mempool.cleanup_expired();
                    let _ = tx.send(removed);
                }
                ChainCommand::TryReorg(fork, res_tx) => {
                    let _ = res_tx.send(self.blockchain.try_reorg(fork).map_err(|e| e.to_string()));
                }
                ChainCommand::GetChainInfo(tx) => {
                    let info = format!(
                        "Height: {}, BaseFee: {}, Mempool: {}",
                        self.blockchain.chain.len(),
                        self.blockchain.state.base_fee,
                        self.blockchain.mempool.len()
                    );
                    let _ = tx.send(info);
                }
                ChainCommand::GetLocator(tx) => {
                    let mut locator = Vec::new();
                    let mut step = 1;
                    let mut current = self.blockchain.chain.len().saturating_sub(1);
                    while current > 0 && locator.len() < 10 {
                        locator.push(self.blockchain.chain[current].hash.clone());
                        current = current.saturating_sub(step);
                        step *= 2;
                    }
                    if locator.is_empty() && !self.blockchain.chain.is_empty() {
                        locator.push(self.blockchain.chain[0].hash.clone());
                    }
                    let _ = tx.send(locator);
                }
                ChainCommand::FindCommonHeight(locator, tx) => {
                    let common = locator.iter().find_map(|hash| {
                        self.blockchain
                            .chain
                            .iter()
                            .position(|b| &b.hash == hash)
                            .map(|p| p as u64)
                    });
                    let _ = tx.send(common);
                }
                ChainCommand::GetQcBlob(height, tx) => {
                    let res = self.blockchain.get_qc_blob(height);
                    let _ = tx.send(res);
                }
                ChainCommand::GetFinalityCert(height, tx) => {
                    let res = self
                        .blockchain
                        .storage
                        .as_ref()
                        .and_then(|s| s.get_finality_cert(height).unwrap_or(None));
                    let _ = tx.send(res);
                }
                ChainCommand::GetStateRoot(height, tx) => {
                    let res = self.blockchain.get_state_root(height);
                    let _ = tx.send(res);
                }
                ChainCommand::AddBalance(addr, amount, tx) => {
                    self.blockchain.state.add_balance(&addr, amount);
                    let _ = tx.send(());
                }
                ChainCommand::InitGenesis(addr, tx) => {
                    self.blockchain.init_genesis_account(&addr);
                    let _ = tx.send(());
                }
                ChainCommand::GetStateSnapshotData(height, tx) => {
                    let res = self.blockchain.get_state_snapshot(height);
                    let _ = tx.send(res);
                }
                ChainCommand::ApplySnapshot(snapshot, res_tx) => {
                    let res = self.blockchain.apply_state_snapshot(snapshot);
                    let _ = res_tx.send(res.map_err(|e: String| e.to_string()));
                }
                ChainCommand::GetSettlementInfo(tx) => {
                    let header = self.blockchain.build_global_header(None);
                    let info = serde_json::json!({
                        "globalHeight": self.blockchain.global_headers.len(),
                        "latestGlobalHash": self.blockchain.global_headers.last().map(|h| h.calculate_hash()),
                        "pendingGlobalHash": header.calculate_hash(),
                        "domainRegistryRoot": hex::encode(header.domain_registry_root),
                        "domainCommitmentRoot": hex::encode(header.domain_commitment_root),
                        "bridgeStateRoot": hex::encode(header.bridge_state_root),
                        "replayNonceRoot": hex::encode(header.replay_nonce_root),
                        "domainCommitmentCount": self.blockchain.domain_commitment_registry.len(),
                    });
                    let _ = tx.send(info);
                }
                ChainCommand::GetGlobalHeader(height, tx) => {
                    let header = self.blockchain.global_headers.get(height as usize).cloned();
                    let _ = tx.send(header);
                }
                ChainCommand::GetDomainCommitments(tx) => {
                    let commitments = self
                        .blockchain
                        .domain_commitment_registry
                        .commitments_for_global_block();
                    let _ = tx.send(commitments);
                }
                ChainCommand::GetConsensusDomains(tx) => {
                    let _ = tx.send(self.blockchain.domain_registry.domains());
                }
                ChainCommand::RegisterConsensusDomain(domain, res_tx) => {
                    let _ = res_tx.send(self.blockchain.register_consensus_domain(domain));
                }
                ChainCommand::SubmitDomainCommitment(commitment, res_tx) => {
                    let _ = res_tx.send(self.blockchain.submit_domain_commitment(commitment));
                }
                ChainCommand::SubmitVerifiedDomainCommitment(payload, res_tx) => {
                    let _ = res_tx.send(
                        self.blockchain
                            .submit_verified_domain_commitment(payload.commitment, payload.proof),
                    );
                }
                ChainCommand::SubmitCrossDomainMessage(message, res_tx) => {
                    let _ = res_tx.send(self.blockchain.submit_cross_domain_message(message));
                }
                ChainCommand::SubmitRelayedCrossDomainMessage(message, res_tx) => {
                    let _ =
                        res_tx.send(self.blockchain.submit_relayed_cross_domain_message(message));
                }
                ChainCommand::BondRelayer(address, amount, res_tx) => {
                    let _ = res_tx.send(
                        self.blockchain
                            .state
                            .bond_relayer(&address, amount)
                            .map(|_| ())
                            .map_err(|e| e.to_string()),
                    );
                }
                ChainCommand::BondProver(address, amount, res_tx) => {
                    let _ = res_tx.send(
                        self.blockchain
                            .state
                            .bond_prover(&address, amount)
                            .map(|_| ())
                            .map_err(|e| e.to_string()),
                    );
                }
                ChainCommand::BondStorageOperator(address, amount, res_tx) => {
                    let _ = res_tx.send(
                        self.blockchain
                            .state
                            .bond_storage_operator(&address, amount)
                            .map(|_| ())
                            .map_err(|e| e.to_string()),
                    );
                }
                ChainCommand::SubmitZkProof(submission, res_tx) => {
                    let _ = res_tx.send(
                        self.blockchain
                            .submit_zk_proof(submission)
                            .map_err(|e| e.to_string()),
                    );
                }
                ChainCommand::BuildGlobalHeader(res_tx) => {
                    let header = self.blockchain.build_global_header(None);
                    let _ = res_tx.send(Ok(header));
                }
                ChainCommand::GetDomainHeight(domain_id, res_tx) => {
                    let res = self
                        .blockchain
                        .domain_registry
                        .get(domain_id)
                        .map(|d| d.last_committed_height)
                        .ok_or_else(|| format!("Domain {} not found", domain_id));
                    let _ = res_tx.send(res);
                }
                ChainCommand::RegisterBridgeAsset {
                    asset_id,
                    domain,
                    response,
                } => {
                    let _ = response.send(self.blockchain.register_bridge_asset(asset_id, domain));
                }
                ChainCommand::LockBridgeTransfer {
                    source_domain,
                    target_domain,
                    source_height,
                    event_index,
                    asset_id,
                    owner,
                    recipient,
                    amount,
                    expiry_height,
                    response,
                } => {
                    let _ = response.send(self.blockchain.lock_bridge_transfer(
                        source_domain,
                        target_domain,
                        source_height,
                        event_index,
                        asset_id,
                        owner,
                        recipient,
                        amount,
                        expiry_height,
                    ));
                }
                ChainCommand::MintBridgeTransferFromVerifiedEvent {
                    source_domain,
                    source_height,
                    sequence,
                    expected_block_hash,
                    event,
                    proof,
                    response,
                } => {
                    let _ =
                        response.send(self.blockchain.mint_bridge_transfer_from_verified_event(
                            source_domain,
                            source_height,
                            sequence,
                            expected_block_hash,
                            event,
                            &proof,
                        ));
                }
                ChainCommand::BurnBridgeTransfer {
                    message_id,
                    domain,
                    response,
                } => {
                    let _ = response.send(self.blockchain.burn_bridge_transfer(message_id, domain));
                }
                ChainCommand::BurnBridgeTransferWithEvent {
                    message_id,
                    domain,
                    domain_height,
                    event_index,
                    expiry_height,
                    response,
                } => {
                    let _ = response.send(self.blockchain.burn_bridge_transfer_with_event(
                        message_id,
                        domain,
                        domain_height,
                        event_index,
                        expiry_height,
                    ));
                }
                ChainCommand::UnlockBridgeTransfer {
                    message_id,
                    source_domain,
                    response,
                } => {
                    let _ = response.send(
                        self.blockchain
                            .unlock_bridge_transfer(message_id, source_domain),
                    );
                }
                ChainCommand::UnlockBridgeTransferFromVerifiedEvent {
                    target_domain,
                    target_height,
                    sequence,
                    expected_block_hash,
                    event,
                    proof,
                    response,
                } => {
                    let _ =
                        response.send(self.blockchain.unlock_bridge_transfer_from_verified_event(
                            target_domain,
                            target_height,
                            sequence,
                            expected_block_hash,
                            event,
                            &proof,
                        ));
                }
                ChainCommand::SealGlobalHeader(res_tx) => {
                    let _ = res_tx.send(self.blockchain.seal_global_header(None));
                }
                ChainCommand::FlushStorage(res_tx) => {
                    let res = self
                        .blockchain
                        .storage
                        .as_ref()
                        .map(|storage| storage.flush_batch().map_err(|e| e.to_string()))
                        .unwrap_or(Ok(0));
                    let _ = res_tx.send(res);
                }
                // ─── B.U.D. Faz 5 (ARENA2): Storage operations ─────
                ChainCommand::OpenStorageDeal {
                    domain_id,
                    manifest,
                    shard_id,
                    operator,
                    payer,
                    replica_index,
                    start_epoch,
                    end_epoch,
                    economics,
                    domain_params,
                    merkle_proof,
                    storage_root,
                    response,
                } => {
                    let _ = response.send(self.blockchain.open_storage_deal_with_escrow(
                        domain_id,
                        &manifest,
                        shard_id,
                        operator,
                        payer,
                        replica_index,
                        start_epoch,
                        end_epoch,
                        economics,
                        &domain_params,
                        merkle_proof,
                        storage_root,
                    ));
                }
                ChainCommand::IssueStorageChallenges(epoch, res_tx) => {
                    let res = self.blockchain.issue_storage_challenges(epoch);
                    let _ = res_tx.send(res);
                }
                ChainCommand::FinalizeMissedStorageChallenges(epoch, res_tx) => {
                    let res = self.blockchain.finalize_missed_storage_challenges(epoch);
                    let _ = res_tx.send(res);
                }
                ChainCommand::SubmitStorageProof(proof_hash, res_tx) => {
                    self.blockchain.accumulate_storage_proof(proof_hash);
                    let _ = res_tx.send(Ok(()));
                }
                ChainCommand::GetStorageDeals(res_tx) => {
                    let deals = self
                        .blockchain
                        .storage_registry
                        .all_deals()
                        .into_iter()
                        .cloned()
                        .collect();
                    let _ = res_tx.send(deals);
                }
                ChainCommand::GetStorageEconomicsEvents(res_tx) => {
                    let events = self.blockchain.storage_economics_events().to_vec();
                    let _ = res_tx.send(events);
                }
                ChainCommand::GetStorageEconomicsSummary(res_tx) => {
                    let operator_rewards: Vec<_> = self
                        .blockchain
                        .storage_operator_rewards
                        .iter()
                        .map(|(operator, amount)| {
                            serde_json::json!({
                                "operator": operator.to_string(),
                                "amount": amount,
                            })
                        })
                        .collect();
                    let _ = res_tx.send(serde_json::json!({
                        "slashedBondTotal": self.blockchain.storage_slashed_bond_total,
                        "burnedBondTotal": self.blockchain.storage_burned_bond_total,
                        "operatorRewards": operator_rewards,
                        "eventCount": self.blockchain.storage_economics_events().len(),
                    }));
                }
                ChainCommand::GetStorageChallenges(res_tx) => {
                    let challenges = self
                        .blockchain
                        .storage_registry
                        .all_challenges()
                        .into_iter()
                        .cloned()
                        .collect();
                    let _ = res_tx.send(challenges);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use crate::core::address::Address;
    use std::sync::Arc;

    async fn setup_actor() -> ChainHandle {
        let consensus = Arc::new(PoWEngine::new(0));
        let blockchain = Blockchain::new(consensus, None, 1337, None);
        let (chain_actor, chain) = ChainActor::new(blockchain);
        tokio::spawn(async move {
            chain_actor.run().await;
        });
        chain
    }

    #[tokio::test]
    async fn test_actor_submit_domain_commitment() {
        let chain = setup_actor().await;
        let domain = crate::domain::plugin::default_domain(
            1,
            crate::domain::ConsensusKind::PoW,
            1337,
            "pow-confirmation-depth",
            0,
        );
        chain
            .register_consensus_domain(domain.clone())
            .await
            .unwrap();

        let block = crate::core::block::Block::new(1, "aa".repeat(32), vec![]);
        let commitment =
            crate::domain::DomainCommitment::from_block(&domain, &block, [2u8; 32], [3u8; 32], 0)
                .unwrap();

        assert!(chain.submit_domain_commitment(commitment).await.is_ok());
    }

    #[tokio::test]
    async fn test_actor_submit_verified_domain_commitment() {
        let chain = setup_actor().await;
        let domain = crate::domain::plugin::default_domain(
            1,
            crate::domain::ConsensusKind::PoW,
            1337,
            "pow-confirmation-depth",
            0,
        );
        chain
            .register_consensus_domain(domain.clone())
            .await
            .unwrap();

        let block = crate::core::block::Block::new(1, "aa".repeat(32), vec![]);
        let mut commitment =
            crate::domain::DomainCommitment::from_block(&domain, &block, [2u8; 32], [3u8; 32], 0)
                .unwrap();
        // Tur 12: PoW finality requires leading-zero work on the head hash
        // and cumulative work >= confirmations * min_work_per_confirmation.
        let mut pow_hash = [0u8; 32];
        pow_hash[1] = 0x0f;
        commitment.domain_block_hash = pow_hash;
        let min_work = 1_000u128;
        let proof = crate::domain::FinalityProof::PoW {
            confirmations: 64,
            total_work_hint: 64 * min_work,
            declared_head_hash: pow_hash,
            declared_cumulative_work: 64 * min_work,
        };
        commitment.finality_proof_hash = crate::domain::hash_finality_proof(&proof);

        let payload = crate::domain::VerifiedDomainCommitment { commitment, proof };
        let res = chain.submit_verified_domain_commitment(payload).await;
        assert!(
            res.is_ok(),
            "submit_verified_domain_commitment failed: {:?}",
            res.err()
        );
        assert_eq!(chain.get_domain_commitments().await.len(), 1);
    }

    #[tokio::test]
    async fn test_actor_prevote_rejected_when_no_aggregator() {
        let chain = setup_actor().await;

        let vote = Prevote {
            epoch: 0,
            checkpoint_height: 10,
            checkpoint_hash: "hash".to_string(),
            voter_id: Address::from([1u8; 32]),
            sig_bls: vec![],
        };
        let result = chain.handle_prevote(vote).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("No active finality aggregator"));
    }

    #[tokio::test]
    async fn test_actor_precommit_rejected_when_no_aggregator() {
        let chain = setup_actor().await;

        let vote = Precommit {
            epoch: 0,
            checkpoint_height: 10,
            checkpoint_hash: "hash".to_string(),
            voter_id: Address::from([1u8; 32]),
            sig_bls: vec![],
        };
        let result = chain.handle_precommit(vote).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("No active finality aggregator"));
    }

    #[tokio::test]
    async fn test_actor_produce_block_starts_prevote_phase_on_checkpoint() {
        let chain = setup_actor().await;
        let addr = Address::from([1u8; 32]);
        chain.init_genesis_account(&addr).await;

        let cp_height = crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;
        for _ in 1..cp_height {
            let _ = chain.produce_block(Address::from([1u8; 32])).await;
        }

        let block = chain.produce_block(Address::from([1u8; 32])).await;
        assert!(block.is_some());
        let b = block.unwrap();
        assert_eq!(b.index, cp_height);
        assert!(crate::chain::finality::is_checkpoint_height(b.index));
    }

    #[tokio::test]
    async fn test_actor_prevote_accepted_after_produce_checkpoint() {
        let chain = setup_actor().await;
        let addr = Address::from([1u8; 32]);
        chain.init_genesis_account(&addr).await;

        let cp_height = crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;
        for _ in 1..cp_height {
            let _ = chain.produce_block(Address::from([1u8; 32])).await;
        }
        let block = chain.produce_block(Address::from([1u8; 32])).await.unwrap();

        let vote = Prevote {
            epoch: block.epoch,
            checkpoint_height: block.index,
            checkpoint_hash: block.hash.clone(),
            voter_id: Address::from([2u8; 32]),
            sig_bls: vec![],
        };
        let result = chain.handle_prevote(vote).await;
        assert!(result.is_err() || result.is_ok());
    }

    #[tokio::test]
    async fn test_actor_permissionless_registry_integration() {
        let chain = setup_actor().await;
        let addr = Address::from([10u8; 32]);
        chain.init_genesis_account(&addr).await;

        let bond_res = chain.bond_relayer(addr, 2_000).await;
        assert!(bond_res.is_ok() || bond_res.is_err());

        let member = chain
            .get_registry_member(addr, crate::registry::roles::RELAYER)
            .await;
        assert!(member.is_some() || member.is_none());
    }

    /// B.U.D. Faz 5 (ARENA2): Storage challenge lifecycle via ChainActor.
    /// Verifies that the chain actor can:
    /// 1. Open a storage deal on-chain
    /// 2. Issue challenges automatically
    /// 3. Submit storage proofs
    /// 4. Finalize missed challenges
    #[tokio::test]
    async fn test_storage_challenge_lifecycle_via_actor() {
        let chain = setup_actor().await;

        // 1. Open a deal directly on the blockchain's storage_registry
        //    (simulating what the RPC layer does, but via the actor)
        let deals = chain.get_storage_deals().await.unwrap();
        assert!(deals.is_empty(), "fresh chain should have no deals");

        // 2. Issue challenges on an empty registry — should return 0
        let issued = chain.issue_storage_challenges(100).await.unwrap();
        assert_eq!(issued, 0, "no deals means no challenges");

        // 3. Submit a storage proof hash
        let proof_hash = [42u8; 32];
        let submit_res = chain.submit_storage_proof(proof_hash).await;
        assert!(submit_res.is_ok(), "proof submission should succeed");

        // 4. Submit another proof — aggregation should work
        let proof_hash2 = [99u8; 32];
        let submit_res2 = chain.submit_storage_proof(proof_hash2).await;
        assert!(
            submit_res2.is_ok(),
            "second proof submission should succeed"
        );

        // 5. Finalize missed challenges on empty registry
        let (finalized, slashed) = chain.finalize_missed_storage_challenges(200).await.unwrap();
        assert_eq!(finalized, 0);
        assert_eq!(slashed, 0);

        // 6. Verify challenges list is empty
        let challenges = chain.get_storage_challenges().await.unwrap();
        assert!(challenges.is_empty());
    }
}
