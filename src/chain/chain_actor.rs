use crate::chain::blockchain::Blockchain;
use crate::chain::finality::{FinalityCert, Precommit, Prevote};
use crate::consensus::qc::{QcBlob, QcFaultProof};
use crate::core::address::Address;
use crate::core::block::Block;
use crate::core::transaction::Transaction;
use tokio::sync::{mpsc, oneshot};

/// P5 ADIM11 Bulgu 31: Direction filter for agent payment queries.
#[derive(Debug)]
pub enum AiPaymentDirection {
    From,
    To,
}

#[derive(Debug)]
pub enum ChainCommand {
    GetHeight(oneshot::Sender<u64>),
    GetBlock(u64, oneshot::Sender<Option<Block>>),
    GetBlockByHash(String, oneshot::Sender<Option<Block>>),
    GetBalance(Address, oneshot::Sender<u64>),
    GetNonce(Address, oneshot::Sender<u64>),
    AddTransaction(Transaction, oneshot::Sender<Result<(), String>>),
    ProduceBlock(Address, oneshot::Sender<Option<(Block, Vec<[u8; 32]>)>>),
    ValidateAndAddBlock(Block, oneshot::Sender<Result<Vec<[u8; 32]>, String>>),
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
    StoragePrune([u8; 32]),
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
    SubmitRelayProof {
        message_id: crate::cross_domain::message::MessageId,
        relayer: crate::core::address::Address,
        proof: crate::cross_domain::event_tree::MerkleProof,
        source_domain: crate::domain::types::DomainId,
        response: oneshot::Sender<Result<crate::cross_domain::message::CrossDomainMessage, String>>,
    },
    GetAiModel(
        crate::ai::types::AiModelId,
        oneshot::Sender<Option<crate::ai::types::AiModelSpec>>,
    ),
    GetAiOutcome(
        crate::ai::types::AiRequestId,
        oneshot::Sender<Option<crate::ai::types::AiInferenceOutcome>>,
    ),
    GetAiRequest(
        crate::ai::types::AiRequestId,
        oneshot::Sender<Option<crate::ai::types::AiInferenceRequest>>,
    ),
    GetAiFeeReclaimStatus(
        crate::ai::types::AiRequestId,
        oneshot::Sender<Result<(crate::core::address::Address, u64), String>>,
    ),
    GetAiEquivocationStatus(
        crate::ai::types::AiRequestId,
        crate::core::address::Address,
        oneshot::Sender<bool>,
    ),
    GetAiCancelStatus(crate::ai::types::AiRequestId, oneshot::Sender<bool>),
    /// P5 ADIM10 Bulgu 27: Get comprehensive dispute status for a (request, verifier) pair.
    GetAiDisputeStatus(
        crate::ai::types::AiRequestId,
        crate::core::address::Address,
        oneshot::Sender<crate::ai::types::AiDisputeStatusInfo>,
    ),
    /// P5 ADIM10 Bulgu 27: Get verifier stake info.
    GetAiVerifierStake(
        crate::core::address::Address,
        oneshot::Sender<crate::ai::types::AiVerifierStakeInfo>,
    ),
    /// P5 ADIM10 Bulgu 28: Get callback events for a callback address.
    GetAiCallbackQueue(
        crate::core::address::Address,
        oneshot::Sender<Vec<crate::ai::types::AiCallbackEvent>>,
    ),
    /// P5 ADIM11 Bulgu 29: Get execution proof for a (request, verifier) pair.
    GetAiExecutionProof {
        request_id: crate::ai::types::AiRequestId,
        verifier: crate::core::address::Address,
        response: oneshot::Sender<Option<crate::ai::types::AiExecutionProof>>,
    },
    /// P5 ADIM11 Bulgu 30: Get QoS metrics for a verifier.
    GetAiVerifierQos {
        verifier: crate::core::address::Address,
        response: oneshot::Sender<Option<crate::ai::types::AiVerifierQos>>,
    },
    /// P5 ADIM11 Bulgu 30: Get all verifiers ordered by reliability score (descending).
    GetAiVerifiersByReliability(oneshot::Sender<Vec<crate::ai::types::AiVerifierQos>>),
    /// P5 ADIM11 Bulgu 31: Get agent payment by ID.
    GetAiAgentPayment {
        payment_id: [u8; 32],
        response: oneshot::Sender<Option<crate::ai::types::AiAgentPayment>>,
    },
    /// P5 ADIM11 Bulgu 31: Get payments from/to an agent.
    GetAiAgentPayments {
        agent: crate::core::address::Address,
        direction: AiPaymentDirection,
        response: oneshot::Sender<Vec<crate::ai::types::AiAgentPayment>>,
    },
    /// P5 ADIM11 Bulgu 33: Get verifier whitelist.
    GetAiVerifierWhitelist(oneshot::Sender<Vec<crate::core::address::Address>>),
    GetAiAgentReputation {
        agent: crate::core::address::Address,
        response: oneshot::Sender<Option<crate::ai::types::AiAgentReputation>>,
    },
    GetAiAgentRanking(oneshot::Sender<Vec<(crate::core::address::Address, f64)>>),
    GetPruneStatus(oneshot::Sender<serde_json::Value>),
    RequestPrune(Option<u64>, oneshot::Sender<Result<u64, String>>),
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
        relayer: crate::core::address::Address,
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
    BnsResolve {
        name: String,
        response: oneshot::Sender<Option<Address>>,
    },
    BnsResolveFull {
        name: String,
        response: oneshot::Sender<Option<crate::bns::types::BnsResolved>>,
    },
    BnsResolveContent {
        name: String,
        response: oneshot::Sender<Option<crate::storage::content_id::ContentId>>,
    },
    BnsResolveSubdomain {
        parent: String,
        label: String,
        response: oneshot::Sender<Option<Address>>,
    },
    BnsSetStorage {
        name: String,
        owner: Address,
        storage_root: [u8; 32],
        storage_domain_id: u32,
        response: oneshot::Sender<Result<(), String>>,
    },
    BnsCalculateCost {
        name: String,
        duration: u64,
        response: oneshot::Sender<u64>,
    },
    NftGet {
        id: u64,
        response: oneshot::Sender<Option<crate::socialfi::types::Nft>>,
    },
    NftGetByOwner {
        owner: Address,
        response: oneshot::Sender<Vec<crate::socialfi::types::Nft>>,
    },
    NftGetFeed {
        limit: usize,
        response: oneshot::Sender<Vec<crate::socialfi::types::Nft>>,
    },
    MarketGetOffers {
        response: oneshot::Sender<Vec<crate::pollen::DataOffer>>,
    },
    PollenGetDataAssets {
        response: oneshot::Sender<Vec<crate::pollen::DataAsset>>,
    },
    PollenGetAccessGrants {
        response: oneshot::Sender<Vec<crate::pollen::AccessGrant>>,
    },
    PollenGetSaleAuthorizations {
        response: oneshot::Sender<Vec<crate::pollen::SaleAuthorization>>,
    },
    HubGetApps {
        response: oneshot::Sender<Vec<crate::hub::types::AppRecord>>,
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

    pub async fn produce_block(&self, producer: Address) -> Option<(Block, Vec<[u8; 32]>)> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.tx.send(ChainCommand::ProduceBlock(producer, tx)).await {
            tracing::error!(error = %e, "Failed to send ProduceBlock command to chain actor");
            return None;
        }
        rx.await.unwrap_or(None)
    }

    pub async fn validate_and_add_block(&self, block: Block) -> Result<Vec<[u8; 32]>, String> {
        let (res_tx, res_rx) = oneshot::channel();
        if let Err(e) = self
            .tx
            .send(ChainCommand::ValidateAndAddBlock(block, res_tx))
            .await
        {
            return Err(format!("Actor dropped: {}", e));
        }
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
        if let Err(e) = self
            .tx
            .send(ChainCommand::AddBalance(*address, amount, tx))
            .await
        {
            tracing::error!(error = %e, "Failed to send AddBalance command to chain actor");
            return;
        }
        if let Err(e) = rx.await {
            tracing::error!(error = %e, "AddBalance response channel closed prematurely");
        }
    }

    pub async fn init_genesis_account(&self, address: &Address) {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.tx.send(ChainCommand::InitGenesis(*address, tx)).await {
            tracing::error!(error = %e, "Failed to send InitGenesis command to chain actor");
            return;
        }
        if let Err(e) = rx.await {
            tracing::error!(error = %e, "InitGenesis response channel closed prematurely");
        }
    }

    pub async fn storage_prune(&self, cid: [u8; 32]) {
        if let Err(e) = self.tx.send(ChainCommand::StoragePrune(cid)).await {
            tracing::error!(error = %e, "Failed to send StoragePrune command to chain actor");
        }
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

    /// Phase 3 §0.3: bond stake for STORAGE_OPERATOR (permissionless).
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

    pub async fn submit_relay_proof(
        &self,
        message_id: crate::cross_domain::message::MessageId,
        relayer: crate::core::address::Address,
        proof: crate::cross_domain::event_tree::MerkleProof,
        source_domain: crate::domain::types::DomainId,
    ) -> Result<crate::cross_domain::message::CrossDomainMessage, String> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self
            .tx
            .send(ChainCommand::SubmitRelayProof {
                message_id,
                relayer,
                proof,
                source_domain,
                response: tx,
            })
            .await
        {
            return Err(format!("Actor dropped: {}", e));
        }
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn get_ai_model(
        &self,
        id: crate::ai::types::AiModelId,
    ) -> Option<crate::ai::types::AiModelSpec> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiModel(id, tx))
            .await
            .is_err()
        {
            return None;
        }
        rx.await.unwrap_or(None)
    }

    pub async fn get_ai_outcome(
        &self,
        id: crate::ai::types::AiRequestId,
    ) -> Option<crate::ai::types::AiInferenceOutcome> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiOutcome(id, tx))
            .await
            .is_err()
        {
            return None;
        }
        rx.await.unwrap_or(None)
    }

    pub async fn get_ai_request(
        &self,
        id: crate::ai::types::AiRequestId,
    ) -> Option<crate::ai::types::AiInferenceRequest> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiRequest(id, tx))
            .await
            .is_err()
        {
            return None;
        }
        rx.await.unwrap_or(None)
    }

    pub async fn get_ai_fee_reclaim_status(
        &self,
        id: crate::ai::types::AiRequestId,
    ) -> Result<(crate::core::address::Address, u64), String> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiFeeReclaimStatus(id, tx))
            .await
            .is_err()
        {
            return Err("ChainActor disconnected".into());
        }
        rx.await
            .map_err(|_| "ChainActor response dropped".to_string())?
    }

    pub async fn get_ai_equivocation_status(
        &self,
        request_id: crate::ai::types::AiRequestId,
        verifier: crate::core::address::Address,
    ) -> bool {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiEquivocationStatus(
                request_id, verifier, tx,
            ))
            .await
            .is_err()
        {
            return false;
        }
        rx.await.unwrap_or(false)
    }

    pub async fn get_ai_cancel_status(&self, request_id: crate::ai::types::AiRequestId) -> bool {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiCancelStatus(request_id, tx))
            .await
            .is_err()
        {
            return false;
        }
        rx.await.unwrap_or(false)
    }

    /// P5 ADIM10 Bulgu 27: Get comprehensive dispute status.
    pub async fn get_ai_dispute_status(
        &self,
        request_id: crate::ai::types::AiRequestId,
        verifier: crate::core::address::Address,
    ) -> crate::ai::types::AiDisputeStatusInfo {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiDisputeStatus(request_id, verifier, tx))
            .await
            .is_err()
        {
            return crate::ai::types::AiDisputeStatusInfo {
                has_equivocated: false,
                is_disputable: false,
                detected_block: None,
                dispute_window_remaining: None,
                is_staked: false,
                stake_amount: 0,
            };
        }
        rx.await
            .unwrap_or_else(|_| crate::ai::types::AiDisputeStatusInfo {
                has_equivocated: false,
                is_disputable: false,
                detected_block: None,
                dispute_window_remaining: None,
                is_staked: false,
                stake_amount: 0,
            })
    }

    /// P5 ADIM10 Bulgu 27: Get verifier stake info.
    pub async fn get_ai_verifier_stake(
        &self,
        verifier: crate::core::address::Address,
    ) -> crate::ai::types::AiVerifierStakeInfo {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiVerifierStake(verifier, tx))
            .await
            .is_err()
        {
            return crate::ai::types::AiVerifierStakeInfo {
                verifier,
                is_staked: false,
                stake_amount: 0,
                total_equivocations: 0,
            };
        }
        rx.await
            .unwrap_or_else(|_| crate::ai::types::AiVerifierStakeInfo {
                verifier,
                is_staked: false,
                stake_amount: 0,
                total_equivocations: 0,
            })
    }

    /// P5 ADIM10 Bulgu 28: Get callback events for a callback address.
    pub async fn get_ai_callback_queue(
        &self,
        callback_address: crate::core::address::Address,
    ) -> Vec<crate::ai::types::AiCallbackEvent> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiCallbackQueue(callback_address, tx))
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// P5 ADIM11 Bulgu 29: Get execution proof for a (request, verifier) pair.
    /// Returns None if no proof exists — results without proofs are
    /// "trust-based"; results with proofs are "trustless" (ZKVM-verified).
    pub async fn get_ai_execution_proof(
        &self,
        request_id: crate::ai::types::AiRequestId,
        verifier: crate::core::address::Address,
    ) -> Option<crate::ai::types::AiExecutionProof> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiExecutionProof {
                request_id,
                verifier,
                response: tx,
            })
            .await
            .is_err()
        {
            return None;
        }
        rx.await.ok().flatten()
    }

    /// P5 ADIM11 Bulgu 30: Get QoS metrics for a verifier.
    pub async fn get_ai_verifier_qos(
        &self,
        verifier: crate::core::address::Address,
    ) -> Option<crate::ai::types::AiVerifierQos> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiVerifierQos {
                verifier,
                response: tx,
            })
            .await
            .is_err()
        {
            return None;
        }
        rx.await.ok().flatten()
    }

    /// P5 ADIM11 Bulgu 30: Get all verifiers ordered by reliability score.
    pub async fn get_ai_verifiers_by_reliability(&self) -> Vec<crate::ai::types::AiVerifierQos> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiVerifiersByReliability(tx))
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// P5 ADIM11 Bulgu 31: Get agent payment by ID.
    pub async fn get_ai_agent_payment(
        &self,
        payment_id: [u8; 32],
    ) -> Option<crate::ai::types::AiAgentPayment> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiAgentPayment {
                payment_id,
                response: tx,
            })
            .await
            .is_err()
        {
            return None;
        }
        rx.await.ok().flatten()
    }

    /// P5 ADIM11 Bulgu 31: Get payments for an agent.
    pub async fn get_ai_agent_payments(
        &self,
        agent: crate::core::address::Address,
        direction: AiPaymentDirection,
    ) -> Vec<crate::ai::types::AiAgentPayment> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiAgentPayments {
                agent,
                direction,
                response: tx,
            })
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// P5 ADIM11 Bulgu 33: Get verifier whitelist.
    pub async fn get_ai_verifier_whitelist(&self) -> Vec<crate::core::address::Address> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiVerifierWhitelist(tx))
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn get_ai_agent_reputation(
        &self,
        agent: crate::core::address::Address,
    ) -> Option<crate::ai::types::AiAgentReputation> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiAgentReputation {
                agent,
                response: tx,
            })
            .await
            .is_err()
        {
            return None;
        }
        rx.await.ok()?
    }

    pub async fn get_ai_agent_ranking(&self) -> Vec<(crate::core::address::Address, f64)> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiAgentRanking(tx))
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn get_prune_status(&self) -> Result<serde_json::Value, String> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.tx.send(ChainCommand::GetPruneStatus(tx)).await {
            return Err(format!("Actor dropped: {}", e));
        }
        rx.await.map_err(|_| "Actor dropped".to_string())
    }

    pub async fn request_prune(&self, min_blocks_to_keep: Option<u64>) -> Result<u64, String> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self
            .tx
            .send(ChainCommand::RequestPrune(min_blocks_to_keep, tx))
            .await
        {
            return Err(format!("Actor dropped: {}", e));
        }
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
        relayer: crate::core::address::Address,
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
                relayer,
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

    pub async fn bns_resolve(&self, name: String) -> Option<Address> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::BnsResolve { name, response: tx })
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn bns_resolve_full(&self, name: String) -> Option<crate::bns::types::BnsResolved> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::BnsResolveFull { name, response: tx })
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn bns_resolve_content(
        &self,
        name: String,
    ) -> Option<crate::storage::content_id::ContentId> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::BnsResolveContent { name, response: tx })
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn bns_resolve_subdomain(&self, parent: String, label: String) -> Option<Address> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::BnsResolveSubdomain {
                parent,
                label,
                response: tx,
            })
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn bns_set_storage(
        &self,
        name: String,
        owner: Address,
        storage_root: [u8; 32],
        storage_domain_id: u32,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::BnsSetStorage {
                name,
                owner,
                storage_root,
                storage_domain_id,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn bns_calculate_cost(&self, name: String, duration: u64) -> u64 {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::BnsCalculateCost {
                name,
                duration,
                response: tx,
            })
            .await;
        rx.await.unwrap_or(0)
    }

    pub async fn nft_get(&self, id: u64) -> Option<crate::socialfi::types::Nft> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::NftGet { id, response: tx })
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn nft_get_by_owner(&self, owner: Address) -> Vec<crate::socialfi::types::Nft> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::NftGetByOwner {
                owner,
                response: tx,
            })
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn nft_get_feed(&self, limit: usize) -> Vec<crate::socialfi::types::Nft> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::NftGetFeed {
                limit,
                response: tx,
            })
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn market_get_offers(&self) -> Vec<crate::pollen::DataOffer> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::MarketGetOffers { response: tx })
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn pollen_get_data_assets(&self) -> Vec<crate::pollen::DataAsset> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::PollenGetDataAssets { response: tx })
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn pollen_get_access_grants(&self) -> Vec<crate::pollen::AccessGrant> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::PollenGetAccessGrants { response: tx })
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn pollen_get_sale_authorizations(&self) -> Vec<crate::pollen::SaleAuthorization> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::PollenGetSaleAuthorizations { response: tx })
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn hub_get_apps(&self) -> Vec<crate::hub::types::AppRecord> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::HubGetApps { response: tx })
            .await;
        rx.await.unwrap_or_default()
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
                    let result = self.blockchain.produce_block(producer);
                    if let Some((ref b, ref cids)) = result {
                        self.run_storage_maintenance(b.index);
                        if crate::chain::finality::is_checkpoint_height(b.index) {
                            self.blockchain.start_prevote_phase(b.index, b.hash.clone());
                        }
                        if !cids.is_empty() {
                            tracing::info!(count = cids.len(), "NftBurn detected during production — notifying node for physical pruning");
                        }
                    }
                    let _ = tx.send(result);
                }
                ChainCommand::ValidateAndAddBlock(block, res_tx) => {
                    let height = block.index;
                    let res = self.blockchain.validate_and_add_block(block);
                    if let Ok(ref cids) = res {
                        self.run_storage_maintenance(height);
                        if !cids.is_empty() {
                            tracing::info!(
                                count = cids.len(),
                                "NftBurn detected — notifying node for physical pruning"
                            );
                        }
                    }
                    let _ = res_tx.send(res);
                }
                ChainCommand::StoragePrune(cid) => {
                    // Manual prune trigger from CLI/RPC
                    let now_epoch = self.blockchain.state.epoch_index;
                    let cid_obj = crate::storage::content_id::ContentId(cid);
                    let pruned_deals = self
                        .blockchain
                        .state
                        .storage_registry
                        .prune_content(&cid_obj, now_epoch);
                    tracing::info!(
                        cid = %hex::encode(cid),
                        pruned_deals,
                        "Manual B.U.D. Hard Prune: storage registry entry removed"
                    );
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
                ChainCommand::SubmitRelayProof {
                    message_id,
                    relayer,
                    proof,
                    source_domain,
                    response,
                } => {
                    let _ = response.send(self.blockchain.submit_relay_proof(
                        message_id,
                        relayer,
                        &proof,
                        source_domain,
                    ));
                }
                ChainCommand::GetAiModel(id, res_tx) => {
                    let res = self.blockchain.state.ai_registry.models.get(&id).cloned();
                    let _ = res_tx.send(res);
                }
                ChainCommand::GetAiOutcome(id, res_tx) => {
                    let res = self.blockchain.state.ai_registry.outcomes.get(&id).cloned();
                    let _ = res_tx.send(res);
                }
                ChainCommand::GetAiRequest(id, res_tx) => {
                    let res = self.blockchain.state.ai_registry.requests.get(&id).cloned();
                    let _ = res_tx.send(res);
                }
                ChainCommand::GetAiFeeReclaimStatus(id, res_tx) => {
                    let current_block = self.blockchain.state.epoch_index.saturating_mul(100);
                    let mut registry = self.blockchain.state.ai_registry.clone();
                    let res = registry.reclaim_fee(&id, current_block);
                    let _ = res_tx.send(res);
                }
                ChainCommand::GetAiEquivocationStatus(request_id, verifier, res_tx) => {
                    let has_equivocated = self
                        .blockchain
                        .state
                        .ai_registry
                        .has_equivocated(&request_id, &verifier);
                    let _ = res_tx.send(has_equivocated);
                }
                ChainCommand::GetAiCancelStatus(request_id, res_tx) => {
                    let is_cancelled = self.blockchain.state.ai_registry.is_cancelled(&request_id);
                    let _ = res_tx.send(is_cancelled);
                }
                ChainCommand::GetAiDisputeStatus(request_id, verifier, res_tx) => {
                    let current_block = self.blockchain.state.epoch_index.saturating_mul(100);
                    let status = self.blockchain.state.ai_registry.get_dispute_status(
                        &request_id,
                        &verifier,
                        current_block,
                    );
                    let _ = res_tx.send(status);
                }
                ChainCommand::GetAiVerifierStake(verifier, res_tx) => {
                    let info = self
                        .blockchain
                        .state
                        .ai_registry
                        .get_verifier_stake_info(&verifier);
                    let _ = res_tx.send(info);
                }
                ChainCommand::GetAiCallbackQueue(callback_address, res_tx) => {
                    let events = self
                        .blockchain
                        .state
                        .ai_registry
                        .get_callback_queue(&callback_address);
                    let _ = res_tx.send(events);
                }
                ChainCommand::GetAiExecutionProof {
                    request_id,
                    verifier,
                    response: res_tx,
                } => {
                    let proof = self
                        .blockchain
                        .state
                        .ai_registry
                        .get_execution_proof(&request_id, &verifier)
                        .cloned();
                    let _ = res_tx.send(proof);
                }
                ChainCommand::GetAiVerifierQos {
                    verifier,
                    response: res_tx,
                } => {
                    let qos = self
                        .blockchain
                        .state
                        .ai_registry
                        .get_verifier_qos(&verifier)
                        .cloned();
                    let _ = res_tx.send(qos);
                }
                ChainCommand::GetAiVerifiersByReliability(res_tx) => {
                    let ranking = self.blockchain.state.ai_registry.verifiers_by_reliability();
                    let _ = res_tx.send(ranking);
                }
                ChainCommand::GetAiAgentPayment {
                    payment_id,
                    response: res_tx,
                } => {
                    let payment = self
                        .blockchain
                        .state
                        .ai_registry
                        .get_agent_payment(&payment_id)
                        .cloned();
                    let _ = res_tx.send(payment);
                }
                ChainCommand::GetAiAgentPayments {
                    agent,
                    direction,
                    response: res_tx,
                } => {
                    let payments = match direction {
                        AiPaymentDirection::From => self
                            .blockchain
                            .state
                            .ai_registry
                            .payments_from_agent(&agent),
                        AiPaymentDirection::To => {
                            self.blockchain.state.ai_registry.payments_to_agent(&agent)
                        }
                    }
                    .into_iter()
                    .cloned()
                    .collect();
                    let _ = res_tx.send(payments);
                }
                ChainCommand::GetAiVerifierWhitelist(res_tx) => {
                    let whitelist: Vec<_> = self
                        .blockchain
                        .state
                        .ai_registry
                        .get_whitelisted_verifiers()
                        .iter()
                        .cloned()
                        .collect();
                    let _ = res_tx.send(whitelist);
                }
                ChainCommand::GetAiAgentReputation { agent, response } => {
                    let rep = self
                        .blockchain
                        .state
                        .ai_registry
                        .get_agent_reputation(&agent)
                        .cloned();
                    let _ = response.send(rep);
                }
                ChainCommand::GetAiAgentRanking(res_tx) => {
                    let ranking = self.blockchain.state.ai_registry.agents_by_trust_score();
                    let _ = res_tx.send(ranking);
                }
                ChainCommand::GetPruneStatus(res_tx) => {
                    let height = self.blockchain.chain.len() as u64;
                    let finalized = self.blockchain.finalized_height;
                    let mobile_mode = self
                        .blockchain
                        .pruning_manager
                        .as_ref()
                        .map(|pm| pm.min_blocks_to_keep < 1000)
                        .unwrap_or(false);
                    let res = serde_json::json!({
                        "current_height": height,
                        "finalized_height": finalized,
                        "mobile_mode": mobile_mode,
                        "snapshot_dir": self.blockchain.pruning_manager.as_ref().map(|pm| pm.snapshot_dir.clone()),
                    });
                    let _ = res_tx.send(res);
                }
                ChainCommand::RequestPrune(min_blocks, res_tx) => {
                    let height = self.blockchain.chain.len() as u64;
                    let finalized = self.blockchain.finalized_height;
                    let mut pruned_count = 0;
                    if let Some(ref pm) = self.blockchain.pruning_manager {
                        let keep = min_blocks.unwrap_or(pm.min_blocks_to_keep);
                        let prunable =
                            pm.get_prunable_blocks(height, height.saturating_sub(1), finalized);
                        if let Some(ref store) = self.blockchain.storage {
                            for h in &prunable {
                                if let Ok(_) = store.delete_block(*h) {
                                    pruned_count += 1;
                                }
                            }
                        }
                    }
                    let _ = res_tx.send(Ok(pruned_count));
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
                        .ok_or_else(|| format!("Domain {domain_id} not found"));
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
                    relayer,
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
                            relayer,
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
                        .state
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
                        .state
                        .storage_registry
                        .all_challenges()
                        .into_iter()
                        .cloned()
                        .collect();
                    let _ = res_tx.send(challenges);
                }
                ChainCommand::BnsResolve { name, response } => {
                    let _ = response.send(
                        self.blockchain
                            .state
                            .bns_registry
                            .resolve(&name, self.blockchain.state.epoch_index),
                    );
                }
                ChainCommand::BnsResolveFull { name, response } => {
                    let _ = response.send(
                        self.blockchain
                            .state
                            .bns_registry
                            .resolve_full(&name, self.blockchain.state.epoch_index),
                    );
                }
                ChainCommand::BnsResolveContent { name, response } => {
                    let _ = response.send(
                        self.blockchain
                            .state
                            .bns_registry
                            .resolve_content(&name, self.blockchain.state.epoch_index),
                    );
                }
                ChainCommand::BnsResolveSubdomain {
                    parent,
                    label,
                    response,
                } => {
                    let _ = response.send(self.blockchain.state.bns_registry.resolve_subdomain(
                        &parent,
                        &label,
                        self.blockchain.state.epoch_index,
                    ));
                }
                ChainCommand::BnsSetStorage {
                    name,
                    owner,
                    storage_root,
                    storage_domain_id,
                    response,
                } => {
                    let _ = response.send(
                        self.blockchain
                            .state
                            .bns_registry
                            .set_storage(
                                &name,
                                owner,
                                storage_root,
                                storage_domain_id,
                                self.blockchain.state.epoch_index,
                            )
                            .map_err(|e| e.to_string()),
                    );
                }
                ChainCommand::BnsCalculateCost {
                    name,
                    duration,
                    response,
                } => {
                    let _ = response.send(
                        self.blockchain
                            .state
                            .bns_registry
                            .calculate_cost(&name, duration),
                    );
                }
                ChainCommand::NftGet { id, response } => {
                    let _ = response.send(self.blockchain.state.nft_registry.get_nft(id).cloned());
                }
                ChainCommand::NftGetByOwner { owner, response } => {
                    let nft_ids = self
                        .blockchain
                        .state
                        .nft_registry
                        .ownership
                        .get(&owner)
                        .cloned()
                        .unwrap_or_default();
                    let nfts: Vec<_> = nft_ids
                        .iter()
                        .filter_map(|id| self.blockchain.state.nft_registry.get_nft(*id))
                        .cloned()
                        .collect();
                    let _ = response.send(nfts);
                }
                ChainCommand::NftGetFeed { limit, response } => {
                    let nfts: Vec<_> = self
                        .blockchain
                        .state
                        .nft_registry
                        .nfts
                        .values()
                        .rev()
                        .take(limit)
                        .cloned()
                        .collect();
                    let _ = response.send(nfts);
                }
                ChainCommand::MarketGetOffers { response } => {
                    let offers: Vec<_> = self
                        .blockchain
                        .state
                        .marketplace
                        .offers
                        .values()
                        .cloned()
                        .collect();
                    let _ = response.send(offers);
                }
                ChainCommand::PollenGetDataAssets { response } => {
                    let assets: Vec<_> = self
                        .blockchain
                        .state
                        .marketplace
                        .data_assets
                        .values()
                        .cloned()
                        .collect();
                    let _ = response.send(assets);
                }
                ChainCommand::PollenGetAccessGrants { response } => {
                    let grants: Vec<_> = self
                        .blockchain
                        .state
                        .marketplace
                        .access_grants
                        .values()
                        .cloned()
                        .collect();
                    let _ = response.send(grants);
                }
                ChainCommand::PollenGetSaleAuthorizations { response } => {
                    let authorizations: Vec<_> = self
                        .blockchain
                        .state
                        .marketplace
                        .sale_authorizations
                        .values()
                        .cloned()
                        .collect();
                    let _ = response.send(authorizations);
                }
                ChainCommand::HubGetApps { response } => {
                    let apps: Vec<_> = self.blockchain.state.hub.apps.values().cloned().collect();
                    let _ = response.send(apps);
                }
            }
        }
    }
}
