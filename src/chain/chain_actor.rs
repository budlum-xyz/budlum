use crate::chain::blockchain::Blockchain;
use crate::chain::finality::{FinalityCert, Precommit, Prevote};
use crate::consensus::qc::{QcBlob, QcFaultProof};
use crate::core::address::Address;
use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::storage::merkle_trie::AccountProofBundle;
use tokio::sync::{mpsc, oneshot};

/// Direction filter for agent payment queries.
#[derive(Debug)]
pub enum AiPaymentDirection {
    From,
    To,
}

/// The storage repair picture at one caller-supplied margin.
///
/// Two lists, kept apart on purpose. An object in `repairable` still has at
/// least `k` shards and can be rebuilt, so the response is to open a
/// replacement deal. An object in `unrecoverable` has fewer than `k` and
/// cannot be rebuilt from what survives; opening a deal for it restores
/// nothing and burns an operator bond. Folding the two together would let the
/// second hide inside the first and read as "a repair is coming".
#[derive(Debug, Default, Clone)]
pub struct StorageRepairBand {
    /// The margin the caller asked about.
    pub margin: u32,
    /// `(manifest_id, live_shards, k)` where `k <= live < k + margin`.
    pub repairable: Vec<(crate::storage::ContentId, u32, u32)>,
    /// `(manifest_id, live_shards, k)` where `live < k`.
    pub unrecoverable: Vec<(crate::storage::ContentId, u32, u32)>,
}

#[derive(Debug)]
pub enum ChainCommand {
    GetHeight(oneshot::Sender<u64>),
    GetFinalizedHeight(oneshot::Sender<u64>),
    GetBlock(u64, oneshot::Sender<Option<Block>>),
    /// A contiguous run of local blocks, `[from, from + count)`.
    ///
    /// The peer-driven reorg path needs the whole shared prefix in one step.
    /// Asking for it one height at a time cost one round trip per block, which
    /// is why a per-batch cap was placed on the fork height in the first
    /// place; with a single read the only real bounds are the suffix length
    /// and the fork depth, both already checked by the caller.
    GetBlocksRange(u64, usize, oneshot::Sender<Vec<Block>>),
    GetBlockByHash(String, oneshot::Sender<Option<Block>>),
    GetBalance(Address, oneshot::Sender<u64>),
    GetNonce(Address, oneshot::Sender<u64>),
    /// Account inclusion/absence proof against the proof-bearing state root.
    ///
    /// Distinct from [`Self::GetBalance`]: that answers what the node says a
    /// balance is, this answers what the node can *prove* about it.
    GetAccountProof(
        Address,
        oneshot::Sender<Option<crate::storage::merkle_trie::AccountProofBundle>>,
    ),
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
    /// Whether the mempool still holds the transaction with this hash.
    MempoolContains(String, oneshot::Sender<bool>),
    HandleFinalityCert(FinalityCert, oneshot::Sender<Result<(), String>>),
    /// Sync over a pruned window: blocks, the certificate that ends
    /// them and its ML-DSA-65 QC.
    ImportPrunedSegment(
        Vec<Block>,
        Box<FinalityCert>,
        Box<crate::consensus::qc::QcBlob>,
        oneshot::Sender<Result<usize, String>>,
    ),
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
    GetRegistryMember(
        crate::core::address::Address,
        crate::registry::RoleId,
        oneshot::Sender<Option<crate::registry::Registration>>,
    ),
    GetRegistryActiveMembers(
        crate::registry::RoleId,
        oneshot::Sender<Vec<crate::registry::Registration>>,
    ),
    GetDelegations(
        crate::core::address::Address,
        oneshot::Sender<Vec<crate::registry::permissionless::DelegationPosition>>,
    ),
    GetDelegationExits(
        crate::core::address::Address,
        oneshot::Sender<Vec<crate::registry::permissionless::DelegationUnbonding>>,
    ),
    /// One validator's profile (`Some(address)`) or every validator's.
    GetValidatorProfiles(
        Option<crate::core::address::Address>,
        oneshot::Sender<Vec<serde_json::Value>>,
    ),
    GetSlashingHistory(oneshot::Sender<Vec<crate::registry::permissionless::SlashingRecord>>),
    DrainSlashingEvidence(oneshot::Sender<Vec<crate::consensus::pos::SlashingEvidence>>),
    CleanupMempool(oneshot::Sender<usize>),
    TryReorg(Vec<Block>, oneshot::Sender<Result<bool, String>>),
    /// Join this actor's own chain with a peer-supplied suffix and evaluate a
    /// reorg (CWE-400). The prefix never leaves the actor: the caller sends
    /// only the fork blocks, whatever height the peer claims to fork at.
    TryReorgSuffix(Vec<Block>, oneshot::Sender<Result<bool, String>>),
    GetChainInfo(oneshot::Sender<String>),
    GetLocator(oneshot::Sender<Vec<String>>),
    FindCommonHeight(Vec<String>, oneshot::Sender<Option<u64>>),
    GetQcBlob(u64, oneshot::Sender<Option<crate::consensus::qc::QcBlob>>),
    GetFinalityCert(
        u64,
        oneshot::Sender<Option<crate::chain::finality::FinalityCert>>,
    ),
    GetPqStageObservation(
        crate::domain::regeneration_stage::Stage,
        u64,
        oneshot::Sender<crate::chain::blockchain::PqStageObservation>,
    ),
    GetPqSealedHeights(u64, oneshot::Sender<(Option<u64>, Option<u64>)>),
    GetQuantumView(oneshot::Sender<serde_json::Value>),
    GetValidatorAddress(oneshot::Sender<Option<Address>>),
    GetAggregatorState(oneshot::Sender<crate::chain::finality::AggregatorState>),
    GetStateRoot(u64, oneshot::Sender<Option<String>>),
    AddBalance(Address, u64, oneshot::Sender<Result<(), String>>),
    FundDevelopmentAccount(Address, oneshot::Sender<Result<(), String>>),
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
    GetGraftApplication(
        [u8; 32],
        oneshot::Sender<Option<crate::settlement::graft::GraftApp>>,
    ),
    GetRestakedValidators(
        oneshot::Sender<(
            Vec<crate::settlement::shared_security::RestakedValidator>,
            std::collections::BTreeMap<crate::core::address::Address, u64>,
        )>,
    ),
    GetGraftPaymentProof(
        [u8; 32],
        oneshot::Sender<Option<crate::settlement::graft::GraftPaymentProof>>,
    ),
    GetCrossDomainMessage(
        [u8; 32],
        oneshot::Sender<Option<crate::cross_domain::CrossDomainMessage>>,
    ),
    GetBridgeTransfer(
        [u8; 32],
        oneshot::Sender<Option<crate::cross_domain::BridgeTransfer>>,
    ),
    GetRelayerStatus(Option<[u8; 32]>, oneshot::Sender<serde_json::Value>),
    GetRelayerIntent([u8; 32], oneshot::Sender<serde_json::Value>),
    GetSovereignTemplate(
        crate::domain::types::DomainId,
        oneshot::Sender<Option<crate::domain::SovereignDomainTemplate>>,
    ),
    ValidateSovereignAuditExport(
        Box<crate::domain::sovereign::AuditExportBundle>,
        oneshot::Sender<Result<(), String>>,
    ),
    // BLG-0199 (P10-F09): the raw, unverified-commitment path is test-only to
    // the last hop. Production RPC answers `bud_submitDomainCommitment` with a
    // refusal, and there is no longer any command route from the actor into
    // `Blockchain::accept_domain_commitment` in a release build - a path that
    // merely "returns Err in prod today" still compiles the unsafe body in
    // every future build. Test suites keep their harness entry below.
    #[cfg(test)]
    SubmitDomainCommitment(
        crate::domain::DomainCommitment,
        oneshot::Sender<Result<(), String>>,
    ),
    GetExternalDomainProfile(
        crate::cross_domain::external::DomainKey,
        oneshot::Sender<
            Option<(
                crate::cross_domain::external::DomainProfile,
                crate::cross_domain::external::IntakeEntry,
                crate::cross_domain::external::AdapterDescriptor,
            )>,
        >,
    ),
    GetExternalDomainProfiles(
        oneshot::Sender<Vec<(crate::cross_domain::external::DomainProfile, String)>>,
    ),
    GetExternalIntakeDigest(oneshot::Sender<Result<[u8; 32], String>>),
    GetExternalQuorumRound(
        crate::cross_domain::external::DomainKey,
        u64,
        oneshot::Sender<Option<crate::cross_domain::external::QuorumRound>>,
    ),
    GetExternalQuorumRounds(
        crate::cross_domain::external::DomainKey,
        oneshot::Sender<(
            Option<crate::cross_domain::external::QuorumPolicy>,
            Vec<crate::cross_domain::external::QuorumRound>,
        )>,
    ),
    GetExternalDomainRegistration(
        crate::cross_domain::external::DomainKey,
        oneshot::Sender<Option<(crate::cross_domain::external::DomainRegistration, u64)>>,
    ),
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
    /// Requests with no outcome whose deadline has not passed (test
    /// verifier harness).
    GetAiOpenRequests(oneshot::Sender<Vec<crate::ai::types::AiInferenceRequest>>),
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
    /// Get comprehensive dispute status for a (request, verifier) pair.
    GetAiDisputeStatus(
        crate::ai::types::AiRequestId,
        crate::core::address::Address,
        oneshot::Sender<crate::ai::types::AiDisputeStatusInfo>,
    ),
    /// Get verifier stake info.
    GetAiVerifierStake(
        crate::core::address::Address,
        oneshot::Sender<crate::ai::types::AiVerifierStakeInfo>,
    ),
    /// Get callback events for a callback address.
    GetAiCallbackQueue(
        crate::core::address::Address,
        oneshot::Sender<Vec<crate::ai::types::AiCallbackEvent>>,
    ),
    /// Get execution proof for a (request, verifier) pair.
    GetAiExecutionProof {
        request_id: crate::ai::types::AiRequestId,
        verifier: crate::core::address::Address,
        response: oneshot::Sender<Option<crate::ai::types::AiExecutionProof>>,
    },
    /// Get QoS metrics for a verifier.
    GetAiVerifierQos {
        verifier: crate::core::address::Address,
        response: oneshot::Sender<Option<crate::ai::types::AiVerifierQos>>,
    },
    /// Get all verifiers ordered by reliability score (descending).
    GetAiVerifiersByReliability(oneshot::Sender<Vec<crate::ai::types::AiVerifierQos>>),
    /// Get agent payment by ID.
    GetAiAgentPayment {
        payment_id: [u8; 32],
        response: oneshot::Sender<Option<crate::ai::types::AiAgentPayment>>,
    },
    /// Get payments from/to an agent.
    GetAiAgentPayments {
        agent: crate::core::address::Address,
        direction: AiPaymentDirection,
        response: oneshot::Sender<Vec<crate::ai::types::AiAgentPayment>>,
    },
    /// Get verifier whitelist.
    GetAiVerifierWhitelist(oneshot::Sender<Vec<crate::core::address::Address>>),
    GetAiAgentReputation {
        agent: crate::core::address::Address,
        response: oneshot::Sender<Option<crate::ai::types::AiAgentReputation>>,
    },
    // BLG-0201 (P10-F11): fixed-point permyriad score, not an `f64` - the
    // actor boundary does not carry floats (Z8).
    GetAiAgentRanking(oneshot::Sender<Vec<(crate::core::address::Address, u64)>>),
    GetPruneStatus(oneshot::Sender<serde_json::Value>),
    RequestPrune(Option<u64>, oneshot::Sender<Result<u64, String>>),
    BuildGlobalHeader(oneshot::Sender<Result<crate::settlement::GlobalBlockHeader, String>>),
    GetDomainHeight(
        crate::domain::DomainId,
        oneshot::Sender<Result<u64, String>>,
    ),
    #[cfg(test)]
    SealGlobalHeader(oneshot::Sender<Result<crate::settlement::GlobalBlockHeader, String>>),
    ///: a committed checkpoint header with the material a light client
    /// checks it against: the checkpoint block and the state root opening.
    GetGlobalHeaderProof(
        u64,
        oneshot::Sender<Option<crate::chain::blockchain::GlobalHeaderProof>>,
    ),
    FlushStorage(oneshot::Sender<Result<usize, String>>),
    /// View-key permission book (Classic private body or Three encrypted recipe).
    IssueViewGrant {
        content_id: crate::storage::ContentId,
        auth: crate::storage::GrantAuthorization,
        grantee: Option<crate::core::address::Address>,
        key_id: [u8; 32],
        policy: crate::storage::ViewPolicy,
        opened_epoch: u64,
        response: oneshot::Sender<Result<u64, String>>,
    },
    RevokeViewGrant {
        grant_id: u64,
        auth: crate::storage::GrantAuthorization,
        at_epoch: u64,
        response: oneshot::Sender<Result<crate::storage::ViewGrant, String>>,
    },
    SocialDelete {
        content_id: crate::storage::ContentId,
        auth: crate::storage::GrantAuthorization,
        at_epoch: u64,
        response: oneshot::Sender<Result<crate::storage::DeleteOutcome, String>>,
    },
    /// Every grant row of one content, with how many of them are live. A read
    /// command: it moves nothing and cannot be refused by the mainnet guard.
    GetViewGrants {
        content_id: crate::storage::ContentId,
        response: oneshot::Sender<(Vec<crate::storage::ViewGrant>, usize)>,
    },
    MayViewContent {
        content_id: crate::storage::ContentId,
        viewer: crate::core::address::Address,
        key_id: [u8; 32],
        owner: crate::core::address::Address,
        response: oneshot::Sender<bool>,
    },
    /// Classic/2.0 confidential body commit (not Three).
    RegisterConfidentialCommit {
        commit: crate::storage::ConfidentialBodyCommit,
        auth: crate::storage::GrantAuthorization,
        response: oneshot::Sender<Result<[u8; 32], String>>,
    },
    GetConfidentialCommit {
        content_id: crate::storage::ContentId,
        response: oneshot::Sender<Option<crate::storage::ConfidentialBodyCommit>>,
    },
    /// Who the chain believes speaks for a confidential object.
    GetConfidentialOwner {
        content_id: crate::storage::ContentId,
        response: oneshot::Sender<Option<crate::core::address::Address>>,
    },
    /// Derive a coding audit for a manifest against chain entropy.
    ///
    /// A retrieval challenge asks whether the operator still holds the bytes.
    /// It cannot ask whether those bytes are valid parity, because the chain
    /// never sees shard contents, so an operator can pass every retrieval
    /// challenge while storing garbage under a parity shard's `ContentId` and
    /// nobody finds out until the repair that needs it.
    ///
    /// `derive_coding_audit` and `verify_coding_audit` were written for that
    /// and no chain path reached either.
    DeriveCodingAudit {
        manifest_id: crate::storage::ContentId,
        challenge_id: u64,
        response: oneshot::Sender<Result<crate::domain::storage_deal::CodingAudit, String>>,
    },
    /// Check an answered coding audit against the generator.
    AnswerCodingAudit {
        audit: crate::domain::storage_deal::CodingAudit,
        data_column: Vec<u8>,
        parity_byte: u8,
        /// The Merkle opening of the answered column. The registry checks the
        /// column against the manifest's commitment before the Reed-Solomon
        /// relationship, so a memorised column cannot pass as an answer.
        column_proof: Vec<[u8; 32]>,
        response: oneshot::Sender<Result<(), String>>,
    },
    GetStorageManifest {
        manifest_id: crate::storage::ContentId,
        response: oneshot::Sender<Option<crate::storage::ContentManifest>>,
    },
    GetStorageDealsByManifest {
        manifest_id: crate::storage::ContentId,
        response: oneshot::Sender<Vec<crate::domain::storage_deal::StorageDeal>>,
    },
    GetStorageDealsByShard {
        manifest_id: crate::storage::ContentId,
        shard_id: crate::storage::ContentId,
        response: oneshot::Sender<Vec<crate::domain::storage_deal::StorageDeal>>,
    },
    GetStorageOutcome {
        challenge_id: u64,
        response: oneshot::Sender<Option<crate::domain::storage_deal::ChallengeResult>>,
    },
    /// B.U.D.: Objects in the repair band at a caller-supplied margin, plus
    /// the objects already past saving.
    ///
    /// The margin is the caller's, not the sweep's. The maintenance pass judges
    /// every object by its own scheme's margin, which is the right rule for a
    /// sweep and the wrong one for an operator asking "what is within two
    /// shards of trouble for me?". That question needs one margin applied
    /// uniformly, which is what `objects_needing_repair` answers.
    GetStorageRepairBand {
        margin: u32,
        response: oneshot::Sender<StorageRepairBand>,
    },
    /// B.U.D.: Query all active storage deals.
    GetStorageDeals(oneshot::Sender<Vec<crate::domain::storage_deal::StorageDeal>>),
    /// B.U.D.: Query storage economics event log.
    GetStorageEconomicsEvents(
        oneshot::Sender<Vec<crate::chain::blockchain::StorageEconomicsEvent>>,
    ),
    /// B.U.D.: Query storage economics accounting summary.
    GetStorageEconomicsSummary(oneshot::Sender<serde_json::Value>),
    /// Permissionless per-operator accounting view for storage clients.
    GetStorageOperatorEconomics {
        operator: Address,
        response: oneshot::Sender<serde_json::Value>,
    },
    /// B.U.D.: Query all storage challenges.
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
    IdentityResolve {
        subject: Address,
        response: oneshot::Sender<Option<(crate::registry::IdentityRecord, u64)>>,
    },
    IdentityCredential {
        credential_id: [u8; 32],
        response:
            oneshot::Sender<Option<(crate::registry::CredentialCommitment, Result<(), String>)>>,
    },
    IdentityVerifyPresentation {
        receipt: crate::registry::PresentationReceipt,
        requester: Address,
        document: String,
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
    /// Which Pollen asset sells the bytes behind a manifest, if any.
    ///
    /// The RPC layer needs this before it hands out a shard list: shard ids
    /// are what a reader fetches bytes with, so publishing them for content
    /// someone is selling is publishing the content itself to anyone who
    /// skips the payment path.
    PollenAssetForContent {
        manifest_id: crate::storage::ContentId,
        response: oneshot::Sender<Option<crate::pollen::AssetId>>,
    },
    PollenGetAccessGrants {
        response: oneshot::Sender<Vec<crate::pollen::AccessGrant>>,
    },
    PollenGetSaleAuthorizations {
        response: oneshot::Sender<Vec<crate::pollen::SaleAuthorization>>,
    },
    PollenGetPurchaseReceipts {
        response: oneshot::Sender<Vec<crate::pollen::PollenPurchaseReceipt>>,
    },
    PollenGetEncryptionPolicies {
        response: oneshot::Sender<Vec<crate::pollen::EncryptionPolicy>>,
    },
    HubGetApps {
        response: oneshot::Sender<Vec<crate::budlumxyz::types::AppRecord>>,
    },
    /// The Graft applications, listed beside the native apps.
    HubGetGraftApps {
        response: oneshot::Sender<Vec<crate::settlement::graft::GraftApp>>,
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

    /// Height of the last block covered by a finality certificate.
    ///
    /// Unlike [`Self::get_height`] this never moves backwards on a reorg, so
    /// it is the only safe cursor for anything with an external side effect.
    pub async fn get_finalized_height(&self) -> u64 {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetFinalizedHeight(tx)).await;
        rx.await.unwrap_or(0)
    }

    pub async fn get_block(&self, height: u64) -> Option<Block> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetBlock(height, tx)).await;
        rx.await.unwrap_or(None)
    }

    /// Read `count` contiguous local blocks starting at `from`, in one
    /// round trip. Returns fewer than `count` when the chain is shorter.
    /// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
    pub async fn get_blocks_range(&self, from: u64, count: usize) -> Vec<Block> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetBlocksRange(from, count, tx))
            .await;
        rx.await.unwrap_or_default()
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

    /// Ask the chain for a proof about one account.
    ///
    /// `None` means the node could not answer, which is not the same as the
    /// account being absent: absence is itself a proof and comes back as
    /// `Some` with `present: false`.
    pub async fn get_account_proof(&self, addr: &Address) -> Option<AccountProofBundle> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetAccountProof(*addr, tx)).await;
        rx.await.unwrap_or(None)
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
            return Err(format!("Actor dropped: {e}"));
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

    /// Whether the mempool still holds `hash`.
    ///
    /// `add_transaction` confirms admission, not execution: the pool can
    /// expire or evict the transaction afterwards. A submitter that must see
    /// its transaction through to a block asks this to tell "still queued"
    /// from "lost". An unreachable actor reads as `false`, the direction in
    /// which the caller resubmits rather than waits forever.
    pub async fn mempool_contains(&self, hash: String) -> bool {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::MempoolContains(hash, tx)).await;
        rx.await.unwrap_or(false)
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

    pub async fn import_pruned_segment(
        &self,
        blocks: Vec<Block>,
        cert: FinalityCert,
        qc: crate::consensus::qc::QcBlob,
    ) -> Result<usize, String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::ImportPrunedSegment(
                blocks,
                Box::new(cert),
                Box::new(qc),
                res_tx,
            ))
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

    pub async fn get_delegations(
        &self,
        validator: crate::core::address::Address,
    ) -> Vec<crate::registry::permissionless::DelegationPosition> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetDelegations(validator, tx))
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn get_validator_profiles(
        &self,
        validator: Option<crate::core::address::Address>,
    ) -> Vec<serde_json::Value> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetValidatorProfiles(validator, tx))
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn get_delegation_exits(
        &self,
        validator: crate::core::address::Address,
    ) -> Vec<crate::registry::permissionless::DelegationUnbonding> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetDelegationExits(validator, tx))
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn get_slashing_history(
        &self,
    ) -> Vec<crate::registry::permissionless::SlashingRecord> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetSlashingHistory(tx)).await;
        rx.await.unwrap_or_default()
    }

    pub async fn try_reorg(&self, fork: Vec<Block>) -> Result<bool, String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::TryReorg(fork, res_tx)).await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    /// Reorg onto a suffix the peer sent, without copying the local chain.
    ///
    /// The join happens inside the actor, so the peer's fork height no longer
    /// sizes a chain read on the caller's side: the only blocks that cross the
    /// boundary are the ones the peer actually sent, already capped by the
    /// sync batch limit.
    pub async fn try_reorg_suffix(&self, suffix: Vec<Block>) -> Result<bool, String> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::TryReorgSuffix(suffix, res_tx))
            .await;
        res_rx
            .await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn get_chain_info(&self) -> String {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetChainInfo(tx)).await;
        rx.await.unwrap_or_default()
    }

    pub async fn issue_view_grant(
        &self,
        content_id: crate::storage::ContentId,
        auth: crate::storage::GrantAuthorization,
        grantee: Option<crate::core::address::Address>,
        key_id: [u8; 32],
        policy: crate::storage::ViewPolicy,
        opened_epoch: u64,
    ) -> Result<u64, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::IssueViewGrant {
                content_id,
                auth,
                grantee,
                key_id,
                policy,
                opened_epoch,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn revoke_view_grant(
        &self,
        grant_id: u64,
        auth: crate::storage::GrantAuthorization,
        at_epoch: u64,
    ) -> Result<crate::storage::ViewGrant, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::RevokeViewGrant {
                grant_id,
                auth,
                at_epoch,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn social_delete(
        &self,
        content_id: crate::storage::ContentId,
        auth: crate::storage::GrantAuthorization,
        at_epoch: u64,
    ) -> Result<crate::storage::DeleteOutcome, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::SocialDelete {
                content_id,
                auth,
                at_epoch,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    /// Grant rows of one content and how many of them are live.
    pub async fn view_grants(
        &self,
        content_id: crate::storage::ContentId,
    ) -> Result<(Vec<crate::storage::ViewGrant>, usize), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetViewGrants {
                content_id,
                response: tx,
            })
            .await;
        rx.await.map_err(|_| "Actor dropped".to_string())
    }

    pub async fn may_view_content(
        &self,
        content_id: crate::storage::ContentId,
        viewer: crate::core::address::Address,
        key_id: [u8; 32],
        owner: crate::core::address::Address,
    ) -> Result<bool, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::MayViewContent {
                content_id,
                viewer,
                key_id,
                owner,
                response: tx,
            })
            .await;
        rx.await.map_err(|_| "Actor dropped".to_string())
    }

    pub async fn register_confidential_commit(
        &self,
        commit: crate::storage::ConfidentialBodyCommit,
        auth: crate::storage::GrantAuthorization,
    ) -> Result<[u8; 32], String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::RegisterConfidentialCommit {
                commit,
                auth,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    /// Who speaks for `content_id`: the manifest owner or the address that
    /// registered the confidential commit. Read-only, and the reason it exists is
    /// that a grant signature is checked against this address; a wallet has to be
    /// able to see what the chain will compare before it spends a key on signing.
    pub async fn confidential_owner(
        &self,
        content_id: crate::storage::ContentId,
    ) -> Result<Option<crate::core::address::Address>, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetConfidentialOwner {
                content_id,
                response: tx,
            })
            .await;
        rx.await.map_err(|_| "Actor dropped".to_string())
    }

    pub async fn get_confidential_commit(
        &self,
        content_id: crate::storage::ContentId,
    ) -> Result<Option<crate::storage::ConfidentialBodyCommit>, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetConfidentialCommit {
                content_id,
                response: tx,
            })
            .await;
        rx.await.map_err(|_| "Actor dropped".to_string())
    }

    /// Derive the coding audit for `manifest_id` at `challenge_id`.
    ///
    /// The column and parity index come from chain entropy, never from the
    /// caller: an opener who picks the column picks one the operator has, and
    /// an operator who knows the column in advance stores only that column.
    pub async fn derive_coding_audit(
        &self,
        manifest_id: crate::storage::ContentId,
        challenge_id: u64,
    ) -> Result<crate::domain::storage_deal::CodingAudit, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::DeriveCodingAudit {
                manifest_id,
                challenge_id,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    /// Check an answered coding audit.
    ///
    /// A pass means the Reed-Solomon relationship holds at that one column
    /// and nothing wider. An operator who miscomputed a fraction `f` of
    /// columns fails a uniformly random one with probability `f`.
    pub async fn answer_coding_audit(
        &self,
        audit: crate::domain::storage_deal::CodingAudit,
        data_column: Vec<u8>,
        parity_byte: u8,
        column_proof: Vec<[u8; 32]>,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::AnswerCodingAudit {
                audit,
                data_column,
                parity_byte,
                column_proof,
                response: tx,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    pub async fn get_storage_manifest(
        &self,
        manifest_id: crate::storage::ContentId,
    ) -> Option<crate::storage::ContentManifest> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetStorageManifest {
                manifest_id,
                response: tx,
            })
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn get_storage_deals_by_manifest(
        &self,
        manifest_id: crate::storage::ContentId,
    ) -> Vec<crate::domain::storage_deal::StorageDeal> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetStorageDealsByManifest {
                manifest_id,
                response: tx,
            })
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn get_storage_deals_by_shard(
        &self,
        manifest_id: crate::storage::ContentId,
        shard_id: crate::storage::ContentId,
    ) -> Vec<crate::domain::storage_deal::StorageDeal> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetStorageDealsByShard {
                manifest_id,
                shard_id,
                response: tx,
            })
            .await;
        rx.await.unwrap_or_default()
    }

    /// Objects within `margin` shards of unrecoverable, and those already past
    /// it, measured at the caller's margin.
    pub async fn get_storage_repair_band(&self, margin: u32) -> StorageRepairBand {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetStorageRepairBand {
                margin,
                response: tx,
            })
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn get_storage_outcome(
        &self,
        challenge_id: u64,
    ) -> Option<crate::domain::storage_deal::ChallengeResult> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetStorageOutcome {
                challenge_id,
                response: tx,
            })
            .await;
        rx.await.unwrap_or(None)
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

    /// The commitment this node holds and the post-quantum canonical
    /// commitment with its seal, for one regeneration stage and height.
    pub async fn pq_stage_observation(
        &self,
        stage: crate::domain::regeneration_stage::Stage,
        height: u64,
    ) -> crate::chain::blockchain::PqStageObservation {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetPqStageObservation(stage, height, tx))
            .await;
        rx.await
            .unwrap_or(crate::chain::blockchain::PqStageObservation {
                local: None,
                canonical: None,
                seal: None,
            })
    }

    /// The quantum alarm and the observed crypto facts of the native domains.
    pub async fn quantum_view(&self) -> serde_json::Value {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetQuantumView(tx)).await;
        rx.await.unwrap_or(serde_json::Value::Null)
    }

    /// The latest Root Seal height and the latest verified anchor at or below
    /// `live`.
    pub async fn pq_sealed_heights(&self, live: u64) -> (Option<u64>, Option<u64>) {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetPqSealedHeights(live, tx))
            .await;
        rx.await.unwrap_or((None, None))
    }

    pub async fn get_state_root(&self, height: u64) -> Option<String> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetStateRoot(height, tx)).await;
        rx.await.unwrap_or(None)
    }

    /// Credit an account outside consensus, on a development chain only.
    ///
    /// # Errors
    ///
    /// Refuses on every chain id except devnet (testnet included). The old
    /// signature returned `()` and logged, so a caller could not tell a
    /// credit from a no-op; a faucet that silently does nothing is as
    /// misleading as one that silently works.
    pub async fn credit_development_account(
        &self,
        address: &Address,
        amount: u64,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self
            .tx
            .send(ChainCommand::AddBalance(*address, amount, tx))
            .await
        {
            return Err(format!("chain actor is gone: {e}"));
        }
        rx.await
            .map_err(|e| format!("credit response channel closed: {e}"))?
    }

    /// Top an account up to `GENESIS_BALANCE`, on a development chain only.
    ///
    /// Was `init_genesis_account`, which named a moment in the chain's life
    /// that the body never checked.
    ///
    /// # Errors
    ///
    /// Refuses on every chain id except devnet (testnet included).
    pub async fn fund_development_account(&self, address: &Address) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self
            .tx
            .send(ChainCommand::FundDevelopmentAccount(*address, tx))
            .await
        {
            return Err(format!("chain actor is gone: {e}"));
        }
        rx.await
            .map_err(|e| format!("faucet response channel closed: {e}"))?
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

    /// A committed checkpoint header with its proof material.
    pub async fn get_global_header_proof(
        &self,
        global_height: u64,
    ) -> Option<crate::chain::blockchain::GlobalHeaderProof> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetGlobalHeaderProof(global_height, tx))
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

    pub async fn get_graft_payment_proof(
        &self,
        payment_id: [u8; 32],
    ) -> Option<crate::settlement::graft::GraftPaymentProof> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetGraftPaymentProof(payment_id, tx))
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn get_graft_application(
        &self,
        graft_id: [u8; 32],
    ) -> Option<crate::settlement::graft::GraftApp> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetGraftApplication(graft_id, tx))
            .await;
        rx.await.unwrap_or(None)
    }

    /// The Mikoriza rows and the capped restaked weight of each validator.
    pub async fn get_restaked_validators(
        &self,
    ) -> (
        Vec<crate::settlement::shared_security::RestakedValidator>,
        std::collections::BTreeMap<crate::core::address::Address, u64>,
    ) {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(ChainCommand::GetRestakedValidators(tx)).await;
        rx.await.unwrap_or_default()
    }

    pub async fn get_cross_domain_message(
        &self,
        message_id: [u8; 32],
    ) -> Option<crate::cross_domain::CrossDomainMessage> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetCrossDomainMessage(message_id, tx))
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn get_bridge_transfer(
        &self,
        message_id: [u8; 32],
    ) -> Option<crate::cross_domain::BridgeTransfer> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetBridgeTransfer(message_id, tx))
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn get_relayer_status(&self, message_id: Option<[u8; 32]>) -> serde_json::Value {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetRelayerStatus(message_id, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| serde_json::json!({"error": "chain actor unavailable"}))
    }

    pub async fn get_relayer_intent(&self, intent_id: [u8; 32]) -> serde_json::Value {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetRelayerIntent(intent_id, tx))
            .await;
        rx.await
            .unwrap_or_else(|_| serde_json::json!({"error": "chain actor unavailable"}))
    }

    pub async fn get_sovereign_template(
        &self,
        domain_id: crate::domain::types::DomainId,
    ) -> Option<crate::domain::SovereignDomainTemplate> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetSovereignTemplate(domain_id, tx))
            .await;
        rx.await.unwrap_or(None)
    }

    /// Verify an audit export against the registered template.
    pub async fn validate_sovereign_audit_export(
        &self,
        bundle: crate::domain::sovereign::AuditExportBundle,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::ValidateSovereignAuditExport(
                Box::new(bundle),
                tx,
            ))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    #[cfg(test)]
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

    /// Reads one external domain's public profile with its intake entry and
    /// registered descriptor.
    pub async fn get_external_domain_profile(
        &self,
        key: crate::cross_domain::external::DomainKey,
    ) -> Option<(
        crate::cross_domain::external::DomainProfile,
        crate::cross_domain::external::IntakeEntry,
        crate::cross_domain::external::AdapterDescriptor,
    )> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetExternalDomainProfile(key, tx))
            .await;
        rx.await.unwrap_or(None)
    }

    /// Reads every external domain's profile with its summary line.
    pub async fn get_external_domain_profiles(
        &self,
    ) -> Vec<(crate::cross_domain::external::DomainProfile, String)> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetExternalDomainProfiles(tx))
            .await;
        rx.await.unwrap_or_default()
    }

    /// The deterministic digest of the whole external-intake state, for
    /// cross-node comparison.
    pub async fn get_external_intake_digest(&self) -> Result<[u8; 32], String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetExternalIntakeDigest(tx))
            .await;
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    /// The quorum round for one external height of one domain, if retained.
    pub async fn external_quorum_round(
        &self,
        key: crate::cross_domain::external::DomainKey,
        height: u64,
    ) -> Option<crate::cross_domain::external::QuorumRound> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetExternalQuorumRound(key, height, tx))
            .await;
        rx.await.unwrap_or(None)
    }

    /// Every retained quorum round of one domain, with its policy.
    pub async fn external_quorum_rounds(
        &self,
        key: crate::cross_domain::external::DomainKey,
    ) -> (
        Option<crate::cross_domain::external::QuorumPolicy>,
        Vec<crate::cross_domain::external::QuorumRound>,
    ) {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetExternalQuorumRounds(key, tx))
            .await;
        rx.await.unwrap_or((None, Vec::new()))
    }

    /// The full registration record of one external domain, with the
    /// registry clock beside it.
    pub async fn external_domain_registration(
        &self,
        key: crate::cross_domain::external::DomainKey,
    ) -> Option<(crate::cross_domain::external::DomainRegistration, u64)> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetExternalDomainRegistration(key, tx))
            .await;
        rx.await.unwrap_or(None)
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

    pub async fn get_ai_open_requests(&self) -> Vec<crate::ai::types::AiInferenceRequest> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::GetAiOpenRequests(tx))
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
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

    /// Get comprehensive dispute status.
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
        rx.await.unwrap_or(crate::ai::types::AiDisputeStatusInfo {
            has_equivocated: false,
            is_disputable: false,
            detected_block: None,
            dispute_window_remaining: None,
            is_staked: false,
            stake_amount: 0,
        })
    }

    /// Get verifier stake info.
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
        rx.await.unwrap_or(crate::ai::types::AiVerifierStakeInfo {
            verifier,
            is_staked: false,
            stake_amount: 0,
            total_equivocations: 0,
        })
    }

    /// Get callback events for a callback address.
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

    /// Get execution proof for a (request, verifier) pair.
    /// Returns None if no proof exists - results without proofs are
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

    /// Get QoS metrics for a verifier.
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

    /// Get all verifiers ordered by reliability score.
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

    /// Get agent payment by ID.
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

    /// Get payments for an agent.
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

    /// Get verifier whitelist.
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

    pub async fn get_ai_agent_ranking(&self) -> Vec<(crate::core::address::Address, u64)> {
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
            return Err(format!("Actor dropped: {e}"));
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
            return Err(format!("Actor dropped: {e}"));
        }
        rx.await
            .unwrap_or_else(|_| Err("Actor dropped".to_string()))
    }

    #[cfg(test)]
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

    // ─── B.U.D.: Storage operations public API ─────

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

    /// Query a single operator's accrued rewards, slash events, and active
    /// Deal count without relying on an off-chain indexer.
    pub async fn get_storage_operator_economics(
        &self,
        operator: Address,
    ) -> Result<serde_json::Value, String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::GetStorageOperatorEconomics {
                operator,
                response: tx,
            })
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

    pub async fn identity_resolve(
        &self,
        subject: Address,
    ) -> Option<(crate::registry::IdentityRecord, u64)> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::IdentityResolve {
                subject,
                response: tx,
            })
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn identity_credential(
        &self,
        credential_id: [u8; 32],
    ) -> Option<(crate::registry::CredentialCommitment, Result<(), String>)> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::IdentityCredential {
                credential_id,
                response: tx,
            })
            .await;
        rx.await.unwrap_or(None)
    }

    pub async fn identity_verify_presentation(
        &self,
        receipt: crate::registry::PresentationReceipt,
        requester: Address,
        document: String,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(ChainCommand::IdentityVerifyPresentation {
                receipt,
                requester,
                document,
                response: tx,
            })
            .await
            .is_err()
        {
            return Err("chain actor closed".to_string());
        }
        rx.await.map_err(|_| "chain actor closed".to_string())?
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

    /// Which Pollen asset sells this content, if any. `None` means the
    /// content is not listed and reading it needs no grant.
    pub async fn pollen_asset_for_content(
        &self,
        manifest_id: crate::storage::ContentId,
    ) -> Option<crate::pollen::AssetId> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::PollenAssetForContent {
                manifest_id,
                response: tx,
            })
            .await;
        // A failed round trip reads as "listed" rather than "free": the
        // actor being unreachable is not evidence that content is public,
        // and defaulting the other way would open the paywall whenever the
        // chain task is busy.
        rx.await
            .unwrap_or_else(|_| Some(crate::pollen::AssetId::zero()))
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

    pub async fn pollen_get_encryption_policies(&self) -> Vec<crate::pollen::EncryptionPolicy> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::PollenGetEncryptionPolicies { response: tx })
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn pollen_get_purchase_receipts(&self) -> Vec<crate::pollen::PollenPurchaseReceipt> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::PollenGetPurchaseReceipts { response: tx })
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn budlumxyz_get_graft_apps(&self) -> Vec<crate::settlement::graft::GraftApp> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::HubGetGraftApps { response: tx })
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn budlumxyz_get_apps(&self) -> Vec<crate::budlumxyz::types::AppRecord> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(ChainCommand::HubGetApps { response: tx })
            .await;
        rx.await.unwrap_or_default()
    }
}
/// The proof-bearing trie, built at most once per chain height.
///
/// Building it costs O(depth * accounts): measured at 5000 accounts, 222 ms.
/// Rebuilding per request turned `bud_getAccountProof` into a work
/// multiplier - ten proofs cost 2.23 s, all of it spent rebuilding the same
/// tree. That is a remote caller choosing how much node CPU to spend.
///
/// Built lazily rather than at the end of every block, because a node nobody
/// asks for proofs should not pay for them at all: the cost belongs to the
/// feature being used, not to running a node. The first request after a new
/// block pays; every later request at that height is a tree walk.
///
/// `leaves` is what makes the cache honest. Balances change outside blocks
/// (faucet, bond debit and refund) and an equal length reorg swaps state at
/// the same chain length, so the chain length cannot tag the trie. The trie
/// keeps the exact (address, balance, nonce) list it was built from. A hit
/// needs the live accounts to match that list, so a stale trie is never used.
/// The compare is one pass over the accounts and is far cheaper than a build.
struct ProofTrieCache {
    leaves: Vec<([u8; 32], u64, u64)>,
    trie: crate::storage::merkle_trie::MerkleTrie,
}

pub struct ChainActor {
    blockchain: Blockchain,
    rx: mpsc::Receiver<ChainCommand>,
    proof_trie: Option<ProofTrieCache>,
}

impl ChainActor {
    /// BLG-0195 (P10-F05): after a successful reorg the old tip's finality
    /// round is dead (0186 invalidated it), but nobody restarted voting - the
    /// node just sat there and the post-fork chain finalized nothing until the
    /// NEXT checkpoint block happened to arrive through AddBlock. Resume the
    /// prevote task on the new tip when it is itself a checkpoint height,
    /// mirroring ValidateAndAddBlock. Shared by both reorg entry points.
    fn resume_finality_after_reorg(&mut self, outcome: &Result<bool, String>) {
        if !matches!(outcome, Ok(true)) {
            return;
        }
        if let Some(tip) = self.blockchain.chain.last().cloned() {
            if crate::chain::finality::is_checkpoint_height_for_chain(
                tip.index,
                self.blockchain.chain_id,
            ) {
                self.blockchain
                    .start_prevote_task(tip.index, tip.hash.clone());
            }
        }
    }

    pub fn new(blockchain: Blockchain) -> (Self, ChainHandle) {
        let (tx, rx) = mpsc::channel(1000);
        (
            Self {
                blockchain,
                rx,
                proof_trie: None,
            },
            ChainHandle { tx },
        )
    }

    /// Proof for one account, reusing the trie when the accounts did not change.
    ///
    /// The cache is keyed by the account contents and rebuilt when they do not
    /// match, so a proof is always drawn against the state the node holds. A
    /// stale trie would produce a proof that verifies against its own root and
    /// describes state that no longer exists - worse than no proof, because it
    /// is a correct-looking answer to the wrong question.
    fn account_proof(&mut self, addr: &Address) -> crate::storage::merkle_trie::AccountProofBundle {
        let accounts = &self.blockchain.state.accounts;
        let fresh = self.proof_trie.as_ref().is_some_and(|cached| {
            cached.leaves.len() == accounts.len()
                && cached
                    .leaves
                    .iter()
                    .zip(accounts.iter())
                    .all(|(l, (a, acct))| l.0 == a.0 && l.1 == acct.balance && l.2 == acct.nonce)
        });
        if !fresh {
            let leaves: Vec<([u8; 32], u64, u64)> = accounts
                .iter()
                .map(|(a, acct)| (a.0, acct.balance, acct.nonce))
                .collect();
            let mut trie = crate::storage::merkle_trie::MerkleTrie::new();
            for (a, balance, nonce) in &leaves {
                trie.insert(a, *balance, *nonce);
            }
            self.proof_trie = Some(ProofTrieCache { leaves, trie });
        }
        match self.proof_trie.as_ref() {
            Some(cached) => crate::storage::merkle_trie::prove_from_trie(&cached.trie, &addr.0),
            // Unreachable: the branch above assigns it. Written as a fallback
            // rather than an unwrap so a future edit that breaks the
            // invariant costs one rebuild instead of stopping the node.
            None => crate::storage::merkle_trie::prove_account(
                self.blockchain
                    .state
                    .accounts
                    .iter()
                    .map(|(a, acct)| (a.0, acct.balance, acct.nonce)),
                &addr.0,
            ),
        }
    }

    /// Height the AI read queries judge deadlines at. It is the height the
    /// executor uses for the same checks, not an epoch guess that is only
    /// right on a chain with 100 blocks per epoch.
    fn ai_query_height(&self) -> u64 {
        self.blockchain.state.current_block_height
    }

    fn storage_economics_disabled_on_mainnet(&self) -> bool {
        self.blockchain.chain_id
            == crate::core::chain_config::Network::Mainnet
                .chain_id()
                .value()
    }

    fn mainnet_storage_disabled_error() -> String {
        "B.U.D. storage economics are disabled on mainnet until transaction-only accounting is wired".into()
    }

    /// View grants are state-root bearing (`view_grants.root()` folds into
    /// the storage registry root): mutating them between blocks diverges the
    /// local root from every peer that did not see the RPC call. The refusal
    /// is chain-independent until grant changes ride a block transaction.
    fn view_grant_rpc_mutation_error() -> String {
        "view grants are state-root bearing and cannot be mutated over RPC; submit StorageTx::IssueViewGrant or StorageTx::RevokeViewGrant through bud_sendRawTransaction".into()
    }

    fn social_delete_rpc_mutation_error() -> String {
        "social delete changes state-root bearing rows and cannot be applied over RPC; submit StorageTx::SocialDelete through bud_sendRawTransaction".into()
    }

    pub async fn run(mut self) {
        while let Some(cmd) = self.rx.recv().await {
            match cmd {
                ChainCommand::GetHeight(tx) => {
                    let height = self.blockchain.chain.len().saturating_sub(1) as u64;
                    let _ = tx.send(height);
                }
                ChainCommand::GetFinalizedHeight(tx) => {
                    let _ = tx.send(self.blockchain.finalized_height);
                }
                ChainCommand::GetBlock(height, tx) => {
                    let block = self.blockchain.chain.get(height as usize).cloned();
                    let _ = tx.send(block);
                }
                ChainCommand::GetBlocksRange(from, count, tx) => {
                    let start = usize::try_from(from).unwrap_or(usize::MAX);
                    let blocks = self
                        .blockchain
                        .chain
                        .iter()
                        .skip(start)
                        .take(count)
                        .cloned()
                        .collect();
                    let _ = tx.send(blocks);
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
                ChainCommand::GetAccountProof(addr, tx) => {
                    let bundle = self.account_proof(&addr);
                    let _ = tx.send(Some(bundle));
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
                        if crate::chain::finality::is_checkpoint_height_for_chain(
                            b.index,
                            self.blockchain.chain_id,
                        ) {
                            self.blockchain.start_prevote_task(b.index, b.hash.clone());
                        }
                        if !cids.is_empty() {
                            tracing::info!(count = cids.len(), "NftBurn detected during production - notifying node for physical pruning");
                        }
                    }
                    let _ = tx.send(result);
                }
                ChainCommand::ValidateAndAddBlock(block, res_tx) => {
                    let height = block.index;
                    let res = self.blockchain.validate_and_add_block(block);
                    if let Ok(ref cids) = res {
                        if crate::chain::finality::is_checkpoint_height_for_chain(
                            height,
                            self.blockchain.chain_id,
                        ) {
                            let checkpoint_hash = self
                                .blockchain
                                .chain
                                .get(height as usize)
                                .map(|checkpoint| checkpoint.hash.clone());
                            if let Some(checkpoint_hash) = checkpoint_hash {
                                self.blockchain.start_prevote_task(height, checkpoint_hash);
                            }
                        }
                        if !cids.is_empty() {
                            tracing::info!(
                                count = cids.len(),
                                "NftBurn detected - notifying node for physical pruning"
                            );
                        }
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
                ChainCommand::MempoolContains(hash, tx) => {
                    let _ = tx.send(self.blockchain.mempool.get(&hash).is_some());
                }
                ChainCommand::GetValidatorAddress(tx) => {
                    let addr = self
                        .blockchain
                        .consensus()
                        .signer()
                        .map(crate::crypto::signer::ConsensusSigner::address);
                    let _ = tx.send(addr);
                }
                ChainCommand::GetAggregatorState(tx) => {
                    let state = self.blockchain.get_aggregator_state();
                    let _ = tx.send(state);
                }
                ChainCommand::ImportPrunedSegment(blocks, cert, qc, res_tx) => {
                    let res = self.blockchain.import_pruned_segment(blocks, &cert, &qc);
                    let _ = res_tx.send(res);
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
                ChainCommand::GetDelegations(validator, res_tx) => {
                    let _ = res_tx.send(self.blockchain.state.registry.delegations_for(&validator));
                }
                ChainCommand::GetValidatorProfiles(validator, res_tx) => {
                    let state = &self.blockchain.state;
                    let profiles = match validator {
                        Some(address) => {
                            crate::registry::validator_profile::validator_profile(state, &address)
                                .into_iter()
                                .collect()
                        }
                        None => crate::registry::validator_profile::validator_profiles(state),
                    };
                    let _ = res_tx.send(profiles);
                }
                ChainCommand::GetDelegationExits(validator, res_tx) => {
                    let _ = res_tx.send(
                        self.blockchain
                            .state
                            .registry
                            .delegation_unbonding_for(&validator),
                    );
                }
                ChainCommand::GetSlashingHistory(res_tx) => {
                    let _ = res_tx.send(self.blockchain.state.registry.slashing_history().to_vec());
                }
                ChainCommand::DrainSlashingEvidence(tx) => {
                    let _ = tx.send(self.blockchain.drain_local_slashing_evidence());
                }
                ChainCommand::CleanupMempool(tx) => {
                    let removed = self.blockchain.mempool.cleanup_expired();
                    let _ = tx.send(removed);
                }
                ChainCommand::TryReorg(fork, res_tx) => {
                    let outcome = self.blockchain.try_reorg(fork).map_err(|e| e.to_string());
                    // BLG-0195 (P10-F05): after a successful reorg the old tip's
                    // finality round is dead (0186 invalidated it), but nobody
                    // restarted voting - the node just sat there and the post-
                    // fork chain finalized nothing until the NEXT checkpoint
                    // block happened to arrive through AddBlock. Resume the
                    // prevote task on the new tip when it is itself a
                    // checkpoint height, mirroring ValidateAndAddBlock.
                    if matches!(outcome, Ok(true)) {
                        let tip = self.blockchain.chain.last().cloned();
                        if let Some(tip) = tip {
                            if crate::chain::finality::is_checkpoint_height_for_chain(
                                tip.index,
                                self.blockchain.chain_id,
                            ) {
                                self.blockchain
                                    .start_prevote_task(tip.index, tip.hash.clone());
                            }
                        }
                    }
                    let _ = res_tx.send(outcome);
                }
                ChainCommand::TryReorgSuffix(suffix, res_tx) => {
                    let outcome = self
                        .blockchain
                        .try_reorg_suffix(suffix)
                        .map_err(|e| e.to_string());
                    self.resume_finality_after_reorg(&outcome);
                    let _ = res_tx.send(outcome);
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
                ChainCommand::GetPqStageObservation(stage, height, tx) => {
                    let res = self.blockchain.pq_stage_observation(stage, height);
                    let _ = tx.send(res);
                }
                ChainCommand::GetQuantumView(tx) => {
                    let _ = tx.send(self.blockchain.quantum_view());
                }
                ChainCommand::GetPqSealedHeights(live, tx) => {
                    let res = self.blockchain.pq_sealed_heights(live);
                    let _ = tx.send(res);
                }
                ChainCommand::GetStateRoot(height, tx) => {
                    let res = self.blockchain.get_state_root(height);
                    let _ = tx.send(res);
                }
                ChainCommand::AddBalance(addr, amount, tx) => {
                    let res = self.blockchain.credit_development_account(&addr, amount);
                    let _ = tx.send(res);
                }
                ChainCommand::FundDevelopmentAccount(addr, tx) => {
                    let res = self.blockchain.fund_development_account(&addr);
                    let _ = tx.send(res);
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
                    let latest = self
                        .blockchain
                        .state
                        .settlement
                        .global_headers
                        .latest()
                        .cloned()
                        .or_else(|| self.blockchain.global_headers.last().cloned());
                    let global_height = latest
                        .as_ref()
                        .map_or(0, |h| h.global_height.saturating_add(1));
                    let info = serde_json::json!({
                        "globalHeight": global_height,
                        "latestGlobalHash": latest
                            .as_ref()
                            .map(super::super::settlement::global_block::GlobalBlockHeader::calculate_hash)
                            .map(|hash| format!("0x{hash}")),
                        "pendingGlobalHash": format!("0x{}", header.calculate_hash()),
                        "domainRegistryRoot": format!("0x{}", hex::encode(header.domain_registry_root)),
                        "domainCommitmentRoot": format!("0x{}", hex::encode(header.domain_commitment_root)),
                        "bridgeStateRoot": format!("0x{}", hex::encode(header.bridge_state_root)),
                        "replayNonceRoot": format!("0x{}", hex::encode(header.replay_nonce_root)),
                        "domainCommitmentCount": self.blockchain.state.settlement.commitments.len(),
                        "proofMarketRoot": format!(
                            "0x{}",
                            hex::encode(self.blockchain.state.proof_market.root())
                        ),
                        "proofMarketActiveTasks": self.blockchain.state.proof_market.active_tasks.len(),
                        "proofMarketPendingReceipts": self.blockchain.state.proof_market.pending_receipts.len(),
                        "proofMarketEscrowedCreators": self.blockchain.state.proof_market.escrowed.len(),
                        "graftRoot": format!(
                            "0x{}",
                            hex::encode(self.blockchain.state.settlement.graft.root())
                        ),
                        "graftApplications": self.blockchain.state.settlement.graft.apps.len(),
                        "graftPayments": self.blockchain.state.settlement.graft.payments.len(),
                        "graftIntents": self.blockchain.state.settlement.graft.intents.len(),
                        "graftClaims": self.blockchain.state.settlement.graft.used_messages.len(),
                    });
                    let _ = tx.send(info);
                }
                ChainCommand::GetGlobalHeader(height, tx) => {
                    let header = self.blockchain.global_header(height);
                    let _ = tx.send(header);
                }
                ChainCommand::GetDomainCommitments(tx) => {
                    let commitments = self
                        .blockchain
                        .state
                        .settlement
                        .commitments
                        .commitments_for_global_block();
                    let _ = tx.send(commitments);
                }
                ChainCommand::GetConsensusDomains(tx) => {
                    let _ = tx.send(self.blockchain.state.settlement.domains.domains());
                }
                ChainCommand::GetGraftPaymentProof(payment_id, tx) => {
                    let _ = tx.send(self.blockchain.graft_payment_proof(&payment_id));
                }
                ChainCommand::GetRestakedValidators(tx) => {
                    let state = &self.blockchain.state;
                    let rows = state
                        .settlement
                        .shared_security
                        .validators
                        .values()
                        .cloned()
                        .collect();
                    let weights = state
                        .validators
                        .values()
                        .filter(|v| v.restaked_weight > 0)
                        .map(|v| (v.address, v.restaked_weight))
                        .collect();
                    let _ = tx.send((rows, weights));
                }
                ChainCommand::GetGraftApplication(graft_id, tx) => {
                    let _ = tx.send(
                        self.blockchain
                            .state
                            .settlement
                            .graft
                            .get(&graft_id)
                            .cloned(),
                    );
                }
                ChainCommand::GetCrossDomainMessage(message_id, tx) => {
                    let _ = tx.send(
                        self.blockchain
                            .state
                            .message_registry
                            .get(&message_id)
                            .cloned(),
                    );
                }
                ChainCommand::GetBridgeTransfer(message_id, tx) => {
                    let _ = tx.send(
                        self.blockchain
                            .state
                            .bridge_state
                            .get_transfer(&message_id)
                            .cloned(),
                    );
                }
                ChainCommand::GetRelayerStatus(message_id, tx) => {
                    let relayer = &self.blockchain.state.settlement.relayer;
                    let pending = message_id.and_then(|id| relayer.pending_relay(&id));
                    let record = message_id.and_then(|id| relayer.ledger.get_record(&id));
                    let _ = tx.send(serde_json::json!({
                        "messageId": message_id.map(|id| format!("0x{}", hex::encode(id))),
                        "pendingCount": relayer.pending_count(),
                        "relayedCount": relayer.relayed_count(),
                        "ledgerRoot": format!("0x{}", hex::encode(relayer.ledger_root())),
                        "pending": pending,
                        "record": record,
                    }));
                }
                ChainCommand::GetRelayerIntent(intent_id, tx) => {
                    let policy = &self.blockchain.state.settlement.relayer_policy;
                    let intent = policy.intents.get(&intent_id);
                    let bids = policy.bids.get(&intent_id);
                    let escrowed = policy.escrowed.get(&intent_id).copied();
                    let settlement = policy.settlements.get(&intent_id);
                    let _ = tx.send(serde_json::json!({
                        "intentId": format!("0x{}", hex::encode(intent_id)),
                        "found": intent.is_some() || bids.is_some() || settlement.is_some(),
                        "intent": intent,
                        "bids": bids,
                        "escrowed": escrowed,
                        "settlement": settlement,
                        "settled": policy.settled_intents.contains(&intent_id),
                        "policyRoot": format!("0x{}", hex::encode(policy.root())),
                    }));
                }
                ChainCommand::GetSovereignTemplate(domain_id, tx) => {
                    let _ = tx.send(
                        self.blockchain
                            .state
                            .settlement
                            .sovereign
                            .templates
                            .get(&domain_id)
                            .cloned(),
                    );
                }
                ChainCommand::ValidateSovereignAuditExport(bundle, res_tx) => {
                    let _ = res_tx.send(
                        self.blockchain
                            .validate_sovereign_audit_export(bundle.as_ref()),
                    );
                }
                #[cfg(test)]
                ChainCommand::SubmitDomainCommitment(commitment, res_tx) => {
                    let _ = res_tx.send(self.blockchain.submit_domain_commitment(commitment));
                }
                ChainCommand::GetExternalDomainProfile(key, res_tx) => {
                    let _ = res_tx.send(self.blockchain.external_domain_profile(&key));
                }
                ChainCommand::GetExternalDomainProfiles(res_tx) => {
                    let _ = res_tx.send(self.blockchain.external_domain_profiles());
                }
                ChainCommand::GetExternalIntakeDigest(res_tx) => {
                    let _ = res_tx.send(self.blockchain.state.settlement.external_intake_digest());
                }
                ChainCommand::GetExternalQuorumRound(key, height, res_tx) => {
                    let _ = res_tx.send(self.blockchain.external_quorum_round(&key, height));
                }
                ChainCommand::GetExternalQuorumRounds(key, res_tx) => {
                    let _ = res_tx.send(self.blockchain.external_quorum_rounds(&key));
                }
                ChainCommand::GetExternalDomainRegistration(key, res_tx) => {
                    let _ = res_tx.send(self.blockchain.external_domain_registration(&key));
                }
                ChainCommand::GetAiModel(id, res_tx) => {
                    let res = self.blockchain.state.ai_registry.models.get(&id).cloned();
                    let _ = res_tx.send(res);
                }
                ChainCommand::GetAiOutcome(id, res_tx) => {
                    let res = self.blockchain.state.ai_registry.outcomes.get(&id).cloned();
                    let _ = res_tx.send(res);
                }
                ChainCommand::GetAiOpenRequests(res_tx) => {
                    let height = self.ai_query_height();
                    let registry = &self.blockchain.state.ai_registry;
                    let res = registry
                        .requests
                        .values()
                        .filter(|r| !registry.outcomes.contains_key(&r.request_id))
                        .filter(|r| r.deadline_block >= height)
                        .take(256)
                        .cloned()
                        .collect();
                    let _ = res_tx.send(res);
                }
                ChainCommand::GetAiRequest(id, res_tx) => {
                    let res = self.blockchain.state.ai_registry.requests.get(&id).cloned();
                    let _ = res_tx.send(res);
                }
                ChainCommand::GetAiFeeReclaimStatus(id, res_tx) => {
                    let current_block = self.ai_query_height();
                    let res = self
                        .blockchain
                        .state
                        .ai_registry
                        .check_reclaimable(&id, current_block);
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
                    let current_block = self.ai_query_height();
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
                    let ranking = self
                        .blockchain
                        .state
                        .ai_registry
                        .agents_by_trust_score_permille();
                    let _ = res_tx.send(ranking);
                }
                ChainCommand::GetPruneStatus(res_tx) => {
                    let height = self.blockchain.chain.len() as u64;
                    let finalized = self.blockchain.finalized_height;
                    let mobile_mode = self
                        .blockchain
                        .pruning_manager
                        .as_ref()
                        .is_some_and(|pm| pm.min_blocks_to_keep < 1000);
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
                        // The snapshot bound has to be the newest snapshot
                        // that actually exists. Passing the tip height here
                        // (the old code) made the bound a no-op, so an
                        // operator prune deleted blocks the next restart
                        // needed to reach its snapshot: lasting data loss,
                        // node unable to boot (P10-F03).
                        let prunable = pm.get_prunable_blocks_with_retention(
                            height,
                            pm.latest_snapshot_height(),
                            finalized,
                            keep,
                        );
                        if let Some(ref store) = self.blockchain.storage {
                            for h in &prunable {
                                if store.delete_block(*h).is_ok() {
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
                        .state
                        .settlement
                        .domains
                        .get(domain_id)
                        .map(|d| d.last_committed_height)
                        .ok_or_else(|| format!("Domain {domain_id} not found"));
                    let _ = res_tx.send(res);
                }
                #[cfg(test)]
                ChainCommand::SealGlobalHeader(res_tx) => {
                    let _ = res_tx.send(self.blockchain.seal_global_header(None));
                }
                ChainCommand::GetGlobalHeaderProof(global_height, res_tx) => {
                    let _ = res_tx.send(self.blockchain.global_header_proof(global_height));
                }
                ChainCommand::FlushStorage(res_tx) => {
                    let res = self.blockchain.storage.as_ref().map_or(Ok(0), |storage| {
                        storage.flush_batch().map_err(|e| e.to_string())
                    });
                    let _ = res_tx.send(res);
                }
                // ─── B.U.D.: Storage operations ─────
                // Manifest registration, deal opening, repair acceptance and
                // retrieval challenges are `StorageTx` transactions applied in
                // block; no command here writes the storage registry.
                ChainCommand::IssueViewGrant { response, .. } => {
                    // View grants are folded into the storage state root, so
                    // issuing one between blocks rewrites the local node's
                    // root alone: a peer that never saw this RPC call computes
                    // a different root and rejects honest blocks (P30-F01).
                    // Until grants ride a block transaction, the RPC mutation
                    // path is refused on every chain, not only on mainnet.
                    let _ = response.send(Err(Self::view_grant_rpc_mutation_error()));
                    continue;
                }
                ChainCommand::RevokeViewGrant { response, .. } => {
                    // Same invariant as IssueViewGrant: the grant book is
                    // state-root bearing and may only change inside a block.
                    let _ = response.send(Err(Self::view_grant_rpc_mutation_error()));
                    continue;
                }
                ChainCommand::SocialDelete { response, .. } => {
                    // A delete rewrites the grant book and the rows keyed by the
                    // content, all state-root bearing. Applied between blocks it
                    // changes this node's root alone, so it is refused on every
                    // chain until it rides a block transaction.
                    let _ = response.send(Err(Self::social_delete_rpc_mutation_error()));
                    continue;
                }
                ChainCommand::GetViewGrants {
                    content_id,
                    response,
                } => {
                    let registry = &self.blockchain.state.storage_registry;
                    let rows = registry.view_grants_for(&content_id);
                    let live = registry.live_view_grant_count(&content_id);
                    let _ = response.send((rows, live));
                }
                ChainCommand::MayViewContent {
                    content_id,
                    viewer,
                    key_id,
                    owner,
                    response,
                } => {
                    let ok = self.blockchain.state.storage_registry.may_view(
                        &content_id,
                        &viewer,
                        &key_id,
                        &owner,
                    );
                    let _ = response.send(ok);
                }
                ChainCommand::RegisterConfidentialCommit {
                    commit,
                    auth,
                    response,
                } => {
                    if self.storage_economics_disabled_on_mainnet() {
                        let _ = response.send(Err(Self::mainnet_storage_disabled_error()));
                        continue;
                    }
                    let _ = (commit, auth);
                    let _ = response.send(Err(
                        "Out-of-block confidential commit registration is disabled to preserve state-root consensus; submit StorageTx::CommitConfidentialBody through bud_sendRawTransaction"
                            .to_string(),
                    ));
                }
                ChainCommand::GetConfidentialOwner {
                    content_id,
                    response,
                } => {
                    let _ =
                        response.send(self.blockchain.state.storage_registry.owner_of(&content_id));
                }
                ChainCommand::GetConfidentialCommit {
                    content_id,
                    response,
                } => {
                    let c = self
                        .blockchain
                        .state
                        .storage_registry
                        .get_confidential_commit(&content_id)
                        .cloned();
                    let _ = response.send(c);
                }
                ChainCommand::DeriveCodingAudit {
                    manifest_id,
                    challenge_id,
                    response,
                } => {
                    if self.storage_economics_disabled_on_mainnet() {
                        let _ = response.send(Err(Self::mainnet_storage_disabled_error()));
                        continue;
                    }
                    // Same entropy shape as the retrieval challenge above, and
                    // for the same reason: the column has to be unpredictable
                    // to both sides. An opener who picks it picks one the
                    // operator has; an operator who learns it in advance
                    // stores that column and discards the rest.
                    //
                    // The last block hash is the chain's own contribution, so
                    // neither party fixes it alone.
                    let entropy = crate::core::hash::hash_fields_bytes(&[
                        b"BDLM_RPC_CODING_AUDIT_ENTROPY_V1",
                        &self.blockchain.chain_id.to_le_bytes(),
                        self.blockchain.last_block().hash.as_bytes(),
                        manifest_id.as_bytes(),
                        &challenge_id.to_le_bytes(),
                    ]);
                    let res = self
                        .blockchain
                        .state
                        .storage_registry
                        .get_manifest(&manifest_id)
                        .ok_or_else(|| {
                            format!(
                                "no manifest {} in this registry, so there is no code word to \
                                 audit",
                                hex::encode(manifest_id.as_bytes())
                            )
                        })
                        .and_then(|manifest| {
                            crate::domain::storage_deal::StorageRegistry::derive_coding_audit(
                                &entropy,
                                manifest,
                                challenge_id,
                            )
                            .map_err(|e| e.to_string())
                        });
                    let _ = response.send(res);
                }
                ChainCommand::AnswerCodingAudit {
                    audit,
                    data_column,
                    parity_byte,
                    column_proof,
                    response,
                } => {
                    if self.storage_economics_disabled_on_mainnet() {
                        let _ = response.send(Err(Self::mainnet_storage_disabled_error()));
                        continue;
                    }
                    let res = self
                        .blockchain
                        .state
                        .storage_registry
                        .verify_coding_audit(&audit, &data_column, parity_byte, &column_proof)
                        .map_err(|e| e.to_string());
                    let _ = response.send(res);
                }
                ChainCommand::GetStorageManifest {
                    manifest_id,
                    response,
                } => {
                    let manifest = self
                        .blockchain
                        .state
                        .storage_registry
                        .get_manifest(&manifest_id)
                        .cloned();
                    let _ = response.send(manifest);
                }
                ChainCommand::GetStorageDealsByManifest {
                    manifest_id,
                    response,
                } => {
                    let deals = self
                        .blockchain
                        .state
                        .storage_registry
                        .deals_for_manifest(&manifest_id)
                        .into_iter()
                        .cloned()
                        .collect();
                    let _ = response.send(deals);
                }
                ChainCommand::GetStorageDealsByShard {
                    manifest_id,
                    shard_id,
                    response,
                } => {
                    let deals = self
                        .blockchain
                        .state
                        .storage_registry
                        .deals_for_shard(&manifest_id, &shard_id)
                        .into_iter()
                        .cloned()
                        .collect();
                    let _ = response.send(deals);
                }
                ChainCommand::GetStorageOutcome {
                    challenge_id,
                    response,
                } => {
                    let outcome = self
                        .blockchain
                        .state
                        .storage_registry
                        .get_result(challenge_id)
                        .cloned();
                    let _ = response.send(outcome);
                }
                ChainCommand::GetStorageRepairBand { margin, response } => {
                    let registry = &self.blockchain.state.storage_registry;
                    let band = StorageRepairBand {
                        margin,
                        // `k <= live < k + margin`: still reconstructible, but
                        // the headroom is gone.
                        repairable: registry.objects_needing_repair(margin),
                        // Below `k`. A repair deal opened here rebuilds nothing
                        // and only burns an operator bond, so it is reported
                        // apart rather than folded into the band above.
                        unrecoverable: registry.unrecoverable_objects(),
                    };
                    let _ = response.send(band);
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
                        .state
                        .storage_registry
                        .economics
                        .operator_rewards
                        .iter()
                        .map(|(operator, amount)| {
                            serde_json::json!({
                                "operator": operator.to_string(),
                                "amount": amount,
                            })
                        })
                        .collect();
                    let reallocation_tickets = self
                        .blockchain
                        .state
                        .storage_registry
                        .all_reallocation_tickets();
                    let pending_reallocations = reallocation_tickets
                        .iter()
                        .filter(|ticket| {
                            ticket.status
                                == crate::domain::storage_deal::ReallocationStatus::Pending
                        })
                        .count();
                    let under_replicated_tickets = reallocation_tickets
                        .iter()
                        .filter(|ticket| {
                            ticket.status
                                == crate::domain::storage_deal::ReallocationStatus::UnderReplicated
                        })
                        .count();
                    let active_replacements = reallocation_tickets
                        .iter()
                        .filter(|ticket| {
                            ticket.status
                                == crate::domain::storage_deal::ReallocationStatus::ActiveReplacement
                        })
                        .count();
                    // A ticket's cause is the part of the incident an operator acts
                    // on, and status alone cannot show it: a never-placed shard needs
                    // a first deal opened, a failed one needs a holder replaced.
                    let never_placed_tickets = reallocation_tickets
                        .iter()
                        .filter(|ticket| {
                            ticket.cause
                                == crate::domain::storage_deal::ReallocationCause::NeverPlaced
                        })
                        .count();
                    let stats_epoch = self.blockchain.last_block().index
                        / crate::core::chain_config::epoch_len_for_chain_id(
                            self.blockchain.chain_id,
                        );
                    let under_replicated_shards = self
                        .blockchain
                        .state
                        .storage_registry
                        .under_replicated_shards(stats_epoch)
                        .len();
                    let _ = res_tx.send(serde_json::json!({
                        "slashedBondTotal": self.blockchain.state.storage_registry.economics.slashed_bond_total,
                        "burnedBondTotal": self.blockchain.state.storage_registry.economics.burned_bond_total,
                        "operatorRewards": operator_rewards,
                        "eventCount": self.blockchain.storage_economics_events().len(),
                        "replicationTarget": crate::domain::storage_deal::STORAGE_REPLICATION_TARGET,
                        "pendingReallocations": pending_reallocations,
                        "underReplicatedTickets": under_replicated_tickets,
                        "activeReplacements": active_replacements,
                        "underReplicatedShards": under_replicated_shards,
                        "neverPlacedTickets": never_placed_tickets,
                    }));
                }
                ChainCommand::GetStorageOperatorEconomics { operator, response } => {
                    let slash_events: Vec<_> = self
                        .blockchain
                        .storage_economics_events()
                        .iter()
                        .filter(|event| {
                            event.operator == operator
                                && event.kind
                                    == crate::chain::blockchain::StorageEconomicsEventKind::OperatorBondSlashed
                        })
                        .map(|event| {
                            serde_json::json!({
                                "epoch": event.epoch,
                                "dealId": event.deal_id,
                                "amount": event.amount,
                                "balanceEffect": event.balance_effect,
                            })
                        })
                        .collect();
                    let active_deal_count = self
                        .blockchain
                        .state
                        .storage_registry
                        .all_deals()
                        .iter()
                        .filter(|deal| deal.operator == operator && deal.is_active())
                        .count();
                    let accrued_rewards = self
                        .blockchain
                        .state
                        .storage_registry
                        .economics
                        .operator_rewards
                        .get(&operator)
                        .copied()
                        .unwrap_or(0);
                    let slash_total = slash_events.iter().fold(0u64, |total, event| {
                        total.saturating_add(event["amount"].as_u64().unwrap_or(0))
                    });
                    let _ = response.send(serde_json::json!({
                        "operator": format!("0x{}", operator.to_hex()),
                        "accruedRewards": accrued_rewards,
                        "activeDealCount": active_deal_count,
                        "slashedBondTotal": slash_total,
                        "slashHistory": slash_events,
                        "slashedBondDisposition": "burn_from_operator_liquid_balance_best_effort",
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
                ChainCommand::IdentityResolve { subject, response } => {
                    // The epoch travels with the record so liveness is
                    // answered at the height the read happened on, not at
                    // whatever `now` the RPC layer later believes in.
                    let record = self
                        .blockchain
                        .state
                        .identity
                        .record(&subject)
                        .cloned()
                        .map(|record| (record, self.blockchain.state.epoch_index));
                    let _ = response.send(record);
                }
                ChainCommand::IdentityCredential {
                    credential_id,
                    response,
                } => {
                    let answer = self
                        .blockchain
                        .state
                        .identity
                        .credential(&credential_id)
                        .cloned()
                        .map(|credential| {
                            let verdict = self
                                .blockchain
                                .state
                                .identity
                                .is_credential_valid(
                                    &credential_id,
                                    self.blockchain.state.epoch_index,
                                )
                                .map_err(|e| e.to_string());
                            (credential, verdict)
                        });
                    let _ = response.send(answer);
                }
                ChainCommand::IdentityVerifyPresentation {
                    receipt,
                    requester,
                    document,
                    response,
                } => {
                    let _ = response.send(
                        crate::registry::check_receipt(
                            &self.blockchain.state.identity,
                            &receipt,
                            &requester,
                            &document,
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
                ChainCommand::PollenAssetForContent {
                    manifest_id,
                    response,
                } => {
                    let asset = self
                        .blockchain
                        .state
                        .marketplace
                        .protected_content
                        .asset_for(&manifest_id);
                    let _ = response.send(asset);
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
                ChainCommand::PollenGetEncryptionPolicies { response } => {
                    let policies: Vec<_> = self
                        .blockchain
                        .state
                        .marketplace
                        .encryption_policies
                        .values()
                        .cloned()
                        .collect();
                    let _ = response.send(policies);
                }
                ChainCommand::PollenGetPurchaseReceipts { response } => {
                    let receipts: Vec<_> = self
                        .blockchain
                        .state
                        .marketplace
                        .purchase_receipts
                        .values()
                        .cloned()
                        .collect();
                    let _ = response.send(receipts);
                }
                ChainCommand::HubGetGraftApps { response } => {
                    let apps = self
                        .blockchain
                        .state
                        .settlement
                        .graft
                        .apps
                        .values()
                        .cloned()
                        .collect();
                    let _ = response.send(apps);
                }
                ChainCommand::HubGetApps { response } => {
                    let apps: Vec<_> = self
                        .blockchain
                        .state
                        .budlumxyz
                        .apps
                        .values()
                        .cloned()
                        .collect();
                    let _ = response.send(apps);
                }
            }
        }
    }
}

#[cfg(test)]
mod proof_cache_tests {
    use super::*;
    use crate::consensus::pow::PoWEngine;
    use std::sync::Arc;

    #[test]
    fn account_proof_follows_balance_change_at_equal_chain_length() {
        let bc = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
        let (mut actor, _handle) = ChainActor::new(bc);
        let who = Address([7u8; 32]);
        actor.blockchain.state.add_balance(&who, 100);
        let before = actor.account_proof(&who);
        assert_eq!(before.balance, 100);
        // No block is added: the chain length stays the same.
        actor.blockchain.state.add_balance(&who, 50);
        let after = actor.account_proof(&who);
        assert_eq!(after.balance, 150);
        assert_ne!(before.root, after.root);
    }

    #[test]
    fn ai_query_height_is_the_state_height_not_an_epoch_guess() {
        let bc = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
        let (mut actor, _handle) = ChainActor::new(bc);
        actor.blockchain.state.epoch_index = 0;
        actor.blockchain.state.current_block_height = 37;
        assert_eq!(actor.ai_query_height(), 37);
    }
}
