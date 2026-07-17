#![allow(clippy::too_many_arguments)]

use crate::core::transaction::Transaction;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::ErrorObjectOwned;

#[rpc(server)]
#[allow(clippy::too_many_arguments)]
pub trait BudlumApi {
    #[method(name = "bud_chainId")]
    async fn chain_id(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_blockNumber")]
    async fn block_number(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_getBlockByNumber")]
    async fn get_block_by_number(&self, number: u64)
        -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_getBlockByHash")]
    async fn get_block_by_hash(&self, hash: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_getBalance")]
    async fn get_balance(&self, address: String) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_getNonce")]
    async fn get_nonce(&self, address: String) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_sendRawTransaction")]
    async fn send_raw_transaction(&self, tx: Transaction) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_getTransactionByHash")]
    async fn get_transaction_by_hash(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_getTransactionReceipt")]
    async fn get_transaction_receipt(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_gasPrice")]
    async fn gas_price(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_estimateGas")]
    async fn estimate_gas(&self, tx: Transaction) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_txPrecheck")]
    async fn tx_precheck(&self, tx: Transaction) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_syncing")]
    async fn syncing(&self) -> Result<bool, ErrorObjectOwned>;

    #[method(name = "bud_netVersion")]
    async fn net_version(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_netListening")]
    async fn net_listening(&self) -> Result<bool, ErrorObjectOwned>;

    #[method(name = "bud_netPeerCount")]
    async fn net_peer_count(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_getSettlementInfo")]
    async fn get_settlement_info(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_getGlobalHeader")]
    async fn get_global_header(&self, height: u64) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_getDomainCommitments")]
    async fn get_domain_commitments(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_getConsensusDomains")]
    async fn get_consensus_domains(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_registerConsensusDomain")]
    async fn register_consensus_domain(
        &self,
        domain: crate::domain::ConsensusDomain,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_submitDomainCommitment")]
    async fn submit_domain_commitment(
        &self,
        commitment: crate::domain::DomainCommitment,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_submitVerifiedDomainCommitment")]
    async fn submit_verified_domain_commitment(
        &self,
        payload: crate::domain::VerifiedDomainCommitment,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_submitCrossDomainMessage")]
    async fn submit_cross_domain_message(
        &self,
        msg: crate::cross_domain::CrossDomainMessage,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_registerBridgeAsset")]
    async fn register_bridge_asset(
        &self,
        asset_id: crate::cross_domain::AssetId,
        domain: crate::domain::DomainId,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // === Phase 0.10 SECURITY FIX (Güvenlik Denetimi §3) =========================
    // `bud_lockBridgeTransfer` RPC'den KALDIRILDI. Yeni: hiçbir koşulda
    // kimlik doğrulamasız (imza/kanıt olmadan) bridge lock oluşturulamaz.
    // Bridge lock'lar artık yalnızca:
    //   1. Internal `Blockchain::lock_bridge_transfer` çağrıları (system
    //      path) — bu yorum, kod tabanındaki tek kalıntıdır.
    //   2. (Phase 0.12+ planı) `lock_bridge_transfer_with_proof` API'si
    //      (`verify_domain_event_proof` benzeri kanıt zorunlu).
    //
    // Mevcut implementasyon `Blockchain::lock_bridge_transfer`'da kalır
    // çünkü internal kod yolları (bridge lock event handler) bunu çağırır.

    #[method(name = "bud_mintBridgeTransfer")]
    async fn mint_bridge_transfer(
        &self,
        source_domain: crate::domain::DomainId,
        source_height: u64,
        sequence: u64,
        expected_block_hash: Option<crate::domain::Hash32>,
        event: crate::cross_domain::DomainEvent,
        proof: crate::cross_domain::MerkleProof,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_burnBridgeTransfer")]
    async fn burn_bridge_transfer(
        &self,
        message_id: crate::cross_domain::MessageId,
        domain: crate::domain::DomainId,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_burnBridgeTransferWithEvent")]
    async fn burn_bridge_transfer_with_event(
        &self,
        message_id: crate::cross_domain::MessageId,
        domain: crate::domain::DomainId,
        domain_height: u64,
        event_index: u32,
        expiry_height: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_unlockBridgeTransfer")]
    async fn unlock_bridge_transfer(
        &self,
        message_id: crate::cross_domain::MessageId,
        source_domain: crate::domain::DomainId,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_unlockBridgeTransferVerified")]
    async fn unlock_bridge_transfer_verified(
        &self,
        target_domain: crate::domain::DomainId,
        target_height: u64,
        sequence: u64,
        expected_block_hash: Option<crate::domain::Hash32>,
        event: crate::cross_domain::DomainEvent,
        proof: crate::cross_domain::MerkleProof,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// ADIM5 §5.1: Submit a relay proof from a relayer.
    #[method(name = "bud_submitRelayProof")]
    async fn submit_relay_proof(
        &self,
        message_id: crate::cross_domain::message::MessageId,
        relayer: String,
        proof: crate::cross_domain::event_tree::MerkleProof,
        source_domain: crate::domain::types::DomainId,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_sealGlobalHeader")]
    async fn seal_global_header(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- Permissionless registry -------------------------------------------
    // These endpoints are permissionless by design: there is NO whitelist,
    // API-key allow-list or approval check gating participation. The only
    // validation is economic (stake) / cryptographic (evidence).

    /// Register for a role by submitting a `Stake` transaction. Staking == being
    /// registered; there is no separate approval step. Returns the tx hash.
    #[method(name = "bud_registryRegister")]
    async fn registry_register(
        &self,
        tx: Transaction,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Legacy operator helper for test/dev administration. Public participants
    /// must use a signed Stake transaction through `bud_registryRegister`.
    #[method(name = "bud_registryBondRelayer")]
    async fn registry_bond_relayer(
        &self,
        address: String,
        amount: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Legacy operator helper for a prover bond. Proof submission remains
    /// permissionless; public stake registration uses a signed Stake tx.
    #[method(name = "bud_registryBondProver")]
    async fn registry_bond_prover(
        &self,
        address: String,
        amount: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Submit a ZK proof (L1 ↔ BudZKVM bridge). Permissionless: anyone may
    /// submit; a valid proof is accepted regardless of registration. Registered
    /// provers additionally earn a reward. Invalid proofs burn the fee.
    #[method(name = "bud_submitZkProof")]
    async fn submit_zk_proof(
        &self,
        submission: crate::prover::ZkProofSubmission,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query a participant's status for a role (roleId: 1=validator, 2=verifier,
    /// 3=relayer, 4=prover, or any custom id).
    #[method(name = "bud_registryQuery")]
    async fn registry_query(
        &self,
        address: String,
        role_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// List active members of a role.
    #[method(name = "bud_registryActiveMembers")]
    async fn registry_active_members(
        &self,
        role_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Submit a slashing evidence report. Permissionless: anyone may submit.
    /// The report is only actioned if structurally valid AND consensus-verified;
    /// unverified reports are rejected without any state change.
    #[method(name = "bud_submitSlashingReport")]
    async fn submit_slashing_report(
        &self,
        report: crate::registry::SlashingReport,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Phase 0.17 (security audit §4): submit a QC fault proof.
    /// Permissionless: anyone can challenge a QC blob they suspect
    /// contains an invalid Dilithium attestation. The proof must
    /// pass the consensus-side Merkle-inclusion + cryptographic
    /// verification (see `QcFaultProof::verify_against_blob`),
    /// otherwise the call is rejected. On success the underlying
    /// QC blob's finality is invalidated from the proof's
    /// checkpoint height. The cost of producing a valid proof
    /// (full dilithium5 signature forgery) makes this a free
    /// permissionless surface without a fee gate.
    #[method(name = "bud_submitQcFaultProof")]
    async fn submit_qc_fault_proof(
        &self,
        proof: crate::consensus::qc::QcFaultProof,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_health")]
    async fn health(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_nodeInfo")]
    async fn node_info(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    // === Phase 0.38 — B.U.D. Storage RPC surface ============================
    // The 7 RPCs below are the public, permissionless query/mutation surface
    // for the storage domain. Per the data-sovereignty rule (Phase 0.39 plan
    // §0.5) every endpoint is callable by any account on a standard node
    // — no team-gated "official indexer" or admin-only RPC exists.
    //
    // IMPORTANT: `bud_storageAnswerChallenge` accepts a `range_hash` only;
    // it does NOT carry shard bytes. The chain does not store the bytes
    // (only the ContentId/manifest commitments), and the retrieval
    // challenge is *interim* (not full Proof-of-Storage — see Phase 0.39
    // §2.5 / vision §9.1). Off-chain verifiers must recompute the
    // expected range hash from the public shard bytes.

    /// Register a `ContentManifest` with the storage domain. Returns the
    /// deterministic `manifest_id` (ContentId) so the caller can address
    /// subsequent deal-open / query calls.
    #[method(name = "bud_storageRegisterManifest")]
    async fn storage_register_manifest(
        &self,
        manifest: crate::storage::ContentManifest,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Open a new `StorageDeal` for a specific shard of a registered manifest.
    #[method(name = "bud_storageOpenDeal")]
    async fn storage_open_deal(
        &self,
        domain_id: u32,
        manifest: crate::storage::ContentManifest,
        shard_id: String,
        operator: String,
        payer: String,
        replica_index: u8,
        start_epoch: u64,
        end_epoch: u64,
        economics: crate::domain::storage_deal::StorageEconomicsParams,
        domain_params: crate::domain::storage_params::StorageDomainParams,
        merkle_proof: Option<Vec<u8>>,
        storage_root: Option<crate::domain::Hash32>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Look up a previously-registered `ContentManifest` by its
    /// `manifest_id`.
    #[method(name = "bud_storageGetManifest")]
    async fn storage_get_manifest(
        &self,
        manifest_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// All `StorageDeal`s bound to a given `manifest_id` (any replica
    /// index, any operator, any status). Permissionless read.
    #[method(name = "bud_storageGetDealsByManifest")]
    async fn storage_get_deals_by_manifest(
        &self,
        manifest_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// All `StorageDeal`s bound to a given `(manifest_id, shard_id)` pair.
    /// Used by clients that downloaded one shard and want to know which
    /// operators are also holding it.
    #[method(name = "bud_storageGetDealsByShard")]
    async fn storage_get_deals_by_shard(
        &self,
        manifest_id: String,
        shard_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Open a `RetrievalChallenge` against an active deal. Anyone may call
    /// this; the anti-spam mechanism is `opener_bond` (returned on
    /// success, burned on false positive). Permissionless.
    #[method(name = "bud_storageOpenChallenge")]
    async fn storage_open_challenge(
        &self,
        request: crate::domain::storage_deal::RetrievalChallengeRequest,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Operator answers an open challenge with a `range_hash`. The chain
    /// only verifies timing + operator identity + structural validity; the
    /// hash itself is recomputed by off-chain verifiers from the public
    /// shard bytes.
    #[method(name = "bud_storageAnswerChallenge")]
    async fn storage_answer_challenge(
        &self,
        response: crate::domain::storage_deal::RetrievalResponse,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query aggregate storage economics accounting from the chain actor.
    /// Permissionless read: no official indexer or team-operated service.
    #[method(name = "bud_storageGetEconomicsSummary")]
    async fn storage_get_economics_summary(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query storage economics events (operator reward accrual and slashed-bond
    /// accounting) from the chain actor. Permissionless read.
    #[method(name = "bud_storageGetEconomicsEvents")]
    async fn storage_get_economics_events(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Look up a finalized `ChallengeResult` by `challenge_id`.
    #[method(name = "bud_storageGetOutcome")]
    async fn storage_get_outcome(
        &self,
        challenge_id: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query active storage operators (STORAGE_OPERATOR RoleId=5).
    /// Phase 3 §0.3 — previously documented as ghost RPC, now implemented.
    /// Returns active `PermissionlessRegistry` members filtered by storage operator role.
    #[method(name = "bud_storageActiveOperators")]
    async fn storage_active_operators(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- B.U.D. Name Service (BNS) ---

    /// Resolve a human-readable name to an address.
    #[method(name = "bud_bnsResolve")]
    async fn bns_resolve(&self, name: String) -> Result<Option<String>, ErrorObjectOwned>;

    /// Resolve a name to full BNS record (address, storage_root, etc).
    #[method(name = "bud_bnsResolveFull")]
    async fn bns_resolve_full(&self, name: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Resolve a name to a B.U.D. Content ID (CID).
    #[method(name = "bud_bnsResolveContent")]
    async fn bns_resolve_content(&self, name: String) -> Result<Option<String>, ErrorObjectOwned>;

    /// Resolve a subdomain (e.g. photos.ayaz.bud).
    #[method(name = "bud_bnsResolveSubdomain")]
    async fn bns_resolve_subdomain(
        &self,
        parent_name: String,
        sub_label: String,
    ) -> Result<Option<String>, ErrorObjectOwned>;

    /// Prepare a registration transaction (offline helper).
    #[method(name = "bud_bnsPrepareRegister")]
    async fn bns_prepare_register(
        &self,
        name: String,
        owner: String,
        duration: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a subdomain registration transaction.
    #[method(name = "bud_bnsPrepareRegisterSubdomain")]
    async fn bns_prepare_register_subdomain(
        &self,
        parent_name: String,
        sub_label: String,
        sub_owner: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a transaction to link content (CID) to a name.
    #[method(name = "bud_bnsPrepareSetContent")]
    async fn bns_prepare_set_content(
        &self,
        name: String,
        owner: String,
        cid: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- B.U.D. SocialFi ---

    /// Get an NFT post by ID.
    #[method(name = "bud_socialGetPost")]
    async fn social_get_post(&self, id: u64) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get all posts by a user.
    #[method(name = "bud_socialGetProfile")]
    async fn social_get_profile(
        &self,
        address: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// B.U.D. SocialFi: Get global social feed.
    #[method(name = "bud_socialGetFeed")]
    async fn social_get_feed(&self, limit: usize) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare an NFT post transaction (Mint).
    #[method(name = "bud_socialPreparePost")]
    async fn social_prepare_post(
        &self,
        author: String,
        cid: String,
        author_name: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;
    /// B.U.D. Gateway: Fetch raw content by BNS name (D-Web entry).
    #[method(name = "bud_gatewayFetchContent")]
    async fn gateway_fetch_content(&self, name: String) -> Result<String, ErrorObjectOwned>;

    // --- B.U.D. SocialFi extended ---

    /// Prepare an NFT burn transaction.
    #[method(name = "bud_socialPrepareBurn")]
    async fn social_prepare_burn(
        &self,
        owner: String,
        nft_id: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare an NFT boost transaction.
    #[method(name = "bud_socialPrepareBoost")]
    async fn social_prepare_boost(
        &self,
        booster: String,
        nft_id: u64,
        amount: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- B.U.D. AI Data Marketplace ---

    /// List all active data offers.
    #[method(name = "bud_marketGetOffers")]
    async fn market_get_offers(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a data offer transaction.
    #[method(name = "bud_marketPrepareOffer")]
    async fn market_prepare_offer(
        &self,
        seller: String,
        cid: String,
        price: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a data purchase transaction.
    #[method(name = "bud_marketPreparePurchase")]
    async fn market_prepare_purchase(
        &self,
        buyer: String,
        offer_id: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- B.U.D. Hub ---

    /// List all registered dApps.
    #[method(name = "bud_hubGetApps")]
    async fn hub_get_apps(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a dApp registration transaction.
    #[method(name = "bud_hubPrepareRegister")]
    async fn hub_prepare_register(
        &self,
        developer: String,
        name: String,
        category: crate::hub::types::AppCategory,
        website_url: String,
        manifest_id: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- B.U.D. Universal Relayer ---

    /// Prepare an external chain relay transaction.
    #[method(name = "bud_relayerPrepareExternalTx")]
    async fn relayer_prepare_external_tx(
        &self,
        from: String,
        chain: crate::core::transaction::ExternalChain,
        target_address: String,
        payload: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- Mobile/Snapshot Pruning API (ADIM 5 §5.2 + §5.3) ---

    /// Get current snapshot/pruning status.
    #[method(name = "bud_pruneStatus")]
    async fn prune_status(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Manually trigger a pruning pass.
    #[method(name = "bud_requestPrune")]
    async fn request_prune(
        &self,
        min_blocks_to_keep: Option<u64>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;
}
