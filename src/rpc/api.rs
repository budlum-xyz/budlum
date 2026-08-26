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

    /// Inclusion or absence proof for one account.
    ///
    /// `bud_getBalance` returns what this node says; this returns what it can
    /// prove. The bundle carries its own root, which is the proof-bearing
    /// trie root and *not* the consensus state root.
    #[method(name = "bud_getAccountProof")]
    async fn get_account_proof(
        &self,
        address: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

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

    #[method(name = "bud_registerSovereignTemplate")]
    async fn register_sovereign_template(
        &self,
        template: crate::domain::SovereignDomainTemplate,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_validateSovereignAuditExport")]
    async fn validate_sovereign_audit_export(
        &self,
        bundle: crate::domain::sovereign::AuditExportBundle,
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

    // === SECURITY FIX (security review section 3) ====================
    // `bud_lockBridgeTransfer` was REMOVED from the RPC. New rule: under no
    // circumstances can a bridge lock be created without authentication (that
    // is, without a signature or a proof). Bridge locks now come only from:
    //   1. Internal `Blockchain::lock_bridge_transfer` calls (the system path)
    //      - this comment is the only remaining trace in the code base.
    //   2. (planned) a `lock_bridge_transfer_with_proof` API (a mandatory
    //      proof, like `verify_domain_event_proof`).
    //
    // The current implementation stays in `Blockchain::lock_bridge_transfer`
    // because internal code paths (the bridge lock event handler) call it.

    #[method(name = "bud_mintBridgeTransfer")]
    async fn mint_bridge_transfer(
        &self,
        source_domain: crate::domain::DomainId,
        source_height: u64,
        sequence: u64,
        expected_block_hash: Option<crate::domain::Hash32>,
        event: crate::cross_domain::DomainEvent,
        proof: crate::cross_domain::MerkleProof,
        relayer: crate::core::address::Address,
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

    /// Submit a relay proof from a relayer.
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
    // Validation is economic (stake) / cryptographic (evidence).

    /// Register by submitting a signed `Stake` (validator) or
    /// `LubotOperatorBond` (RoleId 8) transaction. Bonding == registration;
    /// There is no separate approval step. Returns the tx hash.
    #[method(name = "bud_registryRegister")]
    async fn registry_register(
        &self,
        tx: Transaction,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Legacy operator helper for test/dev administration. Public participants
    /// Must use a signed Stake transaction through `bud_registryRegister`.
    #[method(name = "bud_registryBondRelayer")]
    async fn registry_bond_relayer(
        &self,
        address: String,
        amount: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Legacy operator helper for a prover bond. Proof submission remains
    /// Permissionless; public stake registration uses a signed Stake tx.
    #[method(name = "bud_registryBondProver")]
    async fn registry_bond_prover(
        &self,
        address: String,
        amount: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Begin unbonding a `RELAYER` (3), `PROVER` (4) or `STORAGE_OPERATOR` (5) bond.
    ///
    /// These three bonds debit the account balance when they are posted and had
    /// No exit path: no command, no RPC, no transaction type. The bond was
    /// Permanently unrecoverable. Returns the release epoch, which follows the
    /// `unbonding_epochs` governance parameter.
    ///
    /// Operator-only, matching `bud_registryBondRelayer` - it is the same
    /// Unsigned legacy administration surface, and the exit must not be easier
    /// To reach than the entry.
    #[method(name = "bud_registryBeginRoleBondUnbonding")]
    async fn registry_begin_role_bond_unbonding(
        &self,
        address: String,
        role_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Withdraw a matured `RELAYER` / `PROVER` / `STORAGE_OPERATOR` bond back into the
    /// Account balance. Fails while the bond is still inside its unbonding
    /// Window, and the registration is removed so it cannot be withdrawn twice.
    #[method(name = "bud_registryWithdrawRoleBond")]
    async fn registry_withdraw_role_bond(
        &self,
        address: String,
        role_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Submit a ZK proof (L1 ↔ BudZKVM bridge). Permissionless: anyone may
    /// Submit; a valid proof is accepted regardless of registration. Registered
    /// Provers additionally earn a reward. Invalid proofs burn the fee.
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
    /// Unverified reports are rejected without any state change.
    #[method(name = "bud_submitSlashingReport")]
    async fn submit_slashing_report(
        &self,
        report: crate::registry::SlashingReport,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// (security audit §4) submit a QC fault proof.
    /// Permissionless: anyone can challenge a QC blob they suspect
    /// Contains an invalid Dilithium attestation. The proof must
    /// Pass the consensus-side Merkle-inclusion + cryptographic
    /// Verification (see `QcFaultProof::verify_against_blob`),
    /// Otherwise the call is rejected. On success the underlying
    /// QC blob's finality is invalidated from the proof's
    /// Checkpoint height. The cost of producing a valid proof
    /// (full dilithium5 signature forgery) makes this a free
    /// Permissionless surface without a fee gate.
    #[method(name = "bud_submitQcFaultProof")]
    async fn submit_qc_fault_proof(
        &self,
        proof: crate::consensus::qc::QcFaultProof,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_health")]
    async fn health(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_nodeInfo")]
    async fn node_info(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    // === B.U.D. Storage RPC surface ============================
    // The 7 RPCs below are the public, permissionless query/mutation surface
    // For the storage domain. Per the data-sovereignty rule (plan
    // §0.5) every endpoint is callable by any account on a standard node
    // No team-gated "official indexer" or admin-only RPC exists.
    //
    // IMPORTANT: `bud_storageAnswerChallenge` accepts a `range_hash` only;
    // It does NOT carry shard bytes. The chain does not store the bytes
    // (only the ContentId/manifest commitments), and the retrieval
    // Challenge is *interim* (not full Proof-of-Storage
    // §2.5 / vision §9.1). Off-chain verifiers must recompute the
    // Expected range hash from the public shard bytes.

    /// Register a `ContentManifest` with the storage domain. Returns the
    /// Deterministic `manifest_id` (ContentId) so the caller can address
    /// Subsequent deal-open / query calls.
    #[method(name = "bud_storageRegisterManifest")]
    async fn storage_register_manifest(
        &self,
        manifest: crate::storage::ContentManifest,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Optional node-side encode path: re-encode `data` under the scheme the
    /// client-built `manifest` claims and refuse a mismatch. Costly; the
    /// client-built register path remains the default. Three/Generated has no
    /// body to re-encode — callers should not send one.
    #[method(name = "bud_storageVerifyEncoding")]
    async fn storage_verify_encoding(
        &self,
        data_hex: String,
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
        request_id: u64,
        payer_signature: String,
        operator_signature: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Look up a previously-registered `ContentManifest` by its
    /// `manifest_id`.
    #[method(name = "bud_storageGetManifest")]
    async fn storage_get_manifest(
        &self,
        manifest_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// All `StorageDeal`s bound to a given `manifest_id` (any replica
    /// Index, any operator, any status). Permissionless read.
    #[method(name = "bud_storageGetDealsByManifest")]
    async fn storage_get_deals_by_manifest(
        &self,
        manifest_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// All `StorageDeal`s bound to a given `(manifest_id, shard_id)` pair.
    /// Used by clients that downloaded one shard and want to know which
    /// Operators are also holding it.
    #[method(name = "bud_storageGetDealsByShard")]
    async fn storage_get_deals_by_shard(
        &self,
        manifest_id: String,
        shard_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Open a `RetrievalChallenge` against an active deal. Anyone may call
    /// This; the anti-spam mechanism is `opener_bond` (returned on
    /// Success, burned on false positive). Permissionless.
    #[method(name = "bud_storageOpenChallenge")]
    async fn storage_open_challenge(
        &self,
        request: crate::domain::storage_deal::RetrievalChallengeRequest,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Operator answers an open challenge with a `range_hash`. The chain
    /// Only verifies timing + operator identity + structural validity; the
    /// Hash itself is recomputed by off-chain verifiers from the public
    /// Shard bytes.
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
    /// Accounting) from the chain actor. Permissionless read.
    #[method(name = "bud_storageGetEconomicsEvents")]
    async fn storage_get_economics_events(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query one operator's accrued storage rewards, slash history, and
    /// Active deal count. Permissionless read; no indexer is required.
    #[method(name = "bud_storageGetOperatorEconomics")]
    async fn storage_get_operator_economics(
        &self,
        operator: crate::core::address::Address,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Look up a finalized `ChallengeResult` by `challenge_id`.
    ///
    /// The response always carries `proofKind` and `proof_kind` set to
    /// `"interim_availability_only"`.
    /// A retrieval outcome demonstrates a timely response for one requested
    /// Byte range; it is not a full Proof-of-Storage attestation.
    #[method(name = "bud_storageGetOutcome")]
    async fn storage_get_outcome(
        &self,
        challenge_id: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Objects within `margin` shards of unrecoverable, and those already past
    /// it. Permissionless read; no indexer is required.
    ///
    /// The margin is the caller's. The node's maintenance sweep judges every
    /// object by its own erasure scheme's margin, which is correct for a sweep
    /// and useless to an operator asking a fixed question like "what is within
    /// two shards of trouble?". Both lists come back separately: an object
    /// below `k` cannot be repaired at all, and must not read as one that can.
    #[method(name = "bud_storageRepairBand")]
    async fn storage_repair_band(&self, margin: u32)
        -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query active storage operators (STORAGE_OPERATOR RoleId=5).
    /// Previously documented as ghost RPC, now implemented.
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

    /// B.U.D. Gateway: render recipe-born content into a requested format.
    ///
    /// `format` is one of `svg`, `png:<size>`, `frame:<index>`. The reply
    /// carries the bytes and the render id, which commits to the format:
    /// the same recipe rendered as PNG is a different object from the same
    /// recipe rendered as SVG.
    #[method(name = "bud_gatewayRenderContent")]
    async fn gateway_render_content(
        &self,
        name: String,
        format: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// D-Web Passport profile bundle for budlum.xyz. Read-only and evidence-labelled.
    #[method(name = "bud_passportGetProfile")]
    async fn passport_get_profile(
        &self,
        name: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// D-Web Passport proof bundle for budlum.xyz. Read-only and evidence-only.
    #[method(name = "bud_passportGetProofBundle")]
    async fn passport_get_proof_bundle(
        &self,
        name: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Budlum Atlas wallet context for bud.scan/budlum.xyz. Read-only.
    #[method(name = "bud_atlasGetWalletContext")]
    async fn atlas_get_wallet_context(
        &self,
        address: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

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

    /// List Pollen DataAsset records visible in chain state.
    #[method(name = "bud_pollenGetDataAssets")]
    async fn pollen_get_data_assets(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// List Pollen AccessGrant records visible in chain state.
    #[method(name = "bud_pollenGetAccessGrants")]
    async fn pollen_get_access_grants(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// List Pollen SaleAuthorization records visible in chain state.
    #[method(name = "bud_pollenGetSaleAuthorizations")]
    async fn pollen_get_sale_authorizations(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// List Pollen purchase receipts visible in chain state.
    #[method(name = "bud_pollenGetPurchaseReceipts")]
    async fn pollen_get_purchase_receipts(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Build canonical AiInferenceRequest.input_ref for Pollen-gated data reads.
    #[method(name = "bud_pollenBuildAiInputRef")]
    async fn pollen_build_ai_input_ref(
        &self,
        asset_id: String,
        grant_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare unsigned owner/seller authorization for selling DataAsset pollen.
    #[method(name = "bud_pollenPrepareSaleAuthorization")]
    async fn pollen_prepare_sale_authorization(
        &self,
        seller: String,
        asset_id: String,
        unit_price: u64,
        expires_at_block: u64,
        max_grants: u32,
        terms_hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare an authorization-backed Pollen purchase without mutating state.
    ///
    /// `buyer_signature`: the buyer signs the whole set of purchase
    /// (authorization, fiyat, sure, max_reads, payment_commitment, expiry)
    /// baglanmis ed25519 imzasi - Strix #358: imzasiz purchase kabul
    /// edilmez.
    #[method(name = "bud_pollenPreparePurchase")]
    async fn pollen_prepare_purchase(
        &self,
        authorization_id: String,
        buyer: String,
        grantee: String,
        grant_duration_blocks: u64,
        max_reads: u32,
        payment_commitment: String,
        buyer_signature: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- B.U.D. budlumxyz ---

    /// List all registered dApps.
    #[method(name = "bud_hubGetApps")]
    async fn budlumxyz_get_apps(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a dApp registration transaction.
    #[method(name = "bud_hubPrepareRegister")]
    async fn budlumxyz_prepare_register(
        &self,
        developer: String,
        name: String,
        category: crate::budlumxyz::types::AppCategory,
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

    // --- Mobile/Snapshot Pruning API ---

    /// Get current snapshot/pruning status.
    #[method(name = "bud_pruneStatus")]
    async fn prune_status(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Manually trigger a pruning pass.
    #[method(name = "bud_requestPrune")]
    async fn request_prune(
        &self,
        min_blocks_to_keep: Option<u64>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- (§1): AI Inference & Verifier Layer ---

    /// Query registered AI model specification by model_id hex.
    #[method(name = "bud_aiGetModel")]
    async fn ai_get_model(&self, model_id: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a model registration transaction.
    #[method(name = "bud_aiRegisterModel")]
    /// Prepare an AI model registration transaction template.
    ///
    /// The governance-tunable registration fee
    /// (`RegistryParams::ai_model_register_fee`) must be attached as
    /// `tx.amount`; the template sets amount 0 - the caller signs the final
    /// amount. Below-fee registrations are rejected atomically by the
    /// executor (`ai_model_register_fee_insufficient`).
    /// Register an AI model (template; the governance-tunable registration
    /// fee must be attached as tx.amount - see `ai_model_register_fee`).
    ///
    /// The modality bits (`ModalitySet`). Absent means the old behaviour
    /// (`text_only`). 0 reads nothing (`none` - a deliberate refusal). 1 is
    /// text.
    #[method(name = "bud_aiRegisterModel")]
    async fn ai_register_model(
        &self,
        owner: String,
        model_hash: String,
        min_verifier_count: u32,
        agreement_threshold: u32,
        max_input_ref_bytes: u64,
        max_output_ref_bytes: u64,
        request_deadline_blocks: u64,
        result_deadline_blocks: u64,
        modality_bits: Option<u32>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare an AI inference request transaction.
    ///
    /// The perception declaration: the asset (32B hex), the content (32B hex),
    /// the kind tag (1=text, 2=image, 3=audio, 4=video) and the unit amount.
    /// If all four are given the request is built with a V3 declaration; if
    /// none are given it is built without one (and the executor refuses it,
    /// fail-closed).
    #[method(name = "bud_aiSubmitRequest")]
    async fn ai_submit_request(
        &self,
        requester: String,
        model_id: String,
        input_commitment: String,
        input_ref_hex: String,
        max_fee: u64,
        callback: Option<String>,
        deadline_block: u64,
        perception_asset_id: Option<String>,
        perception_content_id: Option<String>,
        perception_kind_tag: Option<u32>,
        perception_declared_units: Option<u32>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare an AI inference attestation result transaction.
    #[method(name = "bud_aiSubmitResult")]
    async fn ai_submit_result(
        &self,
        verifier: String,
        request_id: String,
        output_commitment: String,
        output_ref_hex: String,
        result_nonce: u64,
        signature_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query finalized AI inference outcome by request_id hex.
    #[method(name = "bud_aiGetOutcome")]
    async fn ai_get_outcome(
        &self,
        request_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query active AI verifiers (RoleId::AI_VERIFIER = RoleId(6)).
    #[method(name = "bud_aiGetActiveVerifiers")]
    async fn ai_get_active_verifiers(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Reclaim escrowed max_fee for expired unfinalized AI inference request.
    #[method(name = "bud_aiReclaimFee")]
    async fn ai_reclaim_fee(
        &self,
        request_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Check if a verifier has equivocated on a specific AI request.
    #[method(name = "bud_aiEquivocationStatus")]
    async fn ai_equivocation_status(
        &self,
        request_id: String,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Check if an AI request has been cancelled.
    #[method(name = "bud_aiCancelStatus")]
    async fn ai_cancel_status(
        &self,
        request_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a dispute slash transaction for an equivocating verifier.
    /// This creates an AiDisputeSlash transaction template that must be signed
    /// And submitted via bud_sendRawTransaction.
    #[method(name = "bud_aiDisputeSlash")]
    async fn ai_dispute_slash(
        &self,
        submitter: String,
        request_id: String,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query dispute/slash status for a (request, verifier) pair.
    /// Returns equivocation status, dispute window info, and verifier stake details.
    #[method(name = "bud_aiSlashingStatus")]
    async fn ai_slashing_status(
        &self,
        request_id: String,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query verifier stake information.
    /// Returns stake amount, staking status, and equivocation history.
    #[method(name = "bud_aiVerifierStake")]
    async fn ai_verifier_stake(
        &self,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query pending callback events for an address.
    /// When an AI inference outcome is finalized with a callback address,
    /// The event is queued here for off-chain delivery.
    #[method(name = "bud_aiCallbackQueue")]
    async fn ai_callback_queue(
        &self,
        callback_address: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query ZKVM execution proof for a (request, verifier) pair.
    /// Results with execution proofs are "trustless", verified by ZKVM
    /// Mathematics rather than by verifier reputation alone. This is the
    /// Core primitive for the Agentic Economy paradigm shift.
    #[method(name = "bud_aiExecutionProof")]
    async fn ai_execution_proof(
        &self,
        request_id: String,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query QoS metrics for a verifier.
    /// Returns reliability score, finalization rate, equivocation count,
    /// And response time metrics. Enables QoS-aware verifier selection.
    #[method(name = "bud_aiVerifierQos")]
    async fn ai_verifier_qos(
        &self,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get all verifiers ranked by reliability score.
    /// Returns verifiers ordered from highest to lowest reliability,
    /// Enabling agents to select the most trustworthy verifiers.
    #[method(name = "bud_aiVerifierRanking")]
    async fn ai_verifier_ranking(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query an agent-to-agent payment by ID.
    #[method(name = "bud_aiAgentPayment")]
    async fn ai_agent_payment(
        &self,
        payment_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query payments for an agent (from or to).
    #[method(name = "bud_aiAgentPayments")]
    async fn ai_agent_payments(
        &self,
        agent: String,
        direction: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query the verifier whitelist.
    /// Returns all whitelisted verifier addresses. If empty, the system
    /// Is in permissionless mode (any staked verifier can submit).
    #[method(name = "bud_aiVerifierWhitelist")]
    async fn ai_verifier_whitelist(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_aiAgentReputation")]
    async fn ai_agent_reputation(
        &self,
        agent: crate::core::address::Address,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_aiAgentRanking")]
    async fn ai_agent_ranking(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// A read-only status endpoint (independent of the relayer's decision).
    #[method(name = "bud_getStatus")]
    async fn get_status(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    ///: Active validator set snapshot.
    #[method(name = "bud_getValidatorSet")]
    async fn get_validator_set(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    ///: Domain info by ID.
    #[method(name = "bud_getDomainInfo")]
    async fn get_domain_info(&self, domain_id: u32) -> Result<serde_json::Value, ErrorObjectOwned>;

    ///: Slashing history (audit trail).
    #[method(name = "bud_getSlashingHistory")]
    async fn get_slashing_history(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Lubot readiness: chain-derived bonded operator count plus explicit
    /// Fail-closed flags for scheduler, worker, proof, and settlement wiring.
    #[method(name = "bud_lubotStats")]
    async fn lubot_stats(&self) -> Result<serde_json::Value, ErrorObjectOwned>;
}
