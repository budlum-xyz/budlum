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

    // === TUR 6 SECURITY FIX (Güvenlik Denetimi §3) =========================
    // `bud_lockBridgeTransfer` RPC'den KALDIRILDI. Yeni: hiçbir koşulda
    // kimlik doğrulamasız (imza/kanıt olmadan) bridge lock oluşturulamaz.
    // Bridge lock'lar artık yalnızca:
    //   1. Internal `Blockchain::lock_bridge_transfer` çağrıları (system
    //      path) — bu yorum, kod tabanındaki tek kalıntıdır.
    //   2. (Tur 7+ planı) `lock_bridge_transfer_with_proof` API'si
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

    #[method(name = "bud_sealGlobalHeader")]
    async fn seal_global_header(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- Permissionless registry -------------------------------------------
    // These endpoints are permissionless by design: there is NO whitelist,
    // API-key allow-list or approval check gating participation. The only
    // validation is economic (stake) / cryptographic (evidence).

    /// Register for a role by submitting a `Stake` transaction. Staking == being
    /// registered; there is no separate approval step. Returns the tx hash.
    #[method(name = "bud_registryRegister")]
    async fn registry_register(&self, tx: Transaction)
        -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Register as a relayer by bonding stake. Staking == registration; no
    /// whitelist or approval. Returns the resulting relayer status.
    #[method(name = "bud_registryBondRelayer")]
    async fn registry_bond_relayer(
        &self,
        address: String,
        amount: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Register as a prover by bonding stake. OPTIONAL — proof submission is
    /// permissionless; registering only makes a prover eligible for rewards.
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

    #[method(name = "bud_health")]
    async fn health(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_nodeInfo")]
    async fn node_info(&self) -> Result<serde_json::Value, ErrorObjectOwned>;
}
