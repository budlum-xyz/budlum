use crate::chain::finality::FinalityCert;
use crate::consensus::pos::Checkpoint;
use crate::consensus::qc::QcBlob;
use crate::core::account::Account;
use crate::core::address::Address;
use crate::core::block::{Block, BlockHeader};
use crate::core::transaction::Transaction;
use crate::cross_domain::message::CrossDomainMessage;
use crate::cross_domain::BridgeState;
use crate::domain::{ConsensusDomain, DomainCommitment};
use crate::settlement::GlobalBlockHeader;
use std::collections::HashMap;

pub type SeenBlockMap = HashMap<(Address, u64), (BlockHeader, Vec<u8>)>;

pub trait BlockchainStorage: Send + Sync {
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn insert_block(&self, block: &Block) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn commit_block(&self, block: &Block, state_root: &str) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn get_block(&self, hash: &str) -> std::io::Result<Option<Block>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn get_block_by_height(&self, height: u64) -> std::io::Result<Option<Block>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn get_canonical_height(&self) -> std::io::Result<u64>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_canonical_height(&self, height: u64) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_state_root(&self, height: u64, state_root: &str) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn get_state_root(&self, height: u64) -> std::io::Result<Option<String>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_last_hash(&self, hash: &str) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn get_last_hash(&self) -> std::io::Result<Option<String>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_chain(&self) -> std::io::Result<Vec<Block>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn delete_block(&self, height: u64) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_qc_blob(&self, height: u64, blob: &QcBlob) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn get_qc_blob(&self, height: u64) -> std::io::Result<Option<QcBlob>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn delete_qc_blob(&self, height: u64) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_finality_cert(&self, height: u64, cert: &FinalityCert) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn get_finality_cert(&self, height: u64) -> std::io::Result<Option<FinalityCert>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn delete_finality_cert(&self, height: u64) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_consensus_domain(&self, domain: &ConsensusDomain) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_consensus_domains(&self) -> std::io::Result<Vec<ConsensusDomain>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_domain_commitment(&self, commitment: &DomainCommitment) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_domain_commitment_batch(
        &self,
        commitment: &DomainCommitment,
        domains: &[ConsensusDomain],
    ) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_domain_commitments(&self) -> std::io::Result<Vec<DomainCommitment>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_global_header(&self, header: &GlobalBlockHeader) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn get_global_header(&self, height: u64) -> std::io::Result<Option<GlobalBlockHeader>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_global_headers(&self) -> std::io::Result<Vec<GlobalBlockHeader>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_bridge_state(&self, bridge_state: &BridgeState) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_bridge_state(&self) -> std::io::Result<Option<BridgeState>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_universal_relayer(
        &self,
        relayer: &crate::cross_domain::relayer::UniversalRelayer,
    ) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_universal_relayer(
        &self,
    ) -> std::io::Result<Option<crate::cross_domain::relayer::UniversalRelayer>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_proof_claim_registry(
        &self,
        registry: &crate::prover::ProofClaimRegistry,
    ) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_proof_claim_registry(
        &self,
    ) -> std::io::Result<Option<crate::prover::ProofClaimRegistry>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_storage_economics_state(
        &self,
        snapshot: &crate::chain::blockchain::StorageEconomicsStateSnapshot,
    ) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_storage_economics_state(
        &self,
    ) -> std::io::Result<Option<crate::chain::blockchain::StorageEconomicsStateSnapshot>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_cross_domain_message(&self, message: &CrossDomainMessage) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_cross_domain_messages(&self) -> std::io::Result<Vec<CrossDomainMessage>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_tx_index(&self, tx_hash: &str, block_height: u64) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn get_tx_block_height(&self, tx_hash: &str) -> std::io::Result<Option<u64>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn delete_tx_index(&self, tx_hash: &str) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_account(&self, pubkey: &Address, account: &Account) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_all_accounts(&self) -> std::io::Result<HashMap<Address, Account>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_mempool_tx(&self, tx: &Transaction) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn remove_mempool_tx(&self, tx_hash: &str) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_mempool_txs(&self) -> std::io::Result<Vec<Transaction>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_checkpoint(&self, checkpoint: &Checkpoint) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_checkpoints(&self) -> std::io::Result<Vec<Checkpoint>>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn save_seen_block(&self, header: &BlockHeader, sig: &[u8]) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_all_seen_blocks(&self) -> std::io::Result<SeenBlockMap>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn flush_batch(&self) -> std::io::Result<usize>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn commit_durable_batch(&self, batch: &DurableCommitBatch) -> std::io::Result<()>;
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DurableCommitBatch {
    pub block: Block,
    pub state_root: String,
    pub finality_cert: Option<FinalityCert>,
    pub global_headers: Vec<GlobalBlockHeader>,
    pub bridge_state: Option<BridgeState>,
    pub accounts: Vec<(Address, Account)>,
}
