use crate::chain::finality::FinalityCert;
use crate::consensus::pos::Checkpoint;
use crate::consensus::qc::QcBlob;
use crate::core::account::Account;
use crate::core::address::Address;
use crate::core::block::{Block, BlockHeader};
use crate::core::transaction::Transaction;
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
    fn save_quarantine_ledger(
        &self,
        ledger: &crate::registry::QuarantineLedger,
    ) -> std::io::Result<()>;
    /// # Errors
    ///
    /// Propagates `std::io::Error` from the step that failed; its variants name the refused
    /// conditions.
    fn load_quarantine_ledger(&self) -> std::io::Result<Option<crate::registry::QuarantineLedger>>;
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
    pub accounts: Vec<(Address, Account)>,
}
