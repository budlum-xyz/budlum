//! A funded chain that applies signed door transactions in produced blocks
//! and restarts from its own storage.
//!
//! Consensus state changes only inside a block (K4). A
//! restart rebuilds the state by replaying the stored blocks over the genesis
//! state, so a write made outside a block - a test shim, an operator call -
//! does not survive it, and a restart test that wants to see something
//! survive has to write it through a block. This harness does that: one
//! funded sender, its key, and the same genesis on every reopen.

use crate::chain::blockchain::Blockchain;
use crate::chain::genesis::GenesisConfig;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::crypto::primitives::KeyPair;
use crate::storage::db::Storage;
use std::sync::Arc;

/// The chain id every harness runs on (the devnet id the restart tests use).
pub const CHAIN_ID: u64 = 45262;
/// The sender's genesis allocation.
pub const FUNDS: u64 = 100_000_000;
/// The fee every harness transaction pays. Mempool admission needs at least 1.
pub const FEE: u64 = 1_000;

/// A chain on disk whose genesis funds one sender.
pub struct BlockHarness {
    pub chain: Blockchain,
    pub key: KeyPair,
    pub sender: Address,
    path: String,
}

fn genesis(sender: Address) -> GenesisConfig {
    let mut genesis = GenesisConfig::new(CHAIN_ID).with_allocation(sender, FUNDS);
    genesis.base_fee = 0;
    genesis
}

impl BlockHarness {
    /// Open a fresh chain at `path` with a new funded sender.
    pub fn open(path: &str) -> Self {
        let key = KeyPair::generate().expect("a key pair generates");
        let sender = Address::from(key.public_key_bytes());
        Self::reopen(path, key, sender)
    }

    fn reopen(path: &str, key: KeyPair, sender: Address) -> Self {
        let storage = Storage::new(path).expect("the store opens");
        let chain = Blockchain::new_with_genesis(
            Arc::new(PoWEngine::new(0)),
            Some(storage),
            CHAIN_ID,
            None,
            Some(genesis(sender)),
        );
        Self {
            chain,
            key,
            sender,
            path: path.to_string(),
        }
    }

    /// Sign `tx_type` from the funded sender, put it in the mempool and
    /// produce one block. Returns the produced block's height.
    ///
    /// # Panics
    ///
    /// When the mempool refuses the transaction, no block is produced, or the
    /// block does not carry the transaction (its door refused it).
    pub fn apply(&mut self, tx_type: TransactionType) -> u64 {
        let nonce = self.chain.state.get_nonce(&self.sender);
        let mut tx = Transaction::new_with_chain_id(
            self.sender,
            Address::zero(),
            0,
            FEE,
            nonce,
            Vec::new(),
            CHAIN_ID,
            tx_type,
        );
        tx.sign(&self.key);
        let hash = tx.hash.clone();
        self.chain
            .add_transaction(tx)
            .expect("the mempool admits the door transaction");
        let (block, _) = self
            .chain
            .produce_block(Address::zero())
            .expect("a block is produced");
        assert!(
            block.transactions.iter().any(|t| t.hash == hash),
            "the block must carry the door transaction (its door refused it)"
        );
        block.index
    }

    /// Close the chain and reopen it from the same store with the same
    /// genesis: the state is rebuilt by replaying the stored blocks.
    #[must_use]
    pub fn restart(self) -> Self {
        let Self {
            chain,
            key,
            sender,
            path,
        } = self;
        drop(chain);
        Self::reopen(&path, key, sender)
    }

    /// A PoW domain operated by the harness sender, ready to register.
    pub fn operated_domain(&self, id: crate::domain::DomainId) -> crate::domain::ConsensusDomain {
        let mut domain = crate::domain::plugin::default_domain(
            id,
            crate::domain::ConsensusKind::PoW,
            CHAIN_ID + u64::from(id),
            crate::domain::types::POW_HEADER_CHAIN_ADAPTER,
            0,
        );
        domain.operator = Some(self.sender);
        domain
    }
}
