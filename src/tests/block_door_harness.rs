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

    /// A PoW domain operated by the harness sender, ready for a
    /// `SettlementTx::RegisterDomain`.
    pub fn operated_domain(&self, id: crate::domain::DomainId) -> crate::domain::ConsensusDomain {
        self.operated_domain_of_kind(id, crate::domain::ConsensusKind::PoW)
    }

    /// A domain of `kind` operated by the harness sender.
    pub fn operated_domain_of_kind(
        &self,
        id: crate::domain::DomainId,
        kind: crate::domain::ConsensusKind,
    ) -> crate::domain::ConsensusDomain {
        let adapter = match kind {
            crate::domain::ConsensusKind::PoW => crate::domain::types::POW_HEADER_CHAIN_ADAPTER,
            crate::domain::ConsensusKind::PoS => "pos-qc-finality",
            _ => "poa-authority-quorum",
        };
        let mut domain =
            crate::domain::plugin::default_domain(id, kind, CHAIN_ID + u64::from(id), adapter, 0);
        domain.operator = Some(self.sender);
        domain
    }

    /// Register `domain` through a block.
    pub fn register_domain(&mut self, domain: crate::domain::ConsensusDomain) -> u64 {
        self.apply(TransactionType::Settlement(
            crate::settlement::domains::SettlementTx::RegisterDomain(Box::new(domain)),
        ))
    }

    /// Register two domains the sender operates (1, PoW, and 2, PoS) and
    /// `asset_id` against domain 1, then lock `amount` of the sender's
    /// balance toward `recipient` on domain 2. Each write is its own block.
    pub fn lock_through_blocks(
        &mut self,
        asset_id: crate::cross_domain::AssetId,
        recipient: Address,
        amount: u64,
    ) {
        use crate::cross_domain::bridge_tx::{BridgeTx, LockRequest};
        let source = self.operated_domain(1);
        let target = self.operated_domain_of_kind(2, crate::domain::ConsensusKind::PoS);
        self.register_domain(source);
        self.register_domain(target);
        self.apply(TransactionType::Bridge(BridgeTx::RegisterAsset {
            asset_id,
            domain: 1,
        }));
        self.apply(TransactionType::Bridge(BridgeTx::Lock(LockRequest {
            source_domain: 1,
            target_domain: 2,
            source_height: 10,
            event_index: 0,
            asset_id,
            recipient,
            amount,
            expiry_height: 1_000,
        })));
    }
}
