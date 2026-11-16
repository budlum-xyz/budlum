//! The aggregation side of a node.
//!
//! An [`Aggregator`] knows objects, claims and frames. A node also has to
//! know the transactions the claims stand for: a block that carries a frame
//! must carry every transaction that uses one of its claims, and those
//! transactions have no witness left, so the mempool cannot hold them. They
//! live here, next to the pool, from the moment their object was verified
//! until a block carries them or they can no longer run.
//!
//! The chain reaches this through `Blockchain`: `agg/object` lands in
//! [`AggNode::admit`], `agg/frame` in [`AggNode::on_frame`], the tick timer
//! in [`AggNode::on_tick`], the block producer asks [`AggNode::block_input`]
//! and every committed block reports through [`AggNode::on_block`].
//!
//! An object travels with its transaction. The directive lists the envelope
//! alone on `agg/object`; a transaction without a witness that arrives on
//! its own cannot be told from a forgery, and a store of unauthenticated
//! transactions is free to fill for anyone. Carried together, the native
//! check of the object is also the check of the transaction.

use std::collections::{BTreeMap, BTreeSet};

use super::aggregator::{Aggregator, TickOutcome};
use super::backend::{AggError, TickCtx};
use super::chain::{account_claim, claim_domain, ChainBackend};
use super::envelope::Envelope;
use super::frame::ClaimFrame;
use super::params::{AggMode, AggParams};
use super::pool::{Admission, Rejection, TxFacts, TxLookup};
use crate::core::address::Address;
use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::domain::types::{DomainId, Hash32};

/// Claimed transactions a node holds at most. Each is a few hundred bytes;
/// past this a new object is turned away until blocks drain the store.
const MAX_PENDING_TRANSACTIONS: usize = 65_536;

/// Why an object and its transaction were not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectRefusal {
    /// This node runs no aggregator.
    NoAggregator,
    /// The bytes are not an envelope.
    Malformed(String),
    /// The transaction cannot run on the state of this node: wrong chain,
    /// nonce, balance, fee or type.
    Transaction(String),
    /// Another pending transaction of the sender holds the nonce.
    NonceHeld,
    /// The transaction is not the claimed form its object stands for: a
    /// witness left on it, another id, another claim than the account rule
    /// asks for.
    NotTheClaimedForm,
    /// The store of claimed transactions is full.
    StoreFull,
    /// An admission rule of the object pool.
    Pool(Rejection),
}

impl ObjectRefusal {
    /// Whether the peer that sent the object broke a rule it could have
    /// checked itself.
    #[must_use]
    pub const fn blames_peer(&self) -> bool {
        match self {
            Self::NotTheClaimedForm | Self::Malformed(_) => true,
            // A transaction that cannot run here may be a race with a block
            // the sender has not seen; a full store and a held nonce are
            // this node's own state.
            Self::NoAggregator | Self::Transaction(_) | Self::NonceHeld | Self::StoreFull => false,
            Self::Pool(rejection) => rejection.blames_peer(),
        }
    }
}

impl std::fmt::Display for ObjectRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotTheClaimedForm => {
                write!(f, "the transaction is not the claimed form of its object")
            }
            Self::NoAggregator => write!(f, "this node runs no aggregator"),
            Self::Malformed(reason) => write!(f, "the object is malformed: {reason}"),
            Self::Transaction(reason) => write!(f, "the transaction cannot run: {reason}"),
            Self::NonceHeld => {
                write!(
                    f,
                    "another pending transaction of the sender holds the nonce"
                )
            }
            Self::StoreFull => write!(f, "the store of claimed transactions is full"),
            Self::Pool(rejection) => write!(f, "{rejection}"),
        }
    }
}

impl std::error::Error for ObjectRefusal {}

/// The pending transactions as the object pool sees them, with the one that
/// is being admitted.
struct Lookup<'a> {
    held: &'a BTreeMap<Hash32, Transaction>,
    incoming: Option<(Hash32, &'a Transaction)>,
}

impl TxLookup for Lookup<'_> {
    fn tx_facts(&self, tx_hash: &Hash32) -> Option<TxFacts> {
        let tx = match self.incoming {
            Some((hash, tx)) if hash == *tx_hash => Some(tx),
            _ => self.held.get(tx_hash),
        }?;
        Some(TxFacts {
            from: tx.from,
            fee: tx.fee,
        })
    }
}

/// The aggregator of a node and the claimed transactions it holds.
#[derive(Debug)]
pub struct AggNode {
    domain: DomainId,
    aggregator: Aggregator<ChainBackend>,
    /// Claimed transactions whose object was verified, by signing hash.
    transactions: BTreeMap<Hash32, Transaction>,
    /// The same transactions by sender and nonce.
    by_sender: BTreeMap<Address, BTreeMap<u64, Hash32>>,
}

impl AggNode {
    /// The aggregation side of a node on the chain `chain_id`, proving for
    /// `aggregator`. `None` unless the layer is on and the chain has a claim
    /// domain: under `Off` and `Shadow` no frame is published.
    #[must_use]
    pub fn new(
        params: &AggParams,
        chain_id: u64,
        aggregator: Address,
        registry: &SchemeStatusRegistry,
    ) -> Option<Self> {
        if params.mode != AggMode::On {
            return None;
        }
        let domain = claim_domain(chain_id)?;
        let ctx = TickCtx { domain, aggregator };
        Some(Self {
            domain,
            aggregator: Aggregator::new(ChainBackend::new(params, registry), ctx, *params),
            transactions: BTreeMap::new(),
            by_sender: BTreeMap::new(),
        })
    }

    /// Whether the node holds the claimed transaction with this signing
    /// hash.
    #[must_use]
    pub fn holds(&self, tx_hash: &Hash32) -> bool {
        self.transactions.contains_key(tx_hash)
    }

    /// What the pending transactions of `sender` add to its account, seen
    /// from the nonce `next` of the state: the nonce after the unbroken run
    /// of pending transactions that starts there, and what that run spends.
    /// A transaction past a gap does not count: it cannot run yet.
    #[must_use]
    pub fn projected(&self, sender: &Address, next: u64) -> (u64, u64) {
        let mut nonce = next;
        let mut spent = 0u64;
        let Some(pending) = self.by_sender.get(sender) else {
            return (nonce, spent);
        };
        while let Some(tx) = pending
            .get(&nonce)
            .and_then(|hash| self.transactions.get(hash))
        {
            spent = spent.saturating_add(tx.amount).saturating_add(tx.fee);
            nonce = nonce.saturating_add(1);
        }
        (nonce, spent)
    }

    /// Whether `tx` is the claimed form the object of `envelope` stands
    /// for: no witness left on it, the id of the envelope, and the claim
    /// the account rule asks for. It costs three hashes, so it runs before
    /// anything is read from the state or verified.
    ///
    /// # Errors
    ///
    /// [`ObjectRefusal::NotTheClaimedForm`].
    pub fn check_form(&self, envelope: &Envelope, tx: &Transaction) -> Result<(), ObjectRefusal> {
        let digest = account_claim(tx).map(|claim| claim.digest(self.domain));
        if envelope.tx_hash != tx.signing_hash()
            || !tx.claimed_shape_is_canonical()
            || digest.is_none()
            || tx.auth_claim != digest
        {
            return Err(ObjectRefusal::NotTheClaimedForm);
        }
        Ok(())
    }

    /// An object arrived with the transaction it authorizes.
    ///
    /// The caller checked the transaction against the state (nonce, balance,
    /// type) as a claimed one; this checks that it is the claimed form of
    /// the object and runs the admission rules, native verification last.
    /// Returns whether the pair is new.
    ///
    /// # Errors
    ///
    /// The [`ObjectRefusal`] that turned the pair away. Nothing is kept.
    pub fn admit(
        &mut self,
        envelope: Envelope,
        tx: Transaction,
        registry: &SchemeStatusRegistry,
    ) -> Result<bool, ObjectRefusal> {
        self.check_form(&envelope, &tx)?;
        let tx_hash = tx.signing_hash();
        if self.transactions.contains_key(&tx_hash) {
            return Ok(false);
        }
        if self
            .by_sender
            .get(&tx.from)
            .is_some_and(|pending| pending.contains_key(&tx.nonce))
        {
            // Only one of the two can ever run, and a frame that carried
            // both claims could never go into a block.
            return Err(ObjectRefusal::NonceHeld);
        }
        if self.transactions.len() >= MAX_PENDING_TRANSACTIONS {
            return Err(ObjectRefusal::StoreFull);
        }
        let lookup = Lookup {
            held: &self.transactions,
            incoming: Some((tx_hash, &tx)),
        };
        match self.aggregator.on_object(envelope, &lookup, registry) {
            Ok(Admission::Accepted(_)) => {
                self.by_sender
                    .entry(tx.from)
                    .or_default()
                    .insert(tx.nonce, tx_hash);
                self.transactions.insert(tx_hash, tx);
                Ok(true)
            }
            // The transaction came with the object, so the pool never waits
            // for it; a pool that knows the object or the claim already has
            // nothing new to learn.
            Ok(Admission::Waiting(_)) | Err(Rejection::Duplicate | Rejection::ClaimKnown) => {
                Ok(false)
            }
            Err(rejection) => Err(ObjectRefusal::Pool(rejection)),
        }
    }

    /// A frame arrived on `agg/frame`. Returns whether it is new.
    ///
    /// # Errors
    ///
    /// [`AggError`] when the frame is not valid; it is dropped.
    pub fn on_frame(&mut self, frame: ClaimFrame) -> Result<bool, AggError> {
        self.aggregator.on_frame(frame)
    }

    /// One tick of the aggregator: the frames to publish on `agg/frame`.
    pub fn on_tick(&mut self, registry: &SchemeStatusRegistry) -> TickOutcome {
        let lookup = Lookup {
            held: &self.transactions,
            incoming: None,
        };
        self.aggregator.on_tick(&lookup, registry)
    }

    /// The frame of the next block and the transactions that use its
    /// claims, each sender's in nonce order (block producer, steps 1 to 4).
    /// `None` when no frame is ready whose transactions are all here.
    #[must_use]
    pub fn block_input(&self) -> Option<(ClaimFrame, Vec<Transaction>)> {
        let usable: BTreeSet<Hash32> = self
            .transactions
            .values()
            .filter_map(|tx| tx.auth_claim)
            .collect();
        let frame = self.aggregator.block_frame(&usable)?;
        let wanted: BTreeSet<Hash32> = frame
            .claims
            .iter()
            .map(|claim| claim.digest(self.domain))
            .collect();
        let mut transactions: Vec<Transaction> = self
            .transactions
            .values()
            .filter(|tx| tx.auth_claim.is_some_and(|digest| wanted.contains(&digest)))
            .cloned()
            .collect();
        transactions.sort_by_key(|tx| (tx.from, tx.nonce));
        Some((frame, transactions))
    }

    /// Forget a transaction that can no longer run. A frame that carries
    /// its claim is not chosen for a block again.
    pub fn drop_transaction(&mut self, tx_hash: &Hash32) {
        if let Some(tx) = self.transactions.remove(tx_hash) {
            if let Some(pending) = self.by_sender.get_mut(&tx.from) {
                pending.remove(&tx.nonce);
                if pending.is_empty() {
                    self.by_sender.remove(&tx.from);
                }
            }
        }
    }

    /// Forget a frame that cannot go into a block as it is: over the block
    /// rules, or too large for a block next to its transactions. Smaller
    /// frames over the same claims are chosen from then on.
    pub fn drop_frame(&mut self, frame: &ClaimFrame) {
        self.aggregator.forget_frame(frame);
    }

    /// A block was committed. The frame it carried is done: its claims
    /// leave the pool and every frame that shares a claim with it is
    /// dropped. Every pending transaction `spent` names (its nonce is
    /// behind the state now) is forgotten.
    pub fn on_block(&mut self, block: &Block, spent: impl Fn(&Transaction) -> bool) {
        if let Some(frame) = block.claim_frame.as_ref() {
            self.aggregator.on_final(frame);
        }
        let gone: Vec<Hash32> = self
            .transactions
            .iter()
            .filter(|(_, tx)| spent(tx))
            .map(|(hash, _)| *hash)
            .collect();
        for hash in &gone {
            self.drop_transaction(hash);
        }
    }
}
