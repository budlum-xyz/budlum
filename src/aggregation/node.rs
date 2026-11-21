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
//!
//! WIRING: [`AggNode::check_form_for`], [`AggNode::admit_with_auth`], and
//! [`AggNode::attach_claim_ref`] serve Phase 4/5 program-auth and PCS companion
//! object admission once `Blockchain` opens `agg/claim_ref` gossip.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use super::aggregator::{Aggregator, TickOutcome};
use super::backend::{AggError, TickCtx};
use super::chain::{account_claim_for, claim_domain, ChainBackend};
use super::envelope::Envelope;
use super::frame::ClaimFrame;
use super::params::{AggMode, AggParams};
use super::pool::{Admission, Rejection, TxFacts, TxLookup};
use crate::core::address::Address;
use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::domain::types::{DomainId, Hash32};
use crate::mempool::pool::charged_bytes;

/// Claimed transactions a node holds at most. Past this (or
/// [`MAX_PENDING_TRANSACTION_BYTES`]), a new object is turned away until
/// blocks drain the store.
const MAX_PENDING_TRANSACTIONS: usize = 65_536;
/// Maximum resident bytes of claimed transactions held in `AggNode`, measured
/// via `mempool::pool::charged_bytes`. Bounds memory even when transactions
/// carry `MAX_TX_SIZE` (100 KiB) payloads.
const MAX_PENDING_TRANSACTION_BYTES: usize = 256 * 1024 * 1024;

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

/// Iterates every claim digest required by `tx` (`auth_claim` followed by `claim_refs`).
fn tx_required_claims(tx: &Transaction) -> impl Iterator<Item = Hash32> + '_ {
    tx.auth_claim
        .into_iter()
        .chain(tx.claim_refs.iter().copied())
}

/// Returns `true` iff `tx.claim_refs` has no duplicates and does not repeat `auth_claim`.
fn claim_refs_are_distinct(tx: &Transaction) -> bool {
    let mut seen = BTreeSet::new();
    if let Some(auth) = tx.auth_claim {
        seen.insert(auth);
    }
    tx.claim_refs.iter().all(|digest| seen.insert(*digest))
}

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

    fn accepts_claim(&self, tx_hash: &Hash32, claim_digest: &Hash32) -> bool {
        if let Some((hash, tx)) = self.incoming {
            if hash == *tx_hash {
                return tx.auth_claim == Some(*claim_digest);
            }
        }
        self.held.get(tx_hash).is_some_and(|tx| {
            tx.auth_claim == Some(*claim_digest) || tx.claim_refs.contains(claim_digest)
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
    /// Total encoded protobuf bytes of `transactions`.
    pending_bytes: usize,
    /// Maximum `pending_bytes` allowed before pruning / refusing with `StoreFull`.
    max_pending_bytes: usize,
    /// The same transactions by sender and nonce.
    by_sender: BTreeMap<Address, BTreeMap<u64, Hash32>>,
}

impl AggNode {
    /// The aggregation side of a node on the chain `chain_id`, proving with
    /// the keypair derived from `signer_seed`. `None` unless the layer is on,
    /// the chain has a claim domain, and `signer_seed` derives a valid keypair.
    #[must_use]
    pub fn new(
        params: &AggParams,
        chain_id: u64,
        signer_seed: Zeroizing<[u8; 32]>,
        registry: &SchemeStatusRegistry,
    ) -> Option<Self> {
        if params.mode != AggMode::On {
            return None;
        }
        let domain = claim_domain(chain_id)?;
        let ctx = TickCtx::from_seed(domain, signer_seed).ok()?;
        Some(Self {
            domain,
            aggregator: Aggregator::new(ChainBackend::new(params, registry), ctx, *params),
            transactions: BTreeMap::new(),
            pending_bytes: 0,
            max_pending_bytes: MAX_PENDING_TRANSACTION_BYTES,
            by_sender: BTreeMap::new(),
        })
    }

    /// Address derived from the active aggregator signing seed.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn aggregator_address(&self) -> Address {
        self.aggregator.ctx().aggregator
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
        self.check_form_for(envelope, tx, None)
    }

    /// Form check supporting both standard V5 signature accounts (`None`) and
    /// Phase 4 `BudZKVM` program-authorized accounts (`Some(program_hash)`),
    /// plus duplicate-free `tx.claim_refs` validation.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectRefusal::NotTheClaimedForm`] if `envelope.tx_hash`,
    /// canonical claimed shape, `auth_claim`, or distinct `claim_refs` fail.
    pub fn check_form_for(
        &self,
        envelope: &Envelope,
        tx: &Transaction,
        auth_program_hash: Option<Hash32>,
    ) -> Result<(), ObjectRefusal> {
        let digest =
            account_claim_for(tx, auth_program_hash).map(|claim| claim.digest(self.domain));
        if envelope.tx_hash != tx.signing_hash()
            || !tx.claimed_shape_is_canonical()
            || digest.is_none()
            || tx.auth_claim != digest
            || !claim_refs_are_distinct(tx)
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
        self.admit_with_auth(envelope, tx, None, registry)
    }

    /// Admits a claimed transaction and its primary authorization envelope for
    /// either a V5 signature account (`None`) or a Phase 4 `BudZKVM` program
    /// account (`Some(program_hash)`).
    ///
    /// # Errors
    ///
    /// Returns [`ObjectRefusal`] if form checks, nonce uniqueness, pending store
    /// bounds, claim-digest binding, or pool verification fail.
    pub fn admit_with_auth(
        &mut self,
        envelope: Envelope,
        tx: Transaction,
        auth_program_hash: Option<Hash32>,
        registry: &SchemeStatusRegistry,
    ) -> Result<bool, ObjectRefusal> {
        self.check_form_for(&envelope, &tx, auth_program_hash)?;
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
        let tx_bytes = charged_bytes(&tx);
        if self.transactions.len() >= MAX_PENDING_TRANSACTIONS
            || self.pending_bytes.saturating_add(tx_bytes) > self.max_pending_bytes
        {
            self.prune_orphans();
            if self.transactions.len() >= MAX_PENDING_TRANSACTIONS
                || self.pending_bytes.saturating_add(tx_bytes) > self.max_pending_bytes
            {
                return Err(ObjectRefusal::StoreFull);
            }
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
                self.pending_bytes = self.pending_bytes.saturating_add(tx_bytes);
                self.transactions.insert(tx_hash, tx);
                // Reap any transactions whose ready pool objects were just
                // evicted to make room in `ObjectPool::admit`.
                self.prune_orphans();
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

    /// Admits a companion Phase 4/5 object (`StarkProof` / `PcsOpening`) whose
    /// derived claim digest is explicitly listed in `tx.claim_refs` of an
    /// already-admitted pending transaction. Uninvited objects are rejected and
    /// blamed (`Rejection::NotTheSender`).
    ///
    /// Convenience: kept for the CLI and Phase 5 `agg/claim_ref` gossip admission.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectRefusal::NotTheClaimedForm`] if `envelope.tx_hash` is not
    /// held or carries no `claim_refs`, or [`ObjectRefusal::Pool`] if pool
    /// verification or claim-digest binding rejects the object.
    pub fn attach_claim_ref(
        &mut self,
        envelope: Envelope,
        registry: &SchemeStatusRegistry,
    ) -> Result<bool, ObjectRefusal> {
        let Some(tx) = self.transactions.get(&envelope.tx_hash) else {
            return Err(ObjectRefusal::NotTheClaimedForm);
        };
        if tx.claim_refs.is_empty() {
            return Err(ObjectRefusal::NotTheClaimedForm);
        }
        let lookup = Lookup {
            held: &self.transactions,
            incoming: None,
        };
        match self.aggregator.on_object(envelope, &lookup, registry) {
            Ok(Admission::Accepted(_)) => {
                self.prune_orphans();
                Ok(true)
            }
            Ok(Admission::Waiting(_)) | Err(Rejection::Duplicate | Rejection::ClaimKnown) => {
                Ok(false)
            }
            Err(rejection) => Err(ObjectRefusal::Pool(rejection)),
        }
    }

    /// A frame arrived on `agg/frame`. Drops (ignores) frames whose claims
    /// do not match transactions currently held by this node before running
    /// expensive ML-DSA-87 verification; returns whether the frame is new.
    ///
    /// # Errors
    ///
    /// [`AggError`] when a frame whose claims are held here fails
    /// validation or proof/attestation verification.
    pub fn on_frame(
        &mut self,
        frame: ClaimFrame,
        registry: &SchemeStatusRegistry,
    ) -> Result<bool, AggError> {
        let usable: BTreeSet<Hash32> = self
            .transactions
            .values()
            .flat_map(tx_required_claims)
            .collect();
        if !frame
            .claims
            .iter()
            .all(|claim| usable.contains(&claim.digest(self.domain)))
        {
            return Ok(false);
        }
        self.aggregator.on_frame(frame, registry)
    }

    /// One tick of the aggregator: the frames to publish on `agg/frame`.
    pub fn on_tick(&mut self, registry: &SchemeStatusRegistry) -> TickOutcome {
        let lookup = Lookup {
            held: &self.transactions,
            incoming: None,
        };
        let outcome = self.aggregator.on_tick(&lookup, registry);
        self.prune_orphans();
        outcome
    }

    /// The frame of the next block and the transactions that use its
    /// claims, each sender's in nonce order (block producer, steps 1 to 4).
    /// `None` when no frame is ready whose transactions are all here.
    #[must_use]
    pub fn block_input(&self) -> Option<(ClaimFrame, Vec<Transaction>)> {
        // Expose a transaction's claims only once EVERY claim it requires
        // (`auth_claim` plus all `claim_refs`) is already proven in a stored
        // frame, preventing partial selection from violating block Rules 7/8.
        let usable: BTreeSet<Hash32> = self
            .transactions
            .values()
            .filter(|tx| {
                tx.is_claimed()
                    && tx_required_claims(tx).all(|digest| self.aggregator.tracks_claim(&digest))
            })
            .flat_map(tx_required_claims)
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
            .filter(|tx| {
                tx.is_claimed() && tx_required_claims(tx).all(|digest| wanted.contains(&digest))
            })
            .cloned()
            .collect();
        let covered: BTreeSet<Hash32> = transactions.iter().flat_map(tx_required_claims).collect();
        if covered.len() != wanted.len() || !wanted.iter().all(|d| covered.contains(d)) {
            return None;
        }
        transactions.sort_by_key(|tx| (tx.from, tx.nonce));
        Some((frame, transactions))
    }

    /// Forget a transaction that can no longer run. Its claims leave the
    /// object pool and any frame that carries them is dropped so stale frames
    /// cannot linger or poison later merges.
    pub fn drop_transaction(&mut self, tx_hash: &Hash32) {
        if let Some(tx) = self.transactions.remove(tx_hash) {
            self.pending_bytes = self.pending_bytes.saturating_sub(charged_bytes(&tx));
            if let Some(pending) = self.by_sender.get_mut(&tx.from) {
                pending.remove(&tx.nonce);
                if pending.is_empty() {
                    self.by_sender.remove(&tx.from);
                }
            }
            for digest in tx_required_claims(&tx) {
                let still_referenced = self
                    .transactions
                    .values()
                    .any(|other| tx_required_claims(other).any(|d| d == digest));
                if !still_referenced {
                    self.aggregator.forget_claim(&digest);
                }
            }
        }
    }

    /// Remove any held transaction whose primary claim is neither tracked by
    /// the object pool (ready or proven) nor covered by any retained frame.
    fn prune_orphans(&mut self) {
        let orphans: Vec<Hash32> = self
            .transactions
            .iter()
            .filter_map(|(hash, tx)| {
                let is_tracked = |digest: &Hash32| {
                    self.aggregator.pool().tracks_claim(digest)
                        || self.aggregator.tracks_claim(digest)
                };
                let orphaned = tx.auth_claim.map_or_else(
                    || !tx.claim_refs.iter().any(is_tracked),
                    |digest| !is_tracked(&digest),
                );
                orphaned.then_some(*hash)
            })
            .collect();
        for hash in orphans {
            self.drop_transaction(&hash);
        }
    }

    /// Forget a frame that cannot go into a block as it is: over the block
    /// rules, or too large for a block next to its transactions. Smaller
    /// frames over the same claims are chosen from then on.
    pub fn drop_frame(&mut self, frame: &ClaimFrame) {
        self.aggregator.forget_frame(frame);
        self.prune_orphans();
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
        self.prune_orphans();
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "wallet-ml-dsa")]
    mod pending_store {
        use super::super::*;
        use crate::aggregation::chain::claim_signature;

        fn sample_node(params: AggParams) -> AggNode {
            AggNode::new(
                &params,
                45_262,
                Zeroizing::new([0xA6; 32]),
                &SchemeStatusRegistry::genesis(),
            )
            .expect("aggregation enabled")
        }

        #[test]
        fn pending_byte_limit_enforces_store_full_and_orphan_pruning_reclaims_space() {
            let registry = SchemeStatusRegistry::genesis();
            let params = AggParams {
                mode: AggMode::On,
                ..AggParams::default()
            };
            let mut node = sample_node(params);
            let recipient = Address::from([0x44; 32]);
            let sender_a = crate::crypto::primitives::WalletKeyPair::from_seed(&[1u8; 32]);
            let sender_b = crate::crypto::primitives::WalletKeyPair::from_seed(&[2u8; 32]);

            let mut tx_a = Transaction::new_with_fee(
                sender_a.address(),
                recipient,
                10,
                100_000,
                0,
                vec![0xAB; 2048],
            );
            tx_a.chain_id = 45_262;
            tx_a.sign_v5(&sender_a);
            let (claimed_a, env_a) = claim_signature(&tx_a).expect("v5 claim");
            let bytes_a = charged_bytes(&claimed_a);

            let mut tx_b = Transaction::new_with_fee(
                sender_b.address(),
                recipient,
                10,
                100_000,
                0,
                vec![0xCD; 2048],
            );
            tx_b.chain_id = 45_262;
            tx_b.sign_v5(&sender_b);
            let (claimed_b, env_b) = claim_signature(&tx_b).expect("v5 claim");

            node.max_pending_bytes = bytes_a + 10;
            assert_eq!(
                node.aggregator_address(),
                crate::aggregation::frame::aggregator_address_from_seed(&[0xA6; 32])
                    .expect("valid seed")
            );
            assert_eq!(
                node.admit(env_a.clone(), claimed_a.clone(), &registry),
                Ok(true)
            );
            assert_eq!(node.pending_bytes, bytes_a);
            assert_eq!(
                node.admit(env_b.clone(), claimed_b.clone(), &registry),
                Err(ObjectRefusal::StoreFull)
            );

            // Removing the object from the pool leaves `claimed_a` as an orphan;
            // `prune_orphans` reclaims its bytes so `claimed_b` can enter.
            if let Some(digest_a) = claimed_a.auth_claim {
                node.aggregator.forget_claim(&digest_a);
            }
            assert_eq!(node.admit(env_b, claimed_b.clone(), &registry), Ok(true));
            assert!(!node.holds(&claimed_a.signing_hash()));
            assert!(node.holds(&claimed_b.signing_hash()));
            assert_eq!(node.pending_bytes, charged_bytes(&claimed_b));
        }

        #[test]
        fn pool_eviction_during_admit_prunes_orphaned_transaction() {
            let registry = SchemeStatusRegistry::genesis();
            let params = AggParams {
                mode: AggMode::On,
                pool_max_bytes: 8_000, // holds one 7.2 KB envelope at a time
                ..AggParams::default()
            };
            let mut node = sample_node(params);
            let recipient = Address::from([0x44; 32]);
            let sender_low = crate::crypto::primitives::WalletKeyPair::from_seed(&[3u8; 32]);
            let sender_high = crate::crypto::primitives::WalletKeyPair::from_seed(&[4u8; 32]);

            let mut tx_low =
                Transaction::new_with_fee(sender_low.address(), recipient, 10, 10_000, 0, vec![]);
            tx_low.chain_id = 45_262;
            tx_low.sign_v5(&sender_low);
            let (claimed_low, env_low) = claim_signature(&tx_low).expect("v5 claim");

            let mut tx_high =
                Transaction::new_with_fee(sender_high.address(), recipient, 10, 50_000, 0, vec![]);
            tx_high.chain_id = 45_262;
            tx_high.sign_v5(&sender_high);
            let (claimed_high, env_high) = claim_signature(&tx_high).expect("v5 claim");

            assert_eq!(
                node.admit(env_low, claimed_low.clone(), &registry),
                Ok(true)
            );
            assert_eq!(
                node.admit(env_high, claimed_high.clone(), &registry),
                Ok(true)
            );
            assert!(!node.holds(&claimed_low.signing_hash()));
            assert!(node.holds(&claimed_high.signing_hash()));
            assert_eq!(node.pending_bytes, charged_bytes(&claimed_high));
        }
    }
}
