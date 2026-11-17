//! The object pool of an aggregator: heavy objects waiting to be proven.
//!
//! The pool holds only objects that passed the admission rules. An object
//! that breaks a rule is dropped, and the caller learns whether the sending
//! peer is to blame.
//!
//! WIRING: the `agg/object` handler fills a [`TxFacts`] from the mempool and
//! reads [`Rejection::blames_peer`] to decide the peer penalty; the node
//! metrics read [`ObjectPool::ready_len`] and [`ObjectPool::waiting_len`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::claim::Claim;
use super::envelope::Envelope;
use super::fees::claim_fee;
use super::object::{derive_claim, max_payload_bytes, ObjectError};
use super::params::AggParams;
use crate::core::address::Address;
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::domain::types::{DomainId, Hash32};

/// Ticks an object waits for a transaction the node has not seen yet.
const MAX_WAIT_TICKS: u8 = 2;
/// Ticks in a row an object may fail to prove before it is dropped.
const MAX_PROVE_FAILURES: u8 = 2;
/// Object ids the pool remembers, so an object it has judged is not judged
/// again. The oldest id is forgotten first.
const SEEN_CAPACITY: usize = 262_144;
/// Proven claim digests the pool remembers before evicting the oldest entry.
const PROVEN_CLAIMS_CAPACITY: usize = SEEN_CAPACITY;

/// A heavy object with the claim it stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolItem {
    /// The object. Its payload is emptied once the object is proven.
    pub envelope: Envelope,
    /// The claim, derived at admission.
    pub claim: Claim,
}

/// What the pool needs to know about a transaction of the mempool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxFacts {
    /// The sender.
    pub from: Address,
    /// The fee the transaction offers.
    pub fee: u64,
}

/// The view of the mempool the pool admits against.
pub trait TxLookup {
    /// The facts of a valid pending transaction, by its hash.
    fn tx_facts(&self, tx_hash: &Hash32) -> Option<TxFacts>;
}

/// What happened to a submitted object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The object is in the pool, under this object id.
    Accepted(Hash32),
    /// The transaction is not known yet; the object waits for it.
    Waiting(Hash32),
}

/// Why an object was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The envelope is for another domain than this pool.
    WrongDomain,
    /// Admission rules 1, 2 and 4: size, scheme, native verification.
    Object(ObjectError),
    /// Admission rule 3: the fee of the transaction does not cover the claim.
    FeeTooLow,
    /// Admission rule 3: the object stands for an account other than the
    /// sender of its transaction.
    NotTheSender,
    /// Admission rule 5: the object was seen before.
    Duplicate,
    /// Another object already stands for the same claim.
    ClaimKnown,
    /// Admission rule 6: the sender is over its limit for this tick.
    SenderLimit,
    /// Admission rule 7: the pool is full and this object pays the least.
    PoolFull,
}

impl Rejection {
    /// Whether the peer that sent the object broke a rule it could have
    /// checked itself. The network layer penalizes the peer for these.
    #[must_use]
    pub const fn blames_peer(&self) -> bool {
        matches!(
            self,
            Self::WrongDomain | Self::Object(_) | Self::NotTheSender
        )
    }
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongDomain => write!(f, "the object is for another domain"),
            Self::Object(e) => write!(f, "{e}"),
            Self::FeeTooLow => write!(f, "the transaction fee does not cover the claim fee"),
            Self::NotTheSender => write!(f, "the object is not from the sender of its transaction"),
            Self::Duplicate => write!(f, "the object was seen before"),
            Self::ClaimKnown => write!(f, "another object stands for the same claim"),
            Self::SenderLimit => write!(f, "the sender is over its limit for this tick"),
            Self::PoolFull => write!(f, "the pool is full and the object pays the least"),
        }
    }
}

impl std::error::Error for Rejection {}

/// An admitted object that is not proven yet.
#[derive(Debug, Clone)]
struct Ready {
    item: PoolItem,
    digest: Hash32,
    fee: u64,
    bytes: usize,
    failures: u8,
}

/// An object whose transaction is not known yet. It is not verified.
#[derive(Debug, Clone)]
struct Waiting {
    envelope: Envelope,
    bytes: usize,
    ticks_left: u8,
}

/// State of a claim digest tracked by the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimEntry {
    /// Object is currently in `ready` waiting to be proven.
    Ready(Hash32),
    /// Object was proven; kept until finalized, abandoned, or evicted at
    /// `PROVEN_CLAIMS_CAPACITY`.
    Proven(Hash32),
}

/// The object pool of one domain.
#[derive(Debug)]
pub struct ObjectPool {
    params: AggParams,
    domain: DomainId,
    ready: BTreeMap<Hash32, Ready>,
    waiting: BTreeMap<Hash32, Waiting>,
    /// Claim digest to the object that stands for it (ready or proven).
    claims: BTreeMap<Hash32, ClaimEntry>,
    /// Insertion order of proven claim digests so `claims` stays bounded even
    /// when proven claims leave without finalizing.
    proven_order: VecDeque<Hash32>,
    seen: BTreeSet<Hash32>,
    seen_order: VecDeque<Hash32>,
    sender_counts: BTreeMap<Address, usize>,
    bytes: usize,
}

/// Whether `(fee_a, bytes_a)` pays less per byte than `(fee_b, bytes_b)`.
/// Compared by cross multiplication, so no ratio is rounded.
fn pays_less(fee_a: u64, bytes_a: usize, fee_b: u64, bytes_b: usize) -> bool {
    let wide = |fee: u64, bytes: usize| {
        u128::from(fee).saturating_mul(u128::try_from(bytes).unwrap_or(u128::MAX))
    };
    wide(fee_a, bytes_b) < wide(fee_b, bytes_a)
}

impl ObjectPool {
    /// An empty pool for `domain`.
    #[must_use]
    pub const fn new(params: AggParams, domain: DomainId) -> Self {
        Self {
            params,
            domain,
            ready: BTreeMap::new(),
            waiting: BTreeMap::new(),
            claims: BTreeMap::new(),
            proven_order: VecDeque::new(),
            seen: BTreeSet::new(),
            seen_order: VecDeque::new(),
            sender_counts: BTreeMap::new(),
            bytes: 0,
        }
    }

    /// Bytes of the envelopes the pool holds.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Objects ready to be proven.
    #[must_use]
    pub fn ready_len(&self) -> usize {
        self.ready.len()
    }

    /// Objects waiting for their transaction.
    #[must_use]
    pub fn waiting_len(&self) -> usize {
        self.waiting.len()
    }

    /// Whether this pool currently tracks `digest` as either ready or proven.
    #[must_use]
    pub fn tracks_claim(&self, digest: &Hash32) -> bool {
        self.claims.contains_key(digest)
    }

    fn remember(&mut self, object_id: Hash32) {
        if self.seen.insert(object_id) {
            self.seen_order.push_back(object_id);
            if self.seen_order.len() > SEEN_CAPACITY {
                if let Some(oldest) = self.seen_order.pop_front() {
                    self.seen.remove(&oldest);
                }
            }
        }
    }

    /// Apply the admission rules to a submitted object.
    ///
    /// The cheap rules run first and native verification runs last, so a
    /// flood of objects that are wrong on their face costs no signature
    /// check. Only an object that was accepted or that failed for good is
    /// remembered; one that was turned away for a limit may come back.
    ///
    /// # Errors
    ///
    /// The [`Rejection`] of the rule the object broke.
    pub fn admit(
        &mut self,
        envelope: Envelope,
        txs: &impl TxLookup,
        registry: &SchemeStatusRegistry,
    ) -> Result<Admission, Rejection> {
        if envelope.domain != self.domain {
            return Err(Rejection::WrongDomain);
        }
        // Rules 1 and 2.
        let limit = max_payload_bytes(&self.params, envelope.kind, envelope.scheme)
            .map_err(Rejection::Object)?;
        if envelope.payload.len() > limit {
            return Err(Rejection::Object(ObjectError::PayloadTooLarge(
                envelope.payload.len(),
            )));
        }
        // Rule 5.
        let object_id = envelope.object_id();
        if self.seen.contains(&object_id) || self.waiting.contains_key(&object_id) {
            return Err(Rejection::Duplicate);
        }
        // Rule 3: the transaction is known, or the object waits for it.
        let Some(tx) = txs.tx_facts(&envelope.tx_hash) else {
            let bytes = envelope.encode().len();
            let victims = self.plan_room(0, bytes)?;
            self.evict(&victims);
            self.bytes = self.bytes.saturating_add(bytes);
            self.waiting.insert(
                object_id,
                Waiting {
                    envelope,
                    bytes,
                    ticks_left: MAX_WAIT_TICKS,
                },
            );
            return Ok(Admission::Waiting(object_id));
        };
        self.admit_known(object_id, envelope, tx, registry)
            .map(|()| Admission::Accepted(object_id))
    }

    /// The rest of the admission rules, for an object whose transaction is
    /// known.
    fn admit_known(
        &mut self,
        object_id: Hash32,
        envelope: Envelope,
        tx: TxFacts,
        registry: &SchemeStatusRegistry,
    ) -> Result<(), Rejection> {
        // Rule 6.
        let used = self.sender_counts.get(&tx.from).copied().unwrap_or(0);
        if used >= self.params.sender_tick_limit {
            return Err(Rejection::SenderLimit);
        }
        // Rule 7, before the signature is checked: an object that pays too
        // little to enter a full pool costs no verification.
        let bytes = envelope.encode().len();
        let victims = self.plan_room(tx.fee, bytes)?;
        // Rule 4. An object that fails here fails forever: remember it.
        let claim = match derive_claim(registry, &envelope) {
            Ok(claim) => claim,
            Err(e) => {
                self.remember(object_id);
                return Err(Rejection::Object(e));
            }
        };
        if let Claim::Sig { signer, .. } = &claim {
            if *signer != tx.from {
                self.remember(object_id);
                return Err(Rejection::NotTheSender);
            }
        }
        // Rule 3: the fee covers the claim.
        if tx.fee < claim_fee(&self.params, &claim) {
            return Err(Rejection::FeeTooLow);
        }
        let digest = claim.digest(self.domain);
        if self.claims.contains_key(&digest) {
            self.remember(object_id);
            return Err(Rejection::ClaimKnown);
        }
        self.evict(&victims);
        self.bytes = self.bytes.saturating_add(bytes);
        self.remember(object_id);
        self.claims.insert(digest, ClaimEntry::Ready(object_id));
        self.sender_counts.insert(tx.from, used.saturating_add(1));
        self.ready.insert(
            object_id,
            Ready {
                item: PoolItem { envelope, claim },
                digest,
                fee: tx.fee,
                bytes,
                failures: 0,
            },
        );
        Ok(())
    }

    /// Plan the room for an object of `bytes` bytes that pays `fee`: the
    /// objects to drop so the pool stays within its budget, the ones that
    /// pay the least per byte first. A waiting object pays nothing and goes
    /// first. When the incoming object itself pays the least it is the one
    /// refused, and nothing is dropped for it.
    fn plan_room(&self, fee: u64, bytes: usize) -> Result<Vec<Hash32>, Rejection> {
        let budget = self.params.pool_max_bytes;
        if bytes > budget {
            return Err(Rejection::PoolFull);
        }
        if self.bytes.saturating_add(bytes) <= budget {
            return Ok(Vec::new());
        }
        let mut cheapest: Vec<(&Hash32, u64, usize)> = self
            .waiting
            .iter()
            .map(|(id, w)| (id, 0, w.bytes))
            .chain(self.ready.iter().map(|(id, r)| (id, r.fee, r.bytes)))
            .collect();
        cheapest.sort_unstable_by(|a, b| {
            if pays_less(a.1, a.2, b.1, b.2) {
                std::cmp::Ordering::Less
            } else if pays_less(b.1, b.2, a.1, a.2) {
                std::cmp::Ordering::Greater
            } else {
                a.0.cmp(b.0)
            }
        });
        let mut victims: Vec<Hash32> = Vec::new();
        let mut freed: usize = 0;
        for (id, victim_fee, victim_bytes) in cheapest {
            if self.bytes.saturating_sub(freed).saturating_add(bytes) <= budget {
                return Ok(victims);
            }
            if !pays_less(victim_fee, victim_bytes, fee, bytes) {
                return Err(Rejection::PoolFull);
            }
            victims.push(*id);
            freed = freed.saturating_add(victim_bytes);
        }
        if self.bytes.saturating_sub(freed).saturating_add(bytes) <= budget {
            Ok(victims)
        } else {
            Err(Rejection::PoolFull)
        }
    }

    /// Drop the objects a room plan named. A dropped object is forgotten, so
    /// it may come back when there is room.
    fn evict(&mut self, victims: &[Hash32]) {
        for object_id in victims {
            self.drop_object(object_id);
            self.seen.remove(object_id);
        }
    }

    /// Remove an object that is ready or waiting, and free its claim.
    fn drop_object(&mut self, object_id: &Hash32) {
        if let Some(waiting) = self.waiting.remove(object_id) {
            self.bytes = self.bytes.saturating_sub(waiting.bytes);
        }
        if let Some(ready) = self.ready.remove(object_id) {
            self.bytes = self.bytes.saturating_sub(ready.bytes);
            self.claims.remove(&ready.digest);
        }
    }

    /// Start a tick: every sender gets its limit back, and each waiting
    /// object is admitted if its transaction arrived, kept if it may still
    /// wait, and dropped otherwise.
    pub fn begin_tick(&mut self, txs: &impl TxLookup, registry: &SchemeStatusRegistry) {
        self.sender_counts.clear();
        let waiting = std::mem::take(&mut self.waiting);
        for (object_id, mut entry) in waiting {
            self.bytes = self.bytes.saturating_sub(entry.bytes);
            if let Some(tx) = txs.tx_facts(&entry.envelope.tx_hash) {
                // A rejection here drops the object, as at first admission.
                let _ = self.admit_known(object_id, entry.envelope, tx, registry);
                continue;
            }
            entry.ticks_left = entry.ticks_left.saturating_sub(1);
            if entry.ticks_left > 0 {
                self.bytes = self.bytes.saturating_add(entry.bytes);
                self.waiting.insert(object_id, entry);
            }
        }
    }

    /// The next objects to prove: at most `tick_max_objects`, the ones that
    /// pay the most per byte first. They stay in the pool until the caller
    /// reports the outcome.
    #[must_use]
    pub fn next_items(&self) -> Vec<PoolItem> {
        let mut order: Vec<&Ready> = self.ready.values().collect();
        order.sort_by(|a, b| {
            if pays_less(b.fee, b.bytes, a.fee, a.bytes) {
                std::cmp::Ordering::Less
            } else if pays_less(a.fee, a.bytes, b.fee, b.bytes) {
                std::cmp::Ordering::Greater
            } else {
                a.digest.cmp(&b.digest)
            }
        });
        order
            .into_iter()
            .take(self.params.tick_max_objects)
            .map(|ready| ready.item.clone())
            .collect()
    }

    /// The tick over `items` was proven: their payload bytes are deleted and
    /// their claims are remembered as proven, so no second object is
    /// admitted for them.
    pub fn mark_proven(&mut self, items: &[PoolItem]) {
        for item in items {
            let object_id = item.envelope.object_id();
            if let Some(ready) = self.ready.remove(&object_id) {
                self.bytes = self.bytes.saturating_sub(ready.bytes);
                self.claims
                    .insert(ready.digest, ClaimEntry::Proven(object_id));
                self.proven_order.push_back(ready.digest);
                if self.proven_order.len() > PROVEN_CLAIMS_CAPACITY {
                    if let Some(oldest) = self.proven_order.pop_front() {
                        if matches!(self.claims.get(&oldest), Some(ClaimEntry::Proven(_))) {
                            self.claims.remove(&oldest);
                        }
                    }
                }
            }
        }
    }

    /// The tick over `items` failed to prove. An object that failed
    /// `MAX_PROVE_FAILURES` ticks in a row is dropped.
    pub fn mark_failed(&mut self, items: &[PoolItem]) {
        for item in items {
            let object_id = item.envelope.object_id();
            let drop = self.ready.get_mut(&object_id).is_some_and(|ready| {
                ready.failures = ready.failures.saturating_add(1);
                ready.failures >= MAX_PROVE_FAILURES
            });
            if drop {
                self.drop_object(&object_id);
            }
        }
    }

    /// Forget that these claims were proven: their block is final, or their
    /// frame was abandoned.
    pub fn forget_claims(&mut self, digests: &[Hash32]) {
        for digest in digests {
            if matches!(self.claims.get(digest), Some(ClaimEntry::Proven(_))) {
                self.claims.remove(digest);
            }
        }
    }

    /// Abandon a claim whose transaction left the node before finality.
    ///
    /// Drops any ready object still waiting to be proven and clears both the
    /// claim entry and the object id from `seen`, so dead claims cannot
    /// accumulate and a temporarily underfunded transaction can be
    /// resubmitted once funded.
    pub(super) fn abandon_claim(&mut self, digest: &Hash32) {
        if let Some(entry) = self.claims.remove(digest) {
            match entry {
                ClaimEntry::Ready(object_id) => {
                    if let Some(ready) = self.ready.remove(&object_id) {
                        self.bytes = self.bytes.saturating_sub(ready.bytes);
                    }
                    self.seen.remove(&object_id);
                }
                ClaimEntry::Proven(object_id) => {
                    self.seen.remove(&object_id);
                }
            }
        }
    }
}
