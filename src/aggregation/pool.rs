//! The object pool: the admission rules of the directive, section 6.1, and the
//! eviction rule that makes a full pool a price instead of an outage.
//!
//! # Why the pool is consensus-adjacent
//!
//! A pool rule cannot change what a block is - the block rules in
//! [`super::backend::verify_frame`] hold whatever a node admits. But a pool rule
//! decides what a node *sees*, and an attacker who can make a node hold
//! unbounded bytes or an unbounded number of sender entries has a
//! denial-of-service primitive against block production. So every limit here is
//! explicit, every one is a refusal rather than a default, and the eviction rule
//! is a quantity (fee per byte) rather than an order of arrival, because arrival
//! order is the thing an attacker controls.
//!
//! # What this pool does not do
//!
//! It does not authenticate senders (the network layer does, and it is the layer
//! that bans a peer), it does not price a transaction (the fee market does), and
//! it does not gossip (the `agg/object` topic does, in Phase 1 step 6). It is
//! the state machine those three drive.

use std::collections::{BTreeMap, BTreeSet};

use super::backend::{envelope_id, object_size_ceiling};
use super::types::{Address, AggError, AggParams, Hash, PoolItem, SchemeRegistry};

/// One admitted object.
#[derive(Debug, Clone)]
struct Entry {
    item: PoolItem,
    object_id: Hash,
    /// The fee the enclosing transaction pays, in the smallest unit, used only
    /// to compute the eviction order and the aggregator's share.
    fee: u64,
    /// The tick the object was admitted in.
    admitted_tick: u64,
    /// The tick the object was first taken into a frame, if it has been.
    taken_tick: Option<u64>,
    /// Whether the transaction the envelope names was known at admission. An
    /// object whose transaction has not arrived is an orphan and expires after
    /// two ticks; an object with a known transaction waits for its block.
    tx_known: bool,
}

impl Entry {
    fn bytes(&self) -> usize {
        self.item.envelope.payload.len()
    }

    /// The eviction quantity. Larger is more valuable, so the smallest is
    /// evicted first. `fee + 1` in the numerator so a zero fee is still an
    /// ordering and not a division by zero.
    fn fee_per_byte(&self) -> u128 {
        (u128::from(self.fee) + 1) * 1_000 / (self.bytes() as u128 + 1_000)
    }
}

/// The admission rules of the directive, section 6.1, as a state machine.
///
/// Rules 1 to 7 of that section map to [`Self::admit`]: the size ceiling is
/// `object_size_ceiling`, rule 2 is the registry lookup inside it, rule 3 is the
/// `tx_known` argument, rule 4 is the verifier, rule 5 is the `seen` set, rule 6
/// is the per-sender tick count, and rule 7 is the byte budget with eviction.
#[derive(Debug)]
pub struct AggPool {
    params: AggParams,
    registry: SchemeRegistry,
    entries: BTreeMap<Hash, Entry>,
    /// Every object id ever admitted. Kept after eviction on purpose: an object
    /// that was evicted for room is not a new object a tick later, and
    /// re-admitting it is the replay the set exists to refuse.
    seen: BTreeSet<Hash>,
    /// (tick, sender) -> how many objects that sender put in that tick.
    per_sender: BTreeMap<(u64, Address), usize>,
    /// Current payload bytes held.
    bytes: usize,
}

impl AggPool {
    /// A pool with `params` and `registry` and nothing in it.
    #[must_use]
    pub fn new(params: AggParams, registry: SchemeRegistry) -> Self {
        Self {
            params,
            registry,
            entries: BTreeMap::new(),
            seen: BTreeSet::new(),
            per_sender: BTreeMap::new(),
            bytes: 0,
        }
    }

    /// The parameters the pool enforces.
    #[must_use]
    pub const fn params(&self) -> &AggParams {
        &self.params
    }

    /// How many objects are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The payload bytes held.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Admit `item` at `tick`.
    ///
    /// `tx_known` is rule 3: the transaction the envelope names must be in the
    /// node's mempool. An object whose transaction has not arrived is an orphan,
    /// and an orphan is allowed to wait at most two ticks
    /// ([`Self::expire_orphans`]) before it is dropped.
    ///
    /// # Errors
    ///
    /// [`AggError::ObjectTooLarge`], [`AggError::UnknownScheme`],
    /// [`AggError::DuplicateObject`], [`AggError::SenderLimit`],
    /// [`AggError::PoolFull`], plus every refusal
    /// [`super::backend::pool_item`] can produce.
    pub fn admit(
        &mut self,
        item: PoolItem,
        sender: Address,
        fee: u64,
        tick: u64,
        tx_known: bool,
        verifier: &dyn super::backend::ObjectVerifier,
    ) -> Result<Hash, AggError> {
        object_size_ceiling(&self.registry, &self.params, &item.envelope)?;
        let id = envelope_id(&item.envelope);
        if self.seen.contains(&id) {
            return Err(AggError::DuplicateObject(id));
        }
        let count = self.per_sender.get(&(tick, sender)).copied().unwrap_or(0);
        if count >= self.params.sender_tick_limit {
            return Err(AggError::SenderLimit { sender });
        }
        // Rule 4: the object is verified at admission, not only when proven.
        // An unverifiable object occupies no bytes.
        verifier.verify(&item.envelope, &item.claim)?;
        let bytes = item.envelope.payload.len();
        self.make_room(bytes, fee, bytes)?;
        self.per_sender.insert((tick, sender), count + 1);
        self.seen.insert(id);
        self.bytes += bytes;
        self.entries.insert(
            id,
            Entry {
                item,
                object_id: id,
                fee,
                admitted_tick: tick,
                taken_tick: None,
                tx_known,
            },
        );
        Ok(id)
    }

    /// Evict until `needed` more bytes fit, or refuse because the newcomer is
    /// the cheapest thing in the pool.
    fn make_room(&mut self, needed: usize, fee: u64, bytes: usize) -> Result<(), AggError> {
        if self.bytes.saturating_add(needed) <= self.params.pool_max_bytes {
            return Ok(());
        }
        let newcomer = (u128::from(fee) + 1) * 1_000 / (bytes as u128 + 1_000);
        loop {
            if self.bytes.saturating_add(needed) <= self.params.pool_max_bytes {
                return Ok(());
            }
            let victim = self
                .entries
                .values()
                .min_by_key(|entry| (entry.fee_per_byte(), entry.admitted_tick, entry.object_id))
                .map(|entry| entry.object_id);
            let Some(victim_id) = victim else {
                // Nothing to evict and no room: the pool is empty and the
                // object alone is larger than the budget.
                return Err(AggError::PoolFull);
            };
            let victim_rate = self.entries.get(&victim_id).map_or(0, Entry::fee_per_byte);
            if newcomer <= victim_rate {
                // Evicting a more valuable object to hold a less valuable one is
                // a griefing win for whoever sends the cheap object.
                return Err(AggError::PoolFull);
            }
            if let Some(removed) = self.entries.remove(&victim_id) {
                self.bytes = self.bytes.saturating_sub(removed.bytes());
            }
        }
    }

    /// Drop orphans older than two ticks. Returns how many were dropped.
    pub fn expire_orphans(&mut self, tick: u64) -> usize {
        let expired: Vec<Hash> = self
            .entries
            .values()
            .filter(|entry| !entry.tx_known && tick.saturating_sub(entry.admitted_tick) > 2)
            .filter(|entry| entry.taken_tick.is_none())
            .map(|entry| entry.object_id)
            .collect();
        for id in &expired {
            if let Some(removed) = self.entries.remove(id) {
                self.bytes = self.bytes.saturating_sub(removed.bytes());
            }
        }
        // The per-sender counters of an old tick cannot refuse anything any
        // more; dropping them keeps the map bounded by the ticks in flight.
        self.per_sender
            .retain(|(counted_tick, _), _| tick.saturating_sub(*counted_tick) <= 2);
        expired.len()
    }

    /// Take up to `max` not-yet-taken items, cheapest fee per byte first, and
    /// mark them taken at `tick`. The payloads stay until the backend has
    /// proven the tick ([`Self::release_proven`]), because a proof that fails
    /// must be retried and a deleted payload cannot be.
    ///
    /// # Errors
    ///
    /// [`AggError::Empty`] when there is nothing to take.
    pub fn take_tick(&mut self, tick: u64, max: usize) -> Result<Vec<PoolItem>, AggError> {
        let mut ids: Vec<(u128, Hash)> = self
            .entries
            .values()
            .filter(|entry| entry.taken_tick.is_none())
            .map(|entry| (entry.fee_per_byte(), entry.object_id))
            .collect();
        if ids.is_empty() {
            return Err(AggError::Empty);
        }
        // Highest fee first: the tick that earns most is the tick that runs.
        ids.sort_by(|a, b| b.cmp(a));
        ids.truncate(max);
        let mut out = Vec::with_capacity(ids.len());
        for (_, id) in ids {
            if let Some(entry) = self.entries.get_mut(&id) {
                entry.taken_tick = Some(tick);
                out.push(entry.item.clone());
            }
        }
        Ok(out)
    }

    /// Drop the payloads of the items a tick proved, keeping the claims until
    /// the block is final. Returns the bytes released.
    pub fn release_proven(&mut self, proved: &[Hash]) -> usize {
        let mut released = 0usize;
        for id in proved {
            if let Some(entry) = self.entries.get_mut(id) {
                released += entry.item.envelope.payload.len();
                entry.item.envelope.payload = Vec::new();
            }
        }
        self.bytes = self.bytes.saturating_sub(released);
        released
    }
}
