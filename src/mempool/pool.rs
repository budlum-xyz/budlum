use crate::core::address::Address;
use crate::core::transaction::Transaction;
use crate::mempool::duty_lane::{self, DutyRefusal};
use std::collections::{BTreeMap, BTreeSet, HashMap};

// (2026-07-21) consensus determinism: transactions sharing a fee arrived in
// HashSet iteration order (process-random), so the block body order that runs
// `get_sorted_transactions` -> `collect_block_transactions` could differ from
// node to node (a different block hash on a same-fee tie, and a potential
// split). The tie-break is canonical now: lexicographic tx.hash order through
// `BTreeSet<String>` - fee DESC, hash ASC. Changing this rule changes
// consensus behaviour: it is documented and tested
// (`test_same_fee_canonical_order_by_hash`).

/// The bytes a full mempool is allowed to hold.
///
/// # Why a byte budget exists beside the entry count
///
/// `max_size` bounds how many transactions the pool holds and says nothing
/// about how large they are. `network::protocol::MAX_TX_SIZE` bounds one
/// transaction at 100 KiB. Multiplied out, the default pool of 20 000 entries
/// admits 1.95 GiB of transaction bodies, which is more resident memory than
/// this repository's own build host has (measured: 1984 MiB). The two limits
/// were each defensible alone and their product was not bounded by anything.
///
/// The attack does not need many peers or an unusual transaction. Signatures
/// are verified before admission, so the flooder pays signing cost, but every
/// transaction is otherwise ordinary: 100 KiB of `data`, a fee above the
/// floor, a fresh nonce. Two hundred senders at the per-sender cap of 100
/// reach the ceiling. Nothing on the path refuses them, because nothing on the
/// path adds up their sizes.
///
/// # Why 256 MiB
///
/// It is chosen against the block the pool feeds rather than against a round
/// number: `MAX_TRANSACTIONS_PER_BLOCK` is 5000, so at the transport ceiling a
/// single block's worth of worst-case transactions is 488 MiB, and holding
/// several blocks' worth of *worst-case* bodies is not a service the pool owes
/// anyone. At realistic transaction sizes 256 MiB is far more than 20 000
/// entries, so the entry count stays the binding limit in normal operation and
/// this budget only engages under the flood it exists for.
pub const DEFAULT_MAX_POOL_BYTES: usize = 256 * 1024 * 1024;

/// The duty lane's block share under the default block budget.
///
/// Section 7.3 item 6 sets the share at 20 percent of a block's bytes
/// (TESTNET-DEFAULT), and the share is derived from `consensus::MAX_BLOCK_SIZE`
/// rather than written as a number beside it: a block budget that changes
/// changes the share with it.
pub const DEFAULT_DUTY_BLOCK_BYTES: usize =
    duty_lane::block_share_bytes(crate::consensus::MAX_BLOCK_SIZE);

/// How many blocks of the duty lane's share the pool holds.
///
/// This is a bound on the wait, not a memory figure. The lane's block share is
/// what one block can clear, so four blocks is the point past which a waiting
/// batch would sit longer than the window it belongs to, and holding more of
/// them only spends pool bytes on duty work no block could carry in time.
const DUTY_LANE_POOL_BLOCKS: usize = 4;

#[derive(Debug, Clone)]
pub struct MempoolConfig {
    pub max_size: usize,

    pub max_per_sender: usize,

    pub min_fee: u64,

    pub tx_ttl_secs: u64,

    pub rbf_bump_percent: u64,

    /// The resident byte ceiling for admitted transaction bodies.
    ///
    /// Counted over the same measure the transport uses to refuse an oversized
    /// transaction, so a transaction that passed `validate_tx_size` is charged
    /// the number that check read. Two different measures of "size" on the
    /// admission path is how a bound gets enforced against the wrong quantity.
    pub max_pool_bytes: usize,

    /// The bytes of a block the duty lane may fill.
    ///
    /// Section 7.3 item 6: the Mobile validator duty lane is bounded by this
    /// share of the block (20 percent, TESTNET-DEFAULT), measured the way the
    /// block validator measures a block. It is a field rather than a constant
    /// so a test can size a block in a few hundred bytes and watch the share
    /// hold, and so governance can move the share with the block budget.
    pub duty_block_bytes: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        MempoolConfig {
            max_size: 20000,
            max_per_sender: 100,
            min_fee: 1,
            tx_ttl_secs: 3600,
            rbf_bump_percent: 10,
            max_pool_bytes: DEFAULT_MAX_POOL_BYTES,
            duty_block_bytes: DEFAULT_DUTY_BLOCK_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MempoolError {
    PoolFull,
    /// The pool is under its entry count but at its byte budget.
    ///
    /// Distinct from `PoolFull` because the operator response differs: a full
    /// pool by count means raise `max_size` or the fee floor, a full pool by
    /// bytes means the pool is being fed large bodies and raising `max_size`
    /// would make it worse.
    PoolBytesFull,
    DuplicateTransaction,
    FeeTooLow,
    SenderLimitReached,
    InvalidNonce,
    TransactionExpired,
    RbfFeeTooLow,
    /// A duty transaction the mobile duty lane will not take (section 7.3,
    /// item 6).
    ///
    /// Distinct from `FeeTooLow` and from `SenderLimitReached` because the
    /// response differs: the lane's limit is a window, so the client waits for
    /// the next window or replaces the batch it already sent, and paying a
    /// higher fee or freeing a sender slot changes nothing.
    DutyLaneRefused(DutyRefusal),
    InvalidTransaction(String),
}

/// A bundle member the pool refused, and where in the bundle it was.
///
/// The index is what the caller needs: the caller's bundle is unchanged by the
/// refusal, and telling it *which* member the pool objected to is the
/// difference between a client that can fix its bundle and one that retries the
/// same body forever.
#[derive(Debug, Clone, PartialEq)]
pub struct BundleRefusal {
    pub index: usize,
    pub cause: MempoolError,
}

impl std::fmt::Display for BundleRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "member {} refused: {:?}", self.index, self.cause)
    }
}

/// What the pool records about a duty batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DutyBatch {
    /// The window the batch belongs to.
    ///
    /// Recorded at admission rather than recomputed later: the rate limit is
    /// "one batch per validator per window", and a batch admitted one second
    /// before a window boundary must still hold its own window, or the same
    /// validator could send a second one immediately after the boundary and
    /// occupy two slots with one action.
    window: u64,
    /// The bytes the batch costs a block, by the block validator's measure.
    ///
    /// Computed once, like `charged`: the lane's byte ceiling and its block
    /// share are both read from the pool often enough that re-serializing
    /// every pending batch on each read would put a JSON encode on the block
    /// production path.
    block_bytes: usize,
}

#[derive(Debug, Clone)]
struct PendingTx {
    tx: Transaction,
    added_at: u128,
    /// The bytes this entry was admitted against, computed once. The size is
    /// fixed for the life of the entry, and re-encoding it on every eviction
    /// scan let one refused submission drive a protobuf encode over every
    /// cheaper entry in the pool.
    charged: usize,
    /// The duty batch this entry is, when it is one.
    duty: Option<DutyBatch>,
}

#[derive(Clone)]
pub struct Mempool {
    config: MempoolConfig,

    transactions: HashMap<String, PendingTx>,

    by_sender: HashMap<Address, BTreeMap<u64, String>>,

    by_fee: BTreeMap<u64, BTreeSet<String>>,

    /// The running total of admitted transaction bytes.
    ///
    /// Kept as a counter rather than recomputed on each admission: summing the
    /// pool per insert is O(n) on the hot path, and a re-encode per entry is
    /// worse than the flood it would be defending against. Every mutation of
    /// `transactions` adjusts this in the same statement block, and
    /// `resident_bytes_are_exact` re-derives it from scratch to prove the two
    /// have not drifted.
    resident_bytes: usize,

    /// The scheme statuses admission verifies under. The chain copies its
    /// state registry in through [`Mempool::sync_scheme_registry`] before it
    /// admits, so a family the chain disabled is refused at the pool door in
    /// the same block it stops verifying in the executor.
    scheme_registry: crate::crypto::scheme::SchemeStatusRegistry,

    /// Authorizations this pool already verified under the current registry. A transaction that
    /// comes back (re-gossip, a block replay) is not verified twice.
    authority_cache: crate::mempool::authority_cache::AuthorityCache,

    /// Entries this pool removed while a bundle was being admitted.
    ///
    /// Admission is not free of side effects on other people's transactions: a
    /// full pool evicts a cheaper one, and a replacement drops the transaction
    /// it replaces. A bundle is all or none, so a member refused half way
    /// through has to put every one of those back; a rollback that only removes
    /// the members already admitted leaves the evictions and the replacement
    /// behind, which is a free deletion primitive for whoever can submit a
    /// bundle that fails at its last member. The journal is `None` outside
    /// bundle admission, so ordinary admission pays nothing for it.
    journal: Option<Vec<PendingTx>>,
}

/// How many bytes one transaction occupies, by the transport's own measure.
///
/// Reuses the protobuf `encoded_len` that `validate_tx_size` refuses on, so a
/// transaction charged here is charged the number it was admitted against.
/// The serialization is discarded; only the length is wanted.
pub fn charged_bytes(tx: &Transaction) -> usize {
    use prost::Message;
    let proto = crate::network::proto_conversions::pb::ProtoTransaction::from(tx);
    proto.encoded_len()
}

impl Mempool {
    pub fn new(config: MempoolConfig) -> Self {
        Mempool {
            config,
            transactions: HashMap::new(),
            by_sender: HashMap::new(),
            by_fee: BTreeMap::new(),
            resident_bytes: 0,
            scheme_registry: crate::crypto::scheme::SchemeStatusRegistry::genesis(),
            authority_cache: crate::mempool::authority_cache::AuthorityCache::default(),
            journal: None,
        }
    }

    /// Adopt the chain-state scheme registry for admission checks.
    pub fn sync_scheme_registry(&mut self, registry: &crate::crypto::scheme::SchemeStatusRegistry) {
        if self.scheme_registry != *registry {
            self.scheme_registry = registry.clone();
        }
    }

    /// The bytes currently held.
    #[must_use]
    pub const fn resident_bytes(&self) -> usize {
        self.resident_bytes
    }

    /// The byte ceiling in force.
    #[must_use]
    pub const fn max_pool_bytes(&self) -> usize {
        self.config.max_pool_bytes
    }

    /// Admit a transaction into the pool at a caller-supplied time.
    ///
    /// [`Self::add_transaction`] is this door with the wall clock, and it is
    /// the door every producer of transactions uses. The time is a parameter
    /// because the duty lane's limit is a window (section 7.3, item 6): a test
    /// that had to reach a real window boundary would wait ten minutes, and a
    /// test that raced one would pass or fail on the second it ran.
    ///
    /// Convenience: [`Self::add_transaction`] calls this door with
    /// `SystemTime::now`, so every admitted transaction already passes
    /// through it. The time parameter is the only difference between the two,
    /// and the wall clock is read in one place so no caller can choose a
    /// window by choosing a door.
    ///
    /// # Errors
    ///
    /// The refusal the pool found, by the same rules as
    /// [`Self::add_transaction`], plus `DutyLaneRefused` for a duty batch the
    /// lane will not take.
    pub fn admit_at(&mut self, tx: Transaction, now_ms: u128) -> Result<(), MempoolError> {
        // The cheap rejections run first. `Transaction::verify` can cost an
        // ML-DSA verification, so a duplicate or a below-floor flood must be
        // refused by a map lookup and an integer compare before it can make
        // the node spend that CPU (audit).
        if self.transactions.contains_key(&tx.hash) {
            return Err(MempoolError::DuplicateTransaction);
        }

        // The duty lane is free (section 7.3, item 6; section 11.6). A Mobile
        // validator's batch is admitted below the fee floor, and the lane's
        // own limits are what bound it instead: one batch per validator per
        // window, and a byte ceiling on the lane. Every other transaction
        // still pays, so the floor has not moved for anyone else.
        let duty = duty_lane::is_duty(&tx).then(|| DutyBatch {
            window: duty_lane::window_at(now_ms),
            block_bytes: duty_lane::block_bytes(&tx),
        });

        if duty.is_none() && tx.fee < self.config.min_fee {
            return Err(MempoolError::FeeTooLow);
        }

        // Verify transaction signature BEFORE
        // Accepting into mempool. Without this, an attacker can flood the
        // Mempool with invalid-signature transactions that propagate via
        // Gossip, wasting every node's CPU on signature verification.
        //
        // `Transaction::verify` already accepts the canonical genesis
        // transaction (zero address, zero fields, no signature) and rejects
        // every other zero-address sender, so no special case is needed
        // here. A blanket zero-address exemption would let an attacker mint
        // unsigned transactions from 0x00..00 (BUDLUM finding #19/#26).
        let registry_commitment = self.scheme_registry.commitment();
        let authorization = bincode::serialize(&tx.authorization).unwrap_or_default();
        let digest = crate::mempool::authority_cache::authorization_digest(&[
            &tx.signing_hash(),
            tx.signature.as_deref().unwrap_or_default(),
            &tx.signer_public_key,
            &authorization,
        ]);
        if !self.authority_cache.contains(&digest, &registry_commitment) {
            if !tx.verify_in(&self.scheme_registry) {
                return Err(MempoolError::InvalidTransaction(
                    "Invalid transaction signature".into(),
                ));
            }
            self.authority_cache
                .insert_accepted(digest, registry_commitment);
        }

        // Eviction is a side effect on somebody else's transaction, so it may
        // not run until this transaction is known to be admissible. The old
        // order evicted first and validated second: a submission that was then
        // refused by the RBF rule or the per-sender cap still left the victim
        // deleted. That is a free deletion primitive - the attacker pays no
        // fee, occupies no slot, and repeats. The eviction call therefore
        // moves below every rejection path.
        //
        // A replacement (same sender, same nonce) frees its own slot and needs
        // no eviction at all, so a full pool must not refuse it.
        let sender_count = self
            .by_sender
            .get(&tx.from)
            .map_or(0, std::collections::BTreeMap::len);
        let existing_hash = self.find_tx_by_sender_nonce(&tx.from, tx.nonce);

        if let Some(existing_hash) = existing_hash.as_ref() {
            // `find_tx_by_sender_nonce` returned this hash from the same map,
            // so the lookup succeeds. Handled rather than unwrapped because
            // this is the transaction-admission path: a panic here is a node
            // that any peer can stop by sending a transaction.
            let Some(existing) = self.transactions.get(existing_hash) else {
                return Err(MempoolError::InvalidTransaction(
                    "replacement target vanished from the pool".to_string(),
                ));
            };
            // The RBF bump must always be POSITIVE. With integer division the
            // bump rounded down to 0 on small fees (fee=1, 10 percent -> bump
            // 0), which allowed unlimited replace-churn at the same fee (a
            // cheap DoS vector). Now: bump = max(1, ceil(fee * pct / 100)),
            // and the replacement fee MUST exceed the old fee. The
            // intermediate computation uses u128 against overflow.
            //
            // A duty batch is exempt: it is free, so a bump rule would make
            // every replacement of it impossible, and the lane's window limit
            // is what stops churn. Replacing the pending batch is the client's
            // repair path when a phone collected one more audit before the
            // window closed.
            if duty.is_none() {
                let bump = (u128::from(existing.tx.fee) * u128::from(self.config.rbf_bump_percent))
                    .div_ceil(100);
                let min_new_fee = existing
                    .tx
                    .fee
                    .saturating_add(u64::try_from(bump.max(1)).unwrap_or(u64::MAX));
                if tx.fee < min_new_fee {
                    return Err(MempoolError::RbfFeeTooLow);
                }
            }
        } else if duty.is_none() && sender_count >= self.config.max_per_sender {
            return Err(MempoolError::SenderLimitReached);
        }

        // The duty lane's two limits. Both are refusals with no side effects,
        // so they run before anything is evicted, for the reason the eviction
        // comment gives above: a refusal that has already deleted somebody
        // else's transaction is a free deletion primitive.
        //
        // The lane is measured over the entries in the pool, not over a
        // counter. A counter has to be told about every path that removes an
        // entry (eviction, replacement, expiry, drain, and the bundle rollback
        // that puts an evicted entry back without admitting it), and one
        // missed path turns the ceiling into a slow leak. The scan is bounded
        // by the entry cap and runs only for a duty transaction, which the
        // window limit already makes rare.
        let incoming = charged_bytes(&tx);
        if let Some(batch) = duty.as_ref() {
            if let Some((open_nonce, _)) = self.open_duty_batch(&tx.from, batch.window) {
                if open_nonce != tx.nonce {
                    return Err(MempoolError::DutyLaneRefused(
                        DutyRefusal::SecondBatchInWindow {
                            window: batch.window,
                            open_nonce,
                        },
                    ));
                }
            }
            // The lane is measured over the block measure throughout, not over
            // `incoming`: this ceiling bounds bytes that a block will have to
            // carry, and `incoming` is the transport measure the pool-wide
            // budget uses. Two measures on one limit is how a bound ends up
            // enforced against a quantity nothing else looks at.
            let replaced = existing_hash
                .as_ref()
                .and_then(|hash| self.transactions.get(hash))
                .and_then(|entry| entry.duty)
                .map_or(0, |replaced| replaced.block_bytes);
            let lane_bytes = self
                .duty_lane_bytes()
                .saturating_sub(replaced)
                .saturating_add(batch.block_bytes);
            let cap = self.duty_lane_cap();
            if lane_bytes > cap {
                return Err(MempoolError::DutyLaneRefused(DutyRefusal::LaneBytesFull {
                    lane_bytes,
                    cap,
                }));
            }
        }

        if existing_hash.is_none()
            && self.transactions.len() >= self.config.max_size
            && !self.evict_lowest_fee(&tx)
        {
            return Err(MempoolError::PoolFull);
        }

        // The byte budget is charged AFTER the count check and BEFORE the
        // replacement is removed, and both orderings matter.
        //
        // After the count check, so a pool that is full by count refuses with
        // `PoolFull` rather than by whichever limit happens to be read first;
        // the two errors tell an operator different things.
        //
        // Before the removal, so a refusal leaves the pool untouched. The
        // eviction ordering above exists because a refusal that had already
        // deleted somebody else's transaction is a free deletion primitive.
        // Charging bytes after the removal would reintroduce exactly that: a
        // replacement large enough to exceed the budget would be refused with
        // the transaction it replaced already gone.
        let freed = existing_hash
            .as_ref()
            .and_then(|h| self.transactions.get(h))
            .map_or(0, |entry| entry.charged);
        let projected = self
            .resident_bytes
            .saturating_sub(freed)
            .saturating_add(incoming);
        if projected > self.config.max_pool_bytes
            && !self.evict_until_bytes_fit(&tx, projected - self.config.max_pool_bytes)
        {
            return Err(MempoolError::PoolBytesFull);
        }

        if let Some(existing_hash) = existing_hash {
            self.remove_transaction(&existing_hash);
        }

        self.by_sender
            .entry(tx.from)
            .or_default()
            .insert(tx.nonce, tx.hash.clone());
        self.by_fee
            .entry(tx.fee)
            .or_default()
            .insert(tx.hash.clone());

        self.resident_bytes = self.resident_bytes.saturating_add(incoming);
        self.transactions.insert(
            tx.hash.clone(),
            PendingTx {
                tx,
                added_at: now_ms,
                charged: incoming,
                duty,
            },
        );

        Ok(())
    }

    /// Admit a transaction into the pool at the current wall-clock time.
    ///
    /// # Errors
    ///
    /// The refusal the pool found: a duplicate, a fee below the floor, a full
    /// pool by count or by bytes, a refused replacement, a refused duty
    /// batch, or an invalid signature.
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), MempoolError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        self.admit_at(tx, now_ms)
    }

    pub fn remove_transaction(&mut self, hash: &str) -> Option<Transaction> {
        if let Some(pending) = self.transactions.remove(hash) {
            self.resident_bytes = self.resident_bytes.saturating_sub(pending.charged);
            if let Some(sender_txs) = self.by_sender.get_mut(&pending.tx.from) {
                sender_txs.remove(&pending.tx.nonce);
                if sender_txs.is_empty() {
                    self.by_sender.remove(&pending.tx.from);
                }
            }

            if let Some(fee_txs) = self.by_fee.get_mut(&pending.tx.fee) {
                fee_txs.remove(hash);
                if fee_txs.is_empty() {
                    self.by_fee.remove(&pending.tx.fee);
                }
            }
            if let Some(journal) = self.journal.as_mut() {
                journal.push(pending.clone());
            }
            return Some(pending.tx);
        }
        None
    }

    /// Admit a bundle's members all or none.
    ///
    /// Each member goes through the ordinary admission door, so the same
    /// checks apply in the same order. What differs is the failure path: the
    /// pool records every entry it removed on the way (evictions, replacements)
    /// and, when a member is refused, takes the admitted members back out and
    /// puts the recorded entries back. The pool is therefore in exactly the
    /// state it was in before the call - not merely free of the bundle, which
    /// is what the previous remove-only rollback achieved while leaving the
    /// evicted victims deleted.
    pub fn add_transaction_bundle(&mut self, txs: Vec<Transaction>) -> Result<(), BundleRefusal> {
        if self.journal.is_some() {
            // Nested admission would journal the inner call's removals into
            // the outer one and restore them twice. Nothing calls this
            // re-entrantly; refusing is cheaper than a corrupted pool.
            return Err(BundleRefusal {
                index: 0,
                cause: MempoolError::InvalidTransaction("nested bundle admission".to_string()),
            });
        }
        self.journal = Some(Vec::new());
        let mut admitted: Vec<String> = Vec::new();
        for (index, tx) in txs.into_iter().enumerate() {
            let hash = tx.hash.clone();
            if let Err(cause) = self.add_transaction(tx) {
                // The journal is taken first: the removals below take the
                // admitted members back out and must not be recorded as
                // evictions of their own.
                let journal = self.journal.take().unwrap_or_default();
                for hash in admitted.iter().rev() {
                    self.remove_transaction(hash);
                }
                // Reverse order, so an entry recorded after another is put
                // back first: the last removal is the one that freed the space
                // for the removals before it.
                for pending in journal.into_iter().rev() {
                    self.restore_entry(pending);
                }
                return Err(BundleRefusal { index, cause });
            }
            admitted.push(hash);
        }
        self.journal = None;
        Ok(())
    }

    /// Put back an entry that was in this pool before, without admitting it.
    ///
    /// Used only by a bundle rollback, where the entry passed admission once
    /// already and the pool's counters were charged for it once already.
    fn restore_entry(&mut self, pending: PendingTx) {
        self.by_sender
            .entry(pending.tx.from)
            .or_default()
            .insert(pending.tx.nonce, pending.tx.hash.clone());
        self.by_fee
            .entry(pending.tx.fee)
            .or_default()
            .insert(pending.tx.hash.clone());
        self.resident_bytes = self.resident_bytes.saturating_add(pending.charged);
        self.transactions.insert(pending.tx.hash.clone(), pending);
    }

    /// The transactions a block should carry, by fee, honouring the duty lane's
    /// share of the block.
    ///
    /// The duty lane may fill at most `duty_block_bytes` of the block
    /// (section 7.3, item 6). A duty batch past the share is skipped, not
    /// dropped: it waits in the pool for the next block, which is where the
    /// producer's own byte budget would have put it. Skipping it here rather
    /// than leaving it to the producer means the share holds even when the
    /// block has room: without this, a window's worth of free batches would
    /// fill a quiet block and the fee-paying transactions that arrived in the
    /// same slot would wait behind them.
    ///
    /// The measure is [`duty_lane::block_bytes`], the one the block validator
    /// uses, so the share is a fraction of the quantity that is actually
    /// bounded.
    pub fn get_sorted_transactions(&self, limit: usize) -> Vec<Transaction> {
        let mut result = Vec::with_capacity(limit);
        let duty_cap = self.config.duty_block_bytes;
        let mut duty_bytes: usize = 0;

        for (_, hashes) in self.by_fee.iter().rev() {
            for hash in hashes {
                if result.len() >= limit {
                    return result;
                }
                let Some(pending) = self.transactions.get(hash) else {
                    continue;
                };
                if let Some(batch) = pending.duty {
                    let next = duty_bytes.saturating_add(batch.block_bytes);
                    if next > duty_cap {
                        continue;
                    }
                    duty_bytes = next;
                }
                result.push(pending.tx.clone());
            }
        }
        result
    }

    pub fn cleanup_expired(&mut self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        let ttl_ms = u128::from(self.config.tx_ttl_secs) * 1000;
        let expired: Vec<String> = self
            .transactions
            .iter()
            .filter(|(_, p)| now.saturating_sub(p.added_at) > ttl_ms)
            .map(|(h, _)| h.clone())
            .collect();

        let count = expired.len();
        for hash in expired {
            self.remove_transaction(&hash);
        }
        count
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// How many distinct sender addresses currently hold at least one
    /// transaction in the pool.
    ///
    /// Distinct from [`Self::len`]: the entry count can be large while a
    /// handful of addresses dominate, and the reverse is also true. Operators
    /// watching only the entry count cannot see sender concentration.
    #[must_use]
    pub fn sender_count(&self) -> usize {
        self.by_sender.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    pub fn get(&self, hash: &str) -> Option<&Transaction> {
        self.transactions.get(hash).map(|p| &p.tx)
    }

    pub fn sender_transactions(&self, sender: &Address) -> Vec<Transaction> {
        self.by_sender
            .get(sender)
            .map(|nonces| {
                nonces
                    .values()
                    .filter_map(|hash| {
                        self.transactions
                            .get(hash)
                            .map(|pending| pending.tx.clone())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn drain(&mut self) -> Vec<Transaction> {
        let txs: Vec<Transaction> = self.transactions.values().map(|p| p.tx.clone()).collect();
        self.transactions.clear();
        self.by_sender.clear();
        self.by_fee.clear();
        // The counter is debited only by `remove_transaction`, which cannot
        // run for entries this call already dropped. Without the reset the
        // stale total grows with every drain until an empty pool refuses
        // every admission with `PoolBytesFull`.
        self.resident_bytes = 0;
        txs
    }

    fn find_tx_by_sender_nonce(&self, sender: &Address, nonce: u64) -> Option<String> {
        self.by_sender
            .get(sender)
            .and_then(|nonces| nonces.get(&nonce).cloned())
    }

    /// The validator's pending duty batch in `window`, as `(nonce, hash)`.
    ///
    /// Walked over the sender's own entries rather than kept as a side index:
    /// a validator holds a handful of transactions and at most one batch, so
    /// the walk is short, and an index would need the same removal bookkeeping
    /// the lane byte total avoids.
    fn open_duty_batch(&self, operator: &Address, window: u64) -> Option<(u64, String)> {
        let nonces = self.by_sender.get(operator)?;
        for (nonce, hash) in nonces {
            let batch = self.transactions.get(hash).and_then(|entry| entry.duty);
            if batch.is_some_and(|held| held.window == window) {
                return Some((*nonce, hash.clone()));
            }
        }
        None
    }

    /// The bytes the pool's duty lane holds, over the block measure.
    fn duty_lane_bytes(&self) -> usize {
        self.transactions
            .values()
            .filter_map(|entry| entry.duty)
            .map(|batch| batch.block_bytes)
            .sum()
    }

    /// The bytes the lane may hold in the pool.
    ///
    /// Derived from the block share rather than configured beside it: the pool
    /// holds a few blocks of what a block can carry, and a second number would
    /// be one more quantity to keep in step with the share.
    fn duty_lane_cap(&self) -> usize {
        self.config
            .duty_block_bytes
            .saturating_mul(DUTY_LANE_POOL_BLOCKS)
    }

    /// Drop the lowest-fee transaction to make room, if the incoming one
    /// outbids it.
    ///
    /// The victim is chosen deterministically, and never from the sender being
    /// admitted.
    ///
    /// Both properties were missing. `hashes.iter().next()` takes an arbitrary
    /// element of a `HashSet`, so two nodes with the same mempool could evict
    /// different transactions - and a test written against it failed roughly
    /// one run in five. Worse, the victim could belong to the sender being
    /// admitted: `add_transaction` then saw a count that eviction had just
    /// decremented, and a sender sitting at `max_per_sender` bought itself
    /// another slot by outbidding its own transaction.
    ///
    /// Skipping the sender's own entries makes the cap mean what it says: to
    /// get a slot when the pool is full, you have to outbid *somebody else*.
    fn evict_lowest_fee(&mut self, new_tx: &Transaction) -> bool {
        for (&fee, hashes) in &self.by_fee {
            if new_tx.fee <= fee {
                // `by_fee` is ordered, so nothing further down can be cheaper.
                break;
            }
            // Deterministic choice among equal fees: the smallest hash. Two
            // nodes with the same mempool must evict the same transaction.
            let victim = hashes
                .iter()
                .filter(|h| {
                    self.transactions
                        .get(*h)
                        .is_some_and(|entry| entry.tx.from != new_tx.from)
                })
                .min()
                .cloned();
            if let Some(hash) = victim {
                self.remove_transaction(&hash);
                return true;
            }
        }
        false
    }

    /// Evict cheaper transactions until `needed` bytes have been freed.
    ///
    /// The same rule as [`Self::evict_lowest_fee`], applied repeatedly: only
    /// transactions strictly cheaper than the incoming one are candidates, the
    /// incoming sender may not evict itself, and ties break on the smallest
    /// hash so two nodes with the same pool evict the same transactions.
    ///
    /// Returns `false` without having evicted anything when the budget cannot
    /// be reached. That is the important half: a partial eviction that then
    /// refuses the transaction would be the free-deletion primitive again,
    /// this time paid for in bytes. So the victims are chosen first and
    /// removed only once the sum is known to be enough.
    /// (accepted with the bound written down): this sweep
    /// is O(pool entries) in the worst case - it walks `by_fee` until the
    /// byte budget is met. The bound that makes that acceptable is the entry
    /// cap (20_000), and the sweep only runs when an admission is about to
    /// be refused for bytes, so the cost is paid on the path that was about
    /// to reject anyway. An index on charged-bytes-per-fee would replace one
    /// linear scan with maintained bookkeeping on EVERY admission - trading
    /// a rare worst case for a common per-insert cost, which is the worse
    /// trade for a pool this size. Revisit only if the entry cap grows an
    /// order of magnitude.
    fn evict_until_bytes_fit(&mut self, new_tx: &Transaction, needed: usize) -> bool {
        let mut victims: Vec<String> = Vec::new();
        let mut freed = 0usize;
        'outer: for (&fee, hashes) in &self.by_fee {
            if new_tx.fee <= fee {
                // `by_fee` is ordered, so nothing further down can be cheaper.
                break;
            }
            for hash in hashes {
                let Some(entry) = self.transactions.get(hash) else {
                    continue;
                };
                if entry.tx.from == new_tx.from {
                    continue;
                }
                freed = freed.saturating_add(entry.charged);
                victims.push(hash.clone());
                if freed >= needed {
                    break 'outer;
                }
            }
        }
        if freed < needed {
            return false;
        }
        for hash in victims {
            self.remove_transaction(&hash);
        }
        true
    }

    pub fn set_min_fee(&mut self, min_fee: u64) {
        self.config.min_fee = min_fee;
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(MempoolConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_tx_from_seed(seed_byte: u8, nonce: u64, fee: u64) -> Transaction {
        // Deterministic test keypair from single byte seed (avoids hard-coded crypto literal).
        let seed = [seed_byte; 32];
        let keypair = crate::crypto::primitives::KeyPair::from_seed(&seed).unwrap();
        let from = crate::core::address::Address::from(keypair.public_key_bytes());
        let mut tx = Transaction::new(from, crate::core::address::Address::zero(), 100, vec![]);
        tx.nonce = nonce;
        tx.fee = fee;
        tx.hash = tx.calculate_hash();
        tx.sign(&keypair);
        tx
    }

    /// Build a signed transaction carrying `payload` bytes of `data`.
    fn create_test_tx_sized(seed_byte: u8, nonce: u64, fee: u64, payload: usize) -> Transaction {
        let seed = [seed_byte; 32];
        let keypair = crate::crypto::primitives::KeyPair::from_seed(&seed).unwrap();
        let from = crate::core::address::Address::from(keypair.public_key_bytes());
        let mut tx = Transaction::new(
            from,
            crate::core::address::Address::zero(),
            100,
            vec![0xAB; payload],
        );
        tx.nonce = nonce;
        tx.fee = fee;
        tx.hash = tx.calculate_hash();
        tx.sign(&keypair);
        tx
    }

    /// A bundle refused at its last member leaves the pool exactly as it was.
    ///
    /// The member before it passed admission by evicting a cheaper transaction.
    /// A rollback that only removes the admitted members leaves that eviction
    /// behind: the sender of the refused bundle paid no fee, ended with nothing
    /// in the pool, and deleted somebody else's transaction. Repeating it with
    /// a fresh last member empties the pool for the price of the signatures.
    #[test]
    fn a_bundle_refused_at_its_last_member_restores_the_evicted_victim() {
        let mut pool = Mempool::new(MempoolConfig {
            max_size: 1,
            min_fee: 1,
            ..MempoolConfig::default()
        });
        let victim = create_test_tx_from_seed(1, 0, 10);
        let victim_bytes = charged_bytes(&victim);
        pool.add_transaction(victim.clone())
            .expect("the victim fits");

        // The first member is admissible: it outbids the victim, which the
        // full pool evicts. The second is refused by the fee floor.
        let accepted = create_test_tx_from_seed(2, 0, 100);
        let refused = create_test_tx_from_seed(3, 0, 0);
        let err = pool
            .add_transaction_bundle(vec![accepted.clone(), refused])
            .expect_err("a below-floor member refuses the whole bundle");
        assert_eq!(err.index, 1, "the refusal names the member that failed");
        assert_eq!(err.cause, MempoolError::FeeTooLow);

        assert!(
            pool.transactions.contains_key(&victim.hash),
            "the evicted victim is back"
        );
        assert!(
            !pool.transactions.contains_key(&accepted.hash),
            "the admitted member is gone"
        );
        assert_eq!(pool.transactions.len(), 1);
        assert_eq!(
            pool.resident_bytes, victim_bytes,
            "the byte counter matches"
        );
    }

    /// A replacement made by an earlier member is undone with the rest.
    #[test]
    fn a_bundle_refused_at_its_last_member_restores_the_replaced_transaction() {
        let mut pool = Mempool::default();
        let original = create_test_tx_from_seed(1, 0, 10);
        pool.add_transaction(original.clone()).expect("admitted");

        let replacement = create_test_tx_from_seed(1, 0, 100);
        let refused = create_test_tx_from_seed(2, 0, 0);
        let err = pool
            .add_transaction_bundle(vec![replacement.clone(), refused])
            .expect_err("the bundle fails at its second member");

        assert_eq!(err.index, 1);
        assert!(
            pool.transactions.contains_key(&original.hash),
            "the replaced transaction is back"
        );
        assert!(!pool.transactions.contains_key(&replacement.hash));
        assert_eq!(pool.transactions.len(), 1);
    }

    /// A bundle whose every member is admissible admits every member.
    #[test]
    fn an_admissible_bundle_admits_every_member() {
        let mut pool = Mempool::default();
        let first = create_test_tx_from_seed(1, 0, 10);
        let second = create_test_tx_from_seed(2, 0, 10);
        pool.add_transaction_bundle(vec![first.clone(), second.clone()])
            .expect("both members are admissible");
        assert!(pool.transactions.contains_key(&first.hash));
        assert!(pool.transactions.contains_key(&second.hash));
        assert_eq!(pool.transactions.len(), 2);
        assert_eq!(
            pool.resident_bytes,
            charged_bytes(&first) + charged_bytes(&second)
        );
        assert!(pool.journal.is_none(), "the journal is released on success");
    }

    /// The byte budget refuses a flood the entry count would admit.
    ///
    /// This is the finding the budget exists for: every transaction here is
    /// individually legal - correctly signed, under the transport's 100 KiB
    /// ceiling, above the fee floor, a fresh nonce - and the pool is nowhere
    /// near `max_size`. Without the budget the pool grows to the product of
    /// the two limits, which on the default configuration is 1.95 GiB.
    #[test]
    fn a_flood_of_legal_transactions_is_refused_by_bytes_not_by_count() {
        let mut pool = Mempool::new(MempoolConfig {
            max_size: 10_000,
            max_per_sender: 100,
            min_fee: 1,
            // 200 KiB: two 64 KiB bodies fit, the third does not.
            max_pool_bytes: 200 * 1024,
            ..Default::default()
        });

        let mut admitted = 0usize;
        let mut refused_by_bytes = false;
        for nonce in 0..8u64 {
            match pool.add_transaction(create_test_tx_sized(9, nonce, 10, 64 * 1024)) {
                Ok(()) => admitted += 1,
                Err(MempoolError::PoolBytesFull) => {
                    refused_by_bytes = true;
                    break;
                }
                Err(other) => panic!("refused for the wrong reason: {other:?}"),
            }
        }

        assert!(
            refused_by_bytes,
            "the pool admitted {admitted} large transactions without reaching its byte budget"
        );
        assert!(
            pool.len() < 10_000,
            "the entry count was never the binding limit, so it must not be what refused"
        );
        assert!(
            pool.resident_bytes() <= pool.max_pool_bytes(),
            "resident {} exceeds the budget {}",
            pool.resident_bytes(),
            pool.max_pool_bytes()
        );
    }

    /// A pool full by count still reports `PoolFull`, not `PoolBytesFull`.
    ///
    /// The two errors tell an operator to do opposite things, so the check
    /// order has to be stable. A generous byte budget with a tiny entry count
    /// must still fail on the count.
    #[test]
    fn a_pool_full_by_count_reports_the_count_error() {
        let mut pool = Mempool::new(MempoolConfig {
            max_size: 2,
            max_per_sender: 100,
            min_fee: 1,
            max_pool_bytes: 64 * 1024 * 1024,
            ..Default::default()
        });
        pool.add_transaction(create_test_tx_sized(1, 0, 10, 16))
            .unwrap();
        pool.add_transaction(create_test_tx_sized(2, 0, 10, 16))
            .unwrap();
        // Same fee as the residents, so it cannot evict either of them.
        assert_eq!(
            pool.add_transaction(create_test_tx_sized(3, 0, 10, 16)),
            Err(MempoolError::PoolFull)
        );
    }

    /// The counter matches a fresh sum of the pool at every step.
    ///
    /// The counter is incremental because summing per insert is O(n) on the
    /// admission path. Incremental counters drift: an early draft charged on
    /// insert and forgot the eviction path, and the pool reported bytes it no
    /// longer held until it refused everything. Re-deriving the total is the
    /// only thing that catches that class.
    #[test]
    fn resident_bytes_are_exact() {
        let mut pool = Mempool::new(MempoolConfig {
            max_size: 100,
            max_per_sender: 100,
            min_fee: 1,
            max_pool_bytes: 8 * 1024 * 1024,
            ..Default::default()
        });

        let recompute = |p: &Mempool| -> usize {
            p.transactions
                .values()
                .map(|e| charged_bytes(&e.tx))
                .sum::<usize>()
        };

        let mut hashes = Vec::new();
        for seed in 1..=5u8 {
            let tx = create_test_tx_sized(seed, 0, 10, usize::from(seed) * 512);
            hashes.push(tx.hash.clone());
            pool.add_transaction(tx).unwrap();
            assert_eq!(pool.resident_bytes(), recompute(&pool), "after an insert");
        }

        for hash in &hashes {
            pool.remove_transaction(hash);
            assert_eq!(pool.resident_bytes(), recompute(&pool), "after a removal");
        }
        assert_eq!(pool.resident_bytes(), 0, "an emptied pool holds no bytes");
    }

    /// A drained pool holds no bytes and still admits transactions.
    #[test]
    fn a_drained_pool_forgets_its_bytes() {
        let mut pool = Mempool::new(MempoolConfig {
            max_size: 100,
            max_per_sender: 100,
            min_fee: 1,
            max_pool_bytes: 80 * 1024,
            ..Default::default()
        });
        pool.add_transaction(create_test_tx_sized(1, 0, 10, 32 * 1024))
            .unwrap();
        pool.add_transaction(create_test_tx_sized(2, 0, 10, 32 * 1024))
            .unwrap();
        assert_eq!(pool.drain().len(), 2);
        assert_eq!(
            pool.resident_bytes(),
            0,
            "a drained pool still charges bytes"
        );
        pool.add_transaction(create_test_tx_sized(3, 0, 10, 32 * 1024))
            .expect("a drained pool must still admit transactions");
    }

    /// A replacement is charged the difference, not the whole body.
    ///
    /// RBF frees the slot it takes. Charging the replacement without crediting
    /// the transaction it replaces would make a sequence of legal fee bumps
    /// look like a flood, and the pool would refuse its own replacement rule.
    #[test]
    fn a_replacement_is_charged_only_the_difference() {
        let mut pool = Mempool::new(MempoolConfig {
            max_size: 100,
            max_per_sender: 100,
            min_fee: 1,
            // Room for one 32 KiB body and very little else.
            max_pool_bytes: 40 * 1024,
            ..Default::default()
        });

        pool.add_transaction(create_test_tx_sized(4, 0, 10, 32 * 1024))
            .unwrap();
        let before = pool.resident_bytes();

        // Same sender, same nonce, higher fee: a replacement.
        pool.add_transaction(create_test_tx_sized(4, 0, 100, 32 * 1024))
            .expect("a fee bump must not be refused for bytes it is about to free");

        assert_eq!(pool.len(), 1, "the replacement did not replace");
        assert_eq!(
            pool.resident_bytes(),
            before,
            "a same-size replacement changed the resident total"
        );
    }

    /// A refused admission leaves the pool exactly as it was.
    ///
    /// The eviction ordering above the byte check exists because a refusal
    /// that had already deleted somebody else's transaction is a free deletion
    /// primitive: the attacker pays no fee and occupies no slot. The byte
    /// budget must not reintroduce it.
    #[test]
    fn a_byte_refusal_deletes_nothing() {
        let mut pool = Mempool::new(MempoolConfig {
            max_size: 100,
            max_per_sender: 100,
            min_fee: 1,
            max_pool_bytes: 80 * 1024,
            ..Default::default()
        });

        // Two expensive residents fill the budget.
        pool.add_transaction(create_test_tx_sized(1, 0, 1_000, 32 * 1024))
            .unwrap();
        pool.add_transaction(create_test_tx_sized(2, 0, 1_000, 32 * 1024))
            .unwrap();
        let before_len = pool.len();
        let before_bytes = pool.resident_bytes();

        // A cheap newcomer cannot evict either of them, so it must be refused
        // and must not have removed anything on the way out.
        assert_eq!(
            pool.add_transaction(create_test_tx_sized(3, 0, 2, 32 * 1024)),
            Err(MempoolError::PoolBytesFull)
        );
        assert_eq!(pool.len(), before_len, "a refusal evicted a resident");
        assert_eq!(pool.resident_bytes(), before_bytes);
    }

    /// A richer transaction evicts cheaper ones until its bytes fit.
    ///
    /// The count-based eviction frees one slot because one slot is what a
    /// count needs. Bytes are not one-for-one: a large newcomer may need
    /// several small victims, and stopping after the first would refuse a
    /// transaction the pool had room for.
    #[test]
    fn a_richer_transaction_evicts_until_its_bytes_fit() {
        let mut pool = Mempool::new(MempoolConfig {
            max_size: 100,
            max_per_sender: 100,
            min_fee: 1,
            max_pool_bytes: 70 * 1024,
            ..Default::default()
        });

        // Four cheap 16 KiB residents, from four distinct senders.
        for seed in 1..=4u8 {
            pool.add_transaction(create_test_tx_sized(seed, 0, 5, 16 * 1024))
                .unwrap();
        }
        assert_eq!(pool.len(), 4);

        // A rich 48 KiB newcomer needs three of them gone.
        pool.add_transaction(create_test_tx_sized(9, 0, 500, 48 * 1024))
            .expect("a fee-beating transaction must be able to make room");

        assert!(
            pool.resident_bytes() <= pool.max_pool_bytes(),
            "the pool overshot its budget after eviction"
        );
        assert!(
            pool.get_sorted_transactions(10)
                .iter()
                .any(|t| t.fee == 500),
            "the rich transaction was not admitted"
        );
    }

    #[test]
    fn test_add_and_get() {
        let mut pool = Mempool::default();
        let tx = create_test_tx_from_seed(1, 0, 10);
        assert!(pool.add_transaction(tx.clone()).is_ok());
        assert_eq!(pool.len(), 1);
        assert!(pool.get(&tx.hash).is_some());
    }

    #[test]
    fn cleanup_tolerates_wall_clock_rollback() {
        let mut pool = Mempool::default();
        let tx = create_test_tx_from_seed(1, 0, 10);
        let hash = tx.hash.clone();
        pool.add_transaction(tx).unwrap();
        pool.transactions.get_mut(&hash).unwrap().added_at = u128::MAX;

        assert_eq!(pool.cleanup_expired(), 0);
        assert!(pool.get(&hash).is_some());
    }

    #[test]
    fn test_duplicate_rejection() {
        let mut pool = Mempool::default();
        let tx = create_test_tx_from_seed(1, 0, 10);
        pool.add_transaction(tx.clone()).unwrap();
        assert_eq!(
            pool.add_transaction(tx),
            Err(MempoolError::DuplicateTransaction)
        );
    }

    /// Cheap checks run before the signature check (audit): an
    /// unsigned transaction below the fee floor is refused as `FeeTooLow`,
    /// which proves `verify` did not run first.
    #[test]
    fn cheap_checks_run_before_signature_verification() {
        let mut pool = Mempool::default();
        let mut tx = create_test_tx_from_seed(1, 0, 0);
        tx.signature = None;
        assert!(!tx.verify());
        assert_eq!(pool.add_transaction(tx), Err(MempoolError::FeeTooLow));

        let good = create_test_tx_from_seed(2, 0, 10);
        pool.add_transaction(good.clone()).unwrap();
        let mut forged = good;
        forged.signature = None;
        assert_eq!(
            pool.add_transaction(forged),
            Err(MempoolError::DuplicateTransaction)
        );

        let mut bad = create_test_tx_from_seed(3, 0, 10);
        bad.signature = None;
        assert!(matches!(
            pool.add_transaction(bad),
            Err(MempoolError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn test_fee_too_low() {
        let mut pool = Mempool::default();
        let tx = create_test_tx_from_seed(1, 0, 0);
        assert_eq!(pool.add_transaction(tx), Err(MempoolError::FeeTooLow));
    }

    #[test]
    fn test_sender_limit() {
        let config = MempoolConfig {
            max_per_sender: 2,
            ..Default::default()
        };
        let mut pool = Mempool::new(config);

        let alice_seed = 1u8;
        pool.add_transaction(create_test_tx_from_seed(alice_seed, 0, 10))
            .unwrap();
        pool.add_transaction(create_test_tx_from_seed(alice_seed, 1, 10))
            .unwrap();
        assert_eq!(
            pool.add_transaction(create_test_tx_from_seed(alice_seed, 2, 10)),
            Err(MempoolError::SenderLimitReached)
        );
    }

    #[test]
    fn test_sorted_by_fee() {
        let mut pool = Mempool::default();
        pool.add_transaction(create_test_tx_from_seed(1, 0, 5))
            .unwrap();
        pool.add_transaction(create_test_tx_from_seed(2, 0, 20))
            .unwrap();
        pool.add_transaction(create_test_tx_from_seed(3, 0, 10))
            .unwrap();

        let sorted = pool.get_sorted_transactions(10);
        assert_eq!(sorted[0].fee, 20);
        assert_eq!(sorted[1].fee, 10);
        assert_eq!(sorted[2].fee, 5);
    }

    #[test]
    fn test_rbf() {
        let mut pool = Mempool::default();
        let alice_seed = 1u8;
        let tx1 = create_test_tx_from_seed(alice_seed, 0, 10);
        pool.add_transaction(tx1).unwrap();

        // Same sender+nonce, higher fee - RBF replace.
        let tx2 = create_test_tx_from_seed(alice_seed, 0, 15);
        assert!(pool.add_transaction(tx2).is_ok());
        assert_eq!(pool.len(), 1);
    }

    /// The same-fee tie-break is canonical (tx.hash ASC). A different
    /// insertion order MUST NOT change the result - the old HashSet path, with
    /// its process-random iteration, would differ between the two pools in
    /// this test (flaky, and a nondeterministic block body order in
    /// production).
    #[test]
    fn test_same_fee_canonical_order_by_hash() {
        // Three different senders with same fee - canonical order by tx.hash.
        let tx_a = create_test_tx_from_seed(1, 0, 10);
        let tx_b = create_test_tx_from_seed(2, 0, 10);
        let tx_c = create_test_tx_from_seed(3, 0, 10);

        let mut hashes = vec![tx_a.hash.clone(), tx_b.hash.clone(), tx_c.hash.clone()];
        hashes.sort();
        // Verify all hashes are distinct
        assert_eq!(hashes.len(), 3);

        let mut pool1 = Mempool::default();
        pool1.add_transaction(tx_c.clone()).unwrap();
        pool1.add_transaction(tx_a.clone()).unwrap();
        pool1.add_transaction(tx_b.clone()).unwrap();
        let order1: Vec<String> = pool1
            .get_sorted_transactions(10)
            .iter()
            .map(|t| t.hash.clone())
            .collect();
        assert_eq!(order1, hashes);

        // A different insertion order, the same canonical output.
        let mut pool2 = Mempool::default();
        pool2.add_transaction(tx_b).unwrap();
        pool2.add_transaction(tx_c).unwrap();
        pool2.add_transaction(tx_a).unwrap();
        let order2: Vec<String> = pool2
            .get_sorted_transactions(10)
            .iter()
            .map(|t| t.hash.clone())
            .collect();
        assert_eq!(order1, order2);
    }

    /// RBF replace her zaman kat'i pozitif bump ister.
    /// The old path: fee=1, 10 percent -> bump=0 -> replacement at the same
    /// fee (the churn vector).
    #[test]
    fn test_rbf_requires_strict_positive_bump() {
        let mut pool = Mempool::default();
        let alice_seed = 1u8;
        let tx1 = create_test_tx_from_seed(alice_seed, 0, 1);
        pool.add_transaction(tx1).unwrap();

        // Replacement at the same fee is REFUSED. Use nonce 1 to get a
        // different hash, then come back to nonce 0 and test the fee bump
        // check.
        // Tx2: same sender, same nonce (0), same fee (1), different data → different hash.
        let seed = [alice_seed; 32];
        let keypair = crate::crypto::primitives::KeyPair::from_seed(&seed).unwrap();
        let from = crate::core::address::Address::from(keypair.public_key_bytes());

        let mut tx2 = Transaction::new(
            from,
            crate::core::address::Address::zero(),
            100,
            b"v2".to_vec(),
        );
        tx2.nonce = 0;
        tx2.fee = 1;
        tx2.hash = tx2.calculate_hash();
        tx2.sign(&keypair);
        assert_eq!(pool.add_transaction(tx2), Err(MempoolError::RbfFeeTooLow));

        // Fee=2 (10% ⇒ ceil(0.1)=1 ⇒ min 2) ACCEPTED.
        let mut tx3 = Transaction::new(
            from,
            crate::core::address::Address::zero(),
            100,
            b"v3".to_vec(),
        );
        tx3.nonce = 0;
        tx3.fee = 2;
        tx3.hash = tx3.calculate_hash();
        tx3.sign(&keypair);
        assert!(pool.add_transaction(tx3).is_ok());
        assert_eq!(pool.len(), 1);

        // Fee=100 (10% ⇒ bump=10 ⇒ min 110): 109 REFUSED, 110 ACCEPTED.
        let mut tx4 = Transaction::new(
            from,
            crate::core::address::Address::zero(),
            100,
            b"v4".to_vec(),
        );
        tx4.nonce = 1;
        tx4.fee = 100;
        tx4.hash = tx4.calculate_hash();
        tx4.sign(&keypair);
        pool.add_transaction(tx4).unwrap();

        let mut tx5 = Transaction::new(
            from,
            crate::core::address::Address::zero(),
            100,
            b"v5".to_vec(),
        );
        tx5.nonce = 1;
        tx5.fee = 109;
        tx5.hash = tx5.calculate_hash();
        tx5.sign(&keypair);
        assert_eq!(pool.add_transaction(tx5), Err(MempoolError::RbfFeeTooLow));

        let mut tx6 = Transaction::new(
            from,
            crate::core::address::Address::zero(),
            100,
            b"v6".to_vec(),
        );
        tx6.nonce = 1;
        tx6.fee = 110;
        tx6.hash = tx6.calculate_hash();
        tx6.sign(&keypair);
        assert!(pool.add_transaction(tx6).is_ok());
    }

    #[test]
    fn test_cleanup_expired() {
        let config = MempoolConfig {
            tx_ttl_secs: 1,
            ..Default::default()
        };
        let mut pool = Mempool::new(config);

        let tx = create_test_tx_from_seed(1, 0, 10);
        pool.add_transaction(tx).unwrap();
        assert_eq!(pool.len(), 1);

        std::thread::sleep(std::time::Duration::from_secs(2));

        let removed = pool.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
    }

    /// Eviction must not let a sender exceed its own cap.
    ///
    /// `evict_lowest_fee` picks the globally lowest-fee transaction with no
    /// regard for whose it is, so it can drop one belonging to the very sender
    /// being admitted. The count used to be read *before* that ran, so the cap
    /// was compared against a number eviction had already invalidated.
    ///
    /// Measured with a canary before the fix, at `max_per_sender = 2`:
    ///
    ///     A holds 2, pool is full, A submits a third at a higher fee -> Ok(())
    ///
    /// The per-sender cap exists so one account cannot occupy the pool, and it
    /// stopped holding exactly when the pool was full and contention mattered.
    #[test]
    fn a_full_pool_does_not_let_a_sender_past_its_own_cap() {
        let mut pool = Mempool::new(MempoolConfig {
            max_size: 4,
            max_per_sender: 2,
            min_fee: 0,
            ..MempoolConfig::default()
        });

        let kp_a = crate::crypto::primitives::KeyPair::generate().expect("keypair");
        let kp_b = crate::crypto::primitives::KeyPair::generate().expect("keypair");
        let a = crate::core::address::Address::from(kp_a.public_key_bytes());

        let mk = |kp: &crate::crypto::primitives::KeyPair, nonce: u64, fee: u64| {
            let from = crate::core::address::Address::from(kp.public_key_bytes());
            let mut tx = Transaction::new_with_chain_id(
                from,
                crate::core::address::Address::zero(),
                1,
                fee,
                nonce,
                vec![],
                crate::core::transaction::DEFAULT_CHAIN_ID,
                crate::core::transaction::TransactionType::Transfer,
            );
            tx.sign(kp);
            tx.hash = tx.calculate_hash();
            tx
        };

        // A fills its cap; B fills the rest, so the pool is full.
        for n in 0..2u64 {
            pool.add_transaction(mk(&kp_a, n, 1)).expect("A within cap");
        }
        for n in 0..2u64 {
            pool.add_transaction(mk(&kp_b, n, 1)).expect("B within cap");
        }
        assert_eq!(pool.transactions.len(), 4, "pool should be full");
        assert_eq!(
            pool.by_sender
                .get(&a)
                .map_or(0, std::collections::BTreeMap::len),
            2
        );

        // A is at its cap. A high fee may win eviction, but it must not buy a
        // third slot for a sender that already holds two.
        let err = pool
            .add_transaction(mk(&kp_a, 2, 99))
            .expect_err("a sender at its cap must be refused even with a high fee");
        assert!(
            matches!(err, MempoolError::SenderLimitReached),
            "unexpected error: {err:?}"
        );
        assert!(
            pool.by_sender
                .get(&a)
                .map_or(0, std::collections::BTreeMap::len)
                <= 2,
            "A holds more than max_per_sender after a rejected admission"
        );
    }

    /// A refused transaction must not delete somebody else's transaction.
    ///
    /// Eviction used to run before the per-sender cap and the RBF rule were
    /// checked, so a submission that was then rejected still left the victim
    /// gone. The attacker paid nothing, occupied no slot, and could repeat:
    /// a free deletion primitive against other users' pending transactions.
    ///
    /// The two rejection paths are tested separately because they leave the
    /// function at different points.
    #[test]
    fn a_rejected_transaction_evicts_nobody() {
        let mk = |kp: &crate::crypto::primitives::KeyPair, nonce: u64, fee: u64| {
            let from = crate::core::address::Address::from(kp.public_key_bytes());
            let mut tx = Transaction::new_with_chain_id(
                from,
                crate::core::address::Address::zero(),
                1,
                fee,
                nonce,
                vec![],
                crate::core::transaction::DEFAULT_CHAIN_ID,
                crate::core::transaction::TransactionType::Transfer,
            );
            tx.sign(kp);
            tx.hash = tx.calculate_hash();
            tx
        };

        // Path 1: refused by the per-sender cap.
        let mut pool = Mempool::new(MempoolConfig {
            max_size: 4,
            max_per_sender: 2,
            min_fee: 0,
            ..MempoolConfig::default()
        });
        let kp_a = crate::crypto::primitives::KeyPair::generate().expect("keypair");
        let kp_b = crate::crypto::primitives::KeyPair::generate().expect("keypair");
        for n in 0..2u64 {
            pool.add_transaction(mk(&kp_a, n, 1)).expect("A within cap");
        }
        for n in 0..2u64 {
            pool.add_transaction(mk(&kp_b, n, 1)).expect("B within cap");
        }
        let before: std::collections::BTreeSet<String> =
            pool.transactions.keys().cloned().collect();
        let err = pool
            .add_transaction(mk(&kp_a, 2, 99))
            .expect_err("a sender at its cap must be refused");
        assert!(matches!(err, MempoolError::SenderLimitReached));
        let after: std::collections::BTreeSet<String> = pool.transactions.keys().cloned().collect();
        assert_eq!(
            before, after,
            "a cap-rejected submission removed a transaction from the pool"
        );

        // Path 2: refused by the RBF bump rule. Same sender and nonce as an
        // entry already held, so this one reaches the replacement branch.
        let mut pool = Mempool::new(MempoolConfig {
            max_size: 3,
            max_per_sender: 5,
            min_fee: 0,
            rbf_bump_percent: 10,
            ..MempoolConfig::default()
        });
        let kp_c = crate::crypto::primitives::KeyPair::generate().expect("keypair");
        let kp_d = crate::crypto::primitives::KeyPair::generate().expect("keypair");
        pool.add_transaction(mk(&kp_c, 0, 100)).expect("C admitted");
        pool.add_transaction(mk(&kp_d, 0, 1)).expect("D admitted");
        pool.add_transaction(mk(&kp_d, 1, 1)).expect("D admitted");
        assert_eq!(pool.transactions.len(), 3, "pool should be full");
        let before: std::collections::BTreeSet<String> =
            pool.transactions.keys().cloned().collect();
        // Same nonce as C's entry, fee above D's cheap entries but below the
        // required bump over C's own 100.
        let err = pool
            .add_transaction(mk(&kp_c, 0, 50))
            .expect_err("an under-bumped replacement must be refused");
        assert!(matches!(err, MempoolError::RbfFeeTooLow));
        let after: std::collections::BTreeSet<String> = pool.transactions.keys().cloned().collect();
        assert_eq!(
            before, after,
            "an RBF-rejected submission removed a transaction from the pool"
        );
    }

    /// A replacement must still be admitted when the pool is full.
    ///
    /// Deferring eviction is only correct if the replacement path never needs
    /// it: the incoming transaction frees the slot it takes. A full pool that
    /// refused replacements would freeze every pending nonce in place.
    #[test]
    fn a_full_pool_still_accepts_a_replacement() {
        let mk = |kp: &crate::crypto::primitives::KeyPair, nonce: u64, fee: u64| {
            let from = crate::core::address::Address::from(kp.public_key_bytes());
            let mut tx = Transaction::new_with_chain_id(
                from,
                crate::core::address::Address::zero(),
                1,
                fee,
                nonce,
                vec![],
                crate::core::transaction::DEFAULT_CHAIN_ID,
                crate::core::transaction::TransactionType::Transfer,
            );
            tx.sign(kp);
            tx.hash = tx.calculate_hash();
            tx
        };
        let mut pool = Mempool::new(MempoolConfig {
            max_size: 2,
            max_per_sender: 5,
            min_fee: 0,
            rbf_bump_percent: 10,
            ..MempoolConfig::default()
        });
        let kp_a = crate::crypto::primitives::KeyPair::generate().expect("keypair");
        let kp_b = crate::crypto::primitives::KeyPair::generate().expect("keypair");
        pool.add_transaction(mk(&kp_a, 0, 10)).expect("A admitted");
        pool.add_transaction(mk(&kp_b, 0, 10)).expect("B admitted");
        assert_eq!(pool.transactions.len(), 2, "pool should be full");

        pool.add_transaction(mk(&kp_a, 0, 100))
            .expect("a properly bumped replacement must be accepted in a full pool");
        assert_eq!(pool.transactions.len(), 2, "replacement changed the size");
        let b = crate::core::address::Address::from(kp_b.public_key_bytes());
        assert_eq!(
            pool.by_sender
                .get(&b)
                .map_or(0, std::collections::BTreeMap::len),
            1,
            "the replacement evicted an unrelated sender"
        );
    }

    /// The cap still admits a sender that has room, even when eviction runs.
    ///
    /// Otherwise the fix above would be a gate that rejects everything.
    #[test]
    fn eviction_still_admits_a_sender_with_room() {
        let mut pool = Mempool::new(MempoolConfig {
            max_size: 3,
            max_per_sender: 5,
            min_fee: 0,
            ..MempoolConfig::default()
        });

        let kp_a = crate::crypto::primitives::KeyPair::generate().expect("keypair");
        let kp_b = crate::crypto::primitives::KeyPair::generate().expect("keypair");

        let mk = |kp: &crate::crypto::primitives::KeyPair, nonce: u64, fee: u64| {
            let from = crate::core::address::Address::from(kp.public_key_bytes());
            let mut tx = Transaction::new_with_chain_id(
                from,
                crate::core::address::Address::zero(),
                1,
                fee,
                nonce,
                vec![],
                crate::core::transaction::DEFAULT_CHAIN_ID,
                crate::core::transaction::TransactionType::Transfer,
            );
            tx.sign(kp);
            tx.hash = tx.calculate_hash();
            tx
        };

        for n in 0..3u64 {
            pool.add_transaction(mk(&kp_b, n, 1)).expect("B fills pool");
        }
        // A has room under its own cap and outbids the floor.
        pool.add_transaction(mk(&kp_a, 0, 50))
            .expect("a sender with room must still get in by outbidding");
        assert_eq!(pool.transactions.len(), 3, "pool stays at max_size");
    }

    /// Two nodes with the same mempool must evict the same transaction.
    ///
    /// `hashes.iter().next()` returned an arbitrary element of a `HashSet`, so
    /// the victim depended on hash iteration order. Nothing in consensus reads
    /// the mempool directly, so this was not a fork, but it made block
    /// contents depend on allocator state, and it made
    /// `a_full_pool_does_not_let_a_sender_past_its_own_cap` fail about one run
    /// in five, which is how it was found.
    #[test]
    fn eviction_picks_the_lowest_hash_among_equal_fees() {
        let kps: Vec<crate::crypto::primitives::KeyPair> = (0..3)
            .map(|_| crate::crypto::primitives::KeyPair::generate().expect("keypair"))
            .collect();
        let bidder = crate::crypto::primitives::KeyPair::generate().expect("keypair");

        let mk = |kp: &crate::crypto::primitives::KeyPair, nonce: u64, fee: u64| {
            let from = crate::core::address::Address::from(kp.public_key_bytes());
            let mut tx = Transaction::new_with_chain_id(
                from,
                crate::core::address::Address::zero(),
                1,
                fee,
                nonce,
                vec![],
                crate::core::transaction::DEFAULT_CHAIN_ID,
                crate::core::transaction::TransactionType::Transfer,
            );
            tx.sign(kp);
            tx.hash = tx.calculate_hash();
            tx
        };

        let mut pool = Mempool::new(MempoolConfig {
            max_size: 3,
            max_per_sender: 5,
            min_fee: 0,
            ..MempoolConfig::default()
        });

        // Three transactions at the same fee. The tie-break must be the
        // smallest hash, not whatever the set yields first.
        let mut seeded: Vec<String> = Vec::new();
        for kp in &kps {
            let tx = mk(kp, 0, 1);
            seeded.push(tx.hash.clone());
            pool.add_transaction(tx).expect("seed");
        }
        let expected_victim = seeded.iter().min().expect("three seeds").clone();

        pool.add_transaction(mk(&bidder, 0, 99)).expect("outbid");

        assert!(
            !pool.transactions.contains_key(&expected_victim),
            "the smallest hash among equal fees should have been evicted"
        );
        for hash in seeded.iter().filter(|h| **h != expected_victim) {
            assert!(
                pool.transactions.contains_key(hash),
                "only one equal-fee entry should be evicted"
            );
        }
    }
}
