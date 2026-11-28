//! Isolated UEL transaction mempool lanes (Section 8.6.3).
//!
//! Each envelope format owns an independent lane with its own capacity budget
//! and replay/ordering rule so congestion in one lane never starves another:
//!
//! 1. `Local` (native post-quantum envelopes, ordered by account `nonce`).
//! 2. `Ethereum` (foreign EIP-155 envelopes, ordered by EVM `nonce`).
//! 3. `Solana` (foreign versioned txs, 150-block recent blockhash window + sig dedup).
//! 4. `Aptos` (foreign BCS `SignedTransaction`, `sequence_number` + `expiration_unix_s`).
//! 5. `Cosmos` (foreign `TxRaw`, `account_number` + `sequence`).
//! 6. `Duty` (mobile/full validator duty batches, rate-limited to 1 per window).
//!
//! Block proposers draw across all non-empty lanes ordered by effective
//! priority fee per BGU (`effective_priority_fee_atto`).
//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

/// Recent blockhash window length for the Solana foreign lane (Section 8.6.2).
pub const SOLANA_BLOCKHASH_WINDOW: usize = 150;

/// The 32-byte digest the Solana lane keeps for a 64-byte signature.
///
/// The lane stores one digest per signature, not the signature itself, because
/// the cache outlives the transaction and a digest is not a credential.
fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes).into()
}

/// Envelope lane classification (Section 8.6.3 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LaneKind {
    Local,
    Ethereum,
    Solana,
    Aptos,
    Cosmos,
    Duty,
}

/// Replay and ordering metadata attached to a lane entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaneReplayRule {
    /// Monotonic account nonce (`Local` and `Ethereum`).
    AccountNonce { sender: [u8; 32], nonce: u64 },
    /// Solana recent-blockhash + 64-byte signature replay check.
    SolanaWindow {
        recent_blockhash: [u8; 32],
        signature_digest: [u8; 32],
    },
    /// Aptos sequence number with strict expiration timestamp.
    AptosSequence {
        sender: [u8; 32],
        sequence: u64,
        expiration_unix_s: u64,
    },
    /// Cosmos `(account_number, sequence)` pair.
    CosmosSequence {
        sender: [u8; 32],
        account_number: u64,
        sequence: u64,
    },
    /// Validator duty batch bounded to one submission per `(validator, window_id)`.
    DutyWindow { validator: [u8; 32], window_id: u64 },
}

/// One admitted transaction sitting in a UEL mempool lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneEntry {
    pub tx_hash: [u8; 32],
    pub lane: LaneKind,
    pub replay: LaneReplayRule,
    pub gas_limit_bgu: u64,
    pub max_fee_per_bgu_atto: u128,
    pub max_priority_fee_per_bgu_atto: u128,
    pub raw_bytes: Vec<u8>,
}

impl LaneEntry {
    /// Effective priority tip per BGU at `base_fee_atto`, or `None` if unaffordable.
    #[must_use]
    pub fn effective_priority_fee(&self, base_fee_atto: u128) -> Option<u128> {
        let headroom = self.max_fee_per_bgu_atto.checked_sub(base_fee_atto)?;
        Some(headroom.min(self.max_priority_fee_per_bgu_atto))
    }
}

/// Refusal reasons when admitting an entry into [`MultiLaneMempool`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaneAdmissionError {
    /// Replay rule variant did not match `entry.lane`.
    MismatchedReplayRule,
    /// Target lane reached its independent entry or byte cap.
    LaneFull(LaneKind),
    /// Duplicate transaction hash or replayed nonce/signature/duty window.
    ReplayRejected(&'static str),
    /// Expired Aptos transaction or unknown Solana recent blockhash.
    StaleOrExpired(&'static str),
    /// A Solana envelope failed strict decoding or carried no execution budget.
    InvalidSolana(&'static str),
    /// The envelope declared no execution budget, or a tip above its own fee cap.
    Unfunded(&'static str),
}

impl fmt::Display for LaneAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MismatchedReplayRule => write!(f, "replay rule does not match lane kind"),
            Self::LaneFull(lane) => write!(f, "mempool lane {lane:?} is full"),
            Self::ReplayRejected(why) => write!(f, "replay rejected: {why}"),
            Self::StaleOrExpired(why) => write!(f, "stale or expired envelope: {why}"),
            Self::InvalidSolana(why) => write!(f, "invalid Solana envelope: {why}"),
            Self::Unfunded(why) => write!(f, "unfunded envelope: {why}"),
        }
    }
}

impl std::error::Error for LaneAdmissionError {}

#[derive(Debug, Default, Clone)]
struct SingleLane {
    entries: BTreeMap<[u8; 32], LaneEntry>,
    used_bytes: usize,
    /// `(sender, sequence, isolator)`: the isolator is the Cosmos
    /// `account_number` and zero for every lane whose sequence is per sender.
    sender_nonces: BTreeSet<([u8; 32], u64, u64)>,
}

/// Default maximum blocks a valid FOCIL inclusion transaction may wait before
/// receiving guaranteed reserve inclusion priority in block assembly.
pub const FOCIL_DEFAULT_MAX_WAIT_BLOCKS: u64 = 4;

/// Maximum share (25% = 2,500 bps) of block BGU budget reserved for overdue
/// FOCIL inclusion transactions so priority-fee markets remain healthy.
pub const FOCIL_BLOCK_BGU_RESERVE_BPS: u64 = 2_500;

/// Metadata tracking an inclusion-list candidate under FOCIL censorship resistance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FocilEntry {
    pub tx_hash: [u8; 32],
    pub first_seen_block: u64,
    pub max_wait_blocks: u64,
}

/// Censorship-resistant FOCIL inclusion tracker layered onto [`MultiLaneMempool`].
#[derive(Debug, Clone, Default)]
pub struct FocilInclusionQueue {
    entries: BTreeMap<[u8; 32], FocilEntry>,
}

impl FocilInclusionQueue {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn record(&mut self, tx_hash: [u8; 32], current_block: u64, max_wait_blocks: u64) {
        let wait = max_wait_blocks.max(1);
        self.entries.entry(tx_hash).or_insert(FocilEntry {
            tx_hash,
            first_seen_block: current_block,
            max_wait_blocks: wait,
        });
    }

    pub fn remove(&mut self, tx_hash: &[u8; 32]) {
        self.entries.remove(tx_hash);
    }

    #[must_use]
    pub fn is_overdue(&self, tx_hash: &[u8; 32], current_block: u64) -> bool {
        self.entries
            .get(tx_hash)
            .is_some_and(|e| current_block.saturating_sub(e.first_seen_block) >= e.max_wait_blocks)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Six-lane isolated transaction pool with priority-fee cross-lane selection.
#[derive(Debug, Clone)]
pub struct MultiLaneMempool {
    max_entries_per_lane: usize,
    max_bytes_per_lane: usize,
    lanes: BTreeMap<LaneKind, SingleLane>,
    recent_blockhashes: VecDeque<[u8; 32]>,
    seen_solana_sigs: BTreeSet<[u8; 32]>,
    solana_sigs_by_blockhash: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
    seen_duty_windows: BTreeSet<([u8; 32], u64)>,
    focil_queue: FocilInclusionQueue,
}

impl MultiLaneMempool {
    /// Create a multi-lane pool with isolated per-lane entry and byte caps.
    ///
    /// Convenience: exposed for node mempool initialization and lane-isolation tests.
    #[must_use]
    pub fn new(max_entries_per_lane: usize, max_bytes_per_lane: usize) -> Self {
        Self {
            max_entries_per_lane,
            max_bytes_per_lane,
            lanes: BTreeMap::new(),
            recent_blockhashes: VecDeque::new(),
            seen_solana_sigs: BTreeSet::new(),
            solana_sigs_by_blockhash: BTreeMap::new(),
            seen_duty_windows: BTreeSet::new(),
            focil_queue: FocilInclusionQueue::new(),
        }
    }

    /// Track an admitted lane transaction inside the censorship-resistant FOCIL inclusion queue.
    pub fn track_focil(&mut self, tx_hash: [u8; 32], current_block: u64, max_wait_blocks: u64) {
        self.focil_queue
            .record(tx_hash, current_block, max_wait_blocks);
    }

    /// Return queued entries whose wait age has reached their FOCIL inclusion deadline.
    #[must_use]
    pub fn overdue_focil_entries(&self, current_block: u64) -> Vec<LaneEntry> {
        let mut out = Vec::new();
        for lane in self.lanes.values() {
            for entry in lane.entries.values() {
                if self.focil_queue.is_overdue(&entry.tx_hash, current_block) {
                    out.push(entry.clone());
                }
            }
        }
        out.sort_by_key(|e| {
            let age = self
                .focil_queue
                .entries
                .get(&e.tx_hash)
                .map_or(0, |f| current_block.saturating_sub(f.first_seen_block));
            (std::cmp::Reverse(age), e.tx_hash)
        });
        out
    }

    /// FOCIL-aware block selection: allocates up to 25% of `block_bgu_budget` to overdue
    /// inclusion-aged transactions first (anti-censorship guarantee), then fills the
    /// remaining budget with highest effective priority fee across all lanes.
    #[must_use]
    pub fn select_for_block_with_focil(
        &self,
        base_fee_atto: u128,
        block_bgu_budget: u64,
        current_block: u64,
    ) -> Vec<LaneEntry> {
        let reserve_bgu = block_bgu_budget.saturating_mul(FOCIL_BLOCK_BGU_RESERVE_BPS) / 10_000;
        let mut picked = Vec::new();
        let mut picked_hashes = BTreeSet::new();
        let mut used_bgu: u64 = 0;

        for entry in self.overdue_focil_entries(current_block) {
            if entry.max_fee_per_bgu_atto < base_fee_atto {
                continue;
            }
            if used_bgu.saturating_add(entry.gas_limit_bgu) <= reserve_bgu {
                used_bgu = used_bgu.saturating_add(entry.gas_limit_bgu);
                picked_hashes.insert(entry.tx_hash);
                picked.push(entry);
            }
        }

        for entry in self.select_for_block(base_fee_atto, block_bgu_budget) {
            if picked_hashes.contains(&entry.tx_hash) {
                continue;
            }
            if used_bgu.saturating_add(entry.gas_limit_bgu) <= block_bgu_budget {
                used_bgu = used_bgu.saturating_add(entry.gas_limit_bgu);
                picked_hashes.insert(entry.tx_hash);
                picked.push(entry);
            }
        }
        picked
    }

    /// Record a new canonical Budlum block hash, retaining the latest 150 hashes.
    ///
    /// Convenience: called at block commit to advance the Solana blockhash window.
    pub fn push_recent_blockhash(&mut self, block_hash: [u8; 32]) {
        if let Some(position) = self
            .recent_blockhashes
            .iter()
            .position(|existing| *existing == block_hash)
        {
            let _ = self.recent_blockhashes.remove(position);
        }
        if self.recent_blockhashes.len() >= SOLANA_BLOCKHASH_WINDOW {
            if let Some(expired) = self.recent_blockhashes.pop_front() {
                if let Some(signatures) = self.solana_sigs_by_blockhash.remove(&expired) {
                    for signature in signatures {
                        self.seen_solana_sigs.remove(&signature);
                    }
                }
            }
        }
        self.recent_blockhashes.push_back(block_hash);

        if let Some(lane) = self.lanes.get_mut(&LaneKind::Solana) {
            let recent = &self.recent_blockhashes;
            let expired: Vec<[u8; 32]> = lane
                .entries
                .iter()
                .filter(|(_, entry)| {
                    matches!(
                        &entry.replay,
                        LaneReplayRule::SolanaWindow { recent_blockhash, .. }
                            if !recent.contains(recent_blockhash)
                    )
                })
                .map(|(hash, _)| *hash)
                .collect();
            for hash in expired {
                if let Some(entry) = lane.entries.remove(&hash) {
                    lane.used_bytes = lane.used_bytes.saturating_sub(entry.raw_bytes.len());
                }
            }
        }
    }

    /// Strictly decode and admit one Solana wire transaction with its execution budget.
    ///
    /// The method decodes internally so callers cannot pair a valid hash with a
    /// different fee payer, signature, blockhash, or raw envelope. The complete
    /// transaction hash identifies the entry; the fee-payer signature is the
    /// independent replay key. Both raw bytes and BGU/fee limits are retained
    /// for block selection and execution.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn admit_foreign_solana(
        &mut self,
        raw_wire: &[u8],
        gas_limit_bgu: u64,
        max_fee_per_bgu_atto: u128,
        max_priority_fee_per_bgu_atto: u128,
        now_unix_s: u64,
    ) -> Result<crate::execution::coordinator::foreign::solana::DecodedSolanaTx, LaneAdmissionError>
    {
        use crate::execution::coordinator::foreign::solana::decode_solana_tx;

        if gas_limit_bgu == 0 {
            return Err(LaneAdmissionError::InvalidSolana("zero BGU budget"));
        }
        let transaction = decode_solana_tx(raw_wire)
            .map_err(|_| LaneAdmissionError::InvalidSolana("strict wire decoding failed"))?;
        let entry = LaneEntry {
            tx_hash: transaction.tx_hash,
            lane: LaneKind::Solana,
            replay: LaneReplayRule::SolanaWindow {
                recent_blockhash: transaction.recent_blockhash,
                signature_digest: sha256_32(&transaction.fee_payer_signature),
            },
            gas_limit_bgu,
            max_fee_per_bgu_atto,
            max_priority_fee_per_bgu_atto,
            raw_bytes: raw_wire.to_vec(),
        };
        self.admit(entry, now_unix_s)?;
        Ok(transaction)
    }

    /// The Solana blockhash window, newest last, as the door reads it.
    #[must_use]
    pub fn solana_blockhash_window(&self) -> Vec<[u8; 32]> {
        self.recent_blockhashes.iter().copied().collect()
    }

    /// Number of queued transactions in `lane`.
    ///
    /// Convenience: exposed for per-lane Prometheus gauges.
    #[must_use]
    pub fn lane_len(&self, lane: LaneKind) -> usize {
        self.lanes.get(&lane).map_or(0, |l| l.entries.len())
    }

    /// Admit `entry` into its dedicated lane after validating lane capacity and replay rules.
    ///
    /// Convenience: entry point for local, foreign-gateway, and duty transaction submission.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn admit(&mut self, entry: LaneEntry, now_unix_s: u64) -> Result<(), LaneAdmissionError> {
        // 0. An envelope has to declare a real execution budget and a tip it can
        // actually pay. `gas_limit_bgu == 0` passed every other check and
        // `select_for_block` charged nothing for it, so such an entry cost the
        // block no budget at all and could be stacked in front of entries that
        // do pay. A tip above `max_fee_per_bgu_atto` is not a bid the sender can
        // honour: execution would cap it at the fee, while selection priced it
        // at the tip and ranked it above honest envelopes.
        if entry.gas_limit_bgu == 0 {
            return Err(LaneAdmissionError::Unfunded("zero gas_limit_bgu"));
        }
        if entry.max_priority_fee_per_bgu_atto > entry.max_fee_per_bgu_atto {
            return Err(LaneAdmissionError::Unfunded(
                "max_priority_fee_per_bgu_atto above max_fee_per_bgu_atto",
            ));
        }
        // 1. Validate lane <-> replay rule match and replay/freshness BEFORE mutating!
        let nonce_pair: Option<([u8; 32], u64, u64)> = match (&entry.lane, &entry.replay) {
            (
                LaneKind::Local | LaneKind::Ethereum,
                LaneReplayRule::AccountNonce { sender, nonce },
            ) => Some((*sender, *nonce, 0)),
            (
                LaneKind::Solana,
                LaneReplayRule::SolanaWindow {
                    recent_blockhash,
                    signature_digest,
                },
            ) => {
                if !self.recent_blockhashes.contains(recent_blockhash) {
                    return Err(LaneAdmissionError::StaleOrExpired(
                        "recent_blockhash outside 150-block window",
                    ));
                }
                if self.seen_solana_sigs.contains(signature_digest) {
                    return Err(LaneAdmissionError::ReplayRejected(
                        "duplicate Solana signature",
                    ));
                }
                None
            }
            (
                LaneKind::Aptos,
                LaneReplayRule::AptosSequence {
                    sender,
                    sequence,
                    expiration_unix_s,
                },
            ) => {
                if *expiration_unix_s <= now_unix_s {
                    return Err(LaneAdmissionError::StaleOrExpired("Aptos tx expired"));
                }
                Some((*sender, *sequence, 0))
            }
            (
                LaneKind::Cosmos,
                LaneReplayRule::CosmosSequence {
                    sender,
                    account_number,
                    sequence,
                },
            ) => Some((*sender, *sequence, *account_number)),
            (
                LaneKind::Duty,
                LaneReplayRule::DutyWindow {
                    validator,
                    window_id,
                },
            ) => {
                if self.seen_duty_windows.contains(&(*validator, *window_id)) {
                    return Err(LaneAdmissionError::ReplayRejected(
                        "second duty batch in same window",
                    ));
                }
                None
            }
            _ => return Err(LaneAdmissionError::MismatchedReplayRule),
        };

        let existing_lane = self.lanes.get(&entry.lane);
        if existing_lane.is_some_and(|l| l.entries.contains_key(&entry.tx_hash)) {
            return Err(LaneAdmissionError::ReplayRejected("duplicate tx_hash"));
        }
        if let Some(pair) = nonce_pair {
            if existing_lane.is_some_and(|l| l.sender_nonces.contains(&pair)) {
                return Err(LaneAdmissionError::ReplayRejected(
                    "duplicate sender nonce/sequence in lane",
                ));
            }
        }
        let current_len = existing_lane.map_or(0, |l| l.entries.len());
        let current_bytes = existing_lane.map_or(0, |l| l.used_bytes);
        if current_len >= self.max_entries_per_lane
            || current_bytes.saturating_add(entry.raw_bytes.len()) > self.max_bytes_per_lane
        {
            return Err(LaneAdmissionError::LaneFull(entry.lane));
        }

        // 2. Commit into the target lane only after every check succeeded.
        if let LaneReplayRule::SolanaWindow {
            recent_blockhash,
            signature_digest,
        } = &entry.replay
        {
            self.seen_solana_sigs.insert(*signature_digest);
            self.solana_sigs_by_blockhash
                .entry(*recent_blockhash)
                .or_default()
                .insert(*signature_digest);
        }
        if let LaneReplayRule::DutyWindow {
            validator,
            window_id,
        } = &entry.replay
        {
            self.seen_duty_windows.insert((*validator, *window_id));
        }
        let lane_slot = self.lanes.entry(entry.lane).or_default();
        if let Some(pair) = nonce_pair {
            lane_slot.sender_nonces.insert(pair);
        }
        lane_slot.used_bytes = lane_slot.used_bytes.saturating_add(entry.raw_bytes.len());
        lane_slot.entries.insert(entry.tx_hash, entry);
        Ok(())
    }

    /// Select transactions across all lanes ordered by descending effective priority fee per BGU,
    /// respecting `block_bgu_budget`.
    ///
    /// Convenience: called by the block proposer when assembling UEL execution batches.
    #[must_use]
    pub fn select_for_block(&self, base_fee_atto: u128, block_bgu_budget: u64) -> Vec<LaneEntry> {
        self.select_fresh(base_fee_atto, block_bgu_budget, None)
    }

    /// Cross-lane selection with an optional block timestamp. `now_unix_s`
    /// drops Aptos envelopes whose expiration has passed.
    fn select_fresh(
        &self,
        base_fee_atto: u128,
        block_bgu_budget: u64,
        now_unix_s: Option<u64>,
    ) -> Vec<LaneEntry> {
        let mut candidates: Vec<(u128, LaneEntry)> = Vec::new();
        for lane in self.lanes.values() {
            for entry in lane.entries.values() {
                if matches!(
                    &entry.replay,
                    LaneReplayRule::SolanaWindow { recent_blockhash, .. }
                        if !self.recent_blockhashes.contains(recent_blockhash)
                ) {
                    continue;
                }
                if matches!(
                    (&entry.replay, now_unix_s),
                    (LaneReplayRule::AptosSequence { expiration_unix_s, .. }, Some(now))
                        if *expiration_unix_s <= now
                ) {
                    continue;
                }
                if let Some(tip) = entry.effective_priority_fee(base_fee_atto) {
                    candidates.push((tip, entry.clone()));
                }
            }
        }
        // Sort descending by effective priority fee, breaking ties deterministically by tx_hash.
        candidates.sort_by(|(tip_a, a), (tip_b, b)| {
            tip_b.cmp(tip_a).then_with(|| a.tx_hash.cmp(&b.tx_hash))
        });

        let mut picked = Vec::new();
        let mut used_bgu: u64 = 0;
        for (_, entry) in candidates {
            if used_bgu.saturating_add(entry.gas_limit_bgu) <= block_bgu_budget {
                used_bgu = used_bgu.saturating_add(entry.gas_limit_bgu);
                picked.push(entry);
            }
        }
        picked
    }

    /// Convenience: timestamp-aware block selection filtering expired transactions.
    ///
    /// `select_for_block` had no clock, so an Aptos envelope was only checked
    /// for expiry when it was admitted: one admitted a second before its
    /// `expiration_unix_s` stayed selectable for as long as it was queued, and
    /// the proposer put an expired transaction in a block. The proposer calls
    /// this variant with the block timestamp.
    #[must_use]
    pub fn select_for_block_at(
        &self,
        base_fee_atto: u128,
        block_bgu_budget: u64,
        now_unix_s: u64,
    ) -> Vec<LaneEntry> {
        self.select_fresh(base_fee_atto, block_bgu_budget, Some(now_unix_s))
    }

    /// Convenience: prune duty-window replay entries older than `min_window`.
    ///
    /// The `(validator, window_id)` set that enforces one duty batch per window
    /// only ever grew: every window the chain ever produced stayed in memory, so
    /// a long-running node paid for its whole history. A window id below
    /// `min_window` can no longer be submitted (the door refuses a stale window
    /// before it reaches this set), so dropping it keeps the rule exact.
    pub fn prune_duty_windows_before(&mut self, min_window: u64) {
        self.seen_duty_windows
            .retain(|(_, window_id)| *window_id >= min_window);
    }

    /// Evict committed transaction hashes across all lanes after block inclusion.
    pub fn evict_committed(&mut self, committed: &[[u8; 32]]) {
        for hash in committed {
            self.focil_queue.remove(hash);
            for lane in self.lanes.values_mut() {
                if let Some(entry) = lane.entries.remove(hash) {
                    lane.used_bytes = lane.used_bytes.saturating_sub(entry.raw_bytes.len());
                    match entry.replay {
                        LaneReplayRule::AccountNonce { sender, nonce } => {
                            lane.sender_nonces.remove(&(sender, nonce, 0));
                        }
                        LaneReplayRule::AptosSequence {
                            sender, sequence, ..
                        } => {
                            lane.sender_nonces.remove(&(sender, sequence, 0));
                        }
                        LaneReplayRule::CosmosSequence {
                            sender,
                            account_number,
                            sequence,
                        } => {
                            lane.sender_nonces
                                .remove(&(sender, sequence, account_number));
                        }
                        LaneReplayRule::SolanaWindow { .. } | LaneReplayRule::DutyWindow { .. } => {
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_ethereum_lane_never_blocks_local_or_solana_and_proposer_sorts_by_tip() {
        let mut pool = MultiLaneMempool::new(1, 4096);
        let bh = [0x77; 32];
        pool.push_recent_blockhash(bh);

        // Fill Ethereum lane to capacity (1).
        pool.admit(
            LaneEntry {
                tx_hash: [1u8; 32],
                lane: LaneKind::Ethereum,
                replay: LaneReplayRule::AccountNonce {
                    sender: [0xAA; 32],
                    nonce: 0,
                },
                gas_limit_bgu: 21_000,
                max_fee_per_bgu_atto: 100,
                max_priority_fee_per_bgu_atto: 10,
                raw_bytes: vec![0u8; 32],
            },
            1_000,
        )
        .unwrap();

        assert_eq!(
            pool.admit(
                LaneEntry {
                    tx_hash: [2u8; 32],
                    lane: LaneKind::Ethereum,
                    replay: LaneReplayRule::AccountNonce {
                        sender: [0xBB; 32],
                        nonce: 0,
                    },
                    gas_limit_bgu: 21_000,
                    max_fee_per_bgu_atto: 100,
                    max_priority_fee_per_bgu_atto: 20,
                    raw_bytes: vec![0u8; 32],
                },
                1_000,
            ),
            Err(LaneAdmissionError::LaneFull(LaneKind::Ethereum))
        );

        // Local and Solana lanes remain completely open!
        pool.admit(
            LaneEntry {
                tx_hash: [3u8; 32],
                lane: LaneKind::Local,
                replay: LaneReplayRule::AccountNonce {
                    sender: [0xCC; 32],
                    nonce: 0,
                },
                gas_limit_bgu: 50_000,
                max_fee_per_bgu_atto: 200,
                max_priority_fee_per_bgu_atto: 80,
                raw_bytes: vec![0u8; 32],
            },
            1_000,
        )
        .unwrap();

        pool.admit(
            LaneEntry {
                tx_hash: [4u8; 32],
                lane: LaneKind::Solana,
                replay: LaneReplayRule::SolanaWindow {
                    recent_blockhash: bh,
                    signature_digest: [0x99; 32],
                },
                gas_limit_bgu: 30_000,
                max_fee_per_bgu_atto: 150,
                max_priority_fee_per_bgu_atto: 40,
                raw_bytes: vec![0u8; 32],
            },
            1_000,
        )
        .unwrap();

        let batch = pool.select_for_block(50, 1_000_000);
        assert_eq!(batch.len(), 3);
        // Ordered by effective tip descending: Local (80), Solana (40), Ethereum (10).
        assert_eq!(batch[0].lane, LaneKind::Local);
        assert_eq!(batch[1].lane, LaneKind::Solana);
        assert_eq!(batch[2].lane, LaneKind::Ethereum);
    }

    #[test]
    fn solana_admission_retains_wire_bytes_prices_execution_and_evicts_replays() {
        use crate::execution::coordinator::foreign::solana::{
            sign_solana_tx, SolanaCompiledInstruction,
        };

        let key = [21u8; 32];
        let blockhash = [0x7Au8; 32];
        let instruction = SolanaCompiledInstruction {
            program_id_index: 1,
            accounts: vec![0],
            data: vec![2, 0, 0, 0],
        };
        let wire = sign_solana_tx(
            &key,
            false,
            blockhash,
            &[[0xEEu8; 32]],
            std::slice::from_ref(&instruction),
        );
        let mut pool = MultiLaneMempool::new(8, 4096);
        pool.push_recent_blockhash(blockhash);
        let decoded = pool
            .admit_foreign_solana(&wire, 1_000, 100, 10, 1_000)
            .expect("valid Solana envelope");
        assert_eq!(pool.lane_len(LaneKind::Solana), 1);
        let entries = pool.select_for_block(0, 1_000);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].raw_bytes, wire);
        assert_eq!(entries[0].tx_hash, decoded.tx_hash);

        assert_eq!(
            pool.admit_foreign_solana(&wire, 1_000, 100, 10, 1_000),
            Err(LaneAdmissionError::ReplayRejected(
                "duplicate Solana signature"
            ))
        );
        assert_eq!(
            pool.admit_foreign_solana(&wire, 0, 100, 10, 1_000),
            Err(LaneAdmissionError::InvalidSolana("zero BGU budget"))
        );

        let stale = sign_solana_tx(&key, false, [0x01u8; 32], &[[0xEEu8; 32]], &[instruction]);
        assert!(matches!(
            pool.admit_foreign_solana(&stale, 1_000, 100, 10, 1_000),
            Err(LaneAdmissionError::StaleOrExpired(_))
        ));

        for step in 0..SOLANA_BLOCKHASH_WINDOW {
            let mut next = [0u8; 32];
            next[..8].copy_from_slice(&(step as u64 + 1).to_le_bytes());
            pool.push_recent_blockhash(next);
        }
        assert!(pool.seen_solana_sigs.is_empty());
        assert!(pool.solana_sigs_by_blockhash.is_empty());
        assert_eq!(pool.lane_len(LaneKind::Solana), 0);
        assert!(pool.select_for_block(0, 1_000).is_empty());
    }

    #[test]
    fn admit_refuses_zero_gas_limit_and_inverted_priority_fee() {
        let mut pool = MultiLaneMempool::new(8, 4096);
        let zero_gas = LaneEntry {
            lane: LaneKind::Ethereum,
            tx_hash: [0xA1; 32],
            raw_bytes: vec![1, 2, 3],
            gas_limit_bgu: 0,
            max_fee_per_bgu_atto: u128::MAX,
            max_priority_fee_per_bgu_atto: u128::MAX,
            replay: LaneReplayRule::AccountNonce {
                sender: [0x11; 32],
                nonce: 0,
            },
        };
        assert!(
            pool.admit(zero_gas, 1_000).is_err(),
            "zero gas_limit_bgu must be refused so free entries cannot front-run blocks"
        );

        let inverted_tip = LaneEntry {
            lane: LaneKind::Local,
            tx_hash: [0xA2; 32],
            raw_bytes: vec![4, 5, 6],
            gas_limit_bgu: 21_000,
            max_fee_per_bgu_atto: 10,
            max_priority_fee_per_bgu_atto: 50,
            replay: LaneReplayRule::AccountNonce {
                sender: [0x22; 32],
                nonce: 0,
            },
        };
        assert!(
            pool.admit(inverted_tip, 1_000).is_err(),
            "max_priority_fee_per_bgu_atto > max_fee_per_bgu_atto must be refused"
        );
    }

    #[test]
    fn select_for_block_at_skips_expired_aptos_and_cosmos_isolates_account_number() {
        let mut pool = MultiLaneMempool::new(8, 4096);
        let aptos_entry = LaneEntry {
            lane: LaneKind::Aptos,
            tx_hash: [0xB1; 32],
            raw_bytes: vec![7; 32],
            gas_limit_bgu: 500,
            max_fee_per_bgu_atto: 100,
            max_priority_fee_per_bgu_atto: 20,
            replay: LaneReplayRule::AptosSequence {
                sender: [0x33; 32],
                sequence: 1,
                expiration_unix_s: 1_000,
            },
        };
        pool.admit(aptos_entry, 999).expect("live at t=999");
        assert!(
            pool.select_for_block_at(0, 10_000, 1_000).is_empty(),
            "Aptos tx with expiration_unix_s <= now_unix_s must not be selected into block"
        );

        let cosmos_a = LaneEntry {
            lane: LaneKind::Cosmos,
            tx_hash: [0xC1; 32],
            raw_bytes: vec![8; 16],
            gas_limit_bgu: 500,
            max_fee_per_bgu_atto: 100,
            max_priority_fee_per_bgu_atto: 10,
            replay: LaneReplayRule::CosmosSequence {
                sender: [0x44; 32],
                account_number: 1,
                sequence: 0,
            },
        };
        let cosmos_b = LaneEntry {
            lane: LaneKind::Cosmos,
            tx_hash: [0xC2; 32],
            raw_bytes: vec![9; 16],
            gas_limit_bgu: 500,
            max_fee_per_bgu_atto: 100,
            max_priority_fee_per_bgu_atto: 10,
            replay: LaneReplayRule::CosmosSequence {
                sender: [0x44; 32],
                account_number: 2,
                sequence: 0,
            },
        };
        pool.admit(cosmos_a, 1_000).expect("cosmos acct 1");
        pool.admit(cosmos_b, 1_000)
            .expect("distinct Cosmos account_number must not collide on sequence");

        for w in 1..=5u64 {
            let duty = LaneEntry {
                lane: LaneKind::Duty,
                tx_hash: [w as u8; 32],
                raw_bytes: vec![1; 8],
                gas_limit_bgu: 100,
                max_fee_per_bgu_atto: 10,
                max_priority_fee_per_bgu_atto: 1,
                replay: LaneReplayRule::DutyWindow {
                    validator: [0x55; 32],
                    window_id: w,
                },
            };
            pool.admit(duty, 1_000).expect("duty window");
        }
        pool.prune_duty_windows_before(4);
        assert_eq!(pool.seen_duty_windows.len(), 2);
    }
}
