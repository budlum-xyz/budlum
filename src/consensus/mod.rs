pub mod merkle_tree;
pub mod poa;
pub mod pos;
pub mod pow;
pub mod qc;
pub mod split_resolver;
use crate::core::block::Block;
pub use poa::PoAEngine;
pub use pos::PoSEngine;
pub use pow::{PoWConfig, PoWEngine};
use std::error::Error;
use std::fmt;
#[derive(Debug)]
pub struct ConsensusError(pub String);
impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Consensus error: {}", self.0)
    }
}
impl Error for ConsensusError {}
pub const MAX_FUTURE_BLOCK_TIME_MS: u128 = 15 * 1000;
pub const MAX_PAST_BLOCK_TIME_MS: u128 = 2 * 60 * 60 * 1000;
pub const MIN_BLOCK_INTERVAL_MS: u128 = 1000;
/// How many leader-election rounds one slot may run (P01-F01, P01-F02).
///
/// A slot with no elected leader used to stall forever: the VRF seed had no
/// retry term, so every retry tick drew the same (empty) result. A round term
/// in the seed re-rolls the election, and the round threshold multiplier
/// widens eligibility geometrically, so a slot fills after a bounded number
/// of rounds even with a minority of the validators online.
pub const MAX_LEADER_ROUNDS: u64 = 16;
/// Wall-clock spacing between leader rounds of one slot (P01-F01, P01-F02).
///
/// Claiming round `r` costs `r` timeouts, and the price is charged twice:
/// the block timestamp must sit at least
/// `MIN_BLOCK_INTERVAL_MS + r * ROUND_TIMEOUT_MS` after its parent, and the
/// claim must be affordable by the verifying node's clock
/// ([`affordable_leader_round`]). Without the floor every validator would jump
/// straight to the widest round and the retry term would buy nothing but forks;
/// without the clock the floor is free, because the producer writes both of the
/// numbers it compares (CWE-807). The floor also removes the "stay 1 s ahead of
/// the parent" steering channel (P01-F20): a later round can no longer be
/// claimed on the minimum step.
pub const ROUND_TIMEOUT_MS: u128 = 3 * 1000;
/// Full wall-clock span of the leader-round retry ladder (`0..=MAX_LEADER_ROUNDS`).
///
/// Once a parent's header stamp lags wall time by more than this span, pricing
/// from the stamp alone would make every round `0..=MAX_LEADER_ROUNDS`
/// affordable at once on every node (CWE-807).
const ROUND_LADDER_SPAN_MS: u128 =
    MIN_BLOCK_INTERVAL_MS + ROUND_TIMEOUT_MS * (MAX_LEADER_ROUNDS as u128);
/// Small producer-side propagation cushion applied before claiming a retry
/// round (`round >= 1`) when node-local adoption time is the active anchor.
const PRODUCER_ROUND_CUSHION_MS: u128 = 500;

/// Wall clock, milliseconds since the Unix epoch.
///
/// One definition for the round pricing below: the producer and the verifier
/// must ask the same question the same way, or the round stops being priced at
/// all (CWE-807).
pub fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// When this node first adopted a block it committed, keyed by hash.
///
/// The round price is "how long ago did the parent land", and a header cannot
/// answer that: production stamps blocks from the slot schedule
/// (`genesis_time + index * slot_ms`), so a chain that has fallen behind its
/// schedule carries parent stamps that are minutes older than the moment the
/// parent actually landed. Pricing straight off the stamp let the gate
/// saturate - at 49 s of lag every round up to [`MAX_LEADER_ROUNDS`] was
/// affordable at once (CWE-807) - while capping the stamp instead froze the
/// retry ladder for genuinely stalled slots.
///
/// A node does know when it adopted a block, and that fact cannot be inflated:
/// a peer can delay delivery, which only makes this node stricter (and
/// self-heals, because `now` keeps moving while the adoption time does not),
/// but it can never backdate it.
///
/// The book holds the blocks this node committed, up to
/// `ROUND_PRICE_WINDOW`, and only chain commit writes it, never validation:
///
/// - Writing from validation would price a parent and its child milliseconds
///   apart whenever a single pass walks several blocks (fork recovery through
///   a peer's candidate chain, replay), so a legitimately produced retry block
///   inside that chain would be refused and a node stuck on a minority fork
///   could never adopt the better one.
/// - The window covers every parent a reorg candidate can legally name: a
///   candidate forks at most [`MAX_REORG_DEPTH`] below the tip, so the fork
///   block is always one this node committed. Beyond the window a parent has
///   no sighting, and a claim on it prices at round 0 - the strict direction,
///   never a producer's header.
/// - The first sighting wins, so re-committing a block (a reorg back onto it,
///   a restore of the same tip) cannot backdate its price, and a reorg inside
///   the window cannot evict the sighting of a block still on the live chain.
pub struct RoundPriceBook {
    seen: std::sync::Mutex<std::collections::VecDeque<(String, u128)>>,
}

/// How many committed blocks the round price book remembers.
///
/// One more than [`MAX_REORG_DEPTH`]: the deepest block a reorg candidate may
/// fork at is `MAX_REORG_DEPTH` below the tip, and the window has to hold the
/// tip itself as well.
pub(crate) const ROUND_PRICE_WINDOW: usize = MAX_REORG_DEPTH + 1;

impl Default for RoundPriceBook {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundPriceBook {
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: std::sync::Mutex::new(std::collections::VecDeque::new()),
        }
    }

    /// Record that `block_hash` was committed at `now_ms`.
    ///
    /// Called from the chain commit path, and from a restore for the tip a
    /// node loads from disk. A poisoned lock is treated as "no adoption
    /// recorded" rather than as a panicking consensus path.
    pub fn note_tip_block(&self, block_hash: &str, now_ms: u128) {
        let Ok(mut seen) = self.seen.lock() else {
            return;
        };
        if seen.iter().any(|(hash, _)| hash == block_hash) {
            // First sighting wins: a re-commit cannot backdate the price.
            return;
        }
        seen.push_back((block_hash.to_string(), now_ms));
        while seen.len() > ROUND_PRICE_WINDOW {
            seen.pop_front();
        }
    }

    /// When this node first committed `block_hash`, while it is still inside
    /// the window.
    #[must_use]
    fn seen_at(&self, block_hash: &str) -> Option<u128> {
        let Ok(seen) = self.seen.lock() else {
            return None;
        };
        seen.iter()
            .find(|(hash, _)| hash == block_hash)
            .map(|(_, at)| *at)
    }

    /// Resolve the local adoption timestamp for `parent` on `chain`.
    ///
    /// When `parent` has not been committed yet (a multi-block sync or reorg
    /// candidate suffix), walk back through `chain` (bounded by
    /// `ROUND_PRICE_WINDOW`) to the nearest ancestor this node already
    /// committed, or fall back to `now_ms` when no block in the window has a
    /// local sighting. That prevents an uncommitted parent's backdated header
    /// stamp from unlocking rounds `1..=MAX_LEADER_ROUNDS` via `None`.
    #[must_use]
    pub fn chain_seen_at(&self, chain: &[Block], parent: &Block, now_ms: u128) -> u128 {
        if let Some(at) = self.seen_at(&parent.hash) {
            return at;
        }
        let anchor_pos = chain.iter().rposition(|b| b.hash == parent.hash);
        let search_end = anchor_pos.map_or(chain.len(), |idx| idx + 1);
        let search_start = search_end.saturating_sub(ROUND_PRICE_WINDOW);
        for ancestor in chain[search_start..search_end].iter().rev() {
            if let Some(at) = self.seen_at(&ancestor.hash) {
                return at;
            }
        }
        now_ms
    }

    /// The highest round this node may *claim*, from the producer's side.
    ///
    /// Uses the same [`affordable_leader_round`] rule validation enforces.
    /// When the parent's header stamp has fallen behind wall time by more than
    /// `ROUND_LADDER_SPAN_MS` so that node-local adoption time is the active
    /// anchor, retry rounds (`round >= 1`) wait an additional
    /// `PRODUCER_ROUND_CUSHION_MS` before being claimed so normal gossip
    /// stagger does not place peers on opposite sides of a timeout boundary.
    #[must_use]
    pub fn claimable_round_for(
        &self,
        parent_hash: &str,
        parent_timestamp_ms: u128,
        now_ms: u128,
    ) -> u64 {
        let seen = self.seen_at(parent_hash);
        let raw = affordable_leader_round(parent_timestamp_ms, seen, now_ms);
        if raw == 0 || seen.is_none() {
            return raw;
        }
        if parent_timestamp_ms.saturating_add(ROUND_LADDER_SPAN_MS) < now_ms {
            affordable_leader_round(
                parent_timestamp_ms,
                seen,
                now_ms.saturating_sub(PRODUCER_ROUND_CUSHION_MS),
            )
        } else {
            raw
        }
    }
}

/// The highest leader round a slot can have reached by `now_ms`.
///
/// Round `r` is affordable once `MIN_BLOCK_INTERVAL_MS + r * ROUND_TIMEOUT_MS`
/// has elapsed since the parent block was published; the result is capped at
/// [`MAX_LEADER_ROUNDS`].
///
/// This is the *pricing* half of the round rule, and it is deliberately
/// clock-based. The other half - the floor "`block.timestamp` must be at least
/// `parent + MIN_BLOCK_INTERVAL_MS + r * ROUND_TIMEOUT_MS`" - compares two
/// values the producer writes, so on its own it prices nothing: the timestamp
/// may sit up to [`MAX_FUTURE_BLOCK_TIME_MS`] ahead of the verifier, which makes
/// rounds `0..=MAX_FUTURE_BLOCK_TIME_MS / ROUND_TIMEOUT_MS` affordable the
/// instant the parent lands. Every authority or validator elected in one of
/// those rounds could then publish a valid block for a slot it does not lead,
/// and a slot would routinely have several valid competing blocks.
///
/// Both sides use this function: the producer clamps the round it claims, the
/// verifier refuses a claim above it. A verifier whose clock trails a producer
/// by more than one [`ROUND_TIMEOUT_MS`] refuses that producer's retry-round
/// block; round 0 - the ordinary case - is unaffected, so a skewed node still
/// follows the chain, and the next round's leader can produce instead.
///
/// # The anchor
///
/// While a parent's header stamp is within `ROUND_LADDER_SPAN_MS` of wall
/// time, `parent_seen_ms` only *lowers* the anchor (`seen.min(stamp)`): in
/// normal cadence every node holding the parent agrees on the shared stamp, and
/// a future-dated header still cannot buy the rounds between its stamp and the
/// moment this node saw it.
///
/// Once `parent_timestamp_ms + ROUND_LADDER_SPAN_MS < now_ms` and this node has
/// an adoption record (`Some(seen)`), pricing from the stale stamp would
/// saturate all `0..=MAX_LEADER_ROUNDS` rounds immediately on arrival - both on
/// a schedule-lagged chain and when an elected producer withholds a backdated
/// parent (CWE-807). In that stale regime the anchor switches to
/// `anchor_ms.max(seen)`, so round 0 alone opens at adoption and retry rounds
/// unlock one [`ROUND_TIMEOUT_MS`] at a time as real wall time elapses. Parents
/// with no local sighting (`None` during historical sync or replay outside
/// `ROUND_PRICE_WINDOW`) continue to price from `parent_timestamp_ms`.
#[must_use]
pub fn affordable_leader_round(
    parent_timestamp_ms: u128,
    parent_seen_ms: Option<u128>,
    now_ms: u128,
) -> u64 {
    let anchor_ms =
        parent_seen_ms.map_or(parent_timestamp_ms, |seen| seen.min(parent_timestamp_ms));
    // A stamp that lags the wall clock by more than the whole ladder is not a
    // price: one withheld block stamped at the minimum interval (or a schedule
    // running behind wall time) would make every round affordable at once on
    // every node, and a slot could then carry up to 17 competing valid blocks.
    // When the stamp is that stale, price from the moment this node adopted the
    // parent instead - a value no producer can write, which stays fixed while
    // `now_ms` advances.
    let anchor_ms = if parent_seen_ms
        .is_some_and(|_| parent_timestamp_ms.saturating_add(ROUND_LADDER_SPAN_MS) < now_ms)
    {
        parent_seen_ms.map_or(anchor_ms, |seen| anchor_ms.max(seen))
    } else {
        anchor_ms
    };
    let spaced = now_ms
        .saturating_sub(anchor_ms)
        .saturating_sub(MIN_BLOCK_INTERVAL_MS);
    u64::try_from(spaced / ROUND_TIMEOUT_MS)
        .unwrap_or(u64::MAX)
        .min(MAX_LEADER_ROUNDS)
}
/// Consensus block-size ceiling, measured over the **JSON** encoding.
///
/// Distinct from `network::protocol::MAX_BLOCK_SIZE` (1 MiB) on purpose, and
/// the two are not interchangeable despite the shared name:
///
/// | constant | value | measured over | rejects at |
/// | :-- | :-- | :-- | :-- |
/// | `consensus::MAX_BLOCK_SIZE` | 1_000_000 | `serde_json::to_vec` | block validation |
/// | `protocol::MAX_BLOCK_SIZE` | 1_048_576 | `prost` `encoded_len` | gossip ingest |
///
/// The transport bound is the looser of the two *and* it measures the more
/// compact encoding, so the consensus check is always the binding one. A block
/// that clears gossip can still be refused by validation; the reverse cannot
/// happen. That ordering is the safe one - the network never accepts something
/// consensus would reject - but it is a property of the current numbers, not
/// of the design, and nothing was recording it.
///
/// If either value moves, keep `protocol::MAX_BLOCK_SIZE` (protobuf) at or
/// above this one (JSON), or gossip starts admitting blocks every validator
/// then refuses.
pub const MAX_BLOCK_SIZE: usize = 1_000_000;
/// Largest single slashing-evidence entry a block may carry.
///
/// Enforced where evidence is admitted (`submit_slashing_evidence`), where it
/// is inlined into a block, and where the consensus engine hands its pool
/// over, so an entry that is accepted is always small enough to be included in
/// some future block. The block builder also reserves this much room for
/// evidence before it spends the rest of the budget on transactions, so a
/// saturated mempool cannot starve a queued double-sign proof out of every
/// block.
pub const MAX_SLASHING_EVIDENCE_BYTES: usize = 65_536;
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 5000;
pub const MAX_REORG_DEPTH: usize = 100;
use crate::core::account::AccountState;

pub trait ConsensusEngine: Send + Sync {
    fn preview_block(
        &self,
        _block: &mut Block,
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        Ok(())
    }
    /// Chain-aware preview for consensus engines whose proposer selection is
    /// Derived from canonical history. Production block construction calls
    /// This method so preview and remote validation consume the same prefix.
    fn preview_block_with_chain(
        &self,
        block: &mut Block,
        state: &AccountState,
        _chain: &[Block],
    ) -> Result<(), ConsensusError> {
        self.preview_block(block, state)
    }
    fn prepare_block(&self, block: &mut Block, state: &AccountState) -> Result<(), ConsensusError>;
    fn prepare_block_with_chain(
        &self,
        block: &mut Block,
        state: &AccountState,
        _chain: &[Block],
    ) -> Result<(), ConsensusError> {
        self.prepare_block(block, state)
    }
    fn validate_block(
        &self,
        block: &Block,
        chain: &[Block],
        state: &AccountState,
    ) -> Result<(), ConsensusError>;

    /// Record that `block_hash` is now this node's tip, adopted at `at_ms`.
    ///
    /// Engines that price rounds (PoA, PoS) keep the observation; the default
    /// does nothing, because an engine with no round term has nothing to
    /// price. Only adoption writes it - the block-apply path and the restore
    /// path - never validation: a pass that walks several blocks (a peer's
    /// candidate chain, a replay) must not price a parent and its child
    /// milliseconds apart, or a legitimate retry block inside that chain would
    /// be refused.
    fn note_block_seen(&self, _block_hash: &str, _at_ms: u128) {}

    /// The kind of chain this engine produces blocks for.
    ///
    /// `AccountState::execution_domain` is stamped from this at every point
    /// a state is built or replaced, and it is what the identity write gate
    /// consults. The default is `PoS`, which is the Budlum mainnet fact and keeps
    /// the master registry closed: an engine that does not declare itself
    /// does not open a gated write. `PoAEngine` overrides; nothing else may.
    fn domain_kind(&self) -> crate::domain::ConsensusKind {
        crate::domain::ConsensusKind::PoS
    }
    fn record_block(
        &self,
        _block: &Block,
        _storage: Option<&crate::storage::db::Storage>,
    ) -> Result<(), ConsensusError> {
        Ok(())
    }

    /// Look at a block received from the network, before the chain accepts or
    /// rejects it, for proof of producer misbehaviour. It must not change
    /// chain state and must not write checkpoints: the block may never
    /// commit. The default is a no-op; `PoSEngine` turns a signed rival block
    /// into double-sign evidence (BLG-0011).
    fn observe_received_block(&self, _block: &Block) -> Result<(), ConsensusError> {
        Ok(())
    }

    /// (security audit §3) chain-aware variant of `record_block`.
    /// Called from `blockchain.rs` AFTER a block has been durably
    /// Committed and the chain is in its post-commit state. The
    /// Default implementation is a no-op; engines that need access to
    /// The full chain (e.g. `PoWEngine` for difficulty adjustment)
    /// Override it. Validation (`validate_block`) MUST remain pure -
    /// Any state mutation triggered by a block landing on the chain
    /// Belongs here, not in validation.
    fn record_block_with_chain(
        &self,
        _block: &Block,
        _chain: &[Block],
        _storage: Option<&crate::storage::db::Storage>,
    ) {
    }

    /// The chain reports the height finalised by quorum certificates
    /// (P01-F04).
    ///
    /// A checkpoint written at local commit time is not a finality claim: two
    /// nodes commit different blocks at an epoch boundary and then reject each
    /// other's chains forever. Checkpoints are therefore held pending until
    /// the height they name is finalised, and this method is how the chain
    /// hands that finality to the engine. The default is a no-op.
    fn note_finalized_height(
        &self,
        _height: u64,
        _chain: &[Block],
        _storage: Option<&crate::storage::db::Storage>,
    ) {
    }
    fn load_state(&self, _storage: &crate::storage::db::Storage) -> Result<(), ConsensusError> {
        Ok(())
    }
    fn drain_slashing_evidence(
        &self,
    ) -> Result<Vec<crate::consensus::pos::SlashingEvidence>, ConsensusError> {
        Ok(Vec::new())
    }
    fn prune_slashing_evidence(&self, _min_height: u64) -> Result<usize, ConsensusError> {
        Ok(0)
    }
    fn consensus_type(&self) -> &'static str;
    fn info(&self) -> String;
    fn signer(&self) -> Option<&dyn crate::crypto::signer::ConsensusSigner> {
        None
    }
    fn bls_secret_key(&self) -> Option<bls12_381::Scalar> {
        None
    }
    fn bls_public_key(&self) -> Option<Vec<u8>> {
        None
    }
    fn validate_timestamp(
        &self,
        block: &Block,
        prev_block: Option<&Block>,
    ) -> Result<(), ConsensusError> {
        // Reject blocks with timestamps too far in the future.
        // This prevents block producers from corrupting time-dependent logic
        // (vesting, BNS expiry, bridge lock expiry, AI deadlines).
        // Uses existing MAX_FUTURE_BLOCK_TIME_MS constant (15 seconds).
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        if block.timestamp > now_ms.saturating_add(MAX_FUTURE_BLOCK_TIME_MS) {
            return Err(ConsensusError(format!(
                "Block timestamp too far in the future. Now: {}, Block: {}, Max drift: {} ms",
                now_ms, block.timestamp, MAX_FUTURE_BLOCK_TIME_MS
            )));
        }

        if let Some(prev) = prev_block {
            if block.timestamp <= prev.timestamp {
                return Err(ConsensusError(format!(
                    "Block timestamp not monotonic. Prev: {}, Current: {}",
                    prev.timestamp, block.timestamp
                )));
            }
            let interval = block.timestamp - prev.timestamp;
            if interval < MIN_BLOCK_INTERVAL_MS {
                return Err(ConsensusError(format!(
                    "Block produced too fast. Min interval: {MIN_BLOCK_INTERVAL_MS} ms, Got: {interval} ms"
                )));
            }
        }
        Ok(())
    }
    fn validate_block_size(&self, block: &Block) -> Result<(), ConsensusError> {
        if block.transactions.len() > MAX_TRANSACTIONS_PER_BLOCK {
            return Err(ConsensusError(format!(
                "Too many transactions. Max: {}, Got: {}",
                MAX_TRANSACTIONS_PER_BLOCK,
                block.transactions.len()
            )));
        }
        // A silent empty serialization would let an oversized block pass
        // This size check. Surface the error instead of defaulting to empty.
        let serialized = serde_json::to_vec(block).map_err(|e| {
            ConsensusError(format!("Failed to serialize block for size check: {e}"))
        })?;
        if serialized.len() > MAX_BLOCK_SIZE {
            return Err(ConsensusError(format!(
                "Block too large. Max: {} bytes, Got: {} bytes",
                MAX_BLOCK_SIZE,
                serialized.len()
            )));
        }
        Ok(())
    }
    fn select_best_chain<'a>(&self, chains: &[&'a [Block]]) -> Option<&'a [Block]> {
        if chains.is_empty() {
            return None;
        }
        chains.iter().max_by_key(|c| c.len()).copied()
    }
    /// Test-only depth probe (P01-F21: `try_reorg` enforces the depth limit
    /// on the live path; nothing production-side calls this).
    #[cfg(test)]
    fn can_reorg(&self, current_chain: &[Block], new_chain: &[Block]) -> bool {
        if new_chain.len() <= current_chain.len() {
            return false;
        }
        // Depth is measured from the slice position, not from `Block::index`:
        // the slices handed in here are not required to start at height zero,
        // and `len - index - 1` underflows on a suffix.
        let ancestor_pos = current_chain
            .iter()
            .rposition(|b| new_chain.iter().any(|nb| nb.hash == b.hash));
        // No shared block means the candidate replaces the whole slice: that
        // is a reorg of depth `len`, not a reorg of depth zero. Left as
        // `None`, this path skipped the depth check and admitted any longer
        // chain with no ancestor at all.
        let reorg_depth =
            ancestor_pos.map_or(current_chain.len(), |pos| current_chain.len() - pos - 1);
        if reorg_depth > MAX_REORG_DEPTH {
            tracing::warn!(
                "Rejecting deep reorg: {} blocks (max: {})",
                reorg_depth,
                MAX_REORG_DEPTH
            );
            return false;
        }
        true
    }
    fn full_validate(
        &self,
        block: &Block,
        chain: &[Block],
        state: &AccountState,
    ) -> Result<(), ConsensusError> {
        if block.index == 0 {
            return self.validate_block(block, chain, state);
        }
        let prev_block = chain.last();
        self.validate_timestamp(block, prev_block)?;
        self.validate_block_size(block)?;
        self.validate_block(block, chain, state)?;
        Ok(())
    }

    fn fork_choice_score(&self, chain: &[Block]) -> u128 {
        chain.len() as u128
    }

    fn is_better_chain(&self, current: &[Block], candidate: &[Block]) -> bool {
        self.fork_choice_score(candidate) > self.fork_choice_score(current)
    }

    /// Whether `is_better_chain` can never prefer a candidate that is strictly
    /// shorter than the current chain.
    ///
    /// `try_reorg_suffix` uses this to answer a peer batch that cannot win
    /// before it materializes the local prefix (CWE-400). The default is the
    /// length-based rule below, where a shorter chain scores strictly less.
    /// Engines that score work or checkpoints - where a shorter chain can
    /// legitimately be the better one - must report `false`, or the shortcut
    /// would refuse a heavier fork.
    fn shorter_chain_can_never_win(&self) -> bool {
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// A claim is priced from the parent's stamp, which every node reads the
    /// same way, and the ladder still walks in real time.
    ///
    /// Pricing from when this node happened to commit the parent put the same
    /// claim on different sides of the boundary at different nodes - a boot
    /// time, a restart or a sync of a few seconds is already more than a
    /// round - and a refused claim is a fork the refusing node keeps, because
    /// the block is refused for good and the slot runs again on the other
    /// side. The devnet mesh split into two chains at height 1 exactly so, on
    /// the first block, where the parent is genesis and every node had booted
    /// a few seconds apart. The stamp is the shared value, so both sides of
    /// the rule price the same claim identically, and a future-dated header
    /// still cannot buy the rounds between its stamp and the sighting.
    #[test]
    fn a_claim_is_priced_by_the_shared_stamp_and_the_ladder_walks_in_real_time() {
        let now = 1_700_000_000_000u128;
        let fresh_stamp = now - 20_000; // within ROUND_LADDER_SPAN_MS (49 s)
        let stale_stamp = now - 600_000; // ten minutes behind the schedule

        // Within the active ladder window, sightings seconds apart agree on the
        // shared parent stamp so mesh nodes do not split on propagation jitter.
        assert_eq!(
            affordable_leader_round(fresh_stamp, Some(fresh_stamp), now),
            6
        );
        assert_eq!(
            affordable_leader_round(fresh_stamp, Some(now - 2_000), now),
            6
        );
        assert_eq!(affordable_leader_round(fresh_stamp, None, now), 6);

        // Once the parent stamp lags wall time by more than the whole ladder,
        // a newly adopted parent opens round 0 only instead of saturating all
        // 17 rounds at once; real elapsed time since adoption still walks up to
        // MAX_LEADER_ROUNDS, and unsighted historical replay keeps the stamp.
        assert_eq!(
            affordable_leader_round(stale_stamp, Some(now - 500), now),
            0
        );
        assert_eq!(
            affordable_leader_round(stale_stamp, Some(now - 10_000), now),
            3
        );
        assert_eq!(
            affordable_leader_round(stale_stamp, Some(stale_stamp), now),
            MAX_LEADER_ROUNDS
        );
        assert_eq!(
            affordable_leader_round(stale_stamp, None, now),
            MAX_LEADER_ROUNDS
        );

        // One round per `ROUND_TIMEOUT_MS`, as the constant says.
        assert_eq!(
            affordable_leader_round(stale_stamp, Some(stale_stamp), stale_stamp + 7_500),
            2
        );

        // A future-dated parent is priced from the moment this node saw it,
        // and recovers by itself once the moment it names has passed: a stamp
        // can lower the anchor, never raise it.
        assert_eq!(
            affordable_leader_round(now + 60_000, Some(now - 1_000), now),
            0
        );
        assert_eq!(affordable_leader_round(now + 60_000, None, now), 0);
        assert_eq!(
            affordable_leader_round(now + 60_000, Some(now - 1_000), now + 109_000),
            MAX_LEADER_ROUNDS
        );
    }

    #[test]
    fn stale_parent_seen_just_now_does_not_saturate_the_round_ladder() {
        let now = 1_700_000_000_000u128;
        let stale_parent = now - ROUND_LADDER_SPAN_MS - 1_000;
        let book = RoundPriceBook::new();
        book.note_tip_block("stale-tip", now);

        assert_eq!(
            affordable_leader_round(stale_parent, book.seen_at("stale-tip"), now),
            0,
            "a parent stamped beyond the ladder span must not unlock rounds 1..=16 at adoption"
        );
        assert_eq!(
            book.claimable_round_for("stale-tip", stale_parent, now),
            0,
            "producer cap must also hold at round 0 when a stale parent just landed"
        );
        // After MIN_BLOCK_INTERVAL_MS + ROUND_TIMEOUT_MS + cushion, round 1 unlocks.
        let after_one_timeout =
            now + MIN_BLOCK_INTERVAL_MS + ROUND_TIMEOUT_MS + PRODUCER_ROUND_CUSHION_MS;
        assert_eq!(
            book.claimable_round_for("stale-tip", stale_parent, after_one_timeout),
            1
        );
    }

    /// The book holds the blocks this node committed, inside the reorg
    /// window, and nothing a peer can move.
    ///
    /// Written only by commit: a candidate chain replayed through validation
    /// cannot write an entry, the first sighting of a block wins so a re-commit
    /// cannot backdate it, and every block a reorg candidate may fork at keeps
    /// its sighting because the window is as deep as `MAX_REORG_DEPTH`.
    #[test]
    fn the_round_price_book_holds_the_committed_reorg_window() {
        let book = RoundPriceBook::new();
        assert_eq!(book.seen_at("aa"), None);

        book.note_tip_block("aa", 1_000);
        assert_eq!(book.seen_at("aa"), Some(1_000));
        assert_eq!(book.seen_at("bb"), None, "an unseen block has no sighting");

        // A committed ancestor keeps its sighting when the tip moves past it:
        // that is the fork block of every reorg candidate.
        book.note_tip_block("bb", 5_000);
        assert_eq!(book.seen_at("aa"), Some(1_000));
        assert_eq!(book.seen_at("bb"), Some(5_000));

        // Re-committing a block does not backdate its first sighting.
        book.note_tip_block("aa", 9_000);
        assert_eq!(book.seen_at("aa"), Some(1_000));

        // The window is bounded: only the last `ROUND_PRICE_WINDOW` blocks are
        // remembered, so the book cannot be grown without limit.
        for height in 0..(ROUND_PRICE_WINDOW as u64 + 5) {
            book.note_tip_block(&format!("h{height}"), 10_000 + u128::from(height));
        }
        assert_eq!(book.seen_at("aa"), None, "evicted from the window");
        assert_eq!(
            book.seen_at(&format!("h{}", ROUND_PRICE_WINDOW as u64 + 4)),
            Some(10_000 + u128::from(ROUND_PRICE_WINDOW as u64) + 4)
        );
        assert_eq!(ROUND_PRICE_WINDOW, MAX_REORG_DEPTH + 1);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAX_FUTURE_BLOCK_TIME_MS, 15_000);
        assert_eq!(MIN_BLOCK_INTERVAL_MS, 1000);
        assert_eq!(MAX_REORG_DEPTH, 100);
        // One definition, two gates. `try_reorg` refuses a deep reorg at the
        // state machine and `is_better_chain` refuses it at fork choice; they
        // used to hold separate `= 100` literals with nothing connecting them,
        // so raising one silently left the other enforcing the old depth, a
        // chain accepted by one gate and refused by the other.
        assert_eq!(
            crate::chain::blockchain::MAX_REORG_DEPTH,
            MAX_REORG_DEPTH,
            "the chain layer must re-export this constant, not redeclare it"
        );
    }

    /// `can_reorg` used `len - Block::index - 1`, which only holds when the
    /// slice starts at height zero. A suffix (the shape a sync round hands
    /// over) underflowed in debug builds and produced a wrapped depth in
    /// release builds. Depth now comes from the slice position.
    #[test]
    fn can_reorg_measures_depth_from_slice_position() {
        fn block(height: u64, prev: &str) -> Block {
            let mut b = Block::new_with_chain_id(height, prev.to_string(), vec![], 1);
            b.hash = b.calculate_hash();
            b
        }
        let engine = crate::consensus::pow::PoWEngine::new(0);

        // Current chain is a suffix starting at height 1000.
        let mut current = vec![block(1000, "root")];
        for h in 1001..1003 {
            let prev = current.last().unwrap().hash.clone();
            current.push(block(h, &prev));
        }
        // New chain forks from the first suffix block and is longer.
        let mut new_chain = vec![current[0].clone()];
        for h in 1001..1005 {
            let prev = new_chain.last().unwrap().hash.clone();
            new_chain.push(block(h, &format!("{prev}-fork")));
        }
        // Depth from the ancestor is 2, well under MAX_REORG_DEPTH.
        assert!(engine.can_reorg(&current, &new_chain));

        // A fork deeper than MAX_REORG_DEPTH is still refused on a suffix.
        let mut deep_current = vec![block(1000, "root")];
        for h in 1001..(1001 + MAX_REORG_DEPTH as u64 + 1) {
            let prev = deep_current.last().unwrap().hash.clone();
            deep_current.push(block(h, &prev));
        }
        let mut deep_new = vec![deep_current[0].clone()];
        for h in 1001..(1001 + MAX_REORG_DEPTH as u64 + 2) {
            let prev = deep_new.last().unwrap().hash.clone();
            deep_new.push(block(h, &format!("{prev}-fork")));
        }
        assert!(!engine.can_reorg(&deep_current, &deep_new));
    }

    /// The suffix reorg shortcut is only applied where it is sound.
    ///
    /// `try_reorg_suffix` answers a batch that cannot win before it
    /// materializes the local prefix, and it may only do that on an engine
    /// where a strictly shorter chain can never win. Length-based PoA
    /// qualifies; PoW (accumulated work) and PoS (checkpoint score) do not,
    /// because a shorter chain can be heavier or carry a better checkpoint.
    /// An engine that flips this without updating the shortcut would refuse
    /// honest reorgs, and flipping the shortcut without the engine would let
    /// a peer force the copy. Both directions are pinned here.
    #[test]
    fn only_length_based_engines_may_reject_a_shorter_candidate() {
        use crate::consensus::poa::{PoAConfig, PoAEngine};
        use crate::consensus::pos::{PoSConfig, PoSEngine};
        use crate::consensus::pow::PoWEngine;

        assert!(
            PoAEngine::new(PoAConfig::default(), None).shorter_chain_can_never_win(),
            "PoA scores chain length"
        );
        assert!(
            !PoWEngine::new(0).shorter_chain_can_never_win(),
            "accumulated work lets a shorter chain win; the shortcut must not apply"
        );
        assert!(
            !PoSEngine::new(PoSConfig::default(), None).shorter_chain_can_never_win(),
            "a checkpoint score lets a shorter chain win; the shortcut must not apply"
        );
    }

    /// A longer candidate that shares no block with the current slice is a
    /// reorg of the whole slice. Under the cap it is admitted; over the cap
    /// it is refused, the same as a fork from a known ancestor. This used to
    /// skip the depth check when no ancestor was found.
    #[test]
    fn can_reorg_treats_no_ancestor_as_a_whole_slice_reorg() {
        fn block(height: u64, prev: &str) -> Block {
            let mut b = Block::new_with_chain_id(height, prev.to_string(), vec![], 1);
            b.hash = b.calculate_hash();
            b
        }
        let engine = crate::consensus::pow::PoWEngine::new(0);
        let build = |len: usize, tag: &str| {
            let mut chain = vec![block(1000, tag)];
            for h in 1001..(1000 + len as u64) {
                let prev = chain.last().unwrap().hash.clone();
                chain.push(block(h, &prev));
            }
            chain
        };
        let short_current = build(3, "root-a");
        let short_new = build(4, "root-b");
        assert!(engine.can_reorg(&short_current, &short_new));

        let deep_current = build(MAX_REORG_DEPTH + 1, "root-a");
        let deep_new = build(MAX_REORG_DEPTH + 2, "root-b");
        assert!(
            !engine.can_reorg(&deep_current, &deep_new),
            "a candidate with no shared block replaces the whole slice"
        );
    }

    #[test]
    fn unseen_candidate_parent_inherits_committed_ancestor_instead_of_header_stamp() {
        fn block(height: u64, prev: &str, ts: u128) -> Block {
            let mut b = Block::new_with_chain_id(height, prev.to_string(), vec![], 1);
            b.timestamp = ts;
            b.hash = b.calculate_hash();
            b
        }

        let now = 500_000_u128;
        let stale_ts = 100_000_u128;
        let genesis = block(0, "0", stale_ts);
        let fork_parent = block(1, &genesis.hash, stale_ts + MIN_BLOCK_INTERVAL_MS);
        let chain = vec![genesis.clone(), fork_parent.clone()];

        let book = RoundPriceBook::new();
        book.note_tip_block(&genesis.hash, now);

        let anchor = book.chain_seen_at(&chain, &fork_parent, now);
        assert_eq!(anchor, now);
        assert_eq!(
            affordable_leader_round(fork_parent.timestamp, Some(anchor), now),
            0,
            "backdated candidate parent must not unlock rounds 1..=16 before timeout elapses"
        );

        let fresh_book = RoundPriceBook::new();
        let fallback_anchor = fresh_book.chain_seen_at(&chain, &fork_parent, now);
        assert_eq!(fallback_anchor, now);
        assert_eq!(
            affordable_leader_round(fork_parent.timestamp, Some(fallback_anchor), now),
            0,
            "unseen window must anchor at wall time rather than trusting stale header timestamps"
        );
    }
}
