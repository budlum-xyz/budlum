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

/// The highest leader round a slot can have reached by `now_ms`.
///
/// Round `r` is affordable once `MIN_BLOCK_INTERVAL_MS + r * ROUND_TIMEOUT_MS`
/// has elapsed since the parent block's timestamp; the result is capped at
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
/// # Why the parent's timestamp is clamped
///
/// A parent's timestamp is not always the moment the parent was published.
/// Production stamps blocks from the slot schedule
/// (`genesis_time + index * slot_ms`), so on a chain that has fallen behind
/// its schedule the newest header can be minutes older than the moment it
/// actually landed. Pricing the round straight off that stamp made the gate
/// saturate: once the lag reached
/// `MIN_BLOCK_INTERVAL_MS + MAX_LEADER_ROUNDS * ROUND_TIMEOUT_MS` (49 s), every
/// round up to [`MAX_LEADER_ROUNDS`] was affordable at once, and every
/// authority or validator elected in one of them could publish a valid
/// competing block for a slot it does not lead. The gate then priced nothing
/// exactly when the chain was least healthy (CWE-807).
///
/// The anchor is therefore clamped to a window the chain already agrees on:
/// a parent stamp older than `now - MAX_FUTURE_BLOCK_TIME_MS` stops buying
/// rounds. That is the mirror image of the future bound - a header may be at
/// most [`MAX_FUTURE_BLOCK_TIME_MS`] ahead of a verifier - so the most a stale
/// parent can ever grant is
/// `(MAX_FUTURE_BLOCK_TIME_MS - MIN_BLOCK_INTERVAL_MS) / ROUND_TIMEOUT_MS`
/// (4) rounds, however far behind the schedule the chain has drifted. A real
/// stall still advances rounds, because a real stall moves the parent into
/// the window by elapsed time, not by schedule arithmetic.
pub fn affordable_leader_round(parent_timestamp_ms: u128, now_ms: u128) -> u64 {
    let anchor = parent_timestamp_ms.max(now_ms.saturating_sub(MAX_FUTURE_BLOCK_TIME_MS));
    let spaced = now_ms
        .saturating_sub(anchor)
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

    /// Schedule lag must not buy rounds.
    ///
    /// Production stamps blocks from the slot schedule, so a chain that has
    /// fallen behind its schedule carries parent timestamps that are much
    /// older than the moment the parent landed. Pricing straight off that
    /// stamp let the gate saturate: at 49 s of lag every round up to
    /// `MAX_LEADER_ROUNDS` was affordable at once and any authority could
    /// produce for a slot it does not lead. The anchor is clamped to the same
    /// window the future bound already allows, so the price flattens out.
    #[test]
    fn a_stale_parent_cannot_buy_more_rounds_than_a_stalled_one() {
        let now = 1_700_000_000_000u128;
        // A parent on time: nothing but round 0 is affordable.
        assert_eq!(affordable_leader_round(now - 1_500, now), 0);
        // A genuinely stalled slot: rounds advance with real elapsed time.
        assert_eq!(affordable_leader_round(now - 13_500, now), 4);
        // A parent ten minutes behind its schedule prices exactly the same as
        // one inside the window: the lag stops paying.
        let stale = affordable_leader_round(now - 600_000, now);
        assert_eq!(stale, 4, "schedule lag must not raise the price");
        assert!(
            stale < MAX_LEADER_ROUNDS,
            "the gate must never saturate to MAX_LEADER_ROUNDS on lag alone"
        );
        // The most a stale parent can grant is the future window, minus the
        // minimum block interval, in round timeouts.
        let ceiling =
            u64::try_from((MAX_FUTURE_BLOCK_TIME_MS - MIN_BLOCK_INTERVAL_MS) / ROUND_TIMEOUT_MS)
                .unwrap();
        assert_eq!(stale, ceiling.min(MAX_LEADER_ROUNDS));
        // A future-dated parent still prices at zero: it buys nothing.
        assert_eq!(affordable_leader_round(now + 60_000, now), 0);
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
}
