use super::{ConsensusEngine, ConsensusError};
use crate::core::account::AccountState;
use crate::core::block::Block;

use crate::consensus::split_resolver::{resolve_split_tie, SplitCandidate, SplitDecision};
use std::sync::RwLock;
use tracing::info;

/// Nonces per mining chunk: the granularity at which the wall-clock budget
/// and the staleness check run (P01-F16).
const MINE_CHUNK: u64 = 10_000;

/// A 256-bit unsigned integer, carrying exactly the three operations
/// accumulated proof-of-work needs: `2^n`, addition, and comparison.
///
/// Chainwork does not fit 128 bits (see [`PoWEngine::accumulated_work`]), and
/// pulling in a bignum crate to add four numbers would be a dependency, an
/// audit obligation and a supply-chain entry for arithmetic that is a dozen
/// lines. Stored as four little-endian 64-bit limbs; `Ord` is derived over the
/// big-endian view via an explicit comparison so ordering matches magnitude.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct U256 {
    /// Little-endian limbs: `limbs[0]` is the least significant.
    limbs: [u64; 4],
}

impl U256 {
    pub const ZERO: Self = Self { limbs: [0; 4] };
    pub const MAX: Self = Self {
        limbs: [u64::MAX; 4],
    };

    /// `2^exponent`, saturating at [`U256::MAX`] rather than wrapping.
    ///
    /// Wrapping here would be the same class of bug this type exists to fix:
    /// a huge amount of work would score as a small one.
    #[must_use]
    pub const fn pow2(exponent: u32) -> Self {
        if exponent >= 256 {
            return Self::MAX;
        }
        let limb = (exponent / 64) as usize;
        let bit = exponent % 64;
        let mut limbs = [0u64; 4];
        limbs[limb] = 1u64 << bit;
        Self { limbs }
    }

    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        let mut limbs = [0u64; 4];
        let mut carry = 0u64;
        // Indexed rather than iterated: `const fn` has no iterators, and the
        // carry chain is inherently sequential across limbs anyway.
        let mut i = 0;
        while i < 4 {
            let (sum, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (sum, c2) = sum.overflowing_add(carry);
            limbs[i] = sum;
            carry = c1 as u64 + c2 as u64; // bool as u64: const fn, From unavailable
            i += 1;
        }
        if carry > 0 {
            Self::MAX
        } else {
            Self { limbs }
        }
    }

    /// The low 128 bits, saturating if anything is set above them.
    ///
    /// Only for reporting. A saturating value cannot order two chains, which
    /// is why `is_better_chain` compares `U256` directly.
    #[must_use]
    pub const fn saturating_to_u128(self) -> u128 {
        if self.limbs[2] != 0 || self.limbs[3] != 0 {
            return u128::MAX;
        }
        (self.limbs[0] as u128) | ((self.limbs[1] as u128) << 64)
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Most significant limb first, so ordering follows magnitude rather
        // than the little-endian storage order.
        for (lhs, rhs) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            match lhs.cmp(rhs) {
                std::cmp::Ordering::Equal => (),
                non_equal => return non_equal,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
#[derive(Debug, Clone)]
pub struct PoWConfig {
    pub difficulty: usize,
    pub target_block_time: u64,
    pub adjustment_interval: u64,
    /// Wall-clock budget for one mining attempt (P01-F16).
    ///
    /// Mining runs synchronously inside the chain actor, so an unbounded
    /// search starves RPC, validation and sync for as long as a hard nonce
    /// takes. The budget caps one attempt: the search gives up with an error,
    /// the actor drains its queue, and the producer loop retries on the
    /// current tip - which also bounds how stale the discarded work can get
    /// (P01-F16b). Defaults to 30 seconds: far beyond any difficulty this
    /// chain retargets to, far below "the node is gone".
    pub mine_time_budget_ms: u64,
}
impl Default for PoWConfig {
    fn default() -> Self {
        PoWConfig {
            difficulty: 2,
            target_block_time: 10,
            adjustment_interval: 100,
            mine_time_budget_ms: 30_000,
        }
    }
}
pub struct PoWEngine {
    pub config: PoWConfig,
    current_difficulty: RwLock<usize>,
}
impl PoWEngine {
    pub fn new(difficulty: usize) -> Self {
        PoWEngine {
            config: PoWConfig {
                difficulty,
                ..Default::default()
            },
            current_difficulty: RwLock::new(difficulty),
        }
    }

    /// Test adapter over the production retarget (P01-F17).
    ///
    /// The old copy reimplemented the expected-time product and called
    /// `retarget` directly, so the tests could stay green while
    /// `adjusted_difficulty` itself broke. This builds the two boundary
    /// blocks and runs the real path.
    #[cfg(test)]
    pub fn adjusted_difficulty_for_test(&self, current: usize, actual_time_sn: u64) -> usize {
        let first = Block {
            timestamp: 1_000_000,
            ..Block::new_with_chain_id(0, "0".repeat(64), vec![], 42)
        };
        let last = Block {
            timestamp: first.timestamp + u128::from(actual_time_sn) * 1000,
            ..Block::new_with_chain_id(1, first.hash.clone(), vec![], 42)
        };
        self.adjusted_difficulty(current, &first, &last)
    }
    /// An engine calibrated to the producer's tick interval.
    ///
    /// `new` always takes `PoWConfig::default()` (a 10 second target), while
    /// the producer ticks at `slot_ms`: 1 second on devnet, 3 on testnet, 6 on
    /// mainnet. Because the two numbers know nothing about each other, the
    /// retarget counts the chain as "too fast" and quadruples the difficulty
    /// every 100 blocks.
    ///
    /// Measured on a live devnet node: at block 100 the difficulty went from 2
    /// to 8 (32 zero bits), then no block was found in 364 million iterations
    /// and the chain stopped. The climb continues 2 -> 8 -> 32 (the ceiling),
    /// so there is no way back.
    ///
    /// This constructor equates the target with the production rate, so the
    /// retarget measures real drift rather than a fixed calibration error.
    pub fn calibrated(difficulty: usize, slot_ms: u64) -> Self {
        let target_block_time = (slot_ms / 1000).max(1);
        PoWEngine::with_config(PoWConfig {
            difficulty,
            target_block_time,
            ..Default::default()
        })
    }

    pub fn with_config(config: PoWConfig) -> Self {
        let d = config.difficulty;
        PoWEngine {
            config,
            current_difficulty: RwLock::new(d),
        }
    }
    /// Accumulated proof-of-work across `chain`, in 256 bits.
    ///
    /// Work per block is `16^difficulty` - one hex digit of leading zeroes per
    /// difficulty step. `adjusted_difficulty` clamps difficulty to 32, and
    /// `16^32` is exactly `2^128`, so the retarget ceiling sits precisely at
    /// the boundary of a `u128`. That is not a coincidence to design around;
    /// it is the same 128 appearing on both sides.
    ///
    /// The previous accumulator saturated instead of widening:
    ///
    /// ```text
    /// let work = 16u128.checked_pow(d).unwrap_or(u128::MAX);
    /// score = score.saturating_add(work.max(1));
    /// ```
    ///
    /// Measured, all of these produced the identical score:
    ///
    /// ```text
    /// difficulty 32, any chain length  -> u128::MAX
    /// difficulty 31, 16 blocks or more -> u128::MAX
    /// ```
    ///
    /// Once two candidates both saturate they compare equal, `is_better_chain`
    /// returns false for every reorg, and the node locks onto whichever chain
    /// it saw first with no way to be corrected. Saturation is not a
    /// conservative failure here: it disables fork choice silently, at exactly
    /// the difficulties a mature chain reaches.
    ///
    /// Scaling every term down by a shared constant would preserve ordering at
    /// the top but destroy it at the bottom - devnet runs at difficulty 1 or 2,
    /// and a shift large enough to save difficulty 32 flattens those to zero.
    /// Bitcoin carries chainwork in 256 bits for this reason, so this does too.
    ///
    /// One forward pass. The retarget boundaries below a height are folded in
    /// as the walk reaches them, which is the same sequence
    /// `difficulty_for_next_block` computes for each prefix; calling that per
    /// block made this quadratic in chain length, and fork choice calls it
    /// for both candidates on every comparison.
    #[must_use]
    pub fn accumulated_work(&self, chain: &[Block]) -> U256 {
        let interval = self.config.adjustment_interval as usize;
        let mut difficulty = self.config.difficulty;
        let mut next_boundary = interval;
        let mut score = U256::ZERO;
        for index in 1..chain.len() {
            if interval > 0 {
                while next_boundary < index {
                    difficulty = self.fold_retarget_boundary(difficulty, chain, next_boundary);
                    next_boundary = next_boundary.saturating_add(interval);
                }
            }
            // 16^d == 2^(4d); take the exponent directly so no intermediate
            // has to fit a narrower type.
            let work = U256::pow2(
                u32::try_from(difficulty)
                    .unwrap_or(u32::MAX)
                    .saturating_mul(4),
            );
            score = score.saturating_add(work);
        }
        score
    }

    /// Apply the retarget at `boundary` (a slice position inside `chain`) to
    /// `difficulty`, or return it unchanged when the block there is not on an
    /// adjustment height. Shared by the per-prefix and the single-pass walks
    /// so the two cannot drift apart.
    fn fold_retarget_boundary(&self, difficulty: usize, chain: &[Block], boundary: usize) -> usize {
        let interval = self.config.adjustment_interval as usize;
        let boundary_block = &chain[boundary];
        if boundary_block.index > 0
            && boundary_block
                .index
                .is_multiple_of(self.config.adjustment_interval)
        {
            let first_index = boundary.saturating_add(1).saturating_sub(interval);
            return self.adjusted_difficulty(difficulty, &chain[first_index], boundary_block);
        }
        difficulty
    }

    pub fn get_difficulty(&self) -> usize {
        *self
            .current_difficulty
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn meets_difficulty_at(hash_hex: &str, difficulty: usize) -> bool {
        let hash_bytes = match hex::decode(hash_hex) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let leading_zero_bits = difficulty.saturating_mul(4);
        let full_bytes = leading_zero_bits / 8;
        let remaining_bits = leading_zero_bits % 8;
        if hash_bytes.len() < full_bytes + usize::from(remaining_bits > 0) {
            return false;
        }
        if hash_bytes[..full_bytes].iter().any(|byte| *byte != 0) {
            return false;
        }
        if remaining_bits > 0 {
            let mask = 0xFFu8 << (8 - remaining_bits);
            if hash_bytes[full_bytes] & mask != 0 {
                return false;
            }
        }
        true
    }

    #[cfg(test)]
    fn meets_difficulty(&self, hash_hex: &str) -> bool {
        Self::meets_difficulty_at(hash_hex, self.get_difficulty())
    }

    /// Mine `block` until it meets `difficulty`, or give up.
    ///
    /// Returns `true` when solved. The search is bounded (P01-F16): every
    /// [`MINE_CHUNK`] nonces it checks the wall-clock budget and, in the
    /// chain-aware entry points, that the block is still built on the tip it
    /// was prepared for (P01-F16b). Stale or unsolved work is discarded and
    /// re-prepared rather than mined forever on a tip the network has left.
    fn mine_at_difficulty(&self, block: &mut Block, difficulty: usize) -> bool {
        self.mine_at_difficulty_on(block, difficulty, || false)
    }

    fn mine_at_difficulty_on(
        &self,
        block: &mut Block,
        difficulty: usize,
        work_is_stale: impl Fn() -> bool,
    ) -> bool {
        let mut iterations: u64 = 0;
        info!(
            "Mining started (difficulty: {}, binary target: {} leading zero bits)",
            difficulty,
            difficulty.saturating_mul(4),
        );
        let started = std::time::Instant::now();
        while !Self::meets_difficulty_at(&block.hash, difficulty) {
            if iterations.is_multiple_of(MINE_CHUNK) {
                if work_is_stale() {
                    info!(
                        "Mining abandoned after {} iterations: the block is no longer built on the tip",
                        iterations
                    );
                    return false;
                }
                if started.elapsed().as_millis() >= u128::from(self.config.mine_time_budget_ms) {
                    info!(
                        "Mining budget exhausted after {} iterations ({} ms): dropping stale work and re-preparing on the current tip",
                        iterations,
                        started.elapsed().as_millis()
                    );
                    return false;
                }
            }
            block.nonce = block.nonce.saturating_add(1);
            block.hash = block.calculate_hash();
            iterations = iterations.saturating_add(1);
            if iterations.is_multiple_of(100_000) {
                info!(
                    "Mining progress: {} iterations, nonce: {}",
                    iterations, block.nonce
                );
            }
        }
        info!(
            "Mining complete: {} iterations, nonce: {}",
            iterations, block.nonce
        );
        true
    }

    fn adjusted_difficulty(&self, current: usize, first: &Block, last: &Block) -> usize {
        let actual_time = u64::try_from(last.timestamp.saturating_sub(first.timestamp) / 1000)
            .unwrap_or(u64::MAX);
        let expected_time = self
            .config
            .target_block_time
            .saturating_mul(self.config.adjustment_interval);
        Self::retarget(current, expected_time, actual_time)
    }

    /// Work per block is `16^difficulty`, so the difficulty is a logarithm of
    /// the work. A ratio `r` of expected to actual time needs `log16(r)` more
    /// digits, not a digit count that is `r` times larger. Round `log16(r)` to
    /// the nearest digit: the cut points are the geometric midpoints 4x and
    /// 1/4x. One step per interval at most, and the result stays in `[1, 32]`.
    fn retarget(current: usize, expected_time: u64, actual_time: u64) -> usize {
        let ratio_scaled = (u128::from(expected_time) * 100) / u128::from(actual_time).max(1);
        let next = if ratio_scaled >= 400 {
            current.saturating_add(1)
        } else if ratio_scaled <= 25 {
            current.saturating_sub(1)
        } else {
            current
        };
        next.clamp(1, 32)
    }

    pub fn difficulty_for_next_block(&self, chain: &[Block]) -> usize {
        let interval = self.config.adjustment_interval as usize;
        let mut difficulty = self.config.difficulty;
        if interval == 0 {
            return difficulty;
        }
        let mut boundary = interval;
        while boundary < chain.len() {
            difficulty = self.fold_retarget_boundary(difficulty, chain, boundary);
            boundary = boundary.saturating_add(interval);
        }
        difficulty
    }

    pub fn calculate_new_difficulty(&self, chain: &[Block]) -> usize {
        self.difficulty_for_next_block(chain)
    }

    /// (security audit §3) difficulty-adjustment driver invoked
    /// From `blockchain.rs` after a block has been durably committed.
    /// Public so the blockchain can drive the adjustment with the full
    /// Post-commit chain in hand. The previous design mutated
    /// `current_difficulty` from inside `validate_block`, which was
    /// Both impure and vulnerable to re-validation attacks.
    pub fn record_block_with_chain(&self, block: &Block, chain: &[Block]) {
        if block.index > 0 && block.index.is_multiple_of(self.config.adjustment_interval) {
            let new_diff = self.calculate_new_difficulty(chain);
            if let Ok(mut d) = self.current_difficulty.write() {
                *d = new_diff;
            }
        }
    }
}
impl ConsensusEngine for PoWEngine {
    fn prepare_block(
        &self,
        block: &mut Block,
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        block.hash = block.calculate_hash();
        if self.mine_at_difficulty(block, self.get_difficulty()) {
            Ok(())
        } else {
            Err(ConsensusError(
                "PoW mining budget exhausted - retry from the current tip".to_string(),
            ))
        }
    }

    fn prepare_block_with_chain(
        &self,
        block: &mut Block,
        _state: &AccountState,
        chain: &[Block],
    ) -> Result<(), ConsensusError> {
        let difficulty = self.difficulty_for_next_block(chain);
        let tip_hash = chain.last().map(|b| b.hash.clone());
        let prev_hash = block.previous_hash.clone();
        block.hash = block.calculate_hash();
        // P01-F16b: work on a block that is no longer anchored to the tip the
        // chain slice carries is abandoned instead of mined to completion and
        // then rejected.
        if self.mine_at_difficulty_on(block, difficulty, || {
            tip_hash.as_deref() != Some(prev_hash.as_str())
        }) {
            Ok(())
        } else {
            Err(ConsensusError(
                "PoW mining abandoned - retry from the current tip".to_string(),
            ))
        }
    }

    fn validate_block(
        &self,
        block: &Block,
        chain: &[Block],
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        if block.index == 0 {
            if block.hash != block.calculate_hash() {
                return Err(ConsensusError("Invalid genesis block hash".into()));
            }
            return Ok(());
        }
        if let Some(prev_block) = chain.last() {
            if block.previous_hash != prev_block.hash {
                return Err(ConsensusError(format!(
                    "Previous hash mismatch. Expected: {}, Got: {}",
                    prev_block.hash, block.previous_hash
                )));
            }
        }
        let calculated_hash = block.calculate_hash();
        if block.hash != calculated_hash {
            return Err(ConsensusError(format!(
                "Invalid block hash. Calculated: {}, Existing: {}",
                calculated_hash, block.hash
            )));
        }

        // Difficulty is replayed from the candidate prefix. Validation never
        // Trusts process-local cache state, so restart and fork validation use
        // Exactly the target that the historical chain implies.
        let expected_difficulty = self.difficulty_for_next_block(chain);
        if !Self::meets_difficulty_at(&block.hash, expected_difficulty) {
            return Err(ConsensusError(format!(
                "Invalid PoW. {} leading-zero nibbles required, hash: {}",
                expected_difficulty, block.hash
            )));
        }
        Ok(())
    }

    fn record_block(
        &self,
        _block: &Block,
        _storage: Option<&crate::storage::db::Storage>,
    ) -> Result<(), ConsensusError> {
        // (security audit §3) the trait `record_block` hook is
        // Intentionally a no-op for PoW. The actual difficulty
        // Adjustment lives in `record_block_with_chain` (overridden
        // Below), which is called from `blockchain.rs` after a block
        // Is durably committed and the chain is in its post-commit
        // State. Keeping the trait hook as a no-op makes the
        // Contract explicit: validation is pure, and the only
        // State mutation triggered by a block landing on the chain
        // Is the chain-aware record path.
        Ok(())
    }

    fn record_block_with_chain(
        &self,
        block: &Block,
        chain: &[Block],
        _storage: Option<&crate::storage::db::Storage>,
    ) {
        // See `record_block_with_chain` in `consensus/mod.rs` for the
        // Contract. The difficulty adjustment fires here, exactly
        // Once per block, after the block has been accepted and
        // Durably committed (see `produce_block` and
        // `validate_and_add_block` in blockchain.rs, which call this
        // Method after `commit_block_durable`).
        if block.index > 0 && block.index.is_multiple_of(self.config.adjustment_interval) {
            let new_diff = self.calculate_new_difficulty(chain);
            if let Ok(mut d) = self.current_difficulty.write() {
                *d = new_diff;
            }
        }
    }
    fn consensus_type(&self) -> &'static str {
        "PoW"
    }
    fn info(&self) -> String {
        format!(
            "PoW (difficulty: {}, binary target: {} leading zero bits)",
            self.get_difficulty(),
            self.get_difficulty() * 4
        )
    }

    fn fork_choice_score(&self, chain: &[Block]) -> u128 {
        // Retained for the trait's reporting use. Chain comparison goes
        // through `accumulated_work`, which does not truncate; this value is
        // the low 128 bits and can saturate, so it must not decide a reorg.
        self.accumulated_work(chain).saturating_to_u128()
    }

    /// A shorter chain can hold more accumulated work: replacing two easy
    /// blocks with one hard one wins fork choice. The suffix shortcut must not
    /// refuse it.
    fn shorter_chain_can_never_win(&self) -> bool {
        false
    }

    fn is_better_chain(&self, current: &[Block], candidate: &[Block]) -> bool {
        let current_work = self.accumulated_work(current);
        let candidate_work = self.accumulated_work(candidate);
        if candidate_work != current_work {
            return candidate_work > current_work;
        }
        // Equal accumulated work is the exact case the deterministic
        // resolver exists for. A strict `>` refused the reorg in both
        // directions, so two honest nodes that first adopted opposite tips
        // kept opposite heads for good: a permanent fork out of fully
        // honest behaviour. The resolver orders equal-work tips by height,
        // then block hash, then proposer, so every node that sees the same
        // two tips picks the same one regardless of arrival order. Work
        // that saturates U256 still compares equal here, and the
        // low-128-bit score must never decide this branch.
        resolve_split_tie(
            &SplitCandidate::from_chain_tip(current, current_work.saturating_to_u128()),
            &SplitCandidate::from_chain_tip(candidate, candidate_work.saturating_to_u128()),
        ) == SplitDecision::RightWins
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pow_mining() {
        let engine = PoWEngine::new(1);
        let mut block = Block::new(1, "0".repeat(64), vec![]);
        let state = AccountState::new();
        engine.prepare_block(&mut block, &state).unwrap();
        assert!(block.hash.starts_with("0"));
    }
    #[test]
    fn test_pow_validation() {
        let engine = PoWEngine::new(1);
        let mut block = Block::new(1, "0".repeat(64), vec![]);
        let state = AccountState::new();
        engine.prepare_block(&mut block, &state).unwrap();
        assert!(engine.validate_block(&block, &[], &state).is_ok());
        let mut tampered = block.clone();
        tampered.hash = "invalid_hash".to_string();
        assert!(engine.validate_block(&tampered, &[], &state).is_err());
    }
    #[test]
    fn test_difficulty_levels() {
        let easy = PoWEngine::new(1);
        let hard = PoWEngine::new(2);
        let mut block1 = Block::new(1, "0".repeat(64), vec![]);
        let mut block2 = Block::new(1, "0".repeat(64), vec![]);
        let state = AccountState::new();
        easy.prepare_block(&mut block1, &state).unwrap();
        hard.prepare_block(&mut block2, &state).unwrap();
        assert!(block1.hash.starts_with("0"));
        assert!(block2.hash.starts_with("00"));
    }

    /// (security audit §3) `validate_block` must be PURE, calling
    /// It twice on the same block must produce the same result AND
    /// Must not mutate the engine's `current_difficulty`. The
    /// Previous implementation mutated difficulty from inside
    /// Validation, so the *second* call could see a different
    /// Difficulty than the first.
    #[test]
    fn validate_block_is_pure_and_idempotent() {
        let engine = PoWEngine::with_config(PoWConfig {
            difficulty: 1,
            target_block_time: 10,
            adjustment_interval: 100,
            ..Default::default()
        });
        let state = AccountState::new();

        // Build a chain with a real genesis block so `validate_block`
        // Can match `block.previous_hash` against the previous block.
        let mut genesis = Block::new(0, "0".repeat(64), vec![]);
        genesis.hash = genesis.calculate_hash();

        // Mine a child block at difficulty 1.
        let mut child = Block::new(1, genesis.hash.clone(), vec![]);
        engine.prepare_block(&mut child, &state).unwrap();

        let chain = vec![genesis];
        let diff_before = engine.get_difficulty();
        let result_1 = engine.validate_block(&child, &chain, &state);
        let diff_after_1 = engine.get_difficulty();
        let result_2 = engine.validate_block(&child, &chain, &state);
        let diff_after_2 = engine.get_difficulty();
        assert!(
            result_1.is_ok(),
            "first validate must succeed: {:?}",
            result_1.err()
        );
        assert!(
            result_2.is_ok(),
            "second validate must also succeed: {:?}",
            result_2.err()
        );
        assert_eq!(
            diff_before, diff_after_1,
            "validate must not mutate difficulty (first call)"
        );
        assert_eq!(
            diff_after_1, diff_after_2,
            "validate must not mutate difficulty (second call)"
        );
    }

    /// (security audit §3) difficulty adjustment must fire
    /// From `record_block_with_chain`, NOT from `validate_block`.
    /// Here, an adjustment-boundary block is *validated* without a
    /// Prior `record_block_with_chain` call, and the difficulty
    /// Must remain at its pre-adjustment value. The adjustment only
    /// Fires once the chain-aware record path is invoked.
    #[test]
    fn difficulty_adjustment_fires_only_from_record_block_with_chain() {
        let engine = PoWEngine::with_config(PoWConfig {
            difficulty: 1,
            target_block_time: 10,
            adjustment_interval: 4,
            ..Default::default()
        });
        assert_eq!(engine.get_difficulty(), 1);

        // Build a synthetic chain of 4 blocks (adjustment boundary
        // At index 4, which is `is_multiple_of(4)`). Difficulty 1
        // Mining is fast - we don't need the chain to be long.
        // P01-F17: the timestamps are stamped explicitly (1 s apart), so the
        // retarget below asserts the exact post-adjustment value instead of
        // only the `[1, 32]` clamp on whatever the wall clock happened to
        // produce.
        let mut chain: Vec<Block> = Vec::new();
        let mut genesis = Block::new(0, "0".repeat(64), vec![]);
        genesis.timestamp = 1_000_000;
        let genesis_ts = genesis.timestamp;
        genesis.hash = genesis.calculate_hash();
        chain.push(genesis);
        for i in 1..=4u64 {
            let prev_hash = chain[(i - 1) as usize].hash.clone();
            let mut b = Block::new(i, prev_hash, vec![]);
            b.timestamp = genesis_ts + u128::from(i) * 1_000;
            let state = AccountState::new();
            engine.prepare_block(&mut b, &state).unwrap();
            chain.push(b);
        }
        let boundary = &chain[4usize];

        // Validating the boundary block alone must NOT trigger the
        // Adjustment (validate is pure). The chain passed to
        // `validate_block` is everything *before* the boundary block
        // (genesis + blocks 1..4), since the block being validated is
        // Not yet part of the chain the validator sees.
        let state = AccountState::new();
        let prefix = &chain[..4];
        assert!(engine.validate_block(boundary, prefix, &state).is_ok());
        assert_eq!(
            engine.get_difficulty(),
            1,
            "validate must not adjust difficulty"
        );

        // Now drive the adjustment through the chain-aware record
        // Path. The chain here is the *post-commit* chain (boundary is
        // the last block). 4 blocks in 4 s against a 40 s target is 10x
        // too fast: exactly one digit up (P01-F17: an exact value, not a
        // range).
        engine.record_block_with_chain(boundary, &chain);
        let diff_after_record = engine.get_difficulty();
        assert_eq!(
            diff_after_record, 2,
            "10x too fast must add exactly one difficulty digit, got {diff_after_record}"
        );
    }

    /// The single-pass accumulator must agree with the per-prefix definition
    /// on a chain whose difficulty actually moves at the boundaries.
    #[test]
    fn accumulated_work_single_pass_matches_per_prefix_definition() {
        let engine = PoWEngine::with_config(PoWConfig {
            difficulty: 2,
            target_block_time: 10,
            adjustment_interval: 3,
            ..Default::default()
        });
        let mut chain: Vec<Block> = Vec::new();
        let mut genesis = Block::new(0, "0".repeat(64), vec![]);
        genesis.timestamp = 0;
        genesis.hash = genesis.calculate_hash();
        chain.push(genesis);
        for i in 1..=14u64 {
            let prev_hash = chain[(i - 1) as usize].hash.clone();
            let mut b = Block::new(i, prev_hash, vec![]);
            // Alternate fast and slow stretches so the retarget goes both ways.
            b.timestamp = if (i / 3) % 2 == 0 {
                u128::from(i) * 1_000
            } else {
                u128::from(i) * 90_000
            };
            b.hash = b.calculate_hash();
            chain.push(b);
        }

        let mut expected = U256::ZERO;
        let mut seen = std::collections::BTreeSet::new();
        for index in 1..chain.len() {
            let difficulty = engine.difficulty_for_next_block(&chain[..index]);
            seen.insert(difficulty);
            expected = expected.saturating_add(U256::pow2(difficulty as u32 * 4));
        }
        assert!(
            seen.len() > 1,
            "the fixture must exercise a retarget: {seen:?}"
        );
        assert_eq!(engine.accumulated_work(&chain), expected);

        // A zero interval means a flat difficulty, in both walks.
        let flat = PoWEngine::with_config(PoWConfig {
            difficulty: 3,
            target_block_time: 10,
            adjustment_interval: 0,
            ..Default::default()
        });
        let mut flat_expected = U256::ZERO;
        for _ in 1..chain.len() {
            flat_expected = flat_expected.saturating_add(U256::pow2(12));
        }
        assert_eq!(flat.accumulated_work(&chain), flat_expected);
    }

    #[test]
    fn test_difficulty_adjustment_safely_handles_non_monotonic_timestamps() {
        let mut engine = PoWEngine::new(1);
        engine.config.adjustment_interval = 2;
        let mut block1 = Block::new(1, "g".into(), vec![]);
        block1.timestamp = 2000;
        let mut block2 = Block::new(2, "b1".into(), vec![]);
        block2.timestamp = 1000;
        let chain = vec![block1, block2.clone()];
        engine.record_block_with_chain(&block2, &chain);
        assert!((1..=32).contains(&engine.get_difficulty()));
    }

    /// Binary difficulty check correctly validates
    /// Hashes with leading zero bits.
    #[test]
    fn meets_difficulty_binary_check() {
        let engine = PoWEngine::new(1);
        // Difficulty=1 → 4 leading zero bits → first hex char must be '0'
        assert!(engine.meets_difficulty("0abc1234"));
        assert!(!engine.meets_difficulty("1abc1234"));

        let engine2 = PoWEngine::new(2);
        // Difficulty=2 → 8 leading zero bits → first two hex chars "00"
        assert!(engine2.meets_difficulty("00abcdef"));
        assert!(!engine2.meets_difficulty("01abcdef"));

        // Odd difficulty: difficulty=3 → 12 leading zero bits → "000" prefix
        let engine3 = PoWEngine::new(3);
        assert!(engine3.meets_difficulty("000abcde"));
        assert!(!engine3.meets_difficulty("001abcde"));

        // Invalid hex should return false, not panic
        assert!(!engine.meets_difficulty("not-a-hex-string"));
    }
    /// FINDING: the producer's tick interval (`slot_ms`) and the PoW retarget
    /// target (`target_block_time`) are set up in ignorance of each other.
    /// `PoWEngine::new` always takes `PoWConfig::default()` (10 seconds) while
    /// the devnet slot is 1 second. Measured: a live devnet node jumped the
    /// difficulty from 2 to 8 (32 zero bits) at block 100, found no block in
    /// 285 million iterations and the chain stopped. Because the retarget can
    /// rise at most 4x every 100 blocks, the climb goes 2 -> 8 -> 32 (the
    /// ceiling); that is a lock with no way back. The existing tests only
    /// verified the [1,32] clamp, not the proportionality.
    #[test]
    fn the_retarget_has_to_be_calibrated_to_the_producer_rate() {
        // The rate the chain really produces at: 1 s per block (devnet
        // slot_ms=1000).
        let real_slot_secs = 1u64;
        // If the target is calibrated to that rate the difficulty has to stay
        // put.
        let engine = PoWEngine::with_config(PoWConfig {
            difficulty: 2,
            target_block_time: real_slot_secs,
            adjustment_interval: 100,
            ..Default::default()
        });
        // 100 blocks x 1 s = 100 s elapsed, and 100 s expected.
        let d = engine.adjusted_difficulty_for_test(2, 100);
        assert_eq!(
            d, 2,
            "the difficulty must not change when the producer rate equals the target, found {d}"
        );

        // Without calibration (the default 10 second target) the same chain
        // counts as 10x too fast. The difficulty is a logarithm of the work,
        // so it rises by one digit (16x work), not to 8 (BLG-0013).
        let uncalibrated = PoWEngine::new(2);
        let d2 = uncalibrated.adjusted_difficulty_for_test(2, 100);
        assert_eq!(
            d2, 3,
            "an uncalibrated engine counts 100 blocks over 100 s as 10x too fast and raises the difficulty by one digit"
        );
    }

    /// `calibrated` equates the retarget with the production rate on every
    /// network.
    #[test]
    fn calibrated_equates_the_target_with_the_production_rate() {
        // (slot_ms, the expected target in seconds)
        for (slot_ms, expected) in [(1_000u64, 1u64), (3_000, 3), (6_000, 6)] {
            let e = PoWEngine::calibrated(2, slot_ms);
            assert_eq!(
                e.config.target_block_time, expected,
                "the target for a {slot_ms}ms slot has to be {expected} s"
            );
            // While the chain produces at exactly that rate the difficulty has
            // to stay put.
            let elapsed = expected.saturating_mul(e.config.adjustment_interval);
            assert_eq!(
                e.adjusted_difficulty_for_test(2, elapsed),
                2,
                "the difficulty must not change when production equals the target (slot {slot_ms}ms)"
            );
        }
    }

    /// Calibration must not lead to a division by zero: slots under 1 second
    /// settle on the floor.
    #[test]
    fn calibrated_does_not_fall_to_zero_at_the_lower_bound() {
        let e = PoWEngine::calibrated(2, 200);
        assert_eq!(
            e.config.target_block_time, 1,
            "the target has to be at least 1 s"
        );
    }

    /// BLG-0013: the retarget adds `log16(ratio)` digits. It must not scale
    /// the digit count by the ratio.
    #[test]
    fn retarget_moves_difficulty_by_log16_of_the_ratio() {
        let engine = PoWEngine::with_config(PoWConfig {
            difficulty: 2,
            target_block_time: 1,
            adjustment_interval: 100,
            ..Default::default()
        });
        // Expected 100 s. 4x too fast: one digit up (was 8 with linear scaling).
        assert_eq!(engine.adjusted_difficulty_for_test(2, 25), 3);
        // 1.5x too fast: no change (was 3).
        assert_eq!(engine.adjusted_difficulty_for_test(2, 67), 2);
        // 4x too slow: one digit down.
        assert_eq!(engine.adjusted_difficulty_for_test(4, 400), 3);
        // Floor and ceiling hold.
        assert_eq!(engine.adjusted_difficulty_for_test(1, 400), 1);
        assert_eq!(engine.adjusted_difficulty_for_test(32, 25), 32);
    }
}
