use super::{ConsensusEngine, ConsensusError};
use crate::core::account::AccountState;
use crate::core::block::Block;
use std::sync::RwLock;
use tracing::info;
#[derive(Debug, Clone)]
pub struct PoWConfig {
    pub difficulty: usize,
    pub target_block_time: u64,
    pub adjustment_interval: u64,
}
impl Default for PoWConfig {
    fn default() -> Self {
        PoWConfig {
            difficulty: 2,
            target_block_time: 10,
            adjustment_interval: 100,
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
    pub fn with_config(config: PoWConfig) -> Self {
        let d = config.difficulty;
        PoWEngine {
            config,
            current_difficulty: RwLock::new(d),
        }
    }
    pub fn get_difficulty(&self) -> usize {
        *self
            .current_difficulty
            .read()
            .unwrap_or_else(|e| e.into_inner())
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

    fn mine_at_difficulty(&self, block: &mut Block, difficulty: usize) {
        let mut iterations: u64 = 0;
        info!(
            "Mining started (difficulty: {}, binary target: {} leading zero bits)",
            difficulty,
            difficulty.saturating_mul(4),
        );
        while !Self::meets_difficulty_at(&block.hash, difficulty) {
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
    }

    fn adjusted_difficulty(&self, current: usize, first: &Block, last: &Block) -> usize {
        let actual_time = last.timestamp.saturating_sub(first.timestamp) / 1000;
        let expected_time = self
            .config
            .target_block_time
            .saturating_mul(self.config.adjustment_interval);
        let ratio_scaled = (expected_time as u128 * 100) / actual_time.max(1);
        let ratio_capped = ratio_scaled.clamp(25, 400);
        ((current as u128 * ratio_capped) / 100).clamp(1, 32) as usize
    }

    pub fn difficulty_for_next_block(&self, chain: &[Block]) -> usize {
        let interval = self.config.adjustment_interval as usize;
        let mut difficulty = self.config.difficulty;
        if interval == 0 {
            return difficulty;
        }
        let mut boundary = interval;
        while boundary < chain.len() {
            let boundary_block = &chain[boundary];
            if boundary_block.index > 0
                && boundary_block
                    .index
                    .is_multiple_of(self.config.adjustment_interval)
            {
                let first_index = boundary.saturating_add(1).saturating_sub(interval);
                difficulty =
                    self.adjusted_difficulty(difficulty, &chain[first_index], boundary_block);
            }
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
        self.mine_at_difficulty(block, self.get_difficulty());
        Ok(())
    }

    fn prepare_block_with_chain(
        &self,
        block: &mut Block,
        _state: &AccountState,
        chain: &[Block],
    ) -> Result<(), ConsensusError> {
        let difficulty = self.difficulty_for_next_block(chain);
        block.hash = block.calculate_hash();
        self.mine_at_difficulty(block, difficulty);
        Ok(())
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
        let mut score = 0u128;
        for index in 1..chain.len() {
            let difficulty = self.difficulty_for_next_block(&chain[..index]);
            let work = 16u128.checked_pow(difficulty as u32).unwrap_or(u128::MAX);
            score = score.saturating_add(work.max(1));
        }
        score
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

    /// (security audit §3) `validate_block` must be PURE — calling
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
        });
        assert_eq!(engine.get_difficulty(), 1);

        // Build a synthetic chain of 4 blocks (adjustment boundary
        // At index 4, which is `is_multiple_of(4)`). Difficulty 1
        // Mining is fast — we don't need the chain to be long.
        let mut chain: Vec<Block> = Vec::new();
        let mut genesis = Block::new(0, "0".repeat(64), vec![]);
        genesis.hash = genesis.calculate_hash();
        chain.push(genesis);
        for i in 1..=4u64 {
            let prev_hash = chain[(i - 1) as usize].hash.clone();
            let mut b = Block::new(i, prev_hash, vec![]);
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
        // Path. The post-adjustment difficulty must stay within the
        // [1, 32] clamp. The chain here is the *post-commit* chain
        // (boundary is the last block in the chain).
        engine.record_block_with_chain(boundary, &chain);
        let diff_after_record = engine.get_difficulty();
        assert!(
            (1..=32).contains(&diff_after_record),
            "adjusted difficulty must be within [1, 32] clamp, got {}",
            diff_after_record
        );
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
}
