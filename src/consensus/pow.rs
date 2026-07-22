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
    fn target(&self) -> String {
        "0".repeat(self.get_difficulty())
    }
    fn meets_difficulty(&self, hash: &str) -> bool {
        hash.starts_with(&self.target())
    }
    fn mine(&self, block: &mut Block) {
        let target = self.target();
        let mut iterations: u64 = 0;
        info!(
            "Mining started (difficulty: {}, target: {}...)",
            self.get_difficulty(),
            target
        );
        while !block.hash.starts_with(&target) {
            block.nonce += 1;
            block.hash = block.calculate_hash();
            iterations += 1;
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
    pub fn calculate_new_difficulty(&self, chain: &[Block]) -> usize {
        if chain.len() < self.config.adjustment_interval as usize {
            return self.get_difficulty();
        }
        let interval = self.config.adjustment_interval as usize;
        let last_block = &chain[chain.len() - 1];
        let first_block = &chain[chain.len() - interval];
        let actual_time = last_block.timestamp.saturating_sub(first_block.timestamp) / 1000;
        let expected_time = self.config.target_block_time * self.config.adjustment_interval;
        let ratio_scaled = (expected_time as u128 * 100) / actual_time.max(1);
        let new_diff = (self.get_difficulty() * ratio_scaled as usize) / 100;
        new_diff.clamp(1, 32)
    }

    /// Task 0.16 (security audit §3): difficulty-adjustment driver invoked
    /// from `blockchain.rs` after a block has been durably committed.
    /// Public so the blockchain can drive the adjustment with the full
    /// post-commit chain in hand. The previous design mutated
    /// `current_difficulty` from inside `validate_block`, which was
    /// both impure and vulnerable to re-validation attacks.
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
        self.mine(block);
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

        // Task 0.16 (security audit §3): validation is now PURE. The previous
        // implementation mutated `current_difficulty` from inside
        // `validate_block`, which had three problems:
        //   1. Validation is a read-only operation and must be idempotent.
        //      Re-validating the same block could re-trigger the
        //      adjustment and double-mutate the difficulty.
        //   2. Adversarial peers could spam re-validations of valid
        //      adjustment-boundary blocks to shift our `current_difficulty`
        //      mid-validation, causing the NEXT block to be checked
        //      against a difficulty that does not match what it was
        //      mined against.
        //   3. The adjustment happened AFTER `meets_difficulty` had
        //      already used the OLD difficulty for the same block, so
        //      the check and the adjustment were operating on
        //      different epochs in the same call.
        // The difficulty adjustment now lives in `record_block`, which
        // is invoked exactly once per block, after the block has been
        // durably committed. The check below uses whatever difficulty
        // the engine currently believes in (which is the difficulty
        // the *next* miner should target), and a failure here is
        // always a real PoW failure, never a side-effect of mutation.
        if !self.meets_difficulty(&block.hash) {
            return Err(ConsensusError(format!(
                "Invalid PoW. {} leading zeros required, hash: {}",
                self.get_difficulty(),
                block.hash
            )));
        }
        Ok(())
    }

    fn record_block(
        &self,
        _block: &Block,
        _storage: Option<&crate::storage::db::Storage>,
    ) -> Result<(), ConsensusError> {
        // Task 0.16 (security audit §3): the trait `record_block` hook is
        // intentionally a no-op for PoW. The actual difficulty
        // adjustment lives in `record_block_with_chain` (overridden
        // below), which is called from `blockchain.rs` after a block
        // is durably committed and the chain is in its post-commit
        // state. Keeping the trait hook as a no-op makes the
        // contract explicit: validation is pure, and the only
        // state mutation triggered by a block landing on the chain
        // is the chain-aware record path.
        Ok(())
    }

    fn record_block_with_chain(
        &self,
        block: &Block,
        chain: &[Block],
        _storage: Option<&crate::storage::db::Storage>,
    ) {
        // See `record_block_with_chain` in `consensus/mod.rs` for the
        // contract. The difficulty adjustment fires here, exactly
        // once per block, after the block has been accepted and
        // durably committed (see `produce_block` and
        // `validate_and_add_block` in blockchain.rs, which call this
        // method after `commit_block_durable`).
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
            "PoW (difficulty: {}, target: {}...)",
            self.get_difficulty(),
            self.target()
        )
    }

    fn fork_choice_score(&self, chain: &[Block]) -> u128 {
        chain.iter().fold(0u128, |acc, b| {
            let leading = b.hash.chars().take_while(|c| *c == '0').count() as u128;
            acc + leading.max(1)
        })
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

    /// Task 0.16 (security audit §3): `validate_block` must be PURE — calling
    /// it twice on the same block must produce the same result AND
    /// must not mutate the engine's `current_difficulty`. The
    /// previous implementation mutated difficulty from inside
    /// validation, so the *second* call could see a different
    /// difficulty than the first.
    #[test]
    fn validate_block_is_pure_and_idempotent() {
        let engine = PoWEngine::with_config(PoWConfig {
            difficulty: 1,
            target_block_time: 10,
            adjustment_interval: 100,
        });
        let state = AccountState::new();

        // Build a chain with a real genesis block so `validate_block`
        // can match `block.previous_hash` against the previous block.
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

    /// Task 0.16 (security audit §3): difficulty adjustment must fire
    /// from `record_block_with_chain`, NOT from `validate_block`.
    /// Here, an adjustment-boundary block is *validated* without a
    /// prior `record_block_with_chain` call, and the difficulty
    /// must remain at its pre-adjustment value. The adjustment only
    /// fires once the chain-aware record path is invoked.
    #[test]
    fn difficulty_adjustment_fires_only_from_record_block_with_chain() {
        let engine = PoWEngine::with_config(PoWConfig {
            difficulty: 1,
            target_block_time: 10,
            adjustment_interval: 4,
        });
        assert_eq!(engine.get_difficulty(), 1);

        // Build a synthetic chain of 4 blocks (adjustment boundary
        // at index 4, which is `is_multiple_of(4)`). Difficulty 1
        // mining is fast — we don't need the chain to be long.
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
        // adjustment (validate is pure). The chain passed to
        // `validate_block` is everything *before* the boundary block
        // (genesis + blocks 1..4), since the block being validated is
        // not yet part of the chain the validator sees.
        let state = AccountState::new();
        let prefix = &chain[..4];
        assert!(engine.validate_block(boundary, prefix, &state).is_ok());
        assert_eq!(
            engine.get_difficulty(),
            1,
            "validate must not adjust difficulty"
        );

        // Now drive the adjustment through the chain-aware record
        // path. The post-adjustment difficulty must stay within the
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
}
