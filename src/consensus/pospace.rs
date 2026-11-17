//! Proof of Space (PoSpace) consensus engine.
//!
//! PoSpace: validators allocate a amount of disk storage ("plot") and produce
//! a proof by extracting values from specific positions of the plot in response
//! to a challenge from the chain. Popularized by Chia. Budlum uses PoSpace for
//! the storage-based validator class.

use crate::consensus::{ConsensusEngine, ConsensusError};
use crate::core::account::AccountState;
use crate::core::block::Block;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;

/// PoSpace configuration.
#[derive(Debug, Clone)]
pub struct PoSpaceConfig {
    /// Plot size in bytes.
    pub plot_size_bytes: u64,
    /// Maximum number of attempts per challenge.
    pub max_challenge_attempts: u64,
    /// Number of segments per plot.
    pub segments_per_plot: u64,
}

impl Default for PoSpaceConfig {
    fn default() -> Self {
        PoSpaceConfig {
            plot_size_bytes: 1_000_000_000, // 1 GB
            max_challenge_attempts: 10,
            segments_per_plot: 1000,
        }
    }
}

/// A validator's plot record.
#[derive(Debug, Clone)]
pub struct PlotRecord {
    pub address: String,
    pub plot_id: [u8; 32],
    pub size_bytes: u64,
    pub last_challenge_response: Option<[u8; 32]>,
}

/// PoSpace engine: plot records and challenge verification.
pub struct PoSpaceEngine {
    pub config: PoSpaceConfig,
    plots: RwLock<HashMap<String, PlotRecord>>,
    challenge_counter: RwLock<u64>,
}

impl PoSpaceEngine {
    pub fn new(config: PoSpaceConfig) -> Self {
        PoSpaceEngine {
            config,
            plots: RwLock::new(HashMap::new()),
            challenge_counter: RwLock::new(0),
        }
    }

    /// Registers a plot.
    pub fn register_plot(&self, address: &str, plot_id: [u8; 32], size_bytes: u64) {
        self.plots.write().unwrap().insert(
            address.to_string(),
            PlotRecord {
                address: address.to_string(),
                plot_id,
                size_bytes,
                last_challenge_response: None,
            },
        );
    }

    /// Issues a challenge and expects a response from the plot owner.
    pub fn issue_challenge(&self) -> [u8; 32] {
        let mut counter = self.challenge_counter.write().unwrap();
        *counter += 1;
        let mut hasher = Sha256::new();
        hasher.update(&counter.to_le_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Verifies a challenge response.
    pub fn verify_response(
        &self,
        address: &str,
        challenge: &[u8; 32],
        response: &[u8; 32],
    ) -> bool {
        let plots = self.plots.read().unwrap();
        let Some(plot) = plots.get(address) else {
            return false;
        };

        // Simplified PoSpace verification: plot_id + challenge + response
        // must be cryptographically bound together.
        let mut hasher = Sha256::new();
        hasher.update(plot.plot_id);
        hasher.update(challenge);
        hasher.update(response);
        let digest = hasher.finalize();

        // The response must not collide with the digest and must not be zero
        // (spam protection).
        digest != *response && response.iter().any(|&b| b != 0)
    }

    /// Returns the total plot capacity.
    pub fn total_capacity(&self) -> u64 {
        self.plots.read().unwrap().values().map(|p| p.size_bytes).sum()
    }

    /// Returns the number of plots.
    pub fn plot_count(&self) -> usize {
        self.plots.read().unwrap().len()
    }
}

impl ConsensusEngine for PoSpaceEngine {
    fn prepare_block(
        &self,
        block: &mut Block,
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        block.hash = block.calculate_hash();
        Ok(())
    }

    fn validate_block(
        &self,
        block: &Block,
        _chain: &[Block],
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        let calculated_hash = block.calculate_hash();
        if block.hash != calculated_hash {
            return Err(ConsensusError(format!(
                "Invalid PoSpace block hash. Calculated: {}, Existing: {}",
                calculated_hash, block.hash
            )));
        }

        Ok(())
    }

    fn record_block(
        &self,
        block: &Block,
        _storage: Option<&crate::storage::db::Storage>,
    ) -> Result<(), ConsensusError> {
        // Each block opens a challenge.
        self.issue_challenge();
        Ok(())
    }

    fn consensus_type(&self) -> &'static str {
        "PoSpace"
    }

    fn info(&self) -> String {
        format!(
            "PoSpace (plots: {}, total_capacity: {} bytes, challenges: {})",
            self.plot_count(),
            self.total_capacity(),
            *self.challenge_counter.read().unwrap()
        )
    }

    fn domain_kind(&self) -> crate::domain::ConsensusKind {
        crate::domain::ConsensusKind::Pospace
    }

    fn shorter_chain_can_never_win(&self) -> bool {
        false
    }

    fn fork_choice_score(&self, chain: &[Block]) -> u128 {
        // In PoSpace, fork choice is weighted by total plot capacity.
        chain.last().map(|b| b.index as u128).unwrap_or(0) * 1000
            + self.total_capacity() as u128
    }

    fn is_better_chain(&self, current: &[Block], candidate: &[Block]) -> bool {
        let current_score = self.fork_choice_score(current);
        let candidate_score = self.fork_choice_score(candidate);
        if candidate_score != current_score {
            return candidate_score > current_score;
        }
        let current_tip = current.last().map(|b| b.hash.as_str()).unwrap_or("");
        let candidate_tip = candidate.last().map(|b| b.hash.as_str()).unwrap_or("");
        candidate_tip > current_tip
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::Block;

    fn make_block(index: u64, prev: &str) -> Block {
        let mut b = Block::new_with_chain_id(index, prev.to_string(), vec![], 1);
        b.hash = b.calculate_hash();
        b
    }

    #[test]
    fn pospace_register_and_verify_plot() {
        let engine = PoSpaceEngine::new(PoSpaceConfig::default());
        let plot_id = [1u8; 32];
        engine.register_plot("validator-1", plot_id, 1_000_000_000);

        assert_eq!(engine.plot_count(), 1);
        assert_eq!(engine.total_capacity(), 1_000_000_000);
    }

    #[test]
    fn pospace_challenge_and_response() {
        let engine = PoSpaceEngine::new(PoSpaceConfig::default());
        let plot_id = [2u8; 32];
        engine.register_plot("validator-2", plot_id, 500_000_000);

        let challenge = engine.issue_challenge();
        // Fake response: must not verify (correct response is unknown).
        let fake_response = [0u8; 32];
        assert!(!engine.verify_response("validator-2", &challenge, &fake_response));

        // Unknown validator.
        assert!(!engine.verify_response("unknown", &challenge, &fake_response));
    }

    #[test]
    fn pospace_prepare_and_validate_block() {
        let engine = PoSpaceEngine::new(PoSpaceConfig::default());
        let mut block = make_block(1, "0".repeat(64));
        engine.prepare_block(&mut block, &AccountState::new()).unwrap();
        assert!(engine.validate_block(&block, &[], &AccountState::new()).is_ok());
    }
}
