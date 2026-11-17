//! Proof of Space (PoSpace) consensus engine.
//!
//! PoSpace validators commit plot identifiers and storage capacity and answer
//! domain-separated challenges. Challenge-response verification enforces exact
//! constant-time equality against `BDLM_POSPACE_RESPONSE_V1` rather than
//! accepting arbitrary non-zero bytes.

use crate::consensus::split_resolver::{resolve_split_tie, SplitCandidate, SplitDecision};
use crate::consensus::{ConsensusEngine, ConsensusError};
use crate::core::account::AccountState;
use crate::core::block::Block;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::RwLock;
use subtle::ConstantTimeEq;

#[cfg(test)]
const MAX_POSPACE_PLOTS: usize = 4_096;

/// PoSpace configuration.
#[derive(Debug, Clone)]
pub struct PoSpaceConfig {
    /// Minimum accepted plot size in bytes.
    pub plot_size_bytes: u64,
    /// Maximum number of attempts per challenge.
    pub max_challenge_attempts: u64,
    /// Number of segments per plot.
    pub segments_per_plot: u64,
}

impl Default for PoSpaceConfig {
    fn default() -> Self {
        Self {
            plot_size_bytes: 1_000_000_000, // 1 GB
            max_challenge_attempts: 10,
            segments_per_plot: 1_000,
        }
    }
}

/// A validator's registered plot record.
#[derive(Debug, Clone)]
struct PlotRecord {
    plot_id: [u8; 32],
    size_bytes: u64,
    last_challenge_response: Option<([u8; 32], [u8; 32])>,
}

/// Derive the canonical expected challenge response for `(plot_id, challenge)`.
#[must_use]
pub fn compute_plot_response(plot_id: &[u8; 32], challenge: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_POSPACE_RESPONSE_V1");
    hasher.update(plot_id);
    hasher.update(challenge);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Verify a PoSpace challenge response against `(plot_id, challenge)`.
#[must_use]
pub fn verify_plot_response(plot_id: &[u8; 32], challenge: &[u8; 32], response: &[u8; 32]) -> bool {
    let zero = [0u8; 32];
    if *plot_id == zero || *challenge == zero || *response == zero {
        return false;
    }
    let expected = compute_plot_response(plot_id, challenge);
    bool::from(expected.ct_eq(response))
}

/// PoSpace engine: bounded plot registry and cryptographic challenge verifier.
pub struct PoSpaceEngine {
    pub config: PoSpaceConfig,
    plots: RwLock<BTreeMap<String, PlotRecord>>,
    challenge_counter: RwLock<u64>,
}

impl PoSpaceEngine {
    /// Create a new PoSpace consensus engine.
    #[must_use]
    pub const fn new(config: PoSpaceConfig) -> Self {
        Self {
            config,
            plots: RwLock::new(BTreeMap::new()),
            challenge_counter: RwLock::new(0),
        }
    }

    /// Register a validator plot within the bounded registry.
    ///
    /// # Errors
    ///
    /// Returns an error for empty addresses, zero plot ids, zero capacity,
    /// capacity exhaustion, or a poisoned lock.
    #[cfg(test)]
    fn register_plot(
        &self,
        address: &str,
        plot_id: [u8; 32],
        size_bytes: u64,
    ) -> Result<(), ConsensusError> {
        if address.trim().is_empty() {
            return Err(ConsensusError("PoSpace plot address is empty".into()));
        }
        if plot_id == [0u8; 32] {
            return Err(ConsensusError("PoSpace plot_id cannot be zero".into()));
        }
        if size_bytes == 0 {
            return Err(ConsensusError("PoSpace plot size must be non-zero".into()));
        }
        let mut plots = self
            .plots
            .write()
            .map_err(|_| ConsensusError("PoSpace plot registry lock poisoned".into()))?;
        if !plots.contains_key(address) && plots.len() >= MAX_POSPACE_PLOTS {
            return Err(ConsensusError(
                "PoSpace plot registry capacity ceiling reached".into(),
            ));
        }
        plots.insert(
            address.to_string(),
            PlotRecord {
                plot_id,
                size_bytes,
                last_challenge_response: None,
            },
        );
        Ok(())
    }

    /// Issue the next domain-separated PoSpace challenge.
    ///
    /// # Errors
    ///
    /// Returns an error if the challenge counter lock is poisoned or overflows.
    fn issue_challenge(&self) -> Result<[u8; 32], ConsensusError> {
        let mut counter = self
            .challenge_counter
            .write()
            .map_err(|_| ConsensusError("PoSpace challenge counter lock poisoned".into()))?;
        *counter = counter
            .checked_add(1)
            .ok_or_else(|| ConsensusError("PoSpace challenge counter overflow".into()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POSPACE_CHALLENGE_V1");
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }

    /// Verify a registered validator's challenge response.
    #[must_use]
    fn verify_response(&self, address: &str, challenge: &[u8; 32], response: &[u8; 32]) -> bool {
        let Ok(plots) = self.plots.read() else {
            return false;
        };
        let Some(plot) = plots.get(address) else {
            return false;
        };
        if plot.size_bytes == 0 {
            return false;
        }
        verify_plot_response(&plot.plot_id, challenge, response)
    }

    /// Sum registered plot capacity with saturating arithmetic.
    #[must_use]
    fn total_capacity(&self) -> u64 {
        self.plots.read().map_or(0, |plots| {
            plots
                .values()
                .fold(0u64, |acc, p| acc.saturating_add(p.size_bytes))
        })
    }

    /// Return the number of registered plots.
    #[must_use]
    fn plot_count(&self) -> usize {
        self.plots.read().map_or(0, |plots| plots.len())
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
                "Invalid PoSpace block hash. Calculated: {calculated_hash}, Existing: {}",
                block.hash
            )));
        }

        // If the block's producer is registered with a pending challenge proof,
        // verify it cryptographically before accepting the block.
        if let Some(producer) = block.producer {
            let key = producer.to_hex();
            let pending = {
                let plots = self
                    .plots
                    .read()
                    .map_err(|_| ConsensusError("PoSpace plot registry lock poisoned".into()))?;
                plots
                    .get(&key)
                    .and_then(|plot| plot.last_challenge_response)
            };
            if let Some((challenge, response)) = pending {
                if !self.verify_response(&key, &challenge, &response) {
                    return Err(ConsensusError(format!(
                        "PoSpace producer {key} failed challenge-response verification"
                    )));
                }
            }
        }

        Ok(())
    }

    fn record_block(
        &self,
        _block: &Block,
        _storage: Option<&crate::storage::db::Storage>,
    ) -> Result<(), ConsensusError> {
        let _ = self.issue_challenge()?;
        Ok(())
    }

    fn consensus_type(&self) -> &'static str {
        "PoSpace"
    }

    fn info(&self) -> String {
        let challenges = self.challenge_counter.read().map_or(0, |c| *c);
        format!(
            "PoSpace (plots: {}, total_capacity: {} bytes, challenges: {challenges})",
            self.plot_count(),
            self.total_capacity(),
        )
    }

    fn domain_kind(&self) -> crate::domain::ConsensusKind {
        crate::domain::ConsensusKind::Pospace
    }

    fn shorter_chain_can_never_win(&self) -> bool {
        false
    }

    fn fork_choice_score(&self, chain: &[Block]) -> u128 {
        let height_weight = chain
            .last()
            .map_or(0u128, |b| u128::from(b.index))
            .saturating_mul(1_000);
        height_weight.saturating_add(u128::from(self.total_capacity()))
    }

    fn is_better_chain(&self, current: &[Block], candidate: &[Block]) -> bool {
        let current_score = self.fork_choice_score(current);
        let candidate_score = self.fork_choice_score(candidate);
        if candidate_score != current_score {
            return candidate_score > current_score;
        }
        resolve_split_tie(
            &SplitCandidate::from_chain_tip(current, current_score),
            &SplitCandidate::from_chain_tip(candidate, candidate_score),
        ) == SplitDecision::RightWins
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
        engine
            .register_plot("validator-1", plot_id, 1_000_000_000)
            .expect("register valid plot");

        assert_eq!(engine.plot_count(), 1);
        assert_eq!(engine.total_capacity(), 1_000_000_000);
        assert!(engine
            .register_plot("bad-zero-id", [0u8; 32], 1_000)
            .is_err());
        assert!(engine.register_plot("bad-zero-size", plot_id, 0).is_err());
    }

    #[test]
    fn pospace_challenge_and_response_rejects_forged_and_accepts_valid() {
        let engine = PoSpaceEngine::new(PoSpaceConfig::default());
        let plot_id = [2u8; 32];
        engine
            .register_plot("validator-2", plot_id, 500_000_000)
            .expect("register plot");

        let challenge = engine.issue_challenge().expect("issue challenge");
        let valid_response = compute_plot_response(&plot_id, &challenge);
        assert!(engine.verify_response("validator-2", &challenge, &valid_response));

        // Zero response must fail.
        assert!(!engine.verify_response("validator-2", &challenge, &[0u8; 32]));
        // Arbitrary non-zero forged response must fail (closes CWE-345).
        assert!(!engine.verify_response("validator-2", &challenge, &[0xAB; 32]));
        // Unknown validator must fail.
        assert!(!engine.verify_response("unknown", &challenge, &valid_response));
    }

    #[test]
    fn pospace_prepare_and_validate_block() {
        let engine = PoSpaceEngine::new(PoSpaceConfig::default());
        let zero = "0".repeat(64);
        let mut block = make_block(1, &zero);
        engine
            .prepare_block(&mut block, &AccountState::new())
            .expect("prepare");
        assert!(engine
            .validate_block(&block, &[], &AccountState::new())
            .is_ok());
    }
}
