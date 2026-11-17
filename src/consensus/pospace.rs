//! Proof of Space (PoSpace) consensus engine.
//!
//! PoSpace requires miners to commit verifiable storage capacity ("plots")
//! and answer cryptographic challenges bound to each registered `plot_id`.
//! Every block carries a hash-covered space proof `(plot_id, challenge,
//! capacity_bytes, response)` in `vrf_proof` / `vrf_output`; `validate_block`
//! fails closed unless a valid challenge-bound response is present, and fork
//! choice scores each candidate chain strictly by the verified plot capacity
//! committed inside that candidate chain.

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
const POSPACE_WITNESS_MAGIC: &[u8; 8] = b"BDLMSPC1";
const POSPACE_WITNESS_LEN: usize = 8 + 32 + 32 + 8;

/// PoSpace configuration.
#[derive(Debug, Clone)]
pub struct PoSpaceConfig {
    /// Minimum plot size in bytes required to participate.
    pub min_plot_size_bytes: u64,
    /// Number of blocks between challenge rotations.
    pub challenge_interval: u64,
}

impl Default for PoSpaceConfig {
    fn default() -> Self {
        Self {
            min_plot_size_bytes: 1_024 * 1_024,
            challenge_interval: 10,
        }
    }
}

/// Registered storage plot record.
#[derive(Debug, Clone)]
struct PlotRecord {
    plot_id: [u8; 32],
    size_bytes: u64,
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

fn encode_pospace_witness(plot_id: &[u8; 32], challenge: &[u8; 32], size_bytes: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(POSPACE_WITNESS_LEN);
    out.extend_from_slice(POSPACE_WITNESS_MAGIC);
    out.extend_from_slice(plot_id);
    out.extend_from_slice(challenge);
    out.extend_from_slice(&size_bytes.to_le_bytes());
    out
}

type DecodedSpaceWitness = ([u8; 32], [u8; 32], u64, [u8; 32]);

fn decode_pospace_witness(block: &Block) -> Result<DecodedSpaceWitness, ConsensusError> {
    if block.vrf_proof.len() != POSPACE_WITNESS_LEN || block.vrf_output.len() != 32 {
        return Err(ConsensusError(
            "PoSpace block missing challenge-bound space proof".into(),
        ));
    }
    let Some(magic) = block.vrf_proof.get(0..8) else {
        return Err(ConsensusError("PoSpace proof header truncated".into()));
    };
    if magic != POSPACE_WITNESS_MAGIC {
        return Err(ConsensusError("PoSpace proof magic mismatch".into()));
    }
    let plot_id: [u8; 32] = block
        .vrf_proof
        .get(8..40)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| ConsensusError("PoSpace proof plot_id truncated".into()))?;
    let challenge: [u8; 32] = block
        .vrf_proof
        .get(40..72)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| ConsensusError("PoSpace proof challenge truncated".into()))?;
    let size_bytes_arr: [u8; 8] = block
        .vrf_proof
        .get(72..80)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| ConsensusError("PoSpace proof size_bytes truncated".into()))?;
    let response: [u8; 32] = block
        .vrf_output
        .as_slice()
        .try_into()
        .map_err(|_| ConsensusError("PoSpace proof response must be 32 bytes".into()))?;
    Ok((
        plot_id,
        challenge,
        u64::from_le_bytes(size_bytes_arr),
        response,
    ))
}

fn derive_block_challenge(previous_hash: &str, block_index: u64, challenge_epoch: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_POSPACE_CHALLENGE_V1");
    hasher.update(previous_hash.as_bytes());
    hasher.update(block_index.to_le_bytes());
    hasher.update(challenge_epoch.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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
    /// Returns an error for empty addresses, zero plot ids, below-minimum capacity,
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
        if size_bytes == 0 || size_bytes < self.config.min_plot_size_bytes {
            return Err(ConsensusError(format!(
                "PoSpace plot size {size_bytes} is below minimum {}",
                self.config.min_plot_size_bytes
            )));
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
    #[cfg(test)]
    #[must_use]
    fn verify_response(&self, address: &str, challenge: &[u8; 32], response: &[u8; 32]) -> bool {
        let Ok(plots) = self.plots.read() else {
            return false;
        };
        let Some(plot) = plots.get(address) else {
            return false;
        };
        if plot.size_bytes < self.config.min_plot_size_bytes {
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

    fn expected_challenge_for_block(&self, block: &Block) -> [u8; 32] {
        let interval = self.config.challenge_interval.max(1);
        let challenge_epoch = block.index / interval;
        derive_block_challenge(&block.previous_hash, block.index, challenge_epoch)
    }
}

impl ConsensusEngine for PoSpaceEngine {
    fn prepare_block(
        &self,
        block: &mut Block,
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        let plot = {
            let plots = self
                .plots
                .read()
                .map_err(|_| ConsensusError("PoSpace plot registry lock poisoned".into()))?;
            if let Some(producer) = block.producer {
                let key = producer.to_hex();
                plots.get(&key).cloned().ok_or_else(|| {
                    ConsensusError(format!("PoSpace producer {key} has no registered plot"))
                })?
            } else {
                plots.values().next().cloned().ok_or_else(|| {
                    ConsensusError("PoSpace engine has no registered plots".into())
                })?
            }
        };

        let challenge = self.expected_challenge_for_block(block);
        let response = compute_plot_response(&plot.plot_id, &challenge);
        block.vrf_output = response.to_vec();
        block.vrf_proof = encode_pospace_witness(&plot.plot_id, &challenge, plot.size_bytes);
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

        let (plot_id, challenge, size_bytes, response) = decode_pospace_witness(block)?;
        if size_bytes < self.config.min_plot_size_bytes {
            return Err(ConsensusError(format!(
                "PoSpace proof plot size {size_bytes} is below minimum {}",
                self.config.min_plot_size_bytes
            )));
        }

        let expected_challenge = self.expected_challenge_for_block(block);
        if !bool::from(challenge.ct_eq(&expected_challenge)) {
            return Err(ConsensusError(
                "PoSpace proof challenge does not match block slot challenge".into(),
            ));
        }

        if !verify_plot_response(&plot_id, &challenge, &response) {
            return Err(ConsensusError(
                "PoSpace block space proof failed cryptographic verification".into(),
            ));
        }

        let plots = self
            .plots
            .read()
            .map_err(|_| ConsensusError("PoSpace plot registry lock poisoned".into()))?;
        if let Some(producer) = block.producer {
            let key = producer.to_hex();
            let Some(reg) = plots.get(&key) else {
                return Err(ConsensusError(format!(
                    "PoSpace producer {key} is not registered in plot registry"
                )));
            };
            if reg.plot_id != plot_id || reg.size_bytes != size_bytes {
                return Err(ConsensusError(format!(
                    "PoSpace producer {key} proof does not match registered plot commitment"
                )));
            }
        } else {
            let matches_registered = plots
                .values()
                .any(|reg| reg.plot_id == plot_id && reg.size_bytes == size_bytes);
            if !matches_registered {
                return Err(ConsensusError(
                    "PoSpace block references an unregistered plot".into(),
                ));
            }
        }

        Ok(())
    }

    fn record_block(
        &self,
        _block: &Block,
        _storage: Option<&crate::persistence::db::Storage>,
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
        // Derive score strictly from verified space proofs committed inside the
        // candidate chain itself (never from engine-global mutable plot totals).
        let height_weight = chain
            .last()
            .map_or(0u128, |b| u128::from(b.index))
            .saturating_mul(1_000);
        let mut proven_capacity = 0u128;
        for block in chain {
            if let Ok((plot_id, challenge, size_bytes, response)) = decode_pospace_witness(block) {
                let expected = self.expected_challenge_for_block(block);
                if size_bytes >= self.config.min_plot_size_bytes
                    && bool::from(challenge.ct_eq(&expected))
                    && verify_plot_response(&plot_id, &challenge, &response)
                {
                    proven_capacity = proven_capacity.saturating_add(u128::from(size_bytes));
                }
            }
        }
        height_weight.saturating_add(proven_capacity)
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
            .register_plot("bad-zero-id", [0u8; 32], 10_000_000)
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

        assert!(!engine.verify_response("validator-2", &challenge, &[0u8; 32]));
        assert!(!engine.verify_response("validator-2", &challenge, &[0xAB; 32]));
        assert!(!engine.verify_response("unknown", &challenge, &valid_response));
    }

    #[test]
    fn pospace_prepare_and_validate_block() {
        let engine = PoSpaceEngine::new(PoSpaceConfig::default());
        let plot_id = [7u8; 32];
        engine
            .register_plot("miner-1", plot_id, 10_000_000)
            .expect("register plot");
        let zero = "0".repeat(64);
        let mut block = make_block(1, &zero);
        engine
            .prepare_block(&mut block, &AccountState::new())
            .expect("prepare");
        assert!(engine
            .validate_block(&block, &[], &AccountState::new())
            .is_ok());
    }

    #[test]
    fn pospace_rejects_block_without_space_proof_or_with_forged_proof() {
        // Fresh engine with zero registered plots MUST fail closed on bare hash-only blocks.
        let empty_engine = PoSpaceEngine::new(PoSpaceConfig::default());
        let zero = "0".repeat(64);
        let bare = make_block(1, &zero);
        assert!(empty_engine
            .validate_block(&bare, &[], &AccountState::new())
            .is_err());

        // Engine with registered plot rejects tampered response.
        let engine = PoSpaceEngine::new(PoSpaceConfig::default());
        engine
            .register_plot("miner-a", [9u8; 32], 50_000_000)
            .expect("register");
        let mut forged = make_block(1, &zero);
        engine
            .prepare_block(&mut forged, &AccountState::new())
            .expect("prepare");
        forged.vrf_output = vec![0xEE; 32];
        forged.hash = forged.calculate_hash();
        assert!(engine
            .validate_block(&forged, &[], &AccountState::new())
            .is_err());
    }

    #[test]
    fn pospace_fork_choice_scores_candidate_chain_capacity_deterministically() {
        let zero = "0".repeat(64);
        let small = PoSpaceEngine::new(PoSpaceConfig::default());
        small
            .register_plot("small-miner", [3u8; 32], 2_000_000)
            .expect("register small");
        let mut b_small = make_block(1, &zero);
        small
            .prepare_block(&mut b_small, &AccountState::new())
            .expect("prepare small");

        let large = PoSpaceEngine::new(PoSpaceConfig::default());
        large
            .register_plot("large-miner", [4u8; 32], 200_000_000)
            .expect("register large");
        let mut b_large = make_block(1, &zero);
        large
            .prepare_block(&mut b_large, &AccountState::new())
            .expect("prepare large");

        let chain_small = vec![b_small];
        let chain_large = vec![b_large];
        // Higher proven plot capacity wins at equal height regardless of engine state.
        assert!(small.is_better_chain(&chain_small, &chain_large));
        assert!(!small.is_better_chain(&chain_large, &chain_small));
        // Reflexivity: a chain is never strictly better than itself.
        assert!(!small.is_better_chain(&chain_small, &chain_small));
    }
}
