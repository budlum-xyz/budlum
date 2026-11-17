//! Proof of History (PoH) consensus engine.
//!
//! PoH orders events via a sequential domain-separated SHA-256 hash chain.
//! Each tick hashes `BDLM_POH_TICK_V1 || prev_hash || step_index`. Verification
//! replays forward from the nearest bounded checkpoint up to a hard step cap
//! (`MAX_POH_VERIFY_STEPS`) to prevent CPU exhaustion.

use crate::consensus::split_resolver::{resolve_split_tie, SplitCandidate, SplitDecision};
use crate::consensus::{ConsensusEngine, ConsensusError};
use crate::core::account::AccountState;
use crate::core::block::Block;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::RwLock;

/// Maximum hash iterations allowed in a single PoH verification call.
const MAX_POH_VERIFY_STEPS: u64 = 16_384;
const MAX_POH_CHECKPOINTS: usize = 4_096;

/// PoH configuration.
#[derive(Debug, Clone)]
pub struct PohConfig {
    /// Number of hash iterations per slot.
    pub hashes_per_slot: u64,
    /// Initial deterministic seed for step 0.
    pub seed: [u8; 32],
}

impl Default for PohConfig {
    fn default() -> Self {
        Self {
            hashes_per_slot: 4,
            seed: [0x42u8; 32],
        }
    }
}

/// PoH chain state: current digest and total step count.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PohState {
    current_hash: [u8; 32],
    hash_count: u64,
}

struct PohLedger {
    state: PohState,
    checkpoints: BTreeMap<u64, [u8; 32]>,
}

/// Compute one domain-separated PoH hash transition.
#[must_use]
fn poh_step(prev_hash: &[u8; 32], step_index: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_POH_TICK_V1");
    hasher.update(prev_hash);
    hasher.update(step_index.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Verify a bounded forward PoH hash sequence from `start_hash` at `start_count`.
#[must_use]
pub fn verify_poh_sequence(
    start_hash: &[u8; 32],
    start_count: u64,
    steps: u64,
    expected_end_hash: &[u8; 32],
) -> bool {
    if steps > MAX_POH_VERIFY_STEPS || start_count.checked_add(steps).is_none() {
        return false;
    }
    let mut current = *start_hash;
    for offset in 0..steps {
        current = poh_step(&current, start_count + offset);
    }
    current == *expected_end_hash
}

/// PoH engine: sequential hash chain with bounded checkpoint verification.
pub struct PohEngine {
    pub config: PohConfig,
    ledger: RwLock<PohLedger>,
}

impl PohEngine {
    /// Create a new PoH consensus engine seeded at step 0.
    #[must_use]
    pub fn new(config: PohConfig) -> Self {
        let seed = config.seed;
        let mut checkpoints = BTreeMap::new();
        checkpoints.insert(0, seed);
        Self {
            config,
            ledger: RwLock::new(PohLedger {
                state: PohState {
                    current_hash: seed,
                    hash_count: 0,
                },
                checkpoints,
            }),
        }
    }

    /// Advance the PoH clock by one tick.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal lock is poisoned or the counter overflows.
    pub fn tick(&self) -> Result<[u8; 32], ConsensusError> {
        let mut ledger = self
            .ledger
            .write()
            .map_err(|_| ConsensusError("PoH state lock poisoned".into()))?;
        let next_count = ledger
            .state
            .hash_count
            .checked_add(1)
            .ok_or_else(|| ConsensusError("PoH hash counter overflow".into()))?;
        let next_hash = poh_step(&ledger.state.current_hash, ledger.state.hash_count);
        ledger.state.current_hash = next_hash;
        ledger.state.hash_count = next_count;
        ledger.checkpoints.insert(next_count, next_hash);
        while ledger.checkpoints.len() > MAX_POH_CHECKPOINTS {
            // Keep genesis checkpoint 0 when possible; evict oldest non-zero checkpoint.
            let evict_key = ledger.checkpoints.keys().copied().find(|&k| k != 0);
            if let Some(key) = evict_key {
                ledger.checkpoints.remove(&key);
            } else {
                break;
            }
        }
        Ok(next_hash)
    }

    /// Verify that `hash` is the exact PoH digest at `expected_count`.
    #[must_use]
    pub fn verify_hash(&self, hash: &[u8; 32], expected_count: u64) -> bool {
        let Ok(ledger) = self.ledger.read() else {
            return false;
        };
        if expected_count > ledger.state.hash_count {
            return false;
        }
        if let Some(cached) = ledger.checkpoints.get(&expected_count) {
            return cached == hash;
        }
        let Some((&anchor_count, &anchor_hash)) =
            ledger.checkpoints.range(..=expected_count).next_back()
        else {
            return false;
        };
        let steps = expected_count.saturating_sub(anchor_count);
        verify_poh_sequence(&anchor_hash, anchor_count, steps, hash)
    }

    #[cfg(test)]
    fn state(&self) -> PohState {
        self.ledger
            .read()
            .map(|l| l.state.clone())
            .unwrap_or(PohState {
                current_hash: [0u8; 32],
                hash_count: 0,
            })
    }

    fn current_hash_count(&self) -> u64 {
        self.ledger.read().map_or(0, |l| l.state.hash_count)
    }
}

impl ConsensusEngine for PohEngine {
    fn prepare_block(
        &self,
        block: &mut Block,
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        let _poh_hash = self.tick()?;
        block.hash = block.calculate_hash();
        Ok(())
    }

    fn validate_block(
        &self,
        block: &Block,
        chain: &[Block],
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        let calculated_hash = block.calculate_hash();
        if block.hash != calculated_hash {
            return Err(ConsensusError(format!(
                "Invalid PoH block hash. Calculated: {calculated_hash}, Existing: {}",
                block.hash
            )));
        }

        // Enforce monotonic timestamps along the PoH-ordered chain.
        if let Some(parent) = chain.last() {
            if block.timestamp < parent.timestamp {
                return Err(ConsensusError(format!(
                    "PoH block timestamp {} regresses below parent timestamp {}",
                    block.timestamp, parent.timestamp
                )));
            }
        }

        // Verify the engine's current head remains self-consistent against its checkpoints.
        let (head_hash, head_count) = {
            let ledger = self
                .ledger
                .read()
                .map_err(|_| ConsensusError("PoH state lock poisoned".into()))?;
            (ledger.state.current_hash, ledger.state.hash_count)
        };
        if !self.verify_hash(&head_hash, head_count) {
            return Err(ConsensusError("PoH head hash verification failed".into()));
        }

        Ok(())
    }

    fn record_block(
        &self,
        _block: &Block,
        _storage: Option<&crate::storage::db::Storage>,
    ) -> Result<(), ConsensusError> {
        let _ = self.tick()?;
        Ok(())
    }

    fn consensus_type(&self) -> &'static str {
        "PoH"
    }

    fn info(&self) -> String {
        format!(
            "PoH (hash_count: {}, hashes_per_slot: {})",
            self.current_hash_count(),
            self.config.hashes_per_slot
        )
    }

    fn domain_kind(&self) -> crate::domain::ConsensusKind {
        crate::domain::ConsensusKind::Poh
    }

    fn shorter_chain_can_never_win(&self) -> bool {
        false
    }

    fn fork_choice_score(&self, chain: &[Block]) -> u128 {
        chain.last().map_or(0, |b| u128::from(b.index))
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
    fn poh_tick_advances_chain() {
        let engine = PohEngine::new(PohConfig::default());
        let h1 = engine.tick().expect("tick 1");
        let h2 = engine.tick().expect("tick 2");
        assert_ne!(h1, h2);
        assert_eq!(engine.state().hash_count, 2);
    }

    #[test]
    fn poh_verify_hash_accepts_historical_and_rejects_forged_or_unbounded() {
        let engine = PohEngine::new(PohConfig::default());
        let h1 = engine.tick().expect("tick 1");
        let h2 = engine.tick().expect("tick 2");
        assert!(engine.verify_hash(&h1, 1));
        assert!(engine.verify_hash(&h2, 2));
        assert!(!engine.verify_hash(&[0xFF; 32], 2));
        assert!(!engine.verify_hash(&h2, 3));
        assert!(!verify_poh_sequence(&h1, 1, MAX_POH_VERIFY_STEPS + 1, &h2));
    }

    #[test]
    fn poh_prepare_and_validate_block_enforces_monotonic_timestamps() {
        let engine = PohEngine::new(PohConfig::default());
        let zero = "0".repeat(64);
        let mut b1 = make_block(1, &zero);
        engine
            .prepare_block(&mut b1, &AccountState::new())
            .expect("prepare b1");
        assert!(engine
            .validate_block(&b1, &[], &AccountState::new())
            .is_ok());

        let mut b2 = make_block(2, &b1.hash);
        b2.timestamp = b1.timestamp.saturating_sub(1);
        b2.hash = b2.calculate_hash();
        assert!(engine
            .validate_block(&b2, &[b1], &AccountState::new())
            .is_err());
    }
}
