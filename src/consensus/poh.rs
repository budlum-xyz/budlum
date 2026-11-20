//! Proof of History (`PoH`) consensus engine.
//!
//! `PoH` orders events via a sequential domain-separated SHA-256 hash chain.
//! Each tick hashes `BDLM_POH_TICK_V1 || prev_hash || step_index`. Proposals
//! bind their `(start_count, steps, end_hash)` witness into the block's
//! hash-covered `vrf_proof` and `vrf_output` fields without mutating canonical
//! state; `validate_block` fails closed unless the witness verifies against a
//! canonical checkpoint, and `record_block` commits the verified transition
//! once (idempotently).

use crate::consensus::split_resolver::{resolve_split_tie, SplitCandidate, SplitDecision};
use crate::consensus::{ConsensusEngine, ConsensusError};
use crate::core::account::AccountState;
use crate::core::block::Block;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::RwLock;

/// Maximum hash iterations allowed in a single `PoH` verification call.
const MAX_POH_VERIFY_STEPS: u64 = 16_384;
const MAX_POH_CHECKPOINTS: usize = 4_096;
const POH_WITNESS_MAGIC: &[u8; 8] = b"BDLMPOH1";
const POH_WITNESS_LEN: usize = 8 + 8 + 8;

/// `PoH` configuration.
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

/// `PoH` chain state: current digest and total step count.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PohState {
    current_hash: [u8; 32],
    hash_count: u64,
}

struct PohLedger {
    state: PohState,
    checkpoints: BTreeMap<u64, [u8; 32]>,
}

/// Compute one domain-separated `PoH` hash transition.
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

fn encode_poh_witness(start_count: u64, steps: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(POH_WITNESS_LEN);
    out.extend_from_slice(POH_WITNESS_MAGIC);
    out.extend_from_slice(&start_count.to_le_bytes());
    out.extend_from_slice(&steps.to_le_bytes());
    out
}

fn decode_poh_witness(block: &Block) -> Result<(u64, u64, [u8; 32]), ConsensusError> {
    if block.vrf_proof.len() != POH_WITNESS_LEN || block.vrf_output.len() != 32 {
        return Err(ConsensusError(
            "PoH block missing commitment-bound PoH witness".into(),
        ));
    }
    let Some(magic) = block.vrf_proof.get(0..8) else {
        return Err(ConsensusError("PoH witness header truncated".into()));
    };
    if magic != POH_WITNESS_MAGIC {
        return Err(ConsensusError("PoH witness magic mismatch".into()));
    }
    let start_bytes: [u8; 8] = block
        .vrf_proof
        .get(8..16)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| ConsensusError("PoH witness start_count truncated".into()))?;
    let step_bytes: [u8; 8] = block
        .vrf_proof
        .get(16..24)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| ConsensusError("PoH witness steps truncated".into()))?;
    let end_hash: [u8; 32] = block
        .vrf_output
        .as_slice()
        .try_into()
        .map_err(|_| ConsensusError("PoH witness end_hash must be 32 bytes".into()))?;
    Ok((
        u64::from_le_bytes(start_bytes),
        u64::from_le_bytes(step_bytes),
        end_hash,
    ))
}

/// Verify a bounded forward `PoH` hash sequence from `start_hash` at `start_count`.
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

/// `PoH` engine: sequential hash chain with bounded checkpoint verification.
pub struct PohEngine {
    pub config: PohConfig,
    ledger: RwLock<PohLedger>,
}

impl PohEngine {
    /// Create a new `PoH` consensus engine seeded at step 0.
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

    fn checkpoint_at(ledger: &PohLedger, target_count: u64) -> Option<[u8; 32]> {
        if target_count > ledger.state.hash_count {
            return None;
        }
        if let Some(&cached) = ledger.checkpoints.get(&target_count) {
            return Some(cached);
        }
        let (&anchor_count, &anchor_hash) =
            ledger.checkpoints.range(..=target_count).next_back()?;
        let steps = target_count.saturating_sub(anchor_count);
        if steps > MAX_POH_VERIFY_STEPS {
            return None;
        }
        let mut current = anchor_hash;
        for offset in 0..steps {
            current = poh_step(&current, anchor_count + offset);
        }
        Some(current)
    }

    fn prune_checkpoints(checkpoints: &mut BTreeMap<u64, [u8; 32]>) {
        while checkpoints.len() > MAX_POH_CHECKPOINTS {
            // Keep genesis checkpoint 0 when possible; evict oldest non-zero checkpoint.
            let evict_key = checkpoints.keys().copied().find(|&k| k != 0);
            if let Some(key) = evict_key {
                checkpoints.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Advance the `PoH` clock by one tick.
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
        Self::prune_checkpoints(&mut ledger.checkpoints);
        Ok(next_hash)
    }

    /// Verify that `hash` is the exact `PoH` digest at `expected_count`.
    #[must_use]
    pub fn verify_hash(&self, hash: &[u8; 32], expected_count: u64) -> bool {
        let Ok(ledger) = self.ledger.read() else {
            return false;
        };
        Self::checkpoint_at(&ledger, expected_count).is_some_and(|expected| expected == *hash)
    }

    fn verify_block_witness_against_ledger(
        &self,
        ledger: &PohLedger,
        block: &Block,
    ) -> Result<(u64, u64, [u8; 32]), ConsensusError> {
        let (start_count, steps, end_hash) = decode_poh_witness(block)?;
        let required_steps = self.config.hashes_per_slot.max(1);
        if steps < required_steps || steps > MAX_POH_VERIFY_STEPS {
            return Err(ConsensusError(format!(
                "PoH witness step count {steps} outside permitted range [{required_steps}, {MAX_POH_VERIFY_STEPS}]"
            )));
        }
        let Some(anchor_hash) = Self::checkpoint_at(ledger, start_count) else {
            return Err(ConsensusError(format!(
                "PoH witness start_count {start_count} cannot be anchored in canonical history (head={})",
                ledger.state.hash_count
            )));
        };
        if !verify_poh_sequence(&anchor_hash, start_count, steps, &end_hash) {
            return Err(ConsensusError(
                "PoH block witness hash chain verification failed".into(),
            ));
        }
        Ok((start_count, steps, end_hash))
    }

    #[cfg(test)]
    fn state(&self) -> PohState {
        self.ledger.read().map_or(
            PohState {
                current_hash: [0u8; 32],
                hash_count: 0,
            },
            |l| l.state.clone(),
        )
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
        let steps = self.config.hashes_per_slot.max(1);
        if steps > MAX_POH_VERIFY_STEPS {
            return Err(ConsensusError(
                "PoH hashes_per_slot exceeds verification ceiling".into(),
            ));
        }
        // Snapshot canonical PoH head without mutating it; canonical state
        // advances once on commit in `record_block`.
        let (start_hash, start_count) = {
            let ledger = self
                .ledger
                .read()
                .map_err(|_| ConsensusError("PoH state lock poisoned".into()))?;
            (ledger.state.current_hash, ledger.state.hash_count)
        };
        start_count
            .checked_add(steps)
            .ok_or_else(|| ConsensusError("PoH hash counter overflow".into()))?;
        let mut end_hash = start_hash;
        for offset in 0..steps {
            end_hash = poh_step(&end_hash, start_count + offset);
        }
        block.vrf_output = end_hash.to_vec();
        block.vrf_proof = encode_poh_witness(start_count, steps);
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

        // Enforce strict contiguous block linkage and monotonic timestamps.
        if let Some(parent) = chain.last() {
            let expected_index = parent
                .index
                .checked_add(1)
                .ok_or_else(|| ConsensusError("PoH parent block index overflows u64".into()))?;
            if block.index != expected_index {
                return Err(ConsensusError(format!(
                    "PoH block index {} does not follow parent index {} (expected {expected_index})",
                    block.index, parent.index
                )));
            }
            if block.previous_hash != parent.hash {
                return Err(ConsensusError(format!(
                    "PoH block previous_hash {} does not match parent hash {}",
                    block.previous_hash, parent.hash
                )));
            }
            if block.timestamp < parent.timestamp {
                return Err(ConsensusError(format!(
                    "PoH block timestamp {} regresses below parent timestamp {}",
                    block.timestamp, parent.timestamp
                )));
            }
        }

        let ledger = self
            .ledger
            .read()
            .map_err(|_| ConsensusError("PoH state lock poisoned".into()))?;
        let (start_count, _steps, _end_hash) =
            self.verify_block_witness_against_ledger(&ledger, block)?;

        // Prevent replaying or skipping PoH steps on every child block:
        // - block 1 above genesis (`parent.index == 0`) must start at count 0;
        // - every subsequent block (`parent.index > 0`) must continue directly
        //   from the parent's exact `(end_count, end_hash)`.
        if let Some(parent) = chain.last() {
            if parent.index == 0 {
                if start_count != 0 {
                    return Err(ConsensusError(format!(
                        "PoH height-1 block start_count {start_count} must anchor at genesis count 0"
                    )));
                }
            } else {
                let (parent_start, parent_steps, parent_end_hash) = decode_poh_witness(parent)?;
                let expected_start = parent_start
                    .checked_add(parent_steps)
                    .ok_or_else(|| ConsensusError("Parent PoH hash counter overflow".into()))?;
                if start_count != expected_start {
                    return Err(ConsensusError(format!(
                        "PoH witness start_count {start_count} does not continue parent end_count {expected_start}"
                    )));
                }
                let Some(anchor_hash) = Self::checkpoint_at(&ledger, start_count) else {
                    return Err(ConsensusError(
                        "PoH witness anchor missing for parent continuation".into(),
                    ));
                };
                if anchor_hash != parent_end_hash {
                    return Err(ConsensusError(
                        "PoH witness anchor hash does not match parent end hash".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn record_block(
        &self,
        block: &Block,
        _storage: Option<&crate::persistence::db::Storage>,
    ) -> Result<(), ConsensusError> {
        let mut ledger = self
            .ledger
            .write()
            .map_err(|_| ConsensusError("PoH state lock poisoned".into()))?;
        let (start_count, steps, end_hash) =
            self.verify_block_witness_against_ledger(&ledger, block)?;
        let end_count = start_count
            .checked_add(steps)
            .ok_or_else(|| ConsensusError("PoH hash counter overflow".into()))?;

        // Idempotent commit: re-recording an already-committed PoH transition
        // verifies consistency and does not double-advance canonical state.
        if end_count <= ledger.state.hash_count {
            let Some(existing) = Self::checkpoint_at(&ledger, end_count) else {
                return Err(ConsensusError(
                    "PoH canonical history missing committed checkpoint".into(),
                ));
            };
            if existing != end_hash {
                return Err(ConsensusError(
                    "PoH witness conflicts with committed canonical checkpoint".into(),
                ));
            }
            return Ok(());
        }

        // Refuse partial-overlap forks (`start_count < head < end_count`) and
        // unanchored gaps (`start_count > head`) so canonical PoH checkpoints
        // can never be overwritten or rolled across a fork boundary.
        if start_count != ledger.state.hash_count {
            return Err(ConsensusError(format!(
                "PoH commit start_count {start_count} does not continue canonical head {} (end_count={end_count})",
                ledger.state.hash_count
            )));
        }

        let Some(anchor_hash) = Self::checkpoint_at(&ledger, start_count) else {
            return Err(ConsensusError(
                "PoH witness anchor unavailable during commit".into(),
            ));
        };
        let mut current = anchor_hash;
        for offset in 0..steps {
            current = poh_step(&current, start_count + offset);
            ledger.checkpoints.insert(start_count + offset + 1, current);
        }
        ledger.state.current_hash = end_hash;
        ledger.state.hash_count = end_count;
        Self::prune_checkpoints(&mut ledger.checkpoints);
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
        let Some(first) = chain.first() else {
            return 0;
        };
        let mut verified_tip = first;
        for blk in chain.iter().skip(1) {
            if Some(blk.index) != verified_tip.index.checked_add(1)
                || blk.previous_hash != verified_tip.hash
                || blk.timestamp < verified_tip.timestamp
            {
                break;
            }
            verified_tip = blk;
        }
        // Refuse single-block unanchored high-index inflation (must start at genesis 0).
        if first.index != 0 {
            return 0;
        }
        u128::from(verified_tip.index)
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
        engine
            .prepare_block(&mut b2, &AccountState::new())
            .expect("prepare b2");
        b2.timestamp = b1.timestamp.saturating_sub(1);
        b2.hash = b2.calculate_hash();
        assert!(engine
            .validate_block(&b2, &[b1], &AccountState::new())
            .is_err());
    }

    #[test]
    fn poh_rejects_block_without_witness_or_forged_witness() {
        let engine = PohEngine::new(PohConfig::default());
        let zero = "0".repeat(64);
        // Hash-only block without PoH witness must fail closed.
        let bare = make_block(1, &zero);
        assert!(engine
            .validate_block(&bare, &[], &AccountState::new())
            .is_err());

        // Block with forged PoH end hash must fail closed.
        let mut forged = make_block(1, &zero);
        engine
            .prepare_block(&mut forged, &AccountState::new())
            .expect("prepare");
        forged.vrf_output = vec![0xAA; 32];
        forged.hash = forged.calculate_hash();
        assert!(engine
            .validate_block(&forged, &[], &AccountState::new())
            .is_err());
    }

    #[test]
    fn poh_prepare_does_not_mutate_canonical_state_and_record_is_idempotent() {
        let producer = PohEngine::new(PohConfig::default());
        let verifier = PohEngine::new(PohConfig::default());
        let zero = "0".repeat(64);
        let mut b1 = make_block(1, &zero);

        // Preparing (or discarding) a proposal must not advance canonical state.
        producer
            .prepare_block(&mut b1, &AccountState::new())
            .expect("prepare b1");
        assert_eq!(producer.state().hash_count, 0);

        // Producer and independent verifier agree on exact canonical hash_count.
        assert!(verifier
            .validate_block(&b1, &[], &AccountState::new())
            .is_ok());
        producer.record_block(&b1, None).expect("producer record");
        verifier.record_block(&b1, None).expect("verifier record");
        assert_eq!(producer.state().hash_count, producer.config.hashes_per_slot);
        assert_eq!(producer.state(), verifier.state());

        // Re-recording the same block is idempotent and does not advance twice.
        producer
            .record_block(&b1, None)
            .expect("idempotent re-record");
        assert_eq!(producer.state().hash_count, producer.config.hashes_per_slot);
    }

    #[test]
    fn poh_rejects_replayed_historical_witness_on_child_block() {
        let engine = PohEngine::new(PohConfig::default());
        let zero = "0".repeat(64);
        let mut b1 = make_block(1, &zero);
        engine
            .prepare_block(&mut b1, &AccountState::new())
            .expect("prepare b1");
        engine
            .validate_block(&b1, &[], &AccountState::new())
            .expect("validate b1");
        engine.record_block(&b1, None).expect("record b1");

        // Replay b1's step-0 witness into b2 with valid timestamp and parent link: must be refused.
        let mut replayed = make_block(2, &b1.hash);
        replayed.timestamp = b1.timestamp.saturating_add(1);
        replayed.vrf_proof = b1.vrf_proof.clone();
        replayed.vrf_output = b1.vrf_output.clone();
        replayed.hash = replayed.calculate_hash();
        assert!(engine
            .validate_block(&replayed, std::slice::from_ref(&b1), &AccountState::new())
            .is_err());

        // Properly advancing from b1's end_count succeeds.
        let mut b2 = make_block(2, &b1.hash);
        b2.timestamp = b1.timestamp.saturating_add(1);
        engine
            .prepare_block(&mut b2, &AccountState::new())
            .expect("prepare b2");
        assert!(engine
            .validate_block(&b2, &[b1], &AccountState::new())
            .is_ok());
    }

    #[test]
    fn b0100_poh_enforces_parent_link_genesis_start_overlap_refusal_and_contiguous_score() {
        let config = PohConfig {
            hashes_per_slot: 8,
            ..PohConfig::default()
        };
        let engine = PohEngine::new(config);
        let zero = "0".repeat(64);
        let mut genesis = make_block(0, &zero);
        genesis.hash = genesis.calculate_hash();

        // 1. Height gap (index 2 on top of genesis 0) and wrong previous_hash are refused.
        let mut gapped = make_block(2, &genesis.hash);
        gapped.timestamp = genesis.timestamp;
        engine
            .prepare_block(&mut gapped, &AccountState::new())
            .unwrap();
        assert!(engine
            .validate_block(
                &gapped,
                std::slice::from_ref(&genesis),
                &AccountState::new()
            )
            .is_err());

        let mut bad_parent = make_block(1, &"f".repeat(64));
        bad_parent.timestamp = genesis.timestamp;
        engine
            .prepare_block(&mut bad_parent, &AccountState::new())
            .unwrap();
        assert!(engine
            .validate_block(
                &bad_parent,
                std::slice::from_ref(&genesis),
                &AccountState::new()
            )
            .is_err());

        // 2. Commit honest height-1 block (0 -> 8), then refuse height-1 block starting at 8.
        let mut b1 = make_block(1, &genesis.hash);
        b1.timestamp = genesis.timestamp + 1;
        engine.prepare_block(&mut b1, &AccountState::new()).unwrap();
        engine
            .validate_block(&b1, std::slice::from_ref(&genesis), &AccountState::new())
            .unwrap();
        engine.record_block(&b1, None).unwrap();
        assert_eq!(engine.state().hash_count, 8);

        let mut skipped_h1 = make_block(1, &genesis.hash);
        skipped_h1.timestamp = genesis.timestamp + 2;
        engine
            .prepare_block(&mut skipped_h1, &AccountState::new())
            .unwrap();
        assert!(engine
            .validate_block(
                &skipped_h1,
                std::slice::from_ref(&genesis),
                &AccountState::new()
            )
            .is_err());

        // 3. Partial-overlap fork (start_count=4 < head=8 < end_count=16) must not corrupt head.
        let anchor_4 = {
            let l = engine.ledger.read().unwrap();
            *l.checkpoints.get(&4).unwrap()
        };
        let mut h = anchor_4;
        for step in 0..12u64 {
            h = poh_step(&h, 4 + step);
        }
        let mut overlap = make_block(2, &b1.hash);
        overlap.timestamp = b1.timestamp + 1;
        overlap.vrf_output = h.to_vec();
        overlap.vrf_proof = encode_poh_witness(4, 12);
        overlap.hash = overlap.calculate_hash();
        let err = engine.record_block(&overlap, None).unwrap_err();
        assert!(err.0.contains("does not continue canonical head"));
        assert_eq!(engine.state().hash_count, 8);

        // 4. fork_choice_score rejects unanchored forged high-index chain.
        let mut forged = make_block(999_999, &zero);
        forged.hash = forged.calculate_hash();
        assert_eq!(engine.fork_choice_score(&[forged.clone()]), 0);
        assert_eq!(
            engine.fork_choice_score(&[genesis.clone(), b1.clone(), forged]),
            1
        );
    }
}
