use super::{
    ConsensusEngine, ConsensusError, MAX_LEADER_ROUNDS, MIN_BLOCK_INTERVAL_MS, ROUND_TIMEOUT_MS,
};
use crate::core::account::AccountState;
use crate::core::address::Address;

use crate::consensus::split_resolver::{resolve_split_tie, SplitCandidate, SplitDecision};
use crate::core::block::Block;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PoSConfig {
    pub min_stake: u64,
    pub epoch_length: u64,
}
impl Default for PoSConfig {
    /// Devnet-shaped defaults.
    ///
    /// C-12: `epoch_length` must always agree with
    /// `chain_config::epoch_len_for_chain_id`, because the chain layer derives
    /// Epoch boundaries from that function while this engine validates
    /// `block.epoch == block.index / self.config.epoch_length` (see
    /// `validate_block`). A default that matches no network at all is a silent
    /// Trap: any caller that forgets to override it validates blocks against a
    /// Schedule the chain never uses.
    ///
    /// The previous value was 32, which is not the epoch length of ANY network
    /// (mainnet 100, testnet 50, devnet 10). It is now pinned to the devnet
    /// Value and asserted against `chain_config` by
    /// `pos_default_epoch_length_matches_a_real_network`.
    ///
    /// Production paths (`main.rs`) already build the config explicitly from
    /// `network_params.epoch_len`; this only fixes the fallback.
    fn default() -> Self {
        PoSConfig {
            min_stake: 1000,
            // P01-F21: the reward/penalty/unbonding knobs were never read by
            // any code path and are gone; slashing ratios come from
            // `RegistryParams`, unbonding from `UNBONDING_EPOCHS`, rewards
            // from tokenomics. A knob nobody reads is a lie to operators.
            epoch_length: crate::core::chain_config::Network::Devnet
                .consensus_params()
                .epoch_len,
        }
    }
}

use serde::{Deserialize, Serialize};

use crate::core::block::BlockHeader;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SlashingEvidence {
    pub header1: BlockHeader,
    pub header2: BlockHeader,
    pub signature1: Vec<u8>,
    pub signature2: Vec<u8>,
}

impl SlashingEvidence {
    pub fn new(
        header1: BlockHeader,
        header2: BlockHeader,
        signature1: Vec<u8>,
        signature2: Vec<u8>,
    ) -> Self {
        SlashingEvidence {
            header1,
            header2,
            signature1,
            signature2,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub block_index: u64,
    pub block_hash: String,
    pub timestamp: u128,
}
use crate::crypto::primitives::ValidatorKeys;
use crate::crypto::signer::ConsensusSigner;

use std::sync::{Arc, RwLock};
use tracing::{info, warn};

/// Slashing evidence seen for `(producer, height)`: the header and its
/// signature. Named so `PoSEngine`'s fields stay readable without an
/// `allow(clippy::type_complexity)` (P01-F26).
type SeenBlocks = HashMap<(Address, u64), (BlockHeader, Vec<u8>)>;

pub struct PoSEngine {
    pub config: PoSConfig,
    seen_blocks: RwLock<SeenBlocks>,
    pub slashing_evidence: RwLock<Vec<SlashingEvidence>>,
    checkpoints: RwLock<Vec<Checkpoint>>,
    /// Epoch-boundary checkpoints awaiting a quorum certificate (P01-F04).
    ///
    /// A checkpoint written at local commit time is a race: each node at a
    /// boundary height commits whichever block it saw first and then refuses
    /// the other node's chain forever. The boundary block is parked here and
    /// only promoted by `note_finalized_height` once the chain reports the
    /// height as finalised.
    pending_checkpoints: RwLock<Vec<Checkpoint>>,
    validator_keys: Option<ValidatorKeys>,
    signer: Option<Arc<dyn ConsensusSigner>>,
    epoch_seed: RwLock<[u8; 32]>,
}
impl PoSEngine {
    /// `PoSConfig::epoch_length` is a public field and nothing rejects zero
    /// at construction; the division paths below must refuse it explicitly
    /// instead of panicking on the first block.
    fn epoch_length_checked(&self) -> Result<u64, ConsensusError> {
        if self.config.epoch_length == 0 {
            return Err(ConsensusError("PoS epoch length must be non-zero".into()));
        }
        Ok(self.config.epoch_length)
    }

    pub fn new(config: PoSConfig, validator_keys: Option<ValidatorKeys>) -> Self {
        PoSEngine {
            config,
            seen_blocks: RwLock::new(HashMap::new()),
            slashing_evidence: RwLock::new(Vec::new()),
            checkpoints: RwLock::new(Vec::new()),
            pending_checkpoints: RwLock::new(Vec::new()),
            validator_keys,
            signer: None,
            epoch_seed: RwLock::new([0u8; 32]),
        }
    }

    pub fn with_signer(
        config: PoSConfig,
        validator_keys: Option<ValidatorKeys>,
        signer: Arc<dyn ConsensusSigner>,
    ) -> Self {
        PoSEngine {
            config,
            seen_blocks: RwLock::new(HashMap::new()),
            slashing_evidence: RwLock::new(Vec::new()),
            checkpoints: RwLock::new(Vec::new()),
            pending_checkpoints: RwLock::new(Vec::new()),
            validator_keys,
            signer: Some(signer),
            epoch_seed: RwLock::new([0u8; 32]),
        }
    }

    pub fn verify_evidence(&self, evidence: &SlashingEvidence) -> bool {
        slashing_evidence_is_valid(evidence)
    }

    /// Prune old slashing evidence to prevent unbounded growth.
    /// Keeps only evidence with header1.index >= `min_height`.
    pub fn prune_slashing_evidence(&self, min_height: u64) -> Result<usize, ConsensusError> {
        let mut guard = self.slashing_evidence.write().map_err(|_| {
            ConsensusError("Failed to acquire write lock on slashing evidence".into())
        })?;
        let before = guard.len();
        guard.retain(|e| e.header1.index >= min_height);
        Ok(before - guard.len())
    }

    /// Test inspection of the committed checkpoint list (P01-F21: no
    /// production caller; the production surface is `last_checkpoint`).
    #[cfg(test)]
    pub fn get_checkpoints(&self) -> Result<Vec<Checkpoint>, ConsensusError> {
        self.checkpoints
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| ConsensusError("Failed to acquire read lock on checkpoints".into()))
    }

    pub fn add_checkpoint(
        &self,
        block: &Block,
        storage: Option<&crate::storage::db::Storage>,
    ) -> Result<(), ConsensusError> {
        let checkpoint = Checkpoint {
            block_index: block.index,
            block_hash: block.hash.clone(),
            timestamp: block.timestamp,
        };
        self.commit_checkpoint(&checkpoint, storage)
    }

    /// Durably record one checkpoint. Called by `add_checkpoint` and by the
    /// finality promotion path (`note_finalized_height`, P01-F04).
    fn commit_checkpoint(
        &self,
        checkpoint: &Checkpoint,
        storage: Option<&crate::storage::db::Storage>,
    ) -> Result<(), ConsensusError> {
        if let Some(store) = storage {
            // Not `let _ =`: a checkpoint that fails to persist is not a
            // cosmetic loss. On restart the node would not know the block was
            // checkpointed and would accept a reorg below it, so the failure
            // has to surface instead of being swallowed.
            store.save_checkpoint(checkpoint).map_err(|error| {
                ConsensusError(format!(
                    "failed to persist checkpoint at height {}: {error}",
                    checkpoint.block_index
                ))
            })?;
        }

        // The durable write comes first. An in-memory checkpoint pushed
        // before a failed write anchored this process to a height the disk
        // never learned, and the two disagreed until the next restart.
        let mut checkpoints = self
            .checkpoints
            .write()
            .map_err(|_| ConsensusError("Failed to acquire write lock on checkpoints".into()))?;
        // Idempotent at one height: `record_block` persists the checkpoint
        // before the seen-block record, and a crash in that window replays
        // this whole path for the same block. Without the check the replay
        // would push a second copy of the same checkpoint.
        if checkpoints.last().is_some_and(|c| {
            c.block_index == checkpoint.block_index && c.block_hash == checkpoint.block_hash
        }) {
            return Ok(());
        }
        checkpoints.push(checkpoint.clone());
        Ok(())
    }
    /// The last checkpoint this node has established, and its hash.
    ///
    /// Returns `None` when no checkpoint exists yet, which is a genuinely
    /// different state from "checkpoint at height 0" and has to stay
    /// distinguishable: a node with no checkpoint has nothing to anchor
    /// against and must not silently behave as though it were anchored at
    /// genesis.
    pub fn last_checkpoint(&self) -> Option<(u64, String)> {
        self.checkpoints
            .read()
            .ok()
            .and_then(|guard| guard.last().map(|c| (c.block_index, c.block_hash.clone())))
    }

    /// Whether `chain` contains this node's last checkpoint at the height and
    /// hash it was recorded with.
    ///
    /// A checkpoint is a revert limit, not a quantity. Ethereum's weak
    /// subjectivity checkpoints work this way: blocks before a checkpoint
    /// cannot be changed, so a fork that departs earlier is invalid *as a
    /// matter of mechanism design*, whatever its length. A candidate that
    /// does not contain the checkpoint is such a fork.
    pub fn chain_honours_checkpoint(&self, chain: &[Block]) -> bool {
        let Some((height, hash)) = self.last_checkpoint() else {
            // Nothing established yet: nothing to violate.
            return true;
        };
        // Locate the block by its height, not by its slice position: the
        // slices handed to fork choice are not required to start at genesis,
        // and on a suffix `chain[height]` names the wrong block (or none),
        // which read as a violation for an honest chain.
        let Some(first) = chain.first() else {
            return false;
        };
        let Some(offset) = height
            .checked_sub(first.index)
            .and_then(|o| usize::try_from(o).ok())
        else {
            return false;
        };
        chain
            .get(offset)
            .is_some_and(|block| block.index == height && block.hash == hash)
    }

    /// Derive epoch randomness from a canonical, already-established VRF
    /// Transcript. Epoch `E` consumes epoch `E-2`, giving the source transcript
    /// A full epoch to settle before it controls leader selection. Only verified
    /// VRF outputs and producer identities enter the transcript: block hashes,
    /// Timestamps and transaction ordering are deliberately excluded so a
    /// Proposer cannot grind future leadership by changing header fields.
    pub fn epoch_randomness_from_chain(
        &self,
        chain_id: u64,
        target_epoch: u64,
        chain: &[Block],
    ) -> Result<[u8; 32], ConsensusError> {
        if self.config.epoch_length == 0 {
            return Err(ConsensusError("PoS epoch length must be non-zero".into()));
        }
        let genesis = chain
            .first()
            .ok_or_else(|| ConsensusError("PoS randomness requires the genesis anchor".into()))?;
        if genesis.index != 0 || genesis.chain_id != chain_id {
            return Err(ConsensusError(
                "PoS randomness genesis anchor has the wrong height or chain ID".into(),
            ));
        }

        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_POS_EPOCH_RANDOMNESS_V3");
        hasher.update(chain_id.to_le_bytes());
        hasher.update(target_epoch.to_le_bytes());
        hasher.update(self.config.epoch_length.to_le_bytes());
        hasher.update(genesis.hash.as_bytes());

        const LOOKBACK_EPOCHS: u64 = 2;
        if let Some(source_epoch) = target_epoch.checked_sub(LOOKBACK_EPOCHS) {
            let start = source_epoch
                .checked_mul(self.config.epoch_length)
                .ok_or_else(|| ConsensusError("PoS randomness source epoch overflow".into()))?;
            let end = start
                .checked_add(self.config.epoch_length)
                .ok_or_else(|| ConsensusError("PoS randomness source range overflow".into()))?;
            let end_index = usize::try_from(end)
                .map_err(|_| ConsensusError("PoS randomness source range is too large".into()))?;
            if chain.len() < end_index {
                return Err(ConsensusError(format!(
                    "PoS randomness source epoch {source_epoch} is incomplete"
                )));
            }

            hasher.update(b"source_epoch");
            hasher.update(source_epoch.to_le_bytes());
            for height in start..end {
                let index = usize::try_from(height).map_err(|_| {
                    ConsensusError("PoS randomness source height is too large".into())
                })?;
                let source = chain.get(index).ok_or_else(|| {
                    ConsensusError(format!("PoS randomness source block {height} is missing"))
                })?;
                if source.index != height || source.chain_id != chain_id {
                    return Err(ConsensusError(format!(
                        "PoS randomness source block {height} is not canonical"
                    )));
                }
                // Genesis has no VRF output. Its hash is already committed above.
                if height == 0 {
                    continue;
                }
                let producer = source.producer.ok_or_else(|| {
                    ConsensusError(format!(
                        "PoS randomness source block {height} has no producer"
                    ))
                })?;
                if source.vrf_output.len() != 32 || source.vrf_proof.is_empty() {
                    return Err(ConsensusError(format!(
                        "PoS randomness source block {height} has no verified VRF transcript"
                    )));
                }
                hasher.update(b"vrf_contribution");
                hasher.update(height.to_le_bytes());
                hasher.update(producer.as_bytes());
                hasher.update(&source.vrf_output);
            }
        } else {
            // Epochs 0 and 1 use a deterministic genesis-anchored bootstrap.
            // No producer-controlled header field enters this value.
            hasher.update(b"genesis_bootstrap");
        }

        Ok(hasher.finalize().into())
    }

    /// Canonical slot seed used by both local production and remote validation.
    ///
    /// `round` is the leader-election retry term (P01-F01): slot `s` runs
    /// rounds `0..MAX_LEADER_ROUNDS`, and each round draws a different VRF
    /// seed, so a slot with no eligible leader in round 0 re-rolls instead of
    /// stalling forever. Validation recovers the round from `block.nonce`.
    pub fn calculate_seed_with_chain(
        &self,
        chain_id: u64,
        epoch: u64,
        slot: u64,
        round: u64,
        chain: &[Block],
    ) -> Result<[u8; 32], ConsensusError> {
        if self.config.epoch_length == 0 || slot / self.config.epoch_length != epoch {
            return Err(ConsensusError(
                "PoS seed epoch/slot pair is not canonical".into(),
            ));
        }
        if round > MAX_LEADER_ROUNDS {
            return Err(ConsensusError(format!(
                "PoS leader round {round} exceeds the cap {MAX_LEADER_ROUNDS}"
            )));
        }
        let epoch_randomness = self.epoch_randomness_from_chain(chain_id, epoch, chain)?;
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_POS_SLOT_SEED_V4");
        hasher.update(chain_id.to_le_bytes());
        hasher.update(epoch.to_le_bytes());
        hasher.update(slot.to_le_bytes());
        hasher.update(round.to_le_bytes());
        hasher.update(epoch_randomness);
        Ok(hasher.finalize().into())
    }

    /// Backward-compatible diagnostic helper. Consensus production and
    /// Validation use `calculate_seed_with_chain`; this method only exposes the
    /// Latest replay-derived cache to callers that used the former API.
    /// Test-only (P01-F21): no production caller.
    #[cfg(test)]
    pub fn calculate_seed(
        &self,
        chain_id: u64,
        epoch: u64,
        slot: u64,
        _validator_set_hash: &str,
    ) -> [u8; 32] {
        let cached = self.epoch_seed.read().map_or_else(
            |_| {
                let mut fallback = Sha3_256::new();
                fallback.update(b"BDLM_POS_CACHE_POISON_V3");
                fallback.update(chain_id.to_le_bytes());
                fallback.update(epoch.to_le_bytes());
                fallback.finalize().into()
            },
            |guard| *guard,
        );
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_POS_SLOT_SEED_COMPAT_V3");
        hasher.update(chain_id.to_le_bytes());
        hasher.update(epoch.to_le_bytes());
        hasher.update(slot.to_le_bytes());
        hasher.update(cached);
        hasher.finalize().into()
    }

    /// The round-widened leadership threshold (P01-F01).
    ///
    /// Round `r` multiplies the base threshold by `r + 1`, so eligibility
    /// widens geometrically as a slot retries: by round `MAX_LEADER_ROUNDS`
    /// any validator holding at least `1 / (MAX_LEADER_ROUNDS + 1)` of the
    /// stake is guaranteed a turn. The base threshold alone left a slot dead
    /// whenever the sampled leader was offline, because the retry drew the
    /// same sample again.
    fn calculate_vrf_threshold_for_round(&self, stake: u64, total_stake: u64, round: u64) -> u64 {
        use crate::core::chain_config::{FIXED_POINT_SCALE, VRF_BASE_PROB};
        if total_stake == 0 || stake == 0 {
            return 0;
        }

        // Threshold = (stake * VRF_BASE_PROB * u64::MAX) / (total_stake * FIXED_POINT_SCALE)
        let base_threshold =
            u128::from(stake).saturating_mul(u128::from(u64::MAX)) / u128::from(total_stake);

        let threshold = (base_threshold.saturating_mul(u128::from(VRF_BASE_PROB)))
            / u128::from(FIXED_POINT_SCALE);

        // Round widening, saturating at u64::MAX: past that every key is
        // eligible and the arithmetic has nothing left to say. The seed caps
        // `round` at MAX_LEADER_ROUNDS, so the factor is at most 17.
        let factor = u128::from(round.saturating_add(1));
        let widened = threshold.saturating_mul(factor);

        if widened >= u128::from(u64::MAX) {
            u64::MAX
        } else {
            widened as u64
        }
    }

    pub fn check_vrf_threshold(&self, vrf_output: &[u8], threshold: u64) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(vrf_output);
        let hash = hasher.finalize();
        let y = u64::from_le_bytes(hash[0..8].try_into().unwrap_or([0; 8]));
        y < threshold
    }
    /// Test mirror of the validator-admission rule (P01-F21: no production
    /// caller; `validate_block` enforces the same predicate inline).
    #[cfg(test)]
    pub fn is_validator(&self, pubkey: &Address, state: &AccountState) -> bool {
        state
            .get_validator(pubkey)
            .is_some_and(|v| v.active && !v.slashed && v.stake >= self.config.min_stake)
    }

    /// Lock-order fixture (P01-F21): the POS_STATE writer is gone; this
    /// stays only so `consensus_lock_order_loom` can pin the checkpoints ->
    /// slashing_evidence lock order.
    #[cfg(test)]
    pub fn serialize_state(&self) -> Result<Vec<u8>, String> {
        let epoch_seed = self
            .epoch_seed
            .read()
            .map_err(|_| "Lock error".to_string())?
            .to_vec();
        let state = serde_json::json!({
            "checkpoints": self.checkpoints.read().map_err(|_| "Lock error".to_string())?.iter().map(|c| {
                serde_json::json!({
                    "block_index": c.block_index,
                    "block_hash": c.block_hash,
                    "timestamp": c.timestamp,
                })
            }).collect::<Vec<_>>(),
            "slashing_evidence": *self.slashing_evidence.read().map_err(|_| "Lock error".to_string())?,
            "epoch_seed": epoch_seed.iter().map(|b| u64::from(*b)).collect::<Vec<_>>(),
        });
        serde_json::to_vec(&state).map_err(|e| format!("Serialization error: {e}"))
    }
    fn preview_common(
        &self,
        block: &mut Block,
        state: &AccountState,
        chain: &[Block],
    ) -> Result<(), ConsensusError> {
        let slot = block.index;
        let epoch = slot / self.epoch_length_checked()?;
        block.epoch = epoch;
        block.slot = slot;

        let active_validators = state.get_active_validators();
        let total_stake = state.get_total_stake();

        // Fail-closed when validator set is empty.
        // Previously this returned Ok which allowed hash-only blocks without
        // Producer membership or signature - a security gap in the bootstrap window.
        // Now we require at least one active, consensus-ready validator.
        if active_validators.is_empty() {
            return Err(ConsensusError(
                "No active validators - PoS block production requires at least one                  consensus-ready validator. Bootstrap via genesis validator set or                  RegisterConsensusKeys transaction."
                    .into(),
            ));
        }

        if let Some(keys) = &self.validator_keys {
            let pubkey = Address::from(keys.sig_key.public_key_bytes());

            if let Some(validator) = state.get_validator(&pubkey) {
                // Eligibility, not the two flags it is made of: `is_eligible`
                // also carries the liveness-fault jail, so a validator serving
                // an unexpired term cannot build a block for this slot even if
                // an ordinary transaction has rewritten `active` underneath.
                if validator.is_eligible(state.epoch_index)
                    && validator.stake >= self.config.min_stake
                {
                    if block.vrf_output.is_empty() || block.vrf_proof.is_empty() {
                        // Leader rounds (P01-F01). A stalled slot widens the
                        // threshold and re-rolls the seed as wall time
                        // advances, instead of retrying the same losing draw
                        // forever. The round a producer may claim is priced by
                        // wall time since the parent landed - one round per
                        // `ROUND_TIMEOUT_MS` - and validation re-prices the
                        // claim against the block timestamp floor
                        // `parent + MIN_BLOCK_INTERVAL_MS + round * ROUND_TIMEOUT_MS`.
                        let round_cap = chain.last().map_or(MAX_LEADER_ROUNDS, |prev| {
                            let now_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis();
                            let spaced = now_ms
                                .saturating_sub(prev.timestamp)
                                .saturating_sub(MIN_BLOCK_INTERVAL_MS);
                            u64::try_from(spaced / ROUND_TIMEOUT_MS)
                                .unwrap_or(u64::MAX)
                                .min(MAX_LEADER_ROUNDS)
                        });
                        let mut elected = false;
                        for round in 0..=round_cap {
                            let seed = self.calculate_seed_with_chain(
                                block.chain_id,
                                epoch,
                                slot,
                                round,
                                chain,
                            )?;
                            let (vrf_io, vrf_proof, _) = keys.vrf_key.vrf_sign(
                                schnorrkel::context::signing_context(b"BUDLUM_VRF").bytes(&seed),
                            );
                            let vrf_output = vrf_io.to_preout().to_bytes();
                            let proof_bytes = vrf_proof.to_bytes();

                            let threshold = self.calculate_vrf_threshold_for_round(
                                validator.stake,
                                total_stake,
                                round,
                            );
                            if self.check_vrf_threshold(&vrf_output, threshold) {
                                block.vrf_output = vrf_output.to_vec();
                                block.vrf_proof = proof_bytes.to_vec();
                                // The block nonce carries the round: it is
                                // the retry term both sides read back.
                                block.nonce = round;
                                // Price the round in the timestamp so the
                                // validation floor holds for this block too.
                                if let Some(prev) = chain.last() {
                                    let floor = prev
                                        .timestamp
                                        .saturating_add(MIN_BLOCK_INTERVAL_MS)
                                        .saturating_add(
                                            ROUND_TIMEOUT_MS.saturating_mul(u128::from(round)),
                                        );
                                    if block.timestamp < floor {
                                        block.timestamp = floor;
                                    }
                                }
                                elected = true;
                                break;
                            }
                        }
                        if !elected {
                            return Err(ConsensusError(
                                "Not selected as VRF leader for this slot".into(),
                            ));
                        }
                    }

                    // Hand over only what a block can still carry, and take
                    // nothing out of the pool yet. The whole pool used to be
                    // inlined here with no size limit and then cleared before
                    // the block was even validated: an oversized entry made
                    // the block fail `validate_block_size`, the slot was
                    // lost, and the evidence it had just taken was gone. The
                    // pool is only pruned by `record_block_with_chain`, once
                    // the block that carried an entry is actually committed.
                    if block.slashing_evidence.is_none() {
                        if let Ok(evidences) = self.slashing_evidence.read() {
                            // Same reservation the block builder makes for
                            // evidence in `collect_block_transactions`.
                            const BLOCK_HEADER_JSON_ALLOWANCE: usize = 4096;
                            let mut remaining = crate::consensus::MAX_BLOCK_SIZE
                                .saturating_sub(BLOCK_HEADER_JSON_ALLOWANCE)
                                .saturating_sub(
                                    serde_json::to_vec(&block.transactions)
                                        .map_or(usize::MAX, |bytes| bytes.len()),
                                );
                            let mut taken = Vec::new();
                            let mut used = 0usize;
                            for evidence in evidences.iter() {
                                let encoded = serde_json::to_vec(evidence)
                                    .map(|bytes| bytes.len())
                                    .unwrap_or(usize::MAX);
                                if encoded <= crate::consensus::MAX_SLASHING_EVIDENCE_BYTES
                                    && used.saturating_add(encoded)
                                        <= crate::consensus::MAX_SLASHING_EVIDENCE_BYTES
                                    && encoded <= remaining
                                {
                                    used = used.saturating_add(encoded);
                                    remaining = remaining.saturating_sub(encoded);
                                    taken.push(evidence.clone());
                                }
                            }
                            if !taken.is_empty() {
                                block.slashing_evidence = Some(taken);
                            }
                        }
                    }
                    block.producer = Some(pubkey);
                    return Ok(());
                }
            }
        }

        Err(ConsensusError(
            "Not selected as VRF leader for this slot".into(),
        ))
    }
}
/// The one structural check for double-sign evidence (P01-F25).
///
/// `Blockchain::verify_slashing_evidence` and `PoSEngine::verify_evidence`
/// used to restate this independently. Two copies of a consensus check drift,
/// and the drift is invisible until the two disagree about an equivocation.
pub fn slashing_evidence_is_valid(evidence: &SlashingEvidence) -> bool {
    if evidence.header1.index != evidence.header2.index {
        return false;
    }
    if evidence.header1.producer != evidence.header2.producer {
        return false;
    }
    if evidence.header1.producer.is_none() {
        return false;
    }
    if evidence.header1.hash == evidence.header2.hash {
        return false;
    }
    evidence.header1.verify_signature(&evidence.signature1)
        && evidence.header2.verify_signature(&evidence.signature2)
}

impl ConsensusEngine for PoSEngine {
    fn preview_block(
        &self,
        _block: &mut Block,
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        Err(ConsensusError(
            "PoS block preview requires canonical chain context".into(),
        ))
    }

    fn preview_block_with_chain(
        &self,
        block: &mut Block,
        state: &AccountState,
        chain: &[Block],
    ) -> Result<(), ConsensusError> {
        self.preview_common(block, state, chain)
    }

    fn prepare_block(
        &self,
        _block: &mut Block,
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        Err(ConsensusError(
            "PoS block preparation requires canonical chain context".into(),
        ))
    }

    fn prepare_block_with_chain(
        &self,
        block: &mut Block,
        state: &AccountState,
        chain: &[Block],
    ) -> Result<(), ConsensusError> {
        self.preview_common(block, state, chain)?;

        if let Some(signer) = &self.signer {
            block
                .sign_with_signer(signer.as_ref())
                .map_err(|e| ConsensusError(format!("HSM block signing failed: {e}")))?;
            return Ok(());
        }

        if let Some(keys) = &self.validator_keys {
            if block.producer == Some(Address::from(keys.sig_key.public_key_bytes())) {
                block.sign(&keys.sig_key);
                return Ok(());
            }
        }

        Err(ConsensusError(
            "Selected PoS validator has no usable block-signing backend".into(),
        ))
    }

    fn validate_block(
        &self,
        block: &Block,
        chain: &[Block],
        state: &AccountState,
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
        // No "below the checkpoint" rejection here. `validate_block` also runs
        // over a candidate chain from block 1 (`try_reorg`, `is_valid`), and
        // every block of a chain that honours the checkpoint sits below it.
        // The checkpoint is enforced where a chain is chosen:
        // `chain_honours_checkpoint` in `is_better_chain`.

        let expected_epoch = block.index / self.epoch_length_checked()?;
        if block.epoch != expected_epoch {
            return Err(ConsensusError(format!(
                "PoS epoch mismatch: expected {}, got {}",
                expected_epoch, block.epoch
            )));
        }
        if block.slot != block.index {
            return Err(ConsensusError(format!(
                "PoS slot mismatch: expected {}, got {}",
                block.index, block.slot
            )));
        }

        let active_validators = state.get_active_validators();
        if !active_validators.is_empty() {
            let producer = block
                .producer
                .as_ref()
                .ok_or_else(|| ConsensusError("Block has no producer".into()))?;
            // The cheap Ed25519 check runs first. The validator set hash
            // Does BLS and PQ key checks for every active validator, and an
            // Unsigned block from a peer must not cost that work.
            if !block.verify_signature() {
                return Err(ConsensusError("Invalid block signature".into()));
            }
            let expected_set_hash = state
                .consensus_validator_set_hash(block.chain_id)
                .map_err(ConsensusError)?;
            if block.validator_set_hash != expected_set_hash {
                return Err(ConsensusError(format!(
                    "Validator set hash mismatch: expected {}, got {}",
                    expected_set_hash, block.validator_set_hash
                )));
            }

            let validator = state
                .get_validator(producer)
                .ok_or_else(|| ConsensusError("Unknown block producer".into()))?;
            // Same predicate as the production gate above: a jailed validator
            // is not eligible until `jail_until`, whatever `active` says. The
            // two gates have to agree - one that admits a block the other
            // refuses splits the chain.
            if !validator.is_eligible(state.epoch_index) || validator.stake < self.config.min_stake
            {
                return Err(ConsensusError("Producer is not an active validator".into()));
            }

            if validator.vrf_public_key.is_empty() {
                return Err(ConsensusError(
                    "Producer has no registered VRF public key".into(),
                ));
            }

            if let Ok(public_key) = schnorrkel::PublicKey::from_bytes(&validator.vrf_public_key) {
                // The block nonce carries the leader round (P01-F01). The
                // round is capped and time-priced: a block claiming round `r`
                // must sit at least `MIN_BLOCK_INTERVAL_MS + r * ROUND_TIMEOUT_MS`
                // after its parent, so a later, wider round cannot be claimed
                // on the cheap (P01-F20).
                let round = block.nonce;
                if round > MAX_LEADER_ROUNDS {
                    return Err(ConsensusError(format!(
                        "PoS leader round {round} exceeds the cap {MAX_LEADER_ROUNDS}"
                    )));
                }
                if round > 0 {
                    if let Some(prev) = chain.last() {
                        let floor = prev
                            .timestamp
                            .saturating_add(MIN_BLOCK_INTERVAL_MS)
                            .saturating_add(ROUND_TIMEOUT_MS.saturating_mul(u128::from(round)));
                        if block.timestamp < floor {
                            return Err(ConsensusError(format!(
                                "PoS leader round {round} claimed too early: block timestamp {} < floor {}",
                                block.timestamp, floor
                            )));
                        }
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis();
                        if now_ms < floor {
                            return Err(ConsensusError(format!(
                                "PoS leader round {round} claimed ahead of wall clock: now {now_ms} < floor {floor}"
                            )));
                        }
                    }
                }
                let seed = self.calculate_seed_with_chain(
                    block.chain_id,
                    block.epoch,
                    block.slot,
                    round,
                    chain,
                )?;

                let mut output_bytes = [0u8; 32];
                if block.vrf_output.len() == 32 {
                    output_bytes.copy_from_slice(&block.vrf_output);
                } else {
                    return Err(ConsensusError("Invalid VRF output length".into()));
                }

                if let Ok(vrf_preout) = schnorrkel::vrf::VRFPreOut::from_bytes(&output_bytes) {
                    if let Ok(vrf_proof) = schnorrkel::vrf::VRFProof::from_bytes(&block.vrf_proof) {
                        if public_key
                            .vrf_verify(
                                schnorrkel::context::signing_context(b"BUDLUM_VRF").bytes(&seed),
                                &vrf_preout,
                                &vrf_proof,
                            )
                            .is_err()
                        {
                            return Err(ConsensusError("VRF proof verification failed".into()));
                        }
                    } else {
                        return Err(ConsensusError("Invalid VRF proof format".into()));
                    }
                } else {
                    return Err(ConsensusError("Invalid VRF output format".into()));
                }
            } else {
                return Err(ConsensusError("Invalid VRF public key format".into()));
            }

            let threshold = self.calculate_vrf_threshold_for_round(
                validator.stake,
                state.get_total_stake(),
                block.nonce,
            );
            if !self.check_vrf_threshold(&block.vrf_output, threshold) {
                return Err(ConsensusError(
                    "VRF output does not meet leadership threshold".into(),
                ));
            }

            if let Some(evidences) = &block.slashing_evidence {
                for (i, evidence) in evidences.iter().enumerate() {
                    if !self.verify_evidence(evidence) {
                        return Err(ConsensusError(format!("Invalid slashing evidence #{i}")));
                    }

                    if let Some(producer) = &evidence.header1.producer {
                        if state.get_validator(producer).is_none() {
                            warn!("Slashing evidence for unknown validator {producer}");
                        } else {
                            info!("Valid slashing evidence found for validator {producer}");
                        }
                    } else {
                        return Err(ConsensusError("Evidence header missing producer".into()));
                    }
                }
            }

            info!(
                "PoS: Block {} validated (producer: {}, stake: {})",
                block.index, producer, validator.stake
            );
        } else {
            return Err(ConsensusError(
                "No active consensus-ready validators; refusing unsigned PoS block".into(),
            ));
        }
        Ok(())
    }
    fn consensus_type(&self) -> &'static str {
        "PoS"
    }
    fn signer(&self) -> Option<&dyn ConsensusSigner> {
        self.signer.as_ref().map(std::convert::AsRef::as_ref)
    }
    fn bls_secret_key(&self) -> Option<bls12_381::Scalar> {
        self.validator_keys
            .as_ref()
            .and_then(|k| k.bls_key.as_ref())
            .map(|b| b.secret_key)
    }
    fn bls_public_key(&self) -> Option<Vec<u8>> {
        self.validator_keys
            .as_ref()
            .and_then(|k| k.bls_key.as_ref())
            .map(|b| b.public_key.clone())
            .or_else(|| self.signer.as_ref().and_then(|s| s.bls_public_key()))
    }
    fn info(&self) -> String {
        format!(
            "PoS (min_stake: {}, checkpoints: {})",
            self.config.min_stake,
            self.checkpoints.read().map_or(0, |c| c.len())
        )
    }
    fn fork_choice_score(&self, chain: &[Block]) -> u128 {
        // A candidate that abandons the checkpoint scores zero rather than
        // scoring low. Previously the checkpoint height was a *term* in the
        // score:
        //
        //     score = last_checkpoint_height * 1000 + chain.len()
        //
        // which let length buy the difference. Measured against that formula,
        // a fork branching from one checkpoint earlier and running 1001 blocks
        // longer wins outright:
        //
        //     honest   cp=10 len=1000 -> 11000
        //     attacker cp= 9 len=2001 -> 11001
        //
        // The 1000 was also unrelated to `epoch_length`, so the exchange rate
        // between "a checkpoint" and "a block" was arbitrary. There should be
        // no exchange rate. A fork that drops the checkpoint is not a worse
        // chain, it is not a chain this node may adopt.
        if !self.chain_honours_checkpoint(chain) {
            return 0;
        }
        chain.len() as u128
    }

    fn is_better_chain(&self, current: &[Block], candidate: &[Block]) -> bool {
        // Fail closed on the candidate specifically. Scoring alone would let
        // a checkpoint-violating candidate win whenever the current chain
        // also scored zero - which happens on a node whose own chain has not
        // reached the checkpoint height yet, exactly the node least able to
        // tell the difference.
        if !self.chain_honours_checkpoint(candidate) {
            return false;
        }
        let candidate_score = self.fork_choice_score(candidate);
        let current_score = self.fork_choice_score(current);
        if candidate_score != current_score {
            return candidate_score > current_score;
        }
        // Equal accumulated weight (a 2-2 validator split): the deterministic
        // resolver picks a side, so honest nodes converge on the same tip
        // regardless of the order in which the two tips arrived. `RightWins`
        // means the candidate replaces the current chain; identical tips keep
        // the incumbent (no reorg).
        resolve_split_tie(
            &SplitCandidate::from_chain_tip(current, current_score),
            &SplitCandidate::from_chain_tip(candidate, candidate_score),
        ) == SplitDecision::RightWins
    }

    fn record_block(
        &self,
        block: &Block,
        storage: Option<&crate::storage::db::Storage>,
    ) -> Result<(), ConsensusError> {
        let epoch_length = self.epoch_length_checked()?;
        let producer = block
            .producer
            .as_ref()
            .ok_or(ConsensusError("Block has no producer".into()))?;
        let header = BlockHeader::from_block(block);
        let signature = block.signature.clone().unwrap_or_default();
        let key = (*producer, header.index);

        let mut seen_blocks = self
            .seen_blocks
            .write()
            .map_err(|_| ConsensusError("Lock error on seen_blocks".into()))?;

        if let Some(existing) = seen_blocks.get(&key) {
            if existing.0.hash != header.hash {
                warn!(
                    "DOUBLE-SIGN: {} signed two blocks for slot {}!",
                    producer, header.index
                );
                // The persisted seen-block record is the double-sign
                // evidence across restarts, so the FIRST header must stay
                // the durable one. Persisting unconditionally here would
                // overwrite `SEEN:{producer}:{height}` with the second,
                // conflicting signature before this comparison runs; after
                // a restart only the second signature would survive and the
                // equivocation could never be proven. `load_state` refills
                // `seen_blocks` from storage at startup, so the in-memory
                // view is authoritative and the write is skipped on a
                // conflict.
                let evidence = SlashingEvidence::new(
                    existing.0.clone(),
                    header,
                    existing.1.clone(),
                    signature,
                );
                let mut slashing_evidence = self
                    .slashing_evidence
                    .write()
                    .map_err(|_| ConsensusError("Lock error on slashing_evidence".into()))?;
                slashing_evidence.push(evidence);
            }
        } else {
            if block.index > 0 && block.index.is_multiple_of(epoch_length) {
                // P01-F04: the boundary block is parked, not checkpointed.
                // A checkpoint written at local commit time splits the net
                // whenever two leaders exist at the boundary: each node
                // commits the block it saw first and then refuses the other
                // chain forever. The checkpoint is promoted only when the
                // chain reports the height as quorum-finalised
                // (`note_finalized_height`). The pending entry is pure
                // memory, so a crash before promotion simply re-parks it on
                // the replay of this same block.
                let checkpoint = Checkpoint {
                    block_index: block.index,
                    block_hash: block.hash.clone(),
                    timestamp: block.timestamp,
                };
                let mut pending = self
                    .pending_checkpoints
                    .write()
                    .map_err(|_| ConsensusError("Lock error on pending_checkpoints".to_string()))?;
                if !pending.iter().any(|c| {
                    c.block_index == checkpoint.block_index && c.block_hash == checkpoint.block_hash
                }) {
                    pending.retain(|c| c.block_index != checkpoint.block_index);
                    pending.push(checkpoint);
                }
            }
            if let Some(store) = storage {
                // Not `let _ =`: the seen-block record is the double-sign
                // evidence. A record that fails to persist means a restart
                // forgets the first signature and the second one is never
                // caught, so the failure has to surface.
                store
                    .save_seen_block(&header, &signature)
                    .map_err(|error| {
                        ConsensusError(format!(
                            "failed to persist seen block at height {}: {error}",
                            header.index
                        ))
                    })?;
            }
            seen_blocks.insert(key, (header, signature));

            // Prune seen_blocks to prevent unbounded growth.
            // Keep entries from the last 2 epochs only, older double-sign evidence
            // Is no longer actionable (already slashed or epoch-finalized).
            let current_epoch = block.index / epoch_length;
            let min_slot = current_epoch.saturating_sub(2) * epoch_length;
            let before = seen_blocks.len();
            seen_blocks.retain(|(_, slot), _| *slot >= min_slot);
            let pruned = before - seen_blocks.len();
            if pruned > 0 {
                if let Some(store) = storage {
                    if let Err(error) = store.prune_seen_blocks_below(min_slot) {
                        tracing::warn!("Failed to prune persisted seen blocks: {error}");
                    }
                }
                tracing::info!(
                    pruned,
                    remaining = seen_blocks.len(),
                    "Pruned seen_blocks entries older than epoch {}",
                    current_epoch.saturating_sub(2)
                );
            }
        }

        Ok(())
    }

    /// Promote parked epoch-boundary checkpoints the chain has finalised
    /// (P01-F04). Only a block the finalised chain actually holds is
    /// promoted; a parked checkpoint on a losing fork is dropped.
    fn note_finalized_height(
        &self,
        height: u64,
        chain: &[Block],
        storage: Option<&crate::storage::db::Storage>,
    ) {
        let promoted: Vec<Checkpoint> = {
            let Ok(mut pending) = self.pending_checkpoints.write() else {
                return;
            };
            let mut ready = Vec::new();
            pending.retain(|c| {
                if c.block_index <= height {
                    ready.push(c.clone());
                    false
                } else {
                    true
                }
            });
            ready
        };
        for checkpoint in promoted {
            let on_chain = chain
                .iter()
                .any(|b| b.index == checkpoint.block_index && b.hash == checkpoint.block_hash);
            if !on_chain {
                info!(
                    "Dropping parked checkpoint at height {}: not on the finalised chain",
                    checkpoint.block_index
                );
                continue;
            }
            if let Err(error) = self.commit_checkpoint(&checkpoint, storage) {
                warn!(
                    "Failed to promote finalised checkpoint at height {}: {error}",
                    checkpoint.block_index
                );
            }
        }
    }

    fn observe_received_block(&self, block: &Block) -> Result<(), ConsensusError> {
        let producer = block
            .producer
            .ok_or(ConsensusError("Block has no producer".into()))?;
        let signature = block
            .signature
            .clone()
            .ok_or(ConsensusError("Block has no signature".into()))?;
        let header = BlockHeader::from_block(block);
        // Only a verified signature may produce evidence. Otherwise anyone
        // could frame a producer with a forged rival block.
        if !header.verify_signature(&signature) {
            return Err(ConsensusError("Invalid block signature".into()));
        }
        let existing = {
            let seen_blocks = self
                .seen_blocks
                .read()
                .map_err(|_| ConsensusError("Lock error on seen_blocks".into()))?;
            match seen_blocks.get(&(producer, header.index)) {
                Some(entry) if entry.0.hash != header.hash => entry.clone(),
                _ => return Ok(()),
            }
        };
        let evidence = SlashingEvidence::new(existing.0, header, existing.1, signature);
        if !self.verify_evidence(&evidence) {
            return Err(ConsensusError("Double-sign evidence did not verify".into()));
        }
        warn!(
            "DOUBLE-SIGN: {} signed two blocks for height {}",
            producer, evidence.header2.index
        );
        let mut pool = self
            .slashing_evidence
            .write()
            .map_err(|_| ConsensusError("Lock error on slashing_evidence".into()))?;
        if !pool.contains(&evidence) {
            pool.push(evidence);
        }
        Ok(())
    }

    fn record_block_with_chain(
        &self,
        block: &Block,
        chain: &[Block],
        _storage: Option<&crate::storage::db::Storage>,
    ) {
        // The block is committed: the evidence it carried has now done its
        // job and leaves the pool. Everything the pool still holds is
        // retried on the next slot, so an entry that lost its race with a
        // full block is never destroyed.
        if let Some(committed) = &block.slashing_evidence {
            if let Ok(mut evidences) = self.slashing_evidence.write() {
                evidences.retain(|pooled| !committed.contains(pooled));
            }
        }
        if self.config.epoch_length == 0 {
            tracing::error!("Cannot refresh PoS randomness with zero epoch length");
            return;
        }
        let next_slot = block.index.saturating_add(1);
        let next_epoch = next_slot / self.config.epoch_length;
        match self.epoch_randomness_from_chain(block.chain_id, next_epoch, chain) {
            Ok(randomness) => match self.epoch_seed.write() {
                Ok(mut cached) => *cached = randomness,
                Err(_) => tracing::error!("PoS replay-derived randomness cache lock is poisoned"),
            },
            Err(error) => {
                tracing::error!("Failed to refresh replay-derived PoS randomness cache: {error}")
            }
        }
    }

    fn load_state(&self, storage: &crate::storage::db::Storage) -> Result<(), ConsensusError> {
        let seen = storage
            .load_all_seen_blocks()
            .map_err(|error| ConsensusError(format!("Failed to load seen PoS blocks: {error}")))?;
        *self
            .seen_blocks
            .write()
            .map_err(|_| ConsensusError("PoS seen-block lock is poisoned".into()))? = seen;

        let checkpoints = storage
            .load_checkpoints()
            .map_err(|error| ConsensusError(format!("Failed to load PoS checkpoints: {error}")))?;
        *self
            .checkpoints
            .write()
            .map_err(|_| ConsensusError("PoS checkpoint lock is poisoned".into()))? = checkpoints;

        let chain = storage.load_chain().map_err(|error| {
            ConsensusError(format!(
                "Failed to load canonical chain for PoS randomness replay: {error}"
            ))
        })?;
        if self.config.epoch_length == 0 {
            return Err(ConsensusError("PoS epoch length must be non-zero".into()));
        }
        if let Some(tip) = chain.last() {
            let next_slot = tip.index.saturating_add(1);
            let next_epoch = next_slot / self.config.epoch_length;
            let randomness = self.epoch_randomness_from_chain(tip.chain_id, next_epoch, &chain)?;
            *self
                .epoch_seed
                .write()
                .map_err(|_| ConsensusError("PoS randomness cache lock is poisoned".into()))? =
                randomness;
        }
        Ok(())
    }

    fn drain_slashing_evidence(&self) -> Result<Vec<SlashingEvidence>, ConsensusError> {
        let mut guard = self
            .slashing_evidence
            .write()
            .map_err(|_| ConsensusError("Lock error on slashing_evidence".into()))?;
        let evidence = guard.clone();
        guard.clear();
        Ok(evidence)
    }

    fn prune_slashing_evidence(&self, min_height: u64) -> Result<usize, ConsensusError> {
        self.prune_slashing_evidence(min_height)
    }
}
#[cfg(test)]
mod tests {

    /// C-12 regression: the PoS engine validates `block.epoch == block.index /
    /// Config.epoch_length`, while the chain layer derives epoch boundaries
    /// From `chain_config::epoch_len_for_chain_id`. If the default drifts away
    /// From every real network, a caller that forgets to override it silently
    /// Validates blocks against a schedule the chain never uses.
    ///
    /// The default used to be 32, which matches no network (mainnet 100,
    /// Testnet 50, devnet 10).
    #[test]
    fn pos_default_epoch_length_matches_a_real_network() {
        use crate::core::chain_config::Network;
        let default_len = PoSConfig::default().epoch_length;
        let known: Vec<u64> = [Network::Mainnet, Network::Testnet, Network::Devnet]
            .iter()
            .map(|n| n.consensus_params().epoch_len)
            .collect();
        assert!(
            known.contains(&default_len),
            "PoSConfig::default().epoch_length = {default_len} matches no network schedule {known:?}"
        );
        // Pinned to devnet: the default is the local/dev shape.
        assert_eq!(
            default_len,
            Network::Devnet.consensus_params().epoch_len,
            "default PoS epoch_length must equal the devnet epoch_len"
        );
        // And it must agree with the chain-layer helper for that chain id.
        assert_eq!(
            default_len,
            crate::core::chain_config::epoch_len_for_chain_id(Network::Devnet.chain_id().value()),
            "PoS engine and chain layer disagree on the devnet epoch length"
        );
    }
    use super::*;
    use crate::core::account::AccountState;
    use crate::core::address::Address;
    #[cfg(test)]
    use crate::core::transaction::Transaction;
    use crate::crypto::primitives::{KeyPair, ValidatorKeys};
    use crate::execution::executor::Executor;

    fn create_stake_tx(keypair: &KeyPair, amount: u64, nonce: u64) -> Transaction {
        let from = Address::from(keypair.public_key_bytes());
        let mut tx = Transaction::new_stake(from, amount, nonce);
        tx.sign(keypair);
        tx
    }

    #[test]
    fn test_validator_threshold() {
        let mut state = AccountState::new();
        let alice = ValidatorKeys::generate().unwrap();
        let alice_addr = Address::from(alice.sig_key.public_key_bytes());
        state.add_balance(&alice_addr, 2000);

        let tx = create_stake_tx(&alice.sig_key, 1000, 1);
        Executor::apply_transaction(&mut state, &tx).unwrap();

        let engine = PoSEngine::new(PoSConfig::default(), None);
        let threshold = engine.calculate_vrf_threshold_for_round(1000, 1000, 0);
        assert_eq!(threshold, u64::MAX);
    }

    #[test]
    fn test_double_sign_detection() {
        let engine = PoSEngine::new(PoSConfig::default(), None);
        let alice = KeyPair::generate().unwrap();
        let alice_addr = Address::from(alice.public_key_bytes());

        let mut block1 = Block::new(10, "prev".into(), vec![]);
        block1.producer = Some(alice_addr);
        block1.hash = "hash1".to_string();
        block1.sign(&alice);

        let mut block2 = Block::new(10, "prev".into(), vec![]);
        block2.timestamp += 1000;
        block2.producer = Some(alice_addr);
        block2.hash = "hash2".to_string();
        block2.sign(&alice);

        engine.record_block(&block1, None).unwrap();
        engine.record_block(&block2, None).unwrap();

        assert_eq!(engine.slashing_evidence.read().unwrap().len(), 1);
        let evidence = engine.slashing_evidence.read().unwrap()[0].clone();
        assert_eq!(evidence.header1.index, 10u64);
        assert!(engine.verify_evidence(&evidence));
    }

    /// BLG-0011: a signed rival block seen on the receive path (it never
    /// commits) must still produce double-sign evidence, and a forged one must
    /// not.
    #[test]
    fn observe_received_block_turns_a_signed_rival_into_evidence() {
        let engine = PoSEngine::new(PoSConfig::default(), None);
        let alice = KeyPair::generate().unwrap();

        let mut committed = Block::new(10, "prev".into(), vec![]);
        committed.sign(&alice);
        engine.record_block(&committed, None).unwrap();

        // The same block again is not a rival.
        engine.observe_received_block(&committed).unwrap();
        assert!(engine.slashing_evidence.read().unwrap().is_empty());

        let mut rival = Block::new(10, "prev".into(), vec![]);
        rival.timestamp += 1000;
        rival.sign(&alice);
        engine.observe_received_block(&rival).unwrap();
        engine.observe_received_block(&rival).unwrap();
        let pool = engine.slashing_evidence.read().unwrap().clone();
        assert_eq!(pool.len(), 1, "one rival gives one evidence record");
        assert!(engine.verify_evidence(&pool[0]));

        // A rival with a bad signature is refused and adds nothing.
        let mut forged = Block::new(10, "prev".into(), vec![]);
        forged.timestamp += 2000;
        forged.sign(&alice);
        forged.signature = Some(vec![0u8; 64]);
        assert!(engine.observe_received_block(&forged).is_err());
        assert_eq!(engine.slashing_evidence.read().unwrap().len(), 1);
    }

    /// BLG-0020: an unsigned block must fail on the cheap signature check,
    /// before the validator set hash does BLS and PQ work for every validator.
    #[test]
    fn unsigned_block_fails_before_the_validator_set_hash() {
        let engine = PoSEngine::new(PoSConfig::default(), None);
        let alice = KeyPair::generate().unwrap();
        let alice_addr = Address::from(alice.public_key_bytes());
        let mut state = AccountState::new();
        state.add_validator(alice_addr, 1_000_000);

        let genesis = Block::genesis();
        let mut block = Block::new(1, genesis.hash.clone(), vec![]);
        block.epoch = 0;
        block.slot = 1;
        block.producer = Some(alice_addr);
        block.hash = block.calculate_hash();

        let error = engine
            .validate_block(&block, &[genesis], &state)
            .unwrap_err();
        assert!(
            error.0.contains("Invalid block signature"),
            "unexpected error: {}",
            error.0
        );
    }

    /// BLG-0021: the memory map of seen blocks was pruned to two epochs, but
    /// the SEEN records on disk stayed forever and were all loaded at start.
    #[test]
    fn pruning_seen_blocks_also_removes_the_persisted_records() {
        let config = PoSConfig {
            epoch_length: 4,
            ..PoSConfig::default()
        };
        let engine = PoSEngine::new(config, None);
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::db::Storage::new(dir.path().to_str().unwrap()).unwrap();
        let alice = KeyPair::generate().unwrap();

        let mut old = Block::new(1, "prev".into(), vec![]);
        old.sign(&alice);
        engine.record_block(&old, Some(&storage)).unwrap();
        assert_eq!(storage.load_all_seen_blocks().unwrap().len(), 1);

        let mut recent = Block::new(21, "prev".into(), vec![]);
        recent.sign(&alice);
        engine.record_block(&recent, Some(&storage)).unwrap();

        let on_disk = storage.load_all_seen_blocks().unwrap();
        assert_eq!(on_disk.len(), 1, "the record for height 1 must be gone");
        assert!(on_disk.keys().all(|(_, slot)| *slot == 21));
    }

    /// BLG-0019: a node that is not the leader for the slot drops the block it
    /// tried to build. The evidence in the pool must stay in the pool then.
    #[test]
    fn failed_block_preview_keeps_the_evidence_pool() {
        let engine = PoSEngine::new(PoSConfig::default(), None);
        let alice = KeyPair::generate().unwrap();
        let mut first = Block::new(10, "prev".into(), vec![]);
        first.sign(&alice);
        engine.record_block(&first, None).unwrap();
        let mut rival = Block::new(10, "prev".into(), vec![]);
        rival.timestamp += 1000;
        rival.sign(&alice);
        engine.observe_received_block(&rival).unwrap();
        assert_eq!(engine.slashing_evidence.read().unwrap().len(), 1);

        let genesis = Block::genesis();
        let mut candidate = Block::new(1, genesis.hash.clone(), vec![]);
        let result =
            engine.preview_block_with_chain(&mut candidate, &AccountState::new(), &[genesis]);
        assert!(result.is_err(), "no validator is active, so no leader");
        assert_eq!(
            engine.slashing_evidence.read().unwrap().len(),
            1,
            "a dropped block must not consume the evidence pool"
        );
    }

    /// BLG-0010: a block below the local checkpoint is part of every candidate
    /// chain that honours it. `validate_block` must not reject it for that
    /// reason, or `try_reorg` and `is_valid` fail on block 1.
    #[test]
    fn validate_block_does_not_reject_blocks_below_the_checkpoint() {
        let engine = PoSEngine::new(PoSConfig::default(), None);
        engine
            .add_checkpoint(&Block::new(10, "prev".into(), vec![]), None)
            .unwrap();
        let mut block = Block::new(5, "prev".into(), vec![]);
        block.hash = block.calculate_hash();
        let error = engine
            .validate_block(&block, &[], &AccountState::new())
            .unwrap_err();
        assert!(
            !error.0.contains("checkpoint"),
            "unexpected checkpoint rejection: {}",
            error.0
        );
    }

    #[test]
    fn empty_validator_set_rejects_unsigned_remote_block() {
        let engine = PoSEngine::new(PoSConfig::default(), None);
        let state = AccountState::new();
        let genesis = Block::genesis();
        let mut block = Block::new(1, genesis.hash.clone(), vec![]);
        block.epoch = 0;
        block.slot = 1;
        block.hash = block.calculate_hash();

        let error = engine
            .validate_block(&block, &[genesis], &state)
            .unwrap_err();
        assert!(error.0.contains("No active consensus-ready validators"));
    }

    #[test]
    fn test_minimum_stake() {
        let mut state = AccountState::new();
        let alice = KeyPair::generate().unwrap();
        let alice_addr = Address::from(alice.public_key_bytes());
        state.add_balance(&alice_addr, 2000);

        let config = PoSConfig {
            min_stake: 1000,
            ..Default::default()
        };
        let engine = PoSEngine::new(config, None);

        let tx = create_stake_tx(&alice, 500, 1);
        Executor::apply_transaction(&mut state, &tx).unwrap();

        assert!(!engine.is_validator(&alice_addr, &state));

        let tx2 = create_stake_tx(&alice, 500, 2);
        Executor::apply_transaction(&mut state, &tx2).unwrap();

        // User-approved policy: stake can exist before the validator completes
        // Its consensus key ceremony, but the validator stays bonded/inactive
        // Until VRF + BLS + PoP + PQ are present.
        assert!(!engine.is_validator(&alice_addr, &state));
        let validator = state.get_validator_mut(&alice_addr).unwrap();
        validator.vrf_public_key = vec![1, 2, 3];
        validator.bls_public_key = vec![4, 5, 6];
        validator.pop_signature = vec![7, 8, 9];
        validator.pq_public_key = vec![10, 11, 12];
        validator.active = validator.is_consensus_ready();

        assert!(engine.is_validator(&alice_addr, &state));
    }

    fn synthetic_pos_chain(epoch_length: u64, epoch_count: u64) -> Vec<Block> {
        let chain_id = crate::core::transaction::DEFAULT_CHAIN_ID;
        let mut chain = vec![Block::genesis()];
        let block_count = epoch_length * epoch_count;
        for height in 1..block_count {
            let previous_hash = chain.last().unwrap().hash.clone();
            let mut block = Block::new_with_chain_id(height, previous_hash, vec![], chain_id);
            block.producer = Some(Address::from([height as u8; 32]));
            block.vrf_output = vec![height as u8; 32];
            block.vrf_proof = vec![height as u8; 64];
            block.hash = block.calculate_hash();
            chain.push(block);
        }
        chain
    }

    /// A zero `epoch_length` is a configuration error, not a reason to divide
    /// by zero on the first block that arrives.
    #[test]
    fn zero_epoch_length_is_refused_not_panicked() {
        let engine = PoSEngine::new(
            PoSConfig {
                epoch_length: 0,
                ..Default::default()
            },
            None,
        );
        let chain = synthetic_pos_chain(4, 1);
        let state = AccountState::new();
        let block = chain[1].clone();

        let err = engine
            .validate_block(&block, &chain[..1], &state)
            .expect_err("validation must refuse a zero epoch length");
        assert!(err.0.contains("epoch length"), "{err:?}");
        let err = engine
            .record_block(&block, None)
            .expect_err("recording must refuse a zero epoch length");
        assert!(err.0.contains("epoch length"), "{err:?}");
    }

    #[test]
    fn replay_derived_randomness_resists_header_grinding_and_xor_cancellation() {
        let config = PoSConfig {
            epoch_length: 4,
            ..Default::default()
        };
        let engine = PoSEngine::new(config.clone(), None);
        let chain = synthetic_pos_chain(config.epoch_length, 2);
        let chain_id = crate::core::transaction::DEFAULT_CHAIN_ID;
        let baseline = engine
            .epoch_randomness_from_chain(chain_id, 2, &chain)
            .unwrap();

        let mut header_variant = chain.clone();
        header_variant[1].timestamp = header_variant[1].timestamp.saturating_add(999);
        header_variant[1].tx_root = "grindable transaction ordering".into();
        header_variant[1].hash = "grindable header hash".into();
        assert_eq!(
            engine
                .epoch_randomness_from_chain(chain_id, 2, &header_variant)
                .unwrap(),
            baseline
        );

        // The two transcripts below have the same byte-wise XOR (1^2 == 0^3),
        // But their ordered VRF commitments must produce different randomness.
        let mut same_xor_variant = chain.clone();
        same_xor_variant[1].vrf_output = vec![0; 32];
        same_xor_variant[2].vrf_output = vec![3; 32];
        assert_ne!(
            engine
                .epoch_randomness_from_chain(chain_id, 2, &same_xor_variant)
                .unwrap(),
            baseline
        );
    }

    #[test]
    fn replay_derived_randomness_is_stable_across_restart_and_ignores_recent_epoch() {
        let config = PoSConfig {
            epoch_length: 4,
            ..Default::default()
        };
        let chain_id = crate::core::transaction::DEFAULT_CHAIN_ID;
        let chain = synthetic_pos_chain(config.epoch_length, 2);
        let before_restart = PoSEngine::new(config.clone(), None)
            .calculate_seed_with_chain(chain_id, 2, 8, 0, &chain)
            .unwrap();
        let after_restart = PoSEngine::new(config.clone(), None)
            .calculate_seed_with_chain(chain_id, 2, 8, 0, &chain)
            .unwrap();
        assert_eq!(before_restart, after_restart);

        let mut recent_epoch_variant = chain.clone();
        for block in &mut recent_epoch_variant[4..8] {
            block.vrf_output.fill(0xEE);
            block.hash = format!("alternate-recent-epoch-{}", block.index);
        }
        assert_eq!(
            PoSEngine::new(config, None)
                .calculate_seed_with_chain(chain_id, 2, 8, 0, &recent_epoch_variant)
                .unwrap(),
            before_restart
        );
    }

    /// F-184/185/186: the consensus penalty constants are integer
    /// fixed-point, not f64 expressions. P01-F21 removed the never-read
    /// `PoSConfig` knobs this used to assert on; the live constants are the
    /// `RegistryParams` slash ratios, which are what is pinned now.
    #[test]
    fn pos_default_fixed_point_constants_are_exact_integers() {
        use crate::core::chain_config::FIXED_POINT_SCALE;
        let params = crate::registry::params::RegistryParams::default();
        assert_eq!(params.double_sign_slash_ratio_fixed, FIXED_POINT_SCALE / 2);
        assert_eq!(params.liveness_slash_ratio_fixed, FIXED_POINT_SCALE / 100);
        assert_eq!(params.malicious_slash_ratio_fixed, FIXED_POINT_SCALE);
    }
    #[test]
    fn pos_vrf_threshold_widens_with_the_round() {
        let engine = PoSEngine::new(PoSConfig::default(), None);
        let base = engine.calculate_vrf_threshold_for_round(1_000, 4_000, 0);
        let round1 = engine.calculate_vrf_threshold_for_round(1_000, 4_000, 1);
        let round_cap = engine.calculate_vrf_threshold_for_round(1_000, 4_000, MAX_LEADER_ROUNDS);
        assert_eq!(
            round1,
            base.saturating_mul(2),
            "round 1 must double the threshold (P01-F01)"
        );
        assert_eq!(
            round_cap,
            base.saturating_mul(MAX_LEADER_ROUNDS + 1),
            "the cap round must price at (cap + 1)x"
        );
    }
}
