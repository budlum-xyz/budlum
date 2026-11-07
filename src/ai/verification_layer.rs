//! AI Verification Layer (Section 10.6).
//!
//! Implements the post-launch verification pipeline above `AiRegistry`:
//! 1. `ModelRecordV2` binding `weights_root` and a Deterministic Inference
//!    Profile (`DIP`) digest into proofs.
//! 2. Epoch `e + 1` stake-weighted integer committee lottery (`n = 5`, `k = 4`),
//!    salted commit-reveal with anti-copying and missed-reveal slashing, and
//!    second-committee statistical sampling (`1%`).
//! 3. Interactive bisection dispute game (`<= 32` rounds) isolating a single
//!    `64 x 64` fixed-point tile step proven and audited deterministically.
//! 4. Small-model bit-exact VM/host equivalence, weights-root binding, VM
//!    journal digest binding, request anti-replay, and deferred
//!    `InferenceAssumption` discharge.
//!
//! WIRING: unwired - post-launch T-Expansion AI Verification Layer;
//! closed until governance activates VL-2/VL-3 dispute and proof doors.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::execution::{
    eval_fixed_point_mlp, input_commitment, matmul_program_hash, output_commitment,
    run_matmul_guest, FixedPointMlpSpec,
};
use super::types::{AiModelId, AiRequestId};
use super::verification_level::{LevelRecord, LevelRefusal, VerificationLevel};
use crate::core::address::Address;

/// TESTNET-DEFAULT committee size (`n = 5`).
pub const DEFAULT_COMMITTEE_SIZE: usize = 5;
/// TESTNET-DEFAULT agreement threshold (`k = 4`).
pub const DEFAULT_QUORUM_THRESHOLD: usize = 4;
/// TESTNET-DEFAULT challenge window length in blocks (`100`).
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 100;
/// TESTNET-DEFAULT second-committee sampling rate in basis points (`100` = 1%).
pub const DEFAULT_SAMPLING_RATE_BPS: u64 = 100;
/// Tile dimension for single-step matmul disputes (`64 x 64`).
pub const TILE_DIM: usize = 64;
/// Number of `i32` cells in one `64 x 64` tile (`4096`).
pub const TILE_CELLS: usize = TILE_DIM * TILE_DIM;
/// Hard ceiling on interactive bisection rounds (`2^32` steps).
pub const MAX_BISECTION_ROUNDS: u32 = 32;

/// Domain tag for `ModelRecordV2` weights root.
pub const MODEL_WEIGHTS_ROOT_TAG: &[u8] = b"BDLM_AI_MODEL_WEIGHTS_ROOT_V2";
/// Domain tag for `DeterministicInferenceProfile` commitments.
pub const DIP_PROFILE_TAG: &[u8] = b"BDLM_AI_DIP_PROFILE_V1";
/// Domain tag for epoch `e + 1` committee lottery draws.
pub const LOTTERY_TAG: &[u8] = b"BDLM_AI_LOTTERY_V1";
/// Domain tag for committee commit-reveal hashes.
pub const COMMIT_VOTE_TAG: &[u8] = b"BDLM_AI_COMMIT_VOTE_V1";
/// Domain tag for second-committee statistical sampling.
pub const SAMPLING_AUDIT_TAG: &[u8] = b"BDLM_AI_SAMPLING_AUDIT_V1";
/// Domain tag for `64 x 64` tile step commitments.
pub const TILE64_PROOF_TAG: &[u8] = b"BDLM_AI_TILE64_PROOF_V1";
/// Domain tag for request-bound small-model full proofs.
pub const BOUND_PROOF_TAG: &[u8] = b"BDLM_AI_BOUND_PROOF_V1";

/// Errors returned by the AI Verification Layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationLayerError {
    /// Committee cannot be drawn until randomness from `request_epoch + 1` is
    /// available .
    FutureEpochRandomnessRequired {
        request_epoch: u64,
        randomness_epoch: u64,
    },
    /// Not enough staked verifiers to fill `committee_size`.
    InsufficientCandidates { available: usize, required: usize },
    /// Account is not a member of the drawn committee.
    NotCommitteeMember(Address),
    /// Commit or reveal arrived outside its block window.
    PhaseClosed,
    /// Reveal hash did not match the committed digest.
    RevealHashMismatch,
    /// Verification level transition violated monotonicity .
    LevelTransition(LevelRefusal),
    /// DIP or MLP evaluation failed validation.
    InvalidModelOrInput(String),
    /// Tile buffer length does not equal [`TILE_CELLS`].
    InvalidTileShape { got: usize },
    /// Bisection bounds are invalid or exceeded [`MAX_BISECTION_ROUNDS`].
    InvalidBisectionState(&'static str),
    /// Host evaluator and in-VM guest disagreed.
    HostGuestMismatch,
}

/// Deterministic Inference Profile (DIP, Section 10.6 item 5).
///
/// Captures every parameter that affects numerical bit-exactness across
/// `x86_64` and `aarch64`. Host hardware vendor strings are intentionally
/// excluded so honest heterogeneous hardware produces identical commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicInferenceProfile {
    /// Integer quantization width in bits (for example `8` or `16`).
    pub quantization_bits: u8,
    /// Fixed-point right-shift applied after integer MAC reduction.
    pub fixed_scale_shift: u8,
    /// Fixed sampling seed (`0` for greedy argmax).
    pub sampling_seed: u64,
    /// Canonical SHA-256 digest of the tokenizer vocabulary and merge table.
    pub tokenizer_digest: [u8; 32],
    /// Canonical SHA-256 digest of the deterministic kernel runtime build.
    pub runtime_digest: [u8; 32],
}

impl DeterministicInferenceProfile {
    /// Canonical SHA-256 digest of the deterministic profile.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DIP_PROFILE_TAG);
        h.update([self.quantization_bits, self.fixed_scale_shift]);
        h.update(self.sampling_seed.to_le_bytes());
        h.update(self.tokenizer_digest);
        h.update(self.runtime_digest);
        h.finalize().into()
    }
}

/// Model registration V2 binding `weights_root`, `dip_digest`, and guest
/// `program_hash` (Step 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRecordV2 {
    /// Canonical model identifier.
    pub model_id: AiModelId,
    /// Schema version (`2`).
    pub version: u32,
    /// Merkle/chunk commitment over quantized weights and biases.
    pub weights_root: [u8; 32],
    /// Digest of the [`DeterministicInferenceProfile`].
    pub dip_digest: [u8; 32],
    /// BudZero guest program hash for small-model proving.
    pub program_hash: [u8; 32],
}

impl ModelRecordV2 {
    /// Build a V2 model record from a validated [`FixedPointMlpSpec`] and DIP.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationLayerError::InvalidModelOrInput`] if `spec` fails
    /// validation.
    pub fn from_mlp_spec(
        model_id: AiModelId,
        spec: &FixedPointMlpSpec,
        dip: &DeterministicInferenceProfile,
    ) -> Result<Self, VerificationLayerError> {
        let program_hash = matmul_program_hash(spec)
            .map_err(VerificationLayerError::InvalidModelOrInput)?;
        Ok(Self {
            model_id,
            version: 2,
            weights_root: compute_weights_root(spec),
            dip_digest: dip.digest(),
            program_hash,
        })
    }
}

/// Canonical chunked Merkle commitment over `spec.dims`, `spec.weights`, and
/// `spec.biases`.
#[must_use]
pub fn compute_weights_root(spec: &FixedPointMlpSpec) -> [u8; 32] {
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    for (chunk_idx, chunk) in spec.weights.chunks(64).enumerate() {
        let mut h = Sha256::new();
        h.update(MODEL_WEIGHTS_ROOT_TAG);
        h.update(b"W");
        h.update((chunk_idx as u64).to_le_bytes());
        for w in chunk {
            h.update(w.to_le_bytes());
        }
        leaves.push(h.finalize().into());
    }
    let mut bias_h = Sha256::new();
    bias_h.update(MODEL_WEIGHTS_ROOT_TAG);
    bias_h.update(b"B");
    for d in &spec.dims {
        bias_h.update(d.to_le_bytes());
    }
    for b in &spec.biases {
        bias_h.update(b.to_le_bytes());
    }
    leaves.push(bias_h.finalize().into());
    fold_merkle_leaves(&leaves)
}

fn fold_merkle_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair.first().copied().unwrap_or([0u8; 32]);
            let right = pair.get(1).copied().unwrap_or(left);
            let mut h = Sha256::new();
            h.update(MODEL_WEIGHTS_ROOT_TAG);
            h.update(b"N");
            h.update(left);
            h.update(right);
            next.push(h.finalize().into());
        }
        level = next;
    }
    level.first().copied().unwrap_or([0u8; 32])
}

/// Evaluate a deterministic quantized forward pass under `dip`.
///
/// Uses strictly ordered integer `i64` accumulation, symmetrical quantization
/// clamping, and fixed-point shift `dip.fixed_scale_shift`. Zero floating-point
/// operations are executed so `x86_64` and `aarch64` are bit-identical .
///
/// # Errors
///
/// Refuses invalid quantization bit widths or mismatched input dimensions.
pub fn eval_dip_inference(
    dip: &DeterministicInferenceProfile,
    spec: &FixedPointMlpSpec,
    prompt_tokens: &[i32],
) -> Result<(Vec<i32>, [u8; 32]), VerificationLayerError> {
    if dip.quantization_bits == 0 || dip.quantization_bits > 31 {
        return Err(VerificationLayerError::InvalidModelOrInput(
            "quantization_bits must be in 1..=31".to_owned(),
        ));
    }
    spec.validate()
        .map_err(VerificationLayerError::InvalidModelOrInput)?;
    let in_dim = usize::from(spec.dims.first().copied().unwrap_or(0));
    if prompt_tokens.len() != in_dim {
        return Err(VerificationLayerError::InvalidModelOrInput(
            "prompt_tokens length mismatch".to_owned(),
        ));
    }

    let q_max = (1i64 << (dip.quantization_bits - 1)) - 1;
    let q_min = -(1i64 << (dip.quantization_bits - 1));
    let quantize = |v: i64| -> i32 { v.clamp(q_min, q_max) as i32 };

    let mut current: Vec<i32> = prompt_tokens
        .iter()
        .map(|t| quantize(i64::from(*t)))
        .collect();
    let mut w_offset = 0usize;
    let mut b_offset = 0usize;
    let num_layers = spec.dims.len().saturating_sub(1);

    for (layer_idx, win) in spec.dims.windows(2).enumerate() {
        let d_in = usize::from(win.first().copied().unwrap_or(0));
        let d_out = usize::from(win.get(1).copied().unwrap_or(0));
        let mut next = Vec::with_capacity(d_out);
        for o in 0..d_out {
            let bias = i64::from(spec.biases.get(b_offset + o).copied().unwrap_or(0));
            // Strictly sequential index 0..d_in reduction (no SIMD lane reorder,
            // no batch mixing).
            let mut acc = bias;
            for i in 0..d_in {
                let w = i64::from(
                    spec.weights
                        .get(w_offset + o * d_in + i)
                        .copied()
                        .unwrap_or(0),
                );
                let x = i64::from(current.get(i).copied().unwrap_or(0));
                acc = acc.saturating_add(w.saturating_mul(x));
            }
            let shifted = acc >> u32::from(dip.fixed_scale_shift.min(30));
            let mut q = quantize(shifted);
            if layer_idx + 1 < num_layers && q < 0 {
                q = 0;
            }
            next.push(q);
        }
        w_offset = w_offset.saturating_add(d_in * d_out);
        b_offset = b_offset.saturating_add(d_out);
        current = next;
    }

    let mut trace_h = Sha256::new();
    trace_h.update(DIP_PROFILE_TAG);
    trace_h.update(dip.digest());
    trace_h.update(compute_weights_root(spec));
    for tok in prompt_tokens {
        trace_h.update(tok.to_le_bytes());
    }
    for y in &current {
        trace_h.update(y.to_le_bytes());
    }
    Ok((current, trace_h.finalize().into()))
}

/// Draw a stake-weighted committee using integer arithmetic from epoch `e + 1`
/// randomness (Section 10.6 item 4).
///
/// # Errors
///
/// Refuses any randomness from an epoch `<= request_epoch` so the requester and
/// verifiers cannot predict the committee at request submission time.
pub fn draw_committee_for_request(
    request_id: &AiRequestId,
    request_epoch: u64,
    randomness_epoch: u64,
    epoch_randomness: &[u8; 32],
    staked_candidates: &[(Address, u64)],
    committee_size: usize,
) -> Result<Vec<Address>, VerificationLayerError> {
    if randomness_epoch <= request_epoch {
        return Err(VerificationLayerError::FutureEpochRandomnessRequired {
            request_epoch,
            randomness_epoch,
        });
    }
    let mut pool: Vec<(Address, u64)> = staked_candidates
        .iter()
        .copied()
        .filter(|(_, stake)| *stake > 0)
        .collect();
    pool.sort_by_key(|(addr, _)| *addr);
    pool.dedup_by_key(|(addr, _)| *addr);

    if pool.len() < committee_size {
        return Err(VerificationLayerError::InsufficientCandidates {
            available: pool.len(),
            required: committee_size,
        });
    }

    let mut selected = Vec::with_capacity(committee_size);
    for draw_idx in 0..committee_size {
        let total_stake: u128 = pool.iter().map(|(_, s)| u128::from(*s)).sum();
        if total_stake == 0 {
            break;
        }
        let mut h = Sha256::new();
        h.update(LOTTERY_TAG);
        h.update(epoch_randomness);
        h.update(randomness_epoch.to_le_bytes());
        h.update(request_id.0);
        h.update((draw_idx as u64).to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let mut raw_u128 = [0u8; 16];
        if let Some(prefix) = digest.get(..16) {
            raw_u128.copy_from_slice(prefix);
        }
        let target = u128::from_le_bytes(raw_u128) % total_stake;

        let mut cumulative = 0u128;
        let mut chosen_pos = 0usize;
        for (pos, (_, stake)) in pool.iter().enumerate() {
            cumulative = cumulative.saturating_add(u128::from(*stake));
            if target < cumulative {
                chosen_pos = pos;
                break;
            }
        }
        let (winner, _) = pool.remove(chosen_pos);
        selected.push(winner);
    }
    Ok(selected)
}

/// Compute a committee member's salted vote commitment.
#[must_use]
pub fn compute_vote_commitment(
    request_id: &AiRequestId,
    member: &Address,
    result_digest: &[u8; 32],
    salt: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMIT_VOTE_TAG);
    h.update(request_id.0);
    h.update(member.as_bytes());
    h.update(result_digest);
    h.update(salt);
    h.finalize().into()
}

/// Offense recorded during commit-reveal committee attestation .
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SlashOffense {
    /// Member submitted a commitment hash identical to another member's commit.
    CopiedCommitment,
    /// Member revealed a value that could not have generated its own bound
    /// commitment, or copied another member's reveal without salt knowledge.
    InvalidReveal,
    /// Drawn committee member failed to reveal before `reveal_deadline_block`.
    MissedReveal,
}

/// Commit-reveal attestation session for one AI inference request.
#[derive(Debug, Clone)]
pub struct CommitRevealSession {
    pub request_id: AiRequestId,
    pub committee: BTreeSet<Address>,
    pub quorum_threshold: usize,
    pub commit_deadline_block: u64,
    pub reveal_deadline_block: u64,
    pub challenge_deadline_block: u64,
    commits: BTreeMap<Address, [u8; 32]>,
    reveals: BTreeMap<Address, [u8; 32]>,
    pub slashed: Vec<(Address, SlashOffense)>,
    pub level: LevelRecord,
    pub agreed_digest: Option<[u8; 32]>,
}

impl CommitRevealSession {
    /// Start a commit-reveal session for `committee`.
    #[must_use]
    pub fn new(
        request_id: AiRequestId,
        committee: Vec<Address>,
        quorum_threshold: usize,
        start_block: u64,
        commit_blocks: u64,
        reveal_blocks: u64,
        challenge_window_blocks: u64,
    ) -> Self {
        let commit_deadline_block = start_block.saturating_add(commit_blocks);
        let reveal_deadline_block = commit_deadline_block.saturating_add(reveal_blocks);
        let challenge_deadline_block =
            reveal_deadline_block.saturating_add(challenge_window_blocks);
        Self {
            request_id,
            committee: committee.into_iter().collect(),
            quorum_threshold: quorum_threshold.max(1),
            commit_deadline_block,
            reveal_deadline_block,
            challenge_deadline_block,
            commits: BTreeMap::new(),
            reveals: BTreeMap::new(),
            slashed: Vec::new(),
            level: LevelRecord::new(),
            agreed_digest: None,
        }
    }

    /// Submit a salted vote commitment before `commit_deadline_block`.
    ///
    /// Copying another member's commitment bytes is immediately flagged and
    /// penalized because honest commitments bind `member.as_bytes()`.
    ///
    /// # Errors
    ///
    /// Refuses non-committee members or late commits.
    pub fn submit_commit(
        &mut self,
        member: Address,
        commitment: [u8; 32],
        block_height: u64,
    ) -> Result<(), VerificationLayerError> {
        if !self.committee.contains(&member) {
            return Err(VerificationLayerError::NotCommitteeMember(member));
        }
        if block_height > self.commit_deadline_block {
            return Err(VerificationLayerError::PhaseClosed);
        }
        let copied = self
            .commits
            .iter()
            .any(|(other, hash)| *other != member && *hash == commitment);
        if copied {
            self.slashed.push((member, SlashOffense::CopiedCommitment));
            return Ok(());
        }
        self.commits.insert(member, commitment);
        Ok(())
    }

    /// Reveal `(result_digest, salt)` during `(commit_deadline_block, reveal_deadline_block]`.
    ///
    /// # Errors
    ///
    /// Slashes and returns [`VerificationLayerError::RevealHashMismatch`] if the
    /// member tries to reveal a copied digest that does not match its own bound
    /// commitment.
    pub fn submit_reveal(
        &mut self,
        member: Address,
        result_digest: [u8; 32],
        salt: [u8; 32],
        block_height: u64,
    ) -> Result<(), VerificationLayerError> {
        if !self.committee.contains(&member) {
            return Err(VerificationLayerError::NotCommitteeMember(member));
        }
        if block_height <= self.commit_deadline_block
            || block_height > self.reveal_deadline_block
        {
            return Err(VerificationLayerError::PhaseClosed);
        }
        let Some(committed) = self.commits.get(&member).copied() else {
            return Err(VerificationLayerError::PhaseClosed);
        };
        let expected = compute_vote_commitment(&self.request_id, &member, &result_digest, &salt);
        if expected != committed {
            self.slashed.push((member, SlashOffense::InvalidReveal));
            return Err(VerificationLayerError::RevealHashMismatch);
        }
        self.reveals.insert(member, result_digest);
        Ok(())
    }

    /// Close the reveal phase after `reveal_deadline_block`, penalizing every
    /// committee member who failed to reveal and promoting the outcome to
    /// `VL-1` (`CommitteeAgreement`) if `quorum_threshold` members agreed.
    ///
    /// # Errors
    ///
    /// Refuses calls before `reveal_deadline_block` has passed.
    pub fn finalize_reveal_phase(
        &mut self,
        block_height: u64,
    ) -> Result<Option<[u8; 32]>, VerificationLayerError> {
        if block_height <= self.reveal_deadline_block {
            return Err(VerificationLayerError::PhaseClosed);
        }
        let already_slashed: BTreeSet<Address> =
            self.slashed.iter().map(|(addr, _)| *addr).collect();
        for member in &self.committee {
            if !self.reveals.contains_key(member) && !already_slashed.contains(member) {
                self.slashed.push((*member, SlashOffense::MissedReveal));
            }
        }

        let mut tallies: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        for digest in self.reveals.values() {
            let entry = tallies.entry(*digest).or_insert(0);
            *entry = entry.saturating_add(1);
        }
        let winner = tallies
            .into_iter()
            .find(|(_, count)| *count >= self.quorum_threshold)
            .map(|(digest, _)| digest);
        if let Some(digest) = winner {
            self.level
                .raise(VerificationLevel::CommitteeAgreement)
                .map_err(VerificationLayerError::LevelTransition)?;
            self.agreed_digest = Some(digest);
        }
        Ok(self.agreed_digest)
    }

    /// Promote a `VL-1` outcome to `VL-2` (`ChallengeWindowClosed`) once
    /// `challenge_deadline_block` passes without refutation.
    ///
    /// # Errors
    ///
    /// Refuses promotion before the challenge window closes or when refuted.
    pub fn close_challenge_window(
        &mut self,
        block_height: u64,
    ) -> Result<VerificationLevel, VerificationLayerError> {
        if block_height <= self.challenge_deadline_block || self.agreed_digest.is_none() {
            return Err(VerificationLayerError::PhaseClosed);
        }
        self.level
            .raise(VerificationLevel::ChallengeWindowClosed)
            .map_err(VerificationLayerError::LevelTransition)?;
        Ok(self.level.level())
    }
}

/// Deterministic statistical draw for second-committee audit (Step 4).
#[must_use]
pub fn should_sample_for_second_committee(
    request_id: &AiRequestId,
    epoch_randomness: &[u8; 32],
    sampling_rate_bps: u64,
) -> bool {
    if sampling_rate_bps == 0 {
        return false;
    }
    if sampling_rate_bps >= 10_000 {
        return true;
    }
    let mut h = Sha256::new();
    h.update(SAMPLING_AUDIT_TAG);
    h.update(epoch_randomness);
    h.update(request_id.0);
    let digest: [u8; 32] = h.finalize().into();
    let mut limb = [0u8; 8];
    if let Some(prefix) = digest.get(..8) {
        limb.copy_from_slice(prefix);
    }
    (u64::from_le_bytes(limb) % 10_000) < sampling_rate_bps
}

/// Interactive bisection game over `total_steps` execution checkpoints (Step 3,
/// verification invariant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputeBisectionGame {
    pub left_step: u64,
    pub right_step: u64,
    pub rounds_used: u32,
}

impl DisputeBisectionGame {
    /// Open a dispute over `[0, total_steps]`, where step `0` is the agreed
    /// initial input commitment and `total_steps >= 1` is the disputed final
    /// checkpoint.
    ///
    /// # Errors
    ///
    /// Refuses `total_steps == 0`.
    pub fn new(total_steps: u64) -> Result<Self, VerificationLayerError> {
        if total_steps == 0 {
            return Err(VerificationLayerError::InvalidBisectionState(
                "total_steps must be >= 1",
            ));
        }
        Ok(Self {
            left_step: 0,
            right_step: total_steps,
            rounds_used: 0,
        })
    }

    /// True once bisection has narrowed disagreement to the single transition
    /// `left_step -> right_step` (`right_step == left_step + 1`).
    #[must_use]
    pub const fn is_converged(&self) -> bool {
        self.right_step.saturating_sub(self.left_step) <= 1
    }

    /// Midpoint queried in the next bisection round.
    #[must_use]
    pub const fn midpoint(&self) -> u64 {
        self.left_step + (self.right_step - self.left_step) / 2
    }

    /// Advance one bisection step by comparing defender's midpoint checkpoint
    /// against challenger's midpoint checkpoint.
    ///
    /// # Errors
    ///
    /// Refuses calls after convergence or beyond [`MAX_BISECTION_ROUNDS`].
    pub fn advance_bisection(
        &mut self,
        defender_mid: &[u8; 32],
        challenger_mid: &[u8; 32],
    ) -> Result<(), VerificationLayerError> {
        if self.is_converged() {
            return Err(VerificationLayerError::InvalidBisectionState(
                "bisection already converged",
            ));
        }
        if self.rounds_used >= MAX_BISECTION_ROUNDS {
            return Err(VerificationLayerError::InvalidBisectionState(
                "bisection exceeded MAX_BISECTION_ROUNDS",
            ));
        }
        let mid = self.midpoint();
        if defender_mid == challenger_mid {
            self.left_step = mid;
        } else {
            self.right_step = mid;
        }
        self.rounds_used = self.rounds_used.saturating_add(1);
        Ok(())
    }
}

/// Single-step proof over one `64 x 64` fixed-point tile multiplication
/// (`C = A * B`, Step 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tile64x64Proof {
    pub a_root: [u8; 32],
    pub b_root: [u8; 32],
    pub c_root: [u8; 32],
    pub c_cells: Vec<i64>,
    pub transcript_digest: [u8; 32],
}

fn commit_tile_i32(label: &[u8], cells: &[i32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TILE64_PROOF_TAG);
    h.update(label);
    for v in cells {
        h.update(v.to_le_bytes());
    }
    h.finalize().into()
}

fn commit_tile_i64(label: &[u8], cells: &[i64]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TILE64_PROOF_TAG);
    h.update(label);
    for v in cells {
        h.update(v.to_le_bytes());
    }
    h.finalize().into()
}

/// Deterministically execute and commit a `64 x 64` integer tile matmul.
///
/// # Errors
///
/// Returns [`VerificationLayerError::InvalidTileShape`] if `a_cells` or
/// `b_cells` does not have length `4096`.
pub fn prove_tile_64x64(
    a_cells: &[i32],
    b_cells: &[i32],
) -> Result<Tile64x64Proof, VerificationLayerError> {
    if a_cells.len() != TILE_CELLS {
        return Err(VerificationLayerError::InvalidTileShape { got: a_cells.len() });
    }
    if b_cells.len() != TILE_CELLS {
        return Err(VerificationLayerError::InvalidTileShape { got: b_cells.len() });
    }
    let mut c_cells = vec![0i64; TILE_CELLS];
    for row in 0..TILE_DIM {
        for col in 0..TILE_DIM {
            let mut acc = 0i64;
            for k in 0..TILE_DIM {
                let a = i64::from(a_cells.get(row * TILE_DIM + k).copied().unwrap_or(0));
                let b = i64::from(b_cells.get(k * TILE_DIM + col).copied().unwrap_or(0));
                acc = acc.saturating_add(a.saturating_mul(b));
            }
            if let Some(slot) = c_cells.get_mut(row * TILE_DIM + col) {
                *slot = acc;
            }
        }
    }
    let a_root = commit_tile_i32(b"A", a_cells);
    let b_root = commit_tile_i32(b"B", b_cells);
    let c_root = commit_tile_i64(b"C", &c_cells);
    let mut tr = Sha256::new();
    tr.update(TILE64_PROOF_TAG);
    tr.update(b"TRANSCRIPT");
    tr.update(a_root);
    tr.update(b_root);
    tr.update(c_root);
    Ok(Tile64x64Proof {
        a_root,
        b_root,
        c_root,
        c_cells,
        transcript_digest: tr.finalize().into(),
    })
}

/// Audit a [`Tile64x64Proof`] against `a_cells` and `b_cells`.
#[must_use]
pub fn is_valid_tile_64x64_proof(
    proof: &Tile64x64Proof,
    a_cells: &[i32],
    b_cells: &[i32],
) -> bool {
    let Ok(expected) = prove_tile_64x64(a_cells, b_cells) else {
        return false;
    };
    proof == &expected
}

/// Request-bound small-model full proof tying `request_id`, `ModelRecordV2`,
/// VM execution journal log, and bit-exact output commitment together
/// (Step 5s).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmallModelBoundProof {
    pub request_id: AiRequestId,
    pub model_id: AiModelId,
    pub weights_root: [u8; 32],
    pub program_hash: [u8; 32],
    pub input_commit: [u8; 32],
    pub output_commit: [u8; 32],
    pub output_limbs: Vec<i32>,
    pub vm_journal_word: u64,
    pub journal_derived_commit: [u8; 32],
    pub proof_binding: [u8; 32],
}

fn derive_journal_output_commit(vm_journal_word: u64, output_limbs: &[i32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BOUND_PROOF_TAG);
    h.update(b"JOURNAL");
    h.update(vm_journal_word.to_le_bytes());
    h.update(output_commitment(output_limbs));
    h.finalize().into()
}

fn compute_proof_binding(
    request_id: &AiRequestId,
    model_id: &AiModelId,
    weights_root: &[u8; 32],
    program_hash: &[u8; 32],
    input_commit: &[u8; 32],
    journal_derived_commit: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BOUND_PROOF_TAG);
    h.update(request_id.0);
    h.update(model_id.0);
    h.update(weights_root);
    h.update(program_hash);
    h.update(input_commit);
    h.update(journal_derived_commit);
    h.finalize().into()
}

/// Execute `spec` in both the host evaluator and `bud_vm::Vm`, verify bit-exact
/// equivalence , and emit a [`SmallModelBoundProof`] bound to
/// `request_id`, `model.weights_root`, and the VM execution log.
///
/// # Errors
///
/// Returns [`VerificationLayerError`] if model validation fails or if host and
/// guest outputs diverge.
pub fn prove_small_model_bound(
    request_id: AiRequestId,
    model: &ModelRecordV2,
    spec: &FixedPointMlpSpec,
    input: &[i32],
) -> Result<SmallModelBoundProof, VerificationLayerError> {
    let actual_weights_root = compute_weights_root(spec);
    if actual_weights_root != model.weights_root {
        return Err(VerificationLayerError::InvalidModelOrInput(
            "weights_root does not match registered ModelRecordV2".to_owned(),
        ));
    }
    let host_out = eval_fixed_point_mlp(spec, input)
        .map_err(VerificationLayerError::InvalidModelOrInput)?;
    let (guest_out, receipt) = run_matmul_guest(spec, input, 500_000)
        .map_err(VerificationLayerError::InvalidModelOrInput)?;
    if host_out != guest_out {
        return Err(VerificationLayerError::HostGuestMismatch);
    }
    let Some(vm_journal_word) = receipt.logs.first().copied() else {
        return Err(VerificationLayerError::InvalidModelOrInput(
            "empty VM log".to_owned(),
        ));
    };
    let input_commit = input_commitment(input);
    let output_commit = output_commitment(&guest_out);
    let journal_derived_commit = derive_journal_output_commit(vm_journal_word, &guest_out);
    let proof_binding = compute_proof_binding(
        &request_id,
        &model.model_id,
        &model.weights_root,
        &model.program_hash,
        &input_commit,
        &journal_derived_commit,
    );
    Ok(SmallModelBoundProof {
        request_id,
        model_id: model.model_id,
        weights_root: model.weights_root,
        program_hash: model.program_hash,
        input_commit,
        output_commit,
        output_limbs: guest_out,
        vm_journal_word,
        journal_derived_commit,
        proof_binding,
    })
}

/// Audit a [`SmallModelBoundProof`] against `(expected_request_id, model, spec, input)`.
#[must_use]
pub fn is_valid_small_model_bound_proof(
    proof: &SmallModelBoundProof,
    expected_request_id: &AiRequestId,
    model: &ModelRecordV2,
    spec: &FixedPointMlpSpec,
    input: &[i32],
) -> bool {
    if &proof.request_id != expected_request_id || proof.model_id != model.model_id {
        return false;
    }
    if proof.weights_root != model.weights_root
        || compute_weights_root(spec) != model.weights_root
    {
        return false;
    }
    if proof.program_hash != model.program_hash {
        return false;
    }
    if proof.input_commit != input_commitment(input) {
        return false;
    }
    let Ok((guest_out, receipt)) = run_matmul_guest(spec, input, 500_000) else {
        return false;
    };
    let Some(expected_log) = receipt.logs.first().copied() else {
        return false;
    };
    if proof.output_limbs != guest_out || proof.vm_journal_word != expected_log {
        return false;
    }
    if proof.output_commit != output_commitment(&guest_out) {
        return false;
    }
    let expected_journal_commit = derive_journal_output_commit(expected_log, &guest_out);
    if proof.journal_derived_commit != expected_journal_commit {
        return false;
    }
    let expected_binding = compute_proof_binding(
        expected_request_id,
        &model.model_id,
        &model.weights_root,
        &model.program_hash,
        &proof.input_commit,
        &expected_journal_commit,
    );
    proof.proof_binding == expected_binding
}

/// Deferred assumption emitted by `VerifyInference` until recursive aggregation
/// discharges it (Step 6, Section 10.6 item 8).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InferenceAssumption {
    pub request_id: AiRequestId,
    pub model_id: AiModelId,
    pub weights_root: [u8; 32],
    pub input_commit: [u8; 32],
    pub output_commit: [u8; 32],
}

/// Tracks open `VerifyInference` assumptions and discharges them when matching
/// `VL-3` full proofs are aggregated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InferenceAssumptionPool {
    pending: BTreeSet<InferenceAssumption>,
}

impl InferenceAssumptionPool {
    /// Record an assumption emitted by a guest execution.
    pub fn record_assumption(&mut self, assumption: InferenceAssumption) {
        self.pending.insert(assumption);
    }

    /// Discharge a matching assumption using a verified [`SmallModelBoundProof`].
    pub fn discharge_with_proof(
        &mut self,
        proof: &SmallModelBoundProof,
        model: &ModelRecordV2,
        spec: &FixedPointMlpSpec,
        input: &[i32],
    ) -> bool {
        if !is_valid_small_model_bound_proof(proof, &proof.request_id, model, spec, input) {
            return false;
        }
        let target = InferenceAssumption {
            request_id: proof.request_id,
            model_id: proof.model_id,
            weights_root: proof.weights_root,
            input_commit: proof.input_commit,
            output_commit: proof.output_commit,
        };
        self.pending.remove(&target)
    }

    /// True iff all recorded inference assumptions have been discharged.
    #[must_use]
    pub fn is_fully_discharged(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dip() -> DeterministicInferenceProfile {
        DeterministicInferenceProfile {
            quantization_bits: 16,
            fixed_scale_shift: 2,
            sampling_seed: 42,
            tokenizer_digest: [0x11; 32],
            runtime_digest: [0x22; 32],
        }
    }

    fn sample_mlp() -> FixedPointMlpSpec {
        FixedPointMlpSpec {
            dims: vec![4, 4, 2],
            weights: vec![
                2, -1, 3, 1, // h0
                -2, 4, 1, 2, // h1
                1, 1, -3, 2, // h2
                3, 0, 2, -1, // h3
                2, 1, -1, 3, // y0
                -1, 2, 4, 1, // y1
            ],
            biases: vec![1, -1, 2, 0, 3, -2],
        }
    }

    /// seed comes from epoch `e + 1` randomness; committee cannot be
    /// computed in epoch `e`.
    #[test]
    fn committee_requires_next_epoch_randomness() {
        let req_id = AiRequestId([0xAA; 32]);
        let candidates: Vec<(Address, u64)> = (1u8..=8)
            .map(|i| (Address::from_bytes([i; 20]), u64::from(i) * 1_000))
            .collect();

        assert_eq!(
            draw_committee_for_request(&req_id, 10, 10, &[0x99; 32], &candidates, 5),
            Err(VerificationLayerError::FutureEpochRandomnessRequired {
                request_epoch: 10,
                randomness_epoch: 10,
            })
        );
        assert_eq!(
            draw_committee_for_request(&req_id, 10, 9, &[0x99; 32], &candidates, 5),
            Err(VerificationLayerError::FutureEpochRandomnessRequired {
                request_epoch: 10,
                randomness_epoch: 9,
            })
        );

        let seed = [0x99; 32];
        let r1 = draw_committee_for_request(&req_id, 10, 11, &seed, &candidates, 5);
        let r2 = draw_committee_for_request(&req_id, 10, 11, &seed, &candidates, 5);
        let c1 = r1.unwrap();
        let c2 = r2.unwrap();
        assert_eq!(c1.len(), DEFAULT_COMMITTEE_SIZE);
        assert_eq!(c1, c2);
    }

    /// copying member is slashed; non-revealing member is slashed.
    #[test]
    fn copying_and_non_revealing_members_are_slashed() {
        let req_id = AiRequestId([0xBB; 32]);
        let addr = |i: u8| Address::from_bytes([i; 20]);
        let members: Vec<Address> = (1u8..=5).map(addr).collect();
        let mut session = CommitRevealSession::new(
            req_id,
            members.clone(),
            DEFAULT_QUORUM_THRESHOLD,
            100,
            10,
            10,
            DEFAULT_CHALLENGE_WINDOW_BLOCKS,
        );
        let agreed_out = [0x77; 32];

        // Members 0..4 commit honestly; member 3's commitment is copied by
        // member 4; member 3 then fails to reveal.
        let mut salts = [[0u8; 32]; 5];
        for (idx, s) in salts.iter_mut().enumerate() {
            *s = [(idx as u8) + 1; 32];
        }
        for i in 0..4 {
            let c = compute_vote_commitment(&req_id, &members[i], &agreed_out, &salts[i]);
            session.submit_commit(members[i], c, 105).unwrap();
        }
        let copied_hash = compute_vote_commitment(&req_id, &members[0], &agreed_out, &salts[0]);
        session.submit_commit(members[4], copied_hash, 106).unwrap();

        // Members 0, 1, 2 reveal honestly; member 3 stays silent.
        for i in 0..3 {
            session
                .submit_reveal(members[i], agreed_out, salts[i], 115)
                .unwrap();
        }
        let outcome = session.finalize_reveal_phase(121).unwrap();
        assert_eq!(outcome, None, "only 3 honest reveals < quorum 4");
        assert!(session
            .slashed
            .contains(&(members[4], SlashOffense::CopiedCommitment)));
        assert!(session
            .slashed
            .contains(&(members[3], SlashOffense::MissedReveal)));
    }

    /// reference DIP evaluation produces identical bits across pure
    /// integer architectures (`x86_64` and `aarch64` lock vector).
    #[test]
    fn dip_reference_model_is_bit_exact() {
        let dip = sample_dip();
        let spec = sample_mlp();
        let prompt = [12, -4, 7, 3];
        let (out_a, digest_a) = eval_dip_inference(&dip, &spec, &prompt).unwrap();
        let (out_b, digest_b) = eval_dip_inference(&dip, &spec, &prompt).unwrap();
        assert_eq!(out_a, vec![35, 31]);
        assert_eq!(out_a, out_b);
        assert_eq!(digest_a, digest_b);
    }

    /// model, prompt, and precision changes are caught; honest hardware
    /// metadata differences pass with identical digest.
    #[test]
    fn dip_catches_model_prompt_and_precision_drift() {
        let base_dip = sample_dip();
        let base_spec = sample_mlp();
        let base_prompt = [12, -4, 7, 3];
        let run_digest =
            |d: &DeterministicInferenceProfile, s: &FixedPointMlpSpec, p: &[i32]| -> [u8; 32] {
                let res = eval_dip_inference(d, s, p);
                res.unwrap().1
            };
        let base_digest = run_digest(&base_dip, &base_spec, &base_prompt);

        // Honest second node on different CPU vendor shares exact DIP fields.
        let second_node_dip = base_dip.clone();
        let second_digest = run_digest(&second_node_dip, &base_spec, &base_prompt);
        assert_eq!(base_digest, second_digest);

        // Mutated weight is caught.
        let mut altered_spec = base_spec.clone();
        altered_spec.weights[0] += 1;
        let weight_digest = run_digest(&base_dip, &altered_spec, &base_prompt);
        assert_ne!(base_digest, weight_digest);

        // Mutated prompt is caught.
        let prompt_digest = run_digest(&base_dip, &base_spec, &[12, -4, 7, 4]);
        assert_ne!(base_digest, prompt_digest);

        // Mutated precision is caught.
        let mut altered_dip = base_dip;
        altered_dip.quantization_bits = 8;
        let prec_digest = run_digest(&altered_dip, &base_spec, &base_prompt);
        assert_ne!(base_digest, prec_digest);
    }

    /// bisection rounds stay within bound and honest party wins.
    #[test]
    fn dispute_bisection_converges_within_bound_and_honest_wins() {
        let total_steps = 1_024u64;
        let fault_at = 337u64;
        let honest_trace: Vec<[u8; 32]> = (0..=total_steps)
            .map(|s| Sha256::digest(s.to_le_bytes()).into())
            .collect();
        let mut dishonest_trace = honest_trace.clone();
        for (idx, slot) in dishonest_trace.iter_mut().enumerate() {
            if (idx as u64) >= fault_at {
                *slot = Sha256::digest((idx as u64 ^ 0xDEAD_BEEF).to_le_bytes()).into();
            }
        }

        let mut game = DisputeBisectionGame::new(total_steps).unwrap();
        while !game.is_converged() {
            let mid = game.midpoint() as usize;
            game.advance_bisection(&dishonest_trace[mid], &honest_trace[mid])
                .unwrap();
        }
        assert!(game.rounds_used <= 10);
        assert!(game.rounds_used <= MAX_BISECTION_ROUNDS);
        assert_eq!(game.left_step, fault_at - 1);
        assert_eq!(game.right_step, fault_at);
    }

    /// `64 x 64` tile proves cleanly; tampered tile is rejected.
    #[test]
    fn tile_64x64_proves_and_rejects_tampering() {
        let a: Vec<i32> = (0..TILE_CELLS).map(|i| ((i % 17) as i32) - 8).collect();
        let b: Vec<i32> = (0..TILE_CELLS).map(|i| ((i % 13) as i32) - 6).collect();
        let proof = prove_tile_64x64(&a, &b).unwrap();
        assert!(is_valid_tile_64x64_proof(&proof, &a, &b));

        let mut tampered = proof;
        tampered.c_cells[128] += 1;
        assert!(!is_valid_tile_64x64_proof(&tampered, &a, &b));
    }

    /// second-committee sampling matches configured 1% rate within
    /// statistical bounds.
    #[test]
    fn sampling_rate_matches_parameter_statistically() {
        let randomness = [0x5A; 32];
        let total_trials = 10_000u64;
        let mut sampled = 0u64;
        for idx in 0..total_trials {
            let mut id_bytes = [0u8; 32];
            id_bytes[..8].copy_from_slice(&idx.to_le_bytes());
            if should_sample_for_second_committee(
                &AiRequestId(id_bytes),
                &randomness,
                DEFAULT_SAMPLING_RATE_BPS,
            ) {
                sampled += 1;
            }
        }
        // Expected mean = 100 (1%), 5-sigma window ~ [50, 150].
        assert!(
            (60..=140).contains(&sampled),
            "sampled {sampled} out of {total_trials} outside 1% statistical band"
        );
    }

    /// verification level never drops and refutation is a separate state.
    #[test]
    fn verification_level_never_drops() {
        let mut record = LevelRecord::new();
        record.raise(VerificationLevel::CommitteeAgreement).unwrap();
        record
            .raise(VerificationLevel::ChallengeWindowClosed)
            .unwrap();
        assert!(record.may_carry_value());
        assert!(record.raise(VerificationLevel::Receipt).is_err());
        record.refute();
        assert!(record.is_refuted());
        assert!(!record.may_carry_value());
        assert_eq!(record.level(), VerificationLevel::ChallengeWindowClosed);
    }

    /// verification invariants 9–12: small-model bound proof matches host bit-for-bit,
    /// rejects modified weights, rejects output commitments not derived from VM
    /// journal log, and rejects replay across requests.
    #[test]
    fn small_model_proof_soundness_and_anti_replay() {
        let dip = sample_dip();
        let spec = sample_mlp();
        let owner = Address::from_bytes([0x01; 20]);
        let model_id = AiModelId::of(&owner, &[0x33; 32], 2);
        let model = ModelRecordV2::from_mlp_spec(model_id, &spec, &dip).unwrap();
        let req_a = AiRequestId([0xA1; 32]);
        let req_b = AiRequestId([0xB2; 32]);
        let input = [3, -2, 5, 1];

        // guest output matches host evaluator bit-for-bit, and closes an
        // InferenceAssumption.
        let host_out = eval_fixed_point_mlp(&spec, &input).unwrap();
        let proof = prove_small_model_bound(req_a, &model, &spec, &input).unwrap();
        assert_eq!(proof.output_limbs, host_out);
        assert!(is_valid_small_model_bound_proof(
            &proof, &req_a, &model, &spec, &input
        ));

        let mut assumptions = InferenceAssumptionPool::default();
        assumptions.record_assumption(InferenceAssumption {
            request_id: req_a,
            model_id,
            weights_root: model.weights_root,
            input_commit: proof.input_commit,
            output_commit: proof.output_commit,
        });
        assert!(assumptions.discharge_with_proof(&proof, &model, &spec, &input));
        assert!(assumptions.is_fully_discharged());

        // proof generated or verified against altered weights is refused.
        let mut altered_spec = spec.clone();
        altered_spec.weights[2] += 1;
        let bad_res = prove_small_model_bound(req_a, &model, &altered_spec, &input);
        assert!(bad_res.is_err());
        assert!(!is_valid_small_model_bound_proof(
            &proof,
            &req_a,
            &model,
            &altered_spec,
            &input
        ));

        // output commitment / journal commitment forged outside the VM
        // log is refused.
        let mut forged_journal = proof.clone();
        forged_journal.journal_derived_commit = [0xEE; 32];
        assert!(!is_valid_small_model_bound_proof(
            &forged_journal,
            &req_a,
            &model,
            &spec,
            &input
        ));

        // replaying the exact valid proof for another request_id is
        // refused.
        assert!(!is_valid_small_model_bound_proof(
            &proof, &req_b, &model, &spec, &input
        ));
    }
}
