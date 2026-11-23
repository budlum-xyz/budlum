//! Chip-offloaded proving and verification for Phase 2 (`AggTick`).
//!
//! Profiling the pure-VM `verify_sig` and `AggTick` bytecode shows that
//! 89.1% of VM steps go to `Keccak-f[1600]` and 4.6% go to ML-DSA-87 NTT
//! arithmetic. This module moves both hotspots onto the bound Plonky3 chips
//! in `bud-proof`:
//!
//! * `BoundKeccakAir` proves every claim digest, claim-tree leaf, internal
//!   Merkle node, and `tick_pi` compression of a tick in a single STARK proof
//!   with preprocessed input/output commitments.
//! * `NttButterflyAir` proves ML-DSA-87 forward NTT butterflies modulo
//!   `q = 8_380_417` with canonical 23-bit range proofs and inter-layer wire
//!   commitments.
//!
//! Verification performs no `Keccak-f[1600]` permutations and no modular
//! multiplications of its own: it stitches each node's padded input directly
//! from its children's proven chip outputs and checks the bound STARK proofs.
//!
//! WIRING: unwired - the Phase 3 `StarkBackend` invokes `prove_tick_chips` and
//! `verify_tick_chips` for production tick proofs; until Phase 3 lands,
//! `benches/agg_tick_steps` and `src/aggregation/tests/programs.rs` drive them.

use bud_proof::chips::batch::{pad_rate_blocks, RATE_BYTES};
use bud_proof::chips::keccak::{
    prove_bound_keccak_f, verify_bound_keccak_f, BoundKeccakProof, KeccakChipError,
    ROWS_PER_PERMUTATION,
};
use bud_proof::chips::mldsa_ntt::{
    prove_ntt_batch, verify_ntt_batch, NttBatchProof, NttChipError, BUTTERFLIES_PER_NTT, N,
};

use super::super::claim::Claim;
use super::super::hash::{TAG_AGG_TICK, TAG_CLAIM, TAG_CLAIM_ROOT};
use super::super::merkle::{LEAF_PREFIX, NODE_PREFIX};
use crate::core::address::Address;
use crate::domain::types::{DomainId, Hash32};

/// Why chip-offloaded tick proving or verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TickChipError {
    /// A tick must cover at least one claim.
    Empty,
    /// Claim count does not fit in `u32`.
    TooManyClaims,
    /// A preimage exceeded the single-block Keccak-256 rate (136 bytes).
    PreimageTooLong(usize),
    /// The supplied outputs or NTT proof shape did not match the tick.
    ShapeMismatch,
    /// The chip-proven `tick_pi` did not match the expected value.
    TickPiMismatch,
    /// Bound Keccak chip error.
    Keccak(KeccakChipError),
    /// ML-DSA NTT chip error.
    Ntt(NttChipError),
}

impl std::fmt::Display for TickChipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "a tick must cover at least one claim"),
            Self::TooManyClaims => write!(f, "claim count exceeds u32"),
            Self::PreimageTooLong(len) => {
                write!(f, "preimage of {len} bytes exceeds single-block rate")
            }
            Self::ShapeMismatch => write!(f, "chip proof shape does not match tick layout"),
            Self::TickPiMismatch => write!(f, "chip-proven tick_pi does not match expected value"),
            Self::Keccak(err) => write!(f, "bound Keccak chip error: {err:?}"),
            Self::Ntt(err) => write!(f, "ML-DSA NTT chip error: {err:?}"),
        }
    }
}

impl std::error::Error for TickChipError {}

/// Bound Plonky3 chip proofs covering the `Keccak-f[1600]` tree and ML-DSA NTT
/// work of an `AggTick` segment.
#[derive(Clone)]
pub struct TickChipProof {
    /// Proven 25-lane output state for every `Keccak-f[1600]` permutation in the
    /// tick (claim digests, Merkle leaves, Merkle internal nodes, and `tick_pi`).
    pub keccak_outputs: Vec<[u64; 25]>,
    /// Single bound Keccak STARK certifying every permutation in `keccak_outputs`.
    pub keccak_proof: BoundKeccakProof,
    /// Proven forward-NTT polynomial outputs for the tick's ML-DSA-87 NTT batch.
    pub ntt_outputs: Vec<[u64; N]>,
    /// Optional bound NTT STARK when NTT polynomials are included in the tick.
    pub ntt_proof: Option<NttBatchProof>,
    /// The verified `tick_pi` squeezed from the final permutation in `keccak_outputs`.
    pub tick_pi: Hash32,
}

/// Step-count accounting comparing pure-VM `AggTick` execution against
/// chip-offloaded execution (`BoundKeccakAir` + `NttButterflyAir`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffloadAccounting {
    /// Total pure-VM steps before offloading.
    pub total_vm_steps: u64,
    /// VM steps spent inside `Keccak-f[1600]`, offloaded to `BoundKeccakAir`.
    pub keccak_vm_steps: u64,
    /// VM steps spent inside ML-DSA NTT, offloaded to `NttButterflyAir`.
    pub ntt_vm_steps: u64,
    /// Residual VM steps remaining after both chip offloads.
    pub residual_vm_steps: u64,
    /// Total `Keccak-f[1600]` permutations committed in `BoundKeccakAir`.
    pub keccak_permutations: usize,
    /// Padded trace rows in `BoundKeccakAir`.
    pub keccak_chip_rows: usize,
    /// Total ML-DSA NTT polynomials committed in `NttButterflyAir`.
    pub ntt_polynomials: usize,
    /// Padded trace rows in `NttButterflyAir`.
    pub ntt_chip_rows: usize,
}

impl OffloadAccounting {
    /// Builds an offload summary from measured pure-VM stage counts and chip batch sizes.
    #[must_use]
    pub const fn compute(
        total_vm_steps: u64,
        keccak_vm_steps: u64,
        ntt_vm_steps: u64,
        keccak_permutations: usize,
        ntt_polynomials: usize,
    ) -> Self {
        let offloaded = keccak_vm_steps.saturating_add(ntt_vm_steps);
        let residual_vm_steps = total_vm_steps.saturating_sub(offloaded);
        let keccak_chip_rows = if keccak_permutations == 0 {
            0
        } else {
            keccak_permutations
                .saturating_mul(ROWS_PER_PERMUTATION)
                .next_power_of_two()
        };
        let ntt_chip_rows = if ntt_polynomials == 0 {
            0
        } else {
            ntt_polynomials
                .saturating_mul(BUTTERFLIES_PER_NTT)
                .next_power_of_two()
        };
        Self {
            total_vm_steps,
            keccak_vm_steps,
            ntt_vm_steps,
            residual_vm_steps,
            keccak_permutations,
            keccak_chip_rows,
            ntt_polynomials,
            ntt_chip_rows,
        }
    }
}

fn single_block_state(parts: &[&[u8]]) -> Result<[u64; 25], TickChipError> {
    let total_len: usize = parts.iter().map(|p| p.len()).sum();
    if total_len >= RATE_BYTES {
        return Err(TickChipError::PreimageTooLong(total_len));
    }
    let mut preimage = Vec::with_capacity(total_len);
    for part in parts {
        preimage.extend_from_slice(part);
    }
    let blocks = pad_rate_blocks(&preimage);
    let [rate] = blocks.as_slice() else {
        return Err(TickChipError::PreimageTooLong(total_len));
    };
    let mut state = [0u64; 25];
    for (dst, src) in state.iter_mut().zip(rate.iter()) {
        *dst = *src;
    }
    Ok(state)
}

fn squeeze_hash(output: &[u64; 25]) -> Hash32 {
    let mut out = [0u8; 32];
    for (chunk, word) in out
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(output.iter().take(4))
    {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Computes all single-block `Keccak-f[1600]` inputs for a tick's claims,
/// Merkle tree, and `tick_pi`, using `outputs` (when verifying) or computing
/// them via the reference permutation (when proving).
fn build_tick_keccak_inputs(
    domain: DomainId,
    aggregator: &Address,
    claims: &[Claim],
    proven_outputs: Option<&[[u64; 25]]>,
) -> Result<(Vec<[u64; 25]>, Hash32), TickChipError> {
    if claims.is_empty() {
        return Err(TickChipError::Empty);
    }
    let count = u32::try_from(claims.len()).map_err(|_| TickChipError::TooManyClaims)?;
    let domain_be = domain.to_be_bytes();
    let count_be = count.to_be_bytes();
    let leaf_tag = [LEAF_PREFIX];
    let node_tag = [NODE_PREFIX];

    let mut inputs = Vec::with_capacity(claims.len().saturating_mul(3).saturating_add(1));
    let mut cursor = 0usize;

    let mut next_digest =
        |parts: &[&[u8]], inputs: &mut Vec<[u64; 25]>| -> Result<Hash32, TickChipError> {
            let state = single_block_state(parts)?;
            inputs.push(state);
            let digest = if let Some(outputs) = proven_outputs {
                let output = outputs.get(cursor).ok_or(TickChipError::ShapeMismatch)?;
                squeeze_hash(output)
            } else {
                super::super::hash::h(parts)
            };
            cursor += 1;
            Ok(digest)
        };

    // 1. Claim digests.
    let mut claim_digests = Vec::with_capacity(claims.len());
    for claim in claims {
        let encoded = claim.encode();
        let digest = next_digest(&[TAG_CLAIM, &domain_be, &encoded], &mut inputs)?;
        claim_digests.push(digest);
    }

    // 2. Claim-tree leaves.
    let mut level = Vec::with_capacity(claim_digests.len());
    for digest in &claim_digests {
        let leaf = next_digest(&[TAG_CLAIM_ROOT, &leaf_tag, digest], &mut inputs)?;
        level.push(leaf);
    }

    // 3. Internal Merkle nodes matching `merkle::claims_root`.
    while level.len() > 1 {
        let (pairs, promoted) = level.as_chunks::<2>();
        let mut next_level = Vec::with_capacity(pairs.len() + promoted.len());
        for [left, right] in pairs {
            let parent = next_digest(&[TAG_CLAIM_ROOT, &node_tag, left, right], &mut inputs)?;
            next_level.push(parent);
        }
        next_level.extend_from_slice(promoted);
        level = next_level;
    }

    let claims_root = level.first().copied().ok_or(TickChipError::Empty)?;

    // 4. Final `tick_pi`.
    let computed_tick_pi = next_digest(
        &[
            TAG_AGG_TICK,
            &domain_be,
            &claims_root,
            &count_be,
            aggregator.as_bytes(),
        ],
        &mut inputs,
    )?;

    if let Some(outputs) = proven_outputs {
        if outputs.len() != inputs.len() {
            return Err(TickChipError::ShapeMismatch);
        }
    }

    Ok((inputs, computed_tick_pi))
}

/// Proves a tick's full claim-digest, Merkle-tree, and `tick_pi` Keccak graph
/// in `BoundKeccakAir` together with any supplied ML-DSA-87 NTT polynomials in
/// `NttButterflyAir`.
///
/// # Errors
///
/// Returns [`TickChipError`] on empty ticks, invalid preimages, or chip errors.
pub fn prove_tick_chips(
    domain: DomainId,
    aggregator: &Address,
    claims: &[Claim],
    ntt_inputs: &[[u64; N]],
) -> Result<TickChipProof, TickChipError> {
    let (keccak_inputs, expected_tick_pi) =
        build_tick_keccak_inputs(domain, aggregator, claims, None)?;
    let (keccak_proof, keccak_outputs) =
        prove_bound_keccak_f(&keccak_inputs).map_err(TickChipError::Keccak)?;
    let squeezed_tick_pi = keccak_outputs
        .last()
        .map(squeeze_hash)
        .ok_or(TickChipError::Empty)?;
    if squeezed_tick_pi != expected_tick_pi {
        return Err(TickChipError::TickPiMismatch);
    }

    let (ntt_outputs, ntt_proof) = if ntt_inputs.is_empty() {
        (Vec::new(), None)
    } else {
        let (outputs, proof) = prove_ntt_batch(ntt_inputs).map_err(TickChipError::Ntt)?;
        (outputs, Some(proof))
    };

    Ok(TickChipProof {
        keccak_outputs,
        keccak_proof,
        ntt_outputs,
        ntt_proof,
        tick_pi: squeezed_tick_pi,
    })
}

/// Verifies a [`TickChipProof`] against `domain`, `aggregator`, `claims`,
/// `expected_tick_pi`, and `ntt_inputs` without running `Keccak-f[1600]` or
/// ML-DSA modular multiplications in the verifier.
///
/// # Errors
///
/// Refuses mismatched `tick_pi`, tampered claims, replayed proofs, or invalid
/// chip STARKs.
pub fn verify_tick_chips(
    domain: DomainId,
    aggregator: &Address,
    claims: &[Claim],
    expected_tick_pi: &Hash32,
    ntt_inputs: &[[u64; N]],
    proof: &TickChipProof,
) -> Result<(), TickChipError> {
    let (keccak_inputs, stitched_tick_pi) =
        build_tick_keccak_inputs(domain, aggregator, claims, Some(&proof.keccak_outputs))?;
    if stitched_tick_pi != *expected_tick_pi || proof.tick_pi != *expected_tick_pi {
        return Err(TickChipError::TickPiMismatch);
    }
    verify_bound_keccak_f(&keccak_inputs, &proof.keccak_outputs, &proof.keccak_proof)
        .map_err(TickChipError::Keccak)?;

    if ntt_inputs.is_empty() {
        if proof.ntt_proof.is_some() || !proof.ntt_outputs.is_empty() {
            return Err(TickChipError::ShapeMismatch);
        }
    } else {
        let Some(ntt_proof) = proof.ntt_proof.as_ref() else {
            return Err(TickChipError::ShapeMismatch);
        };
        verify_ntt_batch(ntt_inputs, &proof.ntt_outputs, ntt_proof).map_err(TickChipError::Ntt)?;
    }

    Ok(())
}
