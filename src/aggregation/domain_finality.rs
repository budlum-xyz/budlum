//! Phase 4 domain state-transition claims and [`ClaimedDomainFinalityAdapter`].
//!
//! WIRING: wired into `SettlementRegistries::claimed_domain_finality` in
//! `src/settlement/registries.rs` (checked during
//! `SettlementRegistries::universal_finality_certificate` and folded into
//! `SettlementRegistries::root` when non-empty) and verified by
//! `tests/k2e_claimed_domain_finality_tests.rs`.
//!
//! Each domain's state-transition STARK proof enters the aggregation layer as
//! an `ObjectKind::StarkProof` envelope and collapses into:
//!
//! ```text
//! Claim::Prog {
//!     program_hash: domain_transition_program_hash,
//!     input_hash:   Poseidon256("BDLM_DOM_TRANS_IN_V1",  domain_id, domain_chain_id, prev_height, prev_state_root),
//!     output_hash:  Poseidon256("BDLM_DOM_TRANS_OUT_V1", domain_id, domain_chain_id, new_height, parent_block_hash, block_hash, state_root, tx_root, event_root, timestamp_ms),
//! }
//! ```
//!
//! Every limb of the witness is range-checked to `< 2^32` inside `BudVM`,
//! full 64-bit `prev_height < new_height` and full 256-bit
//! `state_root == derive_transition_state_root(...)` are constrained with
//! `Assert`, and both `input_hash` and `output_hash` are computed inside the
//! `BudAir` trace and published directly to `SWrite[0..16]` (no unconstrained
//! public-I/O witness cells).
//!
//! Once aggregated into a block's `MasterProof` (`ClaimFrame`),
//! [`ClaimedDomainFinalityAdapter`] implements [`DomainFinalityAdapter`] and
//! reads finality directly from the verified `Claim::Prog` without re-verifying
//! the underlying domain transition STARK.

use std::collections::{BTreeMap, BTreeSet};

use bud_vm::{poseidon4_hash, Vm};
use serde::{Deserialize, Serialize};

use super::backend::{AggBackend, AggError};
use super::claim::{Claim, GOLDILOCKS_MODULUS};
use super::frame::ClaimFrame;
use super::hash::h;
use super::programs::agg_merge::program_hash_of;
use super::programs::asm::{Asm, Program, R};
use super::programs::prog_claim::{
    prove_vm_program, write_cell, write_digest_cells, ProgClaimError, StarkProofObject,
    DIGEST_LIMBS, DIGEST_LIMBS_U32,
};
use crate::crypto::facts::{AssumptionClass, ObservedScheme};
use crate::domain::finality_adapter::{
    DomainFinalityAdapter, FinalityError, FinalityProof, FinalityStatus,
};
use crate::domain::types::{ConsensusDomain, DomainCommitment, DomainId, DomainStatus, Hash32};

/// Domain tag for the pre-state input commitment of a domain transition claim.
pub const TAG_DOMAIN_TRANSITION_IN: &[u8] = b"BDLM_DOM_TRANS_IN_V1";
/// Domain tag for the post-state output commitment of a domain transition claim.
pub const TAG_DOMAIN_TRANSITION_OUT: &[u8] = b"BDLM_DOM_TRANS_OUT_V1";
/// Domain tag for the in-circuit state-root transition commitment.
pub const TAG_DOMAIN_TRANSITION_STEP: &[u8] = b"BDLM_DOM_TRANS_STEP_V1";
/// Maximum verified `Claim::Prog` digests retained in [`ClaimedDomainFinalityAdapter`]
/// before deterministic eviction of the oldest/smallest unpinned entry.
pub const MAX_VERIFIED_PROG_DIGESTS: usize = 16_384;

/// Number of 32-bit little-endian limbs encoding `timestamp_ms: u128`.
const TIMESTAMP_LIMBS: usize = 4;
/// Bitmask asserting canonical 32-bit unsigned limbs inside `BudVM`.
const U32_MASK: u64 = 0xFFFF_FFFF;

/// Derives three domain-separated Goldilocks constants `(seed_a, seed_b, squeeze_tag)`
/// from a canonical `BDLM_*` byte tag.
#[must_use]
fn tag_seeds(tag: &[u8]) -> (u64, u64, u64) {
    let digest = h(&[tag]);
    let word = |start: usize| -> u64 {
        let mut bytes = [0u8; 8];
        if let Some(slice) = digest.get(start..start + 8) {
            bytes.copy_from_slice(slice);
        }
        u64::from_le_bytes(bytes) % GOLDILOCKS_MODULUS
    };
    (word(0), word(8), word(16))
}

#[must_use]
const fn split_u64_limbs(value: u64) -> [u64; 2] {
    [value & U32_MASK, value >> 32]
}

#[must_use]
const fn split_u128_limbs(value: u128) -> [u64; TIMESTAMP_LIMBS] {
    [
        (value as u64) & U32_MASK,
        ((value >> 32) as u64) & U32_MASK,
        ((value >> 64) as u64) & U32_MASK,
        ((value >> 96) as u64) & U32_MASK,
    ]
}

#[must_use]
fn digest_limbs(digest: &Hash32) -> [u64; DIGEST_LIMBS] {
    let mut out = [0u64; DIGEST_LIMBS];
    for (dst, chunk) in out.iter_mut().zip(digest.as_chunks::<4>().0) {
        let [b0, b1, b2, b3] = *chunk;
        *dst = u64::from(u32::from_le_bytes([b0, b1, b2, b3]));
    }
    out
}

/// Evaluates the dual-lane (128-bit capacity) Poseidon sponge over canonical
/// 32-bit limbs and squeezes an 8-limb (256-bit) digest, matching the exact
/// instruction sequence emitted inside [`compile_domain_transition`].
#[must_use]
fn poseidon_sponge_256(tag: &[u8], limbs: &[u64]) -> Hash32 {
    let (seed_a, seed_b, squeeze_base) = tag_seeds(tag);
    let mut acc_a = seed_a;
    for &limb in limbs {
        acc_a = poseidon4_hash(acc_a, limb);
    }
    let mut acc_b = seed_b;
    for &limb in limbs.iter().rev() {
        acc_b = poseidon4_hash(acc_b, limb);
    }
    let mut out = [0u8; 32];
    for (idx, chunk) in (0u64..).zip(out.as_chunks_mut::<4>().0) {
        let domain_idx = squeeze_base.wrapping_add(idx) % GOLDILOCKS_MODULUS;
        let inner = poseidon4_hash(acc_a, domain_idx);
        let word = poseidon4_hash(inner, acc_b);
        let limb = (word & U32_MASK) as u32;
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// Derives the deterministic post-state root enforced inside the reference
/// `BudVM` domain-transition program (`compile_domain_transition`).
#[must_use]
pub fn derive_transition_state_root(
    domain_id: DomainId,
    domain_chain_id: u64,
    prev_height: u64,
    new_height: u64,
    prev_state_root: &Hash32,
    batch_digest: &Hash32,
) -> Hash32 {
    let chain = split_u64_limbs(domain_chain_id);
    let prev_h = split_u64_limbs(prev_height);
    let new_h = split_u64_limbs(new_height);
    let mut limbs = Vec::with_capacity(7 + DIGEST_LIMBS * 2);
    limbs.push(u64::from(domain_id));
    limbs.extend_from_slice(&chain);
    limbs.extend_from_slice(&prev_h);
    limbs.extend_from_slice(&new_h);
    limbs.extend_from_slice(&digest_limbs(prev_state_root));
    limbs.extend_from_slice(&digest_limbs(batch_digest));
    poseidon_sponge_256(TAG_DOMAIN_TRANSITION_STEP, &limbs)
}

/// Canonical `input_hash` of a domain state-transition [`Claim::Prog`],
/// computed directly inside `BudVM` and published to `SWrite[0..8]`.
#[must_use]
pub fn domain_transition_input_hash(
    domain: &ConsensusDomain,
    prev_height: u64,
    prev_state_root: &Hash32,
) -> Hash32 {
    let chain = split_u64_limbs(domain.domain_chain_id);
    let prev_h = split_u64_limbs(prev_height);
    let mut limbs = Vec::with_capacity(5 + DIGEST_LIMBS);
    limbs.push(u64::from(domain.id));
    limbs.extend_from_slice(&chain);
    limbs.extend_from_slice(&prev_h);
    limbs.extend_from_slice(&digest_limbs(prev_state_root));
    poseidon_sponge_256(TAG_DOMAIN_TRANSITION_IN, &limbs)
}

/// Canonical `output_hash` of a domain state-transition [`Claim::Prog`],
/// binding `(domain_id, domain_chain_id, domain_height, parent_domain_block_hash,
/// domain_block_hash, state_root, tx_root, event_root, timestamp_ms)` directly
/// inside `BudVM` and publishing to `SWrite[8..16]`.
#[must_use]
pub fn domain_transition_output_hash(
    domain: &ConsensusDomain,
    commitment: &DomainCommitment,
) -> Hash32 {
    let chain = split_u64_limbs(domain.domain_chain_id);
    let new_h = split_u64_limbs(commitment.domain_height);
    let ts = split_u128_limbs(commitment.timestamp_ms);
    let mut limbs = Vec::with_capacity(5 + DIGEST_LIMBS * 5 + TIMESTAMP_LIMBS);
    limbs.push(u64::from(domain.id));
    limbs.extend_from_slice(&chain);
    limbs.extend_from_slice(&new_h);
    limbs.extend_from_slice(&digest_limbs(&commitment.parent_domain_block_hash));
    limbs.extend_from_slice(&digest_limbs(&commitment.domain_block_hash));
    limbs.extend_from_slice(&digest_limbs(&commitment.state_root));
    limbs.extend_from_slice(&digest_limbs(&commitment.tx_root));
    limbs.extend_from_slice(&digest_limbs(&commitment.event_root));
    limbs.extend_from_slice(&ts);
    poseidon_sponge_256(TAG_DOMAIN_TRANSITION_OUT, &limbs)
}

/// Constructs the canonical [`Claim::Prog`] for one domain state transition.
#[must_use]
pub fn domain_transition_claim(
    program_hash: Hash32,
    domain: &ConsensusDomain,
    prev_height: u64,
    prev_state_root: &Hash32,
    commitment: &DomainCommitment,
) -> Claim {
    Claim::Prog {
        program_hash,
        input_hash: domain_transition_input_hash(domain, prev_height, prev_state_root),
        output_hash: domain_transition_output_hash(domain, commitment),
    }
}

/// A single operand fed into the in-circuit dual-lane Poseidon sponge: either a
/// constant baked into bytecode or a range-checked 32-bit witness cell.
#[derive(Clone, Copy)]
enum LimbSource {
    Const(u64),
    Cell(u64),
}

fn emit_load_source(a: &mut Asm, dst: super::programs::asm::Reg, src: LimbSource) {
    match src {
        LimbSource::Const(v) => a.li(dst, v),
        LimbSource::Cell(cell) => a.load_abs(dst, cell),
    }
}

/// Emits the dual-lane Poseidon sponge over `sources`, placing `(acc_a, acc_b)`
/// in `(R[10], R[11])` and initializing `R[12] = U32_MASK`.
fn emit_dual_poseidon(a: &mut Asm, tag: &[u8], sources: &[LimbSource]) -> u64 {
    let (seed_a, seed_b, squeeze_base) = tag_seeds(tag);
    a.li(R[10], seed_a);
    for &src in sources {
        emit_load_source(a, R[1], src);
        a.poseidon(R[10], R[10], R[1]);
    }
    a.li(R[11], seed_b);
    for &src in sources.iter().rev() {
        emit_load_source(a, R[1], src);
        a.poseidon(R[11], R[11], R[1]);
    }
    a.li(R[12], U32_MASK);
    squeeze_base
}

fn push_cell_range(out: &mut Vec<LimbSource>, first: u64, count: usize) {
    for i in 0..count as u64 {
        out.push(LimbSource::Cell(first + i));
    }
}

/// Memory layout for [`DomainTransitionProgram`] (every cell holds one
/// canonical 32-bit unsigned limb, range-checked at program entry).
#[derive(Debug, Clone, Copy)]
struct TransitionCells {
    first_cell: u64,
    total_cells: u64,
    prev_height: u64,
    new_height: u64,
    prev_root: u64,
    batch_digest: u64,
    parent_block_hash: u64,
    block_hash: u64,
    state_root: u64,
    tx_root: u64,
    event_root: u64,
    timestamp_ms: u64,
}

/// Compiled `BudVM` state-transition program bound to `(domain_id, domain_chain_id)`.
#[derive(Debug, Clone)]
pub struct DomainTransitionProgram {
    /// Compiled `BudVM` bytecode.
    pub program: Program,
    /// `Keccak-256` hash of `program.code`.
    pub program_hash: Hash32,
    /// Domain identifier baked into the guest bytecode.
    pub domain_id: DomainId,
    /// External chain identifier baked into the guest bytecode.
    pub domain_chain_id: u64,
    cells: TransitionCells,
}

/// Compiles a domain state-transition `BudVM` program for `(domain_id, domain_chain_id)`.
///
/// The guest constrains inside `BudAir`:
/// 1. Every witness cell holds a canonical unsigned 32-bit integer (`x & 0xFFFF_FFFF == x`).
/// 2. Exact 64-bit strict height monotonicity: `prev_height < new_height`.
/// 3. Full 256-bit state transition binding:
///    `state_root == derive_transition_state_root(domain_id, domain_chain_id, prev_height, new_height, prev_root, batch)`.
/// 4. In-circuit computation of `input_hash` published directly to `SWrite[0..8]`.
/// 5. In-circuit computation of `output_hash` (binding every commitment header
///    field) published directly to `SWrite[8..16]`.
///
/// # Errors
///
/// Returns [`ProgClaimError`] if guest assembly fails.
pub fn compile_domain_transition(
    domain_id: DomainId,
    domain_chain_id: u64,
) -> Result<DomainTransitionProgram, ProgClaimError> {
    let mut a = Asm::new();
    let prev_height = a.alloc(2);
    let new_height = a.alloc(2);
    let prev_root = a.alloc(DIGEST_LIMBS as u64);
    let batch_digest = a.alloc(DIGEST_LIMBS as u64);
    let parent_block_hash = a.alloc(DIGEST_LIMBS as u64);
    let block_hash = a.alloc(DIGEST_LIMBS as u64);
    let state_root = a.alloc(DIGEST_LIMBS as u64);
    let tx_root = a.alloc(DIGEST_LIMBS as u64);
    let event_root = a.alloc(DIGEST_LIMBS as u64);
    let timestamp_ms = a.alloc(TIMESTAMP_LIMBS as u64);
    let total_cells = (timestamp_ms + TIMESTAMP_LIMBS as u64) - prev_height;
    let cells = TransitionCells {
        first_cell: prev_height,
        total_cells,
        prev_height,
        new_height,
        prev_root,
        batch_digest,
        parent_block_hash,
        block_hash,
        state_root,
        tx_root,
        event_root,
        timestamp_ms,
    };

    // 1. Assert every witness cell is a canonical unsigned 32-bit limb.
    a.region("range_check_u32_limbs");
    a.li(R[2], U32_MASK);
    for offset in 0..cells.total_cells {
        a.load_abs(R[1], cells.first_cell + offset);
        a.and(R[3], R[1], R[2]);
        a.eq(R[3], R[3], R[1]);
        a.assert(R[3]);
    }

    // 2. Assert exact unsigned 64-bit strict monotonicity:
    //    (prev_hi < new_hi) || (prev_hi == new_hi && prev_lo < new_lo).
    a.region("check_height_64bit");
    a.load_abs(R[1], cells.prev_height); // prev_lo
    a.load_abs(R[2], cells.prev_height + 1); // prev_hi
    a.load_abs(R[3], cells.new_height); // new_lo
    a.load_abs(R[4], cells.new_height + 1); // new_hi
    a.lt(R[5], R[2], R[4]); // hi_lt in {0, 1}
    a.eq(R[6], R[2], R[4]); // hi_eq in {0, 1}
    a.lt(R[7], R[1], R[3]); // lo_lt in {0, 1}
    a.mul(R[6], R[6], R[7]); // hi_eq && lo_lt
    a.add(R[5], R[5], R[6]); // disjoint sum in {0, 1}
    a.assert(R[5]);

    let [chain_lo, chain_hi] = split_u64_limbs(domain_chain_id);
    let header_consts = [
        LimbSource::Const(u64::from(domain_id)),
        LimbSource::Const(chain_lo),
        LimbSource::Const(chain_hi),
    ];

    // 3. Recompute expected `state_root` from (domain_id, domain_chain_id,
    //    prev_height, new_height, prev_root, batch_digest) and Assert equality
    //    with all 8 limbs of `cells.state_root`.
    a.region("check_state_transition");
    let mut step_sources = Vec::from(header_consts);
    push_cell_range(&mut step_sources, cells.prev_height, 2);
    push_cell_range(&mut step_sources, cells.new_height, 2);
    push_cell_range(&mut step_sources, cells.prev_root, DIGEST_LIMBS);
    push_cell_range(&mut step_sources, cells.batch_digest, DIGEST_LIMBS);
    let step_squeeze = emit_dual_poseidon(&mut a, TAG_DOMAIN_TRANSITION_STEP, &step_sources);
    for idx in 0..DIGEST_LIMBS as u64 {
        let domain_idx = step_squeeze.wrapping_add(idx) % GOLDILOCKS_MODULUS;
        a.li(R[1], domain_idx);
        a.poseidon(R[2], R[10], R[1]);
        a.poseidon(R[2], R[2], R[11]);
        a.and(R[2], R[2], R[12]);
        a.load_abs(R[3], cells.state_root + idx);
        a.eq(R[4], R[2], R[3]);
        a.assert(R[4]);
    }

    // 4. Recompute `input_hash` in-circuit and publish directly to SWrite[0..8].
    a.region("publish_input_hash");
    let mut in_sources = Vec::from(header_consts);
    push_cell_range(&mut in_sources, cells.prev_height, 2);
    push_cell_range(&mut in_sources, cells.prev_root, DIGEST_LIMBS);
    let in_squeeze = emit_dual_poseidon(&mut a, TAG_DOMAIN_TRANSITION_IN, &in_sources);
    for slot in 0..DIGEST_LIMBS_U32 {
        let domain_idx = in_squeeze.wrapping_add(u64::from(slot)) % GOLDILOCKS_MODULUS;
        a.li(R[1], domain_idx);
        a.poseidon(R[2], R[10], R[1]);
        a.poseidon(R[2], R[2], R[11]);
        a.and(R[2], R[2], R[12]);
        a.swrite(slot, R[2]);
    }

    // 5. Recompute `output_hash` over every commitment header field in-circuit
    //    and publish directly to SWrite[8..16].
    a.region("publish_output_hash");
    let mut out_sources = Vec::from(header_consts);
    push_cell_range(&mut out_sources, cells.new_height, 2);
    push_cell_range(&mut out_sources, cells.parent_block_hash, DIGEST_LIMBS);
    push_cell_range(&mut out_sources, cells.block_hash, DIGEST_LIMBS);
    push_cell_range(&mut out_sources, cells.state_root, DIGEST_LIMBS);
    push_cell_range(&mut out_sources, cells.tx_root, DIGEST_LIMBS);
    push_cell_range(&mut out_sources, cells.event_root, DIGEST_LIMBS);
    push_cell_range(&mut out_sources, cells.timestamp_ms, TIMESTAMP_LIMBS);
    let out_squeeze = emit_dual_poseidon(&mut a, TAG_DOMAIN_TRANSITION_OUT, &out_sources);
    for offset in 0..DIGEST_LIMBS_U32 {
        let domain_idx = out_squeeze.wrapping_add(u64::from(offset)) % GOLDILOCKS_MODULUS;
        a.li(R[1], domain_idx);
        a.poseidon(R[2], R[10], R[1]);
        a.poseidon(R[2], R[2], R[11]);
        a.and(R[2], R[2], R[12]);
        a.swrite(DIGEST_LIMBS_U32 + offset, R[2]);
    }
    a.halt();

    let program = a.finish()?;
    let program_hash = program_hash_of(&program.code);
    Ok(DomainTransitionProgram {
        program,
        program_hash,
        domain_id,
        domain_chain_id,
        cells,
    })
}

/// Proves a domain state transition inside `BudVM` (`BudAir`), returning a
/// [`StarkProofObject`] whose derived claim is `domain_transition_claim(...)`.
///
/// # Errors
///
/// Returns [`ProgClaimError`] if the domain mismatches, the height or
/// state-root transition constraint aborts on `Assert`, or STARK proving fails.
pub fn prove_domain_transition(
    compiled: &DomainTransitionProgram,
    domain: &ConsensusDomain,
    prev_height: u64,
    prev_state_root: &Hash32,
    commitment: &DomainCommitment,
    batch_digest: &Hash32,
    claim_domain: DomainId,
) -> Result<StarkProofObject, ProgClaimError> {
    if compiled.domain_id != domain.id {
        return Err(ProgClaimError::InvalidInput(
            "domain id does not match compiled DomainTransitionProgram",
        ));
    }
    if compiled.domain_chain_id != domain.domain_chain_id {
        return Err(ProgClaimError::InvalidInput(
            "domain chain id does not match compiled DomainTransitionProgram",
        ));
    }
    let input_hash = domain_transition_input_hash(domain, prev_height, prev_state_root);
    let output_hash = domain_transition_output_hash(domain, commitment);

    let mem_bytes = usize::try_from(compiled.program.memory_cells)
        .unwrap_or(0)
        .saturating_add(16)
        .saturating_mul(8);
    let mut vm = Vm::new(mem_bytes.max(4096));
    let [prev_lo, prev_hi] = split_u64_limbs(prev_height);
    let [new_lo, new_hi] = split_u64_limbs(commitment.domain_height);
    write_cell(&mut vm, compiled.cells.prev_height, prev_lo);
    write_cell(&mut vm, compiled.cells.prev_height + 1, prev_hi);
    write_cell(&mut vm, compiled.cells.new_height, new_lo);
    write_cell(&mut vm, compiled.cells.new_height + 1, new_hi);
    write_digest_cells(&mut vm, compiled.cells.prev_root, prev_state_root);
    write_digest_cells(&mut vm, compiled.cells.batch_digest, batch_digest);
    write_digest_cells(
        &mut vm,
        compiled.cells.parent_block_hash,
        &commitment.parent_domain_block_hash,
    );
    write_digest_cells(
        &mut vm,
        compiled.cells.block_hash,
        &commitment.domain_block_hash,
    );
    write_digest_cells(&mut vm, compiled.cells.state_root, &commitment.state_root);
    write_digest_cells(&mut vm, compiled.cells.tx_root, &commitment.tx_root);
    write_digest_cells(&mut vm, compiled.cells.event_root, &commitment.event_root);
    for (idx, limb) in (0u64..).zip(split_u128_limbs(commitment.timestamp_ms)) {
        write_cell(&mut vm, compiled.cells.timestamp_ms + idx, limb);
    }

    prove_vm_program(
        &compiled.program.code,
        &mut vm,
        input_hash,
        output_hash,
        claim_domain,
    )
}

/// [`DomainFinalityAdapter`] backed by verified aggregation `MasterProof`s
/// (`ClaimFrame`s).
///
/// Only claims extracted from a `ClaimFrame` that passed [`AggBackend::verify`]
/// can enter `verified_prog_digests`. Finalizing a [`DomainCommitment`] checks
/// program authorization, predecessor tip continuity (when a finalized anchor
/// is recorded for the domain), and pre-verified `Claim::Prog` inclusion in
/// O(log n) without re-verifying the underlying STARK proof.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClaimedDomainFinalityAdapter {
    claim_domain: DomainId,
    registered_programs: BTreeMap<DomainId, Hash32>,
    verified_prog_digests: BTreeSet<Hash32>,
    finalized_tips: BTreeMap<DomainId, (u64, Hash32)>,
    /// Certified `(height, state_root, claim_digest)` per domain backed by a
    /// verified `Claim::Prog` from an accepted `MasterProof`.
    #[serde(default)]
    certified_commitments: BTreeMap<DomainId, (u64, Hash32, Hash32)>,
}

impl ClaimedDomainFinalityAdapter {
    /// Creates an empty adapter scoped to the aggregation `claim_domain`.
    #[must_use]
    pub const fn new(claim_domain: DomainId) -> Self {
        Self {
            claim_domain,
            registered_programs: BTreeMap::new(),
            verified_prog_digests: BTreeSet::new(),
            finalized_tips: BTreeMap::new(),
            certified_commitments: BTreeMap::new(),
        }
    }

    /// True when no programs, verified claim digests, tips, or certified
    /// commitments have been recorded (so empty registries keep pinned roots).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.registered_programs.is_empty()
            && self.verified_prog_digests.is_empty()
            && self.finalized_tips.is_empty()
            && self.certified_commitments.is_empty()
    }

    /// Deterministic state root committing all registered programs, verified
    /// `Claim::Prog` digests, finalized tips, and certified commitments.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        let mut fields: Vec<Vec<u8>> = Vec::with_capacity(
            4 + self.registered_programs.len() * 2
                + self.verified_prog_digests.len()
                + self.finalized_tips.len() * 3
                + self.certified_commitments.len() * 4,
        );
        fields.push(b"BDLM_CLAIMED_DOMAIN_FINALITY_V1".to_vec());
        fields.push(self.claim_domain.to_le_bytes().to_vec());
        fields.push(
            (self.registered_programs.len() as u64)
                .to_le_bytes()
                .to_vec(),
        );
        for (domain_id, prog_hash) in &self.registered_programs {
            fields.push(domain_id.to_le_bytes().to_vec());
            fields.push(prog_hash.to_vec());
        }
        fields.push(
            (self.verified_prog_digests.len() as u64)
                .to_le_bytes()
                .to_vec(),
        );
        for digest in &self.verified_prog_digests {
            fields.push(digest.to_vec());
        }
        fields.push((self.finalized_tips.len() as u64).to_le_bytes().to_vec());
        for (domain_id, (height, root)) in &self.finalized_tips {
            fields.push(domain_id.to_le_bytes().to_vec());
            fields.push(height.to_le_bytes().to_vec());
            fields.push(root.to_vec());
        }
        fields.push(
            (self.certified_commitments.len() as u64)
                .to_le_bytes()
                .to_vec(),
        );
        for (domain_id, (height, state_root, claim_digest)) in &self.certified_commitments {
            fields.push(domain_id.to_le_bytes().to_vec());
            fields.push(height.to_le_bytes().to_vec());
            fields.push(state_root.to_vec());
            fields.push(claim_digest.to_vec());
        }
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        crate::core::hash::hash_fields_bytes(&refs)
    }

    /// Registers the canonical state-transition `program_hash` for `domain_id`.
    /// Zero hashes are ignored so an uninitialized digest can never authorize transitions.
    pub fn register_domain_program(&mut self, domain_id: DomainId, program_hash: Hash32) {
        if program_hash == [0u8; 32] {
            return;
        }
        self.registered_programs.insert(domain_id, program_hash);
    }

    /// Pins or advances the known finalized `(height, state_root)` tip for
    /// `domain_id`. Subsequent [`DomainFinalityAdapter::verify_finality`] calls
    /// require `(prev_height, prev_state_root)` to connect directly to this tip.
    /// Zero roots, height regressions, and conflicting roots at an already-finalized
    /// height are ignored.
    pub fn record_finalized_tip(&mut self, domain_id: DomainId, height: u64, state_root: Hash32) {
        if state_root == [0u8; 32] {
            return;
        }
        if let Some(&(existing_height, existing_root)) = self.finalized_tips.get(&domain_id) {
            if height < existing_height
                || (height == existing_height && existing_root != state_root)
            {
                return;
            }
        }
        self.finalized_tips.insert(domain_id, (height, state_root));
    }

    /// Verify a `FinalityProof::AggregatedProg` against admitted `MasterProof`
    /// claims and, on success, advance the domain's certified commitment and
    /// finalized tip so `universal_finality_certificate` marks the row Proven.
    ///
    /// # Errors
    ///
    /// Returns [`FinalityError`] when the proof is not `AggregatedProg` or is
    /// rejected; no tip or certification state changes on refusal.
    pub fn verify_and_certify_commitment(
        &mut self,
        domain: &ConsensusDomain,
        commitment: &DomainCommitment,
        proof: &FinalityProof,
    ) -> Result<Hash32, FinalityError> {
        let FinalityProof::AggregatedProg { claim_digest, .. } = proof else {
            return Err(FinalityError(
                "Expected AggregatedProg finality proof".into(),
            ));
        };
        match self.verify_finality(domain, commitment, proof)? {
            FinalityStatus::Finalized => {
                self.finalized_tips
                    .insert(domain.id, (commitment.domain_height, commitment.state_root));
                self.certified_commitments.insert(
                    domain.id,
                    (
                        commitment.domain_height,
                        commitment.state_root,
                        *claim_digest,
                    ),
                );
                Ok(*claim_digest)
            }
            FinalityStatus::Rejected(reason) => Err(FinalityError(reason)),
            FinalityStatus::Pending { .. } => Err(FinalityError(
                "AggregatedProg finality proof remained pending".into(),
            )),
        }
    }

    /// True if `(domain_id, height, state_root)` was certified by a verified
    /// `Claim::Prog` still present in `verified_prog_digests`.
    #[must_use]
    pub fn has_certified_claim(
        &self,
        domain_id: DomainId,
        height: u64,
        state_root: Hash32,
    ) -> bool {
        self.certified_commitments
            .get(&domain_id)
            .is_some_and(|&(h, root, digest)| {
                h == height && root == state_root && self.verified_prog_digests.contains(&digest)
            })
    }

    /// Enforce finality floor and binding guarantees on a certificate row's `FinalityGuarantee`:
    /// only a commitment backed by a verified `Claim::Prog` in this adapter
    /// may carry `FinalityReversibility::CryptographicValidity` ("proven").
    /// Any `agg-claimed-program-finality` domain lacking a verified `Claim::Prog`
    /// cannot be promoted to proven and stays at voted/quorum level.
    #[must_use]
    pub fn certify_guarantee_for_domain(
        &self,
        domain: &ConsensusDomain,
        commitment: Option<&DomainCommitment>,
        mut base: crate::settlement::universal_finality::FinalityGuarantee,
    ) -> crate::settlement::universal_finality::FinalityGuarantee {
        use crate::crypto::facts::QuantumClass;
        use crate::settlement::universal_finality::{FinalityReversibility, FINALITY_BINDS_ALL};

        if domain.status == DomainStatus::Active {
            if let Some(c) = commitment {
                if c.domain_id == domain.id
                    && self.has_certified_claim(domain.id, c.domain_height, c.state_root)
                {
                    base.reversibility = FinalityReversibility::CryptographicValidity;
                    base.quantum_posture = QuantumClass::Hash;
                    base.attestation = FINALITY_BINDS_ALL;
                    if base.fault_tolerance_bps == 0 {
                        base.fault_tolerance_bps = 10_000;
                    }
                    return base;
                }
            }
        }
        // Fail-closed: a non-active domain or an aggregated-claim domain lacking
        // a matching verified Claim::Prog cannot claim CryptographicValidity.
        if (domain.status != DomainStatus::Active || domain.finality_adapter == self.adapter_name())
            && base.reversibility == FinalityReversibility::CryptographicValidity
        {
            base.reversibility = FinalityReversibility::DeterministicQuorum;
        }
        base
    }

    /// Verifies `frame` against `backend` (and validator bonds in `accounts`
    /// when `backend.requires_bonded_aggregators()` is true) for this adapter's
    /// `claim_domain`, then admits every [`Claim::Prog`] inside the verified
    /// `MasterProof`.
    ///
    /// # Errors
    ///
    /// Returns [`AggError`] if any segment aggregator is unbonded/unauthorized
    /// or if `backend.verify(frame, self.claim_domain)` rejects the frame; no
    /// claims are admitted on failure.
    pub fn admit_verified_frame<B: AggBackend>(
        &mut self,
        accounts: &crate::core::account::AccountState,
        backend: &B,
        frame: &ClaimFrame,
    ) -> Result<usize, AggError> {
        if backend.requires_bonded_aggregators() {
            super::fraud::verify_bonded_segment_aggregators(
                accounts,
                u64::from(self.claim_domain),
                frame,
            )?;
        }
        backend.verify(frame, self.claim_domain)?;
        let pinned: BTreeSet<Hash32> = self
            .certified_commitments
            .values()
            .map(|&(_, _, digest)| digest)
            .collect();
        let mut added = 0usize;
        for claim in &frame.claims {
            if !matches!(claim, Claim::Prog { .. }) {
                continue;
            }
            let digest = claim.digest(self.claim_domain);
            if self.verified_prog_digests.contains(&digest) {
                continue;
            }
            if self.verified_prog_digests.len() >= MAX_VERIFIED_PROG_DIGESTS {
                let victim = self
                    .verified_prog_digests
                    .iter()
                    .find(|cand| !pinned.contains(*cand))
                    .copied();
                let Some(evict) = victim else {
                    break;
                };
                self.verified_prog_digests.remove(&evict);
            }
            if self.verified_prog_digests.insert(digest) {
                added += 1;
            }
        }
        Ok(added)
    }
}

impl DomainFinalityAdapter for ClaimedDomainFinalityAdapter {
    fn adapter_name(&self) -> &'static str {
        "agg-claimed-program-finality"
    }

    fn verify_finality(
        &self,
        domain: &ConsensusDomain,
        commitment: &DomainCommitment,
        proof: &FinalityProof,
    ) -> Result<FinalityStatus, FinalityError> {
        let FinalityProof::AggregatedProg {
            program_hash,
            prev_height,
            prev_state_root,
            claim_digest,
        } = proof
        else {
            return Err(FinalityError(
                "Expected AggregatedProg finality proof".into(),
            ));
        };

        if domain.status != DomainStatus::Active {
            return Ok(FinalityStatus::Rejected(format!(
                "domain {} is not Active (status {:?})",
                domain.id, domain.status
            )));
        }

        if commitment.domain_id != domain.id {
            return Ok(FinalityStatus::Rejected(format!(
                "commitment domain_id {} does not match registered domain {}",
                commitment.domain_id, domain.id
            )));
        }

        if *program_hash == [0u8; 32] {
            return Ok(FinalityStatus::Rejected(
                "transition program_hash must be non-zero".into(),
            ));
        }

        if *prev_state_root == [0u8; 32]
            || commitment.state_root == [0u8; 32]
            || commitment.domain_block_hash == [0u8; 32]
        {
            return Ok(FinalityStatus::Rejected(
                "domain transition commitment roots and block hash must be non-zero".into(),
            ));
        }

        if commitment.domain_block_hash == commitment.parent_domain_block_hash {
            return Ok(FinalityStatus::Rejected(
                "domain_block_hash must differ from parent_domain_block_hash".into(),
            ));
        }

        if commitment.domain_height <= *prev_height {
            return Ok(FinalityStatus::Rejected(format!(
                "domain commitment height {} is not strictly above prev_height {}",
                commitment.domain_height, prev_height
            )));
        }

        if let Some((tip_height, tip_root)) = self.finalized_tips.get(&domain.id) {
            if prev_height != tip_height || prev_state_root != tip_root {
                return Ok(FinalityStatus::Rejected(format!(
                    "AggregatedProg predecessor (height {prev_height}) does not connect to finalized domain tip (height {tip_height})"
                )));
            }
        } else {
            if *prev_height != domain.last_committed_height {
                return Ok(FinalityStatus::Rejected(format!(
                    "AggregatedProg prev_height {prev_height} does not match domain.last_committed_height {}",
                    domain.last_committed_height
                )));
            }
            if domain.last_committed_height == 0
                && domain.genesis_state_root != [0u8; 32]
                && *prev_state_root != domain.genesis_state_root
            {
                return Ok(FinalityStatus::Rejected(
                    "AggregatedProg genesis prev_state_root does not match domain.genesis_state_root"
                        .into(),
                ));
            }
        }

        let registered = self.registered_programs.get(&domain.id);
        let allowlisted = domain.zk_program_allowlist.contains(program_hash);
        if let Some(expected_prog) = registered {
            if expected_prog != program_hash {
                return Ok(FinalityStatus::Rejected(
                    "transition program_hash does not match registered domain program".into(),
                ));
            }
            if !domain.zk_program_allowlist.is_empty() && !allowlisted {
                return Ok(FinalityStatus::Rejected(
                    "transition program_hash is not in domain.zk_program_allowlist".into(),
                ));
            }
        } else if !allowlisted {
            return Ok(FinalityStatus::Rejected(format!(
                "no transition program registered or allowlisted for domain {}",
                domain.id
            )));
        }

        let expected_claim = domain_transition_claim(
            *program_hash,
            domain,
            *prev_height,
            prev_state_root,
            commitment,
        );
        let expected_digest = expected_claim.digest(self.claim_domain);
        if expected_digest != *claim_digest {
            return Ok(FinalityStatus::Rejected(
                "AggregatedProg claim_digest does not match commitment transition".into(),
            ));
        }

        if !self.verified_prog_digests.contains(&expected_digest) {
            return Ok(FinalityStatus::Rejected(
                "AggregatedProg claim is not present in any verified MasterProof".into(),
            ));
        }

        Ok(FinalityStatus::Finalized)
    }

    fn observed_schemes(&self, proof: &FinalityProof) -> Vec<ObservedScheme> {
        if matches!(proof, FinalityProof::AggregatedProg { .. }) {
            vec![ObservedScheme::Proof(AssumptionClass::Hash)]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregation::backend::TickCtx;
    use crate::aggregation::frame::FrameLimits;
    use crate::aggregation::pool::PoolItem;
    use crate::core::account::AccountState;
    use crate::crypto::facts::QuantumClass;
    use crate::domain::types::{ConsensusKind, RootScheme};
    use crate::settlement::universal_finality::{
        FinalityGuarantee, FinalityReversibility, FINALITY_BINDS_ALL,
    };
    use zeroize::Zeroizing;

    const TEST_CLAIM_DOMAIN: DomainId = 45_262;

    struct StructuralTestBackend;
    impl AggBackend for StructuralTestBackend {
        fn prove_tick(&self, _ctx: &TickCtx, _items: &[PoolItem]) -> Result<ClaimFrame, AggError> {
            Err(AggError::MalformedProof)
        }
        fn prove_merge(
            &self,
            _left: &ClaimFrame,
            _right: &ClaimFrame,
        ) -> Result<Vec<u8>, AggError> {
            Err(AggError::MalformedProof)
        }
        fn verify(&self, frame: &ClaimFrame, domain: DomainId) -> Result<(), AggError> {
            frame.check_structure(
                domain,
                &FrameLimits {
                    max_claims: 65_536,
                    max_proof_bytes: 16 * 1024 * 1024,
                },
            )?;
            Ok(())
        }
    }

    fn test_domain(program_hash: Hash32) -> ConsensusDomain {
        ConsensusDomain {
            id: 77,
            kind: ConsensusKind::Zk,
            status: DomainStatus::Active,
            domain_chain_id: 42_161,
            operator: None,
            operator_bond: 0,
            config_hash: [0x55; 32],
            validator_set_hash: [0x66; 32],
            finality_adapter: "agg-claimed-program-finality".into(),
            min_confirmations: 1,
            bridge_enabled: true,
            block_hash_scheme: RootScheme::Sha256,
            state_root_scheme: RootScheme::Sha256,
            tx_root_scheme: RootScheme::Sha256,
            last_committed_height: 10,
            last_committed_hash: [0x11; 32],
            pow_parameters: None,
            zk_program_allowlist: vec![program_hash],
            plugin_code_hash: None,
            genesis_state_root: [0x11; 32],
        }
    }

    fn test_commitment(height: u64, state_root: Hash32) -> DomainCommitment {
        DomainCommitment {
            domain_id: 77,
            domain_height: height,
            domain_block_hash: [0x44; 32],
            parent_domain_block_hash: [0x43; 32],
            state_root,
            tx_root: [0x22; 32],
            event_root: [0x33; 32],
            finality_proof_hash: [0x55; 32],
            consensus_kind: ConsensusKind::Zk,
            validator_set_hash: [0x66; 32],
            timestamp_ms: 1_750_000_000_000,
            sequence: height,
            producer: None,
            state_updates: BTreeMap::new(),
        }
    }

    #[test]
    fn non_active_domains_cannot_finalize_or_claim_cryptographic_validity() {
        let mut adapter = ClaimedDomainFinalityAdapter::new(TEST_CLAIM_DOMAIN);
        let prog_hash = [0xAB; 32];
        let mut domain = test_domain(prog_hash);
        adapter.register_domain_program(domain.id, prog_hash);
        let prev_height = 10u64;
        let prev_root = [0x11; 32];
        let commitment = test_commitment(11, [0x22; 32]);
        let claim =
            domain_transition_claim(prog_hash, &domain, prev_height, &prev_root, &commitment);
        let claim_digest = claim.digest(TEST_CLAIM_DOMAIN);
        let agg_seed = Zeroizing::new([0x51u8; 32]);
        let frame =
            ClaimFrame::tick(TEST_CLAIM_DOMAIN, &agg_seed, vec![claim], Vec::new()).unwrap();
        adapter
            .admit_verified_frame(&AccountState::new(), &StructuralTestBackend, &frame)
            .unwrap();

        let proof = FinalityProof::AggregatedProg {
            program_hash: prog_hash,
            prev_height,
            prev_state_root: prev_root,
            claim_digest,
        };
        for status in [DomainStatus::Frozen, DomainStatus::Retired] {
            domain.status = status;
            assert!(matches!(
                adapter
                    .verify_finality(&domain, &commitment, &proof)
                    .unwrap(),
                FinalityStatus::Rejected(_)
            ));
            assert!(adapter
                .verify_and_certify_commitment(&domain, &commitment, &proof)
                .is_err());
        }

        domain.status = DomainStatus::Active;
        adapter
            .verify_and_certify_commitment(&domain, &commitment, &proof)
            .expect("active domain certifies");
        let base = FinalityGuarantee {
            reversibility: FinalityReversibility::CryptographicValidity,
            quantum_posture: QuantumClass::Hash,
            attestation: FINALITY_BINDS_ALL,
            slashable_backing: true,
            fault_tolerance_bps: 10_000,
        };
        assert_eq!(
            adapter
                .certify_guarantee_for_domain(&domain, Some(&commitment), base)
                .reversibility,
            FinalityReversibility::CryptographicValidity
        );

        domain.status = DomainStatus::Frozen;
        assert_eq!(
            adapter
                .certify_guarantee_for_domain(&domain, Some(&commitment), base)
                .reversibility,
            FinalityReversibility::DeterministicQuorum
        );
    }

    #[test]
    fn zero_hashes_self_parent_historical_replay_and_tip_regressions_are_rejected() {
        let mut adapter = ClaimedDomainFinalityAdapter::new(TEST_CLAIM_DOMAIN);
        let zero = [0u8; 32];
        adapter.register_domain_program(77, zero);
        assert!(adapter.is_empty());

        let mut domain = test_domain(zero);
        let prev_root = [0x11; 32];
        let mut bad_comm = test_commitment(11, [0x22; 32]);
        let agg_seed = Zeroizing::new([0x52u8; 32]);

        let zclaim = domain_transition_claim(zero, &domain, 10, &prev_root, &bad_comm);
        let zdigest = zclaim.digest(TEST_CLAIM_DOMAIN);
        let zframe =
            ClaimFrame::tick(TEST_CLAIM_DOMAIN, &agg_seed, vec![zclaim], Vec::new()).unwrap();
        adapter
            .admit_verified_frame(&AccountState::new(), &StructuralTestBackend, &zframe)
            .unwrap();
        assert!(matches!(
            adapter
                .verify_finality(
                    &domain,
                    &bad_comm,
                    &FinalityProof::AggregatedProg {
                        program_hash: zero,
                        prev_height: 10,
                        prev_state_root: prev_root,
                        claim_digest: zdigest,
                    },
                )
                .unwrap(),
            FinalityStatus::Rejected(_)
        ));

        let prog = [0x77; 32];
        domain.zk_program_allowlist = vec![prog];
        adapter.register_domain_program(77, prog);

        // Self-parent block hash cycle rejected.
        bad_comm.parent_domain_block_hash = bad_comm.domain_block_hash;
        let c_cycle = domain_transition_claim(prog, &domain, 10, &prev_root, &bad_comm);
        let d_cycle = c_cycle.digest(TEST_CLAIM_DOMAIN);
        let f_cycle =
            ClaimFrame::tick(TEST_CLAIM_DOMAIN, &agg_seed, vec![c_cycle], Vec::new()).unwrap();
        adapter
            .admit_verified_frame(&AccountState::new(), &StructuralTestBackend, &f_cycle)
            .unwrap();
        assert!(matches!(
            adapter
                .verify_finality(
                    &domain,
                    &bad_comm,
                    &FinalityProof::AggregatedProg {
                        program_hash: prog,
                        prev_height: 10,
                        prev_state_root: prev_root,
                        claim_digest: d_cycle,
                    },
                )
                .unwrap(),
            FinalityStatus::Rejected(_)
        ));

        // Historical transition replay (`prev_height = 2` on `last_committed_height = 10`) rejected.
        let hist_comm = test_commitment(3, [0xDD; 32]);
        let c_hist = domain_transition_claim(prog, &domain, 2, &prev_root, &hist_comm);
        let d_hist = c_hist.digest(TEST_CLAIM_DOMAIN);
        let f_hist =
            ClaimFrame::tick(TEST_CLAIM_DOMAIN, &agg_seed, vec![c_hist], Vec::new()).unwrap();
        adapter
            .admit_verified_frame(&AccountState::new(), &StructuralTestBackend, &f_hist)
            .unwrap();
        assert!(matches!(
            adapter
                .verify_finality(
                    &domain,
                    &hist_comm,
                    &FinalityProof::AggregatedProg {
                        program_hash: prog,
                        prev_height: 2,
                        prev_state_root: prev_root,
                        claim_digest: d_hist,
                    },
                )
                .unwrap(),
            FinalityStatus::Rejected(_)
        ));

        // Height regression and same-height root overwrite in `record_finalized_tip` ignored.
        adapter.record_finalized_tip(77, 15, [0xAA; 32]);
        adapter.record_finalized_tip(77, 15, zero);
        adapter.record_finalized_tip(77, 15, [0xBB; 32]);
        adapter.record_finalized_tip(77, 5, [0xBB; 32]);
        assert_eq!(adapter.finalized_tips.get(&77), Some(&(15, [0xAA; 32])));
    }

    #[test]
    fn verified_prog_digests_stays_bounded_and_preserves_certified_commitments() {
        let mut adapter = ClaimedDomainFinalityAdapter::new(TEST_CLAIM_DOMAIN);
        let prog = [0x99; 32];
        let domain = test_domain(prog);
        adapter.register_domain_program(domain.id, prog);
        let prev_root = [0x11; 32];
        let cert_comm = test_commitment(11, [0x22; 32]);
        let cert_claim = domain_transition_claim(prog, &domain, 10, &prev_root, &cert_comm);
        let cert_digest = cert_claim.digest(TEST_CLAIM_DOMAIN);
        let agg_seed = Zeroizing::new([0x53u8; 32]);
        let cert_frame =
            ClaimFrame::tick(TEST_CLAIM_DOMAIN, &agg_seed, vec![cert_claim], Vec::new()).unwrap();
        adapter
            .admit_verified_frame(&AccountState::new(), &StructuralTestBackend, &cert_frame)
            .unwrap();
        adapter
            .verify_and_certify_commitment(
                &domain,
                &cert_comm,
                &FinalityProof::AggregatedProg {
                    program_hash: prog,
                    prev_height: 10,
                    prev_state_root: prev_root,
                    claim_digest: cert_digest,
                },
            )
            .expect("certify commitment");

        for batch in 0u32..5 {
            let mut claims = Vec::with_capacity(4_000);
            for i in 0u32..4_000 {
                let mut out = [0u8; 32];
                out[0..4].copy_from_slice(&batch.to_le_bytes());
                out[4..8].copy_from_slice(&i.to_le_bytes());
                out[31] = 1;
                claims.push(Claim::Prog {
                    program_hash: prog,
                    input_hash: [0x88; 32],
                    output_hash: out,
                });
            }
            let frame = ClaimFrame::tick(TEST_CLAIM_DOMAIN, &agg_seed, claims, Vec::new()).unwrap();
            adapter
                .admit_verified_frame(&AccountState::new(), &StructuralTestBackend, &frame)
                .unwrap();
        }

        assert_eq!(
            adapter.verified_prog_digests.len(),
            MAX_VERIFIED_PROG_DIGESTS
        );
        assert!(
            adapter.has_certified_claim(domain.id, 11, [0x22; 32]),
            "pinned certified commitment digest must survive bounded eviction"
        );
    }
}
