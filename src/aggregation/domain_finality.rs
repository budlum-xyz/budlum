//! Phase 4 domain state-transition claims and [`ClaimedDomainFinalityAdapter`].
//!
//! WIRING: unwired - Phase 4 domain-transition prover and adapter surface;
//! external rollup provers produce `ObjectKind::StarkProof` envelopes for
//! `agg/object`, and settlement nodes wire `ClaimedDomainFinalityAdapter` into
//! their domain registry once a block's `MasterProof` passes `StarkBackend::verify`.
//!
//! Each domain's state-transition STARK proof enters the aggregation layer as
//! an `ObjectKind::StarkProof` envelope and collapses into:
//!
//! ```text
//! Claim::Prog {
//!     program_hash: domain_transition_program_hash,
//!     input_hash:   H("BDLM_DOM_TRANS_IN_V1"  || domain_id || domain_chain_id || prev_height || prev_state_root),
//!     output_hash:  H("BDLM_DOM_TRANS_OUT_V1" || domain_id || new_height || state_root || tx_root || event_root || block_hash),
//! }
//! ```
//!
//! Once aggregated into a block's `MasterProof` (`ClaimFrame`),
//! [`ClaimedDomainFinalityAdapter`] implements [`DomainFinalityAdapter`] and
//! reads finality directly from the verified `Claim::Prog` without re-verifying
//! the underlying domain transition STARK.
//!

use std::collections::{BTreeMap, BTreeSet};

use bud_vm::{poseidon4_hash, Vm};

use super::backend::{AggBackend, AggError};
use super::claim::Claim;
use super::frame::ClaimFrame;
use super::hash::h;
use super::programs::agg_merge::program_hash_of;
use super::programs::asm::{Asm, Program, R};
use super::programs::prog_claim::{
    emit_swrite_digest_cells, prove_vm_program, write_cell, write_digest_cells, ProgClaimError,
    StarkProofObject, DIGEST_LIMBS, DIGEST_LIMBS_U32,
};
use crate::crypto::facts::{AssumptionClass, ObservedScheme};
use crate::domain::finality_adapter::{
    DomainFinalityAdapter, FinalityError, FinalityProof, FinalityStatus,
};
use crate::domain::types::{ConsensusDomain, DomainCommitment, DomainId, Hash32};

/// Domain tag for the pre-state input commitment of a domain transition claim.
pub const TAG_DOMAIN_TRANSITION_IN: &[u8] = b"BDLM_DOM_TRANS_IN_V1";
/// Domain tag for the post-state output commitment of a domain transition claim.
pub const TAG_DOMAIN_TRANSITION_OUT: &[u8] = b"BDLM_DOM_TRANS_OUT_V1";

/// Goldilocks fold tag for collapsing a 32-byte state root inside `BudVM`.
const STATE_FOLD_TAG: u64 = 0x4244_4C4D_444F_4D31;

/// Canonical `input_hash` of a domain state-transition [`Claim::Prog`].
#[must_use]
pub fn domain_transition_input_hash(
    domain: &ConsensusDomain,
    prev_height: u64,
    prev_state_root: &Hash32,
) -> Hash32 {
    h(&[
        TAG_DOMAIN_TRANSITION_IN,
        &domain.id.to_be_bytes(),
        &domain.domain_chain_id.to_be_bytes(),
        &prev_height.to_be_bytes(),
        prev_state_root,
    ])
}

/// Canonical `output_hash` of a domain state-transition [`Claim::Prog`].
#[must_use]
pub fn domain_transition_output_hash(
    domain: &ConsensusDomain,
    commitment: &DomainCommitment,
) -> Hash32 {
    h(&[
        TAG_DOMAIN_TRANSITION_OUT,
        &domain.id.to_be_bytes(),
        &commitment.domain_height.to_be_bytes(),
        &commitment.state_root,
        &commitment.tx_root,
        &commitment.event_root,
        &commitment.domain_block_hash,
    ])
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

/// Folds a 32-byte digest into one Goldilocks field element via Poseidon
/// (matching the in-VM state transition check).
#[must_use]
fn fold_root_goldilocks(root: &Hash32) -> u64 {
    let mut acc = STATE_FOLD_TAG;
    for chunk in root.chunks_exact(4) {
        let limb = u64::from(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        acc = poseidon4_hash(acc, limb);
    }
    acc
}

/// Computes the deterministic next-state Poseidon commitment checked inside
/// the sample domain state-transition `BudVM` program.
#[must_use]
fn transition_state_commitment(
    domain_id: DomainId,
    domain_chain_id: u64,
    prev_state_root: &Hash32,
    batch_digest: &Hash32,
    new_height: u64,
) -> u64 {
    let prev_fold = fold_root_goldilocks(prev_state_root);
    let batch_fold = fold_root_goldilocks(batch_digest);
    let step1 = poseidon4_hash(prev_fold, batch_fold);
    let step2 = poseidon4_hash(step1, u64::from(domain_id));
    let step3 = poseidon4_hash(step2, domain_chain_id);
    poseidon4_hash(step3, new_height)
}

/// Memory layout for [`DomainTransitionProgram`].
#[derive(Debug, Clone, Copy)]
struct TransitionCells {
    prev_height: u64,
    new_height: u64,
    prev_root_limbs: u64,
    batch_limbs: u64,
    expected_commit: u64,
    input_hash: u64,
    output_hash: u64,
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
/// The guest checks:
/// 1. `new_height > prev_height` (strict height progression).
/// 2. `transition_state_commitment(domain_id, domain_chain_id, prev_root, batch, new_height) == expected_commit`.
/// 3. Publishes `input_hash` and `output_hash` to `SWrite[0..16]`.
///
/// # Errors
///
/// Returns [`ProgClaimError`] if `domain_chain_id` exceeds the Goldilocks
/// modulus or guest assembly fails.
pub fn compile_domain_transition(
    domain_id: DomainId,
    domain_chain_id: u64,
) -> Result<DomainTransitionProgram, ProgClaimError> {
    let mut a = Asm::new();
    let cells = TransitionCells {
        prev_height: a.alloc(1),
        new_height: a.alloc(1),
        prev_root_limbs: a.alloc(DIGEST_LIMBS as u64),
        batch_limbs: a.alloc(DIGEST_LIMBS as u64),
        expected_commit: a.alloc(1),
        input_hash: a.alloc(DIGEST_LIMBS as u64),
        output_hash: a.alloc(DIGEST_LIMBS as u64),
    };

    // 1. Assert strict height monotonicity: prev_height < new_height.
    a.region("check_height");
    a.load_abs(R[1], cells.prev_height);
    a.load_abs(R[2], cells.new_height);
    a.lt(R[3], R[1], R[2]);
    a.assert(R[3]);

    // 2. Fold prev_state_root and batch_digest in-VM via Opcode::Poseidon.
    a.region("check_state_transition");
    a.li(R[4], STATE_FOLD_TAG);
    for i in 0..DIGEST_LIMBS as u64 {
        a.load_abs(R[5], cells.prev_root_limbs + i);
        a.poseidon(R[4], R[4], R[5]);
    }
    a.li(R[6], STATE_FOLD_TAG);
    for i in 0..DIGEST_LIMBS as u64 {
        a.load_abs(R[5], cells.batch_limbs + i);
        a.poseidon(R[6], R[6], R[5]);
    }
    a.poseidon(R[7], R[4], R[6]);
    a.li(R[8], u64::from(domain_id));
    a.poseidon(R[7], R[7], R[8]);
    a.li(R[9], domain_chain_id);
    a.poseidon(R[7], R[7], R[9]);
    a.poseidon(R[7], R[7], R[2]); // R[2] = new_height

    a.load_abs(R[10], cells.expected_commit);
    a.eq(R[11], R[7], R[10]);
    a.assert(R[11]);

    // 3. Publish (input_hash, output_hash) to SWrite[0..16].
    a.region("publish_transition_io");
    emit_swrite_digest_cells(&mut a, cells.input_hash, 0);
    emit_swrite_digest_cells(&mut a, cells.output_hash, DIGEST_LIMBS_U32);
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
/// Returns [`ProgClaimError`] if the domain mismatches, the transition
/// assertion fails, or STARK proving fails.
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
    let expected_commit = transition_state_commitment(
        domain.id,
        domain.domain_chain_id,
        prev_state_root,
        batch_digest,
        commitment.domain_height,
    );

    let mem_bytes = usize::try_from(compiled.program.memory_cells)
        .unwrap_or(0)
        .saturating_add(16)
        .saturating_mul(8);
    let mut vm = Vm::new(mem_bytes.max(4096));
    write_cell(&mut vm, compiled.cells.prev_height, prev_height);
    write_cell(&mut vm, compiled.cells.new_height, commitment.domain_height);
    write_digest_cells(&mut vm, compiled.cells.prev_root_limbs, prev_state_root);
    write_digest_cells(&mut vm, compiled.cells.batch_limbs, batch_digest);
    write_cell(&mut vm, compiled.cells.expected_commit, expected_commit);
    write_digest_cells(&mut vm, compiled.cells.input_hash, &input_hash);
    write_digest_cells(&mut vm, compiled.cells.output_hash, &output_hash);

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
/// can enter `verified_prog_digests`. Finalizing a [`DomainCommitment`] reads
/// the pre-verified `Claim::Prog` digest in O(log n) without re-verifying the
/// underlying STARK proof.
#[derive(Debug, Clone)]
pub struct ClaimedDomainFinalityAdapter {
    claim_domain: DomainId,
    registered_programs: BTreeMap<DomainId, Hash32>,
    verified_prog_digests: BTreeSet<Hash32>,
}

impl ClaimedDomainFinalityAdapter {
    /// Creates an empty adapter scoped to the aggregation `claim_domain`.
    #[must_use]
    pub const fn new(claim_domain: DomainId) -> Self {
        Self {
            claim_domain,
            registered_programs: BTreeMap::new(),
            verified_prog_digests: BTreeSet::new(),
        }
    }

    /// Registers the canonical state-transition `program_hash` for `domain_id`.
    pub fn register_domain_program(&mut self, domain_id: DomainId, program_hash: Hash32) {
        self.registered_programs.insert(domain_id, program_hash);
    }

    /// Verifies `frame` against `backend` for this adapter's `claim_domain` and
    /// admits every [`Claim::Prog`] inside the verified `MasterProof`.
    ///
    /// # Errors
    ///
    /// Returns [`AggError`] if `backend.verify(frame, self.claim_domain)` rejects
    /// the frame; no claims are admitted on failure.
    pub fn admit_verified_frame<B: AggBackend>(
        &mut self,
        backend: &B,
        frame: &ClaimFrame,
    ) -> Result<usize, AggError> {
        backend.verify(frame, self.claim_domain)?;
        let mut added = 0usize;
        for claim in &frame.claims {
            if matches!(claim, Claim::Prog { .. })
                && self
                    .verified_prog_digests
                    .insert(claim.digest(self.claim_domain))
            {
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

        if commitment.domain_height <= *prev_height {
            return Ok(FinalityStatus::Rejected(format!(
                "domain commitment height {} is not strictly above prev_height {}",
                commitment.domain_height, prev_height
            )));
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
