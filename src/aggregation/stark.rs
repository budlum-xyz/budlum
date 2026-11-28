//! Production STARK proving backend (`StarkBackend`, Phase 3).
//!
//! Unlike the devnet-only native backend, `StarkBackend` is compiled in every
//! profile including production builds and produces compact 128-bit provable
//! Plonky3 Goldilocks/Keccak STARK proofs (`AggFoldAir`) binding every tree
//! step's allowlisted program hash (`{agg_tick_program_hash(),
//! agg_merge_program_hash()}`), `tick_pi`, recursive `merge_pi`, `domain`,
//! `parameter_set`, `master_pi`, recursion level and child verifier-key digest.
//! The versioned `RecursiveProofEnvelope` carries that context and the AIR's
//! public challenges commit to the statement digest.
//!
//! Every `AggMerge` step enforces the Phase 3 program-hash allowlist
//! `{agg_tick_program_hash(), agg_merge_program_hash()}` both in Rust before
//! merging and algebraically inside `AggFoldAir`: a proof carrying any other
//! program hash is refused before merging or verification.
//!
//! WIRING: `ChainBackend` dispatches directly to `StarkBackend` in all
//! production builds (without the devnet `agg-native-backend` feature).

use std::sync::OnceLock;

use bud_proof::adapter::PROOF_FORMAT_VERSION;
use bud_proof::chips::fold::{
    prove_agg_fold, verify_agg_fold, AggFoldProof, AggFoldPublic, AggFoldStep, MAX_FOLD_STEPS,
};
use bud_proof::plonky3_prover::ChipProof;
use bud_proof::recursive_envelope::{
    RecursiveProofContext, RecursiveProofEnvelope, MAX_RECURSION_LEVEL,
};

use super::backend::{AggBackend, AggError, TickCtx};
use super::claim::Claim;
use super::frame::{
    aggregator_address_from_seed, merge_pi, tick_pi, verify_segment_attestations, AggProgram,
    ClaimFrame, FrameError, FrameLimits, Segment, SHAPE_MERGE, SHAPE_TICK,
};
use super::hash::{h, TAG_AGG_MERGE, TAG_AGG_TICK};
use super::object::derive_claim;
use super::pool::PoolItem;
use super::programs::agg_merge::{agg_merge, program_hash_of};
use super::programs::agg_tick::agg_tick;
use super::programs::chain_rules;
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::domain::types::{DomainId, Hash32};

/// Protocol tag for the transparent `AggFoldAir` verification-key descriptor.
const AGG_FOLD_VK_TAG: &[u8] = b"BDLM_AGG_FOLD_VK_V1";
/// Domain separator for the complete recursive fold statement.
const AGG_FOLD_STATEMENT_TAG: &[u8] = b"BDLM_AGG_FOLD_STMT_V2";

/// Canonical parameter set id for `StarkBackend` (distinct from devnet native id 1).
pub const STARK_PARAMETER_SET: u32 = 2;

static TICK_PROGRAM_HASH: OnceLock<Hash32> = OnceLock::new();
static MERGE_PROGRAM_HASH: OnceLock<Hash32> = OnceLock::new();

/// Canonical `BudZKVM` program hash of `AggTick` under [`chain_rules`].
#[must_use]
pub fn agg_tick_program_hash() -> Hash32 {
    *TICK_PROGRAM_HASH.get_or_init(|| {
        let rules = chain_rules();
        match agg_tick(&rules, 1) {
            Ok(tick) => program_hash_of(&tick.program.code),
            Err(_) => h(&[TAG_AGG_TICK, b"FALLBACK"]),
        }
    })
}

/// Canonical `BudZKVM` program hash of `AggMerge` bound to [`agg_tick_program_hash`].
#[must_use]
pub fn agg_merge_program_hash() -> Hash32 {
    *MERGE_PROGRAM_HASH.get_or_init(|| {
        let tick_hash = agg_tick_program_hash();
        match agg_merge(&tick_hash) {
            Ok(merge) => merge.self_program_hash,
            Err(_) => h(&[TAG_AGG_MERGE, &tick_hash]),
        }
    })
}

/// Returns whether `program_hash` belongs to the Phase 3 recursive allowlist
/// `{agg_tick_program_hash(), agg_merge_program_hash()}`.
#[must_use]
pub fn is_allowed_agg_program(program_hash: &Hash32) -> bool {
    *program_hash == agg_tick_program_hash() || *program_hash == agg_merge_program_hash()
}

/// Digest of the transparent child verifier key used by recursive aggregation.
///
/// `AggFoldAir` has no secret setup key: its verifier key is the versioned AIR,
/// consensus parameter set, fold bound and canonical child-program allowlist.
/// Domain is separately committed in every statement and envelope.
#[must_use]
pub fn agg_fold_child_verification_key_hash(parameter_set: u32) -> Hash32 {
    let version = PROOF_FORMAT_VERSION.to_be_bytes();
    let max_steps = u32::try_from(MAX_FOLD_STEPS)
        .unwrap_or(u32::MAX)
        .to_be_bytes();
    let tick = agg_tick_program_hash();
    let merge = agg_merge_program_hash();
    let mut descriptor = Vec::with_capacity(
        AGG_FOLD_VK_TAG.len() + version.len() + 4 + max_steps.len() + tick.len() + merge.len(),
    );
    descriptor.extend_from_slice(AGG_FOLD_VK_TAG);
    descriptor.extend_from_slice(&version);
    descriptor.extend_from_slice(&parameter_set.to_be_bytes());
    descriptor.extend_from_slice(&max_steps);
    descriptor.extend_from_slice(&tick);
    descriptor.extend_from_slice(&merge);
    h(&[&descriptor])
}

/// Production STARK proving and verifying backend.
#[derive(Debug, Clone)]
pub struct StarkBackend {
    registry: SchemeStatusRegistry,
    limits: FrameLimits,
    parameter_set: u32,
}

impl StarkBackend {
    /// Creates a `StarkBackend` under `registry`, `limits`, and `parameter_set`.
    /// Two backends with different `parameter_set` values refuse each other's proofs.
    #[must_use]
    pub const fn new(
        registry: SchemeStatusRegistry,
        limits: FrameLimits,
        parameter_set: u32,
    ) -> Self {
        Self {
            registry,
            limits,
            parameter_set,
        }
    }
}

struct DecodedStarkProof {
    envelope: RecursiveProofEnvelope,
    fold_proof: AggFoldProof,
}

fn encode_stark_proof(
    parameter_set: u32,
    domain: DomainId,
    program_hash: &Hash32,
    public_input: &Hash32,
    recursion_level: u32,
    child_verification_key_hash: &Hash32,
    statement_digest: &Hash32,
    fold_proof: &AggFoldProof,
) -> Result<Vec<u8>, AggError> {
    let num_steps = u32::try_from(fold_proof.num_steps).map_err(|_| AggError::MalformedProof)?;
    let proof_bytes =
        postcard::to_allocvec(&fold_proof.proof).map_err(|_| AggError::MalformedProof)?;
    let envelope = RecursiveProofEnvelope {
        proof_format_version: PROOF_FORMAT_VERSION,
        recursion_level,
        child_verification_key_hash: *child_verification_key_hash,
        parameter_set,
        domain,
        program_hash: *program_hash,
        public_input: *public_input,
        statement_digest: *statement_digest,
        num_steps,
        proof_bytes,
    };
    envelope.to_bytes().map_err(|_| AggError::MalformedProof)
}

fn decode_stark_proof(bytes: &[u8]) -> Result<DecodedStarkProof, AggError> {
    let envelope =
        RecursiveProofEnvelope::from_bytes(bytes).map_err(|_| AggError::MalformedProof)?;
    let num_steps = usize::try_from(envelope.num_steps).map_err(|_| AggError::MalformedProof)?;
    if num_steps == 0 || num_steps > MAX_FOLD_STEPS {
        return Err(AggError::MalformedProof);
    }
    let proof: ChipProof =
        postcard::from_bytes(&envelope.proof_bytes).map_err(|_| AggError::MalformedProof)?;

    Ok(DecodedStarkProof {
        envelope,
        fold_proof: AggFoldProof { num_steps, proof },
    })
}

/// Computes the tree depth of a postfix fold shape. A leaf `AggTick` is
/// level zero; each parent merge is one level above its deepest child.
fn recursion_level_for_shape(shape: &[u8]) -> Result<u32, AggError> {
    if shape.is_empty() || shape.len() > MAX_FOLD_STEPS {
        return Err(AggError::Frame(FrameError::BadShape));
    }
    let mut stack = Vec::with_capacity(shape.len());
    for &op in shape {
        match op {
            SHAPE_TICK => stack.push(0u32),
            SHAPE_MERGE => {
                let right = stack.pop().ok_or(AggError::Frame(FrameError::BadShape))?;
                let left = stack.pop().ok_or(AggError::Frame(FrameError::BadShape))?;
                let level = left
                    .max(right)
                    .checked_add(1)
                    .ok_or(AggError::MalformedProof)?;
                if level > MAX_RECURSION_LEVEL {
                    return Err(AggError::MalformedProof);
                }
                stack.push(level);
            }
            _ => return Err(AggError::Frame(FrameError::BadShape)),
        }
    }
    let [level] = stack.as_slice() else {
        return Err(AggError::Frame(FrameError::BadShape));
    };
    Ok(*level)
}

/// Computes a canonical statement commitment over the recursion level, child
/// verifier-key digest, domain, shape, and every Segment. This digest feeds the
/// `AggFoldAir` challenge derivation, so changing metadata changes the proof.
fn compute_shape_digest(
    domain: DomainId,
    recursion_level: u32,
    child_verification_key_hash: &Hash32,
    segments: &[Segment],
    shape: &[u8],
) -> Hash32 {
    let mut buf = Vec::with_capacity(
        AGG_FOLD_STATEMENT_TAG.len()
            + 4
            + 4
            + 32
            + 4
            + shape.len()
            + 4
            + segments.len().saturating_mul(32 + 4 + 32),
    );
    buf.extend_from_slice(AGG_FOLD_STATEMENT_TAG);
    buf.extend_from_slice(&domain.to_be_bytes());
    buf.extend_from_slice(&recursion_level.to_be_bytes());
    buf.extend_from_slice(child_verification_key_hash);
    buf.extend_from_slice(&u32::try_from(shape.len()).unwrap_or(u32::MAX).to_be_bytes());
    buf.extend_from_slice(shape);
    buf.extend_from_slice(
        &u32::try_from(segments.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for seg in segments {
        buf.extend_from_slice(&seg.claims_root);
        buf.extend_from_slice(&seg.count.to_be_bytes());
        buf.extend_from_slice(seg.aggregator.as_bytes());
    }
    h(&[TAG_AGG_MERGE, &buf])
}

/// Walks `shape` in postfix order and constructs the exact [`AggFoldStep`]
/// trace and [`AggFoldPublic`] statement bound by `AggFoldAir`.
fn build_fold_statement(
    parameter_set: u32,
    domain: DomainId,
    segments: &[Segment],
    shape: &[u8],
) -> Result<(Vec<AggFoldStep>, AggFoldPublic, u32, Hash32), AggError> {
    if shape.is_empty() || shape.len() > MAX_FOLD_STEPS {
        return Err(AggError::Frame(FrameError::BadShape));
    }
    let tick_hash = agg_tick_program_hash();
    let merge_hash = agg_merge_program_hash();

    let mut steps = Vec::with_capacity(shape.len());
    let mut stack: Vec<(bool, Hash32)> = Vec::new();
    let mut seg_iter = segments.iter();

    for &op in shape {
        match op {
            SHAPE_TICK => {
                let seg = seg_iter
                    .next()
                    .ok_or(AggError::Frame(FrameError::BadShape))?;
                if seg.count == 0 {
                    return Err(AggError::Frame(FrameError::EmptySegment));
                }
                let pi = tick_pi(domain, seg);
                steps.push(AggFoldStep {
                    is_merge: false,
                    left_is_merge: false,
                    right_is_merge: false,
                    program_hash: tick_hash,
                    node_pi: pi,
                });
                stack.push((false, pi));
            }
            SHAPE_MERGE => {
                let (right_is_merge, right_pi) =
                    stack.pop().ok_or(AggError::Frame(FrameError::BadShape))?;
                let (left_is_merge, left_pi) =
                    stack.pop().ok_or(AggError::Frame(FrameError::BadShape))?;
                let pi = merge_pi(&left_pi, &right_pi);
                steps.push(AggFoldStep {
                    is_merge: true,
                    left_is_merge,
                    right_is_merge,
                    program_hash: merge_hash,
                    node_pi: pi,
                });
                stack.push((true, pi));
            }
            _ => return Err(AggError::Frame(FrameError::BadShape)),
        }
    }

    if seg_iter.next().is_some() {
        return Err(AggError::Frame(FrameError::BadShape));
    }
    let [(root_is_merge, master_pi)] = stack.as_slice() else {
        return Err(AggError::Frame(FrameError::BadShape));
    };
    let final_program_hash = if *root_is_merge {
        merge_hash
    } else {
        tick_hash
    };
    let step_count =
        u32::try_from(steps.len()).map_err(|_| AggError::Frame(FrameError::BadShape))?;
    let recursion_level = recursion_level_for_shape(shape)?;
    let child_verification_key_hash = if recursion_level == 0 {
        [0; 32]
    } else {
        agg_fold_child_verification_key_hash(parameter_set)
    };
    let shape_digest = compute_shape_digest(
        domain,
        recursion_level,
        &child_verification_key_hash,
        segments,
        shape,
    );

    let pub_stmt = AggFoldPublic {
        parameter_set,
        domain,
        tick_program_hash: tick_hash,
        merge_program_hash: merge_hash,
        final_program_hash,
        master_pi: *master_pi,
        shape_digest,
        step_count,
    };
    Ok((
        steps,
        pub_stmt,
        recursion_level,
        child_verification_key_hash,
    ))
}

impl AggBackend for StarkBackend {
    fn prove_tick(&self, ctx: &TickCtx, items: &[PoolItem]) -> Result<ClaimFrame, AggError> {
        let derived = aggregator_address_from_seed(&ctx.signer_seed)
            .map_err(|_| AggError::InvalidSegmentAttestation(0))?;
        if derived != ctx.aggregator {
            return Err(AggError::InvalidSegmentAttestation(0));
        }
        let mut keyed = Vec::with_capacity(items.len());
        for item in items {
            if item.envelope.domain != ctx.domain {
                return Err(AggError::WrongDomain);
            }
            if item.envelope.payload.is_empty() {
                return Err(AggError::PayloadPruned);
            }
            let derived_claim = derive_claim(&self.registry, &item.envelope)?;
            if derived_claim != item.claim {
                return Err(AggError::ProofMismatch);
            }
            keyed.push((item.claim.digest(ctx.domain), item.claim.clone()));
        }
        keyed.sort_unstable_by_key(|(digest, _)| *digest);
        let claims: Vec<Claim> = keyed.into_iter().map(|(_, claim)| claim).collect();
        if claims.len() > self.limits.max_claims {
            return Err(AggError::Frame(FrameError::TooManyClaims(claims.len())));
        }

        let provisional = ClaimFrame::tick(ctx.domain, &ctx.signer_seed, claims, Vec::new())?;
        let (steps, pub_stmt, recursion_level, child_verification_key_hash) = build_fold_statement(
            self.parameter_set,
            ctx.domain,
            &provisional.segments,
            &provisional.shape,
        )?;
        let fold_proof = prove_agg_fold(&steps, &pub_stmt).map_err(|_| AggError::MalformedProof)?;
        let proof_bytes = encode_stark_proof(
            self.parameter_set,
            ctx.domain,
            &pub_stmt.final_program_hash,
            &pub_stmt.master_pi,
            recursion_level,
            &child_verification_key_hash,
            &pub_stmt.shape_digest,
            &fold_proof,
        )?;
        if proof_bytes.len() > self.limits.max_proof_bytes {
            return Err(AggError::Frame(FrameError::ProofTooLarge(
                proof_bytes.len(),
            )));
        }

        Ok(ClaimFrame {
            segments: provisional.segments,
            shape: provisional.shape,
            claims: provisional.claims,
            proof: proof_bytes,
        })
    }

    fn prove_merge(&self, left: &ClaimFrame, right: &ClaimFrame) -> Result<Vec<u8>, AggError> {
        let left_decoded = decode_stark_proof(&left.proof)?;
        let right_decoded = decode_stark_proof(&right.proof)?;
        if left_decoded.envelope.parameter_set != self.parameter_set
            || right_decoded.envelope.parameter_set != self.parameter_set
        {
            return Err(AggError::WrongParameterSet);
        }
        if left_decoded.envelope.domain != right_decoded.envelope.domain {
            return Err(AggError::WrongDomain);
        }
        if !is_allowed_agg_program(&left_decoded.envelope.program_hash)
            || !is_allowed_agg_program(&right_decoded.envelope.program_hash)
        {
            return Err(AggError::ProofMismatch);
        }

        let domain = left_decoded.envelope.domain;
        self.verify(left, domain)?;
        self.verify(right, domain)?;

        let combined = ClaimFrame::combine(left, right, Vec::new())?;
        if combined.claims.len() > self.limits.max_claims {
            return Err(AggError::Frame(FrameError::TooManyClaims(
                combined.claims.len(),
            )));
        }

        let (steps, pub_stmt, recursion_level, child_verification_key_hash) = build_fold_statement(
            self.parameter_set,
            domain,
            &combined.segments,
            &combined.shape,
        )?;
        let fold_proof = prove_agg_fold(&steps, &pub_stmt).map_err(|_| AggError::MalformedProof)?;
        let proof_bytes = encode_stark_proof(
            self.parameter_set,
            domain,
            &pub_stmt.final_program_hash,
            &pub_stmt.master_pi,
            recursion_level,
            &child_verification_key_hash,
            &pub_stmt.shape_digest,
            &fold_proof,
        )?;
        if proof_bytes.len() > self.limits.max_proof_bytes {
            return Err(AggError::Frame(FrameError::ProofTooLarge(
                proof_bytes.len(),
            )));
        }
        Ok(proof_bytes)
    }

    fn verify(&self, frame: &ClaimFrame, domain: DomainId) -> Result<(), AggError> {
        let facts = frame.check_structure(domain, &self.limits)?;
        verify_segment_attestations(&self.registry, domain, &frame.segments)?;
        let decoded = decode_stark_proof(&frame.proof)?;

        if decoded.envelope.parameter_set != self.parameter_set {
            return Err(AggError::WrongParameterSet);
        }
        if decoded.envelope.domain != domain {
            return Err(AggError::WrongDomain);
        }
        let expected_program = match facts.program {
            AggProgram::Tick => agg_tick_program_hash(),
            AggProgram::Merge => agg_merge_program_hash(),
        };
        if decoded.envelope.program_hash != expected_program
            || !is_allowed_agg_program(&decoded.envelope.program_hash)
        {
            return Err(AggError::ProofMismatch);
        }

        let (steps, pub_stmt, recursion_level, child_verification_key_hash) =
            build_fold_statement(self.parameter_set, domain, &frame.segments, &frame.shape)?;
        if pub_stmt.master_pi != facts.master_pi || pub_stmt.final_program_hash != expected_program
        {
            return Err(AggError::ProofMismatch);
        }
        let expected_context = RecursiveProofContext {
            recursion_level,
            child_verification_key_hash,
            parameter_set: self.parameter_set,
            domain,
            program_hash: expected_program,
            public_input: facts.master_pi,
            statement_digest: pub_stmt.shape_digest,
        };
        decoded
            .envelope
            .validate_for(&expected_context)
            .map_err(|_| AggError::ProofMismatch)?;
        verify_agg_fold(&steps, &pub_stmt, &decoded.fold_proof).map_err(|_| AggError::ProofMismatch)
    }

    fn requires_bonded_aggregators(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[path = "r8_tests.rs"]
mod r8_tests;
