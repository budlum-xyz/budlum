//! See [`crate::prover`] for an overview of the protocol and a more detailed soundness analysis.

use p3_air::symbolic::{get_symbolic_constraints, SymbolicAirBuilder};
use p3_air::{Air, RowWindow};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{CommitmentOpening, Pcs, PolynomialSpace, UnivariateStarkPcs};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrixView;
use p3_matrix::stack::VerticalPair;
use p3_util::zip_eq::zip_eq;
use std::string::String;
use std::vec;
use std::vec::Vec;
use tracing::instrument;

use crate::bud_stark::symbolic::get_log_num_quotient_chunks;
use crate::bud_stark::{
    Domain, PcsError, PreprocessedVerifierKey, Proof, StarkGenericConfig, Val,
    VerifierConstraintFolder,
};
pub use p3_air::symbolic::AirLayout;

/// Canonical BudAir main trace width pinned against silent circuit narrowing.
const CANONICAL_BUD_AIR_TRACE_WIDTH: usize = 1073;
/// Canonical BudAir preprocessed trace width.
const CANONICAL_BUD_AIR_PREPROCESSED_WIDTH: usize = 8;
/// Canonical BudAir public-input slot count (`ExecutionPublicInputs`).
const CANONICAL_BUD_AIR_PUBLIC_VALUES: usize = 56;
/// Minimum FRI blowup log factor required for BudAir 128-bit PQ soundness.
const CANONICAL_BUD_AIR_MIN_LOG_BLOWUP: usize = 3;
/// Minimum FRI query count required alongside `log_blowup = 3`.
const CANONICAL_BUD_AIR_MIN_NUM_QUERIES: usize = 76;

/// Structural verification-key and FRI parameter pin guarding against silent
/// circuit width, public-input, or verifier-key drift before shipment.
///
/// WIRING: Enforced by [`verify_bud_air_vk_pin`] on [`crate::plonky3_prover`]
/// proof verification and checked structurally by the `proof-hash-width` gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudStarkVkPin {
    /// Expected main AIR trace width in field columns.
    pub expected_trace_width: usize,
    /// Expected preprocessed AIR width in field columns.
    pub expected_preprocessed_width: usize,
    /// Expected public-value vector length.
    pub expected_public_values: usize,
    /// Minimum FRI `log_blowup`.
    pub min_log_blowup: usize,
    /// Minimum FRI `num_queries`.
    pub min_num_queries: usize,
    /// Optional 32-byte commitment pinning a specific preprocessed VK digest.
    pub expected_vk_commitment: Option<[u8; 32]>,
}

impl BudStarkVkPin {
    /// Return the canonical [`crate::plonky3_air::BudAir`] structural pin.
    #[must_use]
    pub const fn canonical_bud_air() -> Self {
        Self {
            expected_trace_width: CANONICAL_BUD_AIR_TRACE_WIDTH,
            expected_preprocessed_width: CANONICAL_BUD_AIR_PREPROCESSED_WIDTH,
            expected_public_values: CANONICAL_BUD_AIR_PUBLIC_VALUES,
            min_log_blowup: CANONICAL_BUD_AIR_MIN_LOG_BLOWUP,
            min_num_queries: CANONICAL_BUD_AIR_MIN_NUM_QUERIES,
            expected_vk_commitment: None,
        }
    }
}

/// Fail closed with [`VerificationError::InvalidProofShape`] if an AIR,
/// preprocessed VK, FRI parameter set, or VK commitment digest drifted away
/// from `pin`.
///
/// # Errors
///
/// Returns [`VerificationError::InvalidProofShape`] on any structural mismatch.
pub fn verify_bud_air_vk_pin<SC, A>(
    air: &A,
    preprocessed_vk: Option<&PreprocessedVerifierKey<SC>>,
    log_blowup: usize,
    num_queries: usize,
    observed_vk_commitment: Option<[u8; 32]>,
    pin: &BudStarkVkPin,
) -> Result<(), VerificationError<PcsError<SC>>>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>>,
{
    if p3_air::BaseAir::<Val<SC>>::width(air) != pin.expected_trace_width {
        return Err(VerificationError::InvalidProofShape);
    }
    if air.num_public_values() != pin.expected_public_values {
        return Err(VerificationError::InvalidProofShape);
    }
    if log_blowup < pin.min_log_blowup || num_queries < pin.min_num_queries {
        return Err(VerificationError::InvalidProofShape);
    }
    if pin.expected_preprocessed_width > 0 {
        let Some(vk) = preprocessed_vk else {
            return Err(VerificationError::InvalidProofShape);
        };
        if vk.width != pin.expected_preprocessed_width {
            return Err(VerificationError::InvalidProofShape);
        }
    }
    if let Some(expected_digest) = pin.expected_vk_commitment {
        if observed_vk_commitment != Some(expected_digest) {
            return Err(VerificationError::InvalidProofShape);
        }
    }
    Ok(())
}

/// Recomposes the quotient polynomial from its chunks evaluated at a point.
///
/// Given quotient chunks and their domains, this computes the Lagrange
/// Interpolation coefficients (zps) and reconstructs quotient(zeta).
///
/// # Refusals
///
/// Returns `None` when the chunk count does not match the domain count.
///
/// The number of Lagrange coefficients follows the *domains*, while the sum
/// below is indexed by the *chunks*, and the chunk count comes from a proof a
/// remote party supplied. [`verify_with_preprocessed`] checks the two agree
/// before calling here, but this function is `pub`: its safety must not rest
/// on a check that lives in a different function, because a second caller
/// added later inherits none of it, and the failure mode is a panic on the
/// verification path - a remotely triggered node stop, not a rejected proof.
///
/// The check is stated here so that the answer to "what if these disagree?"
/// is in the same place as the code that would be wrong.
pub fn recompose_quotient_from_chunks<SC>(
    quotient_chunks_domains: &[Domain<SC>],
    quotient_chunks: &[Vec<SC::Challenge>],
    zeta: SC::Challenge,
) -> Option<SC::Challenge>
where
    SC: StarkGenericConfig,
{
    if quotient_chunks.is_empty() || quotient_chunks.len() != quotient_chunks_domains.len() {
        return None;
    }
    if quotient_chunks
        .iter()
        .any(|ch| ch.len() != SC::Challenge::DIMENSION)
    {
        return None;
    }
    let mut zps = Vec::with_capacity(quotient_chunks_domains.len());
    for (i, domain) in quotient_chunks_domains.iter().enumerate() {
        let mut prod = SC::Challenge::ONE;
        for (j, other_domain) in quotient_chunks_domains.iter().enumerate() {
            if j == i {
                continue;
            }
            let denom = other_domain
                .vanishing_poly_at_point(domain.first_point())
                .try_inverse()?;
            prod *= other_domain.vanishing_poly_at_point(zeta) * denom;
        }
        zps.push(prod);
    }

    Some(
        quotient_chunks
            .iter()
            .enumerate()
            .map(|(ch_i, ch)| {
                // Lengths were checked equal above, so `get` always finds a
                // coefficient; it is written this way so the compiler, not a
                // comment, is what rules out the panic.
                let zp = zps.get(ch_i).copied().unwrap_or(SC::Challenge::ZERO);
                zp * ch
                    .iter()
                    .enumerate()
                    .map(|(e_i, &c)| {
                        // `e_i` indexes the extension basis, whose length is
                        // `DIMENSION`; the caller checked each chunk has that
                        // many coefficients. Zero is the identity for the sum
                        // below, so an out-of-range index contributes nothing
                        // rather than taking the node down.
                        SC::Challenge::ith_basis_element(e_i).map_or(SC::Challenge::ZERO, |b| b * c)
                    })
                    .sum::<SC::Challenge>()
            })
            .sum::<SC::Challenge>(),
    )
}

/// Verifies that the folded constraints match the quotient polynomial at zeta.
///
/// This evaluates the [`Air`] constraints at the out-of-domain point and checks
/// That constraints(zeta) / Z_H(zeta) = quotient(zeta).
#[allow(clippy::too_many_arguments)]
pub fn verify_constraints<SC, A, PcsErr>(
    air: &A,
    trace_local: &[SC::Challenge],
    trace_next: &[SC::Challenge],
    aux_trace_local: Option<&[SC::Challenge]>,
    aux_trace_next: Option<&[SC::Challenge]>,
    preprocessed_local: Option<&[SC::Challenge]>,
    preprocessed_next: Option<&[SC::Challenge]>,
    public_values: &[Val<SC>],
    trace_domain: Domain<SC>,
    zeta: SC::Challenge,
    alpha: SC::Challenge,
    random_challenges: &[SC::Challenge],
    quotient: SC::Challenge,
) -> Result<(), VerificationError<PcsErr>>
where
    SC: StarkGenericConfig,
    A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    PcsErr: core::fmt::Debug,
{
    if trace_local.len() != trace_next.len() {
        return Err(VerificationError::InvalidProofShape);
    }
    let sels = trace_domain.selectors_at_point(zeta);

    let main = VerticalPair::new(
        RowMajorMatrixView::new_row(trace_local),
        RowMajorMatrixView::new_row(trace_next),
    );

    let aux_next_zeros;
    let aux = match (aux_trace_local, aux_trace_next) {
        (Some(local), Some(next)) if local.len() == next.len() => VerticalPair::new(
            RowMajorMatrixView::new_row(local),
            RowMajorMatrixView::new_row(next),
        ),
        (Some(local), None) => {
            aux_next_zeros = vec![SC::Challenge::ZERO; local.len()];
            VerticalPair::new(
                RowMajorMatrixView::new_row(local),
                RowMajorMatrixView::new_row(&aux_next_zeros),
            )
        }
        (None, None) => VerticalPair::new(
            RowMajorMatrixView::new(&[], 0),
            RowMajorMatrixView::new(&[], 0),
        ),
        _ => return Err(VerificationError::InvalidProofShape),
    };

    let preprocessed = match (preprocessed_local, preprocessed_next) {
        (Some(local), Some(next)) if local.len() == next.len() => VerticalPair::new(
            RowMajorMatrixView::new_row(local),
            RowMajorMatrixView::new_row(next),
        ),
        (None, None) => VerticalPair::new(
            RowMajorMatrixView::new(&[], 0),
            RowMajorMatrixView::new(&[], 0),
        ),
        _ => return Err(VerificationError::InvalidProofShape),
    };

    let preprocessed_window =
        RowWindow::from_two_rows(preprocessed.top.values, preprocessed.bottom.values);
    let mut folder = VerifierConstraintFolder {
        main,
        aux,
        preprocessed,
        preprocessed_window,
        random: random_challenges,
        public_values,
        is_first_row: sels.is_first_row,
        is_last_row: sels.is_last_row,
        is_transition: sels.is_transition,
        alpha,
        accumulator: SC::Challenge::ZERO,
    };
    air.eval(&mut folder);
    let folded_constraints = folder.accumulator;

    // Check that constraints(zeta) / Z_H(zeta) = quotient(zeta)
    if folded_constraints * sels.inv_vanishing != quotient {
        return Err(VerificationError::OodEvaluationMismatch { index: None });
    }

    Ok(())
}

/// Validates and commits the preprocessed trace if present.
/// Returns the preprocessed width and its commitment hash (available iff width > 0).
#[allow(clippy::type_complexity)]
fn process_preprocessed_trace<SC, A>(
    air: &A,
    opened_values: &crate::bud_stark::proof::OpenedValues<SC::Challenge>,
    preprocessed_vk: Option<&PreprocessedVerifierKey<SC>>,
) -> Result<
    (
        usize,
        Option<<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    ),
    VerificationError<PcsError<SC>>,
>
where
    SC: StarkGenericConfig,
    A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    // Determine expected preprocessed width.
    // - If both the AIR and a verifier key declare a preprocessed trace,
    //   their widths must agree; trusting a mismatched VK would let an
    //   under-sized opening reach `air.eval` and panic.
    let air_preprocessed_width = air.preprocessed_trace().as_ref().map(|m| m.width);
    if let (Some(vk), Some(air_w)) = (preprocessed_vk, air_preprocessed_width) {
        if vk.width != air_w {
            return Err(VerificationError::InvalidProofShape);
        }
    }
    let preprocessed_width = preprocessed_vk
        .map(|vk| vk.width)
        .or(air_preprocessed_width)
        .unwrap_or(0);

    // Check that the proof's opened preprocessed values match the expected width.
    let preprocessed_local_len = opened_values
        .preprocessed_local
        .as_ref()
        .map_or(0, |v| v.len());
    let preprocessed_next_len = opened_values
        .preprocessed_next
        .as_ref()
        .map_or(0, |v| v.len());
    let expected_next_len = if !air.preprocessed_next_row_columns().is_empty() {
        preprocessed_width
    } else {
        0
    };
    if preprocessed_width != preprocessed_local_len || expected_next_len != preprocessed_next_len {
        // Verifier expects preprocessed trace while proof does not have it, or vice versa
        return Err(VerificationError::InvalidProofShape);
    }

    // Validate consistency between width, verifier key, and zk settings.
    match (preprocessed_width, preprocessed_vk) {
        // Case: No preprocessed columns.
        //
        // Valid only if no verifier key is provided.
        (0, None) => Ok((0, None)),

        // Case: Preprocessed columns exist.
        //
        // Valid only if VK exists, widths match, and we are NOT in zk mode.
        (w, Some(vk)) if w == vk.width => Ok((w, Some(vk.commitment.clone()))),

        // Catch-all for invalid states, such as:
        // - Width is 0 but VK is provided.
        // - Width > 0 but VK is missing.
        // - Width > 0 but VK width mismatches the expected width.
        _ => Err(VerificationError::InvalidProofShape),
    }
}

/// True when the AIR adds constraints once the auxiliary (LogUp) trace exists.
///
/// The answer comes from the AIR itself, never from the proof. The proof
/// decides only whether it carries an aux commitment, and a prover that drops
/// it would switch every constraint behind the aux guard off.
fn air_requires_aux<F, A>(air: &A, layout: AirLayout) -> bool
where
    F: Field,
    A: Air<SymbolicAirBuilder<F>>,
{
    let with_aux = AirLayout {
        permutation_width: 3,
        num_permutation_challenges: 3,
        ..layout
    };
    // A width of 0 would hand the AIR an empty permutation window, and the
    // symbolic builder panics when the AIR reads it. One column and no
    // challenges keep the aux guard off, which is what "without aux" means.
    let without_aux = AirLayout {
        permutation_width: 1,
        num_permutation_challenges: 0,
        ..layout
    };
    let n_with = get_symbolic_constraints(air, with_aux).len();
    let n_without = get_symbolic_constraints(air, without_aux).len();
    n_with > n_without
}

/// Shape of the opened aux rows.
///
/// With an aux trace the local row must have the expected width. The next row
/// must have it when the AIR reads next rows, and must be absent otherwise:
/// `verify_constraints` feeds the next row to the AIR, so an opening the
/// commitment round never asked for must not be accepted.
fn aux_openings_match<T>(
    has_aux_trace: bool,
    main_next: bool,
    local: Option<&[T]>,
    next: Option<&[T]>,
    expected_width: usize,
) -> bool {
    if !has_aux_trace {
        return local.is_none() && next.is_none();
    }
    let next_ok = if main_next {
        next.is_some_and(|v| v.len() == expected_width)
    } else {
        next.is_none()
    };
    local.is_some_and(|v| v.len() == expected_width) && next_ok
}

#[instrument(skip_all)]
pub fn verify<SC, A>(
    config: &SC,
    air: &A,
    proof: &Proof<SC>,
    public_values: &[Val<SC>],
) -> Result<(), VerificationError<PcsError<SC>>>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    verify_with_preprocessed(config, air, proof, public_values, None)
}

/// Upper bound on the `degree_bits` a proof may claim.
///
/// DoS bound, not soundness: a proof claiming a
/// degree this large fails verification anyway, but it has to fail by being
/// rejected rather than by aborting the process. The release profile sets
/// `overflow-checks = true` and `panic = "abort"`, so an unchecked shift is a
/// remote kill switch on any node that accepts proofs.
///
/// Well below `usize::BITS` on purpose: the value is shifted a second time as
/// `1 << (degree_bits + log_num_quotient_chunks)`, so the bound has to leave
/// room for that addition. 2^32 rows at the current trace width is already far
/// beyond what any prover can hold in memory.
pub const MAX_VERIFIER_DEGREE_BITS: usize = 26;

/// Pure structural shape of a STARK proof's polynomial openings.
///
/// Carries everything [`verify_pcs_openings`] needs to check shape bounds and
/// verify FRI / Merkle openings without evaluating any AIR constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcsOpeningShape {
    /// Width of the main execution trace matrix.
    pub air_width: usize,
    /// Width of the preprocessed matrix (`0` when no preprocessed trace exists).
    pub preprocessed_width: usize,
    /// Base-2 logarithm of the unrandomized quotient chunk count.
    pub log_num_quotient_chunks: usize,
    /// Whether the AIR reads the next row of the main (and aux) trace.
    pub main_next: bool,
    /// Whether the AIR reads the next row of the preprocessed trace.
    pub pre_next: bool,
    /// Whether the proof includes an auxiliary (LogUp) trace commitment.
    pub has_aux_trace: bool,
}

/// Inputs to Stage 1 ([`verify_pcs_openings`]): commitments, opened values,
/// FRI opening proof, and instance metadata.
pub struct PcsOpeningStatement<'a, SC: StarkGenericConfig> {
    /// Structural shape of the opened matrices.
    pub shape: PcsOpeningShape,
    /// Matrix commitments from the proof.
    pub commitments: &'a crate::bud_stark::Commitments<crate::bud_stark::Com<SC>>,
    /// Claimed out-of-domain openings.
    pub opened_values: &'a crate::bud_stark::OpenedValues<SC::Challenge>,
    /// Heavy FRI + Merkle opening proof (verified once off-chain / by aggregators).
    pub opening_proof: &'a crate::bud_stark::PcsProof<SC>,
    /// Base-2 logarithm of the trace height.
    pub degree_bits: usize,
    /// Public instance inputs absorbed into the Fiat-Shamir transcript.
    pub public_values: &'a [Val<SC>],
    /// Commitment to the preprocessed matrix, present iff `shape.preprocessed_width > 0`.
    pub preprocessed_commit: Option<&'a crate::bud_stark::Com<SC>>,
}

/// Inputs to Stage 2 ([`verify_algebra`]): commitments, opened values,
/// public inputs, and optional preprocessed verifier key. Zero FRI bytes.
pub struct AlgebraStatement<'a, SC: StarkGenericConfig> {
    /// Matrix commitments from the proof.
    pub commitments: &'a crate::bud_stark::Commitments<crate::bud_stark::Com<SC>>,
    /// Claimed out-of-domain openings (bound on chain via `Claim::Poly`).
    pub opened_values: &'a crate::bud_stark::OpenedValues<SC::Challenge>,
    /// Base-2 logarithm of the trace height.
    pub degree_bits: usize,
    /// Public instance inputs absorbed into the Fiat-Shamir transcript.
    pub public_values: &'a [Val<SC>],
    /// Preprocessed verifier key, required iff the AIR has preprocessed columns.
    pub preprocessed_vk: Option<&'a PreprocessedVerifierKey<SC>>,
}

/// Deterministic Fiat-Shamir challenges and domains derived identically by
/// [`verify_pcs_openings`] and [`verify_algebra`].
pub struct VerifiedTranscript<SC: StarkGenericConfig> {
    /// Base-2 logarithm of the trace height.
    pub degree_bits: usize,
    /// Structural shape validated for this transcript.
    pub shape: PcsOpeningShape,
    /// Initial (unrandomized) trace domain.
    pub init_trace_domain: Domain<SC>,
    /// Randomized trace domain.
    pub trace_domain: Domain<SC>,
    /// Quotient chunk subdomains used to recompose `quotient(zeta)`.
    pub quotient_chunks_domains: Vec<Domain<SC>>,
    /// Randomized quotient chunk domains opened in the PCS round.
    pub randomized_quotient_chunks_domains: Vec<Domain<SC>>,
    /// Auxiliary permutation challenges (empty when `has_aux_trace == false`).
    pub random_challenges: Vec<SC::Challenge>,
    /// Constraint-folding challenge `alpha`.
    pub alpha: SC::Challenge,
    /// Out-of-domain evaluation point `zeta`.
    pub zeta: SC::Challenge,
    /// Shifted out-of-domain evaluation point `g * zeta`.
    pub zeta_next: SC::Challenge,
}

/// Derives the canonical [`PcsOpeningShape`] for `air` at `degree_bits`.
///
/// Refuses proofs that omit the auxiliary trace when `air` has aux-guarded
/// constraints, and enforces the `MAX_VERIFIER_DEGREE_BITS` ceiling.
///
/// # Errors
///
/// Returns [`VerificationError::InvalidProofShape`] when `degree_bits` is out
/// of bounds, the auxiliary trace is missing for an aux-requiring AIR, or the
/// quotient degree overflows the two-adicity bound.
pub fn shape_for_air<SC, A>(
    config: &SC,
    air: &A,
    degree_bits: usize,
    has_aux_trace: bool,
    preprocessed_width: usize,
) -> Result<PcsOpeningShape, VerificationError<PcsError<SC>>>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    if degree_bits > MAX_VERIFIER_DEGREE_BITS || degree_bits < usize::from(config.is_zk()) {
        return Err(VerificationError::InvalidProofShape);
    }
    let degree = 1usize << degree_bits;
    if !has_aux_trace {
        let base_layout = AirLayout {
            preprocessed_width,
            main_width: air.width(),
            num_public_values: air.num_public_values(),
            ..Default::default()
        };
        if air_requires_aux::<Val<SC>, A>(air, base_layout) {
            return Err(VerificationError::InvalidProofShape);
        }
    }
    let permutation_width = if has_aux_trace { 3 } else { 0 };
    let layout = AirLayout {
        preprocessed_width,
        main_width: air.width(),
        num_public_values: air.num_public_values(),
        permutation_width,
        num_permutation_challenges: if has_aux_trace { 3 } else { 0 },
        ..Default::default()
    };
    let log_num_quotient_chunks = get_log_num_quotient_chunks::<Val<SC>, A>(
        air,
        layout,
        degree >> usize::from(config.is_zk()),
        usize::from(config.is_zk()),
    );
    if log_num_quotient_chunks > MAX_LOG_QUOTIENT_CHUNKS {
        return Err(VerificationError::InvalidProofShape);
    }
    if degree_bits
        .saturating_add(log_num_quotient_chunks)
        .saturating_add(usize::from(config.is_zk()))
        > 30
    {
        return Err(VerificationError::InvalidProofShape);
    }
    Ok(PcsOpeningShape {
        air_width: A::width(air),
        preprocessed_width,
        log_num_quotient_chunks,
        main_next: !air.main_next_row_columns().is_empty(),
        pre_next: !air.preprocessed_next_row_columns().is_empty(),
        has_aux_trace,
    })
}

/// Upper bound on `log_num_quotient_chunks` (`1 << 8 == 256` unrandomized chunks),
/// matching the on-chain Stage 2 quotient-chunk ceiling so an untrusted Stage 1
/// opening statement cannot request millions of quotient subdomains.
pub const MAX_LOG_QUOTIENT_CHUNKS: usize = 8;

type TranscriptOutcome<SC> = Result<
    (
        VerifiedTranscript<SC>,
        <SC as StarkGenericConfig>::Challenger,
    ),
    VerificationError<PcsError<SC>>,
>;

/// Validates structural opening shapes and runs the Fiat-Shamir transcript
/// identically for both [`verify_pcs_openings`] and [`verify_algebra`].
fn derive_transcript<SC>(
    config: &SC,
    shape: PcsOpeningShape,
    commitments: &crate::bud_stark::Commitments<crate::bud_stark::Com<SC>>,
    opened_values: &crate::bud_stark::OpenedValues<SC::Challenge>,
    degree_bits: usize,
    public_values: &[Val<SC>],
    preprocessed_commit: Option<&crate::bud_stark::Com<SC>>,
) -> TranscriptOutcome<SC>
where
    SC: StarkGenericConfig,
{
    if degree_bits > MAX_VERIFIER_DEGREE_BITS || degree_bits < usize::from(config.is_zk()) {
        return Err(VerificationError::InvalidProofShape);
    }
    if shape.air_width == 0 {
        return Err(VerificationError::InvalidProofShape);
    }
    if shape.log_num_quotient_chunks > MAX_LOG_QUOTIENT_CHUNKS {
        return Err(VerificationError::InvalidProofShape);
    }
    if degree_bits
        .saturating_add(shape.log_num_quotient_chunks)
        .saturating_add(usize::from(config.is_zk()))
        > 30
    {
        return Err(VerificationError::InvalidProofShape);
    }
    if commitments.aux_trace.is_some() != shape.has_aux_trace {
        return Err(VerificationError::InvalidProofShape);
    }
    if (shape.preprocessed_width > 0) != preprocessed_commit.is_some() {
        return Err(VerificationError::InvalidProofShape);
    }
    if (opened_values.random.is_some() != SC::Pcs::ZK)
        || (commitments.random.is_some() != SC::Pcs::ZK)
    {
        return Err(VerificationError::RandomizationError);
    }

    // Validate every opening slice length and the quotient chunk count before
    // constructing or splitting evaluation domains, so an untrusted opening
    // header cannot trigger eager subdomain allocation beyond its carried payload.
    let num_quotient_chunks =
        1usize << (shape.log_num_quotient_chunks + usize::from(config.is_zk()));
    let trace_next_ok = if shape.main_next {
        opened_values
            .trace_next
            .as_ref()
            .is_some_and(|v| v.len() == shape.air_width)
    } else {
        opened_values.trace_next.is_none()
    };
    let permutation_width = if shape.has_aux_trace { 3 } else { 0 };
    let expected_aux_base_width = permutation_width * SC::Challenge::DIMENSION;
    let aux_shape_ok = aux_openings_match(
        shape.has_aux_trace,
        shape.main_next,
        opened_values.aux_trace_local.as_deref(),
        opened_values.aux_trace_next.as_deref(),
        expected_aux_base_width,
    );
    let pre_local_ok = if shape.preprocessed_width > 0 {
        opened_values
            .preprocessed_local
            .as_ref()
            .is_some_and(|v| v.len() == shape.preprocessed_width)
    } else {
        opened_values.preprocessed_local.is_none()
    };
    let pre_next_ok = if shape.preprocessed_width > 0 && shape.pre_next {
        opened_values
            .preprocessed_next
            .as_ref()
            .is_some_and(|v| v.len() == shape.preprocessed_width)
    } else {
        opened_values.preprocessed_next.is_none()
    };
    let valid_shape = opened_values.trace_local.len() == shape.air_width
        && trace_next_ok
        && aux_shape_ok
        && pre_local_ok
        && pre_next_ok
        && opened_values.quotient_chunks.len() == num_quotient_chunks
        && opened_values
            .quotient_chunks
            .iter()
            .all(|qc| qc.len() == SC::Challenge::DIMENSION)
        && opened_values
            .random
            .as_ref()
            .is_none_or(|r_comm| r_comm.len() == SC::Challenge::DIMENSION);
    if !valid_shape {
        return Err(VerificationError::InvalidProofShape);
    }

    let pcs = config.pcs();
    let degree = 1usize << degree_bits;
    let trace_domain = pcs.natural_domain_for_degree(degree);
    let init_trace_domain = pcs.natural_domain_for_degree(degree >> usize::from(config.is_zk()));

    let quotient_domain = trace_domain
        .create_disjoint_domain(1usize << (degree_bits + shape.log_num_quotient_chunks));
    let quotient_chunks_domains = quotient_domain.split_domains(num_quotient_chunks);
    let randomized_quotient_chunks_domains = quotient_chunks_domains
        .iter()
        .map(|domain| pcs.natural_domain_for_degree(domain.size() << usize::from(config.is_zk())))
        .collect::<Vec<_>>();

    let mut challenger = config.initialise_challenger();
    challenger.observe(Val::<SC>::from_usize(degree_bits));
    challenger.observe(Val::<SC>::from_usize(
        degree_bits - usize::from(config.is_zk()),
    ));
    challenger.observe(Val::<SC>::from_usize(shape.preprocessed_width));
    challenger.observe_slice(&config.security_parameters());
    challenger.observe(commitments.trace.clone());
    if shape.preprocessed_width > 0 {
        let commit = preprocessed_commit.ok_or(VerificationError::InvalidProofShape)?;
        challenger.observe(commit.clone());
    }
    challenger.observe_slice(public_values);

    let mut random_challenges = vec![];
    if let Some(aux_commit) = &commitments.aux_trace {
        let rand_1: SC::Challenge = challenger.sample_algebra_element();
        let rand_2: SC::Challenge = challenger.sample_algebra_element();
        let rand_3: SC::Challenge = challenger.sample_algebra_element();
        random_challenges.push(rand_1);
        random_challenges.push(rand_2);
        random_challenges.push(rand_3);
        challenger.observe(aux_commit.clone());
    }

    let alpha = challenger.sample_algebra_element();
    challenger.observe(commitments.quotient_chunks.clone());
    if let Some(r_commit) = commitments.random.clone() {
        challenger.observe(r_commit);
    }

    let zeta = challenger.sample_algebra_element();
    let zeta_next = init_trace_domain
        .next_point(zeta)
        .ok_or(VerificationError::NextPointUnavailable)?;

    let transcript = VerifiedTranscript {
        degree_bits,
        shape,
        init_trace_domain,
        trace_domain,
        quotient_chunks_domains,
        randomized_quotient_chunks_domains,
        random_challenges,
        alpha,
        zeta,
        zeta_next,
    };
    Ok((transcript, challenger))
}

/// Stage 1 of split STARK verification: checks opening shapes, derives the
/// Fiat-Shamir opening point `zeta`, and verifies the FRI / Merkle PCS opening
/// proof against every committed polynomial matrix.
///
/// Evaluates zero AIR constraints; works for `BudAir` and any external AIR
/// sharing the same PCS configuration.
///
/// # Errors
///
/// Returns [`VerificationError`] if shapes, randomization settings, or FRI
/// opening arguments are invalid.
#[instrument(skip_all)]
pub fn verify_pcs_openings<SC>(
    config: &SC,
    stmt: &PcsOpeningStatement<'_, SC>,
) -> Result<VerifiedTranscript<SC>, VerificationError<PcsError<SC>>>
where
    SC: StarkGenericConfig,
{
    let (transcript, mut challenger) = derive_transcript(
        config,
        stmt.shape,
        stmt.commitments,
        stmt.opened_values,
        stmt.degree_bits,
        stmt.public_values,
        stmt.preprocessed_commit,
    )?;

    let pcs = config.pcs();
    let commitments = stmt.commitments;
    let opened_values = stmt.opened_values;
    let shape = stmt.shape;
    let zeta = transcript.zeta;
    let zeta_next = transcript.zeta_next;
    let trace_domain = transcript.trace_domain;

    let mut coms_to_verify = if let Some(random_commit) = &commitments.random {
        let random_values = opened_values
            .random
            .as_ref()
            .ok_or(VerificationError::RandomizationError)?;
        vec![(
            random_commit.clone(),
            vec![(trace_domain, vec![(zeta, random_values.clone())])],
        )]
    } else {
        vec![]
    };
    let trace_round = {
        let mut trace_points = vec![(zeta, opened_values.trace_local.clone())];
        if shape.main_next {
            trace_points.push((
                zeta_next,
                opened_values
                    .trace_next
                    .clone()
                    .ok_or(VerificationError::InvalidProofShape)?,
            ));
        }
        (
            commitments.trace.clone(),
            vec![(trace_domain, trace_points)],
        )
    };
    let aux_round = match commitments.aux_trace.clone() {
        Some(commit) => {
            let local = opened_values
                .aux_trace_local
                .clone()
                .ok_or(VerificationError::InvalidProofShape)?;
            let mut aux_points = vec![(zeta, local)];
            if shape.main_next {
                let next = opened_values
                    .aux_trace_next
                    .clone()
                    .ok_or(VerificationError::InvalidProofShape)?;
                aux_points.push((zeta_next, next));
            }
            Some((commit, vec![(trace_domain, aux_points)]))
        }
        None => None,
    };

    coms_to_verify.push(trace_round);
    if let Some(ar) = aux_round {
        coms_to_verify.push(ar);
    }
    coms_to_verify.extend(vec![(
        commitments.quotient_chunks.clone(),
        zip_eq(
            transcript.randomized_quotient_chunks_domains.iter(),
            &opened_values.quotient_chunks,
            VerificationError::InvalidProofShape,
        )?
        .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
        .collect::<Vec<_>>(),
    )]);

    if shape.preprocessed_width > 0 {
        let local = opened_values
            .preprocessed_local
            .clone()
            .ok_or(VerificationError::InvalidProofShape)?;
        let mut pre_points = vec![(zeta, local)];
        if shape.pre_next {
            let next = opened_values
                .preprocessed_next
                .clone()
                .ok_or(VerificationError::InvalidProofShape)?;
            pre_points.push((zeta_next, next));
        }
        let commit = stmt
            .preprocessed_commit
            .cloned()
            .ok_or(VerificationError::InvalidProofShape)?;
        coms_to_verify.push((commit, vec![(trace_domain, pre_points)]));
    }

    let preprocessed_idx = if shape.preprocessed_width > 0 {
        Some(coms_to_verify.len() - 1)
    } else {
        None
    };
    let coms_to_verify: Vec<CommitmentOpening<_, _, _>> =
        coms_to_verify.into_iter().map(Into::into).collect();
    pcs.verify_with_preprocessing(
        coms_to_verify,
        stmt.opening_proof,
        &mut challenger,
        preprocessed_idx,
    )
    .map_err(VerificationError::InvalidOpeningArgument)?;

    Ok(transcript)
}

/// Evaluates the quotient recomposition and AIR constraint identity at `zeta`
/// using an already-derived [`VerifiedTranscript`].
fn verify_algebra_with_transcript<SC, A>(
    air: &A,
    opened_values: &crate::bud_stark::OpenedValues<SC::Challenge>,
    public_values: &[Val<SC>],
    transcript: &VerifiedTranscript<SC>,
) -> Result<(), VerificationError<PcsError<SC>>>
where
    SC: StarkGenericConfig,
    A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    let quotient = recompose_quotient_from_chunks::<SC>(
        &transcript.quotient_chunks_domains,
        &opened_values.quotient_chunks,
        transcript.zeta,
    )
    .ok_or(VerificationError::InvalidProofShape)?;

    let zeros;
    let trace_next_slice = match &opened_values.trace_next {
        Some(v) => v.as_slice(),
        None => {
            zeros = vec![SC::Challenge::ZERO; transcript.shape.air_width];
            &zeros
        }
    };
    let pre_next_zeros;
    let preprocessed_next_for_verify = match &opened_values.preprocessed_next {
        Some(v) => Some(v.as_slice()),
        None if transcript.shape.preprocessed_width > 0 => {
            pre_next_zeros = vec![SC::Challenge::ZERO; transcript.shape.preprocessed_width];
            Some(pre_next_zeros.as_slice())
        }
        None => None,
    };
    verify_constraints::<SC, A, PcsError<SC>>(
        air,
        &opened_values.trace_local,
        trace_next_slice,
        opened_values.aux_trace_local.as_deref(),
        opened_values.aux_trace_next.as_deref(),
        opened_values.preprocessed_local.as_deref(),
        preprocessed_next_for_verify,
        public_values,
        transcript.init_trace_domain,
        transcript.zeta,
        transcript.alpha,
        &transcript.random_challenges,
        quotient,
    )
}

/// Stage 2 of split STARK verification: re-derives `zeta` from commitments and
/// public values, checks AIR/preprocessed shape invariants, recomposes
/// `quotient(zeta)`, and verifies `constraints(zeta) / Z_H(zeta) == quotient(zeta)`.
///
/// Runs zero FRI or Merkle opening checks; callers must bind the returned
/// `transcript.zeta` and `opened_values` to verified `Claim::Poly` claims.
///
/// # Errors
///
/// Returns [`VerificationError`] if shapes, preprocessed VK, auxiliary trace
/// requirement, quotient recomposition, or AIR constraints fail.
#[instrument(skip_all)]
pub fn verify_algebra<SC, A>(
    config: &SC,
    air: &A,
    stmt: &AlgebraStatement<'_, SC>,
) -> Result<VerifiedTranscript<SC>, VerificationError<PcsError<SC>>>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    if stmt.degree_bits > MAX_VERIFIER_DEGREE_BITS || stmt.degree_bits < usize::from(config.is_zk())
    {
        return Err(VerificationError::InvalidProofShape);
    }
    if stmt.public_values.len() != air.num_public_values() {
        return Err(VerificationError::InvalidProofShape);
    }
    let (preprocessed_width, preprocessed_commit) =
        process_preprocessed_trace::<SC, A>(air, stmt.opened_values, stmt.preprocessed_vk)?;
    if let Some(vk) = stmt.preprocessed_vk {
        if preprocessed_width > 0 && vk.degree_bits != stmt.degree_bits {
            return Err(VerificationError::InvalidProofShape);
        }
    }
    let has_aux_trace = stmt.commitments.aux_trace.is_some();
    let shape = shape_for_air::<SC, A>(
        config,
        air,
        stmt.degree_bits,
        has_aux_trace,
        preprocessed_width,
    )?;
    let (transcript, _challenger) = derive_transcript(
        config,
        shape,
        stmt.commitments,
        stmt.opened_values,
        stmt.degree_bits,
        stmt.public_values,
        preprocessed_commit.as_ref(),
    )?;
    verify_algebra_with_transcript::<SC, A>(
        air,
        stmt.opened_values,
        stmt.public_values,
        &transcript,
    )?;
    Ok(transcript)
}

#[instrument(skip_all)]
pub fn verify_with_preprocessed<SC, A>(
    config: &SC,
    air: &A,
    proof: &Proof<SC>,
    public_values: &[Val<SC>],
    preprocessed_vk: Option<&PreprocessedVerifierKey<SC>>,
) -> Result<(), VerificationError<PcsError<SC>>>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    let Proof {
        commitments,
        opened_values,
        opening_proof,
        degree_bits,
    } = proof;

    if *degree_bits > MAX_VERIFIER_DEGREE_BITS || *degree_bits < usize::from(config.is_zk()) {
        return Err(VerificationError::InvalidProofShape);
    }
    if public_values.len() != air.num_public_values() {
        return Err(VerificationError::InvalidProofShape);
    }

    let (preprocessed_width, preprocessed_commit) =
        process_preprocessed_trace::<SC, A>(air, opened_values, preprocessed_vk)?;

    if let Some(vk) = preprocessed_vk {
        if preprocessed_width > 0 && vk.degree_bits != *degree_bits {
            return Err(VerificationError::InvalidProofShape);
        }
    }

    let has_aux_trace = commitments.aux_trace.is_some();
    let shape =
        shape_for_air::<SC, A>(config, air, *degree_bits, has_aux_trace, preprocessed_width)?;

    let transcript = verify_pcs_openings(
        config,
        &PcsOpeningStatement {
            shape,
            commitments,
            opened_values,
            opening_proof,
            degree_bits: *degree_bits,
            public_values,
            preprocessed_commit: preprocessed_commit.as_ref(),
        },
    )?;

    verify_algebra_with_transcript::<SC, A>(air, opened_values, public_values, &transcript)
}

#[derive(Debug)]
pub enum VerificationError<PcsErr>
where
    PcsErr: core::fmt::Debug,
{
    InvalidProofShape,
    /// An error occurred while verifying the claimed openings.
    InvalidOpeningArgument(PcsErr),
    /// Out-of-domain evaluation mismatch, i.e. `constraints(zeta)` did not match
    /// `quotient(zeta) Z_H(zeta)`.
    OodEvaluationMismatch {
        index: Option<usize>,
    },
    /// The FRI batch randomization does not correspond to the ZK setting.
    RandomizationError,
    /// The domain does not support computing the next point algebraically.
    NextPointUnavailable,
    /// Lookup related error
    LookupError(String),
}

impl<PcsErr> core::fmt::Display for VerificationError<PcsErr>
where
    PcsErr: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProofShape => write!(f, "invalid proof shape"),
            Self::InvalidOpeningArgument(err) => write!(f, "invalid opening argument: {err:?}"),
            Self::OodEvaluationMismatch { index } => {
                write!(f, "out-of-domain evaluation mismatch")?;
                if let Some(index) = index {
                    write!(f, " at index {index}")?;
                }
                Ok(())
            }
            Self::RandomizationError => write!(
                f,
                "randomization error: FRI batch randomization does not match ZK setting"
            ),
            Self::NextPointUnavailable => write!(
                f,
                "next point unavailable: domain does not support computing the next point algebraically"
            ),
            Self::LookupError(err) => write!(f, "lookup error: {err}"),
        }
    }
}

impl<PcsErr> std::error::Error for VerificationError<PcsErr> where PcsErr: core::fmt::Debug {}

#[cfg(test)]
mod tests {
    use p3_goldilocks::Goldilocks;

    use super::*;
    use crate::plonky3_air::{BudAir, PREPROCESSED_WIDTH};

    #[test]
    fn aux_next_row_is_refused_without_main_next() {
        let row: &[u8] = &[1, 2, 3];
        assert!(aux_openings_match(true, true, Some(row), Some(row), 3));
        assert!(aux_openings_match(true, false, Some(row), None, 3));
        assert!(!aux_openings_match(true, false, Some(row), Some(row), 3));
        assert!(!aux_openings_match(true, true, Some(row), None, 3));
        assert!(!aux_openings_match(true, false, Some(row), None, 2));
        assert!(aux_openings_match::<u8>(false, true, None, None, 3));
        assert!(!aux_openings_match(false, true, Some(row), None, 3));
    }

    #[test]
    fn bud_air_requires_the_aux_trace() {
        let air = BudAir {
            num_steps: 1,
            program: vec![0],
        };
        let layout = AirLayout {
            preprocessed_width: PREPROCESSED_WIDTH,
            main_width: <BudAir as p3_air::BaseAir<Goldilocks>>::width(&air),
            num_public_values: <BudAir as p3_air::BaseAir<Goldilocks>>::num_public_values(&air),
            ..Default::default()
        };
        assert!(air_requires_aux::<Goldilocks, BudAir>(&air, layout));
    }

    #[test]
    fn degree_bits_ceiling_guards_goldilocks_two_adicity() {
        let ceiling = std::hint::black_box(MAX_VERIFIER_DEGREE_BITS);
        assert!(ceiling <= 26);
    }

    #[test]
    fn pcs_openings_refuses_excess_quotient_chunk_exponent() {
        use p3_field::PrimeCharacteristicRing;

        let config = crate::plonky3_prover::build_config();
        let dummy_commit = crate::plonky3_prover::chip_commitment_from_bytes([0u8; 32]);
        let commitments = crate::bud_stark::Commitments {
            trace: dummy_commit.clone(),
            quotient_chunks: dummy_commit,
            random: None,
            aux_trace: None,
        };
        let ext_zero =
            <crate::plonky3_prover::ChipStarkConfig as StarkGenericConfig>::Challenge::ZERO;
        let opened_values = crate::bud_stark::OpenedValues {
            trace_local: vec![ext_zero; 2],
            trace_next: None,
            quotient_chunks: vec![vec![ext_zero; 3]; 512],
            random: None,
            aux_trace_local: None,
            aux_trace_next: None,
            preprocessed_local: None,
            preprocessed_next: None,
        };
        let shape = PcsOpeningShape {
            air_width: 2,
            preprocessed_width: 0,
            log_num_quotient_chunks: 9,
            main_next: false,
            pre_next: false,
            has_aux_trace: false,
        };
        let res = derive_transcript(&config, shape, &commitments, &opened_values, 2, &[], None);
        assert!(
            matches!(res, Err(VerificationError::InvalidProofShape)),
            "log_num_quotient_chunks above the 256-chunk ceiling must be refused as InvalidProofShape"
        );
    }

    #[test]
    fn derive_transcript_refuses_unbacked_quotient_chunks_without_domain_allocation() {
        use p3_field::PrimeCharacteristicRing;

        let config = crate::plonky3_prover::build_config();
        let dummy_commit = crate::plonky3_prover::chip_commitment_from_bytes([0u8; 32]);
        let commitments = crate::bud_stark::Commitments {
            trace: dummy_commit.clone(),
            quotient_chunks: dummy_commit,
            random: None,
            aux_trace: None,
        };
        let ext_zero =
            <crate::plonky3_prover::ChipStarkConfig as StarkGenericConfig>::Challenge::ZERO;
        let opened_values = crate::bud_stark::OpenedValues {
            trace_local: vec![ext_zero; 2],
            trace_next: None,
            quotient_chunks: Vec::new(),
            random: None,
            aux_trace_local: None,
            aux_trace_next: None,
            preprocessed_local: None,
            preprocessed_next: None,
        };
        let started = std::time::Instant::now();
        for inflated_log in [4usize, 8, 21, 22, 28, 30, usize::MAX] {
            let shape = PcsOpeningShape {
                air_width: 2,
                preprocessed_width: 0,
                log_num_quotient_chunks: inflated_log,
                main_next: false,
                pre_next: false,
                has_aux_trace: false,
            };
            let res = derive_transcript(&config, shape, &commitments, &opened_values, 0, &[], None);
            assert!(
                matches!(res, Err(VerificationError::InvalidProofShape)),
                "inflated log_num_quotient_chunks={inflated_log} with empty openings must fail closed"
            );
        }
        assert!(
            started.elapsed().as_millis() < 5,
            "rejecting unbacked quotient chunk counts must be O(1) without domain-vector allocation"
        );
    }

    #[test]
    fn budprf05_stark_verifier_refuses_bad_public_values_preproc_width_and_quotient_shape() {
        use p3_field::PrimeCharacteristicRing;
        type SC = crate::plonky3_prover::ChipStarkConfig;

        let config = crate::plonky3_prover::build_config();
        let ext_zero = <SC as StarkGenericConfig>::Challenge::ZERO;

        // 1. recompose_quotient_from_chunks must refuse empty slice lists and wrong chunk dims.
        assert!(
            recompose_quotient_from_chunks::<SC>(&[], &[], ext_zero).is_none(),
            "empty quotient chunks must be refused"
        );
        let domain = <<SC as StarkGenericConfig>::Pcs as Pcs<
            <SC as StarkGenericConfig>::Challenge,
            <SC as StarkGenericConfig>::Challenger,
        >>::natural_domain_for_degree(config.pcs(), 4);
        assert!(
            recompose_quotient_from_chunks::<SC>(&[domain], &[vec![ext_zero; 1]], ext_zero)
                .is_none(),
            "truncated quotient chunk (< DIMENSION) must be refused"
        );
        assert!(
            recompose_quotient_from_chunks::<SC>(&[domain], &[vec![ext_zero; 4]], ext_zero)
                .is_none(),
            "oversized quotient chunk (> DIMENSION) must be refused"
        );

        // 2. derive_transcript must refuse air_width == 0.
        let dummy_commit = crate::plonky3_prover::chip_commitment_from_bytes([0u8; 32]);
        let commitments = crate::bud_stark::Commitments {
            trace: dummy_commit.clone(),
            quotient_chunks: dummy_commit.clone(),
            random: None,
            aux_trace: None,
        };
        let empty_openings = crate::bud_stark::OpenedValues {
            trace_local: vec![],
            trace_next: None,
            quotient_chunks: vec![vec![ext_zero; 3]; 1],
            random: None,
            aux_trace_local: None,
            aux_trace_next: None,
            preprocessed_local: None,
            preprocessed_next: None,
        };
        let zero_width_shape = PcsOpeningShape {
            air_width: 0,
            preprocessed_width: 0,
            log_num_quotient_chunks: 0,
            main_next: false,
            pre_next: false,
            has_aux_trace: false,
        };
        assert!(
            matches!(
                derive_transcript(
                    &config,
                    zero_width_shape,
                    &commitments,
                    &empty_openings,
                    2,
                    &[],
                    None
                ),
                Err(VerificationError::InvalidProofShape)
            ),
            "air_width == 0 must be refused as InvalidProofShape"
        );

        // 3. process_preprocessed_trace must refuse a VK whose width disagrees with the AIR's
        // declared preprocessed_trace() width.
        let air = BudAir {
            num_steps: 1,
            program: vec![bud_isa::Instruction {
                opcode: bud_isa::Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            }
            .encode()],
        };
        let bad_vk = PreprocessedVerifierKey::<SC> {
            commitment: dummy_commit.clone(),
            degree_bits: 4,
            width: PREPROCESSED_WIDTH.saturating_sub(1).max(1),
        };
        assert_ne!(bad_vk.width, PREPROCESSED_WIDTH);
        let vk_openings = crate::bud_stark::OpenedValues {
            trace_local: vec![ext_zero; <BudAir as p3_air::BaseAir<Goldilocks>>::width(&air)],
            trace_next: Some(vec![
                ext_zero;
                <BudAir as p3_air::BaseAir<Goldilocks>>::width(&air)
            ]),
            quotient_chunks: vec![vec![ext_zero; 3]; 4],
            random: None,
            aux_trace_local: Some(vec![ext_zero; 9]),
            aux_trace_next: Some(vec![ext_zero; 9]),
            preprocessed_local: Some(vec![ext_zero; bad_vk.width]),
            preprocessed_next: None,
        };
        assert!(
            matches!(
                process_preprocessed_trace::<SC, BudAir>(&air, &vk_openings, Some(&bad_vk)),
                Err(VerificationError::InvalidProofShape)
            ),
            "preprocessed VK width mismatching AIR preprocessed_trace width must be refused"
        );

        // 4. verify_algebra must refuse wrong public_values.len() instead of panicking inside air.eval.
        use p3_air::BaseAir;
        let ext_dim =
            <<SC as StarkGenericConfig>::Challenge as BasedVectorSpace<Val<SC>>>::DIMENSION;
        let good_vk = PreprocessedVerifierKey::<SC> {
            commitment: dummy_commit.clone(),
            degree_bits: 4,
            width: PREPROCESSED_WIDTH,
        };
        let Ok(shape) = shape_for_air::<SC, BudAir>(&config, &air, 4, true, PREPROCESSED_WIDTH)
        else {
            panic!("shape_for_air for canonical BudAir must succeed");
        };
        let num_quotient_chunks =
            1usize << (shape.log_num_quotient_chunks + usize::from(config.is_zk()));
        let pre_next = if shape.pre_next {
            Some(vec![ext_zero; shape.preprocessed_width])
        } else {
            None
        };
        let good_openings = crate::bud_stark::OpenedValues {
            trace_local: vec![ext_zero; shape.air_width],
            trace_next: shape.main_next.then(|| vec![ext_zero; shape.air_width]),
            quotient_chunks: vec![vec![ext_zero; ext_dim]; num_quotient_chunks],
            random: None,
            aux_trace_local: shape.has_aux_trace.then(|| vec![ext_zero; 3 * ext_dim]),
            aux_trace_next: (shape.has_aux_trace && shape.main_next)
                .then(|| vec![ext_zero; 3 * ext_dim]),
            preprocessed_local: Some(vec![ext_zero; shape.preprocessed_width]),
            preprocessed_next: pre_next,
        };
        let aux_commitments = crate::bud_stark::Commitments {
            trace: dummy_commit.clone(),
            quotient_chunks: dummy_commit.clone(),
            random: None,
            aux_trace: shape.has_aux_trace.then_some(dummy_commit),
        };
        // Sanity check: with the exact expected public_values length, the opening shape
        // passes derive_transcript and reaches algebraic OOD verification.
        let valid_pvs = vec![Goldilocks::ZERO; BaseAir::<Goldilocks>::num_public_values(&air)];
        let valid_shape_stmt = AlgebraStatement {
            commitments: &aux_commitments,
            opened_values: &good_openings,
            degree_bits: 4,
            public_values: &valid_pvs,
            preprocessed_vk: Some(&good_vk),
        };
        assert!(
            !matches!(
                verify_algebra::<SC, BudAir>(&config, &air, &valid_shape_stmt),
                Err(VerificationError::InvalidProofShape)
            ),
            "control fixture must have a valid opening shape past derive_transcript"
        );
        let bad_pv_stmt = AlgebraStatement {
            commitments: &aux_commitments,
            opened_values: &good_openings,
            degree_bits: 4,
            public_values: &[], // BudAir expects > 0 public values
            preprocessed_vk: Some(&good_vk),
        };
        assert!(
            matches!(
                verify_algebra::<SC, BudAir>(&config, &air, &bad_pv_stmt),
                Err(VerificationError::InvalidProofShape)
            ),
            "wrong public_values length must return InvalidProofShape instead of panicking"
        );
    }

    #[test]
    fn bud_air_vk_pin_accepts_canonical_and_refuses_drifted_circuit_or_vk() {
        type SC = crate::plonky3_prover::ChipStarkConfig;
        let config = crate::plonky3_prover::build_config();
        let air = BudAir {
            num_steps: 2,
            program: vec![0u64],
        };
        let pin = BudStarkVkPin::canonical_bud_air();
        let _ = config;
        let dummy_commit = crate::plonky3_prover::chip_commitment_from_bytes([0u8; 32]);
        let dummy_vk = PreprocessedVerifierKey::<SC> {
            commitment: dummy_commit,
            degree_bits: 4,
            width: CANONICAL_BUD_AIR_PREPROCESSED_WIDTH,
        };
        assert!(verify_bud_air_vk_pin::<SC, BudAir>(
            &air,
            Some(&dummy_vk),
            CANONICAL_BUD_AIR_MIN_LOG_BLOWUP,
            CANONICAL_BUD_AIR_MIN_NUM_QUERIES,
            None,
            &pin,
        )
        .is_ok());

        // Narrowed FRI query count must fail closed.
        assert!(matches!(
            verify_bud_air_vk_pin::<SC, BudAir>(
                &air,
                Some(&dummy_vk),
                CANONICAL_BUD_AIR_MIN_LOG_BLOWUP,
                CANONICAL_BUD_AIR_MIN_NUM_QUERIES - 1,
                None,
                &pin,
            ),
            Err(VerificationError::InvalidProofShape)
        ));

        // Preprocessed VK width drift must fail closed.
        let mut drifted_vk = dummy_vk.clone();
        drifted_vk.width = CANONICAL_BUD_AIR_PREPROCESSED_WIDTH - 1;
        assert!(matches!(
            verify_bud_air_vk_pin::<SC, BudAir>(
                &air,
                Some(&drifted_vk),
                CANONICAL_BUD_AIR_MIN_LOG_BLOWUP,
                CANONICAL_BUD_AIR_MIN_NUM_QUERIES,
                None,
                &pin,
            ),
            Err(VerificationError::InvalidProofShape)
        ));

        // Expected AIR width drift (e.g. modified circuit constraint count) must fail closed.
        let mut drifted_pin = pin;
        drifted_pin.expected_trace_width = CANONICAL_BUD_AIR_TRACE_WIDTH + 1;
        assert!(matches!(
            verify_bud_air_vk_pin::<SC, BudAir>(
                &air,
                Some(&dummy_vk),
                CANONICAL_BUD_AIR_MIN_LOG_BLOWUP,
                CANONICAL_BUD_AIR_MIN_NUM_QUERIES,
                None,
                &drifted_pin,
            ),
            Err(VerificationError::InvalidProofShape)
        ));

        // Explicit VK commitment digest mismatch must fail closed.
        let mut digest_pin = pin;
        digest_pin.expected_vk_commitment = Some([0x77; 32]);
        assert!(matches!(
            verify_bud_air_vk_pin::<SC, BudAir>(
                &air,
                Some(&dummy_vk),
                CANONICAL_BUD_AIR_MIN_LOG_BLOWUP,
                CANONICAL_BUD_AIR_MIN_NUM_QUERIES,
                Some([0x88; 32]),
                &digest_pin,
            ),
            Err(VerificationError::InvalidProofShape)
        ));
    }
}
