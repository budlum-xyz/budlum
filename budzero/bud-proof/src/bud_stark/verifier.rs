//! See [`crate::prover`] for an overview of the protocol and a more detailed soundness analysis.
//!
//! WIRING: unwired - reached through the `verify` entry points re-exported by
//! bud-proof, not by name from this workspace.

use p3_air::symbolic::SymbolicAirBuilder;
use p3_air::{Air, RowWindow};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
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
    if quotient_chunks.len() != quotient_chunks_domains.len() {
        return None;
    }
    let zps = quotient_chunks_domains
        .iter()
        .enumerate()
        .map(|(i, domain)| {
            quotient_chunks_domains
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, other_domain)| {
                    other_domain.vanishing_poly_at_point(zeta)
                        * other_domain
                            .vanishing_poly_at_point(domain.first_point())
                            .inverse()
                })
                .product::<SC::Challenge>()
        })
        .collect::<Vec<_>>();

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
    let sels = trace_domain.selectors_at_point(zeta);

    let main = VerticalPair::new(
        RowMajorMatrixView::new_row(trace_local),
        RowMajorMatrixView::new_row(trace_next),
    );

    let aux = match (aux_trace_local, aux_trace_next) {
        (Some(local), Some(next)) => VerticalPair::new(
            RowMajorMatrixView::new_row(local),
            RowMajorMatrixView::new_row(next),
        ),
        (Some(local), None) => VerticalPair::new(
            RowMajorMatrixView::new_row(local),
            RowMajorMatrixView::new(&[], 0),
        ),
        _ => VerticalPair::new(
            RowMajorMatrixView::new(&[], 0),
            RowMajorMatrixView::new(&[], 0),
        ),
    };

    let preprocessed = match (preprocessed_local, preprocessed_next) {
        (Some(local), Some(next)) => VerticalPair::new(
            RowMajorMatrixView::new_row(local),
            RowMajorMatrixView::new_row(next),
        ),
        _ => VerticalPair::new(
            RowMajorMatrixView::new(&[], 0),
            RowMajorMatrixView::new(&[], 0),
        ),
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
    // - If a verifier key is provided, trust its width.
    // - Otherwise, derive width from the AIR's preprocessed trace (if any).
    let preprocessed_width = preprocessed_vk
        .map(|vk| vk.width)
        .or_else(|| air.preprocessed_trace().as_ref().map(|m| m.width))
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
pub const MAX_VERIFIER_DEGREE_BITS: usize = 32;

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

    // `degree_bits` is deserialized out of the proof bytes, so it is whatever
    // the submitter sent. `1 << degree_bits` panics on a shift past the word
    // width, and the release profile sets `overflow-checks = true` with
    // `panic = "abort"`, so a corrupt proof takes the node down rather than
    // being rejected.
    //
    // Found by CI: `invalid_proof_burns_fee_and_leaves_state_unchanged` flips
    // one byte of a real proof and expects a rejection. It passed on main and
    // failed here, because absorbing the FRI parameters changed the byte
    // layout of the produced proof and moved which field that one flipped byte
    // lands in. The panic predates this path; the test corrupts a fixed field.
    //
    // The envelope carries its own `degree_bits` and the L1 checks that one
    // against `MAX_DEGREE_BITS`. This is a different field, inside the
    // serialized proof, and nothing compared the two. Bounding it here covers
    // every caller rather than the one that remembered.
    // The bound is not `usize::BITS` but well below it, because `degree_bits`
    // is shifted again further down together with the quotient chunk count:
    // `1 << (degree_bits + log_num_quotient_chunks)`. A value that only just
    // fits the first shift overflows the second. `MAX_VERIFIER_DEGREE_BITS`
    // leaves room for that addition and is far above any honest trace: 2^32
    // rows at the current width is more memory than any prover has.
    if *degree_bits > MAX_VERIFIER_DEGREE_BITS {
        return Err(VerificationError::InvalidProofShape);
    }

    let pcs = config.pcs();
    let degree = 1 << degree_bits;
    let trace_domain = pcs.natural_domain_for_degree(degree);
    // TODO: allow moving preprocessed commitment to preprocess time, if known in advance
    let (preprocessed_width, preprocessed_commit) =
        process_preprocessed_trace::<SC, A>(air, opened_values, preprocessed_vk)?;

    // Ensure the preprocessed trace and main trace have the same height.
    if let Some(vk) = preprocessed_vk {
        if preprocessed_width > 0 && vk.degree_bits != *degree_bits {
            return Err(VerificationError::InvalidProofShape);
        }
    }

    let has_aux_trace = commitments.aux_trace.is_some();
    let permutation_width = if has_aux_trace { 3 } else { 0 };
    let layout = AirLayout {
        preprocessed_width,
        main_width: air.width(),
        num_public_values: air.num_public_values(),
        permutation_width,
        num_permutation_challenges: if has_aux_trace { 3 } else { 0 },
        ..Default::default()
    };
    let log_num_quotient_chunks =
        get_log_num_quotient_chunks::<Val<SC>, A>(air, layout, config.is_zk() as usize);
    let num_quotient_chunks = 1 << (log_num_quotient_chunks + config.is_zk() as usize);
    let mut challenger = config.initialise_challenger();
    let init_trace_domain = pcs.natural_domain_for_degree(degree >> (config.is_zk() as usize));

    let quotient_domain =
        trace_domain.create_disjoint_domain(1 << (degree_bits + log_num_quotient_chunks));
    let quotient_chunks_domains = quotient_domain.split_domains(num_quotient_chunks);

    let randomized_quotient_chunks_domains = quotient_chunks_domains
        .iter()
        .map(|domain| pcs.natural_domain_for_degree(domain.size() << (config.is_zk() as usize)))
        .collect::<Vec<_>>();
    // Check that the random commitments are/are not present depending on the ZK setting.
    // - If ZK is enabled, the prover should have random commitments.
    // - If ZK is not enabled, the prover should not have random commitments.
    if (opened_values.random.is_some() != SC::Pcs::ZK)
        || (commitments.random.is_some() != SC::Pcs::ZK)
    {
        return Err(VerificationError::RandomizationError);
    }

    let air_width = A::width(air);
    let main_next = !air.main_next_row_columns().is_empty();
    let pre_next = !air.preprocessed_next_row_columns().is_empty();
    let trace_next_ok = if main_next {
        opened_values
            .trace_next
            .as_ref()
            .is_some_and(|v| v.len() == air_width)
    } else {
        opened_values.trace_next.is_none()
    };
    let expected_aux_base_width = permutation_width * SC::Challenge::DIMENSION;
    let aux_shape_ok = if has_aux_trace {
        opened_values
            .aux_trace_local
            .as_ref()
            .is_some_and(|v| v.len() == expected_aux_base_width)
            && (!main_next
                || opened_values
                    .aux_trace_next
                    .as_ref()
                    .is_some_and(|v| v.len() == expected_aux_base_width))
    } else {
        opened_values.aux_trace_local.is_none() && opened_values.aux_trace_next.is_none()
    };
    let valid_shape = opened_values.trace_local.len() == air_width
        && trace_next_ok
        && aux_shape_ok
        && opened_values.quotient_chunks.len() == num_quotient_chunks
        && opened_values
            .quotient_chunks
            .iter()
            .all(|qc| qc.len() == SC::Challenge::DIMENSION)
        // We've already checked that opened_values.random is present if and only if ZK is enabled.
        && opened_values.random.as_ref().is_none_or(|r_comm| r_comm.len() == SC::Challenge::DIMENSION);
    if !valid_shape {
        return Err(VerificationError::InvalidProofShape);
    }

    // Observe the instance.
    challenger.observe(Val::<SC>::from_usize(proof.degree_bits));
    challenger.observe(Val::<SC>::from_usize(
        proof.degree_bits - config.is_zk() as usize,
    ));
    challenger.observe(Val::<SC>::from_usize(preprocessed_width));
    // Same slice the prover absorbed, at the same point. The FRI parameters
    // set the soundness error and the grinding cost, and until this line they
    // were the one part of the instance the transcript did not cover. See
    // `StarkGenericConfig::security_parameters`.
    //
    // Still not covered: an encoding of the AIR itself, which would protect
    // against transcript collisions between distinct instances. The known
    // attack in this family comes from omitting public values, and those are
    // absorbed below.
    challenger.observe_slice(&config.security_parameters());
    challenger.observe(commitments.trace.clone());
    if preprocessed_width > 0 {
        // `process_preprocessed_trace` only returns `Some` together with a
        // non-zero width, so this is unreachable on that path. It is an
        // `Err` rather than an `unwrap` because the guarantee lives in
        // another function: a later edit there would turn a rejected proof
        // into a panicking node, and a verifier panic is a liveness bug
        // reachable by anyone who can submit a proof.
        let commit = preprocessed_commit
            .as_ref()
            .ok_or(VerificationError::InvalidProofShape)?;
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

    // Get the first Fiat Shamir challenge which will be used to combine all constraint polynomials
    // Into a single polynomial.
    //
    // Soundness Error: n/|EF| where n is the number of constraints.
    let alpha = challenger.sample_algebra_element();
    challenger.observe(commitments.quotient_chunks.clone());

    // We've already checked that commitments.random is present if and only if ZK is enabled.
    // Observe the random commitment if it is present.
    if let Some(r_commit) = commitments.random.clone() {
        challenger.observe(r_commit);
    }

    // Get an out-of-domain point to open our values at.
    //
    // Soundness Error: dN/|EF| where `N` is the trace length and our constraint polynomial has degree `d`.
    let zeta = challenger.sample_algebra_element();
    let zeta_next = init_trace_domain
        .next_point(zeta)
        .ok_or(VerificationError::NextPointUnavailable)?;

    // We've already checked that commitments.random and opened_values.random are present if and only if ZK is enabled.
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
        if main_next {
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
    // `valid_shape` above ties these to `has_aux_trace`, which is derived from
    // the same `commitments.aux_trace`. Re-checking here keeps the rejection
    // local to the value being read instead of depending on a check performed
    // a hundred lines earlier.
    let aux_round = match commitments.aux_trace.clone() {
        Some(commit) => {
            let local = opened_values
                .aux_trace_local
                .clone()
                .ok_or(VerificationError::InvalidProofShape)?;
            let mut aux_points = vec![(zeta, local)];
            if main_next {
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
        // Check the commitment on the randomized domains.
        zip_eq(
            randomized_quotient_chunks_domains.iter(),
            &opened_values.quotient_chunks,
            VerificationError::InvalidProofShape,
        )?
        .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
        .collect::<Vec<_>>(),
    )]);

    // Add preprocessed commitment verification if present
    if preprocessed_width > 0 {
        let local = opened_values
            .preprocessed_local
            .clone()
            .ok_or(VerificationError::InvalidProofShape)?;
        let mut pre_points = vec![(zeta, local)];
        if pre_next {
            let next = opened_values
                .preprocessed_next
                .clone()
                .ok_or(VerificationError::InvalidProofShape)?;
            pre_points.push((zeta_next, next));
        }
        let commit = preprocessed_commit.ok_or(VerificationError::InvalidProofShape)?;
        coms_to_verify.push((commit, vec![(trace_domain, pre_points)]));
    }

    pcs.verify(coms_to_verify, opening_proof, &mut challenger)
        .map_err(VerificationError::InvalidOpeningArgument)?;

    let quotient = recompose_quotient_from_chunks::<SC>(
        &quotient_chunks_domains,
        &opened_values.quotient_chunks,
        zeta,
    )
    .ok_or(VerificationError::InvalidProofShape)?;

    let zeros;
    let trace_next_slice = match &opened_values.trace_next {
        Some(v) => v.as_slice(),
        None => {
            zeros = vec![SC::Challenge::ZERO; air_width];
            &zeros
        }
    };
    let pre_next_zeros;
    let preprocessed_next_for_verify = match &opened_values.preprocessed_next {
        Some(v) => Some(v.as_slice()),
        None if preprocessed_width > 0 => {
            pre_next_zeros = vec![SC::Challenge::ZERO; preprocessed_width];
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
        init_trace_domain,
        zeta,
        alpha,
        &random_challenges,
        quotient,
    )?;

    Ok(())
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
