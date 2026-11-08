use p3_air::symbolic::SymbolicAirBuilder;
use p3_air::Air;
use p3_commit::Pcs;
use p3_matrix::Matrix;
use tracing::debug_span;

use crate::bud_stark::{ProverConstraintFolder, StarkGenericConfig, Val};

/// Prover-side reusable data for preprocessed columns.
pub struct PreprocessedProverData<SC: StarkGenericConfig> {
    pub width: usize,
    pub degree_bits: usize,
    pub commitment: crate::bud_stark::Com<SC>,
    pub prover_data: crate::bud_stark::ProverData<SC>,
}

/// Verifier-side reusable data for preprocessed columns.
#[derive(Clone)]
pub struct PreprocessedVerifierKey<SC: StarkGenericConfig> {
    pub width: usize,
    pub degree_bits: usize,
    pub commitment: crate::bud_stark::Com<SC>,
}

/// The largest `degree_bits` a preprocessed setup is built for: the envelope bound
/// (`2^24` rows) the node accepts, far above the `2^22` rows the largest legal
/// trace needs. Above it the setup is refused rather than attempted.
pub const MAX_SETUP_DEGREE_BITS: usize = 24;

/// Commits the AIR's preprocessed columns for a trace of `2^degree_bits` rows.
///
/// Returns `None` when there is nothing to set up (no preprocessed columns) and also
/// when the request cannot be honoured: a `degree_bits` above
/// [`MAX_SETUP_DEGREE_BITS`] (so no shift can overflow and no allocation follows a
/// number a peer chose), or a preprocessed height that is not `2^degree_bits`. Those
/// were a shift overflow and an `assert_eq!`; on a node built with `panic = "abort"`
/// each was a way to stop it.
pub fn setup_preprocessed<SC, A>(
    config: &SC,
    air: &A,
    degree_bits: usize,
) -> Option<(PreprocessedProverData<SC>, PreprocessedVerifierKey<SC>)>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<ProverConstraintFolder<'a, SC>>,
{
    if degree_bits > MAX_SETUP_DEGREE_BITS {
        return None;
    }
    let pcs = config.pcs();
    let is_zk = config.is_zk() as usize;

    let init_degree = 1 << degree_bits;
    let degree = 1 << (degree_bits + is_zk);

    let preprocessed = air.preprocessed_trace()?;

    let width = preprocessed.width();
    if width == 0 {
        return None;
    }

    if preprocessed.height() != init_degree {
        return None;
    }

    let trace_domain = pcs.natural_domain_for_degree(degree);
    let (commitment, prover_data) = debug_span!("commit to preprocessed trace")
        .in_scope(|| pcs.commit_preprocessing([(trace_domain, preprocessed)]));

    let degree_bits = degree_bits + is_zk;
    let prover_data = PreprocessedProverData {
        width,
        degree_bits,
        commitment: commitment.clone(),
        prover_data,
    };
    let vk = PreprocessedVerifierKey {
        width,
        degree_bits,
        commitment,
    };
    Some((prover_data, vk))
}
