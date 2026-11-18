//! Reference external (non-`BudAir`) AIR proving a Goldilocks Fibonacci
//! recurrence under the exact same `BudZKVM` PCS configuration
//! (`ChipStarkConfig`).
//!
//! Used by Phase 5 (`Claim::Poly`, `AirRegistry`, `VerifyStark`) to prove and
//! verify STARK proofs produced outside `BudZKVM` without changing the PCS.
//!
//! WIRING: `prove_fibonacci` and `verify_fibonacci` are called by Phase 5
//! differential/external-AIR tests (`src/aggregation/tests/phase5.rs`) and
//! `benches/agg_phase5_pcs.rs`; `verify_fibonacci_algebra` is called by
//! `budlum_core::aggregation::air_registry::ExternalFibAirEvaluator`.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use crate::bud_stark::{AlgebraStatement, PcsOpeningShape};
use crate::plonky3_prover::{
    air_pcs_shape, prove_chip, verify_chip, verify_chip_algebra, ChipCommitments, ChipOpenedValues,
    ChipProof,
};

/// Column count of [`FibonacciAir`]: `[a, b]`.
const FIB_WIDTH: usize = 2;
/// Public value count of [`FibonacciAir`]: `[init_a, init_b, final_b]`.
const FIB_NUM_PUBLIC_VALUES: usize = 3;

/// External 2-column Fibonacci AIR over Goldilocks (`a_{i+1} = b_i`,
/// `b_{i+1} = a_i + b_i`) with boundary public values `[init_a, init_b, final_b]`.
#[derive(Clone, Copy, Debug, Default)]
struct FibonacciAir;

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        FIB_WIDTH
    }

    fn num_public_values(&self) -> usize {
        FIB_NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: Vec<AB::Expr> = main
            .current_slice()
            .iter()
            .cloned()
            .map(Into::into)
            .collect();
        let next: Vec<AB::Expr> = main.next_slice().iter().cloned().map(Into::into).collect();
        let pv: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .cloned()
            .map(Into::into)
            .collect();
        if local.len() < FIB_WIDTH || next.len() < FIB_WIDTH || pv.len() < FIB_NUM_PUBLIC_VALUES {
            return;
        }
        let a = local[0].clone();
        let b = local[1].clone();
        let next_a = next[0].clone();
        let next_b = next[1].clone();

        let init_a = pv[0].clone();
        let init_b = pv[1].clone();
        let final_b = pv[2].clone();

        builder.when_first_row().assert_eq(a.clone(), init_a);
        builder.when_first_row().assert_eq(b.clone(), init_b);
        builder.when_transition().assert_eq(next_a, b.clone());
        builder.when_transition().assert_eq(next_b, a + b.clone());
        builder.when_last_row().assert_eq(b, final_b);
    }
}

/// Computes the deterministic Fibonacci trace and public values
/// `[init_a, init_b, final_b]` for `1 << degree_bits` rows.
#[must_use]
fn build_fibonacci_trace(
    degree_bits: usize,
    init_a: u64,
    init_b: u64,
) -> (RowMajorMatrix<Goldilocks>, [u64; 3]) {
    let rows = 1usize << degree_bits;
    let mut values = Vec::with_capacity(rows.saturating_mul(FIB_WIDTH));
    let mut a = Goldilocks::new(init_a);
    let mut b = Goldilocks::new(init_b);
    for _ in 0..rows {
        values.push(a);
        values.push(b);
        let next_a = b;
        let next_b = a + b;
        a = next_a;
        b = next_b;
    }
    let last_b = values.last().map_or(0, PrimeField64::as_canonical_u64);
    let pvs = [
        Goldilocks::new(init_a).as_canonical_u64(),
        Goldilocks::new(init_b).as_canonical_u64(),
        last_b,
    ];
    (RowMajorMatrix::new(values, FIB_WIDTH), pvs)
}

/// Proves a Goldilocks Fibonacci sequence of length `1 << degree_bits` under
/// the canonical `BudZKVM` PCS configuration (`ChipStarkConfig`).
///
/// Returns `(proof, public_values_u64, shape)`.
///
/// # Errors
///
/// Returns an error if `degree_bits` is outside `4..=20` or if `init_a`/`init_b`
/// are non-canonical Goldilocks elements.
pub fn prove_fibonacci(
    degree_bits: usize,
    init_a: u64,
    init_b: u64,
) -> Result<(ChipProof, [u64; 3], PcsOpeningShape), String> {
    if !(4..=20).contains(&degree_bits) {
        return Err(format!(
            "fibonacci degree_bits {degree_bits} must be in 4..=20"
        ));
    }
    if init_a >= Goldilocks::ORDER_U64 || init_b >= Goldilocks::ORDER_U64 {
        return Err("non-canonical Goldilocks initial value".into());
    }
    let (trace, pvs_u64) = build_fibonacci_trace(degree_bits, init_a, init_b);
    let pvs: Vec<Goldilocks> = pvs_u64.iter().copied().map(Goldilocks::new).collect();
    let air = FibonacciAir;
    let proof = prove_chip(&air, trace, &pvs);
    let shape = air_pcs_shape(&air, degree_bits, false, 0)?;
    Ok((proof, pvs_u64, shape))
}

/// Full monolithic STARK verification of a [`FibonacciAir`] proof.
///
/// # Errors
///
/// Returns an error if public values are non-canonical or verification fails.
pub fn verify_fibonacci(proof: &ChipProof, public_values: &[u64]) -> Result<(), String> {
    if public_values.len() != FIB_NUM_PUBLIC_VALUES
        || public_values.iter().any(|&v| v >= Goldilocks::ORDER_U64)
    {
        return Err("invalid FibonacciAir public values".into());
    }
    let pvs: Vec<Goldilocks> = public_values.iter().copied().map(Goldilocks::new).collect();
    verify_chip(&FibonacciAir, proof, &pvs)
}

/// Stage 2 (`verify_algebra`) for [`FibonacciAir`]: re-derives `zeta` and
/// checks all Fibonacci constraints at `zeta` without running FRI.
///
/// # Errors
///
/// Returns an error if public values are invalid or `verify_algebra` fails.
pub fn verify_fibonacci_algebra(
    commitments: &ChipCommitments,
    opened_values: &ChipOpenedValues,
    degree_bits: usize,
    public_values: &[u64],
) -> Result<([u64; 3], PcsOpeningShape), String> {
    if public_values.len() != FIB_NUM_PUBLIC_VALUES
        || public_values.iter().any(|&v| v >= Goldilocks::ORDER_U64)
    {
        return Err("invalid FibonacciAir public values".into());
    }
    let pvs: Vec<Goldilocks> = public_values.iter().copied().map(Goldilocks::new).collect();
    let stmt = AlgebraStatement {
        commitments,
        opened_values,
        degree_bits,
        public_values: &pvs,
        preprocessed_vk: None,
    };
    verify_chip_algebra(&FibonacciAir, &stmt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bud_stark::PcsOpeningStatement;
    use crate::plonky3_prover::verify_chip_pcs_openings;

    #[test]
    fn fibonacci_full_and_two_stage_verify_agree() {
        let (proof, pvs, shape) = prove_fibonacci(4, 1, 1).expect("prove");
        assert!(verify_fibonacci(&proof, &pvs).is_ok());

        let pvs_f: Vec<Goldilocks> = pvs.iter().copied().map(Goldilocks::new).collect();
        let z1 = verify_chip_pcs_openings(&PcsOpeningStatement {
            shape,
            commitments: &proof.commitments,
            opened_values: &proof.opened_values,
            opening_proof: &proof.opening_proof,
            degree_bits: proof.degree_bits,
            public_values: &pvs_f,
            preprocessed_commit: None,
        })
        .expect("pcs openings");
        let (z2, shape2) = verify_fibonacci_algebra(
            &proof.commitments,
            &proof.opened_values,
            proof.degree_bits,
            &pvs,
        )
        .expect("algebra");
        assert_eq!(z1, z2);
        assert_eq!(shape, shape2);
    }
}
