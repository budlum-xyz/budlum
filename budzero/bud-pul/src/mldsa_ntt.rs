//! The ML-DSA number theoretic transform over q = 8380417.
//!
//! This is the plain Rust definition of FIPS 204 algorithms 41 and 42 that the NTT chip must
//! reproduce row by row. It is the oracle for the chip's equality test: whatever the AIR proves
//! has to equal these functions, and these functions are checked here against the schoolbook
//! product in `Z_q[X] / (X^256 + 1)` instead of against themselves.

use bud_proof::plonky3_prover::{
    prove_chip_with_preprocessed, verify_chip_with_preprocessed, ChipProof,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

/// The ML-DSA modulus.
pub const Q: u64 = 8_380_417;

/// The degree of the ring polynomials.
pub const N: usize = 256;

/// A primitive 512th root of unity modulo `Q` (FIPS 204, section 7.5).
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const ZETA: u64 = 1_753;

/// `256^-1 mod Q`, the scaling of the inverse transform.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const N_INV: u64 = 8_347_681;

fn pow_mod(mut base: u64, mut exp: u64) -> u64 {
    let mut acc = 1u64;
    base %= Q;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * base % Q;
        }
        base = base * base % Q;
        exp >>= 1;
    }
    acc
}

fn bit_reverse_8(mut value: usize) -> usize {
    let mut out = 0usize;
    for _ in 0..8 {
        out = (out << 1) | (value & 1);
        value >>= 1;
    }
    out
}

/// `zetas[k] = ZETA^BitRev8(k) mod Q`, the twiddle table of the transform.
#[must_use]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn zetas() -> [u64; N] {
    let mut table = [0u64; N];
    for (k, slot) in table.iter_mut().enumerate() {
        *slot = pow_mod(ZETA, bit_reverse_8(k) as u64);
    }
    table
}

/// The forward transform (FIPS 204 algorithm 41). Inputs are reduced modulo `Q` first.
#[must_use]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn ntt(input: &[u64; N]) -> [u64; N] {
    let zetas = zetas();
    let mut w = input.map(|c| c % Q);
    let mut m = 0usize;
    let mut len = 128usize;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            m += 1;
            let z = zetas[m];
            for j in start..start + len {
                let t = z * w[j + len] % Q;
                w[j + len] = (w[j] + Q - t) % Q;
                w[j] = (w[j] + t) % Q;
            }
            start += 2 * len;
        }
        len /= 2;
    }
    w
}

/// The inverse transform (FIPS 204 algorithm 42), including the final scaling by `256^-1`.
#[must_use]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn inverse_ntt(input: &[u64; N]) -> [u64; N] {
    let zetas = zetas();
    let mut w = input.map(|c| c % Q);
    let mut m = N;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            m -= 1;
            let z = (Q - zetas[m]) % Q;
            for j in start..start + len {
                let t = w[j];
                w[j] = (t + w[j + len]) % Q;
                w[j + len] = (t + Q - w[j + len]) % Q * z % Q;
            }
            start += 2 * len;
        }
        len *= 2;
    }
    w.map(|c| c * N_INV % Q)
}

/// The product in `Z_q[X] / (X^256 + 1)` through the transform: pointwise in the NTT domain.
#[must_use]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn multiply(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
    let (na, nb) = (ntt(a), ntt(b));
    let mut product = [0u64; N];
    for i in 0..N {
        product[i] = na[i] * nb[i] % Q;
    }
    inverse_ntt(&product)
}

/// Number of butterfly layers in a 256-point FIPS 204 ML-DSA NTT.
const NTT_LAYERS: usize = 8;

/// Number of butterflies per ML-DSA forward NTT (`8 * 128`).
pub const BUTTERFLIES_PER_NTT: usize = 1024;

/// Maximum number of polynomials in one NTT chip batch (`64 * 1024 = 65536` rows).
const MAX_NTT_BATCH: usize = 64;

/// Bit width of canonical ML-DSA field elements (`Q = 8_380_417 < 2^23`).
const Q_BITS: usize = 23;
const Q_MINUS_1: u64 = Q - 1;
const _: () = assert!(Q < (1u64 << Q_BITS), "Q must fit in 23 bits");

const COL_A: usize = 0;
const COL_B: usize = 1;
const COL_Z: usize = 2;
const COL_T: usize = 3;
const COL_QMUL: usize = 4;
const COL_OUT_HI: usize = 5;
const COL_OUT_LO: usize = 6;
const COL_C_ADD: usize = 7;
const COL_C_SUB: usize = 8;
const COL_T_BITS: usize = 9;
const COL_T_COMP_BITS: usize = COL_T_BITS + Q_BITS;
const COL_QMUL_BITS: usize = COL_T_COMP_BITS + Q_BITS;
const COL_HI_BITS: usize = COL_QMUL_BITS + Q_BITS;
const COL_HI_COMP_BITS: usize = COL_HI_BITS + Q_BITS;
const COL_LO_BITS: usize = COL_HI_COMP_BITS + Q_BITS;
const COL_LO_COMP_BITS: usize = COL_LO_BITS + Q_BITS;

/// Main trace width of `NttButterflyAir`.
const NTT_TRACE_WIDTH: usize = COL_LO_COMP_BITS + Q_BITS;

/// Preprocessed width of `NttButterflyAir`: `(a, b, z, out_hi, out_lo, is_active)`.
const NTT_PREP_WIDTH: usize = 6;

const PREP_A: usize = 0;
const PREP_B: usize = 1;
const PREP_Z: usize = 2;
const PREP_HI: usize = 3;
const PREP_LO: usize = 4;
const PREP_ACTIVE: usize = 5;

/// Errors returned by the ML-DSA NTT chip prover or verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NttChipError {
    /// Empty polynomial batch.
    Empty,
    /// Batch exceeds the maximum supported batch size.
    TooMany(usize),
    /// A polynomial coefficient or intermediate witness is `>= Q`.
    NonCanonicalCoefficient,
    /// Input, output, or intermediate layer array lengths do not match.
    ShapeMismatch,
    /// The STARK proof failed verification.
    Rejected(String),
}

#[derive(Debug, Clone, Copy)]
struct ButterflyRecord {
    a: u64,
    b: u64,
    z: u64,
    out_hi: u64,
    out_lo: u64,
}

/// Plonky3 AIR proving canonical FIPS 204 ML-DSA radix-2 Cooley-Tukey
/// butterflies modulo `Q = 8_380_417` inside the 64-bit Goldilocks field, with
/// every inter-layer wire bound through preprocessed commitments.
struct NttButterflyAir {
    butterflies: Vec<ButterflyRecord>,
}

impl NttButterflyAir {
    fn from_schedule(
        inputs: &[[u64; N]],
        layer_states: &[[[u64; N]; NTT_LAYERS - 1]],
        outputs: &[[u64; N]],
    ) -> Result<Self, NttChipError> {
        if inputs.is_empty() {
            return Err(NttChipError::Empty);
        }
        if inputs.len() > MAX_NTT_BATCH {
            return Err(NttChipError::TooMany(inputs.len()));
        }
        if inputs.len() != outputs.len() || inputs.len() != layer_states.len() {
            return Err(NttChipError::ShapeMismatch);
        }
        for poly in inputs.iter().chain(outputs.iter()) {
            if poly.iter().any(|&c| c >= Q) {
                return Err(NttChipError::NonCanonicalCoefficient);
            }
        }
        for layers in layer_states {
            for layer in layers {
                if layer.iter().any(|&c| c >= Q) {
                    return Err(NttChipError::NonCanonicalCoefficient);
                }
            }
        }

        let zeta_table = zetas();
        let mut butterflies = Vec::with_capacity(inputs.len() * BUTTERFLIES_PER_NTT);
        for ((input, layers), output) in inputs.iter().zip(layer_states.iter()).zip(outputs.iter())
        {
            let mut m = 0usize;
            let mut len = 128usize;
            for layer_idx in 0..NTT_LAYERS {
                let src = if layer_idx == 0 {
                    input
                } else {
                    &layers[layer_idx - 1]
                };
                let dst = if layer_idx + 1 == NTT_LAYERS {
                    output
                } else {
                    &layers[layer_idx]
                };
                let mut start = 0usize;
                while start < N {
                    m += 1;
                    let z = zeta_table[m];
                    for j in start..start + len {
                        butterflies.push(ButterflyRecord {
                            a: src[j],
                            b: src[j + len],
                            z,
                            out_hi: dst[j],
                            out_lo: dst[j + len],
                        });
                    }
                    start += 2 * len;
                }
                len /= 2;
            }
        }
        Ok(Self { butterflies })
    }

    fn write_bits(row: &mut [Goldilocks], start_col: usize, value: u64) {
        for bit in 0..Q_BITS {
            row[start_col + bit] = Goldilocks::from_u64((value >> bit) & 1);
        }
    }

    fn build_trace(&self) -> RowMajorMatrix<Goldilocks> {
        let num_rows = self.butterflies.len().next_power_of_two();
        let mut values = vec![Goldilocks::ZERO; num_rows * NTT_TRACE_WIDTH];
        for row_idx in 0..num_rows {
            let rec = self
                .butterflies
                .get(row_idx)
                .copied()
                .unwrap_or(ButterflyRecord {
                    a: 0,
                    b: 0,
                    z: 1,
                    out_hi: 0,
                    out_lo: 0,
                });
            let prod = rec.z * rec.b;
            let q_mul = prod / Q;
            let t = prod % Q;
            let sum = rec.a + t;
            let c_add = u64::from(sum >= Q);
            let out_hi = if sum >= Q { sum - Q } else { sum };
            let diff = rec.a + Q - t;
            let c_sub = u64::from(diff >= Q);
            let out_lo = if diff >= Q { diff - Q } else { diff };

            let base = row_idx * NTT_TRACE_WIDTH;
            let row = &mut values[base..base + NTT_TRACE_WIDTH];
            row[COL_A] = Goldilocks::from_u64(rec.a);
            row[COL_B] = Goldilocks::from_u64(rec.b);
            row[COL_Z] = Goldilocks::from_u64(rec.z);
            row[COL_T] = Goldilocks::from_u64(t);
            row[COL_QMUL] = Goldilocks::from_u64(q_mul);
            row[COL_OUT_HI] = Goldilocks::from_u64(out_hi);
            row[COL_OUT_LO] = Goldilocks::from_u64(out_lo);
            row[COL_C_ADD] = Goldilocks::from_u64(c_add);
            row[COL_C_SUB] = Goldilocks::from_u64(c_sub);
            Self::write_bits(row, COL_T_BITS, t);
            Self::write_bits(row, COL_T_COMP_BITS, Q_MINUS_1 - t);
            Self::write_bits(row, COL_QMUL_BITS, q_mul);
            Self::write_bits(row, COL_HI_BITS, out_hi);
            Self::write_bits(row, COL_HI_COMP_BITS, Q_MINUS_1 - out_hi);
            Self::write_bits(row, COL_LO_BITS, out_lo);
            Self::write_bits(row, COL_LO_COMP_BITS, Q_MINUS_1 - out_lo);
        }
        RowMajorMatrix::new(values, NTT_TRACE_WIDTH)
    }

    fn constrain_bits<AB: AirBuilder>(
        builder: &mut AB,
        bits: &[AB::Expr; Q_BITS],
        target: AB::Expr,
    ) {
        let mut acc = AB::Expr::ZERO;
        let mut pow = 1u64;
        for b in bits {
            builder.assert_bool(b.clone());
            acc += AB::Expr::from_u64(pow) * b.clone();
            pow <<= 1;
        }
        builder.assert_eq(acc, target);
    }
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for NttButterflyAir {
    fn width(&self) -> usize {
        NTT_TRACE_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        if self.butterflies.is_empty() {
            return None;
        }
        let num_rows = self.butterflies.len().next_power_of_two();
        let mut values = vec![F::ZERO; num_rows * NTT_PREP_WIDTH];
        for (idx, rec) in self.butterflies.iter().enumerate() {
            let base = idx * NTT_PREP_WIDTH;
            values[base + PREP_A] = F::from_u64(rec.a);
            values[base + PREP_B] = F::from_u64(rec.b);
            values[base + PREP_Z] = F::from_u64(rec.z);
            values[base + PREP_HI] = F::from_u64(rec.out_hi);
            values[base + PREP_LO] = F::from_u64(rec.out_lo);
            values[base + PREP_ACTIVE] = F::ONE;
        }
        Some(RowMajorMatrix::new(values, NTT_PREP_WIDTH))
    }
}

impl<AB: AirBuilder> Air<AB> for NttButterflyAir
where
    AB::F: Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        let (
            a,
            b,
            z,
            t,
            q_mul,
            out_hi,
            out_lo,
            c_add,
            c_sub,
            t_bits,
            t_comp_bits,
            qmul_bits,
            hi_bits,
            hi_comp_bits,
            lo_bits,
            lo_comp_bits,
            pre_a,
            pre_b,
            pre_z,
            pre_hi,
            pre_lo,
            active,
        ) = {
            let main = builder.main();
            let local = main.current_slice();
            let pre = builder.preprocessed();
            let pre_cur = pre.current_slice();

            let read_bits = |start: usize| -> [AB::Expr; Q_BITS] {
                core::array::from_fn(|bit| local[start + bit].into())
            };

            (
                AB::Expr::from(local[COL_A]),
                AB::Expr::from(local[COL_B]),
                AB::Expr::from(local[COL_Z]),
                AB::Expr::from(local[COL_T]),
                AB::Expr::from(local[COL_QMUL]),
                AB::Expr::from(local[COL_OUT_HI]),
                AB::Expr::from(local[COL_OUT_LO]),
                AB::Expr::from(local[COL_C_ADD]),
                AB::Expr::from(local[COL_C_SUB]),
                read_bits(COL_T_BITS),
                read_bits(COL_T_COMP_BITS),
                read_bits(COL_QMUL_BITS),
                read_bits(COL_HI_BITS),
                read_bits(COL_HI_COMP_BITS),
                read_bits(COL_LO_BITS),
                read_bits(COL_LO_COMP_BITS),
                AB::Expr::from(pre_cur[PREP_A]),
                AB::Expr::from(pre_cur[PREP_B]),
                AB::Expr::from(pre_cur[PREP_Z]),
                AB::Expr::from(pre_cur[PREP_HI]),
                AB::Expr::from(pre_cur[PREP_LO]),
                AB::Expr::from(pre_cur[PREP_ACTIVE]),
            )
        };

        let q = AB::Expr::from_u64(Q);
        let q_minus_1 = AB::Expr::from_u64(Q_MINUS_1);

        // Modular multiplication: z * b = q_mul * Q + t
        builder.assert_eq(z.clone() * b.clone(), q_mul.clone() * q.clone() + t.clone());

        // Modular addition and subtraction with boolean carry flags.
        builder.assert_bool(c_add.clone());
        builder.assert_bool(c_sub.clone());
        builder.assert_eq(a.clone() + t.clone(), c_add * q.clone() + out_hi.clone());
        builder.assert_eq(
            a.clone() + q - t.clone(),
            c_sub * AB::Expr::from_u64(Q) + out_lo.clone(),
        );

        // Canonical range checks: t, out_hi, out_lo in [0, Q) and q_mul in [0, 2^23).
        Self::constrain_bits(builder, &t_bits, t.clone());
        Self::constrain_bits(builder, &t_comp_bits, q_minus_1.clone() - t);
        Self::constrain_bits(builder, &qmul_bits, q_mul);
        Self::constrain_bits(builder, &hi_bits, out_hi.clone());
        Self::constrain_bits(builder, &hi_comp_bits, q_minus_1.clone() - out_hi.clone());
        Self::constrain_bits(builder, &lo_bits, out_lo.clone());
        Self::constrain_bits(builder, &lo_comp_bits, q_minus_1 - out_lo.clone());

        // Preprocessed inter-layer wire and boundary bindings.
        builder.when(active.clone()).assert_eq(a, pre_a);
        builder.when(active.clone()).assert_eq(b, pre_b);
        builder.when(active.clone()).assert_eq(z, pre_z);
        builder.when(active.clone()).assert_eq(out_hi, pre_hi);
        builder.when(active).assert_eq(out_lo, pre_lo);
    }
}

/// A cryptographically bound ML-DSA forward NTT batch proof.
#[derive(Clone)]
pub struct NttBatchProof {
    pub layer_states: Vec<[[u64; N]; NTT_LAYERS - 1]>,
    pub proof: ChipProof,
}

fn ntt_with_layers(
    input: &[u64; N],
) -> Result<([[u64; N]; NTT_LAYERS - 1], [u64; N]), NttChipError> {
    if input.iter().any(|&c| c >= Q) {
        return Err(NttChipError::NonCanonicalCoefficient);
    }
    let zeta_table = zetas();
    let mut w = *input;
    let mut layers = [[0u64; N]; NTT_LAYERS - 1];
    let mut m = 0usize;
    let mut len = 128usize;
    let mut layer_idx = 0usize;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            m += 1;
            let z = zeta_table[m];
            for j in start..start + len {
                let t = z * w[j + len] % Q;
                w[j + len] = (w[j] + Q - t) % Q;
                w[j] = (w[j] + t) % Q;
            }
            start += 2 * len;
        }
        if let Some(slot) = layers.get_mut(layer_idx) {
            *slot = w;
        }
        layer_idx += 1;
        len /= 2;
    }
    Ok((layers, w))
}

/// Proves a batch of canonical FIPS 204 ML-DSA forward NTTs inside
/// `NttButterflyAir`.
///
/// # Errors
///
/// Refuses empty batches, oversized batches, non-canonical input coefficients
/// (`>= Q`), or proving failures.
pub fn prove_ntt_batch(
    inputs: &[[u64; N]],
) -> Result<(Vec<[u64; N]>, NttBatchProof), NttChipError> {
    if inputs.is_empty() {
        return Err(NttChipError::Empty);
    }
    if inputs.len() > MAX_NTT_BATCH {
        return Err(NttChipError::TooMany(inputs.len()));
    }
    let mut layer_states = Vec::with_capacity(inputs.len());
    let mut outputs = Vec::with_capacity(inputs.len());
    for input in inputs {
        let (layers, out) = ntt_with_layers(input)?;
        layer_states.push(layers);
        outputs.push(out);
    }
    let air = NttButterflyAir::from_schedule(inputs, &layer_states, &outputs)?;
    let trace = air.build_trace();
    let proof = prove_chip_with_preprocessed(&air, trace, &[]).map_err(NttChipError::Rejected)?;
    Ok((
        outputs,
        NttBatchProof {
            layer_states,
            proof,
        },
    ))
}

/// Verifies a [`NttBatchProof`] against the claimed `(inputs, outputs)` NTT
/// pairs without executing any modular multiplications in the verifier.
///
/// # Errors
///
/// Refuses empty batches, shape mismatches, non-canonical coefficients, wrong
/// trace heights, or invalid STARK proofs.
pub fn verify_ntt_batch(
    inputs: &[[u64; N]],
    outputs: &[[u64; N]],
    proof: &NttBatchProof,
) -> Result<(), NttChipError> {
    let air = NttButterflyAir::from_schedule(inputs, &proof.layer_states, outputs)?;
    let expected_rows = (inputs.len() * BUTTERFLIES_PER_NTT).next_power_of_two();
    let expected_degree_bits = expected_rows.trailing_zeros() as usize;
    verify_chip_with_preprocessed(&air, &proof.proof, expected_degree_bits, &[])
        .map_err(NttChipError::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seed: u64) -> [u64; N] {
        let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let mut out = [0u64; N];
        for slot in &mut out {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *slot = (state >> 33) % Q;
        }
        out
    }

    /// The schoolbook product modulo `X^256 + 1`: `X^256 = -1`.
    fn negacyclic(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let mut out = [0u64; N];
        for (i, &ai) in a.iter().enumerate() {
            for (j, &bj) in b.iter().enumerate() {
                let term = ai * bj % Q;
                let k = i + j;
                if k < N {
                    out[k] = (out[k] + term) % Q;
                } else {
                    out[k - N] = (out[k - N] + Q - term) % Q;
                }
            }
        }
        out
    }

    #[test]
    fn the_constants_are_what_the_standard_says() {
        assert_eq!(pow_mod(ZETA, 512), 1);
        assert_eq!(pow_mod(ZETA, 256), Q - 1);
        assert_eq!(N_INV * 256 % Q, 1);
        assert_eq!(zetas()[0], 1);
        assert_eq!(zetas()[1], pow_mod(ZETA, 128));
    }

    #[test]
    fn the_inverse_undoes_the_transform() {
        for seed in 0..4 {
            let a = sample(seed);
            assert_eq!(inverse_ntt(&ntt(&a)), a);
        }
    }

    #[test]
    fn the_transform_product_equals_the_schoolbook_product() {
        for seed in 0..3 {
            let a = sample(seed);
            let b = sample(seed + 100);
            assert_eq!(multiply(&a, &b), negacyclic(&a, &b));
        }
    }

    #[test]
    fn ntt_chip_proves_verifies_and_matches_reference_ntt() {
        let inputs = [sample(11), sample(22)];
        let (outputs, proof) = prove_ntt_batch(&inputs).expect("ntt prove");
        for (inp, out) in inputs.iter().zip(outputs.iter()) {
            assert_eq!(*out, ntt(inp));
        }
        verify_ntt_batch(&inputs, &outputs, &proof).expect("ntt verify");
    }

    #[test]
    fn ntt_chip_rejects_tampered_io_intermediate_and_non_canonical() {
        let inputs = [sample(3)];
        let (outputs, proof) = prove_ntt_batch(&inputs).expect("ntt prove");

        // Wrong output coefficient must fail.
        let mut bad_out = outputs.clone();
        bad_out[0][17] = (bad_out[0][17] + 1) % Q;
        assert!(verify_ntt_batch(&inputs, &bad_out, &proof).is_err());

        // Wrong input coefficient must fail.
        let mut bad_in = inputs;
        bad_in[0][0] = (bad_in[0][0] + 1) % Q;
        assert!(verify_ntt_batch(&bad_in, &outputs, &proof).is_err());

        // Tampered intermediate layer must fail.
        let mut bad_mid = proof.clone();
        bad_mid.layer_states[0][3][42] = (bad_mid.layer_states[0][3][42] + 1) % Q;
        assert!(verify_ntt_batch(&inputs, &outputs, &bad_mid).is_err());

        // Non-canonical input >= Q must fail.
        let mut non_canon = inputs;
        non_canon[0][5] = Q;
        assert_eq!(
            prove_ntt_batch(&non_canon).err(),
            Some(NttChipError::NonCanonicalCoefficient)
        );
        assert_eq!(
            verify_ntt_batch(&non_canon, &outputs, &proof),
            Err(NttChipError::NonCanonicalCoefficient)
        );
    }
}
