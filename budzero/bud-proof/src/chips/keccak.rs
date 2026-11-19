//! The `Keccak-f[1600]` chip.
//!
//! A thin wrapper over `p3-keccak-air =0.7.0`: 24 trace rows per permutation, 16 bit
//! limbs, over Goldilocks. The AIR is generic in the field and Plonky3 ships a Goldilocks
//! example; the "field between 2^16 and 2^32" note of the crate is about the limb sums
//! staying below the modulus, which a 64 bit field satisfies with room to spare.
//!
//! The chip proves that the final-round row of each block equals Keccak-f applied to the
//! preimage of its first row. Binding those two to the rest of a statement (the XOF of
//! ExpandA, the message hash `mu`) is the job of the AIR that embeds the chip (
//!); `input_state` and `output_state` read them back from a trace for that.

use crate::plonky3_prover::{
    prove_chip, prove_chip_with_preprocessed, verify_chip, verify_chip_with_preprocessed, ChipProof,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_keccak_air::{generate_trace_rows, KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS, U64_LIMBS};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

/// Trace rows used by one permutation.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const ROWS_PER_PERMUTATION: usize = NUM_ROUNDS;

/// Trace columns of the chip.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COLUMNS: usize = NUM_KECCAK_COLS;

/// The most permutations one chip trace accepts. A proof over more rows is split by the
/// caller; the bound keeps a hostile input from sizing the trace.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const MAX_PERMUTATIONS: usize = 1 << 14;

/// Why a chip operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeccakChipError {
    /// No permutation was given.
    Empty,
    /// More than [`MAX_PERMUTATIONS`] permutations were given.
    TooMany(usize),
    /// The inputs, outputs, or proof metadata shapes do not match.
    ShapeMismatch,
    /// The proof did not verify.
    Rejected(String),
    /// The proof verified, but it is not bound to what the caller asked it to
    /// prove: the chip AIR exposes no public inputs, so a proof of any batch of
    /// permutations stands beside any statement list. Refusing is the only
    /// honest answer until the binding exists.
    UnboundProof,
}

/// Builds the trace of the given permutation inputs (state words in the standard
/// `x + 5 * y` order).
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn keccak_f_trace(inputs: &[[u64; 25]]) -> Result<RowMajorMatrix<Goldilocks>, KeccakChipError> {
    if inputs.is_empty() {
        return Err(KeccakChipError::Empty);
    }
    if inputs.len() > MAX_PERMUTATIONS {
        return Err(KeccakChipError::TooMany(inputs.len()));
    }
    Ok(generate_trace_rows::<Goldilocks>(inputs.to_vec(), 0))
}

/// The input state of permutation `index`, read back from a chip trace.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn input_state(trace: &RowMajorMatrix<Goldilocks>, index: usize) -> [u64; 25] {
    let row = index * ROWS_PER_PERMUTATION;
    read_state(trace, row, cols::preimage)
}

/// The output state of permutation `index`, read back from a chip trace.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn output_state(trace: &RowMajorMatrix<Goldilocks>, index: usize) -> [u64; 25] {
    let row = index * ROWS_PER_PERMUTATION + (ROWS_PER_PERMUTATION - 1);
    read_state(trace, row, cols::output)
}

fn read_state(
    trace: &RowMajorMatrix<Goldilocks>,
    row: usize,
    column: impl Fn(usize, usize, usize) -> usize,
) -> [u64; 25] {
    let mut state = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            let mut word = 0u64;
            for limb in 0..U64_LIMBS {
                let value = trace
                    .get(row, column(y, x, limb))
                    .map(|v| v.as_canonical_u64())
                    .unwrap_or(0);
                word |= value << (limb * 16);
            }
            state[x + 5 * y] = word;
        }
    }
    state
}

/// Column indices into `KeccakCols` laid out `repr(C)` with `T = u8`, derived
/// from the struct itself: `step_flags`, `export`, `preimage`, `a`, `c`,
/// `c_prime`, `a_prime`, `a_prime_prime`, `a_prime_prime_0_0_bits`,
/// `a_prime_prime_prime_0_0_limbs`.
///
/// `p3_keccak_air::input_limb` / `output_limb` are the SPONGE rate map: they
/// `debug_assert!(i < RATE_LIMBS)` and this chip reads the whole 25-lane
/// state, capacity included (the permutation AIR commits all of it). The
/// layout is pinned by `=0.7.0` in Cargo.toml and by the const assert below,
/// which is the guard that the numbers above were re-derived if the struct
/// ever moves.
mod cols {
    use super::*;

    /// Bytes after `step_flags` and `export`: the start of `preimage`.
    const PREIMAGE: usize = NUM_ROUNDS + 1;
    /// Start of `a_prime_prime` (bytes, `T = u8`).
    const A_PRIME_PRIME: usize =
        PREIMAGE + 25 * U64_LIMBS + 25 * U64_LIMBS + 5 * 64 + 5 * 64 + 5 * 5 * 64;
    /// Start of `a_prime_prime_prime_0_0_limbs`.
    const A_PRIME_PRIME_PRIME_0_0: usize = A_PRIME_PRIME + 25 * U64_LIMBS + 64;

    const _: () = assert!(
        NUM_KECCAK_COLS == A_PRIME_PRIME_PRIME_0_0 + U64_LIMBS,
        "p3-keccak-air KeccakCols moved; re-derive the column constants from the struct"
    );

    /// The preimage cell of lane `(y, x)`, limb `limb`.
    pub fn preimage(y: usize, x: usize, limb: usize) -> usize {
        PREIMAGE + (y * 5 + x) * U64_LIMBS + limb
    }

    /// The output cell of lane `(y, x)`, limb `limb`: lane 0 is stored in the
    /// dedicated tail register, the rest in `a_prime_prime`, matching
    /// `KeccakCols::a_prime_prime_prime`.
    pub fn output(y: usize, x: usize, limb: usize) -> usize {
        if y == 0 && x == 0 {
            A_PRIME_PRIME_PRIME_0_0 + limb
        } else {
            A_PRIME_PRIME + (y * 5 + x) * U64_LIMBS + limb
        }
    }
}

/// Proves the given permutations with the BudZero STARK parameters.
pub fn prove_keccak_f(inputs: &[[u64; 25]]) -> Result<ChipProof, KeccakChipError> {
    let trace = keccak_f_trace(inputs)?;
    Ok(prove_chip(&KeccakAir {}, trace, &[]))
}

/// Verifies a Keccak-f chip proof.
pub fn verify_keccak_f(proof: &ChipProof) -> Result<(), KeccakChipError> {
    verify_chip(&KeccakAir {}, proof, &[]).map_err(KeccakChipError::Rejected)
}

/// Packed 32-bit state words per 1600-bit Keccak state (two per 64-bit lane).
const BOUND_STATE_WORDS: usize = 50;

/// Width of the preprocessed schedule for `BoundKeccakAir`:
/// 50 packed 32-bit state words plus 1 active-permutation flag.
const BOUND_PREPROCESSED_WIDTH: usize = BOUND_STATE_WORDS + 1;

const COL_PREP_IS_ACTIVE: usize = BOUND_STATE_WORDS;
const COL_STEP_FLAG_FIRST: usize = 0;
const COL_STEP_FLAG_FINAL: usize = NUM_ROUNDS - 1;
const _: () = assert!(NUM_ROUNDS == 24, "Keccak-f[1600] requires 24 rounds");

/// `Keccak-f[1600]` chip AIR with preprocessed boundary commitments tying every
/// active permutation's 25-lane input state and 25-lane output state directly
/// into the STARK polynomial constraints.
///
/// Each 64-bit lane is committed as two canonical 32-bit words formed from
/// pairs of 16-bit limbs (`limb0 + 2^16 * limb1`). Because `KeccakAir` proves
/// every state bit is boolean, each 16-bit limb lies in `[0, 2^16)` and the
/// 32-bit packing is injective in the 64-bit Goldilocks field.
struct BoundKeccakAir {
    inputs: Vec<[u64; 25]>,
    outputs: Vec<[u64; 25]>,
}

impl BoundKeccakAir {
    /// Constructs a bound `Keccak-f[1600]` AIR over matching `(inputs, outputs)` pairs.
    fn new(inputs: Vec<[u64; 25]>, outputs: Vec<[u64; 25]>) -> Result<Self, KeccakChipError> {
        if inputs.is_empty() {
            return Err(KeccakChipError::Empty);
        }
        if inputs.len() > MAX_PERMUTATIONS {
            return Err(KeccakChipError::TooMany(inputs.len()));
        }
        if inputs.len() != outputs.len() {
            return Err(KeccakChipError::ShapeMismatch);
        }
        Ok(Self { inputs, outputs })
    }

    fn write_packed_state<F: PrimeCharacteristicRing>(row: &mut [F], state: &[u64; 25]) {
        for y in 0..5 {
            for x in 0..5 {
                let word = state[x + 5 * y];
                let lo = word & 0xFFFF_FFFF;
                let hi = word >> 32;
                let base = 2 * (y * 5 + x);
                row[base] = F::from_u64(lo);
                row[base + 1] = F::from_u64(hi);
            }
        }
    }
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for BoundKeccakAir {
    fn width(&self) -> usize {
        NUM_KECCAK_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        if self.inputs.is_empty() || self.inputs.len() != self.outputs.len() {
            return None;
        }
        let num_rows = (self.inputs.len() * NUM_ROUNDS).next_power_of_two();
        let mut values = vec![F::ZERO; num_rows * BOUND_PREPROCESSED_WIDTH];
        for (i, (input, output)) in self.inputs.iter().zip(self.outputs.iter()).enumerate() {
            let base_row = i * NUM_ROUNDS;
            for r in 0..NUM_ROUNDS {
                values[(base_row + r) * BOUND_PREPROCESSED_WIDTH + COL_PREP_IS_ACTIVE] = F::ONE;
            }
            let first_offset = base_row * BOUND_PREPROCESSED_WIDTH;
            Self::write_packed_state(
                &mut values[first_offset..first_offset + BOUND_STATE_WORDS],
                input,
            );
            let final_offset = (base_row + (NUM_ROUNDS - 1)) * BOUND_PREPROCESSED_WIDTH;
            Self::write_packed_state(
                &mut values[final_offset..final_offset + BOUND_STATE_WORDS],
                output,
            );
        }
        Some(RowMajorMatrix::new(values, BOUND_PREPROCESSED_WIDTH))
    }
}

impl<AB: AirBuilder> Air<AB> for BoundKeccakAir
where
    AB::F: Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        KeccakAir {}.eval(builder);

        let shift = AB::Expr::from_u64(1u64 << 16);
        let (is_active, first_step, final_step, prep_words, in_limbs, out_limbs) = {
            let main = builder.main();
            let local = main.current_slice();
            let pre = builder.preprocessed();
            let pre_cur = pre.current_slice();

            let is_active: AB::Expr = pre_cur[COL_PREP_IS_ACTIVE].into();
            let first_step: AB::Expr = local[COL_STEP_FLAG_FIRST].into();
            let final_step: AB::Expr = local[COL_STEP_FLAG_FINAL].into();
            let prep_words: [AB::Expr; BOUND_STATE_WORDS] =
                core::array::from_fn(|i| pre_cur[i].into());
            let in_limbs: [[AB::Expr; 4]; 25] = core::array::from_fn(|lane| {
                let y = lane / 5;
                let x = lane % 5;
                core::array::from_fn(|limb| local[cols::preimage(y, x, limb)].into())
            });
            let out_limbs: [[AB::Expr; 4]; 25] = core::array::from_fn(|lane| {
                let y = lane / 5;
                let x = lane % 5;
                core::array::from_fn(|limb| local[cols::output(y, x, limb)].into())
            });
            (
                is_active, first_step, final_step, prep_words, in_limbs, out_limbs,
            )
        };

        let bind_input = is_active.clone() * first_step;
        let bind_output = is_active * final_step;

        for lane in 0..25 {
            let base = 2 * lane;
            let in_lo = in_limbs[lane][0].clone() + shift.clone() * in_limbs[lane][1].clone();
            let in_hi = in_limbs[lane][2].clone() + shift.clone() * in_limbs[lane][3].clone();
            let out_lo = out_limbs[lane][0].clone() + shift.clone() * out_limbs[lane][1].clone();
            let out_hi = out_limbs[lane][2].clone() + shift.clone() * out_limbs[lane][3].clone();

            builder
                .when(bind_input.clone())
                .assert_eq(in_lo, prep_words[base].clone());
            builder
                .when(bind_input.clone())
                .assert_eq(in_hi, prep_words[base + 1].clone());
            builder
                .when(bind_output.clone())
                .assert_eq(out_lo, prep_words[base].clone());
            builder
                .when(bind_output.clone())
                .assert_eq(out_hi, prep_words[base + 1].clone());
        }
    }
}

/// A cryptographically bound `Keccak-f[1600]` chip proof tying a specific batch
/// of `(inputs, outputs)` state pairs into the STARK's preprocessed commitment.
#[derive(Clone)]
pub struct BoundKeccakProof {
    pub num_permutations: usize,
    pub proof: ChipProof,
}

/// Proves a batch of `Keccak-f[1600]` permutations with every input and output
/// cryptographically bound into the STARK proof.
///
/// # Errors
///
/// Returns [`KeccakChipError::Empty`], [`KeccakChipError::TooMany`], or
/// [`KeccakChipError::Rejected`] if proving fails.
pub fn prove_bound_keccak_f(
    inputs: &[[u64; 25]],
) -> Result<(BoundKeccakProof, Vec<[u64; 25]>), KeccakChipError> {
    let trace = keccak_f_trace(inputs)?;
    let outputs: Vec<[u64; 25]> = (0..inputs.len()).map(|i| output_state(&trace, i)).collect();
    let air = BoundKeccakAir::new(inputs.to_vec(), outputs.clone())?;
    let proof =
        prove_chip_with_preprocessed(&air, trace, &[]).map_err(KeccakChipError::Rejected)?;
    Ok((
        BoundKeccakProof {
            num_permutations: inputs.len(),
            proof,
        },
        outputs,
    ))
}

/// Verifies a [`BoundKeccakProof`] against the exact claimed `(inputs, outputs)`
/// permutation pairs.
///
/// # Errors
///
/// Refuses empty batches, shape mismatches, wrong trace heights, or any proof
/// that does not verify against the committed `(inputs, outputs)` schedule.
pub fn verify_bound_keccak_f(
    inputs: &[[u64; 25]],
    outputs: &[[u64; 25]],
    proof: &BoundKeccakProof,
) -> Result<(), KeccakChipError> {
    if inputs.is_empty() {
        return Err(KeccakChipError::Empty);
    }
    if inputs.len() > MAX_PERMUTATIONS {
        return Err(KeccakChipError::TooMany(inputs.len()));
    }
    if inputs.len() != outputs.len() || proof.num_permutations != inputs.len() {
        return Err(KeccakChipError::ShapeMismatch);
    }
    let expected_rows = (inputs.len() * NUM_ROUNDS).next_power_of_two();
    let expected_degree_bits = expected_rows.trailing_zeros() as usize;
    let air = BoundKeccakAir::new(inputs.to_vec(), outputs.to_vec())?;
    verify_chip_with_preprocessed(&air, &proof.proof, expected_degree_bits, &[])
        .map_err(KeccakChipError::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(mut state: [u64; 25]) -> [u64; 25] {
        tiny_keccak::keccakf(&mut state);
        state
    }

    fn sample(seed: u64) -> [u64; 25] {
        core::array::from_fn(|i| {
            (i as u64 + 1)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .rotate_left((seed % 63) as u32 + 1)
                ^ seed
        })
    }

    #[test]
    fn the_trace_equals_tiny_keccak_for_each_input() {
        let inputs: Vec<[u64; 25]> = (0..5).map(sample).chain([[0u64; 25]]).collect();
        let trace = keccak_f_trace(&inputs).expect("trace");
        for (i, input) in inputs.iter().enumerate() {
            assert_eq!(input_state(&trace, i), *input);
            assert_eq!(output_state(&trace, i), reference(*input));
        }
    }

    #[test]
    fn a_proof_verifies() {
        let proof = prove_keccak_f(&[sample(1), sample(2)]).expect("prove");
        verify_keccak_f(&proof).expect("verify");
    }

    #[test]
    fn a_tampered_output_is_refused() {
        let inputs = [sample(3)];
        let mut trace = keccak_f_trace(&inputs).expect("trace");
        let column = p3_keccak_air::output_limb(0);
        let row = ROWS_PER_PERMUTATION - 1;
        let width = COLUMNS;
        let cell = &mut trace.values[row * width + column];
        *cell += Goldilocks::new(1);
        let proof = std::panic::catch_unwind(|| prove_chip(&KeccakAir {}, trace, &[]));
        // A debug build refuses to prove an unsatisfied trace (panic); a release build
        // proves it and the verifier must refuse.
        if let Ok(proof) = proof {
            assert!(verify_keccak_f(&proof).is_err());
        }
    }

    #[test]
    fn empty_and_oversized_inputs_are_refused() {
        assert_eq!(keccak_f_trace(&[]).unwrap_err(), KeccakChipError::Empty);
        let many = vec![[0u64; 25]; MAX_PERMUTATIONS + 1];
        assert_eq!(
            keccak_f_trace(&many).unwrap_err(),
            KeccakChipError::TooMany(MAX_PERMUTATIONS + 1)
        );
    }

    #[test]
    fn bound_keccak_proves_and_verifies_single_and_batch() {
        let inputs = [sample(11), sample(22), sample(33)];
        let (proof, outputs) = prove_bound_keccak_f(&inputs).expect("bound prove");
        for (input, output) in inputs.iter().zip(outputs.iter()) {
            assert_eq!(*output, reference(*input));
        }
        verify_bound_keccak_f(&inputs, &outputs, &proof).expect("bound verify");
    }

    #[test]
    fn bound_keccak_rejects_wrong_input_output_or_replay() {
        let inputs = [sample(7), sample(8)];
        let (proof, outputs) = prove_bound_keccak_f(&inputs).expect("bound prove");

        // Tampered input must fail.
        let mut bad_inputs = inputs;
        bad_inputs[1][24] ^= 1;
        assert!(verify_bound_keccak_f(&bad_inputs, &outputs, &proof).is_err());

        // Tampered output must fail (even a single bit in lane 0 or lane 24).
        let mut bad_outputs = outputs.clone();
        bad_outputs[0][0] ^= 1 << 32;
        assert!(verify_bound_keccak_f(&inputs, &bad_outputs, &proof).is_err());

        // Swapped order replay must fail.
        let swapped_inputs = [inputs[1], inputs[0]];
        let swapped_outputs = vec![outputs[1], outputs[0]];
        assert!(verify_bound_keccak_f(&swapped_inputs, &swapped_outputs, &proof).is_err());

        // Shape mismatch must fail.
        assert_eq!(
            verify_bound_keccak_f(&inputs[..1], &outputs[..1], &proof),
            Err(KeccakChipError::ShapeMismatch)
        );
    }
}
