//! The Keccak-f[1600] chip.
//!
//! A thin wrapper over `p3-keccak-air =0.7.0`: 24 trace rows per permutation, 16 bit
//! limbs, over Goldilocks. The AIR is generic in the field and Plonky3 ships a Goldilocks
//! example; the "field between 2^16 and 2^32" note of the crate is about the limb sums
//! staying below the modulus, which a 64 bit field satisfies with room to spare.
//!
//! The chip proves that the final-round row of each block equals Keccak-f applied to the
//! preimage of its first row. Binding those two to the rest of a statement (the XOF of
//! ExpandA, the message hash `mu`) is the job of the AIR that embeds the chip (,
//!); `input_state` and `output_state` read them back from a trace for that.

use bud_proof::plonky3_prover::{prove_chip, verify_chip, ChipProof};
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use p3_keccak_air::{generate_trace_rows, KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS, U64_LIMBS};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

/// Trace rows used by one permutation.
/// exposed for: the proof/VM crate's test-and-tooling surface — production readers land with the prover wiring wave.
pub const ROWS_PER_PERMUTATION: usize = NUM_ROUNDS;

/// Trace columns of the chip.
/// exposed for: the proof/VM crate's test-and-tooling surface — production readers land with the prover wiring wave.
pub const COLUMNS: usize = NUM_KECCAK_COLS;

/// The most permutations one chip trace accepts. A proof over more rows is split by the
/// caller; the bound keeps a hostile input from sizing the trace.
/// exposed for: the proof/VM crate's test-and-tooling surface — production readers land with the prover wiring wave.
pub const MAX_PERMUTATIONS: usize = 1 << 14;

/// Why a chip operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeccakChipError {
    /// No permutation was given.
    Empty,
    /// More than [`MAX_PERMUTATIONS`] permutations were given.
    TooMany(usize),
    /// The proof did not verify.
    Rejected(String),
}

/// Builds the trace of the given permutation inputs (state words in the standard
/// `x + 5 * y` order).
/// exposed for: the proof/VM crate's test-and-tooling surface — production readers land with the prover wiring wave.
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
/// exposed for: the proof/VM crate's test-and-tooling surface — production readers land with the prover wiring wave.
pub fn input_state(trace: &RowMajorMatrix<Goldilocks>, index: usize) -> [u64; 25] {
    let row = index * ROWS_PER_PERMUTATION;
    read_state(trace, row, cols::preimage)
}

/// The output state of permutation `index`, read back from a chip trace.
/// exposed for: the proof/VM crate's test-and-tooling surface — production readers land with the prover wiring wave.
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
}
