//! Keccak-256 Merkle path verification STARK chip (depths `1..=24`).
//!
//! Verifies in a single atomic STARK trace that a 32-byte `leaf` at `index`
//! hashes up through `depth` sibling digests (`1 <= depth <= 24`) to `root`
//! under BudZero's native binary Merkle compressor
//! (`CompressionFunctionFromHasher<Keccak256Hash, 2, 32>`):
//!
//! * Embeds `p3_keccak_air::KeccakAir` on columns `0..NUM_KECCAK_COLS` via
//!   [`crate::bud_stark::SubAirBuilder`], executing one 24-row `Keccak-f[1600]`
//!   permutation per Merkle level;
//! * Constrains each level's `index_bit` to `{0, 1}`, reconstructs the full
//!   leaf `index = sum_{i=0}^{depth-1} bit_i * 2^i` in-circuit, and routes
//!   `(current, sibling)` into `(left, right)` algebraically without host trust;
//! * Pins the 64-byte `Keccak-256` `pad10*1` suffix (`lane 8 = 1`,
//!   `lane 16 = 0x8000_0000_0000_0000`) and zeroes the 512-bit sponge capacity
//!   (`lanes 17..25 = 0`) in the AIR constraints;
//! * Chains each level's 32-byte `Keccak-f` output lanes `0..4` into the next
//!   level's `current` digest;
//! * Keeps the preprocessed verification key dependent **only** on `depth`
//!   (`leaf`, `root`, `index`, and `depth` are bound through public values,
//!   while `siblings` live in the main witness trace).
//!
//! WIRING: unwired - Foundation Merkle-opening verification STARK chip documented in
//! `docs/pq/RECURSION_PLAN.md` (`R-3`), matching `ChipStarkConfig`'s
//! `MerkleTreeMmcs` binary compression for recursive FRI query verification.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_keccak::KeccakF;
use p3_keccak_air::{generate_trace_rows, KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS, U64_LIMBS};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_symmetric::Permutation;

use crate::bud_stark::SubAirBuilder;
use crate::plonky3_prover::{
    prove_chip_with_preprocessed, verify_chip_with_preprocessed, ChipProof,
};

/// Minimum supported Merkle path depth.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const MIN_MERKLE_DEPTH: usize = 1;
/// Maximum supported Merkle path depth.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const MAX_MERKLE_DEPTH: usize = 24;

/// Number of 16-bit limbs in a 32-byte Keccak-256 digest (`4` `u64` lanes * `4` limbs).
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const DIGEST_U16_LIMBS: usize = 16;

/// First main-trace column holding the current level's 16-bit digest limbs (`16` columns).
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_CUR_LIMBS_BASE: usize = NUM_KECCAK_COLS;
/// First main-trace column holding the sibling's 16-bit digest limbs (`16` columns).
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_SIB_LIMBS_BASE: usize = COL_CUR_LIMBS_BASE + DIGEST_U16_LIMBS;
/// Main-trace column holding the boolean path direction bit `(index >> level) & 1`.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_INDEX_BIT: usize = COL_SIB_LIMBS_BASE + DIGEST_U16_LIMBS;
/// Main-trace column accumulating `sum_{j=0}^{level} bit_j * 2^j`.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_INDEX_ACC: usize = COL_INDEX_BIT + 1;
/// Total main-trace width of [`MerklePathAir`].
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const MERKLE_PATH_MAIN_WIDTH: usize = COL_INDEX_ACC + 1;

/// Public value count: `8` `u32` words for `leaf` + `8` `u32` words for `root` + `index` + `depth`.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const MERKLE_PUBLIC_VALUES: usize = 18;

const MERKLE_PREP_WIDTH: usize = 6;
const PREP_IS_ACTIVE: usize = 0;
const PREP_IS_LEVEL_START: usize = 1;
const PREP_IS_FIRST_LEVEL_START: usize = 2;
const PREP_IS_LAST_LEVEL_FINAL: usize = 3;
const PREP_HAS_NEXT_LEVEL_FINAL: usize = 4;
const PREP_CHAIN_NEXT_POW2: usize = 5;

const COL_STEP_FLAG_FIRST: usize = 0;
const COL_STEP_FLAG_FINAL: usize = NUM_ROUNDS - 1;
const KECCAK_PAD_FIRST_MARK_LANE: usize = 8;
const KECCAK_PAD_CLOSING_MARK_LANE: usize = 16;
const KECCAK_CLOSING_TOP_U16: u64 = 0x8000;

mod keccak_cols {
    use super::*;

    const PREIMAGE: usize = NUM_ROUNDS + 1;
    const A_PRIME_PRIME: usize =
        PREIMAGE + 25 * U64_LIMBS + 25 * U64_LIMBS + 5 * 64 + 5 * 64 + 5 * 5 * 64;
    const A_PRIME_PRIME_PRIME_0_0: usize = A_PRIME_PRIME + 25 * U64_LIMBS + 64;

    const _: () = assert!(
        NUM_KECCAK_COLS == A_PRIME_PRIME_PRIME_0_0 + U64_LIMBS,
        "p3-keccak-air KeccakCols layout changed"
    );

    pub const fn preimage(lane: usize, limb: usize) -> usize {
        let y = lane / 5;
        let x = lane % 5;
        PREIMAGE + (y * 5 + x) * U64_LIMBS + limb
    }

    pub const fn output(lane: usize, limb: usize) -> usize {
        let y = lane / 5;
        let x = lane % 5;
        if y == 0 && x == 0 {
            A_PRIME_PRIME_PRIME_0_0 + limb
        } else {
            A_PRIME_PRIME + (y * 5 + x) * U64_LIMBS + limb
        }
    }
}

/// Witness inputs for proving a binary Keccak-256 Merkle authentication path.
#[derive(Debug, Clone, PartialEq, Eq)]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub struct MerklePathWitness {
    /// 32-byte leaf digest at the bottom of the path.
    pub leaf: [u8; 32],
    /// 0-based leaf index (`0 <= index < 2^depth`).
    pub index: u64,
    /// Bottom-to-top sibling digests (`1 <= siblings.len() <= 24`).
    pub siblings: Vec<[u8; 32]>,
}

/// Refusal reasons returned by the Merkle path verification chip.
#[derive(Debug, Clone, PartialEq, Eq)]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub enum MerklePathChipError {
    /// Depth is outside `MIN_MERKLE_DEPTH..=MAX_MERKLE_DEPTH`.
    InvalidDepth(usize),
    /// Leaf `index` exceeds `(1 << depth) - 1`.
    IndexOutOfBounds { index: u64, depth: usize },
    /// Trace or public-value dimensions do not match `depth`.
    ShapeMismatch,
    /// Constraint evaluation or STARK verification refused the proof.
    Rejected(String),
}

fn validate_depth_and_index(depth: usize, index: u64) -> Result<(), MerklePathChipError> {
    if !(MIN_MERKLE_DEPTH..=MAX_MERKLE_DEPTH).contains(&depth) {
        return Err(MerklePathChipError::InvalidDepth(depth));
    }
    let bound = 1u64 << depth;
    if index >= bound {
        return Err(MerklePathChipError::IndexOutOfBounds { index, depth });
    }
    Ok(())
}

fn digest_to_u64_lanes(digest: &[u8; 32]) -> [u64; 4] {
    core::array::from_fn(|i| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&digest[8 * i..8 * (i + 1)]);
        u64::from_le_bytes(buf)
    })
}

fn u64_lanes_to_digest(lanes: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, lane) in lanes.iter().enumerate() {
        out[8 * i..8 * (i + 1)].copy_from_slice(&lane.to_le_bytes());
    }
    out
}

fn digest_to_u16_limbs(digest: &[u8; 32]) -> [u64; DIGEST_U16_LIMBS] {
    let lanes = digest_to_u64_lanes(digest);
    core::array::from_fn(|k| {
        let lane = lanes[k / 4];
        let shift = (k % 4) * 16;
        (lane >> shift) & 0xFFFF
    })
}

fn digest_to_u32_words(digest: &[u8; 32]) -> [u64; 8] {
    core::array::from_fn(|i| {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&digest[4 * i..4 * (i + 1)]);
        u64::from(u32::from_le_bytes(buf))
    })
}

fn build_compression_state(left: &[u8; 32], right: &[u8; 32]) -> [u64; 25] {
    let mut state = [0u64; 25];
    let left_lanes = digest_to_u64_lanes(left);
    let right_lanes = digest_to_u64_lanes(right);
    state[..4].copy_from_slice(&left_lanes);
    state[4..8].copy_from_slice(&right_lanes);
    state[KECCAK_PAD_FIRST_MARK_LANE] = 1;
    state[KECCAK_PAD_CLOSING_MARK_LANE] = KECCAK_CLOSING_TOP_U16 << 48;
    state
}

/// Compresses two 32-byte digests with a single `Keccak-256` (`Keccak-f[1600]`)
/// permutation, matching `CompressionFunctionFromHasher<Keccak256Hash, 2, 32>`.
#[must_use]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn compress_keccak_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut state = build_compression_state(left, right);
    KeccakF.permute_mut(&mut state);
    u64_lanes_to_digest(&[state[0], state[1], state[2], state[3]])
}

/// Computes the expected Merkle root of `leaf` at `index` over `siblings`.
///
/// # Errors
///
/// Refuses depths outside `1..=24` or `index >= (1 << depth)`.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn compute_merkle_root(
    leaf: [u8; 32],
    index: u64,
    siblings: &[[u8; 32]],
) -> Result<[u8; 32], MerklePathChipError> {
    let depth = siblings.len();
    validate_depth_and_index(depth, index)?;
    let mut cur = leaf;
    for (lvl, sib) in siblings.iter().enumerate() {
        let bit = (index >> lvl) & 1;
        cur = if bit == 0 {
            compress_keccak_pair(&cur, sib)
        } else {
            compress_keccak_pair(sib, &cur)
        };
    }
    Ok(cur)
}

/// Fixed-VK Keccak-256 Merkle path verification AIR parameterized only by `depth` (`1..=24`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub struct MerklePathAir {
    depth: usize,
}

impl MerklePathAir {
    /// Creates the Merkle path AIR for `depth` (`1..=24`).
    ///
    /// # Errors
    ///
    /// Returns [`MerklePathChipError::InvalidDepth`] if `depth` is outside `1..=24`.
    /// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
    pub fn new(depth: usize) -> Result<Self, MerklePathChipError> {
        if !(MIN_MERKLE_DEPTH..=MAX_MERKLE_DEPTH).contains(&depth) {
            return Err(MerklePathChipError::InvalidDepth(depth));
        }
        Ok(Self { depth })
    }

    const fn padded_rows(&self) -> usize {
        (self.depth * NUM_ROUNDS).next_power_of_two()
    }
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for MerklePathAir {
    fn width(&self) -> usize {
        MERKLE_PATH_MAIN_WIDTH
    }

    fn num_public_values(&self) -> usize {
        MERKLE_PUBLIC_VALUES
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        if !(MIN_MERKLE_DEPTH..=MAX_MERKLE_DEPTH).contains(&self.depth) {
            return None;
        }
        let rows = self.padded_rows();
        let mut values = vec![F::ZERO; rows * MERKLE_PREP_WIDTH];
        for lvl in 0..self.depth {
            let start_row = lvl * NUM_ROUNDS;
            let final_row = start_row + (NUM_ROUNDS - 1);
            for r in start_row..=final_row {
                values[r * MERKLE_PREP_WIDTH + PREP_IS_ACTIVE] = F::ONE;
            }
            values[start_row * MERKLE_PREP_WIDTH + PREP_IS_LEVEL_START] = F::ONE;
            if lvl == 0 {
                values[start_row * MERKLE_PREP_WIDTH + PREP_IS_FIRST_LEVEL_START] = F::ONE;
            }
            if lvl + 1 == self.depth {
                values[final_row * MERKLE_PREP_WIDTH + PREP_IS_LAST_LEVEL_FINAL] = F::ONE;
            } else {
                values[final_row * MERKLE_PREP_WIDTH + PREP_HAS_NEXT_LEVEL_FINAL] = F::ONE;
                values[final_row * MERKLE_PREP_WIDTH + PREP_CHAIN_NEXT_POW2] =
                    F::from_u64(1u64 << (lvl + 1));
            }
        }
        Some(RowMajorMatrix::new(values, MERKLE_PREP_WIDTH))
    }
}

impl<AB: AirBuilder> Air<AB> for MerklePathAir
where
    AB::F: Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        {
            let mut sub = SubAirBuilder::<AB, KeccakAir, AB::F>::new(builder, 0..NUM_KECCAK_COLS);
            KeccakAir {}.eval(&mut sub);
        }

        let shift_16 = AB::Expr::from_u64(1u64 << 16);
        let (
            step_first,
            step_final,
            cur_limbs,
            sib_limbs,
            index_bit,
            index_acc,
            next_cur_limbs,
            next_sib_limbs,
            next_index_bit,
            next_index_acc,
            preimage_lanes,
            out_digest_limbs,
            prep_active,
            prep_level_start,
            prep_first_start,
            prep_last_final,
            prep_has_next_final,
            prep_chain_next_pow2,
            pvs,
        ) = {
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            let prep = builder.preprocessed();
            let prep_cur = prep.current_slice();
            let pv_slice = builder.public_values();
            if pv_slice.len() < MERKLE_PUBLIC_VALUES || prep_cur.len() < MERKLE_PREP_WIDTH {
                return;
            }

            let step_first: AB::Expr = local[COL_STEP_FLAG_FIRST].into();
            let step_final: AB::Expr = local[COL_STEP_FLAG_FINAL].into();
            let cur_limbs: [AB::Expr; DIGEST_U16_LIMBS] =
                core::array::from_fn(|i| local[COL_CUR_LIMBS_BASE + i].into());
            let sib_limbs: [AB::Expr; DIGEST_U16_LIMBS] =
                core::array::from_fn(|i| local[COL_SIB_LIMBS_BASE + i].into());
            let index_bit: AB::Expr = local[COL_INDEX_BIT].into();
            let index_acc: AB::Expr = local[COL_INDEX_ACC].into();

            let next_cur_limbs: [AB::Expr; DIGEST_U16_LIMBS] =
                core::array::from_fn(|i| next[COL_CUR_LIMBS_BASE + i].into());
            let next_sib_limbs: [AB::Expr; DIGEST_U16_LIMBS] =
                core::array::from_fn(|i| next[COL_SIB_LIMBS_BASE + i].into());
            let next_index_bit: AB::Expr = next[COL_INDEX_BIT].into();
            let next_index_acc: AB::Expr = next[COL_INDEX_ACC].into();

            let preimage_lanes: [[AB::Expr; U64_LIMBS]; 25] = core::array::from_fn(|lane| {
                core::array::from_fn(|limb| local[keccak_cols::preimage(lane, limb)].into())
            });
            let out_digest_limbs: [AB::Expr; DIGEST_U16_LIMBS] = core::array::from_fn(|k| {
                let lane = k / 4;
                let limb = k % 4;
                local[keccak_cols::output(lane, limb)].into()
            });

            let prep_active: AB::Expr = prep_cur[PREP_IS_ACTIVE].into();
            let prep_level_start: AB::Expr = prep_cur[PREP_IS_LEVEL_START].into();
            let prep_first_start: AB::Expr = prep_cur[PREP_IS_FIRST_LEVEL_START].into();
            let prep_last_final: AB::Expr = prep_cur[PREP_IS_LAST_LEVEL_FINAL].into();
            let prep_has_next_final: AB::Expr = prep_cur[PREP_HAS_NEXT_LEVEL_FINAL].into();
            let prep_chain_next_pow2: AB::Expr = prep_cur[PREP_CHAIN_NEXT_POW2].into();

            let pvs: [AB::Expr; MERKLE_PUBLIC_VALUES] =
                core::array::from_fn(|i| pv_slice[i].into());

            (
                step_first,
                step_final,
                cur_limbs,
                sib_limbs,
                index_bit,
                index_acc,
                next_cur_limbs,
                next_sib_limbs,
                next_index_bit,
                next_index_acc,
                preimage_lanes,
                out_digest_limbs,
                prep_active,
                prep_level_start,
                prep_first_start,
                prep_last_final,
                prep_has_next_final,
                prep_chain_next_pow2,
                pvs,
            )
        };

        // 1. Path direction bit is boolean on every row.
        builder.assert_bool(index_bit.clone());

        // 2. Inactive tail rows carry zeroes in all Merkle auxiliary columns.
        let inactive = AB::Expr::ONE - prep_active.clone();
        for k in 0..DIGEST_U16_LIMBS {
            builder
                .when(inactive.clone())
                .assert_zero(cur_limbs[k].clone());
            builder
                .when(inactive.clone())
                .assert_zero(sib_limbs[k].clone());
        }
        builder
            .when(inactive.clone())
            .assert_zero(index_bit.clone());
        builder.when(inactive).assert_zero(index_acc.clone());

        // 3. Within each 24-row permutation block, Merkle auxiliary columns stay constant.
        let intra_level =
            builder.is_transition() * prep_active * (AB::Expr::ONE - step_final.clone());
        for k in 0..DIGEST_U16_LIMBS {
            builder
                .when(intra_level.clone())
                .assert_eq(cur_limbs[k].clone(), next_cur_limbs[k].clone());
            builder
                .when(intra_level.clone())
                .assert_eq(sib_limbs[k].clone(), next_sib_limbs[k].clone());
        }
        builder
            .when(intra_level.clone())
            .assert_eq(index_bit.clone(), next_index_bit.clone());
        builder
            .when(intra_level)
            .assert_eq(index_acc.clone(), next_index_acc.clone());

        // 4. At the start of every active level, align with Keccak round 0, select
        //    (left, right) by index_bit, and enforce 64-byte Keccak-256 pad10*1 + zero capacity.
        builder
            .when(prep_level_start.clone())
            .assert_one(step_first);
        let one_minus_bit = AB::Expr::ONE - index_bit.clone();
        for k in 0..DIGEST_U16_LIMBS {
            let lane_left = k / 4;
            let lane_right = 4 + (k / 4);
            let limb = k % 4;
            let left_val = one_minus_bit.clone() * cur_limbs[k].clone()
                + index_bit.clone() * sib_limbs[k].clone();
            let right_val = index_bit.clone() * cur_limbs[k].clone()
                + one_minus_bit.clone() * sib_limbs[k].clone();
            builder
                .when(prep_level_start.clone())
                .assert_eq(preimage_lanes[lane_left][limb].clone(), left_val);
            builder
                .when(prep_level_start.clone())
                .assert_eq(preimage_lanes[lane_right][limb].clone(), right_val);
        }

        // Lane 8 = 0x0000_0000_0000_0001
        builder
            .when(prep_level_start.clone())
            .assert_one(preimage_lanes[KECCAK_PAD_FIRST_MARK_LANE][0].clone());
        for limb_expr in &preimage_lanes[KECCAK_PAD_FIRST_MARK_LANE][1..U64_LIMBS] {
            builder
                .when(prep_level_start.clone())
                .assert_zero(limb_expr.clone());
        }
        // Lanes 9..16 = 0
        for lane in &preimage_lanes[9..KECCAK_PAD_CLOSING_MARK_LANE] {
            for limb_expr in lane {
                builder
                    .when(prep_level_start.clone())
                    .assert_zero(limb_expr.clone());
            }
        }
        // Lane 16 = 0x8000_0000_0000_0000
        for limb_expr in &preimage_lanes[KECCAK_PAD_CLOSING_MARK_LANE][..3] {
            builder
                .when(prep_level_start.clone())
                .assert_zero(limb_expr.clone());
        }
        builder.when(prep_level_start.clone()).assert_eq(
            preimage_lanes[KECCAK_PAD_CLOSING_MARK_LANE][3].clone(),
            AB::Expr::from_u64(KECCAK_CLOSING_TOP_U16),
        );
        // Capacity lanes 17..25 = 0
        for lane in &preimage_lanes[17..25] {
            for limb_expr in lane {
                builder
                    .when(prep_level_start.clone())
                    .assert_zero(limb_expr.clone());
            }
        }

        // 5. Level-to-level chaining across round 23 -> next level round 0.
        builder
            .when(prep_has_next_final.clone())
            .assert_one(step_final.clone());
        for k in 0..DIGEST_U16_LIMBS {
            builder
                .when(prep_has_next_final.clone())
                .assert_eq(next_cur_limbs[k].clone(), out_digest_limbs[k].clone());
        }
        builder.assert_eq(
            prep_has_next_final * (next_index_acc - index_acc.clone()),
            prep_chain_next_pow2 * next_index_bit,
        );

        // 6. First-level boundary: leaf digest, initial index bit, and depth public value.
        builder
            .when(prep_first_start.clone())
            .assert_eq(index_acc.clone(), index_bit);
        builder
            .when(prep_first_start.clone())
            .assert_eq(pvs[17].clone(), AB::Expr::from_u64(self.depth as u64));
        for lane in 0..4 {
            let cur_lo =
                cur_limbs[4 * lane].clone() + shift_16.clone() * cur_limbs[4 * lane + 1].clone();
            let cur_hi = cur_limbs[4 * lane + 2].clone()
                + shift_16.clone() * cur_limbs[4 * lane + 3].clone();
            builder
                .when(prep_first_start.clone())
                .assert_eq(cur_lo, pvs[2 * lane].clone());
            builder
                .when(prep_first_start.clone())
                .assert_eq(cur_hi, pvs[2 * lane + 1].clone());
        }

        // 7. Final-level boundary: root digest and reconstructed leaf index.
        builder.when(prep_last_final.clone()).assert_one(step_final);
        builder
            .when(prep_last_final.clone())
            .assert_eq(index_acc, pvs[16].clone());
        for lane in 0..4 {
            let out_lo = out_digest_limbs[4 * lane].clone()
                + shift_16.clone() * out_digest_limbs[4 * lane + 1].clone();
            let out_hi = out_digest_limbs[4 * lane + 2].clone()
                + shift_16.clone() * out_digest_limbs[4 * lane + 3].clone();
            builder
                .when(prep_last_final.clone())
                .assert_eq(out_lo, pvs[8 + 2 * lane].clone());
            builder
                .when(prep_last_final.clone())
                .assert_eq(out_hi, pvs[8 + 2 * lane + 1].clone());
        }
    }
}

/// Public-value vector encoding `(leaf, root, index, depth)` as 18 canonical Goldilocks elements.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn merkle_public_values(
    leaf: [u8; 32],
    root: [u8; 32],
    index: u64,
    depth: usize,
) -> [Goldilocks; MERKLE_PUBLIC_VALUES] {
    let leaf_words = digest_to_u32_words(&leaf);
    let root_words = digest_to_u32_words(&root);
    let mut pvs = [Goldilocks::ZERO; MERKLE_PUBLIC_VALUES];
    for i in 0..8 {
        pvs[i] = Goldilocks::new(leaf_words[i]);
        pvs[8 + i] = Goldilocks::new(root_words[i]);
    }
    pvs[16] = Goldilocks::new(index);
    pvs[17] = Goldilocks::new(depth as u64);
    pvs
}

/// Output tuple of [`build_merkle_path_trace`]: `(main_trace, public_values, root)`.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub type MerkleTraceBuild = (
    RowMajorMatrix<Goldilocks>,
    [Goldilocks; MERKLE_PUBLIC_VALUES],
    [u8; 32],
);

/// Builds the full main witness trace, public values, and root for `witness`.
///
/// # Errors
///
/// Refuses depths outside `1..=24` or `index >= (1 << depth)`.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn build_merkle_path_trace(
    witness: &MerklePathWitness,
) -> Result<MerkleTraceBuild, MerklePathChipError> {
    let depth = witness.siblings.len();
    validate_depth_and_index(depth, witness.index)?;

    let mut perm_inputs = Vec::with_capacity(depth);
    let mut level_cur_limbs = Vec::with_capacity(depth);
    let mut level_sib_limbs = Vec::with_capacity(depth);
    let mut level_bits = Vec::with_capacity(depth);
    let mut level_accs = Vec::with_capacity(depth);

    let mut cur = witness.leaf;
    let mut acc = 0u64;
    for (lvl, sib) in witness.siblings.iter().enumerate() {
        let bit = (witness.index >> lvl) & 1;
        acc |= bit << lvl;
        level_cur_limbs.push(digest_to_u16_limbs(&cur));
        level_sib_limbs.push(digest_to_u16_limbs(sib));
        level_bits.push(bit);
        level_accs.push(acc);

        let (left, right) = if bit == 0 { (&cur, sib) } else { (sib, &cur) };
        let state = build_compression_state(left, right);
        perm_inputs.push(state);
        cur = compress_keccak_pair(left, right);
    }

    let keccak_trace = generate_trace_rows::<Goldilocks>(perm_inputs, 0);
    let rows = keccak_trace.height();
    let mut values = vec![Goldilocks::ZERO; rows * MERKLE_PATH_MAIN_WIDTH];

    for r in 0..rows {
        let src_start = r * NUM_KECCAK_COLS;
        let dst_start = r * MERKLE_PATH_MAIN_WIDTH;
        values[dst_start..dst_start + NUM_KECCAK_COLS]
            .copy_from_slice(&keccak_trace.values[src_start..src_start + NUM_KECCAK_COLS]);

        let lvl = r / NUM_ROUNDS;
        if lvl < depth {
            for k in 0..DIGEST_U16_LIMBS {
                values[dst_start + COL_CUR_LIMBS_BASE + k] =
                    Goldilocks::new(level_cur_limbs[lvl][k]);
                values[dst_start + COL_SIB_LIMBS_BASE + k] =
                    Goldilocks::new(level_sib_limbs[lvl][k]);
            }
            values[dst_start + COL_INDEX_BIT] = Goldilocks::new(level_bits[lvl]);
            values[dst_start + COL_INDEX_ACC] = Goldilocks::new(level_accs[lvl]);
        }
    }

    let pvs = merkle_public_values(witness.leaf, cur, witness.index, depth);
    Ok((
        RowMajorMatrix::new(values, MERKLE_PATH_MAIN_WIDTH),
        pvs,
        cur,
    ))
}

/// Evaluates all [`MerklePathAir`] constraints row-by-row (including preprocessed
/// schedule and embedded `KeccakAir`), returning `Err(MerklePathChipError::Rejected)`
/// on any constraint failure.
///
/// # Errors
///
/// Refuses invalid depths, mismatched shapes, or violated AIR constraints.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn check_merkle_path_constraints(
    depth: usize,
    trace: &RowMajorMatrix<Goldilocks>,
    public_values: &[Goldilocks],
) -> Result<(), MerklePathChipError> {
    let air = MerklePathAir::new(depth)?;
    if trace.width() != MERKLE_PATH_MAIN_WIDTH
        || trace.height() != air.padded_rows()
        || public_values.len() != MERKLE_PUBLIC_VALUES
    {
        return Err(MerklePathChipError::ShapeMismatch);
    }
    if public_values
        .iter()
        .any(|v| v.as_canonical_u64() >= Goldilocks::ORDER_U64)
    {
        return Err(MerklePathChipError::ShapeMismatch);
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        p3_air::check_constraints(&air, trace, public_values);
    }))
    .map_err(|_| MerklePathChipError::Rejected("MerklePathAir constraint violation".into()))
}

/// Proves `witness` in a single atomic BudZero STARK proof under [`MerklePathAir`].
///
/// Returns `(proof, computed_root)`.
///
/// # Errors
///
/// Refuses invalid depths, out-of-bounds leaf indices, or proving failures.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn prove_merkle_path(
    witness: &MerklePathWitness,
) -> Result<(ChipProof, [u8; 32]), MerklePathChipError> {
    let depth = witness.siblings.len();
    let air = MerklePathAir::new(depth)?;
    let (trace, pvs, root) = build_merkle_path_trace(witness)?;
    let proof =
        prove_chip_with_preprocessed(&air, trace, &pvs).map_err(MerklePathChipError::Rejected)?;
    Ok((proof, root))
}

/// Verifies a Merkle path STARK proof against `(leaf, index, depth, claimed_root)`
/// using the depth-only verification key of [`MerklePathAir`].
///
/// # Errors
///
/// Refuses invalid depths, out-of-bounds indices, degree mismatches, or invalid proofs.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn verify_merkle_path(
    leaf: [u8; 32],
    index: u64,
    depth: usize,
    claimed_root: [u8; 32],
    proof: &ChipProof,
) -> Result<(), MerklePathChipError> {
    validate_depth_and_index(depth, index)?;
    let air = MerklePathAir::new(depth)?;
    let expected_degree_bits = air.padded_rows().trailing_zeros() as usize;
    if proof.degree_bits != expected_degree_bits {
        return Err(MerklePathChipError::ShapeMismatch);
    }
    let pvs = merkle_public_values(leaf, claimed_root, index, depth);
    verify_chip_with_preprocessed(&air, proof, expected_degree_bits, &pvs)
        .map_err(MerklePathChipError::Rejected)
}
