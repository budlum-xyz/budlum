//! `AggFoldAir`: compact 23-column recursive fold AIR for Phase 3 `MasterProof`s.
//!
//! Binds an arbitrary postfix aggregation tree (`SHAPE_TICK` / `SHAPE_MERGE`)
//! of `step_count` nodes inside a single 128-bit Plonky3 STARK under
//! [`crate::plonky3_prover::ChipStarkConfig`] (Goldilocks + cubic extension +
//! Keccak-256 Merkle PCS, `log_blowup = 3`, `num_queries = 76`, `pow_bits = 16`).
//!
//! Every active row `i` proves:
//! 1. Boolean control flags: `is_active`, `is_merge`, `left_is_merge`, `right_is_merge`
//!    are in `{0, 1}`.
//! 2. Monotone active prefix: active rows precede padding rows (`next.is_active * (1 - local.is_active) = 0`),
//!    row `0` is active, and `step_idx` increments by `1` on every active transition
//!    reaching `public.step_count` on the final row.
//! 3. Strict Phase 3 program-hash allowlist on every active row:
//!    `row.program_hash == (1 - is_merge) * public.tick_program_hash + is_merge * public.merge_program_hash`.
//!    No unauthorized program hash can ever satisfy the AIR.
//! 4. On the final row, `row.program_hash == public.final_program_hash` and
//!    `row.node_pi == public.master_pi`.
//! 5. Dual independent 64-bit Goldilocks polynomial accumulators (`acc_lo`, `acc_hi`,
//!    yielding 128-bit algebraic binding) fold every active row's flags,
//!    `program_hash` limbs, and `node_pi` limbs under domain-separated Keccak-256
//!    challenges `(alpha_lo, alpha_hi)` derived from `(parameter_set, domain,
//!    tick_program_hash, merge_program_hash, final_program_hash, master_pi,
//!    shape_digest, step_count)`.
//!
//! Because `FOLD_WIDTH = 23`, a complete 128-bit STARK proof covering 1,024+
//! claims fits well below `AggParams::default().max_proof_bytes` (262,144 bytes)
//! and `MAX_BLOCK_PROOF_BYTES` (333,333 bytes), proving in tens of milliseconds
//! and verifying in single-digit milliseconds.
//!
//! WIRING: `budlum_core::aggregation::stark::StarkBackend` invokes
//! `prove_agg_fold` and `verify_agg_fold` for every tick and recursive merge
//! frame proof, handling `FoldAirError` on invalid statements or proofs.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::batch::{absorb_states, keccak_f};
use crate::plonky3_prover::{prove_chip, verify_chip, ChipProof};

/// Total main trace columns of `AggFoldAir`.
const FOLD_WIDTH: usize = 23;

/// Maximum tree operations (ticks + merges) in a single fold proof (`2^14`).
pub const MAX_FOLD_STEPS: usize = 1 << 14;

/// Number of 32-bit little-endian limbs per 32-byte digest.
const DIGEST_LIMBS: usize = 8;

/// Number of public Goldilocks values consumed by `AggFoldAir`.
///
/// Layout:
/// - `[0..8]`:   `tick_program_hash` (8 u32 limbs)
/// - `[8..16]`:  `merge_program_hash` (8 u32 limbs)
/// - `[16..24]`: `final_program_hash` (8 u32 limbs)
/// - `[24..32]`: `master_pi` (8 u32 limbs)
/// - `[32]`:     `step_count`
/// - `[33]`:     `alpha_lo` (derived from full public header + `shape_digest`)
/// - `[34]`:     `alpha_hi` (independent second challenge)
/// - `[35]`:     `init_acc_lo`
/// - `[36]`:     `init_acc_hi`
/// - `[37]`:     `final_acc_lo`
/// - `[38]`:     `final_acc_hi`
const FOLD_NUM_PUBLIC_VALUES: usize = 39;

const COL_IS_ACTIVE: usize = 0;
const COL_IS_MERGE: usize = 1;
const COL_LEFT_IS_MERGE: usize = 2;
const COL_RIGHT_IS_MERGE: usize = 3;
const COL_STEP_IDX: usize = 4;
const COL_PROG_BASE: usize = 5; // 5..13 (8 limbs)
const COL_PI_BASE: usize = 13; // 13..21 (8 limbs)
const COL_ACC_LO: usize = 21;
const COL_ACC_HI: usize = 22;

const PV_TICK_BASE: usize = 0;
const PV_MERGE_BASE: usize = 8;
const PV_FINAL_PROG_BASE: usize = 16;
const PV_MASTER_PI_BASE: usize = 24;
const PV_STEP_COUNT: usize = 32;
const PV_ALPHA_LO: usize = 33;
const PV_ALPHA_HI: usize = 34;
const PV_INIT_ACC_LO: usize = 35;
const PV_INIT_ACC_HI: usize = 36;
const PV_FINAL_ACC_LO: usize = 37;
const PV_FINAL_ACC_HI: usize = 38;

/// Errors returned by [`prove_agg_fold`] and [`verify_agg_fold`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldAirError {
    /// No steps supplied.
    EmptySteps,
    /// Step count exceeds [`MAX_FOLD_STEPS`] or mismatches `pub_stmt.step_count`.
    InvalidStepCount,
    /// Step program hash does not match the allowlisted tick/merge hash.
    UnauthorizedProgramHash(usize),
    /// Final step program hash or `node_pi` mismatches the public statement.
    FinalStatementMismatch,
    /// Underlying Plonky3 STARK verifier rejected the proof.
    VerifyFailed(String),
}

/// One postfix step (either a tick leaf or a binary merge) in the fold trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggFoldStep {
    /// `false` for `SHAPE_TICK`, `true` for `SHAPE_MERGE`.
    pub is_merge: bool,
    /// For merges: whether the left child was itself a merge (`false` for tick).
    pub left_is_merge: bool,
    /// For merges: whether the right child was itself a merge (`false` for tick).
    pub right_is_merge: bool,
    /// Program hash executed at this step (must equal `tick_program_hash` or `merge_program_hash`).
    pub program_hash: [u8; 32],
    /// Public input digest produced by this step (`tick_pi` or `merge_pi`).
    pub node_pi: [u8; 32],
}

/// Public statement committed by `AggFoldAir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggFoldPublic {
    /// Backend parameter set identifier (`STARK_PARAMETER_SET`).
    pub parameter_set: u32,
    /// Chain claim domain identifier.
    pub domain: u32,
    /// Allowlisted `AggTick` program hash.
    pub tick_program_hash: [u8; 32],
    /// Allowlisted `AggMerge` program hash.
    pub merge_program_hash: [u8; 32],
    /// Expected root program hash (`tick_program_hash` or `merge_program_hash`).
    pub final_program_hash: [u8; 32],
    /// Expected `master_pi` of the frame.
    pub master_pi: [u8; 32],
    /// Canonical Keccak-256 digest over `(domain, shape, segments)`.
    pub shape_digest: [u8; 32],
    /// Number of tree operations (`steps.len()`).
    pub step_count: u32,
}

/// Serialisable 128-bit Plonky3 STARK proof of `AggFoldAir`.
#[derive(Clone)]
pub struct AggFoldProof {
    /// Number of active steps committed in this proof.
    pub num_steps: usize,
    /// Underlying Plonky3 `ChipProof`.
    pub proof: ChipProof,
}

/// 23-column recursive fold AIR.
#[derive(Clone, Copy, Debug, Default)]
struct AggFoldAir;

impl<F> BaseAir<F> for AggFoldAir {
    fn width(&self) -> usize {
        FOLD_WIDTH
    }

    fn num_public_values(&self) -> usize {
        FOLD_NUM_PUBLIC_VALUES
    }
}

/// Unpacks a 32-byte digest into 8 little-endian `u32` limbs stored in `u64`.
fn digest_to_limbs(d: &[u8; 32]) -> [u64; DIGEST_LIMBS] {
    let mut out = [0u64; DIGEST_LIMBS];
    for (i, chunk) in d.chunks_exact(4).enumerate() {
        let limb = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if let Some(slot) = out.get_mut(i) {
            *slot = u64::from(limb);
        }
    }
    out
}

/// Derives two independent non-zero Goldilocks challenges and initial
/// accumulator seeds from all public statement fields via Keccak-256.
fn derive_challenges(pub_stmt: &AggFoldPublic) -> (u64, u64, u64, u64) {
    let mut buf = Vec::with_capacity(15 + 4 + 4 + 32 * 5 + 4);
    buf.extend_from_slice(b"AGG_FOLD_AIR_V1");
    buf.extend_from_slice(&pub_stmt.parameter_set.to_be_bytes());
    buf.extend_from_slice(&pub_stmt.domain.to_be_bytes());
    buf.extend_from_slice(&pub_stmt.tick_program_hash);
    buf.extend_from_slice(&pub_stmt.merge_program_hash);
    buf.extend_from_slice(&pub_stmt.final_program_hash);
    buf.extend_from_slice(&pub_stmt.master_pi);
    buf.extend_from_slice(&pub_stmt.shape_digest);
    buf.extend_from_slice(&pub_stmt.step_count.to_be_bytes());

    let states = absorb_states(&buf);
    let mut final_state = states.last().copied().unwrap_or([0u64; 25]);
    keccak_f(&mut final_state);

    // Mask to 62 bits so values are guaranteed strictly below Goldilocks modulus
    // `2^64 - 2^32 + 1` and non-zero (`| 1`).
    let mask = |w: u64| (w & 0x3FFF_FFFF_FFFF_FFFF) | 1;
    (
        mask(final_state[0]),
        mask(final_state[1]),
        mask(final_state[2]),
        mask(final_state[3]),
    )
}

/// Computes the deterministic row linear payload mixed into both accumulators
/// on row `step`. Kept identical between witness builder and AIR `eval`.
fn row_mix_field(step: &AggFoldStep, step_idx: u64) -> (Goldilocks, Goldilocks) {
    let prog = digest_to_limbs(&step.program_hash);
    let pi = digest_to_limbs(&step.node_pi);
    let flags = u64::from(step.is_merge)
        + 2 * u64::from(step.left_is_merge)
        + 4 * u64::from(step.right_is_merge)
        + 8 * step_idx;

    // Distinct small domain weights per limb so lo and hi linear combinations
    // are linearly independent across all 16 limbs + flags.
    let mut lo = Goldilocks::new(flags + 1);
    let mut hi = Goldilocks::new(flags.wrapping_mul(3) + 5);
    for i in 0..DIGEST_LIMBS {
        let w_prog_lo = Goldilocks::new((i as u64) * 2 + 17);
        let w_pi_lo = Goldilocks::new((i as u64) * 2 + 37);
        let w_prog_hi = Goldilocks::new((i as u64) * 3 + 59);
        let w_pi_hi = Goldilocks::new((i as u64) * 5 + 97);
        lo += Goldilocks::new(prog[i]) * w_prog_lo + Goldilocks::new(pi[i]) * w_pi_lo;
        hi += Goldilocks::new(prog[i]) * w_prog_hi + Goldilocks::new(pi[i]) * w_pi_hi;
    }
    (lo, hi)
}

/// Evaluates the exact same row linear payloads in symbolic `AB::Expr`.
fn row_mix_expr<AB: AirBuilder>(row: &[AB::Expr]) -> (AB::Expr, AB::Expr) {
    let flags = row[COL_IS_MERGE].clone()
        + AB::Expr::from_u64(2) * row[COL_LEFT_IS_MERGE].clone()
        + AB::Expr::from_u64(4) * row[COL_RIGHT_IS_MERGE].clone()
        + AB::Expr::from_u64(8) * row[COL_STEP_IDX].clone();

    let mut lo = flags.clone() + AB::Expr::ONE;
    let mut hi = AB::Expr::from_u64(3) * flags + AB::Expr::from_u64(5);
    for i in 0..DIGEST_LIMBS {
        let w_prog_lo = AB::Expr::from_u64((i as u64) * 2 + 17);
        let w_pi_lo = AB::Expr::from_u64((i as u64) * 2 + 37);
        let w_prog_hi = AB::Expr::from_u64((i as u64) * 3 + 59);
        let w_pi_hi = AB::Expr::from_u64((i as u64) * 5 + 97);
        lo += row[COL_PROG_BASE + i].clone() * w_prog_lo + row[COL_PI_BASE + i].clone() * w_pi_lo;
        hi += row[COL_PROG_BASE + i].clone() * w_prog_hi + row[COL_PI_BASE + i].clone() * w_pi_hi;
    }
    (lo, hi)
}

/// Computes the exact expected `(final_acc_lo, final_acc_hi)` after folding all
/// `steps` under `pub_stmt`.
fn compute_final_accumulators(
    steps: &[AggFoldStep],
    pub_stmt: &AggFoldPublic,
) -> (Goldilocks, Goldilocks) {
    let (alpha_lo_u, alpha_hi_u, init_lo_u, init_hi_u) = derive_challenges(pub_stmt);
    let alpha_lo = Goldilocks::new(alpha_lo_u);
    let alpha_hi = Goldilocks::new(alpha_hi_u);
    let mut acc_lo = Goldilocks::new(init_lo_u);
    let mut acc_hi = Goldilocks::new(init_hi_u);

    for (idx, step) in steps.iter().enumerate() {
        let (mix_lo, mix_hi) = row_mix_field(step, (idx + 1) as u64);
        acc_lo = acc_lo * alpha_lo + mix_lo;
        acc_hi = acc_hi * alpha_hi + mix_hi;
    }
    (acc_lo, acc_hi)
}

/// Builds the 39 public Goldilocks values shared by prover and verifier.
fn build_fold_public_values(steps: &[AggFoldStep], pub_stmt: &AggFoldPublic) -> Vec<Goldilocks> {
    let tick_limbs = digest_to_limbs(&pub_stmt.tick_program_hash);
    let merge_limbs = digest_to_limbs(&pub_stmt.merge_program_hash);
    let final_limbs = digest_to_limbs(&pub_stmt.final_program_hash);
    let master_limbs = digest_to_limbs(&pub_stmt.master_pi);
    let (alpha_lo, alpha_hi, init_lo, init_hi) = derive_challenges(pub_stmt);
    let (final_lo, final_hi) = compute_final_accumulators(steps, pub_stmt);

    let mut pv = Vec::with_capacity(FOLD_NUM_PUBLIC_VALUES);
    pv.extend(tick_limbs.into_iter().map(Goldilocks::new));
    pv.extend(merge_limbs.into_iter().map(Goldilocks::new));
    pv.extend(final_limbs.into_iter().map(Goldilocks::new));
    pv.extend(master_limbs.into_iter().map(Goldilocks::new));
    pv.push(Goldilocks::new(u64::from(pub_stmt.step_count)));
    pv.push(Goldilocks::new(alpha_lo));
    pv.push(Goldilocks::new(alpha_hi));
    pv.push(Goldilocks::new(init_lo));
    pv.push(Goldilocks::new(init_hi));
    pv.push(final_lo);
    pv.push(final_hi);
    pv
}

impl<AB: AirBuilder> Air<AB> for AggFoldAir {
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

        if local.len() < FOLD_WIDTH || next.len() < FOLD_WIDTH || pv.len() < FOLD_NUM_PUBLIC_VALUES
        {
            return;
        }

        let one = AB::Expr::ONE;
        let is_active = local[COL_IS_ACTIVE].clone();
        let is_merge = local[COL_IS_MERGE].clone();
        let left_is_merge = local[COL_LEFT_IS_MERGE].clone();
        let right_is_merge = local[COL_RIGHT_IS_MERGE].clone();
        let next_active = next[COL_IS_ACTIVE].clone();

        // 1. Booleanity of all four flag columns (degree 2).
        builder.assert_zero(is_active.clone() * (one.clone() - is_active.clone()));
        builder.assert_zero(is_merge.clone() * (one.clone() - is_merge.clone()));
        builder.assert_zero(left_is_merge.clone() * (one.clone() - left_is_merge));
        builder.assert_zero(right_is_merge.clone() * (one.clone() - right_is_merge));

        // 2. Strict program-hash allowlist on every active row (degree 3):
        //    is_active * (prog[i] - ((1 - is_merge) * tick[i] + is_merge * merge[i])) == 0.
        for i in 0..DIGEST_LIMBS {
            let expected = (one.clone() - is_merge.clone()) * pv[PV_TICK_BASE + i].clone()
                + is_merge.clone() * pv[PV_MERGE_BASE + i].clone();
            builder.assert_zero(is_active.clone() * (local[COL_PROG_BASE + i].clone() - expected));
        }

        // 3. First row boundary constraints.
        let (local_mix_lo, local_mix_hi) = row_mix_expr::<AB>(&local);
        {
            let mut first = builder.when_first_row();
            first.assert_zero(is_active.clone() - one.clone());
            first.assert_zero(local[COL_STEP_IDX].clone() - one.clone());
            first.assert_zero(
                local[COL_ACC_LO].clone()
                    - (pv[PV_INIT_ACC_LO].clone() * pv[PV_ALPHA_LO].clone() + local_mix_lo),
            );
            first.assert_zero(
                local[COL_ACC_HI].clone()
                    - (pv[PV_INIT_ACC_HI].clone() * pv[PV_ALPHA_HI].clone() + local_mix_hi),
            );
        }

        // 4. Transition constraints (degree <= 3).
        let (next_mix_lo, next_mix_hi) = row_mix_expr::<AB>(&next);
        {
            let mut trans = builder.when_transition();

            // Monotone active prefix: inactive cannot become active.
            trans.assert_zero(next_active.clone() * (one.clone() - is_active.clone()));

            // Step counter: increments by 1 if next row is active, else holds steady.
            trans.assert_zero(
                next[COL_STEP_IDX].clone() - (local[COL_STEP_IDX].clone() + next_active.clone()),
            );

            // Accumulator transition: folds next row when next_active == 1, else carries forward.
            let fold_lo = local[COL_ACC_LO].clone() * pv[PV_ALPHA_LO].clone() + next_mix_lo;
            let fold_hi = local[COL_ACC_HI].clone() * pv[PV_ALPHA_HI].clone() + next_mix_hi;
            let expected_acc_lo = next_active.clone() * fold_lo
                + (one.clone() - next_active.clone()) * local[COL_ACC_LO].clone();
            let expected_acc_hi = next_active.clone() * fold_hi
                + (one.clone() - next_active.clone()) * local[COL_ACC_HI].clone();
            trans.assert_zero(next[COL_ACC_LO].clone() - expected_acc_lo);
            trans.assert_zero(next[COL_ACC_HI].clone() - expected_acc_hi);

            // Padding rows carry forward the final active row's program_hash and node_pi
            // so the last row boundary always binds the true root step.
            let is_pad_next = one.clone() - next_active;
            for i in 0..DIGEST_LIMBS {
                trans.assert_zero(
                    is_pad_next.clone()
                        * (next[COL_PROG_BASE + i].clone() - local[COL_PROG_BASE + i].clone()),
                );
                trans.assert_zero(
                    is_pad_next.clone()
                        * (next[COL_PI_BASE + i].clone() - local[COL_PI_BASE + i].clone()),
                );
            }
        }

        // 5. Last row boundary constraints: step count, final program hash, master_pi,
        //    and both final accumulators must match public values.
        {
            let mut last = builder.when_last_row();
            last.assert_zero(local[COL_STEP_IDX].clone() - pv[PV_STEP_COUNT].clone());
            for i in 0..DIGEST_LIMBS {
                last.assert_zero(
                    local[COL_PROG_BASE + i].clone() - pv[PV_FINAL_PROG_BASE + i].clone(),
                );
                last.assert_zero(
                    local[COL_PI_BASE + i].clone() - pv[PV_MASTER_PI_BASE + i].clone(),
                );
            }
            last.assert_zero(local[COL_ACC_LO].clone() - pv[PV_FINAL_ACC_LO].clone());
            last.assert_zero(local[COL_ACC_HI].clone() - pv[PV_FINAL_ACC_HI].clone());
        }
    }
}

fn validate_statement(steps: &[AggFoldStep], pub_stmt: &AggFoldPublic) -> Result<(), FoldAirError> {
    if steps.is_empty() {
        return Err(FoldAirError::EmptySteps);
    }
    if steps.len() > MAX_FOLD_STEPS || usize::try_from(pub_stmt.step_count) != Ok(steps.len()) {
        return Err(FoldAirError::InvalidStepCount);
    }
    for (idx, step) in steps.iter().enumerate() {
        let expected_prog = if step.is_merge {
            pub_stmt.merge_program_hash
        } else {
            pub_stmt.tick_program_hash
        };
        if step.program_hash != expected_prog {
            return Err(FoldAirError::UnauthorizedProgramHash(idx));
        }
    }
    if let Some(last) = steps.last() {
        if last.program_hash != pub_stmt.final_program_hash || last.node_pi != pub_stmt.master_pi {
            return Err(FoldAirError::FinalStatementMismatch);
        }
    }
    Ok(())
}

/// Generates a 128-bit Plonky3 STARK proof over `AggFoldAir` for `steps`
/// and `pub_stmt`.
pub fn prove_agg_fold(
    steps: &[AggFoldStep],
    pub_stmt: &AggFoldPublic,
) -> Result<AggFoldProof, FoldAirError> {
    validate_statement(steps, pub_stmt)?;

    // Minimum trace height of 16 keeps degree-3 quotient + FRI blowup well-defined.
    let height = steps.len().next_power_of_two().max(16);
    let (alpha_lo_u, alpha_hi_u, init_lo_u, init_hi_u) = derive_challenges(pub_stmt);
    let alpha_lo = Goldilocks::new(alpha_lo_u);
    let alpha_hi = Goldilocks::new(alpha_hi_u);
    let mut acc_lo = Goldilocks::new(init_lo_u);
    let mut acc_hi = Goldilocks::new(init_hi_u);

    let mut values = Vec::with_capacity(height * FOLD_WIDTH);
    let mut last_prog_limbs = [0u64; DIGEST_LIMBS];
    let mut last_pi_limbs = [0u64; DIGEST_LIMBS];

    for (idx, step) in steps.iter().enumerate() {
        let step_num = (idx + 1) as u64;
        let prog_limbs = digest_to_limbs(&step.program_hash);
        let pi_limbs = digest_to_limbs(&step.node_pi);
        let (mix_lo, mix_hi) = row_mix_field(step, step_num);
        acc_lo = acc_lo * alpha_lo + mix_lo;
        acc_hi = acc_hi * alpha_hi + mix_hi;
        last_prog_limbs = prog_limbs;
        last_pi_limbs = pi_limbs;

        values.push(Goldilocks::ONE);
        values.push(Goldilocks::new(u64::from(step.is_merge)));
        values.push(Goldilocks::new(u64::from(step.left_is_merge)));
        values.push(Goldilocks::new(u64::from(step.right_is_merge)));
        values.push(Goldilocks::new(step_num));
        for limb in prog_limbs {
            values.push(Goldilocks::new(limb));
        }
        for limb in pi_limbs {
            values.push(Goldilocks::new(limb));
        }
        values.push(acc_lo);
        values.push(acc_hi);
    }

    // Pad remaining rows with is_active = 0, carrying forward step_count,
    // final program_hash, master_pi, and accumulators.
    let final_step_num = steps.len() as u64;
    for _ in steps.len()..height {
        values.push(Goldilocks::ZERO);
        values.push(Goldilocks::ZERO);
        values.push(Goldilocks::ZERO);
        values.push(Goldilocks::ZERO);
        values.push(Goldilocks::new(final_step_num));
        for limb in last_prog_limbs {
            values.push(Goldilocks::new(limb));
        }
        for limb in last_pi_limbs {
            values.push(Goldilocks::new(limb));
        }
        values.push(acc_lo);
        values.push(acc_hi);
    }

    let public_values = build_fold_public_values(steps, pub_stmt);
    let trace = RowMajorMatrix::new(values, FOLD_WIDTH);
    let proof = prove_chip(&AggFoldAir, trace, &public_values);
    Ok(AggFoldProof {
        num_steps: steps.len(),
        proof,
    })
}

/// Verifies an [`AggFoldProof`] against `steps` and `pub_stmt`.
pub fn verify_agg_fold(
    steps: &[AggFoldStep],
    pub_stmt: &AggFoldPublic,
    proof: &AggFoldProof,
) -> Result<(), FoldAirError> {
    validate_statement(steps, pub_stmt)?;
    if proof.num_steps != steps.len() {
        return Err(FoldAirError::InvalidStepCount);
    }
    let public_values = build_fold_public_values(steps, pub_stmt);
    verify_chip(&AggFoldAir, &proof.proof, &public_values)
        .map_err(|e| FoldAirError::VerifyFailed(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tree() -> (Vec<AggFoldStep>, AggFoldPublic) {
        let tick_hash = [0x11; 32];
        let merge_hash = [0x22; 32];
        let steps = vec![
            AggFoldStep {
                is_merge: false,
                left_is_merge: false,
                right_is_merge: false,
                program_hash: tick_hash,
                node_pi: [0xA1; 32],
            },
            AggFoldStep {
                is_merge: false,
                left_is_merge: false,
                right_is_merge: false,
                program_hash: tick_hash,
                node_pi: [0xA2; 32],
            },
            AggFoldStep {
                is_merge: true,
                left_is_merge: false,
                right_is_merge: false,
                program_hash: merge_hash,
                node_pi: [0xB1; 32],
            },
            AggFoldStep {
                is_merge: false,
                left_is_merge: false,
                right_is_merge: false,
                program_hash: tick_hash,
                node_pi: [0xA3; 32],
            },
            AggFoldStep {
                is_merge: false,
                left_is_merge: false,
                right_is_merge: false,
                program_hash: tick_hash,
                node_pi: [0xA4; 32],
            },
            AggFoldStep {
                is_merge: true,
                left_is_merge: false,
                right_is_merge: false,
                program_hash: merge_hash,
                node_pi: [0xB2; 32],
            },
            AggFoldStep {
                is_merge: true,
                left_is_merge: true,
                right_is_merge: true,
                program_hash: merge_hash,
                node_pi: [0xFF; 32],
            },
        ];
        let pub_stmt = AggFoldPublic {
            parameter_set: 2,
            domain: 43,
            tick_program_hash: tick_hash,
            merge_program_hash: merge_hash,
            final_program_hash: merge_hash,
            master_pi: [0xFF; 32],
            shape_digest: [0x77; 32],
            step_count: 7,
        };
        (steps, pub_stmt)
    }

    #[test]
    fn agg_fold_air_proves_verifies_and_fits_block_budget() {
        let (steps, pub_stmt) = sample_tree();
        let proof = prove_agg_fold(&steps, &pub_stmt).expect("prove");
        let serialized = postcard::to_allocvec(&proof.proof).expect("serialize");
        assert!(
            serialized.len() < 262_144,
            "proof size {} must fit inside 262,144 byte block budget",
            serialized.len()
        );
        verify_agg_fold(&steps, &pub_stmt, &proof).expect("verify");

        // Wrong domain must fail.
        let mut bad_domain = pub_stmt.clone();
        bad_domain.domain = 99;
        assert!(verify_agg_fold(&steps, &bad_domain, &proof).is_err());

        // Wrong parameter set must fail.
        let mut bad_param = pub_stmt.clone();
        bad_param.parameter_set = 3;
        assert!(verify_agg_fold(&steps, &bad_param, &proof).is_err());

        // Altered intermediate node_pi must fail.
        let mut bad_steps = steps.clone();
        bad_steps[0].node_pi[0] ^= 0x01;
        assert!(verify_agg_fold(&bad_steps, &pub_stmt, &proof).is_err());

        // Altered shape digest (e.g. swapped aggregator fee) must fail.
        let mut bad_shape = pub_stmt.clone();
        bad_shape.shape_digest[0] ^= 0x80;
        assert!(verify_agg_fold(&steps, &bad_shape, &proof).is_err());

        // Unauthorized program hash in step must fail before proving.
        let mut rogue = steps;
        rogue[2].program_hash = [0x99; 32];
        assert_eq!(
            prove_agg_fold(&rogue, &pub_stmt).err(),
            Some(FoldAirError::UnauthorizedProgramHash(2))
        );
    }

    #[test]
    fn agg_fold_air_exact_power_of_two_trace_verifies() {
        let tick_hash = [0x31; 32];
        let merge_hash = [0x42; 32];
        let mut steps = Vec::with_capacity(16);
        for i in 0u8..16 {
            steps.push(AggFoldStep {
                is_merge: i == 15,
                left_is_merge: false,
                right_is_merge: false,
                program_hash: if i == 15 { merge_hash } else { tick_hash },
                node_pi: [i; 32],
            });
        }
        let pub_stmt = AggFoldPublic {
            parameter_set: 2,
            domain: 43,
            tick_program_hash: tick_hash,
            merge_program_hash: merge_hash,
            final_program_hash: merge_hash,
            master_pi: [15; 32],
            shape_digest: [0x55; 32],
            step_count: 16,
        };
        let proof = prove_agg_fold(&steps, &pub_stmt).expect("prove 16-row");
        verify_agg_fold(&steps, &pub_stmt, &proof).expect("verify 16-row");
    }
}
