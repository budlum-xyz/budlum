//! Cubic Goldilocks extension field arithmetic STARK chip (`F[X] / (X^3 - X - 1)`).
//!
//! Constrains addition, subtraction, trinomial multiplication, multiplicative
//! inversion, and division over [`crate::plonky3_prover::ChipExtensionField`]
//! (`CubicTrinomialExtensionField<Goldilocks>`).
//!
//! In `GF(p)[X] / (X^3 - X - 1)` with `p = 2^64 - 2^32 + 1`, `X^3 = X + 1` and
//! `X^4 = X^2 + X`, so `(a0 + a1*X + a2*X^2) * (b0 + b1*X + b2*X^2)` equals:
//!
//! * `c0 = a0*b0 + a1*b2 + a2*b1`
//! * `c1 = a0*b1 + a1*b0 + a1*b2 + a2*b1 + a2*b2`
//! * `c2 = a0*b2 + a1*b1 + a2*b0 + a2*b2`
//!
//! Inversion constrains `a * c = [1, 0, 0]`, which has degree 3 with the row
//! selector, uniquely pins `c = a^{-1}` for every non-zero `a`, and has no
//! satisfying witness when `a = [0, 0, 0]` because `GF(p)[X] / (X^3 - X - 1)`
//! is a field.
//!
//! WIRING: Foundation cubic-extension arithmetic gadget and standalone/batch
//! STARK chip documented in `docs/pq/RECURSION_PLAN.md` (`R-2`), consumed by
//! recursion verification harnesses and embeddable via `SubAirBuilder` into
//! FRI folding and out-of-domain evaluation circuits.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::plonky3_prover::{
    chip_ext_to_limbs, prove_chip, prove_chip_with_preprocessed, verify_chip,
    verify_chip_with_preprocessed, ChipExtensionField, ChipProof,
};

/// Active-row boolean flag column.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_IS_ACTIVE: usize = 0;
/// Canonical opcode tag column (`0` inactive, `1..=5` active operations).
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_OP_TAG: usize = 1;
/// Selector column for cubic extension addition.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_SEL_ADD: usize = 2;
/// Selector column for cubic extension subtraction.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_SEL_SUB: usize = 3;
/// Selector column for cubic extension multiplication.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_SEL_MUL: usize = 4;
/// Selector column for cubic extension multiplicative inversion.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_SEL_INV: usize = 5;
/// Selector column for cubic extension division (`a * b^{-1}`).
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_SEL_DIV: usize = 6;
/// First basis limb column of operand `a` (`[a0, a1, a2]`).
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_A_BASE: usize = 7;
/// First basis limb column of operand `b` (`[b0, b1, b2]`).
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_B_BASE: usize = 10;
/// First basis limb column of output `c` (`[c0, c1, c2]`).
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_C_BASE: usize = 13;
/// First basis limb column of the witnessed multiplicative inverse (`a^{-1}` or `b^{-1}`).
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const COL_AUX_INV_BASE: usize = 16;
/// Total main-trace width of the cubic extension arithmetic chip.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const EXT_FIELD_MAIN_WIDTH: usize = 19;

/// Minimum power-of-two trace height required by `ChipStarkConfig` FRI parameters.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const MIN_EXT_FIELD_TRACE_ROWS: usize = 16;

/// Maximum operations proven in a single batch trace to bound prover memory.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const MAX_EXT_FIELD_OPS: usize = 1 << 16;

const OP_TAG_ADD: u64 = 1;
const OP_TAG_SUB: u64 = 2;
const OP_TAG_MUL: u64 = 3;
const OP_TAG_INV: u64 = 4;
const OP_TAG_DIV: u64 = 5;

const SINGLE_PUBLIC_VALUES: usize = 10;
const BATCH_PUBLIC_VALUES: usize = 2;
const BATCH_PREP_WIDTH: usize = 11;
const EXT_FIELD_MODE_TAG: u64 = 0x5232_4558; // "R2EX"

const PREP_IS_ACTIVE: usize = 0;
const PREP_OP_TAG: usize = 1;
const PREP_A_BASE: usize = 2;
const PREP_B_BASE: usize = 5;
const PREP_C_BASE: usize = 8;

/// One operation over [`ChipExtensionField`] represented by canonical Goldilocks basis limbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub enum ExtFieldOp {
    /// `c = a + b`.
    Add { a: [u64; 3], b: [u64; 3] },
    /// `c = a - b`.
    Sub { a: [u64; 3], b: [u64; 3] },
    /// `c = a * b mod (X^3 - X - 1)`.
    Mul { a: [u64; 3], b: [u64; 3] },
    /// `c = a^{-1} mod (X^3 - X - 1)` for non-zero `a`.
    Inv { a: [u64; 3] },
    /// `c = a * b^{-1} mod (X^3 - X - 1)` for non-zero `b`.
    Div { a: [u64; 3], b: [u64; 3] },
}

impl ExtFieldOp {
    const fn op_tag(&self) -> u64 {
        match self {
            Self::Add { .. } => OP_TAG_ADD,
            Self::Sub { .. } => OP_TAG_SUB,
            Self::Mul { .. } => OP_TAG_MUL,
            Self::Inv { .. } => OP_TAG_INV,
            Self::Div { .. } => OP_TAG_DIV,
        }
    }

    const fn operands(&self) -> ([u64; 3], [u64; 3]) {
        match *self {
            Self::Add { a, b } | Self::Sub { a, b } | Self::Mul { a, b } | Self::Div { a, b } => {
                (a, b)
            }
            Self::Inv { a } => (a, [0, 0, 0]),
        }
    }
}

/// Refusal reasons returned by the cubic extension arithmetic chip.
#[derive(Debug, Clone, PartialEq, Eq)]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub enum ExtFieldChipError {
    /// No operation was supplied.
    Empty,
    /// More than [`MAX_EXT_FIELD_OPS`] operations were supplied.
    TooMany(usize),
    /// An operand or claimed output limb is `>= Goldilocks::ORDER_U64`.
    NonCanonicalLimb(u64),
    /// Inversion or division by `[0, 0, 0]` was requested.
    DivisionByZero,
    /// Batch operand/output/proof shapes do not match.
    ShapeMismatch,
    /// Constraint check or STARK verification refused the proof.
    Rejected(String),
}

fn validate_limbs(limbs: [u64; 3]) -> Result<ChipExtensionField, ExtFieldChipError> {
    for limb in limbs {
        if limb >= Goldilocks::ORDER_U64 {
            return Err(ExtFieldChipError::NonCanonicalLimb(limb));
        }
    }
    let coeffs = limbs.map(Goldilocks::new);
    ChipExtensionField::from_basis_coefficients_slice(&coeffs)
        .ok_or_else(|| ExtFieldChipError::Rejected("invalid basis slice length".into()))
}

/// Evaluates `op` natively over [`ChipExtensionField`] after canonical-limb validation.
///
/// # Errors
///
/// Returns [`ExtFieldChipError::NonCanonicalLimb`] or [`ExtFieldChipError::DivisionByZero`].
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn eval_native_op(op: &ExtFieldOp) -> Result<[u64; 3], ExtFieldChipError> {
    let (out, _aux_inv) = eval_native_op_with_aux(op)?;
    Ok(out)
}

fn eval_native_op_with_aux(op: &ExtFieldOp) -> Result<([u64; 3], [u64; 3]), ExtFieldChipError> {
    match *op {
        ExtFieldOp::Add { a, b } => {
            let fa = validate_limbs(a)?;
            let fb = validate_limbs(b)?;
            Ok((chip_ext_to_limbs(fa + fb), [0, 0, 0]))
        }
        ExtFieldOp::Sub { a, b } => {
            let fa = validate_limbs(a)?;
            let fb = validate_limbs(b)?;
            Ok((chip_ext_to_limbs(fa - fb), [0, 0, 0]))
        }
        ExtFieldOp::Mul { a, b } => {
            let fa = validate_limbs(a)?;
            let fb = validate_limbs(b)?;
            Ok((chip_ext_to_limbs(fa * fb), [0, 0, 0]))
        }
        ExtFieldOp::Inv { a } => {
            let fa = validate_limbs(a)?;
            let inv = fa.try_inverse().ok_or(ExtFieldChipError::DivisionByZero)?;
            let limbs = chip_ext_to_limbs(inv);
            Ok((limbs, limbs))
        }
        ExtFieldOp::Div { a, b } => {
            let fa = validate_limbs(a)?;
            let fb = validate_limbs(b)?;
            let b_inv = fb.try_inverse().ok_or(ExtFieldChipError::DivisionByZero)?;
            Ok((chip_ext_to_limbs(fa * b_inv), chip_ext_to_limbs(b_inv)))
        }
    }
}

#[inline]
fn trinomial_product_expr<Expr: PrimeCharacteristicRing + Clone>(
    lhs: &[Expr; 3],
    rhs: &[Expr; 3],
) -> [Expr; 3] {
    let a0b0 = lhs[0].clone() * rhs[0].clone();
    let a0b1 = lhs[0].clone() * rhs[1].clone();
    let a0b2 = lhs[0].clone() * rhs[2].clone();
    let a1b0 = lhs[1].clone() * rhs[0].clone();
    let a1b1 = lhs[1].clone() * rhs[1].clone();
    let a1b2 = lhs[1].clone() * rhs[2].clone();
    let a2b0 = lhs[2].clone() * rhs[0].clone();
    let a2b1 = lhs[2].clone() * rhs[1].clone();
    let a2b2 = lhs[2].clone() * rhs[2].clone();

    let cross_12 = a1b2 + a2b1;
    let c0 = a0b0 + cross_12.clone();
    let c1 = a0b1 + a1b0 + cross_12 + a2b2.clone();
    let c2 = a0b2 + a1b1 + a2b0 + a2b2;
    [c0, c1, c2]
}

/// Enforces all cubic extension arithmetic row constraints on columns
/// `0..EXT_FIELD_MAIN_WIDTH` of `builder.main()`.
///
/// Safe to invoke directly or through [`crate::bud_stark::SubAirBuilder`] inside
/// a wider recursion AIR.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn eval_ext_field_row_constraints<AB: AirBuilder>(builder: &mut AB) {
    let (is_active, op_tag, sel_add, sel_sub, sel_mul, sel_inv, sel_div, a, b, c, aux_inv) = {
        let main = builder.main();
        let local = main.current_slice();
        let is_active: AB::Expr = local[COL_IS_ACTIVE].into();
        let op_tag: AB::Expr = local[COL_OP_TAG].into();
        let sel_add: AB::Expr = local[COL_SEL_ADD].into();
        let sel_sub: AB::Expr = local[COL_SEL_SUB].into();
        let sel_mul: AB::Expr = local[COL_SEL_MUL].into();
        let sel_inv: AB::Expr = local[COL_SEL_INV].into();
        let sel_div: AB::Expr = local[COL_SEL_DIV].into();
        let a: [AB::Expr; 3] = core::array::from_fn(|i| local[COL_A_BASE + i].into());
        let b: [AB::Expr; 3] = core::array::from_fn(|i| local[COL_B_BASE + i].into());
        let c: [AB::Expr; 3] = core::array::from_fn(|i| local[COL_C_BASE + i].into());
        let aux_inv: [AB::Expr; 3] = core::array::from_fn(|i| local[COL_AUX_INV_BASE + i].into());
        (
            is_active, op_tag, sel_add, sel_sub, sel_mul, sel_inv, sel_div, a, b, c, aux_inv,
        )
    };

    builder.assert_bool(is_active.clone());
    builder.assert_bool(sel_add.clone());
    builder.assert_bool(sel_sub.clone());
    builder.assert_bool(sel_mul.clone());
    builder.assert_bool(sel_inv.clone());
    builder.assert_bool(sel_div.clone());

    let selector_sum =
        sel_add.clone() + sel_sub.clone() + sel_mul.clone() + sel_inv.clone() + sel_div.clone();
    builder.assert_eq(selector_sum, is_active.clone());

    let expected_tag = sel_add.clone() * AB::Expr::from_u64(OP_TAG_ADD)
        + sel_sub.clone() * AB::Expr::from_u64(OP_TAG_SUB)
        + sel_mul.clone() * AB::Expr::from_u64(OP_TAG_MUL)
        + sel_inv.clone() * AB::Expr::from_u64(OP_TAG_INV)
        + sel_div.clone() * AB::Expr::from_u64(OP_TAG_DIV);
    builder.assert_eq(op_tag, expected_tag);

    let inactive = AB::Expr::ONE - is_active;
    for i in 0..3 {
        builder.when(inactive.clone()).assert_zero(a[i].clone());
        builder.when(inactive.clone()).assert_zero(b[i].clone());
        builder.when(inactive.clone()).assert_zero(c[i].clone());
        builder
            .when(inactive.clone())
            .assert_zero(aux_inv[i].clone());
    }

    for i in 0..3 {
        builder
            .when(sel_add.clone())
            .assert_eq(c[i].clone(), a[i].clone() + b[i].clone());
        builder
            .when(sel_add.clone())
            .assert_zero(aux_inv[i].clone());

        builder
            .when(sel_sub.clone())
            .assert_eq(c[i].clone() + b[i].clone(), a[i].clone());
        builder
            .when(sel_sub.clone())
            .assert_zero(aux_inv[i].clone());
    }

    let ab_prod = trinomial_product_expr(&a, &b);
    for i in 0..3 {
        builder
            .when(sel_mul.clone())
            .assert_eq(c[i].clone(), ab_prod[i].clone());
        builder
            .when(sel_mul.clone())
            .assert_zero(aux_inv[i].clone());
    }

    let ac_prod = trinomial_product_expr(&a, &c);
    builder
        .when(sel_inv.clone())
        .assert_eq(ac_prod[0].clone(), AB::Expr::ONE);
    builder
        .when(sel_inv.clone())
        .assert_zero(ac_prod[1].clone());
    builder
        .when(sel_inv.clone())
        .assert_zero(ac_prod[2].clone());
    for i in 0..3 {
        builder.when(sel_inv.clone()).assert_zero(b[i].clone());
        builder
            .when(sel_inv.clone())
            .assert_eq(aux_inv[i].clone(), c[i].clone());
    }

    let b_binv_prod = trinomial_product_expr(&b, &aux_inv);
    let a_binv_prod = trinomial_product_expr(&a, &aux_inv);
    builder
        .when(sel_div.clone())
        .assert_eq(b_binv_prod[0].clone(), AB::Expr::ONE);
    builder
        .when(sel_div.clone())
        .assert_zero(b_binv_prod[1].clone());
    builder
        .when(sel_div.clone())
        .assert_zero(b_binv_prod[2].clone());
    for i in 0..3 {
        builder
            .when(sel_div.clone())
            .assert_eq(c[i].clone(), a_binv_prod[i].clone());
    }
}

/// Fixed-VK STARK AIR for a single cubic extension operation bound purely via
/// 10 public values `[op_tag, a0..a2, b0..b2, c0..c2]`.
#[derive(Debug, Clone, Copy, Default)]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub struct ExtFieldSingleAir;

impl<F> BaseAir<F> for ExtFieldSingleAir {
    fn width(&self) -> usize {
        EXT_FIELD_MAIN_WIDTH
    }

    fn num_public_values(&self) -> usize {
        SINGLE_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for ExtFieldSingleAir {
    fn eval(&self, builder: &mut AB) {
        eval_ext_field_row_constraints(builder);

        let (is_active, next_is_active, op_tag, a, b, c, pvs) = {
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            let pv_slice = builder.public_values();
            if pv_slice.len() < SINGLE_PUBLIC_VALUES {
                return;
            }
            let is_active: AB::Expr = local[COL_IS_ACTIVE].into();
            let next_is_active: AB::Expr = next[COL_IS_ACTIVE].into();
            let op_tag: AB::Expr = local[COL_OP_TAG].into();
            let a: [AB::Expr; 3] = core::array::from_fn(|i| local[COL_A_BASE + i].into());
            let b: [AB::Expr; 3] = core::array::from_fn(|i| local[COL_B_BASE + i].into());
            let c: [AB::Expr; 3] = core::array::from_fn(|i| local[COL_C_BASE + i].into());
            let pvs: [AB::Expr; SINGLE_PUBLIC_VALUES] =
                core::array::from_fn(|i| pv_slice[i].into());
            (is_active, next_is_active, op_tag, a, b, c, pvs)
        };

        builder.when_first_row().assert_eq(is_active, AB::Expr::ONE);
        builder.when_first_row().assert_eq(op_tag, pvs[0].clone());
        for i in 0..3 {
            builder
                .when_first_row()
                .assert_eq(a[i].clone(), pvs[1 + i].clone());
            builder
                .when_first_row()
                .assert_eq(b[i].clone(), pvs[4 + i].clone());
            builder
                .when_first_row()
                .assert_eq(c[i].clone(), pvs[7 + i].clone());
        }
        builder.when_transition().assert_zero(next_is_active);
    }
}

/// Batch cubic extension arithmetic STARK AIR binding arbitrary batches of
/// `(op, a, b, c)` tuples into the preprocessed commitment and public values.
#[derive(Debug, Clone)]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub struct ExtFieldBatchAir {
    ops: Vec<ExtFieldOp>,
    outputs: Vec<[u64; 3]>,
}

impl ExtFieldBatchAir {
    /// Constructs a bound batch AIR over matching `(ops, outputs)` slices.
    ///
    /// # Errors
    ///
    /// Refuses empty batches, oversized batches, shape mismatches, or
    /// non-canonical Goldilocks limbs.
    /// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
    pub fn new(ops: Vec<ExtFieldOp>, outputs: Vec<[u64; 3]>) -> Result<Self, ExtFieldChipError> {
        if ops.is_empty() {
            return Err(ExtFieldChipError::Empty);
        }
        if ops.len() > MAX_EXT_FIELD_OPS {
            return Err(ExtFieldChipError::TooMany(ops.len()));
        }
        if ops.len() != outputs.len() {
            return Err(ExtFieldChipError::ShapeMismatch);
        }
        for (op, out) in ops.iter().zip(outputs.iter()) {
            let (a, b) = op.operands();
            let _ = validate_limbs(a)?;
            let _ = validate_limbs(b)?;
            let _ = validate_limbs(*out)?;
        }
        Ok(Self { ops, outputs })
    }

    fn padded_rows(&self) -> usize {
        self.ops
            .len()
            .next_power_of_two()
            .max(MIN_EXT_FIELD_TRACE_ROWS)
    }
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for ExtFieldBatchAir {
    fn width(&self) -> usize {
        EXT_FIELD_MAIN_WIDTH
    }

    fn num_public_values(&self) -> usize {
        BATCH_PUBLIC_VALUES
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        if self.ops.is_empty() || self.ops.len() != self.outputs.len() {
            return None;
        }
        let rows = self.padded_rows();
        let mut values = vec![F::ZERO; rows * BATCH_PREP_WIDTH];
        for (idx, (op, out)) in self.ops.iter().zip(self.outputs.iter()).enumerate() {
            let base = idx * BATCH_PREP_WIDTH;
            let (a, b) = op.operands();
            values[base + PREP_IS_ACTIVE] = F::ONE;
            values[base + PREP_OP_TAG] = F::from_u64(op.op_tag());
            for i in 0..3 {
                values[base + PREP_A_BASE + i] = F::from_u64(a[i]);
                values[base + PREP_B_BASE + i] = F::from_u64(b[i]);
                values[base + PREP_C_BASE + i] = F::from_u64(out[i]);
            }
        }
        Some(RowMajorMatrix::new(values, BATCH_PREP_WIDTH))
    }
}

impl<AB: AirBuilder> Air<AB> for ExtFieldBatchAir
where
    AB::F: Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        eval_ext_field_row_constraints(builder);

        let (
            is_active,
            op_tag,
            a,
            b,
            c,
            prep_active,
            prep_tag,
            prep_a,
            prep_b,
            prep_c,
            pv_count,
            pv_mode,
        ) = {
            let main = builder.main();
            let local = main.current_slice();
            let prep = builder.preprocessed();
            let prep_cur = prep.current_slice();
            let pv_slice = builder.public_values();
            if pv_slice.len() < BATCH_PUBLIC_VALUES || prep_cur.len() < BATCH_PREP_WIDTH {
                return;
            }
            let is_active: AB::Expr = local[COL_IS_ACTIVE].into();
            let op_tag: AB::Expr = local[COL_OP_TAG].into();
            let a: [AB::Expr; 3] = core::array::from_fn(|i| local[COL_A_BASE + i].into());
            let b: [AB::Expr; 3] = core::array::from_fn(|i| local[COL_B_BASE + i].into());
            let c: [AB::Expr; 3] = core::array::from_fn(|i| local[COL_C_BASE + i].into());

            let prep_active: AB::Expr = prep_cur[PREP_IS_ACTIVE].into();
            let prep_tag: AB::Expr = prep_cur[PREP_OP_TAG].into();
            let prep_a: [AB::Expr; 3] = core::array::from_fn(|i| prep_cur[PREP_A_BASE + i].into());
            let prep_b: [AB::Expr; 3] = core::array::from_fn(|i| prep_cur[PREP_B_BASE + i].into());
            let prep_c: [AB::Expr; 3] = core::array::from_fn(|i| prep_cur[PREP_C_BASE + i].into());

            let pv_count: AB::Expr = pv_slice[0].into();
            let pv_mode: AB::Expr = pv_slice[1].into();
            (
                is_active,
                op_tag,
                a,
                b,
                c,
                prep_active,
                prep_tag,
                prep_a,
                prep_b,
                prep_c,
                pv_count,
                pv_mode,
            )
        };

        builder.assert_eq(is_active, prep_active.clone());
        builder.assert_eq(op_tag, prep_tag);
        for i in 0..3 {
            builder
                .when(prep_active.clone())
                .assert_eq(a[i].clone(), prep_a[i].clone());
            builder
                .when(prep_active.clone())
                .assert_eq(b[i].clone(), prep_b[i].clone());
            builder
                .when(prep_active.clone())
                .assert_eq(c[i].clone(), prep_c[i].clone());
        }
        builder
            .when_first_row()
            .assert_eq(pv_count, AB::Expr::from_u64(self.ops.len() as u64));
        builder
            .when_first_row()
            .assert_eq(pv_mode, AB::Expr::from_u64(EXT_FIELD_MODE_TAG));
    }
}

/// Output tuple of [`build_ext_field_trace`]: `(main_trace, batch_public_values, outputs)`.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub type ExtFieldTraceBuild = (RowMajorMatrix<Goldilocks>, [Goldilocks; 2], Vec<[u64; 3]>);

/// Builds a main trace, batch public values, and output list for `ops`.
///
/// # Errors
///
/// Refuses empty/oversized batches, non-canonical limbs, or zero inversions.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn build_ext_field_trace(ops: &[ExtFieldOp]) -> Result<ExtFieldTraceBuild, ExtFieldChipError> {
    if ops.is_empty() {
        return Err(ExtFieldChipError::Empty);
    }
    if ops.len() > MAX_EXT_FIELD_OPS {
        return Err(ExtFieldChipError::TooMany(ops.len()));
    }
    let rows = ops.len().next_power_of_two().max(MIN_EXT_FIELD_TRACE_ROWS);
    let mut values = vec![Goldilocks::ZERO; rows * EXT_FIELD_MAIN_WIDTH];
    let mut outputs = Vec::with_capacity(ops.len());

    for (row_idx, op) in ops.iter().enumerate() {
        let (out, aux_inv) = eval_native_op_with_aux(op)?;
        outputs.push(out);
        let (a, b) = op.operands();
        let base = row_idx * EXT_FIELD_MAIN_WIDTH;
        values[base + COL_IS_ACTIVE] = Goldilocks::ONE;
        values[base + COL_OP_TAG] = Goldilocks::new(op.op_tag());
        match op {
            ExtFieldOp::Add { .. } => values[base + COL_SEL_ADD] = Goldilocks::ONE,
            ExtFieldOp::Sub { .. } => values[base + COL_SEL_SUB] = Goldilocks::ONE,
            ExtFieldOp::Mul { .. } => values[base + COL_SEL_MUL] = Goldilocks::ONE,
            ExtFieldOp::Inv { .. } => values[base + COL_SEL_INV] = Goldilocks::ONE,
            ExtFieldOp::Div { .. } => values[base + COL_SEL_DIV] = Goldilocks::ONE,
        }
        for i in 0..3 {
            values[base + COL_A_BASE + i] = Goldilocks::new(a[i]);
            values[base + COL_B_BASE + i] = Goldilocks::new(b[i]);
            values[base + COL_C_BASE + i] = Goldilocks::new(out[i]);
            values[base + COL_AUX_INV_BASE + i] = Goldilocks::new(aux_inv[i]);
        }
    }

    let pvs = [
        Goldilocks::new(ops.len() as u64),
        Goldilocks::new(EXT_FIELD_MODE_TAG),
    ];
    Ok((
        RowMajorMatrix::new(values, EXT_FIELD_MAIN_WIDTH),
        pvs,
        outputs,
    ))
}

fn single_public_values(
    op: &ExtFieldOp,
    output: [u64; 3],
) -> Result<[Goldilocks; 10], ExtFieldChipError> {
    let (a, b) = op.operands();
    let _ = validate_limbs(a)?;
    let _ = validate_limbs(b)?;
    let _ = validate_limbs(output)?;
    Ok([
        Goldilocks::new(op.op_tag()),
        Goldilocks::new(a[0]),
        Goldilocks::new(a[1]),
        Goldilocks::new(a[2]),
        Goldilocks::new(b[0]),
        Goldilocks::new(b[1]),
        Goldilocks::new(b[2]),
        Goldilocks::new(output[0]),
        Goldilocks::new(output[1]),
        Goldilocks::new(output[2]),
    ])
}

/// Checks [`ExtFieldSingleAir`] constraints row-by-row on `trace` and `public_values`,
/// returning `Err(ExtFieldChipError::Rejected)` instead of panicking on forgery.
///
/// # Errors
///
/// Returns [`ExtFieldChipError::ShapeMismatch`] or [`ExtFieldChipError::Rejected`].
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn check_single_air_constraints(
    trace: &RowMajorMatrix<Goldilocks>,
    public_values: &[Goldilocks],
) -> Result<(), ExtFieldChipError> {
    if trace.width() != EXT_FIELD_MAIN_WIDTH || public_values.len() != SINGLE_PUBLIC_VALUES {
        return Err(ExtFieldChipError::ShapeMismatch);
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        p3_air::check_constraints(&ExtFieldSingleAir, trace, public_values);
    }))
    .map_err(|_| ExtFieldChipError::Rejected("ExtFieldSingleAir constraint violation".into()))
}

/// Proves a single cubic extension operation under the fixed-VK [`ExtFieldSingleAir`].
///
/// # Errors
///
/// Refuses non-canonical Goldilocks limbs or zero inversion/division.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn prove_ext_field_op(op: &ExtFieldOp) -> Result<(ChipProof, [u64; 3]), ExtFieldChipError> {
    let (trace, _batch_pvs, outputs) = build_ext_field_trace(&[*op])?;
    let output = outputs[0];
    let pvs = single_public_values(op, output)?;
    let proof = prove_chip(&ExtFieldSingleAir, trace, &pvs);
    Ok((proof, output))
}

/// Verifies a fixed-VK single-operation proof produced by [`prove_ext_field_op`].
///
/// # Errors
///
/// Refuses non-canonical limbs, wrong trace height, or invalid STARK proofs.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn verify_ext_field_op(
    op: &ExtFieldOp,
    claimed_output: [u64; 3],
    proof: &ChipProof,
) -> Result<(), ExtFieldChipError> {
    let expected_degree_bits = MIN_EXT_FIELD_TRACE_ROWS.trailing_zeros() as usize;
    if proof.degree_bits != expected_degree_bits {
        return Err(ExtFieldChipError::ShapeMismatch);
    }
    let pvs = single_public_values(op, claimed_output)?;
    verify_chip(&ExtFieldSingleAir, proof, &pvs).map_err(ExtFieldChipError::Rejected)
}

/// Batch proof over a schedule of cubic extension operations.
#[derive(Clone)]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub struct ExtFieldBatchProof {
    /// Number of active operations committed in the trace.
    pub num_ops: usize,
    /// Underlying BudZero STARK proof.
    pub proof: ChipProof,
}

/// Proves a batch of cubic extension operations under [`ExtFieldBatchAir`].
///
/// # Errors
///
/// Refuses empty/oversized batches, non-canonical limbs, zero inversions, or
/// proving failures.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn prove_ext_field_batch(
    ops: &[ExtFieldOp],
) -> Result<(ExtFieldBatchProof, Vec<[u64; 3]>), ExtFieldChipError> {
    let (trace, pvs, outputs) = build_ext_field_trace(ops)?;
    let air = ExtFieldBatchAir::new(ops.to_vec(), outputs.clone())?;
    let proof =
        prove_chip_with_preprocessed(&air, trace, &pvs).map_err(ExtFieldChipError::Rejected)?;
    Ok((
        ExtFieldBatchProof {
            num_ops: ops.len(),
            proof,
        },
        outputs,
    ))
}

/// Verifies a batch proof produced by [`prove_ext_field_batch`] against `ops` and `claimed_outputs`.
///
/// # Errors
///
/// Refuses empty/oversized batches, shape mismatches, non-canonical limbs, or
/// any STARK verification failure.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn verify_ext_field_batch(
    ops: &[ExtFieldOp],
    claimed_outputs: &[[u64; 3]],
    batch_proof: &ExtFieldBatchProof,
) -> Result<(), ExtFieldChipError> {
    if batch_proof.num_ops != ops.len() || ops.len() != claimed_outputs.len() {
        return Err(ExtFieldChipError::ShapeMismatch);
    }
    let air = ExtFieldBatchAir::new(ops.to_vec(), claimed_outputs.to_vec())?;
    let expected_degree_bits = air.padded_rows().trailing_zeros() as usize;
    let pvs = [
        Goldilocks::new(ops.len() as u64),
        Goldilocks::new(EXT_FIELD_MODE_TAG),
    ];
    verify_chip_with_preprocessed(&air, &batch_proof.proof, expected_degree_bits, &pvs)
        .map_err(ExtFieldChipError::Rejected)
}
