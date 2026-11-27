//! Acceptance and forgery-rejection tests for the cubic Goldilocks extension
//! field arithmetic STARK chip (`bud_proof::chips::ext_field`).

use bud_proof::bud_stark::SubAirBuilder;
use bud_proof::chips::ext_field::{
    build_ext_field_trace, check_single_air_constraints, eval_ext_field_row_constraints,
    eval_native_op, prove_ext_field_batch, prove_ext_field_op, verify_ext_field_batch,
    verify_ext_field_op, ExtFieldBatchAir, ExtFieldChipError, ExtFieldOp, COL_AUX_INV_BASE,
    COL_C_BASE, COL_OP_TAG, COL_SEL_ADD, COL_SEL_SUB, EXT_FIELD_MAIN_WIDTH,
};
use bud_proof::plonky3_prover::{chip_ext_to_limbs, prove_chip, verify_chip, ChipExtensionField};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_canonical_limb(&mut self) -> u64 {
        loop {
            let v = self.next_u64();
            if v < Goldilocks::ORDER_U64 {
                return v;
            }
        }
    }

    fn next_ext(&mut self) -> [u64; 3] {
        [
            self.next_canonical_limb(),
            self.next_canonical_limb(),
            self.next_canonical_limb(),
        ]
    }

    fn next_nonzero_ext(&mut self) -> [u64; 3] {
        loop {
            let v = self.next_ext();
            if v != [0, 0, 0] {
                return v;
            }
        }
    }
}

fn limbs_to_native(limbs: [u64; 3]) -> ChipExtensionField {
    let coeffs = limbs.map(Goldilocks::new);
    ChipExtensionField::new(coeffs)
}

#[test]
fn random_1000_cubic_extension_ops_agree_with_native_p3_field_and_verify() {
    let mut rng = SplitMix64(0xC0DE_5232_2026_1124);
    let mut ops = Vec::with_capacity(1_000);
    let mut expected_outputs = Vec::with_capacity(1_000);

    for i in 0..1_000usize {
        let op = match i % 5 {
            0 => {
                let a = rng.next_ext();
                let b = rng.next_ext();
                let expected = chip_ext_to_limbs(limbs_to_native(a) + limbs_to_native(b));
                expected_outputs.push(expected);
                ExtFieldOp::Add { a, b }
            }
            1 => {
                let a = rng.next_ext();
                let b = rng.next_ext();
                let expected = chip_ext_to_limbs(limbs_to_native(a) - limbs_to_native(b));
                expected_outputs.push(expected);
                ExtFieldOp::Sub { a, b }
            }
            2 => {
                let a = rng.next_ext();
                let b = rng.next_ext();
                let expected = chip_ext_to_limbs(limbs_to_native(a) * limbs_to_native(b));
                expected_outputs.push(expected);
                ExtFieldOp::Mul { a, b }
            }
            3 => {
                let a = rng.next_nonzero_ext();
                let inv = limbs_to_native(a).inverse();
                let expected = chip_ext_to_limbs(inv);
                expected_outputs.push(expected);
                ExtFieldOp::Inv { a }
            }
            _ => {
                let a = rng.next_ext();
                let b = rng.next_nonzero_ext();
                let expected = chip_ext_to_limbs(limbs_to_native(a) * limbs_to_native(b).inverse());
                expected_outputs.push(expected);
                ExtFieldOp::Div { a, b }
            }
        };
        assert_eq!(
            eval_native_op(&op).unwrap_or_else(|e| panic!("native op: {e:?}")),
            expected_outputs[i]
        );
        ops.push(op);
    }

    let (batch_proof, outputs) =
        prove_ext_field_batch(&ops).unwrap_or_else(|e| panic!("prove 1000-op batch: {e:?}"));
    assert_eq!(outputs, expected_outputs);
    verify_ext_field_batch(&ops, &outputs, &batch_proof)
        .unwrap_or_else(|e| panic!("verify 1000-op batch: {e:?}"));
}

#[test]
fn single_op_fixed_vk_and_sub_air_embedding_verify_every_opcode() {
    let a = [7, Goldilocks::ORDER_U64 - 5, 42];
    let b = [19, 3, Goldilocks::ORDER_U64 - 11];
    let cases = [
        ExtFieldOp::Add { a, b },
        ExtFieldOp::Sub { a, b },
        ExtFieldOp::Mul { a, b },
        ExtFieldOp::Inv { a },
        ExtFieldOp::Div { a, b },
    ];
    for op in cases {
        let (proof, out) =
            prove_ext_field_op(&op).unwrap_or_else(|e| panic!("prove single op: {e:?}"));
        assert_eq!(
            out,
            eval_native_op(&op).unwrap_or_else(|e| panic!("native: {e:?}"))
        );
        verify_ext_field_op(&op, out, &proof).unwrap_or_else(|e| panic!("verify single op: {e:?}"));
    }

    // Verify SubAirBuilder embedding inside a wider parent AIR with a prefix column.
    struct EmbeddedParentAir;
    impl<F> BaseAir<F> for EmbeddedParentAir {
        fn width(&self) -> usize {
            1 + EXT_FIELD_MAIN_WIDTH
        }
    }
    impl<AB: AirBuilder> Air<AB> for EmbeddedParentAir {
        fn eval(&self, builder: &mut AB) {
            let tag: AB::Expr = builder.main().current_slice()[0].into();
            builder
                .when_first_row()
                .assert_eq(tag, AB::Expr::from_u64(99));
            let mut sub =
                SubAirBuilder::<AB, bud_proof::chips::ext_field::ExtFieldSingleAir, AB::F>::new(
                    builder,
                    1..(1 + EXT_FIELD_MAIN_WIDTH),
                );
            eval_ext_field_row_constraints(&mut sub);
        }
    }

    let (inner_trace, _, _) =
        build_ext_field_trace(&[ExtFieldOp::Inv { a }]).unwrap_or_else(|e| panic!("trace: {e:?}"));
    let rows = 16;
    let width = 1 + EXT_FIELD_MAIN_WIDTH;
    let mut parent_vals = vec![Goldilocks::ZERO; rows * width];
    parent_vals[0] = Goldilocks::new(99);
    for r in 0..rows {
        for c in 0..EXT_FIELD_MAIN_WIDTH {
            parent_vals[r * width + 1 + c] = inner_trace.values[r * EXT_FIELD_MAIN_WIDTH + c];
        }
    }
    let parent_trace = RowMajorMatrix::new(parent_vals, width);
    let parent_proof = prove_chip(&EmbeddedParentAir, parent_trace, &[]);
    verify_chip(&EmbeddedParentAir, &parent_proof, &[])
        .unwrap_or_else(|e| panic!("verify embedded SubAirBuilder: {e:?}"));
}

#[test]
fn forged_inverse_witness_is_rejected_by_air_and_stark_verifier() {
    let op = ExtFieldOp::Inv { a: [3, 5, 7] };
    let (mut trace, _, outputs) =
        build_ext_field_trace(&[op]).unwrap_or_else(|e| panic!("valid trace: {e:?}"));
    let wrong = Goldilocks::new((outputs[0][0] + 1) % Goldilocks::ORDER_U64);
    trace.values[COL_C_BASE] = wrong;
    trace.values[COL_AUX_INV_BASE] = wrong;
    let single_pvs = [
        Goldilocks::new(4),
        Goldilocks::new(3),
        Goldilocks::new(5),
        Goldilocks::new(7),
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        wrong,
        Goldilocks::new(outputs[0][1]),
        Goldilocks::new(outputs[0][2]),
    ];
    assert!(check_single_air_constraints(&trace, &single_pvs).is_err());

    // Also mutate the OOD trace_local witness opening of a real STARK proof and confirm refusal.
    let (mut proof, out) = prove_ext_field_op(&op).unwrap_or_else(|e| panic!("prove: {e:?}"));
    proof.opened_values.trace_local[COL_AUX_INV_BASE] += ChipExtensionField::ONE;
    assert!(verify_ext_field_op(&op, out, &proof).is_err());
}

#[test]
fn forged_zero_inversion_row_is_rejected() {
    let valid_op = ExtFieldOp::Add {
        a: [0, 0, 0],
        b: [0, 0, 0],
    };
    let (mut trace, _, _) =
        build_ext_field_trace(&[valid_op]).unwrap_or_else(|e| panic!("trace: {e:?}"));
    trace.values[COL_SEL_ADD] = Goldilocks::ZERO;
    trace.values[COL_SEL_ADD + 3] = Goldilocks::ONE;
    trace.values[COL_OP_TAG] = Goldilocks::new(4);
    trace.values[COL_C_BASE] = Goldilocks::ONE;
    trace.values[COL_C_BASE + 1] = Goldilocks::new(2);
    trace.values[COL_C_BASE + 2] = Goldilocks::new(3);
    trace.values[COL_AUX_INV_BASE] = Goldilocks::ONE;
    trace.values[COL_AUX_INV_BASE + 1] = Goldilocks::new(2);
    trace.values[COL_AUX_INV_BASE + 2] = Goldilocks::new(3);
    let pvs = [
        Goldilocks::new(4),
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ONE,
        Goldilocks::new(2),
        Goldilocks::new(3),
    ];
    assert!(check_single_air_constraints(&trace, &pvs).is_err());
}

#[test]
fn forged_add_sub_mul_div_and_selector_rows_are_rejected() {
    // Forged Add output
    let add_op = ExtFieldOp::Add {
        a: [4, 5, 6],
        b: [7, 8, 9],
    };
    let (mut trace, _, _) =
        build_ext_field_trace(&[add_op]).unwrap_or_else(|e| panic!("trace: {e:?}"));
    trace.values[COL_C_BASE] = Goldilocks::new(999);
    let add_pvs = [
        Goldilocks::ONE,
        Goldilocks::new(4),
        Goldilocks::new(5),
        Goldilocks::new(6),
        Goldilocks::new(7),
        Goldilocks::new(8),
        Goldilocks::new(9),
        Goldilocks::new(999),
        Goldilocks::new(13),
        Goldilocks::new(15),
    ];
    assert!(check_single_air_constraints(&trace, &add_pvs).is_err());

    // Forged Sub output
    let sub_op = ExtFieldOp::Sub {
        a: [10, 10, 10],
        b: [3, 4, 5],
    };
    let (mut trace, _, _) =
        build_ext_field_trace(&[sub_op]).unwrap_or_else(|e| panic!("trace: {e:?}"));
    trace.values[COL_C_BASE + 1] = Goldilocks::new(7);
    let sub_pvs = [
        Goldilocks::new(2),
        Goldilocks::new(10),
        Goldilocks::new(10),
        Goldilocks::new(10),
        Goldilocks::new(3),
        Goldilocks::new(4),
        Goldilocks::new(5),
        Goldilocks::new(7),
        Goldilocks::new(7),
        Goldilocks::new(5),
    ];
    assert!(check_single_air_constraints(&trace, &sub_pvs).is_err());

    // Forged Mul reduction: X^2 * X = X^3 = X + 1 = [1, 1, 0]; forging [1, 0, 0] must fail.
    let mul_op = ExtFieldOp::Mul {
        a: [0, 0, 1],
        b: [0, 1, 0],
    };
    let (mut trace, _, _) =
        build_ext_field_trace(&[mul_op]).unwrap_or_else(|e| panic!("trace: {e:?}"));
    trace.values[COL_C_BASE] = Goldilocks::ONE;
    trace.values[COL_C_BASE + 1] = Goldilocks::ZERO;
    trace.values[COL_C_BASE + 2] = Goldilocks::ZERO;
    let mul_pvs = [
        Goldilocks::new(3),
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ONE,
        Goldilocks::ZERO,
        Goldilocks::ONE,
        Goldilocks::ZERO,
        Goldilocks::ONE,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
    ];
    assert!(check_single_air_constraints(&trace, &mul_pvs).is_err());

    // Forged Div auxiliary inverse even when numerator a == 0
    let div_op = ExtFieldOp::Div {
        a: [0, 0, 0],
        b: [2, 3, 5],
    };
    let (mut trace, _, _) =
        build_ext_field_trace(&[div_op]).unwrap_or_else(|e| panic!("trace: {e:?}"));
    trace.values[COL_AUX_INV_BASE] = Goldilocks::ZERO;
    trace.values[COL_AUX_INV_BASE + 1] = Goldilocks::ZERO;
    trace.values[COL_AUX_INV_BASE + 2] = Goldilocks::ZERO;
    let div_pvs = [
        Goldilocks::new(5),
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::new(2),
        Goldilocks::new(3),
        Goldilocks::new(5),
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
    ];
    assert!(check_single_air_constraints(&trace, &div_pvs).is_err());

    // Forged non-boolean selector (sel_add = 2, sel_sub = -1)
    let (mut trace, _, _) = build_ext_field_trace(&[ExtFieldOp::Add {
        a: [1, 0, 0],
        b: [2, 0, 0],
    }])
    .unwrap_or_else(|e| panic!("trace: {e:?}"));
    trace.values[COL_SEL_ADD] = Goldilocks::new(2);
    trace.values[COL_SEL_SUB] = Goldilocks::new(Goldilocks::ORDER_U64 - 1);
    let bool_pvs = [
        Goldilocks::ZERO,
        Goldilocks::ONE,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::new(2),
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::new(3),
        Goldilocks::ZERO,
        Goldilocks::ZERO,
    ];
    assert!(check_single_air_constraints(&trace, &bool_pvs).is_err());
}

#[test]
fn stark_verifier_rejects_tampered_statement_and_invalid_inputs() {
    assert_eq!(
        prove_ext_field_batch(&[]).err(),
        Some(ExtFieldChipError::Empty)
    );
    assert_eq!(
        prove_ext_field_op(&ExtFieldOp::Inv { a: [0, 0, 0] }).err(),
        Some(ExtFieldChipError::DivisionByZero)
    );
    assert_eq!(
        prove_ext_field_op(&ExtFieldOp::Div {
            a: [1, 2, 3],
            b: [0, 0, 0]
        })
        .err(),
        Some(ExtFieldChipError::DivisionByZero)
    );
    assert_eq!(
        prove_ext_field_op(&ExtFieldOp::Add {
            a: [Goldilocks::ORDER_U64, 0, 0],
            b: [1, 0, 0]
        })
        .err(),
        Some(ExtFieldChipError::NonCanonicalLimb(Goldilocks::ORDER_U64))
    );

    let op = ExtFieldOp::Inv { a: [11, 22, 33] };
    let (proof, out) = prove_ext_field_op(&op).unwrap_or_else(|e| panic!("prove: {e:?}"));
    let mut wrong_out = out;
    wrong_out[2] = (wrong_out[2] + 1) % Goldilocks::ORDER_U64;
    assert!(verify_ext_field_op(&op, wrong_out, &proof).is_err());

    let add_op = ExtFieldOp::Add {
        a: [5, 0, 0],
        b: [3, 0, 0],
    };
    let (add_proof, add_out) =
        prove_ext_field_op(&add_op).unwrap_or_else(|e| panic!("prove add: {e:?}"));
    let swapped_op = ExtFieldOp::Sub {
        a: [5, 0, 0],
        b: [3, 0, 0],
    };
    assert!(verify_ext_field_op(&swapped_op, add_out, &add_proof).is_err());

    let batch_ops = vec![
        ExtFieldOp::Mul {
            a: [2, 3, 4],
            b: [5, 6, 7],
        },
        ExtFieldOp::Inv { a: [9, 8, 7] },
    ];
    let (batch_proof, batch_out) =
        prove_ext_field_batch(&batch_ops).unwrap_or_else(|e| panic!("prove batch: {e:?}"));
    let mut forged_batch_out = batch_out.clone();
    forged_batch_out[1][0] ^= 1;
    assert!(verify_ext_field_batch(&batch_ops, &forged_batch_out, &batch_proof).is_err());

    let dummy_air =
        ExtFieldBatchAir::new(batch_ops, batch_out).unwrap_or_else(|e| panic!("air: {e:?}"));
    assert_eq!(
        <ExtFieldBatchAir as BaseAir<Goldilocks>>::width(&dummy_air),
        EXT_FIELD_MAIN_WIDTH
    );
}
