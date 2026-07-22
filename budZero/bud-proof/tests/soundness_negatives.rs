use bud_isa::{Instruction, Opcode};
use bud_proof::plonky3_air::{BudAir, TRACE_WIDTH};
use bud_vm::Vm;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

fn inst(opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32) -> u64 {
    Instruction {
        opcode,
        rd,
        rs1,
        rs2,
        imm,
    }
    .encode()
}

#[test]
fn test_tampered_pc_violates_constraints() {
    let program = vec![
        inst(Opcode::Add, 1, 2, 3, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(64);
    vm.registers[2] = 10;
    vm.registers[3] = 20;
    let _receipt = vm.run_receipt(&program);

    // Let's create a main trace matrix but tamper with the PC column!
    let mut values = vec![Goldilocks::new(0); 16 * TRACE_WIDTH];
    for (i, step) in vm.trace.iter().enumerate() {
        let row_start = i * TRACE_WIDTH;
        values[row_start] = Goldilocks::new(i as u64); // clk
        values[row_start + 1] = Goldilocks::new(999); // TAMPERED PC! (instead of step.pc)
        values[row_start + 2] = Goldilocks::new(step.instruction.opcode as u64);
        values[row_start + 3] = Goldilocks::new(step.dst_idx as u64);
        values[row_start + 11 + step.instruction.opcode as usize] = Goldilocks::new(1);
        // selector
    }

    let matrix = RowMajorMatrix::new(values, TRACE_WIDTH);
    let air = BudAir {
        num_steps: vm.trace.len(),
        program,
    };

    // Evaluating constraints on tampered trace should fail/panic!
    let res = std::panic::catch_unwind(|| {
        let public_inputs = vec![Goldilocks::new(0); 48];
        p3_air::check_constraints(&air, &matrix, &public_inputs);
    });
    assert!(res.is_err());
}

// ── Negative corpus expansion (2026-07-18, ARENA3 — P0 ZK-soundness) ────────
// Same construction discipline as the original `test_tampered_pc_...` test:
// materialize a 2-row trace, mutate ONE aspect, and require `check_constraints`
// to panic (unsatisfied AIR). These pin the tamper classes the proving system
// must never accept.

fn tampered_check_fails(tamper: impl Fn(&mut [Goldilocks])) -> bool {
    let program = vec![
        inst(Opcode::Add, 1, 2, 3, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(64);
    vm.registers[2] = 10;
    vm.registers[3] = 20;
    let _receipt = vm.run_receipt(&program);

    let mut values = vec![Goldilocks::new(0); 16 * TRACE_WIDTH];
    for (i, step) in vm.trace.iter().enumerate() {
        let row_start = i * TRACE_WIDTH;
        values[row_start] = Goldilocks::new(i as u64);
        values[row_start + 1] = Goldilocks::new(u64::try_from(step.pc).unwrap());
        values[row_start + 2] = Goldilocks::new(step.instruction.opcode as u64);
        values[row_start + 3] = Goldilocks::new(step.dst_idx as u64);
        values[row_start + 11 + step.instruction.opcode as usize] = Goldilocks::new(1);
    }
    tamper(&mut values);

    let matrix = RowMajorMatrix::new(values, TRACE_WIDTH);
    let air = BudAir {
        num_steps: vm.trace.len(),
        program,
    };
    std::panic::catch_unwind(|| {
        let public_inputs = vec![Goldilocks::new(0); 48];
        p3_air::check_constraints(&air, &matrix, &public_inputs);
    })
    .is_err()
}

/// clk column tampering (time column forgery) must break transition constraints.
#[test]
fn test_tampered_clk_violates_constraints() {
    assert!(tampered_check_fails(|v| v[0] = Goldilocks::new(999)));
}

/// dst_idx column tampering (wrong destination register claim) must fail.
#[test]
fn test_tampered_dst_idx_violates_constraints() {
    assert!(tampered_check_fails(|v| v[3] = Goldilocks::new(7)));
}

/// Two opcode selectors set on the same row must be rejected.
#[test]
fn test_conflicting_opcode_selectors_violate_constraints() {
    assert!(tampered_check_fails(|v| {
        v[11 + Opcode::Sub as usize] = Goldilocks::new(1); // row 0 keeps Add selector too
    }));
}

/// Dropping the opcode selector on row 0 must be rejected.
#[test]
fn test_missing_opcode_selector_violates_constraints() {
    assert!(tampered_check_fails(
        |v| v[11 + Opcode::Add as usize] = Goldilocks::new(0)
    ));
}

/// Public-input shape abuse: wrong PI length must not be silently accepted.
#[test]
fn test_wrong_public_input_length_rejected() {
    let program = vec![
        inst(Opcode::Add, 1, 2, 3, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(64);
    vm.registers[2] = 10;
    vm.registers[3] = 20;
    let _receipt = vm.run_receipt(&program);

    let mut values = vec![Goldilocks::new(0); 16 * TRACE_WIDTH];
    for (i, step) in vm.trace.iter().enumerate() {
        let row_start = i * TRACE_WIDTH;
        values[row_start] = Goldilocks::new(i as u64);
        values[row_start + 1] = Goldilocks::new(u64::try_from(step.pc).unwrap());
        values[row_start + 2] = Goldilocks::new(step.instruction.opcode as u64);
        values[row_start + 3] = Goldilocks::new(step.dst_idx as u64);
        values[row_start + 11 + step.instruction.opcode as usize] = Goldilocks::new(1);
    }
    let matrix = RowMajorMatrix::new(values, TRACE_WIDTH);
    let air = BudAir {
        num_steps: vm.trace.len(),
        program,
    };
    let res = std::panic::catch_unwind(|| {
        let public_inputs = vec![Goldilocks::new(0); 47]; // one short
        p3_air::check_constraints(&air, &matrix, &public_inputs);
    });
    assert!(res.is_err());
}
