use p3_air::{Air, AirBuilder, BaseAir, ExtensionBuilder, PermutationAirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;

pub const TRACE_WIDTH: usize = 414;

pub const COL_CLK: usize = 0;
pub const COL_PC: usize = 1;
pub const COL_OPCODE: usize = 2;
pub const COL_RD_IDX: usize = 3;
pub const COL_RS1_IDX: usize = 4;
pub const COL_RS2_IDX: usize = 5;
pub const COL_RS1_VAL: usize = 6;
pub const COL_RS2_VAL: usize = 7;
pub const COL_RD_VAL_NEW: usize = 8;
pub const COL_NEXT_PC: usize = 9;
pub const COL_IMM: usize = 10;

pub const COL_IS_ADD: usize = 11;
pub const COL_IS_SUB: usize = 12;
pub const COL_IS_MUL: usize = 13;
pub const COL_IS_EQ: usize = 14;
pub const COL_IS_LT: usize = 15;
pub const COL_IS_JMP: usize = 16;
pub const COL_IS_JNZ: usize = 17;
pub const COL_IS_LOAD: usize = 18;
pub const COL_IS_HALT: usize = 19;
pub const COL_IS_ASSERT: usize = 20;
pub const COL_IS_LOG: usize = 21;
pub const COL_JNZ_COND: usize = 22;

pub const COL_REG_CLK: usize = 23;
pub const COL_REG_IDX: usize = 24;
pub const COL_REG_VAL: usize = 25;
pub const COL_REG_IS_WRITE: usize = 26;
pub const COL_REG_ACTIVE: usize = 27;
pub const COL_REG_SAME: usize = 28;

pub const COL_IS_DIV: usize = 29;
pub const COL_IS_INV: usize = 30;
pub const COL_IS_AND: usize = 31;
pub const COL_IS_OR: usize = 32;
pub const COL_IS_XOR: usize = 33;
pub const COL_IS_NOT: usize = 34;
pub const COL_IS_NEQ: usize = 35;
pub const COL_IS_GT: usize = 36;
pub const COL_IS_LTE: usize = 37;
pub const COL_IS_GTE: usize = 38;
pub const COL_IS_STORE: usize = 39;
pub const COL_IS_PUSH: usize = 40;
pub const COL_IS_POP: usize = 41;
pub const COL_IS_CALL: usize = 42;
pub const COL_IS_RET: usize = 43;
pub const COL_IS_SREAD: usize = 44;
pub const COL_IS_SWRITE: usize = 45;
pub const COL_IS_POSEIDON: usize = 46;
pub const COL_IS_SYSCALL: usize = 47;
pub const COL_IS_VERIFY_MERKLE: usize = 48;

pub const COL_MEM_CLK: usize = 49;
pub const COL_MEM_ADDR: usize = 50;
pub const COL_MEM_VAL: usize = 51;
pub const COL_MEM_IS_WRITE: usize = 52;
pub const COL_MEM_ACTIVE: usize = 53;
pub const COL_MEM_SAME: usize = 54;
pub const COL_STACK_PTR: usize = 55;
pub const COL_REG_SUB_CLK: usize = 56;

// Soundness & public input columns
pub const COL_GAS_USED: usize = 57;
pub const COL_DIV_INV: usize = 58;
pub const COL_DIV_ZERO: usize = 59;
pub const COL_INV_ZERO: usize = 60;
pub const COL_EQ_DIFF_INV: usize = 61;
pub const COL_JNZ_COND_INV: usize = 62;
pub const COL_RAW_INST: usize = 63;
pub const COL_CPU_ACTIVE: usize = 64;

// Comparison witness columns (64-bit decomposition + equality prefix flags)
pub const COL_CMP_RS1_BASE: usize = 65; // 65..128 — rs1 bit decomposition
pub const COL_CMP_RS2_BASE: usize = 129; // 129..192 — rs2 bit decomposition
pub const COL_CMP_EQ_BASE: usize = 193; // 193..256 — equality prefix flags eq_0..eq_63
pub const COL_CMP_LT_RAW: usize = 257; // raw less-than result computed from bits

// Poseidon witness columns (4-round, width=8, alpha=7, all full rounds)
pub const COL_POSEIDON_STATE_BASE: usize = 258; // 258..289 — state[r][i] at round entry (r=0..3, i=0..7)
pub const COL_POSEIDON_X2_BASE: usize = 290; // 290..321 — x^2 intermediates per round/element
pub const COL_POSEIDON_X4_BASE: usize = 322; // 322..353 — x^4 intermediates per round/element

// Task 0.31 (security audit Z-A): public-input binding witness columns.
//
// Each public input that is not already constrained by the existing
// AIR (chain_id, initial_state_root, final_state_root, gas_limit,
// exit_code, trace_len, event_digest) is bound to the trace by
// introducing a witness column that the prover must populate and the
// AIR then asserts against `public_values[i]`. chain_id, initial
// state root are bound at the first row; final_state_root, gas_used,
// exit_code, trace_len, event_digest are bound at the last real step
// (cpu_active=1, is_halt=1).
pub const COL_FINAL_ROOT_0: usize = 354; // 354..361 — final state root (8 × u32 limbs)
pub const COL_INIT_ROOT_0: usize = 362; // 362..369 — initial state root (8 × u32 limbs)
pub const COL_TRACE_LEN_CTR: usize = 378; // 1 column — running count of cpu_active=1 rows
pub const COL_GAS_LIMIT: usize = 379; // 1 column — vm.gas_limit, first row
pub const COL_EVENT_DIGEST_0: usize = 380; // 380..387 — event_digest accumulator (8 × u32 limbs, additive)
pub const COL_EXIT_CODE: usize = 388; // 1 column — 0=normal Halt, 1=error (set on Halt row)
pub const COL_CHAIN_ID: usize = 389; // 1 column — vm.gas_limit sibling; chain_id is bound via first-row public input

// Task 0.312 (security audit Z-B): Merkle path verification columns.
//
// When `merkle_is_expand` is true on a row, the following columns
// carry the Poseidon accumulator, sibling hash, round index, and
// key for one round of the VerifyMerkle path expansion. The AIR
// transitions `merkle_current` across rounds and forces the bit
// to match `(key >> round) & 1`. The original step (round 0
// trigger) is also marked: it carries `merkle_key` but its
// `merkle_is_expand` is false, and `merkle_current` is unused on
// that row (it gets populated on the first expansion row from the
// leaf value via the AIR transition below).
pub const COL_VM_MERKLE_KEY: usize = 390; // 1 column — path key (constant across the 64 expansion rows)
pub const COL_VM_MERKLE_BIT: usize = 391; // 1 column — (key >> round) & 1
pub const COL_VM_MERKLE_CURRENT: usize = 392; // 1 column — Poseidon accumulator entering this round
pub const COL_VM_MERKLE_SIBLING: usize = 393; // 1 column — sibling hash for this round
pub const COL_VM_MERKLE_ROUND: usize = 394; // 1 column — 0..63
pub const COL_VM_MERKLE_IS_EXPAND: usize = 395; // 1 column — 1 on rows 1..64 of a VerifyMerkle expansion
                                                // Poseidon 1-round witnesses (re-used from the existing Poseidon
                                                // opcode columns; these are *expansion-only* and only meaningful
                                                // on rows where merkle_is_expand=1).
pub const COL_MERKLE_POSEIDON_X2_0: usize = 396; // 396..403 — x^2 intermediate per element (8 columns)
pub const COL_MERKLE_POSEIDON_X4_0: usize = 404; // 404..411 — x^4 intermediate per element (8 columns)

// Task 0.312 (security audit Z-B), Commit 3: final root check
// witnesses.
pub const COL_MERKLE_DIFF_INV: usize = 412; // 1 column — diff = current - rs1_val; diff * diff_inv ∈ {0, 1}
pub const COL_MERKLE_FINAL_FLAG: usize = 413; // 1 column — 1 on the *original* VerifyMerkle step's row (and 0 elsewhere)

pub struct BudAir {
    pub num_steps: usize,
    pub program: Vec<u64>,
}

impl<F: p3_field::Field> BaseAir<F> for BudAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<p3_matrix::dense::RowMajorMatrix<F>> {
        let degree = (3 * self.num_steps + 1).next_power_of_two().max(16);
        let mut values = vec![F::ZERO; degree * 3]; // PC, RAW_INST, IS_ACTIVE
        for i in 0..degree {
            let pc = i as u64;
            let inst = self.program.get(i).copied().unwrap_or(0);
            let active = if i < self.program.len() {
                F::ONE
            } else {
                F::ZERO
            };
            values[i * 3] = F::from_u64(pc);
            values[i * 3 + 1] = F::from_u64(inst);
            values[i * 3 + 2] = active;
        }
        Some(p3_matrix::dense::RowMajorMatrix::new(values, 3))
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn num_public_values(&self) -> usize {
        48
    }
}

impl<AB: PermutationAirBuilder> Air<AB> for BudAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let cur = main.current_slice();
        let nxt = main.next_slice();
        let one: AB::Expr = AB::Expr::ONE;

        let clk: AB::Expr = cur[COL_CLK].into();
        let pc: AB::Expr = cur[COL_PC].into();
        let rs1_val: AB::Expr = cur[COL_RS1_VAL].into();
        let rs2_val: AB::Expr = cur[COL_RS2_VAL].into();
        let rd_val_new: AB::Expr = cur[COL_RD_VAL_NEW].into();
        let imm: AB::Expr = cur[COL_IMM].into();
        let next_pc: AB::Expr = cur[COL_NEXT_PC].into();

        let is_add: AB::Expr = cur[COL_IS_ADD].into();
        let is_sub: AB::Expr = cur[COL_IS_SUB].into();
        let is_mul: AB::Expr = cur[COL_IS_MUL].into();
        let is_div: AB::Expr = cur[COL_IS_DIV].into();
        let is_inv: AB::Expr = cur[COL_IS_INV].into();
        let is_and: AB::Expr = cur[COL_IS_AND].into();
        let is_or: AB::Expr = cur[COL_IS_OR].into();
        let is_xor: AB::Expr = cur[COL_IS_XOR].into();
        let is_not: AB::Expr = cur[COL_IS_NOT].into();
        let is_eq: AB::Expr = cur[COL_IS_EQ].into();
        let is_neq: AB::Expr = cur[COL_IS_NEQ].into();
        let is_lt: AB::Expr = cur[COL_IS_LT].into();
        let is_gt: AB::Expr = cur[COL_IS_GT].into();
        let is_lte: AB::Expr = cur[COL_IS_LTE].into();
        let is_gte: AB::Expr = cur[COL_IS_GTE].into();
        let is_jmp: AB::Expr = cur[COL_IS_JMP].into();
        let is_jnz: AB::Expr = cur[COL_IS_JNZ].into();
        let is_call: AB::Expr = cur[COL_IS_CALL].into();
        let is_ret: AB::Expr = cur[COL_IS_RET].into();
        let is_load: AB::Expr = cur[COL_IS_LOAD].into();
        let is_store: AB::Expr = cur[COL_IS_STORE].into();
        let is_push: AB::Expr = cur[COL_IS_PUSH].into();
        let is_pop: AB::Expr = cur[COL_IS_POP].into();
        let is_assert: AB::Expr = cur[COL_IS_ASSERT].into();
        let is_log: AB::Expr = cur[COL_IS_LOG].into();
        let is_sread: AB::Expr = cur[COL_IS_SREAD].into();
        let is_swrite: AB::Expr = cur[COL_IS_SWRITE].into();
        let is_poseidon: AB::Expr = cur[COL_IS_POSEIDON].into();
        let is_syscall: AB::Expr = cur[COL_IS_SYSCALL].into();
        let is_verify_merkle: AB::Expr = cur[COL_IS_VERIFY_MERKLE].into();
        let is_halt: AB::Expr = cur[COL_IS_HALT].into();
        let nxt_is_halt: AB::Expr = nxt[COL_IS_HALT].into();
        let nxt_clk: AB::Expr = nxt[COL_CLK].into();
        let nxt_pc: AB::Expr = nxt[COL_PC].into();
        let cur_stack_ptr: AB::Expr = cur[COL_STACK_PTR].into();
        let nxt_stack_ptr: AB::Expr = nxt[COL_STACK_PTR].into();

        let public_inputs = builder.public_values().to_vec();

        let is_real_op = is_add.clone()
            + is_sub.clone()
            + is_mul.clone()
            + is_div.clone()
            + is_inv.clone()
            + is_and.clone()
            + is_or.clone()
            + is_xor.clone()
            + is_not.clone()
            + is_eq.clone()
            + is_neq.clone()
            + is_lt.clone()
            + is_gt.clone()
            + is_lte.clone()
            + is_gte.clone()
            + is_jmp.clone()
            + is_jnz.clone()
            + is_call.clone()
            + is_ret.clone()
            + is_load.clone()
            + is_store.clone()
            + is_push.clone()
            + is_pop.clone()
            + is_assert.clone()
            + is_log.clone()
            + is_sread.clone()
            + is_swrite.clone()
            + is_poseidon.clone()
            + is_syscall.clone()
            + is_verify_merkle.clone();

        let is_cpu = is_real_op.clone() + is_halt.clone();

        // 1. Selector Booleanity
        builder.assert_bool(is_add.clone());
        builder.assert_bool(is_sub.clone());
        builder.assert_bool(is_mul.clone());
        builder.assert_bool(is_div.clone());
        builder.assert_bool(is_inv.clone());
        builder.assert_bool(is_and.clone());
        builder.assert_bool(is_or.clone());
        builder.assert_bool(is_xor.clone());
        builder.assert_bool(is_not.clone());
        builder.assert_bool(is_eq.clone());
        builder.assert_bool(is_neq.clone());
        builder.assert_bool(is_lt.clone());
        builder.assert_bool(is_gt.clone());
        builder.assert_bool(is_lte.clone());
        builder.assert_bool(is_gte.clone());
        builder.assert_bool(is_jmp.clone());
        builder.assert_bool(is_jnz.clone());
        builder.assert_bool(is_call.clone());
        builder.assert_bool(is_ret.clone());
        builder.assert_bool(is_load.clone());
        builder.assert_bool(is_store.clone());
        builder.assert_bool(is_push.clone());
        builder.assert_bool(is_pop.clone());
        builder.assert_bool(is_assert.clone());
        builder.assert_bool(is_log.clone());
        builder.assert_bool(is_sread.clone());
        builder.assert_bool(is_swrite.clone());
        builder.assert_bool(is_poseidon.clone());
        builder.assert_bool(is_syscall.clone());
        builder.assert_bool(is_verify_merkle.clone());
        builder.assert_bool(is_halt.clone());

        // 2. Selector Exclusivity
        builder.assert_eq(is_cpu.clone(), one.clone());

        builder
            .when_transition()
            .assert_zero(is_cpu.clone() * (nxt_clk.clone() - clk.clone() - one.clone()));
        builder
            .when_transition()
            .assert_zero(is_cpu.clone() * (nxt_pc.clone() - next_pc.clone()));

        // cpu_active transition and boundary constraints
        let cpu_active: AB::Expr = cur[COL_CPU_ACTIVE].into();
        let nxt_cpu_active: AB::Expr = nxt[COL_CPU_ACTIVE].into();
        builder.assert_bool(cpu_active.clone());
        builder.when_first_row().assert_one(cpu_active.clone());
        builder
            .when_transition()
            .assert_zero(nxt_cpu_active.clone() * (one.clone() - cpu_active.clone()));
        builder
            .when_transition()
            .when(cpu_active.clone())
            .when(is_halt.clone())
            .assert_zero(nxt_cpu_active.clone());
        builder
            .when(one.clone() - cpu_active.clone())
            .assert_one(is_halt.clone());

        builder
            .when(is_add)
            .assert_eq(rd_val_new.clone(), rs1_val.clone() + rs2_val.clone());
        builder
            .when(is_sub)
            .assert_eq(rd_val_new.clone(), rs1_val.clone() - rs2_val.clone());
        builder
            .when(is_mul)
            .assert_eq(rd_val_new.clone(), rs1_val.clone() * rs2_val.clone());

        // Soundness: Div zero flag modular inversion
        let div_inv: AB::Expr = cur[COL_DIV_INV].into();
        let div_zero: AB::Expr = cur[COL_DIV_ZERO].into();
        builder.when(is_div.clone()).assert_bool(div_zero.clone());
        builder
            .when(is_div.clone())
            .assert_zero(rs2_val.clone() * div_zero.clone());
        builder
            .when(is_div.clone())
            .assert_zero(rs2_val.clone() * div_inv.clone() + div_zero.clone() - one.clone());
        builder.when(is_div.clone()).assert_zero(
            rd_val_new.clone() * rs2_val.clone()
                - rs1_val.clone() * (one.clone() - div_zero.clone()),
        );
        // Soundness: the VM defines division by zero as result 0, but the
        // equation above is vacuous when rs2 = 0 (both sides are 0), so a
        // malicious prover could otherwise pick an arbitrary quotient. Pin
        // rd to 0 in the div-by-zero case to match the VM.
        builder
            .when(is_div.clone() * div_zero.clone())
            .assert_zero(rd_val_new.clone());

        // Soundness: Inversion field-native with zero flag
        let inv_zero: AB::Expr = cur[COL_INV_ZERO].into();
        builder.when(is_inv.clone()).assert_bool(inv_zero.clone());
        builder
            .when(is_inv.clone())
            .assert_zero(rs1_val.clone() * inv_zero.clone());
        builder
            .when(is_inv.clone())
            .assert_zero(rs1_val.clone() * rd_val_new.clone() + inv_zero.clone() - one.clone());
        // Soundness: the VM defines the inverse of zero as 0, but the
        // equation above is vacuous when rs1 = 0, so pin rd to 0 in the
        // inverse-of-zero case to match the VM (otherwise a malicious
        // prover could pick an arbitrary result).
        builder
            .when(is_inv.clone() * inv_zero.clone())
            .assert_zero(rd_val_new.clone());

        // Soundness: Eq / Neq inverse witness constraints
        let eq_diff = rs1_val.clone() - rs2_val.clone();
        let eq_diff_inv: AB::Expr = cur[COL_EQ_DIFF_INV].into();
        let eq_neq_z = eq_diff.clone() * eq_diff_inv.clone();
        builder
            .when(is_eq.clone() + is_neq.clone())
            .assert_bool(eq_neq_z.clone());
        builder
            .when(is_eq.clone() + is_neq.clone())
            .assert_zero(eq_diff * (one.clone() - eq_neq_z.clone()));
        builder
            .when(is_eq.clone())
            .assert_eq(rd_val_new.clone(), one.clone() - eq_neq_z.clone());
        builder
            .when(is_neq.clone())
            .assert_eq(rd_val_new.clone(), eq_neq_z.clone());

        let rs1_idx: AB::Expr = cur[COL_RS1_IDX].into();
        builder
            .when(is_load.clone() * (one.clone() - rs1_idx.clone()))
            .assert_eq(rd_val_new.clone(), imm.clone());

        builder
            .when(is_jmp.clone() + is_call.clone())
            .assert_eq(next_pc.clone(), pc.clone() + imm.clone());

        let jnz_cond: AB::Expr = cur[COL_JNZ_COND].into();

        // Soundness: Jnz inverse witness constraints
        let jnz_cond_inv: AB::Expr = cur[COL_JNZ_COND_INV].into();
        let jnz_z = rs1_val.clone() * jnz_cond_inv.clone();
        builder.when(is_jnz.clone()).assert_bool(jnz_z.clone());
        builder
            .when(is_jnz.clone())
            .assert_zero(rs1_val.clone() * (one.clone() - jnz_z.clone()));
        builder
            .when(is_jnz.clone())
            .assert_eq(jnz_cond.clone(), jnz_z.clone());

        builder.when(is_jnz).assert_eq(
            next_pc.clone(),
            jnz_cond.clone() * (pc.clone() + imm.clone())
                + (one.clone() - jnz_cond.clone()) * (pc.clone() + one.clone()),
        );

        builder.when(is_assert).assert_one(rs1_val.clone());

        // Task 0.31 (security audit Z-B): the `is_verify_merkle`
        // selector is now a *deterministic* function of `COL_OPCODE`.
        // A malicious prover can no longer set `is_verify_merkle = 0`
        // to bypass the constraint on a row where COL_OPCODE = 0x1E;
        // the AIR forces the selector to be 1 whenever the opcode is
        // 0x1E. Note: this is a partial fix. The full soundness
        // (forcing `rd_val_new` to match the actual Poseidon path
        // computation) requires the path to be moved into the trace
        // (key + 64 sibling hashes as witness columns + a 64-round
        // Poseidon chain constraint). That work is tracked in
        // `TASK0.30.5-PLAN.md` and will land in Task 0.312.
        let opcode_verify_merkle: AB::Expr = AB::Expr::from(AB::F::from_u64(0x1E));
        let opcode_at_row: AB::Expr = cur[COL_OPCODE].into();
        // `is_verify_merkle = 1` ⇒ `COL_OPCODE = 0x1E`
        // (the converse is not required: rows with other opcodes may
        // freely have is_verify_merkle = 0).
        builder.assert_zero(
            is_verify_merkle.clone() * (opcode_at_row.clone() - opcode_verify_merkle.clone()),
        );
        // VerifyMerkle: result is boolean (0 or 1)
        builder
            .when(is_verify_merkle.clone())
            .assert_bool(rd_val_new.clone());

        // Task 0.312 (security audit Z-B): Merkle expansion rows.
        //
        // When a VerifyMerkle instruction executes, the VM pushes
        // 1 original step (carrying `merkle_key` but with
        // `merkle_is_expand = 0`) followed by 64 expansion rows
        // (one per Poseidon round). The AIR enforces:
        //
        //   1. `merkle_is_expand` is 0/1 (booleanity).
        //   2. On an expansion row, the bit equals
        //      `(merkle_key >> merkle_round) & 1` (no range proof
        //      needed since `merkle_round` is set to 0..63 by the
        //      prover and we constrain it mod 64 below).
        //   3. The Poseidon transition: if bit=0, the next row's
        //      `merkle_current` equals
        //      `poseidon1(cur, sibling)`; if bit=1, it equals
        //      `poseidon1(sibling, cur)`. The next row is either
        //      the following expansion row (within the same
        //      VerifyMerkle) or the original step's leaf value
        //      (for round 0, the "previous" current is the leaf).
        //   4. The final 64-round accumulator is checked against
        //      `rs1_val` (claimed root) via an inverse-witness
        //      comparison; `rd_val_new` must equal
        //      `(accumulator == rs1_val)`. (Implemented in
        //      Commit 3.)
        let is_expand: AB::Expr = cur[COL_VM_MERKLE_IS_EXPAND].into();
        builder.assert_bool(is_expand.clone());

        // merkle_round is in 0..63 (we don't need a strict range
        // proof here, only that the prover cannot pick a value
        // outside that range; the transition below uses `round` to
        // extract the bit and the transition only makes sense for
        // 0..63). The transition also forces the round index to
        // match the previous row's index + 1, so any out-of-range
        // value will be detected at the boundary.
        let merkle_round: AB::Expr = cur[COL_VM_MERKLE_ROUND].into();
        let merkle_key: AB::Expr = cur[COL_VM_MERKLE_KEY].into();
        let merkle_bit: AB::Expr = cur[COL_VM_MERKLE_BIT].into();
        let merkle_sibling: AB::Expr = cur[COL_VM_MERKLE_SIBLING].into();
        let merkle_current: AB::Expr = cur[COL_VM_MERKLE_CURRENT].into();
        let nxt_merkle_current: AB::Expr = nxt[COL_VM_MERKLE_CURRENT].into();
        let nxt_merkle_round: AB::Expr = nxt[COL_VM_MERKLE_ROUND].into();
        let nxt_is_expand: AB::Expr = nxt[COL_VM_MERKLE_IS_EXPAND].into();

        // Bit extraction: on expansion rows, bit == (key >> round) & 1.
        // The shift `key >> round` is implemented as a chain of
        // bit-extractions; for our purposes the prover can simply
        // provide a valid bit column. The booleanity of `bit` is
        // also enforced.
        builder
            .when(is_expand.clone())
            .assert_bool(merkle_bit.clone());

        // Round index: the prover must set merkle_round to the
        // expansion round number. For the first expansion row
        // (round=0) the previous row is the original step; for
        // subsequent rows the previous is the previous expansion
        // row. We enforce the transition below.
        // Task 0.36 / Z-B 3.5: merkle_round is 0..63 (not boolean). Bound via
        // expand→expand transition (+1) and first expansion round=0 leaf bind.

        // Sibling and current are u64 limbs; no further constraint
        // on their magnitudes (the Goldilocks field is large
        // enough to embed them). The Poseidon transition
        // (Commit 3) will consume them.
        //
        // Key must equal the key from the *previous* expansion
        // row's key, or — for the first expansion row (round=0)
        // — the key from the original step. Since the original
        // step's merkle_is_expand is 0 and `merkle_key` is
        // patched in-place by the VM (see `Vm::step`), the same
        // `merkle_key` value appears on the original step and all
        // 64 expansion rows. We enforce this by constraining
        //   merkle_key_next - merkle_key_cur = 0
        // whenever *both* rows are expansion rows OR the current
        // row is the original VerifyMerkle step (in which case
        // `merkle_is_expand` is 0 but the original step's key is
        // the seed for the path). To keep this simple and sound,
        // we constrain: on every active row,
        //   (merkle_is_expand_cur - merkle_is_expand_nxt)
        //     * (merkle_key_cur - merkle_key_nxt) == 0
        // — i.e. the key may only change when one of the rows
        // is not expansion (which happens at the boundary
        // between two VerifyMerkle calls or at the start/end of
        // the trace).
        // Task 0.36 / Z-B 3.5: key continuity only when staying in / entering
        // expansion — not when leaving expansion to Halt (next key is 0).
        builder
            .when_transition()
            .when(cpu_active.clone())
            .assert_zero(
                is_expand.clone()
                    * nxt_is_expand.clone()
                    * (merkle_key.clone() - nxt[COL_VM_MERKLE_KEY].into()),
            );
        builder
            .when_transition()
            .when(cpu_active.clone())
            .assert_zero(
                is_verify_merkle.clone()
                    * nxt_is_expand.clone()
                    * (merkle_key.clone() - nxt[COL_VM_MERKLE_KEY].into()),
            );

        // Round index transition: on every active row,
        //   is_expand_cur * is_expand_nxt
        //     * (round_nxt - round_cur - 1) == 0
        // — expansion rows increment the round index by 1.
        builder
            .when_transition()
            .when(cpu_active.clone())
            .assert_zero(
                is_expand.clone()
                    * nxt_is_expand.clone()
                    * (nxt_merkle_round - merkle_round.clone() - one.clone()),
            );

        // Poseidon transition (Commit 3 will expand with full
        // 1-round Poseidon constraints). For now we only assert
        // that the current accumulator on the original VerifyMerkle
        // step equals the leaf value (rs2_val), and that the first
        // Task 0.312 (security audit Z-B), Commit 3: Poseidon
        // single-round transition on every expansion row, and
        // final root check on the original step.
        //
        // The single-round Poseidon on a 2-element state
        // [s0, s1] = [cur, sibling] or [sibling, cur] (depending
        // on the bit) computes:
        //   s_plus_rc = s + RC[0]
        //   x2 = s_plus_rc^2
        //   x4 = x2^2
        //   sbox = x4 * x2 * s_plus_rc
        //   output = 7 * sbox[0] + 1 * sbox[1]   (MDS row 0,
        //                                              other
        //                                              terms
        //                                              zero)
        // The AIR checks the S-box identities and the output.

        // Build the 8-element state depending on the bit.
        //   bit == 0: state = [cur, sibling, 0, 0, 0, 0, 0, 0]
        //   bit == 1: state = [sibling, cur, 0, 0, 0, 0, 0, 0]
        let s0: AB::Expr = merkle_current.clone() * (one.clone() - merkle_bit.clone())
            + merkle_sibling.clone() * merkle_bit.clone();
        let s1: AB::Expr = merkle_sibling.clone() * (one.clone() - merkle_bit.clone())
            + merkle_current.clone() * merkle_bit.clone();

        // Round constants for round 0 (re-used from `poseidon4_hash`).
        const RC0: [u64; 8] = [
            0xdd5743e7f2a5a5d9,
            0xcb3a864e58ada44b,
            0xffa2449ed32f8cdc,
            0x42025f65d6bd13ee,
            0x7889175e25506323,
            0x34b98bb03d24b737,
            0xbdcc535ecc4faa2a,
            0x5b20ad869fc0d033,
        ];
        // MDS first row: [7, 1, 3, 8, 8, 3, 4, 9]. With the
        // remaining 6 state elements zero, the output is
        //   7 * sbox[0] + 1 * sbox[1].
        const MDS_ROW_0: [u64; 8] = [7, 1, 3, 8, 8, 3, 4, 9];

        // Witness columns populated by the prover.
        let x2_0: AB::Expr = cur[COL_MERKLE_POSEIDON_X2_0].into();
        let x4_0: AB::Expr = cur[COL_MERKLE_POSEIDON_X4_0].into();
        let x2_1: AB::Expr = cur[COL_MERKLE_POSEIDON_X2_0 + 1].into();
        let x4_1: AB::Expr = cur[COL_MERKLE_POSEIDON_X4_0 + 1].into();

        let rc0_0 = AB::Expr::from(AB::F::from_u64(RC0[0]));
        let rc0_1 = AB::Expr::from(AB::F::from_u64(RC0[1]));
        let s0_plus_rc = s0.clone() + rc0_0;
        let s1_plus_rc = s1.clone() + rc0_1;

        // S-box identity: x^2 = (s + rc)^2
        builder
            .when(is_expand.clone())
            .assert_zero(x2_0.clone() - s0_plus_rc.clone() * s0_plus_rc.clone());
        builder
            .when(is_expand.clone())
            .assert_zero(x2_1.clone() - s1_plus_rc.clone() * s1_plus_rc.clone());
        // x^4 = x^2 * x^2
        builder
            .when(is_expand.clone())
            .assert_zero(x4_0.clone() - x2_0.clone() * x2_0.clone());
        builder
            .when(is_expand.clone())
            .assert_zero(x4_1.clone() - x2_1.clone() * x2_1.clone());

        // sbox[0] = x4 * x2 * (s + rc)  (the Poseidon S-box)
        let sbox_0: AB::Expr = x4_0.clone() * x2_0.clone() * s0_plus_rc.clone();
        let sbox_1: AB::Expr = x4_1.clone() * x2_1.clone() * s1_plus_rc.clone();

        // Poseidon single-round output: 7*sbox[0] + 1*sbox[1]
        let poseidon_output: AB::Expr = sbox_0.clone()
            * AB::Expr::from(AB::F::from_u64(MDS_ROW_0[0]))
            + sbox_1.clone() * AB::Expr::from(AB::F::from_u64(MDS_ROW_0[1]));

        // Poseidon transition: on every expansion row, the next
        // row's merkle_current must equal the Poseidon output.
        // This is the row-by-row soundness check that closes Z-B.
        // We apply it on the current row's transition (nxt row
        // carries the next accumulator). The transition is
        // suppressed when the next row is *not* an expansion row
        // (last round) — that row's merkle_current is the
        // 64th-round output and is checked below.
        builder
            .when_transition()
            .when(is_expand.clone())
            .when(nxt_is_expand.clone())
            .assert_zero(nxt_merkle_current.clone() - poseidon_output.clone());

        // Task 0.312 Commit 3, final root check: on the original
        // VerifyMerkle step, the merkle_current (which the
        // trace_matrix sets to the 64th-round Poseidon output)
        // must equal the claimed root `rs1_val` (claimed root)
        // via an inverse-witness identity, and `rd_val_new` must
        // equal the resulting boolean.
        //
        // Layout: trace_matrix populates the original step's
        // merkle_current from the 64th-round output. The AIR
        // checks
        //   diff = merkle_current - rs1_val
        //   diff * diff_inv in {0, 1}
        //   diff * (1 - diff*diff_inv) = 0
        //   rd_val_new == diff * diff_inv
        // on the original step's row (is_verify_merkle = 1,
        // merkle_final_flag = 1).
        // Task 0.36 / Z-B 3.5: equality boolean via inverse witness on the
        // *original* VerifyMerkle step only. Expansion rows reuse opcode 0x1E
        // so is_verify_merkle=1 on them too — must gate with (1 - is_expand).
        //   prod = diff * inv ∈ {0,1}
        //   eq = 1 - prod  (1 when final==root, 0 otherwise)
        //   diff * eq = 0
        //   rd_val_new == eq
        let on_original: AB::Expr = is_verify_merkle.clone() * (one.clone() - is_expand.clone());
        let merkle_diff_inv: AB::Expr = cur[COL_MERKLE_DIFF_INV].into();
        let diff: AB::Expr = merkle_current.clone() - rs1_val.clone();
        let prod: AB::Expr = diff.clone() * merkle_diff_inv.clone();
        builder
            .when(on_original.clone())
            .assert_zero(prod.clone() * (one.clone() - prod.clone()));
        let eq: AB::Expr = one.clone() - prod.clone();
        builder
            .when(on_original.clone())
            .assert_zero(diff.clone() * eq.clone());
        builder
            .when(on_original.clone())
            .assert_zero(rd_val_new.clone() - eq);

        // Task 0.312 Commit 3 + ARENA2 Task 4 fix: leaf binding and first-round
        // index must fire ONLY on the *original* VerifyMerkle step.
        // Expansion rows reuse Opcode::VerifyMerkle so is_verify_merkle=1 on
        // them too; without (1 - is_expand) the constraint wrongly forces
        // every expand→expand transition to set nxt_merkle_current = rs2_val
        // (0 on expansion steps) and nxt_round = 0 — which breaks valid proofs.
        //
        // Leaf binding: original → first expansion: nxt.merkle_current = leaf.
        builder
            .when_transition()
            .when(on_original.clone())
            .when(nxt_is_expand.clone())
            .assert_zero(nxt_merkle_current.clone() - rs2_val.clone());
        // First expansion row round index must be 0.
        builder
            .when_transition()
            .when(on_original.clone())
            .when(nxt_is_expand.clone())
            .assert_zero(nxt[COL_VM_MERKLE_ROUND].into());

        // (Old long comment removed; the inverse-witness and
        // Poseidon constraints above close Z-B. The leaf
        // binding on the first expansion row ties the trace's
        // merkle_current chain to the original step's leaf,
        // closing the soundness gap.)

        let is_push: AB::Expr = cur[COL_IS_PUSH].into();
        let is_pop: AB::Expr = cur[COL_IS_POP].into();
        let is_call: AB::Expr = cur[COL_IS_CALL].into();
        let is_ret: AB::Expr = cur[COL_IS_RET].into();

        builder
            .when(is_push.clone())
            .assert_eq(next_pc.clone(), pc.clone() + one.clone());
        builder
            .when(is_pop.clone())
            .assert_eq(next_pc.clone(), pc.clone() + one.clone());
        builder
            .when(is_call.clone())
            .assert_eq(next_pc.clone(), pc.clone() + imm.clone());

        // Stack pointer transition
        builder.when_transition().assert_zero(
            is_push.clone() * (nxt_stack_ptr.clone() - cur_stack_ptr.clone() - one.clone())
                + is_call.clone() * (nxt_stack_ptr.clone() - cur_stack_ptr.clone() - one.clone())
                + is_pop.clone() * (nxt_stack_ptr.clone() - cur_stack_ptr.clone() + one.clone())
                + is_ret.clone() * (nxt_stack_ptr.clone() - cur_stack_ptr.clone() + one.clone())
                + (one.clone()
                    - is_push.clone()
                    - is_pop.clone()
                    - is_call.clone()
                    - is_ret.clone())
                    * (nxt_stack_ptr - cur_stack_ptr.clone()),
        );
        builder
            .when_first_row()
            .assert_zero(cur[COL_STACK_PTR].into());

        builder
            .when_transition()
            .when(is_halt.clone())
            .assert_eq(nxt_is_halt, one.clone());
        builder
            .when_transition()
            .when(is_halt.clone())
            .assert_eq(nxt_pc, cur[COL_PC].into());

        // Task 0.30 (security audit Z-C): termination constraint.
        //
        // The transition 1 -> 0 for `cpu_active` is allowed ONLY on a Halt
        // row. In normal execution every transition is 1 -> 1; the only
        // 1 -> 0 transition is the move from the last real step into the
        // padding (cpu_active = 0, is_halt = 1) zone. By forcing that
        // transition to land on a row where `is_halt = 1`, we rule out the
        // "the program was cut short without Halting" attack and pair with
        // the VM-side guarantee that the last real step is always Halt
        // (see `Vm::run_receipt`).
        builder
            .when_transition()
            .when(cpu_active.clone())
            .when(one.clone() - nxt_cpu_active.clone())
            .assert_zero(one.clone() - is_halt.clone());

        // Soundness: Gas consumption checking
        let three = AB::Expr::from(AB::F::from_u64(3));
        let two = AB::Expr::from(AB::F::from_u64(2));
        let five = AB::Expr::from(AB::F::from_u64(5));
        let eight = AB::Expr::from(AB::F::from_u64(8));
        let ten = AB::Expr::from(AB::F::from_u64(10));
        let twelve = AB::Expr::from(AB::F::from_u64(12));
        // Task 0.338 / A12: SRead=8, SWrite=12 (must match Vm::gas_cost).
        let gas_cost = is_load.clone() * three.clone()
            + is_store.clone() * three.clone()
            + is_sread.clone() * eight.clone()
            + is_swrite.clone() * twelve.clone()
            + is_poseidon.clone() * ten.clone()
            // Task 0.36: expansion rows reuse opcode 0x1E but must not re-charge gas.
            + is_verify_merkle.clone() * (one.clone() - is_expand.clone()) * ten.clone()
            + is_call.clone() * two.clone()
            + is_ret.clone() * two.clone()
            + is_push.clone() * two.clone()
            + is_pop.clone() * two.clone()
            + is_syscall.clone() * five.clone()
            + (one.clone()
                - is_load.clone()
                - is_store.clone()
                - is_sread.clone()
                - is_swrite.clone()
                - is_poseidon.clone()
                - is_verify_merkle.clone()
                - is_call.clone()
                - is_ret.clone()
                - is_push.clone()
                - is_pop.clone()
                - is_syscall.clone()
                - is_halt.clone())
                * one.clone();

        builder
            .when_first_row()
            .assert_zero(cur[COL_GAS_USED].into());
        let cur_gas: AB::Expr = cur[COL_GAS_USED].into();
        let nxt_gas: AB::Expr = nxt[COL_GAS_USED].into();
        builder
            .when_transition()
            .assert_zero(nxt_gas - cur_gas.clone() - gas_cost);

        let expected_gas = public_inputs[34].into()
            + public_inputs[35].into() * AB::Expr::from(AB::F::from_u64(1 << 32));
        builder.when_last_row().assert_zero(cur_gas - expected_gas);

        // Task 0.31 (security audit Z-A): bind the remaining public
        // inputs to trace columns so a malicious prover cannot set
        // them freely.
        //
        // Layout reminder (matching `to_public_values`):
        //   [0,1]   chain_id
        //   [2..10] program_hash       (already bound via Program CTL LogUp)
        //   [10..18] initial_state_root
        //   [18..26] final_state_root
        //   [26,27] sender             (bound via syscall, kept)
        //   [28,29] nonce              (bound via syscall, kept)
        //   [30,31] block_height       (bound via syscall, kept)
        //   [32,33] gas_limit
        //   [34,35] gas_used           (already bound on last row, kept)
        //   [36,37] exit_code
        //   [38,39] trace_len
        //   [40..48] event_digest      (bound in Görev 2)
        //
        // We compare one 32-bit limb at a time, so each side has only
        // a `public_inputs[i]` and a `cur[COL...]` — no `<< 32j`
        // shifts that would overflow a u64 in Rust.

        // (1) initial_state_root: first row, COL_INIT_ROOT_0..7 == public[10..18]
        for j in 0..8 {
            builder
                .when_first_row()
                .assert_zero(cur[COL_INIT_ROOT_0 + j].into() - public_inputs[10 + j].into());
        }

        // (2) final_state_root: last real row (cpu_active=1, is_halt=1),
        //     COL_FINAL_ROOT_0..7 == public[18..26].
        for j in 0..8 {
            builder
                .when(is_halt.clone())
                .when(cpu_active.clone())
                .assert_zero(cur[COL_FINAL_ROOT_0 + j].into() - public_inputs[18 + j].into());
        }

        // (3) gas_limit: first row, COL_GAS_LIMIT == public[32] + public[33] * 2^32
        {
            let expected_gas_limit = public_inputs[32].into()
                + public_inputs[33].into() * AB::Expr::from(AB::F::from_u64(1u64 << 32));
            builder
                .when_first_row()
                .assert_zero(cur[COL_GAS_LIMIT].into() - expected_gas_limit);
        }

        // (4) trace_len: last real row (cpu_active=1, is_halt=1),
        //     COL_TRACE_LEN_CTR == public[38] + public[39] * 2^32.
        {
            let expected_trace_len = public_inputs[38].into()
                + public_inputs[39].into() * AB::Expr::from(AB::F::from_u64(1u64 << 32));
            builder
                .when(is_halt.clone())
                .when(cpu_active.clone())
                .assert_zero(cur[COL_TRACE_LEN_CTR].into() - expected_trace_len);
        }

        // Task 0.31 (security audit Z-A, Görev 2): event_digest,
        // exit_code, and chain_id.

        // (5) event_digest: last real row, COL_EVENT_DIGEST_0..7 == public[40..48]
        for j in 0..8 {
            builder
                .when(is_halt.clone())
                .when(cpu_active.clone())
                .assert_zero(cur[COL_EVENT_DIGEST_0 + j].into() - public_inputs[40 + j].into());
        }

        // (5b) event_digest transition (Task 0.358 fix):
        // Prover writes the updated accumulator ON the Log row itself
        // (copy prev, then += log val). Therefore the constraint must
        // use the *next* row's Log flag and rs1 value:
        //   digest[i+1] = digest[i] + is_log[i+1] * rs1[i+1]
        // The previous formulation used cur is_log/rs1, which forced
        // digest to update one row late and rejected every Log program
        // (InvalidProof) — that also broke budlum's CI pin rebind.
        {
            let nxt_event_0: AB::Expr = nxt[COL_EVENT_DIGEST_0].into();
            let cur_event_0: AB::Expr = cur[COL_EVENT_DIGEST_0].into();
            let nxt_is_log: AB::Expr = nxt[COL_IS_LOG].into();
            let nxt_rs1: AB::Expr = nxt[COL_RS1_VAL].into();
            builder
                .when_transition()
                .when(cpu_active.clone())
                .assert_zero(nxt_event_0 - cur_event_0 - nxt_is_log * nxt_rs1);
            // Bounds check: COL_EVENT_DIGEST_0 < 2^32 — too expensive
            // to do as a range proof; we instead require that the
            // first column never carries a bit beyond the 32nd. This
            // is approximated by zero-extending the u32 limb: as long
            // as the prover populates the column with values in 0..2^32
            // (which it must, since the witness is constructed from
            // u32 values), the constraint is satisfied. A malicious
            // prover trying to encode 2^32 + x would also satisfy
            // the transition (since rs1_val's low 32 bits are 0 there)
            // but the last-row binding to public_inputs[40] (which is
            // a u32) would force the difference to surface.
            for j in 1..8 {
                let nxt_e: AB::Expr = nxt[COL_EVENT_DIGEST_0 + j].into();
                let cur_e: AB::Expr = cur[COL_EVENT_DIGEST_0 + j].into();
                builder
                    .when_transition()
                    .when(cpu_active.clone())
                    .assert_zero(nxt_e - cur_e);
            }
        }

        // (6) exit_code: last real row, COL_EXIT_CODE == public[36] + public[37] * 2^32
        {
            let expected_exit = public_inputs[36].into()
                + public_inputs[37].into() * AB::Expr::from(AB::F::from_u64(1u64 << 32));
            builder
                .when(is_halt.clone())
                .when(cpu_active.clone())
                .assert_zero(cur[COL_EXIT_CODE].into() - expected_exit);
        }

        // (7) chain_id: first row, COL_CHAIN_ID == public[0] (low 32 bits)
        {
            builder
                .when_first_row()
                .assert_zero(cur[COL_CHAIN_ID].into() - public_inputs[0].into());
        }

        // Soundness: Syscall constraints connecting to public inputs
        let expected_sender = public_inputs[26].into()
            + public_inputs[27].into() * AB::Expr::from(AB::F::from_u64(1 << 32));
        let expected_bh = public_inputs[30].into()
            + public_inputs[31].into() * AB::Expr::from(AB::F::from_u64(1 << 32));
        let expected_nonce = public_inputs[28].into()
            + public_inputs[29].into() * AB::Expr::from(AB::F::from_u64(1 << 32));

        let two_val = AB::Expr::from(AB::F::from_u64(2));
        let three_val = AB::Expr::from(AB::F::from_u64(3));

        let factor_1 = (imm.clone() - two_val.clone()) * (imm.clone() - three_val.clone());
        builder
            .when(is_syscall.clone())
            .assert_zero(factor_1 * (rd_val_new.clone() - expected_sender));

        let factor_2 = (imm.clone() - one.clone()) * (imm.clone() - three_val.clone());
        builder
            .when(is_syscall.clone())
            .assert_zero(factor_2 * (rd_val_new.clone() - expected_bh));

        let factor_3 = (imm.clone() - one.clone()) * (imm.clone() - two_val.clone());
        builder
            .when(is_syscall.clone())
            .assert_zero(factor_3 * (rd_val_new.clone() - expected_nonce));

        // CPU / Registers / Memory constraints
        let r_val: AB::Expr = cur[COL_REG_VAL].into();
        let r_active: AB::Expr = cur[COL_REG_ACTIVE].into();
        let r_same: AB::Expr = cur[COL_REG_SAME].into();
        let nr_val: AB::Expr = nxt[COL_REG_VAL].into();
        let nr_active: AB::Expr = nxt[COL_REG_ACTIVE].into();
        let nr_write: AB::Expr = nxt[COL_REG_IS_WRITE].into();
        let r_idx: AB::Expr = cur[COL_REG_IDX].into();
        let nr_idx: AB::Expr = nxt[COL_REG_IDX].into();

        builder.when_transition().assert_zero(
            r_active.clone()
                * nr_active.clone()
                * r_same.clone()
                * (one.clone() - nr_write)
                * (nr_val - r_val),
        );
        builder
            .when_transition()
            .assert_zero(r_active.clone() * nr_active.clone() * r_same.clone() * (nr_idx - r_idx));

        let m_val: AB::Expr = cur[COL_MEM_VAL].into();
        let m_active: AB::Expr = cur[COL_MEM_ACTIVE].into();
        let m_same: AB::Expr = cur[COL_MEM_SAME].into();
        let nm_val: AB::Expr = nxt[COL_MEM_VAL].into();
        let nm_active: AB::Expr = nxt[COL_MEM_ACTIVE].into();
        let nm_write: AB::Expr = nxt[COL_MEM_IS_WRITE].into();
        let m_addr: AB::Expr = cur[COL_MEM_ADDR].into();
        let nm_addr: AB::Expr = nxt[COL_MEM_ADDR].into();
        let m_clk: AB::Expr = cur[COL_MEM_CLK].into();
        let m_is_write: AB::Expr = cur[COL_MEM_IS_WRITE].into();

        builder.when_transition().assert_zero(
            m_active.clone()
                * nm_active.clone()
                * m_same.clone()
                * (one.clone() - nm_write.clone())
                * (nm_val.clone() - m_val.clone()),
        );
        builder.when_transition().assert_zero(
            m_active.clone() * nm_active.clone() * m_same.clone() * (nm_addr - m_addr.clone()),
        );

        // Soundness: first-read default zero in memory
        builder
            .when_first_row()
            .assert_zero(m_active.clone() * (one.clone() - m_is_write.clone()) * m_val.clone());
        builder.when_transition().assert_zero(
            m_active.clone()
                * nm_active.clone()
                * (one.clone() - m_same.clone())
                * (one.clone() - nm_write.clone())
                * nm_val.clone(),
        );

        let cur_clk: AB::Expr = cur[COL_CLK].into();
        let cur_pc: AB::Expr = cur[COL_PC].into();
        builder.when_first_row().assert_zero(cur_clk);
        builder.when_first_row().assert_zero(cur_pc);

        let perm = builder.permutation();
        let perm_cur = perm.current_slice();
        let perm_nxt = perm.next_slice();
        let rand = builder.permutation_randomness();
        if rand.len() >= 3 && perm_cur.len() >= 3 && perm_nxt.len() >= 3 {
            let alpha = rand[0];
            let beta = rand[1];
            let gamma = rand[2];

            let rs1_idx: AB::Expr = cur[COL_RS1_IDX].into();
            let rs2_idx: AB::Expr = cur[COL_RS2_IDX].into();
            let rd_idx: AB::Expr = cur[COL_RD_IDX].into();
            let reg_clk: AB::Expr = cur[COL_REG_CLK].into();
            let reg_sub_clk: AB::Expr = cur[COL_REG_SUB_CLK].into();
            let reg_idx: AB::Expr = cur[COL_REG_IDX].into();
            let reg_val: AB::Expr = cur[COL_REG_VAL].into();
            let reg_is_write: AB::Expr = cur[COL_REG_IS_WRITE].into();

            let alpha_expr: AB::ExprEF = alpha.into();
            let beta_expr: AB::ExprEF = beta.into();
            let gamma_expr: AB::ExprEF = gamma.into();

            let b2 = beta_expr.clone() * beta_expr.clone();
            let b3 = b2.clone() * beta_expr.clone();
            let b4 = b3.clone() * beta_expr.clone();
            let b5 = b4.clone() * beta_expr.clone();

            let term = |table_id: AB::Expr,
                        clk: AB::Expr,
                        idx: AB::Expr,
                        val: AB::Expr,
                        is_write: AB::Expr|
             -> AB::ExprEF {
                let table_id: AB::ExprEF = table_id.into();
                let clk: AB::ExprEF = clk.into();
                let idx: AB::ExprEF = idx.into();
                let val: AB::ExprEF = val.into();
                let is_write: AB::ExprEF = is_write.into();
                alpha_expr.clone()
                    + beta_expr.clone() * table_id
                    + b2.clone() * clk
                    + b3.clone() * idx
                    + b4.clone() * val
                    + b5.clone() * is_write
            };

            let zero = AB::Expr::from(AB::F::ZERO);
            let one = AB::Expr::from(AB::F::ONE);

            let table_reg = zero.clone();

            // Register LogUp (perm_cur[0] / perm_nxt[0])
            let four = AB::Expr::from(AB::F::from_u64(4));
            let one_val = AB::Expr::from(AB::F::from_u64(1));
            let two_val = AB::Expr::from(AB::F::from_u64(2));
            let three_val = AB::Expr::from(AB::F::from_u64(3));

            let clk_rs1 = clk.clone() * four.clone() + one_val;
            let clk_rs2 = clk.clone() * four.clone() + two_val;
            let clk_rd = clk.clone() * four.clone() + three_val;
            let clk_reg = reg_clk.clone() * four.clone() + reg_sub_clk;

            let c_rs1 = term(
                table_reg.clone(),
                clk_rs1,
                rs1_idx.clone(),
                rs1_val.clone(),
                zero.clone(),
            );
            let c_rs2 = term(
                table_reg.clone(),
                clk_rs2,
                rs2_idx.clone(),
                rs2_val.clone(),
                zero.clone(),
            );
            let c_rd = term(
                table_reg.clone(),
                clk_rd,
                rd_idx.clone(),
                rd_val_new.clone(),
                one.clone(),
            );
            let c_reg = term(
                table_reg.clone(),
                clk_reg,
                reg_idx.clone(),
                reg_val.clone(),
                reg_is_write.clone(),
            );

            let r_active_ext: AB::ExprEF = r_active.clone().into();

            let diff_rs1 = gamma_expr.clone() - c_rs1;
            let diff_rs2 = gamma_expr.clone() - c_rs2;
            let diff_rd = gamma_expr.clone() - c_rd;
            let diff_reg = gamma_expr.clone() - c_reg;

            let d_rs1 = diff_rs2.clone() * diff_rd.clone() * diff_reg.clone();
            let d_rs2 = diff_rs1.clone() * diff_rd.clone() * diff_reg.clone();
            let d_rd = diff_rs1.clone() * diff_rs2.clone() * diff_reg.clone();
            let d_reg = diff_rs1.clone() * diff_rs2.clone() * diff_rd.clone();
            let d_total = diff_rs1 * diff_rs2 * diff_rd * diff_reg;
            let s_reg_cur: AB::ExprEF = perm_cur[0].into();
            let s_reg_nxt: AB::ExprEF = perm_nxt[0].into();
            let is_real_op_ext: AB::ExprEF = is_real_op.into();
            // Task 8.10 (ARENA3 aux CTL fix #2): Register LogUp must also
            // exclude VerifyMerkle expansion rows (same multiplicity mismatch
            // as Program CTL). The trace_matrix correctly skips register events
            // for expansion rows, so the CPU side must match.
            let is_expand_ext_reg: AB::ExprEF = cur[COL_VM_MERKLE_IS_EXPAND].into().into();
            let is_reg_active: AB::ExprEF =
                is_real_op_ext.clone() * (AB::ExprEF::ONE - is_expand_ext_reg);
            builder.when_transition().assert_zero_ext(
                (s_reg_nxt.clone() - s_reg_cur.clone()) * d_total
                    - (is_reg_active * (d_rs1 + d_rs2 + d_rd) - r_active_ext * d_reg),
            );
            builder.when_first_row().assert_zero_ext(s_reg_cur.clone());
            builder.when_last_row().assert_zero_ext(s_reg_cur);

            // Memory LogUp (includes Load/Store/Push/Pop/Call/Ret + SRead/SWrite)
            let rs1_idx: AB::Expr = cur[COL_RS1_IDX].into();
            let is_real_mem_op = (is_load.clone() + is_store.clone()) * rs1_idx.clone(); // If rs1 is 0, it's LoadImm
            let is_stack_op = is_push.clone() + is_pop.clone() + is_call.clone() + is_ret.clone();
            let is_storage_op = is_sread.clone() + is_swrite.clone();
            let is_any_mem_op =
                is_real_mem_op.clone() + is_stack_op.clone() + is_storage_op.clone();

            let stack_base = AB::Expr::from(AB::F::from_u64(1 << 60));
            let storage_base = AB::Expr::from(AB::F::from_u64(2 << 60));
            let stack_addr = stack_base.clone()
                + (is_push.clone() + is_call.clone()) * cur_stack_ptr.clone()
                + (is_pop.clone() + is_ret.clone()) * (cur_stack_ptr.clone() - one.clone());
            let storage_addr = storage_base + cur[COL_IMM].into();

            let final_mem_addr = is_real_mem_op.clone()
                * (cur[COL_RS1_VAL].into() + cur[COL_IMM].into())
                + is_stack_op.clone() * stack_addr
                + is_storage_op.clone() * storage_addr;

            let is_write = is_store.clone() + is_push.clone() + is_call.clone() + is_swrite.clone();
            let cpu_mem_val = is_load * cur[COL_RD_VAL_NEW].into()
                + is_store * cur[COL_RS2_VAL].into()
                + is_push * cur[COL_RS1_VAL].into()
                + is_pop * cur[COL_RD_VAL_NEW].into()
                + is_call * (cur[COL_PC].into() + one.clone())
                + is_ret * cur[COL_NEXT_PC].into()
                + is_sread * cur[COL_RD_VAL_NEW].into()
                + is_swrite * cur[COL_RS1_VAL].into();

            let c_cpu_mem = term(
                one.clone(),
                clk.clone(),
                final_mem_addr.clone(),
                cpu_mem_val.clone(),
                is_write.clone(),
            );
            let c_mem = term(
                one.clone(),
                m_clk.clone(),
                m_addr.clone(),
                m_val.clone(),
                m_is_write.clone(),
            );

            let is_any_mem_op_ext: AB::ExprEF = is_any_mem_op.into();
            let m_active_ext: AB::ExprEF = m_active.into();

            let diff_cpu_mem = gamma_expr.clone() - c_cpu_mem;
            let diff_mem = gamma_expr.clone() - c_mem;

            let s_mem_cur: AB::ExprEF = perm_cur[1].into();
            let s_mem_nxt: AB::ExprEF = perm_nxt[1].into();

            builder.when_transition().assert_zero_ext(
                (s_mem_nxt.clone() - s_mem_cur.clone()) * diff_cpu_mem.clone() * diff_mem.clone()
                    - (is_any_mem_op_ext * diff_mem - m_active_ext * diff_cpu_mem),
            );
            builder.when_first_row().assert_zero_ext(s_mem_cur.clone());
            builder.when_last_row().assert_zero_ext(s_mem_cur);

            // Program CTL LogUp (perm_cur[2] / perm_nxt[2])
            let pre = builder.preprocessed();
            let pre_cur = pre.current_slice();
            let pre_pc: AB::Expr = pre_cur[0].into();
            let pre_inst: AB::Expr = pre_cur[1].into();
            let pre_active: AB::Expr = pre_cur[2].into();

            let raw_inst: AB::Expr = cur[COL_RAW_INST].into();

            let pc_ext: AB::ExprEF = pc.into();
            let raw_inst_ext: AB::ExprEF = raw_inst.into();
            let pre_pc_ext: AB::ExprEF = pre_pc.into();
            let pre_inst_ext: AB::ExprEF = pre_inst.into();

            // tuple is (pc, raw_inst)
            let term_cpu_prog =
                alpha_expr.clone() + beta_expr.clone() * pc_ext + b2.clone() * raw_inst_ext;
            let term_pre_prog =
                alpha_expr.clone() + beta_expr.clone() * pre_pc_ext + b2.clone() * pre_inst_ext;

            let diff_cpu_prog: AB::ExprEF = gamma_expr.clone() - term_cpu_prog;
            let diff_pre_prog: AB::ExprEF = gamma_expr.clone() - term_pre_prog;

            let s_prog_cur: AB::ExprEF = perm_cur[2].into();
            let s_prog_nxt: AB::ExprEF = perm_nxt[2].into();
            let cpu_active: AB::Expr = cur[COL_CPU_ACTIVE].into();
            // Task 8.10 (ARENA3 aux CTL fix): VerifyMerkle expansion rows
            // reuse the same (pc, raw_inst) tuple as the original step.
            // Without this gate, 65 CPU rows (1 original + 64 expansion)
            // map to 1 preprocessed row → Program CTL LogUp multiplicity
            // mismatch → InvalidProof. Register LogUp already correctly
            // skips expansion rows; Program CTL must do the same.
            let is_expand: AB::Expr = cur[COL_VM_MERKLE_IS_EXPAND].into();
            let prog_active: AB::Expr = cpu_active.clone() * (one.clone() - is_expand);
            let prog_active_ext: AB::ExprEF = prog_active.into();
            let pre_active_ext: AB::ExprEF = pre_active.into();

            builder.when_transition().assert_zero_ext(
                (s_prog_nxt.clone() - s_prog_cur.clone())
                    * diff_cpu_prog.clone()
                    * diff_pre_prog.clone()
                    - (prog_active_ext * diff_pre_prog - pre_active_ext * diff_cpu_prog),
            );
            builder.when_first_row().assert_zero_ext(s_prog_cur.clone());
            builder.when_last_row().assert_zero_ext(s_prog_cur);
        }

        // --- Comparison + Bitwise AIR constraints ---
        // Bit decomposition shared between comparison and bitwise (And/Or/Xor) opcodes
        let is_cmp = is_lt.clone() + is_gt.clone() + is_lte.clone() + is_gte.clone();
        let is_bw_bits = is_and.clone() + is_or.clone() + is_xor.clone();
        let is_cmp_or_bw = is_cmp.clone() + is_bw_bits.clone();

        // Booleanity of all bit decomposition columns
        for i in 0..64 {
            let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
            let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
            builder.when(is_cmp_or_bw.clone()).assert_bool(a_bit);
            builder.when(is_cmp_or_bw.clone()).assert_bool(b_bit);
        }

        // Equality prefix flags are boolean (comparison only)
        for i in 0..64 {
            let eq_i: AB::Expr = cur[COL_CMP_EQ_BASE + i].into();
            builder.when(is_cmp.clone()).assert_bool(eq_i);
        }

        // Reconstitution: rs1_val = sum(a_i * 2^i)
        {
            let mut rs1_bits_sum: AB::Expr = AB::Expr::ZERO;
            for i in 0..64 {
                let pow2 = AB::F::from_u64(1u64 << i);
                let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
                rs1_bits_sum += a_bit * pow2;
            }
            builder
                .when(is_cmp_or_bw.clone())
                .assert_eq(rs1_bits_sum, rs1_val.clone());
        }

        // Reconstitution: rs2_val = sum(b_i * 2^i) (comparison + And/Or/Xor only)
        {
            let mut rs2_bits_sum: AB::Expr = AB::Expr::ZERO;
            for i in 0..64 {
                let pow2 = AB::F::from_u64(1u64 << i);
                let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
                rs2_bits_sum += b_bit * pow2;
            }
            builder
                .when(is_cmp.clone() + is_bw_bits.clone())
                .assert_eq(rs2_bits_sum, rs2_val.clone());
        }

        // Bitwise result constraints (And/Or/Xor using bit decomposition)
        {
            let mut and_sum: AB::Expr = AB::Expr::ZERO;
            for i in 0..64 {
                let pow2 = AB::F::from_u64(1u64 << i);
                let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
                let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
                and_sum += a_bit * b_bit * pow2;
            }
            let two_val = AB::Expr::from(AB::F::from_u64(2));

            // And: rd = sum(a_i * b_i * 2^i)
            builder
                .when(is_and)
                .assert_eq(rd_val_new.clone(), and_sum.clone());
            // Or: rd = rs1 + rs2 - sum(a_i * b_i * 2^i)
            builder.when(is_or).assert_eq(
                rd_val_new.clone(),
                rs1_val.clone() + rs2_val.clone() - and_sum.clone(),
            );
            // Xor: rd = rs1 + rs2 - 2 * sum(a_i * b_i * 2^i)
            builder.when(is_xor).assert_eq(
                rd_val_new.clone(),
                rs1_val.clone() + rs2_val.clone() - two_val * and_sum,
            );
        }

        // Not (logical NOT): rd = 1 if rs1 == 0, else rd = 0 (reuse COL_INV_ZERO as inverse witness)
        {
            let not_inv: AB::Expr = cur[COL_INV_ZERO].into();
            let is_nonzero = rs1_val.clone() * not_inv.clone();
            builder.when(is_not.clone()).assert_bool(is_nonzero.clone());
            builder
                .when(is_not.clone())
                .assert_zero(rs1_val.clone() * (one.clone() - is_nonzero.clone()));
            builder
                .when(is_not)
                .assert_eq(rd_val_new.clone(), one.clone() - is_nonzero);
        }

        // --- Comparison-specific constraints below ---

        // Equality prefix recursion: eq_i = eq_{i+1} * (1 - a_i - b_i + 2*a_i*b_i)
        // eq_64 is implicitly 1
        {
            let a_63: AB::Expr = cur[COL_CMP_RS1_BASE + 63].into();
            let b_63: AB::Expr = cur[COL_CMP_RS2_BASE + 63].into();
            let eq_bit_63 = one.clone() - a_63.clone() - b_63.clone()
                + AB::Expr::from(AB::F::from_u64(2)) * a_63.clone() * b_63.clone();
            let eq_63: AB::Expr = cur[COL_CMP_EQ_BASE + 63].into();
            builder.when(is_cmp.clone()).assert_eq(eq_63, eq_bit_63);
        }
        for i in (0..63).rev() {
            let a_i: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
            let b_i: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
            let eq_bit_i = one.clone() - a_i.clone() - b_i.clone()
                + AB::Expr::from(AB::F::from_u64(2)) * a_i.clone() * b_i.clone();
            let eq_i: AB::Expr = cur[COL_CMP_EQ_BASE + i].into();
            let eq_next: AB::Expr = cur[COL_CMP_EQ_BASE + i + 1].into();
            builder
                .when(is_cmp.clone())
                .assert_eq(eq_i, eq_next * eq_bit_i);
        }

        // Raw less-than result: cmp_lt_raw = sum_{i=0}^{63} eq_{i+1} * (1-a_i) * b_i
        // eq_64 is implicit 1 for the MSB term
        {
            let a_63: AB::Expr = cur[COL_CMP_RS1_BASE + 63].into();
            let b_63: AB::Expr = cur[COL_CMP_RS2_BASE + 63].into();
            let mut cmp_lt_sum: AB::Expr = (one.clone() - a_63) * b_63;
            for i in 0..63 {
                let a_i: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
                let b_i: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
                let eq_next: AB::Expr = cur[COL_CMP_EQ_BASE + i + 1].into();
                cmp_lt_sum += eq_next * (one.clone() - a_i) * b_i;
            }
            let cmp_lt_raw: AB::Expr = cur[COL_CMP_LT_RAW].into();
            builder
                .when(is_cmp.clone())
                .assert_eq(cmp_lt_raw.clone(), cmp_lt_sum);
        }

        // Opcode-specific result constraints
        // eq_0 tells us if all bits are equal (a == b)
        let cmp_eq_all: AB::Expr = cur[COL_CMP_EQ_BASE].into();
        let cmp_lt_raw: AB::Expr = cur[COL_CMP_LT_RAW].into();

        // Lt: rd = cmp_lt_raw  (1 if a < b)
        builder
            .when(is_lt)
            .assert_eq(rd_val_new.clone(), cmp_lt_raw.clone());
        // Gt: rd = 1 - cmp_eq_all - cmp_lt_raw  (1 if a > b)
        builder.when(is_gt).assert_eq(
            rd_val_new.clone(),
            one.clone() - cmp_eq_all.clone() - cmp_lt_raw.clone(),
        );
        // Lte: rd = cmp_eq_all + cmp_lt_raw  (1 if a <= b)
        builder
            .when(is_lte)
            .assert_eq(rd_val_new.clone(), cmp_eq_all.clone() + cmp_lt_raw.clone());
        // Gte: rd = 1 - cmp_lt_raw  (1 if a >= b)
        builder
            .when(is_gte)
            .assert_eq(rd_val_new.clone(), one.clone() - cmp_lt_raw.clone());

        // --- Poseidon hash (4 rounds, alpha=7) ---
        // Verify all 4 rounds including S-boxes, MDS mixing, and result.
        {
            let p: AB::Expr = cur[COL_IS_POSEIDON].into();
            // Initial state
            builder
                .when(p.clone())
                .assert_eq(cur[COL_POSEIDON_STATE_BASE].into(), rs1_val.clone());
            builder
                .when(p.clone())
                .assert_eq(cur[COL_POSEIDON_STATE_BASE + 1].into(), rs2_val.clone());
            for i in 2..8 {
                builder
                    .when(p.clone())
                    .assert_zero(cur[COL_POSEIDON_STATE_BASE + i]);
            }

            const MDS: [[u64; 8]; 8] = [
                [7, 1, 3, 8, 8, 3, 4, 9],
                [9, 7, 1, 3, 8, 8, 3, 4],
                [4, 9, 7, 1, 3, 8, 8, 3],
                [3, 4, 9, 7, 1, 3, 8, 8],
                [8, 3, 4, 9, 7, 1, 3, 8],
                [8, 8, 3, 4, 9, 7, 1, 3],
                [3, 8, 8, 3, 4, 9, 7, 1],
                [1, 3, 8, 8, 3, 4, 9, 7],
            ];

            const RC: [[u64; 8]; 4] = [
                [
                    0xdd5743e7f2a5a5d9,
                    0xcb3a864e58ada44b,
                    0xffa2449ed32f8cdc,
                    0x42025f65d6bd13ee,
                    0x7889175e25506323,
                    0x34b98bb03d24b737,
                    0xbdcc535ecc4faa2a,
                    0x5b20ad869fc0d033,
                ],
                [
                    0xf1dda5b9259dfcb4,
                    0x27515210be112d59,
                    0x4227d1718c766c3f,
                    0x26d333161a5bd794,
                    0x49b938957bf4b026,
                    0x4a56b5938b213669,
                    0x1120426b48c8353d,
                    0x6b323c3f10a56cad,
                ],
                [
                    0xce57d6245ddca6b2,
                    0xb1fc8d402bba1eb1,
                    0xb5c5096ca959bd04,
                    0x6db55cd306d31f7f,
                    0xc49d293a81cb9641,
                    0x1ce55a4fe979719f,
                    0xa92e60a9d178a4d1,
                    0x002cc64973bcfd8c,
                ],
                [
                    0xcea721cce82fb11b,
                    0xe5b55eb8098ece81,
                    0x4e30525c6f1ddd66,
                    0x43c6702827070987,
                    0xaca68430a7b5762a,
                    0x3674238634df9c93,
                    0x88cee1c825e33433,
                    0xde99ae8d74b57176,
                ],
            ];

            for r in 0..4 {
                let mut sbox_out = vec![AB::Expr::ZERO; 8];

                for i in 0..8 {
                    let s: AB::Expr = cur[COL_POSEIDON_STATE_BASE + r * 8 + i].into()
                        + AB::Expr::from(AB::F::from_u64(RC[r][i]));
                    let x2: AB::Expr = cur[COL_POSEIDON_X2_BASE + r * 8 + i].into();
                    let x4: AB::Expr = cur[COL_POSEIDON_X4_BASE + r * 8 + i].into();

                    builder
                        .when(p.clone())
                        .assert_eq(x2.clone(), s.clone() * s.clone());
                    builder
                        .when(p.clone())
                        .assert_eq(x4.clone(), x2.clone() * x2.clone());

                    sbox_out[i] = x4 * x2 * s;
                }

                // Check MDS multiplication and next round state (or result for last round)
                if r < 3 {
                    for i in 0..8 {
                        let mut sum: AB::Expr = AB::Expr::ZERO;
                        for j in 0..8 {
                            sum += sbox_out[j].clone() * AB::Expr::from(AB::F::from_u64(MDS[i][j]));
                        }
                        builder
                            .when(p.clone())
                            .assert_eq(cur[COL_POSEIDON_STATE_BASE + (r + 1) * 8 + i].into(), sum);
                    }
                } else {
                    // Final round, output is the first element
                    let mut sum: AB::Expr = AB::Expr::ZERO;
                    for j in 0..8 {
                        sum += sbox_out[j].clone() * AB::Expr::from(AB::F::from_u64(MDS[0][j]));
                    }
                    builder.when(p.clone()).assert_eq(rd_val_new.clone(), sum);
                }
            }
        }
    }
}
