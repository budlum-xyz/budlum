use p3_air::{Air, AirBuilder, BaseAir, ExtensionBuilder, PermutationAirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;

pub const TRACE_WIDTH: usize = 1073;

/// Columns in the preprocessed (program ROM) trace: pc, raw instruction word,
/// active flag, then the four decoded fields (opcode, rd, rs1, rs2).
///
/// The decoded fields are redundant with the raw word for anyone who can split
/// a field element into bit ranges, which an AIR cannot do without a range
/// check this machine does not have. Carrying them as their own columns is
/// what lets the Program CTL bind the CPU trace's decode columns to the
/// committed program.
///
/// Instructions encode as
/// `opcode | rd << 8 | rs1 << 13 | rs2 << 18 | imm << 23`, so each field is a
/// shift and a mask away from the word.
///
/// `imm` needed one extra step. It is a signed 32-bit value and the CPU trace
/// stores it as a field element, wrapping negatives to `P - |imm|`, so the raw
/// masked bits do not match what the trace holds. Measured: `imm = -1` masks
/// to `4294967295` but the trace carries `P - 1 = 18446744069414584320`. The
/// preprocessed side therefore applies the same reinterpretation the VM does,
/// through `bud_isa::decode_any`, rather than reproducing the arithmetic here.
/// One decoder, one answer.
pub const PREPROCESSED_WIDTH: usize = 8;

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
/// Marks a memory row that carries a value the host placed in memory before
/// execution began, rather than one the program wrote.
///
/// Without it the AIR has to require that the first access to any address
/// reads zero - otherwise a prover could claim whatever starting memory made
/// its trace work out, which for the AI guest means claiming whatever weights
/// it liked. That rule is correct but it also makes a host-seeded image
/// unprovable: the matmul guest reads weights written before the first
/// instruction, so its first memory event is a non-zero read.
///
/// A row with this flag set is exempt from the zero rule and instead has to
/// appear in `public_inputs.initial_state_root`, which commits to the whole
/// image. The prover cannot invent one: changing any seeded byte changes the
/// commitment, and the commitment is a public input the verifier already
/// holds.
///
/// The flag is allowed on an active row only, and only on the first row of an
/// address block: the row after a row of the same address cannot carry it.
pub const COL_MEM_IS_INIT: usize = 914;

/// Running fold of every initial-image row, checked against
/// `public_inputs.initial_state_root` on the last row.
///
/// [`COL_MEM_IS_INIT`] is safe to exempt from the zero rule.
/// Each flagged row folds `(addr, val)` into the accumulator, so a prover that
/// flags a row it did not seed, or seeds a different value, lands on a
/// different accumulator than the public input it is checked against.
///
/// The fold is `acc' = acc * BETA + addr * GAMMA + val`, with fixed constants
/// rather than Fiat-Shamir challenges. That is weaker than a hash: it is a
/// polynomial evaluation at a known point, so a prover who wants a specific
/// accumulator can solve for a set of rows that reaches it. What it does bind
/// is *accidental* divergence and any substitution that does not go to the
/// trouble of solving the system - which is the difference between "the
/// verifier holds a value nobody checks" and "the verifier holds a value the
/// trace must reproduce". Replacing the constants with transcript challenges
/// is the remaining step; see `docs/AI_VERIFICATION_STATUS.md`.
pub const COL_MEM_INIT_ACC: usize = 915;

/// Fold constants for [`COL_MEM_INIT_ACC`].
pub const MEM_INIT_BETA: u64 = 0x9E37_79B9_7F4A_7C15;
pub const MEM_INIT_GAMMA: u64 = 0xC2B2_AE3D_27D4_EB4F;
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
pub const COL_CMP_RS1_BASE: usize = 65; // 65..128 - rs1 bit decomposition
pub const COL_CMP_RS2_BASE: usize = 129; // 129..192 - rs2 bit decomposition
pub const COL_CMP_EQ_BASE: usize = 193; // 193..256 - equality prefix flags eq_0..eq_63
pub const COL_CMP_LT_RAW: usize = 257; // raw less-than result computed from bits

// Poseidon witness columns.
//
// The permutation is the instance: Goldilocks width-12 Poseidon1, `R_F = 8` full
// rounds (4 leading + 4 trailing), `R_P = 22` partial rounds, `alpha = 7`, 30 rounds
// total, capacity 4. The round constants and the MDS matrix are taken from `bud_vm`
// (which reads `budlum-note-packing`) so the AIR, the prover's witness generator and
// the VM cannot drift apart.
//
// Layout. Every round records its entry state (12 columns). The S-box intermediates
// are only recorded where an S-box actually runs: full rounds touch all twelve lanes,
// partial rounds only lane 0. That asymmetry is the point of partial rounds - they
// raise the algebraic degree at a fraction of the width - so the trace must not pay
// for lanes that are never squared.
//
//   state: 30 * 12                        = 360 columns
//   x2:    8 * 12 (full) + 22 * 1 (part)  = 118 columns
//   x4:    same shape                     = 118 columns
pub const POSEIDON_ROUNDS: usize = 30;
/// Lanes of the permutation state.
pub const POSEIDON_WIDTH: usize = 12;
///
/// Convenience: the round split is part of the AIR definition this
/// module publishes; `POSEIDON_HALF_FULL` derives from it here, and it
/// stays pub so the split is read, not restated, by other tooling.
pub const POSEIDON_FULL_ROUNDS: usize = 8;
///
/// Convenience: published with the rest of the Poseidon round split
/// for the same reason as `POSEIDON_FULL_ROUNDS`; the runnable total
/// in-tree is `POSEIDON_ROUNDS`.
pub const POSEIDON_PARTIAL_ROUNDS: usize = 22;
pub const POSEIDON_HALF_FULL: usize = POSEIDON_FULL_ROUNDS / 2;

/// Number of S-box lanes in round `r`: all twelve in a full round, one in a
/// partial round.
pub const fn poseidon_sbox_lanes(round: usize) -> usize {
    if round < POSEIDON_HALF_FULL || round >= POSEIDON_ROUNDS - POSEIDON_HALF_FULL {
        POSEIDON_WIDTH
    } else {
        1
    }
}

/// Offset of round `r`'s S-box intermediates within the x2/x4 blocks.
pub const fn poseidon_sbox_offset(round: usize) -> usize {
    let mut off = 0;
    let mut r = 0;
    while r < round {
        off += poseidon_sbox_lanes(r);
        r += 1;
    }
    off
}

/// Total S-box intermediates per block (x2 and x4 each need this many).
///
/// Convenience: pub with the rest of the column layout this module
/// defines, so an external verifier or trace tool lays out the same
/// columns; the layout constants beside it are what read it in-tree.
pub const POSEIDON_SBOX_SLOTS: usize = poseidon_sbox_offset(POSEIDON_ROUNDS);

pub const COL_POSEIDON_STATE_BASE: usize = 258; // state[r][i] at round entry
pub const COL_POSEIDON_X2_BASE: usize = COL_POSEIDON_STATE_BASE + POSEIDON_ROUNDS * POSEIDON_WIDTH;
pub const COL_POSEIDON_X4_BASE: usize = COL_POSEIDON_X2_BASE + POSEIDON_SBOX_SLOTS;
///
/// Convenience: the end of the Poseidon column block, pub so trace
/// tooling outside this crate can bound the block without restating the
/// layout arithmetic that defines it here.
pub const COL_POSEIDON_END: usize = COL_POSEIDON_X4_BASE + POSEIDON_SBOX_SLOTS;

// (security audit) public-input binding witness columns.
//
// Each public input that is not already constrained by the existing
// AIR (chain_id, initial_state_root, final_state_root, gas_limit,
// Exit_code, trace_len, event_digest) is bound to the trace by
// Introducing a witness column that the prover must populate and the
// AIR then asserts against `public_values[i]`. chain_id, initial
// State root are bound at the first row; final_state_root, gas_used,
// Exit_code, trace_len, event_digest are bound at the last real step
// (cpu_active=1, is_halt=1).
pub const COL_FINAL_ROOT_0: usize = 854; // 354..361 - final state root (8 × u32 limbs)
pub const COL_INIT_ROOT_0: usize = 862; // 362..369 - initial state root (8 × u32 limbs)

// (2026-07-22) privacy-layer opcode selectors.
// Consumes 3 columns from the intentional reserved gap (was 370..378).
pub const COL_IS_PRIVACY_COMMIT: usize = 870;
pub const COL_IS_NULLIFIER_CHECK: usize = 871;
pub const COL_IS_SUM_CONSERVATION: usize = 872;

// Opcode 0x1F is reserved. The selector and the expansion flag are forced
// to zero on every row, so no proof of a trace with this opcode exists.
// The columns 689 to 693 stay in the layout so the width and the proof
// format do not change.
pub const COL_IS_VERIFY_INFERENCE: usize = 873;
pub const COL_INFERENCE_IS_EXPAND: usize = 874; // 1 on expansion rows (8 follow-up rows)
pub const COL_INFERENCE_MODEL_COMMIT: usize = 875; // model commitment limb (u64 → Goldilocks)
pub const COL_INFERENCE_INPUT_COMMIT: usize = 876; // input commitment limb
pub const COL_INFERENCE_OUTPUT_COMMIT: usize = 877; // output commitment limb

/// Inverse witness for the dynamic-storage-slot flag `imm == -1`.
pub const COL_STORAGE_SLOT_INV: usize = COL_INFERENCE_MODEL_COMMIT;

pub const COL_TRACE_LEN_CTR: usize = 878; // 1 column - running count of cpu_active=1 rows
pub const COL_GAS_LIMIT: usize = 879; // 1 column - vm.gas_limit, first row
pub const COL_EVENT_DIGEST_0: usize = 880; // 380..387 - event_digest accumulator (8 × u32 limbs, additive)
pub const COL_EXIT_CODE: usize = 888; // 1 column - 0=normal Halt, 1=error (set on Halt row)
pub const COL_CHAIN_ID: usize = 889; // 1 column - vm.gas_limit sibling; chain_id is bound via first-row public input
                                     // HIGH CWE-345 (2026-08-17): post-execution storage-write digest.
                                     // 8 u32 limbs, bound at the last real row against public_inputs[48..56].
pub const COL_STATE_WRITES_0: usize = 929;

// Merkle path verification columns.
//
// A `VerifyMerkle` is one original row followed by `MERKLE_ROUNDS` (264)
// expansion rows, one per word of the path window
// `[key, leaf[4], 64 x sibling[4], root[4]]`. A 256-bit node is four words and the
// memory argument carries one event per row, so each row reads one word and the
// rows come in groups of four:
//
//   group 0        the leaf        (`COL_MERKLE_LEAFG` = 1)
//   groups 1..=64  one level each  (the path groups)
//   group 65       the root        (`COL_MERKLE_ROOTG` = 1)
//
// The columns below are the walk state. `COL_MERKLE_BUF` collects the four words of
// the current group (a word is written on its own row and carried to the next three),
// `COL_MERKLE_CUR` is the node the walk holds, and on the last row of a path group
// (`COL_MERKLE_HASH` = 1) the shared Poseidon gadget compresses the node and the buffer
// into the next node. The root group compares the held node with the root words one
// word per row.
pub const COL_VM_MERKLE_KEY: usize = 890; // path key, constant across the expansion rows
pub const COL_VM_MERKLE_BIT: usize = 891; // (key >> level) & 1 on path rows
pub const COL_MERKLE_LEAFG: usize = 892; // 1 on the four leaf rows
/// The word this row reads from the path window, as the memory argument sees it.
pub const COL_VM_MERKLE_SIBLING: usize = 893;
pub const COL_VM_MERKLE_ROUND: usize = 894; // row index in the window, 0..263
pub const COL_VM_MERKLE_IS_EXPAND: usize = 895; // 1 on every expansion row
pub const COL_MERKLE_CUR: usize = 896; // 4 columns: the node the walk holds entering the row
pub const COL_MERKLE_BUF: usize = 900; // 4 columns: the words of the current group
pub const COL_MERKLE_ROOTG: usize = 904; // 1 on the four root rows
pub const COL_MERKLE_HASH: usize = 905; // 1 on the last row of a path group: the gadget runs here
pub const COL_MERKLE_RESULT: usize = 906; // the `rd` value of the original row, carried
pub const COL_MERKLE_EQ: usize = 907; // root rows: 1 when the held node word equals the root word
pub const COL_MERKLE_OH: usize = 908; // 4 columns: one-hot word index within the group
pub const COL_MERKLE_DINV: usize = 912; // root rows: inverse witness of the word difference
pub const COL_MERKLE_ACC: usize = 913; // root rows: running product of `COL_MERKLE_EQ`

/// Expansion rows of one `VerifyMerkle`. Mirrors `bud_vm::MERKLE_ROUNDS`.
pub const MERKLE_ROUNDS: usize = 4 + 64 * 4 + 4;

/// Remaining path key on a Merkle expansion row: `key >> round`.
///
/// This column is what binds [`COL_VM_MERKLE_BIT`] to [`COL_VM_MERKLE_KEY`].
/// Booleanity alone left the direction bit free: a prover could flip "left
/// sibling" to "right sibling" on any round, recompute the chain, and produce
/// a different root for the same leaf and siblings, measured, and the AIR
/// accepted it. A Merkle proof whose direction bits are unconstrained proves
/// nothing about membership.
///
/// The binding is a shift chain rather than a 64-bit decomposition:
///
/// ```text
/// round 0:      rem == key
/// every round:  bit == rem - 2 * rem_next      (so rem = 2 * rem_next + bit)
/// last round:   rem_next == 0
/// ```
///
/// With `bit` already boolean, `rem = 2 * rem' + bit` is exactly one step of
/// binary long division, so the chain forces `rem_r = key >> r` and
/// `bit_r = (key >> r) & 1` for every round. Ending at zero after 64 rounds
/// additionally pins `key` to 64 bits, which the old code assumed but never
/// checked.
pub const COL_MERKLE_KEY_REM: usize = 916;

/// Inverse witness for `next_reg_idx - reg_idx`, the column that makes
/// [`COL_REG_SAME`] mean what its name says.
///
/// `COL_REG_SAME` gates the two constraints that give the register table its
/// meaning: that a register keeps its value between a write and the next read,
/// and that consecutive rows for one register agree on which register it is.
/// Both are written as `r_active * nr_active * r_same * (...)`, so `r_same = 0`
/// switches them off.
///
/// Nothing said when `r_same` was allowed to be zero. Not booleanity, not a
/// counterpart constraint, and not the LogUp argument, which never reads the
/// column at all. So the honest value was whatever the prover felt like
/// writing, and writing zero on the row before a read removed the requirement
/// that the read return what was written. Register values feed every
/// arithmetic constraint in the machine, so that is a free hand over the
/// inputs of any computation.
///
/// The memory table has the same shape and is not vulnerable, which is what
/// made this easy to miss on a read. There, `m_same = 0` is not free: a
/// separate constraint says the first read of a new address must return zero,
/// and it is gated on `(1 - m_same)`. Claiming "different address" therefore
/// costs the prover the value it wanted to invent. The register side has no
/// such rule, because registers have no equivalent of "first touch reads
/// zero", so the counterpart was never written and `r_same` was left with a
/// cost of nothing.
///
/// With this column, `r_same` is pinned to the equality it claims:
///
/// ```text
/// diff = nr_idx - r_idx
/// z    = diff * diff_inv          (boolean)
/// diff * (1 - z) == 0             (diff != 0 forces z = 1)
/// r_same == 1 - z                 (so r_same = 1 exactly when diff = 0)
/// ```
///
/// This is the same inverse-witness pattern already used for `Eq`/`Neq`
/// ([`COL_EQ_DIFF_INV`]) and for the Merkle root comparison
/// ([`COL_MERKLE_DIFF_INV`]). A separate column is needed rather than reusing
/// one of those: the register table is laid out on the same rows as the CPU
/// trace, so a `Eq` instruction and a register event share a row and would
/// otherwise fight over the same witness.
pub const COL_REG_SAME_INV: usize = 917;

/// Inverse witness for `rd_idx`, used to decide in-circuit whether an
/// instruction writes to r0.
///
/// r0 is the machine's constant zero. `bud-vm` enforces it directly
/// (`self.registers[0] = 0` after every step) and the trace builder used to
/// paper over it by writing `0` into `COL_RD_VAL_NEW` whenever `dst_idx == 0`.
/// The AIR said nothing at all. Measured: `rd_idx` and `rd_val_new` appear
/// together in exactly one place, the register LogUp tuple, which pairs them
/// without relating them.
///
/// That left two problems facing opposite directions.
///
/// Soundness: a prover could write any value it liked to r0 and publish a
/// matching register-table row. r0 is used across the tree as a source of
/// zero, in `Assert rs2 = r0`, in `Add rd, rs, r0` register moves, in the
/// `Load` immediate path keyed on `rs1_idx == 0`. A prover that can make r0
/// non-zero rewrites what all of those mean.
///
/// Completeness: the trace builder's own workaround made honest programs
/// unprovable. For `Add r0, r1, r2` the VM records `dst_val = 12`, the builder
/// wrote `COL_RD_VAL_NEW = 0`, and the AIR asked for
/// `rd_val_new == rs1_val + rs2_val`, that is `0 == 12`. Any program writing
/// to r0 could be executed and never proved. `bud-compiler` does not emit such
/// code today, so nothing in the tree hit it, but hand written bytecode does
/// and a future change to register allocation would.
///
/// Both are closed by moving the rule off `COL_RD_VAL_NEW` and onto the value
/// the row publishes on the register bus:
///
/// ```text
/// z          = rd_idx * rd_idx_inv        (boolean)
/// rd_idx * (1 - z) == 0                   (rd_idx != 0 forces z = 1)
/// rd_is_zero = 1 - z
/// bus value  = rd_val_new * (1 - rd_is_zero)
/// ```
///
/// So an r0 row computes its arithmetic result honestly, satisfying whichever
/// of the thirty-odd per opcode rules applies to it, and then contributes zero
/// to the register argument. A prover that puts a non-zero value in the
/// register table for r0 unbalances LogUp instead.
///
/// Gating the thirty rules on `rd_idx != 0` was the other option and was
/// rejected: a new opcode added without the guard is unprovable when it
/// targets r0, and nothing would say so.
pub const COL_RD_IDX_INV: usize = 918;

/// Marks a register-table row as describing state the program started from
/// rather than state it produced.
///
/// The register table records reads and writes as execution goes. A read that
/// happens before anything wrote that register is reading the *starting*
/// register file, and until this column existed nothing said what that file
/// contained. `Plonky3Adapter::prove` takes the trace, the public inputs and
/// the program, and the starting register file appears in none of them: two
/// runs beginning from different register contents produced proofs the same
/// public inputs would accept.
///
/// Today that is not reachable, because the only production path constructs
/// the VM through `Vm::new` and every register starts at zero. But that is a
/// property of one constructor, not something the proof states, and a
/// continuation mechanism or a call that carried registers across would make
/// it reachable without touching the AIR.
///
/// This is the register mirror of [`COL_MEM_IS_INIT`], and it is deliberately
/// the same shape: a flag on the first touch of an index when that touch is a
/// read of a non-zero value, folded into an accumulator the AIR checks against
/// a public input. Anything a prover invents about the starting registers has
/// to survive that check.
///
/// The flag is allowed on an active row only, and only on the first row of a
/// register block: the row after a row of the same register cannot carry it.
/// Before that rule a padding row or the middle of a block could carry the
/// flag and add an entry to the folded image that no first read backs.
pub const COL_REG_IS_INIT: usize = 919;

/// Running fold of every initial register row, checked against limbs 2 and 3
/// of `public_inputs.initial_state_root` on the last real row.
///
/// The memory image occupies limbs 0 and 1 of the same public input. Limbs 2
/// and 3 were carried into the trace and compared against a column the prover
/// filled from the public input itself, so nothing else touched them; the
/// register image goes there. Widening the public input instead would mean
/// changing `ExecutionPublicInputs`, which is declared twice and constructed
/// in 62 places across the chain, the CLI, the benchmarks and the fuzz targets,
/// for a commitment that fits in space already reserved and already carried.
///
/// Same fold as [`COL_MEM_INIT_ACC`], with the same caveat: fixed constants
/// rather than transcript challenges, so it binds accidental divergence and
/// any substitution that does not solve the system, not an adversary willing
/// to do that work. Replacing both sets of constants with challenges is one
/// change, not two, and is tracked with the memory one.
pub const COL_REG_INIT_ACC: usize = 920;

/// Inverse witness deciding, in circuit, whether a `Load` or `Store` row
/// addresses memory at all.
///
/// `Load rd, r0, imm` is the machine's load-immediate: it puts `imm` in `rd`
/// and touches no memory. Every other `Load` and every `Store` reads or writes
/// the word at `rs1_val + imm`. The memory argument has to tell those apart,
/// and the AIR was doing it with
///
/// ```text
/// is_real_mem_op = (is_load + is_store) * rs1_idx  (before the fix below)
/// ```
///
/// which is not a flag but a register number. On `Store r0, r7, r2` the
/// demand side of the memory LogUp is scaled by seven while the memory table
/// supplies the row once, and the prover mirrors the same line as a boolean.
/// The two sides then disagree for every base register except `r1`, so the
/// argument only balances on programs that happen to use `r1` as their
/// pointer. Every other honest program is unprovable, and the imbalance is a
/// prover-chosen quantity rather than a rejection, which is the wrong side of
/// the soundness line to be guessing on.
///
/// This is the same shape as [`COL_RD_IDX_INV`] and is deliberately spelled
/// the same way:
///
/// ```text
/// z            = rs1_idx * rs1_idx_inv     (boolean)
/// rs1_idx * (1 - z) == 0                   (rs1_idx != 0 forces z = 1)
/// is_real_mem_op = is_load * z + is_store
/// ```
///
/// so the multiplier is one or zero and never a register index. A `Store`
/// always writes memory, so it is not scaled by `z`; only `Load` with base r0
/// is load-immediate.
pub const COL_RS1_IDX_INV: usize = 921;

/// Inverse witnesses proving a bit decomposition is the canonical one.
///
/// `Lt`, `Gt`, `Lte`, `Gte`, `And`, `Or` and `Xor` all work on the 64 bit
/// columns rather than on the register value, and the only thing tying the
/// bits to the value is
///
/// ```text
/// sum(b_i * 2^i) == rs_val
/// ```
///
/// with each `b_i` boolean. That is not enough. Goldilocks is
/// `P = 2^64 - 2^32 + 1`, so `2^64 > P` and a 64 bit pattern can be at or
/// above the modulus and wrap. Two different bit strings then reconstitute to
/// the same field element:
///
/// ```text
/// rs_val = 5
///   honest      0x0000000000000005
///   alternative 0xFFFFFFFF00000006   (= 5 + P, still below 2^64)
/// ```
///
/// There are `2^64 - P = 2^32 - 1` values with a second representation. The
/// comparison reads the bits, so the prover picks which answer it gets:
/// against `rs2 = 100` the honest bits give `5 < 100 = 1` and the alternative
/// sets the top bit and gives `0`. A contract checking `balance >= amount`
/// through any of these opcodes has a check the prover decides.
///
/// The fix pins the decomposition to the canonical representative. A pattern
/// is at or above the modulus exactly when its high 32 bits are all ones and
/// its low 32 bits are not all zero, because `P = 0xFFFFFFFF_00000001`. With
///
/// ```text
/// hi = sum(b_i * 2^(i-32))  for i in 32..64
/// lo = sum(b_i * 2^i)       for i in 0..32
/// d  = hi - 0xFFFFFFFF
/// z  = d * d_inv            (boolean)
/// d * (1 - z) == 0          (d nonzero forces z = 1)
/// (1 - z) * lo == 0         (hi saturated forces lo = 0)
/// ```
///
/// the excluded patterns are exactly the non-canonical ones and the constraint
/// stays degree three. `d_inv` is the witness these columns carry, one per
/// operand.
pub const COL_CMP_RS1_HI_INV: usize = 922;
pub const COL_CMP_RS2_HI_INV: usize = 923;

/// Inverse witness proving an `Assert` row's condition is non-zero.
///
/// The VM refuses only on zero: `Assert` halts when `src1_val == 0` and
/// otherwise carries on, so every non-zero value passes. The AIR asked for
/// `assert_one(rs1_val)`, which is a different rule: it demands exactly 1.
///
/// The two agree on the values every test happened to use, `0` and `1`,
/// because `Eq` and the comparison opcodes produce those. They disagree on
/// everything else, and BudL's `constrain(...)` lowers straight to this
/// opcode, so `constrain(flags & MASK)` or `constrain(count)` is a contract
/// the VM runs and no prover can prove.
///
/// The direction is completeness, not soundness: the AIR was stricter than
/// the VM, so nothing false got through. Correct programs were rejected
/// instead, which is the failure mode that looks like the tooling being
/// broken rather than like an attack.
///
/// The rule the VM states is `rs1 != 0`, and that needs a witness:
///
/// ```text
/// z = rs1_val * assert_inv     (boolean)
/// rs1_val * (1 - z) == 0       (a non-zero condition forces z = 1)
/// z == 1                       (on Assert rows: the condition is non-zero)
/// ```
///
/// A separate column from [`COL_INV_ZERO`], which `Div`, `Inv` and `Not`
/// already share. Those three are mutually exclusive with each other by the
/// selector rules, and adding a fourth reader would work only for as long as
/// that stays true.
pub const COL_ASSERT_INV: usize = 924;

/// Boolean witness for "this `Syscall` row has `imm == 6`".
///
/// `Syscall` with `imm = 6` emits two events in the VM:
///
/// ```text
/// self.events.push(0x00A1_00A1);
/// self.events.push(src1_val);
/// ```
///
/// and the AIR's event digest only ever counted `Log` rows:
///
/// ```text
/// digest[i+1] = digest[i] + is_log[i+1] * rs1[i+1]
/// ```
///
/// So the two events the syscall announces never reached the digest, and the
/// public input, which the caller builds from `receipt.events`, carried them.
/// Measured with `src1 = 5`: the receipt digest is `10551462` and the trace
/// column reaches `0`, so the last-row comparison fails and no program using
/// this syscall can be proven at all.
///
/// The emission is not removable. `executor.rs` reads `0x00A1_00A1` as the
/// marker for an AI inference request and takes the model id, fee and
/// deadline from the events that follow it, so a contract calling this syscall
/// is how that request gets queued.
///
/// A separate boolean is needed because the existing `imm6_guard`,
/// `(imm-1)(imm-2)(imm-3)`, is not one: at `imm = 6` it evaluates to 60. That
/// is fine for gating an equality, which only cares whether the factor is
/// zero, and useless as a multiplier inside a sum. The digest needs to add the
/// contribution exactly once.
pub const COL_SYSCALL_IS_6: usize = 925;

/// Boolean witnesses for the remaining syscall numbers.
///
/// The AIR picked out each syscall with a polynomial that is zero on the
/// others:
///
/// ```text
/// sender       (imm-2)(imm-3)(imm-6)
/// block height (imm-1)(imm-3)(imm-6)
/// nonce        (imm-1)(imm-2)(imm-6)
/// unknown      (imm-1)(imm-2)(imm-3)(imm-6)
/// ```
///
/// Those are correct about the four numbers they name and wrong about every
/// other one. At `imm = 4` all four are non-zero, so the row is told to return
/// the sender, and the block height, and the nonce, and zero, at the same
/// time. They agree only when the three context values are zero, so a program
/// containing an unknown syscall cannot be proven on a chain where the sender
/// or the height or the nonce is anything but zero.
///
/// The VM is happy with those programs: an unrecognised `imm` returns zero and
/// execution continues. So this is completeness again, and it hid for the same
/// reason as the others, every fixture leaves the context zeroed.
///
/// A polynomial cannot fix it. What is wanted is "this row is syscall one",
/// which is a boolean, and the polynomial is only ever "this row is not
/// syscall two or three or six". Each number gets a witness pinned in both
/// directions, the same shape as [`COL_SYSCALL_IS_6`], and the unknown case is
/// then one minus the sum of the four.
pub const COL_SYSCALL_IS_1: usize = 926;
pub const COL_SYSCALL_IS_2: usize = 927;
pub const COL_SYSCALL_IS_3: usize = 928;

/// The Program CTL multiplicity witness: how many times pc=`i` appears in the
/// CPU trace, meaning how many times that instruction was executed.
///
/// The Program CTL is a *lookup*, not a permutation. With branching an instruction may
/// never run (a skipped branch) or run several times (a loop body). As long as
/// the fixed weight `pre_active` is used, an honest prover produces an
/// unbalanced LogUp sum and gets `InvalidProof`.
pub const COL_PROG_MULT: usize = 937;

/// The register table order witness: 32 bits of the step from this register
/// row to the next one.
///
/// The table must be sorted by `(idx, time)` with `time = clk * 4 + sub_clk`,
/// and every step must be strictly forward. For a pair of active rows the step
/// is `time' - time - 1` when both rows name one register, and
/// `idx' - idx - 1` when they do not. The bits sum to that step, so the step
/// is a 32 bit number. A step that goes backward is a field element near
/// 2^64 and has no 32 bit form. This is sound because `idx` is below 32 and
/// `time` is below 2^32, so no honest or forged step wraps into range.
pub const COL_REG_ORD_BITS_BASE: usize = 938;
pub const REG_ORD_BITS: usize = 32;

/// Inverse witness pinning `COL_MEM_SAME` to the cell equality it claims.
///
/// Same shape as [`COL_REG_SAME_INV`], over `diff = next_key - key`:
/// `diff * inv` is boolean, `diff * (1 - diff * inv) == 0`, and `m_same` equals
/// `1 - diff * inv`. Before this column a prover could write zero for
/// `m_same` on two rows of one address, turning off the value continuity
/// between them. The first read of the next block then only had to be zero.
pub const COL_MEM_SAME_INV: usize = 970;

/// The table a memory row belongs to: 1 memory, 2 stack, 3 storage.
///
/// The three regions used to share table id 1 and sit apart only by address
/// bases (`1 << 60` and `2 << 60`). Nothing bounded a `Load` address, so a
/// pointer of `1 << 60` named a stack cell. The id is now a column of its own
/// and a part of the sort key, and the address below it is 32 bit.
pub const COL_MEM_TID: usize = 971;

/// The 64 bits of canonical `COL_MEM_ADDR` (`0..32` low limb `a_lo`,
/// `32..64` high limb `a_hi`). Memory (`tid = 1`) and stack (`tid = 2`)
/// addresses enforce `a_hi == 0` so cell indices stay below `2^32`; storage
/// rows (`tid = 3`) span the full canonical Goldilocks field so Poseidon-derived
/// `Map<K, V>` slots execute and verify identically.
pub const COL_MEM_ADDR_BITS_BASE: usize = 972;
pub const MEM_ADDR_BITS: usize = 64;

/// Inverse witness for `0xFFFF_FFFF - a_hi`, enforcing canonical Goldilocks
/// representation (`a_hi == 0xFFFF_FFFF ==> a_lo == 0`).
pub const COL_MEM_HI_MAX_INV: usize = 1036;

/// Boolean flag and inverse witness pinning `m_top_same == (ntop == top)` where
/// `top = tid * 2^32 + a_hi < 2^34` across consecutive live memory rows.
pub const COL_MEM_TOP_SAME: usize = 1037;
pub const COL_MEM_TOP_SAME_INV: usize = 1038;

/// The memory table order witness: 34 bits of the step from this row to the
/// next one across lexicographic `(top, a_lo, clk)` where
/// `top = tid * 2^32 + a_hi < 2^34`, `a_lo < 2^32`, and `clk < 2^20`.
pub const COL_MEM_ORD_BITS_BASE: usize = 1039;
pub const MEM_ORD_BITS: usize = 34;

/// Fold constants for [`COL_REG_INIT_ACC`].
///
/// Deliberately different from the memory constants. Sharing them would let a
/// register row and a memory row with the same `(index, value)` produce the
/// same contribution, so a prover could move a seeded value from one image to
/// the other without changing either accumulator.
pub const REG_INIT_BETA: u64 = 0xD1B5_4A32_D192_ED03;
pub const REG_INIT_GAMMA: u64 = 0xA24B_AED4_963E_E407;

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
        // PC, RAW_INST, IS_ACTIVE, then the decoded fields OPCODE, RD, RS1,
        // RS2, IMM.
        //
        // Each decoded field is computed here from the program the verifier
        // already committed to, so the Program CTL tuple can carry them. See
        // the decode comment in `eval` for why carrying the whole word was not
        // enough: nothing tied the CPU trace's decode columns back to
        // `COL_RAW_INST`, and splitting the word inside the AIR would need a
        // range check this machine does not have.
        //
        // `imm` goes through `bud_isa::decode_any` rather than a mask written
        // out here. The trace stores a negative immediate as `P - |imm|`, and
        // reproducing that from the raw bits means repeating the sign
        // reinterpretation the decoder already performs. Two copies of that
        // rule is one copy too many: if they ever disagree the honest prover
        // is the one that fails.
        let mut values = vec![F::ZERO; degree * PREPROCESSED_WIDTH];
        for i in 0..degree {
            let pc = i as u64;
            let inst = self.program.get(i).copied().unwrap_or(0);
            let active = if i < self.program.len() {
                F::ONE
            } else {
                F::ZERO
            };
            // A word that does not decode contributes zero for the immediate.
            // Such a row can never be matched by a CPU row anyway: the VM
            // refuses to step on it, so no trace row carries that pc.
            let imm = bud_isa::Instruction::decode_any(inst)
                .map(|d| d.imm)
                .unwrap_or(0);
            let imm_field = if imm < 0 {
                F::ZERO - F::from_u64((-(imm as i64)) as u64)
            } else {
                F::from_u64(imm as u64)
            };
            values[i * PREPROCESSED_WIDTH] = F::from_u64(pc);
            values[i * PREPROCESSED_WIDTH + 1] = F::from_u64(inst);
            values[i * PREPROCESSED_WIDTH + 2] = active;
            values[i * PREPROCESSED_WIDTH + 3] = F::from_u64(inst & 0xFF);
            values[i * PREPROCESSED_WIDTH + 4] = F::from_u64((inst >> 8) & 0x1F);
            values[i * PREPROCESSED_WIDTH + 5] = F::from_u64((inst >> 13) & 0x1F);
            values[i * PREPROCESSED_WIDTH + 6] = F::from_u64((inst >> 18) & 0x1F);
            values[i * PREPROCESSED_WIDTH + 7] = imm_field;
        }
        Some(p3_matrix::dense::RowMajorMatrix::new(
            values,
            PREPROCESSED_WIDTH,
        ))
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn num_public_values(&self) -> usize {
        56
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

        let storage_delta: AB::Expr = imm.clone() + one.clone();
        let storage_delta_z: AB::Expr = storage_delta.clone() * cur[COL_STORAGE_SLOT_INV].into();
        let is_dynamic_slot: AB::Expr = one.clone() - storage_delta_z.clone();
        let storage_slot: AB::Expr = is_dynamic_slot.clone() * rs2_val.clone()
            + (one.clone() - is_dynamic_slot) * imm.clone();

        let is_add: AB::Expr = cur[COL_IS_ADD].into();
        let is_sub: AB::Expr = cur[COL_IS_SUB].into();
        let is_mul: AB::Expr = cur[COL_IS_MUL].into();
        let is_div: AB::Expr = cur[COL_IS_DIV].into();
        let is_inv: AB::Expr = cur[COL_IS_INV].into();
        let is_and: AB::Expr = cur[COL_IS_AND].into();
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
        let is_privacy_commit: AB::Expr = cur[COL_IS_PRIVACY_COMMIT].into();
        let is_nullifier_check: AB::Expr = cur[COL_IS_NULLIFIER_CHECK].into();
        let is_sum_conservation: AB::Expr = cur[COL_IS_SUM_CONSERVATION].into();
        let is_verify_inference: AB::Expr = cur[COL_IS_VERIFY_INFERENCE].into();
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
            + is_verify_merkle.clone()
            + is_privacy_commit.clone()
            + is_nullifier_check.clone()
            + is_sum_conservation.clone();

        let is_cpu = is_real_op.clone() + is_halt.clone();

        // 1. Selector Booleanity
        builder.assert_bool(is_add.clone());
        builder.assert_bool(is_sub.clone());
        builder.assert_bool(is_mul.clone());
        builder.assert_bool(is_div.clone());
        builder.assert_bool(is_inv.clone());
        builder.assert_bool(is_and.clone());
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
        // Reserved opcode 0x1F: the selector and the expansion flag are zero
        // on every row. A row that carries opcode 0x1F then matches no
        // selector, so the exclusivity sum below cannot reach one.
        builder.assert_zero(is_verify_inference.clone());
        builder.assert_zero(cur[COL_INFERENCE_IS_EXPAND].into());
        builder.assert_bool(is_privacy_commit.clone());
        builder.assert_bool(is_nullifier_check.clone());
        builder.assert_bool(is_sum_conservation.clone());
        builder.assert_bool(is_halt.clone());

        // 2. Selector Exclusivity
        builder.assert_eq(is_cpu.clone(), one.clone());

        // 3. Selector <-> opcode binding, for every selector.
        //
        // Booleanity plus exclusivity says exactly one selector is set. It
        // does not say *which* one, and until this constraint existed nothing
        // else did either for 29 of the 35. Six had a binding written by hand
        // (Poseidon 0x19, VerifyMerkle 0x1E, VerifyInference 0x1F,
        // PrivacyCommit 0x20, NullifierCheck 0x21, SumConservation 0x22),
        // each added when the opcode it guards was audited. The other 29 were
        // free: a prover could take an honest `Assert` row and set
        // `is_assert = 0, is_mul = 1` instead.
        //
        // That forgery passed everything. `Mul` demands
        // `rd_val_new = rs1_val * rs2_val`, and an Assert row carries
        // `rd_val_new = 0` with `rs2_val = 0`, so `0 = x * 0` holds for any
        // `rs1_val`. Both opcodes fall through to the same unit gas cost, both
        // sit inside `is_real_op` so exclusivity still sums to one, and
        // neither the register nor the memory nor the program argument reads
        // the selector in a way that would notice. The row that was supposed
        // to enforce `assert_one(rs1_val)` simply stopped being an Assert row,
        // and `constrain(...)` in BudL, which is what `Assert` compiles from,
        // became a no-op the prover could switch off per call.
        //
        // The same substitution works the other way for anything whose
        // constraint is satisfiable at the honest row's values, so this is not
        // one bad pair, it is a missing invariant. Rather than write 29 more
        // hand bindings and leave the next opcode to be added unbound by
        // default, the sum below covers all of them at once: each selector
        // multiplied by the difference between the row's opcode and the
        // constant it stands for. Exactly one term is live per row, and it
        // forces the opcode to match. A new selector added without a line here
        // makes `is_cpu` sum to one while contributing nothing to the sum, and
        // `check-air-selectors-are-opcode-bound.sh` fails the build for it.
        let opcode_here: AB::Expr = cur[COL_OPCODE].into();
        let op = |v: u64| AB::Expr::from(AB::F::from_u64(v));
        let selector_opcode_binding = is_halt.clone() * (opcode_here.clone() - op(0x00))
            + is_add.clone() * (opcode_here.clone() - op(0x01))
            + is_sub.clone() * (opcode_here.clone() - op(0x02))
            + is_mul.clone() * (opcode_here.clone() - op(0x03))
            + is_div.clone() * (opcode_here.clone() - op(0x04))
            + is_inv.clone() * (opcode_here.clone() - op(0x05))
            + is_and.clone() * (opcode_here.clone() - op(0x06))
            + is_not.clone() * (opcode_here.clone() - op(0x09))
            + is_eq.clone() * (opcode_here.clone() - op(0x0A))
            + is_neq.clone() * (opcode_here.clone() - op(0x0B))
            + is_lt.clone() * (opcode_here.clone() - op(0x0C))
            + is_gt.clone() * (opcode_here.clone() - op(0x0D))
            + is_lte.clone() * (opcode_here.clone() - op(0x0E))
            + is_gte.clone() * (opcode_here.clone() - op(0x0F))
            + is_jmp.clone() * (opcode_here.clone() - op(0x10))
            + is_jnz.clone() * (opcode_here.clone() - op(0x11))
            + is_call.clone() * (opcode_here.clone() - op(0x12))
            + is_ret.clone() * (opcode_here.clone() - op(0x13))
            + is_load.clone() * (opcode_here.clone() - op(0x14))
            + is_store.clone() * (opcode_here.clone() - op(0x15))
            + is_push.clone() * (opcode_here.clone() - op(0x16))
            + is_pop.clone() * (opcode_here.clone() - op(0x17))
            + is_assert.clone() * (opcode_here.clone() - op(0x18))
            + is_poseidon.clone() * (opcode_here.clone() - op(0x19))
            + is_log.clone() * (opcode_here.clone() - op(0x1A))
            + is_sread.clone() * (opcode_here.clone() - op(0x1B))
            + is_swrite.clone() * (opcode_here.clone() - op(0x1C))
            + is_syscall.clone() * (opcode_here.clone() - op(0x1D))
            + is_verify_merkle.clone() * (opcode_here.clone() - op(0x1E))
            + is_verify_inference.clone() * (opcode_here.clone() - op(0x1F))
            + is_privacy_commit.clone() * (opcode_here.clone() - op(0x20))
            + is_nullifier_check.clone() * (opcode_here.clone() - op(0x21))
            + is_sum_conservation.clone() * (opcode_here.clone() - op(0x22));
        builder.assert_zero(selector_opcode_binding);

        builder
            .when_transition()
            .assert_zero(is_cpu.clone() * (nxt_clk.clone() - clk.clone() - one.clone()));
        builder
            .when_transition()
            .assert_zero(is_cpu.clone() * (nxt_pc.clone() - next_pc.clone()));

        // Control flow: where `next_pc` may point.
        //
        // The line above only says the next row sits at this row's `next_pc`.
        // `next_pc` itself was constrained for the jumps, calls, `Push`,
        // `Pop` and `Halt`, and for `Ret` through the stack tuple; every
        // other opcode left it to the prover, so a fall-through could land
        // anywhere the program table has a row and the instructions in
        // between were never executed. Two rules close it.
        //
        // A row stays on its pc only while it is part of a multi-row
        // instruction: a `VerifyMerkle` row whose successor is one of its
        // own expansion rows. The expansion rows are
        // the only rows that share a pc, and each expansion row has to be
        // preceded by a row of the same opcode, so the flag cannot be raised
        // anywhere else.
        let exp_merkle: AB::Expr = cur[COL_VM_MERKLE_IS_EXPAND].into();
        let nxt_exp_merkle: AB::Expr = nxt[COL_VM_MERKLE_IS_EXPAND].into();
        builder.when_last_row().assert_one(is_halt.clone());
        builder.when_first_row().assert_zero(exp_merkle.clone());
        builder
            .when_transition()
            .assert_zero(nxt_exp_merkle.clone() * (one.clone() - is_verify_merkle.clone()));
        let stays_on_pc: AB::Expr = is_verify_merkle.clone() * nxt_exp_merkle;
        builder
            .when_transition()
            .assert_zero(stays_on_pc.clone() * (next_pc.clone() - pc.clone()));
        // Everything else that does not branch, stop or return falls through
        // to the next instruction. The branching opcodes keep their own rules
        // below (`Jmp`, `Call`, `Jnz`) or are bound through the stack tuple
        // (`Ret`); `Halt` is held in place by its own transition.
        builder.when_transition().assert_zero(
            (one.clone()
                - is_jmp.clone()
                - is_jnz.clone()
                - is_call.clone()
                - is_ret.clone()
                - is_halt.clone()
                - stays_on_pc)
                * (next_pc.clone() - pc.clone() - one.clone()),
        );

        // Cpu_active transition and boundary constraints
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
        // Equation above is vacuous when rs2 = 0 (both sides are 0), so a
        // Malicious prover could otherwise pick an arbitrary quotient. Pin
        // Rd to 0 in the div-by-zero case to match the VM.
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
        // Equation above is vacuous when rs1 = 0, so pin rd to 0 in the
        // Inverse-of-zero case to match the VM (otherwise a malicious
        // Prover could pick an arbitrary result).
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

        // `Load rd, r0, imm` is load-immediate: the destination takes the
        // immediate and no memory is touched. Every other `Load` reads the
        // word at `rs1_val + imm`, so this rule must be off for those rows.
        //
        // The guard used to be `is_load * (1 - rs1_idx)`, which is a register
        // number subtracted from one rather than the boolean "rs1 is r0". At
        // `rs1_idx = 7` the coefficient is `-6`, non-zero, so the rule fires on
        // a row it was written to skip and demands `rd_val_new == imm` of a
        // read that returns whatever memory held. No honest proof exists for
        // it. The same expression is also what a prover would exploit in the
        // other direction: the multiplier is a field element the prover
        // supplies, so the rule that defines load-immediate is switched on and
        // off by a value the circuit does not pin.
        //
        // `rs1_idx_z` is that boolean, derived through the inverse witness in
        // `COL_RS1_IDX_INV` and pinned there. `1 - rs1_idx_z` is exactly
        // "rs1 is r0".
        let rs1_idx: AB::Expr = cur[COL_RS1_IDX].into();
        let rs1_idx_inv_cpu: AB::Expr = cur[COL_RS1_IDX_INV].into();
        let rs1_idx_z_cpu = rs1_idx.clone() * rs1_idx_inv_cpu;
        builder.assert_bool(rs1_idx_z_cpu.clone());
        builder.assert_zero(rs1_idx.clone() * (one.clone() - rs1_idx_z_cpu.clone()));
        builder
            .when(is_load.clone() * (one.clone() - rs1_idx_z_cpu.clone()))
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

        // Assert passes on any non-zero condition, which is what the VM does.
        // See `COL_ASSERT_INV` for why `assert_one` was wrong.
        {
            let assert_inv: AB::Expr = cur[COL_ASSERT_INV].into();
            let assert_z = rs1_val.clone() * assert_inv;
            builder
                .when(is_assert.clone())
                .assert_bool(assert_z.clone());
            builder
                .when(is_assert.clone())
                .assert_zero(rs1_val.clone() * (one.clone() - assert_z.clone()));
            builder.when(is_assert).assert_one(assert_z);
        }

        // (security audit) the `is_verify_merkle`
        // Selector is now a *deterministic* function of `COL_OPCODE`.
        // A malicious prover can no longer set `is_verify_merkle = 0`
        // To bypass the constraint on a row where COL_OPCODE = 0x1E;
        // The AIR forces the selector to be 1 whenever the opcode is
        // 0x1E.
        //
        // This selector binding was once the only layer. The path itself
        // Is now recomputed in-circuit as well: siblings and direction
        // Bits live in the expansion rows, the Poseidon chain is
        // Constrained per round, `COL_MERKLE_KEY_REM` binds the bits to
        // `merkle_key`, and the LogUp memory argument binds the siblings
        // To the memory they were read from. See the `COL_MERKLE_KEY_REM`
        // Shift chain further down in this file.
        let opcode_verify_merkle: AB::Expr = AB::Expr::from(AB::F::from_u64(0x1E));
        let opcode_at_row: AB::Expr = cur[COL_OPCODE].into();
        // `is_verify_merkle = 1` ⇒ `COL_OPCODE = 0x1E`
        // (the converse is not required: rows with other opcodes may
        // Freely have is_verify_merkle = 0).
        builder.assert_zero(
            is_verify_merkle.clone() * (opcode_at_row.clone() - opcode_verify_merkle.clone()),
        );
        // VerifyMerkle: result is boolean (0 or 1)
        builder
            .when(is_verify_merkle.clone())
            .assert_bool(rd_val_new.clone());

        // Merkle expansion rows.
        //
        // A `VerifyMerkle` is one original row (it carries the key) followed by
        // `MERKLE_ROUNDS` expansion rows, one per word of the path window
        // `[key, leaf[4], 64 x sibling[4], root[4]]`. The rows come in groups of four,
        // because a 256-bit node is four words and the memory argument carries one event
        // per row:
        //
        //   group 0         the leaf: the four words become the held node
        //   groups 1..=64   a level: the four words are the sibling, and the last row of
        //                   the group (`COL_MERKLE_HASH`) runs the Poseidon gadget on the
        //                   node and the sibling, ordered by the key bit; the output is
        //                   the node of the next row
        //   group 65        the root: each row compares one word of the held node with
        //                   the word it reads, and the last row hands the product of the
        //                   comparisons to the `rd` value the original row carries
        //
        // The words reach the memory argument through `COL_VM_MERKLE_SIBLING` and the
        // address `imm + 8 + 8 * round`, so nothing the walk consumes is chosen by the
        // prover.
        let is_expand: AB::Expr = cur[COL_VM_MERKLE_IS_EXPAND].into();
        builder.assert_bool(is_expand.clone());
        let nxt_is_expand: AB::Expr = nxt[COL_VM_MERKLE_IS_EXPAND].into();

        let merkle_round: AB::Expr = cur[COL_VM_MERKLE_ROUND].into();
        let nxt_merkle_round: AB::Expr = nxt[COL_VM_MERKLE_ROUND].into();
        let merkle_key: AB::Expr = cur[COL_VM_MERKLE_KEY].into();
        let merkle_bit: AB::Expr = cur[COL_VM_MERKLE_BIT].into();
        let merkle_word: AB::Expr = cur[COL_VM_MERKLE_SIBLING].into();
        let leafg: AB::Expr = cur[COL_MERKLE_LEAFG].into();
        let rootg: AB::Expr = cur[COL_MERKLE_ROOTG].into();
        let nxt_leafg: AB::Expr = nxt[COL_MERKLE_LEAFG].into();
        let nxt_rootg: AB::Expr = nxt[COL_MERKLE_ROOTG].into();
        let merkle_hash: AB::Expr = cur[COL_MERKLE_HASH].into();
        let cu = |i: usize| -> AB::Expr { cur[i].into() };
        let oh: Vec<AB::Expr> = (0..4).map(|k| cur[COL_MERKLE_OH + k].into()).collect();
        let nxt_oh: Vec<AB::Expr> = (0..4).map(|k| nxt[COL_MERKLE_OH + k].into()).collect();
        let nxt_pathg: AB::Expr = nxt_is_expand.clone() - nxt_leafg.clone() - nxt_rootg.clone();
        let merkle_rows_before_root: AB::Expr =
            AB::Expr::from(AB::F::from_u64((MERKLE_ROUNDS - 4) as u64));
        let merkle_last_round: AB::Expr =
            AB::Expr::from(AB::F::from_u64((MERKLE_ROUNDS - 1) as u64));
        let two: AB::Expr = AB::Expr::from(AB::F::from_u8(2));
        let on_original: AB::Expr = is_verify_merkle.clone() * (one.clone() - is_expand.clone());

        // The block is closed on both sides.
        //
        // An expansion row has to be a `VerifyMerkle` row: the flag switches off the
        // program lookup, the register argument and the gas charge, and without this
        // it could be raised on any other opcode. An original row has to be followed
        // by its expansion rows: the result on it is only worth anything when the path
        // behind it was walked.
        builder.assert_zero(is_expand.clone() * (one.clone() - is_verify_merkle.clone()));
        builder
            .when_transition()
            .assert_zero(on_original.clone() * (one.clone() - nxt_is_expand.clone()));
        // The path buffer address is one value for the whole path. Each expansion row
        // derives its memory address from `imm`, which is exempt from the program table
        // on an expansion row.
        builder.when_transition().assert_zero(
            is_verify_merkle.clone() * nxt_is_expand.clone() * (nxt[COL_IMM].into() - imm.clone()),
        );
        // The path key is one value for the whole path.
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

        // The direction bit is boolean, and the group kinds partition the expansion rows.
        builder
            .when(is_expand.clone())
            .assert_bool(merkle_bit.clone());
        builder.assert_bool(leafg.clone());
        builder.assert_bool(rootg.clone());
        builder.assert_bool(is_expand.clone() - leafg.clone() - rootg.clone());

        // The word index is one-hot on expansion rows (and zero elsewhere), it rotates by
        // one each row, and `COL_MERKLE_HASH` is the last word of a path group.
        let mut oh_sum: AB::Expr = AB::Expr::ZERO;
        for o in oh.iter().take(4) {
            builder.assert_bool(o.clone());
            oh_sum += o.clone();
        }
        builder.assert_eq(oh_sum, is_expand.clone());
        let path_g: AB::Expr = is_expand.clone() - leafg.clone() - rootg.clone();
        builder.assert_eq(merkle_hash.clone(), path_g * oh[3].clone());

        // Original row -> first expansion row: round 0, the leaf group, word 0, and the
        // `rd` value starts its journey to the last row.
        builder
            .when_transition()
            .when(on_original.clone())
            .when(nxt_is_expand.clone())
            .assert_zero(nxt_merkle_round.clone());
        builder
            .when_transition()
            .when(on_original.clone())
            .when(nxt_is_expand.clone())
            .assert_one(nxt_leafg.clone());
        builder
            .when_transition()
            .when(on_original.clone())
            .when(nxt_is_expand.clone())
            .assert_one(nxt_oh[0].clone());
        builder
            .when_transition()
            .when(on_original.clone())
            .when(nxt_is_expand.clone())
            .assert_eq(nxt[COL_MERKLE_RESULT].into(), rd_val_new.clone());

        // Expansion row -> expansion row.
        // The round counts up by one, the word index rotates, the result is carried.
        builder
            .when_transition()
            .when(cpu_active.clone())
            .assert_zero(
                is_expand.clone()
                    * nxt_is_expand.clone()
                    * (nxt_merkle_round.clone() - merkle_round.clone() - one.clone()),
            );
        for k in 0..4 {
            builder
                .when_transition()
                .when(is_expand.clone())
                .when(nxt_is_expand.clone())
                .assert_eq(nxt_oh[(k + 1) % 4].clone(), oh[k].clone());
        }
        builder
            .when_transition()
            .when(is_expand.clone())
            .when(nxt_is_expand.clone())
            .assert_eq(nxt[COL_MERKLE_RESULT].into(), cur[COL_MERKLE_RESULT].into());
        // The buffer keeps every slot the next row does not write.
        for k in 0..4 {
            builder
                .when_transition()
                .when(is_expand.clone())
                .when(nxt_is_expand.clone())
                .when(one.clone() - nxt_oh[k].clone())
                .assert_eq(
                    nxt[COL_MERKLE_BUF + k].into(),
                    cur[COL_MERKLE_BUF + k].into(),
                );
        }
        // The word this row reads is the slot of the buffer its index names.
        let mut buffered: AB::Expr = AB::Expr::ZERO;
        for (k, o) in oh.iter().enumerate().take(4) {
            buffered += o.clone() * cu(COL_MERKLE_BUF + k);
        }
        builder
            .when(is_expand.clone())
            .assert_eq(merkle_word.clone(), buffered);

        // Inside a group the node, the group kind, the bit and the remaining key stay.
        for k in 0..4 {
            builder
                .when_transition()
                .when(is_expand.clone())
                .when(nxt_is_expand.clone())
                .when(one.clone() - oh[3].clone())
                .assert_eq(
                    nxt[COL_MERKLE_CUR + k].into(),
                    cur[COL_MERKLE_CUR + k].into(),
                );
        }
        for (now, next) in [
            (leafg.clone(), nxt_leafg.clone()),
            (rootg.clone(), nxt_rootg.clone()),
            (merkle_bit.clone(), nxt[COL_VM_MERKLE_BIT].into()),
            (
                cur[COL_MERKLE_KEY_REM].into(),
                nxt[COL_MERKLE_KEY_REM].into(),
            ),
        ] {
            builder
                .when_transition()
                .when(is_expand.clone())
                .when(nxt_is_expand.clone())
                .when(one.clone() - oh[3].clone())
                .assert_eq(next, now);
        }

        // The group kinds move at a group boundary only: the leaf group is the first
        // group, the root group starts exactly after 64 levels (its first row is round
        // `MERKLE_ROUNDS - 4`) and, once started, never ends.
        builder
            .when_transition()
            .when(is_expand.clone())
            .when(oh[3].clone())
            .assert_zero(nxt_leafg.clone());
        builder
            .when_transition()
            .when(is_expand.clone())
            .when(nxt_is_expand.clone())
            .assert_zero(
                (nxt_rootg.clone() - rootg.clone())
                    * (nxt_merkle_round.clone() - merkle_rows_before_root.clone()),
            );
        builder
            .when_transition()
            .when(is_expand.clone())
            .when(nxt_is_expand.clone())
            .assert_zero(rootg.clone() * (one.clone() - nxt_rootg.clone()));
        // The last expansion row is the last row of the window and belongs to the root.
        builder.when_transition().assert_zero(
            is_expand.clone()
                * (one.clone() - nxt_is_expand.clone())
                * (merkle_round.clone() - merkle_last_round.clone()),
        );
        builder.when_transition().assert_zero(
            is_expand.clone()
                * (one.clone() - nxt_is_expand.clone())
                * (one.clone() - rootg.clone()),
        );

        // The held node. The last leaf row hands the buffer over; the last row of a
        // path group hands over the gadget output (the constraint sits with the gadget).
        for k in 0..4 {
            builder
                .when_transition()
                .when(leafg.clone() * oh[3].clone())
                .assert_eq(
                    nxt[COL_MERKLE_CUR + k].into(),
                    cur[COL_MERKLE_BUF + k].into(),
                );
        }

        // The remaining key. The first path row starts it at the whole key; each level
        // halves it, `rem == 2 * rem' + bit`; the last level ends it, `rem == bit`. With
        // `bit` boolean that is one step of binary long division, so the chain forces
        // `bit == (key >> level) & 1` and, by ending after exactly 64 levels, pins `key`
        // to 64 bits.
        builder
            .when_transition()
            .when(leafg.clone() * oh[3].clone())
            .assert_eq(
                nxt[COL_MERKLE_KEY_REM].into(),
                nxt[COL_VM_MERKLE_KEY].into(),
            );
        builder
            .when_transition()
            .when(merkle_hash.clone())
            .when(nxt_pathg.clone())
            .assert_zero(
                cu(COL_MERKLE_KEY_REM)
                    - two.clone() * nxt[COL_MERKLE_KEY_REM].into()
                    - merkle_bit.clone(),
            );
        builder
            .when_transition()
            .when(merkle_hash.clone())
            .when(nxt_rootg.clone())
            .assert_eq(cur[COL_MERKLE_KEY_REM].into(), merkle_bit.clone());

        // The root group: one word per row. `held` is the word of the node the row's
        // index names, `diff` its difference from the word read, and `COL_MERKLE_EQ` is 1
        // exactly when they are equal (an inverse witness, as for `Eq`).
        let mut held: AB::Expr = AB::Expr::ZERO;
        for (k, o) in oh.iter().enumerate().take(4) {
            held += o.clone() * cu(COL_MERKLE_CUR + k);
        }
        let diff: AB::Expr = held - merkle_word.clone();
        let eq: AB::Expr = cur[COL_MERKLE_EQ].into();
        builder
            .when(rootg.clone())
            .assert_eq(eq.clone(), one.clone() - diff.clone() * cu(COL_MERKLE_DINV));
        builder.when(rootg.clone()).assert_zero(diff * eq.clone());
        // The running product: it starts at the first root row and the last row hands it
        // to the result.
        builder
            .when_transition()
            .when(one.clone() - rootg.clone())
            .when(nxt_rootg.clone())
            .assert_eq(nxt[COL_MERKLE_ACC].into(), nxt[COL_MERKLE_EQ].into());
        builder
            .when_transition()
            .when(rootg.clone())
            .when(nxt_rootg.clone())
            .assert_eq(
                nxt[COL_MERKLE_ACC].into(),
                cu(COL_MERKLE_ACC) * nxt[COL_MERKLE_EQ].into(),
            );
        builder.when_transition().assert_zero(
            is_expand.clone()
                * (one.clone() - nxt_is_expand.clone())
                * (cu(COL_MERKLE_RESULT) - cur[COL_MERKLE_ACC].into()),
        );

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

        // (security audit) termination constraint.
        //
        // The transition 1 -> 0 for `cpu_active` is allowed ONLY on a Halt
        // Row. In normal execution every transition is 1 -> 1; the only
        // 1 -> 0 transition is the move from the last real step into the
        // Padding (cpu_active = 0, is_halt = 1) zone. By forcing that
        // Transition to land on a row where `is_halt = 1`, we rule out the
        // "the program was cut short without Halting" attack and pair with
        // The VM-side guarantee that the last real step is always Halt
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
        // SRead=8, SWrite=12 (must match Vm::gas_cost).
        let gas_cost = is_load.clone() * three.clone()
            + is_store.clone() * three.clone()
            + is_sread.clone() * eight.clone()
            + is_swrite.clone() * twelve.clone()
            + is_poseidon.clone() * ten.clone()
            // Expansion rows reuse opcode 0x1E but must not re-charge gas.
            + is_verify_merkle.clone() * (one.clone() - is_expand.clone()) * ten.clone()
            // Privacy opcodes share Poseidon gas cost (10).
            + is_privacy_commit.clone() * ten.clone()
            + is_nullifier_check.clone() * ten.clone()
            + is_sum_conservation.clone() * ten.clone()
            + is_call.clone() * two.clone()
            + is_ret.clone() * two.clone()
            + is_push.clone() * two.clone()
            + is_pop.clone() * two.clone()
            + is_syscall.clone() * five.clone()
            // Div is the binary long division (64 rows); priced with the heavy
            // ops, so the AIR's gas arithmetic matches Vm::gas_cost.
            + is_div.clone() * ten.clone()
            + (one.clone()
                - is_load.clone()
                - is_store.clone()
                - is_sread.clone()
                - is_swrite.clone()
                - is_poseidon.clone()
                - is_verify_merkle.clone()
                - is_privacy_commit.clone()
                - is_nullifier_check.clone()
                - is_sum_conservation.clone()
                - is_call.clone()
                - is_ret.clone()
                - is_push.clone()
                - is_pop.clone()
                - is_syscall.clone()
                - is_div.clone()
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

        // (security audit) bind the remaining public
        // Inputs to trace columns so a malicious prover cannot set
        // Them freely.
        //
        // Layout reminder (matching `to_public_values`):
        //   [0,1]   chain_id
        //   [2..10] program_hash (already bound via Program CTL LogUp)
        //   [10..18] initial_state_root
        //   [18..26] final_state_root
        //   [26,27] sender (bound via syscall, kept)
        //   [28,29] nonce (bound via syscall, kept)
        //   [30,31] block_height (bound via syscall, kept)
        //   [32,33] gas_limit
        //   [34,35] gas_used (already bound on last row, kept)
        //   [36,37] exit_code
        //   [38,39] trace_len
        //   [40..48] event_digest (bound)
        //   [48..56] state_writes_digest (bound)
        //
        // We compare one 32-bit limb at a time, so each side has only
        // A `public_inputs[i]` and a `cur[COL...]` - no `<< 32j`
        // Shifts that would overflow a u64 in Rust.

        // (1b) initial memory image: last real row, the fold equals the low
        // 64 bits of `initial_state_root`.
        //
        // `initial_state_root` was a public input nothing constrained, every
        // caller passed zeroes and the AIR compared them against a column the
        // prover also filled with zeroes. It now carries the commitment to the
        // memory image the program started from, which is what lets a
        // host-seeded guest be proven at all.
        //
        // Checked on the very last row rather than on the last CPU row, for
        // the reason spelled out under the register image below. The memory
        // table is not the CPU table: its length is the number of memory
        // events, and nothing in the AIR says that number is at most the
        // number of CPU rows.
        //
        // It happens to be, today. Measured: three opcodes set `memory_addr`
        // on their step (`Load`, `Store`, `VerifyMerkle`; `SumConservation`
        // reads no memory despite carrying a memory slot in older comments)
        // and six push an extra event from the stack or storage buffers
        // (`Push`, `Pop`, `Call`, `Ret`, `SRead`, `SWrite`); the two sets do
        // not intersect, so one step contributes at most one memory event and
        // `n_mem <= n_cpu` holds. That is a property of the current opcode
        // table, not something this AIR states, and the register table taught
        // us what the failure looks like: three register events per step made
        // `n_reg > n_cpu`, the accumulator was still mid-fold when the CPU
        // side reached its Halt, and four honest proofs stopped verifying.
        // The opcode that pairs a `memory_addr` with a stack push would do
        // the same here, silently, to a constraint nobody was editing.
        //
        // The prover holds the finished fold across the padding, so the last
        // row carries the whole commitment whichever table is longer, and
        // moving the check costs nothing while it stays true.
        {
            let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let expected = public_inputs[10].into()
                + public_inputs[11].into() * AB::Expr::from(AB::F::from_u64(1u64 << 32));
            builder.when_last_row().assert_eq(acc_last, expected);
        }

        // (1c) initial register image: the fold equals limbs 2 and 3 of
        // `initial_state_root`.
        //
        // Limbs 0 and 1 carry the memory image. Limbs 2 and 3 were carried
        // into the trace and compared against a column the prover filled from
        // the public input itself, so nothing else constrained them; the
        // register image goes there rather than widening the public input,
        // which is declared twice and constructed in 62 places.
        //
        // Checked on the very last row rather than on the last CPU row. The
        // register table is not the same length as the CPU table: one step
        // contributes three register events, so a two-instruction program has
        // two CPU rows and three register rows, and the accumulator is still
        // mid-fold when the CPU side reaches its Halt. Measured by CI, which
        // failed `d2_proves_nullifier_check_invalid_secret` on exactly that
        // shape. The prover holds the finished value across the padding, so
        // the last row carries the whole commitment whichever table is longer.
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into()
                + public_inputs[13].into() * AB::Expr::from(AB::F::from_u64(1u64 << 32));
            builder.when_last_row().assert_eq(acc_last, expected);
        }

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

        // (2a) The final root is the storage-writes fold: last real row,
        //      COL_FINAL_ROOT_0..7 == COL_STATE_WRITES_0..7.
        //
        //      The AIR has no final-image fold yet (BLG-0232): nothing
        //      derives a post-state root from last accesses, so on its own
        //      (2) compares a prover-copied column against the public input
        //      it was copied from and any root baked in before proving
        //      verifies. The one post-execution commitment the AIR truly
        //      computes is the SWrite accumulator bound in (2b), and the
        //      chain already only accepts `final_state_root ==
        //      state_writes_digest` for exactly that reason. Tying the two
        //      columns together makes that convention a constraint rather
        //      than a prover promise: until the real final-image fold
        //      lands, the final root a proof can carry is the digest of the
        //      storage writes the execution actually performed.
        for j in 0..8 {
            builder
                .when(is_halt.clone())
                .when(cpu_active.clone())
                .assert_zero(cur[COL_FINAL_ROOT_0 + j].into() - cur[COL_STATE_WRITES_0 + j].into());
        }

        // (2b) state_writes_digest: last real row, COL_STATE_WRITES_0..7 ==
        //      public[48..56] (HIGH CWE-345, 2026-08-17). Without this
        //      the proof never commits to the VM's post-execution storage
        //      writes; a storage-mutating program could verify while its
        //      actual state transition stayed unbound.
        //
        //      This body once compared `COL_FINAL_ROOT_0` against
        //      `public[18..26]`, a second copy of (2), so the digest was not
        //      bound at all and a proof carrying any `state_writes_digest`
        //      verified (measured 2026-09-03: a storage-writing program proved
        //      and verified with an all-zero digest). The post-proof tamper
        //      tests did not notice because Fiat-Shamir refuses any public
        //      value changed after proving; only a wrong value baked in before
        //      proving reaches this constraint. `soundness_negatives.rs`
        //      now bakes one in.
        for j in 0..8 {
            builder
                .when(is_halt.clone())
                .when(cpu_active.clone())
                .assert_zero(cur[COL_STATE_WRITES_0 + j].into() - public_inputs[48 + j].into());
        }

        // (2c) state-write accumulator carry + first-row zero (HIGH)
        for j in 0..8 {
            builder
                .when_transition()
                .when(one.clone() - is_swrite.clone())
                .assert_eq(
                    nxt[COL_STATE_WRITES_0 + j].into(),
                    cur[COL_STATE_WRITES_0 + j].into(),
                );
        }
        for j in 0..8 {
            builder
                .when_first_row()
                .assert_zero(cur[COL_STATE_WRITES_0 + j]);
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

        // (security audit) event_digest,
        // Exit_code, and chain_id.

        // (5) event_digest: last real row, COL_EVENT_DIGEST_0..7 == public[40..48]
        for j in 0..8 {
            builder
                .when(is_halt.clone())
                .when(cpu_active.clone())
                .assert_zero(cur[COL_EVENT_DIGEST_0 + j].into() - public_inputs[40 + j].into());
        }

        // (5b) event_digest transition:
        // Prover writes the updated accumulator ON the Log row itself
        // (copy prev, then += log val). Therefore the constraint must
        // Use the *next* row's Log flag and rs1 value:
        //   Digest[i+1] = digest[i] + is_log[i+1] * rs1[i+1]
        // The previous formulation used cur is_log/rs1, which forced
        // Digest to update one row late and rejected every Log program
        // (InvalidProof) - that also broke budlum's CI pin rebind.
        {
            let nxt_event_0: AB::Expr = nxt[COL_EVENT_DIGEST_0].into();
            let cur_event_0: AB::Expr = cur[COL_EVENT_DIGEST_0].into();
            let nxt_is_log: AB::Expr = nxt[COL_IS_LOG].into();
            let nxt_rs1: AB::Expr = nxt[COL_RS1_VAL].into();
            // Syscall 6 announces two events, `0x00A1_00A1` and its `rs1`, so
            // it contributes both. Without this the digest counted only `Log`
            // rows while the caller built the public input from
            // `receipt.events`, and no program using the syscall could be
            // proven. See `COL_SYSCALL_IS_6`.
            let nxt_syscall6: AB::Expr = nxt[COL_SYSCALL_IS_6].into();
            let ai_marker = AB::Expr::from(AB::F::from_u64(0x00A1_00A1));
            builder
                .when_transition()
                .when(cpu_active.clone())
                .assert_zero(
                    nxt_event_0
                        - cur_event_0.clone()
                        - nxt_is_log * nxt_rs1.clone()
                        - nxt_syscall6 * (ai_marker + nxt_rs1),
                );

            // The accumulator starts at zero.
            //
            // Without this the transition above only fixes the *differences*
            // between consecutive rows, never the starting point, so the whole
            // sequence slides: a prover writes `D` on the first row, every
            // transition still holds because each one is relative, and the
            // last row carries `D + sum(logged values)`. The proof then states
            // an `event_digest` for events the program never emitted, with `D`
            // chosen freely.
            //
            // That field is not decorative. `storage_deal.rs` puts its whole
            // replay context in it, deal and challenge and responder and epoch
            // and chain, precisely so one shard proof cannot answer a
            // different challenge. An unconstrained starting value is a prover
            // choosing that context.
            //
            // Every other accumulator in this AIR already had its first row
            // pinned: the memory image fold, the register image fold, `clk`,
            // `pc`, and all three LogUp running sums. This one was the
            // exception, and the sequence it accumulates is the one the chain
            // reads back as "what this execution announced".
            // The first row folds its own contribution in the same way, for
            // the same reason the Log term is here: the prover writes row
            // zero's own events into the accumulator rather than starting at
            // zero and catching up on the next row.
            {
                let cur_syscall6: AB::Expr = cur[COL_SYSCALL_IS_6].into();
                let ai_marker_first = AB::Expr::from(AB::F::from_u64(0x00A1_00A1));
                builder.when_first_row().assert_zero(
                    cur_event_0
                        - cur[COL_IS_LOG].into() * cur[COL_RS1_VAL].into()
                        - cur_syscall6 * (ai_marker_first + cur[COL_RS1_VAL].into()),
                );
            }

            // Limbs 1..7 are constant for the whole trace (the transition
            // rule below) and bound to `public_inputs[41..48]` on the last
            // row, but nothing pinned the value they start from: a prover
            // that filled them with arbitrary constants satisfied every
            // constraint, and the last row carried those constants into the
            // bound public input. Only limb 0 tracks execution, so without
            // this the 32 byte event digest is bound in its first 8 bytes and
            // free in the remaining 24 - which is the value an attested event
            // root is taken from. The honest witness writes zero into every
            // limb on row zero (`event_digest_from_events`), so this is what
            // the last-row binding already assumed.
            for j in 1..8 {
                builder
                    .when_first_row()
                    .assert_zero(cur[COL_EVENT_DIGEST_0 + j]);
            }

            // The old comment here claimed a bounds check was unnecessary
            // because `public_inputs[40]` is a u32, so an out-of-range
            // accumulator would surface at the last-row binding. That stopped
            // being true when `to_public_values` was corrected to read limb 0
            // as a full 64-bit element: a Poseidon output logged by a contract
            // exceeds 2^32 and truncating it made honest proofs fail. Limb 0
            // is now a field element on both sides and there is no width to
            // disagree about, which is why no range check is needed rather
            // than the argument that was written here.
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

        // A boolean saying "this row is syscall 6", used both by the event
        // digest and by the return-value rule below.
        //
        // The polynomial factors cannot serve either purpose. They are
        // non-zero rather than one on the number they select, which is fine
        // for gating an equality and wrong both as a multiplier inside a sum
        // and as a way to exclude 6 from a rule that must still fire on 4.
        //
        // Pinned in both directions:
        //
        //   d = imm - 6
        //   z = d * d_inv          (boolean)
        //   d * (1 - z) == 0       (imm != 6 forces the flag off)
        //   flag * d == 0          (imm == 6 forces the flag on)
        //
        // The second is what stops a prover declining to count the events its
        // syscall emitted.
        let syscall6_flag: AB::Expr = cur[COL_SYSCALL_IS_6].into();
        {
            let six_for_flag = AB::Expr::from(AB::F::from_u64(6));
            let d = imm.clone() - six_for_flag;
            let z = one.clone() - syscall6_flag.clone();
            builder.when(is_syscall.clone()).assert_bool(z.clone());
            builder
                .when(is_syscall.clone())
                .assert_zero(d.clone() * (one.clone() - z));
            builder
                .when(is_syscall.clone())
                .assert_zero(syscall6_flag.clone() * d);
            // Off on every row that is not a syscall at all.
            builder
                .when(one.clone() - is_syscall.clone())
                .assert_zero(syscall6_flag.clone());
        }

        // One boolean per known syscall number, each pinned in both
        // directions, then the unknown case as one minus their sum.
        //
        // These used to be polynomials, `(imm-2)(imm-3)(imm-6)` and its
        // siblings. Those are correct about the four numbers they name and
        // wrong about every other: at `imm = 4` all four are non-zero, so the
        // row was required to return the sender, the block height, the nonce
        // and zero simultaneously. They agree only when all three context
        // values are zero, so a program containing an unknown syscall could
        // not be proven on a chain where any of them is set. The VM accepts
        // those programs, returning zero and carrying on, so this was
        // completeness rather than soundness, and every fixture zeroes the
        // context, which is why it survived.
        //
        // A polynomial cannot express "this row is syscall one". It can only
        // express "this row is not two or three or six", and those differ on
        // everything else. See `COL_SYSCALL_IS_1`.
        let syscall_flags: Vec<(AB::Expr, u64)> = vec![
            (cur[COL_SYSCALL_IS_1].into(), 1),
            (cur[COL_SYSCALL_IS_2].into(), 2),
            (cur[COL_SYSCALL_IS_3].into(), 3),
        ];
        for (flag, number) in &syscall_flags {
            let d = imm.clone() - AB::Expr::from(AB::F::from_u64(*number));
            let z = one.clone() - flag.clone();
            builder.when(is_syscall.clone()).assert_bool(z.clone());
            // A different immediate forces the flag off.
            builder
                .when(is_syscall.clone())
                .assert_zero(d.clone() * (one.clone() - z));
            // This immediate forces the flag on, so a prover cannot decline a
            // rule by declining to admit which syscall it ran.
            builder
                .when(is_syscall.clone())
                .assert_zero(flag.clone() * d);
            // Off entirely on rows that are not syscalls.
            builder
                .when(one.clone() - is_syscall.clone())
                .assert_zero(flag.clone());
        }

        let is_sc1 = syscall_flags[0].0.clone();
        let is_sc2 = syscall_flags[1].0.clone();
        let is_sc3 = syscall_flags[2].0.clone();

        builder
            .when(is_syscall.clone())
            .assert_zero(is_sc1 * (rd_val_new.clone() - expected_sender));

        builder
            .when(is_syscall.clone())
            .assert_zero(is_sc2 * (rd_val_new.clone() - expected_bh.clone()));

        builder
            .when(is_syscall.clone())
            .assert_zero(is_sc3 * (rd_val_new.clone() - expected_nonce));

        // An unrecognised syscall returns zero, matching the VM's fallback
        // arm. "Unrecognised" is exactly "none of the four flags is set",
        // which the booleans can say and the polynomials could not.
        let known_syscall = syscall_flags[0].0.clone()
            + syscall_flags[1].0.clone()
            + syscall_flags[2].0.clone()
            + syscall6_flag.clone();
        builder
            .when(is_syscall.clone())
            .assert_zero((one.clone() - known_syscall) * rd_val_new.clone());

        // Syscall 6 returns the block height plus its operand.
        //
        // Gated on the boolean rather than on `(imm-1)(imm-2)(imm-3)`, which
        // was the old factor and is non-zero on every unknown syscall number
        // too: at `imm = 4` it is 6, so an unknown syscall was required to
        // return `block_height + rs1` while the guard above required it to
        // return zero. Both hold only when the block height and the operand
        // are zero, so unknown syscalls were unprovable on any real chain.
        builder.when(is_syscall.clone()).assert_zero(
            syscall6_flag.clone() * (rd_val_new.clone() - expected_bh - rs1_val.clone()),
        );

        // CPU / Registers / Memory constraints
        let r_val: AB::Expr = cur[COL_REG_VAL].into();
        let r_active: AB::Expr = cur[COL_REG_ACTIVE].into();
        let r_same: AB::Expr = cur[COL_REG_SAME].into();
        let r_is_write: AB::Expr = cur[COL_REG_IS_WRITE].into();
        let nr_val: AB::Expr = nxt[COL_REG_VAL].into();
        let nr_active: AB::Expr = nxt[COL_REG_ACTIVE].into();
        let nr_write: AB::Expr = nxt[COL_REG_IS_WRITE].into();
        let r_idx: AB::Expr = cur[COL_REG_IDX].into();
        let nr_idx: AB::Expr = nxt[COL_REG_IDX].into();

        // `r_same` says "the next row is about the same register". It gates
        // both constraints below, so it has to mean that and not merely claim
        // it. Before this block it claimed it: no booleanity, no counterpart
        // constraint, and the LogUp argument never reads the column, so a
        // prover could write zero on the row before a read and delete the
        // requirement that the read return the value that was written.
        //
        // The memory table looks identical and is not vulnerable, which is why
        // `m_same = 0`
        // triggers "the first read of a new address returns zero", so lying
        // costs the prover the value it was trying to invent. Registers have no
        // first-touch rule, so nothing was ever written on the other side.
        //
        // Standard inverse witness, same shape as `Eq`/`Neq` above.
        //
        // Gated on both rows being active, matching the two constraints it
        // feeds. Outside that window the register columns are padding and
        // `r_same` is not read by anything, so demanding a value there would
        // reject honest traces without buying any soundness. The gate cannot
        // be used as an escape hatch either: `r_active` is the multiplicity on
        // the supply side of the register LogUp, so understating it leaves the
        // argument unbalanced and the proof fails there instead.
        let reg_pair_live = r_active.clone() * nr_active.clone();
        let reg_idx_diff = nr_idx.clone() - r_idx.clone();
        let reg_same_inv: AB::Expr = cur[COL_REG_SAME_INV].into();
        let reg_diff_z = reg_idx_diff.clone() * reg_same_inv;
        builder
            .when_transition()
            .when(reg_pair_live.clone())
            .assert_bool(reg_diff_z.clone());
        builder
            .when_transition()
            .when(reg_pair_live.clone())
            .assert_zero(reg_idx_diff * (one.clone() - reg_diff_z.clone()));
        builder
            .when_transition()
            .when(reg_pair_live)
            .assert_eq(r_same.clone(), one.clone() - reg_diff_z);
        // Booleanity, stated rather than inferred. It follows from the
        // equality above while that equality stands, but a flag whose only
        // claim to being boolean is another constraint two lines up loses it
        // silently the moment that constraint is edited. This is cheap and the
        // column is load bearing.
        builder.assert_bool(r_same.clone());

        // The table is a prefix: active rows first, padding after. Every rule
        // of the table is gated by `r_active * nr_active`, so an inactive row
        // between two active ones would switch all of them off at once.
        builder.assert_bool(r_active.clone());
        builder
            .when_transition()
            .assert_zero((one.clone() - r_active.clone()) * nr_active.clone());

        // Sorted by `(idx, time)`, strictly. LogUp compares multisets and
        // cannot see the order, so without this a write could be moved to
        // another time and a read paired with it.
        {
            let four = AB::Expr::from(AB::F::from_u64(4));
            let clk: AB::Expr = cur[COL_REG_CLK].into();
            let sub: AB::Expr = cur[COL_REG_SUB_CLK].into();
            let nclk: AB::Expr = nxt[COL_REG_CLK].into();
            let nsub: AB::Expr = nxt[COL_REG_SUB_CLK].into();
            let time = clk * four.clone() + sub;
            let ntime = nclk * four + nsub;
            let step = r_same.clone() * (ntime - time - one.clone())
                + (one.clone() - r_same.clone()) * (nr_idx.clone() - r_idx.clone() - one.clone());
            let mut bits_sum = AB::Expr::from(AB::F::ZERO);
            for i in 0..REG_ORD_BITS {
                let bit: AB::Expr = cur[COL_REG_ORD_BITS_BASE + i].into();
                builder.assert_bool(bit.clone());
                bits_sum += bit * AB::Expr::from(AB::F::from_u64(1u64 << i));
            }
            builder
                .when_transition()
                .when(r_active.clone() * nr_active.clone())
                .assert_eq(step, bits_sum);
        }

        builder.when_transition().assert_zero(
            r_active.clone()
                * nr_active.clone()
                * r_same.clone()
                * (one.clone() - nr_write.clone())
                * (nr_val.clone() - r_val.clone()),
        );
        builder.when_transition().assert_zero(
            r_active.clone() * nr_active.clone() * r_same.clone() * (nr_idx - r_idx.clone()),
        );

        // The first read of a register returns zero, unless the row is part of
        // the committed initial register image.
        //
        // Without this, a register nothing ever wrote could be read as any
        // value a prover liked: put the invented value on both sides of the
        // register bus and LogUp balances, `r_same` is honestly zero because
        // the previous row really is a different register, and nothing else
        // looks. Register values are the inputs to every arithmetic
        // constraint, so that is money from nowhere.
        //
        // The bare mirror of the memory rule was tried first and was wrong.
        // Memory can distinguish "not written in this trace" from "not part of
        // the committed starting state" because seeded rows carry
        // `COL_MEM_IS_INIT` and fold into a commitment; registers had no such
        // marking, so asserting zero rejected every proof whose execution
        // began from a non-zero register file. CI found it by failing 68
        // existing tests, and it was right to.
        //
        // `COL_REG_IS_INIT` supplies the missing half. A flagged row is exempt
        // from the zero rule and instead has to appear in the accumulator the
        // AIR checks against limbs 2 and 3 of `initial_state_root`, so the
        // starting register file is now something the proof states rather than
        // something the caller happens to have arranged.
        let r_is_init: AB::Expr = cur[COL_REG_IS_INIT].into();
        let nr_is_init: AB::Expr = nxt[COL_REG_IS_INIT].into();
        builder.assert_bool(r_is_init.clone());
        // An initial-image row describes the register file before the program
        // ran, so it is a read by definition.
        builder.assert_zero(r_is_init.clone() * r_is_write.clone());
        // The flag lives on active rows, and only on the first row of a
        // register block. The fold below is still the weak one described at
        // `COL_REG_INIT_ACC`; the step that replaces its constants closes that.
        builder.assert_zero(r_is_init.clone() * (one.clone() - r_active.clone()));
        builder.when_transition().assert_zero(
            r_active.clone() * nr_active.clone() * r_same.clone() * nr_is_init.clone(),
        );

        builder.when_first_row().assert_zero(
            r_active.clone()
                * (one.clone() - r_is_write.clone())
                * (one.clone() - r_is_init.clone())
                * r_val.clone(),
        );
        builder.when_transition().assert_zero(
            r_active.clone()
                * nr_active.clone()
                * (one.clone() - r_same.clone())
                * (one.clone() - nr_write.clone())
                * (one.clone() - nr_is_init.clone())
                * nr_val.clone(),
        );

        // Fold every initial register row into the accumulator, the same shape
        // the memory image uses:
        //
        //   acc' = acc                            when the next row is not seeded
        //   acc' = acc*BETA + idx*GAMMA + val     when it is
        //
        // Different constants from the memory fold on purpose: shared ones
        // would let a seeded value move between the two images without either
        // accumulator changing.
        {
            let beta = AB::Expr::from(AB::F::from_u64(REG_INIT_BETA));
            let gamma = AB::Expr::from(AB::F::from_u64(REG_INIT_GAMMA));
            let acc: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let nacc: AB::Expr = nxt[COL_REG_INIT_ACC].into();
            let nr_val_e: AB::Expr = nxt[COL_REG_VAL].into();
            let nr_idx_e: AB::Expr = nxt[COL_REG_IDX].into();

            builder.when_first_row().assert_eq(
                acc.clone(),
                r_is_init.clone() * (r_idx.clone() * gamma.clone() + r_val.clone()),
            );

            let folded = acc.clone() * beta + nr_idx_e * gamma + nr_val_e;
            builder
                .when_transition()
                .assert_eq(nacc, acc.clone() + nr_is_init.clone() * (folded - acc));
        }

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

        // `m_same` was never exploitable the way `r_same` was, because the
        // memory table constrains both of its sides: `m_same` gates value and
        // address continuity, and `1 - m_same` gates "the first read of a new
        // address returns zero". A value outside {0, 1} makes both live at
        // once, which demands same address, same value, and that the value is
        // zero, so it is strictly worse for a prover than telling the truth.
        //
        // Stating booleanity anyway. The argument above is a proof about the
        // current shape of three constraints spread over forty lines, and the
        // reader who edits one of them will not redo it. Making the flag
        // boolean outright means they do not have to.
        builder.assert_bool(m_same.clone());

        // A cell is a table id and an address inside it. The sort key joins
        // them: `tid * 2^32 + addr`. The key is injective only while the
        // address is below `2^32`, which the constraint below enforces for
        // memory and stack rows but not for storage: storage slots are
        // full-width Goldilocks elements. The initial-image flag is therefore
        // pinned to the memory table (see the `COL_MEM_IS_INIT` block), so no
        // storage row ever enters this fold. With the folded domain bounded to
        // `tid in {1, 2}` and `addr < 2^32`, two cells have one key only if
        // they are one cell.
        let two_pow_32 = AB::Expr::from(AB::F::from_u64(1u64 << 32));
        let m_tid: AB::Expr = cur[COL_MEM_TID].into();
        let nm_tid: AB::Expr = nxt[COL_MEM_TID].into();
        let m_key = m_tid.clone() * two_pow_32.clone() + m_addr.clone();
        let nm_key = nm_tid.clone() * two_pow_32.clone() + nm_addr.clone();

        // The table is a prefix: active rows first, padding after. Every rule
        // of the table is gated by `m_active * nm_active`, so an inactive row
        // between two active ones would switch all of them off at once.
        builder.assert_bool(m_active.clone());
        builder
            .when_transition()
            .assert_zero((one.clone() - m_active.clone()) * nm_active.clone());

        // An active row sits in one of the three tables: 1 memory, 2 stack,
        // 3 storage. Padding rows keep a zero.
        builder.assert_zero(
            m_active.clone()
                * (m_tid.clone() - one.clone())
                * (m_tid.clone() - AB::Expr::from(AB::F::from_u64(2)))
                * (m_tid.clone() - AB::Expr::from(AB::F::from_u64(3))),
        );

        // Two-limb canonical decomposition of `COL_MEM_ADDR = a_lo + 2^32 * a_hi`
        // on every row (padding included: zero splits into 0 + 0).
        // Memory (`tid = 1`), stack (`tid = 2`), and padding (`tid = 0`) assert
        // `a_hi == 0` via `(tid - 3) * a_hi == 0`; storage rows (`tid = 3`) span
        // the full canonical Goldilocks field `[0, P - 1]` with `a_hi == 2^32 - 1 ==> a_lo == 0`.
        let mut m_addr_lo = AB::Expr::from(AB::F::ZERO);
        let mut m_addr_hi = AB::Expr::from(AB::F::ZERO);
        let mut nm_addr_lo = AB::Expr::from(AB::F::ZERO);
        let mut nm_addr_hi = AB::Expr::from(AB::F::ZERO);
        for i in 0..32 {
            let coeff = AB::Expr::from(AB::F::from_u64(1u64 << i));
            let bit_lo: AB::Expr = cur[COL_MEM_ADDR_BITS_BASE + i].into();
            let bit_hi: AB::Expr = cur[COL_MEM_ADDR_BITS_BASE + 32 + i].into();
            builder.assert_bool(bit_lo.clone());
            builder.assert_bool(bit_hi.clone());
            m_addr_lo += bit_lo * coeff.clone();
            m_addr_hi += bit_hi * coeff.clone();
            let nbit_lo: AB::Expr = nxt[COL_MEM_ADDR_BITS_BASE + i].into();
            let nbit_hi: AB::Expr = nxt[COL_MEM_ADDR_BITS_BASE + 32 + i].into();
            nm_addr_lo += nbit_lo * coeff.clone();
            nm_addr_hi += nbit_hi * coeff;
        }
        builder.assert_eq(
            m_addr.clone(),
            m_addr_lo.clone() + m_addr_hi.clone() * two_pow_32.clone(),
        );
        builder
            .assert_zero((m_tid.clone() - AB::Expr::from(AB::F::from_u64(3))) * m_addr_hi.clone());
        {
            let hi_gap = AB::Expr::from(AB::F::from_u64(0xFFFF_FFFF)) - m_addr_hi.clone();
            let hi_inv: AB::Expr = cur[COL_MEM_HI_MAX_INV].into();
            let is_hi_max = one.clone() - hi_gap.clone() * hi_inv;
            builder.assert_zero(hi_gap * is_hi_max.clone());
            builder.assert_zero(is_hi_max * m_addr_lo.clone());
        }

        // Exact two-limb cell identity and strict lexicographic ordering over
        // `(top, a_lo, clk)` where `top = tid * 2^32 + a_hi < 2^34`.
        let mem_pair_live = m_active.clone() * nm_active.clone();
        let m_top = m_tid.clone() * two_pow_32.clone() + m_addr_hi;
        let nm_top = nm_tid * two_pow_32 + nm_addr_hi;
        let m_top_same: AB::Expr = cur[COL_MEM_TOP_SAME].into();
        let m_top_same_inv: AB::Expr = cur[COL_MEM_TOP_SAME_INV].into();
        builder.assert_bool(m_top_same.clone());
        let top_diff = nm_top.clone() - m_top.clone();
        let top_diff_nz = top_diff.clone() * m_top_same_inv;
        builder
            .when_transition()
            .when(mem_pair_live.clone())
            .assert_bool(top_diff_nz.clone());
        builder
            .when_transition()
            .when(mem_pair_live.clone())
            .assert_zero(top_diff * (one.clone() - top_diff_nz.clone()));
        builder
            .when_transition()
            .when(mem_pair_live.clone())
            .assert_eq(m_top_same.clone(), one.clone() - top_diff_nz);

        let lo_diff = nm_addr_lo.clone() - m_addr_lo.clone();
        let mem_same_inv: AB::Expr = cur[COL_MEM_SAME_INV].into();
        let lo_diff_nz = lo_diff.clone() * mem_same_inv;
        builder
            .when_transition()
            .when(mem_pair_live.clone())
            .assert_bool(lo_diff_nz.clone());
        builder
            .when_transition()
            .when(mem_pair_live.clone())
            .assert_zero(lo_diff * (one.clone() - lo_diff_nz.clone()));
        builder
            .when_transition()
            .when(mem_pair_live.clone())
            .assert_eq(
                m_same.clone(),
                m_top_same.clone() * (one.clone() - lo_diff_nz),
            );

        // Sorted by `(top, a_lo, clk)`, strictly. Every limb difference sits
        // inside `[0, 2^34 - 1]`, so a step in the wrong direction wraps near
        // `P` and cannot be decomposed into 34 boolean bits.
        {
            let nclk: AB::Expr = nxt[COL_MEM_CLK].into();
            let step = (one.clone() - m_top_same.clone()) * (nm_top - m_top - one.clone())
                + (m_top_same - m_same.clone()) * (nm_addr_lo - m_addr_lo - one.clone())
                + m_same.clone() * (nclk - m_clk.clone() - one.clone());
            let mut bits_sum = AB::Expr::from(AB::F::ZERO);
            for i in 0..MEM_ORD_BITS {
                let bit: AB::Expr = cur[COL_MEM_ORD_BITS_BASE + i].into();
                builder.assert_bool(bit.clone());
                bits_sum += bit * AB::Expr::from(AB::F::from_u64(1u64 << i));
            }
            builder
                .when_transition()
                .when(mem_pair_live)
                .assert_eq(step, bits_sum);
        }

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

        // First read of an address returns zero, unless the row is flagged as
        // part of the committed initial image.
        //
        // The exemption is not a hole: `COL_MEM_IS_INIT` is itself boolean-
        // constrained, and every row carrying it is folded into the memory
        // commitment that the AIR checks against
        // `public_inputs.initial_state_root`. A prover that flags a row it did
        // not seed changes the commitment and fails that check instead.
        let m_is_init: AB::Expr = cur[COL_MEM_IS_INIT].into();
        let nm_is_init: AB::Expr = nxt[COL_MEM_IS_INIT].into();
        builder.assert_bool(m_is_init.clone());
        // An initial-image row is a read by definition; it describes memory as
        // it was before the program ran.
        builder.assert_zero(m_is_init.clone() * m_is_write.clone());
        // Only the memory table may be seeded. The fold key joins a table id to
        // an address as `tid * 2^32 + addr`, and that key is injective only
        // while the address stays below `2^32` - which is exactly what the
        // address bound enforces for memory and stack rows, but not for
        // storage rows, whose slots span the whole Goldilocks field. An
        // unpinned flag therefore let a seeded storage slot and a memory cell
        // share one fold key, so a proof about the storage slot verified
        // against the initial-image root of a memory cell. Storage and stack
        // both start empty by design (no path seeds them), so pinning the flag
        // to the memory table costs nothing and leaves the key injective.
        builder
            .assert_zero(m_is_init.clone() * (m_tid.clone() - AB::Expr::from(AB::F::from_u64(1))));
        // The flag lives on active rows, and only on the first row of an
        // address block. The fold below is still the weak one described at
        // `COL_MEM_INIT_ACC`; the step that replaces its constants closes that.
        builder.assert_zero(m_is_init.clone() * (one.clone() - m_active.clone()));
        builder.when_transition().assert_zero(
            m_active.clone() * nm_active.clone() * m_same.clone() * nm_is_init.clone(),
        );

        builder.when_first_row().assert_zero(
            m_active.clone()
                * (one.clone() - m_is_write.clone())
                * (one.clone() - m_is_init.clone())
                * m_val.clone(),
        );
        builder.when_transition().assert_zero(
            m_active.clone()
                * nm_active.clone()
                * (one.clone() - m_same.clone())
                * (one.clone() - nm_write.clone())
                * (one.clone() - nm_is_init.clone())
                * nm_val.clone(),
        );

        // Fold every initial-image row into the accumulator.
        //
        //   acc' = acc                       when the next row is not seeded
        //   acc' = acc*BETA + key*GAMMA + val    when it is
        //
        // The key is the sort key `tid * 2^32 + addr`, not the bare address.
        // Memory cell 5 and storage slot 5 share an address, and a bare
        // address would give them one term, so one root would stand for both.
        // The first row starts the fold from zero, so an empty image gives a
        // zero accumulator and matches an all-zero `initial_state_root` - the
        // behaviour every existing program relies on.
        {
            let beta = AB::Expr::from(AB::F::from_u64(MEM_INIT_BETA));
            let gamma = AB::Expr::from(AB::F::from_u64(MEM_INIT_GAMMA));
            let acc: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let nacc: AB::Expr = nxt[COL_MEM_INIT_ACC].into();
            let nm_val_e: AB::Expr = nxt[COL_MEM_VAL].into();

            // First row: acc is the fold of that row alone, or zero.
            builder.when_first_row().assert_eq(
                acc.clone(),
                m_is_init.clone() * (m_key * gamma.clone() + m_val.clone()),
            );

            let folded = acc.clone() * beta + nm_key * gamma + nm_val_e;
            builder
                .when_transition()
                .assert_eq(nacc, acc.clone() + nm_is_init.clone() * (folded - acc));
        }

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
            let b6 = b5.clone() * beta_expr.clone();
            let b7 = b6.clone() * beta_expr.clone();

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
            // r0 is the constant zero, so a row targeting it must publish zero
            // on the register bus no matter what it computed. See
            // `COL_RD_IDX_INV` for why the rule lives here rather than on
            // `COL_RD_VAL_NEW`: putting it on the value column would make
            // honest programs that write to r0 unprovable, because the per
            // opcode rules constrain that same column.
            let rd_idx_inv: AB::Expr = cur[COL_RD_IDX_INV].into();
            let rd_idx_z = rd_idx.clone() * rd_idx_inv;
            builder.assert_bool(rd_idx_z.clone());
            builder.assert_zero(rd_idx.clone() * (one.clone() - rd_idx_z.clone()));
            let rd_written = rd_val_new.clone() * rd_idx_z;

            // Only the opcodes that write `rd` publish a write. Every other
            // row reads `rd` at its current value, so the register table, and
            // not the prover, decides what that value is. The selectors are
            // mutually exclusive, so the sum is boolean. VerifyInference is
            // left out: its selector is held at zero above and the opcode is
            // outside `is_real_op`.
            // Some selectors were moved into `when(...)` above, so they are
            // read from the row again here.
            let sel = |col: usize| -> AB::Expr { cur[col].into() };
            let writes_rd = sel(COL_IS_ADD)
                + sel(COL_IS_SUB)
                + sel(COL_IS_MUL)
                + sel(COL_IS_DIV)
                + sel(COL_IS_INV)
                + sel(COL_IS_AND)
                + sel(COL_IS_NOT)
                + sel(COL_IS_LOAD)
                + sel(COL_IS_POP)
                + sel(COL_IS_EQ)
                + sel(COL_IS_NEQ)
                + sel(COL_IS_LT)
                + sel(COL_IS_GT)
                + sel(COL_IS_LTE)
                + sel(COL_IS_GTE)
                + sel(COL_IS_SREAD)
                + sel(COL_IS_POSEIDON)
                + sel(COL_IS_SYSCALL)
                + sel(COL_IS_VERIFY_MERKLE)
                + sel(COL_IS_PRIVACY_COMMIT)
                + sel(COL_IS_NULLIFIER_CHECK)
                + sel(COL_IS_SUM_CONSERVATION);

            let c_rd = term(
                table_reg.clone(),
                clk_rd,
                rd_idx.clone(),
                rd_written,
                writes_rd,
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
            // Register LogUp must also
            // Exclude VerifyMerkle AND VerifyInference expansion rows (same
            // multiplicity mismatch As Program CTL). The trace_matrix
            // correctly skips register events For expansion rows, so the CPU
            // side must match. (2026-08-28: COL_INFERENCE_IS_EXPAND was
            // missing here - every clean VerifyInference proof failed with
            // InvalidProof because 1+8 CPU rows claimed register events that
            // were never supplied.)
            let is_expand_ext_reg: AB::ExprEF =
                (cur[COL_VM_MERKLE_IS_EXPAND].into() + cur[COL_INFERENCE_IS_EXPAND].into()).into();
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
            // `rs1_idx == 0` means load-immediate, which touches no memory.
            // The multiplier has to be the *boolean* "rs1 is not r0", not the
            // register number: scaling the demand side by seven because the
            // pointer happened to live in r7 unbalances the argument against a
            // memory table that supplies the row once. See `COL_RS1_IDX_INV`.
            //
            // Same witness the load-immediate rule above is guarded by, read
            // again here rather than re-derived: two derivations of one flag
            // is the shape that produced this bug in the first place.
            let rs1_idx_inv: AB::Expr = cur[COL_RS1_IDX_INV].into();
            let rs1_idx_z = rs1_idx.clone() * rs1_idx_inv;
            builder.assert_bool(rs1_idx_z.clone());
            builder.assert_zero(rs1_idx.clone() * (one.clone() - rs1_idx_z.clone()));
            let is_real_mem_op = is_load.clone() * rs1_idx_z + is_store.clone();
            let is_stack_op = is_push.clone() + is_pop.clone() + is_call.clone() + is_ret.clone();
            let is_storage_op = is_sread.clone() + is_swrite.clone();
            builder
                .when(is_storage_op.clone())
                .assert_bool(storage_delta_z.clone());
            builder
                .when(is_storage_op.clone())
                .assert_zero(storage_delta.clone() * (one.clone() - storage_delta_z.clone()));
            // A `VerifyMerkle` expansion row reads one sibling word from the
            // path buffer, and the original step reads the key. Those reads go
            // through the memory table like any other, so they have to appear
            // on the demand side of the LogUp too - a row that supplies a
            // memory entry without a matching demand unbalances the argument
            // and every proof fails with `InvalidProof`.
            //
            // Binds `merkle_sibling` and `merkle_key` to the
            // program's memory. Before it, both were free witness columns: the
            // AIR consumed them as Poseidon inputs and nothing said they had
            // come from `path_addr`, so a prover could walk a path that was
            // never written.
            let is_merkle_expand_mem: AB::Expr = cur[COL_VM_MERKLE_IS_EXPAND].into();
            let is_merkle_key_read: AB::Expr =
                is_verify_merkle.clone() * (one.clone() - is_merkle_expand_mem.clone());
            let is_merkle_mem_op = is_merkle_expand_mem.clone() + is_merkle_key_read.clone();
            let is_any_mem_op = is_real_mem_op.clone()
                + is_stack_op.clone()
                + is_storage_op.clone()
                + is_merkle_mem_op.clone();

            // The region is the table id on the bus, so the address is the
            // address inside the table: the stack slot, or the storage slot.
            let stack_addr = (is_push.clone() + is_call.clone()) * cur_stack_ptr.clone()
                + (is_pop.clone() + is_ret.clone()) * (cur_stack_ptr.clone() - one.clone());
            let storage_addr: AB::Expr = storage_slot.clone();
            let two_val_tid = AB::Expr::from(AB::F::from_u64(2));
            let three_val_tid = AB::Expr::from(AB::F::from_u64(3));
            let cpu_mem_tid = is_real_mem_op.clone()
                + is_merkle_mem_op.clone()
                + two_val_tid * is_stack_op.clone()
                + three_val_tid * is_storage_op.clone();

            // The path buffer starts at the instruction's immediate. The key
            // is the word at `path_addr`; expansion round `r` reads the
            // sibling at `path_addr + 8 + 8*r`. Both are derived from columns
            // the AIR already constrains, so the address a Merkle row claims
            // in the memory argument is not something the prover chooses.
            let merkle_path_addr: AB::Expr = cur[COL_IMM].into();
            let eight: AB::Expr = AB::Expr::from(AB::F::from_u8(8));
            let merkle_sibling_addr = merkle_path_addr.clone()
                + eight.clone()
                + eight.clone() * cur[COL_VM_MERKLE_ROUND].into();
            let final_mem_addr = is_real_mem_op.clone()
                * (cur[COL_RS1_VAL].into() + cur[COL_IMM].into())
                + is_stack_op.clone() * stack_addr
                + is_storage_op.clone() * storage_addr
                + is_merkle_expand_mem.clone() * merkle_sibling_addr
                + is_merkle_key_read.clone() * merkle_path_addr;

            let is_write = is_store.clone() + is_push.clone() + is_call.clone() + is_swrite.clone();
            let cpu_mem_val = is_load * cur[COL_RD_VAL_NEW].into()
                + is_store * cur[COL_RS2_VAL].into()
                + is_push * cur[COL_RS1_VAL].into()
                + is_pop * cur[COL_RD_VAL_NEW].into()
                + is_call * (cur[COL_PC].into() + one.clone())
                + is_ret * cur[COL_NEXT_PC].into()
                + is_sread * cur[COL_RD_VAL_NEW].into()
                + is_swrite.clone() * cur[COL_RS1_VAL].into()
                + is_merkle_expand_mem * cur[COL_VM_MERKLE_SIBLING].into()
                + is_merkle_key_read * cur[COL_VM_MERKLE_KEY].into();

            let c_cpu_mem = term(
                cpu_mem_tid,
                clk.clone(),
                final_mem_addr.clone(),
                cpu_mem_val.clone(),
                is_write.clone(),
            );
            let c_mem = term(
                m_tid.clone(),
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
            // The LogUp weight of the ROM side: how many times this pc was executed.
            // It stays in the committed main trace -- because the verifier does not
            // see the trace it cannot be placed in the preprocessed table.
            let prog_mult: AB::Expr = cur[COL_PROG_MULT].into();

            let raw_inst: AB::Expr = cur[COL_RAW_INST].into();
            let pre_opcode: AB::Expr = pre_cur[3].into();
            let pre_rd: AB::Expr = pre_cur[4].into();
            let pre_rs1: AB::Expr = pre_cur[5].into();
            let pre_rs2: AB::Expr = pre_cur[6].into();
            let pre_imm: AB::Expr = pre_cur[7].into();
            let opcode_col: AB::Expr = cur[COL_OPCODE].into();
            let rd_idx_col: AB::Expr = cur[COL_RD_IDX].into();
            let rs1_idx_col: AB::Expr = cur[COL_RS1_IDX].into();
            let rs2_idx_col: AB::Expr = cur[COL_RS2_IDX].into();
            let imm_col: AB::Expr = cur[COL_IMM].into();

            let pc_ext: AB::ExprEF = pc.into();
            let raw_inst_ext: AB::ExprEF = raw_inst.into();
            let pre_pc_ext: AB::ExprEF = pre_pc.into();
            let pre_inst_ext: AB::ExprEF = pre_inst.into();
            let opcode_ext: AB::ExprEF = opcode_col.into();
            let pre_opcode_ext: AB::ExprEF = pre_opcode.into();
            let rd_ext: AB::ExprEF = rd_idx_col.into();
            let rs1_ext: AB::ExprEF = rs1_idx_col.into();
            let rs2_ext: AB::ExprEF = rs2_idx_col.into();
            let pre_rd_ext: AB::ExprEF = pre_rd.into();
            let pre_rs1_ext: AB::ExprEF = pre_rs1.into();
            let pre_rs2_ext: AB::ExprEF = pre_rs2.into();
            let imm_ext: AB::ExprEF = imm_col.into();
            let pre_imm_ext: AB::ExprEF = pre_imm.into();

            // Tuple is (pc, raw_inst, opcode, rd, rs1, rs2): the whole decode.
            //
            // `raw_inst` was pinned to the committed program by this argument
            // from the start, and that looked like enough. It was not. The AIR
            // never splits the word, so every field the CPU trace decodes out
            // of it sat in a free witness column that nothing related back to
            // the word beside it. A prover could fetch the honest instruction
            // at `pc` and write whatever it liked into the decode columns.
            //
            // `opcode` was the first field fixed, because the selectors key
            // off it and that made instruction semantics itself forgeable.
            // The register indices are the same hole one level down, and
            // measurably worth money. Take `total = amount + fee` compiled to
            // `Add r3, r2, r1`, and rewrite `rs2_idx` from 1 to 2: the row now
            // computes `amount + amount`. The arithmetic constraint is
            // satisfied because the value column follows the index, the
            // register argument balances because r2 is genuinely read
            // elsewhere, and the fee is never paid.
            //
            // The preprocessed side supplies each field masked out of the word
            // the verifier committed to, so matching the tuple forces the CPU
            // columns to be the real decode. Doing the split inside the AIR
            // instead would need a range check on the remaining bits, and this
            // machine has no range check machinery.
            //
            // `imm` is the last field and took one extra step, because the
            // trace does not hold the raw bits. A negative immediate is stored
            // as `P - |imm|`, so the preprocessed side runs the word through
            // `bud_isa::decode_any` and applies the same wrap rather than
            // masking. It matters as much as the registers do: `storage_addr`
            // is `storage_base + imm`, the Merkle path buffer address is
            // `imm`, a Load or Store resolves to `rs1_val + imm`, and a jump
            // target is `pc + imm`. An unbound immediate is a prover choosing
            // which storage slot a contract writes to.
            let term_cpu_prog = alpha_expr.clone()
                + beta_expr.clone() * pc_ext
                + b2.clone() * raw_inst_ext
                + b3.clone() * opcode_ext
                + b4.clone() * rd_ext
                + b5.clone() * rs1_ext
                + b6.clone() * rs2_ext
                + b7.clone() * imm_ext;
            let term_pre_prog = alpha_expr.clone()
                + beta_expr.clone() * pre_pc_ext
                + b2.clone() * pre_inst_ext
                + b3.clone() * pre_opcode_ext
                + b4.clone() * pre_rd_ext
                + b5.clone() * pre_rs1_ext
                + b6.clone() * pre_rs2_ext
                + b7.clone() * pre_imm_ext;

            let diff_cpu_prog: AB::ExprEF = gamma_expr.clone() - term_cpu_prog;
            let diff_pre_prog: AB::ExprEF = gamma_expr.clone() - term_pre_prog;

            let s_prog_cur: AB::ExprEF = perm_cur[2].into();
            let s_prog_nxt: AB::ExprEF = perm_nxt[2].into();
            let cpu_active: AB::Expr = cur[COL_CPU_ACTIVE].into();
            // VerifyMerkle expansion rows
            // Reuse the same (pc, raw_inst) tuple as the original step.
            // Without this gate, 65 CPU rows (1 original + 64 expansion)
            // Map to 1 preprocessed row → Program CTL LogUp multiplicity
            // Mismatch → InvalidProof. Register LogUp already correctly
            // Skips expansion rows; Program CTL must do the same.
            // (2026-08-28) Same exclusion for VerifyInference expansion rows:
            // 1 original + 8 expansion rows map to 1 preprocessed ROM row;
            // without COL_INFERENCE_IS_EXPAND here the LogUp multiplicity
            // never balances and every VerifyInference proof is InvalidProof.
            let is_expand: AB::Expr =
                cur[COL_VM_MERKLE_IS_EXPAND].into() + cur[COL_INFERENCE_IS_EXPAND].into();
            let prog_active: AB::Expr = cpu_active.clone() * (one.clone() - is_expand);
            let prog_active_ext: AB::ExprEF = prog_active.into();
            // A row outside the program can lend nothing: the multiplicity can be
            // non-zero only on a real ROM row (pre_active=1).
            // Otherwise the prover could write weight to a pc absent from the program and
            // dengeyi uydurabilirdi.
            builder.assert_zero(prog_mult.clone() * (one.clone() - pre_active.clone()));
            let pre_active_ext: AB::ExprEF = prog_mult.into();

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
        let is_bw_bits = is_and.clone();
        let is_cmp_or_bw = is_cmp.clone() + is_bw_bits.clone();

        // Booleanity of all bit decomposition columns
        for i in 0..64 {
            let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
            let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
            builder.when(is_cmp_or_bw.clone()).assert_bool(a_bit);
            builder.when(is_cmp_or_bw.clone()).assert_bool(b_bit);
        }

        // Canonicity: the decomposition must be the representative below the
        // modulus.
        //
        // Booleanity and `sum(b_i * 2^i) == rs_val` leave `2^32 - 1` values
        // with a second valid bit string, because `2^64 > P`. The comparison
        // opcodes read the bits, so a prover holding a second representation
        // chooses the answer. See `COL_CMP_RS1_HI_INV`.
        //
        // `P = 0xFFFFFFFF_00000001`, so a pattern is out of range exactly when
        // its high half is saturated and its low half is not zero.
        {
            let hi_max = AB::Expr::from(AB::F::from_u64(0xFFFF_FFFF));
            for (base, inv_col) in [
                (COL_CMP_RS1_BASE, COL_CMP_RS1_HI_INV),
                (COL_CMP_RS2_BASE, COL_CMP_RS2_HI_INV),
            ] {
                let mut hi: AB::Expr = AB::Expr::ZERO;
                for i in 32..64 {
                    let bit: AB::Expr = cur[base + i].into();
                    hi += bit * AB::Expr::from(AB::F::from_u64(1u64 << (i - 32)));
                }
                let mut lo: AB::Expr = AB::Expr::ZERO;
                for i in 0..32 {
                    let bit: AB::Expr = cur[base + i].into();
                    lo += bit * AB::Expr::from(AB::F::from_u64(1u64 << i));
                }

                let d = hi - hi_max.clone();
                let d_inv: AB::Expr = cur[inv_col].into();
                let z = d.clone() * d_inv;
                builder.when(is_cmp_or_bw.clone()).assert_bool(z.clone());
                // A nonzero difference forces z = 1, so z = 0 is only
                // available when the high half really is saturated.
                builder
                    .when(is_cmp_or_bw.clone())
                    .assert_zero(d * (AB::Expr::ONE - z.clone()));
                // Saturated high half, so the low half has to be zero.
                builder
                    .when(is_cmp_or_bw.clone())
                    .assert_zero((AB::Expr::ONE - z) * lo);
            }
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
            // And: rd = sum(a_i * b_i * 2^i)
            //
            // `Or` and `Xor` used to sit here as `rs1 + rs2 - and_sum` and
            // `rs1 + rs2 - 2 * and_sum`. Both are exact over integers and both
            // could leave the field: measured, `(P-1) | (P-2) = 2^64 - 1`,
            // which is above the modulus, and the register then held a value
            // no canonical bit decomposition can represent. Any later
            // comparison on that register was unprovable.
            //
            // `And` has no such case. Its result is at most the smaller
            // operand, so two canonical inputs always give a canonical
            // result. That is why it is the one that stayed.
            builder
                .when(is_and)
                .assert_eq(rd_val_new.clone(), and_sum.clone());
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
        // Eq_64 is implicitly 1
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
        // Eq_64 is implicit 1 for the MSB term
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
        // Eq_0 tells us if all bits are equal (a == b)
        let cmp_eq_all: AB::Expr = cur[COL_CMP_EQ_BASE].into();
        let cmp_lt_raw: AB::Expr = cur[COL_CMP_LT_RAW].into();

        // Lt: rd = cmp_lt_raw (1 if a < b)
        builder
            .when(is_lt)
            .assert_eq(rd_val_new.clone(), cmp_lt_raw.clone());
        // Gt: rd = 1 - cmp_eq_all - cmp_lt_raw (1 if a > b)
        builder.when(is_gt).assert_eq(
            rd_val_new.clone(),
            one.clone() - cmp_eq_all.clone() - cmp_lt_raw.clone(),
        );
        // Lte: rd = cmp_eq_all + cmp_lt_raw (1 if a <= b)
        builder
            .when(is_lte)
            .assert_eq(rd_val_new.clone(), cmp_eq_all.clone() + cmp_lt_raw.clone());
        // Gte: rd = 1 - cmp_lt_raw (1 if a >= b)
        builder
            .when(is_gte)
            .assert_eq(rd_val_new.clone(), one.clone() - cmp_lt_raw.clone());

        // --- Poseidon hash gadget (4 rounds, alpha=7) ---
        // Shared by:
        //   * Poseidon opcode (0x19): state=[rs1, rs2, 0..] ; rd = out
        //   * PrivacyCommit (0x20):   state=[rs1, rs2, imm, 0..] ; rd = out
        //   * NullifierCheck (0x21):  state=[rs2, DOMAIN_NULLIFIER, 0..] ;
        //                            Rd = 1 iff out == rs1 (claimed nullifier)
        // Witness columns COL_POSEIDON_* are reused; at most one of the three
        // Selectors is 1 (selector exclusivity via is_cpu == 1).
        {
            let p_poseidon: AB::Expr = is_poseidon.clone();
            let p_commit: AB::Expr = is_privacy_commit.clone();
            let p_null: AB::Expr = is_nullifier_check.clone();
            let p_sw: AB::Expr = is_swrite.clone();
            // The last row of a Merkle path group: the gadget compresses two nodes.
            let p_merkle: AB::Expr = cur[COL_MERKLE_HASH].into();
            // Any row that needs the Poseidon gadget.
            let p: AB::Expr = p_poseidon.clone()
                + p_commit.clone()
                + p_null.clone()
                + p_sw.clone()
                + p_merkle.clone();

            // Opcode ↔ selector binding (malicious prover cannot flip selector).
            let opcode_at: AB::Expr = cur[COL_OPCODE].into();
            builder.assert_zero(
                p_poseidon.clone() * (opcode_at.clone() - AB::Expr::from(AB::F::from_u64(0x19))),
            );
            builder.assert_zero(
                p_commit.clone() * (opcode_at.clone() - AB::Expr::from(AB::F::from_u64(0x20))),
            );
            builder.assert_zero(
                p_null.clone() * (opcode_at.clone() - AB::Expr::from(AB::F::from_u64(0x21))),
            );
            builder.assert_zero(
                p_sw.clone() * (opcode_at.clone() - AB::Expr::from(AB::F::from_u64(0x1C))),
            );
            builder.assert_zero(
                is_sum_conservation.clone()
                    * (opcode_at.clone() - AB::Expr::from(AB::F::from_u64(0x22))),
            );

            // Initial state:
            //   Poseidon:        s0=rs1, s1=rs2, s2..s7=0
            //   PrivacyCommit:   s0=rs1(amount), s1=rs2(blinding), s2=imm(recipient), s3..s7=0
            //   NullifierCheck:  s0=rs2(secret), s1=DOMAIN_NULLIFIER, s2..s7=0
            //   SWrite (0x1C):   s0=slot(imm), s1=val(rs1), s2..s5=prev_acc
            //                    (COL_STATE_WRITES_0..7 = 4 x u64), s6..s7=0
            // DOMAIN_NULLIFIER = 0x4e554c4c49464552 ("NULLIFER") - must match bud-vm.
            let domain_nullifier = AB::Expr::from(AB::F::from_u64(0x4e554c4c49464552));
            // HIGH CWE-345: prev_acc lane k (u64) from the 8 x u32-limb
            // accumulator committed in COL_STATE_WRITES_0..7.
            let acc_lane = |k: usize| {
                cur[COL_STATE_WRITES_0 + 2 * k].into()
                    + cur[COL_STATE_WRITES_0 + 2 * k + 1].into()
                        * AB::Expr::from(AB::F::from_u64(1u64 << 32))
            };
            // The Merkle lanes: the node and the buffer, ordered by the key bit. Lanes 0..4
            // are the left child, lanes 4..8 the right child.
            let merkle_bit_here: AB::Expr = cur[COL_VM_MERKLE_BIT].into();
            let merkle_lane = |k: usize, right: bool| -> AB::Expr {
                let node: AB::Expr = cur[COL_MERKLE_CUR + k].into();
                let buf: AB::Expr = cur[COL_MERKLE_BUF + k].into();
                let (first, second) = if right { (buf, node) } else { (node, buf) };
                first * (one.clone() - merkle_bit_here.clone()) + second * merkle_bit_here.clone()
            };
            let mut expected: Vec<AB::Expr> = vec![AB::Expr::ZERO; POSEIDON_WIDTH];
            expected[0] = p_poseidon.clone() * rs1_val.clone()
                + p_commit.clone() * rs1_val.clone()
                + p_null.clone() * rs2_val.clone()
                + p_sw.clone() * storage_slot.clone();
            expected[1] = p_poseidon.clone() * rs2_val.clone()
                + p_commit.clone() * rs2_val.clone()
                + p_null.clone() * domain_nullifier
                + p_sw.clone() * rs1_val.clone();
            expected[2] = p_commit.clone() * imm.clone() + p_sw.clone() * acc_lane(0);
            expected[3] = p_sw.clone() * acc_lane(1);
            expected[4] = p_sw.clone() * acc_lane(2);
            expected[5] = p_sw.clone() * acc_lane(3);
            for k in 0..4 {
                expected[k] = expected[k].clone() + p_merkle.clone() * merkle_lane(k, false);
                expected[4 + k] = expected[4 + k].clone() + p_merkle.clone() * merkle_lane(k, true);
            }
            // Lanes 8..12 (the capacity) start at zero for every use.
            for (lane, want) in expected.into_iter().enumerate() {
                builder
                    .when(p.clone())
                    .assert_eq(cur[COL_POSEIDON_STATE_BASE + lane].into(), want);
            }

            // Single source of truth: the VM computes what the AIR checks, so
            // both read the same constants. All three used to carry their own
            // copy of a 4-round prefix.
            use bud_vm::{POSEIDON_MDS as MDS, POSEIDON_RC_FULL as RC};

            // Running expression for the final Poseidon output (MDS row 0 of last round).
            let mut poseidon_out: AB::Expr = AB::Expr::ZERO;

            for r in 0..POSEIDON_ROUNDS {
                let lanes = poseidon_sbox_lanes(r);
                let sbox_off = poseidon_sbox_offset(r);
                let mut sbox_out = vec![AB::Expr::ZERO; POSEIDON_WIDTH];

                for i in 0..POSEIDON_WIDTH {
                    let s: AB::Expr = cur[COL_POSEIDON_STATE_BASE + r * POSEIDON_WIDTH + i].into()
                        + AB::Expr::from(AB::F::from_u64(RC[r][i]));

                    if i < lanes {
                        // S-box lane: constrain x^2 and x^4 against witness
                        // columns, then build x^7 = x^4 * x^2 * x.
                        let x2: AB::Expr = cur[COL_POSEIDON_X2_BASE + sbox_off + i].into();
                        let x4: AB::Expr = cur[COL_POSEIDON_X4_BASE + sbox_off + i].into();
                        builder
                            .when(p.clone())
                            .assert_eq(x2.clone(), s.clone() * s.clone());
                        builder
                            .when(p.clone())
                            .assert_eq(x4.clone(), x2.clone() * x2.clone());
                        sbox_out[i] = x4 * x2 * s;
                    } else {
                        // Partial round, lane above 0: the round constant is
                        // still added but the S-box is skipped, so the value
                        // passes through linearly. No witness column is spent
                        // and no constraint is needed beyond this identity.
                        sbox_out[i] = s;
                    }
                }

                if r + 1 < POSEIDON_ROUNDS {
                    for i in 0..POSEIDON_WIDTH {
                        let mut sum: AB::Expr = AB::Expr::ZERO;
                        for j in 0..POSEIDON_WIDTH {
                            sum += sbox_out[j].clone() * AB::Expr::from(AB::F::from_u64(MDS[i][j]));
                        }
                        builder.when(p.clone()).assert_eq(
                            cur[COL_POSEIDON_STATE_BASE + (r + 1) * POSEIDON_WIDTH + i].into(),
                            sum,
                        );
                    }
                } else {
                    let mut sum: AB::Expr = AB::Expr::ZERO;
                    for j in 0..POSEIDON_WIDTH {
                        sum += sbox_out[j].clone() * AB::Expr::from(AB::F::from_u64(MDS[0][j]));
                    }
                    poseidon_out = sum;
                    // HIGH CWE-345: the first 4 lanes of the last-round SWrite
                    // output become the next accumulator (8 x u32 limbs).
                    for k in 0..4 {
                        let mut out_k: AB::Expr = AB::Expr::ZERO;
                        for j in 0..POSEIDON_WIDTH {
                            out_k +=
                                sbox_out[j].clone() * AB::Expr::from(AB::F::from_u64(MDS[k][j]));
                        }
                        // The same four lanes are the node a Merkle level hands to the
                        // next row.
                        builder
                            .when_transition()
                            .when(p_merkle.clone())
                            .assert_eq(nxt[COL_MERKLE_CUR + k].into(), out_k.clone());
                        let next_limb_lo: AB::Expr = nxt[COL_STATE_WRITES_0 + 2 * k].into();
                        let next_limb_hi: AB::Expr = nxt[COL_STATE_WRITES_0 + 2 * k + 1].into();
                        builder.when_transition().when(is_swrite.clone()).assert_eq(
                            next_limb_lo
                                + next_limb_hi * AB::Expr::from(AB::F::from_u64(1u64 << 32)),
                            out_k,
                        );
                    }
                }
            }

            // Poseidon opcode + PrivacyCommit: rd equals the Poseidon output.
            builder
                .when(p_poseidon.clone() + p_commit.clone())
                .assert_eq(rd_val_new.clone(), poseidon_out.clone());

            // NullifierCheck: rd is boolean equality of (poseidon_out == rs1/claimed).
            // Reuse COL_EQ_DIFF_INV as inverse witness for (out - claimed).
            {
                let diff = poseidon_out.clone() - rs1_val.clone();
                let diff_inv: AB::Expr = cur[COL_EQ_DIFF_INV].into();
                let is_nonzero = diff.clone() * diff_inv.clone();
                builder.when(p_null.clone()).assert_bool(is_nonzero.clone());
                builder
                    .when(p_null.clone())
                    .assert_zero(diff * (one.clone() - is_nonzero.clone()));
                // Rd = 1 iff equal iff is_nonzero == 0
                builder
                    .when(p_null.clone())
                    .assert_eq(rd_val_new.clone(), one.clone() - is_nonzero);
                builder.when(p_null.clone()).assert_bool(rd_val_new.clone());
            }
        }

        // --- SumConservation (0x22) ---
        // Value conservation private witness: rd = 1 iff rs1 (Σin) == rs2 (Σout).
        // Amounts are bound to commitments by PrivacyCommit on other rows.
        // Poseidon commitments are NOT additively homomorphic; the soundness
        // Of a full private transfer requires the prover to also open the
        // Commitments inside the same STARK (PrivacyCommit rows). This
        // Opcode enforces the arithmetic equality gate.
        {
            let sc: AB::Expr = is_sum_conservation.clone();
            let diff = rs1_val.clone() - rs2_val.clone();
            let diff_inv: AB::Expr = cur[COL_EQ_DIFF_INV].into();
            let is_nonzero = diff.clone() * diff_inv.clone();
            builder.when(sc.clone()).assert_bool(is_nonzero.clone());
            builder
                .when(sc.clone())
                .assert_zero(diff * (one.clone() - is_nonzero.clone()));
            builder
                .when(sc.clone())
                .assert_eq(rd_val_new.clone(), one.clone() - is_nonzero);
            builder.when(sc).assert_bool(rd_val_new.clone());
        }
    }
}
