use crate::adapter::{
    ExecutionPublicInputs, ProofEnvelope, ProverAdapter, ProverError, VerifyError,
    PROOF_FORMAT_VERSION,
};
use crate::bud_stark::{
    prove_with_preprocessed, setup_preprocessed,
    verify_with_preprocessed as stark_verify_with_preprocessed, StarkConfig,
};
use crate::plonky3_air::*;
use bud_vm::{Step, Vm};
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::TwoAdicFriPcs;
use p3_goldilocks::Goldilocks;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_util::log2_strict_usize;
use std::boxed::Box;
use tiny_keccak::{Hasher, Keccak};
use tracing::{debug, info};

type MyExtensionField = BinomialExtensionField<Goldilocks, 2>;
type MyHasher = SerializingHasher<Keccak256Hash>;
type MyCompress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;
type MyMmcs = MerkleTreeMmcs<Goldilocks, u8, MyHasher, MyCompress, 2, 32>;
type MyChallengeMmcs = ExtensionMmcs<Goldilocks, MyExtensionField, MyMmcs>;
type MyPcs = TwoAdicFriPcs<Goldilocks, Radix2DitParallel<Goldilocks>, MyMmcs, MyChallengeMmcs>;
type MyChallenger = SerializingChallenger64<Goldilocks, HashChallenger<u8, Keccak256Hash, 32>>;
type MyConfig = StarkConfig<MyPcs, MyExtensionField, MyChallenger>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegEvent {
    clk: u64,
    idx: u64,
    val: u64,
    is_write: bool,
    sub_clk: u8,
    /// This row reads a register the trace never wrote, so it describes the
    /// register file execution began from rather than anything execution did.
    is_init: bool,
}

#[derive(Clone, Copy)]
struct MemEvent {
    clk: u64,
    /// The table: `TID_MEMORY`, `TID_STACK` or `TID_STORAGE`.
    tid: u64,
    /// The address inside the table.
    addr: u64,
    val: u64,
    is_write: bool,
    /// This row describes memory as the host left it before execution, not
    /// something the program did. See `COL_MEM_IS_INIT`.
    is_init: bool,
}

const TID_MEMORY: u64 = 1;
const TID_STACK: u64 = 2;
const TID_STORAGE: u64 = 3;

/// The field fold tag of a memory event in `COL_MEM_INIT_ACC`, matching
/// `m_tid * 2^32 + m_addr` in Goldilocks arithmetic.
fn mem_key(tid: u64, addr: u64) -> u64 {
    (Goldilocks::new(tid) * Goldilocks::new(1u64 << 32) + Goldilocks::new(addr)).as_canonical_u64()
}

pub struct Plonky3Adapter;

fn build_config() -> MyConfig {
    let hash = MyHasher::new(Keccak256Hash {});
    let compress = MyCompress::new(Keccak256Hash {});
    let val_mmcs = MyMmcs::new(hash, compress, 0);
    let challenge_mmcs = MyChallengeMmcs::new(val_mmcs.clone());
    let fri_params = p3_fri::FriParameters {
        log_blowup: 3,
        max_log_arity: 2,
        log_final_poly_len: 0,
        num_queries: 100,
        commit_proof_of_work_bits: 16,
        query_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    // The parameters both sides absorb into the transcript, read back out of
    // the same value handed to the PCS rather than written a second time. A
    // hand-written copy is a second source of truth that can drift from the
    // one that governs the proof, which is the whole failure this binding
    // exists to prevent.
    let security = vec![
        fri_params.log_blowup as u64,
        fri_params.max_log_arity as u64,
        fri_params.log_final_poly_len as u64,
        fri_params.num_queries as u64,
        fri_params.commit_proof_of_work_bits as u64,
        fri_params.query_proof_of_work_bits as u64,
    ];
    let inner_challenger = HashChallenger::<u8, Keccak256Hash, 32>::new(vec![], Keccak256Hash {});
    let challenger = MyChallenger::new(inner_challenger);
    let dft = Radix2DitParallel::default();
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    MyConfig::new_with_security(pcs, challenger, security)
}

/// Whether the VM writes `rd` for this opcode. The AIR sums 22 selectors into
/// `writes_rd`. This list also holds the reserved `VerifyInference`: the AIR
/// leaves it out because its selector is zero on every row.
fn opcode_writes_rd(op: bud_isa::Opcode) -> bool {
    use bud_isa::Opcode as O;
    matches!(
        op,
        O::Add
            | O::Sub
            | O::Mul
            | O::Div
            | O::Inv
            | O::And
            | O::Not
            | O::Load
            | O::Pop
            | O::Eq
            | O::Neq
            | O::Lt
            | O::Gt
            | O::Lte
            | O::Gte
            | O::SRead
            | O::Poseidon
            | O::Syscall
            | O::VerifyMerkle
            | O::VerifyInference
            | O::PrivacyCommit
            | O::NullifierCheck
            | O::SumConservation
    )
}

/// The value `rd` holds while this step runs. An opcode that writes no
/// register leaves it alone, so the register file after the step is the same
/// file the step started from.
fn rd_value_kept(step: &Step) -> u64 {
    if step.dst_idx == 0 {
        0
    } else {
        step.registers[step.dst_idx as usize]
    }
}

fn register_events(trace: &[Step]) -> Vec<RegEvent> {
    let mut events = Vec::new();

    for (i, step) in trace.iter().enumerate() {
        if step.instruction.opcode == bud_isa::Opcode::Halt {
            continue;
        }
        // Merkle and VerifyInference expansion rows are synthetic - no
        // register bus traffic (they reuse the original opcode with
        // zeroed operands). (2026-08-28) COL_INFERENCE_IS_EXPAND was
        // missing here: 8 expansion rows per VerifyInference step produced
        // 24 phantom register events, unbalancing the Register LogUp and
        // rejecting every clean VerifyInference proof.
        if step.merkle_is_expand || step.inference_is_expand {
            continue;
        }
        let clk = i as u64;
        events.push(RegEvent {
            clk,
            idx: step.src1_idx as u64,
            val: step.src1_val,
            is_write: false,
            sub_clk: 1,
            is_init: false,
        });
        events.push(RegEvent {
            clk,
            idx: step.src2_idx as u64,
            val: step.src2_val,
            is_write: false,
            sub_clk: 2,
            is_init: false,
        });
        let writes_rd = opcode_writes_rd(step.instruction.opcode);
        events.push(RegEvent {
            clk,
            idx: step.dst_idx as u64,
            val: if step.dst_idx == 0 {
                0
            } else if writes_rd {
                step.dst_val
            } else {
                rd_value_kept(step)
            },
            is_write: writes_rd,
            sub_clk: 3,
            is_init: false,
        });
    }

    events.sort_by_key(|e| (e.idx, e.clk, e.sub_clk));
    // Mark the rows that describe the starting register file, now that the
    // events are grouped by index. Same rule as the memory table: the first
    // touch of an index, when that touch is a read of a non-zero value, is
    // reading state the trace did not produce.
    let mut prev_idx: Option<u64> = None;
    for e in events.iter_mut() {
        let first_at_idx = prev_idx != Some(e.idx);
        prev_idx = Some(e.idx);
        e.is_init = first_at_idx && !e.is_write && e.val != 0;
    }
    events
}

/// The starting register values a trace reads, in the order the AIR folds
/// them.
///
/// The companion to [`initial_memory_reads`]. Callers need both to compute
/// `initial_state_root`: limbs 0 and 1 carry the memory image, limbs 2 and 3
/// the register image, and getting either set or order wrong produces a proof
/// the AIR rejects.
pub fn initial_register_reads(trace: &[Step]) -> Vec<(u64, u64)> {
    register_events(trace)
        .into_iter()
        .filter(|e| e.is_init)
        .map(|e| (e.idx, e.val))
        .collect()
}

/// Build the memory event list, marking the rows that describe pre-execution
/// state.
///
/// A read is "initial" when it is the first event at its address and returns a
/// non-zero value: nothing in the trace wrote it, so it came from the image the
/// host placed in memory. Those rows are exempt from the AIR's first-read-zero
/// rule and are folded into the commitment the verifier checks instead.
fn memory_events(trace: &[Step]) -> Vec<MemEvent> {
    let mut events = Vec::new();
    for (i, step) in trace.iter().enumerate() {
        let clk = i as u64;
        if let Some(addr) = step.memory_addr {
            events.push(MemEvent {
                clk,
                tid: TID_MEMORY,
                addr: addr as u64,
                val: step.memory_val.unwrap_or(0),
                is_write: step.is_memory_write,
                is_init: false,
            });
        }

        let opcode = step.instruction.opcode;
        match opcode {
            bud_isa::Opcode::Push => {
                events.push(MemEvent {
                    clk,
                    tid: TID_STACK,
                    addr: (step.stack_pointer as u64).wrapping_sub(1),
                    val: step.src1_val,
                    is_write: true,
                    is_init: false,
                });
            }
            bud_isa::Opcode::Pop => {
                events.push(MemEvent {
                    clk,
                    tid: TID_STACK,
                    addr: step.stack_pointer as u64,
                    val: step.dst_val,
                    is_write: false,
                    is_init: false,
                });
            }
            bud_isa::Opcode::Call => {
                events.push(MemEvent {
                    clk,
                    tid: TID_STACK,
                    addr: (step.stack_pointer as u64).wrapping_sub(1),
                    val: step.pc as u64 + 1,
                    is_write: true,
                    is_init: false,
                });
            }
            bud_isa::Opcode::Ret => {
                events.push(MemEvent {
                    clk,
                    tid: TID_STACK,
                    addr: step.stack_pointer as u64,
                    val: step.dst_val,
                    is_write: false,
                    is_init: false,
                });
            }
            bud_isa::Opcode::SRead => {
                let slot: u64 = if step.instruction.imm == -1 {
                    step.src2_val
                } else {
                    bud_vm::constant_storage_slot(step.instruction.imm)
                };
                events.push(MemEvent {
                    clk,
                    tid: TID_STORAGE,
                    addr: slot,
                    val: step.dst_val,
                    is_write: false,
                    is_init: false,
                });
            }
            bud_isa::Opcode::SWrite => {
                let slot: u64 = if step.instruction.imm == -1 {
                    step.src2_val
                } else {
                    bud_vm::constant_storage_slot(step.instruction.imm)
                };
                events.push(MemEvent {
                    clk,
                    tid: TID_STORAGE,
                    addr: slot,
                    val: step.src1_val,
                    is_write: true,
                    is_init: false,
                });
            }
            _ => {}
        }
    }
    events.sort_by_key(|e| (e.tid, Goldilocks::new(e.addr).as_canonical_u64(), e.clk));
    // Mark the pre-execution rows now that the events are grouped by canonical cell.
    //
    // Only the memory table carries seeded state: storage and stack both start
    // empty, and the AIR pins `COL_MEM_IS_INIT` to `tid == 1` because the
    // initial-image fold key `tid * 2^32 + addr` is injective only for bounded
    // addresses, which full-width storage slots do not have. Marking a storage
    // row here would make the honest matrix fail that AIR constraint.
    let mut prev_cell: Option<(u64, u64)> = None;
    for e in events.iter_mut() {
        let canon_addr = Goldilocks::new(e.addr).as_canonical_u64();
        let first_at_cell = prev_cell != Some((e.tid, canon_addr));
        prev_cell = Some((e.tid, canon_addr));
        e.is_init = e.tid == TID_MEMORY && first_at_cell && !e.is_write && e.val != 0;
    }
    events
}

/// The seeded reads a trace performs, in the order the AIR folds them.
///
/// Callers need this to compute `initial_state_root`: the commitment covers
/// exactly the pre-written words the program read, and getting the set or the
/// order wrong produces a proof the AIR rejects.
///
/// Each read is `(key, value)` with `key = table id * 2^32 + address`, the
/// number the AIR folds. A memory cell and a storage slot with one address
/// have two keys.
pub fn initial_memory_reads(trace: &[Step]) -> Vec<(u64, u64)> {
    memory_events(trace)
        .into_iter()
        .filter(|e| e.is_init)
        .map(|e| (mem_key(e.tid, e.addr), e.val))
        .collect()
}

#[doc(hidden)]
pub fn trace_matrix(
    trace: &[Step],
    program: &[u64],
    public_inputs: &ExecutionPublicInputs,
) -> (RowMajorMatrix<Goldilocks>, usize) {
    let events = register_events(trace);
    let mem_events = memory_events(trace);
    let n_cpu = trace.len();
    let n_reg = events.len();
    let n_mem = mem_events.len();
    let num_rows = (3 * n_cpu + 1).next_power_of_two().max(16);

    let mut values = vec![Goldilocks::new(0); num_rows * TRACE_WIDTH];

    // The Program CTL multiplicity witness. Row `i` carries how many times
    // pc=`i` was executed; that is the LogUp weight of the ROM side.
    //
    // VerifyMerkle expansion rows reuse the same (pc, raw_inst) tuple as the
    // original step and the CTL leaves them out via `is_expand`, so they are
    // not counted here either.
    {
        let prog_len = program.len();
        let mut mult = vec![0u64; prog_len];
        for step in trace {
            // Expansion rows reuse the same (pc, raw_inst) tuple as the
            // original step; because the CTL excludes them via `is_expand`
            // they do not join the multiplicity either. If they did, a single
            // VerifyMerkle step would be counted 65 times.
            if step.merkle_is_expand || step.inference_is_expand {
                continue;
            }
            if step.pc < prog_len {
                mult[step.pc] += 1;
            }
        }
        for (pc, count) in mult.iter().enumerate() {
            if pc < num_rows {
                values[pc * TRACE_WIDTH + COL_PROG_MULT] = Goldilocks::new(*count);
            }
        }
    }

    let mut running_gas = 0u64;

    for (i, step) in trace.iter().enumerate() {
        let row_start = i * TRACE_WIDTH;
        let op = step.instruction.opcode as u8;
        // HIGH CWE-345 (2026-08-17): state-write accumulator. Row 0
        // starts at zero; later rows are filled by the post-loop carry below
        // (which never overwrites the fresh value an SWrite row wrote into
        // the following row).
        if i == 0 {
            for j in 0..8 {
                values[row_start + COL_STATE_WRITES_0 + j] = Goldilocks::ZERO;
            }
        }
        values[row_start + COL_CLK] = Goldilocks::new(i as u64);
        values[row_start + COL_PC] = Goldilocks::new(step.pc as u64);
        values[row_start + COL_OPCODE] = Goldilocks::new(op as u64);

        // (security audit) first-row initial-state binding
        // And trace-length counter (only meaningful on the first real
        // Row, but we update it on every real row so the AIR can check
        // It on the last row as well).
        if i == 0 {
            for j in 0..8 {
                let mut word = [0u8; 4];
                word.copy_from_slice(&public_inputs.initial_state_root[j * 4..j * 4 + 4]);
                let limb = u32::from_le_bytes(word);
                values[row_start + COL_INIT_ROOT_0 + j] = Goldilocks::new(limb as u64);
            }
            // Gas_limit: bound to public_inputs[32,33] on the first
            // Real row. The AIR checks `COL_GAS_LIMIT == public.gas_limit`
            // Via `when_first_row`; we simply record the value here so
            // A malicious prover cannot pick something else.
            //
            // We don't yet have vm.gas_limit in this function; the
            // Caller passes it through `public_inputs` already.
            values[row_start + COL_GAS_LIMIT] = Goldilocks::new(public_inputs.gas_limit);
            // Chain_id: bound to public_inputs[0,1] on the first row.
            // Chain_id is a fixed domain constant - we record
            // (public.chain_id & 0xFFFFFFFF) here; the AIR compares
            // It to public_inputs[0,1] on the first row.
            values[row_start + COL_CHAIN_ID] =
                Goldilocks::new(public_inputs.chain_id & 0xFFFF_FFFF);
        }
        // Event_digest accumulator: 8 x u32 limbs, initialised to 0
        // On the first row, then updated on every Log row by
        // `prev + (val mod 2^32)` per limb (additive accumulator).
        // The first limb tracks the current event; remaining limbs
        // Are reserved for future use and stay 0 for now. The AIR
        // Binds the last real row to public_inputs[40..48].
        for j in 0..8 {
            values[row_start + COL_EVENT_DIGEST_0 + j] = if i == 0 {
                Goldilocks::new(0)
            } else {
                values[(i - 1) * TRACE_WIDTH + COL_EVENT_DIGEST_0 + j]
            };
        }
        if op == 0x1A {
            // Log opcode: accumulate rs1 into limb 0 of the event digest.
            //
            // The whole value, in the field - not the low 32 bits. The AIR
            // constrains `nxt_event_0 - cur_event_0 - is_log * nxt_rs1 == 0`
            // and `nxt_rs1` is the full register, so masking here made the
            // witness disagree with the constraint for any logged value at or
            // above 2^32. Small values matched by accident, which is why the
            // mismatch survived: every test logged a small constant, and the
            // one caller that logged a Poseidon output never verified its own
            // proof.
            values[row_start + COL_EVENT_DIGEST_0] += Goldilocks::new(step.src1_val);
        }
        if op == 0x1D {
            // One flag per known syscall number. The AIR reads these instead
            // of the polynomial factors it used to build from `imm`, because
            // a polynomial can say "not two or three or six" and cannot say
            // "is one", and the difference is every unrecognised number. See
            // `COL_SYSCALL_IS_1`.
            for (number, col) in [
                (1i32, COL_SYSCALL_IS_1),
                (2, COL_SYSCALL_IS_2),
                (3, COL_SYSCALL_IS_3),
            ] {
                if step.instruction.imm == number {
                    values[row_start + col] = Goldilocks::new(1);
                }
            }
        }
        if op == 0x1D && step.instruction.imm == 6 {
            // Syscall 6 announces two events, the AI inference marker and its
            // rs1, so both go into the digest. The caller builds the public
            // input from `receipt.events`, which contains exactly these two,
            // and until the AIR counted them no program using this syscall
            // could be proven. See `COL_SYSCALL_IS_6`.
            values[row_start + COL_SYSCALL_IS_6] = Goldilocks::new(1);
            values[row_start + COL_EVENT_DIGEST_0] += Goldilocks::new(0x00A1_00A1);
            values[row_start + COL_EVENT_DIGEST_0] += Goldilocks::new(step.src1_val);
        }
        values[row_start + COL_RD_IDX] = Goldilocks::new(step.dst_idx as u64);
        values[row_start + COL_RS1_IDX] = Goldilocks::new(step.src1_idx as u64);
        values[row_start + COL_RS2_IDX] = Goldilocks::new(step.src2_idx as u64);
        values[row_start + COL_RS1_VAL] = Goldilocks::new(step.src1_val);
        values[row_start + COL_RS2_VAL] = Goldilocks::new(step.src2_val);
        // The value the instruction computed, whatever its destination. This
        // used to be forced to zero when the destination was r0, which kept
        // the register bus honest but broke the per opcode rules: `Add r0,
        // r1, r2` then asked the AIR for `0 == rs1 + rs2`, so any program
        // writing to r0 could run and never be proved. The zeroing now happens
        // where it belongs, on the register bus, gated by COL_RD_IDX_INV.
        // An opcode that writes no register reads `rd` at its current value,
        // which is what the register bus expects of it.
        values[row_start + COL_RD_VAL_NEW] =
            Goldilocks::new(if opcode_writes_rd(step.instruction.opcode) {
                step.dst_val
            } else {
                rd_value_kept(step)
            });
        // Inverse witness deciding, in circuit, whether this row writes to r0.
        values[row_start + COL_RD_IDX_INV] = Goldilocks::new(if step.dst_idx == 0 {
            0
        } else {
            bud_vm::field_inverse_goldilocks(step.dst_idx as u64)
        });
        // Inverse witness deciding, in circuit, whether this row addresses
        // memory. `Load rd, r0, imm` is load-immediate and touches none.
        values[row_start + COL_RS1_IDX_INV] = Goldilocks::new(if step.src1_idx == 0 {
            0
        } else {
            bud_vm::field_inverse_goldilocks(step.src1_idx as u64)
        });
        values[row_start + COL_NEXT_PC] = Goldilocks::new(step.next_pc as u64);
        values[row_start + COL_CPU_ACTIVE] = Goldilocks::new(1);

        let opcode = step.instruction.opcode;
        let cur_stack_ptr = match opcode {
            bud_isa::Opcode::Push | bud_isa::Opcode::Call => step.stack_pointer - 1,
            bud_isa::Opcode::Pop | bud_isa::Opcode::Ret => step.stack_pointer + 1,
            _ => step.stack_pointer,
        };
        values[row_start + COL_STACK_PTR] = Goldilocks::new(cur_stack_ptr as u64);

        let imm = step.instruction.imm;
        values[row_start + COL_IMM] = if imm < 0 {
            // unsigned_abs(): -imm i32::MIN'de panic eder (2026-08-17).
            Goldilocks::new(0) - Goldilocks::new(imm.unsigned_abs() as u64)
        } else {
            Goldilocks::new(imm as u64)
        };

        // Soundness & public input columns
        values[row_start + COL_GAS_USED] = Goldilocks::new(running_gas);
        // Expansion rows reuse Opcode::VerifyMerkle but must
        // Not re-charge gas (matches BudAir gas_cost = is_verify_merkle *
        // (1 - is_expand) * 10). VM only charges once for the original step.
        // Same for VerifyInference expansion rows.
        if !step.merkle_is_expand && !step.inference_is_expand {
            running_gas = running_gas.saturating_add(Vm::gas_cost(opcode));
        }

        values[row_start + COL_RAW_INST] = Goldilocks::new(step.instruction.encode());

        if opcode == bud_isa::Opcode::Div {
            let b = step.src2_val;
            let (inv, zero) = if b != 0 {
                (bud_vm::field_inverse_goldilocks(b), 0)
            } else {
                (0, 1)
            };
            values[row_start + COL_DIV_INV] = Goldilocks::new(inv);
            values[row_start + COL_DIV_ZERO] = Goldilocks::new(zero);
        }

        if opcode == bud_isa::Opcode::Inv {
            let a = step.src1_val;
            let zero = if a != 0 { 0 } else { 1 };
            values[row_start + COL_INV_ZERO] = Goldilocks::new(zero);
        }

        if opcode == bud_isa::Opcode::Assert {
            // The witness proving the condition is non-zero. The VM refuses
            // only on zero, so any other value has an inverse and the AIR's
            // `z = rs1 * assert_inv` comes out 1. A row that reaches here at
            // all passed the VM, so `src1_val` is never zero, but the branch
            // is written for both cases rather than relying on that.
            let a = step.src1_val;
            values[row_start + COL_ASSERT_INV] = Goldilocks::new(if a == 0 {
                0
            } else {
                bud_vm::field_inverse_goldilocks(a)
            });
        }

        if opcode == bud_isa::Opcode::Eq || opcode == bud_isa::Opcode::Neq {
            let diff = bud_vm::field_sub_goldilocks(step.src1_val, step.src2_val);
            let inv = if diff != 0 {
                bud_vm::field_inverse_goldilocks(diff)
            } else {
                0
            };
            values[row_start + COL_EQ_DIFF_INV] = Goldilocks::new(inv);
        }

        // SumConservation equality witness (rs1 - rs2).
        if opcode == bud_isa::Opcode::SumConservation {
            let diff = bud_vm::field_sub_goldilocks(step.src1_val, step.src2_val);
            let inv = if diff != 0 {
                bud_vm::field_inverse_goldilocks(diff)
            } else {
                0
            };
            values[row_start + COL_EQ_DIFF_INV] = Goldilocks::new(inv);
        }

        if opcode == bud_isa::Opcode::Jnz {
            let cond = step.src1_val;
            let inv = if cond != 0 {
                bud_vm::field_inverse_goldilocks(cond)
            } else {
                0
            };
            values[row_start + COL_JNZ_COND_INV] = Goldilocks::new(inv);
        }

        match op {
            0x01 => values[row_start + COL_IS_ADD] = Goldilocks::new(1),
            0x02 => values[row_start + COL_IS_SUB] = Goldilocks::new(1),
            0x03 => values[row_start + COL_IS_MUL] = Goldilocks::new(1),
            0x04 => values[row_start + COL_IS_DIV] = Goldilocks::new(1),
            0x05 => values[row_start + COL_IS_INV] = Goldilocks::new(1),
            0x06 => values[row_start + COL_IS_AND] = Goldilocks::new(1),
            0x09 => values[row_start + COL_IS_NOT] = Goldilocks::new(1),
            0x0A => values[row_start + COL_IS_EQ] = Goldilocks::new(1),
            0x0B => values[row_start + COL_IS_NEQ] = Goldilocks::new(1),
            0x0C => values[row_start + COL_IS_LT] = Goldilocks::new(1),
            0x0D => values[row_start + COL_IS_GT] = Goldilocks::new(1),
            0x0E => values[row_start + COL_IS_LTE] = Goldilocks::new(1),
            0x0F => values[row_start + COL_IS_GTE] = Goldilocks::new(1),
            0x10 => values[row_start + COL_IS_JMP] = Goldilocks::new(1),
            0x11 => {
                values[row_start + COL_IS_JNZ] = Goldilocks::new(1);
                values[row_start + COL_JNZ_COND] = if step.src1_val != 0 {
                    Goldilocks::new(1)
                } else {
                    Goldilocks::new(0)
                };
            }
            0x12 => values[row_start + COL_IS_CALL] = Goldilocks::new(1),
            0x13 => values[row_start + COL_IS_RET] = Goldilocks::new(1),
            0x14 => values[row_start + COL_IS_LOAD] = Goldilocks::new(1),
            0x15 => values[row_start + COL_IS_STORE] = Goldilocks::new(1),
            0x16 => values[row_start + COL_IS_PUSH] = Goldilocks::new(1),
            0x17 => values[row_start + COL_IS_POP] = Goldilocks::new(1),
            0x18 => values[row_start + COL_IS_ASSERT] = Goldilocks::new(1),
            0x19 => values[row_start + COL_IS_POSEIDON] = Goldilocks::new(1),
            0x1A => values[row_start + COL_IS_LOG] = Goldilocks::new(1),
            0x1B => values[row_start + COL_IS_SREAD] = Goldilocks::new(1),
            0x1C => values[row_start + COL_IS_SWRITE] = Goldilocks::new(1),
            0x1D => values[row_start + COL_IS_SYSCALL] = Goldilocks::new(1),
            0x1E => values[row_start + COL_IS_VERIFY_MERKLE] = Goldilocks::new(1),
            0x1F => values[row_start + COL_IS_VERIFY_INFERENCE] = Goldilocks::new(1),
            0x20 => values[row_start + COL_IS_PRIVACY_COMMIT] = Goldilocks::new(1),
            0x21 => values[row_start + COL_IS_NULLIFIER_CHECK] = Goldilocks::new(1),
            0x22 => values[row_start + COL_IS_SUM_CONSERVATION] = Goldilocks::new(1),
            0x00 => values[row_start + COL_IS_HALT] = Goldilocks::new(1),
            _ => {}
        }

        // Comparison + Bitwise witness: bit decomposition + equality prefix flags
        let is_cmp = opcode == bud_isa::Opcode::Lt
            || opcode == bud_isa::Opcode::Gt
            || opcode == bud_isa::Opcode::Lte
            || opcode == bud_isa::Opcode::Gte;
        let is_bw_bits = opcode == bud_isa::Opcode::And;

        if is_cmp || is_bw_bits {
            let a = step.src1_val;
            let b = step.src2_val;

            for i in 0..64 {
                values[row_start + COL_CMP_RS1_BASE + i] = Goldilocks::new((a >> i) & 1);
                values[row_start + COL_CMP_RS2_BASE + i] = Goldilocks::new((b >> i) & 1);
            }

            // Canonicity witnesses. The AIR needs the inverse of
            // `high_half - 0xFFFFFFFF` to tell a saturated high half from any
            // other, which is what rules out the second bit string every value
            // below `2^32 - 1` would otherwise have. See `COL_CMP_RS1_HI_INV`.
            //
            // `a` and `b` come out of the VM as canonical u64s, so the
            // difference is zero only for the genuinely saturated patterns and
            // the inverse exists everywhere else.
            for (val, inv_col) in [(a, COL_CMP_RS1_HI_INV), (b, COL_CMP_RS2_HI_INV)] {
                let hi = val >> 32;
                // In the field, not with `wrapping_sub`. Measured: for
                // `hi = 0` the u64 wrap gives `0xFFFFFFFF00000001` while the
                // field difference is `P - 0xFFFFFFFF`, and those are
                // different elements, so the inverse would be the inverse of
                // the wrong value and every honest comparison would fail.
                let d = bud_vm::field_sub_goldilocks(hi, 0xFFFF_FFFF);
                values[row_start + inv_col] = Goldilocks::new(if d == 0 {
                    0
                } else {
                    bud_vm::field_inverse_goldilocks(d)
                });
            }

            if is_cmp {
                let mut eq_cur = true;
                for i in (0..64).rev() {
                    let a_i = (a >> i) & 1;
                    let b_i = (b >> i) & 1;
                    eq_cur = eq_cur && (a_i == b_i);
                    values[row_start + COL_CMP_EQ_BASE + i] =
                        Goldilocks::new(if eq_cur { 1 } else { 0 });
                }

                let mut eq_next = true;
                let mut cmp_lt_raw = 0u64;
                for i in (0..64).rev() {
                    let a_i = (a >> i) & 1;
                    let b_i = (b >> i) & 1;
                    let eq_bit = a_i == b_i;
                    if eq_next && !eq_bit && a_i == 0 && b_i == 1 {
                        cmp_lt_raw = 1;
                    }
                    eq_next = eq_next && eq_bit;
                }
                values[row_start + COL_CMP_LT_RAW] = Goldilocks::new(cmp_lt_raw);
            }
        }

        // Not (logical NOT) - store inverse witness in COL_INV_ZERO
        if opcode == bud_isa::Opcode::Not {
            let a = step.src1_val;
            let inv = if a != 0 {
                bud_vm::field_inverse_goldilocks(a)
            } else {
                0
            };
            values[row_start + COL_INV_ZERO] = Goldilocks::new(inv);
        }

        // Poseidon witness: fill 4-round state + S-box intermediates
        // + Poseidon: fill Poseidon witness columns for any opcode that
        // Uses the shared 4-round gadget (Poseidon / PrivacyCommit / NullifierCheck).
        let poseidon_init: Option<[u64; 8]> = match opcode {
            bud_isa::Opcode::Poseidon => Some([step.src1_val, step.src2_val, 0, 0, 0, 0, 0, 0]),
            bud_isa::Opcode::PrivacyCommit => {
                // HIGH (CWE-682, 2026-08-17): VM layout'i
                // poseidon4_hash3(amount=rs1, blinding=rs2, recipient=imm).
                // recipient must be BYTE-IDENTICAL to COL_IMM in the trace:
                // a negative imm carries the Goldilocks modular negative
                // (P - |imm|), not the i64->u64 two's complement.
                let imm = step.instruction.imm;
                // unsigned_abs(): -imm panics at i32::MIN (2026-08-17).
                let recipient = if imm < 0 {
                    bud_vm::GOLDILOCKS_P.wrapping_sub(imm.unsigned_abs() as u64)
                } else {
                    imm as u64
                };
                Some([step.src1_val, step.src2_val, recipient, 0, 0, 0, 0, 0])
            }
            bud_isa::Opcode::NullifierCheck => {
                // State = [secret=rs2, DOMAIN_NULLIFIER, 0..]
                Some([step.src2_val, bud_vm::DOMAIN_NULLIFIER, 0, 0, 0, 0, 0, 0])
            }
            bud_isa::Opcode::VerifyInference if !step.inference_is_expand => {
                // Stage 3a: state = [model_c, input_c, 0..0]; the AIR binds
                // the resulting poseidon_out to rd via the equality
                // constraint (rd = 1 iff output_c == Poseidon(model_c,
                // input_c)). Expansion rows take the default None branch
                // (no gadget on expansion rows).
                Some([
                    step.inference_model_commitment.unwrap_or(0),
                    step.inference_input_commitment.unwrap_or(0),
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
            }
            bud_isa::Opcode::SWrite => {
                let slot: u64 = if step.instruction.imm == -1 {
                    step.src2_val
                } else {
                    bud_vm::constant_storage_slot(step.instruction.imm)
                };
                let mut prev = [0u64; 4];
                for k in 0..4 {
                    let lo = values[row_start + COL_STATE_WRITES_0 + 2 * k].as_canonical_u64();
                    let hi = values[row_start + COL_STATE_WRITES_0 + 2 * k + 1].as_canonical_u64();
                    prev[k] = lo | (hi << 32);
                }
                Some([
                    slot,
                    step.src1_val,
                    prev[0],
                    prev[1],
                    prev[2],
                    prev[3],
                    0,
                    0,
                ])
            }
            _ => None,
        };

        // Stage 3a: poseidon_out must be visible outside the gadget block:
        // the VerifyInference equality witness below runs on EVERY
        // VerifyInference row (including expansion rows, where the gadget
        // block itself is skipped and poseidon_out stays zero).
        let mut poseidon_out = 0u64;
        if let Some(init_state) = poseidon_init {
            const P: u64 = 18446744069414584321;
            // Same constants the AIR reads; see plonky3_air.rs.
            use bud_vm::{POSEIDON_MDS as mds, POSEIDON_RC_FULL as rc};

            let mut s: [u64; 8] = init_state;

            for r in 0..POSEIDON_ROUNDS {
                for i in 0..8 {
                    values[row_start + COL_POSEIDON_STATE_BASE + r * 8 + i] = Goldilocks::new(s[i]);
                }

                let lanes = poseidon_sbox_lanes(r);
                let sbox_off = poseidon_sbox_offset(r);
                let mut sbox: [u64; 8] = [0; 8];
                for i in 0..8 {
                    let s_rc = ((s[i] as u128 + rc[r][i] as u128) % P as u128) as u64;
                    if i < lanes {
                        let x2 = ((s_rc as u128 * s_rc as u128) % P as u128) as u64;
                        let x4 = ((x2 as u128 * x2 as u128) % P as u128) as u64;
                        values[row_start + COL_POSEIDON_X2_BASE + sbox_off + i] =
                            Goldilocks::new(x2);
                        values[row_start + COL_POSEIDON_X4_BASE + sbox_off + i] =
                            Goldilocks::new(x4);
                        sbox[i] = (((x4 as u128 * x2 as u128) % P as u128 * s_rc as u128)
                            % P as u128) as u64;
                    } else {
                        // Partial round: no S-box above lane 0, the value
                        // carries through with only the round constant added.
                        sbox[i] = s_rc;
                    }
                }

                if r + 1 < POSEIDON_ROUNDS {
                    let mut next: [u64; 8] = [0; 8];
                    for i in 0..8 {
                        let mut sum: u128 = 0;
                        for j in 0..8 {
                            sum = (sum + mds[i][j] as u128 * sbox[j] as u128) % P as u128;
                        }
                        next[i] = sum as u64;
                    }
                    s = next;
                } else {
                    // Final round output = MDS row 0 * sbox (matches AIR / poseidon4_hash_state).
                    let mut sum: u128 = 0;
                    for j in 0..8 {
                        sum = (sum + mds[0][j] as u128 * sbox[j] as u128) % P as u128;
                    }
                    poseidon_out = sum as u64;
                    // HIGH CWE-345: for SWrite the WHOLE final state is
                    // needed (first 4 lanes become the next accumulator), not
                    // just lane 0.
                    if opcode == bud_isa::Opcode::SWrite {
                        for i in 0..8 {
                            let mut acc_sum: u128 = 0;
                            for j in 0..8 {
                                acc_sum =
                                    (acc_sum + mds[i][j] as u128 * sbox[j] as u128) % P as u128;
                            }
                            s[i] = acc_sum as u64;
                        }
                    }
                }
            }

            // HIGH CWE-345: SWrite writes the next accumulator into the
            // NEXT row's COL_STATE_WRITES_0..7 (first 4 lanes of the final
            // gadget state, split into 8 x u32 limbs).
            if opcode == bud_isa::Opcode::SWrite {
                for k in 0..4 {
                    let v = s[k];
                    let lo = (v & 0xFFFF_FFFF) as u32;
                    let hi = (v >> 32) as u32;
                    values[row_start + TRACE_WIDTH + COL_STATE_WRITES_0 + 2 * k] =
                        Goldilocks::new(lo as u64);
                    values[row_start + TRACE_WIDTH + COL_STATE_WRITES_0 + 2 * k + 1] =
                        Goldilocks::new(hi as u64);
                }
            }

            // NullifierCheck: equality witness for (poseidon_out - claimed_nullifier).
            if opcode == bud_isa::Opcode::NullifierCheck {
                let claimed = step.src1_val;
                // Field subtraction, not `wrapping_sub`: the AIR computes
                // `poseidon_out - rs1` in Goldilocks, so the inverse witness
                // has to be the inverse of the *field* difference. The two
                // agree only when `poseidon_out >= claimed`; otherwise
                // `wrapping_sub` produces `2^64 - d`, whose field
                // representative is `2^64 - d - P`, and the constraint
                // `diff * (1 - diff*inv) == 0` fails.
                let diff = bud_vm::field_sub_goldilocks(poseidon_out, claimed);
                let inv = if diff != 0 {
                    bud_vm::field_inverse_goldilocks(diff)
                } else {
                    0
                };
                values[row_start + COL_EQ_DIFF_INV] = Goldilocks::new(inv);
            }
        }

        // VerifyInference (stage 3a): equality witness for
        // (Poseidon(model, input) - claimed_output). Same field-subtraction
        // discipline as NullifierCheck: the AIR computes the difference
        // in Goldilocks, so the inverse witness must be the inverse of
        // the *field* difference.
        //
        // Expansion rows get the witness too: the AIR evaluates
        // diff = poseidon_out - output on every is_verify_inference row,
        // and on expansion rows poseidon_out collapses to ZERO (the x2/x4
        // witness columns are not written there, so the sbox expression
        // x4*x2*s vanishes and the whole gadget output is 0). The inverse
        // must therefore be inverse(0 - output_c) on expansion rows, or
        // the equality constraints fail on rows that carry a non-zero
        // output commitment (e.g. a valid chain, where output_c is a real
        // Poseidon hash).
        if opcode == bud_isa::Opcode::VerifyInference {
            let claimed = step.inference_output_commitment.unwrap_or(0);
            let diff = if step.inference_is_expand {
                bud_vm::field_sub_goldilocks(0, claimed)
            } else {
                bud_vm::field_sub_goldilocks(poseidon_out, claimed)
            };
            let inv = if diff != 0 {
                bud_vm::field_inverse_goldilocks(diff)
            } else {
                0
            };
            values[row_start + COL_EQ_DIFF_INV] = Goldilocks::new(inv);
        }

        // (security audit) trace-length counter and
        // (on the last real row) the final-state-root, event-digest
        // And exit-code binding. The counter is updated on every
        // Real row so the AIR can assert `COL_TRACE_LEN_CTR == n_cpu`
        // On the last real row (= n_cpu - 1, the synthetic Halt row
        // Added).
        values[row_start + COL_TRACE_LEN_CTR] = Goldilocks::new((i + 1) as u64);
        if i == n_cpu.saturating_sub(1) {
            for j in 0..8 {
                let mut word = [0u8; 4];
                word.copy_from_slice(&public_inputs.final_state_root[j * 4..j * 4 + 4]);
                let limb = u32::from_le_bytes(word);
                values[row_start + COL_FINAL_ROOT_0 + j] = Goldilocks::new(limb as u64);
            }
            // Exit_code: 0 = success (real Halt), 1 = error (
            // Synthetic Halt). The prover passes the right value
            // Through `public_inputs.exit_code`; the AIR binds it.
            values[row_start + COL_EXIT_CODE] = Goldilocks::new(public_inputs.exit_code);
            // HIGH CWE-345 (2026-08-17): the last real row's
            // COL_STATE_WRITES_0..7 is the carried accumulator value (filled
            // by the post-loop carry below), NOT a copy of the public input;
            // the AIR binds it to public[48..56].
        }

        // (security audit) Merkle expansion rows. The
        // Trace's CPU step is the original VerifyMerkle step on row
        // `i` if `step.merkle_is_expand` is true *or* if it carries
        // `merkle_key` (the original step's `merkle_key` patch
        // Happens immediately after the step is pushed in VM,
        // So we treat the first Merkle row in a sequence as the
        // "original" one). The expansion rows are pushed
        // Immediately after the original in `Vm::step`, so they
        // Share the same `i` index here.
        if step.merkle_is_expand {
            // Expansion row.
            // `Vm::step` fills these four together with `merkle_is_expand`,
            // so on an expansion row they are all present. Read as a group
            // rather than unwrapped one by one: the guarantee lives in
            // another crate, and a drift there must leave the row unwritten
            // instead of aborting the prover mid-trace.
            let (Some(key), Some(cur), Some(sibling), Some(round)) = (
                step.merkle_key,
                step.merkle_current,
                step.merkle_sibling,
                step.merkle_round,
            ) else {
                continue;
            };
            let bit = (key >> round) & 1;
            values[row_start + COL_VM_MERKLE_KEY] = Goldilocks::new(key);
            values[row_start + COL_VM_MERKLE_BIT] = Goldilocks::new(bit);
            // Remaining key for this round. The AIR walks this down with
            // `rem == 2 * rem' + bit`, which is what ties `bit` to `key`;
            // without it the direction bits were free and a flipped bit
            // produced a different root that the AIR still accepted.
            // The value expected by the original row that started this
            // expansion: the round-64 output that must be reached when the
            // path ends. The original row comes immediately before the
            // expansions, so we search backwards for the first non-expansion
            // Merkle row. If none is found it stays 0 and the AIR's last-round
            // equality breaks - rather than passing silently.
            let final_merkle_value = trace[..i]
                .iter()
                .rev()
                .find(|s| !s.merkle_is_expand)
                .and_then(|s| s.merkle_current)
                .unwrap_or(0);
            values[row_start + COL_MERKLE_KEY_REM] = Goldilocks::new(key >> round);
            values[row_start + COL_VM_MERKLE_CURRENT] = Goldilocks::new(cur);
            values[row_start + COL_VM_MERKLE_SIBLING] = Goldilocks::new(sibling);
            values[row_start + COL_VM_MERKLE_ROUND] = Goldilocks::new(round as u64);
            values[row_start + COL_VM_MERKLE_IS_EXPAND] = Goldilocks::new(1);
            // This column is no longer a flag but **a carried value**: the
            // round-64 output the original row will compare against the root
            // is carried unchanged through the expansion and checked for
            // equality with the output produced in the last round
            // (`plonky3_air.rs`, "The output of the last round ..."). It used
            // to be a constant 0 here and the AIR never read the column, so
            // the original row's value was bound to nothing.
            values[row_start + COL_MERKLE_FINAL_FLAG] = Goldilocks::new(final_merkle_value);

            // Poseidon witnesses: on every expansion row,
            // Populate the x^2 / x^4 columns with the Goldilocks
            // Poseidon single-round intermediates. We use the
            // First round of the existing 4-round Poseidon
            // (round constants RC[0], MDS first row).
            //
            // The first two state elements are `[cur, sibling]`
            // Or `[sibling, cur]` depending on the bit; the rest
            // Are zero (consistent with `Vm::poseidon4_hash`).
            const P_GOLDILOCKS: u64 = 0xFFFFFFFF00000001; // 2^64 - 2^32 + 1
            let p = P_GOLDILOCKS;
            let rc0: [u64; 8] = [
                0xdd5743e7f2a5a5d9,
                0xcb3a864e58ada44b,
                0xffa2449ed32f8cdc,
                0x42025f65d6bd13ee,
                0x7889175e25506323,
                0x34b98bb03d24b737,
                0xbdcc535ecc4faa2a,
                0x5b20ad869fc0d033,
            ];
            let s0_in = if bit == 0 { cur } else { sibling };
            let s1_in = if bit == 0 { sibling } else { cur };
            // X^2 = (s + rc)^2 (mod P)
            // (gate) use u128 for addition to prevent
            // Goldilocks field overflow. `wrapping_add` wraps at u64::MAX
            // But Goldilocks P = 2^64-2^32+1 < u64::MAX, so when
            // S_in + rc0[i] > u64::MAX the wrapping_add result is wrong
            // Mod P. The VM uses u128 correctly in `merkle_poseidon_round`.
            for (i, s_in) in [s0_in, s1_in].iter().enumerate() {
                let s_plus_rc = ((*s_in as u128 + rc0[i] as u128) % p as u128) as u64;
                let x2 = ((s_plus_rc as u128 * s_plus_rc as u128) % p as u128) as u64;
                let x4 = ((x2 as u128 * x2 as u128) % p as u128) as u64;
                values[row_start + COL_MERKLE_POSEIDON_X2_0 + i] = Goldilocks::new(x2);
                values[row_start + COL_MERKLE_POSEIDON_X4_0 + i] = Goldilocks::new(x4);
            }
            // Also fill the unused 6 elements with 0.
            for i in 2..8 {
                values[row_start + COL_MERKLE_POSEIDON_X2_0 + i] = Goldilocks::new(0);
                values[row_start + COL_MERKLE_POSEIDON_X4_0 + i] = Goldilocks::new(0);
            }
        } else if let Some(key) = step.merkle_key {
            // Original VerifyMerkle step. The VM patched this row
            // With merkle_key immediately after push.
            values[row_start + COL_VM_MERKLE_KEY] = Goldilocks::new(key);
            values[row_start + COL_VM_MERKLE_IS_EXPAND] = Goldilocks::new(0);
            // Merkle_current on the original step is the
            // 64th-round Poseidon accumulator (the final
            // Poseidon output of the path). The VM has
            // Already populated this on the Step in `Vm::step`
            // (Commit 3 trace layout decision: the original
            // Step carries the 64th-round output, allowing
            // The AIR to apply the final root check on the
            // Original step's row, bridging to rd_val_new).
            // The VM sets this on the original step; read it instead of
            // asserting, so a change there leaves the column at zero rather
            // than aborting the prover mid-trace.
            let final_merkle = step.merkle_current.unwrap_or(0);
            values[row_start + COL_VM_MERKLE_CURRENT] = Goldilocks::new(final_merkle);
            // Merkle_round=0 on the original step so the AIR can
            // Extract the right bit (key & 1) for the first
            // Expansion row.
            values[row_start + COL_VM_MERKLE_ROUND] = Goldilocks::new(0);
            // The bit on the original step is bit-0 (key & 1);
            // The expansion row 0 will write the real bit from
            // `(key >> 0) & 1`. They should match.
            values[row_start + COL_VM_MERKLE_BIT] = Goldilocks::new(key & 1);
            //: this is the "final" row of the
            // VerifyMerkle path - the AIR uses the final_flag
            // (1 only here) to apply the final root check on the
            // *64th* expansion row's `merkle_current`.
            values[row_start + COL_MERKLE_FINAL_FLAG] = Goldilocks::new(1);
            // Inverse-witness for final root equality check.
            // Rd_val_new is constrained to equal (final == root) as a field boolean.
            let root = step.src1_val;
            // Field subtraction, as for NullifierCheck above: the AIR forms
            // `final - root` in Goldilocks, so `wrapping_sub` gives a wrong
            // inverse witness whenever `final < root`.
            let diff = bud_vm::field_sub_goldilocks(final_merkle, root);
            let inv = if diff != 0 {
                bud_vm::field_inverse_goldilocks(diff)
            } else {
                0
            };
            values[row_start + COL_MERKLE_DIFF_INV] = Goldilocks::new(inv);
        } else {
            // Non-Merkle row. Force the merkle columns to zero so
            // Any prover who tries to mark a non-VerifyMerkle row
            // As expansion will be caught by the AIR.
            values[row_start + COL_VM_MERKLE_IS_EXPAND] = Goldilocks::new(0);
        }

        // VerifyInference expansion column population.
        // Map Step's inference_* fields to AIR columns.
        if step.inference_is_expand {
            // Expansion row: carry commitment chain witnesses.
            values[row_start + COL_INFERENCE_IS_EXPAND] = Goldilocks::new(1);
            values[row_start + COL_INFERENCE_MODEL_COMMIT] =
                Goldilocks::new(step.inference_model_commitment.unwrap_or(0));
            values[row_start + COL_INFERENCE_INPUT_COMMIT] =
                Goldilocks::new(step.inference_input_commitment.unwrap_or(0));
            values[row_start + COL_INFERENCE_OUTPUT_COMMIT] =
                Goldilocks::new(step.inference_output_commitment.unwrap_or(0));
        } else if step.inference_model_commitment.is_some() {
            // Original VerifyInference step (not expansion): carry model
            // Commitment but is_expand=0.
            values[row_start + COL_INFERENCE_IS_EXPAND] = Goldilocks::new(0);
            values[row_start + COL_INFERENCE_MODEL_COMMIT] =
                Goldilocks::new(step.inference_model_commitment.unwrap_or(0));
            values[row_start + COL_INFERENCE_INPUT_COMMIT] =
                Goldilocks::new(step.inference_input_commitment.unwrap_or(0));
            values[row_start + COL_INFERENCE_OUTPUT_COMMIT] =
                Goldilocks::new(step.inference_output_commitment.unwrap_or(0));
        } else {
            // Non-inference row: zero out inference columns.
            values[row_start + COL_INFERENCE_IS_EXPAND] = Goldilocks::new(0);
            values[row_start + COL_INFERENCE_MODEL_COMMIT] = Goldilocks::new(0);
            values[row_start + COL_INFERENCE_INPUT_COMMIT] = Goldilocks::new(0);
            values[row_start + COL_INFERENCE_OUTPUT_COMMIT] = Goldilocks::new(0);
        }
    }

    for i in n_cpu..num_rows {
        let row_start = i * TRACE_WIDTH;
        values[row_start + COL_CLK] = Goldilocks::new(i as u64);
        values[row_start + COL_IS_HALT] = Goldilocks::new(1);
        if n_cpu > 0 {
            let last_pc = trace[n_cpu - 1].next_pc as u64;
            values[row_start + COL_PC] = Goldilocks::new(last_pc);
            values[row_start + COL_NEXT_PC] = Goldilocks::new(last_pc);
            values[row_start + COL_STACK_PTR] =
                Goldilocks::new(trace[n_cpu - 1].stack_pointer as u64);
            // Carry event_digest (and other accumulators) into
            // Padding so the active->padding transition does not zero them.
            let last_start = (n_cpu - 1) * TRACE_WIDTH;
            for j in 0..8 {
                values[row_start + COL_EVENT_DIGEST_0 + j] =
                    values[last_start + COL_EVENT_DIGEST_0 + j];
                values[row_start + COL_FINAL_ROOT_0 + j] =
                    values[last_start + COL_FINAL_ROOT_0 + j];
                values[row_start + COL_STATE_WRITES_0 + j] =
                    values[last_start + COL_STATE_WRITES_0 + j];
            }
            values[row_start + COL_EXIT_CODE] = values[last_start + COL_EXIT_CODE];
            values[row_start + COL_TRACE_LEN_CTR] = values[last_start + COL_TRACE_LEN_CTR];
        }
        values[row_start + COL_GAS_USED] = Goldilocks::new(running_gas);
        values[row_start + COL_RAW_INST] = Goldilocks::new(
            bud_isa::Instruction {
                opcode: bud_isa::Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            }
            .encode(),
        );
        values[row_start + COL_CPU_ACTIVE] = Goldilocks::new(0);
    }

    for i in 0..num_rows {
        let row_start = i * TRACE_WIDTH;
        let delta = values[row_start + COL_IMM] + Goldilocks::ONE;
        values[row_start + COL_STORAGE_SLOT_INV] = if delta == Goldilocks::ZERO {
            Goldilocks::ZERO
        } else {
            Goldilocks::new(bud_vm::field_inverse_goldilocks(delta.as_canonical_u64()))
        };
    }

    for (i, e) in events.iter().enumerate() {
        let row_start = i * TRACE_WIDTH;
        values[row_start + COL_REG_CLK] = Goldilocks::new(e.clk);
        values[row_start + COL_REG_IDX] = Goldilocks::new(e.idx);
        values[row_start + COL_REG_VAL] = Goldilocks::new(e.val);
        values[row_start + COL_REG_SUB_CLK] = Goldilocks::new(e.sub_clk as u64);
        values[row_start + COL_REG_IS_WRITE] = if e.is_write {
            Goldilocks::new(1)
        } else {
            Goldilocks::new(0)
        };
        values[row_start + COL_REG_ACTIVE] = Goldilocks::new(1);
        values[row_start + COL_REG_IS_INIT] = Goldilocks::new(u64::from(e.is_init));

        if i < n_reg - 1 && events[i + 1].idx == e.idx {
            values[row_start + COL_REG_SAME] = Goldilocks::new(1);
        }

        // Inverse witness pinning COL_REG_SAME to the equality it claims.
        // Only meaningful while both this row and the next carry a register
        // event, which is exactly where the AIR checks it; past the last event
        // the next row is inactive and the constraint is gated off.
        if i < n_reg - 1 {
            let diff = events[i + 1].idx.wrapping_sub(e.idx);
            let inv = if diff != 0 {
                bud_vm::field_inverse_goldilocks(diff)
            } else {
                0
            };
            values[row_start + COL_REG_SAME_INV] = Goldilocks::new(inv);

            // The step to the next row, in bits. The events are sorted by
            // `(idx, clk, sub_clk)` and no two are equal, so the step is
            // never negative.
            let next = &events[i + 1];
            let step = if next.idx == e.idx {
                (next.clk * 4 + next.sub_clk as u64) - (e.clk * 4 + e.sub_clk as u64) - 1
            } else {
                next.idx - e.idx - 1
            };
            debug_assert!(step < (1u64 << REG_ORD_BITS));
            for b in 0..REG_ORD_BITS {
                values[row_start + COL_REG_ORD_BITS_BASE + b] = Goldilocks::new((step >> b) & 1);
            }
        }
    }

    // Padding rows (all zeros) still satisfy `(0xFFFF_FFFF - a_hi) * inv`
    // because `is_hi_max * a_lo == 1 * 0 == 0` ONLY if `hi_gap == 0`; when
    // `a_hi == 0`, `hi_gap = 0xFFFF_FFFF != 0`, so every row needs `COL_MEM_HI_MAX_INV`!
    let default_hi_max_inv = Goldilocks::new(bud_vm::field_inverse_goldilocks(0xFFFF_FFFF));
    for r in 0..num_rows {
        values[r * TRACE_WIDTH + COL_MEM_HI_MAX_INV] = default_hi_max_inv;
    }

    for (i, e) in mem_events.iter().enumerate() {
        let row_start = i * TRACE_WIDTH;
        let canon_addr = Goldilocks::new(e.addr).as_canonical_u64();
        let addr_lo = canon_addr & 0xFFFF_FFFF;
        let addr_hi = canon_addr >> 32;
        values[row_start + COL_MEM_CLK] = Goldilocks::new(e.clk);
        values[row_start + COL_MEM_TID] = Goldilocks::new(e.tid);
        values[row_start + COL_MEM_ADDR] = Goldilocks::new(canon_addr);
        for b in 0..MEM_ADDR_BITS {
            values[row_start + COL_MEM_ADDR_BITS_BASE + b] = Goldilocks::new((canon_addr >> b) & 1);
        }
        let hi_gap = 0xFFFF_FFFFu64 - addr_hi;
        values[row_start + COL_MEM_HI_MAX_INV] = Goldilocks::new(if hi_gap != 0 {
            bud_vm::field_inverse_goldilocks(hi_gap)
        } else {
            0
        });
        values[row_start + COL_MEM_VAL] = Goldilocks::new(e.val);
        values[row_start + COL_MEM_IS_WRITE] = if e.is_write {
            Goldilocks::new(1)
        } else {
            Goldilocks::new(0)
        };
        values[row_start + COL_MEM_ACTIVE] = Goldilocks::new(1);
        values[row_start + COL_MEM_IS_INIT] = Goldilocks::new(u64::from(e.is_init));

        if i < n_mem - 1 {
            let next = &mem_events[i + 1];
            let next_canon = Goldilocks::new(next.addr).as_canonical_u64();
            let next_lo = next_canon & 0xFFFF_FFFF;
            let next_hi = next_canon >> 32;
            let top = (e.tid << 32) | addr_hi;
            let next_top = (next.tid << 32) | next_hi;

            let top_diff = (Goldilocks::new(next_top) - Goldilocks::new(top)).as_canonical_u64();
            values[row_start + COL_MEM_TOP_SAME] = Goldilocks::new(u64::from(top_diff == 0));
            values[row_start + COL_MEM_TOP_SAME_INV] = Goldilocks::new(if top_diff != 0 {
                bud_vm::field_inverse_goldilocks(top_diff)
            } else {
                0
            });

            let lo_diff = (Goldilocks::new(next_lo) - Goldilocks::new(addr_lo)).as_canonical_u64();
            values[row_start + COL_MEM_SAME_INV] = Goldilocks::new(if lo_diff != 0 {
                bud_vm::field_inverse_goldilocks(lo_diff)
            } else {
                0
            });
            let same_cell = top_diff == 0 && lo_diff == 0;
            values[row_start + COL_MEM_SAME] = Goldilocks::new(u64::from(same_cell));

            // The step to the next row, in bits, sorted strictly by `(top, lo, clk)`.
            let step = if same_cell {
                next.clk.wrapping_sub(e.clk).wrapping_sub(1)
            } else if top_diff == 0 {
                next_lo.wrapping_sub(addr_lo).wrapping_sub(1)
            } else {
                next_top.wrapping_sub(top).wrapping_sub(1)
            };
            for b in 0..MEM_ORD_BITS {
                values[row_start + COL_MEM_ORD_BITS_BASE + b] = Goldilocks::new((step >> b) & 1);
            }
        }
    }

    // Fold the initial-image rows, then hold the final value on every
    // remaining row so the last real row carries the whole commitment.
    {
        let beta = Goldilocks::new(MEM_INIT_BETA);
        let gamma = Goldilocks::new(MEM_INIT_GAMMA);
        let mut acc = Goldilocks::ZERO;
        for (i, e) in mem_events.iter().enumerate() {
            if e.is_init {
                let term = Goldilocks::new(mem_key(e.tid, e.addr)) * gamma + Goldilocks::new(e.val);
                acc = if i == 0 { term } else { acc * beta + term };
            }
            values[i * TRACE_WIDTH + COL_MEM_INIT_ACC] = acc;
        }
        for r in mem_events.len()..num_rows {
            values[r * TRACE_WIDTH + COL_MEM_INIT_ACC] = acc;
        }
    }

    // Same fold for the starting register file, into its own accumulator with
    // its own constants.
    {
        let beta = Goldilocks::new(REG_INIT_BETA);
        let gamma = Goldilocks::new(REG_INIT_GAMMA);
        let mut acc = Goldilocks::ZERO;
        for (i, e) in events.iter().enumerate() {
            if e.is_init {
                let term = Goldilocks::new(e.idx) * gamma + Goldilocks::new(e.val);
                acc = if i == 0 { term } else { acc * beta + term };
            }
            values[i * TRACE_WIDTH + COL_REG_INIT_ACC] = acc;
        }
        for r in events.len()..num_rows {
            values[r * TRACE_WIDTH + COL_REG_INIT_ACC] = acc;
        }
    }

    // HIGH CWE-345: state-write accumulator carry across ALL rows
    // (real + padding), applied AFTER the per-step loop. For every row whose
    // PREVIOUS row is not an SWrite, the accumulator copies forward; an
    // SWrite row already wrote its next value into the following row inside
    // the loop, so it is left untouched. This keeps the AIR's non-SWrite
    // carry constraint satisfied on every consecutive row pair.
    for i in 1..num_rows {
        let prev = (i - 1) * TRACE_WIDTH;
        let rs = i * TRACE_WIDTH;
        if values[prev + COL_IS_SWRITE].as_canonical_u64() != 1 {
            for j in 0..8 {
                values[rs + COL_STATE_WRITES_0 + j] = values[prev + COL_STATE_WRITES_0 + j];
            }
        }
    }

    (RowMajorMatrix::new(values, TRACE_WIDTH), n_cpu)
}

fn register_term(
    alpha: MyExtensionField,
    beta: MyExtensionField,
    table_id: Goldilocks,
    clk: Goldilocks,
    idx: Goldilocks,
    val: Goldilocks,
    is_write: Goldilocks,
) -> MyExtensionField {
    let b2 = beta * beta;
    let b3 = b2 * beta;
    let b4 = b3 * beta;
    let b5 = b4 * beta;
    alpha
        + beta * MyExtensionField::from(table_id)
        + b2 * MyExtensionField::from(clk)
        + b3 * MyExtensionField::from(idx)
        + b4 * MyExtensionField::from(val)
        + b5 * MyExtensionField::from(is_write)
}

#[allow(clippy::type_complexity)]
fn aux_trace_generator(
    main_trace: RowMajorMatrix<Goldilocks>,
    trace_len: usize,
    program: Vec<u64>,
) -> Box<dyn FnOnce(&[MyExtensionField]) -> RowMajorMatrix<Goldilocks>> {
    Box::new(move |random_challenges| {
        let num_rows = main_trace.height();
        let mut aux_values = vec![MyExtensionField::ZERO; num_rows * 3]; // Reg, Mem, Prog
        let alpha = random_challenges[0];
        let beta = random_challenges[1];
        let gamma = random_challenges[2];

        let b2 = beta * beta;
        let b3 = b2 * beta;
        let b4 = b3 * beta;
        let b5 = b4 * beta;
        let b6 = b5 * beta;
        let b7 = b6 * beta;

        let mut s_reg = MyExtensionField::ZERO;
        let mut s_mem = MyExtensionField::ZERO;
        let mut s_prog = MyExtensionField::ZERO;

        aux_values[0] = s_reg;
        aux_values[1] = s_mem;
        aux_values[2] = s_prog;

        for i in 0..num_rows - 1 {
            let row_start = i * TRACE_WIDTH;
            let row = &main_trace.values[row_start..row_start + TRACE_WIDTH];

            // Register LogUp
            let is_add = row[COL_IS_ADD];
            let is_sub = row[COL_IS_SUB];
            let is_mul = row[COL_IS_MUL];
            let is_div = row[COL_IS_DIV];
            let is_inv = row[COL_IS_INV];
            let is_and = row[COL_IS_AND];
            let is_not = row[COL_IS_NOT];
            let is_eq = row[COL_IS_EQ];
            let is_neq = row[COL_IS_NEQ];
            let is_lt = row[COL_IS_LT];
            let is_gt = row[COL_IS_GT];
            let is_lte = row[COL_IS_LTE];
            let is_gte = row[COL_IS_GTE];
            let is_jmp = row[COL_IS_JMP];
            let is_jnz = row[COL_IS_JNZ];
            let is_call = row[COL_IS_CALL];
            let is_ret = row[COL_IS_RET];
            let is_load = row[COL_IS_LOAD];
            let is_store = row[COL_IS_STORE];
            let is_push = row[COL_IS_PUSH];
            let is_pop = row[COL_IS_POP];
            let is_assert = row[COL_IS_ASSERT];
            let is_log = row[COL_IS_LOG];
            let is_sread = row[COL_IS_SREAD];
            let is_swrite = row[COL_IS_SWRITE];
            let is_poseidon = row[COL_IS_POSEIDON];
            let is_syscall = row[COL_IS_SYSCALL];
            let is_verify_merkle = row[COL_IS_VERIFY_MERKLE];
            let is_privacy_commit = row[COL_IS_PRIVACY_COMMIT];
            let is_nullifier_check = row[COL_IS_NULLIFIER_CHECK];
            let is_sum_conservation = row[COL_IS_SUM_CONSERVATION];
            let is_verify_inference = row[COL_IS_VERIFY_INFERENCE];

            // Expansion rows keep is_verify_merkle=1 but must not
            // Contribute to the register bus (operands are zeroed synthetics).
            let is_expand_aux = row[COL_VM_MERKLE_IS_EXPAND];
            let is_real_op = is_add
                + is_sub
                + is_mul
                + is_div
                + is_inv
                + is_and
                + is_not
                + is_eq
                + is_neq
                + is_lt
                + is_gt
                + is_lte
                + is_gte
                + is_jmp
                + is_jnz
                + is_call
                + is_ret
                + is_load
                + is_store
                + is_push
                + is_pop
                + is_assert
                + is_log
                + is_sread
                + is_swrite
                + is_poseidon
                + is_syscall
                + is_privacy_commit
                + is_nullifier_check
                + is_sum_conservation
                + is_verify_merkle * (Goldilocks::ONE - is_expand_aux)
                + is_verify_inference * (Goldilocks::ONE - row[COL_INFERENCE_IS_EXPAND]);

            let clk = row[COL_CLK];
            let pc = row[COL_PC];
            let rs1_idx = row[COL_RS1_IDX];
            let rs2_idx = row[COL_RS2_IDX];
            let rd_idx = row[COL_RD_IDX];
            let rs1_val = row[COL_RS1_VAL];
            let rs2_val = row[COL_RS2_VAL];
            let rd_val_new = row[COL_RD_VAL_NEW];

            let reg_active = row[COL_REG_ACTIVE];
            let reg_clk = row[COL_REG_CLK];
            let reg_sub_clk = row[COL_REG_SUB_CLK];
            let reg_idx = row[COL_REG_IDX];
            let reg_val = row[COL_REG_VAL];
            let reg_is_write = row[COL_REG_IS_WRITE];

            let clk_rs1 = clk * Goldilocks::from_u64(4) + Goldilocks::from_u64(1);
            let clk_rs2 = clk * Goldilocks::from_u64(4) + Goldilocks::from_u64(2);
            let clk_rd = clk * Goldilocks::from_u64(4) + Goldilocks::from_u64(3);
            let clk_reg = reg_clk * Goldilocks::from_u64(4) + reg_sub_clk;

            let c_rs1 = register_term(
                alpha,
                beta,
                Goldilocks::ZERO,
                clk_rs1,
                rs1_idx,
                rs1_val,
                Goldilocks::ZERO,
            );
            let c_rs2 = register_term(
                alpha,
                beta,
                Goldilocks::ZERO,
                clk_rs2,
                rs2_idx,
                rs2_val,
                Goldilocks::ZERO,
            );
            // A row targeting r0 publishes zero on the register bus whatever
            // it computed, matching `rd_written` in the AIR. Building the
            // honest side any other way leaves the argument unbalanced on
            // every program that writes to r0.
            let rd_idx_z = rd_idx * row[COL_RD_IDX_INV];
            let writes_rd = is_add
                + is_sub
                + is_mul
                + is_div
                + is_inv
                + is_and
                + is_not
                + is_load
                + is_pop
                + is_eq
                + is_neq
                + is_lt
                + is_gt
                + is_lte
                + is_gte
                + is_sread
                + is_poseidon
                + is_syscall
                + is_verify_merkle
                + is_privacy_commit
                + is_nullifier_check
                + is_sum_conservation
                + is_verify_inference;
            let c_rd = register_term(
                alpha,
                beta,
                Goldilocks::ZERO,
                clk_rd,
                rd_idx,
                rd_val_new * rd_idx_z,
                writes_rd,
            );
            let c_reg = register_term(
                alpha,
                beta,
                Goldilocks::ZERO,
                clk_reg,
                reg_idx,
                reg_val,
                reg_is_write,
            );

            if is_real_op != Goldilocks::ZERO {
                s_reg += (gamma - c_rs1).inverse()
                    + (gamma - c_rs2).inverse()
                    + (gamma - c_rd).inverse();
            }
            if reg_active != Goldilocks::ZERO {
                s_reg -= (gamma - c_reg).inverse();
            }

            // Memory LogUp (includes SRead/SWrite as table id 3)
            let m_active = row[COL_MEM_ACTIVE];
            let m_tid = row[COL_MEM_TID];
            let m_clk = row[COL_MEM_CLK];
            let m_addr = row[COL_MEM_ADDR];
            let m_val = row[COL_MEM_VAL];
            let m_is_write = row[COL_MEM_IS_WRITE];

            // Built from the same witness the AIR reads, not from a Rust
            // comparison that happens to agree with it. The two spellings
            // disagreed for every base register except r1, because the AIR
            // multiplied by `rs1_idx` itself while this side produced a
            // boolean.
            let rs1_idx_z = rs1_idx * row[COL_RS1_IDX_INV];
            let is_real_mem_op = is_load * rs1_idx_z + is_store;
            let is_stack_op = is_push + is_pop + is_call + is_ret;
            let is_storage_op = is_sread + is_swrite;
            // Merkle path reads join the demand side: an expansion row reads
            // one sibling, the original step reads the key. The memory table
            // already supplies those rows, and a supply without a matching
            // demand unbalances the LogUp.
            let is_verify_merkle_row = row[COL_IS_VERIFY_MERKLE];
            let is_merkle_expand_mem = row[COL_VM_MERKLE_IS_EXPAND];
            let is_merkle_key_read =
                is_verify_merkle_row * (Goldilocks::ONE - is_merkle_expand_mem);
            let is_merkle_mem_op = is_merkle_expand_mem + is_merkle_key_read;
            let is_any_mem_op = is_real_mem_op + is_stack_op + is_storage_op + is_merkle_mem_op;

            let stack_ptr = row[COL_STACK_PTR];
            let stack_addr =
                (is_push + is_call) * stack_ptr + (is_pop + is_ret) * (stack_ptr - Goldilocks::ONE);
            let slot_delta = row[COL_IMM] + Goldilocks::ONE;
            let slot_delta_z = slot_delta * row[COL_STORAGE_SLOT_INV];
            let is_dynamic_slot = Goldilocks::ONE - slot_delta_z;
            let storage_addr = is_dynamic_slot * row[COL_RS2_VAL]
                + (Goldilocks::ONE - is_dynamic_slot) * row[COL_IMM];
            let cpu_mem_tid = is_real_mem_op
                + is_merkle_mem_op
                + Goldilocks::from_u64(TID_STACK) * is_stack_op
                + Goldilocks::from_u64(TID_STORAGE) * is_storage_op;

            let merkle_path_addr = row[COL_IMM];
            let eight = Goldilocks::from_u64(8);
            let merkle_sibling_addr = merkle_path_addr + eight + eight * row[COL_VM_MERKLE_ROUND];
            let final_mem_addr = is_real_mem_op * (row[COL_RS1_VAL] + row[COL_IMM])
                + is_stack_op * stack_addr
                + is_storage_op * storage_addr
                + is_merkle_expand_mem * merkle_sibling_addr
                + is_merkle_key_read * merkle_path_addr;

            let is_write = is_store + is_push + is_call + is_swrite;
            let cpu_mem_val = is_load * row[COL_RD_VAL_NEW]
                + is_store * row[COL_RS2_VAL]
                + is_push * row[COL_RS1_VAL]
                + is_pop * row[COL_RD_VAL_NEW]
                + is_call * (row[COL_PC] + Goldilocks::ONE)
                + is_ret * row[COL_NEXT_PC]
                + is_sread * row[COL_RD_VAL_NEW]
                + is_swrite * row[COL_RS1_VAL]
                + is_merkle_expand_mem * row[COL_VM_MERKLE_SIBLING]
                + is_merkle_key_read * row[COL_VM_MERKLE_KEY];

            let c_cpu_mem = register_term(
                alpha,
                beta,
                cpu_mem_tid,
                clk,
                final_mem_addr,
                cpu_mem_val,
                is_write,
            );
            let c_mem = register_term(alpha, beta, m_tid, m_clk, m_addr, m_val, m_is_write);

            if is_any_mem_op != Goldilocks::ZERO {
                s_mem += (gamma - c_cpu_mem).inverse();
            }
            if m_active != Goldilocks::ZERO {
                s_mem -= (gamma - c_mem).inverse();
            }

            // Program LogUp. The tuple is (pc, raw_inst, opcode, rd, rs1, rs2):
            // the whole decode. Those four terms are what bind the CPU trace's
            // decode columns to the committed program, so the prover side has
            // to build the same six term sum the AIR checks.
            let raw_inst = row[COL_RAW_INST];
            let opcode_col = row[COL_OPCODE];
            let rd_col = row[COL_RD_IDX];
            let rs1_col = row[COL_RS1_IDX];
            let rs2_col = row[COL_RS2_IDX];
            let imm_col = row[COL_IMM];
            let term_cpu_prog = alpha
                + beta * MyExtensionField::from(pc)
                + b2 * MyExtensionField::from(raw_inst)
                + b3 * MyExtensionField::from(opcode_col)
                + b4 * MyExtensionField::from(rd_col)
                + b5 * MyExtensionField::from(rs1_col)
                + b6 * MyExtensionField::from(rs2_col)
                + b7 * MyExtensionField::from(imm_col);

            let pre_pc = Goldilocks::from_u64(i as u64);
            let pre_inst_word = program.get(i).copied().unwrap_or(0);
            let pre_inst = Goldilocks::from_u64(pre_inst_word);
            let pre_opcode = Goldilocks::from_u64(pre_inst_word & 0xFF);
            let pre_rd = Goldilocks::from_u64((pre_inst_word >> 8) & 0x1F);
            let pre_rs1 = Goldilocks::from_u64((pre_inst_word >> 13) & 0x1F);
            let pre_rs2 = Goldilocks::from_u64((pre_inst_word >> 18) & 0x1F);
            // Same decoder the AIR's preprocessed trace uses, so the signed
            // immediate wraps the same way on both sides.
            let pre_imm_signed = bud_isa::Instruction::decode_any(pre_inst_word)
                .map(|d| d.imm)
                .unwrap_or(0);
            let pre_imm = if pre_imm_signed < 0 {
                Goldilocks::ZERO - Goldilocks::from_u64((-(pre_imm_signed as i64)) as u64)
            } else {
                Goldilocks::from_u64(pre_imm_signed as u64)
            };
            let term_pre_prog = alpha
                + beta * MyExtensionField::from(pre_pc)
                + b2 * MyExtensionField::from(pre_inst)
                + b3 * MyExtensionField::from(pre_opcode)
                + b4 * MyExtensionField::from(pre_rd)
                + b5 * MyExtensionField::from(pre_rs1)
                + b6 * MyExtensionField::from(pre_rs2)
                + b7 * MyExtensionField::from(pre_imm);

            let diff_cpu_prog = gamma - term_cpu_prog;
            let diff_pre_prog = gamma - term_pre_prog;

            // Expansion rows reuse opcode 0x1E at the same PC
            // But are NOT program fetches - counting them unbalances LogUp
            // (trace_len >> program.len for VerifyMerkle paths).
            // (2026-08-28) Same for VerifyInference expansion rows: without
            // COL_INFERENCE_IS_EXPAND here, 8 phantom demands per step were
            // added to the program LogUp partial sum while the AIR excluded
            // them, and every clean VerifyInference proof failed at OOD.
            let is_expand_row = row[COL_VM_MERKLE_IS_EXPAND] + row[COL_INFERENCE_IS_EXPAND];
            if i < trace_len && is_expand_row == Goldilocks::ZERO {
                s_prog += diff_cpu_prog.inverse();
            }
            // The ROM-side weight is the multiplicity column, not a constant
            // 1. In a branching program a pc is either never executed (a
            // skipped branch) or executed several times (a loop body); a
            // constant 1 unbalances both cases and an honest prover gets
            // `InvalidProof`.
            if i < program.len() {
                let mult = row[COL_PROG_MULT];
                if mult != Goldilocks::ZERO {
                    s_prog -= diff_pre_prog.inverse() * MyExtensionField::from(mult);
                }
            }

            aux_values[(i + 1) * 3] = s_reg;
            aux_values[(i + 1) * 3 + 1] = s_mem;
            aux_values[(i + 1) * 3 + 2] = s_prog;
        }

        RowMajorMatrix::new(aux_values, 3).flatten_to_base()
    })
}

#[doc(hidden)]
pub fn to_public_values(pi: &ExecutionPublicInputs) -> Vec<Goldilocks> {
    let mut vals = Vec::new();

    vals.push(Goldilocks::from_u64(pi.chain_id & 0xFFFF_FFFF));
    vals.push(Goldilocks::from_u64(pi.chain_id >> 32));

    for chunk in pi.program_hash.chunks_exact(4) {
        let val = u32::from_le_bytes(chunk.try_into().unwrap_or([0u8; 4]));
        vals.push(Goldilocks::from_u64(val as u64));
    }

    for chunk in pi.initial_state_root.chunks_exact(4) {
        let val = u32::from_le_bytes(chunk.try_into().unwrap_or([0u8; 4]));
        vals.push(Goldilocks::from_u64(val as u64));
    }

    for chunk in pi.final_state_root.chunks_exact(4) {
        let val = u32::from_le_bytes(chunk.try_into().unwrap_or([0u8; 4]));
        vals.push(Goldilocks::from_u64(val as u64));
    }

    vals.push(Goldilocks::from_u64(pi.sender & 0xFFFF_FFFF));
    vals.push(Goldilocks::from_u64(pi.sender >> 32));

    vals.push(Goldilocks::from_u64(pi.nonce & 0xFFFF_FFFF));
    vals.push(Goldilocks::from_u64(pi.nonce >> 32));

    vals.push(Goldilocks::from_u64(pi.block_height & 0xFFFF_FFFF));
    vals.push(Goldilocks::from_u64(pi.block_height >> 32));

    vals.push(Goldilocks::from_u64(pi.gas_limit & 0xFFFF_FFFF));
    vals.push(Goldilocks::from_u64(pi.gas_limit >> 32));

    vals.push(Goldilocks::from_u64(pi.gas_used & 0xFFFF_FFFF));
    vals.push(Goldilocks::from_u64(pi.gas_used >> 32));

    vals.push(Goldilocks::from_u64(pi.exit_code & 0xFFFF_FFFF));
    vals.push(Goldilocks::from_u64(pi.exit_code >> 32));

    vals.push(Goldilocks::from_u64(pi.trace_len & 0xFFFF_FFFF));
    vals.push(Goldilocks::from_u64(pi.trace_len >> 32));

    // Limb 0 is a full Goldilocks element, not a u32.
    //
    // The AIR compares `COL_EVENT_DIGEST_0` against `public_inputs[40]`, and
    // that column accumulates each `Log` row's whole `rs1`. Reading limb 0 as
    // four bytes truncated it, so the comparison held only while every logged
    // value stayed below 2^32 - which every test did, and which a Poseidon
    // output never does.
    // `chunks_exact(4)` and this fixed window always yield the right width;
    // written without a fallible conversion so no panic remains.
    let mut event_head = [0u8; 8];
    event_head.copy_from_slice(&pi.event_digest[0..8]);
    vals.push(Goldilocks::from_u64(u64::from_le_bytes(event_head)));
    // Limbs 1..8 are reserved; they are packed as u32 and asserted zero.
    for chunk in pi.event_digest[8..32].chunks_exact(4) {
        let val = u32::from_le_bytes(chunk.try_into().unwrap_or([0u8; 4]));
        vals.push(Goldilocks::from_u64(val as u64));
    }
    // One more slot so event_digest stays at 8 public values ([40..48]).
    vals.push(Goldilocks::from_u64(0));
    // state_writes_digest: 8 u32 limbs -> public_inputs[48..56] (HIGH,
    // CWE-345, 2026-08-17).
    for chunk in pi.state_writes_digest.chunks_exact(4) {
        let val = u32::from_le_bytes(chunk.try_into().unwrap_or([0u8; 4]));
        vals.push(Goldilocks::from_u64(val as u64));
    }

    vals
}

impl ProverAdapter for Plonky3Adapter {
    fn prove(
        trace: &[Step],
        public_inputs: &ExecutionPublicInputs,
        program: &[u64],
    ) -> Result<ProofEnvelope, ProverError> {
        info!(trace_len = trace.len(), "Building trace matrix");
        let (matrix, trace_len) = trace_matrix(trace, program, public_inputs);
        let config = build_config();

        let air = BudAir {
            num_steps: trace.len(),
            program: program.to_vec(),
        };

        let degree_bits = log2_strict_usize(matrix.height());
        debug!(
            degree_bits,
            height = matrix.height(),
            "Commencing STARK prove"
        );
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let public_values = to_public_values(public_inputs);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(aux_trace_generator(
                matrix.clone(),
                trace_len,
                program.to_vec(),
            )),
            &public_values,
            preprocessed_ref,
        );

        let proof_bytes = postcard::to_allocvec(&p3_proof)
            .map_err(|e| ProverError::SerializationError(e.to_string()))?;

        Ok(ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: public_inputs.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        })
    }

    /// Verify under the default activation state, in which the staged
    /// opcodes (`VerifyMerkle`, `VerifyInference`) are off. A program that
    /// uses one is refused; see [`Plonky3Adapter::verify_with_activation`].
    fn verify(
        envelope: &ProofEnvelope,
        expected_inputs: &ExecutionPublicInputs,
        program: &[u64],
    ) -> Result<(), VerifyError> {
        Self::verify_with_activation(
            envelope,
            expected_inputs,
            program,
            bud_isa::MainnetActivation::default(),
        )
    }
}

/// True when every 64 bit scalar public input is below the Goldilocks
/// modulus, so it is the canonical representative of its field element.
fn has_canonical_scalars(pi: &ExecutionPublicInputs) -> bool {
    [
        pi.chain_id,
        pi.sender,
        pi.nonce,
        pi.block_height,
        pi.gas_limit,
        pi.gas_used,
        pi.exit_code,
        pi.trace_len,
    ]
    .iter()
    .all(|&v| v < bud_vm::GOLDILOCKS_P)
}

impl Plonky3Adapter {
    /// Verify a proof exactly as [`ProverAdapter::verify`] does, but under an
    /// explicit activation state.
    ///
    /// [`ProverAdapter::verify`] uses [`bud_isa::MainnetActivation::default`],
    /// in which `VerifyMerkle` and `VerifyInference` are off: a proof whose
    /// program contains either is refused with
    /// `VerifyError::InvalidEnvelope` before the STARK is looked at. A network
    /// that has activated them passes its own state here.
    pub fn verify_with_activation(
        envelope: &ProofEnvelope,
        expected_inputs: &ExecutionPublicInputs,
        program: &[u64],
        activation: bud_isa::MainnetActivation,
    ) -> Result<(), VerifyError> {
        debug!(
            version = envelope.proof_format_version,
            proof_len = envelope.proof_bytes.len(),
            "Verifying proof"
        );
        // Shape bounds first: nothing below may allocate or compute off an
        // unbounded field. A trace_len above the cap would overflow the
        // `3 * trace_len + 1` degree derivation; a program above the cap
        // cannot be a canonical program and is refused before it is hashed.
        envelope.validate_shape()?;
        expected_inputs.validate_shape()?;
        // Each 64 bit public field enters the AIR as `lo + hi * 2^32`, a
        // Goldilocks element. A value at or above the modulus has the same
        // element as `value - p`, so one proof would verify for two inputs.
        if !has_canonical_scalars(expected_inputs) {
            return Err(VerifyError::PublicInputsMismatch);
        }
        if program.len() > crate::adapter::MAX_TRACE_LEN {
            return Err(VerifyError::InvalidEnvelope(format!(
                "program length {} exceeds the {} cap",
                program.len(),
                crate::adapter::MAX_TRACE_LEN
            )));
        }
        if envelope.proof_format_version != PROOF_FORMAT_VERSION {
            return Err(VerifyError::InvalidEnvelope(
                "Unsupported proof format version".to_string(),
            ));
        }
        if envelope.backend != "Plonky3-Keccak-Goldilocks" {
            return Err(VerifyError::InvalidEnvelope(
                "Unsupported backend".to_string(),
            ));
        }
        if envelope.p3_version != "0.5.2" {
            return Err(VerifyError::InvalidEnvelope(
                "Unsupported Plonky3 version".to_string(),
            ));
        }
        if envelope.fri_params_id != "test_fri_params" {
            return Err(VerifyError::InvalidEnvelope(
                "Unsupported FRI parameters".to_string(),
            ));
        }
        if envelope.public_inputs_hash != expected_inputs.hash() {
            return Err(VerifyError::PublicInputsMismatch);
        }

        // Program hash verification
        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut computed_prog_hash = [0u8; 32];
        hasher.finalize(&mut computed_prog_hash);

        if computed_prog_hash != expected_inputs.program_hash {
            return Err(VerifyError::PublicInputsMismatch);
        }

        // The AIR proves that a program ran; it does not decide whether the
        // chain allows the program to run. An opcode that is not activated
        // is refused here, on the program the proof is bound to, so that a
        // staged opcode cannot enter through a proof even though the
        // execution path would have refused to run it. Words that do not
        // decode are left to the AIR, which has no row for them.
        for word in program {
            if let Ok(instruction) = bud_isa::Instruction::decode_any(*word) {
                if !activation.allows(instruction.opcode) {
                    return Err(VerifyError::InvalidEnvelope(format!(
                        "opcode {:?} is not activated",
                        instruction.opcode
                    )));
                }
            }
        }

        let config = build_config();
        let air = BudAir {
            num_steps: expected_inputs.trace_len as usize,
            program: program.to_vec(),
        };

        let degree_bits = log2_strict_usize(
            (3 * expected_inputs.trace_len as usize + 1)
                .next_power_of_two()
                .max(16),
        );
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_vk_ref = preprocessed.as_ref().map(|(_, vk)| vk);

        let public_values = to_public_values(expected_inputs);

        let bounded_bytes = &envelope.proof_bytes[..envelope
            .proof_bytes
            .len()
            .min(crate::adapter::MAX_ENVELOPE_PROOF_BYTES)];
        // One proof must have one encoding: trailing bytes after the proof
        // would give a single valid proof many distinct byte strings, and
        // the relay fingerprint hashes and signs those bytes.
        let (p3_proof, trailing): (crate::bud_stark::Proof<MyConfig>, &[u8]) =
            postcard::take_from_bytes(bounded_bytes)
                .map_err(|e| VerifyError::DeserializationError(e.to_string()))?;
        if !trailing.is_empty() {
            return Err(VerifyError::DeserializationError(format!(
                "{} trailing bytes after the proof",
                trailing.len()
            )));
        }

        stark_verify_with_preprocessed(
            &config,
            &air,
            &p3_proof,
            &public_values,
            preprocessed_vk_ref,
        )
        .map_err(|_| VerifyError::InvalidProof)
    }
}

impl Plonky3Adapter {
    /// Verify a proof exactly as [`ProverAdapter::verify`] does, and
    /// additionally require the proven program to be part of the canonical
    /// set ([`crate::canonical_set`]).
    ///
    /// This is the ZKVM-side alarm of the regeneration gate: a proof for a
    /// program outside the canonical set is refused with
    /// `VerifyError::NonCanonicalProgram`, which is a different, explicit
    /// failure than a bogus proof.
    pub fn verify_canonical_program(
        envelope: &ProofEnvelope,
        expected_inputs: &ExecutionPublicInputs,
        program: &[u64],
    ) -> Result<(), VerifyError> {
        Self::verify_canonical_program_with_activation(
            envelope,
            expected_inputs,
            program,
            bud_isa::MainnetActivation::default(),
        )
    }

    /// [`Plonky3Adapter::verify_canonical_program`] under an explicit
    /// activation state. The canonical set holds a program that uses
    /// `VerifyMerkle` (the storage challenge), so a verifier that has not
    /// activated that opcode refuses it here rather than accepting it by way
    /// of the canonical set.
    pub fn verify_canonical_program_with_activation(
        envelope: &ProofEnvelope,
        expected_inputs: &ExecutionPublicInputs,
        program: &[u64],
        activation: bud_isa::MainnetActivation,
    ) -> Result<(), VerifyError> {
        Self::verify_with_activation(envelope, expected_inputs, program, activation)?;
        if !crate::canonical_set::is_canonical_program_hash(&expected_inputs.program_hash) {
            return Err(VerifyError::NonCanonicalProgram(
                expected_inputs.program_hash,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bud_isa::{Instruction, Opcode};
    use bud_vm::Vm;
    use p3_field::PrimeField64;

    /// A mutation that corrupts a single field of a proof.
    ///
    /// Written directly, `Vec<(&str, Box<dyn Fn(&mut Proof<MyConfig>)>)>`
    /// triggers clippy's `type_complexity` - rightly, because the reader has
    /// to unpack the type first and only then work out what it does.
    type ProofMutation = Box<dyn Fn(&mut crate::bud_stark::Proof<MyConfig>)>;

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

    fn prove_and_verify(program: Vec<u64>, setup: impl FnOnce(&mut Vm)) -> ProofEnvelope {
        prove_and_verify_full(program, setup).0
    }

    /// Prove a program, verify it, and return the envelope together with the
    /// public inputs - for tests that must tamper with the envelope after a
    /// successful round-trip.
    fn prove_and_verify_full(
        program: Vec<u64>,
        setup: impl FnOnce(&mut Vm),
    ) -> (ProofEnvelope, ExecutionPublicInputs) {
        let mut vm = Vm::new(64);
        setup(&mut vm);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        // Callers of this helper often seed registers with
        // `vm.registers[n] = x` before running, so the trace reads values
        // nothing in it wrote. Those reads are the starting register file and
        // the AIR now requires the public inputs to commit to them, so the
        // root is computed from the trace rather than assumed to be zero. A
        // program that seeds nothing folds to zero and lands on the same
        // all-zero root as before.
        let initial_root = crate::adapter::initial_state_root_of(
            crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
            crate::adapter::register_image_commitment_of_reads(&initial_register_reads(&vm.trace)),
        );
        // The AIR ties the final root to the storage-writes fold (2a), so
        // the honest final root is the receipt's write digest - the same
        // convention the chain enforces. A program that writes nothing
        // folds to zero and lands on the same all-zero root as before.
        let final_root = receipt.state_writes_digest;

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: initial_root,
            final_state_root: final_root,
            sender: vm.context.sender,
            nonce: vm.context.nonce,
            block_height: vm.context.block_height,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: receipt.state_writes_digest,
        };

        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        let verify_res = Plonky3Adapter::verify(&envelope, &pi, &program);
        if let Err(ref e) = verify_res {
            eprintln!("Verification error: {:?}", e);
        }
        assert!(verify_res.is_ok());
        (envelope, pi)
    }

    /// The proof format version is a hard gate: bytes from an older format
    /// are not migrated and bytes claiming a future format are not
    /// understood. Both must be rejected before anything else is inspected.
    #[test]
    fn verifier_rejects_old_and_future_proof_format_versions() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let (mut envelope, pi) = prove_and_verify_full(program.clone(), |_| {});

        // v0 (pre-versioning) and v2 (unknown future) are both unsupported.
        for bad_version in [0u32, PROOF_FORMAT_VERSION - 1, PROOF_FORMAT_VERSION + 1] {
            if bad_version == PROOF_FORMAT_VERSION {
                continue;
            }
            let mut tampered = envelope.clone();
            tampered.proof_format_version = bad_version;
            match Plonky3Adapter::verify(&tampered, &pi, &program) {
                Err(VerifyError::InvalidEnvelope(_)) => {}
                other => panic!(
                    "version {bad_version} must be rejected as InvalidEnvelope, got {other:?}"
                ),
            }
        }

        // Sanity: the untouched envelope still verifies after the tampered
        // attempts (the check reads the field, it does not consume it).
        envelope.proof_format_version = PROOF_FORMAT_VERSION;
        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_ok(),
            "the untouched envelope must still verify"
        );
    }

    /// Run a program honestly and return what the verifier answers, with the
    /// event and state write digests the run published. `prove_and_verify`
    /// leaves both at zero, which only suits a program that emits nothing.
    fn verify_honest_run(program: &[u64]) -> Result<(), VerifyError> {
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(program);
        assert!(receipt.success, "the honest run must succeed");
        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);
        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            // The AIR ties the final root to the storage-writes fold, so an
            // honest run of a writing program carries that digest as both.
            final_state_root: receipt.state_writes_digest,
            sender: vm.context.sender,
            nonce: vm.context.nonce,
            block_height: vm.context.block_height,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: crate::event_digest_from_events(&receipt.events),
            state_writes_digest: receipt.state_writes_digest,
        };
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, program).expect("prove");
        Plonky3Adapter::verify(&envelope, &pi, program)
    }

    /// Prove a hand-built step list and return what the verifier answers.
    ///
    /// The trace goes through `trace_matrix` unchanged and the proof is made
    /// with the lower-level prover, so nothing between the forged steps and
    /// the AIR gets a chance to refuse them first. The public inputs are
    /// derived from the steps and from the two gas figures the caller states,
    /// which is what a prover claiming a different run would publish.
    fn verify_forged_trace(
        program: &[u64],
        trace: &[Step],
        gas_limit: u64,
        gas_used: u64,
    ) -> Result<(), VerifyError> {
        verify_forged_matrix(program, trace, gas_limit, gas_used, |_| {})
    }

    /// Same as [`verify_forged_trace`], with a hook that edits the finished
    /// matrix before it is proved. For forgeries a step list cannot express,
    /// because the trace builder derives the cell from honest state.
    fn verify_forged_matrix(
        program: &[u64],
        trace: &[Step],
        gas_limit: u64,
        gas_used: u64,
        edit: impl FnOnce(&mut [Goldilocks]),
    ) -> Result<(), VerifyError> {
        verify_forged_matrix_with_aux(program, trace, gas_limit, gas_used, edit, |_, _, _| {})
    }

    /// Same as [`verify_forged_matrix`], with a second hook that edits the
    /// finished bus columns. The honest bus builder counts a memory row as
    /// one if its flag is nonzero. The AIR counts it as the flag itself. A
    /// matrix whose flag is not 0 or 1 needs this hook, or the bus is wrong
    /// for a reason other than the rule under test.
    fn verify_forged_matrix_with_aux(
        program: &[u64],
        trace: &[Step],
        gas_limit: u64,
        gas_used: u64,
        edit: impl FnOnce(&mut [Goldilocks]),
        fix_aux: impl FnOnce(
                &RowMajorMatrix<Goldilocks>,
                &[MyExtensionField],
                &mut RowMajorMatrix<Goldilocks>,
            ) + 'static,
    ) -> Result<(), VerifyError> {
        verify_forged_matrix_full(program, trace, gas_limit, gas_used, None, edit, fix_aux)
    }

    /// Same as [`verify_forged_matrix`], with the starting memory reads the
    /// public root commits to stated by the caller, not derived from the
    /// trace. For forgeries whose only rule left to refuse them is the one
    /// under test, because the root the honest derivation gives would refuse
    /// them first.
    fn verify_forged_matrix_with_reads(
        program: &[u64],
        trace: &[Step],
        gas_limit: u64,
        gas_used: u64,
        memory_reads: Vec<(u64, u64)>,
        edit: impl FnOnce(&mut [Goldilocks]),
    ) -> Result<(), VerifyError> {
        verify_forged_matrix_full(
            program,
            trace,
            gas_limit,
            gas_used,
            Some(memory_reads),
            edit,
            |_, _, _| {},
        )
    }

    fn verify_forged_matrix_full(
        program: &[u64],
        trace: &[Step],
        gas_limit: u64,
        gas_used: u64,
        memory_reads: Option<Vec<(u64, u64)>>,
        edit: impl FnOnce(&mut [Goldilocks]),
        fix_aux: impl FnOnce(
                &RowMajorMatrix<Goldilocks>,
                &[MyExtensionField],
                &mut RowMajorMatrix<Goldilocks>,
            ) + 'static,
    ) -> Result<(), VerifyError> {
        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(
                    &memory_reads.unwrap_or_else(|| initial_memory_reads(trace)),
                ),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(trace)),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit,
            gas_used,
            exit_code: 0,
            trace_len: trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(trace, program, &pi);
        edit(&mut matrix.values);
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);
        let air = BudAir {
            num_steps: trace.len(),
            program: program.to_vec(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some({
                let main = matrix.clone();
                let honest = crate::plonky3_prover::aux_trace_generator(
                    matrix.clone(),
                    n_cpu,
                    program.to_vec(),
                );
                Box::new(move |challenges: &[MyExtensionField]| {
                    let mut aux = honest(challenges);
                    fix_aux(&main, challenges, &mut aux);
                    aux
                })
            }),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };
        Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            program,
            bud_isa::MainnetActivation::full(),
        )
    }

    /// The `VerifyMerkle` fixture the forgery tests below start from: the
    /// one-sibling path of `proves_verify_merkle_valid_1_depth`, run through
    /// the honest VM.
    fn merkle_one_depth_run() -> (Vec<u64>, Vm) {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let key: u64 = 0;
        let mut siblings = [0u64; 64];
        siblings[0] = 1;
        let leaf: u64 = 0xBEEF;
        let mut cur = leaf;
        for &sib in siblings.iter() {
            cur = bud_vm::merkle_poseidon_round(cur, sib);
        }
        vm.memory[256..264].copy_from_slice(&key.to_le_bytes());
        for (i, &sib) in siblings.iter().enumerate() {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&sib.to_le_bytes());
        }
        vm.registers[2] = cur;
        vm.registers[3] = leaf;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.trace.len(), 66, "the original row, 64 rounds, Halt");
        (program, vm)
    }

    /// Point a forged `VerifyMerkle` trace at the root its (altered) rounds
    /// actually produce: re-run the chain from the leaf over whatever
    /// siblings the expansion rows now carry, and make the original row, its
    /// root operand and every register snapshot agree on the result. This is
    /// what a prover forging a path does, because the root register is the
    /// prover's to choose.
    fn rechain_merkle_trace(trace: &mut [Step]) {
        let mut cur = trace[0].src2_val;
        for step in trace.iter_mut().filter(|s| s.merkle_is_expand) {
            step.merkle_current = Some(cur);
            let sib = step.merkle_sibling.expect("expansion rows carry one");
            let bit = (step.merkle_key.expect("and the key") >> step.merkle_round.unwrap()) & 1;
            cur = if bit == 0 {
                bud_vm::merkle_poseidon_round(cur, sib)
            } else {
                bud_vm::merkle_poseidon_round(sib, cur)
            };
        }
        trace[0].merkle_current = Some(cur);
        trace[0].src1_val = cur;
        for step in trace.iter_mut() {
            step.registers[2] = cur;
        }
    }

    /// Run the program, tamper the trace, and assert that proving FAILS.
    fn prove_fails_after_tamper(
        program: Vec<u64>,
        setup: impl FnOnce(&mut Vm),
        tamper: impl FnOnce(&mut Vec<Step>),
    ) {
        let mut vm = Vm::new(64);
        setup(&mut vm);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        tamper(&mut vm.trace);

        // Callers of this helper often seed registers with
        // `vm.registers[n] = x` before running, so the trace reads values
        // nothing in it wrote. Those reads are the starting register file and
        // the AIR now requires the public inputs to commit to them, so the
        // root is computed from the trace rather than assumed to be zero. A
        // program that seeds nothing folds to zero and lands on the same
        // all-zero root as before.
        let initial_root = crate::adapter::initial_state_root_of(
            crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
            crate::adapter::register_image_commitment_of_reads(&initial_register_reads(&vm.trace)),
        );
        // As in `prove_and_verify_full`: the honest final root is the
        // storage-writes fold the AIR binds (2a).
        let final_root = receipt.state_writes_digest;
        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: initial_root,
            final_state_root: final_root,
            sender: vm.context.sender,
            nonce: vm.context.nonce,
            block_height: vm.context.block_height,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            // The honest digest, so a tampered storage test fails on the
            // tampering it names and not on a digest mismatch.
            state_writes_digest: receipt.state_writes_digest,
        };

        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            res.is_err(),
            "Expected verification to FAIL after tampering, but it succeeded!"
        );
    }

    /// Ten opcodes were constrained in the AIR and never attacked.
    ///
    /// Coverage was measured per opcode by walking every `rejects_*` test body
    /// for the `Opcode::` variants it builds, rather than by reading test
    /// names. Names lie: `rejects_tampered_comparison_result` sounds like it
    /// covers the comparison family and builds only `Lt`.
    ///
    /// A constraint with no forgery test is a constraint nobody has watched
    /// fail. Each test below tampers exactly one witness value and asserts the
    /// proof stops closing.
    #[test]
    fn rejects_a_forged_inverse() {
        // `Inv` is checked by `rs1 * rd + inv_zero - 1 == 0`. A prover naming
        // any other field element as the inverse breaks that product.
        let program = vec![
            inst(Opcode::Load, 2, 0, 0, 7),
            inst(Opcode::Inv, 1, 2, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_fails_after_tamper(
            program,
            |_| {},
            |trace| {
                trace[1].dst_val = trace[1].dst_val.wrapping_add(1);
            },
        );
    }

    /// `Inv` of zero is defined as zero by the VM, and the AIR carries a
    /// separate `inv_zero` flag for it. Claiming a non-zero inverse for zero
    /// is the forgery that flag exists to refuse.
    #[test]
    fn rejects_an_inverse_invented_for_zero() {
        let program = vec![
            inst(Opcode::Load, 2, 0, 0, 0),
            inst(Opcode::Inv, 1, 2, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_fails_after_tamper(
            program,
            |_| {},
            |trace| {
                trace[1].dst_val = 99;
            },
        );
    }

    /// `Not` is `1 - is_nonzero`, with `is_nonzero` proved boolean and pinned
    /// by `rs1 * (1 - is_nonzero) == 0`. Flipping the result alone leaves the
    /// witness pointing the other way.
    #[test]
    fn rejects_a_forged_logical_not() {
        let program = vec![
            inst(Opcode::Load, 2, 0, 0, 5),
            inst(Opcode::Not, 1, 2, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_fails_after_tamper(
            program,
            |_| {},
            |trace| {
                // 5 is non-zero, so Not is 0. Claim 1.
                trace[1].dst_val = 1;
            },
        );
    }

    /// `Eq` and `Neq` share one zero-test witness. `Eq` reads
    /// `1 - z` and `Neq` reads `z`, so a forged `Eq` result contradicts the
    /// same witness the difference pins.
    #[test]
    fn rejects_a_forged_equality() {
        let program = vec![inst(Opcode::Eq, 1, 2, 3, 0), inst(Opcode::Halt, 0, 0, 0, 0)];
        prove_fails_after_tamper(
            program,
            |vm| {
                vm.registers[2] = 42;
                vm.registers[3] = 42;
            },
            |trace| {
                // 42 == 42 is 1. Claim they differ.
                trace[0].dst_val = 0;
            },
        );
    }

    /// The mirror of the above on the other side of the shared witness.
    #[test]
    fn rejects_a_forged_inequality() {
        let program = vec![
            inst(Opcode::Neq, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_fails_after_tamper(
            program,
            |vm| {
                vm.registers[2] = 7;
                vm.registers[3] = 9;
            },
            |trace| {
                // 7 != 9 is 1. Claim they match.
                trace[0].dst_val = 0;
            },
        );
    }

    /// `Gt` reads the same 64-bit decomposition as `Lt` but takes the opposite
    /// side. A test on `Lt` alone leaves the reversed reading unwatched.
    #[test]
    fn rejects_a_forged_greater_than() {
        let program = vec![inst(Opcode::Gt, 1, 2, 3, 0), inst(Opcode::Halt, 0, 0, 0, 0)];
        prove_fails_after_tamper(
            program,
            |vm| {
                vm.registers[2] = 3;
                vm.registers[3] = 8;
            },
            |trace| {
                // 3 > 8 is 0. Claim it holds.
                trace[0].dst_val = 1;
            },
        );
    }

    /// `Lte` is the boundary case the strict comparisons do not reach: it must
    /// answer 1 when the operands are equal.
    #[test]
    fn rejects_a_forged_less_or_equal_at_the_boundary() {
        let program = vec![
            inst(Opcode::Lte, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_fails_after_tamper(
            program,
            |vm| {
                vm.registers[2] = 6;
                vm.registers[3] = 6;
            },
            |trace| {
                // 6 <= 6 is 1. Claim it fails.
                trace[0].dst_val = 0;
            },
        );
    }

    /// `Gte` at the same boundary, from the other direction.
    #[test]
    fn rejects_a_forged_greater_or_equal_at_the_boundary() {
        let program = vec![
            inst(Opcode::Gte, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_fails_after_tamper(
            program,
            |vm| {
                vm.registers[2] = 4;
                vm.registers[3] = 4;
            },
            |trace| {
                trace[0].dst_val = 0;
            },
        );
    }

    /// `Jmp` is `next_pc == pc + imm`. A rewritten destination is the
    /// arbitrary-jump forgery that cost Polygon zkEVM a critical finding, where
    /// a missing boolean constraint let a prover land anywhere in the ROM.
    #[test]
    fn rejects_a_jump_to_a_rewritten_destination() {
        let program = vec![
            inst(Opcode::Jmp, 0, 0, 0, 1),
            inst(Opcode::Load, 1, 0, 0, 5),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_fails_after_tamper(
            program,
            |_| {},
            |trace| {
                // The jump lands on pc + 1. Claim it landed somewhere else.
                trace[0].next_pc = 2;
            },
        );
    }

    /// `Jnz` picks between two destinations by a condition proved boolean and
    /// tied to `rs1` through an inverse witness. Forging the condition claims
    /// the branch went the way the register does not support.
    #[test]
    fn rejects_a_branch_that_forges_its_condition() {
        let program = vec![
            inst(Opcode::Load, 2, 0, 0, 0),
            inst(Opcode::Jnz, 0, 2, 0, 2),
            inst(Opcode::Load, 1, 0, 0, 5),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_fails_after_tamper(
            program,
            |_| {},
            |trace| {
                // r2 is zero, so the branch is not taken and next_pc is pc + 1.
                // Claim it jumped.
                trace[1].next_pc = 3;
            },
        );
    }

    /// The memory-image fold uses fixed constants, and a collision is one
    /// subtraction away.
    ///
    /// `COL_MEM_INIT_ACC` folds the starting memory image with
    /// `acc' = acc * BETA + addr * GAMMA + val` at constants baked into the
    /// AIR. The module doc is honest that this is weaker than a hash. This
    /// test measures *how much* weaker, because "weaker" without a number
    /// invites someone to read it as "still hard".
    ///
    /// It is not hard. Two initial-memory entries collide when
    /// `a1 * GAMMA + v1 == a2 * GAMMA + v2`, so for any address a prover
    /// wants to move a value to, the value that keeps the accumulator
    /// unchanged is `v2 = v1 + (a1 - a2) * GAMMA`, in one field operation.
    ///
    /// The fix is Fiat-Shamir: derive BETA and GAMMA from a transcript over
    /// the trace commitment, so the prover cannot solve for them before
    /// committing. That is a protocol change, not a constant swap, which is
    /// why this test states the exposure rather than pretending it is closed.
    #[test]
    fn the_memory_fold_constants_are_solvable_and_this_is_measured() {
        // Goldilocks. The fold runs in this field, so the arithmetic below is
        // the arithmetic the AIR does.
        const P: u128 = 0xFFFF_FFFF_0000_0001;
        let gamma = u128::from(MEM_INIT_GAMMA);

        let term = |addr: u128, val: u128| (addr * gamma + val) % P;

        let (a1, v1) = (100u128, 42u128);
        let a2 = 200u128;
        // v2 = v1 + (a1 - a2) * GAMMA, computed without going negative.
        let v2 = (v1 + (P - (a2 - a1) % P) * gamma) % P;

        assert_ne!((a1, v1), (a2, v2), "the two entries must actually differ");
        assert_eq!(
            term(a1, v1),
            term(a2, v2),
            "a different address and value reach the same fold term, which is \
             what fixed constants allow and a transcript challenge would not"
        );
    }

    /// The register-image fold has the same shape and the same exposure.
    ///
    /// Recorded separately because the two accumulators carry their own
    /// constants, and a fix applied to one and not the other would leave this
    /// one standing while the first test went green.
    #[test]
    fn the_register_fold_shares_the_memory_fold_weakness() {
        const P: u128 = 0xFFFF_FFFF_0000_0001;
        let gamma = u128::from(REG_INIT_GAMMA);

        assert_ne!(
            REG_INIT_BETA, MEM_INIT_BETA,
            "the register fold keeps its own beta"
        );
        assert_ne!(
            REG_INIT_GAMMA, MEM_INIT_GAMMA,
            "the register fold keeps its own gamma"
        );

        // Same first read. The second read moves from register 2 to register 3
        // and the value absorbs the difference: v2 = v1 + (i1 - i2) * GAMMA.
        let (i1, v1) = (2u128, 20u128);
        let i2 = 3u128;
        let v2 = (v1 + (P - (i2 - i1) % P) * gamma) % P;
        let first = (1u64, 10u64);
        let reads_a = [first, (i1 as u64, v1 as u64)];
        let reads_b = [first, (i2 as u64, v2 as u64)];

        assert_ne!(reads_a, reads_b, "the two read lists must differ");
        assert_eq!(
            crate::adapter::register_image_commitment_of_reads(&reads_a),
            crate::adapter::register_image_commitment_of_reads(&reads_b),
            "two different register read lists reach one production commitment"
        );
    }

    /// Read the stack pointer out of the column the constraint reads.
    ///
    /// `Step::stack_pointer` is the depth *after* the instruction ran.
    /// `trace_matrix` converts it back to the depth *before* the instruction,
    /// because that is the value `COL_STACK_PTR` holds and the value the
    /// transition constraint is written against. The two differ by one on
    /// exactly the rows that matter: after the first `Call` the VM field says
    /// 1 while the column says the 0 that `when_first_row` pins.
    ///
    /// A test that reads the VM field is measuring a neighbouring number and
    /// calling it the constrained one. This helper takes the column, padding
    /// rows included, since the constraint applies to every row of the matrix
    /// and not only to the rows that came from the VM.
    fn stack_pointer_column(program: &[u64]) -> (Vec<u64>, usize) {
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(program);
        assert!(
            receipt.success,
            "the honest program must run, or the column proves nothing"
        );

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash: [0u8; 32],
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (matrix, n_cpu) = trace_matrix(&vm.trace, program, &pi);
        let rows = matrix.values.len() / TRACE_WIDTH;
        let column = (0..rows)
            .map(|i| matrix.values[i * TRACE_WIDTH + COL_STACK_PTR].as_canonical_u64())
            .collect();
        (column, n_cpu)
    }

    /// The stack pointer has no explicit upper bound, and does not need one.
    ///
    /// Carried as an open finding for a long time: `COL_STACK_PTR` is
    /// constrained only in transition (`+1` on push and call, `-1` on pop and
    /// ret, `0` otherwise) with no range check. The stack is table 2 of the
    /// memory argument, with 32 bit slots, so the question is whether a prover
    /// can drive the pointer up until it leaves that range.
    ///
    /// It cannot, through three constraints that already exist and were never
    /// read together:
    ///
    /// 1. `when_first_row` pins the pointer to zero.
    /// 2. `assert_eq(is_cpu, 1)` makes exactly one opcode selector live per
    ///    row, and every selector is `assert_bool`. Two increments cannot land
    ///    on one row.
    /// 3. The transition allows at most `+1` per row.
    ///
    /// Starting at zero and rising by at most one per row, the pointer after
    /// `n` rows is at most `n`. `trace_len` is a public input the verifier
    /// checks, so the bound is whatever the caller committed to rather than
    /// something the prover picks.
    ///
    /// Pins the column read path.
    /// than the VM field beside it: see `stack_pointer_column`. A change that
    /// lets a row push twice, or that drops the first-row pin, fails here
    /// instead of waiting for someone to rederive the argument.
    #[test]
    fn the_stack_pointer_cannot_outrun_the_trace() {
        // Nested calls drive the pointer as fast as the machine allows.
        let program = vec![
            inst(Opcode::Call, 0, 0, 0, 2),
            inst(Opcode::Halt, 0, 0, 0, 0),
            inst(Opcode::Call, 0, 0, 0, 2),
            inst(Opcode::Halt, 0, 0, 0, 0),
            inst(Opcode::Call, 0, 0, 0, 2),
            inst(Opcode::Halt, 0, 0, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let (column, n_cpu) = stack_pointer_column(&program);

        assert_eq!(
            column[0], 0,
            "the first row starts at zero, which is what `when_first_row` pins"
        );

        for row in 1..column.len() {
            let delta = column[row] as i64 - column[row - 1] as i64;
            assert!(
                (-1..=1).contains(&delta),
                "row {row} moved the stack pointer by {delta}; the transition \
                 allows at most one, and the bound is derived from that"
            );
        }

        for (row, depth) in column.iter().enumerate() {
            assert!(
                *depth <= row as u64,
                "row {row} holds depth {depth}, past the row index; starting \
                 at zero and rising by at most one is what bounds it"
            );
        }

        // The program has to actually drive the pointer, or the two checks
        // above hold over a column of zeros and mean nothing.
        assert!(
            column.iter().take(n_cpu).any(|d| *d > 0),
            "the nested calls never raised the pointer, so this test measured \
             an idle column"
        );
    }

    /// A trace that pushes on every row reaches the bound and no further.
    ///
    /// The inverse witness for the test above: if the pointer could exceed the
    /// row count, this is the program that would show it, because every row
    /// after the first takes the increment.
    #[test]
    fn a_trace_of_pushes_stops_at_the_row_count() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Push, 0, 1, 0, 0),
            inst(Opcode::Push, 0, 1, 0, 0),
            inst(Opcode::Push, 0, 1, 0, 0),
            inst(Opcode::Push, 0, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let (column, n_cpu) = stack_pointer_column(&program);

        let peak = column.iter().copied().max().expect("the matrix has rows");
        assert_eq!(peak, 4, "four pushes reach four, not more");
        assert!(
            peak <= n_cpu as u64,
            "the peak stayed under the row count the VM produced"
        );
        assert!(
            column[n_cpu..].iter().all(|d| *d == peak),
            "padding must carry the last depth forward; a padding row that \
             drops it would be a transition the constraint forbids"
        );
    }

    /// The privacy three carry the sharpest forgeries in the instruction set,
    /// because each one, forged, is money.
    ///
    /// `PrivacyCommit` hashes `(amount, blinding, recipient)` into the
    /// commitment a shielded note is identified by. A prover who can name a
    /// different hash for the same inputs mints a note whose stated amount is
    /// not the amount the commitment binds.
    #[test]
    fn rejects_a_privacy_commitment_that_does_not_hash_its_inputs() {
        let program = vec![
            inst(Opcode::Load, 2, 0, 0, 1_000),
            inst(Opcode::Load, 3, 0, 0, 424_242),
            inst(Opcode::PrivacyCommit, 1, 2, 3, 7),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_fails_after_tamper(
            program,
            |_| {},
            |trace| {
                // Same amount, same blinding, a commitment of the prover's choice.
                trace[2].dst_val = trace[2].dst_val.wrapping_add(1);
            },
        );
    }

    /// `NullifierCheck` answers 1 only when the claimed nullifier equals
    /// `Poseidon(secret)`. Forging that answer is double-spending: the same
    /// note is spent twice because the second spend claims a nullifier it
    /// cannot derive.
    #[test]
    fn rejects_a_nullifier_that_was_never_derived() {
        let program = vec![
            inst(Opcode::Load, 2, 0, 0, 12_345),
            inst(Opcode::Load, 3, 0, 0, 6_789),
            inst(Opcode::NullifierCheck, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(
            vm.registers[1], 0,
            "an arbitrary claim is not the nullifier the secret derives"
        );

        prove_fails_after_tamper(
            program,
            |_| {},
            |trace| {
                // The check failed honestly. Claim it passed.
                trace[2].dst_val = 1;
            },
        );
    }

    /// `SumConservation` is the constraint that stops a shielded transfer from
    /// printing value: inputs must equal outputs. Forging its answer inflates
    /// the supply by exactly the difference.
    #[test]
    fn rejects_a_transfer_that_claims_unequal_sums_balance() {
        let program = vec![
            inst(Opcode::Load, 2, 0, 0, 500),
            inst(Opcode::Load, 3, 0, 0, 900),
            inst(Opcode::SumConservation, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(
            vm.registers[1], 0,
            "500 in and 900 out does not conserve, so the honest answer is 0"
        );

        prove_fails_after_tamper(
            program,
            |_| {},
            |trace| {
                // Claim 400 units appeared from nowhere and the sums balanced.
                trace[2].dst_val = 1;
            },
        );
    }

    /// `Syscall` reads context the caller does not control. A forged answer is
    /// a claim about the block or the sender that the public inputs contradict.
    #[test]
    fn rejects_a_syscall_that_forges_its_answer() {
        let program = vec![
            inst(Opcode::Syscall, 1, 0, 0, 2),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_fails_after_tamper(
            program,
            |_| {},
            |trace| {
                trace[0].dst_val = trace[0].dst_val.wrapping_add(1);
            },
        );
    }

    /// `Syscall` had no prover coverage. It is constrained in the AIR (selector
    /// booleanity, exclusivity, a gas cost of 5) and reads context values, so a
    /// proof over it must close.
    #[test]
    fn proves_syscall_reading_context() {
        let program = vec![
            inst(Opcode::Syscall, 1, 0, 0, 1), // r1 = sender
            inst(Opcode::Syscall, 2, 0, 0, 2), // r2 = block_height
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |_| {});
    }

    /// `Jmp` had no prover coverage. A jump that lands on the next instruction
    /// executes every program row, so it is provable and pins the
    /// `next_pc = pc + imm` constraint.
    #[test]
    fn proves_jump_that_skips_nothing() {
        let program = vec![
            inst(Opcode::Jmp, 0, 0, 0, 1),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |_| {});
    }

    /// `Store` had no prover coverage at all: it is constrained in the AIR and
    /// wired into the memory CTL, but no test ever proved a program using it.
    /// Struct-using BudL contracts lower into Store/Load pairs, so the gap was
    /// load-bearing.
    #[test]
    fn proves_store_then_load_roundtrip() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 0),  // r1 = 0 (address)
            inst(Opcode::Load, 2, 0, 0, 42), // r2 = 42 (value)
            inst(Opcode::Store, 0, 1, 2, 0), // mem[r1] = r2
            inst(Opcode::Load, 3, 1, 0, 0),  // r3 = mem[r1]
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |_| {});
    }

    /// The same round trip through a base register that is not `r1`.
    ///
    /// `proves_store_then_load_roundtrip` above passes and always did, and
    /// that is the whole reason this one is here. The memory argument scaled
    /// its demand side by `rs1_idx` itself rather than by "rs1 is not r0", so
    /// the CPU side asked the bus for `rs1_idx` copies of a row the memory
    /// table supplies once. With the pointer in `r1` the multiplier is one and
    /// the argument balances; with it in `r7` the CPU side asks seven times
    /// and no honest proof exists. A whole class of correct programs was
    /// unprovable and every test picked `r1`.
    ///
    /// The register a compiler happens to allocate is not a soundness
    /// boundary, so the completeness half is tested across several of them.
    #[test]
    fn proves_store_then_load_through_a_high_base_register() {
        for base in [2u8, 7, 30] {
            let program = vec![
                inst(Opcode::Load, base, 0, 0, 0),  // r_base = 0 (address)
                inst(Opcode::Load, 1, 0, 0, 42),    // r1 = 42 (value)
                inst(Opcode::Store, 0, base, 1, 0), // mem[r_base] = r1
                inst(Opcode::Load, 3, base, 0, 0),  // r3 = mem[r_base]
                inst(Opcode::Halt, 0, 0, 0, 0),
            ];
            let mut vm = Vm::new(64);
            let receipt = vm.run_receipt(&program);
            assert!(receipt.success, "base r{base} must execute");
            assert_eq!(vm.registers[3], 42, "base r{base} must read 42 back");
            prove_and_verify(program, |_| {});
        }
    }

    /// A `Load` that names a base register must actually read memory.
    ///
    /// The soundness half of the same column. `Load rd, r0, imm` is
    /// load-immediate and touches no memory; every other `Load` reads the word
    /// at `rs1_val + imm`. The flag separating them is now
    /// `rs1_idx * rs1_idx_inv`, and a prover that zeroes the inverse witness
    /// is claiming a memory-addressing `Load` never went to the bus, which
    /// would let the destination register take a value memory never held.
    #[test]
    fn rejects_a_load_that_denies_touching_memory() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 0),  // r1 = 0 (address)
            inst(Opcode::Load, 2, 0, 0, 99), // r2 = 99
            inst(Opcode::Store, 0, 1, 2, 0), // mem[r1] = 99
            inst(Opcode::Load, 3, 1, 0, 0),  // r3 = mem[r1]
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.registers[3], 99);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);

        // Find the reading Load: `is_load` with a non-zero base register.
        let mut load_row = None;
        for i in 0..n_cpu {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_IS_LOAD].as_canonical_u64() == 1
                && matrix.values[row_start + COL_RS1_IDX].as_canonical_u64() != 0
            {
                load_row = Some(i);
                break;
            }
        }
        let load_row = load_row.expect("the trace must contain a memory-reading Load");
        let lr = load_row * TRACE_WIDTH;
        assert_ne!(
            matrix.values[lr + COL_RS1_IDX_INV].as_canonical_u64(),
            0,
            "the honest row must carry the inverse of its base register"
        );

        // The forgery: claim this Load never addressed memory, which switches
        // it off the demand side of the memory argument.
        matrix.values[lr + COL_RS1_IDX_INV] = Goldilocks::new(0);

        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);
        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a Load denied addressing memory and the proof verified; the \
             destination register can then take a value memory never held"
        );
    }

    fn store_through_r0_program() -> Vec<u64> {
        vec![
            inst(Opcode::Load, 2, 0, 0, 99),  // r2 = 99
            inst(Opcode::Store, 0, 0, 2, 16), // mem[0 + 16] = r2, base is r0
            inst(Opcode::Load, 1, 0, 0, 16),  // r1 = 16
            inst(Opcode::Load, 3, 1, 0, 0),   // r3 = mem[16]
            inst(Opcode::Halt, 0, 0, 0, 0),
        ]
    }

    /// An honest `Store` whose base register is r0 writes memory, so it must
    /// put a demand on the memory bus like every other `Store`.
    #[test]
    fn proves_store_through_r0() {
        let program = store_through_r0_program();
        let mut vm = Vm::new(64);
        assert!(vm.run_receipt(&program).success);
        assert_eq!(vm.registers[3], 99);
        prove_and_verify(program, |_| {});
    }

    /// `Store rs1=r0` is not load-immediate: only `Load` has that meaning. A
    /// prover that drops the write from the memory argument could let a later
    /// `Load` read a value no write ever put there.
    #[test]
    fn rejects_a_store_through_r0_that_skips_memory() {
        let program = store_through_r0_program();
        let mut vm = Vm::new(64);
        assert!(vm.run_receipt(&program).success);
        assert_eq!(vm.registers[3], 99);

        // The forgery: the Store claims it touched no memory, and the Load
        // that read the word back claims memory held zero.
        assert_eq!(vm.trace[1].instruction.opcode, Opcode::Store);
        assert_eq!(vm.trace[3].instruction.opcode, Opcode::Load);
        vm.trace[1].memory_addr = None;
        vm.trace[1].memory_val = None;
        vm.trace[3].memory_val = Some(0);
        vm.trace[3].dst_val = 0;
        for step in vm.trace.iter_mut().skip(3) {
            step.registers[3] = 0;
        }

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);
        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a Store through r0 skipped the memory argument and the proof \
             verified; a later Load can then read a word nothing wrote"
        );
    }

    /// A negative immediate is the field element `P - |imm|` in the VM, the
    /// trace and the AIR alike. `Load rd, r0, imm` copies it to `rd`.
    #[test]
    fn proves_load_imm_negative() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, -1),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        assert!(vm.run_receipt(&program).success);
        assert_eq!(vm.registers[1], bud_vm::GOLDILOCKS_P - 1);
        prove_and_verify(program, |_| {});
    }

    /// Honest `Eq`, `Neq` and `SumConservation` with `rs1 < rs2`. The inverse
    /// witness is the field inverse of `rs1 - rs2`; `wrapping_sub` gave
    /// `2^64 - d`, which is not that element.
    #[test]
    fn proves_eq_neq_sc_when_rs1_lt_rs2() {
        for op in [Opcode::Eq, Opcode::Neq, Opcode::SumConservation] {
            let program = vec![
                inst(Opcode::Load, 1, 0, 0, 1),
                inst(Opcode::Load, 2, 0, 0, 2),
                inst(op, 3, 1, 2, 0),
                inst(Opcode::Halt, 0, 0, 0, 0),
            ];
            prove_and_verify(program, |_| {});
        }
    }

    /// `Assert` had no prover coverage either, and BudL's `constrain(...)`
    /// lowers straight to it.
    #[test]
    fn proves_assert_on_a_true_condition() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Load, 2, 0, 0, 7),
            inst(Opcode::Eq, 3, 1, 2, 0),
            inst(Opcode::Assert, 0, 3, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |_| {});
    }

    /// Public inputs built by the shared helper must verify, this is the path
    /// every caller outside this crate takes.
    ///
    /// The in-crate `prove_and_verify` helper hard-codes
    /// `event_digest: [0u8; 32]`, which is only correct for programs that emit
    /// nothing. That blind spot let `bud-cli` ship a keccak-based digest that
    /// made every proof it generated fail verification.
    #[test]
    fn helper_built_event_digest_verifies_for_a_logging_program() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Log, 0, 1, 0, 0),
            inst(Opcode::Load, 2, 0, 0, 5),
            inst(Opcode::Log, 0, 2, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(receipt.events, vec![7, 5]);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: vm.context.sender,
            nonce: vm.context.nonce,
            block_height: vm.context.block_height,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: crate::event_digest_from_events(&receipt.events),
            state_writes_digest: [0u8; 32],
        };
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_ok(),
            "helper-built event_digest must satisfy the AIR binding"
        );
    }

    /// Canary: hashing the event list instead of accumulating it must stay
    /// rejected, so the mistake cannot come back unnoticed.
    #[test]
    fn keccak_style_event_digest_is_rejected_by_the_air() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Log, 0, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let event_bytes: Vec<u8> = receipt
            .events
            .iter()
            .flat_map(|&e| e.to_le_bytes().to_vec())
            .collect();
        let mut eh = Keccak::v256();
        eh.update(&event_bytes);
        let mut hashed_digest = [0u8; 32];
        eh.finalize(&mut hashed_digest);
        assert_ne!(
            hashed_digest,
            crate::event_digest_from_events(&receipt.events),
            "the two encodings must differ for this canary to bite"
        );

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: vm.context.sender,
            nonce: vm.context.nonce,
            block_height: vm.context.block_height,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: hashed_digest,
            state_writes_digest: [0u8; 32],
        };
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a hashed event digest must not satisfy the accumulator binding"
        );
    }

    /// Log updates event_digest; public inputs must carry limb0=sum.
    #[test]
    fn proves_log_event_digest() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Log, 0, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(receipt.events, vec![7]);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let mut event_digest = [0u8; 32];
        event_digest[0..4].copy_from_slice(&7u32.to_le_bytes());

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: vm.context.sender,
            nonce: vm.context.nonce,
            block_height: vm.context.block_height,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest,
            state_writes_digest: [0u8; 32],
        };
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        assert!(Plonky3Adapter::verify(&envelope, &pi, &program).is_ok());
    }

    #[test]
    fn proves_simple_add_trace() {
        let program = vec![
            inst(Opcode::Add, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];

        prove_and_verify(program, |vm| {
            vm.registers[2] = 10;
            vm.registers[3] = 20;
        });
    }

    #[test]
    fn proves_arithmetic_trace() {
        let program = vec![
            inst(Opcode::Add, 1, 2, 3, 0),
            inst(Opcode::Sub, 4, 1, 3, 0),
            inst(Opcode::Mul, 5, 4, 2, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];

        prove_and_verify(program, |vm| {
            vm.registers[2] = 7;
            vm.registers[3] = 5;
        });
    }

    /// Division (field) and the div-by-zero / inverse-of-zero edge cases
    /// Round-trip through the prover. The VM defines `x / 0 = 0` and
    /// `inv(0) = 0`; the AIR now pins `rd` to 0 in those cases (soundness:
    /// A malicious prover can no longer pick an arbitrary quotient), and
    /// Honest trace satisfying the constraint.
    #[test]
    fn proves_division_and_zero_edge_cases() {
        let program = vec![
            inst(Opcode::Div, 4, 2, 3, 0), // r4 = r2 / r3 (field division)
            inst(Opcode::Div, 5, 2, 6, 0), // r5 = r2 / r6, with r6 = 0 -> div by zero -> 0
            inst(Opcode::Inv, 7, 6, 0, 0), // r7 = inv(r6), r6 = 0 -> inv(0) -> 0
            inst(Opcode::Inv, 8, 2, 0, 0), // r8 = inv(r2) (non-zero)
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];

        prove_and_verify(program, |vm| {
            vm.registers[2] = 10;
            vm.registers[3] = 3;
            vm.registers[6] = 0; // zero divisor / zero inverse input
        });
    }

    /// Div-by-zero is defined as result 0 by the VM and pinned by the AIR
    /// (`when(is_div * div_zero).assert_zero(rd_val_new)`). A prover claiming a
    /// non-zero quotient for a zero divisor is the forgery that pin exists to
    /// refuse - the canary that it is actually live.
    #[test]
    fn rejects_a_forged_div_by_zero_result() {
        let program = vec![
            inst(Opcode::Div, 4, 2, 3, 0), // r4 = r2 / r3, with r3 = 0
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_fails_after_tamper(
            program,
            |vm| {
                vm.registers[2] = 5; // dividend
                vm.registers[3] = 0; // zero divisor -> div by zero -> 0
            },
            |trace| {
                // The honest VM result is 0. Claim 7 instead.
                trace[0].dst_val = 7;
            },
        );
    }

    #[test]
    fn proves_load_immediate_trace() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 42),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];

        prove_and_verify(program, |_| {});
    }

    #[test]
    fn proves_push_pop_trace() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 123),
            inst(Opcode::Push, 0, 1, 0, 0),
            inst(Opcode::Pop, 2, 0, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];

        prove_and_verify(program, |_| {});
    }

    #[test]
    fn proves_call_ret_trace() {
        let program = vec![
            inst(Opcode::Call, 0, 0, 0, 2),
            inst(Opcode::Halt, 0, 0, 0, 0),
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Ret, 0, 0, 0, 0),
        ];

        prove_and_verify(program, |_| {});
    }

    #[test]
    fn proves_nested_call_trace() {
        let program = vec![
            inst(Opcode::Call, 0, 0, 0, 4), // Call B
            inst(Opcode::Halt, 0, 0, 0, 0),
            // Func A (index 2)
            inst(Opcode::Load, 1, 0, 0, 42),
            inst(Opcode::Ret, 0, 0, 0, 0),
            // Func B (index 4)
            inst(Opcode::Call, 0, 0, 0, -2), // Call A
            inst(Opcode::Ret, 0, 0, 0, 0),
        ];

        prove_and_verify(program, |_| {});
    }

    /// A `Pop` cannot invent a value the stack never held.
    ///
    /// `Pop` has the same shape as `Ret`: measured, the only builder
    /// statements naming it are selector booleanity, the `pc + 1` step, and
    /// the shared stack pointer rule. Nothing per opcode says what lands in
    /// the destination register.
    ///
    /// The memory argument carries it. `Pop` demands a read at
    /// stack slot `stack_ptr - 1` whose value is `COL_RD_VAL_NEW`, and the
    /// matching `Push` supplied a write there carrying its `rs1`. Changing the
    /// popped value unbalances the argument against what was pushed.
    ///
    /// Worth its own test for the same reason `Ret` was: the property lives in
    /// a different subsystem from the opcode, so a change to the memory
    /// argument could remove it without anything named `Pop` being touched.
    #[test]
    fn rejects_a_pop_that_invents_a_value() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 123),
            inst(Opcode::Push, 0, 1, 0, 0),
            inst(Opcode::Pop, 2, 0, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(
            vm.registers[2], 123,
            "the honest pop returns what was pushed"
        );

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: crate::event_digest_from_events(&receipt.events),
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);

        let mut pop_row = None;
        for i in 0..n_cpu {
            if matrix.values[i * TRACE_WIDTH + COL_IS_POP].as_canonical_u64() == 1 {
                pop_row = Some(i);
                break;
            }
        }
        let pop_row = pop_row.expect("the trace must contain a Pop row");
        let at = pop_row * TRACE_WIDTH;
        assert_eq!(
            matrix.values[at + COL_RD_VAL_NEW].as_canonical_u64(),
            123,
            "the honest row pops the pushed value"
        );

        // The forgery: pop something the stack never held.
        matrix.values[at + COL_RD_VAL_NEW] = Goldilocks::new(999);

        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);
        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a Pop returned a value nothing pushed and the proof verified; \
             the stack would then be a place a prover can read anything from"
        );
    }

    /// Every syscall number the VM accepts must be provable.
    ///
    /// The AIR picked out each number with a polynomial that is zero on the
    /// others, and those are correct about the four they name and wrong about
    /// everything else. At `imm = 4` all four fired at once, so the row had to
    /// return the sender, the block height, the nonce and zero simultaneously.
    /// That holds only when the context is all zeroes, which is what every
    /// fixture happens to be.
    ///
    /// The context here is deliberately non-zero, so the old polynomials would
    /// fail on the unknown number while passing on 1, 2 and 3.
    #[test]
    fn proves_every_syscall_number_including_unknown_ones() {
        for imm in [1i32, 2, 3, 4, 6, 99] {
            let program = vec![
                inst(Opcode::Syscall, 2, 1, 0, imm),
                inst(Opcode::Halt, 0, 0, 0, 0),
            ];
            let mut vm = Vm::new(64);
            vm.registers[1] = 5;
            vm.context.sender = 0xAAAA;
            vm.context.block_height = 0xBBBB;
            vm.context.nonce = 0xCCCC;
            let receipt = vm.run_receipt(&program);
            assert!(receipt.success, "the VM accepts syscall {imm}");

            let program_bytes: Vec<u8> = program
                .iter()
                .flat_map(|&i| i.to_le_bytes().to_vec())
                .collect();
            let mut hasher = Keccak::v256();
            hasher.update(&program_bytes);
            let mut program_hash = [0u8; 32];
            hasher.finalize(&mut program_hash);

            let pi = ExecutionPublicInputs {
                chain_id: 1,
                program_hash,
                initial_state_root: crate::adapter::initial_state_root_of(
                    crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(
                        &vm.trace,
                    )),
                    crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                        &vm.trace,
                    )),
                ),
                final_state_root: [0u8; 32],
                sender: vm.context.sender,
                nonce: vm.context.nonce,
                block_height: vm.context.block_height,
                gas_limit: vm.gas_limit,
                gas_used: vm.gas_used,
                exit_code: 0,
                trace_len: vm.trace.len() as u64,
                event_digest: crate::event_digest_from_events(&receipt.events),
                state_writes_digest: [0u8; 32],
            };

            let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program)
                .unwrap_or_else(|e| panic!("syscall {imm} must build a proof: {e:?}"));
            Plonky3Adapter::verify(&envelope, &pi, &program).unwrap_or_else(|e| {
                panic!(
                    "syscall {imm} must verify against a non-zero context: {e:?}. \
                     A polynomial selector cannot say \"this row is syscall one\", \
                     only \"not two or three or six\", and those differ on every \
                     number the list does not mention"
                )
            });
        }
    }

    /// A program calling syscall 6 must be provable.
    ///
    /// The syscall emits two events in the VM, the AI inference marker
    /// `0x00A1_00A1` and its `rs1`, and `executor.rs` reads exactly that
    /// pattern to queue an inference request. The AIR's event digest only ever
    /// counted `Log` rows, so the trace column reached zero while the caller
    /// built the public input from `receipt.events` and got the sum of both.
    /// Measured with `rs1 = 5`: the receipt digest is 10551462 against a
    /// column holding 0, and the last-row comparison refuses.
    ///
    /// Completeness, like the `Assert` case: the AIR was not wrong about
    /// anything false, it disagreed with the VM about what happened, and the
    /// honest prover is the one that loses.
    #[test]
    fn proves_a_program_that_calls_the_inference_syscall() {
        let program = vec![
            inst(Opcode::Syscall, 2, 1, 0, 6),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        vm.registers[1] = 5;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(
            receipt.events,
            vec![0x00A1_00A1, 5],
            "the syscall announces the marker and its operand, which is what \
             executor.rs reads to queue an inference request"
        );

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: vm.context.sender,
            nonce: vm.context.nonce,
            block_height: vm.context.block_height,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: crate::event_digest_from_events(&receipt.events),
            state_writes_digest: [0u8; 32],
        };

        let envelope =
            Plonky3Adapter::prove(&vm.trace, &pi, &program).expect("the honest proof must build");
        Plonky3Adapter::verify(&envelope, &pi, &program).expect(
            "a program calling syscall 6 must be provable; the digest has to \
             count the events the syscall announces, not only Log rows",
        );
    }

    /// A `Ret` cannot return to an address the matching `Call` did not push.
    ///
    /// `Ret` has almost no constraints of its own: measured, only booleanity
    /// of its selector and the stack pointer step. Nothing in the per opcode
    /// rules ties `next_pc` to anything, which is what made it worth testing.
    ///
    /// What holds it is the memory argument, one step removed. `Ret` demands a
    /// read at stack slot `stack_ptr - 1` whose value is `COL_NEXT_PC`, and
    /// `Call` supplies a write at the same address whose value is `pc + 1`.
    /// Redirecting the return means either changing the value read, which
    /// unbalances the argument against what `Call` wrote, or changing the
    /// address, which reads somewhere the trace never wrote and hits the
    /// first-read-zero rule.
    ///
    /// An indirect binding is still a binding, but it is the kind that gets
    /// broken by a change to a different opcode, so it gets a test naming the
    /// property rather than the mechanism.
    #[test]
    fn rejects_a_return_to_an_address_never_pushed() {
        // Call jumps forward two, the body loads 7, Ret comes back to the Halt.
        let program = vec![
            inst(Opcode::Call, 0, 0, 0, 2),
            inst(Opcode::Halt, 0, 0, 0, 0),
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Ret, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: crate::event_digest_from_events(&receipt.events),
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);

        let mut ret_row = None;
        for i in 0..n_cpu {
            if matrix.values[i * TRACE_WIDTH + COL_IS_RET].as_canonical_u64() == 1 {
                ret_row = Some(i);
                break;
            }
        }
        let ret_row = ret_row.expect("the trace must contain a Ret row");
        let at = ret_row * TRACE_WIDTH;

        let honest = matrix.values[at + COL_NEXT_PC].as_canonical_u64();
        assert_eq!(honest, 1, "the honest Ret returns to the Halt at pc 1");

        // The forgery: return into the called body instead, which skips the
        // Halt and re-runs the load.
        matrix.values[at + COL_NEXT_PC] = Goldilocks::new(2);

        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);
        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a Ret returned somewhere its Call never pushed and the proof \
             verified; control flow after a call would then be the prover's \
             to choose"
        );
    }

    /// A jump whose target lies past the end of the program must not verify.
    ///
    /// The VM refuses to step on such a pc (`if self.pc >= program.len()`), but
    /// the AIR places no bound on `COL_PC` at all: the jump constraint says
    /// `next_pc = pc + imm` and nothing says the result addresses a real
    /// instruction. SP1 Hypercube shipped the neighbouring version of this,
    /// where JALR computed its target without the specified `& ~1`; Polygon
    /// zkEVM shipped the severe one, where a missing boolean constraint let a
    /// prover reach an arbitrary ROM address and mint balance.
    ///
    /// What closes it here is not a range check but the Program CTL. Every CPU
    /// row has to match a preprocessed row on `(pc, raw_inst, ...)`, and the
    /// preprocessed table carries `IS_ACTIVE = 0` at every index from
    /// `program.len()` upward. A CPU row at such a pc contributes to the LogUp
    /// sum with nothing on the other side to cancel it, so the running sum
    /// cannot close and the proof is refused.
    ///
    /// That is a real defence and also an indirect one: it lives in a
    /// different constraint from the jump it protects, and nothing in the jump
    /// constraint mentions it. This test is what ties the two together.
    /// Someone optimising the Program CTL, or relaxing `IS_ACTIVE`, would
    /// otherwise reopen arbitrary control flow without editing a line that
    /// looks like it has anything to do with jumps.
    ///
    /// The fixture's first row is a real `Jmp` with `imm = 5`, so the jump
    /// rule `next_pc == pc + imm` and the sequential rule both hold. Only the
    /// Program CTL refuses the Halt row at pc 5.
    /// `rejects_a_fall_through_that_skips_an_instruction` pins the sequential
    /// rule on its own.
    #[test]
    fn rejects_a_jump_past_the_end_of_the_program() {
        // A real jump whose target is past the program end. The VM refuses
        // to step at pc 5, so `run_receipt` ends the trace with a synthetic
        // Halt row at that pc. The jump row keeps `next_pc == pc + imm`, so
        // the sequential rule has nothing to say and only the Program CTL
        // can object to the Halt row at pc 5.
        let program = vec![
            inst(Opcode::Jmp, 0, 0, 0, 5),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(
            !receipt.success,
            "the VM must refuse the out of range pc, or the fixture is not a bad jump"
        );

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: crate::event_digest_from_events(&receipt.events),
            state_writes_digest: [0u8; 32],
        };

        let (matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        assert!(n_cpu >= 2, "the fixture needs at least two CPU rows");
        assert_eq!(
            matrix.values[COL_NEXT_PC].as_canonical_u64(),
            5,
            "the first row must jump to the out of range pc"
        );

        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);
        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a CPU row executed at a pc past the end of the program and the \
             proof verified. Nothing in the AIR bounds `COL_PC`; the Program \
             CTL is the only thing between a prover and arbitrary control \
             flow, and it just stopped being that."
        );
    }

    /// The default verifier refuses the staged opcodes, whatever the proof.
    ///
    /// The AIR proves that a program ran, not that the chain allows it to run.
    /// `VerifyMerkle` and `VerifyInference` are off unless activated, and
    /// the execution path refuses them, but a proof reaches the verifier
    /// without passing through it. Both proofs below are honest and verify
    /// under full activation; under the default they are refused before the
    /// STARK is looked at, with an error that names the opcode.
    #[test]
    fn verifier_refuses_verify_merkle_under_default_activation() {
        // VerifyMerkle: the honest one-sibling path.
        let (program, vm) = merkle_one_depth_run();
        let program_hash = {
            let bytes: Vec<u8> = program.iter().flat_map(|&i| i.to_le_bytes()).collect();
            let mut hasher = Keccak::v256();
            hasher.update(&bytes);
            let mut out = [0u8; 32];
            hasher.finalize(&mut out);
            out
        };
        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        assert!(Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full()
        )
        .is_ok());
        for refused in [
            Plonky3Adapter::verify(&envelope, &pi, &program),
            Plonky3Adapter::verify_with_activation(
                &envelope,
                &pi,
                &program,
                bud_isa::MainnetActivation::default(),
            ),
        ] {
            match refused {
                Err(VerifyError::InvalidEnvelope(msg)) => {
                    assert!(
                        msg.contains("VerifyMerkle"),
                        "the error names the opcode: {msg}"
                    );
                }
                other => panic!("VerifyMerkle must be refused by default, got {other:?}"),
            }
        }

        // One opcode on does not turn the other on.
        let only_inference = bud_isa::MainnetActivation {
            verify_inference_enabled: true,
            ..bud_isa::MainnetActivation::default()
        };
        assert!(matches!(
            Plonky3Adapter::verify_with_activation(&envelope, &pi, &program, only_inference),
            Err(VerifyError::InvalidEnvelope(_))
        ));

        // VerifyInference: no expansion rows are needed to reach the gate.
        let program = vec![
            inst(Opcode::VerifyInference, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(16);
        assert!(vm.run_receipt(&program).success);
        let bytes: Vec<u8> = program.iter().flat_map(|&i| i.to_le_bytes()).collect();
        let mut hasher = Keccak::v256();
        hasher.update(&bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);
        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        // The opcode is reserved: with every opcode activated the activation
        // gate lets it through and the AIR refuses the proof.
        let full = Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full(),
        );
        assert!(
            full.is_err() && !matches!(full, Err(VerifyError::InvalidEnvelope(_))),
            "a reserved VerifyInference must be refused by the AIR, got {full:?}"
        );
        match Plonky3Adapter::verify(&envelope, &pi, &program) {
            Err(VerifyError::InvalidEnvelope(msg)) => {
                assert!(
                    msg.contains("VerifyInference"),
                    "the error names the opcode: {msg}"
                );
            }
            other => panic!("VerifyInference must be refused by default, got {other:?}"),
        }
    }

    /// A row that falls through must land on the next instruction, not on
    /// one the prover picks.
    ///
    /// The only link between consecutive rows is `nxt_pc == next_pc`, and
    /// `next_pc` was constrained for jumps, calls, `Ret`, `Push`, `Pop` and
    /// `Halt` only. Every other opcode left it free, so a `Load` could claim
    /// its successor sits at pc 2 and the row for pc 1 was never executed.
    ///
    /// Here the program is `Load r1 = 0; Assert r1; Halt`, which the VM
    /// refuses at the `Assert`. The forgery drops that step: the `Load` row
    /// names pc 2 as its successor and the terminal row sits at pc 2. The
    /// Program CTL is satisfied because both rows match real instructions, and
    /// the gas claimed is the honest figure minus the skipped `Assert`.
    #[test]
    fn rejects_a_fall_through_that_skips_an_instruction() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 0),
            inst(Opcode::Assert, 0, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(!receipt.success, "the honest run fails at the Assert");
        assert_eq!(vm.trace.len(), 2, "a Load row and the terminal row");

        let assert_gas = Vm::gas_cost(Opcode::Assert);
        let mut trace = vm.trace.clone();
        trace[0].next_pc = 2;
        trace[1].pc = 2;
        trace[1].next_pc = 2;

        let verdict = verify_forged_trace(&program, &trace, vm.gas_limit, vm.gas_used - assert_gas);
        assert!(
            verdict.is_err(),
            "a Load that claimed its successor sits two instructions on \
             verified: the Assert in between was never executed and the \
             proof says the program completed. verdict={verdict:?}"
        );
    }

    /// A `VerifyMerkle` with no expansion rows after it proves nothing.
    ///
    /// The root comparison lives on the original row and the only thing that
    /// ties its `merkle_current` to a walked path is the expansion block that
    /// follows. Leave the block out and the cell is the prover's to write: it
    /// is set to the claimed root, the comparison holds, and `rd` is 1.
    #[test]
    fn rejects_verify_merkle_without_expansion_rows() {
        let (program, vm) = merkle_one_depth_run();
        let mut trace = vm.trace.clone();
        trace.drain(1..65);
        trace[0].next_pc = 1;
        assert_eq!(trace[0].dst_val, 1, "the claim being forged is a pass");

        let verdict = verify_forged_trace(&program, &trace, vm.gas_limit, vm.gas_used);
        assert!(
            verdict.is_err(),
            "a VerifyMerkle row with no expansion block verified: its result \
             was never derived from a path. verdict={verdict:?}"
        );
    }

    /// A path that stops after its first round proves membership under a
    /// root only one hash deep.
    ///
    /// The key is zero, so every direction bit is zero and the shortened walk
    /// satisfies every per-row rule: round 0 is followed by a row that is not
    /// an expansion, which the terminator treats as the end of the path. The
    /// claimed root is the round-0 output, so the comparison holds.
    #[test]
    fn rejects_verify_merkle_that_stops_early() {
        let (program, vm) = merkle_one_depth_run();
        let mut trace = vm.trace.clone();
        trace.drain(2..65);
        trace[1].next_pc = 1;
        rechain_merkle_trace(&mut trace);
        assert_eq!(trace.len(), 3, "original row, round 0, Halt");

        let verdict = verify_forged_trace(&program, &trace, vm.gas_limit, vm.gas_used);
        assert!(
            verdict.is_err(),
            "a Merkle path cut to one round verified against a root one hash \
             deep. verdict={verdict:?}"
        );
    }

    /// The path buffer address may not move between rows of one path.
    ///
    /// Each expansion row's memory address is `imm + 8 + 8 * round`, and `imm`
    /// on an expansion row is exempt from the program table, so nothing tied
    /// it to the instruction's. Round 0 here reads the word round 1 reads, one
    /// slot over, and the root is recomputed from what it found there: the
    /// walk is over words the program laid out, but not along the path the
    /// instruction names.
    #[test]
    fn rejects_verify_merkle_with_a_shifted_sibling_address() {
        let (program, vm) = merkle_one_depth_run();
        let mut trace = vm.trace.clone();
        let shifted = trace[1].memory_addr.unwrap() + 8;
        let mut word = [0u8; 8];
        word.copy_from_slice(&vm.memory[shifted..shifted + 8]);
        let word = u64::from_le_bytes(word);
        trace[1].instruction.imm += 8;
        trace[1].memory_addr = Some(shifted);
        trace[1].memory_val = Some(word);
        trace[1].merkle_sibling = Some(word);
        rechain_merkle_trace(&mut trace);
        assert_ne!(word, 1, "round 0 must now read a different word");

        let verdict = verify_forged_trace(&program, &trace, vm.gas_limit, vm.gas_used);
        assert!(
            verdict.is_err(),
            "an expansion row whose address was shifted off the instruction's \
             path buffer verified. verdict={verdict:?}"
        );
    }

    /// A `VerifyMerkle` expansion row cannot stand alone.
    ///
    /// An expansion row is exempt from the program lookup, the register
    /// argument and the gas charge, and nothing required it to belong to an
    /// original `VerifyMerkle` row before it or to a path that runs its 64
    /// rounds. The program here has no 0x1E in it. Its `Store` row is
    /// replaced by a lone expansion row: the row for that pc is no longer
    /// matched against the program, the register file is not asked about it,
    /// and the store never happens. The proof still says the program ran to
    /// the end, at the honest gas minus the skipped store.
    #[test]
    fn rejects_a_stray_merkle_expansion_row_that_stores() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Load, 2, 0, 0, 16),
            inst(Opcode::Store, 0, 2, 1, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.trace.len(), 4);
        assert_eq!(vm.trace[2].instruction.opcode, Opcode::Store);

        let mut trace = vm.trace.clone();
        let sibling = 5u64;
        // The expansion block reads the value the previous non-expansion row
        // carries; give it the one this round produces.
        trace[1].merkle_current = Some(bud_vm::merkle_poseidon_round(0, sibling));
        let imm = 16;
        let stray = &mut trace[2];
        stray.instruction = Instruction {
            opcode: Opcode::VerifyMerkle,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm,
        };
        stray.src1_idx = 0;
        stray.src2_idx = 0;
        stray.dst_idx = 0;
        stray.src1_val = 0;
        stray.src2_val = 0;
        stray.dst_val = 0;
        stray.memory_addr = Some(imm as usize + 8);
        stray.memory_val = Some(sibling);
        stray.is_memory_write = false;
        stray.merkle_key = Some(0);
        stray.merkle_current = Some(0);
        stray.merkle_sibling = Some(sibling);
        stray.merkle_round = Some(0);
        stray.merkle_is_expand = true;

        let store_gas = Vm::gas_cost(Opcode::Store);
        let verdict = verify_forged_trace(&program, &trace, vm.gas_limit, vm.gas_used - store_gas);
        assert!(
            verdict.is_err(),
            "a lone Merkle expansion row stood in for a Store and the proof \
             verified: an instruction of the program was never executed. \
             verdict={verdict:?}"
        );
    }

    /// `Assert` must accept any non-zero condition, as the VM does.
    ///
    /// The VM halts only when the condition is zero. The AIR asked for
    /// `assert_one(rs1_val)`, which demands exactly 1, and the two agree only
    /// on the values every existing test used: `0` and `1`, which is what
    /// `Eq` and the comparisons produce. BudL's `constrain(...)` lowers to
    /// this opcode, so `constrain(flags & MASK)` was a contract the VM ran and
    /// no prover could prove.
    ///
    /// Completeness, not soundness: the AIR was stricter, so nothing false got
    /// through. Correct programs were rejected, which reads as broken tooling
    /// rather than as an attack, and is the reason it survived.
    #[test]
    fn proves_assert_on_conditions_that_are_not_one() {
        for cond in [1u64, 2, 7, 0xFFFF, 18_446_744_069_414_584_320] {
            let program = vec![
                inst(Opcode::Assert, 0, 1, 0, 0),
                inst(Opcode::Halt, 0, 0, 0, 0),
            ];
            let mut vm = Vm::new(64);
            vm.registers[1] = cond;
            let receipt = vm.run_receipt(&program);
            assert!(
                receipt.success,
                "the VM accepts any non-zero condition, including {cond}"
            );

            prove_and_verify(program, move |vm| {
                vm.registers[1] = cond;
            });
        }
    }

    /// An `Assert` on a zero condition must still be unprovable.
    ///
    /// The soundness half of the same column. Relaxing `assert_one(rs1)` to
    /// "non-zero" must not relax it to "anything": a prover that writes a
    /// witness claiming the condition was non-zero when it was zero is
    /// claiming an assertion held that did not.
    #[test]
    fn rejects_an_assert_that_claims_zero_is_non_zero() {
        // The VM refuses to run this, so the trace is built from a passing
        // program and the condition is zeroed afterwards, which is exactly
        // what a prover forging a failed assertion would do.
        let program = vec![
            inst(Opcode::Assert, 0, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        vm.registers[1] = 1;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: crate::event_digest_from_events(&receipt.events),
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);

        let mut assert_row = None;
        for i in 0..n_cpu {
            if matrix.values[i * TRACE_WIDTH + COL_IS_ASSERT].as_canonical_u64() == 1 {
                assert_row = Some(i);
                break;
            }
        }
        let assert_row = assert_row.expect("the trace must contain an Assert row");
        let at = assert_row * TRACE_WIDTH;

        // The condition becomes zero, so the assertion did not hold. The
        // witness is left as it was, claiming otherwise.
        matrix.values[at + COL_RS1_VAL] = Goldilocks::new(0);

        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);
        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "an Assert on a zero condition verified; relaxing the rule from \
             `== 1` to `!= 0` must not relax it to `anything`"
        );
    }

    /// A comparison cannot be answered from a non-canonical bit string.
    ///
    /// `Lt`, `Gt`, `Lte`, `Gte`, `And`, `Or` and `Xor` read the 64 bit columns
    /// rather than the register value. The only thing tying the two together
    /// was booleanity plus `sum(b_i * 2^i) == rs_val`, and that is satisfied by
    /// two different bit strings for every value below `2^32 - 1`, because
    /// Goldilocks is `2^64 - 2^32 + 1` and a 64 bit pattern can wrap.
    ///
    /// Here `rs1 = 5` and `rs2 = 100`, so the honest answer to `Lt` is 1. The
    /// forgery rewrites `rs1`'s bits as `5 + P = 0xFFFFFFFF00000006`, which
    /// reconstitutes to the same field element and sets the top bit, so the
    /// bitwise comparison reads 5 as the larger operand and answers 0. A
    /// contract checking `balance >= amount` through any of these opcodes has
    /// a check the prover decides.
    #[test]
    fn rejects_a_comparison_read_from_a_wrapped_bit_string() {
        const P: u64 = 18_446_744_069_414_584_321;

        // r1 = 5; r2 = 100; r3 = (r1 < r2). The honest result is 1.
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 5),
            inst(Opcode::Load, 2, 0, 0, 100),
            inst(Opcode::Lt, 3, 1, 2, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.registers[3], 1, "5 < 100 honestly answers 1");

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: crate::event_digest_from_events(&receipt.events),
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);

        let mut lt_row = None;
        for i in 0..n_cpu {
            if matrix.values[i * TRACE_WIDTH + COL_IS_LT].as_canonical_u64() == 1 {
                lt_row = Some(i);
                break;
            }
        }
        let lt_row = lt_row.expect("the trace must contain an Lt row");
        let at = lt_row * TRACE_WIDTH;

        // The second representation of 5. Reconstitutes to the same field
        // element, so `sum(b_i * 2^i) == rs1_val` still holds.
        let wrapped = 5u64.wrapping_add(P);
        assert_eq!(
            (wrapped as u128) % (P as u128),
            5,
            "the wrapped pattern must be the same field element, otherwise the \
             test is exercising a different hole"
        );
        for i in 0..64 {
            matrix.values[at + COL_CMP_RS1_BASE + i] = Goldilocks::new((wrapped >> i) & 1);
        }

        // The equality prefix flags and the result follow the bits the
        // comparison actually reads, so the forged row is internally
        // consistent about answering 0.
        let b = 100u64;
        let mut eq = true;
        for i in (0..64).rev() {
            eq = eq && (((wrapped >> i) & 1) == ((b >> i) & 1));
            matrix.values[at + COL_CMP_EQ_BASE + i] = Goldilocks::new(u64::from(eq));
        }
        matrix.values[at + COL_RD_VAL_NEW] = Goldilocks::new(0);

        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);
        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a comparison answered from a wrapped bit string verified; every \
             value below 2^32 has a second representation, so a balance check \
             written with Lt is a check the prover decides"
        );
    }

    /// Comparisons across the whole range must still be provable.
    ///
    /// The completeness half. Canonicity is enforced by excluding the patterns
    /// with a saturated high half and a nonzero low half, and the value one
    /// below the modulus sits right against that boundary: its high half *is*
    /// saturated and its low half is zero, so it must be accepted. Writing the
    /// rule as "the high half is never saturated" would have been simpler and
    /// would have made that value unprovable.
    #[test]
    fn proves_comparisons_at_the_edge_of_the_field() {
        const P: u64 = 18_446_744_069_414_584_321;
        for (a, b) in [
            (0u64, 1u64),
            (5, 100),
            (P - 1, 1),
            (1, P - 1),
            (P - 1, P - 1),
        ] {
            let program = vec![inst(Opcode::Lt, 3, 1, 2, 0), inst(Opcode::Halt, 0, 0, 0, 0)];
            let mut vm = Vm::new(64);
            vm.registers[1] = a;
            vm.registers[2] = b;
            let receipt = vm.run_receipt(&program);
            assert!(receipt.success, "Lt on ({a}, {b}) must execute");

            prove_and_verify(program, move |vm| {
                vm.registers[1] = a;
                vm.registers[2] = b;
            });
        }
    }

    /// A prover cannot announce events the program never emitted.
    ///
    /// `COL_EVENT_DIGEST_0` accumulates the `rs1` of every `Log` row. The only
    /// constraints on it were the transition, which fixes differences between
    /// consecutive rows, and the last-row binding to `public_inputs[40]`.
    /// Nothing fixed where the sequence started, so the whole thing could
    /// slide: write `D` on the first row, every relative step still holds, and
    /// the last row carries `D + sum(logged)`. The proof then states an
    /// `event_digest` for events that were never emitted.
    ///
    /// The field carries the replay context for storage challenges, so a
    /// prover choosing it is a prover choosing which challenge a shard proof
    /// answers.
    #[test]
    fn rejects_a_shifted_event_digest() {
        // r1 = 5; Log r1; Halt. The honest digest is 5.
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 5),
            inst(Opcode::Log, 0, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(receipt.events, vec![5], "the honest run logs exactly one 5");

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        // The forged public inputs announce a digest the program did not
        // produce. `D` is what the prover adds to the first row.
        const D: u64 = 0xDEAD_BEEF;
        let mut event_digest = [0u8; 32];
        event_digest[0..8].copy_from_slice(&(5u64 + D).to_le_bytes());

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest,
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        let rows = matrix.values.len() / TRACE_WIDTH;

        // Slide the whole accumulator by D. Every transition still holds
        // because each one only constrains a difference.
        for i in 0..rows {
            let at = i * TRACE_WIDTH + COL_EVENT_DIGEST_0;
            matrix.values[at] += Goldilocks::new(D);
        }
        assert_eq!(
            matrix.values[(n_cpu - 1) * TRACE_WIDTH + COL_EVENT_DIGEST_0].as_canonical_u64(),
            5 + D,
            "the slid trace must reach the forged digest, otherwise the test \
             is not exercising the hole"
        );

        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);
        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a proof announcing an event digest the program never produced \
             verified; the field carries the replay context for storage \
             challenges, so choosing it chooses which challenge a proof answers"
        );
    }

    /// A program whose very first instruction is a `Log` must still be
    /// provable.
    ///
    /// The completeness half. Pinning the first row cannot be written as
    /// "the accumulator is zero there": the prover folds the first row's own
    /// `Log` into it, so a program that logs immediately starts at `rs1`, not
    /// at zero. The constraint has to say `digest == is_log * rs1`, and this
    /// test is what tells the two apart.
    #[test]
    fn proves_a_program_that_logs_on_its_first_instruction() {
        // The seeded register means row 0 is the Log itself.
        let program = vec![
            inst(Opcode::Log, 0, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        vm.registers[1] = 9;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(receipt.events, vec![9]);

        // Not `prove_and_verify`: that helper hard-codes
        // `event_digest: [0u8; 32]`, which is only correct for programs that
        // emit nothing. Using it here would fail on the last-row digest
        // binding and say nothing about the first-row constraint this test
        // exists for.
        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: vm.context.sender,
            nonce: vm.context.nonce,
            block_height: vm.context.block_height,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: crate::event_digest_from_events(&receipt.events),
            state_writes_digest: [0u8; 32],
        };

        let envelope =
            Plonky3Adapter::prove(&vm.trace, &pi, &program).expect("the honest proof must build");
        Plonky3Adapter::verify(&envelope, &pi, &program).expect(
            "a program whose first instruction is a Log must be provable; the \
             first-row constraint has to read `is_log * rs1`, not zero, \
             because the prover folds row zero's own Log into the accumulator",
        );
    }

    /// A proof claiming an absurd degree must be rejected, not abort the node.
    ///
    /// `Proof::degree_bits` is deserialized out of the submitted bytes and was
    /// fed straight into `1 << degree_bits`. The release profile sets
    /// `overflow-checks = true` and `panic = "abort"`, so a shift past the word
    /// width is a remote kill switch on any node that accepts proofs, reached
    /// by flipping bytes rather than by producing anything valid.
    ///
    /// The envelope carries a separate `degree_bits` that the caller bounds against
    /// `MAX_DEGREE_BITS`. This is the other one, inside the serialized proof,
    /// and nothing compared them. The test drives the crate's own entry point
    /// so it covers every caller rather than the one that remembered to check.
    ///
    /// Found by CI on an unrelated branch: a fixed test that flips one byte of
    /// a real proof started landing on this field once the transcript changed
    /// the proof's byte layout. The panic was always reachable; which byte
    /// reaches it is not stable.
    /// Are the verifier's shape checks really a gate.
    ///
    /// `verify_with_preprocessed` checks that the proof's opened values are of
    /// the expected width (`valid_shape`) and refuses anything that does not
    /// match with `InvalidProofShape`. These checks cover the areas the proof
    /// system does **not** constrain: the PCS verifies openings at the given
    /// points, not the length of a vector. So this is the boundary the
    /// verifier has to hold in its own code - and this is exactly the most
    /// common zkVM vulnerability class in the literature (a verifier trusting
    /// the circuit and skipping its own check).
    ///
    /// The 652-line `bud_stark/verifier.rs` was running on the production path
    /// with not a single test. This test puts the first gate on that surface:
    /// an honest proof passes, and four proofs each with one corrupted field
    /// are refused.
    #[test]
    fn verifier_shape_checks_reject_malformed_openings() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program)
            .expect("an honest proof must be produced");

        // Control group. If this does not pass, the refusals below would be
        // owed to a setup error rather than to the attack.
        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_ok(),
            "an honest proof must verify: the setup is broken"
        );

        let base: crate::bud_stark::Proof<MyConfig> =
            postcard::from_bytes(&envelope.proof_bytes).expect("the real proof must decode");

        // Each corrupts a single field. All of them must land on
        // `InvalidProofShape` through `valid_shape`.
        let mutations: Vec<(&str, ProofMutation)> = vec![
            (
                "trace_local kisaltildi",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    p.opened_values.trace_local.pop();
                }),
            ),
            (
                "trace_local uzatildi",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    let v = p.opened_values.trace_local[0];
                    p.opened_values.trace_local.push(v);
                }),
            ),
            (
                "quotient chunk dropped",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    p.opened_values.quotient_chunks.pop();
                }),
            ),
            (
                "yardimci iz acilisi silindi",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    p.opened_values.aux_trace_local = None;
                }),
            ),
            (
                "quotient chunk extended",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    let v = p.opened_values.quotient_chunks[0][0];
                    p.opened_values.quotient_chunks[0].push(v);
                }),
            ),
            (
                "quotient chunk shortened",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    p.opened_values.quotient_chunks[0].pop();
                }),
            ),
            (
                "extra quotient chunk added",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    let extra = p.opened_values.quotient_chunks[0].clone();
                    p.opened_values.quotient_chunks.push(extra);
                }),
            ),
            (
                "aux opening shortened",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    if let Some(aux) = p.opened_values.aux_trace_local.as_mut() {
                        aux.pop();
                    }
                }),
            ),
            (
                "aux opening extended",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    if let Some(aux) = p.opened_values.aux_trace_local.as_mut() {
                        let v = aux[0];
                        aux.push(v);
                    }
                }),
            ),
            (
                "aux trace commitment and openings stripped together (P15-F01)",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    p.commitments.aux_trace = None;
                    p.opened_values.aux_trace_local = None;
                    p.opened_values.aux_trace_next = None;
                }),
            ),
        ];

        for (ad, mutate) in mutations {
            let mut forged_proof = base.clone();
            mutate(&mut forged_proof);
            let forged = ProofEnvelope {
                proof_bytes: postcard::to_allocvec(&forged_proof).unwrap(),
                ..envelope.clone()
            };
            assert!(
                Plonky3Adapter::verify(&forged, &pi, &program).is_err(),
                "a malformed-shape proof verified ({ad})"
            );

            // The adapter flattens every error into `InvalidProof`, so the
            // assertion above says "it was refused" but not **why** it was
            // refused - a cryptographic verification failure would give the
            // same answer. The verifier is called directly so that the refusal
            // is measured to really come from the shape gate. Without that
            // distinction the test stayed green even with the shape check
            // removed entirely - measured, and it did.
            let air_p = BudAir {
                num_steps: vm.trace.len(),
                program: program.clone(),
            };
            let cfg_p = build_config();
            let pv_p = to_public_values(&pi);
            let pp_p = setup_preprocessed(&cfg_p, &air_p, forged_proof.degree_bits);
            let direct = crate::bud_stark::verify_with_preprocessed(
                &cfg_p,
                &air_p,
                &forged_proof,
                &pv_p,
                pp_p.as_ref().map(|(_, v)| v),
            );
            let reason = direct
                .as_ref()
                .err()
                .map(|e| format!("{e}"))
                .unwrap_or_else(|| "accepted".to_string());
            assert_eq!(
                reason, "invalid proof shape",
                "{ad}: the refusal did not come from the shape gate"
            );
        }
    }

    /// Strip the aux (LogUp) trace from an honest proof: the commitment and
    /// both openings together.
    ///
    /// This is the shape of P15-F01, but built from a proof that was made
    /// with the aux trace, so the PCS opening argument still covers it and
    /// the verifier must refuse. The forged shape, a proof that the prover
    /// built with no aux generator at all, is not tested here: it needs the
    /// verifier to take the aux flag from the AIR and not from the proof, and
    /// that fix is in `bud_stark/verifier.rs`. The reason of the refusal is
    /// not pinned, because it was not measured.
    #[test]
    fn rejects_a_proof_with_the_aux_trace_stripped() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let (envelope, pi) = prove_and_verify_full(program.clone(), |_| {});
        let mut stripped: crate::bud_stark::Proof<MyConfig> =
            postcard::from_bytes(&envelope.proof_bytes).expect("the real proof must decode");
        assert!(
            stripped.commitments.aux_trace.is_some(),
            "the honest proof must carry an aux commitment, or the strip proves nothing"
        );
        stripped.commitments.aux_trace = None;
        stripped.opened_values.aux_trace_local = None;
        stripped.opened_values.aux_trace_next = None;

        let forged = ProofEnvelope {
            proof_bytes: postcard::to_allocvec(&stripped).unwrap(),
            ..envelope.clone()
        };
        assert!(
            Plonky3Adapter::verify(&forged, &pi, &program).is_err(),
            "a proof with the aux commitment and openings removed verified"
        );
    }

    /// A proof with the right shape but corrupted **content** must be refused.
    ///
    /// `VerificationError` carries five variants and it was measured: four of them
    /// (`OodEvaluationMismatch`, `RandomizationError`, `InvalidOpeningArgument`,
    /// `NextPointUnavailable`) had no coverage in any test. The shape gate
    /// (`InvalidProofShape`) was tested, but that gate only screens a proof
    /// *formally*.
    ///
    /// This test changes an opened value without touching any length - that
    /// is, a proof that passes the shape gate and is merely wrong in its
    /// content. That is exactly what an attacker would produce.
    ///
    /// **The measured refusal path is `InvalidOpeningArgument`** (the FRI/PCS
    /// layer), not the `OodEvaluationMismatch` expected while the test was
    /// being written: when an opened value changes, the proof is screened out
    /// in PCS opening verification before it ever reaches the constraint
    /// check. The assertion was therefore framed as "refused for a reason
    /// other than shape"; pinning a specific error variant would encode an
    /// expectation written without measurement. The `OodEvaluationMismatch`
    /// path is still untested - reaching it requires producing a proof that is
    /// consistent with the PCS opening but breaks the constraint.
    #[test]
    fn rejects_a_proof_whose_openings_are_altered_without_changing_its_shape() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program)
            .expect("an honest proof must be produced");

        // Control group: if this does not pass, the refusal below would be
        // owed to a setup error rather than to the attack.
        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_ok(),
            "an honest proof must verify: the setup is broken"
        );

        let base: crate::bud_stark::Proof<MyConfig> =
            postcard::from_bytes(&envelope.proof_bytes).expect("the real proof must decode");

        // Mutations that leave the shape **intact**: the lengths are kept
        // exactly and the only change is an opened value itself. That way
        // `valid_shape` passes and the refusal has to come from the constraint
        // check.
        let mutations: Vec<(&str, ProofMutation)> = vec![
            (
                "a value of the trace opening was altered",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    p.opened_values.trace_local[0] += MyExtensionField::ONE;
                }),
            ),
            (
                "a value of the quotient chunk was altered",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    p.opened_values.quotient_chunks[0][0] += MyExtensionField::ONE;
                }),
            ),
        ];

        for (ad, mutate) in mutations {
            let mut forged_proof = base.clone();
            mutate(&mut forged_proof);

            let air_p = BudAir {
                num_steps: vm.trace.len(),
                program: program.clone(),
            };
            let cfg_p = build_config();
            let pv_p = to_public_values(&pi);
            let pp_p = setup_preprocessed(&cfg_p, &air_p, forged_proof.degree_bits);
            let direct = crate::bud_stark::verify_with_preprocessed(
                &cfg_p,
                &air_p,
                &forged_proof,
                &pv_p,
                pp_p.as_ref().map(|(_, v)| v),
            );

            let reason = direct
                .as_ref()
                .err()
                .map(|e| format!("{e}"))
                .unwrap_or_else(|| "accepted".to_string());
            assert_ne!(
                reason, "accepted",
                "{ad}: a content-corrupted proof verified"
            );
            // The refusal must not come from the **shape** gate: the shape
            // was preserved, so this refusal has to come from the
            // cryptographic check. If the shape answer shows up here the
            // mutation unintentionally broke a length and the test is
            // measuring shape again rather than soundness.
            assert_ne!(
                reason, "invalid proof shape",
                "{ad}: the refusal came from the shape gate; since the shape was \
                 preserved the refusal should have come from the cryptographic check"
            );
        }
    }

    /// **Every one** of the public inputs must invalidate the proof.
    ///
    /// The test was written to reach the `OodEvaluationMismatch` path (the
    /// constraint equation failing to hold at zeta) and the measurement showed
    /// something else:
    /// **when each of the 56 public input values is altered the refusal
    /// through `InvalidPowWitness`**, that is the FRI proof-of-work
    /// check - before the constraint check is ever reached.
    ///
    /// The reason is good news for the proof system: the public inputs enter
    /// the Fiat-Shamir transcript by absorption (`prover.rs` `observe_slice`,
    /// mirrored in `verifier.rs`). When one of them changes the whole challenge
    /// chain changes and the FRI queries do not hold. The binding is
    /// established in the transcript layer **before** the constraint layer;
    /// that is exactly the property the "Last Challenge Attack" class
    /// engellendigi yer tam burasi.
    ///
    /// The assertion therefore pins the **refusal** rather than a specific
    /// error variant: which layer catches it is an implementation detail, what
    /// must not change is that no public input is left free. Reaching
    /// `OodEvaluationMismatch` would require producing a forged proof that
    /// also keeps the transcript consistent - which cannot be done without
    /// breaking the proof system, and that is the desired
    /// property.
    ///
    /// That there are two independent layers was measured by mutation:
    ///
    /// * when `observe_slice(public_values)` is broken **partially** (by
    ///   dropping the last value) the test stays green - that value is bound
    ///   by the AIR constraint as well.
    /// * When the absorption is removed **entirely**, `public input 1` is left
    ///   free and the test goes red - that is, some values are bound only by the
    ///   transcript and not by the constraint layer.
    ///
    /// Together the two give full coverage; removing either opens a hole.
    /// That is also why the test walks each index separately: a single kind of coverage
    /// but comes from a different layer depending on the index.
    ///
    /// `Plonky3Adapter::verify` cannot measure this path: it screens the
    /// public inputs beforehand with its own hash. That is why the verifier is
    /// called directly.
    #[test]
    fn rejects_a_proof_for_every_altered_public_input() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program)
            .expect("an honest proof must be produced");
        let proof: crate::bud_stark::Proof<MyConfig> =
            postcard::from_bytes(&envelope.proof_bytes).expect("the real proof must decode");

        let air_p = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let cfg_p = build_config();
        let pp_p = setup_preprocessed(&cfg_p, &air_p, proof.degree_bits);

        // Control group: it must pass with the correct public inputs.
        let durust = to_public_values(&pi);
        assert!(
            crate::bud_stark::verify_with_preprocessed(
                &cfg_p,
                &air_p,
                &proof,
                &durust,
                pp_p.as_ref().map(|(_, v)| v),
            )
            .is_ok(),
            "an honest proof must verify: the setup is broken"
        );

        // The proof stays as is; only the public input presented to the
        // verifier changes. Each index is asserted **separately**: a single
        // bulk assertion would hide one index being entirely unbound beneath
        // the success of the others - the class of SP1's unconstrained
        // `committed_value_digest`.
        for i in 0..durust.len() {
            let mut bozuk = durust.clone();
            bozuk[i] += Goldilocks::ONE;

            let result = crate::bud_stark::verify_with_preprocessed(
                &cfg_p,
                &air_p,
                &proof,
                &bozuk,
                pp_p.as_ref().map(|(_, v)| v),
            );

            assert!(
                result.is_err(),
                "public input {i} was altered but the proof was still considered \
                 valid; that value is not bound to the proof"
            );
        }
    }

    /// The ZK flag and the randomness commitment in the proof must **agree**.
    ///
    /// `verifier.rs:363` checks this explicitly: with ZK on, randomness
    /// commitment must be present when it is on and absent when it is off.
    /// There was no test for it at all. If a mismatch were accepted, a proof
    /// with no randomness while ZK is on would silently lose the privacy
    /// claim.
    #[test]
    fn rejects_a_proof_whose_randomization_does_not_match_the_zk_setting() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program)
            .expect("an honest proof must be produced");
        let base: crate::bud_stark::Proof<MyConfig> =
            postcard::from_bytes(&envelope.proof_bytes).expect("the real proof must decode");

        let air_p = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let cfg_p = build_config();
        let pv_p = to_public_values(&pi);
        let pp_p = setup_preprocessed(&cfg_p, &air_p, base.degree_bits);

        // Control group: an untouched proof must pass.
        assert!(
            crate::bud_stark::verify_with_preprocessed(
                &cfg_p,
                &air_p,
                &base,
                &pv_p,
                pp_p.as_ref().map(|(_, v)| v),
            )
            .is_ok(),
            "an honest proof must verify: the setup is broken"
        );

        // Both directions are measured separately.
        //
        // Adding the commitment alone was not enough: a **second** place
        // inside `verifier.rs` also catches that case (`RandomizationError`
        // when the opened randomness value is missing), so the test stayed
        // green even with the first gate deleted entirely - measured. The
        // second case, which corrupts the `opened_values` side, exercises that
        // gate on its own.
        let vakalar: Vec<(&str, ProofMutation)> = vec![
            (
                "commitment present, opened value missing",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    p.commitments.random = Some(p.commitments.quotient_chunks.clone());
                    p.opened_values.random = None;
                }),
            ),
            (
                "opened value present, commitment missing",
                Box::new(|p: &mut crate::bud_stark::Proof<MyConfig>| {
                    p.commitments.random = None;
                    p.opened_values.random = Some(p.opened_values.quotient_chunks[0].clone());
                }),
            ),
        ];

        for (ad, boz) in vakalar {
            let mut forged = base.clone();
            boz(&mut forged);

            let reason = crate::bud_stark::verify_with_preprocessed(
                &cfg_p,
                &air_p,
                &forged,
                &pv_p,
                pp_p.as_ref().map(|(_, v)| v),
            )
            .err()
            .map(|e| format!("{e}"))
            .unwrap_or_else(|| "accepted".to_string());

            assert_eq!(
                reason, "randomization error: FRI batch randomization does not match ZK setting",
                "{ad}: randomness contradicting the ZK setting was not refused for the right reason"
            );
        }
    }

    #[test]
    fn rejects_a_proof_claiming_an_impossible_degree() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        // Start from a real proof so everything except the degree is
        // well-formed; a wholly random blob would be rejected by postcard
        // before the shift is reached and would prove nothing.
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program)
            .expect("the honest proof must be produced");
        let mut p3_proof: crate::bud_stark::Proof<MyConfig> =
            postcard::from_bytes(&envelope.proof_bytes).expect("a real proof must deserialize");

        // 255 is past the word width, so `1 << degree_bits` overflows.
        p3_proof.degree_bits = 255;
        let forged = ProofEnvelope {
            proof_bytes: postcard::to_allocvec(&p3_proof).unwrap(),
            ..envelope
        };

        assert!(
            Plonky3Adapter::verify(&forged, &pi, &program).is_err(),
            "a proof claiming 2^255 rows must be rejected; reaching the shift \
             aborts the process under the release profile, which turns a \
             corrupt proof into a way to stop a node"
        );
    }

    #[test]
    fn rejects_invalid_proof_bytes() {
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: [0u8; 32],
            proof_bytes: vec![1, 2, 3, 4],
            degree_bits: 4,
        };

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash: [0u8; 32],
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: 1000000,
            gas_used: 0,
            exit_code: 0,
            trace_len: 0,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let res = Plonky3Adapter::verify(&envelope, &pi, &[]);
        assert!(res.is_err());
    }

    /// Garbage bytes behind an envelope that passes every header, hash and
    /// program check must reach the proof decoder and be refused there.
    ///
    /// `rejects_invalid_proof_bytes` uses a zero public inputs hash, so it is
    /// refused before decoding starts and never tests the decoder.
    #[test]
    fn rejects_garbage_proof_bytes_behind_a_valid_envelope() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 42),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let (envelope, pi) = prove_and_verify_full(program.clone(), |_| {});
        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_ok(),
            "the untouched envelope must verify, or the refusals below prove nothing"
        );

        let honest = envelope.proof_bytes.clone();
        let garbage: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![1, 2, 3, 4],
            vec![0xFF; 512],
            (0..honest.len()).map(|i| (i * 31 % 251) as u8).collect(),
            honest[..honest.len() / 2].to_vec(),
        ];
        for bytes in garbage {
            let mut broken = envelope.clone();
            broken.proof_bytes = bytes;
            let res = Plonky3Adapter::verify(&broken, &pi, &program);
            assert!(
                matches!(
                    res,
                    Err(VerifyError::DeserializationError(_)) | Err(VerifyError::InvalidProof)
                ),
                "garbage proof bytes must fail in the decoder or the verifier, got {res:?}"
            );
        }
    }

    /// P15-F02: one proof has exactly one encoding. Bytes appended after a
    /// valid proof are refused, so the proof hash and the relay fingerprint
    /// cannot be varied without invalidating the proof.
    #[test]
    fn rejects_trailing_bytes_after_a_valid_proof() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 42),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let (envelope, pi) = prove_and_verify_full(program.clone(), |_| {});
        assert!(Plonky3Adapter::verify(&envelope, &pi, &program).is_ok());

        let mut padded = envelope.clone();
        padded.proof_bytes.push(0);
        let res = Plonky3Adapter::verify(&padded, &pi, &program);
        assert!(
            matches!(res, Err(VerifyError::DeserializationError(_))),
            "a trailing byte must be refused by the decoder, got {res:?}"
        );
    }

    #[test]
    fn rejects_tampered_public_inputs() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 42),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];

        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let initial_root = [0u8; 32];
        let final_root = [0u8; 32];
        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash: [0u8; 32],
            initial_state_root: initial_root,
            final_state_root: final_root,
            sender: 100, // Expected sender
            nonce: 5,
            block_height: 10,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        // Prover generates valid proof
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();

        // Verifier uses tampered public inputs (e.g. different sender)
        let mut tampered_pi = pi.clone();
        tampered_pi.sender = 999;
        assert!(matches!(
            Plonky3Adapter::verify(&envelope, &tampered_pi, &program),
            Err(VerifyError::PublicInputsMismatch)
        ));

        // Verifier uses different gas_used
        let mut tampered_pi = pi.clone();
        tampered_pi.gas_used = 12345;
        // This will mismatch the public input hash
        assert!(matches!(
            Plonky3Adapter::verify(&envelope, &tampered_pi, &program),
            Err(VerifyError::PublicInputsMismatch)
        ));
    }

    #[test]
    fn rejects_tampered_program() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 42),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];

        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let initial_root = [0u8; 32];
        let final_root = [0u8; 32];
        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash: [0u8; 32],
            initial_state_root: initial_root,
            final_state_root: final_root,
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();

        // Verifier attempts to verify with a different program
        let tampered_program = vec![
            inst(Opcode::Load, 1, 0, 0, 999), // Different loaded value
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];

        let res = Plonky3Adapter::verify(&envelope, &pi, &tampered_program);
        assert!(res.is_err());
    }

    #[test]
    fn proves_lt_comparison() {
        let program = vec![inst(Opcode::Lt, 1, 2, 3, 0), inst(Opcode::Halt, 0, 0, 0, 0)];
        prove_and_verify(program, |vm| {
            vm.registers[2] = 5;
            vm.registers[3] = 10;
        });
    }

    #[test]
    fn proves_gt_comparison() {
        let program = vec![inst(Opcode::Gt, 1, 2, 3, 0), inst(Opcode::Halt, 0, 0, 0, 0)];
        prove_and_verify(program, |vm| {
            vm.registers[2] = 10;
            vm.registers[3] = 5;
        });
    }

    #[test]
    fn proves_lte_gte_edge() {
        let program = vec![
            inst(Opcode::Lte, 1, 2, 3, 0),
            inst(Opcode::Gte, 4, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = 7;
            vm.registers[3] = 7;
        });
    }

    #[test]
    fn proves_all_comparisons() {
        let program = vec![
            inst(Opcode::Lt, 1, 2, 3, 0),  // 5 < 10 -> 1
            inst(Opcode::Gt, 2, 2, 3, 0),  // 5 > 10 -> 0
            inst(Opcode::Lte, 3, 2, 3, 0), // 5 <= 10 -> 1
            inst(Opcode::Gte, 4, 2, 3, 0), // 5 >= 10 -> 0
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = 5;
            vm.registers[3] = 10;
        });
    }

    #[test]
    fn proves_bitwise_and() {
        let program = vec![
            inst(Opcode::And, 1, 2, 3, 0), // 0b1100 & 0b1010 = 0b1000 = 8
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = 0b1100;
            vm.registers[3] = 0b1010;
        });
    }

    /// The opcode slots `Or` and `Xor` used to occupy must not decode.
    ///
    /// Removed: results can leave the field.
    /// `(P-1) | (P-2) = 2^64 - 1`, which is above the modulus, and a register
    /// holding that has no canonical bit decomposition, so any later
    /// comparison on it is unprovable. `And` cannot do this, since its result
    /// is at most the smaller operand.
    ///
    /// Removing an opcode is only real if the encoding stops accepting it.
    /// Leaving `0x07` and `0x08` decodable would keep them reachable from
    /// hand-written bytecode while the AIR no longer constrains them, which is
    /// strictly worse than having left them in.
    #[test]
    fn rejects_the_withdrawn_bitwise_opcodes() {
        for slot in [0x07u64, 0x08] {
            assert!(
                bud_isa::Instruction::decode_any(slot).is_err(),
                "opcode {slot:#04x} still decodes; it was withdrawn because its \
                 result can exceed the modulus, and an opcode the AIR does not \
                 constrain must not be reachable"
            );
        }
        // The neighbours are untouched, so this is not testing that decoding
        // is broken in general.
        assert!(
            bud_isa::Instruction::decode_any(0x06).is_ok(),
            "And must still decode"
        );
        assert!(
            bud_isa::Instruction::decode_any(0x09).is_ok(),
            "Not must still decode"
        );
    }

    #[test]
    fn proves_logical_not() {
        // Not(0) = 1
        let program = vec![
            inst(Opcode::Not, 1, 2, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = 0;
        });
    }

    #[test]
    fn proves_logical_not_nonzero() {
        // Not(nonzero) = 0
        let program = vec![
            inst(Opcode::Not, 1, 2, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = 42;
        });
    }

    #[test]
    fn proves_poseidon_hash() {
        let program = vec![
            inst(Opcode::Poseidon, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = 42;
            vm.registers[3] = 7;
        });
    }

    ///: PrivacyCommit Poseidon3 binding proves + verifies.
    #[test]
    fn d2_proves_privacy_commit() {
        let amount = 100u64;
        let recipient = 7u64;
        let blinding: i32 = 99;
        let program = vec![
            inst(Opcode::PrivacyCommit, 1, 2, 3, blinding),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = amount;
            vm.registers[3] = recipient;
        });
    }

    /// HIGH (CWE-682, 2026-08-17) regression: a negative imm, with the
    /// VM layout poseidon4_hash3(amount=rs1, blinding=rs2, recipient=imm). The
    /// old witness truncated imm to u32 and called it "blinding"; with a
    /// negative imm the proof does not prove the commitment the VM computed
    /// (u32 truncate = 2^32-5, i64 -> u64 = 2^64-5). This test forces a round
    /// trip on large/negative imm.
    #[test]
    fn d2_proves_privacy_commit_negative_imm() {
        let amount = 100u64;
        let recipient = 7u64;
        let blinding: i32 = -5;
        let program = vec![
            inst(Opcode::PrivacyCommit, 1, 2, 3, blinding),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = amount;
            vm.registers[3] = recipient;
        });
    }

    /// HIGH (2026-08-17): normalization must not panic on an i32::MIN imm.
    /// -imm overflows i32; unsigned_abs() returns |-2^31| = 2^31.
    #[test]
    fn d2_proves_privacy_commit_i32_min_imm() {
        let amount = 1u64;
        let recipient = 2u64;
        let blinding: i32 = i32::MIN;
        let program = vec![
            inst(Opcode::PrivacyCommit, 1, 2, 3, blinding),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = amount;
            vm.registers[3] = recipient;
        });
    }

    /// NullifierCheck accepts matching secret under AIR constraints.
    #[test]
    fn d2_proves_nullifier_check_valid() {
        let secret = 0xA11CEu64;
        let nullifier = bud_vm::poseidon4_hash(secret, bud_vm::DOMAIN_NULLIFIER);
        let program = vec![
            inst(Opcode::NullifierCheck, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = nullifier;
            vm.registers[3] = secret;
        });
    }

    /// NullifierCheck rejects wrong secret (rd=0) and still proves.
    #[test]
    fn d2_proves_nullifier_check_invalid_secret() {
        let secret = 0xA11CEu64;
        let nullifier = bud_vm::poseidon4_hash(secret, bud_vm::DOMAIN_NULLIFIER);
        let program = vec![
            inst(Opcode::NullifierCheck, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = nullifier;
            vm.registers[3] = secret ^ 1;
        });
    }

    /// SumConservation equal / unequal.
    #[test]
    fn d2_proves_sum_conservation() {
        let program = vec![
            inst(Opcode::SumConservation, 1, 2, 3, 0), // equal
            inst(Opcode::SumConservation, 4, 2, 5, 0), // unequal
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = 50;
            vm.registers[3] = 50;
            vm.registers[5] = 49;
        });
    }

    /// E2E private-transfer skeleton -
    /// Commit inputs/outputs + nullifier ownership + sum conservation.
    #[test]
    fn d2_proves_private_transfer_e2e() {
        let amount_in = 100u64;
        let amount_out = 100u64;
        let recipient = 0xB0Bu64;
        let blinding_in: i32 = 11;
        let blinding_out: i32 = 22;
        let secret = 0x5EC2EFu64;
        let nullifier = bud_vm::poseidon4_hash(secret, bud_vm::DOMAIN_NULLIFIER);

        let program = vec![
            // R1 = commit(in)
            inst(Opcode::PrivacyCommit, 1, 2, 3, blinding_in),
            // R4 = commit(out)
            inst(Opcode::PrivacyCommit, 4, 5, 6, blinding_out),
            // R7 = nullifier check
            inst(Opcode::NullifierCheck, 7, 8, 9, 0),
            // R10 = sum conservation (amount_in == amount_out)
            inst(Opcode::SumConservation, 10, 2, 5, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = amount_in;
            vm.registers[3] = 0xA11Cu64; // old owner tag (private)
            vm.registers[5] = amount_out;
            vm.registers[6] = recipient;
            vm.registers[8] = nullifier;
            vm.registers[9] = secret;
        });
    }

    #[test]
    fn proves_storage_write_read() {
        let program = vec![
            inst(Opcode::SWrite, 0, 1, 0, 5), // storage[5] = r1(=99)
            inst(Opcode::SRead, 2, 0, 0, 5),  // r2 = storage[5]
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[1] = 99;
        });
    }

    #[test]
    fn proves_dynamic_storage_slot_write_read() {
        let program = vec![
            inst(Opcode::SWrite, 0, 1, 2, -1), // storage[r2] = r1(=99)
            inst(Opcode::SRead, 3, 0, 2, -1),  // r3 = storage[r2]
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[1] = 99;
            vm.registers[2] = 0xDEAD_BEEFu64;
        });
    }

    /// A **negative** constant slot is one field element everywhere: the key
    /// the VM writes its storage map with, the address the prover puts in the
    /// memory table, and the `COL_IMM` the AIR reads the slot from. Encoded as
    /// the i64 two's complement (`2^64 - |imm|`) the honest trace could never
    /// be proven: the memory LogUp had no matching row and the `SWrite` gadget
    /// bound the wrong slot.
    #[test]
    fn proves_a_negative_constant_storage_slot() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 777),
            inst(Opcode::SWrite, 0, 1, 0, -5), // storage[-5] = r1
            inst(Opcode::SRead, 2, 0, 0, -5),  // r2 = storage[-5]
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the negative-slot run must succeed");
        assert_eq!(vm.registers[2], 777);
        let canonical = bud_vm::GOLDILOCKS_P - 5;
        assert_eq!(bud_vm::constant_storage_slot(-5), canonical);
        assert_eq!(
            vm.storage.get(&canonical),
            Some(&777),
            "the VM must key storage by the canonical field element the AIR proves"
        );
        assert!(
            !vm.storage.contains_key(&(-5i64 as u64)),
            "the two's-complement encoding must not be used"
        );
        prove_and_verify(program, |_| {});
    }

    #[test]
    fn proves_storage_multiple_slots() {
        let program = vec![
            inst(Opcode::SWrite, 0, 1, 0, 1), // storage[1] = r1(=10)
            inst(Opcode::SWrite, 0, 2, 0, 2), // storage[2] = r2(=20)
            inst(Opcode::SRead, 3, 0, 0, 1),  // r3 = storage[1]
            inst(Opcode::SRead, 4, 0, 0, 2),  // r4 = storage[2]
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[1] = 10;
            vm.registers[2] = 20;
        });
    }

    #[test]
    fn proves_storage_read_default_zero() {
        let program = vec![
            inst(Opcode::SRead, 1, 0, 0, 99), // r1 = storage[99] (should be 0)
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |_| {});
    }

    // --- (security audit) security audit
    //
    // The ZK soundness of the `VerifyMerkle` opcode (0x1E) has two layers:
    //
    //   (a) **Selector binding (partial fix).** The prover can no
    //       Longer set `is_verify_merkle = 0` on a row where
    //       `COL_OPCODE = 0x1E` - the AIR forces
    //       `is_verify_merkle * (opcode - 0x1E) = 0`. This closes the
    //       Trivial "set the selector to 0 and pick any rd_val_new" attack.
    //
    //   (b) **Path verification (implemented).** The path is recomputed
    //       In-circuit over expansion rows: the sibling and direction bit
    //       Of each round are witness columns, the Poseidon chain is
    //       Constrained round by round, and `COL_MERKLE_KEY_REM` ties the
    //       Direction bits to `merkle_key` through the shift chain
    //       `rem == 2 * rem' + bit` (terminating at zero, which also pins
    //       The key to 64 bits). The sibling values are bound to the
    //       Memory they were read from by the LogUp memory argument, so a
    //       Prover cannot substitute a path it never loaded. See
    //       `plonky3_air.rs` around `COL_MERKLE_KEY_REM` for the
    //       Constraints and `budzero/docs/BudL_SPEC.md` ("VerifyMerkle
    //       Soundness") for the argument.
    //
    //   (c) **Binding the path's result to the root.** (a) and (b) were
    //       long considered sufficient, and they were not. The chain was
    //       computed correctly row by row and **where it arrived was bound
    //       to nothing**: the root comparison looks at the original row's
    //       `merkle_current` cell, and no constraint forced the round-64
    //       output to be written into that cell. Without touching the
    //       expansion rows at all, a prover writing the claimed root itself
    //       into the original row produced a proof that verified - it was
    //       measured, and it did. `COL_MERKLE_FINAL_FLAG` now carries the
    //       expected value through the expansion and its equality with the
    //       output produced in the last round is checked.
    //       Test: `rejects_verify_merkle_root_not_produced_by_the_path`.
    //
    // What this does *not* license: `verify_merkle_enabled` stays `false`
    // In the default ISA config. That flag is gated on external review of
    // The soundness argument, which is a process step, not a missing
    // Constraint. Do not flip it on the strength of this comment.
    //
    // (c) also shows why that distinction is kept: an earlier version of
    // this comment declared (b) "implemented" and the declaration was true -
    // what was missing was not (b) but (c), which nobody had written down as
    // a separate item. That is precisely what an internal review misses.
    //
    // Tests: `verify_merkle_opcode_is_deprecated_for_zk_proofs` pins the
    // 0x1E encoding, `rejects_verify_merkle_with_zero_selector` covers (a),
    // And `rejects_verify_merkle_with_flipped_direction_bit` and its
    // Neighbours cover (b).

    #[test]
    fn verify_merkle_opcode_is_deprecated_for_zk_proofs() {
        // Pin the 0x1E encoding so the AIR-side opcode binding above
        // (which references 0x1E as a literal) cannot silently rot.
        let opcode = bud_isa::Opcode::VerifyMerkle;
        let encoded = bud_isa::Instruction {
            opcode,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        }
        .encode();
        assert_eq!(encoded & 0xFF, 0x1E);
    }

    /// P12-F01 (K9-C: the AIR is not touched): each VerifyMerkle level hashes
    /// with a single Poseidon round, which has no second preimage resistance,
    /// so the opcode must stay closed in production. This pins the closed
    /// gate where proofs are consumed: the default activation refuses the
    /// opcode, and the mainnet decode path rejects it.
    #[test]
    fn verify_merkle_stays_closed_under_default_activation() {
        let default = bud_isa::MainnetActivation::default();
        assert!(
            !default.verify_merkle_enabled,
            "VerifyMerkle must stay gated until the Poseidon round is replaced"
        );
        assert!(!default.allows(bud_isa::Opcode::VerifyMerkle));

        let raw = bud_isa::Instruction {
            opcode: bud_isa::Opcode::VerifyMerkle,
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
        }
        .encode();
        let err = bud_isa::Instruction::decode_for_mainnet(raw, default)
            .expect_err("the default mainnet decode must refuse VerifyMerkle");
        assert!(matches!(
            err,
            bud_isa::DecodeError::MainnetActivationRequired(bud_isa::Opcode::VerifyMerkle)
        ));
    }

    /// (security audit) partial-fix test for the
    /// Selector binding. Take a valid Add+Halt program, mutate the
    /// Trace so the *last* real row's `is_verify_merkle` column is
    /// Zeroed out while `COL_OPCODE` is left at 0x00 (Halt), that
    /// Row is still a Halt so the constraint
    /// `is_verify_merkle * (opcode - 0x1E) = 0` is vacuously true.
    ///
    /// A more interesting attack would be to set `is_verify_merkle = 0`
    /// On a row where `COL_OPCODE = 0x1E` and write a fake `rd_val_new`
    /// That is exactly what the new AIR constraint rejects. The
    /// `proves_simple_add_trace` test (which uses Halt, not VerifyMerkle)
    /// Continues to pass because the constraint is satisfied
    /// Trivially on every row that isn't a VerifyMerkle row.
    #[test]
    fn rejects_verify_merkle_row_with_zero_selector() {
        // Build a trace that contains a VerifyMerkle row and check
        // That the AIR rejects a trace where the row's
        // `is_verify_merkle` column is zeroed out while
        // `COL_OPCODE` is left at 0x1E.
        //
        // The program: set r2=root, r3=leaf, run VerifyMerkle on a
        // Trivial 64-sibling path, then Halt. We do not need the
        // Path to be valid - we only need the opcode to be 0x1E.
        let program = vec![
            inst(Opcode::Load, 2, 0, 0, 0xCAFE),
            inst(Opcode::Load, 3, 0, 0, 0xBABE),
            inst(Opcode::VerifyMerkle, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        // Build the matrix, then zero out the VerifyMerkle row's
        // `is_verify_merkle` column. With the old AIR, this
        // Would be a valid trace. With fix, the
        // Constraint `is_verify_merkle * (opcode - 0x1E) = 0` is
        // Violated because COL_OPCODE on that row IS 0x1E.
        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        // Find the VerifyMerkle row: it's the one with COL_OPCODE = 0x1E.
        let mut verify_row = None;
        for i in 0..n_cpu {
            let row_start = i * TRACE_WIDTH;
            let op_val = matrix.values[row_start + COL_OPCODE].as_canonical_u64();
            if op_val == 0x1E {
                verify_row = Some(i);
                break;
            }
        }
        let verify_row = verify_row.expect("trace should contain a VerifyMerkle row");

        // Zero out the is_verify_merkle column on that row.
        let row_start = verify_row * TRACE_WIDTH;
        matrix.values[row_start + COL_IS_VERIFY_MERKLE] = Goldilocks::new(0);
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        // Verification must reject the proof because the
        // Is_verify_merkle selector was zeroed out on a row where
        // COL_OPCODE = 0x1E, which violates the new AIR constraint.
        let res = Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full(),
        );
        assert!(
            res.is_err(),
            "Expected verification to FAIL when is_verify_merkle is zeroed on a 0x1E row, but it succeeded!"
        );
    }

    /// A forged product must not verify.
    ///
    /// Found by asking a question the RISC Zero disclosure makes concrete: not
    /// "is there a constraint" but "has a forgery against it ever been shown
    /// to fail". RISC Zero's own corpus put 95 of 99 circuit bugs in the
    /// under-constrained class, and the 2.0.x break was `remu`/`divu`, opcodes
    /// with constraints written and no negative test behind them.
    ///
    /// Counted here: 35 opcodes have a positive round-trip test, 22 of them
    /// had no forgery test at all. `Mul` and `Sub` are the two that carry
    /// arithmetic into balances, so they go first.
    ///
    /// The AIR says `when(is_mul).assert_eq(rd_val_new, rs1_val * rs2_val)`.
    /// This claims 6 * 7 == 41 and requires the verifier to refuse.
    #[test]
    fn rejects_a_forged_product() {
        let program = vec![
            inst(Opcode::Load, 2, 0, 0, 6),
            inst(Opcode::Load, 3, 0, 0, 7),
            inst(Opcode::Mul, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.registers[1], 42, "the honest product must be 42");

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        let mut mul_row = None;
        for i in 0..n_cpu {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_IS_MUL].as_canonical_u64() == 1 {
                mul_row = Some(i);
                break;
            }
        }
        let mul_row = mul_row.expect("the trace must contain a Mul row");
        let row_start = mul_row * TRACE_WIDTH;
        assert_eq!(
            matrix.values[row_start + COL_RD_VAL_NEW].as_canonical_u64(),
            42,
            "the honest trace must hold the real product before it is forged"
        );

        matrix.values[row_start + COL_RD_VAL_NEW] = Goldilocks::new(41);
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a proof claiming 6 * 7 == 41 verified; the multiplication \
             constraint is not holding"
        );
    }

    /// A forged difference must not verify.
    ///
    /// Same class as the product above. `Sub` matters on its own because the
    /// VM computes in the Goldilocks field, so a difference is not a machine
    /// subtraction, and a balance debit that a prover can choose is the same
    /// hazard as a mint.
    #[test]
    fn rejects_a_forged_difference() {
        let program = vec![
            inst(Opcode::Load, 2, 0, 0, 100),
            inst(Opcode::Load, 3, 0, 0, 30),
            inst(Opcode::Sub, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.registers[1], 70, "the honest difference must be 70");

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        let mut sub_row = None;
        for i in 0..n_cpu {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_IS_SUB].as_canonical_u64() == 1 {
                sub_row = Some(i);
                break;
            }
        }
        let sub_row = sub_row.expect("the trace must contain a Sub row");
        let row_start = sub_row * TRACE_WIDTH;
        assert_eq!(
            matrix.values[row_start + COL_RD_VAL_NEW].as_canonical_u64(),
            70,
            "the honest trace must hold the real difference before it is forged"
        );

        // 100 - 30 claimed as 100: a debit that took nothing.
        matrix.values[row_start + COL_RD_VAL_NEW] = Goldilocks::new(100);
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a proof claiming 100 - 30 == 100 verified; a debit that takes \
             nothing is a mint with extra steps"
        );
    }

    /// A register must not change value without a write.
    ///
    /// The register table is sorted by `(idx, clk, sub_clk)`, so the events
    /// for one register land on consecutive rows and the AIR checks continuity
    /// across each pair:
    ///
    /// ```text
    /// r_active * nr_active * r_same * (1 - nr_write) * (nr_val - r_val) == 0
    /// ```
    ///
    /// `r_same` means "the next row is about this same register". Nothing said
    /// so. It had no booleanity constraint, no counterpart on the `1 - r_same`
    /// side, and it does not appear anywhere in the LogUp argument, so it was
    /// a free column whose only job was to switch the rule above on and off.
    /// Writing zero cost the prover nothing and deleted the requirement that a
    /// read return the value that was written.
    ///
    /// The memory table has the identical shape and is not vulnerable, which
    /// is the reason this survived a direct reading of the file more than
    /// once. There, `m_same = 0` is a claim that the next row is a different
    /// address, and a separate constraint then requires the first read of a
    /// new address to return zero. Lying costs the prover exactly the value it
    /// was trying to invent. Registers have no first-touch rule, so the
    /// counterpart was never written, and the flag was left free.
    ///
    /// The program here writes 5 into r1 and reads it back through an `Add`.
    /// The forgery rewrites the read to 999 on both sides of the register bus
    /// so the LogUp argument stays balanced, carries the lie into the `Add`
    /// result so the arithmetic constraint is satisfied, and clears `r_same`
    /// on the row before so continuity is not checked. Nothing was written to
    /// r1 in between. Register values are the inputs to every arithmetic
    /// constraint in the machine, so a prover who can do this chooses the
    /// inputs of any computation it likes.
    #[test]
    fn rejects_a_register_that_changes_value_without_a_write() {
        // r1 = 5; r2 = r1 + r0; halt.
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 5),
            inst(Opcode::Add, 2, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(
            vm.registers[1], 5,
            "r1 must hold the value that was written"
        );
        assert_eq!(vm.registers[2], 5, "the honest sum is 5 + 0");

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);

        // The two register-table rows for r1: the write from Load, then the
        // read by Add. They are adjacent because the table is sorted by index
        // first, and that adjacency is what `r_same` is about.
        let mut write_row = None;
        let mut read_row = None;
        for i in 0..matrix.values.len() / TRACE_WIDTH {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_REG_ACTIVE].as_canonical_u64() != 1 {
                continue;
            }
            if matrix.values[row_start + COL_REG_IDX].as_canonical_u64() != 1 {
                continue;
            }
            if matrix.values[row_start + COL_REG_IS_WRITE].as_canonical_u64() == 1 {
                write_row = Some(i);
            } else if write_row.is_some() && read_row.is_none() {
                read_row = Some(i);
            }
        }
        let write_row = write_row.expect("the register table must hold the write to r1");
        let read_row = read_row.expect("the register table must hold the read of r1");
        assert_eq!(
            read_row,
            write_row + 1,
            "the write and the read of r1 must be adjacent rows, otherwise \
             r_same is not the flag governing this pair and the forgery below \
             is aimed at the wrong place"
        );

        let write_start = write_row * TRACE_WIDTH;
        let read_start = read_row * TRACE_WIDTH;
        assert_eq!(
            matrix.values[write_start + COL_REG_SAME].as_canonical_u64(),
            1,
            "the honest trace must mark the pair as belonging to one register"
        );
        assert_eq!(
            matrix.values[read_start + COL_REG_VAL].as_canonical_u64(),
            5,
            "the honest read must return the value that was written"
        );

        // Find the Add row so the lie can be carried into the arithmetic too.
        let mut add_row = None;
        for i in 0..n_cpu {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_IS_ADD].as_canonical_u64() == 1 {
                add_row = Some(i);
                break;
            }
        }
        let add_row = add_row.expect("the trace must contain an Add row");
        let add_start = add_row * TRACE_WIDTH;

        // The forgery. r1 becomes 999 at the point it is read, with no write
        // anywhere between, and every other constraint is kept satisfied:
        //
        //   - both sides of the register bus move together, so the LogUp
        //     argument stays balanced and does not catch it
        //   - the Add result moves with its input, so rd == rs1 + rs2 holds
        //   - r_same is cleared, so continuity is not checked
        matrix.values[read_start + COL_REG_VAL] = Goldilocks::new(999);
        matrix.values[add_start + COL_RS1_VAL] = Goldilocks::new(999);
        matrix.values[add_start + COL_RD_VAL_NEW] = Goldilocks::new(999);
        matrix.values[write_start + COL_REG_SAME] = Goldilocks::new(0);

        // r2's own table row has to follow the value it was given, or the
        // proof fails on the register bus rather than on continuity.
        for i in 0..matrix.values.len() / TRACE_WIDTH {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_REG_ACTIVE].as_canonical_u64() == 1
                && matrix.values[row_start + COL_REG_IDX].as_canonical_u64() == 2
                && matrix.values[row_start + COL_REG_IS_WRITE].as_canonical_u64() == 1
            {
                matrix.values[row_start + COL_REG_VAL] = Goldilocks::new(999);
            }
        }

        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a register went from 5 to 999 with no write in between and the \
             proof verified; register continuity is then optional and the \
             prover picks the inputs to every computation"
        );
    }

    /// A prover must not invent the register file the program started from.
    ///
    /// `Plonky3Adapter::prove` takes the trace, the public inputs and the
    /// program. Until this commitment existed, the starting register file
    /// appeared in none of them: a read of a register nothing had written was
    /// reading state the proof said nothing about, so two runs beginning from
    /// different register contents produced proofs the same public inputs
    /// would accept.
    ///
    /// The first attempt at closing this asserted that such a read must return
    /// zero. CI rejected 68 existing tests, correctly: that is an assumption
    /// about the caller, not something the proof system can check. Memory
    /// solved the same problem years earlier by marking seeded rows and
    /// folding them into a commitment, and this is that mirror, in the same
    /// public input the memory image already uses.
    ///
    /// Here the host seeds r4 before the program runs. The honest root commits
    /// to `r4 = 100`; the forgery claims 999 while presenting that same root.
    #[test]
    fn rejects_an_invented_starting_register() {
        // r3 = r4 + r0, and the host seeds r4 before the program runs.
        let program = vec![
            inst(Opcode::Add, 3, 4, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        vm.registers[4] = 100;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.registers[3], 100, "the honest sum reads the seeded r4");

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        // The honest root commits to r4 = 100. The forgery below claims r4 was
        // something else while presenting this root, which is the whole point:
        // the starting register file is now part of what the proof states.
        let honest_root = crate::adapter::initial_state_root_of(
            crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
            crate::adapter::register_image_commitment_of_reads(&initial_register_reads(&vm.trace)),
        );
        assert_ne!(
            honest_root, [0u8; 32],
            "a seeded register must move the root off zero, otherwise the \
             commitment is not covering it"
        );

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: honest_root,
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        let rows = matrix.values.len() / TRACE_WIDTH;

        let mut r4_row = None;
        for i in 0..rows {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_REG_ACTIVE].as_canonical_u64() == 1
                && matrix.values[row_start + COL_REG_IDX].as_canonical_u64() == 4
            {
                r4_row = Some(i);
                break;
            }
        }
        let r4_row = r4_row.expect("the register table must hold the read of r4");
        let r4_start = r4_row * TRACE_WIDTH;
        assert_eq!(
            matrix.values[r4_start + COL_REG_IS_INIT].as_canonical_u64(),
            1,
            "the read of a register nothing wrote must be flagged as initial"
        );

        let mut add_row = None;
        for i in 0..n_cpu {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_IS_ADD].as_canonical_u64() == 1 {
                add_row = Some(i);
                break;
            }
        }
        let add_start = add_row.expect("the trace must contain an Add row") * TRACE_WIDTH;

        // The forgery: claim the program started with r4 = 999 while
        // presenting the root that commits to 100. Both sides of the register
        // bus move together and the sum follows its input, so nothing but the
        // initial-image commitment can catch it.
        matrix.values[r4_start + COL_REG_VAL] = Goldilocks::new(999);
        matrix.values[add_start + COL_RS1_VAL] = Goldilocks::new(999);
        matrix.values[add_start + COL_RD_VAL_NEW] = Goldilocks::new(999);
        for i in 0..rows {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_REG_ACTIVE].as_canonical_u64() == 1
                && matrix.values[row_start + COL_REG_IDX].as_canonical_u64() == 3
                && matrix.values[row_start + COL_REG_IS_WRITE].as_canonical_u64() == 1
            {
                matrix.values[row_start + COL_REG_VAL] = Goldilocks::new(999);
            }
        }

        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a proof claimed the program started with r4 = 999 while \
             presenting a root that commits to 100, and it verified; the \
             starting register file is then whatever the prover says"
        );
    }

    /// A program that starts from a seeded register file must be provable.
    ///
    /// The completeness half. The first attempt at this rule asserted that a
    /// register nothing wrote reads as zero, and CI rejected 68 existing tests
    /// because that is an assumption about the caller the proof system cannot
    /// check. The commitment is what makes the rule honest: a seeded register
    /// is allowed, it just has to be declared.
    #[test]
    fn proves_a_program_that_starts_from_seeded_registers() {
        let program = vec![
            inst(Opcode::Add, 3, 4, 5, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        vm.registers[4] = 40;
        vm.registers[5] = 2;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.registers[3], 42);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        // Both seeded registers must be in the commitment, in the order the
        // AIR folds them. Checked rather than assumed: if the helper stopped
        // reporting them the root would silently go back to zero and this test
        // would pass while proving nothing.
        let reg_reads = initial_register_reads(&vm.trace);
        assert_eq!(
            reg_reads,
            vec![(4, 40), (5, 2)],
            "both seeded registers must be reported, sorted by index"
        );

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&reg_reads),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program)
            .expect("a program starting from seeded registers must be provable");
        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_ok(),
            "an honest run from a seeded register file was rejected; the \
             initial register commitment is not matching the fold"
        );
    }

    /// A prover must not redirect a storage write to a different slot.
    ///
    /// The last field of the instruction word to be bound. `imm` decides more
    /// than it looks: `SRead` and `SWrite` take their slot straight from it,
    /// the Merkle path buffer address is it, a `Load` or `Store` resolves to
    /// `rs1_val + imm`, and a jump target is `pc + imm`. While it was free, a
    /// prover chose which storage slot a contract wrote to.
    ///
    /// Binding it needed one step the other fields did not. The trace stores a
    /// negative immediate as `P - |imm|`, so the raw masked bits are not what
    /// the CPU column holds: `imm = -1` masks to `4294967295` and the trace
    /// carries `18446744069414584320`. The preprocessed side runs the word
    /// through `bud_isa::decode_any` and applies the same wrap, so there is
    /// one decoder rather than two copies of a sign rule that could drift
    /// apart.
    ///
    /// Here the program writes a balance to slot 7. The forgery sends it to
    /// slot 9 instead, leaving the value and the register bus untouched.
    #[test]
    fn rejects_a_redirected_storage_slot() {
        // r1 = 500; storage[7] = r1.
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 500),
            inst(Opcode::SWrite, 0, 1, 0, 7),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(
            vm.storage.get(&7).copied(),
            Some(500),
            "the honest run must write the balance to slot 7"
        );

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            // The honest digest: the refusal below has to come from the
            // redirected slot, not from constraint (2b) seeing a zero digest.
            state_writes_digest: receipt.state_writes_digest,
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        let rows = matrix.values.len() / TRACE_WIDTH;

        let mut swrite_row = None;
        for i in 0..n_cpu {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_IS_SWRITE].as_canonical_u64() == 1 {
                swrite_row = Some(i);
                break;
            }
        }
        let swrite_row = swrite_row.expect("the trace must contain an SWrite row");
        let sw_start = swrite_row * TRACE_WIDTH;

        assert_eq!(
            matrix.values[sw_start + COL_IMM].as_canonical_u64(),
            7,
            "the honest row must name slot 7"
        );
        let honest_word = matrix.values[sw_start + COL_RAW_INST].as_canonical_u64();

        // The forgery: the same value, written to a slot the contract never
        // named. The memory argument places storage at address `imm` of table 3,
        // so the storage row has to move with the immediate or the proof
        // fails on the bus instead of on the decode binding.
        matrix.values[sw_start + COL_IMM] = Goldilocks::new(9);
        assert_eq!(
            matrix.values[sw_start + COL_RAW_INST].as_canonical_u64(),
            honest_word,
            "the instruction word must be left alone; pinning it was never the \
             part that was missing"
        );

        for i in 0..rows {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_MEM_ACTIVE].as_canonical_u64() == 1
                && matrix.values[row_start + COL_MEM_TID].as_canonical_u64() == TID_STORAGE
                && matrix.values[row_start + COL_MEM_ADDR].as_canonical_u64() == 7
            {
                set_mem_addr(&mut matrix.values, i, 9);
            }
        }

        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a storage write aimed at slot 7 landed on slot 9 and the proof \
             verified; a prover can then move any contract's state anywhere it \
             likes"
        );
    }

    /// A program with a negative immediate must still be provable.
    ///
    /// The completeness half of binding `imm`. Negative immediates are the
    /// reason this field needed a decoder rather than a mask: the trace holds
    /// `P - |imm|` while the raw bits say `4294967295`, so a preprocessed side
    /// that masked instead of decoding would reject every honest program that
    /// jumps backwards. Loops jump backwards.
    #[test]
    fn proves_a_program_with_a_negative_immediate() {
        // r1 = 1; jump forward over a Halt; the skipped instruction is reached
        // by a backward jump, so the program exercises a negative immediate.
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 1),
            inst(Opcode::Jmp, 0, 0, 0, 2),
            inst(Opcode::Halt, 0, 0, 0, 0),
            inst(Opcode::Jmp, 0, 0, 0, -1),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(
            receipt.success,
            "the honest program must run; if it does not, this test proves \
             nothing about negative immediates"
        );

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        // The backward jump has to actually be in the trace, or the test is
        // about nothing. Its immediate is stored wrapped, so it is checked
        // against the wrapped form rather than against -1.
        let (matrix, _n) = trace_matrix(&vm.trace, &program, &pi);
        let wrapped_minus_one = Goldilocks::ZERO - Goldilocks::new(1);
        let mut saw_negative_imm = false;
        for i in 0..vm.trace.len() {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_IMM] == wrapped_minus_one {
                saw_negative_imm = true;
                break;
            }
        }
        assert!(
            saw_negative_imm,
            "the trace must contain a row whose immediate is the wrapped -1"
        );

        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program)
            .expect("a program with a negative immediate must be provable");
        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_ok(),
            "an honest backward jump was rejected; the immediate binding is \
             comparing raw bits against a wrapped field element"
        );
    }

    /// A prover must not swap which register an instruction reads.
    ///
    /// The Program CTL pins `COL_RAW_INST` to the committed program, and that
    /// reads like it settles the matter. It does not: the AIR never splits the
    /// word, so every field the CPU trace decodes out of it sat in a free
    /// witness column with nothing relating it back to the word beside it.
    /// `COL_OPCODE` was the first field closed, because the selectors key off
    /// it. The register indices are the same hole one level down.
    ///
    /// This is the shape it takes in money. A contract computing
    /// `total = amount + fee` compiles to `Add r3, r2, r1` with the fee in r1.
    /// Rewrite `rs2_idx` from 1 to 2 and the row computes `amount + amount`
    /// instead. Every other constraint stays satisfied:
    ///
    /// - the arithmetic rule holds, because the value column moves with the
    ///   index it names
    /// - the register argument balances, because r2 is genuinely read on this
    ///   row and its value is genuinely what is claimed
    /// - the Program CTL used to balance, because `raw_inst` was untouched
    ///
    /// The fee is never paid and the proof verifies. The tuple now carries the
    /// decoded fields alongside the word, so the CPU columns have to be the
    /// real decode of the instruction actually fetched.
    #[test]
    fn rejects_a_swapped_source_register() {
        // fee = 100, amount = 5, total = amount + fee.
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 100),
            inst(Opcode::Load, 2, 0, 0, 5),
            inst(Opcode::Add, 3, 2, 1, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.registers[3], 105, "the honest total is amount plus fee");

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        let rows = matrix.values.len() / TRACE_WIDTH;

        let mut add_row = None;
        for i in 0..n_cpu {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_IS_ADD].as_canonical_u64() == 1 {
                add_row = Some(i);
                break;
            }
        }
        let add_row = add_row.expect("the trace must contain an Add row");
        let add_start = add_row * TRACE_WIDTH;

        // Preconditions, asserted rather than assumed: if the honest row does
        // not look like this, the substitution below is not the one described.
        assert_eq!(
            matrix.values[add_start + COL_RS1_IDX].as_canonical_u64(),
            2,
            "rs1 must name the amount register"
        );
        assert_eq!(
            matrix.values[add_start + COL_RS2_IDX].as_canonical_u64(),
            1,
            "rs2 must name the fee register"
        );
        assert_eq!(
            matrix.values[add_start + COL_RS2_VAL].as_canonical_u64(),
            100,
            "the honest row must read the fee"
        );
        assert_eq!(
            matrix.values[add_start + COL_RD_VAL_NEW].as_canonical_u64(),
            105,
            "the honest sum must include the fee"
        );
        let honest_word = matrix.values[add_start + COL_RAW_INST].as_canonical_u64();

        // The forgery. rs2 now names r2 instead of r1, so the row adds the
        // amount to itself and the fee is skipped. The value column follows
        // the index it names and the result follows the sum, so the register
        // argument balances and `rd == rs1 + rs2` still holds.
        matrix.values[add_start + COL_RS2_IDX] = Goldilocks::new(2);
        matrix.values[add_start + COL_RS2_VAL] = Goldilocks::new(5);
        matrix.values[add_start + COL_RD_VAL_NEW] = Goldilocks::new(10);
        assert_eq!(
            matrix.values[add_start + COL_RAW_INST].as_canonical_u64(),
            honest_word,
            "the instruction word must be left alone; the whole point is that \
             pinning it was not enough"
        );

        // The register table has to agree, or the proof fails on the register
        // bus rather than on the decode binding. The Add row now reads r2
        // twice, so the r1 read disappears and a second r2 read takes its
        // place, and r3 receives the smaller sum.
        for i in 0..rows {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_REG_ACTIVE].as_canonical_u64() != 1 {
                continue;
            }
            let idx = matrix.values[row_start + COL_REG_IDX].as_canonical_u64();
            let is_write = matrix.values[row_start + COL_REG_IS_WRITE].as_canonical_u64();
            let val = matrix.values[row_start + COL_REG_VAL].as_canonical_u64();
            if idx == 1 && is_write == 0 && val == 100 {
                // The fee read that no longer happens becomes a second read
                // of the amount register.
                matrix.values[row_start + COL_REG_IDX] = Goldilocks::new(2);
                matrix.values[row_start + COL_REG_VAL] = Goldilocks::new(5);
            }
            if idx == 3 && is_write == 1 {
                matrix.values[row_start + COL_REG_VAL] = Goldilocks::new(10);
            }
        }

        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "an Add that was told to read the fee read the amount twice \
             instead and the proof verified; a prover can then redirect any \
             operand to any register and skip whatever the contract meant to \
             charge"
        );
    }

    /// A prover must not write to r0.
    ///
    /// r0 is the machine's constant zero. `bud-vm` enforces it directly and
    /// the trace builder used to enforce it by writing zero into the value
    /// column, but the AIR never did: `rd_idx` and `rd_val_new` met in exactly
    /// one place, the register LogUp tuple, which pairs them without relating
    /// them.
    ///
    /// r0 is a source of zero throughout the tree. `Assert` reads `rs2` from
    /// it, register moves are written as `Add rd, rs, r0`, and the `Load`
    /// immediate path is selected by `rs1_idx == 0`. A prover that can make r0
    /// hold something else changes what all of those mean.
    ///
    /// The fix does not constrain `rd_val_new`, it constrains what the row
    /// publishes on the register bus, so the arithmetic rules are untouched.
    /// See the completeness test below for why that distinction matters.
    #[test]
    fn rejects_a_write_to_the_zero_register() {
        // r0 = r1 + r2, which the machine must treat as discarding the result.
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 5),
            inst(Opcode::Load, 2, 0, 0, 7),
            inst(Opcode::Add, 0, 1, 2, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.registers[0], 0, "r0 must still be zero after the write");

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        let rows = matrix.values.len() / TRACE_WIDTH;

        // The register-table row where the Add writes to r0. Its honest value
        // is zero: that is the rule being tested.
        let mut r0_write = None;
        for i in 0..rows {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_REG_ACTIVE].as_canonical_u64() == 1
                && matrix.values[row_start + COL_REG_IDX].as_canonical_u64() == 0
                && matrix.values[row_start + COL_REG_IS_WRITE].as_canonical_u64() == 1
            {
                r0_write = Some(i);
                break;
            }
        }
        let r0_write = r0_write.expect("the register table must hold the write to r0");
        let r0_start = r0_write * TRACE_WIDTH;
        assert_eq!(
            matrix.values[r0_start + COL_REG_VAL].as_canonical_u64(),
            0,
            "the honest trace must publish zero for a write to r0"
        );

        // The forgery: claim r0 now holds 12. The arithmetic row is left
        // completely alone, so nothing but the r0 rule can catch this.
        matrix.values[r0_start + COL_REG_VAL] = Goldilocks::new(12);
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "r0 was made to hold 12 and the proof verified; the machine's \
             constant zero is then whatever the prover says it is"
        );
    }

    /// A program that writes to r0 must still be provable.
    ///
    /// The completeness half of the test above, and the reason the r0 rule is
    /// written against the register bus rather than against `COL_RD_VAL_NEW`.
    ///
    /// The trace builder used to write zero into `COL_RD_VAL_NEW` whenever the
    /// destination was r0. That kept the register bus honest and made honest
    /// programs unprovable: the AIR asks every `Add` row for
    /// `rd_val_new == rs1_val + rs2_val`, so an `Add r0, r1, r2` with `r1 = 5`
    /// and `r2 = 7` was asking it to accept `0 == 12`. The program ran fine
    /// and could not be proved.
    ///
    /// `bud-compiler` does not emit writes to r0 today, so nothing in the tree
    /// tripped over it, but hand written bytecode does and a change to
    /// register allocation would. A soundness fix that closes a hole by making
    /// valid programs unprovable has moved the problem, not fixed it, so both
    /// directions are tested.
    #[test]
    fn proves_a_program_that_writes_to_the_zero_register() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 5),
            inst(Opcode::Load, 2, 0, 0, 7),
            inst(Opcode::Add, 0, 1, 2, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(
            vm.registers[0], 0,
            "r0 must read as zero after a write to it"
        );

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program)
            .expect("a program writing to r0 must be provable");

        // The arithmetic row holds the real sum. If the trace builder went
        // back to zeroing it, the per opcode rule would be asking for
        // `0 == 12` and this program would stop being provable, so the value
        // is checked rather than assumed.
        let (matrix, _n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        let mut add_row = None;
        for i in 0..vm.trace.len() {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_IS_ADD].as_canonical_u64() == 1 {
                add_row = Some(i);
                break;
            }
        }
        let add_start = add_row.expect("the trace must contain an Add row") * TRACE_WIDTH;
        assert_eq!(
            matrix.values[add_start + COL_RD_VAL_NEW].as_canonical_u64(),
            12,
            "the arithmetic column must carry the real sum even when the \
             destination is r0"
        );

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_ok(),
            "an honest program that writes to r0 was rejected; the r0 rule has \
             been written against the wrong column"
        );
    }

    /// Programs whose instruction at `at` names r5 as `rd` without writing it,
    /// followed by an `Add` that reads r5. The VM leaves r5 at 3.
    fn non_writing_rd_programs() -> Vec<(&'static str, Vec<u64>, usize)> {
        vec![
            (
                "Store",
                vec![
                    inst(Opcode::Load, 5, 0, 0, 3),
                    inst(Opcode::Load, 1, 0, 0, 8),
                    inst(Opcode::Load, 2, 0, 0, 1),
                    inst(Opcode::Store, 5, 1, 2, 0),
                    inst(Opcode::Add, 6, 5, 0, 0),
                    inst(Opcode::Halt, 0, 0, 0, 0),
                ],
                3,
            ),
            (
                "Push",
                vec![
                    inst(Opcode::Load, 5, 0, 0, 3),
                    inst(Opcode::Load, 1, 0, 0, 7),
                    inst(Opcode::Push, 5, 1, 0, 0),
                    inst(Opcode::Add, 6, 5, 0, 0),
                    inst(Opcode::Halt, 0, 0, 0, 0),
                ],
                2,
            ),
            (
                "Call and Ret",
                vec![
                    inst(Opcode::Load, 5, 0, 0, 3),
                    inst(Opcode::Call, 5, 0, 0, 3),
                    inst(Opcode::Add, 6, 5, 0, 0),
                    inst(Opcode::Halt, 0, 0, 0, 0),
                    inst(Opcode::Ret, 5, 0, 0, 0),
                ],
                1,
            ),
            (
                "Jmp",
                vec![
                    inst(Opcode::Load, 5, 0, 0, 3),
                    inst(Opcode::Jmp, 5, 0, 0, 1),
                    inst(Opcode::Add, 6, 5, 0, 0),
                    inst(Opcode::Halt, 0, 0, 0, 0),
                ],
                1,
            ),
            (
                "Jnz",
                vec![
                    inst(Opcode::Load, 5, 0, 0, 3),
                    inst(Opcode::Load, 1, 0, 0, 7),
                    inst(Opcode::Jnz, 5, 1, 0, 1),
                    inst(Opcode::Add, 6, 5, 0, 0),
                    inst(Opcode::Halt, 0, 0, 0, 0),
                ],
                2,
            ),
            (
                "Assert",
                vec![
                    inst(Opcode::Load, 5, 0, 0, 3),
                    inst(Opcode::Load, 1, 0, 0, 7),
                    inst(Opcode::Assert, 5, 1, 0, 0),
                    inst(Opcode::Add, 6, 5, 0, 0),
                    inst(Opcode::Halt, 0, 0, 0, 0),
                ],
                2,
            ),
            (
                "Log",
                vec![
                    inst(Opcode::Load, 5, 0, 0, 3),
                    inst(Opcode::Load, 1, 0, 0, 7),
                    inst(Opcode::Log, 5, 1, 0, 0),
                    inst(Opcode::Add, 6, 5, 0, 0),
                    inst(Opcode::Halt, 0, 0, 0, 0),
                ],
                2,
            ),
            (
                "SWrite",
                vec![
                    inst(Opcode::Load, 5, 0, 0, 3),
                    inst(Opcode::Load, 1, 0, 0, 7),
                    inst(Opcode::SWrite, 5, 1, 0, 1),
                    inst(Opcode::Add, 6, 5, 0, 0),
                    inst(Opcode::Halt, 0, 0, 0, 0),
                ],
                2,
            ),
        ]
    }

    /// An opcode that writes no register must not be able to give `rd` a
    /// value.
    ///
    /// The register bus used to publish a write for the `rd` slot of every
    /// row, so `Store r5, ...` could write anything into r5 as long as the
    /// next reader of r5 agreed. The forged matrix below is the proof such a
    /// prover would hand in: the Store row carries `rd_val_new = 1000`, the
    /// register table holds a write of 1000 at the Store's slot, and every
    /// later r5 event and the `Add` that reads it follow. Nothing but the
    /// "does this opcode write" rule stands between it and acceptance.
    #[test]
    fn rejects_a_register_write_from_an_opcode_that_writes_none() {
        const FORGED: u64 = 1000;
        for (name, program, at) in non_writing_rd_programs() {
            // The other programs are covered by the honest test. The forgery
            // targets Store and Push only: the Add after Call and Ret sits two
            // steps on, and Log and SWrite need the digests an honest run
            // publishes, which this helper leaves at zero.
            if !matches!(name, "Store" | "Push") {
                continue;
            }
            let mut vm = Vm::new(1024);
            let receipt = vm.run_receipt(&program);
            assert!(receipt.success, "{name}: the honest run must succeed");
            assert_eq!(vm.registers[5], 3, "{name}: the VM must leave r5 alone");
            let k = vm
                .trace
                .iter()
                .position(|s| s.pc == at)
                .expect("the non-writing step must be in the trace");
            assert_eq!(vm.trace[k + 1].instruction.opcode, Opcode::Add);

            let verdict =
                verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                    let set = |values: &mut [Goldilocks], row: usize, col: usize, v: u64| {
                        values[row * TRACE_WIDTH + col] = Goldilocks::new(v);
                    };
                    set(values, k, COL_RD_VAL_NEW, FORGED);
                    set(values, k + 1, COL_RS1_VAL, FORGED);
                    set(values, k + 1, COL_RD_VAL_NEW, FORGED);
                    let rows = values.len() / TRACE_WIDTH;
                    for row in 0..rows {
                        let at_ = row * TRACE_WIDTH;
                        if values[at_ + COL_REG_ACTIVE].as_canonical_u64() != 1 {
                            continue;
                        }
                        let idx = values[at_ + COL_REG_IDX].as_canonical_u64();
                        let clk = values[at_ + COL_REG_CLK].as_canonical_u64();
                        let sub = values[at_ + COL_REG_SUB_CLK].as_canonical_u64();
                        if idx == 5 && clk >= k as u64 {
                            set(values, row, COL_REG_VAL, FORGED);
                            if clk == k as u64 && sub == 3 {
                                set(values, row, COL_REG_IS_WRITE, 1);
                            }
                        }
                        if idx == 6 && clk == k as u64 + 1 && sub == 3 {
                            set(values, row, COL_REG_VAL, FORGED);
                        }
                    }
                });
            assert!(
                verdict.is_err(),
                "{name}: an opcode that writes no register gave r5 a value of \
                 its own choosing and the proof verified. verdict={verdict:?}"
            );
        }
    }

    /// An opcode that writes no register still names an `rd`, and honest
    /// programs must stay provable: the slot is a read of r5's current value.
    #[test]
    fn proves_non_writing_opcode_with_nonzero_rd() {
        for (name, program, _) in non_writing_rd_programs() {
            let mut vm = Vm::new(1024);
            let receipt = vm.run_receipt(&program);
            assert!(receipt.success, "{name}: the honest run must succeed");
            assert_eq!(vm.registers[5], 3, "{name}: r5 must stay at 3");
            let verdict = verify_honest_run(&program);
            assert!(
                verdict.is_ok(),
                "{name}: an honest program with a non-zero rd on an opcode \
                 that writes none must verify. verdict={verdict:?}"
            );
        }
    }

    /// The prover publishes a register write for the opcodes in
    /// `opcode_writes_rd`, and the AIR sums selectors for the same set. The VM
    /// is the truth. If the VM starts to write `rd` for another opcode, or
    /// stops for one on the list, the honest trace no longer matches the
    /// register table, so the two must agree for all 33 opcodes.
    #[test]
    fn opcode_writes_rd_matches_what_the_vm_does() {
        const OLD: u64 = 0xDEAD_BEEF;
        let mut seen = 0;
        for byte in 0u64..=0xFF {
            let Ok(decoded) = Instruction::decode_any(byte) else {
                continue;
            };
            let op = decoded.opcode;
            seen += 1;
            let program = vec![inst(op, 5, 1, 2, 0)];
            let mut vm = Vm::new(1024);
            vm.registers[1] = 8;
            vm.registers[2] = 3;
            vm.registers[5] = OLD;
            vm.stack.push(9);
            vm.step(&program)
                .unwrap_or_else(|e| panic!("{op:?}: the single instruction must run: {e:?}"));
            assert!(!vm.trace.is_empty(), "{op:?}: the step must be traced");
            let wrote = vm.registers[5] != OLD;
            assert_eq!(
                wrote,
                opcode_writes_rd(op),
                "{op:?}: the VM and `opcode_writes_rd` disagree on whether rd is written"
            );
        }
        assert_eq!(seen, 33, "the opcode set changed; extend this test");
    }

    /// The register table columns that describe one event. Moving a row means
    /// moving all of them. `COL_REG_INIT_ACC` is a running sum, so it stays.
    const REG_TABLE_COLS: [usize; 9] = [
        COL_REG_CLK,
        COL_REG_IDX,
        COL_REG_VAL,
        COL_REG_IS_WRITE,
        COL_REG_ACTIVE,
        COL_REG_SAME,
        COL_REG_SUB_CLK,
        COL_REG_SAME_INV,
        COL_REG_IS_INIT,
    ];

    /// The register table row that holds the event `(idx, clk, sub_clk)`.
    fn find_reg_row(values: &[Goldilocks], idx: u64, clk: u64, sub: u64) -> usize {
        (0..values.len() / TRACE_WIDTH)
            .find(|&row| {
                let at = |col: usize| values[row * TRACE_WIDTH + col].as_canonical_u64();
                at(COL_REG_ACTIVE) == 1
                    && at(COL_REG_IDX) == idx
                    && at(COL_REG_CLK) == clk
                    && at(COL_REG_SUB_CLK) == sub
            })
            .expect("the register event must be in the table")
    }

    /// The memory table columns that describe one event, with the bits of its
    /// address. Moving a row means moving all of them. `COL_MEM_INIT_ACC` is a
    /// running sum, so it stays. The order witness describes the step to the
    /// next row, not the event, so it stays too.
    const MEM_TABLE_COLS: [usize; 12 + MEM_ADDR_BITS] = {
        let head = [
            COL_MEM_CLK,
            COL_MEM_TID,
            COL_MEM_ADDR,
            COL_MEM_VAL,
            COL_MEM_IS_WRITE,
            COL_MEM_ACTIVE,
            COL_MEM_SAME,
            COL_MEM_SAME_INV,
            COL_MEM_IS_INIT,
            COL_MEM_HI_MAX_INV,
            COL_MEM_TOP_SAME,
            COL_MEM_TOP_SAME_INV,
        ];
        let mut cols = [0usize; 12 + MEM_ADDR_BITS];
        let mut i = 0;
        while i < head.len() {
            cols[i] = head[i];
            i += 1;
        }
        let mut b = 0;
        while b < MEM_ADDR_BITS {
            cols[head.len() + b] = COL_MEM_ADDR_BITS_BASE + b;
            b += 1;
        }
        cols
    };

    /// Set the address of a memory row together with its canonical limbs.
    fn set_mem_addr(values: &mut [Goldilocks], row: usize, addr: u64) {
        let canon = Goldilocks::new(addr).as_canonical_u64();
        let hi_gap = 0xFFFF_FFFFu64 - (canon >> 32);
        values[row * TRACE_WIDTH + COL_MEM_ADDR] = Goldilocks::new(canon);
        values[row * TRACE_WIDTH + COL_MEM_HI_MAX_INV] = Goldilocks::new(if hi_gap != 0 {
            bud_vm::field_inverse_goldilocks(hi_gap)
        } else {
            0
        });
        for b in 0..MEM_ADDR_BITS {
            values[row * TRACE_WIDTH + COL_MEM_ADDR_BITS_BASE + b] =
                Goldilocks::new((canon >> b) & 1);
        }
    }

    /// The memory table row that holds the event `(tid, addr, clk)`.
    fn find_mem_row(values: &[Goldilocks], tid: u64, addr: u64, clk: u64) -> usize {
        (0..values.len() / TRACE_WIDTH)
            .find(|&row| {
                let at = |col: usize| values[row * TRACE_WIDTH + col].as_canonical_u64();
                at(COL_MEM_ACTIVE) == 1
                    && at(COL_MEM_TID) == tid
                    && at(COL_MEM_ADDR) == addr
                    && at(COL_MEM_CLK) == clk
            })
            .expect("the memory event must be in the table")
    }

    /// Writes 7 to address 5 and reads it back into r3. The table holds a
    /// write and a read of one address, and a padding row after them.
    fn memory_round_trip_program() -> Vec<u64> {
        vec![
            inst(Opcode::Load, 1, 0, 0, 5),
            inst(Opcode::Load, 2, 0, 0, 7),
            inst(Opcode::Store, 0, 1, 2, 0),
            inst(Opcode::Load, 3, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ]
    }

    /// Writes 0 to address 0 and reads it back. The table holds a write and a
    /// read of address 0, both with value 0, so an extra starting-image flag
    /// on one of them leaves the public root unchanged.
    fn memory_zero_round_trip_program() -> Vec<u64> {
        vec![
            inst(Opcode::Load, 1, 0, 0, 0),
            inst(Opcode::Store, 0, 1, 0, 0),
            inst(Opcode::Load, 3, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ]
    }

    /// The register table is a sorted list with no gaps, and nothing used to
    /// say so.
    ///
    /// Every transition rule of the table is gated by `r_active * nr_active`.
    /// A row of padding in the middle closes all of them at once: the read
    /// after the gap does not have to continue the write before it, and the
    /// first read of a register is only asked to be zero when the row before it
    /// is active. The forged matrix below moves the read of r9 one row down,
    /// leaves an inactive row behind it, and makes the read 1000. The write
    /// before the gap stays 7, the `Add` reads 1000, and the bus still
    /// balances because every event is still there once.
    #[test]
    fn rejects_register_read_after_inactive_gap() {
        const FORGED: u64 = 1000;
        // r9 is the highest register used, so its rows are the last active
        // rows and the row below them is padding.
        let program = vec![
            inst(Opcode::Load, 9, 0, 0, 7),
            inst(Opcode::Add, 2, 9, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert_eq!(vm.trace[1].instruction.opcode, Opcode::Add);

        let verdict =
            verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                let at = |row: usize, col: usize| row * TRACE_WIDTH + col;
                let rows = values.len() / TRACE_WIDTH;
                let read = find_reg_row(values, 9, 1, 1);
                let write2 = find_reg_row(values, 2, 1, 3);
                assert!(read + 1 < rows, "a padding row must follow the table");
                assert_eq!(values[at(read + 1, COL_REG_ACTIVE)].as_canonical_u64(), 0);
                for col in REG_TABLE_COLS {
                    values[at(read + 1, col)] = values[at(read, col)];
                    values[at(read, col)] = Goldilocks::new(0);
                }
                // The write before the gap no longer continues into a read.
                values[at(read - 1, COL_REG_SAME)] = Goldilocks::new(0);
                values[at(read + 1, COL_REG_VAL)] = Goldilocks::new(FORGED);
                values[at(write2, COL_REG_VAL)] = Goldilocks::new(FORGED);
                values[at(1, COL_RS1_VAL)] = Goldilocks::new(FORGED);
                values[at(1, COL_RD_VAL_NEW)] = Goldilocks::new(FORGED);
            });
        assert!(
            verdict.is_err(),
            "a read after an inactive gap returned a value nothing wrote and \
             the proof verified. verdict={verdict:?}"
        );
    }

    /// The LogUp argument compares multisets, so it cannot tell that two
    /// writes of one register swapped places. Only the order constraint can.
    ///
    /// The forged matrix swaps the two r1 writes (7 then 9 becomes 9 then 7),
    /// so the read that follows sees 7 and the `Add` is made to use it. Every
    /// continuity rule holds on the swapped rows.
    #[test]
    fn rejects_reordered_register_writes() {
        const FORGED: u64 = 7;
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Load, 1, 0, 0, 9),
            inst(Opcode::Add, 2, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert_eq!(vm.trace[2].instruction.opcode, Opcode::Add);

        let verdict =
            verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                let at = |row: usize, col: usize| row * TRACE_WIDTH + col;
                let first = find_reg_row(values, 1, 0, 3);
                let second = find_reg_row(values, 1, 1, 3);
                let read = find_reg_row(values, 1, 2, 1);
                let write2 = find_reg_row(values, 2, 2, 3);
                assert_eq!((second, read), (first + 1, first + 2));
                for col in REG_TABLE_COLS {
                    let a = values[at(first, col)];
                    values[at(first, col)] = values[at(second, col)];
                    values[at(second, col)] = a;
                }
                // Both writes and the read belong to r1, so the same flags
                // are right for the new positions.
                values[at(read, COL_REG_VAL)] = Goldilocks::new(FORGED);
                values[at(write2, COL_REG_VAL)] = Goldilocks::new(FORGED);
                values[at(2, COL_RS1_VAL)] = Goldilocks::new(FORGED);
                values[at(2, COL_RD_VAL_NEW)] = Goldilocks::new(FORGED);
            });
        assert!(
            verdict.is_err(),
            "two writes of one register swapped places and the proof verified. \
             verdict={verdict:?}"
        );
    }

    /// The starting-file flag belongs to active rows only. Here a padding row
    /// right after the table carries the flag. The honest program has no
    /// starting registers, so the fold stays at zero and the public root
    /// still matches.
    #[test]
    fn rejects_register_init_flag_on_padding_row() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Add, 2, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert!(
            initial_register_reads(&vm.trace).is_empty(),
            "the program must start from an all-zero register file"
        );

        let verdict =
            verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                let at = |row: usize, col: usize| row * TRACE_WIDTH + col;
                let rows = values.len() / TRACE_WIDTH;
                let last = find_reg_row(values, 2, 1, 3);
                assert!(last + 1 < rows, "a padding row must follow the table");
                assert_eq!(values[at(last + 1, COL_REG_ACTIVE)].as_canonical_u64(), 0);
                values[at(last + 1, COL_REG_IS_INIT)] = Goldilocks::new(1);
            });
        assert!(
            verdict.is_err(),
            "the starting-file flag was accepted on a padding row. \
             verdict={verdict:?}"
        );
    }

    /// The starting-file flag marks the first row of a register block and
    /// nothing else. Here the second read of r0 inside its block carries it.
    /// The value and index are zero, so the fold does not move and the public
    /// root still matches.
    #[test]
    fn rejects_register_init_flag_inside_a_block() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Add, 2, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert!(
            initial_register_reads(&vm.trace).is_empty(),
            "the program must start from an all-zero register file"
        );

        let verdict =
            verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                let at = |row: usize, col: usize| row * TRACE_WIDTH + col;
                let inner = find_reg_row(values, 0, 0, 2);
                assert!(inner > 0, "the row must not open the table");
                assert_eq!(values[at(inner - 1, COL_REG_IDX)].as_canonical_u64(), 0);
                assert_eq!(values[at(inner - 1, COL_REG_SAME)].as_canonical_u64(), 1);
                values[at(inner, COL_REG_IS_INIT)] = Goldilocks::new(1);
            });
        assert!(
            verdict.is_err(),
            "the starting-file flag was accepted inside a register block. \
             verdict={verdict:?}"
        );
    }

    /// The events of one register must form one block. Here the events of r1
    /// are split in two blocks with the block of r2 between them, and the
    /// second r1 block starts with a read of zero that is not flagged as
    /// starting state. Every flag and inverse witness is set to match the new
    /// layout, so only the strict order of the table stands in the way.
    #[test]
    fn rejects_register_events_split_into_two_blocks() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Add, 2, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert_eq!(vm.trace[1].instruction.opcode, Opcode::Add);

        let verdict =
            verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                let at = |row: usize, col: usize| row * TRACE_WIDTH + col;
                let first = find_reg_row(values, 1, 0, 3);
                let second = first + 1;
                let third = first + 2;
                assert_eq!(find_reg_row(values, 1, 1, 1), second);
                assert_eq!(find_reg_row(values, 2, 1, 3), third);
                // Swap the last two rows: the table becomes r1 write, r2
                // write, r1 read.
                for col in REG_TABLE_COLS {
                    let a = values[at(second, col)];
                    values[at(second, col)] = values[at(third, col)];
                    values[at(third, col)] = a;
                }
                let zero = Goldilocks::new(0);
                // Every pair of neighbours holds two different registers, so
                // no row continues into the next.
                values[at(first, COL_REG_SAME)] = zero;
                values[at(first, COL_REG_SAME_INV)] = Goldilocks::new(1);
                values[at(second, COL_REG_SAME)] = zero;
                values[at(second, COL_REG_SAME_INV)] = zero - Goldilocks::new(1);
                values[at(third, COL_REG_SAME)] = zero;
                values[at(third, COL_REG_SAME_INV)] = zero;
                // The read of r1 in the second block returns zero, and the
                // add that used it follows.
                values[at(second, COL_REG_VAL)] = zero;
                values[at(third, COL_REG_VAL)] = zero;
                values[at(1, COL_RS1_VAL)] = zero;
                values[at(1, COL_RD_VAL_NEW)] = zero;
            });
        assert!(
            verdict.is_err(),
            "the events of one register were accepted in two blocks. \
             verdict={verdict:?}"
        );
    }

    /// The memory table is a prefix: active rows first, padding after. Every
    /// rule of the table is gated by `m_active * nm_active`, so an inactive
    /// row between two active ones switches all of them off at once.
    ///
    /// The forged matrix moves the read of address 5 one row down and leaves
    /// an inactive row behind the write. The read returns 1000 and r3 takes
    /// that value.
    #[test]
    fn rejects_memory_read_after_inactive_gap() {
        const FORGED: u64 = 1000;
        let program = memory_round_trip_program();
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert_eq!(vm.trace[3].instruction.opcode, Opcode::Load);

        let verdict =
            verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                let at = |row: usize, col: usize| row * TRACE_WIDTH + col;
                let rows = values.len() / TRACE_WIDTH;
                let write = find_mem_row(values, TID_MEMORY, 5, 2);
                let read = find_mem_row(values, TID_MEMORY, 5, 3);
                assert_eq!(read, write + 1);
                assert!(read + 1 < rows, "a padding row must follow the table");
                assert_eq!(values[at(read + 1, COL_MEM_ACTIVE)].as_canonical_u64(), 0);
                for col in MEM_TABLE_COLS {
                    values[at(read + 1, col)] = values[at(read, col)];
                    values[at(read, col)] = Goldilocks::new(0);
                }
                values[at(write, COL_MEM_SAME)] = Goldilocks::new(0);
                values[at(read + 1, COL_MEM_VAL)] = Goldilocks::new(FORGED);
                let reg = find_reg_row(values, 3, 3, 3);
                values[at(reg, COL_REG_VAL)] = Goldilocks::new(FORGED);
                values[at(3, COL_RD_VAL_NEW)] = Goldilocks::new(FORGED);
            });
        assert!(
            verdict.is_err(),
            "a memory read after an inactive gap returned a value nothing \
             wrote and the proof verified. verdict={verdict:?}"
        );
    }

    /// The memory flag is the multiplicity of the row on the memory bus, so
    /// it must be 0 or 1. The prefix rule does not say so: it only forces the
    /// flag to 1 on a row whose successor is active. The last active row is
    /// free of it.
    ///
    /// The forged matrix copies the last read of address 5 into two more
    /// rows. The first two copies continue the block with the same flag, and
    /// the third carries `-1` as its flag. The third row cancels the second
    /// on the bus, so the bus stays in balance. The ordering rules and the
    /// same-address rules hold, and nothing but the booleanity of the flag
    /// is left to refuse the table.
    ///
    /// The bus columns are rebuilt from the edited matrix, and then the
    /// third row is counted with its flag, as the AIR counts it. Nothing
    /// else is touched.
    ///
    /// Since the order rule of R4a-2, the two copies of one cell and one time
    /// also fail the strict clock step, so this table is refused twice. No
    /// table keeps the cancelling pair and passes the order rule, because the
    /// two rows would need one term, which means one cell and one time. This
    /// is an argument, not a mutation result: the check that removes the flag
    /// rule was not run. The rule stays.
    #[test]
    fn rejects_memory_active_flag_not_boolean() {
        let program = memory_round_trip_program();
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert_eq!(vm.trace[3].instruction.opcode, Opcode::Load);

        let verdict = verify_forged_matrix_with_aux(
            &program,
            &vm.trace,
            vm.gas_limit,
            vm.gas_used,
            |values| {
                let at = |row: usize, col: usize| row * TRACE_WIDTH + col;
                let rows = values.len() / TRACE_WIDTH;
                let read = find_mem_row(values, TID_MEMORY, 5, 3);
                assert!(read + 3 < rows, "two padding rows must follow the table");
                assert_eq!(values[at(read + 1, COL_MEM_ACTIVE)].as_canonical_u64(), 0);
                assert_eq!(values[at(read + 2, COL_MEM_ACTIVE)].as_canonical_u64(), 0);
                for col in MEM_TABLE_COLS {
                    values[at(read + 1, col)] = values[at(read, col)];
                    values[at(read + 2, col)] = values[at(read, col)];
                }
                let zero = Goldilocks::new(0);
                let one = Goldilocks::new(1);
                // The first two rows of the run continue into the next row.
                // The third one ends it, and carries the flag -1.
                values[at(read, COL_MEM_SAME)] = one;
                values[at(read, COL_MEM_SAME_INV)] = zero;
                values[at(read + 1, COL_MEM_SAME)] = one;
                values[at(read + 1, COL_MEM_SAME_INV)] = zero;
                values[at(read + 2, COL_MEM_SAME)] = zero;
                values[at(read + 2, COL_MEM_SAME_INV)] = zero;
                values[at(read + 2, COL_MEM_ACTIVE)] = zero - one;
            },
            |main, challenges, aux| {
                let (alpha, beta, gamma) = (challenges[0], challenges[1], challenges[2]);
                let width = aux.width;
                let rows = main.height();
                for row in 0..rows - 1 {
                    let at = |col: usize| main.values[row * TRACE_WIDTH + col];
                    let flag = at(COL_MEM_ACTIVE);
                    if flag.as_canonical_u64() <= 1 {
                        continue;
                    }
                    let term = register_term(
                        alpha,
                        beta,
                        at(COL_MEM_TID),
                        at(COL_MEM_CLK),
                        at(COL_MEM_ADDR),
                        at(COL_MEM_VAL),
                        at(COL_MEM_IS_WRITE),
                    );
                    // The builder took 1 for this row, the AIR takes the flag.
                    let delta =
                        (gamma - term).inverse() * MyExtensionField::from(Goldilocks::ONE - flag);
                    let coeffs: Vec<Goldilocks> =
                        p3_field::BasedVectorSpace::as_basis_coefficients_slice(&delta).to_vec();
                    for later in row + 1..rows {
                        for (k, c) in coeffs.iter().enumerate() {
                            // The memory bus is the second extension column.
                            aux.values[later * width + 2 + k] += *c;
                        }
                    }
                }
            },
        );
        assert!(
            verdict.is_err(),
            "a memory row with flag -1 was accepted and the proof verified. \
             verdict={verdict:?}"
        );
    }

    /// Swap two memory table rows. All columns of an event move together.
    fn swap_mem_rows(values: &mut [Goldilocks], a: usize, b: usize) {
        for col in MEM_TABLE_COLS {
            values.swap(a * TRACE_WIDTH + col, b * TRACE_WIDTH + col);
        }
    }

    /// Address 5 gets two writes and a read. Returns the program and the
    /// honest run.
    fn memory_reordered_writes_run() -> (Vec<u64>, Vm) {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 5),
            inst(Opcode::Load, 2, 0, 0, 7),
            inst(Opcode::Store, 0, 1, 2, 0),
            inst(Opcode::Load, 4, 0, 0, 9),
            inst(Opcode::Store, 0, 1, 4, 0),
            inst(Opcode::Load, 3, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert_eq!(vm.trace[5].instruction.opcode, Opcode::Load);
        assert_eq!(vm.trace[5].dst_val, 9);
        (program, vm)
    }

    /// Swap the two writes of address 5 and let the read return the earlier
    /// one. Returns the first row of the three. The order witness stays as the
    /// honest run left it.
    fn forge_memory_reordered_writes(values: &mut [Goldilocks]) -> usize {
        let at = |row: usize, col: usize| row * TRACE_WIDTH + col;
        let early = find_mem_row(values, TID_MEMORY, 5, 2);
        let late = find_mem_row(values, TID_MEMORY, 5, 4);
        let read = find_mem_row(values, TID_MEMORY, 5, 5);
        assert_eq!(late, early + 1);
        assert_eq!(read, late + 1);
        swap_mem_rows(values, early, late);
        values[at(read, COL_MEM_VAL)] = Goldilocks::new(7);
        let reg = find_reg_row(values, 3, 5, 3);
        values[at(reg, COL_REG_VAL)] = Goldilocks::new(7);
        values[at(5, COL_RD_VAL_NEW)] = Goldilocks::new(7);
        early
    }

    /// The memory table is sorted by table id, address and then time. The bus
    /// only compares the set of events, so it cannot see the order.
    ///
    /// Address 5 gets two writes and a read. The forged table lists the
    /// later write first, so the read follows the earlier write and returns
    /// its value. The set of events is the same.
    #[test]
    fn rejects_reordered_memory_writes() {
        let (program, vm) = memory_reordered_writes_run();
        let verdict =
            verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                forge_memory_reordered_writes(values);
            });
        assert!(
            verdict.is_err(),
            "a memory table out of time order was accepted. verdict={verdict:?}"
        );
    }

    /// The order witness is a list of bits. The reordered table above has a
    /// backward step of `-3` from its first row to its second. Here the first
    /// bit of that row holds `-3` as a field element, so the sum of the bits
    /// is the step, and only the booleanity of the bit refuses the row. The
    /// second row gets the honest bits of its forward step, 2.
    #[test]
    fn rejects_memory_order_bit_not_boolean() {
        let (program, vm) = memory_reordered_writes_run();
        let verdict =
            verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                let first = forge_memory_reordered_writes(values);
                let zero = Goldilocks::new(0);
                for b in 0..MEM_ORD_BITS {
                    values[(first) * TRACE_WIDTH + COL_MEM_ORD_BITS_BASE + b] = zero;
                    values[(first + 1) * TRACE_WIDTH + COL_MEM_ORD_BITS_BASE + b] =
                        Goldilocks::new(u64::from(b == 1));
                }
                values[first * TRACE_WIDTH + COL_MEM_ORD_BITS_BASE] =
                    Goldilocks::new(bud_vm::GOLDILOCKS_P - 3);
            });
        assert!(
            verdict.is_err(),
            "a backward step with a non-boolean order bit was accepted. \
             verdict={verdict:?}"
        );
    }

    /// All events of one address sit in one block of the memory table.
    ///
    /// Address 5 gets a write and a read, and address 6 gets a write in
    /// between. The forged table puts the read of address 5 after the block of
    /// address 6. A block start may read zero, so the read returns 0.
    #[test]
    fn rejects_memory_events_split_into_two_blocks() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 5),
            inst(Opcode::Load, 2, 0, 0, 7),
            inst(Opcode::Store, 0, 1, 2, 0),
            inst(Opcode::Load, 4, 0, 0, 16),
            inst(Opcode::Store, 0, 4, 2, 0),
            inst(Opcode::Load, 3, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert_eq!(vm.trace[5].instruction.opcode, Opcode::Load);
        assert_eq!(vm.trace[5].dst_val, 7);

        let verdict =
            verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                let at = |row: usize, col: usize| row * TRACE_WIDTH + col;
                let zero = Goldilocks::new(0);
                let write = find_mem_row(values, TID_MEMORY, 5, 2);
                let read = find_mem_row(values, TID_MEMORY, 5, 5);
                let other = find_mem_row(values, TID_MEMORY, 16, 4);
                assert_eq!(read, write + 1);
                assert_eq!(other, read + 1);
                swap_mem_rows(values, read, other);
                // Three blocks of one row each. The inverse witness is the
                // inverse of the address step to the next row.
                values[at(write, COL_MEM_SAME)] = zero;
                values[at(write, COL_MEM_SAME_INV)] =
                    Goldilocks::new(bud_vm::field_inverse_goldilocks(11));
                values[at(read, COL_MEM_SAME)] = zero;
                values[at(read, COL_MEM_SAME_INV)] =
                    Goldilocks::new(bud_vm::field_inverse_goldilocks(bud_vm::GOLDILOCKS_P - 11));
                values[at(other, COL_MEM_SAME)] = zero;
                values[at(other, COL_MEM_SAME_INV)] = zero;
                values[at(other, COL_MEM_VAL)] = zero;
                let reg = find_reg_row(values, 3, 5, 3);
                values[at(reg, COL_REG_VAL)] = zero;
                values[at(5, COL_RD_VAL_NEW)] = zero;
            });
        assert!(
            verdict.is_err(),
            "the events of one address were accepted in two blocks. \
             verdict={verdict:?}"
        );
    }

    /// A forged run whose last `Load` reads memory at exactly `2^32`.
    ///
    /// The program builds `2^32` in r1 and then loads an immediate into r3.
    /// The forged trace turns that last step into a `Load` through r1 that
    /// reads 0. The address is the first one past the 32 bit range, so the sort
    /// key `tid * 2^32 + addr` is still below `2^34`, and only the address bits
    /// can refuse the row. Returns the forged program, the forged trace and
    /// the two gas figures.
    fn memory_load_at_2_pow_32() -> (Vec<u64>, Vec<Step>, u64, u64) {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 1 << 16),
            inst(Opcode::Mul, 1, 1, 1, 0),
            inst(Opcode::Load, 3, 0, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert_eq!(vm.trace[1].dst_val, 1 << 32);
        assert_eq!(vm.trace[2].instruction.opcode, Opcode::Load);

        // The load-immediate at pc 2 becomes a load through r1. Both Loads
        // cost the same gas, so the gas figures stay.
        let mut forged_program = program.clone();
        forged_program[2] = inst(Opcode::Load, 3, 1, 0, 0);
        let mut trace = vm.trace.clone();
        let step = &mut trace[2];
        step.instruction = Instruction {
            opcode: Opcode::Load,
            rd: 3,
            rs1: 1,
            rs2: 0,
            imm: 0,
        };
        step.src1_idx = 1;
        step.src1_val = 1 << 32;
        step.dst_val = 0;
        step.memory_addr = Some(1usize << 32);
        step.memory_val = Some(0);
        step.is_memory_write = false;
        (forged_program, trace, vm.gas_limit, vm.gas_used)
    }

    /// A `Load` address is a number inside the memory table, below `2^32`. The
    /// honest VM refuses an address outside its memory, but the AIR is what a
    /// verifier trusts, and nothing else bounded the address.
    ///
    /// The row keeps the low 32 bits of the address as its bits, which are
    /// zero here, so the bits do not add up to the address.
    #[test]
    fn rejects_memory_load_address_above_32_bits() {
        let (program, trace, gas_limit, gas_used) = memory_load_at_2_pow_32();
        let verdict = verify_forged_trace(&program, &trace, gas_limit, gas_used);
        assert!(
            verdict.is_err(),
            "a load at address 2^32 was accepted. verdict={verdict:?}"
        );
    }

    /// The address bits are bits. Here the first one holds `2^32`, so the
    /// sum of the bits is the address and only the booleanity of the bit
    /// refuses the row.
    #[test]
    fn rejects_memory_address_bit_not_boolean() {
        let (program, trace, gas_limit, gas_used) = memory_load_at_2_pow_32();
        let verdict = verify_forged_matrix(&program, &trace, gas_limit, gas_used, |values| {
            let row = find_mem_row(values, TID_MEMORY, 1 << 32, 2);
            values[row * TRACE_WIDTH + COL_MEM_ADDR_BITS_BASE] = Goldilocks::new(1 << 32);
        });
        assert!(
            verdict.is_err(),
            "an address bit of 2^32 was accepted. verdict={verdict:?}"
        );
    }

    /// The table id is part of the cell, and the bus carries it.
    ///
    /// The program pushes 7 and then loads memory cell 0, which holds 0. The
    /// forged table calls the stack write a write to memory cell 0 and moves it
    /// in front of the load. The load then reads 7 from a block that has no
    /// starting-image flag, so the public root stays the root of an empty
    /// image. The CPU side of the bus still names the push as table 2, so only
    /// the table id on the bus refuses the table.
    #[test]
    fn rejects_memory_stack_row_relabelled_as_memory_cell() {
        let program = vec![
            inst(Opcode::Load, 5, 0, 0, 7),
            inst(Opcode::Push, 0, 5, 0, 0),
            inst(Opcode::Load, 1, 0, 0, 0),
            inst(Opcode::Load, 3, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert_eq!(vm.trace[3].instruction.opcode, Opcode::Load);
        assert_eq!(vm.trace[3].dst_val, 0);

        let verdict =
            verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                let at = |row: usize, col: usize| row * TRACE_WIDTH + col;
                let load = find_mem_row(values, TID_MEMORY, 0, 3);
                let push = find_mem_row(values, TID_STACK, 0, 1);
                assert_eq!(push, load + 1);
                swap_mem_rows(values, load, push);
                // The first row is now the push, called a memory write. The
                // two rows are one cell, so the first one continues into the
                // second and the step is the clock step minus one.
                values[at(load, COL_MEM_TID)] = Goldilocks::new(TID_MEMORY);
                values[at(load, COL_MEM_SAME)] = Goldilocks::new(1);
                values[at(load, COL_MEM_SAME_INV)] = Goldilocks::new(0);
                for b in 0..MEM_ORD_BITS {
                    values[at(load, COL_MEM_ORD_BITS_BASE + b)] =
                        Goldilocks::new(u64::from(b == 0));
                }
                values[at(push, COL_MEM_VAL)] = Goldilocks::new(7);
                let reg = find_reg_row(values, 3, 3, 3);
                values[at(reg, COL_REG_VAL)] = Goldilocks::new(7);
                values[at(3, COL_RD_VAL_NEW)] = Goldilocks::new(7);
            });
        assert!(
            verdict.is_err(),
            "a stack write was read back as memory cell 0 and the proof \
             verified. verdict={verdict:?}"
        );
    }

    /// An active memory row names table 1, 2 or 3. Here both rows of a cell
    /// name table 0 or table 4.
    ///
    /// The CPU side of the bus names table 1 for these events, so the bus
    /// refuses the table too. The range rule is a second wall: the sort key
    /// is a 34 bit number only while the table id is small.
    #[test]
    fn rejects_memory_row_with_table_id_outside_one_to_three() {
        let program = memory_round_trip_program();
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");

        for forged_tid in [0u64, 4] {
            let verdict =
                verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                    let write = find_mem_row(values, TID_MEMORY, 5, 2);
                    let read = find_mem_row(values, TID_MEMORY, 5, 3);
                    for row in [write, read] {
                        values[row * TRACE_WIDTH + COL_MEM_TID] = Goldilocks::new(forged_tid);
                    }
                });
            assert!(
                verdict.is_err(),
                "a memory row with table id {forged_tid} was accepted. verdict={verdict:?}"
            );
        }
    }

    /// The root names the table of a starting read.
    ///
    /// The host seeds memory cell 5 with 7 and a program reads it. A second
    /// program reads storage slot 5, which holds 7 too. Before the table id
    /// was part of the fold, both reads gave one term, so the root of the
    /// first run was the root of the second. The forged proof is the storage
    /// run, stated with the root of the memory run.
    #[test]
    fn rejects_memory_image_root_that_names_a_storage_slot() {
        let memory_program = vec![
            inst(Opcode::Load, 2, 0, 0, 5),
            inst(Opcode::Load, 1, 2, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut memory_vm = Vm::new(1024);
        memory_vm.memory[5..13].copy_from_slice(&7u64.to_le_bytes());
        let receipt = memory_vm.run_receipt(&memory_program);
        assert!(receipt.success, "the memory run must succeed");
        let memory_reads = initial_memory_reads(&memory_vm.trace);
        assert_eq!(
            memory_reads.len(),
            1,
            "the memory run reads one seeded cell"
        );

        let storage_program = vec![
            inst(Opcode::SRead, 1, 0, 0, 5),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        vm.storage.insert(5, 7);
        let receipt = vm.run_receipt(&storage_program);
        assert!(receipt.success, "the storage run must succeed");
        assert!(
            initial_memory_reads(&vm.trace).is_empty(),
            "seeded storage is not part of the memory image: the AIR pins the \
             initial-image flag to the memory table so the fold key stays injective"
        );

        let verdict = verify_forged_matrix_with_reads(
            &storage_program,
            &vm.trace,
            vm.gas_limit,
            vm.gas_used,
            memory_reads.clone(),
            |_| {},
        );
        assert!(
            verdict.is_err(),
            "the root of a seeded memory cell was accepted for a seeded \
             storage slot. verdict={verdict:?}"
        );

        // The wide-slot case, past `2^32`: that is where the fold key
        // `tid * 2^32 + addr` stops being injective, because a full-width
        // storage slot can take any value in the field. Seeded storage is not
        // part of the memory image at all, so the image root cannot be made to
        // stand for it.
        let wide_program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Load, 2, 0, 0, 99),
            inst(Opcode::Poseidon, 3, 1, 2, 0),
            inst(Opcode::SRead, 4, 0, 3, -1),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut probe_vm = Vm::new(1024);
        let receipt = probe_vm.run_receipt(&wide_program);
        assert!(receipt.success, "the wide-slot probe run must succeed");
        let wide_slot = probe_vm.registers[3];
        assert!(
            wide_slot > u64::from(u32::MAX),
            "the Poseidon slot must exceed 2^32: {wide_slot}"
        );
        let mut wide_vm = Vm::new(1024);
        wide_vm.storage.insert(wide_slot, 7);
        let receipt = wide_vm.run_receipt(&wide_program);
        assert!(receipt.success, "the wide-slot storage run must succeed");
        assert_eq!(wide_vm.registers[4], 7);
        assert!(
            initial_memory_reads(&wide_vm.trace).is_empty(),
            "a seeded wide storage slot is not part of the memory image"
        );
        let verdict = verify_forged_matrix_with_reads(
            &wide_program,
            &wide_vm.trace,
            wide_vm.gas_limit,
            wide_vm.gas_used,
            memory_reads.clone(),
            |_| {},
        );
        assert!(
            verdict.is_err(),
            "the root of a seeded memory cell was accepted for a seeded wide \
             storage slot. verdict={verdict:?}"
        );
    }

    /// `m_same` gates the value continuity between two rows of one address.
    /// Here it is cleared on the write of address 5, so the read after it only
    /// has to be zero, and it is. Its value is 0 and it is not flagged as
    /// starting state.
    ///
    /// Since the order rule of R4a-2, a cleared flag on two rows of one cell
    /// also makes the step `-1`, which has no 34 bit form, so this table is
    /// refused by the order rule as well as by the inverse witness. A cleared
    /// flag cannot pass the order rule at all. This is an argument, not a
    /// mutation result: the check that removes the inverse rule was not run.
    #[test]
    fn rejects_memory_same_flag_cleared_on_same_address() {
        let program = memory_round_trip_program();
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert_eq!(vm.trace[3].instruction.opcode, Opcode::Load);

        let verdict =
            verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                let at = |row: usize, col: usize| row * TRACE_WIDTH + col;
                let write = find_mem_row(values, TID_MEMORY, 5, 2);
                let read = find_mem_row(values, TID_MEMORY, 5, 3);
                assert_eq!(read, write + 1);
                assert_eq!(values[at(write, COL_MEM_SAME)].as_canonical_u64(), 1);
                values[at(write, COL_MEM_SAME)] = Goldilocks::new(0);
                values[at(read, COL_MEM_VAL)] = Goldilocks::new(0);
                let reg = find_reg_row(values, 3, 3, 3);
                values[at(reg, COL_REG_VAL)] = Goldilocks::new(0);
                values[at(3, COL_RD_VAL_NEW)] = Goldilocks::new(0);
            });
        assert!(
            verdict.is_err(),
            "a memory read returned zero after a write of 7 to the same \
             address and the proof verified. verdict={verdict:?}"
        );
    }

    /// The starting-image flag belongs to active rows only. Here a padding row
    /// right after the memory table carries it. The program has no starting
    /// memory, so the fold stays at zero and the public root still matches.
    #[test]
    fn rejects_memory_init_flag_on_padding_row() {
        let program = memory_zero_round_trip_program();
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert!(
            initial_memory_reads(&vm.trace).is_empty(),
            "the program must start from an empty memory image"
        );

        let verdict =
            verify_forged_matrix(&program, &vm.trace, vm.gas_limit, vm.gas_used, |values| {
                let at = |row: usize, col: usize| row * TRACE_WIDTH + col;
                let rows = values.len() / TRACE_WIDTH;
                let read = find_mem_row(values, TID_MEMORY, 0, 2);
                assert!(read + 1 < rows, "a padding row must follow the table");
                assert_eq!(values[at(read + 1, COL_MEM_ACTIVE)].as_canonical_u64(), 0);
                values[at(read + 1, COL_MEM_IS_INIT)] = Goldilocks::new(1);
            });
        assert!(
            verdict.is_err(),
            "the starting-image flag was accepted on a padding row. \
             verdict={verdict:?}"
        );
    }

    /// The starting-image flag marks the first row of a cell block and nothing
    /// else. Here the read after the write of memory cell 0 carries it.
    ///
    /// The flag moves the fold, so the forged matrix carries the new
    /// accumulator on the rows after the read, and the public root is the root
    /// of that one starting read. The fold, the root and the cell rules hold.
    /// Only the rule on the flag inside a block is left to refuse the table.
    #[test]
    fn rejects_memory_init_flag_inside_a_block() {
        let program = memory_zero_round_trip_program();
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the honest run must succeed");
        assert!(
            initial_memory_reads(&vm.trace).is_empty(),
            "the program must start from an empty memory image"
        );

        let key = mem_key(TID_MEMORY, 0);
        let verdict = verify_forged_matrix_with_reads(
            &program,
            &vm.trace,
            vm.gas_limit,
            vm.gas_used,
            vec![(key, 0)],
            |values| {
                let at = |row: usize, col: usize| row * TRACE_WIDTH + col;
                let rows = values.len() / TRACE_WIDTH;
                let write = find_mem_row(values, TID_MEMORY, 0, 1);
                let read = find_mem_row(values, TID_MEMORY, 0, 2);
                assert_eq!(read, write + 1);
                assert_eq!(values[at(write, COL_MEM_SAME)].as_canonical_u64(), 1);
                values[at(read, COL_MEM_IS_INIT)] = Goldilocks::new(1);
                // The fold of one starting read with value 0: key * gamma.
                let acc = Goldilocks::new(key) * Goldilocks::new(MEM_INIT_GAMMA);
                for row in read..rows {
                    values[at(row, COL_MEM_INIT_ACC)] = acc;
                }
            },
        );
        assert!(
            verdict.is_err(),
            "the starting-image flag was accepted inside a memory block. \
             verdict={verdict:?}"
        );
    }

    /// A prover must not relabel an instruction as a different one.
    ///
    /// Every per opcode rule in the AIR is written as
    /// `builder.when(is_<op>).assert_...`, so a rule only runs on rows where
    /// its selector is set. Booleanity and the exclusivity sum
    /// (`is_cpu == 1`) together say exactly one selector is set per row. They
    /// never said *which* one had to be set, and for 29 of the 35 selectors
    /// nothing else did either. Six were bound by hand to their opcode when
    /// the opcode they guard was audited; the rest were free witness columns.
    ///
    /// So this is the attack. Compile `constrain(x)`, which emits `Assert`,
    /// run it honestly, then in the trace set `is_assert = 0` and
    /// `is_mul = 1` on that row. Nothing about the row's data changes.
    ///
    /// It goes through because `Mul` demands
    /// `rd_val_new == rs1_val * rs2_val`, and the honest `Assert` row carries
    /// `rd_val_new = 0` with `rs2_val = 0`, so the identity reads `0 == x * 0`
    /// and holds for every `rs1_val`. Both opcodes charge the same unit gas,
    /// both are inside `is_real_op` so the exclusivity sum is still one, and
    /// the register, memory and program arguments do not look at which
    /// selector it was. `assert_one(rs1_val)`, the whole point of the
    /// instruction, is simply never evaluated.
    ///
    /// The program below runs an assertion that holds, so the row reaches the
    /// trace in the first place. A failing assertion cannot be used here: the
    /// VM returns from `step` before pushing the failing step, so there would
    /// be no Assert row left to relabel. What the forgery then demonstrates is
    /// that the rule stops being enforced on a row it governs, which is the
    /// property that matters. A prover holding this capability picks, per row,
    /// whether `assert_one(rs1_val)` applies, and would exercise it on exactly
    /// the rows where the assertion is about to fail.
    ///
    /// The fix binds every selector to `COL_OPCODE`, and binds `COL_OPCODE`
    /// itself to the committed program through the Program CTL, since the
    /// column was free too and pinning selectors to a free column would only
    /// move the forgery one step back.
    #[test]
    fn rejects_a_row_relabelled_as_a_different_opcode() {
        // r1 = 1; assert(r1); halt.
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 1),
            inst(Opcode::Assert, 0, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(
            receipt.success,
            "the honest program must run to completion, otherwise the failing \
             Assert never reaches the trace and there is nothing to relabel"
        );

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);

        // Find the Assert row by its opcode, not by its selector: the point of
        // the test is that the two can disagree.
        let mut assert_row = None;
        for i in 0..n_cpu {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_OPCODE].as_canonical_u64() == 0x18 {
                assert_row = Some(i);
                break;
            }
        }
        let assert_row = assert_row.expect("the trace must contain an Assert row");
        let row_start = assert_row * TRACE_WIDTH;

        // The preconditions the forgery relies on. If any of these stops
        // holding the substitution would fail for an unrelated reason and the
        // test would pass while proving nothing, so they are asserted rather
        // than assumed.
        assert_eq!(
            matrix.values[row_start + COL_IS_ASSERT].as_canonical_u64(),
            1,
            "the honest row must be marked as an Assert before it is relabelled"
        );
        assert_eq!(
            matrix.values[row_start + COL_RS2_VAL].as_canonical_u64(),
            0,
            "rs2 must be zero for the Mul identity to read 0 == x * 0"
        );
        assert_eq!(
            matrix.values[row_start + COL_RD_VAL_NEW].as_canonical_u64(),
            0,
            "rd must be zero for the Mul identity to read 0 == x * 0"
        );

        // The relabelling. Data untouched, only the two selectors move.
        matrix.values[row_start + COL_IS_ASSERT] = Goldilocks::new(0);
        matrix.values[row_start + COL_IS_MUL] = Goldilocks::new(1);
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "an Assert row relabelled as a Mul verified; assert_one(rs1_val) \
             is then something the prover turns off per row, and every \
             constrain(...) in BudL is optional"
        );
    }

    /// The opcode column must come from the committed program.
    ///
    /// The companion to the test above. Binding selectors to `COL_OPCODE` is
    /// only worth something if `COL_OPCODE` is itself pinned down, and it was
    /// not: the Program CTL carried `(pc, raw_inst)`, which tied the raw
    /// instruction word to the program ROM and said nothing at all about the
    /// opcode column sitting next to it. A prover could fetch the honest word
    /// at `pc` and write a different opcode beside it, then set the selector
    /// that matches the opcode it wrote, and both the CTL and the selector
    /// binding would be satisfied.
    ///
    /// Here the Assert row keeps its honest `raw_inst` but has its opcode
    /// column rewritten to `Mul`, with the selectors moved to agree. Only the
    /// opcode term added to the CTL tuple catches this.
    #[test]
    fn rejects_an_opcode_column_that_disagrees_with_the_program() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 1),
            inst(Opcode::Assert, 0, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(
            receipt.success,
            "the honest program must run to completion so the Assert row is in \
             the trace to be tampered with"
        );

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);

        let mut assert_row = None;
        for i in 0..n_cpu {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_OPCODE].as_canonical_u64() == 0x18 {
                assert_row = Some(i);
                break;
            }
        }
        let assert_row = assert_row.expect("the trace must contain an Assert row");
        let row_start = assert_row * TRACE_WIDTH;

        // The raw instruction word stays honest. That is the whole point: the
        // Program CTL is satisfied on the (pc, raw_inst) part of the tuple,
        // and only the opcode term can tell that the row is lying.
        let honest_word = matrix.values[row_start + COL_RAW_INST].as_canonical_u64();
        assert_eq!(
            honest_word & 0xFF,
            0x18,
            "the honest instruction word must decode to Assert, otherwise the \
             forgery below is not the substitution it claims to be"
        );

        matrix.values[row_start + COL_OPCODE] = Goldilocks::new(0x03);
        matrix.values[row_start + COL_IS_ASSERT] = Goldilocks::new(0);
        matrix.values[row_start + COL_IS_MUL] = Goldilocks::new(1);
        assert_eq!(
            matrix.values[row_start + COL_RAW_INST].as_canonical_u64(),
            honest_word,
            "the raw instruction word must be left alone by the forgery"
        );
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        assert!(
            Plonky3Adapter::verify(&envelope, &pi, &program).is_err(),
            "a row whose opcode column disagrees with the committed program \
             verified; binding selectors to that column would then be binding \
             them to nothing"
        );
    }

    /// A prover must not choose the quotient when the divisor is zero.
    ///
    /// The VM defines `x / 0 == 0`. The AIR's main division identity is
    ///
    /// ```text
    /// rd * rs2 - rs1 * (1 - div_zero) == 0
    /// ```
    ///
    /// which is vacuous at `rs2 = 0`: both sides are zero for **any** `rd`.
    /// A separate constraint pins it,
    ///
    /// ```text
    /// when(is_div * div_zero).assert_zero(rd)
    /// ```
    ///
    /// and that line carries a comment saying it exists so a malicious prover
    /// cannot pick an arbitrary quotient. The comment was the only evidence.
    /// Searching this file for a division-by-zero rejection returned nothing,
    /// so the constraint had never been shown to reject anything.
    ///
    /// This forges exactly that: a trace where the divide-by-zero row claims a
    /// non-zero result. Without the pinning constraint it verifies, because
    /// the main identity cannot see it.
    #[test]
    fn rejects_a_forged_quotient_when_dividing_by_zero() {
        // r2 = 7, r3 = 0, r1 = r2 / r3. The VM writes 0.
        let program = vec![
            inst(Opcode::Load, 2, 0, 0, 7),
            inst(Opcode::Load, 3, 0, 0, 0),
            inst(Opcode::Div, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the program itself must run");
        assert_eq!(
            vm.registers[1], 0,
            "the VM defines division by zero as zero; if that changed, this \
             test is pinning the wrong contract"
        );

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);

        // Find the Div row and confirm the trace really is the zero-divisor
        // case, so a change in row layout turns this into a failure rather
        // than a test that forges nothing.
        let mut div_row = None;
        for i in 0..n_cpu {
            let row_start = i * TRACE_WIDTH;
            if matrix.values[row_start + COL_IS_DIV].as_canonical_u64() == 1 {
                div_row = Some(i);
                break;
            }
        }
        let div_row = div_row.expect("the trace must contain a Div row");
        let row_start = div_row * TRACE_WIDTH;
        assert_eq!(
            matrix.values[row_start + COL_DIV_ZERO].as_canonical_u64(),
            1,
            "the div_zero flag must be set on this row, or the forgery below \
             is aimed at the wrong constraint"
        );
        assert_eq!(
            matrix.values[row_start + COL_RD_VAL_NEW].as_canonical_u64(),
            0,
            "the honest trace must write 0 before we forge a different value"
        );

        // The forgery: claim 7 / 0 == 12345.
        matrix.values[row_start + COL_RD_VAL_NEW] = Goldilocks::new(12345);
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            res.is_err(),
            "a proof claiming 7 / 0 == 12345 verified. The main division \
             identity is vacuous at rs2 = 0, so the only thing standing \
             between a prover and an arbitrary quotient is \
             `when(is_div * div_zero).assert_zero(rd)`, and it is not holding."
        );
    }

    /// A flipped direction bit must be refused.
    ///
    /// `merkle_bit` decides which side of the Poseidon pair the sibling goes
    /// on, so it is the part of a Merkle path that says *where* the leaf sits.
    /// It used to be constrained only to be boolean, and the AIR comment said
    /// outright that "the prover can simply provide a valid bit column".
    /// Measured against that version: flipping the round-0 bit, recomputing
    /// the whole chain from it and leaving `merkle_key` untouched produced a
    /// different root, and the proof still verified.
    ///
    /// `COL_MERKLE_KEY_REM` closes it with a shift chain
    /// (`rem == 2 * rem' + bit`, seeded from the key, terminating at zero), so
    /// a flipped bit no longer has a consistent remainder to sit in.
    #[test]
    fn rejects_verify_merkle_with_flipped_direction_bit() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        // key = 0 keeps every honest bit at 0, so flipping one is a clean,
        // single-variable change.
        vm.memory[256..264].copy_from_slice(&0u64.to_le_bytes());
        for i in 0..64 {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&((1000 + i) as u64).to_le_bytes());
        }
        let _ = vm.run_receipt(&program);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);

        // Flip the round-0 direction bit and recompute the Poseidon chain
        // from it, so the trace stays internally consistent everywhere the
        // old AIR looked. `merkle_key` is deliberately left alone, that is
        // the disagreement this test is about.
        let row1 = TRACE_WIDTH;
        let bit_before = matrix.values[row1 + COL_VM_MERKLE_BIT].as_canonical_u64();
        let cur0 = matrix.values[row1 + COL_VM_MERKLE_CURRENT].as_canonical_u64();
        let sib0 = matrix.values[row1 + COL_VM_MERKLE_SIBLING].as_canonical_u64();
        matrix.values[row1 + COL_VM_MERKLE_BIT] = Goldilocks::new(1 - bit_before);

        // Round 0's S-box witnesses have to be rebuilt too: flipping the bit
        // swaps which of (current, sibling) is s0. Leaving them stale would
        // trip the Poseidon identity instead, and the test would pass for a
        // reason that has nothing to do with the direction bit, which is
        // exactly what a first attempt at this test did.
        let (f0, f1) = if bit_before == 0 {
            (sib0, cur0)
        } else {
            (cur0, sib0)
        };
        for (i, v) in [f0, f1, 0, 0, 0, 0, 0, 0].iter().enumerate() {
            let x = Goldilocks::new(*v) + Goldilocks::new(bud_vm::POSEIDON_RC_FULL[0][i]);
            let x2 = x * x;
            matrix.values[row1 + COL_MERKLE_POSEIDON_X2_0 + i] = x2;
            matrix.values[row1 + COL_MERKLE_POSEIDON_X4_0 + i] = x2 * x2;
        }

        let mut running = bud_vm::merkle_poseidon_round(f0, f1);
        for round in 1..64usize {
            let base = (1 + round) * TRACE_WIDTH;
            matrix.values[base + COL_VM_MERKLE_CURRENT] = Goldilocks::new(running);
            let b = matrix.values[base + COL_VM_MERKLE_BIT].as_canonical_u64();
            let sib = matrix.values[base + COL_VM_MERKLE_SIBLING].as_canonical_u64();
            let (s0, s1) = if b == 0 {
                (running, sib)
            } else {
                (sib, running)
            };
            let state = [s0, s1, 0, 0, 0, 0, 0, 0];
            for (i, v) in state.iter().enumerate() {
                let x = Goldilocks::new(*v) + Goldilocks::new(bud_vm::POSEIDON_RC_FULL[0][i]);
                let x2 = x * x;
                matrix.values[base + COL_MERKLE_POSEIDON_X2_0 + i] = x2;
                matrix.values[base + COL_MERKLE_POSEIDON_X4_0 + i] = x2 * x2;
            }
            running = bud_vm::merkle_poseidon_round(s0, s1);
        }

        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);
        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        // Proving a trace that violates a constraint panics inside Plonky3, so
        // the attempt is caught. Whichever way it comes out, the tampered
        // trace must not end up as a verifying proof, and the two outcomes
        // are kept distinguishable rather than both being treated as success,
        // because "the prover panicked" would otherwise mask a missing
        // constraint just as well as a working one.
        let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_with_preprocessed(
                &config,
                &air,
                matrix.clone(),
                Some(crate::plonky3_prover::aux_trace_generator(
                    matrix.clone(),
                    n_cpu,
                    program.clone(),
                )),
                &public_values,
                preprocessed_ref,
            )
        }));

        let rejected_at_proving = attempted.is_err();
        let rejected_at_verification = match attempted {
            Err(_) => false,
            Ok(p3_proof) => {
                let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
                let envelope = ProofEnvelope {
                    proof_format_version: PROOF_FORMAT_VERSION,
                    backend: "Plonky3-Keccak-Goldilocks".to_string(),
                    p3_version: "0.5.2".to_string(),
                    fri_params_id: "test_fri_params".to_string(),
                    public_inputs_hash: pi.hash(),
                    proof_bytes,
                    degree_bits: degree_bits as u32,
                };
                Plonky3Adapter::verify_with_activation(
                    &envelope,
                    &pi,
                    &program,
                    bud_isa::MainnetActivation::full(),
                )
                .is_err()
            }
        };

        assert!(
            rejected_at_proving || rejected_at_verification,
            "a flipped Merkle direction bit produced a verifying proof: the \
             path would prove membership at a position the key does not \
             describe. proving_rejected={rejected_at_proving}, \
             verification_rejected={rejected_at_verification}"
        );
    }

    /// A claimed root the path did not produce must be refused.
    ///
    /// The root check compares the `merkle_current` cell of the **original**
    /// VerifyMerkle row against the claimed root (`rs1_val`). The prover
    /// writes the round-64 output into that cell - but no constraint forced
    /// it. The 64 expansion rows compute the Poseidon chain correctly row by
    /// row, and the result they arrive at was bound to nothing.
    ///
    /// The attacker builds the trace at VM level: it starts with a **valid**
    /// path (the same setup as `proves_verify_merkle_valid_64_depth`), then
    /// changes the claimed root and writes that new root into the original
    /// step's `merkle_current` field, declaring a match. The expansion rows
    /// are untouched - the chain stays internally consistent, only where it
    /// arrives is ignored. `trace_matrix` produces every derived column
    /// consistently from this trace, so there is no stale witness involved.
    ///
    /// Measured with the constraint removed: this proof **verified**
    /// (`verify` Ok). With the constraint it is refused. That was exactly the
    /// reason the opcode is kept off in production ("unfinished path
    /// verification").
    #[test]
    fn rejects_verify_merkle_root_not_produced_by_the_path() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let key: u64 = 7;
        let siblings: [u64; 64] = std::array::from_fn(|i| ((i as u64) * 31) + 1);
        let leaf: u64 = 0xBEEF;
        let mut current = leaf;
        for (i, &sibling) in siblings.iter().enumerate() {
            let bit = (key >> i) & 1;
            current = if bit == 0 {
                bud_vm::merkle_poseidon_round(current, sibling)
            } else {
                bud_vm::merkle_poseidon_round(sibling, current)
            };
        }
        let honest_root = current;
        vm.memory[256..264].copy_from_slice(&key.to_le_bytes());
        for (i, &sibling) in siblings.iter().enumerate() {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&sibling.to_le_bytes());
        }
        vm.registers[2] = honest_root;
        vm.registers[3] = leaf;

        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.trace.len(), 66);

        // The attack: a different root is claimed and the original step
        // carries that root instead of the result the path arrived at,
        // declaring a match.
        let forged_root = honest_root ^ 0xFFFF;
        let mut trace = vm.trace.clone();
        trace[0].src1_val = forged_root;
        trace[0].registers[2] = forged_root;
        trace[0].merkle_current = Some(forged_root);
        trace[0].dst_val = 1;
        for st in trace.iter_mut().skip(1) {
            st.registers[1] = 1;
            st.registers[2] = forged_root;
        }

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(
                    &crate::plonky3_prover::initial_memory_reads(&trace),
                ),
                crate::adapter::register_image_commitment_of_reads(
                    &crate::plonky3_prover::initial_register_reads(&trace),
                ),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Plonky3Adapter::prove(&trace, &pi, &program)
        }));

        let rejected_at_proving = match &attempted {
            Err(_) => true,
            Ok(Err(_)) => true,
            Ok(Ok(_)) => false,
        };
        let rejected_at_verification = match attempted {
            Ok(Ok(envelope)) => Plonky3Adapter::verify_with_activation(
                &envelope,
                &pi,
                &program,
                bud_isa::MainnetActivation::full(),
            )
            .is_err(),
            _ => false,
        };

        assert!(
            rejected_at_proving || rejected_at_verification,
            "a root the path did not produce verified: 64 rounds were computed \
             and their result skipped. proving_rejected={rejected_at_proving}, \
             verification_rejected={rejected_at_verification}"
        );
    }

    /// A public scalar at or above the modulus is the same field element as
    /// `value - p` (BLG-0218). One proof must not verify for both.
    #[test]
    fn rejects_a_non_canonical_public_scalar() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 5),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let (envelope, pi) = prove_and_verify_full(program.clone(), |_| {});
        assert!(pi.gas_used < 1 << 20);
        let mut alias = pi.clone();
        alias.gas_used += bud_vm::GOLDILOCKS_P;
        let mut aliased = envelope.clone();
        aliased.public_inputs_hash = alias.hash();
        assert!(matches!(
            Plonky3Adapter::verify(&aliased, &alias, &program),
            Err(VerifyError::PublicInputsMismatch)
        ));
    }

    /// An honest `VerifyMerkle` that does NOT match its claimed root must
    /// still be provable (BLG-0219). The inverse witness of `final - root`
    /// has to be taken in the field; with `wrapping_sub` it was wrong
    /// whenever the path result was below the claimed root.
    #[test]
    fn proves_an_honest_verify_merkle_mismatch_when_final_is_below_root() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let key: u64 = 7;
        let siblings: [u64; 64] = std::array::from_fn(|i| ((i as u64) * 31) + 1);
        let leaf: u64 = 0xBEEF;
        let mut current = leaf;
        for (i, &sibling) in siblings.iter().enumerate() {
            let bit = (key >> i) & 1;
            current = if bit == 0 {
                bud_vm::merkle_poseidon_round(current, sibling)
            } else {
                bud_vm::merkle_poseidon_round(sibling, current)
            };
        }
        // The claimed root is above the path result, so `final < root`.
        assert!(current < bud_vm::GOLDILOCKS_P - 1);
        let claimed_root = current + 1;
        vm.memory[256..264].copy_from_slice(&key.to_le_bytes());
        for (i, &sibling) in siblings.iter().enumerate() {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&sibling.to_le_bytes());
        }
        vm.registers[2] = claimed_root;
        vm.registers[3] = leaf;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.trace.len(), 66);
        assert_eq!(vm.trace[0].dst_val, 0, "the honest result is a mismatch");

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);
        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).expect("honest proof");
        Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full(),
        )
        .expect("an honest mismatch must verify");
    }

    /// (security audit) negative test for the Merkle
    /// Expansion row transition. We take a valid VerifyMerkle
    /// Trace (1 original + 64 expansion + 1 Halt = 66 rows) and
    /// Tamper with one expansion row's `merkle_round` column so
    /// That two consecutive expansion rows report the same round
    /// Index. The AIR transition
    ///   `is_expand * is_expand * (nxt_round - round - 1) = 0`
    /// Forces the round index to increment by exactly 1 on every
    /// Active transition, so this tampering is detected.
    /// A sibling the program never read must not verify.
    ///
    /// `merkle_sibling` used to be a free witness column: the AIR consumed it
    /// as a Poseidon input and nothing tied it to the bytes at
    /// `path_addr + 8 + 8 * round`. Measured before the fix - 64 expansion
    /// rows, 0 carrying a `memory_addr`, and 0 of the 65 path words present in
    /// the memory argument - so a prover could walk a path that was never
    /// written and still produce a verifying proof.
    ///
    /// The expansion rows now emit their reads, and the LogUp demands them at
    /// the address the instruction's immediate implies, so swapping a sibling
    /// for one the memory table does not supply leaves the argument
    /// unbalanced.
    #[test]
    fn rejects_verify_merkle_with_a_sibling_not_in_memory() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        vm.memory[256..264].copy_from_slice(&0u64.to_le_bytes());
        for i in 0..64 {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&((1000 + i) as u64).to_le_bytes());
        }
        let _ = vm.run_receipt(&program);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(
                    &crate::plonky3_prover::initial_memory_reads(&vm.trace),
                ),
                crate::adapter::register_image_commitment_of_reads(
                    &crate::plonky3_prover::initial_register_reads(&vm.trace),
                ),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);

        // Replace round 0's sibling with a value the program never read, and
        // rebuild the Poseidon chain from it so the trace stays internally
        // consistent everywhere except the memory argument.
        let row1 = TRACE_WIDTH;
        let cur0 = matrix.values[row1 + COL_VM_MERKLE_CURRENT].as_canonical_u64();
        let bit0 = matrix.values[row1 + COL_VM_MERKLE_BIT].as_canonical_u64();
        let forged_sibling = 424_242u64;
        matrix.values[row1 + COL_VM_MERKLE_SIBLING] = Goldilocks::new(forged_sibling);

        let (f0, f1) = if bit0 == 0 {
            (cur0, forged_sibling)
        } else {
            (forged_sibling, cur0)
        };
        for (i, v) in [f0, f1, 0, 0, 0, 0, 0, 0].iter().enumerate() {
            let x = Goldilocks::new(*v) + Goldilocks::new(bud_vm::POSEIDON_RC_FULL[0][i]);
            let x2 = x * x;
            matrix.values[row1 + COL_MERKLE_POSEIDON_X2_0 + i] = x2;
            matrix.values[row1 + COL_MERKLE_POSEIDON_X4_0 + i] = x2 * x2;
        }
        let mut running = bud_vm::merkle_poseidon_round(f0, f1);
        for round in 1..64usize {
            let base = (1 + round) * TRACE_WIDTH;
            matrix.values[base + COL_VM_MERKLE_CURRENT] = Goldilocks::new(running);
            let b = matrix.values[base + COL_VM_MERKLE_BIT].as_canonical_u64();
            let sib = matrix.values[base + COL_VM_MERKLE_SIBLING].as_canonical_u64();
            let (s0, s1) = if b == 0 {
                (running, sib)
            } else {
                (sib, running)
            };
            for (i, v) in [s0, s1, 0, 0, 0, 0, 0, 0].iter().enumerate() {
                let x = Goldilocks::new(*v) + Goldilocks::new(bud_vm::POSEIDON_RC_FULL[0][i]);
                let x2 = x * x;
                matrix.values[base + COL_MERKLE_POSEIDON_X2_0 + i] = x2;
                matrix.values[base + COL_MERKLE_POSEIDON_X4_0 + i] = x2 * x2;
            }
            running = bud_vm::merkle_poseidon_round(s0, s1);
        }

        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);
        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_with_preprocessed(
                &config,
                &air,
                matrix.clone(),
                Some(crate::plonky3_prover::aux_trace_generator(
                    matrix.clone(),
                    n_cpu,
                    program.clone(),
                )),
                &public_values,
                preprocessed_ref,
            )
        }));

        let rejected_at_proving = attempted.is_err();
        let rejected_at_verification = match attempted {
            Err(_) => false,
            Ok(p3_proof) => {
                let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
                let envelope = ProofEnvelope {
                    proof_format_version: PROOF_FORMAT_VERSION,
                    backend: "Plonky3-Keccak-Goldilocks".to_string(),
                    p3_version: "0.5.2".to_string(),
                    fri_params_id: "test_fri_params".to_string(),
                    public_inputs_hash: pi.hash(),
                    proof_bytes,
                    degree_bits: degree_bits as u32,
                };
                Plonky3Adapter::verify_with_activation(
                    &envelope,
                    &pi,
                    &program,
                    bud_isa::MainnetActivation::full(),
                )
                .is_err()
            }
        };

        assert!(
            rejected_at_proving || rejected_at_verification,
            "a sibling that memory never supplied produced a verifying proof: \
             the path would prove membership under values the program never \
             read. proving_rejected={rejected_at_proving}, \
             verification_rejected={rejected_at_verification}"
        );
    }

    #[test]
    fn rejects_verify_merkle_with_skipped_round() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        // Populate path memory at addr 256.
        vm.memory[256..264].copy_from_slice(&7u64.to_le_bytes());
        for i in 0..64 {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&((1000 + i) as u64).to_le_bytes());
        }
        let _ = vm.run_receipt(&program);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        // Tamper row 5 (the 5th expansion row, round 4): copy the
        // Round index from row 6 (round 5) so we have two rows
        // Claiming round=5. The AIR's round transition
        // `nxt_round - cur_round - 1 = 0` is then violated on the
        // 4->5 transition.
        let row_5 = (1 + 5) * TRACE_WIDTH;
        let row_6 = (1 + 6) * TRACE_WIDTH;
        matrix.values[row_5 + COL_VM_MERKLE_ROUND] = matrix.values[row_6 + COL_VM_MERKLE_ROUND];
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        let res = Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full(),
        );
        assert!(
            res.is_err(),
            "Expected verification to FAIL with a skipped Merkle round, but it succeeded!"
        );
    }

    /// (security audit) positive test for
    /// The Poseidon single-round + final root check. We build a
    /// Program that runs VerifyMerkle on a *real* 64-depth path
    /// (constructed by walking the path in software) and assert
    /// The proof verifies end-to-end.
    ///
    /// Commit 3.5 target: valid 64-depth path. Partial fixes landed in
    /// (pre-round currents, single-round hash align, original-only
    /// Root check, expand gas). The test below is not ignored.
    /// Diagnostic: check expansion Poseidon chain + leaf bind on matrix
    /// Without running the full STARK (isolates witness vs AIR constraint bugs).
    #[test]
    fn diagnose_verify_merkle_matrix_chain() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let key: u64 = 7;
        let siblings: [u64; 64] = std::array::from_fn(|i| ((i as u64) * 31) + 1);
        let leaf: u64 = 0xBEEF;
        let mut current = leaf;
        for (i, &sibling) in siblings.iter().enumerate() {
            let bit = (key >> i) & 1;
            current = if bit == 0 {
                bud_vm::merkle_poseidon_round(current, sibling)
            } else {
                bud_vm::merkle_poseidon_round(sibling, current)
            };
        }
        let root = current;
        vm.memory[256..264].copy_from_slice(&key.to_le_bytes());
        for (i, &sibling) in siblings.iter().enumerate() {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&sibling.to_le_bytes());
        }
        vm.registers[2] = root;
        vm.registers[3] = leaf;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "VM must accept valid path");
        assert_eq!(vm.trace.len(), 66);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);
        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };
        let (matrix, _n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        assert_eq!(matrix.values.len() % TRACE_WIDTH, 0);
        let n_rows = matrix.values.len() / TRACE_WIDTH;

        // Row 0 = original VerifyMerkle
        let r0 = 0;
        let is_exp0 = matrix.values[r0 * TRACE_WIDTH + COL_VM_MERKLE_IS_EXPAND].as_canonical_u64();
        let final_flag = matrix.values[r0 * TRACE_WIDTH + COL_MERKLE_FINAL_FLAG].as_canonical_u64();
        let orig_cur = matrix.values[r0 * TRACE_WIDTH + COL_VM_MERKLE_CURRENT].as_canonical_u64();
        let is_vm = matrix.values[r0 * TRACE_WIDTH + COL_IS_VERIFY_MERKLE].as_canonical_u64();
        let rd_new = matrix.values[r0 * TRACE_WIDTH + COL_RD_VAL_NEW].as_canonical_u64();
        println!(
            "row0: is_expand={is_exp0} final_flag={final_flag} is_vm={is_vm} merkle_current={orig_cur:#x} root={root:#x} rd_new={rd_new}"
        );
        assert_eq!(is_exp0, 0);
        assert_eq!(final_flag, 1);
        assert_eq!(is_vm, 1);
        assert_eq!(
            orig_cur, root,
            "original merkle_current must be final path root"
        );
        assert_eq!(rd_new, 1, "dst must be 1 for valid path");

        // Expansion rows 1..64 (round 0..63)
        let mut expected = leaf;
        for round in 0..64u64 {
            let r = (round + 1) as usize; // row index
            let base = r * TRACE_WIDTH;
            let is_exp = matrix.values[base + COL_VM_MERKLE_IS_EXPAND].as_canonical_u64();
            let cur = matrix.values[base + COL_VM_MERKLE_CURRENT].as_canonical_u64();
            let sib = matrix.values[base + COL_VM_MERKLE_SIBLING].as_canonical_u64();
            let bit = matrix.values[base + COL_VM_MERKLE_BIT].as_canonical_u64();
            let rnd = matrix.values[base + COL_VM_MERKLE_ROUND].as_canonical_u64();
            let is_vm_r = matrix.values[base + COL_IS_VERIFY_MERKLE].as_canonical_u64();
            assert_eq!(is_exp, 1, "row {r} expand");
            assert_eq!(rnd, round, "row {r} round");
            assert_eq!(
                is_vm_r, 1,
                "expansion still has opcode 0x1E so is_verify_merkle=1"
            );
            assert_eq!(cur, expected, "row {r} pre-round current");
            assert_eq!(bit, (key >> round) & 1);
            assert_eq!(sib, siblings[round as usize]);
            let out = if bit == 0 {
                bud_vm::merkle_poseidon_round(cur, sib)
            } else {
                bud_vm::merkle_poseidon_round(sib, cur)
            };
            // Next row current
            if round < 63 {
                let nxt =
                    matrix.values[(r + 1) * TRACE_WIDTH + COL_VM_MERKLE_CURRENT].as_canonical_u64();
                assert_eq!(nxt, out, "poseidon chain break at round {round}");
            } else {
                // Last expand: output should equal root / original.merkle_current
                assert_eq!(out, root, "last expand poseidon output must equal root");
            }
            expected = out;
        }
        println!("matrix chain OK for 64-depth path (n_rows={n_rows})");
    }

    /// Q15 depth_1_test - 1 meaningful sibling, but VM always does 64 rounds (66 rows total)
    /// This isolates whether InvalidProof is due to row count (64 vs small), we still do 64 rounds,
    /// But 63 siblings are zero, so Poseidon chain is simple.
    #[test]
    fn proves_verify_merkle_valid_1_depth() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let key: u64 = 0; // bit0=0, rest 0
        let siblings: [u64; 64] = {
            let mut arr = [0u64; 64];
            arr[0] = 1;
            arr
        };
        let leaf: u64 = 0xBEEF;
        let mut cur = leaf;
        for (i, &sib) in siblings.iter().enumerate() {
            let bit = (key >> i) & 1;
            cur = if bit == 0 {
                bud_vm::merkle_poseidon_round(cur, sib)
            } else {
                bud_vm::merkle_poseidon_round(sib, cur)
            };
        }
        let root = cur;
        vm.memory[256..264].copy_from_slice(&key.to_le_bytes());
        for (i, &sib) in siblings.iter().enumerate() {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&sib.to_le_bytes());
        }
        vm.registers[2] = root;
        vm.registers[3] = leaf;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.trace.len(), 66); // VM always 1+64+1
        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);
        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            // The VerifyMerkle path words are read from memory, so they are
            // now part of the initial-memory commitment. Derive it rather
            // than asserting a zero root: a hard-coded value here would have
            // to be updated by hand every time the path changes, and getting
            // it wrong looks exactly like a soundness failure.
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(
                    &crate::plonky3_prover::initial_memory_reads(&vm.trace),
                ),
                crate::adapter::register_image_commitment_of_reads(
                    &crate::plonky3_prover::initial_register_reads(&vm.trace),
                ),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        let res = Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full(),
        );
        assert!(res.is_ok(), "1-depth should succeed: {:?}", res);
    }

    /// Q15 depth_2_test - 2 meaningful siblings, rest zero, still 66 rows
    #[test]
    fn proves_verify_merkle_valid_2_depth() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let key: u64 = 2; // binary 10 -> bit0=0, bit1=1
        let siblings: [u64; 64] = {
            let mut arr = [0u64; 64];
            arr[0] = 10;
            arr[1] = 20;
            arr
        };
        let leaf: u64 = 0xBEEF;
        let mut cur = leaf;
        for (i, &sib) in siblings.iter().enumerate() {
            let bit = (key >> i) & 1;
            cur = if bit == 0 {
                bud_vm::merkle_poseidon_round(cur, sib)
            } else {
                bud_vm::merkle_poseidon_round(sib, cur)
            };
        }
        let root = cur;
        vm.memory[256..264].copy_from_slice(&key.to_le_bytes());
        for (i, &sib) in siblings.iter().enumerate() {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&sib.to_le_bytes());
        }
        vm.registers[2] = root;
        vm.registers[3] = leaf;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.trace.len(), 66); // 1 original + 2 expansion + Halt
        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);
        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            // The VerifyMerkle path words are read from memory, so they are
            // now part of the initial-memory commitment. Derive it rather
            // than asserting a zero root: a hard-coded value here would have
            // to be updated by hand every time the path changes, and getting
            // it wrong looks exactly like a soundness failure.
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(
                    &crate::plonky3_prover::initial_memory_reads(&vm.trace),
                ),
                crate::adapter::register_image_commitment_of_reads(
                    &crate::plonky3_prover::initial_register_reads(&vm.trace),
                ),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        let res = Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full(),
        );
        assert!(res.is_ok(), "2-depth should succeed: {:?}", res);
    }

    #[test]
    fn proves_verify_merkle_valid_64_depth() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        // Build a deterministic path: key=7, siblings = (i*31) for
        // I=0..63. Compute the leaf and root in software.
        let key: u64 = 7;
        let siblings: [u64; 64] = std::array::from_fn(|i| ((i as u64) * 31) + 1);
        let leaf: u64 = 0xBEEF;
        let mut current = leaf;
        for (i, &sibling) in siblings.iter().enumerate() {
            let bit = (key >> i) & 1;
            current = if bit == 0 {
                bud_vm::merkle_poseidon_round(current, sibling)
            } else {
                bud_vm::merkle_poseidon_round(sibling, current)
            };
        }
        let root = current;
        vm.memory[256..264].copy_from_slice(&key.to_le_bytes());
        for (i, &sibling) in siblings.iter().enumerate() {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&sibling.to_le_bytes());
        }
        vm.registers[2] = root;
        vm.registers[3] = leaf;

        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        // 1 original + 64 expansion + 1 Halt = 66 rows.
        assert_eq!(vm.trace.len(), 66);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            // The VerifyMerkle path words are read from memory, so they are
            // now part of the initial-memory commitment. Derive it rather
            // than asserting a zero root: a hard-coded value here would have
            // to be updated by hand every time the path changes, and getting
            // it wrong looks exactly like a soundness failure.
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(
                    &crate::plonky3_prover::initial_memory_reads(&vm.trace),
                ),
                crate::adapter::register_image_commitment_of_reads(
                    &crate::plonky3_prover::initial_register_reads(&vm.trace),
                ),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        // End-to-end: prove and verify. If the AIR's Poseidon
        // Single-round transition or final root check is broken,
        // Verification will fail.
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        let res = Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full(),
        );
        assert!(
            res.is_ok(),
            "Expected verification to SUCCEED for a valid 64-depth path, but it failed: {:?}",
            res
        );
    }

    /// (security audit) negative test for
    /// The final root check. Build a valid path, then tamper the
    /// 64th expansion row's merkle_current to a value that
    /// Doesn't match the (real) root. The inverse-witness check
    /// Should reject.
    #[test]
    fn rejects_verify_merkle_with_tampered_final_accumulator() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let key: u64 = 7;
        let siblings: [u64; 64] = std::array::from_fn(|i| ((i as u64) * 31) + 1);
        let leaf: u64 = 0xBEEF;
        let mut current = leaf;
        for (i, &sibling) in siblings.iter().enumerate() {
            let bit = (key >> i) & 1;
            current = if bit == 0 {
                bud_vm::merkle_poseidon_round(current, sibling)
            } else {
                bud_vm::merkle_poseidon_round(sibling, current)
            };
        }
        let root = current;
        vm.memory[256..264].copy_from_slice(&key.to_le_bytes());
        for (i, &sibling) in siblings.iter().enumerate() {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&sibling.to_le_bytes());
        }
        vm.registers[2] = root;
        vm.registers[3] = leaf;
        let _ = vm.run_receipt(&program);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        // Tamper the 64th expansion row (row 1+63=64) by setting
        // Merkle_current to a value that does NOT equal the root
        // But still passes the Poseidon transition (we keep the
        // Next row's merkle_current unchanged, but the next row
        // Is the original step which has merkle_current = root;
        // The AIR's transition nxt = poseidon(cur) would fail on
        // This row). To make the test focus on the *final root
        // Check*, we keep the Poseidon transition intact and
        // Instead tamper the original step's merkle_current
        // (row 0): we change it to (root + 1) so the inverse
        // Witness on the original step's row fails.
        let row_0 = 0; // base offset of trace row 0
        let new_root = root.wrapping_add(1);
        matrix.values[row_0 + COL_VM_MERKLE_CURRENT] = Goldilocks::new(new_root);
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        let res = Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full(),
        );
        assert!(
            res.is_err(),
            "Expected verification to FAIL with a tampered final accumulator, but it succeeded!"
        );
    }

    /// (security audit) negative test for
    /// The Poseidon single-round transition. Build a valid path,
    /// Then tamper one expansion row's Poseidon x^2 witness. The
    /// S-box identity check should reject.
    #[test]
    fn rejects_verify_merkle_with_tampered_poseidon_sbox() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let key: u64 = 7;
        let siblings: [u64; 64] = std::array::from_fn(|i| ((i as u64) * 31) + 1);
        let leaf: u64 = 0xBEEF;
        let mut current = leaf;
        for (i, &sibling) in siblings.iter().enumerate() {
            let bit = (key >> i) & 1;
            current = if bit == 0 {
                bud_vm::merkle_poseidon_round(current, sibling)
            } else {
                bud_vm::merkle_poseidon_round(sibling, current)
            };
        }
        let root = current;
        vm.memory[256..264].copy_from_slice(&key.to_le_bytes());
        for (i, &sibling) in siblings.iter().enumerate() {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&sibling.to_le_bytes());
        }
        vm.registers[2] = root;
        vm.registers[3] = leaf;
        let _ = vm.run_receipt(&program);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        // Tamper the Poseidon x^2 witness on round 5 (row 1+5=6)
        // So the S-box identity x^2 = (s + rc)^2 fails.
        let row_6 = (1 + 5) * TRACE_WIDTH;
        matrix.values[row_6 + COL_MERKLE_POSEIDON_X2_0] = Goldilocks::new(12345);
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        let res = Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full(),
        );
        assert!(
            res.is_err(),
            "Expected verification to FAIL with a tampered Poseidon S-box, but it succeeded!"
        );
    }

    // --- Soundness negative tests (tampered trace rejection) ---

    /// (security audit) negative test for the termination
    /// Constraint. The last "real" (cpu_active=1) row in a trace must be
    /// A Halt. We take a valid Add + Halt program, then surgically
    /// Rewrite the *last* step's `COL_OPCODE` and `COL_IS_HALT` columns
    /// So that the row reads as an `Add` (is_halt=0, cpu_active=1) and
    /// The row immediately after is the (cpu_active=0, is_halt=1)
    /// Padding. This violates; verification must reject the proof.
    #[test]
    fn rejects_trace_with_non_halt_termination() {
        let program = vec![
            inst(Opcode::Add, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        vm.registers[2] = 10;
        vm.registers[3] = 20;
        let _receipt = vm.run_receipt(&program);
        assert!(_receipt.success);
        assert!(matches!(
            vm.trace.last().unwrap().instruction.opcode,
            Opcode::Halt
        ));

        // (security audit) build `pi` first so we can
        // Pass it into `trace_matrix` for the public-input binding
        // Columns (final_state_root, initial_state_root, gas_limit,
        // Trace_len).
        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash: {
                // The real program hash: a zero hash is refused at the
                // envelope check before the AIR runs, which would make this
                // test pass whatever the termination rule does.
                let program_bytes: Vec<u8> = program
                    .iter()
                    .flat_map(|&inst| inst.to_le_bytes().to_vec())
                    .collect();
                let mut hasher = Keccak::v256();
                hasher.update(&program_bytes);
                let mut program_hash = [0u8; 32];
                hasher.finalize(&mut program_hash);
                program_hash
            },
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: 1000000,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        // Build the matrix, then mutate the *last* real row to look like
        // A non-Halt step while leaving cpu_active=1 on it. The padding
        // Row right after will then read as cpu_active=0, is_halt=1
        // (already correct) but the 1->0 transition lands on a non-Halt
        // Row, which the new constraint forbids.
        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        // The trace has 2 rows: row 0 = Add, row 1 = Halt. We rewrite
        // Row 1's opcode/is_halt so the row looks like an Add (the
        // Existing arithmetic constraints force dst_val=10+20=30, but
        // We don't care - the *transition* 1->0 is the violation).
        let last = n_cpu - 1;
        let row_start = last * TRACE_WIDTH;
        matrix.values[row_start + COL_OPCODE] = Goldilocks::new(Opcode::Add as u64);
        matrix.values[row_start + COL_IS_HALT] = Goldilocks::new(0);
        matrix.values[row_start + COL_IS_ADD] = Goldilocks::new(1);
        // The padding row (row 2) was already cpu_active=0, is_halt=1.
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };

        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            matches!(res, Err(VerifyError::InvalidProof)),
            "Expected the AIR to refuse non-Halt termination (Z-C), got {res:?}"
        );
    }

    // --- (security audit): public-input binding tests ---

    /// Helper: prove a trivial Add+Halt program and return the envelope + the
    /// public inputs.
    ///
    /// BLG-0232 (P14-F02): the old helper doc claimed the caller's
    /// between-prove-and-verify mutation "asserts that the AIR rejects" -
    /// it asserted nothing of the sort. The envelope pins
    /// `public_inputs_hash`, so a mutated `pi` was always refused at the
    /// envelope gate (`VerifyError::PublicInputsMismatch`) and the AIR never
    /// ran. Each binding test now (a) asserts THAT variant by name - the
    /// envelope gate is a real line of defense and it should stay green by
    /// its own name, and (b) for roots, an extra test that bakes the forged
    /// value in BEFORE proving (via `build_arith_proof_forged`), so the
    /// envelope agrees and only the AIR's fold-vs-column constraint can
    /// reject. Fields whose AIR binding is an equality to the public inputs
    /// the prover itself copies (gas_limit, chain_id, exit_code, trace_len,
    /// event digest limbs 1..7) would PASS such a test - that gap is the
    /// AIR-side finding P12-F04/P13-F01, tracked there, not papered over
    /// by a test that asserts acceptance.
    fn build_arith_proof() -> (ProofEnvelope, ExecutionPublicInputs, Vec<u64>) {
        build_arith_proof_forged(|_| {})
    }

    /// Prove with a FORGED public input baked in before proving: the envelope
    /// hash matches the forged values, so a verification failure can only
    /// come from the AIR constraints (BLG-0232/P14-F02).
    fn build_arith_proof_forged(
        forge: impl FnOnce(&mut ExecutionPublicInputs),
    ) -> (ProofEnvelope, ExecutionPublicInputs, Vec<u64>) {
        let program = vec![
            inst(Opcode::Add, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        vm.registers[2] = 10;
        vm.registers[3] = 20;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let mut pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        forge(&mut pi);
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        (envelope, pi, program)
    }

    #[test]
    fn rejects_tampered_final_state_root() {
        let (envelope, mut pi, program) = build_arith_proof();
        // Forge final_state_root to a non-zero value.
        pi.final_state_root = [0xAB; 32];
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            matches!(res, Err(VerifyError::PublicInputsMismatch)),
            "a pi the envelope was not built for must die at the envelope hash gate, got {res:?}"
        );
    }

    /// The AIR-level version of the test above: the forgery is baked in
    /// BEFORE proving, so the envelope agrees and only the constraint that
    /// compares the committed final memory fold against `COL_FINAL_ROOT` can
    /// reject (BLG-0232/P14-F02).
    #[test]
    fn air_rejects_a_forged_final_state_root_baked_in_before_proving() {
        let (envelope, pi, program) =
            build_arith_proof_forged(|pi| pi.final_state_root = [0xAB; 32]);
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            matches!(res, Err(VerifyError::InvalidProof)),
            "the final-root fold constraint must refuse a trace that commits to a root the execution never produced, got {res:?}"
        );
    }

    #[test]
    fn rejects_tampered_initial_state_root() {
        let (envelope, mut pi, program) = build_arith_proof();
        pi.initial_state_root = [0xCD; 32];
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            matches!(res, Err(VerifyError::PublicInputsMismatch)),
            "a pi the envelope was not built for must die at the envelope hash gate, got {res:?}"
        );
    }

    /// BLG-0232 (P14-F02): the initial image is bound through the
    /// commitment of the read rows; baked in, the fold comparison still
    /// refuses the forgery.
    #[test]
    fn air_rejects_a_forged_initial_state_root_baked_in_before_proving() {
        let (envelope, pi, program) =
            build_arith_proof_forged(|pi| pi.initial_state_root = [0xCD; 32]);
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            matches!(res, Err(VerifyError::InvalidProof)),
            "the initial-root fold constraint must refuse a forged starting image, got {res:?}"
        );
    }

    #[test]
    fn rejects_tampered_gas_limit() {
        let (envelope, mut pi, program) = build_arith_proof();
        // Gas_limit differs from what the trace recorded.
        pi.gas_limit = pi.gas_limit.wrapping_add(1);
        // BLG-0232 (P14-F02): the rejection here is the envelope hash gate -
        // pinned by variant, not by `is_err`. An AIR-level binding for
        // gas_limit is P12-F04's job (the column's only reader is the compare
        // to public inputs the prover copies), so baking this forgery in
        // would prove the hole, not close it.
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            matches!(res, Err(VerifyError::PublicInputsMismatch)),
            "a pi the envelope was not built for must die at the envelope hash gate, got {res:?}"
        );
    }

    #[test]
    fn rejects_tampered_trace_len() {
        let (envelope, mut pi, program) = build_arith_proof();
        // Bump trace_len by one - should fail because
        // COL_TRACE_LEN_CTR was set to n_cpu (which doesn't change).
        pi.trace_len = pi.trace_len.wrapping_add(1);
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            matches!(res, Err(VerifyError::PublicInputsMismatch)),
            "a pi the envelope was not built for must die at the envelope hash gate, got {res:?}"
        );
    }

    #[test]
    fn rejects_tampered_event_digest() {
        let (envelope, mut pi, program) = build_arith_proof();
        // Forge event_digest: the trace has no Log opcodes so the
        // Accumulator is 0; the verifier must reject any non-zero
        // Public event_digest.
        pi.event_digest = [0xEF; 32];
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            matches!(res, Err(VerifyError::PublicInputsMismatch)),
            "a pi the envelope was not built for must die at the envelope hash gate, got {res:?}"
        );
    }

    #[test]
    fn rejects_tampered_exit_code() {
        let (envelope, mut pi, program) = build_arith_proof();
        // Forge exit_code from 0 (success) to 1 (error).
        pi.exit_code = 1;
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            matches!(res, Err(VerifyError::PublicInputsMismatch)),
            "a pi the envelope was not built for must die at the envelope hash gate, got {res:?}"
        );
    }

    #[test]
    fn rejects_tampered_chain_id() {
        let (envelope, mut pi, program) = build_arith_proof();
        // Forge chain_id: change the low 32 bits.
        pi.chain_id = 0xDEAD_BEEF;
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            matches!(res, Err(VerifyError::PublicInputsMismatch)),
            "a pi the envelope was not built for must die at the envelope hash gate, got {res:?}"
        );
    }

    #[test]
    fn rejects_tampered_comparison_result() {
        let program = vec![inst(Opcode::Lt, 1, 2, 3, 0), inst(Opcode::Halt, 0, 0, 0, 0)];
        prove_fails_after_tamper(
            program,
            |vm| {
                vm.registers[2] = 5;
                vm.registers[3] = 10;
            },
            |trace| {
                // 5 < 10 -> should be 1. Tamper to 0.
                trace[0].dst_val = 0;
            },
        );
    }

    #[test]
    fn rejects_tampered_bitwise_and_result() {
        let program = vec![
            inst(Opcode::And, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_fails_after_tamper(
            program,
            |vm| {
                vm.registers[2] = 0b1100;
                vm.registers[3] = 0b1010;
            },
            |trace| {
                // 0b1100 & 0b1010 = 0b1000 = 8. Tamper to 0.
                trace[0].dst_val = 0;
            },
        );
    }

    #[test]
    fn rejects_tampered_poseidon_sbox() {
        let program = vec![
            inst(Opcode::Poseidon, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        vm.registers[2] = 42;
        vm.registers[3] = 7;
        let _receipt = vm.run_receipt(&program);
        assert!(_receipt.success);

        // (security audit) build `pi` first so we can
        // Pass it into `trace_matrix` for the public-input binding
        // Columns (final_state_root, initial_state_root, gas_limit,
        // Trace_len).
        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash: {
                // The real program hash: a zero hash is refused at the
                // envelope check before the AIR runs and the test would
                // pass whatever the S-box constraint does.
                let program_bytes: Vec<u8> = program
                    .iter()
                    .flat_map(|&inst| inst.to_le_bytes().to_vec())
                    .collect();
                let mut hasher = Keccak::v256();
                hasher.update(&program_bytes);
                let mut program_hash = [0u8; 32];
                hasher.finalize(&mut program_hash);
                program_hash
            },
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: 1000000,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        // Tamper the trace matrix directly: corrupt an S-box intermediate (x2) column
        let (mut matrix, _trace_len) = trace_matrix(&vm.trace, &program, &pi);
        // Round 0, lane 0 S-box square. 290 lies inside the state block, so
        // the earlier version of this test never touched an S-box witness.
        matrix.values[crate::plonky3_air::COL_POSEIDON_X2_BASE] = Goldilocks::new(999);
        // Re-wrap in RowMajorMatrix
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };

        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        // Proving with tampered S-box should still produce a proof, but...
        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                _trace_len,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );

        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        // ...verification should FAIL because the S-box constraint is violated
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            matches!(res, Err(VerifyError::InvalidProof)),
            "Expected the AIR to refuse a tampered S-box, got {res:?}"
        );
    }

    #[test]
    fn rejects_tampered_storage_write_result() {
        let program = vec![
            inst(Opcode::SWrite, 0, 1, 0, 5),
            inst(Opcode::SRead, 2, 0, 0, 5),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_fails_after_tamper(
            program,
            |vm| {
                vm.registers[1] = 99;
            },
            |trace| {
                // Tamper the read-back value
                trace[1].dst_val = 404;
            },
        );
    }

    #[test]
    fn proves_verify_merkle_returning_zero_for_an_incorrect_root() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let key: u64 = 7;
        let siblings: [u64; 64] = [1; 64];
        let leaf: u64 = 0xBEEF;
        // Incorrect root
        let wrong_root = 0xBAD_C0DE;

        vm.memory[256..264].copy_from_slice(&key.to_le_bytes());
        for (i, sibling) in siblings.iter().enumerate() {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&sibling.to_le_bytes());
        }
        vm.registers[2] = wrong_root;
        vm.registers[3] = leaf;

        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        // The VM should return 0 in rd_val_new because root doesn't match
        assert_eq!(vm.registers[1], 0);

        // The public inputs must bind to the REAL program hash: verify
        // Recomputes keccak(program) and rejects dummies.
        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut real_program_hash = [0u8; 32];
        hasher.finalize(&mut real_program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash: real_program_hash,
            // The VerifyMerkle path words are read from memory, so they are
            // now part of the initial-memory commitment. Derive it rather
            // than asserting a zero root: a hard-coded value here would have
            // to be updated by hand every time the path changes, and getting
            // it wrong looks exactly like a soundness failure.
            initial_state_root: crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(
                    &crate::plonky3_prover::initial_memory_reads(&vm.trace),
                ),
                crate::adapter::register_image_commitment_of_reads(
                    &crate::plonky3_prover::initial_register_reads(&vm.trace),
                ),
            ),
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        // This proof SHOULD verify because we are proving that the VM
        // CORRECTLY COMPUTES '0' when the root doesn't match.
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        assert!(Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full()
        )
        .is_ok());
    }

    /// VerifyInference AIR binding soundness test.
    /// Build a trace containing a VerifyInference row and verify that
    /// The AIR rejects a tampered trace where the `is_verify_inference`
    /// Selector is zeroed out while COL_OPCODE remains 0x1F.
    #[test]
    fn rejects_verify_inference_row_with_zero_selector() {
        // Program: load some values, run VerifyInference, then Halt. The
        // proof window at address 42 is all zeros, so the stage 3a chain
        // (output_c == Poseidon(model_c, input_c)) does not hold: rd = 0.
        let program = vec![
            inst(Opcode::Load, 2, 0, 0, 42),
            inst(Opcode::Load, 3, 0, 0, 99),
            inst(Opcode::VerifyInference, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        // A zeroed window is a broken chain: VerifyInference answers 0.
        // Find the VerifyInference step and check rd_val = 0
        let vi_step = vm
            .trace
            .iter()
            .find(|s| s.instruction.opcode == Opcode::VerifyInference && !s.inference_is_expand);
        assert!(
            vi_step.is_some(),
            "trace should contain a VerifyInference step"
        );
        assert_eq!(vi_step.unwrap().dst_val, 0, "VerifyInference must return 0");

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&inst| inst.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        // Build the matrix, then zero out the VerifyInference row's
        // `is_verify_inference` column.
        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        let mut vi_row = None;
        for i in 0..n_cpu {
            let row_start = i * TRACE_WIDTH;
            let op_val = matrix.values[row_start + COL_OPCODE].as_canonical_u64();
            if op_val == 0x1F
                && matrix.values[row_start + COL_INFERENCE_IS_EXPAND] == Goldilocks::ZERO
            {
                vi_row = Some(i);
                break;
            }
        }
        let vi_row = vi_row.expect("trace should contain a VerifyInference original row");

        // Zero out the is_verify_inference column on that row.
        let row_start = vi_row * TRACE_WIDTH;
        matrix.values[row_start + COL_IS_VERIFY_INFERENCE] = Goldilocks::new(0);
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);

        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let proof_bytes = postcard::to_allocvec(&p3_proof).unwrap();
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        };

        let res = Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full(),
        );
        assert!(
            res.is_err(),
            "Expected verification to FAIL when is_verify_inference is zeroed on a 0x1F row, but it succeeded!"
        );
    }

    /// Proves `trace` for `program` and verifies it with every opcode
    /// activated. The error text says whether proving or verifying refused.
    fn prove_and_verify_all_active(
        trace: &[Step],
        program: &[u64],
        gas_used: u64,
        gas_limit: u64,
    ) -> Result<(), String> {
        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);

        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit,
            gas_used,
            exit_code: 0,
            trace_len: trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };
        let envelope = Plonky3Adapter::prove(trace, &pi, program)
            .map_err(|e| format!("prove refused: {e:?}"))?;
        Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            program,
            bud_isa::MainnetActivation::full(),
        )
        .map(|_| ())
        .map_err(|e| format!("verify refused: {e:?}"))
    }

    /// No trace that contains opcode 0x1F can be proven, whatever the
    /// immediate or the memory behind the register. The opcode is reserved
    /// and the AIR forces its selector to zero on every row.
    #[test]
    fn rejects_verify_inference_in_any_trace() {
        let model_c = 0xABCD_EF01_2345_6789u64;
        let input_c = 0x1122_3344_5566_7788u64;
        let output_c = bud_vm::poseidon4_hash(model_c, input_c);
        for imm in [0i32, 1, 2] {
            let program = vec![
                inst(Opcode::VerifyInference, 2, 1, 0, imm),
                inst(Opcode::Halt, 0, 0, 0, 0),
            ];
            let mut vm = Vm::new(1024);
            vm.memory[64..72].copy_from_slice(&model_c.to_le_bytes());
            vm.memory[72..80].copy_from_slice(&input_c.to_le_bytes());
            vm.memory[80..88].copy_from_slice(&output_c.to_le_bytes());
            vm.registers[1] = 64;
            let receipt = vm.run_receipt(&program);
            assert!(receipt.success);
            assert!(vm
                .trace
                .iter()
                .any(|s| s.instruction.opcode == Opcode::VerifyInference));

            // The initial register image is part of the statement, so the
            // pre-set r1 is committed the same way the old tests did it.
            let initial_root = crate::adapter::initial_state_root_of(
                crate::adapter::memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace)),
                crate::adapter::register_image_commitment_of_reads(&initial_register_reads(
                    &vm.trace,
                )),
            );
            let program_bytes: Vec<u8> = program
                .iter()
                .flat_map(|&i| i.to_le_bytes().to_vec())
                .collect();
            let mut hasher = Keccak::v256();
            hasher.update(&program_bytes);
            let mut program_hash = [0u8; 32];
            hasher.finalize(&mut program_hash);
            let pi = ExecutionPublicInputs {
                chain_id: 1,
                program_hash,
                initial_state_root: initial_root,
                final_state_root: [0u8; 32],
                sender: 0,
                nonce: 0,
                block_height: 0,
                gas_limit: vm.gas_limit,
                gas_used: vm.gas_used,
                exit_code: 0,
                trace_len: vm.trace.len() as u64,
                event_digest: [0u8; 32],
                state_writes_digest: [0u8; 32],
            };
            let res = Plonky3Adapter::prove(&vm.trace, &pi, &program)
                .map_err(|e| format!("prove refused: {e:?}"))
                .and_then(|envelope| {
                    Plonky3Adapter::verify_with_activation(
                        &envelope,
                        &pi,
                        &program,
                        bud_isa::MainnetActivation::full(),
                    )
                    .map_err(|e| format!("verify refused: {e:?}"))
                });
            let err = res.expect_err("a trace with VerifyInference must be refused");
            assert!(
                err.starts_with("verify refused"),
                "the AIR must refuse VerifyInference (imm={imm}), got {err}"
            );
        }
    }

    /// Inference expansion rows must not work as free filler. The honest
    /// prefix ends in Halt, and extra rows with the expansion flag set are
    /// spliced after the VerifyInference row. They add no gas and the row
    /// count is not part of the statement, so the flag has to be refused.
    #[test]
    fn rejects_inference_expansion_rows_used_as_filler() {
        let program = vec![
            inst(Opcode::VerifyInference, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let mut trace = vm.trace.clone();
        let vi_idx = trace
            .iter()
            .position(|s| s.instruction.opcode == Opcode::VerifyInference)
            .expect("trace holds the VerifyInference row");
        let fillers = 11u8;
        {
            let main = &mut trace[vi_idx];
            main.inference_model_commitment = Some(5);
            main.inference_input_commitment = Some(6);
            main.inference_output_commitment = Some(7);
            main.next_pc = main.pc;
        }
        for round in 0..fillers {
            let mut row = trace[vi_idx].clone();
            row.next_pc = if round == fillers - 1 {
                row.pc + 1
            } else {
                row.pc
            };
            row.instruction.rd = 0;
            row.instruction.imm = (round % 2) as i32;
            row.dst_idx = 0;
            row.dst_val = 0;
            row.inference_proof_round = Some(round);
            row.inference_is_expand = true;
            trace.insert(vi_idx + 1 + round as usize, row);
        }

        let res = prove_and_verify_all_active(&trace, &program, vm.gas_used, vm.gas_limit);
        assert!(
            res.is_err(),
            "inference expansion rows used as filler must be refused, got {res:?}"
        );
    }

    /// Positive control for the 0x1F tests: a trace without opcode 0x1F
    /// proves and verifies, so the refusals above are not a broken setup.
    #[test]
    fn accepts_simple_trace_without_verify_inference() {
        let program = vec![
            inst(Opcode::Add, 1, 0, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        let res = prove_and_verify_all_active(&vm.trace, &program, vm.gas_used, vm.gas_limit);
        assert!(res.is_ok(), "an honest trace must verify, got {res:?}");
    }

    /// The expansion flag is zero on every row. The trace has no 0x1F row,
    /// so the selector constraint cannot fire. The Halt row gets the flag,
    /// its ROM multiplicity is zeroed, and the aux trace is built from that
    /// same matrix. Without the flag constraint this forgery verifies.
    #[test]
    fn rejects_expand_flag_on_non_inference_row() {
        let program = vec![
            inst(Opcode::Add, 1, 0, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert!(!vm
            .trace
            .iter()
            .any(|s| s.instruction.opcode == Opcode::VerifyInference));

        let program_bytes: Vec<u8> = program
            .iter()
            .flat_map(|&i| i.to_le_bytes().to_vec())
            .collect();
        let mut hasher = Keccak::v256();
        hasher.update(&program_bytes);
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);
        let pi = ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        let row = (0..n_cpu)
            .find(|&i| {
                matrix.values[i * TRACE_WIDTH + COL_OPCODE].as_canonical_u64()
                    == Opcode::Halt as u64
            })
            .expect("trace holds a Halt row");
        assert_eq!(
            matrix.values[row * TRACE_WIDTH + COL_INFERENCE_IS_EXPAND],
            Goldilocks::ZERO
        );
        matrix.values[row * TRACE_WIDTH + COL_INFERENCE_IS_EXPAND] = Goldilocks::new(1);
        // The flagged row no longer fetches its ROM word, so its ROM
        // multiplicity goes to zero too. Program CTL then balances and the
        // flag constraint is the only thing left that can refuse the trace.
        let pc = matrix.values[row * TRACE_WIDTH + COL_PC].as_canonical_u64() as usize;
        matrix.values[pc * TRACE_WIDTH + COL_PROG_MULT] = Goldilocks::ZERO;
        let matrix = RowMajorMatrix::new(matrix.values, TRACE_WIDTH);

        let air = BudAir {
            num_steps: vm.trace.len(),
            program: program.clone(),
        };
        let config = build_config();
        let public_values = to_public_values(&pi);
        let degree_bits = p3_util::log2_strict_usize(matrix.height());
        let preprocessed = setup_preprocessed(&config, &air, degree_bits);
        let preprocessed_ref = preprocessed.as_ref().map(|(p, _)| p);
        let p3_proof = prove_with_preprocessed(
            &config,
            &air,
            matrix.clone(),
            Some(crate::plonky3_prover::aux_trace_generator(
                matrix.clone(),
                n_cpu,
                program.clone(),
            )),
            &public_values,
            preprocessed_ref,
        );
        let envelope = ProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: pi.hash(),
            proof_bytes: postcard::to_allocvec(&p3_proof).unwrap(),
            degree_bits: degree_bits as u32,
        };
        let res = Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full(),
        );
        assert!(
            res.is_err(),
            "the expansion flag on a non-0x1F row must be refused, got {res:?}"
        );
    }

    /// Budlum's STARK is sound and succinct, but it is NOT hiding: the PCS is
    /// `TwoAdicFriPcs`, whose `Pcs::ZK` is `false`, so the prover never commits
    /// a randomization polynomial and the witness is not protected.
    ///
    /// That is the intended trade - these proofs attest that a computation
    /// happened, they do not keep its inputs secret. This test exists so the
    /// trade stays deliberate. If a future PCS swap flips `ZK` to `true`, this
    /// fails, and whoever flipped it has to say so in the same change rather
    /// than letting a privacy property appear (or a privacy claim become
    /// true-by-accident) without review.
    ///
    /// The check sits in a `const` block on purpose: the flag is an associated
    /// constant, so a plain `assert!` is constant-valued and clippy's
    /// `assertions_on_constants` rejects it. In a `const` block the same
    /// assertion is evaluated at compile time, which is strictly stronger -
    /// a PCS that starts claiming ZK stops the build instead of failing a run.
    #[test]
    fn proves_poseidon_derived_wide_dynamic_storage_slot() {
        // Mimics compiled `Map<K, V>` codegen: hash `(base_slot, key)` via
        // `Opcode::Poseidon` into `r3` (full-width Goldilocks element > 2^32),
        // write via `SWrite` (`imm = -1`), read back via `SRead` (`imm = -1`),
        // and verify the STARK proof end-to-end.
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Load, 2, 0, 0, 99),
            inst(Opcode::Poseidon, 3, 1, 2, 0),
            inst(Opcode::Load, 4, 0, 0, 777),
            inst(Opcode::SWrite, 0, 4, 3, -1),
            inst(Opcode::SRead, 5, 0, 3, -1),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut check_vm = Vm::new(4096);
        let receipt = check_vm.run_receipt(&program);
        assert!(receipt.success, "poseidon dynamic slot program failed");
        let wide_slot = check_vm.registers[3];
        assert!(
            wide_slot > u64::from(u32::MAX),
            "Poseidon slot must exceed 2^32 to exercise the full-width storage key: {wide_slot}"
        );
        assert_eq!(check_vm.registers[5], 777);
        assert_eq!(check_vm.storage.get(&wide_slot), Some(&777));

        prove_and_verify(program, |_| {});
    }

    #[test]
    fn zk_flag_is_pinned() {
        const {
            assert!(
                !<MyPcs as p3_commit::Pcs<MyExtensionField, MyChallenger>>::ZK,
                "the proof system PCS now claims ZK. Budlum's docs and the \
                 bud_stark prover both state that these proofs do not hide the \
                 witness; update that story before pinning the new value here."
            );
        }
    }
}
