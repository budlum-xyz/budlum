use crate::adapter::{
    ExecutionPublicInputs, ProofEnvelope, ProverAdapter, ProverError, VerifyError,
};
use crate::bud_stark::{
    prove_with_preprocessed, setup_preprocessed,
    verify_with_preprocessed as stark_verify_with_preprocessed, StarkConfig,
};
use crate::plonky3_air::*;
const MAX_PROOF_BYTES: usize = 10 * 1024 * 1024;
use bud_vm::{Step, Vm};
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
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
}

#[derive(Clone, Copy)]
struct MemEvent {
    clk: u64,
    addr: u64,
    val: u64,
    is_write: bool,
    /// This row describes memory as the host left it before execution, not
    /// something the program did. See `COL_MEM_IS_INIT`.
    is_init: bool,
}

const STACK_BASE: u64 = 1 << 60;
const STORAGE_BASE: u64 = 2 << 60;

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
    let inner_challenger = HashChallenger::<u8, Keccak256Hash, 32>::new(vec![], Keccak256Hash {});
    let challenger = MyChallenger::new(inner_challenger);
    let dft = Radix2DitParallel::default();
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    MyConfig::new(pcs, challenger)
}

fn register_events(trace: &[Step]) -> Vec<RegEvent> {
    let mut events = Vec::new();

    for (i, step) in trace.iter().enumerate() {
        if step.instruction.opcode == bud_isa::Opcode::Halt {
            continue;
        }
        // Merkle expansion rows are synthetic — no register
        // Bus traffic (they reuse Opcode::VerifyMerkle with zeroed operands).
        if step.merkle_is_expand {
            continue;
        }
        let clk = i as u64;
        events.push(RegEvent {
            clk,
            idx: step.src1_idx as u64,
            val: step.src1_val,
            is_write: false,
            sub_clk: 1,
        });
        events.push(RegEvent {
            clk,
            idx: step.src2_idx as u64,
            val: step.src2_val,
            is_write: false,
            sub_clk: 2,
        });
        events.push(RegEvent {
            clk,
            idx: step.dst_idx as u64,
            val: if step.dst_idx == 0 { 0 } else { step.dst_val },
            is_write: true,
            sub_clk: 3,
        });
    }

    events.sort_by_key(|e| (e.idx, e.clk, e.sub_clk));
    events
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
                    addr: STACK_BASE + step.stack_pointer as u64 - 1,
                    val: step.src1_val,
                    is_write: true,
                    is_init: false,
                });
            }
            bud_isa::Opcode::Pop => {
                events.push(MemEvent {
                    clk,
                    addr: STACK_BASE + step.stack_pointer as u64,
                    val: step.dst_val,
                    is_write: false,
                    is_init: false,
                });
            }
            bud_isa::Opcode::Call => {
                events.push(MemEvent {
                    clk,
                    addr: STACK_BASE + step.stack_pointer as u64 - 1,
                    val: step.pc as u64 + 1,
                    is_write: true,
                    is_init: false,
                });
            }
            bud_isa::Opcode::Ret => {
                events.push(MemEvent {
                    clk,
                    addr: STACK_BASE + step.stack_pointer as u64,
                    val: step.dst_val,
                    is_write: false,
                    is_init: false,
                });
            }
            bud_isa::Opcode::SRead => {
                let slot = if step.instruction.imm == -1 {
                    step.src2_val as i32
                } else {
                    step.instruction.imm
                };
                events.push(MemEvent {
                    clk,
                    addr: STORAGE_BASE + slot as u64,
                    val: step.dst_val,
                    is_write: false,
                    is_init: false,
                });
            }
            bud_isa::Opcode::SWrite => {
                let slot = if step.instruction.imm == -1 {
                    step.src2_val as i32
                } else {
                    step.instruction.imm
                };
                events.push(MemEvent {
                    clk,
                    addr: STORAGE_BASE + slot as u64,
                    val: step.src1_val,
                    is_write: true,
                    is_init: false,
                });
            }
            _ => {}
        }
    }
    events.sort_by_key(|e| (e.addr, e.clk));
    // Mark the pre-execution rows now that the events are grouped by address.
    let mut prev_addr: Option<u64> = None;
    for e in events.iter_mut() {
        let first_at_addr = prev_addr != Some(e.addr);
        prev_addr = Some(e.addr);
        e.is_init = first_at_addr && !e.is_write && e.val != 0;
    }
    events
}

/// The seeded reads a trace performs, in the order the AIR folds them.
///
/// Callers need this to compute `initial_state_root`: the commitment covers
/// exactly the pre-written words the program read, and getting the set or the
/// order wrong produces a proof the AIR rejects.
pub fn initial_memory_reads(trace: &[Step]) -> Vec<(u64, u64)> {
    memory_events(trace)
        .into_iter()
        .filter(|e| e.is_init)
        .map(|e| (e.addr, e.val))
        .collect()
}

fn trace_matrix(
    trace: &[Step],
    _program: &[u64],
    public_inputs: &ExecutionPublicInputs,
) -> (RowMajorMatrix<Goldilocks>, usize) {
    let events = register_events(trace);
    let mem_events = memory_events(trace);
    let n_cpu = trace.len();
    let n_reg = events.len();
    let n_mem = mem_events.len();
    let num_rows = (3 * n_cpu + 1).next_power_of_two().max(16);

    let mut values = vec![Goldilocks::new(0); num_rows * TRACE_WIDTH];

    let mut running_gas = 0u64;

    for (i, step) in trace.iter().enumerate() {
        let row_start = i * TRACE_WIDTH;
        let op = step.instruction.opcode as u8;
        values[row_start + COL_CLK] = Goldilocks::new(i as u64);
        values[row_start + COL_PC] = Goldilocks::new(step.pc as u64);
        values[row_start + COL_OPCODE] = Goldilocks::new(op as u64);

        // (security audit) first-row initial-state binding
        // And trace-length counter (only meaningful on the first real
        // Row, but we update it on every real row so the AIR can check
        // It on the last row as well).
        if i == 0 {
            for j in 0..8 {
                let limb = u32::from_le_bytes(
                    public_inputs.initial_state_root[j * 4..j * 4 + 4]
                        .try_into()
                        .unwrap(),
                );
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
            // Chain_id is a fixed domain constant — we record
            // (public.chain_id & 0xFFFFFFFF) here; the AIR compares
            // It to public_inputs[0,1] on the first row.
            values[row_start + COL_CHAIN_ID] =
                Goldilocks::new(public_inputs.chain_id & 0xFFFF_FFFF);
        }
        // Event_digest accumulator: 8 × u32 limbs, initialised to 0
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
            // The whole value, in the field — not the low 32 bits. The AIR
            // constrains `nxt_event_0 - cur_event_0 - is_log * nxt_rs1 == 0`
            // and `nxt_rs1` is the full register, so masking here made the
            // witness disagree with the constraint for any logged value at or
            // above 2^32. Small values matched by accident, which is why the
            // mismatch survived: every test logged a small constant, and the
            // one caller that logged a Poseidon output never verified its own
            // proof.
            values[row_start + COL_EVENT_DIGEST_0] += Goldilocks::new(step.src1_val);
        }
        values[row_start + COL_RD_IDX] = Goldilocks::new(step.dst_idx as u64);
        values[row_start + COL_RS1_IDX] = Goldilocks::new(step.src1_idx as u64);
        values[row_start + COL_RS2_IDX] = Goldilocks::new(step.src2_idx as u64);
        values[row_start + COL_RS1_VAL] = Goldilocks::new(step.src1_val);
        values[row_start + COL_RS2_VAL] = Goldilocks::new(step.src2_val);
        values[row_start + COL_RD_VAL_NEW] = if step.dst_idx == 0 {
            Goldilocks::new(0)
        } else {
            Goldilocks::new(step.dst_val)
        };
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
            Goldilocks::new(0) - Goldilocks::new((-imm) as u64)
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

        if opcode == bud_isa::Opcode::Eq || opcode == bud_isa::Opcode::Neq {
            let diff = step.src1_val.wrapping_sub(step.src2_val);
            let inv = if diff != 0 {
                bud_vm::field_inverse_goldilocks(diff)
            } else {
                0
            };
            values[row_start + COL_EQ_DIFF_INV] = Goldilocks::new(inv);
        }

        // SumConservation equality witness (rs1 - rs2).
        if opcode == bud_isa::Opcode::SumConservation {
            let diff = step.src1_val.wrapping_sub(step.src2_val);
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
            0x07 => values[row_start + COL_IS_OR] = Goldilocks::new(1),
            0x08 => values[row_start + COL_IS_XOR] = Goldilocks::new(1),
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
        let is_bw_bits = opcode == bud_isa::Opcode::And
            || opcode == bud_isa::Opcode::Or
            || opcode == bud_isa::Opcode::Xor;

        if is_cmp || is_bw_bits {
            let a = step.src1_val;
            let b = step.src2_val;

            for i in 0..64 {
                values[row_start + COL_CMP_RS1_BASE + i] = Goldilocks::new((a >> i) & 1);
                values[row_start + COL_CMP_RS2_BASE + i] = Goldilocks::new((b >> i) & 1);
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

        // Not (logical NOT) — store inverse witness in COL_INV_ZERO
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
                let blinding = step.instruction.imm as u32 as u64;
                Some([step.src1_val, step.src2_val, blinding, 0, 0, 0, 0, 0])
            }
            bud_isa::Opcode::NullifierCheck => {
                // State = [secret=rs2, DOMAIN_NULLIFIER, 0..]
                Some([step.src2_val, bud_vm::DOMAIN_NULLIFIER, 0, 0, 0, 0, 0, 0])
            }
            _ => None,
        };

        if let Some(init_state) = poseidon_init {
            const P: u64 = 18446744069414584321;
            // Same constants the AIR reads; see plonky3_air.rs.
            use bud_vm::{POSEIDON_MDS as mds, POSEIDON_RC_FULL as rc};

            let mut s: [u64; 8] = init_state;
            let mut poseidon_out = 0u64;

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
                    // Final round output = MDS row 0 · sbox (matches AIR / poseidon4_hash_state).
                    let mut sum: u128 = 0;
                    for j in 0..8 {
                        sum = (sum + mds[0][j] as u128 * sbox[j] as u128) % P as u128;
                    }
                    poseidon_out = sum as u64;
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

        // (security audit) trace-length counter and
        // (on the last real row) the final-state-root, event-digest
        // And exit-code binding. The counter is updated on every
        // Real row so the AIR can assert `COL_TRACE_LEN_CTR == n_cpu`
        // On the last real row (= n_cpu - 1, the synthetic Halt row
        // Added).
        values[row_start + COL_TRACE_LEN_CTR] = Goldilocks::new((i + 1) as u64);
        if i == n_cpu.saturating_sub(1) {
            for j in 0..8 {
                let limb = u32::from_le_bytes(
                    public_inputs.final_state_root[j * 4..j * 4 + 4]
                        .try_into()
                        .unwrap(),
                );
                values[row_start + COL_FINAL_ROOT_0 + j] = Goldilocks::new(limb as u64);
            }
            // Exit_code: 0 = success (real Halt), 1 = error (
            // Synthetic Halt). The prover passes the right value
            // Through `public_inputs.exit_code`; the AIR binds it.
            values[row_start + COL_EXIT_CODE] = Goldilocks::new(public_inputs.exit_code);
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
            let key = step.merkle_key.expect("expansion row must have merkle_key");
            let cur = step
                .merkle_current
                .expect("expansion row must have merkle_current");
            let sibling = step
                .merkle_sibling
                .expect("expansion row must have merkle_sibling");
            let round = step
                .merkle_round
                .expect("expansion row must have merkle_round");
            let bit = (key >> round) & 1;
            values[row_start + COL_VM_MERKLE_KEY] = Goldilocks::new(key);
            values[row_start + COL_VM_MERKLE_BIT] = Goldilocks::new(bit);
            // Remaining key for this round. The AIR walks this down with
            // `rem == 2 * rem' + bit`, which is what ties `bit` to `key`;
            // without it the direction bits were free and a flipped bit
            // produced a different root that the AIR still accepted.
            values[row_start + COL_MERKLE_KEY_REM] = Goldilocks::new(key >> round);
            values[row_start + COL_VM_MERKLE_CURRENT] = Goldilocks::new(cur);
            values[row_start + COL_VM_MERKLE_SIBLING] = Goldilocks::new(sibling);
            values[row_start + COL_VM_MERKLE_ROUND] = Goldilocks::new(round as u64);
            values[row_start + COL_VM_MERKLE_IS_EXPAND] = Goldilocks::new(1);
            //: only the *original* step is the
            // Final row of the path; expansion rows are intermediates.
            values[row_start + COL_MERKLE_FINAL_FLAG] = Goldilocks::new(0);

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
        } else if step.merkle_key.is_some() {
            // Original VerifyMerkle step. The VM patched this row
            // With merkle_key immediately after push.
            let key = step.merkle_key.unwrap();
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
            let final_merkle = step
                .merkle_current
                .expect("original VerifyMerkle step must have merkle_current (the VM sets this)");
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
            // VerifyMerkle path — the AIR uses the final_flag
            // (1 only here) to apply the final root check on the
            // *64th* expansion row's `merkle_current`.
            values[row_start + COL_MERKLE_FINAL_FLAG] = Goldilocks::new(1);
            // Inverse-witness for final root equality check.
            // Rd_val_new is constrained to equal (final == root) as a field boolean.
            let root = step.src1_val;
            let diff = final_merkle.wrapping_sub(root);
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
            // Padding so the active→padding transition does not zero them.
            let last_start = (n_cpu - 1) * TRACE_WIDTH;
            for j in 0..8 {
                values[row_start + COL_EVENT_DIGEST_0 + j] =
                    values[last_start + COL_EVENT_DIGEST_0 + j];
                values[row_start + COL_FINAL_ROOT_0 + j] =
                    values[last_start + COL_FINAL_ROOT_0 + j];
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

        if i < n_reg - 1 && events[i + 1].idx == e.idx {
            values[row_start + COL_REG_SAME] = Goldilocks::new(1);
        }
    }

    for (i, e) in mem_events.iter().enumerate() {
        let row_start = i * TRACE_WIDTH;
        values[row_start + COL_MEM_CLK] = Goldilocks::new(e.clk);
        values[row_start + COL_MEM_ADDR] = Goldilocks::new(e.addr);
        values[row_start + COL_MEM_VAL] = Goldilocks::new(e.val);
        values[row_start + COL_MEM_IS_WRITE] = if e.is_write {
            Goldilocks::new(1)
        } else {
            Goldilocks::new(0)
        };
        values[row_start + COL_MEM_ACTIVE] = Goldilocks::new(1);
        values[row_start + COL_MEM_IS_INIT] = Goldilocks::new(u64::from(e.is_init));

        if i < n_mem - 1 && mem_events[i + 1].addr == e.addr {
            values[row_start + COL_MEM_SAME] = Goldilocks::new(1);
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
                let term = Goldilocks::new(e.addr) * gamma + Goldilocks::new(e.val);
                acc = if i == 0 { term } else { acc * beta + term };
            }
            values[i * TRACE_WIDTH + COL_MEM_INIT_ACC] = acc;
        }
        for r in mem_events.len()..num_rows {
            values[r * TRACE_WIDTH + COL_MEM_INIT_ACC] = acc;
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
            let is_or = row[COL_IS_OR];
            let is_xor = row[COL_IS_XOR];
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
                + is_or
                + is_xor
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
            let c_rd = register_term(
                alpha,
                beta,
                Goldilocks::ZERO,
                clk_rd,
                rd_idx,
                rd_val_new,
                Goldilocks::ONE,
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

            // Memory LogUp (includes SRead/SWrite via STORAGE_BASE)
            let m_active = row[COL_MEM_ACTIVE];
            let m_clk = row[COL_MEM_CLK];
            let m_addr = row[COL_MEM_ADDR];
            let m_val = row[COL_MEM_VAL];
            let m_is_write = row[COL_MEM_IS_WRITE];

            let is_real_mem_op = (is_load + is_store)
                * if rs1_idx != Goldilocks::ZERO {
                    Goldilocks::ONE
                } else {
                    Goldilocks::ZERO
                };
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
            let stack_base = Goldilocks::from_u64(STACK_BASE);
            let storage_base = Goldilocks::from_u64(STORAGE_BASE);
            let stack_addr = stack_base
                + (is_push + is_call) * stack_ptr
                + (is_pop + is_ret) * (stack_ptr - Goldilocks::ONE);
            let storage_addr = storage_base + row[COL_IMM];

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
                Goldilocks::ONE,
                clk,
                final_mem_addr,
                cpu_mem_val,
                is_write,
            );
            let c_mem = register_term(
                alpha,
                beta,
                Goldilocks::ONE,
                m_clk,
                m_addr,
                m_val,
                m_is_write,
            );

            if is_any_mem_op != Goldilocks::ZERO {
                s_mem += (gamma - c_cpu_mem).inverse();
            }
            if m_active != Goldilocks::ZERO {
                s_mem -= (gamma - c_mem).inverse();
            }

            // Program LogUp
            let raw_inst = row[COL_RAW_INST];
            let term_cpu_prog =
                alpha + beta * MyExtensionField::from(pc) + b2 * MyExtensionField::from(raw_inst);

            let pre_pc = Goldilocks::from_u64(i as u64);
            let pre_inst = Goldilocks::from_u64(program.get(i).copied().unwrap_or(0));
            let term_pre_prog = alpha
                + beta * MyExtensionField::from(pre_pc)
                + b2 * MyExtensionField::from(pre_inst);

            let diff_cpu_prog = gamma - term_cpu_prog;
            let diff_pre_prog = gamma - term_pre_prog;

            // Expansion rows reuse opcode 0x1E at the same PC
            // But are NOT program fetches — counting them unbalances LogUp
            // (trace_len >> program.len for VerifyMerkle paths).
            let is_expand_row = row[COL_VM_MERKLE_IS_EXPAND];
            if i < trace_len && is_expand_row == Goldilocks::ZERO {
                s_prog += diff_cpu_prog.inverse();
            }
            if i < program.len() {
                s_prog -= diff_pre_prog.inverse();
            }

            aux_values[(i + 1) * 3] = s_reg;
            aux_values[(i + 1) * 3 + 1] = s_mem;
            aux_values[(i + 1) * 3 + 2] = s_prog;
        }

        RowMajorMatrix::new(aux_values, 3).flatten_to_base()
    })
}

fn to_public_values(pi: &ExecutionPublicInputs) -> Vec<Goldilocks> {
    let mut vals = Vec::new();

    vals.push(Goldilocks::from_u64(pi.chain_id & 0xFFFF_FFFF));
    vals.push(Goldilocks::from_u64(pi.chain_id >> 32));

    for chunk in pi.program_hash.chunks_exact(4) {
        let val = u32::from_le_bytes(chunk.try_into().unwrap());
        vals.push(Goldilocks::from_u64(val as u64));
    }

    for chunk in pi.initial_state_root.chunks_exact(4) {
        let val = u32::from_le_bytes(chunk.try_into().unwrap());
        vals.push(Goldilocks::from_u64(val as u64));
    }

    for chunk in pi.final_state_root.chunks_exact(4) {
        let val = u32::from_le_bytes(chunk.try_into().unwrap());
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
    // value stayed below 2^32 — which every test did, and which a Poseidon
    // output never does.
    vals.push(Goldilocks::from_u64(u64::from_le_bytes(
        pi.event_digest[0..8].try_into().unwrap(),
    )));
    // Limbs 1..8 are reserved; they are packed as u32 and asserted zero.
    for chunk in pi.event_digest[8..32].chunks_exact(4) {
        let val = u32::from_le_bytes(chunk.try_into().unwrap());
        vals.push(Goldilocks::from_u64(val as u64));
    }
    // One more slot so the vector length stays at 48.
    vals.push(Goldilocks::from_u64(0));

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
            proof_format_version: 1,
            backend: "Plonky3-Keccak-Goldilocks".to_string(),
            p3_version: "0.5.2".to_string(),
            fri_params_id: "test_fri_params".to_string(),
            public_inputs_hash: public_inputs.hash(),
            proof_bytes,
            degree_bits: degree_bits as u32,
        })
    }

    fn verify(
        envelope: &ProofEnvelope,
        expected_inputs: &ExecutionPublicInputs,
        program: &[u64],
    ) -> Result<(), VerifyError> {
        debug!(
            version = envelope.proof_format_version,
            proof_len = envelope.proof_bytes.len(),
            "Verifying proof"
        );
        if envelope.proof_format_version != 1 {
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

        let bounded_bytes =
            &envelope.proof_bytes[..envelope.proof_bytes.len().min(MAX_PROOF_BYTES)];
        let p3_proof: crate::bud_stark::Proof<MyConfig> = postcard::from_bytes(bounded_bytes)
            .map_err(|e| VerifyError::DeserializationError(e.to_string()))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use bud_isa::{Instruction, Opcode};
    use bud_vm::Vm;
    use p3_field::PrimeField64;

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
        let mut vm = Vm::new(64);
        setup(&mut vm);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let initial_root = [0u8; 32];
        let final_root = [0u8; 32];

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
        };

        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        let verify_res = Plonky3Adapter::verify(&envelope, &pi, &program);
        if let Err(ref e) = verify_res {
            eprintln!("Verification error: {:?}", e);
        }
        assert!(verify_res.is_ok());
        envelope
    }

    /// Run the program, tamper the trace, and assert that proving FAILS.
    fn prove_fails_after_tamper(
        program: Vec<u64>,
        setup: impl FnOnce(&mut Vm),
        tamper: impl FnOnce(&mut Vec<Step>),
    ) {
        let mut vm = Vm::new(64);
        setup(&mut vm);
        let _receipt = vm.run_receipt(&program);
        assert!(_receipt.success);

        tamper(&mut vm.trace);

        let initial_root = [0u8; 32];
        let final_root = [0u8; 32];
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
        };

        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            res.is_err(),
            "Expected verification to FAIL after tampering, but it succeeded!"
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

    /// Public inputs built by the shared helper must verify — this is the path
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
    /// This honest trace satisfies that.
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

    #[test]
    fn rejects_invalid_proof_bytes() {
        let envelope = ProofEnvelope {
            proof_format_version: 1,
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
        };

        let res = Plonky3Adapter::verify(&envelope, &pi, &[]);
        assert!(res.is_err());
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
            inst(Opcode::Lt, 1, 2, 3, 0),  // 5 < 10 → 1
            inst(Opcode::Gt, 2, 2, 3, 0),  // 5 > 10 → 0
            inst(Opcode::Lte, 3, 2, 3, 0), // 5 <= 10 → 1
            inst(Opcode::Gte, 4, 2, 3, 0), // 5 >= 10 → 0
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

    #[test]
    fn proves_bitwise_or() {
        let program = vec![
            inst(Opcode::Or, 1, 2, 3, 0), // 0b1100 | 0b1010 = 0b1110 = 14
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = 0b1100;
            vm.registers[3] = 0b1010;
        });
    }

    #[test]
    fn proves_bitwise_xor() {
        let program = vec![
            inst(Opcode::Xor, 1, 2, 3, 0), // 0b1100 ^ 0b1010 = 0b0110 = 6
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        prove_and_verify(program, |vm| {
            vm.registers[2] = 0b1100;
            vm.registers[3] = 0b1010;
        });
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

    /// E2E private-transfer skeleton —
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
    // `VerifyMerkle` opcode'unun (0x1E) ZK soundness'ı iki katmandan oluşur:
    //
    //   (a) **Selector binding (partial fix).** The prover can no
    //       Longer set `is_verify_merkle = 0` on a row where
    //       `COL_OPCODE = 0x1E` — the AIR forces
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
    // What this does *not* license: `verify_merkle_enabled` stays `false`
    // In the default ISA config. That flag is gated on external review of
    // The soundness argument, which is a process step, not a missing
    // Constraint. Do not flip it on the strength of this comment.
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

    /// (security audit) partial-fix test for the
    /// Selector binding. Take a valid Add+Halt program, mutate the
    /// Trace so the *last* real row's `is_verify_merkle` column is
    /// Zeroed out while `COL_OPCODE` is left at 0x00 (Halt) — that
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
        // Path to be valid — we only need the opcode to be 0x1E.
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
            proof_format_version: 1,
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
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            res.is_err(),
            "Expected verification to FAIL when is_verify_merkle is zeroed on a 0x1E row, but it succeeded!"
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
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);

        // Flip the round-0 direction bit and recompute the Poseidon chain
        // from it, so the trace stays internally consistent everywhere the
        // old AIR looked. `merkle_key` is deliberately left alone — that is
        // the disagreement this test is about.
        let row1 = TRACE_WIDTH;
        let bit_before = matrix.values[row1 + COL_VM_MERKLE_BIT].as_canonical_u64();
        let cur0 = matrix.values[row1 + COL_VM_MERKLE_CURRENT].as_canonical_u64();
        let sib0 = matrix.values[row1 + COL_VM_MERKLE_SIBLING].as_canonical_u64();
        matrix.values[row1 + COL_VM_MERKLE_BIT] = Goldilocks::new(1 - bit_before);

        // Round 0's S-box witnesses have to be rebuilt too: flipping the bit
        // swaps which of (current, sibling) is s0. Leaving them stale would
        // trip the Poseidon identity instead, and the test would pass for a
        // reason that has nothing to do with the direction bit — which is
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
        // trace must not end up as a verifying proof — and the two outcomes
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
                    proof_format_version: 1,
                    backend: "Plonky3-Keccak-Goldilocks".to_string(),
                    p3_version: "0.5.2".to_string(),
                    fri_params_id: "test_fri_params".to_string(),
                    public_inputs_hash: pi.hash(),
                    proof_bytes,
                    degree_bits: degree_bits as u32,
                };
                Plonky3Adapter::verify(&envelope, &pi, &program).is_err()
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
    /// `path_addr + 8 + 8 * round`. Measured before the fix — 64 expansion
    /// rows, 0 carrying a `memory_addr`, and 0 of the 65 path words present in
    /// the memory argument — so a prover could walk a path that was never
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
            initial_state_root: crate::adapter::memory_image_commitment_of_reads(
                &crate::plonky3_prover::initial_memory_reads(&vm.trace),
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
                    proof_format_version: 1,
                    backend: "Plonky3-Keccak-Goldilocks".to_string(),
                    p3_version: "0.5.2".to_string(),
                    fri_params_id: "test_fri_params".to_string(),
                    public_inputs_hash: pi.hash(),
                    proof_bytes,
                    degree_bits: degree_bits as u32,
                };
                Plonky3Adapter::verify(&envelope, &pi, &program).is_err()
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
        };

        let (mut matrix, n_cpu) = trace_matrix(&vm.trace, &program, &pi);
        // Tamper row 5 (the 5th expansion row, round 4): copy the
        // Round index from row 6 (round 5) so we have two rows
        // Claiming round=5. The AIR's round transition
        // `nxt_round - cur_round - 1 = 0` is then violated on the
        // 4→5 transition.
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
            proof_format_version: 1,
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
    /// Root check, expand gas). Still ignored until full prove is green.
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

    /// Q15 depth_1_test — 1 meaningful sibling, but VM always does 64 rounds (66 rows total)
    /// This isolates whether InvalidProof is due to row count (64 vs small) — we still do 64 rounds,
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
            initial_state_root: crate::adapter::memory_image_commitment_of_reads(
                &crate::plonky3_prover::initial_memory_reads(&vm.trace),
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
        };
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(res.is_ok(), "1-depth should succeed: {:?}", res);
    }

    /// Q15 depth_2_test — 2 meaningful siblings, rest zero, still 66 rows
    #[test]
    fn proves_verify_merkle_valid_2_depth() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let key: u64 = 2; // binary 10 → bit0=0, bit1=1
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
            initial_state_root: crate::adapter::memory_image_commitment_of_reads(
                &crate::plonky3_prover::initial_memory_reads(&vm.trace),
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
        };
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
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
            initial_state_root: crate::adapter::memory_image_commitment_of_reads(
                &crate::plonky3_prover::initial_memory_reads(&vm.trace),
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
        };

        // End-to-end: prove and verify. If the AIR's Poseidon
        // Single-round transition or final root check is broken,
        // Verification will fail.
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
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
            proof_format_version: 1,
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
            proof_format_version: 1,
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
            program_hash: [0u8; 32],
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: 1000000,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
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
        // We don't care — the *transition* 1->0 is the violation).
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
            proof_format_version: 1,
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
            "Expected verification to FAIL with non-Halt termination (Z-C), but it succeeded!"
        );
    }

    // --- (security audit): public-input binding tests ---

    /// Helper: prove a trivial Add+Halt program and return the envelope + the
    /// Public inputs. The caller mutates `pi` between prove/verify to assert
    /// That the AIR rejects the forged public input.
    fn build_arith_proof() -> (ProofEnvelope, ExecutionPublicInputs, Vec<u64>) {
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
        };

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
            res.is_err(),
            "Expected verification to FAIL with tampered final_state_root, but it succeeded!"
        );
    }

    #[test]
    fn rejects_tampered_initial_state_root() {
        let (envelope, mut pi, program) = build_arith_proof();
        pi.initial_state_root = [0xCD; 32];
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            res.is_err(),
            "Expected verification to FAIL with tampered initial_state_root, but it succeeded!"
        );
    }

    #[test]
    fn rejects_tampered_gas_limit() {
        let (envelope, mut pi, program) = build_arith_proof();
        // Gas_limit differs from what the trace recorded.
        pi.gas_limit = pi.gas_limit.wrapping_add(1);
        // The public-input-hash check will also fire here; either way
        // The proof must be rejected.
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            res.is_err(),
            "Expected verification to FAIL with tampered gas_limit, but it succeeded!"
        );
    }

    #[test]
    fn rejects_tampered_trace_len() {
        let (envelope, mut pi, program) = build_arith_proof();
        // Bump trace_len by one — should fail because
        // COL_TRACE_LEN_CTR was set to n_cpu (which doesn't change).
        pi.trace_len = pi.trace_len.wrapping_add(1);
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            res.is_err(),
            "Expected verification to FAIL with tampered trace_len, but it succeeded!"
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
            res.is_err(),
            "Expected verification to FAIL with tampered event_digest, but it succeeded!"
        );
    }

    #[test]
    fn rejects_tampered_exit_code() {
        let (envelope, mut pi, program) = build_arith_proof();
        // Forge exit_code from 0 (success) to 1 (error).
        pi.exit_code = 1;
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            res.is_err(),
            "Expected verification to FAIL with tampered exit_code, but it succeeded!"
        );
    }

    #[test]
    fn rejects_tampered_chain_id() {
        let (envelope, mut pi, program) = build_arith_proof();
        // Forge chain_id: change the low 32 bits.
        pi.chain_id = 0xDEAD_BEEF;
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(
            res.is_err(),
            "Expected verification to FAIL with tampered chain_id, but it succeeded!"
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
                // 5 < 10 → should be 1. Tamper to 0.
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
            program_hash: [0u8; 32],
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: 1000000,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
        };

        // Tamper the trace matrix directly: corrupt an S-box intermediate (x2) column
        let (mut matrix, _trace_len) = trace_matrix(&vm.trace, &program, &pi);
        // Round 0, element 0 x2 is at COL_POSEIDON_X2_BASE = 290
        matrix.values[290] = Goldilocks::new(999);
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
            proof_format_version: 1,
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
            res.is_err(),
            "Expected verification to FAIL with tampered S-box, but it succeeded!"
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
    fn rejects_verify_merkle_with_incorrect_root() {
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
            initial_state_root: crate::adapter::memory_image_commitment_of_reads(
                &crate::plonky3_prover::initial_memory_reads(&vm.trace),
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
        };

        // This proof SHOULD verify because we are proving that the VM
        // CORRECTLY COMPUTES '0' when the root doesn't match.
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        assert!(Plonky3Adapter::verify(&envelope, &pi, &program).is_ok());
    }

    /// VerifyInference AIR binding soundness test.
    /// Build a trace containing a VerifyInference row and verify that
    /// The AIR rejects a tampered trace where the `is_verify_inference`
    /// Selector is zeroed out while COL_OPCODE remains 0x1F.
    #[test]
    fn rejects_verify_inference_row_with_zero_selector() {
        // Program: load some values, run VerifyInference (always returns 0
        // On mainnet), then Halt.
        let program = vec![
            inst(Opcode::Load, 2, 0, 0, 42),
            inst(Opcode::Load, 3, 0, 0, 99),
            inst(Opcode::VerifyInference, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        // VerifyInference should always return 0 (disabled)
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
            proof_format_version: 1,
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
            "Expected verification to FAIL when is_verify_inference is zeroed on a 0x1F row, but it succeeded!"
        );
    }
}
