// Unsafe lock: this crate is at 0 unsafe today. The moment an `unsafe` block
// enters, the build FAILs (a regression gate). The same policy as the main crate.
#![forbid(unsafe_code)]
use bud_isa::{Instruction, Opcode};
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VmError {
    OutOfGas,
    AssertionFailed,
    StackUnderflow,
    StackOverflow,
    InvalidOpcode(String),
    InvalidPc,
    InvalidMemoryAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub success: bool,
    pub error: Option<VmError>,
    pub gas_used: u64,
    pub exit_code: u64,
    pub events: Vec<u64>,
    pub final_pc: u64,
    pub trace_len: u64,
    pub state_writes_digest: [u8; 32],
}

// Mainnet decoding uses the staged-rollout defaults, not full activation.
//
// The env var `BUDLUM_VERIFY_MERKLE` was removed for a good reason: an
// operator could set it to "false" and turn off Merkle verification, which is
// a configuration attack vector. But the replacement went past the target. It
// hard-coded `MainnetActivation::full()`, which sets every gate to true and
// makes `MainnetActivation::default()` unreachable from the only place that
// consults it.
//
// The defaults are not decorative. `verify_merkle_enabled: false` is there
// because the path verification is unfinished, and
// `verify_inference_enabled: false` is there because, in the words of
// `docs/AI_VERIFICATION_STATUS.md`, there is no verification circuit behind
// the opcode at all and it returns a hard-coded zero. README states plainly
// that VerifyMerkle is "gated off in production until 64-depth soundness is
// proven". With `full()`, both opcodes decode and execute on mainnet, and
// nothing downstream stops them - the execute arm has no second check.
//
// So the fix is `default()`, not `full()`. Turning a gate on is then a source
// change with a reviewer, which is what "staged rollout should use
// governance/genesis config, not env vars" was asking for; an env var is
// still not consulted anywhere.
fn decode_instruction(raw: u64, mainnet_mode: bool) -> Result<bud_isa::Instruction, String> {
    if mainnet_mode {
        // Staged-rollout defaults - no env var override, and no blanket
        // activation either.
        let activation = bud_isa::MainnetActivation::default();
        bud_isa::Instruction::decode_for_mainnet(raw, activation).map_err(|e| e.to_string())
    } else {
        #[cfg(test)]
        {
            use bud_isa::IsaProfile;
            bud_isa::Instruction::decode_for_profile(raw, IsaProfile::Testing)
                .map_err(|e| e.to_string())
        }
        #[cfg(not(test))]
        {
            bud_isa::Instruction::decode(raw)
        }
    }
}

pub mod private_transfer;
pub mod syscall_context;

pub struct Vm {
    pub registers: [u64; 32],
    pub pc: usize,
    pub stack: Vec<u64>,
    pub memory: Vec<u8>,
    pub storage: std::collections::HashMap<i32, u64>,
    pub events: Vec<u64>,
    pub context: Context,
    pub trace: Vec<Step>,
    pub halted: bool,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub error: Option<VmError>,
    pub state_writes: Vec<(i32, u64)>,
    /// F2: Mainnet mode flag. When true, VerifyMerkle is gated behind
    /// `MainnetActivation::full`. Set by `ZkVmExecutor::execute_bytecode`
    /// When network is Mainnet.
    pub mainnet_mode: bool,
}

pub struct Context {
    pub sender: u64,
    pub nonce: u64,
    pub block_height: u64,
    /// (security audit) initial state root.
    /// The VM does not consume this directly (state roots are produced
    /// Externally), but the prover trace records it on the first row
    /// So the AIR can bind `public_inputs.initial_state_root`.
    pub initial_state_root: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Step {
    pub pc: usize,
    pub next_pc: usize,
    pub instruction: Instruction,
    pub src1_idx: u8,
    pub src2_idx: u8,
    pub dst_idx: u8,
    pub src1_val: u64,
    pub src2_val: u64,
    pub dst_val: u64,
    pub registers: [u64; 32],
    pub memory_addr: Option<usize>,
    pub memory_val: Option<u64>,
    pub is_memory_write: bool,
    pub stack_pointer: usize,
    /// (security audit) Merkle path expansion rows. The
    /// Original step that triggers a `VerifyMerkle` has these set to
    /// `None` and `merkle_is_expand = false`; the 64 follow-up
    /// "expansion" rows (one per Poseidon round) carry the key, the
    /// Current Poseidon accumulator, the sibling hash for that round,
    /// And the round index. The AIR uses these to verify the path
    /// Against the claimed root (`rs1_val`).
    pub merkle_key: Option<u64>,
    pub merkle_current: Option<u64>,
    pub merkle_sibling: Option<u64>,
    pub merkle_round: Option<u8>,
    pub merkle_is_expand: bool,
    /// AI inference verification expansion rows.
    /// The original VerifyInference step carries these as None/0;
    /// Follow-up expansion rows carry the commitment values being
    /// Verified by the AIR trace. The AIR checks that:
    /// 1. model_id matches the registered model's program_hash
    /// 2. input_commitment matches the request's input_commitment
    /// 3. output_commitment is derived from the proof execution
    /// 4. The STARK proof envelope verifies against the public inputs
    pub inference_model_commitment: Option<u64>,
    pub inference_input_commitment: Option<u64>,
    pub inference_output_commitment: Option<u64>,
    pub inference_proof_round: Option<u8>,
    pub inference_is_expand: bool,
}

pub fn field_inverse_goldilocks(val: u64) -> u64 {
    const P: u64 = 18446744069414584321;
    if val == 0 {
        return 0;
    }
    let mut exp = P - 2;
    let mut base = val as u128;
    let mut res = 1u128;
    while exp > 0 {
        if exp & 1 == 1 {
            res = (res * base) % P as u128;
        }
        base = (base * base) % P as u128;
        exp >>= 1;
    }
    res as u64
}

/// The Goldilocks prime `P = 2^64 - 2^32 + 1`. This is the field the
/// STARK AIR (`plonky3_air`) constrains execution over.
pub const GOLDILOCKS_P: u64 = 18446744069414584321;

/// Goldilocks field addition (`(a + b) mod P`).
///
/// The VM **must** compute arithmetic in the same field the AIR
/// Constrains, otherwise a generated STARK proof attests to a different
/// Computation than the VM actually executed (a soundness break). The
/// AIR's Add/Sub/Mul constraints are field operations mod `P`, so the VM
/// Uses these field helpers instead of wrapping-`u64` arithmetic. The
/// Result is always canonical (`< P`).
pub fn field_add_goldilocks(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % GOLDILOCKS_P as u128) as u64
}

/// Goldilocks field subtraction (`(a - b) mod P`).
pub fn field_sub_goldilocks(a: u64, b: u64) -> u64 {
    ((a as u128 + GOLDILOCKS_P as u128 - (b as u128 % GOLDILOCKS_P as u128)) % GOLDILOCKS_P as u128)
        as u64
}

/// Goldilocks field multiplication (`(a * b) mod P`).
pub fn field_mul_goldilocks(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % GOLDILOCKS_P as u128) as u64
}

impl Vm {
    pub fn new(memory_size: usize) -> Self {
        Self::with_gas_limit(memory_size, 1_000_000)
    }

    pub fn with_gas_limit(memory_size: usize, gas_limit: u64) -> Self {
        Self {
            registers: [0; 32],
            pc: 0,
            stack: Vec::new(),
            memory: vec![0; memory_size],
            storage: std::collections::HashMap::new(),
            events: Vec::new(),
            context: Context {
                sender: 0,
                nonce: 0,
                block_height: 0,
                initial_state_root: [0u8; 32],
            },
            trace: Vec::new(),
            halted: false,
            gas_used: 0,
            gas_limit,
            error: None,
            state_writes: Vec::new(),
            mainnet_mode: false,
        }
    }

    /// F2: Create a VM in mainnet mode where VerifyMerkle is gated
    /// Behind `MainnetActivation::full`.
    pub fn with_mainnet_mode(memory_size: usize, gas_limit: u64, mainnet: bool) -> Self {
        let mut vm = Self::with_gas_limit(memory_size, gas_limit);
        vm.mainnet_mode = mainnet;
        vm
    }

    pub fn consume_gas(&mut self, amount: u64) -> Result<(), VmError> {
        self.gas_used = self.gas_used.saturating_add(amount);
        if self.gas_used > self.gas_limit {
            self.halted = true;
            self.error = Some(VmError::OutOfGas);
            return Err(VmError::OutOfGas);
        }
        Ok(())
    }

    pub fn step(&mut self, program: &[u64]) -> Result<(), VmError> {
        // (security audit) semantics of error returns.
        //
        // On any error path, `Vm::step` does NOT push a Step to
        // `self.trace` for the failing instruction. The matching terminal
        // Halt step is appended by `run_receipt` after the error is
        // Observed, so the trace still ends with a Halt row and the AIR
        // Termination constraint is satisfied. The set of fields that
        // `step` is allowed to mutate on error is: `halted` (set to true)
        // And `error` (set to Some(...)). Do not push partial steps.
        self.registers[0] = 0; // Enforce r0 is always 0
        if self.halted {
            return Ok(());
        }
        if self.pc >= program.len() {
            self.halted = true;
            self.error = Some(VmError::InvalidPc);
            return Err(VmError::InvalidPc);
        }

        let raw_inst = program[self.pc];
        let inst = match decode_instruction(raw_inst, self.mainnet_mode) {
            Ok(i) => i,
            Err(e) => {
                self.halted = true;
                self.error = Some(VmError::InvalidOpcode(e.clone()));
                return Err(VmError::InvalidOpcode(e));
            }
        };

        let cur_pc = self.pc;
        self.consume_gas(Self::gas_cost(inst.opcode))?;

        let src1_idx = inst.rs1;
        let src2_idx = inst.rs2;
        let dst_idx = inst.rd;
        let src1_val = self.registers[src1_idx as usize];
        let src2_val = self.registers[src2_idx as usize];

        let mut memory_addr = None;
        let mut memory_val = None;
        let mut is_memory_write = false;

        let (dst_val, next_pc) = match inst.opcode {
            Opcode::Halt => {
                self.halted = true;
                (0, cur_pc)
            }
            Opcode::Add => {
                // Goldilocks field add - must match the AIR's
                // `rd = rs1 + rs2` field constraint (see GOLDILOCKS_P).
                let result = field_add_goldilocks(src1_val, src2_val);
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Sub => {
                // Goldilocks field sub - matches the AIR field constraint.
                let result = field_sub_goldilocks(src1_val, src2_val);
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Mul => {
                // Goldilocks field mul - matches the AIR field constraint.
                let result = field_mul_goldilocks(src1_val, src2_val);
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Div => {
                const P: u64 = 18446744069414584321;
                let result = if src2_val != 0 {
                    let inv = field_inverse_goldilocks(src2_val);
                    ((src1_val as u128 * inv as u128) % P as u128) as u64
                } else {
                    0
                };
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Inv => {
                let result = if src1_val != 0 {
                    field_inverse_goldilocks(src1_val)
                } else {
                    0
                };
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::And => {
                let result = src1_val & src2_val;
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Not => {
                let result = if src1_val == 0 { 1 } else { 0 };
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Load => {
                let result = if src1_idx == 0 {
                    inst.imm as u64
                } else if let Some(addr) =
                    Self::memory_word_addr(src1_val, inst.imm, self.memory.len())
                {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&self.memory[addr..addr + 8]);
                    memory_addr = Some(addr);
                    let val = u64::from_le_bytes(bytes);
                    memory_val = Some(val);
                    val
                } else {
                    self.halted = true;
                    self.error = Some(VmError::InvalidMemoryAccess);
                    return Err(VmError::InvalidMemoryAccess);
                };
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Store => {
                if let Some(addr) = Self::memory_word_addr(src1_val, inst.imm, self.memory.len()) {
                    let bytes = src2_val.to_le_bytes();
                    self.memory[addr..addr + 8].copy_from_slice(&bytes);
                    memory_addr = Some(addr);
                    memory_val = Some(src2_val);
                    is_memory_write = true;
                } else {
                    self.halted = true;
                    self.error = Some(VmError::InvalidMemoryAccess);
                    return Err(VmError::InvalidMemoryAccess);
                }
                self.pc += 1;
                (0, cur_pc + 1)
            }
            Opcode::Jmp => {
                let target = (cur_pc as i64 + inst.imm as i64) as usize;
                self.pc = target;
                (0, target)
            }
            Opcode::Jnz => {
                let target = if src1_val != 0 {
                    (cur_pc as i64 + inst.imm as i64) as usize
                } else {
                    cur_pc + 1
                };
                self.pc = target;
                (0, target)
            }
            Opcode::Call => {
                if self.stack.len() >= 1024 {
                    self.halted = true;
                    self.error = Some(VmError::StackOverflow);
                    return Err(VmError::StackOverflow);
                }
                let target = (cur_pc as i64 + inst.imm as i64) as usize;
                self.stack.push((cur_pc + 1) as u64);
                self.pc = target;
                ((cur_pc + 1) as u64, target)
            }
            Opcode::Ret => {
                let target = match self.stack.pop() {
                    Some(val) => val as usize,
                    None => {
                        self.halted = true;
                        self.error = Some(VmError::StackUnderflow);
                        return Err(VmError::StackUnderflow);
                    }
                };
                self.pc = target;
                (target as u64, target)
            }
            Opcode::Push => {
                if self.stack.len() >= 1024 {
                    self.halted = true;
                    self.error = Some(VmError::StackOverflow);
                    return Err(VmError::StackOverflow);
                }
                self.stack.push(src1_val);
                self.pc += 1;
                (src1_val, cur_pc + 1)
            }
            Opcode::Pop => {
                let result = match self.stack.pop() {
                    Some(val) => val,
                    None => {
                        self.halted = true;
                        self.error = Some(VmError::StackUnderflow);
                        return Err(VmError::StackUnderflow);
                    }
                };
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Eq => {
                let result = if src1_val == src2_val { 1 } else { 0 };
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Neq => {
                let result = if src1_val != src2_val { 1 } else { 0 };
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Lt => {
                let result = if src1_val < src2_val { 1 } else { 0 };
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Gt => {
                let result = if src1_val > src2_val { 1 } else { 0 };
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Lte => {
                let result = if src1_val <= src2_val { 1 } else { 0 };
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Gte => {
                let result = if src1_val >= src2_val { 1 } else { 0 };
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Assert => {
                if src1_val == 0 {
                    self.halted = true;
                    self.error = Some(VmError::AssertionFailed);
                    return Err(VmError::AssertionFailed);
                }
                self.pc += 1;
                (0, cur_pc + 1)
            }
            Opcode::SRead => {
                let slot = if inst.imm == -1 {
                    src2_val as i32
                } else {
                    inst.imm
                };
                let val = *self.storage.get(&slot).unwrap_or(&0);
                self.registers[dst_idx as usize] = val;
                self.pc += 1;
                (val, cur_pc + 1)
            }
            Opcode::SWrite => {
                let slot = if inst.imm == -1 {
                    src2_val as i32
                } else {
                    inst.imm
                };
                self.storage.insert(slot, src1_val);
                self.state_writes.push((slot, src1_val));
                self.pc += 1;
                (0, cur_pc + 1)
            }
            Opcode::Poseidon => {
                let result = poseidon4_hash(src1_val, src2_val);
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Log => {
                let val = src1_val;
                self.events.push(val);
                self.pc += 1;
                (0, cur_pc + 1)
            }
            Opcode::Syscall => {
                let result = match inst.imm {
                    1 => self.context.sender,
                    2 => self.context.block_height,
                    3 => self.context.nonce,
                    6 => {
                        self.events.push(0x00A1_00A1);
                        self.events.push(src1_val);
                        self.context.block_height.saturating_add(src1_val)
                    }
                    _ => 0,
                };
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::VerifyMerkle => {
                let root = src1_val;
                let leaf = src2_val;
                let path_addr = inst.imm as usize;
                // Memory layout: [key: u64, 64 × sibling: u64]
                // Total: 520 bytes (65 × u64)
                //
                // (security audit) the original step
                // Records `merkle_key` and `dst_val = 0` (the result is
                // Not known yet - it will be set by the final expansion
                // Round). 64 follow-up "expansion" rows are pushed
                // Immediately, one per Poseidon round, so the AIR can
                // Verify the path row-by-row.
                // `wrapping_add` made this bound decide the opposite of what
                // it reads like. `path_addr` is `inst.imm`, which the program
                // supplies, so a value within 520 of `usize::MAX` wraps the
                // sum to a small number, the comparison passes, and the slice
                // below is indexed at the unwrapped address. The fuzzer
                // reached it in about one second:
                //
                //   range start index 18446744073709551110 out of range for
                //   slice of length 8192
                //
                // A panic here is not a contained error. The VM executes
                // untrusted contract bytecode, `run_receipt` is the
                // non-panicking entry point every caller relies on, and the
                // release profile is `panic = "abort"`, so this is a remote
                // halt of any node that executes the instruction rather than
                // a rejected transaction.
                //
                // `checked_add` gives the bound its stated meaning: an
                // address whose window does not fit is out of range, which is
                // what the wrapped value was pretending to prove.
                let result = if path_addr
                    .checked_add(8 * 65)
                    .is_some_and(|end| end <= self.memory.len())
                {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&self.memory[path_addr..path_addr + 8]);
                    let key = u64::from_le_bytes(bytes);
                    // The key is read from memory like any other word, so it
                    // belongs in the memory argument. Without this the AIR
                    // constrains the key only for continuity across rows and
                    // nothing ties it to `path_addr`, letting a prover pick
                    // the direction bits' source out of thin air.
                    memory_addr = Some(path_addr);
                    memory_val = Some(key);
                    // We keep the path's result computation for
                    // Backward compatibility (so the dst register
                    // Still gets the correct answer), but the
                    // *sound* verification lives in the expansion
                    // Rows the AIR checks. dst_val is set to the
                    // Correct result here so the trace is faithful
                    // To the VM semantics; the AIR will additionally
                    // Constrain it via the expansion path.
                    // Path hash must match AIR single-round.
                    let mut current = leaf;
                    for i in 0..64 {
                        let sibling_addr = path_addr + 8 + i * 8;
                        bytes.copy_from_slice(&self.memory[sibling_addr..sibling_addr + 8]);
                        let sibling = u64::from_le_bytes(bytes);
                        let bit = (key >> i) & 1;
                        current = if bit == 0 {
                            merkle_poseidon_round(current, sibling)
                        } else {
                            merkle_poseidon_round(sibling, current)
                        };
                    }
                    if current == root {
                        1
                    } else {
                        0
                    }
                } else {
                    0
                };
                self.registers[dst_idx as usize] = result;
                // Stash the path key on the VM so the expansion rows
                // (pushed immediately below) can read it. We use a
                // Local `Vec<(u64, u64, u8)>`-style scratch on `self`
                // By reusing a private field - but to keep the
                // Signature simple we just walk the path twice
                // (once for `result`, once for the expansion rows
                // Below). For depth 64 this is 2*64=128 hashes per
                // VerifyMerkle, which is acceptable for an audit
                // Milestone and is in any case dwarfed by the
                // 64*8 single-round hash cost of the AIR.
                self.pc += 1;
                (result, cur_pc + 1)
            }
            // AI Inference verification opcode.
            // Kademe 3a (2026-08-28): commitment-chain binding.
            // The proof window at `src1_val` (32 bytes) carries three
            // commitments: model_c, input_c, output_c. The chain the VM can
            // check without running the model is the hash binding
            //     rd = 1 iff output_c == Poseidon(model_c, input_c)
            // and any other case answers 0 (fail-closed: a broken or missing
            // window never verifies). The real zkML verification circuit
            // (kademe 3b) is a separate architecture decision; this is the
            // on-chain commitment-chain binding. imm keeps its kademe 2b
            // meaning: 0 = STARK proof, 1 = SNARK wrap (AIR-pinned).
            Opcode::VerifyInference => {
                let proof_addr = src1_val as usize;
                let result = if proof_addr
                    .checked_add(8 * 4)
                    .is_some_and(|end| end <= self.memory.len())
                {
                    let read_u64 = |addr: usize| -> u64 {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(&self.memory[addr..addr + 8]);
                        u64::from_le_bytes(bytes)
                    };
                    let model_c = read_u64(proof_addr);
                    let input_c = read_u64(proof_addr + 8);
                    let output_c = read_u64(proof_addr + 16);
                    // poseidon4_hash(model, input) == poseidon4_hash3(model, input, 0)
                    if output_c == poseidon4_hash(model_c, input_c) {
                        1
                    } else {
                        0
                    }
                } else {
                    0
                };
                let dst_idx = inst.rd;
                if dst_idx as usize > 0 {
                    self.registers[dst_idx as usize] = result;
                }
                self.pc += 1;
                (result, cur_pc + 1)
            }
            // (2026-07-22) privacy-layer opcodes - real semantics.
            //
            // PrivacyCommit (0x20):
            //   Commitment = Poseidon3(amount=rs1, recipient=rs2, blinding=imm)
            //   Only the commitment is written to the chain (the note registry).
            //
            // NullifierCheck (0x21):
            //   Claimed_nullifier = rs1, secret = rs2
            //   Rd = 1 iff Poseidon2(secret, DOMAIN_NULLIFIER) == claimed_nullifier
            //   (Spent set membership is on the NoteRegistry side; the VM proves the ownership binding.)
            //
            // SumConservation (0x22):
            //   The Poseidon commitment is not homomorphic -> value conservation goes through a
            //   private witness: rd = 1 iff rs1 (sum of in amounts) == rs2 (sum of out amounts).
            //   The amounts are bound to the commitment with PrivacyCommit (separate rows).
            // Blinding from register (full u64),
            // Recipient tag from imm (i32 fits). Eliminates u32 truncation
            // That caused wallet-core/VM commitment mismatch and reduced
            // Blinding entropy to 32 bits (brute-forceable).
            Opcode::PrivacyCommit => {
                let amount = src1_val;
                let blinding = src2_val; // full u64 from register
                                         // Strix HIGH (CWE-682, 2026-08-17): recipient, trace'teki
                                         // It must be EXACTLY the same value as COL_IMM. COL_IMM carries a negative
                                         // imm as the Goldilocks modular negative (P - |imm|); the i64->u64
                                         // two's complement (2^64-|imm|) was incompatible with the AIR.
                                         // The VM, prover and AIR now use the same value.
                                         // Strix HIGH (CWE-682 + i32::MIN, 2026-08-17): `-imm` i32::MIN
                                         // panics for that case; unsigned_abs() is safe (|-2^31| = 2^31).
                let recipient = if inst.imm < 0 {
                    GOLDILOCKS_P.wrapping_sub(inst.imm.unsigned_abs() as u64)
                } else {
                    inst.imm as u64
                };
                let result = poseidon4_hash3(amount, blinding, recipient);
                if dst_idx as usize > 0 {
                    self.registers[dst_idx as usize] = result;
                }
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::NullifierCheck => {
                let claimed = src1_val;
                let secret = src2_val;
                let derived = poseidon4_hash(secret, DOMAIN_NULLIFIER);
                let result = if derived == claimed { 1 } else { 0 };
                if dst_idx as usize > 0 {
                    self.registers[dst_idx as usize] = result;
                }
                self.pc += 1;
                (result, cur_pc + 1)
            }
            // SumConservation uses field-safe
            // Comparison. Values >= Goldilocks prime P = 0xFFFFFFFF00000001
            // Would cause u64 vs field comparison mismatch. Reject such
            // Values (amounts should always be < P in practice).
            Opcode::SumConservation => {
                let sum_in = src1_val;
                let sum_out = src2_val;
                const GOLDILOCKS_P: u64 = 0xFFFFFFFF00000001;
                let result = if sum_in < GOLDILOCKS_P && sum_out < GOLDILOCKS_P && sum_in == sum_out
                {
                    1
                } else {
                    0
                };
                if dst_idx as usize > 0 {
                    self.registers[dst_idx as usize] = result;
                }
                self.pc += 1;
                (result, cur_pc + 1)
            }
        };

        self.registers[0] = 0; // Enforce r0 is always 0

        self.trace.push(Step {
            pc: cur_pc,
            next_pc,
            instruction: inst,
            src1_idx,
            src2_idx,
            dst_idx,
            src1_val,
            src2_val,
            dst_val,
            registers: self.registers,
            memory_addr,
            memory_val,
            is_memory_write,
            stack_pointer: self.stack.len(),
            merkle_key: None,
            merkle_current: None,
            merkle_sibling: None,
            merkle_round: None,
            merkle_is_expand: false,
            inference_model_commitment: None,
            inference_input_commitment: None,
            inference_output_commitment: None,
            inference_proof_round: None,
            inference_is_expand: false,
        });

        // (security audit) if the just-pushed step is a
        // VerifyMerkle, immediately push 64 follow-up "expansion"
        // Rows. Each row carries the current Poseidon accumulator,
        // The sibling hash for that round, the round index, and the
        // Key (the AIR uses these to verify the path). The original
        // Step's `merkle_key` is also set here (post-push, in-place
        // Via index) so the AIR knows the path's key.
        //
        // Kademe 3a (2026-08-28): VerifyInference used to share this path
        // (its 8 commitment-chain rows were pushed below, after it), which
        // produced 64 phantom Merkle expansion rows for every inference
        // proof and patched the commitment chain onto the last of them
        // instead of the original step. VerifyInference has its own
        // expansion block below and must not walk the Merkle path.
        if matches!(inst.opcode, Opcode::VerifyMerkle) {
            let path_addr = inst.imm as usize;
            // The same wrapped bound as the execution path, and it has to
            // stay identical to it. These two read the same window for two
            // different purposes, the value the register receives and the key
            // the trace records, and a bound that admitted an address in one
            // place and refused it in the other would leave the trace
            // describing a read that did not happen. Kademe 3a: only
            // `VerifyMerkle` walks this path; `VerifyInference` has its own
            // 8-row commitment-chain block below.
            if path_addr
                .checked_add(8 * 65)
                .is_some_and(|end| end <= self.memory.len())
            {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&self.memory[path_addr..path_addr + 8]);
                let key = u64::from_le_bytes(bytes);
                // Patch the just-pushed step to carry the key.
                if let Some(last) = self.trace.last_mut() {
                    last.merkle_key = Some(key);
                }
                // Walk the path and push 64 expansion rows. The
                // `current` accumulator is computed here (in the VM)
                // For the trace's faithfulness, and the AIR
                // Re-derives it independently.
                // Expansion rows carry the *pre-round*
                // Accumulator so AIR can check nxt = poseidon(cur, sibling).
                // Expansion rows share the original PC and must
                // Keep next_pc == pc until the final expansion, which hands
                // Off to the real next instruction (pc+1). The AIR enforces
                // `nxt_pc == next_pc` on every cpu row; setting next_pc=pc+1
                // On intermediate expansions makes nxt_pc (still pc) fail.
                // Also patch the original step's next_pc to stay on this pc
                // So original → first expansion satisfies the same rule.
                if let Some(last) = self.trace.last_mut() {
                    last.next_pc = cur_pc;
                }
                let mut current = src2_val; // leaf input to round 0
                for i in 0..64u8 {
                    let sibling_addr = path_addr + 8 + (i as usize) * 8;
                    let mut sb = [0u8; 8];
                    sb.copy_from_slice(&self.memory[sibling_addr..sibling_addr + 8]);
                    let sibling = u64::from_le_bytes(sb);
                    let bit = (key >> i) & 1;
                    let input = current;
                    current = if bit == 0 {
                        merkle_poseidon_round(input, sibling)
                    } else {
                        merkle_poseidon_round(sibling, input)
                    };
                    let expand_next_pc = if i == 63 { cur_pc + 1 } else { cur_pc };
                    self.trace.push(Step {
                        pc: cur_pc,
                        next_pc: expand_next_pc,
                        instruction: Instruction {
                            opcode: Opcode::VerifyMerkle, // reused; merkle_is_expand marks it
                            rd: 0,
                            rs1: 0,
                            rs2: 0,
                            // Carry the path base address. The memory
                            // argument derives each expansion row's address as
                            // `imm + 8 + 8 * round`, so a zero here would make
                            // every sibling read claim an address near zero
                            // while the memory table supplies the real one,
                            // measured as a 7-of-8 mismatch across the first
                            // rows before this was set.
                            imm: inst.imm,
                        },
                        src1_idx: 0,
                        src2_idx: 0,
                        dst_idx: 0,
                        src1_val: 0,
                        src2_val: 0,
                        dst_val: 0,
                        registers: self.registers,
                        // Each expansion row carries the read that produced
                        // its sibling. Without this the 64 words the path is
                        // built from never reach the memory argument, so the
                        // AIR sees a Poseidon chain over values that nothing
                        // ties to the program's memory - a prover could supply
                        // a path that was never there. Measured before the
                        // fix: 64 expansion rows, 0 with `memory_addr`, and 0
                        // of the 65 path words present in the argument.
                        memory_addr: Some(sibling_addr),
                        memory_val: Some(sibling),
                        is_memory_write: false,
                        stack_pointer: self.stack.len(),
                        merkle_key: Some(key),
                        merkle_current: Some(input), // pre-round
                        merkle_sibling: Some(sibling),
                        merkle_round: Some(i),
                        merkle_is_expand: true,
                        inference_model_commitment: None,
                        inference_input_commitment: None,
                        inference_output_commitment: None,
                        inference_proof_round: None,
                        inference_is_expand: false,
                    });
                }
                //: patch the original step's
                // Merkle_current to the 64th-round Poseidon
                // Output. This bridges the 64 expansion rows to
                // The original step, allowing the AIR to apply
                // The final root check on the original step's
                // Row (is_verify_merkle = 1, merkle_final_flag = 1).
                let orig_idx = self.trace.len() - 1 - 64;
                if orig_idx < self.trace.len() {
                    self.trace[orig_idx].merkle_current = Some(current);
                }
            }
        }

        // VerifyInference expansion rows.
        // If the just-pushed step is a VerifyInference, push 8 follow-up
        // Expansion rows. Each row carries the commitment values for the
        // AIR to verify the commitment chain (model → input → output).
        // Fix next_pc pattern to match VerifyMerkle:
        // Original step stays on cur_pc, expansion rows 0-6 stay on cur_pc,
        // Expansion row 7 advances to cur_pc+1.
        if matches!(inst.opcode, Opcode::VerifyInference) {
            let proof_addr = src1_val as usize;
            // The third copy of the bound the fuzzer broke, and the one whose
            // address is the easiest to steer: `src1_val` is a register, so it
            // is whatever the program last computed rather than a field of the
            // instruction word. `wrapping_add` let a value near the top of the
            // space wrap to a small sum, pass this comparison, and index the
            // slice below at the unwrapped address.
            //
            // `VerifyInference` (kademe 3a) answers from the same window this
            // block reads: the register value and the trace key come from the
            // same memory. This block runs before that answer is used: it is
            // the trace writer, and it reads memory whether or not the
            // opcode's answer is used. The bound below must stay identical to
            // the execution bound above - a bound that admitted an address in
            // one place and refused it in the other would leave the trace
            // describing a read that did not happen.
            if proof_addr
                .checked_add(8 * 4)
                .is_some_and(|end| end <= self.memory.len())
            {
                let read_u64 = |addr: usize| -> u64 {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&self.memory[addr..addr + 8]);
                    u64::from_le_bytes(bytes)
                };
                let model_c = read_u64(proof_addr);
                let input_c = read_u64(proof_addr + 8);
                let output_c = read_u64(proof_addr + 16);

                // Patch the original step (just pushed, still the last row)
                // with commitments and next_pc = cur_pc. Kademe 3a: this used
                // to hit the last of the phantom Merkle expansion rows; with
                // VerifyInference off the Merkle path, `last` is the
                // original step again.
                if let Some(last) = self.trace.last_mut() {
                    last.inference_model_commitment = Some(model_c);
                    last.inference_input_commitment = Some(input_c);
                    last.inference_output_commitment = Some(output_c);
                    last.next_pc = cur_pc; // stay on same PC for expansion
                }

                // Push 8 expansion rows for AIR commitment verification
                for round in 0..8u8 {
                    let expand_next_pc = if round == 7 { cur_pc + 1 } else { cur_pc };
                    self.trace.push(Step {
                        pc: cur_pc,
                        next_pc: expand_next_pc,
                        instruction: Instruction {
                            opcode: Opcode::VerifyInference,
                            rd: 0,
                            rs1: inst.rs1,
                            rs2: inst.rs2,
                            imm: round as i32,
                        },
                        src1_idx: inst.rs1,
                        src2_idx: inst.rs2,
                        dst_idx: 0,
                        src1_val,
                        src2_val,
                        dst_val: 0,
                        registers: self.registers,
                        memory_addr: None,
                        memory_val: None,
                        is_memory_write: false,
                        stack_pointer: self.stack.len(),
                        merkle_key: None,
                        merkle_current: None,
                        merkle_sibling: None,
                        merkle_round: None,
                        merkle_is_expand: false,
                        inference_model_commitment: Some(model_c),
                        inference_input_commitment: Some(input_c),
                        inference_output_commitment: Some(output_c),
                        inference_proof_round: Some(round),
                        inference_is_expand: true,
                    });
                }
            }
        }

        debug!(
            pc = cur_pc,
            op = ?inst.opcode,
            rd = inst.rd,
            rs1 = inst.rs1,
            rs2 = inst.rs2,
            imm = inst.imm,
            dst_val,
            gas = self.gas_used,
            "Step executed"
        );

        Ok(())
    }

    pub fn run(&mut self, program: &[u64]) -> Result<ExecutionReceipt, VmError> {
        let receipt = self.run_receipt(program);
        if let Some(ref e) = receipt.error {
            Err(e.clone())
        } else {
            Ok(receipt)
        }
    }

    pub fn run_receipt(&mut self, program: &[u64]) -> ExecutionReceipt {
        let mut error = None;
        while !self.halted {
            if let Err(e) = self.step(program) {
                error = Some(e);
                break;
            }
        }

        // (security audit) when the program terminates with an
        // Error (OutOfGas, StackUnderflow, InvalidMemoryAccess, ...),
        // `Vm::step` returns before pushing the failing step to `self.trace`.
        // We still need a terminal row in the trace so that the AIR's
        // `cpu_active` transition lands on a Halt row, matching
        // Termination constraint. Synthesize a synthetic Halt step here.
        // The synthetic step is byte-identical to a real Halt (pc = current
        // Pc, dst_val = 0, all other fields zeroed / derived from the VM
        // State) and is *only* appended when the program ended on an error
        // (i.e. there is no real Halt in the trace yet).
        if error.is_some() {
            let last_is_halt = self
                .trace
                .last()
                .map(|s| matches!(s.instruction.opcode, Opcode::Halt))
                .unwrap_or(false);
            if !last_is_halt {
                let cur_pc = self.pc;
                let inst = Instruction {
                    opcode: Opcode::Halt,
                    rd: 0,
                    rs1: 0,
                    rs2: 0,
                    imm: 0,
                };
                self.trace.push(Step {
                    pc: cur_pc,
                    next_pc: cur_pc,
                    instruction: inst,
                    src1_idx: 0,
                    src2_idx: 0,
                    dst_idx: 0,
                    src1_val: 0,
                    src2_val: 0,
                    dst_val: 0,
                    registers: self.registers,
                    memory_addr: None,
                    memory_val: None,
                    is_memory_write: false,
                    stack_pointer: self.stack.len(),
                    merkle_key: None,
                    merkle_current: None,
                    merkle_sibling: None,
                    merkle_round: None,
                    merkle_is_expand: false,
                    inference_model_commitment: None,
                    inference_input_commitment: None,
                    inference_output_commitment: None,
                    inference_proof_round: None,
                    inference_is_expand: false,
                });
            }
        }

        // Strix HIGH CWE-345 (2026-08-17): state-write digest is a Poseidon
        // STATE CHAIN over the executed (slot, val) pairs in EXECUTION ORDER
        // (matching the trace, which feeds the gadget on each SWrite row in
        // program order). 32 bytes = first 4 lanes of the final accumulator.
        let mut acc = [0u64; 8];
        for (slot, val) in &self.state_writes {
            let mut st = [0u64; 8];
            st[0] = *slot as u64;
            st[1] = *val;
            st[2] = acc[0];
            st[3] = acc[1];
            st[4] = acc[2];
            st[5] = acc[3];
            acc = poseidon_full_state(st);
        }
        let mut state_writes_digest = [0u8; 32];
        for k in 0..4 {
            state_writes_digest[k * 8..k * 8 + 8].copy_from_slice(&acc[k].to_le_bytes());
        }

        ExecutionReceipt {
            success: error.is_none(),
            error: error.clone(),
            gas_used: self.gas_used,
            exit_code: if error.is_none() { 0 } else { 1 },
            events: self.events.clone(),
            final_pc: self.pc as u64,
            trace_len: self.trace.len() as u64,
            state_writes_digest,
        }
    }

    fn memory_word_addr(base: u64, imm: i32, memory_len: usize) -> Option<usize> {
        let addr = i128::from(base) + i128::from(imm);
        if addr < 0 {
            return None;
        }

        let addr = usize::try_from(addr).ok()?;
        let end = addr.checked_add(8)?;
        (end <= memory_len).then_some(addr)
    }

    pub fn gas_cost(opcode: Opcode) -> u64 {
        match opcode {
            Opcode::Halt => 0,
            // Memory ops stay cheap.
            Opcode::Load | Opcode::Store => 3,
            // Storage ops are more expensive than plain memory
            // (persist / state-root impact); price them above Load/Store.
            Opcode::SRead => 8,
            Opcode::SWrite => 12,
            Opcode::Poseidon
            | Opcode::VerifyMerkle
            | Opcode::VerifyInference
            | Opcode::PrivacyCommit
            | Opcode::NullifierCheck
            | Opcode::SumConservation => 10,
            Opcode::Call | Opcode::Ret | Opcode::Push | Opcode::Pop => 2,
            Opcode::Syscall => 5,
            // `Div` is a binary long division: the AIR expands one row per bit
            // (up to 64), so leaving it on the cheap default would be a cheap
            // call that forces expensive proof work. Priced with the heavy
            // ops, not the arithmetic default.
            Opcode::Div => 10,
            _ => 1,
        }
    }
}

/// Single-round Poseidon used by `VerifyMerkle` path hashing.
/// Must match `BudAir` Merkle expansion constraints (RC0 + MDS first row [7,1]).
/// Distinct from `poseidon4_hash` (4 full rounds) used by the Poseidon opcode.
pub fn merkle_poseidon_round(a: u64, b: u64) -> u64 {
    const P: u64 = 0xFFFFFFFF00000001;
    const RC0: [u64; 2] = [0xdd5743e7f2a5a5d9, 0xcb3a864e58ada44b];
    let s0 = ((a as u128 + RC0[0] as u128) % P as u128) as u64;
    let s1 = ((b as u128 + RC0[1] as u128) % P as u128) as u64;
    let sbox = |x: u64| -> u64 {
        let x2 = ((x as u128 * x as u128) % P as u128) as u64;
        let x4 = ((x2 as u128 * x2 as u128) % P as u128) as u64;
        (((x4 as u128 * x2 as u128) % P as u128 * x as u128) % P as u128) as u64
    };
    let out = (7u128 * sbox(s0) as u128 + sbox(s1) as u128) % P as u128;
    out as u64
}

/// 4-round Poseidon hash over Goldilocks field (alpha=7, width=8, full rounds only).
/// Used for both VM execution and prover trace generation.
///
/// MDS circulant matrix first row: [7, 1, 3, 8, 8, 3, 4, 9]
/// Domain separator for nullifier derivation.
/// ASCII-ish constant "NULLIFER" as a field element, domain-separates
/// Nullifier hashes from plain Poseidon(a,b) and PrivacyCommit.
pub const DOMAIN_NULLIFIER: u64 = 0x4e55_4c4c_4946_4552; // "NULLIFER"

/// MDS circulant matrix - must match BudAir / plonky3_prover.
/// Module-level const so lock test can access.
pub const POSEIDON_MDS: [[u64; 8]; 8] = [
    [7, 1, 3, 8, 8, 3, 4, 9],
    [9, 7, 1, 3, 8, 8, 3, 4],
    [4, 9, 7, 1, 3, 8, 8, 3],
    [3, 4, 9, 7, 1, 3, 8, 8],
    [8, 3, 4, 9, 7, 1, 3, 8],
    [8, 8, 3, 4, 9, 7, 1, 3],
    [3, 8, 8, 3, 4, 9, 7, 1],
    [1, 3, 8, 8, 3, 4, 9, 7],
];

/// Round constants: first 4 rounds from Plonky3 Poseidon1 Goldilocks width-8.
/// Module-level const so lock test can access.
/// Full Poseidon1 round constants for Goldilocks width 8 - the parameter set
/// the weak 4-round permutation below is a truncation of.
///
/// Source: Plonky3 `goldilocks/src/poseidon1.rs`, `GOLDILOCKS_POSEIDON1_RC_8`.
/// Verified: `POSEIDON_RC` (the 4-round set actually in use) is byte-identical
/// to the first four rows here, which is what makes the truncation claim
/// checkable rather than folklore - see `four_round_set_is_a_prefix_of_full`.
///
/// Round schedule for this instance:
///
/// ```text
///   R_F = 8   full rounds    (4 leading + 4 trailing)
///   R_P = 22  partial rounds (S-box on lane 0 only)
///   total     30 rounds, 86 S-box evaluations
/// ```
///
/// R_P is not a taste: it comes from the interpolation bound in the Poseidon
/// paper (Eq. 3) for this field and S-box,
///
/// ```text
///   R_interp >= ceil(min(k, n) / log2(alpha)) + ceil(log_alpha(t)) - 5
///             = ceil(64 / log2(7)) + ceil(log_7(8)) - 5
///             = 23 + 2 - 5 = 20
/// ```
///
/// plus the paper's +7.5% margin: `ceil(1.075 * 20) = 22`.
///
/// # Why this constant exists but is not wired in
///
/// [`poseidon4_hash_state`] still runs four rounds, because the BudZero AIR
/// constrains exactly four (`plonky3_air.rs`, `for r in 0..4`). Swapping the
/// permutation without rebuilding those constraints would produce proofs that
/// attest to a different function than the VM ran, a soundness break strictly
/// worse than the weak hash. The parameters are derived and pinned here so the
/// AIR work has something exact to target; the opcodes that depend on the hash
/// stay disabled until it lands.
pub const POSEIDON_RC_FULL: [[u64; 8]; 30] = [
    // round  0 (full)
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
    // round  1 (full)
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
    // round  2 (full)
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
    // round  3 (full)
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
    // round  4 (partial)
    [
        0x488897d85ff51f56,
        0x1140737ccb162218,
        0xa7eeb9215866ed35,
        0x9bd2976fee49fcc9,
        0xc0c8f0de580a3fcc,
        0x4fb2dae6ee8fc793,
        0x343a89f35f37395b,
        0x223b525a77ca72c8,
    ],
    // round  5 (partial)
    [
        0x56ccb62574aaa918,
        0xc4d507d8027af9ed,
        0xa080673cf0b7e95c,
        0xf0184884eb70dcf8,
        0x044f10b0cb3d5c69,
        0xe9e3f7993938f186,
        0x1b761c80e772f459,
        0x606cec607a1b5fac,
    ],
    // round  6 (partial)
    [
        0x14a0c2e1d45f03cd,
        0x4eace8855398574f,
        0xf905ca7103eff3e6,
        0xf8c8f8d20862c059,
        0xb524fe8bdd678e5a,
        0xfbb7865901a1ec41,
        0x014ef1197d341346,
        0x9725e20825d07394,
    ],
    // round  7 (partial)
    [
        0xfdb25aef2c5bae3b,
        0xbe5402dc598c971e,
        0x93a5711f04cdca3d,
        0xc45a9a5b2f8fb97b,
        0xfe8946a924933545,
        0x2af997a27369091c,
        0xaa62c88e0b294011,
        0x058eb9d810ce9f74,
    ],
    // round  8 (partial)
    [
        0xb3cb23eced349ae4,
        0xa3648177a77b4a84,
        0x43153d905992d95d,
        0xf4e2a97cda44aa4b,
        0x5baa2702b908682f,
        0x082923bdf4f750d1,
        0x98ae09a325893803,
        0xf8a6475077968838,
    ],
    // round  9 (partial)
    [
        0xceb0735bf00b2c5f,
        0x0a1a5d953888e072,
        0x2fcb190489f94475,
        0xb5be06270dec69fc,
        0x739cb934b09acf8b,
        0x537750b75ec7f25b,
        0xe9dd318bae1f3961,
        0xf7462137299efe1a,
    ],
    // round 10 (partial)
    [
        0xb1f6b8eee9adb940,
        0xbdebcc8a809dfe6b,
        0x40fc1f791b178113,
        0x3ac1c3362d014864,
        0x9a016184bdb8aeba,
        0x95f2394459fbc25e,
        0xe3f34a07a76a66c2,
        0x8df25f9ad98b1b96,
    ],
    // round 11 (partial)
    [
        0x85ffc27171439d9d,
        0xddcb9a2dcfd26910,
        0x26b5ba4bf3afb94e,
        0xffff9cc7c7651e2f,
        0x8c88364698280b55,
        0xebc114167b910501,
        0x2d77b4d89ecfb516,
        0x332e0828eba151f2,
    ],
    // round 12 (partial)
    [
        0x46fa6a6450dd4735,
        0xd00db7dd92384a33,
        0x5fd4fb751f3a5fc5,
        0x496fb90c0bb65ea2,
        0xf3baec0bb87cc5c7,
        0x862a3c0a7d4c7713,
        0xbf5f38336a3f47d8,
        0x41ad9dbc1394a20c,
    ],
    // round 13 (partial)
    [
        0xcc535945b7dbf0f7,
        0x82af2bc93685bcec,
        0x8e4c8d0c8cebfccd,
        0x17cb39417e84597e,
        0xd4a965a8c749b232,
        0xa2cab040f33f3ee5,
        0xa98811a1fed4e3a6,
        0x1cc48b54f377e2a1,
    ],
    // round 14 (partial)
    [
        0xe40cd4f6c5609a27,
        0x11de79ebca97a4a4,
        0x9177c73d8b7e929d,
        0x2a6fe8085797e792,
        0x3de6e93329f8d5ae,
        0x3f7af9125da962ff,
        0xd710682cfc77d3ac,
        0x48faf05f3b053cf4,
    ],
    // round 15 (partial)
    [
        0x287db8630da89c8b,
        0x4d0de32053cb30e9,
        0x8b37a4f20c5ada7b,
        0xe7cc6ebe78c84ecf,
        0x240bdc0a66a2610d,
        0x8299e7f02caa1650,
        0x380a53fefb6e754e,
        0x684a1d8cf8eb6810,
    ],
    // round 16 (partial)
    [
        0xe839452eb4b8a5e1,
        0xb03fa62e90626af4,
        0x11a688602fbc5efc,
        0x30dda75c355a2d62,
        0x0f712adcb73810de,
        0xffdc1102187f1ae1,
        0x40c34f398254b99c,
        0xede021b9dc289a4a,
    ],
    // round 17 (partial)
    [
        0x8b7b05225c4e7dad,
        0x3bc794346f9d9ff9,
        0xfccb5a57f2ca86ff,
        0xbb1502015a7da9d4,
        0xd7e0a35d4352a015,
        0x27af7a44f8160931,
        0xc37442f6782f4615,
        0xbdf392a9bd095dcb,
    ],
    // round 18 (partial)
    [
        0xc17f55037cf00de9,
        0xbcffedd34c71a874,
        0x5eb45d2a8133d1f2,
        0xbabe251e1612ebdf,
        0x3efeb9fbe438c536,
        0x2d7cef97b4afe1cf,
        0xe5de1b4660016c0b,
        0xcdcc26c332f5657c,
    ],
    // round 19 (partial)
    [
        0xe01dd653daf15809,
        0xb0a6bdd4b41094b5,
        0x27eac858b0b03a05,
        0x51d43b5e93adbdc0,
        0x8b89a23b0fea5fc9,
        0xdc8ac3b14f7f2fc1,
        0xe793f82f1efec039,
        0x9f6f2cf8969e7b80,
    ],
    // round 20 (partial)
    [
        0x49d45382e0f21d4a,
        0x5f4ad1797cd72786,
        0x4dc3dbebfd45f795,
        0x03a3ef84dba6e1bc,
        0x204bc9b3d3fc4c01,
        0x9ad706081e89b9ba,
        0x638bfb4d840e9f89,
        0x5ef2938cd095ae35,
    ],
    // round 21 (partial)
    [
        0x42cca18ebeb265c8,
        0xb7b2ec5c29aecbf8,
        0x0d84f9535dc78f0f,
        0x04e64ad942e77b8c,
        0xb4880dffffc9da0b,
        0x16db16d9c29adeb1,
        0x09bbaf2a0590cd1e,
        0x76460e74961fcf8d,
    ],
    // round 22 (partial)
    [
        0xed12a2276dfa1553,
        0x0b5acec5de0436fd,
        0x3c6cfea033a1f0a8,
        0x2b5ecefe546cac15,
        0x6e2d82884cd3bf6f,
        0xc134878d1add7b83,
        0x997963422eb7a280,
        0x5e834537ac648cf6,
    ],
    // round 23 (partial)
    [
        0x89e779214737c0b7,
        0x1a8c05e8581ad95b,
        0x8d18b72796437cf7,
        0xe7252c949e04b106,
        0x53267c4fd174585a,
        0xa16ef5d9c81dad47,
        0xda65191937270a46,
        0xcb2a5b55f2df664c,
    ],
    // round 24 (partial)
    [
        0x854aee2dc1924137,
        0xf37013c9d479ece6,
        0x0e163bc0630c4696,
        0x384ee64955048f76,
        0xf65d814e28ee4ec5,
        0xe57bc564fd82f1b1,
        0x4b338937b6876614,
        0x66ee0b04ed43cd8d,
    ],
    // round 25 (partial)
    [
        0x49884bf25f4ef15d,
        0xeb51fe28de1c6f54,
        0x2cd64e84fce8dfcc,
        0x29164a96a541a013,
        0x173ce7558f4cacb8,
        0xeb5b1ce5877c89e9,
        0x5faff4b0f5217bf6,
        0xac42d0b1c20f205e,
    ],
    // round 26 (full)
    [
        0xfb1d6bf0ca43221b,
        0x97b0a1b01d6a2955,
        0x08c60bd622952b30,
        0x43f2be0f9e24147c,
        0xfa7268b7d3730f5d,
        0x43a6c419a23983bb,
        0xcd77c1f7b29b113c,
        0xcfa43c9db8eec29f,
    ],
    // round 27 (full)
    [
        0xcaaa95a6c7365dec,
        0x0a91193f798f3be0,
        0x1104497652735dc6,
        0x35aecb93663b515e,
        0x8dbc9916065aa858,
        0xada8f7a0266579ed,
        0x524dee7bec1ea789,
        0xa93aee9dd5af9521,
    ],
    // round 28 (full)
    [
        0x9d1f1b54750d707e,
        0x7c9feab87096d5dc,
        0xa2e1fb19f9d4261b,
        0xb714deb448de6346,
        0x225d1f0d011c5403,
        0x1549b7f1d28cedc0,
        0xaef3e46f97d43942,
        0x6dfc7ffe0b38bf08,
    ],
    // round 29 (full)
    [
        0x7de853fdc542b663,
        0xa68ecc96610657b2,
        0xe88bb5428af289b1,
        0xd7cfa1504c5569f5,
        0x78a9aad0d642d30a,
        0xd68315f2353dce52,
        0x46e56300f86fcfd5,
        0x323d95332b145fd6,
    ],
];

/// Full rounds for the Goldilocks width-8 Poseidon1 instance (4 leading + 4
/// trailing).
pub const POSEIDON_FULL_ROUNDS: usize = 8;

/// Partial rounds for the same instance (see [`POSEIDON_RC_FULL`] for the
/// derivation).
pub const POSEIDON_PARTIAL_ROUNDS: usize = 22;

/// S-box exponent. `gcd(7, P - 1) = 1` over Goldilocks, so `x -> x^7` is a
/// permutation of the field.
pub const POSEIDON_ALPHA: u64 = 7;

/// Rounds actually evaluated by [`poseidon4_hash_state`], and constrained by
/// the AIR. It now equals the full schedule; the constant is kept because
/// `vm_hash_still_matches_the_air_round_count` asserts the VM and the AIR
/// agree, and that check is the thing keeping them from drifting apart again.
pub const POSEIDON_ROUNDS_IN_USE: usize = POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS;

/// Reference implementation of the **full** 30-round permutation.
///
/// Not used by the VM: the AIR constrains four rounds, and the VM must compute
/// what the AIR checks. This exists so the target is executable, the AIR work
/// can be validated against it, and
/// `full_permutation_differs_from_truncated_one` proves the two really are
/// different functions rather than the same one under another name.
pub fn poseidon_full_hash_state(mut s: [u64; 8]) -> u64 {
    const P: u64 = GOLDILOCKS_P;
    let sbox = |x: u64| -> u64 {
        let x2 = ((x as u128 * x as u128) % P as u128) as u64;
        let x4 = ((x2 as u128 * x2 as u128) % P as u128) as u64;
        (((x4 as u128 * x2 as u128) % P as u128 * x as u128) % P as u128) as u64
    };
    let half_full = POSEIDON_FULL_ROUNDS / 2;
    for (round, rc) in POSEIDON_RC_FULL.iter().enumerate() {
        for i in 0..8 {
            s[i] = ((s[i] as u128 + rc[i] as u128) % P as u128) as u64;
        }
        // Full rounds apply the S-box to every lane; partial rounds only to
        // lane 0. That asymmetry is the whole point of the partial rounds,
        // they raise the algebraic degree cheaply.
        let is_full = round < half_full || round >= POSEIDON_RC_FULL.len() - half_full;
        if is_full {
            for lane in s.iter_mut() {
                *lane = sbox(*lane);
            }
        } else {
            s[0] = sbox(s[0]);
        }
        let mut next = [0u64; 8];
        for i in 0..8 {
            let mut sum: u128 = 0;
            for j in 0..8 {
                sum = (sum + POSEIDON_MDS[i][j] as u128 * s[j] as u128) % P as u128;
            }
            next[i] = sum as u64;
        }
        s = next;
    }
    s[0]
}

/// Full 30-round Poseidon permutation returning the ENTIRE 8-lane state.
///
/// Strix HIGH CWE-345 (2026-08-17): the state-write digest must be bound to
/// executed `SWrite` effects inside the STARK. `poseidon_full_hash_state`
/// collapses the state to lane 0; this variant returns all 8 lanes so the
/// AIR can constrain a state chain (slot, val, prev_acc..) -> next_acc in
/// full, matching the witness columns it already constrains.
pub fn poseidon_full_state(mut s: [u64; 8]) -> [u64; 8] {
    const P: u64 = GOLDILOCKS_P;
    let sbox = |x: u64| -> u64 {
        let x2 = ((x as u128 * x as u128) % P as u128) as u64;
        let x4 = ((x2 as u128 * x2 as u128) % P as u128) as u64;
        (((x4 as u128 * x2 as u128) % P as u128 * x as u128) % P as u128) as u64
    };
    let half_full = POSEIDON_FULL_ROUNDS / 2;
    for (round, rc) in POSEIDON_RC_FULL.iter().enumerate() {
        for i in 0..8 {
            s[i] = ((s[i] as u128 + rc[i] as u128) % P as u128) as u64;
        }
        let is_full = round < half_full || round >= POSEIDON_RC_FULL.len() - half_full;
        if is_full {
            for lane in s.iter_mut() {
                *lane = sbox(*lane);
            }
        } else {
            s[0] = sbox(s[0]);
        }
        let mut next = [0u64; 8];
        for i in 0..8 {
            let mut sum: u128 = 0;
            for j in 0..8 {
                sum = (sum + POSEIDON_MDS[i][j] as u128 * s[j] as u128) % P as u128;
            }
            next[i] = sum as u64;
        }
        s = next;
    }
    s
}

/// Round constants for the 4-round Poseidon permutation.
///
/// # Superseded - kept only as the AIR's historical prefix
///
/// `poseidon4_hash_state` no longer uses these. It runs the full 30-round
/// permutation ([`POSEIDON_RC_FULL`]), which the AIR now constrains in full.
/// The four-round set below is retained because
/// `four_round_set_is_a_prefix_of_full` checks it against the full table, and
/// because the security note is worth keeping next to the numbers it is about.
///
/// What was wrong with it:
///
/// Four full rounds with `alpha = 7` and no partial rounds leaves the whole
/// permutation at algebraic degree `7^4 = 2401`. A system of that degree is
/// invertible in practice by interpolation or a Gröbner-basis attack, and the
/// function is cheap enough that a generic birthday collision search (~2^32
/// evaluations) is hours of GPU time rather than a theoretical bound.
///
/// For `PrivacyCommit` that means an observer can recover
/// `(amount, blinding, recipient_tag)` from a published commitment, hiding is
/// gone, and can find a second opening for the same commitment or nullifier,
/// binding is gone.
///
/// These are the *first four rounds* of Plonky3's Goldilocks width-8 Poseidon1
/// instance. Real parameters for this width need roughly 8 full plus 22 partial
/// rounds; this is a truncation of a safe set, not a design.
///
/// The AIR is not the problem: it constrains all four rounds faithfully, so the
/// proof system honestly proves that this weak function was evaluated
/// correctly.
///
/// The opcodes that depend on it are disabled by default in `MainnetActivation`
/// and `bud-isa` carries a test that fails if that changes while the round
/// count is still four. Fix the parameters before enabling them.
pub const POSEIDON_RC: [[u64; 8]; 4] = [
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

/// 4-round Poseidon over Goldilocks with an arbitrary 8-element initial state
/// (alpha=7, width=8, full rounds only). Shared by `poseidon4_hash`,
/// `poseidon4_hash3` and the AIR Poseidon gadget.
pub fn poseidon4_hash_state(s: [u64; 8]) -> u64 {
    // Kept under its historical name so call sites do not churn, but this is
    // the full 30-round permutation now: `R_F = 8`, `R_P = 22`, `alpha = 7`.
    // The AIR in `bud-proof` constrains exactly these rounds and the prover
    // fills exactly these witness columns, so all three move together.
    poseidon_full_hash_state(s)
}

/// 4-round Poseidon over Goldilocks with 3 absorbed field elements
/// (state = [a, b, c, 0, 0, 0, 0, 0]). Used by `PrivacyCommit`.
pub fn poseidon4_hash3(a: u64, b: u64, c: u64) -> u64 {
    poseidon4_hash_state([a, b, c, 0, 0, 0, 0, 0])
}

/// 4-round Poseidon hash over Goldilocks field (alpha=7, width=8, full rounds only).
///
/// Rate-2 absorption: state = [a, b, 0, 0, 0, 0, 0, 0]. Used by the Poseidon
/// Opcode and NullifierCheck (with DOMAIN_NULLIFIER as second input).
///
/// Round constants: first 4 rounds from Plonky3 Poseidon1 Goldilocks width-8
pub fn poseidon4_hash(a: u64, b: u64) -> u64 {
    poseidon4_hash_state([a, b, 0, 0, 0, 0, 0, 0])
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The address whose window wraps must be refused, not indexed.
    ///
    /// `VerifyMerkle` reads a 520-byte window at `inst.imm`. The bound used
    /// `wrapping_add`, so an address near the top of the space wrapped to a
    /// small sum, compared as in range, and then indexed the slice at the
    /// unwrapped value. `vm_execute` found it in roughly a second of fuzzing.
    ///
    /// An unreadable window answers "not verified" and the program continues,
    /// which is the opcode's existing contract for an address out of range.
    /// The property under test is that the answer is a value rather than an
    /// abort: under `panic = "abort"` the difference between the two is the
    /// difference between a rejected proof and a halted node.
    #[test]
    fn verify_merkle_refuses_an_address_whose_window_wraps() {
        // -1 as i32 sign-extends to usize::MAX, and usize::MAX + 520 wraps to
        // 518, which is below any sane memory length. Before the fix this
        // compared as in range and then indexed at the unwrapped address.
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, -1),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(8192);
        let receipt = vm.run_receipt(&program);
        assert!(
            receipt.success,
            "the program must run to Halt rather than abort the process"
        );
        assert_eq!(
            vm.registers[1], 0,
            "a window that does not fit cannot have verified a path"
        );
    }

    /// The same bound, one byte past the end rather than wrapped.
    ///
    /// Wrapping is the exotic case; this is the ordinary one, and it is what
    /// shows the replacement still refuses for the plain reason too.
    #[test]
    fn verify_merkle_refuses_a_window_that_runs_past_the_end() {
        let memory = 8192usize;
        // The window is 520 bytes, so the last address that fits is
        // memory - 520. One past that must not be read.
        let too_far = i32::try_from(memory - 520 + 1).expect("fits in i32");
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, too_far),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(memory);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the program must still reach Halt");
        assert_eq!(vm.registers[1], 0, "a window past the end must not be read");
    }

    /// The bound has to leave the legitimate case alone.
    ///
    /// A guard that refused everything would satisfy both tests above and
    /// break the opcode. The last address whose window fits exactly must
    /// still be read, which is the off-by-one the replacement could plausibly
    /// get wrong in the other direction. An all-zero memory does not hash to
    /// the zero root, so the answer is a truthful "not verified" reached by
    /// actually walking the path, and the property recorded here is that the
    /// read happened at all: it is the one address where refusing and
    /// answering are indistinguishable in the register, so the trace is what
    /// separates them.
    #[test]
    fn verify_merkle_still_reads_the_last_window_that_fits() {
        let memory = 8192usize;
        let last_fitting = i32::try_from(memory - 520).expect("fits in i32");
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, last_fitting),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(memory);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the program must reach Halt");
        // Reading the window pushes the key into the trace and 64 expansion
        // rows after it. A refused address pushes neither, so this is what
        // tells the two apart.
        assert!(
            vm.trace.iter().any(|row| row.merkle_key.is_some()),
            "the last window that fits must still be read"
        );
    }

    /// The third copy of the same bound, reached through a register.
    ///
    /// `VerifyInference` takes its address from `src1_val` rather than from
    /// the instruction word, so the value is whatever the program last
    /// computed. The opcode is disabled on mainnet and answers zero, but the
    /// block that reads memory runs before that answer is chosen: it is the
    /// trace writer. A profile flag decides what the opcode returns, not what
    /// it reads, which is why this needed the same fix rather than the same
    /// excuse.
    #[test]
    fn verify_inference_refuses_a_register_address_whose_window_wraps() {
        // Put usize::MAX-ish into r2, then use it as the proof address.
        // 8 * 4 = 32 past it wraps to a small number.
        let program = vec![
            // r2 = 0 - 1, computed rather than written, since imm is i32 and
            // the address here comes from the register file.
            inst(Opcode::Sub, 2, 0, 1, 0),
            inst(Opcode::VerifyInference, 3, 2, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(8192);
        vm.registers[0] = 0;
        vm.registers[1] = 1;
        let receipt = vm.run_receipt(&program);
        assert!(
            receipt.success,
            "the program must run to Halt rather than abort the process"
        );
        // Refusing and answering leave the same zero in the register, so the
        // trace is what separates them: the inference block records the three
        // commitments only when the window fits, and a wrapped register
        // address fits nothing. The refusal is the absence of that read.
        assert!(
            vm.trace.iter().all(|row| {
                row.inference_model_commitment.is_none()
                    && row.inference_input_commitment.is_none()
                    && row.inference_output_commitment.is_none()
            }),
            "a refused register address must leave no inference read in the trace"
        );
    }

    // --- Kademe 3a (2026-08-28): commitment-chain binding. ---

    /// A valid chain (output_c == Poseidon(model_c, input_c)) answers rd = 1
    /// for both defined proof types (imm = 0 STARK, imm = 1 SNARK wrap).
    #[test]
    fn verify_inference_accepts_a_valid_commitment_chain() {
        let model_c = 0xABCD_EF01_2345_6789u64;
        let input_c = 0x1122_3344_5566_7788u64;
        let output_c = poseidon4_hash(model_c, input_c);
        for imm in [0i32, 1] {
            let mut vm = Vm::new(256);
            // 24-byte commitment window at address 64: model, input, output.
            vm.memory[64..72].copy_from_slice(&model_c.to_le_bytes());
            vm.memory[72..80].copy_from_slice(&input_c.to_le_bytes());
            vm.memory[80..88].copy_from_slice(&output_c.to_le_bytes());
            vm.registers[1] = 64; // proof address
            let program = vec![
                inst(Opcode::VerifyInference, 3, 1, 0, imm),
                inst(Opcode::Halt, 0, 0, 0, 0),
            ];
            let receipt = vm.run_receipt(&program);
            assert!(receipt.success);
            assert_eq!(vm.registers[3], 1, "valid chain must answer 1 (imm={imm})");
        }
    }

    /// A broken output commitment fails closed: rd = 0 even though the
    /// model/input pair is unchanged. Tampering with any link of the chain
    /// must never verify.
    #[test]
    fn verify_inference_rejects_a_broken_output_commitment() {
        let model_c = 7u64;
        let input_c = 9u64;
        let good = poseidon4_hash(model_c, input_c);
        let bad = good ^ 1; // flip one bit of the claimed output
        let mut vm = Vm::new(256);
        vm.memory[64..72].copy_from_slice(&model_c.to_le_bytes());
        vm.memory[72..80].copy_from_slice(&input_c.to_le_bytes());
        vm.memory[80..88].copy_from_slice(&bad.to_le_bytes());
        vm.registers[1] = 64;
        let program = vec![
            inst(Opcode::VerifyInference, 3, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.registers[3], 0, "broken chain must fail closed");
    }

    #[test]
    fn push_and_pop_round_trip_through_stack() {
        let program = vec![
            inst(Opcode::Push, 0, 1, 0, 0),
            inst(Opcode::Pop, 2, 0, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];

        let mut vm = Vm::new(64);
        vm.registers[1] = 42;
        let receipt = vm.run_receipt(&program);

        assert!(receipt.success);
        assert_eq!(vm.registers[2], 42);
        assert!(vm.stack.is_empty());
    }

    #[test]
    fn call_and_ret_use_return_stack() {
        let program = vec![
            inst(Opcode::Call, 0, 0, 0, 2),
            inst(Opcode::Halt, 0, 0, 0, 0),
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Ret, 0, 0, 0, 0),
        ];

        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);

        assert!(receipt.success);
        assert_eq!(vm.registers[1], 7);
        assert_eq!(vm.pc, 1);
        assert!(vm.stack.is_empty());
    }

    #[test]
    fn d2_privacy_opcodes_execute_real_semantics() {
        // Real Poseidon3 commitment / nullifier ownership /
        // Sum-conservation equality. MainnetActivation still gates mainnet;
        // Testing profile decodes and executes.
        let amount = 100u64;
        let recipient = 7u64;
        let blinding = 99u32 as u64;
        let commitment = poseidon4_hash3(amount, recipient, blinding);
        let secret = 0xA11CEu64;
        let nullifier = poseidon4_hash(secret, DOMAIN_NULLIFIER);

        let program = vec![
            // R1 = PrivacyCommit(r2=amount, r3=recipient, imm=blinding)
            inst(Opcode::PrivacyCommit, 1, 2, 3, blinding as i32),
            // R4 = NullifierCheck(r5=claimed_nullifier, r6=secret)
            inst(Opcode::NullifierCheck, 4, 5, 6, 0),
            // R7 = SumConservation(r8=sum_in, r9=sum_out) - equal
            inst(Opcode::SumConservation, 7, 8, 9, 0),
            // R10 = SumConservation unequal
            inst(Opcode::SumConservation, 10, 8, 2, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        vm.registers[2] = amount;
        vm.registers[3] = recipient;
        vm.registers[5] = nullifier;
        vm.registers[6] = secret;
        vm.registers[8] = 50;
        vm.registers[9] = 50;
        let receipt = vm.run_receipt(&program);
        assert!(
            receipt.success,
            "D2 privacy opcodes must execute: {:?}",
            receipt.error
        );
        assert_eq!(
            vm.registers[1], commitment,
            "PrivacyCommit Poseidon3 binding"
        );
        assert_eq!(vm.registers[4], 1, "NullifierCheck accepts matching secret");
        assert_eq!(vm.registers[7], 1, "SumConservation accepts equal sums");
        assert_eq!(vm.registers[10], 0, "SumConservation rejects unequal sums");
    }

    #[test]
    fn d2_nullifier_check_rejects_wrong_secret() {
        let secret = 0xBEEFu64;
        let nullifier = poseidon4_hash(secret, DOMAIN_NULLIFIER);
        let program = vec![
            inst(Opcode::NullifierCheck, 1, 2, 3, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        vm.registers[2] = nullifier;
        vm.registers[3] = secret ^ 1; // wrong secret
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.registers[1], 0);
    }

    #[test]
    fn d2_privacy_gas_matches_poseidon() {
        assert_eq!(Vm::gas_cost(Opcode::PrivacyCommit), 10);
        assert_eq!(Vm::gas_cost(Opcode::NullifierCheck), 10);
        assert_eq!(Vm::gas_cost(Opcode::SumConservation), 10);
    }

    #[test]
    fn gas_limit_stops_unbounded_execution() {
        let program = vec![inst(Opcode::Jmp, 0, 0, 0, 0)];
        let mut vm = Vm::with_gas_limit(64, 3);

        let receipt = vm.run_receipt(&program);
        assert!(!receipt.success);
        assert_eq!(receipt.error, Some(VmError::OutOfGas));
    }

    #[test]
    fn gas_accounting_matches_instruction_costs() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, 9),
            inst(Opcode::Push, 0, 1, 0, 0),
            inst(Opcode::Syscall, 2, 0, 0, 1),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];

        let mut vm = Vm::new(64);
        vm.context.sender = 77;
        let receipt = vm.run_receipt(&program);

        assert!(receipt.success);
        assert_eq!(vm.gas_used, 10);
        assert_eq!(vm.registers[1], 9);
        assert_eq!(vm.registers[2], 77);
        assert_eq!(vm.trace.len(), 4);
    }

    #[test]
    fn test_syscall_imm_6_emits_ai_request_event() {
        let program = vec![
            // Load r1 with the immediate 42 (src1_idx == 0 makes Load an
            // Immediate-load); Push has stack semantics, not imm-load.
            inst(Opcode::Load, 1, 0, 0, 42),
            inst(Opcode::Syscall, 2, 1, 0, 6),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];

        let mut vm = Vm::new(64);
        vm.context.block_height = 100;
        let receipt = vm.run_receipt(&program);

        assert!(receipt.success);
        assert_eq!(vm.events, vec![0x00A1_00A1, 42]);
        assert_eq!(vm.registers[2], 142);
    }

    #[test]
    fn step_after_halt_is_idempotent() {
        let program = vec![
            inst(Opcode::Halt, 0, 0, 0, 0),
            inst(Opcode::Load, 1, 0, 0, 99),
        ];

        let mut vm = Vm::new(64);
        let _ = vm.step(&program);

        assert!(vm.halted);
        assert_eq!(vm.pc, 0);
        assert_eq!(vm.trace.len(), 1);

        let _ = vm.step(&program);

        assert!(vm.halted);
        assert_eq!(vm.pc, 0);
        assert_eq!(vm.trace.len(), 1);
        assert_eq!(vm.registers[1], 0);
    }

    #[test]
    fn test_memory_oob_safety() {
        let program_load_oob = vec![inst(Opcode::Load, 1, 1, 0, 100)];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program_load_oob);
        assert!(!receipt.success);
        assert_eq!(receipt.error, Some(VmError::InvalidMemoryAccess));

        let program_store_oob = vec![inst(Opcode::Store, 0, 1, 2, 100)];
        let mut vm2 = Vm::new(64);
        let receipt2 = vm2.run_receipt(&program_store_oob);
        assert!(!receipt2.success);
        assert_eq!(receipt2.error, Some(VmError::InvalidMemoryAccess));
    }

    /// Arithmetic is Goldilocks-field (mod P), not wrapping-u64, so the VM
    /// Matches the STARK AIR's field constraints. `(P-1) + 1 == 0` in the
    /// Field, whereas wrapping-u64 would give `P`. (Soundness: the VM and
    /// The AIR must compute the same operation.)
    #[test]
    fn add_is_goldilocks_field_not_wrapping() {
        let program = vec![
            inst(Opcode::Add, 3, 1, 2, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        vm.registers[1] = GOLDILOCKS_P - 1;
        vm.registers[2] = 1;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.registers[3], 0, "field add must reduce at P, not 2^64");
    }

    /// Field subtraction: `0 - 1 == P - 1` (mod P), not `u64::MAX`.
    #[test]
    fn sub_is_goldilocks_field_not_wrapping() {
        let program = vec![
            inst(Opcode::Sub, 3, 1, 2, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        vm.registers[1] = 0;
        vm.registers[2] = 1;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(
            vm.registers[3],
            GOLDILOCKS_P - 1,
            "field sub: 0 - 1 == P - 1"
        );
    }

    /// Field multiplication near the prime: `(P-1) * 2 == P - 2` (mod P),
    /// I.e. `(-1) * 2 == -2`, not the wrapping-u64 product.
    #[test]
    fn mul_is_goldilocks_field_not_wrapping() {
        let program = vec![
            inst(Opcode::Mul, 3, 1, 2, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        vm.registers[1] = GOLDILOCKS_P - 1; // == -1 mod P
        vm.registers[2] = 2;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(
            vm.registers[3],
            GOLDILOCKS_P - 2,
            "field mul: -1 * 2 == P - 2"
        );
    }

    /// (security audit) `VerifyMerkle` must produce
    /// 1 original step + 64 expansion rows (one per Poseidon round),
    /// So the AIR can verify the path row-by-row. The original
    /// Step carries `merkle_key`; each expansion row carries
    /// `merkle_current`, `merkle_sibling`, and `merkle_round`.
    #[test]
    fn verify_merkle_emits_64_expansion_rows() {
        // Build a simple program that runs VerifyMerkle and then Halt.
        // Memory layout for the path: [key (8 bytes), 64×sibling (8 each)]
        // → 520 bytes. We populate the first 64×8 bytes with a
        // Deterministic pattern; the key is `key = 0` so every
        // Round uses bit = 0 (i.e. current = poseidon(current, sibling)).
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256), // path_addr = 256
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(1024);
        // Put a non-zero key and deterministic siblings.
        vm.memory[256..264].copy_from_slice(&7u64.to_le_bytes());
        for i in 0..64 {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&(1000u64 + i as u64).to_le_bytes());
        }
        // Leaf and root registers don't matter for the trace-length
        // Assertion.
        vm.registers[2] = 0xDEAD;
        vm.registers[3] = 0xBEEF;

        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        // 1 VerifyMerkle + 64 expansion rows + 1 Halt = 66
        assert_eq!(
            vm.trace.len(),
            66,
            "expected 1 VerifyMerkle + 64 expansion + 1 Halt = 66, got {}",
            vm.trace.len()
        );
        // The original step must carry merkle_key = Some(7).
        let first = &vm.trace[0];
        assert_eq!(first.instruction.opcode, Opcode::VerifyMerkle);
        assert_eq!(first.merkle_key, Some(7));
        assert!(!first.merkle_is_expand);
        // Each expansion row must carry merkle_round = Some(i).
        for i in 0..64 {
            let row = &vm.trace[1 + i];
            assert!(
                row.merkle_is_expand,
                "row {i} should be marked as expansion"
            );
            assert_eq!(row.merkle_key, Some(7));
            assert_eq!(row.merkle_round, Some(i as u8));
            assert!(row.merkle_current.is_some());
            assert!(row.merkle_sibling.is_some());
        }
        // The final Halt must NOT be an expansion row.
        let last = &vm.trace[65];
        assert_eq!(last.instruction.opcode, Opcode::Halt);
        assert!(!last.merkle_is_expand);
    }

    /// (security audit) when the program terminates on an
    /// Error, the trace must still end on a Halt row so that the AIR
    /// Termination constraint is satisfied. `Vm::step` is allowed
    /// To return Err *without* pushing the failing step; the synthetic
    /// Terminal Halt step is appended by `run_receipt` instead.
    #[test]
    fn error_termination_appends_synthetic_halt_step() {
        // Jump past the end of the program: pc=0, Jmp 1 → pc=1, which
        // Is out of bounds for a 1-instruction program → InvalidPc.
        let program = vec![inst(Opcode::Jmp, 0, 0, 0, 1)];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);

        assert!(!receipt.success);
        assert_eq!(receipt.error, Some(VmError::InvalidPc));

        // The trace must contain the Jmp step + a synthetic terminal
        // Halt step (the failing InvalidPc step is intentionally not
        // Pushed by `Vm::step`).
        assert_eq!(vm.trace.len(), 2);
        assert_eq!(vm.trace[0].instruction.opcode, Opcode::Jmp);
        assert_eq!(vm.trace[1].instruction.opcode, Opcode::Halt);
        assert_eq!(vm.trace[1].pc, 1);
        assert_eq!(vm.trace[1].next_pc, 1);
        assert_eq!(vm.trace[1].dst_val, 0);
        assert!(vm.halted);
    }

    /// SRead/SWrite cost more gas than Load/Store.
    #[test]
    fn storage_gas_above_memory() {
        assert_eq!(Vm::gas_cost(Opcode::Load), 3);
        assert_eq!(Vm::gas_cost(Opcode::Store), 3);
        assert_eq!(Vm::gas_cost(Opcode::SRead), 8);
        assert_eq!(Vm::gas_cost(Opcode::SWrite), 12);
        assert!(Vm::gas_cost(Opcode::SRead) > Vm::gas_cost(Opcode::Load));
        assert!(Vm::gas_cost(Opcode::SWrite) > Vm::gas_cost(Opcode::Store));
        assert!(Vm::gas_cost(Opcode::SWrite) > Vm::gas_cost(Opcode::SRead));
        // Gas calibration: an opcode whose proof expands to many trace rows
        // must not sit at the cheap arithmetic default. `Div` is a 64-row
        // binary long division, so it is priced with the heavy ops.
        assert!(
            Vm::gas_cost(Opcode::Div) > 1,
            "long-division must not be cheap"
        );
        assert_eq!(Vm::gas_cost(Opcode::Div), 10);
    }

    /// Lock Poseidon MDS and RC constants.
    /// If someone changes these in bud-vm, this test fails.
    /// Wallet-core has its own lock test - both must match.
    #[test]
    fn poseidon_mds_rc_lock() {
        // MDS circulant matrix first row must be [7,1,3,8,8,3,4,9]
        assert_eq!(
            POSEIDON_MDS[0],
            [7, 1, 3, 8, 8, 3, 4, 9],
            "MDS row 0 mismatch"
        );
        assert_eq!(
            POSEIDON_MDS[7],
            [1, 3, 8, 8, 3, 4, 9, 7],
            "MDS row 7 mismatch"
        );
        // RC round 0 first two elements must match Plonky3 Poseidon1 Goldilocks
        assert_eq!(POSEIDON_RC[0][0], 0xdd5743e7f2a5a5d9, "RC[0][0] mismatch");
        assert_eq!(POSEIDON_RC[0][1], 0xcb3a864e58ada44b, "RC[0][1] mismatch");
    }

    /// The whole table is bound to a single constant.
    ///
    /// The lock above pinned **two** of the 240 round constants. The remaining 238
    /// could be changed silently: changing a constant changes what the permutation
    /// degistirir, permutasyonu degistirmek taahhutlerin ne sakladigini ve neye
    /// binds - and no test would see it.
    ///
    /// A spot check is exactly the kind of check that misses this class: a lock that
    /// always passes (because it leaves everything outside the sample free) is worse
    /// than no lock, because it reads as though a lock exists.
    ///
    /// The fingerprint is computed with FNV-1a 64. It is not a cryptographic digest and
    /// does not need to be: what is defended here is not secrecy but
    /// **sensitivity to change**. If a single bit of a constant changes the value shifts.
    /// Adding a hash library would mean a new dependency living in the same tree as the
    /// table it locks.
    ///
    /// When the value changes the thing to do is not to update it but to ask **what
    /// degistigini bulmaktir**.
    #[test]
    fn the_whole_constant_table_is_locked() {
        const fn fnv1a64(vals: &[[u64; 8]]) -> u64 {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            let mut r = 0;
            while r < vals.len() {
                let mut c = 0;
                while c < 8 {
                    let bytes = vals[r][c].to_le_bytes();
                    let mut b = 0;
                    while b < 8 {
                        h ^= bytes[b] as u64;
                        h = h.wrapping_mul(0x100_0000_01b3);
                        b += 1;
                    }
                    c += 1;
                }
                r += 1;
            }
            h
        }

        assert_eq!(
            fnv1a64(&POSEIDON_RC_FULL),
            0x5abc_6908_02c0_0f4a,
            "the 30-round constant table changed; 238 of these 240 values were \
             previously unchecked. Find what moved before touching this number"
        );
        assert_eq!(
            fnv1a64(&POSEIDON_MDS),
            0x7fb2_9bd1_52c1_ff25,
            "the MDS matrix changed; row 0 and row 7 alone did not cover it"
        );
        // Two edges holding the ends: together with the fingerprint they hold both the
        // length and the bound of the table.
        assert_eq!(POSEIDON_RC_FULL[0][0], 0xdd57_43e7_f2a5_a5d9);
        assert_eq!(POSEIDON_RC_FULL[29][7], 0x323d_9533_2b14_5fd6);
    }
}

#[cfg(test)]
mod poseidon_parameter_tests {
    use super::*;

    /// The claim in `POSEIDON_RC` is that it is a *truncation* of a safe set,
    /// not an ad-hoc design. That is only checkable if the safe set is here,
    /// so check it.
    #[test]
    fn four_round_set_is_a_prefix_of_full() {
        assert_eq!(
            POSEIDON_RC.len(),
            4,
            "the historical prefix stays four rounds"
        );
        for (r, row) in POSEIDON_RC.iter().enumerate() {
            assert_eq!(
                row, &POSEIDON_RC_FULL[r],
                "round {r} of the in-use constants diverges from the Plonky3 \
                 Goldilocks width-8 set; the truncation claim in the docs is \
                 no longer true"
            );
        }
    }

    /// The round schedule must add up to the constants that are stored.
    #[test]
    fn round_schedule_matches_the_constant_table() {
        assert_eq!(
            POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS,
            POSEIDON_RC_FULL.len(),
            "8 full + 22 partial must be exactly the 30 stored round constants"
        );
        assert_eq!(
            POSEIDON_FULL_ROUNDS % 2,
            0,
            "R_F must be even (split in half)"
        );
    }

    /// The partial-round count is derived, not chosen. Recompute the bound.
    #[test]
    fn partial_round_count_matches_the_interpolation_bound() {
        // R_interp >= ceil(64 / log2(7)) + ceil(log_7(8)) - 5
        let alpha = POSEIDON_ALPHA as f64;
        let interp = (64.0 / alpha.log2()).ceil() + (8f64.ln() / alpha.ln()).ceil() - 5.0;
        assert_eq!(interp as usize, 20, "interpolation bound should be 20");
        // +7.5% security margin, rounded up.
        let with_margin = (interp * 1.075).ceil() as usize;
        assert_eq!(
            with_margin, POSEIDON_PARTIAL_ROUNDS,
            "POSEIDON_PARTIAL_ROUNDS must equal the derived bound plus margin"
        );
    }

    /// The S-box must actually be a permutation of the field.
    #[test]
    fn sbox_exponent_is_coprime_with_field_order() {
        fn gcd(a: u64, b: u64) -> u64 {
            if b == 0 {
                a
            } else {
                gcd(b, a % b)
            }
        }
        assert_eq!(
            gcd(POSEIDON_ALPHA, GOLDILOCKS_P - 1),
            1,
            "x^alpha is only a bijection when gcd(alpha, P-1) = 1"
        );
    }

    /// The VM's hash *is* the full permutation now.
    ///
    /// Pins that the 30-round reference and
    /// the 4-round permutation the VM ran were different functions, so the
    /// derived parameters could not quietly become decoration. They are the
    /// same function today because the VM was moved onto them, and the AIR
    /// moved with it.
    ///
    /// What it guards now is the reverse: if `poseidon4_hash_state` is ever
    /// pointed back at a truncated schedule, this fails.
    #[test]
    fn vm_hash_is_the_full_permutation() {
        for a in [0u64, 1, 2, 12345, GOLDILOCKS_P - 1] {
            for b in [0u64, 7, 999, GOLDILOCKS_P - 2] {
                let state = [a, b, 0, 0, 0, 0, 0, 0];
                assert_eq!(
                    poseidon4_hash_state(state),
                    poseidon_full_hash_state(state),
                    "the VM must compute the 30-round permutation the AIR \
                     constrains; a mismatch means proofs attest to a different \
                     function than the VM ran"
                );
            }
        }
    }

    /// The truncated schedule is still a different function, which is what
    /// made moving off it worth doing.
    #[test]
    fn truncated_schedule_differs_from_the_full_one() {
        const P: u64 = GOLDILOCKS_P;
        // Reproduce the old four-round behaviour locally rather than keeping a
        // second implementation in the crate.
        let truncated = |mut s: [u64; 8]| -> u64 {
            let sbox = |x: u64| -> u64 {
                let x2 = ((x as u128 * x as u128) % P as u128) as u64;
                let x4 = ((x2 as u128 * x2 as u128) % P as u128) as u64;
                (((x4 as u128 * x2 as u128) % P as u128 * x as u128) % P as u128) as u64
            };
            for rc in POSEIDON_RC.iter() {
                for i in 0..8 {
                    s[i] = ((s[i] as u128 + rc[i] as u128) % P as u128) as u64;
                }
                let sb: Vec<u64> = s.iter().map(|x| sbox(*x)).collect();
                let mut next = [0u64; 8];
                for i in 0..8 {
                    let mut sum: u128 = 0;
                    for j in 0..8 {
                        sum = (sum + POSEIDON_MDS[i][j] as u128 * sb[j] as u128) % P as u128;
                    }
                    next[i] = sum as u64;
                }
                s = next;
            }
            s[0]
        };

        let mut differing = 0;
        for a in [0u64, 1, 2, 12345, GOLDILOCKS_P - 1] {
            for b in [0u64, 7, 999, GOLDILOCKS_P - 2] {
                let state = [a, b, 0, 0, 0, 0, 0, 0];
                if truncated(state) != poseidon_full_hash_state(state) {
                    differing += 1;
                }
            }
        }
        assert_eq!(
            differing, 20,
            "every sampled input must separate the two schedules; if they \
             agreed, lengthening the permutation would have changed nothing"
        );
    }

    /// The full permutation must be deterministic and stay canonical.
    #[test]
    fn full_permutation_is_deterministic_and_canonical() {
        let state = [1u64, 2, 3, 4, 5, 6, 7, 8];
        let a = poseidon_full_hash_state(state);
        let b = poseidon_full_hash_state(state);
        assert_eq!(a, b);
        assert!(a < GOLDILOCKS_P);
        // A one-bit change must not leave the output unchanged.
        let mut other = state;
        other[7] ^= 1;
        assert_ne!(a, poseidon_full_hash_state(other));
    }

    /// The VM must keep computing what the AIR constrains. Four rounds is the
    /// number the AIR enforces, so the VM's hash must stay at four until the
    /// AIR is rebuilt - swapping only one side is a soundness break.
    #[test]
    fn vm_hash_still_matches_the_air_round_count() {
        assert_eq!(
            POSEIDON_ROUNDS_IN_USE,
            POSEIDON_RC_FULL.len(),
            "the in-use round count and the in-use constants must agree"
        );
        assert_eq!(
            POSEIDON_ROUNDS_IN_USE,
            POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS,
            "the VM and the AIR both run the full 30-round schedule now; if \
             one is cut back the other must be cut back in the same change, \
             or the proof attests to a different function than the VM ran"
        );
    }

    /// Degree is the reason the truncated version is unsound; keep the number
    /// in the tree rather than only in prose.
    #[test]
    fn truncated_permutation_degree_is_far_below_the_field() {
        // The truncated permutation's degree is what made it unsound; keep
        // the number in the tree next to the schedule that replaced it.
        let truncated = POSEIDON_ALPHA.pow(4);
        assert_eq!(truncated, 2401);
        assert!(
            truncated < 1u64 << 32,
            "2401 is far below the field size - interpolable in practice, \
             which is why four rounds was not enough"
        );
        // Eight full rounds alone already exceed it by orders of magnitude,
        // and the 22 partial rounds continue to raise it one lane at a time.
        let full_only = POSEIDON_ALPHA.pow(POSEIDON_FULL_ROUNDS as u32);
        assert!(
            full_only > truncated * 1000,
            "the full-round half alone must dwarf the truncated degree"
        );
    }
}
