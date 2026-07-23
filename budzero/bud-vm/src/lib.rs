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

// S5 fix (pre-mortem audit): VerifyMerkle/VerifyInference gate is now
// hard-coded to FULL activation on mainnet. Removed env var
// BUDLUM_VERIFY_MERKLE which was a configuration attack vector —
// a node operator could set it to "false" and disable Merkle
// verification, breaking state root trust.
// Staged rollout should use governance/genesis config, not env vars.
fn decode_instruction(raw: u64, mainnet_mode: bool) -> Result<bud_isa::Instruction, String> {
    if mainnet_mode {
        // Always full activation — no env var override
        let activation = bud_isa::MainnetActivation::full();
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
    /// `MainnetActivation::full()`. Set by `ZkVmExecutor::execute_bytecode`
    /// when network is Mainnet.
    pub mainnet_mode: bool,
}

pub struct Context {
    pub sender: u64,
    pub nonce: u64,
    pub block_height: u64,
    /// Task 0.31 (security audit Z-A): initial state root.
    /// The VM does not consume this directly (state roots are produced
    /// externally), but the prover trace records it on the first row
    /// so the AIR can bind `public_inputs.initial_state_root`.
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
    /// Task 0.312 (security audit Z-B): Merkle path expansion rows. The
    /// original step that triggers a `VerifyMerkle` has these set to
    /// `None` and `merkle_is_expand = false`; the 64 follow-up
    /// "expansion" rows (one per Poseidon round) carry the key, the
    /// current Poseidon accumulator, the sibling hash for that round,
    /// and the round index. The AIR uses these to verify the path
    /// against the claimed root (`rs1_val`).
    pub merkle_key: Option<u64>,
    pub merkle_current: Option<u64>,
    pub merkle_sibling: Option<u64>,
    pub merkle_round: Option<u8>,
    pub merkle_is_expand: bool,
    /// P5 ADIM11 Bulgu 32: AI inference verification expansion rows.
    /// The original VerifyInference step carries these as None/0;
    /// follow-up expansion rows carry the commitment values being
    /// verified by the AIR trace. The AIR checks that:
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
/// constrains, otherwise a generated STARK proof attests to a different
/// computation than the VM actually executed (a soundness break). The
/// AIR's Add/Sub/Mul constraints are field operations mod `P`, so the VM
/// uses these field helpers instead of wrapping-`u64` arithmetic. The
/// result is always canonical (`< P`).
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
    /// behind `MainnetActivation::full()`.
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
        // Task 0.30 (security audit Z-D): semantics of error returns.
        //
        // On any error path, `Vm::step` does NOT push a Step to
        // `self.trace` for the failing instruction. The matching terminal
        // Halt step is appended by `run_receipt` after the error is
        // observed, so the trace still ends with a Halt row and the AIR
        // Z-C termination constraint is satisfied. The set of fields that
        // `step` is allowed to mutate on error is: `halted` (set to true)
        // and `error` (set to Some(...)). Do not push partial steps.
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
                // Goldilocks field add — must match the AIR's
                // `rd = rs1 + rs2` field constraint (see GOLDILOCKS_P).
                let result = field_add_goldilocks(src1_val, src2_val);
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Sub => {
                // Goldilocks field sub — matches the AIR field constraint.
                let result = field_sub_goldilocks(src1_val, src2_val);
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Mul => {
                // Goldilocks field mul — matches the AIR field constraint.
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
            Opcode::Or => {
                let result = src1_val | src2_val;
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            Opcode::Xor => {
                let result = src1_val ^ src2_val;
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
                // Task 0.312 (security audit Z-B): the original step
                // records `merkle_key` and `dst_val = 0` (the result is
                // not known yet — it will be set by the final expansion
                // round). 64 follow-up "expansion" rows are pushed
                // immediately, one per Poseidon round, so the AIR can
                // verify the path row-by-row.
                let path_end = path_addr.wrapping_add(8 * 65);
                let result = if path_end <= self.memory.len() {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&self.memory[path_addr..path_addr + 8]);
                    let key = u64::from_le_bytes(bytes);
                    // We keep the path's result computation for
                    // backward compatibility (so the dst register
                    // still gets the correct answer), but the
                    // *sound* verification lives in the expansion
                    // rows the AIR checks. dst_val is set to the
                    // correct result here so the trace is faithful
                    // to the VM semantics; the AIR will additionally
                    // constrain it via the expansion path.
                    // Task 0.36 / Z-B 3.5: path hash must match AIR single-round.
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
                // local `Vec<(u64, u64, u8)>`-style scratch on `self`
                // by reusing a private field — but to keep the
                // signature simple we just walk the path twice
                // (once for `result`, once for the expansion rows
                // below). For depth 64 this is 2*64=128 hashes per
                // VerifyMerkle, which is acceptable for an audit
                // milestone and is in any case dwarfed by the
                // 64*8 single-round hash cost of the AIR.
                self.pc += 1;
                (result, cur_pc + 1)
            }
            // P5 ADIM11 Bulgu 32: AI Inference verification opcode.
            // V110 fix: VerifyInference opcode disabled on mainnet.
            // Previously, any non-zero commitment was accepted (no real verification).
            // This opcode is now a no-op that always returns 0 (verification failed)
            // until a proper STARK verification AIR is implemented.
            // Mainnet activation gate: this ensures no AI output can be "verified"
            // without real cryptographic proof.
            Opcode::VerifyInference => {
                // V110: Always return 0 (verification failed) until proper
                // STARK verification AIR is implemented. Operands intentionally
                // unread — keep decode/execute shape for future activation.
                let _proof_addr = src1_val as usize;
                let _model_addr = src2_val as usize;
                let _proof_type = inst.imm; // 0=STARK, 1=SNARK wrap
                let result = 0u64;
                let dst_idx = inst.rd;
                if dst_idx as usize > 0 {
                    self.registers[dst_idx as usize] = result;
                }
                self.pc += 1;
                (result, cur_pc + 1)
            }
            // D2 (2026-07-22) Görev D: privacy-layer opcodes — real semantics.
            //
            // PrivacyCommit (0x20):
            //   commitment = Poseidon3(amount=rs1, recipient=rs2, blinding=imm)
            //   Zincire yalnızca commitment yazılır (note registry).
            //
            // NullifierCheck (0x21):
            //   claimed_nullifier = rs1, secret = rs2
            //   rd = 1 iff Poseidon2(secret, DOMAIN_NULLIFIER) == claimed_nullifier
            //   (Spent-set membership NoteRegistry tarafında; VM sahiplik bağını kanıtlar.)
            //
            // SumConservation (0x22):
            //   Poseidon commitment homomorfik değil → value conservation private
            //   witness üzerinden: rd = 1 iff rs1 (Σ in amounts) == rs2 (Σ out amounts).
            //   Amount'lar PrivacyCommit ile commitment'a bağlanır (ayrı satırlar).
            // S1 fix (pre-mortem audit): blinding from register (full u64),
            // recipient tag from imm (i32 fits). Eliminates u32 truncation
            // that caused wallet-core/VM commitment mismatch and reduced
            // blinding entropy to 32 bits (brute-forceable).
            Opcode::PrivacyCommit => {
                let amount = src1_val;
                let blinding = src2_val; // full u64 from register
                let recipient = inst.imm as i64 as u64; // recipient tag from imm
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
            // S2 fix (pre-mortem audit): SumConservation uses field-safe
            // comparison. Values >= Goldilocks prime P = 0xFFFFFFFF00000001
            // would cause u64 vs field comparison mismatch. Reject such
            // values (amounts should always be < P in practice).
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

        // Task 0.312 (security audit Z-B): if the just-pushed step is a
        // VerifyMerkle, immediately push 64 follow-up "expansion"
        // rows. Each row carries the current Poseidon accumulator,
        // the sibling hash for that round, the round index, and the
        // key (the AIR uses these to verify the path). The original
        // step's `merkle_key` is also set here (post-push, in-place
        // via index) so the AIR knows the path's key.
        if matches!(inst.opcode, Opcode::VerifyMerkle | Opcode::VerifyInference) {
            let path_addr = inst.imm as usize;
            let path_end = path_addr.wrapping_add(8 * 65);
            if path_end <= self.memory.len() {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&self.memory[path_addr..path_addr + 8]);
                let key = u64::from_le_bytes(bytes);
                // Patch the just-pushed step to carry the key.
                if let Some(last) = self.trace.last_mut() {
                    last.merkle_key = Some(key);
                }
                // Walk the path and push 64 expansion rows. The
                // `current` accumulator is computed here (in the VM)
                // for the trace's faithfulness, and the AIR
                // re-derives it independently in Commit 2.
                // Task 0.36 / Z-B 3.5: expansion rows carry the *pre-round*
                // accumulator so AIR can check nxt = poseidon(cur, sibling).
                // ARENA2 Task 4: expansion rows share the original PC and must
                // keep next_pc == pc until the final expansion, which hands
                // off to the real next instruction (pc+1). The AIR enforces
                // `nxt_pc == next_pc` on every cpu row; setting next_pc=pc+1
                // on intermediate expansions makes nxt_pc (still pc) fail.
                // Also patch the original step's next_pc to stay on this pc
                // so original → first expansion satisfies the same rule.
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
                            imm: 0,
                        },
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
                // Task 0.312 Commit 3: patch the original step's
                // merkle_current to the 64th-round Poseidon
                // output. This bridges the 64 expansion rows to
                // the original step, allowing the AIR to apply
                // the final root check on the original step's
                // row (is_verify_merkle = 1, merkle_final_flag = 1).
                let orig_idx = self.trace.len() - 1 - 64;
                if orig_idx < self.trace.len() {
                    self.trace[orig_idx].merkle_current = Some(current);
                }
            }
        }

        // P5 ADIM11 Bulgu 32: VerifyInference expansion rows.
        // If the just-pushed step is a VerifyInference, push 8 follow-up
        // expansion rows. Each row carries the commitment values for the
        // AIR to verify the commitment chain (model → input → output).
        // ARENA2 (2026-07-23): Fix next_pc pattern to match VerifyMerkle:
        // original step stays on cur_pc, expansion rows 0-6 stay on cur_pc,
        // expansion row 7 advances to cur_pc+1.
        if matches!(inst.opcode, Opcode::VerifyInference) {
            let proof_addr = src1_val as usize;
            let proof_end = proof_addr.wrapping_add(8 * 4);
            if proof_end <= self.memory.len() {
                let read_u64 = |addr: usize| -> u64 {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&self.memory[addr..addr + 8]);
                    u64::from_le_bytes(bytes)
                };
                let model_c = read_u64(proof_addr);
                let input_c = read_u64(proof_addr + 8);
                let output_c = read_u64(proof_addr + 16);

                // Patch original step with commitments and next_pc = cur_pc
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

        // Task 0.30 (security audit Z-D): when the program terminates with an
        // error (OutOfGas, StackUnderflow, InvalidMemoryAccess, ...),
        // `Vm::step` returns before pushing the failing step to `self.trace`.
        // We still need a terminal row in the trace so that the AIR's
        // `cpu_active` transition lands on a Halt row, matching the Z-C
        // termination constraint. Synthesize a synthetic Halt step here.
        // The synthetic step is byte-identical to a real Halt (pc = current
        // pc, dst_val = 0, all other fields zeroed / derived from the VM
        // state) and is *only* appended when the program ended on an error
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

        let mut sorted_writes = self.state_writes.clone();
        sorted_writes.sort_by_key(|w| w.0);
        let mut bytes = Vec::new();
        for (slot, val) in sorted_writes {
            bytes.extend_from_slice(&slot.to_le_bytes());
            bytes.extend_from_slice(&val.to_le_bytes());
        }
        let mut state_writes_digest = [0u8; 32];
        if !bytes.is_empty() {
            use tiny_keccak::{Hasher, Keccak};
            let mut hasher = Keccak::v256();
            hasher.update(&bytes);
            hasher.finalize(&mut state_writes_digest);
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
            // Task 0.338 / A12: storage ops are more expensive than plain memory
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
            _ => 1,
        }
    }
}

/// Single-round Poseidon used by `VerifyMerkle` path hashing (Task 0.36 / Z-B 3.5).
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
/// Domain separator for nullifier derivation (D2).
/// ASCII-ish constant "NULLIFER" as a field element — domain-separates
/// nullifier hashes from plain Poseidon(a,b) and PrivacyCommit.
pub const DOMAIN_NULLIFIER: u64 = 0x4e55_4c4c_4946_4552; // "NULLIFER"

/// MDS circulant matrix — must match BudAir / plonky3_prover.
/// H5 fix: module-level const so lock test can access.
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
/// H5 fix: module-level const so lock test can access.
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
pub fn poseidon4_hash_state(mut s: [u64; 8]) -> u64 {
    const P: u64 = 18446744069414584321;

    for round_rc in POSEIDON_RC.iter() {
        for i in 0..8 {
            s[i] = ((s[i] as u128 + round_rc[i] as u128) % P as u128) as u64;
        }
        let mut sbox: [u64; 8] = [0; 8];
        for i in 0..8 {
            let x = s[i];
            let x2 = ((x as u128 * x as u128) % P as u128) as u64;
            let x4 = ((x2 as u128 * x2 as u128) % P as u128) as u64;
            sbox[i] = (((x4 as u128 * x2 as u128) % P as u128 * x as u128) % P as u128) as u64;
        }
        let mut next: [u64; 8] = [0; 8];
        for i in 0..8 {
            let mut sum: u128 = 0;
            for j in 0..8 {
                sum = (sum + POSEIDON_MDS[i][j] as u128 * sbox[j] as u128) % P as u128;
            }
            next[i] = sum as u64;
        }
        s = next;
    }
    s[0]
}

/// 4-round Poseidon over Goldilocks with 3 absorbed field elements
/// (state = [a, b, c, 0, 0, 0, 0, 0]). Used by `PrivacyCommit`.
pub fn poseidon4_hash3(a: u64, b: u64, c: u64) -> u64 {
    poseidon4_hash_state([a, b, c, 0, 0, 0, 0, 0])
}

/// 4-round Poseidon hash over Goldilocks field (alpha=7, width=8, full rounds only).
///
/// Rate-2 absorption: state = [a, b, 0, 0, 0, 0, 0, 0]. Used by the Poseidon
/// opcode and NullifierCheck (with DOMAIN_NULLIFIER as second input).
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
        // D2 Görev D: real Poseidon3 commitment / nullifier ownership /
        // sum-conservation equality. MainnetActivation still gates mainnet;
        // Testing profile decodes and executes.
        let amount = 100u64;
        let recipient = 7u64;
        let blinding = 99u32 as u64;
        let commitment = poseidon4_hash3(amount, recipient, blinding);
        let secret = 0xA11CEu64;
        let nullifier = poseidon4_hash(secret, DOMAIN_NULLIFIER);

        let program = vec![
            // r1 = PrivacyCommit(r2=amount, r3=recipient, imm=blinding)
            inst(Opcode::PrivacyCommit, 1, 2, 3, blinding as i32),
            // r4 = NullifierCheck(r5=claimed_nullifier, r6=secret)
            inst(Opcode::NullifierCheck, 4, 5, 6, 0),
            // r7 = SumConservation(r8=sum_in, r9=sum_out) — equal
            inst(Opcode::SumConservation, 7, 8, 9, 0),
            // r10 = SumConservation unequal
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
            // immediate-load); Push has stack semantics, not imm-load.
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
    /// matches the STARK AIR's field constraints. `(P-1) + 1 == 0` in the
    /// field, whereas wrapping-u64 would give `P`. (Soundness: the VM and
    /// the AIR must compute the same operation.)
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
    /// i.e. `(-1) * 2 == -2`, not the wrapping-u64 product.
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

    /// Task 0.312 (security audit Z-B): `VerifyMerkle` must produce
    /// 1 original step + 64 expansion rows (one per Poseidon round),
    /// so the AIR can verify the path row-by-row. The original
    /// step carries `merkle_key`; each expansion row carries
    /// `merkle_current`, `merkle_sibling`, and `merkle_round`.
    #[test]
    fn verify_merkle_emits_64_expansion_rows() {
        // Build a simple program that runs VerifyMerkle and then Halt.
        // Memory layout for the path: [key (8 bytes), 64×sibling (8 each)]
        // → 520 bytes. We populate the first 64×8 bytes with a
        // deterministic pattern; the key is `key = 0` so every
        // round uses bit = 0 (i.e. current = poseidon(current, sibling)).
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
        // leaf and root registers don't matter for the trace-length
        // assertion.
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

    /// Task 0.30 (security audit Z-D): when the program terminates on an
    /// error, the trace must still end on a Halt row so that the AIR
    /// Z-C termination constraint is satisfied. `Vm::step` is allowed
    /// to return Err *without* pushing the failing step; the synthetic
    /// terminal Halt step is appended by `run_receipt` instead.
    #[test]
    fn error_termination_appends_synthetic_halt_step() {
        // Jump past the end of the program: pc=0, Jmp 1 → pc=1, which
        // is out of bounds for a 1-instruction program → InvalidPc.
        let program = vec![inst(Opcode::Jmp, 0, 0, 0, 1)];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&program);

        assert!(!receipt.success);
        assert_eq!(receipt.error, Some(VmError::InvalidPc));

        // The trace must contain the Jmp step + a synthetic terminal
        // Halt step (the failing InvalidPc step is intentionally not
        // pushed by `Vm::step`).
        assert_eq!(vm.trace.len(), 2);
        assert_eq!(vm.trace[0].instruction.opcode, Opcode::Jmp);
        assert_eq!(vm.trace[1].instruction.opcode, Opcode::Halt);
        assert_eq!(vm.trace[1].pc, 1);
        assert_eq!(vm.trace[1].next_pc, 1);
        assert_eq!(vm.trace[1].dst_val, 0);
        assert!(vm.halted);
    }

    /// Task 0.338 / A12: SRead/SWrite cost more gas than Load/Store.
    #[test]
    fn tur119_storage_gas_above_memory() {
        assert_eq!(Vm::gas_cost(Opcode::Load), 3);
        assert_eq!(Vm::gas_cost(Opcode::Store), 3);
        assert_eq!(Vm::gas_cost(Opcode::SRead), 8);
        assert_eq!(Vm::gas_cost(Opcode::SWrite), 12);
        assert!(Vm::gas_cost(Opcode::SRead) > Vm::gas_cost(Opcode::Load));
        assert!(Vm::gas_cost(Opcode::SWrite) > Vm::gas_cost(Opcode::Store));
        assert!(Vm::gas_cost(Opcode::SWrite) > Vm::gas_cost(Opcode::SRead));
    }

    /// H5 fix (pre-mortem V3): Lock Poseidon MDS and RC constants.
    /// If someone changes these in bud-vm, this test fails.
    /// wallet-core has its own lock test — both must match.
    #[test]
    fn poseidon_mds_rc_lock() {
        // MDS circulant matrix first row must be [7,1,3,8,8,3,4,9]
        assert_eq!(POSEIDON_MDS[0], [7, 1, 3, 8, 8, 3, 4, 9], "MDS row 0 mismatch");
        assert_eq!(POSEIDON_MDS[7], [1, 3, 8, 8, 3, 4, 9, 7], "MDS row 7 mismatch");
        // RC round 0 first two elements must match Plonky3 Poseidon1 Goldilocks
        assert_eq!(POSEIDON_RC[0][0], 0xdd5743e7f2a5a5d9, "RC[0][0] mismatch");
        assert_eq!(POSEIDON_RC[0][1], 0xcb3a864e58ada44b, "RC[0][1] mismatch");
    }
}
