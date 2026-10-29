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
// `docs/AI_VERIFICATION_STATUS.md`, no circuit re-derives the verified output
// from the model weights yet; the opcode only checks the commitment binding. README states plainly
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
    pub storage: std::collections::HashMap<u64, u64>,
    pub events: Vec<u64>,
    pub context: Context,
    pub trace: Vec<Step>,
    pub halted: bool,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub error: Option<VmError>,
    pub state_writes: Vec<(u64, u64)>,
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
    /// Merkle path expansion rows. The original step that triggers a
    /// `VerifyMerkle` carries only `merkle_key`. It is followed by
    /// [`MERKLE_ROUNDS`] expansion rows, one per word of the path window: four
    /// leaf words, 64 levels of four sibling words, four root words. Every
    /// expansion row reads one word, so every word reaches the memory argument.
    ///
    /// `merkle_current` is the 256-bit node the walk holds entering the row,
    /// `merkle_sibling` the four-word buffer the AIR holds on the row (the words
    /// of the current group read so far, older words carried), `merkle_word` the
    /// word this row reads and `merkle_round` the row's index in the window.
    pub merkle_key: Option<u64>,
    pub merkle_current: Option<[u64; 4]>,
    pub merkle_sibling: Option<[u64; 4]>,
    pub merkle_word: Option<u64>,
    pub merkle_round: Option<u16>,
    pub merkle_is_expand: bool,
    /// Reserved inference columns. The VM never fills them (always None or
    /// false) because VerifyInference emits no expansion rows. The AIR forces
    /// the matching trace columns to zero.
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

/// The storage slot a **constant** `SRead`/`SWrite` immediate names, as the
/// one field element the AIR, the VM and the prover must all agree on.
///
/// `imm == -1` is the dynamic form (slot from `rs2`) and is not this helper's
/// business. Any other negative immediate is `P - |imm|`, the Goldilocks
/// modular negative that `COL_IMM` carries and that `Load`-immediate and
/// `PrivacyCommit` already use. Encoding it as the i64 two's complement
/// (`2^64 - |imm|`) instead made the honest trace unprovable: the memory
/// LogUp had no matching row and the `SWrite` gadget bound the wrong slot.
///
/// `unsigned_abs` is used so `i32::MIN` cannot overflow the negation.
#[must_use]
pub fn constant_storage_slot(imm: i32) -> u64 {
    if imm < 0 {
        GOLDILOCKS_P.wrapping_sub(u64::from(imm.unsigned_abs()))
    } else {
        imm as u64
    }
}

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

/// The most memory a VM may hold, in bytes. The memory table of the proof
/// names an address with 32 bits, so a larger memory could run but not be
/// proved.
pub const MAX_MEMORY_BYTES: u64 = 1 << 32;

/// True if a memory of `memory_size` bytes can be proved.
fn memory_size_is_provable(memory_size: usize) -> bool {
    memory_size as u64 <= MAX_MEMORY_BYTES
}

impl Vm {
    pub fn new(memory_size: usize) -> Self {
        Self::with_gas_limit(memory_size, 1_000_000)
    }

    /// Panics if `memory_size` is above [`MAX_MEMORY_BYTES`]. The size comes
    /// from the host that builds the VM, never from a program.
    pub fn with_gas_limit(memory_size: usize, gas_limit: u64) -> Self {
        assert!(
            memory_size_is_provable(memory_size),
            "memory size {memory_size} is above the 2^32 byte address space of the proof"
        );
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

    fn memory_word(&self, addr: usize) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.memory[addr..addr + 8]);
        u64::from_le_bytes(bytes)
    }

    /// Walk the path window at `path_addr`, or `None` when the window does not fit
    /// in memory. The window is `[key, leaf[4], 64 x sibling[4], root[4]]`.
    ///
    /// The rows are computed exactly as the AIR constrains them: each group of
    /// four rows reads four words into a buffer, and at the end of a group the
    /// held node becomes the leaf (group 0), the compression of the node and the
    /// buffer ordered by the key bit (groups 1 to 64), or stays (the root group,
    /// whose rows compare the held node with the root words).
    fn merkle_walk(&self, path_addr: usize) -> Option<MerkleWalk> {
        let end = path_addr.checked_add(8 * MERKLE_WINDOW_WORDS)?;
        if end > self.memory.len() {
            return None;
        }
        let key = self.memory_word(path_addr);
        let mut rows = Vec::with_capacity(MERKLE_ROUNDS);
        let mut current = [0u64; 4];
        let mut buffer = [0u64; 4];
        let mut matches = true;
        for round in 0..MERKLE_ROUNDS {
            let addr = path_addr + 8 + 8 * round;
            let word = self.memory_word(addr);
            let lane = round % 4;
            let group = round / 4;
            buffer[lane] = word;
            rows.push(MerkleRow {
                addr,
                word,
                round: round as u16,
                current,
                buffer,
            });
            if round >= MERKLE_ROOT_ROUND {
                matches &= current[lane] == word;
            }
            if lane == 3 {
                if group == 0 {
                    current = buffer;
                } else if group <= 64 {
                    let bit = (key >> (group - 1)) & 1;
                    current = if bit == 0 {
                        merkle_node(current, buffer)
                    } else {
                        merkle_node(buffer, current)
                    };
                }
            }
        }
        Some(MerkleWalk { key, rows, matches })
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
                    // Canonical field element, as in the trace and the AIR.
                    if inst.imm < 0 {
                        GOLDILOCKS_P.wrapping_sub(inst.imm.unsigned_abs() as u64)
                    } else {
                        inst.imm as u64
                    }
                } else if let Some(addr) =
                    Self::memory_word_addr(src1_val, inst.imm, self.memory.len())
                {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&self.memory[addr..addr + 8]);
                    let val = u64::from_le_bytes(bytes);
                    // The trace, every AIR constraint and the state-write
                    // digest read a memory word as a Goldilocks element, i.e.
                    // as `val mod P`, while this VM compares and stores the
                    // raw `u64`. A word at or above the modulus therefore
                    // makes the executed and the proven operand disagree, and
                    // that is reachable: `Store` needs no alignment, so a
                    // write to a neighbouring address rewrites a cell's low
                    // byte without ever recording a value for that cell.
                    // Refuse it, exactly as the immediate form above is
                    // canonicalised rather than truncated.
                    if val >= GOLDILOCKS_P {
                        self.halted = true;
                        self.error = Some(VmError::InvalidMemoryAccess);
                        return Err(VmError::InvalidMemoryAccess);
                    }
                    memory_addr = Some(addr);
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
                    src2_val
                } else {
                    constant_storage_slot(inst.imm)
                };
                let val = *self.storage.get(&slot).unwrap_or(&0);
                self.registers[dst_idx as usize] = val;
                self.pc += 1;
                (val, cur_pc + 1)
            }
            Opcode::SWrite => {
                let slot = if inst.imm == -1 {
                    src2_val
                } else {
                    constant_storage_slot(inst.imm)
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
                // The path window at `imm` is, in 8-byte words:
                //   [key, leaf[4], 64 levels x sibling[4], root[4]]
                // The operands `rs1` and `rs2` are not read: a 256-bit node does
                // not fit a register, so the leaf and the root live in the window
                // and every word of it is read by its own expansion row, which is
                // what binds them to the memory argument. `rd` receives 1 when
                // the walk from the leaf ends at the root.
                let path_addr = inst.imm as usize;
                // `checked_add`: `inst.imm` is program supplied, and an address
                // within the window length of `usize::MAX` must be refused, not
                // wrapped into a small number that passes the bound.
                let walk = self.merkle_walk(path_addr);
                let result = match &walk {
                    Some(w) => {
                        // The key is read from memory like any other word, so it
                        // belongs in the memory argument.
                        memory_addr = Some(path_addr);
                        memory_val = Some(w.key);
                        u64::from(w.matches)
                    }
                    None => 0,
                };
                self.registers[dst_idx as usize] = result;
                self.pc += 1;
                (result, cur_pc + 1)
            }
            // VerifyInference is reserved. The VM always answers 0 and reads
            // no memory. Any proof of a trace containing this opcode is
            // refused by the AIR. Weights, input and output binding is
            // planned through a hash-over-memory primitive, not here.
            Opcode::VerifyInference => {
                let result = 0;
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
                                         // HIGH (CWE-682, 2026-08-17): recipient, trace'teki
                                         // It must be EXACTLY the same value as COL_IMM. COL_IMM carries a negative
                                         // imm as the Goldilocks modular negative (P - |imm|); the i64->u64
                                         // two's complement (2^64-|imm|) was incompatible with the AIR.
                                         // The VM, prover and AIR now use the same value.
                                         // HIGH (CWE-682 + i32::MIN, 2026-08-17): `-imm` i32::MIN
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
            merkle_word: None,
            merkle_round: None,
            merkle_is_expand: false,
            inference_model_commitment: None,
            inference_input_commitment: None,
            inference_output_commitment: None,
            inference_proof_round: None,
            inference_is_expand: false,
        });

        // A `VerifyMerkle` is followed by one expansion row per word of its path
        // window. The rows share the original pc and keep `next_pc == pc` until the
        // last one, which hands off to the next instruction (the AIR enforces
        // `nxt_pc == next_pc` on every cpu row).
        if matches!(inst.opcode, Opcode::VerifyMerkle) {
            let path_addr = inst.imm as usize;
            if let Some(walk) = self.merkle_walk(path_addr) {
                if let Some(last) = self.trace.last_mut() {
                    last.merkle_key = Some(walk.key);
                    last.next_pc = cur_pc;
                }
                let rows = walk.rows.len();
                for (index, row) in walk.rows.iter().enumerate() {
                    let expand_next_pc = if index + 1 == rows {
                        cur_pc + 1
                    } else {
                        cur_pc
                    };
                    self.trace.push(Step {
                        pc: cur_pc,
                        next_pc: expand_next_pc,
                        instruction: Instruction {
                            opcode: Opcode::VerifyMerkle, // reused; merkle_is_expand marks it
                            rd: 0,
                            rs1: 0,
                            rs2: 0,
                            // The path base address: the memory argument derives each
                            // expansion row's address as `imm + 8 + 8 * round`.
                            imm: inst.imm,
                        },
                        src1_idx: 0,
                        src2_idx: 0,
                        dst_idx: 0,
                        src1_val: 0,
                        src2_val: 0,
                        dst_val: 0,
                        registers: self.registers,
                        // Each expansion row carries the read of its word, so every
                        // word of the window is in the memory argument.
                        memory_addr: Some(row.addr),
                        memory_val: Some(row.word),
                        is_memory_write: false,
                        stack_pointer: self.stack.len(),
                        merkle_key: Some(walk.key),
                        merkle_current: Some(row.current),
                        merkle_sibling: Some(row.buffer),
                        merkle_word: Some(row.word),
                        merkle_round: Some(row.round),
                        merkle_is_expand: true,
                        inference_model_commitment: None,
                        inference_input_commitment: None,
                        inference_output_commitment: None,
                        inference_proof_round: None,
                        inference_is_expand: false,
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
                    merkle_word: None,
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

        // HIGH CWE-345 (2026-08-17): state-write digest is a Poseidon
        // STATE CHAIN over the executed (slot, val) pairs in EXECUTION ORDER
        // (matching the trace, which feeds the gadget on each SWrite row in
        // program order). 32 bytes = first 4 lanes of the final accumulator.
        let mut acc = [0u64; 4];
        for (slot, val) in &self.state_writes {
            let mut st = [0u64; POSEIDON_WIDTH];
            st[0] = *slot;
            st[1] = *val;
            st[2..6].copy_from_slice(&acc);
            let out = poseidon_full_state(st);
            acc.copy_from_slice(&out[..4]);
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

/// Expansion rows of one `VerifyMerkle`: 4 leaf words, 64 levels of 4 sibling
/// words, 4 root words.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const MERKLE_ROUNDS: usize = 4 + 64 * 4 + 4;

/// Words in the path window: the key, then the expansion words.
///
/// WIRING: the size of the window a program lays out for `VerifyMerkle`; the VM bound
/// check uses it and the compiler and wallet tooling read it to size memory.
pub const MERKLE_WINDOW_WORDS: usize = 1 + MERKLE_ROUNDS;

/// First expansion row that reads a root word.
pub const MERKLE_ROOT_ROUND: usize = 4 + 64 * 4;

/// One expansion row of a Merkle walk, as the AIR sees it.
///
/// WIRING: produced by the VM walk and consumed by the trace builder in `bud-proof`.
#[derive(Debug, Clone)]
pub struct MerkleRow {
    /// Address of the word this row reads.
    pub addr: usize,
    /// The word.
    pub word: u64,
    /// Index of the row in the window.
    pub round: u16,
    /// The node the walk holds entering the row.
    pub current: [u64; 4],
    /// The four-word buffer on the row, this row's word included.
    pub buffer: [u64; 4],
}

/// The whole walk of a `VerifyMerkle`.
///
/// WIRING: produced by the VM and read by the trace builder in `bud-proof`.
#[derive(Debug, Clone)]
pub struct MerkleWalk {
    /// The path key: bit `i` says which side level `i` sits on.
    pub key: u64,
    /// One entry per expansion row.
    pub rows: Vec<MerkleRow>,
    /// The walk from the leaf ended at the root.
    pub matches: bool,
}

/// Domain separator for nullifier derivation.
/// ASCII-ish constant "NULLIFER" as a field element. It is the second input
/// of the nullifier hash, nothing more. It does NOT separate the domains:
/// the Poseidon opcode, `PrivacyCommit` and the nullifier hash all run the
/// same permutation with zero capacity and no tag, so `Poseidon(a, b)` equals
/// `PrivacyCommit(a, b, 0)` and `nullifier(s)` equals `Poseidon(s, D)`
/// A real separation needs a capacity tag, which changes the AIR.
pub const DOMAIN_NULLIFIER: u64 = 0x4e55_4c4c_4946_4552; // "NULLIFER"

// The in-VM hash is the Poseidon parameter set: Goldilocks, width 12,
// 8 full and 22 partial rounds, `alpha = 7`, capacity 4, output 4 elements.
// The definition lives in `budlum-note-packing` so the wallet, the VM and the
// node read one copy; `budzero/bud-proof/tests/poseidon_parity.rs` checks it
// against Plonky3's own permutation.

/// State width of the in-VM permutation.
pub const POSEIDON_WIDTH: usize = budlum_note_packing::poseidon::WIDTH;

/// MDS matrix - must match `BudAir`. Module-level const so lock tests can see it.
pub const POSEIDON_MDS: [[u64; POSEIDON_WIDTH]; POSEIDON_WIDTH] =
    budlum_note_packing::poseidon::MDS;

/// All 30 rounds of round constants for the width-12 instance
/// (4 leading full rounds, 22 partial rounds, 4 trailing full rounds).
///
/// Source: Plonky3 `goldilocks/src/poseidon1.rs`, `GOLDILOCKS_POSEIDON1_RC_12`.
pub const POSEIDON_RC_FULL: [[u64; 12]; 30] = budlum_note_packing::poseidon::RC;

/// Full rounds (4 leading + 4 trailing).
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const POSEIDON_FULL_ROUNDS: usize = budlum_note_packing::poseidon::FULL_ROUNDS;

/// Partial rounds: the S-box runs on lane 0 only. The count comes from the
/// interpolation bound of the Poseidon paper (Eq. 3) for this field and
/// S-box, `ceil(64 / log2(7)) + ceil(log_7(12)) - 5 = 20`, plus the paper's
/// 7.5% margin: `ceil(1.075 * 20) = 22`.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const POSEIDON_PARTIAL_ROUNDS: usize = budlum_note_packing::poseidon::PARTIAL_ROUNDS;

/// S-box exponent. `gcd(7, P - 1) = 1` over Goldilocks, so `x -> x^7` is a
/// permutation of the field.
pub const POSEIDON_ALPHA: u64 = budlum_note_packing::poseidon::ALPHA;

/// Rounds evaluated by [`poseidon_full_state`] and constrained by the AIR.
/// `vm_hash_still_matches_the_air_round_count` asserts the VM and the AIR
/// agree, and that check keeps them from drifting apart.
pub const POSEIDON_ROUNDS_IN_USE: usize = POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS;

/// The full 30-round permutation over the whole 12-lane state.
///
/// The state-write digest chains the first four lanes of this, the AIR
/// gadget constrains every round, and the Merkle node function is its first
/// four output lanes.
pub fn poseidon_full_state(s: [u64; POSEIDON_WIDTH]) -> [u64; POSEIDON_WIDTH] {
    budlum_note_packing::poseidon::permute(s)
}

/// The permutation collapsed to lane 0, the value the `Poseidon` opcode writes.
pub fn poseidon_full_hash_state(s: [u64; POSEIDON_WIDTH]) -> u64 {
    poseidon_full_state(s)[0]
}

/// Lane 0 of the permutation of an arbitrary 12-lane initial state. Shared by
/// `poseidon4_hash`, `poseidon4_hash3` and the AIR Poseidon gadget.
pub fn poseidon4_hash_state(s: [u64; POSEIDON_WIDTH]) -> u64 {
    poseidon_full_hash_state(s)
}

/// Poseidon with 3 absorbed field elements (state = [a, b, c, 0, ...]).
pub fn poseidon4_hash3(a: u64, b: u64, c: u64) -> u64 {
    let mut state = [0u64; POSEIDON_WIDTH];
    state[0] = a;
    state[1] = b;
    state[2] = c;
    poseidon4_hash_state(state)
}

/// Poseidon with 2 absorbed field elements (state = [a, b, 0, ...]). Used by
/// the Poseidon opcode and by `NullifierCheck` (with `DOMAIN_NULLIFIER` as the
/// second input).
pub fn poseidon4_hash(a: u64, b: u64) -> u64 {
    poseidon4_hash3(a, b, 0)
}

/// The Merkle node function: two 256-bit nodes into one.
///
/// WIRING: the VM walk uses it; `bud-proof` tests, the benchmark seeds and the zkVM
/// adapter test build their expected roots with it.
pub fn merkle_node(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
    budlum_note_packing::poseidon::compress(left, right)
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

    /// The memory table of the proof names an address with 32 bits, so a
    /// memory above `2^32` bytes cannot be proved. The constructor refuses it.
    #[cfg(target_pointer_width = "64")]
    #[test]
    #[should_panic(expected = "memory size")]
    fn rejects_memory_larger_than_the_proof_address_space() {
        let _ = Vm::new((1usize << 32) + 1);
    }

    /// The bound is inclusive. This checks the check only and never builds a
    /// VM of `MAX_MEMORY_BYTES`.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn memory_bound_accepts_the_maximum_and_refuses_one_more() {
        assert!(memory_size_is_provable(MAX_MEMORY_BYTES as usize));
        assert!(!memory_size_is_provable(MAX_MEMORY_BYTES as usize + 1));
    }

    #[test]
    fn memory_bound_accepts_small_sizes() {
        assert!(memory_size_is_provable(0));
        assert!(memory_size_is_provable(8192));
    }

    /// The assert fires before the allocation, so this is safe to run.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn with_gas_limit_refuses_one_byte_above_the_maximum() {
        let outcome =
            std::panic::catch_unwind(|| Vm::with_gas_limit(MAX_MEMORY_BYTES as usize + 1, 1));
        let Err(payload) = outcome else {
            panic!("one byte above the maximum must be refused");
        };
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(message.contains("memory size"), "got {message:?}");
    }

    /// `Load rd, r0, imm` copies the immediate as a field element. A negative
    /// immediate is `P - |imm|`, the value the trace and the AIR use, and not
    /// the two's complement `2^64 - |imm|`, which is not below `P`.
    #[test]
    fn load_imm_negative_is_canonical() {
        let program = vec![
            inst(Opcode::Load, 1, 0, 0, -1),
            inst(Opcode::Load, 2, 0, 0, i32::MIN),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        assert!(vm.run_receipt(&program).success);
        assert_eq!(vm.registers[1], GOLDILOCKS_P - 1);
        assert_eq!(vm.registers[2], GOLDILOCKS_P - (1u64 << 31));
    }

    /// The address whose window wraps must be refused, not indexed.
    ///
    /// `VerifyMerkle` reads a window of `8 * MERKLE_WINDOW_WORDS` bytes at `inst.imm`. The bound used
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
        // The window is `8 * MERKLE_WINDOW_WORDS` bytes, so the last address that
        // fits is memory minus that. One past it must not be read.
        let too_far = i32::try_from(memory - 8 * MERKLE_WINDOW_WORDS + 1).expect("fits in i32");
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
        let last_fitting = i32::try_from(memory - 8 * MERKLE_WINDOW_WORDS).expect("fits in i32");
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

    /// VerifyInference is reserved. It reads no memory, even through a
    /// register address whose window would wrap, and it leaves no inference
    /// data in the trace.
    #[test]
    fn verify_inference_refuses_a_register_address_whose_window_wraps() {
        let program = vec![
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
        assert_eq!(vm.registers[3], 0);
        assert_no_inference_data(&vm);
    }

    fn assert_no_inference_data(vm: &Vm) {
        assert!(
            vm.trace.iter().all(|row| {
                row.inference_model_commitment.is_none()
                    && row.inference_input_commitment.is_none()
                    && row.inference_output_commitment.is_none()
                    && row.inference_proof_round.is_none()
                    && !row.inference_is_expand
            }),
            "VerifyInference must leave no inference data in the trace"
        );
    }

    /// Even a window that used to be a valid commitment chain answers 0, and
    /// the trace holds exactly one VerifyInference row and no expansion rows.
    #[test]
    fn verify_inference_always_returns_zero_and_emits_no_expansion_rows() {
        let model_c = 0xABCD_EF01_2345_6789u64;
        let input_c = 0x1122_3344_5566_7788u64;
        let output_c = poseidon4_hash(model_c, input_c);
        for imm in [0i32, 1] {
            let mut vm = Vm::new(256);
            vm.memory[64..72].copy_from_slice(&model_c.to_le_bytes());
            vm.memory[72..80].copy_from_slice(&input_c.to_le_bytes());
            vm.memory[80..88].copy_from_slice(&output_c.to_le_bytes());
            vm.registers[1] = 64;
            let program = vec![
                inst(Opcode::VerifyInference, 3, 1, 0, imm),
                inst(Opcode::Halt, 0, 0, 0, 0),
            ];
            let receipt = vm.run_receipt(&program);
            assert!(receipt.success);
            assert_eq!(
                vm.registers[3], 0,
                "reserved opcode must answer 0 (imm={imm})"
            );
            let n = vm
                .trace
                .iter()
                .filter(|r| r.instruction.opcode == Opcode::VerifyInference)
                .count();
            assert_eq!(n, 1, "exactly one VerifyInference row, no expansion");
            assert_no_inference_data(&vm);
        }
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

    /// The stack limit, an empty pop and a jump below zero all end
    /// the run with a typed error. None of them is a panic.
    #[test]
    fn stack_limit_empty_pop_and_negative_jump_are_typed_errors() {
        let mut overflow: Vec<u64> = (0..1025).map(|_| inst(Opcode::Push, 0, 1, 0, 0)).collect();
        overflow.push(inst(Opcode::Halt, 0, 0, 0, 0));
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&overflow);
        assert!(!receipt.success);
        assert_eq!(receipt.error, Some(VmError::StackOverflow));

        let pop = vec![
            inst(Opcode::Pop, 2, 0, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&pop);
        assert!(!receipt.success);
        assert_eq!(receipt.error, Some(VmError::StackUnderflow));

        let jump = vec![
            inst(Opcode::Jmp, 0, 0, 0, -5),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        let receipt = vm.run_receipt(&jump);
        assert!(!receipt.success);
        assert_eq!(receipt.error, Some(VmError::InvalidPc));
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

    /// A memory word at or above the Goldilocks modulus is not a field
    /// element. The trace, every AIR constraint and the state-write digest
    /// read such a word as `val mod P` while the VM used to compare and store
    /// the raw `u64`, so a proof could attest to a comparison outcome and a
    /// storage value that no honest execution produces. `Store` needs no
    /// alignment, so a neighbouring write can plant one; the memory form of
    /// `Load` refuses it now, as the immediate form already canonicalises.
    #[test]
    fn load_refuses_a_memory_word_that_is_not_a_field_element() {
        let program = vec![
            inst(Opcode::Load, 1, 2, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        vm.memory[0..8].copy_from_slice(&GOLDILOCKS_P.to_le_bytes());
        let receipt = vm.run_receipt(&program);
        assert!(
            !receipt.success,
            "a non-canonical word must not enter a register"
        );
        assert_eq!(receipt.error, Some(VmError::InvalidMemoryAccess));

        // A guard that refused every memory word would satisfy the assertion
        // above and break the opcode; the largest canonical value still loads.
        let canonical = GOLDILOCKS_P - 1;
        let mut vm = Vm::new(64);
        vm.memory[0..8].copy_from_slice(&canonical.to_le_bytes());
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "a canonical word must still be loaded");
        assert_eq!(vm.registers[1], canonical);
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

    /// `VerifyMerkle` pushes the original step and one expansion row per word of
    /// its path window: four leaf words, 64 levels of four sibling words
    /// and four root words, so that every word reaches the memory argument.
    #[test]
    fn verify_merkle_emits_one_row_per_window_word() {
        let program = vec![
            inst(Opcode::VerifyMerkle, 1, 2, 3, 256),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(4096);
        vm.memory[256..264].copy_from_slice(&7u64.to_le_bytes());
        for i in 0..MERKLE_ROUNDS {
            let off = 264 + i * 8;
            vm.memory[off..off + 8].copy_from_slice(&(1000u64 + i as u64).to_le_bytes());
        }
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(
            vm.trace.len(),
            1 + MERKLE_ROUNDS + 1,
            "the original row, one row per window word, Halt"
        );
        let first = &vm.trace[0];
        assert_eq!(first.instruction.opcode, Opcode::VerifyMerkle);
        assert_eq!(first.merkle_key, Some(7));
        assert!(!first.merkle_is_expand);
        for i in 0..MERKLE_ROUNDS {
            let row = &vm.trace[1 + i];
            assert!(row.merkle_is_expand, "row {i} should be an expansion row");
            assert_eq!(row.merkle_key, Some(7));
            assert_eq!(row.merkle_round, Some(i as u16));
            assert_eq!(row.merkle_word, Some(1000 + i as u64));
            assert_eq!(row.memory_addr, Some(264 + 8 * i));
            assert!(row.merkle_current.is_some() && row.merkle_sibling.is_some());
        }
        let last = &vm.trace[MERKLE_ROUNDS + 1];
        assert_eq!(last.instruction.opcode, Opcode::Halt);
        assert!(!last.merkle_is_expand);
        assert_eq!(
            vm.registers[1], 0,
            "an arbitrary window is not a path to its root"
        );
    }

    /// A window built by walking a leaf up 64 levels verifies, and changing any
    /// root word, any sibling word or the key makes it fail.
    #[test]
    fn verify_merkle_accepts_the_real_root_and_nothing_else() {
        let leaf = [11u64, 12, 13, 14];
        let key = 0x0123_4567_89ab_cdefu64;
        let mut siblings = [[0u64; 4]; 64];
        for (level, sibling) in siblings.iter_mut().enumerate() {
            *sibling = [level as u64, 1 + level as u64, 2, 3];
        }
        let mut node = leaf;
        for (level, sibling) in siblings.iter().enumerate() {
            node = if (key >> level) & 1 == 0 {
                merkle_node(node, *sibling)
            } else {
                merkle_node(*sibling, node)
            };
        }
        let run = |tamper: &dyn Fn(&mut Vec<u64>)| {
            let mut words = vec![key];
            words.extend_from_slice(&leaf);
            for sibling in &siblings {
                words.extend_from_slice(sibling);
            }
            words.extend_from_slice(&node);
            tamper(&mut words);
            let program = vec![
                inst(Opcode::VerifyMerkle, 1, 0, 0, 256),
                inst(Opcode::Halt, 0, 0, 0, 0),
            ];
            let mut vm = Vm::new(4096);
            for (i, w) in words.iter().enumerate() {
                vm.memory[256 + 8 * i..264 + 8 * i].copy_from_slice(&w.to_le_bytes());
            }
            assert!(vm.run_receipt(&program).success);
            vm.registers[1]
        };
        assert_eq!(run(&|_| {}), 1, "the honest window verifies");
        assert_eq!(
            run(&|w| w[MERKLE_WINDOW_WORDS - 1] ^= 1),
            0,
            "last root word"
        );
        assert_eq!(
            run(&|w| w[MERKLE_WINDOW_WORDS - 4] ^= 1),
            0,
            "first root word"
        );
        assert_eq!(run(&|w| w[5 + 4 * 31 + 2] ^= 1), 0, "a sibling word");
        assert_eq!(run(&|w| w[1] ^= 1), 0, "a leaf word");
        assert_eq!(run(&|w| w[0] ^= 1), 0, "the key");
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

    /// A dynamic storage key keeps all 64 bits: two keys that agree in the
    /// low 32 bits are two different slots.
    #[test]
    fn dynamic_storage_key_is_not_truncated() {
        let wide = (1u64 << 32) | 3;
        let program = vec![
            inst(Opcode::SWrite, 0, 1, 2, -1),
            inst(Opcode::SWrite, 0, 4, 3, -1),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(64);
        vm.registers[1] = 5;
        vm.registers[2] = wide;
        vm.registers[3] = 3;
        vm.registers[4] = 9;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        assert_eq!(vm.storage.get(&wide), Some(&5));
        assert_eq!(vm.storage.get(&3), Some(&9));
        assert_eq!(vm.state_writes, vec![(wide, 5), (3, 9)]);
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
    #[test]
    fn poseidon_mds_rc_lock() {
        // MDS circulant matrix first row of the width-12 instance.
        assert_eq!(
            POSEIDON_MDS[0],
            [1, 1, 2, 1, 8, 9, 10, 7, 5, 9, 4, 10],
            "MDS row 0 mismatch"
        );
        assert_eq!(
            POSEIDON_MDS[11],
            [1, 2, 1, 8, 9, 10, 7, 5, 9, 4, 10, 1],
            "MDS row 11 mismatch"
        );
        assert_eq!(
            POSEIDON_RC_FULL[0][0], 0x13dc_f33a_ba21_4f46,
            "RC[0][0] mismatch"
        );
    }

    /// The whole table is bound to a single constant.
    ///
    /// A spot check misses every constant it does not sample, and a changed
    /// constant is a changed permutation. The fingerprint is FNV-1a 64: it does
    /// not have to be cryptographic, it has to move when a single bit moves.
    /// When the value changes the thing to do is not to update it but to find
    /// out what changed.
    #[test]
    fn the_whole_constant_table_is_locked() {
        const fn fnv1a64(vals: &[[u64; 12]]) -> u64 {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            let mut r = 0;
            while r < vals.len() {
                let mut c = 0;
                while c < 12 {
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
            0xd3fc_7a39_5e21_481c,
            "the 30-round constant table changed; find what moved before touching this number"
        );
        assert_eq!(
            fnv1a64(&POSEIDON_MDS),
            0x99be_3c65_3797_0be5,
            "the MDS matrix changed"
        );
        assert_eq!(POSEIDON_RC_FULL[0][0], 0x13dc_f33a_ba21_4f46);
        assert_eq!(POSEIDON_RC_FULL[29][11], 0x23c7_426a_f725_a6a0);
    }
}

#[cfg(test)]
mod poseidon_parameter_tests {
    use super::*;

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
        assert_eq!(POSEIDON_WIDTH, 12);
    }

    /// The partial-round count is derived, not chosen. Recompute the bound.
    #[test]
    fn partial_round_count_matches_the_interpolation_bound() {
        // R_interp >= ceil(64 / log2(7)) + ceil(log_7(12)) - 5
        let alpha = POSEIDON_ALPHA as f64;
        let interp = (64.0 / alpha.log2()).ceil() + (12f64.ln() / alpha.ln()).ceil() - 5.0;
        assert_eq!(interp as usize, 20, "interpolation bound should be 20");
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

    /// The VM's hash is the full permutation, lane 0 of it.
    #[test]
    fn vm_hash_is_the_full_permutation() {
        for a in [0u64, 1, 2, 12345, GOLDILOCKS_P - 1] {
            for b in [0u64, 7, 999, GOLDILOCKS_P - 2] {
                let mut state = [0u64; POSEIDON_WIDTH];
                state[0] = a;
                state[1] = b;
                assert_eq!(poseidon4_hash_state(state), poseidon_full_state(state)[0]);
                assert_eq!(poseidon4_hash(a, b), poseidon4_hash_state(state));
            }
        }
    }

    /// The full permutation must be deterministic and stay canonical.
    #[test]
    fn full_permutation_is_deterministic_and_canonical() {
        let mut state = [0u64; POSEIDON_WIDTH];
        for (i, lane) in state.iter_mut().enumerate().take(8) {
            *lane = 1 + i as u64;
        }
        let a = poseidon_full_hash_state(state);
        assert_eq!(a, poseidon_full_hash_state(state));
        assert!(a < GOLDILOCKS_P);
        let mut other = state;
        other[7] ^= 1;
        assert_ne!(a, poseidon_full_hash_state(other));
    }

    /// The VM must keep computing what the AIR constrains.
    #[test]
    fn vm_hash_still_matches_the_air_round_count() {
        assert_eq!(POSEIDON_ROUNDS_IN_USE, POSEIDON_RC_FULL.len());
        assert_eq!(
            POSEIDON_ROUNDS_IN_USE,
            POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS,
            "the VM and the AIR both run the full 30-round schedule; if one is cut \
             back the other must be cut back in the same change"
        );
    }

    /// The three hash uses share one function with zero capacity.
    /// This test records the overlap so nobody reads the nullifier constant
    /// as domain separation.
    #[test]
    fn poseidon_privacy_commit_and_nullifier_share_one_domain() {
        let (a, b) = (11u64, 22u64);
        assert_eq!(poseidon4_hash(a, b), poseidon4_hash3(a, b, 0));
        let secret = 99u64;
        assert_eq!(
            poseidon4_hash(secret, DOMAIN_NULLIFIER),
            poseidon4_hash3(secret, DOMAIN_NULLIFIER, 0)
        );
    }

    /// The node function is four lanes wide: a node does not collapse to one
    /// element, and the two children are not interchangeable.
    #[test]
    fn the_merkle_node_is_256_bits_and_ordered() {
        let (a, b) = ([1u64, 2, 3, 4], [5u64, 6, 7, 8]);
        let node = merkle_node(a, b);
        assert_ne!(node, merkle_node(b, a));
        let distinct = node.iter().collect::<std::collections::BTreeSet<_>>().len();
        assert_eq!(
            distinct, 4,
            "the four lanes of a node are four different elements"
        );
    }
}
