//! Deterministic `#![forbid(unsafe_code)]` RISC-V 32IM (`RV32I + M`)
//! execution engine for Budlum (`EeId::RV32 = 0x0C`).
//!
//! WIRING: wired through `EeId::RV32` in `src/execution/coordinator/expansion_ee.rs`
//! and out-of-process worker `execution/rv32`.
//!
//! Supports two image containers with strict bounded validation:
//! 1. `BRV1` compact image (`"BRV1" || entry_u32_le || text_len_u32_le || data_len_u32_le || text || data`)
//! 2. Standard 32-bit little-endian RISC-V `ELF` (`\x7fELF`, `EI_CLASS = 1`, `EI_DATA = 1`, `e_machine = 0xF3`)
//!
//! Executes strictly in deterministic interpreter mode (`x0 == 0` enforced,
//! wrapping two's-complement arithmetic, RISC-V division-by-zero / `INT_MIN / -1`
//! semantics with zero host panics) inside a 1 MiB virtual address space and exposes
//! Budlum's `HostApi` via standard `ECALL` (`a7` syscall number).

#![forbid(unsafe_code)]

use budlum_uel_abi::{
    CodeInfo, EeCall, EeCallKind, EeIdentity, EeLog, EeOutcome, EeRefusal, HostApi, Namespace,
    OutcomeStatus, RefusalCode,
};
use sha2::{Digest, Sha256};

/// Compact binary container magic: `"BRV1"`.
pub const BRV1_MAGIC: &[u8; 4] = b"BRV1";

/// Standard ELF magic: `0x7F 'E' 'L' 'F'`.
pub const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

/// Fixed virtual memory size per contract invocation (`1 MiB`).
pub const RV32_MEMORY_BYTES: usize = 1024 * 1024;

/// Maximum instruction steps permitted in one deterministic invocation.
pub const MAX_RV32_STEPS: u64 = 250_000;

/// Base gas charged per RV32 execution.
pub const RV32_BASE_DEPLOY_GAS: u64 = 20_000;
pub const RV32_BASE_CALL_GAS: u64 = 5_000;
pub const RV32_PER_BYTE_GAS: u64 = 16;
pub const RV32_STEP_GAS: u64 = 1;
pub const RV32_ECALL_GAS: u64 = 50;

/// Default stack pointer placed near the top of the 1 MiB isolated address space.
const INITIAL_SP: u32 = (RV32_MEMORY_BYTES as u32) - 16;

/// Base address for compact `BRV1` `.data` section (`64 KiB`).
const BRV1_DATA_BASE: usize = 65_536;

/// `ECALL` syscall numbers passed in `x17` (`a7`).
pub mod syscall {
    pub const EXIT_OK: u32 = 0;
    pub const REVERT: u32 = 1;
    pub const INPUT_LEN: u32 = 2;
    pub const READ_INPUT: u32 = 3;
    pub const STORAGE_READ: u32 = 4;
    pub const STORAGE_WRITE: u32 = 5;
    pub const EMIT_LOG: u32 = 6;
    pub const BUD_BALANCE: u32 = 7;
    pub const UNIVERSAL_CALL: u32 = 8;
}

/// Decoded deterministic RV32 program segments ready for VM load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rv32Image {
    pub entry_pc: u32,
    pub segments: Vec<(u32, Vec<u8>)>,
    pub code_hash: [u8; 32],
}

fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    let slice = bytes.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let slice = bytes.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Parse and validate either a `BRV1` compact RV32IM image or a 32-bit LE RISC-V ELF.
///
/// # Errors
/// Returns an [`EeRefusal`] if the header, section bounds, alignment, or container
/// magic violates Budlum's deterministic RV32 rules.
pub fn parse_rv32_image(code: &[u8], max_code_bytes: usize) -> Result<Rv32Image, EeRefusal> {
    if code.len() < 16 || code.len() > max_code_bytes {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("RV32 image size out of bounds"),
        });
    }
    if crate::execution::coordinator::assets::is_pointer_bytecode_prefixed(code) {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("system pointer bytecode prefix is reserved for uel/assets"),
        });
    }
    let code_hash: [u8; 32] = Sha256::digest(code).into();

    if code.starts_with(BRV1_MAGIC) {
        let entry_pc = read_u32_le(code, 4).ok_or_else(|| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("BRV1 missing entry"),
        })?;
        let text_len = read_u32_le(code, 8).ok_or_else(|| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("BRV1 missing text length"),
        })? as usize;
        let data_len = read_u32_le(code, 12).ok_or_else(|| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("BRV1 missing data length"),
        })? as usize;
        let total = 16usize
            .checked_add(text_len)
            .and_then(|v| v.checked_add(data_len))
            .ok_or_else(|| EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("BRV1 section length overflow"),
            })?;
        if total != code.len() || text_len == 0 || !text_len.is_multiple_of(4) {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("BRV1 section alignment or length mismatch"),
            });
        }
        if (entry_pc as usize) >= text_len
            || text_len > BRV1_DATA_BASE
            || BRV1_DATA_BASE.saturating_add(data_len) > RV32_MEMORY_BYTES
            || !entry_pc.is_multiple_of(4)
        {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("BRV1 entry or memory bounds invalid"),
            });
        }
        let text_end = 16usize.checked_add(text_len).ok_or_else(|| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("BRV1 text end overflow"),
        })?;
        let text = code
            .get(16..text_end)
            .ok_or_else(|| EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("BRV1 text section out of bounds"),
            })?
            .to_vec();
        let data = code
            .get(text_end..)
            .ok_or_else(|| EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("BRV1 data section out of bounds"),
            })?
            .to_vec();
        let mut segments = vec![(0u32, text)];
        if !data.is_empty() {
            segments.push((BRV1_DATA_BASE as u32, data));
        }
        return Ok(Rv32Image {
            entry_pc,
            segments,
            code_hash,
        });
    }

    if code.starts_with(ELF_MAGIC) {
        if code.len() < 52 {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("ELF header truncated"),
            });
        }
        // EI_CLASS = 1 (ELFCLASS32), EI_DATA = 1 (ELFDATA2LSB), e_machine = 0xF3 (EM_RISCV)
        if code.get(4) != Some(&1) || code.get(5) != Some(&1) || read_u16_le(code, 18) != Some(0xF3)
        {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("ELF must be 32-bit little-endian RISC-V"),
            });
        }
        let entry_pc = read_u32_le(code, 24).unwrap_or(0);
        let phoff = read_u32_le(code, 28).unwrap_or(0) as usize;
        let phentsize = usize::from(read_u16_le(code, 42).unwrap_or(0));
        let phnum = usize::from(read_u16_le(code, 44).unwrap_or(0));
        if phentsize < 32 || phnum == 0 || phnum > 32 || (entry_pc as usize) >= RV32_MEMORY_BYTES {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("ELF program header table invalid"),
            });
        }
        let mut segments = Vec::new();
        for idx in 0..phnum {
            let off = phoff
                .checked_add(idx.saturating_mul(phentsize))
                .ok_or_else(|| EeRefusal {
                    code: RefusalCode::InvalidCode,
                    message: String::from("ELF phdr offset overflow"),
                })?;
            let p_type = read_u32_le(code, off).ok_or_else(|| EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("ELF phdr out of bounds"),
            })?;
            if p_type != 1 {
                continue;
            }
            let p_offset = read_u32_le(code, off + 4).unwrap_or(0) as usize;
            let p_vaddr = read_u32_le(code, off + 8).unwrap_or(0);
            let p_filesz = read_u32_le(code, off + 16).unwrap_or(0) as usize;
            let p_memsz = read_u32_le(code, off + 20).unwrap_or(0) as usize;
            if p_memsz < p_filesz {
                return Err(EeRefusal {
                    code: RefusalCode::InvalidCode,
                    message: String::from("ELF PT_LOAD memsz < filesz"),
                });
            }
            let file_end = p_offset.checked_add(p_filesz).ok_or_else(|| EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("ELF file slice overflow"),
            })?;
            let mem_end = (p_vaddr as usize)
                .checked_add(p_memsz)
                .ok_or_else(|| EeRefusal {
                    code: RefusalCode::InvalidCode,
                    message: String::from("ELF vaddr overflow"),
                })?;
            if file_end > code.len() || mem_end > RV32_MEMORY_BYTES {
                return Err(EeRefusal {
                    code: RefusalCode::InvalidCode,
                    message: String::from("ELF PT_LOAD exceeds 1 MiB virtual RAM or file length"),
                });
            }
            let mut seg = vec![0u8; p_memsz];
            let src = code.get(p_offset..file_end).ok_or_else(|| EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("ELF PT_LOAD file slice out of bounds"),
            })?;
            let dst = seg.get_mut(..p_filesz).ok_or_else(|| EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("ELF PT_LOAD mem slice out of bounds"),
            })?;
            dst.copy_from_slice(src);
            segments.push((p_vaddr, seg));
        }
        if segments.is_empty() || !entry_pc.is_multiple_of(4) {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("ELF has no loadable segments or unaligned entry"),
            });
        }
        return Ok(Rv32Image {
            entry_pc,
            segments,
            code_hash,
        });
    }

    Err(EeRefusal {
        code: RefusalCode::InvalidCode,
        message: String::from("RV32 image must start with BRV1 or ELF magic"),
    })
}

/// Validate an RV32 deployment artifact and produce [`CodeInfo`].
///
/// # Errors
/// Returns [`EeRefusal`] if `code` is not a valid `BRV1` or RISC-V `ELF32` image.
pub fn validate_rv32_deploy(code: &[u8], max_code_bytes: usize) -> Result<CodeInfo, EeRefusal> {
    let parsed = parse_rv32_image(code, max_code_bytes)?;
    Ok(CodeInfo {
        code_hash: parsed.code_hash,
        abi_tag: String::from("rv32im-host-v1"),
    })
}

/// Build a canonical compact `BRV1` executable blob from 32-bit machine words and initial `.data`.
#[cfg(test)]
#[must_use]
pub(crate) fn encode_brv1_image(entry_pc: u32, instructions: &[u32], data: &[u8]) -> Vec<u8> {
    let text_len = instructions.len().saturating_mul(4);
    let mut out = Vec::with_capacity(16 + text_len + data.len());
    out.extend_from_slice(BRV1_MAGIC);
    out.extend_from_slice(&entry_pc.to_le_bytes());
    out.extend_from_slice(&(u32::try_from(text_len).unwrap_or(u32::MAX)).to_le_bytes());
    out.extend_from_slice(&(u32::try_from(data.len()).unwrap_or(u32::MAX)).to_le_bytes());
    for word in instructions {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}

#[derive(Debug)]
struct Rv32Machine {
    regs: [u32; 32],
    pc: u32,
    ram: Vec<u8>,
    gas_used: u64,
}

impl Rv32Machine {
    fn load(image: &Rv32Image) -> Self {
        let mut ram = vec![0u8; RV32_MEMORY_BYTES];
        for (base, bytes) in &image.segments {
            let start = *base as usize;
            if let Some(end) = start.checked_add(bytes.len()) {
                if let Some(dst) = ram.get_mut(start..end) {
                    dst.copy_from_slice(bytes);
                }
            }
        }
        let mut regs = [0u32; 32];
        if let Some(sp) = regs.get_mut(2) {
            *sp = INITIAL_SP;
        }
        Self {
            regs,
            pc: image.entry_pc,
            ram,
            gas_used: 0,
        }
    }

    fn read_u8(&self, addr: u32) -> Result<u8, &'static str> {
        self.ram
            .get(addr as usize)
            .copied()
            .ok_or("rv32 memory read out of bounds")
    }

    fn read_u16(&self, addr: u32) -> Result<u16, &'static str> {
        let a = addr as usize;
        let end = a.checked_add(2).ok_or("rv32 addr overflow")?;
        let slice = self.ram.get(a..end).ok_or("rv32 u16 read out of bounds")?;
        Ok(u16::from_le_bytes([slice[0], slice[1]]))
    }

    fn read_u32(&self, addr: u32) -> Result<u32, &'static str> {
        let a = addr as usize;
        let end = a.checked_add(4).ok_or("rv32 addr overflow")?;
        let slice = self.ram.get(a..end).ok_or("rv32 u32 read out of bounds")?;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    fn read_slice(&self, ptr: u32, len: u32) -> Result<&[u8], &'static str> {
        let start = ptr as usize;
        let end = start
            .checked_add(len as usize)
            .ok_or("rv32 slice overflow")?;
        self.ram.get(start..end).ok_or("rv32 slice out of bounds")
    }

    fn write_u8(&mut self, addr: u32, val: u8) -> Result<(), &'static str> {
        let slot = self
            .ram
            .get_mut(addr as usize)
            .ok_or("rv32 u8 write out of bounds")?;
        *slot = val;
        Ok(())
    }

    fn write_u16(&mut self, addr: u32, val: u16) -> Result<(), &'static str> {
        let a = addr as usize;
        let end = a.checked_add(2).ok_or("rv32 addr overflow")?;
        let dst = self
            .ram
            .get_mut(a..end)
            .ok_or("rv32 u16 write out of bounds")?;
        dst.copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn write_u32(&mut self, addr: u32, val: u32) -> Result<(), &'static str> {
        let a = addr as usize;
        let end = a.checked_add(4).ok_or("rv32 addr overflow")?;
        let dst = self
            .ram
            .get_mut(a..end)
            .ok_or("rv32 u32 write out of bounds")?;
        dst.copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn write_slice(&mut self, ptr: u32, data: &[u8]) -> Result<(), &'static str> {
        let start = ptr as usize;
        let end = start
            .checked_add(data.len())
            .ok_or("rv32 write slice overflow")?;
        let dst = self
            .ram
            .get_mut(start..end)
            .ok_or("rv32 write slice out of bounds")?;
        dst.copy_from_slice(data);
        Ok(())
    }

    fn reg(&self, idx: usize) -> u32 {
        self.regs.get(idx).copied().unwrap_or(0)
    }

    fn set_reg(&mut self, rd: usize, val: u32) {
        if rd != 0 {
            if let Some(slot) = self.regs.get_mut(rd) {
                *slot = val;
            }
        }
    }
}

fn sign_extend(val: u32, bits: u8) -> i32 {
    let shift = 32 - u32::from(bits);
    ((val << shift) as i32) >> shift
}

fn imm_i(insn: u32) -> i32 {
    sign_extend(insn >> 20, 12)
}

fn imm_s(insn: u32) -> i32 {
    let raw = ((insn >> 25) << 5) | ((insn >> 7) & 0x1f);
    sign_extend(raw, 12)
}

fn imm_b(insn: u32) -> i32 {
    let raw = (((insn >> 31) & 1) << 12)
        | (((insn >> 7) & 1) << 11)
        | (((insn >> 25) & 0x3f) << 5)
        | (((insn >> 8) & 0x0f) << 1);
    sign_extend(raw, 13)
}

fn imm_u(insn: u32) -> u32 {
    insn & 0xffff_f000
}

fn imm_j(insn: u32) -> i32 {
    let raw = (((insn >> 31) & 1) << 20)
        | (((insn >> 12) & 0xff) << 12)
        | (((insn >> 20) & 1) << 11)
        | (((insn >> 21) & 0x3ff) << 1);
    sign_extend(raw, 21)
}

fn charge_gas(
    host: &mut dyn HostApi,
    gas_used: &mut u64,
    amount: u64,
    gas_limit: u64,
) -> Option<EeOutcome> {
    if host.charge(amount).is_err() {
        return Some(EeOutcome {
            status: OutcomeStatus::OutOfGas,
            output: Vec::new(),
            gas_used: gas_limit,
        });
    }
    *gas_used = gas_used.saturating_add(amount);
    None
}

fn namespaced_slot(target: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + target.len() + key.len());
    out.extend_from_slice(b"data:");
    out.extend_from_slice(target);
    out.push(b':');
    out.extend_from_slice(key);
    out
}

/// Execute an `EeId::RV32` contract deploy or call deterministically against `host`.
///
/// # Errors
/// Returns [`EeRefusal`] only for malformed host/namespace arguments; deterministic VM
/// faults, illegal instructions, or reverts map to [`OutcomeStatus::Revert`] or
/// [`OutcomeStatus::OutOfGas`].
pub fn execute_rv32_call(
    store_ns: &Namespace,
    call: &EeCall,
    max_code_bytes: usize,
    host: &mut dyn HostApi,
) -> Result<EeOutcome, EeRefusal> {
    let map_host = |e: budlum_uel_abi::HostError| EeRefusal {
        code: RefusalCode::Denied,
        message: e.to_string(),
    };
    let mut code_key = Vec::with_capacity(6 + call.target.id.len());
    code_key.extend_from_slice(b"code:");
    code_key.push(budlum_uel_abi::EeId::RV32.0);
    code_key.extend_from_slice(&call.target.id);

    match call.kind {
        EeCallKind::Deploy => {
            let _info = validate_rv32_deploy(&call.input, max_code_bytes)?;
            let byte_gas = u64::try_from(call.input.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(RV32_PER_BYTE_GAS);
            let gas = RV32_BASE_DEPLOY_GAS.saturating_add(byte_gas);
            if host.charge(gas).is_err() {
                return Ok(EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                });
            }
            if host.read(store_ns, &code_key).map_err(map_host)?.is_some() {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"RV32 contract already deployed at target".to_vec(),
                    gas_used: gas,
                });
            }
            host.write(store_ns, &code_key, Some(&call.input))
                .map_err(map_host)?;
            Ok(EeOutcome {
                status: OutcomeStatus::Success,
                output: call.target.id.clone(),
                gas_used: gas,
            })
        }
        EeCallKind::Call => {
            let (is_static, clean_input) =
                crate::execution::coordinator::universal_call::unwrap_static_universal_input(
                    &call.input,
                );
            let byte_gas = u64::try_from(clean_input.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(RV32_PER_BYTE_GAS);
            let gas_used = RV32_BASE_CALL_GAS.saturating_add(byte_gas);
            if host.charge(gas_used).is_err() {
                return Ok(EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                });
            }
            let Some(code) = host.read(store_ns, &code_key).map_err(map_host)? else {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"RV32 contract not found".to_vec(),
                    gas_used,
                });
            };
            let Ok(image) = parse_rv32_image(&code, max_code_bytes) else {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"stored RV32 image corrupt".to_vec(),
                    gas_used,
                });
            };
            let mut vm = Rv32Machine::load(&image);
            vm.gas_used = gas_used;
            run_vm(
                &mut vm,
                store_ns,
                &call.target,
                clean_input,
                is_static,
                call.gas_limit,
                host,
            )
        }
    }
}

fn run_vm(
    vm: &mut Rv32Machine,
    store_ns: &Namespace,
    target: &EeIdentity,
    input: &[u8],
    is_static: bool,
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<EeOutcome, EeRefusal> {
    for _step in 0..MAX_RV32_STEPS {
        if let Some(oog) = charge_gas(host, &mut vm.gas_used, RV32_STEP_GAS, gas_limit) {
            return Ok(oog);
        }
        if !vm.pc.is_multiple_of(4) {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"rv32 misaligned instruction fetch".to_vec(),
                gas_used: vm.gas_used,
            });
        }
        let insn = match vm.read_u32(vm.pc) {
            Ok(w) => w,
            Err(msg) => {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: msg.as_bytes().to_vec(),
                    gas_used: vm.gas_used,
                });
            }
        };
        let opcode = insn & 0x7f;
        let rd = ((insn >> 7) & 0x1f) as usize;
        let funct3 = (insn >> 12) & 0x7;
        let rs1 = ((insn >> 15) & 0x1f) as usize;
        let rs2 = ((insn >> 20) & 0x1f) as usize;
        let funct7 = (insn >> 25) & 0x7f;
        let mut next_pc = vm.pc.wrapping_add(4);

        let step_res: Result<Option<EeOutcome>, &'static str> = (|| {
            match opcode {
                0x37 => {
                    // LUI
                    vm.set_reg(rd, imm_u(insn));
                }
                0x17 => {
                    // AUIPC
                    vm.set_reg(rd, vm.pc.wrapping_add(imm_u(insn)));
                }
                0x6f => {
                    // JAL
                    let target_pc = vm.pc.wrapping_add(imm_j(insn) as u32);
                    vm.set_reg(rd, next_pc);
                    next_pc = target_pc;
                }
                0x67 if funct3 == 0 => {
                    // JALR
                    let target_pc = vm.reg(rs1).wrapping_add(imm_i(insn) as u32) & !1;
                    vm.set_reg(rd, next_pc);
                    next_pc = target_pc;
                }
                0x63 => {
                    // Branches
                    let a = vm.reg(rs1);
                    let b = vm.reg(rs2);
                    let take = match funct3 {
                        0 => a == b,
                        1 => a != b,
                        4 => (a as i32) < (b as i32),
                        5 => (a as i32) >= (b as i32),
                        6 => a < b,
                        7 => a >= b,
                        _ => return Err("illegal branch funct3"),
                    };
                    if take {
                        next_pc = vm.pc.wrapping_add(imm_b(insn) as u32);
                    }
                }
                0x03 => {
                    // Loads
                    let addr = vm.reg(rs1).wrapping_add(imm_i(insn) as u32);
                    let val = match funct3 {
                        0 => ((vm.read_u8(addr)? as i8) as i32) as u32,
                        1 => ((vm.read_u16(addr)? as i16) as i32) as u32,
                        2 => vm.read_u32(addr)?,
                        4 => u32::from(vm.read_u8(addr)?),
                        5 => u32::from(vm.read_u16(addr)?),
                        _ => return Err("illegal load funct3"),
                    };
                    vm.set_reg(rd, val);
                }
                0x23 => {
                    // Stores
                    let addr = vm.reg(rs1).wrapping_add(imm_s(insn) as u32);
                    let val = vm.reg(rs2);
                    match funct3 {
                        0 => vm.write_u8(addr, val as u8)?,
                        1 => vm.write_u16(addr, val as u16)?,
                        2 => vm.write_u32(addr, val)?,
                        _ => return Err("illegal store funct3"),
                    }
                }
                0x13 => {
                    // OP-IMM
                    let a = vm.reg(rs1);
                    let imm = imm_i(insn);
                    let shamt = (insn >> 20) & 0x1f;
                    let val = match funct3 {
                        0 => a.wrapping_add(imm as u32),
                        1 if funct7 == 0 => a << shamt,
                        2 => u32::from((a as i32) < imm),
                        3 => u32::from(a < (imm as u32)),
                        4 => a ^ (imm as u32),
                        5 if funct7 == 0 => a >> shamt,
                        5 if funct7 == 0x20 => ((a as i32) >> shamt) as u32,
                        6 => a | (imm as u32),
                        7 => a & (imm as u32),
                        _ => return Err("illegal op-imm encoding"),
                    };
                    vm.set_reg(rd, val);
                }
                0x33 => {
                    // OP (RV32I + RV32M)
                    let a = vm.reg(rs1);
                    let b = vm.reg(rs2);
                    let val = match (funct7, funct3) {
                        (0x00, 0) => a.wrapping_add(b),
                        (0x20, 0) => a.wrapping_sub(b),
                        (0x00, 1) => a << (b & 0x1f),
                        (0x00, 2) => u32::from((a as i32) < (b as i32)),
                        (0x00, 3) => u32::from(a < b),
                        (0x00, 4) => a ^ b,
                        (0x00, 5) => a >> (b & 0x1f),
                        (0x20, 5) => ((a as i32) >> (b & 0x1f)) as u32,
                        (0x00, 6) => a | b,
                        (0x00, 7) => a & b,
                        // M-extension (funct7 == 0x01)
                        (0x01, 0) => a.wrapping_mul(b),
                        (0x01, 1) => ((i64::from(a as i32) * i64::from(b as i32)) >> 32) as u32,
                        (0x01, 2) => ((i64::from(a as i32) * i64::from(b)) >> 32) as u32,
                        (0x01, 3) => ((u64::from(a) * u64::from(b)) >> 32) as u32,
                        (0x01, 4) => {
                            let sa = a as i32;
                            let sb = b as i32;
                            if sb == 0 {
                                u32::MAX
                            } else {
                                sa.wrapping_div(sb) as u32
                            }
                        }
                        (0x01, 5) => a.checked_div(b).unwrap_or(u32::MAX),
                        (0x01, 6) => {
                            let sa = a as i32;
                            let sb = b as i32;
                            if sb == 0 {
                                a
                            } else if sa == i32::MIN && sb == -1 {
                                0
                            } else {
                                sa.wrapping_rem(sb) as u32
                            }
                        }
                        (0x01, 7) => a.checked_rem(b).unwrap_or(a),
                        _ => return Err("illegal op encoding"),
                    };
                    vm.set_reg(rd, val);
                }
                0x0f => {
                    // FENCE: deterministic single-hart no-op
                }
                0x73 if insn == 0x0000_0073 => {
                    // ECALL Host ABI
                    if let Some(oog) = charge_gas(host, &mut vm.gas_used, RV32_ECALL_GAS, gas_limit)
                    {
                        return Ok(Some(oog));
                    }
                    let outcome = handle_ecall(vm, store_ns, target, input, is_static, host)?;
                    if outcome.is_some() {
                        return Ok(outcome);
                    }
                }
                0x73 if insn == 0x0010_0073 => {
                    // EBREAK -> clean revert
                    return Ok(Some(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"rv32 ebreak".to_vec(),
                        gas_used: vm.gas_used,
                    }));
                }
                _ => return Err("illegal rv32 opcode"),
            }
            Ok(None)
        })();

        match step_res {
            Ok(Some(outcome)) => return Ok(outcome),
            Ok(None) => vm.pc = next_pc,
            Err(msg) => {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: msg.as_bytes().to_vec(),
                    gas_used: vm.gas_used,
                });
            }
        }
    }

    Ok(EeOutcome {
        status: OutcomeStatus::OutOfGas,
        output: b"rv32 max step limit reached".to_vec(),
        gas_used: vm.gas_used,
    })
}

fn handle_ecall(
    vm: &mut Rv32Machine,
    store_ns: &Namespace,
    target: &EeIdentity,
    input: &[u8],
    is_static: bool,
    host: &mut dyn HostApi,
) -> Result<Option<EeOutcome>, &'static str> {
    let call_num = vm.reg(17); // a7
    let a0 = vm.reg(10);
    let a1 = vm.reg(11);
    let a2 = vm.reg(12);
    let a3 = vm.reg(13);
    let a4 = vm.reg(14);
    let a5 = vm.reg(15);

    match call_num {
        syscall::EXIT_OK => {
            if a1 > 65_536 {
                return Err("rv32 return buffer exceeds 64 KiB");
            }
            let out = vm.read_slice(a0, a1)?.to_vec();
            Ok(Some(EeOutcome {
                status: OutcomeStatus::Success,
                output: out,
                gas_used: vm.gas_used,
            }))
        }
        syscall::REVERT => {
            let capped = a1.min(65_536);
            let out = vm.read_slice(a0, capped)?.to_vec();
            Ok(Some(EeOutcome {
                status: OutcomeStatus::Revert,
                output: out,
                gas_used: vm.gas_used,
            }))
        }
        syscall::INPUT_LEN => {
            vm.set_reg(10, u32::try_from(input.len()).unwrap_or(u32::MAX));
            Ok(None)
        }
        syscall::READ_INPUT => {
            let off = a1 as usize;
            let len = a2 as usize;
            let slice = input
                .get(off..off.saturating_add(len).min(input.len()))
                .unwrap_or(&[]);
            vm.write_slice(a0, slice)?;
            vm.set_reg(10, u32::try_from(slice.len()).unwrap_or(u32::MAX));
            Ok(None)
        }
        syscall::STORAGE_READ => {
            if a1 > 1024 {
                return Err("rv32 key too large");
            }
            let key = vm.read_slice(a0, a1)?;
            let slot_key = namespaced_slot(&target.id, key);
            match host.read(store_ns, &slot_key) {
                Ok(Some(val)) => {
                    let copy_len = (a3 as usize).min(val.len());
                    if let Some(chunk) = val.get(..copy_len) {
                        vm.write_slice(a2, chunk)?;
                    }
                    vm.set_reg(10, u32::try_from(val.len()).unwrap_or(u32::MAX));
                    Ok(None)
                }
                Ok(None) => {
                    vm.set_reg(10, u32::MAX);
                    Ok(None)
                }
                Err(_) => Err("rv32 host read refused"),
            }
        }
        syscall::STORAGE_WRITE => {
            if is_static {
                return Err("rv32 storage write forbidden in static call");
            }
            if a1 > 1024 {
                return Err("rv32 key too large");
            }
            let key = vm.read_slice(a0, a1)?.to_vec();
            let slot_key = namespaced_slot(&target.id, &key);
            if a3 == u32::MAX {
                host.write(store_ns, &slot_key, None)
                    .map_err(|_| "rv32 host delete refused")?;
            } else {
                if a3 > 65_536 {
                    return Err("rv32 value too large");
                }
                let val = vm.read_slice(a2, a3)?.to_vec();
                host.write(store_ns, &slot_key, Some(&val))
                    .map_err(|_| "rv32 host write refused")?;
            }
            vm.set_reg(10, 0);
            Ok(None)
        }
        syscall::EMIT_LOG => {
            if is_static {
                return Err("rv32 log forbidden in static call");
            }
            if a1 > 16_384 {
                return Err("rv32 log exceeds 16 KiB");
            }
            let data = vm.read_slice(a0, a1)?.to_vec();
            host.emit_log(EeLog {
                emitter: target.clone(),
                topics: Vec::new(),
                data,
            })
            .map_err(|_| "rv32 host emit_log refused")?;
            vm.set_reg(10, 0);
            Ok(None)
        }
        syscall::BUD_BALANCE => {
            let addr_bytes = vm.read_slice(a0, 32)?.to_vec();
            let who = EeIdentity::new(budlum_uel_abi::EeId::RV32, addr_bytes)
                .map_err(|_| "rv32 invalid identity")?;
            let bal = host
                .bud_balance(&who)
                .map_err(|_| "rv32 host bud_balance refused")?;
            vm.write_slice(a1, &bal.0.to_le_bytes())?;
            vm.set_reg(10, 0);
            Ok(None)
        }
        syscall::UNIVERSAL_CALL => {
            if a2 > 128 || a4 > 16_384 {
                return Err("rv32 universal_call argument too large");
            }
            let ee_byte = u8::try_from(a0).map_err(|_| "invalid ee id")?;
            let callee_id = vm.read_slice(a1, a2)?.to_vec();
            let call_input = vm.read_slice(a3, a4)?.to_vec();
            let out_ptr = a5;
            let out_cap = vm.reg(16); // t1
            let callee_ident = EeIdentity::new(budlum_uel_abi::EeId(ee_byte), callee_id)
                .map_err(|_| "invalid callee identity")?;
            let res = host
                .universal_call(budlum_uel_abi::UniversalCall {
                    from: target.clone(),
                    to_ee: budlum_uel_abi::EeId(ee_byte),
                    target: callee_ident,
                    value: budlum_uel_abi::BudAmount(0),
                    input: call_input,
                    gas_limit: 50_000,
                    is_static,
                })
                .map_err(|_| "rv32 universal_call refused")?;
            let copy_len = (out_cap as usize).min(res.output.len());
            if let Some(chunk) = res.output.get(..copy_len) {
                if !chunk.is_empty() {
                    vm.write_slice(out_ptr, chunk)?;
                }
            }
            vm.set_reg(10, u32::try_from(res.output.len()).unwrap_or(u32::MAX));
            Ok(None)
        }
        _ => Err("unknown rv32 syscall"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budlum_uel_abi::{BudAmount, EeId, HostError, OutOfGas, UniversalCall, UniversalResult};
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MockHost {
        kv: BTreeMap<(String, Vec<u8>), Vec<u8>>,
        logs: Vec<EeLog>,
        gas_left: u64,
    }

    impl budlum_uel_abi::HostRead for MockHost {
        fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
            Ok(self
                .kv
                .get(&(ns.as_str().to_string(), key.to_vec()))
                .cloned())
        }
        fn bud_balance(&self, _who: &EeIdentity) -> Result<BudAmount, HostError> {
            Ok(BudAmount(42_000))
        }
    }

    impl HostApi for MockHost {
        fn write(
            &mut self,
            ns: &Namespace,
            key: &[u8],
            value: Option<&[u8]>,
        ) -> Result<(), HostError> {
            match value {
                Some(v) => {
                    self.kv
                        .insert((ns.as_str().to_string(), key.to_vec()), v.to_vec());
                }
                None => {
                    self.kv.remove(&(ns.as_str().to_string(), key.to_vec()));
                }
            }
            Ok(())
        }
        fn universal_call(&mut self, _call: UniversalCall) -> Result<UniversalResult, HostError> {
            Ok(UniversalResult {
                success: true,
                output: b"pong".to_vec(),
                gas_used: 100,
            })
        }
        fn emit_log(&mut self, log: EeLog) -> Result<(), HostError> {
            self.logs.push(log);
            Ok(())
        }
        fn charge(&mut self, bgu: u64) -> Result<(), OutOfGas> {
            if self.gas_left < bgu {
                return Err(OutOfGas);
            }
            self.gas_left -= bgu;
            Ok(())
        }
        fn bud_transfer(
            &mut self,
            _: &EeIdentity,
            _: &EeIdentity,
            _: u128,
        ) -> Result<(), HostError> {
            Ok(())
        }
    }

    const fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
        (((imm as u32) & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x13
    }
    const fn mul(rd: u32, rs1: u32, rs2: u32) -> u32 {
        (0x01 << 25) | (rs2 << 20) | (rs1 << 15) | (rd << 7) | 0x33
    }
    const fn sw(rs1: u32, rs2: u32, imm: i32) -> u32 {
        let u = imm as u32;
        (((u >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15) | (2 << 12) | ((u & 0x1f) << 7) | 0x23
    }
    const fn lui(rd: u32, imm20: u32) -> u32 {
        (imm20 << 12) | (rd << 7) | 0x37
    }
    const fn ecall() -> u32 {
        0x0000_0073
    }

    #[test]
    fn rv32im_executes_arithmetic_store_ecall_and_returns_exact_bytes() {
        // Computes 6 * 7 = 42, stores 42 at BRV1_DATA_BASE (0x10000), calls EXIT_OK(0x10000, 4).
        let program = encode_brv1_image(
            0,
            &[
                addi(10, 0, 6),  // x10 = 6
                addi(11, 0, 7),  // x11 = 7
                mul(12, 10, 11), // x12 = 42
                lui(13, 0x10),   // x13 = 0x10000
                sw(13, 12, 0),   // *0x10000 = 42
                addi(10, 13, 0), // a0 = 0x10000
                addi(11, 0, 4),  // a1 = 4
                addi(17, 0, 0),  // a7 = EXIT_OK
                ecall(),
            ],
            &[],
        );
        let ns = Namespace::new("ee/rv32/state").unwrap();
        let target = EeIdentity {
            ee: EeId::RV32,
            id: vec![1, 2, 3, 4],
        };
        let mut host = MockHost {
            gas_left: 500_000,
            ..Default::default()
        };

        let deploy = execute_rv32_call(
            &ns,
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: EeIdentity {
                    ee: EeId::RV32,
                    id: vec![0; 32],
                },
                target: target.clone(),
                value: BudAmount(0),
                input: program,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0; 32],
            },
            524_288,
            &mut host,
        )
        .unwrap();
        assert_eq!(deploy.status, OutcomeStatus::Success);

        let call = execute_rv32_call(
            &ns,
            &EeCall {
                kind: EeCallKind::Call,
                caller: EeIdentity {
                    ee: EeId::RV32,
                    id: vec![0; 32],
                },
                target,
                value: BudAmount(0),
                input: Vec::new(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0; 32],
            },
            524_288,
            &mut host,
        )
        .unwrap();
        assert_eq!(call.status, OutcomeStatus::Success);
        assert_eq!(call.output, 42u32.to_le_bytes());
    }

    #[test]
    fn rv32im_div_by_zero_and_bad_elf_fail_deterministically_without_panicking() {
        assert!(parse_rv32_image(b"BAD_MAGIC_BYTES_1234", 524_288).is_err());

        // DIV x12, x10, x0 -> RISC-V defines division by zero as 0xffff_ffff.
        let div_u32 = (0x01 << 25) | (10 << 15) | (4 << 12) | (12 << 7) | 0x33;
        let program = encode_brv1_image(
            0,
            &[
                addi(10, 0, 99),
                div_u32,
                lui(13, 0x10),
                sw(13, 12, 0),
                addi(10, 13, 0),
                addi(11, 0, 4),
                addi(17, 0, 0),
                ecall(),
            ],
            &[],
        );
        let ns = Namespace::new("ee/rv32/state").unwrap();
        let target = EeIdentity {
            ee: EeId::RV32,
            id: vec![9; 4],
        };
        let mut host = MockHost {
            gas_left: 500_000,
            ..Default::default()
        };
        execute_rv32_call(
            &ns,
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: EeIdentity {
                    ee: EeId::RV32,
                    id: vec![0; 32],
                },
                target: target.clone(),
                value: BudAmount(0),
                input: program,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0; 32],
            },
            524_288,
            &mut host,
        )
        .unwrap();
        let call = execute_rv32_call(
            &ns,
            &EeCall {
                kind: EeCallKind::Call,
                caller: EeIdentity {
                    ee: EeId::RV32,
                    id: vec![0; 32],
                },
                target,
                value: BudAmount(0),
                input: Vec::new(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0; 32],
            },
            524_288,
            &mut host,
        )
        .unwrap();
        assert_eq!(call.status, OutcomeStatus::Success);
        assert_eq!(call.output, u32::MAX.to_le_bytes());
    }
}
