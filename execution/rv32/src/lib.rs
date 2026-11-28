//! Out-of-process deterministic RISC-V 32IM (`RV32I + M`) UEL execution worker
//! (`EeId::RV32 = 0x0C`).
//!
//! Parses both compact `BRV1` images and 32-bit little-endian RISC-V `ELF` binaries
//! (`e_machine = 0xF3`), executes deterministically with `x0 == 0`, strict memory bounds,
//! cycle-accurate BGU gas metering, and Budlum Host ABI syscalls, while enforcing
//! `expansion_environment_enabled_by_default(ctx.chain_id)` fail-closed gating.

#![forbid(unsafe_code)]

use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, Namespace,
    OutcomeStatus, RefusalCode, UniversalCall,
};
use sha2::{Digest as _, Sha256};

/// Canonical UEL namespace storing RV32 code blobs and contract state.
pub const NS_RV32_STATE: &str = "ee/rv32/state";

/// Compact RV32 binary magic (`"BRV1"`).
pub const BRV1_MAGIC: &[u8; 4] = b"BRV1";

/// ELF magic bytes.
pub const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

/// Maximum RV32 image size accepted at deployment (`512 KiB`).
pub const MAX_RV32_IMAGE_BYTES: usize = 512 * 1024;

/// Virtual RAM size per VM execution (`1 MiB`).
pub const RV32_MEMORY_BYTES: usize = 1024 * 1024;

/// Maximum deterministic VM steps per call.
pub const MAX_RV32_STEPS: u64 = 250_000;

const BASE_DEPLOY_GAS: u64 = 20_000;
const BASE_CALL_GAS: u64 = 5_000;
const PER_BYTE_GAS: u64 = 16;
const STEP_GAS: u64 = 1;
const ECALL_GAS: u64 = 50;
const INITIAL_SP: u32 = (RV32_MEMORY_BYTES as u32) - 16;
const BRV1_DATA_BASE: usize = 65_536;

/// Worker state for `EeId::RV32`.
#[derive(Debug, Default)]
pub struct Rv32Worker;

impl Rv32Worker {
    /// Construct a fresh stateless worker (all state persists in coordinator `HostApi`).
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone)]
struct ParsedRv32Image {
    entry_pc: u32,
    segments: Vec<(u32, Vec<u8>)>,
    code_hash: [u8; 32],
}

fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    let slice = bytes.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let slice = bytes.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn parse_image(code: &[u8]) -> Result<ParsedRv32Image, EeRefusal> {
    if code.len() < 16 || code.len() > MAX_RV32_IMAGE_BYTES {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("RV32 image size out of bounds"),
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
            message: String::from("BRV1 missing text_len"),
        })? as usize;
        let data_len = read_u32_le(code, 12).ok_or_else(|| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("BRV1 missing data_len"),
        })? as usize;
        let total = 16usize
            .checked_add(text_len)
            .and_then(|v| v.checked_add(data_len))
            .ok_or_else(|| EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("BRV1 section length overflow"),
            })?;
        if total != code.len()
            || text_len == 0
            || !text_len.is_multiple_of(4)
            || (entry_pc as usize) >= text_len
            || text_len > BRV1_DATA_BASE
            || BRV1_DATA_BASE.saturating_add(data_len) > RV32_MEMORY_BYTES
            || !entry_pc.is_multiple_of(4)
        {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("BRV1 layout invalid"),
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
                message: String::from("BRV1 text out of bounds"),
            })?
            .to_vec();
        let data = code
            .get(text_end..)
            .ok_or_else(|| EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("BRV1 data out of bounds"),
            })?
            .to_vec();
        let mut segments = vec![(0u32, text)];
        if !data.is_empty() {
            segments.push((BRV1_DATA_BASE as u32, data));
        }
        return Ok(ParsedRv32Image {
            entry_pc,
            segments,
            code_hash,
        });
    }

    if code.starts_with(ELF_MAGIC) {
        if code.len() < 52
            || code.get(4) != Some(&1)
            || code.get(5) != Some(&1)
            || read_u16_le(code, 18) != Some(0xF3)
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
        if phentsize < 32
            || phnum == 0
            || phnum > 32
            || (entry_pc as usize) >= RV32_MEMORY_BYTES
            || !entry_pc.is_multiple_of(4)
        {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("ELF header invalid"),
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
                message: String::from("ELF phdr truncated"),
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
                message: String::from("ELF file end overflow"),
            })?;
            let mem_end = (p_vaddr as usize)
                .checked_add(p_memsz)
                .ok_or_else(|| EeRefusal {
                    code: RefusalCode::InvalidCode,
                    message: String::from("ELF memory end overflow"),
                })?;
            if file_end > code.len() || mem_end > RV32_MEMORY_BYTES {
                return Err(EeRefusal {
                    code: RefusalCode::InvalidCode,
                    message: String::from("ELF PT_LOAD out of bounds"),
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
        if segments.is_empty() {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("ELF has no loadable segments"),
            });
        }
        return Ok(ParsedRv32Image {
            entry_pc,
            segments,
            code_hash,
        });
    }

    Err(EeRefusal {
        code: RefusalCode::InvalidCode,
        message: String::from("RV32 image must use BRV1 or ELF magic"),
    })
}

/// Encode a compact `BRV1` RV32IM program image from 32-bit machine instructions and initial `.data`.
#[must_use]
pub fn encode_brv1_image(entry_pc: u32, instructions: &[u32], data: &[u8]) -> Vec<u8> {
    let text_len = instructions.len().saturating_mul(4);
    let mut out = Vec::with_capacity(16 + text_len + data.len());
    out.extend_from_slice(BRV1_MAGIC);
    out.extend_from_slice(&entry_pc.to_le_bytes());
    out.extend_from_slice(&u32::try_from(text_len).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes());
    for word in instructions {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}

struct Vm {
    regs: [u32; 32],
    pc: u32,
    ram: Vec<u8>,
    gas_used: u64,
}

impl Vm {
    fn load(image: &ParsedRv32Image) -> Self {
        let mut ram = vec![0u8; RV32_MEMORY_BYTES];
        for (base, seg) in &image.segments {
            let start = *base as usize;
            if let Some(end) = start.checked_add(seg.len()) {
                if let Some(dst) = ram.get_mut(start..end) {
                    dst.copy_from_slice(seg);
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
            .ok_or("rv32 read_u8 out of bounds")
    }

    fn read_u16(&self, addr: u32) -> Result<u16, &'static str> {
        let a = addr as usize;
        let end = a.checked_add(2).ok_or("rv32 addr overflow")?;
        let s = self.ram.get(a..end).ok_or("rv32 read_u16 out of bounds")?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    fn read_u32(&self, addr: u32) -> Result<u32, &'static str> {
        let a = addr as usize;
        let end = a.checked_add(4).ok_or("rv32 addr overflow")?;
        let s = self.ram.get(a..end).ok_or("rv32 read_u32 out of bounds")?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_slice(&self, ptr: u32, len: u32) -> Result<&[u8], &'static str> {
        let start = ptr as usize;
        let end = start.checked_add(len as usize).ok_or("rv32 len overflow")?;
        self.ram.get(start..end).ok_or("rv32 slice out of bounds")
    }

    fn write_u8(&mut self, addr: u32, val: u8) -> Result<(), &'static str> {
        let slot = self
            .ram
            .get_mut(addr as usize)
            .ok_or("rv32 write_u8 out of bounds")?;
        *slot = val;
        Ok(())
    }

    fn write_u16(&mut self, addr: u32, val: u16) -> Result<(), &'static str> {
        let a = addr as usize;
        let end = a.checked_add(2).ok_or("rv32 addr overflow")?;
        let dst = self
            .ram
            .get_mut(a..end)
            .ok_or("rv32 write_u16 out of bounds")?;
        dst.copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn write_u32(&mut self, addr: u32, val: u32) -> Result<(), &'static str> {
        let a = addr as usize;
        let end = a.checked_add(4).ok_or("rv32 addr overflow")?;
        let dst = self
            .ram
            .get_mut(a..end)
            .ok_or("rv32 write_u32 out of bounds")?;
        dst.copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn write_slice(&mut self, ptr: u32, data: &[u8]) -> Result<(), &'static str> {
        let start = ptr as usize;
        let end = start.checked_add(data.len()).ok_or("rv32 len overflow")?;
        let dst = self
            .ram
            .get_mut(start..end)
            .ok_or("rv32 write_slice out of bounds")?;
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
    sign_extend(((insn >> 25) << 5) | ((insn >> 7) & 0x1f), 12)
}

fn imm_b(insn: u32) -> i32 {
    let raw = (((insn >> 31) & 1) << 12)
        | (((insn >> 7) & 1) << 11)
        | (((insn >> 25) & 0x3f) << 5)
        | (((insn >> 8) & 0x0f) << 1);
    sign_extend(raw, 13)
}

fn imm_j(insn: u32) -> i32 {
    let raw = (((insn >> 31) & 1) << 20)
        | (((insn >> 12) & 0xff) << 12)
        | (((insn >> 20) & 1) << 11)
        | (((insn >> 21) & 0x3ff) << 1);
    sign_extend(raw, 21)
}

fn code_key(id: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(6 + id.len());
    k.extend_from_slice(b"code:");
    k.push(EeId::RV32.0);
    k.extend_from_slice(id);
    k
}

fn data_key(id: &[u8], slot: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(6 + id.len() + slot.len());
    k.extend_from_slice(b"data:");
    k.extend_from_slice(id);
    k.push(b':');
    k.extend_from_slice(slot);
    k
}

fn ns_rv32() -> Result<Namespace, EeRefusal> {
    Namespace::new(NS_RV32_STATE).map_err(|e| EeRefusal {
        code: RefusalCode::InvalidCode,
        message: e.to_string(),
    })
}

fn check_open(ctx: &BlockContext) -> Result<(), EeRefusal> {
    if budlum_uel_abi::expansion_environment_enabled_by_default(ctx.chain_id) {
        return Ok(());
    }
    Err(EeRefusal {
        code: RefusalCode::Denied,
        message: format!(
            "RV32 execution environment is closed on chain {}",
            ctx.chain_id
        ),
    })
}

fn unwrap_static(input: &[u8]) -> (bool, &[u8]) {
    if let Some(rest) = input.strip_prefix(b"\0STATIC:") {
        (true, rest)
    } else {
        (false, input)
    }
}

fn run_vm(
    vm: &mut Vm,
    store_ns: &Namespace,
    target: &EeIdentity,
    input: &[u8],
    is_static: bool,
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> EeOutcome {
    for _step in 0..MAX_RV32_STEPS {
        if host.charge(STEP_GAS).is_err() {
            return EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: gas_limit,
            };
        }
        vm.gas_used = vm.gas_used.saturating_add(STEP_GAS);
        if !vm.pc.is_multiple_of(4) {
            return EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"rv32 misaligned pc".to_vec(),
                gas_used: vm.gas_used,
            };
        }
        let insn = match vm.read_u32(vm.pc) {
            Ok(w) => w,
            Err(e) => {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: e.as_bytes().to_vec(),
                    gas_used: vm.gas_used,
                };
            }
        };
        let opcode = insn & 0x7f;
        let rd = ((insn >> 7) & 0x1f) as usize;
        let funct3 = (insn >> 12) & 0x7;
        let rs1 = ((insn >> 15) & 0x1f) as usize;
        let rs2 = ((insn >> 20) & 0x1f) as usize;
        let funct7 = (insn >> 25) & 0x7f;
        let mut next_pc = vm.pc.wrapping_add(4);

        let res: Result<Option<EeOutcome>, &'static str> = (|| {
            match opcode {
                0x37 => vm.set_reg(rd, insn & 0xffff_f000),
                0x17 => vm.set_reg(rd, vm.pc.wrapping_add(insn & 0xffff_f000)),
                0x6f => {
                    let tgt = vm.pc.wrapping_add(imm_j(insn) as u32);
                    vm.set_reg(rd, next_pc);
                    next_pc = tgt;
                }
                0x67 if funct3 == 0 => {
                    let tgt = vm.reg(rs1).wrapping_add(imm_i(insn) as u32) & !1;
                    vm.set_reg(rd, next_pc);
                    next_pc = tgt;
                }
                0x63 => {
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
                    let addr = vm.reg(rs1).wrapping_add(imm_i(insn) as u32);
                    let v = match funct3 {
                        0 => ((vm.read_u8(addr)? as i8) as i32) as u32,
                        1 => ((vm.read_u16(addr)? as i16) as i32) as u32,
                        2 => vm.read_u32(addr)?,
                        4 => u32::from(vm.read_u8(addr)?),
                        5 => u32::from(vm.read_u16(addr)?),
                        _ => return Err("illegal load funct3"),
                    };
                    vm.set_reg(rd, v);
                }
                0x23 => {
                    let addr = vm.reg(rs1).wrapping_add(imm_s(insn) as u32);
                    let v = vm.reg(rs2);
                    match funct3 {
                        0 => vm.write_u8(addr, v as u8)?,
                        1 => vm.write_u16(addr, v as u16)?,
                        2 => vm.write_u32(addr, v)?,
                        _ => return Err("illegal store funct3"),
                    }
                }
                0x13 => {
                    let a = vm.reg(rs1);
                    let imm = imm_i(insn);
                    let shamt = (insn >> 20) & 0x1f;
                    let v = match funct3 {
                        0 => a.wrapping_add(imm as u32),
                        1 if funct7 == 0 => a << shamt,
                        2 => u32::from((a as i32) < imm),
                        3 => u32::from(a < (imm as u32)),
                        4 => a ^ (imm as u32),
                        5 if funct7 == 0 => a >> shamt,
                        5 if funct7 == 0x20 => ((a as i32) >> shamt) as u32,
                        6 => a | (imm as u32),
                        7 => a & (imm as u32),
                        _ => return Err("illegal op-imm"),
                    };
                    vm.set_reg(rd, v);
                }
                0x33 => {
                    let a = vm.reg(rs1);
                    let b = vm.reg(rs2);
                    let v = match (funct7, funct3) {
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
                        _ => return Err("illegal op"),
                    };
                    vm.set_reg(rd, v);
                }
                0x0f => {}
                0x73 if insn == 0x0000_0073 => {
                    if host.charge(ECALL_GAS).is_err() {
                        return Ok(Some(EeOutcome {
                            status: OutcomeStatus::OutOfGas,
                            output: Vec::new(),
                            gas_used: gas_limit,
                        }));
                    }
                    vm.gas_used = vm.gas_used.saturating_add(ECALL_GAS);
                    let a0 = vm.reg(10);
                    let a1 = vm.reg(11);
                    let a2 = vm.reg(12);
                    let a3 = vm.reg(13);
                    let a4 = vm.reg(14);
                    let a5 = vm.reg(15);
                    match vm.reg(17) {
                        0 => {
                            if a1 > 65_536 {
                                return Err("return too large");
                            }
                            return Ok(Some(EeOutcome {
                                status: OutcomeStatus::Success,
                                output: vm.read_slice(a0, a1)?.to_vec(),
                                gas_used: vm.gas_used,
                            }));
                        }
                        1 => {
                            let len = a1.min(65_536);
                            return Ok(Some(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: vm.read_slice(a0, len)?.to_vec(),
                                gas_used: vm.gas_used,
                            }));
                        }
                        2 => vm.set_reg(10, u32::try_from(input.len()).unwrap_or(u32::MAX)),
                        3 => {
                            let off = a1 as usize;
                            let slice = input
                                .get(off..off.saturating_add(a2 as usize).min(input.len()))
                                .unwrap_or(&[]);
                            vm.write_slice(a0, slice)?;
                            vm.set_reg(10, u32::try_from(slice.len()).unwrap_or(u32::MAX));
                        }
                        4 => {
                            if a1 > 1024 {
                                return Err("key too large");
                            }
                            let key = vm.read_slice(a0, a1)?;
                            let slot = data_key(&target.id, key);
                            match host.read(store_ns, &slot).map_err(|_| "host read failed")? {
                                Some(val) => {
                                    let copy = (a3 as usize).min(val.len());
                                    if let Some(chunk) = val.get(..copy) {
                                        vm.write_slice(a2, chunk)?;
                                    }
                                    vm.set_reg(10, u32::try_from(val.len()).unwrap_or(u32::MAX));
                                }
                                None => vm.set_reg(10, u32::MAX),
                            }
                        }
                        5 => {
                            if is_static {
                                return Err("write in static call");
                            }
                            if a1 > 1024 {
                                return Err("key too large");
                            }
                            let key = vm.read_slice(a0, a1)?.to_vec();
                            let slot = data_key(&target.id, &key);
                            if a3 == u32::MAX {
                                host.write(store_ns, &slot, None)
                                    .map_err(|_| "host delete failed")?;
                            } else {
                                if a3 > 65_536 {
                                    return Err("val too large");
                                }
                                let val = vm.read_slice(a2, a3)?.to_vec();
                                host.write(store_ns, &slot, Some(&val))
                                    .map_err(|_| "host write failed")?;
                            }
                            vm.set_reg(10, 0);
                        }
                        6 => {
                            if is_static {
                                return Err("log in static call");
                            }
                            if a1 > 16_384 {
                                return Err("log too large");
                            }
                            let data = vm.read_slice(a0, a1)?.to_vec();
                            host.emit_log(EeLog {
                                emitter: target.clone(),
                                topics: Vec::new(),
                                data,
                            })
                            .map_err(|_| "emit_log failed")?;
                            vm.set_reg(10, 0);
                        }
                        7 => {
                            let addr = vm.read_slice(a0, 32)?.to_vec();
                            let who = EeIdentity::new(EeId::RV32, addr)
                                .map_err(|_| "invalid identity")?;
                            let bal = host.bud_balance(&who).map_err(|_| "bud_balance failed")?;
                            vm.write_slice(a1, &bal.0.to_le_bytes())?;
                            vm.set_reg(10, 0);
                        }
                        8 => {
                            if a2 > 128 || a4 > 16_384 {
                                return Err("universal_call args too large");
                            }
                            let ee_id = u8::try_from(a0).map_err(|_| "bad ee")?;
                            let callee = vm.read_slice(a1, a2)?.to_vec();
                            let inp = vm.read_slice(a3, a4)?.to_vec();
                            let out_cap = vm.reg(16) as usize;
                            let callee_ident = EeIdentity::new(EeId(ee_id), callee)
                                .map_err(|_| "bad callee identity")?;
                            let res = host
                                .universal_call(UniversalCall {
                                    from: target.clone(),
                                    to_ee: EeId(ee_id),
                                    target: callee_ident,
                                    value: BudAmount(0),
                                    input: inp,
                                    gas_limit: 50_000,
                                    is_static,
                                })
                                .map_err(|_| "universal_call refused")?;
                            let copy = out_cap.min(res.output.len());
                            if let Some(chunk) = res.output.get(..copy) {
                                if !chunk.is_empty() {
                                    vm.write_slice(a5, chunk)?;
                                }
                            }
                            vm.set_reg(10, u32::try_from(res.output.len()).unwrap_or(u32::MAX));
                        }
                        _ => return Err("unknown syscall"),
                    }
                }
                0x73 if insn == 0x0010_0073 => {
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

        match res {
            Ok(Some(out)) => return out,
            Ok(None) => vm.pc = next_pc,
            Err(msg) => {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: msg.as_bytes().to_vec(),
                    gas_used: vm.gas_used,
                };
            }
        }
    }

    EeOutcome {
        status: OutcomeStatus::OutOfGas,
        output: b"rv32 max steps exceeded".to_vec(),
        gas_used: vm.gas_used,
    }
}

impl ExecutionEnvironment for Rv32Worker {
    fn id(&self) -> EeId {
        EeId::RV32
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        let parsed = parse_image(code)?;
        Ok(CodeInfo {
            code_hash: parsed.code_hash,
            abi_tag: String::from("rv32im-host-v1"),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        if let Err(refusal) = check_open(ctx) {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: refusal.message.into_bytes(),
                gas_used: 0,
            });
        }
        let store_ns = match ns_rv32() {
            Ok(n) => n,
            Err(refusal) => {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: refusal.message.into_bytes(),
                    gas_used: 0,
                });
            }
        };
        let ckey = code_key(&call.target.id);
        match call.kind {
            EeCallKind::Deploy => {
                if let Err(refusal) = parse_image(&call.input) {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: refusal.message.into_bytes(),
                        gas_used: 0,
                    });
                }
                let gas = BASE_DEPLOY_GAS.saturating_add(
                    u64::try_from(call.input.len())
                        .unwrap_or(u64::MAX)
                        .saturating_mul(PER_BYTE_GAS),
                );
                if host.charge(gas).is_err() {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                }
                if host
                    .read(&store_ns, &ckey)
                    .map_err(|e| EeFault {
                        ee: EeId::RV32,
                        panic_digest: budlum_uel_abi::host::panic_digest(
                            EeId::RV32,
                            &e.to_string(),
                        ),
                    })?
                    .is_some()
                {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"RV32 contract already deployed".to_vec(),
                        gas_used: gas,
                    });
                }
                host.write(&store_ns, &ckey, Some(&call.input))
                    .map_err(|e| EeFault {
                        ee: EeId::RV32,
                        panic_digest: budlum_uel_abi::host::panic_digest(
                            EeId::RV32,
                            &e.to_string(),
                        ),
                    })?;
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: call.target.id.clone(),
                    gas_used: gas,
                })
            }
            EeCallKind::Call => {
                let (is_static, clean_input) = unwrap_static(&call.input);
                let gas = BASE_CALL_GAS.saturating_add(
                    u64::try_from(clean_input.len())
                        .unwrap_or(u64::MAX)
                        .saturating_mul(PER_BYTE_GAS),
                );
                if host.charge(gas).is_err() {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                }
                let code = match host.read(&store_ns, &ckey) {
                    Ok(Some(c)) => c,
                    Ok(None) => {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"RV32 contract not found".to_vec(),
                            gas_used: gas,
                        });
                    }
                    Err(e) => {
                        return Err(EeFault {
                            ee: EeId::RV32,
                            panic_digest: budlum_uel_abi::host::panic_digest(
                                EeId::RV32,
                                &e.to_string(),
                            ),
                        });
                    }
                };
                let Ok(img) = parse_image(&code) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"stored RV32 image invalid".to_vec(),
                        gas_used: gas,
                    });
                };
                let mut vm = Vm::load(&img);
                vm.gas_used = gas;
                Ok(run_vm(
                    &mut vm,
                    &store_ns,
                    &call.target,
                    clean_input,
                    is_static,
                    call.gas_limit,
                    host,
                ))
            }
        }
    }

    fn query(
        &self,
        ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        check_open(ctx)?;
        let store_ns = ns_rv32()?;
        let slot = data_key(&q.target.id, &q.input);
        host.read(&store_ns, &slot)
            .map(Option::unwrap_or_default)
            .map_err(|e| EeRefusal {
                code: RefusalCode::Denied,
                message: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budlum_uel_abi::{BudAmount, HostError, OutOfGas, UniversalResult};
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct TestHost {
        kv: BTreeMap<(String, Vec<u8>), Vec<u8>>,
        logs: Vec<EeLog>,
        gas_left: u64,
    }

    impl HostRead for TestHost {
        fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
            Ok(self
                .kv
                .get(&(ns.as_str().to_string(), key.to_vec()))
                .cloned())
        }
        fn bud_balance(&self, _who: &EeIdentity) -> Result<BudAmount, HostError> {
            Ok(BudAmount(99_999))
        }
    }

    impl HostApi for TestHost {
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
                output: b"ok".to_vec(),
                gas_used: 50,
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
    fn rv32_is_closed_on_testnet() {
        let mut worker = Rv32Worker::new();
        let target = EeIdentity {
            ee: EeId::RV32,
            id: vec![7; 4],
        };
        let prog = encode_brv1_image(
            0,
            &[
                addi(10, 0, 9),
                addi(11, 0, 11),
                mul(12, 10, 11),
                lui(13, 0x10),
                sw(13, 12, 0),
                addi(10, 13, 0),
                addi(11, 0, 4),
                addi(17, 0, 0),
                ecall(),
            ],
            &[],
        );

        let mut host = TestHost {
            gas_left: 500_000,
            ..Default::default()
        };
        let testnet_ctx = BlockContext {
            chain_id: budlum_uel_abi::BUDLUM_TESTNET_CHAIN_ID,
            height: 1,
            timestamp_ms: 1,
        };
        let denied = worker
            .execute(
                &testnet_ctx,
                &EeCall {
                    kind: EeCallKind::Deploy,
                    caller: EeIdentity {
                        ee: EeId::RV32,
                        id: vec![1; 32],
                    },
                    target: target.clone(),
                    value: BudAmount(0),
                    input: prog.clone(),
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [0; 32],
                },
                &mut host,
            )
            .unwrap();
        assert_eq!(denied.status, OutcomeStatus::Revert);

        let devnet_ctx = BlockContext {
            chain_id: budlum_uel_abi::BUDLUM_DEVNET_CHAIN_ID,
            height: 1,
            timestamp_ms: 1,
        };
        let deployed = worker
            .execute(
                &devnet_ctx,
                &EeCall {
                    kind: EeCallKind::Deploy,
                    caller: EeIdentity {
                        ee: EeId::RV32,
                        id: vec![1; 32],
                    },
                    target: target.clone(),
                    value: BudAmount(0),
                    input: prog,
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [0; 32],
                },
                &mut host,
            )
            .unwrap();
        assert_eq!(deployed.status, OutcomeStatus::Success);

        let called = worker
            .execute(
                &devnet_ctx,
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: EeIdentity {
                        ee: EeId::RV32,
                        id: vec![1; 32],
                    },
                    target,
                    value: BudAmount(0),
                    input: Vec::new(),
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [0; 32],
                },
                &mut host,
            )
            .unwrap();
        assert_eq!(called.status, OutcomeStatus::Success);
        assert_eq!(called.output, 99u32.to_le_bytes());
    }

    #[test]
    fn worker_accepts_minimal_elf32_riscv_header_and_executes() {
        let mut elf = vec![0u8; 52 + 32 + 12];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 1; // ELFCLASS32
        elf[5] = 1; // ELFDATA2LSB
        elf[18..20].copy_from_slice(&0xF3u16.to_le_bytes()); // EM_RISCV
        elf[24..28].copy_from_slice(&0u32.to_le_bytes()); // e_entry = 0
        elf[28..32].copy_from_slice(&52u32.to_le_bytes()); // e_phoff = 52
        elf[42..44].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize = 32
        elf[44..46].copy_from_slice(&1u16.to_le_bytes()); // e_phnum = 1
                                                          // PT_LOAD at offset 52
        elf[52..56].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        elf[56..60].copy_from_slice(&84u32.to_le_bytes()); // p_offset = 84
        elf[60..64].copy_from_slice(&0u32.to_le_bytes()); // p_vaddr = 0
        elf[68..72].copy_from_slice(&12u32.to_le_bytes()); // p_filesz = 12
        elf[72..76].copy_from_slice(&12u32.to_le_bytes()); // p_memsz = 12
                                                           // Instructions at offset 84: return 0-byte success via EXIT_OK(0, 0)
        elf[84..88].copy_from_slice(&addi(10, 0, 0).to_le_bytes());
        elf[88..92].copy_from_slice(&addi(11, 0, 0).to_le_bytes());
        elf[92..96].copy_from_slice(&ecall().to_le_bytes());

        let mut worker = Rv32Worker::new();
        let info = worker.validate_deploy(&elf).unwrap();
        assert_eq!(info.abi_tag, "rv32im-host-v1");
        let mut host = TestHost {
            gas_left: 500_000,
            ..Default::default()
        };
        let ctx = BlockContext {
            chain_id: budlum_uel_abi::BUDLUM_DEVNET_CHAIN_ID,
            height: 1,
            timestamp_ms: 1,
        };
        let target = EeIdentity {
            ee: EeId::RV32,
            id: vec![1; 4],
        };
        assert_eq!(
            worker
                .execute(
                    &ctx,
                    &EeCall {
                        kind: EeCallKind::Deploy,
                        caller: EeIdentity {
                            ee: EeId::RV32,
                            id: vec![0; 32]
                        },
                        target: target.clone(),
                        value: BudAmount(0),
                        input: elf,
                        gas_limit: 500_000,
                        depth: 0,
                        tx_hash: [0; 32],
                    },
                    &mut host,
                )
                .unwrap()
                .status,
            OutcomeStatus::Success
        );
        assert_eq!(
            worker
                .execute(
                    &ctx,
                    &EeCall {
                        kind: EeCallKind::Call,
                        caller: EeIdentity {
                            ee: EeId::RV32,
                            id: vec![0; 32]
                        },
                        target,
                        value: BudAmount(0),
                        input: Vec::new(),
                        gas_limit: 500_000,
                        depth: 0,
                        tx_hash: [0; 32],
                    },
                    &mut host,
                )
                .unwrap()
                .status,
            OutcomeStatus::Success
        );
    }
}
