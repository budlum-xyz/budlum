//! A small assembler for `BudISA`.
//!
//! The programs of the aggregation layer (signature verification, the tick)
//! are too long to write by hand and `BudL` has no arrays, so they are
//! generated: Rust code calls this assembler and gets bytecode. The
//! assembler knows registers, memory cells, labels and nothing else; every
//! statement of the programs is spelled out by the generator that calls it.
//!
//! Conventions every generated program keeps:
//!
//! * register 0 is the zero of the machine;
//! * register 30 is never written, so it holds zero and serves as the base of an
//!   absolute memory read (a load whose base is register 0 is an immediate
//!   load in this machine);
//! * register 31 belongs to the assembler: [`Asm::li`] uses it for constants
//!   that do not fit an immediate;
//! * a memory cell is one 8 byte word, and addresses are counted in cells.
//!
//! An error (an immediate out of range, a label never bound) is kept and
//! reported by [`Asm::finish`], so a generator reads as straight code.

use bud_isa::{Instruction, Opcode};

/// The Goldilocks modulus: every register and memory cell holds a value
/// below it.
const FIELD_MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

/// A register of the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reg(u8);

/// The register that is always zero.
pub const ZERO: Reg = Reg(0);
/// A register no program writes: the base of an absolute memory read.
const ZB: Reg = Reg(30);
/// The scratch register of the assembler.
const AT: Reg = Reg(31);

/// The general registers, `R[1]` to `R[29]`; `R[0]` is [`ZERO`].
pub const R: [Reg; 30] = [
    Reg(0),
    Reg(1),
    Reg(2),
    Reg(3),
    Reg(4),
    Reg(5),
    Reg(6),
    Reg(7),
    Reg(8),
    Reg(9),
    Reg(10),
    Reg(11),
    Reg(12),
    Reg(13),
    Reg(14),
    Reg(15),
    Reg(16),
    Reg(17),
    Reg(18),
    Reg(19),
    Reg(20),
    Reg(21),
    Reg(22),
    Reg(23),
    Reg(24),
    Reg(25),
    Reg(26),
    Reg(27),
    Reg(28),
    Reg(29),
];

/// A place in the code that a jump can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Label(usize);

/// Why a program could not be assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsmError {
    /// A constant is not a field element.
    ConstantOutOfField(u64),
    /// A memory address or offset does not fit an immediate.
    AddressOutOfRange(u64),
    /// A jump is further than an immediate reaches.
    JumpOutOfRange,
    /// A label was used and never bound.
    UnboundLabel(usize),
    /// A label was bound twice.
    LabelBoundTwice(usize),
    /// A register was used where the machine or the conventions forbid it.
    ReservedRegister(&'static str),
    /// The machine refused to encode an instruction.
    Encoding,
}

impl std::fmt::Display for AsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConstantOutOfField(value) => write!(f, "constant {value} is not a field element"),
            Self::AddressOutOfRange(cell) => write!(f, "memory cell {cell} is out of range"),
            Self::JumpOutOfRange => write!(f, "a jump is out of range"),
            Self::UnboundLabel(label) => write!(f, "label {label} is never bound"),
            Self::LabelBoundTwice(label) => write!(f, "label {label} is bound twice"),
            Self::ReservedRegister(what) => write!(f, "reserved register: {what}"),
            Self::Encoding => write!(f, "an instruction does not encode"),
        }
    }
}

impl std::error::Error for AsmError {}

/// A named stretch of code, for the step profile of a run.
///
/// The type is exposed for whoever profiles a run: the tests and
/// `benches/agg_tick_steps` read it through [`Program::regions`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    /// What the code does.
    pub name: &'static str,
    /// First instruction of the stretch.
    pub start: usize,
    /// One past its last instruction.
    pub end: usize,
}

/// An assembled program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// The bytecode.
    pub code: Vec<u64>,
    /// The named stretches of the code, in order, covering all of it.
    pub regions: Vec<Region>,
    /// Memory cells the program uses.
    pub memory_cells: u64,
}

/// The assembler.
#[derive(Debug, Default)]
pub struct Asm {
    code: Vec<Instruction>,
    labels: Vec<Option<usize>>,
    fixups: Vec<(usize, Label)>,
    marks: Vec<(usize, &'static str)>,
    cells: u64,
    error: Option<AsmError>,
}

impl Asm {
    /// An empty program.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn fail(&mut self, error: AsmError) {
        self.error.get_or_insert(error);
    }

    fn emit(&mut self, opcode: Opcode, rd: Reg, rs1: Reg, rs2: Reg, imm: i32) {
        self.code.push(Instruction {
            opcode,
            rd: rd.0,
            rs1: rs1.0,
            rs2: rs2.0,
            imm,
        });
    }

    fn op(&mut self, opcode: Opcode, rd: Reg, a: Reg, b: Reg) {
        if rd == ZERO || rd == ZB {
            self.fail(AsmError::ReservedRegister(
                "a result goes to a general register",
            ));
        }
        self.emit(opcode, rd, a, b, 0);
    }

    /// Reserve `cells` memory cells and return the first.
    pub const fn alloc(&mut self, cells: u64) -> u64 {
        let first = self.cells;
        self.cells = self.cells.saturating_add(cells);
        first
    }

    /// Start a named stretch of code. It ends where the next one starts.
    pub fn region(&mut self, name: &'static str) {
        self.marks.push((self.code.len(), name));
    }

    /// `rd = a + b` in the field.
    pub fn add(&mut self, rd: Reg, a: Reg, b: Reg) {
        self.op(Opcode::Add, rd, a, b);
    }

    /// `rd = a - b` in the field.
    pub fn sub(&mut self, rd: Reg, a: Reg, b: Reg) {
        self.op(Opcode::Sub, rd, a, b);
    }

    /// `rd = a * b` in the field.
    pub fn mul(&mut self, rd: Reg, a: Reg, b: Reg) {
        self.op(Opcode::Mul, rd, a, b);
    }

    /// `rd = a / b` in the field. An exact division of integers when `b`
    /// divides `a`.
    pub fn div(&mut self, rd: Reg, a: Reg, b: Reg) {
        self.op(Opcode::Div, rd, a, b);
    }

    /// `rd = 1 / a` in the field.
    pub fn inv(&mut self, rd: Reg, a: Reg) {
        self.op(Opcode::Inv, rd, a, ZERO);
    }

    /// `rd = a & b`, bit by bit.
    pub fn and(&mut self, rd: Reg, a: Reg, b: Reg) {
        self.op(Opcode::And, rd, a, b);
    }

    /// `rd = 1` when `a` is zero, else `0`.
    pub fn not(&mut self, rd: Reg, a: Reg) {
        self.op(Opcode::Not, rd, a, ZERO);
    }

    /// `rd = (a == b)`.
    pub fn eq(&mut self, rd: Reg, a: Reg, b: Reg) {
        self.op(Opcode::Eq, rd, a, b);
    }

    /// `rd = (a != b)`.
    pub fn neq(&mut self, rd: Reg, a: Reg, b: Reg) {
        self.op(Opcode::Neq, rd, a, b);
    }

    /// `rd = (a < b)` as integers.
    pub fn lt(&mut self, rd: Reg, a: Reg, b: Reg) {
        self.op(Opcode::Lt, rd, a, b);
    }

    /// `rd = (a > b)` as integers.
    pub fn gt(&mut self, rd: Reg, a: Reg, b: Reg) {
        self.op(Opcode::Gt, rd, a, b);
    }

    /// `rd = (a <= b)` as integers.
    pub fn lte(&mut self, rd: Reg, a: Reg, b: Reg) {
        self.op(Opcode::Lte, rd, a, b);
    }

    /// `rd = (a >= b)` as integers.
    pub fn gte(&mut self, rd: Reg, a: Reg, b: Reg) {
        self.op(Opcode::Gte, rd, a, b);
    }

    /// `rd = a`.
    pub fn mov(&mut self, rd: Reg, a: Reg) {
        self.op(Opcode::Add, rd, a, ZERO);
    }

    /// Stop the run with an error unless `a` is not zero.
    pub fn assert(&mut self, a: Reg) {
        self.emit(Opcode::Assert, ZERO, a, ZERO, 0);
    }

    /// Append `a` to the event log of the run.
    pub fn log(&mut self, a: Reg) {
        self.emit(Opcode::Log, ZERO, a, ZERO, 0);
    }

    /// Write `value` to storage slot `slot`. The writes of a run, in order,
    /// are what its proof commits to: this is how a program publishes a
    /// result.
    pub fn swrite(&mut self, slot: u32, value: Reg) {
        match i32::try_from(slot) {
            Ok(imm) => self.emit(Opcode::SWrite, ZERO, value, ZERO, imm),
            Err(_) => self.fail(AsmError::AddressOutOfRange(u64::from(slot))),
        }
    }

    /// End the run.
    pub fn halt(&mut self) {
        self.emit(Opcode::Halt, ZERO, ZERO, ZERO, 0);
    }

    /// Return from a subroutine.
    pub fn ret(&mut self) {
        self.emit(Opcode::Ret, ZERO, ZERO, ZERO, 0);
    }

    /// `rd = value`. One instruction when the value fits an immediate,
    /// else a short chain through the scratch register.
    pub fn li(&mut self, rd: Reg, value: u64) {
        const CHUNK_BITS: u32 = 30;
        const CHUNK: u64 = 1 << CHUNK_BITS;
        if rd == ZERO || rd == ZB || rd == AT {
            self.fail(AsmError::ReservedRegister(
                "a constant goes to a general register",
            ));
        }
        if value >= FIELD_MODULUS {
            self.fail(AsmError::ConstantOutOfField(value));
            return;
        }
        if let Ok(imm) = i32::try_from(value) {
            self.emit(Opcode::Load, rd, ZERO, ZERO, imm);
            return;
        }
        // Most significant chunk first; each later chunk is one multiply by
        // 2^30 and, unless it is zero, one add.
        let chunks = [
            value >> (2 * CHUNK_BITS),
            (value >> CHUNK_BITS) % CHUNK,
            value % CHUNK,
        ];
        let mut started = false;
        for chunk in chunks {
            let Ok(imm) = i32::try_from(chunk) else {
                self.fail(AsmError::ConstantOutOfField(value));
                return;
            };
            if !started {
                if chunk != 0 {
                    self.emit(Opcode::Load, rd, ZERO, ZERO, imm);
                    started = true;
                }
                continue;
            }
            self.emit(Opcode::Load, AT, ZERO, ZERO, 1 << CHUNK_BITS);
            self.emit(Opcode::Mul, rd, rd, AT, 0);
            if chunk != 0 {
                self.emit(Opcode::Load, AT, ZERO, ZERO, imm);
                self.emit(Opcode::Add, rd, rd, AT, 0);
            }
        }
    }

    fn cell_imm(&mut self, cell: u64) -> i32 {
        if let Some(Ok(imm)) = cell.checked_mul(8).map(i32::try_from) {
            imm
        } else {
            self.fail(AsmError::AddressOutOfRange(cell));
            0
        }
    }

    /// The byte address of a memory cell, as a constant a pointer register
    /// can hold.
    #[must_use]
    pub const fn address(cell: u64) -> u64 {
        cell.saturating_mul(8)
    }

    /// `rd = memory[base + cell]`: `base` holds a byte address (zero for an
    /// absolute read) and `cell` is a constant cell offset.
    pub fn load(&mut self, rd: Reg, base: Reg, cell: u64) {
        if base == ZERO {
            self.fail(AsmError::ReservedRegister(
                "a memory read needs a base register",
            ));
        }
        let imm = self.cell_imm(cell);
        if rd == ZERO || rd == ZB {
            self.fail(AsmError::ReservedRegister(
                "a result goes to a general register",
            ));
        }
        self.emit(Opcode::Load, rd, base, ZERO, imm);
    }

    /// `rd = memory[cell]`.
    pub fn load_abs(&mut self, rd: Reg, cell: u64) {
        self.load(rd, ZB, cell);
    }

    /// `memory[base + cell] = value`.
    pub fn store(&mut self, base: Reg, cell: u64, value: Reg) {
        let imm = self.cell_imm(cell);
        self.emit(Opcode::Store, ZERO, base, value, imm);
    }

    /// `memory[cell] = value`.
    pub fn store_abs(&mut self, cell: u64, value: Reg) {
        self.store(ZERO, cell, value);
    }

    /// A label to bind later.
    pub fn label(&mut self) -> Label {
        self.labels.push(None);
        Label(self.labels.len().saturating_sub(1))
    }

    /// Bind a label to the next instruction.
    pub fn bind(&mut self, label: Label) {
        let here = self.code.len();
        if let Some(slot @ None) = self.labels.get_mut(label.0) {
            *slot = Some(here);
        } else {
            self.fail(AsmError::LabelBoundTwice(label.0));
        }
    }

    /// A label bound to the next instruction.
    pub fn here(&mut self) -> Label {
        let label = self.label();
        self.bind(label);
        label
    }

    fn branch(&mut self, opcode: Opcode, cond: Reg, target: Label) {
        self.fixups.push((self.code.len(), target));
        self.emit(opcode, ZERO, cond, ZERO, 0);
    }

    /// Continue at `target`.
    pub fn jmp(&mut self, target: Label) {
        self.branch(Opcode::Jmp, ZERO, target);
    }

    /// Continue at `target` when `cond` is not zero.
    pub fn jnz(&mut self, cond: Reg, target: Label) {
        self.branch(Opcode::Jnz, cond, target);
    }

    /// Call the subroutine at `target`.
    pub fn call(&mut self, target: Label) {
        self.branch(Opcode::Call, ZERO, target);
    }

    /// The program.
    ///
    /// # Errors
    ///
    /// The first [`AsmError`] of the generator.
    pub fn finish(mut self) -> Result<Program, AsmError> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        for (at, label) in &self.fixups {
            let target = self
                .labels
                .get(label.0)
                .copied()
                .flatten()
                .ok_or(AsmError::UnboundLabel(label.0))?;
            let from = i64::try_from(*at).map_err(|_| AsmError::JumpOutOfRange)?;
            let to = i64::try_from(target).map_err(|_| AsmError::JumpOutOfRange)?;
            let offset =
                i32::try_from(to.saturating_sub(from)).map_err(|_| AsmError::JumpOutOfRange)?;
            if let Some(instruction) = self.code.get_mut(*at) {
                instruction.imm = offset;
            }
        }
        let code = self
            .code
            .iter()
            .map(|instruction| instruction.try_encode().map_err(|_| AsmError::Encoding))
            .collect::<Result<Vec<u64>, AsmError>>()?;
        let mut regions = Vec::with_capacity(self.marks.len().saturating_add(1));
        let mut start = 0usize;
        let mut name = "start";
        for (at, next) in self.marks {
            if at > start {
                regions.push(Region {
                    name,
                    start,
                    end: at,
                });
            }
            start = at;
            name = next;
        }
        if code.len() > start {
            regions.push(Region {
                name,
                start,
                end: code.len(),
            });
        }
        Ok(Program {
            code,
            regions,
            memory_cells: self.cells,
        })
    }
}
