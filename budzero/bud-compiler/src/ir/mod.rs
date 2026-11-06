//! Integration status: the pipeline slice that routes `compile()` through
//! this module (replacing the direct AST codegen path) plus the first
//! verifier call-site are the *next* integration step after this port;
//! until then the public surface here is exercised by the module's own
//! tests. The gates count the display/lowering cross-file calls inside this
//! crate as call evidence for the module root.
//!
//! WIRING: `Effect`/`effect()` are bound to the instruction-effect audit of
//! that same pipeline slice (they classify every `Instruction` the verifier
//! walks); the call-site lands with `compile()` integration above.
//!
//! # BudIR - Canonical, Target-Independent Intermediate Representation
//!
//! BudIR depends on neither the BudL surface syntax, nor physical VM
//! registers, PC/jump offsets, STARK trace columns, or Plonky3 internals.
//! Any frontend (BudL today, AI-native tomorrow) can lower into the same IR;
//! any backend (BudVM ISA, WASM, EVM ...) can generate code from it.
//!
//! ## Hierarchy
//! ```text
//! IrProgram
//!  └── IrFunction*
//!       └── BasicBlock*
//!            ├── InstrNode*  (instruction + optional result ValueId)
//!            └── Terminator  (exactly one per block)
//! ```
//!
//! ## SSA Status
//! Every computation produces a unique [`ValueId`] (single-assignment).
//! Mutable locals (BudL `let` + assignment) are modeled through [`LocalId`]
//! slots (`ReadLocal` / `WriteLocal`). This is the "pre-SSA" /
//! "pre-mem2reg" style, the precursor of strict academic SSA. A later
//! `mem2reg` pass may turn these slots into real SSA phi nodes.

mod display;
pub mod lower;
pub mod verify;

use std::collections::HashMap;

// ─── Identifiers ─────────────────────────────────────────────────────────

/// Immutable SSA value identifier standing for one computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValueId(pub(crate) u32);

/// Identifies a basic block within a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockId(pub(crate) u32);

/// Identifies a function within an [`IrProgram`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FunctionId(pub(crate) u32);

/// Mutable local slot (pre-SSA).
///
/// The same `LocalId` may be written more than once (not strict SSA).
/// Its type is kept in the [`IrFunction::locals`] list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocalId(pub(crate) u32);

impl ValueId {
    pub fn index(self) -> usize {
        self.0 as usize
    }
    #[cfg(test)]
    pub fn new(v: u32) -> Self {
        Self(v)
    }
}
impl BlockId {
    pub fn index(self) -> usize {
        self.0 as usize
    }
    #[cfg(test)]
    pub fn new(v: u32) -> Self {
        Self(v)
    }
}
impl FunctionId {
    pub fn index(self) -> usize {
        self.0 as usize
    }
}
impl LocalId {
    pub fn index(self) -> usize {
        self.0 as usize
    }
    #[cfg(test)]
    pub fn new(v: u32) -> Self {
        Self(v)
    }
}

// ─── Types ───────────────────────────────────────────────────────────────

/// Canonical IR type. A `sema::Type::Unknown` becomes a lowering error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrType {
    U64,
    Bool,
    Field,
    Struct(String),
    Void,
}

// ─── Effect Model ──────────────────────────────────────────────────────────

/// Coarse side-effect class of an instruction.
///
/// Not a capability system: optimizers and AI frontends can query this
/// without knowing ISA/backend details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// No observable side effect.
    Pure,
    /// Reads heap memory.
    MemoryRead,
    /// Writes heap memory.
    MemoryWrite,
    /// Reads durable contract storage.
    StateRead,
    /// Writes durable contract storage.
    StateWrite,
    /// Reads execution context (sender, block height, ...).
    ContextRead,
    /// Emits an off-chain log event.
    Event,
    /// Calls another function; may carry any side effect.
    Call,
}

// ─── Context Fields ──────────────────────────────────────────────────────

/// Semantic identifier for an execution-context field.
///
/// The numeric `Syscall 1/2/3` mapping in the ISA is deliberately left to the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextKind {
    /// `msg::sender()` - the account that initiated the transaction.
    Sender,
    /// `msg::nonce()` - the transaction nonce.
    Nonce,
    /// `block::number()` - the current block height.
    BlockHeight,
}

// ─── Instruction ──────────────────────────────────────────────────────────

/// A single BudIR instruction.
///
/// The result [`ValueId`] lives in [`InstrNode::result`], not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    // Sabitler
    Const {
        ty: IrType,
        value: u64,
    },

    // Arithmetic
    Add {
        ty: IrType,
        lhs: ValueId,
        rhs: ValueId,
    },
    Sub {
        ty: IrType,
        lhs: ValueId,
        rhs: ValueId,
    },
    Mul {
        ty: IrType,
        lhs: ValueId,
        rhs: ValueId,
    },
    Div {
        ty: IrType,
        lhs: ValueId,
        rhs: ValueId,
    },

    // Comparison (the result type is always Bool)
    IrEq {
        ty: IrType,
        lhs: ValueId,
        rhs: ValueId,
    },
    IrNe {
        ty: IrType,
        lhs: ValueId,
        rhs: ValueId,
    },
    Lt {
        ty: IrType,
        lhs: ValueId,
        rhs: ValueId,
    },
    Le {
        ty: IrType,
        lhs: ValueId,
        rhs: ValueId,
    },
    Gt {
        ty: IrType,
        lhs: ValueId,
        rhs: ValueId,
    },
    Ge {
        ty: IrType,
        lhs: ValueId,
        rhs: ValueId,
    },

    // Heap memory (struct fields)
    Load {
        ty: IrType,
        base: ValueId,
        offset: i64,
    },
    Store {
        base: ValueId,
        offset: i64,
        value: ValueId,
    },

    // Durable contract storage
    StateRead {
        ty: IrType,
        slot: i32,
    },
    StateWrite {
        slot: i32,
        value: ValueId,
    },

    // Mutable locals (pre-SSA)
    ReadLocal {
        local: LocalId,
        ty: IrType,
    },
    WriteLocal {
        local: LocalId,
        value: ValueId,
    },

    // Function call
    Call {
        function: FunctionId,
        args: Vec<ValueId>,
        ret_ty: IrType,
    },

    // ZK / domain-specific
    Assert {
        condition: ValueId,
    },
    Poseidon {
        lhs: ValueId,
        rhs: ValueId,
    },
    Emit {
        event_name: String,
        args: Vec<ValueId>,
    },
    ContextRead {
        kind: ContextKind,
    },
}

impl Instruction {
    /// IR type of the value this instruction produces; `None` if none.
    pub fn result_type(&self) -> Option<IrType> {
        match self {
            Instruction::Const { ty, .. } => Some(ty.clone()),
            Instruction::Add { ty, .. }
            | Instruction::Sub { ty, .. }
            | Instruction::Mul { ty, .. }
            | Instruction::Div { ty, .. } => Some(ty.clone()),
            Instruction::IrEq { .. }
            | Instruction::IrNe { .. }
            | Instruction::Lt { .. }
            | Instruction::Le { .. }
            | Instruction::Gt { .. }
            | Instruction::Ge { .. } => Some(IrType::Bool),
            Instruction::Load { ty, .. } => Some(ty.clone()),
            Instruction::Store { .. } => None,
            Instruction::StateRead { ty, .. } => Some(ty.clone()),
            Instruction::StateWrite { .. } => None,
            Instruction::ReadLocal { ty, .. } => Some(ty.clone()),
            Instruction::WriteLocal { .. } => None,
            Instruction::Call { ret_ty, .. } => {
                if *ret_ty == IrType::Void {
                    None
                } else {
                    Some(ret_ty.clone())
                }
            }
            Instruction::Assert { .. } => None,
            Instruction::Poseidon { .. } => Some(IrType::U64),
            Instruction::Emit { .. } => None,
            Instruction::ContextRead { .. } => Some(IrType::U64),
        }
    }

    /// Coarse side-effect class of this instruction.
    pub fn effect(&self) -> Effect {
        match self {
            Instruction::Const { .. }
            | Instruction::Add { .. }
            | Instruction::Sub { .. }
            | Instruction::Mul { .. }
            | Instruction::Div { .. }
            | Instruction::IrEq { .. }
            | Instruction::IrNe { .. }
            | Instruction::Lt { .. }
            | Instruction::Le { .. }
            | Instruction::Gt { .. }
            | Instruction::Ge { .. }
            | Instruction::Poseidon { .. }
            | Instruction::Assert { .. }
            | Instruction::ReadLocal { .. } => Effect::Pure,
            Instruction::Load { .. } => Effect::MemoryRead,
            Instruction::Store { .. } | Instruction::WriteLocal { .. } => Effect::MemoryWrite,
            Instruction::StateRead { .. } => Effect::StateRead,
            Instruction::StateWrite { .. } => Effect::StateWrite,
            Instruction::ContextRead { .. } => Effect::ContextRead,
            Instruction::Emit { .. } => Effect::Event,
            Instruction::Call { .. } => Effect::Call,
        }
    }
}

// ─── Terminator ───────────────────────────────────────────────────────────

/// The control-flow instruction closing a BasicBlock.
/// Every block must end with exactly one Terminator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminator {
    /// Unconditional branch.
    Jump(BlockId),
    /// Conditional branch.
    Branch {
        condition: ValueId,
        then_block: BlockId,
        else_block: BlockId,
    },
    /// Return from the function, with an optional value.
    Return(Option<ValueId>),
    /// Statically unreachable path.
    Unreachable,
}

// ─── BasicBlock ───────────────────────────────────────────────────────────

/// Instruction plus optional result pair.
#[derive(Debug, Clone)]
pub struct InstrNode {
    /// SSA value; `None` for void instructions.
    pub result: Option<ValueId>,
    pub instr: Instruction,
}

/// Instruction sequence with a single entry point and one Terminator.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    pub instrs: Vec<InstrNode>,
    /// `None` while the IR is being built; the verifier errors on `None` in a finished IR.
    pub terminator: Option<Terminator>,
}

// ─── Function ─────────────────────────────────────────────────────────────

/// An IR function. `blocks[0]` is the entry block.
#[derive(Debug, Clone)]
pub struct IrFunction {
    pub id: FunctionId,
    pub name: String,
    /// Parameter list: (value_id, type).
    pub params: Vec<(ValueId, IrType)>,
    pub ret_ty: IrType,
    /// Basic blocks, kept in [`BlockId`] order (deterministic output).
    pub blocks: Vec<BasicBlock>,
    /// Mutable local slot types, indexed by [`LocalId`].
    pub locals: Vec<IrType>,
}

// ─── Program ──────────────────────────────────────────────────────────────

/// Top-level IR artifact produced from one `.bud` contract.
#[derive(Debug, Clone, Default)]
pub struct IrProgram {
    pub functions: Vec<IrFunction>,
    /// Name to ID map, for call resolution and display.
    pub function_names: HashMap<String, FunctionId>,
}
