//! AST → BudIR lowering.
//!
//! WIRING: `lower_contract` and `LoweringError` are reached by `compile()`
//! in the BudIR pipeline slice (the next integration step described in
//! `ir/mod.rs`); the note stays until that call-site lands.
//!
//! This module is fully independent of the existing `codegen.rs`: no
//! physical registers, PC offsets, or ISA opcode knowledge exists here.
//!
//! ## Supported subset (first version)
//! - Expressions: integer literal, identifier, arithmetic, comparison,
//!   function call, storage read, context built-ins, poseidon(...)
//! - Expressions (not yet supported): struct literal, mapping read/write
//! - Deyimler: let, assign, constrain, if/else, while, for, return,
//!   emit, storage write, expression statement
//!
//! ## The SSA decision
//! Mutable locals (BudL `let` + assignment) are modeled through `LocalId`
//! slots. Every computation produces a unique `ValueId`, but a mutable
//! variable may be written more than once. This is the "pre-SSA" /
//! "pre-mem2reg" style - full SSA via a later `mem2reg` pass.
//! For branch merges that would need phi nodes, `ReadLocal` always reads
//! the latest value in the slot; no dominance analysis over the CFG.

use std::collections::HashMap;

use crate::ast::{BinOp, Contract, Expr, Stmt};
use crate::sema::{self, SemanticAnalyzer};

use super::{
    BasicBlock, BlockId, ContextKind, FunctionId, InstrNode, Instruction, IrFunction, IrProgram,
    IrType, LocalId, Terminator, ValueId,
};

// ─── Error type ────────────────────────────────────────────────────────────

/// Errors that can arise during AST to BudIR conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoweringError {
    /// A `sema::Type::Unknown` or unrecognized type name that could not be resolved.
    UnresolvedType(String),
    /// An undefined variable name.
    UndefinedVariable(String),
    /// An undefined function name.
    UndefinedFunction(String),
    /// An AST node this version does not support.
    UnsupportedNode(String),
    /// Type mismatch (sema should already have caught this - defensive check).
    TypeMismatch { expected: IrType, got: IrType },
    /// An inconsistency inside the lowerer (bug).
    InternalError(String),
}

impl std::fmt::Display for LoweringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoweringError::UnresolvedType(t) => write!(f, "unresolved type: {t}"),
            LoweringError::UndefinedVariable(v) => write!(f, "undefined variable: {v}"),
            LoweringError::UndefinedFunction(fn_) => write!(f, "undefined function: {fn_}"),
            LoweringError::UnsupportedNode(n) => write!(f, "unsupported AST node: {n}"),
            LoweringError::TypeMismatch { expected, got } => {
                write!(f, "type mismatch: expected {expected:?}, got {got:?}")
            }
            LoweringError::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for LoweringError {}

// ─── Conversion helpers ───────────────────────────────────────────────────

/// `sema::Type` to `IrType`. Unknown becomes a lowering error.
fn from_sema_type(ty: &sema::Type) -> Result<IrType, LoweringError> {
    match ty {
        sema::Type::U64 => Ok(IrType::U64),
        sema::Type::Bool => Ok(IrType::Bool),
        sema::Type::Field => Ok(IrType::Field),
        sema::Type::Struct(n) => Ok(IrType::Struct(n.clone())),
        sema::Type::Void => Ok(IrType::Void),
        sema::Type::Unknown => Err(LoweringError::UnresolvedType("Unknown".into())),
        // This tree's sema knows 32-byte opaque types and storage mappings;
        // the IR does not model their widths yet, so lowering one is an
        // honest refusal (typed as Unsupported), never a silent U64 alias.
        sema::Type::Address | sema::Type::Hash32 => Err(LoweringError::UnsupportedNode(format!(
            "opaque 32-byte sema type has no IR type yet: {ty:?}"
        ))),
        sema::Type::Map(..) => Err(LoweringError::UnsupportedNode(
            "storage mappings have no IR type yet".into(),
        )),
    }
}

/// String type name to `IrType`.
fn parse_ir_type(s: &str) -> Result<IrType, LoweringError> {
    match s {
        "u64" => Ok(IrType::U64),
        "bool" => Ok(IrType::Bool),
        "field" => Ok(IrType::Field),
        "void" | "" => Ok(IrType::Void),
        // Literal-name arm binds nothing, so the name stays in the message itself.
        "Address" | "Hash32" => Err(LoweringError::UnsupportedNode(
            "opaque 32-byte type has no IR type yet (Address/Hash32)".into(),
        )),
        other if other.starts_with("Map<") => Err(LoweringError::UnsupportedNode(
            "storage mappings have no IR type yet".into(),
        )),
        other => Ok(IrType::Struct(other.to_string())),
    }
}

// ─── Public entry point ───────────────────────────────────────────────────

/// Converts a contract into an [`IrProgram`].
///
/// The existing production codegen (`codegen.rs`) is left untouched; this
/// function is the parallel BudIR path alongside it, not a replacement.
pub fn lower_contract(
    contract: &Contract,
    sema: &SemanticAnalyzer,
) -> Result<IrProgram, LoweringError> {
    let mut lowerer = Lowerer::new(contract, sema);
    lowerer.lower(contract)
}

// ─── Lowerer ──────────────────────────────────────────────────────────────

struct Lowerer<'a> {
    sema: &'a SemanticAnalyzer,
    /// Storage field name to slot index (0-based).
    storage_slots: HashMap<String, i32>,
    /// Struct name to ordered field-name list (for byte-offset computation).
    struct_field_order: HashMap<String, Vec<String>>,
    /// Function name to FunctionId (first pass).
    function_ids: HashMap<String, FunctionId>,
}

impl<'a> Lowerer<'a> {
    fn new(contract: &Contract, sema: &'a SemanticAnalyzer) -> Self {
        let storage_slots = contract
            .storage
            .iter()
            .enumerate()
            .map(|(i, f)| (f.name.clone(), i as i32))
            .collect();

        let struct_field_order = contract
            .structs
            .iter()
            .map(|s| {
                let fields = s.fields.iter().map(|f| f.name.clone()).collect();
                (s.name.clone(), fields)
            })
            .collect();

        Lowerer {
            sema,
            storage_slots,
            struct_field_order,
            function_ids: HashMap::new(),
        }
    }

    fn lower(&mut self, contract: &Contract) -> Result<IrProgram, LoweringError> {
        let mut program = IrProgram::default();

        // 1st pass: assign every function a FunctionId.
        for (i, func) in contract.functions.iter().enumerate() {
            let fid = FunctionId(i as u32);
            self.function_ids.insert(func.name.clone(), fid);
            program.function_names.insert(func.name.clone(), fid);
        }

        // 2nd pass: lower each function.
        for (i, func) in contract.functions.iter().enumerate() {
            let ir_fn = self.lower_function(FunctionId(i as u32), func)?;
            program.functions.push(ir_fn);
        }

        Ok(program)
    }

    fn lower_function(
        &mut self,
        fid: FunctionId,
        func: &crate::ast::Function,
    ) -> Result<IrFunction, LoweringError> {
        let ret_ty = match &func.return_type {
            Some(t) => parse_ir_type(t)?,
            None => IrType::Void,
        };

        let mut ctx = FnCtx::new();

        // Params: each gets a ValueId, backed by a LocalId behind the scenes.
        let mut params = Vec::new();
        for param in &func.params {
            let ty = parse_ir_type(&param.ty)?;
            let val = ctx.fresh_value(); // the param value
            params.push((val, ty.clone()));
            let local = ctx.fresh_local(ty.clone());
            ctx.define_local(&param.name, local, ty);
            // Initialize the slot with the param value.
            ctx.push_instr(Instruction::WriteLocal { local, value: val });
        }

        // Lower the body.
        for stmt in &func.body {
            self.lower_stmt(stmt, &mut ctx)?;
        }

        // Append a void return if no explicit return exists.
        if !ctx.current_block_terminated() {
            ctx.set_terminator(Terminator::Return(None));
        }

        // Collect blocks in deterministic order.
        let mut blocks = ctx.blocks;
        blocks.sort_by_key(|b| b.id);

        Ok(IrFunction {
            id: fid,
            name: func.name.clone(),
            params,
            ret_ty,
            blocks,
            locals: ctx.locals,
        })
    }

    // ── Deyim lowering ────────────────────────────────────────────────────

    fn lower_stmt(&mut self, stmt: &Stmt, ctx: &mut FnCtx) -> Result<(), LoweringError> {
        // Emitting into a terminated block.
        if ctx.current_block_terminated() {
            return Ok(());
        }

        match stmt {
            Stmt::Let(name, expr) => {
                let (val, ty) = self.lower_expr_value(expr, ctx)?;
                let local = ctx.fresh_local(ty.clone());
                ctx.define_local(name, local, ty);
                ctx.push_instr(Instruction::WriteLocal { local, value: val });
            }

            Stmt::Assign(name, expr) => {
                let (val, _) = self.lower_expr_value(expr, ctx)?;
                let (local, _) = ctx
                    .lookup_local(name)
                    .ok_or_else(|| LoweringError::UndefinedVariable(name.clone()))?;
                ctx.push_instr(Instruction::WriteLocal { local, value: val });
            }

            Stmt::Constrain(expr) => {
                let (val, _) = self.lower_expr_value(expr, ctx)?;
                ctx.push_instr(Instruction::Assert { condition: val });
            }

            Stmt::StorageWrite(name, expr) => {
                let slot = *self
                    .storage_slots
                    .get(name)
                    .ok_or_else(|| LoweringError::UndefinedVariable(name.clone()))?;
                let (val, _) = self.lower_expr_value(expr, ctx)?;
                ctx.push_instr(Instruction::StateWrite { slot, value: val });
            }

            Stmt::If(cond, then_body, else_body) => {
                let (cond_val, _) = self.lower_expr_value(cond, ctx)?;
                let then_block = ctx.fresh_block();
                let else_block = ctx.fresh_block();
                let merge_block = ctx.fresh_block();

                ctx.set_terminator(Terminator::Branch {
                    condition: cond_val,
                    then_block,
                    else_block,
                });

                // then branch
                ctx.switch_to(then_block);
                ctx.push_scope();
                for s in then_body {
                    self.lower_stmt(s, ctx)?;
                }
                ctx.pop_scope();
                if !ctx.current_block_terminated() {
                    ctx.set_terminator(Terminator::Jump(merge_block));
                }

                // else branch
                ctx.switch_to(else_block);
                ctx.push_scope();
                if let Some(eb) = else_body {
                    for s in eb {
                        self.lower_stmt(s, ctx)?;
                    }
                }
                ctx.pop_scope();
                if !ctx.current_block_terminated() {
                    ctx.set_terminator(Terminator::Jump(merge_block));
                }

                ctx.switch_to(merge_block);
            }

            Stmt::While(cond, body) => {
                let header_block = ctx.fresh_block();
                let body_block = ctx.fresh_block();
                let exit_block = ctx.fresh_block();

                ctx.set_terminator(Terminator::Jump(header_block));

                // header: condition evaluation
                ctx.switch_to(header_block);
                let (cond_val, _) = self.lower_expr_value(cond, ctx)?;
                ctx.set_terminator(Terminator::Branch {
                    condition: cond_val,
                    then_block: body_block,
                    else_block: exit_block,
                });

                // body
                ctx.switch_to(body_block);
                ctx.push_scope();
                for s in body {
                    self.lower_stmt(s, ctx)?;
                }
                ctx.pop_scope();
                if !ctx.current_block_terminated() {
                    ctx.set_terminator(Terminator::Jump(header_block));
                }

                ctx.switch_to(exit_block);
            }

            Stmt::For {
                var,
                start,
                end,
                body,
            } => {
                let (start_val, _) = self.lower_expr_value(start, ctx)?;
                let (end_val, _) = self.lower_expr_value(end, ctx)?;

                // Local slot for the loop variable.
                let loop_local = ctx.fresh_local(IrType::U64);
                ctx.push_instr(Instruction::WriteLocal {
                    local: loop_local,
                    value: start_val,
                });

                // Keep the end value in a slot too (the header block may reference it).
                let end_local = ctx.fresh_local(IrType::U64);
                ctx.push_instr(Instruction::WriteLocal {
                    local: end_local,
                    value: end_val,
                });

                let header_block = ctx.fresh_block();
                let body_block = ctx.fresh_block();
                let exit_block = ctx.fresh_block();

                ctx.set_terminator(Terminator::Jump(header_block));

                // header: i < end
                ctx.switch_to(header_block);
                let loop_val = ctx.push_value_instr(Instruction::ReadLocal {
                    local: loop_local,
                    ty: IrType::U64,
                })?;
                let end_read = ctx.push_value_instr(Instruction::ReadLocal {
                    local: end_local,
                    ty: IrType::U64,
                })?;
                let cond_val = ctx.push_value_instr(Instruction::Lt {
                    ty: IrType::U64,
                    lhs: loop_val,
                    rhs: end_read,
                })?;
                ctx.set_terminator(Terminator::Branch {
                    condition: cond_val,
                    then_block: body_block,
                    else_block: exit_block,
                });

                // body
                ctx.switch_to(body_block);
                ctx.push_scope();
                ctx.define_local(var, loop_local, IrType::U64);
                for s in body {
                    self.lower_stmt(s, ctx)?;
                }
                ctx.pop_scope();
                if !ctx.current_block_terminated() {
                    // i += 1
                    let cur = ctx.push_value_instr(Instruction::ReadLocal {
                        local: loop_local,
                        ty: IrType::U64,
                    })?;
                    let one = ctx.push_value_instr(Instruction::Const {
                        ty: IrType::U64,
                        value: 1,
                    })?;
                    let next = ctx.push_value_instr(Instruction::Add {
                        ty: IrType::U64,
                        lhs: cur,
                        rhs: one,
                    })?;
                    ctx.push_instr(Instruction::WriteLocal {
                        local: loop_local,
                        value: next,
                    });
                    ctx.set_terminator(Terminator::Jump(header_block));
                }

                ctx.switch_to(exit_block);
            }

            Stmt::Return(maybe_expr) => {
                let ret_val = match maybe_expr {
                    Some(e) => {
                        let (v, _) = self.lower_expr_value(e, ctx)?;
                        Some(v)
                    }
                    None => None,
                };
                ctx.set_terminator(Terminator::Return(ret_val));
            }

            Stmt::Emit(event_name, args) => {
                let mut arg_vals = Vec::new();
                for arg in args {
                    let (v, _) = self.lower_expr_value(arg, ctx)?;
                    arg_vals.push(v);
                }
                ctx.push_instr(Instruction::Emit {
                    event_name: event_name.clone(),
                    args: arg_vals,
                });
            }

            Stmt::Match { .. } => {
                return Err(LoweringError::UnsupportedNode(
                    "match statement - not yet supported in IR lowering".into(),
                ));
            }

            Stmt::Expr(expr) => {
                // All expressions, void calls included; the result is discarded.
                self.lower_expr(expr, ctx)?;
            }

            Stmt::MappingWrite(_, _, _) => {
                return Err(LoweringError::UnsupportedNode(
                    "MappingWrite - not yet supported by IR lowering".into(),
                ));
            }
        }

        Ok(())
    }

    // ── Expression lowering ─────────────────────────────────────────────

    /// Lowers the expression and returns `Option<(ValueId, IrType)>`.
    /// Returns `None` for void calls; every other expression returns `Some(...)`.
    fn lower_expr(
        &mut self,
        expr: &Expr,
        ctx: &mut FnCtx,
    ) -> Result<Option<(ValueId, IrType)>, LoweringError> {
        match expr {
            Expr::Int(v) => {
                let val = ctx.push_value_instr(Instruction::Const {
                    ty: IrType::U64,
                    value: *v,
                })?;
                Ok(Some((val, IrType::U64)))
            }

            Expr::Ident(name) => {
                let (local, ty) = ctx
                    .lookup_local(name)
                    .ok_or_else(|| LoweringError::UndefinedVariable(name.clone()))?;
                let val = ctx.push_value_instr(Instruction::ReadLocal {
                    local,
                    ty: ty.clone(),
                })?;
                Ok(Some((val, ty)))
            }

            Expr::Binary(lhs, op, rhs) => {
                let (l_val, l_ty) = self.lower_expr_value(lhs, ctx)?;
                let (r_val, _) = self.lower_expr_value(rhs, ctx)?;

                let (instr, res_ty) = match op {
                    BinOp::Add => (
                        Instruction::Add {
                            ty: l_ty.clone(),
                            lhs: l_val,
                            rhs: r_val,
                        },
                        l_ty,
                    ),
                    BinOp::Sub => (
                        Instruction::Sub {
                            ty: l_ty.clone(),
                            lhs: l_val,
                            rhs: r_val,
                        },
                        l_ty,
                    ),
                    BinOp::Mul => (
                        Instruction::Mul {
                            ty: l_ty.clone(),
                            lhs: l_val,
                            rhs: r_val,
                        },
                        l_ty,
                    ),
                    BinOp::Div => (
                        Instruction::Div {
                            ty: l_ty.clone(),
                            lhs: l_val,
                            rhs: r_val,
                        },
                        l_ty,
                    ),
                    BinOp::Eq => (
                        Instruction::IrEq {
                            ty: l_ty,
                            lhs: l_val,
                            rhs: r_val,
                        },
                        IrType::Bool,
                    ),
                    BinOp::Neq => (
                        Instruction::IrNe {
                            ty: l_ty,
                            lhs: l_val,
                            rhs: r_val,
                        },
                        IrType::Bool,
                    ),
                    BinOp::Lt => (
                        Instruction::Lt {
                            ty: l_ty,
                            lhs: l_val,
                            rhs: r_val,
                        },
                        IrType::Bool,
                    ),
                    BinOp::Lte => (
                        Instruction::Le {
                            ty: l_ty,
                            lhs: l_val,
                            rhs: r_val,
                        },
                        IrType::Bool,
                    ),
                    BinOp::Gt => (
                        Instruction::Gt {
                            ty: l_ty,
                            lhs: l_val,
                            rhs: r_val,
                        },
                        IrType::Bool,
                    ),
                    BinOp::Gte => (
                        Instruction::Ge {
                            ty: l_ty,
                            lhs: l_val,
                            rhs: r_val,
                        },
                        IrType::Bool,
                    ),
                };

                let val = ctx.push_value_instr(instr)?;
                Ok(Some((val, res_ty)))
            }

            Expr::StorageRead(name) => {
                let slot = *self
                    .storage_slots
                    .get(name)
                    .ok_or_else(|| LoweringError::UndefinedVariable(name.clone()))?;
                let val = ctx.push_value_instr(Instruction::StateRead {
                    ty: IrType::U64,
                    slot,
                })?;
                Ok(Some((val, IrType::U64)))
            }

            Expr::Call(name, args) => self.lower_call(name, args, ctx),

            Expr::FieldAccess(base_expr, field) => {
                let (base_val, base_ty) = self.lower_expr_value(base_expr, ctx)?;
                let struct_name = match &base_ty {
                    IrType::Struct(n) => n.clone(),
                    _ => {
                        return Err(LoweringError::UnsupportedNode(
                            "field access on non-struct type".into(),
                        ));
                    }
                };
                let fields = self
                    .struct_field_order
                    .get(&struct_name)
                    .ok_or_else(|| LoweringError::UnresolvedType(struct_name.clone()))?;
                let idx = fields.iter().position(|f| f == field).ok_or_else(|| {
                    LoweringError::UnsupportedNode(format!(
                        "struct {struct_name} has no field {field}"
                    ))
                })?;
                let offset = (idx * 8) as i64;
                let val = ctx.push_value_instr(Instruction::Load {
                    ty: IrType::U64,
                    base: base_val,
                    offset,
                })?;
                Ok(Some((val, IrType::U64)))
            }

            Expr::StructLiteral(_, _) => Err(LoweringError::UnsupportedNode(
                "struct literal - the heap allocation model has not landed in the IR yet".into(),
            )),

            Expr::MappingRead(_, _) => Err(LoweringError::UnsupportedNode(
                "MappingRead - not yet supported by IR lowering".into(),
            )),
        }
    }

    /// Lowers the expression and demands it produce a value.
    /// Void expressions (a void function call) return an error.
    fn lower_expr_value(
        &mut self,
        expr: &Expr,
        ctx: &mut FnCtx,
    ) -> Result<(ValueId, IrType), LoweringError> {
        self.lower_expr(expr, ctx)?
            .ok_or_else(|| LoweringError::UnsupportedNode("void expression used as value".into()))
    }

    /// Lowers a function call. Built-ins are handled specially.
    fn lower_call(
        &mut self,
        name: &str,
        args: &[Expr],
        ctx: &mut FnCtx,
    ) -> Result<Option<(ValueId, IrType)>, LoweringError> {
        // Context built-ins
        if name == "msg::sender" {
            let val = ctx.push_value_instr(Instruction::ContextRead {
                kind: ContextKind::Sender,
            })?;
            return Ok(Some((val, IrType::U64)));
        }
        if name == "msg::nonce" {
            let val = ctx.push_value_instr(Instruction::ContextRead {
                kind: ContextKind::Nonce,
            })?;
            return Ok(Some((val, IrType::U64)));
        }
        if name == "block::number" {
            let val = ctx.push_value_instr(Instruction::ContextRead {
                kind: ContextKind::BlockHeight,
            })?;
            return Ok(Some((val, IrType::U64)));
        }

        // Poseidon built-in
        if name == "poseidon" {
            if args.len() != 2 {
                return Err(LoweringError::UnsupportedNode(
                    "poseidon() exactly 2 arguments required".into(),
                ));
            }
            let (lhs, _) = self.lower_expr_value(&args[0], ctx)?;
            let (rhs, _) = self.lower_expr_value(&args[1], ctx)?;
            let val = ctx.push_value_instr(Instruction::Poseidon { lhs, rhs })?;
            return Ok(Some((val, IrType::U64)));
        }

        // verify_merkle_proof - not yet supported
        if name == "verify_merkle_proof" {
            return Err(LoweringError::UnsupportedNode(
                "verify_merkle_proof - not yet supported by IR lowering".into(),
            ));
        }

        // User-defined function
        let fid = self
            .function_ids
            .get(name)
            .copied()
            .ok_or_else(|| LoweringError::UndefinedFunction(name.to_string()))?;

        let mut arg_vals = Vec::new();
        for arg in args {
            let (v, _) = self.lower_expr_value(arg, ctx)?;
            arg_vals.push(v);
        }

        // Take the return type from sema.
        let ret_ty = if let Some((_, ret)) = self.sema.functions.get(name) {
            from_sema_type(ret)?
        } else {
            IrType::Void
        };

        let instr = Instruction::Call {
            function: fid,
            args: arg_vals,
            ret_ty: ret_ty.clone(),
        };
        let result = ctx.push_instr(instr);

        if ret_ty == IrType::Void {
            Ok(None)
        } else {
            let value = result.ok_or_else(|| {
                LoweringError::InternalError("non-void call produces value".into())
            })?;
            Ok(Some((value, ret_ty)))
        }
    }
}

// ─── Function-build context ───────────────────────────────────────────────

/// Mutable state held while lowering one function.
struct FnCtx {
    next_value: u32,
    next_block: u32,
    blocks: Vec<BasicBlock>,
    current_block: BlockId,
    /// Scope stack: name to (LocalId, IrType). Outermost scopes are searched first.
    scopes: Vec<HashMap<String, (LocalId, IrType)>>,
    /// Local slot types, indexed by LocalId.
    locals: Vec<IrType>,
}

impl FnCtx {
    fn new() -> Self {
        let entry = BasicBlock {
            id: BlockId(0),
            instrs: vec![],
            terminator: None,
        };
        FnCtx {
            next_value: 0,
            next_block: 1,
            blocks: vec![entry],
            current_block: BlockId(0),
            scopes: vec![HashMap::new()],
            locals: vec![],
        }
    }

    fn fresh_value(&mut self) -> ValueId {
        let v = ValueId(self.next_value);
        self.next_value += 1;
        v
    }

    fn fresh_block(&mut self) -> BlockId {
        let b = BlockId(self.next_block);
        self.next_block += 1;
        self.blocks.push(BasicBlock {
            id: b,
            instrs: vec![],
            terminator: None,
        });
        b
    }

    fn fresh_local(&mut self, ty: IrType) -> LocalId {
        let l = LocalId(self.locals.len() as u32);
        self.locals.push(ty);
        l
    }

    /// Pushes the instruction into the current block; returns the result ValueId.
    fn push_instr(&mut self, instr: Instruction) -> Option<ValueId> {
        let result = instr.result_type().map(|_| {
            let v = ValueId(self.next_value);
            self.next_value += 1;
            v
        });
        let block = self.block_mut(self.current_block);
        block.instrs.push(InstrNode { result, instr });
        result
    }

    /// Pushes a value-producing instruction and yields its result `ValueId`.
    /// The `InternalError` path is formally unreachable for the instruction
    /// kinds callers pass here (a void instruction never arrives), but the
    /// invariant is expressed as an error instead of an `expect`, which the
    /// workspace lints deny.
    fn push_value_instr(&mut self, instr: Instruction) -> Result<ValueId, LoweringError> {
        self.push_instr(instr).ok_or_else(|| {
            LoweringError::InternalError(
                "push_value_instr: value-producing instruction gave no value".into(),
            )
        })
    }

    fn set_terminator(&mut self, term: Terminator) {
        self.block_mut(self.current_block).terminator = Some(term);
    }

    fn switch_to(&mut self, block: BlockId) {
        self.current_block = block;
    }

    fn current_block_terminated(&self) -> bool {
        let id = self.current_block;
        self.blocks
            .iter()
            .find(|b| b.id == id)
            .is_some_and(|b| b.terminator.is_some())
    }

    fn block_mut(&mut self, id: BlockId) -> &mut BasicBlock {
        // Invariant: every BlockId reaching this function was minted by this
        // FnCtx (new/new_block), so the position lookup is total. Written
        // without Option::expect because the crate denies it workspace-wide.
        let pos = self
            .blocks
            .iter()
            .position(|b| b.id == id)
            .unwrap_or_else(|| unreachable!("block_mut: block id was not minted by this FnCtx"));
        &mut self.blocks[pos]
    }

    fn define_local(&mut self, name: &str, local: LocalId, ty: IrType) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_string(), (local, ty));
        }
    }

    fn lookup_local(&self, name: &str) -> Option<(LocalId, IrType)> {
        for scope in self.scopes.iter().rev() {
            if let Some(entry) = scope.get(name) {
                return Some(entry.clone());
            }
        }
        None
    }

    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;
    use crate::sema::SemanticAnalyzer;

    fn lower_source(src: &str) -> Result<IrProgram, LoweringError> {
        let mut p = Parser::new(src).expect("parser construction failed");
        let contract = p.parse_contract().expect("parse failed");
        let mut sema = SemanticAnalyzer::new();
        sema.analyze(&contract).expect("sema failed");
        lower_contract(&contract, &sema)
    }

    // ── 1. Arithmetic AST to IR ─────────────────────────────────────────────
    #[test]
    fn test_arithmetic_lowering() {
        let prog = lower_source(
            "contract T { pub fn main() -> u64 { let a = 10; let b = 20; return a + b; } }",
        )
        .expect("lowering failed");
        assert_eq!(prog.functions.len(), 1);
        let f = &prog.functions[0];
        // entry block'ta Const 10, WriteLocal, Const 20, WriteLocal, ReadLocal, ReadLocal, Add,
        // ReadLocal (ret), Return gibi instruction'lar bekleniyor.
        let bb0 = &f.blocks[0];
        let has_add = bb0
            .instrs
            .iter()
            .any(|n| matches!(&n.instr, Instruction::Add { .. }));
        assert!(has_add, "Add instruction missing");
        assert!(matches!(bb0.terminator, Some(Terminator::Return(Some(_)))));
    }

    // ── 2. Comparison ────────────────────────────────────────────────
    #[test]
    fn test_comparison_lowering() {
        let prog = lower_source(
            "contract T { pub fn main() -> u64 { let a = 5; let b = 10; let c = a < b; return a; } }",
        )
        .expect("lowering failed");
        let f = &prog.functions[0];
        let bb0 = &f.blocks[0];
        let has_lt = bb0
            .instrs
            .iter()
            .any(|n| matches!(&n.instr, Instruction::Lt { .. }));
        assert!(has_lt, "Lt instruction missing");
    }

    // ── 3. if/else CFG ───────────────────────────────────────────────────
    #[test]
    fn test_if_else_cfg() {
        let prog = lower_source(
            r"contract T {
                pub fn main() -> u64 {
                    let x = 0;
                    if (x == 0) {
                        return 1;
                    } else {
                        return 2;
                    }
                }
            }",
        )
        .expect("lowering failed");
        let f = &prog.functions[0];
        // En az 3 blok: entry (branch), then, else + merge (opsiyonel)
        assert!(
            f.blocks.len() >= 3,
            "expected at least 3 blocks, got {}",
            f.blocks.len()
        );
        let entry = &f.blocks[0];
        assert!(
            matches!(entry.terminator, Some(Terminator::Branch { .. })),
            "entry block must terminate with Branch"
        );
    }

    // ── 4. Function call ───────────────────────────────────────────
    #[test]
    fn test_function_call_lowering() {
        let prog = lower_source(
            r"contract T {
                fn add(a: u64, b: u64) -> u64 { return a + b; }
                pub fn main() -> u64 { return add(1, 2); }
            }",
        )
        .expect("lowering failed");
        assert_eq!(prog.functions.len(), 2);
        let main_fn = prog
            .functions
            .iter()
            .find(|f| f.name == "main")
            .expect("main not found");
        let has_call = main_fn
            .blocks
            .iter()
            .flat_map(|b| &b.instrs)
            .any(|n| matches!(&n.instr, Instruction::Call { .. }));
        assert!(has_call, "Call instruction missing in main");
    }

    // ── 5. context.sender ────────────────────────────────────────────────
    #[test]
    fn test_context_sender_lowering() {
        let prog = lower_source(
            "contract T { pub fn main() -> u64 { let s = msg::sender(); return s; } }",
        )
        .expect("lowering failed");
        let f = &prog.functions[0];
        let has_sender = f.blocks.iter().flat_map(|b| &b.instrs).any(|n| {
            matches!(
                &n.instr,
                Instruction::ContextRead {
                    kind: ContextKind::Sender
                }
            )
        });
        assert!(has_sender, "ContextRead(Sender) missing");
    }

    // ── 6. Storage read / write ───────────────────────────────────────────
    #[test]
    fn test_storage_read_write_lowering() {
        let prog = lower_source(
            r"contract T {
                storage { counter: u64, }
                pub fn main() {
                    let v = storage::counter;
                    storage::counter = v;
                }
            }",
        )
        .expect("lowering failed");
        let f = &prog.functions[0];
        let instrs: Vec<_> = f.blocks.iter().flat_map(|b| &b.instrs).collect();
        let has_read = instrs
            .iter()
            .any(|n| matches!(&n.instr, Instruction::StateRead { .. }));
        let has_write = instrs
            .iter()
            .any(|n| matches!(&n.instr, Instruction::StateWrite { .. }));
        assert!(has_read, "StateRead missing");
        assert!(has_write, "StateWrite missing");
    }

    // ── 7. constrain → Assert ────────────────────────────────────────────
    #[test]
    fn test_constrain_becomes_assert() {
        let prog = lower_source("contract T { pub fn main() { let x = 1; constrain(x); } }")
            .expect("lowering failed");
        let f = &prog.functions[0];
        let has_assert = f
            .blocks
            .iter()
            .flat_map(|b| &b.instrs)
            .any(|n| matches!(&n.instr, Instruction::Assert { .. }));
        assert!(has_assert, "Assert instruction missing");
    }

    // ── 8. Deterministik IR dump ──────────────────────────────────────────
    #[test]
    fn test_deterministic_dump() {
        let src = "contract T { pub fn main() -> u64 { let a = 1; return a; } }";
        let prog1 = lower_source(src).expect("1st lower failed");
        let prog2 = lower_source(src).expect("2nd lower failed");
        let dump1 = format!("{prog1}");
        let dump2 = format!("{prog2}");
        assert_eq!(dump1, dump2, "IR dump is non-deterministic");
    }

    // ── 9. while loop ──────────────────────────────────────────────
    #[test]
    fn test_while_lowering() {
        let prog = lower_source(
            r"contract T {
                pub fn main() -> u64 {
                    let i = 0;
                    while (i < 10) {
                        i = i + 1;
                    }
                    return i;
                }
            }",
        )
        .expect("lowering failed");
        let f = &prog.functions[0];
        // while → header (branch) + body (jump back) + exit
        assert!(
            f.blocks.len() >= 4,
            "expected >= 4 blocks for while, got {}",
            f.blocks.len()
        );
    }

    // ── 10. emit deyimi ──────────────────────────────────────────────────
    #[test]
    fn test_emit_lowering() {
        let prog = lower_source("contract T { pub fn main() { let x = 42; emit Transfer(x); } }")
            .expect("lowering failed");
        let f = &prog.functions[0];
        let has_emit = f
            .blocks
            .iter()
            .flat_map(|b| &b.instrs)
            .any(|n| matches!(&n.instr, Instruction::Emit { .. }));
        assert!(has_emit, "Emit instruction missing");
    }

    // ── 11. Poseidon call ──────────────────────────────────────────
    #[test]
    fn test_poseidon_lowering() {
        let prog = lower_source(
            "contract T { pub fn main() -> u64 { let h = poseidon(1, 2); return h; } }",
        )
        .expect("lowering failed");
        let f = &prog.functions[0];
        let has_poseidon = f
            .blocks
            .iter()
            .flat_map(|b| &b.instrs)
            .any(|n| matches!(&n.instr, Instruction::Poseidon { .. }));
        assert!(has_poseidon, "Poseidon instruction missing");
    }
}
