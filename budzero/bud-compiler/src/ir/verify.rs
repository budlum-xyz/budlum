//! Structural verifier for BudIR.
//!
//! WIRING: `verify_program` and `verify_function` are reached by the BudIR
//! pipeline slice that routes `compile()` through this module (the next
//! integration step described in `ir/mod.rs`); the note stays until that
//! call-site lands.
//!
//! Catches mistakes in lowering output or hand-built IR early.
//! An LLVM IR verifier for our IR: it checks IR invariants before
//! a backend ever sees them.
//!
//! ## Checked invariants
//! 1. Is every used `ValueId` defined? (SSA single-def)
//! 2. Is any `ValueId` defined more than once?
//! 3. Do the `BlockId`s referenced by terminators and instructions exist?
//! 4. Does every block end with exactly one Terminator?
//! 5. Is the type of a `Return` value compatible with the function's return type?
//! 6. Is a `Branch` condition `Bool`?
//! 7. Do arithmetic operand types match?
//! 8. Are the `LocalId`s in `ReadLocal` / `WriteLocal` valid?
//! 9. Are parameter `ValueId`s treated as valid definitions?

use std::collections::{HashMap, HashSet};

use super::{
    BasicBlock, BlockId, FunctionId, Instruction, IrFunction, IrProgram, IrType, LocalId,
    Terminator, ValueId,
};

// ─── Error type ────────────────────────────────────────────────────────────

/// IR verification error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// A referenced `ValueId` is defined nowhere.
    UndefinedValue { value: ValueId, in_function: String },
    /// The same `ValueId` is defined more than once.
    DuplicateValueDef { value: ValueId, in_function: String },
    /// A referenced `BlockId` does not exist inside the function.
    UndefinedBlock { block: BlockId, in_function: String },
    /// A block ends without a Terminator.
    MissingTerminator { block: BlockId, in_function: String },
    /// The type of a `Return` value conflicts with the function's return type.
    ReturnTypeMismatch {
        expected: IrType,
        got: Option<IrType>,
        in_function: String,
    },
    /// A `Branch` condition type is not `Bool`.
    BranchConditionNotBool {
        value: ValueId,
        actual_ty: IrType,
        in_function: String,
    },
    /// Arithmetic or comparison operand types do not match.
    OperandTypeMismatch {
        lhs_ty: IrType,
        rhs_ty: IrType,
        in_function: String,
    },
    /// A `LocalId` outside the function's `locals` list.
    UndefinedLocal { local: LocalId, in_function: String },
    /// Function not found (program-level cross-reference).
    UndefinedFunction {
        function: FunctionId,
        in_caller: String,
    },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::UndefinedValue { value, in_function } => {
                write!(f, "fn {in_function}: undefined value %{}", value.0)
            }
            VerifyError::DuplicateValueDef { value, in_function } => {
                write!(
                    f,
                    "fn {in_function}: value %{} defined more than once",
                    value.0
                )
            }
            VerifyError::UndefinedBlock { block, in_function } => {
                write!(f, "fn {in_function}: undefined block bb{}", block.0)
            }
            VerifyError::MissingTerminator { block, in_function } => {
                write!(f, "fn {in_function}: block bb{} has no terminator", block.0)
            }
            VerifyError::ReturnTypeMismatch {
                expected,
                got,
                in_function,
            } => {
                write!(
                    f,
                    "fn {in_function}: return type mismatch - expected {expected:?}, got {got:?}"
                )
            }
            VerifyError::BranchConditionNotBool {
                value,
                actual_ty,
                in_function,
            } => {
                write!(
                    f,
                    "fn {in_function}: branch condition %{} has type {actual_ty:?} (expected Bool)",
                    value.0
                )
            }
            VerifyError::OperandTypeMismatch {
                lhs_ty,
                rhs_ty,
                in_function,
            } => {
                write!(
                    f,
                    "fn {in_function}: operand type mismatch - lhs {lhs_ty:?}, rhs {rhs_ty:?}"
                )
            }
            VerifyError::UndefinedLocal { local, in_function } => {
                write!(f, "fn {in_function}: undefined local l{}", local.0)
            }
            VerifyError::UndefinedFunction {
                function,
                in_caller,
            } => {
                write!(
                    f,
                    "fn {in_caller}: call to undefined function id {}",
                    function.0
                )
            }
        }
    }
}

impl std::error::Error for VerifyError {}

// ─── Public entry points ──────────────────────────────────────────────────

/// Verifies the whole program. Returns the first error found.
pub fn verify_program(program: &IrProgram) -> Result<(), VerifyError> {
    let valid_fids: HashSet<FunctionId> = program.functions.iter().map(|f| f.id).collect();
    let signatures: HashMap<FunctionId, (Vec<IrType>, IrType)> = program
        .functions
        .iter()
        .map(|f| {
            let param_tys = f.params.iter().map(|(_, ty)| ty.clone()).collect();
            (f.id, (param_tys, f.ret_ty.clone()))
        })
        .collect();

    for func in &program.functions {
        verify_function(func, &valid_fids)?;
        verify_function_call_signatures(func, &signatures)?;
    }
    Ok(())
}

fn verify_function_call_signatures(
    func: &IrFunction,
    signatures: &HashMap<FunctionId, (Vec<IrType>, IrType)>,
) -> Result<(), VerifyError> {
    let mut defined: HashMap<ValueId, IrType> = HashMap::new();
    for (vid, ty) in &func.params {
        defined.insert(*vid, ty.clone());
    }
    for block in &func.blocks {
        for node in &block.instrs {
            if let (Some(vid), Some(ty)) = (node.result, node.instr.result_type()) {
                defined.insert(vid, ty);
            }
        }
    }
    for block in &func.blocks {
        for node in &block.instrs {
            if let Instruction::Call {
                function,
                args,
                ret_ty,
            } = &node.instr
            {
                let (param_tys, expected_ret) = signatures.get(function).ok_or_else(|| {
                    VerifyError::UndefinedFunction {
                        function: *function,
                        in_caller: func.name.clone(),
                    }
                })?;
                if expected_ret != ret_ty {
                    return Err(VerifyError::ReturnTypeMismatch {
                        expected: expected_ret.clone(),
                        got: Some(ret_ty.clone()),
                        in_function: func.name.clone(),
                    });
                }
                if args.len() != param_tys.len() {
                    return Err(VerifyError::OperandTypeMismatch {
                        lhs_ty: param_tys.first().cloned().unwrap_or(IrType::Void),
                        rhs_ty: args
                            .first()
                            .and_then(|v| defined.get(v).cloned())
                            .unwrap_or(IrType::Void),
                        in_function: func.name.clone(),
                    });
                }
                for (arg_vid, expected_ty) in args.iter().zip(param_tys.iter()) {
                    let arg_ty = check_value_ref(*arg_vid, &func.name, &defined)?;
                    if &arg_ty != expected_ty {
                        return Err(VerifyError::OperandTypeMismatch {
                            lhs_ty: expected_ty.clone(),
                            rhs_ty: arg_ty,
                            in_function: func.name.clone(),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

/// Verifies a single function.
pub fn verify_function(
    func: &IrFunction,
    valid_fids: &HashSet<FunctionId>,
) -> Result<(), VerifyError> {
    let fname = &func.name;
    let local_count = func.locals.len();
    let valid_blocks: HashSet<BlockId> = func.blocks.iter().map(|b| b.id).collect();

    // ── 1. Collect defined ValueIds: params first ────────────────
    let mut defined: HashMap<ValueId, IrType> = HashMap::new();
    let mut defined_order: Vec<ValueId> = Vec::new();

    for (vid, ty) in &func.params {
        if defined.insert(*vid, ty.clone()).is_some() {
            return Err(VerifyError::DuplicateValueDef {
                value: *vid,
                in_function: fname.clone(),
            });
        }
        defined_order.push(*vid);
    }

    // ── 2. Pre-scan all instructions (the definition set) ────────
    // (The verifier uses a flat "all definitions" set; no dominance
    //  analysis. Enough for this pre-SSA IR.)
    for block in &func.blocks {
        for node in &block.instrs {
            // A node with `result: Some` carries a value-producing
            // instruction, so `result_type` is `Some`; a `None` here would be
            // an inconsistency inside this crate, not user input.
            if let (Some(vid), Some(ty)) = (node.result, node.instr.result_type()) {
                if defined.insert(vid, ty).is_some() {
                    return Err(VerifyError::DuplicateValueDef {
                        value: vid,
                        in_function: fname.clone(),
                    });
                }
                defined_order.push(vid);
            }
        }
    }

    // ── 3. Verify each block one by one ──────────────────────────
    for block in &func.blocks {
        verify_block(
            block,
            func,
            fname,
            &defined,
            &valid_blocks,
            valid_fids,
            local_count,
        )?;
    }

    Ok(())
}

fn verify_block(
    block: &BasicBlock,
    func: &IrFunction,
    fname: &str,
    defined: &HashMap<ValueId, IrType>,
    valid_blocks: &HashSet<BlockId>,
    valid_fids: &HashSet<FunctionId>,
    local_count: usize,
) -> Result<(), VerifyError> {
    // ── Check the instructions ───────────────────────────────────
    for node in &block.instrs {
        if node.result.is_some() != node.instr.result_type().is_some() {
            return Err(VerifyError::ReturnTypeMismatch {
                expected: node.instr.result_type().unwrap_or(IrType::Void),
                got: None,
                in_function: fname.to_string(),
            });
        }
        verify_instr(
            &node.instr,
            func,
            fname,
            defined,
            valid_blocks,
            valid_fids,
            local_count,
        )?;
    }

    // ── Check the terminator ─────────────────────────────────────
    let term = block
        .terminator
        .as_ref()
        .ok_or_else(|| VerifyError::MissingTerminator {
            block: block.id,
            in_function: fname.to_string(),
        })?;

    match term {
        Terminator::Jump(target) => {
            check_block_ref(*target, fname, valid_blocks)?;
        }
        Terminator::Branch {
            condition,
            then_block,
            else_block,
        } => {
            // The condition type must be Bool.
            let cond_ty = defined
                .get(condition)
                .ok_or_else(|| VerifyError::UndefinedValue {
                    value: *condition,
                    in_function: fname.to_string(),
                })?;
            if *cond_ty != IrType::Bool {
                return Err(VerifyError::BranchConditionNotBool {
                    value: *condition,
                    actual_ty: cond_ty.clone(),
                    in_function: fname.to_string(),
                });
            }
            check_block_ref(*then_block, fname, valid_blocks)?;
            check_block_ref(*else_block, fname, valid_blocks)?;
        }
        Terminator::Return(maybe_val) => {
            let got_ty = match maybe_val {
                Some(vid) => {
                    let ty = defined
                        .get(vid)
                        .ok_or_else(|| VerifyError::UndefinedValue {
                            value: *vid,
                            in_function: fname.to_string(),
                        })?
                        .clone();
                    Some(ty)
                }
                None => None,
            };

            // Return-type compatibility (Void = None, non-void = Some).
            let expected = &func.ret_ty;
            let matches = match (expected, &got_ty) {
                (IrType::Void, None) => true,
                (IrType::Void, Some(_)) => false,
                (_, None) => false,
                (exp, Some(got)) => exp == got,
            };
            if !matches {
                return Err(VerifyError::ReturnTypeMismatch {
                    expected: expected.clone(),
                    got: got_ty,
                    in_function: fname.to_string(),
                });
            }
        }
        Terminator::Unreachable => {}
    }

    Ok(())
}

fn verify_instr(
    instr: &Instruction,
    func: &IrFunction,
    fname: &str,
    defined: &HashMap<ValueId, IrType>,
    valid_blocks: &HashSet<BlockId>,
    valid_fids: &HashSet<FunctionId>,
    local_count: usize,
) -> Result<(), VerifyError> {
    match instr {
        Instruction::Const { .. } => {}

        Instruction::Add { lhs, rhs, ty }
        | Instruction::Sub { lhs, rhs, ty }
        | Instruction::Mul { lhs, rhs, ty }
        | Instruction::Div { lhs, rhs, ty } => {
            let l_ty = check_value_ref(*lhs, fname, defined)?;
            let r_ty = check_value_ref(*rhs, fname, defined)?;
            if &l_ty != ty || &r_ty != ty {
                return Err(VerifyError::OperandTypeMismatch {
                    lhs_ty: l_ty,
                    rhs_ty: r_ty,
                    in_function: fname.to_string(),
                });
            }
        }

        Instruction::IrEq { lhs, rhs, ty }
        | Instruction::IrNe { lhs, rhs, ty }
        | Instruction::Lt { lhs, rhs, ty }
        | Instruction::Le { lhs, rhs, ty }
        | Instruction::Gt { lhs, rhs, ty }
        | Instruction::Ge { lhs, rhs, ty } => {
            let l_ty = check_value_ref(*lhs, fname, defined)?;
            let r_ty = check_value_ref(*rhs, fname, defined)?;
            if &l_ty != ty || &r_ty != ty {
                return Err(VerifyError::OperandTypeMismatch {
                    lhs_ty: l_ty,
                    rhs_ty: r_ty,
                    in_function: fname.to_string(),
                });
            }
        }

        Instruction::Load { base, .. } => {
            check_value_ref(*base, fname, defined)?;
        }
        Instruction::Store { base, value, .. } => {
            check_value_ref(*base, fname, defined)?;
            check_value_ref(*value, fname, defined)?;
        }

        Instruction::StateRead { .. } => {}
        Instruction::StateWrite { value, .. } => {
            check_value_ref(*value, fname, defined)?;
        }

        Instruction::ReadLocal { local, ty } => {
            check_local_ref(*local, fname, local_count)?;
            let slot_ty = &func.locals[local.index()];
            if slot_ty != ty {
                return Err(VerifyError::OperandTypeMismatch {
                    lhs_ty: slot_ty.clone(),
                    rhs_ty: ty.clone(),
                    in_function: fname.to_string(),
                });
            }
        }
        Instruction::WriteLocal { local, value } => {
            check_local_ref(*local, fname, local_count)?;
            let val_ty = check_value_ref(*value, fname, defined)?;
            let slot_ty = &func.locals[local.index()];
            if &val_ty != slot_ty {
                return Err(VerifyError::OperandTypeMismatch {
                    lhs_ty: slot_ty.clone(),
                    rhs_ty: val_ty,
                    in_function: fname.to_string(),
                });
            }
        }

        Instruction::Call { function, args, .. } => {
            if !valid_fids.contains(function) {
                return Err(VerifyError::UndefinedFunction {
                    function: *function,
                    in_caller: fname.to_string(),
                });
            }
            for &arg in args {
                check_value_ref(arg, fname, defined)?;
            }
        }

        Instruction::Assert { condition } => {
            let cond_ty = check_value_ref(*condition, fname, defined)?;
            if cond_ty != IrType::Bool {
                return Err(VerifyError::BranchConditionNotBool {
                    value: *condition,
                    actual_ty: cond_ty,
                    in_function: fname.to_string(),
                });
            }
        }
        Instruction::Poseidon { lhs, rhs } => {
            let l_ty = check_value_ref(*lhs, fname, defined)?;
            let r_ty = check_value_ref(*rhs, fname, defined)?;
            if !matches!(l_ty, IrType::U64 | IrType::Field)
                || !matches!(r_ty, IrType::U64 | IrType::Field)
            {
                return Err(VerifyError::OperandTypeMismatch {
                    lhs_ty: l_ty,
                    rhs_ty: r_ty,
                    in_function: fname.to_string(),
                });
            }
        }
        Instruction::Emit { args, .. } => {
            for &arg in args {
                check_value_ref(arg, fname, defined)?;
            }
        }
        Instruction::ContextRead { .. } => {}
    }

    let _ = valid_blocks; // reserved for tighter CFG checks later
    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────────

fn check_value_ref(
    vid: ValueId,
    fname: &str,
    defined: &HashMap<ValueId, IrType>,
) -> Result<IrType, VerifyError> {
    defined
        .get(&vid)
        .cloned()
        .ok_or_else(|| VerifyError::UndefinedValue {
            value: vid,
            in_function: fname.to_string(),
        })
}

fn check_block_ref(
    bid: BlockId,
    fname: &str,
    valid_blocks: &HashSet<BlockId>,
) -> Result<(), VerifyError> {
    if valid_blocks.contains(&bid) {
        Ok(())
    } else {
        Err(VerifyError::UndefinedBlock {
            block: bid,
            in_function: fname.to_string(),
        })
    }
}

fn check_local_ref(local: LocalId, fname: &str, local_count: usize) -> Result<(), VerifyError> {
    if local.index() < local_count {
        Ok(())
    } else {
        Err(VerifyError::UndefinedLocal {
            local,
            in_function: fname.to_string(),
        })
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        BasicBlock, BlockId, FunctionId, InstrNode, Instruction, IrFunction, IrProgram, IrType,
        LocalId, Terminator, ValueId,
    };

    /// Helper that builds a minimal valid program.
    fn valid_program() -> IrProgram {
        // fn test() -> u64 {
        //   %0 = const.u64 42
        //   ret %0
        // }
        let block = BasicBlock {
            id: BlockId::new(0),
            instrs: vec![InstrNode {
                result: Some(ValueId::new(0)),
                instr: Instruction::Const {
                    ty: IrType::U64,
                    value: 42,
                },
            }],
            terminator: Some(Terminator::Return(Some(ValueId::new(0)))),
        };
        let func = IrFunction {
            id: FunctionId(0),
            name: "test".to_string(),
            params: vec![],
            ret_ty: IrType::U64,
            blocks: vec![block],
            locals: vec![],
        };
        IrProgram {
            functions: vec![func],
            function_names: [("test".to_string(), FunctionId(0))].into(),
        }
    }

    // ── 9. The verifier accepts a valid IR ───────────────────────
    #[test]
    fn verifier_accepts_valid_program() {
        let prog = valid_program();
        assert!(verify_program(&prog).is_ok());
    }

    // ── 10. The verifier rejects an undefined ValueId ────────────
    #[test]
    fn verifier_rejects_undefined_value() {
        let block = BasicBlock {
            id: BlockId::new(0),
            instrs: vec![InstrNode {
                result: Some(ValueId::new(0)),
                instr: Instruction::Add {
                    ty: IrType::U64,
                    lhs: ValueId::new(99), // undefined!
                    rhs: ValueId::new(99), // undefined!
                },
            }],
            terminator: Some(Terminator::Return(Some(ValueId::new(0)))),
        };
        let func = IrFunction {
            id: FunctionId(0),
            name: "bad".to_string(),
            params: vec![],
            ret_ty: IrType::U64,
            blocks: vec![block],
            locals: vec![],
        };
        let prog = IrProgram {
            functions: vec![func],
            function_names: Default::default(),
        };
        let result = verify_program(&prog);
        assert!(
            matches!(result, Err(VerifyError::UndefinedValue { .. })),
            "expected UndefinedValue, got: {result:?}"
        );
    }

    // ── 11. The verifier rejects an undefined BlockId ────────────
    #[test]
    fn verifier_rejects_undefined_block() {
        let block = BasicBlock {
            id: BlockId::new(0),
            instrs: vec![InstrNode {
                result: Some(ValueId::new(0)),
                instr: Instruction::Const {
                    ty: IrType::U64,
                    value: 1,
                },
            }],
            // bb999 does not exist!
            terminator: Some(Terminator::Jump(BlockId::new(999))),
        };
        let func = IrFunction {
            id: FunctionId(0),
            name: "bad".to_string(),
            params: vec![],
            ret_ty: IrType::Void,
            blocks: vec![block],
            locals: vec![],
        };
        let prog = IrProgram {
            functions: vec![func],
            function_names: Default::default(),
        };
        let result = verify_program(&prog);
        assert!(
            matches!(result, Err(VerifyError::UndefinedBlock { .. })),
            "expected UndefinedBlock, got: {result:?}"
        );
    }

    // ── 12. The verifier rejects a missing terminator ────────────
    #[test]
    fn verifier_rejects_missing_terminator() {
        let block = BasicBlock {
            id: BlockId::new(0),
            instrs: vec![],
            terminator: None, // missing!
        };
        let func = IrFunction {
            id: FunctionId(0),
            name: "bad".to_string(),
            params: vec![],
            ret_ty: IrType::Void,
            blocks: vec![block],
            locals: vec![],
        };
        let prog = IrProgram {
            functions: vec![func],
            function_names: Default::default(),
        };
        assert!(matches!(
            verify_program(&prog),
            Err(VerifyError::MissingTerminator { .. })
        ));
    }

    // ── 13. The verifier rejects a non-Bool branch condition ─────
    #[test]
    fn verifier_rejects_non_bool_branch_condition() {
        let bb1 = BasicBlock {
            id: BlockId::new(1),
            instrs: vec![],
            terminator: Some(Terminator::Return(None)),
        };
        let bb2 = BasicBlock {
            id: BlockId::new(2),
            instrs: vec![],
            terminator: Some(Terminator::Return(None)),
        };
        let block = BasicBlock {
            id: BlockId::new(0),
            instrs: vec![InstrNode {
                result: Some(ValueId::new(0)),
                // returns U64, not Bool
                instr: Instruction::Const {
                    ty: IrType::U64,
                    value: 1,
                },
            }],
            terminator: Some(Terminator::Branch {
                condition: ValueId::new(0), // U64, not Bool!
                then_block: BlockId::new(1),
                else_block: BlockId::new(2),
            }),
        };
        let func = IrFunction {
            id: FunctionId(0),
            name: "bad".to_string(),
            params: vec![],
            ret_ty: IrType::Void,
            blocks: vec![block, bb1, bb2],
            locals: vec![],
        };
        let prog = IrProgram {
            functions: vec![func],
            function_names: Default::default(),
        };
        assert!(matches!(
            verify_program(&prog),
            Err(VerifyError::BranchConditionNotBool { .. })
        ),);
    }

    // ── 14. The verifier rejects a wrong return type ─────────────
    #[test]
    fn verifier_rejects_wrong_return_type() {
        let block = BasicBlock {
            id: BlockId::new(0),
            instrs: vec![InstrNode {
                result: Some(ValueId::new(0)),
                instr: Instruction::Const {
                    ty: IrType::U64,
                    value: 5,
                },
            }],
            terminator: Some(Terminator::Return(Some(ValueId::new(0)))),
        };
        let func = IrFunction {
            id: FunctionId(0),
            name: "bad".to_string(),
            params: vec![],
            ret_ty: IrType::Void, // function must return void but returns U64
            blocks: vec![block],
            locals: vec![],
        };
        let prog = IrProgram {
            functions: vec![func],
            function_names: Default::default(),
        };
        assert!(matches!(
            verify_program(&prog),
            Err(VerifyError::ReturnTypeMismatch { .. })
        ));
    }

    // ── 15. The verifier rejects a doubly-defined ValueId ────────
    #[test]
    fn verifier_rejects_duplicate_value_def() {
        let block = BasicBlock {
            id: BlockId::new(0),
            instrs: vec![
                InstrNode {
                    result: Some(ValueId::new(0)),
                    instr: Instruction::Const {
                        ty: IrType::U64,
                        value: 1,
                    },
                },
                InstrNode {
                    result: Some(ValueId::new(0)), // duplicate!
                    instr: Instruction::Const {
                        ty: IrType::U64,
                        value: 2,
                    },
                },
            ],
            terminator: Some(Terminator::Return(Some(ValueId::new(0)))),
        };
        let func = IrFunction {
            id: FunctionId(0),
            name: "bad".to_string(),
            params: vec![],
            ret_ty: IrType::U64,
            blocks: vec![block],
            locals: vec![],
        };
        let prog = IrProgram {
            functions: vec![func],
            function_names: Default::default(),
        };
        assert!(matches!(
            verify_program(&prog),
            Err(VerifyError::DuplicateValueDef { .. })
        ));
    }

    // ── 16. The verifier rejects an undefined LocalId ────────────
    #[test]
    fn verifier_rejects_undefined_local() {
        let block = BasicBlock {
            id: BlockId::new(0),
            instrs: vec![InstrNode {
                result: Some(ValueId::new(0)),
                instr: Instruction::ReadLocal {
                    local: LocalId::new(99), // locals list is empty - invalid!
                    ty: IrType::U64,
                },
            }],
            terminator: Some(Terminator::Return(Some(ValueId::new(0)))),
        };
        let func = IrFunction {
            id: FunctionId(0),
            name: "bad".to_string(),
            params: vec![],
            ret_ty: IrType::U64,
            blocks: vec![block],
            locals: vec![], // empty - LocalId(99) is invalid
        };
        let prog = IrProgram {
            functions: vec![func],
            function_names: Default::default(),
        };
        assert!(matches!(
            verify_program(&prog),
            Err(VerifyError::UndefinedLocal { .. })
        ));
    }

    // ── 17. The verifier counts function params as defined ───────
    #[test]
    fn verifier_params_are_defined() {
        // fn add(a: u64, b: u64) -> u64 { ret %0 + %1 }  (params %0, %1)
        let block = BasicBlock {
            id: BlockId::new(0),
            instrs: vec![InstrNode {
                result: Some(ValueId::new(2)),
                instr: Instruction::Add {
                    ty: IrType::U64,
                    lhs: ValueId::new(0), // param
                    rhs: ValueId::new(1), // param
                },
            }],
            terminator: Some(Terminator::Return(Some(ValueId::new(2)))),
        };
        let func = IrFunction {
            id: FunctionId(0),
            name: "add".to_string(),
            params: vec![
                (ValueId::new(0), IrType::U64),
                (ValueId::new(1), IrType::U64),
            ],
            ret_ty: IrType::U64,
            blocks: vec![block],
            locals: vec![],
        };
        let prog = IrProgram {
            functions: vec![func],
            function_names: Default::default(),
        };
        assert!(verify_program(&prog).is_ok());
    }

    #[test]
    fn verifier_rejects_local_assert_and_call_type_mismatches() {
        // 1. WriteLocal with Bool into a U64 local slot fails.
        let bad_local_block = BasicBlock {
            id: BlockId::new(0),
            instrs: vec![
                InstrNode {
                    result: Some(ValueId::new(0)),
                    instr: Instruction::Const {
                        ty: IrType::Bool,
                        value: 1,
                    },
                },
                InstrNode {
                    result: None,
                    instr: Instruction::WriteLocal {
                        local: LocalId::new(0),
                        value: ValueId::new(0),
                    },
                },
            ],
            terminator: Some(Terminator::Return(None)),
        };
        let bad_local_fn = IrFunction {
            id: FunctionId(0),
            name: "bad_local".to_string(),
            params: vec![],
            ret_ty: IrType::Void,
            blocks: vec![bad_local_block],
            locals: vec![IrType::U64],
        };
        let prog_local = IrProgram {
            functions: vec![bad_local_fn],
            function_names: Default::default(),
        };
        assert!(matches!(
            verify_program(&prog_local),
            Err(VerifyError::OperandTypeMismatch { .. })
        ));

        // 2. Assert on non-Bool fails.
        let bad_assert_block = BasicBlock {
            id: BlockId::new(0),
            instrs: vec![
                InstrNode {
                    result: Some(ValueId::new(0)),
                    instr: Instruction::Const {
                        ty: IrType::U64,
                        value: 1,
                    },
                },
                InstrNode {
                    result: None,
                    instr: Instruction::Assert {
                        condition: ValueId::new(0),
                    },
                },
            ],
            terminator: Some(Terminator::Return(None)),
        };
        let bad_assert_fn = IrFunction {
            id: FunctionId(0),
            name: "bad_assert".to_string(),
            params: vec![],
            ret_ty: IrType::Void,
            blocks: vec![bad_assert_block],
            locals: vec![],
        };
        let prog_assert = IrProgram {
            functions: vec![bad_assert_fn],
            function_names: Default::default(),
        };
        assert!(matches!(
            verify_program(&prog_assert),
            Err(VerifyError::BranchConditionNotBool { .. })
        ));

        // 3. Call with wrong argument count fails.
        let callee = IrFunction {
            id: FunctionId(0),
            name: "callee".to_string(),
            params: vec![(ValueId::new(0), IrType::U64)],
            ret_ty: IrType::U64,
            blocks: vec![BasicBlock {
                id: BlockId::new(0),
                instrs: vec![],
                terminator: Some(Terminator::Return(Some(ValueId::new(0)))),
            }],
            locals: vec![],
        };
        let caller = IrFunction {
            id: FunctionId(1),
            name: "caller".to_string(),
            params: vec![],
            ret_ty: IrType::U64,
            blocks: vec![BasicBlock {
                id: BlockId::new(0),
                instrs: vec![InstrNode {
                    result: Some(ValueId::new(0)),
                    instr: Instruction::Call {
                        function: FunctionId(0),
                        args: vec![],
                        ret_ty: IrType::U64,
                    },
                }],
                terminator: Some(Terminator::Return(Some(ValueId::new(0)))),
            }],
            locals: vec![],
        };
        let prog_call = IrProgram {
            functions: vec![callee, caller],
            function_names: Default::default(),
        };
        assert!(matches!(
            verify_program(&prog_call),
            Err(VerifyError::OperandTypeMismatch { .. })
        ));
    }
}
