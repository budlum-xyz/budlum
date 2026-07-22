use crate::ast::*;
use crate::CompileError;
use bud_isa::{Instruction, IsaProfile, Opcode};

/// Per-variable codegen metadata. Alongside the assigned register we
/// track the struct type a variable holds (when it holds a struct
/// pointer). `FieldAccess` uses this to resolve the field offset within
/// the base expression's *actual* struct layout instead of guessing by
/// scanning every declared struct — which is wrong (and, because
/// `struct_layouts` is a hash map, non-deterministic) as soon as two
/// structs declare a field with the same name at different positions.
///
/// This mirrors the semantic analyzer, whose environment already maps
/// each variable to a `Type` (including `Type::Struct(name)`); codegen
/// is a separate pass and therefore keeps its own minimal type record.
#[derive(Clone)]
struct VarInfo {
    reg: u8,
    /// `Some(struct_name)` when this variable holds a pointer to that
    /// struct; `None` for scalar values (u64 / bool / field) or when
    /// the type cannot be resolved statically.
    struct_type: Option<String>,
}

#[allow(dead_code)]
pub struct Codegen {
    instructions: Vec<u64>,
    next_reg: u8,
    profile: IsaProfile,
    error: Option<CompileError>,
    unpatched_calls: Vec<(usize, String)>,
    struct_layouts: std::collections::HashMap<String, Vec<String>>,
}

impl Default for Codegen {
    fn default() -> Self {
        Self::new()
    }
}

impl Codegen {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            next_reg: 1,
            profile: IsaProfile::Production,
            error: None,
            unpatched_calls: Vec::new(),
            struct_layouts: std::collections::HashMap::new(),
        }
    }

    pub fn new_with_profile(profile: IsaProfile) -> Self {
        Self {
            instructions: Vec::new(),
            next_reg: 1,
            profile,
            error: None,
            unpatched_calls: Vec::new(),
            struct_layouts: std::collections::HashMap::new(),
        }
    }

    pub fn generate(&mut self, contract: &Contract) -> Result<Vec<u64>, CompileError> {
        // Populate struct layouts
        for s in &contract.structs {
            let mut fields = Vec::new();
            for f in &s.fields {
                fields.push(f.name.clone());
            }
            self.struct_layouts.insert(s.name.clone(), fields);
        }

        self.emit(Opcode::Load, 31, 0, 0, 4096); // Initialize heap ptr!
        let jump_to_main_idx = self.instructions.len();
        self.emit(Opcode::Call, 0, 0, 0, 0);
        self.emit(Opcode::Halt, 0, 0, 0, 0);

        let mut func_offsets = std::collections::HashMap::new();

        for func in &contract.functions {
            func_offsets.insert(func.name.clone(), self.instructions.len());
            self.generate_function(func, contract);
        }

        // Patch main call
        if let Some(main_idx) = func_offsets.get("main") {
            self.patch_jump(
                jump_to_main_idx,
                (*main_idx as i32) - (jump_to_main_idx as i32),
            );
        } else {
            self.error = Some(CompileError::CodegenError(
                "main function not found".to_string(),
            ));
        }

        let unpatched = std::mem::take(&mut self.unpatched_calls);
        for (call_idx, func_name) in unpatched {
            if let Some(target_idx) = func_offsets.get(&func_name) {
                self.patch_jump(call_idx, (*target_idx as i32) - (call_idx as i32));
            } else {
                self.error = Some(CompileError::CodegenError(format!(
                    "Undefined function {}",
                    func_name
                )));
            }
        }

        if let Some(err) = self.error.take() {
            Err(err)
        } else {
            Ok(self.instructions.clone())
        }
    }

    fn generate_function(&mut self, func: &Function, contract: &Contract) {
        if self.error.is_some() {
            return;
        }

        self.next_reg = 1;
        let mut scope: std::collections::HashMap<String, VarInfo> =
            std::collections::HashMap::new();

        let ret_addr_reg = self.alloc_reg();
        self.emit(Opcode::Pop, ret_addr_reg, 0, 0, 0);

        let mut param_regs = Vec::new();
        for _ in 0..func.params.len() {
            param_regs.push(self.alloc_reg());
        }

        for param_reg in param_regs.iter().rev() {
            self.emit(Opcode::Pop, *param_reg, 0, 0, 0);
        }

        for (param, reg) in func.params.iter().zip(param_regs.iter()) {
            // A parameter whose declared type names a struct holds a
            // struct pointer — record that so `FieldAccess` on the
            // parameter resolves against the correct layout.
            let struct_type = if self.struct_layouts.contains_key(&param.ty) {
                Some(param.ty.clone())
            } else {
                None
            };
            scope.insert(
                param.name.clone(),
                VarInfo {
                    reg: *reg,
                    struct_type,
                },
            );
        }

        self.emit(Opcode::Push, 0, ret_addr_reg, 0, 0);

        let mut storage_map = std::collections::HashMap::new();
        for (i, field) in contract.storage.iter().enumerate() {
            storage_map.insert(field.name.clone(), i as i32);
        }

        for stmt in &func.body {
            self.generate_stmt(stmt, &mut scope, &storage_map);
        }

        let temp = self.alloc_reg();
        self.emit(Opcode::Pop, temp, 0, 0, 0);
        let zero = self.alloc_reg();
        self.emit(Opcode::Load, zero, 0, 0, 0);
        self.emit(Opcode::Push, 0, zero, 0, 0);
        self.emit(Opcode::Push, 0, temp, 0, 0);
        self.emit(Opcode::Ret, 0, 0, 0, 0);
    }

    fn generate_stmt(
        &mut self,
        stmt: &Stmt,
        scope: &mut std::collections::HashMap<String, VarInfo>,
        storage: &std::collections::HashMap<String, i32>,
    ) {
        if self.error.is_some() {
            return;
        }

        let saved_reg = self.next_reg;

        match stmt {
            Stmt::Let(name, expr) => {
                // Resolve the bound struct type (if any) *before*
                // generating the expression: the lookup is read-only on
                // the AST/scope and must not see the variable being
                // defined. For a `StructLiteral` this is the literal's
                // own type; for an `Ident` it is the aliased variable's
                // recorded type; otherwise it is `None`.
                let struct_type = self.expr_struct_type(expr, scope);
                let reg = self.generate_expr(expr, scope, storage);
                scope.insert(name.clone(), VarInfo { reg, struct_type });
                if reg >= saved_reg {
                    self.next_reg = reg + 1;
                } else {
                    self.next_reg = saved_reg;
                }
            }
            Stmt::Constrain(expr) => {
                let reg = self.generate_expr(expr, scope, storage);
                self.emit(Opcode::Assert, 0, reg, 0, 0);
                self.next_reg = saved_reg;
            }
            Stmt::StorageWrite(name, expr) => {
                let reg = self.generate_expr(expr, scope, storage);
                let slot = match storage.get(name) {
                    Some(s) => *s,
                    None => {
                        if self.error.is_none() {
                            self.error = Some(CompileError::CodegenError(format!(
                                "Unknown storage variable: {}",
                                name
                            )));
                        }
                        return;
                    }
                };
                self.emit(Opcode::SWrite, 0, reg, 0, slot);
                self.next_reg = saved_reg;
            }
            Stmt::MappingWrite(name, key, val) => {
                let base_slot = match storage.get(name) {
                    Some(s) => *s,
                    None => {
                        if self.error.is_none() {
                            self.error = Some(CompileError::CodegenError(format!(
                                "Unknown mapping variable: {}",
                                name
                            )));
                        }
                        return;
                    }
                };
                let key_reg = self.generate_expr(key, scope, storage);
                let val_reg = self.generate_expr(val, scope, storage);

                let base_reg = self.alloc_reg();
                self.emit(Opcode::Load, base_reg, 0, 0, base_slot);

                let target_slot_reg = self.alloc_reg();
                self.emit(Opcode::Poseidon, target_slot_reg, base_reg, key_reg, 0);

                self.emit(Opcode::SWrite, 0, val_reg, target_slot_reg, -1);
                self.next_reg = saved_reg;
            }
            Stmt::Assign(name, expr) => {
                let reg = self.generate_expr(expr, scope, storage);
                let target_reg = match scope.get(name) {
                    Some(vi) => vi.reg,
                    None => {
                        if self.error.is_none() {
                            self.error = Some(CompileError::CodegenError(format!(
                                "Undefined variable: {}",
                                name
                            )));
                        }
                        return;
                    }
                };
                self.emit(Opcode::Add, target_reg, reg, 0, 0);
                self.next_reg = saved_reg;
            }
            Stmt::If(cond, then_branch, else_branch) => {
                let cond_reg = self.generate_expr(cond, scope, storage);
                let jump_to_then_idx = self.instructions.len();
                self.emit(Opcode::Jnz, 0, cond_reg, 0, 0);
                self.next_reg = saved_reg;

                if let Some(eb) = else_branch {
                    for s in eb {
                        self.generate_stmt(s, scope, storage);
                    }
                }
                let jump_to_end_idx = self.instructions.len();
                self.emit(Opcode::Jmp, 0, 0, 0, 0);

                let then_start_idx = self.instructions.len();
                for s in then_branch {
                    self.generate_stmt(s, scope, storage);
                }
                let end_idx = self.instructions.len();

                self.patch_jump(
                    jump_to_then_idx,
                    (then_start_idx as i32) - (jump_to_then_idx as i32),
                );
                self.patch_jump(jump_to_end_idx, (end_idx as i32) - (jump_to_end_idx as i32));
            }
            Stmt::While(cond, body) => {
                let start_idx = self.instructions.len();
                let cond_reg = self.generate_expr(cond, scope, storage);

                let jump_to_body_idx = self.instructions.len();
                self.emit(Opcode::Jnz, 0, cond_reg, 0, 0);
                self.next_reg = saved_reg;

                let jump_to_end_idx = self.instructions.len();
                self.emit(Opcode::Jmp, 0, 0, 0, 0);

                let body_start_idx = self.instructions.len();
                for s in body {
                    self.generate_stmt(s, scope, storage);
                }

                let current_idx = self.instructions.len();
                self.emit(
                    Opcode::Jmp,
                    0,
                    0,
                    0,
                    (start_idx as i32) - (current_idx as i32),
                );

                let end_idx = self.instructions.len();
                self.patch_jump(
                    jump_to_body_idx,
                    (body_start_idx as i32) - (jump_to_body_idx as i32),
                );
                self.patch_jump(jump_to_end_idx, (end_idx as i32) - (jump_to_end_idx as i32));
            }
            Stmt::Match { scrutinee, arms } => {
                // Task 0.14: pattern matching codegen. ZK-circuit-friendly
                // linear jump chain — at most one arm body executes per
                // match, so the prover's trace records exactly one
                // branch (no non-determinism).
                //
                // Layout per arm (integer pattern):
                //     Load    tmp, <pattern_literal>
                //     Sub     diff, scrutinee, tmp
                //     Jnz     body, diff, _, _       ; jump if diff == 0 (match)
                //     <body statements>
                //     Jmp     end
                //
                // Layout per arm (wildcard `_`):
                //     Jmp     body                   ; unconditional
                //     <body statements>
                //     Jmp     end
                //
                // The semantic analyzer enforces that the last arm is a
                // wildcard (otherwise the chain has no fall-through
                // termination, which is undefined).
                let scrutinee_reg = self.generate_expr(scrutinee, scope, storage);
                self.next_reg = saved_reg;

                // Placeholder jumps to the per-arm body, patched once we
                // know where the body starts. Using `Option<usize>`
                // keeps the wildcard and integer-pattern cases
                // symmetric without an extra struct field.
                let mut arm_body_placeholder: Option<usize>;
                let mut end_jump_indices: Vec<usize> = Vec::new();

                for arm in arms {
                    // Emit the test or unconditional jump. Whichever
                    // path we take, the next instruction is the start
                    // of this arm's body — the placeholder is patched
                    // right after we know the body's first PC.
                    match &arm.pattern {
                        MatchPattern::IntLit(val) => {
                            let pat_reg = self.alloc_reg();
                            self.emit(Opcode::Load, pat_reg, 0, 0, *val as i32);
                            let diff_reg = self.alloc_reg();
                            self.emit(Opcode::Sub, diff_reg, scrutinee_reg, pat_reg, 0);
                            let placeholder = self.instructions.len();
                            self.emit(Opcode::Jnz, 0, diff_reg, 0, 0);
                            arm_body_placeholder = Some(placeholder);
                            self.next_reg = saved_reg;
                        }
                        MatchPattern::Wildcard => {
                            let placeholder = self.instructions.len();
                            self.emit(Opcode::Jmp, 0, 0, 0, 0);
                            arm_body_placeholder = Some(placeholder);
                        }
                    }

                    // Body of this arm.
                    let body_start = self.instructions.len();
                    for s in &arm.body {
                        self.generate_stmt(s, scope, storage);
                    }
                    // Patch the test/wildcard placeholder to land here.
                    if let Some(placeholder) = arm_body_placeholder.take() {
                        self.patch_jump(placeholder, (body_start as i32) - (placeholder as i32));
                    }
                    // After the body, jump to the end of the match.
                    let end_jump = self.instructions.len();
                    self.emit(Opcode::Jmp, 0, 0, 0, 0);
                    end_jump_indices.push(end_jump);
                    self.next_reg = saved_reg;
                }

                // Patch every arm's end-jump to the instruction after
                // the last arm body. This is the natural "match result"
                // site — the caller is expected to use the produced
                // register if the match ever grows a value (Task 0.16+).
                let end_idx = self.instructions.len();
                for idx in end_jump_indices {
                    self.patch_jump(idx, (end_idx as i32) - (idx as i32));
                }
            }
            Stmt::For {
                var,
                start,
                end,
                body,
            } => {
                let start_reg = self.generate_expr(start, scope, storage);
                let end_reg = self.generate_expr(end, scope, storage);
                let loop_reg = self.alloc_reg();
                self.emit(Opcode::Add, loop_reg, start_reg, 0, 0);
                self.next_reg = loop_reg + 1; // loop var is kept!

                let mut inner_scope = scope.clone();
                inner_scope.insert(
                    var.clone(),
                    VarInfo {
                        reg: loop_reg,
                        struct_type: None, // loop counter is a scalar
                    },
                );

                let start_idx = self.instructions.len();

                let inner_saved = self.next_reg;
                let cond_reg = self.alloc_reg();
                self.emit(Opcode::Lt, cond_reg, loop_reg, end_reg, 0);

                let jump_to_body_idx = self.instructions.len();
                self.emit(Opcode::Jnz, 0, cond_reg, 0, 0);
                self.next_reg = inner_saved;

                let jump_to_end_idx = self.instructions.len();
                self.emit(Opcode::Jmp, 0, 0, 0, 0);

                let body_start_idx = self.instructions.len();
                for s in body {
                    self.generate_stmt(s, &mut inner_scope, storage);
                }

                let one_reg = self.alloc_reg();
                self.emit(Opcode::Load, one_reg, 0, 0, 1);
                self.emit(Opcode::Add, loop_reg, loop_reg, one_reg, 0);
                self.next_reg = inner_saved;

                let current_idx = self.instructions.len();
                self.emit(
                    Opcode::Jmp,
                    0,
                    0,
                    0,
                    (start_idx as i32) - (current_idx as i32),
                );

                let end_idx = self.instructions.len();
                self.patch_jump(
                    jump_to_body_idx,
                    (body_start_idx as i32) - (jump_to_body_idx as i32),
                );
                self.patch_jump(jump_to_end_idx, (end_idx as i32) - (jump_to_end_idx as i32));

                self.next_reg = saved_reg;
            }
            Stmt::Return(expr) => {
                let temp = self.alloc_reg();
                self.emit(Opcode::Pop, temp, 0, 0, 0);

                if let Some(e) = expr {
                    let reg = self.generate_expr(e, scope, storage);
                    self.emit(Opcode::Push, 0, reg, 0, 0);
                } else {
                    let zero = self.alloc_reg();
                    self.emit(Opcode::Load, zero, 0, 0, 0);
                    self.emit(Opcode::Push, 0, zero, 0, 0);
                }

                self.emit(Opcode::Push, 0, temp, 0, 0);
                self.emit(Opcode::Ret, 0, 0, 0, 0);
                self.next_reg = saved_reg;
            }
            Stmt::Emit(_name, args) => {
                for arg in args {
                    let reg = self.generate_expr(arg, scope, storage);
                    self.emit(Opcode::Log, 0, reg, 0, 0);
                }
                self.next_reg = saved_reg;
            }
            Stmt::Expr(expr) => {
                self.generate_expr(expr, scope, storage);
                self.next_reg = saved_reg;
            }
        }
    }

    fn patch_jump(&mut self, idx: usize, offset: i32) {
        if self.error.is_some() {
            return;
        }
        let inst_raw = self.instructions[idx];
        let mut inst = match Instruction::decode_any(inst_raw) {
            Ok(i) => i,
            Err(_) => {
                if self.error.is_none() {
                    self.error = Some(CompileError::CodegenError(
                        "patch_jump: failed to decode instruction".to_string(),
                    ));
                }
                return;
            }
        };
        inst.imm = offset;
        self.instructions[idx] = inst.encode();
    }

    /// Best-effort static resolution of the struct type an expression
    /// evaluates to. Used by `FieldAccess` to pick the correct struct
    /// layout. Returns `None` when the type cannot be determined (scalar
    /// expressions, or a nested field access whose intermediate type is
    /// not tracked), in which case the caller falls back to the legacy
    /// layout scan. Mirrors how the semantic analyzer derives
    /// `Type::Struct(name)` for these same expression forms.
    fn expr_struct_type(
        &self,
        expr: &Expr,
        scope: &std::collections::HashMap<String, VarInfo>,
    ) -> Option<String> {
        match expr {
            Expr::StructLiteral(name, _) => Some(name.clone()),
            Expr::Ident(name) => scope.get(name).and_then(|vi| vi.struct_type.clone()),
            _ => None,
        }
    }

    fn generate_expr(
        &mut self,
        expr: &Expr,
        scope: &std::collections::HashMap<String, VarInfo>,
        storage: &std::collections::HashMap<String, i32>,
    ) -> u8 {
        if self.error.is_some() {
            return 0;
        }

        match expr {
            Expr::Int(val) => {
                let v = *val;
                // The VM and STARK AIR operate over the Goldilocks field
                // (mod P = 2^64 - 2^32 + 1), so every value must be a
                // canonical field element (< P). A literal >= P is not
                // representable as itself — field arithmetic would silently
                // reduce it to `v mod P` — so reject it at compile time
                // instead, making the out-of-range value explicit.
                const GOLDILOCKS_P: u64 = 18446744069414584321;
                if v >= GOLDILOCKS_P {
                    if self.error.is_none() {
                        self.error = Some(CompileError::CodegenError(format!(
                            "integer literal {} exceeds the Goldilocks field modulus (max {})",
                            v,
                            GOLDILOCKS_P - 1
                        )));
                    }
                    return 0;
                }
                if v <= i32::MAX as u64 {
                    let reg = self.alloc_reg();
                    self.emit(Opcode::Load, reg, 0, 0, v as i32);
                    reg
                } else {
                    // Values larger than i32::MAX cannot be encoded in a
                    // single Load immediate. We decompose them into three
                    // base-2^30 digits:
                    //   v = high * 2^60 + mid * 2^30 + low
                    // where each digit fits in a signed i32 immediate.
                    // This covers the full u64 range because:
                    //   high in [0, 15], mid/low in [0, 2^30 - 1].
                    let chunks = [
                        ((v >> 60) & 0xF) as i32,
                        ((v >> 30) & 0x3FFFFFFF) as i32,
                        (v & 0x3FFFFFFF) as i32,
                    ];
                    let reg = self.alloc_reg();
                    let shift_reg = self.alloc_reg();
                    self.emit(Opcode::Load, shift_reg, 0, 0, 1073741824); // 2^30
                    let temp_reg = self.alloc_reg();

                    let mut started = false;
                    for chunk in chunks {
                        if chunk > 0 || started {
                            if started {
                                self.emit(Opcode::Mul, reg, reg, shift_reg, 0);
                                if chunk > 0 {
                                    self.emit(Opcode::Load, temp_reg, 0, 0, chunk);
                                    self.emit(Opcode::Add, reg, reg, temp_reg, 0);
                                }
                            } else {
                                started = true;
                                self.emit(Opcode::Load, reg, 0, 0, chunk);
                            }
                        }
                    }
                    reg
                }
            }
            Expr::Ident(name) => match scope.get(name) {
                Some(vi) => vi.reg,
                None => {
                    if self.error.is_none() {
                        self.error = Some(CompileError::CodegenError(format!(
                            "Undefined variable in codegen: {}",
                            name
                        )));
                    }
                    0
                }
            },
            Expr::StorageRead(name) => {
                let reg = self.alloc_reg();
                let slot = match storage.get(name) {
                    Some(s) => *s,
                    None => {
                        if self.error.is_none() {
                            self.error = Some(CompileError::CodegenError(format!(
                                "Unknown storage variable in codegen: {}",
                                name
                            )));
                        }
                        return 0;
                    }
                };
                self.emit(Opcode::SRead, reg, 0, 0, slot);
                reg
            }
            Expr::MappingRead(name, key) => {
                let base_slot = match storage.get(name) {
                    Some(s) => *s,
                    None => {
                        if self.error.is_none() {
                            self.error = Some(CompileError::CodegenError(format!(
                                "Unknown mapping in codegen: {}",
                                name
                            )));
                        }
                        return 0;
                    }
                };
                let key_reg = self.generate_expr(key, scope, storage);

                let base_reg = self.alloc_reg();
                self.emit(Opcode::Load, base_reg, 0, 0, base_slot);

                let target_slot_reg = self.alloc_reg();
                self.emit(Opcode::Poseidon, target_slot_reg, base_reg, key_reg, 0);

                let res_reg = self.alloc_reg();
                self.emit(Opcode::SRead, res_reg, 0, target_slot_reg, -1);
                res_reg
            }
            Expr::StructLiteral(name, fields) => {
                let saved_next_reg = self.next_reg;
                let ptr_reg = self.alloc_reg();
                self.emit(Opcode::Add, ptr_reg, 31, 0, 0); // copy heap ptr to ptr_reg

                // Store each field at its *declared* offset (looked up
                // from the struct layout) rather than at the position it
                // happens to occupy in the literal. `FieldAccess` reads
                // by declaration order, so the two must agree; storing by
                // literal order silently swapped values whenever a literal
                // listed its fields in a different order than the struct
                // declaration. The layout is cloned so the immutable
                // lookup does not overlap the mutable `generate_expr`
                // calls below.
                let layout: Option<Vec<String>> = self.struct_layouts.get(name).cloned();

                let mut field_vals: Vec<(usize, u8)> = Vec::new();
                for (fname, val) in fields {
                    let val_reg = self.generate_expr(val, scope, storage);
                    let offset = match layout
                        .as_ref()
                        .and_then(|fs| fs.iter().position(|f| f == fname))
                    {
                        Some(idx) => idx * 8,
                        None => {
                            // sema rejects literals naming a field the
                            // struct does not declare; defense in depth.
                            // Fall back to the next positional slot so
                            // fields never overlap.
                            if self.error.is_none() {
                                self.error = Some(CompileError::CodegenError(format!(
                                    "Field '{}' not found in struct '{}' literal",
                                    fname, name
                                )));
                            }
                            field_vals.len() * 8
                        }
                    };
                    field_vals.push((offset, val_reg));
                }

                for (offset, val_reg) in field_vals {
                    self.emit(Opcode::Store, 0, ptr_reg, val_reg, offset as i32);
                }

                // Allocate the full *declared* struct size (not the
                // literal's field count) so the block is correctly sized
                // regardless of the order the literal lists its fields.
                // Falls back to the literal count when the layout is
                // unknown.
                let size_words = layout.as_ref().map_or(fields.len(), |fs| fs.len());
                let size_reg = self.alloc_reg();
                self.emit(Opcode::Load, size_reg, 0, 0, (size_words * 8) as i32);
                self.emit(Opcode::Add, 31, 31, size_reg, 0); // bump heap pointer

                self.next_reg = saved_next_reg;
                let res_reg = self.alloc_reg();
                self.emit(Opcode::Add, res_reg, ptr_reg, 0, 0); // return pointer
                res_reg
            }
            Expr::FieldAccess(base, field) => {
                // Resolve the base's struct type *before* generating it
                // (the lookup is read-only on the AST/scope).
                let struct_type = self.expr_struct_type(base, scope);
                let base_reg = self.generate_expr(base, scope, storage);
                let res_reg = self.alloc_reg();

                let offset = match struct_type
                    .as_ref()
                    .and_then(|name| self.struct_layouts.get(name))
                {
                    // Type-aware path: resolve the offset within the
                    // base's *actual* struct layout. This stays correct
                    // when several structs declare a field with the same
                    // name at different positions — the old code scanned
                    // every layout and took the first hit, which is both
                    // wrong and (hash-map iteration order) non-deterministic.
                    Some(fields) => match fields.iter().position(|f| f == field) {
                        Some(idx) => idx * 8,
                        None => {
                            // The semantic analyzer rejects field access
                            // on a struct that lacks the field, so this
                            // is pure defense in depth.
                            if self.error.is_none() {
                                self.error = Some(CompileError::CodegenError(format!(
                                    "Field '{}' not found in struct '{}'",
                                    field,
                                    struct_type.as_ref().unwrap()
                                )));
                            }
                            0
                        }
                    },
                    // Unknown base type (e.g. a nested `a.b.c` whose
                    // intermediate field type is not tracked): keep the
                    // legacy scan so behaviour is unchanged for the cases
                    // sema has already validated.
                    None => {
                        let mut offset = 0;
                        for fields in self.struct_layouts.values() {
                            if let Some(idx) = fields.iter().position(|f| f == field) {
                                offset = idx * 8;
                                break;
                            }
                        }
                        offset
                    }
                };

                self.emit(Opcode::Load, res_reg, base_reg, 0, offset as i32);
                res_reg
            }
            Expr::Binary(left, op, right) => {
                let saved1 = self.next_reg;
                let l_reg = self.generate_expr(left, scope, storage);
                let saved2 = self.next_reg;
                let r_reg = self.generate_expr(right, scope, storage);

                let res_reg = if l_reg >= saved1 {
                    l_reg
                } else if r_reg >= saved2 {
                    r_reg
                } else {
                    self.alloc_reg()
                };

                let opcode = match op {
                    BinOp::Add => Opcode::Add,
                    BinOp::Sub => Opcode::Sub,
                    BinOp::Mul => Opcode::Mul,
                    BinOp::Div => Opcode::Div,
                    BinOp::Eq => Opcode::Eq,
                    BinOp::Neq => Opcode::Neq,
                    BinOp::Lt => Opcode::Lt,
                    BinOp::Gt => Opcode::Gt,
                    BinOp::Lte => Opcode::Lte,
                    BinOp::Gte => Opcode::Gte,
                };

                self.emit(opcode, res_reg, l_reg, r_reg, 0);
                self.next_reg = std::cmp::max(res_reg + 1, saved1);
                res_reg
            }
            Expr::Call(name, args) => {
                if name == "poseidon" {
                    let saved1 = self.next_reg;
                    let r1 = self.generate_expr(&args[0], scope, storage);
                    let saved2 = self.next_reg;
                    let r2 = self.generate_expr(&args[1], scope, storage);

                    let res = if r1 >= saved1 {
                        r1
                    } else if r2 >= saved2 {
                        r2
                    } else {
                        self.alloc_reg()
                    };

                    self.emit(Opcode::Poseidon, res, r1, r2, 0);
                    self.next_reg = std::cmp::max(res + 1, saved1);
                    res
                } else if name == "msg::sender" {
                    let res = self.alloc_reg();
                    self.emit(Opcode::Syscall, res, 0, 0, 1);
                    res
                } else if name == "msg::nonce" {
                    let res = self.alloc_reg();
                    self.emit(Opcode::Syscall, res, 0, 0, 3);
                    res
                } else if name == "block::number" {
                    let res = self.alloc_reg();
                    self.emit(Opcode::Syscall, res, 0, 0, 2);
                    res
                } else if name == "verify_merkle_proof" {
                    let r_root = self.generate_expr(&args[0], scope, storage);
                    let r_leaf = self.generate_expr(&args[1], scope, storage);

                    // Task 0.338 / B4: the VM's VerifyMerkle opcode takes
                    // the path *address* as an immediate (`imm`). The path
                    // address must therefore be a compile-time constant
                    // that fits in a signed 32-bit offset.
                    // Reject dynamic expressions and out-of-range literals
                    // explicitly instead of silently truncating a register
                    // number (the old `r_path as i32` bug).
                    let path_addr = match &args[2] {
                        Expr::Int(v) => *v,
                        _ => {
                            if self.error.is_none() {
                                self.error = Some(CompileError::CodegenError(
                                    "verify_merkle_proof path argument must be a compile-time constant address fitting in i32".to_string(),
                                ));
                            }
                            return 0;
                        }
                    };
                    if path_addr > i32::MAX as u64 {
                        if self.error.is_none() {
                            self.error = Some(CompileError::CodegenError(format!(
                                "verify_merkle_proof path address {} exceeds i32::MAX",
                                path_addr
                            )));
                        }
                        return 0;
                    }

                    let res = self.alloc_reg();
                    self.emit(Opcode::VerifyMerkle, res, r_root, r_leaf, path_addr as i32);
                    res
                } else {
                    let saved_next_reg = self.next_reg;
                    for r in 1..saved_next_reg {
                        self.emit(Opcode::Push, 0, r, 0, 0);
                    }

                    let mut arg_regs = Vec::new();
                    for arg in args {
                        arg_regs.push(self.generate_expr(arg, scope, storage));
                    }
                    for arg_reg in arg_regs {
                        self.emit(Opcode::Push, 0, arg_reg, 0, 0);
                    }

                    let call_idx = self.instructions.len();
                    self.emit(Opcode::Call, 0, 0, 0, 0);
                    self.unpatched_calls.push((call_idx, name.clone()));

                    self.next_reg = saved_next_reg;
                    let res_reg = self.alloc_reg();
                    self.emit(Opcode::Pop, res_reg, 0, 0, 0);

                    for r in (1..saved_next_reg).rev() {
                        self.emit(Opcode::Pop, r, 0, 0, 0);
                    }

                    res_reg
                }
            }
        }
    }

    fn alloc_reg(&mut self) -> u8 {
        if self.next_reg >= 31 {
            if self.error.is_none() {
                self.error = Some(CompileError::RegisterExhausted);
            }
            return 30; // 31 is reserved for heap ptr
        }
        let r = self.next_reg;
        self.next_reg += 1;
        r
    }

    fn emit(&mut self, opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32) {
        if opcode.is_experimental() {
            #[cfg(not(feature = "experimental"))]
            {
                if self.error.is_none() {
                    self.error = Some(CompileError::ExperimentalOpcodeDisabled(format!(
                        "Opcode {:?} is experimental and disabled in production",
                        opcode
                    )));
                }
                return;
            }

            #[cfg(feature = "experimental")]
            if self.profile == IsaProfile::Production {
                if self.error.is_none() {
                    self.error = Some(CompileError::ExperimentalOpcodeDisabled(format!(
                        "Opcode {:?} is experimental and disabled in production",
                        opcode
                    )));
                }
                return;
            }
        }

        let inst = Instruction {
            opcode,
            rd,
            rs1,
            rs2,
            imm,
        };
        self.instructions.push(inst.encode());
    }
}
