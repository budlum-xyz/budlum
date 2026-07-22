use crate::ast::*;
use crate::CompileError;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    U64,
    Bool,
    Field,
    Struct(String),
    Void,
    Unknown,
}

impl Type {
    fn from_str(s: &str) -> Result<Type, String> {
        match s {
            "u64" => Ok(Type::U64),
            "bool" => Ok(Type::Bool),
            "field" => Ok(Type::Field),
            _ => Ok(Type::Struct(s.to_string())), // Assume it's a struct type
        }
    }
}

pub struct SemanticAnalyzer {
    pub structs: HashMap<String, HashMap<String, Type>>,
    pub functions: HashMap<String, (Vec<Type>, Type)>,
    pub current_func_ret: Type,
}

impl Default for SemanticAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticAnalyzer {
    pub fn new() -> Self {
        Self {
            structs: HashMap::new(),
            functions: HashMap::new(),
            current_func_ret: Type::Void,
        }
    }

    pub fn analyze(&mut self, contract: &Contract) -> Result<(), CompileError> {
        let mut errors = Vec::new();

        // 1. Register structs
        for s in &contract.structs {
            let mut fields = HashMap::new();
            for f in &s.fields {
                let ty = Type::from_str(&f.ty).map_err(CompileError::SemanticError)?;
                fields.insert(f.name.clone(), ty);
            }
            self.structs.insert(s.name.clone(), fields);
        }

        // 1b. Validate struct *type references* in field declarations.
        // `Type::from_str` maps ANY non-primitive name to
        // `Type::Struct(name)` without checking the struct exists, so a
        // typo in a field's type (e.g. `b: Ponit`) would silently become
        // a phantom struct type — and field access on values of that
        // type would then skip validation entirely (a soundness gap).
        // This runs *after* the registration pass so fields may reference
        // structs declared later in the contract.
        for s in &contract.structs {
            for f in &s.fields {
                if let Ok(ty) = Type::from_str(&f.ty) {
                    self.check_struct_type(
                        &ty,
                        &format!("field '{}.{}'", s.name, f.name),
                        &mut errors,
                    );
                }
            }
        }

        // 2. Register functions
        for f in &contract.functions {
            let mut params = Vec::new();
            for p in &f.params {
                let ty = Type::from_str(&p.ty).unwrap_or(Type::Unknown);
                self.check_struct_type(
                    &ty,
                    &format!("parameter '{}' of function '{}'", p.name, f.name),
                    &mut errors,
                );
                params.push(ty);
            }
            let ret_ty = if let Some(r) = &f.return_type {
                let ty = Type::from_str(r).unwrap_or(Type::Unknown);
                self.check_struct_type(
                    &ty,
                    &format!("return type of function '{}'", f.name),
                    &mut errors,
                );
                ty
            } else {
                Type::Void
            };
            self.functions.insert(f.name.clone(), (params, ret_ty));
        }

        // 3. Builtins
        self.functions.insert(
            "poseidon".to_string(),
            (vec![Type::U64, Type::U64], Type::U64),
        );
        self.functions.insert(
            "verify_merkle_proof".to_string(),
            (vec![Type::U64, Type::U64, Type::U64], Type::U64),
        );
        self.functions
            .insert("msg::sender".to_string(), (vec![], Type::U64));
        self.functions
            .insert("msg::nonce".to_string(), (vec![], Type::U64));
        self.functions
            .insert("block::number".to_string(), (vec![], Type::U64));

        for func in &contract.functions {
            self.analyze_function(func, &mut errors);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.remove(0))
        }
    }

    /// Validate that a type reference resolving to a struct names a
    /// struct that is actually declared. `Type::from_str` maps ANY
    /// non-primitive name to `Type::Struct(name)`, so without this check
    /// a typo in a struct type annotation (field / parameter / return)
    /// would silently become a phantom struct type — and field access on
    /// values of that type would then skip validation entirely.
    fn check_struct_type(&self, ty: &Type, ctx: &str, errors: &mut Vec<CompileError>) {
        if let Type::Struct(name) = ty {
            if !self.structs.contains_key(name) {
                errors.push(CompileError::SemanticError(format!(
                    "Undefined struct type '{}' in {}",
                    name, ctx
                )));
            }
        }
    }

    /// A value used as a condition (`if` / `while` / `constrain`) is
    /// tested for non-zero by the VM, so it must be a scalar
    /// (u64 / bool / field). A struct value is a heap pointer — always
    /// non-zero, so the branch/assertion is trivially true — and `void`
    /// is not a value; both are near-certain bugs, rejected at compile
    /// time. (match has its own stricter scrutinee check.)
    fn check_condition_type(&self, ty: &Type, ctx: &str, errors: &mut Vec<CompileError>) {
        if matches!(ty, Type::Struct(_) | Type::Void) {
            errors.push(CompileError::SemanticError(format!(
                "{} condition must be a scalar (u64/bool/field), got {:?}",
                ctx, ty
            )));
        }
    }

    fn analyze_function(&mut self, func: &Function, errors: &mut Vec<CompileError>) {
        let mut env = HashMap::new();
        for param in &func.params {
            let ty = Type::from_str(&param.ty).unwrap_or(Type::Unknown);
            env.insert(param.name.clone(), ty);
        }
        self.current_func_ret = if let Some(r) = &func.return_type {
            Type::from_str(r).unwrap_or(Type::Unknown)
        } else {
            Type::Void
        };

        for stmt in &func.body {
            self.analyze_stmt(stmt, &mut env, errors);
        }
    }

    fn analyze_stmt(
        &mut self,
        stmt: &Stmt,
        env: &mut HashMap<String, Type>,
        errors: &mut Vec<CompileError>,
    ) {
        match stmt {
            Stmt::Let(name, expr) => {
                let ty = self.analyze_expr(expr, env, errors);
                env.insert(name.clone(), ty);
            }
            Stmt::Constrain(expr) => {
                let ty = self.analyze_expr(expr, env, errors);
                self.check_condition_type(&ty, "constrain", errors);
            }
            Stmt::Assign(name, expr) => {
                if let Some(expected_ty) = env.get(name).cloned() {
                    let ty = self.analyze_expr(expr, env, errors);
                    if ty != expected_ty && ty != Type::Unknown && expected_ty != Type::Unknown {
                        errors.push(CompileError::SemanticError(format!(
                            "Type mismatch in assign: expected {:?}, got {:?}",
                            expected_ty, ty
                        )));
                    }
                } else {
                    errors.push(CompileError::SemanticError(format!(
                        "Undefined variable: {}",
                        name
                    )));
                    self.analyze_expr(expr, env, errors);
                }
            }
            Stmt::StorageWrite(_, expr) => {
                self.analyze_expr(expr, env, errors);
            }
            Stmt::MappingWrite(_, key, val) => {
                self.analyze_expr(key, env, errors);
                self.analyze_expr(val, env, errors);
            }
            Stmt::If(cond, then_branch, else_branch) => {
                let cond_ty = self.analyze_expr(cond, env, errors);
                self.check_condition_type(&cond_ty, "if", errors);
                for s in then_branch {
                    self.analyze_stmt(s, env, errors);
                }
                if let Some(eb) = else_branch {
                    for s in eb {
                        self.analyze_stmt(s, env, errors);
                    }
                }
            }
            Stmt::While(cond, body) => {
                let cond_ty = self.analyze_expr(cond, env, errors);
                self.check_condition_type(&cond_ty, "while", errors);
                for s in body {
                    self.analyze_stmt(s, env, errors);
                }
            }
            Stmt::For {
                var,
                start,
                end,
                body,
            } => {
                self.analyze_expr(start, env, errors);
                self.analyze_expr(end, env, errors);
                let mut inner_env = env.clone();
                inner_env.insert(var.clone(), Type::U64);
                for s in body {
                    self.analyze_stmt(s, &mut inner_env, errors);
                }
            }
            Stmt::Return(expr) => {
                let ret_ty = if let Some(e) = expr {
                    self.analyze_expr(e, env, errors)
                } else {
                    Type::Void
                };
                if ret_ty != self.current_func_ret
                    && ret_ty != Type::Unknown
                    && self.current_func_ret != Type::Unknown
                {
                    errors.push(CompileError::SemanticError(format!(
                        "Type mismatch in return: expected {:?}, got {:?}",
                        self.current_func_ret, ret_ty
                    )));
                }
            }
            Stmt::Emit(_, args) => {
                for arg in args {
                    self.analyze_expr(arg, env, errors);
                }
            }
            // Task 0.14: pattern matching. The scrutinee must be an integer
            // expression (`u64`). Each arm body is analyzed in a
            // child scope. Exhaustiveness is checked in Task 0.16; for
            // now we just require the arm to syntactically parse and
            // each body to type-check.
            Stmt::Match { scrutinee, arms } => {
                let scrutinee_ty = self.analyze_expr(scrutinee, env, errors);
                if scrutinee_ty != Type::U64 && scrutinee_ty != Type::Bool {
                    errors.push(CompileError::SemanticError(format!(
                        "match scrutinee must be u64 or bool, got {:?}",
                        scrutinee_ty
                    )));
                }
                for arm in arms {
                    let mut arm_env = env.clone();
                    for s in &arm.body {
                        self.analyze_stmt(s, &mut arm_env, errors);
                    }
                }
            }
            Stmt::Expr(expr) => {
                self.analyze_expr(expr, env, errors);
            }
        }
    }

    fn analyze_expr(
        &mut self,
        expr: &Expr,
        env: &HashMap<String, Type>,
        errors: &mut Vec<CompileError>,
    ) -> Type {
        match expr {
            Expr::Int(_) => Type::U64,
            Expr::Ident(name) => {
                if let Some(ty) = env.get(name) {
                    ty.clone()
                } else {
                    errors.push(CompileError::SemanticError(format!(
                        "Undefined identifier: {}",
                        name
                    )));
                    Type::Unknown
                }
            }
            Expr::StorageRead(_) => Type::U64,
            Expr::MappingRead(_, key) => {
                self.analyze_expr(key, env, errors);
                Type::U64
            }
            Expr::FieldAccess(base, field) => {
                let base_ty = self.analyze_expr(base, env, errors);
                if let Type::Struct(sname) = base_ty {
                    if let Some(fields) = self.structs.get(&sname) {
                        if let Some(fty) = fields.get(field) {
                            return fty.clone();
                        } else {
                            errors.push(CompileError::SemanticError(format!(
                                "Struct {} has no field {}",
                                sname, field
                            )));
                        }
                    }
                } else if base_ty != Type::Unknown {
                    errors.push(CompileError::SemanticError(
                        "Field access on non-struct".to_string(),
                    ));
                }
                Type::Unknown
            }
            Expr::StructLiteral(name, fields) => {
                if let Some(sfields) = self.structs.get(name).cloned() {
                    for (fname, val) in fields {
                        let ty = self.analyze_expr(val, env, errors);
                        if let Some(expected_ty) = sfields.get(fname) {
                            if ty != *expected_ty && ty != Type::Unknown {
                                errors.push(CompileError::SemanticError(format!(
                                    "Field {} type mismatch",
                                    fname
                                )));
                            }
                        } else {
                            errors.push(CompileError::SemanticError(format!(
                                "Unknown field {}",
                                fname
                            )));
                        }
                    }
                    // Reject partial literals: every declared field must
                    // be initialized. A field left out would be read as
                    // uninitialized memory at its (declared) offset —
                    // undefined behavior in the VM — so we fail at compile
                    // time instead. Fail-fast keeps ZK contracts total:
                    // a struct value always carries a defined value for
                    // every field (mirrors Rust's exhaustive struct
                    // literals; a future `..default` could relax this
                    // explicitly).
                    for fname in sfields.keys() {
                        if !fields.iter().any(|(provided, _)| provided == fname) {
                            errors.push(CompileError::SemanticError(format!(
                                "Struct {} literal is missing field {}",
                                name, fname
                            )));
                        }
                    }
                    // Reject duplicate field initializers: a field listed
                    // twice is almost certainly a mistake — codegen stores
                    // both at the same declared offset, so the last write
                    // silently wins (a hidden, order-dependent value).
                    // Fail at compile time instead.
                    let mut seen_fields: HashSet<&String> = HashSet::new();
                    for (fname, _) in fields {
                        if !seen_fields.insert(fname) {
                            errors.push(CompileError::SemanticError(format!(
                                "Struct {} literal initializes field {} more than once",
                                name, fname
                            )));
                        }
                    }
                    Type::Struct(name.clone())
                } else {
                    errors.push(CompileError::SemanticError(format!(
                        "Undefined struct: {}",
                        name
                    )));
                    Type::Unknown
                }
            }
            Expr::Call(name, args) => {
                let mut arg_types = Vec::new();
                for arg in args {
                    arg_types.push(self.analyze_expr(arg, env, errors));
                }
                if let Some((params, ret_ty)) = self.functions.get(name) {
                    if params.len() != args.len() {
                        errors.push(CompileError::SemanticError(format!(
                            "Function {} expects {} args, got {}",
                            name,
                            params.len(),
                            args.len()
                        )));
                    } else {
                        for (i, (exp, act)) in params.iter().zip(arg_types.iter()).enumerate() {
                            if exp != act && act != &Type::Unknown && exp != &Type::Unknown {
                                errors.push(CompileError::SemanticError(format!(
                                    "Arg {} type mismatch in {}",
                                    i, name
                                )));
                            }
                        }
                    }
                    ret_ty.clone()
                } else {
                    errors.push(CompileError::SemanticError(format!(
                        "Undefined function: {}",
                        name
                    )));
                    Type::Unknown
                }
            }
            Expr::Binary(left, op, right) => {
                let l_ty = self.analyze_expr(left, env, errors);
                let r_ty = self.analyze_expr(right, env, errors);
                if l_ty != r_ty && l_ty != Type::Unknown && r_ty != Type::Unknown {
                    errors.push(CompileError::SemanticError(
                        "Type mismatch in binary expression".to_string(),
                    ));
                }
                // Reject operators that are meaningless on the operand
                // types. A struct value is a heap pointer and `void` is
                // not a value, so arithmetic (+ - * /) and ordering
                // (< > <= >=) over them would make the VM compute over
                // raw pointer words — silent nonsense that previously
                // type-checked. Equality (== !=) on structs stays
                // allowed (pointer equality is meaningful). Booleans are
                // permitted in arithmetic because BudL exposes no
                // logical/bitwise operators, so 0/1 arithmetic is the
                // sanctioned way to combine flags.
                if matches!(
                    op,
                    BinOp::Add
                        | BinOp::Sub
                        | BinOp::Mul
                        | BinOp::Div
                        | BinOp::Lt
                        | BinOp::Gt
                        | BinOp::Lte
                        | BinOp::Gte
                ) {
                    for ty in [&l_ty, &r_ty] {
                        if matches!(ty, Type::Struct(_) | Type::Void) && *ty != Type::Unknown {
                            errors.push(CompileError::SemanticError(format!(
                                "Operator {:?} cannot be applied to {:?} (struct/void operands are not numeric)",
                                op, ty
                            )));
                        }
                    }
                }
                // Comparisons yield a boolean result; arithmetic yields
                // the (shared) operand type. Typing comparisons as Bool
                // (rather than the operand type) lets the checker catch
                // e.g. using a comparison result in u64 arithmetic.
                if matches!(
                    op,
                    BinOp::Eq | BinOp::Neq | BinOp::Lt | BinOp::Gt | BinOp::Lte | BinOp::Gte
                ) {
                    Type::Bool
                } else {
                    l_ty
                }
            }
        }
    }
}
