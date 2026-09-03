use crate::ast::*;
use crate::CompileError;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    U64,
    Bool,
    Field,
    /// An account address, opaque: it can be copied, compared and passed
    /// around, and that is all.
    ///
    /// Arithmetic on it is a compile error rather than a silent truncation.
    /// The VM has 64-bit registers, so a full 32-byte address needs four
    /// words; allowing `+` would either need multi-limb codegen or would
    /// quietly operate on one limb of four.
    ///
    /// **Measured limitation, stated rather than hidden:** codegen currently
    /// lays out every struct field at `index * 8` bytes
    /// (`codegen.rs`, `Expr::StructLiteral`), so an `Address` field occupies
    /// one word, not four. The type therefore buys the *rules* today (no
    /// arithmetic, not interchangeable with `Hash32`, distinct in a
    /// signature) and not yet the *width*. Widening the layout is a separate
    /// change to struct offsets and to the syscall that would return one;
    /// naming the type first is what makes that change reviewable, and
    /// `msg::sender()` deliberately still returns `u64` rather than pretending
    /// otherwise.
    Address,
    /// A 32-byte hash. Same rules as [`Type::Address`], different meaning, and
    /// deliberately not interchangeable with it: a hash used where an address
    /// is expected is a bug worth catching.
    Hash32,
    Struct(String),
    /// A storage mapping `Map<K,V>`: key type, value type. Only a storage
    /// field can have it; it is read as `name[key]` and written as
    /// `name[key] = value`, and the VM keys the slot on a hash of the key.
    Map(Box<Type>, Box<Type>),
    Void,
    Unknown,
}

impl Type {
    /// Types that occupy 32 bytes and support no arithmetic.
    #[must_use]
    pub fn is_opaque_bytes32(&self) -> bool {
        matches!(self, Type::Address | Type::Hash32)
    }

    /// The name to print in a diagnostic.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Type::U64 => "u64".into(),
            Type::Bool => "bool".into(),
            Type::Field => "field".into(),
            Type::Address => "Address".into(),
            Type::Hash32 => "Hash32".into(),
            Type::Struct(n) => n.clone(),
            Type::Map(k, v) => format!("Map<{},{}>", k.name(), v.name()),
            Type::Void => "()".into(),
            Type::Unknown => "?".into(),
        }
    }
}

/// Type names that a reader will reasonably expect to exist and that BudL
/// does not have, mapped to what to say instead.
///
/// Without this list they fall through to `Type::Struct(name)` and the author
/// is told "unknown struct type: u128", which is true and useless: it points
/// at the struct machinery rather than at the fact that the type does not
/// exist. `BudL_SPEC.md` listed `u32`, `u128`, `Address` and `Hash32` in its
/// type table and used `Address` in both of its example contracts, so the
/// documentation itself produced this error.
///
/// `u32` and `u128` are not simply unimplemented, they are not implementable
/// as written: the VM computes in the Goldilocks field, and proving that a
/// value fits in 32 bits needs range-check columns the AIR does not have.
/// Naming them would be a label, not a guarantee.
const RESERVED_TYPE_NAMES: &[(&str, &str)] = &[
    ("u8", "BudL has one integer type, `u64`, and it is a Goldilocks field element"),
    ("u16", "BudL has one integer type, `u64`, and it is a Goldilocks field element"),
    ("u32", "BudL has one integer type, `u64`; a narrower type would need range-check columns the AIR does not have"),
    ("u128", "BudL has one integer type, `u64`; a wider type would need multi-limb arithmetic the VM does not have"),
    ("i8", "BudL integers are unsigned field elements"),
    ("i16", "BudL integers are unsigned field elements"),
    ("i32", "BudL integers are unsigned field elements"),
    ("i64", "BudL integers are unsigned field elements"),
    ("usize", "BudL has one integer type, `u64`"),
    ("isize", "BudL has one integer type, `u64`"),
    ("String", "BudL has no string type"),
    ("str", "BudL has no string type"),
    ("Vec", "BudL has no dynamic collections; a proof has to bound its own length"),
];

impl Type {
    fn from_str(s: &str) -> Result<Type, String> {
        match s {
            "u64" => Ok(Type::U64),
            "bool" => Ok(Type::Bool),
            "field" => Ok(Type::Field),
            "Address" => Ok(Type::Address),
            "Hash32" => Ok(Type::Hash32),
            _ => {
                // The parser spells a mapping storage field `Map<K,V>`. This
                // used to fall through to `Type::Struct("Map<K,V>")`, and
                // `check_struct_type` then refused every mapping declaration
                // as an undefined struct before code generation ran.
                if let Some(inner) = s.strip_prefix("Map<").and_then(|r| r.strip_suffix('>')) {
                    let (k, v) = inner.split_once(',').ok_or_else(|| {
                        format!("`{s}` is not a mapping type: expected `Map<K,V>`")
                    })?;
                    let key = Type::from_str(k.trim())?;
                    let value = Type::from_str(v.trim())?;
                    if matches!(key, Type::Map(..)) || matches!(value, Type::Map(..)) {
                        return Err(format!("`{s}`: a mapping cannot nest a mapping"));
                    }
                    return Ok(Type::Map(Box::new(key), Box::new(value)));
                }
                if let Some((_, why)) = RESERVED_TYPE_NAMES.iter().find(|(n, _)| *n == s) {
                    return Err(format!("`{s}` is not a BudL type: {why}"));
                }
                // Anything else is taken as a struct name. Whether that struct
                // exists is checked separately by `check_struct_type`, which
                // is what turns a typo into an error rather than a silent
                // phantom type.
                Ok(Type::Struct(s.to_string()))
            }
        }
    }
}

pub struct SemanticAnalyzer {
    pub structs: HashMap<String, HashMap<String, Type>>,
    pub functions: HashMap<String, (Vec<Type>, Type)>,
    /// The types of the fields declared in the contract's `storage { ... }` block.
    ///
    /// Access uses the `storage::name` syntax and is parsed as `Stmt::StorageWrite` /
    /// `Expr::StorageRead`, so the fields are
    /// not placed into the variable environment. They are held here so the types
    /// are verified once: a typo in a field's type name must not silently turn
    /// into an imaginary struct type, as it can with struct field types.
    pub storage: HashMap<String, Type>,
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
            storage: HashMap::new(),
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

        // 1a. Register storage fields. Their types are validated here once,
        // the same way struct field types are, so a typo in a storage type
        // is reported rather than silently becoming a phantom struct.
        for field in &contract.storage {
            match Type::from_str(&field.ty) {
                Ok(ty) => {
                    self.storage.insert(field.name.clone(), ty);
                }
                Err(e) => errors.push(CompileError::SemanticError(e)),
            }
        }

        // 1a-bis. Verify that the storage field types really exist.
        // `Type::from_str` turns EVERY non-primitive name into `Type::Struct(name)`,
        // so a typo such as `count: Uint644` would turn into an imaginary struct
        // type and be accepted silently - the same class as the hole closed for
        // struct field types. It runs after the struct registration pass so that
        // a field can refer to a struct declared later.
        for field in &contract.storage {
            if let Ok(ty) = Type::from_str(&field.ty) {
                self.check_struct_type(
                    &ty,
                    &format!("storage field '{}'", field.name),
                    &mut errors,
                );
            }
        }

        // 1b. Validate struct *type references* in field declarations.
        // `Type::from_str` maps ANY non-primitive name to
        // `Type::Struct(name)` without checking the struct exists, so a
        // Typo in a field's type (e.g. `b: Ponit`) would silently become
        // A phantom struct type - and field access on values of that
        // Type would then skip validation entirely (a soundness gap).
        // This runs *after* the registration pass so fields may reference
        // Structs declared later in the contract.
        for s in &contract.structs {
            for f in &s.fields {
                let parsed = Type::from_str(&f.ty);
                if let Err(why) = &parsed {
                    errors.push(CompileError::SemanticError(format!(
                        "field '{}.{}': {why}",
                        s.name, f.name
                    )));
                }
                if let Ok(ty) = parsed {
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
                // A rejected type name has to become an error here, not a
                // silent `Unknown`. `Unknown` is treated as compatible with
                // everything downstream, so swallowing it means `fn f(x: u32)`
                // reports nothing at all and the reserved-name list is dead.
                let ty = match Type::from_str(&p.ty) {
                    Ok(ty) => ty,
                    Err(why) => {
                        errors.push(CompileError::SemanticError(format!(
                            "parameter '{}' of function '{}': {why}",
                            p.name, f.name
                        )));
                        Type::Unknown
                    }
                };
                self.check_struct_type(
                    &ty,
                    &format!("parameter '{}' of function '{}'", p.name, f.name),
                    &mut errors,
                );
                params.push(ty);
            }
            let ret_ty = if let Some(r) = &f.return_type {
                let ty = match Type::from_str(r) {
                    Ok(ty) => ty,
                    Err(why) => {
                        errors.push(CompileError::SemanticError(format!(
                            "return type of function '{}': {why}",
                            f.name
                        )));
                        Type::Unknown
                    }
                };
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
    /// Struct that is actually declared. `Type::from_str` maps ANY
    /// Non-primitive name to `Type::Struct(name)`, so without this check
    /// A typo in a struct type annotation (field / parameter / return)
    /// Would silently become a phantom struct type, and field access on
    /// Values of that type would then skip validation entirely.
    fn check_struct_type(&self, ty: &Type, ctx: &str, errors: &mut Vec<CompileError>) {
        match ty {
            Type::Struct(name) => {
                if !self.structs.contains_key(name) {
                    errors.push(CompileError::SemanticError(format!(
                        "Undefined struct type '{}' in {}",
                        name, ctx
                    )));
                }
            }
            // A mapping is checked through its key and value types.
            Type::Map(key, value) => {
                self.check_struct_type(key, &format!("the key of {ctx}"), errors);
                self.check_struct_type(value, &format!("the value of {ctx}"), errors);
            }
            _ => {}
        }
    }

    /// The value type of the storage mapping `name`, or `Unknown` with an
    /// error when `name` is not a declared mapping. Reading `total[3]` from
    /// a `total: u64` field used to type as `u64` and pass.
    fn mapping_value_type(&self, name: &str, errors: &mut Vec<CompileError>) -> Type {
        match self.storage.get(name) {
            Some(Type::Map(_, value)) => (**value).clone(),
            Some(other) => {
                errors.push(CompileError::SemanticError(format!(
                    "storage field '{}' is {}, not a mapping",
                    name,
                    other.name()
                )));
                Type::Unknown
            }
            None => {
                errors.push(CompileError::SemanticError(format!(
                    "Undefined storage mapping '{}'",
                    name
                )));
                Type::Unknown
            }
        }
    }

    /// A value used as a condition (`if` / `while` / `constrain`) is
    /// Tested for non-zero by the VM, so it must be a scalar
    /// (u64 / bool / field). A struct value is a heap pointer, always
    /// Non-zero, so the branch/assertion is trivially true - and `void`
    /// Is not a value; both are near-certain bugs, rejected at compile
    /// Time. (match has its own stricter scrutinee check.)
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
        // `unwrap_or(Unknown)` is correct on this pass and only on this pass:
        // the signature was already walked in `analyze`, which reported any
        // bad type name once. Reporting again here would print the same
        // diagnostic twice for one mistake.
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
            Stmt::MappingWrite(name, key, val) => {
                self.analyze_expr(key, env, errors);
                let val_ty = self.analyze_expr(val, env, errors);
                let expected = self.mapping_value_type(name, errors);
                if expected != Type::Unknown && val_ty != Type::Unknown && val_ty != expected {
                    errors.push(CompileError::SemanticError(format!(
                        "mapping '{}' holds {}, got {}",
                        name,
                        expected.name(),
                        val_ty.name()
                    )));
                }
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
            // Pattern matching. The scrutinee must be an integer
            // Expression (`u64`). Each arm body is analyzed in a
            // Child scope. Exhaustiveness is checked.16; for
            // Now we just require the arm to syntactically parse and
            // Each body to type-check.
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
            Expr::MappingRead(name, key) => {
                self.analyze_expr(key, env, errors);
                self.mapping_value_type(name, errors)
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
                    // Be initialized. A field left out would be read as
                    // Uninitialized memory at its (declared) offset -
                    // Undefined behavior in the VM - so we fail at compile
                    // Time instead. Fail-fast keeps ZK contracts total:
                    // A struct value always carries a defined value for
                    // Every field (mirrors Rust's exhaustive struct
                    // Literals; a future `..default` could relax this
                    // Explicitly).
                    for fname in sfields.keys() {
                        if !fields.iter().any(|(provided, _)| provided == fname) {
                            errors.push(CompileError::SemanticError(format!(
                                "Struct {} literal is missing field {}",
                                name, fname
                            )));
                        }
                    }
                    // Reject duplicate field initializers: a field listed
                    // Twice is almost certainly a mistake - codegen stores
                    // Both at the same declared offset, so the last write
                    // Silently wins (a hidden, order-dependent value).
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
                // Types. A struct value is a heap pointer and `void` is
                // Not a value, so arithmetic (+ - * /) and ordering
                // (< > <= >=) over them would make the VM compute over
                // Raw pointer words - silent nonsense that previously
                // Type-checked. Equality (== !=) on structs stays
                // Allowed (pointer equality is meaningful). Booleans are
                // Permitted in arithmetic because BudL exposes no
                // Logical/bitwise operators, so 0/1 arithmetic is the
                // Sanctioned way to combine flags.
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
                        // `Address` and `Hash32` are 32 bytes; a VM register
                        // holds 8. Permitting arithmetic would compile to an
                        // operation on one limb of four and silently produce a
                        // value that is not the sum of anything. Equality and
                        // assignment stay allowed, which is what these types
                        // are for.
                        // `/` is field division, not integer division.
                        //
                        // The VM executes `Opcode::Div` as the Goldilocks
                        // multiplicative inverse (`bud-vm`: `rs1 * rs2^-1 mod
                        // p`) and the AIR constraint pins that down
                        // (`rd * rs2 = rs1`). That is the right choice in a ZK
                        // circuit; integer division would need separate range
                        // checks for the quotient and the remainder.
                        //
                        // But a developer writing `u64` expects integer division.
                        // Measured: `7 / 2` gives 9223372034707292164 in the field,
                        // not 3. Every contract that builds a condition on such a
                        // result branches silently wrongly.
                        //
                        // So `/` is free only over `field`: there the semantics
                        // are field arithmetic already, and whoever writes it
                        // chose that deliberately. It is refused for `u64`.
                        // A division result of 0 on division by zero is likewise
                        // meaningful only in a `field` context, for the same reason
                        // (the AIR constrains this explicitly).
                        if matches!(op, BinOp::Div) && matches!(ty, Type::U64) {
                            errors.push(CompileError::SemanticError(String::from(
                                "Operator Div cannot be applied to u64 (`/` is field \
                                 division, not integer division: it computes \
                                 rs1 * rs2^-1 mod p, so 7 / 2 is not 3; declare the \
                                 operands as `field` if that is what you mean)",
                            )));
                        }
                        if ty.is_opaque_bytes32() {
                            errors.push(CompileError::SemanticError(format!(
                                "Operator {:?} cannot be applied to {} ({} is an opaque \
                                 32-byte identity; compare it or pass it, do not compute \
                                 with it)",
                                op,
                                ty.name(),
                                ty.name()
                            )));
                        }
                    }
                }
                // Comparisons yield a boolean result; arithmetic yields
                // The (shared) operand type. Typing comparisons as Bool
                // (rather than the operand type) lets the checker catch
                // E.g. using a comparison result in u64 arithmetic.
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
