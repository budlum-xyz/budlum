#[derive(Debug, Clone)]
pub struct Contract {
    pub name: String,
    pub storage: Vec<StorageField>,
    pub structs: Vec<Struct>,
    pub functions: Vec<Function>,
}

#[derive(Debug, Clone)]
pub struct StorageField {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub params: Vec<Param>,
    pub return_type: Option<String>,
    pub body: Vec<Stmt>,
    pub is_pub: bool,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Let(String, Expr),
    Constrain(Expr),
    Assign(String, Expr),
    StorageWrite(String, Expr),
    MappingWrite(String, Expr, Expr),
    If(Expr, Vec<Stmt>, Option<Vec<Stmt>>),
    While(Expr, Vec<Stmt>),
    For {
        var: String,
        start: Expr,
        end: Expr,
        body: Vec<Stmt>,
    },
    Return(Option<Expr>),
    Emit(String, Vec<Expr>),
    /// Task 0.14: `match <scrutinee> { pattern => body, ... }` pattern
    /// expression statement. The optional default arm (`_ =>`) is
    /// required by the semantic analyzer (every match must be
    /// exhaustive over the scrutinee's reachable value set), but
    /// at the AST level we keep it as just another arm to keep the
    /// parser simple — sema is where exhaustiveness is checked.
    Match {
        scrutinee: Expr,
        arms: Vec<MatchArm>,
    },
    Expr(Expr),
}

/// One arm of a `match` expression. The pattern is restricted to
/// integer literals or a wildcard (`_`) in Task 0.14 — full algebraic
/// data type patterns (struct destructuring, ranges) are Task 0.16+.
#[derive(Debug, Clone)]
pub struct MatchArm {
    pub pattern: MatchPattern,
    pub body: Vec<Stmt>,
}

/// Pattern matched against a `match` scrutinee. The wildcard pattern
/// (`_`) always matches; integer patterns match exactly that value.
#[derive(Debug, Clone)]
pub enum MatchPattern {
    /// `0`, `1`, `42`, ... — exact integer match.
    IntLit(u64),
    /// `_` — matches anything not matched by a previous arm.
    Wildcard,
}

#[derive(Debug, Clone)]
pub struct Struct {
    pub name: String,
    pub fields: Vec<StorageField>,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Int(u64),
    Ident(String),
    StorageRead(String),
    MappingRead(String, Box<Expr>),
    FieldAccess(Box<Expr>, String),
    StructLiteral(String, Vec<(String, Expr)>),
    Binary(Box<Expr>, BinOp, Box<Expr>),
    Call(String, Vec<Expr>),
}

#[derive(Debug, Clone)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    Neq,
    Lt,
    Gt,
    Lte,
    Gte,
}
