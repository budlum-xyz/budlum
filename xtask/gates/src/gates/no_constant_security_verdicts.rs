//! No security verdict is a constant.
//!
//! # The failure this closes
//!
//! `bud/src/quantum_chain.rs` carried a `SnowHybrid::is_quantum_resistant`
//! whose answer was read from a function that returned `false` and a family of
//! `QuantumChainGates::kq_*` verdicts that were wrappers around fixed answers.
//! A function named like a security verdict that returns a literal tells the
//! reader the question was asked and answered, when nothing was checked. The
//! `false` ones are the quieter risk: they read as fail-closed and nobody notices
//! when the thing they stand for is later "turned on" by flipping the literal.
//!
//! # What is refused
//!
//! A non-test function (free, inherent method, trait method with a default body,
//! trait implementation method) that
//!
//! * returns `bool` (or `Result<bool, _>`),
//! * has a name with a verdict token (`verify`, `secure`, `safe`, `resistant`,
//!   `authentic`, `attested`, `trusted`, `sound`, `verdict`), a `kq_` prefix or an
//!   `_ok` suffix,
//! * and whose whole body is a literal answer: `true`, `false`, `return true;`,
//!   `Ok(true)` and the like.
//!
//! Test code (`#[cfg(test)]`, `#[test]`, files under `tests/`) is outside the
//! gate: a stub that always accepts is exactly what a test double is.
//! [`ALLOWED`] holds the functions that are constant on purpose, each with its
//! reason; the list is meant to stay empty.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};
use syn::{Attribute, Block, Expr, ImplItemFn, ItemFn, ItemMod, ReturnType, Stmt, TraitItemFn};

/// Name tokens that make a function a security verdict.
const VERDICT_TOKENS: &[&str] = &[
    "verify",
    "verified",
    "verdict",
    "secure",
    "safe",
    "resistant",
    "authentic",
    "authenticated",
    "attested",
    "trusted",
    "sound",
];

/// Functions that return a constant on purpose: `(repository path, function name, reason)`.
const ALLOWED: &[(&str, &str, &str)] = &[];

/// Source trees whose non-test code is scanned.
const ROOTS: &[&str] = &["src", "bud/src"];

/// Workspace members that carry a `src` tree: `crates/*/src` and `budzero/*/src`.
const MEMBER_PARENTS: &[&str] = &["crates", "budzero"];

/// A scan that visits fewer functions than this looked at nothing.
const VACUITY_FLOOR: usize = 500;

fn is_verdict_name(name: &str) -> bool {
    name.starts_with("kq_")
        || name.ends_with("_ok")
        || name.split('_').any(|token| VERDICT_TOKENS.contains(&token))
}

fn is_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        let text = quote::ToTokens::to_token_stream(&a.meta).to_string();
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        compact == "test" || compact.starts_with("cfg(test") || compact.starts_with("cfg(all(test")
    })
}

fn returns_bool(output: &ReturnType) -> bool {
    let ReturnType::Type(_, ty) = output else {
        return false;
    };
    let text: String = quote::ToTokens::to_token_stream(ty.as_ref())
        .to_string()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    text == "bool" || text.starts_with("Result<bool,") || text.starts_with("Option<bool>")
}

fn is_bool_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(lit) => matches!(lit.lit, syn::Lit::Bool(_)),
        Expr::Paren(p) => is_bool_literal(&p.expr),
        Expr::Group(g) => is_bool_literal(&g.expr),
        Expr::Call(call) => {
            let callee = quote::ToTokens::to_token_stream(call.func.as_ref())
                .to_string()
                .replace(' ', "");
            (callee == "Ok" || callee == "Some")
                && call.args.len() == 1
                && call.args.first().is_some_and(is_bool_literal)
        }
        _ => false,
    }
}

/// Is the whole body one literal answer?
fn body_is_constant(block: &Block) -> bool {
    let [stmt] = block.stmts.as_slice() else {
        return false;
    };
    let Stmt::Expr(expr, _) = stmt else {
        return false;
    };
    match expr {
        Expr::Return(ret) => ret.expr.as_deref().is_some_and(is_bool_literal),
        Expr::Block(inner) => body_is_constant(&inner.block),
        other => is_bool_literal(other),
    }
}

struct Finder<'a> {
    rel: &'a str,
    functions: usize,
    findings: Vec<String>,
}

impl Finder<'_> {
    fn check(&mut self, name: &str, output: &ReturnType, block: &Block) {
        self.functions += 1;
        if !is_verdict_name(name) || !returns_bool(output) || !body_is_constant(block) {
            return;
        }
        if ALLOWED
            .iter()
            .any(|(path, func, _)| *path == self.rel && *func == name)
        {
            return;
        }
        self.findings.push(format!(
            "{}: `{name}` is named like a security verdict and its whole body is a literal answer",
            self.rel
        ));
    }
}

impl<'ast> Visit<'ast> for Finder<'_> {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if !is_cfg_test(&node.attrs) {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if is_cfg_test(&node.attrs) {
            return;
        }
        self.check(&node.sig.ident.to_string(), &node.sig.output, &node.block);
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        if is_cfg_test(&node.attrs) {
            return;
        }
        self.check(&node.sig.ident.to_string(), &node.sig.output, &node.block);
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        if is_cfg_test(&node.attrs) {
            return;
        }
        if let Some(block) = &node.default {
            self.check(&node.sig.ident.to_string(), &node.sig.output, block);
        }
        visit::visit_trait_item_fn(self, node);
    }
}

/// Scan one source text. Returns the number of functions seen and the findings.
fn scan_source(rel: &str, text: &str) -> Result<(usize, Vec<String>), String> {
    let file = syn::parse_file(text).map_err(|e| format!("{rel} does not parse: {e}"))?;
    let mut finder = Finder {
        rel,
        functions: 0,
        findings: Vec::new(),
    };
    finder.visit_file(&file);
    Ok((finder.functions, finder.findings))
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = read.filter_map(Result::ok).collect();
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if kind.is_dir() {
            if name != "tests" && name != "target" {
                collect_rs(&path, out);
            }
        } else if kind.is_file() && path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn source_roots(root: &Path) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = ROOTS.iter().map(|r| root.join(r)).collect();
    for parent in MEMBER_PARENTS {
        let Ok(read) = fs::read_dir(root.join(parent)) else {
            continue;
        };
        let mut members: Vec<_> = read.filter_map(Result::ok).collect();
        members.sort_by_key(fs::DirEntry::file_name);
        for member in members {
            let src = member.path().join("src");
            if src.is_dir() {
                roots.push(src);
            }
        }
    }
    roots
}

/// # Errors
///
/// A verdict function whose body is a literal, a source file that does not
/// parse, or a scan that saw too few functions to mean anything.
pub fn run(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    for src in source_roots(root) {
        collect_rs(&src, &mut files);
    }
    let mut functions = 0usize;
    let mut findings = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let (count, found) = scan_source(&rel, &text)?;
        functions += count;
        findings.extend(found);
    }
    if functions < VACUITY_FLOOR {
        return Err(format!(
            "only {functions} functions seen in {} files; the gate would look at nothing",
            files.len()
        ));
    }
    if findings.is_empty() {
        return Ok(format!(
            "No constant security verdicts: {functions} functions in {} files.",
            files.len()
        ));
    }
    let mut msg = String::new();
    for finding in &findings {
        let _ = writeln!(msg, "FAIL: {finding}");
    }
    Err(msg)
}

/// # Errors
///
/// The first canary that misbehaves: each constant shape must be caught, and
/// computed answers, ordinary names and test code must pass.
pub fn self_test() -> Result<String, String> {
    let cases: &[(&str, &str, usize)] = &[
        ("literal true", "pub fn is_secure() -> bool { true }", 1),
        ("literal false", "pub fn is_quantum_resistant() -> bool { false }", 1),
        ("return true", "fn verify_thing() -> bool { return true; }", 1),
        ("kq prefix", "fn kq_p2p() -> bool { false }", 1),
        ("ok suffix", "fn handshake_ml_kem_ok() -> bool { false }", 1),
        (
            "constant through a call",
            "struct S; impl S { fn handshake_is_safe(&self) -> bool { Self::flag() } fn flag() -> bool { false } fn verify(&self) -> bool { true } }",
            1,
        ),
        (
            "trait default",
            "trait T { fn is_trusted(&self) -> bool { true } }",
            1,
        ),
        (
            "Ok(true)",
            "fn verify_all() -> Result<bool, ()> { Ok(true) }",
            1,
        ),
        ("a computed answer", "fn is_secure(x: u8) -> bool { x > 3 }", 0),
        ("an ordinary name", "fn is_empty() -> bool { true }", 0),
        (
            "several statements",
            "fn verify(x: u8) -> bool { let y = x; true }",
            0,
        ),
        (
            "a test module",
            "#[cfg(test)] mod t { fn is_secure() -> bool { true } }",
            0,
        ),
        ("a test function", "#[test] fn verify_ok() -> bool { true }", 0),
    ];
    for (label, source, expected) in cases {
        let (_, found) = scan_source("canary.rs", source)?;
        if found.len() != *expected {
            return Err(format!(
                "canary `{label}`: expected {expected} finding(s), got {}",
                found.len()
            ));
        }
    }
    let (count, _) = scan_source("canary.rs", "fn a() {} fn b() {}")?;
    if count != 2 {
        return Err(format!("canary: counted {count} functions, expected 2"));
    }
    Ok(format!(
        "no-constant-security-verdicts self-test ok: {} cases",
        cases.len() + 1
    ))
}
