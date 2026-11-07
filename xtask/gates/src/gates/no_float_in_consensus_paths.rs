//! No floating-point arithmetic in consensus paths.
//!
//! IEEE 754 floating-point operations are sensitive to rounding modes, fused
//! multiply-add lowering, `NaN` payload propagation and transcendental library
//! differences across `x86_64` and `aarch64`. Any float inside a state
//! transition, block validation, validator registry, B.U.D. 3.0 storage rule,
//! AI verification path or `BudZero` crate risks a consensus split.
//!
//! This gate parses every non-test Rust source file under [`CONSENSUS_ROOTS`]
//! into a `syn` AST and rejects:
//!
//! * any `f32` or `f64` type path (fields, parameters, locals, `as f64` casts);
//! * any `f32::...` or `f64::...` expression path (`f64::NAN`, `f32::from_bits`);
//! * any floating-point literal (`syn::Lit::Float`, e.g. `0.5`, `1.0_f64`).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::visit::{self, Visit};

/// Consensus-critical source roots scanned by the gate.
const CONSENSUS_ROOTS: &[&str] = &[
    "src/chain",
    "src/consensus",
    "src/execution",
    "src/settlement",
    "src/validators",
    "src/storage/bud3",
    "src/ai/execution",
    "src/ai/verification_level.rs",
    "budzero",
];

/// Directory names that do not carry production consensus logic.
const SKIP_DIRS: &[&str] = &["target", ".git", "tests", "benches", "examples"];

/// Explicit non-consensus offline simulator paths excluded by specification.
const ALLOW_PATHS: &[&str] = &["src/storage/bud3/placement_tool.rs"];

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let tokens: String = attr
            .meta
            .to_token_stream()
            .to_string()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        tokens == "cfg(test)"
            || tokens.contains("(test,")
            || tokens.contains(",test)")
            || tokens.contains(",test,")
    })
}

fn is_float_ident(ident: &syn::Ident) -> bool {
    ident == "f32" || ident == "f64"
}

struct FloatVisitor {
    rel: String,
    findings: Vec<String>,
}

impl<'ast> Visit<'ast> for FloatVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !has_cfg_test(&node.attrs) {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !has_cfg_test(&node.attrs) {
            visit::visit_item_fn(self, node);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if !has_cfg_test(&node.attrs) {
            visit::visit_item_impl(self, node);
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !has_cfg_test(&node.attrs) {
            visit::visit_impl_item_fn(self, node);
        }
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if !has_cfg_test(&node.attrs) {
            visit::visit_item_struct(self, node);
        }
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if !has_cfg_test(&node.attrs) {
            visit::visit_item_enum(self, node);
        }
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        if !has_cfg_test(&node.attrs) {
            visit::visit_item_const(self, node);
        }
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if !has_cfg_test(&node.attrs) {
            visit::visit_item_type(self, node);
        }
    }

    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        if let Some(last) = node.path.segments.last() {
            if is_float_ident(&last.ident) {
                self.findings
                    .push(format!("{}: floating-point type `{}`", self.rel, last.ident));
            }
        }
        visit::visit_type_path(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if let Some(first) = node.path.segments.first() {
            if is_float_ident(&first.ident) {
                let expr = node.to_token_stream().to_string();
                self.findings
                    .push(format!("{}: floating-point path `{expr}`", self.rel));
            }
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_lit(&mut self, node: &'ast syn::Lit) {
        if let syn::Lit::Float(lit) = node {
            let token = lit.base10_digits();
            self.findings
                .push(format!("{}: floating-point literal `{token}`", self.rel));
        }
        visit::visit_lit(self, node);
    }
}

fn is_test_filename(name: &str) -> bool {
    name == "tests.rs" || name.ends_with("_tests.rs")
}

fn collect_rs_files(path: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) {
    if path.is_file() {
        if path.extension().is_some_and(|e| e == "rs") {
            if let Ok(rel) = path.strip_prefix(root) {
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                if !ALLOW_PATHS.contains(&rel_str.as_str()) {
                    out.push((rel_str, path.to_path_buf()));
                }
            }
        }
        return;
    }
    let Ok(rd) = std::fs::read_dir(path) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let child = entry.path();
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if ft.is_dir() {
            if !SKIP_DIRS.contains(&name_str) {
                collect_rs_files(&child, root, out);
            }
        } else if ft.is_file() && name_str.ends_with(".rs") && !is_test_filename(name_str) {
            if let Ok(rel) = child.strip_prefix(root) {
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                if !ALLOW_PATHS.contains(&rel_str.as_str()) {
                    out.push((rel_str, child));
                }
            }
        }
    }
}

fn check(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    for rel_root in CONSENSUS_ROOTS {
        let target = root.join(rel_root);
        if target.exists() {
            collect_rs_files(&target, root, &mut files);
        }
    }
    if files.is_empty() {
        return Err(String::from(
            "no consensus source files discovered; gate cannot pass vacuously",
        ));
    }
    let mut findings = Vec::new();
    for (rel, path) in &files {
        let src = std::fs::read_to_string(path).map_err(|e| format!("cannot read {rel}: {e}"))?;
        let parsed = syn::parse_file(&src).map_err(|e| format!("cannot parse {rel}: {e}"))?;
        let mut visitor = FloatVisitor {
            rel: rel.clone(),
            findings: Vec::new(),
        };
        visitor.visit_file(&parsed);
        findings.extend(visitor.findings);
    }
    if findings.is_empty() {
        Ok(format!(
            "OK: {} consensus Rust file(s) scanned, zero floating-point types or literals.",
            files.len()
        ))
    } else {
        let mut report = String::new();
        for f in &findings {
            let _ = writeln!(report, "  {f}");
        }
        Err(format!(
            "floating-point usage in consensus path(s) ({} finding(s)):\n{report}",
            findings.len()
        ))
    }
}

/// Run the consensus floating-point ban gate.
///
/// # Errors
///
/// Returns an error if no consensus files exist, if a file fails to parse, or
/// if any non-test consensus file uses `f32`, `f64`, or a float literal.
pub fn run(root: &Path) -> Result<String, String> {
    check(root)
}

/// Run the canary suite for `no-float-in-consensus-paths`.
///
/// # Errors
///
/// Returns an error if a clean staged tree fails or if injected `f64` types,
/// `as f32` casts, or float literals are accepted.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-no-float")?;
    let result = (|| {
        let chain_dir = dir.join("src/chain");
        std::fs::create_dir_all(&chain_dir).map_err(|e| e.to_string())?;
        let clean = chain_dir.join("state.rs");
        std::fs::write(
            &clean,
            "pub fn apply(x: u64) -> u64 { x.saturating_add(1) }\n#[cfg(test)]\nmod tests { fn metric() -> f64 { 0.5 } }\n",
        )
        .map_err(|e| e.to_string())?;
        check(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;

        let bad_type = chain_dir.join("bad_type.rs");
        std::fs::write(&bad_type, "pub fn ratio(x: u64) -> f64 { x as f64 }\n")
            .map_err(|e| e.to_string())?;
        match check(&dir) {
            Err(e) if e.contains("bad_type.rs") && e.contains("f64") => {}
            other => {
                return Err(format!(
                    "canary: injected f64 type was not caught: {other:?}"
                ))
            }
        }
        std::fs::remove_file(&bad_type).map_err(|e| e.to_string())?;

        let bad_lit = chain_dir.join("bad_lit.rs");
        std::fs::write(&bad_lit, "pub fn half() { let _ = 0.5; }\n")
            .map_err(|e| e.to_string())?;
        match check(&dir) {
            Err(e) if e.contains("bad_lit.rs") && e.contains("0.5") => {}
            other => {
                return Err(format!(
                    "canary: injected float literal was not caught: {other:?}"
                ))
            }
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "no-float-in-consensus-paths canary OK: f64 type, cast and float literal rejected; #[cfg(test)] allowed.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_float_in_consensus_paths_canary_and_repo() {
        assert!(self_test().is_ok());
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let verdict = run(&root);
        assert!(verdict.is_ok(), "{verdict:?}");
    }
}
