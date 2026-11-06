//! No floating point on the consensus-relevant production paths.
//!
//! The directive names the scope: `src/chain`, `src/consensus`,
//! `src/execution`, `src/settlement`, `src/validators`, `src/storage/bud3`,
//! the AI selection path, and `budzero/`. A float there makes a decision
//! depend on the machine's rounding mode, so two honest nodes can derive
//! different roots from the same blocks.
//!
//! The reader is `syn`, not a text search: a float inside a comment or a
//! string literal is not a float in the program. Test-only items are outside
//! the production path and are skipped. The AI selection path is the agent
//! ranking surface in `src/ai/registry.rs`; the display-only score helpers
//! in `src/ai/types.rs` are not a selection path and stay outside this gate.

use std::path::{Path, PathBuf};

use syn::visit::Visit;
use syn::Attribute;

const SCAN_DIRS: &[&str] = &[
    "src/chain",
    "src/consensus",
    "src/execution",
    "src/settlement",
    "src/validators",
    "src/storage/bud3",
    "budzero",
];

const SCAN_FILES: &[&str] = &["src/ai/registry.rs"];

fn is_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .meta
                .require_list()
                .is_ok_and(|list| {
                    list.tokens
                        .to_string()
                        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .any(|t| t == "test")
                })
    })
}

fn is_test_fn(attrs: &[Attribute]) -> bool {
    is_cfg_test(attrs)
        || attrs.iter().any(|attr| {
            attr.path()
                .segments
                .last()
                .is_some_and(|seg| seg.ident == "test")
        })
}

struct FloatFinder {
    path: String,
    findings: Vec<String>,
}

impl FloatFinder {
    fn report(&mut self, what: &str, line: usize) {
        self.findings
            .push(format!("{}:{line}: {what}", self.path));
    }
}

impl<'ast> Visit<'ast> for FloatFinder {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        if is_cfg_test(&module.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, module);
    }

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        if is_test_fn(&function.attrs) {
            return;
        }
        syn::visit::visit_item_fn(self, function);
    }

    fn visit_type_path(&mut self, type_path: &'ast syn::TypePath) {
        if let Some(segment) = type_path.path.segments.last() {
            if segment.ident == "f32" || segment.ident == "f64" {
                self.report("floating-point type", segment.ident.span().start().line);
            }
        }
        syn::visit::visit_type_path(self, type_path);
    }

    fn visit_expr_cast(&mut self, cast: &'ast syn::ExprCast) {
        if let syn::Type::Path(type_path) = &*cast.ty {
            if let Some(segment) = type_path.path.segments.last() {
                if segment.ident == "f32" || segment.ident == "f64" {
                    self.report("cast to a floating-point type", segment.ident.span().start().line);
                }
            }
        }
        syn::visit::visit_expr_cast(self, cast);
    }

    fn visit_lit_float(&mut self, literal: &'ast syn::LitFloat) {
        self.report("floating-point literal", literal.span().start().line);
    }
}

fn skip_path(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component.as_os_str().to_string_lossy().as_ref(),
            "tests" | "benches" | "fuzz" | "kani" | "examples" | "target" | ".git"
        )
    })
}

fn rust_files_under(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if skip_path(&path) {
            continue;
        }
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_dir() {
            rust_files_under(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn scan_file(path: &Path, root: &Path, findings: &mut Vec<String>) -> Result<(), String> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let file = syn::parse_file(&source)
        .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let mut finder = FloatFinder {
        path: relative,
        findings: Vec::new(),
    };
    finder.visit_file(&file);
    findings.append(&mut finder.findings);
    Ok(())
}

/// # Errors
///
/// Returns every floating-point use found on a scanned production path.
pub fn run(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    for dir in SCAN_DIRS {
        let path = root.join(dir);
        if path.is_dir() {
            rust_files_under(&path, &mut files)?;
        }
    }
    for file in SCAN_FILES {
        let path = root.join(file);
        if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    files.dedup();
    if files.is_empty() {
        return Err(String::from(
            "no consensus-path source files were found; the gate would check nothing",
        ));
    }
    let mut findings = Vec::new();
    for path in &files {
        scan_file(path, root, &mut findings)?;
    }
    if !findings.is_empty() {
        let mut message = String::from("floating point on a consensus-relevant production path:\n");
        for finding in findings.iter().take(40) {
            message.push_str("  ");
            message.push_str(finding);
            message.push('\n');
        }
        if findings.len() > 40 {
            message.push_str(&format!("  ... and {} more\n", findings.len() - 40));
        }
        return Err(message);
    }
    Ok(format!(
        "no_float_in_consensus_paths OK: {} production file(s) scanned, no f32/f64",
        files.len()
    ))
}

fn write_fixture(root: &Path, relative: &str, source: &str) -> Result<(), String> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, source).map_err(|e| e.to_string())
}

/// # Errors
///
/// Returns a finding when a canary does not behave as the gate promises.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-no-float")?;
    let result = (|| {
        write_fixture(
            &dir,
            "src/chain/clean.rs",
            "pub fn add(a: u64, b: u64) -> u64 { a.saturating_add(b) }\n",
        )?;
        run(&dir)?;

        write_fixture(
            &dir,
            "src/consensus/float.rs",
            "pub fn score(x: u64) -> f64 { x as f64 * 0.5 }\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an f64 consensus score passed"));
        }
        std::fs::remove_file(dir.join("src/consensus/float.rs")).map_err(|e| e.to_string())?;

        write_fixture(
            &dir,
            "src/chain/tests/float_ok.rs",
            "pub fn check(x: f64) -> f64 { x }\n",
        )?;
        write_fixture(
            &dir,
            "src/chain/inline_test.rs",
            "pub fn production() -> u64 { 1 }\n#[cfg(test)]\nmod tests { fn t() { let x: f64 = 0.5; assert!(x > 0.0); } }\n",
        )?;
        write_fixture(
            &dir,
            "src/chain/comment.rs",
            "// f64 was here once\npub const NAME: &str = \"f64\";\n",
        )?;
        run(&dir)?;

        write_fixture(
            &dir,
            "src/ai/registry.rs",
            "pub fn rank(scores: &[f64]) -> f64 { scores[0] }\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a float AI ranking passed"));
        }
        Ok(String::from(
            "no_float_in_consensus_paths canary OK: clean passes, f64 type/cast/literal fail, test-only and comment/string floats pass, AI ranking float fails",
        ))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_float_in_consensus_paths_catches_injected_f64() {
        super::self_test().expect("no-float canary");
    }
}
