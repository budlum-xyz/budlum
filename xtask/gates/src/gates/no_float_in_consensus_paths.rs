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

/// A float the repository still owes, with the finding that records it.
///
/// `BLG-240` is verifier/agent ranking in `f64`, display only. Closing it is
/// an API change owned by `WP-45` (open PR #44), not by this CI package. The
/// pin is a ceiling equal to the measured AST finding count on this tree, so
/// one new float in the pinned file fails; a pin whose file has no float left
/// is stale and fails, so closing the finding cannot leave a silent exemption
/// behind.
///
/// Measured against this tree by AST position, not counted with `grep`:
/// three `f64` types in the two ranking return types and the local binding,
/// two float literals in the quantization, and one `as f64` cast. Six.
///
/// A doc comment that mentions `f64` is a string literal, not a float, and is
/// not counted; neither is the text of `const NAME: &str = "f64"`. A cast is
/// counted once: the target type of `expr as f64` is reported by the cast
/// itself, and visiting it again as a type would double it.
const PINNED: &[(&str, usize, &str, &str)] = &[("src/ai/registry.rs", 6, "BLG-240", "WP-45")];

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
    scope: String,
    findings: Vec<String>,
}

impl FloatFinder {
    fn report(&mut self, what: &str) {
        self.findings
            .push(format!("{}:{}: {what}", self.path, self.scope));
    }
}

impl<'ast> Visit<'ast> for FloatFinder {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        if is_cfg_test(&module.attrs) {
            return;
        }
        let prev = std::mem::replace(&mut self.scope, module.ident.to_string());
        syn::visit::visit_item_mod(self, module);
        self.scope = prev;
    }

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        if is_test_fn(&function.attrs) {
            return;
        }
        let prev = std::mem::replace(&mut self.scope, function.sig.ident.to_string());
        syn::visit::visit_item_fn(self, function);
        self.scope = prev;
    }

    fn visit_impl_item_fn(&mut self, method: &'ast syn::ImplItemFn) {
        if is_test_fn(&method.attrs) {
            return;
        }
        let prev = std::mem::replace(&mut self.scope, method.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, method);
        self.scope = prev;
    }

    fn visit_type_path(&mut self, type_path: &'ast syn::TypePath) {
        if let Some(segment) = type_path.path.segments.last() {
            if segment.ident == "f32" || segment.ident == "f64" {
                self.report("floating-point type");
            }
        }
        syn::visit::visit_type_path(self, type_path);
    }

    fn visit_expr_cast(&mut self, cast: &'ast syn::ExprCast) {
        if let syn::Type::Path(type_path) = &*cast.ty {
            if let Some(segment) = type_path.path.segments.last() {
                if segment.ident == "f32" || segment.ident == "f64" {
                    self.report("cast to a floating-point type");
                    // Visit the operand only. The full walk would descend
                    // into the target type as well and `visit_type_path`
                    // would report this one float a second time, which would
                    // make the measured count - and so the pin - wrong.
                    syn::visit::visit_expr(self, &cast.expr);
                    return;
                }
            }
        }
        syn::visit::visit_expr_cast(self, cast);
    }

    fn visit_lit_float(&mut self, _literal: &'ast syn::LitFloat) {
        self.report("floating-point literal");
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
        scope: String::from("<module>"),
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
    let mut pinned_notes = Vec::new();
    for (path, ceiling, finding, owner) in PINNED {
        if !root.join(path).is_file() {
            continue;
        }
        let prefix = format!("{path}:");
        let count = findings.iter().filter(|f| f.starts_with(prefix.as_str())).count();
        if count == 0 {
            return Err(format!(
                "stale float pin {finding} for {path}: the file has no f32/f64 left; remove the pin when {owner} closes it"
            ));
        }
        if count > *ceiling {
            return Err(format!(
                "{path}: {count} floating-point findings exceed the {finding} ceiling {ceiling} owned by {owner}"
            ));
        }
        pinned_notes.push(format!("{path}: {count}/{ceiling} pinned by {finding} ({owner})"));
    }
    let unpinned: Vec<&String> = findings
        .iter()
        .filter(|f| {
            !PINNED
                .iter()
                .any(|(path, _, _, _)| f.starts_with(&format!("{path}:")))
        })
        .collect();
    if !unpinned.is_empty() {
        let mut message = String::from("floating point on a consensus-relevant production path:\n");
        for finding in unpinned.iter().take(40) {
            message.push_str("  ");
            message.push_str(finding);
            message.push('\n');
        }
        if unpinned.len() > 40 {
            message.push_str(&format!("  ... and {} more\n", unpinned.len() - 40));
        }
        return Err(message);
    }
    let mut ok = format!(
        "no_float_in_consensus_paths OK: {} production file(s) scanned, no un-pinned f32/f64",
        files.len()
    );
    for note in pinned_notes {
        ok.push_str("; ");
        ok.push_str(&note);
    }
    Ok(ok)
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

        // A pinned file at exactly its ceiling passes - the pin is a ceiling,
        // not a ban - and one float above it fails. The fixture has to land on
        // the ceiling exactly, or it passes for the wrong reason.
        // Five `f64` parameters and an `f64` return: six findings, the ceiling.
        let at_ceiling =
            "pub fn rank(a: f64, b: f64, c: f64, d: f64, e: f64) -> f64 { a }\n";
        write_fixture(&dir, "src/ai/registry.rs", at_ceiling)?;
        match run(&dir) {
            Ok(note) => {
                if !note.contains("6/6") {
                    return Err(format!(
                        "canary: a pinned file at its ceiling must be reported as 6/6, got {note}"
                    ));
                }
            }
            Err(e) => return Err(format!("canary: a pinned file at its ceiling failed: {e}")),
        }
        write_fixture(
            &dir,
            "src/ai/registry.rs",
            "pub fn rank(a: f64, b: f64, c: f64, d: f64, e: f64, f: f64, g: f64) -> f64 { a }\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: a float AI ranking above the BLG-240 ceiling passed",
            ));
        }
        // The pin must not survive the float it pins: a pinned file with no
        // float left is a stale exemption.
        write_fixture(&dir, "src/ai/registry.rs", "pub fn rank(a: u64) -> u64 { a }\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a stale float pin passed"));
        }
        Ok(String::from(
            "no_float_in_consensus_paths canary OK: clean passes, f64 type/cast/literal fail, test-only and comment/string floats pass, AI ranking float above the BLG-240 ceiling fails",
        ))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    /// The injected canary, run as a unit test too.
    ///
    /// The cargo-test log is the third place a named test can be required, so
    /// this name is asserted by hand rather than left to `--self-test` alone.
    #[test]
    fn no_float_in_consensus_paths_catches_injected_f64() {
        super::self_test().expect("no-float canary");
    }
}
