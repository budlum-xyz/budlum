//! Pre-merge Rust syntax gate: every `.rs` source file in the repository must
//! parse as valid Rust AST (`syn::parse_file`).
//!
//! `git merge` is not a compiler: open pull requests #8, #9 and #55 shipped
//! syntactically broken `.rs` files (orphan `f` tokens, unclosed braces,
//! deleted method identifiers, and mid-expression field insertions). Running
//! `syn::parse_file` inside `budlum-gates` catches all of those classes in the
//! fast gate job before full workspace compilation.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const ROOTS: &[&str] = &[
    "src",
    "crates",
    "budzero",
    "bud",
    "xtask",
    "tests",
    "examples",
    "benches",
    "fuzz",
    "kani",
    "mobile",
    "contracts",
    "ops",
];

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "build",
    "dist",
    "Unselected files",
];

const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REPORTED: usize = 32;

fn walk_rs(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk_rs(&path, root, out);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(rel) = path.strip_prefix(root) {
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                out.push((rel_str, path));
            }
        }
    }
}

fn rust_files(root: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let build_rs = root.join("build.rs");
    if build_rs.is_file() {
        out.push((String::from("build.rs"), build_rs));
    }
    for dir_name in ROOTS {
        let dir = root.join(dir_name);
        if dir.is_dir() {
            walk_rs(&dir, root, &mut out);
        }
    }
    out
}

/// # Errors
///
/// Returns an error if no Rust files are found or if any `.rs` file fails
/// `syn::parse_file`.
pub fn run(root: &Path) -> Result<String, String> {
    let files = rust_files(root);
    if files.is_empty() {
        return Err(String::from("no Rust sources were scanned"));
    }
    let mut offenders = Vec::new();
    let mut scanned = 0usize;
    for (rel, path) in files {
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        if let Err(err) = syn::parse_file(&text) {
            offenders.push(format!("{rel}: {err}"));
        }
    }
    if !offenders.is_empty() {
        let mut msg = String::from("unparseable Rust sources:");
        for item in offenders.iter().take(MAX_REPORTED) {
            let _ = write!(msg, "\n  {item}");
        }
        if offenders.len() > MAX_REPORTED {
            let _ = write!(msg, "\n  ... and {} more", offenders.len() - MAX_REPORTED);
        }
        return Err(msg);
    }
    Ok(format!(
        "rust-syntax-is-parseable OK: {scanned} Rust source files parsed cleanly."
    ))
}

/// # Errors
///
/// Returns an error if the gate accepts any syntactically invalid canary or
/// rejects a valid Rust fixture.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-rust-syntax")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        let clean = "//! Braces in comments { ( [ and raw strings.\n\
pub fn answer() -> &'static str { r#\"unbalanced { [ (\"# }\n\
#[cfg(test)]\nmod tests {\n    #[test]\n    fn ok() { assert_eq!(super::answer().len(), 16); }\n}\n";
        put("src/clean.rs", clean)?;
        run(&dir).map_err(|e| format!("canary: clean Rust source was refused: {e}"))?;

        for (label, broken) in [
            ("orphan-f-token", "#[test]\nf\nfn orphan() {}\n"),
            ("unclosed-brace", "pub fn broken() { let _ = 1;\n"),
            (
                "deleted-method-ident",
                "pub struct S;\nimpl S { pub fn f(&self) { self.\n.clone(); } }\n",
            ),
            (
                "mid-expression-field",
                "pub fn f() -> u64 { let x = 1 +\n    field: 2\n}\n",
            ),
            (
                "orphan-variant",
                "pub enum E { A }\nBud3NotReady,\npub fn g() -> u8 { 0 }\n",
            ),
        ] {
            put("src/bad.rs", broken)?;
            if run(&dir).is_ok() {
                return Err(format!("canary `{label}` was accepted as valid Rust"));
            }
        }
        std::fs::remove_file(dir.join("src/bad.rs")).map_err(|e| e.to_string())?;
        run(&dir).map_err(|e| format!("canary: clean tree failed after cleanup: {e}"))?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "rust-syntax-is-parseable canary OK: five invalid AST shapes failed and clean Rust passed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn rust_syntax_gate_self_test() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
