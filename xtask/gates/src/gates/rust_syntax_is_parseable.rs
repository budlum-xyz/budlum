//! Every tracked `.rs` file in the repository must parse as valid Rust syntax.
//!
//! # The failure this closes
//!
//! Multiple open branches pushed syntactically malformed `.rs` files (for
//! example orphaned match arms in `src/persistence/db.rs`, unclosed braces in
//! `crates/bud-codec/src/container.rs`, and malformed structs in
//! `src/storage/bud3/private_dedup.rs`). Without a dedicated syntax gate inside
//! `budlum-gates`, a branch touching workspaces not compiled by an early fast
//! step only discovers the parse failure late in compilation or not at all when
//! a workspace directory is not yet wired into root builds.
//!
//! Because `xtask/gates` already carries `syn` (`full` + `parsing`), parsing
//! every `.rs` source file across all Rust trees in the repository catches any
//! syntax error deterministically in milliseconds with zero false positives on
//! valid Rust 2021 code.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Top-level trees that hold Rust sources.
const ROOTS: &[&str] = &[
    "src",
    "crates",
    "budzero",
    "bud",
    "xtask",
    "fuzz",
    "kani",
    "execution",
    "mobile",
    "contracts",
    "tests",
    "benches",
    "examples",
];

/// Minimum `.rs` file count required so a mispointed root cannot pass by
/// scanning nothing.
const VACUITY_FLOOR: usize = 50;

/// Maximum parse failures printed in detail before summarising the remainder.
const MAX_REPORTED: usize = 25;

/// One syntax error in a repository `.rs` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxFinding {
    /// Repository-relative path.
    pub file: String,
    /// `syn` diagnostic text.
    pub error: String,
}

struct ScanOutcome {
    files_checked: usize,
    findings: Vec<SyntaxFinding>,
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if matches!(name, "target" | ".git" | "node_modules") {
            continue;
        }
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn rel_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn scan_tree(root: &Path) -> ScanOutcome {
    let mut files = Vec::new();
    for sub in ROOTS {
        let candidate = root.join(sub);
        if candidate.is_dir() {
            collect_rs_files(&candidate, &mut files);
        }
    }
    let mut findings = Vec::new();
    for file in &files {
        let rel = rel_display(root, file);
        let src = match fs::read_to_string(file) {
            Ok(s) => s,
            Err(err) => {
                findings.push(SyntaxFinding {
                    file: rel,
                    error: format!("unreadable UTF-8 source: {err}"),
                });
                continue;
            }
        };
        if let Err(err) = syn::parse_file(&src) {
            findings.push(SyntaxFinding {
                file: rel,
                error: err.to_string(),
            });
        }
    }
    ScanOutcome {
        files_checked: files.len(),
        findings,
    }
}

/// # Errors
///
/// Returns an error if fewer than [`VACUITY_FLOOR`] `.rs` files were scanned or
/// if any `.rs` file fails `syn::parse_file`.
pub fn run(root: &Path) -> Result<String, String> {
    let outcome = scan_tree(root);
    if outcome.files_checked < VACUITY_FLOOR {
        return Err(format!(
            "vacuous Rust syntax scan: checked {} `.rs` files, need at least {VACUITY_FLOOR}",
            outcome.files_checked
        ));
    }
    if outcome.findings.is_empty() {
        return Ok(format!(
            "OK: {} Rust source files parsed cleanly with syn.",
            outcome.files_checked
        ));
    }

    let mut msg = format!(
        "{} Rust source file(s) failed syntax parsing (out of {} checked):\n",
        outcome.findings.len(),
        outcome.files_checked
    );
    for finding in outcome.findings.iter().take(MAX_REPORTED) {
        let _ = writeln!(msg, "  - {}: {}", finding.file, finding.error);
    }
    if outcome.findings.len() > MAX_REPORTED {
        let _ = writeln!(
            msg,
            "  ... and {} more",
            outcome.findings.len() - MAX_REPORTED
        );
    }
    Err(msg)
}

fn populate_filler(src_dir: &Path, count: usize) -> Result<(), String> {
    for idx in 0..count {
        let path = src_dir.join(format!("valid_{idx}.rs"));
        let body = format!("pub const VALUE_{idx}: u64 = {idx};\n");
        fs::write(path, body).map_err(|e| format!("cannot write filler: {e}"))?;
    }
    Ok(())
}

/// # Errors
///
/// Returns a description of any canary that did not behave as expected.
pub fn self_test() -> Result<String, String> {
    let dir = super::rust_literals::exclusive_scratch_dir("budlum-gates-rust-syntax")?;
    let src_dir = dir.join("src");
    fs::create_dir(&src_dir).map_err(|e| format!("cannot create scratch src: {e}"))?;

    let mut failures: Vec<String> = Vec::new();

    // 1. Vacuity guard rejects an under-populated tree.
    populate_filler(&src_dir, 3)?;
    match run(&dir) {
        Err(msg) if msg.contains("vacuous Rust syntax scan") => {}
        other => failures.push(format!("vacuity canary did not fail as expected: {other:?}")),
    }

    // 2. Clean tree with >= VACUITY_FLOOR valid files passes.
    populate_filler(&src_dir, VACUITY_FLOOR)?;
    if let Err(msg) = run(&dir) {
        failures.push(format!("clean tree canary failed unexpectedly: {msg}"));
    }

    // 3. Unclosed brace is caught.
    let probe = src_dir.join("broken_unclosed.rs");
    fs::write(&probe, "pub fn broken() {\n    let x = 1;\n")
        .map_err(|e| format!("cannot write probe: {e}"))?;
    match run(&dir) {
        Err(msg) if msg.contains("src/broken_unclosed.rs") => {}
        other => failures.push(format!("unclosed-brace canary missed: {other:?}")),
    }

    // 4. Orphaned closing brace / match arm fragment is caught.
    fs::write(&probe, "pub fn ok() {}\n    Some(v) => v,\n}\n")
        .map_err(|e| format!("cannot write probe: {e}"))?;
    match run(&dir) {
        Err(msg) if msg.contains("src/broken_unclosed.rs") => {}
        other => failures.push(format!("orphaned-arm canary missed: {other:?}")),
    }

    let _ = fs::remove_dir_all(&dir);

    if failures.is_empty() {
        Ok(String::from(
            "SELF-TEST OK: rust-syntax-is-parseable (4 canaries passed)",
        ))
    } else {
        Err(failures.join("; "))
    }
}
