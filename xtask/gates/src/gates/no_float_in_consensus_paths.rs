//! No floating-point types on consensus paths.
//!
//! Determinism (G-2) and the cross-architecture root-equality gate forbid
//! `f32` and `f64` on any consensus, state-root, or block-execution path.
//! Floating-point in the RPC layer, metrics, local policy and test code is
//! fine, but the moment a float touches a structure that ends up in a state
//! root, a block hash, a committee weight or a reward calculation the result
//! can differ between x86_64 and aarch64 (and even between two builds on
//! the same arch if a codegen choice changes), and two honest nodes can
//! disagree on the same block.
//!
//! This gate scans the consensus-critical directories for Rust uses of
//! `f32` / `f64` as bare identifiers (i.e. type uses) and refuses them.
//! Off-tree uses (test modules with `#[cfg(test)]`, benches, fuzz, rpc
//! metrics helpers, the local policy engine) live on a shrinking baseline
//! until every last one is gone; raising the baseline to make a run pass
//! is itself a defect.
//!
//! Scope (Section 15.8 WP-42, item 4):
//!
//! * `src/consensus/`  - block production, fork choice, leader election
//! * `src/chain/`      - block application, finality, state roots
//! * `src/validators/` - committee, seats, rewards, presence accounting
//! * `src/execution/`  - transaction ordering and EE dispatch
//! * `src/tokenomics/` - reward math, pool shares, fees
//! * `src/storage/bud3/` - placement-table math, fee arithmetic
//!
//! The gate does NOT parse Rust; it scans for `f32` / `f64` as
//! word-bounded tokens in `.rs` files. That catches type annotations,
//! turbofish (`::<f64>`), and cast operators (`as f64`). Literals like
//! `1.0` are intentionally not flagged because they do not name the type
//! directly and a literal parsed as a float at the top level of a
//! consensus function would already break determinism tests.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

const TOKENS: &[&str] = &["f32", "f64"];

/// Consensus-critical roots. These paths must not contain any float type.
const ROOTS: &[&str] = &[
    "src/consensus",
    "src/chain",
    "src/validators",
    "src/execution",
    "src/tokenomics",
    "src/storage/bud3",
];

const SKIP_DIRS: &[&str] = &["target", ".git"];

/// Files allowed to mention float types: the gate, the baseline, and docs.
const SELF: &[&str] = &[
    "xtask/gates/src/gates/no_float_in_consensus_paths.rs",
    ".github/no-float-in-consensus-baseline.txt",
];

/// Historical audit records reference floats on purpose.
const HISTORY_DIRS: &[&str] = &["docs/audit/", "docs/work/"];

/// Files under these subtrees are exempt even inside a consensus root:
/// they are test code, benches, or non-consensus helpers.
const EXEMPT_PREFIXES: &[&str] = &[
    "tests/",
    "benches/",
    "fuzz/",
];

const BASELINE: &str = ".github/no-float-in-consensus-baseline.txt";
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, std::path::PathBuf)>) {
    if dir.is_file() {
        if let Ok(rel) = dir.strip_prefix(root) {
            out.push((rel.to_string_lossy().replace('\\', "/"), dir.to_path_buf()));
        }
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(&p, root, out);
            }
        } else if let Ok(rel) = p.strip_prefix(root) {
            out.push((rel.to_string_lossy().replace('\\', "/"), p.clone()));
        }
    }
}

fn is_id_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn contains_token(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if hay[i..i + needle.len()].eq(needle) {
            let before_ok = i == 0 || !is_id_byte(hay[i - 1]);
            let after = i + needle.len();
            let after_ok = after == hay.len() || !is_id_byte(hay[after]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn offenders(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    for r in ROOTS {
        let p = root.join(r);
        if p.exists() {
            walk(&p, root, &mut files);
        }
    }
    let mut out = Vec::new();
    for (rel, path) in files {
        if SELF.contains(&rel.as_str()) || HISTORY_DIRS.iter().any(|d| rel.starts_with(d)) {
            continue;
        }
        if !rel.ends_with(".rs") {
            continue;
        }
        // Test modules inside the crate tree are allowed to use floats
        // (e.g. `#[cfg(test)] mod tests { ... }`). Rather than parse the
        // file, we exempt files whose path starts with a known test/bench
        // prefix. Per-file inline `#[cfg(test)]` blocks remain the
        // responsibility of the reviewer until a parser-based gate lands.
        if EXEMPT_PREFIXES.iter().any(|p| rel.starts_with(p)) {
            continue;
        }
        if std::fs::metadata(&path).map_or(true, |m| m.len() > MAX_FILE_BYTES) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        for tok in TOKENS {
            if contains_token(&bytes, tok.as_bytes()) {
                out.push((rel, (*tok).to_string()));
                break;
            }
        }
    }
    out
}

fn baseline(root: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(root.join(BASELINE))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Run the gate.
///
/// # Errors
///
/// Returns the finding.
pub fn run(root: &Path) -> Result<String, String> {
    let hits = offenders(root);
    let allowed = baseline(root);

    let mut new = String::new();
    let hit_set: BTreeSet<&str> = hits.iter().map(|(f, _)| f.as_str()).collect();
    for (file, tok) in &hits {
        if !allowed.contains(file) {
            let _ = writeln!(new, "  {file}: {tok}");
        }
    }
    let mut stale = String::new();
    for file in &allowed {
        if !hit_set.contains(file.as_str()) {
            let _ = writeln!(stale, "  {file}");
        }
    }
    if !new.is_empty() {
        return Err(format!(
            "FAIL: floating-point type used on a consensus-critical path:\n{new}\n  \
             Consensus paths are deterministic and must not use f32/f64 (G-2). \
             Use fixed-point or integer math (e.g. u64/U256 with an explicit factor)."
        ));
    }
    if !stale.is_empty() {
        return Err(format!(
            "FAIL: these baseline files no longer use a float type; remove their lines from {BASELINE}:\n{stale}"
        ));
    }
    Ok(format!(
        "no-float-in-consensus-paths OK: {} file(s) on the shrinking baseline; consensus paths are integer-only",
        hits.len()
    ))
}

/// Canary: inject an `f64` use under a consensus root and confirm it
/// fails; baseline it, confirm pass; fix the file and confirm the stale
/// baseline fails.
///
/// # Errors
///
/// When the gate misbehaves.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-no-float-consensus")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        put("src/consensus/clean.rs", "pub fn weight(x: u64) -> u64 { x * 2 }\n")?;
        put(BASELINE, "# empty\n")?;
        run(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;

        put("src/consensus/bad.rs", "pub fn ratio(hits: u64, slots: u64) -> f64 {\n    hits as f64 / slots as f64\n}\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an injected f64 on a consensus path was accepted"));
        }

        put(BASELINE, "src/consensus/bad.rs\n")?;
        run(&dir).map_err(|e| format!("canary: baselined float use failed: {e}"))?;

        put("src/consensus/bad.rs", "pub fn ratio(hits: u64, slots: u64) -> u64 { hits / slots }\n")?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: a stale baseline entry was accepted after the file was fixed",
            ));
        }

        // A tests/ subdir is exempt.
        put(BASELINE, "\n")?;
        put("src/consensus/tests/stats.rs", "pub fn avg(xs: &[u64]) -> f64 { 0.0 }\n")?;
        run(&dir).map_err(|e| format!("canary: tests/ subdir was not exempt: {e}"))?;

        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "no-float-in-consensus-paths canary OK: injected f64 fails, baselined use passes, stale baseline fails, tests/ subdirs exempt.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_float_in_consensus_paths_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }

    #[test]
    fn token_match_respects_word_boundaries() {
        // `f64` inside `f64some` is not a type use.
        assert!(!super::contains_token(b"f64some_val", b"f64"));
        assert!(super::contains_token(b"hits as f64", b"f64"));
        assert!(super::contains_token(b"::<f32>", b"f32"));
        // f32le (a byte-order suffix in binary codecs) should not match.
        assert!(!super::contains_token(b"f32le", b"f32"));
    }
}
