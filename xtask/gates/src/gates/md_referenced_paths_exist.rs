//! Gate: a file path a markdown file names must exist in the tree.
//!
//! Where this came from: `README.md` told the reader to run
//! `bash ops/scripts/devnet-multinode-smoke.sh`, a script that was never
//! committed to git (`git log --all` for it is empty). The script family had
//! moved to `xtask/tools` and the migration table lived in
//! `xtask/tools/src/bin/budlum-tools.rs`, but the reader's first run still
//! ended in "No such file or directory". The badge gates already enforce that
//! a *claim* cannot be stale ("a translated claim is still a claim"); this is
//! the same rule for a *path*: a command a document hands the reader must name
//! something that exists at that commit.
//!
//! What it checks: every tracked `.md` file, both markdown link targets and
//! inline-code spans that look like repository file paths. A reference must
//! exist in the tree, or be listed in the checked-in ratchet baseline
//! `.github/md-path-drift-baseline.txt` (known pre-existing debt). The
//! baseline may only shrink: a line that no longer violates is itself a
//! failure, so fixing drift deletes its line in the same change.
//!
//! What it deliberately does not check: URLs, absolute paths, wildcards,
//! placeholders (`<name>`, `$VAR`, `~`), `target/` build output and paths with
//! `..` - those are prose, not tree claims. The filter is conservative on
//! purpose: a gate that cries wolf gets silenced, and a silenced gate is the
//! failure mode this repository refuses.

use std::collections::BTreeSet;
use std::path::Path;

const BASELINE: &str = ".github/md-path-drift-baseline.txt";

/// Does this inline token look like a repository file path we can check?
fn is_checkable_path(tok: &str) -> bool {
    if tok.is_empty() || tok.len() > 200 {
        return false;
    }
    if !tok
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-'))
    {
        return false;
    }
    if tok.contains("..") || tok.starts_with('/') || tok.starts_with("./") {
        return false;
    }
    // A bare extension mention (".rs") is prose about a class of files.
    if tok.starts_with('.') && !tok.contains('/') {
        return false;
    }
    if tok.starts_with("http") || tok.starts_with("www.") {
        return false;
    }
    // Build output and operator-created runtime state are prose about things
    // that exist outside the tree at run time, not tree claims.
    let first = tok.split('/').next().unwrap_or("");
    if matches!(first, "target" | "secrets") {
        return false;
    }
    // A checkable path either points into a directory or names a file with an
    // extension; bare words like `fail-closed` are prose. Extension matching
    // goes through `Path::extension`, not string suffixes.
    let known_ext = matches!(
        Path::new(tok).extension().and_then(|e| e.to_str()),
        Some(
            "rs" | "md" | "toml" | "yml" | "yaml" | "sh" | "lock" | "proto" | "json" | "sol" | "py"
        )
    );
    (tok.contains('/') || known_ext) && tok.contains('.')
}

/// Inline-code spans: `...` runs of one or more backticks.
fn inline_code_spans(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'`' {
            let start = i;
            while i < bytes.len() && bytes[i] == b'`' {
                i += 1;
            }
            let fence_len = i - start;
            // Find the matching close fence of the same length.
            let rest = &line[i..];
            let mut j = 0;
            let mut closed = None;
            while j < rest.len() {
                if rest.as_bytes()[j] == b'`' {
                    let s = j;
                    while j < rest.len() && rest.as_bytes()[j] == b'`' {
                        j += 1;
                    }
                    if j - s == fence_len {
                        closed = Some(s);
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            if let Some(close) = closed {
                out.push(rest[..close].trim().to_string());
                i += close + fence_len;
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Local markdown link targets: [text](target), skipping URLs and anchors.
fn link_targets(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find("](") {
        let after = &rest[open + 2..];
        if let Some(close) = after.find(')') {
            let target = after[..close].trim();
            if !target.is_empty()
                && !target.starts_with('#')
                && !target.starts_with("http")
                && !target.contains("://")
                && !target.contains(' ')
            {
                // Strip a trailing #anchor from a local path.
                let path = target.split('#').next().unwrap_or(target);
                if !path.is_empty() {
                    out.push(path.to_string());
                }
            }
            rest = &after[close + 1..];
        } else {
            break;
        }
    }
    out
}

fn md_references(text: &str) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    for line in text.lines() {
        for span in inline_code_spans(line) {
            // A span may be a whole command (`bash ops/scripts/x.sh`); each
            // whitespace-separated word is a path candidate.
            for word in span.split_whitespace() {
                if is_checkable_path(word) {
                    refs.insert(word.to_string());
                }
            }
        }
        for target in link_targets(line) {
            if is_checkable_path(&target) {
                refs.insert(target);
            }
        }
    }
    refs
}

fn tracked_md_files(root: &Path) -> Result<Vec<String>, String> {
    let out = std::process::Command::new("git")
        .args(["-C", &root.display().to_string(), "ls-files", "*.md"])
        .output()
        .map_err(|e| format!("git ls-files failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Does the reference resolve? A document may name a path from the repository
/// root (`src/core/block.rs`), from its own directory (`mod.rs` next to the
/// README), or by a bare filename it expects somewhere in the tree (`ci.yml`).
/// Any one witness is enough; none means the reference is drift.
fn reference_resolves(root: &Path, md_file: &str, reference: &str) -> bool {
    if root.join(reference).exists() {
        return true;
    }
    if let Some(dir) = Path::new(md_file).parent() {
        if root.join(dir).join(reference).exists() {
            return true;
        }
    }
    let wanted = Path::new(reference)
        .file_name()
        .map(|f| f.to_string_lossy().to_string());
    if let Some(wanted) = wanted {
        if let Ok(out) = std::process::Command::new("git")
            .args(["-C", &root.display().to_string(), "ls-files"])
            .output()
        {
            let hit = String::from_utf8_lossy(&out.stdout).lines().any(|l| {
                Path::new(l)
                    .file_name()
                    .is_some_and(|f| f.to_string_lossy() == wanted)
            });
            if hit {
                return true;
            }
        }
    }
    false
}

/// One `md: reference` record per missing reference.
fn violations(root: &Path) -> Result<(BTreeSet<String>, usize), String> {
    let files = tracked_md_files(root)?;
    if files.is_empty() {
        return Err(String::from(
            "FAIL: no markdown file was scanned - wrong root, the gate would be vacuous",
        ));
    }
    let mut missing = BTreeSet::new();
    let mut scanned = 0usize;
    for md in &files {
        let Ok(text) = std::fs::read_to_string(root.join(md)) else {
            continue;
        };
        scanned += 1;
        for r in md_references(&text) {
            if !reference_resolves(root, md, &r) {
                missing.insert(format!("{md}: {r}"));
            }
        }
    }
    if scanned == 0 {
        return Err(String::from(
            "FAIL: markdown files listed but none readable - the gate would be vacuous",
        ));
    }
    Ok((missing, scanned))
}

fn baseline_entries(root: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(root.join(BASELINE))
        .map(|t| {
            t.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn run(root: &Path) -> Result<String, String> {
    let (missing, scanned) = violations(root)?;
    let baseline = baseline_entries(root);

    // New violations: missing and not in the baseline.
    let new: Vec<&String> = missing.difference(&baseline).collect();
    // Stale baseline lines: allowed but no longer violating. The ratchet may
    // only shrink, so a stale line is a failure in the same change that fixed
    // its drift.
    let stale: Vec<&String> = baseline.difference(&missing).collect();

    if !new.is_empty() || !stale.is_empty() {
        use std::fmt::Write as _;
        let mut msg = String::new();
        for v in &new {
            let _ = writeln!(
                msg,
                "FAIL [gate] md-referenced-paths-exist: {v} names a path that does not exist"
            );
        }
        for s in &stale {
            let _ = writeln!(
                msg,
                "FAIL [gate] md-referenced-paths-exist: {BASELINE} still lists {s}, whose drift is fixed - delete the line (the ratchet may only shrink)"
            );
        }
        return Err(msg.trim_end().to_string());
    }
    Ok(format!(
        "OK: {scanned} markdown files, every named path exists ({} known-baseline)",
        baseline.len()
    ))
}

pub fn self_test() -> Result<String, String> {
    let tmp = std::env::temp_dir().join(format!("md-paths-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let git = |args: &[&str]| -> Result<(), String> {
        std::process::Command::new("git")
            .args(["-C", &tmp.display().to_string()])
            .args(args)
            .output()
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    let io = |e: std::io::Error| e.to_string();
    std::fs::create_dir_all(tmp.join("docs")).map_err(io)?;
    std::fs::create_dir_all(tmp.join(".github")).map_err(io)?;
    std::fs::write(tmp.join("docs/real.md"), "exists").map_err(io)?;
    std::fs::write(tmp.join(BASELINE), "# empty\n").map_err(io)?;
    git(&["init", "-q"])?;

    // Canary 1: a reference to a path that does not exist must be caught.
    std::fs::write(
        tmp.join("README.md"),
        "Run `bash ops/scripts/never-committed.sh` and see docs/real.md.\n",
    )
    .map_err(io)?;
    git(&["add", "-A"])?;
    match run(&tmp) {
        Err(msg) if msg.contains("never-committed.sh") => {}
        other => {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(format!(
                "self-test: a missing reference was NOT caught (got: {other:?})"
            ));
        }
    }

    // Canary 2 (honest control): once the reference is real, the gate passes.
    std::fs::write(tmp.join("README.md"), "See docs/real.md for the map.\n").map_err(io)?;
    git(&["add", "-A"])?;
    match run(&tmp) {
        Ok(msg) if msg.contains("every named path exists") => {}
        other => {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(format!(
                "self-test: the honest fixture did NOT pass (got: {other:?})"
            ));
        }
    }

    // Canary 3: a stale baseline line must fail, so the ratchet may only shrink.
    std::fs::write(tmp.join(BASELINE), "README.md: docs/real.md\n").map_err(io)?;
    git(&["add", "-A"])?;
    match run(&tmp) {
        Err(msg) if msg.contains("may only shrink") => {}
        other => {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(format!(
                "self-test: a stale baseline line was NOT caught (got: {other:?})"
            ));
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(String::from(
        "OK: canary 1 missing-reference caught, canary 2 honest fixture passes, canary 3 stale-baseline caught",
    ))
}
