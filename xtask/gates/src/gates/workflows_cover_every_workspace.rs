//! Every Cargo workspace is built by a workflow, or named as exempt.
//!
//! Gate code: `K-WORKSPACE-COVERED`. A finding or a document that names this
//! code resolves here.
//!
//! # Why
//!
//! A workspace that no workflow builds is a crate nobody compiles on a pull
//! request. It can rot for months, and the first time it is read is the day it
//! is needed. This tree has seven workspace roots - the root manifest is a
//! plain package, so the separate ones are the workspaces - and the count is
//! discovered, not listed, because a hand-kept list goes stale the moment a
//! workspace is added.
//!
//! # What "covered" means
//!
//! The workspace's directory appears as a path in a workflow file, followed by
//! something a path continues with. `fuzz/` is covered by
//! `--manifest-path fuzz/Cargo.toml`; a bare mention of `kani` inside a word
//! (`kani-slow.yml` names the job, not the path) is not. The root workspace is
//! covered by any `cargo` invocation with no `--manifest-path`, which is every
//! other step in `ci.yml`.
//!
//! # The two exemptions
//!
//! `contracts/object-layer/cosmwasm` and `contracts/object-layer/svm` are
//! workspaces with empty `[workspace]` tables and their own toolchains
//! (cosmwasm/optimizer, `cargo build-sbf`). No stock GitHub runner builds
//! them, and a job that pretended to would need the two toolchains installed
//! first. They are exempt by name here, with the reason, and the exemption is
//! itself checked: if the directory disappears, or a workflow starts building
//! it, the gate fails rather than carrying a permission nobody re-reads.
//! `solidity.yml` is not counted as their cover; it compiles Solidity with
//! `solc`, which says nothing about a Rust workspace.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Workspaces no stock runner builds, with the reason. Each must still exist
/// and still need the exemption.
const EXEMPT: &[(&str, &str)] = &[
    (
        "contracts/object-layer/cosmwasm",
        "cosmwasm/optimizer builds it for wasm32; the runner has no optimizer",
    ),
    (
        "contracts/object-layer/svm",
        "`cargo build-sbf` builds it; the runner has no Solana toolchain",
    ),
];

/// A scan that found fewer workspaces than this is looking at the wrong tree.
const VACUITY_FLOOR: usize = 5;

fn read(root: &Path, rel: &str) -> Result<String, String> {
    let f = root.join(rel);
    std::fs::read_to_string(&f).map_err(|e| format!("cannot read {rel}: {e}"))
}

/// Every `Cargo.toml` under `root` that declares a `[workspace]` table.
/// Repository-relative directory, sorted; the root workspace is `.`.
fn workspace_roots(root: &Path) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if kind.is_dir() {
                if name_str != "target" && name_str != ".git" && name_str != "node_modules" {
                    stack.push(entry.path());
                }
            } else if name_str == "Cargo.toml" {
                let Ok(text) = std::fs::read_to_string(entry.path()) else {
                    continue;
                };
                // A real table line, not the word inside a comment.
                let declares = text
                    .lines()
                    .any(|l| l.trim_start().starts_with("[workspace]"));
                if !declares {
                    continue;
                }
                let Ok(rel) = entry.path().strip_prefix(root) else {
                    continue;
                };
                let rel = match rel.parent() {
                    Some(parent) => parent.to_string_lossy(),
                    None => std::borrow::Cow::Borrowed(""),
                };
                out.push(rel.replace('\\', "/"));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Every workflow file's text, concatenated, and the file count.
///
/// One string is enough: the question is whether a path is used anywhere. The
/// count is what makes a scan that read nothing fail instead of pass.
fn workflow_text(root: &Path) -> Result<String, String> {
    let dir = root.join(".github/workflows");
    let rd = std::fs::read_dir(&dir).map_err(|e| format!("no .github/workflows: {e}"))?;
    let mut text = String::new();
    let mut count = 0usize;
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !(name_str.ends_with(".yml") || name_str.ends_with(".yaml")) {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        count += 1;
        text.push_str(&body);
        text.push('\n');
    }
    if count == 0 {
        return Err(String::from(".github/workflows holds no workflow file"));
    }
    Ok(text)
}

/// Does any command in `text` name the workspace directory `ws` as a path?
///
/// Both sides matter. Before: the character must not continue a longer path
/// segment, so `xws3` is not `ws3`. After: the character must be `/`, because
/// what follows a workspace directory in a command is a file
/// (`crates/budscan/Cargo.toml`). A needle that only needs the next character to
/// be a separator counts `ws30/` as `ws3`, which is the canary's second case.
fn names_the_path(text: &str, ws: &str) -> bool {
    let mut from = 0usize;
    while let Some(idx) = text[from..].find(ws) {
        let start = from + idx;
        let end = start + ws.len();
        let before_ok = match text.get(..start).and_then(|t| t.chars().next_back()) {
            None => true,
            Some(c) => !(c.is_alphanumeric() || c == '_' || c == '-'),
        };
        let after_ok = text.get(end..).is_some_and(|t| t.starts_with('/'));
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// Which workspaces a workflow builds, and which it does not. Sorted by
/// directory; the root workspace is `.`.
fn measure(root: &Path) -> Result<(Vec<String>, Vec<String>), String> {
    let roots = workspace_roots(root)?;
    if roots.len() < VACUITY_FLOOR {
        return Err(format!(
            "only {} workspace root(s) found; the scan is looking at the wrong tree",
            roots.len()
        ));
    }
    let text = workflow_text(root)?;
    let mut covered: Vec<String> = Vec::new();
    let mut uncovered: Vec<String> = Vec::new();
    for ws in roots {
        if ws.is_empty() {
            // The root workspace is built by any cargo command with no
            // `--manifest-path`, and those are the commonest in the workflows.
            let hit = text.contains("cargo build")
                || text.contains("cargo test")
                || text.contains("cargo clippy")
                || text.contains("cargo fmt");
            if hit {
                covered.push(String::from("."));
            } else {
                uncovered.push(String::from("."));
            }
            continue;
        }
        if names_the_path(&text, &ws) || EXEMPT.iter().any(|(p, _)| *p == ws) {
            covered.push(ws);
        } else {
            uncovered.push(ws);
        }
    }
    Ok((covered, uncovered))
}

/// An exemption that no longer names a directory, or no longer saves anything,
/// is stale. Both are lies the next reader cannot see, and a permission nobody
/// re-reads is the way a list like this turns into decoration.
fn stale_exemptions(root: &Path) -> Vec<String> {
    let mut stale = Vec::new();
    for (path, _) in EXEMPT {
        if !root.join(path).is_dir() {
            stale.push(format!("{path}: the directory is gone"));
            continue;
        }
        // `covered` contains it either because the exemption applied or
        // because a workflow now names it; tell the two apart.
        let named = workflow_text(root).is_ok_and(|text| names_the_path(&text, path));
        if named {
            stale.push(format!(
                "{path}: a workflow now builds it, so the exemption is no longer needed"
            ));
        }
    }
    stale
}

/// The gate.
///
/// # Errors
///
/// A workspace no workflow builds, or a stale exemption.
pub fn run(root: &Path) -> Result<String, String> {
    let (covered, uncovered) = measure(root)?;
    let stale = stale_exemptions(root);
    if !stale.is_empty() {
        return Err(format!(
            "a workspace exemption is stale, so the list is no longer the truth:\n  {}",
            stale.join("\n  ")
        ));
    }
    if uncovered.is_empty() {
        return Ok(format!(
            "OK: every Cargo workspace is built by a workflow ({} covered, {} exempt: {}).",
            covered.len().saturating_sub(EXEMPT.len()),
            EXEMPT.len(),
            EXEMPT.iter()
                .map(|(p, _)| *p)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let mut msg = String::from(
        "a Cargo workspace is built by no workflow, so nothing compiles it on a pull\n  \
         request and its rot is invisible:\n",
    );
    for ws in &uncovered {
        let _ = writeln!(
            msg,
            "  {ws}: add a job that runs `cargo build --manifest-path {ws}/Cargo.toml`,\n    \
             or add it to EXEMPT in this gate with the toolchain that really builds it"
        );
    }
    Err(msg)
}

/// Stage a tree with `count` workspaces, each covered by a workflow line that
/// names its path, plus the two exempt directories.
fn stage_tree(dir: &Path, count: usize) -> Result<(), String> {
    let mut jobs = String::from("jobs:\n  build:\n    steps:\n");
    for i in 0..count {
        let rel = format!("ws{i}");
        std::fs::create_dir_all(dir.join(&rel)).map_err(|e| e.to_string())?;
        std::fs::write(
            dir.join(&rel).join("Cargo.toml"),
            format!("[package]\nname = \"ws{i}\"\n\n[workspace]\n"),
        )
        .map_err(|e| e.to_string())?;
        let _ = writeln!(
            jobs,
            "      - run: cargo build --manifest-path {rel}/Cargo.toml"
        );
    }
    std::fs::create_dir_all(dir.join(".github/workflows")).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(".github/workflows/ci.yml"), jobs).map_err(|e| e.to_string())?;
    for (path, _) in EXEMPT {
        std::fs::create_dir_all(dir.join(path)).map_err(|e| e.to_string())?;
        std::fs::write(
            dir.join(path).join("Cargo.toml"),
            "[package]\nname = \"exempt\"\n\n[workspace]\n",
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The canary: a workspace whose path no workflow names fails and names only
/// itself; a path that is a prefix of a longer word does not cover; and an
/// exemption that stopped being needed fails.
///
/// # Errors
///
/// The first staging step or assertion that misbehaves.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-wscov")?;
    let result = (|| {
        // An empty tree is vacuous and must say so.
        if measure(&dir).is_ok() {
            return Err(String::from("canary: an empty tree passed"));
        }
        stage_tree(&dir, VACUITY_FLOOR)?;
        let (covered, uncovered) =
            measure(&dir).map_err(|e| format!("canary: a covered tree failed: {e}"))?;
        if !uncovered.is_empty() {
            return Err(format!(
                "canary: a covered tree reported {uncovered:?} as uncovered"
            ));
        }
        if covered.len() < VACUITY_FLOOR {
            return Err(format!("canary: only {} covered", covered.len()));
        }

        // 1. Drop one workspace's build line: exactly that one is reported.
        let ci = read(&dir, ".github/workflows/ci.yml")?;
        let dropped = ci
            .lines()
            .filter(|l| !l.contains("ws3/Cargo.toml"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(dir.join(".github/workflows/ci.yml"), &dropped)
            .map_err(|e| e.to_string())?;
        let (_, uncovered) = measure(&dir).map_err(|e| e.to_string())?;
        if uncovered != vec![String::from("ws3")] {
            return Err(format!(
                "canary: dropping one build line reported {uncovered:?}, not [ws3]"
            ));
        }

        // 2. A path that is only the prefix of a longer word does not cover it.
        let renamed = ci.replace("ws3/Cargo.toml", "ws30/Cargo.toml");
        std::fs::write(dir.join(".github/workflows/ci.yml"), &renamed)
            .map_err(|e| e.to_string())?;
        let (_, uncovered) = measure(&dir).map_err(|e| e.to_string())?;
        if uncovered != vec![String::from("ws3")] {
            return Err(format!("canary: `ws30/` covered `ws3`: {uncovered:?}"));
        }

        // 3. An exemption that a workflow now covers is stale and fails.
        let mut extra = ci.clone();
        extra.push_str(
            "      - run: cargo build --manifest-path contracts/object-layer/svm/Cargo.toml\n",
        );
        std::fs::write(dir.join(".github/workflows/ci.yml"), &extra).map_err(|e| e.to_string())?;
        let stale = stale_exemptions(&dir);
        if !stale.iter().any(|s| s.contains("svm")) {
            return Err(format!(
                "canary: a now-covered exemption was not stale: {stale:?}"
            ));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "workspace-coverage canary OK: a dropped build line, a prefix that is not a path and a \
         stale exemption all behaved.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_word_that_starts_with_a_path_is_not_that_path() {
        let text = "cargo build --manifest-path ws30/Cargo.toml\n";
        assert!(!names_the_path(text, "ws3"), "`ws30/` covered `ws3`");
        let named = "cargo build --manifest-path ws3/Cargo.toml\n";
        assert!(names_the_path(named, "ws3"));
        assert!(!names_the_path("xws3/Cargo.toml", "ws3"));
        assert!(!names_the_path("ws3", "ws3"));
        assert!(names_the_path("crates/budscan/Cargo.toml", "crates/budscan"));
    }

    #[test]
    fn workspace_discovery_ignores_a_commented_table() {
        let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-wscov-t")
            .unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir_all(dir.join("a")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(
            dir.join("a/Cargo.toml"),
            "# [workspace]\n[package]\nname = \"a\"\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let roots = workspace_roots(&dir).unwrap_or_else(|e| panic!("{e}"));
        assert!(roots.is_empty(), "a commented table was counted: {roots:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
