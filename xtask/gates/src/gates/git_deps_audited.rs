//! Every git dependency revision built must be recorded in the audit file.
//!
//! Ported from `scripts/check-git-deps-are-audited-by-commit.sh`. A git
//! dependency's version field is set by the manifest at that commit and does
//! not change when the code does, so no scanner can tell a patched revision
//! from an unpatched one. Each `rev=<40hex>` in a lockfile must appear in
//! `.github/git-dep-audit.toml`, and nothing recorded may be unused.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// The 40-hex commit a lock `source = "git+..."` line builds.
///
/// A `?rev=` source names it twice; a `?branch=` or `?tag=` source names it
/// only after the `#`. Both are read, so a branch or tag pin needs an audit
/// record too.
fn commit_of_source(line: &str) -> Option<String> {
    let rest = line.trim().strip_prefix("source = \"git+")?;
    let take40 = |text: &str| -> Option<String> {
        let hex: String = text.chars().take_while(char::is_ascii_hexdigit).collect();
        (hex.len() == 40).then_some(hex)
    };
    if let Some((_, frag)) = rest.rsplit_once('#') {
        if let Some(hex) = take40(frag) {
            return Some(hex);
        }
    }
    rest.find("rev=").and_then(|i| take40(&rest[i + 4..]))
}

/// Collect the built git commits from every Cargo.lock under `root`.
///
/// # Errors
///
/// An unreadable directory or lock file: a gate that cannot look is not clean.
fn lockfile_revs(root: &Path) -> Result<BTreeSet<String>, String> {
    let mut out = BTreeSet::new();
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd =
            std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for e in rd.filter_map(Result::ok) {
            let Ok(path_kind) = e.file_type() else {
                continue;
            };
            let path = e.path();
            if path_kind.is_dir() {
                // The directory's own name, not a substring of the whole path.
                if e.file_name() != "target" {
                    stack.push(path);
                }
            } else if path.file_name().is_some_and(|n| n == "Cargo.lock") {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                out.extend(text.lines().filter_map(commit_of_source));
            }
        }
    }
    Ok(out)
}

/// How many lock files stand under `root`, and how many packages in them
/// name where they come from.
///
/// "No git revision is built" is a statement about lock files that were
/// read. Without one, or with lock files that name no source at all, the
/// same empty set comes out of a tree the gate never looked at.
///
/// # Errors
///
/// An unreadable directory or lock file: a gate that cannot look is not clean.
fn lockfile_evidence(root: &Path) -> Result<(usize, usize), String> {
    let (mut files, mut sources) = (0usize, 0usize);
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd =
            std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for e in rd.filter_map(Result::ok) {
            let Ok(path_kind) = e.file_type() else {
                continue;
            };
            let path = e.path();
            if path_kind.is_dir() {
                if e.file_name() != "target" {
                    stack.push(path);
                }
            } else if path.file_name().is_some_and(|n| n == "Cargo.lock") {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                files += 1;
                sources += text
                    .lines()
                    .filter(|l| l.trim_start().starts_with("source = \""))
                    .count();
            }
        }
    }
    Ok((files, sources))
}

/// Collect `rev = "<40hex>"` from the audit record.
fn recorded_revs(record: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for l in record.lines() {
        let t = l.trim_start();
        let Some(rest) = t.strip_prefix("rev") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let v = rest.trim().trim_matches('"');
        if v.len() == 40 && v.chars().all(|c| c.is_ascii_hexdigit()) {
            out.insert(v.to_string());
        }
    }
    out
}

/// # Errors
///
/// Returns a finding when a built revision is unrecorded, a recorded revision
/// is unused, or no lock file with a package source was found to read.
pub fn run(root: &Path) -> Result<String, String> {
    let record_path = root.join(".github/git-dep-audit.toml");
    if !record_path.is_file() {
        return Err(String::from(
            "no git dependency audit record at .github/git-dep-audit.toml",
        ));
    }
    let record = std::fs::read_to_string(&record_path).map_err(|e| e.to_string())?;
    let used = lockfile_revs(root)?;
    let recorded = recorded_revs(&record);
    // An empty answer is only an answer when something was read. This gate
    // used to refuse the empty case outright, as vacuous; now that no git
    // dependency is built, "none" is the expected finding, and what keeps it
    // from being vacuous is the count of what was looked at.
    let (files, sources) = lockfile_evidence(root)?;
    if files == 0 || sources == 0 {
        return Err(format!(
            "FAIL: {files} Cargo.lock file(s) naming {sources} package source(s) were found \
             under {}; the gate looked at nothing and would be vacuous",
            root.display()
        ));
    }
    if used.is_empty() && recorded.is_empty() {
        return Ok(format!(
            "Git-dep audit OK: 0 git revisions built; {sources} package source(s) in \
             {files} lock file(s) all come from a registry."
        ));
    }
    let missing: Vec<&String> = used.difference(&recorded).collect();
    if !missing.is_empty() {
        let mut msg = String::from(
            "FAIL: these git revisions are built but not recorded in .github/git-dep-audit.toml:\n",
        );
        for m in &missing {
            writeln!(msg, "  - {m}").expect("writing to a String cannot fail");
        }
        msg.push_str(
            "\nA git dependency's version field is set by the manifest at that commit and does\n\
             not change when the code does, so no scanner can tell a patched revision from an\n\
             unpatched one. Record what was checked at this revision: the advisories, and the\n\
             file and symbol carrying each fix.",
        );
        return Err(msg);
    }
    let extra: Vec<&String> = recorded.difference(&used).collect();
    if !extra.is_empty() {
        let mut msg =
            String::from("FAIL: these revisions are recorded but no lockfile uses them:\n");
        for e in &extra {
            writeln!(msg, "  - {e}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "Git-dep audit OK: {} revision(s) built and recorded.",
        used.len()
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-gd")?;
    let _ = std::fs::create_dir_all(dir.join(".github"));
    let _ = std::fs::create_dir_all(dir.join("src"));

    let rev = "a".repeat(40);
    let rev2 = "b".repeat(40);
    std::fs::write(
        dir.join("src/Cargo.lock"),
        format!("source = \"git+https://x/y?rev={rev}\"\n"),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join(".github/git-dep-audit.toml"),
        format!("rev = \"{rev}\"\n"),
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a correct record was refused"));
    }
    // Record missing rev2.
    std::fs::write(
        dir.join("src/Cargo.lock"),
        format!("source = \"git+https://x/y?rev={rev2}\"\n"),
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: an unrecorded rev passed"));
    }
    // No git dependency at all, which is what the repository builds today:
    // registry sources and an empty record pass, and say what was read.
    let registry = "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
    std::fs::write(dir.join("src/Cargo.lock"), registry).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(".github/git-dep-audit.toml"), "# none\n")
        .map_err(|e| e.to_string())?;
    match run(&dir) {
        Ok(found) if found.contains("1 package source(s) in 1 lock file(s)") => {}
        other => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!(
                "canary: a tree without git dependencies was not reported as read: {other:?}"
            ));
        }
    }
    // A branch pin is a git revision too, and the empty record does not cover it.
    std::fs::write(
        dir.join("src/Cargo.lock"),
        format!("{registry}source = \"git+https://x/y?branch=main#{rev2}\"\n"),
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a branch-pinned git source passed an empty record",
        ));
    }
    // A lock file that names no source, and no lock file at all: nothing was
    // looked at, so "no git revision" is not a finding.
    std::fs::write(dir.join("src/Cargo.lock"), "version = 4\n").map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a lock file without package sources passed",
        ));
    }
    std::fs::remove_file(dir.join("src/Cargo.lock")).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a tree without a lock file passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "git-deps canary OK: a recorded rev PASSes, an unrecorded or branch-pinned one \
         FAILs, an all-registry tree PASSes with its counts, and a tree with nothing to \
         read FAILs.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_and_tag_sources_name_a_commit() {
        let h = "c".repeat(40);
        assert_eq!(
            commit_of_source(&format!("source = \"git+https://x/y?branch=main#{h}\"")),
            Some(h.clone())
        );
        assert_eq!(
            commit_of_source(&format!("source = \"git+https://x/y?tag=v1#{h}\"")),
            Some(h.clone())
        );
        assert_eq!(
            commit_of_source(&format!("source = \"git+https://x/y?rev={h}#{h}\"")),
            Some(h)
        );
        assert_eq!(commit_of_source("source = \"registry+https://x\""), None);
    }
}
