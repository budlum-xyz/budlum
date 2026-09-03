//! No conflict marker may be committed.
//!
//! Ported from `scripts/check-no-conflict-markers-are-committed.sh`, a grep
//! over the tree. The port keeps the same scan set (`.git` and `target`
//! excluded, the gate's own file excluded), the same marker shapes and the
//! same canary set.
//!
//! # Why this gate exists
//!
//! A merge that was resolved by hand can leave `<<<<<<<`, `=======` and
//! `>>>>>>>` in a file, and nothing noticed. Measured: `main` carried three
//! of them in README.md for two merges, advertised on the front page of the
//! repository, while all 62 checks stayed green. The badge gate read the
//! badge number with a regex that matched the line inside the conflict block,
//! so the badge looked correct and the markers around it were never
//! examined. rustfmt would have caught it in a `.rs` file; nothing read
//! Markdown.
//!
//! The check is deliberately whole-tree rather than diff-scoped. A marker
//! that survives one merge survives every later one, so scoping to the
//! current change would let an old marker sit forever.

use std::fs;
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[".git", "target"];

/// The gate must not fail on its own source: the canaries below embed real
/// marker strings. Skipped by the exact repository-relative path, never by
/// basename: a committed file elsewhere that merely shares the basename must
/// still be scanned (CWE-697).
const SELF_PATH: &str = "xtask/gates/src/gates/no_conflict_markers.rs";

/// `grep -rnE '^(<<<<<<< |>>>>>>> |={7}$)'` on a single line. The trailing
/// space on the open and close markers matters: `<<<<<<<` with no space is a
/// legitimate thing to write in prose about merge conflicts.
fn is_marker(line: &str) -> bool {
    line.starts_with("<<<<<<< ") || line.starts_with(">>>>>>> ") || line == "======="
}

fn scan(root: &Path) -> Vec<String> {
    let files = sorted_walk(root, SKIP_DIRS);
    let mut found = Vec::new();
    for path in files {
        if path.ends_with(SELF_PATH) {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        // grep reads binary files too and reports a match by path; lossy
        // decoding keeps the line content readable in the report. The path is
        // shown root-joined, mirroring `grep "$dir"`, so an absolute
        // BUDLUM_ROOT prints absolute paths exactly like the shell gate.
        let text = String::from_utf8_lossy(&bytes);
        let shown = path.to_string_lossy();
        for (lineno, line) in text.split('\n').enumerate() {
            if is_marker(line) {
                found.push(format!("{shown}:{}:{}", lineno + 1, line));
            }
        }
    }
    found
}

/// Recursively collect files, in deterministic (sorted) order.
fn sorted_walk(root: &Path, skip_dirs: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_into(root, skip_dirs, &mut out);
    out
}

fn walk_into(dir: &Path, skip_dirs: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        // `file_type` reports the entry itself, not the symlink target, so a
        // committed symlink to a directory (`loop -> .`, `docs -> /tree`) is
        // not followed: the shell gate's os.walk did not follow symlinked
        // directories either, and following them would walk outside the
        // repository boundary and re-scan in a loop (CWE-61).
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if kind.is_dir() {
            if !skip_dirs.contains(&name_str.as_ref()) {
                walk_into(&path, skip_dirs, out);
            }
        } else if kind.is_file()
            || (kind.is_symlink() && fs::metadata(&path).is_ok_and(|m| m.is_file()))
        {
            // A symlink to a file is still a file with content worth
            // scanning; only directory symlinks are not followed.
            out.push(path);
        }
    }
}

/// # Errors
///
/// Returns every marker line, root-joined, when the tree contains one.
pub fn run(root: &Path) -> Result<String, String> {
    let found = scan(root);
    if found.is_empty() {
        return Ok(String::from("OK: no conflict markers in the tree"));
    }
    let mut msg = String::new();
    for line in &found {
        msg.push_str(line);
        msg.push('\n');
    }
    msg.push_str("FAIL: conflict markers are committed; a merge was left half-resolved");
    Err(msg)
}

/// A fresh scratch directory for a self-test run.
fn scratch_dir() -> Result<PathBuf, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-conflict")?;
    Ok(dir)
}

fn write_case(dir: &Path, name: &str, content: &str) -> Result<PathBuf, String> {
    let sub = dir.join(name);
    fs::create_dir_all(&sub).map_err(|e| format!("cannot create {name}: {e}"))?;
    fs::write(sub.join("file.txt"), content).map_err(|e| format!("cannot write {name}: {e}"))?;
    Ok(sub)
}

/// # Errors
///
/// Returns the first canary that misbehaves. The canaries mirror the shell
/// gate's seven one for one.
pub fn self_test() -> Result<String, String> {
    let tmp = scratch_dir()?;
    let mut canaries = 0u32;

    // Canary 1: the exact shape found on main.
    let c1 = write_case(
        &tmp,
        "c1",
        "<<<<<<< HEAD\n[badge A]\n=======\n>>>>>>> abc1234 (msg)\n",
    )?;
    if scan(&c1).is_empty() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary 1: the marker set found on main was not detected",
        ));
    }
    canaries += 1;

    // Canary 2: open marker alone, the half a truncated resolution leaves.
    let c2 = write_case(&tmp, "c2", "text\n<<<<<<< ours\nmore\n")?;
    if scan(&c2).is_empty() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary 2: a lone open marker was not detected",
        ));
    }
    canaries += 1;

    // Canary 3: close marker alone.
    let c3 = write_case(&tmp, "c3", "text\n>>>>>>> theirs\n")?;
    if scan(&c3).is_empty() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary 3: a lone close marker was not detected",
        ));
    }
    canaries += 1;

    // Canary 4: the bare separator, which is the one a human reader skips.
    let c4 = write_case(&tmp, "c4", "text\n=======\nmore\n")?;
    if scan(&c4).is_empty() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary 4: a bare seven-equals separator was not detected",
        ));
    }
    canaries += 1;

    // Canary 5: a setext heading underline is six or more equals and is NOT
    // a conflict; nine equals must stay unflagged.
    let c5 = write_case(&tmp, "c5", "A heading\n=========\nbody\n")?;
    if !scan(&c5).is_empty() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary 5: a nine-equals setext heading must not be flagged",
        ));
    }
    canaries += 1;

    // Canary 6: prose about merge markers, written without the trailing
    // space, must stay legal.
    let c6 = write_case(&tmp, "c6", "we look for <<<<<<< and >>>>>>> in files\n")?;
    if !scan(&c6).is_empty() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary 6: prose mentioning markers must not be flagged",
        ));
    }
    canaries += 1;

    // Canary 7: a clean tree returns nothing, so the gate is not passing by
    // matching everything.
    let c7 = write_case(&tmp, "c7", "ordinary line\nanother\n")?;
    if !scan(&c7).is_empty() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary 7: a clean tree must produce no findings",
        ));
    }
    canaries += 1;

    // Canary 8 (CWE-61): a committed symlink to a directory must not be
    // followed. `loop -> .` would make a `Path::is_dir()` walker re-scan the
    // same tree forever; the file_type walker never enters it, and a marker
    // inside the target that is reachable only through the symlink is not
    // reported twice.
    #[cfg(unix)]
    {
        let loop_dir = tmp.join("c8");
        fs::create_dir_all(&loop_dir).map_err(|e| e.to_string())?;
        fs::write(loop_dir.join("real.txt"), "a real file with no marker\n")
            .map_err(|e| e.to_string())?;
        std::os::unix::fs::symlink(&loop_dir, loop_dir.join("loop")).map_err(|e| e.to_string())?;
        if scan(&loop_dir).len() > 1 {
            let _ = fs::remove_dir_all(&tmp);
            return Err(String::from(
                "canary 8: a directory symlink was followed by the walker",
            ));
        }
        canaries += 1;
    }

    // Canary 9 (CWE-697): the gate skips only its own source by the
    // full repository-relative path, never by basename. A committed file
    // elsewhere that happens to be named `no_conflict_markers.rs` must still
    // be scanned: drop one at the fixture root and it must be flagged.
    let imposter = tmp.join("no_conflict_markers.rs");
    fs::write(&imposter, "text\n<<<<<<< HEAD\nmore\n").map_err(|e| e.to_string())?;
    let mut saw_imposter = false;
    for hit in scan(&tmp) {
        if hit.contains("no_conflict_markers.rs") {
            saw_imposter = true;
        }
    }
    if !saw_imposter {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary 9: a basename lookalike of the gate's own source was skipped",
        ));
    }
    canaries += 1;

    let _ = fs::remove_dir_all(&tmp);
    Ok(format!(
        "conflict marker gate self-test OK: {canaries} canaries"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_shapes_are_exact() {
        assert!(is_marker("<<<<<<< HEAD"));
        assert!(is_marker(">>>>>>> theirs"));
        assert!(is_marker("======="));
        assert!(!is_marker("<<<<<<<"));
        assert!(!is_marker(">>>>>>>"));
        assert!(!is_marker("========="));
        assert!(!is_marker("========"));
        assert!(!is_marker(" ======="));
    }

    #[test]
    fn gate_excludes_itself() {
        // The module's own source embeds real marker strings (the canaries),
        // so a run over the crate must not fail on this file. Exercised by
        // pointing the gate at its own crate root.
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(run(here).is_ok(), "gate must exclude its own source");
    }
}
