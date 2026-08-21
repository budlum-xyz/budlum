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

/// Collect `rev=<40hex>` from every Cargo.lock under `root`.
fn lockfile_revs(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.filter_map(Result::ok) {
            let Ok(path_kind) = e.file_type() else {
                continue;
            };
            let path = e.path();
            if path_kind.is_dir() {
                let s = path.to_string_lossy();
                if !s.contains("/target") {
                    stack.push(path);
                }
            } else if path.file_name().is_some_and(|n| n == "Cargo.lock") {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    for l in text.lines() {
                        let t = l.trim();
                        if let Some(rest) = t.strip_prefix("source = \"git+") {
                            if let Some(rev) = rest.find("rev=") {
                                let rev = &rest[rev + 4..];
                                let hex: String =
                                    rev.chars().take_while(char::is_ascii_hexdigit).collect();
                                if hex.len() == 40 {
                                    out.insert(hex);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    out
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
/// is unused, or both sets are empty.
pub fn run(root: &Path) -> Result<String, String> {
    let record_path = root.join(".github/git-dep-audit.toml");
    if !record_path.is_file() {
        return Err(String::from(
            "no git dependency audit record at .github/git-dep-audit.toml",
        ));
    }
    let record = std::fs::read_to_string(&record_path).map_err(|e| e.to_string())?;
    let used = lockfile_revs(root);
    let recorded = recorded_revs(&record);
    if used.is_empty() && recorded.is_empty() {
        return Err(String::from(
            "no git revisions in any lockfile and none recorded - gate would be vacuous",
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
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!("budlum-gates-gd-{}-{nanos}", std::process::id()));
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
        return Err(String::from("canary: dogru kayit reddedildi"));
    }
    // Record missing rev2.
    std::fs::write(
        dir.join("src/Cargo.lock"),
        format!("source = \"git+https://x/y?rev={rev2}\"\n"),
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: kayitsiz rev gecti"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "git-deps kanaryasi OK (kayitli PASS, kayitsiz FAIL).",
    ))
}
