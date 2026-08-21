//! No typographic dash may enter the tree.
//!
//! Ported from `scripts/check-no-unicode-dashes.sh`, which scanned the tree
//! with an inline Python here-doc. The port replaces two languages with one
//! and keeps the shell gate's skip sets, vacuity floor, report format and
//! canary set, so the two gates agree on every fixture.
//!
//! # Why this gate exists
//!
//! A previous pass removed 1299 em dashes by hand and reported the tree
//! clean. It was not. Nineteen survived, and three of them sat in the
//! `name:` field of workflow jobs that branch protection lists as required
//! checks. Renaming a required check silently unlists it: the job still
//! runs, still passes, and stops counting toward the merge requirement. So a
//! cosmetic character in a job name is a branch-protection hazard, and the
//! only way to retire it safely is to rename the job and update protection
//! in the same change. A hand count cannot be trusted with that; a gate can.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// The eight rejected characters, in the shell gate's report order.
const DASHES: [(char, &str); 8] = [
    ('\u{2010}', "U+2010 hyphen"),
    ('\u{2011}', "U+2011 non-breaking hyphen"),
    ('\u{2012}', "U+2012 figure dash"),
    ('\u{2013}', "U+2013 en dash"),
    ('\u{2014}', "U+2014 em dash"),
    ('\u{2015}', "U+2015 horizontal bar"),
    ('\u{2212}', "U+2212 minus sign"),
    ('\u{00ad}', "U+00AD soft hyphen"),
];

/// Directories that carry no prose worth scanning.
const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".cargo"];

/// Machine-written files that carry no prose.
const SKIP_FILES: &[&str] = &["Cargo.lock", "flake.lock", "imports.lock", "LICENSE.md"];

/// A scan that walked fewer than this many text files is vacuous and must
/// fail rather than pass by looking at nothing.
const VACUITY_FLOOR: usize = 50;

/// Recursively collect files, in deterministic (sorted) order.
fn sorted_walk(root: &Path, skip_dirs: &[&str], skip_files: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_into(root, skip_dirs, skip_files, &mut out);
    out
}

fn walk_into(dir: &Path, skip_dirs: &[&str], skip_files: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        // `file_type` reports the entry itself, not the symlink target, so a
        // committed symlink to a directory is not followed (the python gate's
        // os.walk did not follow them either); a symlink to a file is still
        // scanned. Following directory symlinks would walk outside the
        // repository boundary and re-scan in a loop (Strix CWE-61).
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if kind.is_dir() {
            if !skip_dirs.contains(&name_str.as_ref()) {
                walk_into(&path, skip_dirs, skip_files, out);
            }
        } else if !skip_files.contains(&name_str.as_ref())
            && (kind.is_file()
                || (kind.is_symlink() && fs::metadata(&path).is_ok_and(|m| m.is_file())))
        {
            out.push(path);
        }
    }
}

/// The shell gate's `line.strip()[:100]`: trim, keep the first 100
/// characters (not bytes).
fn truncate100(s: &str) -> String {
    s.trim().chars().take(100).collect()
}

/// # Errors
///
/// Returns a finding when a dash is present anywhere, or when the scan
/// walked fewer than [`VACUITY_FLOOR`] text files and would be vacuous.
pub fn run(root: &Path) -> Result<String, String> {
    let files = sorted_walk(root, SKIP_DIRS, SKIP_FILES);
    let mut scanned = 0usize;
    let mut hits: Vec<String> = Vec::new();

    for path in files {
        let Ok(text) = fs::read_to_string(&path) else {
            // Unreadable or non-UTF-8 files carry no prose; skip, matching
            // the python gate's (UnicodeDecodeError, OSError) handler.
            continue;
        };
        scanned += 1;
        let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
        for (lineno, line) in text.lines().enumerate() {
            for (ch, label) in DASHES {
                if line.contains(ch) {
                    hits.push(format!(
                        "  {rel}:{}: {label}\n      {}",
                        lineno + 1,
                        truncate100(line)
                    ));
                }
            }
        }
    }

    if scanned < VACUITY_FLOOR {
        return Err(format!(
            "only {scanned} text files scanned under {}; the gate would be vacuous",
            root.display()
        ));
    }

    if !hits.is_empty() {
        let n = hits.len();
        let mut msg = format!("{n} typographic dash(es) in the tree:\n");
        for h in hits.iter().take(40) {
            msg.push_str(h);
            msg.push('\n');
        }
        if n > 40 {
            writeln!(msg, "  ... and {} more", n - 40).expect("writing to a String cannot fail");
        }
        msg.push_str(
            "\n  Replace with ASCII: a comma or colon in prose, a plain hyphen in ranges.\n  \
             If the hit is a workflow `name:` that branch protection requires,\n  \
             update the protection contexts in the same change or the check stops counting.",
        );
        return Err(msg);
    }

    Ok(format!(
        "No typographic dashes: {scanned} text files scanned."
    ))
}

/// A fresh scratch directory for a self-test run.
fn scratch_dir() -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-unicode-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create scratch dir: {e}"))?;
    Ok(dir)
}

/// Build the clean fixture tree used by the shell gate's self-test: 60 .rs
/// files plus one README.md, enough to clear the vacuity floor.
fn build_clean_tree(root: &Path) -> std::io::Result<()> {
    let src = root.join("src");
    fs::create_dir_all(&src)?;
    for i in 1..=60 {
        fs::write(
            src.join(format!("f{i}.rs")),
            format!("fn f{i}() {{ let a = 1 - 1; }}\n"),
        )?;
    }
    fs::write(
        root.join("README.md"),
        "# Title\n\nPlain ASCII prose, nothing typographic here.\n",
    )?;
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    for f in sorted_walk(src, &[], &[]) {
        let rel = f.strip_prefix(src).expect("walked file is under src");
        let target = dst.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&f, &target)?;
    }
    Ok(())
}

/// # Errors
///
/// Returns the first canary that misbehaves. The canaries mirror the shell
/// gate's one for one: a clean tree passes, each of the eight characters is
/// caught on its own, a workflow job name is caught, and the vacuity floor
/// fires on a near-empty tree.
pub fn self_test() -> Result<String, String> {
    let tmp = scratch_dir()?;

    // Clean tree must pass with the exact expected message.
    let clean = tmp.join("clean");
    build_clean_tree(&clean).map_err(|e| format!("cannot build clean tree: {e}"))?;
    if let Err(msg) = run(&clean) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("canary: a clean tree was rejected: {msg}"));
    }

    // Each character has to be caught on its own; catching only the em dash
    // is how the previous pass missed the en dashes and the minus signs.
    for (idx, (ch, _)) in DASHES.iter().enumerate() {
        let dirty = tmp.join(format!("dirty{idx}"));
        copy_tree(&clean, &dirty).map_err(|e| format!("cannot stage dirty tree: {e}"))?;
        let fixture = format!("# A heading {ch} with a typographic dash\n");
        fs::write(dirty.join("DIRTY.md"), fixture)
            .map_err(|e| format!("cannot write fixture for U+{:04x}: {e}", *ch as u32))?;
        if run(&dirty).is_ok() {
            let _ = fs::remove_dir_all(&tmp);
            return Err(format!("canary: U+{:04x} was not detected", *ch as u32));
        }
    }

    // A job name is the case that motivated the gate, so it is exercised by
    // name.
    let wf = tmp.join("wf");
    copy_tree(&clean, &wf).map_err(|e| format!("cannot stage workflow tree: {e}"))?;
    let wf_dir = wf.join(".github/workflows");
    fs::create_dir_all(&wf_dir).map_err(|e| format!("cannot create workflow dir: {e}"))?;
    let semver =
        "jobs:\n  x:\n    name: Semver Check (Madde 5 \u{2014} public API breakage gate)\n";
    fs::write(wf_dir.join("semver.yml"), semver)
        .map_err(|e| format!("cannot write semver.yml: {e}"))?;
    if run(&wf).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: an em dash inside a workflow job name was not detected",
        ));
    }

    // The vacuity floor itself has to fire, or an empty checkout would pass.
    let empty = tmp.join("empty");
    fs::create_dir_all(&empty).map_err(|e| format!("cannot create empty tree: {e}"))?;
    fs::write(empty.join("only.txt"), "nothing\n")
        .map_err(|e| format!("cannot write vacuity fixture: {e}"))?;
    if run(&empty).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a near-empty tree passed; the vacuity floor is not working",
        ));
    }

    // A committed symlink to a directory must not be followed (Strix CWE-61):
    // a `loop -> .` would re-scan the same files forever, and a file reachable
    // only through the symlink is reported once, not twice.
    #[cfg(unix)]
    {
        let sym = tmp.join("symlink-canary");
        build_clean_tree(&sym).map_err(|e| format!("cannot build symlink tree: {e}"))?;
        std::os::unix::fs::symlink(&sym, sym.join("loop")).map_err(|e| e.to_string())?;
        if run(&sym).is_err() {
            let _ = fs::remove_dir_all(&tmp);
            return Err(String::from("canary: a directory symlink broke the walker"));
        }
    }

    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "Self-test OK: clean tree passes, 8 dash characters detected, workflow name detected, vacuity floor fires.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        scratch_dir().expect("scratch dir")
    }

    #[test]
    fn clean_tree_passes() {
        let d = scratch();
        build_clean_tree(&d).expect("clean tree");
        assert_eq!(
            run(&d).expect("clean tree must pass"),
            "No typographic dashes: 61 text files scanned."
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn each_dash_is_caught() {
        let d = scratch();
        build_clean_tree(&d).expect("clean tree");
        for (ch, _) in DASHES {
            let f = d.join("DIRTY.md");
            fs::write(&f, format!("# A heading {ch} with a typographic dash\n")).expect("fixture");
            assert!(run(&d).is_err(), "U+{:04x} not detected", ch as u32);
            fs::remove_file(&f).expect("remove fixture");
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn vacuity_floor_fires() {
        let d = scratch();
        fs::write(d.join("only.txt"), "nothing\n").expect("fixture");
        assert!(run(&d).is_err());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn truncate_keeps_100_chars() {
        assert_eq!(truncate100(&"x".repeat(120)).chars().count(), 100);
        assert_eq!(truncate100("  hello  "), "hello");
    }
}
