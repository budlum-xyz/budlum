//! B.U.D. 3.0 forbidden phrases.
//!
//! The commitment of an object is fixed-size (32 bytes); the object is not.
//! The network holds the symbols of every object; it does not hold nothing.
//! Phrases that claim otherwise ("zero storage", "fixed-size object",
//! "holds nothing", ...) misdescribe the system, so they are refused in code,
//! tests and documents.
//!
//! The legacy storage tree still carries some of them. Those files are listed
//! in `.github/bud3-forbidden-phrases-baseline.txt`. The baseline is a
//! ratchet: a file outside it fails, and a listed file that no longer carries a
//! phrase also fails until its line is removed, so the list only shrinks.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// The phrases, lowercase. Matching is case-insensitive.
const PHRASES: &[&str] = &[
    "zero storage",
    "storage-zero",
    "fixed-size recipe",
    "fixed-size object",
    "nothing is held",
    "holds nothing",
    "no notion of storage",
    "without holding the body",
    "sıfır depolama",
    "sabit boyutlu tarif",
    "hiçbir şey tutulmaz",
    "depolama kavramı yok",
    "gövde tutmadan üretir",
];

const ROOTS: &[&str] = &[
    "src",
    "crates",
    "budzero",
    "xtask",
    "docs",
    "tests",
    "proto",
    "README.md",
    "README.tr.md",
];

const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// Files that name the phrases to forbid them.
const SELF: &[&str] = &[
    "xtask/gates/src/gates/bud3_forbidden_phrases.rs",
    ".github/bud3-forbidden-phrases-baseline.txt",
    "xtask/gates/src/gates/no_legacy_storage.rs",
];

/// Historical audit records quote old claims on purpose.
const HISTORY_DIRS: &[&str] = &["docs/audit/", "docs/work/"];

const BASELINE: &str = ".github/bud3-forbidden-phrases-baseline.txt";
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

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

/// Files that carry a phrase, with the first phrase found.
fn offenders(root: &Path) -> Vec<(String, &'static str)> {
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
        if std::fs::metadata(&path).map_or(true, |m| m.len() > MAX_FILE_BYTES) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let lower = text.to_lowercase();
        if let Some(p) = PHRASES.iter().find(|p| lower.contains(*p)) {
            out.push((rel, *p));
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
/// A finding, as a sentence.
pub fn run(root: &Path) -> Result<String, String> {
    let found = offenders(root);
    let allowed = baseline(root);
    let mut new = String::new();
    let found_set: BTreeSet<&str> = found.iter().map(|(f, _)| f.as_str()).collect();
    for (file, phrase) in &found {
        if !allowed.contains(file) {
            let _ = writeln!(new, "  {file}: \"{phrase}\"");
        }
    }
    let mut stale = String::new();
    for file in &allowed {
        if !found_set.contains(file.as_str()) {
            let _ = writeln!(stale, "  {file}");
        }
    }
    if !new.is_empty() {
        return Err(format!(
            "FAIL: B.U.D. 3.0 forbidden phrases in files outside the legacy baseline:\n{new}\n  \
             The commitment is fixed-size; the object is not, and the network holds its symbols. \
             Say what the system does."
        ));
    }
    if !stale.is_empty() {
        return Err(format!(
            "FAIL: these baseline files no longer carry a forbidden phrase; remove their lines from {BASELINE}:\n{stale}"
        ));
    }
    Ok(format!(
        "bud3 forbidden phrases OK: {} legacy file(s) on the shrinking baseline, none elsewhere",
        found.len()
    ))
}

/// The canary: an injected phrase must fail, and a stale baseline must fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-phrases")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        put("src/clean.rs", "// The object is header plus payload.\n")?;
        put(BASELINE, "# legacy\n")?;
        run(&dir).map_err(|e| format!("canary: a clean tree failed: {e}"))?;
        put("src/bad.rs", "// The network Holds Nothing.\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an injected phrase passed"));
        }
        put(BASELINE, "src/bad.rs\n")?;
        run(&dir).map_err(|e| format!("canary: a baselined file failed: {e}"))?;
        put("src/bad.rs", "// fixed.\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a stale baseline line passed"));
        }
        put("docs/audit/old.md", "zero storage was claimed here\n")?;
        put(BASELINE, "")?;
        run(&dir).map_err(|e| format!("canary: the history dir was scanned: {e}"))?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-forbidden-phrases canary OK: an injected phrase failed, a stale baseline failed, history is exempt.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_forbidden_phrases_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
