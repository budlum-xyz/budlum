//! B.U.D. 3.0 forbidden phrases gate (Directive Section 6.1.4).
//!
//! An object's commitment is 32 bytes; the object itself is coded into fountain
//! symbols and held by custody validators. Phrases claiming zero-storage magic
//! or single-QR canonical storage misdescribe the protocol and are refused
//! across code, tests, proto, and active documentation with no baseline file.

use std::path::Path;

const PHRASES: &[&str] = &[
    "zero storage",
    "storage-zero",
    "fixed-size recipe",
    "fixed-size object",
    "nothing is held",
    "holds nothing",
    "no notion of storage",
    "without holding the body",
    "stored inside a single qr",
    "fits in one qr",
    "qr is the canonical format",
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
const SELF: &[&str] = &[
    "xtask/gates/src/gates/bud3_forbidden_phrases.rs",
    "xtask/gates/src/gates/no_legacy_storage.rs",
];
const HISTORY_DIRS: &[&str] = &["docs/audit/", "docs/work/"];

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, std::path::PathBuf)>) {
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

/// # Errors
///
/// Returns every file, line, and forbidden phrase found in the tree.
pub fn run(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    for r in ROOTS {
        let p = root.join(r);
        if p.is_file() {
            files.push((String::from(*r), p));
        } else if p.is_dir() {
            walk(&p, root, &mut files);
        }
    }
    let mut hits = Vec::new();
    for (rel, path) in &files {
        if SELF.contains(&rel.as_str()) || HISTORY_DIRS.iter().any(|h| rel.starts_with(h)) {
            continue;
        }
        if std::fs::metadata(path).map_or(true, |m| m.len() > 4 * 1024 * 1024) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for (lineno, line) in text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            for phrase in PHRASES {
                if lower.contains(phrase) {
                    hits.push(format!("  {rel}:{}: {phrase:?}", lineno + 1));
                }
            }
        }
    }
    if !hits.is_empty() {
        return Err(format!(
            "B.U.D. 3.0 forbidden phrase(s) found:\n{}\n  \\\n  Section 6.1.4 retires these claims permanently.",
            hits.join("\n")
        ));
    }
    Ok(format!(
        "bud3-forbidden-phrases OK: {} phrases absent across {} files",
        PHRASES.len(),
        files.len()
    ))
}

/// Canary self-test: a clean tree passes, an injected forbidden phrase fails.
///
/// # Errors
///
/// Returns an error if the gate fails to reject an injected phrase or rejects a clean tree.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-phrases")?;
    let result = (|| {
        let src = dir.join("src");
        std::fs::create_dir_all(&src).map_err(|e| e.to_string())?;
        std::fs::write(src.join("ok.rs"), "// fountain symbols over GF(256)\n")
            .map_err(|e| e.to_string())?;
        run(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;

        std::fs::write(src.join("bad.rs"), "// Zero Storage magic\n")
            .map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: injected forbidden phrase passed"));
        }
        std::fs::remove_file(src.join("bad.rs")).map_err(|e| e.to_string())?;
        run(&dir).map_err(|e| format!("canary: restored tree failed: {e}"))?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-forbidden-phrases canary OK: injected phrase rejected and clean tree accepted.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_forbidden_phrases_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
