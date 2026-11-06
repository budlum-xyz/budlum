//! Required exact named tests: the B.U.D. 3.0 acceptance suite.
//!
//! The acceptance suite is the numbered test list of the B.U.D. 3.0 chapter.
//! Each test joins this required list in the package that writes it, and a
//! required test can never be renamed or quietly deleted: the gate reads the
//! tree and fails when a listed name stops being a test.
//!
//! The list so far: the fountain acceptance sweep, the genesis limits, the
//! object replacement round trip, the codec golden vectors and the fast
//! probe skip. The remaining acceptance names arrive with their packages.

use std::path::Path;

/// The required test names and where they live.
pub(crate) const TESTS: &[&str] = &[
    "storage::bud3::fountain::tests::bud3_fountain_acceptance_small_loss_sweep",
    "storage::bud3::limits::tests::bud3_limits_are_genesis_parameters",
    "storage::bud3::replace::tests::bud3_object_replacement",
    "bud_codec::bud3_codec_vectors",
    "bud_codec::bud3_fast_probe_skips_slow_candidates",
];

const ROOTS: &[&str] = &["src", "crates"];

const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
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
                walk(&p, out);
            }
        } else if name.ends_with(".rs") {
            out.push(p);
        }
    }
}

/// Whether a file defines `fn <short>()` behind a `#[test]` attribute.
fn defines_test(text: &str, short: &str) -> bool {
    let needle = format!("fn {short}(");
    for (i, line) in text.lines().enumerate() {
        if line.contains(&needle) {
            let head = text.lines().take(i).rev().take(4).collect::<Vec<_>>();
            if head.iter().any(|l| l.contains("#[test]")) {
                return true;
            }
        }
    }
    false
}

/// # Errors
///
/// The required test that is no longer a test.
pub fn run(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    for r in ROOTS {
        let p = root.join(r);
        if p.exists() {
            walk(&p, &mut files);
        }
    }
    let mut texts = Vec::new();
    for f in &files {
        if let Ok(t) = std::fs::read_to_string(f) {
            texts.push(t);
        }
    }
    let mut missing = Vec::new();
    for full in TESTS {
        let short = full.rsplit("::").next().unwrap_or(full);
        if !texts.iter().any(|t| defines_test(t, short)) {
            missing.push(*full);
        }
    }
    if !missing.is_empty() {
        let mut msg = String::from("a required acceptance test is gone:\n");
        for m in &missing {
            msg.push_str("  - ");
            msg.push_str(m);
            msg.push('\n');
        }
        msg.push_str("  A required test is renamed or deleted only by rewriting this list with the\n  package that owns it.");
        return Err(msg);
    }
    Ok(format!(
        "bud3 e2e OK: {} required acceptance tests are tests, name by name",
        TESTS.len()
    ))
}

/// The canary: a tree missing one required test must fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-e2e")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        let mut all = String::new();
        for full in TESTS {
            let short = full.rsplit("::").next().unwrap_or(full);
            all.push_str("#[test]\nfn ");
            all.push_str(short);
            all.push_str("() {}\n");
        }
        put("src/tests/all.rs", &all)?;
        run(&dir).map_err(|e| format!("canary: a full tree failed: {e}"))?;
        let short = TESTS[0].rsplit("::").next().unwrap_or(TESTS[0]);
        let cut = all.replace(&format!("fn {short}("), "fn renamed_x(");
        put("src/tests/all.rs", &cut)?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a renamed required test passed"));
        }
        put("src/tests/all.rs", &all)?;
        run(&dir).map_err(|e| format!("canary: the restored tree failed: {e}"))?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-e2e canary OK: a renamed required test failed and the restored tree passed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_e2e_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
