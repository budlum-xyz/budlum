//! A missed audit costs rewards and time, never stake.
//!
//! The validator's stake is the consensus bond. A missed custody audit is an
//! availability failure: it drops the storage reward and suspends the share;
//! it does not cut stake. A repair that submits a wrong symbol is slashed
//! one percent by its own rule; that cut is not this door.
//!
//! This gate refuses a stake cut on the missed-audit path. The reward module
//! is filled by the rebuild package that owns rewards; the refusal is armed
//! now.

use std::path::Path;

/// Roots scanned for the missed-audit path.
const ROOTS: &[&str] = &["src"];

const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// Words that mean a stake cut.
const SLASH_WORDS: &[&str] = &["slash", "slashed", "slash_stake", "cut_stake", "burn_stake"];

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
        } else if name.ends_with(".rs") {
            if let Ok(rel) = p.strip_prefix(root) {
                out.push((rel.to_string_lossy().replace('\\', "/"), p.clone()));
            }
        }
    }
}

fn production_code(text: &str) -> String {
    let no_tests = super::capability_modules_are_wired::strip_test_mods(text);
    no_tests
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase()
}

/// The body of every fn whose name concerns a missed audit.
fn missed_audit_bodies(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(at) = code[from..].find("fn ") {
        let start = from + at;
        let after = start + 3;
        let mut j = after;
        while j < code.len() && (code.as_bytes()[j].is_ascii_alphanumeric() || code.as_bytes()[j] == b'_') {
            j += 1;
        }
        let name = &code[after..j];
        let is_miss = (name.contains("miss") || name.contains("expired_audit") || name.contains("audit_expired"))
            && (name.contains("audit") || name.contains("custody"));
        if is_miss {
            if let Some(brace) = code[j..].find('{') {
                let o = j + brace;
                let mut d = 0usize;
                let mut k = o;
                while k < code.len() {
                    if code.as_bytes()[k] == b'{' {
                        d += 1;
                    } else if code.as_bytes()[k] == b'}' {
                        d -= 1;
                        if d == 0 {
                            out.push(code[start..=k].to_string());
                            break;
                        }
                    }
                    k += 1;
                }
            }
        }
        from = j.max(start + 3);
    }
    out
}

/// # Errors
///
/// The missed-audit path that cuts stake.
pub fn run(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    for r in ROOTS {
        let p = root.join(r);
        if p.exists() {
            walk(&p, root, &mut files);
        }
    }
    let mut checked = 0usize;
    for (rel, path) in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let code = production_code(&text);
        for body in missed_audit_bodies(&code) {
            checked += 1;
            for word in SLASH_WORDS {
                if body.contains(word) {
                    return Err(format!(
                        "{rel}: the missed-audit path calls `{word}`. A missed audit costs rewards \\\n  and time, never stake: the stake cut is reserved for equivocation and a bad repair."
                    ));
                }
            }
        }
    }
    Ok(format!(
        "bud3 custody rewards OK: {checked} missed-audit handler(s) checked; none cuts stake"
    ))
}

/// The canary: a missed-audit handler that slashes must fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-reward")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        put(
            "src/storage/bud3/registry.rs",
            "pub fn on_missed_audit(who: u64) {\n    suspend(who);\n}\n",
        )?;
        run(&dir).map_err(|e| format!("canary: a clean handler failed: {e}"))?;
        put(
            "src/storage/bud3/registry.rs",
            "pub fn on_missed_audit(who: u64) {\n    slash_stake(who);\n}\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a stake cut on a missed audit passed"));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-custody-rewards canary OK: a stake cut on a missed audit failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_custody_rewards_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
