//! A `.lock()` failure must not default a bound open.
//!
//! Ported from `scripts/check-lock-failures-do-not-open-a-bound.sh`. A lock
//! failure defaulting to `true` (`unwrap_or(true)`) is the permissive answer:
//! the bound stops rejecting the moment the mutex is poisoned. Functions
//! marked `FAILOPEN: allowed - <reason>` are exempt.

use std::fmt::Write as _;
use std::path::Path;

const SCAN_ROOTS: &[&str] = &[
    "src",
    "budzero",
    "bud",
    "crates/ai-inference",
    "crates/bpqs",
    "crates/budscan",
    "crates/note-packing",
    "crates/wallet-core",
];

/// Remove every `#[cfg(test)]` item. The shared stripper ends a body-less item
/// at its own `;`, so code after `#[cfg(test)] mod tests;` is still scanned and
/// a name containing "mod" cannot start a cut.
fn strip_test_mods(text: &str) -> String {
    super::capability_modules_are_wired::strip_test_mods(text)
}

fn is_test_path(rel: &str) -> bool {
    rel.contains("/tests/") || rel.ends_with("_tests.rs") || rel.ends_with("/tests.rs")
}

fn is_open_default(line: &str) -> bool {
    // Spaces are dropped so `|_|true` and `|_| true` are one spelling.
    let t: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    [
        "unwrap_or(true)",
        "unwrap_or_else(|_|true)",
        "unwrap_or_else(|e|true)",
        "map_or(true,",
        "Err(_)=>true",
    ]
    .iter()
    .any(|p| t.contains(p))
}

fn collect_files(root: &Path) -> Vec<(std::path::PathBuf, String)> {
    let mut files = Vec::new();
    for scan_root in SCAN_ROOTS {
        let base = root.join(scan_root);
        if !base.is_dir() {
            continue;
        }
        let mut stack = vec![base];
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
                    let n = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if !matches!(n.as_str(), ".git" | "target" | "node_modules") {
                        stack.push(path);
                    }
                } else if path.extension().is_some_and(|x| x == "rs") {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    if !is_test_path(&rel) {
                        files.push((path, rel));
                    }
                }
            }
        }
    }
    files
}

/// # Errors
///
/// Returns a finding per offending lock site.
pub fn run(root: &Path) -> Result<String, String> {
    let files = collect_files(root);
    if files.is_empty() {
        return Err(format!(
            "no production .rs files found under {}",
            root.display()
        ));
    }

    let mut problems: Vec<String> = Vec::new();
    let mut checked_locks = 0usize;

    for (path, rel) in &files {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {rel}: {e}"))?;
        let src = strip_test_mods(&raw);
        if !src.contains(".lock()") {
            continue;
        }
        let lines: Vec<&str> = src.lines().collect();
        let exempt_from: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains("FAILOPEN: allowed"))
            .map(|(i, _)| i)
            .collect();

        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("//") || !line.contains(".lock()") {
                continue;
            }
            checked_locks += 1;
            let window_end = (i + 6).min(lines.len());
            for (offset, w) in lines[i..window_end].iter().enumerate() {
                if w.trim_start().starts_with("//") {
                    continue;
                }
                if !is_open_default(w) {
                    continue;
                }
                let declared = exempt_from.iter().any(|e| *e <= i && i - *e <= 30);
                if declared {
                    break;
                }
                problems.push(format!(
                    "{rel}:{}: a `.lock()` failure defaults to `true`. \
                     `true` is the permissive answer, so the bound this feeds stops \
                     rejecting the moment the mutex is poisoned, which is exactly \
                     when something has already gone wrong. Recover the guard \
                     instead (see `peer_manager_lock`), or write \
                     `FAILOPEN: allowed - <reason>` on the function.",
                    i + offset + 1
                ));
                break;
            }
        }
    }

    if checked_locks == 0 {
        return Err(String::from(
            "gate found no `.lock()` call to measure - wrong root, or the \
             locking pattern changed shape.",
        ));
    }
    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "lock-failure gate OK: {checked_locks} `.lock()` sites, none of them \
         defaulting a bound open on failure"
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-lf")?;
    let _ = std::fs::create_dir_all(dir.join("src"));
    let _ = std::fs::create_dir_all(dir.join("budzero"));
    let _ = std::fs::create_dir_all(dir.join("wallet-core"));

    let good = "impl Node {\n    fn admit(&self) -> bool {\n        self.peer_manager_lock().can_admit()\n    }\n    fn peer_manager_lock(&self) -> MutexGuard<'_, PeerManager> {\n        self.peer_manager.lock().unwrap_or_else(|p| p.into_inner())\n    }\n}\n";
    std::fs::write(dir.join("src/lib.rs"), good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a recovered guard was rejected"));
    }
    let bad = "impl Node {\n    fn admit(&self) -> bool {\n        self.peer_manager\n            .lock()\n            .map(|pm| pm.can_admit())\n            .unwrap_or(true)\n    }\n}\n";
    std::fs::write(dir.join("src/lib.rs"), bad).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a fail-open passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "lock-failures canary OK: a guard PASSes and a fail-open FAILs.",
    ))
}

#[cfg(test)]
mod scan_root_tests {
    use super::SCAN_ROOTS;

    /// A scan root that is not a directory is skipped without a word, so a
    /// wrong path turns the gate off for that tree.
    #[test]
    fn every_scan_root_is_a_directory_of_the_repository() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for root in SCAN_ROOTS {
            assert!(
                repo.join(root).is_dir(),
                "scan root `{root}` is not a directory of the repository"
            );
        }
    }

    /// Every crate directory under `crates/` and the `bud` tree must be
    /// scanned, so a new crate cannot sit outside the gate unnoticed.
    #[test]
    fn every_crate_directory_is_a_scan_root() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert!(SCAN_ROOTS.contains(&"bud"), "bud/ is not scanned");
        let entries = std::fs::read_dir(repo.join("crates")).expect("crates/ is readable");
        for e in entries.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                let rel = format!("crates/{}", e.file_name().to_string_lossy());
                assert!(
                    SCAN_ROOTS.contains(&rel.as_str()),
                    "`{rel}` is not a scan root of the lock-failure gate"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn more_fail_open_spellings_are_seen() {
        for l in [
            "x.lock().map_or(true, |g| g.ok())",
            "x.lock().unwrap_or_else(|e| true)",
            "x.lock().unwrap_or_else(|_|true)",
            "Err(_) => true,",
            "x.lock().unwrap_or(true)",
        ] {
            assert!(is_open_default(l), "{l}");
        }
        assert!(!is_open_default("x.lock().unwrap_or(false)"));
    }

    #[test]
    fn bodyless_test_mod_at_the_end_keeps_the_code_before_it() {
        let src = "fn a() { m.lock().unwrap_or(true); }\n#[cfg(test)]\nmod tests;\n";
        assert!(strip_test_mods(src).contains("unwrap_or(true)"));
        let model = "#[cfg(test)]\nconst X: u8 = 1;\nfn model() { m.lock().unwrap_or(true); }\n";
        assert!(strip_test_mods(model).contains("unwrap_or(true)"));
    }
}
