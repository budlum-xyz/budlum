//! Loss past the threshold produces a repair task.
//!
//! Custody shares erode. When the live symbol count of a segment falls under
//! the loss threshold, the system must produce a repair task and new symbols
//! come from the fountain; a silent segment is a lost segment. The repair
//! module is filled by the rebuild package that owns repair; this gate arms
//! the contract and refuses a repair path with no threshold test.

use std::path::Path;

/// Roots scanned for repair task production.
const ROOTS: &[&str] = &["src", "crates"];

const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

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
}

/// # Errors
///
/// The repair producer that fires on no threshold.
pub fn run(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    for r in ROOTS {
        let p = root.join(r);
        if p.exists() {
            walk(&p, root, &mut files);
        }
    }
    let mut producers = 0usize;
    for (rel, path) in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let code = production_code(&text);
        // A repair task producer: a fn that builds a repair task or job.
        let names = ["fn repair_task", "fn schedule_repair", "fn repair_job", "fn produce_repair"];
        for n in names {
            if code.contains(n) {
                producers += 1;
                let window = &code;
                let has_threshold = window.contains("threshold")
                    || window.contains("loss")
                    || window.contains("below")
                    || window.contains("short");
                if !has_threshold {
                    return Err(format!(
                        "{rel}: `{n}` produces a repair task with no loss threshold in sight. \\\n  Repair fires when the live symbols fall past the threshold."
                    ));
                }
            }
        }
    }
    Ok(format!(
        "bud3 repair fires OK: {producers} repair producer(s) checked; the contract is armed for the repair module"
    ))
}

/// The canary: a producer without a threshold must fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-repair")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        put("src/storage/bud3/repair.rs", "pub fn other() {}\n")?;
        run(&dir).map_err(|e| format!("canary: a clean tree failed: {e}"))?;
        put(
            "src/storage/bud3/repair.rs",
            "pub fn repair_task(live: u32) -> u32 { live }\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a repair producer with no threshold passed"));
        }
        put(
            "src/storage/bud3/repair.rs",
            "pub fn repair_task(live: u32, threshold: u32) -> u32 {\n    assert!(live < threshold);\n    live\n}\n",
        )?;
        run(&dir).map_err(|e| format!("canary: a thresholded producer failed: {e}"))?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-repair-fires canary OK: a producer with no threshold failed, a thresholded producer passed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_repair_fires_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
