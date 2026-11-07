//! Gate `ee-workers-build-with-unwind`: node binary builds with `panic = "abort"`,
//! while every execution-environment worker (`execution/*/Cargo.toml`) builds with
//! `panic = "unwind"` so engine panics are caught at `catch_unwind` (`BLG-250`).

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// Check `[profile.release]` `panic` settings on the root manifest and every
/// `execution/*/Cargo.toml` worker manifest under `root`.
///
/// # Errors
///
/// Returns an `Err(String)` when a manifest cannot be read.
pub fn check_root(root: &Path) -> Result<Vec<String>, String> {
    let mut problems = Vec::new();

    let root_manifest = root.join("Cargo.toml");
    let root_text = fs::read_to_string(&root_manifest)
        .map_err(|e| format!("cannot read {}: {e}", root_manifest.display()))?;
    match release_panic_mode(&root_text) {
        Some("abort") => {}
        other => problems.push(format!(
            "Cargo.toml: `[profile.release]` must set `panic = \"abort\"` on the node binary \
             (found `{}`)",
            other.unwrap_or("unset")
        )),
    }

    let exec_dir = root.join("execution");
    if exec_dir.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(&exec_dir)
            .map_err(|e| format!("cannot read {}: {e}", exec_dir.display()))?
            .filter_map(Result::ok)
            .collect();
        entries.sort_by_key(fs::DirEntry::file_name);

        for entry in entries {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let manifest = path.join("Cargo.toml");
            if !manifest.is_file() {
                continue;
            }
            let rel = manifest
                .strip_prefix(root)
                .unwrap_or(&manifest)
                .display()
                .to_string();
            let text = fs::read_to_string(&manifest)
                .map_err(|e| format!("cannot read {rel}: {e}"))?;
            // Pure conformance test-runner crates are not out-of-process worker binaries.
            if rel == "execution/conformance/Cargo.toml" {
                continue;
            }
            match release_panic_mode(&text) {
                Some("unwind") => {}
                other => problems.push(format!(
                    "{rel}: EE worker `[profile.release]` must set `panic = \"unwind\"` so \
                     `catch_unwind` isolates deterministic engine panics (`BLG-250`); found `{}`",
                    other.unwrap_or("unset")
                )),
            }
        }
    }

    Ok(problems)
}

fn release_panic_mode(cargo_toml: &str) -> Option<&str> {
    let mut in_release = false;
    for raw_line in cargo_toml.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_release = line == "[profile.release]";
            continue;
        }
        if in_release {
            if let Some((key, val)) = line.split_once('=') {
                if key.trim() == "panic" {
                    let unquoted = val.trim().trim_matches('"').trim_matches('\'');
                    return match unquoted {
                        "abort" => Some("abort"),
                        "unwind" => Some("unwind"),
                        _ => Some("invalid"),
                    };
                }
            }
        }
    }
    None
}

/// Run the `ee-workers-build-with-unwind` gate on the repository root.
///
/// # Errors
///
/// Returns every offending manifest and setting.
pub fn run(root: &Path) -> Result<String, String> {
    let problems = check_root(root)?;
    if problems.is_empty() {
        Ok(String::from(
            "ee-workers-build-with-unwind OK: node release profile uses `panic = \"abort\"` and \
             all EE worker manifests use `panic = \"unwind\"`.",
        ))
    } else {
        let mut out = String::from("ee-workers-build-with-unwind FAILED:\n");
        for p in &problems {
            let _ = writeln!(out, "  - {p}");
        }
        Err(out)
    }
}

/// Self-test verifying both compliant and violating worker manifests.
///
/// # Errors
///
/// Returns a finding when a canary does not behave as the gate promises.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-ee-unwind")?;
    let result = (|| {
        let node_ok = "[package]\nname = \"node\"\n[profile.release]\npanic = \"abort\"\n";
        fs::write(dir.join("Cargo.toml"), node_ok).map_err(|e| e.to_string())?;
        let worker_dir = dir.join("execution/evm");
        fs::create_dir_all(&worker_dir).map_err(|e| e.to_string())?;

        // 1. Worker with panic = "abort" must fail.
        let worker_bad =
            "[package]\nname = \"budlum-ee-evm\"\n[profile.release]\npanic = \"abort\"\n";
        fs::write(worker_dir.join("Cargo.toml"), worker_bad).map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "VACUOUS: accepted EE worker with panic = \"abort\"",
            ));
        }

        // 2. Worker with panic = "unwind" must pass.
        let worker_good =
            "[package]\nname = \"budlum-ee-evm\"\n[profile.release]\npanic = \"unwind\"\n";
        fs::write(worker_dir.join("Cargo.toml"), worker_good).map_err(|e| e.to_string())?;
        run(&dir)?;
        Ok(String::from(
            "ee-workers-build-with-unwind self-test OK: rejected abort worker and accepted unwind.",
        ))
    })();
    let _ = fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn ee_workers_build_with_unwind_catches_injected_abort() {
        super::self_test().expect("ee-workers-build-with-unwind canary");
    }
}
