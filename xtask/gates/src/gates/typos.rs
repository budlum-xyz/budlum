//! typos spell-check gate - local mirror of the Typos CI workflow.
//!
//! Why: the repo's spell check lived ONLY in CI (`.github/workflows/
//! typos.yml`, calibrated via `.quality/typos.toml`). That let tree-wide
//! findings surface for the first time in CI - the 2026-09-22 case being a
//! two-character parameter name in `tools/bpqs_checksum_domination_exact.py`
//! that read as a typo of `and`, passed every local gate, and tripped only
//! the CI workflow. This gate runs the same whole-tree calibrated scan
//! locally so the finding class is caught where every other gate runs.
//!
//! House posture (same as actionlint): binary-pinned via `TYPOS_BIN` with a
//! plain `typos` fallback, fail-closed when the binary is absent. CI installs
//! the pinned binary itself, so an absent local binary costs exactly one FAIL
//! line locally and nothing in CI. The self-test proves the gate can fail by
//! scanning a deliberately misspelled word assembled from two pieces - the
//! misspelling must not appear literally in this file, because CI scans this
//! file too (the same trick the workflow's canary uses).

use std::path::Path;

fn bin() -> String {
    std::env::var("TYPOS_BIN").unwrap_or_else(|_| "typos".to_string())
}

/// # Errors
///
/// Returns typos' report on any finding, and when the binary cannot run.
pub fn run(root: &Path) -> Result<String, String> {
    let config = root.join(".quality/typos.toml");
    if !config.is_file() {
        return Err(format!("missing calibration file: {}", config.display()));
    }
    let out = std::process::Command::new(bin())
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "long",
        ])
        .current_dir(root)
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(String::from(
            "typos temiz. (whole-tree, calibrated, mirrors the CI workflow)",
        )),
        Ok(o) => Err(format!(
            "typos findings:\n{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )),
        Err(e) => Err(format!("typos did not run: {e}")),
    }
}

/// # Errors
///
/// Returns a finding when a deliberately misspelled word passes typos.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-typos")?;
    // Assembled on purpose: a literal misspelling in this source file would
    // fail the CI scan this gate mirrors.
    let mut word = String::from("reci");
    word.push_str("eve");
    std::fs::write(
        dir.join("canary.rs"),
        format!("fn main() {{ let _{word} = 1; }}\n"),
    )
    .map_err(|e| e.to_string())?;
    let out = std::process::Command::new(bin())
        .arg("--isolated")
        .arg(&dir)
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    match out {
        Ok(o) if o.status.success() => Err(String::from(
            "self-test FAILED: typos reported the planted misspelling as clean",
        )),
        Ok(_) => Ok(String::from("self-test: typos catches the planted word.")),
        Err(e) => Err(format!("self-test: typos does not run here: {e}")),
    }
}
