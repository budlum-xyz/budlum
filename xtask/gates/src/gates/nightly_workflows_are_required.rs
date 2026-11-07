//! Every required nightly workflow exists, runs on a schedule, and carries at
//! least one binding verification step.
//!
//! Section 16.2 rule 1 makes the nightly workflows required gates: a scheduled
//! workflow that is missing, unscheduled, or softened (`continue-on-error:
//! true`, `if: false`, `if: failure()`) is not a gate. This check inspects the
//! baseline nightly workflows (`fuzz-nightly.yml`, `kani-slow.yml`,
//! `air-mutants-nightly.yml`, `miri.yml`) together with any additional
//! `*-nightly.yml` file present in `.github/workflows/`, and requires each one
//! to declare a live `schedule:` with a `cron:` entry and at least one
//! unsoftened verification command.

use std::collections::BTreeSet;
use std::path::Path;

use crate::gates::ci_workflow_guards::run_blocks;

const BASELINE_NIGHTLY: &[&str] = &[
    ".github/workflows/fuzz-nightly.yml",
    ".github/workflows/kani-slow.yml",
    ".github/workflows/air-mutants-nightly.yml",
    ".github/workflows/miri.yml",
];

const VERIFICATION_VERBS: &[&str] = &[
    "fuzz", "kani", "mutants", "miri", "test", "build", "check", "clippy", "run",
];

fn has_schedule(text: &str) -> bool {
    let mut scheduled = false;
    let mut cron = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "schedule:" {
            scheduled = true;
        }
        if trimmed.starts_with("- cron:") || trimmed.starts_with("cron:") {
            cron = true;
        }
    }
    scheduled && cron
}

fn is_verification_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return false;
    }
    if trimmed.contains("budlum-gates") {
        return true;
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    let Some(cargo) = tokens.iter().position(|t| *t == "cargo") else {
        return false;
    };
    let Some(verb) = tokens
        .get(cargo + 1..)
        .into_iter()
        .flatten()
        .copied()
        .find(|token| !token.starts_with('+'))
    else {
        return false;
    };
    VERIFICATION_VERBS.contains(&verb)
}

fn check_workflow(label: &str, text: &str) -> Result<(), String> {
    if !has_schedule(text) {
        return Err(format!(
            "{label}: no live schedule trigger with a cron entry"
        ));
    }
    let blocks = run_blocks(text);
    let mut binding = false;
    for block in &blocks {
        let verification = block.lines.iter().any(|line| is_verification_line(line));
        if !verification {
            continue;
        }
        if let Some(why) = &block.softened {
            return Err(format!(
                "{label}: verification step `{}` is softened ({why})",
                block.step
            ));
        }
        binding = true;
    }
    if !binding {
        return Err(format!(
            "{label}: no binding verification step runs on the schedule"
        ));
    }
    Ok(())
}

fn workflow_paths(root: &Path) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BASELINE_NIGHTLY
        .iter()
        .map(|rel| (*rel).to_string())
        .collect();
    let dir = root.join(".github/workflows");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if !kind.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with("-nightly.yml") {
                out.insert(format!(".github/workflows/{name}"));
            }
        }
    }
    out
}

/// # Errors
///
/// Returns a finding when a required nightly workflow is missing, unscheduled,
/// or softened.
pub fn run(root: &Path) -> Result<String, String> {
    let paths = workflow_paths(root);
    let mut problems = Vec::new();
    for relative in &paths {
        let path = root.join(relative);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) => {
                problems.push(format!("{relative}: cannot read: {e}"));
                continue;
            }
        };
        if let Err(problem) = check_workflow(relative, &text) {
            problems.push(problem);
        }
    }
    if !problems.is_empty() {
        return Err(problems.join("\n"));
    }
    Ok(format!(
        "nightly_workflows_are_required OK: {} scheduled workflow(s) carry a binding verification step",
        paths.len()
    ))
}

const GOOD_WORKFLOW: &str = "\
name: Nightly fixture
on:
  schedule:
    - cron: \"15 2 * * *\"
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Run verification
        run: cargo test --workspace
";

fn stage_clean(root: &Path) -> Result<(), String> {
    let wf_dir = root.join(".github/workflows");
    std::fs::create_dir_all(&wf_dir).map_err(|e| e.to_string())?;
    for relative in BASELINE_NIGHTLY {
        std::fs::write(root.join(relative), GOOD_WORKFLOW).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// # Errors
///
/// Returns a finding when a canary does not behave as the gate promises.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-nightly-required")?;
    stage_clean(&dir)?;
    if let Err(e) = run(&dir) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(format!("canary: a clean nightly workflow set failed: {e}"));
    }

    let target = dir.join(BASELINE_NIGHTLY[0]);
    std::fs::remove_file(&target).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a missing baseline nightly workflow passed",
        ));
    }

    let cases = [
        (
            "name: No schedule\non:\n  workflow_dispatch:\njobs:\n  v:\n    steps:\n      - name: Check\n        run: cargo test\n",
            "canary: an unscheduled nightly workflow passed",
        ),
        (
            "name: Commented cron\non:\n  schedule:\n    # - cron: \"0 0 * * *\"\njobs:\n  v:\n    steps:\n      - name: Check\n        run: cargo test\n",
            "canary: a nightly workflow with a commented-out cron passed",
        ),
        (
            "name: Softened continue\non:\n  schedule:\n    - cron: \"0 0 * * *\"\njobs:\n  v:\n    steps:\n      - name: Check\n        continue-on-error: true\n        run: cargo fuzz run target\n",
            "canary: a continue-on-error nightly verification step passed",
        ),
        (
            "name: Softened if-false\non:\n  schedule:\n    - cron: \"0 0 * * *\"\njobs:\n  v:\n    steps:\n      - name: Check\n        if: false\n        run: cargo miri test\n",
            "canary: an if: false nightly verification step passed",
        ),
        (
            "name: No verification verb\non:\n  schedule:\n    - cron: \"0 0 * * *\"\njobs:\n  v:\n    steps:\n      - name: Echo only\n        run: echo ok\n",
            "canary: a nightly workflow with no verification step passed",
        ),
    ];

    for (bad, reason) in cases {
        std::fs::write(&target, bad).map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(String::from(reason));
        }
    }

    std::fs::write(&target, GOOD_WORKFLOW).map_err(|e| e.to_string())?;
    let extra = dir.join(".github/workflows/conformance-nightly.yml");
    std::fs::write(
        &extra,
        "name: Unscheduled extra\non:\n  workflow_dispatch:\njobs:\n  v:\n    steps:\n      - run: cargo check\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: an unscheduled *-nightly.yml workflow passed",
        ));
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "nightly_workflows_are_required self-test OK: clean passes; missing, unscheduled, \
         commented-cron, softened, and verification-free workflows fail.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nightly_workflows_are_required_catches_injected_unscheduled_workflow() {
        assert!(check_workflow(".github/workflows/fuzz-nightly.yml", GOOD_WORKFLOW).is_ok());
        let unscheduled = GOOD_WORKFLOW.replace("  schedule:\n    - cron: \"15 2 * * *\"\n", "");
        assert!(check_workflow(".github/workflows/fuzz-nightly.yml", &unscheduled).is_err());
    }

    #[test]
    fn verification_line_recognises_toolchain_overrides_and_gates() {
        assert!(is_verification_line("cargo +nightly miri test"));
        assert!(is_verification_line(
            "./xtask/gates/target/release/budlum-gates regen-health-door"
        ));
        assert!(!is_verification_line("# cargo fuzz run target"));
        assert!(!is_verification_line("cargo install --locked cargo-fuzz"));
    }
}
