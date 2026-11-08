//! The named nightly workflows exist, run on a schedule, and carry at least
//! one binding verification step.
//!
//! A nightly workflow that is missing, unscheduled, or softened is not a
//! gate. This reader checks the repository shape that makes the nightly
//! surface a required part of CI: the workflow file is present, a
//! `schedule:` trigger is declared, and a verification command runs in a
//! step that is not `continue-on-error`, constant-false, or failure-only.
//! It reuses the workflow run-block reader, so a command in a comment does
//! not satisfy it.

use std::path::Path;

use crate::gates::ci_workflow_guards::run_blocks;

const REQUIRED_NIGHTLY: &[&str] = &[
    ".github/workflows/fuzz-nightly.yml",
    ".github/workflows/kani-slow.yml",
    ".github/workflows/air-mutants-nightly.yml",
    ".github/workflows/miri.yml",
    ".github/workflows/conformance-nightly.yml",
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
    if line.trim_start().starts_with('#') {
        return false;
    }
    if line.contains("budlum-gates") {
        return true;
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let Some(cargo) = tokens.iter().position(|t| *t == "cargo") else {
        return false;
    };
    let Some(verb) = tokens[cargo + 1..]
        .iter()
        .copied()
        .find(|token| !token.starts_with('+'))
    else {
        return false;
    };
    VERIFICATION_VERBS.contains(&verb)
}

fn check_workflow(path: &Path, text: &str) -> Result<(), String> {
    let label = path.display().to_string();
    if !has_schedule(text) {
        return Err(format!("{label}: no live schedule trigger with a cron entry"));
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

/// # Errors
///
/// Returns a finding when a required nightly workflow is not a live gate.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems = Vec::new();
    for relative in REQUIRED_NIGHTLY {
        let path = root.join(relative);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) => {
                problems.push(format!("{relative}: cannot read: {e}"));
                continue;
            }
        };
        if let Err(problem) = check_workflow(&path, &text) {
            problems.push(problem);
        }
    }
    if !problems.is_empty() {
        return Err(problems.join("\n"));
    }
    Ok(format!(
        "nightly_workflows_are_required OK: {} scheduled workflow(s) carry a binding verification step",
        REQUIRED_NIGHTLY.len()
    ))
}

/// # Errors
///
/// Returns a finding when a canary does not behave as the gate promises.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-nightly-required")?;
    let result = (|| {
        let workflows = dir.join(".github/workflows");
        std::fs::create_dir_all(&workflows).map_err(|e| e.to_string())?;
        let good = "name: nightly\non:\n  schedule:\n    - cron: \"0 3 * * *\"\njobs:\n  verify:\n    steps:\n      - run: cargo test --workspace\n";
        for relative in REQUIRED_NIGHTLY {
            std::fs::write(dir.join(relative), good).map_err(|e| e.to_string())?;
        }
        run(&dir)?;

        let missing = REQUIRED_NIGHTLY[0];
        std::fs::remove_file(dir.join(missing)).map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a missing nightly workflow passed"));
        }
        std::fs::write(dir.join(missing), good).map_err(|e| e.to_string())?;

        let unscheduled = good.replace("  schedule:\n    - cron: \"0 3 * * *\"\n", "  workflow_dispatch:\n");
        std::fs::write(dir.join(missing), unscheduled).map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an unscheduled nightly workflow passed"));
        }

        let softened = good.replace("      - run: cargo test --workspace\n", "      - continue-on-error: true\n        run: cargo test --workspace\n");
        std::fs::write(dir.join(missing), softened).map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a softened nightly verification passed"));
        }

        let commented = good.replace("      - run: cargo test --workspace\n", "      # - run: cargo test --workspace\n      - run: echo nothing\n");
        std::fs::write(dir.join(missing), commented).map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a commented nightly verification passed"));
        }
        Ok(String::from(
            "nightly_workflows_are_required canary OK: scheduled binding passes, missing/unscheduled/softened/commented verification fails",
        ))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn nightly_workflows_are_required_catches_injected_softening() {
        super::self_test().expect("nightly required canary");
    }
}
