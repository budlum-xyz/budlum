//! Every workflow can be started on demand: a live `workflow_dispatch:`
//! trigger under the top-level `on:` block of every file in
//! `.github/workflows`.
//!
//! # The failure this closes
//!
//! Four workflows (`determinism.yml`, `semver.yml`, `benchmark.yml`,
//! `pkcs11-pq.yml`) described themselves as running "on the schedule and on
//! demand" and had no `workflow_dispatch` trigger. The API answered
//! `422 Workflow does not have 'workflow_dispatch' trigger`, so the heavy
//! battery could not be started on a blocked stack head, and the evidence
//! window that the fan-out budget relies on ("the evidence-window owner
//! dispatches this workflow on the wave head") had no way to open. The
//! descriptor promised a trigger that did not exist, and nothing in CI read
//! the promise against the file.
//!
//! The snapshot path in `ci.yml` is built on the same trigger: a manual run on
//! a `snapshot/<sha>` ref is the only run a push to a stacked branch cannot
//! cancel. A workflow without `workflow_dispatch` has no such run and no
//! complete result for any head that is not the tip of its branch.
//!
//! # What is checked
//!
//! Statically, without calling GitHub, for every `.yml`/`.yaml` file in
//! `.github/workflows`:
//!
//! 1. The file declares a top-level `on:` block (block style) or a flow list
//!    (`on: [push, workflow_dispatch]`).
//! 2. That block names `workflow_dispatch` as a trigger key, at the first
//!    indentation level below `on:`. A `workflow_dispatch:` under `push:`, in
//!    a comment, or under `jobs:` is not a trigger and does not count.
//!
//! A file that cannot be read, has no `on:` block, or has an empty workflow
//! directory is a finding: the gate fails closed rather than counting what it
//! could not see. The parser is the same deliberately small line reader the
//! other workflow gates use: the indentation structure of a known file shape,
//! no YAML dependency.

use std::path::{Path, PathBuf};

/// The text of a line with a trailing `# comment` removed.
///
/// A `#` inside quotes would also be cut; no trigger key in this repository
/// carries one, and the only question asked of the remainder is whether it is
/// the key `workflow_dispatch`.
fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or("").trim_end()
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// Whether `rest` (the part of the `on:` line after the key) is a flow-style
/// list naming `workflow_dispatch`.
fn flow_list_dispatches(rest: &str) -> bool {
    let rest = rest.trim();
    let Some(inner) = rest.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        return false;
    };
    inner
        .split(',')
        .map(|item| item.trim().trim_matches(['"', '\'']))
        .any(|item| item == "workflow_dispatch")
}

fn is_on_key(line: &str) -> Option<&str> {
    for key in ["on:", "\"on\":", "'on':"] {
        if let Some(rest) = line.strip_prefix(key) {
            return Some(rest);
        }
    }
    None
}

/// Whether the workflow text declares a live `workflow_dispatch` trigger.
///
/// Returns `Err` with the reason when it does not, so the finding names what
/// was missing rather than only that something was.
fn check_text(text: &str) -> Result<(), String> {
    let mut saw_on = false;
    let mut in_on = false;
    let mut level: Option<usize> = None;
    for raw in text.lines() {
        let line = strip_comment(raw);
        if line.trim().is_empty() {
            continue;
        }
        if indent_of(line) == 0 {
            if in_on {
                // The block ended without a trigger; a later top-level `on:`
                // is not valid YAML, so the answer is known here.
                return Err(String::from(
                    "the `on:` block declares no `workflow_dispatch` trigger",
                ));
            }
            if let Some(rest) = is_on_key(line) {
                saw_on = true;
                if flow_list_dispatches(rest) {
                    return Ok(());
                }
                if !rest.trim().is_empty() {
                    return Err(format!(
                        "the `on:` value `{}` names no `workflow_dispatch` trigger",
                        rest.trim()
                    ));
                }
                in_on = true;
            }
            continue;
        }
        if !in_on {
            continue;
        }
        let indent = indent_of(line);
        let first = *level.get_or_insert(indent);
        if indent != first {
            continue;
        }
        let key = line.trim();
        if key == "workflow_dispatch:" || key.starts_with("workflow_dispatch: ") {
            return Ok(());
        }
    }
    if in_on {
        return Err(String::from(
            "the `on:` block declares no `workflow_dispatch` trigger",
        ));
    }
    if saw_on {
        return Err(String::from("the `on:` key has no trigger"));
    }
    Err(String::from("no top-level `on:` block"))
}

fn collect_workflows(root: &Path) -> Result<Vec<PathBuf>, String> {
    let dir = root.join(".github/workflows");
    let entries =
        std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        let is_yaml = path
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("yml") || x.eq_ignore_ascii_case("yaml"));
        if is_yaml {
            out.push(path);
        }
    }
    out.sort();
    if out.is_empty() {
        return Err(format!("no workflow files under {}", dir.display()));
    }
    Ok(out)
}

/// # Errors
///
/// Returns a finding naming every workflow that cannot be started on demand,
/// or the reason the workflow directory could not be measured.
pub fn run(root: &Path) -> Result<String, String> {
    let workflows = collect_workflows(root)?;
    let mut problems = Vec::new();
    for path in &workflows {
        let label = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        match std::fs::read_to_string(path) {
            Ok(text) => {
                if let Err(why) = check_text(&text) {
                    problems.push(format!("{label}: {why}"));
                }
            }
            Err(e) => problems.push(format!("{label}: cannot read: {e}")),
        }
    }
    if !problems.is_empty() {
        return Err(format!(
            "workflows-are-dispatchable: {} workflow(s) cannot be run on demand \
             (POST /actions/workflows/<file>/dispatches answers 422 for them):\n{}",
            problems.len(),
            problems.join("\n")
        ));
    }
    Ok(format!(
        "workflows-are-dispatchable OK: {} workflow(s) declare a live workflow_dispatch trigger",
        workflows.len()
    ))
}

/// # Errors
///
/// Returns a finding when a canary does not behave as the gate promises.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-dispatchable")?;
    let result = (|| {
        let workflows = dir.join(".github/workflows");
        std::fs::create_dir_all(&workflows).map_err(|e| e.to_string())?;
        let file = workflows.join("battery.yml");
        let good = "name: battery\n\non:\n  pull_request:\n    branches: [main]\n  workflow_dispatch:\n  push:\n    branches: [main]\n\njobs:\n  verify:\n    steps:\n      - run: cargo test --workspace\n";
        let expect_pass = |text: &str, what: &str| -> Result<(), String> {
            std::fs::write(&file, text).map_err(|e| e.to_string())?;
            run(&dir)
                .map(|_| ())
                .map_err(|why| format!("canary: {what} failed: {why}"))
        };
        let expect_fail = |text: &str, what: &str| -> Result<(), String> {
            std::fs::write(&file, text).map_err(|e| e.to_string())?;
            if run(&dir).is_ok() {
                return Err(format!("canary: {what} passed"));
            }
            Ok(())
        };

        expect_pass(good, "a block-style dispatch trigger")?;
        expect_pass(
            &good.replace(
                "  workflow_dispatch:\n",
                "  workflow_dispatch:\n    inputs:\n      ref:\n        required: false\n",
            ),
            "a dispatch trigger with inputs",
        )?;
        expect_pass(
            "name: flow\non: [push, workflow_dispatch]\njobs:\n  verify:\n    steps:\n      - run: cargo test\n",
            "a flow-style dispatch trigger",
        )?;

        expect_fail(
            &good.replace("  workflow_dispatch:\n", ""),
            "a workflow without workflow_dispatch",
        )?;
        expect_fail(
            &good.replace("  workflow_dispatch:\n", "  # workflow_dispatch:\n"),
            "a commented-out dispatch trigger",
        )?;
        expect_fail(
            &good.replace("  workflow_dispatch:\n", "    workflow_dispatch:\n"),
            "a dispatch key nested under another trigger",
        )?;
        expect_fail(
            &good.replace("  workflow_dispatch:\n", "").replace(
                "jobs:\n",
                "jobs:\n  workflow_dispatch:\n    steps:\n      - run: true\n",
            ),
            "a dispatch key under jobs",
        )?;
        expect_fail(
            "name: flow\non: [push, pull_request]\njobs:\n  verify:\n    steps:\n      - run: cargo test\n",
            "a flow-style trigger list without dispatch",
        )?;
        expect_fail(
            "name: none\njobs:\n  verify:\n    steps:\n      - run: cargo test\n",
            "a workflow without an on block",
        )?;

        // A second file without the trigger fails the directory even when the
        // first is fine: every workflow is checked, not the first one found.
        std::fs::write(&file, good).map_err(|e| e.to_string())?;
        let other = workflows.join("other.yml");
        std::fs::write(&other, good.replace("  workflow_dispatch:\n", ""))
            .map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: a second workflow without workflow_dispatch passed",
            ));
        }
        std::fs::remove_file(&other).map_err(|e| e.to_string())?;

        // An empty workflow directory is not a pass.
        std::fs::remove_file(&file).map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an empty workflow directory passed"));
        }
        Ok(String::from(
            "workflows-are-dispatchable canary OK: live dispatch passes; missing, commented, nested, misplaced, flow-without-dispatch, no-on and empty-directory fail",
        ))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn workflows_are_dispatchable_catches_injected_omissions() {
        super::self_test().expect("dispatchable canary");
    }

    #[test]
    fn issue_203_shape_is_a_finding() {
        // The exact shape the issue measured: the header says "on demand" and
        // the block has no trigger for it.
        let text = "name: Semver Check\n\non:\n  push:\n    branches: [main]\n  # Heavy battery. It runs on pull requests to `main`, on demand and on\n  # pushes to `main`.\n  pull_request:\n    branches: [main, consensus-of-consensuses]\n\nconcurrency:\n  group: semver-${{ github.ref }}\n";
        let why = super::check_text(text).expect_err("issue 203 shape must fail");
        assert!(why.contains("workflow_dispatch"), "{why}");
    }

    #[test]
    fn repaired_shape_passes() {
        let text = "name: Semver Check\n\non:\n  workflow_dispatch:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main, consensus-of-consensuses]\n";
        super::check_text(text).expect("repaired shape passes");
    }
}
