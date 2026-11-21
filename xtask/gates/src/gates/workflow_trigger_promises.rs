//! A workflow header that promises a trigger the file does not declare is a
//! runbook that cannot be followed.
//!
//! # The failure this closes
//!
//! Four heavy workflows told the reader they run "on the schedule and on
//! demand" while declaring no `schedule:` at all, and for a stretch none of
//! them declared `workflow_dispatch:` either, so the on-demand snapshot run
//! the CI protocol relies on was refused by GitHub with a 422. The code was
//! fine; the descriptor lied about how to start it, and the lie was only
//! found when an operator needed the run during a blocked merge queue.
//!
//! So this gate reads the promise and the declaration from the same place:
//! the `on:` block. A comment inside that block that says "on demand" is a
//! claim that `workflow_dispatch:` is declared; a comment that says "on the
//! schedule" or "on a schedule" is a claim that `schedule:` is declared.
//! Either claim without its trigger is refused. Comments outside the `on:`
//! block explain jobs, not triggers, and are not read as promises.
//!
//! The check is deliberately textual and dependency-free, like the rest of
//! this crate: the trigger keys sit at a fixed indentation under `on:`, and
//! the promise lives in the comment lines interleaved with them.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The trigger keys this gate can see promised, with the phrase that
/// promises each one.
const PROMISES: &[(&str, &str)] = &[
    ("on demand", "workflow_dispatch"),
    ("on the schedule", "schedule"),
    ("on a schedule", "schedule"),
];

/// Indentation of a line, in spaces.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The lines of the top-level `on:` mapping: from the `on:` key until the
/// next key at column zero. Empty when the file has no block-form `on:`.
fn on_block_lines(text: &str) -> Vec<&str> {
    let lines: Vec<&str> = text.lines().collect();
    let Some(start) = lines
        .iter()
        .position(|l| l.trim_end() == "on:" || l.trim_end().starts_with("on: "))
    else {
        return Vec::new();
    };
    // A flow-form `on: [push, ...]` declares its triggers on the same line;
    // there is no block for a comment to promise anything inside.
    if lines[start].trim_end() != "on:" {
        return Vec::new();
    }
    let mut out = Vec::new();
    for line in &lines[start + 1..] {
        if !line.trim().is_empty() && indent_of(line) == 0 {
            break;
        }
        out.push(*line);
    }
    out
}

/// True when the `on:` block declares `trigger:` as one of its keys.
fn declares(block: &[&str], trigger: &str) -> bool {
    // Trigger keys are the mapping keys directly under `on:`, at the first
    // indentation level the block uses.
    let key_indent = block
        .iter()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|l| indent_of(l))
        .min();
    let Some(key_indent) = key_indent else {
        return false;
    };
    block
        .iter()
        .any(|l| indent_of(l) == key_indent && l.trim_start().starts_with(&format!("{trigger}:")))
}

/// Every promise in one workflow text that its own `on:` block does not keep.
fn violations_for(name: &str, text: &str) -> Vec<String> {
    let block = on_block_lines(text);
    if block.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for line in &block {
        let Some(comment) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let comment = comment.to_lowercase();
        for (phrase, trigger) in PROMISES {
            if comment.contains(phrase) && !declares(&block, trigger) {
                out.push(format!(
                    "{name}: the `on:` header promises \"{phrase}\" but declares no \
                     `{trigger}:` trigger, so the run it describes cannot be started \
                     the way the file says it can. Add the trigger or remove the promise."
                ));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Workflow files GitHub reads, in stable order.
fn collect_workflows(root: &Path) -> Vec<PathBuf> {
    let dir = root.join(".github/workflows");
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("yml") || x.eq_ignore_ascii_case("yaml"))
            {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// # Errors
///
/// Returns every workflow whose header promises a trigger it does not
/// declare, or refuses when there is nothing to watch.
pub fn run(root: &Path) -> Result<String, String> {
    let files = collect_workflows(root);
    if files.is_empty() {
        return Err(String::from(
            "no workflow files found under .github/workflows. Either the directory moved \
             or CI is gone, and this gate is now watching nothing.",
        ));
    }
    let mut findings = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap_or_default();
        let name = f
            .strip_prefix(root)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        findings.extend(violations_for(&name, &src));
    }
    if findings.is_empty() {
        return Ok(format!(
            "Workflow trigger promise gate OK: {} workflows, every trigger promised in an \
             `on:` header is declared in that same block.",
            files.len()
        ));
    }
    let mut msg = String::new();
    let _ = writeln!(msg, "{} finding(s):\n", findings.len());
    for f in &findings {
        let _ = writeln!(msg, "  {f}\n");
    }
    Err(msg)
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    // Kept promise: both triggers declared, both phrases present.
    let kept = "name: X\non:\n  workflow_dispatch:\n  schedule:\n    - cron: \"0 0 * * 1\"\n  # It runs on the schedule and on demand.\n  push:\njobs:\n  a:\n    runs-on: ubuntu-latest\n";
    if !violations_for("kept.yml", kept).is_empty() {
        problems.push(String::from(
            "BROKEN: a workflow that declares what it promises was refused",
        ));
    }

    // The measured shape: an on-demand promise with no dispatch trigger.
    let no_dispatch =
        "name: X\non:\n  # It runs on demand.\n  push:\njobs:\n  a:\n    runs-on: ubuntu-latest\n";
    if violations_for("no-dispatch.yml", no_dispatch).is_empty() {
        problems.push(String::from(
            "VACUOUS: an \"on demand\" promise without workflow_dispatch was accepted",
        ));
    }

    // The measured shape: a schedule promise with no schedule trigger.
    let no_schedule = "name: X\non:\n  workflow_dispatch:\n  # It runs on the schedule and on demand.\n  push:\njobs:\n  a:\n    runs-on: ubuntu-latest\n";
    let v = violations_for("no-schedule.yml", no_schedule);
    if v.len() != 1 || !v[0].contains("schedule") {
        problems.push(format!(
            "VACUOUS: a schedule promise without a schedule trigger was not refused exactly once: {v:?}"
        ));
    }

    // A trigger phrase in a job comment is an explanation, not a promise
    // about the `on:` block, and must not be read as one.
    let job_comment = "name: X\non:\n  push:\njobs:\n  a:\n    # Retried on demand by the operator.\n    runs-on: ubuntu-latest\n";
    if !violations_for("job-comment.yml", job_comment).is_empty() {
        problems.push(String::from(
            "BROKEN: a job comment outside the `on:` block was read as a trigger promise",
        ));
    }

    if problems.is_empty() {
        Ok(String::from(
            "workflow-trigger-promises self-test: kept promises pass, unkept dispatch and \
             schedule promises are refused, and job comments are not promises",
        ))
    } else {
        Err(problems.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn workflow_trigger_promises_self_test() {
        super::self_test().expect("workflow-trigger-promises self-test");
    }
}
