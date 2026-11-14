//! A cancelled run must be able to end.
//!
//! # The failure this closes
//!
//! `ci.yml` closes with a `Budlum Core` job that reads the result of the five
//! core splits. It carried `if: always()`. `always()` still holds after a
//! cancel: when a push cancels the run of the commit before it, GitHub
//! cancels the running jobs and then schedules every `always()` job anyway.
//! On a busy pool that one job waited in the queue for half an hour. The run
//! stayed open the whole time, and its concurrency group (`ci-<ref>`) stayed
//! taken, so the run for the new commit sat `pending` with no jobs. Four more
//! workflows queued behind the same stack.
//!
//! The fix is `!cancelled()`. It runs the job after a failure, which is the
//! reason for `always()` on an aggregator, and skips it after a cancel, so the
//! run closes and the group is free.
//!
//! # What is checked
//!
//! In every workflow that runs on `pull_request` or `pull_request_target`, no
//! job-level `if:` uses `always()`. A step-level `if: always()` is fine: the
//! step belongs to a job that is already running. A scheduled workflow is not
//! stacked by pushes and is left alone.
//!
//! The reader is line based, like its neighbours in this crate. A job key sits
//! at four spaces of indentation under `jobs:`; a step key is deeper.

use std::path::{Path, PathBuf};

/// Indentation of a line, in spaces.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// A line whose first non-space character is `#` is a comment.
fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

/// True when the workflow runs on a pull request event.
///
/// Reads the lines before `jobs:`. The block form (`pull_request:` under
/// `on:`), the list form (`- pull_request`) and the inline forms
/// (`on: pull_request`, `on: [push, pull_request]`) all count.
fn runs_on_pull_request(src: &str) -> bool {
    for line in src.lines() {
        if is_comment(line) {
            continue;
        }
        let t = line.trim();
        if indent_of(line) == 0 && t.starts_with("jobs:") {
            break;
        }
        // Block form, list form and inline form of the trigger.
        if t.starts_with("pull_request:")
            || t.starts_with("pull_request_target:")
            || t == "- pull_request"
            || t == "- pull_request_target"
        {
            return true;
        }
        if indent_of(line) == 0 && t.starts_with("on:") && t.contains("pull_request") {
            return true;
        }
    }
    false
}

/// One job-level `if:` that holds `always()`.
struct Finding {
    line: usize,
    job: String,
}

/// The job-level conditions of one workflow that hold `always()`.
///
/// A condition may continue on the following, deeper lines (`if: >-`), so
/// those are joined before the test.
fn always_jobs(src: &str) -> Vec<Finding> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut in_jobs = false;
    let mut job = String::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        i += 1;
        if is_comment(line) || line.trim().is_empty() {
            continue;
        }
        let ind = indent_of(line);
        let t = line.trim();
        if ind == 0 {
            in_jobs = t.starts_with("jobs:");
            continue;
        }
        if !in_jobs {
            continue;
        }
        if ind == 2 && t.ends_with(':') {
            job = t.trim_end_matches(':').to_string();
            continue;
        }
        if ind == 4 && t.starts_with("if:") {
            let mut cond = t.trim_start_matches("if:").to_string();
            let start = i;
            while i < lines.len() {
                let next = lines[i];
                if next.trim().is_empty() || is_comment(next) {
                    i += 1;
                    continue;
                }
                if indent_of(next) <= 4 {
                    break;
                }
                cond.push(' ');
                cond.push_str(next.trim());
                i += 1;
            }
            if cond.contains("always()") {
                out.push(Finding {
                    line: start,
                    job: job.clone(),
                });
            }
        }
    }
    out
}

/// The refusals for one workflow, as printable lines.
fn findings_for(rel: &str, src: &str) -> Vec<String> {
    if !runs_on_pull_request(src) {
        return Vec::new();
    }
    always_jobs(src)
        .into_iter()
        .map(|f| {
            format!(
                "{rel}:{}: job `{}` has a job-level `if:` with `always()`. A cancelled run \
                 still schedules it, so the run stays open behind a full queue and its \
                 concurrency group stays taken. Use `${{{{ !cancelled() }}}}`.",
                f.line, f.job
            )
        })
        .collect()
}

/// Workflow files under `.github/workflows`, sorted.
fn collect_workflows(root: &Path) -> Vec<PathBuf> {
    let Ok(dir) = std::fs::read_dir(root.join(".github/workflows")) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = dir
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("yml") || x.eq_ignore_ascii_case("yaml"))
        })
        .collect();
    files.sort();
    files
}

/// # Errors
///
/// Returns every pull-request workflow whose job-level condition holds
/// `always()`.
pub fn run(root: &Path) -> Result<String, String> {
    let files = collect_workflows(root);
    if files.is_empty() {
        return Err(String::from(
            "no workflow files found under .github/workflows. Either the directory moved \
             or CI is gone, and this gate is now watching nothing.",
        ));
    }
    let mut findings = Vec::new();
    let mut checked = 0usize;
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap_or_default();
        let rel = f.strip_prefix(root).unwrap_or(f).display().to_string();
        if runs_on_pull_request(&src) {
            checked += 1;
        }
        findings.extend(findings_for(&rel, &src));
    }
    if findings.is_empty() {
        Ok(format!(
            "ci-jobs-end-on-cancel OK: {checked} pull-request workflow(s), no job-level \
             always()"
        ))
    } else {
        Err(format!(
            "ci-jobs-end-on-cancel: {} job(s) cannot end after a cancel:\n  {}",
            findings.len(),
            findings.join("\n  ")
        ))
    }
}

/// The reader against fixtures that hold and fixtures that break the rule.
///
/// # Errors
///
/// Returns the fixtures the reader got wrong.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    let head = "name: X\non:\n  pull_request:\n    branches: [main]\njobs:\n  a:\n    steps: []\n";
    let refused = [
        ("plain", "  gate:\n    needs: [a]\n    if: always()\n    steps: []\n"),
        (
            "wrapped",
            "  gate:\n    needs: [a]\n    if: ${{ always() }}\n    steps: []\n",
        ),
        (
            "combined",
            "  gate:\n    needs: [a]\n    if: always() && needs.a.result == 'failure'\n    steps: []\n",
        ),
        (
            "folded",
            "  gate:\n    needs: [a]\n    if: >-\n      needs.a.result != 'success' &&\n      always()\n    steps: []\n",
        ),
    ];
    for (name, body) in refused {
        let src = format!("{head}{body}");
        if findings_for("x.yml", &src).len() != 1 {
            problems.push(format!(
                "VACUOUS: the {name} job-level always() was not refused"
            ));
        }
    }

    let passed = [
        (
            "cancelled",
            "  gate:\n    needs: [a]\n    if: ${{ !cancelled() }}\n    steps: []\n",
        ),
        (
            "step level",
            "  gate:\n    steps:\n      - name: tidy\n        if: always() && steps.x.outcome == 'success'\n        run: true\n",
        ),
        ("no condition", "  gate:\n    needs: [a]\n    steps: []\n"),
    ];
    for (name, body) in passed {
        let src = format!("{head}{body}");
        let found = findings_for("x.yml", &src);
        if !found.is_empty() {
            problems.push(format!("BROKEN: the {name} job was refused: {found:?}"));
        }
    }

    // A scheduled workflow is not stacked by pushes.
    let scheduled = "name: X\non:\n  schedule:\n    - cron: \"0 * * * *\"\njobs:\n  a:\n    steps: []\n  s:\n    needs: [a]\n    if: always()\n    steps: []\n";
    if !findings_for("x.yml", scheduled).is_empty() {
        problems.push(String::from(
            "BROKEN: a scheduled workflow was refused for always()",
        ));
    }

    // The inline and list trigger forms count as pull-request workflows.
    for inline in [
        "on: pull_request",
        "on: [push, pull_request]",
        "on:\n  - push\n  - pull_request",
    ] {
        let src = format!(
            "name: X\n{inline}\njobs:\n  s:\n    needs: [a]\n    if: always()\n    steps: []\n"
        );
        if findings_for("x.yml", &src).len() != 1 {
            problems.push(format!(
                "VACUOUS: `{inline}` was not read as a pull-request trigger"
            ));
        }
    }

    // The refusal names the job and the line.
    let src = format!("{head}  gate:\n    if: always()\n    steps: []\n");
    let named = findings_for("x.yml", &src);
    if !named
        .first()
        .is_some_and(|m| m.contains("x.yml:") && m.contains("`gate`"))
    {
        problems.push(format!(
            "BROKEN: the refusal does not name the file and job: {named:?}"
        ));
    }

    if problems.is_empty() {
        Ok(String::from(
            "ci-jobs-end-on-cancel self-test OK: a plain, a wrapped, a combined and a folded \
             job-level always() are refused in a pull-request workflow; !cancelled(), a \
             step-level always(), no condition and a scheduled workflow pass; the inline and list \
             trigger forms are read.",
        ))
    } else {
        Err(problems.join("\n  "))
    }
}
