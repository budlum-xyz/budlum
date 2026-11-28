//! Every status context the protected branch requires is produced, on the
//! branch it protects, by a job that exists.
//!
//! # The failure this closes
//!
//! Branch protection on `consensus-of-consensuses` required a context named
//! `merge-block-default-branch`. Measured 2026-11-27 over every branch of the
//! repository: thirty-nine workflow files, and not one job named
//! `merge-block-default-branch`. A required check that nothing reports is not a
//! protection; it is a permanent "Expected - Waiting for status to be
//! reported", which is what the delivery pull request #215 showed with seventy
//! -nine green checks beside it.
//!
//! The reason nobody noticed is structural. The required contexts live in the
//! repository's *settings*, the producing jobs live in its *tree*, and nothing
//! read both. Renaming a job, or deleting the workflow that carried it, quietly
//! converts a required check into a check that will never arrive. This gate
//! reads both, and the only thing it adds to the tree is the claim file that
//! says what the settings currently require.
//!
//! # What this gate decides
//!
//! `.github/required-status-contexts.txt` lists `context<TAB>branch` pairs: the
//! status contexts branch protection requires, and the branch each one protects.
//! For every pair the gate requires a workflow file that
//!
//! 1. declares a job whose check-run name is exactly that context, and
//! 2. triggers on `pull_request` into that branch (or on `pull_request` with no
//!    branch list, which covers every branch).
//!
//! Both halves matter and they fail differently. A context no job names never
//! reports at all. A context whose job exists but whose workflow does not fire
//! on pull requests into the protected branch reports on the wrong events, which
//! looks healthier and is the same dead end.
//!
//! # Why a claim file rather than the live API
//!
//! Reading branch protection needs a token and a network, and a gate that
//! cannot run offline is a gate that gets skipped. The claim file is checked in
//! and reviewed like code, and the rule that keeps it honest is the one the
//! surrounding gates already use: the file is a statement about the tree, and a
//! statement the tree does not satisfy fails. When the protection changes, the
//! claim changes in the same pull request, and a reviewer sees both.
//!
//! The self-test canaries prove the gate can fail in each direction: a context
//! no job names, a context produced by a job in a workflow that does not fire
//! on the branch, a claim entry with no branch, and an empty claim file.

use std::path::Path;

use super::ci_trigger_coverage::pull_request_branches;

/// The claim: `context<TAB>branch`, one per line.
pub const CLAIM_PATH: &str = ".github/required-status-contexts.txt";

/// One claimed protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The required status context, as branch protection spells it.
    pub context: String,
    /// The branch whose pull requests must report it.
    pub branch: String,
}

/// Parse the claim file.
///
/// A missing branch is an error rather than a default: guessing which branch a
/// context protects would let the gate check the wrong pull-request path and
/// pass, which is the failure this gate exists to catch.
pub fn parse_claims(text: &str) -> Result<Vec<Claim>, String> {
    let mut out: Vec<Claim> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split('\t');
        let context = fields.next().unwrap_or_default().trim();
        let branch = fields.next().map(str::trim);
        if context.is_empty() {
            return Err(format!(
                "required-contexts-are-produced: {}:{} has no context",
                CLAIM_PATH,
                n + 1
            ));
        }
        let Some(branch) = branch else {
            return Err(format!(
                "required-contexts-are-produced: {}:{} names context `{context}` with no branch. \
                 The pair is `context<TAB>branch`; a context without its branch cannot be checked.",
                CLAIM_PATH,
                n + 1
            ));
        };
        if branch.is_empty() {
            return Err(format!(
                "required-contexts-are-produced: {}:{} names context `{context}` with an empty \
                 branch",
                CLAIM_PATH,
                n + 1
            ));
        }
        out.push(Claim {
            context: context.to_owned(),
            branch: branch.to_owned(),
        });
    }
    if out.is_empty() {
        return Err(format!(
            "required-contexts-are-produced: {CLAIM_PATH} claims nothing. An empty claim reads as \
             \"no context is required\", which is the absent-as-permission mistake this gate \
             exists for."
        ));
    }
    Ok(out)
}

/// True when this workflow declares a job whose check-run name is `context`.
///
/// Two spellings produce a check-run name: a job key (`  merge-block-x:`) uses
/// the key, and a job `name:` (`    name: merge-block-x`) overrides it. Both are
/// read; anything indented deeper than a job key is a step, not a job, and is
/// not read, because a step's name never becomes a status context.
#[must_use]
pub fn declares_job_named(workflow: &str, context: &str) -> bool {
    let mut in_jobs = false;
    for raw in workflow.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - trimmed.len();
        if indent == 0 {
            in_jobs = trimmed == "jobs:";
            continue;
        }
        if !in_jobs {
            continue;
        }
        if indent == 2 {
            // A job key, optionally followed by nothing else on the line.
            if let Some(key) = trimmed.strip_suffix(':') {
                if key == context {
                    return true;
                }
            }
            continue;
        }
        if indent == 4 {
            if let Some(rest) = trimmed.strip_prefix("name:") {
                if rest.trim().trim_matches('"').trim_matches('\'') == context {
                    return true;
                }
            }
        }
    }
    false
}

/// True when this workflow reports on pull requests into `branch`.
#[must_use]
pub fn fires_on(workflow: &str, branch: &str) -> bool {
    match pull_request_branches(workflow) {
        None => true,
        Some(names) => names.iter().any(|n| n == branch),
    }
}

/// The findings for one claim, empty when it holds.
#[must_use]
pub fn findings_for(claim: &Claim, workflows: &[(String, String)]) -> Vec<String> {
    let mut findings: Vec<String> = Vec::new();
    let producers: Vec<&(String, String)> = workflows
        .iter()
        .filter(|(_, src)| declares_job_named(src, &claim.context))
        .collect();
    if producers.is_empty() {
        findings.push(format!(
            "context `{}` is required on `{}` and no workflow declares a job with that name. A \
             required check nothing reports never arrives, so the branch cannot be merged into.",
            claim.context, claim.branch
        ));
        return findings;
    }
    if !producers.iter().any(|(_, src)| fires_on(src, &claim.branch)) {
        let names: Vec<&str> = producers.iter().map(|(n, _)| n.as_str()).collect();
        findings.push(format!(
            "context `{}` is produced by {} but none of them triggers on `pull_request` into \
             `{}`. The job exists and the check will not report on the pull requests that need it.",
            claim.context,
            names.join(", "),
            claim.branch
        ));
    }
    findings
}

/// Read every workflow file under `.github/workflows`.
pub fn read_workflows(root: &Path) -> Result<Vec<(String, String)>, String> {
    let dir = root.join(".github/workflows");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("required-contexts-are-produced: {} is unreadable: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e == "yml" || e == "yaml")
        })
        .collect();
    paths.sort();
    let mut out: Vec<(String, String)> = Vec::new();
    for path in paths {
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let src = std::fs::read_to_string(&path).map_err(|e| {
            format!(
                "required-contexts-are-produced: {} is unreadable: {e}",
                path.display()
            )
        })?;
        out.push((name, src));
    }
    if out.is_empty() {
        return Err(String::from(
            "required-contexts-are-produced: no workflow files found. A check that examines nothing \
             reports OK, which is the failure this gate exists for.",
        ));
    }
    Ok(out)
}

pub fn run(root: &Path) -> Result<String, String> {
    let claim_path = root.join(CLAIM_PATH);
    let text = std::fs::read_to_string(&claim_path).map_err(|e| {
        format!(
            "required-contexts-are-produced: {} is unreadable ({e}). The list of contexts branch \
             protection requires is the input; without it this gate would be checking nothing.",
            claim_path.display()
        )
    })?;
    let claims = parse_claims(&text)?;
    let workflows = read_workflows(root)?;
    let mut findings: Vec<String> = Vec::new();
    for claim in &claims {
        findings.extend(findings_for(claim, &workflows));
    }
    if !findings.is_empty() {
        return Err(format!(
            "required-contexts-are-produced: {} finding(s):\n  - {}",
            findings.len(),
            findings.join("\n  - ")
        ));
    }
    Ok(format!(
        "required-contexts-are-produced OK: {} required context(s) each produced by a job that \
         reports on pull requests into the branch it protects, across {} workflow file(s)",
        claims.len(),
        workflows.len()
    ))
}

pub fn self_test() -> Result<String, String> {
    let happy = (
        String::from("merge-gate.yml"),
        String::from(
            "on:\n  pull_request:\n    branches: [consensus-of-consensuses]\njobs:\n  gate:\n    \
             name: merge-block-default-branch\n    runs-on: ubuntu-latest\n",
        ),
    );
    let claim = Claim {
        context: String::from("merge-block-default-branch"),
        branch: String::from("consensus-of-consensuses"),
    };

    // The declarative case must hold, or the gate is a wall.
    if !findings_for(&claim, std::slice::from_ref(&happy)).is_empty() {
        return Err(String::from(
            "canary: a context produced on the protected branch must pass",
        ));
    }

    // A context no job names: the failure this gate was written for.
    let orphan = Claim {
        context: String::from("some-check-nobody-produces"),
        branch: String::from("consensus-of-consensuses"),
    };
    let orphan_findings = findings_for(&orphan, std::slice::from_ref(&happy));
    if orphan_findings.len() != 1 || !orphan_findings[0].contains("no workflow declares a job") {
        return Err(format!(
            "canary: a required context no job names must be reported, got {orphan_findings:?}"
        ));
    }

    // A job that exists in a workflow that does not fire on the branch.
    let wrong_trigger = (
        String::from("elsewhere.yml"),
        String::from(
            "on:\n  pull_request:\n    branches: [main]\njobs:\n  gate:\n    \
             name: merge-block-default-branch\n    runs-on: ubuntu-latest\n",
        ),
    );
    let misdirected = findings_for(&claim, &[wrong_trigger]);
    if misdirected.len() != 1 || !misdirected[0].contains("triggers on") {
        return Err(format!(
            "canary: a producer that does not fire on the branch must be reported, got \
             {misdirected:?}"
        ));
    }

    // A job key, not a job `name:`, also produces the context.
    let by_key = (
        String::from("merge-gate.yml"),
        String::from(
            "on:\n  pull_request:\njobs:\n  merge-block-default-branch:\n    runs-on: \
             ubuntu-latest\n    steps:\n      - name: merge-block-default-branch\n        run: \
             true\n",
        ),
    );
    if !findings_for(&claim, &[by_key]).is_empty() {
        return Err(String::from(
            "canary: a job key produces the context name and must be read",
        ));
    }

    // A step name is not a job name and must not count.
    let step_only = (
        String::from("steps.yml"),
        String::from(
            "on:\n  pull_request:\njobs:\n  other:\n    runs-on: ubuntu-latest\n    steps:\n      - \
             name: merge-block-default-branch\n        run: true\n",
        ),
    );
    if findings_for(&claim, &[step_only]).is_empty() {
        return Err(String::from(
            "canary: a step name must not be read as a status context",
        ));
    }

    // An unreadable claim shape is refused, not guessed.
    if parse_claims("merge-block-default-branch\n").is_ok() {
        return Err(String::from("canary: a claim without a branch must be refused"));
    }
    if parse_claims("# empty\n\n").is_ok() {
        return Err(String::from("canary: an empty claim file must be refused"));
    }

    Ok(String::from(
        "required-contexts-are-produced canary OK (a context no job declares and a producer that \
         does not fire on the protected branch are both reported; a job key and a job name are \
         both read; a step name, a claim without a branch and an empty claim file are refused).",
    ))
}
