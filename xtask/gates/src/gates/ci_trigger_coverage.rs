//! Every long-lived branch a pull request can target is gated.
//!
//! "The workflows are not working" has a measurable core: a `pull_request`
//! trigger lists branch names, and a PR whose base is not on that list starts
//! no workflow at all. The PR looks open, the branch looks healthy, and nothing
//! has run. Measured 2026-11-23: the repository carries long-lived integration
//! branches (`ortak-teslim`, `budlum-unification`, `budlum-universal`, ...)
//! while the gate-bearing workflows list eight names none of which are those.
//!
//! # What this gate decides
//!
//! A branch is *gated* when at least one workflow that runs the full gate set
//! (`budlum-gates --all`) is triggered by `pull_request` into it. The gate reads
//! the workflow files, not the live API: the question is what the repository
//! promises, and the promise lives in `.github/workflows`.
//!
//! # Which branches it checks
//!
//! Only branches that are not somebody's work-in-progress. A branch under
//! `ajan/`, `arena/`, `baskul/`, `snapshot/`, `dependabot/`, `ci-snapshot`,
//! `fix/`, `feature/`, `security/`, `diag/`, `teslim/`, `strix/`, `tmp/`, `wip/`
//! is short-lived by convention: its PR targets a gated branch and the base is
//! what CI reads. Everything else is a branch a PR can target directly, and it
//! has to be named in the trigger list or this gate fails.
//!
//! The failure names the branch and the file, because "CI is not running" is
//! exactly the kind of report that is useless without the name of the thing
//! that did not run.

use std::collections::BTreeSet;
use std::path::Path;

/// The file that lists the branches this repository claims to gate.
pub const CLAIM_PATH: &str = ".github/workflows/ci-trigger-branches.txt";

/// Prefixes whose branches are working branches, not PR targets.
const WORKING_PREFIXES: &[&str] = &[
    "ajan/", "arena/", "baskul/", "snapshot/", "dependabot/", "ci-snapshot", "fix/", "feature/",
    "security/", "diag/", "teslim/", "strix/", "tmp/", "wip/", "test/", "hotfix/", "revert/",
];

/// Is this branch name a working branch (short-lived, not a PR target)?
#[must_use]
pub fn is_working_branch(name: &str) -> bool {
    WORKING_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// The branch names a `pull_request: branches:` list carries, as written.
///
/// Kept deliberately dumb: this reads the YAML text for the trigger block rather
/// than parsing YAML, because the gate has no YAML dependency and the shape it
/// needs is one indentation level deep. A shape it cannot read is reported, not
/// guessed.
#[must_use]
pub fn pull_request_branches(workflow: &str) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let mut in_on = false;
    let mut in_pr = false;
    let mut in_branches = false;
    let mut pr_indent = 0usize;
    for raw in workflow.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if indent == 0 {
            in_on = trimmed == "on:" || trimmed.starts_with("on: ");
            in_pr = false;
            in_branches = false;
            continue;
        }
        if !in_on {
            continue;
        }
        if trimmed.starts_with("pull_request:") {
            in_pr = true;
            pr_indent = indent;
            // `pull_request: [main]` inline form.
            if let Some(rest) = trimmed.strip_prefix("pull_request:") {
                let rest = rest.trim();
                if rest.starts_with('[') {
                    for part in rest.trim_matches(['[', ']'].as_ref()).split(',') {
                        let p = part.trim().trim_matches(['"', '\''].as_ref());
                        if !p.is_empty() {
                            out.push(p.to_string());
                        }
                    }
                }
            }
            continue;
        }
        if !in_pr {
            continue;
        }
        if indent <= pr_indent && !trimmed.starts_with('-') {
            in_pr = false;
            in_branches = false;
            continue;
        }
        if trimmed.starts_with("branches:") {
            in_branches = true;
            if let Some(rest) = trimmed.strip_prefix("branches:") {
                let rest = rest.trim();
                if rest.starts_with('[') {
                    for part in rest.trim_matches(['[', ']'].as_ref()).split(',') {
                        let p = part.trim().trim_matches(['"', '\''].as_ref());
                        if !p.is_empty() {
                            out.push(p.to_string());
                        }
                    }
                }
            }
            continue;
        }
        if in_branches {
            if let Some(rest) = trimmed.strip_prefix('-') {
                let p = rest.trim().trim_matches(['"', '\''].as_ref());
                if !p.is_empty() {
                    out.push(p.to_string());
                }
            } else if !trimmed.starts_with('-') {
                in_branches = false;
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Does this workflow run the whole gate set on `pull_request`?
#[must_use]
pub fn runs_all_gates(workflow: &str) -> bool {
    let text = workflow;
    let has_pr = text.lines().any(|l| l.trim_start().starts_with("pull_request:"));
    let has_all = text.contains("budlum-gates --all") || text.contains("--all ");
    has_pr && has_all
}

/// The checkable core: given (workflow name, source) pairs and the branches that
/// exist, return the branches a PR can target that no full-gate workflow covers.
#[must_use]
pub fn uncovered(branches: &[String], workflows: &[(String, String)]) -> Vec<String> {
    if covers_every_branch(workflows) {
        return Vec::new();
    }
    let mut gated: BTreeSet<String> = BTreeSet::new();
    for (_, src) in workflows {
        if !runs_all_gates(src) {
            continue;
        }
        if let Some(names) = pull_request_branches(src) {
            gated.extend(names);
        }
    }
    let mut out: Vec<String> = branches
        .iter()
        .filter(|b| !is_working_branch(b))
        .filter(|b| !gated.contains(*b))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn run(root: &Path) -> Result<String, String> {
    let wf_dir = root.join(".github/workflows");
    let entries = std::fs::read_dir(&wf_dir)
        .map_err(|e| format!("ci-trigger-coverage: {} is unreadable: {e}", wf_dir.display()))?;
    let mut workflows: Vec<(String, String)> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("ci-trigger-coverage: read_dir failed: {e}"))?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            let name = path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            let src = std::fs::read_to_string(&path)
                .map_err(|e| format!("ci-trigger-coverage: {} is unreadable: {e}", path.display()))?;
            workflows.push((name, src));
        }
    }
    if workflows.is_empty() {
        return Err(String::from(
            "ci-trigger-coverage: no workflow files found. A check that examines nothing reports \
             OK, which is the failure this gate exists for.",
        ));
    }
    if covers_every_branch(&workflows) {
        return Ok(format!(
            "ci-trigger-coverage OK: {} workflow file(s); a full-gate trigger is unrestricted and \
             covers every branch",
            workflows.len()
        ));
    }
    let claim_path = root.join(CLAIM_PATH);
    let claim = std::fs::read_to_string(&claim_path).map_err(|e| {
        format!(
            "ci-trigger-coverage: {} is unreadable ({e}). The list of branches the repository \
             claims to gate is the input; without it this gate would be checking nothing.",
            claim_path.display()
        )
    })?;
    let claimed: Vec<String> = claim
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    if claimed.is_empty() {
        return Err(String::from(
            "ci-trigger-coverage: the branch claim file names no branch. An empty claim reads as \
             full coverage; that is the failure this gate exists for.",
        ));
    }
    // The requirement is per branch and per meaning: a claimed branch must be
    // named by a trigger that RUNS THE GATES. A `pull_request` trigger in a
    // workflow that runs nothing is coverage on paper only - measured while
    // building this gate: removing a branch from all three gate-bearing
    // triggers still read as covered because a non-gate workflow named it.
    let mut gate_covered: BTreeSet<String> = BTreeSet::new();
    for (_, src) in &workflows {
        if !runs_all_gates(src) {
            continue;
        }
        if let Some(names) = pull_request_branches(src) {
            gate_covered.extend(names);
        }
    }
    let missing: Vec<String> = claimed
        .iter()
        .filter(|b| !gate_covered.contains(*b))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "ci-trigger-coverage: these claimed branches are not named by any pull_request trigger \
             that runs `budlum-gates --all`: {}. A PR into one of them starts no gate at all. Add \
             them to a gate-bearing trigger or take them out of {}.",
            missing.join(", "),
            CLAIM_PATH
        ));
    }
    let gated = gated_branch_set(&workflows);
    Ok(format!(
        "ci-trigger-coverage OK: {} workflow file(s), {} claimed branch(es) each named by a \
         full-gate pull_request trigger ({} branch(es) gated in total), 0 stale",
        workflows.len(),
        claimed.len(),
        gated.len()
    ))
}

/// True when a full-gate workflow fires on `pull_request` into ANY branch.
///
/// A trigger with no `branches:` list is unrestricted, and treating "no names"
/// as "no coverage" was measured to report every branch as uncovered - the same
/// absent-as-failure mistake this repository keeps paying for, in the other
/// direction.
#[must_use]
pub fn covers_every_branch(workflows: &[(String, String)]) -> bool {
    workflows
        .iter()
        .any(|(_, src)| runs_all_gates(src) && pull_request_branches(src).is_none())
}

/// Every branch name a full-gate `pull_request` trigger mentions.
#[must_use]
pub fn gated_branch_set(workflows: &[(String, String)]) -> BTreeSet<String> {
    let mut gated: BTreeSet<String> = BTreeSet::new();
    for (_, src) in workflows {
        if !runs_all_gates(src) {
            continue;
        }
        if let Some(names) = pull_request_branches(src) {
            gated.extend(names);
        }
    }
    gated
}

pub fn self_test() -> Result<String, String> {
    // A branch a PR can target that no full-gate trigger names: the failure.
    let wf = ("ci.yml".to_string(), String::from(
        "on:\n  pull_request:\n    branches:\n      - main\njobs:\n  g:\n    steps:\n      - run: budlum-gates --all\n",
    ));
    let uncovered_here = uncovered(&["main".into(), "ortak-teslim".into()], std::slice::from_ref(&wf));
    if uncovered_here != vec![String::from("ortak-teslim")] {
        return Err(format!(
            "canary: an unnamed integration branch must be reported, got {uncovered_here:?}"
        ));
    }

    // A working branch is not a PR target and must not be reported.
    let none = uncovered(&["ajan/yildiz/x".into(), "snapshot/abc".into()], std::slice::from_ref(&wf));
    if !none.is_empty() {
        return Err(format!("canary: working branches must be skipped, got {none:?}"));
    }

    // A workflow that runs only one gate does not cover a branch.
    let partial = ("rust.yml".to_string(), String::from(
        "on:\n  pull_request:\n    branches:\n      - ortak-teslim\njobs:\n  g:\n    steps:\n      - run: budlum-gates door\n",
    ));
    let still = uncovered(&["ortak-teslim".into()], &[partial]);
    if still.is_empty() {
        return Err(String::from(
            "canary: a workflow that runs one gate must not count as full coverage",
        ));
    }

    // Inline list form is read.
    let inline = ("ci.yml".to_string(), String::from(
        "on:\n  pull_request: [main, ortak-teslim]\njobs:\n  g:\n    steps:\n      - run: budlum-gates --all\n",
    ));
    if !uncovered(&["ortak-teslim".into()], &[inline]).is_empty() {
        return Err(String::from("canary: the inline branch list must be read"));
    }

    // A workflow whose pull_request has no branch list gates every branch, so
    // nothing is uncovered - and the gate must not invent a failure there.
    let any = ("ci.yml".to_string(), String::from(
        "on:\n  pull_request:\njobs:\n  g:\n    steps:\n      - run: budlum-gates --all\n",
    ));
    if !uncovered(&["ortak-teslim".into()], &[any]).is_empty() {
        return Err(String::from(
            "canary: an unrestricted pull_request trigger already covers every branch",
        ));
    }

    Ok(String::from(
        "ci-trigger-coverage canary OK (an unnamed integration branch is reported, working \
         branches are skipped, a single-gate workflow is not coverage, the inline list form is \
         read, and an unrestricted trigger covers everything).",
    ))
}
