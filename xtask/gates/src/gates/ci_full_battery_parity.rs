//! A branch promised the full battery is not quietly given a smaller one.
//!
//! # The failure this gate closes
//!
//! [`super::ci_trigger_coverage`] answers one question: does any workflow
//! *start* for a pull request into this branch. It reads triggers. A job
//! inside a started workflow can still decide not to run, and GitHub reports
//! that decision as a `skipped` check - which a required-status-check rule
//! treats as satisfied and a reviewer reads as green.
//!
//! Measured 2026-11-27 on the live repository. Two pull requests, stacked:
//! `slice -> testnet-50` and `testnet-50 -> consensus-of-consensuses`. The
//! upper one produced 112 check runs; the lower one produced 106, and eight
//! of the jobs it did show were `skipped`:
//!
//! | job | workflow |
//! |---|---|
//! | `Auditable + Audit (binary SBOM + CVE)` | `extra-tooling.yml` |
//! | `Dead Deps (machete + shear)` | `extra-tooling.yml` |
//! | `Binary Size (rapor)` | `extra-tooling.yml` |
//! | `Config Lint (taplo)` | `extra-tooling.yml` |
//! | `Kani Proofs (bond arithmetic)` | `extra-tooling.yml` |
//! | `Udeps: the unused dependency gate` | `supply-chain-extra.yml` |
//! | `Geiger: unsafe visibility` | `supply-chain-extra.yml` |
//! | `Semver Check (public API breakage gate)` | `semver.yml` |
//!
//! Every one of them carried the same job-level condition:
//! `contains(fromJSON('["main","consensus-of-consensuses"]'),
//! github.event.pull_request.base.ref)`. In a stacked pull request the
//! `branches:` filter is evaluated against the root of the stack, so the
//! workflow starts for the lower pull request too; the job-level condition
//! then sees the *immediate* base and skips. `testnet-50` carried no required
//! status check at all, so nothing downstream noticed.
//!
//! # What this gate decides
//!
//! `.github/workflows/ci-full-battery-branches.txt` is the repository's
//! promise about which bases get everything. For each name in it:
//!
//! 1. every job-level base-ref allowlist in `.github/workflows` admits it, and
//! 2. every workflow carrying such an allowlist names it in its
//!    `pull_request:` trigger - a job that admits a base is still not run if
//!    the workflow never starts for it.
//!
//! The promise is also required to be a subset of the trigger claim in
//! `ci-trigger-branches.txt`: a branch cannot be given everything while not
//! being gated at all.
//!
//! Fail-closed in both directions. A missing or empty promise file is a
//! failure, not full coverage: an empty promise cannot be violated, and a
//! check that cannot be violated measures nothing.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// The file that names the branches promised the full battery.
pub const PROMISE_PATH: &str = ".github/workflows/ci-full-battery-branches.txt";

/// The file that names the branches the repository claims to gate at all.
pub const CLAIM_PATH: &str = ".github/workflows/ci-trigger-branches.txt";

/// The expression fragments that mean "the base branch of this pull request".
const BASE_REF_MARKERS: &[&str] = &[
    "pull_request.base.ref",
    "github.base_ref",
    "env.PR_BASE_REF",
];

/// A job whose `if:` decides on the pull request's base branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRefJob {
    /// The job id as written under `jobs:`.
    pub id: String,
    /// The branch names the condition mentions.
    pub names: Vec<String>,
    /// `true` when the names are the branches that RUN (an allowlist),
    /// `false` when they are the branches that are EXCLUDED (a denylist built
    /// from `!=` comparisons).
    pub is_allowlist: bool,
}

impl BaseRefJob {
    /// Does this job run for a pull request whose base is `branch`?
    #[must_use]
    pub fn admits(&self, branch: &str) -> bool {
        let named = self.names.iter().any(|n| n == branch);
        if self.is_allowlist {
            named
        } else {
            !named
        }
    }
}

/// Strip a comment that starts outside of any quoted string.
fn without_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut single = false;
    let mut double = false;
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !double => single = !single,
            b'"' if !single => double = !double,
            b'#' if !single && !double => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Every single-quoted and double-quoted literal in an expression, in order.
fn quoted_literals(expr: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut rest = expr;
    while let Some(start) = rest.find(['\'', '"']) {
        let quote = rest.as_bytes()[start];
        let after = &rest[start + 1..];
        let Some(end) = after.find(quote as char) else {
            break;
        };
        let literal = &after[..end];
        if !literal.is_empty() {
            out.push(literal.to_string());
        }
        rest = &after[end + 1..];
    }
    out
}

/// The branch names a `fromJSON('[...]')` array literal carries.
fn from_json_names(expr: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for chunk in expr.split("fromJSON(").skip(1) {
        // The argument is a quoted JSON array; take it up to the closing
        // quote of whichever quote style opened it.
        let arg = chunk.trim_start();
        let Some(quote) = arg.chars().next() else {
            continue;
        };
        if quote != '\'' && quote != '"' {
            continue;
        }
        let body = &arg[1..];
        let Some(end) = body.find(quote) else {
            continue;
        };
        let json = &body[..end];
        for part in json.trim().trim_matches(['[', ']'].as_ref()).split(',') {
            let name = part.trim().trim_matches(['"', '\''].as_ref());
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// Read the jobs of one workflow whose `if:` decides on the base branch.
///
/// Deliberately line-based, like [`super::ci_trigger_coverage`]: this crate
/// carries no YAML parser, and the shape needed here is two indentation levels
/// deep. A shape that cannot be read is reported by the caller as "no job",
/// never guessed into coverage, because the tests in
/// `xtask/gates/tests/full_battery_parity.rs` check the same files by a second,
/// independent route.
#[must_use]
pub fn jobs_with_base_ref_allowlist(workflow: &str) -> Vec<BaseRefJob> {
    let mut out: Vec<BaseRefJob> = Vec::new();
    let mut in_jobs = false;
    let mut current: Option<String> = None;
    let mut job_indent = 0usize;
    for raw in workflow.lines() {
        let line = without_comment(raw).trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - trimmed.len();
        if indent == 0 {
            in_jobs = trimmed == "jobs:";
            current = None;
            continue;
        }
        if !in_jobs {
            continue;
        }
        // A job id is the first nesting level under `jobs:`.
        if current.is_none() || indent <= job_indent {
            if let Some(id) = trimmed.strip_suffix(':') {
                if !id.is_empty() && !id.contains(' ') {
                    current = Some(id.to_string());
                    job_indent = indent;
                    continue;
                }
            }
        }
        let Some(id) = current.clone() else {
            continue;
        };
        if indent <= job_indent {
            continue;
        }
        let Some(expr) = trimmed.strip_prefix("if:") else {
            continue;
        };
        if !BASE_REF_MARKERS.iter().any(|m| expr.contains(m)) {
            continue;
        }
        let names = from_json_names(expr);
        if !names.is_empty() {
            out.push(BaseRefJob {
                id,
                names,
                is_allowlist: true,
            });
            continue;
        }
        // No array literal: an `== '<name>'` chain is an allowlist, a
        // `!= '<name>'` chain is a denylist. A condition that mixes the two is
        // not modelled, and an unmodelled condition is reported as admitting
        // nothing so it cannot pass unexamined.
        let has_eq = expr.contains("==");
        let has_ne = expr.contains("!=");
        let literals = quoted_literals(expr);
        if literals.is_empty() {
            continue;
        }
        if has_eq && !has_ne {
            out.push(BaseRefJob {
                id,
                names: literals,
                is_allowlist: true,
            });
        } else if has_ne && !has_eq {
            out.push(BaseRefJob {
                id,
                names: literals,
                is_allowlist: false,
            });
        } else {
            out.push(BaseRefJob {
                id,
                names: Vec::new(),
                is_allowlist: true,
            });
        }
    }
    out
}

/// Names from a newline list file, comments and blanks dropped.
fn list_file(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// One finding: a promised branch a job or a trigger leaves out.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gap {
    pub workflow: String,
    pub job: String,
    pub branch: String,
    pub reason: &'static str,
}

/// The checkable core: promised branches against workflow sources.
#[must_use]
pub fn gaps(promised: &[String], workflows: &[(String, String)]) -> Vec<Gap> {
    let mut out: Vec<Gap> = Vec::new();
    for (file, src) in workflows {
        let jobs = jobs_with_base_ref_allowlist(src);
        if jobs.is_empty() {
            continue;
        }
        let triggered = super::ci_trigger_coverage::pull_request_branches(src);
        for branch in promised {
            if let Some(names) = triggered.as_ref() {
                if !names.iter().any(|n| n == branch) {
                    out.push(Gap {
                        workflow: file.clone(),
                        job: String::from("<trigger>"),
                        branch: branch.clone(),
                        reason: "the pull_request trigger does not name this base, so the \
                                 base-ref gated jobs below it never start for it",
                    });
                }
            }
            for job in &jobs {
                if !job.admits(branch) {
                    out.push(Gap {
                        workflow: file.clone(),
                        job: job.id.clone(),
                        branch: branch.clone(),
                        reason: "the job condition skips this base; GitHub reports the skip as a \
                                 passing check",
                    });
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Read `.github/workflows`, sorted, failing closed on an empty directory.
fn read_workflows(root: &Path) -> Result<Vec<(String, String)>, String> {
    let wf_dir = root.join(".github/workflows");
    let entries = std::fs::read_dir(&wf_dir).map_err(|e| {
        format!(
            "ci-full-battery-parity: {} is unreadable: {e}",
            wf_dir.display()
        )
    })?;
    let mut workflows: Vec<(String, String)> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("ci-full-battery-parity: read_dir failed: {e}"))?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            let name = path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            let src = std::fs::read_to_string(&path).map_err(|e| {
                format!(
                    "ci-full-battery-parity: {} is unreadable: {e}",
                    path.display()
                )
            })?;
            workflows.push((name, src));
        }
    }
    if workflows.is_empty() {
        return Err(String::from(
            "ci-full-battery-parity: no workflow files found. A check that examines nothing \
             reports OK, which is the failure this gate exists for.",
        ));
    }
    workflows.sort();
    Ok(workflows)
}

/// A branch cannot be promised everything while no workflow is required to
/// start for it, so the promise has to be a subset of the trigger claim.
fn promise_is_inside_the_claim(root: &Path, promised: &[String]) -> Result<(), String> {
    let claim_path = root.join(CLAIM_PATH);
    let claim = std::fs::read_to_string(&claim_path).map_err(|e| {
        format!(
            "ci-full-battery-parity: {} is unreadable ({e}).",
            claim_path.display()
        )
    })?;
    let claimed: BTreeSet<String> = list_file(&claim).into_iter().collect();
    let unclaimed: Vec<&String> = promised.iter().filter(|b| !claimed.contains(*b)).collect();
    if unclaimed.is_empty() {
        return Ok(());
    }
    Err(format!(
        "ci-full-battery-parity: {unclaimed:?} are promised the full battery but are not claimed \
         as gated at all in {CLAIM_PATH}. A branch cannot be given everything while no workflow \
         is required to start for it."
    ))
}

/// The finding, one line per branch/job pair, named so the reader can go to it.
fn report(found: &[Gap]) -> String {
    let mut msg = format!(
        "ci-full-battery-parity: {} branch/job pair(s) are promised the full battery and do not \
         get it:\n",
        found.len()
    );
    for g in found {
        let _ = writeln!(
            msg,
            "  - {} job `{}` base `{}`: {}",
            g.workflow, g.job, g.branch, g.reason
        );
    }
    msg.push_str(
        "Either admit the base in the condition and the trigger, or take the branch out of ",
    );
    msg.push_str(PROMISE_PATH);
    msg.push('.');
    msg
}

pub fn run(root: &Path) -> Result<String, String> {
    let promise_path = root.join(PROMISE_PATH);
    let promise = std::fs::read_to_string(&promise_path).map_err(|e| {
        format!(
            "ci-full-battery-parity: {} is unreadable ({e}). The list of branches promised the \
             full battery is the input; without it this gate would be checking nothing, which is \
             the failure it exists for.",
            promise_path.display()
        )
    })?;
    let promised = list_file(&promise);
    if promised.is_empty() {
        return Err(format!(
            "ci-full-battery-parity: {PROMISE_PATH} names no branch. An empty promise cannot be \
             violated and so measures nothing."
        ));
    }

    promise_is_inside_the_claim(root, &promised)?;

    let workflows = read_workflows(root)?;

    let gated_jobs: usize = workflows
        .iter()
        .map(|(_, s)| jobs_with_base_ref_allowlist(s).len())
        .sum();
    if gated_jobs == 0 {
        return Err(String::from(
            "ci-full-battery-parity: no job-level base-ref condition was found in any workflow. \
             The condition this gate measures was present when it was written; finding none means \
             the reader is broken or the conditions moved, and either way the gate is no longer \
             measuring what it claims.",
        ));
    }

    let found = gaps(&promised, &workflows);
    if !found.is_empty() {
        return Err(report(&found));
    }

    Ok(format!(
        "ci-full-battery-parity OK: {} workflow file(s), {} base-ref gated job(s), {} promised \
         branch(es) ({}) admitted by every condition and named by every trigger",
        workflows.len(),
        gated_jobs,
        promised.len(),
        promised.join(", ")
    ))
}

/// The edge canaries: a `!=` denylist, a job with no base-ref condition,
/// and a `#` inside quotes. Separate so neither half grows past the length
/// the lint allows and neither can be deleted without the other noticing.
fn canary_edges() -> Result<(), String> {
    // A `!=` condition is a denylist, and the excluded name is the gap.
    let denylist = (
        "x.yml".to_string(),
        String::from(
            "on:\n  pull_request:\njobs:\n  j:\n    if: ${{ github.base_ref != 'testnet-50' \
             }}\n    name: J\n",
        ),
    );
    let deny = gaps(
        &[String::from("main"), String::from("testnet-50")],
        std::slice::from_ref(&denylist),
    );
    if deny.len() != 1 || deny[0].branch != "testnet-50" {
        return Err(format!(
            "canary: a `!=` denylist must report the excluded base and only it, got {deny:?}"
        ));
    }

    // A job without a base-ref condition is not this gate's business, and a
    // workflow made only of those must produce no finding at all.
    let plain = (
        "typos.yml".to_string(),
        String::from(
            "on:\n  pull_request:\n    branches: [main]\njobs:\n  typos:\n    name: Typos\n",
        ),
    );
    if !gaps(&[String::from("testnet-50")], std::slice::from_ref(&plain)).is_empty() {
        return Err(String::from(
            "canary: a workflow with no base-ref gated job must produce no finding",
        ));
    }

    // A `#` inside a quoted expression is not a comment.
    let hashed = jobs_with_base_ref_allowlist(
        "jobs:\n  j:\n    if: ${{ contains(fromJSON('[\"re#lease\"]'), github.base_ref) }}\n",
    );
    if hashed.len() != 1 || hashed[0].names != vec![String::from("re#lease")] {
        return Err(format!(
            "canary: a `#` inside quotes must not be read as a comment, got {hashed:?}"
        ));
    }

    Ok(())
}

pub fn self_test() -> Result<String, String> {
    // The measured shape: a job allowlist that leaves out a promised base.
    let skipping = (
        "extra-tooling.yml".to_string(),
        String::from(
            "on:\n  pull_request:\n    branches: [main, testnet-50]\njobs:\n  kani-proofs:\n    \
             if: ${{ github.event_name != 'pull_request' || \
             contains(fromJSON('[\"main\"]'), github.event.pull_request.base.ref) }}\n    \
             name: Kani Proofs\n",
        ),
    );
    let found = gaps(
        &[String::from("main"), String::from("testnet-50")],
        std::slice::from_ref(&skipping),
    );
    if found.len() != 1 || found[0].job != "kani-proofs" || found[0].branch != "testnet-50" {
        return Err(format!(
            "canary: a job allowlist that leaves out a promised base must be reported once, got \
             {found:?}"
        ));
    }

    // The same file once the base is admitted: no finding.
    let fixed = (
        "extra-tooling.yml".to_string(),
        String::from(
            "on:\n  pull_request:\n    branches: [main, testnet-50]\njobs:\n  kani-proofs:\n    \
             if: ${{ github.event_name != 'pull_request' || \
             contains(fromJSON('[\"main\",\"testnet-50\"]'), github.event.pull_request.base.ref) \
             }}\n    name: Kani Proofs\n",
        ),
    );
    let none = gaps(
        &[String::from("main"), String::from("testnet-50")],
        std::slice::from_ref(&fixed),
    );
    if !none.is_empty() {
        return Err(format!(
            "canary: an admitted base must produce no finding, got {none:?}"
        ));
    }

    // A condition that admits the base but a trigger that does not name it is
    // still a gap: the workflow never starts, so the job never runs.
    let untriggered = (
        "semver.yml".to_string(),
        String::from(
            "on:\n  pull_request:\n    branches: [main]\njobs:\n  semver-check:\n    if: ${{ \
             contains(fromJSON('[\"main\",\"testnet-50\"]'), github.event.pull_request.base.ref) \
             }}\n    name: Semver Check\n",
        ),
    );
    let trigger_gap = gaps(
        &[String::from("testnet-50")],
        std::slice::from_ref(&untriggered),
    );
    if trigger_gap.len() != 1 || trigger_gap[0].job != "<trigger>" {
        return Err(format!(
            "canary: a base the trigger does not name must be reported, got {trigger_gap:?}"
        ));
    }

    // An unrestricted trigger covers every base, and the gate must not invent
    // a trigger finding there.
    let unrestricted = (
        "native-security-review.yml".to_string(),
        String::from(
            "on:\n  pull_request:\njobs:\n  review:\n    if: ${{ \
             contains(fromJSON('[\"main\",\"testnet-50\"]'), github.event.pull_request.base.ref) \
             }}\n    name: Review\n",
        ),
    );
    if !gaps(
        &[String::from("testnet-50")],
        std::slice::from_ref(&unrestricted),
    )
    .is_empty()
    {
        return Err(String::from(
            "canary: an unrestricted pull_request trigger already starts for every base",
        ));
    }

    canary_edges()?;

    Ok(String::from(
        "ci-full-battery-parity canary OK (a job allowlist that leaves out a promised base is \
         reported, an admitted base is not, a trigger that does not name the base is reported, an \
         unrestricted trigger is not, a `!=` denylist reports the excluded base, a job with no \
         base-ref condition is ignored, and a `#` inside quotes is not a comment).",
    ))
}
