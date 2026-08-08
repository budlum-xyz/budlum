//! A security scan that cannot fail is a report, and it is filed as a gate.
//!
//! # What was measured
//!
//! Twenty-four places across the workflows soften a check: `continue-on-error`
//! on a job or step, or `|| true` on the command that does the work. Some are
//! right. A benchmark that prints a number, a size report, a teardown step
//! that must run whatever happened before it: none of those should stop a
//! merge.
//!
//! Five are not right, and they are all in the two files named for security:
//!
//!   zizmor          GitHub Actions static analysis, the tool that finds the
//!                   pwn-request and cache-poisoning shapes
//!   cargo-hack      feature matrix, which is how a feature combination that
//!                   does not compile reaches main
//!   mutants         mutation testing, the only check that measures whether
//!                   the tests would notice a change
//!   supply-chain    publisher visibility
//!   tsan            `ThreadSanitizer`, data race detection
//!
//! `tsan` carries both softeners at once: `continue-on-error: true` on the job
//! and `|| true` on the command. It cannot fail under any circumstance, and it
//! has no canary, so nothing distinguishes "no data races" from "the binary
//! never ran".
//!
//! For a chain, a data race is not a flaky test. Two nodes disagreeing about
//! state because of one is a fork.
//!
//! # What this gate does, and what it does not
//!
//! It does not demand every softener be removed. Some scans are genuinely
//! informational and some are too slow or too noisy to block on today, and
//! saying otherwise would be a rule nobody could follow.
//!
//! It demands that each one is *listed*, with a reason, in this file. A
//! softener that appears in a workflow and not here fails, and an entry here
//! matching no softener fails too, so the list cannot outlive what it
//! describes. That is the same shape as `PENDING_REVIEW` in the capability
//! gate, for the same reason: a suppression nobody can audit is worse than the
//! finding it hides.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// A softened check, and why it is allowed to be soft.
struct Allowed {
    /// Workflow file name.
    file: &'static str,
    /// Job id or the step name it appears under.
    what: &'static str,
    /// Why this one does not block, in a sentence somebody can disagree with.
    reason: &'static str,
}

/// Every softener in the tree, with its justification.
///
/// Measured, not typed: the gate refuses an entry that matches nothing.
const ALLOWED: &[Allowed] = &[
    Allowed {
        file: "security-audit.yml",
        what: "zizmor",
        reason: "the workflow static analyser reports findings the tree has not \
                 triaged; the pinning and permission rules it would catch are \
                 enforced by workflows-produce-jobs, which does block",
    },
    Allowed {
        file: "ci.yml",
        what: "budlum",
        reason: "clippy pedantic/nursery ratchet reports a count against a baseline; \
                 the baseline itself is enforced elsewhere and blocks",
    },
    Allowed {
        file: "ci.yml",
        what: "poa-isolation",
        reason: "the tests block; the softened line collects output for the summary",
    },
    Allowed {
        file: "ci.yml",
        what: "license-compliance",
        reason: "inventory listing for the job summary; the licence gate itself blocks",
    },
    Allowed {
        file: "determinism.yml",
        what: "cross-platform-determinism",
        reason: "collects the existing suite's output; determinism is asserted by the \
                 comparison step that follows and does block",
    },
    Allowed {
        file: "docker-smoke.yml",
        what: "devnet-multinode-smoke",
        reason: "compose teardown must run whatever happened before it, and the smoke \
                 assertions block separately",
    },
    Allowed {
        file: "extra-tooling.yml",
        what: "dead-deps",
        reason: "cargo-shear is a second opinion beside cargo-machete, which blocks",
    },
    Allowed {
        file: "extra-tooling.yml",
        what: "binary-size",
        reason: "size report for the PR summary; no threshold has been measured, so \
                 there is nothing to fail against yet",
    },
    Allowed {
        file: "fuzz-nightly.yml",
        what: "fuzz-deep",
        reason: "artefact upload runs only when a crash exists; the fuzz run blocks",
    },
    Allowed {
        file: "miri.yml",
        what: "asan",
        reason: "the canary deliberately runs a program with a memory error, so that \
                 command is expected to exit non-zero; the decision is made by the grep \
                 that follows and the sanitizer run itself blocks",
    },
    Allowed {
        file: "miri.yml",
        what: "miri-crypto",
        reason: "the storage module under Miri is slow and not yet clean; the crypto \
                 module is the one that blocks",
    },
    Allowed {
        file: "security-audit.yml",
        what: "cargo-hack",
        reason: "feature-matrix build; the matrix is large and its failures have not \
                 been triaged, so blocking would stop every PR on a known backlog",
    },
    Allowed {
        file: "security-hardening.yml",
        what: "machete",
        reason: "root-tree machete duplicates the blocking run in extra-tooling.yml",
    },
    Allowed {
        file: "security-hardening.yml",
        what: "mutants",
        reason: "mutation testing over the whole tree does not finish in a PR budget; \
                 it runs to a five-minute timeout and reports",
    },
    Allowed {
        file: "security-hardening.yml",
        what: "supply-chain",
        reason: "publisher visibility is a listing of who can push a crate; there is \
                 no threshold to fail against",
    },
    Allowed {
        file: "semver.yml",
        what: "semver-check",
        reason: "the diagnostic step records evidence; the semver gate blocks",
    },
    Allowed {
        file: "supply-chain-extra.yml",
        what: "udeps",
        reason: "measured against a baseline ratchet that does block",
    },
    Allowed {
        file: "supply-chain-extra.yml",
        what: "geiger",
        reason: "measured against a first-party unsafe count that does block",
    },
];

/// Softeners that must be removed rather than justified.
///
/// One entry, and it is the reason this gate exists. Everything else on the
/// list above is arguable; this one is not, because the failure it hides is a
/// consensus failure rather than a test failure.
const MUST_BLOCK: &[(&str, &str, &str)] = &[
    (
        "security-hardening.yml",
        "tsan",
        "ThreadSanitizer carries continue-on-error on the job and `|| true` on the \
         command, so it cannot fail in any circumstance, and it has no canary, so a \
         clean report is indistinguishable from a binary that never ran. For a chain \
         a data race is not a flaky test: two nodes disagreeing about state because \
         of one is a fork.",
    ),
    (
        "security-hardening.yml",
        "loom",
        "loom is the half TSan cannot do. TSan reports the races it observed on the \
         schedule the machine picked; loom runs every interleaving the memory model \
         permits and so proves a lock inversion cannot happen. The consensus engine \
         nests three pairs of its four locks, and an inversion there deadlocks a \
         validator rather than crashing it, which is the failure a node cannot \
         report about itself. Softening this job would leave the ordering resting \
         on an argument in a comment again.",
    ),
];

/// One softener found in a workflow.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Soft {
    file: String,
    job: String,
    kind: &'static str,
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Find every `continue-on-error` and `|| true` under each job.
fn softeners_in(path: &Path, src: &str) -> Vec<Soft> {
    let file = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let lines: Vec<&str> = src.lines().collect();
    let Some(jobs_at) = lines.iter().position(|l| l.trim_end() == "jobs:") else {
        return Vec::new();
    };
    let job_indent = lines[jobs_at + 1..]
        .iter()
        .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map_or(2, |l| indent_of(l));

    let mut out = Vec::new();
    let mut job = String::new();
    for raw in lines.iter().skip(jobs_at + 1) {
        let line = raw.trim_end();
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let ind = indent_of(line);
        if ind == 0 {
            break;
        }
        if ind == job_indent && t.ends_with(':') {
            job = t.trim_end_matches(':').to_string();
            continue;
        }
        if job.is_empty() {
            continue;
        }
        let bare = t.strip_prefix("- ").unwrap_or(t);
        if bare.starts_with("continue-on-error:") && bare.contains("true") {
            out.push(Soft {
                file: file.clone(),
                job: job.clone(),
                kind: "continue-on-error",
            });
        }
        if t.contains("|| true") {
            out.push(Soft {
                file: file.clone(),
                job: job.clone(),
                kind: "|| true",
            });
        }
    }
    out.sort();
    out.dedup();
    out
}

fn collect(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root.join(".github/workflows")) {
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

fn judge(found: &[Soft]) -> Vec<String> {
    let mut problems = Vec::new();

    for (file, job, why) in MUST_BLOCK {
        if found.iter().any(|s| s.file == *file && s.job == *job) {
            problems.push(format!(
                "{file}: job `{job}` must not be softened.\n    {why}"
            ));
        }
    }

    let listed: BTreeSet<(&str, &str)> = ALLOWED.iter().map(|a| (a.file, a.what)).collect();

    for s in found {
        if MUST_BLOCK
            .iter()
            .any(|(f, j, _)| *f == s.file && *j == s.job)
        {
            continue;
        }
        if !listed.contains(&(s.file.as_str(), s.job.as_str())) {
            problems.push(format!(
                "{}: job `{}` carries `{}` and is not listed in this gate. A check that \
                 cannot fail is a report; say so here with a reason, or make it block.",
                s.file, s.job, s.kind
            ));
        }
    }

    for a in ALLOWED {
        if !found.iter().any(|s| s.file == a.file && s.job == a.what) {
            problems.push(format!(
                "{}: `{}` is listed here as softened, with the reason \"{}\", and nothing \
                 in the workflow softens it. Either it started blocking, in which case \
                 remove the entry, or it moved. A justification for something that no \
                 longer exists is a suppression nobody can audit.",
                a.file, a.what, a.reason
            ));
        }
    }
    problems
}

/// # Errors
///
/// Returns the softened checks that are unlisted, or listed and gone.
pub fn run(root: &Path) -> Result<String, String> {
    let files = collect(root);
    if files.is_empty() {
        return Err(String::from(
            "no workflows found; this gate is watching nothing.",
        ));
    }
    let mut found = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap_or_default();
        found.extend(softeners_in(f, &src));
    }

    let problems = judge(&found);
    if problems.is_empty() {
        return Ok(format!(
            "Security scan gate OK: {} softened checks across {} workflows, each listed \
             with a reason, and nothing on the must-block list is softened.",
            found.len(),
            files.len()
        ));
    }
    let mut msg = String::new();
    let _ = writeln!(msg, "{} finding(s):\n", problems.len());
    for p in &problems {
        let _ = writeln!(msg, "  {p}\n");
    }
    Err(msg)
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    let wf = "\
name: X
on: push
jobs:
  reporter:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - run: echo hi
  masked:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test || true
  strict:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test
";
    let found = softeners_in(Path::new("x.yml"), wf);
    if found.len() != 2 {
        problems.push(format!("BROKEN: expected two softeners, read {found:?}"));
    }
    if !found
        .iter()
        .any(|s| s.job == "reporter" && s.kind == "continue-on-error")
    {
        problems.push(String::from("BROKEN: continue-on-error was not seen"));
    }
    if !found
        .iter()
        .any(|s| s.job == "masked" && s.kind == "|| true")
    {
        problems.push(String::from("BROKEN: `|| true` was not seen"));
    }
    if found.iter().any(|s| s.job == "strict") {
        problems.push(String::from("VACUOUS: a strict job was called softened"));
    }

    // An unlisted softener must be refused.
    let unlisted = vec![Soft {
        file: "brand-new.yml".to_string(),
        job: "whatever".to_string(),
        kind: "|| true",
    }];
    // ALLOWED entries will also report as missing here; only the unlisted
    // finding is what this canary is about.
    if !judge(&unlisted).iter().any(|p| p.contains("brand-new.yml")) {
        problems.push(String::from("VACUOUS: an unlisted softener was accepted"));
    }

    // The must-block entry, softened, must be refused.
    let blocked = vec![Soft {
        file: "security-hardening.yml".to_string(),
        job: "tsan".to_string(),
        kind: "continue-on-error",
    }];
    if !judge(&blocked)
        .iter()
        .any(|p| p.contains("must not be softened"))
    {
        problems.push(String::from(
            "VACUOUS: a must-block job was accepted while softened",
        ));
    }

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "security scan gate self-test OK: continue-on-error and `|| true` are both seen, \
         a strict job is not called softened, an unlisted softener is refused, and a \
         must-block job carrying a softener is refused.",
    ))
}
