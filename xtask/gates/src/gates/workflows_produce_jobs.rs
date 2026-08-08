//! A workflow that parses but produces no jobs is a check that does not exist.
//!
//! # The failure this closes
//!
//! `extra-tooling.yml` ran zero jobs on every push for an unknown stretch, and
//! the header of that file records what happened: a `slsa-provenance` job
//! called a reusable workflow from `steps[].uses`. Reusable workflows are only
//! valid at job level, so GitHub rejected the whole file. Every run finished
//! instantly as a failure with no jobs, and the other five jobs in the file,
//! `cargo-auditable`, `cargo-audit`, dead-dependency detection, taplo and
//! Kani, ran not at all.
//!
//! Nothing caught it. `actionlint` passes the file locally; the construct is
//! syntactically fine and only invalid in that position.
//! `check-gates-are-wired.sh` confirms a script is *named* by some workflow,
//! which was true the entire time. Six weeks of "the gate is wired" and the
//! gate was not running.
//!
//! So the question this asks is not "does the YAML parse" but "would this
//! file produce work".
//!
//! # What is checked
//!
//! Statically, without calling GitHub:
//!
//! 1. Every workflow declares at least one job.
//! 2. No job uses a reusable workflow from inside `steps[].uses`. That is the
//!    exact construct that killed the file, and it is invalid anywhere except
//!    `jobs.<id>.uses`.
//! 3. A job with neither `steps` nor `uses` produces nothing.
//! 4. Every `steps[].uses` action reference is pinned to a 40-character commit
//!    SHA. A tag is mutable, and a mutable reference in a job that can read
//!    the repository is the supply-chain shape the `TanStack` compromise used.
//!
//! The parser is deliberately small. A full YAML implementation would be a
//! dependency, and this crate has none by choice: it decides what reaches
//! `main`, so every crate it pulls in widens that trust boundary. What is
//! needed here is the indentation structure of a known file shape, which is
//! reachable by reading lines.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// A step's `uses:` reference, with where it was found.
struct UsesRef {
    line: usize,
    value: String,
    /// True when the reference sits under a job rather than a step.
    job_level: bool,
}

/// What one workflow file declares.
struct Workflow {
    path: PathBuf,
    /// Job ids, in file order.
    jobs: Vec<String>,
    /// Jobs that declare neither `steps:` nor `uses:`.
    empty_jobs: Vec<String>,
    /// Every `uses:` seen, job level and step level.
    uses: Vec<UsesRef>,
}

/// Indentation of a line, in spaces. Tabs are not valid YAML indentation.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Read the structure this gate reasons about out of one workflow.
///
/// Looks for the `jobs:` mapping, then treats every key at the next
/// indentation level as a job id.
fn parse(path: &Path, src: &str) -> Workflow {
    let mut wf = Workflow {
        path: path.to_path_buf(),
        jobs: Vec::new(),
        empty_jobs: Vec::new(),
        uses: Vec::new(),
    };

    let lines: Vec<&str> = src.lines().collect();
    let Some(jobs_at) = lines.iter().position(|l| l.trim_end() == "jobs:") else {
        return wf;
    };

    // Indentation of a job id: the first non-blank, non-comment line under
    // `jobs:` sets it.
    let job_indent = lines[jobs_at + 1..]
        .iter()
        .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map_or(2, |l| indent_of(l));

    let mut current: Option<String> = None;
    let mut has_body = false;

    for (i, raw) in lines.iter().enumerate().skip(jobs_at + 1) {
        let line = raw.trim_end();
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let ind = indent_of(line);

        // Left the jobs mapping entirely.
        if ind == 0 {
            break;
        }

        // A new job id.
        if ind == job_indent && line.trim_end().ends_with(':') {
            if let Some(prev) = current.take() {
                if !has_body {
                    wf.empty_jobs.push(prev);
                }
            }
            let id = line.trim().trim_end_matches(':').to_string();
            wf.jobs.push(id.clone());
            current = Some(id);
            has_body = false;
            continue;
        }

        let trimmed = line.trim_start();
        if trimmed.starts_with("steps:") {
            has_body = true;
        }
        // A step is a list item, so its key arrives as `- uses:` rather than
        // `uses:`. Missing that read every step-level reference as absent,
        // which made the gate pass the exact file it was written for.
        let after_dash = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        if let Some(rest) = after_dash.strip_prefix("uses:") {
            // An inline `# comment` is not part of the reference. Every pin
            // in this tree carries one naming the tag the SHA came from, so
            // reading it as part of the value made all 164 of them look
            // unpinned, which is a gate that fails on a correct tree.
            let value = rest
                .split('#')
                .next()
                .unwrap_or(rest)
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
            // A `uses:` two levels in from the job id is the job's own
            // reusable-workflow call. Deeper than that, it is inside a step.
            let job_level = ind <= job_indent + 2;
            if job_level {
                has_body = true;
            }
            wf.uses.push(UsesRef {
                line: i + 1,
                value,
                job_level,
            });
        }
    }
    if let Some(prev) = current {
        if !has_body {
            wf.empty_jobs.push(prev);
        }
    }
    wf
}

/// Is this reference a reusable workflow rather than an action?
///
/// A reusable workflow points at a `.yml` or `.yaml` file. An action points at
/// a repository or a directory inside one.
fn is_reusable_workflow(value: &str) -> bool {
    let before_ref = value.split('@').next().unwrap_or(value);
    // Compared case-insensitively: GitHub accepts either spelling, and a
    // reference is a string here rather than a path on disk, so the extension
    // helpers do not apply.
    // Split on the final dot rather than matching a suffix: clippy reads a
    // suffix match as a path-extension test, and this is a reference string,
    // not a path.
    before_ref
        .rsplit_once('.')
        .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"))
}

/// Is this action pinned to a full commit SHA?
///
/// Local actions (`./.github/actions/x`) and docker references are not pinned
/// this way and are not the risk being measured.
fn is_sha_pinned(value: &str) -> bool {
    if value.starts_with('.') || value.starts_with("docker://") {
        return true;
    }
    value
        .split('@')
        .nth(1)
        .is_some_and(|r| r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit()))
}

fn collect_workflows(root: &Path) -> Vec<PathBuf> {
    let dir = root.join(".github/workflows");
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let p = e.path();
            let is_yaml = p
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("yml") || x.eq_ignore_ascii_case("yaml"));
            if is_yaml {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn findings_for(wf: &Workflow, root: &Path) -> Vec<String> {
    let rel = wf
        .path
        .strip_prefix(root)
        .unwrap_or(&wf.path)
        .display()
        .to_string();
    let mut out = Vec::new();

    if wf.jobs.is_empty() {
        out.push(format!(
            "{rel} declares no jobs. A workflow that produces no work is a check that \
             does not exist, and it reports as a pass."
        ));
        return out;
    }

    for j in &wf.empty_jobs {
        out.push(format!(
            "{rel}: job `{j}` has neither `steps:` nor a job-level `uses:`, so it runs \
             nothing."
        ));
    }

    for u in &wf.uses {
        if !u.job_level && is_reusable_workflow(&u.value) {
            out.push(format!(
                "{rel}:{}: `{}` is a reusable workflow called from inside a step. That is \
                 only valid at job level, and GitHub rejects the entire file when it \
                 appears here: every run finishes instantly with zero jobs, and every \
                 other job in the file silently stops running. This exact construct took \
                 extra-tooling.yml offline once already.",
                u.line, u.value
            ));
        }
        if !u.job_level && !is_sha_pinned(&u.value) {
            out.push(format!(
                "{rel}:{}: `{}` is not pinned to a 40-character commit SHA. A tag can be \
                 moved by whoever owns it, so a job that reads the repository is trusting \
                 a mutable reference.",
                u.line, u.value
            ));
        }
    }
    out
}

/// # Errors
///
/// Returns the workflows that would produce no work, or that pin nothing.
pub fn run(root: &Path) -> Result<String, String> {
    let files = collect_workflows(root);
    if files.is_empty() {
        return Err(String::from(
            "no workflow files found under .github/workflows. Either the directory moved \
             or CI is gone, and this gate is now watching nothing.",
        ));
    }

    let mut findings = Vec::new();
    let mut jobs_total = 0usize;
    let mut pinned = 0usize;
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap_or_default();
        let wf = parse(f, &src);
        jobs_total += wf.jobs.len();
        pinned += wf
            .uses
            .iter()
            .filter(|u| !u.job_level && is_sha_pinned(&u.value))
            .count();
        findings.extend(findings_for(&wf, root));
    }

    if findings.is_empty() {
        return Ok(format!(
            "Workflow gate OK: {} workflows declaring {jobs_total} jobs, none empty, no \
             reusable workflow called from a step, and all {pinned} step actions pinned \
             to a commit SHA.",
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

/// Canaries for the two reference classifiers.
fn self_test_classifiers(problems: &mut Vec<String>) {
    // Reference classification.
    if !is_reusable_workflow("org/repo/.github/workflows/x.yml@v1") {
        problems.push(String::from(
            "BROKEN: a .yml reference is a reusable workflow",
        ));
    }
    if is_reusable_workflow("actions/checkout@v4") {
        problems.push(String::from(
            "BROKEN: an action was called a reusable workflow",
        ));
    }
    if is_sha_pinned("actions/checkout@v4") {
        problems.push(String::from("BROKEN: a tag counted as a SHA pin"));
    }
    if !is_sha_pinned("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1") {
        problems.push(String::from("BROKEN: a real SHA pin was not recognised"));
    }
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();
    let root = Path::new("/tmp/does-not-exist");

    // The shape that killed extra-tooling.yml: a reusable workflow under a
    // step. Must be refused.
    let killed = "\
name: X
on: push
jobs:
  provenance:
    runs-on: ubuntu-latest
    steps:
      - uses: slsa-framework/slsa-github-generator/.github/workflows/generator.yml@v1.9.0
";
    let wf = parse(Path::new("x.yml"), killed);
    let f = findings_for(&wf, root);
    if !f.iter().any(|x| x.contains("reusable workflow")) {
        problems.push(format!(
            "VACUOUS: a reusable workflow called from a step was accepted: {f:?}"
        ));
    }

    // The same reference at job level is legal and must pass.
    let legal = "\
name: X
on: push
jobs:
  provenance:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator.yml@v1.9.0
";
    let wf = parse(Path::new("x.yml"), legal);
    let f = findings_for(&wf, root);
    if !f.is_empty() {
        problems.push(format!(
            "BROKEN: a job-level reusable workflow was rejected: {f:?}"
        ));
    }

    // No jobs at all.
    let empty = "name: X\non: push\n";
    let wf = parse(Path::new("x.yml"), empty);
    if !findings_for(&wf, root)
        .iter()
        .any(|x| x.contains("declares no jobs"))
    {
        problems.push(String::from(
            "VACUOUS: a workflow with no jobs was accepted",
        ));
    }

    // A job with nothing in it.
    let hollow = "\
name: X
on: push
jobs:
  ghost:
    runs-on: ubuntu-latest
";
    let wf = parse(Path::new("x.yml"), hollow);
    if !findings_for(&wf, root)
        .iter()
        .any(|x| x.contains("runs nothing"))
    {
        problems.push(String::from("VACUOUS: a job with no steps was accepted"));
    }

    // A tag-pinned action.
    let tagged = "\
name: X
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
";
    let wf = parse(Path::new("x.yml"), tagged);
    if !findings_for(&wf, root)
        .iter()
        .any(|x| x.contains("not pinned"))
    {
        problems.push(String::from("VACUOUS: a tag-pinned action was accepted"));
    }

    // A SHA-pinned action, and a local one, both fine.
    let good = "\
name: X
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: ./.github/actions/local
      - run: echo hi
";
    let wf = parse(Path::new("x.yml"), good);
    let f = findings_for(&wf, root);
    if !f.is_empty() {
        problems.push(format!("BROKEN: a correct workflow was rejected: {f:?}"));
    }

    self_test_classifiers(&mut problems);

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "workflow gate self-test OK: a reusable workflow called from a step, a workflow \
         with no jobs, a job with no steps and a tag-pinned action are all refused; the \
         same reusable workflow at job level, a SHA-pinned action and a local action all \
         pass.",
    ))
}
