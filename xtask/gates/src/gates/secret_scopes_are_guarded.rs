//! A stored secret is reachable only from a scope that was declared.
//!
//! # The question this gate answers
//!
//! `secrets.X` in a workflow is not a reference to a value; it is a reference
//! to *who can cause that value to be handed to a job*. A job with no
//! `environment:` and no ref guard is reachable from `workflow_dispatch` on any
//! branch, which is a ref the caller chooses. So the same line is a different
//! promise depending on where it sits, and nothing in the tree was reading
//! that difference.
//!
//! The measured case: `provenance.yml` hands `PQ_RELEASE_SEED` - the SLH-DSA
//! release signing seed - to a job that declares no environment, while the
//! file carries a `workflow_dispatch` trigger. The seed file itself was
//! already made to disappear on the failure path; that closed the *in-run*
//! leak. This gate is about the other half: which refs may start the run at
//! all.
//!
//! # The rule, stated as a rule
//!
//! A reference to a stored repository secret must sit inside a job that
//! declares an `environment:` (the protections live on the environment, not in
//! the YAML) or a step whose `if:` restricts the run to `refs/heads/main`.
//!
//! `secrets.GITHUB_TOKEN` is exempt: it is minted per run, scoped to the job,
//! and is not a stored secret. Treating it as one would demand an environment
//! for a token that cannot be stolen from the repository.
//!
//! # Why text and not a YAML parser
//!
//! The gate must run on the tree it judges, and adding a YAML implementation to
//! the gate crate widens the trust boundary of the thing that decides whether
//! a commit may land. The shapes this gate reads are fixed by GitHub's own
//! schema: two-space job keys, `- ` steps under a job, `if:`/`environment:`
//! keys at known indents. A line the parser does not recognise is not silently
//! skipped - an unreadable or empty workflow directory is a finding, and a file
//! whose job block cannot be found is a finding.

use std::path::Path;

/// The token GitHub mints for the run. Not a stored secret.
const AUTO_TOKEN: &str = "secrets.GITHUB_TOKEN";

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn is_comment_or_blank(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with('#')
}

/// True when an `if:` expression confines the run to the default branch.
fn guards_to_main(line: &str) -> bool {
    let t = line.trim();
    if !t.starts_with("if:") && !t.starts_with("- if:") {
        return false;
    }
    (t.contains("github.ref") && t.contains("refs/heads/main"))
        || (t.contains("github.ref_name") && t.contains("'main'"))
        || (t.contains("github.ref_name") && t.contains("\"main\""))
}

/// One job block: its body, with the line number of every key in it.
struct Job {
    body: Vec<(usize, String)>,
}

/// Split a workflow into job blocks by the two-space job keys under `jobs:`.
///
/// Returns `Err` when the file has no `jobs:` section at all: a workflow
/// without jobs is not a workflow this gate can read, and reporting "no
/// findings" for it would be the vacuous pass the crate's header warns about.
fn jobs_of(text: &str) -> Vec<Job> {
    let mut jobs = Vec::new();
    let mut in_jobs = false;
    let mut current: Option<Job> = None;
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        if is_comment_or_blank(raw) {
            continue;
        }
        let indent = indent_of(raw);
        let trimmed = raw.trim_end();
        if indent == 0 {
            if let Some(job) = current.take() {
                jobs.push(job);
            }
            in_jobs = trimmed.trim_start().starts_with("jobs:");
            continue;
        }
        if !in_jobs {
            continue;
        }
        if indent == 2 && trimmed.trim_start().ends_with(':') {
            if let Some(job) = current.take() {
                jobs.push(job);
            }
            current = Some(Job { body: Vec::new() });
            continue;
        }
        if let Some(job) = current.as_mut() {
            job.body.push((line_no, trimmed.to_string()));
        }
    }
    if let Some(job) = current.take() {
        jobs.push(job);
    }
    jobs
}

/// A step block inside a job: the `- ` entry and the keys under it.
fn steps_of(job: &Job) -> Vec<Vec<(usize, String)>> {
    let mut steps: Vec<Vec<(usize, String)>> = Vec::new();
    let mut current: Option<Vec<(usize, String)>> = None;
    for (line_no, line) in &job.body {
        let indent = indent_of(line);
        let starts_step = indent == 6 && line.trim_start().starts_with("- ");
        if starts_step {
            if let Some(step) = current.take() {
                steps.push(step);
            }
            current = Some(vec![(*line_no, line.clone())]);
            continue;
        }
        if let Some(step) = current.as_mut() {
            step.push((*line_no, line.clone()));
        }
    }
    if let Some(step) = current.take() {
        steps.push(step);
    }
    steps
}

fn job_is_guarded(job: &Job) -> bool {
    job.body.iter().any(|(_, line)| {
        indent_of(line) == 4
            && (line.trim_start().starts_with("environment:")
                || (line.trim_start().starts_with("if:") && guards_to_main(line)))
    })
}

fn step_is_guarded(step: &[(usize, String)]) -> bool {
    step.iter()
        .any(|(_, line)| indent_of(line) >= 6 && guards_to_main(line))
}

/// Secrets named in a line, excluding the auto-minted token.
fn secrets_in(line: &str) -> Vec<String> {
    const PREFIX: &str = "secrets.";
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(pos) = rest.find(PREFIX) {
        let after = &rest[pos + PREFIX.len()..];
        let end = after
            .char_indices()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
            .map_or(after.len(), |(i, _)| i);
        let name = &after[..end];
        if name.is_empty() {
            break;
        }
        let token = format!("{PREFIX}{name}");
        if token != AUTO_TOKEN {
            out.push(token);
        }
        rest = &after[end..];
    }
    out
}

/// # Errors
///
/// Returns every unguarded stored-secret reference as `file:line`, or the
/// reason the tree could not be read.
pub fn run(root: &Path) -> Result<String, String> {
    let dir = root.join(".github/workflows");
    let rd = std::fs::read_dir(&dir)
        .map_err(|e| format!("no workflow directory {}: {e}", dir.display()))?;
    let mut files: Vec<std::path::PathBuf> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| matches!(p.extension().and_then(|x| x.to_str()), Some("yml" | "yaml")))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("no workflow files under {}", dir.display()));
    }

    let mut findings: Vec<String> = Vec::new();
    let mut measured = 0_usize;
    for path in &files {
        let name = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("{name} is unreadable: {e}"))?;
        if !text.contains("secrets.") {
            continue;
        }
        let jobs = jobs_of(&text);
        if jobs.is_empty() {
            return Err(format!("{name} has no job this gate can read"));
        }
        for job in &jobs {
            let guarded = job_is_guarded(job);
            for step in steps_of(job) {
                let step_guarded = step_is_guarded(&step);
                for (line_no, line) in &step {
                    if line.trim_start().starts_with('#') {
                        continue;
                    }
                    for secret in secrets_in(line) {
                        measured += 1;
                        if !guarded && !step_guarded {
                            findings.push(format!(
                                "{name}:{line_no}: {secret} is handed to a scope with no \
                                 environment: and no refs/heads/main guard"
                            ));
                        }
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        return Ok(format!(
            "secret scope gate OK: {measured} stored-secret reference(s) across {} workflow \
             file(s), each inside an environment: or a default-branch guard.",
            files.len()
        ));
    }
    Err(format!(
        "{} unguarded stored-secret reference(s):\n{}",
        findings.len(),
        findings.join("\n")
    ))
}

/// # Errors
///
/// Returns a finding when the canary shapes are not refused, or when the
/// guarded shape is refused too (a gate that refuses everything proves
/// nothing).
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-secret-scope")?;
    let wf_dir = dir.join(".github/workflows");
    std::fs::create_dir_all(&wf_dir).map_err(|e| e.to_string())?;

    let unguarded = "name: canary\non:\n  workflow_dispatch:\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - name: sign\n        env:\n          SEED: ${{ secrets.RELEASE_SEED }}\n        run: echo ok\n";
    std::fs::write(wf_dir.join("bad.yml"), unguarded).map_err(|e| e.to_string())?;
    let bad = run(&dir);
    let bad_refused = match &bad {
        Ok(_) => false,
        Err(msg) => msg.contains("RELEASE_SEED") && msg.contains("bad.yml"),
    };

    let guarded = "name: canary\non:\n  push:\n    branches: [main]\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - name: sign\n        if: github.ref == 'refs/heads/main'\n        env:\n          SEED: ${{ secrets.RELEASE_SEED }}\n          TOKEN: ${{ secrets.GITHUB_TOKEN }}\n        run: echo ok\n";
    std::fs::write(wf_dir.join("bad.yml"), guarded).map_err(|e| e.to_string())?;
    let good = run(&dir);
    let good_accepted = good.is_ok();

    let empty_dir = dir.join(".github/workflows-empty");
    std::fs::create_dir_all(&empty_dir).map_err(|e| e.to_string())?;
    let empty_refused = run(&empty_dir).is_err();

    let _ = std::fs::remove_dir_all(&dir);

    if !bad_refused {
        return Err(format!(
            "VACUOUS GATE: an unguarded stored secret was accepted ({bad:?})"
        ));
    }
    if !good_accepted {
        return Err(format!(
            "the gate refuses a guarded secret too, so it carries no information: {good:?}"
        ));
    }
    if !empty_refused {
        return Err(String::from(
            "an empty workflow directory was accepted; a gate that measures nothing reported OK",
        ));
    }
    Ok(String::from(
        "canary OK: an unguarded stored secret, a guarded one and an empty directory are told \
         apart (the auto-minted GITHUB_TOKEN is not counted as a stored secret).",
    ))
}
