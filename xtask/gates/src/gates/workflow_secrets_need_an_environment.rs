//! A job that reads a repository secret declares a deployment environment.
//!
//! # The failure this closes
//!
//! `provenance.yml` signs the SBOM with the SLH-DSA release seed, read as
//! `${{ secrets.PQ_RELEASE_SEED }}` in a job with no `environment:`. The
//! workflow runs on `workflow_dispatch`, and a dispatch takes any ref: a
//! branch whose `xtask/release` prints the seed, or whose copy of the
//! workflow drops every guard, runs with the same secret, because a
//! repository secret is handed to every run of every workflow in the
//! repository. An `if: github.ref == ...` in the workflow is no defence; the
//! dispatched branch carries its own copy of the file.
//!
//! The control GitHub offers for this is the environment: a secret stored on
//! an environment is only released to a job that names that environment, and
//! the environment's deployment branch policy decides which refs may do so.
//! The policy is evaluated by GitHub against the ref, not by the workflow, so
//! a branch cannot edit its way past it. Naming the environment in the job is
//! the half of that control that lives in this tree; this gate keeps it
//! there. The other half (the secret stored on the environment, the policy
//! limited to the release branch) is repository configuration and is written
//! next to the job.
//!
//! # What is checked
//!
//! For every `.yml`/`.yaml` file in `.github/workflows`, read by lines with
//! comments removed:
//!
//! 1. A job whose body mentions `secrets.<NAME>` for any `NAME` other than
//!    `GITHUB_TOKEN`, or passes `secrets: inherit` to a reusable workflow,
//!    must carry a job-level `environment:` key.
//! 2. A secret mentioned at workflow level (outside `jobs:`), for example in
//!    a top-level `env:` block, reaches every job and is a finding on its
//!    own.
//!
//! `GITHUB_TOKEN` is exempt: it is scoped by `permissions:` per job and
//! expires with the run. A file that cannot be read is a finding.

use std::path::{Path, PathBuf};

const EXEMPT: &[&str] = &["GITHUB_TOKEN"];

fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or("").trim_end()
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// The secret names a line refers to through the `secrets` context, and
/// whether it passes the whole context on (`secrets: inherit`).
fn secret_refs(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    if line.trim() == "secrets: inherit" {
        out.push(String::from("inherit"));
    }
    let mut rest = line;
    while let Some(pos) = rest.find("secrets.") {
        let after = &rest[pos + "secrets.".len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() && !EXEMPT.contains(&name.as_str()) {
            out.push(name);
        }
        rest = after;
    }
    out
}

struct Job {
    id: String,
    has_environment: bool,
    secrets: Vec<String>,
}

struct Workflow {
    top_level_secrets: Vec<String>,
    jobs: Vec<Job>,
}

fn parse(text: &str) -> Workflow {
    let mut wf = Workflow {
        top_level_secrets: Vec::new(),
        jobs: Vec::new(),
    };
    let mut in_jobs = false;
    let mut job_indent: Option<usize> = None;
    for raw in text.lines() {
        let line = strip_comment(raw);
        if line.trim().is_empty() {
            continue;
        }
        let indent = indent_of(line);
        if indent == 0 {
            in_jobs = line.trim() == "jobs:";
            if !in_jobs {
                wf.top_level_secrets.extend(secret_refs(line));
            }
            continue;
        }
        if !in_jobs {
            wf.top_level_secrets.extend(secret_refs(line));
            continue;
        }
        let first = *job_indent.get_or_insert(indent);
        if indent == first {
            let id = line.trim().trim_end_matches(':').to_string();
            wf.jobs.push(Job {
                id,
                has_environment: false,
                secrets: Vec::new(),
            });
            continue;
        }
        let Some(job) = wf.jobs.last_mut() else {
            continue;
        };
        let key = line.trim();
        if indent == first + 2 && (key == "environment:" || key.starts_with("environment: ")) {
            job.has_environment = true;
        }
        job.secrets.extend(secret_refs(line));
    }
    wf
}

fn check_text(text: &str) -> Vec<String> {
    let wf = parse(text);
    let mut problems = Vec::new();
    if !wf.top_level_secrets.is_empty() {
        problems.push(format!(
            "workflow-level reference to secrets {} reaches every job; move it into a job with an `environment:`",
            wf.top_level_secrets.join(", ")
        ));
    }
    for job in &wf.jobs {
        if !job.secrets.is_empty() && !job.has_environment {
            problems.push(format!(
                "job `{}` reads secrets {} without a job-level `environment:`",
                job.id,
                job.secrets.join(", ")
            ));
        }
    }
    problems
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
/// Returns a finding naming every job that reads a secret outside an
/// environment, or the reason the workflow directory could not be measured.
pub fn run(root: &Path) -> Result<String, String> {
    let workflows = collect_workflows(root)?;
    let mut problems = Vec::new();
    let mut guarded = 0usize;
    for path in &workflows {
        let label = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let found = check_text(&text);
                if found.is_empty() {
                    guarded += parse(&text)
                        .jobs
                        .iter()
                        .filter(|j| !j.secrets.is_empty())
                        .count();
                }
                problems.extend(found.into_iter().map(|p| format!("{label}: {p}")));
            }
            Err(e) => problems.push(format!("{label}: cannot read: {e}")),
        }
    }
    if !problems.is_empty() {
        return Err(format!(
            "workflow-secrets-need-an-environment: {} finding(s):\n{}",
            problems.len(),
            problems.join("\n")
        ));
    }
    Ok(format!(
        "workflow-secrets-need-an-environment OK: {} workflow(s), {} secret-reading job(s) all name an environment",
        workflows.len(),
        guarded
    ))
}

/// # Errors
///
/// Returns a finding when a canary does not behave as the gate promises.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-secrets-env")?;
    let result = (|| {
        let workflows = dir.join(".github/workflows");
        std::fs::create_dir_all(&workflows).map_err(|e| e.to_string())?;
        let file = workflows.join("release.yml");
        let good = "name: release\non:\n  push:\n    branches: [main]\n  workflow_dispatch:\njobs:\n  sign:\n    runs-on: ubuntu-latest\n    environment: release\n    steps:\n      - name: Sign\n        env:\n          SEED: ${{ secrets.RELEASE_SEED }}\n        run: sign \"$SEED\"\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ secrets.GITHUB_TOKEN }}\" > /dev/null\n";
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

        expect_pass(good, "a secret read inside an environment")?;
        expect_pass(
            &good.replace(
                "    environment: release\n",
                "    environment:\n      name: release\n      url: https://example.invalid\n",
            ),
            "an environment written as a mapping",
        )?;
        expect_pass(
            &good.replace("    environment: release\n", "").replace(
                "          SEED: ${{ secrets.RELEASE_SEED }}\n",
                "          # SEED: ${{ secrets.RELEASE_SEED }}\n          SEED: fixture\n",
            ),
            "a secret mentioned only in a comment",
        )?;

        expect_fail(
            &good.replace("    environment: release\n", ""),
            "a secret read without an environment",
        )?;
        expect_fail(
            &good.replace(
                "    environment: release\n",
                "    env:\n      environment: release\n",
            ),
            "an environment key nested under env",
        )?;
        expect_fail(
            &good.replace("    environment: release\n", "").replace(
                "        env:\n          SEED: ${{ secrets.RELEASE_SEED }}\n        run: sign \"$SEED\"\n",
                "        run: sign \"${{ secrets.RELEASE_SEED }}\"\n",
            ),
            "a secret expanded inline in run without an environment",
        )?;
        expect_fail(
            "name: reuse\non:\n  push:\njobs:\n  call:\n    uses: ./.github/workflows/other.yml\n    secrets: inherit\n",
            "secrets inherited by a reusable workflow without an environment",
        )?;
        expect_fail(
            &good.replace(
                "jobs:\n",
                "env:\n  SEED: ${{ secrets.RELEASE_SEED }}\njobs:\n",
            ),
            "a workflow-level env secret",
        )?;
        Ok(String::from(
            "workflow-secrets-need-an-environment canary OK: environment (scalar and mapping) and comment-only pass; missing, nested-under-env, inline-run, secrets-inherit and workflow-level fail",
        ))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn workflow_secrets_need_an_environment_catches_injected_omissions() {
        super::self_test().expect("secrets environment canary");
    }

    #[test]
    fn github_token_alone_is_not_a_finding() {
        let text = "name: t\non:\n  push:\njobs:\n  a:\n    steps:\n      - run: gh auth status\n        env:\n          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n";
        assert!(super::check_text(text).is_empty());
    }

    #[test]
    fn the_release_seed_shape_is_a_finding() {
        let text = "name: Provenance\non:\n  push:\n    branches: [main]\n  workflow_dispatch:\njobs:\n  sbom-attestation:\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write\n    steps:\n      - name: Sign the SBOM\n        env:\n          PQ_RELEASE_SEED: ${{ secrets.PQ_RELEASE_SEED }}\n        run: sign\n";
        let found = super::check_text(text);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("sbom-attestation") && found[0].contains("PQ_RELEASE_SEED"));
    }
}
