//! Every Cargo workspace in the repository is covered by CI workflows, and
//! every scheduled nightly workflow runs fail-closed.
//!
//! # What is checked
//!
//! 1. Every directory holding both `Cargo.toml` and `Cargo.lock` (excluding
//!    `target`, `.git` and `node_modules`) is a standalone Cargo workspace or
//!    package whose tests are not covered by `cargo test --lib` at the root.
//!    At least one non-comment line across `.github/workflows/*.yml` must
//!    reference that workspace path (or run root `cargo test` for `.`).
//! 2. Every workflow declaring a non-comment `schedule:` trigger must remain
//!    fail-closed: no job or step in a scheduled workflow may set
//!    `continue-on-error` to anything other than `false`.

use std::fmt::Write as _;
use std::path::Path;

const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

fn discover_workspaces(dir: &Path, root: &Path, out: &mut Vec<String>) {
    if dir.join("Cargo.toml").is_file() && dir.join("Cargo.lock").is_file() {
        let rel = dir.strip_prefix(root).map_or_else(
            |_| String::from("."),
            |p| p.to_string_lossy().replace('\\', "/"),
        );
        let entry = if rel.is_empty() {
            String::from(".")
        } else {
            rel
        };
        out.push(entry);
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if !ft.is_dir() || ft.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if SKIP_DIRS.contains(&name_str) {
            continue;
        }
        discover_workspaces(&entry.path(), root, out);
    }
}

fn read_workflows(workflows_dir: &Path) -> Result<Vec<(String, Vec<String>)>, String> {
    let rd = std::fs::read_dir(workflows_dir)
        .map_err(|e| format!("cannot read {}: {e}", workflows_dir.display()))?;
    let mut paths: Vec<_> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|ext| {
                ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml")
            })
        })
        .collect();
    paths.sort();
    if paths.is_empty() {
        return Err(String::from("no workflow files found in .github/workflows"));
    }
    let mut out = Vec::new();
    for path in paths {
        let name = path.file_name().map_or_else(
            || String::from("workflow.yml"),
            |n| n.to_string_lossy().into_owned(),
        );
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("cannot read {name}: {e}"))?;
        let active_lines: Vec<String> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect();
        out.push((name, active_lines));
    }
    Ok(out)
}

fn workspace_is_referenced(ws: &str, workflows: &[(String, Vec<String>)]) -> bool {
    if ws == "." {
        return workflows.iter().any(|(_, lines)| {
            lines
                .iter()
                .any(|l| l.contains("cargo test") && !l.contains("--manifest-path"))
        });
    }
    let manifest_flag = format!("{ws}/Cargo.toml");
    let workdir_colon = format!("working-directory: {ws}");
    let workdir_quoted = format!("working-directory: \"{ws}\"");
    let cd_cmd = format!("cd {ws}");
    workflows.iter().any(|(_, lines)| {
        lines.iter().any(|l| {
            l.contains(&manifest_flag)
                || l.contains(&workdir_colon)
                || l.contains(&workdir_quoted)
                || l.contains(&cd_cmd)
        })
    })
}

fn check_nightly_required(workflows: &[(String, Vec<String>)]) -> Vec<String> {
    let mut findings = Vec::new();
    for (name, lines) in workflows {
        let is_scheduled = lines
            .iter()
            .any(|l| l == "schedule:" || l.starts_with("schedule: "));
        if !is_scheduled {
            continue;
        }
        for line in lines {
            let stripped = line.strip_prefix('-').map_or(line.as_str(), str::trim_start);
            if let Some(rest) = stripped.strip_prefix("continue-on-error:") {
                let val = rest.trim().trim_matches(|c| c == '\'' || c == '"');
                if !val.eq_ignore_ascii_case("false") {
                    findings.push(format!(
                        "{name}: scheduled workflow softens failure with `continue-on-error: {val}`"
                    ));
                }
            }
        }
    }
    findings
}

fn check(root: &Path) -> Result<String, String> {
    let mut workspaces = Vec::new();
    discover_workspaces(root, root, &mut workspaces);
    if workspaces.is_empty() {
        return Err(String::from("no Cargo workspaces discovered"));
    }
    let workflows = read_workflows(&root.join(".github/workflows"))?;
    let mut bad = String::new();
    for ws in &workspaces {
        if !workspace_is_referenced(ws, &workflows) {
            let _ = writeln!(
                bad,
                "  workspace `{ws}` has Cargo.toml + Cargo.lock but no workflow exercises it"
            );
        }
    }
    for night_err in check_nightly_required(&workflows) {
        let _ = writeln!(bad, "  {night_err}");
    }
    if bad.is_empty() {
        Ok(format!(
            "OK: {} Cargo workspace(s) covered across {} workflow(s); scheduled workflows fail-closed.",
            workspaces.len(),
            workflows.len()
        ))
    } else {
        Err(format!("workflow workspace/nightly coverage failed:\n{bad}"))
    }
}

/// Run the workspace and nightly workflow coverage gate.
///
/// # Errors
///
/// Returns an error if any Cargo workspace lacks workflow coverage or if any
/// scheduled workflow uses `continue-on-error` to soften failures.
pub fn run(root: &Path) -> Result<String, String> {
    check(root)
}

/// Run the canary suite for `workflows-cover-every-workspace`.
///
/// # Errors
///
/// Returns an error if an uncovered workspace or a softened scheduled workflow
/// is not rejected.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-wf-ws")?;
    let result = (|| {
        let wf_dir = dir.join(".github/workflows");
        let covered_dir = dir.join("crates/covered");
        std::fs::create_dir_all(&wf_dir).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&covered_dir).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"root\"\n")
            .map_err(|e| e.to_string())?;
        std::fs::write(dir.join("Cargo.lock"), "# lock\n").map_err(|e| e.to_string())?;
        std::fs::write(covered_dir.join("Cargo.toml"), "[package]\nname = \"c\"\n")
            .map_err(|e| e.to_string())?;
        std::fs::write(covered_dir.join("Cargo.lock"), "# lock\n").map_err(|e| e.to_string())?;
        std::fs::write(
            wf_dir.join("ci.yml"),
            "jobs:\n  test:\n    steps:\n      - run: cargo test --lib\n      - run: cargo test --manifest-path crates/covered/Cargo.toml\n",
        )
        .map_err(|e| e.to_string())?;
        std::fs::write(
            wf_dir.join("nightly.yml"),
            "on:\n  schedule:\n    - cron: '0 3 * * *'\njobs:\n  fuzz:\n    steps:\n      - run: cargo test --lib\n",
        )
        .map_err(|e| e.to_string())?;

        check(&dir).map_err(|e| format!("canary: clean staged tree failed: {e}"))?;

        let orphan = dir.join("crates/orphan");
        std::fs::create_dir_all(&orphan).map_err(|e| e.to_string())?;
        std::fs::write(orphan.join("Cargo.toml"), "[package]\nname = \"o\"\n")
            .map_err(|e| e.to_string())?;
        std::fs::write(orphan.join("Cargo.lock"), "# lock\n").map_err(|e| e.to_string())?;
        match check(&dir) {
            Err(e) if e.contains("crates/orphan") => {}
            other => {
                return Err(format!(
                    "canary: uncovered workspace was not caught: {other:?}"
                ))
            }
        }
        std::fs::remove_dir_all(&orphan).map_err(|e| e.to_string())?;

        std::fs::write(
            wf_dir.join("nightly.yml"),
            "on:\n  schedule:\n    - cron: '0 3 * * *'\njobs:\n  fuzz:\n    continue-on-error: true\n    steps:\n      - run: cargo test --lib\n",
        )
        .map_err(|e| e.to_string())?;
        match check(&dir) {
            Err(e) if e.contains("nightly.yml") && e.contains("continue-on-error") => {}
            other => {
                return Err(format!(
                    "canary: softened nightly workflow was not caught: {other:?}"
                ))
            }
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "workflows-cover-every-workspace canary OK: uncovered workspace and softened nightly workflow rejected.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflows_cover_every_workspace() {
        assert!(self_test().is_ok());
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let verdict = run(&root);
        assert!(verdict.is_ok(), "{verdict:?}");
    }

    #[test]
    fn nightly_workflows_are_required() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let workflows = read_workflows(&root.join(".github/workflows")).unwrap_or_default();
        assert!(!workflows.is_empty());
        let findings = check_nightly_required(&workflows);
        assert!(findings.is_empty(), "{findings:?}");
    }
}
