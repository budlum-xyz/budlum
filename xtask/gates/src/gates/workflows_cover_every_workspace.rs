//! Every Cargo workspace is compiled by at least one workflow.
//!
//! A standalone workspace that no workflow builds is a blind spot: its
//! tests, lints and dependency graph can drift without a red check. This
//! gate discovers workspace roots from the manifests, then reads the
//! executable `run:` blocks of every workflow and asks whether a cargo
//! command compiles each root. A comment, a softened step, `cargo fmt`
//! and `cargo metadata` do not count. A non-optional path dependency of a
//! compiled manifest counts, because cargo compiles it with that manifest.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::gates::ci_workflow_guards::run_blocks;

const COMPILE_VERBS: &[&str] = &[
    "build", "test", "check", "clippy", "run", "fuzz", "bench", "kani", "mutants", "miri", "doc",
];

fn normalize(relative: &str) -> String {
    let trimmed = relative.trim().trim_matches(['"', '\'']);
    let mut parts: Vec<&str> = Vec::new();
    for part in trimmed.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else {
                    parts.push("..");
                }
            }
            _ => parts.push(part),
        }
    }
    if parts.is_empty() {
        String::from(".")
    } else {
        parts.join("/")
    }
}

fn join_relative(base: &str, child: &str) -> String {
    let child = normalize(child);
    if base == "." {
        child
    } else if child == "." {
        base.to_string()
    } else {
        format!("{base}/{child}")
    }
}

fn component_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn glob_match(pattern: &str, text: &str) -> bool {
    fn go(p: &[&str], t: &[&str]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some(&"**") => (0..=t.len()).any(|i| go(&p[1..], &t[i..])),
            Some(component) => {
                !t.is_empty() && component_match(component, t[0]) && go(&p[1..], &t[1..])
            }
        }
    }
    let p: Vec<&str> = pattern.split('/').collect();
    let t: Vec<&str> = text.split('/').collect();
    go(&p, &t)
}

fn collect_manifests(root: &Path) -> Result<BTreeMap<String, toml::Value>, String> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, toml::Value>) -> Result<(), String> {
        let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(name.as_ref(), ".git" | "target" | "node_modules") {
                continue;
            }
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_dir() {
                walk(&path, root, out)?;
            } else if name == "Cargo.toml" {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                let value: toml::Value = toml::from_str(&text)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                let relative = path
                    .parent()
                    .and_then(|p| p.strip_prefix(root).ok())
                    .map_or_else(|| String::from("."), |p| normalize(&p.to_string_lossy()));
                out.insert(relative, value);
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

fn workspace_members(value: &toml::Value) -> Vec<String> {
    value
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(toml::Value::as_array)
        .map(|members| {
            members
                .iter()
                .filter_map(toml::Value::as_str)
                .map(normalize)
                .collect()
        })
        .unwrap_or_default()
}

fn is_member(manifests: &BTreeMap<String, toml::Value>, workspace: &str, dir: &str) -> bool {
    let Some(value) = manifests.get(workspace) else {
        return false;
    };
    let relative = if workspace == "." {
        dir.to_string()
    } else {
        dir.strip_prefix(&format!("{workspace}/"))
            .unwrap_or(dir)
            .to_string()
    };
    workspace_members(value)
        .iter()
        .any(|pattern| glob_match(pattern, &relative))
}

fn workspace_roots(manifests: &BTreeMap<String, toml::Value>) -> BTreeSet<String> {
    let mut roots = BTreeSet::new();
    for (dir, value) in manifests {
        if value.get("workspace").is_some() {
            roots.insert(dir.clone());
            continue;
        }
        if value.get("package").is_none() {
            continue;
        }
        let mut parent = Path::new(dir).parent();
        let mut owned = false;
        while let Some(ancestor) = parent {
            let ancestor_dir = normalize(&ancestor.to_string_lossy());
            if ancestor_dir != *dir
                && manifests
                    .get(&ancestor_dir)
                    .is_some_and(|v| v.get("workspace").is_some())
                && is_member(manifests, &ancestor_dir, dir)
            {
                owned = true;
                break;
            }
            parent = ancestor.parent();
        }
        if !owned {
            roots.insert(dir.clone());
        }
    }
    roots
}

fn workspace_for_dir<'a>(dir: &str, roots: &'a BTreeSet<String>) -> Option<&'a str> {
    let dir = normalize(dir);
    roots
        .iter()
        .map(String::as_str)
        .filter(|root| *root == "." || dir == *root || dir.starts_with(&format!("{root}/")))
        .max_by_key(|root| root.len())
}

struct CargoCommand {
    verb: String,
    manifest: Option<String>,
}

fn cargo_command(line: &str) -> Option<CargoCommand> {
    if line.trim_start().starts_with('#') {
        return None;
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let cargo = tokens.iter().position(|t| *t == "cargo")?;
    let mut rest = tokens[cargo + 1..].iter().copied().peekable();
    while rest.peek().is_some_and(|t| t.starts_with('+')) {
        rest.next();
    }
    let verb = rest.next()?.to_string();
    if !COMPILE_VERBS.contains(&verb.as_str()) && !verb.starts_with("build-") {
        return None;
    }
    let mut manifest = None;
    let args: Vec<&str> = rest.collect();
    for (i, token) in args.iter().enumerate() {
        if *token == "--manifest-path" {
            manifest = args.get(i + 1).map(|s| normalize(s));
        } else if let Some(value) = token.strip_prefix("--manifest-path=") {
            manifest = Some(normalize(value));
        }
    }
    Some(CargoCommand { verb, manifest })
}

fn path_dependencies(dir: &str, value: &toml::Value) -> Vec<String> {
    let mut out = Vec::new();
    for table in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(deps) = value.get(table).and_then(toml::Value::as_table) else {
            continue;
        };
        for dep in deps.values() {
            if dep.get("optional").and_then(toml::Value::as_bool) == Some(true) {
                continue;
            }
            if let Some(path) = dep.get("path").and_then(toml::Value::as_str) {
                out.push(join_relative(dir, path));
            }
        }
    }
    out
}

fn covered_workspaces(
    root: &Path,
    roots: &BTreeSet<String>,
    manifests: &BTreeMap<String, toml::Value>,
) -> Result<BTreeSet<String>, String> {
    let workflows = root.join(".github/workflows");
    let entries = std::fs::read_dir(&workflows)
        .map_err(|e| format!("cannot read {}: {e}", workflows.display()))?;
    let mut covered = BTreeSet::new();
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
        })
        .collect();
    paths.sort();
    for path in paths {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        for block in run_blocks(&text) {
            if block.softened.is_some() {
                continue;
            }
            let working_directory = block
                .working_directory
                .as_deref()
                .unwrap_or(".");
            for line in &block.lines {
                let Some(command) = cargo_command(line) else {
                    continue;
                };
                if let Some(manifest) = command.manifest {
                    let manifest_dir = Path::new(&manifest)
                        .parent()
                        .map_or_else(|| String::from("."), |p| normalize(&p.to_string_lossy()));
                    if let Some(workspace) = workspace_for_dir(&manifest_dir, roots) {
                        covered.insert(workspace.to_string());
                    }
                } else if command.verb == "fuzz" {
                    let fuzz_dir = join_relative(working_directory, "fuzz");
                    if roots.contains(&fuzz_dir) {
                        covered.insert(fuzz_dir);
                    } else if let Some(workspace) = workspace_for_dir(working_directory, roots) {
                        covered.insert(workspace.to_string());
                    }
                } else if let Some(workspace) = workspace_for_dir(working_directory, roots) {
                    covered.insert(workspace.to_string());
                }
            }
        }
    }

    loop {
        let before = covered.len();
        let snapshot = covered.clone();
        for workspace in snapshot {
            for (dir, value) in manifests {
                if workspace_for_dir(dir, roots) != Some(workspace.as_str()) {
                    continue;
                }
                for dep in path_dependencies(dir, value) {
                    if let Some(dependency_workspace) = workspace_for_dir(&dep, roots) {
                        covered.insert(dependency_workspace.to_string());
                    }
                }
            }
        }
        if covered.len() == before {
            break;
        }
    }
    Ok(covered)
}

/// # Errors
///
/// Returns the workspace roots no workflow compiles.
pub fn run(root: &Path) -> Result<String, String> {
    let manifests = collect_manifests(root)?;
    let roots = workspace_roots(&manifests);
    if roots.is_empty() {
        return Err(String::from("no Cargo workspace was discovered"));
    }
    let covered = covered_workspaces(root, &roots, &manifests)?;
    let missing: Vec<&str> = roots
        .iter()
        .filter(|root| !covered.contains(*root))
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "workflows do not compile these Cargo workspaces: {}",
            missing.join(", ")
        ));
    }
    Ok(format!(
        "workflows_cover_every_workspace OK: {} workspace(s) compiled by a workflow",
        roots.len()
    ))
}

fn fixture(root: &Path, workflow: &str) -> Result<(), String> {
    std::fs::create_dir_all(root.join(".github/workflows")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(root.join("crates/a")).map_err(|e| e.to_string())?;
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\na = { path = \"crates/a\" }\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        root.join("crates/a/Cargo.toml"),
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(root.join(".github/workflows/ci.yml"), workflow).map_err(|e| e.to_string())
}

/// # Errors
///
/// Returns a finding when a canary does not behave as the gate promises.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-workspace-cover")?;
    let result = (|| {
        let good = "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test --workspace\n";
        fixture(&dir, good)?;
        run(&dir)?;

        fixture(&dir, "name: ci\non: [push]\njobs:\n  build:\n    steps:\n      - run: echo nothing\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an uncovered workspace passed"));
        }

        fixture(&dir, "name: ci\njobs:\n  build:\n    steps:\n      # cargo test --workspace\n      - run: echo comment\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a commented cargo command counted"));
        }

        fixture(&dir, "name: ci\njobs:\n  build:\n    steps:\n      - continue-on-error: true\n        run: cargo test --workspace\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a softened build counted"));
        }

        fixture(&dir, "name: ci\njobs:\n  build:\n    steps:\n      - run: cargo fmt --all\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: cargo fmt counted as a compile"));
        }
        Ok(String::from(
            "workflows_cover_every_workspace canary OK: path dependency coverage passes, missing/commented/softened/fmt-only coverage fails",
        ))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn workflows_cover_every_workspace_catches_injected_uncovered_workspace() {
        super::self_test().expect("workspace coverage canary");
    }
}
