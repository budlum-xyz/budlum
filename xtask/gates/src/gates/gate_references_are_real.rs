//! Every gate name a workflow invokes must be a gate that exists.
//!
//! # The failure this closes
//!
//! `watchdog.yml` ran `./xtask/gates/target/release/budlum-gates
//! state-recovery-door` on a tree whose gate binary answers only to
//! `regen-health-door`. The step failed with ``FAIL: no gate named
//! `state-recovery-door`.`` and the scheduled pulse went red on every run
//! until somebody read the log. Nothing else saw it: `actionlint` parses the
//! YAML, `workflows_produce_jobs` confirms the file produces jobs,
//! `ci_workflow_guards` confirms three *protected* gates are invoked, and
//! `gates_are_wired` confirms `scripts/check-*.sh` files are named. A
//! reference to a gate that does not exist is the one shape none of them asks
//! about.
//!
//! The same drift is reachable in the other direction: a gate is renamed or
//! deleted while a workflow still calls the old name, and the rename reads as
//! a cleanup.
//!
//! # What is checked
//!
//! 1. The gate-name table is read out of `xtask/gates/src/main.rs`'s `GATES`
//!    array, so a name that is only a file on disk cannot satisfy the gate.
//! 2. Every line of `.github/workflows/*.{yml,yaml}` that invokes
//!    `budlum-gates` with a bare positional name is checked against that
//!    table. Flags (`--all`, `--list`, `--self-test`) are not names, and a
//!    comment line is not an invocation.
//! 3. A name no gate answers to is a failure that names the file and line.
//!
//! # Self-test
//!
//! The check is factored into [`probe`], which takes the workflow text and
//! the name table. The self-test feeds it a synthetic workflow and a synthetic
//! table, so it proves the gate can fail without depending on which gates this
//! branch happens to carry.

use std::path::{Path, PathBuf};

/// One `budlum-gates <name>` invocation found in a workflow.
struct Invocation {
    line: usize,
    name: String,
}

/// The gate names declared in `main.rs`'s `GATES` array.
///
/// Only the array is read. `name:` appears nowhere else in the file, but the
/// scan still starts at `const GATES` and stops at its closing `];` so a
/// future second table cannot be silently merged in.
fn declared_gate_names(main_rs: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_table = false;
    for line in main_rs.lines() {
        if !in_table {
            if line.starts_with("const GATES") {
                in_table = true;
            }
            continue;
        }
        if line.starts_with("];") {
            break;
        }
        let Some(rest) = line.trim().strip_prefix("name: \"") else {
            continue;
        };
        let Some(end) = rest.find('"') else {
            continue;
        };
        names.push(rest[..end].to_string());
    }
    names
}

/// The invocations in one workflow file that name a gate not in `names`.
fn probe(text: &str, names: &[String]) -> Vec<Invocation> {
    let mut bad = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for (position, token) in tokens.iter().enumerate() {
            if !token.ends_with("budlum-gates") {
                continue;
            }
            let Some(next) = tokens.get(position + 1) else {
                continue;
            };
            let name = next.trim_matches(|c| c == '"' || c == '\'');
            // `--all`, `--list` and `--self-test` are flags, not gate names.
            if name.is_empty() || name.starts_with("--") || name.contains('=') {
                continue;
            }
            if !names.iter().any(|declared| declared == name) {
                bad.push(Invocation {
                    line: index + 1,
                    name: name.to_string(),
                });
            }
        }
    }
    bad
}

/// Every workflow file under `.github/workflows`, sorted for a stable report.
fn workflow_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let dir = root.join(".github/workflows");
    let entries =
        std::fs::read_dir(&dir).map_err(|e| format!("{}: cannot read ({e})", dir.display()))?;
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if extension == "yml" || extension == "yaml" {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// # Errors
///
/// When the gate table cannot be read, a workflow cannot be read, or an
/// invocation names a gate that does not exist.
pub fn run(root: &Path) -> Result<String, String> {
    let main_rs = std::fs::read_to_string(root.join("xtask/gates/src/main.rs"))
        .map_err(|e| format!("xtask/gates/src/main.rs: cannot read ({e})"))?;
    let names = declared_gate_names(&main_rs);
    if names.is_empty() {
        return Err(String::from(
            "no gate names parsed out of the GATES array in xtask/gates/src/main.rs",
        ));
    }

    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for file in workflow_files(root)? {
        let text = std::fs::read_to_string(&file)
            .map_err(|e| format!("{}: cannot read ({e})", file.display()))?;
        for invocation in probe(&text, &names) {
            problems.push(format!(
                "{}:{}: `budlum-gates {}` names no gate in the GATES array",
                file.display(),
                invocation.line,
                invocation.name
            ));
        }
        checked += 1;
    }

    if problems.is_empty() {
        Ok(format!(
            "{checked} workflow(s) invoke only gates that exist ({} gates declared).",
            names.len()
        ))
    } else {
        Err(problems.join("\n"))
    }
}

/// # Errors
///
/// When the gate accepts a name that is not in the table, or rejects one that
/// is.
pub fn self_test() -> Result<String, String> {
    let names = vec!["real-gate".to_string(), "other-gate".to_string()];

    let clean = "run: ./x/budlum-gates real-gate\nrun: ./x/budlum-gates --self-test\n";
    if !probe(clean, &names).is_empty() {
        return Err(String::from(
            "gate-references-are-real reported a gate name that is in the table",
        ));
    }

    let bogus = "run: ./x/budlum-gates no-such-gate\n";
    let found = probe(bogus, &names);
    if found.len() != 1 || found[0].name != "no-such-gate" || found[0].line != 1 {
        return Err(String::from(
            "gate-references-are-real did not catch an unknown gate name",
        ));
    }

    let commented = "# ./x/budlum-gates no-such-gate\n";
    if !probe(commented, &names).is_empty() {
        return Err(String::from(
            "gate-references-are-real counted a comment as an invocation",
        ));
    }

    Ok(String::from(
        "gate-references-are-real passes a real gate name, a flag and a comment, and catches an unknown name.",
    ))
}
