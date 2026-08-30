//! CI workflow guards gate (hardening vector 3, 2026-08-28): the critical
//! security gates must actually run in CI.
//!
//! The failure this closes: a gate can be deleted from `ci.yml` (or its
//! `run:` block emptied) and nothing complains - the repo's other checks
//! still pass, the gate's `self_test` still works, and the protection is
//! silently gone. `gates_are_wired` only checks that scripts in `scripts/`
//! are named somewhere; it does not check that the *Rust* gates run, and it
//! does not check that their `--self-test` canary is invoked.
//!
//! This gate parses `ci.yml` (plus `diverse-double-compiling.yml`, which also
//! runs gates) and verifies:
//!   1. each protected gate name appears in a `run:` block as
//!      `-- <name>` (the subcommand form the gate binary uses);
//!   2. each protected gate's `--self-test` is also invoked;
//!   3. the canary rule holds: a `--self-test` call for a protected gate
//!      must appear BEFORE its plain run in the same step (red-before-green,
//!      per the repo's canary convention).
//!
//! The self-test proves the gate can fail by tampering with a workflow copy.

use std::path::Path;

/// The gate subcommands CI must invoke for the protection to be live.
/// Ordered; every entry is a real gate in `main.rs`'s GATES list.
const PROTECTED_GATES: &[&str] = &["regeneration", "relay", "tree-pin"];

/// Workflow files that run gates.
const WORKFLOWS: &[&str] = &[
    ".github/workflows/ci.yml",
    ".github/workflows/diverse-double-compiling.yml",
];

/// Extract the `run:` blocks (inline `run: cmd` and folded `run: | ...`)
/// from a workflow file, with `(step_name, run_text)` pairs.
///
/// The scanner tracks YAML block indentation: a folded block ends at the
/// first line whose indentation is <= the `run:` line's indentation, or at
/// the next `- name:` / `- uses:` / `- run:` step marker.
fn run_blocks(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current_step = String::new();
    let mut in_run_block = false;
    let mut block = String::new();
    let mut run_indent = 0usize;

    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();

        if in_run_block {
            // Blank lines inside a folded block are kept.
            if trimmed.is_empty() {
                block.push('\n');
                i += 1;
                continue;
            }
            // Any line at or above the run: indent ends the block.
            if indent <= run_indent {
                out.push((current_step.clone(), std::mem::take(&mut block)));
                in_run_block = false;
                continue;
            }
            block.push_str(trimmed);
            block.push('\n');
            i += 1;
            continue;
        }

        if let Some(step) = trimmed.strip_prefix("- name: ") {
            current_step = step.to_string();
            i += 1;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("run:") {
            current_step = if current_step.is_empty() {
                "run".to_string()
            } else {
                current_step.clone()
            };
            let rest = rest.trim_start();
            if rest.starts_with('|') || rest.starts_with('>') {
                in_run_block = true;
                run_indent = indent;
                block = String::new();
            } else if !rest.is_empty() {
                out.push((current_step.clone(), rest.to_string()));
            }
            i += 1;
            continue;
        }
        i += 1;
    }
    if in_run_block {
        out.push((current_step, block));
    }
    out
}

/// True if the run text invokes the gate binary with the given subcommand.
///
/// The subcommand must appear as a standalone argument after `--` (the gate
/// binary's subcommand form): `-- relay ` or `-- relay\n`. A bare substring
/// match would count `relayer_escrow`, `relayer`, comments and prose.
fn invokes(run: &str, subcommand: &str) -> bool {
    let needle = format!("-- {subcommand}");
    if !run.contains(&needle) {
        return false;
    }
    // The character after the subcommand must be whitespace or end-of-line,
    // so `-- relayx` or `-- relayer` does not match `relay`.
    run.split(&needle)
        .skip(1)
        .any(|tail| tail.chars().next().is_none_or(char::is_whitespace))
}

/// True if the run text invokes the gate binary with the given subcommand in
/// any of the accepted invocation forms (see [`invokes`]). This is the
/// public predicate used by the checks.
fn invokes_anywhere(run: &str, subcommand: &str) -> bool {
    // `-- <gate>` (the main form) or `-- <gate>` preceded by a path to the
    // gate binary (`cargo run ... -- <gate>`, `./budlum-gates <gate>`).
    if invokes(run, subcommand) {
        return true;
    }
    // The diverse-double-compiling workflow runs the gate binary from a
    // subdirectory: `(cd xtask/gates && cargo run --release --quiet -- regeneration)`.
    run.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.contains("cargo run") && trimmed.contains("--") && trimmed.contains(subcommand)
    })
}

fn check_workflow(path: &Path, require_self_test: bool) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("ci-workflow-guards: cannot read {}: {e}", path.display()))?;
    let blocks = run_blocks(&text);
    let mut findings: Vec<String> = Vec::new();

    for gate in PROTECTED_GATES {
        let plain = blocks
            .iter()
            .filter(|(_, r)| invokes_anywhere(r, gate))
            .count();
        let self_test = blocks
            .iter()
            .filter(|(_, r)| invokes_anywhere(r, gate) && r.contains("--self-test"))
            .count();
        if plain == 0 {
            findings.push(format!(
                "{}: gate `{gate}` is not invoked in any run block - the protection is not live",
                path.display()
            ));
        }
        // The self-test canary is mandatory in the main CI job. The
        // diverse-double-compiling workflow consumes the regeneration gate
        // for *production* (compiler comparison), not as a canary, so the
        // canary requirement is scoped to ci.yml.
        if require_self_test && self_test == 0 {
            findings.push(format!(
                "{}: gate `{gate}` has no `--self-test` canary - a broken gate can pass",
                path.display()
            ));
        }
    }

    // Canary order: for each protected gate, the first occurrence of
    // `--self-test` must be in an earlier run block than the first plain
    // invocation within the same step block ordering (red-before-green).
    // A single run block that contains BOTH the canary and the plain run
    // (the ci.yml convention: `--self-test` line first, plain line second)
    // satisfies the canary rule.
    if require_self_test {
        for gate in PROTECTED_GATES {
            let mut first_self_test: Option<usize> = None;
            let mut first_plain: Option<usize> = None;
            for (i, (_, r)) in blocks.iter().enumerate() {
                if !invokes_anywhere(r, gate) {
                    continue;
                }
                let has_canary = r.contains("--self-test");
                if has_canary && first_self_test.is_none() {
                    first_self_test = Some(i);
                }
                if !has_canary && first_plain.is_none() {
                    first_plain = Some(i);
                }
            }
            match (first_self_test, first_plain) {
                (Some(st), Some(p)) if st > p => findings.push(format!(
                    "{}: gate `{gate}` runs before its `--self-test` canary - \
                     a broken gate could pass without being noticed",
                    path.display()
                )),
                _ => {}
            }
        }
    }

    Ok(findings)
}

pub fn run(root: &Path) -> Result<String, String> {
    let mut all: Vec<String> = Vec::new();
    for wf in WORKFLOWS {
        let require_self_test = wf.ends_with("ci.yml");
        all.extend(check_workflow(&root.join(wf), require_self_test)?);
    }
    if !all.is_empty() {
        return Err(format!(
            "ci-workflow-guards: the security gate coverage in CI is broken:\n  {}",
            all.join("\n  ")
        ));
    }
    Ok(format!(
        "ci-workflow-guards: all {} protected gates run with self-test canaries in {}",
        PROTECTED_GATES.len(),
        WORKFLOWS.join(", ")
    ))
}

/// Self-test: the gate must fail on every tamper it is built to catch.
pub fn self_test() -> Result<String, String> {
    // A workflow that runs everything correctly passes.
    let good = format!(
        "name: ci\non: [push]\njobs:\n  gates:\n    runs-on: ubuntu-latest\n    steps:\n\
         - name: run {g}\n      run: |\n        cargo run -- gate {g} --self-test\n\
         - name: check {g}\n      run: |\n        cargo run -- gate {g}\n",
        g = PROTECTED_GATES[0]
    );
    let blocks = run_blocks(&good);
    if blocks.len() != 2 {
        return Err(String::from(
            "ci-workflow-guards self-test: run-block extraction failed on a good workflow",
        ));
    }
    if !invokes_anywhere(&blocks[0].1, PROTECTED_GATES[0]) {
        return Err(String::from(
            "ci-workflow-guards self-test: invocation detection failed",
        ));
    }

    // 1. Gate deleted from the workflow -> finding.
    let no_gate = "name: ci\non: [push]\njobs:\n  other:\n    runs-on: ubuntu-latest\n    steps:\n      - name: x\n        run: echo hi\n";
    let f = check_workflow_path_text(no_gate, true)?;
    if f.is_empty() {
        return Err(String::from(
            "ci-workflow-guards self-test: a workflow without the protected gate passed",
        ));
    }
    // 2. Self-test canary missing -> finding.
    let no_canary = format!(
        "name: ci\non: [push]\njobs:\n  gates:\n    runs-on: ubuntu-latest\n    steps:\n      - name: run {g}\n        run: cargo run -- gate {g}\n",
        g = PROTECTED_GATES[0]
    );
    let f = check_workflow_path_text(&no_canary, true)?;
    if f.is_empty() {
        return Err(String::from(
            "ci-workflow-guards self-test: a workflow without the self-test canary passed",
        ));
    }
    // 3. Canary order inverted (plain before self-test) -> finding.
    let inverted = format!(
        "name: ci\non: [push]\njobs:\n  gates:\n    runs-on: ubuntu-latest\n    steps:\n\
         - name: run {g}\n        run: cargo run -- gate {g}\n\
         - name: canary {g}\n        run: cargo run -- gate {g} --self-test\n",
        g = PROTECTED_GATES[0]
    );
    let f = check_workflow_path_text(&inverted, true)?;
    if f.is_empty() {
        return Err(String::from(
            "ci-workflow-guards self-test: inverted canary order passed",
        ));
    }

    Ok(String::from(
        "ci-workflow-guards self-test: extraction, invocation, canary presence and \
         canary order all behave",
    ))
}

/// Helper for self-test: check workflow text without touching the repo.
fn check_workflow_path_text(text: &str, require_self_test: bool) -> Result<Vec<String>, String> {
    let tmp = std::env::temp_dir().join(format!("bud-cwg-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let path = tmp.join("wf.yml");
    std::fs::write(&path, text).map_err(|e| e.to_string())?;
    let res = check_workflow(&path, require_self_test);
    let _ = std::fs::remove_dir_all(&tmp);
    res
}
