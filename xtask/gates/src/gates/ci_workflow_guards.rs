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

/// One `run:` block of a workflow step.
struct RunBlock {
    /// The step's `name:` (or `run` when it has none).
    step: String,
    /// The block's command lines, YAML comment lines dropped.
    lines: Vec<String>,
    /// Why the step cannot be counted as a live gate run (`continue-on-error`,
    /// a constant-false or failure-only `if:`), or `None`.
    softened: Option<String>,
}

/// Why a step-level `key: value` pair makes the step non-binding, if it does.
fn softening(key: &str, value: &str) -> Option<String> {
    let value = value.trim();
    let bare = value
        .trim_start_matches("${{")
        .trim_end_matches("}}")
        .trim()
        .trim_matches(|c| c == '\'' || c == '"')
        .trim();
    match key {
        "continue-on-error" if !bare.eq_ignore_ascii_case("false") => {
            Some(format!("continue-on-error: {value}"))
        }
        "if" if bare.eq_ignore_ascii_case("false")
            || bare == "0"
            || bare.is_empty()
            || bare.contains("failure()")
            || bare.contains("cancelled()") =>
        {
            Some(format!("if: {value}"))
        }
        _ => None,
    }
}

/// Keys that can open a step as `- key: value`.
fn is_step_key(body: &str) -> bool {
    [
        "name:",
        "uses:",
        "run:",
        "id:",
        "if:",
        "env:",
        "with:",
        "shell:",
        "working-directory:",
        "continue-on-error:",
        "timeout-minutes:",
    ]
    .iter()
    .any(|k| body.starts_with(k))
}

/// Extract the `run:` blocks (inline `run: cmd` and folded `run: | ...`)
/// from a workflow file.
///
/// The scanner tracks YAML block indentation: a folded block ends at the
/// first line whose indentation is <= the `run:` key's indentation. A step
/// that starts with `- run:` is recognised, comment lines inside a block are
/// dropped, and the step's `continue-on-error` / `if:` keys are read so a
/// softened step is not counted as a live run.
fn run_blocks(text: &str) -> Vec<RunBlock> {
    struct Raw {
        step: String,
        lines: Vec<String>,
        step_idx: usize,
    }
    let mut raws: Vec<Raw> = Vec::new();
    let mut soft: Vec<Option<String>> = Vec::new();
    let mut step_idx = 0usize;
    let mut step_item_indent: Option<usize> = None;
    let mut current_step = String::new();
    let mut in_run_block = false;
    let mut block: Vec<String> = Vec::new();
    let mut run_indent = 0usize;

    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();

        if in_run_block {
            if trimmed.is_empty() {
                i += 1;
                continue;
            }
            // Any line at or above the run: key indent ends the block.
            if indent <= run_indent {
                raws.push(Raw {
                    step: current_step.clone(),
                    lines: std::mem::take(&mut block),
                    step_idx,
                });
                in_run_block = false;
                continue;
            }
            if !trimmed.starts_with('#') {
                block.push(trimmed.to_string());
            }
            i += 1;
            continue;
        }

        let (is_item, body) = match trimmed.strip_prefix("- ") {
            Some(b) => (true, b.trim_start()),
            None => (false, trimmed),
        };
        let key_indent = if is_item { indent + 2 } else { indent };
        if is_item && is_step_key(body) && step_item_indent.is_none_or(|s| indent <= s) {
            soft.push(None);
            step_idx = soft.len() - 1;
            step_item_indent = Some(indent);
            current_step = String::from("run");
        }
        let at_step_key = step_item_indent.is_some_and(|s| key_indent == s + 2);
        if at_step_key {
            if let Some(step) = body.strip_prefix("name: ") {
                current_step = step.to_string();
            } else if let Some(rest) = body.strip_prefix("run:") {
                let rest = rest.trim_start();
                if rest.starts_with('|') || rest.starts_with('>') {
                    in_run_block = true;
                    run_indent = key_indent;
                    block = Vec::new();
                } else if !rest.is_empty() && !rest.starts_with('#') {
                    raws.push(Raw {
                        step: current_step.clone(),
                        lines: vec![rest.to_string()],
                        step_idx,
                    });
                }
            } else if let Some((key, value)) = body.split_once(':') {
                if let Some(why) = softening(key.trim(), value) {
                    soft[step_idx] = Some(why);
                }
            }
        }
        i += 1;
    }
    if in_run_block {
        raws.push(Raw {
            step: current_step,
            lines: block,
            step_idx,
        });
    }
    raws.into_iter()
        .map(|r| RunBlock {
            step: r.step,
            lines: r.lines,
            softened: soft.get(r.step_idx).cloned().flatten(),
        })
        .collect()
}

/// One gate-binary invocation found on a command line.
struct Invocation {
    gate: String,
    self_test: bool,
}

/// Parse a command line as an invocation of the gate binary:
/// `cargo run ... xtask/gates/... -- <gate> [--self-test]`, also inside a
/// subshell `(cd xtask/gates && cargo run ... -- <gate>)`.
///
/// The subcommand is the token directly after the first standalone `--`, so
/// `cargo run -p budlum-relayer`, a YAML comment, or another gate's
/// `--self-test` on a different line cannot satisfy a protected gate.
fn parse_invocation(line: &str) -> Option<Invocation> {
    let line = line.trim();
    if line.starts_with('#') || !line.contains("cargo run") || !line.contains("xtask/gates") {
        return None;
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let dashes = tokens.iter().position(|t| *t == "--")?;
    let gate = tokens
        .get(dashes + 1)?
        .trim_end_matches([')', ';', '&', '|']);
    if gate.is_empty() || gate.starts_with('-') {
        return None;
    }
    let self_test = tokens[dashes + 2..]
        .iter()
        .any(|t| t.trim_end_matches([')', ';']) == "--self-test");
    Some(Invocation {
        gate: gate.to_string(),
        self_test,
    })
}

/// Position of an invocation: (block index, line index).
type Pos = (usize, usize);

fn check_workflow(path: &Path, require_self_test: bool) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("ci-workflow-guards: cannot read {}: {e}", path.display()))?;
    Ok(check_text(
        &text,
        &path.display().to_string(),
        require_self_test,
    ))
}

fn check_text(text: &str, label: &str, require_self_test: bool) -> Vec<String> {
    let blocks = run_blocks(text);
    let mut findings: Vec<String> = Vec::new();

    for gate in PROTECTED_GATES {
        let mut plain: Vec<Pos> = Vec::new();
        let mut canary: Vec<Pos> = Vec::new();
        for (bi, b) in blocks.iter().enumerate() {
            for (li, l) in b.lines.iter().enumerate() {
                let Some(inv) = parse_invocation(l) else {
                    continue;
                };
                if inv.gate != *gate {
                    continue;
                }
                if let Some(why) = &b.softened {
                    findings.push(format!(
                        "{label}: gate `{gate}` runs in step `{}` which is softened ({why}) - \
                         a failing gate would not fail the job",
                        b.step
                    ));
                    continue;
                }
                if inv.self_test {
                    canary.push((bi, li));
                } else {
                    plain.push((bi, li));
                }
            }
        }
        if plain.is_empty() {
            findings.push(format!(
                "{label}: gate `{gate}` is not invoked in any live run block - \
                 the protection is not live"
            ));
        }
        // The self-test canary is mandatory in the main CI job. The
        // diverse-double-compiling workflow consumes the regeneration gate
        // for *production* (compiler comparison), not as a canary, so the
        // canary requirement is scoped to ci.yml.
        if require_self_test {
            if canary.is_empty() {
                findings.push(format!(
                    "{label}: gate `{gate}` has no `--self-test` canary - a broken gate can pass"
                ));
            } else if let (Some(first_canary), Some(first_plain)) =
                (canary.iter().min(), plain.iter().min())
            {
                // Red-before-green: the canary line must come before the
                // first plain run, in the same block or an earlier one.
                if first_canary > first_plain {
                    findings.push(format!(
                        "{label}: gate `{gate}` runs before its `--self-test` canary - \
                         a broken gate could pass without being noticed"
                    ));
                }
            }
        }
    }
    findings
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

fn gate_line(gate: &str, self_test: bool) -> String {
    let suffix = if self_test { " --self-test" } else { "" };
    format!("cargo run --release --manifest-path xtask/gates/Cargo.toml -- {gate}{suffix}")
}

const FIXTURE_HEAD: &str =
    "name: ci\non: [push]\njobs:\n  gates:\n    runs-on: ubuntu-latest\n    steps:\n";

/// Build a workflow with one step per protected gate. `extra` is an optional
/// step-level key line, and `lines(gate)` gives the step's run lines.
fn workflow_with(extra: &str, lines: impl Fn(&str) -> Vec<String>) -> String {
    let mut out = String::from(FIXTURE_HEAD);
    for gate in PROTECTED_GATES {
        out.push_str(&format!("      - name: {gate} + canary\n"));
        if !extra.is_empty() {
            out.push_str(&format!("        {extra}\n"));
        }
        out.push_str("        run: |\n");
        for l in lines(gate) {
            out.push_str(&format!("          {l}\n"));
        }
    }
    out
}

/// Self-test: the gate must fail on every tamper it is built to catch.
///
/// # Errors
///
/// Returns a finding when a tampered workflow passes or a good one fails.
pub fn self_test() -> Result<String, String> {
    let good = |g: &str| vec![gate_line(g, true), gate_line(g, false)];
    let expect_red = |name: &str, text: &str| -> Result<(), String> {
        if check_text(text, "fixture", true).is_empty() {
            Err(format!("ci-workflow-guards self-test: {name} passed"))
        } else {
            Ok(())
        }
    };

    let good_wf = workflow_with("", good);
    let blocks = run_blocks(&good_wf);
    if blocks.len() != PROTECTED_GATES.len() || blocks.iter().any(|b| b.lines.len() != 2) {
        return Err(String::from(
            "ci-workflow-guards self-test: run-block extraction failed on a good workflow",
        ));
    }
    let f = check_text(&good_wf, "fixture", true);
    if !f.is_empty() {
        return Err(format!(
            "ci-workflow-guards self-test: a workflow that runs everything correctly was refused: {}",
            f.join("; ")
        ));
    }

    // 1. Gate deleted from the workflow.
    expect_red(
        "a workflow without the protected gates",
        "name: ci\non: [push]\njobs:\n  other:\n    runs-on: ubuntu-latest\n    steps:\n      - name: x\n        run: echo hi\n",
    )?;
    // 2. Self-test canary missing.
    expect_red(
        "a workflow without the self-test canary",
        &workflow_with("", |g| vec![gate_line(g, false)]),
    )?;
    // 3. Canary order inverted (plain before self-test).
    expect_red(
        "an inverted canary order",
        &workflow_with("", |g| vec![gate_line(g, false), gate_line(g, true)]),
    )?;
    // 4. The plain invocation survives only as a YAML comment.
    expect_red(
        "a commented-out invocation",
        &workflow_with("", |g| {
            vec![gate_line(g, true), format!("# {}", gate_line(g, false))]
        }),
    )?;
    // 5. A step with continue-on-error, a constant-false `if:`, or a
    //    failure-only `if:`.
    for (extra, label) in [
        ("continue-on-error: true", "a continue-on-error step"),
        ("if: false", "an `if: false` step"),
        ("if: ${{ failure() }}", "a failure-only step"),
    ] {
        expect_red(label, &workflow_with(extra, good))?;
    }
    // 6. A lookalike command that merely contains the gate name, and another
    //    gate's canary in the same block, must not satisfy the gate.
    expect_red(
        "a lookalike command and a foreign canary",
        &workflow_with("", |g| {
            vec![
                format!("cargo run --release -p budlum-{g}er"),
                gate_line("other", true),
                gate_line("other", false),
            ]
        }),
    )?;
    // 7. The `- run:` step form and the subshell form of the diverse
    //    double-compiling workflow are read.
    let ddc = "name: ddc\njobs:\n  j:\n    steps:\n      - run: (cd xtask/gates && cargo run --release --quiet -- regeneration) > /tmp/x 2>&1\n";
    let found = run_blocks(ddc)
        .iter()
        .flat_map(|b| b.lines.iter())
        .filter_map(|l| parse_invocation(l))
        .any(|inv| inv.gate == "regeneration" && !inv.self_test);
    if !found {
        return Err(String::from(
            "ci-workflow-guards self-test: the `- run:` subshell form was not read",
        ));
    }

    Ok(String::from(
        "ci-workflow-guards self-test: extraction, invocation, comments, softened steps, \
         lookalikes, canary presence and canary order all behave",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() {
        super::self_test().expect("ci-workflow-guards self-test");
    }
}
