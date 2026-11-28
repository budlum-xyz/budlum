//! A red workflow step keeps the words that explain it.
//!
//! # Why this gate exists
//!
//! `Stage 1 (independent)` went red on `testnet` with one annotation:
//!
//! ```text
//! [ failure ] .github : 11 - 11  "Process completed with exit code 101."
//! ```
//!
//! The job log held a single line of cause:
//!
//! ```text
//! error: could not compile `budlum-core` (lib) due to 9 previous errors
//! ```
//!
//! Nine diagnostics had been produced and none of them reached the log,
//! because the step ended in
//!
//! ```yaml
//! cargo build --release 2>&1 | tail -5
//! ```
//!
//! The summary line fit in five lines; the nine errors that explain it did not.
//! Recovering them meant rebuilding the crate outside CI - a toolchain
//! install, a protoc pin, a swap file and thirty minutes - to learn what
//! rustc had already printed. That cost was paid more than once on this
//! branch, always for the same reason, so it belongs in a gate rather than in
//! a note asking writers to remember.
//!
//! # The shapes refused
//!
//! Three ways a `run:` block makes a red step undiagnosable, each mechanical:
//!
//!   1. **Truncated build log.** A `cargo build|check|test|clippy|run` (or
//!      `pytest`) invocation piped into `tail`. The exit status still travels
//!      through `pipefail`, so the job is red for the right reason and silent
//!      about it - the worst combination.
//!   2. **Swallowed outcome.** A live `continue-on-error: true`. The step
//!      reports success whatever happened, so the log that would have
//!      explained the failure is never looked at.
//!   3. **Swallowed exit status.** A live `|| true` on a line that runs a
//!      build or a test. Same outcome as (2), spelled smaller.
//!
//! # What it deliberately does not flag
//!
//! Comment lines. This tree documents its own hardening - several workflows
//! carry a comment explaining that `continue-on-error: true` was removed and
//! why - and a gate that flags the explanation of a fix would force writers to
//! delete the explanation. Only the executed YAML is read.
//!
//! `tail` on a command that carries no diagnosis is also allowed:
//! `cargo clean 2>&1 | tail -3` only hides a line about removing files.

use std::path::{Path, PathBuf};

/// Builds and tests whose failure explanation lives in their own output.
const DIAGNOSTIC_COMMANDS: [&str; 7] = [
    "cargo build",
    "cargo check",
    "cargo test",
    "cargo clippy",
    "cargo run",
    "cargo nextest",
    "pytest",
];

fn workflow_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let dir = root.join(".github/workflows");
    let entries =
        std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "yml" || e == "yaml");
        if is_yaml {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn runs_a_diagnostic_command(line: &str) -> bool {
    DIAGNOSTIC_COMMANDS.iter().any(|c| line.contains(c))
}

/// A `run:` command piped into `tail`, where the command's own output is the
/// only place the reason for a failure ever appears.
fn is_truncated_diagnostic(line: &str) -> bool {
    if !line.contains('|') || !line.contains("tail") {
        return false;
    }
    // The pipe must feed tail, not merely appear somewhere on the line.
    let Some((left, right)) = line.split_once('|') else {
        return false;
    };
    runs_a_diagnostic_command(left) && right.trim_start().starts_with("tail")
}

/// A `|| true` that swallows the exit status of a build or a test.
fn is_swallowed_status(line: &str) -> bool {
    line.contains("|| true") && runs_a_diagnostic_command(line)
}

/// # Errors
///
/// Returns one finding per workflow line that would make a red step
/// undiagnosable.
pub fn run(root: &Path) -> Result<String, String> {
    let files = workflow_files(root)?;
    if files.is_empty() {
        return Err(String::from(
            "no workflow files found - this gate would be vacuous",
        ));
    }
    let mut findings: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for path in &files {
        let body = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        for (idx, raw) in body.lines().enumerate() {
            scanned += 1;
            let line = raw.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if is_truncated_diagnostic(line) {
                findings.push(format!(
                    "{rel}:{} truncates a build log into `tail`, so a red step keeps its exit\n  \
                     status and loses its reason. Keep the whole output and still fail on the\n  \
                     compiler: `{cmd} 2>&1 | tee /tmp/build.log; exit \"${{PIPESTATUS[0]}}\"`",
                    idx + 1,
                    cmd = DIAGNOSTIC_COMMANDS
                        .iter()
                        .find(|c| line.contains(**c))
                        .copied()
                        .unwrap_or("cargo build"),
                ));
            }
            if line.starts_with("continue-on-error:") && line.contains("true") {
                findings.push(format!(
                    "{rel}:{} reports success whatever the step did, so the log that would\n  \
                     explain the failure is never read. Remove it or narrow it to a single\n  \
                     named step whose failure is genuinely not a finding",
                    idx + 1
                ));
            }
            if is_swallowed_status(line) {
                findings.push(format!(
                    "{rel}:{} swallows the exit status of a build or test with `|| true`",
                    idx + 1
                ));
            }
        }
    }
    if !findings.is_empty() {
        return Err(format!(
            "{} workflow step(s) make a red build undiagnosable:\n\n{}",
            findings.len(),
            findings.join("\n\n")
        ));
    }
    Ok(format!(
        "Red steps keep their words: {} workflow file(s), {scanned} line(s), no truncated build\n  \
         logs, no `continue-on-error: true`, no `|| true` on a build or test.",
        files.len()
    ))
}

/// # Errors
///
/// Returns a finding when a canary that must be refused is accepted, or a
/// clean workflow is refused.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-red-keeps-words")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        let clear = || -> Result<(), String> {
            let d = dir.join(".github/workflows");
            if d.exists() {
                std::fs::remove_dir_all(&d).map_err(|e| e.to_string())?;
            }
            Ok(())
        };

        // 1. A clean workflow passes: full output, tee, explicit status.
        put(
            ".github/workflows/clean.yml",
            "jobs:\n  b:\n    steps:\n      - name: build\n        run: |\n          cargo build --release 2>&1 | tee /tmp/b.log; exit \"${PIPESTATUS[0]}\"\n",
        )?;
        run(&dir).map_err(|e| format!("canary: a clean workflow was refused: {e}"))?;

        // 2. A comment explaining a removed mask must NOT be flagged. Writers
        //    document their own hardening, and flagging the explanation would
        //    force them to delete it.
        put(
            ".github/workflows/clean.yml",
            "jobs:\n  b:\n    steps:\n      # The old form carried `continue-on-error: true` and `|| true`.\n      - name: build\n        # cargo build was piped into `tail -5` before this fix.\n        run: cargo build --release\n",
        )?;
        run(&dir).map_err(|e| format!("canary: commented-out history was refused: {e}"))?;

        // 3. tail on a command that carries no diagnosis is allowed.
        put(
            ".github/workflows/clean.yml",
            "jobs:\n  b:\n    steps:\n      - name: clean\n        run: cargo clean 2>&1 | tail -3\n",
        )?;
        run(&dir).map_err(|e| format!("canary: cargo clean truncation was refused: {e}"))?;

        // 4. Truncating a build log is refused.
        put(
            ".github/workflows/truncated.yml",
            "jobs:\n  b:\n    steps:\n      - name: build\n        run: |\n          set -euo pipefail\n          cargo build --release 2>&1 | tail -5\n",
        )?;
        let err = run(&dir)
            .err()
            .ok_or_else(|| String::from("canary: a truncated build log was accepted"))?;
        if !err.contains("truncated.yml:7") {
            return Err(format!("canary: the finding did not name the line: {err}"));
        }
        clear()?;

        // 5. continue-on-error: true is refused.
        put(
            ".github/workflows/masked.yml",
            "jobs:\n  b:\n    steps:\n      - name: test\n        continue-on-error: true\n        run: cargo test\n",
        )?;
        run(&dir)
            .err()
            .ok_or_else(|| String::from("canary: continue-on-error: true was accepted"))?;
        clear()?;

        // 6. `|| true` on a test is refused.
        put(
            ".github/workflows/swallowed.yml",
            "jobs:\n  b:\n    steps:\n      - name: test\n        run: cargo test --all || true\n",
        )?;
        run(&dir)
            .err()
            .ok_or_else(|| String::from("canary: `cargo test --all || true` was accepted"))?;
        clear()?;

        // 7. An empty tree is refused rather than reported as clean.
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: a tree with no workflows passed - the gate would be vacuous",
            ));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "Red-step canaries: 3 accepted shapes (clean, commented history, non-diagnostic tail)\n  \
         and 4 refused shapes (truncated build, continue-on-error, `|| true`, empty tree).",
    ))
}
