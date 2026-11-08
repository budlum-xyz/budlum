//! Every Security & Quality scanner, SARIF upload, coverage upload, and
//! dependency-graph submission must remain wired in `.github/workflows/`.
//!
//! # Why this gate exists
//!
//! Adding a scanner workflow without a gate that enforces its wiring leaves the
//! integration fragile: dropping an `upload-sarif` category, reverting the
//! Dependency Submission endpoint URL, removing Cobertura coverage upload,
//! reverting the runtime container image back to an OS-advisory-laden base, or
//! omitting `consensus-of-consensuses` from a PR gate's `pull_request` branch
//! filter all leave `cargo test` green while silently blinding GitHub's
//! Security & Quality surfaces.
//!
//! This gate checks six structural properties across the repository:
//!   1. All 16 `github/codeql-action/upload-sarif@<sha>` categories plus the
//!      `github/codeql-action/analyze@<sha>` job are present across
//!      `.github/workflows/`, and every workflow that uploads SARIF grants
//!      `security-events: write`.
//!   2. Every `xtask/tools` `sarif` conversion in `.github/workflows/` runs
//!      `sarif --self-test` before `sarif <tool>`.
//!   3. `.github/workflows/ci.yml` uploads Cobertura XML via a SHA-pinned
//!      `actions/upload-code-coverage@<40-hex>` step and invokes this gate
//!      (`security-quality-tools-are-wired --self-test` before plain run).
//!   4. `.github/workflows/dependency-submission.yml` runs
//!      `dependency-snapshot --self-test` before `--submit`, grants
//!      `contents: write`, carries no `pull_request` trigger, and
//!      `xtask/tools/src/dep_snapshot.rs` posts to GitHub's
//!      `/dependency-graph/snapshots` endpoint.
//!   5. `ops/Dockerfile` runs its final stage on a digest-pinned Chainguard
//!      Wolfi base (`cgr.dev/chainguard/wolfi-base@sha256:`) under numeric
//!      non-root `USER 1000`.
//!   6. Every PR security/quality gate workflow includes
//!      `consensus-of-consensuses` in its `pull_request` branch list when it
//!      filters `pull_request` by `branches:`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Every SARIF `category:` that must be uploaded by `.github/workflows/`.
const REQUIRED_SARIF_CATEGORIES: &[&str] = &[
    "actionlint",
    "aderyn",
    "cargo-audit",
    "cargo-deny",
    "cargo-geiger",
    "clippy",
    "gitleaks",
    "grype",
    "hadolint",
    "osv-scanner",
    "scorecard",
    "semgrep",
    "trivy-config",
    "trivy-fs",
    "trivy-image",
];

/// PR security and quality workflows that filter `pull_request` by branch and
/// must cover `consensus-of-consensuses` alongside `main`.
const REQUIRED_PR_BRANCH_WORKFLOWS: &[&str] = &[
    "audit-guard.yml",
    "benchmark.yml",
    "cargo-vet.yml",
    "ci.yml",
    "code-scanning-sarif.yml",
    "dependency-review.yml",
    "determinism.yml",
    "docker-smoke.yml",
    "extra-tooling.yml",
    "grype.yml",
    "miri.yml",
    "osv-scanner.yml",
    "rust.yml",
    "security-audit.yml",
    "semgrep.yml",
    "solidity.yml",
    "supply-chain-extra.yml",
    "typos.yml",
];

/// Additional branch-filtered PR gate workflows introduced in stacked branches;
/// enforced whenever present in `.github/workflows`.
const OPTIONAL_PR_BRANCH_WORKFLOWS: &[&str] = &["pkcs11-pq.yml", "release-signature.yml"];

/// In-memory snapshot of the files this gate inspects so `--self-test` can
/// mutate copies without touching the working tree.
#[derive(Clone)]
struct RepoSnapshot {
    workflows: BTreeMap<String, String>,
    dockerfile: String,
    dep_snapshot_rs: String,
}

impl RepoSnapshot {
    fn load(root: &Path) -> Result<Self, String> {
        let wf_dir = root.join(".github/workflows");
        let entries = std::fs::read_dir(&wf_dir)
            .map_err(|e| format!("cannot read {}: {e}", wf_dir.display()))?;
        let mut workflows = BTreeMap::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
                continue;
            };
            if !ext.eq_ignore_ascii_case("yml") && !ext.eq_ignore_ascii_case("yaml") {
                continue;
            }
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let content = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            workflows.insert(name.to_string(), content);
        }
        let dockerfile_path = root.join("ops/Dockerfile");
        let dockerfile = std::fs::read_to_string(&dockerfile_path)
            .map_err(|e| format!("cannot read {}: {e}", dockerfile_path.display()))?;
        let dep_path = root.join("xtask/tools/src/dep_snapshot.rs");
        let dep_snapshot_rs = std::fs::read_to_string(&dep_path)
            .map_err(|e| format!("cannot read {}: {e}", dep_path.display()))?;
        Ok(Self {
            workflows,
            dockerfile,
            dep_snapshot_rs,
        })
    }
}

fn has_sha40_pin(line: &str, action_prefix: &str) -> bool {
    let Some(pos) = line.find(action_prefix) else {
        return false;
    };
    let rest = &line[pos + action_prefix.len()..];
    let sha: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
    sha.len() == 40
}

fn non_comment_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

fn check_sarif_wiring(snap: &RepoSnapshot, findings: &mut Vec<String>) {
    let mut seen_categories = BTreeSet::new();
    let mut saw_codeql_analyze = false;
    let mut saw_zizmor_action = false;

    for (name, content) in &snap.workflows {
        let lines = non_comment_lines(content);
        let mut wf_uploads_sarif = false;
        for line in &lines {
            if has_sha40_pin(line, "github/codeql-action/analyze@") {
                saw_codeql_analyze = true;
                wf_uploads_sarif = true;
            }
            if has_sha40_pin(line, "zizmorcore/zizmor-action@") {
                saw_zizmor_action = true;
                wf_uploads_sarif = true;
            }
            if has_sha40_pin(line, "github/codeql-action/upload-sarif@") {
                wf_uploads_sarif = true;
            }
            if let Some(rest) = line.strip_prefix("category:") {
                let cat = rest
                    .split('#')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');
                if !cat.is_empty() {
                    seen_categories.insert(cat.to_string());
                }
            }
        }
        if wf_uploads_sarif && !lines.contains(&"security-events: write") {
            findings.push(format!(
                "{name}: uploads SARIF or runs CodeQL without `security-events: write`"
            ));
        }

        // Check red-before-green canary on `sarif` invocations in this workflow.
        let mut saw_sarif_canary = false;
        for (idx, line) in lines.iter().enumerate() {
            if line.contains("sarif --self-test") {
                saw_sarif_canary = true;
            } else if line.starts_with("sarif ")
                && !saw_sarif_canary
                && lines
                    .get(idx.saturating_sub(1))
                    .is_some_and(|prev| prev.contains("xtask/tools/Cargo.toml"))
            {
                findings.push(format!(
                    "{name}: invokes `budlum-tools sarif` before `sarif --self-test`"
                ));
            }
        }
    }

    if !saw_codeql_analyze {
        findings.push(
            "missing SHA-pinned `github/codeql-action/analyze@<40-hex>` in workflows".to_string(),
        );
    }
    if !saw_zizmor_action {
        findings.push(
            "missing SHA-pinned `zizmorcore/zizmor-action@<40-hex>` in workflows".to_string(),
        );
    }
    for required in REQUIRED_SARIF_CATEGORIES {
        if !seen_categories.contains(*required) {
            findings.push(format!(
                "missing SARIF category `{required}` across `.github/workflows/`"
            ));
        }
    }
}

fn check_ci_coverage_and_self_gate(snap: &RepoSnapshot, findings: &mut Vec<String>) {
    let Some(ci) = snap.workflows.get("ci.yml") else {
        findings.push("missing `.github/workflows/ci.yml`".to_string());
        return;
    };
    let lines = non_comment_lines(ci);
    if !lines
        .iter()
        .any(|l| has_sha40_pin(l, "actions/upload-code-coverage@"))
    {
        findings.push(
            "ci.yml: missing SHA-pinned `actions/upload-code-coverage@<40-hex>` step".to_string(),
        );
    }
    let canary_pos = lines.iter().position(|l| {
        l.contains("xtask/gates/Cargo.toml")
            && l.contains("-- security-quality-tools-are-wired --self-test")
    });
    let plain_pos = lines.iter().position(|l| {
        l.contains("xtask/gates/Cargo.toml") && l.ends_with("-- security-quality-tools-are-wired")
    });
    match (canary_pos, plain_pos) {
        (None, _) => findings.push(
            "ci.yml: missing `security-quality-tools-are-wired --self-test` canary".to_string(),
        ),
        (_, None) => findings
            .push("ci.yml: missing live `security-quality-tools-are-wired` invocation".to_string()),
        (Some(c), Some(p)) if c >= p => findings.push(
            "ci.yml: `security-quality-tools-are-wired` runs before its `--self-test` canary"
                .to_string(),
        ),
        (Some(_), Some(_)) => {}
    }
}

fn check_dependency_submission(snap: &RepoSnapshot, findings: &mut Vec<String>) {
    let Some(dep_wf) = snap.workflows.get("dependency-submission.yml") else {
        findings.push("missing `.github/workflows/dependency-submission.yml`".to_string());
        return;
    };
    let lines = non_comment_lines(dep_wf);
    if lines.iter().any(|l| l.starts_with("pull_request")) {
        findings.push(
            "dependency-submission.yml: must not trigger on `pull_request` (`contents: write`)"
                .to_string(),
        );
    }
    if !lines.contains(&"contents: write") {
        findings.push("dependency-submission.yml: missing `contents: write`".to_string());
    }
    let canary_pos = lines
        .iter()
        .position(|l| l.contains("dependency-snapshot --self-test"));
    let submit_pos = lines
        .iter()
        .position(|l| l.contains("dependency-snapshot") && l.contains("--submit"));
    match (canary_pos, submit_pos) {
        (None, _) => findings.push(
            "dependency-submission.yml: missing `dependency-snapshot --self-test` canary"
                .to_string(),
        ),
        (_, None) => findings.push(
            "dependency-submission.yml: missing `dependency-snapshot ... --submit` step"
                .to_string(),
        ),
        (Some(c), Some(s)) if c >= s => findings.push(
            "dependency-submission.yml: `--submit` runs before `dependency-snapshot --self-test`"
                .to_string(),
        ),
        (Some(_), Some(_)) => {}
    }

    if !snap
        .dep_snapshot_rs
        .contains("/repos/{repo}/dependency-graph/snapshots")
    {
        findings.push(
            "xtask/tools/src/dep_snapshot.rs: missing `/repos/{repo}/dependency-graph/snapshots` endpoint"
                .to_string(),
        );
    }
}

fn check_dockerfile_hardening(snap: &RepoSnapshot, findings: &mut Vec<String>) {
    let lines = non_comment_lines(&snap.dockerfile);
    let from_lines: Vec<&&str> = lines.iter().filter(|l| l.starts_with("FROM ")).collect();
    let Some(final_from) = from_lines.last() else {
        findings.push("ops/Dockerfile: no `FROM` instruction found".to_string());
        return;
    };
    if !final_from.starts_with("FROM cgr.dev/chainguard/wolfi-base@sha256:") {
        findings.push(format!(
            "ops/Dockerfile: final runtime stage must pin `cgr.dev/chainguard/wolfi-base@sha256:`, found `{final_from}`"
        ));
    }
    if !lines.contains(&"USER 1000") {
        findings.push("ops/Dockerfile: missing numeric non-root `USER 1000`".to_string());
    }
}

fn workflow_pr_has_branch(content: &str, branch: &str) -> bool {
    let mut in_on = false;
    let mut in_pr = false;
    let mut pr_indent = 0usize;
    for raw in content.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent == 0 {
            in_on = trimmed == "on:" || trimmed.starts_with("on:");
            in_pr = false;
            continue;
        }
        if !in_on {
            continue;
        }
        if in_pr && indent <= pr_indent {
            in_pr = false;
        }
        if trimmed.starts_with("pull_request:") {
            in_pr = true;
            pr_indent = indent;
            continue;
        }
        if in_pr && trimmed.contains(branch) {
            return true;
        }
    }
    false
}

fn check_pr_branch_coverage(snap: &RepoSnapshot, findings: &mut Vec<String>) {
    for wf in REQUIRED_PR_BRANCH_WORKFLOWS {
        let Some(content) = snap.workflows.get(*wf) else {
            findings.push(format!(
                "missing required PR gate workflow `.github/workflows/{wf}`"
            ));
            continue;
        };
        if !workflow_pr_has_branch(content, "consensus-of-consensuses") {
            findings.push(format!(
                "{wf}: `pull_request` trigger does not include `consensus-of-consensuses`"
            ));
        }
    }
    for wf in OPTIONAL_PR_BRANCH_WORKFLOWS {
        if let Some(content) = snap.workflows.get(*wf) {
            if !workflow_pr_has_branch(content, "consensus-of-consensuses") {
                findings.push(format!(
                    "{wf}: `pull_request` trigger does not include `consensus-of-consensuses`"
                ));
            }
        }
    }
}

fn evaluate(snap: &RepoSnapshot) -> Vec<String> {
    let mut findings = Vec::new();
    check_sarif_wiring(snap, &mut findings);
    check_ci_coverage_and_self_gate(snap, &mut findings);
    check_dependency_submission(snap, &mut findings);
    check_dockerfile_hardening(snap, &mut findings);
    check_pr_branch_coverage(snap, &mut findings);
    findings
}

/// Inspect the live repository root.
///
/// # Errors
///
/// Returns every missing or softened Security & Quality wiring invariant.
pub fn run(root: &Path) -> Result<String, String> {
    let snap = RepoSnapshot::load(root)?;
    let findings = evaluate(&snap);
    if !findings.is_empty() {
        return Err(format!(
            "security-quality-tools-are-wired found {} issue(s):\n  - {}",
            findings.len(),
            findings.join("\n  - ")
        ));
    }
    Ok(format!(
        "OK: CodeQL + {} SARIF categories, Cobertura coverage upload, Cargo dependency-graph \
         submission, Wolfi runtime pin, and {} PR gate branch triggers are all wired.",
        REQUIRED_SARIF_CATEGORIES.len(),
        REQUIRED_PR_BRANCH_WORKFLOWS.len()
    ))
}

/// Synthetic clean fixture + six negative tampers proving the gate is not vacuous.
///
/// # Errors
///
/// Fails if the clean fixture fails or if any of the six tampers passes.
pub fn self_test() -> Result<String, String> {
    let sha = "1111111111111111111111111111111111111111";
    let mut workflows = BTreeMap::new();
    for wf in REQUIRED_PR_BRANCH_WORKFLOWS {
        workflows.insert(
            (*wf).to_string(),
            "name: gate\non:\n  pull_request:\n    branches: [main, consensus-of-consensuses]\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
                .to_string(),
        );
    }

    let mut sarif_steps = String::from(
        "name: sarif\non:\n  pull_request:\n    branches: [main, consensus-of-consensuses]\npermissions:\n  contents: read\n  security-events: write\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: github/codeql-action/analyze@",
    );
    sarif_steps.push_str(sha);
    sarif_steps.push_str("\n      - uses: zizmorcore/zizmor-action@");
    sarif_steps.push_str(sha);
    sarif_steps.push_str("\n      - run: |\n          cargo run --release --manifest-path xtask/tools/Cargo.toml -- sarif --self-test\n          cargo run --release --manifest-path xtask/tools/Cargo.toml -- \\\n            sarif clippy /tmp/in.json out.sarif\n");
    for cat in REQUIRED_SARIF_CATEGORIES {
        sarif_steps.push_str("      - uses: github/codeql-action/upload-sarif@");
        sarif_steps.push_str(sha);
        sarif_steps.push_str("\n        with:\n          category: ");
        sarif_steps.push_str(cat);
        sarif_steps.push('\n');
    }
    workflows.insert("code-scanning-sarif.yml".to_string(), sarif_steps);

    let ci_yml = format!(
        "name: CI\non:\n  pull_request:\n    branches: [main, consensus-of-consensuses]\njobs:\n  cov:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/upload-code-coverage@{sha}\n  gates:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          cargo run --release --manifest-path xtask/gates/Cargo.toml -- security-quality-tools-are-wired --self-test\n          cargo run --release --manifest-path xtask/gates/Cargo.toml -- security-quality-tools-are-wired\n"
    );
    workflows.insert("ci.yml".to_string(), ci_yml);

    workflows.insert(
        "dependency-submission.yml".to_string(),
        "name: DepSub\non:\n  push:\n    branches: [main]\njobs:\n  sub:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n    steps:\n      - run: cargo run --release --manifest-path xtask/tools/Cargo.toml -- dependency-snapshot --self-test\n      - run: cargo run --release --manifest-path xtask/tools/Cargo.toml -- dependency-snapshot /tmp/s.json --submit\n"
            .to_string(),
    );

    let clean = RepoSnapshot {
        workflows,
        dockerfile: "FROM rust:1.97.1-bookworm AS builder\nFROM cgr.dev/chainguard/wolfi-base@sha256:24f549a7fcace88e69b9557941168c74645688ecc4acf7fb6d734a6b74e9019d\nUSER 1000\n"
            .to_string(),
        dep_snapshot_rs:
            "let url = format!(\"https://api.github.com/repos/{repo}/dependency-graph/snapshots\");\n"
                .to_string(),
    };

    let clean_findings = evaluate(&clean);
    if !clean_findings.is_empty() {
        return Err(format!(
            "self-test clean fixture failed: {}",
            clean_findings.join("; ")
        ));
    }

    // Tamper 1: drop one SARIF category (`aderyn`).
    let mut t1 = clean.clone();
    if let Some(w) = t1.workflows.get_mut("code-scanning-sarif.yml") {
        *w = w.replace("category: aderyn", "category: duplicate-clippy");
    }
    if evaluate(&t1).is_empty() {
        return Err("self-test tamper 1 (missing SARIF category) passed".to_string());
    }

    // Tamper 2: drop Cobertura upload from ci.yml.
    let mut t2 = clean.clone();
    if let Some(w) = t2.workflows.get_mut("ci.yml") {
        *w = w.replace("actions/upload-code-coverage@", "actions/upload-artifact@");
    }
    if evaluate(&t2).is_empty() {
        return Err("self-test tamper 2 (missing upload-code-coverage) passed".to_string());
    }

    // Tamper 3: revert dependency-graph endpoint URL to `/dependency-snapshots`.
    let mut t3 = clean.clone();
    t3.dep_snapshot_rs = t3
        .dep_snapshot_rs
        .replace("/dependency-graph/snapshots", "/dependency-snapshots");
    if evaluate(&t3).is_empty() {
        return Err("self-test tamper 3 (wrong dependency-graph URL) passed".to_string());
    }

    // Tamper 4: add `pull_request:` trigger to dependency-submission.yml.
    let mut t4 = clean.clone();
    if let Some(w) = t4.workflows.get_mut("dependency-submission.yml") {
        *w = w.replace("on:\n  push:", "on:\n  pull_request:\n  push:");
    }
    if evaluate(&t4).is_empty() {
        return Err(
            "self-test tamper 4 (pull_request on dependency-submission) passed".to_string(),
        );
    }

    // Tamper 5: revert runtime Dockerfile to debian:bookworm-slim.
    let mut t5 = clean.clone();
    t5.dockerfile =
        "FROM rust:1.97.1-bookworm AS builder\nFROM debian:bookworm-slim@sha256:7ff6\nUSER 1000\n"
            .to_string();
    if evaluate(&t5).is_empty() {
        return Err("self-test tamper 5 (non-Wolfi runtime image) passed".to_string());
    }

    // Tamper 6: omit `consensus-of-consensuses` from `extra-tooling.yml`.
    let mut t6 = clean;
    if let Some(w) = t6.workflows.get_mut("extra-tooling.yml") {
        *w = w.replace(", consensus-of-consensuses", "");
    }
    if evaluate(&t6).is_empty() {
        return Err("self-test tamper 6 (missing PR branch coverage) passed".to_string());
    }

    Ok(
        "canary OK: all 6 Security & Quality wiring tampers fail and the clean fixture passes."
            .to_string(),
    )
}
