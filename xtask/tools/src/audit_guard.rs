//! Fail-closed audit of the review boundary.
//!
//! It replaces `.github/scripts/audit_guard.py`.
//!
//! This is a structural gate, not a replacement for Rust, `CodeQL`,
//! `actionlint`, `zizmor` or the supply-chain jobs. Its purpose is to catch a CI
//! configuration that silently stops auditing, and to keep the repository's
//! own review identity out of active code and new commit subjects.
//!
//! The workflow rules are line based, as the Python regexes were. No YAML
//! parser is needed, and the pure function [`workflow_text_audit`] can be
//! mutated by the red team without touching the disk.

use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

use crate::report::Report;

/// The command line the workflows must use to run this tool. The audit of
/// `audit-guard.yml` and `ci.yml` looks for exactly this text.
pub const INVOKE: &str =
    "cargo run -q --release --manifest-path xtask/tools/Cargo.toml -- audit-guard";

/// This file, which is exempt from the identity scan the way the Python script
/// exempted itself.
const SELF_PATH: &str = "xtask/tools/src/audit_guard.rs";

/// The name that must not appear in active code. It is built from two pieces
/// so this guard cannot trip over its own explanatory source text.
fn review_identity() -> String {
    format!("{}{}", "Ar", "ena")
}

const CHECKOUT: &str = "actions/checkout@";

const ACTIVE_PREFIXES: &[&str] = &[
    "src/",
    "crates/",
    "bud/",
    "budzero/",
    "xtask/",
    "contracts/",
    "ops/",
    "fuzz/",
    "kani/",
    "examples/",
    ".github/workflows/",
];

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `^\s*<key>\s*:` on any line.
fn has_key(text: &str, key: &str) -> bool {
    text.lines().any(|line| {
        line.trim_start()
            .strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    })
}

/// `^\s*<key>:\s*<value>\s*$` on any line.
fn has_pair(text: &str, key: &str, value: &str) -> bool {
    text.lines().any(|line| {
        line.trim_start()
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix(':'))
            .is_some_and(|rest| rest.trim() == value)
    })
}

/// `\|\|\s*true` anywhere in the text.
fn swallows_failure(text: &str) -> bool {
    (0..text.len()).any(|i| {
        text.get(i..)
            .and_then(|rest| rest.strip_prefix("||"))
            .is_some_and(|rest| rest.trim_start().starts_with("true"))
    })
}

/// `\bgit\s+push\b` on one line.
fn mentions_git_push(line: &str) -> bool {
    line.match_indices("git").any(|(i, _)| {
        let before_ok = !line[..i].chars().next_back().is_some_and(is_word);
        let rest = &line[i + 3..];
        let trimmed = rest.trim_start();
        let spaced = rest.len() > trimmed.len();
        let pushes = trimmed
            .strip_prefix("push")
            .is_some_and(|after| !after.chars().next().is_some_and(is_word));
        before_ok && spaced && pushes
    })
}

/// The action reference of a `uses:` line, if the line is one.
fn uses_ref(line: &str) -> Option<&str> {
    let body = line.trim_start();
    let body = body.strip_prefix('-').map_or(body, str::trim_start);
    let rest = body.strip_prefix("uses:")?.trim_start();
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '#')
        .unwrap_or(rest.len());
    if end == 0 {
        None
    } else {
        Some(&rest[..end])
    }
}

/// `@[0-9a-fA-F]{40}$`
fn is_sha_pinned(reference: &str) -> bool {
    reference.len() > 40
        && reference.is_char_boundary(reference.len() - 41)
        && reference[reference.len() - 41..]
            .strip_prefix('@')
            .is_some_and(|sha| sha.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_write_permission(line: &str) -> bool {
    let line = line.trim_start();
    for key in ["contents", "actions", "pull-requests"] {
        if let Some(rest) = line.strip_prefix(key).and_then(|r| r.strip_prefix(':')) {
            let value = rest.trim();
            return value == "write" || value == "write-all";
        }
    }
    false
}

/// Audit one workflow text. Kept pure so the red team can mutate it.
pub fn workflow_text_audit(rel: &str, text: &str, errors: &mut Vec<String>) {
    let uncommented: Vec<&str> = text
        .lines()
        .map(|line| line.split('#').next().unwrap_or(""))
        .collect();

    if !text.lines().any(|line| {
        line.strip_prefix("permissions:")
            .is_some_and(|rest| rest.trim().is_empty())
    }) {
        errors.push(format!("{rel}: missing top-level permissions block"));
    }
    if has_key(text, "pull_request_target") {
        errors.push(format!("{rel}: pull_request_target is forbidden"));
    }
    if has_key(text, "workflow_run") {
        errors.push(format!(
            "{rel}: workflow_run is forbidden in the audit surface"
        ));
    }

    // The guard workflow is itself part of the review boundary. Removing its
    // self-test, its real audit, or its fail-closed shell mode must turn this
    // audit red rather than silently reducing coverage.
    let self_test_call = format!("{INVOKE} --self-test");
    let is_workflow = |name: &str| rel == name || rel.ends_with(&format!("/{name}"));
    if is_workflow(".github/workflows/audit-guard.yml") {
        if !text.contains(&self_test_call) {
            errors.push(format!("{rel}: guard self-test is missing"));
        }
        if !text.lines().any(|line| line.trim() == INVOKE) {
            errors.push(format!("{rel}: real audit invocation is missing"));
        }
        if has_pair(text, "continue-on-error", "true") {
            errors.push(format!("{rel}: audit guard may not continue on error"));
        }
        if swallows_failure(text) {
            errors.push(format!("{rel}: audit guard may not swallow failures"));
        }
    }
    if is_workflow(".github/workflows/ci.yml") {
        if !text.contains(&self_test_call) {
            errors.push(format!(
                "{rel}: gates aggregator is missing Audit Guard self-test"
            ));
        }
        if !text.lines().any(|line| line.trim() == INVOKE) {
            errors.push(format!(
                "{rel}: gates aggregator is missing the real Audit Guard"
            ));
        }
    }

    let lines: Vec<&str> = text.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let Some(reference) = uses_ref(line) else {
            continue;
        };
        if reference.starts_with("./") {
            continue;
        }
        if !is_sha_pinned(reference) {
            errors.push(format!(
                "{rel}:{}: action is not pinned to a full commit SHA: {reference}",
                index + 1
            ));
        }
    }

    for (start, line) in lines.iter().enumerate() {
        if !line.contains(CHECKOUT) || line.trim_start().starts_with('#') {
            continue;
        }
        let end = (start + 12).min(lines.len());
        if !lines[start..end]
            .iter()
            .any(|l| l.contains("persist-credentials: false"))
        {
            errors.push(format!(
                "{rel}:{}: checkout must disable persisted credentials",
                start + 1
            ));
        }
    }

    let has_pull_request = text.lines().any(|line| line.trim() == "pull_request:");
    if has_pull_request {
        for (index, line) in uncommented.iter().enumerate() {
            if is_write_permission(line) {
                errors.push(format!(
                    "{rel}:{}: write permission on a pull_request workflow",
                    index + 1
                ));
            }
        }
    }

    for (index, line) in uncommented.iter().enumerate() {
        if mentions_git_push(line) {
            errors.push(format!(
                "{rel}:{}: workflow must not push repository changes",
                index + 1
            ));
        }
    }
}

/// The workflow files, `*.yml` first and then `*.yaml`, each sorted.
fn workflow_files(root: &Path) -> Vec<std::path::PathBuf> {
    let dir = root.join(".github").join("workflows");
    let mut first = Vec::new();
    let mut second = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            match path.extension().and_then(|e| e.to_str()) {
                Some("yml") => first.push(path),
                Some("yaml") => second.push(path),
                _ => {}
            }
        }
    }
    first.sort();
    second.sort();
    first.extend(second);
    first
}

fn workflow_audit(root: &Path, errors: &mut Vec<String>) -> Result<usize, String> {
    let files = workflow_files(root);
    if files.is_empty() {
        errors.push("no workflow files were found".to_string());
        return Ok(0);
    }
    for path in &files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("{} could not be read: {e}", path.display()))?;
        workflow_text_audit(&rel, &text, errors);
    }
    Ok(files.len())
}

fn git_stdout(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("`git {}` could not be run: {e}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "`git {}` exited with {}",
            args.join(" "),
            output.status
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn active_code_audit(root: &Path, errors: &mut Vec<String>) -> Result<(), String> {
    let identity = review_identity();
    for rel in git_stdout(root, &["ls-files", "-z"])?
        .split('\0')
        .filter(|item| !item.is_empty())
    {
        if rel == SELF_PATH || !ACTIVE_PREFIXES.iter().any(|p| rel.starts_with(p)) {
            continue;
        }
        let path = root.join(rel);
        if !path.is_file() {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if text.contains(&identity) {
            errors.push(format!(
                "{rel}: review identity remains in active code or workflow text"
            ));
        }
    }
    Ok(())
}

/// The first violating subject, if any. Pure, for tests.
fn subject_has_identity(subject: &str) -> bool {
    subject
        .to_lowercase()
        .contains(&review_identity().to_lowercase())
}

fn commit_subject_audit(root: &Path, errors: &mut Vec<String>) -> Result<(), String> {
    let log = git_stdout(root, &["log", "--format=%H%x09%s", "HEAD"])?;
    for row in log.lines() {
        let (sha, subject) = row.split_once('\t').unwrap_or((row, ""));
        if subject_has_identity(subject) {
            let short: String = sha.chars().take(12).collect();
            errors.push(format!(
                "commit {short}: review identity remains in subject"
            ));
        }
    }
    Ok(())
}

const CLEAN: &str = "
permissions:
  contents: read
on:
  pull_request:
    branches: [main]
jobs:
  check:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          persist-credentials: false
";

fn guard_clean() -> String {
    format!(
        "
permissions:
  contents: read
jobs:
  audit-guard:
    steps:
      - run: |
          set -euo pipefail
          {INVOKE} --self-test
      - run: |
          set -euo pipefail
          {INVOKE}
"
    )
}

fn require_rejected(
    rel: &str,
    name: &str,
    mutant: &str,
    expected: &str,
    kind: &str,
) -> Result<(), String> {
    let mut errors = Vec::new();
    workflow_text_audit(rel, mutant, &mut errors);
    if errors.iter().any(|e| e.contains(expected)) {
        Ok(())
    } else {
        Err(format!("{kind} passed unexpectedly: {name}: {errors:?}"))
    }
}

/// Mutate each protected rule and require the detector to go red.
///
/// # Errors
///
/// If any mutant passes the audit.
pub fn red_team() -> Result<usize, String> {
    let sha = "actions/checkout@0123456789abcdef0123456789abcdef01234567";
    let mutants: [(&str, String, &str); 6] = [
        (
            "unpinned-action",
            CLEAN.replace(sha, "actions/checkout@main"),
            "not pinned",
        ),
        (
            "missing-permissions",
            CLEAN.replacen("permissions:\n  contents: read\n", "", 1),
            "missing top-level permissions",
        ),
        (
            "checkout-credentials",
            CLEAN.replace("persist-credentials: false", "persist-credentials: true"),
            "disable persisted credentials",
        ),
        (
            "forbidden-trigger",
            CLEAN.replace("pull_request:\n", "pull_request_target:\n"),
            "pull_request_target is forbidden",
        ),
        (
            "pull-write",
            CLEAN.replace("contents: read\n    steps:", "contents: write\n    steps:"),
            "write permission on a pull_request",
        ),
        (
            "workflow-push",
            format!("{CLEAN}\n# mutation\nrun: git push\n"),
            "workflow must not push",
        ),
    ];
    let mut count = 0;
    for (name, mutant, expected) in &mutants {
        require_rejected(
            &format!("red-team/{name}.yml"),
            name,
            mutant,
            expected,
            "red-team mutant",
        )?;
        count += 1;
    }

    let clean = guard_clean();
    let guard_mutants: [(&str, String, &str); 4] = [
        (
            "guard-self-test-removed",
            clean.replace(&format!("          {INVOKE} --self-test\n"), ""),
            "self-test is missing",
        ),
        (
            "guard-real-audit-removed",
            clean.replace(&format!("          {INVOKE}\n"), ""),
            "real audit invocation is missing",
        ),
        (
            "guard-continue-open",
            format!("{clean}\n    continue-on-error: true\n"),
            "may not continue on error",
        ),
        (
            "guard-swallowed-error",
            format!("{clean}\n          {INVOKE} || true\n"),
            "may not swallow failures",
        ),
    ];
    for (name, mutant, expected) in &guard_mutants {
        require_rejected(
            ".github/workflows/audit-guard.yml",
            name,
            mutant,
            expected,
            "guard mutant",
        )?;
        count += 1;
    }
    Ok(count)
}

fn self_test(root: &Path) -> Report {
    let count = match red_team() {
        Ok(count) => count,
        Err(e) => return Report::fail_with(format!("FAIL: {e}\n"), 1),
    };
    let mut out = format!("audit-guard red-team: PASS ({count} mutations rejected)\n");
    let mut errors = Vec::new();
    let scanned =
        active_code_audit(root, &mut errors).and_then(|()| commit_subject_audit(root, &mut errors));
    if let Err(e) = scanned {
        return Report {
            stdout: out,
            stderr: format!("FAIL: {e}\n"),
            code: 1,
        };
    }
    if !errors.is_empty() {
        let list: Vec<String> = errors.iter().map(|e| format!("- {e}")).collect();
        return Report {
            stdout: out,
            stderr: format!(
                "self-test found existing violations:\n{}\n",
                list.join("\n")
            ),
            code: 1,
        };
    }
    out.push_str("audit-guard self-test: PASS\n");
    Report::ok(out)
}

fn audit(root: &Path) -> Report {
    let mut errors = Vec::new();
    let checked = workflow_audit(root, &mut errors).and_then(|n| {
        active_code_audit(root, &mut errors)?;
        commit_subject_audit(root, &mut errors)?;
        Ok(n)
    });
    let count = match checked {
        Ok(n) => n,
        Err(e) => return Report::fail_with(format!("FAIL: {e}\n"), 1),
    };
    if !errors.is_empty() {
        let mut err = String::from("audit-guard: FAIL\n");
        for e in &errors {
            let _ = writeln!(err, "- {e}");
        }
        return Report::fail_with(err, 1);
    }
    Report::ok(format!(
        "audit-guard: PASS\n\
         - workflows checked: {count}\n\
         - action refs, permissions, checkout credentials, forbidden triggers and push paths checked\n\
         - active code/workflow review identity check: clean\n\
         - reachable commit subjects review identity check: clean\n"
    ))
}

/// Run the tool with its command line arguments.
#[must_use]
pub fn cli(args: &[&str], root: &Path) -> Report {
    if args.contains(&"--self-test") {
        self_test(root)
    } else {
        audit(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_text(rel: &str, text: &str) -> Vec<String> {
        let mut errors = Vec::new();
        workflow_text_audit(rel, text, &mut errors);
        errors
    }

    #[test]
    fn a_clean_workflow_passes() {
        assert_eq!(audit_text("x.yml", CLEAN), Vec::<String>::new());
    }

    #[test]
    fn the_red_team_rejects_all_ten_mutants() {
        assert_eq!(red_team(), Ok(10));
    }

    #[test]
    fn the_guard_fixture_is_clean_for_the_guard_workflow() {
        let errors = audit_text(".github/workflows/audit-guard.yml", &guard_clean());
        assert_eq!(errors, Vec::<String>::new());
    }

    #[test]
    fn ci_yml_needs_both_invocations() {
        let errors = audit_text(".github/workflows/ci.yml", &guard_clean());
        assert_eq!(errors, Vec::<String>::new());
        let errors = audit_text("/repo/.github/workflows/ci.yml", CLEAN);
        assert_eq!(errors.len(), 2, "{errors:?}");
    }

    #[test]
    fn sha_pins_need_exactly_forty_hex_digits_after_the_at_sign() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert!(is_sha_pinned(&format!("actions/checkout@{sha}")));
        assert!(is_sha_pinned(&format!("a@{}", sha.to_uppercase())));
        assert!(!is_sha_pinned("actions/checkout@main"));
        assert!(!is_sha_pinned(&format!("actions/checkout@{sha}0")));
        assert!(!is_sha_pinned(&format!("actions/checkout:{sha}")));
        assert!(!is_sha_pinned(&sha[..39]));
    }

    #[test]
    fn uses_lines_are_read_with_or_without_the_dash() {
        assert_eq!(uses_ref("      - uses: a/b@v1 # note"), Some("a/b@v1"));
        assert_eq!(uses_ref("        uses:   ./local"), Some("./local"));
        assert_eq!(uses_ref("      - name: uses: x"), None);
        assert_eq!(uses_ref("        uses: # nothing"), None);
    }

    #[test]
    fn git_push_needs_word_boundaries() {
        assert!(mentions_git_push("run: git push origin main"));
        assert!(mentions_git_push("git   push"));
        assert!(!mentions_git_push("digit push"));
        assert!(!mentions_git_push("git pushed"));
        assert!(!mentions_git_push("git"));
    }

    #[test]
    fn a_commented_git_push_is_not_a_finding() {
        let text = format!("{CLEAN}\n# git push is only discussed here\n");
        assert_eq!(audit_text("x.yml", &text), Vec::<String>::new());
    }

    #[test]
    fn a_commented_checkout_is_not_audited_for_credentials() {
        let text = "permissions:\n  contents: read\n# uses: actions/checkout@main\n";
        assert_eq!(audit_text("x.yml", text), Vec::<String>::new());
    }

    #[test]
    fn swallowed_failures_are_found_across_spacing() {
        assert!(swallows_failure("cmd || true"));
        assert!(swallows_failure("cmd ||true"));
        assert!(swallows_failure("cmd |||true"));
        assert!(!swallows_failure("cmd || false"));
    }

    #[test]
    fn commit_subjects_are_matched_case_blind() {
        let name = review_identity();
        assert!(subject_has_identity(&format!(
            "fix: {}",
            name.to_uppercase()
        )));
        assert!(!subject_has_identity("fix: a normal subject"));
    }
}
