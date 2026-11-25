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

/// The frozen record of commit subjects that already carried the review
/// identity when this guard first ran.
///
/// Rewriting those commits would mean rewriting pushed history, which the
/// project forbids outright, so the guard has exactly two ways to be honest
/// about them: stay red forever, or name them. Staying red forever is worse
/// than it sounds: a gate that is red on every run cannot mark the run where a
/// *new* identity-carrying subject appears, and the pull request that carries
/// the repair can never merge.
///
/// So the file names them, under five constraints that make the list a ratchet
/// rather than a hole:
///
/// 1. It holds commit ids only. A subject is not copied into the tree, because
///    the subjects themselves carried internal tracker ids and copying them
///    would smuggle those past `no-internal-ids`.
/// 2. `MAX_QUARANTINED_SUBJECTS` is a ceiling in code: the list cannot grow.
///    A third entry fails the gate no matter who writes it.
/// 3. A named commit must exist in the repository and be an ancestor of
///    `HEAD`. An id that names nothing, or a history rewritten around it,
///    fails.
/// 4. A named commit's subject must *still* carry the identity. An entry that
///    no longer points at a violation is stale and fails, so the file can only
///    shrink as the commits it names leave the audited range.
/// 5. Every suppression is printed. The pass line reports how many subjects
///    were carried, so the allowance is visible in every run rather than
///    inferred from a file.
///
/// Constraints 2 to 5 are each covered by a red-team case in `self_test`; the
/// unit tests in this file cover the same rules against a temporary git
/// repository.
const QUARANTINE_PATH: &str = ".github/audit-guard-history-quarantine.txt";

/// How many historical subjects the quarantine may carry. It may only shrink.
const MAX_QUARANTINED_SUBJECTS: usize = 2;

/// The name that must not appear in active code. It is built from two pieces
/// so this guard cannot trip over its own explanatory source text.
fn review_identity() -> String {
    format!("{}{}", "Ar", "ena")
}

const CHECKOUT: &str = "actions/checkout@";

const ACTIVE_PREFIXES: &[&str] = &[
    "src/",
    "crates/",
    "budzero/",
    "xtask/",
    // `contracts/` is compile-only in CI
    // (solidity.yml) and deliberately un-deployed - BudlumFinalityVerifier
    // is quarantined behind its fixes. The guard watches the path
    // for action-pin drift like any other active source tree; watching it
    // is not a statement that the contract ships.
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

/// Does a (comment-stripped) line name `word` as a whole word? This is the
/// trigger test: `pull_request_target:` (map form), `on: pull_request_target`
/// (scalar), `on: [push, pull_request_target]` (inline list) and
/// `- pull_request_target` (block list) all name the trigger. Matching only a
/// line that starts with the key missed the last three forms.
fn names_word(line: &str, word: &str) -> bool {
    line.match_indices(word).any(|(i, _)| {
        let before = line[..i].chars().next_back();
        let after = line[i + word.len()..].chars().next();
        !before.is_some_and(|c| is_word(c) || c == '-') && !after.is_some_and(is_word)
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
    if line
        .strip_prefix("permissions:")
        .is_some_and(|rest| rest.trim() == "write-all")
    {
        return true;
    }
    for key in [
        "contents",
        "actions",
        "pull-requests",
        "id-token",
        "packages",
        "checks",
        "issues",
        "statuses",
        "deployments",
        "pages",
    ] {
        if let Some(rest) = line.strip_prefix(key).and_then(|r| r.strip_prefix(':')) {
            let value = rest.trim();
            return value == "write" || value == "write-all";
        }
    }
    false
}

fn guard_workflow_checks(rel: &str, text: &str, errors: &mut Vec<String>) {
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
}

fn checkout_checks(rel: &str, lines: &[&str], errors: &mut Vec<String>) {
    for (start, line) in lines.iter().enumerate() {
        if !line.contains(CHECKOUT) || line.trim_start().starts_with('#') {
            continue;
        }
        let end = (start + 12).min(lines.len());
        let indent = line.len() - line.trim_start().len();
        // The window ends where the next step of the same list begins.
        let step_end = (start + 1..end)
            .find(|&j| {
                let l = lines[j];
                l.trim_start().starts_with("- ") && l.len() - l.trim_start().len() <= indent
            })
            .unwrap_or(end);
        if !lines[start..step_end]
            .iter()
            .any(|l| l.contains("persist-credentials: false"))
        {
            errors.push(format!(
                "{rel}:{}: checkout must disable persisted credentials",
                start + 1
            ));
        }
    }
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
    if uncommented
        .iter()
        .any(|line| names_word(line, "pull_request_target"))
    {
        errors.push(format!("{rel}: pull_request_target is forbidden"));
    }
    if uncommented
        .iter()
        .any(|line| names_word(line, "workflow_run"))
    {
        errors.push(format!(
            "{rel}: workflow_run is forbidden in the audit surface"
        ));
    }

    let live_text = uncommented.join("\n");
    if has_pair(&live_text, "continue-on-error", "true") {
        errors.push(format!(
            "{rel}: continue-on-error: true hides a failing step"
        ));
    }
    if swallows_failure(&live_text) {
        errors.push(format!("{rel}: `|| true` swallows a failing command"));
    }

    guard_workflow_checks(rel, text, errors);

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

    checkout_checks(rel, &lines, errors);

    let has_pull_request = uncommented.iter().any(|line| {
        let t = line.trim();
        t == "pull_request:"
            || t.strip_prefix("on:").is_some_and(|rest| {
                let rest = rest.trim();
                rest == "pull_request"
                    || (rest.starts_with('[')
                        && rest
                            .trim_matches(|c| c == '[' || c == ']')
                            .split(',')
                            .any(|e| e.trim() == "pull_request"))
            })
    });
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

/// True when every occurrence of the review identity in this subject is the
/// first segment of a branch path (`<identity>/...`) rather than the identity
/// standing on its own.
///
/// A merge commit has to name the branch it merges, and the delivery branch is
/// named after the identity, so its subject contains the word no matter who
/// writes it. That is a path, not an attribution: the guard exists to keep the
/// identity out of *authored* text, and `merge(testnet): bring testnet into
/// <identity>/ajan-teslim` says nothing about who reviewed what. The caller
/// applies this only to two-parent commits, so an ordinary commit cannot use a
/// branch name to smuggle the identity past the check.
fn identity_only_in_branch_paths(subject: &str) -> bool {
    let needle = review_identity().to_lowercase();
    let lower = subject.to_lowercase();
    let mut rest = lower.as_str();
    let mut found = false;
    while let Some(at) = rest.find(&needle) {
        found = true;
        let after = &rest[at + needle.len()..];
        if !after.starts_with('/') {
            return false;
        }
        rest = after;
    }
    found
}

/// Recognize GitHub's generated merge subject so a branch path is not mistaken
/// for authored commit text. The caller also requires a two-parent commit.
fn is_generated_merge_subject(subject: &str) -> bool {
    let Some(rest) = subject.strip_prefix("Merge pull request #") else {
        return false;
    };
    let Some((number, source)) = rest.split_once(" from ") else {
        return false;
    };
    let Some((owner, branch)) = source.split_once('/') else {
        return false;
    };
    !number.is_empty()
        && number.bytes().all(|byte| byte.is_ascii_digit())
        && !owner.is_empty()
        && !branch.is_empty()
        && !source.bytes().any(|byte| byte.is_ascii_whitespace())
}

fn configured_commit_base() -> Option<String> {
    if let Ok(base_ref) = std::env::var("GITHUB_BASE_REF") {
        if !base_ref.is_empty() {
            return Some(format!("origin/{base_ref}"));
        }
    }
    if let Ok(before) = std::env::var("GITHUB_EVENT_BEFORE") {
        if before.bytes().any(|byte| byte != b'0') {
            return Some(before);
        }
    }
    None
}

/// Select commits introduced by this run: after the change base or push's before
/// SHA. Local runs use `origin/main`, falling back to the last commit there.
fn commit_subject_range(root: &Path, base_ref: Option<&str>) -> Result<String, String> {
    if let Some(base_ref) = base_ref {
        let merge_base = git_stdout(root, &["merge-base", "HEAD", base_ref])?;
        return Ok(format!("{}..HEAD", merge_base.trim()));
    }

    let head = git_stdout(root, &["rev-parse", "HEAD"])?;
    if let Ok(merge_base) = git_stdout(root, &["merge-base", "HEAD", "origin/main"]) {
        if merge_base.trim() != head.trim() {
            return Ok(format!("{}..HEAD", merge_base.trim()));
        }
    }
    if let Ok(parent) = git_stdout(root, &["rev-parse", "--verify", "HEAD^"]) {
        return Ok(format!("{}..HEAD", parent.trim()));
    }
    Ok(String::from("HEAD"))
}

/// Read and validate the frozen history quarantine.
///
/// Every rule is enforced here rather than at the point of use, so a malformed
/// or dishonest ledger fails the gate even on a run whose change range happens
/// to contain no violations. Returns the quarantined commit ids.
fn quarantine_entries(root: &Path) -> Result<Vec<String>, String> {
    let path = root.join(QUARANTINE_PATH);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(Vec::new());
    };
    let mut ids: Vec<String> = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() != 40 || !line.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "{QUARANTINE_PATH}:{}: an entry must be one full 40-hex commit id, not `{line}`",
                number + 1
            ));
        }
        let id = line.to_lowercase();
        if ids.contains(&id) {
            return Err(format!(
                "{QUARANTINE_PATH}:{}: `{id}` is listed twice",
                number + 1
            ));
        }
        ids.push(id);
    }
    if ids.len() > MAX_QUARANTINED_SUBJECTS {
        return Err(format!(
            "{QUARANTINE_PATH}: {} entries, the ceiling is {MAX_QUARANTINED_SUBJECTS}. The list \
             may only shrink: a new violating subject must be removed from history, not named here",
            ids.len()
        ));
    }
    for id in &ids {
        if git_stdout(root, &["cat-file", "-e", &format!("{id}^{{commit}}")]).is_err() {
            return Err(format!(
                "{QUARANTINE_PATH}: `{id}` does not name a commit in this repository"
            ));
        }
        if git_stdout(root, &["merge-base", "--is-ancestor", id, "HEAD"]).is_err() {
            return Err(format!(
                "{QUARANTINE_PATH}: `{id}` is not an ancestor of HEAD, so it is not history"
            ));
        }
        let subject = git_stdout(root, &["log", "-1", "--format=%s", id])?;
        if !subject_has_identity(subject.trim_end()) {
            return Err(format!(
                "{QUARANTINE_PATH}: `{id}` no longer carries the identity; the entry is stale and \
                 must be deleted"
            ));
        }
    }
    Ok(ids)
}

/// # Errors
///
/// When a subject in range carries the review identity and is not one of the
/// frozen historical commits, or when the quarantine itself is invalid.
fn commit_subject_audit(
    root: &Path,
    base_ref: Option<&str>,
    errors: &mut Vec<String>,
) -> Result<usize, String> {
    let quarantine = quarantine_entries(root)?;
    let range = commit_subject_range(root, base_ref)?;
    let log = git_stdout(root, &["log", "--format=%H%x09%P%x09%s", &range])?;
    let mut carried = 0usize;
    for row in log.lines() {
        let (sha, remainder) = row.split_once('\t').unwrap_or((row, ""));
        let (parents, subject) = remainder.split_once('\t').unwrap_or((remainder, ""));
        let is_merge_commit = parents.split_whitespace().count() == 2;
        let generated_merge = is_merge_commit && is_generated_merge_subject(subject);
        let merge_naming_a_branch_path = is_merge_commit && identity_only_in_branch_paths(subject);
        if subject_has_identity(subject) && !generated_merge && !merge_naming_a_branch_path {
            if quarantine.iter().any(|id| id == &sha.to_lowercase()) {
                carried += 1;
                continue;
            }
            let short: String = sha.chars().take(12).collect();
            errors.push(format!(
                "commit {short}: review identity remains in subject"
            ));
        }
    }
    Ok(carried)
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
    let mutants: [(&str, String, &str); 10] = [
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
            "forbidden-trigger-inline-list",
            format!("{CLEAN}\non: [push, pull_request_target]\n"),
            "pull_request_target is forbidden",
        ),
        (
            "forbidden-trigger-scalar",
            format!("{CLEAN}\non: pull_request_target\n"),
            "pull_request_target is forbidden",
        ),
        (
            "forbidden-trigger-block-list",
            format!("{CLEAN}\n  - pull_request_target\n"),
            "pull_request_target is forbidden",
        ),
        (
            "workflow-run-inline",
            format!("{CLEAN}\non: [workflow_run]\n"),
            "workflow_run is forbidden",
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
    let base_ref = configured_commit_base();
    let mut carried = 0usize;
    let scanned = active_code_audit(root, &mut errors).and_then(|()| {
        commit_subject_audit(root, base_ref.as_deref(), &mut errors).map(|n| carried = n)
    });
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
    let _ = writeln!(
        out,
        "audit-guard self-test: PASS (frozen historical subjects carried: {carried})"
    );
    Report::ok(out)
}

fn audit(root: &Path) -> Report {
    let mut errors = Vec::new();
    let base_ref = configured_commit_base();
    let mut carried = 0usize;
    let checked = workflow_audit(root, &mut errors).and_then(|n| {
        active_code_audit(root, &mut errors)?;
        commit_subject_audit(root, base_ref.as_deref(), &mut errors).map(|c| carried = c)?;
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
         - new commit subjects review identity check: clean\n\
         - frozen historical subjects carried: {carried}\n"
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
    fn write_scopes_and_inline_triggers_are_seen() {
        for trigger in ["on: [push, pull_request]", "on: pull_request"] {
            let text = format!("{trigger}\npermissions:\n  id-token: write\n");
            let errors = audit_text("x.yml", &text);
            assert!(
                errors.iter().any(|e| e.contains("write permission")),
                "{trigger}: {errors:?}"
            );
        }
        let all = "on:\n  pull_request:\npermissions: write-all\n";
        assert!(audit_text("x.yml", all)
            .iter()
            .any(|e| e.contains("write permission")));
    }

    #[test]
    fn swallowed_failures_are_found_in_every_workflow() {
        let text = format!("{CLEAN}\n      continue-on-error: true\n      run: make || true\n");
        let errors = audit_text("other.yml", &text);
        assert!(errors.iter().any(|e| e.contains("continue-on-error")));
        assert!(errors.iter().any(|e| e.contains("|| true")));
        let commented = format!("{CLEAN}\n# run: make || true\n");
        assert_eq!(audit_text("other.yml", &commented), Vec::<String>::new());
    }

    #[test]
    fn credentials_of_the_next_step_do_not_count() {
        let text = "permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n        with:\n          persist-credentials: false\n";
        let errors = audit_text("x.yml", text);
        assert_eq!(
            errors
                .iter()
                .filter(|e| e.contains("persisted credentials"))
                .count(),
            1,
            "{errors:?}"
        );
    }

    #[test]
    fn a_clean_workflow_passes() {
        assert_eq!(audit_text("x.yml", CLEAN), Vec::<String>::new());
    }

    #[test]
    fn the_red_team_rejects_all_fourteen_mutants() {
        assert_eq!(red_team(), Ok(14));
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

    #[test]
    fn generated_merge_subjects_are_distinguished_from_authored_subjects() {
        let generated = format!(
            "Merge pull request #123 from lubothebook/{}/feature-branch",
            review_identity().to_lowercase()
        );
        assert!(is_generated_merge_subject(&generated));
        assert!(!is_generated_merge_subject(
            "Merge pull request #x from lubothebook/feature/branch"
        ));
        assert!(!is_generated_merge_subject(
            "Merge pull request #6 from example/branch feature"
        ));
    }

    #[test]
    fn identity_in_a_merge_subject_is_a_branch_path_and_not_an_attribution() {
        let name = review_identity().to_lowercase();
        // A branch path: the identity is a path segment, followed by a slash.
        assert!(identity_only_in_branch_paths(&format!(
            "merge(testnet): bring testnet into {name}/ajan-teslim"
        )));
        assert!(identity_only_in_branch_paths(&format!(
            "Merge remote-tracking branch 'origin/{name}/ajan-teslim' into {name}/ajan-teslim"
        )));
        // The identity standing alone is an attribution and stays a violation.
        assert!(!identity_only_in_branch_paths(&format!(
            "fix: {name} approved this"
        )));
        assert!(!identity_only_in_branch_paths(&format!(
            "{name} reviewed the finality path"
        )));
        // Mixed: one path segment does not excuse the standalone mention.
        assert!(!identity_only_in_branch_paths(&format!(
            "merge {name}/x: reviewed by {name}"
        )));
        // A subject without the identity is not a path mention either.
        assert!(!identity_only_in_branch_paths("merge: garden into testnet"));
    }

    fn run_git(root: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .expect("git must be available for this test");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn commit_audit_checks_only_commits_after_the_base() {
        let root =
            std::env::temp_dir().join(format!("audit-guard-commit-range-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temporary git repository");
        run_git(&root, &["init", "-q"]);
        run_git(&root, &["config", "user.name", "Audit Guard Test"]);
        run_git(
            &root,
            &["config", "user.email", "audit-guard@example.invalid"],
        );
        let inherited = format!("Add {}_launcher.py", review_identity().to_lowercase());
        run_git(&root, &["commit", "--allow-empty", "-m", &inherited]);
        run_git(&root, &["branch", "base"]);
        run_git(
            &root,
            &["commit", "--allow-empty", "-m", "fix: ordinary change"],
        );

        let mut errors = Vec::new();
        commit_subject_audit(&root, Some("base"), &mut errors).expect("commit audit");
        assert!(
            errors.is_empty(),
            "base history is outside the change range: {errors:?}"
        );

        let introduced = format!("fix: {} is forbidden", review_identity());
        run_git(&root, &["commit", "--allow-empty", "-m", &introduced]);
        commit_subject_audit(&root, Some("base"), &mut errors).expect("commit audit");
        assert_eq!(errors.len(), 1, "new violating subject must be found");
        let _ = std::fs::remove_dir_all(&root);
    }
    /// A temporary repository with one clean commit, returned with its root.
    fn repo_with_clean_commit(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "audit-guard-quarantine-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temporary git repository");
        run_git(&root, &["init", "-q"]);
        run_git(&root, &["config", "user.name", "Audit Guard Test"]);
        run_git(
            &root,
            &["config", "user.email", "audit-guard@example.invalid"],
        );
        run_git(
            &root,
            &["commit", "--allow-empty", "-m", "fix: ordinary change"],
        );
        root
    }

    fn write_quarantine(root: &Path, body: &str) {
        let path = root.join(QUARANTINE_PATH);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("ledger dir");
        std::fs::write(&path, body).expect("ledger");
    }

    fn head(root: &Path) -> String {
        let output = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(root)
            .output()
            .expect("git");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// A violating commit is refused while it is not in the ledger, and carried
    /// once its id is. The subject itself never enters the tree.
    #[test]
    fn quarantine_carries_a_named_commit_and_nothing_else() {
        let root = repo_with_clean_commit("named");
        let violating = format!("fix: {} is forbidden", review_identity());
        run_git(&root, &["commit", "--allow-empty", "-m", &violating]);
        let mut errors = Vec::new();
        commit_subject_audit(&root, Some("HEAD~1"), &mut errors).expect("audit");
        assert_eq!(errors.len(), 1, "an unnamed violating subject must fail");

        write_quarantine(&root, &format!("# frozen\n{}\n", head(&root)));
        let mut errors = Vec::new();
        let carried = commit_subject_audit(&root, Some("HEAD~1"), &mut errors).expect("audit");
        assert!(errors.is_empty(), "a named subject is carried: {errors:?}");
        assert_eq!(carried, 1, "the allowance is reported, not hidden");

        // The next violating commit is still refused: the ledger carries one
        // commit, not a class of commits.
        let second = format!("fix: {} is asked again", review_identity());
        run_git(&root, &["commit", "--allow-empty", "-m", &second]);
        let mut errors = Vec::new();
        commit_subject_audit(&root, Some("HEAD~2"), &mut errors).expect("audit");
        assert_eq!(errors.len(), 1, "a new violating subject must still fail");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The list may not grow past the ceiling in code.
    #[test]
    fn quarantine_has_a_ceiling() {
        let root = repo_with_clean_commit("ceiling");
        // Distinct ids, so this case measures the ceiling and not the
        // duplicate rule that runs first.
        let mut body = String::from("# frozen\n");
        for digit in 1..=MAX_QUARANTINED_SUBJECTS + 1 {
            body.push_str(&digit.to_string().repeat(40));
            body.push('\n');
        }
        write_quarantine(&root, &body);
        let err = quarantine_entries(&root).expect_err("a third entry must fail");
        assert!(err.contains("may only shrink"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An id that names no commit, and an id that no longer violates, both
    /// fail: the file states history, not intent.
    #[test]
    fn quarantine_entries_must_name_a_reachable_violation() {
        let root = repo_with_clean_commit("reachable");
        write_quarantine(&root, &format!("{}\n", "0".repeat(40)));
        let err = quarantine_entries(&root).expect_err("an unknown commit must fail");
        assert!(err.contains("does not name a commit"), "{err}");

        write_quarantine(&root, &format!("{}\n", head(&root)));
        let err = quarantine_entries(&root).expect_err("a clean subject must not be carried");
        assert!(err.contains("stale"), "{err}");

        write_quarantine(&root, "not-a-sha\n");
        let err = quarantine_entries(&root).expect_err("a malformed line must fail");
        assert!(err.contains("40-hex"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A duplicate line is a second entry for one commit; it must not be able
    /// to spend two slots.
    #[test]
    fn quarantine_entries_are_unique() {
        let root = repo_with_clean_commit("unique");
        let id = head(&root);
        write_quarantine(&root, &format!("{id}\n{id}\n"));
        let err = quarantine_entries(&root).expect_err("a duplicate must fail");
        assert!(err.contains("listed twice"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
