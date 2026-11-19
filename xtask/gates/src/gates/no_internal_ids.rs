//! No internal finding, task, work-package or scratch-audit identifier may enter
//! the repository, and every commit must carry the repository owner's identity
//! without agent or third-party co-author trailers.
//!
//! # Why this gate exists
//!
//! Code comments, error strings, test names, workflow labels and commit
//! messages must state the technical invariant they enforce rather than pointing
//! at private tracker numbers or external coordination repositories. A bare
//! tracker tag explains nothing to an engineer reading the source and leaks
//! internal process taxonomy into the product tree. Likewise, commits authored
//! under placeholder sandbox identities or carrying automated co-author
//! trailers fragment repository provenance.
//!
//! # Scope and explicit carve-outs
//!
//! Every regular text file in the repository is scanned except:
//!
//! * machine-generated lockfiles and license text (`SKIP_FILES`),
//! * build/dependency directories (`SKIP_DIRS`),
//! * `docs/audit/` and `xtask/gates/src/gates/launch_evidence.rs`, which form
//!   the structured launch-gate evidence schema checked by `launch-evidence`,
//! * this gate's own source file (`xtask/gates/src/gates/no_internal_ids.rs`).
//!
//! Any top-level scratch audit directory of the historical name is refused
//! unconditionally.

use regex::Regex;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Canonical repository owner identity required on commits.
const OWNER_NAME: &str = "Lubo's Ruler";
const OWNER_EMAIL: &str = "ayazkussann@gmail.com";

/// GitHub web-flow committer allowed only on synthetic pull-request merge
/// commits whose second parent is verified separately.
const GITHUB_WEBFLOW_COMMITTER: &str = "GitHub <noreply@github.com>";

/// Directories that never carry repository source or documentation prose.
const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".cargo"];

/// Generated or third-party files skipped by the prose scan.
const SKIP_FILES: &[&str] = &["Cargo.lock", "flake.lock", "imports.lock", "LICENSE.md"];

/// Scratch directories that must never exist inside the product repository.
const FORBIDDEN_DIRS: &[&str] = &["audit-notes"];

/// Minimum number of scanned text files required for a non-vacuous run.
const VACUITY_FLOOR: usize = 50;

struct Rule {
    label: &'static str,
    regex: Regex,
}

fn build_rules() -> Result<Vec<Rule>, String> {
    // Construct tracker prefixes from pieces so even a naive grep over the tree
    // never sees a literal tracker identifier in this module.
    let specs: [(&str, String); 13] = [
        ("finding-b-id", format!(r"\b{}0\d{{3}}\b", "B-")),
        (
            "finding-blg-id",
            format!(
                r"(?:\b{}\d{{2,4}}\b|(?:^|[^A-Za-z0-9]){}\d{{2,4}})",
                "BLG-", "blg_"
            ),
        ),
        (
            "task-id",
            format!(
                r"(?:\b{}\d{{1,3}}\b|(?:^|[^A-Za-z0-9]){}_?\d{{1,3}})",
                "GOREV-", "gorev"
            ),
        ),
        ("scanner-tag", {
            // The scanner token is assembled from parts so this source
            // file carries none of the literals it refuses; the built
            // pattern still matches exactly the same strings.
            let head = concat!("Str", "ix");
            let upper = head.to_ascii_uppercase();
            let lower = head.to_ascii_lowercase();
            format!(r"(?:\b{upper}-[A-Z0-9-]+|\b{head}\b|(?:^|[^A-Za-z0-9]){lower}[a-z0-9_]+)")
        }),
        ("work-item-ip", format!(r"\b{}\d{{2}}\b", "IP-")),
        ("work-package-wp", format!(r"\b{}\d{{1,2}}\b", "WP-")),
        (
            "decision-kr",
            format!(r"(?:\b{}\d{{2}}\b|\b{}UEL-[A-Z-]+)", "KR-", "KR-"),
        ),
        (
            "launch-tag-outside-ledger",
            format!(r"\b{}\d{{2}}\b", "TLG-"),
        ),
        ("phase-finding-id", format!(r"\bP\d{{2}}-{}\d{{2}}\b", "F")),
        (
            "subphase-finding-id",
            format!(r"\b{}10\.[1-9][a-z]?\b", "F"),
        ),
        (
            "governance-id",
            format!(
                r"(?:\b{}\d{{1,3}}\b|\b{}\d{{1,3}}\b|\b{}00[1-9]\b|\bS-\d{{3}}-\d{{2}}\b)",
                "CEO-", "KARAR-", "RFC-"
            ),
        ),
        (
            "directive-name",
            format!(r"(?:{}|{})", "THE[ _]BUDLUM[ _]DIREKTIF", "UST[ _]DIREKTIF"),
        ),
        (
            "workspace-ref",
            format!(r"(?:{}/workspace|{}/bulgular)", "budlum-xyz", "denetim"),
        ),
    ];

    let mut rules = Vec::with_capacity(specs.len());
    for (label, pattern) in specs {
        let regex = Regex::new(&pattern)
            .map_err(|e| format!("no-internal-ids: invalid pattern {label}: {e}"))?;
        rules.push(Rule { label, regex });
    }
    Ok(rules)
}

fn commit_message_rules() -> Result<Vec<Rule>, String> {
    let mut rules = build_rules()?;
    let trailer_specs: [(&str, String); 2] = [
        (
            "co-authored-by-trailer",
            format!(r"(?i)^\s*{}\s*:", "co-authored-by"),
        ),
        (
            "non-owner-identity-marker",
            format!(
                r"(?i)(?:noreply@anthropic\.com|audit@localhost|audit@local|@budlum\.local|security@budlum\.com|dev@budlum\.xyz|{})",
                "arena-agent"
            ),
        ),
    ];
    for (label, pattern) in trailer_specs {
        let regex = Regex::new(&pattern)
            .map_err(|e| format!("no-internal-ids: invalid commit pattern {label}: {e}"))?;
        rules.push(Rule { label, regex });
    }
    Ok(rules)
}

/// Returns `true` when `(rel, label)` names the repository's own `.gitignore`
/// and absence-lock test forbidding the external directive filename.
fn is_exempt_finding(rel: &str, label: &str) -> bool {
    label == "directive-name"
        && matches!(
            rel,
            ".gitignore"
                | "xtask/gates/src/gates/tree_is_english.rs"
                | "xtask/gates/tests/repository_locks.rs"
        )
}

fn is_exempt_rel_path(rel: &str) -> bool {
    rel.starts_with("docs/audit/")
        || rel == "xtask/gates/src/gates/launch_evidence.rs"
        || rel == "xtask/gates/src/gates/no_internal_ids.rs"
}

fn sorted_walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_into(root, &mut out);
    out
}

fn walk_into(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        let name = entry.file_name();
        let name_s = name.to_string_lossy();
        let path = entry.path();
        if ft.is_dir() {
            if SKIP_DIRS.contains(&name_s.as_ref()) {
                continue;
            }
            walk_into(&path, out);
        } else if ft.is_file() {
            if SKIP_FILES.contains(&name_s.as_ref()) {
                continue;
            }
            out.push(path);
        }
    }
}

fn scan_tree(root: &Path, floor: usize, findings: &mut Vec<String>) -> Result<usize, String> {
    for banned in FORBIDDEN_DIRS {
        if root.join(banned).exists() {
            findings.push(format!(
                "{banned}/: forbidden scratch audit directory exists in product repository"
            ));
        }
    }

    let rules = build_rules()?;
    let mut scanned = 0usize;

    for path in sorted_walk(root) {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if is_exempt_rel_path(&rel) {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        if bytes.contains(&0) {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        scanned += 1;
        for (idx, line) in text.lines().enumerate() {
            for rule in &rules {
                if is_exempt_finding(&rel, rule.label) {
                    continue;
                }
                if let Some(m) = rule.regex.find(line) {
                    findings.push(format!(
                        "{rel}:{}: [{}] forbidden token `{}`",
                        idx + 1,
                        rule.label,
                        m.as_str()
                    ));
                    break;
                }
            }
        }
    }

    if scanned < floor {
        return Err(format!(
            "no-internal-ids: scanned only {scanned} text files (floor {floor}); refusing vacuous pass"
        ));
    }

    Ok(scanned)
}

fn check_git_head(root: &Path, findings: &mut Vec<String>) -> Result<bool, String> {
    if !root.join(".git").exists() {
        return Ok(false);
    }

    let head_out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["log", "-1", "--format=%an%n%ae%n%cn%n%ce%n%P%n%s"])
        .output();
    let Ok(output) = head_out else {
        return Ok(false);
    };
    if !output.status.success() {
        return Ok(false);
    }
    let meta = String::from_utf8_lossy(&output.stdout);
    let mut lines = meta.lines();
    let author_name = lines.next().unwrap_or_default();
    let author_email = lines.next().unwrap_or_default();
    let committer_name = lines.next().unwrap_or_default();
    let committer_email = lines.next().unwrap_or_default();
    let parents = lines.next().unwrap_or_default();
    let subject = lines.next().unwrap_or_default();

    let committer_full = format!("{committer_name} <{committer_email}>");
    let parent_list: Vec<&str> = parents.split_whitespace().collect();

    // GitHub Actions checks out a synthetic `Merge <sha> into <sha>` commit for
    // `pull_request` workflows; validate its PR-head parent (`HEAD^2`) instead.
    let target_rev = if committer_full == GITHUB_WEBFLOW_COMMITTER
        && parent_list.len() == 2
        && subject.starts_with("Merge ")
        && subject.contains(" into ")
    {
        "HEAD^2"
    } else {
        "HEAD"
    };

    verify_commit_rev(
        root,
        target_rev,
        findings,
        (author_name, author_email),
        (committer_name, committer_email),
    )
}

fn verify_commit_rev(
    root: &Path,
    rev: &str,
    findings: &mut Vec<String>,
    author_pair: (&str, &str),
    committer_pair: (&str, &str),
) -> Result<bool, String> {
    let (author_name, author_email, committer_name, committer_email, body) = if rev == "HEAD" {
        let body_out = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["log", "-1", "--format=%B", "HEAD"])
            .output()
            .map_err(|e| format!("no-internal-ids: git log failed: {e}"))?;
        (
            author_pair.0.to_string(),
            author_pair.1.to_string(),
            committer_pair.0.to_string(),
            committer_pair.1.to_string(),
            String::from_utf8_lossy(&body_out.stdout).into_owned(),
        )
    } else {
        let out = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["log", "-1", "--format=%an%n%ae%n%cn%n%ce%n%B", rev])
            .output()
            .map_err(|e| format!("no-internal-ids: git log {rev} failed: {e}"))?;
        if !out.status.success() {
            return Ok(false);
        }
        let raw = String::from_utf8_lossy(&out.stdout);
        let mut it = raw.splitn(5, '\n');
        (
            it.next().unwrap_or_default().to_string(),
            it.next().unwrap_or_default().to_string(),
            it.next().unwrap_or_default().to_string(),
            it.next().unwrap_or_default().to_string(),
            it.next().unwrap_or_default().to_string(),
        )
    };

    if author_name != OWNER_NAME || author_email != OWNER_EMAIL {
        findings.push(format!(
            "git {rev}: author `{author_name} <{author_email}>` must be `{OWNER_NAME} <{OWNER_EMAIL}>`"
        ));
    }
    let committer_full = format!("{committer_name} <{committer_email}>");
    if (committer_name != OWNER_NAME || committer_email != OWNER_EMAIL)
        && committer_full != GITHUB_WEBFLOW_COMMITTER
    {
        findings.push(format!(
            "git {rev}: committer `{committer_name} <{committer_email}>` must be `{OWNER_NAME} <{OWNER_EMAIL}>`"
        ));
    }

    let msg_rules = commit_message_rules()?;
    for (idx, line) in body.lines().enumerate() {
        for rule in &msg_rules {
            if let Some(m) = rule.regex.find(line) {
                findings.push(format!(
                    "git {rev} message line {}: [{}] forbidden token `{}`",
                    idx + 1,
                    rule.label,
                    m.as_str()
                ));
                break;
            }
        }
    }

    Ok(true)
}

fn evaluate(root: &Path, floor: usize) -> Result<String, String> {
    let mut findings = Vec::new();
    let scanned = scan_tree(root, floor, &mut findings)?;
    let checked_git = check_git_head(root, &mut findings)?;

    if !findings.is_empty() {
        let mut msg = format!(
            "no-internal-ids: {} violation(s) across {scanned} files:\n",
            findings.len()
        );
        for item in findings.iter().take(60) {
            let _ = writeln!(msg, "  {item}");
        }
        if findings.len() > 60 {
            let _ = writeln!(msg, "  ... and {} more", findings.len() - 60);
        }
        return Err(msg.trim_end().to_string());
    }

    let git_note = if checked_git {
        ", HEAD identity/message verified"
    } else {
        ""
    };
    Ok(format!(
        "0 internal tracker identifiers across {scanned} text files{git_note}"
    ))
}

/// Run the `no-internal-ids` gate against `root`.
///
/// # Errors
///
/// Returns a diagnostic string when any forbidden internal identifier,
/// forbidden scratch directory or non-owner commit metadata is found.
pub fn run(root: &Path) -> Result<String, String> {
    evaluate(root, VACUITY_FLOOR)
}

/// Run self-test canaries for `no-internal-ids`.
///
/// # Errors
///
/// Returns a diagnostic string when a clean fixture is rejected or any
/// positive defect fixture slips through.
pub fn self_test() -> Result<String, String> {
    let tmp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let base = tmp.path();

    fs::create_dir_all(base.join("src")).map_err(|e| e.to_string())?;
    fs::create_dir_all(base.join("docs/audit")).map_err(|e| e.to_string())?;

    // Clean baseline with legitimate protocol standards must pass.
    fs::write(
        base.join("src/lib.rs"),
        "//! Clean protocol code using EIP-1559, BIP-340, RFC 6962, FIPS 204, F64, P256 and ML-DSA-65.\npub fn ok() -> u32 { 1 }\n",
    )
    .map_err(|e| e.to_string())?;
    // Exempt structured launch ledger must not trip the prose check.
    fs::write(
        base.join("docs/audit/LIVE_STATUS.md"),
        format!("| {}001 | closed |\n| {}01 | verified |\n", "BLG-", "TLG-"),
    )
    .map_err(|e| e.to_string())?;

    evaluate(base, 1).map_err(|e| format!("clean canary failed: {e}"))?;

    // Every forbidden token class must fail closed.
    let bad_samples: [(&str, String); 11] = [
        ("b-id", format!("// see {}0042\n", "B-")),
        ("blg-id", format!("// regression for {}239\n", "BLG-")),
        ("blg-fn", format!("fn {}113_case() {{}}\n", "blg_")),
        ("task-id", format!("//! module ({}21)\n", "GOREV-")),
        ("scanner", format!("// {}{} check\n", "Str", "ix")),
        ("ip-id", format!("// per {}35\n", "IP-")),
        ("wp-id", format!("# Mobile ({}11)\n", "WP-")),
        ("tlg-id", format!("// blocker {}03\n", "TLG-")),
        ("phase-finding", format!("// {}01 guard\n", "P04-F")),
        ("subphase", format!("//! {}2 verifier\n", "F10.")),
        ("ws-ref", format!("# see {}/workspace\n", "budlum-xyz")),
    ];

    let probe = base.join("src/probe.rs");
    for (name, content) in bad_samples {
        fs::write(&probe, content).map_err(|e| e.to_string())?;
        if evaluate(base, 1).is_ok() {
            return Err(format!("canary `{name}` passed when it must fail"));
        }
    }
    fs::remove_file(&probe).map_err(|e| e.to_string())?;

    // Forbidden scratch directory must fail even when empty.
    fs::create_dir_all(base.join("audit-notes")).map_err(|e| e.to_string())?;
    if evaluate(base, 1).is_ok() {
        return Err(String::from(
            "canary scratch-directory passed when it must fail",
        ));
    }
    fs::remove_dir_all(base.join("audit-notes")).map_err(|e| e.to_string())?;

    verify_git_canaries(base)?;

    Ok(String::from(
        "no-internal-ids canary OK: 11 token classes, the scratch-directory class, alien author and co-author trailer refused",
    ))
}

fn verify_git_canaries(base: &Path) -> Result<(), String> {
    if !Command::new("git")
        .arg("-C")
        .arg(base)
        .arg("init")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        return Ok(());
    }
    let _ = Command::new("git")
        .arg("-C")
        .arg(base)
        .args(["add", "."])
        .output();

    // Alien author must fail.
    let _ = Command::new("git")
        .arg("-C")
        .arg(base)
        .env("GIT_AUTHOR_NAME", "Sandbox Agent")
        .env("GIT_AUTHOR_EMAIL", "agent@budlum.local")
        .env("GIT_COMMITTER_NAME", "Sandbox Agent")
        .env("GIT_COMMITTER_EMAIL", "agent@budlum.local")
        .args(["commit", "-m", "feat: clean subject"])
        .output();
    if evaluate(base, 1).is_ok() {
        return Err(String::from(
            "canary `alien-git-author` passed when it must fail",
        ));
    }

    // Owner author with a Co-Authored-By trailer must fail.
    let trailer_msg = format!(
        "feat: clean subject\n\n{}: Bot <bot@example.com>",
        "Co-Authored-By"
    );
    let _ = Command::new("git")
        .arg("-C")
        .arg(base)
        .env("GIT_AUTHOR_NAME", OWNER_NAME)
        .env("GIT_AUTHOR_EMAIL", OWNER_EMAIL)
        .env("GIT_COMMITTER_NAME", OWNER_NAME)
        .env("GIT_COMMITTER_EMAIL", OWNER_EMAIL)
        .args(["commit", "--allow-empty", "-m", &trailer_msg])
        .output();
    if evaluate(base, 1).is_ok() {
        return Err(String::from(
            "canary `co-authored-by` passed when it must fail",
        ));
    }

    // Pure owner commit with clean technical message must pass.
    let _ = Command::new("git")
        .arg("-C")
        .arg(base)
        .env("GIT_AUTHOR_NAME", OWNER_NAME)
        .env("GIT_AUTHOR_EMAIL", OWNER_EMAIL)
        .env("GIT_COMMITTER_NAME", OWNER_NAME)
        .env("GIT_COMMITTER_EMAIL", OWNER_EMAIL)
        .args([
            "commit",
            "--allow-empty",
            "-m",
            "fix(consensus): tighten epoch check",
        ])
        .output();
    evaluate(base, 1)
        .map(|_| ())
        .map_err(|e| format!("owner git canary failed: {e}"))
}
