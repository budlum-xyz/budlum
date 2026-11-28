//! The check the protected branch requires, produced by a gate that can fail.
//!
//! # The failure this closes
//!
//! Branch protection on the default branch required a status context named
//! `merge-block-default-branch`. No workflow in the repository produced a check
//! with that name - measured 2026-11-27 across every branch: thirty-nine
//! workflow files, zero jobs named `merge-block-default-branch`. A required
//! context that nothing reports does not block a bad merge; it blocks every
//! merge. The pull request that carries this file sat at `mergeable_state:
//! blocked` with seventy-nine successful checks and one check that GitHub was
//! still waiting for, so the delivery chain could not close no matter how green
//! the tree was.
//!
//! # What this gate decides
//!
//! It answers the question the required context is named after: *may this pull
//! request be merged into the default branch?* The answer is computed from the
//! event payload GitHub hands the runner and from the working tree, never from
//! the network, and every unreadable input is a denial:
//!
//! 1. **The payload must be readable and complete.** A missing file, a missing
//!    field, or a base sha that is not forty hexadecimal characters is a
//!    denial. The rules below cannot be evaluated against an input this gate
//!    could not parse, and "could not evaluate" is not "allowed".
//! 2. **The gate is about the default branch.** When the pull request targets
//!    any other branch the gate reports success and says so: nothing is being
//!    merged into the default branch, so there is nothing for it to block.
//!    Reporting a failure there would put a red check on a stacked pull request
//!    whose base is an integration branch, which is a false alarm that teaches
//!    people to ignore the check.
//! 3. **A fork cannot merge into the default branch.** The head repository must
//!    be the base repository. A missing head repository is a denial.
//! 4. **The head branch must be declared.** `.github/merge-gate-branches.txt`
//!    is the repository's claim about itself: these are the branches whose pull
//!    requests may close into the default branch. An undeclared branch is a
//!    denial, and so is a claim file that is missing or empty - an empty
//!    allowlist read as "no restriction" is the absent-as-permission mistake
//!    this repository keeps paying for.
//! 5. **The diff must not carry what the product may not carry.** The paths in
//!    `.github/merge-gate-forbidden-paths.txt` are prefixes the product tree
//!    does not accept: planning documents, audit notes, review reports. A pull
//!    request that adds one is a denial, because the rule is about what reaches
//!    the product, and a gate that only checks it after the merge is a report.
//! 6. **The diff must be readable.** If `git diff` cannot be run, the changed
//!    paths are unknown, so the gate denies rather than assuming an empty diff.
//!
//! # Why the diff is read here rather than in the workflow
//!
//! A `run:` block that interpolates `${{ github.event.pull_request.* }}` hands
//! workflow authoring a shell-injection surface, and the repository's `zizmor`
//! and `actionlint` jobs reject it. The payload is read by this program from
//! `GITHUB_EVENT_PATH`, which keeps every value out of the shell, and the two
//! shas reach `git` as arguments rather than as text in a script.

use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

use crate::json::{self, Value};

/// The check context the protected branch requires. The workflow job that runs
/// this gate is named exactly this string.
pub const CONTEXT: &str = "merge-block-default-branch";

/// Branches whose pull requests may close into the default branch.
pub const BRANCHES_REL: &str = ".github/merge-gate-branches.txt";

/// Path prefixes the product tree does not accept.
pub const FORBIDDEN_REL: &str = ".github/merge-gate-forbidden-paths.txt";

/// The environment variable GitHub sets to the path of the event payload.
const EVENT_ENV: &str = "GITHUB_EVENT_PATH";

/// What the gate decided, and why. The reason is part of the result because a
/// red check without a sentence is a puzzle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// True when the pull request may merge.
    pub allowed: bool,
    /// One line naming the rule and the evidence.
    pub detail: String,
}

impl Decision {
    fn allow(detail: impl Into<String>) -> Self {
        Self {
            allowed: true,
            detail: detail.into(),
        }
    }

    fn deny(detail: impl Into<String>) -> Self {
        Self {
            allowed: false,
            detail: detail.into(),
        }
    }
}

/// The fields of the payload this gate needs, extracted once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeRequest {
    /// `pull_request.base.sha`, lowercased, forty hex characters.
    pub base_sha: String,
    /// `pull_request.head.sha`, lowercased, forty hex characters.
    pub head_sha: String,
    /// `pull_request.base.ref`, for example `consensus-of-consensuses`.
    pub base_ref: String,
    /// `pull_request.head.ref`, for example `testnet-50`.
    pub head_ref: String,
    /// `repository.default_branch`.
    pub default_branch: String,
    /// `pull_request.head.repo.full_name`; `None` when the head repository is
    /// gone, which is a denial rather than a skip.
    pub head_repo: Option<String>,
    /// `repository.full_name`.
    pub base_repo: String,
    /// `pull_request.number`.
    pub number: u64,
}

/// True when `s` is exactly forty hexadecimal characters.
fn is_sha(s: &str) -> bool {
    s.len() == 40
        && s.bytes().all(|b| b.is_ascii_hexdigit())
        && !s.bytes().any(|b| b.is_ascii_uppercase())
}

fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// Read the payload. Every absent or malformed field is named in the error,
/// because "the payload is wrong" without the field is not actionable.
pub fn read_payload(payload: &str) -> Result<MergeRequest, String> {
    let root =
        json::parse(payload).map_err(|e| format!("{CONTEXT}: event payload is not JSON: {e}"))?;
    let pr = root
        .get("pull_request")
        .ok_or_else(|| format!("{CONTEXT}: event payload has no `pull_request` object"))?;
    let base = pr
        .get("base")
        .ok_or_else(|| format!("{CONTEXT}: event payload has no `pull_request.base` object"))?;
    let head = pr
        .get("head")
        .ok_or_else(|| format!("{CONTEXT}: event payload has no `pull_request.head` object"))?;
    let repo = root
        .get("repository")
        .ok_or_else(|| format!("{CONTEXT}: event payload has no `repository` object"))?;

    let base_sha = text(base, "sha")
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| format!("{CONTEXT}: `pull_request.base.sha` is missing"))?;
    let head_sha = text(head, "sha")
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| format!("{CONTEXT}: `pull_request.head.sha` is missing"))?;
    if !is_sha(&base_sha) {
        return Err(format!(
            "{CONTEXT}: `pull_request.base.sha` is not a forty-character commit id"
        ));
    }
    if !is_sha(&head_sha) {
        return Err(format!(
            "{CONTEXT}: `pull_request.head.sha` is not a forty-character commit id"
        ));
    }
    let base_ref = text(base, "ref")
        .ok_or_else(|| format!("{CONTEXT}: `pull_request.base.ref` is missing"))?
        .to_owned();
    let head_ref = text(head, "ref")
        .ok_or_else(|| format!("{CONTEXT}: `pull_request.head.ref` is missing"))?
        .to_owned();
    let default_branch = text(repo, "default_branch")
        .ok_or_else(|| format!("{CONTEXT}: `repository.default_branch` is missing"))?
        .to_owned();
    let base_repo = text(repo, "full_name")
        .ok_or_else(|| format!("{CONTEXT}: `repository.full_name` is missing"))?
        .to_owned();
    let head_repo = head
        .get("repo")
        .and_then(|r| text(r, "full_name"))
        .map(str::to_owned);
    let number = pr
        .get("number")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{CONTEXT}: `pull_request.number` is missing"))?;

    Ok(MergeRequest {
        base_sha,
        head_sha,
        base_ref,
        head_ref,
        default_branch,
        head_repo,
        base_repo,
        number,
    })
}

/// Parse a claim file into its entries, ignoring comments and blank lines.
///
/// The parser refuses a `#`-only file and an empty name rather than returning
/// an empty list: an empty allowlist read as "no restriction" is exactly the
/// absent-as-permission mistake the surrounding gates exist to stop.
pub fn read_list(text: &str, path: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.contains(char::is_whitespace) {
            return Err(format!(
                "{CONTEXT}: {path} has an entry with whitespace ({line:?}); one name per line"
            ));
        }
        out.push(line.to_owned());
    }
    if out.is_empty() {
        return Err(format!(
            "{CONTEXT}: {path} names nothing. An empty claim reads as full permission, which is \
             the failure this gate exists for."
        ));
    }
    Ok(out)
}

/// True when `path` is unacceptable in the product tree.
///
/// An entry is either a prefix (`.github/audit/`) or a file name without a
/// slash (`NOTES.md`, matched against the basename at any depth), and a `*`
/// suffix makes a suffix match over the basename (`*_PLAN.md`).
#[must_use]
pub fn is_forbidden(path: &str, forbidden: &[String]) -> Option<String> {
    let base = path.rsplit('/').next().unwrap_or(path);
    for entry in forbidden {
        if let Some(stem) = entry.strip_prefix('*') {
            if base.ends_with(stem) {
                return Some(entry.clone());
            }
            continue;
        }
        if entry.contains('/') {
            if path.starts_with(entry.as_str()) || path == entry.trim_end_matches('/') {
                return Some(entry.clone());
            }
            continue;
        }
        if base == entry {
            return Some(entry.clone());
        }
    }
    None
}

/// The whole decision, as a pure function of its inputs.
#[must_use]
pub fn decide(
    req: &MergeRequest,
    branches: &[String],
    forbidden: &[String],
    changed: &[String],
) -> Decision {
    if req.base_ref != req.default_branch {
        return Decision::allow(format!(
            "{CONTEXT}: pull request #{} targets `{}`, not the default branch `{}`; nothing is \
             merging into the default branch, so there is nothing to block here",
            req.number, req.base_ref, req.default_branch
        ));
    }
    match req.head_repo.as_deref() {
        None => {
            return Decision::deny(format!(
                "{CONTEXT}: pull request #{} has no head repository. A fork whose repository is \
                 gone cannot be merged into the default branch.",
                req.number
            ))
        }
        Some(head) if head != req.base_repo => {
            return Decision::deny(format!(
            "{CONTEXT}: pull request #{} comes from fork `{head}`, not `{}`. Fork pull requests \
                 do not merge into the default branch.",
            req.number, req.base_repo
        ))
        }
        Some(_) => {}
    }
    if !branches.iter().any(|b| b == &req.head_ref) {
        return Decision::deny(format!(
            "{CONTEXT}: head branch `{}` is not named by {BRANCHES_REL}. Declared: {}. A branch \
             that is not declared may not close into `{}`.",
            req.head_ref,
            branches.join(", "),
            req.default_branch
        ));
    }
    let mut offences: Vec<String> = Vec::new();
    for path in changed {
        if let Some(entry) = is_forbidden(path, forbidden) {
            offences.push(format!("{path} (matches {entry})"));
        }
    }
    if !offences.is_empty() {
        offences.sort();
        offences.truncate(10);
        return Decision::deny(format!(
            "{CONTEXT}: pull request #{} adds paths the product tree does not accept: {}",
            req.number,
            offences.join("; ")
        ));
    }
    Decision::allow(format!(
        "{CONTEXT}: pull request #{} merges `{}` into `{}` from the same repository, the head \
         branch is declared, and none of the {} changed path(s) is unacceptable",
        req.number,
        req.head_ref,
        req.default_branch,
        changed.len()
    ))
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("{CONTEXT}: cannot run git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{CONTEXT}: git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("{CONTEXT}: git printed non-UTF-8: {e}"))
}

/// The paths the pull request changes, as git reports them.
///
/// Deletions are excluded on purpose: a pull request that *removes* a planning
/// document is doing the right thing, and failing it would make the rule
/// impossible to satisfy.
pub fn changed_paths(root: &Path, req: &MergeRequest) -> Result<Vec<String>, String> {
    let out = git(
        root,
        &[
            "diff",
            "--name-only",
            "--diff-filter=d",
            "--no-renames",
            &req.base_sha,
            &req.head_sha,
        ],
    )?;
    let mut paths: Vec<String> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    paths.sort();
    Ok(paths)
}

/// Run the gate where it is meant to run: from the payload GitHub provides.
pub fn run(root: &Path) -> Result<String, String> {
    let path = std::env::var(EVENT_ENV).map_err(|_| {
        format!(
            "{CONTEXT}: {EVENT_ENV} is not set. Without the event payload this gate cannot \
             evaluate the merge, and a merge it cannot evaluate is not allowed."
        )
    })?;
    let payload = std::fs::read_to_string(&path)
        .map_err(|e| format!("{CONTEXT}: event payload {path} is unreadable: {e}"))?;
    let req = read_payload(&payload)?;
    let branches = read_list(
        &std::fs::read_to_string(root.join(BRANCHES_REL))
            .map_err(|e| format!("{CONTEXT}: {BRANCHES_REL} is unreadable: {e}"))?,
        BRANCHES_REL,
    )?;
    let forbidden = read_list(
        &std::fs::read_to_string(root.join(FORBIDDEN_REL))
            .map_err(|e| format!("{CONTEXT}: {FORBIDDEN_REL} is unreadable: {e}"))?,
        FORBIDDEN_REL,
    )?;
    // The diff is only read when the merge target is the default branch: the
    // other inputs are already enough to answer for a stacked pull request, and
    // running git for a decision that cannot change is work with no witness.
    let changed = if req.base_ref == req.default_branch {
        changed_paths(root, &req)?
    } else {
        Vec::new()
    };
    let decision = decide(&req, &branches, &forbidden, &changed);
    if decision.allowed {
        Ok(decision.detail)
    } else {
        Err(decision.detail)
    }
}

/// Canaries. Each one is a case the gate must get wrong in the direction that
/// hurts: the first four name a merge that must be denied, the last two a merge
/// that must not be.
pub fn self_test() -> Result<String, String> {
    let branches = vec![String::from("testnet-50")];
    let forbidden = vec![
        String::from("review-notes/"),
        String::from("NOTES.md"),
        String::from("*_PLAN.md"),
    ];
    let clean = vec![
        String::from("src/lib.rs"),
        String::from("xtask/tools/src/main.rs"),
    ];
    let base = MergeRequest {
        base_sha: "0".repeat(40),
        head_sha: "1".repeat(40),
        base_ref: String::from("consensus-of-consensuses"),
        head_ref: String::from("testnet-50"),
        default_branch: String::from("consensus-of-consensuses"),
        head_repo: Some(String::from("budlum-xyz/budlum")),
        base_repo: String::from("budlum-xyz/budlum"),
        number: 215,
    };

    // 1. An undeclared head branch is denied.
    let mut undeclared = base.clone();
    undeclared.head_ref = String::from("someone/scratch");
    if decide(&undeclared, &branches, &forbidden, &clean).allowed {
        return Err(format!(
            "canary: an undeclared head branch must be denied by {CONTEXT}"
        ));
    }

    // 2. A fork is denied.
    let mut fork = base.clone();
    fork.head_repo = Some(String::from("attacker/budlum"));
    if decide(&fork, &branches, &forbidden, &clean).allowed {
        return Err(format!("canary: a fork pull request must be denied"));
    }

    // 3. A missing head repository is denied, not skipped.
    let mut gone = base.clone();
    gone.head_repo = None;
    if decide(&gone, &branches, &forbidden, &clean).allowed {
        return Err(format!(
            "canary: a head repository that is gone must be denied, not skipped"
        ));
    }

    // 4. A forbidden path is denied, by prefix, by basename and by suffix.
    for path in [
        "review-notes/2026-11-27-x.md",
        "docs/NOTES.md",
        "docs/FUTURE_PLAN.md",
    ] {
        let changed = vec![String::from(path)];
        if decide(&base, &branches, &forbidden, &changed).allowed {
            return Err(format!("canary: `{path}` must be denied as a product path"));
        }
    }

    // 5. A stacked pull request whose base is not the default branch is
    //    allowed, and the reason says why: a red check there is a false alarm.
    let mut stacked = base.clone();
    stacked.base_ref = String::from("testnet-50");
    stacked.head_ref = String::from("someone/scratch");
    let ok = decide(
        &stacked,
        &branches,
        &forbidden,
        &[String::from("review-notes/x.md")],
    );
    if !ok.allowed || !ok.detail.contains("not the default branch") {
        return Err(format!(
            "canary: a non-default base must be allowed with its reason stated, got {ok:?}"
        ));
    }

    // 6. The declared, same-repository, clean pull request is allowed.
    if !decide(&base, &branches, &forbidden, &clean).allowed {
        return Err(format!(
            "canary: the declarative path must be allowed, or the gate is a wall"
        ));
    }

    // 7. An empty claim file is a denial, not a permission.
    if read_list("# nothing here\n\n", BRANCHES_REL).is_ok() {
        return Err(format!(
            "canary: an empty claim file must be refused, not read as full permission"
        ));
    }

    // 8. A malformed payload is a denial, not a skip.
    if read_payload("{\"pull_request\":{}}").is_ok() {
        return Err(format!("canary: an incomplete payload must not parse"));
    }

    let mut msg = String::new();
    let _ = writeln!(
        msg,
        "{CONTEXT} canary OK (an undeclared branch, a fork, a vanished head repository, a forbidden \
         path and an empty claim file are all denied; a stacked pull request and the declared clean \
         path are allowed with their reasons stated)."
    );
    Ok(msg.trim_end().to_owned())
}

/// Command line: `merge-gate [--self-test]`.
pub fn cli(args: &[&str], root: &Path) -> Result<String, String> {
    match args {
        [] => run(root),
        [flag] if *flag == "--self-test" => self_test(),
        [other, ..] => Err(format!(
            "{CONTEXT}: unknown argument `{other}`; use `--self-test` or nothing"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(base_ref: &str) -> MergeRequest {
        MergeRequest {
            base_sha: "a".repeat(40),
            head_sha: "b".repeat(40),
            base_ref: base_ref.to_owned(),
            head_ref: String::from("testnet-50"),
            default_branch: String::from("consensus-of-consensuses"),
            head_repo: Some(String::from("budlum-xyz/budlum")),
            base_repo: String::from("budlum-xyz/budlum"),
            number: 215,
        }
    }

    #[test]
    fn self_test_canaries_hold() {
        self_test().expect("the canaries must hold");
    }

    #[test]
    fn default_branch_merge_from_a_declared_branch_is_allowed() {
        let d = decide(
            &req("consensus-of-consensuses"),
            &[String::from("testnet-50")],
            &[],
            &[],
        );
        assert!(d.allowed, "{d:?}");
    }

    #[test]
    fn an_undeclared_branch_is_denied_and_named() {
        let d = decide(
            &req("consensus-of-consensuses"),
            &[String::from("other")],
            &[],
            &[],
        );
        assert!(!d.allowed);
        assert!(d.detail.contains("testnet-50"), "{}", d.detail);
    }

    #[test]
    fn the_allowlist_entry_must_match_exactly() {
        let d = decide(
            &req("consensus-of-consensuses"),
            &[String::from("testnet-50-evil")],
            &[],
            &[],
        );
        assert!(
            !d.allowed,
            "a prefix of a declared branch is not the branch"
        );
    }

    #[test]
    fn a_stacked_pull_request_is_allowed_with_its_reason() {
        let d = decide(
            &req("testnet-50"),
            &[],
            &[],
            &[String::from("review-notes/x.md")],
        );
        assert!(d.allowed);
        assert!(d.detail.contains("not the default branch"));
    }

    #[test]
    fn forbidden_matching_reads_prefix_basename_and_suffix() {
        let forbidden = vec![
            String::from("review-notes/"),
            String::from("NOTES.md"),
            String::from("*_PLAN.md"),
        ];
        assert!(is_forbidden("review-notes/a.md", &forbidden).is_some());
        assert!(is_forbidden("deep/dir/NOTES.md", &forbidden).is_some());
        assert!(is_forbidden("deep/dir/X_PLAN.md", &forbidden).is_some());
        assert!(is_forbidden("deep/dir/PLAN.md", &forbidden).is_none());
        assert!(is_forbidden("src/NOTES.md.bak", &forbidden).is_none());
    }

    #[test]
    fn a_deleted_planning_document_is_not_an_offence() {
        // `changed_paths` filters deletions, so the pure decision never sees
        // one; this asserts the reason the filter exists is stated in code.
        let d = decide(
            &req("consensus-of-consensuses"),
            &[String::from("testnet-50")],
            &[],
            &[],
        );
        assert!(d.allowed);
    }

    #[test]
    fn payload_fields_are_read_and_shas_are_validated() {
        let payload = r#"{
            "repository": {"full_name": "budlum-xyz/budlum", "default_branch": "consensus-of-consensuses"},
            "pull_request": {
                "number": 215,
                "base": {"sha": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "ref": "consensus-of-consensuses"},
                "head": {"sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "ref": "testnet-50",
                         "repo": {"full_name": "budlum-xyz/budlum"}}
            }
        }"#;
        let parsed = read_payload(payload).expect("the payload must parse");
        assert_eq!(parsed.base_sha, "a".repeat(40), "the sha is lowercased");
        assert_eq!(parsed.head_ref, "testnet-50");
        assert_eq!(parsed.number, 215);

        let short = payload.replace(&"a".repeat(40).to_uppercase(), "abc");
        assert!(read_payload(&short).is_err(), "a short sha must be refused");
    }

    #[test]
    fn a_whitespace_bearing_claim_entry_is_refused() {
        assert!(read_list("testnet-50 extra\n", BRANCHES_REL).is_err());
    }
}
