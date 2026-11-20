//! A seal moves with the tree it seals, and with nothing else.
//!
//! Two artefacts in this repository are not code but claims about code:
//!
//!   * `xtask/gates/pins/*` pins the Keccak-256 of every source and build input
//!     under `budzero/`;
//!   * `.github/gate-source-provenance-baseline.txt` pins the SHA-256 of every
//!     file under `xtask/gates/`.
//!
//! Both are whole-file digests of a tree that lives somewhere else. The
//! contract they work under is written in `tree_pin.rs`: pins move with
//! development, and a regenerated pin file must be committed together with the
//! change it describes. CI runs the check without `--pin`, so an unpinned edit
//! is red.
//!
//! # What this gate asks, and what it deliberately does not
//!
//! This gate asks the one question that follows from that contract: **if a seal
//! changed, did the tree it seals change in the same commit?**
//!
//! A seal that moves while its tree stands still describes nothing. Either the
//! pin was regenerated from the wrong tree, or an edit to the sealed tree is
//! hiding behind an unrelated commit, or the seal is being moved to quiet a
//! gate. All three are worth a red light, and none of them is visible to
//! `tree-pin` or `gate-source-provenance`, which only compare the seal against
//! the tree as it stands at the tip.
//!
//! The gate does **not** ask whether a commit that touches a seal touches
//! anything else. That was the first shape of this gate and it was wrong:
//! `tree-pin`'s contract requires the pin to travel with its change, so forcing
//! the pin into a commit of its own guarantees a red intermediate commit and
//! poisons `git bisect`. Measured over 21 mixed commits, about half were
//! legitimate atomic changes, so the isolation rule was a false alarm machine.
//!
//! # Ratchet baselines are not seals
//!
//! Nineteen files under `.github/` also end in `-baseline.txt`, and they are a
//! different thing. `idle-code-baseline.txt`, `concept-names-baseline.txt`,
//! `dead-pub-api-baseline.txt` and the rest are counters of the tree's own
//! debt: a line is removed from them when the code change that made it
//! removable lands. Their contract is the opposite of a seal's - they must move
//! **with** the code, in the same commit. Treating them as seals would forbid
//! the only correct way to update them, so they are out of scope here.
//!
//! # Window, cutoff and failing closed
//!
//! On CI the window is `origin/$GITHUB_BASE_REF..HEAD`. Locally it falls back to
//! the last [`WINDOW`] commits, or the whole history when the repository is
//! shorter. A window that cannot be resolved is an error: a gate that inspects
//! zero commits reports green while proving nothing.
//!
//! Commits before the date in [`.github/seal-tree-cutoff.txt`] are counted and
//! reported but not judged. A date and not a list of SHAs, because a rebase or a
//! squash rewrites every SHA in a pull request and would silently empty a
//! SHA-keyed exemption list. A missing cutoff judges everything; an unparsable
//! one fails closed.
//!
//! # Merge commits
//!
//! A merge has no diff of its own, so it is not judged. Merges are counted in
//! the report so the window cannot shrink unnoticed.

use std::path::Path;
use std::process::Command;

/// A seal, and the tree whose files it digests.
const SEALS: &[(&str, &str)] = &[
    ("xtask/gates/pins/", "budzero/"),
    (
        ".github/gate-source-provenance-baseline.txt",
        "xtask/gates/",
    ),
];

/// Fallback window when no base ref is configured.
const WINDOW: usize = 200;

/// Grandfathering cutoff, as an RFC 3339 date in UTC.
const CUTOFF_FILE: &str = ".github/seal-tree-cutoff.txt";

/// One seal that moved while its tree stood still.
#[derive(Debug, PartialEq, Eq)]
struct Finding {
    sha: String,
    subject: String,
    seal: String,
    tree: String,
}

/// The tree a path belongs to, when the path is a seal.
fn sealed_tree(path: &str) -> Option<&'static str> {
    let path = path.strip_prefix("./").unwrap_or(path);
    SEALS
        .iter()
        .find(|(seal, _)| path.starts_with(seal))
        .map(|(_, tree)| *tree)
}

/// Run git inside `root` and return stdout, failing on a non-zero exit.
fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|e| format!("git {} failed to start: {e}", args.join(" ")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "git {} exited {}: {}",
            args.join(" "),
            out.status,
            err.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Resolve the commit window to inspect.
fn window(root: &Path) -> Result<Option<String>, String> {
    if let Ok(base) = std::env::var("GITHUB_BASE_REF") {
        let base = base.trim();
        if !base.is_empty() {
            for candidate in [format!("origin/{base}"), base.to_string()] {
                if git(root, &["rev-parse", "--verify", "--quiet", &candidate]).is_ok() {
                    return Ok(Some(format!("{candidate}..HEAD")));
                }
            }
            return Err(format!(
                "GITHUB_BASE_REF is `{base}` but neither origin/{base} nor {base} resolves; refusing to inspect an empty window"
            ));
        }
    }
    let deep = format!("HEAD~{WINDOW}");
    if git(root, &["rev-parse", "--verify", "--quiet", &deep]).is_ok() {
        return Ok(Some(format!("{deep}..HEAD")));
    }
    Ok(None)
}

/// List the commits in the window, newest first.
fn commits(root: &Path, range: Option<&str>) -> Result<Vec<String>, String> {
    let mut args = vec!["rev-list", "--no-merges"];
    if let Some(r) = range {
        args.push(r);
    } else {
        args.push("HEAD");
    }
    let out = git(root, &args)?;
    Ok(out
        .lines()
        .map(str::trim)
        .filter(|l| l.len() >= 7)
        .map(str::to_string)
        .collect())
}

/// Read the files one commit changed, as repository-relative paths.
fn changed_files(root: &Path, sha: &str) -> Result<Vec<String>, String> {
    let out = git(
        root,
        &[
            "show",
            "--no-renames",
            "--name-only",
            "--format=",
            "--unified=0",
            sha,
        ],
    )?;
    Ok(out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

/// Subject line of a commit, for the report.
fn subject(root: &Path, sha: &str) -> String {
    git(root, &["log", "-1", "--format=%s", sha])
        .unwrap_or_default()
        .trim()
        .chars()
        .take(72)
        .collect()
}

/// Commit time as a unix timestamp.
fn commit_time(root: &Path, sha: &str) -> Result<i64, String> {
    let out = git(root, &["log", "-1", "--format=%ct", sha])?;
    out.trim()
        .parse::<i64>()
        .map_err(|e| format!("commit {sha} has no readable time: {e}"))
}

/// Parse an RFC 3339 UTC date into a unix timestamp without pulling in chrono.
///
/// Only the documented shape is accepted: `YYYY-MM-DD` with an optional
/// `THH:MM:SSZ`. Anything else is an error, because a cutoff that is silently
/// misread exempts commits nobody meant to exempt.
fn parse_cutoff(text: &str) -> Result<i64, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err(format!("{CUTOFF_FILE} is empty"));
    }
    let (date, time) = match t.split_once('T') {
        Some((d, rest)) => {
            let rest = rest.strip_suffix('Z').ok_or_else(|| {
                format!("{CUTOFF_FILE}: `{t}` needs a `Z` suffix to say it is UTC")
            })?;
            (d, rest)
        }
        None => (t, "00:00:00"),
    };
    let mut dp = date.split('-');
    let (y, m, d) = (
        dp.next().unwrap_or(""),
        dp.next().unwrap_or(""),
        dp.next().unwrap_or(""),
    );
    if dp.next().is_some() {
        return Err(format!("{CUTOFF_FILE}: `{t}` has too many date parts"));
    }
    let tp: Vec<&str> = time.split(':').collect();
    if tp.len() != 3 {
        return Err(format!("{CUTOFF_FILE}: `{t}` time is not HH:MM:SS"));
    }
    let num = |s: &str, what: &str| -> Result<i64, String> {
        s.parse::<i64>()
            .map_err(|_| format!("{CUTOFF_FILE}: `{t}` {what} is not a number"))
    };
    let (year, month, day) = (num(y, "year")?, num(m, "month")?, num(d, "day")?);
    let (hour, minute, second) = (
        num(tp[0], "hour")?,
        num(tp[1], "minute")?,
        num(tp[2], "second")?,
    );
    if !(1970..=2999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(format!("{CUTOFF_FILE}: `{t}` is not a real date and time"));
    }
    // Days from the epoch by Hinnant's civil calendar inverse. No float, no
    // locale, no wall clock: one input, one answer.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Read the grandfathering cutoff, if the tree carries one.
fn cutoff(root: &Path) -> Result<Option<i64>, String> {
    let path = root.join(CUTOFF_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{CUTOFF_FILE}: {e}"))?;
    Ok(Some(parse_cutoff(&text)?))
}

/// Core judgement over an already-resolved window.
fn evaluate(root: &Path) -> Result<String, String> {
    let range = window(root)?;
    let shas = commits(root, range.as_deref())?;
    let cutoff = cutoff(root)?;
    let mut findings: Vec<Finding> = Vec::new();
    let mut inspected = 0_usize;
    let mut seals = 0_usize;
    let mut exempt = 0_usize;

    for sha in &shas {
        inspected = inspected.saturating_add(1);
        let files = changed_files(root, sha)?;
        let mut moved: Vec<(&str, &str)> = Vec::new();
        for f in &files {
            if let Some(tree) = sealed_tree(f) {
                if !moved.iter().any(|(_, t)| *t == tree) {
                    moved.push((f, tree));
                }
            }
        }
        if moved.is_empty() {
            continue;
        }
        seals = seals.saturating_add(moved.len());
        if let Some(cut) = cutoff {
            if commit_time(root, sha)? < cut {
                exempt = exempt.saturating_add(1);
                continue;
            }
        }
        for (seal, tree) in moved {
            if !files.iter().any(|f| f.starts_with(tree)) {
                findings.push(Finding {
                    sha: sha.chars().take(10).collect(),
                    subject: subject(root, sha),
                    seal: seal.to_string(),
                    tree: tree.to_string(),
                });
            }
        }
    }

    if !findings.is_empty() {
        use std::fmt::Write as _;
        let mut msg = format!(
            "a seal moved while the tree it seals stood still: {} case(s) in {} commit(s)\n",
            findings.len(),
            inspected
        );
        for f in findings.iter().take(20) {
            let _ = writeln!(
                msg,
                "  {} {} | seal: {} | sealed tree with no change: {}",
                f.sha, f.subject, f.seal, f.tree
            );
        }
        if findings.len() > 20 {
            let _ = writeln!(msg, "  ... {} more", findings.len() - 20);
        }
        msg.push_str(
            "A regenerated seal belongs in the commit that changed the tree it describes.",
        );
        return Err(msg);
    }

    let scope = match &range {
        Some(r) => r.clone(),
        None => format!("full history (shorter than {WINDOW} commits)"),
    };
    let exempted = if exempt > 0 {
        format!(", {exempt} grandfathered by {CUTOFF_FILE}")
    } else {
        String::new()
    };
    Ok(format!(
        "seals move with their tree: {inspected} commit(s) inspected in {scope}, {seals} seal change(s){exempted}, none moved alone"
    ))
}

/// Gate entry point.
pub fn run(root: &Path) -> Result<String, String> {
    evaluate(root)
}

/// Scratch directory for the canary, unique per process and instant.
fn scratch_dir() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("seal-tree-canary-{}-{nanos}", std::process::id()))
}

/// Run git inside the canary tree, ignoring output but not failure.
fn git_in(base: &Path, args: &[&str]) -> Result<(), String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(base)
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    Ok(())
}

/// Commit the canary tree under a fixed identity.
fn commit_in(base: &Path, msg: &str) -> Result<(), String> {
    git_in(
        base,
        &[
            "-c",
            "user.name=canary",
            "-c",
            "user.email=canary@budlum.local",
            "commit",
            "-q",
            "-m",
            msg,
        ],
    )
}

/// Write a file inside the canary tree.
fn write_in(base: &Path, rel: &str, body: &str) -> Result<(), String> {
    std::fs::write(base.join(rel), body).map_err(|e| e.to_string())
}

/// Stage everything in the canary tree.
fn add_all_in(base: &Path) -> Result<(), String> {
    git_in(base, &["add", "-A"])
}

/// Seed the canary: a sealed tree and its seal, in one commit.
fn seed(base: &Path) -> Result<(), String> {
    write_in(base, "budzero/src/lib.rs", "pub fn f() -> u8 { 1 }\n")?;
    write_in(
        base,
        "xtask/gates/pins/tree.pins",
        "budzero/src/lib.rs aaa\n",
    )?;
    write_in(base, "xtask/gates/src/gate.rs", "pub fn g() {}\n")?;
    write_in(
        base,
        ".github/gate-source-provenance-baseline.txt",
        "digest: aaa\n",
    )?;
    write_in(base, ".github/idle-code-baseline.txt", "src/x.rs\n")?;
    write_in(base, "src/x.rs", "pub fn x() {}\n")?;
    add_all_in(base)?;
    commit_in(base, "seed: tree and seal together")?;
    evaluate(base)
        .map(|_| ())
        .map_err(|e| format!("canary `seed` failed when it must pass: {e}"))
}

/// Canaries around the seal: what may and may not travel with it.
fn canary_seal_rules(base: &Path) -> Result<(), String> {
    // The contract: a seal regenerated beside its tree is correct.
    write_in(base, "budzero/src/lib.rs", "pub fn f() -> u8 { 2 }\n")?;
    write_in(
        base,
        "xtask/gates/pins/tree.pins",
        "budzero/src/lib.rs bbb\n",
    )?;
    add_all_in(base)?;
    commit_in(base, "seal moves with its tree")?;
    evaluate(base)
        .map(|_| ())
        .map_err(|e| format!("canary `seal-with-tree` failed when it must pass: {e}"))?;

    // A seal regenerated while its tree stands still describes nothing.
    write_in(
        base,
        "xtask/gates/pins/tree.pins",
        "budzero/src/lib.rs ccc\n",
    )?;
    add_all_in(base)?;
    commit_in(base, "seal alone")?;
    if evaluate(base).is_ok() {
        return Err(String::from("canary `seal-alone` passed when it must fail"));
    }
    git_in(base, &["reset", "-q", "--hard", "HEAD~1"])?;

    // The provenance seal answers to xtask/gates, not to budzero.
    write_in(
        base,
        ".github/gate-source-provenance-baseline.txt",
        "digest: bbb\n",
    )?;
    add_all_in(base)?;
    commit_in(base, "provenance seal alone")?;
    if evaluate(base).is_ok() {
        return Err(String::from(
            "canary `provenance-seal-alone` passed when it must fail",
        ));
    }
    git_in(base, &["reset", "-q", "--hard", "HEAD~1"])?;

    // The same seal beside a change under xtask/gates is correct.
    write_in(
        base,
        "xtask/gates/src/gate.rs",
        "pub fn g() { let _ = 1; }\n",
    )?;
    write_in(
        base,
        ".github/gate-source-provenance-baseline.txt",
        "digest: ccc\n",
    )?;
    add_all_in(base)?;
    commit_in(base, "provenance seal with its tree")?;
    evaluate(base)
        .map(|_| ())
        .map_err(|e| format!("canary `provenance-with-tree` failed when it must pass: {e}"))?;

    // A ratchet baseline is a counter, not a seal: it must move with the code.
    write_in(base, ".github/idle-code-baseline.txt", "")?;
    write_in(base, "src/x.rs", "pub fn x() { let _ = 2; }\n")?;
    add_all_in(base)?;
    commit_in(base, "ratchet baseline with its code")?;
    evaluate(base)
        .map(|_| ())
        .map_err(|e| format!("canary `ratchet-with-code` failed when it must pass: {e}"))?;

    // A seal travelling with unrelated work is still fine, as long as the
    // sealed tree moved too. That is the correction to the first shape of this
    // gate: tree-pin's contract asks the pin to travel with its change.
    write_in(base, "budzero/src/lib.rs", "pub fn f() -> u8 { 3 }\n")?;
    write_in(
        base,
        "xtask/gates/pins/tree.pins",
        "budzero/src/lib.rs ddd\n",
    )?;
    write_in(base, "src/x.rs", "pub fn x() { let _ = 3; }\n")?;
    add_all_in(base)?;
    commit_in(base, "seal, its tree, and unrelated work in one commit")?;
    evaluate(base)
        .map(|_| ())
        .map_err(|e| format!("canary `seal-tree-plus-work` failed when it must pass: {e}"))
}

/// Canaries around the cutoff and the window: both fail closed.
fn canary_cutoffs(base: &Path) -> Result<(), String> {
    write_in(
        base,
        "xtask/gates/pins/tree.pins",
        "budzero/src/lib.rs eee\n",
    )?;
    add_all_in(base)?;
    commit_in(base, "seal alone again")?;
    if evaluate(base).is_ok() {
        return Err(String::from(
            "canary `second-seal-alone` passed when it must fail",
        ));
    }
    // A cutoff after the mixed commits grandfathers them.
    write_in(base, CUTOFF_FILE, "2999-01-01T00:00:00Z\n")?;
    add_all_in(base)?;
    commit_in(base, "cutoff: grandfather the history")?;
    evaluate(base)
        .map(|_| ())
        .map_err(|e| format!("canary `cutoff-grandfathers` failed when it must pass: {e}"))?;
    // An unparsable cutoff fails closed.
    write_in(base, CUTOFF_FILE, "next quarter\n")?;
    if evaluate(base).is_ok() {
        return Err(String::from(
            "canary `unparsable-cutoff` passed when it must fail closed",
        ));
    }
    // An unresolvable base ref fails closed rather than inspecting nothing.
    write_in(base, CUTOFF_FILE, "1970-01-02T00:00:00Z\n")?;
    std::env::set_var("GITHUB_BASE_REF", "no-such-base-ref");
    let closed = evaluate(base);
    std::env::remove_var("GITHUB_BASE_REF");
    if closed.is_ok() {
        return Err(String::from(
            "canary `unresolvable-base-ref` passed when it must fail closed",
        ));
    }
    Ok(())
}

/// Canary: a seal beside its tree passes, a seal alone fails.
pub fn self_test() -> Result<String, String> {
    let base = scratch_dir();
    for d in [
        "xtask/gates/pins",
        "xtask/gates/src",
        "budzero/src",
        ".github",
        "src",
    ] {
        std::fs::create_dir_all(base.join(d)).map_err(|e| e.to_string())?;
    }
    if git_in(&base, &["init"]).is_err() {
        let _ = std::fs::remove_dir_all(&base);
        return Ok(String::from(
            "seals-move-with-their-tree canary skipped: git unavailable",
        ));
    }
    let outcome = seed(&base)
        .and_then(|()| canary_seal_rules(&base))
        .and_then(|()| canary_cutoffs(&base));
    let _ = std::fs::remove_dir_all(&base);
    outcome?;
    Ok(String::from(
        "seals-move-with-their-tree canary OK: seal-with-tree, provenance-with-tree, ratchet-with-code and seal-tree-plus-work accepted; seal-alone and provenance-seal-alone refused; a future cutoff grandfathers; unparsable cutoff and unresolvable base ref fail closed",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_answer_to_their_own_tree() {
        assert_eq!(
            sealed_tree("xtask/gates/pins/budzero-tree.pins"),
            Some("budzero/")
        );
        assert_eq!(
            sealed_tree("xtask/gates/pins/nested/deep.pins"),
            Some("budzero/")
        );
        assert_eq!(
            sealed_tree(".github/gate-source-provenance-baseline.txt"),
            Some("xtask/gates/")
        );
        assert_eq!(
            sealed_tree("./xtask/gates/pins/tree.pins"),
            Some("budzero/")
        );
    }

    #[test]
    fn ratchet_baselines_are_not_seals() {
        for f in [
            ".github/idle-code-baseline.txt",
            ".github/concept-names-baseline.txt",
            ".github/dead-pub-api-baseline.txt",
            ".github/no-legacy-storage-baseline.txt",
            ".github/unwired-baseline.txt",
            ".github/turkish-baseline.txt",
        ] {
            assert_eq!(sealed_tree(f), None, "`{f}` is a counter, not a seal");
        }
    }

    #[test]
    fn code_and_other_artefacts_are_not_seals() {
        for f in [
            "src/privacy/note_registry.rs",
            "budzero/src/lib.rs",
            "xtask/gates/src/main.rs",
            ".github/workflows/ci.yml",
            ".github/audit-guard-history-quarantine.txt",
            "xtask/gates/pins",
        ] {
            assert_eq!(sealed_tree(f), None, "`{f}` must not be read as a seal");
        }
    }

    #[test]
    fn cutoff_parses_and_orders() {
        let day = parse_cutoff("2026-11-21").expect("bare date");
        assert_eq!(day, 1_795_219_200);
        assert_eq!(parse_cutoff("2026-11-21T00:00:00Z").expect("full"), day);
        assert_eq!(
            parse_cutoff("2026-11-21T01:00:00Z").expect("hour"),
            day + 3_600
        );
        assert!(parse_cutoff("2026-11-22").expect("next day") > day);
        assert!(parse_cutoff("2024-02-29").is_ok());
        assert!(parse_cutoff("2026-12-31T23:59:59Z").is_ok());
    }

    #[test]
    fn cutoff_refuses_nonsense() {
        for bad in [
            "",
            "next quarter",
            "2026-13-01",
            "2026-00-10",
            "2026-11-32",
            "2026-11-20T25:00:00Z",
            "2026-11-20T10:70:00Z",
            "2026-11-20 10:00:00Z",
            "2026-11-20T10:00:00",
            "2026-11-20-extra",
        ] {
            assert!(
                parse_cutoff(bad).is_err(),
                "`{bad}` must not be accepted as a cutoff"
            );
        }
    }

    #[test]
    fn canary_runs() {
        self_test().expect("canary must pass");
    }
}
