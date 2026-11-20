//! A commit that re-pins the vendored tree changes nothing but the pins.
//!
//! The vendored proof tree and the gate source provenance baseline are sealed
//! by SHA-256 over whole files: `xtask/gates/pins/*.pins` and
//! `.github/*-baseline.txt`. Sealing by file hash is deliberate. It catches a
//! smuggled one-character change that a semantic diff would not describe, and
//! it makes "the vendored bytes are exactly the audited bytes" a statement a
//! machine can check instead of a statement a reviewer has to believe.
//!
//! # The friction this gate removes by making it cheap
//!
//! The price of byte sealing is paid on every legitimate edit. Making a
//! vendored constant `pub` so first-party code can read a limit changes one
//! word, changes no behaviour, and changes the SHA-256 of the file. The seal
//! goes red, the whole vendored tree has to be re-measured, and a commit that
//! carried a hardening now has to carry a re-measurement as well.
//!
//! That price is the reason re-pin discipline decays. An agent facing a red
//! seal in the middle of unrelated work has two ways out: re-measure now, in
//! the same commit, mixing a pin update with logic; or quiet the gate. The
//! second option is the one that ends a supply chain control, and it is always
//! available.
//!
//! This gate makes the first option the only one, and makes it mechanical. A
//! commit that touches a pin or a baseline file touches **nothing else**. Not
//! one source line, not one workflow, not one test. The re-measurement is its
//! own commit, so:
//!
//!   * the logic diff and the pin diff never have to be reviewed at the same
//!     time, which is what makes re-pinning cheap instead of dreaded;
//!   * a logic change can never hide inside a re-pin commit, because there is
//!     nowhere in that commit for it to be;
//!   * the pin update stays revertible on its own. A bad re-measurement can be
//!     dropped without dragging the hardening down with it.
//!
//! # Why "inert" and not "correct"
//!
//! This gate does not verify that the new pin values are right. That is
//! `gate-source-provenance`, which recomputes every hash and compares the
//! binary against the tree. A commit can be perfectly inert and pin the wrong
//! bytes; the provenance gate is what catches that. What this gate forbids is
//! narrower and complementary: the inert commit must stay inert.
//!
//! # What counts as a pin path
//!
//!   * anything under `xtask/gates/pins/`;
//!   * anything directly under `.github/` whose name ends in `-baseline.txt`.
//!
//! Both are whole-file digests of another artefact, so both carry the same
//! review problem. Baselines are ratchets that only shrink, and a ratchet line
//! removed beside the code change that made it removable is exactly the
//! pairing a reviewer should see in one diff - so baselines are treated the
//! same way and the pairing has to be two commits, not one.
//!
//! # Why this is ratcheted and not absolute
//!
//! Measured on the tree when this gate was written: of the last 119 commits,
//! **31** mix a pin or baseline update with other files. A gate that fails on
//! all of them fails on every commit and gets switched off, which is worse
//! than no gate - the same reasoning that made `no-idle-code` and
//! `indexing-is-not-new` ratchets.
//!
//! So the history is grandfathered by a cutoff date in
//! [`.github/re-pin-inert-cutoff.txt`]: commits dated before the cutoff are
//! counted and reported but not judged. Every commit after it must be inert.
//! A date, not a list of SHAs, because a rebase or a squash rewrites every SHA
//! in a pull request and would silently empty a SHA-keyed exemption list.
//! Moving the cutoff later is a visible one-line diff and belongs to whoever
//! reviews it; the ratchet only earns trust if the line is honest about being
//! moved.
//!
//! A missing cutoff file judges everything. A cutoff that cannot be parsed is
//! an error, not a pass.
//!
//! # Window, and what happens when it cannot be measured
//!
//! On CI the window is `origin/$GITHUB_BASE_REF..HEAD`: exactly the commits the
//! pull request adds. Locally there is no base ref, so the window falls back to
//! the last [`WINDOW`] commits, or the whole reachable history when the
//! repository is shorter than that.
//!
//! A window that cannot be resolved is an error, not a pass. A gate that
//! silently inspects zero commits reports green while checking nothing, and
//! that green is worse than the friction the gate exists to remove.
//!
//! # Merge commits
//!
//! A merge commit has no diff of its own, so it cannot be judged for inertness
//! and is not judged. It is counted in the report so the window cannot shrink
//! without anyone noticing: if a merge brings in a re-pin alongside logic, both
//! of those arrived through real commits on a branch, and those commits are in
//! the window and are judged.

use std::path::Path;
use std::process::Command;

/// Directory holding the vendored tree seals.
const PINS_DIR: &str = "xtask/gates/pins";

/// Directory holding the gate baselines.
const BASELINE_DIR: &str = ".github";

/// Suffix that marks a gate baseline file.
const BASELINE_SUFFIX: &str = "-baseline.txt";

/// Fallback window when no base ref is configured.
const WINDOW: usize = 200;

/// Grandfathering cutoff, as an RFC 3339 date in UTC.
const CUTOFF_FILE: &str = ".github/re-pin-inert-cutoff.txt";

/// One commit that mixed a pin update with something else.
#[derive(Debug, PartialEq, Eq)]
struct Finding {
    sha: String,
    subject: String,
    pins: Vec<String>,
    others: Vec<String>,
}

/// True when the path is a pin file or a gate baseline.
fn is_pin_path(rel: &str) -> bool {
    let rel = rel.strip_prefix("./").unwrap_or(rel);
    if let Some(rest) = rel.strip_prefix(PINS_DIR) {
        return rest.starts_with('/') && rest.len() > 1;
    }
    if let Some(rest) = rel.strip_prefix(BASELINE_DIR) {
        if let Some(name) = rest.strip_prefix('/') {
            return !name.contains('/') && name.ends_with(BASELINE_SUFFIX);
        }
    }
    false
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
///
/// Returns the revision range argument, or `None` for "whole history".
fn window(root: &Path) -> Result<Option<String>, String> {
    if let Ok(base) = std::env::var("GITHUB_BASE_REF") {
        let base = base.trim();
        if !base.is_empty() {
            for candidate in [format!("origin/{base}"), base.to_string()] {
                if git(root, &["rev-parse", "--verify", "--quiet", &candidate]).is_ok() {
                    return Ok(Some(format!("{candidate}..HEAD")));
                }
            }
            // The base ref was named but cannot be resolved. Fail closed:
            // inspecting nothing would report green over an empty window.
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
        .map(|l| l.trim().to_string())
        .filter(|l| l.len() >= 7)
        .collect())
}

/// Parse an RFC 3339 UTC date into a unix timestamp without pulling in chrono.
///
/// Only the shape this file documents is accepted: `YYYY-MM-DD` with an
/// optional `THH:MM:SSZ`. Anything else is an error, because a cutoff that is
/// silently misread exempts commits nobody meant to exempt.
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
    // Days from the epoch, Hinnant's civil_from_days inverse. No float, no
    // locale, no wall clock: the same input always gives the same second.
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

/// Commit time as a unix timestamp.
fn commit_time(root: &Path, sha: &str) -> Result<i64, String> {
    let out = git(root, &["log", "-1", "--format=%ct", sha])?;
    out.trim()
        .parse::<i64>()
        .map_err(|e| format!("commit {sha} has no readable time: {e}"))
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
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
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

/// Core judgement over an already-resolved window.
fn evaluate(root: &Path) -> Result<String, String> {
    let range = window(root)?;
    let shas = commits(root, range.as_deref())?;
    let cutoff = cutoff(root)?;
    let mut findings: Vec<Finding> = Vec::new();
    let mut inspected = 0_usize;
    let mut repins = 0_usize;
    let mut exempt = 0_usize;

    for sha in &shas {
        inspected = inspected.saturating_add(1);
        let files = changed_files(root, sha)?;
        let mut pins: Vec<String> = Vec::new();
        let mut others: Vec<String> = Vec::new();
        for f in files {
            if is_pin_path(&f) {
                pins.push(f);
            } else {
                others.push(f);
            }
        }
        if pins.is_empty() {
            continue;
        }
        repins = repins.saturating_add(1);
        if let Some(cut) = cutoff {
            if commit_time(root, sha)? < cut {
                exempt = exempt.saturating_add(1);
                continue;
            }
        }
        if !others.is_empty() {
            pins.sort();
            others.sort();
            findings.push(Finding {
                sha: sha.chars().take(10).collect(),
                subject: subject(root, sha),
                pins,
                others,
            });
        }
    }

    if !findings.is_empty() {
        use std::fmt::Write as _;
        let mut msg = format!(
            "re-pin commits are not inert: {} of {} commit(s) in the window mix a pin or baseline update with other files\n",
            findings.len(),
            inspected
        );
        for f in findings.iter().take(20) {
            let _ = writeln!(
                msg,
                "  {} {} | pin(s): {} | other file(s): {}",
                f.sha,
                f.subject,
                f.pins.join(", "),
                f.others.join(", ")
            );
        }
        if findings.len() > 20 {
            let _ = writeln!(msg, "  ... {} more", findings.len() - 20);
        }
        msg.push_str(
            "Split it: one commit carries the change, the next carries only the re-measured pins and baselines.",
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
        "re-pin commits are inert: {inspected} commit(s) inspected in {scope}, {repins} re-pin commit(s){exempted}, none judged carries another file"
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
    std::env::temp_dir().join(format!("re-pin-canary-{}-{nanos}", std::process::id()))
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

/// Seed the canary tree in two commits, the way this gate asks for it: the
/// source first, then the pins that seal it.
///
/// One combined seed commit would be a re-pin carrying a source file and would
/// fail its own canary, so every later measurement would be measuring the seed.
fn seed(base: &Path) -> Result<(), String> {
    write_in(base, "src/lib.rs", "pub fn f() -> u8 { 1 }\n")?;
    add_all_in(base)?;
    commit_in(base, "seed: source")?;
    write_in(base, "xtask/gates/pins/tree.pins", "src/lib.rs aaa\n")?;
    write_in(
        base,
        &format!("{BASELINE_DIR}/sample{BASELINE_SUFFIX}"),
        "src/lib.rs\n",
    )?;
    add_all_in(base)?;
    commit_in(base, "seed: pins")?;
    evaluate(base)
        .map(|_| ())
        .map_err(|e| format!("canary `split-seed` failed when it must pass: {e}"))
}

/// Canaries that must fail: a pin update carried beside other work.
fn canary_refuses_mixtures(base: &Path) -> Result<(), String> {
    // A pin update carrying a logic change must fail.
    write_in(base, "xtask/gates/pins/tree.pins", "src/lib.rs bbb\n")?;
    write_in(base, "src/lib.rs", "pub fn f() -> u8 { 2 }\n")?;
    add_all_in(base)?;
    commit_in(base, "mixed pin and logic")?;
    if evaluate(base).is_ok() {
        return Err(String::from(
            "canary `pin-plus-logic` passed when it must fail",
        ));
    }

    // The same work split in two. The inert half must pass.
    //
    // `--hard`, not `--soft`. A soft reset keeps the pin file staged, so the
    // "logic only" commit silently carries it - which is exactly the mixture
    // this gate refuses. The canary found that while it was being written.
    git_in(base, &["reset", "-q", "--hard", "HEAD~1"])?;
    write_in(base, "src/lib.rs", "pub fn f() -> u8 { 3 }\n")?;
    add_all_in(base)?;
    commit_in(base, "logic only")?;
    write_in(base, "xtask/gates/pins/tree.pins", "src/lib.rs ccc\n")?;
    git_in(base, &["add", "xtask/gates/pins/tree.pins"])?;
    commit_in(base, "pins only")?;
    evaluate(base).map_err(|e| format!("canary `split-in-two` failed when it must pass: {e}"))?;

    // A baseline ratchet line removed beside its code change must fail, for
    // the same reason as a pin.
    write_in(base, &format!("{BASELINE_DIR}/sample{BASELINE_SUFFIX}"), "")?;
    write_in(base, "src/lib.rs", "pub fn f() -> u8 { 4 }\n")?;
    add_all_in(base)?;
    commit_in(base, "ratchet plus logic")?;
    if evaluate(base).is_ok() {
        return Err(String::from(
            "canary `baseline-plus-logic` passed when it must fail",
        ));
    }

    // A deleted pin file carried beside logic is still a pin touch.
    git_in(base, &["reset", "-q", "--hard", "HEAD~1"])?;
    std::fs::remove_file(base.join("xtask/gates/pins/tree.pins")).map_err(|e| e.to_string())?;
    write_in(base, "src/lib.rs", "pub fn f() -> u8 { 5 }\n")?;
    add_all_in(base)?;
    commit_in(base, "pin deletion plus logic")?;
    if evaluate(base).is_ok() {
        return Err(String::from(
            "canary `pin-deletion-plus-logic` passed when it must fail",
        ));
    }
    Ok(())
}

/// Canaries around the cutoff and the window: both fail closed.
fn canary_cutoffs(base: &Path) -> Result<(), String> {
    // A cutoff dated after the mixed commits grandfathers them, so the same
    // tree that just failed now passes. This is the ratchet working, not the
    // gate going quiet: the grandfathered count is in the report.
    write_in(base, CUTOFF_FILE, "2999-01-01T00:00:00Z\n")?;
    add_all_in(base)?;
    commit_in(base, "cutoff: grandfather the history")?;
    evaluate(base)
        .map_err(|e| format!("canary `cutoff-grandfathers` failed when it must pass: {e}"))?;

    // A cutoff that cannot be parsed fails closed. A misread cutoff would
    // exempt commits nobody meant to exempt, and quietly.
    write_in(base, CUTOFF_FILE, "next quarter\n")?;
    if evaluate(base).is_ok() {
        return Err(String::from(
            "canary `unparsable-cutoff` passed when it must fail closed",
        ));
    }

    // A window that names an unresolvable base ref fails closed rather than
    // inspecting nothing.
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

/// Canary: a mixed commit fails, an inert re-pin passes, a plain commit passes.
pub fn self_test() -> Result<String, String> {
    let base = scratch_dir();
    for d in [PINS_DIR, BASELINE_DIR, "src"] {
        std::fs::create_dir_all(base.join(d)).map_err(|e| e.to_string())?;
    }
    if git_in(&base, &["init"]).is_err() {
        let _ = std::fs::remove_dir_all(&base);
        return Ok(String::from(
            "re-pin-commits-are-inert canary skipped: git unavailable",
        ));
    }
    let outcome = seed(&base)
        .and_then(|()| canary_refuses_mixtures(&base))
        .and_then(|()| canary_cutoffs(&base));
    let _ = std::fs::remove_dir_all(&base);
    outcome?;
    Ok(String::from(
        "re-pin-commits-are-inert canary OK: pin-plus-logic, baseline-plus-logic and pin-deletion-plus-logic refused; split-seed and split-in-two accepted; a future cutoff grandfathers; unparsable cutoff and unresolvable base ref fail closed",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_paths_are_recognised() {
        assert!(is_pin_path("xtask/gates/pins/budzero-tree.pins"));
        assert!(is_pin_path("xtask/gates/pins/nested/deep.pins"));
        assert!(is_pin_path(".github/gate-source-provenance-baseline.txt"));
        assert!(is_pin_path(".github/idle-code-baseline.txt"));
    }

    #[test]
    fn lookalike_paths_are_not_pins() {
        // The directory itself is not a file inside it.
        assert!(!is_pin_path("xtask/gates/pins"));
        // A baseline nested deeper is not a gate baseline.
        assert!(!is_pin_path(".github/nested/x-baseline.txt"));
        // A different suffix is a different artefact.
        assert!(!is_pin_path(".github/audit-guard-history-quarantine.txt"));
        // Source and workflows are never pins.
        assert!(!is_pin_path("src/privacy/note_registry.rs"));
        assert!(!is_pin_path(".github/workflows/ci.yml"));
        // A file that merely mentions the suffix in the middle is not one.
        assert!(!is_pin_path(".github/x-baseline.txt.bak"));
    }

    #[test]
    fn leading_dot_slash_is_stripped() {
        assert!(is_pin_path("./xtask/gates/pins/tree.pins"));
    }

    #[test]
    fn cutoff_parses_and_orders() {
        // 2026-11-21T00:00:00Z is 1795219200 seconds after the epoch.
        let day = parse_cutoff("2026-11-21").expect("bare date");
        assert_eq!(day, 1_795_219_200);
        assert_eq!(parse_cutoff("2026-11-21T00:00:00Z").expect("full"), day);
        assert_eq!(
            parse_cutoff("2026-11-21T01:00:00Z").expect("hour"),
            day + 3_600
        );
        // A later date is a larger number, so `<` orders history correctly.
        assert!(parse_cutoff("2026-11-22").expect("next day") > day);
        // Leap day and year end are real dates.
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
