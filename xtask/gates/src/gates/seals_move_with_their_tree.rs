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
//! # Recorded late re-seals
//!
//! A seal that arrived one commit after its tree is still a finding, because
//! the history cannot be rewritten without discarding the CI evidence every
//! SHA carries. Such a commit can be recorded in
//! `.github/seal-late-pin-exemptions.txt`, one line per seal transition:
//! `<seal_diff_digest> <seal> <tree> <reason>`. The key is not a SHA - a rebase
//! rewrites those - but the digest of the transition itself: the seal's path,
//! and its mode and blob id before and after the commit. A blob id hashes the
//! raw bytes, so a whitespace difference inside a literal is a different key,
//! the same transition replayed by a rebase is the same key, and the same hunk
//! moved elsewhere in the seal is a different key. A line that does not parse,
//! names a pair that is not a seal and its tree, or gives no reason of at least
//! [`MIN_REASON_CHARS`] characters fails closed. Every finding prints its
//! digest, so a record is copied from the report, never computed by hand.
//!
//! A record cannot forgive the commit that writes it. Each line exempts only a
//! commit strictly older than the commit that introduced the line: an ancestor
//! of it, never the same commit, and never through a line that is not
//! committed yet. The number of lines is ratcheted in
//! `.github/seal-late-pin-exemptions-count.txt`: adding a record means
//! moving that count in the same change, and a count that disagrees with the
//! record fails closed.
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

/// Recorded late re-seals, keyed by the digest of the seal transition.
const LATE_PIN_FILE: &str = ".github/seal-late-pin-exemptions.txt";

/// How many records [`LATE_PIN_FILE`] may hold, ratcheted by hand.
const LATE_PIN_COUNT_FILE: &str = ".github/seal-late-pin-exemptions-count.txt";

/// Domain separation for [`seal_diff_digest`].
const LATE_PIN_TAG: &[u8] = b"seal-late-pin/v1";

/// A recorded late re-seal states why in at least this many characters.
const MIN_REASON_CHARS: usize = 20;

/// One seal that moved while its tree stood still.
#[derive(Debug, PartialEq, Eq)]
struct Finding {
    sha: String,
    subject: String,
    seal: String,
    tree: String,
    digest: String,
}

/// One recorded late re-seal.
#[derive(Debug, PartialEq, Eq)]
struct LatePin {
    digest: String,
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

/// Resolve the commit window to inspect. `declared_base` is the CI base
/// ref, read from the environment exactly once at the gate's entry point:
/// a pure parameter here, so the canary's scratch repositories and the
/// unit tests never touch process-global state.
fn window(root: &Path, declared_base: Option<&str>) -> Result<Option<String>, String> {
    if let Some(base) = declared_base {
        let base = base.trim();
        if !base.is_empty() {
            for candidate in [format!("origin/{base}"), base.to_string()] {
                if git(root, &["rev-parse", "--verify", "--quiet", &candidate]).is_ok() {
                    return Ok(Some(format!("{candidate}..HEAD")));
                }
            }
            // A pull-request checkout often carries only the PR head; one
            // fetch attempt keeps the declared window honest before the
            // refusal. A repository with no such remote ref still fails
            // closed below - the canary pins that.
            if git(root, &["fetch", "--quiet", "origin", base]).is_ok()
                && git(root, &["rev-parse", "--verify", "--quiet", "FETCH_HEAD"]).is_ok()
            {
                return Ok(Some(String::from("FETCH_HEAD..HEAD")));
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

/// Mode and blob id of `path` at `rev`, or `absent` twice when the path does
/// not exist there.
fn seal_object(root: &Path, rev: &str, path: &str) -> Result<(String, String), String> {
    let out = git(root, &["ls-tree", rev, "--", path])?;
    let Some(line) = out.lines().next() else {
        return Ok((String::from("absent"), String::from("absent")));
    };
    let meta = line.split('\t').next().unwrap_or_default();
    let mut fields = meta.split_whitespace();
    match (fields.next(), fields.next(), fields.next()) {
        (Some(mode), Some("blob"), Some(oid)) => Ok((mode.to_string(), oid.to_string())),
        _ => Err(format!(
            "git ls-tree {rev} -- {path} gave an entry that is not a blob: `{line}`"
        )),
    }
}

/// The digest of one seal transition: the seal's path, and its mode and blob
/// id before and after `sha`, each length-prefixed under [`LATE_PIN_TAG`].
fn seal_diff_digest(root: &Path, sha: &str, seal: &str) -> Result<String, String> {
    let (old_mode, old_blob) = seal_object(root, &format!("{sha}^"), seal)?;
    let (new_mode, new_blob) = seal_object(root, sha, seal)?;
    let mut preimage = Vec::new();
    for part in [
        LATE_PIN_TAG,
        seal.as_bytes(),
        old_mode.as_bytes(),
        old_blob.as_bytes(),
        new_mode.as_bytes(),
        new_blob.as_bytes(),
    ] {
        let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
        preimage.extend_from_slice(&len.to_le_bytes());
        preimage.extend_from_slice(part);
    }
    Ok(crate::sha256::hex_digest(&preimage))
}

/// Parse the late re-seal record. Comments and blank lines are skipped; every
/// other line must read `<digest> <seal> <tree> <reason>`.
fn parse_late_pins(text: &str) -> Result<Vec<LatePin>, String> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = index.saturating_add(1);
        let shape = || format!("{LATE_PIN_FILE}:{at}: expected `<digest> <seal> <tree> <reason>`");
        let (digest, rest) = line.split_once(char::is_whitespace).ok_or_else(shape)?;
        let (seal, rest) = rest
            .trim_start()
            .split_once(char::is_whitespace)
            .ok_or_else(shape)?;
        let (tree, reason) = rest
            .trim_start()
            .split_once(char::is_whitespace)
            .ok_or_else(shape)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(format!(
                "{LATE_PIN_FILE}:{at}: the digest must be 64 lowercase hexadecimal characters"
            ));
        }
        if sealed_tree(seal) != Some(tree) {
            return Err(format!(
                "{LATE_PIN_FILE}:{at}: `{seal}` is not a seal of `{tree}`"
            ));
        }
        if reason.trim().chars().count() < MIN_REASON_CHARS {
            return Err(format!(
                "{LATE_PIN_FILE}:{at}: a recorded late re-seal needs a reason of at least {MIN_REASON_CHARS} characters"
            ));
        }
        out.push(LatePin {
            digest: digest.to_string(),
            seal: seal.to_string(),
            tree: tree.to_string(),
        });
    }
    Ok(out)
}

/// Read the late re-seal record, if the tree carries one.
fn late_pins(root: &Path) -> Result<Vec<LatePin>, String> {
    let path = root.join(LATE_PIN_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("cannot read {LATE_PIN_FILE}: {e}"))?;
    parse_late_pins(&text)
}

/// The record must hold exactly as many lines as its ratchet says.
fn check_record_count(root: &Path, records: usize) -> Result<(), String> {
    let path = root.join(LATE_PIN_COUNT_FILE);
    if !path.exists() {
        if records == 0 {
            return Ok(());
        }
        return Err(format!(
            "{LATE_PIN_FILE} holds {records} record(s) but {LATE_PIN_COUNT_FILE} is missing; \
             a record and its count move together"
        ));
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {LATE_PIN_COUNT_FILE}: {e}"))?;
    let declared: usize = text
        .trim()
        .parse()
        .map_err(|e| format!("{LATE_PIN_COUNT_FILE} is not a count: {e}"))?;
    if declared != records {
        return Err(format!(
            "{LATE_PIN_FILE} holds {records} record(s) but {LATE_PIN_COUNT_FILE} says {declared}; \
             a record and its count move together"
        ));
    }
    Ok(())
}

/// The commit that introduced the record line carrying `digest`, if any
/// commit did: the newest commit that changed how often the digest appears in
/// the record. While the line is present, that commit added it.
fn record_introduction(root: &Path, digest: &str) -> Result<Option<String>, String> {
    let pickaxe = format!("-S{digest}");
    let out = git(root, &["log", "--format=%H", &pickaxe, "--", LATE_PIN_FILE])?;
    Ok(out.lines().next().map(|l| l.trim().to_string()))
}

/// Whether `older` is an ancestor of `newer` (a commit is its own ancestor).
fn is_ancestor(root: &Path, older: &str, newer: &str) -> Result<bool, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["merge-base", "--is-ancestor", older, newer])
        .output()
        .map_err(|e| format!("cannot run git merge-base: {e}"))?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(format!(
            "git merge-base --is-ancestor {older} {newer} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
    }
}

/// A record line exempts `sha` only when the line was committed after it:
/// introduced by a strict descendant of `sha`.
fn record_predates(root: &Path, sha: &str, digest: &str) -> Result<bool, String> {
    let Some(intro) = record_introduction(root, digest)? else {
        return Ok(false);
    };
    if intro == sha {
        return Ok(false);
    }
    is_ancestor(root, sha, &intro)
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

/// The red verdict: every unrecorded seal-alone commit with the digest a
/// record would carry.
fn findings_report(findings: &[Finding], inspected: usize) -> String {
    use std::fmt::Write as _;
    let mut msg = format!(
        "a seal moved while the tree it seals stood still: {} case(s) in {} commit(s)\n",
        findings.len(),
        inspected
    );
    for f in findings.iter().take(20) {
        let _ = writeln!(
            msg,
            "  {} {} | seal: {} | sealed tree with no change: {} | seal_diff_digest: {}",
            f.sha, f.subject, f.seal, f.tree, f.digest
        );
    }
    if findings.len() > 20 {
        let _ = writeln!(msg, "  ... {} more", findings.len() - 20);
    }
    msg.push_str("A regenerated seal belongs in the commit that changed the tree it describes.");
    msg
}

/// Core judgement over an already-resolved window.
fn evaluate(root: &Path, declared_base: Option<&str>) -> Result<String, String> {
    // A shallow checkout cannot witness a declared window at all, and the
    // failure is worse than emptiness: the shallow boundary turns the merge head into
    // a parentless commit, `git show` lists the whole tree as its change,
    // and a hidden seal-alone commit reads as "seal moved with its tree".
    // Measured live before this rule: full history RED, depth=1 GREEN,
    // unshallowed RED again on the same head. So declared-base mode
    // refuses shallowness outright instead of out-guessing boundary cuts.
    if declared_base.is_some()
        && git(root, &["rev-parse", "--is-shallow-repository"]).is_ok_and(|s| s.trim() == "true")
    {
        return Err(String::from(
            "the checkout is shallow, so the declared base window cannot be witnessed; \
             a boundary-cut head can dress a seal-alone commit as a joint change - \
             fetch the full history (fetch-depth: 0)",
        ));
    }
    let range = window(root, declared_base)?;
    let shas = commits(root, range.as_deref())?;
    // A declared base that resolves to an empty window is not a verdict:
    // judging nothing must never read as green. The local fallbacks keep
    // their meaning - a repository shorter than the window genuinely has
    // that few commits.
    if shas.is_empty() && declared_base.is_some() {
        return Err(String::from(
            "the declared base window contains no commits; an empty declared window \
             is not a verdict - fetch the full history (fetch-depth: 0)",
        ));
    }
    let cutoff = cutoff(root)?;
    let late = late_pins(root)?;
    check_record_count(root, late.len())?;
    let mut findings: Vec<Finding> = Vec::new();
    let mut inspected = 0_usize;
    let mut seals = 0_usize;
    let mut exempt = 0_usize;
    let mut recorded = 0_usize;

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
                let digest = seal_diff_digest(root, sha, seal)?;
                if late
                    .iter()
                    .any(|p| p.digest == digest && p.seal == seal && p.tree == tree)
                    && record_predates(root, sha, &digest)?
                {
                    recorded = recorded.saturating_add(1);
                    continue;
                }
                findings.push(Finding {
                    sha: sha.chars().take(10).collect(),
                    subject: subject(root, sha),
                    seal: seal.to_string(),
                    tree: tree.to_string(),
                    digest,
                });
            }
        }
    }

    if !findings.is_empty() {
        return Err(findings_report(&findings, inspected));
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
    let covered = if recorded > 0 {
        format!(", {recorded} recorded as late re-seals in {LATE_PIN_FILE}")
    } else {
        String::new()
    };
    Ok(format!(
        "seals move with their tree: {inspected} commit(s) inspected in {scope}, {seals} seal change(s){exempted}{covered}, none moved alone"
    ))
}

/// Gate entry point: the one place the environment is read.
pub fn run(root: &Path) -> Result<String, String> {
    let declared = std::env::var("GITHUB_BASE_REF").ok();
    evaluate(root, declared.as_deref())
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
    evaluate(base, None)
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
    evaluate(base, None)
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
    if evaluate(base, None).is_ok() {
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
    if evaluate(base, None).is_ok() {
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
    evaluate(base, None)
        .map(|_| ())
        .map_err(|e| format!("canary `provenance-with-tree` failed when it must pass: {e}"))?;

    // A ratchet baseline is a counter, not a seal: it must move with the code.
    write_in(base, ".github/idle-code-baseline.txt", "")?;
    write_in(base, "src/x.rs", "pub fn x() { let _ = 2; }\n")?;
    add_all_in(base)?;
    commit_in(base, "ratchet baseline with its code")?;
    evaluate(base, None)
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
    evaluate(base, None)
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
    if evaluate(base, None).is_ok() {
        return Err(String::from(
            "canary `second-seal-alone` passed when it must fail",
        ));
    }
    // A cutoff after the mixed commits grandfathers them.
    write_in(base, CUTOFF_FILE, "2999-01-01T00:00:00Z\n")?;
    add_all_in(base)?;
    commit_in(base, "cutoff: grandfather the history")?;
    evaluate(base, None)
        .map(|_| ())
        .map_err(|e| format!("canary `cutoff-grandfathers` failed when it must pass: {e}"))?;
    // An unparsable cutoff fails closed.
    write_in(base, CUTOFF_FILE, "next quarter\n")?;
    if evaluate(base, None).is_ok() {
        return Err(String::from(
            "canary `unparsable-cutoff` passed when it must fail closed",
        ));
    }
    // An unresolvable base ref fails closed rather than inspecting nothing.
    write_in(base, CUTOFF_FILE, "1970-01-02T00:00:00Z\n")?;
    if evaluate(base, Some("no-such-base-ref")).is_ok() {
        return Err(String::from(
            "canary `unresolvable-base-ref` passed when it must fail closed",
        ));
    }
    // A base ref that RESOLVES but spans no commits is refused too: an
    // empty declared window judged nothing and must not read as green.
    git_in(base, &["branch", "--force", "window-base", "HEAD"])?;
    if evaluate(base, Some("window-base")).is_ok() {
        return Err(String::from(
            "canary `empty-declared-window` passed when it must fail closed",
        ));
    }
    git_in(base, &["branch", "-D", "window-base"])?;
    // A shallow clone is refused in declared-base mode before any window
    // arithmetic: the boundary-cut head can dress a seal-alone commit as
    // a joint change, so shallowness itself is the refusal.
    let shallow = base.with_file_name(format!(
        "{}-shallow",
        base.file_name().and_then(|n| n.to_str()).unwrap_or("seal")
    ));
    let _ = std::fs::remove_dir_all(&shallow);
    let url = format!("file://{}", base.display());
    let cloned = Command::new("git")
        .args(["clone", "--quiet", "--depth", "1", &url])
        .arg(&shallow)
        .output()
        .is_ok_and(|o| o.status.success());
    if cloned {
        let verdict = evaluate(&shallow, Some("any-base"));
        let _ = std::fs::remove_dir_all(&shallow);
        if verdict.is_ok() {
            return Err(String::from(
                "canary `shallow-checkout` passed when it must fail closed",
            ));
        }
    } else {
        let _ = std::fs::remove_dir_all(&shallow);
    }
    Ok(())
}

/// Head commit of the canary tree.
fn head_in(base: &Path) -> Result<String, String> {
    git(base, &["rev-parse", "HEAD"]).map(|s| s.trim().to_string())
}

/// Write the late re-seal record in the canary tree.
fn record_in(base: &Path, body: &str) -> Result<(), String> {
    write_in(base, LATE_PIN_FILE, body)
}

/// Write a one-line record with its count and commit both.
fn commit_record_in(base: &Path, line: &str, message: &str) -> Result<(), String> {
    record_in(base, &format!("{line}\n"))?;
    write_in(base, LATE_PIN_COUNT_FILE, "1\n")?;
    add_all_in(base)?;
    commit_in(base, message)
}

/// Canaries around the late re-seal record: the key is the transition, the
/// record fails closed, and a rebase keeps the key.
fn canary_late_pins(base: &Path) -> Result<(), String> {
    const SEAL: &str = "xtask/gates/pins/tree.pins";
    const REASON: &str = "late re-seal of a tree changed one commit earlier";
    // The tree moves alone, then its seal follows one commit late.
    write_in(base, "budzero/src/lib.rs", "pub fn f() -> u8 { 7 }\n")?;
    add_all_in(base)?;
    commit_in(base, "tree alone")?;
    write_in(
        base,
        SEAL,
        "budzero/src/lib.rs kkk\nbudzero/src/other.rs lll\n",
    )?;
    add_all_in(base)?;
    commit_in(base, "late seal")?;
    if evaluate(base, None).is_ok() {
        return Err(String::from(
            "canary `late-seal-unrecorded` passed when it must fail",
        ));
    }
    let late = head_in(base)?;
    let key = seal_diff_digest(base, &late, SEAL)?;
    let line = format!("{key} {SEAL} budzero/ {REASON}");
    // A record that is not committed yet forgives nothing.
    record_in(base, &format!("{line}\n"))?;
    write_in(base, LATE_PIN_COUNT_FILE, "1\n")?;
    if evaluate(base, None).is_ok() {
        return Err(String::from(
            "canary `record-uncommitted` passed when it must fail",
        ));
    }
    // Committed after the late seal, under its own transition digest, the
    // record forgives it.
    commit_record_in(base, &line, "record the late seal")?;
    evaluate(base, None)
        .map(|_| ())
        .map_err(|e| format!("canary `late-seal-recorded` failed when it must pass: {e}"))?;
    // The count is a ratchet: one that disagrees with the record, or is
    // missing while records exist, fails closed.
    write_in(base, LATE_PIN_COUNT_FILE, "0\n")?;
    if evaluate(base, None).is_ok() {
        return Err(String::from(
            "canary `record-count-mismatch` passed when it must fail closed",
        ));
    }
    std::fs::remove_file(base.join(LATE_PIN_COUNT_FILE)).map_err(|e| e.to_string())?;
    if evaluate(base, None).is_ok() {
        return Err(String::from(
            "canary `record-count-missing` passed when it must fail closed",
        ));
    }
    git_in(base, &["checkout", "-q", "--", LATE_PIN_COUNT_FILE])?;
    // A record without a reason, with a short one, with a malformed digest or
    // for a pair that is not a seal and its tree fails closed.
    for (name, body) in [
        ("record-without-reason", format!("{key} {SEAL} budzero/\n")),
        (
            "record-short-reason",
            format!("{key} {SEAL} budzero/ too short\n"),
        ),
        (
            "record-bad-digest",
            format!("{} {SEAL} budzero/ {REASON}\n", key.to_uppercase()),
        ),
        (
            "record-wrong-pair",
            format!("{key} {SEAL} xtask/gates/ {REASON}\n"),
        ),
    ] {
        record_in(base, &body)?;
        if evaluate(base, None).is_ok() {
            return Err(format!("canary `{name}` passed when it must fail closed"));
        }
    }
    git_in(base, &["checkout", "-q", "--", LATE_PIN_FILE])?;
    canary_record_cannot_forgive_itself(base)?;
    canary_late_pin_key(base, &key)
}

/// Canary: a commit that re-seals late and records its own transition in the
/// same commit is not forgiven.
fn canary_record_cannot_forgive_itself(base: &Path) -> Result<(), String> {
    const SEAL: &str = "xtask/gates/pins/tree.pins";
    const REASON: &str = "late re-seal recorded by the commit that makes it";
    let start = head_in(base)?;
    write_in(base, "budzero/src/lib.rs", "pub fn f() -> u8 { 8 }\n")?;
    add_all_in(base)?;
    commit_in(base, "tree alone again")?;
    write_in(base, SEAL, "budzero/src/lib.rs mmm\n")?;
    add_all_in(base)?;
    commit_in(base, "late seal, about to record itself")?;
    let own = seal_diff_digest(base, &head_in(base)?, SEAL)?;
    // Fold the record into the same commit: the transition, and so the
    // digest, does not change. The earlier record stays, so only this commit
    // can make the verdict red.
    git_in(base, &["reset", "-q", "--soft", "HEAD~1"])?;
    let earlier = std::fs::read_to_string(base.join(LATE_PIN_FILE)).map_err(|e| e.to_string())?;
    record_in(base, &format!("{earlier}{own} {SEAL} budzero/ {REASON}\n"))?;
    write_in(base, LATE_PIN_COUNT_FILE, "2\n")?;
    add_all_in(base)?;
    commit_in(base, "late seal that records itself")?;
    let verdict = evaluate(base, None);
    git_in(base, &["reset", "-q", "--hard", &start])?;
    if verdict.is_ok() {
        return Err(String::from(
            "canary `record-same-commit` passed when it must fail",
        ));
    }
    Ok(())
}

/// Canaries around the record key: a rebase keeps it, a byte or a moved hunk
/// changes it.
fn canary_late_pin_key(base: &Path, key: &str) -> Result<(), String> {
    const SEAL: &str = "xtask/gates/pins/tree.pins";
    const REASON: &str = "late re-seal of a tree changed one commit earlier";
    let line = format!("{key} {SEAL} budzero/ {REASON}");
    // Metadata alone - a reworded, re-dated commit, as a rebase produces -
    // keeps the key. The record commit is replayed on top, as a rebase would.
    git_in(base, &["reset", "-q", "--hard", "HEAD~1"])?;
    git_in(
        base,
        &[
            "-c",
            "user.name=canary",
            "-c",
            "user.email=canary@budlum.local",
            "commit",
            "-q",
            "--amend",
            "--date=2000-01-01T00:00:00Z",
            "-m",
            "late seal, reworded by a rebase",
        ],
    )?;
    let rebased = head_in(base)?;
    if seal_diff_digest(base, &rebased, SEAL)? != key {
        return Err(String::from(
            "canary `metadata-only-same-digest` failed: a reworded commit changed the key",
        ));
    }
    commit_record_in(base, &line, "record the late seal again")?;
    evaluate(base, None)
        .map(|_| ())
        .map_err(|e| format!("canary `metadata-only-same-digest` failed when it must pass: {e}"))?;
    // A whitespace difference inside a literal is a different transition.
    git_in(base, &["reset", "-q", "--hard", "HEAD~2"])?;
    write_in(
        base,
        SEAL,
        "budzero/src/lib.rs  kkk\nbudzero/src/other.rs lll\n",
    )?;
    add_all_in(base)?;
    commit_in(base, "late seal with a different space")?;
    let spaced = head_in(base)?;
    commit_record_in(base, &line, "record the original key")?;
    if seal_diff_digest(base, &spaced, SEAL)? == key || evaluate(base, None).is_ok() {
        return Err(String::from(
            "canary `whitespace-different-digest` passed when it must fail",
        ));
    }
    // The same added line in another place of the seal is a different key.
    git_in(base, &["reset", "-q", "--hard", "HEAD~2"])?;
    write_in(
        base,
        SEAL,
        "budzero/src/other.rs lll\nbudzero/src/lib.rs kkk\n",
    )?;
    add_all_in(base)?;
    commit_in(base, "late seal with the hunk moved")?;
    let moved = head_in(base)?;
    commit_record_in(base, &line, "record the original key")?;
    if seal_diff_digest(base, &moved, SEAL)? == key || evaluate(base, None).is_ok() {
        return Err(String::from(
            "canary `moved-hunk-different-digest` passed when it must fail",
        ));
    }
    Ok(())
}

/// Create and seed a fresh canary tree.
fn fresh_canary(base: &Path) -> Result<bool, String> {
    for d in [
        "xtask/gates/pins",
        "xtask/gates/src",
        "budzero/src",
        ".github",
        "src",
    ] {
        std::fs::create_dir_all(base.join(d)).map_err(|e| e.to_string())?;
    }
    if git_in(base, &["init"]).is_err() {
        return Ok(false);
    }
    seed(base)?;
    Ok(true)
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
    let late = base.with_file_name(format!(
        "{}-late",
        base.file_name().and_then(|n| n.to_str()).unwrap_or("seal")
    ));
    let _ = std::fs::remove_dir_all(&late);
    let late_outcome = fresh_canary(&late).and_then(|ready| {
        if ready {
            canary_late_pins(&late)
        } else {
            Ok(())
        }
    });
    let _ = std::fs::remove_dir_all(&late);
    late_outcome?;
    Ok(String::from(
        "seals-move-with-their-tree canary OK: seal-with-tree, provenance-with-tree, ratchet-with-code and seal-tree-plus-work accepted; seal-alone and provenance-seal-alone refused; a future cutoff grandfathers; unparsable cutoff, unresolvable base ref, an empty declared window and a shallow checkout fail closed; a late seal is refused until recorded under its transition digest in a later commit, an uncommitted record, a record in the violating commit itself and a count that disagrees or is missing are refused, a reworded commit keeps the key, a whitespace or moved-hunk variant does not, and a record without a reason, with a short one, a malformed digest or a wrong pair fails closed",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CI shape that killed two jobs per wave: the runner's own
    /// `GITHUB_BASE_REF` must not leak into the scratch repositories. The
    /// base ref is a pure parameter now and only `run()` reads the
    /// environment, so the canary is immune by construction - this pins
    /// that the plumbing stays that way even with the variable present.
    #[test]
    fn an_ambient_base_ref_does_not_poison_the_scratch_canary() {
        std::env::set_var("GITHUB_BASE_REF", "main");
        let outcome = self_test();
        std::env::remove_var("GITHUB_BASE_REF");
        outcome.expect("the canary must judge its scratch repos, not the runner's env");
    }

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
    fn late_pin_records_parse_and_refuse() {
        let key = "a".repeat(64);
        let ok = parse_late_pins(&format!(
            "# comment\n\n{key} xtask/gates/pins/budzero-tree.pins budzero/ re-seal of the url bump lock\n"
        ))
        .expect("a well-formed record");
        assert_eq!(
            ok,
            vec![LatePin {
                digest: key.clone(),
                seal: String::from("xtask/gates/pins/budzero-tree.pins"),
                tree: String::from("budzero/"),
            }]
        );
        for bad in [
            format!("{key} xtask/gates/pins/budzero-tree.pins budzero/"),
            format!("{key} xtask/gates/pins/budzero-tree.pins budzero/ short"),
            format!("{} xtask/gates/pins/budzero-tree.pins budzero/ re-seal of the url bump lock", "A".repeat(64)),
            format!("{} xtask/gates/pins/budzero-tree.pins budzero/ re-seal of the url bump lock", "a".repeat(63)),
            format!("{key} xtask/gates/pins/budzero-tree.pins xtask/gates/ re-seal of the url bump lock"),
            format!("{key} src/lib.rs budzero/ re-seal of the url bump lock"),
            String::from("not a record"),
        ] {
            assert!(parse_late_pins(&bad).is_err(), "`{bad}` must be refused");
        }
    }

    #[test]
    fn canary_runs() {
        self_test().expect("canary must pass");
    }
}
