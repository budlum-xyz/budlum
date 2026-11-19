//! The native deterministic security review gate.
//!
//! # Why this gate exists
//!
//! Branch protection on `main` requires one status context, and that
//! context was published by an external review application. When the
//! application's free review quota ran out, the context stopped reporting
//! entirely: every pull request sat at `mergeable_state=blocked` forever
//! and no repair could land on `main`. A required check that depends on
//! an externally metered quota is a structural lock the repository cannot open
//! from the inside.
//!
//! The decision ledger mandates the fix this gate implements: the review
//! work runs inside the repository, deterministically and fail-closed,
//! and branch protection requires the job of
//! `.github/workflows/native-security-review.yml` (`Native Security
//! Review`) instead. The external application may return as an extra
//! layer when its quota allows; it must never again be the single
//! required check, and nothing in this repository publishes a status on
//! its behalf.
//!
//! # The three review steps
//!
//!   1. **Attack surface.** The security-relevant surface is enumerated
//!      from the tree itself - workflow files, binaries under `src/bin`,
//!      and every `Cargo.toml` - and pinned by digest in
//!      `.github/native-review-surface-baseline.txt`. A surface change
//!      must land in the same commit as its re-measured baseline: growth
//!      is refused until it is pinned, and silent removal is refused too.
//!      Floors refuse a vacuous scan: an empty or pruned tree would
//!      otherwise hash happily and pass.
//!   2. **Hardening of that surface.** Every workflow file keeps an
//!      explicit deny-by-default `permissions:` block, and the grants
//!      and triggers `write-all` and `pull_request_target` fail the gate
//!      outright. Measured when this gate landed: all 38 workflows
//!      already comply, so the ratchet starts at zero.
//!   3. **Proven claims.** The review workflow must invoke each pinned
//!      security gate twice - its `--self-test` canary first, then the
//!      plain run, red before green - and this gate verifies that
//!      statically from the workflow text. Deleting, reordering or
//!      softening a step turns the required check red without needing a
//!      human eye.
//!
//! # Determinism
//!
//! Every input is a file in the repository or text derived from one;
//! walks are sorted, sets are ordered, and the digest is SHA-256 over
//! the ordered entries. Two runs on the same tree produce the same
//! bytes and the same verdict: no wall clock, no floats, no dependence
//! on directory iteration order.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use super::ci_workflow_guards::{run_blocks, RunBlock};
use crate::sha256::hex_digest;

/// The pinned attack-surface baseline (step 1).
const BASELINE_PATH: &str = ".github/native-review-surface-baseline.txt";

/// The review workflow whose job name is the required check context.
const REVIEW_WORKFLOW: &str = ".github/workflows/native-security-review.yml";

/// Grants and triggers the review surface must never contain (step 2).
const BANNED_SNIPPETS: &[&str] = &["write-all", "pull_request_target"];

/// Security gates whose canary and plain invocations the review workflow
/// must carry (step 3). Every entry is a real gate in `main.rs`'s GATES
/// list; the workflow runs canary first, then the plain gate.
const PINNED_EVIDENCE_GATES: &[&str] = &[
    "native-security-review",
    "ast-security-gates",
    "no-constant-security-verdicts",
    "classical-crypto-is-paired",
    "suppressions-are-justified",
];

/// Floors under which the scan is considered vacuous (step 1). Measured
/// on the landing tree: 38 workflows, 12 binaries, 52 manifests. The
/// floors sit well below the measurements so only a pruned or empty
/// scan trips them; surface movement itself is handled by the baseline.
const MIN_WORKFLOWS: usize = 30;
const MIN_BINS: usize = 8;
const MIN_MANIFESTS: usize = 40;

/// Directories the surface walk never descends into.
const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules"];

/// The review itself: enumerate the surface, pin it, harden it, prove it.
pub fn run(root: &Path) -> Result<String, String> {
    review(root)
}

fn review(root: &Path) -> Result<String, String> {
    let (entries, digest) = measure(root)?;
    let workflows = count_kind(&entries, "workflow");
    let bins = count_kind(&entries, "bin");
    let manifests = count_kind(&entries, "manifest");
    if workflows < MIN_WORKFLOWS || bins < MIN_BINS || manifests < MIN_MANIFESTS {
        return Err(format!(
            "vacuous scan: {workflows} workflows / {bins} binaries / {manifests} manifests \
             measured; the floors are {MIN_WORKFLOWS}/{MIN_BINS}/{MIN_MANIFESTS} - run the \
             gate from the repository root"
        ));
    }

    let baseline_path = root.join(BASELINE_PATH);
    let baseline = fs::read_to_string(&baseline_path).map_err(|_| {
        format!(
            "{BASELINE_PATH} is missing; pin the measured surface by committing this file:\n\n{}",
            baseline_text(&entries, &digest)
        )
    })?;
    check_baseline(&baseline, &entries, &digest)?;

    let workflows_dir = root.join(".github").join("workflows");
    let mut hardened = 0usize;
    for rel in list_files(&workflows_dir, ".yml")? {
        let text = fs::read_to_string(workflows_dir.join(&rel))
            .map_err(|e| format!("cannot read .github/workflows/{rel}: {e}"))?;
        check_workflow_permissions(&text, &format!(".github/workflows/{rel}"))?;
        hardened += 1;
    }

    let review_text = fs::read_to_string(root.join(REVIEW_WORKFLOW))
        .map_err(|e| format!("cannot read {REVIEW_WORKFLOW}: {e}"))?;
    check_evidence(&review_text)?;

    Ok(format!(
        "native security review: surface pinned ({workflows} workflows, {bins} binaries, \
         {manifests} manifests, digest {}), {hardened} workflows deny-by-default, {} pinned \
         evidence gates verified canary-first in {REVIEW_WORKFLOW}",
        short_digest(&digest),
        PINNED_EVIDENCE_GATES.len(),
    ))
}

/// Entry point with arguments: no argument runs the review, `--print-surface`
/// emits the exact baseline text the current tree measures.
pub fn run_args(root: &Path, args: &[&str]) -> Result<String, String> {
    match args.first().copied() {
        None => run(root),
        Some("--print-surface") => {
            let (entries, digest) = measure(root)?;
            Ok(baseline_text(&entries, &digest))
        }
        Some(other) => Err(format!(
            "unknown argument `{other}`; pass nothing for the review, or `--print-surface` \
             to emit the baseline"
        )),
    }
}

/// Assert that an outcome which must be red actually is. `is_ok()` on a
/// required failure is the assertion mechanism: a passing red-check is the
/// self-test's own failure.
fn expect_red<T>(label: &str, outcome: &Result<T, String>) -> Result<(), String> {
    if outcome.is_ok() {
        Err(format!("native-security-review self-test: {label} passed"))
    } else {
        Ok(())
    }
}

/// The canary: proves the gate fails on every failure mode it claims to
/// catch, and passes on a compliant tree.
pub fn self_test() -> Result<String, String> {
    baseline_suite()?;
    hardening_suite()?;
    evidence_suite()?;
    tree_suite()?;
    Ok(String::from(
        "native-security-review self-test: 3 steps exercised, every failure mode reproduced",
    ))
}

/// Step 1 canaries at text level: the baseline accepts a correct pin and
/// refuses growth, silent removal, and every corrupt shape.
fn baseline_suite() -> Result<(), String> {
    let entries: Vec<String> = vec![
        String::from("bin\tsrc/bin/alpha.rs"),
        String::from("manifest\tcrates/one/Cargo.toml"),
        String::from("workflow\t.github/workflows/ci.yml"),
    ];
    let digest = digest_of(&entries);
    let baseline = baseline_text(&entries, &digest);
    check_baseline(&baseline, &entries, &digest).map_err(|e| {
        format!("native-security-review self-test: a correct baseline was refused: {e}")
    })?;

    // Growth: the tree carries an entry the baseline never pinned. Two
    // shapes - a stale baseline (count and digest still describe the old
    // surface) and a consistent subset baseline (re-measured, but the tree
    // moved on after it was pinned).
    let mut grown = entries.clone();
    grown.push(String::from("bin\tsrc/bin/extra.rs"));
    let grown_digest = digest_of(&grown);
    expect_red(
        "a grown surface against a stale baseline",
        &check_baseline(&baseline, &grown, &grown_digest),
    )?;
    let mut subset = entries.clone();
    subset.remove(0);
    let subset_baseline = baseline_text(&subset, &digest_of(&subset));
    expect_red(
        "a baseline missing one tree entry",
        &check_baseline(&subset_baseline, &entries, &digest),
    )?;

    // Silent removal: the baseline pins an entry the tree no longer has.
    let mut with_phantom = entries.clone();
    with_phantom.push(String::from("workflow\t.github/workflows/removed.yml"));
    let phantom_baseline = baseline_text(&with_phantom, &digest_of(&with_phantom));
    expect_red(
        "a baseline pinning an entry the tree no longer has",
        &check_baseline(&phantom_baseline, &entries, &digest),
    )?;

    // Corrupt shapes: a tampered digest, a missing digest line, and a
    // declared count that disagrees with the carried entry lines.
    expect_red(
        "a tampered digest",
        &check_baseline(&baseline, &entries, "0000"),
    )?;
    expect_red(
        "a baseline without a digest line",
        &check_baseline("entries: 3\n", &entries, &digest),
    )?;
    let mut corrupt = baseline_text(&entries, &digest);
    corrupt = corrupt.replacen("bin\tsrc/bin/alpha.rs\n", "", 1);
    expect_red(
        "a baseline whose declared count disagrees with its lines",
        &check_baseline(&corrupt, &entries, &digest),
    )?;
    Ok(())
}

/// Step 2 canaries at text level: deny-by-default is required, and the
/// banned grants are refused wherever they appear.
fn hardening_suite() -> Result<(), String> {
    let compliant =
        "on: [push]\npermissions: {}\njobs:\n  a:\n    permissions:\n      contents: read\n";
    check_workflow_permissions(compliant, "fixture.yml").map_err(|e| {
        format!("native-security-review self-test: a compliant workflow was refused: {e}")
    })?;
    expect_red(
        "a workflow without a permissions block",
        &check_workflow_permissions("on: [push]\njobs:\n  a:\n    run: x\n", "fixture.yml"),
    )?;
    expect_red(
        "a workflow granting an unrestricted write scope",
        &check_workflow_permissions(
            "on: [push]\npermissions: write-all\njobs:\n  a:\n    run: x\n",
            "fixture.yml",
        ),
    )?;
    expect_red(
        "a workflow triggered by the unsafe cross-repo event",
        &check_workflow_permissions(
            "on: [pull_request_target]\npermissions: {}\njobs:\n  a:\n    run: x\n",
            "fixture.yml",
        ),
    )?;
    Ok(())
}

/// Step 3 canaries at text level: the evidence loop requires canary-first
/// plain runs for every pinned gate, in order, unsoftened.
fn evidence_suite() -> Result<(), String> {
    let good_workflow = fixture_review_workflow(false, None, false);
    check_evidence(&good_workflow).map_err(|e| {
        format!("native-security-review self-test: a complete review workflow was refused: {e}")
    })?;
    expect_red(
        "a review workflow missing one canary",
        &check_evidence(&fixture_review_workflow(
            false,
            Some("classical-crypto-is-paired"),
            false,
        )),
    )?;
    expect_red(
        "a review workflow with inverted canary order",
        &check_evidence(&fixture_review_workflow(true, None, false)),
    )?;
    expect_red(
        "a review workflow with a softened plain run",
        &check_evidence(&fixture_review_workflow(false, None, true)),
    )?;
    Ok(())
}

/// The canaries only a real walk can produce: a compliant tree passes, and
/// a tree without a baseline or a tree that grew after pinning fails.
fn tree_suite() -> Result<(), String> {
    let (dir, root) = fixture_tree(false, None)?;
    let (entries, digest) = measure(&root)?;
    let baseline = baseline_text(&entries, &digest);
    fs::write(dir.path().join(BASELINE_PATH), &baseline)
        .map_err(|e| format!("self-test: cannot write baseline: {e}"))?;
    review(&root).map_err(|e| {
        format!("native-security-review self-test: a compliant tree was refused: {e}")
    })?;

    let (_dir, root) = fixture_tree(false, None)?;
    expect_red("a tree without a baseline", &review(&root))?;

    let (_dir, root) = fixture_tree(true, None)?;
    expect_red("a tree that grew after pinning", &review(&root))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 1: the surface and its baseline.
// ---------------------------------------------------------------------------

/// Enumerate the security-relevant surface of the repository and digest it.
fn measure(root: &Path) -> Result<(Vec<String>, String), String> {
    let mut entries: BTreeSet<String> = BTreeSet::new();
    for name in list_files(&root.join(".github").join("workflows"), ".yml")? {
        entries.insert(format!("workflow\t.github/workflows/{name}"));
    }
    for name in list_files(&root.join("src").join("bin"), ".rs")? {
        entries.insert(format!("bin\tsrc/bin/{name}"));
    }
    for name in list_files(root, "Cargo.toml")? {
        entries.insert(format!("manifest\t{name}"));
    }
    let ordered: Vec<String> = entries.into_iter().collect();
    let digest = digest_of(&ordered);
    Ok((ordered, digest))
}

fn digest_of(entries: &[String]) -> String {
    hex_digest(entries.join("\n").as_bytes())
}

fn count_kind(entries: &[String], kind: &str) -> usize {
    entries
        .iter()
        .filter(|entry| entry.starts_with(kind))
        .count()
}

fn short_digest(digest: &str) -> &str {
    let end = digest.len().min(12);
    &digest[..end]
}

/// Files under `dir` whose name ends with `suffix`, sorted, relative to `dir`.
fn list_files(dir: &Path, suffix: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    collect_files(dir, dir, suffix, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_files(
    base: &Path,
    dir: &Path,
    suffix: &str,
    out: &mut Vec<String>,
) -> Result<(), String> {
    let read = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in read {
        let entry = entry.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let file_type = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if file_type.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            collect_files(base, &path, suffix, out)?;
        } else if name.ends_with(suffix) {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(path.as_path())
                .to_string_lossy()
                .into_owned();
            out.push(rel);
        }
    }
    Ok(())
}

/// The exact baseline text the current tree measures, ready to commit.
fn baseline_text(entries: &[String], digest: &str) -> String {
    let mut text = String::new();
    text.push_str("# Native security review attack-surface baseline (step 1).\n");
    text.push_str("# The surface is enumerated from the tree; growth and silent removal\n");
    text.push_str("# both fail the gate. Re-measure in the same change that moves it:\n");
    text.push_str("#   cargo run --release --manifest-path xtask/gates/Cargo.toml -- native-security-review --print-surface\n");
    let _ = writeln!(text, "digest: {digest}");
    let _ = writeln!(text, "entries: {}", entries.len());
    for entry in entries {
        let _ = writeln!(text, "{entry}");
    }
    text
}

fn parse_baseline(baseline: &str) -> Result<(String, BTreeSet<String>), String> {
    let mut digest: Option<String> = None;
    let mut declared: Option<usize> = None;
    let mut pinned: BTreeSet<String> = BTreeSet::new();
    let mut carried = 0usize;
    for line in baseline.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("digest:") {
            digest = Some(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix("entries:") {
            match rest.trim().parse::<usize>() {
                Ok(n) => declared = Some(n),
                Err(_) => return Err(format!("baseline `entries:` line is not a number: {line}")),
            }
            continue;
        }
        pinned.insert(line.to_string());
        carried += 1;
    }
    let Some(digest) = digest else {
        return Err(String::from("baseline has no `digest:` line"));
    };
    match declared {
        Some(n) if n == carried => {}
        Some(n) => {
            return Err(format!(
                "baseline declares `entries: {n}` but carries {carried} entry lines"
            ))
        }
        None => return Err(String::from("baseline has no `entries:` line")),
    }
    Ok((digest, pinned))
}

/// The baseline must describe exactly the measured surface: growth is
/// refused until pinned, silent removal is refused, and identical entry
/// lines must hash to the pinned digest.
fn check_baseline(baseline: &str, tree: &[String], digest: &str) -> Result<(), String> {
    let (pinned_digest, pinned) = parse_baseline(baseline)?;
    let tree_set: BTreeSet<String> = tree.iter().cloned().collect();
    let grew: Vec<&String> = tree_set.difference(&pinned).collect();
    if !grew.is_empty() {
        let mut message = format!(
            "the attack surface grew by {} entr{} without a re-measured baseline; \
             pin the surface in the same change:",
            grew.len(),
            if grew.len() == 1 { "y" } else { "ies" },
        );
        for entry in grew.iter().take(20) {
            let _ = writeln!(message, "\n  + {entry}");
        }
        return Err(message);
    }
    let shrank: Vec<&String> = pinned.difference(&tree_set).collect();
    if !shrank.is_empty() {
        let mut message = format!(
            "the baseline pins {} surface entr{} the tree no longer has; re-measure - \
             the baseline only shrinks with the tree it measures:",
            shrank.len(),
            if shrank.len() == 1 { "y" } else { "ies" },
        );
        for entry in shrank.iter().take(20) {
            let _ = writeln!(message, "\n  - {entry}");
        }
        return Err(message);
    }
    if pinned_digest != digest {
        return Err(format!(
            "surface digest mismatch: pinned {pinned_digest}, measured {digest}; \
             identical entry lines must hash identically - re-measure"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 2: the surface stays deny-by-default.
// ---------------------------------------------------------------------------

fn check_workflow_permissions(text: &str, rel: &str) -> Result<(), String> {
    let mut declares_permissions = false;
    for (idx, line) in text.lines().enumerate() {
        let no = idx + 1;
        // A comment cannot grant a permission; scanning one would let a
        // documented example of the banned grant turn a compliant file red.
        if line.trim_start().starts_with('#') {
            continue;
        }
        for banned in BANNED_SNIPPETS {
            if line.contains(banned) {
                return Err(format!(
                    "{rel}:{no} contains `{banned}`; the review surface stays deny-by-default"
                ));
            }
        }
        if line.trim_start().starts_with("permissions:") {
            declares_permissions = true;
        }
    }
    if !declares_permissions {
        return Err(format!(
            "{rel}: no `permissions:` block; declare deny-by-default permissions and \
             scope every job"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 3: the claims the review makes are backed by canary-first runs.
// ---------------------------------------------------------------------------

fn check_evidence(workflow_text: &str) -> Result<(), String> {
    let blocks = run_blocks(workflow_text);
    if blocks.is_empty() {
        return Err(format!(
            "{REVIEW_WORKFLOW} carries no `run:` blocks; the evidence loop is empty"
        ));
    }
    for gate in PINNED_EVIDENCE_GATES {
        verify_invocation(&blocks, gate)?;
    }
    Ok(())
}

fn verify_invocation(blocks: &[RunBlock], gate: &str) -> Result<(), String> {
    let plain_needle = format!("-- {gate}");
    let canary_needle = format!("-- {gate} --self-test");
    let mut canary: Option<(usize, usize)> = None;
    let mut plain: Option<(usize, usize)> = None;
    for (bi, block) in blocks.iter().enumerate() {
        if block.softened.is_some() {
            continue;
        }
        for (li, line) in block.lines.iter().enumerate() {
            let hits_canary = line.contains(&canary_needle);
            let hits_plain =
                !hits_canary && line.contains(&plain_needle) && line.contains("cargo run");
            if hits_canary && canary.is_none() {
                canary = Some((bi, li));
            }
            if hits_plain && plain.is_none() {
                plain = Some((bi, li));
            }
        }
    }
    let (canary_block, canary_line) = canary.ok_or_else(|| {
        format!(
            "the review workflow never runs the `{gate}` canary; every pinned gate must \
             run `--self-test` first"
        )
    })?;
    let (plain_block, plain_line) = plain.ok_or_else(|| {
        format!(
            "the review workflow never runs `{gate}` itself; a canary without the plain \
             run proves nothing"
        )
    })?;
    if canary_block > plain_block || (canary_block == plain_block && canary_line > plain_line) {
        return Err(format!(
            "the `{gate}` canary must precede its plain run (red before green)"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixtures for the canary.
// ---------------------------------------------------------------------------

/// A review-workflow text with the requested fault, mirroring the shape of
/// the real `.github/workflows/native-security-review.yml`.
fn fixture_review_workflow(invert: bool, drop_canary: Option<&str>, soften_plain: bool) -> String {
    let mut steps = String::new();
    for gate in PINNED_EVIDENCE_GATES {
        let canary = format!(
            "      - name: Canary for {gate}\n        if: always()\n        run: cargo run \
             --release --manifest-path xtask/gates/Cargo.toml -- {gate} --self-test\n"
        );
        let plain_body = if soften_plain {
            "        continue-on-error: true\n        run: cargo run --release \
             --manifest-path xtask/gates/Cargo.toml"
        } else {
            "        run: cargo run --release --manifest-path xtask/gates/Cargo.toml"
        };
        let plain = format!("      - name: {gate}\n        if: always()\n{plain_body} -- {gate}\n");
        if invert {
            steps.push_str(&plain);
            if drop_canary != Some(*gate) {
                steps.push_str(&canary);
            }
        } else {
            if drop_canary != Some(*gate) {
                steps.push_str(&canary);
            }
            steps.push_str(&plain);
        }
    }
    format!(
        "name: Native Security Review\non: [push, pull_request]\npermissions: {{}}\njobs:\n  \
         native-security-review:\n    name: Native Security Review\n    runs-on: \
         ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n{steps}"
    )
}

/// A fixture tree that passes the floors: `extra_workflow` adds one file so
/// the growth case can be exercised after the baseline is pinned.
fn fixture_tree(
    extra_workflow: bool,
    permissions_fault: Option<&str>,
) -> Result<(tempfile::TempDir, std::path::PathBuf), String> {
    let dir = tempfile::tempdir().map_err(|e| format!("self-test: tempdir: {e}"))?;
    let root = dir.path().to_path_buf();
    let workflows_dir = root.join(".github").join("workflows");
    fs::create_dir_all(&workflows_dir).map_err(|e| format!("self-test: mkdir workflows: {e}"))?;
    for index in 0..30usize {
        let body = match permissions_fault {
            Some(fault) if index == 0 => fault.to_string(),
            _ => String::from("on: [push]\npermissions: {}\njobs:\n  a:\n    run: echo ok\n"),
        };
        let path = workflows_dir.join(format!("w{index:02}.yml"));
        fs::write(&path, body).map_err(|e| format!("self-test: write w{index:02}: {e}"))?;
    }
    if extra_workflow {
        fs::write(
            workflows_dir.join("extra.yml"),
            "on: [push]\npermissions: {}\njobs:\n  a:\n    run: echo ok\n",
        )
        .map_err(|e| format!("self-test: write extra: {e}"))?;
    }
    let bins_dir = root.join("src").join("bin");
    fs::create_dir_all(&bins_dir).map_err(|e| format!("self-test: mkdir bins: {e}"))?;
    for index in 0..8usize {
        fs::write(bins_dir.join(format!("bin{index}.rs")), "fn main() {}\n")
            .map_err(|e| format!("self-test: write bin{index}: {e}"))?;
    }
    for index in 0..40usize {
        let crate_dir = root.join("crates").join(format!("c{index:02}"));
        fs::create_dir_all(&crate_dir).map_err(|e| format!("self-test: mkdir c{index:02}: {e}"))?;
        fs::write(
            crate_dir.join("Cargo.toml"),
            format!("[package]\nname = \"c{index:02}\"\nversion = \"0.1.0\"\n"),
        )
        .map_err(|e| format!("self-test: write c{index:02}: {e}"))?;
    }
    let review_path = workflows_dir.join("native-security-review.yml");
    fs::write(&review_path, fixture_review_workflow(false, None, false))
        .map_err(|e| format!("self-test: write review workflow: {e}"))?;
    Ok((dir, root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_test_passes() {
        self_test().unwrap_or_else(|e| panic!("self_test failed: {e}"));
    }

    #[test]
    fn baseline_digest_mismatch_is_a_finding() {
        let entries = vec![String::from("bin\tsrc/bin/a.rs")];
        let baseline = baseline_text(&entries, "deadbeef");
        assert!(check_baseline(&baseline, &entries, "cafe").is_err());
    }

    #[test]
    fn growth_and_silent_removal_are_findings() {
        let entries = vec![
            String::from("bin\tsrc/bin/a.rs"),
            String::from("manifest\tcrates/a/Cargo.toml"),
        ];
        let digest = digest_of(&entries);
        let baseline = baseline_text(&entries, &digest);
        let mut grown = entries.clone();
        grown.push(String::from("workflow\t.github/workflows/new.yml"));
        assert!(check_baseline(&baseline, &grown, &digest).is_err());
        let mut shrunk = entries.clone();
        shrunk.pop();
        assert!(check_baseline(&baseline, &shrunk, &digest).is_err());
    }

    #[test]
    fn missing_permissions_and_banned_grants_are_findings() {
        assert!(check_workflow_permissions("on: [push]\njobs:\n  a:\n", "w.yml").is_err());
        assert!(check_workflow_permissions(
            "on: [push]\npermissions: write-all\njobs:\n  a:\n",
            "w.yml"
        )
        .is_err());
        assert!(check_workflow_permissions(
            "on: [pull_request_target]\npermissions: {}\njobs:\n  a:\n",
            "w.yml"
        )
        .is_err());
    }

    #[test]
    fn evidence_requires_canary_first_plain_run() {
        assert!(check_evidence(&fixture_review_workflow(false, None, false)).is_ok());
        assert!(check_evidence(&fixture_review_workflow(
            false,
            Some("classical-crypto-is-paired"),
            false
        ))
        .is_err());
        assert!(check_evidence(&fixture_review_workflow(true, None, false)).is_err());
        assert!(check_evidence(&fixture_review_workflow(false, None, true)).is_err());
        assert!(check_evidence("name: empty\non: [push]\njobs:\n  a:\n").is_err());
    }
}
