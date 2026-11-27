//! A branch the repository promises the full battery to must actually get it.
//!
//! # The failure these tests pin
//!
//! Measured on 2026-11-27 against the live repository: a pull request whose
//! base is `consensus-of-consensuses` produced 112 check runs; the pull
//! request one step below it in the same stack, whose base is `testnet-50`,
//! produced 106, and eight of the jobs it did show were reported `skipped`:
//!
//! * `Auditable + Audit (binary SBOM + CVE)`
//! * `Dead Deps (machete + shear)`
//! * `Binary Size (rapor)`
//! * `Config Lint (taplo)`
//! * `Kani Proofs (bond arithmetic)`
//! * `Udeps: the unused dependency gate`
//! * `Geiger: unsafe visibility (the first-party 0 evidence layer)`
//! * `Semver Check (item 5: public API breakage gate)`
//!
//! The cause is a job-level condition of the form
//! `contains(fromJSON('["main","consensus-of-consensuses"]'),
//! github.event.pull_request.base.ref)`. In a stacked pull request the
//! `branches:` filter is evaluated against the root of the stack, so the
//! workflow starts; the job-level condition then sees the *immediate* base and
//! skips. GitHub reports a skipped job as a passing check, and `testnet-50`
//! carries no required status check at all, so the delivery branch looks gated
//! and is not.
//!
//! `ci-trigger-coverage` cannot see this: it reads triggers, not job
//! conditions, so a branch it calls covered can still receive a strictly
//! weaker battery than the branch above it in the stack. The gate that can see
//! it is `ci-full-battery-parity`; these tests pin the finding itself to the
//! repository state so the fix cannot silently regress.
//!
//! The tests read repository files only.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    std::env::var_os("BUDLUM_ROOT").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
        PathBuf::from,
    )
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// The branches promised the full battery, as the repository writes them.
fn promised_branches() -> Vec<String> {
    read(".github/workflows/ci-full-battery-branches.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Workflow files that carry a job-level base-ref allowlist, and the jobs that
/// carry it. Found by text, because the shape being pinned is a text shape:
/// the literal JSON array inside `fromJSON(...)`.
fn base_ref_allowlists() -> Vec<(String, String)> {
    let dir = root().join(".github/workflows");
    let mut out: Vec<(String, String)> = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("the workflow directory is readable") {
        let path = entry.expect("the directory entry is readable").path();
        if !path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            continue;
        }
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let src = std::fs::read_to_string(&path).expect("the workflow file is readable");
        for line in src.lines() {
            let t = line.trim_start();
            if !t.starts_with("if:") {
                continue;
            }
            if !(t.contains("pull_request.base.ref") || t.contains("github.base_ref")) {
                continue;
            }
            if let Some(rest) = t.split("fromJSON('").nth(1) {
                if let Some(list) = rest.split("')").next() {
                    out.push((name.clone(), list.to_string()));
                }
            }
        }
    }
    out.sort();
    out
}

/// The promise exists, is non-empty, and names the live delivery chain.
///
/// An empty promise reads as full coverage; that is the shape of the failure
/// this family exists for.
#[test]
fn the_full_battery_promise_names_the_live_delivery_chain() {
    let branches = promised_branches();
    assert!(
        !branches.is_empty(),
        "ci-full-battery-branches.txt names no branch; an empty promise cannot be violated and \
         so measures nothing"
    );
    for required in ["main", "consensus-of-consensuses", "testnet-50"] {
        assert!(
            branches.iter().any(|b| b == required),
            "{required} is a live delivery base (an open pull request targets it) but is not \
             promised the full battery; branches promised: {branches:?}"
        );
    }
}

/// Every job-level base-ref allowlist admits every promised branch.
///
/// Red when written: `extra-tooling.yml` (five jobs), `supply-chain-extra.yml`
/// (two jobs) and `semver.yml` (one job) admitted `main` and
/// `consensus-of-consensuses` only.
#[test]
fn no_promised_branch_is_skipped_by_a_job_condition() {
    let promised = promised_branches();
    let allowlists = base_ref_allowlists();
    assert!(
        !allowlists.is_empty(),
        "no job-level base-ref allowlist was found. The condition this test exists for would \
         then be invisible to it, and a test that examines nothing reports OK."
    );
    let mut gaps: Vec<String> = Vec::new();
    for (file, list) in &allowlists {
        for branch in &promised {
            let quoted = format!("\"{branch}\"");
            if !list.contains(&quoted) {
                gaps.push(format!("{file}: allowlist {list} skips base {branch}"));
            }
        }
    }
    gaps.sort();
    gaps.dedup();
    assert!(
        gaps.is_empty(),
        "a job condition skips a branch the repository promises the full battery to. GitHub \
         reports the skip as a passing check, so the pull request page claims a gate that never \
         ran:\n  {}",
        gaps.join("\n  ")
    );
}

/// Every workflow carrying a base-ref allowlist also triggers for every
/// promised branch.
///
/// A job condition that admits the branch is not enough on its own: if the
/// workflow never starts for that base, the job never runs either. The two are
/// written in two different places, so they are checked separately.
#[test]
fn every_workflow_with_a_base_ref_allowlist_triggers_for_the_promised_branches() {
    let promised = promised_branches();
    let mut seen: Vec<String> = base_ref_allowlists().into_iter().map(|(f, _)| f).collect();
    seen.sort();
    seen.dedup();
    let mut gaps: Vec<String> = Vec::new();
    for file in seen {
        let src = read(&format!(".github/workflows/{file}"));
        // The `branches:` list of the `pull_request:` trigger, inline form,
        // which is the form every workflow in this repository uses.
        let Some(list) = src
            .lines()
            .skip_while(|l| l.trim_start() != "pull_request:")
            .take(4)
            .find_map(|l| l.trim_start().strip_prefix("branches:"))
        else {
            // No list: an unrestricted trigger fires for every base.
            continue;
        };
        for branch in &promised {
            let named = list
                .trim()
                .trim_matches(['[', ']'].as_ref())
                .split(',')
                .any(|p| p.trim().trim_matches(['"', '\''].as_ref()) == branch);
            if !named {
                gaps.push(format!("{file} does not trigger for base {branch}"));
            }
        }
    }
    assert!(
        gaps.is_empty(),
        "a workflow whose jobs are base-ref gated does not start for a branch promised the full \
         battery:\n  {}",
        gaps.join("\n  ")
    );
}

/// The promise and the trigger-coverage claim do not contradict each other: a
/// branch promised the full battery is also a branch the repository claims to
/// gate at all.
#[test]
fn the_promise_is_a_subset_of_the_trigger_claim() {
    let claimed: Vec<String> = read(".github/workflows/ci-trigger-branches.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    let missing: Vec<String> = promised_branches()
        .into_iter()
        .filter(|b| !claimed.contains(b))
        .collect();
    assert!(
        missing.is_empty(),
        "these branches are promised the full battery but are not claimed as gated at all in \
         ci-trigger-branches.txt: {missing:?}"
    );
}
