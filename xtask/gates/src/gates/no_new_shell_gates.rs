//! The shell gates are a closed set, and it only shrinks.
//!
//! Seventy-four `scripts/check-*.sh`, eighteen thousand lines, all of them
//! inside the trust boundary because they decide what lands on `main`. They
//! are being rewritten in Rust one at a time. A rewrite that takes months is
//! only worth starting if the pile stops growing while it happens, and the
//! cheapest way for it to grow is for the next gate to be written in shell
//! because that is what the neighbours look like.
//!
//! So this gate pins the inventory. The number of `scripts/check-*.sh` may
//! fall and may not rise, and the names are listed rather than counted, so
//! deleting one gate and adding another nets to zero on a count and fails
//! here.
//!
//! # Why a list and not a count
//!
//! A count is satisfied by a swap. The list is the thing that carries the
//! intent: every name on it is a gate waiting to be ported, and a name that
//! is not on it is a shell gate written after the decision to stop writing
//! them. When a gate is ported, its name comes off the list in the same
//! commit that deletes the script, and the list gets shorter.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// Every `scripts/check-*.sh` that existed when the migration to Rust began.
///
/// Sorted, one per line, so a diff on this file reads as exactly which gate
/// was ported. Nothing may be added. Removing an entry means the gate now
/// lives in `xtask/gates` and the script is gone from the tree.
const SHELL_GATES_AT_MIGRATION_START: &[&str] = &[
    "check-a-derivation-cannot-outlive-its-master.sh",
    "check-accumulators-pin-their-first-row.sh",
    "check-actionlint.sh",
    "check-air-selectors-are-opcode-bound.sh",
    "check-badges-are-current.sh",
    "check-binding-claims-match-reality.sh",
    "check-bit-decompositions-are-canonical.sh",
    "check-bns-gate.sh",
    "check-bud-e2e.sh",
    "check-capability-modules-are-wired.sh",
    "check-cargo-vet.sh",
    "check-clippy-extra.sh",
    "check-coding-audit-samples-the-relationship.sh",
    "check-consensus-maps-are-ordered.sh",
    "check-containment-defaults.sh",
    "check-content-encryption-is-declared-and-bound.sh",
    "check-coverage.sh",
    "check-cross-table-checks-use-last-row.sh",
    "check-derived-content-stays-byte-exact.sh",
    "check-docker-toolchain-matches-pin.sh",
    "check-domain-tags.sh",
    "check-economy-invariants.sh",
    "check-every-opcode-has-a-forgery-test.sh",
    "check-evidence-provenance-is-checked.sh",
    "check-forgery-tests-are-named.sh",
    "check-fork-choice-gate.sh",
    "check-fuzz-targets-are-wired.sh",
    "check-gates-are-wired.sh",
    "check-gating-flags-are-pinned.sh",
    "check-geiger.sh",
    "check-generated-content-is-verifiable.sh",
    "check-git-deps-are-audited-by-commit.sh",
    "check-governance-invariants.sh",
    "check-guards-are-reachable.sh",
    "check-hash-inputs-are-length-prefixed.sh",
    "check-kani.sh",
    "check-lock-failures-do-not-open-a-bound.sh",
    "check-logup-multipliers-are-boolean.sh",
    "check-lubot-reads-but-does-not-generate.sh",
    "check-network-hardening-gate.sh",
    "check-no-conflict-markers-are-committed.sh",
    "check-no-orphan-source-files.sh",
    "check-no-unicode-dashes.sh",
    "check-node-classification-gate.sh",
    "check-paid-content-cannot-be-read-for-free.sh",
    "check-pinned-downloads-are-really-pinned.sh",
    "check-poa-compliance-gate.sh",
    "check-readme-does-not-deny-shipped-code.sh",
    "check-reduction-claims-state-both-units.sh",
    "check-refusals-do-not-mutate-first.sh",
    "check-rejection-tests-assert-rejection.sh",
    "check-repair-fires-on-loss.sh",
    "check-required-tests-are-tests.sh",
    "check-security-parameters-are-derived.sh",
    "check-self-derived-ids-cover-every-field.sh",
    "check-semver.sh",
    "check-shard-placement-is-sticky-and-staked.sh",
    "check-slash-expression-has-one-home.sh",
    "check-source-reading-tests-are-narrowed.sh",
    "check-storage-is-priced-by-size.sh",
    "check-storage-penalties-are-enforced.sh",
    "check-storage-proof-production-boundary.sh",
    "check-storage-provider-gate.sh",
    "check-threshold-rates-share-one-scale.sh",
    "check-timing-safe.sh",
    "check-udeps.sh",
    "check-uncheckable-proof-paths-do-not-slash.sh",
    "check-untrusted-manifests-are-fully-validated.sh",
    "check-value-transfers-are-priced-by-value.sh",
    "check-wallet-core-gate.sh",
    "check-wire-fields-are-signed.sh",
    "check-zero-storage-bytes-are-frozen.sh",
    "check-zero-tests-use-an-inverse-witness.sh",
    "check-zizmor.sh",
];

/// Read the shell gates actually present in the tree.
fn present(root: &Path) -> Result<BTreeSet<String>, String> {
    let dir = root.join("scripts");
    let entries =
        std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;

    let mut found = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read an entry under scripts/: {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_shell = std::path::Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("sh"));
        if name.starts_with("check-") && is_shell {
            found.insert(name);
        }
    }
    Ok(found)
}

fn judge(found: &BTreeSet<String>, allowed: &BTreeSet<String>) -> Result<String, String> {
    let added: Vec<&String> = found.difference(allowed).collect();
    let ported: Vec<&String> = allowed.difference(found).collect();

    if !added.is_empty() {
        let mut msg = String::new();
        let _ = writeln!(
            msg,
            "{} shell gate(s) exist that are not on the migration list:",
            added.len()
        );
        for a in &added {
            let _ = writeln!(msg, "  scripts/{a}");
        }
        let _ = write!(
            msg,
            "\nThe shell gates are a closed set that only shrinks. These decide what \
             lands on main, so they sit inside the trust boundary, and shell is a poor \
             place for that: a misspelt variable is an empty string rather than an \
             error, so a check can examine nothing and report OK. Two gates on this \
             branch passed while missing the exact defect they were written for.\n\n\
             Write the new gate in xtask/gates as a Rust module with `run` and \
             `self_test`, and wire it through `budlum-gates`."
        );
        return Err(msg);
    }

    let remaining = found.len();
    let done = ported.len();
    if done == 0 {
        return Ok(format!(
            "Shell gate inventory OK: {remaining} scripts, none added. \
             The list only shrinks, and nothing has come off it yet."
        ));
    }
    Ok(format!(
        "Shell gate inventory OK: {remaining} scripts left, {done} ported to Rust and \
         removed from the tree. Nothing was added."
    ))
}

/// # Errors
///
/// Returns a finding when a shell gate exists that is not on the list.
pub fn run(root: &Path) -> Result<String, String> {
    let found = present(root)?;
    if found.is_empty() {
        return Err(String::from(
            "scripts/ contains no check-*.sh at all. The migration list expects some \
             to remain, so either the directory moved or the gates were deleted \
             rather than ported, and this check is now watching nothing.",
        ));
    }
    let allowed: BTreeSet<String> = SHELL_GATES_AT_MIGRATION_START
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    judge(&found, &allowed)
}

/// # Errors
///
/// Returns the list of canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    let allowed: BTreeSet<String> = ["check-a.sh", "check-b.sh"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    // The whole list, unchanged, passes.
    let same: BTreeSet<String> = allowed.clone();
    if let Err(e) = judge(&same, &allowed) {
        problems.push(format!("BROKEN: an unchanged inventory was rejected: {e}"));
    }

    // A new shell gate is refused.
    let mut grown = allowed.clone();
    grown.insert("check-brand-new.sh".to_string());
    match judge(&grown, &allowed) {
        Ok(_) => problems.push(String::from(
            "VACUOUS: a shell gate that is not on the list was accepted",
        )),
        Err(e) => {
            if !e.contains("check-brand-new.sh") {
                problems.push(format!(
                    "BROKEN: the finding does not name the new gate: {e}"
                ));
            }
        }
    }

    // A gate ported away passes, and says so.
    let mut shrunk = allowed.clone();
    shrunk.remove("check-b.sh");
    match judge(&shrunk, &allowed) {
        Ok(msg) => {
            if !msg.contains("1 ported") {
                problems.push(format!("BROKEN: a ported gate was not counted: {msg}"));
            }
        }
        Err(e) => problems.push(format!("BROKEN: a shrinking inventory was rejected: {e}")),
    }

    // The swap: one gate deleted, one added. A count nets to zero here, which
    // is the reason this gate carries names instead.
    let mut swapped = allowed.clone();
    swapped.remove("check-b.sh");
    swapped.insert("check-replacement.sh".to_string());
    if judge(&swapped, &allowed).is_ok() {
        problems.push(String::from(
            "VACUOUS: a gate swapped for a new shell gate was accepted, so this check \
             is counting rather than listing",
        ));
    }

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "shell inventory gate self-test OK: a new shell gate is rejected, and so is a \
         swap that leaves the count unchanged; an unchanged inventory and a ported gate \
         both pass.",
    ))
}
