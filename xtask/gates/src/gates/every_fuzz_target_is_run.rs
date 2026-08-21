//! A fuzz target nothing schedules is a test that never runs.
//!
//! # The failure this closes
//!
//! `fuzz/Cargo.toml` declares thirteen targets. Two of them,
//! `evm_rlp_decode` and `evm_mpt_verify`, appear in neither the pull-request
//! job nor the nightly matrix. They compile, they are counted whenever
//! somebody counts fuzz targets, and no machine has ever driven them. The
//! comment beside the quick list says as much and calls them
//! "nightly/manual", but the nightly matrix does not list them either, so the
//! sentence describes an intention rather than a schedule.
//!
//! That is the same defect this tree has now found several times in different
//! clothes: a number or a name written down rather than measured. Thirteen
//! targets exist, eleven run, and every report that says "thirteen fuzz
//! targets" is off by two in the direction that matters.
//!
//! # Why a seed corpus is part of the same question
//!
//! `budl_compile_then_run` found a real stack overflow in the parser on the
//! night of 6 August 2026 and again on the 7th, and the guard that fixed it
//! landed on the 8th. The target has no corpus directory, so the input that
//! reached that bug is not kept anywhere: the crash artifact is uploaded to a
//! run artifact that expires, and the next fuzzer starts from nothing.
//!
//! libFuzzer rediscovers shallow bugs quickly, so this is not a claim that
//! coverage is lost forever. It is a claim about time: a target that starts
//! from an empty corpus spends its four hours re-deriving the shape of a
//! valid input, and a target that starts from ten seeds spends them looking
//! past that shape. Eleven of the thirteen have seeds. The three that do not
//! are `budl_compile`, `budl_compile_then_run` and `reputation`, and the
//! first two take structured source text, which is exactly the kind of input
//! a fuzzer is slowest to invent from scratch.
//!
//! # What is checked
//!
//! 1. Every target declared in `fuzz/Cargo.toml` has a `fuzz_targets/<name>.rs`.
//! 2. Every file in `fuzz_targets/` is declared in `fuzz/Cargo.toml`.
//! 3. Every declared target is named by at least one schedule: the
//!    pull-request list in `ci.yml` or the matrix in `fuzz-nightly.yml`.
//! 4. Every declared target has a non-empty seed corpus directory.
//! 5. No corpus directory belongs to a target that no longer exists.
//!
//! Checks 1, 2 and 5 are about the three lists agreeing. Check 3 is the one
//! that found the gap. Check 4 is a floor rather than a target: one seed is
//! enough to satisfy it, because the claim being enforced is that somebody
//! chose a starting point, not that the corpus is large.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

/// A target whose absence from a schedule is intentional, with the reason.
///
/// Empty, and it should stay that way. It exists because the honest way to
/// exclude a target is to say so here rather than to leave it out of a list
/// and write a comment somewhere else, which is how `evm_rlp_decode` and
/// `evm_mpt_verify` came to be unscheduled while a comment claimed they were
/// nightly.
const UNSCHEDULED_ON_PURPOSE: &[(&str, &str)] = &[];

/// What the three sources say, measured rather than assumed.
struct Inventory {
    /// Targets declared as `[[bin]]` entries in `fuzz/Cargo.toml`.
    declared: BTreeSet<String>,
    /// Files present in `fuzz/fuzz_targets/`.
    files: BTreeSet<String>,
    /// Target to the schedules that name it.
    scheduled: BTreeMap<String, Vec<String>>,
    /// Corpus directory to the number of seeds in it.
    corpora: BTreeMap<String, usize>,
}

/// Read the `[[bin]] name = "..."` entries out of a fuzz manifest.
///
/// `cargo-fuzz` writes one `[[bin]]` per target and nothing else uses that
/// section here, so the section header is the signal and the `name` key
/// immediately under it is the value.
fn declared_targets(manifest: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_bin = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_bin = t == "[[bin]]";
            continue;
        }
        if !in_bin {
            continue;
        }
        if let Some(rest) = t.strip_prefix("name") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let v = rest.trim().trim_matches('"');
                if !v.is_empty() {
                    out.insert(v.to_string());
                }
            }
        }
    }
    out
}

/// Whether a schedule file names a target.
///
/// Both schedules are lists of bare target names, one per line, in a YAML
/// sequence or a shell array. Reading them as "a line whose only content is
/// this name, possibly after a dash" matches both and refuses a match inside
/// a sentence, which is what makes the comment claiming the EVM targets are
/// nightly fail to count as a schedule.
fn names_target(text: &str, target: &str) -> bool {
    text.lines().any(|line| {
        let t = line.trim();
        // A comment mentioning the target is not a schedule.
        if t.starts_with('#') {
            return false;
        }
        let t = t.strip_prefix("- ").unwrap_or(t);
        t.trim() == target
    })
}

fn measure(root: &Path) -> Result<Inventory, String> {
    let manifest_path = root.join("fuzz/Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("cannot read {}: {e}", manifest_path.display()))?;
    let declared = declared_targets(&manifest);
    if declared.is_empty() {
        return Err(String::from(
            "fuzz/Cargo.toml declares no [[bin]] targets. Either the manifest moved or the \
             reader stopped working; a gate that measured nothing must not pass.",
        ));
    }

    let mut files = BTreeSet::new();
    let dir = root.join("fuzz/fuzz_targets");
    let entries =
        std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(stem) = name.strip_suffix(".rs") {
            files.insert(stem.to_string());
        }
    }

    // The two schedules.
    let sources: [(&str, &str); 2] = [
        ("ci.yml", ".github/workflows/ci.yml"),
        ("fuzz-nightly.yml", ".github/workflows/fuzz-nightly.yml"),
    ];
    let mut scheduled: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for target in &declared {
        scheduled.insert(target.clone(), Vec::new());
    }
    for (label, rel) in sources {
        let path = root.join(rel);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        for target in &declared {
            if names_target(&text, target) {
                scheduled
                    .entry(target.clone())
                    .or_default()
                    .push(label.to_string());
            }
        }
    }

    let mut corpora = BTreeMap::new();
    let corpus_root = root.join("fuzz/corpus");
    if let Ok(entries) = std::fs::read_dir(&corpus_root) {
        for entry in entries.flatten() {
            let Ok(entry_kind) = entry.file_type() else {
                continue;
            };
            if !entry_kind.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let count = std::fs::read_dir(entry.path())
                .map_or(0, |d| d.flatten().filter(|f| f.path().is_file()).count());
            corpora.insert(name, count);
        }
    }

    Ok(Inventory {
        declared,
        files,
        scheduled,
        corpora,
    })
}

/// # Errors
///
/// Returns the targets that are declared but not scheduled, not seeded, or
/// out of step with the files on disk.
pub fn run(root: &Path) -> Result<String, String> {
    let inv = measure(root)?;
    let mut problems: Vec<String> = Vec::new();

    for target in &inv.declared {
        if !inv.files.contains(target) {
            problems.push(format!(
                "`{target}` is declared in fuzz/Cargo.toml and there is no \
                 fuzz_targets/{target}.rs to build."
            ));
        }
    }
    for file in &inv.files {
        if !inv.declared.contains(file) {
            problems.push(format!(
                "fuzz_targets/{file}.rs exists and no [[bin]] in fuzz/Cargo.toml declares it, \
                 so cargo-fuzz will not build or run it."
            ));
        }
    }

    for target in &inv.declared {
        let none = Vec::new();
        let listed_by = inv.scheduled.get(target).unwrap_or(&none);
        if listed_by.is_empty() {
            if let Some((_, reason)) = UNSCHEDULED_ON_PURPOSE.iter().find(|(t, _)| t == target) {
                let _ = reason;
                continue;
            }
            problems.push(format!(
                "`{target}` is declared and no schedule names it: not in the pull-request list \
                 in ci.yml, not in the matrix in fuzz-nightly.yml. It compiles and it has never \
                 been run. Add it to a schedule, or list it in UNSCHEDULED_ON_PURPOSE with the \
                 reason."
            ));
        }
    }

    for target in &inv.declared {
        match inv.corpora.get(target) {
            None => problems.push(format!(
                "`{target}` has no fuzz/corpus/{target}/ directory, so every run starts from \
                 nothing and spends its budget re-deriving the shape of a valid input instead \
                 of looking past it. Commit at least one seed."
            )),
            Some(0) => problems.push(format!(
                "fuzz/corpus/{target}/ exists and is empty, which is the same as having no \
                 corpus while looking like it has one."
            )),
            Some(_) => {}
        }
    }

    for name in inv.corpora.keys() {
        if !inv.declared.contains(name) {
            problems.push(format!(
                "fuzz/corpus/{name}/ belongs to no declared target. Either the target was \
                 removed and its seeds were left behind, or the directory is misspelled and the \
                 target it was meant for is running without them."
            ));
        }
    }

    if problems.is_empty() {
        let seeds: usize = inv.corpora.values().sum();
        return Ok(format!(
            "Fuzz gate OK: {} targets declared, each with a source file, each named by a \
             schedule, and each starting from one of {} committed seeds.",
            inv.declared.len(),
            seeds
        ));
    }

    let mut msg = format!("{} fuzz problem(s):\n\n", problems.len());
    for p in &problems {
        let _ = writeln!(msg, "  {p}\n");
    }
    Err(msg)
}

/// Canaries for the manifest reader and the schedule matcher.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    // The manifest reader takes names only from [[bin]] sections.
    let manifest = r#"
[package]
name = "budlum-fuzz"

[dependencies]
libfuzzer-sys = "0.4"

[[bin]]
name = "alpha"
path = "fuzz_targets/alpha.rs"

[[bin]]
name = "beta"
path = "fuzz_targets/beta.rs"
"#;
    let declared = declared_targets(manifest);
    if !declared.contains("alpha") || !declared.contains("beta") {
        problems.push(format!(
            "BROKEN: manifest reader missed a target: {declared:?}"
        ));
    }
    if declared.contains("budlum-fuzz") {
        problems.push(String::from(
            "BROKEN: manifest reader took the package name for a target",
        ));
    }
    if declared.len() != 2 {
        problems.push(format!(
            "BROKEN: manifest reader read {} names, expected 2",
            declared.len()
        ));
    }

    // A YAML sequence entry counts as a schedule.
    let yaml = "      matrix:\n        target:\n          - alpha\n          - beta\n";
    if !names_target(yaml, "alpha") {
        problems.push(String::from(
            "BROKEN: a YAML sequence entry was not read as a schedule",
        ));
    }
    // A shell array entry counts too.
    let shell = "          targets=(\n            alpha\n            gamma\n          )\n";
    if !names_target(shell, "gamma") {
        problems.push(String::from(
            "BROKEN: a shell array entry was not read as a schedule",
        ));
    }
    // A comment does not. This is the whole point: the EVM targets were
    // described as nightly in a comment and scheduled nowhere.
    let comment = "          # Note: evm_rlp_decode remains nightly/manual\n";
    if names_target(comment, "evm_rlp_decode") {
        problems.push(String::from(
            "BROKEN: a comment mentioning a target was counted as scheduling it",
        ));
    }
    // Nor does a mention inside a sentence.
    let prose = "          # quick gate covers alpha and beta today\n";
    if names_target(prose, "alpha") {
        problems.push(String::from(
            "BROKEN: a bare mention in prose was counted as a schedule",
        ));
    }
    // A name that is a prefix of a scheduled one is not scheduled by it.
    let similar = "          - budl_compile_then_run\n";
    if names_target(similar, "budl_compile") {
        problems.push(String::from(
            "BROKEN: a target was matched by a longer name that starts with it",
        ));
    }
    if !names_target(similar, "budl_compile_then_run") {
        problems.push(String::from(
            "BROKEN: an exact sequence entry did not match",
        ));
    }

    if problems.is_empty() {
        return Ok(String::from(
            "fuzz gate self-test OK: the manifest reader takes names from [[bin]] and not the \
             package, YAML sequence and shell array entries both count as schedules, and a \
             comment, a mention in prose and a longer name sharing a prefix all do not.",
        ));
    }
    Err(problems.join("\n"))
}
