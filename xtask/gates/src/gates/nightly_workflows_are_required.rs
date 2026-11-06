//! A workflow whose name promises a nightly has to run at night.
//!
//! # The failure this closes
//!
//! Two shapes, both of which look like CI and are not:
//!
//!   * a file called `*-nightly.yml` with no `schedule:` trigger. It runs on
//!     pull requests, passes, and is green in a list that makes a reader
//!     believe the long run happened overnight. The cheap run is real; the
//!     expensive one it stands in for does not exist.
//!   * a scheduled trigger with no `cron:` under it, which YAML accepts and
//!     GitHub reads as an empty schedule: no run, no error, no badge.

//! Nightly runs are a gate in their own right (Section 16.2 rule 1): a red
//! nightly opens a finding and blocks merges on the affected lock paths. A
//! nightly that never fires protects nothing, and nothing in the tree would
//! say so.
//!
//! # The deferred list, and why the gate is not red about it
//!
//! Section 16.2 requires workflows whose subject does not exist yet:
//! `execution.yml` needs the execution workspaces of WP-26 to WP-35,
//! `mobile.yml` needs the mobile validator of WP-36, `storage-nightly.yml`
//! needs the acceptance runs of WP-18 and WP-20. A gate that fails on a file
//! whose subject is not in the tree fails on every commit until four other
//! packages land, which is the failure mode the `udeps` and `no-idle-code`
//! gates already rejected: a gate that is always red gets switched off.
//!
//! So absence is reported, not failed. The report names every missing file
//! with the package that owns it, which means the list is visible in the gate
//! output of every run and goes down as those packages land. A file that
//! exists is checked strictly: a required workflow that is present and is not
//! scheduled fails, which is the state this gate exists to catch.
//!
//! A scheduled workflow that declares no jobs, or whose jobs are all
//! permanently disabled, fails too: that is a schedule that fires into
//! nothing.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// A file name marker that promises a scheduled run.
const SCHEDULED_MARKERS: &[&str] = &["nightly", "weekly"];

/// A scheduled workflow Section 16.2 requires.
struct Required {
    /// File name inside `.github/workflows`.
    file: &'static str,
    /// The package that adds it.
    owner: &'static str,
    /// What it runs.
    why: &'static str,
}

/// The scheduled workflows of Section 16.2.
///
/// `execution.yml` is in the table for a pull request trigger only, so it is
/// not here: it is not a nightly. Every entry below runs on a schedule.
const REQUIRED: &[Required] = &[
    Required {
        file: "conformance-nightly.yml",
        owner: "WP-42",
        why: "ecosystem conformance of the endpoint contracts",
    },
    Required {
        file: "fuzz-nightly.yml",
        owner: "WP-42",
        why: "long fuzz runs",
    },
    Required {
        file: "kani-slow.yml",
        owner: "WP-42",
        why: "the slow Kani proofs",
    },
    Required {
        file: "air-mutants-nightly.yml",
        owner: "WP-42",
        why: "AIR mutation testing",
    },
    Required {
        file: "miri.yml",
        owner: "WP-42",
        why: "Miri over the undefined-behaviour surface",
    },
    Required {
        file: "determinism.yml",
        owner: "WP-46",
        why: "golden vectors across x86_64 and aarch64",
    },
    Required {
        file: "storage-nightly.yml",
        owner: "WP-20",
        why: "heavy storage acceptance runs T3, T4, T6, T7, T17",
    },
    Required {
        file: "churn-nightly.yml",
        owner: "WP-14",
        why: "churn scenarios",
    },
    Required {
        file: "nat-nightly.yml",
        owner: "WP-15",
        why: "NAT simulation",
    },
    Required {
        file: "mobile.yml",
        owner: "WP-36",
        why: "Android build and emulator runs",
    },
    Required {
        file: "mobile-ios.yml",
        owner: "WP-38",
        why: "iOS build and simulator runs",
    },
    Required {
        file: "supply-chain.yml",
        owner: "WP-42",
        why: "cargo-deny, cargo-audit, cargo-vet, osv-scanner, Grype, SBOM",
    },
];

/// Is the workflow's whole text a working scheduled workflow?
///
/// A scheduled workflow needs a top level `schedule:` key, at least one
/// `cron:` entry under it, a `jobs:` mapping, and no line that disables a job
/// with a literal false.
fn scheduled_ok(text: &str) -> Result<(), String> {
    let mut has_schedule = false;
    let mut has_cron = false;
    let mut has_jobs = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "schedule:" || trimmed == "\"schedule\":" {
            has_schedule = true;
        }
        if trimmed.starts_with("- cron:") || trimmed.starts_with("cron:") {
            if has_schedule {
                has_cron = true;
            }
        }
        if trimmed == "jobs:" {
            has_jobs = true;
        }
        let bare = trimmed.replace(' ', "");
        if bare == "if:false" || bare == "if:false||true" {
            return Err(String::from(
                "a job or step is disabled with a literal false, so the schedule fires into nothing",
            ));
        }
    }
    if !has_schedule {
        return Err(String::from(
            "no top level `schedule:` trigger, so the file runs on its other triggers only",
        ));
    }
    if !has_cron {
        return Err(String::from(
            "`schedule:` carries no `cron:` entry, so GitHub has no time to run it",
        ));
    }
    if !has_jobs {
        return Err(String::from(
            "no `jobs:` mapping, so there is nothing for the schedule to run",
        ));
    }
    Ok(())
}

/// Every workflow file GitHub reads.
fn workflow_files(root: &Path) -> Vec<PathBuf> {
    let dir = root.join(".github/workflows");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("yml") || x.eq_ignore_ascii_case("yaml"));
        if is_yaml {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// The file name of a path, as a string.
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Does the file name promise a scheduled run?
fn promises_schedule(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SCHEDULED_MARKERS.iter().any(|marker| lower.contains(marker))
}

/// Run the gate.
///
/// # Errors
///
/// A file that promises a nightly without a working schedule, a required
/// workflow that is present and is not scheduled, or a tree with no workflows.
pub fn run(root: &Path) -> Result<String, String> {
    let files = workflow_files(root);
    if files.is_empty() {
        return Err(String::from(
            "no workflow files under .github/workflows; there is no nightly to require",
        ));
    }

    let mut findings: Vec<String> = Vec::new();
    let mut scheduled_count = 0usize;

    for file in &files {
        let name = file_name(file);
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        let promised = promises_schedule(&name);
        let required = REQUIRED.iter().find(|r| r.file == name.as_str());
        if !promised && required.is_none() {
            continue;
        }
        match scheduled_ok(&text) {
            Ok(()) => scheduled_count += 1,
            Err(reason) => {
                let owner = required.map_or_else(
                    || String::from("this file's name promises a nightly"),
                    |r| format!("required by Section 16.2, owned by {}", r.owner),
                );
                findings.push(format!("{name}: {reason} ({owner})"));
            }
        }
    }

    let mut deferred: Vec<&Required> = Vec::new();
    for required in REQUIRED {
        if !files.iter().any(|f| file_name(f) == required.file) {
            deferred.push(required);
        }
    }

    if !findings.is_empty() {
        let mut msg = String::new();
        let _ = writeln!(msg, "{} finding(s):\n", findings.len());
        for finding in &findings {
            let _ = writeln!(msg, "  {finding}");
        }
        return Err(msg);
    }

    let mut deferred_note = String::new();
    if !deferred.is_empty() {
        let _ = writeln!(
            deferred_note,
            " {} required workflow(s) are deferred until their subject exists in the tree:",
            deferred.len()
        );
        for entry in &deferred {
            let _ = writeln!(
                deferred_note,
                "   {} ({}, {})",
                entry.file, entry.owner, entry.why
            );
        }
    }

    Ok(format!(
        "Nightly gate OK: {scheduled_count} scheduled workflow(s) carry a cron trigger, a jobs \
         mapping and no permanently disabled job; every file whose name promises a nightly is one \
         of them.{deferred_note}"
    ))
}

/// Canaries for the scheduled-workflow reader.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    let good = "\
name: X
on:
  schedule:
    - cron: \"17 3 * * *\"
  workflow_dispatch:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
";
    if scheduled_ok(good).is_err() {
        problems.push(format!(
            "BROKEN: a correct scheduled workflow was rejected: {:?}",
            scheduled_ok(good)
        ));
    }

    // The shape the gate is for: a file called nightly with no schedule.
    let unscheduled = "\
name: X
on:
  pull_request:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
";
    if scheduled_ok(unscheduled).is_ok() {
        problems.push(String::from(
            "VACUOUS: a workflow with no schedule was accepted, which is a nightly that never runs at night",
        ));
    }

    // A schedule with no cron fires at no time.
    let empty_schedule = "\
name: X
on:
  schedule:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
";
    if scheduled_ok(empty_schedule).is_ok() {
        problems.push(String::from(
            "VACUOUS: a `schedule:` with no `cron:` was accepted",
        ));
    }

    // A schedule that fires into no jobs.
    let no_jobs = "\
name: X
on:
  schedule:
    - cron: \"17 3 * * *\"
";
    if scheduled_ok(no_jobs).is_ok() {
        problems.push(String::from(
            "VACUOUS: a scheduled workflow with no jobs mapping was accepted",
        ));
    }

    // A job disabled with a literal false.
    let disabled = "\
name: X
on:
  schedule:
    - cron: \"17 3 * * *\"
jobs:
  a:
    if: false
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
";
    if scheduled_ok(disabled).is_ok() {
        problems.push(String::from(
            "VACUOUS: a scheduled workflow whose job is disabled with `if: false` was accepted",
        ));
    }

    // The name rule: a file that promises a nightly is recognised, and a file
    // that does not is not dragged into the requirement.
    if !promises_schedule("fuzz-nightly.yml") {
        problems.push(String::from(
            "BROKEN: `fuzz-nightly.yml` was not recognised as a nightly",
        ));
    }
    if !promises_schedule("miri-storage-weekly.yml") {
        problems.push(String::from(
            "BROKEN: a weekly workflow was not recognised as scheduled",
        ));
    }
    if promises_schedule("ci.yml") {
        problems.push(String::from(
            "BROKEN: `ci.yml` was read as a nightly workflow",
        ));
    }

    // Every required entry names a package and a reason, and no two entries
    // name the same file.
    for (index, entry) in REQUIRED.iter().enumerate() {
        if !entry.owner.starts_with("WP-") {
            problems.push(format!(
                "BROKEN: `{}` names `{}` rather than a work package",
                entry.file, entry.owner
            ));
        }
        if entry.why.is_empty() {
            problems.push(format!("BROKEN: `{}` carries no reason", entry.file));
        }
        if REQUIRED[index + 1..]
            .iter()
            .any(|other| other.file == entry.file)
        {
            problems.push(format!("BROKEN: `{}` is required twice", entry.file));
        }
    }

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "nightly gate self-test OK: a cron-scheduled workflow passes; a workflow with no schedule, a \
         `schedule:` with no `cron:`, a schedule with no jobs and a job disabled with `if: false` are \
         all refused; `*-nightly` and `*-weekly` names are recognised and `ci.yml` is not; every \
         required entry names a work package, carries a reason and is unique.",
    ))
}
