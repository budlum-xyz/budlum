//! The dependency audit.
//!
//! It replaces `ops/scripts/audit-deps.sh`. It runs `cargo audit` over both
//! lockfiles (root and `budzero`), prints the raw findings into the log, lists
//! the advisory identifiers it saw and writes `target/audit/DEPENDENCY_AUDIT.md`.
//!
//! The exit code of `cargo audit` is the verdict. The root lockfile wins when
//! both fail. The tool reports the finding as an error, so the process exits
//! non-zero, which is what CI looks at.
//!
//! # Why the findings are printed
//!
//! An earlier version sent the raw output to a report file that no workflow
//! uploaded, so the job came back green with no advisory name in the log.
//! `.quality/deny.toml` sets `unmaintained = "none"` on the promise that
//! `cargo audit` reports those warnings on every run. Printing the output keeps
//! that promise true. If this printing is removed, that decision has to be
//! reconsidered as well.

use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::support::{git_short_head, head_lines, utc_timestamp};
use crate::{has_program, run_checked};

const ROOT_LOCK: &str = "Cargo.lock";
const BUDZERO_LOCK: &str = "budzero/Cargo.lock";

/// Run the audit.
///
/// # Errors
///
/// If a tool cannot be run, the report cannot be written, or `cargo audit`
/// reports a finding.
pub fn run(root: &Path) -> Result<String, String> {
    println!("[audit-deps] starting the Budlum Core dependency audit...");

    if !has_program("cargo-audit") {
        println!("[audit-deps] installing cargo-audit...");
        run_checked("cargo", &["install", "--locked", "cargo-audit"], root)?;
    }

    // The JSON runs only decide the exit codes; nothing reads their output.
    let root_exit = audit_exit(root, ROOT_LOCK)?;
    let budzero_exit = audit_exit(root, BUDZERO_LOCK)?;
    let verdict = combined_exit(root_exit, budzero_exit);

    let root_raw = raw_output(root, ROOT_LOCK)?;
    let budzero_raw = raw_output(root, BUDZERO_LOCK)?;

    println!();
    println!("-------- cargo audit - root Cargo.lock --------");
    println!("{root_raw}");
    println!("-------- cargo audit - budzero/Cargo.lock --------");
    println!("{budzero_raw}");
    println!("--------------------------------------------------");
    println!();

    let advisories = advisory_ids(&[&root_raw, &budzero_raw]);
    if advisories.is_empty() {
        println!("[audit-deps] no advisory was found.");
    } else {
        println!("[audit-deps] advisories seen in this tree:");
        for id in &advisories {
            println!("  - {id}");
        }
    }
    println!();

    let report_path = root.join("target/audit/DEPENDENCY_AUDIT.md");
    if let Some(dir) = report_path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("{} could not be created: {e}", dir.display()))?;
    }
    let report = render_report(
        &utc_timestamp(),
        &git_short_head(root),
        root_exit,
        budzero_exit,
        &root_raw,
        &budzero_raw,
    );
    std::fs::write(&report_path, report)
        .map_err(|e| format!("{} could not be written: {e}", report_path.display()))?;

    println!("[audit-deps] report: {}", report_path.display());

    if verdict == 0 {
        Ok("[audit-deps] done.".to_string())
    } else {
        Err(format!("cargo audit exited with code {verdict}"))
    }
}

/// Run `cargo audit --json` for one lockfile and return its exit code. The
/// JSON itself is discarded; the findings are read from the raw run below.
fn audit_exit(root: &Path, lock: &str) -> Result<i32, String> {
    let status = Command::new("cargo")
        .args(["audit", "--file", lock, "--json"])
        .current_dir(root)
        .stdout(Stdio::null())
        .status()
        .map_err(|e| format!("`cargo audit` could not be run: {e}"))?;
    Ok(status.code().unwrap_or(-1))
}

/// Run `cargo audit --deny warnings` for one lockfile and capture stdout and
/// stderr together, in the order the tool wrote them. The exit code is not
/// used here: the JSON run above decided the verdict.
fn raw_output(root: &Path, lock: &str) -> Result<String, String> {
    let dir = crate::support::make_temp_dir("budlum-audit-raw")?;
    let path = dir.join("out.txt");
    let result = (|| {
        let out = File::create(&path)
            .map_err(|e| format!("{} could not be created: {e}", path.display()))?;
        let err = out
            .try_clone()
            .map_err(|e| format!("could not share the output file: {e}"))?;
        Command::new("cargo")
            .args(["audit", "--file", lock, "--deny", "warnings"])
            .current_dir(root)
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .status()
            .map_err(|e| format!("`cargo audit` could not be run: {e}"))?;
        std::fs::read(&path)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .map_err(|e| format!("{} could not be read: {e}", path.display()))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// The root lockfile's code wins, then the `BudZero` one, else zero.
#[must_use]
pub fn combined_exit(root_exit: i32, budzero_exit: i32) -> i32 {
    if root_exit != 0 {
        root_exit
    } else {
        budzero_exit
    }
}

/// Every `RUSTSEC-YYYY-NNNN` identifier in the texts, sorted and unique.
#[must_use]
pub fn advisory_ids(texts: &[&str]) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for text in texts {
        let bytes = text.as_bytes();
        let mut from = 0;
        while let Some(found) = text[from..].find("RUSTSEC-") {
            let start = from + found;
            let tail = &bytes[start + 8..];
            let shape_ok = tail.len() >= 9
                && tail[..4].iter().all(u8::is_ascii_digit)
                && tail[4] == b'-'
                && tail[5..9].iter().all(u8::is_ascii_digit);
            if shape_ok {
                ids.push(text[start..start + 17].to_string());
            }
            from = start + 8;
        }
    }
    ids.sort();
    ids.dedup();
    ids
}

/// The Markdown report. Each raw block is cut to its first 50 lines.
#[must_use]
pub fn render_report(
    timestamp: &str,
    head: &str,
    root_exit: i32,
    budzero_exit: i32,
    root_raw: &str,
    budzero_raw: &str,
) -> String {
    let verdict = combined_exit(root_exit, budzero_exit);
    let summary = if verdict == 0 {
        "- OK **NO** known security hole (root + budzero lockfile).".to_string()
    } else {
        format!("- WARNING cargo-audit exit code: {verdict} (usually an unmaintained warning).")
    };
    format!(
        "# Dependency Audit Report\n\
         \n\
         **Generated:** {timestamp}\n\
         **Tool:** cargo-audit (https://github.com/rustsec/rustsec)\n\
         **Repo:** budlum-xyz/budlum @ `{head}`\n\
         \n\
         ## Summary\n\
         \n\
         {summary}\n\
         - Root lockfile exit code: {root_exit}\n\
         - BudZero lockfile exit code: {budzero_exit}\n\
         \n\
         ## Raw output - root Cargo.lock\n\
         \n\
         ```\n\
         {root}\n\
         ```\n\
         \n\
         ## Raw output - budzero/Cargo.lock\n\
         \n\
         ```\n\
         {budzero}\n\
         ```\n\
         \n\
         ## Acceptance criterion\n\
         \n\
         The `dependency-audit` job in CI runs this tool. **If a known\n\
         security hole (CVE) is detected the job fails.** Unmaintained\n\
         warnings are reported as warnings (they do not fail). The root and BudZero\n\
         lockfiles are checked together.\n\
         \n\
         This report is generated automatically.\n",
        root = head_lines(root_raw, 50),
        budzero = head_lines(budzero_raw, 50),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_lockfile_decides_first() {
        assert_eq!(combined_exit(0, 0), 0);
        assert_eq!(combined_exit(1, 0), 1);
        assert_eq!(combined_exit(0, 2), 2);
        assert_eq!(combined_exit(3, 2), 3);
    }

    #[test]
    fn finds_sorted_unique_advisory_ids() {
        let a = "warning: RUSTSEC-2024-0380 found\nID: RUSTSEC-2023-0001\n";
        let b = "again RUSTSEC-2024-0380, and RUSTSEC-2024-038 (short), RUSTSEC-24-0001, RUSTSEC-2022-12345";
        let ids = advisory_ids(&[a, b]);
        assert_eq!(
            ids,
            vec![
                "RUSTSEC-2022-1234",
                "RUSTSEC-2023-0001",
                "RUSTSEC-2024-0380"
            ]
        );
    }

    #[test]
    fn no_advisory_gives_an_empty_list() {
        assert!(advisory_ids(&["Success No vulnerable packages found", ""]).is_empty());
    }

    #[test]
    fn the_report_states_the_verdict_and_cuts_long_output() {
        let long = (0..80)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let report = render_report("2026-10-07T00:00:00Z", "abc1234", 0, 0, &long, "ok");
        assert!(report.contains("- OK **NO** known security hole"));
        assert!(report.contains("\n49\n"));
        assert!(!report.contains("\n50\n"));
        assert!(report.contains("**Repo:** budlum-xyz/budlum @ `abc1234`"));
        assert!(report.contains("- Root lockfile exit code: 0"));

        let bad = render_report("t", "h", 0, 1, "", "");
        assert!(bad.contains("- WARNING cargo-audit exit code: 1"));
        assert!(bad.contains("- BudZero lockfile exit code: 1"));
    }
}
