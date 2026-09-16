//! Shared machinery for the "named required tests" gates.
//!
//! A whole family of shell gates share one shape: a list of test names that
//! must appear in a cargo test log, plus a self-test that stages a fake log
//! (all names present -> pass; first name removed -> fail). This module holds
//! that shape once so each ported gate is a name list and a subject string.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// Does this log line show `name` followed by `ok` somewhere?
///
/// The shell gate matches `grep -Eq "test .*NAME .*ok|NAME.*ok"`. Both
/// alternatives reduce to "NAME appears and `ok` appears after it", which is
/// what this checks.
fn line_matches(line: &str, name: &str) -> bool {
    match line.find(name) {
        Some(pos) => line[pos + name.len()..].contains("ok"),
        None => false,
    }
}

/// # Errors
///
/// Returns a finding naming the first required test that did not run/pass, or
/// when the log file is missing. The `subject` fills the message the shell
/// gate printed (e.g. "Fork-choice").
pub fn check_log(log: &Path, tests: &[&str], subject: &str) -> Result<String, String> {
    if !log.is_file() {
        return Err(format!("test log missing: {}", log.display()));
    }
    let content =
        fs::read_to_string(log).map_err(|e| format!("cannot read {}: {e}", log.display()))?;
    for name in tests {
        if !content.lines().any(|l| line_matches(l, name)) {
            return Err(format!("required {subject} test did not run/pass: {name}"));
        }
    }
    Ok(format!(
        "{subject} gate OK: {} named tests observed.",
        tests.len()
    ))
}

/// # Errors
///
/// Returns a finding when the fake log does not behave: a log carrying every
/// required test must pass, and the same log minus the first test must fail.
/// This is the shell gate's self-test, one for one.
pub fn self_test(tests: &[&str], subject: &str) -> Result<String, String> {
    // The log lives in a directory this call created exclusively, so a
    // pre-planted symlink at a guessable name cannot redirect the write.
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-named")?;
    let log = dir.join("tests.log");

    let mut full = String::new();
    for n in tests {
        writeln!(full, "test {n} ... ok").expect("writing to a String cannot fail");
    }
    fs::write(&log, &full).map_err(|e| format!("cannot stage log: {e}"))?;
    if check_log(&log, tests, subject).is_err() {
        let _ = fs::remove_dir_all(&dir);
        return Err(format!(
            "{subject} self-test: a log with every required test was rejected"
        ));
    }

    let mut missing = String::new();
    for n in &tests[1..] {
        writeln!(missing, "test {n} ... ok").expect("writing to a String cannot fail");
    }
    fs::write(&log, &missing).map_err(|e| format!("cannot stage bad log: {e}"))?;
    if check_log(&log, tests, subject).is_ok() {
        let _ = fs::remove_dir_all(&dir);
        return Err(format!(
            "{subject} self-test: a log missing a required test was accepted"
        ));
    }

    let _ = fs::remove_dir_all(&dir);
    Ok(format!("{subject} gate self-test OK"))
}
