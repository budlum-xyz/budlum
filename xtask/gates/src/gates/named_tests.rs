//! Shared machinery for the "named required tests" gates.
//!
//! A whole family of shell gates share one shape: a list of test names that
//! must appear in a cargo test log, plus a self-test that stages a fake log
//! (all names present -> pass; first name removed -> fail). This module holds
//! that shape once so each ported gate is a name list and a subject string.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// Is this log line the libtest result `test <path> ... ok` of the test
/// `name`? The path must be `name` or end in `::name`.
///
/// The first version matched "name appears, then `ok` appears later" anywhere
/// in the line. A failure line such as `thread 'tests::x::name' panicked at
/// src/tokenomics/...` has the name followed by the letters `ok`, and a longer
/// name such as `name_v2 ... ok` contains `name`. Both counted as a pass.
fn line_matches(line: &str, name: &str) -> bool {
    let Some(rest) = line.trim_end().strip_prefix("test ") else {
        return false;
    };
    let Some(path) = rest.strip_suffix(" ... ok") else {
        return false;
    };
    path == name || path.ends_with(&format!("::{name}"))
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

#[cfg(test)]
mod tests {
    use super::line_matches;

    #[test]
    fn only_the_exact_ok_line_of_the_named_test_matches() {
        assert!(line_matches(
            "test economy::tests::burn_is_capped ... ok",
            "burn_is_capped"
        ));
        assert!(line_matches("test burn_is_capped ... ok", "burn_is_capped"));
        // A failure line whose path holds "ok" after the name.
        assert!(!line_matches(
            "thread 'tests::burn_is_capped' panicked at src/tokenomics/mod.rs:9:1:",
            "burn_is_capped"
        ));
        // A longer name must not satisfy a shorter one.
        assert!(!line_matches(
            "test tests::burn_is_capped_v2 ... ok",
            "burn_is_capped"
        ));
        assert!(!line_matches(
            "test tests::xburn_is_capped ... ok",
            "burn_is_capped"
        ));
        // A failed or ignored result is not a pass.
        assert!(!line_matches(
            "test tests::burn_is_capped ... FAILED",
            "burn_is_capped"
        ));
        assert!(!line_matches(
            "test tests::burn_is_capped ... ignored",
            "burn_is_capped"
        ));
    }
}
