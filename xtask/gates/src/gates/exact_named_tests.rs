//! Shared machinery for the "exact named tests" gates (`bud_e2e`, `bns`).
//!
//! A small family of gates requires each test name to appear *exactly* as
//! `test <module>::<name> ... ok` in a cargo test log. Unlike the broader
//! [`super::named_tests`] family, these use exact line matching so a
//! substring (e.g. `invariant_1` matching `invariant_10`) cannot satisfy
//! them. This module holds the shape once.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// Check that every `name` appears as a full `test <name> ... ok` line in
/// the log, where `name` is the full test path (e.g.
/// `tests::bns::tests::test_bns_registration_and_resolution`). Every observed
/// outcome for a required name must be `ok`; an earlier success cannot hide
/// a failed or ignored run of the same test.
pub fn check_exact_log(log: &Path, tests: &[&str], subject: &str) -> Result<String, String> {
    if tests.is_empty() {
        return Err(format!(
            "the {subject} gate has no required test names, so it would check nothing"
        ));
    }
    if !log.is_file() {
        return Err(format!(
            "the test output is missing/empty: {}",
            log.display()
        ));
    }
    let content = fs::read_to_string(log).map_err(|e| e.to_string())?;
    let mut missing: Vec<String> = Vec::new();
    for name in tests {
        let prefix = format!("test {name} ... ");
        let mut seen = false;
        let mut all_ok = true;
        for outcome in content
            .lines()
            .filter_map(|line| line.trim_end().strip_prefix(&prefix))
        {
            seen = true;
            all_ok &= outcome == "ok";
        }
        if !seen || !all_ok {
            missing.push(name.to_string());
        }
    }
    if !missing.is_empty() {
        let mut msg = String::from("an expected test is missing from the output or is not ok:\n");
        for m in &missing {
            writeln!(msg, "  - {m}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "OK: the required {subject} tests are ok name by name."
    ))
}

/// The shell gates' canary: full log passes, a missing name fails, a FAILED
/// line fails.
pub fn self_test_exact(tests: &[&str], subject: &str) -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-exact")?;

    let full = dir.join("full.txt");
    let mut full_text = String::new();
    for t in tests {
        writeln!(full_text, "test {t} ... ok").expect("writing to a String cannot fail");
    }
    fs::write(&full, &full_text).map_err(|e| e.to_string())?;
    let full_ok = check_exact_log(&full, tests, subject).is_ok();

    let missing = dir.join("missing.txt");
    let mut missing_text = String::new();
    for (i, t) in tests.iter().enumerate() {
        if i == 0 {
            continue;
        }
        writeln!(missing_text, "test {t} ... ok").expect("writing to a String cannot fail");
    }
    fs::write(&missing, &missing_text).map_err(|e| e.to_string())?;
    let missing_fails = check_exact_log(&missing, tests, subject).is_err();

    let failed = dir.join("failed.txt");
    let mut failed_text = String::new();
    for (i, t) in tests.iter().enumerate() {
        let status = if i == 0 { "FAILED" } else { "ok" };
        writeln!(failed_text, "test {t} ... {status}").expect("writing to a String cannot fail");
    }
    fs::write(&failed, &failed_text).map_err(|e| e.to_string())?;
    let failed_fails = check_exact_log(&failed, tests, subject).is_err();

    let conflicting = dir.join("conflicting.txt");
    let mut conflicting_text = full_text.clone();
    if let Some(first) = tests.first() {
        writeln!(conflicting_text, "test {first} ... FAILED").map_err(|e| e.to_string())?;
    }
    fs::write(&conflicting, &conflicting_text).map_err(|e| e.to_string())?;
    let conflicting_fails = check_exact_log(&conflicting, tests, subject).is_err();

    let _ = fs::remove_dir_all(&dir);

    if !full_ok {
        return Err(format!("canary: complete output was refused ({subject})"));
    }
    if !missing_fails {
        return Err(format!("canary: a missing test passed ({subject})"));
    }
    if !failed_fails {
        return Err(format!("canary: a FAILED line passed ({subject})"));
    }
    if !conflicting_fails {
        return Err(format!("canary: conflicting outcomes passed ({subject})"));
    }
    Ok(format!(
        "canary OK: complete -> PASS, missing/FAILED/conflicting -> FAIL ({subject})."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_output(content: &str) -> Result<String, String> {
        let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-exact-outcomes")
            .expect("create isolated log fixture");
        let log = dir.join("tests.log");
        fs::write(&log, content).expect("write log fixture");
        let result = check_exact_log(&log, &["proof::is_bound"], "proof");
        fs::remove_dir_all(&dir).expect("remove log fixture");
        result
    }

    #[test]
    fn accepts_an_exact_success() {
        assert!(check_output("test proof::is_bound ... ok\n").is_ok());
    }

    #[test]
    fn refuses_a_missing_required_test() {
        assert!(check_output("running 0 tests\n").is_err());
    }

    #[test]
    fn refuses_a_similarly_named_test() {
        assert!(check_output("test proof::is_bound_extra ... ok\n").is_err());
    }

    #[test]
    fn refuses_a_failed_required_test() {
        assert!(check_output("test proof::is_bound ... FAILED\n").is_err());
    }

    #[test]
    fn accepts_repeated_consistent_successes() {
        assert!(check_output("test proof::is_bound ... ok\ntest proof::is_bound ... ok\n").is_ok());
    }

    #[test]
    fn refuses_success_followed_by_failure() {
        assert!(
            check_output("test proof::is_bound ... ok\ntest proof::is_bound ... FAILED\n").is_err()
        );
    }

    #[test]
    fn refuses_failure_followed_by_success() {
        assert!(
            check_output("test proof::is_bound ... FAILED\ntest proof::is_bound ... ok\n").is_err()
        );
    }

    #[test]
    fn refuses_success_followed_by_ignored() {
        assert!(
            check_output("test proof::is_bound ... ok\ntest proof::is_bound ... ignored\n")
                .is_err()
        );
    }
}
