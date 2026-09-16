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
/// `tests::bns::tests::test_bns_registration_and_resolution`).
pub fn check_exact_log(log: &Path, tests: &[&str], subject: &str) -> Result<String, String> {
    if !log.is_file() {
        return Err(format!(
            "the test output is missing/empty: {}",
            log.display()
        ));
    }
    let content = fs::read_to_string(log).map_err(|e| e.to_string())?;
    let mut missing: Vec<String> = Vec::new();
    for name in tests {
        let needle = format!("test {name} ... ok");
        if !content.lines().any(|l| l.trim_end() == needle) {
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
    Ok(format!(
        "canary OK: complete -> PASS, missing/FAILED -> FAIL ({subject})."
    ))
}
