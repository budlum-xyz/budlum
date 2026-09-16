//! A test named for a rejection must assert one.
//!
//! Ported from `scripts/check-rejection-tests-assert-rejection.sh`. A test
//! name is a claim, and it is the claim a reader trusts when counting
//! coverage rather than reading bodies. Three tests in this tree made a claim
//! their bodies contradicted (e.g. `pow_empty_block_rejected_by_validation`
//! asserted `result.is_some()`). This gate reads every `#[test]` whose name
//! promises a refusal and requires the body to contain a matching negative
//! assertion. It cannot tell whether the assertion is about the right thing,
//! but it catches the case where there is no negative assertion at all.
//!
//! The promise pattern is deliberately narrow and the evidence pattern
//! deliberately broad, exactly as the shell gate defined them: the promise
//! only matches names saying something was rejected/refused/denied or must
//! fail, and the evidence recognises every honest way to say "this did not
//! go through" (`is_err`, `assert!(!..)`, `should_panic`, a `Rejected` status, an
//! unchanged value, a cap, ...).

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

const SCAN_ROOTS: &[&str] = &["src", "budzero", "wallet-core"];

/// Substrings that make a function name promise a refusal (the shell
/// PROMISE regex, precomputed).
const PROMISE_PARTS: &[&str] = &[
    "_reject",
    "_rejects",
    "_rejected",
    "_refuse",
    "_refuses",
    "_refused",
    "_denied",
    "_denies",
    "_is_not_accepted",
    "_must_fail",
    "_must_be_refused",
    "_forbidden",
];

/// A line naming a function whose name promises a refusal.
fn promise_fn_name(line: &str) -> Option<&str> {
    let line = line.trim_start();
    if !line.starts_with("fn ") {
        return None;
    }
    let rest = &line[3..];
    let name_end = rest.find(|c: char| !c.is_ascii_alphanumeric() && c != '_')?;
    let name = &rest[..name_end];
    if !PROMISE_PARTS.iter().any(|p| name.contains(p)) {
        return None;
    }
    // `\s*\(` after the name.
    let after = &rest[name_end..];
    if !after.trim_start().starts_with('(') {
        return None;
    }
    Some(name)
}

/// The shell NEGATIVE regex, as a list of checks over the joined body.
fn has_negative(body: &str) -> bool {
    let b = body;
    // Result / Option refusals
    if b.contains("is_err()")
        || b.contains("is_err(")
        || b.contains("unwrap_err(")
        || b.contains("expect_err(")
        || b.contains("is_none()")
        || b.contains("Err(")
        || b.contains("Err (")
        || b.contains("matches!(") && (b.contains("Err") || b.contains("None"))
    {
        return true;
    }
    // Explicitly negated or inequality assertions. `assert!(!..)` may span
    // lines (`assert!(\n    !expr`), which the shell regex `assert!\s*\(\s*!`
    // tolerates via `\s`; `multiline_assert_bang` covers that shape.
    if b.contains("assert!(!")
        || b.contains("assert_ne!")
        || b.contains("debug_assert!(!")
        || multiline_assert_bang(b)
    {
        return true;
    }
    // Panic-based refusals
    if b.contains("should_panic") || b.contains("catch_unwind") || b.contains(".is_err") {
        return true;
    }
    // Status enums that name the refusal (word-ish boundaries)
    for w in [
        "Rejected",
        "Refused",
        "Denied",
        "Invalid",
        "Unauthorized",
        "Forbidden",
        "Expired",
        "NotAccepted",
        "Slashed",
        "Banned",
        "Failed",
    ] {
        if word_in(b, w) {
            return true;
        }
    }
    // "nothing happened": zero/empty/unchanged outcomes
    if b.contains(".is_empty()") || b.contains("is_banned(") || b.contains("is_jailed(") {
        return true;
    }
    // `assert_eq!(x, 0)`, `assert_eq!(x, false)`, `assert_eq!(x, None)`,
    // `assert_eq!(x, vec![])`, `assert_eq!(x, "")`: a zero/empty outcome is
    // the refusal. The shell regex is
    // `assert_eq!\s*\([^;]*?,\s*(?:0|false|None|vec!\[\]|"")\s*[,)]`, so the
    // value may sit on a later line; compare a whitespace-stripped tail.
    if let Some(pos) = b.find("assert_eq!(") {
        let tail = &b[pos..];
        let compact: String = tail.chars().filter(|c| !c.is_whitespace()).collect();
        for pat in [
            ",0,", ",0)", ",0);", ",false,", ",false)", ",None,", ",None)", ",vec![]", ",\"\"",
        ] {
            if compact.contains(pat) {
                return true;
            }
        }
    }
    // "nothing changed": snapshot before the attempt
    if b.contains("assert_eq!(")
        && ["before", "initial", "unchanged", "original", "prior"]
            .iter()
            .any(|k| b.contains(k))
    {
        return true;
    }
    // Policy locks and bound checks
    if b.contains("\"deny\"")
        || b.contains("stays_closed")
        || b.contains("must keep denying")
        || b.contains("cannot_exceed")
        || b.contains("_cap")
        || b.contains("saturat")
    {
        return true;
    }
    false
}

/// `assert!(\n    !expr`: the negation opens on a later line.
fn multiline_assert_bang(b: &str) -> bool {
    let mut rest = b;
    while let Some(pos) = rest.find("assert!(") {
        let after = &rest[pos + "assert!(".len()..];
        let first_nonspace = after.chars().find(|c| !c.is_whitespace());
        if first_nonspace == Some('!') {
            return true;
        }
        rest = after;
    }
    false
}

/// Word-boundary-ish contains: `w` surrounded by non-alphanumeric chars.
fn word_in(s: &str, w: &str) -> bool {
    let bytes = s.as_bytes();
    let wb = w.as_bytes();
    let mut i = 0;
    while i + wb.len() <= bytes.len() {
        if &bytes[i..i + wb.len()] == wb {
            let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            let after_ok =
                i + wb.len() == bytes.len() || !bytes[i + wb.len()].is_ascii_alphanumeric();
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Collect every `.rs` file under the scan roots.
fn rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for sub in SCAN_ROOTS {
        let base = root.join(sub);
        walk(&base, &mut out);
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let Ok(path_kind) = e.file_type() else {
            continue;
        };
        let path = e.path();
        if path_kind.is_dir() {
            if path
                .file_name()
                .is_some_and(|n| n == "target" || n == ".git")
            {
                continue;
            }
            walk(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// # Errors
///
/// Returns a finding when a rejection-named test asserts no refusal, or when
/// no rejection-named test exists at all (vacuous).
pub fn run(root: &Path) -> Result<String, String> {
    if !root.join("src").is_dir() {
        return Err(format!(
            "no src directory at {} - wrong root?",
            root.display()
        ));
    }
    let mut scanned = 0usize;
    let mut offenders: Vec<String> = Vec::new();

    for path in rs_files(root) {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
        for (i, line) in lines.iter().enumerate() {
            let Some(fn_name) = promise_fn_name(line) else {
                continue;
            };
            // Must be an actual test, not a helper or production function.
            let window_start = i.saturating_sub(6);
            let window = &lines[window_start..i];
            if !window.iter().any(|w| w.contains("#[test]")) {
                continue;
            }
            scanned += 1;

            // Body: from here to the next line that starts a sibling item at
            // the same or lower indentation.
            let indent = line.len() - line.trim_start().len();
            let mut body: Vec<&str> = Vec::new();
            for nxt in lines.iter().skip(i + 1) {
                let nxt = *nxt;
                if !nxt.trim().is_empty() && (nxt.len() - nxt.trim_start().len()) <= indent {
                    let t = nxt.trim_start();
                    if t.starts_with("fn ") || t.starts_with("#[") || t.starts_with('}') {
                        break;
                    }
                }
                body.push(nxt);
            }
            if !has_negative(&body.join("\n")) {
                offenders.push(format!("{rel}:{}  {fn_name}", i + 1));
            }
        }
    }

    if scanned == 0 {
        return Err(String::from(
            "no test named for a rejection was found at all - the gate would be vacuous",
        ));
    }

    if !offenders.is_empty() {
        let mut msg = String::from("these tests are named for a rejection but assert none:\n");
        for o in &offenders {
            writeln!(msg, "  - {o}").expect("writing to a String cannot fail");
        }
        msg.push_str(
            "\nA name is the claim a reader trusts when counting coverage. Either assert the\n\
             refusal (is_err / unwrap_err / assert!(!..) / should_panic), or rename the test\n\
             to what it actually checks.",
        );
        return Err(msg);
    }

    Ok(format!(
        "Rejection-test gate OK: all {scanned} tests named for a refusal assert one."
    ))
}

/// Build a fixture crate with the given lib.rs lines.
fn mk_fixture(base: &Path, name: &str, lines: &[&str]) -> Result<PathBuf, String> {
    let dir = base.join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src")).map_err(|e| e.to_string())?;
    let content = lines.join("\n");
    fs::write(dir.join("src/lib.rs"), content).map_err(|e| e.to_string())?;
    Ok(dir)
}

/// Canary fixtures (mirror the shell gate's seven).
const LIAR: &[&str] = &[
    "#[test]",
    "fn pow_empty_block_rejected_by_validation() {",
    "    let result = produce();",
    "    assert!(result.is_some(), \"must succeed\");",
    "}",
];
const REFUSES: &[&str] = &[
    "#[test]",
    "fn the_chain_refuses_a_short_fork() {",
    "    assert_eq!(chain.len(), 3);",
    "}",
];
const NONE: &[&str] = &[
    "#[test]",
    "fn a_block_is_produced() {",
    "    assert!(true);",
    "}",
];
const GOOD: &[&str] = &[
    "#[test]",
    "fn import_rejects_an_empty_set() {",
    "    let result = import(empty());",
    "    assert!(result.is_err(), \"must be refused\");",
    "}",
];
const NOTATEST: &[&str] = &[
    "fn rejects_everything() -> bool { false }",
    "#[test]",
    "fn import_rejects_an_empty_set() {",
    "    assert!(import(empty()).is_err());",
    "}",
];
const BANG: &[&str] = &[
    "#[test]",
    "fn onboarding_rejects_below_floor_as_active() {",
    "    assert!(!registry.is_active(&staker), \"below floor must not be active\");",
    "}",
];

/// A fresh scratch directory for a self-test run.
fn scratch_dir() -> Result<PathBuf, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-rejection")?;
    Ok(dir)
}

/// Assert that a run failed, naming the canary on failure.
fn expect_fail(out: &Result<String, String>, msg: &str) -> Result<(), String> {
    if out.is_ok() {
        Err(msg.to_string())
    } else {
        Ok(())
    }
}

/// Assert that a run passed, naming the canary on failure.
fn expect_ok(out: &Result<String, String>, msg: &str) -> Result<(), String> {
    if out.is_err() {
        Err(msg.to_string())
    } else {
        Ok(())
    }
}

/// # Errors
///
/// Returns the first canary that misbehaves. The canaries mirror the shell
/// gate's seven one for one.
pub fn self_test() -> Result<String, String> {
    let tmp = scratch_dir()?;

    // 1. A name promising rejection over a body asserting success must fail.
    let liar = mk_fixture(&tmp, "liar", LIAR)?;
    expect_fail(
        &run(&liar),
        "canary: a test named _rejected asserting is_some() was accepted",
    )?;

    // 2. `_refuses` with a purely positive body must also fail.
    let refuses = mk_fixture(&tmp, "refuses", REFUSES)?;
    expect_fail(
        &run(&refuses),
        "canary: a _refuses test with no negative assertion was accepted",
    )?;

    // 3. A tree with no such tests must fail (vacuous).
    let none = mk_fixture(&tmp, "none", NONE)?;
    expect_fail(
        &run(&none),
        "canary: a tree with no rejection tests at all was accepted",
    )?;

    // 4. A missing src must fail.
    let empty = tmp.join("empty");
    let _ = fs::remove_dir_all(&empty);
    fs::create_dir_all(&empty).map_err(|e| e.to_string())?;
    expect_fail(
        &run(&empty),
        "canary: a tree with no src directory was accepted",
    )?;

    // 5. A properly asserted rejection must pass.
    let good = mk_fixture(&tmp, "good", GOOD)?;
    expect_ok(
        &run(&good),
        "canary: a test that does assert its rejection was rejected",
    )?;

    // 6. A non-test function whose name mentions rejection is not a test.
    let notatest = mk_fixture(&tmp, "notatest", NOTATEST)?;
    expect_ok(
        &run(&notatest),
        "canary: a plain function was treated as a test",
    )?;

    // 7. assert!(!..) counts as a negative assertion.
    let bang = mk_fixture(&tmp, "bang", BANG)?;
    expect_ok(
        &run(&bang),
        "canary: assert!(!..) was not recognised as asserting a refusal",
    )?;

    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "rejection-test gate self-test OK: a _rejected test asserting success, a _refuses test \
         with no negative assertion, a tree with no rejection tests and a missing src are all \
         rejected; is_err and assert!(!..) pass and a plain function is ignored.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promise_parts_match() {
        assert_eq!(
            promise_fn_name("fn pow_empty_block_rejected_by_validation() {"),
            Some("pow_empty_block_rejected_by_validation")
        );
        assert_eq!(
            promise_fn_name("fn the_chain_refuses_a_short_fork() {"),
            Some("the_chain_refuses_a_short_fork")
        );
        assert_eq!(promise_fn_name("fn a_block_is_produced() {"), None);
        // `rejects_everything` has no underscore prefix, so it is not a
        // promise in the shell gate's sense either.
        assert_eq!(
            promise_fn_name("    fn rejects_everything() -> bool { false }"),
            None
        );
    }

    #[test]
    fn negative_detection() {
        assert!(has_negative("assert!(result.is_err());"));
        assert!(has_negative("assert!(!registry.is_active(&s));"));
        assert!(has_negative("assert_eq!(result, Err(Error::Rejected));"));
        assert!(has_negative("matches!(r, Err(_))"));
        assert!(has_negative("assert_eq!(score, 0);"));
        assert!(!has_negative("assert_eq!(chain.len(), 3);"));
        assert!(!has_negative("let x = 1;"));
    }
}
