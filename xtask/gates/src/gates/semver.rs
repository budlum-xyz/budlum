//! Public API breakage gate for budlum-core, via cargo-semver-checks.
//!
//! Ported from `scripts/check-semver.sh`. The gate compares a current
//! checkout against a baseline root:
//!
//!   * `cargo semver-checks` exits 0 -> PASS (no public API breakage).
//!   * exit != 0 (a breakage report OR an infrastructure failure) ->
//!     `.github/semver-exceptions.txt` is consulted. A comment-only file
//!     means FAIL; a file with at least one justified, user-approved entry
//!     means PASS-EXCEPTION. Infrastructure crashes are never masked by an
//!     exception: a crash means "unknown", not "no breakage", so those are
//!     fail-closed (the same rule the shell gate enforced).
//!
//! The port keeps the shell gate's two-root call shape, its ANSI stripping
//! (colour codes would split the "error:" regexes), its 240-line report
//! excerpt, its infra/breakage classification and every canary.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The classification is a pass/fail verdict over a plaintext report.
type Verdict = Result<String, String>;

/// Strip ANSI CSI sequences, matching `sed 's/\x1b\[[0-9;]*[A-Za-z]//g'`.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find('\u{1b}') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let consumed = after.strip_prefix('[').and_then(|tail| {
            let mut idx = 0usize;
            while let Some(ch) = tail[idx..].chars().next() {
                if ch.is_ascii_digit() || ch == ';' {
                    idx += ch.len_utf8();
                } else {
                    break;
                }
            }
            let letter = tail[idx..].chars().next()?;
            letter
                .is_ascii_alphabetic()
                .then_some(1 + idx + letter.len_utf8())
        });
        if let Some(len) = consumed {
            rest = &after[len..];
        } else {
            out.push('\u{1b}');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// `error[E<digits>]` anywhere in the line, byte-safe.
fn contains_error_code(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx..].starts_with(b"error[E") {
            let mut j = idx + "error[E".len();
            let mut digits = 0usize;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
                digits += 1;
            }
            if digits > 0 && j < bytes.len() && bytes[j] == b']' {
                return true;
            }
            idx = j;
        } else {
            idx += 1;
        }
    }
    false
}

/// The infra class: the tool died without answering, so an exception can
/// never apply. Mirrors `SEMVER_INFRA_PATTERN`.
fn line_is_infra(line: &str) -> bool {
    if line.starts_with("error: running cargo-doc")
        || line.starts_with("error: running cargo-metadata")
        || line.starts_with("error: could not compile")
        || line.starts_with("error: could not document")
        || line.starts_with("error: failed to build rustdoc")
        || line.starts_with("error: no such command")
    {
        return true;
    }
    contains_error_code(line)
        || line.contains("failed to parse lock file")
        || line.contains("no matching package")
}

/// The breakage class: a real report naming a removed or changed API.
fn line_is_breakage(line: &str) -> bool {
    line.starts_with("--- failure")
        || line.starts_with("--- warning")
        || line.contains("requires new major version")
        || line.contains("requires new minor version")
}

/// Does the exceptions file carry at least one non-comment, non-blank line?
fn has_justified_entries(path: &Path) -> Result<Vec<String>, String> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let content =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(content
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .map(str::to_string)
        .collect())
}

/// Classification: report text + exceptions file -> verdict.
///
/// 0 = pass, 1 = reject, carried as `Ok`/`Err` so the gate can be called from
/// a test without a process exit. The canaries run this directly, which is
/// what the shell gate's `--self-test` did with `classify_semver_report`.
fn classify_report(report: &str, exc: &Path) -> Verdict {
    let stripped = strip_ansi(report);
    let lines: Vec<&str> = stripped.lines().collect();

    if lines.iter().any(|line| line_is_infra(line)) {
        return Err(String::from(
            "SEMVER GATE: FAIL - the tool ended inconclusive with an INFRASTRUCTURE \
             error (a crash is not a breakage; no exception applies).\n\
             The exception mechanism applies only to real breakage reports.",
        ));
    }
    if !lines.iter().any(|line| line_is_breakage(line)) {
        return Err(String::from(
            "SEMVER GATE: FAIL - the output is neither a breakage report nor a known \
             infrastructure error (fail-closed classification).",
        ));
    }
    let entries = has_justified_entries(exc)?;
    if !entries.is_empty() {
        let mut msg = String::from(
            "SEMVER GATE: PASS-EXCEPTION - .github/semver-exceptions.txt contains a \
             justified acceptance:\n",
        );
        for entry in entries {
            msg.push_str("  ISTISNA: ");
            msg.push_str(&entry);
            msg.push('\n');
        }
        return Ok(msg);
    }

    Err(String::from(
        "SEMVER GATE: FAIL - a public API breakage with no exception.\n\
         Options: (a) revert the breakage, (b) if MAJOR/MINOR is intended and \
         approved, add a justified line to .github/semver-exceptions.txt.",
    ))
}

/// # Errors
///
/// Returns a finding when `cargo semver-checks` reports breakage without a
/// justified exception, or crashes, or the classification is unrecognised.
pub fn run_args(root: &Path, args: &[&str]) -> Verdict {
    let (current_s, baseline_s) = match args {
        [current, baseline] => (*current, *baseline),
        _ => {
            return Err(String::from("usage: semver <current-root> <baseline-root>"));
        }
    };

    // Absolute-path canonicalisation, exactly like `cd "$1" && pwd`: the gate
    // changes directory into the current root, so a relative baseline would
    // otherwise resolve against the wrong place.
    let Ok(current) = fs::canonicalize(current_s) else {
        return Err(format!("current root yok: {current_s}"));
    };
    let Ok(baseline) = fs::canonicalize(baseline_s) else {
        return Err(format!("baseline root yok: {baseline_s}"));
    };
    if !current.join("Cargo.toml").is_file() {
        return Err(format!(
            "current root without Cargo.toml: {}",
            current.display()
        ));
    }
    if !baseline.join("Cargo.toml").is_file() {
        // First release / empty baseline: there is no previous version to compare against,
        // dolayisiyla public API kirilmasi diye bir olcu yoktur. Bu bir
        // this is not an infrastructure error but the first-PR scenario; let it pass.
        return Ok(String::from(
            "SEMVER GATE: PASS - the baseline is empty (first release), no comparison.",
        ));
    }

    // The shell gate refused to run without the tool installed; keep that
    // early, explicit failure.
    if Command::new("cargo-semver-checks")
        .arg("--version")
        .output()
        .is_err()
    {
        return Err(String::from(
            "cargo-semver-checks not installed (cargo install cargo-semver-checks --locked)",
        ));
    }

    // The exceptions file belongs to the checkout under test; fall back to
    // the gate's own tree when the current root predates it.
    let mut exc = current.join(".github/semver-exceptions.txt");
    if !exc.is_file() {
        exc = root.join(".github/semver-exceptions.txt");
    }

    // The shell ran `CARGO_TERM_COLOR=never cargo semver-checks
    // check-release -p budlum-core --baseline-root "$baseline"
    // --default-features` inside the current root, merging stdout and stderr.
    // `--default-features` is load-bearing: the all-features heuristic hits
    // the pq-dilithium + pq-ml-dsa compile_error! lock, so the gate runs the
    // crate-defined default set.
    let output = match Command::new("cargo")
        .arg("semver-checks")
        .arg("check-release")
        .arg("-p")
        .arg("budlum-core")
        .arg("--baseline-root")
        .arg(&baseline)
        .arg("--default-features")
        .current_dir(&current)
        .env("CARGO_TERM_COLOR", "never")
        .output()
    {
        Ok(output) => output,
        Err(e) => return Err(format!("cannot run cargo semver-checks: {e}")),
    };
    let status = output.status.code().unwrap_or(1);
    let mut report = String::from_utf8_lossy(&output.stdout).into_owned();
    report.push_str(&String::from_utf8_lossy(&output.stderr));
    let report = strip_ansi(&report);

    // The shell gate printed the first 240 lines of the report regardless of
    // the verdict; keep that so the step's log shows what was compared.
    for line in report.lines().take(240) {
        println!("{line}");
    }

    if status == 0 {
        return Ok(String::from(
            "SEMVER GATE: PASS - no public API breakage (budlum-core versus the baseline).",
        ));
    }
    println!("::warning::cargo-semver-checks reported a breakage/error (exit={status}).");
    classify_report(&report, &exc)
}

fn scratch_dir() -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-semver-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create scratch dir: {e}"))?;
    Ok(dir)
}

/// # Errors
///
/// Returns the first canary that misbehaves. The canaries mirror the shell
/// gate's: the exceptions file is present and well-formed, an infrastructure
/// crash is never masked by an exception, unrecognised output is fail-closed,
/// breakage without an exception fails, and breakage with a justified
/// exception passes.
pub fn self_test() -> Result<String, String> {
    let root = std::env::var_os("BUDLUM_ROOT").map_or_else(
        || std::env::current_dir().unwrap_or_default(),
        PathBuf::from,
    );
    let real_exc = root.join(".github/semver-exceptions.txt");
    if !real_exc.is_file() {
        return Err(String::from(
            "self-test: missing .github/semver-exceptions.txt",
        ));
    }
    let content = fs::read_to_string(&real_exc).map_err(|e| e.to_string())?;
    if !content.contains("SEMVER EXCEPTIONS") {
        return Err(String::from("self-test: exceptions header missing"));
    }
    if !content.to_lowercase().contains("approval evidence") {
        return Err(String::from("self-test: exceptions policy line missing"));
    }

    let tmp = scratch_dir()?;
    let empty_exc = tmp.join("none");
    let filled_exc = tmp.join("some");
    fs::write(&empty_exc, "# comment\n\n").map_err(|e| e.to_string())?;
    fs::write(&filled_exc, "BDLM-1: a known breakage, approved\n").map_err(|e| e.to_string())?;

    // An infra crash must be rejected even when the exceptions file is full:
    // a crash says "unknown", not "no breakage". Each case carries a real
    // breakage line beside it so the infra pattern is what the canary pins.
    let infra_cases = [
        "error: could not document `budlum-core`",
        "error[E0432]: unresolved import",
        "error: running cargo-metadata failed",
        "error: failed to build rustdoc",
        "error: no such command: `semver-checks`",
    ];
    for case in infra_cases {
        let report = format!("{case}\n--- failure struct_missing: pub struct removed\n");
        if classify_report(&report, &filled_exc).is_ok() {
            let _ = fs::remove_dir_all(&tmp);
            return Err(format!(
                "self-test: an infrastructure error was masked by an exception: {case}"
            ));
        }
    }

    // Unrecognised output: neither a breakage report nor a known crash, so
    // fail-closed.
    let unexpected = "beklenmedik bir sey\n";
    if classify_report(unexpected, &empty_exc).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "self-test: unclassifiable output was let through (not fail-closed)",
        ));
    }

    // A real breakage without an exception must be rejected.
    let breaking = "--- failure struct_missing: pub struct removed\n";
    if classify_report(breaking, &empty_exc).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "self-test: a breakage with no exception was let through",
        ));
    }

    // A real breakage with a justified exception must pass; without this the
    // gate would reject everything and the four checks above would pass for
    // free.
    if classify_report(breaking, &filled_exc).is_err() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "self-test: a justified exception was not accepted (the gate refuses everything)",
        ));
    }

    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "canary OK: a crash is not masked, unrecognised output is fail-closed, a breakage \
         FAILs without an exception / PASSes with a justified one (the gate is not vacuous).",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        scratch_dir().expect("scratch dir")
    }

    #[test]
    fn ansi_sequences_are_stripped() {
        assert_eq!(strip_ansi("\u{1b}[31mred\u{1b}[0m"), "red");
        assert_eq!(strip_ansi("\u{1b}[1;31m bold \u{1b}[m"), " bold ");
        assert_eq!(strip_ansi("plain text"), "plain text");
        assert_eq!(strip_ansi("\u{1b}[31m"), "");
    }

    #[test]
    fn infra_is_never_masked() {
        let d = scratch();
        let exc = d.join("some");
        fs::write(&exc, "BDLM-1: onayli\n").expect("fixture");
        for case in [
            "error: could not document `budlum-core`",
            "error[E0432]: unresolved import",
            "error: running cargo-metadata failed",
        ] {
            let report = format!("{case}\n--- failure struct_missing: x\n");
            assert!(classify_report(&report, &exc).is_err(), "{case}");
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn breakage_with_and_without_exception() {
        let d = scratch();
        let empty = d.join("empty");
        let filled = d.join("filled");
        fs::write(&empty, "# sadece yorum\n").expect("fixture");
        fs::write(&filled, "method_missing: X | justification | approval\n").expect("fixture");
        let breaking = "--- failure struct_missing: pub struct removed\n";
        assert!(classify_report(breaking, &empty).is_err());
        assert!(classify_report(breaking, &filled).is_ok());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn unrecognised_output_is_fail_closed() {
        let d = scratch();
        let empty = d.join("empty");
        fs::write(&empty, "# yorum\n").expect("fixture");
        assert!(classify_report("beklenmedik bir sey\n", &empty).is_err());
        let _ = fs::remove_dir_all(&d);
    }
}
