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
//!
//! # The rustdoc is built here, under each checkout's own lock file
//!
//! `cargo semver-checks --baseline-root` builds the rustdoc JSON itself,
//! in a placeholder project of its own, and runs `cargo update` there
//! (upstream `data_generation/generate.rs`, "we have to run cargo update
//! inside the newly-generated project"). The checkout's `Cargo.lock` is
//! not consulted, so the comparison depended on whatever crates.io held
//! at that minute. Measured on 2026-09-03: `tinyvec 1.13.0` was published
//! at 21:13 UTC and does not compile (`cannot find macro vec`, upstream
//! issue 225); the semver run at 21:30 went red with an infrastructure
//! error while `Cargo.lock` still pinned `1.11.0` and every other job on
//! the same commit, all of them `--locked`, stayed green. The 19:47 run on
//! the previous commit had passed with the same source tree.
//!
//! Now the gate runs `cargo rustdoc --locked` inside each checkout, so the
//! lock file that every other gate builds against is the one compared
//! here too, and hands the two JSON files to `cargo semver-checks` with
//! `--current-rustdoc` / `--baseline-rustdoc`. A stale lock file is an
//! infrastructure error of this tree (fail-closed, as before), not a
//! reason to resolve afresh.

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
        || line.starts_with("error: failed to load rustdoc")
        || line.starts_with("error: no such command")
    {
        return true;
    }
    contains_error_code(line)
        || line.contains("failed to parse lock file")
        || line.contains("no matching package")
        || line.contains("cannot update the lock file")
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
        // so there is no such measure as a public API break. This is
        // not an infrastructure error but the first-PR scenario; let it pass.
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

    compare(&current, &baseline, &exc)
}

/// Build both rustdoc files and let cargo-semver-checks compare them.
fn compare(current: &Path, baseline: &Path, exc: &Path) -> Verdict {
    // Both rustdoc files are built here, each under its checkout's own
    // `Cargo.lock` (see the module doc for the measured reason). A build
    // failure is reported through the same classifier as before, so it is
    // an infrastructure error that no exception can mask.
    let current_json = match rustdoc_json(current) {
        Ok(path) => path,
        Err(report) => return classify_report(&report, exc),
    };
    let baseline_json = match rustdoc_json(baseline) {
        Ok(path) => path,
        Err(report) => return classify_report(&report, exc),
    };
    // Two checkouts that share a target directory (`CARGO_TARGET_DIR`, or a
    // `build.target-dir` in a config both read) write the same
    // `doc/<package>.json`: the baseline build overwrites the current one and
    // the tool compares the baseline with itself, so every removal passes.
    // That is an infrastructure error, not a verdict.
    if current_json == baseline_json {
        return Err(format!(
            "error: running cargo-doc wrote both rustdoc files to one path ({}); the \
             current and baseline checkouts share a target directory, so the comparison \
             would be of the baseline with itself. Give each checkout its own target \
             directory.",
            current_json.display()
        ));
    }

    // The shell ran `CARGO_TERM_COLOR=never cargo semver-checks
    // check-release -p budlum-core --baseline-root "$baseline"
    // --default-features` inside the current root, merging stdout and
    // stderr. The feature set is now fixed by the rustdoc build above (the
    // crate default: the all-features heuristic hits the pq-dilithium +
    // pq-ml-dsa compile_error! lock), and the two files are handed over.
    let output = match Command::new("cargo")
        .arg("semver-checks")
        .arg("check-release")
        .arg("--current-rustdoc")
        .arg(&current_json)
        .arg("--baseline-rustdoc")
        .arg(&baseline_json)
        .current_dir(current)
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
            "SEMVER GATE: PASS - no public API breakage (current versus the baseline).",
        ));
    }
    println!("::warning::cargo-semver-checks reported a breakage/error (exit={status}).");
    classify_report(&report, exc)
}

/// The flags cargo-semver-checks passes to rustdoc for its own builds
/// (upstream `EXTRA_RUSTDOCFLAGS`): the JSON format it reads, private and
/// hidden items included so lint queries can see them, lints capped so a
/// warning in the tree cannot turn into a build failure here.
const RUSTDOC_JSON_FLAGS: &str = "-Z unstable-options --output-format=json \
     --document-private-items --document-hidden-items --cap-lints=allow";

/// The package name in `root/Cargo.toml`: the first `name = "..."` line,
/// which in a root manifest belongs to `[package]`.
fn package_name(root: &Path) -> Result<String, String> {
    let manifest = root.join("Cargo.toml");
    let text = fs::read_to_string(&manifest).map_err(|e| {
        format!(
            "error: running cargo-metadata failed: {}: {e}",
            manifest.display()
        )
    })?;
    text.lines()
        .map(str::trim)
        .find_map(|line| {
            line.strip_prefix("name")
                .map(str::trim_start)
                .and_then(|rest| rest.strip_prefix('='))
                .map(str::trim)
                .and_then(|v| v.strip_prefix('"'))
                .and_then(|v| v.strip_suffix('"'))
                .map(str::to_string)
        })
        .ok_or_else(|| {
            format!(
                "error: running cargo-metadata failed: no package name in {}",
                manifest.display()
            )
        })
}

/// Build the root package's rustdoc JSON inside `root`, under its own
/// `Cargo.lock`, and return the file's path.
///
/// # Errors
///
/// Returns the build's combined output, prefixed with the same
/// `error: running cargo-doc` line cargo-semver-checks prints for its own
/// build failures, so `classify_report` files it as infrastructure.
fn rustdoc_json(root: &Path) -> Result<PathBuf, String> {
    let package = package_name(root)?;
    let output = Command::new("cargo")
        .arg("rustdoc")
        .arg("--locked")
        .arg("-p")
        .arg(&package)
        .arg("--lib")
        .arg("--")
        .args(RUSTDOC_JSON_FLAGS.split_whitespace())
        .current_dir(root)
        // `-Z` needs a nightly or the bootstrap switch; the CI pins a
        // nightly, a stable toolchain elsewhere goes through the switch,
        // exactly as cargo-semver-checks does for its own build.
        .env("RUSTC_BOOTSTRAP", "1")
        .env("CARGO_TERM_COLOR", "never")
        .output()
        .map_err(|e| format!("error: running cargo-doc failed to start: {e}"))?;
    let mut report = String::from_utf8_lossy(&output.stdout).into_owned();
    report.push_str(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err(format!(
            "error: running cargo-doc on crate '{package}' failed in {} (exit {}):\n{report}",
            root.display(),
            output.status.code().unwrap_or(1)
        ));
    }
    let json = target_dir(root)?
        .join("doc")
        .join(format!("{}.json", package.replace('-', "_")));
    if !json.is_file() {
        return Err(format!(
            "error: failed to build rustdoc for crate {package}: {} is missing after a \
             successful cargo rustdoc\n{report}",
            json.display()
        ));
    }
    Ok(json)
}

/// The target directory cargo uses for `root`, read from `cargo metadata`
/// so a `CARGO_TARGET_DIR` or `build.target-dir` setting is honoured.
fn target_dir(root: &Path) -> Result<PathBuf, String> {
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--locked")
        .arg("--no-deps")
        .arg("--format-version")
        .arg("1")
        .current_dir(root)
        .output()
        .map_err(|e| format!("error: running cargo-metadata failed to start: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "error: running cargo-metadata failed in {}:\n{}",
            root.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let meta: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("error: running cargo-metadata gave unreadable JSON: {e}"))?;
    meta.get("target_directory")
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| String::from("error: running cargo-metadata gave no target_directory"))
}

fn scratch_dir() -> Result<PathBuf, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-semver")?;
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
        // The two lines the in-tree rustdoc build adds: a lock file that
        // `--locked` refuses to rewrite, and a JSON file semver-checks
        // cannot read. Both mean "unknown", never "no breakage".
        "error: cannot update the lock file /x/Cargo.lock because --locked was passed",
        "error: failed to load rustdoc from file at `/x/budlum_core.json`",
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
    let unexpected = "something unexpected\n";
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

    // The in-tree rustdoc path, measured on a fixture pair rather than
    // trusted: a removed `pub fn` is reported as breakage, the same crate
    // against itself passes, and a manifest that disagrees with its lock
    // file is refused as infrastructure (the `--locked` promise). Skipped
    // only where the tool itself is absent, and the message says so.
    let live = if Command::new("cargo-semver-checks")
        .arg("--version")
        .output()
        .is_ok()
    {
        if let Err(e) = live_canaries(&tmp, &empty_exc) {
            let _ = fs::remove_dir_all(&tmp);
            return Err(e);
        }
        "; live: a removed pub fn FAILs, an identical crate PASSes, a stale lock is infra"
    } else {
        "; live pair skipped (cargo-semver-checks not installed here)"
    };

    let _ = fs::remove_dir_all(&tmp);
    Ok(format!(
        "canary OK: a crash is not masked, unrecognised output is fail-closed, a breakage \
         FAILs without an exception / PASSes with a justified one (the gate is not vacuous){live}.",
    ))
}

/// Write a one-file library crate with a matching lock file.
fn fixture_crate(dir: &Path, version: &str, body: &str) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"semver-canary\"\nversion = \"{version}\"\nedition = \"2021\"\n\n\
             [lib]\npath = \"lib.rs\"\n"
        ),
    )
    .map_err(|e| e.to_string())?;
    fs::write(dir.join("lib.rs"), body).map_err(|e| e.to_string())?;
    fs::write(
        dir.join("Cargo.lock"),
        format!(
            "# This file is automatically @generated by Cargo.\n# It is not intended for manual \
             editing.\nversion = 4\n\n[[package]]\nname = \"semver-canary\"\nversion = \"{version}\"\n"
        ),
    )
    .map_err(|e| e.to_string())
}

fn live_canaries(tmp: &Path, empty_exc: &Path) -> Result<(), String> {
    let base = tmp.join("base");
    let broken = tmp.join("broken");
    let stale = tmp.join("stale");
    fixture_crate(
        &base,
        "0.1.0",
        "pub fn kept() -> u32 { 1 }\npub fn removed() -> u32 { 2 }\n",
    )?;
    fixture_crate(&broken, "0.1.1", "pub fn kept() -> u32 { 1 }\n")?;
    fixture_crate(&stale, "0.1.0", "pub fn kept() -> u32 { 1 }\n")?;
    // The manifest moves on, the lock file does not: `--locked` must refuse.
    fs::write(
        stale.join("Cargo.toml"),
        "[package]\nname = \"semver-canary\"\nversion = \"0.2.0\"\nedition = \"2021\"\n\n\
         [lib]\npath = \"lib.rs\"\n",
    )
    .map_err(|e| e.to_string())?;

    let report = match compare(&broken, &base, empty_exc) {
        Ok(msg) => return Err(format!("live canary: a removed pub fn passed: {msg}")),
        Err(report) => report,
    };
    if !report.contains("public API breakage with no exception") {
        return Err(format!(
            "live canary: a removed pub fn was refused for the wrong reason: {report}"
        ));
    }
    if let Err(report) = compare(&base, &base, empty_exc) {
        return Err(format!(
            "live canary: a crate against itself failed: {report}"
        ));
    }
    match compare(&stale, &base, empty_exc) {
        Ok(msg) => Err(format!("live canary: a stale lock file passed: {msg}")),
        Err(report) if report.contains("INFRASTRUCTURE") => Ok(()),
        Err(report) => Err(format!(
            "live canary: a stale lock file was refused for the wrong reason: {report}"
        )),
    }
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
        fs::write(&empty, "# comment only\n").expect("fixture");
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
        fs::write(&empty, "# comment\n").expect("fixture");
        assert!(classify_report("something unexpected\n", &empty).is_err());
        let _ = fs::remove_dir_all(&d);
    }
}
