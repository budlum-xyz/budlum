//! cargo-vet unvetted-dependency count ratchet.
//!
//! Ported from `scripts/check-cargo-vet.sh`. Runs `cargo vet check`, reads the
//! `<N> unvetted dependencies` count from its output, and fails when the
//! count exceeds `.github/cargo-vet-baseline.txt`. The count may fall (the
//! baseline is tightened in a deliberate PR), never rise.

use std::path::Path;

fn baseline(root: &Path) -> Result<u64, String> {
    let f = root.join(".github/cargo-vet-baseline.txt");
    let text = std::fs::read_to_string(&f)
        .map_err(|e| format!("the baseline could not be read ({}): {e}", f.display()))?;
    text.lines()
        .find(|l| l.chars().all(|c| c.is_ascii_digit()) && !l.is_empty())
        .ok_or_else(|| format!("the baseline could not be read ({})", f.display()))?
        .parse::<u64>()
        .map_err(|e| format!("the baseline is not a number: {e}"))
}

fn count_from_output(out: &str) -> Option<u64> {
    out.lines().find_map(|l| {
        let t = l.trim_start();
        // The count is the leading run of digits.
        let digits: String = t.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        let rest = &t[digits.len()..];
        if rest.starts_with(" unvetted dependencies") {
            digits.parse().ok()
        } else {
            None
        }
    })
}

/// `cargo vet` prints this exact line when nothing is unvetted, and prints no
/// count at all. That is the only shape allowed to mean zero: any other
/// countless output is an unfinished scan, not a clean one.
fn is_clean_report(out: &str) -> bool {
    out.lines().any(|l| l.trim() == "Vetting Succeeded!")
}

/// Run `cargo vet check` in the repo root and return its stdout/stderr.
///
/// A spawn failure is an error, not text. The previous shape turned
/// "cargo vet did not run: ..." into a normal report string, which then parsed
/// as zero unvetted dependencies and passed the gate. A gate that reports
/// clean when its scanner never ran proves nothing.
fn run_vet(root: &Path) -> Result<String, String> {
    let out = std::process::Command::new("cargo")
        .args(["vet", "check"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cargo vet did not run: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
}

/// `cargo-vet` is a separate binary, and Repo Lint does not install it.
///
/// Cargo answers a missing subcommand with "no such command: vet". That is
/// not an unfinished scan, it is *no* scan: the gate has nothing to judge and
/// no evidence that anything is wrong. Treating it as a finding made the
/// dedicated Cargo Vet job the second place this gate ran, and the only place
/// it could pass - so Repo Lint failed on every push for a tool it never
/// installs.
///
/// The distinction that matters: a *missing tool* is skipped, a tool that
/// *ran and produced an unreadable report* is still a hard failure. The
/// second case is the fail-open hole this gate exists to close.
fn tool_is_absent(out: &str) -> bool {
    out.lines()
        .any(|l| l.contains("no such command") && l.contains("vet"))
}

/// # Errors
///
/// Returns a finding when the unvetted count exceeds the baseline.
pub fn run(root: &Path) -> Result<String, String> {
    let base = baseline(root)?;
    let output = run_vet(root)?;
    if tool_is_absent(&output) {
        return Ok(String::from(
            "SKIPPED: cargo-vet is not installed on this job; the ratchet decision\n\
             is made by the separate `Cargo Vet` job (cargo-vet.yml). The absence\n\
             of the tool is not a finding - the tool running and producing an\n\
             unreadable report is still a hard error.",
        ));
    }
    let n = match count_from_output(&output) {
        Some(n) => n,
        None if is_clean_report(&output) => 0,
        None => {
            return Err(format!(
                "the cargo-vet output contains neither an unvetted dependency\n\
                 count nor a 'Vetting Succeeded!' line; the scan is treated as\n\
                 incomplete and the gate does not accept it as clean:\n{output}"
            ));
        }
    };
    let msg = format!("cargo-vet unvetted dependencies: {n} | baseline: {base}");
    if n > base {
        return Err(format!(
            "{msg}\nFAIL: the unvetted dependency count went over the baseline (+{}).\n      If a new dependency was added: either a trusted import source must\n      cover it, or a justified audit entry must be recorded with\n      `cargo vet certify`. RAISING the baseline is not a fix.",
            n - base
        ));
    }
    if n < base {
        return Ok(format!(
            "{msg}\nIMPROVEMENT: the baseline can be lowered {base} -> {n}.\n          Set .github/cargo-vet-baseline.txt to {n} (the ratchet tightens).\n\nOK: unvetted dependencies are at or below the baseline (the ratchet holds)."
        ));
    }
    Ok(format!(
        "{msg}\nOK: unvetted dependencies are at or below the baseline (the ratchet holds)."
    ))
}

/// # Errors
///
/// Returns a finding when the output parser misreads a known shape.
pub fn self_test() -> Result<String, String> {
    let got = count_from_output(
        "Vetting Failed!\n\n123 unvetted dependencies:\n  aead:0.5.2 missing [\"safe-to-deploy\"]",
    );
    if got != Some(123) {
        return Err(format!(
            "canary: the counter read '{got:?}' instead of 123 (parsing is broken)"
        ));
    }
    // A missing tool and an unreadable report must not be conflated: the first is skipped,
    // the second breaks the gate. The canary pins that distinction.
    if !tool_is_absent("error: no such command: `vet`") {
        return Err(String::from(
            "canary: a missing cargo-vet binary was not recognised (the skip arm is dead)",
        ));
    }
    if tool_is_absent("Vetting Failed!\n\n7 unvetted dependencies:") {
        return Err(String::from(
            "canary: a real vet report was mistaken for 'no tool' (the gate is fail-open)",
        ));
    }
    let clean = "Vetting Succeeded!";
    if count_from_output(clean).is_some() || !is_clean_report(clean) {
        return Err(String::from(
            "canary: 'Vetting Succeeded!' was not recognised as a clean report",
        ));
    }
    // A scanner that died before saying anything must not read as zero. This
    // is the shape the gate used to accept.
    let broken = "error: no such subcommand: `vet`";
    if count_from_output(broken).is_some() || is_clean_report(broken) {
        return Err(String::from(
            "canary: broken scanner output was read as clean/0 (fail-open)",
        ));
    }
    Ok(String::from(
        "Canary OK: 123 was counted, a clean report was recognised, broken output was refused.",
    ))
}
