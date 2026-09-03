//! clippy pedantic+nursery warning count ratchet.
//!
//! Ported from `scripts/check-clippy-extra.sh`. Reads a `cargo clippy
//! --message-format=json` stream and counts `clippy::*` warnings; the count
//! must not exceed the baseline in `.github/clippy-extra-baseline.txt`.
//!
//! The crate deliberately has no dependencies (a gate sits in the trust
//! boundary), so the JSON is parsed with a minimal line-level scanner rather
//! than `serde_json`: a `compiler-message` reason, a `warning` level and a
//! `clippy::` code on the same line. That is exactly the field triple the
//! shell gate's python counted, matched without pulling in a JSON parser.
//!
//! ## The ratchet has two directions
//!
//! `n > base` refuses new warnings. The other failure mode is silence: a
//! baseline that sits far above the measured count lets that many new warnings
//! in without CI noticing, and the ratchet has been observed to sit 5% high for
//! weeks while nobody looked. So a baseline more than [`STALL_SLACK_PERCENT`]
//! above the measured count is refused as well, with the instruction to lower it
//! to the number the current head actually measures. Lowering is only ever done
//! from a measured CI log, never from a local run: a local count depends on the
//! toolchain and the feature set of whoever ran it, and the baseline is a
//! property of the tree.

use std::path::Path;

/// How far above the measured count a baseline may sit before the gap itself is
/// the finding. Ten percent is wide enough that an in-flight cleanup (a branch
/// that removes warnings without touching the baseline) stays green, and narrow
/// enough that slack cannot accumulate silently over a month of pushes.
const STALL_SLACK_PERCENT: u64 = 10;

fn baseline(root: &Path) -> Result<u64, String> {
    let f = root.join(".github/clippy-extra-baseline.txt");
    let text = std::fs::read_to_string(&f)
        .map_err(|e| format!("the baseline could not be read ({}): {e}", f.display()))?;
    text.lines()
        .find(|l| l.chars().all(|c| c.is_ascii_digit()) && !l.is_empty())
        .ok_or_else(|| format!("the baseline could not be read ({})", f.display()))?
        .parse::<u64>()
        .map_err(|e| format!("the baseline is not a number: {e}"))
}

/// A `compiler-message` line carrying a `warning` level and a `clippy::`
/// code counts as one pedantic/nursery warning.
fn is_clippy_warning(line: &str) -> bool {
    // All three fields, grouped. Written without the parentheses this read
    // as `reason || (reason && level && code)`, so a bare `reason` counted:
    // every rustc note and error in the stream inflated the number.
    let compiler_message = line.contains("\"reason\":\"compiler-message\"")
        || line.contains("\"reason\": \"compiler-message\"");
    let warning = line.contains("\"level\":\"warning\"") || line.contains("\"level\": \"warning\"");
    compiler_message && warning && line.contains("clippy::")
}

fn count_json(path: &Path) -> Result<u64, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("the clippy JSON is missing/empty ({}): {e}", path.display()))?;
    Ok(text.lines().filter(|l| is_clippy_warning(l)).count() as u64)
}

/// # Errors
///
/// Returns a finding when the warning count exceeds the baseline.
pub fn run(root: &Path, json: &Path) -> Result<String, String> {
    if !json.is_file() {
        return Err(format!(
            "the clippy JSON is missing/empty: {}",
            json.display()
        ));
    }
    let base = baseline(root)?;
    let n = count_json(json)?;
    let msg = format!("clippy-extra: {n} | baseline: {base}");
    if n > base {
        return Err(format!(
            "{msg}\nFAIL: the pedantic/nursery warning count went over the baseline (+{}) - a new warning hit the ratchet.",
            n - base
        ));
    }
    let slack = n + n * STALL_SLACK_PERCENT / 100;
    if base > slack {
        return Err(format!(
            "{msg}\nFAIL: the baseline is {} above the measured count, more than the {}% a ratchet may be off by. Lower `.github/clippy-extra-baseline.txt` to {n}: an unlowered baseline is silent permission for that many new warnings.\n  Lower it from this run's number, and only from a number CI measured on the head being pushed.",
            base - n,
            STALL_SLACK_PERCENT
        ));
    }
    let slack = STALL_SLACK_PERCENT;
    Ok(format!(
        "{msg}\nOK: pedantic/nursery is at or below the baseline, and the baseline is within {slack}% of the measured count (the ratchet holds in both directions)."
    ))
}

/// # Errors
///
/// Returns a finding when the canary JSON does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-clippy")?;
    let _ = std::fs::create_dir_all(dir.join(".github"));
    std::fs::write(dir.join(".github/clippy-extra-baseline.txt"), "11\n")
        .map_err(|e| e.to_string())?;

    let mk = |n: u64, name: &str| -> Result<(), String> {
        let mut s = String::new();
        for _ in 0..n {
            s.push_str("{\"reason\":\"compiler-message\",\"message\":{\"level\":\"warning\",\"code\":{\"code\":\"clippy::x\"},\"rendered\":\"\"}}\n");
        }
        // Lines that carry the reason but not the level or not the code:
        // a rustc error, a rustc warning, a note. None of them is a
        // pedantic/nursery warning, and none of them may count.
        for _ in 0..n {
            s.push_str("{\"reason\":\"compiler-message\",\"message\":{\"level\":\"error\",\"code\":{\"code\":\"E0308\"},\"rendered\":\"\"}}\n");
            s.push_str("{\"reason\":\"compiler-message\",\"message\":{\"level\":\"warning\",\"code\":{\"code\":\"unused_variables\"},\"rendered\":\"\"}}\n");
            s.push_str("{\"reason\":\"compiler-message\",\"message\":{\"level\":\"note\",\"code\":null,\"rendered\":\"clippy::x\"}}\n");
        }
        std::fs::write(dir.join(name), s).map_err(|e| e.to_string())
    };
    // 10 against a baseline of 11: at or under, and inside the slack.
    mk(10, "few.json")?;
    mk(999, "many.json")?;
    // 2 against a baseline of 11: under, but 9 of slack is the finding.
    mk(2, "stale.json")?;

    let few_ok = run(&dir, &dir.join("few.json")).is_ok();
    let many_fail = run(&dir, &dir.join("many.json")).is_err();
    let stale_fail = run(&dir, &dir.join("stale.json")).is_err();
    let _ = std::fs::remove_dir_all(&dir);

    if !few_ok {
        return Err(String::from(
            "canary: 10 warnings against a baseline of 11 were refused",
        ));
    }
    if !many_fail {
        return Err(String::from("canary: 999 warnings passed the baseline"));
    }
    if !stale_fail {
        return Err(String::from(
            "canary: a baseline 9 above the measured count passed, so the slack alarm is inert",
        ));
    }
    Ok(String::from(
        "canary OK: over the baseline FAILs, within the slack PASSes, and a stale baseline FAILs (the gate is not vacuous in either direction).",
    ))
}
