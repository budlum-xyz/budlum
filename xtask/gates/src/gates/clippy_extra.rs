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

use std::path::Path;

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
    line.contains("\"reason\":\"compiler-message\"")
        || line.contains("\"reason\": \"compiler-message\"")
            && (line.contains("\"level\":\"warning\"") || line.contains("\"level\": \"warning\""))
            && line.contains("clippy::")
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
    Ok(format!(
        "{msg}\nOK: pedantic/nursery is at or below the baseline (the ratchet holds)."
    ))
}

/// # Errors
///
/// Returns a finding when the canary JSON does not behave.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-clippy-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::create_dir_all(dir.join(".github"));
    std::fs::write(dir.join(".github/clippy-extra-baseline.txt"), "100\n")
        .map_err(|e| e.to_string())?;

    let mk = |n: u64, name: &str| -> Result<(), String> {
        let mut s = String::new();
        for _ in 0..n {
            s.push_str("{\"reason\":\"compiler-message\",\"message\":{\"level\":\"warning\",\"code\":{\"code\":\"clippy::x\"},\"rendered\":\"\"}}\n");
        }
        std::fs::write(dir.join(name), s).map_err(|e| e.to_string())
    };
    mk(2, "few.json")?;
    mk(999, "many.json")?;

    let few_ok = run(&dir, &dir.join("few.json")).is_ok();
    let many_fail = run(&dir, &dir.join("many.json")).is_err();
    let _ = std::fs::remove_dir_all(&dir);

    if !few_ok {
        return Err(String::from("canary: 2 warnings were refused"));
    }
    if !many_fail {
        return Err(String::from("canary: 999 warnings passed the baseline"));
    }
    Ok(String::from(
        "canary OK: over the baseline FAILs, under it PASSes (the gate is not vacuous).",
    ))
}
