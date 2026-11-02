//! Line-coverage ratchet.
//!
//! Ported from `scripts/check-coverage.sh`. Reads a coverage report
//! (`coverage/cov.json`, llvm-cov JSON) and checks the line-coverage
//! percentage against `.github/coverage-baseline.txt`. The baseline may only
//! be raised in a deliberate PR; lowering it is a CI-softening violation.

use std::path::Path;

/// Parse a baseline value: a finite percentage from 0 to 100.
///
/// `parse::<f64>` also accepts `nan`, `inf` and `-5`; a `NaN` baseline makes
/// `pct < base` false for every report, which would turn the ratchet off.
fn parse_baseline(text: &str) -> Result<f64, String> {
    let v = text
        .trim_end_matches('%')
        .trim()
        .parse::<f64>()
        .map_err(|e| format!("the baseline is not a number: {e}"))?;
    if !v.is_finite() || !(0.0..=100.0).contains(&v) {
        return Err(format!(
            "the baseline {v} is not a percentage from 0 to 100"
        ));
    }
    Ok(v)
}

fn baseline(root: &Path) -> Result<f64, String> {
    let f = root.join(".github/coverage-baseline.txt");
    let text = std::fs::read_to_string(&f)
        .map_err(|e| format!("the baseline could not be read ({}): {e}", f.display()))?;
    // The file holds a plain float (`64.30`), as the shell gate's `float()`
    // read it; a trailing `%` is tolerated for hand-edited values.
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or_else(|| format!("the baseline could not be read ({})", f.display()))?;
    parse_baseline(line)
}

/// Pull the line-coverage percentage out of the llvm-cov JSON export:
/// `data[0].totals.lines.percent`. The export lists every file with its own
/// `summary.lines` before the `totals` object, so a text search for the first
/// `"lines":{` reads the first file, not the total.
fn percent_from_json(text: &str) -> Option<f64> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value
        .get("data")?
        .get(0)?
        .get("totals")?
        .get("lines")?
        .get("percent")?
        .as_f64()
}

/// # Errors
///
/// Returns a finding when the measured coverage is below the baseline.
pub fn run(root: &Path, report: &Path) -> Result<String, String> {
    if !report.is_file() {
        return Err(format!(
            "the coverage report is missing: {}",
            report.display()
        ));
    }
    let base = baseline(root)?;
    let text = std::fs::read_to_string(report).map_err(|e| e.to_string())?;
    let Some(pct) = percent_from_json(&text) else {
        return Err(format!(
            "the line-coverage percentage could not be read from the coverage report: {}",
            report.display()
        ));
    };
    if !pct.is_finite() {
        return Err(format!(
            "the measured coverage {pct} is not a finite number"
        ));
    }
    let msg = format!("coverage: lines {pct:.2}% | baseline: {base:.2}%");
    if pct < base {
        return Err(format!(
            "{msg}\nFAIL: line coverage is below the baseline (ratchet; lowering the baseline is a CI-loosening violation)."
        ));
    }
    Ok(format!(
        "{msg}\nOK: line coverage is at or above the baseline."
    ))
}

/// # Errors
///
/// Returns a finding when the percent parser misreads a known shape.
pub fn self_test() -> Result<String, String> {
    // The shape llvm-cov actually emits: totals.lines.percent, with a
    // functions block after it that must not win.
    let json = r#"{"data":[{"totals":{"lines":{"count":14493,"covered":9301,"percent":64.15},"functions":{"count":0,"percent":54.89}}}]}"#;
    let pct = percent_from_json(json).ok_or("canary: the percent could not be read")?;
    if (pct - 64.15).abs() > 1e-9 {
        return Err(format!("canary: read '{pct}' instead of 64.15"));
    }
    // The committed baseline is a plain float without `%`; the parser must
    // read it (the shell gate's `float()` did, and CI writes it that way).
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-cov")?;
    std::fs::create_dir_all(dir.join(".github")).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(".github/coverage-baseline.txt"), "64.30\n")
        .map_err(|e| e.to_string())?;
    let base =
        baseline(&dir).map_err(|e| format!("canary: the baseline could not be read: {e}"))?;
    if (base - 64.30).abs() > 1e-9 {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(format!(
            "canary: read '{base}' instead of the 64.30 baseline"
        ));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "coverage parse canary OK (64.15 was read correctly; the baseline was read as a float).",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_must_be_a_finite_percentage() {
        assert!(parse_baseline("nan").is_err());
        assert!(parse_baseline("inf").is_err());
        assert!(parse_baseline("-5").is_err());
        assert!(parse_baseline("100.5").is_err());
        assert_eq!(parse_baseline("64.30%"), Ok(64.30));
    }

    #[test]
    fn parses_percent() {
        let j = r#"{"data":[{"totals":{"lines":{"count":1,"percent":50.0}}}]}"#;
        assert_eq!(percent_from_json(j), Some(50.0));
    }

    #[test]
    fn picks_line_not_function() {
        let j = r#"{"data":[{"totals":{"lines":{"percent":12.5},"functions":{"percent":99.0}}}]}"#;
        assert_eq!(percent_from_json(j), Some(12.5));
    }
}

#[cfg(test)]
mod percent_tests {
    use super::percent_from_json;

    #[test]
    fn the_total_is_read_not_the_first_file() {
        let text = r#"{"data":[{"files":[{"filename":"a.rs","summary":{"lines":{"count":10,"covered":1,"percent":10.0}}}],"functions":[],"totals":{"lines":{"count":100,"covered":70,"percent":70.0},"functions":{"percent":5.0}}}],"type":"llvm.coverage.json.export"}"#;
        assert_eq!(percent_from_json(text), Some(70.0));
        assert_eq!(percent_from_json("not json"), None);
        assert_eq!(percent_from_json(r#"{"data":[]}"#), None);
    }
}
