//! Line-coverage ratchet.
//!
//! Ported from `scripts/check-coverage.sh`. Reads a coverage report
//! (`coverage/cov.json`, llvm-cov JSON) and checks the line-coverage
//! percentage against `.github/coverage-baseline.txt`. The baseline may only
//! be raised in a deliberate PR; lowering it is a CI-softening violation.

use std::path::Path;

fn baseline(root: &Path) -> Result<f64, String> {
    let f = root.join(".github/coverage-baseline.txt");
    let text = std::fs::read_to_string(&f)
        .map_err(|e| format!("baseline okunamadı ({}): {e}", f.display()))?;
    // The file holds a plain float (`64.30`), as the shell gate's `float()`
    // read it; a trailing `%` is tolerated for hand-edited values.
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or_else(|| format!("baseline okunamadı ({})", f.display()))?
        .trim_end_matches('%')
        .trim()
        .parse::<f64>()
        .map_err(|e| format!("baseline sayı değil: {e}"))
}

/// Pull the line-coverage percentage out of llvm-cov JSON without a JSON
/// dependency. The shell gate's python read `data[0]["totals"]["lines"]
/// ["percent"]`; llvm-cov's summary block is `"totals":{"lines":{...},
/// "functions":{...},...}`, so find the `"lines":{` fragment and read the
/// first `"percent":` value inside it (a trailing `"functions"` block also
/// carries a `"percent"` that must not be picked).
fn percent_from_json(text: &str) -> Option<f64> {
    let lines_block = text.find("\"lines\":{")?;
    let block = &text[lines_block..];
    let pct_pos = block.find("\"percent\":")?;
    let after = &block[pct_pos + "\"percent\":".len()..];
    let num: String = after
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();
    num.parse().ok()
}

/// # Errors
///
/// Returns a finding when the measured coverage is below the baseline.
pub fn run(root: &Path, report: &Path) -> Result<String, String> {
    if !report.is_file() {
        return Err(format!("coverage raporu yok: {}", report.display()));
    }
    let base = baseline(root)?;
    let text = std::fs::read_to_string(report).map_err(|e| e.to_string())?;
    let Some(pct) = percent_from_json(&text) else {
        return Err(format!(
            "coverage raporundan line-coverage yüzdesi okunamadı: {}",
            report.display()
        ));
    };
    let msg = format!("coverage: lines {pct:.2}% | baseline: {base:.2}%");
    if pct < base {
        return Err(format!(
            "{msg}\nFAIL: line coverage baseline'ın altında (ratchet; baseline'ı düşürmek CI gevşetme ihlalidir)."
        ));
    }
    Ok(format!("{msg}\nOK: line coverage baseline üstünde/eşit."))
}

/// # Errors
///
/// Returns a finding when the percent parser misreads a known shape.
pub fn self_test() -> Result<String, String> {
    // The shape llvm-cov actually emits: totals.lines.percent, with a
    // functions block after it that must not win.
    let json = r#"{"data":[{"totals":{"lines":{"count":14493,"covered":9301,"percent":64.15},"functions":{"count":0,"percent":54.89}}}]}"#;
    let pct = percent_from_json(json).ok_or("canary: percent okunamadı")?;
    if (pct - 64.15).abs() > 1e-9 {
        return Err(format!("canary: 64.15 yerine '{pct}' okundu"));
    }
    // The committed baseline is a plain float without `%`; the parser must
    // read it (the shell gate's `float()` did, and CI writes it that way).
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!("budlum-gates-cov-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(dir.join(".github")).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(".github/coverage-baseline.txt"), "64.30\n")
        .map_err(|e| e.to_string())?;
    let base = baseline(&dir).map_err(|e| format!("canary: baseline okunamadı: {e}"))?;
    if (base - 64.30).abs() > 1e-9 {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(format!("canary: baseline 64.30 yerine '{base}' okundu"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "coverage parse kanaryası OK (64.15 doğru okundu; baseline float olarak okundu).",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
