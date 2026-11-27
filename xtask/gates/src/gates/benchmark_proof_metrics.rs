//! Require named, numeric proof-benchmark observations, not merely nonempty logs.
//!
//! This validates report completeness and schema. Activation, producer authenticity,
//! hardware suitability, and performance-regression budgets are separate obligations.

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::Path;

const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
const BASELINE: &str = "budzero-proof-baseline-v1";
const STORAGE: &str = "budzero-canonical-storage-challenge-v1";
const CANONICAL: &[&str] = &[
    STORAGE,
    "budzero-canonical-private-transfer-v1",
    "budzero-canonical-matmul-2-3-2-v1",
];

fn validate_log(text: &str, expected: &[&str], label: &str) -> Result<usize, String> {
    let mut seen = BTreeSet::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('{'))
    {
        let value: Value = serde_json::from_str(line)
            .map_err(|error| format!("invalid proof-metric JSON in {label}: {error}"))?;
        let name = value
            .get("benchmark")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("proof metric in {label} has no benchmark name"))?;
        if !expected.contains(&name) {
            return Err(format!("unexpected proof benchmark in {label}"));
        }
        if !seen.insert(name.to_owned()) {
            return Err(format!("duplicate proof benchmark in {label}"));
        }
        for field in ["samples", "trace_rows", "proof_bytes"] {
            if value
                .get(field)
                .and_then(Value::as_u64)
                .is_none_or(|n| n == 0)
            {
                return Err(format!("{label} requires a positive integer {field}"));
            }
        }
        for field in ["prove_seconds_mean", "verify_seconds_mean"] {
            if value
                .get(field)
                .and_then(Value::as_f64)
                .is_none_or(|n| !n.is_finite() || n <= 0.0)
            {
                return Err(format!("{label} requires a finite positive {field}"));
            }
        }
    }
    if expected.iter().any(|name| !seen.contains(*name)) {
        return Err(format!("missing required proof benchmark in {label}"));
    }
    Ok(seen.len())
}

fn read_log(path: &Path) -> Result<String, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("unmeasured benchmark log {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_LOG_BYTES {
        return Err(format!(
            "benchmark log is not a bounded regular file: {}",
            path.display()
        ));
    }
    let file = fs::File::open(path).map_err(|error| error.to_string())?;
    let mut text = String::new();
    file.take(MAX_LOG_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|error| error.to_string())?;
    if u64::try_from(text.len()).map_err(|error| error.to_string())? > MAX_LOG_BYTES {
        return Err("benchmark log grew beyond its byte budget".into());
    }
    Ok(text)
}

/// Check the canonical-program and baseline proof logs in one artifact directory.
///
/// # Errors
/// Refuses missing logs, malformed or duplicate reports, and absent or invalid metrics.
pub fn run(_root: &Path, logs: &Path) -> Result<String, String> {
    let canonical = read_log(&logs.join("bench-budzero-canonical.txt"))?;
    let baseline = read_log(&logs.join("bench-budzero-baseline.txt"))?;
    let count = validate_log(&canonical, CANONICAL, "canonical log")?
        + validate_log(&baseline, &[BASELINE], "baseline log")?;
    Ok(format!("OK: {count} required proof measurements contain numeric fields; activation and regression budgets are not inferred."))
}

fn sample(name: &str) -> String {
    format!(
        r#"{{"benchmark":"{name}","samples":1,"trace_rows":1,"proof_bytes":1,"prove_seconds_mean":1.0,"verify_seconds_mean":1.0}}"#
    )
}

/// Exercise the positive report and independent refusal paths.
///
/// # Errors
/// Fails if valid observations are refused or incomplete/invalid observations pass.
pub fn self_test() -> Result<String, String> {
    let baseline = sample(BASELINE);
    let canonical = CANONICAL
        .iter()
        .map(|name| sample(name))
        .collect::<Vec<_>>()
        .join("\n");
    validate_log(
        &format!("Compiling fixture\n{baseline}"),
        &[BASELINE],
        "baseline log",
    )?;
    validate_log(&canonical, CANONICAL, "canonical log")?;
    let reversed = CANONICAL
        .iter()
        .rev()
        .map(|name| sample(name))
        .collect::<Vec<_>>()
        .join("\n");
    validate_log(&reversed, CANONICAL, "canonical log")?;
    let mut refused = 0usize;
    for (name, text) in [
        (
            "compiler-only output",
            "Compiling fixture\nFinished build\n".to_string(),
        ),
        (
            "malformed trailing report",
            format!("{baseline}\n{{broken}}"),
        ),
        (
            "unexpected trailing benchmark",
            format!("{baseline}\n{}", sample("unexpected-proof-metric")),
        ),
        ("duplicate benchmark", format!("{baseline}\n{baseline}")),
        ("missing benchmark name", "{\"samples\":1}".to_string()),
    ] {
        if validate_log(&text, &[BASELINE], "baseline log").is_ok() {
            return Err(format!("canary accepted {name}"));
        }
        refused += 1;
    }
    for field in ["samples", "trace_rows", "proof_bytes"] {
        for invalid in ["0", "1.5", "\"one\""] {
            let changed =
                baseline.replace(&format!("\"{field}\":1"), &format!("\"{field}\":{invalid}"));
            if changed == baseline || validate_log(&changed, &[BASELINE], "baseline log").is_ok() {
                return Err(format!("canary accepted invalid integer field {field}"));
            }
            refused += 1;
        }
    }
    for field in ["prove_seconds_mean", "verify_seconds_mean"] {
        for invalid in ["0.0", "-1.0", "\"NaN\"", "null"] {
            let changed = baseline.replace(
                &format!("\"{field}\":1.0"),
                &format!("\"{field}\":{invalid}"),
            );
            if changed == baseline || validate_log(&changed, &[BASELINE], "baseline log").is_ok() {
                return Err(format!("canary accepted invalid time field {field}"));
            }
            refused += 1;
        }
    }
    let incomplete = CANONICAL
        .iter()
        .take(2)
        .map(|name| sample(name))
        .collect::<Vec<_>>()
        .join("\n");
    for text in [
        incomplete,
        format!("{canonical}\n{}", sample(STORAGE)),
        baseline,
    ] {
        if validate_log(&text, CANONICAL, "canonical log").is_ok() {
            return Err(
                "canary accepted incomplete, duplicate, or wrong-file canonical reports".into(),
            );
        }
        refused += 1;
    }
    Ok(format!("benchmark-proof-metrics canary OK: valid reports passed; {refused} invalid observations refused."))
}
