//! Per-module line coverage: a table on every run, a ratchet once measured.
//!
//! Ported from `ops/scripts/check_module_coverage.py`. That script resolved
//! its repository root one directory too shallow (`ops/`), so the baseline
//! path it looked for was `ops/.github/module-coverage-baselines.json`; a
//! baseline committed at the repository root would have been ignored and the
//! gate would have skipped forever. The gate now takes the root it is given.
//!
//! # Two honest steps
//!
//! 1. Report mode: the `cargo llvm-cov --json` file summaries are aggregated
//!    by module prefix (weighted: covered lines over counted lines) and
//!    printed. With no `.github/module-coverage-baselines.json` the gate
//!    says SKIP and passes; nothing is asserted that was never measured.
//! 2. Measured floors: once the file exists, every module it names must be
//!    present in the report and at or above its floor. Lowering a floor is
//!    a CI-softening violation like any other baseline.
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use serde_json::Value;

/// Module name and the repository-relative path prefix it owns.
const MODULE_PREFIXES: &[(&str, &str)] = &[
    ("budlum:consensus", "src/consensus/"),
    ("budlum:crypto", "src/crypto/"),
    ("budlum:rpc", "src/rpc/"),
    ("budlum:chain", "src/chain/"),
    ("budlum:core", "src/core/"),
    ("budlum:domain", "src/domain/"),
    ("budlum:network", "src/network/"),
    ("budlum:storage", "src/storage/"),
    ("budlum:tokenomics", "src/tokenomics/"),
    ("budlum:node_di", "src/node_di/"),
    ("budlum:cli", "src/cli/"),
    ("budlum:docs", "src/docs/"),
    ("budzero:vm", "budzero/src/"),
    ("budzero:proof", "budzero/bud-proof/src/"),
    ("budzero:isa", "budzero/bud-isa/src/"),
    ("budzero:node", "budzero/bud-node/src/"),
    ("budzero:compiler", "budzero/bud-compiler/src/"),
];

const BASELINES: &str = ".github/module-coverage-baselines.json";

/// Covered and counted lines of one module.
#[derive(Clone, Copy, Default)]
struct Lines {
    covered: u64,
    total: u64,
}

impl Lines {
    /// Percentage with two decimals, computed in integers so no line count
    /// is ever rounded through a float; only the final hundredths become one.
    fn percent(self) -> f64 {
        if self.total == 0 {
            return 100.0;
        }
        let hundredths = u128::from(self.covered) * 10_000 / u128::from(self.total);
        let hundredths = u32::try_from(hundredths).unwrap_or(u32::MAX);
        f64::from(hundredths) / 100.0
    }
}

/// Make an llvm-cov file path repository relative. The report carries
/// absolute paths; the checkout directory is `budlum/` on CI and anything
/// at all locally, so the `budzero/` anchor is tried on its own as well.
fn normalize(path: &str) -> &str {
    let p = path;
    if let Some(i) = p.find("/budlum/") {
        return &p[i + "/budlum/".len()..];
    }
    if let Some(i) = p.find("budzero/") {
        return &p[i..];
    }
    p
}

fn module_of(path: &str) -> &'static str {
    MODULE_PREFIXES
        .iter()
        .find(|(_, prefix)| path.starts_with(prefix))
        .map_or("__other__", |(name, _)| name)
}

/// Aggregate the report's file summaries per module.
fn analyze(cov: &Value) -> BTreeMap<&'static str, Lines> {
    let mut acc: BTreeMap<&'static str, Lines> = BTreeMap::new();
    let files = cov["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| d["files"].as_array())
        .flatten();
    for f in files {
        let name = f["filename"]
            .as_str()
            .unwrap_or_default()
            .replace('\\', "/");
        let lines = &f["summary"]["lines"];
        let total = lines["count"].as_u64().unwrap_or_default();
        if total == 0 {
            continue;
        }
        let covered = lines["covered"].as_u64().unwrap_or_default();
        let entry = acc.entry(module_of(normalize(&name))).or_default();
        entry.covered += covered;
        entry.total += total;
    }
    acc
}

fn table(rows: &BTreeMap<&'static str, Lines>) -> String {
    let mut out = format!(
        "{:<22}{:>10}{:>10}{:>9}\n",
        "module", "covered", "total", "%"
    );
    for (name, l) in rows {
        let _ = writeln!(
            out,
            "{name:<22}{:>10}{:>10}{:>8.2}",
            l.covered,
            l.total,
            l.percent()
        );
    }
    out
}

/// Every module with a floor must be reported and at or above it.
fn gate(rows: &BTreeMap<&'static str, Lines>, floors: &BTreeMap<String, f64>) -> Vec<String> {
    let mut fails = Vec::new();
    for (name, floor) in floors {
        match rows.get(name.as_str()) {
            None => fails.push(format!(
                "a module with a baseline is missing from the report: {name}"
            )),
            Some(l) if l.percent() + 1e-9 < *floor => fails.push(format!(
                "{name} coverage {:.2}% < baseline {floor:.2}% (ratchet)",
                l.percent()
            )),
            Some(_) => {}
        }
    }
    fails
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{} is not JSON: {e}", path.display()))
}

/// Floors from the baselines file: `{"module_line_floors": {name: pct}}`.
fn floors(path: &Path) -> Result<BTreeMap<String, f64>, String> {
    let v = read_json(path)?;
    let mut out = BTreeMap::new();
    if let Some(map) = v["module_line_floors"].as_object() {
        for (k, f) in map {
            let pct = f
                .as_f64()
                .ok_or_else(|| format!("{}: floor of {k} is not a number", path.display()))?;
            out.insert(k.clone(), pct);
        }
    }
    Ok(out)
}

fn evaluate(root: &Path, report: &Path) -> Result<String, String> {
    let rows = analyze(&read_json(report)?);
    let mut msg = table(&rows);
    let baselines = root.join(BASELINES);
    if !baselines.is_file() {
        let _ = write!(
            msg,
            "SKIP: {BASELINES} is absent (report mode); measured floors are added from a green artifact, never guessed."
        );
        return Ok(msg);
    }
    let floors = floors(&baselines)?;
    if floors.is_empty() {
        let _ = write!(msg, "SKIP: {BASELINES} names no module (report mode).");
        return Ok(msg);
    }
    let fails = gate(&rows, &floors);
    if fails.is_empty() {
        let _ = write!(
            msg,
            "OK: every one of {} module floor(s) held (ratchet direction: no drop).",
            floors.len()
        );
        Ok(msg)
    } else {
        for f in fails {
            let _ = write!(msg, "\nFAIL: {f}");
        }
        Err(msg)
    }
}

/// # Errors
///
/// Returns the report when a module is below its floor or the report cannot
/// be read.
pub fn run(root: &Path, report: &Path) -> Result<String, String> {
    if !report.is_file() {
        return Err(format!("no coverage report at {}", report.display()));
    }
    evaluate(root, report)
}

/// # Errors
///
/// Returns a finding when the aggregation is wrong, a floor above the
/// measurement passes, a floor below it fails, or a missing baselines file
/// does anything but SKIP.
pub fn self_test() -> Result<String, String> {
    let fake = serde_json::json!({"data": [{"files": [
        {"filename": "/x/budlum/src/consensus/pow.rs",
         "summary": {"lines": {"count": 100, "covered": 50}}},
        {"filename": "/x/budlum/src/crypto/hash.rs",
         "summary": {"lines": {"count": 100, "covered": 90}}},
        {"filename": "/x/budlum/budzero/src/lib.rs",
         "summary": {"lines": {"count": 10, "covered": 8}}},
    ]}]});
    let rows = analyze(&fake);
    for (name, want) in [
        ("budlum:consensus", 50.0),
        ("budlum:crypto", 90.0),
        ("budzero:vm", 80.0),
    ] {
        let got = rows.get(name).map(|l| l.percent());
        if got.is_none_or(|g| (g - want).abs() > 1e-6) {
            return Err(format!("canary: {name} measured {got:?}, expected {want}"));
        }
    }
    let low: BTreeMap<String, f64> = [(String::from("budlum:consensus"), 49.0)].into();
    if !gate(&rows, &low).is_empty() {
        return Err(String::from(
            "canary: a floor of 49 below 50% measured was refused",
        ));
    }
    let high: BTreeMap<String, f64> = [(String::from("budlum:consensus"), 51.0)].into();
    if gate(&rows, &high).is_empty() {
        return Err(String::from(
            "canary: a floor of 51 above 50% measured passed",
        ));
    }
    let absent: BTreeMap<String, f64> = [(String::from("budlum:rpc"), 1.0)].into();
    if gate(&rows, &absent).is_empty() {
        return Err(String::from(
            "canary: a floor for an unreported module passed",
        ));
    }
    let dir = super::rust_literals::exclusive_scratch_dir("module-coverage-canary")?;
    let report = dir.join("cov.json");
    std::fs::write(&report, fake.to_string()).map_err(|e| e.to_string())?;
    let verdict = evaluate(&dir, &report);
    let _ = std::fs::remove_dir_all(&dir);
    match verdict {
        Ok(msg) if msg.contains("SKIP:") => Ok(String::from(
            "module coverage canary OK: the aggregation is right, a floor below passes, a floor above fails, an unreported module fails, no baselines file means SKIP",
        )),
        Ok(msg) => Err(format!("canary: no baselines file did not SKIP:\n{msg}")),
        Err(e) => Err(format!("canary: no baselines file failed instead of SKIP:\n{e}")),
    }
}
