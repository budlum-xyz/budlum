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
///
/// The table must cover every directory of the two measured trees. A file
/// under `src/` or `budzero/` that no prefix owns fails the gate (see
/// [`unclassified`]), so a new module cannot sit outside the ratchet, and
/// [`missing_prefix_dirs`] fails a prefix whose directory does not exist.
const MODULE_PREFIXES: &[(&str, &str)] = &[
    ("budlum:account_abstraction", "src/account_abstraction/"),
    ("budlum:ai", "src/ai/"),
    ("budlum:ai_inference", "src/ai_inference/"),
    ("budlum:bns", "src/bns/"),
    ("budlum:budlumxyz", "src/budlumxyz/"),
    ("budlum:chain", "src/chain/"),
    ("budlum:cli", "src/cli/"),
    ("budlum:consensus", "src/consensus/"),
    ("budlum:core", "src/core/"),
    ("budlum:cross_domain", "src/cross_domain/"),
    ("budlum:crypto", "src/crypto/"),
    ("budlum:deed", "src/deed/"),
    ("budlum:domain", "src/domain/"),
    ("budlum:execution", "src/execution/"),
    ("budlum:gateway", "src/gateway/"),
    ("budlum:light_client", "src/light_client/"),
    ("budlum:mempool", "src/mempool/"),
    ("budlum:network", "src/network/"),
    ("budlum:pollen", "src/pollen/"),
    ("budlum:privacy", "src/privacy/"),
    ("budlum:prover", "src/prover/"),
    ("budlum:registry", "src/registry/"),
    ("budlum:relayer", "src/relayer/"),
    ("budlum:rpc", "src/rpc/"),
    ("budlum:sdk", "src/sdk/"),
    ("budlum:settlement", "src/settlement/"),
    ("budlum:sharding", "src/sharding/"),
    ("budlum:socialfi", "src/socialfi/"),
    ("budlum:storage", "src/storage/"),
    ("budlum:tokenomics", "src/tokenomics/"),
    ("budlum:bin", "src/bin/"),
    ("budlum:tests", "src/tests/"),
    ("budzero:cli", "budzero/bud-cli/"),
    ("budzero:compiler", "budzero/bud-compiler/"),
    ("budzero:isa", "budzero/bud-isa/"),
    ("budzero:node", "budzero/bud-node/"),
    ("budzero:proof", "budzero/bud-proof/"),
    ("budzero:state", "budzero/bud-state/"),
    ("budzero:vm", "budzero/bud-vm/"),
    ("budzero:verifier_registry", "budzero/verifier-registry/"),
];

/// Files directly in `src/` (lib.rs, main.rs, error.rs, ...).
const ROOT_MODULE: &str = "budlum:root";

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
    if let Some(rest) = path.strip_prefix("src/") {
        if !rest.contains('/') {
            return ROOT_MODULE;
        }
    }
    MODULE_PREFIXES
        .iter()
        .find(|(_, prefix)| path.starts_with(prefix))
        .map_or("__other__", |(name, _)| name)
}

/// Report files under the two measured trees that no module owns.
fn unclassified(cov: &Value) -> Vec<String> {
    let files = cov["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| d["files"].as_array())
        .flatten();
    let mut out: Vec<String> = Vec::new();
    for f in files {
        let name = f["filename"]
            .as_str()
            .unwrap_or_default()
            .replace('\\', "/");
        let rel = normalize(&name);
        let measured = rel.starts_with("src/") || rel.starts_with("budzero/");
        if measured && module_of(rel) == "__other__" {
            out.push(rel.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Prefixes in [`MODULE_PREFIXES`] whose directory is not in the tree.
fn missing_prefix_dirs(root: &Path) -> Vec<&'static str> {
    MODULE_PREFIXES
        .iter()
        .filter(|(_, prefix)| !root.join(prefix.trim_end_matches('/')).is_dir())
        .map(|(_, prefix)| *prefix)
        .collect()
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
            // A floor is a percentage. Below zero every measurement clears
            // it and the ratchet for that module is a number nobody can
            // fail; above a hundred nothing clears it; NaN compares false
            // both ways. None of the three is a floor, so none is accepted.
            if !pct.is_finite() || !(0.0..=100.0).contains(&pct) {
                return Err(format!(
                    "{}: floor of {k} is {pct}, which is not a percentage in 0..=100",
                    path.display()
                ));
            }
            out.insert(k.clone(), pct);
        }
    }
    Ok(out)
}

fn evaluate(root: &Path, report: &Path) -> Result<String, String> {
    let cov = read_json(report)?;
    let rows = analyze(&cov);
    let mut msg = table(&rows);
    let orphans = unclassified(&cov);
    if !orphans.is_empty() {
        let shown: Vec<&str> = orphans.iter().take(10).map(String::as_str).collect();
        return Err(format!(
            "{msg}FAIL: {} measured file(s) belong to no module in the coverage table, \
             so no floor can ever cover them (add the module to MODULE_PREFIXES): {}",
            orphans.len(),
            shown.join(", ")
        ));
    }
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
    let missing = missing_prefix_dirs(root);
    if !missing.is_empty() {
        return Err(format!(
            "module coverage table names directories that do not exist: {}",
            missing.join(", ")
        ));
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
        {"filename": "/x/budlum/budzero/bud-vm/src/lib.rs",
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
    // A measured file that no module owns must fail the gate.
    let orphan = serde_json::json!({"data": [{"files": [
        {"filename": "/x/budlum/src/brand_new_module/x.rs",
         "summary": {"lines": {"count": 10, "covered": 10}}},
    ]}]});
    if unclassified(&orphan).len() != 1 {
        return Err(String::from(
            "canary: a file under src/ that no module owns was not reported",
        ));
    }
    if !unclassified(&fake).is_empty() {
        return Err(String::from(
            "canary: owned files were reported as unclassified",
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
    // A floor outside 0..=100 is refused when the baselines are read: a
    // negative one would make the module's ratchet a number nobody fails.
    let baselines = dir.join(BASELINES);
    if let Some(parent) = baselines.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    for bad in ["-1.0", "100.5"] {
        std::fs::write(
            &baselines,
            format!("{{\"module_line_floors\": {{\"budlum:consensus\": {bad}}}}}"),
        )
        .map_err(|e| e.to_string())?;
        if evaluate(&dir, &report).is_ok() {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!("canary: a floor of {bad} was accepted"));
        }
    }
    std::fs::write(
        &baselines,
        "{\"module_line_floors\": {\"budlum:consensus\": 0.0, \"budlum:crypto\": 100.0}}",
    )
    .map_err(|e| e.to_string())?;
    match evaluate(&dir, &report) {
        Ok(_) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(String::from(
                "canary: a floor of 100 above 90% measured passed",
            ));
        }
        Err(e) if !e.contains("budlum:crypto") => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!(
                "canary: the edge floors 0 and 100 were not read as floors: {e}"
            ));
        }
        Err(_) => {}
    }
    std::fs::remove_file(&baselines).map_err(|e| e.to_string())?;
    let verdict = evaluate(&dir, &report);
    let _ = std::fs::remove_dir_all(&dir);
    match verdict {
        Ok(msg) if msg.contains("SKIP:") => Ok(String::from(
            "module coverage canary OK: the aggregation is right, a floor below passes, a floor above fails, an unreported module fails, a floor outside 0..=100 is refused, no baselines file means SKIP",
        )),
        Ok(msg) => Err(format!("canary: no baselines file did not SKIP:\n{msg}")),
        Err(e) => Err(format!("canary: no baselines file failed instead of SKIP:\n{e}")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() {
        super::self_test().expect("module-coverage self-test");
    }

    #[test]
    fn the_table_matches_the_tree() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert_eq!(
            super::missing_prefix_dirs(&root),
            Vec::<&str>::new(),
            "a prefix names a directory that is not in the tree"
        );
        // Every top-level directory of src/ and every crate of budzero/ is
        // owned by some prefix, so a new module cannot sit outside the table.
        for tree in ["src", "budzero"] {
            for e in std::fs::read_dir(root.join(tree))
                .expect("read tree")
                .flatten()
            {
                if !e.path().is_dir() {
                    continue;
                }
                let name = e.file_name().to_string_lossy().into_owned();
                if tree == "budzero" && !e.path().join("Cargo.toml").is_file() {
                    continue;
                }
                let probe = format!("{tree}/{name}/x.rs");
                assert_ne!(
                    super::module_of(&probe),
                    "__other__",
                    "{tree}/{name} is owned by no coverage module"
                );
            }
        }
    }
}
