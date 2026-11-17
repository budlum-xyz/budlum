//! Every launch-matrix test the tree cites is a test that exists.
//!
//! The launch matrix states, per feature, whether the testnet chain id admits
//! it. Each verdict is proved by one test, named `<feature>_is_open_on_testnet`
//! or `<feature>_is_closed_on_testnet`, and the documents and module headers
//! cite that name as the evidence. A cited name with no test behind it is a
//! claim nothing checks: the feature was opened and the test renamed, or the
//! test was never written, and the document went on pointing at it.
//!
//! The gate collects every such name from the text of the tree and requires a
//! `#[test]` function of exactly that name in a Rust source file. It also
//! refuses a feature that carries both verdicts at once.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// The roots the gate reads, relative to the repository root.
const SCAN_ROOTS: &[&str] = &[
    "src",
    "crates",
    "budzero",
    "execution",
    "mobile",
    "docs",
    "config",
    "ops",
    "README.md",
    "README.tr.md",
];

/// Directories that are never source.
const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// Files above this size are not source text.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

const OPEN_SUFFIX: &str = "_is_open_on_testnet";
const CLOSED_SUFFIX: &str = "_is_closed_on_testnet";
const MATRIX_PATH: &str = ".quality/testnet-feature-matrix.toml";

#[derive(Debug, Clone, PartialEq, Eq)]
struct MatrixFeature {
    id: String,
    state: String,
    evidence: String,
}

fn matrix_string<'a>(
    table: &'a toml::map::Map<String, toml::Value>,
    field: &str,
    index: usize,
) -> Result<&'a str, String> {
    table
        .get(field)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("{MATRIX_PATH}: feature row {index} needs string `{field}`"))
}

fn load_matrix(root: &Path) -> Result<Vec<MatrixFeature>, String> {
    let path = root.join(MATRIX_PATH);
    let text = fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let parsed: toml::Value =
        toml::from_str(&text).map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
    let table = parsed
        .as_table()
        .ok_or_else(|| format!("{MATRIX_PATH}: root must be a table"))?;
    if table.get("version").and_then(toml::Value::as_integer) != Some(1) {
        return Err(format!("{MATRIX_PATH}: `version` must be 1"));
    }
    let rows = table
        .get("feature")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("{MATRIX_PATH}: at least one `[[feature]]` row is required"))?;
    if rows.is_empty() {
        return Err(format!("{MATRIX_PATH}: feature list cannot be empty"));
    }

    let mut ids = BTreeSet::new();
    let mut evidence_names = BTreeSet::new();
    let mut features = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let row = row
            .as_table()
            .ok_or_else(|| format!("{MATRIX_PATH}: feature row {index} must be a table"))?;
        let id = matrix_string(row, "id", index)?;
        let state = matrix_string(row, "state", index)?;
        let evidence = matrix_string(row, "evidence", index)?;
        if id.is_empty()
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(format!(
                "{MATRIX_PATH}: feature row {index} has invalid id `{id}`"
            ));
        }
        if !matches!(state, "open" | "closed") {
            return Err(format!(
                "{MATRIX_PATH}: feature `{id}` state must be `open` or `closed`, got `{state}`"
            ));
        }
        let expected = format!("{id}_is_{state}_on_testnet");
        if evidence != expected {
            return Err(format!(
                "{MATRIX_PATH}: feature `{id}` says `{state}` but evidence is `{evidence}`; expected `{expected}`"
            ));
        }
        if !ids.insert(id.to_string()) {
            return Err(format!("{MATRIX_PATH}: duplicate feature id `{id}`"));
        }
        if !evidence_names.insert(evidence.to_string()) {
            return Err(format!(
                "{MATRIX_PATH}: duplicate evidence test `{evidence}`"
            ));
        }
        features.push(MatrixFeature {
            id: id.to_string(),
            state: state.to_string(),
            evidence: evidence.to_string(),
        });
    }
    Ok(features)
}

/// Production predicates that share the naming pattern. They are code, not
/// evidence, so a mention of one is not a citation of a test. Sorted.
const PREDICATES: &[&str] = &["codec_is_open_on_testnet"];

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Every `<feature>_is_{open,closed}_on_testnet` identifier in `text`.
fn cited_names(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for suffix in [OPEN_SUFFIX, CLOSED_SUFFIX] {
        for (at, _) in text.match_indices(suffix) {
            let end = at.saturating_add(suffix.len());
            if text.as_bytes().get(end).copied().is_some_and(is_ident_byte) {
                continue;
            }
            let head = text.get(..at).unwrap_or_default();
            let start = head
                .bytes()
                .rposition(|byte| !is_ident_byte(byte))
                .map_or(0, |pos| pos.saturating_add(1));
            if start == at {
                continue;
            }
            if let Some(name) = text.get(start..end) {
                names.insert(name.to_string());
            }
        }
    }
    names
}

/// The name of the function a line declares, when it declares one.
fn declared_fn(line: &str) -> Option<&str> {
    let mut rest = line.trim_start();
    for qualifier in ["pub(crate) ", "pub ", "async ", "const "] {
        rest = rest.strip_prefix(qualifier).unwrap_or(rest);
    }
    let rest = rest.strip_prefix("fn ")?;
    let end = rest.bytes().position(|byte| !is_ident_byte(byte))?;
    rest.get(..end).filter(|name| !name.is_empty())
}

/// Every launch-matrix name a Rust file defines as a `#[test]` function.
fn defined_tests(text: &str) -> BTreeSet<String> {
    let mut tests = BTreeSet::new();
    let mut is_test = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[test]") || trimmed.starts_with("#[tokio::test") {
            is_test = true;
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("#[") || trimmed.starts_with("//") {
            continue;
        }
        if is_test {
            if let Some(name) = declared_fn(trimmed) {
                if name.ends_with(OPEN_SUFFIX) || name.ends_with(CLOSED_SUFFIX) {
                    tests.insert(name.to_string());
                }
            }
        }
        is_test = false;
    }
    tests
}

#[derive(Default)]
struct Survey {
    /// Cited name to the first file that cites it.
    cited: BTreeMap<String, String>,
    defined: BTreeSet<String>,
}

fn survey_file(root: &Path, path: &Path, survey: &mut Survey) {
    let Ok(meta) = fs::metadata(path) else {
        return;
    };
    if meta.len() > MAX_FILE_BYTES {
        return;
    }
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    for name in cited_names(&text) {
        survey.cited.entry(name).or_insert_with(|| rel.clone());
    }
    if path.extension().is_some_and(|ext| ext == "rs") {
        survey.defined.extend(defined_tests(&text));
    }
}

fn survey_dir(root: &Path, dir: &Path, survey: &mut Survey) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    let mut paths: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if path.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                survey_dir(root, &path, survey)?;
            }
        } else {
            survey_file(root, &path, survey);
        }
    }
    Ok(())
}

fn feature_of(name: &str) -> Option<&str> {
    name.strip_suffix(OPEN_SUFFIX)
        .or_else(|| name.strip_suffix(CLOSED_SUFFIX))
}

/// # Errors
///
/// Returns a finding when a cited launch-matrix test has no `#[test]`
/// function, when one feature carries both verdicts, or when the tree holds
/// no launch-matrix test at all.
pub fn run(root: &Path) -> Result<String, String> {
    let mut survey = Survey::default();
    for scan_root in SCAN_ROOTS {
        let path = root.join(scan_root);
        if path.is_dir() {
            survey_dir(root, &path, &mut survey)?;
        } else if path.is_file() {
            survey_file(root, &path, &mut survey);
        }
    }
    if survey.defined.is_empty() {
        return Err(String::from(
            "launch-matrix-tests-exist: no `_is_open_on_testnet` or `_is_closed_on_testnet` \
             test was found, so the gate would check nothing",
        ));
    }

    let matrix = load_matrix(root)?;
    let matrix_evidence: BTreeSet<&str> = matrix
        .iter()
        .map(|feature| feature.evidence.as_str())
        .collect();

    let mut problems = Vec::new();
    for feature in &matrix {
        if !survey.defined.contains(&feature.evidence) {
            problems.push(format!(
                "{MATRIX_PATH}: feature `{}` names `{}` but no such launch-verdict test exists",
                feature.id, feature.evidence
            ));
        }
    }
    for name in &survey.defined {
        if !matrix_evidence.contains(name.as_str()) {
            problems.push(format!(
                "launch-verdict test `{name}` has no row in `{MATRIX_PATH}`"
            ));
        }
    }
    for predicate in PREDICATES {
        if !survey.cited.contains_key(*predicate) {
            problems.push(format!(
                "`{predicate}` is listed as a production predicate and the tree no longer names it"
            ));
        }
        if survey.defined.contains(*predicate) {
            problems.push(format!(
                "`{predicate}` is listed as a production predicate and is a `#[test]` function"
            ));
        }
    }
    for (name, file) in &survey.cited {
        if PREDICATES.contains(&name.as_str()) {
            continue;
        }
        if !survey.defined.contains(name) {
            problems.push(format!(
                "`{name}` is cited in `{file}` and no `#[test] fn {name}` exists"
            ));
        }
    }
    for name in &survey.defined {
        let Some(feature) = name.strip_suffix(OPEN_SUFFIX) else {
            continue;
        };
        if survey
            .defined
            .contains(&format!("{feature}{CLOSED_SUFFIX}"))
        {
            problems.push(format!(
                "feature `{feature}` has both an open and a closed launch-matrix test"
            ));
        }
    }
    if !problems.is_empty() {
        let mut msg = String::from("launch-matrix-tests-exist failed:\n");
        for problem in &problems {
            let _ = writeln!(msg, "  - {problem}");
        }
        return Err(msg);
    }

    let features: BTreeSet<&str> = survey
        .defined
        .iter()
        .filter_map(|name| feature_of(name))
        .collect();
    Ok(format!(
        "launch-matrix-tests-exist OK: {} machine row(s), {} cited name(s), {} test(s), {} feature(s).",
        matrix.len(),
        survey.cited.len(),
        survey.defined.len(),
        features.len()
    ))
}

/// Self-test with positive and negative synthetic trees.
///
/// # Errors
///
/// Returns an error if a clean tree fails or a canary passes.
pub fn self_test() -> Result<String, String> {
    let dir =
        crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-launch-matrix-tests")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(&p, body).map_err(|e| e.to_string())
        };
        let open_test = "#[test]\nfn widget_is_open_on_testnet() {}\n";
        let clean_doc = "The widget is open (`widget_is_open_on_testnet`).\n";

        put("src/widget.rs", open_test)?;
        put("docs/WIDGET.md", clean_doc)?;
        put(
            "src/codec.rs",
            "pub const fn codec_is_open_on_testnet(id: u8) -> bool {\n    id != 9\n}\n",
        )?;
        put(
            MATRIX_PATH,
            "version = 1\n\n[[feature]]\nid = \"widget\"\nstate = \"open\"\nevidence = \"widget_is_open_on_testnet\"\n",
        )?;
        run(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;

        // Canary 1: a document cites a test nobody wrote.
        put(
            "docs/WIDGET.md",
            "The widget is closed (`widget_is_closed_on_testnet`).\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a cited test with no function passed"));
        }
        put("docs/WIDGET.md", clean_doc)?;

        // Canary 2: the name exists but is not a test.
        put("src/widget.rs", "fn widget_is_open_on_testnet() {}\n")?;
        put(
            "src/other.rs",
            "#[test]\nfn gadget_is_open_on_testnet() {}\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a plain function counted as a test"));
        }
        put("src/widget.rs", open_test)?;
        fs::remove_file(dir.join("src/other.rs")).map_err(|e| e.to_string())?;

        // Canary 3: a longer name does not stand in for the cited one.
        put(
            "docs/WIDGET.md",
            "See `gadget_is_open_on_testnet` and `get_is_open_on_testnet`.\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a name suffix matched another test"));
        }
        put("docs/WIDGET.md", clean_doc)?;

        // Canary 4: one feature cannot be open and closed at once.
        put(
            "src/other.rs",
            "#[test]\nfn widget_is_closed_on_testnet() {}\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a feature with both verdicts passed"));
        }
        fs::remove_file(dir.join("src/other.rs")).map_err(|e| e.to_string())?;

        // Canary 5: a listed predicate the tree no longer names is stale.
        fs::remove_file(dir.join("src/codec.rs")).map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a stale predicate entry passed"));
        }
        put(
            "src/codec.rs",
            "pub const fn codec_is_open_on_testnet(id: u8) -> bool {\n    id != 9\n}\n",
        )?;

        // Canary 6: a tree with no launch-matrix test checks nothing.
        put("src/widget.rs", "fn unrelated() {}\n")?;
        put("docs/WIDGET.md", "No claim.\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an empty survey passed"));
        }
        Ok(())
    })();
    let _ = fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "launch-matrix-tests-exist canary OK: a clean tree passed; a missing test, a plain \
         function, a suffix match, a double verdict, a stale predicate and an empty survey failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn launch_matrix_tests_exist_canary() {
        assert_eq!(super::self_test().err(), None);
    }

    #[test]
    fn cited_names_stop_at_identifier_boundaries() {
        let names = super::cited_names(
            "`a_is_open_on_testnet`, b_is_closed_on_testnet_v2, _is_open_on_testnet, \
             x::c_is_closed_on_testnet()",
        );
        let expected: Vec<&str> = vec!["a_is_open_on_testnet", "c_is_closed_on_testnet"];
        assert_eq!(
            names.iter().map(String::as_str).collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn machine_matrix_refuses_a_state_that_disagrees_with_its_test() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::create_dir_all(dir.path().join(".quality")).unwrap();
        std::fs::write(
            dir.path().join("src/widget.rs"),
            "#[test]\nfn widget_is_closed_on_testnet() {}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("src/codec.rs"),
            "pub const fn codec_is_open_on_testnet(id: u8) -> bool { id != 9 }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".quality/testnet-feature-matrix.toml"),
            "version = 1\n\n[[feature]]\nid = \"widget\"\nstate = \"open\"\nevidence = \"widget_is_closed_on_testnet\"\n",
        )
        .unwrap();

        assert!(super::run(dir.path()).is_err());
    }
}
