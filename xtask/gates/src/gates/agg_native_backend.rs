//! The native aggregation backend never reaches a production build.
//!
//! # The failure this closes
//!
//! `src/aggregation/native.rs` is a proving backend whose proof is the list
//! of the objects themselves. It exists so the claim layer can run before the
//! STARK backend does. It saves no bytes, and nothing in its proof binds the
//! aggregator of a segment, so a node that accepted it on a real network
//! would let a block producer redirect aggregator fees. The aggregation
//! directive (section 11, build test) asks that a production profile carry
//! no native backend.
//!
//! The backend is compiled under `cfg(any(test, feature =
//! "agg-native-backend"))`. That holds only while three things stay true, and
//! each one can be undone by a one-line edit somewhere else:
//!
//! 1. The feature is not a default feature and no other feature turns it on.
//! 2. The module, and every other mention of `NativeBackend` in production
//!    code, sits behind that `cfg`.
//! 3. No container image and no release workflow builds with the feature or
//!    with `--all-features`.
//!
//! # What is checked
//!
//! Exactly those three. The gate fails by naming the file and the line.

use std::fs;
use std::path::{Path, PathBuf};

const FEATURE: &str = "agg-native-backend";
const TYPE_NAME: &str = "NativeBackend";
const MODULE_FILE: &str = "src/aggregation/mod.rs";
/// The files that may name the backend without a `cfg` of their own: the
/// module itself, and the test files, which the module list already gates.
const OWN_FILES: &[&str] = &["src/aggregation/native.rs"];
/// The test tree of the module: `mod tests` is `cfg(test)` as a whole.
const TEST_DIR: &str = "src/aggregation/tests/";
const TEST_MODULE: &str = "mod tests;";
/// A `cfg` attribute counts for an item when it is at most this many lines
/// above the mention.
const CFG_WINDOW: usize = 3;

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// The `[features]` table of a manifest, as `(name, value)` lines.
fn features(manifest: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == "[features]";
            continue;
        }
        if !inside || line.starts_with('#') {
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            out.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    out
}

fn check_manifest(root: &Path) -> Result<(), String> {
    let manifest = read(&root.join("Cargo.toml"))?;
    let table = features(&manifest);
    if !table.iter().any(|(name, _)| name == FEATURE) {
        return Err(format!(
            "Cargo.toml: the `{FEATURE}` feature is gone; the native backend has no switch"
        ));
    }
    let quoted = format!("\"{FEATURE}\"");
    for (name, value) in &table {
        if name != FEATURE && value.contains(&quoted) {
            return Err(format!(
                "Cargo.toml: feature `{name}` turns on `{FEATURE}`; the native backend must be asked for by name"
            ));
        }
    }
    Ok(())
}

fn is_feature_cfg(line: &str) -> bool {
    let line = line.trim();
    line.starts_with("#[cfg(") && line.contains(&format!("feature = \"{FEATURE}\""))
}

/// Whether a `cfg` naming the feature stands within the window above `at`.
fn gated(lines: &[&str], at: usize) -> bool {
    let from = at.saturating_sub(CFG_WINDOW);
    lines
        .get(from..at)
        .is_some_and(|above| above.iter().any(|line| is_feature_cfg(line)))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn check_sources(root: &Path) -> Result<usize, String> {
    let module = read(&root.join(MODULE_FILE))?;
    let lines: Vec<&str> = module.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.trim() == "pub mod native;")
        .ok_or_else(|| format!("{MODULE_FILE}: `pub mod native;` not found"))?;
    if !gated(&lines, at) {
        return Err(format!(
            "{MODULE_FILE}:{}: `pub mod native;` is not behind cfg(feature = \"{FEATURE}\")",
            at.saturating_add(1)
        ));
    }

    // The test tree is skipped below, so it must really be test-only.
    if let Some(at) = lines.iter().position(|line| line.trim() == TEST_MODULE) {
        let test_only = at
            .checked_sub(1)
            .and_then(|above| lines.get(above))
            .is_some_and(|line| line.trim() == "#[cfg(test)]");
        if !test_only {
            return Err(format!(
                "{MODULE_FILE}:{}: `{TEST_MODULE}` is not behind #[cfg(test)]",
                at.saturating_add(1)
            ));
        }
    }

    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();
    let mut mentions = 0usize;
    for path in files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if OWN_FILES.contains(&rel.as_str()) || rel.starts_with(TEST_DIR) {
            continue;
        }
        let text = read(&path)?;
        let lines: Vec<&str> = text.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if !code.contains(TYPE_NAME) {
                continue;
            }
            mentions = mentions.saturating_add(1);
            if !gated(&lines, at) {
                return Err(format!(
                    "{rel}:{}: `{TYPE_NAME}` is named outside cfg(feature = \"{FEATURE}\")",
                    at.saturating_add(1)
                ));
            }
        }
    }
    Ok(mentions)
}

/// Container files and release workflows: the places a production binary is
/// built.
fn production_build_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in [root.to_path_buf(), root.join("ops"), root.join("docker")] {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_file() && name.starts_with("Dockerfile") {
                out.push(path);
            }
        }
    }
    if let Ok(entries) = fs::read_dir(root.join(".github/workflows")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains("release") || name.contains("docker") || name.contains("publish") {
                out.push(entry.path());
            }
        }
    }
    out.sort();
    out
}

fn check_production_builds(root: &Path) -> Result<usize, String> {
    let files = production_build_files(root);
    for path in &files {
        let text = read(path)?;
        for (at, line) in text.lines().enumerate() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            if line.contains(FEATURE) || line.contains("--all-features") {
                return Err(format!(
                    "{}:{}: a production build turns on `{FEATURE}` (by name or with --all-features)",
                    path.strip_prefix(root).unwrap_or(path).display(),
                    at.saturating_add(1)
                ));
            }
        }
    }
    Ok(files.len())
}

/// # Errors
///
/// Names the file and line that would let the native backend into a
/// production build.
pub fn run(root: &Path) -> Result<String, String> {
    check_manifest(root)?;
    let mentions = check_sources(root)?;
    let builds = check_production_builds(root)?;
    Ok(format!(
        "PASS: `{FEATURE}` is off by default, the module and {mentions} other mention(s) are behind its cfg, {builds} production build file(s) do not enable it"
    ))
}

const CLEAN_MANIFEST: &str = "[package]\nname = \"x\"\n\n[features]\ndefault = [\"pq-ml-dsa\"]\npq-ml-dsa = []\nagg-native-backend = []\n\n[dependencies]\n";
const CLEAN_MODULE: &str = "pub mod merkle;\n#[cfg(any(test, feature = \"agg-native-backend\"))]\npub mod native;\npub mod object;\n";
const CLEAN_DOCKERFILE: &str = "FROM rust\nRUN cargo build --release --locked\n";

fn stage(
    root: &Path,
    manifest: &str,
    module: &str,
    extra: &str,
    dockerfile: &str,
) -> Result<(), String> {
    let write = |rel: &str, text: &str| -> Result<(), String> {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        fs::write(&path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))
    };
    write("Cargo.toml", manifest)?;
    write(MODULE_FILE, module)?;
    write("src/aggregation/native.rs", "pub struct NativeBackend;\n")?;
    write("src/node.rs", extra)?;
    write("Dockerfile", dockerfile)
}

/// # Errors
///
/// Returns the first canary that misbehaves: a clean tree must pass, and each
/// of the ways the backend could leak must be caught on its own.
pub fn self_test() -> Result<String, String> {
    let tmp = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-agg-native")?;
    let gated_use = "#[cfg(feature = \"agg-native-backend\")]\nuse crate::aggregation::native::NativeBackend;\n";
    let cases: [(&str, &str, &str, &str, &str, bool); 9] = [
        ("clean", CLEAN_MANIFEST, CLEAN_MODULE, "fn f() {}\n", CLEAN_DOCKERFILE, true),
        ("gated-use", CLEAN_MANIFEST, CLEAN_MODULE, gated_use, CLEAN_DOCKERFILE, true),
        (
            "default-feature",
            "[features]\ndefault = [\"pq-ml-dsa\", \"agg-native-backend\"]\nagg-native-backend = []\n",
            CLEAN_MODULE,
            "fn f() {}\n",
            CLEAN_DOCKERFILE,
            false,
        ),
        (
            "enabled-by-another-feature",
            "[features]\ndefault = []\ndevnet = [\"agg-native-backend\"]\nagg-native-backend = []\n",
            CLEAN_MODULE,
            "fn f() {}\n",
            CLEAN_DOCKERFILE,
            false,
        ),
        (
            "feature-removed",
            "[features]\ndefault = []\n",
            CLEAN_MODULE,
            "fn f() {}\n",
            CLEAN_DOCKERFILE,
            false,
        ),
        (
            "module-not-gated",
            CLEAN_MANIFEST,
            "pub mod merkle;\npub mod native;\n",
            "fn f() {}\n",
            CLEAN_DOCKERFILE,
            false,
        ),
        (
            "test-tree-not-test-only",
            CLEAN_MANIFEST,
            "#[cfg(any(test, feature = \"agg-native-backend\"))]\npub mod native;\nmod tests;\n",
            "fn f() {}\n",
            CLEAN_DOCKERFILE,
            false,
        ),
        (
            "ungated-use",
            CLEAN_MANIFEST,
            CLEAN_MODULE,
            "use crate::aggregation::native::NativeBackend;\n",
            CLEAN_DOCKERFILE,
            false,
        ),
        (
            "dockerfile-enables-it",
            CLEAN_MANIFEST,
            CLEAN_MODULE,
            "fn f() {}\n",
            "FROM rust\nRUN cargo build --release --features agg-native-backend\n",
            false,
        ),
    ];
    let mut verdict = Ok(());
    for (name, manifest, module, extra, dockerfile, should_pass) in cases {
        let root = tmp.join(name);
        let outcome = stage(&root, manifest, module, extra, dockerfile).map(|()| run(&root));
        match outcome {
            Err(e) => verdict = Err(format!("canary `{name}`: {e}")),
            Ok(result) if result.is_ok() != should_pass => {
                verdict = Err(format!(
                    "canary `{name}`: expected {}, got {result:?}",
                    if should_pass { "PASS" } else { "FAIL" }
                ));
            }
            Ok(_) => {}
        }
        if verdict.is_err() {
            break;
        }
    }
    let _ = fs::remove_dir_all(&tmp);
    verdict.map(|()| {
        "PASS: canaries: clean and gated trees pass; default feature, indirect feature, removed feature, ungated module, ungated test tree, ungated use and an enabling Dockerfile are each caught".to_string()
    })
}
