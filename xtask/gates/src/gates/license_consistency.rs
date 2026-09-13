//! Every place that names the licence names the same one.
//!
//! Ported from `.quality/check_license.py`, which no workflow ran.
//!
//! # The failure this closes
//!
//! The licence is declared in more than one place: the root `LICENSE.md`, the
//! `budzero/LICENSE` copy, the `license` field of every `Cargo.toml`, the README
//! badge and `docs/NOTICE`. Before the move to `PolyForm` Shield they
//! contradicted each other (`budzero/LICENSE` said MIT while
//! `budzero/Cargo.toml` said Apache-2.0) and nobody noticed, because no
//! program compared them.
//!
//! The python version had a hole of its own: a manifest with no `license`
//! line was skipped, so a new package could omit the field and still pass.
//! Here every package manifest has to resolve to the SPDX expression, either
//! by declaring it or by inheriting it from a workspace root that declares
//! it (`license.workspace = true`, or `license = { workspace = true }`).
//!
//! Third-party attributions are protected in the same pass: the Plonky3
//! notice and the `deny.toml` licence allow-list are the record of what the
//! tree owes upstream, and a licence change must not sweep them away.
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use super::regeneration::{hex32, keccak256};

/// The one licence expression every manifest must resolve to.
const SPDX: &str = "LicenseRef-PolyForm-Shield-1.0.0";

/// Length of the canonical `PolyForm` Shield 1.0.0 text at the head of
/// `LICENSE.md`; the project's own required notices follow it.
const CANONICAL_LENGTH: usize = 5747;

/// Keccak-256 of those bytes, so the text is compared to itself over time
/// without a network fetch.
const CANONICAL_KECCAK: &str = "c992c8486f4a401a28226499160fe61174a2cbc14a3bf82ca598ae2d1d79bbd5";

/// Section headings the Shield text carries, in order.
const SECTIONS: &[&str] = &[
    "Acceptance",
    "Copyright License",
    "Distribution License",
    "Notices",
    "Changes and New Works License",
    "Patent License",
    "Noncompete",
    "Competition",
    "New Products",
    "Discontinued Products",
    "Sales of Business",
    "Fair Use",
    "No Other Rights",
    "Patent Defense",
    "Violations",
    "No Liability",
    "Definitions",
];

/// Directories that hold no manifest of ours.
const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".cargo"];

/// How the `license` key of one manifest reads.
#[derive(Debug, PartialEq, Eq)]
enum Declared {
    /// `license = "<expr>"`.
    Literal(String),
    /// `license.workspace = true` or `license = { workspace = true }`.
    Workspace,
    /// No `license` key at all.
    Absent,
}

/// Read the `license` key of a manifest, section-aware: only the key under
/// `[package]` or `[workspace.package]` counts, so a `license` entry inside a
/// `[package.metadata]` table cannot satisfy the gate.
fn declared_in(text: &str, section: &str) -> Declared {
    let mut in_section = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_section = line == format!("[{section}]");
            continue;
        }
        if !in_section || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.split('#').next().unwrap_or("").trim();
        if key == "license.workspace" && value == "true" {
            return Declared::Workspace;
        }
        if key == "license" {
            if value.starts_with('{') && value.contains("workspace") && value.contains("true") {
                return Declared::Workspace;
            }
            return Declared::Literal(value.trim_matches('"').to_string());
        }
    }
    Declared::Absent
}

/// The nearest ancestor manifest that declares `[workspace]`, if any.
fn workspace_root_of(manifest: &Path, root: &Path) -> Option<PathBuf> {
    let mut dir = manifest.parent()?.parent();
    while let Some(d) = dir {
        let candidate = d.join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&candidate) {
            if text.lines().any(|l| l.trim() == "[workspace]") {
                return Some(candidate);
            }
        }
        if d == root {
            break;
        }
        dir = d.parent();
    }
    None
}

fn collect_manifests(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        if kind.is_dir() {
            if !SKIP_DIRS.contains(&name.to_string_lossy().as_ref()) {
                collect_manifests(&path, out);
            }
        } else if name == "Cargo.toml" {
            out.push(path);
        }
    }
}

fn check_licence_texts(root: &Path, problems: &mut Vec<String>) -> Result<(), String> {
    let lic_path = root.join("LICENSE.md");
    let lic =
        std::fs::read(&lic_path).map_err(|e| format!("cannot read {}: {e}", lic_path.display()))?;
    if lic.len() < CANONICAL_LENGTH
        || hex32(&keccak256(&lic[..CANONICAL_LENGTH])) != CANONICAL_KECCAK
    {
        problems.push(String::from(
            "LICENSE.md does not start with the canonical PolyForm Shield 1.0.0 text",
        ));
    }
    for rel in ["LICENSE.md", "budzero/LICENSE"] {
        let path = root.join(rel);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if !text.contains("PolyForm Shield License 1.0.0") {
            problems.push(format!("{rel}: the Shield title is missing"));
        }
        for section in SECTIONS {
            if !text.contains(&format!("## {section}")) {
                problems.push(format!("{rel}: the '{section}' section is missing"));
            }
        }
        for needle in ["Required Notice:", "Licensor Line of Business:"] {
            if !text.contains(needle) {
                problems.push(format!("{rel}: '{needle}' is missing"));
            }
        }
        for old in ["Apache License", "MIT License"] {
            if text.contains(old) {
                problems.push(format!("{rel}: the old '{old}' text is back"));
            }
        }
    }
    Ok(())
}

fn check_manifests(root: &Path, problems: &mut Vec<String>) -> usize {
    let mut manifests = Vec::new();
    collect_manifests(root, &mut manifests);
    for manifest in &manifests {
        let rel = manifest
            .strip_prefix(root)
            .unwrap_or(manifest)
            .display()
            .to_string();
        let Ok(text) = std::fs::read_to_string(manifest) else {
            problems.push(format!("{rel}: cannot be read"));
            continue;
        };
        let is_package = text.lines().any(|l| l.trim() == "[package]");
        if !is_package {
            // A virtual workspace root carries no licence of its own; its
            // `[workspace.package]` is checked through the members.
            continue;
        }
        match declared_in(&text, "package") {
            Declared::Literal(expr) if expr == SPDX => {}
            Declared::Literal(expr) => {
                problems.push(format!("{rel}: license = \"{expr}\", expected \"{SPDX}\""));
            }
            Declared::Workspace => match workspace_root_of(manifest, root) {
                Some(ws) => {
                    let ws_rel = ws.strip_prefix(root).unwrap_or(&ws).display().to_string();
                    let ws_text = std::fs::read_to_string(&ws).unwrap_or_default();
                    match declared_in(&ws_text, "workspace.package") {
                        Declared::Literal(expr) if expr == SPDX => {}
                        Declared::Literal(expr) => problems.push(format!(
                            "{rel} inherits its licence from {ws_rel}, which declares \"{expr}\" instead of \"{SPDX}\""
                        )),
                        _ => problems.push(format!(
                            "{rel} inherits its licence from {ws_rel}, which declares none under [workspace.package]"
                        )),
                    }
                }
                None => problems.push(format!(
                    "{rel} says license.workspace = true but no ancestor manifest declares [workspace]"
                )),
            },
            Declared::Absent => problems.push(format!(
                "{rel} declares no license; every package resolves to \"{SPDX}\", published or not"
            )),
        }
    }
    manifests.len()
}

fn check_notices(root: &Path, problems: &mut Vec<String>) -> Result<(), String> {
    let readme = std::fs::read_to_string(root.join("README.md"))
        .map_err(|e| format!("cannot read README.md: {e}"))?;
    if !readme.contains("PolyForm%20Shield") {
        problems.push(String::from(
            "README.md: the licence badge is not the Shield badge",
        ));
    }
    if readme.contains("license-Apache") {
        problems.push(String::from("README.md: the old Apache badge is back"));
    }
    let notice = std::fs::read_to_string(root.join("docs/NOTICE"))
        .map_err(|e| format!("cannot read docs/NOTICE: {e}"))?;
    if !notice.contains("PolyForm Shield License 1.0.0") {
        problems.push(String::from(
            "docs/NOTICE does not declare the Shield licence",
        ));
    }
    for needle in ["Plonky3", "MIT OR Apache-2.0"] {
        if !notice.contains(needle) {
            problems.push(format!(
                "docs/NOTICE lost the Plonky3 attribution ('{needle}')"
            ));
        }
    }
    let deny = std::fs::read_to_string(root.join("budzero/deny.toml"))
        .map_err(|e| format!("cannot read budzero/deny.toml: {e}"))?;
    if !(deny.contains("\"Apache-2.0\"") && deny.contains("\"MIT\"")) {
        problems.push(String::from(
            "budzero/deny.toml lost the upstream licence allow-list (MIT, Apache-2.0)",
        ));
    }
    Ok(())
}

/// # Errors
///
/// Returns every disagreement between the places that name the licence.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems = Vec::new();
    check_licence_texts(root, &mut problems)?;
    let manifests = check_manifests(root, &mut problems);
    check_notices(root, &mut problems)?;
    if manifests == 0 {
        return Err(String::from(
            "licence gate found no Cargo.toml; the scan is vacuous",
        ));
    }
    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            let _ = writeln!(msg, "FAIL: {p}");
        }
        return Err(msg);
    }
    Ok(format!(
        "licence gate OK: {manifests} manifests resolve to {SPDX}; LICENSE.md, budzero/LICENSE, the README badge and docs/NOTICE agree"
    ))
}

/// # Errors
///
/// Returns a finding when a fixture with a known defect passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-lic")?;
    let result = self_test_in(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn write(dir: &Path, rel: &str, text: &str) -> Result<(), String> {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, text).map_err(|e| e.to_string())
}

/// A tree in which every declaration agrees; returns the licence text so
/// the canaries can restore it.
fn consistent_fixture(dir: &Path) -> Result<Vec<u8>, String> {
    // The real licence text is the fixture's licence text: the canonical
    // digest is a property of that text, not of this checkout.
    let real_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let lic = std::fs::read(real_root.join("LICENSE.md")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir.join("budzero")).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("LICENSE.md"), &lic).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("budzero/LICENSE"), &lic).map_err(|e| e.to_string())?;
    write(
        dir,
        "README.md",
        "[![License](https://img.shields.io/badge/license-PolyForm%20Shield-blue)](LICENSE.md)\n",
    )?;
    write(
        dir,
        "docs/NOTICE",
        "PolyForm Shield License 1.0.0\nPlonky3 MIT OR Apache-2.0\n",
    )?;
    write(
        dir,
        "budzero/deny.toml",
        "allow = [\"MIT\", \"Apache-2.0\"]\n",
    )?;
    write(
        dir,
        "Cargo.toml",
        &format!("[package]\nname = \"root\"\nlicense = \"{SPDX}\"\n"),
    )?;
    write(
        dir,
        "budzero/Cargo.toml",
        &format!("[workspace]\nmembers = [\"vm\"]\n[workspace.package]\nlicense = \"{SPDX}\"\n"),
    )?;
    write(
        dir,
        "budzero/vm/Cargo.toml",
        "[package]\nname = \"vm\"\nlicense.workspace = true\n",
    )?;
    write(
        dir,
        "kani/Cargo.toml",
        &format!("[package]\nname = \"kani\"\npublish = false\nlicense = \"{SPDX}\"\n"),
    )?;
    Ok(lic)
}

fn self_test_in(dir: &Path) -> Result<String, String> {
    let lic = consistent_fixture(dir)?;
    run(dir).map_err(|e| format!("canary: a consistent tree was refused:\n{e}"))?;

    // 1. A package with no licence at all (the hole the python gate had).
    write(
        dir,
        "fuzz/Cargo.toml",
        "[package]\nname = \"fuzz\"\npublish = false\n",
    )?;
    match run(dir) {
        Err(e) if e.contains("fuzz/Cargo.toml declares no license") => {}
        Err(e) => {
            return Err(format!(
                "canary: wrong reason for the missing licence:\n{e}"
            ))
        }
        Ok(_) => return Err(String::from("canary: a manifest with no licence passed")),
    }
    let _ = std::fs::remove_dir_all(dir.join("fuzz"));

    // 2. Inheritance from a workspace that declares a different licence.
    write(
        dir,
        "budzero/Cargo.toml",
        "[workspace]\nmembers = [\"vm\"]\n[workspace.package]\nlicense = \"Apache-2.0\"\n",
    )?;
    match run(dir) {
        Err(e) if e.contains("declares \"Apache-2.0\"") => {}
        Err(e) => {
            return Err(format!(
                "canary: wrong reason for the drifted workspace:\n{e}"
            ))
        }
        Ok(_) => return Err(String::from("canary: a drifted workspace licence passed")),
    }
    write(
        dir,
        "budzero/Cargo.toml",
        &format!("[workspace]\nmembers = [\"vm\"]\n[workspace.package]\nlicense = \"{SPDX}\"\n"),
    )?;

    // 3. A licence key hidden in a metadata table does not count.
    write(
        dir,
        "kani/Cargo.toml",
        &format!("[package]\nname = \"kani\"\n[package.metadata]\nlicense = \"{SPDX}\"\n"),
    )?;
    if run(dir).is_ok() {
        return Err(String::from(
            "canary: a licence under [package.metadata] satisfied the gate",
        ));
    }
    write(
        dir,
        "kani/Cargo.toml",
        &format!("[package]\nname = \"kani\"\nlicense = \"{SPDX}\"\n"),
    )?;

    // 4. The old licence text coming back in the budzero copy.
    write(dir, "budzero/LICENSE", "MIT License\n")?;
    if run(dir).is_ok() {
        return Err(String::from("canary: an MIT budzero/LICENSE passed"));
    }
    std::fs::write(dir.join("budzero/LICENSE"), &lic).map_err(|e| e.to_string())?;

    // 5. The Plonky3 attribution dropped from NOTICE.
    write(dir, "docs/NOTICE", "PolyForm Shield License 1.0.0\n")?;
    if run(dir).is_ok() {
        return Err(String::from(
            "canary: a NOTICE without the Plonky3 attribution passed",
        ));
    }
    Ok(String::from(
        "licence canary OK: a missing licence, a drifted workspace licence, a metadata-only key, an old licence text and a dropped attribution all FAIL; the consistent tree PASSES.",
    ))
}
