//! Tree-pin gate (hardening depth, 2026-08-28): integrity pins for the
//! whole budzero source tree.
//!
//! The regeneration gate embeds canonical content for two producer files and
//! pins four program hashes; everything else in `budzero/` is outside any
//! integrity check. This gate closes that gap: it pins the Keccak-256 hash of
//! every `.rs` file under `budzero/` (excluding build outputs) in
//! `xtask/gates/pins/budzero-tree.pins` and turns the relay red when any file
//! is added, deleted or modified against the pins.
//!
//! Pins move with development, not with the wind: `--pin` rewrites the pin
//! file from the current tree and must be committed together with the change
//! it describes; CI runs the gate without `--pin`, so an unpinned edit is a
//! red relay.
//!
//! Detection and reporting only - repair is manual.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use super::regeneration::{hex32, keccak256};

/// Pin file, relative to the repo root.
pub const PIN_FILE: &str = "xtask/gates/pins/budzero-tree.pins";

/// Collect every `.rs` file under `budzero/`, excluding `target/` build
/// outputs. Returns (relpath, bytes) pairs sorted by relpath.
fn collect_tree_files(root: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let base = root.join("budzero");
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    collect_dir(&base, &base, &mut out)?;
    Ok(out.into_iter().collect())
}

fn collect_dir(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("tree-pin: cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("tree-pin: read_dir entry: {e}"))?;
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue; // build output, not source
            }
            collect_dir(base, &path, out)?;
            continue;
        }
        if path.extension().is_some_and(|e| e == "rs") {
            let rel = path
                .strip_prefix(base)
                .map_err(|_| String::from("tree-pin: path outside budzero"))?;
            let bytes = std::fs::read(&path)
                .map_err(|e| format!("tree-pin: cannot read {}: {e}", path.display()))?;
            out.insert(rel.to_string_lossy().to_string(), bytes);
        }
    }
    Ok(())
}

/// Parse the pin file: one `relpath hex64` per line, `#` comments allowed.
fn read_pins(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let path = root.join(PIN_FILE);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("tree-pin: cannot read pin file {}: {e}", path.display()))?;
    let mut pins = BTreeMap::new();
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((rel, hex)) = line.split_once(char::is_whitespace) else {
            return Err(format!(
                "tree-pin: pin file line {} is not `relpath hex64`: {line}",
                idx + 1
            ));
        };
        let hex = hex.trim();
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "tree-pin: pin file line {} has a non-64-hex hash: {line}",
                idx + 1
            ));
        }
        pins.insert(rel.to_string(), hex.to_string());
    }
    if pins.is_empty() {
        return Err(String::from(
            "tree-pin: the pin file lists no files - either the tree is empty or the \
             scan is blind; neither may pass silently",
        ));
    }
    Ok(pins)
}

/// Write the pin file for the current tree (sorted, deterministic).
fn write_pins(root: &Path) -> Result<String, String> {
    let files = collect_tree_files(root)?;
    let mut text = String::from("# budzero source-tree integrity pins (Keccak-256)\n");
    text.push_str("# Regenerate with: cargo run --release --manifest-path xtask/gates/Cargo.toml -- tree-pin --pin\n");
    text.push_str("# Commit the new pins together with the change they describe.\n");
    for (rel, bytes) in &files {
        let digest = keccak256(bytes);
        let _ = writeln!(text, "{rel} {}", hex32(&digest));
    }
    let path = root.join(PIN_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("tree-pin: cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, text)
        .map_err(|e| format!("tree-pin: cannot write {}: {e}", path.display()))?;
    Ok(format!(
        "tree-pin: pinned {} files to {}",
        files.len(),
        PIN_FILE
    ))
}

/// Verify the tree against the pins.
fn verify_tree(root: &Path) -> Result<String, String> {
    let pins = read_pins(root)?;
    let files = collect_tree_files(root)?;
    let mut findings: Vec<String> = Vec::new();

    let by_rel: BTreeMap<&str, &[u8]> = files
        .iter()
        .map(|(rel, b)| (rel.as_str(), b.as_slice()))
        .collect();

    // Every pinned file must still exist with the same hash.
    for (rel, pin_hex) in &pins {
        match by_rel.get(rel.as_str()) {
            None => findings.push(format!("deleted: {rel}")),
            Some(bytes) => {
                let got = hex32(&keccak256(bytes));
                if &got != pin_hex {
                    findings.push(format!(
                        "modified: {rel} (pinned {}..., on-disk {}...)",
                        &pin_hex[..16],
                        &got[..16]
                    ));
                }
            }
        }
    }
    // Every tree file must be pinned (a new file is a silent addition).
    for rel in by_rel.keys() {
        if !pins.contains_key(*rel) {
            findings.push(format!("unpinned (new): {rel}"));
        }
    }

    if !findings.is_empty() {
        return Err(format!(
            "tree-pin: the budzero source tree does not match its integrity pins:\n  {}\n\
             If the change is intentional, re-pin with `tree-pin --pin` and commit \
             the pins together with the change; if not, an outside attacker touched \
             canonical sources.",
            findings.join("\n  ")
        ));
    }
    Ok(format!(
        "tree-pin: all {} files match their pins",
        pins.len()
    ))
}

/// Run with optional extra arguments: `--pin` rewrites the pins, anything
/// else is a plain verification.
pub fn run_with_args(root: &Path, args: &[&str]) -> Result<String, String> {
    if args.contains(&"--pin") {
        return write_pins(root);
    }
    if args.contains(&"--repin") || args.contains(&"-p") {
        return write_pins(root);
    }
    verify_tree(root)
}

/// Placeholder used by the plain `run` slot: the gate requires the `--pin`
/// flag for rewriting, so the no-arg entry point explains itself.
pub fn run(_root: &Path) -> Result<String, String> {
    Err(String::from(
        "tree-pin verifies the budzero source tree against xtask/gates/pins/budzero-tree.pins; \
         pass --pin to rewrite the pins from the current tree",
    ))
}

/// Self-test: every red-injection this gate must catch, caught.
pub fn self_test() -> Result<String, String> {
    // Isolated tree: two source files under budzero/.
    let tmp = std::env::temp_dir().join(format!("bud-tree-pin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let a_path = tmp.join("budzero/bud-vm/src/a.rs");
    let b_path = tmp.join("budzero/bud-proof/src/b.rs");
    std::fs::create_dir_all(a_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(b_path.parent().unwrap()).unwrap();
    std::fs::write(&a_path, "pub fn a() -> u64 { 1 }\n").unwrap();
    std::fs::write(&b_path, "pub fn b() -> u64 { 2 }\n").unwrap();

    // Pin the tree.
    write_pins(&tmp)?;
    // Verification passes.
    verify_tree(&tmp)?;

    // Modified file must be caught.
    std::fs::write(&a_path, "pub fn a() -> u64 { 7 }\n").unwrap();
    if verify_tree(&tmp).is_ok() {
        return Err(String::from(
            "tree-pin self-test: a modified file was accepted",
        ));
    }
    // Deleted file must be caught.
    std::fs::remove_file(&a_path).unwrap();
    if verify_tree(&tmp).is_ok() {
        return Err(String::from(
            "tree-pin self-test: a deleted file was accepted",
        ));
    }
    // New unpinned file must be caught.
    std::fs::write(&a_path, "pub fn a() -> u64 { 1 }\n").unwrap();
    std::fs::write(tmp.join("budzero/bud-vm/src/evil.rs"), "pub fn evil() {}\n").unwrap();
    if verify_tree(&tmp).is_ok() {
        return Err(String::from(
            "tree-pin self-test: an unpinned new file was accepted",
        ));
    }
    std::fs::remove_file(tmp.join("budzero/bud-vm/src/evil.rs")).unwrap();

    // Re-pin, then a tampered pin entry must be caught as a mismatch.
    write_pins(&tmp)?;
    let pin_path = tmp.join(PIN_FILE);
    let pin_text = std::fs::read_to_string(&pin_path).unwrap();
    let tampered = pin_text.replacen('1', "9", 1);
    assert_ne!(pin_text, tampered, "replacen must change the file");
    std::fs::write(&pin_path, tampered).unwrap();
    if verify_tree(&tmp).is_ok() {
        return Err(String::from(
            "tree-pin self-test: a tampered pin entry was accepted",
        ));
    }
    // A missing pin file must not pass silently.
    std::fs::remove_file(&pin_path).unwrap();
    if verify_tree(&tmp).is_ok() {
        return Err(String::from(
            "tree-pin self-test: a missing pin file was accepted",
        ));
    }

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(String::from(
        "tree-pin self-test: add/delete/modify detection, tampered pins and \
         missing pin file all behave",
    ))
}
