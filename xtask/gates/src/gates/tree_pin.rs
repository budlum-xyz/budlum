//! Tree-pin gate (hardening depth, 2026-08-28): integrity pins for the
//! whole budzero source tree.
//!
//! The regeneration gate embeds canonical content for two producer files and
//! pins four program hashes; everything else in `budzero/` is outside any
//! integrity check. This gate closes that gap: it pins the Keccak-256 hash of
//! every source and build-input file under `budzero/` (excluding build
//! outputs) in `xtask/gates/pins/budzero-tree.pins` and turns the relay red
//! when any file is added, deleted or modified against the pins.
//!
//! What counts as a source: `.rs` files, and the files that decide what those
//! sources compile into or run against. A pin set that covered only `.rs`
//! left `Cargo.toml` (dependencies, features, lints), `Cargo.lock` (exact
//! versions), `rust-toolchain.toml` (the compiler), `deny.toml` and
//! `osv-scanner.toml` (the audit policy), the `.bud` example programs the
//! CLI tests run, and the Nix flake outside the check: an edit to any of
//! them changes the produced artefact or the audit result without moving a
//! single pinned hash. The extension set is [`PINNED_EXTENSIONS`] plus the
//! [`PINNED_BASENAMES`] that have no extension.
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

/// File extensions that are pinned: sources, manifests, lock files, the
/// toolchain and audit policies, the `.bud` programs and the Nix flake.
/// Markdown is not a build input and stays out. JSON is pinned because the
/// checked-in `budzero/state.json` schema is an input to the CLI tests.
pub const PINNED_EXTENSIONS: &[&str] = &["rs", "toml", "lock", "bud", "nix", "json"];

/// Extension-less files that are pinned by name.
pub const PINNED_BASENAMES: &[&str] = &[".gitignore", "LICENSE"];

/// Whether a file under `budzero/` takes part in the integrity pins.
fn is_pinned_file(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        return PINNED_EXTENSIONS.contains(&ext);
    }
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| PINNED_BASENAMES.contains(&n))
}

/// Collect every pinned file under `budzero/`, excluding `target/` build
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
        // `file_type` describes the entry itself, not a link target, so a
        // committed symlink is neither followed into another directory nor
        // hashed as a source file (CWE-61). `Path::is_dir` follows links:
        // `budzero/loop -> .` recursed until the stack ran out, and a link
        // out of the tree pinned files beyond the declared root.
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        let path = entry.path();
        if kind.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue; // build output, not source
            }
            collect_dir(base, &path, out)?;
            continue;
        }
        if is_pinned_file(&path) {
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
/// A committed directory symlink is not followed (CWE-61): `loop -> .`
/// used to recurse until the stack ran out, and a link out of the tree
/// pinned files beyond the declared root. Neither the loop nor the outside
/// file may reach the pin set.
fn symlink_canary(tmp: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        write_pins(tmp)?;
        let outside = tmp.join("outside");
        std::fs::create_dir_all(&outside).map_err(|e| e.to_string())?;
        std::fs::write(outside.join("leak.rs"), "pub fn leak() {}\n").map_err(|e| e.to_string())?;
        std::os::unix::fs::symlink(".", tmp.join("budzero/loop")).map_err(|e| e.to_string())?;
        std::os::unix::fs::symlink(&outside, tmp.join("budzero/escape"))
            .map_err(|e| e.to_string())?;
        let pinned = collect_tree_files(tmp)?;
        if pinned
            .iter()
            .any(|(k, _)| k.contains("loop") || k.contains("escape"))
        {
            return Err(String::from(
                "tree-pin self-test: a directory symlink was followed",
            ));
        }
        verify_tree(tmp).map_err(|e| {
            format!("tree-pin self-test: symlinks must not change the pinned set: {e}")
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = tmp;
    }
    Ok(())
}

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

    // Build inputs are pinned too: a manifest, a lock file, the toolchain,
    // an audit policy and a `.bud` program each count as a new unpinned file
    // before they are pinned, and as a modification after. Markdown does
    // not: a README edit must not move the pins.
    for rel in [
        "budzero/bud-vm/Cargo.toml",
        "budzero/Cargo.lock",
        "budzero/rust-toolchain.toml",
        "budzero/deny.toml",
        "budzero/example.bud",
        "budzero/flake.nix",
    ] {
        let p = tmp.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "original\n").unwrap();
        if verify_tree(&tmp).is_ok() {
            return Err(format!(
                "tree-pin self-test: an unpinned build input {rel} was accepted"
            ));
        }
        write_pins(&tmp)?;
        verify_tree(&tmp)?;
        std::fs::write(&p, "edited\n").unwrap();
        if verify_tree(&tmp).is_ok() {
            return Err(format!(
                "tree-pin self-test: a modified build input {rel} was accepted"
            ));
        }
        write_pins(&tmp)?;
    }
    // Markdown stays excluded, while the checked-in state schema is pinned.
    std::fs::write(tmp.join("budzero/README.md"), "# notes\n").unwrap();
    std::fs::write(tmp.join("budzero/state.json"), "{}\n").unwrap();
    if verify_tree(&tmp).is_ok() {
        return Err(String::from(
            "tree-pin self-test: an unpinned state.json was accepted",
        ));
    }
    write_pins(&tmp)?;
    std::fs::write(tmp.join("budzero/README.md"), "# edited notes\n").unwrap();
    verify_tree(&tmp).map_err(|e| {
        format!("tree-pin self-test: markdown must remain excluded: {e}")
    })?;
    std::fs::write(tmp.join("budzero/state.json"), "{\"changed\":true}\n").unwrap();
    if verify_tree(&tmp).is_ok() {
        return Err(String::from(
            "tree-pin self-test: a modified state.json was accepted",
        ));
    }

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

    symlink_canary(&tmp)?;

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(String::from(
        "tree-pin self-test: add/delete/modify detection on sources and build \
        inputs (including state.json), markdown left out, tampered pins and missing pin file all behave",
    ))
}
