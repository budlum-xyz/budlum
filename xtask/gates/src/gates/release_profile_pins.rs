//! The release profile is a security boundary, so a gate holds it.
//!
//! `overflow-checks = true` and `panic = "abort"` are load-bearing as a
//! pair: the first turns silent arithmetic wrapping into a panic, the
//! second turns that panic into a process exit. Cargo defaults the checks
//! to OFF in release builds, so nothing but the manifest table keeps them
//! on, and an edit that drops either field passes every test: tests run
//! under the dev profile, where the checks are on regardless. The other
//! three pinned fields (`lto`, `codegen-units`, `strip`) are hardening
//! claims the manifest makes about every shipped binary, and they fail the
//! same way: quietly, in a build nobody re-examined.
//!
//! The gate reads the workspace manifest and refuses a `[profile.release]`
//! that does not carry the five pinned fields with the exact expected
//! values. It does not parse TOML: the table is flat and its values are
//! scalars, and a line scanner keeps the gate inside the zero-dependency
//! trust boundary (the same trade the clippy-extra gate documents for its
//! JSON).

use std::fs;
use std::path::{Path, PathBuf};

/// The five pinned fields and their exact expected values, as they appear
/// in the manifest after trimming (the panic value keeps its quotes).
const PINS: [(&str, &str); 5] = [
    ("overflow-checks", "true"),
    ("panic", "\"abort\""),
    ("lto", "true"),
    ("codegen-units", "1"),
    ("strip", "true"),
];

/// The `key = value` lines of the `[profile.release]` table, comments and
/// blanks removed.
///
/// A manifest without the table is an error, not an empty result: the gate
/// must not pass by finding nothing to check.
fn release_profile_lines(manifest: &str) -> Result<Vec<String>, String> {
    let mut current = String::new();
    let mut saw_table = false;
    let mut lines: Vec<String> = Vec::new();
    for raw in manifest.lines() {
        let line = raw.trim();
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            current = name.to_string();
            if current == "profile.release" {
                saw_table = true;
            }
            continue;
        }
        if current == "profile.release" && !line.is_empty() && !line.starts_with('#') {
            lines.push(line.to_string());
        }
    }
    if !saw_table {
        return Err(String::from(
            "Cargo.toml carries no [profile.release] table. The release hardening is a \
             security boundary: absent is not default-and-fine, it is unpinned.",
        ));
    }
    Ok(lines)
}

/// Check a manifest's release profile against the pins.
fn check(manifest: &str) -> Result<(), String> {
    let lines = release_profile_lines(manifest)?;
    for (key, expected) in PINS {
        let found = lines.iter().find_map(|line| {
            let (k, v) = line.split_once('=')?;
            (k.trim() == key).then(|| v.trim().to_string())
        });
        match found {
            None => {
                return Err(format!(
                    "the release profile does not pin {key}. Cargo defaults it in release \
                     builds, and the tests cannot notice: they run under the dev profile, \
                     where the behaviour is on regardless. Pin it in [profile.release]."
                ));
            }
            Some(v) if v != expected => {
                return Err(format!(
                    "the release profile pins {key} = {v}; the hardened value is {expected}."
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Runs the gate against the repository root.
///
/// # Errors
///
/// Returns `Err` when `Cargo.toml` is unreadable, carries no
/// `[profile.release]` table, or any pinned field is missing or changed.
pub fn run(root: &Path) -> Result<String, String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|e| format!("Cargo.toml could not be read: {e}"))?;
    check(&manifest)?;
    Ok(String::from(
        "release profile pins held: overflow-checks, panic, lto, codegen-units, strip.",
    ))
}

/// A fresh scratch directory for the staged-copy canaries.
fn staged_dir() -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("release-profile-pins-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| format!("cannot stage the self-test dir: {e}"))?;
    Ok(dir)
}

/// Staged-copy canaries: the hardened manifest passes, and every tampered
/// variant fails - each of the five fields changed, a field removed, the
/// table removed, and a pin that only exists in another table.
pub fn self_test() -> Result<String, String> {
    let tmp = staged_dir()?;
    let good = concat!(
        "[package]\n",
        "name = \"x\"\n",
        "\n",
        "[profile.release]\n",
        "# a comment inside the table is tolerated\n",
        "overflow-checks = true\n",
        "panic = \"abort\"\n",
        "lto = true\n",
        "codegen-units = 1\n",
        "strip = true\n",
    );

    // The run path: the good manifest on disk passes through `run`.
    fs::write(tmp.join("Cargo.toml"), good).map_err(|e| format!("cannot stage fixture: {e}"))?;
    if let Err(e) = run(&tmp) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("canary: the hardened manifest must pass, got: {e}"));
    }

    // One tampered value per field.
    let cases: [(&str, &str, &str); 5] = [
        // (key, hardened value, tampered value)
        ("overflow-checks", "true", "false"),
        ("panic", "\"abort\"", "\"unwind\""),
        ("lto", "true", "false"),
        ("codegen-units", "1", "16"),
        ("strip", "true", "false"),
    ];
    for (key, hardened, tampered) in cases {
        let manifest = good.replacen(
            &format!("{key} = {hardened}"),
            &format!("{key} = {tampered}"),
            1,
        );
        if check(&manifest).is_ok() {
            let _ = fs::remove_dir_all(&tmp);
            return Err(format!("canary: {key} = {tampered} must be refused"));
        }
    }

    // A removed field is named in the refusal.
    let missing = good.replacen("overflow-checks = true\n", "", 1);
    if let Err(e) = check(&missing) {
        if !e.contains("overflow-checks") {
            let _ = fs::remove_dir_all(&tmp);
            return Err(format!(
                "canary: the refusal must name the missing field, got: {e}"
            ));
        }
    } else {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a release profile without overflow-checks must be refused",
        ));
    }

    // A manifest without the table is refused, not passed vacuously.
    let no_table = "[package]\nname = \"x\"\n";
    if check(no_table).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a manifest with no [profile.release] must be refused",
        ));
    }

    // A pin that only exists in another table does not count.
    let wrong_table = "[profile.dev]\noverflow-checks = true\npanic = \"abort\"\nlto = true\ncodegen-units = 1\nstrip = true\n";
    if check(wrong_table).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: pins in the wrong table must not satisfy the gate",
        ));
    }

    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "Self-test OK: hardened profile passes; changed, missing, wrong-table and absent \
         variants all refused.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hardened_profile_passes() {
        let manifest = concat!(
            "[package]\nname = \"x\"\n\n[profile.release]\n",
            "overflow-checks = true\npanic = \"abort\"\nlto = true\n",
            "codegen-units = 1\nstrip = true\n",
        );
        assert!(check(manifest).is_ok());
    }

    #[test]
    fn every_tampered_pin_is_refused() {
        let manifest = concat!(
            "[profile.release]\n",
            "overflow-checks = true\npanic = \"abort\"\nlto = true\n",
            "codegen-units = 1\nstrip = true\n",
        );
        for (key, expected) in PINS {
            let bad = manifest.replacen(
                &format!("{key} = {expected}"),
                &format!("{key} = something-else"),
                1,
            );
            assert!(check(&bad).is_err(), "{key} must be pinned to {expected}");
        }
    }

    #[test]
    fn a_manifest_without_the_table_is_refused() {
        assert!(check("[package]\nname = \"x\"\n").is_err());
    }
}
