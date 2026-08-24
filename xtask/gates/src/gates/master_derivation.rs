//! A derivation cannot outlive its master.
//!
//! Ported from `scripts/check-a-derivation-cannot-outlive-its-master.sh`. The
//! derived-content module must track master dependencies (`MasterRegistry`,
//! `derivation_count`), expose the three `DerivedError` variants, and carry
//! the five regression tests that pin the release rules.

use std::fmt::Write as _;
use std::path::Path;

fn code_of(root: &Path) -> Result<String, String> {
    let f = root.join("src/storage/derived.rs");
    if !f.is_file() {
        return Err(format!("derived-content module missing at {}", f.display()));
    }
    std::fs::read_to_string(&f).map_err(|e| e.to_string())
}

/// # Errors
///
/// Returns the first violated claim.
pub fn run(root: &Path) -> Result<String, String> {
    let code = code_of(root)?;
    for (needle, msg) in [
        (
            "pub struct MasterRegistry",
            "no MasterRegistry: nothing tracks what depends on a master, so releasing one \
             would take its derivations with it silently",
        ),
        (
            "fn derivation_count",
            "MasterRegistry does not expose a derivation count; a refusal nobody can inspect \
             cannot be reasoned about at the call site",
        ),
    ] {
        if !code.contains(needle) {
            return Err(msg.to_string());
        }
    }
    for variant in [
        "MasterStillDerived",
        "MasterGraceNotElapsed",
        "UnknownMaster",
    ] {
        if !code.contains(variant) {
            return Err(format!("DerivedError has no {variant} variant"));
        }
    }
    for t in [
        "a_master_carrying_derivations_is_not_released",
        "a_master_nothing_derives_from_is_released",
        "the_last_derivation_opens_a_grace_window",
        "a_new_derivation_cancels_a_pending_release",
        "a_derivation_of_an_unheld_master_is_refused",
    ] {
        if !code.contains(&format!("fn {t}")) {
            return Err(format!("missing test: {t}"));
        }
    }
    Ok(String::from(
        "a-derivation gate OK: master registry, refusal variants and 5 regression tests present.",
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-master-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(dir.join("src/storage"));

    let mut good = String::from(
        "pub struct MasterRegistry {}\npub fn derivation_count() -> usize { 0 }\npub enum DerivedError {\n    MasterStillDerived,\n    MasterGraceNotElapsed,\n    UnknownMaster,\n}\n",
    );
    for t in [
        "a_master_carrying_derivations_is_not_released",
        "a_master_nothing_derives_from_is_released",
        "the_last_derivation_opens_a_grace_window",
        "a_new_derivation_cancels_a_pending_release",
        "a_derivation_of_an_unheld_master_is_refused",
    ] {
        writeln!(good, "fn {t}() {{}}").expect("writing to a String cannot fail");
    }
    std::fs::write(dir.join("src/storage/derived.rs"), &good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a correct module was refused"));
    }
    let bad = good.replace("MasterRegistry", "MasterThing");
    std::fs::write(dir.join("src/storage/derived.rs"), bad).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a module with no MasterRegistry passed",
        ));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "a-derivation canary OK (correct PASSes, missing FAILs).",
    ))
}
