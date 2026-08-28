//! The dependencies of the proof system are fixed at an exact version.
//!
//! The `p3-*` crates carry the **soundness** of the proof: challenge derivation,
//! FRI, the commitment scheme. In this family a patch release usually means not a
//! "bug fix" but a **security boundary** moving. A concrete example:
//! CVE-2026-46654, transcript malleability in `MultiField32Challenger` -
//! `< 0.4.3` and `>= 0.5.0, < 0.5.3` are affected, and the patches are 0.4.3
//! and 0.5.3.
//!
//! Writing a caret (`"0.6"`) means "any member of the 0.6.x family". The lock
//! file holds 0.6.3 today, but at every moment the lock is refreshed - a
//! `cargo update`, a dependency conflict, a lock-free install in CI - the
//! selected version drifts **silently**. Where it drifts is a newer release and
//! usually good; the problem is that "usually" is not a sufficient guarantee at
//! a soundness boundary. The version of the proof system is part of what the
//! proof proves: without knowing which code produced and verified it, we do not
//! know what was verified.
//!
//! The gate looks for an exact pin of the form `=x.y.z`. Upgrading is not forbidden - the upgrade
//! must be **visible**: a single line change in the manifest, a line read in code
//! review.

use std::fmt::Write as _;
use std::path::Path;

/// The manifests where the proof system's version is bound.
const MANIFESTS: &[&str] = &["budzero/bud-proof/Cargo.toml"];

/// The dependency prefixes that require an exact pin.
///
/// `p3-*`: the Plonky3 family, for the reason above. The list is kept as a prefix so that
/// when a new crate joins the family the gate covers it on its own -
/// adding an exemption takes a deliberate edit, forgetting is not enough.
const PINNED_PREFIXES: &[(&str, &str)] = &[(
    "p3-",
    "a Plonky3 crate carrying the soundness of the proof (CVE-2026-46654 is in this family)",
)];

/// Extract `(name, version expression)` from a manifest line.
///
/// Only the short form `name = "version"` is handled; the table form
/// (`name = { version = "..." }`) is caught too because what is sought is the
/// version string on the line.
fn dependency(line: &str) -> Option<(&str, &str)> {
    let t = line.trim();
    if t.starts_with('#') {
        return None;
    }
    let (name, rest) = t.split_once('=')?;
    let name = name.trim();
    if name.is_empty() || name.contains(' ') {
        return None;
    }
    let rest = rest.trim();
    // Kisa yazim: ad = "0.6"
    let version = if let Some(v) = rest.strip_prefix('"') {
        v.split('"').next()?
    } else if rest.starts_with('{') {
        // Tablo yazimi: ad = { version = "0.6", ... }
        let v = rest.split("version").nth(1)?;
        v.split('"').nth(1)?
    } else {
        return None;
    };
    Some((name, version))
}

/// # Errors
///
/// If a covered dependency is not fixed at an exact version.
pub fn run(root: &Path) -> Result<String, String> {
    let mut checked = 0usize;
    let mut problems = String::new();

    for manifest in MANIFESTS {
        let path = root.join(manifest);
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("could not read {manifest}: {e}"))?;
        for line in text.lines() {
            let Some((name, version)) = dependency(line) else {
                continue;
            };
            let Some((_, why)) = PINNED_PREFIXES
                .iter()
                .find(|(prefix, _)| name.starts_with(prefix))
            else {
                continue;
            };
            checked += 1;
            if !version.starts_with('=') {
                let _ = write!(
                    problems,
                    "\n  {manifest}: `{name} = \"{version}\"` is not an exact pin. \
                     {why}; a caret allows a patch release to change silently \
                     and the proof system's version is part of what the proof proves. \
                     Write it with `=` (example: `{name} = \"={}\"`)",
                    version.trim_start_matches(['^', '~', '=']),
                );
            }
        }
    }

    if !problems.is_empty() {
        return Err(format!("proof-deps-are-exactly-pinned:{problems}"));
    }
    if checked == 0 {
        return Err(
            "proof-deps-are-exactly-pinned: no covered dependency was found. \
             The gate has gone blind - if the manifest moved, MANIFESTS must be updated."
                .into(),
        );
    }
    Ok(format!(
        "proof-deps-are-exactly-pinned OK: {checked} proof dependencies are fixed at an exact version"
    ))
}

/// # Errors
///
/// Kapi caret veya tilde yazimini tam pinden ayirt edemezse.
pub fn self_test() -> Result<String, String> {
    let cases = [
        ("p3-fri = \"=0.6.3\"", Some(("p3-fri", "=0.6.3"))),
        ("p3-fri = \"0.6\"", Some(("p3-fri", "0.6"))),
        ("p3-fri = \"^0.6\"", Some(("p3-fri", "^0.6"))),
        (
            "p3-air = { version = \"0.6\", features = [] }",
            Some(("p3-air", "0.6")),
        ),
        ("# p3-fri = \"0.6\"", None),
        ("[dependencies]", None),
    ];
    for (line, want) in cases {
        if dependency(line) != want {
            return Err(format!(
                "self_test: {want:?} was expected for `{line}`, {:?} came out",
                dependency(line)
            ));
        }
    }
    let pinned = dependency("p3-fri = \"=0.6.3\"").ok_or("self_test: pin ayristirilamadi")?;
    if !pinned.1.starts_with('=') {
        return Err("self_test: tam pin `=` ile baslamiyor sayildi".into());
    }
    let loose = dependency("p3-fri = \"0.6\"").ok_or("self_test: caret ayristirilamadi")?;
    if loose.1.starts_with('=') {
        return Err("self_test: caret yazimi tam pin sayildi".into());
    }
    Ok("proof-deps-are-exactly-pinned self-test OK: caret, tilde, tablo yazimi ve yorum ayirt ediliyor".into())
}
