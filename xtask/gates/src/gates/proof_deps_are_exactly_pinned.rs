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
    // Short form: name = "0.6"
    let version = if let Some(v) = rest.strip_prefix('"') {
        v.split('"').next()?
    } else if rest.starts_with('{') {
        // Table form: name = { version = "0.6", ... }
        let v = rest.split("version").nth(1)?;
        v.split('"').nth(1)?
    } else {
        return None;
    };
    Some((name, version))
}

/// Is this version expression `=x.y.z` with three numeric parts? `=0.7` would
/// still let Cargo take any 0.7.x release.
fn is_exact_pin(version: &str) -> bool {
    let Some(rest) = version.strip_prefix('=') else {
        return false;
    };
    // An optional pre-release or build suffix after the three numbers.
    let core = rest.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// A covered dependency written in a form that carries no version on the line:
/// `{ workspace = true }` or a `git` source. Its version cannot be read here.
fn unreadable_dependency(line: &str) -> Option<&str> {
    let t = line.trim();
    if t.starts_with('#') {
        return None;
    }
    let (name, rest) = t.split_once('=')?;
    let name = name.trim();
    if !PINNED_PREFIXES.iter().any(|(p, _)| name.starts_with(p)) || name.contains(' ') {
        return None;
    }
    let rest = rest.trim();
    (rest.starts_with('{') && !rest.contains("version")).then_some(name)
}

/// # Errors
///
/// If a covered dependency is not fixed at an exact version.
pub fn run(root: &Path) -> Result<String, String> {
    let mut checked = 0usize;
    let mut problems = String::new();

    for manifest in MANIFESTS {
        let path = root.join(manifest);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("could not read {manifest}: {e}"))?;
        for line in text.lines() {
            if let Some(name) = unreadable_dependency(line) {
                checked += 1;
                let _ = write!(
                    problems,
                    "\n  {manifest}: `{name}` has no version on its line (workspace or git \
                     source), so the exact pin cannot be checked. Pin it here with `=x.y.z`"
                );
                continue;
            }
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
            if !is_exact_pin(version) {
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
/// If the gate cannot tell a caret or tilde spelling from an exact pin.
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
    let pinned =
        dependency("p3-fri = \"=0.6.3\"").ok_or("self_test: the pin could not be parsed")?;
    if !pinned.1.starts_with('=') {
        return Err("self_test: an exact pin was judged not to start with `=`".into());
    }
    let loose =
        dependency("p3-fri = \"0.6\"").ok_or("self_test: the caret form could not be parsed")?;
    if loose.1.starts_with('=') {
        return Err("self_test: a caret spelling was judged an exact pin".into());
    }
    Ok("proof-deps-are-exactly-pinned self-test OK: caret, tilde, table spelling and comments are told apart".into())
}

#[cfg(test)]
mod pin_tests {
    use super::*;

    #[test]
    fn only_a_full_three_part_pin_is_exact() {
        assert!(is_exact_pin("=0.7.0"));
        assert!(is_exact_pin("=1.2.3-rc.1"));
        assert!(!is_exact_pin("=0.7"));
        assert!(!is_exact_pin("0.7.0"));
        assert!(!is_exact_pin("^0.7.0"));
    }

    #[test]
    fn workspace_and_git_forms_are_reported() {
        assert_eq!(
            unreadable_dependency("p3-fri = { workspace = true }"),
            Some("p3-fri")
        );
        assert_eq!(
            unreadable_dependency("p3-fri = { git = \"https://x\" }"),
            Some("p3-fri")
        );
        assert_eq!(
            unreadable_dependency("p3-fri = { version = \"=0.7.0\" }"),
            None
        );
        assert_eq!(unreadable_dependency("serde = { workspace = true }"), None);
    }
}
