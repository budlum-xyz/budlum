//! A delivery a commit message claims is present in the tree it lands in.
//!
//! Measured 2026-11-23: a branch claimed to carry two deliveries, the gate board
//! was 188/188 green, and one of the two was not on the branch at all. Nothing
//! failed, because every gate reads *files* and none asks whether a thing the
//! change set claims to have done is actually there.
//!
//! The question this gate answers is narrower than "is the commit honest" - a
//! gate cannot read intent. It answers exactly one measurable version:
//!
//! > Every identifier the change set says it adds or changes exists in the tree.
//!
//! The claim is stated in the commit message in a fixed, checkable form - a
//! `DELIVERS:` block naming one identifier per line. If a name in that block is
//! nowhere in the tree, the commit shipped a claim without its code, which is
//! the shape of the failure that motivated this gate.
//!
//! # Why the format is fixed
//!
//! Free prose cannot be checked without guessing, and a gate that guesses
//! becomes a gate that is switched off. A `DELIVERS:` block that is absent
//! means the commit makes no claim and the gate says nothing about it - the
//! gate is silent on commits that do not opt in, and loud on commits that opt
//! in and do not deliver.
//!
//! # Fail closed
//!
//! A `DELIVERS:` block whose names are all present passes. A block naming a
//! symbol the tree does not contain fails with the missing name and the commit
//! in the message. A block that names nothing fails too: an empty claim is a
//! formatting mistake that reads as a satisfied check, which is the exact class
//! this repository keeps paying for.

use std::path::Path;
use std::process::Command;

/// The marker that starts a claim block in a commit message.
pub const CLAIM_MARKER: &str = "DELIVERS:";

/// One claim: the commit that makes it and the names it promises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub commit: String,
    pub names: Vec<String>,
}

/// Read every `DELIVERS:` block out of a commit body.
///
/// The block starts at the marker and runs until a blank line or a new
/// `UPPERCASE:` section header. Names are trimmed, and lines that are empty are
/// ignored so the block can be spaced for readability.
#[must_use]
pub fn claims_in(body: &str) -> Vec<Claim> {
    let mut out: Vec<Claim> = Vec::new();
    let mut current: Option<Vec<String>> = None;
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(CLAIM_MARKER) {
            out.extend(current.take().map(|names| Claim {
                commit: String::new(),
                names,
            }));
            let mut names: Vec<String> = Vec::new();
            let rest = rest.trim();
            if !rest.is_empty() {
                names.push(rest.to_string());
            }
            current = Some(names);
            continue;
        }
        let ends_block = trimmed.is_empty()
            || (trimmed.ends_with(':')
                && trimmed
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_uppercase())
                && !trimmed.contains(' '));
        if ends_block {
            if let Some(names) = current.take() {
                out.push(Claim {
                    commit: String::new(),
                    names,
                });
            }
            continue;
        }
        if let Some(names) = current.as_mut() {
            names.push(trimmed.to_string());
        }
    }
    if let Some(names) = current {
        out.push(Claim {
            commit: String::new(),
            names,
        });
    }
    // An empty block is KEPT: "DELIVERS:" with nothing under it is a claim that
    // names nothing, and that has to fail loudly rather than read as "no claim".
    // Dropping it here was measured to turn the empty case into a silent pass.
    out
}

/// Does `name` appear anywhere in `tree` as a whole identifier?
#[must_use]
pub fn name_present(tree: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let bytes = tree.as_bytes();
    let needle = name.as_bytes();
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut start = 0;
    while let Some(found) = find_from(tree, start, name) {
        let before_ok = found == 0 || !ident(bytes[found - 1]);
        let after = found + needle.len();
        let after_ok = after >= bytes.len() || !ident(bytes[after]);
        if before_ok && after_ok {
            return true;
        }
        start = found + 1;
    }
    false
}

fn find_from(haystack: &str, from: usize, needle: &str) -> Option<usize> {
    haystack.get(from..)?.find(needle).map(|i| i + from)
}

fn git(args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .output()
        .map_err(|e| format!("git {} could not run: {e}", args.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn run(_root: &Path) -> Result<String, String> {
    let body = git(&["log", "-1", "--format=%B"])?;
    run_on_body(&body, &|name| {
        // Search the tracked text files, once, through git so nothing from the
        // working tree that is not part of the change set can satisfy a claim.
        let hit = Command::new("git")
            .args(["grep", "-q", "-w", "-F", "--", name])
            .output()
            .map_err(|e| format!("git grep could not run: {e}"))?;
        Ok(hit.status.success())
    })
}

/// The checkable core, kept separate from git so the canary can drive it.
pub fn run_on_body(
    body: &str,
    present: &dyn Fn(&str) -> Result<bool, String>,
) -> Result<String, String> {
    let claims = claims_in(body);
    if claims.is_empty() {
        return Ok(String::from(
            "delivery-presence: no DELIVERS: claim in the commit message; nothing to check",
        ));
    }
    for claim in &claims {
        if claim.names.is_empty() {
            return Err(String::from(
                "delivery-presence: a DELIVERS: block names nothing. An empty claim reads as a \
                 satisfied check; write the identifiers or drop the block.",
            ));
        }
        for name in &claim.names {
            if !present(name)? {
                return Err(format!(
                    "delivery-presence: the commit claims `{name}` and no such identifier is in \
                     the tree. A claim without its code is the failure this gate exists for: \
                     either deliver it or take the line out of the message."
                ));
            }
        }
    }
    let total: usize = claims.iter().map(|c| c.names.len()).sum();
    Ok(format!(
        "delivery-presence OK: {total} claimed identifier(s) present in {} block(s)",
        claims.len()
    ))
}

fn canary_accepts() -> Result<(), String> {
    let tree = "pub fn intake_root_for_header() {}\nfn hidden() {}\n";
    let present = |n: &str| Ok(name_present(tree, n).then_some(()).is_some());

    // No claim: silent, not a pass that pretends to check.
    let out = run_on_body("just a message with no claim", &present)?;
    if !out.contains("nothing to check") {
        return Err(String::from("canary: a body with no claim must say so"));
    }

    // A claimed name that exists passes.
    run_on_body("DELIVERS:\nintake_root_for_header\n", &present)?;

    // A claimed name that does not exist fails, and names it.
    let err = run_on_body("DELIVERS:\nsymbol_that_is_not_there\n", &present)
        .expect_err("canary: a missing claim must fail");
    if !err.contains("symbol_that_is_not_there") {
        return Err(String::from(
            "canary: the failure must name the missing symbol",
        ));
    }

    // A substring of a real name is not a match: the claim is for the item.
    let err = run_on_body("DELIVERS:\nintake_root\n", &present)
        .expect_err("canary: a prefix of a real name is not the real name");
    if !err.contains("intake_root") {
        return Err(String::from(
            "canary: a partial name must be reported as missing",
        ));
    }

    // An empty claim block is a mistake that reads as a satisfied check.
    let err = run_on_body("DELIVERS:\n\nrest of the message\n", &present)
        .expect_err("canary: an empty claim must fail");
    if !err.contains("names nothing") {
        return Err(String::from(
            "canary: an empty block must say it names nothing",
        ));
    }

    // The block ends at the next section header, so a header line is not a name.
    run_on_body(
        "DELIVERS:\nintake_root_for_header\n\nSCOPE:\nnot-a-name\n",
        &present,
    )?;

    // Case is part of the name.
    if name_present(tree, "INTAKE_ROOT_FOR_HEADER") {
        return Err(String::from("canary: the check must be case-sensitive"));
    }
    Ok(())
}

pub fn self_test() -> Result<String, String> {
    canary_accepts()?;

    Ok(String::from(
        "delivery-presence canary OK (a claim that is present PASSes, a missing one FAILs and \
         names itself, a prefix FAILs, an empty block FAILs, a section header ends the block, \
         matching is word-bounded and case-sensitive, no claim is silent rather than green).",
    ))
}
