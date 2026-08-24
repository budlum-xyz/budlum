//! The storage challenge verifier cannot slash on a rejection it cannot
//! justify.
//!
//! Ported from `scripts/check-uncheckable-proof-paths-do-not-slash.sh`. While
//! `storage_challenge_proofs_are_checkable()` is false, a proof-carrying
//! answer must not move the bond (`Ok(())` under the `!flag` guard), a
//! no-proof answer must still be `Err` (Mismatched), the flag must be a plain
//! constant `false`, and the two named containment tests must exist.
//!
//! The Strix CWE-184 hardening is kept: the scan runs on a literal- and
//! comment-scrubbed view (literals first, then block comments with a depth
//! counter, then line comments), so prose that merely names the guard cannot
//! satisfy a check about the guard.

use std::fmt::Write as _;
use std::path::Path;

use super::rust_literals;

fn code_of(root: &Path) -> Result<String, String> {
    let f = root.join("src/domain/storage_deal.rs");
    if !f.is_file() {
        return Err(format!("no storage_deal.rs at {}", f.display()));
    }
    let src = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    Ok(rust_literals::scrub(&src))
}

fn has_fn(code: &str, name: &str) -> bool {
    code.contains(&format!("fn {name}("))
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let code = code_of(root)?;
    let flag = "storage_challenge_proofs_are_checkable";
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    // The flag is a plain constant `false`. Line-based: find the line that
    // defines `fn <flag>() -> bool {`, then the first non-empty line inside
    // the body must be `false`.
    let flag_value: Option<bool> = {
        let needle = format!("fn {flag}()");
        match code.lines().position(|l| l.contains(&needle)) {
            None => None,
            Some(def_idx) => code
                .lines()
                .skip(def_idx + 1)
                .find(|l| !l.trim().is_empty())
                .map(|l| l.trim() == "false"),
        }
    };
    // `flag_value` is `Some(true)` when the body is exactly `false`, i.e.
    // the flag is correctly closed; `Some(false)` means the flag now reports
    // `true`.
    match flag_value {
        None => problems.push(format!(
            "`{flag}` is missing or is no longer a plain constant. It gates whether \
             a storage challenge proof can be checked at all; if it became \
             configurable, an operator could switch on a verifier that rejects \
             honest work and slashes for it."
        )),
        Some(true) => checked += 1,
        Some(false) => problems.push(format!(
            "`{flag}` now reports true. If the path really can state an honest \
             proof, this gate and the two tests it names have to be rewritten \
             deliberately rather than left pointing at a rule that no longer \
             holds. That rewrite is the point of failing here."
        )),
    }

    // The `(Some, Some)` arm is guarded by `!Self::flag()`.
    let guard = code.find(&format!("if !Self::{flag}() => Ok(())"));
    if let Some(guard_pos) = guard {
        checked += 1;
        let verify_arm = code.find("DefaultAdapter::verify");
        if verify_arm.is_some_and(|v| guard_pos > v) {
            problems.push(format!(
                "the `{flag}` guard appears after `DefaultAdapter::verify` is \
                 reached, so it does not gate anything."
            ));
        } else {
            checked += 1;
        }
    } else {
        problems.push(format!(
            "the `(Some, Some)` arm of the verification match is not guarded by \
             `!Self::{flag}()`. Without that guard a proof-carrying answer reaches \
             a verifier that rejects everything, and the caller reads the rejection \
             as a wrong answer and takes the operator's bond."
        ));
    }

    // No-proof arm returns Err.
    if code.contains("(Some(_), None) => Err(") {
        checked += 1;
    } else {
        problems.push(
            "the no-proof arm no longer returns `Err`. An answer with no proof is a \
             fact about the answer rather than a limitation of the verifier, so it \
             must still resolve as `Mismatched` and cost the bond. A carve-out that \
             swallows this case makes every wrong answer free."
                .to_string(),
        );
    }

    // The two containment tests exist.
    for (name, why) in [
        (
            "an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable",
            "the containment itself: a proof-carrying answer must not move the bond while the verifier cannot state an honest proof",
        ),
        (
            "the_unverifiable_proof_carve_out_does_not_cover_a_missing_proof",
            "the boundary: an answer with no proof must still slash",
        ),
    ] {
        if has_fn(&code, name) {
            checked += 1;
        } else {
            problems.push(format!("the test `{name}` is gone. It holds {why}."));
        }
    }

    if checked == 0 {
        return Err(String::from("gate checked nothing"));
    }
    if !problems.is_empty() {
        let mut msg = String::new();
        for p in problems {
            writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "uncheckable-proof containment OK: {checked} checks, the storage challenge \
         verifier cannot slash on a rejection it cannot justify"
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
        "budlum-gates-uncheck-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(dir.join("src/domain"));

    let good = "pub(crate) fn storage_challenge_proofs_are_checkable() -> bool {\n    false\n}\nfn f() {\n    match (a, b) {\n        (Some(_), Some(_)) if !Self::storage_challenge_proofs_are_checkable() => Ok(()),\n        (Some(_), None) => Err(StorageError::InvalidMerkleProof(\"x\".into())),\n        (None, _) => Ok(()),\n    }\n    DefaultAdapter::verify(&e, &i, &p);\n}\nfn an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable() {}\nfn the_unverifiable_proof_carve_out_does_not_cover_a_missing_proof() {}\n";
    std::fs::write(dir.join("src/domain/storage_deal.rs"), good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a contained tree was refused"));
    }

    // Bad: flag reports true.
    let bad = good.replace("    false\n", "    true\n");
    std::fs::write(dir.join("src/domain/storage_deal.rs"), bad).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a true flag passed"));
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "uncheckable-proof canary OK (contained PASSes, a true flag FAILs).",
    ))
}
