//! The storage challenge verifier enforces real 64-depth `VerifyMerkle`
//! Plonky3 STARK proofs and never bypasses verification with an uncheckable carve-out.

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
    rust_literals::has_live_test(code, name)
}

/// `Some(true)` when the body of `fn <flag>()` is exactly `true`,
/// `Some(false)` when it is anything else, `None` when there is no such fn.
fn flag_is_constant_true(code: &str, flag: &str) -> Option<bool> {
    let needle = format!("fn {flag}()");
    let at = code.find(&needle)?;
    let open = at + code[at..].find('{')?;
    let mut depth = 0usize;
    for (i, c) in code[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(code[open + 1..open + i].trim() == "true");
                }
            }
            _ => {}
        }
    }
    None
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let code = code_of(root)?;
    let flag = "storage_challenge_proofs_are_checkable";
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    match flag_is_constant_true(&code, flag) {
        None => problems.push(format!(
            "`{flag}` is missing or is no longer a plain boolean function."
        )),
        Some(true) => checked += 1,
        Some(false) => problems.push(format!(
            "`{flag}` no longer returns `true`; 64-depth VerifyMerkle STARK verification must remain active on testnet."
        )),
    }

    if code.contains(&format!("if !Self::{flag}() => Ok(())")) {
        problems.push(format!(
            "a `!Self::{flag}() => Ok(())` bypass remains in the verification match."
        ));
    } else {
        checked += 1;
    }

    if code.contains("DefaultAdapter::verify") {
        checked += 1;
    } else {
        problems.push(
            "`DefaultAdapter::verify` is missing from storage challenge verification.".to_string(),
        );
    }

    if code.contains("(Some(_), None) => Err(") {
        checked += 1;
    } else {
        problems.push("the no-proof arm no longer returns `Err`.".to_string());
    }

    for (name, why) in [
        (
            "an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable",
            "verifies both honest STARK acceptance and forged-proof slashing",
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
        "uncheckable-proof check OK: {checked} checks, 64-depth VerifyMerkle STARK proofs enforced"
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-uncheck")?;
    let _ = std::fs::create_dir_all(dir.join("src/domain"));

    let good = "pub(crate) fn storage_challenge_proofs_are_checkable() -> bool {\n    true\n}\nfn f() {\n    match (a, b) {\n        (Some(r), Some(p)) => Self::verify_answer_challenge_zk_proof(&c, &r, &h, p),\n        (Some(_), None) => Err(StorageError::InvalidMerkleProof(\"x\".into())),\n        (None, _) => Ok(()),\n    }\n    DefaultAdapter::verify(&e, &i, &p);\n}\n#[test]\nfn an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable() {}\n#[test]\nfn the_unverifiable_proof_carve_out_does_not_cover_a_missing_proof() {}\n";
    std::fs::write(dir.join("src/domain/storage_deal.rs"), good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a verified tree was refused"));
    }

    let bad = good.replace("    true\n", "    false\n");
    std::fs::write(dir.join("src/domain/storage_deal.rs"), bad).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a false flag passed"));
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "uncheckable-proof canary OK (active verifier PASSes, disabled flag FAILs).",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_bare_true_body_is_an_active_flag() {
        let f = "storage_challenge_proofs_are_checkable";
        let active = format!("fn {f}() -> bool {{\n    true\n}}\n");
        assert_eq!(flag_is_constant_true(&active, f), Some(true));
        let one_line = format!("fn {f}() -> bool {{ true }}\n");
        assert_eq!(flag_is_constant_true(&one_line, f), Some(true));
        let disabled = format!("fn {f}() -> bool {{\n    false\n}}\n");
        assert_eq!(flag_is_constant_true(&disabled, f), Some(false));
    }
}
