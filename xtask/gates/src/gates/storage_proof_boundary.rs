//! The storage challenge proof path must stay behind the production
//! boundary.
//!
//! Ported from `scripts/check-storage-proof-production-boundary.sh`. The
//! challenge-answer verifier must be mandatory (`verify_answer_challenge_zk_proof`),
//! the mock proof must be test-only (`cfg!(test) && proof_bytes ==
//! "test-mock-proof"`), a wrong answer must produce `ChallengeOutcome::Mismatched`,
//! and the bond must be burned for it.

use std::path::Path;

fn code_of(root: &Path, rel: &str) -> Result<String, String> {
    let f = root.join(rel);
    if !f.is_file() {
        return Err(format!("expected file missing: {}", f.display()));
    }
    std::fs::read_to_string(&f).map_err(|e| e.to_string())
}

/// Production lines (before the first test module) that name the mock proof
/// without the `cfg!(test)` guard.
fn unguarded_mock_sites(src: &str) -> usize {
    let production = src.split("\n#[cfg(test)]").next().unwrap_or(src);
    production
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| l.contains("test-mock-proof") && !l.contains("cfg!(test) &&"))
        .count()
}

/// # Errors
///
/// Returns the first violated claim.
pub fn run(root: &Path) -> Result<String, String> {
    let src = code_of(root, "src/domain/storage_deal.rs")?;
    let actor = code_of(root, "src/chain/chain_actor.rs")?;

    for (needle, msg) in [
        (
            "verify_answer_challenge_zk_proof",
            "verify_answer_challenge_zk_proof not found in storage_deal.rs",
        ),
        (
            "DefaultAdapter::verify",
            "DefaultAdapter::verify not found in storage_deal.rs",
        ),
        ("proof_bytes", "proof_bytes field not found in storage_deal.rs"),
        (
            "cfg!(test) && proof_bytes == b\"test-mock-proof\"",
            "cfg!(test) guard for test-mock-proof not found - production may accept mock proofs",
        ),
        (
            "ChallengeOutcome::Mismatched",
            "storage_deal.rs never produces ChallengeOutcome::Mismatched - a wrong answer costs the operator nothing",
        ),
    ] {
        if !src.contains(needle) {
            return Err(msg.to_string());
        }
    }
    if unguarded_mock_sites(&src) > 0 {
        return Err(String::from(
            "storage_deal.rs names test-mock-proof in production code outside the cfg!(test) guard",
        ));
    }
    let root_bound = src.contains("storage_root") && src.contains("proof_bytes")
        || src.contains("storage_root.is_some");
    if !root_bound {
        return Err(String::from("storage_root + proof_bytes binding not found"));
    }
    if !actor.contains("apply_storage_bond_slash") {
        return Err(String::from(
            "chain_actor.rs does not burn the bond for a Mismatched answer - the slash is recorded but never applied",
        ));
    }
    Ok(String::from(
        "Storage proof production boundary OK: STARK verification mandatory, test-mock-proof only in cfg!(test), a failed proof slashes the operator bond.",
    ))
}

/// # Errors
///
/// Returns a finding when the gate accepts a broken copy of the real tree.
pub fn self_test() -> Result<String, String> {
    let root = std::env::var_os("BUDLUM_ROOT").map_or_else(
        || std::env::current_dir().unwrap_or_default(),
        std::path::PathBuf::from,
    );
    if !root.join("src/domain/storage_deal.rs").is_file() {
        return Err(String::from(
            "canary: real tree not found (run from the repo root)",
        ));
    }
    let tmp = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-spb")?;
    for sub in ["src/domain", "src/chain"] {
        std::fs::create_dir_all(tmp.join(sub)).map_err(|e| e.to_string())?;
    }
    std::fs::copy(
        root.join("src/domain/storage_deal.rs"),
        tmp.join("src/domain/storage_deal.rs"),
    )
    .map_err(|e| e.to_string())?;
    std::fs::copy(
        root.join("src/chain/chain_actor.rs"),
        tmp.join("src/chain/chain_actor.rs"),
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: an unmodified copy was refused"));
    }
    // Break: never produce Mismatched.
    let deal = tmp.join("src/domain/storage_deal.rs");
    let text = std::fs::read_to_string(&deal).map_err(|e| e.to_string())?;
    std::fs::write(
        &deal,
        text.replace("ChallengeOutcome::Mismatched", "ChallengeOutcome::Answered"),
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a tree that produces no Mismatched passed",
        ));
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(String::from(
        "Storage proof boundary canary OK (clean PASSes, broken FAILs).",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unguarded_mock_proof_in_production_is_counted() {
        let guarded = "fn a() {\n    if cfg!(test) && proof_bytes == b\"test-mock-proof\" {}\n}\n";
        assert_eq!(unguarded_mock_sites(guarded), 0);
        let open =
            format!("{guarded}fn b() {{\n    if proof_bytes == b\"test-mock-proof\" {{}}\n}}\n");
        assert_eq!(unguarded_mock_sites(&open), 1);
        let in_tests = format!(
            "{guarded}\n#[cfg(test)]\nmod t {{ const P: &[u8] = b\"test-mock-proof\"; }}\n"
        );
        assert_eq!(unguarded_mock_sites(&in_tests), 0);
    }
}
