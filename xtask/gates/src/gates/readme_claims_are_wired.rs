//! Verifies that every working subsystem claimed in `README.md` is backed by a real
//! production module and test in the repository, and that all relative Markdown links
//! in `README.md` and `README.tr.md` resolve on disk.

use std::path::Path;

/// `(claimed_phrase_in_readme, production_file, production_symbol, test_file, test_fn)`
const WIRED_CLAIMS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "B.U.D. 3.0",
        "src/storage/bud3/pipeline.rs",
        "pub fn prepare_public_upload",
        "src/tests/bud3_door.rs",
        "fn ",
    ),
    (
        "Committee of up to 128 seats",
        "src/validators/committee.rs",
        "COMMITTEE_MAX_SEATS",
        "src/tests/finality_live_path.rs",
        "fn ",
    ),
    (
        "EVM, CosmWasm, SVM, Move and BudZero",
        "src/execution/coordinator/mod.rs",
        "ExecutionCoordinator",
        "src/tests/conformance_locks.rs",
        "fn uel_conformance_evm",
    ),
    (
        "pointers that hold no balance",
        "src/execution/coordinator/assets/mod.rs",
        "POINTER_BYTECODE_PREFIX",
        "src/execution/coordinator/uel_wp27_wp29_wp30_tests.rs",
        "fn ",
    ),
    (
        "Android",
        "mobile/core/src/lib.rs",
        "pub ",
        "src/tests/regression_ops_crypto.rs",
        "fn android_reproducible_build_matches",
    ),
];

fn verify_markdown_links(root: &Path, rel: &str, text: &str) -> Result<usize, String> {
    let mut checked = 0_usize;
    for (line_no, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(open) = rest.find("](") {
            let after = rest.get(open + 2..).unwrap_or("");
            let Some(close) = after.find(')') else {
                break;
            };
            let target_raw = after.get(..close).unwrap_or("").trim();
            rest = after.get(close + 1..).unwrap_or("");
            let target = target_raw.split('#').next().unwrap_or("").trim();
            if target.is_empty()
                || target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
            {
                continue;
            }
            checked += 1;
            if !root.join(target).exists() {
                return Err(format!(
                    "{rel}:{}: broken relative link `{target}`",
                    line_no + 1
                ));
            }
        }
    }
    Ok(checked)
}

/// Checks every wired README claim and relative Markdown link in `README.md` and `README.tr.md`.
///
/// # Errors
///
/// Returns an error if a claimed phrase, production module, test file, or relative link is missing.
pub fn run(root: &Path) -> Result<String, String> {
    let readme_en = std::fs::read_to_string(root.join("README.md"))
        .map_err(|e| format!("cannot read README.md: {e}"))?;
    let readme_tr = std::fs::read_to_string(root.join("README.tr.md"))
        .map_err(|e| format!("cannot read README.tr.md: {e}"))?;

    for &(claim, prod_rel, prod_sym, test_rel, test_sym) in WIRED_CLAIMS {
        if !readme_en.contains(claim) {
            return Err(format!(
                "README.md no longer contains expected capability phrase `{claim}`; update readme_claims_are_wired"
            ));
        }
        let prod_src = std::fs::read_to_string(root.join(prod_rel))
            .map_err(|e| format!("claim `{claim}` production file {prod_rel} missing: {e}"))?;
        if !prod_src.contains(prod_sym) {
            return Err(format!(
                "claim `{claim}` production file {prod_rel} does not contain `{prod_sym}`"
            ));
        }
        let test_src = std::fs::read_to_string(root.join(test_rel))
            .map_err(|e| format!("claim `{claim}` test file {test_rel} missing: {e}"))?;
        if !test_src.contains(test_sym) {
            return Err(format!(
                "claim `{claim}` test file {test_rel} does not contain `{test_sym}`"
            ));
        }
    }

    let en_links = verify_markdown_links(root, "README.md", &readme_en)?;
    let tr_links = verify_markdown_links(root, "README.tr.md", &readme_tr)?;
    if en_links == 0 || tr_links == 0 {
        return Err(String::from("vacuous link scan: zero relative links found"));
    }

    Ok(format!(
        "README claims & links OK: {} capability claims wired, {en_links} EN + {tr_links} TR relative links resolved.",
        WIRED_CLAIMS.len()
    ))
}

/// Canary self-test ensuring broken relative links and missing trees fail.
///
/// # Errors
///
/// Returns an error if a broken relative link is accepted.
pub fn self_test() -> Result<String, String> {
    let bad = verify_markdown_links(Path::new("."), "README.md", "See [missing](no/such/doc.md).");
    if bad.is_ok() {
        return Err(String::from("canary: broken relative link was accepted"));
    }
    if run(Path::new("/nonexistent-readme-claims-canary")).is_ok() {
        return Err(String::from("canary: missing tree was accepted"));
    }
    Ok(String::from(
        "readme-claims-are-wired self-test OK: broken link and missing tree rejected.",
    ))
}
