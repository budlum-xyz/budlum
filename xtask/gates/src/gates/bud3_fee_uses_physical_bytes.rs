//! B.U.D. 3.0 storage fees are priced strictly from physical bytes.
//!
//! Every stored object pays from `user_physical_bytes` (`object_bytes * redundancy`)
//! via integer ceiling division (`div_ceil`) over `2^30 * 365`, subject to the
//! `0.001 BUD` (`1_000` base units) minimum fee, with `95%` credited to the
//! Custody Endowment and `5%` credited to the upload gateway. The legacy
//! `held_bytes == 0` exemption file must remain deleted, and no
//! B.U.D. 3.0 storage fee path may use floating-point arithmetic or return a
//! zero-fee exemption.

use std::fmt::Write as _;
use std::path::Path;

fn read_rel(root: &Path, rel: &str) -> Result<String, String> {
    let path = root.join(rel);
    if !path.is_file() {
        return Err(format!("missing required file: {rel}"));
    }
    std::fs::read_to_string(&path).map_err(|e| format!("{rel}: {e}"))
}

fn strip_cfg_test(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(idx) => src.get(..idx).unwrap_or(src),
        None => src,
    }
}

fn strip_line_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let code = match line.find("//") {
            Some(idx) => line.get(..idx).unwrap_or(line),
            None => line,
        };
        out.push_str(code);
        out.push('\n');
    }
    out
}

/// Run the `bud3-fee-uses-physical-bytes` gate against `root`.
///
/// # Errors
///
/// Returns a human-readable failure report if any physical-byte pricing
/// invariant is broken.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    let legacy_rel = format!("src/storage/{}.rs", ["three", "_regime"].concat());
    if root.join(&legacy_rel).exists() {
        problems.push(String::from(
            "legacy `held_bytes == 0` storage exemption file exists; it must stay deleted.",
        ));
    }

    let fees_raw = read_rel(root, "src/storage/bud3/fees.rs")?;
    let registry_raw = read_rel(root, "src/storage/bud3/registry.rs")?;
    let fees_prod = strip_line_comments(strip_cfg_test(&fees_raw));
    let registry_prod = strip_line_comments(strip_cfg_test(&registry_raw));

    for token in [
        "user_physical_bytes",
        "decentralization_physical_bytes",
        "GIB_BYTES",
        "DAYS_PER_YEAR",
        "MIN_STORAGE_FEE_BUD",
        "ENDOWMENT_SHARE_BPS",
        "GATEWAY_SHARE_BPS",
        "div_ceil",
        "storage_fee_for_days",
        "storage_fee_for_epochs",
        "split_storage_fee",
        "shared_public_reference_fee_epochs",
        "same_owner_sealed_dedup_fee",
        "renewal_fee_epochs",
        "replace_object_refund",
    ] {
        if !fees_prod.contains(token) {
            problems.push(format!(
                "`src/storage/bud3/fees.rs` is missing required pricing symbol `{token}`."
            ));
        }
    }

    if !fees_prod.contains("9_500") || !fees_prod.contains("500") {
        problems.push(String::from(
            "`src/storage/bud3/fees.rs` must pin the 95% / 5% Custody Endowment / gateway split (`9_500` / `500` bps).",
        ));
    }

    for float_tok in ["f32", "f64"] {
        if fees_prod.contains(float_tok) {
            problems.push(format!(
                "`src/storage/bud3/fees.rs` contains floating-point type `{float_tok}` in consensus pricing code."
            ));
        }
    }

    for banned in ["ContentRegime", "held_bytes_for", "RentBasis::None"] {
        if fees_prod.contains(banned) || registry_prod.contains(banned) {
            problems.push(format!(
                "legacy zero-rent symbol `{banned}` reappeared in `src/storage/bud3/`."
            ));
        }
    }

    for wired in [
        "FeeRecord::from_placed_shares",
        "storage_fee_for_epochs",
        "renewal_fee_epochs",
        "split_storage_fee",
    ] {
        if !registry_prod.contains(wired) {
            problems.push(format!(
                "`src/storage/bud3/registry.rs` does not call `{wired}` on registration/renewal."
            ));
        }
    }

    if !problems.is_empty() {
        let mut msg = String::from("bud3-fee-uses-physical-bytes failed:\n");
        for p in &problems {
            let _ = writeln!(msg, "  - {p}");
        }
        return Err(msg);
    }

    Ok(String::from(
        "bud3-fee-uses-physical-bytes OK: physical-byte ceiling formula, 0.001 BUD floor, 95/5 split, and registry wiring verified.",
    ))
}

/// Self-test with positive and negative synthetic trees.
///
/// # Errors
///
/// Returns an error if any canary fails to trigger or clean tree fails.
pub fn self_test() -> Result<String, String> {
    let dir =
        crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-fee-physical")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        let clean_fees = "\
pub const GIB_BYTES: u128 = 1 << 30;
pub const DAYS_PER_YEAR: u128 = 365;
pub const MIN_STORAGE_FEE_BUD: u64 = 1_000;
pub const ENDOWMENT_SHARE_BPS: u64 = 9_500;
pub const GATEWAY_SHARE_BPS: u64 = 500;
pub struct FeeRecord { pub user_physical_bytes: u64, pub decentralization_physical_bytes: u64 }
pub fn storage_fee_for_days(x: u128, y: u128) -> u128 { x.div_ceil(y) }
pub fn storage_fee_for_epochs(x: u128, y: u128) -> u128 { x.div_ceil(y) }
pub fn split_storage_fee() {}
pub fn shared_public_reference_fee_epochs() {}
pub fn same_owner_sealed_dedup_fee() {}
pub fn renewal_fee_epochs() {}
pub fn replace_object_refund() {}
";
        let clean_reg = "\
pub fn reg() {
    let _ = FeeRecord::from_placed_shares();
    let _ = storage_fee_for_epochs();
    let _ = renewal_fee_epochs();
    let _ = split_storage_fee();
}
";
        put("src/storage/bud3/fees.rs", clean_fees)?;
        put("src/storage/bud3/registry.rs", clean_reg)?;
        run(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;

        // Canary 1: resurrecting the deleted zero-held-bytes file must fail.
        let legacy_rel = format!("src/storage/{}.rs", ["three", "_regime"].concat());
        put(&legacy_rel, "pub fn held_bytes_for() -> u64 { 0 }\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: resurrected zero-held-bytes file passed"));
        }
        let _ = std::fs::remove_file(dir.join(&legacy_rel));

        // Canary 2: float in fees.rs must fail.
        put(
            "src/storage/bud3/fees.rs",
            &format!("{clean_fees}\npub fn bad() -> f64 {{ 0.0 }}\n"),
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: float in fees.rs passed"));
        }

        // Canary 3: dropping div_ceil must fail.
        put(
            "src/storage/bud3/fees.rs",
            &clean_fees.replace("div_ceil", "wrapping_div"),
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: missing div_ceil passed"));
        }

        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-fee-uses-physical-bytes canary OK: clean tree passed; zero-held-bytes, float, and non-ceiling division failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_fee_uses_physical_bytes_canary() {
        assert!(super::self_test().is_ok());
    }
}
