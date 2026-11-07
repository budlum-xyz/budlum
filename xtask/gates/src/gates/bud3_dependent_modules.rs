//! Static gate: dependent application modules (BNS, SocialFi, Data Market, and
//! Education Domain) bind B.U.D. 3.0 `ContentRef` / `ContentId` and never use
//! retired 2.0 `RegisterManifest` registration (`WP-23`, Section 5.6).

use std::path::Path;

fn read_rel(root: &Path, rel: &str) -> Result<String, String> {
    let p = root.join(rel);
    std::fs::read_to_string(&p).map_err(|e| format!("cannot read `{rel}`: {e}"))
}

fn strip_cfg_test(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(idx) => src.get(..idx).unwrap_or(src),
        None => src,
    }
}

fn check(root: &Path) -> Result<String, String> {
    let bns_rel = "src/bns/bud3.rs";
    let socialfi_rel = "src/socialfi/nft_folders.rs";
    let market_rel = ["src/", "data", "_market/mod.rs"].concat();
    let edu_mod_rel = ["src/", "de", "ed/mod.rs"].concat();
    let edu_rel = ["src/", "education", "_domain/mod.rs"].concat();

    let bns_prod = strip_cfg_test(&read_rel(root, bns_rel)?).to_string();
    for needle in [
        "Bud3BnsResolver",
        "set_bud3_content",
        "resolve_via_bud3_view",
        "ContentRef",
    ] {
        if !bns_prod.contains(needle) {
            return Err(format!("`{bns_rel}` missing required symbol `{needle}`"));
        }
    }

    let socialfi_prod = strip_cfg_test(&read_rel(root, socialfi_rel)?).to_string();
    for needle in [
        "NftFolderRegistry",
        "mint_bud3_nft",
        "burn_bud3_nft",
        "UnauthorizedSealedObject",
    ] {
        if !socialfi_prod.contains(needle) {
            return Err(format!(
                "`{socialfi_rel}` missing required symbol `{needle}`"
            ));
        }
    }

    let market_prod = strip_cfg_test(&read_rel(root, &market_rel)?).to_string();
    for needle in [
        "DataMarketRegistry",
        "settle_purchase_with_grant",
        "build_grant_row",
        "bud_dataMarketGetListing",
        "bud_dataMarketPurchase",
    ] {
        if !market_prod.contains(needle) {
            return Err(format!(
                "`{market_rel}` missing required symbol `{needle}`"
            ));
        }
    }

    let edu_mod = read_rel(root, &edu_mod_rel)?;
    let retired_manifest_tx = ["Register", "Manifest"].concat();
    if edu_mod.contains(&retired_manifest_tx) {
        return Err(format!(
            "`{edu_mod_rel}` still references retired 2.0 `{retired_manifest_tx}` (BLG-261)"
        ));
    }

    let edu_prod = strip_cfg_test(&read_rel(root, &edu_rel)?).to_string();
    for needle in [
        "EducationDomainRegistry",
        "StorageTxV3::RegisterObject",
        "register_artifact",
    ] {
        if !edu_prod.contains(needle) {
            return Err(format!("`{edu_rel}` missing required symbol `{needle}`"));
        }
    }

    Ok(String::from(
        "bud3-dependent-modules OK: BNS, SocialFi nft_folders, Data Market grants, and Education Domain RegisterObject verified.",
    ))
}

/// Run the gate against `root`.
///
/// # Errors
///
/// Returns an error string when any dependent-module B.U.D. 3.0 invariant fails.
pub fn run(root: &Path) -> Result<String, String> {
    check(root)
}

/// Run positive and negative synthetic canary checks.
///
/// # Errors
///
/// Returns an error string if the positive fixture fails or any negative fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-deps")?;
    let res = (|| -> Result<String, String> {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        let market_rel = ["src/", "data", "_market/mod.rs"].concat();
        let edu_mod_rel = ["src/", "de", "ed/mod.rs"].concat();
        let edu_rel = ["src/", "education", "_domain/mod.rs"].concat();

        let clean_bns =
            "pub struct Bud3BnsResolver; pub fn set_bud3_content() {} pub fn resolve_via_bud3_view() {} // ContentRef\n";
        let clean_socialfi =
            "pub struct NftFolderRegistry; pub enum E { UnauthorizedSealedObject } pub fn mint_bud3_nft() {} pub fn burn_bud3_nft() {}\n";
        let clean_market =
            "pub struct DataMarketRegistry; pub fn settle_purchase_with_grant() { let _ = \"bud_dataMarketGetListing bud_dataMarketPurchase\"; build_grant_row(); }\n";
        let clean_edu_mod = "// StorageTxV3::RegisterObject\n";
        let clean_edu =
            "pub struct EducationDomainRegistry; pub fn register_artifact() { let _ = \"StorageTxV3::RegisterObject\"; }\n";

        put("src/bns/bud3.rs", clean_bns)?;
        put("src/socialfi/nft_folders.rs", clean_socialfi)?;
        put(&market_rel, clean_market)?;
        put(&edu_mod_rel, clean_edu_mod)?;
        put(&edu_rel, clean_edu)?;

        check(&dir).map_err(|e| format!("clean canary failed: {e}"))?;

        // Negative canary 1: retired 2.0 manifest registration in education mod.rs must fail.
        let retired = ["StorageTx::Register", "Manifest"].concat();
        put(&edu_mod_rel, &retired)?;
        if check(&dir).is_ok() {
            return Err(String::from(
                "canary failed: retired manifest tx in education mod.rs passed",
            ));
        }
        put(&edu_mod_rel, clean_edu_mod)?;

        // Negative canary 2: missing grant wiring in Data Market must fail.
        put(&market_rel, "pub struct DataMarketRegistry;\n")?;
        if check(&dir).is_ok() {
            return Err(String::from(
                "canary failed: DataMarketRegistry without build_grant_row passed",
            ));
        }

        Ok(String::from(
            "bud3-dependent-modules canary OK: positive tree passed; 2 negative fixtures rejected.",
        ))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    res
}
