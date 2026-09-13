//! BUD edition Three is recipe-only: no body, no deal, sealed or public recipe.
//!
//! Hardens the product claim: `3.0` means `tarif`. Bodies are Classic/2.0. A public
//! seed is the public surface; `SealedGenerated` is the private surface
//! (seed off-chain under view-grants). Opening a deal on Three is refused.

use std::path::Path;

fn read(root: &Path, rel: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(rel)).map_err(|e| format!("read {rel}: {e}"))
}

fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// # Errors
///
/// First missing structural claim.
pub fn run(root: &Path) -> Result<String, String> {
    let gen = read(root, "src/storage/generated.rs")?;
    let deal = read(root, "src/domain/storage_deal.rs")?;
    let deal_code = strip_line_comments(&deal);

    if !gen.contains("enum BudStorageEdition") {
        return Err("BudStorageEdition missing".into());
    }
    if !gen.contains("admits_body") {
        return Err("admits_body missing".into());
    }
    if !gen.contains("SealedGenerated") {
        return Err(
            "SealedGenerated source missing - private Three recipes need sealed form".into(),
        );
    }
    if !gen.contains("struct SealedGeneratedSpec") {
        return Err("SealedGeneratedSpec missing".into());
    }
    if !gen.contains("recipe_seed_is_public") {
        return Err(
            "recipe_seed_is_public missing - must distinguish public vs sealed seed".into(),
        );
    }
    // Three check_source must allow SealedGenerated
    if !gen.contains("ContentSource::Generated(_) | ContentSource::SealedGenerated(_)")
        && !gen.contains("SealedGenerated(_) => Ok(())")
    {
        return Err("Three check_source must accept SealedGenerated".into());
    }
    // open_deal must refuse Three
    if !deal_code.contains("admits_body()") {
        return Err("open_deal must call admits_body() - Three must not open storage deals".into());
    }
    if !deal.contains("Three admits no storage deal") && !deal.contains("admits no storage deal") {
        return Err("open_deal must state Three admits no storage deal".into());
    }
    // confidential body refuse Three
    if !deal.contains("confidential body commit refused") {
        return Err("confidential body commit must refuse Three manifests".into());
    }

    Ok(
        "three-is-recipe-only OK (SealedGenerated, admits_body deal ban, confidential refuse)."
            .into(),
    )
}

/// # Errors
///
/// Canary misbehaviour.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-three")?;
    std::fs::create_dir_all(dir.join("src/storage")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir.join("src/domain")).map_err(|e| e.to_string())?;

    let good_gen = r"
enum BudStorageEdition { Classic, Three }
fn admits_body() {}
enum ContentSource { Generated(u8), SealedGenerated(u8), Stored }
fn check() { ContentSource::Generated(_) | ContentSource::SealedGenerated(_) => Ok(()); }
struct SealedGeneratedSpec {}
fn recipe_seed_is_public() {}
";
    let good_deal = r#"
fn open_deal() {
    if !manifest.edition.admits_body() {
        return Err("Three admits no storage deal");
    }
}
fn conf() { "confidential body commit refused" }
"#;
    std::fs::write(dir.join("src/storage/generated.rs"), good_gen).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("src/domain/storage_deal.rs"), good_deal).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err("canary: clean tree refused".into());
    }
    // Remove SealedGenerated
    std::fs::write(
        dir.join("src/storage/generated.rs"),
        good_gen.replace("SealedGenerated", "MissingSealed"),
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err("canary: missing SealedGenerated passed".into());
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok("three-is-recipe-only canary OK".into())
}
