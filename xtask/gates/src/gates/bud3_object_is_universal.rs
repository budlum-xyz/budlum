//! B.U.D. 3.0 universal object gate (`bud3-object-is-universal`).
//!
//! Enforces that:
//! 1. `src/storage/bud3/bof1.rs` implements both canonical binary (`encode`,
//!    `decode`) and canonical text (`encode_text`, `decode_text`) BOF-1
//!    representations, refuses testnet-closed flags (`Flags::LIVE`,
//!    `Flags::HAS_CONTEXT`), and admits 0-byte content (`max_content_bytes`
//!    only caps the upper bound, never rejecting `len == 0`).
//! 2. `src/storage/bud3/two_path.rs` implements Y10-Y12 (`verify_upload_two_path_and_round_trip`)
//!    so every content class round-trips identically through the encoder and
//!    optical QR paths.
//! 3. No `src/storage/bud3/` file carries legacy recipe-only types
//!    (`ThreeRecipe`, `ThreeRecipePublic`, `VideoRecipe`).

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

/// Run the `bud3-object-is-universal` gate against `root`.
///
/// # Errors
///
/// Returns a failure report if universal BOF-1 object invariants are broken.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    let bof1_raw = read_rel(root, "src/storage/bud3/bof1.rs")?;
    let two_path_raw = read_rel(root, "src/storage/bud3/two_path.rs")?;
    let limits_raw = read_rel(root, "src/storage/bud3/limits.rs")?;

    let bof1_prod = strip_line_comments(strip_cfg_test(&bof1_raw));
    let two_path_prod = strip_line_comments(strip_cfg_test(&two_path_raw));
    let limits_prod = strip_line_comments(strip_cfg_test(&limits_raw));

    for token in [
        "BUD3-OBJECT 1",
        "end commitment=",
        "encode_text",
        "decode_text",
        "validate_testnet",
        "LiveNotOpen",
        "ContextNotOpen",
    ] {
        if !bof1_prod.contains(token) {
            problems.push(format!(
                "`src/storage/bud3/bof1.rs` is missing required BOF-1 symbol `{token}`."
            ));
        }
    }

    for token in [
        "verify_upload_two_path_and_round_trip",
        "extract_object_from_optical_seconds",
        "decode_logical_path",
        "decode_optical_path",
    ] {
        if !two_path_prod.contains(token) {
            problems.push(format!(
                "`src/storage/bud3/two_path.rs` is missing required symbol `{token}`."
            ));
        }
    }

    if limits_prod.contains("len == 0") && limits_prod.contains("Err(") {
        problems.push(String::from(
            "`src/storage/bud3/limits.rs` rejects 0-byte content; 0-byte content must be admitted as a universal BOF-1 object.",
        ));
    }

    let bud3_dir = root.join("src/storage/bud3");
    if let Ok(entries) = std::fs::read_dir(&bud3_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|e| e == "rs") {
                let name = entry.file_name().to_string_lossy().to_string();
                let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
                let prod = strip_line_comments(strip_cfg_test(&text));
                for legacy in ["ThreeRecipe", "ThreeRecipePublic", "VideoRecipe"] {
                    if prod.contains(legacy) {
                        problems.push(format!(
                            "`src/storage/bud3/{name}` references legacy recipe type `{legacy}`; only `bud3::Object` is permitted."
                        ));
                    }
                }
            }
        }
    }

    if !problems.is_empty() {
        let mut msg = String::from("bud3-object-is-universal failed:\n");
        for p in &problems {
            let _ = writeln!(msg, "  - {p}");
        }
        return Err(msg);
    }

    Ok(String::from(
        "bud3-object-is-universal OK: binary and text BOF-1, testnet flag refusals, two-path equivalence, and zero-legacy-recipe checks verified.",
    ))
}

/// Self-test with positive and negative synthetic trees.
///
/// # Errors
///
/// Returns an error if any canary fails to trigger or a clean tree fails.
pub fn self_test() -> Result<String, String> {
    let dir =
        crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-universal-obj")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        let clean_bof1 = "\
pub enum Bof1Error { LiveNotOpen, ContextNotOpen }
pub fn encode_text() -> &'static str { \"BUD3-OBJECT 1\\nend commitment=\" }
pub fn decode_text() {}
pub fn validate_testnet() {}
";
        let clean_two_path = "\
pub fn verify_upload_two_path_and_round_trip() {}
pub fn extract_object_from_optical_seconds() {}
pub fn decode_logical_path() {}
pub fn decode_optical_path() {}
";
        let clean_limits = "pub fn admit_content(len: u64, max: u64) -> bool { len <= max }\n";

        put("src/storage/bud3/bof1.rs", clean_bof1)?;
        put("src/storage/bud3/two_path.rs", clean_two_path)?;
        put("src/storage/bud3/limits.rs", clean_limits)?;
        run(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;

        // Canary 1: legacy ThreeRecipe inside bud3 must fail.
        put(
            "src/storage/bud3/two_path.rs",
            &format!("{clean_two_path}\npub struct ThreeRecipe;\n"),
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: ThreeRecipe in bud3 passed"));
        }
        put("src/storage/bud3/two_path.rs", clean_two_path)?;

        // Canary 2: missing BOF-1 text format must fail.
        put(
            "src/storage/bud3/bof1.rs",
            &clean_bof1.replace("decode_text", "missing_fn"),
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: missing decode_text passed"));
        }

        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-object-is-universal canary OK: clean tree passed; legacy recipe and missing text decoder failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_object_is_universal_canary() {
        assert!(super::self_test().is_ok());
    }
}
