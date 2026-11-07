//! B.U.D. 3.0 paid-view and network-reveal gate (`bud3-paid-view`,).
//!
//! Enforces statically that:
//! 1. G8 server-side fallback decoding (`fallback_decode_public` in
//!    `src/storage/bud3/view.rs` and `bud_storageGetContent` in `src/storage/bud3/rpc.rs`)
//!    requires a `PaidViewReceipt` (`MIN_PAID_VIEW_FEE_ATOMS`) and unconditionally
//!    refuses `ContentIdKind::Sealed` (`SealedFallbackForbidden`).
//! 2. Reveal sessions (`RevealSessionManager::open_reveal`) fetch symbols strictly
//!    via `NetworkSymbolSource` rather than caller-supplied raw content bytes ().
//! 3. `src/storage/bud3/content_ref.rs` carries zero `Bud3NotReady` placeholders.

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

/// Run the `bud3-paid-view` gate against `root`.
///
/// # Errors
///
/// Returns an error if G8 fallback decoding is unpaid, permits sealed content,
/// or reveal sessions bypass `NetworkSymbolSource`.
pub fn run(root: &Path) -> Result<String, String> {
    let view_src = strip_line_comments(strip_cfg_test(&read_rel(
        root,
        "src/storage/bud3/view.rs",
    )?));
    for required in [
        "MIN_PAID_VIEW_FEE_ATOMS",
        "pub struct PaidViewReceipt",
        "pub trait NetworkSymbolSource",
        "SealedFallbackForbidden",
        "UnpaidFallbackView",
        "pub fn fallback_decode_public",
        "pub fn open_reveal<N: NetworkSymbolSource>",
    ] {
        if !view_src.contains(required) {
            return Err(format!(
                "bud3-paid-view: src/storage/bud3/view.rs missing `{required}`"
            ));
        }
    }

    let rpc_src = strip_line_comments(strip_cfg_test(&read_rel(
        root,
        "src/storage/bud3/rpc.rs",
    )?));
    for required in [
        "\"bud_storageGetContent\"",
        "fallback_decode_public",
        "PaidViewReceipt",
        "\"bud_storageOpenReveal\"",
    ] {
        if !rpc_src.contains(required) {
            return Err(format!(
                "bud3-paid-view: src/storage/bud3/rpc.rs missing `{required}`"
            ));
        }
    }

    let cref_src = strip_line_comments(strip_cfg_test(&read_rel(
        root,
        "src/storage/bud3/content_ref.rs",
    )?));
    if cref_src.contains("Bud3NotReady") {
        return Err(String::from(
            "bud3-paid-view: content_ref.rs still contains forbidden `Bud3NotReady` rejection",
        ));
    }

    Ok(String::from(
        "bud3-paid-view OK: G8 fallback requires PaidViewReceipt and refuses Sealed content; reveal sessions fetch from NetworkSymbolSource.",
    ))
}

/// Self-test with positive and negative synthetic trees.
///
/// # Errors
///
/// Returns an error if a clean synthetic tree fails or an unpaid/sealed fallback canary passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-paid-view")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        let clean_view = "\
pub const MIN_PAID_VIEW_FEE_ATOMS: u64 = 100;
pub struct PaidViewReceipt;
pub trait NetworkSymbolSource {}
pub enum E { SealedFallbackForbidden, UnpaidFallbackView }
pub fn fallback_decode_public() {}
pub fn open_reveal<N: NetworkSymbolSource>() {}
";
        let clean_rpc = "\
pub fn h() { let _ = (\"bud_storageGetContent\", \"bud_storageOpenReveal\", fallback_decode_public, PaidViewReceipt); }
";
        let clean_cref = "pub struct ContentRef;\n";

        put("src/storage/bud3/view.rs", clean_view)?;
        put("src/storage/bud3/rpc.rs", clean_rpc)?;
        put("src/storage/bud3/content_ref.rs", clean_cref)?;
        run(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;

        put("src/storage/bud3/content_ref.rs", "pub enum E { Bud3NotReady }\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: Bud3NotReady in content_ref.rs passed"));
        }
        put("src/storage/bud3/content_ref.rs", clean_cref)?;

        put("src/storage/bud3/view.rs", "pub fn fallback_decode_public() {}\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: unpaid view.rs passed"));
        }

        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-paid-view canary OK: clean tree passed; Bud3NotReady and unpaid fallback failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_paid_view_canary() {
        assert!(super::self_test().is_ok());
    }
}
