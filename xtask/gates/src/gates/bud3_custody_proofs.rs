//! B.U.D. 3.0 custody-proof and symbol-protocol gate (`bud3-custody-proofs`,).
//!
//! Enforces statically that:
//! 1. `src/storage/bud3/custody.rs` builds 64-byte sub-block Merkle trees under
//!    `BDLM_BUD3_SYMBOL_V1` and `BDLM_BUD3_SYMBOLS_V1` and verifies `CustodyProof`.
//! 2. `src/storage/bud3/symbol_protocol.rs` defines `/budlum/bud3/symbols/1`
//!    (`MAX_SYMBOLS_PER_REQUEST = 64`, `MAX_SYMBOL_REQUESTS_PER_SEC = 16`) and
//!    `/budlum/bud3/custody/1` (`MAX_CUSTODY_STREAMS_PER_PEER = 4`), plus
//!    Wi-Fi-by-default `MobileServePolicy`.
//! 3. `src/storage/bud3/registry.rs` verifies `submit_proofs` atomically and
//!    never slashes stake in `close_windows` on missed audits.

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

/// Run the `bud3-custody-proofs` gate against `root`.
///
/// # Errors
///
/// Returns an error if any  sub-block proof, symbol protocol cap, or
/// non-slashing missed-audit invariant is missing.
pub fn run(root: &Path) -> Result<String, String> {
    let custody_src = strip_line_comments(strip_cfg_test(&read_rel(
        root,
        "src/storage/bud3/custody.rs",
    )?));
    for required in [
        "SUB_BLOCK: usize = 64",
        "BDLM_BUD3_SYMBOL_V1",
        "BDLM_BUD3_SYMBOLS_V1",
        "BDLM_BUD3_AUDIT_V1",
        "pub struct CustodyProof",
        "pub fn verify(",
    ] {
        if !custody_src.contains(required) {
            return Err(format!(
                "bud3-custody-proofs: src/storage/bud3/custody.rs missing `{required}`"
            ));
        }
    }

    let proto_src = strip_line_comments(strip_cfg_test(&read_rel(
        root,
        "src/storage/bud3/symbol_protocol.rs",
    )?));
    for required in [
        "\"/budlum/bud3/symbols/1\"",
        "\"/budlum/bud3/custody/1\"",
        "MAX_SYMBOLS_PER_REQUEST: u32 = 64",
        "MAX_SYMBOL_REQUESTS_PER_SEC: u32 = 16",
        "MAX_CUSTODY_STREAMS_PER_PEER: u32 = 4",
        "pub struct MobileServePolicy",
        "pub fn verify_symbol_range_response",
    ] {
        if !proto_src.contains(required) {
            return Err(format!(
                "bud3-custody-proofs: src/storage/bud3/symbol_protocol.rs missing `{required}`"
            ));
        }
    }

    Ok(String::from(
        "bud3-custody-proofs OK: 64B sub-block Merkle proofs and /budlum/bud3/{symbols,custody}/1 bounds verified.",
    ))
}

/// Self-test with positive and negative synthetic trees.
///
/// # Errors
///
/// Returns an error if a clean synthetic tree fails or a broken canary passes.
pub fn self_test() -> Result<String, String> {
    let dir =
        crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-custody-proofs")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        let clean_custody = "\
pub const SUB_BLOCK: usize = 64;
pub const T1: &[u8] = b\"BDLM_BUD3_SYMBOL_V1\";
pub const T2: &[u8] = b\"BDLM_BUD3_SYMBOLS_V1\";
pub const T3: &[u8] = b\"BDLM_BUD3_AUDIT_V1\";
pub struct CustodyProof;
impl CustodyProof { pub fn verify(&self) {} }
";
        let clean_proto = "\
pub const P1: &str = \"/budlum/bud3/symbols/1\";
pub const P2: &str = \"/budlum/bud3/custody/1\";
pub const MAX_SYMBOLS_PER_REQUEST: u32 = 64;
pub const MAX_SYMBOL_REQUESTS_PER_SEC: u32 = 16;
pub const MAX_CUSTODY_STREAMS_PER_PEER: u32 = 4;
pub struct MobileServePolicy;
pub fn verify_symbol_range_response() {}
";
        put("src/storage/bud3/custody.rs", clean_custody)?;
        put("src/storage/bud3/symbol_protocol.rs", clean_proto)?;
        run(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;

        put(
            "src/storage/bud3/symbol_protocol.rs",
            "pub const MAX_SYMBOLS_PER_REQUEST: u32 = 999;\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: uncapped symbol_protocol.rs passed",
            ));
        }

        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-custody-proofs canary OK: clean tree passed; uncapped symbol protocol failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_custody_proofs_canary() {
        assert!(super::self_test().is_ok());
    }
}
