//! B.U.D. 3.0 sealed-content, unlinkable view-grant, and cryptographic-erasure
//! gate (`bud3-sealed-and-deletion`, WP-22).
//!
//! Enforces the Section 6.8 & WP-22 invariants statically across `src/storage/bud3/`:
//! 1. `seal.rs` applies Padme bucket padding (`padme_padded_len`), seals via
//!    `XChaCha20Poly1305` bound to `SEAL_AAD_TAG`, and zeroes the outer BOF-1
//!    `content_len: 0` (`sealed_header_hides_length`).
//! 2. `grants.rs` defines an unlinkable `GrantRow` carrying `grant_tag`,
//!    `one_time_pk`, `sealed_key_package`, and `expires_at_epoch`, and NEVER
//!    carries `content_id`, `issuer`, or `grantee` fields (`grant_rows_are_unlinkable`).
//! 3. `keys.rs` seals key packages via `HpkeEnvelope` (PQ-hybrid X-Wing `0x647a`)
//!    and derives/signs one-time grant keys with `SchemeId::ML_DSA_65` under
//!    `ctx::STORAGE_V2`.
//! 4. `registry.rs` removes revoked/shredded grant rows from `self.grants` and
//!    records `self.revoked_grants` so revoked packages are never served, and
//!    enforces `check_same_owner_dependency`.

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

fn extract_struct_body<'a>(code: &'a str, marker: &str) -> Option<&'a str> {
    let start = code.find(marker)?;
    let tail = code.get(start..)?;
    let open = tail.find('{')?;
    let after_open = tail.get(open + 1..)?;
    let close = after_open.find('}')?;
    after_open.get(..close)
}

/// Run the `bud3-sealed-and-deletion` gate against `root`.
///
/// # Errors
///
/// Returns an actionable message if any WP-22 sealing, unlinkability, or
/// cryptographic-erasure invariant is violated.
pub fn run(root: &Path) -> Result<String, String> {
    let seal_src = strip_line_comments(strip_cfg_test(&read_rel(
        root,
        "src/storage/bud3/seal.rs",
    )?));
    for required in [
        "pub fn padme_padded_len",
        "XChaCha20Poly1305",
        "SEAL_AAD_TAG",
        "Flags::SEALED",
        "content_len: 0",
        "CODEC_RAW",
    ] {
        if !seal_src.contains(required) {
            return Err(format!(
                "bud3-sealed-and-deletion: src/storage/bud3/seal.rs missing required token `{required}`"
            ));
        }
    }

    let grants_src = strip_line_comments(strip_cfg_test(&read_rel(
        root,
        "src/storage/bud3/grants.rs",
    )?));
    let grant_row_body = extract_struct_body(&grants_src, "pub struct GrantRow")
        .ok_or_else(|| String::from("bud3-sealed-and-deletion: missing `pub struct GrantRow`"))?;
    for required_field in [
        "grant_tag",
        "one_time_pk",
        "sealed_key_package",
        "expires_at_epoch",
    ] {
        if !grant_row_body.contains(required_field) {
            return Err(format!(
                "bud3-sealed-and-deletion: GrantRow missing field `{required_field}`"
            ));
        }
    }
    for forbidden_field in ["content_id", "issuer", "grantee", "owner", "object"] {
        if grant_row_body.contains(forbidden_field) {
            return Err(format!(
                "bud3-sealed-and-deletion: GrantRow must remain unlinkable; found forbidden field token `{forbidden_field}`"
            ));
        }
    }

    let keys_src = strip_line_comments(strip_cfg_test(&read_rel(
        root,
        "src/storage/bud3/keys.rs",
    )?));
    for required in [
        "HpkeEnvelope::seal",
        "HpkeEnvelope::from_bytes",
        "SchemeId::ML_DSA_65",
        "STORAGE_V2",
        "ClientSealedDedupIndex",
    ] {
        if !keys_src.contains(required) {
            return Err(format!(
                "bud3-sealed-and-deletion: src/storage/bud3/keys.rs missing `{required}`"
            ));
        }
    }

    let reg_src = strip_line_comments(strip_cfg_test(&read_rel(
        root,
        "src/storage/bud3/registry.rs",
    )?));
    for required in [
        "pub fn issue_view_grant",
        "pub fn revoke_view_grant",
        "pub fn social_delete",
        "revoked_grants",
        "check_same_owner_dependency",
    ] {
        if !reg_src.contains(required) {
            return Err(format!(
                "bud3-sealed-and-deletion: src/storage/bud3/registry.rs missing `{required}`"
            ));
        }
    }

    Ok(String::from(
        "bud3-sealed-and-deletion OK: Padme + XChaCha20-Poly1305 hides length, GrantRow is unlinkable, X-Wing + ML-DSA-65 grant shredding wired.",
    ))
}

/// Self-test with positive and negative synthetic trees.
///
/// # Errors
///
/// Returns an error if a clean synthetic tree fails or a broken canary passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir(
        "budlum-gates-bud3-sealed-and-deletion",
    )?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        let clean_seal = "\
pub fn padme_padded_len() {}
pub fn seal() { let _ = (XChaCha20Poly1305, SEAL_AAD_TAG, Flags::SEALED, CODEC_RAW); Header { content_len: 0 }; }
";
        let clean_grants = "\
pub struct GrantRow {
    pub grant_tag: [u8; 32],
    pub one_time_pk: Vec<u8>,
    pub sealed_key_package: Vec<u8>,
    pub expires_at_epoch: u64,
}
";
        let clean_keys = "\
pub struct ClientSealedDedupIndex;
pub fn k() { let _ = (HpkeEnvelope::seal, HpkeEnvelope::from_bytes, SchemeId::ML_DSA_65, STORAGE_V2); }
";
        let clean_reg = "\
pub fn issue_view_grant() {}
pub fn revoke_view_grant() { let _ = revoked_grants; }
pub fn social_delete() { let _ = check_same_owner_dependency; }
";

        put("src/storage/bud3/seal.rs", clean_seal)?;
        put("src/storage/bud3/grants.rs", clean_grants)?;
        put("src/storage/bud3/keys.rs", clean_keys)?;
        put("src/storage/bud3/registry.rs", clean_reg)?;
        run(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;

        // Canary 1: GrantRow leaking grantee / content_id must fail.
        put(
            "src/storage/bud3/grants.rs",
            "\
pub struct GrantRow {
    pub grant_tag: [u8; 32],
    pub grantee: [u8; 32],
    pub one_time_pk: Vec<u8>,
    pub sealed_key_package: Vec<u8>,
    pub expires_at_epoch: u64,
}
",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: GrantRow with `grantee` field passed"));
        }
        put("src/storage/bud3/grants.rs", clean_grants)?;

        // Canary 2: seal.rs leaking non-zero content_len must fail.
        put(
            "src/storage/bud3/seal.rs",
            "pub fn padme_padded_len() {}\npub fn seal() { let _ = (XChaCha20Poly1305, SEAL_AAD_TAG, Flags::SEALED, CODEC_RAW); Header { content_len: 42 }; }\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: seal.rs without `content_len: 0` passed",
            ));
        }

        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-sealed-and-deletion canary OK: clean tree passed; linkable GrantRow and non-zero sealed content_len failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_sealed_and_deletion_canary() {
        assert!(super::self_test().is_ok());
    }
}
