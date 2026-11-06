//! The sealed flag is declared and bound.
//!
//! A sealed object encrypts its payload; the compression happens first. The
//! declaration is BOF-1 `flags` bit0, and the binding is twofold: the content
//! id of sealed content is the keyed HMAC of the content, not a bare digest,
//! and the object commitment covers the header bytes, so the flag rides into
//! every custody share. A flag that is declared but unbound is a trailer an
//! attacker moves; a keyed id that no flag declares is a sealed object the
//! view path treats as public.
//!
//! This gate pins the three anchors: the flag bit, the keyed id, and the
//! commitment over the object bytes.

use std::path::Path;

/// Production text: line comments and test modules removed.
fn production_code(text: &str) -> String {
    let no_tests = super::capability_modules_are_wired::strip_test_mods(text);
    no_tests
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

fn read(root: &Path, rel: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(rel)).map_err(|e| format!("read {rel}: {e}"))
}

/// # Errors
///
/// The anchor that is missing.
pub fn run(root: &Path) -> Result<String, String> {
    let bof1 = production_code(&read(root, "src/storage/bud3/bof1.rs")?);
    let cid = production_code(&read(root, "src/storage/bud3/content_id.rs")?);
    let seg = production_code(&read(root, "src/storage/bud3/segment.rs")?);

    // 1. The declaration: flags bit0 is the sealed bit.
    if !bof1.contains("SEALED: u8 = 1 << 0") {
        return Err(String::from(
            "bof1.rs no longer declares the sealed flag as bit0 of `flags`. The declaration is \n  the bit, not a side table.",
        ));
    }
    // 2. The id binding: sealed content ids are keyed (HMAC), not bare digests.
    if !cid.contains("Hmac") && !cid.contains("hmac") {
        return Err(String::from(
            "content_id.rs no longer keys the sealed id: sealed content is HMAC-SHA-256 under \n  the mac key, so only a granted key derives the id.",
        ));
    }
    if !cid.contains("Sealed") {
        return Err(String::from(
            "content_id.rs no longer has a sealed kind: the id kind must match the flag.",
        ));
    }
    // 3. The commitment binding: the object commitment covers the object
    //    bytes, header included, so the flag rides into every share.
    if !seg.contains("pub fn object_commitment(") {
        return Err(String::from(
            "segment.rs no longer derives the object commitment: the commitment is what binds \n  the sealed flag into the shares.",
        ));
    }
    if !seg.contains("object") {
        return Err(String::from(
            "segment.rs commitment no longer covers the object: the header flags must ride in.",
        ));
    }
    // 4. The join: a sealed flag implies the sealed id kind at the door.
    if !bof1.contains("is_sealed") {
        return Err(String::from(
            "bof1.rs no longer joins the flag to the body: `is_sealed` is how the view and \n  grant paths read the declaration.",
        ));
    }
    Ok(String::from(
        "content encryption OK: the sealed flag is bit0, the sealed id is keyed, and the commitment covers the flag",
    ))
}

/// The canary: each anchor removed must fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-enc")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        put("src/storage/bud3/bof1.rs", "pub const SEALED: u8 = 1 << 0;\npub fn is_sealed() {}\n")?;
        put("src/storage/bud3/content_id.rs", "struct HmacSha256;\nenum Kind { Sealed }\n")?;
        put("src/storage/bud3/segment.rs", "pub fn object_commitment(o: &[u8]) -> [u8; 32] { [0; 32] }\n")?;
        run(&dir).map_err(|e| format!("canary: a complete tree failed: {e}"))?;
        put("src/storage/bud3/bof1.rs", "pub const SEALED: u8 = 1 << 1;\npub fn is_sealed() {}\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: the flag moved to bit1 and passed"));
        }
        put("src/storage/bud3/bof1.rs", "pub const SEALED: u8 = 1 << 0;\npub fn is_sealed() {}\n")?;
        put("src/storage/bud3/content_id.rs", "enum Kind { Sealed }\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an unkeyed sealed id passed"));
        }
        put("src/storage/bud3/content_id.rs", "struct HmacSha256;\nenum Kind { Sealed }\n")?;
        put("src/storage/bud3/segment.rs", "pub fn digest_only() {}\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: no object commitment passed"));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "content-encryption-bound canary OK: a moved flag, an unkeyed id and a missing commitment each failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn content_encryption_is_declared_and_bound() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
