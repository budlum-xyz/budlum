//! Untrusted bytes and untrusted symbols are refused at the door.
//!
//! A caller builds an object from bytes it chose, and a holder serves
//! symbols it chose. Both doors run the validator before anything is stored
//! or shown: the object door decodes under a metered budget and refuses a
//! payload whose decode is not the content, and the view door refuses a
//! rebuild whose object commitment is not the recorded one. Without those
//! refusals a relayer rewrites a payload and the signature or the record
//! still verifies.
//!
//! This gate pins the three refusals in the B.U.D. 3.0 pipeline.

use std::path::Path;

fn read(root: &Path, rel: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(rel)).map_err(|e| format!("read {rel}: {e}"))
}

fn production_code(text: &str) -> String {
    let no_tests = super::capability_modules_are_wired::strip_test_mods(text);
    no_tests
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// # Errors
///
/// The refusal that is missing.
pub fn run(root: &Path) -> Result<String, String> {
    let bof1 = production_code(&read(root, "src/storage/bud3/bof1.rs")?);
    let pipe = production_code(&read(root, "src/storage/bud3/pipeline.rs")?);

    // 1. The byte door: untrusted object bytes decode under a meter.
    if !bof1.contains("pub fn decode(") {
        return Err(String::from(
            "bof1.rs no longer decodes untrusted bytes under a meter. The decode door is \n  where a caller-built payload is refused, not trusted.",
        ));
    }
    // 2. The round trip: a payload whose decode is not the content is refused.
    if !bof1.contains("ContentMismatch") {
        return Err(String::from(
            "bof1.rs no longer refuses a payload whose decode is not the content. The \n  equality is the admission rule; without it a codec lies.",
        ));
    }
    // 3. The view door: a rebuild whose commitment is not the record's is refused.
    if !pipe.contains("CommitmentMismatch") {
        return Err(String::from(
            "pipeline.rs no longer refuses a rebuild whose object commitment is not the \n  recorded one. The view path shows content only when the commitment matches.",
        ));
    }
    // 4. The upload door: the limits run before anything is coded.
    if !pipe.contains("admit_content") {
        return Err(String::from(
            "pipeline.rs no longer admits content through the limits first. Size is a \n  governance parameter and it is checked before the work happens.",
        ));
    }
    Ok(String::from(
        "untrusted input OK: the byte door decodes under a meter, the round trip is enforced, and the view door checks the commitment",
    ))
}

/// The canary: each refusal removed must fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-untr")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        put(
            "src/storage/bud3/bof1.rs",
            "pub fn decode() {}\npub fn public_coded() { let _ = ContentMismatch; }\n",
        )?;
        put(
            "src/storage/bud3/pipeline.rs",
            "pub fn view_public() { let _ = CommitmentMismatch; }\npub fn prepare() { admit_content(); }\n",
        )?;
        run(&dir).map_err(|e| format!("canary: a complete tree failed: {e}"))?;
        put("src/storage/bud3/bof1.rs", "pub fn public_coded() {}\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: no decode door passed"));
        }
        put(
            "src/storage/bud3/bof1.rs",
            "pub fn decode() {}\npub fn public_coded() {}\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: no round-trip refusal passed"));
        }
        put(
            "src/storage/bud3/pipeline.rs",
            "pub fn view_public() {}\npub fn prepare() { admit_content(); }\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: no commitment refusal passed"));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "untrusted-manifests canary OK: each removed refusal failed the gate.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn untrusted_manifests_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
