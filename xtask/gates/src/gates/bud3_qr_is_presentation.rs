//! The QR video and the PNG frames are a presentation, never an id and never
//! a record.
//!
//! The same symbols ride the optical frames and the custody shares, but the
//! chain sees only the object. If QR or PNG bytes could enter a content id or
//! a persistent record, the presentation would become a second storage copy
//! under another name and the id would depend on rendering choices.
//!
//! This gate pins the rule where it can bite: the id surface and the record
//! surface name no presentation bytes. The rule statements in docs are fine;
//! production code is what is scanned.

use std::path::Path;

/// The id and record surfaces: no presentation identifier may appear in their
/// production code.
const SURFACES: &[&str] = &[
    "src/storage/bud3/content_id.rs",
    "src/storage/bud3/registry.rs",
    "src/storage/bud3/pipeline.rs",
];

/// Presentation identifiers, matched as words, case-insensitively.
const PRESENTATION: &[&str] = &["qr", "png", "video", "frame", "carousel"];

/// Production text: line comments and test modules removed.
fn production_code(text: &str) -> String {
    let no_tests = super::capability_modules_are_wired::strip_test_mods(text);
    no_tests
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase()
}

/// Word-boundary scan of one lowered text.
fn find_word(lowered: &str, word: &str) -> bool {
    let mut from = 0usize;
    while let Some(at) = lowered[from..].find(word) {
        let start = from + at;
        let end = start + word.len();
        let before_ok = start == 0 || !lowered.as_bytes()[start - 1].is_ascii_alphanumeric();
        let after_ok = end >= lowered.len() || !lowered.as_bytes()[end].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// # Errors
///
/// The surface and the identifier that rode into it.
pub fn run(root: &Path) -> Result<String, String> {
    let mut scanned = 0usize;
    for rel in SURFACES {
        let p = root.join(rel);
        if !p.is_file() {
            return Err(format!("{rel} is missing - the id or record surface is gone"));
        }
        let text = std::fs::read_to_string(&p).map_err(|e| format!("read {rel}: {e}"))?;
        let code = production_code(&text);
        scanned += 1;
        for word in PRESENTATION {
            if find_word(&code, word) {
                return Err(format!(
                    "{rel} production code names `{word}`. The QR video and the PNG frames are a \\\n  presentation: their bytes never enter a content id or a persistent record. Keep the \\\n  rule where the docs state it, not in the id or record derivation."
                ));
            }
        }
    }
    Ok(format!(
        "bud3 qr is presentation OK: {scanned} id and record surfaces name no presentation bytes"
    ))
}

/// The canary: a presentation field injected into the id surface must fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-qr")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        for rel in SURFACES {
            put(rel, "// clean\npub fn derive() {}\n")?;
        }
        run(&dir).map_err(|e| format!("canary: a clean tree failed: {e}"))?;
        put(
            "src/storage/bud3/content_id.rs",
            "pub fn derive() {\n    let _png = qr_video_bytes();\n}\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: presentation bytes in the id surface passed"));
        }
        put(
            "src/storage/bud3/content_id.rs",
            "// The frames are a presentation; the id is content only.\npub fn derive() {}\n",
        )?;
        run(&dir).map_err(|e| format!("canary: the rule statement in a doc failed: {e}"))?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-qr-is-presentation canary OK: an injected presentation field failed, a doc statement passed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_qr_is_presentation_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
