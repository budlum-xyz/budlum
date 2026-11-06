//! README contains no placeholder markers (İP-43).
//!
//! Section 16.3: strings such as `TODO`, `TBD`, `FIXME`, `XXX`, `LATER`,
//! or Turkish `YAPILACAK`, `SONRA`, `BEKLEMEDE` are refused in README.md
//! and README.tr.md. A user reading the README should never hit a blank.

use std::fmt::Write as _;
use std::path::Path;

const PLACEHOLDERS: &[&str] = &[
    "TODO", "TBD", "FIXME", "XXX", "LATER",
    "YAPILACAK", "SONRA", "BEKLEMEDE",
];

const README_FILES: &[&str] = &["README.md", "README.tr.md"];

fn is_id_byte(b: u8) -> bool { b.is_ascii_alphanumeric() || b == b'_' }

fn contains_word(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return false; }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if hay[i..i + needle.len()].eq(needle) {
            let before_ok = i == 0 || !is_id_byte(hay[i - 1]);
            let after = i + needle.len();
            let after_ok = after == hay.len() || !is_id_byte(hay[after]);
            if before_ok && after_ok { return true; }
        }
        i += 1;
    }
    false
}

pub fn run(root: &Path) -> Result<String, String> {
    let mut findings = String::new();
    for rf in README_FILES {
        let path = root.join(rf);
        if !path.exists() { continue; }
        let Ok(bytes) = std::fs::read(&path) else { continue };
        for ph in PLACEHOLDERS {
            if contains_word(&bytes, ph.as_bytes()) {
                let _ = writeln!(findings, "  {rf}: {ph}");
            }
        }
    }
    if !findings.is_empty() {
        return Err(format!(
            "FAIL: README contains placeholder markers:\n{findings}\n  Remove placeholders before merging."
        ));
    }
    Ok(String::from("readme-has-no-placeholders OK"))
}

pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-readme-placeholders")?;
    let result = (|| {
        std::fs::write(dir.join("README.md"), "Budlum works.\n").map_err(|e| e.to_string())?;
        run(&dir).map_err(|e| format!("canary: clean README failed: {e}"))?;
        std::fs::write(dir.join("README.md"), "TODO: write docs\n").map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: TODO marker accepted"));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from("readme-has-no-placeholders canary OK: placeholders refused."))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() { assert!(super::self_test().is_ok(), "{:?}", super::self_test()); }
}
