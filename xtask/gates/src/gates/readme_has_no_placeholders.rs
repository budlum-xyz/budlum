//! Ensures `README.md` and `README.tr.md` contain zero unresolved `{{...}}` template placeholders.

use std::path::Path;

fn scan_text(rel: &str, text: &str) -> Result<(), String> {
    for (idx, line) in text.lines().enumerate() {
        if let Some(start) = line.find("{{") {
            let tail = line.get(start..).unwrap_or("");
            if tail.contains("}}") {
                return Err(format!(
                    "{rel}:{} still carries an unresolved template placeholder: {line}",
                    idx + 1
                ));
            }
        }
    }
    Ok(())
}

/// Checks `README.md` and `README.tr.md` for unresolved `{{...}}` placeholders.
///
/// # Errors
///
/// Returns an error when either file cannot be read or contains `{{...}}`.
pub fn run(root: &Path) -> Result<String, String> {
    for rel in ["README.md", "README.tr.md"] {
        let text = std::fs::read_to_string(root.join(rel))
            .map_err(|e| format!("cannot read {rel}: {e}"))?;
        scan_text(rel, &text)?;
    }
    Ok(String::from(
        "README placeholders OK: zero unresolved {{...}} tokens in README.md and README.tr.md.",
    ))
}

/// Canary self-test ensuring an unresolved `{{placeholder}}` is caught.
///
/// # Errors
///
/// Returns an error if a synthetic placeholder passes or clean text fails.
pub fn self_test() -> Result<String, String> {
    if scan_text("README.md", "Release: {{release:version}}\n").is_ok() {
        return Err(String::from("canary: unresolved {{release:version}} passed"));
    }
    scan_text("README.md", "Release: v0.1.0-testnet\n")?;
    Ok(String::from(
        "readme-has-no-placeholders self-test OK: unresolved token rejected and clean text accepted.",
    ))
}
