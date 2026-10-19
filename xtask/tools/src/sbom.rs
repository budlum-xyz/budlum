//! The SBOM generator.
//!
//! It replaces `ops/scripts/generate-sbom.sh`. It runs `cargo cyclonedx`
//! (pinned), moves the result to `sbom.cdx.json` in the repository root,
//! checks that the file is valid JSON, counts its components and writes the
//! summary `target/audit/SBOM.md`.
//!
//! # The pin
//!
//! The `cargo-cyclonedx` version is pinned because its flags change between
//! releases (run 728: `--output-file` had been removed). The pin is what keeps
//! the gate deterministic.

use std::path::Path;
use std::process::Command;

use crate::json::{self, Value};
use crate::support::{git_short_head, utc_timestamp};
use crate::{has_program, run_checked};

/// The pinned `cargo-cyclonedx` version.
pub const CYCLONEDX_VERSION: &str = "0.5.9";

/// `cargo-cyclonedx` writes `<package-name>.cdx.json` next to the manifest.
/// The root manifest is the single package `budlum-core`, so that name is the
/// artifact of this run. A stale file from an earlier run must not stand in
/// for it, which is why it is removed first and named explicitly afterwards.
const TOOL_OUTPUT: &str = "budlum-core.cdx.json";

/// Generate the SBOM.
///
/// # Errors
///
/// If a tool cannot be run, the SBOM was not written, or it is not valid JSON.
pub fn run(root: &Path) -> Result<String, String> {
    println!("[generate-sbom] starting SBOM generation...");

    if !has_program("cargo-cyclonedx") || !pinned_version_installed(root) {
        println!("[generate-sbom] installing cargo-cyclonedx {CYCLONEDX_VERSION} (pinned)...");
        run_checked(
            "cargo",
            &[
                "install",
                "--locked",
                "cargo-cyclonedx",
                "--version",
                CYCLONEDX_VERSION,
            ],
            root,
        )?;
    }

    let sbom_file = root.join("sbom.cdx.json");
    let tool_output = root.join(TOOL_OUTPUT);
    if tool_output.exists() {
        std::fs::remove_file(&tool_output)
            .map_err(|e| format!("{} could not be removed: {e}", tool_output.display()))?;
    }
    run_checked("cargo", &["cyclonedx", "--format", "json"], root)?;
    if !tool_output.is_file() {
        let found = list_cdx_files(root);
        let listing = if found.is_empty() {
            String::new()
        } else {
            format!(" Found instead: {}.", found.join(", "))
        };
        return Err(format!(
            "cargo-cyclonedx did not write {}.{listing}",
            tool_output.display()
        ));
    }
    std::fs::rename(&tool_output, &sbom_file).map_err(|e| {
        format!(
            "{} could not be moved to {}: {e}",
            tool_output.display(),
            sbom_file.display()
        )
    })?;

    let text = std::fs::read(&sbom_file)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .map_err(|e| format!("{} could not be read: {e}", sbom_file.display()))?;
    let parsed = json::parse(&text).map_err(|e| format!("the SBOM is not parseable JSON: {e}"))?;

    let size =
        std::fs::metadata(&sbom_file).map_or_else(|_| "?".to_string(), |m| m.len().to_string());
    let components = component_count(&parsed);

    let doc = root.join("target/audit/SBOM.md");
    if let Some(dir) = doc.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("{} could not be created: {e}", dir.display()))?;
    }
    std::fs::write(
        &doc,
        render_report(&utc_timestamp(), &git_short_head(root), &size, &components),
    )
    .map_err(|e| format!("{} could not be written: {e}", doc.display()))?;

    println!(
        "[generate-sbom] SBOM: {} ({size} bytes, {components} components)",
        sbom_file.display()
    );
    println!("[generate-sbom] report: {}", doc.display());
    Ok("[generate-sbom] done.".to_string())
}

fn pinned_version_installed(root: &Path) -> bool {
    Command::new("cargo")
        .args(["cyclonedx", "--version"])
        .current_dir(root)
        .output()
        .is_ok_and(|o| {
            o.status.success() && String::from_utf8_lossy(&o.stdout).contains(CYCLONEDX_VERSION)
        })
}

/// The `*.cdx.json` files in the root, for the failure message.
fn list_cdx_files(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".cdx.json"))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// The length of the top-level `components` array: 0 when it is absent, `?`
/// when it is there but is not an array.
#[must_use]
pub fn component_count(doc: &Value) -> String {
    match doc.get("components") {
        None => "0".to_string(),
        Some(value) => value
            .as_array()
            .map_or_else(|| "?".to_string(), |items| items.len().to_string()),
    }
}

/// The Markdown summary.
#[must_use]
pub fn render_report(timestamp: &str, head: &str, size: &str, components: &str) -> String {
    format!(
        "# SBOM (Software Bill of Materials)\n\
         \n\
         **Generated:** {timestamp}\n\
         **Tool:** cargo-cyclonedx (https://github.com/CycloneDX/cyclonedx-rust-cargo)\n\
         **Format:** CycloneDX 1.5 (JSON)\n\
         **Repo:** budlum-xyz/budlum @ `{head}`\n\
         \n\
         ## Summary\n\
         \n\
         - **SBOM file:** `sbom.cdx.json` (size: {size} bytes)\n\
         - **Component count:** {components}\n\
         \n\
         ## Usage\n\
         \n\
         The external audit firm can use `sbom.cdx.json` directly.\n\
         Format: CycloneDX 1.5 JSON, it includes every transitive dependency.\n\
         \n\
         ## Regeneration\n\
         \n\
         ```bash\n\
         cargo run --release --manifest-path xtask/tools/Cargo.toml -- generate-sbom\n\
         ```\n\
         \n\
         This report is generated automatically.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_components() {
        let doc =
            json::parse(r#"{"bomFormat":"CycloneDX","components":[{},{},{}]}"#).expect("json");
        assert_eq!(component_count(&doc), "3");
    }

    #[test]
    fn a_missing_components_member_counts_zero() {
        let doc = json::parse(r#"{"bomFormat":"CycloneDX"}"#).expect("json");
        assert_eq!(component_count(&doc), "0");
    }

    #[test]
    fn a_components_member_that_is_not_a_list_is_unknown() {
        let doc = json::parse(r#"{"components":"many"}"#).expect("json");
        assert_eq!(component_count(&doc), "?");
    }

    #[test]
    fn the_report_names_the_size_and_count() {
        let r = render_report("2026-10-07T00:00:00Z", "abc", "1234", "56");
        assert!(r.contains("(size: 1234 bytes)"));
        assert!(r.contains("- **Component count:** 56"));
        assert!(r.contains("@ `abc`"));
        assert!(r.contains("generate-sbom"));
    }

    #[test]
    fn the_pin_is_a_plain_version() {
        assert!(CYCLONEDX_VERSION
            .split('.')
            .all(|p| p.parse::<u32>().is_ok()));
    }
}
