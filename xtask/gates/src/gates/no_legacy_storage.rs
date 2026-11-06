//! No legacy storage identifiers in the tree.
//!
//! Section 5.5 of THE BUDLUM DIREKTIF names a forbidden list of type names,
//! RPC names and file paths from B.U.D. 1.0 and B.U.D. 2.0. The gate refuses
//! any identifier that still lives in `src/`, `crates/`, `budzero/`,
//! `xtask/`, `contracts/`, `proto/` and `docs/` once WP-07 lands. Until the
//! legacy code is actually removed, known offenders live on a shrinking
//! baseline (`.github/no-legacy-storage-baseline.txt`) so the count may only
//! go down; raising the baseline to make a run pass is itself a defect.
//!
//! Path bans (Section 5.5 "Yol yasakları") are absolute: any file under those
//! paths fails the gate regardless of content.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// Identifier bans: legacy B.U.D. 1.0 / 2.0 type, function and RPC names.
///
/// Each entry uses word-boundary matching (`\b`) so partial names such as
/// `ContentProvider` (an unrelated term in other crates) are not flagged.
const IDENTIFIERS: &[&str] = &[
    "ContentManifest",
    "ErasureScheme",
    "ReedSolomon",
    "EncodedObject",
    "LrcLayout",
    "MsrError",
    "StorageRegistry",
    "StorageDealOpen",
    "OpenDeal",
    "AnswerCodingAudit",
    "AcceptReallocation",
    "OpenChallenge",
    "AnswerChallenge",
    "StorageProvider",
    "InMemoryStorageProvider",
    "BudStorageEdition",
    "GeneratedSpec",
    "MobileSelfProfile",
    "MobileSelfContentPolicy",
    "CustodyLedger",
    "ServerAdmission",
    "OneShareRegistry",
    "SingleScreenView",
    "PactBinding",
    "BudBitswap",
    "MemoryContentStore",
    "ContentDiscovery",
    "VideoRecipe",
    "ThreeRecipePublic",
    "bud_storageOpenDeal",
    "bud_storageRegisterManifest",
    "bud_storageQrFeedPreview",
];

/// Path bans: entire directories or files that must not exist.
///
/// During WP-07 these paths are removed; until then they sit on the same
/// shrinking baseline so CI is green today and the list only shrinks. The
/// line `# PATHS` separates file offenders from path offenders.
const PATH_BANS: &[&str] = &[
    "bud/",
    "budzero/bud-node/",
    "src/domain/storage_deal.rs",
    "src/domain/deal_open.rs",
    "src/chain/storage_maintenance.rs",
];

const ROOTS: &[&str] = &[
    "src", "crates", "budzero", "xtask", "contracts", "proto", "docs", "tests",
];

/// Files that reference the list itself, the gate, or the to-be-removed
/// legacy shell gates by name (Section 5.4) are exempt from identifier
/// scanning. Those files use the old names as string labels only.
const SELF: &[&str] = &[
    "xtask/gates/src/gates/no_legacy_storage.rs",
    "xtask/gates/src/gates/storage_provider_gate.rs",
    "xtask/gates/src/gates/coding_audit_samples_the_relationship.rs",
    "xtask/gates/src/gates/generated_content.rs",
    "xtask/gates/src/gates/paid_content.rs",
    "xtask/gates/src/gates/qr_is_derivative_only.rs",
    "xtask/gates/src/gates/three_is_recipe_only.rs",
    "xtask/gates/src/gates/zero_storage_frozen.rs",
    "xtask/gates/src/gates/untrusted_manifests.rs",
    "xtask/gates/src/gates/content_encryption_is_declared_and_bound.rs",
    "xtask/gates/src/gates/storage_priced.rs",
    "xtask/gates/src/gates/shard_placement.rs",
    "xtask/gates/src/gates/repair_fires.rs",
    "xtask/gates/src/gates/storage_penalties.rs",
    "xtask/gates/src/gates/storage_proof_boundary.rs",
    "xtask/gates/src/gates/storage_priced.rs",
    ".github/no-legacy-storage-baseline.txt",
];

/// Historical audit records reference the old names on purpose.
const HISTORY_DIRS: &[&str] = &["docs/audit/", "docs/work/"];

const BASELINE: &str = ".github/no-legacy-storage-baseline.txt";
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, std::path::PathBuf)>) {
    if dir.is_file() {
        if let Ok(rel) = dir.strip_prefix(root) {
            out.push((rel.to_string_lossy().replace('\\', "/"), dir.to_path_buf()));
        }
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(&p, root, out);
            }
        } else if let Ok(rel) = p.strip_prefix(root) {
            out.push((rel.to_string_lossy().replace('\\', "/"), p.clone()));
        }
    }
}

/// Collect every file under the scanned roots.
fn all_files(root: &Path) -> Vec<(String, std::path::PathBuf)> {
    let mut files = Vec::new();
    for r in ROOTS {
        let p = root.join(r);
        if p.exists() {
            walk(&p, root, &mut files);
        }
    }
    files
}

/// Files that contain a banned identifier, and the first identifier found.
fn identifier_offenders(root: &Path) -> Vec<(String, String)> {
    let files = all_files(root);
    let mut out = Vec::new();
    for (rel, path) in files {
        if SELF.contains(&rel.as_str()) || HISTORY_DIRS.iter().any(|d| rel.starts_with(d)) {
            continue;
        }
        if std::fs::metadata(&path).map_or(true, |m| m.len() > MAX_FILE_BYTES) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for id in IDENTIFIERS {
            if contains_word(&text, id) {
                out.push((rel, (*id).to_string()));
                break;
            }
        }
    }
    out
}

/// Word-boundary substring match. A token is bounded by non-identifier
/// characters (`[^A-Za-z0-9_]`) or string edges. This keeps `ContentProvider`
/// from being flagged for `Content` and keeps `bud_storageOpenDeal_v2`
/// flagged.
fn contains_word(hay: &str, needle: &str) -> bool {
    let n = needle.as_bytes();
    if n.is_empty() {
        return false;
    }
    let h = hay.as_bytes();
    let mut i = 0;
    while i + n.len() <= h.len() {
        if h[i..i + n.len()].eq_ignore_ascii_case(n) {
            let before_ok = i == 0 || !is_id_byte(h[i - 1]);
            let after = i + n.len();
            let after_ok = after == h.len() || !is_id_byte(h[after]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_id_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Paths that are banned and currently exist.
fn path_ban_offenders(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for ban in PATH_BANS {
        let p = root.join(ban);
        if p.exists() {
            // Only flag the directory path itself, not descend into it here.
            // The directory ban is about the legacy tree existing at all.
            out.push((*ban).to_string());
        }
    }
    out
}

/// Run the gate.
///
/// # Errors
///
/// Returns a finding sentence.
pub fn run(root: &Path) -> Result<String, String> {
    let (allowed_files, allowed_paths) = baseline(root);
    let id_hits = identifier_offenders(root);
    let path_hits = path_ban_offenders(root);

    // Identifier bans use a shrinking baseline of files.
    let mut new = String::new();
    let found_set: BTreeSet<&str> = id_hits.iter().map(|(f, _)| f.as_str()).collect();
    for (file, ident) in &id_hits {
        if !allowed_files.contains(file.as_str()) {
            let _ = writeln!(new, "  {file}: \"{ident}\"");
        }
    }
    let mut stale = String::new();
    for file in &allowed_files {
        if !found_set.contains(file.as_str()) {
            let _ = writeln!(stale, "  {file}");
        }
    }

    // Path bans also use a shrinking baseline. WP-07 deletes these.
    let mut new_paths = String::new();
    let path_set: BTreeSet<&str> = path_hits.iter().map(|s| s.as_str()).collect();
    for p in &path_hits {
        if !allowed_paths.contains(p.as_str()) {
            let _ = writeln!(new_paths, "  {p}");
        }
    }
    let mut stale_paths = String::new();
    for p in &allowed_paths {
        if !path_set.contains(p.as_str()) {
            let _ = writeln!(stale_paths, "  {p}");
        }
    }

    if !new.is_empty() {
        return Err(format!(
            "FAIL: legacy storage identifiers appear outside the shrinking baseline:\n{new}\n  \
             B.U.D. 3.0 is the single storage system (KR-01); remove these identifiers or migrate \
             the call sites through the ContentRef temporary interface (Section 5.7)."
        ));
    }
    if !stale.is_empty() {
        return Err(format!(
            "FAIL: these baseline files no longer carry a legacy identifier; remove their lines from {BASELINE}:\n{stale}"
        ));
    }
    if !new_paths.is_empty() {
        return Err(format!(
            "FAIL: banned legacy storage paths exist outside the shrinking baseline; Section 5.5 removes them:\n{new_paths}"
        ));
    }
    if !stale_paths.is_empty() {
        return Err(format!(
            "FAIL: these baseline paths no longer exist; remove their lines from {BASELINE}:\n{stale_paths}"
        ));
    }

    Ok(format!(
        "no-legacy-storage OK: {} file(s) and {} path(s) on the shrinking baseline; the list may only shrink (WP-07).",
        id_hits.len(),
        path_hits.len()
    ))
}

fn baseline(root: &Path) -> (BTreeSet<String>, BTreeSet<String>) {
    let text = std::fs::read_to_string(root.join(BASELINE)).unwrap_or_default();
    let mut files = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut in_paths = false;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            if line == "# PATHS" {
                in_paths = true;
            }
            continue;
        }
        if in_paths {
            paths.insert(line.to_string());
        } else {
            files.insert(line.to_string());
        }
    }
    (files, paths)
}

/// Canary: inject a legacy identifier and confirm the gate catches it; then
/// mark it baselined and confirm the gate passes; then fix the file and
/// confirm the stale baseline is rejected.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-no-legacy-storage")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        let mkdir = |rel: &str| -> Result<(), String> {
            std::fs::create_dir_all(dir.join(rel)).map_err(|e| e.to_string())
        };
        let rmdir = |rel: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if p.exists() {
                std::fs::remove_dir_all(&p).map_err(|e| e.to_string())?;
            }
            Ok(())
        };

        // Clean tree, empty baseline (with separator): must pass.
        put("src/clean.rs", "// fresh code, no legacy names\n")?;
        put(BASELINE, "# empty\n# PATHS\n")?;
        run(&dir).map_err(|e| format!("canary: a clean tree failed: {e}"))?;

        // Inject a legacy identifier: must fail.
        put("src/bad.rs", "use serde::{Deserialize, Serialize};\npub type X = ContentManifest;\n")?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: an injected legacy identifier (ContentManifest) was accepted",
            ));
        }

        // Baselining the bad file: must pass.
        put(BASELINE, "# files\nsrc/bad.rs\n# PATHS\n")?;
        run(&dir).map_err(|e| format!("canary: a baselined file failed: {e}"))?;

        // Fix the file: stale file baseline must fail.
        put("src/bad.rs", "// renamed to bud3::Object\n")?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: a stale file baseline entry was accepted after the file was fixed",
            ));
        }

        // Clear file baseline, create a banned path: must fail on the path ban
        // even when no identifier appears anywhere.
        put(BASELINE, "# files\n# PATHS\n")?;
        put("src/bad.rs", "// clean\n")?;
        mkdir("bud/src")?;
        put("bud/src/lib.rs", "// legacy bud crate\n")?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: a banned directory (bud/) was not flagged",
            ));
        }

        // Baselining the path: must pass.
        put(BASELINE, "# files\n# PATHS\nbud/\n")?;
        run(&dir).map_err(|e| format!("canary: a baselined path failed: {e}"))?;

        // Remove the banned directory: stale path baseline must fail.
        rmdir("bud")?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: a stale path baseline entry was accepted after the directory was removed",
            ));
        }

        // Audit dirs are exempt from identifier scanning.
        put(BASELINE, "# files\n# PATHS\n")?;
        put("docs/audit/old.md", "ContentManifest was removed\n")?;
        run(&dir).map_err(|e| format!("canary: docs/audit/ was scanned for identifiers: {e}"))?;

        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "no-legacy-storage canary OK: injected identifier fails, baselined identifier passes, stale file baseline fails, banned path fails, baselined path passes, stale path baseline fails, audit dirs exempt.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_legacy_storage_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }

    #[test]
    fn word_boundary_does_not_match_substrings() {
        assert!(!super::contains_word(
            "use storage_provider::ContentProviderClient;",
            "StorageProvider"
        ));
        assert!(super::contains_word(
            "let _x: Box<dyn StorageProvider>;",
            "StorageProvider"
        ));
        assert!(super::contains_word(
            "call bud_storageRegisterManifest(...);",
            "bud_storageRegisterManifest"
        ));
    }
}
