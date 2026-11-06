//! No legacy storage: B.U.D. 3.0 is the single storage system.
//!
//! The identifiers and paths of the removed systems (B.U.D. 1.0/2.0, the
//! deal economy, the second 3.0 implementation under `bud/`, the Bitswap
//! content node under `budzero/bud-node/`) must not appear in the tree.
//!
//! The legacy removal is landing incrementally. Files that still carry a
//! legacy identifier are listed in `.github/no-legacy-storage-baseline.txt`.
//! The baseline is a ratchet: a file outside it fails, and a listed file that
//! no longer carries an identifier also fails until its line is removed, so
//! the list only shrinks. When the last line leaves the baseline, the gate
//! passes with an empty baseline and the removal is complete.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// Forbidden identifiers, matched case-sensitively as written.
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

/// Forbidden paths.
const PATHS: &[&str] = &[
    "bud/",
    "budzero/bud-node/",
    "src/domain/storage_deal.rs",
    "src/domain/deal_open.rs",
    "src/chain/storage_maintenance.rs",
];

/// The tree roots the gate scans.
const ROOTS: &[&str] = &["src", "crates", "budzero", "xtask", "docs"];

const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// Files that name the identifiers to forbid them.
const SELF: &[&str] = &[
    "xtask/gates/src/gates/no_legacy_storage.rs",
    ".github/no-legacy-storage-baseline.txt",
];

const BASELINE: &str = ".github/no-legacy-storage-baseline.txt";
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
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
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// Files that carry a forbidden identifier, with the first identifier found.
fn offenders(root: &Path) -> Vec<(String, &'static str)> {
    let mut files = Vec::new();
    for r in ROOTS {
        let p = root.join(r);
        if p.exists() {
            walk(&p, root, &mut files);
        }
    }
    let mut out = Vec::new();
    for rel in files {
        if SELF.contains(&rel.as_str()) {
            continue;
        }
        let path = root.join(&rel);
        if std::fs::metadata(&path).map_or(true, |m| m.len() > MAX_FILE_BYTES) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some(id) = IDENTIFIERS.iter().find(|id| text.contains(**id)) {
            out.push((rel, *id));
        }
    }
    // Banned paths are findings while they exist.
    for ban in PATHS {
        if root.join(ban.trim_end_matches('/')).exists() {
            out.push((ban.to_string(), "banned path"));
        }
    }
    out
}

fn baseline(root: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(root.join(BASELINE))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Run the gate.
///
/// # Errors
///
/// A finding, as a sentence.
pub fn run(root: &Path) -> Result<String, String> {
    let found = offenders(root);
    let allowed = baseline(root);
    let mut new = String::new();
    let found_set: BTreeSet<&str> = found.iter().map(|(f, _)| f.as_str()).collect();
    for (file, id) in &found {
        if !allowed.contains(file) {
            let _ = writeln!(new, "  {file}: \"{id}\"");
        }
    }
    let mut stale = String::new();
    for file in &allowed {
        if !found_set.contains(file.as_str()) {
            let _ = writeln!(stale, "  {file}");
        }
    }
    if !new.is_empty() {
        return Err(format!(
            "FAIL: legacy storage identifiers outside the removal baseline:\n{new}\n  \
             B.U.D. 3.0 is the single storage system; remove the legacy code."
        ));
    }
    if !stale.is_empty() {
        return Err(format!(
            "FAIL: these baseline entries no longer carry a legacy identifier; remove their lines from {BASELINE}:\n{stale}"
        ));
    }
    Ok(format!(
        "no legacy storage OK: {} legacy file(s) on the shrinking baseline, none elsewhere",
        found.len()
    ))
}

/// The canary: an injected identifier must fail, a banned path must fail,
/// and a stale baseline must fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-no-legacy")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        put("src/clean.rs", "// B.U.D. 3.0 only.\n")?;
        put(BASELINE, "# legacy\n")?;
        run(&dir).map_err(|e| format!("canary: a clean tree failed: {e}"))?;
        put("src/bad.rs", "// uses ContentManifest today\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an injected identifier passed"));
        }
        put(BASELINE, "src/bad.rs\n")?;
        run(&dir).map_err(|e| format!("canary: a baselined file failed: {e}"))?;
        put("src/bad.rs", "// fixed.\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a stale baseline line passed"));
        }
        put("src/domain/storage_deal.rs", "// legacy deal economy\n")?;
        put(BASELINE, "# empty again\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a banned path passed while unlisted"));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "no-legacy-storage canary OK: an injected identifier failed, a banned path failed, a stale baseline failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_legacy_storage_gate_catches_injected_identifier() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
