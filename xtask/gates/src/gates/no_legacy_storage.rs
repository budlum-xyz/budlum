//! No legacy storage identifiers and no legacy storage paths.
//!
//! The old content stack is gone. Its identifiers are not vocabulary: a
//! name that reappears revives the old model by accident, in a type, a
//! comment or a document. The same holds for the paths the stack owned.
//!
//! This gate searches `src/`, `crates/`, `budzero/`, `xtask/` and `docs/`
//! for the retired identifiers as words, and refuses the retired paths.
//! A find is a red build.

use std::path::Path;

/// The retired identifiers, matched as words.
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

/// The retired paths.
const PATHS: &[&str] = &[
    "bud",
    "budzero/bud-node",
    "src/domain/storage_deal.rs",
    "src/domain/deal_open.rs",
    "src/chain/storage_maintenance.rs",
];

const ROOTS: &[&str] = &["src", "crates", "budzero", "xtask", "docs"];

const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// This gate names the identifiers to forbid them.
const SELF: &[&str] = &["xtask/gates/src/gates/no_legacy_storage.rs"];

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, std::path::PathBuf)>) {
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

/// Word-boundary scan of one text for one identifier.
fn word_in(text: &str, word: &str) -> bool {
    let mut from = 0usize;
    while let Some(at) = text[from..].find(word) {
        let start = from + at;
        let end = start + word.len();
        let before_ok = start == 0 || !text.as_bytes()[start - 1].is_ascii_alphanumeric();
        let after_ok = end >= text.len() || !text.as_bytes()[end].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// # Errors
///
/// The retired identifier or path that is present.
pub fn run(root: &Path) -> Result<String, String> {
    let mut path_hits = Vec::new();
    for p in PATHS {
        if root.join(p).exists() {
            path_hits.push(*p);
        }
    }
    if !path_hits.is_empty() {
        return Err(format!(
            "retired storage path(s) still exist: {path_hits:?}\n  \\\n  The old stack is gone; its paths are not allowed back."
        ));
    }
    let mut files = Vec::new();
    for r in ROOTS {
        let p = root.join(r);
        if p.exists() {
            walk(&p, root, &mut files);
        }
    }
    let mut found = Vec::new();
    for (rel, path) in &files {
        if SELF.contains(&rel.as_str()) {
            continue;
        }
        if std::fs::metadata(path).map_or(true, |m| m.len() > 4 * 1024 * 1024) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for id in IDENTIFIERS {
            if word_in(&text, id) {
                found.push(format!("  {rel}: {id}"));
            }
        }
    }
    if !found.is_empty() {
        return Err(format!(
            "retired storage identifiers found:\n{}\n  \\\n  The old content stack is gone; its names are not vocabulary. \\\n  Say what the system does now.",
            found.join("\n")
        ));
    }
    Ok(format!(
        "no legacy storage OK: {} retired identifiers and {} retired paths are absent from {} files",
        IDENTIFIERS.len(),
        PATHS.len(),
        files.len()
    ))
}

/// The canary: an injected identifier and an injected path must each fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-legacy")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        put("src/clean.rs", "// nothing retired here.\n")?;
        run(&dir).map_err(|e| format!("canary: a clean tree failed: {e}"))?;
        put("src/bad.rs", "// OpenChallenge was refused here.\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an injected identifier passed"));
        }
        put("src/bad.rs", "// OpenChallengeBlocksExpiry is a different identifier.\n")?;
        run(&dir).map_err(|e| format!("canary: a compound name failed: {e}"))?;
        put("src/bad.rs", "// fixed.\n")?;
        std::fs::create_dir_all(dir.join("bud")).map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an injected retired path passed"));
        }
        std::fs::remove_dir_all(dir.join("bud")).map_err(|e| e.to_string())?;
        run(&dir).map_err(|e| format!("canary: the restored tree failed: {e}"))?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "no-legacy-storage canary OK: an injected identifier failed, a compound name passed, and a retired path failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_legacy_storage_gate_catches_injected_identifier() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
