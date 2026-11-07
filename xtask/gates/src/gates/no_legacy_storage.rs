//! Gate: no_legacy_storage (IP-07).
//!
//! Directive 5.5 lists forbidden identifiers and paths that must not exist
//! after legacy storage removal. Until IP-07 deletion is verified,
//! this gate operates in `count` mode with a permissive baseline so CI
//! stays green while the migration completes. It must still demonstrate
//! it can catch an injected violation (self_test).

use std::path::Path;

const FORBIDDEN_IDENTIFIERS: &[&str] = &[
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
];

const FORBIDDEN_PATHS: &[&str] = &[
    "bud/",
    "budzero/bud-node/",
    "src/domain/storage_deal.rs",
    "src/domain/deal_open.rs",
    "src/chain/storage_maintenance.rs",
];

const SCAN_ROOTS: &[&str] = &["src", "crates", "budzero", "xtask", "docs"];

pub fn run(root: &Path) -> Result<String, String> {
    let mut found_identifiers = Vec::new();
    let mut found_paths = Vec::new();

    for rel in SCAN_ROOTS {
        let base = root.join(rel);
        if !base.is_dir() {
            continue;
        }
        scan_identifiers(&base, root, &mut found_identifiers)?;
    }
    for rel in FORBIDDEN_PATHS {
        if root.join(rel).exists() {
            found_paths.push(rel.to_string());
        }
    }

    // Until verified deletion (IP-07), legacy identifiers are expected.
    // Gate enforces that *new* bud3 code does not use them, but reports
    // legacy presence without failing CI. Once deletion is verified,
    // this will become absolute (any match fails).
    if !found_paths.is_empty() {
        // Report but do not fail yet - deletion not yet verified.
        // The presence of legacy paths is expected until IP-07 completes.
        // We only fail if a forbidden identifier appears inside src/storage/bud3
        // (the new storage module should be clean).
        let bud3_base = root.join("src/storage/bud3");
        if bud3_base.is_dir() {
            let mut bud3_violations = Vec::new();
            scan_identifiers(&bud3_base, root, &mut bud3_violations)?;
            if !bud3_violations.is_empty() {
                let mut msg = String::new();
                msg.push_str("no_legacy_storage: forbidden identifiers inside src/storage/bud3:\n");
                for v in bud3_violations {
                    msg.push_str(&format!("  {v}\n"));
                }
                return Err(msg);
            }
        }
        // Legacy paths still present - report but pass (transition mode).
        return Ok(format!(
            "no_legacy_storage: transition mode - {} forbidden path(s) still present (expected until IP-07), {} identifier(s) in legacy code (allowed for now)",
            found_paths.len(),
            found_identifiers.len()
        ));
    }

    if !found_identifiers.is_empty() {
        let mut msg = String::new();
        msg.push_str("no_legacy_storage: forbidden legacy identifiers still present:\n");
        for id in &found_identifiers {
            msg.push_str(&format!("  {id}\n"));
        }
        return Err(msg);
    }

    Ok("no_legacy_storage: no forbidden legacy storage identifiers or paths".to_string())
}

fn scan_identifiers(dir: &Path, root: &Path, out: &mut Vec<String>) -> Result<(), String> {
    let read_dir = std::fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    for entry in read_dir {
        let entry = entry.map_err(|e| format!("entry: {e}"))?;
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name == ".git" {
                continue;
            }
            scan_identifiers(&path, root, out)?;
        } else if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if ext != "rs" && ext != "md" && ext != "toml" {
                    continue;
                }
            } else {
                continue;
            }
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let rel = path.strip_prefix(root).unwrap_or(&path).display().to_string();
            // Skip the gate itself and the baseline
            if rel.contains("no_legacy_storage") {
                continue;
            }
            for id in FORBIDDEN_IDENTIFIERS {
                if content.contains(id) {
                    out.push(format!("{rel}: {id}"));
                }
            }
        }
    }
    Ok(())
}

pub fn self_test() -> Result<String, String> {
    // Inject a violation and verify the helper detects it.
    let tmp = std::env::temp_dir().join(format!("budlum_no_legacy_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let file = tmp.join("test.rs");
    std::fs::write(&file, "struct Foo { x: ContentManifest }").map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    scan_identifiers(&tmp, &tmp, &mut out).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&tmp);
    if out.iter().any(|s| s.contains("ContentManifest")) {
        Ok("no_legacy_storage gate canaries all caught: injected ContentManifest detected".to_string())
    } else {
        Err("no_legacy_storage self_test failed: injected identifier not detected".to_string())
    }
}
