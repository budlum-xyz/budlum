//! Every content class enters through the universal B.U.D. 3.0 Object.
//!
//! Section 16.3 / İP-19: `bud3_object_is_universal` enforces that there is
//! one object model, `bud3::Object`, and that content classes (video,
//! audio, document, deed, NFT bind, paywalled, sealed, empty) all enter
//! through RegisterObject rather than through a separate transaction type
//! or a legacy "recipe" model.
//!
//! Today this is a skeleton gate: it refuses known legacy class-specific
//! registration transaction names (the B.U.D. 2.0 `three_recipe` /
//! `VideoRecipe` path) and relies on the `no_legacy_storage` identifier
//! bans for the rest. The full gate (İP-19) walks the transaction-type
//! enum and confirms every content class maps to a RegisterObject call.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

const LEGACY_CLASS_TX: &[&str] = &[
    "RegisterManifest",
    "RegisterThreeRecipe",
    "OpenDeal",
    "bud_storageRegisterManifest",
];

const ROOTS: &[&str] = &["src", "crates", "budzero", "xtask"];
const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];
const SELF: &[&str] = &[
    "xtask/gates/src/gates/bud3_object_is_universal.rs",
    // Legacy shell gates that still reference RegisterManifest by name
    // to refuse it; they are deleted in WP-07/İP-19.
    "xtask/gates/src/gates/paid_content.rs",
    "xtask/gates/src/gates/untrusted_manifests.rs",
    "xtask/gates/src/gates/no_legacy_storage.rs",
];
const HISTORY_DIRS: &[&str] = &["docs/audit/", "docs/work/"];
const BASELINE: &str = ".github/bud3-object-is-universal-baseline.txt";

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, std::path::PathBuf)>) {
    if dir.is_file() {
        if let Ok(rel) = dir.strip_prefix(root) {
            out.push((rel.to_string_lossy().replace('\\', "/"), dir.to_path_buf()));
        }
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
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

fn offenders(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    for r in ROOTS {
        let p = root.join(r);
        if p.exists() { walk(&p, root, &mut files); }
    }
    let mut out = Vec::new();
    for (rel, path) in files {
        if SELF.contains(&rel.as_str()) || HISTORY_DIRS.iter().any(|d| rel.starts_with(d)) {
            continue;
        }
        if !rel.ends_with(".rs") { continue; }
        let Ok(bytes) = std::fs::read(&path) else { continue };
        for tok in LEGACY_CLASS_TX {
            if contains_word(&bytes, tok.as_bytes()) {
                out.push((rel, (*tok).to_string()));
                break;
            }
        }
    }
    out
}

fn baseline(root: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(root.join(BASELINE))
        .unwrap_or_default()
        .lines().map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

pub fn run(root: &Path) -> Result<String, String> {
    let hits = offenders(root);
    let allowed = baseline(root);
    let mut new = String::new();
    let hit_set: BTreeSet<&str> = hits.iter().map(|(f, _)| f.as_str()).collect();
    for (file, tok) in &hits {
        if !allowed.contains(file) {
            let _ = writeln!(new, "  {file}: {tok}");
        }
    }
    let mut stale = String::new();
    for file in &allowed {
        if !hit_set.contains(file.as_str()) {
            let _ = writeln!(stale, "  {file}");
        }
    }
    if !new.is_empty() {
        return Err(format!(
            "FAIL: class-specific content registration transaction found; all content classes must enter through bud3::Object::RegisterObject:\n{new}"
        ));
    }
    if !stale.is_empty() {
        return Err(format!(
            "FAIL: these baseline files no longer reference class-specific tx types; remove their lines from {BASELINE}:\n{stale}"
        ));
    }
    Ok(format!(
        "bud3-object-is-universal OK: {} file(s) on the shrinking baseline",
        hits.len()
    ))
}

pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-object-universal")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        put("src/chain/clean.rs", "pub fn register() {}\n")?;
        put(BASELINE, "# empty\n")?;
        run(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;
        put("src/chain/bad.rs", "pub enum Tx { RegisterManifest }\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: RegisterManifest was accepted"));
        }
        put(BASELINE, "src/chain/bad.rs\n")?;
        run(&dir).map_err(|e| format!("canary: baselined offender failed: {e}"))?;
        put("src/chain/bad.rs", "pub enum Tx { RegisterObject }\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: stale baseline entry was accepted after file was fixed"));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from("bud3-object-is-universal canary OK: class-specific tx types refused, baselined passes, stale baseline fails."))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() { assert!(super::self_test().is_ok(), "{:?}", super::self_test()); }
}
