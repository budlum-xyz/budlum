//! No legacy storage system may stay in the tree.
//!
//! Directive section 5.5 names the identifiers and the paths that belong to the
//! storage systems B.U.D. 3.0 replaces: the 2.0 manifests, the erasure and LRC
//! layouts, the provider trait, the coding audits, the mobile self profiles and
//! the Three recipe surfaces. Finding one of them in `src`, `crates`,
//! `budzero`, `xtask` or `docs` is a finding, not a style question: the tree is
//! supposed to have one storage system, and a legacy identifier is a second
//! one still reachable.
//!
//! # Why a ratchet and not a hard zero
//!
//! A hard zero on the day the gate lands would be a gate nobody can merge
//! against, because the migration is in progress: the B.U.D. 3.0 modules exist
//! next to the modules they replace. So the gate carries a baseline, the same
//! shape `concept-names`, `dead-public-api` and `idle-code` use. A count above
//! the baseline fails (a legacy name was added), a count below it fails until
//! the baseline is lowered (the file is the ratchet), and the number can only
//! fall. When every line is zero the baseline is deleted and the gate becomes
//! absolute.
//!
//! # Two kinds of entry
//!
//! * `path:<prefix>` is one of the forbidden paths of section 5.5. Its value is
//!   the number of files under it, so a half-emptied directory still shows work
//!   left to do rather than a silent zero.
//! * every other entry is a forbidden identifier, counted as whole-word
//!   occurrences across the scanned text files.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// The roots the gate searches.
const SCAN_ROOTS: &[&str] = &["src", "crates", "budzero", "xtask", "docs"];

/// Directories that are never source.
const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// Files above this size are not source text.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// The identifiers of directive section 5.5.
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
];

/// The paths of directive section 5.5, as `path:<prefix>` baseline entries.
const FORBIDDEN_PATHS: &[&str] = &[
    "bud/",
    "budzero/bud-node/",
    "src/domain/storage_deal.rs",
    "src/domain/deal_open.rs",
    "src/chain/storage_maintenance.rs",
];

const BASELINE_PATH: &str = ".github/no-legacy-storage-baseline.txt";

/// The gate's own file, excluded from the scan for the reason in `measure`.
const SELF_PATH: &str = "xtask/gates/src/gates/no_legacy_storage.rs";
const WRITE_ENV: &str = "BUDLUM_NO_LEGACY_STORAGE_WRITE";

/// Is this byte part of a word, for the whole-word rule?
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Whole-word occurrences of `needle` in `text`.
///
/// A `CamelCase` identifier is a word here: the check is that neither neighbour
/// of the match is an ASCII word byte, so `StorageRegistryEntry` does not count
/// as `StorageRegistry` and `MyStorageRegistry` does not either. Both are
/// separate identifiers and counting them as the forbidden one would make the
/// ratchet lie in the direction that hides work.
fn count_word(text: &str, needle: &str) -> usize {
    let hay = text.as_bytes();
    let mut count = 0usize;
    for (start, _) in text.match_indices(needle) {
        let end = start + needle.len();
        let before_ok = start == 0 || !is_word_byte(hay[start - 1]);
        let after_ok = end >= hay.len() || !is_word_byte(hay[end]);
        if before_ok && after_ok {
            count += 1;
        }
    }
    count
}

fn collect_files(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if SKIP_DIRS.contains(&name_str.as_ref()) {
                continue;
            }
            collect_files(&path, root, out);
        } else if ft.is_file() {
            if let Ok(rel) = path.strip_prefix(root) {
                let rel = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((rel, path));
            }
        }
    }
}

/// Count files under one forbidden path.
fn count_path(root: &Path, prefix: &str) -> usize {
    let target = root.join(prefix.trim_end_matches('/'));
    if target.is_file() {
        return 1;
    }
    if !target.is_dir() {
        return 0;
    }
    let mut files = Vec::new();
    collect_files(&target, root, &mut files);
    files
        .iter()
        .filter(|(rel, _)| rel.starts_with(prefix))
        .count()
}

/// Measure every entry over one tree.
fn measure(root: &Path) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for id in IDENTIFIERS {
        counts.insert((*id).to_string(), 0);
    }
    for p in FORBIDDEN_PATHS {
        counts.insert(format!("path:{p}"), count_path(root, *p));
    }
    let mut files = Vec::new();
    for r in SCAN_ROOTS {
        collect_files(&root.join(r), root, &mut files);
    }
    for (rel, path) in files {
        // This file holds the identifier list, so counting it would count the
        // gate itself once per name and inflate every number in the baseline.
        if rel == SELF_PATH {
            continue;
        }
        let Ok(meta) = fs::metadata(&path) else { continue };
        if meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else { continue };
        for id in IDENTIFIERS {
            let n = count_word(&text, *id);
            if n > 0 {
                if let Some(slot) = counts.get_mut(*id) {
                    *slot += n;
                }
            }
        }
    }
    counts
}

fn parse_baseline(text: &str) -> Result<BTreeMap<String, usize>, String> {
    let mut out = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some((name, value)) = t.split_once('|') else {
            return Err(format!("{BASELINE_PATH}:{}: expected `name|count`", i + 1));
        };
        let n = value
            .trim()
            .parse::<usize>()
            .map_err(|e| format!("{BASELINE_PATH}:{}: {e}", i + 1))?;
        out.insert(name.trim().to_string(), n);
    }
    Ok(out)
}

fn render_baseline(counts: &BTreeMap<String, usize>) -> String {
    let mut s = String::from(
        "# Legacy storage identifiers and paths of directive section 5.5.\n\
         # One line per entry: name|count. A ratchet: the numbers may only fall.\n\
         # Lower it with: BUDLUM_NO_LEGACY_STORAGE_WRITE=1 budlum-gates no-legacy-storage\n\
         # Delete this file when every line is zero; the gate then becomes absolute.\n",
    );
    for (name, n) in counts {
        let _ = writeln!(s, "{name}|{n}");
    }
    s
}

fn check(root: &Path, write: bool) -> Result<String, String> {
    let counts = measure(root);
    let total: usize = counts.values().sum();
    let base_path = root.join(BASELINE_PATH);
    let baseline = match fs::read_to_string(&base_path) {
        Ok(t) => parse_baseline(&t)?,
        Err(_) if write => BTreeMap::new(),
        Err(e) => return Err(format!("cannot read {BASELINE_PATH}: {e}")),
    };

    if write {
        for (name, n) in &counts {
            if let Some(b) = baseline.get(name) {
                if n > b {
                    return Err(format!(
                        "refusing to write: {name} rose to {n}, above the baseline {b}",
                    ));
                }
            }
        }
        fs::write(&base_path, render_baseline(&counts))
            .map_err(|e| format!("cannot write {BASELINE_PATH}: {e}"))?;
        return Ok(format!("wrote {BASELINE_PATH}: {total} legacy occurrence(s) in total."));
    }

    let mut bad = String::new();
    for (name, n) in &counts {
        match baseline.get(name) {
            None => {
                let _ = writeln!(bad, "  {name}: no line in {BASELINE_PATH}");
            }
            Some(b) => {
                if n > b {
                    let _ = writeln!(
                        bad,
                        "  {name}: {n}, above the baseline {b}. A legacy storage name was added.",
                    );
                } else if n < b {
                    let _ = writeln!(
                        bad,
                        "  {name}: {n}, below the baseline {b}. Lower {BASELINE_PATH} (run with {WRITE_ENV}=1).",
                    );
                }
            }
        }
    }
    for name in baseline.keys() {
        if !counts.contains_key(name) {
            let _ = writeln!(
                bad,
                "  {name}: baseline line for an entry section 5.5 no longer lists",
            );
        }
    }
    if bad.is_empty() {
        Ok(format!(
            "OK: no legacy storage entry above its baseline, {total} occurrence(s) left in total.",
        ))
    } else {
        Err(format!("FAIL: legacy storage entries:\n{bad}"))
    }
}

fn scratch_dir() -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!(
        "budlum-no-legacy-storage-{}-{:?}",
        std::process::id(),
        std::thread::current().id(),
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create scratch dir: {e}"))?;
    Ok(dir)
}

fn seed_baseline(dir: &Path) -> Result<(), String> {
    let counts = measure(dir);
    fs::write(dir.join(BASELINE_PATH), render_baseline(&counts))
        .map_err(|e| format!("cannot write baseline: {e}"))
}

/// # Errors
///
/// Returns every entry whose count moved away from the baseline.
pub fn run(root: &Path) -> Result<String, String> {
    let write = std::env::var(WRITE_ENV).is_ok();
    check(root, write)
}

/// # Errors
///
/// The self-test fails when a tree it stages is classified wrongly.
pub fn self_test() -> Result<String, String> {
    let tmp = scratch_dir()?;
    fs::create_dir_all(tmp.join(".github")).map_err(|e| format!("cannot create .github: {e}"))?;

    // A clean tree passes once its baseline is written from the same rules.
    let clean = tmp.join("clean");
    fs::create_dir_all(clean.join("src")).map_err(|e| format!("cannot create src: {e}"))?;
    fs::write(clean.join("src/lib.rs"), "pub fn canonical_object() {}\n")
        .map_err(|e| format!("cannot write lib.rs: {e}"))?;
    fs::create_dir_all(clean.join(".github")).map_err(|e| format!("cannot create .github: {e}"))?;
    seed_baseline(&clean)?;
    if let Err(msg) = check(&clean, false) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("canary: a clean tree was rejected: {msg}"));
    }

    // One added identifier must be caught. The baseline is unchanged, so this
    // is the rise case the gate exists for.
    let dirty = tmp.join("dirty");
    fs::create_dir_all(dirty.join("src")).map_err(|e| format!("cannot create src: {e}"))?;
    fs::write(dirty.join("src/lib.rs"), "pub fn canonical_object() {}\n")
        .map_err(|e| format!("cannot write lib.rs: {e}"))?;
    fs::create_dir_all(dirty.join(".github")).map_err(|e| format!("cannot create .github: {e}"))?;
    seed_baseline(&dirty)?;
    fs::write(
        dirty.join("src/legacy.rs"),
        "pub struct StorageProvider;\npub struct StorageDealOpen;\n",
    )
    .map_err(|e| format!("cannot write legacy.rs: {e}"))?;
    if check(&dirty, false).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from("canary: an added legacy identifier was not detected"));
    }

    // A forbidden path must be caught even when no identifier is written in it:
    // the directory itself is the finding.
    let path_case = tmp.join("path_case");
    fs::create_dir_all(path_case.join("src")).map_err(|e| format!("cannot create src: {e}"))?;
    fs::write(path_case.join("src/lib.rs"), "pub fn canonical_object() {}\n")
        .map_err(|e| format!("cannot write lib.rs: {e}"))?;
    fs::create_dir_all(path_case.join(".github"))
        .map_err(|e| format!("cannot create .github: {e}"))?;
    seed_baseline(&path_case)?;
    fs::create_dir_all(path_case.join("src/domain"))
        .map_err(|e| format!("cannot create src/domain: {e}"))?;
    fs::write(path_case.join("src/domain/storage_deal.rs"), "pub fn f() {}\n")
        .map_err(|e| format!("cannot write storage_deal.rs: {e}"))?;
    if check(&path_case, false).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from("canary: a forbidden path was not detected"));
    }

    // A fall that the baseline has not followed must fail too, or the baseline
    // stops being a ratchet.
    let fell = tmp.join("fell");
    fs::create_dir_all(fell.join("src")).map_err(|e| format!("cannot create src: {e}"))?;
    fs::write(fell.join("src/lib.rs"), "pub fn canonical_object() {}\n")
        .map_err(|e| format!("cannot write lib.rs: {e}"))?;
    fs::create_dir_all(fell.join(".github")).map_err(|e| format!("cannot create .github: {e}"))?;
    seed_baseline(&fell)?;
    let stale = format!("StorageProvider|1\n");
    fs::write(fell.join(BASELINE_PATH), stale).map_err(|e| format!("cannot write: {e}"))?;
    if check(&fell, false).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a count below the baseline was accepted; the ratchet does not hold",
        ));
    }

    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "no-legacy-storage self-test OK: a clean tree passed, an added identifier, a forbidden path and a stale baseline were each caught.",
    ))
}
