//! The concept-name counter gate.
//!
//! `config/naming/concept_map.toml` lists every legacy architecture name. This
//! gate searches the tree for each entry's `patterns` and holds the counts
//! against `.github/concept-names-baseline.txt`.
//!
//! * `count` mode (the starting mode): a count above the baseline fails, and a
//!   count below it also fails until the baseline is lowered, so the number can
//!   only fall and the file is the ratchet.
//! * `absolute` mode (set once every count is zero): any match fails.
//!
//! To lower the baseline run the gate with `BUDLUM_CONCEPT_NAMES_WRITE=1`. The
//! writer refuses to raise any number.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

/// The roots the gate searches.
const SCAN_ROOTS: &[&str] = &[
    "src",
    "crates",
    "budzero",
    "execution",
    "mobile",
    "xtask",
    "docs",
    "config",
    "proto",
    "contracts",
];

/// Directories that are never source.
const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// Files above this size are not source text.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

const MAP_PATH: &str = "config/naming/concept_map.toml";
const BASELINE_PATH: &str = ".github/concept-names-baseline.txt";
const WRITE_ENV: &str = "BUDLUM_CONCEPT_NAMES_WRITE";

/// Counts for one concept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Count {
    pub files: usize,
    pub matches: usize,
}

/// Count mode ratchets, absolute mode forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Count,
    Absolute,
}

/// One entry of the map, reduced to what the gate reads.
struct Concept {
    name: String,
    owner: String,
    patterns: Vec<regex::Regex>,
    paths: Vec<String>,
    allow_paths: Vec<String>,
}

fn is_known_owner(owner: &str) -> bool {
    matches!(
        owner,
        "consensus"
            | "operations"
            | "settlement"
            | "storage"
            | "explorer"
            | "wallet"
            | "persistence"
            | "budzero"
            | "object-format"
            | "storage-api"
            | "placement"
            | "codecs"
            | "storage-migration"
            | "privacy"
            | "proof-recursion"
            | "ai-privacy"
            | "object-layer"
            | "naming"
    )
}

struct Map {
    mode: Mode,
    global_allow: Vec<String>,
    concepts: Vec<Concept>,
}

/// Compare measured counts against a baseline for one concept.
///
/// # Errors
///
/// A rise, or a fall that the baseline has not followed.
pub fn compare(name: &str, measured: Count, baseline: Count) -> Result<(), String> {
    if measured.files > baseline.files || measured.matches > baseline.matches {
        return Err(format!(
            "{name}: the count rose to {} file(s) / {} match(es), above the baseline {} / {}. A legacy name was added.",
            measured.files, measured.matches, baseline.files, baseline.matches
        ));
    }
    if measured != baseline {
        return Err(format!(
            "{name}: the count fell to {} file(s) / {} match(es) and the baseline is still {} / {}. Lower {BASELINE_PATH} (run with {WRITE_ENV}=1).",
            measured.files, measured.matches, baseline.files, baseline.matches
        ));
    }
    Ok(())
}

fn string_list(table: &toml::Table, key: &str) -> Result<Vec<String>, String> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("`{key}` holds a non-string entry"))
            })
            .collect(),
        Some(_) => Err(format!("`{key}` is not an array")),
    }
}

fn required_str<'a>(table: &'a toml::Table, key: &str, who: &str) -> Result<&'a str, String> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{who}: missing or empty `{key}`"))
}

fn parse_map(text: &str) -> Result<Map, String> {
    let table: toml::Table = text.parse().map_err(|e| format!("{MAP_PATH}: {e}"))?;
    if table.get("schema").and_then(toml::Value::as_integer) != Some(1) {
        return Err(format!("{MAP_PATH}: `schema` must be 1"));
    }
    let mode = match table.get("mode").and_then(toml::Value::as_str) {
        Some("count") => Mode::Count,
        Some("absolute") => Mode::Absolute,
        other => {
            return Err(format!(
                "{MAP_PATH}: `mode` must be count or absolute, got {other:?}"
            ))
        }
    };
    let global_allow = string_list(&table, "global_allow_paths")?;
    let entries = table
        .get("concept")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("{MAP_PATH}: no [[concept]] entries"))?;
    let mut concepts = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let t = entry
            .as_table()
            .ok_or_else(|| format!("concept #{i} is not a table"))?;
        let old = string_list(t, "old")?;
        let name = old
            .first()
            .cloned()
            .ok_or_else(|| format!("concept #{i}: `old` is empty"))?;
        let who = format!("concept `{name}`");
        for key in ["new_code", "term_en", "term_tr", "area", "reason"] {
            required_str(t, key, &who)?;
        }
        let owner = required_str(t, "owner", &who)?.to_string();
        if !is_known_owner(&owner) {
            return Err(format!("{who}: unknown component owner `{owner}`"));
        }
        let raw = string_list(t, "patterns")?;
        if raw.is_empty() {
            return Err(format!("{who}: `patterns` is empty"));
        }
        let mut patterns = Vec::new();
        for p in raw {
            patterns
                .push(regex::Regex::new(&p).map_err(|e| format!("{who}: bad pattern {p}: {e}"))?);
        }
        concepts.push(Concept {
            name,
            owner,
            patterns,
            paths: string_list(t, "paths")?,
            allow_paths: string_list(t, "allow_paths")?,
        });
    }
    Ok(Map {
        mode,
        global_allow,
        concepts,
    })
}

fn collect_files(dir: &Path, root: &Path, out: &mut Vec<(String, std::path::PathBuf)>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            let name = entry.file_name();
            if SKIP_DIRS.iter().any(|s| name.to_str() == Some(s)) {
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

fn under(rel: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|p| rel.starts_with(p.as_str()))
}

/// Count every concept over the tree.
fn measure(map: &Map, root: &Path) -> BTreeMap<String, Count> {
    let mut files = Vec::new();
    for r in SCAN_ROOTS {
        collect_files(&root.join(r), root, &mut files);
    }
    let mut counts: BTreeMap<String, Count> = map
        .concepts
        .iter()
        .map(|c| (c.name.clone(), Count::default()))
        .collect();
    for (rel, path) in files {
        if under(&rel, &map.global_allow) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for c in &map.concepts {
            if (!c.paths.is_empty() && !under(&rel, &c.paths)) || under(&rel, &c.allow_paths) {
                continue;
            }
            let n: usize = text
                .lines()
                .map(|line| {
                    c.patterns
                        .iter()
                        .map(|p| p.find_iter(line).count())
                        .sum::<usize>()
                })
                .sum();
            if n > 0 {
                if let Some(slot) = counts.get_mut(&c.name) {
                    slot.files += 1;
                    slot.matches += n;
                }
            }
        }
    }
    counts
}

fn parse_baseline(text: &str) -> Result<BTreeMap<String, Count>, String> {
    let mut out = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = t.split('|').collect();
        let [name, files, matches] = parts.as_slice() else {
            return Err(format!(
                "{BASELINE_PATH}:{}: expected `name|files|matches`",
                i + 1
            ));
        };
        let num = |s: &str| {
            s.trim()
                .parse::<usize>()
                .map_err(|e| format!("{BASELINE_PATH}:{}: {e}", i + 1))
        };
        out.insert(
            (*name).to_string(),
            Count {
                files: num(files)?,
                matches: num(matches)?,
            },
        );
    }
    Ok(out)
}

fn render_baseline(counts: &BTreeMap<String, Count>) -> String {
    let mut s = String::from(
        "# Legacy concept-name counts per entry of config/naming/concept_map.toml.\n\
         # One line per entry: name|files|matches. A ratchet: the numbers may only fall.\n\
         # Lower it with: BUDLUM_CONCEPT_NAMES_WRITE=1 budlum-gates concept-names\n\
         # The map moves to `absolute` mode once every line is zero.\n",
    );
    for (name, c) in counts {
        let _ = writeln!(s, "{name}|{}|{}", c.files, c.matches);
    }
    s
}

/// Check a tree. Pure of the environment, so the canary can stage one.
fn check(root: &Path, write: bool) -> Result<String, String> {
    let text = std::fs::read_to_string(root.join(MAP_PATH))
        .map_err(|e| format!("cannot read {MAP_PATH}: {e}"))?;
    let map = parse_map(&text)?;
    let counts = measure(&map, root);
    let total: usize = counts.values().map(|c| c.matches).sum();

    if map.mode == Mode::Absolute {
        let mut bad = String::new();
        for (name, c) in &counts {
            if c.matches > 0 {
                let _ = writeln!(
                    bad,
                    "  {name}: {} file(s) / {} match(es)",
                    c.files, c.matches
                );
            }
        }
        return if bad.is_empty() {
            Ok(String::from(
                "OK: absolute mode, no legacy concept name remains.",
            ))
        } else {
            Err(format!(
                "FAIL: legacy concept names in absolute mode:\n{bad}"
            ))
        };
    }

    let base_path = root.join(BASELINE_PATH);
    let baseline = match std::fs::read_to_string(&base_path) {
        Ok(t) => parse_baseline(&t)?,
        Err(_) if write => BTreeMap::new(),
        Err(e) => return Err(format!("cannot read {BASELINE_PATH}: {e}")),
    };
    if write {
        for (name, c) in &counts {
            if let Some(b) = baseline.get(name) {
                if c.files > b.files || c.matches > b.matches {
                    return Err(format!(
                        "refusing to write: {name} rose to {} / {} above the baseline {} / {}",
                        c.files, c.matches, b.files, b.matches
                    ));
                }
            }
        }
        std::fs::write(&base_path, render_baseline(&counts))
            .map_err(|e| format!("cannot write {BASELINE_PATH}: {e}"))?;
        return Ok(format!(
            "wrote {BASELINE_PATH}: {total} legacy match(es) in total."
        ));
    }

    let owners: BTreeMap<&str, &str> = map
        .concepts
        .iter()
        .map(|c| (c.name.as_str(), c.owner.as_str()))
        .collect();
    let mut bad = String::new();
    for (name, c) in &counts {
        match baseline.get(name) {
            None => {
                let _ = writeln!(bad, "  {name}: no line in {BASELINE_PATH}");
            }
            Some(b) => {
                if let Err(e) = compare(name, *c, *b) {
                    let owner = owners.get(name.as_str()).copied().unwrap_or("unknown");
                    let _ = writeln!(bad, "  [{owner}] {e}");
                }
            }
        }
    }
    for name in baseline.keys() {
        if !counts.contains_key(name) {
            let _ = writeln!(
                bad,
                "  {name}: baseline line for an entry the map no longer has"
            );
        }
    }
    if bad.is_empty() {
        Ok(format!(
            "OK: count mode, {} concept(s), {total} legacy match(es), all equal to the baseline.",
            counts.len()
        ))
    } else {
        Err(format!("FAIL: concept-name counts:\n{bad}"))
    }
}

/// The gate.
///
/// # Errors
///
/// A finding, as a sentence.
pub fn run(root: &Path) -> Result<String, String> {
    check(root, std::env::var_os(WRITE_ENV).is_some_and(|v| v == "1"))
}

const CANARY_MAP: &str = "schema = 1\nmode = \"count\"\nglobal_allow_paths = [\"config/naming/\", \"docs/NAMING.md\"]\n\n[[concept]]\nold = [\"Canaryname\"]\npatterns = ['(?i)canary-?name']\nnew_code = \"x\"\nterm_en = \"x\"\nterm_tr = \"x\"\narea = \"x\"\nowner = \"naming\"\nreason = \"x\"\n";

fn stage(root: &Path, map: &str, baseline: &str) -> Result<(), String> {
    let put = |rel: &str, body: &str| -> Result<(), String> {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&p, body).map_err(|e| e.to_string())
    };
    put(MAP_PATH, map)?;
    put(BASELINE_PATH, baseline)?;
    put("src/clean.rs", "fn clean() {}\n")?;
    put("docs/NAMING.md", "This file may name CANARY-NAME freely.\n")
}

/// The canary: an injected legacy name must turn the gate red.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-concepts")?;
    let result = (|| {
        let zero = "Canaryname|0|0\n";
        stage(&dir, CANARY_MAP, zero)?;
        check(&dir, false).map_err(|e| format!("canary: a clean tree failed: {e}"))?;
        std::fs::write(dir.join("src/injected.rs"), "// CanaryName\n")
            .map_err(|e| e.to_string())?;
        match check(&dir, false) {
            Err(e) if e.contains("rose") => {}
            other => {
                return Err(format!(
                    "canary: the injected name did not raise the count: {other:?}"
                ))
            }
        }
        std::fs::write(dir.join(BASELINE_PATH), "Canaryname|1|1\n").map_err(|e| e.to_string())?;
        check(&dir, false).map_err(|e| format!("canary: an equal baseline failed: {e}"))?;
        std::fs::remove_file(dir.join("src/injected.rs")).map_err(|e| e.to_string())?;
        match check(&dir, false) {
            Err(e) if e.contains("fell") => {}
            other => return Err(format!("canary: a lowered count was accepted: {other:?}")),
        }
        if check(&dir, true).is_err() {
            return Err(String::from("canary: the writer failed on a lowered count"));
        }
        std::fs::write(dir.join("src/injected.rs"), "// CanaryName\n")
            .map_err(|e| e.to_string())?;
        if check(&dir, true).is_ok() {
            return Err(String::from("canary: the writer raised the baseline"));
        }
        stage(&dir, &CANARY_MAP.replace("count", "absolute"), zero)?;
        if check(&dir, false).is_ok() {
            return Err(String::from("canary: absolute mode accepted a legacy name"));
        }
        stage(&dir, &CANARY_MAP.replace("naming", "unknown"), zero)?;
        if check(&dir, false).is_ok() {
            return Err(String::from("canary: accepted an unknown component owner"));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "concept-names canary OK: an injected name raised the count, a lowered count and a rising writer were refused, and absolute mode failed.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concept_names_gate_catches_injected_name() {
        assert!(
            self_test().is_ok_and(|m| m.contains("injected")),
            "canary must prove the injected name turns the gate red"
        );
    }

    #[test]
    fn concept_names_baseline_only_decreases() {
        let b = Count {
            files: 3,
            matches: 10,
        };
        assert!(compare(
            "x",
            Count {
                files: 3,
                matches: 10
            },
            b
        )
        .is_ok());
        assert!(compare(
            "x",
            Count {
                files: 4,
                matches: 10
            },
            b
        )
        .is_err());
        assert!(compare(
            "x",
            Count {
                files: 3,
                matches: 11
            },
            b
        )
        .is_err());
        assert!(compare(
            "x",
            Count {
                files: 2,
                matches: 10
            },
            b
        )
        .is_err());
        assert!(compare(
            "x",
            Count {
                files: 3,
                matches: 9
            },
            b
        )
        .is_err());
    }

    #[test]
    fn concept_map_parses_with_every_entry() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let map = std::fs::read_to_string(root.join(MAP_PATH)).unwrap_or_default();
        let parsed = parse_map(&map);
        assert!(parsed.is_ok(), "{:?}", parsed.as_ref().err());
        if let Ok(m) = parsed {
            assert_eq!(m.concepts.len(), 27);
        }
    }

    #[test]
    fn concept_map_owner_is_a_known_component() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let map = std::fs::read_to_string(root.join(MAP_PATH)).unwrap_or_default();
        let parsed = parse_map(&map);
        assert!(parsed.is_ok(), "{:?}", parsed.as_ref().err());
        if let Ok(m) = parsed {
            for concept in &m.concepts {
                assert!(
                    is_known_owner(&concept.owner),
                    "unknown owner {} for {}",
                    concept.owner,
                    concept.name
                );
            }
        }
        assert!(!is_known_owner(""));
        assert!(!is_known_owner("unknown"));
        assert!(is_known_owner("naming"));
    }
}
