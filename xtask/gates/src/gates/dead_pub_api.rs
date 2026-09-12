//! A `pub fn` nothing reaches is public API, not a helper.
//!
//! `guards-are-reachable` counts the refusal-shaped subset: a `check_*` nobody
//! calls is a comment. The same disease across the whole surface was measured by
//! hand in `docs/AUDIT-DEAD-PUB-API-2026-09-10.md`, and the finding that matters
//! is not the count but the absence of a ratchet - a new dead `pub fn` costs
//! nothing, so the number drifts upward between reviews and every review starts
//! by rediscovering it. This is the gate the report asked for.
//!
//! # The measure
//!
//! - *Candidates*: every `pub fn`, `pub async fn`, `pub const fn` or
//!   `pub unsafe fn` in `src/**/*.rs`, with `#[cfg(test)]` modules removed and
//!   files named `*_tests.rs` or living under a `tests/` directory left out.
//! - *Referenced*: the name appears as a whole token anywhere under `src/`,
//!   `crates/`, `examples/`, `benches/`, `budzero/`, `xtask/`, `ops/`,
//!   `.github/`, `config/` or `proto/` - in `.rs`, `.toml`, `.yml`, `.md`,
//!   `.sh`, `.py` or `.json` files - outside the `#[cfg(test)]` modules of `.rs`
//!   sources, minus the declaration lines of that name in that file. A name used
//!   only from a test is therefore dead for the node, which is the only reading
//!   that keeps "tested" and "wired" different words.
//! - *Exempt*: a `WIRING:`, `Convenience:` or `exposed for` line within the
//!   fourteen lines above the declaration. Fourteen because the audit used
//!   fourteen, and a reviewer has to read the sentence next to the function.
//! - *Ratchet*: `.github/dead-pub-api-baseline.txt` holds sorted `path:name`
//!   lines. A new entry fails; a stale entry fails too, with the line to delete
//!   named. An empty baseline is the goal, not a loophole - it admits nothing.
//!
//! # What it cannot see, stated rather than patched around
//!
//! A `.md` mention counts as a reference, because that is the audit's rule and
//! two numbers measuring different things cannot be compared. It is also a way
//! to silence this gate by writing prose about a function instead of calling it.
//! Nothing here prevents that. What prevents it is that the exemption is visible
//! in the diff, and that this gate's job is to keep the list in front of a human
//! rather than to certify the list.
//!
//! Two further limits, and they err in opposite directions so neither can be
//! argued away by pointing at the other: a name taken as a value
//! (`let hook = registry::seed;`) is not a call and reads as dead, and a
//! function reached only from another member's `src/` reads as live because the
//! corpus is cross-directory.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::ffi::OsStr;
use std::path::Path;

use super::guards_reachable::strip_test_mods;

const BASELINE_FILE: &str = ".github/dead-pub-api-baseline.txt";
const CORPUS_DIRS: &[&str] = &[
    "src",
    "crates",
    "examples",
    "benches",
    "budzero",
    "xtask",
    "ops",
    ".github",
    "config",
    "proto",
];
const CORPUS_EXT: &[&str] = &["rs", "toml", "yml", "md", "sh", "py", "json"];
const EXEMPT_TOKENS: &[&str] = &["WIRING:", "Convenience:", "exposed for"];
const LOOKBACK: usize = 14;
const MAX_REPORTED: usize = 40;

/// The name a line declares, if it declares one this gate cares about.
///
/// Deliberately literal about the shape: the qualifier words are consumed one at
/// a time and anything else - `extern`, a `where` clause on the header - stops
/// the match. An extractor that guessed would invent candidates, and an invented
/// candidate is a baseline entry no one can ever remove.
fn decl_name(trimmed: &str) -> Option<&str> {
    let mut rest = trimmed.strip_prefix("pub ")?;
    loop {
        if let Some(tail) = rest.strip_prefix("fn ") {
            rest = tail;
            break;
        }
        let mut ate = false;
        for qual in ["async ", "const ", "unsafe "] {
            if let Some(tail) = rest.strip_prefix(qual) {
                rest = tail;
                ate = true;
                break;
            }
        }
        if !ate {
            return None;
        }
    }
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    let name = &rest[..end];
    if !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        return None;
    }
    Some(name)
}

/// Visit every identifier-shaped token in `text`.
///
/// ASCII-bounded like the audit's grep: `a1b` is one token, `2fa` yields nothing
/// rather than `fa`. Byte offsets are used for the slices, which is safe because
/// a run starts at an ASCII letter and stops at the first non-identifier byte.
fn for_each_token(text: &str, seen: &mut impl FnMut(&str)) {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let starts = b[i] == b'_' || b[i].is_ascii_alphabetic();
        if !starts {
            i += 1;
            continue;
        }
        if i > 0 {
            let prev = b[i - 1];
            if prev == b'_' || prev.is_ascii_alphanumeric() {
                i += 1;
                continue;
            }
        }
        let mut j = i;
        while j < b.len() && (b[j] == b'_' || b[j].is_ascii_alphanumeric()) {
            j += 1;
        }
        seen(&text[i..j]);
        i = j;
    }
}

/// Every corpus file that exists under `root`, as `/`-normalized relative paths.
fn corpus(root: &Path) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for dir in CORPUS_DIRS {
        let top = root.join(dir);
        if !top.is_dir() {
            continue;
        }
        let mut stack = vec![top];
        while let Some(cur) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&cur) else {
                continue;
            };
            for entry in rd.filter_map(Result::ok) {
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                let path = entry.path();
                if file_type.is_dir() {
                    let name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if name != ".git" && name != "target" && name != "node_modules" {
                        stack.push(path);
                    }
                    continue;
                }
                let ext = path
                    .extension()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if CORPUS_EXT.contains(&ext.as_str()) {
                    if let Ok(rel) = path.strip_prefix(root) {
                        out.insert(rel.to_string_lossy().replace('\\', "/"));
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Is this path a `.rs` file?
///
/// Written on the extension rather than as `ends_with(".rs")`: the string form
/// matches a file *named* `.rs`, and it is the shape clippy's
/// `case_sensitive_file_extension_comparisons` exists to point at. The comparison
/// stays case-sensitive on purpose - the tree's files are all lowercase, and a
/// gate that quietly started accepting `.RS` would be a second, undocumented
/// change to what the audit counts.
fn has_rs_extension(rel: &str) -> bool {
    Path::new(rel).extension() == Some(OsStr::new("rs"))
}

fn is_candidate_file(rel: &str) -> bool {
    rel.starts_with("src/")
        && has_rs_extension(rel)
        && !rel.ends_with("_tests.rs")
        && !rel.contains("/tests/")
}

/// What the tree says about every name: how often it is referenced, and where it
/// is declared.
struct Surface {
    references: BTreeMap<String, usize>,
    declarations: BTreeMap<String, BTreeMap<String, usize>>,
    bodies: BTreeMap<String, Vec<String>>,
}

fn scan(root: &Path) -> Surface {
    let mut surface = Surface {
        references: BTreeMap::new(),
        declarations: BTreeMap::new(),
        bodies: BTreeMap::new(),
    };
    for rel in corpus(root) {
        let Ok(text) = std::fs::read_to_string(root.join(&rel)) else {
            continue;
        };
        let scan_text = if has_rs_extension(&rel) {
            strip_test_mods(&text)
        } else {
            text.clone()
        };
        for_each_token(&scan_text, &mut |name| {
            *surface
                .references
                .entry(name.to_string())
                .or_insert(0) += 1;
        });
        if !is_candidate_file(&rel) {
            continue;
        }
        let mut own: BTreeMap<String, usize> = BTreeMap::new();
        for line in text.lines() {
            if let Some(name) = decl_name(line.trim_start()) {
                *own.entry(name.to_string()).or_insert(0) += 1;
            }
        }
        surface.bodies.insert(
            rel.clone(),
            strip_test_mods(&text).lines().map(str::to_string).collect(),
        );
        surface.declarations.insert(rel, own);
    }
    surface
}

/// The `path:name` keys of every candidate nothing outside its own declaration
/// reaches, after the doc-comment exemption.
fn dead_entries(surface: &Surface) -> BTreeSet<String> {
    let mut findings: BTreeSet<String> = BTreeSet::new();
    for (rel, body) in &surface.bodies {
        let empty = BTreeMap::new();
        let own = surface.declarations.get(rel).unwrap_or(&empty);
        for (index, line) in body.iter().enumerate() {
            let Some(name) = decl_name(line.trim_start()) else {
                continue;
            };
            let counted = surface.references.get(name).copied().unwrap_or(0);
            let declared = own.get(name).copied().unwrap_or(0);
            if counted > declared {
                continue;
            }
            let start = index.saturating_sub(LOOKBACK);
            let exempt = body[start..index]
                .iter()
                .any(|doc| EXEMPT_TOKENS.iter().any(|token| doc.contains(token)));
            if exempt {
                continue;
            }
            findings.insert(format!("{rel}:{name}"));
        }
    }
    findings
}

/// The recorded debt, one `path:name` per line, `#` lines and blanks ignored.
fn read_baseline(root: &Path) -> Result<BTreeSet<String>, String> {
    let path = root.join(BASELINE_FILE);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Err(format!(
            "baseline missing: {} - nothing to compare against, and an unmeasured \
             protection is not a protection",
            path.display()
        ));
    };
    let mut baseline = BTreeSet::new();
    for line in text.lines() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        if !entry.contains(':') {
            return Err(format!(
                "{BASELINE_FILE}: `{entry}` is not `path:name`; a baseline line the gate \
                 cannot match is a line that silently never matches"
            ));
        }
        baseline.insert(entry.to_string());
    }
    Ok(baseline)
}

/// # Errors
///
/// Returns a finding when dead public API grew, when the baseline is stale, or
/// when the baseline file is missing or malformed.
pub fn run(root: &Path) -> Result<String, String> {
    if corpus(root).is_empty() {
        return Err(String::from(
            "corpus is empty: the gate is pointed at a directory with no source in it, \
             and a green run from here would mean nothing",
        ));
    }
    let findings = dead_entries(&scan(root));
    let baseline = read_baseline(root)?;
    let new: Vec<&String> = findings
        .iter()
        .filter(|entry| !baseline.contains(*entry))
        .collect();
    let gone: Vec<&String> = baseline
        .iter()
        .filter(|entry| !findings.contains(*entry))
        .collect();
    let mut msg = format!(
        "dead public api: {} | baseline: {}\n",
        findings.len(),
        baseline.len()
    );
    if !new.is_empty() {
        let _ = writeln!(msg, "--- new, nothing in the tree calls these ---");
        for entry in new.iter().take(MAX_REPORTED) {
            let _ = writeln!(msg, "  {entry}");
        }
        if new.len() > MAX_REPORTED {
            let _ = writeln!(msg, "  ... and {} more", new.len() - MAX_REPORTED);
        }
        let _ = write!(
            msg,
            "FAIL: {n} public function(s) entered the tree that no production line reaches.\n  \
             Call it from the path it was written for, or write the exemption next to it: a\n  \
             `/// Convenience: kept for the CLI` line within {lookback} lines above.\n  \
             Do not add a line to the baseline to pass this: the baseline exists to catch that.",
            n = new.len(),
            lookback = LOOKBACK
        );
        return Err(msg);
    }
    if !gone.is_empty() {
        let _ = writeln!(msg, "--- baseline entries no longer dead ---");
        for entry in gone.iter().take(MAX_REPORTED) {
            let _ = writeln!(msg, "  {entry}");
        }
        let _ = write!(
            msg,
            "FAIL: {} entries were wired up or deleted and the baseline was not tightened.\n  \
             Remove those lines in this pull request, or the next author inherits the slack.",
            gone.len()
        );
        return Err(msg);
    }
    let _ = write!(msg, "OK: the surface is exactly what is on record.");
    Ok(msg)
}

/// Write a fixture file for the canary.
///
/// `impl AsRef<str>` and not `&str`: the closure this replaced fixed its
/// parameter type at the first call site, so the two later fixtures built by
/// `.concat()` - owned `String`s - were a type error. Nothing in this crate can
/// be compiled from the sandbox that wrote it, and CI said so precisely
/// (`error[E0308]: mismatched types` at two call sites) while the step that
/// reported it was named "Badge canary", which is how a build failure spends a
/// day wearing a gate's clothes. A helper that accepts either cannot reintroduce
/// it, and it stays private so it cannot grow the public-API baseline it guards.
fn write_fixture(path: std::path::PathBuf, text: impl AsRef<str>) -> Result<(), String> {
    std::fs::write(path, text.as_ref().as_bytes()).map_err(|e| e.to_string())
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-dp")?;
    let fail = |why: &str| {
        let _ = std::fs::remove_dir_all(&dir);
        String::from(why)
    };
    let created = std::fs::create_dir_all(dir.join("src"))
        .and_then(|()| std::fs::create_dir_all(dir.join(".github")));
    if created.is_err() {
        return Err(fail("canary: no scratch directory for the fixture"));
    }
    let baseline = dir.join(BASELINE_FILE);
    let orphan = "pub fn lonely_helper(x: u8) -> u8 {\n    x\n}\n";
    let recorded = "src/lib.rs:lonely_helper\n";

    write_fixture(dir.join("src/lib.rs"), orphan)?;
    write_fixture(baseline.clone(), recorded)?;
    if run(&dir).is_err() {
        return Err(fail("canary: a recorded dead function still failed the gate"));
    }

    // A second unreached function has to grow the set, not the tolerance.
    let grown = format!("{orphan}pub fn second_orphan() -> u8 {{\n    1\n}}\n");
    write_fixture(dir.join("src/lib.rs"), &grown)?;
    if run(&dir).is_ok() {
        return Err(fail("canary: new dead public api passed against a stale baseline"));
    }

    // Wiring one up is allowed; leaving the baseline loose is not. Both entries
    // are recorded first, so the only thing left to complain about is the stale one.
    let wired = format!("{orphan}pub fn second_orphan() -> u8 {{\n    lonely_helper(1)\n}}\n");
    write_fixture(dir.join("src/lib.rs"), &wired)?;
    write_fixture(baseline.clone(), "src/lib.rs:lonely_helper\nsrc/lib.rs:second_orphan\n")?;
    if run(&dir).is_ok() {
        return Err(fail("canary: a baseline that names a wired-up function did not nag"));
    }
    write_fixture(baseline.clone(), "src/lib.rs:second_orphan\n")?;
    if run(&dir).is_err() {
        return Err(fail("canary: a call site was not seen, so the entry could not be dropped"));
    }

    // The exemption token, and only the token: the helper is still uncalled.
    let documented = [
        "/// Convenience: kept for the CLI.\n",
        "pub fn documented_helper(x: u8) -> u8 {\n    x\n}\n",
    ]
    .concat();
    write_fixture(dir.join("src/lib.rs"), documented)?;
    write_fixture(baseline.clone(), "")?;
    if run(&dir).is_err() {
        return Err(fail("canary: the documented exemption was not honoured"));
    }
    let naked = [
        "/// nothing that matches\n",
        "pub fn naked_helper(x: u8) -> u8 {\n    x\n}\n",
    ]
    .concat();
    write_fixture(dir.join("src/lib.rs"), naked)?;
    if run(&dir).is_ok() {
        return Err(fail("canary: an undecorated dead function passed an empty baseline"));
    }

    // A caller that exists only inside `#[cfg(test)]` is not wiring.
    let tested = [
        "pub fn test_only(x: u8) -> u8 {\n    x\n}\n",
        "\n#[cfg(test)]\nmod t {\n    use super::test_only;\n",
        "    #[test]\n    fn covers() {\n        let _ = test_only(1);\n    }\n}\n",
    ]
    .concat();
    write_fixture(dir.join("src/lib.rs"), &tested)?;
    write_fixture(baseline.clone(), "src/lib.rs:test_only\n")?;
    if run(&dir).is_err() {
        return Err(fail("canary: a test-module caller was treated as a production call"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "dead-pub-api canary OK: growth fails, a stale baseline nags, a call site clears an \
         entry, a doc token exempts at the declaration, and a test-only caller does not count.",
    ))
}
