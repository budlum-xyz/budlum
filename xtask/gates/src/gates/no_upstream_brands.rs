//! No product read for research is named in this tree.
//!
//! Some of the architecture here was arrived at by reading other projects. That
//! reading is legitimate and the resulting designs are our own: no code was
//! copied and no dependency was added. What must not happen is the *name*
//! travelling into the tree along with the idea.
//!
//! The reason is not etiquette. A type called `ServeEngine::Colibri` looks like
//! an integration. A reader concludes the tree depends on that project, checks
//! its licence against ours, and reasons about upgrades to a thing we never
//! link. The variant it replaced described nothing about our own system - it
//! named someone else's - and the honest name, `StreamingMoe`, says what the
//! variant actually selects: an engine that pages experts off disk. The rename
//! lost no information; it removed a false one.
//!
//! There is a second reason, and it is the one that survives a licence audit.
//! An idea we adopted is ours to defend. If a design turns out to be wrong we
//! change it, and a name borrowed from a project that made a different tradeoff
//! quietly argues against the change.
//!
//! # What this gate does not claim
//!
//! It does not detect copied code, and no scan of ours could. Attribution
//! obligations are a licence question and live in `LICENSE.md` and any future
//! `NOTICE.md`; if a dependency is ever genuinely added, the name belongs
//! there, and [`ATTRIBUTION_FILES`] keeps those paths out of the scan so the
//! gate never argues against complying with a licence.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Names read during research that must not appear in the tree.
///
/// Lowercased; matching is case-insensitive. Each is a whole word, so `code`
/// inside `jcode` is fine and `bud` inside `budlum` is untouched.
const FORBIDDEN: &[(&str, &str)] = &[
    (
        "colibri",
        "an on-device MoE engine. What we took was the idea of a placement \
         hierarchy across VRAM, RAM and disk; that idea now lives in \
         `ai-serve/src/residency.rs` under our own terms.",
    ),
    (
        "jcode",
        "a coding agent read for its memory discipline. The bounded-buffer and \
         ceiling work it prompted is ours and is described in \
         `docs/ARCHITECTURE.md`.",
    ),
    (
        "system_prompts_leaks",
        "a corpus of published system prompts, read while writing \
         `ai-core/src/system_prompt.rs`. Our prompt states our own system's \
         behaviour and is checked against the tree by `ai-inference-prompt-is-true`.",
    ),
];

/// Paths where a name may legitimately appear, because a licence requires it.
///
/// A gate that forbade attribution would be worse than no gate: it would push a
/// project toward a licence violation to stay green.
const ATTRIBUTION_FILES: &[&str] = &["LICENSE.md", "NOTICE.md", "THIRD-PARTY.md"];

/// This gate names what it forbids, so it cannot scan itself.
const SELF_PATH: &str = "xtask/gates/src/gates/no_upstream_brands.rs";

/// Directories never scanned.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".cargo",
    "corpus",
    "__pycache__",
];

/// Extensions never scanned: no prose, and a false hit in a binary is noise.
const SKIP_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "ico", "pdf", "zip", "gz", "tar", "bin", "wasm", "so", "a", "o",
    "lock", "svg", "woff", "woff2", "ttf", "webp",
];

/// A scan that walks too few files is vacuous and must fail rather than pass.
///
/// Without this, a broken root path or an over-eager skip list turns the gate
/// into a function that returns OK. The floor is well under the real count, so
/// it fires on breakage rather than on growth.
const VACUITY_FLOOR: usize = 50;

/// How many findings are printed before the list is summarised.
const MAX_REPORTED: usize = 20;

/// Is `path` skipped by extension?
fn skipped_ext(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| SKIP_EXTS.contains(&e.to_string_lossy().to_ascii_lowercase().as_str()))
}

/// Files under `root`, sorted, so findings are reported in a stable order.
fn sorted_walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_into(root, &mut out);
    out.sort();
    out
}

fn walk_into(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // `file_type` rather than `metadata`: a symlink to a directory is not
        // followed, since following one can walk outside the repository or
        // loop forever.
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if kind.is_dir() {
            if !SKIP_DIRS.contains(&name_str.as_ref()) {
                walk_into(&path, out);
            }
        } else if kind.is_file() && !skipped_ext(&path) {
            out.push(path);
        }
    }
}

/// Does `haystack` contain `needle` as a whole word?
///
/// Substring matching is wrong in both directions here. `colibri` inside a
/// longer identifier is still the name, but a bare `contains` would also fire
/// on unrelated words that happen to embed a short name, and the list is meant
/// to grow. A word boundary keeps the check honest as it grows.
///
/// Underscores are treated as separators, not word characters, so
/// `serve_colibri_engine` is a hit: `snake_case` is exactly how a name leaks
/// into Rust.
fn contains_word(haystack_lower: &str, needle: &str) -> bool {
    let mut from = 0usize;
    while let Some(offset) = haystack_lower[from..].find(needle) {
        let at = from + offset;
        let end = at + needle.len();
        // Underscores are deliberately *not* word characters here. In Rust a
        // name leaks as `spawn_colibri_process` far more often than as a bare
        // word, and treating `_` as part of the word would let every
        // `snake_case` identifier through - which is the common case, not the
        // edge case. Alphanumerics still bind, so `jcodex` is not a `jcode`
        // hit and the list stays safe to grow.
        let before_ok = haystack_lower[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let after_ok = haystack_lower[end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
        from = at + needle.len();
    }
    false
}

/// Scan one file's text. Returns `(name, line number, trimmed line)` per hit.
fn findings_in(rel: &str, text: &str) -> Vec<(&'static str, usize, String)> {
    let mut out = Vec::new();
    if rel == SELF_PATH || ATTRIBUTION_FILES.contains(&rel) {
        return out;
    }
    for (line_no, line) in text.lines().enumerate() {
        let lower = line.to_lowercase();
        for (name, _) in FORBIDDEN {
            if contains_word(&lower, name) {
                let mut shown = line.trim().to_string();
                shown.truncate(120);
                out.push((*name, line_no + 1, shown));
            }
        }
    }
    out
}

/// Why a name is forbidden, for the failure message.
fn reason(name: &str) -> &'static str {
    FORBIDDEN
        .iter()
        .find(|(n, _)| *n == name)
        .map_or("read during research", |(_, why)| *why)
}

/// # Errors
///
/// Returns the list of places a researched product is named.
pub fn run(root: &Path) -> Result<String, String> {
    let mut scanned = 0usize;
    let mut findings: Vec<(String, &'static str, usize, String)> = Vec::new();

    for path in sorted_walk(root) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            // Not valid UTF-8: nothing prose-like to read.
            continue;
        };
        scanned += 1;
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        for (name, line, text) in findings_in(&rel, &text) {
            findings.push((rel.clone(), name, line, text));
        }
    }

    if scanned < VACUITY_FLOOR {
        return Err(format!(
            "only {scanned} files were scanned, below the floor of {VACUITY_FLOOR}.\n  \
             A scan this small is not evidence of anything: the root is probably \
             wrong or the skip list is swallowing the tree, and a gate that \
             reports OK after looking at nothing is worse than an absent one."
        ));
    }

    if !findings.is_empty() {
        let mut msg = format!(
            "{} place(s) name a product that was read for research:\n",
            findings.len()
        );
        for (rel, name, line, text) in findings.iter().take(MAX_REPORTED) {
            let _ = writeln!(
                msg,
                "  {rel}:{line}: {text}\n    `{name}` is {}",
                reason(name)
            );
        }
        if findings.len() > MAX_REPORTED {
            let _ = writeln!(msg, "  ... and {} more", findings.len() - MAX_REPORTED);
        }
        msg.push_str(
            "  Rename to what the thing does in our system rather than where the \
             idea came from. If a dependency was genuinely added, the name belongs \
             in LICENSE.md or NOTICE.md, which this gate does not scan.",
        );
        return Err(msg);
    }

    Ok(format!(
        "no researched product is named in {scanned} scanned files \
         ({} names checked)",
        FORBIDDEN.len()
    ))
}

/// # Errors
///
/// Returns the first canary that did not behave.
pub fn self_test() -> Result<String, String> {
    // 1. A clean file passes.
    if !findings_in("src/x.rs", "let engine = StreamingMoe;").is_empty() {
        return Err(String::from("canary 1: a clean line was reported"));
    }

    // 2. The name is caught.
    if findings_in("src/x.rs", "    Colibri,").is_empty() {
        return Err(String::from(
            "canary 2: an enum variant named after a researched product was not caught",
        ));
    }

    // 3. Case does not hide it.
    if findings_in("src/x.rs", "// COLIBRI notes").is_empty() {
        return Err(String::from(
            "canary 3: an uppercase mention was not caught",
        ));
    }

    // 4. snake_case is how it really leaks.
    if findings_in("src/x.rs", "fn spawn_colibri_process() {}").is_empty() {
        return Err(String::from(
            "canary 4: a snake_case identifier embedding the name was not caught",
        ));
    }

    // 5. A word that merely embeds a short name is not a hit.
    if !findings_in("src/x.rs", "let decoded = jcodex_value;").is_empty() {
        return Err(String::from(
            "canary 5: `jcodex` was reported; the check must respect word boundaries \
             or it will misfire as the list grows",
        ));
    }

    // 6. Attribution files are exempt: a licence may require the name.
    if !findings_in("NOTICE.md", "Colibri, Apache-2.0").is_empty() {
        return Err(String::from(
            "canary 6: NOTICE.md was scanned. A gate that forbids attribution \
             pushes the project toward a licence violation to stay green.",
        ));
    }

    // 7. This file names what it forbids and must exempt itself.
    if !findings_in(SELF_PATH, "    (\"colibri\", \"an on-device MoE engine\"),").is_empty() {
        return Err(String::from("canary 7: the gate reported its own list"));
    }

    // 8. Every other gate is still scanned, so the exemption is one file only.
    if findings_in("xtask/gates/src/gates/other.rs", "// colibri").is_empty() {
        return Err(String::from(
            "canary 8: the self-exemption leaked to another gate file",
        ));
    }

    Ok(String::from("no-upstream-brands: 8 canaries"))
}
