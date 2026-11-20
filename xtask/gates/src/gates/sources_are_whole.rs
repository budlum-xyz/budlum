//! Sources are whole: a committed file carries its body, not a summary of it.
//!
//! # Why this gate exists
//!
//! A source file can be destroyed by a commit that looks like a feature. Two
//! of them landed on the same branch within three minutes of each other:
//! one replaced a 525-line storage module with three comment lines, the other
//! replaced a 592-line aggregation module with four. Both commit subjects
//! announced a hardening change; both diffs were `-525/+3` and `-591/+3`; what
//! actually remained in the tree was
//!
//! ```text
//! // ... (original content)
//! // ADDED: <subject line of the commit>
//! // ... (original content)
//! ```
//!
//! Every downstream module still imported the deleted types, so the whole
//! crate stopped compiling and twelve CI checks went red at once. Reading the
//! red logs costs an hour; reading `-525/+3` costs a second, and no gate was
//! looking at it.
//!
//! The failure mode is not a typo, it is a shape: a writer that summarises a
//! file instead of editing it. The shape is mechanically detectable, so it is
//! refused here rather than in review:
//!
//!   1. **Elided body.** A comment that opens with an ellipsis and then says
//!      the body was left out (`... (original content)`, `... rest of file
//!      unchanged`), or a parenthesised version of the same claim.
//!   2. **Bare placeholder.** A plain (non-doc) comment whose entire body is
//!      an ellipsis - the `// ...` that stands where code used to be.
//!   3. **Empty body.** A `.rs` file that declares nothing at all: strip its
//!      comments and whitespace and nothing is left. A module wired into the
//!      crate graph with no items in it is a hole, whether or not the writer
//!      left a placeholder behind.
//!
//! # What it deliberately does not flag
//!
//! Prose that happens to contain an ellipsis and the word `unchanged` is not
//! a placeholder. Two real lines in this tree say
//!
//! ```text
//! //!     `Blockchain::new(...)` has to be byte for byte the same as the direct
//! //! unchanged value, a cap, ...).
//! ```
//!
//! and both must pass. The rule is therefore positional: the ellipsis has to
//! *open* the comment (that is what an elision marker does), or the claim has
//! to be parenthesised in one of the fixed forms. Both canaries are in
//! [`self_test`], so a later widening of the patterns that re-breaks them
//! fails here first.
//!
//! Every input is a file in the scanned tree. There is no wall clock, no
//! network access and no dependence on directory iteration order: the walk is
//! sorted and the findings are reported in path order.
//!
//! # Errors
//!
//! The entry points return a finding when a scanned file carries an elision
//! placeholder or declares nothing.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Trees that hold compiled sources. A file outside them cannot break a build.
const ROOTS: &[&str] = &[
    "src",
    "crates",
    "budzero",
    "bud",
    "xtask",
    "execution",
    "benches",
    "fuzz",
    "tests",
    "examples",
];

/// Directories that are build output or foreign code, never sources of ours.
const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules", "vendor"];

/// A file larger than this is generated data, not hand-written source.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// This file names the patterns in order to forbid them.
const SELF: &str = "xtask/gates/src/gates/sources_are_whole.rs";

/// Words that turn a leading ellipsis into the claim "the body is elsewhere".
const ELISION_WORDS: &[&str] = &[
    "original",
    "unchanged",
    "rest of",
    "as before",
    "previous content",
    "snip",
    "omitted",
    "same as",
    "remainder",
    "truncated",
];

/// Parenthesised elision claims, which are findings wherever they appear.
const PAREN_CLAIMS: &[&str] = &[
    "(original content",
    "(rest of file",
    "(rest of the file",
    "(unchanged)",
    "(previous content",
    "(code unchanged",
    "(same as before",
    "(body omitted",
    "(content omitted",
];

/// One finding: where it is and what shape it has.
struct Finding {
    path: String,
    line: usize,
    reason: &'static str,
    text: String,
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) {
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
        } else if name.ends_with(".rs") {
            if let Ok(rel) = p.strip_prefix(root) {
                out.push((rel.to_string_lossy().replace('\\', "/"), p.clone()));
            }
        }
    }
}

/// The comment body of a line, and whether the comment is a doc comment.
///
/// Returns `None` for a line that does not start a comment. A line that only
/// continues a block comment (`* ...` inside `/* */`) counts as a comment
/// body, because that is where a summariser puts the placeholder too.
fn comment_body(line: &str) -> Option<(&str, bool)> {
    let t = line.trim_start();
    if let Some(rest) = t.strip_prefix("//!") {
        return Some((rest, true));
    }
    if let Some(rest) = t.strip_prefix("///") {
        return Some((rest, true));
    }
    if let Some(rest) = t.strip_prefix("//") {
        return Some((rest, false));
    }
    if let Some(rest) = t.strip_prefix("/*") {
        return Some((rest.trim_end_matches("*/"), false));
    }
    if let Some(rest) = t.strip_prefix('*') {
        return Some((rest.trim_end_matches("*/"), false));
    }
    None
}

/// Classifies one comment body, or `None` when it is ordinary prose.
fn elision_reason(body: &str, is_doc: bool) -> Option<&'static str> {
    let trimmed = body.trim();
    let low = trimmed.to_lowercase();
    let opens_with_ellipsis = low.starts_with("...") || low.starts_with('…');
    if opens_with_ellipsis {
        if ELISION_WORDS.iter().any(|w| low.contains(w)) {
            return Some("a comment opens with an ellipsis and says the body was left out");
        }
        let only_dots = low
            .chars()
            .all(|c| c == '.' || c == '…' || c.is_whitespace());
        if only_dots && !is_doc && !low.is_empty() {
            return Some("a plain comment whose whole body is an ellipsis stands where code should");
        }
    }
    if PAREN_CLAIMS.iter().any(|c| low.contains(c)) {
        return Some("a parenthesised claim that the body was left out");
    }
    None
}

/// The file with its comments and whitespace removed.
///
/// Used only to answer "does this file declare anything at all", so a crude
/// strip is enough: over-stripping can only make a file look emptier, and a
/// file that survives the strip has real content by construction.
fn without_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_block = 0_usize;
    while let Some(c) = chars.next() {
        if in_block > 0 {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block = in_block.saturating_sub(1);
            } else if c == '/' && chars.peek() == Some(&'*') {
                chars.next();
                in_block = in_block.saturating_add(1);
            }
            continue;
        }
        if c == '/' {
            match chars.peek() {
                Some('/') => {
                    for n in chars.by_ref() {
                        if n == '\n' {
                            break;
                        }
                    }
                    continue;
                }
                Some('*') => {
                    chars.next();
                    in_block = 1;
                    continue;
                }
                _ => {}
            }
        }
        out.push(c);
    }
    out.trim().to_string()
}

fn scan_file(rel: &str, text: &str, out: &mut Vec<Finding>) {
    for (i, line) in text.lines().enumerate() {
        let Some((body, is_doc)) = comment_body(line) else {
            continue;
        };
        if let Some(reason) = elision_reason(body, is_doc) {
            out.push(Finding {
                path: rel.to_string(),
                line: i.saturating_add(1),
                reason,
                text: line.trim().chars().take(100).collect(),
            });
        }
    }
    if without_comments(text).is_empty() {
        out.push(Finding {
            path: rel.to_string(),
            line: 0,
            reason: "the file declares no item: comments and whitespace are all that is left",
            text: String::new(),
        });
    }
}

/// Runs the gate over `root`.
///
/// # Errors
///
/// When a scanned file carries an elision placeholder or declares nothing.
pub fn run(root: &Path) -> Result<String, String> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    for r in ROOTS {
        let p = root.join(r);
        if p.is_dir() {
            walk(&p, root, &mut files);
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut findings: Vec<Finding> = Vec::new();
    let mut scanned = 0_usize;
    for (rel, path) in &files {
        if rel == SELF {
            continue;
        }
        let Ok(meta) = std::fs::metadata(path) else {
            continue;
        };
        if meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        scanned = scanned.saturating_add(1);
        scan_file(rel, &text, &mut findings);
    }

    if findings.is_empty() {
        return Ok(format!(
            "sources are whole OK: {scanned} Rust file(s), no elided body and no item-less module"
        ));
    }
    let mut msg = format!("{} file region(s) carry no body:\n", findings.len());
    for f in &findings {
        if f.line == 0 {
            let _ = writeln!(msg, "  {}: {}", f.path, f.reason);
        } else {
            let _ = writeln!(msg, "  {}:{}: {} -> {}", f.path, f.line, f.reason, f.text);
        }
    }
    let _ = write!(
        msg,
        "Restore the body from the commit before the one that shortened it; a summary of a file is not the file."
    );
    Err(msg)
}

/// The canary: the two real destruction shapes must fail, and the two real
/// prose lines that look like them must pass.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-sources-whole")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        put("src/clean.rs", "pub const WHOLE: u8 = 1;\n")?;
        run(&dir).map_err(|e| format!("canary: a clean tree failed: {e}"))?;

        // Prose that contains an ellipsis and an elision word is not a
        // placeholder: both lines are real lines from this repository.
        put(
            "src/prose.rs",
            "//!     `Blockchain::new(...)` has to be byte for byte the same as the direct\n\
             //! unchanged value, a cap, ...).\npub const P: u8 = 2;\n",
        )?;
        run(&dir).map_err(|e| format!("canary: prose was read as a placeholder: {e}"))?;

        // Shape 1: the storage module as the destroying commit left it.
        put(
            "src/storage_stub.rs",
            "// ... (original content)\n// ADDED: registry integration\n// ... (original content)\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an elided body passed"));
        }
        std::fs::remove_file(dir.join("src/storage_stub.rs")).map_err(|e| e.to_string())?;
        run(&dir).map_err(|e| format!("canary: the tree stayed red after the fix: {e}"))?;

        // Shape 2: a plain comment standing in for code.
        put("src/placeholder.rs", "pub fn f() {\n    // ...\n}\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a bare `// ...` placeholder passed"));
        }
        std::fs::remove_file(dir.join("src/placeholder.rs")).map_err(|e| e.to_string())?;

        // Shape 3: a module that declares nothing, with no placeholder text.
        put("src/empty_module.rs", "//! A module header and nothing else.\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an item-less module passed"));
        }
        std::fs::remove_file(dir.join("src/empty_module.rs")).map_err(|e| e.to_string())?;

        // A doc example may show an ellipsis; that is not a hole in the file.
        put(
            "src/doc_example.rs",
            "/// ```\n/// let v = build();\n/// // ...\n/// ```\npub fn build() -> u8 {\n    3\n}\n",
        )?;
        run(&dir).map_err(|e| format!("canary: a doc example was read as a hole: {e}"))?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "sources-are-whole canary OK: an elided body, a bare placeholder and an item-less module each failed; prose and doc examples passed.",
    ))
}

#[cfg(test)]
mod tests {
    use super::{elision_reason, run, self_test, without_comments};

    #[test]
    fn sources_are_whole_gate() {
        assert!(self_test().is_ok(), "{:?}", self_test());
    }

    /// The exact lines the two destroying commits left behind.
    #[test]
    fn the_real_destruction_shapes_are_findings() {
        assert!(elision_reason(" ... (original content)", false).is_some());
        assert!(elision_reason(" ... (original content from testnet branch)", false).is_some());
        assert!(elision_reason(" ...", false).is_some());
    }

    /// The exact prose lines in this tree that must stay quiet.
    #[test]
    fn prose_with_an_ellipsis_is_not_a_placeholder() {
        assert!(
            elision_reason(
                "     `Blockchain::new(...)` has to be byte for byte the same as the direct",
                true
            )
            .is_none()
        );
        assert!(elision_reason(" unchanged value, a cap, ...).", true).is_none());
        assert!(elision_reason(" ...", true).is_none(), "a doc ellipsis is prose");
    }

    #[test]
    fn a_file_of_comments_has_no_body() {
        assert!(without_comments("// only a comment\n/* and a block */\n").is_empty());
        assert!(!without_comments("//! header\npub const A: u8 = 1;\n").is_empty());
    }

    /// The gate has to be able to run on the repository it ships in.
    #[test]
    fn the_tree_this_gate_ships_in_is_whole() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        if root.join("src").is_dir() {
            assert!(run(&root).is_ok(), "{:?}", run(&root));
        }
    }
}
