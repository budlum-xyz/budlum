//! Reject machine-mangled Rust before it can be merged.
//!
//! `git merge` is not a compiler. Three open pull requests in the live stack
//! ship Rust that no compiler can read: orphaned `#[test]` attributes followed
//! by a lone `f`, a deleted method name leaving `self.` at the end of a line,
//! an enum variant outside its enum, and unbalanced delimiters. A clean merge
//! carries those bytes downstream and the first red CI run is blamed on the
//! integrator rather than on the branch that produced them (BLG-298, BLG-314,
//! BLG-318).
//!
//! This gate is the cheap structural pre-merge check. It does not pretend to be
//! a Rust parser: `ops/scripts/stack_compatibility_audit.py` parses every blob
//! with the tree-sitter Rust grammar, and CI is the type-check. What this gate
//! adds is a wired, self-tested refusal inside the repository's own gate
//! registry, so the defect class cannot be merged without a red verdict.
//!
//! What it refuses, all found in the live stack:
//!
//! * unbalanced `()`, `[]` or `{}` outside strings, comments and char literals;
//! * a module-level line that is a single ASCII letter (`f`, `a`);
//! * `#[test]` / `#[tokio::test]` not followed by a function or another attribute;
//! * a `self.` line fragment whose method name was deleted;
//! * a doc or comment line prefixed by a stray `f`;
//! * a `Name,` line at module level, i.e. an enum variant outside its enum.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const ROOTS: &[&str] = &[
    "src",
    "crates",
    "budzero",
    "bud",
    "xtask",
    "tests",
    "examples",
    "benches",
    "fuzz",
    "mobile",
    "execution",
    "contracts",
    "ops",
];
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "Unselected files",
    "build",
    "dist",
];
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_REPORTED: usize = 40;

fn rust_files(root: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for r in ROOTS {
        let p = root.join(r);
        if p.exists() {
            walk(&p, root, &mut out);
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) {
    if dir.is_file() {
        if dir.extension().is_some_and(|e| e == "rs") {
            if let Ok(rel) = dir.strip_prefix(root) {
                out.push((rel.to_string_lossy().replace('\\', "/"), dir.to_path_buf()));
            }
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
        let name = e.file_name().to_string_lossy().into_owned();
        if p.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(&p, root, out);
            }
        } else if p.extension().is_some_and(|ext| ext == "rs") {
            if let Ok(rel) = p.strip_prefix(root) {
                out.push((rel.to_string_lossy().replace('\\', "/"), p.clone()));
            }
        }
    }
}

/// Replace string, char, and comment bytes with spaces, keeping line breaks.
///
/// A lifetime tick (`'a`) is not the start of a char literal: a `'` opens a
/// literal only when a closing `'` follows within three bytes. Raw strings use
/// the number of `#` between the `r` and the opening quote as their terminator.
fn strip_literals(text: &str) -> Vec<String> {
    #[derive(Clone, Copy)]
    enum Scan {
        Code,
        Block(usize),
        Str,
        Raw(usize),
    }
    let b = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    let mut state = Scan::Code;
    while i < b.len() {
        match state {
            Scan::Code => {
                if b[i] == b'\n' {
                    out.push(b'\n');
                    i += 1;
                    continue;
                }
                if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'/' {
                    out.extend_from_slice(b"  ");
                    i += 2;
                    while i < b.len() && b[i] != b'\n' {
                        out.push(b' ');
                        i += 1;
                    }
                    continue;
                }
                if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
                    out.extend_from_slice(b"  ");
                    i += 2;
                    state = Scan::Block(1);
                    continue;
                }
                // A raw string may span lines, so it needs a state, not a
                // single-line lookahead. `r"..."`, `r#"..."#` and `br#"...`.
                let mut j = i;
                if b[j] == b'b' && j + 1 < b.len() && b[j + 1] == b'r' {
                    j += 1;
                }
                if b[j] == b'r' {
                    let mut k = j + 1;
                    while k < b.len() && b[k] == b'#' {
                        k += 1;
                    }
                    if k < b.len() && b[k] == b'"' {
                        let hashes = k - (j + 1);
                        for _ in i..=k {
                            out.push(b' ');
                        }
                        i = k + 1;
                        state = Scan::Raw(hashes);
                        continue;
                    }
                }
                if b[i] == b'"' {
                    out.push(b' ');
                    i += 1;
                    state = Scan::Str;
                    continue;
                }
                if b[i] == b'\'' {
                    // A lifetime tick is not the start of a char literal.
                    let closes = (i + 2 < b.len() && b[i + 2] == b'\'')
                        || (i + 3 < b.len() && b[i + 1] == b'\\' && b[i + 3] == b'\'');
                    if closes {
                        let end = if b[i + 1] == b'\\' { i + 4 } else { i + 3 };
                        for _ in i..end.min(b.len()) {
                            out.push(b' ');
                        }
                        i = end.min(b.len());
                    } else {
                        out.push(b'\'');
                        i += 1;
                    }
                    continue;
                }
                out.push(b[i]);
                i += 1;
            }
            Scan::Block(depth) => {
                if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
                    out.extend_from_slice(b"  ");
                    i += 2;
                    state = Scan::Block(depth + 1);
                } else if i + 1 < b.len() && b[i] == b'*' && b[i + 1] == b'/' {
                    out.extend_from_slice(b"  ");
                    i += 2;
                    state = if depth == 1 {
                        Scan::Code
                    } else {
                        Scan::Block(depth - 1)
                    };
                } else {
                    out.push(if b[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
            }
            Scan::Str => {
                if b[i] == b'\\' {
                    out.push(b' ');
                    i += 1;
                    if i < b.len() {
                        out.push(if b[i] == b'\n' { b'\n' } else { b' ' });
                        i += 1;
                    }
                } else if b[i] == b'\n' {
                    // Rust string literals may span lines; stay in the string.
                    out.push(b'\n');
                    i += 1;
                } else {
                    out.push(b' ');
                    let closing = b[i] == b'"';
                    i += 1;
                    if closing {
                        state = Scan::Code;
                    }
                }
            }
            Scan::Raw(hashes) => {
                if b[i] == b'"'
                    && i + 1 + hashes <= b.len()
                    && b[i + 1..i + 1 + hashes].iter().all(|c| *c == b'#')
                {
                    for _ in i..i + 1 + hashes {
                        out.push(b' ');
                    }
                    i += 1 + hashes;
                    state = Scan::Code;
                } else {
                    out.push(if b[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
            }
        }
    }
    String::from_utf8_lossy(&out)
        .lines()
        .map(str::to_string)
        .collect()
}

fn is_test_attr(line: &str) -> bool {
    let t = line.trim();
    let Some(inner) = t.strip_prefix("#[").and_then(|s| s.strip_suffix(']')) else {
        return false;
    };
    // `#[cfg(test)]` is a cfg, not a test attribute. Only the final path
    // segment counts: `tokio::test` is one, `cfg(test)` is not.
    let name = inner.split(['(', ',', ' ']).next().unwrap_or(inner);
    name == "test" || name.ends_with("::test") || name.starts_with("test_case")
}

fn is_item_start(line: &str) -> bool {
    let t = line.trim();
    [
        "fn ",
        "pub ",
        "async ",
        "const ",
        "unsafe ",
        "extern ",
        "mod ",
        "struct ",
        "enum ",
        "impl",
        "trait ",
        "type ",
        "static ",
        "use ",
        "macro_rules!",
        "#[",
    ]
    .iter()
    .any(|p| t.starts_with(*p))
        || t.starts_with("fn")
        || t.starts_with("///")
        || t.starts_with("//!")
}

/// Structural findings for one source, as `line: reason` strings.
fn findings(text: &str) -> Vec<String> {
    let code = strip_literals(text);
    let raw: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut stack: Vec<(char, usize)> = Vec::new();
    let mut depth: i64 = 0;
    let mut pending_test_attr: Option<usize> = None;
    let mut previous_self_dot = false;

    for (idx, line) in code.iter().enumerate() {
        let lineno = idx + 1;
        let t = line.trim();
        let start_depth = depth;

        if pending_test_attr.is_some() && !t.is_empty() {
            let at = pending_test_attr.take().unwrap();
            if !is_item_start(t) {
                out.push(format!(
                    "{at}: test attribute is followed by `{}`, not a function",
                    t.chars().take(24).collect::<String>()
                ));
            }
        }
        if is_test_attr(t) {
            pending_test_attr = Some(lineno);
        }
        if previous_self_dot && (t.starts_with('.') || t.is_empty()) {
            out.push(format!("{lineno}: method name after `self.` is missing"));
        }
        previous_self_dot = t.ends_with("self.");

        let raw_t = raw.get(idx).copied().unwrap_or("").trim_start();
        if raw_t.starts_with("f//") {
            out.push(format!("{lineno}: stray `f` prefix on a comment line"));
        }

        if start_depth == 0 {
            if t.len() == 1 && t.as_bytes()[0].is_ascii_alphabetic() {
                out.push(format!("{lineno}: lone identifier `{t}` at module level"));
            }
            let no_semicolon = t.strip_suffix(',').unwrap_or("").trim();
            let after_item_close = idx > 0
                && code[..idx]
                    .iter()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .is_some_and(|l| l.trim().ends_with('}') || l.trim().ends_with("};"));
            if !no_semicolon.is_empty()
                && t.ends_with(',')
                && after_item_close
                && no_semicolon
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && no_semicolon
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_uppercase())
            {
                out.push(format!(
                    "{lineno}: enum variant `{no_semicolon}` outside an enum"
                ));
            }
        }

        for c in line.chars() {
            match c {
                '(' | '[' | '{' => {
                    stack.push((c, lineno));
                    depth += 1;
                }
                ')' | ']' | '}' => {
                    let expected = match c {
                        ')' => '(',
                        ']' => '[',
                        _ => '{',
                    };
                    match stack.pop() {
                        Some((open, _)) if open == expected => depth -= 1,
                        Some((open, at)) => {
                            out.push(format!(
                                "{lineno}: closing `{c}` does not match `{open}` opened at line {at}"
                            ));
                            depth -= 1;
                        }
                        None => out.push(format!("{lineno}: unmatched closing `{c}`")),
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(at) = pending_test_attr {
        out.push(format!("{at}: test attribute at end of file has no function"));
    }
    for (open, at) in stack {
        out.push(format!("{at}: `{open}` is never closed"));
    }
    out.sort();
    out.dedup();
    out
}

pub fn run(root: &Path) -> Result<String, String> {
    let files = rust_files(root);
    if files.is_empty() {
        return Err(String::from("no Rust sources were scanned"));
    }
    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for (rel, path) in files {
        if std::fs::metadata(&path).map_or(true, |m| m.len() > MAX_FILE_BYTES) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        for f in findings(&text) {
            offenders.push(format!("{rel}:{f}"));
        }
    }
    if !offenders.is_empty() {
        offenders.sort();
        let mut msg = String::from("mangled Rust sources:");
        for o in offenders.iter().take(MAX_REPORTED) {
            let _ = write!(msg, "\n  {o}");
        }
        if offenders.len() > MAX_REPORTED {
            let _ = write!(msg, "\n  ... and {} more", offenders.len() - MAX_REPORTED);
        }
        return Err(msg);
    }
    Ok(format!(
        "rust syntax check OK: {scanned} Rust sources have balanced delimiters and no mangled fragments."
    ))
}

pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-rust-syntax")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        let clean = "//! A string with { and ( and a comment // }\n\
pub fn answer() -> u64 {\n    let x = vec![1, 2, 3];\n    x.iter().sum()\n}\n\n\
#[test]\nfn answer_is_42() {\n    assert_eq!(answer(), 6);\n}\n";
        put("src/clean.rs", clean)?;
        run(&dir).map_err(|e| format!("canary: clean source was refused: {e}"))?;

        // Each canary reproduces one defect class seen on an open PR head.
        put("src/bad.rs", "#[test]\nf\nfn orphan() {}\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a lone `f` after #[test] was accepted"));
        }
        std::fs::remove_file(dir.join("src/bad.rs")).map_err(|e| e.to_string())?;

        put("src/bad.rs", "pub fn f() { let _ = 1; \n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an unclosed brace was accepted"));
        }

        put(
            "src/bad.rs",
            "pub struct S;\nimpl Clone for S {\n    fn clone(&self) -> Self {\n        self.\n            .clone()\n    }\n}\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a deleted method name was accepted"));
        }

        put("src/bad.rs", "f/// a mangled doc line\npub fn g() {}\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a stray `f` doc prefix was accepted"));
        }

        put("src/bad.rs", "pub enum E { A }\nBud3NotReady,\npub fn g() -> u8 { 0 }\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an orphan enum variant was accepted"));
        }

        // A comment or a string full of braces is not a structural finding.
        put(
            "src/bad.rs",
            "/// { [ ( unmatched on purpose\npub fn g() -> &'static str { \"}}} {{{ \" }\n",
        )?;
        run(&dir).map_err(|e| format!("canary: literals and comments were scanned as code: {e}"))?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "rust-syntax-is-parseable canary OK: five mangled shapes fail; balanced delimiters, literals, comments and real test attributes pass.",
    ))
}
