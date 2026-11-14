//! Source scanning helpers shared by the post-quantum gates.
//!
//! `classical-crypto-is-paired`, `scheme-is-never-inferred` and
//! `pq-ctx-is-bound` all read production Rust the same way: walk the source
//! roots, drop test code, look for identifier tokens, and sometimes read the
//! arguments of a call. This module is that reading, once.

use std::path::{Path, PathBuf};

/// Directories that never hold production code, wherever they appear.
const SKIP_DIRS: &[&str] = &["target", ".git", "tests", "benches", "fuzz", "examples"];

/// Every `.rs` file under the given roots, as `(relative path, absolute path)`,
/// sorted by relative path. Test and bench trees are skipped.
pub(crate) fn rust_files(root: &Path, roots: &[&str]) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for sub in roots {
        walk(&root.join(sub), root, &mut out);
    }
    out.sort();
    out
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if !SKIP_DIRS.contains(&&*name) {
                walk(&path, root, out);
            }
        } else if path.extension().is_some_and(|x| x == "rs") {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if !is_test_support(&rel) {
                out.push((rel, path));
            }
        }
    }
}

/// Files whose whole purpose is test support.
pub(crate) fn is_test_support(rel: &str) -> bool {
    rel.contains("/tests/")
        || rel.contains("_tests.rs")
        || rel.contains("/test_")
        || rel.ends_with("/tests.rs")
}

/// The text of a source file with `#[cfg(test)]` items removed.
pub(crate) fn production_text(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    Some(super::capability_modules_are_wired::strip_test_mods(&text))
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The line without its trailing `//` comment, and empty for a comment line.
pub(crate) fn code_part(line: &str) -> &str {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return "";
    }
    match line.find("//") {
        Some(at) => line.get(..at).unwrap_or(line),
        None => line,
    }
}

/// Whether `token` occurs in `text` as a whole token: the character before it
/// and the character after it are not identifier characters.
pub(crate) fn has_token(text: &str, token: &str) -> bool {
    let mut from = 0;
    while let Some(found) = text.get(from..).and_then(|rest| rest.find(token)) {
        let start = from + found;
        let end = start + token.len();
        let before = text.get(..start).and_then(|s| s.chars().next_back());
        let after = text.get(end..).and_then(|s| s.chars().next());
        if !before.is_some_and(is_ident_char) && !after.is_some_and(is_ident_char) {
            return true;
        }
        from = start + 1;
    }
    false
}

/// The name of the function a line sits in: the nearest `fn name` above it.
pub(crate) fn enclosing_fn(lines: &[&str], index: usize) -> String {
    for line in lines.iter().take(index + 1).rev() {
        let code = code_part(line);
        let mut from = 0;
        while let Some(found) = code.get(from..).and_then(|rest| rest.find("fn ")) {
            let start = from + found;
            let before = code.get(..start).and_then(|s| s.chars().next_back());
            if !before.is_some_and(is_ident_char) {
                let name: String = code
                    .get(start + 3..)
                    .unwrap_or("")
                    .chars()
                    .take_while(|c| is_ident_char(*c))
                    .collect();
                if !name.is_empty() {
                    return name;
                }
            }
            from = start + 3;
        }
    }
    String::from("(module)")
}

/// The top-level arguments of the call whose opening parenthesis is the first
/// `(` at or after `from` in `text`. Strings, characters and nested brackets are
/// respected. `None` when the call is not closed.
pub(crate) fn call_args(text: &str, from: usize) -> Option<Vec<String>> {
    let rest = text.get(from..)?;
    let open = rest.find('(')?;
    let body = rest.get(open + 1..)?;
    let mut args = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                current.push(c);
                while let Some(s) = chars.next() {
                    current.push(s);
                    if s == '\\' {
                        if let Some(escaped) = chars.next() {
                            current.push(escaped);
                        }
                    } else if s == '"' {
                        break;
                    }
                }
            }
            '(' | '[' | '{' => {
                depth += 1;
                current.push(c);
            }
            ')' | ']' | '}' => {
                if depth == 0 {
                    if c != ')' {
                        return None;
                    }
                    let last = current.trim().to_string();
                    if !last.is_empty() {
                        args.push(last);
                    }
                    return Some(args);
                }
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    None
}

/// Byte offsets of every occurrence of `needle` in `text`.
pub(crate) fn find_all(text: &str, needle: &str) -> Vec<usize> {
    text.match_indices(needle).map(|(at, _)| at).collect()
}

/// The 1-based line number of a byte offset.
pub(crate) fn line_of(text: &str, offset: usize) -> usize {
    text.get(..offset)
        .map_or(1, |head| head.matches('\n').count() + 1)
}

/// The text with `//` comments blanked out, keeping every byte offset and line
/// break where it was. Slash-slash inside a string literal is left alone.
pub(crate) fn blank_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut in_comment = false;
    let mut prev = '\0';
    for c in text.chars() {
        if in_comment {
            if c == '\n' {
                in_comment = false;
                out.push(c);
            } else {
                out.push(' ');
            }
            prev = c;
            continue;
        }
        if in_string {
            out.push(c);
            if c == '"' && prev != '\\' {
                in_string = false;
            }
            prev = if c == '\\' && prev == '\\' { '\0' } else { c };
            continue;
        }
        if c == '"' {
            in_string = true;
            out.push(c);
        } else if c == '/' && prev == '/' {
            // The first slash was already pushed; turn it into a blank too.
            out.pop();
            out.push(' ');
            out.push(' ');
            in_comment = true;
        } else {
            out.push(c);
        }
        prev = c;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_respect_identifier_boundaries() {
        assert!(has_token("use ed25519_dalek::Signer;", "ed25519_dalek"));
        assert!(has_token("let k = x25519(a);", "x25519"));
        assert!(!has_token("fn x25519_only_suite()", "x25519"));
        assert!(!has_token("not_bls12_381_either", "bls12_381"));
    }

    #[test]
    fn call_arguments_split_at_top_level_only() {
        let args = call_args("f(a, g(b, c), \"x, y\", [1, 2])", 0);
        assert_eq!(
            args,
            Some(vec![
                "a".to_string(),
                "g(b, c)".to_string(),
                "\"x, y\"".to_string(),
                "[1, 2]".to_string()
            ])
        );
        assert_eq!(call_args("f(a, b", 0), None);
    }

    #[test]
    fn comments_are_blanked_without_moving_offsets() {
        let text = "a // note\nb \"//\" c";
        let blanked = blank_comments(text);
        assert_eq!(blanked.len(), text.len());
        assert!(!blanked.contains("note"));
        assert!(blanked.contains("\"//\""));
    }
}
