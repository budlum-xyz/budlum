//! Rust literal and comment scrubbing shared by the source-scanning gates.
//!
//! Ported from the Strix CWE-184 hardening (follow-up work) that main's
//! `check-consensus-maps-are-ordered.sh`, `check-cross-table-checks-use-last-
//! row.sh` and `check-uncheckable-proof-paths-do-not-slash.sh` carried: a
//! `/*` or `*/` inside a string is data, not a comment, and an `r` inside a
//! string must not start a raw-string match, so literals are blanked before
//! the comment walks.
//!
//! Strip order matters:
//!   1. literals first, via a single-pass scanner that tells ordinary/byte
//!      strings, char literals and raw strings (`r#`, `br#`, hash count
//!      matched) apart;
//!   2. block comments with a depth counter (they nest in Rust; a flat regex
//!      leaves the tail of a nested comment visible as fake code);
//!   3. line comments last - after literals and blocks are gone, a `//` can
//!      only be a real line comment.
//!
//! Blanking keeps the newline structure, so line numbers stay meaningful.

/// Replace every non-newline character with a space, keeping newlines.
fn blank(chars: &[char]) -> String {
    let mut out = String::with_capacity(chars.len());
    for ch in chars {
        out.push(if *ch == '\n' { '\n' } else { ' ' });
    }
    out
}

/// One-pass Rust literal scanner. A char literal is a `'...'` with a closing
/// quote; a Rust lifetime `'a` has none, so it is left alone.
pub fn strip_rust_literals(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < n {
        let c = chars[i];
        if c == '\'' {
            let start = i;
            let mut j = i + 1;
            if j < n && chars[j] == '\\' {
                j += 2; // escaped char: '\n', '\\', '\''
            } else {
                j += 1;
            }
            if j < n && chars[j] == '\'' {
                // Closing quote present: a char literal, blank it.
                out.push_str(&blank(&chars[start..=j]));
                i = j + 1;
                continue;
            }
            // No closing quote: a lifetime, leave it.
            out.push(c);
            i += 1;
            continue;
        }
        if c == '"' || (c == 'b' && i + 1 < n && chars[i + 1] == '"') {
            let start = i;
            i += if c == 'b' { 2 } else { 1 };
            while i < n {
                if chars[i] == '\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                if chars[i] == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push_str(&blank(&chars[start..i]));
            continue;
        }
        if c == 'r' || (c == 'b' && i + 1 < n && chars[i + 1] == 'r') {
            let start = i;
            let prefix = if c == 'b' { 2 } else { 1 };
            let mut j = i + prefix;
            while j < n && chars[j] == '#' {
                j += 1;
            }
            let hashes = j - (i + prefix);
            // A raw string starts at an identifier boundary: `r"` alone is
            // not a raw string, and `br"` needs the `b` next to `r`.
            let prev_is_ident = i > 0
                && matches!(
                    chars[i - 1],
                    'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '"' | '\''
                );
            if j < n && chars[j] == '"' && !prev_is_ident {
                let closing_hashes = hashes;
                let mut end = j + 1;
                let mut matched = false;
                while end < n {
                    if end + 1 + closing_hashes <= n
                        && chars[end] == '"'
                        && (0..closing_hashes).all(|k| chars[end + 1 + k] == '#')
                    {
                        end += 1 + closing_hashes;
                        out.push_str(&blank(&chars[start..end]));
                        i = end;
                        matched = true;
                        break;
                    }
                    end += 1;
                }
                if matched {
                    continue;
                }
            }
            out.push(c);
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Strip Rust block comments with a depth counter (they nest).
pub fn strip_block_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    let mut depth = 0usize;
    while i < n {
        if i + 1 < n && chars[i] == '/' && chars[i + 1] == '*' {
            depth += 1;
            out.push_str("  ");
            i += 2;
            continue;
        }
        if depth > 0 && i + 1 < n && chars[i] == '*' && chars[i + 1] == '/' {
            depth -= 1;
            out.push_str("  ");
            i += 2;
            continue;
        }
        if depth > 0 {
            out.push(if chars[i] == '\n' { '\n' } else { ' ' });
            i += 1;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Remove line comments (`//...` to end of line), keeping newlines.
fn strip_line_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        let (line, had_newline, next) = match rest.find('\n') {
            Some(idx) => (&rest[..idx], true, &rest[idx + 1..]),
            None => (rest, false, ""),
        };
        let cut = line.find("//").unwrap_or(line.len());
        out.push_str(&line[..cut]);
        if had_newline {
            out.push('\n');
        }
        rest = next;
    }
    out
}

/// The full scrub the shell gates applied: literals, then block comments,
/// then line comments.
pub fn scrub(text: &str) -> String {
    let after_literals = strip_rust_literals(text);
    let after_blocks = strip_block_comments(&after_literals);
    strip_line_comments(&after_blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_literals_are_blanked() {
        let out = strip_rust_literals("let s = \"/* not a comment */\"; let a = 1;");
        assert!(!out.contains("/*"));
        assert!(out.contains("let a = 1;"));
    }

    #[test]
    fn char_literal_and_lifetime() {
        let out = strip_rust_literals("let c = '{'; let x = 'a'; let r = &'static str;");
        assert!(out.contains("'static"));
        assert!(!out.contains("'{'"));
        assert!(!out.contains("'a'"));
    }

    #[test]
    fn raw_string_with_hashes() {
        let out = strip_rust_literals("let s = r##\"quote \"# inside\"##; let a = 1;");
        assert!(out.contains("let a = 1;"));
        assert!(!out.contains("quote"));
    }

    #[test]
    fn nested_block_comments() {
        let out = strip_block_comments("/* outer /* inner */ still comment */ let a = 1;");
        assert!(out.contains("let a = 1;"));
        assert!(!out.contains("inner"));
    }

    #[test]
    fn scrub_removes_all_comment_kinds() {
        let src =
            "let a = 1; // line\n/* block */ let b = r#\"/* fake */\"#; // tail\nlet c = 3;\n";
        let out = scrub(src);
        assert!(out.contains("let a = 1;"));
        assert!(out.contains("let b ="));
        assert!(out.contains("let c = 3;"));
        assert!(!out.contains("line"));
        assert!(!out.contains("fake"));
    }
}
