//! What a tool prints and how it exits.
//!
//! The first tools in this crate return `Result<String, String>`. The tools
//! ported from Python scripts keep the exact stdout, stderr and exit code their
//! scripts had, because workflows and people read those. So they return this
//! type, and the entry point only prints it.

/// The complete outcome of one tool run.
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    /// Printed to stdout exactly as given. Include the trailing newline.
    pub stdout: String,
    /// Printed to stderr exactly as given.
    pub stderr: String,
    /// The process exit code.
    pub code: i32,
}

impl Report {
    /// Exit 0 with output on stdout.
    #[must_use]
    pub fn ok(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            code: 0,
        }
    }

    /// A non-zero exit with output on stdout and nothing on stderr.
    #[must_use]
    pub fn exit_with(stdout: String, code: i32) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            code,
        }
    }

    /// A non-zero exit with the finding on stderr.
    #[must_use]
    pub fn fail_with(stderr: String, code: i32) -> Self {
        Self {
            stdout: String::new(),
            stderr,
            code,
        }
    }
}

/// Python's `repr` for a string: single quotes unless the text holds a single
/// quote and no double quote.
#[must_use]
pub fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repr_picks_the_quote_like_python() {
        assert_eq!(py_repr("abc"), "'abc'");
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("a'b\"c"), "'a\\'b\"c'");
        assert_eq!(py_repr("a\nb"), "'a\\nb'");
    }
}
