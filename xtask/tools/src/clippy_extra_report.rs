//! Turn a clippy-extra ratchet count into an address.
//!
//! It replaces `ops/scripts/clippy-extra-report.py`.
//!
//! The `clippy-extra` gate reports a single number: how many pedantic and
//! nursery warnings the tree has, against a baseline that must not rise. When
//! it trips, the number alone does not say which warnings are new, and the JSON
//! it counts lives in the runner's `/tmp`, so there is nothing to inspect after
//! the job ends.
//!
//! This prints the per-lint tally and the `file:line` of every hit under
//! `src/` and `kani/`, straight into the CI log. It reads the same JSON the
//! gate reads and writes nothing, so it cannot change the gate's verdict.
//!
//! Usage: `clippy-extra-report <clippy-json> [max-per-lint]`
//!
//! The second argument is accepted for compatibility and ignored. The first
//! version truncated the list at 40 per lint and hid over 2000 addresses, and a
//! truncated list cannot be diffed between two runs.
//!
//! Each line is one JSON value, which is what cargo writes. The reader is the
//! crate's own `json` module.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::Path;

use crate::json::{self, Value};
use crate::report::Report;

/// The warnings counted so far.
#[derive(Default)]
struct Tally {
    /// Lint code to count, in first-seen order.
    counts: Vec<(String, usize)>,
    index: HashMap<String, usize>,
    /// `file:line` of the first span, as `place\tcode`, first-party only.
    addresses: BTreeSet<String>,
}

impl Tally {
    /// Take one line of cargo's JSON output.
    fn add_line(&mut self, line: &str) {
        let Ok(record) = json::parse(line) else {
            return;
        };
        if record.get("reason").and_then(Value::as_str) != Some("compiler-message") {
            return;
        }
        let Some(message) = record.get("message") else {
            return;
        };
        let code = message
            .get("code")
            .and_then(|c| c.get("code"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if message.get("level").and_then(Value::as_str) != Some("warning")
            || !code.starts_with("clippy::")
        {
            return;
        }
        if let Some(&at) = self.index.get(code) {
            self.counts[at].1 += 1;
        } else {
            self.index.insert(code.to_string(), self.counts.len());
            self.counts.push((code.to_string(), 1));
        }
        let first = match message.get("spans") {
            Some(Value::Array(spans)) => spans.first(),
            _ => None,
        };
        if let Some(span) = first {
            let file = span.get("file_name").and_then(Value::as_str);
            let line_start = match span.get("line_start") {
                Some(Value::Number(n)) => Some(n.as_str()),
                _ => None,
            };
            if let (Some(file), Some(line_start)) = (file, line_start) {
                let place = format!("{file}:{line_start}");
                if place.starts_with("src/") || place.starts_with("kani/") {
                    self.addresses.insert(format!("{place}\t{code}"));
                }
            }
        }
    }

    fn render(&self) -> String {
        let total: usize = self.counts.iter().map(|(_, n)| n).sum();
        let mut out = format!(
            "--- clippy-extra: {total} warnings across {} lints ---\n",
            self.counts.len()
        );
        let mut ranked: Vec<&(String, usize)> = self.counts.iter().collect();
        // Stable, so equal counts keep first-seen order like `most_common`.
        ranked.sort_by_key(|row| std::cmp::Reverse(row.1));
        for (code, count) in ranked.into_iter().take(30) {
            let _ = writeln!(out, "{count:6}  {code}");
        }
        out.push_str("--- first-party hits (src/, kani/), one per line ---\n");
        for row in &self.addresses {
            let _ = writeln!(out, "{row}");
        }
        let _ = writeln!(
            out,
            "--- {} first-party addresses ---",
            self.addresses.len()
        );
        out
    }
}

/// Build the report text for the contents of a clippy JSON file.
#[must_use]
pub fn report_for(contents: &str) -> String {
    let mut tally = Tally::default();
    for line in contents.lines() {
        tally.add_line(line);
    }
    tally.render()
}

/// Run the tool with its command line arguments.
#[must_use]
pub fn cli(args: &[&str], _root: &Path) -> Report {
    let Some(path) = args.first() else {
        return Report::fail_with(
            "usage: clippy-extra-report <clippy-json> [max-per-lint]\n".to_string(),
            2,
        );
    };
    if let Some(cap) = args.get(1) {
        if cap.trim().parse::<i64>().is_err() {
            return Report::fail_with(
                format!("clippy-extra-report: max-per-lint must be an integer, got {cap}\n"),
                1,
            );
        }
    }
    match std::fs::read(path) {
        Ok(bytes) => Report::ok(report_for(&String::from_utf8_lossy(&bytes))),
        // A missing file is the gate's problem to report, not this tool's.
        Err(e) => Report::ok(format!("clippy-extra-report: cannot read {path}: {e}\n")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(level: &str, code: &str, file: &str, line: u32) -> String {
        format!(
            "{{\"reason\":\"compiler-message\",\"message\":{{\"level\":\"{level}\",\
             \"code\":{{\"code\":\"{code}\"}},\"spans\":[{{\"file_name\":\"{file}\",\
             \"line_start\":{line}}}]}}}}"
        )
    }

    #[test]
    fn only_clippy_warnings_count() {
        let input = [
            message("warning", "clippy::pedantic_a", "src/a.rs", 10),
            message("warning", "clippy::pedantic_a", "src/a.rs", 10),
            message("warning", "clippy::pedantic_a", "src/b.rs", 3),
            message("error", "clippy::pedantic_a", "src/c.rs", 1),
            message("warning", "unused_variables", "src/d.rs", 1),
            message("warning", "clippy::other", "crates/x.rs", 5),
            message("warning", "clippy::other", "kani/h.rs", 9),
            "not json at all".to_string(),
            "{\"reason\":\"compiler-artifact\"}".to_string(),
        ]
        .join("\n");
        let out = report_for(&input);
        let expected = "--- clippy-extra: 5 warnings across 2 lints ---\n\
                        \x20    3  clippy::pedantic_a\n\
                        \x20    2  clippy::other\n\
                        --- first-party hits (src/, kani/), one per line ---\n\
                        kani/h.rs:9\tclippy::other\n\
                        src/a.rs:10\tclippy::pedantic_a\n\
                        src/b.rs:3\tclippy::pedantic_a\n\
                        --- 3 first-party addresses ---\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn equal_counts_keep_first_seen_order() {
        let input = [
            message("warning", "clippy::b", "src/x.rs", 1),
            message("warning", "clippy::a", "src/x.rs", 2),
        ]
        .join("\n");
        let out = report_for(&input);
        let b = out.find("clippy::b").expect("b listed");
        let a = out.find("clippy::a").expect("a listed");
        assert!(b < a);
    }

    #[test]
    fn a_missing_file_is_reported_with_exit_zero() {
        let report = cli(&["/definitely/not/here.json"], Path::new("."));
        assert_eq!(report.code, 0);
        assert!(report
            .stdout
            .starts_with("clippy-extra-report: cannot read"));
    }

    #[test]
    fn no_arguments_is_a_usage_error() {
        let report = cli(&[], Path::new("."));
        assert_eq!(report.code, 2);
        assert!(report.stderr.starts_with("usage:"));
    }
}
