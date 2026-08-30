//! A gate that panics reports a backtrace instead of a finding.
//!
//! The workspace crates deny `unwrap_used` and `expect_used` in production
//! code. `xtask/gates` does not, and the reason it was skipped is that gate
//! code "is not production" - it does not ship in the node binary.
//!
//! That reasoning is wrong in the way that matters. When a gate panics, CI
//! prints a panic message and a backtrace, and the operator has to work out
//! whether the tree is broken or the gate is. The failure is indistinguishable
//! from a real finding at a glance and much harder to read than one, so the
//! panic costs more attention than the check saves. Worse, a gate that panics
//! on a malformed input is a gate that stops checking the rest of the tree: the
//! process is gone, and every finding it had not reached yet is silently not
//! reported. A gate is exactly the code that must degrade into a sentence.
//!
//! # What is exempt, and why
//!
//! Two categories are not findings, and both are recognised structurally rather
//! than by an allowlist:
//!
//! - **Canary bodies.** A self-test asserts the gate behaves; panicking there
//!   is the assertion mechanism, and the panic happens under `--self-test`
//!   where a backtrace is the expected way to report a broken canary.
//! - **`write!`/`writeln!` into a `String`.** `std::fmt::Write` for `String` is
//!   infallible, and the `Result` exists only because the trait is shared with
//!   `io::Write`. Rewriting these buys nothing.
//!
//! Everything else ratchets: [`BASELINE_PATH`] records what is still there, the
//! list may only shrink, and a line that is no longer a panic point is itself a
//! failure so the file cannot rot into a permanent excuse.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// The recorded panic points that have not been removed yet.
const BASELINE_PATH: &str = ".github/gate-panics-baseline.txt";

/// Where gate sources live.
const GATES_DIR: &str = "xtask/gates/src";

/// A scan that walks too few files is vacuous and must fail rather than pass.
const VACUITY_FLOOR: usize = 40;

/// How many findings are printed before the list is summarised.
const MAX_REPORTED: usize = 30;

/// A panic point: the file it is in and the line, plus the source text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PanicPoint {
    /// Repository-relative path.
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    /// The trimmed source line, for the report.
    pub text: String,
    /// Which occurrence of this exact text in this file, counting from 1.
    ///
    /// Four identical `.unwrap()` lines in one file are four debts. Without an
    /// ordinal they collapse into one baseline key, and removing three of them
    /// leaves the fourth matching the same entry - the ratchet reports no
    /// change for work that did most of the job.
    pub ordinal: usize,
}

impl PanicPoint {
    /// The baseline key: path, occurrence index, and line text.
    ///
    /// Line numbers are deliberately excluded. Inserting a comment above a
    /// panic point would change its number and turn one baseline entry into
    /// both a "no longer present" failure and a "new" failure, for a change
    /// that moved nothing. The ordinal keeps duplicates distinct without
    /// reintroducing that fragility: it only shifts when a duplicate is
    /// actually added or removed, which is exactly when the debt changed.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}\t{}\t{}", self.file, self.ordinal, self.text)
    }
}

/// Is this a `write!`/`writeln!` into a `String`?
///
/// Matched on the macro rather than the receiver: a gate builds its message in
/// a `String`, and `std::fmt::Write` for `String` cannot fail. The `Result`
/// exists because the trait is shared with `io::Write`, where it can.
fn is_infallible_fmt(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("write!") || t.starts_with("writeln!") || t.starts_with("let _ = write")
}

/// Does this line contain a panicking unwrap?
///
/// `.expect(` is only counted when its argument is a string literal.
/// `self.expect(Token::Comma)` is a parser method returning `Result`, not a
/// panic, and an earlier count of this debt reported 81 phantom findings in one
/// file for exactly that reason.
fn is_panic_point(line: &str) -> bool {
    let t = line.trim();
    if t.starts_with("//") || t.starts_with("///") {
        return false;
    }
    if is_infallible_fmt(t) {
        return false;
    }
    t.contains(".unwrap()") || t.contains(".unwrap_err()") || t.contains(".expect(\"")
}

/// Scan one file's source for panic points outside tests and canaries.
///
/// `#[cfg(test)]` modules are skipped by brace depth, and any function whose
/// name contains `self_test` or `canar` is skipped to the end of its body.
#[must_use]
pub fn scan(rel: &str, source: &str) -> Vec<PanicPoint> {
    let lines: Vec<&str> = source.lines().collect();
    let mut out: Vec<PanicPoint> = Vec::new();
    let mut seen: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();

        // Skip a `#[cfg(test)]` item entirely.
        if trimmed.starts_with("#[cfg(test)]") {
            i = skip_item(&lines, i);
            continue;
        }
        // Skip a canary function entirely.
        if is_canary_signature(trimmed) {
            i = skip_item(&lines, i);
            continue;
        }
        if is_panic_point(line) {
            let mut text = line.trim().to_string();
            text.truncate(120);
            let ordinal = {
                let n = seen.entry(text.clone()).or_insert(0);
                *n += 1;
                *n
            };
            out.push(PanicPoint {
                file: rel.to_string(),
                line: i + 1,
                text,
                ordinal,
            });
        }
        i += 1;
    }
    out
}

/// Is this line the signature of a self-test or canary function?
fn is_canary_signature(trimmed: &str) -> bool {
    let is_fn = trimmed.starts_with("fn ")
        || trimmed.starts_with("pub fn ")
        || trimmed.starts_with("pub(crate) fn ");
    is_fn && (trimmed.contains("self_test") || trimmed.contains("canar"))
}

/// Index of the first line after the item starting at `start`.
///
/// Counts braces from the first `{` at or after `start`. An item with no brace
/// at all (an attribute on a `use`, say) consumes only its own line, so the
/// scan cannot be made to swallow the rest of a file by a stray attribute.
fn skip_item(lines: &[&str], start: usize) -> usize {
    let mut i = start;
    while i < lines.len() && !lines[i].contains('{') {
        // A `;` before any brace ends the item: `#[cfg(test)] use x;`.
        if lines[i].trim_end().ends_with(';') {
            return i + 1;
        }
        i += 1;
    }
    if i >= lines.len() {
        return lines.len();
    }
    let mut depth = 0i32;
    while i < lines.len() {
        for c in lines[i].chars() {
            if c == '{' {
                depth += 1;
            } else if c == '}' {
                depth -= 1;
            }
        }
        i += 1;
        if depth <= 0 {
            break;
        }
    }
    i
}

/// Read the baseline into a set of keys, ignoring comments and blank lines.
fn read_baseline(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// Walk `.rs` files under `dir`, sorted for a stable report order.
fn rust_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            walk(&path, out);
        } else if kind.is_file() && path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// # Errors
///
/// Returns the panic points that are not on the baseline, or the baseline
/// entries that are no longer panic points.
pub fn run(root: &Path) -> Result<String, String> {
    let gates = root.join(GATES_DIR);
    let files = rust_files(&gates);
    if files.len() < VACUITY_FLOOR {
        return Err(format!(
            "only {} gate source files were found under {GATES_DIR}, below the \
             floor of {VACUITY_FLOOR}.\n  A scan this small is not evidence: the \
             root is wrong, and a gate that reports OK after looking at nothing \
             is worse than an absent one.",
            files.len()
        ));
    }

    let mut found: Vec<PanicPoint> = Vec::new();
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        found.extend(scan(&rel, &text));
    }

    let baseline_file = root.join(BASELINE_PATH);
    let baseline_text = std::fs::read_to_string(&baseline_file)
        .map_err(|e| format!("{}: {e}", baseline_file.display()))?;
    let baseline = read_baseline(&baseline_text);

    let keys: BTreeSet<String> = found.iter().map(PanicPoint::key).collect();
    let new: Vec<&PanicPoint> = found
        .iter()
        .filter(|p| !baseline.contains(&p.key()))
        .collect();
    let gone: Vec<&String> = baseline.iter().filter(|k| !keys.contains(*k)).collect();

    if !new.is_empty() {
        let mut msg = format!("{} new panic point(s) in gate code:\n", new.len());
        for p in new.iter().take(MAX_REPORTED) {
            let _ = writeln!(msg, "  {}:{}: {}", p.file, p.line, p.text);
        }
        if new.len() > MAX_REPORTED {
            let _ = writeln!(msg, "  ... and {} more", new.len() - MAX_REPORTED);
        }
        msg.push_str(
            "  A gate that panics prints a backtrace instead of a finding, and \
             stops checking the rest of the tree on its way out. Return a \
             `Result` describing what was wrong. Do not add a line to the \
             baseline to silence this.",
        );
        return Err(msg);
    }

    if !gone.is_empty() {
        let mut msg = format!(
            "{} baseline entr(ies) are no longer panic points:\n",
            gone.len()
        );
        for k in gone.iter().take(MAX_REPORTED) {
            let _ = writeln!(msg, "  {}", k.replace('\t', " | "));
        }
        let _ = write!(
            msg,
            "  Remove them from {BASELINE_PATH}. The list only shrinks, and it \
             has to shrink in the same commit that fixes the code, or it turns \
             into a record of a tree that no longer exists."
        );
        return Err(msg);
    }

    Ok(format!(
        "no new panic points in {} gate source files ({} on the baseline, \
         canaries and infallible String writes exempt)",
        files.len(),
        baseline.len()
    ))
}

/// # Errors
///
/// Returns the first canary that did not behave.
pub fn self_test() -> Result<String, String> {
    // 1. A plain unwrap in a gate function is a finding.
    let src = "pub fn run() {\n    let x = thing().unwrap();\n}\n";
    if scan("g.rs", src).len() != 1 {
        return Err(String::from("canary 1: a plain unwrap was not reported"));
    }

    // 2. A canary body is exempt: panicking is how a self-test asserts.
    let src = "pub fn self_test() -> Result<(), String> {\n    a().unwrap();\n}\n";
    if !scan("g.rs", src).is_empty() {
        return Err(String::from(
            "canary 2: a panic inside a self-test was reported; that is the \
             assertion mechanism, not a defect",
        ));
    }

    // 3. `#[cfg(test)]` is exempt.
    let src = "#[cfg(test)]\nmod tests {\n    fn t() {\n        a().unwrap();\n    }\n}\n";
    if !scan("g.rs", src).is_empty() {
        return Err(String::from(
            "canary 3: a panic under cfg(test) was reported",
        ));
    }

    // 4. The scan resumes after a skipped item, rather than swallowing the file.
    let src = "#[cfg(test)]\nmod tests {\n    fn t() { a().unwrap(); }\n}\npub fn run() {\n    b().unwrap();\n}\n";
    if scan("g.rs", src).len() != 1 {
        return Err(String::from(
            "canary 4: the scan did not resume after a cfg(test) module - a \
             skip that runs to the end of the file makes every later gate \
             invisible",
        ));
    }

    // 5. Writing into a String is infallible and exempt.
    let src = "pub fn run() {\n    writeln!(msg, \"x\").expect(\"writing to a String cannot fail\");\n}\n";
    if !scan("g.rs", src).is_empty() {
        return Err(String::from(
            "canary 5: an infallible String write was reported",
        ));
    }

    // 6. A `Result`-returning method called `expect` is not a panic.
    let src = "pub fn run() {\n    self.expect(Token::Comma)?;\n}\n";
    if !scan("g.rs", src).is_empty() {
        return Err(String::from(
            "canary 6: `self.expect(Token::Comma)?` was counted as a panic. A \
             count that made this mistake reported 81 phantom findings in one \
             parser.",
        ));
    }

    // 7. A commented-out unwrap is not a finding.
    if !scan("g.rs", "// let x = a().unwrap();\n").is_empty() {
        return Err(String::from(
            "canary 7: a commented-out unwrap was reported",
        ));
    }

    // 8. The key ignores line numbers, so inserting a line above a panic point
    //    does not turn one entry into two failures.
    let a = scan("g.rs", "pub fn run() {\n    a().unwrap();\n}\n");
    let b = scan("g.rs", "// note\npub fn run() {\n    a().unwrap();\n}\n");
    let (Some(a0), Some(b0)) = (a.first(), b.first()) else {
        return Err(String::from(
            "canary 8: the fixture stopped producing a point",
        ));
    };
    if a0.key() != b0.key() {
        return Err(String::from(
            "canary 8: the baseline key changed when a comment was inserted \
             above the panic point; the key must not depend on the line number",
        ));
    }
    if a0.line == b0.line {
        return Err(String::from(
            "canary 8: the reported line number did not move, so the fixture is \
             not exercising what the key is supposed to ignore",
        ));
    }

    // 9. Duplicate lines in one file are distinct debts.
    let dup = scan(
        "g.rs",
        "pub fn run() {\n    a().unwrap();\n    a().unwrap();\n}\n",
    );
    if dup.len() != 2 {
        return Err(String::from(
            "canary 9: two identical panic points were not both found",
        ));
    }
    let (Some(d0), Some(d1)) = (dup.first(), dup.get(1)) else {
        return Err(String::from(
            "canary 9: the duplicate fixture stopped producing points",
        ));
    };
    if d0.key() == d1.key() {
        return Err(String::from(
            "canary 9: two identical panic points share a baseline key. Removing \
             one of them would then leave the other matching the same entry, and \
             the ratchet would report no change for work that halved the debt.",
        ));
    }

    Ok(String::from("gates-do-not-panic: 9 canaries"))
}
