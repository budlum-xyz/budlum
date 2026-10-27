//! A signature scheme is named, never guessed from a length.
//!
//! The old `classify_pq_signature_len` turned a byte length into a scheme. It
//! contradicted its own rule: a length says how many bytes there are, not which
//! algorithm made them, and the day two schemes share a length (or one scheme
//! gets a second encoding) the guess verifies the wrong thing. Every object now
//! carries a `SchemeId`; the lengths in the scheme table are used only to refuse
//! bytes that do not fit the scheme the caller already named.
//!
//! This gate reads production Rust under `src/` and `crates/` and fails on
//! three shapes of inference:
//!
//! * a name that is an inference function (`classify_pq_signature_len`,
//!   `pq_signature_len_acceptable`, `PqSignatureClass`, `scheme_from_len`, and
//!   the like);
//! * a `match` on a `.len()` whose arms name a signature or public key length
//!   constant;
//! * an `if` chain that tests one `.len()` against two different signature or
//!   key length constants.
//!
//! Comparing a length with the constant of the one scheme the caller named is
//! validation and is not flagged. Test code is out of scope.

use std::fmt::Write as _;
use std::path::Path;

/// Roots holding shipped code.
const SCAN_ROOTS: &[&str] = &["src", "crates", "budzero"];

/// Names that exist only to turn a length into a scheme.
const INFERENCE_NAMES: &[&str] = &[
    "classify_pq_signature_len",
    "pq_signature_len_acceptable",
    "PqSignatureClass",
    "PqSigClass",
    "scheme_from_len",
    "scheme_from_length",
    "scheme_of_len",
    "infer_scheme",
    "guess_scheme",
];

/// Suffixes of the constants that hold a scheme's key or signature length.
const LENGTH_CONSTANT_SUFFIXES: &[&str] =
    &["_SIGNATURE_LEN", "_SIG_LEN", "_PUBLIC_KEY_LEN", "_PK_LEN"];

/// How far below a `match` or an `if` the gate looks for the other arms.
const WINDOW: usize = 10;

fn length_constant(text: &str) -> Option<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .find(|word| {
            word.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                && LENGTH_CONSTANT_SUFFIXES.iter().any(|s| word.ends_with(s))
        })
        .map(str::to_string)
}

/// The finding lines of one source text, as `line: reason`.
#[must_use]
pub fn findings_of(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    // `(line, expression, constant)` of every `expr.len() == CONST` seen.
    let mut comparisons: Vec<(usize, String, String)> = Vec::new();
    for (index, raw) in lines.iter().enumerate() {
        let code = super::pq_scan::code_part(raw);
        for name in INFERENCE_NAMES {
            if super::pq_scan::has_token(code, name) {
                out.push(format!(
                    "{}: `{name}` infers a scheme from a length",
                    index + 1
                ));
            }
        }
        let trimmed = code.trim_start();
        if trimmed.starts_with("match ") && code.contains(".len()") {
            let window = lines
                .iter()
                .skip(index + 1)
                .take(WINDOW)
                .map(|l| super::pq_scan::code_part(l))
                .collect::<Vec<_>>()
                .join("\n");
            if let Some(constant) = length_constant(&window) {
                out.push(format!(
                    "{}: a match on a length names `{constant}`; the scheme must come from the object, not its size",
                    index + 1
                ));
            }
        }
        if let Some((left, right)) = code.split_once(".len() ==") {
            if let Some(constant) = length_constant(right) {
                let expr: String = left
                    .chars()
                    .rev()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                comparisons.push((index + 1, expr, constant));
            }
        }
    }
    for (i, (line, expr, constant)) in comparisons.iter().enumerate() {
        let other = comparisons
            .iter()
            .skip(i + 1)
            .find(|(l, e, c)| e == expr && c != constant && l.saturating_sub(*line) <= WINDOW);
        if let Some((other_line, _, other_constant)) = other {
            out.push(format!(
                "{line}: `{expr}.len()` is tested against `{constant}` and (line {other_line}) `{other_constant}`; that picks a scheme by length"
            ));
        }
    }
    out
}

/// Run the gate.
///
/// # Errors
///
/// Any inference found in production code.
pub fn run(root: &Path) -> Result<String, String> {
    let files = super::pq_scan::rust_files(root, SCAN_ROOTS);
    if files.len() < 100 {
        return Err(format!(
            "only {} source files found under the scan roots; the gate would be vacuous",
            files.len()
        ));
    }
    let mut report = String::new();
    let mut count = 0usize;
    for (rel, path) in &files {
        let Some(text) = super::pq_scan::production_text(path) else {
            continue;
        };
        for finding in findings_of(&text) {
            count += 1;
            let _ = writeln!(report, "  {rel}:{finding}");
        }
    }
    if count == 0 {
        Ok(format!(
            "No scheme is inferred from a length: {} files scanned.",
            files.len()
        ))
    } else {
        Err(format!(
            "{count} place(s) infer a signature scheme from a length (INV-03):\n{report}\n  \
             Carry a SchemeId with the object (crypto::scheme) and check the length against \
             the scheme the caller named."
        ))
    }
}

/// Canaries.
///
/// # Errors
///
/// A canary that does not behave as stated.
pub fn self_test() -> Result<String, String> {
    let bad = [
        "fn f() { classify_pq_signature_len(sig.len()) }",
        "match sig.len() {\n    ML_DSA_65_SIGNATURE_LEN => A,\n    _ => B,\n}",
        "if sig.len() == FOO_SIGNATURE_LEN {\n} else if sig.len() == BAR_SIGNATURE_LEN {\n}",
        "enum PqSignatureClass { A }",
    ];
    for source in bad {
        if findings_of(source).is_empty() {
            return Err(format!("an inference was missed: {source:?}"));
        }
    }
    let good = [
        "if signature.len() != ML_DSA_87_SIGNATURE_LEN { return Err(e); }",
        "if sig.len() == FOO_SIGNATURE_LEN {} // and sig.len() == BAR_SIGNATURE_LEN",
        "match kind { Kind::A => 1, Kind::B => 2 }",
        "let n = sig.len();",
    ];
    for source in good {
        let found = findings_of(source);
        if !found.is_empty() {
            return Err(format!("a clean line was flagged: {source:?} -> {found:?}"));
        }
    }
    Ok(String::from(
        "canary OK: inference functions, length matches and length chains are caught; plain validation is not.",
    ))
}
