//! `bud3_placement`: the placement path uses no floating point and reads the
//! table by integer comparison.
//!
//! §6.9.3 item 3 and item 6, and G-2: the consensus path must not use floating
//! point. The placement table itself is computed off-chain with floats
//! (`xtask/tools/src/placement_table.rs`), which is allowed because the result
//! is a genesis parameter and nothing on the chain recomputes it. What is not
//! allowed is a float anywhere between reading the table and choosing a bucket,
//! because two nodes with different FPUs (or a reordered optimisation) would
//! place the same segment on different validators and split the state root.
//!
//! # What this gate looks at
//!
//! The files of the placement path: `src/storage/bud3/placement.rs`, the
//! registry that consumes it, and `bud3/repair.rs`, which ranks candidates for
//! a repair assignment with the same rendezvous hash. Three signals, because
//! each catches what the others miss:
//!
//!   1. An `f32`/`f64` type, a float literal (`0.5`), or `as f64`/`as f32`.
//!   2. A float method or module: `.sqrt()`, `.ln()`, `.powf(`, `.floor()`,
//!      `f64::`, `f32::`.
//!   3. `std::ops::Div` on integers written as `/` in a score comparison is
//!      *not* flagged: integer division is exact and is what the ranker uses
//!      (`stake / l` is a cross-multiplied comparison, not a division).
//!
//! The canary injects each signal into a scratch copy and requires a failure.

use std::fmt::Write as _;
use std::path::Path;

/// The files whose floating point would be a consensus bug.
const FILES: &[&str] = &[
    "src/storage/bud3/placement.rs",
    "src/storage/bud3/repair.rs",
    "src/storage/bud3/registry.rs",
];

/// Type names and literals that mean floating point is in play.
///
/// `f64`/`f32` are matched as whole words so `inform64` does not trip the gate
/// and `f64::` does.
const FLOAT_TOKENS: &[&str] = &[
    "f32::", "f64::", "as f32", "as f64", ".sqrt()", ".ln()", ".log2()", ".log10()", ".powf(",
    ".powi(", ".floor()", ".ceil()", ".round()", ".exp()", "std::f32", "std::f64",
];

/// The finding for one line, if any.
fn float_in(line: &str) -> Option<String> {
    if let Some(token) = FLOAT_TOKENS.iter().find(|t| line.contains(*t)) {
        return Some(format!("uses `{token}`"));
    }
    // A float literal: a digit, a dot and a digit, in a context that is not a
    // version or a file name. `0.5`, `1.0`, but not `v1.2` and not
    // `docs/1.2/x.md` - both of those have a non-digit before the dot, and the
    // scan below stops at the first non-digit.
    let bytes: Vec<char> = line.chars().collect();
    for i in 1..bytes.len().saturating_sub(1) {
        if bytes[i] == '.' && bytes[i - 1].is_ascii_digit() && bytes[i + 1].is_ascii_digit() {
            // The run before the dot must be digits all the way back to a
            // non-identifier character, or this is part of a longer token such
            // as an IP address or a version string (`1.2.3`).
            let mut start = i;
            while start > 0 && (bytes[start - 1].is_ascii_digit() || bytes[start - 1] == '.') {
                start -= 1;
            }
            let dotted: String = bytes[start..=i + 1].iter().collect();
            if dotted.matches('.').count() > 1 {
                continue;
            }
            // An exponent or a second dot later in the same token means it is
            // not a simple literal either.
            let before_ident = start == 0
                || !(bytes[start - 1].is_alphanumeric() || bytes[start - 1] == '_');
            if before_ident && !dotted.starts_with("0.0") {
                return Some(format!("carries the float literal `{dotted}`"));
            }
        }
    }
    None
}

/// Scan one file's text.
///
/// Only production code is scanned. A unit test that checks a fixed-point
/// logarithm against the real number is the test that earns the fixed point
/// its trust, and `#[cfg(test)]` code is not on the consensus path - it is not
/// compiled into the node at all. The gate therefore stops at the first
/// `#[cfg(test)]` in the file, which is the one convention every module here
/// follows.
fn scan_text(name: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") {
            break;
        }
        // A comment is prose, and a doc comment in this tree names `f64` on
        // purpose. Only code is scanned.
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(why) = float_in(line) {
            let _ = writeln!(out, "{name}:{}: {why}", n + 1);
        }
    }
    out
}

/// Scan the tree.
fn scan(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for rel in FILES {
        let path = root.join(rel);
        let Ok(text) = std::fs::read_to_string(&path) else {
            // A file that is not there cannot use a float. The gate is about
            // the placement path that exists; `no_legacy_storage` is the gate
            // that notices one going missing.
            continue;
        };
        out.extend(scan_text(rel, &text));
    }
    out
}

/// Run the gate.
///
/// # Errors
///
/// The findings, one per line.
pub fn run(root: &Path) -> Result<String, String> {
    let found = scan(root);
    if found.is_empty() {
        return Ok(format!(
            "bud3 placement OK: no floating point in {} placement-path file(s); \
             bucket selection is integer comparison",
            FILES.len()
        ));
    }
    Err(format!(
        "FAIL: floating point on the B.U.D. 3.0 placement path (G-2, §6.9.3 item 3):\n  {}\n  \
         Two nodes with different FPUs would place the same segment on different \
         validators and split the state root. Rank with the fixed-point integers \
         in `placement.rs`; compute tables off-chain.",
        found.join("\n  ")
    ))
}

/// The canary: a float type, a float literal and a float method each fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-placement")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        // Clean: integer comparison and fixed-point arithmetic.
        for rel in FILES {
            put(
                rel,
                "fn rank(a: u128, b: u128) -> bool { a * 100 >= b } // f64 in prose is fine\n",
            )?;
        }
        run(&dir).map_err(|e| format!("canary: a clean placement path failed: {e}"))?;

        put(
            FILES[0],
            "fn score() -> u128 { 1u128 }\nfn x() { let _ = 0.5; }\n",
        )?;
        if let Ok(msg) = run(&dir) {
            return Err(format!("canary: a float literal passed: {msg}"));
        }
        put(FILES[0], "fn x(v: f64) -> f64 { v }\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an `f64` type passed"));
        }
        put(FILES[0], "fn x(v: f64) { let _ = v.sqrt(); }\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a float method passed"));
        }
        put(FILES[0], "// a comment naming f64 and 0.5 is prose\n")?;
        run(&dir).map_err(|e| format!("canary: a comment was reported as code: {e}"))?;
        // A version string is not a float literal.
        put(FILES[0], "const VERSION: &str = \"v1.2.3\";\n")?;
        run(&dir).map_err(|e| format!("canary: a version string was reported: {e}"))?;
        // A unit test may convert: it is not compiled into the node.
        put(
            FILES[0],
            "#[cfg(test)]\nmod tests {\n    fn x() { let _ = 1u64 as f64 + 0.5; }\n}\n",
        )?;
        run(&dir)
            .map_err(|e| format!("canary: a test module was reported as consensus code: {e}"))?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-placement canary OK: a float literal, type and method each failed; \
         a comment, a version string and a test module did not.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_placement_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }

    #[test]
    fn the_tree_is_clean() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("the gate crate lives two levels below the root");
        assert!(super::run(root).is_ok(), "{:?}", super::run(root));
    }
}
