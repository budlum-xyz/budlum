//! A `chain_id` written as a literal is a proof bound to nothing.
//!
//! # The failure this closes
//!
//! `src/lubot/verify.rs` built `ExecutionPublicInputs` with `chain_id: 1`.
//! The chain's real id is 45262. `chain_id` is a public input: it is the
//! field that ties a proof to the chain it was produced for. Pinned to a
//! literal, two things follow. The proofs produced here belong to no real
//! chain, and a proof carrying `chain_id = 1` matches the expected inputs
//! here regardless of where it came from.
//!
//! This is the "public input mis-binding" class from the threat model. The
//! same class in Aleo/snarkVM produced full transaction forgery, and it is
//! in scope on every zkVM bounty programme surveyed (wrong state root, wrong
//! chain id, transcript reuse).
//!
//! The helper had no production caller when it was found, which is exactly
//! why it survived: a pinned field is invisible until the day something calls
//! it. The gate closes the return path rather than trusting review.
//!
//! # What is measured
//!
//! Any struct-literal field `chain_id: <integer literal>` under the scanned
//! roots fails. Accepted instead:
//!
//! * `chain_id` taken from a named constant, a parameter, a config field or
//!   any other expression (`chain_id: DEFAULT_CHAIN_ID`, `chain_id,`
//!   `chain_id: self.chain_id`, `chain_id: inputs.chain_id`).
//! * Test modules and test-support files, where a literal is how a fixture
//!   states which chain it means. A test that cannot write `chain_id: 1`
//!   cannot test cross-chain rejection at all.
//! * Constant definitions themselves (`const DEFAULT_CHAIN_ID: u64 = 45262;`),
//!   which are the one place the number is supposed to appear.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Roots holding shipped library code.
const SCAN_ROOTS: &[&str] = &["src", "budzero", "crates"];

/// Strip `#[cfg(test)] mod tests { ... }` bodies, brace-counted.
///
/// A literal inside a test is a fixture stating which chain it means, not a
/// binding decision. Counting braces rather than cutting at the first `}`
/// keeps nested blocks inside the test module from ending the skip early.
fn strip_test_modules(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos..];
        let Some(brace) = after.find('{') else {
            break;
        };
        let mut depth = 0usize;
        let mut end = None;
        for (i, c) in after.char_indices().skip(brace) {
            if c == '{' {
                depth += 1;
            } else if c == '}' {
                depth -= 1;
                if depth == 0 {
                    end = Some(i + 1);
                    break;
                }
            }
        }
        match end {
            Some(e) => rest = &after[e..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Is this line a `chain_id: <int literal>` struct field?
///
/// Returns the offending literal when it is.
fn hardcoded_chain_id(line: &str) -> Option<String> {
    let trimmed = line.trim();
    // A constant definition is where the number belongs.
    if trimmed.starts_with("const ") || trimmed.starts_with("pub const ") {
        return None;
    }
    let idx = trimmed.find("chain_id:")?;
    // Only a field named exactly `chain_id`, not `expected_chain_id:` etc.
    let before = trimmed[..idx].chars().next_back();
    if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    let after = trimmed[idx + "chain_id:".len()..].trim();
    // A type annotation (`chain_id: u64`) is a declaration, not a value.
    let value: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '_')
        .collect();
    if value.is_empty() {
        return None;
    }
    // The digits must be the whole value, ending at `,` or `}`.
    let tail = after[value.len()..].trim_start();
    if tail.is_empty() || tail.starts_with(',') || tail.starts_with('}') {
        return Some(value);
    }
    None
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            if matches!(&*name, "target" | ".git" | "tests" | "benches" | "fuzz") {
                continue;
            }
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Files whose whole purpose is test support.
fn is_test_support(rel: &str) -> bool {
    rel.contains("/tests/")
        || rel.contains("_tests.rs")
        || rel.contains("/test_")
        || rel.ends_with("/tests.rs")
}

/// # Errors
///
/// Fails when a `chain_id` is written as an integer literal outside tests.
pub fn run(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    for sub in SCAN_ROOTS {
        let base = root.join(sub);
        if base.is_dir() {
            walk(&base, &mut files);
        }
    }
    if files.is_empty() {
        return Err(String::from(
            "FAIL: no .rs files found - wrong root, the gate would be vacuous",
        ));
    }

    let mut hits: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for f in &files {
        let rel = f
            .strip_prefix(root)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_support(&rel) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        scanned += 1;
        let code = strip_test_modules(&text);
        for (n, line) in code.lines().enumerate() {
            if let Some(v) = hardcoded_chain_id(line) {
                hits.push(format!("{rel}:{}  chain_id: {v}", n + 1));
            }
        }
    }

    if !hits.is_empty() {
        let mut msg = String::from("FAIL: a chain_id is written as a literal:\n");
        for h in &hits {
            let _ = writeln!(msg, "  - {h}");
        }
        msg.push_str(
            "\nchain_id is the public input that binds a proof to its chain. Pinned to a\n\
             literal, the proof belongs to no real chain and a proof carrying that same\n\
             literal matches wherever it came from - the public-input mis-binding class.\n\
             Take it from a constant, a parameter or config instead.",
        );
        return Err(msg);
    }

    Ok(format!(
        "chain-id gate OK: {scanned} files carry no literal chain_id outside tests."
    ))
}

/// # Errors
///
/// Fails when a canary is misclassified.
pub fn self_test() -> Result<String, String> {
    let must_flag = [
        "        chain_id: 1,",
        "    chain_id: 45262,",
        "chain_id: 0 }",
        "            chain_id: 1_000,",
    ];
    for c in must_flag {
        if hardcoded_chain_id(c).is_none() {
            return Err(format!("a literal chain_id was accepted: {c:?}"));
        }
    }

    let must_pass = [
        "        chain_id: DEFAULT_CHAIN_ID,",
        "        chain_id,",
        "        chain_id: self.chain_id,",
        "        chain_id: inputs.chain_id,",
        "    pub chain_id: u64,",
        "fn f(_chain_id: u64, backend: &str) -> bool {",
        "pub const DEFAULT_CHAIN_ID: u64 = 45262;",
        "        expected_chain_id: 1,",
        "        chain_id: cfg.chain_id(),",
    ];
    for c in must_pass {
        if let Some(v) = hardcoded_chain_id(c) {
            return Err(format!("a legitimate line was flagged: {c:?} -> {v}"));
        }
    }

    // A literal inside a test module must be invisible to the scan.
    let with_test = "fn a() { let x = 1; }\n\
                     #[cfg(test)]\n\
                     mod tests {\n\
                     fn b() { if true { } }\n\
                     let pi = P { chain_id: 1, };\n\
                     }\n\
                     fn c() {}\n";
    let stripped = strip_test_modules(with_test);
    if stripped.contains("chain_id: 1") {
        return Err(String::from("a test-module literal was not skipped"));
    }
    if !stripped.contains("fn c() {}") {
        return Err(String::from(
            "the brace counter ate code after the test module",
        ));
    }

    Ok(String::from(
        "chain-id gate self-test OK: literal chain_id rejected in four forms; \
         constant, parameter, field, type annotation, prefixed name and \
         test-module literals all pass.",
    ))
}
