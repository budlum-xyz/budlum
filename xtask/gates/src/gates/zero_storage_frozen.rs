//! Generated-content bytes must be pinned to frozen vectors.
//!
//! Ported from `scripts/check-zero-storage-bytes-are-frozen.sh`. The
//! generated-content module must carry a frozen-vector test with, for every
//! `GeneratorId` variant, at least two 64-hex digests and at least two
//! distinct output lengths, so a geometry change and a colour change cannot
//! look alike.

use std::fmt::Write as _;
use std::path::Path;

fn code_of(root: &Path) -> Result<String, String> {
    let f = root.join("src/storage/generated.rs");
    if !f.is_file() {
        return Err(format!(
            "generated-content module missing at {}",
            f.display()
        ));
    }
    std::fs::read_to_string(&f).map_err(|e| e.to_string())
}

fn generator_variants(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let start = code.find("pub enum GeneratorId").unwrap_or(usize::MAX);
    if start == usize::MAX {
        return out;
    }
    let rest = &code[start..];
    let end = rest.find('}').unwrap_or(rest.len());
    for line in rest[..end].lines() {
        let t = line.trim();
        if let Some(name) = t.strip_suffix(',') {
            let name = name.trim();
            if !name.is_empty() && name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// The test whose table this gate reads.
///
/// Named once because the gate looks for it twice - to decide the test exists,
/// and to find where its table starts. Two string literals would let those two
/// searches drift apart, and the second one used to `unwrap` on the assumption
/// the first had already succeeded. Sharing the constant is what actually makes
/// that assumption true.
const FROZEN_TEST_FN: &str = "fn generated_bytes_match_their_frozen_vectors";

/// # Errors
///
/// Returns a finding when a generator is under-pinned or the digests are not
/// 64 hex characters.
pub fn run(root: &Path) -> Result<String, String> {
    let code = code_of(root)?;
    let generators = generator_variants(&code);
    if generators.is_empty() {
        return Err(String::from(
            "could not read any variant from enum GeneratorId",
        ));
    }
    // One search, not two. This used to ask `contains` whether the test was
    // there and then `find` where it was, unwrapping the second on the strength
    // of the first; asking once removes both the duplication and the panic.
    let Some(start) = code.find(FROZEN_TEST_FN) else {
        return Err(String::from(
            "no frozen-vector test: the bytes are pinned to nothing, so a change that \
             alters every generated object would pass CI silently",
        ));
    };
    // The test body from the fn to the first closing brace at depth 1.
    let rest = &code[start..];
    let table_end = rest.find("\n    }").unwrap_or(rest.len());
    let table = &rest[..table_end];

    let hex_re = |s: &str| -> Vec<String> {
        let mut out = Vec::new();
        let mut i = 0;
        let bytes = s.as_bytes();
        while i < bytes.len() {
            if bytes[i] == b'"' {
                let end = s[i + 1..].find('"').map_or(s.len(), |p| i + 1 + p);
                let lit = &s[i + 1..end];
                if lit.chars().all(|c| c.is_ascii_hexdigit()) && lit.len() >= 8 {
                    out.push(lit.to_string());
                }
                i = end + 1;
            } else {
                i += 1;
            }
        }
        out
    };

    let digests = hex_re(table);
    let short: Vec<&String> = digests.iter().filter(|d| d.len() != 64).collect();
    if !short.is_empty() {
        let mut msg = String::from("these frozen digests are not 64 hex characters:\n");
        for d in short {
            writeln!(msg, "  - {d}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    if digests.is_empty() {
        return Err(String::from("the frozen-vector test contains no digests"));
    }

    for g in &generators {
        let needle = format!("GeneratorId::{g},");
        let count = table.matches(&needle).count();
        if count < 2 {
            return Err(format!(
                "generator {g} has {count} frozen vector(s), at least 2 are required \
                 so a geometry change and a colour change cannot look alike"
            ));
        }
        // Distinct output lengths. Each vector tuple is
        // `(GeneratorId::<g>, <seed>, <length>, "<hash>")`; the shell gate
        // took the second numeric literal after each occurrence
        // (`grep -A3 | sed 's/^[0-9]+,$//' | awk 'NR % 2 == 0'`), which is
        // the length. Collect every numeric literal after each occurrence and
        // take the second one.
        let mut lengths: Vec<String> = Vec::new();
        let mut idx = 0;
        while let Some(pos) = table[idx..].find(&needle) {
            let after = &table[idx + pos + needle.len()..];
            let mut nums: Vec<String> = Vec::new();
            let mut i = 0;
            while i < after.len() {
                let c = after.as_bytes()[i];
                if c.is_ascii_digit() {
                    let end = i + after[i..]
                        .find(|ch: char| !ch.is_ascii_digit())
                        .unwrap_or(after.len() - i);
                    nums.push(after[i..end].to_string());
                    i = end;
                } else {
                    i += 1;
                }
                if nums.len() >= 2 {
                    break;
                }
            }
            if let Some(len) = nums.get(1) {
                lengths.push(len.clone());
            }
            idx += pos + needle.len();
        }
        lengths.sort();
        lengths.dedup();
        if lengths.len() < 2 {
            return Err(format!(
                "generator {g} is pinned at only {} distinct output length(s), \
                 at least 2 are required",
                lengths.len()
            ));
        }
    }

    Ok(format!(
        "Zero-storage bytes gate OK: {} generators, each pinned to 2+ digests and 2+ lengths.",
        generators.len()
    ))
}

/// # Errors
///
/// Returns a finding when an under-pinned fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-zero")?;
    let _ = std::fs::create_dir_all(dir.join("src/storage"));

    // Good: two variants, each with 2 vectors in the real tuple layout
    // `(GeneratorId::<g>, <seed>, <length>, "<hash>")`.
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    let c = "c".repeat(64);
    let d = "d".repeat(64);
    let good = format!(
        "pub enum GeneratorId {{\n    Gradient,\n    Plasma,\n}}\nfn generated_bytes_match_their_frozen_vectors() {{\n    let _: &[(GeneratorId, u8, u32, &str)] = &[\n        (\n            GeneratorId::Gradient,\n            7,\n            3072,\n            \"{a}\",\n        ),\n        (\n            GeneratorId::Gradient,\n            1,\n            192,\n            \"{b}\",\n        ),\n        (\n            GeneratorId::Plasma,\n            7,\n            3072,\n            \"{c}\",\n        ),\n        (\n            GeneratorId::Plasma,\n            1,\n            192,\n            \"{d}\",\n        ),\n    ];\n}}\n"
    );
    std::fs::write(dir.join("src/storage/generated.rs"), good).map_err(|e| e.to_string())?;
    let good_ok = run(&dir).is_ok();

    // Bad: only one length per generator.
    let bad = format!(
        "pub enum GeneratorId {{\n    Gradient,\n}}\nfn generated_bytes_match_their_frozen_vectors() {{\n    let _: &[(GeneratorId, u8, u32, &str)] = &[\n        (\n            GeneratorId::Gradient,\n            7,\n            3072,\n            \"{a}\",\n        ),\n        (\n            GeneratorId::Gradient,\n            1,\n            3072,\n            \"{b}\",\n        ),\n    ];\n}}\n"
    );
    std::fs::write(dir.join("src/storage/generated.rs"), bad).map_err(|e| e.to_string())?;
    let bad_fails = run(&dir).is_err();

    let _ = std::fs::remove_dir_all(&dir);

    if !good_ok {
        return Err(String::from("canary: a well frozen module was refused"));
    }
    if !bad_fails {
        return Err(String::from("canary: a single-length pin passed"));
    }
    Ok(String::from(
        "zero-storage canary OK (good PASSes, single-length FAILs).",
    ))
}
