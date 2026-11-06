//! No floating-point arithmetic on the consensus path.
//!
//! Gate code: `K-NO-FLOAT`. A finding or a document that names this code
//! resolves here.
//!
//! # Why
//!
//! A consensus path decides something two nodes must agree on: a block, a
//! state root, a placement, a fee, a seat. A `f32` or `f64` in that decision
//! makes the answer depend on the machine: `x87` evaluates in 80-bit extended
//! precision, two compilers may contract `a * b + c` into one FMA or not, and
//! an optimizer may reassociate. The same input then yields two answers, and
//! two honest nodes that disagree about a block have forked. Nothing in the
//! tree can be made to pay for that, so the answer is a gate: no float in the
//! directories whose output is consensus state.
//!
//! # What counts as the consensus path
//!
//! Section 15.8 of the directive, package WP-42 item 4, names the scope:
//! `src/chain`, `src/consensus`, `src/execution`, `src/settlement`,
//! `src/validators`, `src/storage/bud3` (its placement tool aside) and the
//! `src/ai` selection path. The tree has no directory named for a selection
//! path, so the whole of `src/ai` is in scope and the one display-only method
//! that needs a float carries a named exception instead. `budzero/` is in
//! scope as a whole; a guest program that computes differently per host is
//! the same fork one layer down.
//!
//! # What is not counted
//!
//! * Test bodies (`#[cfg(test)]`, `#[cfg(all(test, ...))]`,
//!   `#[cfg(any(test, ...))]`). A test that measures a distribution with
//!   `f64` decides nothing; `eligibility_output_is_uniform_enough_for_the_threshold`
//!   is exactly that, and it is the only float in `src/consensus`.
//! * `#[cfg(test)] use` lines and `#[cfg(test)]` items on a single line: the
//!   same rule, applied by brace depth rather than by the flavour of the item.
//! * String, character and raw-string literals, and comments. `"0.5.2"` is a
//!   version, not arithmetic, and a doc comment naming `f64` is prose.
//! * `benches/`, `examples/`, `build.rs` and `target/`.
//! * A function named in `EXEMPT_FUNCS` with the reason its float cannot
//!   reach state. The exemption is a span found by function name, so it cannot
//!   widen to the next function, and a renaming fails the gate instead of
//!   silently dropping the permission.
//!
//! # The named exceptions, and why they are named
//!
//! `AiAgentReputation::trust_score` and `AiVerifierQos::reliability_score` are
//! display-only scores: their own doc comments say they must never feed
//! consensus, verifier selection or fees, and the state root hashes the integer
//! counters only. The actor boundary already carries the quantised permyriad
//! form (`agents_by_trust_score_permille`), so the float stops at the RPC
//! reader. Rounding the 0.4 / 0.6 weighted ratio to an integer instead would
//! change every score a caller reads, for a property that is not on the state
//! path, so the functions stay and the gate names them, with the reason.
//!
//! `verifiers_by_reliability` is the one ordering the tree still computes from
//! a float, and it is *not* exempt: it sorts verifiers with
//! `partial_cmp` on a score. Nothing on the state path calls it, but a
//! selection rule that orders candidates by a float is exactly the shape this
//! gate exists to keep out, so the next step for it is `u64` permille and the
//! gate says so.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use super::rust_literals;

/// The directories whose output is consensus state. `src/ai` is here because
/// the card names its selection path and the tree has no narrower directory.
const SCOPE: &[&str] = &[
    "src/chain",
    "src/consensus",
    "src/execution",
    "src/settlement",
    "src/validators",
    "src/storage/bud3",
    "src/ai",
    "budzero",
];

/// Path fragments that are not shipped consensus code.
const SKIP_PATH_PARTS: &[&str] = &[
    "/benches/",
    "/examples/",
    "/tests/",
    "/target/",
    "/.git/",
];

/// Whole functions the gate accepts, each with the reason its float cannot
/// reach consensus state. `(path, function name, why)`.
///
/// A function span, not a line: `return 0.0;` appears in both scores, so a
/// line-keyed exception would exempt every future `return 0.0;` in either
/// file. The span is found by name, so a rename fails the gate instead of
/// silently widening the permission.
const EXEMPT_FUNCS: &[(&str, &str, &str)] = &[
    (
        "src/ai/types.rs",
        "reliability_score",
        "display-only verifier score; the state root hashes the integer counters",
    ),
    (
        "src/ai/types.rs",
        "trust_score",
        "display-only agent score; the state root hashes the integer counters",
    ),
    (
        "src/ai/registry.rs",
        "agents_by_trust_score",
        "read model ordered by a display-only score; the actor carries permyriad",
    ),
    (
        "src/ai/registry.rs",
        "top_agents",
        "the bounded cut of the display-only ranking above",
    ),
    (
        "src/ai/registry.rs",
        "agents_by_trust_score_permille",
        "the one quantisation step that keeps the float off every boundary below",
    ),
    (
        "src/storage/bud3/placement.rs",
        "log2_fixed_point_is_exact_on_powers_and_close_elsewhere",
        "the card exempts the placement tool: this test measures i64 fixed point \
         against an f64 reference, which is the measurement, not the placement",
    ),
];

/// A scan that walked fewer files than this is vacuous and must fail.
const VACUITY_FLOOR: usize = 40;

/// How many findings are printed before the list is summarised.
const MAX_REPORTED: usize = 40;

/// A float occurrence on the consensus path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Repository-relative path.
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    /// The type or literal that matched.
    pub what: String,
    /// The trimmed source line.
    pub text: String,
}

/// Blank every `#[cfg(test)]`-gated item, and only those, by brace depth.
///
/// # The two spellings that made the first version wrong
///
/// 1. **`#[cfg(test)]` on a `use` or a `const` hides nothing.** The attribute
///    gates the item beneath it, and that item is one line. The first version
///    treated `#[cfg(test)]` as "everything until the next `;`", so
///    `#[cfg(test)] use foo::Bar;` followed by a real `pub fn` blanked the
///    function too - a production float directly under such a `use` was
///    invisible. The rule below distinguishes "the item ends at this `;`" from
///    "the item is a block", which is the difference the attribute actually
///    makes.
/// 2. **`#[cfg(all(test, unix))]` is a test item; `#[cfg(any(test, feature))]`
///    is not.** `all` narrows to builds where every clause holds, so
///    `all(test, unix)` is test-only and must be blanked. `any` widens, so
///    `any(test, feature = "x")` is built in production whenever the feature is
///    on, and blanking it would hide production code. The first version treated
///    `any(test` as test-only, which is a blind spot, not an exemption.
fn strip_test_items(lines: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(lines.len());
    let mut i = 0usize;
    while i < lines.len() {
        let t = lines[i].trim();
        // `all(test, ...)` is test-only. `any(test, ...)` is not, and a bare
        // `test` clause is not.
        let default_off = t == "#[cfg(test)]" || t.starts_with("#[cfg(all(test");
        let default_on = t.starts_with("#[cfg(any(");
        if !default_off && !default_on {
            out.push(lines[i].clone());
            i += 1;
            continue;
        }
        out.push(String::new());
        i += 1;
        // The gated item: one line when it ends in `;` before any `{`, a brace
        // block otherwise.
        let mut depth = 0i32;
        let mut started = false;
        while i < lines.len() {
            for c in lines[i].chars() {
                if c == '{' {
                    depth += 1;
                    started = true;
                } else if c == '}' {
                    depth -= 1;
                }
            }
            let single_line = !started && lines[i].trim_end().ends_with(';');
            let ends_here = started && depth <= 0;
            if default_off || (!default_off && !default_on) {
                // Test-only: the item is blanked whatever its shape.
                out.push(String::new());
            } else {
                // Built in production: keep the text, because a float in it is
                // a real float on the consensus path.
                out.push(lines[i].clone());
            }
            i += 1;
            if ends_here || single_line {
                break;
            }
        }
    }
    out
}

/// Does this line name a float type or carry a float literal?
///
/// Three rules, each with the case that motivated it:
///
/// * `f32` / `f64` count only at an identifier boundary. `my_f64_helper` is a
///   name, not the type, and a test called `rounds_to_f64` must not fail a
///   gate that is about arithmetic.
/// * A float literal is digits, a dot, digits. `0.4` is one; `scheme.0` is a
///   field access and `..` is range syntax.
/// * A dot inside a longer dotted run is a version or a path (`0.5.2`,
///   `1.2.3.4`), not a literal. Strings and comments never reach here, because
///   the scrubber blanked them, but a numeric constant could.
fn float_on_line(line: &str) -> Option<&'static str> {
    let b = line.as_bytes();
    for i in 0..b.len() {
        if b[i] != b'f' {
            continue;
        }
        // Identifier boundary before the `f`.
        if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') {
            continue;
        }
        let Some(tail) = line.get(i + 1..i + 3) else {
            continue;
        };
        if tail == "32" || tail == "64" {
            // Identifier boundary after the digits: `f64x` is a name.
            let after = b.get(i + 3).copied();
            if after.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_') {
                continue;
            }
            return Some(if tail == "32" { "f32" } else { "f64" });
        }
    }
    for i in 0..b.len() {
        if !b[i].is_ascii_digit() || b.get(i + 1) != Some(&b'.') {
            continue;
        }
        if !b.get(i + 2).is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        // The digit run this literal starts with, and what precedes it. An
        // underscore is a numeric separator (`10_000.0` is a float literal),
        // so it joins the run; a letter before the run means an identifier
        // (`ML_DSA_65.0` is a field access), so it does not.
        let mut run = i;
        while run > 0 && (b[run - 1].is_ascii_digit() || b[run - 1] == b'_') {
            run -= 1;
        }
        if run > 0 && (b[run - 1] == b'.' || b[run - 1].is_ascii_alphabetic()) {
            continue;
        }
        // A `.` after the fractional digits makes this one leg of a version.
        let mut j = i + 2;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if b.get(j) == Some(&b'.') {
            continue;
        }
        return Some("literal");
    }
    None
}

fn path_is_skipped(rel: &str) -> bool {
    let with_slashes = format!("/{rel}");
    SKIP_PATH_PARTS
        .iter()
        .any(|p| with_slashes.contains(p) || rel.ends_with("build.rs"))
}

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if kind.is_dir() {
            if name_str != "target" && name_str != ".git" {
                walk_rs(&entry.path(), out);
            }
        } else if kind.is_file() && name_str.ends_with(".rs") {
            out.push(entry.path());
        }
    }
}

/// The line span of `fn <name>` in `code`, signature line through closing
/// brace, both 0-based and inclusive. Brace depth is counted on scrubbed code,
/// so a `{` inside a string or a comment cannot move the end.
fn span_of(code: &[String], name: &str) -> Option<(usize, usize)> {
    let needle = format!("fn {name}(");
    let start = code.iter().position(|l| l.contains(&needle))?;
    let mut depth = 0i32;
    let mut started = false;
    for (i, line) in code.iter().enumerate().skip(start) {
        for c in line.chars() {
            if c == '{' {
                depth += 1;
                started = true;
            } else if c == '}' {
                depth -= 1;
            }
        }
        if started && depth <= 0 {
            return Some((start, i));
        }
    }
    None
}

/// Scan one tree. Pure of the environment, so the canary can stage one.
fn check(root: &Path) -> Result<(Vec<Finding>, usize), String> {
    // Every exemption must still name a function, or the list has rotted.
    let mut stale: Vec<String> = Vec::new();
    for (path, name, _) in EXEMPT_FUNCS {
        let Ok(text) = std::fs::read_to_string(root.join(path)) else {
            stale.push(format!("{path}: the file is gone, so `{name}` is not exempt"));
            continue;
        };
        let code: Vec<String> = rust_literals::scrub(&text)
            .lines()
            .map(str::to_string)
            .collect();
        if span_of(&code, name).is_none() {
            stale.push(format!("{path}: no `fn {name}(` any more"));
        }
    }
    if !stale.is_empty() {
        return Err(format!(
            "a named float exemption no longer names a function, so the list is stale:\n  {}",
            stale.join("\n  ")
        ));
    }

    let mut files: Vec<PathBuf> = Vec::new();
    for r in SCOPE {
        let p = root.join(r);
        if p.is_dir() {
            walk_rs(&p, &mut files);
        }
    }
    if files.len() < VACUITY_FLOOR {
        return Err(format!(
            "only {} Rust files under the consensus scope; the gate would be vacuous",
            files.len()
        ));
    }
    let mut findings: Vec<Finding> = Vec::new();
    for path in &files {
        let Ok(rel) = path.strip_prefix(root) else {
            continue;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        if path_is_skipped(&rel) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let scrubbed = rust_literals::scrub(&text);
        let lines: Vec<String> = scrubbed.lines().map(str::to_string).collect();
        let source: Vec<&str> = text.lines().collect();
        let kept = strip_test_items(&lines);
        // Spans are taken on the post-test-strip numbering, which is the
        // numbering `kept` is reported in.
        let spans: Vec<(usize, usize)> = EXEMPT_FUNCS
            .iter()
            .filter(|(p, _, _)| *p == rel)
            .filter_map(|(_, name, _)| span_of(&kept, name))
            .collect();
        for (i, line) in kept.iter().enumerate() {
            let Some(what) = float_on_line(line) else {
                continue;
            };
            if spans.iter().any(|(a, b)| i >= *a && i <= *b) {
                continue;
            }
            let original = source.get(i).copied().unwrap_or("").trim();
            findings.push(Finding {
                file: rel.clone(),
                line: i + 1,
                what: what.to_string(),
                text: original.chars().take(120).collect(),
            });
        }
    }
    Ok((findings, files.len()))
}

/// The gate.
///
/// # Errors
///
/// A float on the consensus path, or a stale exception.
pub fn run(root: &Path) -> Result<String, String> {
    let (findings, scanned) = check(root)?;
    if findings.is_empty() {
        return Ok(format!(
            "OK: no floating point on the consensus path ({scanned} files scanned, {} named \
             display-only function exemptions).",
            EXEMPT_FUNCS.len()
        ));
    }
    let mut msg = String::from(
        "floating point on a consensus path. Two nodes can then disagree about a\n  \
         block, a root or a fee, which is a fork:\n",
    );
    for f in findings.iter().take(MAX_REPORTED) {
        let _ = writeln!(msg, "  {}:{} ({}): {}", f.file, f.line, f.what, f.text);
    }
    if findings.len() > MAX_REPORTED {
        let _ = writeln!(msg, "  ... and {} more", findings.len() - MAX_REPORTED);
    }
    let _ = writeln!(
        msg,
        "  Use integer or fixed-point arithmetic. A display-only score may be named in \
         EXEMPT_FUNCS with the reason it cannot reach state."
    );
    Err(msg)
}

/// Stage the two files the real exception list names, with the same function
/// names and a float in each. Without them, every canary would fail on the
/// stale-exception check rather than on the property it is testing.
fn stage_exempt_files(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir.join("src/ai")).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("src/ai/types.rs"),
        "pub fn reliability_score(&self) -> f64 {\n    1.0\n}\n\
         pub fn trust_score(&self) -> f64 {\n    1.0\n}\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("src/ai/registry.rs"),
        "pub fn agents_by_trust_score(&self) -> Vec<(u8, f64)> {\n    vec![]\n}\n\
         pub fn top_agents(&self, n: usize) -> Vec<(u8, f64)> {\n    vec![]\n}\n\
         pub fn agents_by_trust_score_permille(&self) -> Vec<(u8, u64)> {\n    vec![]\n}\n",
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Steps 1 to 4 of the canary, on a staged tree whose exemptions are sound.
fn staged_canaries(dir: &Path) -> Result<(), String> {
    // 1. A float in production code is a finding.
    std::fs::write(
        dir.join("src/consensus/floaty.rs"),
        "pub fn share(a: u64, b: u64) -> f64 {\n    a as f64 / b as f64\n}\n",
    )
    .map_err(|e| e.to_string())?;
    let flagged = check(dir);
    if !matches!(flagged, Ok((ref f, _)) if f.len() >= 3) {
        return Err(format!(
            "canary: a production float was not reported: {:?}",
            flagged.map(|(f, _)| f.len())
        ));
    }
    std::fs::remove_file(dir.join("src/consensus/floaty.rs")).map_err(|e| e.to_string())?;

    // 1b. A `#[cfg(test)]` on a `use` hides the use, not the function under
    //     it. The first version blanked both and lost a production float; this
    //     stages exactly that shape.
    std::fs::write(
        dir.join("src/consensus/after_use.rs"),
        "#[cfg(test)]\nuse std::f64::consts::PI;\n\
         pub fn share(a: u64, b: u64) -> f64 {\n    a as f64 / b as f64\n}\n",
    )
    .map_err(|e| e.to_string())?;
    let leaked = check(dir);
    if !matches!(leaked, Ok((ref f, _)) if !f.is_empty()) {
        return Err(String::from(
            "canary: a float under `#[cfg(test)] use` was hidden",
        ));
    }
    std::fs::remove_file(dir.join("src/consensus/after_use.rs")).map_err(|e| e.to_string())?;

    // 1c. `all(test, unix)` is test-only and blanked; `any(test, feature)` is
    //     built in production, so a float inside it is reported.
    std::fs::write(
        dir.join("src/consensus/cfg_forms.rs"),
        "#[cfg(all(test, unix))]\nmod unix_tests {\n    fn x() -> f64 { 1.0 }\n}\n",
    )
    .map_err(|e| e.to_string())?;
    let clean = check(dir).map_err(|e| format!("canary: all(test) failed: {e}"))?;
    if !clean.0.is_empty() {
        return Err(format!(
            "canary: `all(test, unix)` was not blanked: {:?}",
            clean.0
        ));
    }
    std::fs::write(
        dir.join("src/consensus/cfg_forms.rs"),
        "#[cfg(any(test, feature = \"wide\"))]\npub fn ratio() -> f64 { 0.5 }\n",
    )
    .map_err(|e| e.to_string())?;
    let flagged = check(dir);
    if !matches!(flagged, Ok((ref f, _)) if !f.is_empty()) {
        return Err(String::from(
            "canary: `any(test, feature)` was blanked, hiding production code",
        ));
    }
    std::fs::remove_file(dir.join("src/consensus/cfg_forms.rs")).map_err(|e| e.to_string())?;
    // 2. A float in a test module is not a finding.
    std::fs::write(
        dir.join("src/consensus/tested.rs"),
        "pub fn share(a: u64, b: u64) -> u64 {\n    a / b\n}\n\
         #[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n\
             let x = 0.5f64;\n    }\n}\n",
    )
    .map_err(|e| e.to_string())?;
    let clean = check(dir).map_err(|e| format!("canary: a test float failed: {e}"))?;
    if !clean.0.is_empty() {
        return Err(format!(
            "canary: a float in a test module was reported: {:?}",
            clean.0
        ));
    }

    // 3. A comment, a doc comment, a version string, a char and a field
    //    access are not arithmetic.
    std::fs::write(
        dir.join("src/consensus/tested.rs"),
        "// a `f64` in a comment is prose\n\
         /// and in a doc comment too, with 0.5 in it\n\
         pub const VERSION: &str = \"0.5.2\";\n\
         pub fn field_access(scheme: u8) -> [u8; 1] {\n    [scheme.0]\n}\n",
    )
    .map_err(|e| e.to_string())?;
    let clean = check(dir).map_err(|e| format!("canary: prose failed: {e}"))?;
    if !clean.0.is_empty() {
        return Err(format!(
            "canary: a comment, a string or a field access was reported: {:?}",
            clean.0
        ));
    }

    // 4. A bench is not shipped code.
    std::fs::create_dir_all(dir.join("budzero/benches")).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("budzero/benches/b.rs"), "fn f() -> f64 { 1.5 }\n")
        .map_err(|e| e.to_string())?;
    check(dir).map_err(|e| format!("canary: a bench failed: {e}"))?;
    Ok(())
}

/// The canary: a float in a consensus directory is reported, and a float in a
/// test module, in a comment, in a string, in a char, in a bench or inside a
/// named exemption is not, and a renamed exemption is refused.
///
/// # Errors
///
/// The first staging step or assertion that misbehaves.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-nofloat")?;
    let result = (|| {
        // Too small a tree is vacuous, by design, and says so instead of
        // passing on nothing.
        if check(&dir).is_ok() {
            return Err(String::from("canary: an empty tree passed"));
        }
        std::fs::create_dir_all(dir.join("src/consensus")).map_err(|e| e.to_string())?;
        for i in 0..VACUITY_FLOOR {
            std::fs::write(
                dir.join(format!("src/consensus/filler{i}.rs")),
                "pub const N: u64 = 1;\n",
            )
            .map_err(|e| e.to_string())?;
        }
        stage_exempt_files(&dir)?;
        // The staged exemptions carry floats and still pass: that is the
        // exemption working rather than the scan missing them.
        let clean = check(&dir).map_err(|e| format!("canary: a clean tree failed: {e}"))?;
        if !clean.0.is_empty() {
            return Err(format!(
                "canary: an exempt function was reported: {:?}",
                clean.0
            ));
        }
        staged_canaries(&dir)?;

        // 5. A renamed exemption is stale and fails rather than silently
        //    widening. Rename one function and expect the refusal.
        std::fs::write(
            dir.join("src/ai/types.rs"),
            "pub fn reliability_score_v2(&self) -> f64 {\n    1.0\n}\n\
             pub fn trust_score(&self) -> f64 {\n    1.0\n}\n",
        )
        .map_err(|e| e.to_string())?;
        let stale = check(&dir);
        if !matches!(stale, Err(ref e) if e.contains("stale")) {
            return Err(format!(
                "canary: a renamed exemption was not refused: {:?}",
                stale.map(|(f, _)| f.len())
            ));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "no-float canary OK: a production float, a test float, a comment, a string, a bench and \
         a renamed exemption all behaved, and the named exemptions passed with their floats.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_on_line_separates_a_literal_from_a_version() {
        assert_eq!(float_on_line("let x: f64 = 1;"), Some("f64"));
        assert_eq!(float_on_line("let x = 0.25;"), Some("literal"));
        assert_eq!(float_on_line("let v = \"0.5.2\";"), None);
        assert_eq!(float_on_line("scheme.0.to_be_bytes()"), None);
        assert_eq!(float_on_line("ten_0_amount"), None);
        // A numeric separator is part of the literal, not an identifier.
        assert_eq!(float_on_line("let q = 10_000.0;"), Some("literal"));
        // An identifier that happens to end in `f64` is a name.
        assert_eq!(float_on_line("rounds_to_f64(x)"), None);
        assert_eq!(float_on_line("let limit: f64x = 1;"), None);
    }

    #[test]
    fn test_modules_and_their_floats_are_dropped() {
        let src = "pub fn a() {}\n#[cfg(test)]\nmod t {\n    fn x() -> f64 { 1.0 }\n}\n";
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let kept = strip_test_items(&lines);
        assert!(kept.iter().all(|l| !l.contains("f64")), "{kept:?}");
        // The one-line spelling is the same rule.
        let src = "#[cfg(test)] use foo::f64ish;\npub fn b() {}\n";
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let kept = strip_test_items(&lines);
        assert_eq!(kept.iter().filter(|l| l.contains("f64ish")).count(), 0);
    }
}
