//! Gate: `no-float-in-consensus-paths`.
//!
//! # The failure this closes
//!
//! Consensus has to be reproducible byte for byte on every machine, and IEEE
//! 754 arithmetic is not: `x86_64` is allowed to keep an intermediate through
//! an 80-bit register, `aarch64` rounds at every step, and the rounding mode a
//! process inherits is not part of the protocol. A float that reaches a block
//! makes a node on one architecture accept a block that a node on another
//! rejects - a consensus split with no attacker behind it.
//!
//! The directive (package `ip-42`, item 4) names the surfaces where a float is
//! forbidden outright and asks for this gate:
//!
//! * `src/chain`, `src/consensus`, `src/execution`, `src/settlement`,
//!   `src/validators`, `src/storage/bud3`, `src/ai` (the selection path), and
//!   `budzero`.
//! * `src/storage/bud3` is exempt for its layout tool. The tree has no
//!   `src/storage/bud3` yet, so there is nothing to exempt; when the directory
//!   arrives, the layout tool is pinned below like any other site rather than
//!   named here as a path that does not exist.
//!
//! # What counts
//!
//! Comments and literals are blanked first: a `f64` in prose, in a doc string
//! or in an error message is not arithmetic. The scan then stops at the file's
//! test module - a statistical test may measure a distribution with a float,
//! and nothing it computes reaches a block - and counts the surviving `f32`
//! and `f64` tokens as whole words, so `u64`, `i64` and `my_f64` are not hits
//! while the suffix of `1.0f64` is.
//!
//! # It ratchets instead of starting red
//!
//! Two files carry floats inside `src/ai` today: the display-only trust scores
//! and the registry's selection path. Both are pinned with a ceiling, an owner
//! and a reason. The ceilings only go down, and a ceiling above what the file
//! carries fails the gate so it cannot stay loose; the code that removes them
//! belongs to the AI package, and a gate that is red on arrival teaches the
//! repository to route around it.

use std::fs;
use std::path::{Path, PathBuf};

use super::rust_literals;

/// The directories where a float would make a result non-reproducible.
const SURFACES: &[&str] = &[
    "src/chain",
    "src/consensus",
    "src/execution",
    "src/settlement",
    "src/validators",
    "src/storage/bud3",
    "src/ai",
    "budzero",
];

/// The surfaces that must exist for the gate to mean anything.
///
/// `src/validators` and `src/storage/bud3` are in [`SURFACES`] because the
/// directive names them, but the tree does not have them yet: a surface that
/// is absent is silent, one of these five going absent is a failure.
const REQUIRED: &[&str] = &[
    "src/chain",
    "src/consensus",
    "src/execution",
    "src/settlement",
    "src/ai",
    "budzero",
];

/// Directories inside a surface whose floats cannot reach a block.
const NOT_CONSENSUS: &[&str] = &["benches", "examples", "fuzz", "tests"];

/// The tokens that name a floating-point type.
const TOKENS: &[&str] = &["f32", "f64"];

/// A site that carries floats today, with the ceiling it may not cross.
struct Pinned {
    /// Path from the repository root.
    path: &'static str,
    /// The most float tokens the file may carry.
    ceiling: usize,
    /// The package that removes them (the directive's id, spelled in ASCII so
    /// the tree stays ASCII).
    owner: &'static str,
    /// Why the site exists.
    reason: &'static str,
}

/// The pre-existing sites. A ceiling may go down; a site may leave the table
/// when its last float is gone; nothing may go up or arrive without a pin.
const PINNED: &[Pinned] = &[
    Pinned {
        path: "src/ai/registry.rs",
        ceiling: 4,
        owner: "ip-57",
        reason: "the trust-score ordering, quantised to permyriad before it leaves",
    },
    Pinned {
        path: "src/ai/types.rs",
        ceiling: 10,
        owner: "ip-57",
        reason: "display-only scores: read by a UI, never by a verifier",
    },
];

/// One file's float count.
struct Measured {
    /// Path from the repository root.
    path: String,
    /// Whole float tokens outside the test module.
    count: usize,
}

/// A character that can continue an identifier before a type name.
///
/// A digit is not one: the prefix of `1.0f64` is a number, and the type name
/// that follows it is a real float.
fn joins_prefix(character: char) -> bool {
    character.is_alphabetic() || character == '_'
}

/// A character that can continue a type name. Digits count: `f641` is not a
/// type.
fn joins_suffix(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// Count the whole `f32`/`f64` tokens in the code above the test module.
fn count_floats(source: &str) -> usize {
    let scrubbed = rust_literals::scrub(source);
    let code = scrubbed
        .find("#[cfg(test)]")
        .map_or(scrubbed.as_str(), |cut| &scrubbed[..cut]);
    let characters: Vec<char> = code.chars().collect();
    let mut total = 0usize;
    for token in TOKENS {
        let needle: Vec<char> = token.chars().collect();
        let mut i = 0usize;
        while i + needle.len() <= characters.len() {
            if &characters[i..i + needle.len()] == &needle[..] {
                let before = i.checked_sub(1).map(|index| characters[index]);
                let after = characters.get(i + needle.len()).copied();
                if !before.is_some_and(joins_prefix) && !after.is_some_and(joins_suffix) {
                    total += 1;
                }
                i += needle.len();
            } else {
                i += 1;
            }
        }
    }
    total
}

/// Every `.rs` file inside the surfaces, benches and tests excluded.
fn sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for surface in SURFACES {
        let directory = root.join(surface);
        if directory.is_dir() {
            walk_into(&directory, &mut out);
        }
    }
    out.sort();
    out
}

/// Collect `*.rs` under `directory`, skipping the non-consensus directories.
fn walk_into(directory: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !NOT_CONSENSUS.contains(&name.as_str()) {
                walk_into(&path, out);
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

/// The path of `path` from `root`, with forward slashes.
fn relative(root: &Path, path: &Path) -> Result<String, String> {
    let stripped = path
        .strip_prefix(root)
        .map_err(|_| format!("`{}` is outside the root", path.display()))?;
    Ok(stripped.to_string_lossy().replace('\\', "/"))
}

/// Is `path` inside one of the surfaces?
fn in_a_surface(path: &str) -> bool {
    SURFACES
        .iter()
        .any(|surface| path == *surface || path.starts_with(&format!("{surface}/")))
}

/// Run the gate against the tree at `root`.
///
/// # Errors
///
/// A required surface is missing, a source cannot be read, a surface has no
/// source at all, a file carries a float without a ceiling, a ceiling is
/// crossed, or a ceiling is above what the file carries.
pub fn run(root: &Path) -> Result<String, String> {
    for required in REQUIRED {
        if !root.join(required).is_dir() {
            return Err(format!(
                "`{required}` is missing: the gate would not see its floats",
            ));
        }
    }
    for pin in PINNED {
        if !in_a_surface(pin.path) {
            return Err(format!(
                "`{}` is pinned but lies outside every surface: the pin is dead",
                pin.path,
            ));
        }
    }

    let mut measured: Vec<Measured> = Vec::new();
    let mut scanned = 0usize;
    for path in sources(root) {
        scanned += 1;
        let text = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read `{}`: {error}", path.display()))?;
        let count = count_floats(&text);
        if count == 0 {
            continue;
        }
        measured.push(Measured {
            path: relative(root, &path)?,
            count,
        });
    }
    if scanned == 0 {
        return Err(String::from("no source scanned under the surfaces"));
    }

    let mut failures: Vec<String> = Vec::new();
    for site in &measured {
        match PINNED.iter().find(|pin| pin.path == site.path) {
            Some(pin) if site.count > pin.ceiling => failures.push(format!(
                "`{}` carries {} float token(s), the ceiling is {} ({}: {})",
                site.path, site.count, pin.ceiling, pin.owner, pin.reason,
            )),
            Some(_) => {}
            None => failures.push(format!(
                "`{}` carries {} float token(s) and has no ceiling: consensus arithmetic is exact",
                site.path, site.count,
            )),
        }
    }
    for pin in PINNED {
        let count = measured
            .iter()
            .find(|site| site.path == pin.path)
            .map_or(0, |site| site.count);
        if count < pin.ceiling {
            failures.push(format!(
                "`{}` carries {count} float token(s) and the ceiling says {}: lower the ceiling",
                pin.path, pin.ceiling,
            ));
        }
    }

    if !failures.is_empty() {
        let mut message = String::from("float(s) in a consensus path:\n");
        for failure in &failures {
            message.push_str("  ");
            message.push_str(failure);
            message.push('\n');
        }
        return Err(message);
    }

    let mut pinned = String::new();
    for pin in PINNED {
        pinned.push_str(&format!(
            " {} in `{}` ({})",
            pin.ceiling, pin.path, pin.owner,
        ));
    }
    Ok(format!(
        "No floats in consensus paths: {scanned} sources scanned, {} pinned site(s):{pinned}.",
        PINNED.len(),
    ))
}

/// A body that carries exactly `count` float tokens and no test module.
fn float_body(count: usize) -> String {
    let mut body = String::from("pub struct Scores {\n    pub values: Vec<f64>,\n");
    for index in 1..count {
        body.push_str(&format!("    pub field_{index}: f64,\n"));
    }
    body.push_str("}\n");
    body
}

/// Stage one self-test case: the required surfaces exist, every pinned file
/// carries exactly its ceiling, and the case's own files are written last so a
/// case can override a pinned path.
fn staged(prefix: &str, files: &[(&str, &str)]) -> Result<PathBuf, String> {
    let root = rust_literals::exclusive_scratch_dir(prefix)?;
    for required in REQUIRED {
        fs::create_dir_all(root.join(required))
            .map_err(|error| format!("scratch `{required}`: {error}"))?;
    }
    let mut staged_files: Vec<(String, String)> = PINNED
        .iter()
        .map(|pin| (pin.path.to_string(), float_body(pin.ceiling)))
        .collect();
    for (path, body) in files {
        staged_files.push(((*path).to_string(), (*body).to_string()));
    }
    for (path, body) in staged_files {
        let target = root.join(&path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("scratch `{path}`: {error}"))?;
        }
        fs::write(&target, body).map_err(|error| format!("scratch `{path}`: {error}"))?;
    }
    Ok(root)
}

/// The gate's own canaries.
///
/// # Errors
///
/// A canary does not hold: the clean tree is refused, an injected float passes,
/// a ceiling crosses without a report, a loose ceiling is not reported, a test
/// module is counted, a bench is counted, a file outside the surfaces is
/// counted, or a missing surface is accepted.
pub fn self_test() -> Result<String, String> {
    let clean = staged(
        "float-clean",
        &[("src/consensus/round.rs", "pub fn round(n: u64) -> u64 { n }")],
    )?;
    if let Err(error) = run(&clean) {
        return Err(format!("canary: the clean tree was refused: {error}"));
    }

    let injected = staged(
        "float-injected",
        &[(
            "src/consensus/round.rs",
            "pub fn share(hits: u64, slots: u64) -> f64 { hits as f64 / slots as f64 }",
        )],
    )?;
    match run(&injected) {
        Ok(_) => return Err(String::from("canary: an injected float passed")),
        Err(error) if !error.contains("src/consensus/round.rs") => {
            return Err(format!("canary: the report does not name the file: {error}"))
        }
        Err(_) => {}
    }

    let crossed = staged("float-crossed", &[("src/ai/types.rs", &float_body(11))])?;
    match run(&crossed) {
        Ok(_) => return Err(String::from("canary: a crossed ceiling passed")),
        Err(error) if !error.contains("the ceiling is 10") => {
            return Err(format!("canary: the report does not name the ceiling: {error}"))
        }
        Err(_) => {}
    }

    let loose = staged("float-loose", &[("src/ai/types.rs", &float_body(3))])?;
    match run(&loose) {
        Ok(_) => return Err(String::from("canary: a loose ceiling passed")),
        Err(error) if !error.contains("lower the ceiling") => {
            return Err(format!("canary: the report does not ask for the drop: {error}"))
        }
        Err(_) => {}
    }

    let capped = staged(
        "float-test-module",
        &[(
            "src/chain/probe.rs",
            "pub fn ratio() -> u64 { 0 }\n\n#[cfg(test)]\nmod tests {\n    \
             #[test]\n    fn uniformity() {\n        let share: f64 = 1.0f64 / 4.0;\n    }\n}\n",
        )],
    )?;
    if let Err(error) = run(&capped) {
        return Err(format!("canary: a test module's float was counted: {error}"));
    }

    let benched = staged("float-bench", &[("src/ai/benches/scores.rs", &float_body(7))])?;
    if let Err(error) = run(&benched) {
        return Err(format!("canary: a bench was counted: {error}"));
    }

    let outside = staged("float-outside", &[("src/other/scores.rs", &float_body(7))])?;
    if let Err(error) = run(&outside) {
        return Err(format!("canary: a file outside the surfaces was counted: {error}"));
    }

    let absent = rust_literals::exclusive_scratch_dir("float-absent")?;
    for required in REQUIRED {
        if *required == "src/chain" {
            continue;
        }
        fs::create_dir_all(absent.join(required))
            .map_err(|error| format!("canary scratch `{required}`: {error}"))?;
    }
    match run(&absent) {
        Ok(_) => return Err(String::from("canary: a missing surface was accepted")),
        Err(error) if !error.contains("`src/chain` is missing") => {
            return Err(format!("canary: the report does not name the loss: {error}"))
        }
        Err(_) => {}
    }

    Ok(String::from(
        "Self-test OK: the clean tree passes, an injected float is named, a crossed ceiling \
         and a loose ceiling are reported, a test module and a bench are not counted, a file \
         outside the surfaces is not counted, a missing surface is refused.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_tokens_only() {
        assert_eq!(count_floats("let x = 1.0f64;"), 1);
        assert_eq!(count_floats("let x: u64 = 1; let y: i64 = 2;"), 0);
        assert_eq!(count_floats("let my_f64 = 1;"), 0);
        assert_eq!(count_floats("type Pair = (f32, f32);"), 2);
    }

    #[test]
    fn prose_and_strings_are_not_arithmetic() {
        assert_eq!(count_floats("// the score is an f64 today\nlet x = 1;"), 0);
        assert_eq!(count_floats("let note = \"an f64\";"), 0);
        assert_eq!(count_floats("/* f64 */ let x = 1;"), 0);
    }

    #[test]
    fn a_test_module_is_exempt() {
        let source = "let x: f64 = 1.0;\n#[cfg(test)]\nmod t { fn f() { let y: f64 = 1.0; } }";
        assert_eq!(count_floats(source), 1);
    }

    #[test]
    fn the_float_body_carries_exactly_its_count() {
        assert_eq!(count_floats(&float_body(1)), 1);
        assert_eq!(count_floats(&float_body(11)), 11);
    }

    #[test]
    fn the_pins_lie_inside_the_surfaces() {
        for pin in PINNED {
            assert!(in_a_surface(pin.path), "{} is outside the surfaces", pin.path);
        }
    }

    #[test]
    fn the_pins_have_owners_and_reasons() {
        for pin in PINNED {
            assert!(!pin.owner.is_empty(), "{} has no owner", pin.path);
            assert!(!pin.reason.is_empty(), "{} has no reason", pin.path);
        }
    }
}
