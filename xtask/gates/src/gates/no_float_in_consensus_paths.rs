//! No floating point on a path that decides what a block is.
//!
//! # The failure this closes
//!
//! `f64` is not a consensus type. The same expression can give two answers on
//! two machines, and it can give two answers on the same machine after a
//! rebuild: the CPU is allowed to keep an intermediate value in a wider
//! register, so `a * b + c` is one rounding on one target and two on another.
//! A node that computes a share, a score or a placement weight this way and a
//! node that computes it another way disagree about the state root, and the
//! disagreement looks like a fork.
//!
//! The repository already says this in words: `G-2` in the directive and the
//! `Z8` rule beside `AiVerifierQos::reliability_score`. Words do not fail a
//! build. This gate does.
//!
//! # Scope
//!
//! The paths the work package names, which are the ones whose output reaches a
//! block, a receipt or a committee seat:
//!
//!   * `src/chain`, `src/consensus`, `src/validators`, `src/execution`,
//!     `src/settlement`, `src/storage/bud3`
//!   * the AI selection path, `src/ai`
//!   * the `budzero/` workspaces
//!
//! Two kinds of file are outside the ban because they are not the consensus
//! path even when they sit inside one of its directories:
//!
//!   * the placement tool, `src/storage/bud3/placement.rs`, which the work
//!     package card names as the one exception: its arithmetic is checked
//!     against a hand computed value in a test, and the test needs the float
//!     to do the checking.
//!   * measurement harnesses (`tests/`, `benches/`, `examples/`) and
//!     `#[cfg(test)]` modules. A timing average is a float by definition and
//!     never reaches a block.
//!
//! The rule for the `#[cfg(test)]` exemption is the narrow one: the attribute
//! must be followed by `mod`, and only that module's braces are blanked. A
//! `#[cfg(test)]` on a `use` or a `const` does not hide the item after it,
//! which a coarser reader did: it skipped forward to the next `mod` in the file
//! and blanked whatever stood between, which is how a gate can report that it
//! examined a file it never read.
//!
//! # The pinned exception, and why it is not a relaxation
//!
//! `BLG-240` records that verifier ranking is done in `f64` and is display
//! only. Closing it is a change to the ranking API and belongs to the AI
//! boundary package (`WP-45`), not to this one. Rather than either pretend the
//! file is clean or leave the gate red for a finding another package owns, the
//! two files are pinned by name here.
//!
//! A pin is a ceiling, not a permit:
//!
//!   * the occurrence count may not rise above the pin. A new float in a
//!     pinned file fails exactly like a new float anywhere else.
//!   * a pin whose file has no float left is stale, and a stale pin fails. The
//!     message names the finding and the package that owns it, so closing
//!     `BLG-240` cannot leave this gate quietly exempting a clean file.
//!
//! There is no writer for the pin table and no baseline file to regenerate: a
//! pin is deleted by hand, in the pull request that removes the float, and the
//! self-test refuses a pin with no finding behind it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The production paths the work package puts inside the float ban.
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

/// Directory names that hold a measurement harness rather than consensus work.
const HARNESS_DIRS: &[&str] = &["tests", "benches", "examples", "target", "fuzz", "kani"];

/// Files the work package card exempts by name.
const EXEMPT_FILES: &[&str] = &["src/storage/bud3/placement.rs"];

/// A float the repository still owes, with the finding that records it.
struct Pin {
    /// Repository relative path.
    path: &'static str,
    /// Ceiling for `f32`/`f64` occurrences in the file's whole text.
    max_occurrences: usize,
    /// The finding that must close before the pin can be deleted.
    finding: &'static str,
    /// The package that closes it.
    owner: &'static str,
}

/// The pinned files, each tied to an open finding.
///
/// Both entries are `BLG-240`: verifier and agent ranking is computed in
/// `f64`. The code says so at the definition (`Display only (Z8)`), and the
/// integer form (`agents_by_trust_score_permille`) already exists for the
/// boundary that needs it. What is missing is the API change, which is
/// `WP-45`'s.
const PINS: &[Pin] = &[
    Pin {
        path: "src/ai/registry.rs",
        max_occurrences: 5,
        finding: "BLG-240",
        owner: "WP-45",
    },
    Pin {
        path: "src/ai/types.rs",
        max_occurrences: 12,
        finding: "BLG-240",
        owner: "WP-45",
    },
];

/// Is this byte part of an identifier or a number?
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Blank comments and string literals, keeping every byte offset and every
/// newline in place.
///
/// Offsets are preserved so a finding can still name the line it came from, and
/// newlines are preserved so the line number is the file's own. Bytes inside a
/// comment or a literal become spaces, which is what stops a hex constant that
/// happens to contain `f64` from being read as a float.
fn blank_noise(src: &str) -> Vec<u8> {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if c == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                out[i] = b' ';
                i += 1;
            }
            continue;
        }
        if c == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            out[i] = b' ';
            out[i + 1] = b' ';
            i += 2;
            while i < b.len() {
                if b[i] == b'*' && i + 1 < b.len() && b[i + 1] == b'/' {
                    out[i] = b' ';
                    out[i + 1] = b' ';
                    i += 2;
                    break;
                }
                if b[i] != b'\n' {
                    out[i] = b' ';
                }
                i += 1;
            }
            continue;
        }
        if c == b'"' {
            // A raw string opens with `r` and any number of `#`s before the
            // quote. The hashes matter: `r#"a "quoted" b"#` ends at the only
            // `"#`, so the inner quote is content.
            let mut hashes = 0usize;
            let mut k = i;
            while k > 0 && b[k - 1] == b'#' {
                hashes += 1;
                k -= 1;
            }
            let raw = k > 0 && b[k - 1] == b'r' && (k < 2 || !is_ident_byte(b[k - 2]));
            if raw {
                for j in k..i {
                    out[j] = b' ';
                }
                out[i] = b' ';
                let mut j = i + 1;
                while j < b.len() {
                    if b[j] == b'"' && j + hashes < b.len() {
                        let mut closes = true;
                        for h in 1..=hashes {
                            if b[j + h] != b'#' {
                                closes = false;
                                break;
                            }
                        }
                        if closes {
                            for h in 0..=hashes {
                                out[j + h] = b' ';
                            }
                            j += hashes + 1;
                            break;
                        }
                    }
                    if b[j] != b'\n' {
                        out[j] = b' ';
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
            out[i] = b' ';
            let mut j = i + 1;
            while j < b.len() {
                if b[j] == b'\\' {
                    out[j] = b' ';
                    if j + 1 < b.len() {
                        if b[j + 1] != b'\n' {
                            out[j + 1] = b' ';
                        }
                    }
                    j += 2;
                    continue;
                }
                if b[j] == b'"' {
                    out[j] = b' ';
                    j += 1;
                    break;
                }
                if b[j] != b'\n' {
                    out[j] = b' ';
                }
                j += 1;
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

/// Does this line open a `#[cfg(test)]` module?
fn opens_test_module(line: &str) -> bool {
    line.trim() == "#[cfg(test)]"
}

/// Does this line start a module item?
fn is_module_item(line: &str) -> bool {
    let t = line.trim();
    let t = t
        .strip_prefix("pub(crate) ")
        .or_else(|| t.strip_prefix("pub(super) "))
        .or_else(|| t.strip_prefix("pub "))
        .unwrap_or(t);
    t.starts_with("mod ") || t.starts_with("mod\t")
}

/// Blank every `#[cfg(test)]` module, and nothing else.
///
/// The input must already have its comments and literals blanked: the brace
/// walk below counts braces, and a `{` inside a string would end a module early
/// or late.
fn strip_test_modules(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut out: Vec<&str> = Vec::with_capacity(lines.len());
    let mut i = 0usize;
    while i < lines.len() {
        if opens_test_module(lines[i]) {
            // The attribute may be followed by other attributes, blank lines
            // or comments before the `mod` keyword.
            let mut j = i + 1;
            while j < lines.len() {
                let t = lines[j].trim();
                if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
                    j += 1;
                    continue;
                }
                break;
            }
            if j < lines.len() && is_module_item(lines[j]) {
                let mut depth: i64 = 0;
                let mut opened = false;
                let mut k = j;
                while k < lines.len() {
                    for byte in lines[k].bytes() {
                        if byte == b'{' {
                            depth += 1;
                            opened = true;
                        } else if byte == b'}' {
                            depth -= 1;
                        }
                    }
                    k += 1;
                    if opened && depth <= 0 {
                        break;
                    }
                }
                for _ in i..k {
                    out.push("");
                }
                i = k;
                continue;
            }
            // A `#[cfg(test)]` on a `use` or a single item hides nothing.
        }
        out.push(lines[i]);
        i += 1;
    }
    out.join("\n")
}

/// Every `f64`/`f32` in a source text, as `(line, whole line)`.
///
/// The token rule is not a substring search. `f64` counts when it stands as a
/// type or a literal suffix:
///
///   * `-> f64`, `f64::MAX`, `as f64`, `1.0f64` count.
///   * `AsF64`, `my_f64_score` do not: a letter or `_` before the token makes
///     it part of a longer name.
///   * `0x6bf64a07` does not: a digit before the token is read back through the
///     number, and a number that starts `0x`, `0b` or `0o` is not a float
///     literal. A number that starts with a decimal digit is one, so `1f64`
///     still counts.
fn floats_in(src: &str) -> Vec<(usize, String)> {
    let b = src.as_bytes();
    let mut found = Vec::new();
    let mut line = 1usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        let is_float_token = b[i] == b'f'
            && i + 2 < b.len()
            && (b[i + 1] == b'6' || b[i + 1] == b'3')
            && (b[i + 2] == b'4' || b[i + 2] == b'2');
        if !is_float_token {
            i += 1;
            continue;
        }
        let mut skip = i + 3 < b.len() && is_ident_byte(b[i + 3]);
        if !skip && i > 0 {
            let prev = b[i - 1];
            if prev.is_ascii_alphabetic() || prev == b'_' {
                skip = true;
            } else if prev.is_ascii_digit() {
                // Read the whole number back. A radix prefix means this is not
                // a float literal; anything else means the token is a suffix.
                let mut j = i;
                while j > 0 && (b[j - 1].is_ascii_hexdigit() || b[j - 1] == b'_') {
                    j -= 1;
                }
                let radix = j >= 2
                    && (b[j - 1] == b'x'
                        || b[j - 1] == b'X'
                        || b[j - 1] == b'b'
                        || b[j - 1] == b'B'
                        || b[j - 1] == b'o'
                        || b[j - 1] == b'O')
                    && b[j - 2] == b'0';
                if radix {
                    skip = true;
                }
            }
        }
        if !skip {
            let start = src[..i].rfind('\n').map_or(0, |p| p + 1);
            let end = src[i..].find('\n').map_or(src.len(), |p| i + p);
            found.push((line, src[start..end].trim().to_string()));
        }
        i += 3;
    }
    found
}

/// A source text with its comments, literals and test modules removed.
fn readable_source(src: &str) -> String {
    let blanked = blank_noise(src);
    let text = String::from_utf8_lossy(&blanked).into_owned();
    strip_test_modules(&text)
}

/// Every `.rs` file under `dir`, skipping measurement harnesses.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if path.is_dir() {
            if HARNESS_DIRS.contains(&name.as_str()) {
                continue;
            }
            rust_files(&path, out);
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

/// The repository relative form of `path`, with `/` separators.
fn relative(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<String>>()
        .join("/")
}

/// Run the gate.
///
/// # Errors
///
/// A float outside the pins, a pinned file that grew, a stale pin, or a scope
/// path that is not in the tree.
pub fn run(root: &Path) -> Result<String, String> {
    let mut findings: Vec<String> = Vec::new();

    // Pins are ceilings, so the file's scan is bounded by them and a growth in
    // either production or test code fails.
    let mut pinned_seen: Vec<Option<(usize, Vec<(usize, String)>)>> = PINS.iter().map(|_| None).collect();

    let mut files_scanned = 0usize;
    let mut scope_missing: Vec<&str> = Vec::new();

    for scope in SCOPE {
        let dir = root.join(*scope);
        if !dir.is_dir() {
            scope_missing.push(*scope);
            continue;
        }
        let mut files = Vec::new();
        rust_files(&dir, &mut files);
        for file in files {
            let rel = relative(root, &file);
            if EXEMPT_FILES.contains(&rel.as_str()) {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&file) else {
                findings.push(format!("{rel}: unreadable"));
                continue;
            };
            files_scanned += 1;
            let text = readable_source(&src);
            let floats = floats_in(&text);
            if let Some(index) = PINS.iter().position(|p| p.path == rel.as_str()) {
                pinned_seen[index] = Some((floats.len(), floats));
                continue;
            }
            for (line, body) in floats {
                findings.push(format!(
                    "{rel}:{line}: floating point outside the pins: {body}"
                ));
            }
        }
    }

    for scope in scope_missing {
        findings.push(format!(
            "scope path `{scope}` is not a directory; the gate's scope and the tree disagree"
        ));
    }

    let mut pinned_occurrences = 0usize;
    for (pin, seen) in PINS.iter().zip(pinned_seen.iter()) {
        match seen {
            None => findings.push(format!(
                "pin for `{}` ({}, {}) did not match a scanned file; the pin and the tree disagree",
                pin.path, pin.finding, pin.owner
            )),
            Some((count, floats)) => {
                pinned_occurrences += *count;
                if *count > pin.max_occurrences {
                    let first = floats
                        .first()
                        .map(|(line, body)| format!(" (first at line {line}: {body})"))
                        .unwrap_or_default();
                    findings.push(format!(
                        "`{}`: {count} floating point occurrence(s) exceed the pin of {} for {} ({}){first}. \
                         A pinned file may not grow: remove the float, or the pin grows with the finding.",
                        pin.path, pin.max_occurrences, pin.finding, pin.owner
                    ));
                }
                if *count == 0 {
                    findings.push(format!(
                        "stale pin: `{}` has no floating point left. {} is closed on this path, so delete \
                         the pin in {} and let the gate protect the file like any other.",
                        pin.path, pin.finding, pin.owner
                    ));
                }
            }
        }
    }

    if findings.is_empty() {
        return Ok(format!(
            "No-float gate OK: {files_scanned} file(s) under {} scoped path(s) carry no floating point, \
             except {pinned_occurrences} occurrence(s) pinned to BLG-240 and owned by WP-45.",
            SCOPE.len()
        ));
    }

    let mut msg = String::new();
    let _ = writeln!(msg, "{} finding(s):\n", findings.len());
    for f in &findings {
        let _ = writeln!(msg, "  {f}");
    }
    Err(msg)
}

/// Canaries for the scanner and the pin rule.
///
/// Each one is a text in, verdict out pair, so the canaries need no fixture on
/// disk and cannot pass by reading a tree that happens to be clean.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    // A float in production code is found.
    let injected = "pub fn share() -> f64 {\n    0.5\n}\n";
    if floats_in(&readable_source(injected)).is_empty() {
        problems.push(String::from(
            "VACUOUS: an injected `-> f64` was accepted. This is the exact shape the gate exists for.",
        ));
    }

    // A float literal with a suffix is found, and the token is not read as part
    // of the number in front of it.
    if floats_in(&readable_source("let x = 1.0f64;\n")).is_empty() {
        problems.push(String::from(
            "VACUOUS: a `1.0f64` literal was accepted",
        ));
    }
    if floats_in(&readable_source("let x = 1f32;\n")).is_empty() {
        problems.push(String::from("VACUOUS: a `1f32` literal was accepted"));
    }

    // An associated constant and a cast are found.
    if floats_in(&readable_source("let m = f64::MAX;\n")).is_empty() {
        problems.push(String::from("VACUOUS: `f64::MAX` was accepted"));
    }
    if floats_in(&readable_source("let y = x as f32;\n")).is_empty() {
        problems.push(String::from("VACUOUS: `as f32` was accepted"));
    }

    // A comment is not code.
    if !floats_in(&readable_source("// speed is an f64 in the harness\nlet a = 1;\n")).is_empty() {
        problems.push(String::from(
            "BROKEN: a float named in a line comment was reported",
        ));
    }
    if !floats_in(&readable_source("/* f64 belongs to the harness */\nlet a = 1;\n")).is_empty() {
        problems.push(String::from(
            "BROKEN: a float named in a block comment was reported",
        ));
    }

    // A doc comment on a public item is a comment too.
    if !floats_in(&readable_source("/// Returns f64 for the harness.\npub fn a() {}\n")).is_empty() {
        problems.push(String::from(
            "BROKEN: a float named in a doc comment was reported",
        ));
    }

    // A hex constant that contains the bytes `f64` is not a float. The tree has
    // one (`...6bf64a07...` in a signature constant), and reading it as a float
    // is how this gate would fail on a correct commit.
    let hex = "const SIGNATURE: [u8; 32] = [0x6b, 0xf6, 0x4a, 0x07];\nconst ONE: u64 = 0x6bf64a07;\n";
    if !floats_in(&readable_source(hex)).is_empty() {
        problems.push(String::from(
            "BROKEN: a hex constant holding the bytes `f64` was reported as a float",
        ));
    }

    // A string literal is not code, whether it is plain or raw.
    if !floats_in(&readable_source("let s = \"f64 in a message\";\n")).is_empty() {
        problems.push(String::from(
            "BROKEN: a float inside a string literal was reported",
        ));
    }
    if !floats_in(&readable_source("let s = r#\"f64 \"quoted\" f64\"#;\n")).is_empty() {
        problems.push(String::from(
            "BROKEN: a float inside a raw string literal was reported",
        ));
    }

    // An identifier that merely ends with the token is not a float.
    if !floats_in(&readable_source("struct AsF64;\nlet my_f64 = 1;\n")).is_empty() {
        problems.push(String::from(
            "BROKEN: an identifier ending in `F64` was reported as a float",
        ));
    }

    // A `#[cfg(test)]` module is a harness even when it sits inside a scoped
    // file, and a `#[cfg(test)]` on a single item hides nothing.
    let test_module = "pub fn a() {}\n#[cfg(test)]\nmod tests {\n    fn b() -> f64 {\n        0.0\n    }\n}\n";
    if !floats_in(&readable_source(test_module)).is_empty() {
        problems.push(String::from(
            "BROKEN: a float inside a `#[cfg(test)]` module was reported",
        ));
    }
    let single_item = "#[cfg(test)]\nuse std::f64::consts::PI;\npub fn c(x: f64) -> f64 {\n    x\n}\n";
    let found = floats_in(&readable_source(single_item));
    if found.is_empty() {
        problems.push(String::from(
            "VACUOUS: a `#[cfg(test)]` on a `use` hid the float in the `fn` after it",
        ));
    }

    // The pin table itself: every pin names a finding and an owning package,
    // and no two pins name the same file.
    for (index, pin) in PINS.iter().enumerate() {
        if !pin.finding.starts_with("BLG-") {
            problems.push(format!(
                "BROKEN: the pin for `{}` names `{}` rather than a finding id",
                pin.path, pin.finding
            ));
        }
        if !pin.owner.starts_with("WP-") {
            problems.push(format!(
                "BROKEN: the pin for `{}` names `{}` rather than a work package",
                pin.path, pin.owner
            ));
        }
        if PINS[index + 1..].iter().any(|other| other.path == pin.path) {
            problems.push(format!("BROKEN: `{}` is pinned twice", pin.path));
        }
        if pin.max_occurrences == 0 {
            problems.push(format!(
                "BROKEN: the pin for `{}` allows zero occurrences, which is not a pin",
                pin.path
            ));
        }
    }

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "no-float gate self-test OK: `-> f64`, `1.0f64`, `1f32`, `f64::MAX` and `as f32` are all \
         reported; a float in a line comment, block comment, doc comment, string, raw string or hex \
         constant and a float inside a `#[cfg(test)]` module are all accepted; a `#[cfg(test)]` on a \
         `use` does not hide the float after it; every pin names a finding, names a work package and \
         is unique.",
    ))
}
