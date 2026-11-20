//! The number of declared-unwired items may fall, never rise.
//!
//! # Why this gate exists
//!
//! The tree has an honest convention. A module that compiles, lints and passes
//! its own tests but that no production caller reaches must say so, in a
//! comment, with the marker `WIRING: unwired`. The capability-wiring gate
//! enforces the honesty: a capability module is either called or it declares
//! that it is not.
//!
//! What nothing enforced is the *size* of that set. "Declare it and move on" is
//! a correct answer exactly once per item and a disaster in aggregate, because
//! each individual declaration is locally reasonable - the caller is coming in
//! the follow-up merge, the variant joins the intake table next week - while the
//! total silently becomes the real shape of the system. A reviewer reading one
//! file sees one honest note. Nobody was reading all of them at once.
//!
//! The measurement that prompted this gate: of the 52 adapters under
//! `src/cross_domain/external/`, fifteen files carry an unwired declaration,
//! and thirteen whole consensus families - Kaspa `GHOSTDAG`, Cardano Ouroboros
//! and Mithril, Chia proof-of-space with its VDF, `HoneyBadger` BFT, `NIPoPoW`,
//! Solana Tower BFT, NEAR Doomslug, Arweave `SPoRA`, Babylon EOTS, Internet
//! Computer chain-key NI-DKG, Symbiotic restaking vaults and the STARK validity
//! rollup - are reachable from no production code outside the module's own
//! re-export. Each is written, each is tested, and a node built from this tree
//! calls none of them. That is a legitimate state for research code to be in.
//! It is not a legitimate state to be in *by accident*, and it is not a number
//! that may drift upward without anyone deciding that it should.
//!
//! So this gate does one thing: it counts the declarations and refuses growth.
//! Wiring an adapter lowers the number. Adding a sixteenth unwired module
//! raises it, and raising it now costs an explicit, reviewable edit to
//! `.github/unwired-baseline.txt` instead of nothing at all.
//!
//! ## The ratchet has two directions
//!
//! `n > base` refuses a new unwired item. The opposite failure is silence: a
//! baseline parked well above the measured count is standing permission for
//! that many new declarations, and it buys that permission without a single
//! line of review. A baseline more than [`STALL_SLACK_PERCENT`] above the
//! measurement is therefore refused too, with the instruction to lower it. The
//! contract is deliberately the same one `clippy-extra` already uses, so there
//! is one ratchet idiom in this repository rather than two.
//!
//! ## What is counted, and what is not
//!
//! The marker is matched inside comments only. A `WIRING: unwired` sitting in a
//! string literal is data, not a declaration, and counting it would let the
//! number be moved by code that declares nothing.
//!
//! `xtask/` is not scanned. The gates crate is build tooling rather than the
//! shipped node, and more to the point this file and the capability-wiring
//! gate's canaries both contain the marker as fixture text; a gate whose own
//! test data moves its own measurement is not measuring the tree.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Roots that make up the shipped node. `xtask` is excluded on purpose - see
/// the module docs.
const ROOTS: &[&str] = &["src", "crates", "budzero", "bud", "execution"];

/// Directories that never hold first-party source.
const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules", "vendor"];

/// The declaration this gate counts.
const MARKER: &str = "WIRING: unwired";

/// How far above the measured count the baseline may sit before the gap is
/// itself the finding. Ten percent matches `clippy-extra`: wide enough that a
/// branch which wires something up stays green until the baseline catches up,
/// narrow enough that slack cannot pile up over a month of pushes.
const STALL_SLACK_PERCENT: u64 = 10;

/// Largest file this gate will read. A source file past this is not source.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

fn baseline(root: &Path) -> Result<u64, String> {
    let f = root.join(".github/unwired-baseline.txt");
    let text = std::fs::read_to_string(&f)
        .map_err(|e| format!("the baseline could not be read ({}): {e}", f.display()))?;
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_digit()))
        .ok_or_else(|| {
            format!(
                "the baseline holds no number ({}): a ratchet with no baseline is not a ratchet",
                f.display()
            )
        })?
        .parse::<u64>()
        .map_err(|e| format!("the baseline is not a number: {e}"))
}

/// Count the marker in comment text only.
///
/// The scan walks the file once, tracking whether it is inside a line comment,
/// a block comment, a string literal, a raw string or a char literal, and
/// counts a hit only while inside a comment. This is the same reason the
/// provenance gates strip literals: a marker in a string is data that some
/// other code may print, and a gate that counts it can be moved by a test
/// fixture rather than by a declaration.
fn count_in_comments(src: &str) -> usize {
    let b = src.as_bytes();
    let mut i = 0usize;
    let mut hits = 0usize;
    let m = MARKER.as_bytes();
    while i < b.len() {
        match b[i] {
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                let start = i;
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                hits += count_occurrences(&b[start..i], m);
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                let start = i;
                i += 2;
                let mut depth = 1usize;
                while i < b.len() && depth > 0 {
                    if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && i + 1 < b.len() && b[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                hits += count_occurrences(&b[start..i.min(b.len())], m);
            }
            b'"' => {
                i += 1;
                while i < b.len() {
                    if b[i] == b'\\' {
                        i += 2;
                    } else if b[i] == b'"' {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
            }
            b'r' if raw_string_hashes(b, i).is_some() => {
                let hashes = raw_string_hashes(b, i).unwrap_or(0);
                i += 1 + hashes + 1;
                let mut close = Vec::with_capacity(hashes + 1);
                close.push(b'"');
                close.extend(std::iter::repeat_n(b'#', hashes));
                while i < b.len() {
                    if b[i..].starts_with(&close) {
                        i += close.len();
                        break;
                    }
                    i += 1;
                }
            }
            b'\'' => {
                // A lifetime (`'a`) is not a char literal; only step over a
                // literal when the quote actually closes on the same line.
                let mut j = i + 1;
                let mut closed = false;
                while j < b.len() && j < i + 8 && b[j] != b'\n' {
                    if b[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if b[j] == b'\'' {
                        closed = true;
                        break;
                    }
                    j += 1;
                }
                i = if closed { j + 1 } else { i + 1 };
            }
            _ => i += 1,
        }
    }
    hits
}

fn raw_string_hashes(b: &[u8], i: usize) -> Option<usize> {
    if b[i] != b'r' {
        return None;
    }
    let mut j = i + 1;
    while j < b.len() && b[j] == b'#' {
        j += 1;
    }
    if j < b.len() && b[j] == b'"' {
        Some(j - i - 1)
    } else {
        None
    }
}

fn count_occurrences(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    let mut n = 0;
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            n += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    n
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        if p.is_dir() {
            if !SKIP_DIRS.contains(&name.as_ref()) {
                collect(&p, out);
            }
        } else if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("rs")) {
            out.push(p);
        }
    }
}

struct Measured {
    total: u64,
    per_file: BTreeMap<String, usize>,
    adapters_total: usize,
    adapters_unwired: usize,
}

fn measure(root: &Path) -> Measured {
    let mut files = Vec::new();
    for r in ROOTS {
        let p = root.join(r);
        if p.is_dir() {
            collect(&p, &mut files);
        }
    }
    files.sort();
    let mut per_file = BTreeMap::new();
    let mut total = 0u64;
    for f in &files {
        let Ok(meta) = std::fs::metadata(f) else {
            continue;
        };
        if meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        if !text.contains(MARKER) {
            continue;
        }
        let n = count_in_comments(&text);
        if n > 0 {
            let rel = f
                .strip_prefix(root)
                .unwrap_or(f)
                .to_string_lossy()
                .replace('\\', "/");
            per_file.insert(rel, n);
            total += n as u64;
        }
    }

    // The headline number the "consensus of consensuses" claim rests on.
    let ext = root.join("src/cross_domain/external");
    let mut adapters_total = 0usize;
    let mut adapters_unwired = 0usize;
    if ext.is_dir() {
        let mut adapter_files = Vec::new();
        collect(&ext, &mut adapter_files);
        for f in adapter_files {
            let base = f
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if base == "mod.rs" {
                continue;
            }
            adapters_total += 1;
            let rel = f
                .strip_prefix(root)
                .unwrap_or(&f)
                .to_string_lossy()
                .replace('\\', "/");
            if per_file.contains_key(&rel) {
                adapters_unwired += 1;
            }
        }
    }

    Measured {
        total,
        per_file,
        adapters_total,
        adapters_unwired,
    }
}

/// # Errors
///
/// Returns a finding when the declared-unwired count rose above the baseline,
/// or when the baseline sits so far above the measurement that it is standing
/// permission for new declarations.
pub fn run(root: &Path) -> Result<String, String> {
    let base = baseline(root)?;
    let m = measure(root);
    let n = m.total;

    let mut head = format!("unwired declarations: {n} | baseline: {base}");
    if m.adapters_total > 0 {
        let _ = write!(
            head,
            "\n  external consensus adapters: {} of {} carry a `{MARKER}` declaration",
            m.adapters_unwired, m.adapters_total
        );
    }

    if n > base {
        let mut msg = format!(
            "{head}\nFAIL: the declared-unwired count rose by {} over the baseline.\n\n\
             A `{MARKER}` note is an honest answer to \"who calls this\", and it is the\n\
             right answer while the caller is still being written. It is not a place to\n\
             park a module. Either wire the new item to a production caller, or raise\n\
             `.github/unwired-baseline.txt` in the same commit so that the decision to\n\
             grow the unwired surface is a thing a reviewer can see and argue with.\n\n\
             Every file currently carrying the declaration:\n",
            n - base
        );
        for (f, c) in &m.per_file {
            let _ = writeln!(msg, "  {c:3}  {f}");
        }
        return Err(msg);
    }

    let slack = n + n * STALL_SLACK_PERCENT / 100;
    if base > slack {
        return Err(format!(
            "{head}\nFAIL: the baseline is {} above the measured count, more than the \
             {STALL_SLACK_PERCENT}% a ratchet may be off by. Lower \
             `.github/unwired-baseline.txt` to {n}: an unlowered baseline is silent \
             permission for that many new unwired modules.\n  Lower it from this run's \
             number, and only from a number CI measured on the head being pushed.",
            base - n
        ));
    }

    let mut ok = format!(
        "{head}\nOK: the unwired surface is at or below the baseline, and the baseline is \
         within {STALL_SLACK_PERCENT}% of it (the ratchet holds in both directions)."
    );
    let mut worst: Vec<(&String, &usize)> = m.per_file.iter().collect();
    worst.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    if !worst.is_empty() {
        let _ = write!(ok, "\n  heaviest files:");
        for (f, c) in worst.iter().take(5) {
            let _ = write!(ok, "\n    {c:3}  {f}");
        }
    }
    Ok(ok)
}

/// # Errors
///
/// Returns a finding when the canary tree does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-unwired")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        let set_base = |n: &str| -> Result<(), String> { put(".github/unwired-baseline.txt", n) };

        // Two real declarations: one line comment, one inner doc comment.
        put(
            "src/a.rs",
            "// WIRING: unwired - the caller lands in the intake merge.\npub fn a() {}\n",
        )?;
        put(
            "src/b.rs",
            "//! WIRING: unwired - verified by selftest, no production caller yet.\npub fn b() {}\n",
        )?;

        // A string literal and a raw string that merely contain the marker.
        // These are data. If either one counted, a fixture could move the
        // ratchet without declaring anything.
        put(
            "src/decoy.rs",
            "pub const S: &str = \"WIRING: unwired\";\npub const R: &str = r#\"WIRING: unwired\"#;\n\
             pub fn tick<'a>(x: &'a str) -> &'a str { x }\n",
        )?;

        set_base("2")?;
        let at_baseline = run(&dir)?;
        if !at_baseline.contains("unwired declarations: 2 | baseline: 2") {
            return Err(format!(
                "CANARY: two comment declarations plus two string decoys must measure 2, got:\n{at_baseline}"
            ));
        }

        // Growth is refused.
        put(
            "src/c.rs",
            "/* WIRING: unwired - block comments count too. */\npub fn c() {}\n",
        )?;
        let grown = run(&dir);
        match &grown {
            Err(e) if e.contains("rose by 1") && e.contains("src/c.rs") => {}
            other => {
                return Err(format!(
                    "CANARY: a third declaration against a baseline of 2 must be refused and must \
                     name the file, got: {other:?}"
                ))
            }
        }

        // A baseline parked above the measurement is refused from the other side.
        set_base("9")?;
        let stalled = run(&dir);
        match &stalled {
            Err(e) if e.contains("above the measured count") => {}
            other => {
                return Err(format!(
                    "CANARY: a baseline of 9 against a measurement of 3 must be refused as slack, \
                     got: {other:?}"
                ))
            }
        }

        // Wiring one up lowers the number, and the matching baseline is green.
        std::fs::remove_file(dir.join("src/c.rs")).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("src/a.rs"), "pub fn a() {}\n").map_err(|e| e.to_string())?;
        set_base("1")?;
        let lowered = run(&dir)?;
        if !lowered.contains("unwired declarations: 1 | baseline: 1") {
            return Err(format!(
                "CANARY: removing a declaration must lower the measurement, got:\n{lowered}"
            ));
        }

        // A missing baseline is a refusal, not a pass. A ratchet that cannot
        // read its baseline must never report success.
        std::fs::remove_file(dir.join(".github/unwired-baseline.txt"))
            .map_err(|e| e.to_string())?;
        match run(&dir) {
            Err(e) if e.contains("baseline could not be read") => {}
            other => {
                return Err(format!(
                    "CANARY: an unreadable baseline must fail closed, got: {other:?}"
                ))
            }
        }

        Ok(
            "unwired ratchet canary OK: comment declarations counted, string and raw-string \
            decoys ignored, growth refused by name, parked baseline refused as slack, removal \
            lowers the count, missing baseline fails closed"
                .to_string(),
        )
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}
