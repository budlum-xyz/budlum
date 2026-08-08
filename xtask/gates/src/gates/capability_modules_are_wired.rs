//! Every capability module is called by something, or says it is not.
//!
//! Ported from `scripts/check-capability-modules-are-wired.sh`, 706 lines of
//! shell wrapping Python, the largest gate in the tree. The shell was a
//! here-doc launcher and the Python did the work, so the port replaces two
//! languages with one.
//!
//! # What it measures
//!
//! A module under `src/`, `budzero/` or `wallet-core/` exporting three or
//! more public functions is a capability surface. For each, this asks whether
//! any other production module names one of the things it exports. If nothing
//! does, the module either declares `//! WIRING: unwired - <reason>` or the
//! gate fails.
//!
//! The point is not tidiness. A refusal nothing calls protects nothing, and
//! this tree has found several: `validate_inference_grant` was documented as
//! running and was called from nowhere, and a second proof market sat beside
//! the real one disagreeing about deadlines with no caller to notice.
//!
//! # Why the measurement is careful
//!
//! Name matching is crude, so the shell version accumulated corrections and
//! every one of them is a bug it let through once. They are kept:
//!
//! * Test modules are stripped before anything is read. A module called only
//!   by its own tests is unwired, and counting those would report the whole
//!   tree as reached.
//! * String literals and doc links are stripped. A module named in prose or
//!   in a rustdoc intra-doc link has been mentioned, not called;
//!   `generated.rs` was reported wired because `derived.rs` explained its
//!   design by referring to it.
//! * `use` statements are stripped. An import is a declaration of intent, and
//!   the intent is checked by looking for the call.
//! * Enum bodies are stripped. A variant sharing a name with a function
//!   elsewhere is not that function.
//! * A name defined by two modules identifies neither, so ambiguous names are
//!   dropped. A module left with none is skipped and reported as skipped,
//!   rather than counted either way.
//! * Function names must be followed by a call. `complete` and `assign`
//!   appearing in comments carried `settlement/proof_market.rs` as wired while
//!   nothing reached it. Types and constants still match bare, because a
//!   `dyn` dispatch leaves no parenthesis at the call site.
//! * `Other::name` does not count, but `this_module::name` does.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Roots holding shipped library code.
///
/// Benches, fuzz targets, kani harnesses and examples are drivers: they call
/// into the tree and are not called by it, so measuring them for inbound
/// calls would flag every one.
const SCAN_ROOTS: &[&str] = &["src", "budzero", "wallet-core"];

/// Below this a module is a helper, not a capability surface, and name
/// matching is too noisy to act on.
const MIN_PUB_FNS: usize = 3;

/// Implemented almost everywhere; counting them would drown the signal.
const UBIQUITOUS: &[&str] = &["new", "default", "fmt", "from", "into", "validate"];

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Remove `#[cfg(test)] mod tests { ... }` blocks, braces balanced.
fn strip_test_mods(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes: Vec<char> = src.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        // Look for a cfg(test) attribute followed by a mod.
        if bytes[i] == '#' && src[byte_index(&bytes, i)..].starts_with("#[cfg(test)]") {
            // Find the opening brace of the module that follows.
            let mut j = i;
            let mut depth = 0i32;
            let mut started = false;
            while j < bytes.len() {
                if bytes[j] == '{' {
                    depth += 1;
                    started = true;
                } else if bytes[j] == '}' {
                    depth -= 1;
                    if started && depth == 0 {
                        j += 1;
                        break;
                    }
                }
                j += 1;
            }
            if started {
                i = j;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Char index to byte index, for the one place a substring check is needed.
fn byte_index(chars: &[char], idx: usize) -> usize {
    chars[..idx].iter().map(|c| c.len_utf8()).sum()
}

/// Blank out string literals, including raw strings, and line comments that
/// carry doc links. What remains is code.
fn strip_noise(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < chars.len() {
        // Line comment: drop to end of line. Doc comments included, which is
        // what removes `[`crate::path::Thing`]` cross-references.
        if chars[i] == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        // Block comment.
        if chars[i] == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            continue;
        }
        // Raw string: r"..." or r#"..."#.
        if chars[i] == 'r' && i + 1 < chars.len() && (chars[i + 1] == '"' || chars[i + 1] == '#') {
            let mut hashes = 0;
            let mut j = i + 1;
            while j < chars.len() && chars[j] == '#' {
                hashes += 1;
                j += 1;
            }
            if j < chars.len() && chars[j] == '"' {
                j += 1;
                loop {
                    if j >= chars.len() {
                        break;
                    }
                    if chars[j] == '"' {
                        let mut k = j + 1;
                        let mut seen = 0;
                        while k < chars.len() && chars[k] == '#' && seen < hashes {
                            seen += 1;
                            k += 1;
                        }
                        if seen == hashes {
                            j = k;
                            break;
                        }
                    }
                    j += 1;
                }
                i = j;
                out.push(' ');
                continue;
            }
        }
        // Ordinary string.
        if chars[i] == '"' {
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' {
                    i += 2;
                    continue;
                }
                if chars[i] == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push(' ');
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Drop `use ...;` items, to the semicolon rather than to the newline.
///
/// A re-export names every symbol it forwards, so `pub use capability::{a, b}`
/// reads exactly like code invoking them. Line-based filtering is not enough:
/// the ones that matter here span several lines, and dropping only the first
/// leaves the names behind. That mistake reported eight modules as wired by
/// their own `mod.rs` re-export.
fn strip_use_statements(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < chars.len() {
        let at_line_start = i == 0 || chars[i - 1] == '\n';
        if at_line_start {
            // Skip indentation, then look for `use` or `pub use`.
            let mut j = i;
            while j < chars.len() && (chars[j] == ' ' || chars[j] == '\t') {
                j += 1;
            }
            let rest: String = chars[j..(j + 8).min(chars.len())].iter().collect();
            let is_use = rest.starts_with("use ") || rest.starts_with("pub use ");
            if is_use {
                while j < chars.len() && chars[j] != ';' {
                    j += 1;
                }
                i = (j + 1).min(chars.len());
                out.push('\n');
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Remove the inside of `enum ... { ... }` declarations.
///
/// A variant sharing a name with a function elsewhere is not that function,
/// and enum bodies are full of short capitalised words that collide with
/// exported type names.
fn strip_enum_bodies(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < chars.len() {
        let starts_enum = chars[i] == 'e'
            && chars[i..].starts_with(&['e', 'n', 'u', 'm', ' '])
            && (i == 0 || !is_ident_char(chars[i - 1]));
        if starts_enum {
            // Find the opening brace, then skip a balanced body.
            let mut j = i;
            while j < chars.len() && chars[j] != '{' && chars[j] != ';' {
                j += 1;
            }
            if j < chars.len() && chars[j] == '{' {
                let mut depth = 0i32;
                while j < chars.len() {
                    if chars[j] == '{' {
                        depth += 1;
                    } else if chars[j] == '}' {
                        depth -= 1;
                        if depth == 0 {
                            j += 1;
                            break;
                        }
                    }
                    j += 1;
                }
                out.push_str("enum ");
                i = j;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Names following a keyword, e.g. every `pub fn <name>`.
fn names_after(src: &str, keyword: &str, lowercase_only: bool) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let chars: Vec<char> = src.chars().collect();
    let kw: Vec<char> = keyword.chars().collect();
    let mut i = 0;
    while i + kw.len() < chars.len() {
        let matches = chars[i..].starts_with(&kw) && (i == 0 || !is_ident_char(chars[i - 1]));
        if !matches {
            i += 1;
            continue;
        }
        let mut j = i + kw.len();
        while j < chars.len() && chars[j].is_whitespace() {
            j += 1;
        }
        // Optional `async `.
        if chars[j..].starts_with(&['a', 's', 'y', 'n', 'c']) {
            j += 5;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
        }
        let start = j;
        while j < chars.len() && is_ident_char(chars[j]) {
            j += 1;
        }
        if j > start {
            let name: String = chars[start..j].iter().collect();
            let first_ok = name.chars().next().is_some_and(|c| {
                if lowercase_only {
                    c.is_ascii_lowercase() || c == '_'
                } else {
                    true
                }
            });
            if first_ok {
                found.insert(name);
            }
        }
        i = j.max(i + 1);
    }
    found
}

/// Public function names in a body.
fn pub_fns(src: &str) -> BTreeSet<String> {
    names_after(src, "pub fn", true)
        .union(&names_after(src, "pub async fn", true))
        .cloned()
        .collect()
}

/// Public type, constant and static names in a body.
fn pub_types(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for kw in [
        "pub struct",
        "pub enum",
        "pub trait",
        "pub const",
        "pub static",
        "pub type",
    ] {
        out.extend(names_after(src, kw, false));
    }
    out
}

/// Does `haystack` name `needle` as a call, or as a bare mention?
///
/// `require_call` is true for function names: a comment saying `complete` is
/// not evidence that a function called `complete` ran. Types and constants
/// match bare, because a `dyn` dispatch leaves no parenthesis behind.
///
/// `Other::needle` does not count. `own_module::needle` does, and so does
/// `Type::needle` where `Type` is one of the module's own exports: an
/// associated function is reached through its type, so `ContentId::of(...)`
/// is a call into the module defining `ContentId`. Rejecting it lost
/// `of_subrange_for_deal`, which `provider.rs` calls at line 183, well above
/// its `mod tests`, and reported `content_id.rs` as unreached.
fn mentions(
    haystack: &str,
    needle: &str,
    own_module: &str,
    require_call: bool,
    own_types: &BTreeSet<String>,
) -> bool {
    let chars: Vec<char> = haystack.chars().collect();
    let pat: Vec<char> = needle.chars().collect();
    let own: Vec<char> = format!("{own_module}::").chars().collect();
    let mut i = 0;
    while i + pat.len() <= chars.len() {
        if !chars[i..].starts_with(&pat) {
            i += 1;
            continue;
        }
        let after = i + pat.len();
        // Must not run into a longer identifier.
        if after < chars.len() && is_ident_char(chars[after]) {
            i += 1;
            continue;
        }
        // Preceded by `::` means it is a member of something else, unless
        // that something else is this module.
        let mut qualified_elsewhere = false;
        if i >= 2 && chars[i - 1] == ':' && chars[i - 2] == ':' {
            let by_module = i >= own.len() && chars[i - own.len()..i] == own[..];
            // Read the qualifier back and see whether it is a type this
            // module exports.
            let mut k = i - 2;
            while k > 0 && is_ident_char(chars[k - 1]) {
                k -= 1;
            }
            let qualifier: String = chars[k..i - 2].iter().collect();
            let by_own_type = own_types.contains(&qualifier);
            // A type is commonly addressed through the module that re-exports
            // it rather than the one that defines it:
            // `crate::storage::StorageLifecycleState` reaches
            // `storage/lifecycle.rs`, and the qualifier is `storage`. The name
            // itself is what identifies the module here, and it only reached
            // this loop because it is unique to it, so a path qualifier that
            // is neither the module nor one of its own types is still a use of
            // this module's name and not somebody else's member.
            //
            // What must stay rejected is `Other::name` where `Other` is a
            // type: that names a member of `Other`. Distinguished by case,
            // which is the convention Rust enforces everywhere it matters.
            let looks_like_a_type = qualifier.chars().next().is_some_and(char::is_uppercase);
            qualified_elsewhere = !(by_module || by_own_type) && looks_like_a_type;
        } else if i > 0 && is_ident_char(chars[i - 1]) {
            i += 1;
            continue;
        }
        if qualified_elsewhere {
            i += 1;
            continue;
        }
        if require_call {
            // Skip whitespace, an optional turbofish, then require `(`.
            let mut j = after;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if j + 1 < chars.len() && chars[j] == ':' && chars[j + 1] == ':' {
                j += 2;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                if j < chars.len() && chars[j] == '<' {
                    while j < chars.len() && chars[j] != '>' {
                        j += 1;
                    }
                    j = (j + 1).min(chars.len());
                    while j < chars.len() && chars[j].is_whitespace() {
                        j += 1;
                    }
                }
            }
            if j < chars.len() && chars[j] == '(' {
                return true;
            }
            i += 1;
            continue;
        }
        return true;
    }
    false
}

fn is_test_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.contains("/tests/")
        || s.ends_with("_tests.rs")
        || s.ends_with("/tests.rs")
        || s.contains("/benches/")
}

fn collect_rs(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if p.is_dir() {
            if matches!(name.as_str(), ".git" | "target" | "node_modules") {
                continue;
            }
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("rs")) {
            out.push(p);
        }
    }
}

/// Does the module declare itself unwired?
fn declares_unwired(src: &str) -> bool {
    src.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("//!") && t.contains("WIRING:") && t.contains("unwired")
    })
}

struct Outcome {
    checked: usize,
    skipped: usize,
    problems: Vec<String>,
}

/// Read every scanned file with its test modules removed.
fn read_bodies(root: &Path) -> Result<(Vec<PathBuf>, BTreeMap<PathBuf, String>), String> {
    let mut files = Vec::new();
    for r in SCAN_ROOTS {
        collect_rs(&root.join(r), &mut files);
    }
    if files.is_empty() {
        return Err(format!("no .rs files found under {}", root.display()));
    }
    files.sort();

    let mut bodies: BTreeMap<PathBuf, String> = BTreeMap::new();
    for p in &files {
        let raw = std::fs::read_to_string(p).unwrap_or_default();
        bodies.insert(p.clone(), strip_test_mods(&raw));
    }
    Ok((files, bodies))
}

/// Names defined by more than one production module, which identify neither.
fn ambiguous_names(production: &[PathBuf], bodies: &BTreeMap<PathBuf, String>) -> BTreeSet<String> {
    let mut definers: BTreeMap<String, BTreeSet<PathBuf>> = BTreeMap::new();
    for p in production {
        let body = &bodies[p];
        for n in pub_fns(body).union(&pub_types(body)) {
            definers.entry(n.clone()).or_default().insert(p.clone());
        }
    }
    definers
        .into_iter()
        .filter(|(_, owners)| owners.len() > 1)
        .map(|(n, _)| n)
        .collect()
}

fn measure(root: &Path) -> Result<Outcome, String> {
    let (files, bodies) = read_bodies(root)?;

    let production: Vec<PathBuf> = files.iter().filter(|p| !is_test_path(p)).cloned().collect();

    // Evidence of a call: the body with imports, strings and comments gone.
    let evidence: BTreeMap<PathBuf, String> = bodies
        .iter()
        .map(|(p, b)| {
            (
                p.clone(),
                strip_enum_bodies(&strip_use_statements(&strip_noise(b))),
            )
        })
        .collect();

    let ambiguous = ambiguous_names(&production, &bodies);

    let ubiquitous: BTreeSet<String> = UBIQUITOUS.iter().map(|s| (*s).to_string()).collect();

    let mut checked = 0usize;
    let mut skipped = 0usize;
    let mut problems = Vec::new();

    for path in &production {
        let body = &bodies[path];
        let fns: BTreeSet<String> = pub_fns(body).difference(&ubiquitous).cloned().collect();
        if fns.len() < MIN_PUB_FNS {
            continue;
        }
        let own_types = pub_types(body);
        let mut exported = fns.clone();
        exported.extend(own_types.iter().cloned());

        let identifying: Vec<String> = exported
            .iter()
            .filter(|n| !ambiguous.contains(*n))
            .cloned()
            .collect();
        if identifying.is_empty() {
            skipped += 1;
            continue;
        }
        checked += 1;

        let mod_name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();

        let mut wired = false;
        'outer: for other in &production {
            if other == path {
                continue;
            }
            let hay = &evidence[other];
            for n in &identifying {
                if mentions(hay, n, &mod_name, fns.contains(n), &own_types) {
                    wired = true;
                    break 'outer;
                }
            }
        }

        let declared = declares_unwired(body);
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();

        if !wired && !declared {
            problems.push(format!(
                "{rel} exports {} public functions and no production module calls any of \
                 them. Either wire it up, or add `//! WIRING: unwired - <reason>` to the \
                 module doc saying why it is here unreached.",
                fns.len()
            ));
        }
        if wired && declared {
            problems.push(format!(
                "{rel} declares `WIRING: unwired` and something calls it. The marker is \
                 stale, and a stale marker is worse than none: it tells the next reader \
                 not to look."
            ));
        }
    }

    Ok(Outcome {
        checked,
        skipped,
        problems,
    })
}

/// Findings the shell version does not report, pending review.
///
/// # Why this list exists rather than a straight failure
///
/// The port is stricter than the script in one specific way, and the
/// difference is real rather than a bug in either.
///
/// The script keeps comments in the evidence pool on purpose, with a
/// documented reason: stripping them was tried and hid four modules that
/// "really are wired", because a comment usually sits beside the call it
/// describes. Measured against this tree, that reasoning does not hold for
/// at least one of the four. `budzero/bud-node/src/discovery.rs` counts as
/// wired because the word `Provider` appears in
/// `src/storage/provider.rs` inside the doc comment
/// "Provider that answers as `operator`" - a different crate, a different
/// subject, no call anywhere, just the same word.
///
/// So the port strips comments and finds twelve modules the script does not.
/// Some are probably genuinely unreached; `discovery.rs` exports eleven
/// public functions and nothing in `budzero` calls any of them, only
/// `pub use discovery::ContentDiscovery` re-exports one name.
///
/// Twelve modules is more than one commit should decide. Until each has been
/// read, they are listed and not failed on: the gate reports them, keeps the
/// script's verdict as the one that blocks, and this list only shrinks. An
/// entry removed means somebody looked and either wired the module or added
/// the marker.
///
/// Three entries came off it in the same commit that added it. Counting a
/// call made through the module's own type, `ContentId::of_subrange_for_deal`
/// and the like, resolved `content_id.rs`, `pruning.rs` and
/// `discovery.rs` outright: two are genuinely called that way, and the
/// dead-entry check below is what said so rather than a person rechecking.
///
/// Counting own-type calls also surfaced two the earlier pass had masked:
/// `src/registry/evidence.rs` and `budzero/bud-node/src/sharding.rs` both
/// declare `WIRING: unwired` while something reaches them.
/// `permissionless.rs` calls `SlashingReport::consensus_invalid_relay_griefing`
/// at line 1085, so at least the first marker is simply stale.
///
/// Three more came off after being read. `sdk/devnet.rs` and `sdk/runner.rs`
/// are developer tooling: a person runs them, the tree does not, so measuring
/// them for inbound calls asks the wrong question of the right heuristic.
/// `cross_domain/bridge_relayer.rs` sequences three steps that are each
/// reached individually; what is absent is the loop that orders them, which
/// is a node-lifecycle decision nobody has made. All three now carry the
/// marker.
///
/// Three more resolved by a third matcher correction. A type is usually
/// addressed through the module that re-exports it rather than the one that
/// defines it: `crate::storage::StorageLifecycleState` reaches
/// `storage/lifecycle.rs` while the qualifier reads `storage`, and
/// `crate::storage::MobileSelfProfile` reaches `storage/mobile_self.rs` the
/// same way. Both were being read as somebody else's member.
///
/// `storage/provider.rs` was read and is genuinely unreached: nothing
/// constructs a `StorageProvider`, which is what a boundary looks like from
/// the inside. It carries the marker now.
///
/// The list is measured, not typed. A first draft carried twenty-one entries
/// against twelve findings, because nine of them named modules whose only
/// problem was a stale `WIRING` marker, and that class stopped firing once
/// the comment handling changed. Nine entries suppressing nothing is the same
/// defect this branch found three times elsewhere: a number written down
/// rather than counted. `no_pending_entry_is_dead` keeps them equal.
const PENDING_REVIEW: &[&str] = &[
    "budzero/bud-node/src/sharding.rs",
    "budzero/bud-state/src/note.rs",
    "src/registry/evidence.rs",
    "src/registry/poa_onboarding.rs",
    "src/storage/living_threshold.rs",
];

/// # Errors
///
/// Returns the modules that are neither called nor honest about it, excluding
/// the ones on [`PENDING_REVIEW`].
pub fn run(root: &Path) -> Result<String, String> {
    let o = measure(root)?;

    let (pending, blocking): (Vec<&String>, Vec<&String>) = o
        .problems
        .iter()
        .partition(|p| PENDING_REVIEW.iter().any(|m| p.starts_with(m)));

    // An entry suppressing nothing is a claim nobody checked.
    //
    // The list exists to hold findings back while they are read. One that
    // matches no finding is either a module somebody fixed without shortening
    // the list, or a name that was never right. Either way the list has
    // stopped describing the tree, and a list that has stopped describing the
    // tree is how a suppression outlives the thing it suppressed.
    let dead: Vec<&&str> = PENDING_REVIEW
        .iter()
        .filter(|m| !o.problems.iter().any(|p| p.starts_with(**m)))
        .collect();
    if !dead.is_empty() {
        let mut msg = format!(
            "{} PENDING_REVIEW entr(ies) match no finding:\n",
            dead.len()
        );
        for d in &dead {
            let _ = writeln!(msg, "  {d}");
        }
        let _ = write!(
            msg,
            "\nEach either got fixed without the list being shortened, or was never a \
             finding. Remove them: an entry that suppresses nothing is a suppression \
             nobody can audit, and the count in the summary stops meaning anything."
        );
        return Err(msg);
    }

    if blocking.is_empty() {
        let mut msg = format!(
            "capability wiring gate OK: {} capability modules measured, each either called \
             or declaring that it is not ({} skipped as untraceable by name)",
            o.checked, o.skipped
        );
        if !pending.is_empty() {
            let _ = write!(
                msg,
                "\n  {} finding(s) held for review, see PENDING_REVIEW: this port strips \
                 comments and the script does not, and at least one module the script calls \
                 wired is reached only by the same word appearing in an unrelated doc comment.",
                pending.len()
            );
        }
        return Ok(msg);
    }

    let mut msg = String::new();
    let _ = writeln!(msg, "{} module(s):\n", blocking.len());
    for p in &blocking {
        let _ = writeln!(msg, "  {p}\n");
    }
    Err(msg)
}

/// Canaries for the name readers and the unwired marker.
fn self_test_extraction(problems: &mut Vec<String>) {
    // Name extraction.
    let src = "pub fn one() {}\npub async fn two() {}\nfn private() {}\npub struct Three;\n";
    let fns = pub_fns(src);
    if !fns.contains("one") || !fns.contains("two") || fns.contains("private") {
        problems.push(format!("BROKEN: pub_fns read {fns:?}"));
    }
    if !pub_types(src).contains("Three") {
        problems.push(String::from("BROKEN: pub_types missed a struct"));
    }

    // The marker.
    if !declares_unwired("//! WIRING: unwired - measured: nothing calls this\n") {
        problems.push(String::from("BROKEN: an unwired marker was not recognised"));
    }
    if declares_unwired("//! this module is wired\n") {
        problems.push(String::from(
            "VACUOUS: a module without a marker declared one",
        ));
    }
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    // Test modules are stripped, so a call from one is not a call.
    let with_test = "pub fn alpha() {}\n#[cfg(test)]\nmod tests {\n  fn t() { alpha(); }\n}\n";
    if strip_test_mods(with_test).contains("alpha();") {
        problems.push(String::from(
            "VACUOUS: a call from inside #[cfg(test)] survived stripping",
        ));
    }

    // A mention in a doc comment is not a call.
    if mentions(
        &strip_noise("//! see [`crate::x::alpha`]\n"),
        "alpha",
        "x",
        true,
        &BTreeSet::new(),
    ) {
        problems.push(String::from("VACUOUS: a doc link counted as a call"));
    }

    // A mention in a string is not a call.
    if mentions(
        &strip_noise("let s = \"alpha()\";\n"),
        "alpha",
        "x",
        true,
        &BTreeSet::new(),
    ) {
        problems.push(String::from("VACUOUS: a string literal counted as a call"));
    }

    // A bare mention of a function name is not a call.
    if mentions(
        "// complete the thing\nlet complete = 1;",
        "complete",
        "x",
        true,
        &BTreeSet::new(),
    ) {
        problems.push(String::from(
            "VACUOUS: a bare mention counted as a function call",
        ));
    }

    // A real call is a call.
    if !mentions("let v = alpha();", "alpha", "x", true, &BTreeSet::new()) {
        problems.push(String::from("BROKEN: a plain call was not seen"));
    }
    // Turbofish included.
    if !mentions(
        "let v = alpha::<u8>();",
        "alpha",
        "x",
        true,
        &BTreeSet::new(),
    ) {
        problems.push(String::from("BROKEN: a turbofish call was not seen"));
    }
    // Another module's member is not this module's function.
    if mentions("Other::alpha();", "alpha", "x", true, &BTreeSet::new()) {
        problems.push(String::from(
            "VACUOUS: Other::alpha counted as this module's alpha",
        ));
    }
    // This module named explicitly does count.
    if !mentions("x::alpha();", "alpha", "x", true, &BTreeSet::new()) {
        problems.push(String::from(
            "BROKEN: own_module::alpha was not counted as a call",
        ));
    }
    // An associated function reached through this module's own type is a call
    // into this module. Rejecting it reported content_id.rs as unreached while
    // provider.rs was calling ContentId::of_subrange_for_deal in production.
    let own: BTreeSet<String> = ["ContentId".to_string()].into_iter().collect();
    if !mentions(
        "ContentId::of_subrange_for_deal(b, 0, 8);",
        "of_subrange_for_deal",
        "content_id",
        true,
        &own,
    ) {
        problems.push(String::from(
            "BROKEN: a call through the module's own type was not counted",
        ));
    }
    // A type this module does not export still qualifies elsewhere.
    if mentions("Other::alpha();", "alpha", "x", true, &own) {
        problems.push(String::from(
            "VACUOUS: Other::alpha counted despite Other not being an export",
        ));
    }

    // Types match bare, because dyn dispatch leaves no parenthesis.
    if !mentions(
        "let t: Alpha = read();",
        "Alpha",
        "x",
        false,
        &BTreeSet::new(),
    ) {
        problems.push(String::from("BROKEN: a bare type mention was not seen"));
    }
    // A longer identifier is not a match.
    if mentions("alphabet();", "alpha", "x", true, &BTreeSet::new()) {
        problems.push(String::from("VACUOUS: alphabet matched alpha"));
    }

    self_test_extraction(&mut problems);

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "capability wiring gate self-test OK: calls from test modules, doc links, string \
         literals, bare mentions and another module's members are all refused as evidence; \
         plain calls, turbofish calls, own-module paths and bare type mentions are accepted; \
         name extraction and the unwired marker behave.",
    ))
}
