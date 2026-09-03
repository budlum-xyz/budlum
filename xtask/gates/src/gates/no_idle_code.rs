//! No new idle code enters the tree.
//!
//! A `pub` item that nothing outside its own file names is idle: it compiles,
//! it is reviewed, it appears in the public surface, and it does no work. The
//! tree has paid for this before - a second proof market sat beside the real
//! one, and a grant validator was documented as running while nothing called
//! it.
//!
//! # Why this gate is not the wiring gate
//!
//! `capability-modules-are-wired` asks the question one level up: is this
//! *module* reached at all. A module passes as soon as a single one of its
//! exports is called, so the nine dead functions beside the live one are
//! invisible to it. `guards-reachable` is narrower still: it only looks at
//! items whose name begins with `check_`, `verify_`, `validate_` and friends.
//!
//! This gate asks the item-level question the other two do not: does anything
//! outside this file name this item.
//!
//! # Why a ratchet and not a ban
//!
//! Measured on the tree at the time of writing: 4600 public items, of which
//! 1962 are idle. A gate that fails on all of them fails on every commit and
//! gets switched off in a week, which is worse than no gate. So this is the
//! same shape as `udeps` and `indexing-is-not-new`: the existing set is
//! recorded in [`BASELINE_PATH`], and the gate fails when an item **not on the
//! baseline** becomes idle.
//!
//! The baseline only shrinks. Wiring an item up, or deleting it, removes its
//! line; the gate reports stale entries so the file cannot rot into a
//! permanent excuse.
//!
//! # What counts as a reference
//!
//! Any mention of the name in another production `.rs` file, after the file
//! has been scrubbed of:
//!
//!   * `#[cfg(test)]` blocks - an item called only by its own tests is idle,
//!     and counting tests as callers reports the whole tree as busy;
//!   * comments and string literals - a name in prose has been mentioned, not
//!     used, which is how `generated.rs` was once reported as reached;
//!   * `use` statements - an import is a declaration of intent. The intent is
//!     checked by looking for the use of the name somewhere else.
//!
//! One part of a `use` statement is kept: a rename. `use bud_vm::POSEIDON_MDS
//! as MDS;` followed by `MDS[i][j]` reaches `POSEIDON_MDS` exactly as the
//! unaliased name would, so the original of an alias counts as mentioned
//! wherever the alias is. An alias nobody uses reaches nothing.
//!
//! A `pub use` re-export is deliberately treated as an import, not a use.
//! `bud/src/lib.rs` re-exports its whole surface, so counting re-exports would
//! mark every item in that crate as reached and measure nothing.
//!
//! A trait is the one kind of item a file can use without ever repeating its
//! name: `use bud_state::StateBackend;` followed by `state.commit()` calls a
//! trait method, and the text shows only the import. So for a `pub trait`, a
//! private `use` in another file counts as a use. The premise is the
//! compiler's: rustc's `unused_imports` lint, denied in CI, refuses a private
//! import that resolves no name and no method call, so such an import cannot
//! land. A `pub use` of a trait is still a re-export and still counts for
//! nothing, and a private import of a function or a type rescues nothing
//! either, because those are named at every use and the text shows it.
//!
//! # What is out of scope
//!
//! * `tests/`, `benches/`, `fuzz/`, `examples/` - not production.
//! * A name defined by more than one file identifies neither, so ambiguous
//!   names are skipped rather than guessed at, and the count of skips is
//!   reported.
//! * Trait method implementations. A `fn` inside `impl Trait for Type` is
//!   called through the trait, so its name need not appear anywhere.
//! * `main`, and the `#[no_mangle]` / `#[export_name]` surface, which is
//!   called from outside the tree by definition.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Roots that hold production code.
const PROD_ROOTS: &[&str] = &["src", "budzero", "crates", "bud"];

/// Directories that are never production, wherever they appear.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "tests",
    "benches",
    "fuzz",
    "examples",
    "corpus",
];

/// The recorded set of items that were already idle.
const BASELINE_PATH: &str = ".github/idle-code-baseline.txt";

/// Names that are reached from outside the tree and can never be proven idle
/// by reading it.
const ALWAYS_REACHED: &[&str] = &["main"];

/// A scan finding too few items is vacuous and must fail rather than pass.
const VACUITY_FLOOR: usize = 200;

/// How many findings are printed before the list is summarised.
const MAX_REPORTED: usize = 40;

/// Report every finding instead of the first [`MAX_REPORTED`], so the output
/// can be turned into a baseline. See the note on the same helper in
/// `tree_is_english`: hand-editing the constant is what let a stray value
/// reach CI.
fn report_limit() -> usize {
    if std::env::var_os("BUDLUM_GATE_REPORT_ALL").is_some() {
        usize::MAX
    } else {
        MAX_REPORTED
    }
}

/// One public item: where it is defined and what kind it is.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Item {
    file: String,
    kind: &'static str,
    name: String,
}

impl Item {
    /// The baseline line format: one tab-separated record per item.
    fn key(&self) -> String {
        format!("{}\t{}\t{}", self.file, self.kind, self.name)
    }
}

/// Remove every `#[cfg(test)]` block by matching braces.
///
/// A regex cannot do this: test modules nest, and the closing brace of the
/// first inner block would end the match early.
fn strip_cfg_test(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    while i < src.len() {
        let Some(rel) = src[i..].find("#[cfg(test)]") else {
            out.push_str(&src[i..]);
            break;
        };
        let at = i + rel;
        out.push_str(&src[i..at]);
        i = cfg_test_end(src, at + "#[cfg(test)]".len());
    }
    out
}

/// Byte offset just past the item, block or statement that a `#[cfg(test)]`
/// ending at `from` decorates, so the whole of it can be dropped.
///
/// The decorated thing ends at the first of: a balanced `{ ... }` (an item
/// body, a module, a block), a `;` at brace depth zero (a `use`, a trait
/// method signature, a statement such as `panic!("... {e}");`), or an
/// enclosing `}` (a tail expression). Comments, string and char literals
/// are stepped over on the way, so a `{` inside a format string or a `;`
/// inside a doc comment cannot decide where the item ends. The scan used
/// to take the first `{` it met: for a statement that was the placeholder
/// inside its string, the literal's tail `");` stayed behind, and from that
/// stray quote the rest of the file read as one string, so every call
/// after it went unseen and its callee was reported idle.
fn cfg_test_end(src: &str, from: usize) -> usize {
    let b = src.as_bytes();
    let mut k = from;
    let mut depth = 0usize;
    while k < b.len() {
        match b[k] {
            b'/' if k + 1 < b.len() && b[k + 1] == b'/' => {
                while k < b.len() && b[k] != b'\n' {
                    k += 1;
                }
            }
            b'/' if k + 1 < b.len() && b[k + 1] == b'*' => {
                let mut d = 1usize;
                k += 2;
                while k < b.len() && d > 0 {
                    if b[k] == b'/' && k + 1 < b.len() && b[k + 1] == b'*' {
                        d += 1;
                        k += 2;
                    } else if b[k] == b'*' && k + 1 < b.len() && b[k + 1] == b'/' {
                        d -= 1;
                        k += 2;
                    } else {
                        k += 1;
                    }
                }
            }
            b'"' => {
                k += 1;
                while k < b.len() {
                    if b[k] == b'\\' {
                        k += 2;
                        continue;
                    }
                    if b[k] == b'"' {
                        k += 1;
                        break;
                    }
                    k += 1;
                }
            }
            b'\'' => {
                // `'x'`, `'"'`, `'{'` are char literals; `'\n'` is an escaped
                // one; anything else is a lifetime and one byte long.
                if k + 2 < b.len() && b[k + 1] == b'\\' {
                    k += 2;
                    while k < b.len() && b[k] != b'\'' {
                        k += 1;
                    }
                    k += 1;
                } else if k + 2 < b.len() && b[k + 2] == b'\'' {
                    k += 3;
                } else {
                    k += 1;
                }
            }
            b'{' => {
                depth += 1;
                k += 1;
            }
            b'}' => {
                if depth == 0 {
                    return k;
                }
                depth -= 1;
                k += 1;
                if depth == 0 {
                    return k;
                }
            }
            b';' if depth == 0 => return k + 1,
            _ => k += 1,
        }
    }
    src.len()
}

/// Replace comments and string literals with spaces, preserving byte length
/// where it is cheap to do so. Rust block comments nest, so a depth counter is
/// required; a flat scan stops at the first `*/`.
fn strip_comments_and_strings(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    while i < b.len() {
        // Raw string: r"..." or r#"..."#
        if b[i] == b'r' && i + 1 < b.len() && (b[i + 1] == b'"' || b[i + 1] == b'#') {
            let mut hashes = 0usize;
            let mut j = i + 1;
            while j < b.len() && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < b.len() && b[j] == b'"' {
                let close = format!("\"{}", "#".repeat(hashes));
                let rest = &src[j + 1..];
                let end = rest
                    .find(&close)
                    .map_or(b.len(), |p| j + 1 + p + close.len());
                out.push(' ');
                i = end;
                continue;
            }
        }
        match b[i] {
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                let mut depth = 1usize;
                i += 2;
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
                out.push(' ');
            }
            b'"' => {
                i += 1;
                while i < b.len() {
                    if b[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if b[i] == b'"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                out.push(' ');
            }
            b'\'' => {
                // A char literal or a lifetime. Copy it through; neither
                // carries an item name that matters here.
                out.push('\'');
                i += 1;
            }
            _ => {
                let ch_len = src[i..].chars().next().map_or(1, char::len_utf8);
                out.push_str(&src[i..i + ch_len]);
                i += ch_len;
            }
        }
    }
    out
}

/// Remove `use` and `pub use` statements. A re-export is an import, not a use.
///
/// A `use` is found wherever it begins, not only at the head of a
/// `;`-delimited segment: after `mod m {`, after a closing brace, after an
/// attribute. Checked at the segment head alone, an import inside a nested
/// module or one that followed an item body stayed in the text, and the
/// name it imported counted as reached.
fn strip_use_statements(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for segment in src.split_inclusive(';') {
        match use_start(segment) {
            Some(at) => {
                out.push_str(&segment[..at]);
                out.push(' ');
            }
            None => out.push_str(segment),
        }
    }
    out
}

/// Byte offset of the `use` keyword (or the `pub` that introduces it) that
/// begins a `use` item in `segment`, if the segment ends with one.
fn use_start(segment: &str) -> Option<usize> {
    let b = segment.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        let rest = &segment[i..];
        let starts_item = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        if starts_item {
            for head in ["use ", "pub use ", "pub(crate) use ", "pub(super) use "] {
                if rest.starts_with(head) {
                    return Some(i);
                }
            }
        }
        i += rest.chars().next().map_or(1, char::len_utf8);
    }
    None
}

/// What one file's `use` statements say, kept after the statements themselves
/// are scrubbed away.
#[derive(Default)]
struct Imports {
    /// `use path::Original as Alias;` pairs, alias first.
    aliases: Vec<(String, String)>,
    /// The last path segment of every private (non-`pub`) `use`. Only a
    /// `pub trait` may be reached through one of these: see the module notes.
    private_names: BTreeSet<String>,
}

impl Imports {
    /// Add the original name behind every alias the scrubbed text uses. An
    /// alias that appears nowhere outside its own `use` reaches nothing.
    fn reach_originals(&self, ids: &mut BTreeSet<String>) {
        for (alias, original) in &self.aliases {
            if ids.contains(alias) {
                ids.insert(original.clone());
            }
        }
    }
}

/// Read the aliases and the private imports out of a file whose comments and
/// strings are already gone. Nested groups are handled by looking at each
/// `,`- or `{`-delimited leaf: `use a::{B as C, d::E};` yields the alias
/// `C -> B` and the private names `B`, `E`.
fn imports_in(prose_free: &str) -> Imports {
    let mut out = Imports::default();
    for segment in prose_free.split_inclusive(';') {
        let Some(at) = use_start(segment) else {
            continue;
        };
        let stmt = &segment[at..];
        let is_pub = stmt.starts_with("pub");
        let body = stmt.trim_start_matches("pub").trim_start();
        let body = body
            .strip_prefix('(')
            .and_then(|b| b.split_once(')'))
            .map_or(body, |(_, rest)| rest.trim_start());
        let Some(body) = body.strip_prefix("use ") else {
            continue;
        };
        for leaf in body.split([',', '{', '}', ';']) {
            let leaf = leaf.trim();
            if leaf.is_empty() {
                continue;
            }
            let (path, alias) = match leaf.split_once(" as ") {
                Some((p, a)) => (p.trim(), Some(a.trim())),
                None => (leaf, None),
            };
            let original = path.rsplit("::").next().map_or(path, str::trim);
            if original.is_empty() || original == "*" || original == "self" {
                continue;
            }
            if let Some(alias) = alias.filter(|a| *a != "_" && !a.is_empty()) {
                out.aliases.push((alias.to_string(), original.to_string()));
            }
            if !is_pub {
                out.private_names.insert(original.to_string());
            }
        }
    }
    out
}

/// True when this `fn` at byte offset `at` sits inside an `impl ... for ...`
/// block: a trait method, called through the trait rather than by name.
fn inside_trait_impl(src: &str, at: usize) -> bool {
    // Walk back to the nearest unmatched `{` and check whether the header
    // that opened it was an `impl <Trait> for <Type>`.
    let b = src.as_bytes();
    let mut depth = 0i32;
    let mut i = at;
    while i > 0 {
        i -= 1;
        match b[i] {
            b'}' => depth += 1,
            b'{' => {
                if depth == 0 {
                    let head_start = src[..i].rfind(['}', ';']).map_or(0, |p| p + 1);
                    let head = &src[head_start..i];
                    return head.contains("impl") && head.contains(" for ");
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    false
}

/// Find the public items defined in one scrubbed source file.
fn definitions_in(path: &str, scrubbed: &str) -> Vec<Item> {
    let mut out = Vec::new();
    let bytes = scrubbed.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = scrubbed[i..].find("pub") {
        let at = i + rel;
        i = at + 3;
        // `pub` must be a whole word.
        if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
            continue;
        }
        let mut rest = &scrubbed[at + 3..];
        // Skip a visibility restriction: pub(crate), pub(super), pub(in ...)
        let rest_trimmed = rest.trim_start();
        if rest_trimmed.starts_with('(') {
            let Some(close) = rest_trimmed.find(')') else {
                continue;
            };
            rest = &rest_trimmed[close + 1..];
        }
        let mut rest = rest.trim_start();
        // Skip the modifiers that may sit between `pub` and the keyword.
        loop {
            let mut moved = false;
            for kw in ["async ", "const ", "unsafe ", "default "] {
                if rest.starts_with(kw) {
                    rest = rest[kw.len()..].trim_start();
                    moved = true;
                }
            }
            if rest.starts_with("extern \"") {
                if let Some(p) = rest[8..].find('"') {
                    rest = rest[8 + p + 1..].trim_start();
                    moved = true;
                }
            }
            if !moved {
                break;
            }
        }
        let kinds: [(&str, &str); 6] = [
            ("fn ", "fn"),
            ("struct ", "struct"),
            ("enum ", "enum"),
            ("trait ", "trait"),
            ("type ", "type"),
            ("static ", "const"),
        ];
        let mut matched: Option<(&str, &str)> = None;
        for (prefix, kind) in kinds {
            if let Some(tail) = rest.strip_prefix(prefix) {
                matched = Some((tail, kind));
                break;
            }
        }
        // `pub const NAME` reaches here with `const ` already eaten as a
        // modifier, so a bare identifier following it is a constant unless the
        // `fn` branch above claimed it.
        let Some((after, kind)) = matched else {
            if let Some(name) = bare_const_name(rest) {
                out.push(Item {
                    file: path.to_string(),
                    kind: "const",
                    name,
                });
            }
            continue;
        };
        let name: String = after
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() || ALWAYS_REACHED.contains(&name.as_str()) {
            continue;
        }
        if kind == "fn" {
            let abs = after.as_ptr() as usize - scrubbed.as_ptr() as usize;
            if inside_trait_impl(scrubbed, abs) {
                continue;
            }
        }
        out.push(Item {
            file: path.to_string(),
            kind,
            name,
        });
    }
    out
}

/// Every identifier mentioned in a scrubbed file.
fn identifiers_in(scrubbed: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let b = scrubbed.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i].is_ascii_alphabetic() || b[i] == b'_' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.insert(scrubbed[start..i].to_string());
        } else {
            i += 1;
        }
    }
    out
}

/// `pub const NAME: T` reaches the caller with `const ` already eaten as a
/// modifier, so what remains is a bare `SCREAMING_CASE` identifier followed by
/// a type ascription. Returns its name, or [`None`] if this is not that shape.
fn bare_const_name(rest: &str) -> Option<String> {
    let ident: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if ident.is_empty() {
        return None;
    }
    let screaming = ident
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if screaming && rest.get(ident.len()..)?.trim_start().starts_with(':') {
        Some(ident)
    } else {
        None
    }
}

fn walk_rs(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(root) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if kind.is_dir() {
            if !SKIP_DIRS.contains(&name_str.as_ref()) {
                walk_rs(&path, out);
            }
        } else if kind.is_file() && name_str.ends_with(".rs") {
            out.push(path);
        }
    }
}

/// The measurement: every public item, and whether any other production file
/// names it.
struct Scan {
    idle: Vec<Item>,
    total_items: usize,
    ambiguous: usize,
    /// Ambiguous names that no file outside their own definitions mentions.
    ///
    /// Skipping every ambiguous name left 1267 items - over a quarter of the
    /// public surface - checked by nothing at all. Most of that skip is
    /// justified: when two files define `is_valid`, a mention of `is_valid`
    /// somewhere else does not say which one it reached, so calling either idle
    /// would be a guess.
    ///
    /// But one case needs no guess. If *no* file outside the defining set
    /// mentions the name at all, then no definition under it was reached,
    /// whichever one a mention would have meant. Ambiguity stops mattering when
    /// the count of mentions is zero.
    unreached_ambiguous: Vec<Item>,
}

fn scan(root: &Path) -> Scan {
    let mut files: Vec<PathBuf> = Vec::new();
    for r in PROD_ROOTS {
        let p = root.join(r);
        if p.is_dir() {
            walk_rs(&p, &mut files);
        }
    }

    let mut scrubbed: BTreeMap<String, String> = BTreeMap::new();
    let mut imports: BTreeMap<String, Imports> = BTreeMap::new();
    for path in &files {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let prose_free = strip_comments_and_strings(&strip_cfg_test(&text));
        let s = strip_use_statements(&prose_free);
        imports.insert(rel.clone(), imports_in(&prose_free));
        scrubbed.insert(rel, s);
    }

    // Definitions, keyed by name so ambiguity can be detected.
    let mut by_name: BTreeMap<String, Vec<Item>> = BTreeMap::new();
    let mut total_items = 0usize;
    for (rel, s) in &scrubbed {
        for item in definitions_in(rel, s) {
            total_items += 1;
            by_name.entry(item.name.clone()).or_default().push(item);
        }
    }

    let refs: BTreeMap<&String, BTreeSet<String>> = scrubbed
        .iter()
        .map(|(rel, s)| {
            let mut ids = identifiers_in(s);
            if let Some(imp) = imports.get(rel) {
                imp.reach_originals(&mut ids);
            }
            (rel, ids)
        })
        .collect();

    let mut idle = Vec::new();
    let mut ambiguous = 0usize;
    let mut unreached_ambiguous = Vec::new();
    for (name, items) in &by_name {
        if items.len() > 1 {
            ambiguous += items.len();
            // Ambiguity is only a reason to skip while there is something to
            // be ambiguous *about*. With no outside mention there is nothing
            // to attribute, so every definition under the name is unreached.
            let owners: BTreeSet<&String> = items.iter().map(|i| &i.file).collect();
            let mentioned = refs
                .iter()
                .any(|(rel, ids)| !owners.contains(*rel) && ids.contains(name));
            if !mentioned {
                unreached_ambiguous.extend(items.iter().cloned());
            }
            continue;
        }
        let item = &items[0];
        let reached = refs
            .iter()
            .any(|(rel, ids)| **rel != item.file && ids.contains(name));
        let imported_trait = item.kind == "trait"
            && imports
                .iter()
                .any(|(rel, imp)| *rel != item.file && imp.private_names.contains(name));
        if !reached && !imported_trait {
            idle.push(item.clone());
        }
    }
    idle.sort();
    unreached_ambiguous.sort();
    Scan {
        idle,
        total_items,
        ambiguous,
        unreached_ambiguous,
    }
}

/// Read the baseline, ignoring blank lines and `#` comments.
fn read_baseline(root: &Path) -> BTreeSet<String> {
    let path = root.join(BASELINE_PATH);
    let Ok(text) = fs::read_to_string(path) else {
        return BTreeSet::new();
    };
    text.lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// # Errors
///
/// Returns a finding when an item that is not on the baseline is idle, or when
/// the scan found fewer than [`VACUITY_FLOOR`] public items and would be
/// vacuous.
pub fn run(root: &Path) -> Result<String, String> {
    let scan_result = scan(root);

    if scan_result.total_items < VACUITY_FLOOR {
        return Err(format!(
            "only {} public items found under {}; the gate would be vacuous",
            scan_result.total_items,
            root.display()
        ));
    }

    let baseline = read_baseline(root);
    // Unreached ambiguous items are the same finding as an idle item and ride
    // the same baseline. They are folded in here rather than reported
    // separately because a reader does not care why the scan was unsure of the
    // name; they care that nothing calls it.
    let all_idle: Vec<&Item> = scan_result
        .idle
        .iter()
        .chain(scan_result.unreached_ambiguous.iter())
        .collect();
    let current: BTreeSet<String> = all_idle.iter().map(|i| i.key()).collect();

    let new_idle: Vec<&Item> = all_idle
        .iter()
        .copied()
        .filter(|i| !baseline.contains(&i.key()))
        .collect();

    // A baseline entry that is no longer idle has been wired up or deleted.
    // Reporting it is what keeps the file shrinking instead of rotting.
    let stale: Vec<&String> = baseline.iter().filter(|k| !current.contains(*k)).collect();

    if !new_idle.is_empty() {
        let n = new_idle.len();
        let mut msg = format!("{n} newly idle public item(s):\n");
        for item in new_idle.iter().take(report_limit()) {
            let _ = writeln!(msg, "  {}: pub {} {}", item.file, item.kind, item.name);
        }
        if n > report_limit() {
            let _ = writeln!(msg, "  ... and {} more", n - report_limit());
        }
        msg.push_str(
            "\n  Nothing outside the defining file names these. Either call them from the\n  \
             path that is supposed to use them, or delete them. A `pub use` re-export is\n  \
             an import, not a use, so re-exporting does not settle it.\n  \
             The baseline only shrinks: do not add a line to ",
        );
        msg.push_str(BASELINE_PATH);
        msg.push('.');
        return Err(msg);
    }

    if !stale.is_empty() {
        let n = stale.len();
        let mut msg = format!("{n} stale baseline entr(ies) in {BASELINE_PATH}:\n");
        for k in stale.iter().take(report_limit()) {
            let _ = writeln!(msg, "  {k}");
        }
        if n > report_limit() {
            let _ = writeln!(msg, "  ... and {} more", n - report_limit());
        }
        msg.push_str(
            "\n  These are no longer idle, so the baseline is claiming a debt that was\n  \
             already paid. Delete the lines; the baseline only shrinks.",
        );
        return Err(msg);
    }

    Ok(format!(
        "No new idle code: {} public items, {} idle on the baseline ({} of them \
         under a name more than one file defines), {} ambiguous items skipped as \
         genuinely undecidable.",
        scan_result.total_items,
        current.len(),
        scan_result.unreached_ambiguous.len(),
        scan_result
            .ambiguous
            .saturating_sub(scan_result.unreached_ambiguous.len())
    ))
}

/// A fresh scratch directory for a self-test run.
fn scratch_dir() -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir =
        std::env::temp_dir().join(format!("budlum-gates-idle-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create scratch dir: {e}"))?;
    Ok(dir)
}

/// A fixture tree: `src/` with enough public items to clear the vacuity floor,
/// every one of them reached from `src/driver.rs`.
fn build_clean_tree(root: &Path) -> std::io::Result<()> {
    let src = root.join("src");
    fs::create_dir_all(&src)?;
    let mut driver = String::from("fn drive() {\n");
    for i in 1..=210 {
        fs::write(
            src.join(format!("m{i}.rs")),
            format!("pub fn reached{i}() -> u32 {{ {i} }}\n"),
        )?;
        let _ = writeln!(driver, "    let _ = crate::m{i}::reached{i}();");
    }
    driver.push_str("}\n");
    fs::write(src.join("driver.rs"), driver)?;
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    let mut files = Vec::new();
    walk_rs(src, &mut files);
    for f in files {
        let rel = f.strip_prefix(src).expect("walked file is under src");
        let target = dst.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&f, &target)?;
    }
    // The baseline lives outside the .rs walk, so copy it explicitly.
    let bl = src.join(BASELINE_PATH);
    if bl.is_file() {
        let target = dst.join(BASELINE_PATH);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&bl, &target)?;
    }
    Ok(())
}

/// Stage a copy of the clean tree plus one extra file and report acceptance.
fn accepts_with(
    clean: &Path,
    tmp: &Path,
    tag: &str,
    files: &[(&str, &str)],
) -> Result<bool, String> {
    let dir = tmp.join(tag);
    copy_tree(clean, &dir).map_err(|e| format!("cannot stage {tag}: {e}"))?;
    for (name, body) in files {
        let target = dir.join(name);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create dir for {tag}: {e}"))?;
        }
        fs::write(&target, body).map_err(|e| format!("cannot write fixture for {tag}: {e}"))?;
    }
    Ok(run(&dir).is_ok())
}

/// Three things that look like use but are not: a re-export, a test-only call,
/// and a mention in a comment or string literal.
///
/// # Errors
///
/// Returns the first canary that misbehaves.
fn not_a_caller_canaries(clean: &Path, tmp: &Path) -> Result<(), String> {
    // A `pub use` re-export must NOT rescue an idle item, or one glob in
    // lib.rs silences the whole gate.
    if accepts_with(
        clean,
        tmp,
        "reexport",
        &[
            ("src/idle.rs", "pub fn only_reexported() -> u32 { 1 }\n"),
            ("src/reexport.rs", "pub use crate::idle::only_reexported;\n"),
        ],
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: a pub use re-export counted as a caller, so one glob would silence the gate",
        ));
    }

    // An item called only by its own tests is idle.
    if accepts_with(
        clean,
        tmp,
        "testonly",
        &[(
            "src/idle.rs",
            "pub fn only_tests_call_this() -> u32 { 2 }\n\
             #[cfg(test)]\nmod tests {\n  use super::*;\n  #[test]\n  fn t() { assert_eq!(only_tests_call_this(), 2); }\n}\n",
        )],
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: an item called only from its own #[cfg(test)] block passed as reached",
        ));
    }

    // An import inside a nested module, or one that follows an item body,
    // is still an import. Found only at the head of a `;` segment, a
    // `use` after `mod m {` or after a `}` stayed in the text and the name
    // it named was taken as reached.
    if accepts_with(
        clean,
        tmp,
        "nested_use",
        &[
            (
                "src/idle.rs",
                "pub fn only_imported_inside() -> u32 { 9 }\n",
            ),
            (
                "src/importer.rs",
                "pub mod inner {\n    use crate::idle::only_imported_inside;\n}\n\
                 fn f() -> u32 { 1 }\n\
                 pub use crate::idle::only_imported_inside as again;\n",
            ),
        ],
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: a use inside a nested module or after an item body counted as a caller",
        ));
    }

    // A name that appears only in a comment or a string is not a caller.
    if accepts_with(
        clean,
        tmp,
        "prose",
        &[
            ("src/idle.rs", "pub fn mentioned_only_in_prose() -> u32 { 3 }\n"),
            (
                "src/talker.rs",
                "fn t() {\n  // mentioned_only_in_prose explains the design\n  let _ = \"mentioned_only_in_prose\";\n}\n",
            ),
        ],
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: a mention in a comment or string counted as a caller",
        ));
    }

    Ok(())
}

/// The two things a `use` statement can settle: an alias that the file then
/// uses reaches the original, and a private import of a trait is a use of
/// that trait. Each comes with its negative, or the rule would be a hole.
///
/// # Errors
/// Returns the first canary that misbehaves.
fn import_canaries(clean: &Path, tmp: &Path) -> Result<(), String> {
    let cases: [(&str, bool, &str, &str); 4] = [
        (
            "alias_used",
            true,
            "use crate::idle::NOBODY_NAMES_THIS_DIRECTLY as N;\nfn f() -> u32 { N }\n",
            "canary: a constant reached through a used alias was reported idle",
        ),
        (
            "alias_unused",
            false,
            "use crate::idle::NOBODY_NAMES_THIS_DIRECTLY as N;\nfn f() -> u32 { 1 }\n",
            "canary: an alias nobody uses rescued the item it renames",
        ),
        (
            "alias_reexported",
            false,
            "pub use crate::idle::NOBODY_NAMES_THIS_DIRECTLY as N;\n",
            "canary: a pub use with a rename counted as a caller",
        ),
        (
            "alias_only_in_prose",
            false,
            "use crate::idle::NOBODY_NAMES_THIS_DIRECTLY as N;\nfn f() -> u32 { /* N */ 1 }\n",
            "canary: an alias mentioned only in a comment reached its original",
        ),
    ];
    expect_each(
        clean,
        tmp,
        "pub const NOBODY_NAMES_THIS_DIRECTLY: u32 = 5;\n",
        &cases,
    )?;
    trait_import_canaries(clean, tmp)
}

/// Stage `idle_body` as `src/idle.rs` beside each importer and check that
/// the gate's verdict is the one the case expects.
///
/// # Errors
/// Returns the complaint of the first case whose verdict is wrong.
fn expect_each(
    clean: &Path,
    tmp: &Path,
    idle_body: &str,
    cases: &[(&str, bool, &str, &str)],
) -> Result<(), String> {
    for (tag, must_pass, importer, complaint) in cases {
        let passed = accepts_with(
            clean,
            tmp,
            tag,
            &[("src/idle.rs", idle_body), ("src/importer.rs", importer)],
        )?;
        if passed != *must_pass {
            let _ = fs::remove_dir_all(tmp);
            return Err(String::from(*complaint));
        }
    }
    Ok(())
}

/// A trait's methods are called without its name, so a private import of a
/// `pub trait` is a use; a re-export or a test-only import is not.
///
/// # Errors
/// Returns the first canary that misbehaves.
fn trait_import_canaries(clean: &Path, tmp: &Path) -> Result<(), String> {
    let trait_cases: [(&str, bool, &str, &str); 3] = [
        (
            "trait_imported",
            true,
            "use crate::idle::NobodyNamesThis;\nfn f(x: &dyn std::any::Any) -> u32 { x.go() }\n",
            "canary: a trait reached only through a private import was reported \
             idle; its methods are called without its name",
        ),
        (
            "trait_reexported",
            false,
            "pub use crate::idle::NobodyNamesThis;\n",
            "canary: a pub use of a trait counted as a use",
        ),
        (
            "trait_imported_in_tests",
            false,
            "#[cfg(test)]\nmod tests {\n    use crate::idle::NobodyNamesThis;\n}\n",
            "canary: a trait imported only by a test module passed as reached",
        ),
    ];
    expect_each(
        clean,
        tmp,
        "pub trait NobodyNamesThis {\n    fn go(&self) -> u32;\n}\n",
        &trait_cases,
    )
}

/// The ratchet canaries: a recorded item must be exempt, and a recorded item
/// that is no longer idle must fail so the list cannot rot into an excuse.
///
/// # Errors
///
/// Returns the first canary that misbehaves.
fn baseline_canaries(clean: &Path, tmp: &Path) -> Result<(), String> {
    // The baseline must actually exempt, or the ratchet cannot be adopted.
    if !accepts_with(
        clean,
        tmp,
        "baselined",
        &[
            ("src/idle.rs", "pub fn known_idle() -> u32 { 5 }\n"),
            (BASELINE_PATH, "# known debt\nsrc/idle.rs\tfn\tknown_idle\n"),
        ],
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: a baselined item still failed, so the ratchet cannot be adopted",
        ));
    }

    // A stale baseline entry must fail, or the file rots into a permanent
    // excuse.
    if accepts_with(
        clean,
        tmp,
        "stale",
        &[(
            BASELINE_PATH,
            "# paid off long ago\nsrc/gone.rs\tfn\tdeleted_item\n",
        )],
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: a stale baseline entry passed, so the baseline can rot",
        ));
    }

    Ok(())
}

/// # Errors
///
/// Returns the first canary that misbehaves.
/// `#[cfg(test)]` scrubbing must drop exactly the decorated thing, or callers
/// after it vanish and their callees are reported idle.
fn cfg_test_canaries(clean: &Path, tmp: &Path) -> Result<(), String> {
    // The attribute decorates a statement, not a block, and the statement
    // carries a `{` inside a string: the first `{` after the attribute is a
    // format placeholder. The scrubber used to take it for the block, keep
    // the tail `");` of the literal, and from that stray quote on read the
    // rest of the file as one string, so a caller placed after it was never
    // seen and its callee was reported idle.
    if !accepts_with(
        clean,
        tmp,
        "cfg_test_statement",
        &[
            (
                "src/idle.rs",
                "pub fn called_after_the_attribute() -> u32 { 6 }\n",
            ),
            (
                "src/caller.rs",
                "fn c(e: u32) -> u32 {\n    #[cfg(test)]\n    panic!(\"unreadable: {e}\");\n    \
                 crate::idle::called_after_the_attribute()\n}\n",
            ),
        ],
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: a cfg(test) statement with a braced string hid the caller after it",
        ));
    }

    // The block form still has to go in full: a caller that lives only
    // inside a `#[cfg(test)]` module is not a caller, and a test module
    // whose strings carry `;` or `}` must not end early and leak its calls.
    if accepts_with(
        clean,
        tmp,
        "cfg_test_module",
        &[
            (
                "src/idle.rs",
                "pub fn only_tests_call_this() -> u32 { 8 }\n",
            ),
            (
                "src/caller.rs",
                "#[cfg(test)]\nmod tests {\n    const S: &str = \"a; b } c\";\n    \
                 fn c() -> u32 { crate::idle::only_tests_call_this() }\n}\n",
            ),
        ],
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: a call made only from a cfg(test) module with a braced string was taken as wiring",
        ));
    }
    Ok(())
}

/// The vacuity floor must fire on a near-empty tree.
///
/// # Errors
/// Returns the canary complaint if the near-empty tree passes.
fn vacuity_canary(tmp: &Path) -> Result<(), String> {
    let empty = tmp.join("empty");
    fs::create_dir_all(empty.join("src")).map_err(|e| format!("cannot create empty tree: {e}"))?;
    fs::write(empty.join("src/only.rs"), "pub fn a() {}\n")
        .map_err(|e| format!("cannot write vacuity fixture: {e}"))?;
    if run(&empty).is_ok() {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: a near-empty tree passed, so the gate can be vacuous",
        ));
    }
    Ok(())
}

pub fn self_test() -> Result<String, String> {
    let tmp = scratch_dir()?;
    let clean = tmp.join("clean");
    build_clean_tree(&clean).map_err(|e| format!("cannot build clean tree: {e}"))?;

    // A tree where everything is reached passes, or every canary below is
    // meaningless.
    if let Err(msg) = run(&clean) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("canary: a fully wired tree was rejected: {msg}"));
    }

    // An idle function is the whole point.
    if accepts_with(
        &clean,
        &tmp,
        "idle_fn",
        &[("src/idle.rs", "pub fn nobody_calls_this() -> u32 { 7 }\n")],
    )? {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from("canary: an idle pub fn was not detected"));
    }

    // Idle types and constants count too, or a dead struct hides behind the
    // function rule.
    for (tag, body) in [
        (
            "idle_struct",
            "pub struct NobodyBuildsThis { pub a: u32 }\n",
        ),
        ("idle_enum", "pub enum NobodyMatchesThis { A, B }\n"),
        ("idle_const", "pub const NOBODY_READS_THIS: u32 = 5;\n"),
    ] {
        if accepts_with(&clean, &tmp, tag, &[("src/idle.rs", body)])? {
            let _ = fs::remove_dir_all(&tmp);
            return Err(format!("canary: an idle item was not detected: {tag}"));
        }
    }

    not_a_caller_canaries(&clean, &tmp)?;
    import_canaries(&clean, &tmp)?;

    // The control group: a real caller must clear the finding, or the gate is
    // simply always red and teaches nothing.
    if !accepts_with(
        &clean,
        &tmp,
        "wired",
        &[
            ("src/idle.rs", "pub fn genuinely_called() -> u32 { 4 }\n"),
            (
                "src/caller.rs",
                "fn c() -> u32 { crate::idle::genuinely_called() }\n",
            ),
        ],
    )? {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a genuinely called item was reported idle; the gate is too wide",
        ));
    }

    cfg_test_canaries(&clean, &tmp)?;

    baseline_canaries(&clean, &tmp)?;

    // Two files defining the same name, and nothing mentioning it: this used
    // to be skipped as ambiguous, which left over a quarter of the public
    // surface checked by nothing.
    if accepts_with(
        &clean,
        &tmp,
        "amb_unreached",
        &[
            ("src/amb_a.rs", "pub fn shared_name() -> u32 { 1 }\n"),
            ("src/amb_b.rs", "pub fn shared_name() -> u32 { 2 }\n"),
        ],
    )? {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: two definitions of one name, mentioned by no other file, \
             were accepted. Ambiguity is a reason to skip only while there is \
             something to be ambiguous about; with zero outside mentions, no \
             definition under the name was reached whichever one a mention \
             would have meant.",
        ));
    }

    // The same pair, with one outside mention, must pass: now the scan really
    // cannot say which definition was meant, and guessing would be worse than
    // skipping.
    if !accepts_with(
        &clean,
        &tmp,
        "amb_reached",
        &[
            ("src/amb_a.rs", "pub fn shared_name() -> u32 { 1 }\n"),
            ("src/amb_b.rs", "pub fn shared_name() -> u32 { 2 }\n"),
            ("src/amb_use.rs", "fn c() { let _ = shared_name(); }\n"),
        ],
    )? {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: an ambiguous name with a real outside mention was reported \
             as idle. That attribution is a guess, and the gate must not make it.",
        ));
    }

    vacuity_canary(&tmp)?;

    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "no-idle-code canary OK (wired PASSes, idle fn/struct/enum/const FAIL, re-export and \
         test-only and prose FAIL, a real caller PASSes, a used alias PASSes and an unused, \
         re-exported or commented one FAILs, a privately imported trait PASSes and a re-exported \
         or test-imported one FAILs, baseline exempts, stale baseline FAILs, an unmentioned \
         ambiguous name FAILs, a mentioned one PASSes, empty tree FAILs).",
    ))
}
