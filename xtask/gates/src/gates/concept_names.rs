//! The concept-name counter gate.
//!
//! `config/naming/concept_map.toml` lists every legacy architecture name and the
//! code name that replaced it. This gate searches the tree for each record's
//! `patterns` and holds the counts against `.github/concept-names-baseline.txt`.
//!
//! # Two modes, and why the first one is a ratchet
//!
//! * `count`: the number of files and the number of matches per concept are
//!   compared with the baseline. A count **above** it is a failure, because a
//!   legacy name was added. A count **below** it is also a failure until the
//!   baseline is lowered in the same change, so progress cannot go unrecorded
//!   and the recorded number can only fall.
//! * `absolute`: once every count is zero the map's `mode` becomes `absolute`
//!   and a single match is a failure.
//!
//! Rewriting the baseline is a deliberate act. The gate only writes the file
//! when `BUDLUM_CONCEPT_NAMES_WRITE=1` is set, and the writer refuses to raise a
//! number, so the variable can lower the ratchet and cannot record a
//! regression.
//!
//! # Why the pattern language is implemented here
//!
//! The map is the binding list, and its `patterns` entries are the ban itself.
//! Two options existed: take `regex` and `toml` as dependencies, or model the
//! subset of both that this file uses. It takes the second. The gates workspace
//! sits inside the trust boundary and carries three dependencies, each written
//! down in `xtask/gates/Cargo.toml` with the reason it earns its place. A gate
//! that pulls a regex engine and a TOML parser in order to search for
//! twenty-seven words widens that surface without adding a capability the tree
//! needs.
//!
//! The subset is closed rather than approximate. `.` and the `*`, `+` and `{m,n}`
//! quantifiers are refused by name, so a map entry that wants one fails loudly
//! and gets a decision instead of a silent count of zero. What is supported is
//! what the map uses: literal text, `(?i)` as a whole-pattern flag, character
//! classes with ranges and negation, `\\b`, `^`, `$`, grouping with `|`, and `?`
//! as the only quantifier.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The roots the gate searches.
const SCAN_ROOTS: &[&str] = &[
    "src",
    "crates",
    "budzero",
    "execution",
    "mobile",
    "xtask",
    "docs",
    "config",
    "proto",
    "contracts",
];

/// Directories that are never source.
const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// Files above this size are not source text.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Where the map lives, relative to the repository root.
const MAP_PATH: &str = "config/naming/concept_map.toml";

/// Where the ratchet lives, relative to the repository root.
const BASELINE_PATH: &str = ".github/concept-names-baseline.txt";

/// Set this to `1` to rewrite the baseline from the tree. It never raises a
/// number.
const WRITE_ENV: &str = "BUDLUM_CONCEPT_NAMES_WRITE";

/// The last package the directive defines: `WP-01` to `WP-64`.
const LAST_PACKAGE: u8 = 64;

/// How many findings a report names before it stops listing.
const MAX_REPORTED: usize = 40;

/// The header the writer puts on a fresh baseline.
const BASELINE_HEADER: &str = "\
# Legacy concept names still in the tree: files and matches per concept,
# counted from config/naming/concept_map.toml.
#
# The numbers only go DOWN. Raise one and the gate fails: a legacy name was
# added. Lower one and the gate fails until the number here follows, so
# progress cannot go unrecorded.
#
# Regenerate with BUDLUM_CONCEPT_NAMES_WRITE=1 and
# `cargo run --release --manifest-path xtask/gates/Cargo.toml -- concept-names`.
# The writer refuses to raise a number, so the variable cannot record a
# regression and this file is never edited by hand.
#
# Format: <concept> TAB <files> TAB <matches>
";

/// One atom of a pattern. A group's alternatives nest, so a group is an atom
/// that holds a whole pattern.
enum Atom {
    Literal(char),
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
    Boundary,
    Start,
    End,
    Group(Vec<Sequence>),
}

/// An atom plus the only quantifier the map uses.
struct Step {
    atom: Atom,
    optional: bool,
}

/// One alternative: the atoms that have to match in order.
type Sequence = Vec<Step>;

/// One `patterns` entry, compiled.
struct Pattern {
    insensitive: bool,
    alts: Vec<Sequence>,
    /// A literal every match must contain, used to skip lines cheaply. `None`
    /// when the pattern holds no run of two literal characters.
    needle: Option<String>,
}

/// One record of the map, compiled.
struct Concept {
    name: String,
    owner: String,
    patterns: Vec<Pattern>,
    paths: Vec<String>,
    allow_paths: Vec<String>,
}

/// The map, as the gate reads it.
struct Map {
    absolute: bool,
    global_allow: Vec<String>,
    concepts: Vec<Concept>,
}

/// Files and matches for one concept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Count {
    files: usize,
    matches: usize,
}

/// A TOML value, reduced to the three shapes the map uses.
enum Value {
    Text(String),
    List(Vec<String>),
    Bare(String),
}

/// Lowercase one character for case-insensitive comparison.
///
/// A character whose lowercase form expands to more than one character (the
/// dotted capital I of Turkish text is the case that appears here) keeps the
/// first, so the fold is one character in and one character out.
fn fold(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

/// Whether a character is a word character for `\\b`. `_` counts, because the
/// map searches identifiers as well as prose.
fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn same_char(left: char, right: char, insensitive: bool) -> bool {
    if insensitive {
        fold(left) == fold(right)
    } else {
        left == right
    }
}

/// Read one character class, starting after its `[`.
fn parse_class(text: &[char], start: usize) -> Result<(Atom, usize), String> {
    let mut i = start;
    let mut negated = false;
    if text.get(i) == Some(&'^') {
        negated = true;
        i += 1;
    }
    let mut ranges: Vec<(char, char)> = Vec::new();
    let mut first = true;
    while let Some(c) = text.get(i) {
        if *c == ']' && !first {
            return Ok((Atom::Class { negated, ranges }, i + 1));
        }
        first = false;
        let next = text.get(i + 1);
        let after = text.get(i + 2);
        if next == Some(&'-') && after.is_some_and(|a| *a != ']') {
            ranges.push((*c, after.copied().unwrap_or(*c)));
            i += 3;
            continue;
        }
        ranges.push((*c, *c));
        i += 1;
    }
    Err(String::from(
        "a character class does not close; the pattern language has no `[` without `]`",
    ))
}

/// Parse one atom, returning it and the position after it.
fn parse_atom(text: &[char], start: usize, source: &str) -> Result<(Atom, usize), String> {
    let Some(c) = text.get(start) else {
        return Err(format!("`{source}` ends where an atom was expected"));
    };
    match *c {
        '(' => {
            let (alts, next) = parse_alts(text, start + 1, Some(')'), source)?;
            Ok((Atom::Group(alts), next))
        }
        '[' => parse_class(text, start + 1),
        '\\' => {
            let Some(escaped) = text.get(start + 1) else {
                return Err(format!("`{source}` ends in a dangling escape"));
            };
            if *escaped == 'b' {
                Ok((Atom::Boundary, start + 2))
            } else {
                Ok((Atom::Literal(*escaped), start + 2))
            }
        }
        '^' => Ok((Atom::Start, start + 1)),
        '$' => Ok((Atom::End, start + 1)),
        ')' | '*' | '?' | '+' => Err(format!(
            "`{source}` uses `{c}` where the pattern language does not allow it"
        )),
        '.' => Err(format!(
            "`{source}` uses `.`, and the pattern language has no wildcard. Write the \
             character to look for, or `\\.` for a full stop."
        )),
        _ => Ok((Atom::Literal(*c), start + 1)),
    }
}

/// Parse alternatives until a terminator, or to the end of the pattern.
fn parse_alts(
    text: &[char],
    start: usize,
    terminator: Option<char>,
    source: &str,
) -> Result<(Vec<Sequence>, usize), String> {
    let mut alts: Vec<Sequence> = Vec::new();
    let mut seq: Sequence = Vec::new();
    let mut i = start;
    while let Some(c) = text.get(i) {
        if *c == '|' {
            alts.push(std::mem::take(&mut seq));
            i += 1;
            continue;
        }
        if terminator == Some(*c) {
            alts.push(std::mem::take(&mut seq));
            return Ok((alts, i + 1));
        }
        let (atom, next) = parse_atom(text, i, source)?;
        i = next;
        let mut optional = false;
        if text.get(i) == Some(&'?') {
            optional = true;
            i += 1;
        }
        if let Some(quantifier) = text.get(i) {
            if matches!(*quantifier, '*' | '+' | '{') {
                return Err(format!(
                    "`{source}` uses `{quantifier}`, which the map's pattern language does \
                     not support. A repeated or wildcard pattern needs a decision, not a \
                     silently different count."
                ));
            }
        }
        seq.push(Step { atom, optional });
    }
    if terminator.is_some() {
        return Err(format!("`{source}` opens a group it does not close"));
    }
    alts.push(seq);
    Ok((alts, i))
}

/// Compile one `patterns` entry.
fn compile_pattern(source: &str) -> Result<Pattern, String> {
    let mut body = source;
    let mut insensitive = false;
    if let Some(rest) = source.strip_prefix("(?i)") {
        insensitive = true;
        body = rest;
    }
    if body.contains("(?") {
        return Err(format!(
            "`{source}` carries an inline flag the pattern language does not model; \
             `(?i)` at the start of a pattern is the only flag the map uses"
        ));
    }
    let chars: Vec<char> = body.chars().collect();
    let (alts, _) = parse_alts(&chars, 0, None, source)?;
    let needle = needle_of(insensitive, &alts);
    Ok(Pattern {
        insensitive,
        alts,
        needle,
    })
}

/// The longest run of literal characters in one alternative.
fn literal_run(seq: &[Step]) -> String {
    let mut best = String::new();
    let mut run = String::new();
    for step in seq {
        let extends = match &step.atom {
            Atom::Literal(c) if !step.optional => Some(*c),
            _ => None,
        };
        if let Some(c) = extends {
            run.push(c);
            continue;
        }
        if run.chars().count() > best.chars().count() {
            best = std::mem::take(&mut run);
        } else {
            run.clear();
        }
    }
    if run.chars().count() > best.chars().count() {
        best = run;
    }
    best
}

/// The literal every match must contain, or `None` when no run of two literal
/// characters exists.
fn needle_of(insensitive: bool, alts: &[Sequence]) -> Option<String> {
    let mut best = String::new();
    for seq in alts {
        let run = literal_run(seq);
        if run.chars().count() > best.chars().count() {
            best = run;
        }
    }
    if best.chars().count() < 2 {
        return None;
    }
    if insensitive {
        Some(best.chars().map(fold).collect())
    } else {
        Some(best)
    }
}

/// Match one atom at `pos`, returning the position after it.
fn match_atom(atom: &Atom, text: &[char], pos: usize, insensitive: bool) -> Option<usize> {
    match atom {
        Atom::Literal(expected) => {
            let actual = *text.get(pos)?;
            same_char(*expected, actual, insensitive).then_some(pos + 1)
        }
        Atom::Class { negated, ranges } => {
            let actual = *text.get(pos)?;
            let folded = if insensitive { fold(actual) } else { actual };
            let hit = ranges.iter().any(|(lo, hi)| {
                let lo = if insensitive { fold(*lo) } else { *lo };
                let hi = if insensitive { fold(*hi) } else { *hi };
                (lo..=hi).contains(&folded)
            });
            (hit != *negated).then_some(pos + 1)
        }
        Atom::Boundary => {
            let before = pos > 0 && text.get(pos - 1).is_some_and(|c| is_word(*c));
            let after = text.get(pos).is_some_and(|c| is_word(*c));
            (before != after).then_some(pos)
        }
        Atom::Start => (pos == 0).then_some(pos),
        Atom::End => (pos == text.len()).then_some(pos),
        Atom::Group(alts) => match_alts(alts, text, pos, insensitive),
    }
}

/// Match the alternatives of a pattern or of a group at `pos`.
///
/// The first alternative that matches wins, which is the order a reader expects
/// from `a|ab` and the order the map is written in.
fn match_alts(alts: &[Sequence], text: &[char], pos: usize, insensitive: bool) -> Option<usize> {
    for seq in alts {
        if let Some(end) = match_seq(seq, text, pos, insensitive, 0) {
            return Some(end);
        }
    }
    None
}

/// Match one alternative from `index` on.
///
/// `?` is the only quantifier, so the greedy branch is tried first and the
/// shorter parse is tried when the rest of the sequence does not match.
fn match_seq(
    seq: &[Step],
    text: &[char],
    pos: usize,
    insensitive: bool,
    index: usize,
) -> Option<usize> {
    let Some(step) = seq.get(index) else {
        return Some(pos);
    };
    if step.optional {
        if let Some(after) = match_atom(&step.atom, text, pos, insensitive) {
            if let Some(end) = match_seq(seq, text, after, insensitive, index + 1) {
                return Some(end);
            }
        }
        return match_seq(seq, text, pos, insensitive, index + 1);
    }
    let after = match_atom(&step.atom, text, pos, insensitive)?;
    match_seq(seq, text, after, insensitive, index + 1)
}

/// Fold a whole line, so the needle check and the matcher agree on case.
fn fold_line(line: &str) -> String {
    line.chars().map(fold).collect()
}

/// Count the matches of one pattern on one line.
fn count_line(pattern: &Pattern, text: &str, chars: &[char], folded: &str) -> usize {
    if let Some(needle) = &pattern.needle {
        let haystack = if pattern.insensitive { folded } else { text };
        if !haystack.contains(needle.as_str()) {
            return 0;
        }
    }
    let mut total = 0usize;
    let mut pos = 0usize;
    while pos <= chars.len() {
        if let Some(end) = match_alts(&pattern.alts, chars, pos, pattern.insensitive) {
            total += 1;
            pos = if end > pos { end } else { pos + 1 };
        } else {
            pos += 1;
        }
    }
    total
}

/// Drop a trailing `#` comment, leaving the `#` characters inside strings alone.
fn strip_comment(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::new();
    let mut quote: Option<char> = None;
    let mut i = 0usize;
    while let Some(c) = chars.get(i) {
        if let Some(open) = quote {
            if *c == '\\' && open == '"' {
                let next = chars.get(i + 1).copied().unwrap_or('\\');
                out.push(*c);
                out.push(next);
                i += 2;
                continue;
            }
            if *c == open {
                quote = None;
            }
            out.push(*c);
        } else if *c == '"' || *c == '\'' {
            quote = Some(*c);
            out.push(*c);
        } else if *c == '#' {
            break;
        } else {
            out.push(*c);
        }
        i += 1;
    }
    out
}

/// Read a quoted string starting at `start`, returning it and the next position.
fn take_quoted(text: &[char], start: usize) -> Result<(String, usize), String> {
    let Some(quote) = text.get(start).copied() else {
        return Err(String::from("a value ends where a string was expected"));
    };
    let mut out = String::new();
    let mut i = start + 1;
    while let Some(c) = text.get(i) {
        if quote == '"' && *c == '\\' {
            let Some(next) = text.get(i + 1).copied() else {
                return Err(String::from("a string in the map ends in a dangling escape"));
            };
            out.push(match next {
                'n' => '\n',
                't' => '\t',
                other => other,
            });
            i += 2;
            continue;
        }
        if *c == quote {
            return Ok((out, i + 1));
        }
        out.push(*c);
        i += 1;
    }
    Err(String::from("a string in the map is not closed"))
}

/// Read one value: a string, a bare word, or an array of strings.
fn parse_value(raw: &str) -> Result<Value, String> {
    let raw = raw.trim();
    if raw.starts_with('[') {
        let chars: Vec<char> = raw.chars().collect();
        if chars.last() != Some(&']') {
            return Err(String::from("an array in the map is not closed"));
        }
        let mut items: Vec<String> = Vec::new();
        let mut i = 1usize;
        while let Some(c) = chars.get(i) {
            if *c == '"' || *c == '\'' {
                let (item, next) = take_quoted(&chars, i)?;
                items.push(item);
                i = next;
                continue;
            }
            i += 1;
        }
        return Ok(Value::List(items));
    }
    if raw.starts_with('"') || raw.starts_with('\'') {
        let chars: Vec<char> = raw.chars().collect();
        let (item, _) = take_quoted(&chars, 0)?;
        return Ok(Value::Text(item));
    }
    Ok(Value::Bare(raw.to_string()))
}

/// Read the map as `key = value` statements, joining an array that spans lines.
fn statements(text: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let mut buffer = String::new();
    for line in text.lines() {
        let line = strip_comment(line);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !buffer.is_empty() {
            buffer.push(' ');
        }
        buffer.push_str(line);
        if buffer.matches('[').count() > buffer.matches(']').count() {
            continue;
        }
        out.push(std::mem::take(&mut buffer));
    }
    if !buffer.is_empty() {
        return Err(String::from(
            "the map ends inside an array; every array has to close",
        ));
    }
    Ok(out)
}

/// One string value, or an error naming the record and the key.
fn text_of(value: Option<&Value>, key: &str, who: &str) -> Result<String, String> {
    match value {
        Some(Value::Text(text)) if !text.is_empty() => Ok(text.clone()),
        Some(_) => Err(format!("{who}: `{key}` is not a non-empty string")),
        None => Err(format!("{who}: `{key}` is missing")),
    }
}

/// One array-of-strings value; a missing key is an empty list.
fn list_of(value: Option<&Value>, key: &str, who: &str) -> Result<Vec<String>, String> {
    match value {
        Some(Value::List(items)) => Ok(items.clone()),
        Some(_) => Err(format!("{who}: `{key}` is not an array of strings")),
        None => Ok(Vec::new()),
    }
}

/// A directory prefix, or an exact file, with no way out of the tree.
fn validate_paths(paths: &[String], key: &str, who: &str) -> Result<(), String> {
    for path in paths {
        let trimmed = path.strip_suffix('/').unwrap_or(path);
        let bad = trimmed.is_empty()
            || path.starts_with('/')
            || path.contains('\\')
            || trimmed
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..");
        if bad {
            return Err(format!(
                "{who}: `{key}` holds `{path}`, which is not a repository-relative path"
            ));
        }
    }
    Ok(())
}

fn is_known_package(owner: &str) -> bool {
    let Some(digits) = owner.strip_prefix("WP-") else {
        return false;
    };
    if digits.len() != 2 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    digits
        .parse::<u8>()
        .is_ok_and(|number| (1..=LAST_PACKAGE).contains(&number))
}

/// Build one record, refusing anything the gate cannot read exactly.
fn build_concept(record: &BTreeMap<String, Value>, index: usize) -> Result<Concept, String> {
    let unknown = format!("concept #{index}");
    let old = list_of(record.get("old"), "old", &unknown)?;
    let Some(name) = old.first().cloned() else {
        return Err(format!(
            "{unknown}: `old` is empty, so the record names no concept"
        ));
    };
    let who = format!("concept `{name}`");
    for key in ["new_code", "term_en", "term_tr", "area", "reason"] {
        text_of(record.get(key), key, &who)?;
    }
    let owner = text_of(record.get("owner"), "owner", &who)?;
    if !is_known_package(&owner) {
        let last = LAST_PACKAGE;
        return Err(format!(
            "{who}: owner `{owner}` is not a package the directive defines \
             (`WP-01` to `WP-{last}`)"
        ));
    }
    let sources = list_of(record.get("patterns"), "patterns", &who)?;
    if sources.is_empty() {
        return Err(format!(
            "{who}: `patterns` is empty, so the record bans nothing"
        ));
    }
    let mut patterns = Vec::new();
    for source in sources {
        patterns.push(compile_pattern(&source).map_err(|e| format!("{who}: {e}"))?);
    }
    let paths = list_of(record.get("paths"), "paths", &who)?;
    validate_paths(&paths, "paths", &who)?;
    let allow_paths = list_of(record.get("allow_paths"), "allow_paths", &who)?;
    validate_paths(&allow_paths, "allow_paths", &who)?;
    Ok(Concept {
        name,
        owner,
        patterns,
        paths,
        allow_paths,
    })
}

/// Read and validate the map.
fn load_map(root: &Path) -> Result<Map, String> {
    let path = root.join(MAP_PATH);
    let text = fs::read_to_string(&path).map_err(|e| format!("{MAP_PATH}: {e}"))?;
    let mut head: BTreeMap<String, Value> = BTreeMap::new();
    let mut records: Vec<BTreeMap<String, Value>> = Vec::new();
    for statement in statements(&text)? {
        if statement == "[[concept]]" {
            records.push(BTreeMap::new());
            continue;
        }
        if statement.starts_with('[') {
            return Err(format!(
                "{MAP_PATH}: `{statement}` is not a `[[concept]]` table"
            ));
        }
        let Some((key, value)) = statement.split_once('=') else {
            return Err(format!("{MAP_PATH}: `{statement}` is not `key = value`"));
        };
        let parsed = parse_value(value)?;
        match records.last_mut() {
            Some(record) => {
                record.insert(key.trim().to_string(), parsed);
            }
            None => {
                head.insert(key.trim().to_string(), parsed);
            }
        }
    }
    let schema = match head.get("schema") {
        Some(Value::Bare(number)) => number.clone(),
        _ => return Err(format!("{MAP_PATH}: `schema` is missing or not a number")),
    };
    if schema != "1" {
        return Err(format!("{MAP_PATH}: `schema` must be 1, found `{schema}`"));
    }
    let mode = text_of(head.get("mode"), "mode", MAP_PATH)?;
    let absolute = match mode.as_str() {
        "count" => false,
        "absolute" => true,
        other => {
            return Err(format!(
                "{MAP_PATH}: `mode` must be `count` or `absolute`, found `{other}`"
            ))
        }
    };
    let global_allow = list_of(head.get("global_allow_paths"), "global_allow_paths", MAP_PATH)?;
    validate_paths(&global_allow, "global_allow_paths", MAP_PATH)?;
    if records.is_empty() {
        return Err(format!(
            "{MAP_PATH}: no `[[concept]]` records, so the gate would ban nothing"
        ));
    }
    let mut concepts = Vec::new();
    for (index, record) in records.iter().enumerate() {
        concepts.push(build_concept(record, index)?);
    }
    Ok(Map {
        absolute,
        global_allow,
        concepts,
    })
}

/// Collect every scanned file, in a deterministic order.
fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for rel in SCAN_ROOTS {
        let base = root.join(*rel);
        if base.is_dir() {
            walk_into(&base, &mut out);
        }
    }
    out.sort();
    out
}

fn walk_into(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            let name = entry.file_name();
            if !SKIP_DIRS.contains(&name.to_string_lossy().as_ref()) {
                walk_into(&path, out);
            }
            continue;
        }
        if fs::metadata(&path).is_ok_and(|meta| meta.len() > MAX_FILE_BYTES) {
            continue;
        }
        out.push(path);
    }
}

/// Whether a relative path is under one of the prefixes, or is the file named.
fn under(rel: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|prefix| {
        if prefix.ends_with('/') {
            rel.starts_with(prefix.as_str())
        } else {
            rel == prefix
        }
    })
}

/// Count every concept over the tree.
fn measure(root: &Path, map: &Map) -> Result<BTreeMap<String, Count>, String> {
    let mut counts: BTreeMap<String, Count> = BTreeMap::new();
    for concept in &map.concepts {
        counts.insert(concept.name.clone(), Count::default());
    }
    let mut scanned = 0usize;
    for path in walk(root) {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if under(&rel, &map.global_allow) {
            continue;
        }
        let wanted: Vec<bool> = map
            .concepts
            .iter()
            .map(|concept| {
                (concept.paths.is_empty() || under(&rel, &concept.paths))
                    && !under(&rel, &concept.allow_paths)
            })
            .collect();
        if !wanted.iter().any(|flag| *flag) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        let mut per_file = vec![0usize; map.concepts.len()];
        for line in text.lines() {
            let chars: Vec<char> = line.chars().collect();
            let folded = fold_line(line);
            for (index, concept) in map.concepts.iter().enumerate() {
                if !wanted.get(index).copied().unwrap_or(false) {
                    continue;
                }
                for pattern in &concept.patterns {
                    let hits = count_line(pattern, line, &chars, &folded);
                    if let Some(slot) = per_file.get_mut(index) {
                        *slot += hits;
                    }
                }
            }
        }
        for (index, concept) in map.concepts.iter().enumerate() {
            let hits = per_file.get(index).copied().unwrap_or(0);
            if hits == 0 {
                continue;
            }
            if let Some(count) = counts.get_mut(&concept.name) {
                count.files += 1;
                count.matches += hits;
            }
        }
    }
    if scanned == 0 {
        return Err(format!(
            "no source file was readable under {}; the gate would be vacuous",
            root.display()
        ));
    }
    Ok(counts)
}

/// Read the ratchet.
fn parse_baseline(root: &Path) -> Result<BTreeMap<String, Count>, String> {
    let path = root.join(BASELINE_PATH);
    let text = fs::read_to_string(&path).map_err(|e| format!("{BASELINE_PATH}: {e}"))?;
    let mut out: BTreeMap<String, Count> = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim_end();
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let line_number = index + 1;
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 3 {
            return Err(format!(
                "{BASELINE_PATH}:{line_number}: expected `<concept>` TAB `<files>` TAB \
                 `<matches>`"
            ));
        }
        let name = parts.first().copied().unwrap_or_default().trim();
        if name.is_empty() {
            return Err(format!(
                "{BASELINE_PATH}:{line_number}: the concept name is empty"
            ));
        }
        let mut numbers = [0usize; 2];
        for (slot, raw) in numbers.iter_mut().zip(parts.iter().skip(1)) {
            let field = raw.trim();
            *slot = field.parse::<usize>().map_err(|e| {
                format!("{BASELINE_PATH}:{line_number}: `{field}` is not a number: {e}")
            })?;
        }
        let count = Count {
            files: numbers.first().copied().unwrap_or(0),
            matches: numbers.get(1).copied().unwrap_or(0),
        };
        if out.insert(name.to_string(), count).is_some() {
            return Err(format!(
                "{BASELINE_PATH}:{line_number}: `{name}` is listed twice"
            ));
        }
    }
    Ok(out)
}

/// Compare one measured count with its recorded one.
fn judgement(concept: &Concept, measured: Count, baseline: Count) -> Result<(), String> {
    let name = &concept.name;
    let owner = &concept.owner;
    let now_files = measured.files;
    let now_matches = measured.matches;
    let recorded_files = baseline.files;
    let recorded_matches = baseline.matches;
    if measured.files > baseline.files || measured.matches > baseline.matches {
        return Err(format!(
            "{name} ({owner}): the count rose to {now_files} file(s) / {now_matches} \
             match(es), above the baseline {recorded_files} / {recorded_matches}. A legacy \
             name was added; use the code name the map gives."
        ));
    }
    if measured != baseline {
        return Err(format!(
            "{name} ({owner}): the count fell to {now_files} file(s) / {now_matches} \
             match(es) and the baseline still says {recorded_files} / {recorded_matches}. \
             Lower it with {WRITE_ENV}=1."
        ));
    }
    Ok(())
}

/// Rewrite the ratchet from the tree. It never raises a number.
fn write_baseline(
    root: &Path,
    counts: &BTreeMap<String, Count>,
    map: &Map,
) -> Result<String, String> {
    let previous: BTreeMap<String, Count> = parse_baseline(root).unwrap_or_default();
    let mut body = String::from(BASELINE_HEADER);
    for concept in &map.concepts {
        let Some(count) = counts.get(&concept.name) else {
            continue;
        };
        if let Some(old) = previous.get(&concept.name) {
            if count.files > old.files || count.matches > old.matches {
                let recorded_files = old.files;
                let recorded_matches = old.matches;
                let now_files = count.files;
                let now_matches = count.matches;
                let name = &concept.name;
                return Err(format!(
                    "refusing to raise `{name}` from {recorded_files} file(s) / \
                     {recorded_matches} match(es) to {now_files} / {now_matches}. A rising \
                     count is a regression, not a baseline update."
                ));
            }
        }
        let name = &concept.name;
        let files = count.files;
        let matches = count.matches;
        body.push_str(&format!("{name}\t{files}\t{matches}\n"));
    }
    fs::write(root.join(BASELINE_PATH), body).map_err(|e| format!("{BASELINE_PATH}: {e}"))?;
    let total = map.concepts.len();
    Ok(format!(
        "{BASELINE_PATH} rewritten from the tree: {total} concept(s)."
    ))
}

/// # Errors
///
/// Returns a finding for every concept whose count rose, every count that fell
/// without the baseline following, every concept the baseline lists and the map
/// does not, a missing or malformed map, and a missing baseline. In `absolute`
/// mode a single match is a finding.
pub fn run(root: &Path) -> Result<String, String> {
    let map = load_map(root)?;
    let counts = measure(root, &map)?;
    if std::env::var(WRITE_ENV).is_ok_and(|value| value == "1") {
        return write_baseline(root, &counts, &map);
    }
    let baseline = parse_baseline(root)?;
    let mut findings: Vec<String> = Vec::new();
    let mut legacy_matches = 0usize;
    for concept in &map.concepts {
        let measured = counts.get(&concept.name).copied().unwrap_or_default();
        legacy_matches += measured.matches;
        let recorded = baseline.get(&concept.name).copied();
        let Some(recorded) = recorded else {
            let name = &concept.name;
            findings.push(format!(
                "{name}: the concept is missing from {BASELINE_PATH}; add it with \
                 {WRITE_ENV}=1"
            ));
            continue;
        };
        if map.absolute && measured.matches > 0 {
            let name = &concept.name;
            let left = measured.matches;
            findings.push(format!(
                "{name}: the map is in `absolute` mode and {left} match(es) remain"
            ));
            continue;
        }
        if let Err(finding) = judgement(concept, measured, recorded) {
            findings.push(finding);
        }
    }
    for name in baseline.keys() {
        if !map.concepts.iter().any(|concept| &concept.name == name) {
            findings.push(format!(
                "{name}: {BASELINE_PATH} lists a concept the map does not carry"
            ));
        }
    }
    if !findings.is_empty() {
        let total = findings.len();
        let mut msg = format!("{total} concept-name finding(s):\n");
        for finding in findings.iter().take(MAX_REPORTED) {
            msg.push_str("  ");
            msg.push_str(finding);
            msg.push('\n');
        }
        return Err(msg);
    }
    let total = map.concepts.len();
    let mode = if map.absolute { "absolute" } else { "count" };
    Ok(format!(
        "concept-names: {total} concept(s) at the baseline, {legacy_matches} legacy \
         match(es) left, mode {mode}."
    ))
}

/// A fixture map: one concept, one pattern, a valid owner.
///
/// The fixture names a concept the tree does not carry. A canary that wrote a
/// real legacy name into this file would count it in the ratchet it is testing,
/// and the gate would be measuring its own fixtures.
const FIXTURE_MAP: &str = "\
schema = 1
mode = \"count\"
global_allow_paths = [\"config/naming/\"]

[[concept]]
old = [\"FixtureName\"]
patterns = ['(?i)fixturename']
new_code = \"fixture_code\"
term_en = \"fixture concept\"
term_tr = \"fixture\"
area = \"fixture\"
owner = \"WP-12\"
reason = \"Fixture record for the self-test.\"
";

/// Write a fixture tree: the map, an optional baseline, and one source file.
fn stage(root: &Path, map: &str, baseline: Option<&str>, lines: &[&str]) -> Result<(), String> {
    if root.exists() {
        fs::remove_dir_all(root).map_err(|e| format!("cannot clear the fixture tree: {e}"))?;
    }
    for dir in ["config/naming", ".github", "src"] {
        fs::create_dir_all(root.join(dir)).map_err(|e| format!("cannot create {dir}: {e}"))?;
    }
    fs::write(root.join(MAP_PATH), map).map_err(|e| format!("cannot write the map: {e}"))?;
    if let Some(text) = baseline {
        fs::write(root.join(BASELINE_PATH), text)
            .map_err(|e| format!("cannot write the baseline: {e}"))?;
    }
    let mut source = String::new();
    for line in lines {
        source.push_str(line);
        source.push('\n');
    }
    fs::write(root.join("src/fixture.rs"), source)
        .map_err(|e| format!("cannot write the fixture source: {e}"))?;
    Ok(())
}

/// The canaries: every arm of the gate, exercised on a scratch tree.
fn canaries(root: &Path) -> Result<(), String> {
    stage(root, FIXTURE_MAP, Some("FixtureName\t0\t0\n"), &["fn clean() {}"])?;
    run(root)?;

    stage(
        root,
        FIXTURE_MAP,
        Some("FixtureName\t0\t0\n"),
        &["fn clean() {}", "// FixtureName was seen here"],
    )?;
    if run(root).is_ok() {
        return Err(String::from(
            "canary: an injected legacy name was not caught",
        ));
    }

    stage(root, FIXTURE_MAP, Some("FixtureName\t1\t1\n"), &["fn clean() {}"])?;
    if run(root).is_ok() {
        return Err(String::from(
            "canary: a baseline higher than the measured count was not reported",
        ));
    }

    stage(
        root,
        FIXTURE_MAP,
        Some("FixtureName\t0\t0\n"),
        &["fn clean() {}", "// FixtureName was seen here"],
    )?;
    let map = load_map(root)?;
    let counts = measure(root, &map)?;
    if write_baseline(root, &counts, &map).is_ok() {
        return Err(String::from(
            "canary: the baseline writer raised a count instead of refusing",
        ));
    }

    let bad_owner = FIXTURE_MAP.replace("WP-12", "WP-99");
    stage(root, &bad_owner, Some("FixtureName\t0\t0\n"), &["fn clean() {}"])?;
    if load_map(root).is_ok() {
        return Err(String::from(
            "canary: an owner outside WP-01 to WP-64 was accepted",
        ));
    }

    let bad_pattern = FIXTURE_MAP.replace("'(?i)filiz'", "'(?i)fil+'");
    stage(root, &bad_pattern, Some("FixtureName\t0\t0\n"), &["fn clean() {}"])?;
    if load_map(root).is_ok() {
        return Err(String::from(
            "canary: an unsupported quantifier was accepted instead of refused",
        ));
    }
    Ok(())
}

/// # Errors
///
/// Returns the first canary that misbehaves, or the scratch directory that could
/// not be created.
pub fn self_test() -> Result<String, String> {
    let scratch = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-concept-names")?;
    let outcome = canaries(&scratch);
    let _ = fs::remove_dir_all(&scratch);
    outcome?;
    Ok(String::from(
        "Self-test OK: a clean tree passes, an injected legacy name is caught, a baseline \
         that is too high is reported, the writer refuses to raise a count, an unknown \
         owner is refused, and an unsupported quantifier is refused.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(prefix: &str) -> PathBuf {
        crate::gates::rust_literals::exclusive_scratch_dir(prefix)
            .unwrap_or_else(|e| panic!("scratch dir: {e}"))
    }

    #[test]
    fn concept_names_gate_catches_injected_name() {
        let dir = scratch("budlum-concept-names-injected");
        stage(&dir, FIXTURE_MAP, Some("FixtureName\t0\t0\n"), &["fn clean() {}"])
            .expect("fixture");
        run(&dir).expect("a clean tree passes");
        stage(
            &dir,
            FIXTURE_MAP,
            Some("FixtureName\t0\t0\n"),
            &["fn clean() {}", "// FixtureName was seen here"],
        )
        .expect("fixture");
        assert!(run(&dir).is_err(), "the injected name was not caught");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concept_names_baseline_only_decreases() {
        let dir = scratch("budlum-concept-names-ratchet");
        stage(
            &dir,
            FIXTURE_MAP,
            Some("FixtureName\t0\t0\n"),
            &["fn clean() {}", "// FixtureName was seen here"],
        )
        .expect("fixture");
        assert!(run(&dir).is_err(), "a rise was not reported");
        let map = load_map(&dir).expect("map");
        let counts = measure(&dir, &map).expect("measure");
        assert!(
            write_baseline(&dir, &counts, &map).is_err(),
            "the writer raised a count"
        );
        stage(&dir, FIXTURE_MAP, Some("FixtureName\t1\t1\n"), &["fn clean() {}"])
            .expect("fixture");
        assert!(run(&dir).is_err(), "a fall the baseline did not follow passed");
        stage(&dir, FIXTURE_MAP, Some("FixtureName\t0\t0\n"), &["fn clean() {}"]).expect("fixture");
        run(&dir).expect("a lowered baseline passes");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concept_map_owner_is_a_known_package() {
        let dir = scratch("budlum-concept-names-owner");
        let bad = FIXTURE_MAP.replace("WP-12", "WP-65");
        stage(&dir, &bad, Some("FixtureName\t0\t0\n"), &["fn clean() {}"]).expect("fixture");
        assert!(load_map(&dir).is_err(), "WP-65 was accepted");
        stage(&dir, FIXTURE_MAP, Some("FixtureName\t0\t0\n"), &["fn clean() {}"]).expect("fixture");
        assert!(load_map(&dir).is_ok(), "WP-12 was refused");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn patterns_match_case_insensitively_and_on_classes() {
        let pattern = compile_pattern("(?i)abc[0-9]").expect("pattern");
        let text = "ABC7";
        let chars: Vec<char> = text.chars().collect();
        let folded = fold_line(text);
        assert_eq!(count_line(&pattern, text, &chars, &folded), 1);
    }

    #[test]
    fn unsupported_quantifiers_are_refused() {
        assert!(compile_pattern("(?i)fil+").is_err());
        assert!(compile_pattern("(?i)fil.*").is_err());
        assert!(compile_pattern("(?m)filiz").is_err());
    }
}
