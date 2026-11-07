//! Old concept names are counted, and the count only goes down.
//!
//! # The rule
//!
//! Two concept names stay in this architecture: `BudZero` and `B.U.D.`
//! Everything else that was named by metaphor - a sprout for the leader
//! election, a fungal symbiosis for shared security, a botanical market for
//! the data market, a bud for a sealed object - is replaced by a professional
//! term that says what the thing does. The map of old name to new name lives
//! in `config/naming/concept_map.toml`; its English register is
//! `docs/NAMING.md`. This file does not quote the old names outside its
//! canary map, so the gate is not one of the files its own count reports.
//!
//! The rename is not done in one sweep. Fifty packages touch these paths and
//! each one renames what it owns, so a gate that failed on every remaining
//! occurrence would fail on every commit until the last package lands, and a
//! gate that fails on every commit gets switched off. That is worse than no
//! gate: the count would then be free to grow.
//!
//! So this is a ratchet, the same shape as `udeps`, `tree-is-english` and
//! `dead-public-api`. `.github/concept-names-baseline.txt` records, per map
//! record, how many files still carry the old name and how many times. The
//! gate fails when
//!
//!   * a record's file count or match count is **higher** than recorded, or
//!   * a record is **absent** from the baseline, or
//!   * a count is **lower** than recorded and the file was not updated, or
//!   * a record in the map carries an owner that is not a package in the
//!     dependency table.
//!
//! The third arm is the one that makes the ratchet one-way: a rename that does
//! not lower the recorded number is a rename nobody can see, and the next
//! package then has no way to know how much is left. Finishing the rename is
//! the only way to stay green.
//!
//! # The last step
//!
//! `mode = "count"` in the map is the ratchet. The final documentation package
//! sets it to `"absolute"`, after which a single occurrence of a single old
//! name fails. The switch is a one-word change in the map, not a rewrite of
//! this gate, so the gate cannot be the thing that quietly keeps the ratchet
//! alive after the counter reached zero.
//!
//! # Why this gate has its own matcher
//!
//! The map's `patterns` are written in `regex` syntax: `(?i)`, `\b`, `^`, `$`,
//! character classes, groups with alternation and the `?` quantifier. The gate
//! needs those and nothing more - no backreferences, no repetition counts, no
//! laziness, no lookaround - so it carries a matcher for exactly that subset
//! instead of a dependency, which is the same trade the other text gates made.
//! The subset is small enough to be checked: the matcher's behaviour is pinned
//! by the canaries below, and the baseline in the repository was produced by an
//! independent implementation of the same subset and agreed with it on every
//! record across the whole tree.
//!
//! A pattern the matcher cannot parse is a hard error, not a skipped pattern.
//! A gate that silently ignores one arm of a map is a gate that reports a
//! lower count than the tree carries.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Where the machine-readable map lives.
const MAP_PATH: &str = "config/naming/concept_map.toml";

/// Where the recorded counts live.
const BASELINE_PATH: &str = ".github/concept-names-baseline.txt";

/// Roots the map is applied to.
///
/// The map's own `paths` field narrows a record further; a record without one
/// is searched in all of these.
const SCAN_ROOTS: &[&str] = &[
    "src/",
    "crates/",
    "budzero/",
    "execution/",
    "mobile/",
    "xtask/",
    "docs/",
    "config/",
    "proto/",
    "contracts/",
];

/// Directories never walked.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".cargo",
    "corpus",
    "__pycache__",
];

/// Files never read.
const SKIP_FILES: &[&str] = &["Cargo.lock", "flake.lock", "imports.lock"];

/// Extensions never read: they carry bytes, not names.
const SKIP_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "ico", "pdf", "zip", "gz", "tar", "bin", "wasm", "so", "a", "o",
    "lock", "svg", "woff", "woff2", "ttf", "webp",
];

/// The package ids that may own a rename.
///
/// A typo in an `owner` field sends the rename to a package that does not
/// exist, which is how a name outlives the plan that removes it. The list is
/// the dependency table's id range.
const KNOWN_PACKAGES: &[&str] = &[
    "WP-01", "WP-02", "WP-03", "WP-04", "WP-05", "WP-06", "WP-07", "WP-08", "WP-09", "WP-10",
    "WP-11", "WP-12", "WP-13", "WP-14", "WP-15", "WP-16", "WP-17", "WP-18", "WP-19", "WP-20",
    "WP-21", "WP-22", "WP-23", "WP-24", "WP-25", "WP-26", "WP-27", "WP-28", "WP-29", "WP-30",
    "WP-31", "WP-32", "WP-33", "WP-34", "WP-35", "WP-36", "WP-37", "WP-38", "WP-39", "WP-40",
    "WP-41", "WP-42", "WP-43", "WP-44", "WP-45", "WP-46", "WP-47", "WP-48", "WP-49", "WP-50",
    "WP-51", "WP-52", "WP-53", "WP-54", "WP-55", "WP-56", "WP-57", "WP-58", "WP-59", "WP-60",
    "WP-61", "WP-62", "WP-63", "WP-64",
];

/// A scan that walked too few files proves nothing and must fail.
const VACUITY_FLOOR: usize = 50;

/// How many findings are listed before the report is truncated.
const MAX_REPORTED: usize = 30;

/// The map's two operating modes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum Mode {
    /// Counts are compared against the baseline and may only fall.
    #[default]
    Count,
    /// Any occurrence of any old name is a finding.
    Absolute,
}

/// One node of a compiled pattern.
enum Node {
    /// A literal character.
    Lit(char),
    /// A character class; `neg` is the leading `^`.
    Class { chars: Vec<char>, neg: bool },
    /// A group: the alternatives it may match.
    Group(Vec<Vec<Node>>),
    /// `?` or `*` around one node.
    Repeat { inner: Box<Node>, star: bool },
    /// `\b`.
    Boundary,
    /// `^`.
    Start,
    /// `$`.
    End,
}

/// A compiled `patterns` entry.
struct Pattern {
    /// The source text, kept so a finding can quote what matched.
    source: String,
    /// Whether `(?i)` was present.
    ci: bool,
    /// The top-level alternatives.
    alts: Vec<Vec<Node>>,
}

/// One `[[concept]]` record of the map.
struct Record {
    /// The old names, for reporting.
    old: Vec<String>,
    /// The compiled patterns.
    patterns: Vec<Pattern>,
    /// If non-empty, only these paths are searched.
    paths: Vec<String>,
    /// Paths inside the search that are exempt.
    allow_paths: Vec<String>,
    /// The new code name; also the record's key in the baseline.
    new_code: String,
    /// The package that renames it.
    owner: String,
}

/// The parsed map.
struct ConceptMap {
    mode: Mode,
    global_allow_paths: Vec<String>,
    records: Vec<Record>,
}

/// A `[[concept]]` record as it is being read, before its patterns compile.
#[derive(Default)]
struct Partial {
    old: Vec<String>,
    patterns: Vec<String>,
    paths: Vec<String>,
    allow_paths: Vec<String>,
    new_code: String,
    owner: String,
}

/// Where the map reader is.
#[derive(Default)]
struct MapState {
    mode: Mode,
    saw_mode: bool,
    global_allow_paths: Vec<String>,
    current: Option<Partial>,
    records: Vec<Record>,
}

// ---------------------------------------------------------------- reading

/// Strip a trailing `#` comment that is not inside a string.
fn strip_comment(line: &str) -> String {
    let mut out = String::new();
    let mut quote: Option<char> = None;
    let mut prev = '\0';
    for c in line.chars() {
        match quote {
            Some(q) => {
                if c == q && prev != '\\' {
                    quote = None;
                }
            }
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                } else if c == '#' {
                    break;
                }
            }
        }
        out.push(c);
        prev = c;
    }
    out
}

/// Split a TOML array body into its string members.
///
/// Both quote styles are accepted: the map writes its `patterns` in single
/// quotes (a literal string, so `\b` survives) and its other values in double
/// quotes. A member that is not a string is an error rather than a skip.
fn array_members(body: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let bytes: Vec<char> = body.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c == ',' || c.is_whitespace() {
            i += 1;
            continue;
        }
        if c != '\'' && c != '"' {
            return Err(format!(
                "an array member does not start with a quote: `{}`",
                body.trim()
            ));
        }
        let quote = c;
        i += 1;
        let mut value = String::new();
        let mut closed = false;
        while i < bytes.len() {
            let d = bytes[i];
            if d == '\\' && quote == '"' && i + 1 < bytes.len() {
                i += 1;
                match bytes[i] {
                    'n' => value.push('\n'),
                    't' => value.push('\t'),
                    '"' => value.push('"'),
                    '\\' => value.push('\\'),
                    other => value.push(other),
                }
                i += 1;
                continue;
            }
            if d == quote {
                closed = true;
                i += 1;
                break;
            }
            value.push(d);
            i += 1;
        }
        if !closed {
            return Err(format!("an unterminated string in array `{}`", body.trim()));
        }
        out.push(value);
    }
    Ok(out)
}

/// The value of `key = ...` on one line, quoted or bare.
///
/// The map writes its strings in quotes and its `schema` as a bare integer;
/// both are read here so the gate does not have to know which keys are
/// numbers. An empty value is an error rather than an empty string.
fn scalar_value(rest: &str) -> Result<String, String> {
    let trimmed = rest.trim();
    let first = trimmed.chars().next().unwrap_or(' ');
    if first == '"' || first == '\'' {
        let members = array_members(trimmed)?;
        return members
            .into_iter()
            .next()
            .ok_or_else(|| format!("an empty string value: `{trimmed}`"));
    }
    if trimmed.is_empty() {
        return Err(String::from("a key with no value"));
    }
    Ok(String::from(trimmed))
}

/// What one read of an array produced.
enum ArrayRead {
    /// The array closed; these are its members.
    Closed(Vec<String>),
    /// The array is still open; this is the text read so far.
    Open(String),
}

/// Read an array that starts at the beginning of `s` and may span lines.
///
/// The scan is string-aware, and it has to be: `patterns` entries are
/// character classes, so a single line of the map carries `]` characters that
/// belong to a pattern and not to the array. Stopping at the first `]` cuts a
/// diacritic-matching class in half, and a gate that reads half a pattern
/// counts half the tree.
fn read_array(s: &str) -> Result<ArrayRead, String> {
    let chars: Vec<char> = s.chars().collect();
    let mut quote: Option<char> = None;
    let mut depth = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some(q) => {
                if c == '\\' && q == '"' && i + 1 < chars.len() {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                '[' => depth += 1,
                ']' => {
                    if depth <= 1 {
                        let body: String = chars[1..i].iter().collect();
                        return Ok(ArrayRead::Closed(array_members(&body)?));
                    }
                    depth -= 1;
                }
                _ => {}
            },
        }
        i += 1;
    }
    Ok(ArrayRead::Open(String::from(s)))
}

/// Compile one pattern of the supported subset.
fn compile(src: &str) -> Result<Pattern, String> {
    let mut ci = false;
    let mut rest = src;
    if let Some(tail) = rest.strip_prefix("(?i)") {
        ci = true;
        rest = tail;
    }
    let chars: Vec<char> = rest.chars().collect();
    let mut pos = 0usize;
    let alts = parse_alternatives(&chars, &mut pos, None, src)?;
    if pos != chars.len() {
        return Err(format!("pattern `{src}` has a trailing `)` with no group"));
    }
    Ok(Pattern {
        source: String::from(src),
        ci,
        alts,
    })
}

/// Parse `a|b|c`, stopping at `close` (a `)` inside a group) or at the end.
fn parse_alternatives(
    chars: &[char],
    pos: &mut usize,
    close: Option<char>,
    src: &str,
) -> Result<Vec<Vec<Node>>, String> {
    let mut alts: Vec<Vec<Node>> = vec![Vec::new()];
    while *pos < chars.len() {
        let c = chars[*pos];
        if close == Some(c) {
            return Ok(alts);
        }
        if c == '|' {
            *pos += 1;
            alts.push(Vec::new());
            continue;
        }
        let node = parse_node(chars, pos, src)?;
        let last = alts.len() - 1;
        alts[last].push(node);
    }
    if close.is_some() {
        return Err(format!("pattern `{src}` has an unclosed group"));
    }
    Ok(alts)
}

/// Parse one node, applying a trailing quantifier if one follows.
fn parse_node(chars: &[char], pos: &mut usize, src: &str) -> Result<Node, String> {
    let c = chars[*pos];
    let node = match c {
        '(' => {
            *pos += 1;
            let alts = parse_alternatives(chars, pos, Some(')'), src)?;
            // `parse_alternatives` stops on the closing `)` rather than eating
            // it, and it errors if the input ends first, so the byte here is
            // the group's own close.
            *pos += 1;
            Node::Group(alts)
        }
        '[' => parse_class(chars, pos, src)?,
        '\\' => {
            *pos += 1;
            if *pos >= chars.len() {
                return Err(format!("pattern `{src}` ends in a backslash"));
            }
            let escaped = chars[*pos];
            *pos += 1;
            if escaped == 'b' {
                Node::Boundary
            } else {
                Node::Lit(escaped)
            }
        }
        '^' => {
            *pos += 1;
            Node::Start
        }
        '$' => {
            *pos += 1;
            Node::End
        }
        ')' | ']' => {
            return Err(format!("pattern `{src}` closes `{c}` with nothing open"));
        }
        other => {
            *pos += 1;
            Node::Lit(other)
        }
    };
    if *pos < chars.len() && (chars[*pos] == '?' || chars[*pos] == '*') {
        let star = chars[*pos] == '*';
        *pos += 1;
        return Ok(Node::Repeat {
            inner: Box::new(node),
            star,
        });
    }
    Ok(node)
}

/// Parse `[...]`, including ranges and a leading `^`.
fn parse_class(chars: &[char], pos: &mut usize, src: &str) -> Result<Node, String> {
    *pos += 1;
    let mut neg = false;
    if *pos < chars.len() && chars[*pos] == '^' {
        neg = true;
        *pos += 1;
    }
    let mut set: Vec<char> = Vec::new();
    let mut closed = false;
    while *pos < chars.len() {
        let c = chars[*pos];
        if c == ']' {
            *pos += 1;
            closed = true;
            break;
        }
        if c == '\\' {
            *pos += 1;
            if *pos >= chars.len() {
                return Err(format!("pattern `{src}` ends inside a class"));
            }
            set.push(chars[*pos]);
            *pos += 1;
            continue;
        }
        // `a-z` is a range only when the `-` is not the last member; `[ _-]`
        // is the class {space, underscore, hyphen}, not a range into `]`.
        if *pos + 2 < chars.len() && chars[*pos + 1] == '-' && chars[*pos + 2] != ']' {
            let from = u32::from(c);
            let to = u32::from(chars[*pos + 2]);
            if from > to {
                return Err(format!("pattern `{src}` has a reversed class range"));
            }
            for code in from..=to {
                if let Some(ch) = char::from_u32(code) {
                    set.push(ch);
                }
            }
            *pos += 3;
            continue;
        }
        set.push(c);
        *pos += 1;
    }
    if !closed {
        return Err(format!("pattern `{src}` has an unclosed class"));
    }
    Ok(Node::Class { chars: set, neg })
}

/// Read the map file.
///
/// # Errors
///
/// Returns the reason the map could not be read, which is always a finding:
/// a gate that cannot read its own list has nothing to check.
fn read_map(root: &Path) -> Result<ConceptMap, String> {
    let path = root.join(MAP_PATH);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {MAP_PATH}: {e}"))?;
    parse_map(&text)
}

/// Parse the map text.
fn parse_map(text: &str) -> Result<ConceptMap, String> {
    let mut state = MapState::default();
    let mut pending: Option<(String, String)> = None;

    for raw in text.lines() {
        if let Some((key, body)) = pending.take() {
            let joined = format!("{body} {}", strip_comment(raw));
            match read_array(&joined)? {
                ArrayRead::Closed(members) => {
                    apply(&key, members, &mut state)?;
                }
                ArrayRead::Open(partial) => pending = Some((key, partial)),
            }
            continue;
        }
        let line = strip_comment(raw).trim().to_string();
        if line.is_empty() {
            continue;
        }
        if line == "[[concept]]" {
            if let Some(c) = state.current.take() {
                state.records.push(finish(c)?);
            }
            state.current = Some(Partial::default());
            continue;
        }
        let Some((key, rest)) = line.split_once('=') else {
            return Err(format!("a line that is not `key = value`: `{line}`"));
        };
        let key = key.trim().to_string();
        let rest = rest.trim();
        let members = if rest.starts_with('[') {
            match read_array(rest)? {
                ArrayRead::Closed(m) => m,
                ArrayRead::Open(partial) => {
                    pending = Some((key, partial));
                    continue;
                }
            }
        } else {
            vec![scalar_value(rest)?]
        };
        apply(&key, members, &mut state)?;
    }
    if let Some(c) = state.current.take() {
        state.records.push(finish(c)?);
    }
    if !state.saw_mode {
        return Err(String::from(
            "the map does not state a mode; `mode` selects the ratchet and cannot be left \
             to a default",
        ));
    }
    if state.records.is_empty() {
        return Err(String::from("the map has no `[[concept]]` record"));
    }
    Ok(ConceptMap {
        mode: state.mode,
        global_allow_paths: state.global_allow_paths,
        records: state.records,
    })
}

/// Turn a parsed record into a compiled one.
fn finish(part: Partial) -> Result<Record, String> {
    if part.new_code.is_empty() {
        return Err(String::from(
            "a map record has no `new_code`; it is the record's key in the baseline",
        ));
    }
    if part.patterns.is_empty() {
        return Err(format!("map record `{}` has no `patterns` entry", part.new_code));
    }
    let compiled = part
        .patterns
        .iter()
        .map(compile)
        .collect::<Result<Vec<Pattern>, String>>()?;
    Ok(Record {
        old: part.old,
        patterns: compiled,
        paths: part.paths,
        allow_paths: part.allow_paths,
        new_code: part.new_code,
        owner: part.owner,
    })
}

/// Store one parsed key on the record being read, or on the map itself.
///
/// An unknown key is an error. A key the gate does not read is a rule nobody
/// enforces, and the map is the binding text: silently ignoring a line of it
/// would make the gate weaker than the document it implements.
fn apply(key: &str, members: Vec<String>, state: &mut MapState) -> Result<(), String> {
    let value = members.first().cloned().unwrap_or_default();
    match key {
        "schema" => {
            if value != "1" {
                return Err(format!(
                    "the map declares schema `{value}`; this gate reads schema 1"
                ));
            }
        }
        "mode" => {
            state.saw_mode = true;
            state.mode = match value.as_str() {
                "count" => Mode::Count,
                "absolute" => Mode::Absolute,
                other => {
                    return Err(format!(
                        "the map declares mode `{other}`; the modes are `count` and `absolute`"
                    ))
                }
            };
        }
        "global_allow_paths" => state.global_allow_paths = members,
        "old" | "patterns" | "paths" | "allow_paths" | "new_code" | "owner" | "term_en"
        | "term_tr" | "area" | "reason" => {
            let Some(slot) = state.current.as_mut() else {
                return Err(format!(
                    "`{key}` appears before the first `[[concept]]`; the map-level keys are \
                     `schema`, `mode` and `global_allow_paths`"
                ));
            };
            match key {
                "old" => slot.old = members,
                "patterns" => slot.patterns = members,
                "paths" => slot.paths = members,
                "allow_paths" => slot.allow_paths = members,
                "new_code" => slot.new_code = value,
                "owner" => slot.owner = value,
                // The four human-readable fields belong to the register, not to
                // the count: `docs/NAMING.md` carries them and the gate does
                // not read them.
                _ => {}
            }
        }
        other => {
            return Err(format!(
                "the map carries a key this gate does not read: `{other}`. A key the gate \
                 ignores is a rule nobody enforces."
            ))
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- matching

/// Is `c` a word character for `\b`?
fn is_word(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

/// Do two characters match, honouring the pattern's case flag?
fn char_eq(a: char, b: char, ci: bool) -> bool {
    a == b || (ci && a.to_lowercase().next() == b.to_lowercase().next())
}

/// Does `c` satisfy a class, honouring the pattern's case flag?
fn class_hit(c: char, set: &[char], neg: bool, ci: bool) -> bool {
    let mut hit = set.contains(&c);
    if !hit && ci {
        if let Some(low) = c.to_lowercase().next() {
            hit = set.contains(&low);
        }
        if !hit {
            if let Some(up) = c.to_uppercase().next() {
                hit = set.contains(&up);
            }
        }
    }
    if neg {
        !hit
    } else {
        hit
    }
}

/// Every position one node can stop at, greedy first.
///
/// Returning all of them rather than the first is what makes the matcher
/// correct where a quantified group is followed by more pattern: `\bVault(Id)?\b`
/// has to be able to give the `?` up when the boundary after it does not hold,
/// and a group with several alternatives has to be able to try the second one
/// when the first leads nowhere.
fn node_stops(text: &[char], at: usize, node: &Node, ci: bool) -> Vec<usize> {
    match node {
        Node::Lit(c) => {
            if at < text.len() && char_eq(text[at], *c, ci) {
                vec![at + 1]
            } else {
                Vec::new()
            }
        }
        Node::Class { chars, neg } => {
            if at < text.len() && class_hit(text[at], chars, *neg, ci) {
                vec![at + 1]
            } else {
                Vec::new()
            }
        }
        Node::Group(alts) => {
            let mut out: Vec<usize> = Vec::new();
            for seq in alts {
                if let Some(stop) = match_sequence(text, at, seq, 0, ci) {
                    if !out.contains(&stop) {
                        out.push(stop);
                    }
                }
            }
            out
        }
        Node::Repeat { inner, star } => {
            let mut out = vec![at];
            let mut cursor = at;
            loop {
                // A node that can match the empty string would spin here; the
                // guard is what makes `()?` and `(a*)*` terminate.
                let Some(next) = node_stops(text, cursor, inner, ci)
                    .into_iter()
                    .find(|stop| *stop > cursor)
                else {
                    break;
                };
                out.push(next);
                cursor = next;
                if !*star {
                    break;
                }
            }
            out
        }
        Node::Boundary => {
            let left = at > 0 && is_word(text[at - 1]);
            let right = at < text.len() && is_word(text[at]);
            if left == right {
                Vec::new()
            } else {
                vec![at]
            }
        }
        Node::Start => {
            if at == 0 {
                vec![at]
            } else {
                Vec::new()
            }
        }
        Node::End => {
            if at == text.len() {
                vec![at]
            } else {
                Vec::new()
            }
        }
    }
}

/// Try each alternative in turn at `at`.
fn match_alternatives(text: &[char], at: usize, alts: &[Vec<Node>], ci: bool) -> Option<usize> {
    for seq in alts {
        if let Some(stop) = match_sequence(text, at, seq, 0, ci) {
            return Some(stop);
        }
    }
    None
}

/// Match one alternative from node `k` onwards.
fn match_sequence(text: &[char], at: usize, seq: &[Node], k: usize, ci: bool) -> Option<usize> {
    if k == seq.len() {
        return Some(at);
    }
    for stop in node_stops(text, at, &seq[k], ci) {
        if let Some(end) = match_sequence(text, stop, seq, k + 1, ci) {
            return Some(end);
        }
    }
    None
}

/// The longest run of literal characters in the first alternative, lowercased.
///
/// Every pattern in the map carries one. A line that does not contain it
/// cannot match, which keeps the character matcher off the lines that carry
/// nothing - the difference between a gate that takes seconds and one that
/// takes minutes.
fn literal_probe(pat: &Pattern) -> String {
    let mut best = String::new();
    for seq in &pat.alts {
        let mut run = String::new();
        for node in seq {
            if let Node::Lit(c) = node {
                run.push(*c);
            } else {
                if run.len() > best.len() {
                    best = run.clone();
                }
                run.clear();
            }
        }
        if run.len() > best.len() {
            best = run;
        }
    }
    best.to_lowercase()
}

/// How many times `pat` matches in `line`.
fn count_in_line(line: &[char], pat: &Pattern) -> usize {
    let mut total = 0usize;
    let mut at = 0usize;
    while at <= line.len() {
        match match_alternatives(line, at, &pat.alts, pat.ci) {
            Some(stop) => {
                total += 1;
                at = if stop > at { stop } else { at + 1 };
            }
            None => at += 1,
        }
    }
    total
}

/// How many times any pattern of `rec` matches in `text`.
fn count_in_text(text: &str, rec: &Record) -> usize {
    let mut total = 0usize;
    for line in text.split('\n') {
        let chars: Vec<char> = line.chars().collect();
        let lowered: String = line.to_lowercase();
        for pat in &rec.patterns {
            let probe = literal_probe(pat);
            if !probe.is_empty() && !lowered.contains(&probe) {
                continue;
            }
            total += count_in_line(&chars, pat);
        }
    }
    total
}

/// Is `rel` under one of `prefixes`?
fn under(rel: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|p| rel.starts_with(p.as_str()))
}

// ---------------------------------------------------------------- walking

/// Every file under the scan roots, in a stable order.
fn sorted_walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for base in SCAN_ROOTS {
        let dir = root.join(base);
        if dir.is_dir() {
            walk_into(&dir, &mut out);
        }
    }
    out.sort();
    out
}

fn walk_into(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // `file_type` rather than `metadata`: a symlink to a directory is not
        // followed, since following one can walk outside the repository or
        // loop forever.
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if kind.is_dir() {
            if !SKIP_DIRS.contains(&name_str.as_ref()) {
                walk_into(&path, out);
            }
        } else if kind.is_file() && !skipped(&path, &name_str) {
            out.push(path);
        }
    }
}

/// Is this file one the gate does not read?
fn skipped(path: &Path, name: &str) -> bool {
    if SKIP_FILES.contains(&name) {
        return true;
    }
    let Some(ext) = path.extension() else {
        return false;
    };
    SKIP_EXTS.contains(&ext.to_string_lossy().to_ascii_lowercase().as_str())
}

// ---------------------------------------------------------------- baseline

/// One recorded line of the baseline.
struct BaselineRow {
    key: String,
    files: usize,
    matches: usize,
}

/// Read the baseline.
///
/// # Errors
///
/// Returns the reason the baseline could not be read.
fn read_baseline(root: &Path) -> Result<Vec<BaselineRow>, String> {
    let path = root.join(BASELINE_PATH);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {BASELINE_PATH}: {e}"))?;
    let mut rows: Vec<BaselineRow> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split('\t');
        let Some(key) = parts.next() else {
            return Err(format!("a baseline line with no key: `{trimmed}`"));
        };
        let files = parts
            .next()
            .and_then(|v| v.parse::<usize>().ok())
            .ok_or_else(|| format!("a baseline line whose file count is not a number: `{trimmed}`"))?;
        let matches = parts
            .next()
            .and_then(|v| v.parse::<usize>().ok())
            .ok_or_else(|| format!("a baseline line whose match count is not a number: `{trimmed}`"))?;
        if parts.next().is_some() {
            return Err(format!("a baseline line with more than three columns: `{trimmed}`"));
        }
        rows.push(BaselineRow {
            key: String::from(key),
            files,
            matches,
        });
    }
    Ok(rows)
}

/// The verdict of comparing one measured record against the baseline.
enum Verdict {
    Ok,
    /// The count rose: the rename went backwards.
    Grew { files: usize, matches: usize },
    /// The count fell but the recorded number was not lowered with it.
    Fell { files: usize, matches: usize },
}

/// Compare one measured pair against the recorded one.
fn compare(measured: (usize, usize), recorded: Option<(usize, usize)>) -> Verdict {
    match recorded {
        None => Verdict::Grew {
            files: measured.0,
            matches: measured.1,
        },
        Some((rf, rm)) if measured.0 > rf || measured.1 > rm => Verdict::Grew {
            files: measured.0,
            matches: measured.1,
        },
        Some((rf, rm)) if measured.0 < rf || measured.1 < rm => Verdict::Fell {
            files: measured.0,
            matches: measured.1,
        },
        Some(_) => Verdict::Ok,
    }
}

// ---------------------------------------------------------------- the gate

/// # Errors
///
/// Returns the concept names whose count grew, the ones whose recorded number
/// is now stale, and in `absolute` mode every remaining occurrence.
pub fn run(root: &Path) -> Result<String, String> {
    let map = read_map(root)?;
    for rec in &map.records {
        if !KNOWN_PACKAGES.contains(&rec.owner.as_str()) {
            return Err(format!(
                "map record `{}` is owned by `{}`, which is not a package in the \
                 dependency table. A rename owned by a package that does not exist \
                 is a rename that never happens.",
                rec.new_code, rec.owner
            ));
        }
    }

    let files = sorted_walk(root);
    let mut scanned = 0usize;
    let mut measured: Vec<(String, usize, usize, Vec<String>)> = Vec::new();
    for rec in &map.records {
        let mut hit_files = 0usize;
        let mut hit_matches = 0usize;
        let mut examples: Vec<String> = Vec::new();
        for path in &files {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if under(&rel, &map.global_allow_paths) {
                continue;
            }
            if !rec.paths.is_empty() && !under(&rel, &rec.paths) {
                continue;
            }
            if under(&rel, &rec.allow_paths) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            scanned += 1;
            let hits = count_in_text(&text, rec);
            if hits > 0 {
                hit_files += 1;
                hit_matches += hits;
                if examples.len() < 5 {
                    examples.push(format!("{rel} ({hits})"));
                }
            }
        }
        measured.push((rec.new_code.clone(), hit_files, hit_matches, examples));
    }

    if scanned < VACUITY_FLOOR {
        return Err(format!(
            "only {scanned} file reads were made, below the floor of {VACUITY_FLOOR}. A scan \
             this small is not evidence of anything: the root is probably wrong or the skip \
             list is swallowing the tree, and a gate that reports OK after looking at nothing \
             is worse than an absent one."
        ));
    }

    if map.mode == Mode::Absolute {
        return absolute_verdict(&measured);
    }

    let baseline = read_baseline(root)?;
    count_verdict(&map, &measured, &baseline)
}

/// The `absolute` verdict: anything left is a finding.
fn absolute_verdict(measured: &[(String, usize, usize, Vec<String>)]) -> Result<String, String> {
    let remaining: Vec<&(String, usize, usize, Vec<String>)> =
        measured.iter().filter(|m| m.1 > 0).collect();
    if !remaining.is_empty() {
        let mut msg = String::from("the map is in `absolute` mode and old concept names remain:\n");
        for (key, files, matches, examples) in remaining.iter().take(MAX_REPORTED) {
            let _ = writeln!(
                msg,
                "  {key}: {files} file(s), {matches} match(es)\n    {}",
                examples.join(", ")
            );
        }
        if remaining.len() > MAX_REPORTED {
            let _ = writeln!(msg, "  ... and {} more", remaining.len() - MAX_REPORTED);
        }
        msg.push_str(
            "  Rename each to the `new_code` the map gives it. In this mode there is no \
             ratchet left to fall back on: one occurrence is a finding.",
        );
        return Err(msg);
    }
    Ok(String::from(
        "no old concept name remains anywhere under the scan roots (absolute mode)",
    ))
}

/// The `count` verdict: the ratchet.
fn count_verdict(
    map: &ConceptMap,
    measured: &[(String, usize, usize, Vec<String>)],
    baseline: &[BaselineRow],
) -> Result<String, String> {
    let mut grew: Vec<String> = Vec::new();
    let mut fell: Vec<String> = Vec::new();
    let mut stale: Vec<String> = Vec::new();
    let mut total_files = 0usize;
    let mut total_matches = 0usize;

    for (key, files, matches, examples) in measured {
        total_files += files;
        total_matches += matches;
        let recorded = baseline
            .iter()
            .find(|r| &r.key == key)
            .map(|r| (r.files, r.matches));
        match compare((*files, *matches), recorded) {
            Verdict::Ok => {}
            Verdict::Grew { .. } => {
                let was = recorded.map_or_else(
                    || String::from("no recorded line"),
                    |(rf, rm)| format!("recorded {rf} file(s), {rm} match(es)"),
                );
                grew.push(format!(
                    "  {key}: {files} file(s), {matches} match(es) - {was}\n    {}\n    \
                     owner: {}",
                    examples.join(", "),
                    owner_of(map, key)
                ));
            }
            Verdict::Fell { .. } => {
                fell.push(format!("{key}\t{files}\t{matches}"));
            }
        }
    }
    for row in baseline {
        if !measured.iter().any(|m| &m.0 == &row.key) {
            stale.push(row.key.clone());
        }
    }

    if !grew.is_empty() || !fell.is_empty() || !stale.is_empty() {
        let mut msg = format!(
            "the concept-name counter does not match {}:\n",
            BASELINE_PATH
        );
        if !grew.is_empty() {
            let _ = writeln!(
                msg,
                "{} record(s) carry MORE old names than recorded. The counter only goes down; \
                 rename what this change added:",
                grew.len()
            );
            for g in grew.iter().take(MAX_REPORTED) {
                let _ = writeln!(msg, "{g}");
            }
        }
        if !fell.is_empty() {
            let _ = writeln!(
                msg,
                "{} record(s) went down but the recorded number was not lowered with them. \
                 Replace their lines in {} with:",
                fell.len(),
                BASELINE_PATH
            );
            for f in &fell {
                let _ = writeln!(msg, "  {f}");
            }
        }
        if !stale.is_empty() {
            let _ = writeln!(
                msg,
                "{} recorded line(s) have no record in the map any more and must leave the \
                 file: {}",
                stale.len(),
                stale.join(", ")
            );
        }
        return Err(msg);
    }

    Ok(format!(
        "{} concept-name record(s) at or below the baseline: {} file(s), {} match(es) remain \
         across {} map record(s)",
        measured.len(),
        total_files,
        total_matches,
        map.records.len()
    ))
}

/// The package that owns a record, for the report.
fn owner_of(map: &ConceptMap, key: &str) -> &str {
    map.records
        .iter()
        .find(|r| r.new_code == key)
        .map_or("unowned", |r| r.owner.as_str())
}

/// # Errors
///
/// Returns the first canary that did not behave.
pub fn self_test() -> Result<String, String> {
    let map = canary_map()?;
    let rec = &map.records[0];

    // 1. The new name is not a finding.
    if count_in_text("fn hash_chain_election() {}", rec) != 0 {
        return Err(String::from(
            "canary 1: the replacement name was reported as the old name",
        ));
    }

    // 2. The old name is caught.
    if count_in_text("mod filiz { }", rec) == 0 {
        return Err(String::from("canary 2: the old name was not caught"));
    }

    // 3. Case does not hide it, and the domain tag is caught too.
    if count_in_text("const TAG: &str = \"BDLM_FILIZ_LINK_V1\";", rec) == 0 {
        return Err(String::from(
            "canary 3: an uppercase domain tag carrying the old name was not caught",
        ));
    }

    // 4. A word boundary keeps the matcher honest: `?` and a class must not
    //    turn into a substring match.
    let vault = &map.records[1];
    if count_in_text("let vault_id = 1;", vault) == 0 {
        return Err(String::from("canary 4: `vault_id` was not caught"));
    }
    if count_in_text("let vaulted = true;", vault) != 0 {
        return Err(String::from(
            "canary 5: `vaulted` was reported; the group and the boundary must both hold \
             or the counter will fire on ordinary English",
        ));
    }

    // 6. `paths` narrows a record: a path outside it is not that record's
    //    business, and a path inside it is.
    if rec.paths.is_empty() || under("src/bin/faucet.rs", &rec.paths) {
        return Err(String::from(
            "canary 6: the canary map's `paths` field did not narrow the record",
        ));
    }
    if !under("src/consensus/leader.rs", &rec.paths) {
        return Err(String::from(
            "canary 7: a path inside the record's `paths` was excluded",
        ));
    }

    // 7. The ratchet is one-way in both directions.
    if !matches!(compare((3, 9), Some((2, 9))), Verdict::Grew { .. }) {
        return Err(String::from(
            "canary 7: a file count above the baseline was not a finding",
        ));
    }
    if !matches!(compare((1, 9), Some((2, 9))), Verdict::Fell { .. }) {
        return Err(String::from(
            "canary 8: a file count below the baseline was not reported, so the recorded \
             number would never come down",
        ));
    }
    if !matches!(compare((2, 9), Some((2, 9))), Verdict::Ok) {
        return Err(String::from("canary 9: an unchanged count was a finding"));
    }
    if !matches!(compare((1, 1), None), Verdict::Grew { .. }) {
        return Err(String::from(
            "canary 10: a record missing from the baseline was not a finding",
        ));
    }

    // 11. A pattern the matcher cannot parse is an error, not a skip: a gate
    //     that ignores one arm of the map reports a lower count than the tree.
    if compile("filiz(").is_ok() {
        return Err(String::from(
            "canary 11: an unclosed group compiled instead of failing",
        ));
    }
    if compile("[z-a]").is_ok() {
        return Err(String::from(
            "canary 12: a reversed class range compiled instead of failing",
        ));
    }

    // 13. The mode is read, and an unknown mode is refused rather than assumed.
    if parse_map("schema = 1\n[[concept]]\nnew_code = \"x\"\npatterns = ['x']\nowner = \"WP-05\"\n")
        .is_ok()
    {
        return Err(String::from(
            "canary 13: a map with no `mode` was accepted",
        ));
    }

    // 14. An owner that is not a package is refused.
    if KNOWN_PACKAGES.contains(&"WP-99") {
        return Err(String::from(
            "canary 14: the package list admits an id outside the dependency table",
        ));
    }
    if !KNOWN_PACKAGES.contains(&"WP-05") {
        return Err(String::from("canary 15: the package list lost WP-05"));
    }

    // 16. The probe keeps the character matcher off the lines that carry
    //     nothing, so a probe that is not a substring of every possible match
    //     would hide findings. It is the longest literal run, and every
    //     pattern in the map has one.
    let tag = &rec.patterns[1];
    if literal_probe(tag) != "bdlm_filiz_" {
        return Err(format!(
            "canary 16: the probe of the domain-tag pattern is `{}`, not the tag prefix; \
             a probe that is not inside every match hides findings",
            literal_probe(tag)
        ));
    }
    if count_in_line(&"BDLM_FILIZ_LINK_V1".chars().collect::<Vec<char>>(), tag) == 0 {
        return Err(String::from(
            "canary 17: the domain-tag pattern did not match its own tag",
        ));
    }

    Ok(String::from("concept-names: 17 canaries"))
}

/// The two-record map the canaries run against.
///
/// A real map would be read from disk; a canary that depends on the repository
/// it is checking cannot prove anything about the matcher, because changing
/// the map would change the canary's answer.
fn canary_map() -> Result<ConceptMap, String> {
    parse_map(
        "schema = 1\n\
         mode = \"count\"\n\
         global_allow_paths = [\"config/naming/\"]\n\
         \n\
         [[concept]]\n\
         old = [\"Filiz (leader election)\"]\n\
         patterns = ['(?i)filiz', 'BDLM_FILIZ_']\n\
         paths = [\"src/consensus/\", \"src/chain/\"]\n\
         new_code = \"hash_chain_election\"\n\
         owner = \"WP-12\"\n\
         \n\
         [[concept]]\n\
         old = [\"Vault\"]\n\
         patterns = ['\\\\bVault(Error|Registry|Tx|Id|Entry|Folder)?\\\\b', '\\\\bvault_']\n\
         new_code = \"nft_folders\"\n\
         owner = \"WP-23\"\n",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canary the directive names: an injected old name is a finding.
    #[test]
    fn concept_names_gate_catches_injected_name() {
        let map = canary_map().expect("the canary map must parse");
        let rec = &map.records[0];
        assert_eq!(count_in_text("mod filiz { }", rec), 1);
        assert_eq!(count_in_text("FILIZ and filiz and BDLM_FILIZ_LINK_V1", rec), 3);
        assert_eq!(count_in_text("hash_chain_election", rec), 0);
    }

    /// The counter moves one way only, and says so in both directions.
    #[test]
    fn concept_names_baseline_only_decreases() {
        assert!(matches!(
            compare((5, 20), Some((4, 20))),
            Verdict::Grew { .. }
        ));
        assert!(matches!(
            compare((4, 21), Some((4, 20))),
            Verdict::Grew { .. }
        ));
        assert!(matches!(
            compare((3, 20), Some((4, 20))),
            Verdict::Fell { .. }
        ));
        assert!(matches!(compare((4, 20), Some((4, 20))), Verdict::Ok));
    }

    /// Every owner in the shipped map is a package in the dependency table.
    #[test]
    fn concept_map_owner_is_a_known_package() {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../..")
                .join(MAP_PATH),
        )
        .expect("the concept map is in the repository");
        let map = parse_map(&text).expect("the concept map parses");
        for rec in &map.records {
            assert!(
                KNOWN_PACKAGES.contains(&rec.owner.as_str()),
                "record `{}` is owned by `{}`, which is not a package",
                rec.new_code,
                rec.owner
            );
        }
        assert!(!map.records.is_empty());
    }
}
