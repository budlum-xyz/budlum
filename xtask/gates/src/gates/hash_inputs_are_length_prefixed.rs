//! Two variable-length fields hashed back to back must carry their lengths.
//!
//! Ported from `scripts/check-hash-inputs-are-length-prefixed.sh`, 541 lines
//! of shell wrapping Python. The shell was a here-doc launcher and the Python
//! did the work, so the port replaces two languages with one, and the
//! Python's regexes become plain string and brace matching.
//!
//! # Why this gate exists
//!
//! Four consensus digests hashed a validator's key set by appending the
//! fields one after another with nothing between them:
//!
//! ```text
//! hasher.update(&v.bls_public_key);   // Vec<u8>
//! hasher.update(&v.pop_signature);    // Vec<u8>
//! hasher.update(&v.pq_public_key);    // Vec<u8>
//! ```
//!
//! Concatenation without lengths is not injective. A 96-byte BLS key
//! followed by a 48-byte `PoP` produces exactly the bytes of a 144-byte `BLS` key
//! followed by an empty `PoP`, so the two hash identically. Measured, not
//! argued: the module doc in `src/crypto/key_set_preimage.rs` carries the
//! demonstration.
//!
//! It was reachable. `Validator` is a `serde` struct with `#[serde(default)]`
//! on all four key fields and it crosses the wire inside a snapshot, and
//! neither `AccountState::from_snapshot` nor `from_snapshot_v2` re-derives
//! the split; they copy the vectors verbatim. A snapshot carrying the `PoP`
//! folded into the BLS key reproduces the honest state root, passes
//! `verify()`, passes the state-root comparison in `apply_v2_snapshot`, and
//! installs a validator with no `PoP`. `is_consensus_ready` then drops it from
//! the active set, so the restoring node computes a different `set_hash` from
//! its peers while both agree on the state root. A partition with no error
//! naming its cause.
//!
//! # What the gate checks
//!
//! In production code, when a hasher update takes a field whose declared type
//! is variable-length (`Vec<u8>`, `String`, `BoundedBytes`) and the
//! immediately following update takes another variable-length value, the pair
//! must be length-prefixed: a `len()` must appear on that line or the line
//! above, or the field's declaration must carry `HASHLEN: exempt - <reason>`.
//!
//! A single variable-length field at the end of a preimage, followed by
//! nothing or by a fixed-width value, is not flagged: there is nothing for it
//! to trade bytes with.
//!
//! # Known limits
//!
//! The type is resolved by field name across the tree, so a name used by two
//! structs with different types is treated as variable-length if either is.
//! That errs toward flagging, which is the safe direction for a gate about
//! consensus preimages. The gate also cannot see through a helper that takes
//! the bytes as an argument; it measures the call sites it can read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Roots holding shipped library code.
const SCAN_ROOTS: &[&str] = &["src", "budzero", "wallet-core"];

/// Types whose byte length is not fixed, so concatenation is ambiguous.
const VARIABLE_TYPES: &[&str] = &["Vec<u8>", "String", "BoundedBytes", "Vec<String>"];

/// Method calls that convert a field to bytes rather than naming a new field.
/// `self.block_hash.as_bytes()` ends in `as_bytes`, and taking the last path
/// segment as the field name would resolve it to a method, which no struct
/// declares, so the pair would be silently skipped.
const ACCESSORS: &[&str] = &["as_bytes", "as_slice", "as_str", "as_ref", "to_vec", "0"];

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_ident_path_byte(b: u8) -> bool {
    is_ident_byte(b) || b == b'.'
}

fn ws_skip(src: &str, mut j: usize) -> usize {
    while j < src.len() && src.as_bytes()[j].is_ascii_whitespace() {
        j += 1;
    }
    j
}

/// The brace-matched body of the item whose opening brace sits at `open_at`.
fn balanced(src: &str, open_at: usize) -> String {
    let bytes = src.as_bytes();
    let mut depth = 0usize;
    let mut j = open_at;
    while j < bytes.len() {
        match bytes[j] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return src[open_at..=j].to_string();
                }
            }
            _ => {}
        }
        j += 1;
    }
    src[open_at..].to_string()
}

/// Remove `#[cfg(test)] mod name { ... }` blocks, braces balanced.
fn strip_test_mods(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    while let Some(rel) = src[i..].find("#[cfg(test)]") {
        let start = i + rel;
        let mut j = start + "#[cfg(test)]".len();
        j = ws_skip(src, j);
        if src[j..].starts_with("pub") {
            j += 3;
            j = ws_skip(src, j);
        }
        if !src[j..].starts_with("mod") {
            out.push_str(&src[i..start + "#[cfg(test)]".len()]);
            i = start + "#[cfg(test)]".len();
            continue;
        }
        j += 3;
        j = ws_skip(src, j);
        let id_start = j;
        while j < src.len() && is_ident_byte(src.as_bytes()[j]) {
            j += 1;
        }
        if j == id_start {
            out.push_str(&src[i..start + "#[cfg(test)]".len()]);
            i = start + "#[cfg(test)]".len();
            continue;
        }
        j = ws_skip(src, j);
        if !src[j..].starts_with('{') {
            out.push_str(&src[i..start + "#[cfg(test)]".len()]);
            i = start + "#[cfg(test)]".len();
            continue;
        }
        let mut depth = 0usize;
        let mut k = j;
        while k < src.len() {
            match src.as_bytes()[k] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            k += 1;
        }
        out.push_str(&src[i..start]);
        i = (k + 1).min(src.len());
    }
    out.push_str(&src[i..]);
    out
}

/// A path under a test directory, or a file that is itself a test module.
fn is_test_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.contains("/tests/") || s.ends_with("_tests.rs") || s.ends_with("/tests.rs")
}

/// Every `.rs` file under a root, excluding generated and test paths.
fn collect_rs(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(p_kind) = entry.file_type() else {
            continue;
        };
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if p_kind.is_dir() {
            if matches!(name.as_str(), ".git" | "target" | "node_modules") {
                continue;
            }
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("rs")) && !is_test_path(&p) {
            out.push(p);
        }
    }
}

/// The struct field an update expression names, past any accessor call.
fn field_of(expr: &str) -> &str {
    let mut last = expr;
    while let Some(dot) = last.rfind('.') {
        let tail = &last[dot + 1..];
        if ACCESSORS.contains(&tail) {
            last = &last[..dot];
        } else {
            break;
        }
    }
    last.rsplit('.').next().unwrap_or("")
}

/// The receiver of a `.update(` call in the text, if any.
fn receiver_of(text: &str) -> Option<&str> {
    let pos = text.find(".update(")?;
    let mut start = pos;
    while start > 0 && is_ident_path_byte(text.as_bytes()[start - 1]) {
        start -= 1;
    }
    Some(&text[start..pos])
}

/// The expression passed to the first `.update(` that takes an identifier.
///
/// A length update `(x.len() as u64).to_le_bytes()` starts with `(` and so
/// does not match: only field feeds count as updates.
fn find_update(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let needle = b".update(";
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let mut j = ws_skip(text, i + needle.len());
            if j < bytes.len() && bytes[j] == b'&' {
                j += 1;
            }
            if j < bytes.len() && (bytes[j].is_ascii_alphabetic() || bytes[j] == b'_') {
                let start = j;
                while j < bytes.len() && is_ident_path_byte(bytes[j]) {
                    j += 1;
                }
                return Some(text[start..j].to_string());
            }
        }
        i += 1;
    }
    None
}

/// Every variable-length field and the doc comments attached to it.
fn parse_fields(src: &str) -> (BTreeSet<String>, BTreeMap<String, Vec<String>>) {
    let mut variable = BTreeSet::new();
    let mut docs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut i = 0usize;
    while let Some(rel) = src[i..].find("pub struct ") {
        let start = i + rel;
        let after = start + "pub struct ".len();
        let mut j = after;
        while j < src.len() && is_ident_byte(src.as_bytes()[j]) {
            j += 1;
        }
        j = ws_skip(src, j);
        if !src[j..].starts_with('{') {
            i = j;
            continue;
        }
        let body = balanced(src, j);
        let mut doc: Vec<String> = Vec::new();
        for line in body.split('\n') {
            let stripped = line.trim();
            if stripped.starts_with("//") {
                doc.push(stripped.to_string());
                continue;
            }
            if let Some(rest) = stripped.strip_prefix("pub") {
                if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
                    doc.clear();
                    continue;
                }
                let rest = rest.trim_start();
                let name_end = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
                if name_end == 0 {
                    doc.clear();
                    continue;
                }
                let name = &rest[..name_end];
                let after_name = rest[name_end..].trim_start();
                if let Some(type_part) = after_name.strip_prefix(':') {
                    let mut parts = type_part.split(',');
                    let ty = parts.next().unwrap_or("").trim();
                    let tail_ok = parts.all(|s| s.trim().is_empty());
                    if tail_ok && VARIABLE_TYPES.contains(&ty) {
                        variable.insert(name.to_string());
                        docs.entry(name.to_string())
                            .or_default()
                            .push(doc.join("\n"));
                    }
                }
                doc.clear();
                continue;
            }
            if stripped.starts_with("#[") {
                continue;
            }
            if !stripped.is_empty() {
                doc.clear();
            }
        }
        i = j + 1;
    }
    (variable, docs)
}

/// Does the doc comment declare a written exemption from the length rule?
fn hashlens_exempt(doc: &str) -> bool {
    let Some(at) = doc.find("HASHLEN:") else {
        return false;
    };
    let mut j = at + "HASHLEN:".len();
    j = ws_skip(doc, j);
    if !doc[j..].starts_with("exempt") {
        return false;
    }
    let after = j + "exempt".len();
    !doc.as_bytes().get(after).is_some_and(|b| is_ident_byte(*b))
}

struct Outcome {
    checked: usize,
    adjacent: usize,
    problems: Vec<String>,
}

/// One update site: its line index, the line text, and the field it names.
struct Update {
    line: usize,
    text: String,
    field: String,
    expr: String,
}

/// Measure one file's hasher feeds against the variable-length field set.
fn measure_file(
    path: &Path,
    src: &str,
    variable: &BTreeSet<String>,
    docs: &BTreeMap<String, Vec<String>>,
    root: &Path,
    out: &mut Outcome,
) {
    let lines: Vec<&str> = src.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let mut updates: Vec<Update> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        if let Some(expr) = find_update(line) {
            updates.push(Update {
                line: i,
                text: (*line).to_string(),
                field: field_of(&expr).to_string(),
                expr,
            });
        } else if line.trim_end().ends_with(".update(") {
            let joined = if i + 1 < lines.len() {
                format!("{}{}", line.trim_end(), lines[i + 1].trim())
            } else {
                (*line).to_string()
            };
            if let Some(expr) = find_update(&joined) {
                updates.push(Update {
                    line: i,
                    text: joined,
                    field: field_of(&expr).to_string(),
                    expr,
                });
            }
        }
    }

    for u in &updates {
        if variable.contains(&u.field) {
            out.checked += 1;
        }
    }

    for k in 0..updates.len().saturating_sub(1) {
        let (cur, nxt) = (&updates[k], &updates[k + 1]);
        let between = if nxt.line > cur.line + 1 {
            lines[cur.line + 1..nxt.line].join("\n")
        } else {
            String::new()
        };
        if between.contains(".update(") {
            continue;
        }
        let (Some(recv_a), Some(recv_b)) = (receiver_of(&cur.text), receiver_of(&nxt.text)) else {
            continue;
        };
        if recv_a != recv_b {
            continue;
        }
        if !variable.contains(&cur.field) || !variable.contains(&nxt.field) {
            continue;
        }
        out.adjacent += 1;
        let window = lines[cur.line.saturating_sub(1)..=cur.line].join("\n");
        if window.contains("len()") {
            continue;
        }
        let exempt = docs
            .get(&cur.field)
            .is_some_and(|list| list.iter().any(|d| hashlens_exempt(d)));
        if exempt {
            continue;
        }
        let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy();
        out.problems.push(format!(
            "{}:{}: `{}` is variable-length and the next hashed value (`{}`) is too, \
             with no length between them. Concatenation without lengths is not \
             injective: bytes can be moved from one field to the next and the digest \
             will not change. Write the length first (see \
             `crate::crypto::key_set_preimage`), or mark the field \
             `HASHLEN: exempt - <reason>` in its declaration.",
            rel,
            cur.line + 1,
            cur.expr,
            nxt.field
        ));
    }
}

/// Measure the whole tree.
fn measure(root: &Path) -> Result<Outcome, String> {
    let mut files = Vec::new();
    for r in SCAN_ROOTS {
        collect_rs(&root.join(r), &mut files);
    }
    files.sort();
    if files.is_empty() {
        return Err(format!(
            "no production .rs files found under {}",
            root.display()
        ));
    }

    let mut variable = BTreeSet::new();
    let mut docs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut sources: Vec<(PathBuf, String)> = Vec::new();
    for p in &files {
        let raw = std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
        let src = String::from_utf8_lossy(&raw).into_owned();
        let stripped = strip_test_mods(&src);
        let (v, d) = parse_fields(&stripped);
        variable.extend(v);
        for (name, list) in d {
            docs.entry(name).or_default().extend(list);
        }
        sources.push((p.clone(), stripped));
    }

    if variable.is_empty() {
        return Err(String::from(
            "gate found no variable-length struct field to reason about - wrong root?",
        ));
    }

    let mut out = Outcome {
        checked: 0,
        adjacent: 0,
        problems: Vec::new(),
    };
    for (p, src) in &sources {
        measure_file(p, src, &variable, &docs, root, &mut out);
    }

    if out.checked == 0 {
        return Err(String::from(
            "gate found no variable-length hash input to measure - wrong root, or \
             the update pattern changed shape.",
        ));
    }
    Ok(out)
}

/// # Errors
///
/// Returns a finding when an adjacent variable-length pair is not
/// length-prefixed, or when the tree has nothing to measure.
pub fn run(root: &Path) -> Result<String, String> {
    let out = measure(root)?;
    if !out.problems.is_empty() {
        return Err(out.problems.join("\n"));
    }
    Ok(format!(
        "hash-input length gate OK: {} variable-length hash inputs read, {} of them \
         adjacent to another, each length-prefixed or declaring why it does not \
         need to be",
        out.checked, out.adjacent
    ))
}

/// A fixture directory with `src/lib.rs` carrying the given body.
fn mk_fixture(tmp: &Path, case: &str, body: &str) -> Result<(), String> {
    let dir = tmp.join(case);
    std::fs::create_dir_all(dir.join("src"))
        .map_err(|e| format!("cannot create fixture dirs: {e}"))?;
    std::fs::write(dir.join("src/lib.rs"), body).map_err(|e| format!("cannot write fixture: {e}"))
}

/// Run the gate against a fixture and classify the result.
///
/// `want` is what the canary expects: a finding, a pass, or a
/// measured-nothing exit. The Rust runner cannot distinguish exit 1 from
/// exit 2, so the classification reads the error text instead.
enum Expect {
    Finding,
    Pass,
    MeasuredNothing,
}

fn verdict(tmp: &Path, case: &str, want: &Expect) -> Result<(), String> {
    let dir = tmp.join(case);
    match (run(&dir), want) {
        (Ok(_), Expect::Pass) => Ok(()),
        (Ok(msg), _) => Err(format!("VACUOUS: {case} passed: {msg}")),
        (Err(msg), Expect::Finding) => {
            if msg.contains("no variable-length") || msg.contains("no production .rs") {
                Err(format!(
                    "BROKEN: {case} measured nothing instead of finding: {msg}"
                ))
            } else {
                Ok(())
            }
        }
        (Err(msg), Expect::MeasuredNothing) => {
            if msg.contains("no variable-length") || msg.contains("no production .rs") {
                Ok(())
            } else {
                Err(format!(
                    "MISREPORTS: {case} expected measured-nothing, got a finding: {msg}"
                ))
            }
        }
        (Err(msg), Expect::Pass) => Err(format!("WRONG: {case} was rejected: {msg}")),
    }
}

/// A fresh, exclusively-created scratch directory under the system temp dir.
///
/// The system temp dir is shared, so the name must be unpredictable and the
/// creation must be exclusive: `create_dir` fails when the path already
/// exists, which turns a pre-planted symlink or directory into a retry rather
/// than a follow.
fn scratch_dir() -> Result<PathBuf, String> {
    // The crate's own target dir, which the tree owns, is writable wherever
    // the binary runs and is excluded from the Semgrep scan. The shared
    // system temp dir is not used: it is world-writable, so a fixed name
    // there is a path anyone can pre-plant.
    let root = std::env::var("BUDLUM_ROOT")
        .map(PathBuf::from)
        .or_else(|_| std::env::current_dir().map_err(|e| e.to_string()))
        .map_err(|e| format!("cannot determine repo root for fixtures: {e}"))?;
    let base = root.join("target").join("gate-fixtures");
    std::fs::create_dir_all(&base).map_err(|e| format!("cannot create {}: {e}", base.display()))?;
    for attempt in 0..100u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = base.join(format!("hashlen-{}-{nanos}-{attempt}", std::process::id()));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("cannot create scratch dir: {e}")),
        }
    }
    Err(String::from(
        "cannot find a free scratch directory name under target/gate-fixtures",
    ))
}

/// # Errors
///
/// Returns every canary that did not behave, joined so the runner prints them
/// as one finding.
/// A fixture and what the gate must do with it.
struct Canary {
    name: &'static str,
    body: &'static str,
    /// An extra test file under `src/tests/`, for the test-code canary.
    extra_test: Option<&'static str>,
    expect: Expect,
}

const CANARIES: &[Canary] = &[
    Canary {
        name: "raw",
        body: "pub struct Validator {
    pub bls_public_key: Vec<u8>,
    pub pop_signature: Vec<u8>,
}
pub fn digest(v: &Validator, hasher: &mut Sha3_256) {
    hasher.update(&v.bls_public_key);
    hasher.update(&v.pop_signature);
}",
        extra_test: None,
        expect: Expect::Finding,
    },
    Canary {
        name: "prefixed",
        body: "pub struct Validator {
    pub bls_public_key: Vec<u8>,
    pub pop_signature: Vec<u8>,
}
pub fn digest(v: &Validator, hasher: &mut Sha3_256) {
    hasher.update((v.bls_public_key.len() as u64).to_le_bytes());
    hasher.update(&v.bls_public_key);
    hasher.update((v.pop_signature.len() as u64).to_le_bytes());
    hasher.update(&v.pop_signature);
}",
        extra_test: None,
        expect: Expect::Pass,
    },
    Canary {
        name: "exempt",
        body: "pub struct Validator {
    /// HASHLEN: exempt - fixed 96 bytes, refused at every ingress.
    pub bls_public_key: Vec<u8>,
    pub pop_signature: Vec<u8>,
}
pub fn digest(v: &Validator, hasher: &mut Sha3_256) {
    hasher.update(&v.bls_public_key);
    hasher.update(&v.pop_signature);
}",
        extra_test: None,
        expect: Expect::Pass,
    },
    Canary {
        name: "single",
        body: "pub struct Deal {
    pub note: String,
    pub amount: u64,
}
pub fn digest(d: &Deal, hasher: &mut Sha3_256) {
    hasher.update(&d.note);
    hasher.update(d.amount.to_le_bytes());
}
pub struct Pair {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
}
pub fn other(p: &Pair, hasher: &mut Sha3_256) {
    hasher.update((p.a.len() as u64).to_le_bytes());
    hasher.update(&p.a);
    hasher.update((p.b.len() as u64).to_le_bytes());
    hasher.update(&p.b);
}",
        extra_test: None,
        expect: Expect::Pass,
    },
    Canary {
        name: "three",
        body: "pub struct Keys {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub c: Vec<u8>,
}
pub fn digest(k: &Keys, hasher: &mut Sha3_256) {
    hasher.update((k.a.len() as u64).to_le_bytes());
    hasher.update(&k.a);
    hasher.update(&k.b);
    hasher.update(&k.c);
}",
        extra_test: None,
        expect: Expect::Finding,
    },
    Canary {
        name: "testonly",
        body: "pub struct Keys {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
}
pub fn digest(k: &Keys, hasher: &mut Sha3_256) {
    hasher.update((k.a.len() as u64).to_le_bytes());
    hasher.update(&k.a);
    hasher.update((k.b.len() as u64).to_le_bytes());
    hasher.update(&k.b);
}",
        extra_test: Some("src/tests/fixture.rs"),
        expect: Expect::Pass,
    },
    Canary {
        name: "cfgtest",
        body: "pub struct Keys {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
}
pub fn digest(k: &Keys, hasher: &mut Sha3_256) {
    hasher.update((k.a.len() as u64).to_le_bytes());
    hasher.update(&k.a);
    hasher.update((k.b.len() as u64).to_le_bytes());
    hasher.update(&k.b);
}
#[cfg(test)]
mod tests {
    pub fn fixture(k: &Keys, hasher: &mut Sha3_256) {
        hasher.update(&k.a);
        hasher.update(&k.b);
    }
}",
        extra_test: None,
        expect: Expect::Pass,
    },
    Canary {
        name: "nofields",
        body: "pub struct Fixed {
    pub id: [u8; 32],
}
pub fn digest(f: &Fixed, hasher: &mut Sha3_256) {
    hasher.update(f.id);
}",
        extra_test: None,
        expect: Expect::MeasuredNothing,
    },
    Canary {
        name: "nopairs",
        body: "pub struct Deal {
    pub note: String,
    pub amount: u64,
}
pub fn digest(d: &Deal, hasher: &mut Sha3_256) {
    hasher.update(&d.note);
    hasher.update(d.amount.to_le_bytes());
}",
        extra_test: None,
        expect: Expect::Pass,
    },
    Canary {
        name: "wrapped",
        body: "pub struct Entry {
    pub name: String,
    pub sig: Vec<u8>,
}
pub fn leaf(e: &Entry, hasher: &mut Sha3_256) {
    hasher.update(
        e.name.as_bytes(),
    );
    hasher.update(&e.sig);
}",
        extra_test: None,
        expect: Expect::Finding,
    },
    Canary {
        name: "two_hashers",
        body: "pub struct Item {
    pub name: String,
    pub sig: Vec<u8>,
}
pub fn root(items: &[Item]) -> [u8; 32] {
    let mut combined = Sha256::new();
    for item in items {
        let mut h = Sha256::new();
        h.update((item.name.len() as u64).to_le_bytes());
        h.update(item.name.as_bytes());
        h.update((item.sig.len() as u64).to_le_bytes());
        h.update(&item.sig);
        combined.update(h.finalize());
    }
    combined.finalize().into()
}",
        extra_test: None,
        expect: Expect::Pass,
    },
];

/// # Errors
///
/// Returns every canary that did not behave, joined so the runner prints
/// them as one finding.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();
    let tmp = scratch_dir()?;

    for c in CANARIES {
        if let Err(e) = mk_fixture(&tmp, c.name, c.body) {
            problems.push(e);
            continue;
        }
        if let Some(rel) = c.extra_test {
            std::fs::create_dir_all(tmp.join(c.name).join("src/tests"))
                .map_err(|e| format!("cannot create test fixture dir: {e}"))?;
            if let Err(e) = std::fs::write(tmp.join(c.name).join(rel), TEST_FIXTURE) {
                problems.push(e.to_string());
                continue;
            }
        }
        if let Err(e) = verdict(&tmp, c.name, &c.expect) {
            problems.push(e);
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);

    if !problems.is_empty() {
        return Err(problems.join("\n"));
    }
    Ok(String::from(
        "hash-input length gate self-test OK: a raw pair, a mid-sequence raw pair \
         and a tree with no variable-length field at all are rejected; a prefixed \
         pair, a declared exemption, a trailing single field, a never-adjacent \
         field and both flavours of test code all pass.",
    ))
}

/// The test fixture body shared by the test-code canaries.
const TEST_FIXTURE: &str = "pub fn fixture(k: &Keys, hasher: &mut Sha3_256) {
    hasher.update(&k.a);
    hasher.update(&k.b);
}";
