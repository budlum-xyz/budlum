//! A collection hashed into a commitment must be ordered.
//!
//! Ported from `scripts/check-consensus-maps-are-ordered.sh`. A hashing
//! function (`root`, `calculate_state_root`, `leaf_hash`, `compute_hash`,
//! `state_root`, `digest`) that iterates a `HashMap`/`HashSet` folds in a
//! per-process random order: two honest nodes with identical state produce
//! different digests. Iteration of `BTreeMap`/`BTreeSet`/`Vec` is fine.
//!
//! The CWE-184 hardening is kept:
//!   * field declarations and `type` aliases are resolved per module scope,
//!     so an inner `mod` cannot be masked by a safe outer alias of the same
//!     name (lexical shadowing);
//!   * aliases resolve through chains, including lowercase, generic
//!     (`type Entries<K, V> = HashMap<K, V>`), nested generic applications
//!     and path-qualified uses (`rows: super::entries`);
//!   * the module-scope brace walk runs on a literal- and comment-scrubbed
//!     view, so a `}` inside a comment, string or char literal cannot pop a
//!     module early.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::Path;

use super::rust_literals;

const HASHING_FNS: &[&str] = &[
    "root",
    "calculate_state_root",
    "leaf_hash",
    "compute_hash",
    "state_root",
    "digest",
];

const UNORDERED: &[&str] = &["HashMap", "HashSet"];

struct Finding {
    path: String,
    line: usize,
    fname: String,
    field: String,
    kind: String,
}

fn is_hashing_fn(line: &str) -> Option<String> {
    let t = line.trim_start();
    // optional `pub(...) ` then `fn <name>(`
    let t = if let Some(rest) = t.strip_prefix("pub") {
        let rest = rest.trim_start();
        if let Some(rest) = rest.strip_prefix('(') {
            rest.find(')')
                .map_or(rest, |end| rest[end + 1..].trim_start())
        } else {
            rest
        }
    } else {
        t
    };
    let rest = t.strip_prefix("fn ")?;
    let name_end = rest.find(|c: char| !c.is_ascii_alphanumeric() && c != '_')?;
    let name = &rest[..name_end];
    if HASHING_FNS.contains(&name) {
        Some(name.to_string())
    } else {
        None
    }
}

/// Strip an optional `pub` / `pub(...)` visibility prefix and the following
/// whitespace, mirroring `(?:pub(?:\([^)]*\))?\s+)?`.
fn strip_pub_vis(t: &str) -> &str {
    let Some(rest) = t.strip_prefix("pub") else {
        return t;
    };
    let rest = rest.trim_start();
    if let Some(rest) = rest.strip_prefix('(') {
        // a visibility group: pub(crate), pub(in crate::m), ...
        if let Some(end) = rest.find(')') {
            return rest[end + 1..].trim_start();
        }
        return rest;
    }
    rest
}

/// The first identifier on the line, or `None` when there is none.
fn ident_start(t: &str) -> Option<(&str, &str)> {
    let end = t.find(|c: char| !c.is_ascii_alphanumeric() && c != '_')?;
    if end == 0 {
        return None;
    }
    let name = &t[..end];
    let first = name.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    Some((name, &t[end..]))
}

/// The first type name on the line: `[A-Za-z_][A-Za-z0-9_:]*`, so a
/// path-qualified type like `super::entries` is read as one token.
fn type_ident(t: &str) -> Option<(&str, &str)> {
    let end = t.find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != ':')?;
    if end == 0 {
        return None;
    }
    let name = &t[..end];
    let first = name.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    Some((name, &t[end..]))
}

/// `mod <name> {` (optionally `pub(...)`-qualified), for the scope walk.
fn module_name(sline: &str) -> Option<String> {
    let t = strip_pub_vis(sline.trim_start());
    let t = t.strip_prefix("mod ")?;
    let (name, rest) = ident_start(t)?;
    rest.trim_start().starts_with('{').then(|| name.to_string())
}

/// `type <name> = <type>` (optionally `pub(...)`-qualified, generic name
/// allowed). Returns (alias name, last path segment of the resolved type).
fn alias_decl(sline: &str) -> Option<(String, String)> {
    let t = strip_pub_vis(sline.trim_start());
    let t = t.strip_prefix("type ")?;
    let (name, rest) = ident_start(t)?;
    let rest = rest.trim_start();
    // optional single-level generic args on the alias name
    let rest = if let Some(r) = rest.strip_prefix('<') {
        let end = r.find('>')?;
        &r[end + 1..]
    } else {
        rest
    };
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let (type_name, _) = type_ident(rest)?;
    let last = type_name.rsplit("::").next().unwrap_or(type_name);
    Some((name.to_string(), last.to_string()))
}

/// `name: BTreeMap|BTreeSet|HashMap|HashSet|Vec <` - a direct collection field.
fn field_kind_collection(sline: &str) -> Option<(String, String)> {
    let t = strip_pub_vis(sline.trim_start());
    let (name, rest) = ident_start(t)?;
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    for kind in ["BTreeMap", "BTreeSet", "HashMap", "HashSet", "Vec"] {
        if let Some(after) = rest.strip_prefix(kind) {
            if after.trim_start().starts_with('<') {
                return Some((name.to_string(), kind.to_string()));
            }
        }
    }
    None
}

/// `name: <type>` where the type may be an alias (lowercase or not), generic
/// (nested angle brackets allowed) or path-qualified.
fn field_kind_any(sline: &str) -> Option<(String, String)> {
    let t = strip_pub_vis(sline.trim_start());
    let (name, rest) = ident_start(t)?;
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let (type_name, after) = type_ident(rest)?;
    // optional generic arguments: `<.*>` greedy to the last `>`
    let after = after.trim_start();
    let after = if let Some(r) = after.strip_prefix('<') {
        let end = r.rfind('>')?;
        &r[end + 1..]
    } else {
        after
    };
    let after = after.trim_start();
    if !(after.is_empty() || after == ",") {
        return None;
    }
    let last = type_name.rsplit("::").next().unwrap_or(type_name);
    Some((name.to_string(), last.to_string()))
}

/// The shell gate's `ITER` regex on one candidate: `for <binding> in
/// (optional &) self . <field> (.values()|.keys()|.iter())?` followed by `{`
/// or `&`. The candidate may be a whitespace-normalised multi-line window.
fn iter_field(candidate: &str) -> Option<String> {
    let pos = candidate.find("for ")?;
    let rest = &candidate[pos + 4..];
    let in_pos = rest.find(" in ")?;
    let binding = &rest[..in_pos];
    if binding.trim().is_empty() {
        return None;
    }
    let after = rest[in_pos + 4..].trim_start();
    let after = after.strip_prefix('&').unwrap_or(after).trim_start();
    let after = after.strip_prefix("self")?.trim_start();
    let after = after.strip_prefix('.')?.trim_start();
    let (field, after_field) = ident_start(after)?;
    let after_field = after_field.trim_start();
    // optional `.values()` / `.keys()` / `.iter()`
    let after_method = if let Some(r) = after_field.strip_prefix('.') {
        let r = r.trim_start();
        let matched = ["values()", "keys()", "iter()"]
            .iter()
            .find(|m| r.starts_with(**m))?;
        &r[matched.len()..]
    } else {
        after_field
    };
    // the iteration must be followed by `{` or `&`
    let tail = after_method.trim_start();
    if tail.starts_with('{') || tail.starts_with('&') {
        Some(field.to_string())
    } else {
        None
    }
}

/// Look up `name` under `scope`, walking from the deepest module to the
/// crate root (lexical shadowing).
fn scoped_get<'a>(
    table: &'a HashMap<(Vec<String>, String), String>,
    scope: &[String],
    name: &str,
) -> Option<&'a String> {
    for len in (0..=scope.len()).rev() {
        let key = (scope[..len].to_vec(), name.to_string());
        if let Some(value) = table.get(&key) {
            return Some(value);
        }
    }
    None
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Scan forward from `from` past a run of word bytes, returning the end.
fn word_run_end(bytes: &[u8], from: usize) -> usize {
    let mut end = from;
    while end < bytes.len() && is_word_byte(bytes[end]) {
        end += 1;
    }
    end
}

/// Scan forward from `from` past a run of ASCII whitespace.
fn ws_end(bytes: &[u8], from: usize) -> usize {
    let mut end = from;
    while end < bytes.len() && bytes[end].is_ascii_whitespace() {
        end += 1;
    }
    end
}

/// `\w+ \s* a \s* b` anywhere in the text.
fn word_then(text: &str, a: &str, b: &str) -> bool {
    let bytes = text.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if is_word_byte(bytes[pos]) {
            let word_end = word_run_end(bytes, pos);
            let after_word = ws_end(bytes, word_end);
            if text[after_word..].starts_with(a) {
                let after_a = ws_end(bytes, after_word + a.len());
                if text[after_a..].starts_with(b) {
                    return true;
                }
            }
            pos = word_end;
        } else {
            pos += 1;
        }
    }
    false
}

/// `\w+ \s* [op] =` (fold like `x += 1`).
fn word_op_assign(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if is_word_byte(bytes[pos]) {
            let word_end = word_run_end(bytes, pos);
            let after_word = ws_end(bytes, word_end);
            if after_word < bytes.len()
                && matches!(bytes[after_word], b'+' | b'-' | b'^' | b'|')
                && text[after_word + 1..].trim_start().starts_with('=')
            {
                return true;
            }
            pos = word_end;
        } else {
            pos += 1;
        }
    }
    false
}

/// `\w+ \s* = \s* \w+ \s* [op]` (fold like `sum = sum + x`).
fn word_assign_word_op(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if is_word_byte(bytes[pos]) {
            let word_end = word_run_end(bytes, pos);
            let after_word = ws_end(bytes, word_end);
            if text[after_word..].starts_with('=') {
                let after_eq = ws_end(bytes, after_word + 1);
                if after_eq < bytes.len() && is_word_byte(bytes[after_eq]) {
                    let rhs_end = word_run_end(bytes, after_eq);
                    let after_rhs = ws_end(bytes, rhs_end);
                    if after_rhs < bytes.len()
                        && matches!(bytes[after_rhs], b'+' | b'-' | b'^' | b'|')
                    {
                        return true;
                    }
                }
            }
            pos = word_end;
        } else {
            pos += 1;
        }
    }
    false
}

fn has_fold(body: &str) -> bool {
    word_then(body, ".", "update(")
        || word_then(body, ".", "push(")
        || word_op_assign(body)
        || word_assign_word_op(body)
}

/// `\w+ [ \w+ ] =` - a write to an indexed slot, order-independent.
fn has_own_slot_write(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if is_word_byte(bytes[pos]) {
            let word_end = word_run_end(bytes, pos);
            let after_word = ws_end(bytes, word_end);
            if after_word < bytes.len() && bytes[after_word] == b'[' {
                let after_bracket = ws_end(bytes, after_word + 1);
                if after_bracket < bytes.len() && is_word_byte(bytes[after_bracket]) {
                    let index_end = word_run_end(bytes, after_bracket);
                    let after_index = ws_end(bytes, index_end);
                    if after_index < bytes.len()
                        && bytes[after_index] == b']'
                        && body[after_index + 1..].trim_start().starts_with('=')
                    {
                        return true;
                    }
                }
            }
            pos = word_end;
        } else {
            pos += 1;
        }
    }
    false
}

/// Signed brace balance of one line.
fn brace_delta(line: &str) -> i64 {
    i64::try_from(line.matches('{').count()).unwrap_or(i64::MAX)
        - i64::try_from(line.matches('}').count()).unwrap_or(i64::MAX)
}

/// Walk every `.rs` file under `root`, flagging hashing functions that
/// iterate unordered collections.
fn collect_findings(root: &Path) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.filter_map(Result::ok) {
            let Ok(path_kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if path_kind.is_dir() {
                let name = path.to_string_lossy();
                if !name.contains("/target") && !name.contains("/.git") {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                findings.extend(scan_file(&path, &rel));
            }
        }
    }
    findings
}

/// Analyse one `.rs` file: build the module-scoped declaration and alias
/// tables from the scrubbed view, then walk hashing function bodies on the
/// raw lines looking for unordered iteration.
fn scan_file(path: &std::path::Path, rel: &str) -> Vec<Finding> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    let mut findings: Vec<Finding> = Vec::new();

    // Module-scoped declared types and aliases, from the scrubbed view so
    // braces inside comments/strings cannot move scope.
    let scrubbed = rust_literals::scrub(&text);
    let scrubbed_lines: Vec<&str> = scrubbed.lines().collect();
    let mut declared: HashMap<(Vec<String>, String), String> = HashMap::new();
    let mut aliases: HashMap<(Vec<String>, String), String> = HashMap::new();
    let mut module_stack: Vec<(String, i64)> = Vec::new();
    let mut block_depth = 0i64;
    let mut line_scopes: Vec<Vec<String>> = Vec::with_capacity(lines.len());
    for sline in &scrubbed_lines {
        if let Some(name) = module_name(sline) {
            module_stack.push((
                name,
                block_depth + i64::try_from(sline.matches('{').count()).unwrap_or(0),
            ));
        }
        let scope: Vec<String> = module_stack.iter().map(|(n, _)| n.clone()).collect();
        line_scopes.push(scope.clone());
        block_depth += brace_delta(sline);
        if let Some((name, typ)) = alias_decl(sline) {
            aliases.insert((scope.clone(), name), typ);
        }
        if let Some((name, kind)) = field_kind_collection(sline) {
            declared.insert((scope, name), kind);
        } else if let Some((name, typ)) = field_kind_any(sline) {
            declared.insert((scope, name), typ);
        }
        while module_stack
            .last()
            .is_some_and(|(_, open)| block_depth < *open)
        {
            module_stack.pop();
        }
    }

    // Walk function bodies on the raw lines, like the shell gate.
    let mut inside = false;
    let mut depth = 0i64;
    let mut fname = String::new();
    let mut start = 0usize;
    for (idx, line) in lines.iter().enumerate() {
        if let Some(name) = is_hashing_fn(line) {
            if !inside {
                inside = true;
                depth = 0;
                fname = name;
                start = idx;
            }
        }
        if !inside {
            continue;
        }
        depth += brace_delta(line);
        // rustfmt splits a long `for` header across lines; join the next
        // three lines before searching (four total).
        let window = lines[idx..(idx + 4).min(lines.len())]
            .iter()
            .map(|l| l.trim())
            .collect::<Vec<_>>()
            .join(" ");
        let field = iter_field(line).or_else(|| iter_field(&window));
        if let Some(field) = field {
            let scope = line_scopes.get(idx).cloned().unwrap_or_default();
            let mut kind = scoped_get(&declared, &scope, &field).cloned();
            let mut seen: HashSet<String> = HashSet::new();
            while let Some(current) = kind.clone() {
                if !seen.insert(current.clone()) {
                    break;
                }
                match scoped_get(&aliases, &scope, &current) {
                    Some(next) => kind = Some(next.clone()),
                    None => break,
                }
            }
            if kind.as_deref().is_some_and(|k| UNORDERED.contains(&k)) {
                let body = lines[idx..(idx + 40).min(lines.len())].join("\n");
                let body = body
                    .find("\n        }")
                    .map(|e| body[..e].to_string())
                    .unwrap_or(body);
                if has_fold(&body) && !has_own_slot_write(&body) {
                    findings.push(Finding {
                        path: rel.to_string(),
                        line: idx + 1,
                        fname: fname.clone(),
                        field,
                        kind: kind.unwrap_or_default(),
                    });
                }
            }
        }
        if depth <= 0 && idx > start {
            inside = false;
        }
    }
    findings
}

/// # Errors
///
/// Returns a finding per hashing function iterating an unordered collection.
pub fn run(root: &Path) -> Result<String, String> {
    let findings = collect_findings(root);

    if findings.is_empty() {
        return Ok(String::from(
            "Consensus-map ordering OK: every collection hashed into a commitment is ordered.",
        ));
    }
    let mut msg = String::from("FAIL: a hashing function iterates an unordered collection:\n");
    for f in &findings {
        writeln!(
            msg,
            "  {}:{}  fn {}() iterates self.{}: {}<..>",
            f.path, f.line, f.fname, f.field, f.kind
        )
        .expect("writing to a String cannot fail");
    }
    msg.push_str(
        "\nHashMap/HashSet iteration order comes from a per-process random seed, so\n\
         two honest nodes with identical state produce different digests. Use\n\
         BTreeMap/BTreeSet, or collect and sort before hashing.",
    );
    Err(msg)
}

fn scratch_dir() -> Result<std::path::PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-consensus-map-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create scratch dir: {e}"))?;
    Ok(dir)
}

/// Run the gate on a single-fixture tree and return whether it passed.
fn fixture_passes(dir: &std::path::Path, src: &str) -> Result<bool, String> {
    std::fs::write(dir.join("src/ok.rs"), src).map_err(|e| e.to_string())?;
    Ok(run(dir).is_ok())
}

/// # Errors
///
/// Returns a finding when a `HashMap` hashed into a root passes, or when an
/// ordered or order-independent loop fails.
pub fn self_test() -> Result<String, String> {
    let dir = scratch_dir()?;
    std::fs::create_dir_all(dir.join("src")).map_err(|e| e.to_string())?;
    let mut failures: Vec<String> = Vec::new();

    let ordered = "pub struct Registry {\n    entries: BTreeMap<u64, u64>,\n}\nimpl Registry {\n    pub fn root(&self) -> [u8; 32] {\n        let mut hasher = Sha256::new();\n        for entry in self.entries.values() {\n            hasher.update(entry.to_le_bytes());\n        }\n        hasher.finalize().into()\n    }\n}\n";
    if !fixture_passes(&dir, ordered)? {
        failures.push(String::from("ordered tree rejected"));
    }

    let hashed = ordered.replace("BTreeMap<u64, u64>", "HashMap<u64, u64>");
    if fixture_passes(&dir, &hashed)? {
        failures.push(String::from("a HashMap hashed into a root was accepted"));
    }

    // The same HashMap outside a hashing function is fine.
    let non_hashing = "pub struct Registry {\n    entries: HashMap<u64, u64>,\n}\nimpl Registry {\n    pub fn total(&self) -> u64 {\n        let mut sum = 0;\n        for entry in self.entries.values() {\n            sum += entry;\n        }\n        sum\n    }\n}\n";
    if !fixture_passes(&dir, non_hashing)? {
        failures.push(String::from(
            "a HashMap that never reaches a digest was flagged",
        ));
    }

    // Tuple destructuring, the shape almost every map walk uses.
    let tuple_walk = "pub struct Registry {\n    entries: HashMap<u64, u64>,\n}\nimpl Registry {\n    pub fn root(&self) -> [u8; 32] {\n        let mut hasher = Sha256::new();\n        for (k, v) in &self.entries {\n            hasher.update(k.to_le_bytes());\n            hasher.update(v.to_le_bytes());\n        }\n        hasher.finalize().into()\n    }\n}\n";
    if fixture_passes(&dir, tuple_walk)? {
        failures.push(String::from(
            "a HashMap walked as (key, value) pairs was accepted",
        ));
    }

    // Lowercase alias.
    let lower_alias = "type entries = HashMap<u64, u64>;\npub struct Registry {\n    rows: entries,\n}\nimpl Registry {\n    pub fn root(&self) -> [u8; 32] {\n        let mut hasher = Sha256::new();\n        for (k, v) in &self.rows {\n            hasher.update(k.to_le_bytes());\n            hasher.update(v.to_le_bytes());\n        }\n        hasher.finalize().into()\n    }\n}\n";
    if fixture_passes(&dir, lower_alias)? {
        failures.push(String::from(
            "a lowercase alias hiding a hashed HashMap was accepted",
        ));
    }

    // Generic alias.
    let generic_alias = "type Entries<K, V> = HashMap<K, V>;\npub struct Registry {\n    rows: Entries<u64, u64>,\n}\nimpl Registry {\n    pub fn root(&self) -> [u8; 32] {\n        let mut hasher = Sha256::new();\n        for (k, v) in &self.rows {\n            hasher.update(k.to_le_bytes());\n            hasher.update(v.to_le_bytes());\n        }\n        hasher.finalize().into()\n    }\n}\n";
    if fixture_passes(&dir, generic_alias)? {
        failures.push(String::from(
            "a generic alias hiding a hashed HashMap was accepted",
        ));
    }

    // Nested generic application.
    let nested_generic = "type Entries<K, V> = HashMap<K, V>;\npub struct Registry {\n    rows: Entries<HashMap<u64, u64>, u64>,\n}\nimpl Registry {\n    pub fn root(&self) -> [u8; 32] {\n        let mut hasher = Sha256::new();\n        for (k, v) in &self.rows {\n            hasher.update(k.to_le_bytes());\n            hasher.update(v.to_le_bytes());\n        }\n        hasher.finalize().into()\n    }\n}\n";
    if fixture_passes(&dir, nested_generic)? {
        failures.push(String::from(
            "a nested generic alias hiding a hashed HashMap was accepted",
        ));
    }

    // Path-qualified alias use.
    let path_qualified = "type entries = HashMap<u64, u64>;\npub struct Registry {\n    rows: super::entries,\n}\nimpl Registry {\n    pub fn root(&self) -> [u8; 32] {\n        let mut hasher = Sha256::new();\n        for (k, v) in &self.rows {\n            hasher.update(k.to_le_bytes());\n            hasher.update(v.to_le_bytes());\n        }\n        hasher.finalize().into()\n    }\n}\n";
    if fixture_passes(&dir, path_qualified)? {
        failures.push(String::from(
            "a path-qualified alias hiding a hashed HashMap was accepted",
        ));
    }

    // Path-qualified visibility.
    let vis_qualified = "pub(in crate::m) type entries = HashMap<u64, u64>;\npub struct Registry {\n    rows: entries,\n}\nimpl Registry {\n    pub fn root(&self) -> [u8; 32] {\n        let mut hasher = Sha256::new();\n        for (k, v) in &self.rows {\n            hasher.update(k.to_le_bytes());\n            hasher.update(v.to_le_bytes());\n        }\n        hasher.finalize().into()\n    }\n}\n";
    if fixture_passes(&dir, vis_qualified)? {
        failures.push(String::from(
            "a visibility-qualified alias hiding a hashed HashMap was accepted",
        ));
    }

    // Shadowed alias inside a module must not be masked by a safe outer one.
    let shadowed = "use std::collections::{BTreeMap, HashMap};\nuse sha2::{Digest, Sha256};\n\ntype Entries = BTreeMap<u64, u64>;\n\npub(crate) mod attacker {\n    use super::*;\n    type Entries = HashMap<u64, u64>;\n    pub struct Registry {\n        rows: Entries,\n    }\n    impl Registry {\n        pub fn root(&self) -> [u8; 32] {\n            let mut hasher = Sha256::new();\n            for (k, v) in &self.rows {\n                hasher.update(k.to_le_bytes());\n                hasher.update(v.to_le_bytes());\n            }\n            hasher.finalize().into()\n        }\n    }\n}\n";
    if fixture_passes(&dir, shadowed)? {
        failures.push(String::from(
            "an inner module shadowing an outer alias was accepted",
        ));
    }

    // A stray `}` in a comment or string must not pop the module scope.
    let comment_brace = "use std::collections::{BTreeMap, HashMap};\nuse sha2::{Digest, Sha256};\n\ntype Entries = BTreeMap<u64, u64>;\n\npub(crate) mod attacker {\n    use super::*;\n    type Entries = HashMap<u64, u64>;\n    pub struct Registry {\n        rows: Entries,\n        // }  this brace is inside a comment\n    }\n    impl Registry {\n        pub fn root(&self) -> [u8; 32] {\n            let marker = \"}\";  // and this one inside a string\n            let mut hasher = Sha256::new();\n            for (k, v) in &self.rows {\n                hasher.update(k.to_le_bytes());\n                hasher.update(v.to_le_bytes());\n            }\n            hasher.finalize().into()\n        }\n    }\n}\n";
    if fixture_passes(&dir, comment_brace)? {
        failures.push(String::from(
            "comment/string braces popping module scope early was accepted",
        ));
    }

    // A `}` inside a char literal must not pop the module scope.
    let char_brace = "use std::collections::{BTreeMap, HashMap};\nuse sha2::{Digest, Sha256};\n\ntype Entries = BTreeMap<u64, u64>;\n\npub(crate) mod attacker {\n    use super::*;\n    const CLOSER: char = '}';\n    type Entries = HashMap<u64, u64>;\n    pub struct Registry {\n        rows: Entries,\n    }\n    impl Registry {\n        pub fn root(&self) -> [u8; 32] {\n            let mut hasher = Sha256::new();\n            for (k, v) in &self.rows {\n                hasher.update(k.to_le_bytes());\n                hasher.update(v.to_le_bytes());\n            }\n            hasher.finalize().into()\n        }\n    }\n}\n";
    if fixture_passes(&dir, char_brace)? {
        failures.push(String::from(
            "a char literal brace popping module scope early was accepted",
        ));
    }

    // The same shape wrapped across lines by the formatter.
    let wrapped = "pub struct Registry {\n    entries: HashMap<u64, u64>,\n}\nimpl Registry {\n    pub fn root(&self) -> [u8; 32] {\n        let mut hasher = Sha256::new();\n        for (k, v) in self\n            .entries\n            .iter()\n        {\n            hasher.update(k.to_le_bytes());\n            hasher.update(v.to_le_bytes());\n        }\n        hasher.finalize().into()\n    }\n}\n";
    if fixture_passes(&dir, wrapped)? {
        failures.push(String::from("a wrapped HashMap iterator was accepted"));
    }

    // A loop that writes each entry to its own slot is order-independent.
    let own_slot = "pub struct Registry {\n    dirty: HashSet<u64>,\n    leaves: Vec<[u8; 32]>,\n}\nimpl Registry {\n    pub fn calculate_state_root(&mut self) -> [u8; 32] {\n        for key in &self.dirty {\n            let pos = *key as usize;\n            let mut h = Sha256::new();\n            h.update(key.to_le_bytes());\n            self.leaves[pos] = h.finalize().into();\n        }\n        self.leaves[0]\n    }\n}\n";
    if !fixture_passes(&dir, own_slot)? {
        failures.push(String::from(
            "a loop that writes each entry to its own slot was flagged",
        ));
    }

    let _ = std::fs::remove_dir_all(&dir);
    if failures.is_empty() {
        Ok(String::from(
            "Consensus-map ordering self-test OK: a hashed HashMap, one walked as \
             (key, value) pairs, one wrapped across lines, one hidden behind a \
             lowercase alias, one behind a generic alias, one behind a nested \
             generic application, one behind a path-qualified alias use, one \
             behind a visibility-qualified alias, one behind a path-qualified \
             visibility, one shadowed inside a module, one whose scope is \
             protected from comment/string braces and one protected from a \
             char-literal brace are all rejected; an ordered map, a non-hashing \
             HashMap and a write-to-own-slot loop all pass.",
        ))
    } else {
        Err(failures.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashing_fn_names_are_recognised() {
        assert_eq!(
            is_hashing_fn("    pub fn root(&self) -> [u8; 32] {"),
            Some("root".into())
        );
        assert_eq!(
            is_hashing_fn("    pub(crate) fn calculate_state_root(&mut self)"),
            Some("calculate_state_root".into())
        );
        assert_eq!(is_hashing_fn("    fn rooted(&self) {}"), None);
        assert_eq!(is_hashing_fn("    fn total(&self) {}"), None);
    }

    #[test]
    fn iter_field_matches_the_shell_shapes() {
        assert_eq!(
            iter_field("for (k, v) in &self.rows {"),
            Some("rows".into())
        );
        assert_eq!(
            iter_field("for entry in self.entries.values() {"),
            Some("entries".into())
        );
        assert_eq!(
            iter_field("for (k, v) in self .entries .iter() {"),
            Some("entries".into())
        );
        assert_eq!(iter_field("for x in self.rows"), None);
        assert_eq!(iter_field("for x in self.rows &&"), Some("rows".into()));
    }

    #[test]
    fn alias_chain_resolves_to_collection() {
        let mut aliases: HashMap<(Vec<String>, String), String> = HashMap::new();
        aliases.insert((vec![], "Entries".into()), "HashMap".into());
        let scope: Vec<String> = Vec::new();
        let kind = scoped_get(&aliases, &scope, "Entries").cloned();
        assert_eq!(kind.as_deref(), Some("HashMap"));
        // scope lookup falls back to the crate root
        let scope = vec!["attacker".to_string()];
        assert_eq!(
            scoped_get(&aliases, &scope, "Entries").cloned().as_deref(),
            Some("HashMap")
        );
    }

    #[test]
    fn fold_detection_matches_the_shell_regexes() {
        assert!(has_fold("    hasher.update(x);"));
        assert!(has_fold("    self.leaves.push(x);"));
        assert!(has_fold("    sum += entry;"));
        assert!(has_fold("    sum = sum + entry;"));
        assert!(!has_fold("    let x = 1;"));
        assert!(has_own_slot_write("    self.leaves[pos] = h.finalize();"));
        assert!(!has_own_slot_write("    let x = y;"));
    }
}
