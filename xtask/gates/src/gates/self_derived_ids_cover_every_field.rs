//! A field outside a self-derived id must say so next to itself.
//!
//! Ported from `scripts/check-self-derived-ids-cover-every-field.sh`, 522
//! lines of shell wrapping Python. The shell was a here-doc launcher and the
//! Python did the work, so the port replaces two languages with one, and the
//! Python's regexes become plain string and brace matching.
//!
//! # Why this gate exists
//!
//! `AiInferenceRequest` carries a `request_id` that the requester computes
//! from the request's own fields, signs inside the transaction, and the
//! registry re-derives before it will accept anything: `submit_request`
//! refuses when `verify_id` fails. That makes the id the thing the requester
//! is bound to.
//!
//! The `effort` tier was added to the struct and, in the same change, to
//! `calculate_id`. Had it been added to the struct alone, the shape would
//! have looked finished and behaved as a hole: an operator could take a
//! `5.0x` request, rewrite the tier to `0.5x`, keep the id it was handed, do
//! the cheap work, and claim the deep fee, because nothing the requester
//! signed named the depth.
//!
//! That failure is not specific to one field. Any struct with a self-derived
//! id has the same shape: the id is only a commitment to the fields it
//! hashes, and a field left outside can be rewritten under a stable id.
//!
//! # What the gate checks
//!
//! For every production struct whose impl defines `verify_id`, every field
//! other than the id itself must either be named in the derivation the id
//! comes from, or carry `IDENTITY: excluded - <reason>` in its own doc
//! comment. It also refuses the reverse: a field that is both marked excluded
//! and named in the derivation.
//!
//! # Known limits
//!
//! Coverage is measured by name: a derivation that mentions `self.foo` counts
//! `foo` as bound, and this gate cannot tell whether it was hashed, printed,
//! or used in a length check.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Roots holding shipped library code.
const SCAN_ROOTS: &[&str] = &["src", "budzero", "wallet-core"];

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
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
///
/// Test fixtures build these structs by hand all the time, and a fixture
/// naming a field is not a derivation binding it. A `#[cfg(test)]` that is
/// not a `mod` (a bare `fn`) is not removed: the marker is left in place so
/// the text after it survives, exactly as Python's `re.search` does.
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

/// `name -> body` for every function with a body in `src`.
///
/// A regex that stops at the first brace-or-semicolon after the argument list
/// looks like it would do this and does not: `-> [u8; 32]` contains a
/// semicolon, so every function returning a fixed-size array is skipped. The
/// signature is walked instead: the argument list is paren-balanced, then the
/// return type is bracket-balanced, with the `>` of `->` excluded.
fn fn_bodies(src: &str) -> BTreeMap<String, String> {
    let bytes = src.as_bytes();
    let mut bodies = BTreeMap::new();
    let mut pos = 0usize;
    while pos + 2 < bytes.len() {
        if bytes[pos] == b'f' && bytes[pos + 1] == b'n' && bytes[pos + 2].is_ascii_whitespace() {
            let word_ok =
                pos == 0 || !(bytes[pos - 1].is_ascii_alphanumeric() || bytes[pos - 1] == b'_');
            if word_ok {
                let mut cursor = ws_skip(src, pos + 2);
                let name_start = cursor;
                while cursor < bytes.len() && is_ident_byte(bytes[cursor]) {
                    cursor += 1;
                }
                let name = &src[name_start..cursor];
                cursor = ws_skip(src, cursor);
                if cursor < bytes.len() && bytes[cursor] == b'(' {
                    let mut depth = 0usize;
                    let mut arg = cursor;
                    while arg < bytes.len() {
                        match bytes[arg] {
                            b'(' => depth += 1,
                            b')' => {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                        arg += 1;
                    }
                    let mut brackets = 0usize;
                    let mut ret = arg + 1;
                    while ret < bytes.len() {
                        let c = bytes[ret];
                        if c == b'>' && ret > 0 && bytes[ret - 1] == b'-' {
                            ret += 1;
                            continue;
                        }
                        match c {
                            b'[' | b'<' | b'(' => brackets += 1,
                            b']' | b'>' | b')' => brackets = brackets.saturating_sub(1),
                            b'{' if brackets == 0 => {
                                bodies.insert(name.to_string(), balanced(src, ret));
                                break;
                            }
                            b';' if brackets == 0 => break,
                            _ => {}
                        }
                        ret += 1;
                    }
                    pos = ret;
                    continue;
                }
            }
        }
        pos += 1;
    }
    bodies
}

/// `(name, doc)` for each `pub` field, doc being the comment above it.
fn struct_fields(body: &str) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    let mut doc: Vec<String> = Vec::new();
    for line in body.split('\n') {
        let stripped = line.trim();
        if stripped.starts_with("///") || stripped.starts_with("//") {
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
            let after = rest[name_end..].trim_start();
            if after.starts_with(':') {
                fields.push((name.to_string(), doc.join("\n")));
            }
            doc.clear();
            continue;
        }
        if stripped.starts_with('#') {
            continue;
        }
        if !stripped.is_empty() {
            doc.clear();
        }
    }
    fields
}

/// The reason on an `IDENTITY: excluded` marker, or `None` when absent.
fn identity_excluded(doc: &str) -> Option<String> {
    let at = doc.find("IDENTITY:")?;
    let mut j = at + "IDENTITY:".len();
    j = ws_skip(doc, j);
    if !doc[j..].starts_with("excluded") {
        return None;
    }
    let after = j + "excluded".len();
    if doc.as_bytes().get(after).is_some_and(|b| is_ident_byte(*b)) {
        return None;
    }
    Some(
        doc[after..]
            .trim_matches(|c: char| c == ' ' || c == '-' || c == '\t')
            .to_string(),
    )
}

/// Is `self.field` present with word boundaries in the derivation text?
fn bound_in(derivation: &str, field: &str) -> bool {
    let needle = format!("self.{field}");
    let nb = needle.as_bytes();
    let bytes = derivation.as_bytes();
    let mut i = 0usize;
    while i + nb.len() <= bytes.len() {
        if &bytes[i..i + nb.len()] == nb {
            let prev_ok = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            let after = i + nb.len();
            let next_ok = after >= bytes.len()
                || !(bytes[after].is_ascii_alphanumeric() || bytes[after] == b'_');
            if prev_ok && next_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Every `name(` call in the text, deduplicated.
fn called_names(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut out = BTreeSet::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if is_ident_byte(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_ident_byte(bytes[i]) {
                i += 1;
            }
            let name = &text[start..i];
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                out.insert(name.to_string());
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

/// The field `verify_id` compares against, falling back to the first field.
fn id_field_of(derivation: &str, first_field: &str) -> String {
    let bytes = derivation.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"self.") {
            let mut j = i + 5;
            let start = j;
            while j < bytes.len() && is_ident_byte(bytes[j]) {
                j += 1;
            }
            if j > start {
                let name = &derivation[start..j];
                let mut k = j;
                while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
                let cmp = k + 2 <= bytes.len()
                    && (&bytes[k..k + 2] == b"==" || &bytes[k..k + 2] == b"!=");
                if cmp {
                    return name.to_string();
                }
            }
            i = j;
            continue;
        }
        i += 1;
    }
    first_field.to_string()
}

struct Outcome {
    structs: usize,
    fields: usize,
    problems: Vec<String>,
}

/// Measure the whole tree for structs with a self-derived id.
fn measure(root: &Path) -> Result<Outcome, String> {
    let mut files = Vec::new();
    for scan_root in SCAN_ROOTS {
        collect_rs(&root.join(scan_root), &mut files);
    }
    files.sort();
    if files.is_empty() {
        return Err(format!(
            "no production .rs files found under {}",
            root.display()
        ));
    }

    let mut out = Outcome {
        structs: 0,
        fields: 0,
        problems: Vec::new(),
    };

    for path in &files {
        measure_one(path, root, &mut out);
    }

    if out.structs == 0 {
        return Err(String::from(
            "gate found no struct with a verify_id to measure - wrong root?",
        ));
    }
    Ok(out)
}

/// Measure one file: structs with a `verify_id` impl and their field coverage.
fn measure_one(path: &Path, root: &Path, out: &mut Outcome) {
    let raw = std::fs::read(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))
        .unwrap_or_default();
    let src = String::from_utf8_lossy(&raw).into_owned();
    let src = strip_test_mods(&src);
    if !src.contains("fn verify_id") {
        return;
    }

    let mut structs: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut cursor = 0usize;
    while let Some(rel) = src[cursor..].find("pub struct ") {
        let start = cursor + rel;
        let after = start + "pub struct ".len();
        let mut pos = after;
        while pos < src.len() && is_ident_byte(src.as_bytes()[pos]) {
            pos += 1;
        }
        let name = src[after..pos].to_string();
        pos = ws_skip(&src, pos);
        if src[pos..].starts_with('{') {
            structs.insert(name, struct_fields(&balanced(&src, pos)));
        }
        cursor = pos;
    }

    let helpers = fn_bodies(&src);

    let mut impl_cursor = 0usize;
    while let Some(rel) = src[impl_cursor..].find("impl ") {
        let start = impl_cursor + rel;
        let after = start + "impl ".len();
        let mut pos = after;
        while pos < src.len() && is_ident_byte(src.as_bytes()[pos]) {
            pos += 1;
        }
        let name = src[after..pos].to_string();
        pos = ws_skip(&src, pos);
        if !src[pos..].starts_with('{') {
            impl_cursor = pos;
            continue;
        }
        let impl_body = balanced(&src, pos);
        if !impl_body.contains("fn verify_id") {
            impl_cursor = pos + 1;
            continue;
        }
        let Some(fields) = structs.get(&name) else {
            impl_cursor = pos + 1;
            continue;
        };
        if fields.is_empty() {
            impl_cursor = pos + 1;
            continue;
        }
        check_impl(&impl_body, &name, fields, &helpers, path, root, out);
        impl_cursor = pos + 1;
    }
}

/// Check one impl's `verify_id` against its struct's fields.
fn check_impl(
    impl_body: &str,
    name: &str,
    fields: &[(String, String)],
    helpers: &BTreeMap<String, String>,
    path: &Path,
    root: &Path,
    out: &mut Outcome,
) {
    let methods = fn_bodies(impl_body);
    let mut derivation = methods.get("verify_id").cloned().unwrap_or_else(|| {
        let rest = &impl_body[impl_body.find("fn verify_id").unwrap_or(0)..];
        match rest.find('{') {
            Some(open) => balanced(
                impl_body,
                impl_body.find("fn verify_id").unwrap_or(0) + open,
            ),
            None => String::new(),
        }
    });
    let mut frontier = vec![derivation.clone()];
    let mut seen: BTreeSet<String> = ["verify_id".to_string()].into_iter().collect();
    while let Some(text) = frontier.pop() {
        for called in called_names(&text) {
            if seen.contains(&called) {
                continue;
            }
            if let Some(body) = methods.get(&called) {
                seen.insert(called.clone());
                derivation.push_str(body);
                frontier.push(body.clone());
            } else if let Some(body) = helpers.get(&called) {
                seen.insert(called.clone());
                derivation.push_str(body);
                frontier.push(body.clone());
            }
        }
    }

    let first = fields[0].0.clone();
    let id_field = id_field_of(&derivation, &first);
    out.structs += 1;
    let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy();

    for (field, doc) in fields {
        if *field == id_field {
            continue;
        }
        out.fields += 1;
        let bound = bound_in(&derivation, field);
        let declared = identity_excluded(doc);
        if !bound && declared.is_none() {
            out.problems.push(format!(
                "{rel}: {name}.{field} is outside the id that {name}.{id_field} \
                 commits to, and the field does not say so. Two values of this \
                 struct can disagree about it under one id, and whichever is \
                 stored first defines the entry. Hash it in the derivation, or \
                 write `IDENTITY: excluded - <reason>` in the field's doc."
            ));
        } else if bound {
            if let Some(reason) = declared {
                out.problems.push(format!(
                    "{rel}: {name}.{field} is marked `IDENTITY: excluded` \
                     ({reason}) and the derivation does read it. The marker is \
                     stale and now describes a hole that is closed. Remove it \
                     in the commit that closed it.",
                    reason = if reason.is_empty() {
                        "no reason given".to_string()
                    } else {
                        reason
                    }
                ));
            }
        }
    }
}

/// # Errors
///
/// Returns a finding when a non-id field is outside the derivation without a
/// marker, or a marker sits on a field the derivation reads.
pub fn run(root: &Path) -> Result<String, String> {
    let out = measure(root)?;
    if !out.problems.is_empty() {
        return Err(out.problems.join("\n"));
    }
    Ok(format!(
        "self-derived id gate OK: {} structs with a verify_id, {} non-id fields \
         each hashed into the id or declaring that they are not",
        out.structs, out.fields
    ))
}

/// A fixture and what the gate must do with it.
struct Canary {
    name: &'static str,
    body: &'static str,
    expect: Expect,
}

/// The classification a canary expects from the gate.
enum Expect {
    Finding,
    Pass,
    MeasuredNothing,
}

const CANARIES: &[Canary] = &[
    Canary {
        name: "covered",
        body: "pub struct Req {\n    pub id: [u8; 32],\n    pub amount: u64,\n    pub effort: u16,\n}\nimpl Req {\n    pub fn calculate_id(&self) -> [u8; 32] {\n        let mut h = Vec::new();\n        h.extend_from_slice(&self.amount.to_le_bytes());\n        h.extend_from_slice(&self.effort.to_le_bytes());\n        [h.len() as u8; 32]\n    }\n    pub fn verify_id(&self) -> bool {\n        self.id == self.calculate_id()\n    }\n}",
        expect: Expect::Pass,
    },
    Canary {
        name: "silent",
        body: "pub struct Req {\n    pub id: [u8; 32],\n    pub amount: u64,\n    pub effort: u16,\n}\nimpl Req {\n    pub fn calculate_id(&self) -> [u8; 32] {\n        let mut h = Vec::new();\n        h.extend_from_slice(&self.amount.to_le_bytes());\n        [h.len() as u8; 32]\n    }\n    pub fn verify_id(&self) -> bool {\n        self.id == self.calculate_id()\n    }\n}",
        expect: Expect::Finding,
    },
    Canary {
        name: "declared",
        body: "pub struct Req {\n    pub id: [u8; 32],\n    pub amount: u64,\n    /// IDENTITY: excluded - mutable across the lifecycle, cannot sit in a\n    /// stable id.\n    pub status: u8,\n}\nimpl Req {\n    pub fn calculate_id(&self) -> [u8; 32] {\n        let mut h = Vec::new();\n        h.extend_from_slice(&self.amount.to_le_bytes());\n        [h.len() as u8; 32]\n    }\n    pub fn verify_id(&self) -> bool {\n        self.id == self.calculate_id()\n    }\n}",
        expect: Expect::Pass,
    },
    Canary {
        name: "stale",
        body: "pub struct Req {\n    pub id: [u8; 32],\n    pub amount: u64,\n    /// IDENTITY: excluded - left over from before it was bound.\n    pub effort: u16,\n}\nimpl Req {\n    pub fn calculate_id(&self) -> [u8; 32] {\n        let mut h = Vec::new();\n        h.extend_from_slice(&self.amount.to_le_bytes());\n        h.extend_from_slice(&self.effort.to_le_bytes());\n        [h.len() as u8; 32]\n    }\n    pub fn verify_id(&self) -> bool {\n        self.id == self.calculate_id()\n    }\n}",
        expect: Expect::Finding,
    },
    Canary {
        name: "delegated",
        body: "pub struct Req {\n    pub id: [u8; 32],\n    pub amount: u64,\n    pub effort: u16,\n}\nfn derive(amount: u64, effort: u16) -> [u8; 32] {\n    [(amount as u8).wrapping_add(effort as u8); 32]\n}\nimpl Req {\n    pub fn verify_id(&self) -> bool {\n        self.id == derive(self.amount, self.effort)\n    }\n}",
        expect: Expect::Pass,
    },
    Canary {
        name: "fixture",
        body: "pub struct Req {\n    pub id: [u8; 32],\n    pub amount: u64,\n    pub effort: u16,\n}\nimpl Req {\n    pub fn calculate_id(&self) -> [u8; 32] {\n        [self.amount as u8; 32]\n    }\n    pub fn verify_id(&self) -> bool {\n        self.id == self.calculate_id()\n    }\n}\n#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn builds() {\n        let r = Req { id: [0; 32], amount: 1, effort: 2 };\n        assert_eq!(r.effort, 2);\n        assert!(!r.verify_id());\n    }\n}",
        expect: Expect::Finding,
    },
    Canary {
        name: "no_verify",
        body: "pub struct Plain {\n    pub a: u64,\n    pub b: u64,\n}\npub struct Req {\n    pub id: [u8; 32],\n    pub amount: u64,\n}\nimpl Req {\n    pub fn calculate_id(&self) -> [u8; 32] {\n        [self.amount as u8; 32]\n    }\n    pub fn verify_id(&self) -> bool {\n        self.id == self.calculate_id()\n    }\n}",
        expect: Expect::Pass,
    },
    Canary {
        name: "empty",
        body: "pub fn nothing() {}",
        expect: Expect::MeasuredNothing,
    },
];

/// A fixture directory with `src/lib.rs` carrying the given body.
fn mk_fixture(tmp: &Path, case: &str, body: &str) -> Result<(), String> {
    let dir = tmp.join(case);
    std::fs::create_dir_all(dir.join("src"))
        .map_err(|e| format!("cannot create fixture dirs: {e}"))?;
    std::fs::write(dir.join("src/lib.rs"), body).map_err(|e| format!("cannot write fixture: {e}"))
}

/// Run the gate against a fixture and classify the result.
fn verdict(tmp: &Path, case: &str, want: &Expect) -> Result<(), String> {
    let dir = tmp.join(case);
    match (run(&dir), want) {
        (Ok(_), Expect::Pass) => Ok(()),
        (Ok(msg), _) => Err(format!("VACUOUS: {case} passed: {msg}")),
        (Err(msg), Expect::Finding) => {
            if msg.contains("no struct with a verify_id") || msg.contains("no production .rs") {
                Err(format!(
                    "BROKEN: {case} measured nothing instead of finding: {msg}"
                ))
            } else {
                Ok(())
            }
        }
        (Err(msg), Expect::MeasuredNothing) => {
            if msg.contains("no struct with a verify_id") || msg.contains("no production .rs") {
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

/// A fresh, exclusively-created scratch directory under the crate's own
/// `target/gate-fixtures`, which the tree owns and the Semgrep scan skips.
fn scratch_dir() -> Result<PathBuf, String> {
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
        let dir = base.join(format!(
            "self-derived-id-{}-{nanos}-{attempt}",
            std::process::id()
        ));
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
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();
    let tmp = scratch_dir()?;
    for c in CANARIES {
        if let Err(e) = mk_fixture(&tmp, c.name, c.body) {
            problems.push(e);
            continue;
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
        "self-derived id gate self-test OK: every field hashed passes, a field \
         silently outside is refused, a declared exclusion passes, a stale \
         exclusion on a bound field is refused, delegation is followed, test \
         fixtures are not bindings, a struct without verify_id is skipped, and \
         a tree with nothing to measure reports so.",
    ))
}
