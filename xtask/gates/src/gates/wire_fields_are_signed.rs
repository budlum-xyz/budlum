//! A field a peer can put on the wire must be inside the signing preimage.
//!
//! Ported from `scripts/check-wire-fields-are-signed.sh`, 466 lines of shell
//! wrapping Python. The shell was a here-doc launcher and the Python did the
//! work, so the port replaces two languages with one, and the Python's
//! regexes become plain string and brace matching.
//!
//! # Why this gate exists
//!
//! `Transaction::signing_hash` builds a byte string by hand, field by field,
//! and `encode_transaction_type_payload` appends the variant's own payload.
//! Three variants drifted: `AiModelSpec.execution_weights_digest` and
//! `.execution_dims`, `AiInferenceRequest.effort`, and
//! `AiExecutionProof.weights_digest` and `.public_inputs` all crossed the
//! wire without reaching the preimage, so a relaying node could rewrite them
//! and the signature still verified.
//!
//! # What the gate checks
//!
//! For every `TransactionType` variant, take the struct types it carries,
//! take every `pub` field of those structs, and require that
//! `encode_transaction_type_payload` (following the `encode_*` helpers it
//! calls) mentions each one, or that the field carries
//! `SIGNING: excluded - <reason>` in its own doc comment.
//!
//! # Known limits
//!
//! Coverage is by name: a preimage that mentions `spec.foo` counts `foo` as
//! committed, and this gate cannot tell whether the bytes were appended or
//! the field was read for a length check.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The transaction module, where the enum and the encoder live.
const TX: &str = "src/core/transaction.rs";

/// Roots holding shipped library code, for resolving carried structs.
const SCAN_ROOTS: &[&str] = &["src", "wallet-core"];

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

/// The body of `fn name`, walking the signature rather than guessing.
///
/// A regex that stops at the first brace or semicolon after the arguments
/// misses any function returning `[u8; 32]`, because the return type holds a
/// semicolon.
fn fn_body(src: &str, name: &str) -> Option<String> {
    let bytes = src.as_bytes();
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
                if &src[name_start..cursor] == name {
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
                                    return Some(balanced(src, ret));
                                }
                                b';' if brackets == 0 => return None,
                                _ => {}
                            }
                            ret += 1;
                        }
                        return None;
                    }
                }
            }
        }
        pos += 1;
    }
    None
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

/// The reason on an `SIGNING: excluded` marker, or `None` when absent.
fn signing_excluded(doc: &str) -> Option<String> {
    let at = doc.find("SIGNING:")?;
    let mut j = at + "SIGNING:".len();
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

/// Is `.field` present with word boundaries in the text?
fn bound_in(text: &str, field: &str) -> bool {
    let needle = format!(".{field}");
    let nb = needle.as_bytes();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i + nb.len() <= bytes.len() {
        if &bytes[i..i + nb.len()] == nb {
            let after = i + nb.len();
            let next_ok = after >= bytes.len()
                || !(bytes[after].is_ascii_alphanumeric() || bytes[after] == b'_');
            if next_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Every `encode_*` helper name called directly in the text.
fn helpers_called(text: &str, all_helpers: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for name in all_helpers {
        let needle = format!("{name}(");
        if text.contains(&needle) {
            out.insert(name.clone());
        }
    }
    out
}

/// Every capitalised word in the enum body: the carried struct types.
fn carried_types(enum_body: &str) -> BTreeSet<String> {
    let bytes = enum_body.as_bytes();
    let mut out = BTreeSet::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_uppercase() {
            let start = i;
            while i < bytes.len() && is_ident_byte(bytes[i]) {
                i += 1;
            }
            if i > start {
                out.insert(enum_body[start..i].to_string());
            }
            continue;
        }
        i += 1;
    }
    out
}

struct Outcome {
    structs: usize,
    fields: usize,
    problems: Vec<String>,
}

/// Measure the tree.
/// The preimage text: the payload encoder plus every `encode_*` helper it
/// reaches, two levels deep.
fn build_committed(tx_src: &str) -> Result<String, String> {
    let preimage = fn_body(tx_src, "encode_transaction_type_payload");
    let Some(mut committed) = preimage else {
        return Err(String::from(
            "`encode_transaction_type_payload` has no body the gate can read.",
        ));
    };

    // The helpers it delegates to are part of the preimage, two levels deep.
    let mut helpers: BTreeMap<String, String> = BTreeMap::new();
    let mut pos = 0usize;
    while let Some(rel) = tx_src[pos..].find("fn encode_") {
        let start = pos + rel;
        let after = start + "fn encode_".len();
        let mut j = after;
        while j < tx_src.len() && is_ident_byte(tx_src.as_bytes()[j]) {
            j += 1;
        }
        let name = format!("encode_{}", &tx_src[after..j]);
        if let Some(body) = fn_body(tx_src, &name) {
            helpers.insert(name, body);
        }
        pos = j;
    }
    let helper_names: BTreeSet<String> = helpers.keys().cloned().collect();
    let first_level = helpers_called(&committed, &helper_names);
    for name in &first_level {
        if let Some(body) = helpers.get(name) {
            committed.push_str(body);
        }
    }
    for name in &helper_names {
        if committed.contains(&format!("{name}(")) {
            if let Some(body) = helpers.get(name) {
                committed.push_str(body);
            }
        }
    }
    Ok(committed)
}

/// Every struct in the tree, resolved to its relative path and fields.
fn collect_structs(root: &Path) -> BTreeMap<String, (String, Vec<(String, String)>)> {
    let mut structs: BTreeMap<String, (String, Vec<(String, String)>)> = BTreeMap::new();
    let mut files = Vec::new();
    for r in SCAN_ROOTS {
        collect_rs(&root.join(r), &mut files);
    }
    for path in &files {
        let raw = std::fs::read(path).unwrap_or_default();
        let src = String::from_utf8_lossy(&raw).into_owned();
        let mut cursor = 0usize;
        while let Some(rel) = src[cursor..].find("pub struct ") {
            let start = cursor + rel;
            let after = start + "pub struct ".len();
            let mut j = after;
            while j < src.len() && is_ident_byte(src.as_bytes()[j]) {
                j += 1;
            }
            let name = src[after..j].to_string();
            j = ws_skip(&src, j);
            if src[j..].starts_with('{') {
                structs.entry(name.clone()).or_insert_with(|| {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .into_owned();
                    (rel, struct_fields(&balanced(&src, j)))
                });
            }
            cursor = j;
        }
    }
    structs
}

fn measure(root: &Path) -> Result<Outcome, String> {
    let tx = root.join(TX);
    if !tx.is_file() {
        return Err(String::from("no transaction module found - wrong root?"));
    }
    let tx_src =
        std::fs::read_to_string(&tx).map_err(|e| format!("cannot read {}: {e}", tx.display()))?;

    let enum_at = tx_src.find("pub enum TransactionType");
    if enum_at.is_none() {
        return Err(String::from(
            "no `pub enum TransactionType` found - wrong root?",
        ));
    }
    let enum_at = enum_at.unwrap();
    let open = tx_src[enum_at..].find('{').map(|d| enum_at + d);
    let Some(open) = open else {
        return Err(String::from(
            "`TransactionType` has no body the gate can read.",
        ));
    };
    let enum_body = balanced(&tx_src, open);

    let committed = build_committed(&tx_src)?;
    // Every struct in the tree, so a variant carrying `AiModelSpec` can be
    // resolved.
    let structs = collect_structs(root);

    let carried = carried_types(&enum_body);
    if carried.is_empty() {
        return Err(String::from(
            "TransactionType carries no named types - wrong parse?",
        ));
    }

    let mut out = Outcome {
        structs: 0,
        fields: 0,
        problems: Vec::new(),
    };

    for type_name in carried {
        let Some((rel, fields)) = structs.get(&type_name) else {
            continue;
        };
        if fields.is_empty() {
            continue;
        }
        out.structs += 1;
        for (field, doc) in fields {
            out.fields += 1;
            let bound = bound_in(&committed, field);
            let declared = signing_excluded(doc);
            if !bound && declared.is_none() {
                out.problems.push(format!(
                    "{rel}: {type_name}.{field} rides inside a signed transaction and is \
                     not in the signing preimage. A relaying node can rewrite it and the \
                     signature still verifies. Append it in \
                     `encode_transaction_type_payload` (or the `encode_*` helper for this \
                     type), or write `SIGNING: excluded - <reason>` in the field's doc."
                ));
            } else if bound {
                if let Some(reason) = declared {
                    out.problems.push(format!(
                        "{rel}: {type_name}.{field} is marked `SIGNING: excluded` \
                         ({reason}) and the preimage does commit it. The marker is \
                         stale and now describes a hole that is closed.",
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

    if out.structs == 0 {
        return Err(String::from(
            "gate resolved no struct carried by TransactionType - wrong root?",
        ));
    }
    Ok(out)
}

/// # Errors
///
/// Returns a finding when a carried field is outside the preimage without a
/// marker, or a marker sits on a field the preimage commits.
pub fn run(root: &Path) -> Result<String, String> {
    let out = measure(root)?;
    if !out.problems.is_empty() {
        return Err(out.problems.join("\n"));
    }
    Ok(format!(
        "wire-field signing gate OK: {} structs carried by a transaction, {} \
         fields each in the preimage or declaring why they are not",
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
        body: "pub struct Spec {\n    pub model_id: [u8; 32],\n    pub weights_digest: Option<[u8; 32]>,\n}\npub enum TransactionType {\n    Register(Spec),\n}\nfn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {\n    match tx_type {\n        TransactionType::Register(spec) => encode_spec(spec, out),\n    }\n}\nfn encode_spec(spec: &Spec, out: &mut Vec<u8>) {\n    put_fixed(out, &spec.model_id);\n    put_option_fixed32(out, spec.weights_digest);\n}",
        expect: Expect::Pass,
    },
    Canary {
        name: "silent",
        body: "pub struct Spec {\n    pub model_id: [u8; 32],\n    pub weights_digest: Option<[u8; 32]>,\n}\npub enum TransactionType {\n    Register(Spec),\n}\nfn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {\n    match tx_type {\n        TransactionType::Register(spec) => encode_spec(spec, out),\n    }\n}\nfn encode_spec(spec: &Spec, out: &mut Vec<u8>) {\n    put_fixed(out, &spec.model_id);\n}",
        expect: Expect::Finding,
    },
    Canary {
        name: "declared",
        body: "pub struct Spec {\n    pub model_id: [u8; 32],\n    /// SIGNING: excluded - server-assigned after the signature is checked.\n    pub received_at: u64,\n}\npub enum TransactionType {\n    Register(Spec),\n}\nfn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {\n    match tx_type {\n        TransactionType::Register(spec) => encode_spec(spec, out),\n    }\n}\nfn encode_spec(spec: &Spec, out: &mut Vec<u8>) {\n    put_fixed(out, &spec.model_id);\n}",
        expect: Expect::Pass,
    },
    Canary {
        name: "stale",
        body: "pub struct Spec {\n    pub model_id: [u8; 32],\n    /// SIGNING: excluded - left over from before it was committed.\n    pub weights_digest: Option<[u8; 32]>,\n}\npub enum TransactionType {\n    Register(Spec),\n}\nfn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {\n    match tx_type {\n        TransactionType::Register(spec) => encode_spec(spec, out),\n    }\n}\nfn encode_spec(spec: &Spec, out: &mut Vec<u8>) {\n    put_fixed(out, &spec.model_id);\n    put_option_fixed32(out, spec.weights_digest);\n}",
        expect: Expect::Finding,
    },
    Canary {
        name: "nested",
        body: "pub struct Inner {\n    pub value: u64,\n}\npub struct Spec {\n    pub model_id: [u8; 32],\n    pub inner: Inner,\n}\npub enum TransactionType {\n    Register(Spec),\n}\nfn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {\n    match tx_type {\n        TransactionType::Register(spec) => encode_spec(spec, out),\n    }\n}\nfn encode_spec(spec: &Spec, out: &mut Vec<u8>) {\n    put_fixed(out, &spec.model_id);\n    encode_inner(&spec.inner, out);\n}\nfn encode_inner(inner: &Inner, out: &mut Vec<u8>) {\n    put_u64(out, inner.value);\n}",
        expect: Expect::Pass,
    },
    Canary {
        name: "array_return",
        body: "pub struct Spec {\n    pub model_id: [u8; 32],\n    pub weights_digest: Option<[u8; 32]>,\n}\npub enum TransactionType {\n    Register(Spec),\n}\nfn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {\n    match tx_type {\n        TransactionType::Register(spec) => encode_spec(spec, out),\n    }\n}\nfn encode_spec(spec: &Spec, out: &mut Vec<u8>) -> [u8; 32] {\n    put_fixed(out, &spec.model_id);\n    put_option_fixed32(out, spec.weights_digest);\n    [0u8; 32]\n}",
        expect: Expect::Pass,
    },
    Canary {
        name: "empty",
        body: "",
        expect: Expect::MeasuredNothing,
    },
    Canary {
        name: "bare",
        body: "pub enum TransactionType {\n    Transfer,\n}\nfn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {\n    match tx_type {\n        TransactionType::Transfer => {}\n    }\n}",
        expect: Expect::MeasuredNothing,
    },
];

/// Build a fixture tree with `src/core/transaction.rs` carrying the body.
fn write_fixture(tmp: &Path, case: &str, body: &str) -> Result<(), String> {
    let dir = tmp.join(case);
    std::fs::create_dir_all(dir.join("src/core"))
        .map_err(|e| format!("cannot create fixture dirs: {e}"))?;
    std::fs::write(dir.join(TX), body).map_err(|e| format!("cannot write fixture: {e}"))
}

/// Run the gate against a fixture and classify the result.
fn verdict(tmp: &Path, case: &str, want: &Expect) -> Result<(), String> {
    let dir = tmp.join(case);
    match (run(&dir), want) {
        (Ok(_), Expect::Pass) => Ok(()),
        (Ok(msg), _) => Err(format!("VACUOUS: {case} passed: {msg}")),
        (Err(msg), Expect::Finding) => {
            if msg.contains("no transaction module")
                || msg.contains("no struct carried")
                || msg.contains("TransactionType") && msg.contains("no")
            {
                Err(format!(
                    "BROKEN: {case} measured nothing instead of finding: {msg}"
                ))
            } else {
                Ok(())
            }
        }
        (Err(msg), Expect::MeasuredNothing) => {
            if msg.contains("no transaction module")
                || msg.contains("no struct carried")
                || msg.contains("no `pub enum TransactionType`")
            {
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
            "wire-fields-{}-{nanos}-{attempt}",
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
        if let Err(e) = write_fixture(&tmp, c.name, c.body) {
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
        "wire-field signing gate self-test OK: a missing field, a stale marker, \
         an unreadable tree and an enum with nothing to measure are all rejected; \
         a covered variant, a declared exclusion, a two-level helper chain and an \
         array return all pass.",
    ))
}
