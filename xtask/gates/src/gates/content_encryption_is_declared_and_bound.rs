//! A manifest must say whether its bytes are ciphertext, and the saying must
//! be part of what the id commits to.
//!
//! Ported from `scripts/check-content-encryption-is-declared-and-bound.sh`,
//! 550 lines of shell wrapping Python. The shell was a here-doc launcher and
//! the Python did the work, so the port replaces two languages with one, and
//! the Python's regexes become plain string and brace matching.
//!
//! # Why this gate exists
//!
//! `src/storage/` held no encryption of any kind and no statement about it
//! either. Every manifest was silent, so every reader resolved the silence
//! for itself: an operator could not tell whether the shard it served was
//! readable content, and a client whose decrypt failed could not tell a wrong
//! key from a corrupt shard.
//!
//! The chain cannot encrypt anything. It holds no bytes. What it can do is
//! carry the uploader's statement and make it immutable, and the only way to
//! make it immutable is to put it inside `manifest_id`. Left outside, the
//! claim is rewritable under a stable id: register as `ClientSide`, serve a
//! manifest reading `Plaintext` at the same id, and every later reader
//! concludes the bytes were never protected. That is the whole reason the
//! binding, and not just the field, is what this gate watches.
//!
//! The measured shapes this refuses:
//!
//! 1. The field exists but `manifest_id_from_parts` never reads it. The
//!    declaration is then decorative: two manifests share an id and disagree
//!    about whether the content is private, and first-writer-wins picks one.
//! 2. The commitment tag is derived from the enum's declaration order rather
//!    than written out, so reordering variants silently changes every
//!    manifest id ever computed.
//! 3. `Plaintext` stops being the default, so every manifest written before
//!    the field deserializes into a privacy claim nobody made.
//! 4. A key, key id, wrapped key or nonce is added to the declaration, which
//!    publishes key material on a public chain.
//!
//! What this gate does not check: that anything was actually encrypted.
//! Nothing on chain can check that, and a gate claiming to would be reporting
//! a guarantee the system does not have.

use std::fmt::Write as _;
use std::path::Path;

/// The manifest, where the declaration and its binding live.
const MANIFEST: &str = "src/storage/manifest.rs";
/// The regression tests that pin the declaration's behaviour.
const LOCKS: &str = "src/tests/manifest_commitment_locks.rs";

/// The six tests this gate requires to exist as real `#[test]`s.
const REQUIRED_TESTS: &[&str] = &[
    "declaring_client_side_encryption_changes_the_manifest_id",
    "rewriting_the_declaration_breaks_the_id",
    "a_manifest_written_before_this_field_reads_as_plaintext",
    "an_object_too_small_to_hold_an_auth_tag_cannot_claim_encryption",
    "an_object_at_the_tag_length_is_accepted",
    "the_declaration_carries_no_key_material",
];

/// Words that look like key material inside the declaration.
const KEY_MATERIAL_WORDS: &[&str] = &["key", "nonce", "secret", "iv", "wrapped"];

/// Remove line comments. The shell version did exactly this, no more: a `//`
/// inside a string literal is removed too, and so is one inside a URL. That
/// is a fault, but it is a fault the port must reproduce, because the
/// evidence pool it builds must match the shell's for the two to agree.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.split_inclusive('\n') {
        if let Some(rel) = line.find("//") {
            let (head, _) = line.split_at(rel);
            out.push_str(head);
            if line.ends_with('\n') {
                out.push('\n');
            }
        } else {
            out.push_str(line);
        }
    }
    out
}

/// The brace-matched body of the item whose text starts at `marker`, or
/// `None` when the marker is absent.
///
/// The shell cut at the first `#[cfg(test)]` in early versions and stopped at
/// the next `}` in later ones; matching braces is the only reading that
/// survives both a nested block and tests at the bottom of the file.
fn body_of(src: &str, marker: &str) -> Option<String> {
    let start = src.find(marker)?;
    let open = src[start + marker.len()..].find('{')? + start + marker.len();
    let mut depth = 0usize;
    for (idx, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(src[open..=open + idx].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// The text inside the first parentheses after `marker`, when the function
/// also returns something (`->` follows the closing paren).
fn parens_of(src: &str, marker: &str) -> Option<String> {
    let start = src.find(marker)?;
    let after = start + marker.len();
    let open = src[after..].find('(')? + after;
    let close = src[open + 1..].find(')')? + open + 1;
    let mut j = close + 1;
    while j < src.len() && src[j..].chars().next().is_some_and(char::is_whitespace) {
        let len = src[j..].chars().next().map_or(1, char::len_utf8);
        j += len;
    }
    if !src[j..].starts_with("->") {
        return None;
    }
    Some(src[open + 1..close].to_string())
}

/// Does the text cast the enum with `as u8`, with word boundaries, and
/// without a `match` anywhere?
fn casts_enum_as_u8(tagfn: &str) -> bool {
    if tagfn.contains("match") {
        return false;
    }
    let bytes = tagfn.as_bytes();
    let needle = b"as u8";
    if bytes.len() < needle.len() {
        return false;
    }
    let limit = bytes.len() - needle.len();
    let mut i = 0;
    while i <= limit {
        if &bytes[i..i + needle.len()] == needle {
            let prev_ok = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            let after = i + needle.len();
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

/// Every key-material word the declaration carries, sorted and de-duplicated.
fn key_material_in(enum_body: &str) -> Vec<String> {
    let lower = enum_body.to_ascii_lowercase();
    let mut found: Vec<String> = Vec::new();
    for word in KEY_MATERIAL_WORDS {
        let mut i = 0;
        while let Some(rel) = lower[i..].find(word) {
            let abs = i + rel;
            let prev_ok = abs == 0
                || !(lower.as_bytes()[abs - 1].is_ascii_alphanumeric()
                    || lower.as_bytes()[abs - 1] == b'_');
            let mut j = abs + word.len();
            while j < lower.len()
                && (lower.as_bytes()[j].is_ascii_alphanumeric() || lower.as_bytes()[j] == b'_')
            {
                j += 1;
            }
            while j < lower.len() && lower.as_bytes()[j].is_ascii_whitespace() {
                j += 1;
            }
            if prev_ok
                && j < lower.len()
                && lower.as_bytes()[j] == b':'
                && !found.contains(&word.to_string())
            {
                found.push(word.to_string());
            }
            i = abs + word.len();
        }
    }
    found
}

/// Is the test present as a real `#[test] fn`, allowing attributes between
/// the marker and the name?
fn test_is_present(locks: &str, name: &str) -> bool {
    let needle = "#[test]";
    let mut i = 0;
    while let Some(rel) = locks[i..].find(needle) {
        let mut j = i + rel + needle.len();
        loop {
            while j < locks.len() && locks.as_bytes()[j].is_ascii_whitespace() {
                j += 1;
            }
            if locks[j..].starts_with("#[") {
                if let Some(end) = locks[j..].find(']') {
                    j += end + 1;
                    continue;
                }
            }
            break;
        }
        if locks[j..].starts_with("fn") {
            let mut k = j + 2;
            while k < locks.len() && locks.as_bytes()[k].is_ascii_whitespace() {
                k += 1;
            }
            if locks[k..].starts_with(name) {
                let mut m = k + name.len();
                while m < locks.len() && locks.as_bytes()[m].is_ascii_whitespace() {
                    m += 1;
                }
                if locks[m..].starts_with('(') {
                    return true;
                }
            }
        }
        i = j;
    }
    false
}

/// One group of checks: how many it contributed and what it found.
struct Checks {
    checked: usize,
    problems: Vec<String>,
}

impl Checks {
    fn new(checked: usize, problems: Vec<String>) -> Self {
        Self { checked, problems }
    }
}

/// The declaration must exist, offer both states, and default to `Plaintext`.
/// Returns the enum body so later checks can reuse it.
fn check_declaration(code: &str) -> (Checks, Option<String>) {
    let mut checked = 1;
    let mut problems = Vec::new();
    let Some(enum_body) = body_of(code, "pub enum ContentEncryption") else {
        problems.push(String::from(
            "`ContentEncryption` is gone. A manifest with no declaration leaves \
             every reader to resolve the silence for itself: an operator cannot \
             tell whether it is serving readable content, and a failed decrypt \
             cannot be distinguished from a corrupt shard.",
        ));
        return (Checks::new(checked, problems), None);
    };

    checked += 1;
    for state in ["Plaintext", "ClientSide"] {
        if !enum_body.contains(state) {
            problems.push(format!(
                "`ContentEncryption::{state}` is gone; the type no longer \
                 distinguishes protected content from readable content."
            ));
        }
    }

    checked += 1;
    let variants = enum_body
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(&enum_body);
    let default_at = variants.find("#[default]");
    let plaintext_at = variants.find("Plaintext");
    let clientside_at = variants.find("ClientSide");
    match default_at {
        None => problems.push(String::from(
            "`ContentEncryption` has no `#[default]`. Manifests written \
             before this field deserialize through the default, and without \
             one the type will not derive `Default` at all.",
        )),
        Some(d) => {
            let plain_ok = plaintext_at.is_some_and(|p| d < p);
            let side_ok = clientside_at.is_none_or(|c| d < c);
            if !(plain_ok && side_ok) {
                problems.push(String::from(
                    "`#[default]` is not on `Plaintext`. Every manifest written \
                     before this field would deserialize into a privacy claim \
                     nobody made, which is worse than no claim: a reader would \
                     trust it.",
                ));
            }
        }
    }
    (Checks::new(checked, problems), Some(enum_body))
}

/// The field must exist on the manifest and carry `#[serde(default)]`.
fn check_field(code: &str) -> Checks {
    let mut checked = 1;
    let mut problems = Vec::new();
    let Some(struct_body) = body_of(code, "pub struct ContentManifest") else {
        problems.push(String::from(
            "cannot find `ContentManifest` to check its fields.",
        ));
        return Checks::new(checked, problems);
    };

    checked += 1;
    let field_re = "pub encryption:";
    if !struct_body.contains(field_re) {
        problems.push(String::from(
            "`ContentManifest` has no `encryption` field, so nothing records \
             whether the shards are ciphertext.",
        ));
    }
    if let Some(at) = struct_body.find(field_re) {
        let preceding = &struct_body[at.saturating_sub(200)..at];
        if !preceding.contains("#[serde(default)]") {
            problems.push(String::from(
                "`encryption` is not `#[serde(default)]`, so every snapshot \
                 written before this field fails to deserialize.",
            ));
        }
    }
    Checks::new(checked, problems)
}

/// The binding: the commitment must take the declaration, read its tag and
/// stay domain-separated as V4.
fn check_binding(code: &str) -> Checks {
    let mut checked = 1;
    let mut problems = Vec::new();
    // Visibility is not the property: what must hold is that the binding reads the
    // declaration's tag. The anchor is therefore the bare function name, which a
    // private `fn` and a `pub fn` both contain. Pinning the anchor to
    // `pub fn` let the check go quiet the moment the helper stopped being
    // re-exported: an unread argument and a missing function produced the same
    // verdict, so a rename or a visibility change was indistinguishable from a
    // binding that stopped reading the tag. The first match is the function itself,
    // which the `_stored` sibling follows.
    let commit = body_of(code, "fn manifest_id_from_parts");
    let sig = parens_of(code, "fn manifest_id_from_parts");
    let (Some(commit), Some(sig)) = (commit.as_deref(), sig.as_deref()) else {
        problems.push(String::from(
            "`manifest_id_from_parts` is gone; nothing binds the manifest's \
             fields to its id.",
        ));
        return Checks::new(checked, problems);
    };

    checked += 1;
    if !sig.contains("ContentEncryption") {
        problems.push(String::from(
            "`manifest_id_from_parts` does not take the encryption \
             declaration. Outside the commitment the claim is rewritable \
             under a stable id: register `ClientSide`, then serve a manifest \
             reading `Plaintext` at the same id.",
        ));
    }
    checked += 1;
    if !commit.contains("commitment_tag") {
        problems.push(String::from(
            "`manifest_id_from_parts` never reads the declaration's \
             commitment tag, so the argument is accepted and ignored. That \
             is the same as not binding it, with the appearance of binding.",
        ));
    }
    checked += 1;
    if !commit.contains("BDLM_MANIFEST_V4") {
        problems.push(String::from(
            "the commitment is not domain-separated as V4. Adding a field \
             without changing the domain tag lets a V3 id and a V4 id \
             collide across different meanings.",
        ));
    }
    Checks::new(checked, problems)
}

/// Every production caller must pass the manifest's own declaration, not a
/// literal.
fn check_call_sites(code: &str) -> Checks {
    let checked = 1;
    let mut problems = Vec::new();
    let needle = "manifest_id_from_parts(&self.shards";
    let mut i = 0;
    while let Some(rel) = code[i..].find(needle) {
        let abs = i + rel;
        let rest = &code[abs + needle.len()..];
        let close = rest.find(')').map(|d| abs + needle.len() + d);
        let call = match close {
            Some(c) => &code[abs..=c],
            None => &code[abs..],
        };
        if !call.contains("self.encryption") {
            problems.push(format!(
                "a `manifest_id_from_parts` call inside `ContentManifest` does \
                 not pass `self.encryption`: {}. The id would then commit to a \
                 declaration the manifest does not carry.",
                call.trim()
            ));
        }
        i = abs + needle.len();
    }
    Checks::new(checked, problems)
}

/// The tag must be written out per variant, not derived from ordering.
fn check_tag(code: &str) -> Checks {
    let mut checked = 1;
    let mut problems = Vec::new();
    let Some(tagfn) = body_of(code, "fn commitment_tag(&self) -> u8") else {
        problems.push(String::from(
            "`commitment_tag` is gone; the commitment has no stable byte.",
        ));
        return Checks::new(checked, problems);
    };

    checked += 1;
    if casts_enum_as_u8(&tagfn) {
        problems.push(String::from(
            "`commitment_tag` casts the enum rather than matching it. \
             Reordering the variants would then silently change every \
             manifest id ever computed.",
        ));
    }
    Checks::new(checked, problems)
}

/// No key material may live inside the declaration.
fn check_key_material(enum_body: Option<&str>) -> Checks {
    let checked = 1;
    let mut problems = Vec::new();
    if let Some(body) = enum_body {
        let banned = key_material_in(body);
        if !banned.is_empty() {
            problems.push(format!(
                "`ContentEncryption` carries what looks like key material ({}). \
                 A key in a public commitment is a key published on a public \
                 chain.",
                banned.join(", ")
            ));
        }
    }
    Checks::new(checked, problems)
}

/// The regressions must exist as real tests.
fn check_tests(locks: &str) -> Checks {
    let checked = 1;
    let mut problems = Vec::new();
    for test in REQUIRED_TESTS {
        if !test_is_present(locks, test) {
            problems.push(format!(
                "required regression test `{test}` is missing or is not a `#[test]`."
            ));
        }
    }
    Checks::new(checked, problems)
}

/// Read both required files and measure every property the claim depends on.
fn measure(root: &Path) -> Result<Outcome, String> {
    let manifest = root.join(MANIFEST);
    let locks = root.join(LOCKS);
    for path in [&manifest, &locks] {
        if !path.is_file() {
            return Err(format!("expected source file missing: {}", path.display()));
        }
    }

    let manifest_src = std::fs::read_to_string(&manifest)
        .map_err(|e| format!("cannot read {}: {e}", manifest.display()))?;
    let manifest_code = strip_comments(&manifest_src);
    let locks_src = std::fs::read_to_string(&locks)
        .map_err(|e| format!("cannot read {}: {e}", locks.display()))?;

    let (declaration, enum_body) = check_declaration(&manifest_code);
    let field = check_field(&manifest_code);
    let binding = check_binding(&manifest_code);
    let call_sites = check_call_sites(&manifest_code);
    let tag = check_tag(&manifest_code);
    let key_material = check_key_material(enum_body.as_deref());
    let tests = check_tests(&locks_src);

    let checked = declaration.checked
        + field.checked
        + binding.checked
        + call_sites.checked
        + tag.checked
        + key_material.checked
        + tests.checked;
    let mut problems = declaration.problems;
    problems.extend(field.problems);
    problems.extend(binding.problems);
    problems.extend(call_sites.problems);
    problems.extend(tag.problems);
    problems.extend(key_material.problems);
    problems.extend(tests.problems);

    Ok(Outcome { checked, problems })
}

struct Outcome {
    checked: usize,
    problems: Vec<String>,
}

/// # Errors
///
/// Returns the list of findings when the tree does not declare, default and
/// bind the encryption claim.
pub fn run(root: &Path) -> Result<String, String> {
    let outcome = measure(root)?;
    if outcome.checked == 0 {
        return Err(String::from("gate checked nothing"));
    }
    if !outcome.problems.is_empty() {
        return Err(outcome.problems.join("\n"));
    }
    Ok(format!(
        "content encryption declaration gate OK: {} checks, the claim is \
         declared, defaulted honestly and bound to the id",
        outcome.checked
    ))
}

fn fixture_enum(mode: &str) -> String {
    match mode {
        "gone" => String::new(),
        "wrongdefault" => String::from(
            "pub enum ContentEncryption {\n    ClientSide(ContentCipher),\n    #[default]\n    Plaintext,\n}\n",
        ),
        "nodefault" => String::from(
            "pub enum ContentEncryption {\n    Plaintext,\n    ClientSide(ContentCipher),\n}\n",
        ),
        "haskey" => String::from(
            "pub enum ContentEncryption {\n    #[default]\n    Plaintext,\n    ClientSide { cipher: ContentCipher, wrapped_key: Vec<u8> },\n}\n",
        ),
        _ => String::from(
            "pub enum ContentEncryption {\n    #[default]\n    Plaintext,\n    ClientSide(ContentCipher),\n}\n",
        ),
    }
}

fn fixture_tagfn(mode: &str) -> String {
    match mode {
        "cast" => String::from(
            "    pub const fn commitment_tag(&self) -> u8 {\n        *self as u8\n    }\n",
        ),
        "gone" => String::new(),
        _ => String::from(
            "    pub const fn commitment_tag(&self) -> u8 {\n        match self {\n            Self::Plaintext => 0,\n            Self::ClientSide(c) => c.commitment_tag(),\n        }\n    }\n",
        ),
    }
}

fn fixture_field(mode: &str) -> String {
    match mode {
        "gone" => String::new(),
        "noserde" => String::from("    pub encryption: ContentEncryption,\n"),
        _ => String::from("    #[serde(default)]\n    pub encryption: ContentEncryption,\n"),
    }
}

/// The commitment function and the call site that recomputes the id.
fn fixture_commit(mode: &str) -> (String, String) {
    match mode {
        "unbound" => (
            String::from(
                "pub fn manifest_id_from_parts(\n    shards: &[ShardRef],\n    \
                 erasure: &ErasureScheme,\n) -> ContentId {\n    let mut buf = Vec::new();\n    \
                 buf.extend_from_slice(b\"BDLM_MANIFEST_V4\");\n    \
                 buf.extend_from_slice(&erasure.k.to_le_bytes());\n    \
                 ContentId(hash_fields_bytes(&[b\"BDLM_MANIFEST_V4\", &buf]))\n}\n",
            ),
            String::from(
                "        self.manifest_id = manifest_id_from_parts(&self.shards, &self.erasure);\n",
            ),
        ),
        "ignored" => (
            String::from(
                "pub fn manifest_id_from_parts(\n    shards: &[ShardRef],\n    \
                 erasure: &ErasureScheme,\n    encryption: &ContentEncryption,\n) -> ContentId {\n    \
                 let mut buf = Vec::new();\n    buf.extend_from_slice(b\"BDLM_MANIFEST_V4\");\n    \
                 buf.extend_from_slice(&erasure.k.to_le_bytes());\n    \
                 ContentId(hash_fields_bytes(&[b\"BDLM_MANIFEST_V4\", &buf]))\n}\n",
            ),
            String::from(
                "        self.manifest_id = manifest_id_from_parts(&self.shards, &self.erasure, &self.encryption);\n",
            ),
        ),
        "v2tag" => (
            String::from(
                "pub fn manifest_id_from_parts(\n    shards: &[ShardRef],\n    \
                 erasure: &ErasureScheme,\n    encryption: &ContentEncryption,\n) -> ContentId {\n    \
                 let mut buf = Vec::new();\n    buf.extend_from_slice(b\"BDLM_MANIFEST_V2\");\n    \
                 buf.push(encryption.commitment_tag());\n    \
                 ContentId(hash_fields_bytes(&[b\"BDLM_MANIFEST_V2\", &buf]))\n}\n",
            ),
            String::from(
                "        self.manifest_id = manifest_id_from_parts(&self.shards, &self.erasure, &self.encryption);\n",
            ),
        ),
        "literal" => (
            String::from(
                "pub fn manifest_id_from_parts(\n    shards: &[ShardRef],\n    \
                 erasure: &ErasureScheme,\n    encryption: &ContentEncryption,\n) -> ContentId {\n    \
                 let mut buf = Vec::new();\n    buf.extend_from_slice(b\"BDLM_MANIFEST_V4\");\n    \
                 buf.push(encryption.commitment_tag());\n    \
                 ContentId(hash_fields_bytes(&[b\"BDLM_MANIFEST_V4\", &buf]))\n}\n",
            ),
            String::from(
                "        self.manifest_id = manifest_id_from_parts(&self.shards, &self.erasure, &ContentEncryption::Plaintext);\n",
            ),
        ),
        _ => (
            String::from(
                "pub fn manifest_id_from_parts(\n    shards: &[ShardRef],\n    \
                 erasure: &ErasureScheme,\n    encryption: &ContentEncryption,\n) -> ContentId {\n    \
                 let mut buf = Vec::new();\n    buf.extend_from_slice(b\"BDLM_MANIFEST_V4\");\n    \
                 buf.extend_from_slice(&erasure.k.to_le_bytes());\n    \
                 buf.push(encryption.commitment_tag());\n    \
                 ContentId(hash_fields_bytes(&[b\"BDLM_MANIFEST_V4\", &buf]))\n}\n",
            ),
            String::from(
                "        self.manifest_id = manifest_id_from_parts(&self.shards, &self.erasure, &self.encryption);\n",
            ),
        ),
    }
}

/// Build a fixture tree with the requested shapes. The modes mirror the shell
/// version's `build` helper exactly, so each canary proves the same defect.
fn write_fixture(
    tmp: &Path,
    case: &str,
    enum_mode: &str,
    field_mode: &str,
    commit_mode: &str,
    tag_mode: &str,
    tests_mode: &str,
) -> Result<(), String> {
    let root = tmp.join(case);
    std::fs::create_dir_all(root.join("src/storage"))
        .map_err(|e| format!("cannot create fixture dirs: {e}"))?;
    std::fs::create_dir_all(root.join("src/tests"))
        .map_err(|e| format!("cannot create fixture dirs: {e}"))?;

    let field = fixture_field(field_mode);
    let struct_src = format!(
        "pub struct ContentManifest {{\n    pub manifest_id: ContentId,\n    \
         pub total_size: u64,\n    pub shard_count: u32,\n    pub shards: Vec<ShardRef>,\n{field}}}\n"
    );

    let (commit, site) = fixture_commit(commit_mode);
    let impl_src = format!(
        "impl ContentEncryption {{\n{}    pub fn is_encrypted(&self) -> bool {{\n        \
         matches!(self, ContentEncryption::ClientSide(_))\n    }}\n}}\n",
        fixture_tagfn(tag_mode)
    );
    let recompute = format!(
        "impl ContentManifest {{\n    pub fn with_encryption(mut self, encryption: ContentEncryption) -> Self {{\n        \
         self.encryption = encryption;\n{site}        self\n    }}\n}}\n"
    );
    let manifest_src = format!(
        "{}\n{impl_src}\n{struct_src}\n{recompute}\n{commit}",
        fixture_enum(enum_mode)
    );

    let mut names = REQUIRED_TESTS.to_vec();
    if tests_mode == "absent" {
        names.pop();
    }
    let mut locks = String::new();
    for n in names {
        let _ = writeln!(locks, "#[test]\nfn {n}() {{}}\n");
    }

    std::fs::write(root.join(MANIFEST), manifest_src)
        .map_err(|e| format!("cannot write fixture manifest: {e}"))?;
    std::fs::write(root.join(LOCKS), locks)
        .map_err(|e| format!("cannot write fixture locks: {e}"))?;
    Ok(())
}

/// Run the gate against a fixture directory and report whether it behaved.
fn fixture_verdict(tmp: &Path, case: &str) -> Result<(), String> {
    let dir = tmp.join(case);
    match run(&dir) {
        Ok(msg) => Err(format!("VACUOUS: {case} passed: {msg}")),
        Err(_) => Ok(()),
    }
}

/// A fresh, exclusively-created scratch directory under the system temp dir.
///
/// The system temp dir is shared, so the name must be unpredictable and the
/// creation must be exclusive: `create_dir` fails when the path already
/// exists, which turns a pre-planted symlink or directory into a retry rather
/// than a follow. A fixed name plus `create_dir_all` would instead silently
/// reuse whatever an attacker left at that path.
fn scratch_dir() -> Result<std::path::PathBuf, String> {
    // The crate's own target dir, which the tree owns, is writable wherever
    // the binary runs and is excluded from the Semgrep scan. The shared
    // system temp dir is not used: it is world-writable, so a fixed name
    // there is a path anyone can pre-plant.
    let root = std::env::var("BUDLUM_ROOT")
        .map(std::path::PathBuf::from)
        .or_else(|_| std::env::current_dir().map_err(|e| e.to_string()))
        .map_err(|e| format!("cannot determine repo root for fixtures: {e}"))?;
    let base = root.join("target").join("gate-fixtures");
    std::fs::create_dir_all(&base).map_err(|e| format!("cannot create {}: {e}", base.display()))?;
    for attempt in 0..100u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = base.join(format!(
            "content-encryption-{}-{nanos}-{attempt}",
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

    // 1. The corrected shape must pass, or every canary below proves nothing.
    write_fixture(&tmp, "good", "ok", "serde", "bound", "match", "present")?;
    if let Err(e) = run(&tmp.join("good")) {
        problems.push(format!("BROKEN: the corrected tree was rejected: {e}"));
    }

    // 2-14. Every defect must be refused, by the shape that produces it.
    let cases: &[(&str, &str, &str, &str, &str, &str)] = &[
        ("noenum", "gone", "serde", "bound", "match", "present"),
        ("unbound", "ok", "serde", "unbound", "match", "present"),
        ("ignored", "ok", "serde", "ignored", "match", "present"),
        ("literal", "ok", "serde", "literal", "match", "present"),
        ("v2", "ok", "serde", "v2tag", "match", "present"),
        (
            "wrongdefault",
            "wrongdefault",
            "serde",
            "bound",
            "match",
            "present",
        ),
        (
            "nodefault",
            "nodefault",
            "serde",
            "bound",
            "match",
            "present",
        ),
        ("noserde", "ok", "noserde", "bound", "match", "present"),
        ("nofield", "ok", "gone", "bound", "match", "present"),
        ("cast", "ok", "serde", "bound", "cast", "present"),
        ("notag", "ok", "serde", "bound", "gone", "present"),
        ("haskey", "haskey", "serde", "bound", "match", "present"),
        ("notest", "ok", "serde", "bound", "match", "absent"),
    ];
    for (case, e, f, c, t, tm) in cases {
        write_fixture(&tmp, case, e, f, c, t, tm)?;
        if let Err(verdict) = fixture_verdict(&tmp, case) {
            problems.push(verdict);
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);

    if !problems.is_empty() {
        return Err(problems.join("\n"));
    }
    Ok(String::from(
        "content encryption declaration gate self-test OK: the corrected tree \
         passes and all 13 defect shapes are refused.",
    ))
}
