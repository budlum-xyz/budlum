//! The B.U.D. 3.0 wire contract is total: every message is reachable, every
//! field is numbered once, and the object's own bytes do not cross this wire.
//!
//! Directive section 6.3.2 rule 7 and section 15.8 (WP-10 item 6) ask for a
//! `bud3.proto` whose messages are "placeholder-free and exactly fielded". A
//! proto file is not compiled by the Rust workspace, so nothing in `cargo test`
//! reads it: a message nobody can reach, a field numbered twice, or a second
//! encoding of the BOF-1 header would all pass every build. This gate is what
//! makes the claim checkable.
//!
//! # What it refuses
//!
//! 1. **An unreachable message.** Every `message` must be named by a field of
//!    another message, or be the body of a request/response pair whose name
//!    ends in `Request`/`Response`. A message nothing names is a placeholder
//!    that was written and not used, which is the shape the directive forbids.
//! 2. **A field numbered twice** inside one message, and **a field number
//!    reused after deletion**, which the file records as `reserved`.
//! 3. **A BOF-1 field in the proto.** The object header is canonical in
//!    `src/storage/bud3/bof1.rs`; a `magic`, `version`, `flags` or `payload`
//!    field here would be a second encoding of it, and the first time the two
//!    disagreed the network would have two objects with one name.
//! 4. **A presentation field.** No raster reaches a wire message: `png`,
//!    `bdlv` and `h264` are refused by name, the same rule
//!    `bud3_qr_is_presentation` applies to hash inputs.
//!
//! # What it does not prove
//!
//! It reads the file as text. It does not type-check the messages against the
//! Rust types, because the Rust side does not generate code from this file yet
//! (WP-21 lands the RPC door). What it does prove is the part a reviewer cannot
//! see by reading one message at a time: that the file as a whole is closed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

/// The wire contract, relative to the repository root.
const PROTO: &str = "proto/budlum/storage/v3/bud3.proto";

/// Field names that would be a second encoding of the BOF-1 header.
///
/// `version` is deliberately absent. BOF-1's `version` is the object format's
/// version (always 1, section 6.3.2); a `version` field here is the protocol's,
/// and every Request carries one because a peer speaking another version has to
/// be refused before its body is read. The four names below have no honest
/// reading on this wire: the magic, the sealing flags and the payload belong to
/// the object, whose canonical encoding is `bof1.rs`.
const BOF1_FIELDS: &[&str] = &["magic", "flags", "payload"];

/// Names that mean a drawing. A drawing has no place on this wire.
const PRESENTATION: &[&str] = &["png", "bdlv", "h264"];

/// A message and the field names and numbers it declares.
#[derive(Debug, Default, PartialEq, Eq)]
struct Message {
    fields: Vec<(String, u32)>,
    reserved: BTreeSet<u32>,
    /// The message type names its fields carry, for the reachability rule.
    refers_to: Vec<String>,
}

/// Parse the messages of a proto file.
///
/// Deliberately literal: comments are dropped, and only `message <Name> {`
/// opens a block this gate reads. Nesting is tracked by brace depth so a field
/// inside a nested block is attributed to the outer message rather than to
/// nothing.
fn parse(text: &str) -> BTreeMap<String, Message> {
    let mut out: BTreeMap<String, Message> = BTreeMap::new();
    let mut stack: Vec<String> = Vec::new();
    let mut depth = 0i32;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("//") {
            continue;
        }
        let opens = line.ends_with('{');
        let head = line.trim_end_matches('{').trim();
        if let Some(name) = head.strip_prefix("message ") {
            let name = name.split_whitespace().next().unwrap_or("").to_string();
            if !name.is_empty() {
                out.entry(name.clone()).or_default();
                if opens {
                    stack.push(name);
                    depth += 1;
                    continue;
                }
            }
        }
        if let Some(rest) = head.strip_prefix("reserved ") {
            if let Some(current) = stack.last() {
                for piece in rest.split(',') {
                    if let Ok(n) = piece.trim().parse::<u32>() {
                        if let Some(m) = out.get_mut(current) {
                            m.reserved.insert(n);
                        }
                    }
                }
            }
            continue;
        }
        // `repeated Foo bar = 3;` / `Foo bar = 3;` / `map<..> bar = 3;`
        if let Some(eq) = line.find('=') {
            let after = line.get(eq + 1..).unwrap_or("").trim();
            let number: String = after.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(number) = number.parse::<u32>() {
                let before = line.get(..eq).unwrap_or("").trim();
                let mut words: Vec<&str> = before.split_whitespace().collect();
                if let Some(last) = words.pop() {
                    if let Some(current) = stack.last() {
                        let ty = words.last().copied().unwrap_or("");
                        let ty = ty.trim_start_matches("repeated ").to_string();
                        if let Some(m) = out.get_mut(current) {
                            m.fields.push((last.to_string(), number));
                            if ty
                                .chars()
                                .next()
                                .is_some_and(|c| c.is_ascii_uppercase())
                            {
                                m.refers_to.push(ty);
                            }
                        }
                    }
                }
            }
        }
        if line.starts_with('}') {
            if depth > 0 {
                depth -= 1;
                stack.pop();
            }
        }
    }
    out
}

/// # Errors
///
/// The first refusal, naming the message and the line-level reason.
pub fn run(root: &Path) -> Result<String, String> {
    let path = root.join(PROTO);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("read {PROTO}: {e}"))?;
    let messages = parse(&text);
    if messages.is_empty() {
        return Err(format!(
            "{PROTO} declares no message: the gate would pass on an empty file, \
             which is the failure it exists to catch."
        ));
    }

    // Rule 2: a number used twice, or reused after being reserved.
    let mut offences = String::new();
    for (name, message) in &messages {
        let mut seen: BTreeMap<u32, &str> = BTreeMap::new();
        for (field, number) in &message.fields {
            if let Some(other) = seen.insert(*number, field) {
                let _ = writeln!(
                    offences,
                    "  {name}: field number {number} is used by both `{other}` and `{field}`"
                );
            }
            if message.reserved.contains(number) {
                let _ = writeln!(
                    offences,
                    "  {name}: field number {number} (`{field}`) is reserved and may not be reused"
                );
            }
        }
    }
    if !offences.is_empty() {
        return Err(format!(
            "FAIL: a field number is not unique:\n{offences}  The numbers are the wire; \
             reusing one makes two fields one field."
        ));
    }

    // Rule 1: every message is reachable from another message's field.
    let mut named: BTreeSet<String> = BTreeSet::new();
    for message in messages.values() {
        for ty in &message.refers_to {
            named.insert(ty.clone());
        }
    }
    let mut orphans = String::new();
    for name in messages.keys() {
        // A request/response pair is entered from outside the file by its RPC,
        // so its own name is its reachability.
        let is_entry = name.ends_with("Request") || name.ends_with("Response");
        if !is_entry && !named.contains(name) {
            let _ = writeln!(orphans, "  {name}");
        }
    }
    if !orphans.is_empty() {
        return Err(format!(
            "FAIL: a message nothing names is a placeholder:\n{orphans}  Either a field of \
             another message carries it, or it is a Request/Response the RPC enters."
        ));
    }

    // Rules 3 and 4: the object header and the drawings stay off this wire.
    let mut forbidden = String::new();
    // A Request opens an exchange or continues one. An opener states its
    // protocol version, because a peer speaking another version has to be
    // refused before its body is read. A continuation names the session it
    // belongs to, and the version was agreed when that session opened, so
    // repeating it there would be a second place for the two to disagree.
    for (name, message) in &messages {
        if !name.ends_with("Request") {
            continue;
        }
        let has = |field: &str| message.fields.iter().any(|(f, _)| f == field);
        if !has("version") && !has("session_id") {
            let _ = writeln!(
                forbidden,
                "  {name} carries neither `version` nor `session_id`: it opens an exchange \
                 without stating the version it speaks"
            );
        }
        if has("version") && has("session_id") {
            let _ = writeln!(
                forbidden,
                "  {name} carries both `version` and `session_id`: the session's version \
                 was agreed at `Open`, and repeating it is a second place to disagree"
            );
        }
    }
    for (name, message) in &messages {
        for (field, _) in &message.fields {
            let lower = field.to_lowercase();
            if BOF1_FIELDS.contains(&lower.as_str()) {
                let _ = writeln!(
                    forbidden,
                    "  {name}.{field} is a BOF-1 header field: the object's header is \
                     canonical in src/storage/bud3/bof1.rs"
                );
            }
            if PRESENTATION.iter().any(|p| lower.contains(p)) {
                let _ = writeln!(
                    forbidden,
                    "  {name}.{field} names a drawing: presentation never reaches the wire"
                );
            }
        }
    }
    if !forbidden.is_empty() {
        return Err(format!(
            "FAIL: the wire contract carries something it must not:\n{forbidden}"
        ));
    }

    Ok(format!(
        "bud3 proto is total OK: {} message(s), every one reached by a field or an RPC, \
         no number reused, no BOF-1 header and no drawing",
        messages.len()
    ))
}

/// The canary: an orphan, a reused number and a BOF-1 field must all fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-proto")?;
    let result = (|| {
        let put = |body: &str| -> Result<(), String> {
            let p = dir.join(PROTO);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        let clean = "syntax = \"proto3\";\n\
                     message EnvelopeRequest {\n  // the version\n  uint32 version = 1;\n  \
                     // the body\n  Symbol body = 2;\n}\n\
                     message EnvelopeResponse {\n  // the body\n  Symbol body = 1;\n}\n\
                     message Symbol {\n  // esi\n  uint32 esi = 1;\n}\n";
        put(clean)?;
        run(&dir).map_err(|e| format!("canary: a clean file failed: {e}"))?;

        let orphan = format!("{clean}message Unused {{\n  // n\n  uint32 n = 1;\n}}\n");
        put(&orphan)?;
        match run(&dir) {
            Err(e) if e.contains("placeholder") => {}
            other => {
                return Err(format!(
                    "canary: an unreachable message did not fail the gate: {other:?}"
                ))
            }
        }

        let dup = "message A {\n  // x\n  uint32 x = 1;\n  // y\n  uint32 y = 1;\n}\n";
        // The duplicate is checked before reachability, so this fixture needs no
        // pair of messages around it.
        put(dup)?;
        match run(&dir) {
            Err(e) if e.contains("not unique") => {}
            other => {
                return Err(format!(
                    "canary: a reused field number did not fail the gate: {other:?}"
                ))
            }
        }

        let reserved = "message A {\n  reserved 2;\n  // x\n  uint32 x = 2;\n}\n";
        put(reserved)?;
        match run(&dir) {
            Err(e) if e.contains("reserved") => {}
            other => {
                return Err(format!(
                    "canary: a reserved number did not fail the gate: {other:?}"
                ))
            }
        }

        let header = format!("{clean}message Rpc {{\n  // the magic\n  bytes magic = 9;\n}}\n");
        put(&header)?;
        match run(&dir) {
            Err(e) if e.contains("BOF-1") => {}
            other => {
                return Err(format!(
                    "canary: a BOF-1 field on the wire did not fail the gate: {other:?}"
                ))
            }
        }

        let unversioned = format!(
            "{clean}message NoVersionRequest {{\n  // x\n  Symbol body = 1;\n}}\n\
             message NoVersionResponse {{\n  // x\n  Symbol body = 1;\n}}\n"
        );
        put(&unversioned)?;
        match run(&dir) {
            Err(e) if e.contains("opens an exchange") => {}
            other => {
                return Err(format!(
                    "canary: a Request with no version did not fail the gate: {other:?}"
                ))
            }
        }

        let drawing =
            format!("{clean}message Rpc2 {{\n  // a raster\n  bytes png_bytes = 9;\n}}\n");
        put(&drawing)?;
        match run(&dir) {
            Err(e) if e.contains("drawing") => {}
            other => {
                return Err(format!(
                    "canary: a presentation field on the wire did not fail the gate: {other:?}"
                ))
            }
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-proto-is-total canary OK: an orphan message, a reused number, a reserved \
         number, a BOF-1 header field and a raster field all failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_proto_is_total_catches_injected_orphan() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
