//! The ownerless-dependency gate: no crates.io dependency may have zero
//! publishers.
//!
//! It replaces the Python script that `security-hardening.yml` wrote to
//! `/tmp` from a heredoc (Z6: gates are Rust, not shell or Python). The input
//! is the `cargo supply-chain json --diffable` output. An ownerless crate is
//! one nobody can take over and nobody can patch; for a chain that is not a
//! version lag but a hole that will never close.
//!
//! The parser accepts the three shapes the tool has emitted (a map from crate
//! name to owners, a list of objects, a list of bare names) so a tool-side
//! format change cannot crash it, refuses any other shape instead of calling
//! an unparsed file clean, and refuses an inspection of zero crates.

use std::path::Path;

use serde_json::Value;

/// The crates with their owner lists, from one JSON document.
fn crate_owners(data: &Value) -> Result<Vec<(String, usize)>, String> {
    let owners_len = |v: Option<&Value>| v.and_then(Value::as_array).map_or(0, Vec::len);
    match data.get("crates_io_crates") {
        Some(Value::Object(map)) => Ok(map
            .iter()
            .map(|(name, owners)| (name.clone(), owners_len(Some(owners))))
            .collect()),
        Some(Value::Array(entries)) => Ok(entries
            .iter()
            .filter_map(|entry| match entry {
                Value::Object(obj) => Some((
                    obj.get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("?")
                        .to_string(),
                    owners_len(obj.get("owners")),
                )),
                Value::String(name) => Some((name.clone(), 0)),
                _ => None,
            })
            .collect()),
        other => Err(format!(
            "unrecognised crates_io_crates shape ({}); the gate refuses to claim a verdict over \
             JSON it cannot parse",
            match other {
                None => "missing",
                Some(Value::Null) => "null",
                Some(Value::Bool(_)) => "bool",
                Some(Value::Number(_)) => "number",
                Some(Value::String(_)) => "string",
                _ => "unknown",
            }
        )),
    }
}

/// Judge one JSON text.
fn judge(text: &str) -> Result<String, String> {
    let data: Value =
        serde_json::from_str(text).map_err(|e| format!("the supply-chain JSON is invalid: {e}"))?;
    let pairs = crate_owners(&data)?;
    if pairs.is_empty() {
        return Err(String::from(
            "THE GATE RAN EMPTY: no crates were inspected.",
        ));
    }
    let mut orphans: Vec<&str> = pairs
        .iter()
        .filter(|(_, owners)| *owners == 0)
        .map(|(name, _)| name.as_str())
        .collect();
    orphans.sort_unstable();
    if !orphans.is_empty() {
        return Err(format!(
            "{} ownerless dependencies:\n  {}\n\nAn ownerless crate cannot be patched by anyone. \
             If a vulnerability appears there is nobody to wait for; replace the dependency or \
             vendor it in.",
            orphans.len(),
            orphans.join("\n  ")
        ));
    }
    Ok(format!(
        "No ownerless dependencies: all {} crates.io crates have a publisher.",
        pairs.len()
    ))
}

/// # Errors
///
/// Returns the ownerless crates, or a refusal when the file cannot be read or
/// parsed or lists no crate at all.
pub fn run(_root: &Path, json: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(json)
        .map_err(|e| format!("cannot read {}: {e}", json.display()))?;
    judge(&text)
}

/// # Errors
///
/// Returns a finding when a canary does not behave: each bad shape must fail
/// and the clean tree must pass, so the gate is neither a constant pass nor a
/// constant fail.
pub fn self_test() -> Result<String, String> {
    let must_fail = [
        (
            "an ownerless crate beside an owned one (map shape)",
            r#"{"crates_io_crates": {"owned-crate": [{"login": "someone", "kind": "user"}], "orphan-crate": []}}"#,
        ),
        (
            "a bare-name entry in the list shape",
            r#"{"crates_io_crates": [{"name": "owned-crate", "owners": [{"login": "someone"}]}, "bare-string-crate"]}"#,
        ),
        (
            "a list entry with no owners",
            r#"{"crates_io_crates": [{"name": "orphan", "owners": []}]}"#,
        ),
        (
            "a shape the gate does not know",
            r#"{"crates_io_crates": 42}"#,
        ),
        ("a missing crates_io_crates", r"{}"),
        ("an empty inspection", r#"{"crates_io_crates": {}}"#),
        ("text that is not JSON", "not json"),
    ];
    for (what, text) in must_fail {
        if judge(text).is_ok() {
            return Err(format!("canary: the gate passed {what} -> vacuous"));
        }
    }
    let clean = r#"{"crates_io_crates": {"a": [{"login": "x"}], "b": [{"login": "y"}]}}"#;
    if judge(clean).is_err() {
        return Err(String::from(
            "canary: a wholly owned tree was refused, so the gate is a constant FAIL",
        ));
    }
    let clean_list = r#"{"crates_io_crates": [{"name": "a", "owners": [{"login": "x"}]}]}"#;
    if judge(clean_list).is_err() {
        return Err(String::from(
            "canary: a wholly owned list-shape tree was refused",
        ));
    }
    Ok(String::from(
        "ownerless-dependencies canary OK: every ownerless, unknown, empty and unparsable input FAILs; owned trees PASS.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() {
        super::self_test().expect("ownerless-dependencies self-test");
    }

    #[test]
    fn the_orphan_is_named() {
        let err = super::judge(r#"{"crates_io_crates": {"a": [{"login": "x"}], "z-orphan": []}}"#)
            .expect_err("an orphan");
        assert!(err.contains("z-orphan"));
        assert!(err.contains("1 ownerless"));
    }
}
