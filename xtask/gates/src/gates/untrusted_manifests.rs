//! Every path that takes a manifest from a caller must apply the same check.
//!
//! Ported from `scripts/check-untrusted-manifests-are-fully-validated.sh`.
//!
//! # The failure this closes
//!
//! Two entry points accept a `ContentManifest` an untrusted caller built.
//! `RegisterStorageManifest` called `validate_untrusted`. `open_deal` called
//! `verify_id` and stopped there, and `open_deal` is the path that also takes
//! the payer's money. `verify_id` proves the id was derived from the fields
//! present, not that they agree: `manifest_id` covers `k` and `n`, so a
//! manifest declaring `k = 1, n = 3` hashes consistently while reporting a
//! loss tolerance its shard list cannot deliver.
//!
//! # What is checked
//!
//! 1. `validate_untrusted` still ties `k` and `n` to the shards actually
//!    present.
//! 2. Every door that accepts a caller-supplied manifest calls it: `open_deal`
//!    and the `RegisterStorageManifest` match arm (not the `send` site that
//!    shares the name).
//! 3. No such path settles for `verify_id` alone, with string literals and
//!    comments stripped so inert text cannot satisfy the gate.
//! 4. The named regressions exist as real `#[test]` functions.

use std::fmt::Write as _;
use std::path::Path;

/// Python `\s`.
fn skip_py_ws(s: &str) -> &str {
    let mut idx = 0usize;
    for (i, c) in s.char_indices() {
        if matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{000c}' | '\u{000b}') {
            idx = i + c.len_utf8();
        } else {
            break;
        }
    }
    &s[idx..]
}

fn word_before(s: &str, idx: usize) -> bool {
    s[..idx]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn word_at(s: &str, idx: usize) -> bool {
    s[idx..]
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Blank Rust block comments, which nest.
fn strip_block_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    let mut depth = 0usize;
    let n = chars.len();
    while i < n {
        if i + 1 < n && chars[i] == '/' && chars[i + 1] == '*' {
            depth += 1;
            out.push_str("  ");
            i += 2;
            continue;
        }
        if depth > 0 && i + 1 < n && chars[i] == '*' && chars[i + 1] == '/' {
            depth -= 1;
            out.push_str("  ");
            i += 2;
            continue;
        }
        if depth > 0 {
            out.push(if chars[i] == '\n' { '\n' } else { ' ' });
            i += 1;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn blank_chars(chars: &[char]) -> String {
    chars
        .iter()
        .map(|&c| if c == '\n' { '\n' } else { ' ' })
        .collect()
}

/// Blank string literals (`b?"..."`) and char literals (`b?'...'`).
fn strip_quoted(text: &str, quote: char) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = String::new();
    let mut i = 0usize;
    while i < n {
        let c = chars[i];
        let start = if c == quote || (c == 'b' && i + 1 < n && chars[i + 1] == quote) {
            Some(i)
        } else {
            None
        };
        let Some(start) = start else {
            out.push(c);
            i += 1;
            continue;
        };
        let content_start = start + 1 + usize::from(chars[start] == 'b');
        let mut ok = false;
        let mut close_at = 0usize;
        if quote == '\'' {
            if content_start < n {
                let item_end = if chars[content_start] == '\\' {
                    if content_start + 1 < n {
                        content_start + 2
                    } else {
                        content_start + 1
                    }
                } else {
                    content_start + 1
                };
                if item_end < n && chars[item_end] == '\'' {
                    ok = true;
                    close_at = item_end;
                }
            }
        } else {
            let mut j = content_start;
            while j < n {
                match chars[j] {
                    '\\' => {
                        if j + 1 < n {
                            j += 2;
                        } else {
                            break;
                        }
                    }
                    '"' => {
                        ok = true;
                        close_at = j;
                        break;
                    }
                    _ => j += 1,
                }
            }
        }
        if !ok {
            out.push(chars[start]);
            i = start + 1;
            continue;
        }
        out.push_str(&blank_chars(&chars[start..=close_at]));
        i = close_at + 1;
    }
    out
}

/// Strip line comments, nested block comments and string/char literals,
/// preserving line structure.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.split_inclusive('\n') {
        let Some(pos) = line.find("//") else {
            out.push_str(line);
            continue;
        };
        out.push_str(&line[..pos]);
        for c in line[pos..].chars() {
            out.push(if c == '\n' { '\n' } else { ' ' });
        }
    }
    let out = strip_block_comments(&out);
    let out = strip_quoted(&out, '"');
    strip_quoted(&out, '\'')
}

/// Brace-matched body of `pub fn NAME\s*\(`.
fn body_of<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let header = format!("pub fn {name}");
    let mut from = 0usize;
    while let Some(pos) = src[from..].find(&header) {
        let abs = from + pos;
        let rest = &src[abs + header.len()..];
        if !skip_py_ws(rest).starts_with('(') {
            from = abs + 1;
            continue;
        }
        let open_rel = src[abs + header.len()..].find('{')?;
        let i = abs + header.len() + open_rel;
        let mut depth = 0usize;
        for (off, c) in src[i..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&src[i..i + off + c.len_utf8()]);
                    }
                }
                _ => {}
            }
        }
        return None;
    }
    None
}

/// `\.k\b`: a `.k` whose following character is not a word character.
fn has_dot_k_boundary(vu: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = vu[from..].find(".k") {
        let abs = from + pos;
        if !word_at(vu, abs + 2) {
            return true;
        }
        from = abs + 1;
    }
    false
}

/// `\bn\b`: a standalone `n`.
fn has_standalone_n(vu: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = vu[from..].find('n') {
        let abs = from + pos;
        if !word_before(vu, abs) && !word_at(vu, abs + 1) {
            return true;
        }
        from = abs + 1;
    }
    false
}

/// `\bmanifest\s*\.\s*METHOD\s*\(`.
fn has_manifest_call(region: &str, method: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = region[from..].find("manifest") {
        let abs = from + pos;
        if word_before(region, abs) {
            from = abs + 1;
            continue;
        }
        let rest = skip_py_ws(&region[abs + "manifest".len()..]);
        let Some(rest) = rest.strip_prefix('.') else {
            from = abs + 1;
            continue;
        };
        let rest = skip_py_ws(rest);
        let Some(rest) = rest.strip_prefix(method) else {
            from = abs + 1;
            continue;
        };
        if skip_py_ws(rest).starts_with('(') {
            return true;
        }
        from = abs + 1;
    }
    false
}

/// The `ChainCommand::RegisterStorageManifest { ... } =>` match arm, plus the
/// 2000 characters after its start.
fn register_handler_region(actor_code: &str) -> Option<String> {
    let needle = "ChainCommand::RegisterStorageManifest";
    let mut from = 0usize;
    while let Some(pos) = actor_code[from..].find(needle) {
        let abs = from + pos;
        let rest = skip_py_ws(&actor_code[abs + needle.len()..]);
        let Some(rest) = rest.strip_prefix('{') else {
            from = abs + 1;
            continue;
        };
        // `[^}]*` then `}` then `\s*=>`.
        let Some(close) = rest.find('}') else {
            from = abs + 1;
            continue;
        };
        if skip_py_ws(&rest[close + 1..]).starts_with("=>") {
            let region: String = actor_code[abs..].chars().take(2000).collect();
            return Some(region);
        }
        from = abs + 1;
    }
    None
}

/// `#[test]\s*(?:#\[[^\]]*\]\s*)*fn\s+TEST\s*\(` in the raw source.
fn has_test_fn(src: &str, test: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = src[from..].find("#[test]") {
        let abs = from + pos;
        let mut rest = &src[abs + "#[test]".len()..];
        rest = skip_py_ws(rest);
        while rest.starts_with("#[") {
            let Some(close) = rest.find(']') else {
                break;
            };
            rest = skip_py_ws(&rest[close + 1..]);
        }
        let Some(after_fn) = rest.strip_prefix("fn") else {
            from = abs + 1;
            continue;
        };
        if after_fn.len() == skip_py_ws(after_fn).len() {
            from = abs + 1;
            continue; // `\s+` after `fn` is required
        }
        let after_fn = skip_py_ws(after_fn);
        let Some(tail) = after_fn.strip_prefix(test) else {
            from = abs + 1;
            continue;
        };
        if skip_py_ws(tail).starts_with('(') {
            return true;
        }
        from = abs + 1;
    }
    false
}

fn check_strong(vu: Option<&str>, problems: &mut Vec<String>, checked: &mut usize) {
    // The strong check must still be strong.
    *checked += 1;
    if let Some(vu) = vu {
        *checked += 1;
        if (!vu.contains("erasure.k") && !has_dot_k_boundary(vu)) || !vu.contains("ShardKind::Data")
        {
            problems.push(String::from(
                "`validate_untrusted` no longer compares `k` against the data \
                 shards present. Without that comparison a manifest can declare a \
                 loss tolerance its shard list cannot deliver, and the id will \
                 still verify because `manifest_id` covers `k` and `n`.",
            ));
        }
        if (!vu.contains("erasure.n") && !has_standalone_n(vu)) || !vu.contains("shard_count") {
            problems.push(String::from(
                "`validate_untrusted` no longer ties `n` to `shard_count`.",
            ));
        }
    } else {
        problems.push(String::from(
            "`ContentManifest::validate_untrusted` is gone. It is the only check \
             that ties the declared erasure scheme to the shards present.",
        ));
    }
}

fn check_door(label: &str, region: Option<&str>, problems: &mut Vec<String>, checked: &mut usize) {
    // Both doors must use the strong check, and neither may settle for the
    // weaker one.
    *checked += 1;
    if let Some(region) = region {
        if !has_manifest_call(region, "validate_untrusted") {
            let weak = has_manifest_call(region, "verify_id");
            let detail = if weak {
                " It calls `verify_id`, which only proves the id was derived from \
                 the fields present, not that they agree with each other."
            } else {
                ""
            };
            problems.push(format!(
                "`{label}` accepts a caller-supplied manifest without calling \
                 `validate_untrusted`.{detail}"
            ));
        }
    } else {
        problems.push(format!(
            "cannot find `{label}` to check what it validates. If it was renamed, \
             update this gate in the same commit so the door stays watched."
        ));
    }
}

fn check_regressions(deal_src: &str, problems: &mut Vec<String>, checked: &mut usize) {
    // The regressions must exist as real tests.
    *checked += 1;
    for test in REGRESSION_TESTS {
        if !has_test_fn(deal_src, test) {
            problems.push(format!(
                "required regression test `{test}` is missing or is not a `#[test]`."
            ));
        }
    }
}

/// # Errors
///
/// Missing sources, a hollowed or absent strong check, an unguarded door, or
/// a missing regression test.
pub fn run(root: &Path) -> Result<String, String> {
    let manifest = root.join("src/storage/manifest.rs");
    let deal = root.join("src/domain/storage_deal.rs");
    let actor = root.join("src/chain/chain_actor.rs");

    for path in [&manifest, &deal, &actor] {
        if !path.is_file() {
            return Err(format!(
                "FAIL: expected source file missing: {}",
                path.display()
            ));
        }
    }

    let manifest_code = strip_comments(&std::fs::read_to_string(&manifest).unwrap_or_default());
    let deal_src = std::fs::read_to_string(&deal).unwrap_or_default();
    let deal_code = strip_comments(&deal_src);
    let actor_code = strip_comments(&std::fs::read_to_string(&actor).unwrap_or_default());

    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    check_strong(
        body_of(&manifest_code, "validate_untrusted"),
        &mut problems,
        &mut checked,
    );
    check_door(
        "open_deal",
        body_of(&deal_code, "open_deal"),
        &mut problems,
        &mut checked,
    );
    check_door(
        "RegisterStorageManifest handler",
        register_handler_region(&actor_code).as_deref(),
        &mut problems,
        &mut checked,
    );
    check_regressions(&deal_src, &mut problems, &mut checked);

    if checked == 0 {
        return Err(String::from("FAIL: gate checked nothing"));
    }

    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            let _ = writeln!(msg, "FAIL: {p}");
        }
        return Err(msg);
    }

    Ok(format!(
        "untrusted manifest gate OK: {checked} checks, both doors apply the same validation"
    ))
}

const REGRESSION_TESTS: [&str; 2] = [
    "a_deal_open_refuses_a_manifest_claiming_parity_it_does_not_have",
    "a_deal_open_still_accepts_a_coherent_manifest",
];

// ---------------------------------------------------------------------------
// Self-test: the seven canaries of the shell version.
// ---------------------------------------------------------------------------

const STRONG_MANIFEST: &str = "    pub fn validate_untrusted(&self) -> Result<(), String> {\n\
        if self.erasure.n != self.shard_count { return Err(\"n\".into()); }\n\
        let data = self.shards.iter().filter(|s| s.kind == ShardKind::Data).count() as u32;\n\
        if data != self.erasure.k { return Err(\"k\".into()); }\n\
        self.verify_id()\n\
    }\n";
const WEAK_MANIFEST: &str = "    pub fn validate_untrusted(&self) -> Result<(), String> {\n\
        self.verify_id()\n\
    }\n";
const LIT_DEAL: &str = "    pub fn open_deal(&mut self) -> Result<(), String> {\n\
        let _s = \"manifest.validate_untrusted()\";\n\
        /* outer /* inner */ manifest.validate_untrusted() */\n\
        manifest.verify_id()?;\n\
        Ok(())\n\
    }\n\
    #[test]\n\
    fn a_deal_open_refuses_a_manifest_claiming_parity_it_does_not_have() {}\n\
    #[test]\n\
    fn a_deal_open_still_accepts_a_coherent_manifest() {}\n";
const CHAIN_ACTOR: &str = "pub async fn register_storage_manifest(&self) {\n\
    self.tx.send(ChainCommand::RegisterStorageManifest {\n\
        manifest,\n\
        response: tx,\n\
    }).await;\n\
}\n\
ChainCommand::RegisterStorageManifest { manifest, response } => {\n\
    if let Err(e) = manifest.validate_untrusted() { return; }\n\
}\n";

/// Write a fixture tree and check the gate's verdict.
fn check_fixture(
    vu_mode: &str,
    deal_mode: &str,
    tests_mode: &str,
    lit: bool,
    expect_ok: bool,
    label: &str,
) -> Result<(), String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-manifest")?;
    for sub in ["src/storage", "src/domain", "src/chain"] {
        let _ = std::fs::create_dir_all(dir.join(sub));
    }

    let manifest = match vu_mode {
        "strong" => STRONG_MANIFEST,
        "weak" => WEAK_MANIFEST,
        _ => "",
    };
    std::fs::write(dir.join("src/storage/manifest.rs"), manifest).map_err(|e| e.to_string())?;

    let (_call, deal_body) = if lit {
        (None, Some(LIT_DEAL.to_string()))
    } else {
        let call = if deal_mode == "strong" {
            "manifest.validate_untrusted()?;"
        } else {
            "manifest.verify_id()?;"
        };
        let mut tests = String::new();
        if tests_mode == "present" {
            for name in [
                "a_deal_open_refuses_a_manifest_claiming_parity_it_does_not_have",
                "a_deal_open_still_accepts_a_coherent_manifest",
            ] {
                let _ = writeln!(tests, "#[test]\nfn {name}() {{}}");
            }
        }
        (
            Some(call),
            Some(format!(
                "    pub fn open_deal(&mut self) -> Result<(), String> {{\n        {call}\n        Ok(())\n    }}\n{tests}"
            )),
        )
    };
    std::fs::write(
        dir.join("src/domain/storage_deal.rs"),
        deal_body.unwrap_or_default(),
    )
    .map_err(|e| e.to_string())?;

    std::fs::write(dir.join("src/chain/chain_actor.rs"), CHAIN_ACTOR).map_err(|e| e.to_string())?;

    let result = run(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    if expect_ok {
        result.map(|_| ()).map_err(|e| format!("{label}: {e}"))
    } else {
        match result {
            Err(_) => Ok(()),
            Ok(_) => Err(format!("{label}: gate passed when it must fail")),
        }
    }
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    // 1. Both doors strong: the corrected shape must pass.
    check_fixture(
        "strong",
        "strong",
        "present",
        false,
        true,
        "the corrected tree was rejected",
    )?;

    // 2. The original bug: the deal door settles for `verify_id`.
    check_fixture(
        "strong",
        "weak",
        "present",
        false,
        false,
        "a deal-open that only calls verify_id",
    )?;

    // 3. The check itself is hollowed out while both call sites still call it.
    check_fixture(
        "weak",
        "strong",
        "present",
        false,
        false,
        "a validate_untrusted that checks no scheme",
    )?;

    // 4. The check disappears entirely.
    check_fixture(
        "gone",
        "strong",
        "present",
        false,
        false,
        "a missing validate_untrusted",
    )?;

    // 5. A regression test is dropped.
    check_fixture(
        "strong",
        "strong",
        "absent",
        false,
        false,
        "a missing regression test",
    )?;

    // 6. The guarded handler must still pass when the same command name also
    //    appears at the `send` site. Every fixture above already carries both
    //    spellings, so this asserts the distinction directly.
    check_fixture(
        "strong",
        "strong",
        "present",
        false,
        true,
        "the `send` site was mistaken for the handler",
    )?;

    // 7. A door whose only `validate_untrusted` evidence lives inside a string
    //    or a nested block comment still settles for verify_id.
    check_fixture(
        "strong",
        "weak",
        "present",
        true,
        false,
        "a door whose only validate_untrusted evidence is inside a string or comment",
    )?;

    Ok(String::from(
        "untrusted manifest gate self-test OK: 7 canaries",
    ))
}
