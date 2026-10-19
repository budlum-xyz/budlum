//! Secret masking - hides confidential values in LLM input and in generated
//! artifacts while preserving code shape and line structure.
//!
//! Closed-circuit principle: no text entering AI inference layer may contain an API key,
//! token or password. This module cleans text in two layers:
//! 1) key-name patterns (`api_key: x`, `token = "y"`),
//! 2) known secret shapes (`sk-...`, `AKIA...`, `ghp_...`, JWT),
//! 3) PEM private key blocks (the base64 body lines carry no key name).

/// The fixed token substituted after masking.
pub const REDACTION_TOKEN: &str = "<SECRET:MASKED>";

const SECRET_KEYWORDS: &[&str] = &[
    "api_key",
    "apikey",
    "access_key",
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "private_key",
    "client_secret",
    "auth",
    "credential",
    "passphrase",
    "seed",
    "mnemonic",
    "privkey",
    "wallet_key",
];

/// Does a key name carry one of the secret keywords?
fn is_secret_key(key: &str) -> bool {
    let key_norm = key.to_lowercase().replace('-', "_");
    SECRET_KEYWORDS.iter().any(|kw| key_norm.contains(kw))
}

fn is_generic_sk_key(v: &str) -> bool {
    v.len() >= 18
        && v.starts_with("sk-")
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_aws_access_key(v: &str) -> bool {
    v.len() == 20
        && v.starts_with("AKIA")
        && v.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn is_github_token(v: &str) -> bool {
    v.len() >= 22
        && (v.starts_with("ghp_")
            || v.starts_with("gho_")
            || v.starts_with("ghu_")
            || v.starts_with("ghs_")
            || v.starts_with("ghr_"))
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_slack_token(v: &str) -> bool {
    v.len() >= 18
        && (v.starts_with("xoxb-")
            || v.starts_with("xoxa-")
            || v.starts_with("xoxp-")
            || v.starts_with("xoxr-")
            || v.starts_with("xoxs-"))
}

fn is_jwt(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts[0].starts_with("eyJ")
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn is_googoly_api_key(v: &str) -> bool {
    // Google API keys are 39 characters, prefix "AIza", the rest base62
    // (alphanumeric plus a few punctuation). This is a high-confidence prefix:
    // an unrelated 39-char token beginning with "AIza" is essentially a key.
    v.len() == 39
        && v.starts_with("AIza")
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_scoped_ant_key(v: &str) -> bool {
    // One scoped family uses an `sk-ant-api03-` prefix: long and prefixed.
    v.len() >= 20
        && v.starts_with("sk-ant-")
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_scoped_proj_key(v: &str) -> bool {
    // Another scoped family uses `sk-proj-` (long). The generic `sk-`
    // prefix is already covered by `is_generic_sk_key`; this catches the two
    // well-known scoped families and the legacy `sk-` form.
    v.len() >= 20
        && (v.starts_with("sk-proj-") || v.starts_with("sk-svcacct-"))
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_stripe_key(v: &str) -> bool {
    // Stripe keys are `sk_live_...` or `sk_test_...`, long and base62.
    v.len() >= 24
        && (v.starts_with("sk_live_") || v.starts_with("sk_test_") || v.starts_with("rk_live_"))
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_bearer_jwt_like(v: &str) -> bool {
    // A long dotted token that is not a JWT (no `eyJ` header) begins like a
    // compound credential. Kept conservative: only a string of 3 dot-separated
    // base64url segments with a long total, which is a JWT-shaped secret.
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && v.len() >= 40
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Known secret shapes: (kind name, detection function).
/// A predicate that says whether a value looks like a particular kind of
/// secret. The table is made of `(label, predicate)` pairs.
type ValuePredicate = fn(&str) -> bool;

const VALUE_PATTERNS: &[(&str, ValuePredicate)] = &[
    ("scoped_ant_key", is_scoped_ant_key),
    ("scoped_proj_key", is_scoped_proj_key),
    ("stripe_key", is_stripe_key),
    ("google_api_key", is_googoly_api_key),
    ("generic_sk_key", is_generic_sk_key),
    ("aws_access_key", is_aws_access_key),
    ("github_token", is_github_token),
    ("slack_token", is_slack_token),
    ("jwt", is_jwt),
    ("jwt_like_token", is_bearer_jwt_like),
];

/// Masking report: per-kind counts of the maskings applied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionReport {
    counts: std::collections::BTreeMap<String, usize>,
}

impl RedactionReport {
    fn add(&mut self, kind: &str) {
        *self.counts.entry(kind.to_string()).or_insert(0) += 1;
    }

    /// Total number of maskings.
    #[must_use]
    pub fn total(&self) -> usize {
        self.counts.values().sum()
    }

    /// Counts per kind.
    #[must_use]
    pub fn as_map(&self) -> &std::collections::BTreeMap<String, usize> {
        &self.counts
    }

    /// Was any masking performed?
    #[must_use]
    pub fn changed(&self) -> bool {
        self.total() > 0
    }
}

/// Masked text + report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    text: String,
    report: RedactionReport,
}

impl RedactionResult {
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub fn report(&self) -> &RedactionReport {
        &self.report
    }

    #[must_use]
    pub fn into_text(self) -> String {
        self.text
    }
}

/// Position of the first `:` or `=` outside double quotes. A backslash
/// escapes the next character. A lone apostrophe does not open a quote: it is
/// ordinary prose far more often than a string delimiter.
fn find_separator(s: &str) -> Option<usize> {
    let mut in_quote = false;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => in_quote = !in_quote,
            ':' | '=' if !in_quote => return Some(i),
            _ => {}
        }
    }
    None
}

/// Offset of the closing quote `q` in `body` (a backslash escapes).
fn find_closing_quote(body: &str, q: char) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in body.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == q {
            return Some(i);
        }
    }
    None
}

/// Mask the confidential field of every `key: value` / `key = value` pair on
/// the line. If the key name contains one of the secret keywords, the value is
/// replaced with the mask. A line may hold several pairs (compact JSON).
fn redact_key_value(line: &str, report: &mut RedactionReport) -> String {
    let mut out = String::with_capacity(line.len());
    let mut start = 0;
    while let Some(rel) = find_separator(&line[start..]) {
        let pos = start + rel;
        let head = &line[start..pos];
        // The key is the text after the last pair delimiter in front of the separator.
        let key = head.rfind([',', '{', '[']).map_or(head, |i| &head[i + 1..]);
        out.push_str(head);
        out.push_str(&line[pos..=pos]);
        start = pos + 1;
        if !is_secret_key(key.trim()) {
            continue;
        }

        let after = &line[start..];
        let trimmed = after.trim_start();
        let lead_ws = &after[..after.len() - trimmed.len()];
        let quote = trimmed.chars().next().filter(|c| *c == '"' || *c == '\'');
        let q = quote.map(String::from).unwrap_or_default();
        let body = quote.map_or(trimmed, |_| &trimmed[1..]);

        // A quoted value that closes ends there; the rest of the line may hold more pairs.
        if let Some(close) = quote.and_then(|c| find_closing_quote(body, c)) {
            let value = &body[..close];
            out.push_str(lead_ws);
            out.push_str(&q);
            if value.is_empty() || value.starts_with(REDACTION_TOKEN) {
                out.push_str(value);
            } else {
                report.add("key_value");
                out.push_str(REDACTION_TOKEN);
            }
            out.push_str(&q);
            start += lead_ws.len() + 1 + close + 1;
            continue;
        }

        // Otherwise the value runs to the end of the line. Split off the
        // punctuation at the end of the value (comma, semicolon, closing bracket).
        let value_end = body
            .char_indices()
            .rev()
            .find(|(_, c)| !matches!(c, ',' | ';' | ')' | '}' | ']' | ' ' | '\t'))
            .map_or(0, |(i, c)| i + c.len_utf8());
        let tail = &body[value_end..];
        let value = &body[..value_end];
        if value.is_empty() || value.starts_with(REDACTION_TOKEN) {
            out.push_str(&line[start..]);
            return out;
        }
        report.add("key_value");
        out.push_str(lead_ws);
        out.push_str(&q);
        out.push_str(REDACTION_TOKEN);
        out.push_str(&q);
        out.push_str(tail);
        return out;
    }
    out.push_str(&line[start..]);
    out
}

/// Does the line open a PEM private key block?
fn is_pem_private_begin(line: &str) -> bool {
    line.contains("-----BEGIN ") && line.contains("PRIVATE KEY")
}

/// Width of the leading white space of a line.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// If the line opens a YAML block scalar (`key: |` or `key: >`) under a secret
/// key, returns the indent of the key line. The block lines that follow hold
/// the secret.
fn block_scalar_indent(line: &str) -> Option<usize> {
    let pos = line.find(':')?;
    if !is_secret_key(&line[..pos]) {
        return None;
    }
    let value = line[pos + 1..].trim();
    let is_block = matches!(value, "|" | ">" | "|-" | ">-" | "|+" | ">+");
    is_block.then(|| indent_of(line))
}

/// Mask the known secret shapes inside a line (word boundaries are preserved).
fn redact_known_values(line: &str, report: &mut RedactionReport) -> String {
    let mut out = String::new();
    let mut current = String::new();
    let flush = |current: &mut String, out: &mut String, report: &mut RedactionReport| {
        if current.is_empty() {
            return;
        }
        // Sentence dots around a word are not part of the secret.
        let core = current.trim_matches('.');
        let lead_len = current.len() - current.trim_start_matches('.').len();
        let trail_len = current.len() - current.trim_end_matches('.').len();
        let find = |word: &str| {
            VALUE_PATTERNS
                .iter()
                .find(|(_, detect)| detect(word))
                .map(|(kind, _)| *kind)
        };
        if let Some(kind) = find(current.as_str()) {
            report.add(kind);
            out.push_str(REDACTION_TOKEN);
        } else if let Some(kind) = find(core).filter(|_| !core.is_empty()) {
            report.add(kind);
            out.push_str(&current[..lead_len]);
            out.push_str(REDACTION_TOKEN);
            out.push_str(&current[current.len() - trail_len..]);
        } else {
            out.push_str(current);
        }
        current.clear();
    };
    for ch in line.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
            current.push(ch);
        } else {
            flush(&mut current, &mut out, report);
            out.push(ch);
        }
    }
    flush(&mut current, &mut out, report);
    out
}

/// Mask the text: preserves code shape and line count.
#[must_use]
pub fn redact_text(text: &str) -> RedactionResult {
    let mut report = RedactionReport::default();
    let mut lines: Vec<String> = Vec::new();
    // Indent of the key line of a secret block scalar we are inside.
    let mut block: Option<usize> = None;
    // Are we inside a PEM private key block?
    let mut in_pem = false;
    for line in text.lines() {
        if in_pem {
            if line.contains("-----END ") {
                in_pem = false;
                lines.push(line.to_string());
            } else {
                report.add("pem_private_key");
                lines.push(REDACTION_TOKEN.to_string());
            }
            continue;
        }
        if is_pem_private_begin(line) {
            // A one-line block (BEGIN and END together) is masked whole.
            if line.contains("-----END ") {
                report.add("pem_private_key");
                lines.push(REDACTION_TOKEN.to_string());
            } else {
                in_pem = true;
                lines.push(line.to_string());
            }
            continue;
        }
        if let Some(indent) = block {
            if line.trim().is_empty() {
                lines.push(line.to_string());
                continue;
            }
            let width = indent_of(line);
            if width > indent {
                report.add("block_scalar");
                lines.push(format!("{}{REDACTION_TOKEN}", &line[..width]));
                continue;
            }
        }
        // A line that does not nest under the block ends it; the next state
        // comes from this line alone.
        block = block_scalar_indent(line);
        let l = redact_key_value(line, &mut report);
        lines.push(redact_known_values(&l, &mut report));
    }
    RedactionResult {
        text: lines.join("\n"),
        report,
    }
}

/// Is a value likely to contain a secret?
#[must_use]
pub fn looks_secretish(value: &str) -> bool {
    let lower = value.to_lowercase();
    if lower.contains(&REDACTION_TOKEN.to_lowercase()) {
        return false;
    }
    if SECRET_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return true;
    }
    VALUE_PATTERNS.iter().any(|(_, detect)| detect(value))
}

/// Masks every string below a secret-named key (the whole value, whatever its shape).
fn mask_all_strings(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            if s.is_empty() || s.starts_with(REDACTION_TOKEN) {
                serde_json::Value::String(s.clone())
            } else {
                serde_json::Value::String(REDACTION_TOKEN.to_string())
            }
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(mask_all_strings).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), mask_all_strings(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Runs every string in a structured value through the masking function
/// (rewrites the JSON tree). Cache records and LLM outputs are not written to
/// disk without passing through this function. A string under a key that names
/// a secret (`password`, `api_key`, ...) is masked whole, even when its shape is
/// not a known one.
#[must_use]
pub fn redact_model_strings(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            let r = redact_text(s);
            serde_json::Value::String(r.into_text())
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(redact_model_strings).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| {
                    if is_secret_key(k) {
                        (k.clone(), mask_all_strings(v))
                    } else {
                        (k.clone(), redact_model_strings(v))
                    }
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_api_key_value() {
        // The test data is built in pieces: no password pattern appears in the
        // static source (so a secret scan does not mistake this test file for a leak).
        let secret = format!("sk-{}", "abcdefghijklmnopqrstuvwxyz123");
        let input = format!("api_key: {secret}");
        let r = redact_text(&input);
        assert!(r.text().contains(REDACTION_TOKEN));
        assert!(!r.text().contains(&secret));
        assert!(r.report().changed());
    }

    /// The value end is a byte offset: one past the last character, so a
    /// multi-byte last character needs its own width added, not one. With
    /// `i + 1` the slice landed inside the character and the redactor
    /// panicked on the record instead of storing it.
    #[test]
    fn a_multibyte_value_is_redacted_without_panicking() {
        let secret = "de\u{011f}er\u{015f}\u{015f}";
        let input = format!("api_key: {secret},");
        let r = redact_text(&input);
        assert!(r.text().contains(REDACTION_TOKEN));
        assert!(!r.text().contains(secret));
        assert!(
            r.text().ends_with(','),
            "the punctuation after the value stays"
        );
        assert!(r.report().changed());
    }

    #[test]
    fn preserves_code_shape() {
        let input = "let api_key = \"secret123\";\nprintln!(\"ok\");";
        let r = redact_text(input);
        assert_eq!(r.text().lines().count(), input.lines().count());
        assert!(!r.text().contains("secret123"));
        assert!(r.text().contains("println!"));
    }

    #[test]
    fn plain_text_untouched() {
        let input = "fn main() { println!(\"hello\"); }";
        let r = redact_text(input);
        assert!(!r.report().changed());
        assert_eq!(r.text(), input);
    }

    #[test]
    fn github_token_redacted() {
        let secret = format!("ghp_{}", "abcdefghijklmnopqrstuvwxyz123456");
        let r = redact_text(&format!("token={secret}"));
        assert!(r.text().contains(REDACTION_TOKEN));
        assert!(!r.text().contains("ghp_"));
    }

    #[test]
    fn jwt_redacted() {
        let jwt = format!("eyJ{}.eyJ{}.{}", "hbGciOiJIUzI1NiJ9", "zdWIiOiIxIn0", "sig");
        let r = redact_text(&format!("auth: {jwt}"));
        assert!(r.text().contains(REDACTION_TOKEN));
    }

    #[test]
    fn already_redacted_stays_unchanged() {
        let input = format!("password = {REDACTION_TOKEN}");
        let r = redact_text(&input);
        assert_eq!(r.text(), input);
        assert!(!r.report().changed());
    }

    /// A Google API key in free text is masked even without a keyword.
    #[test]
    fn google_api_key_in_free_text_is_redacted() {
        // Real Google API keys are exactly 39 chars, prefix "AIza". Build a
        // deterministic synthetic one at that length (not a real key).
        let key = format!("AIza{}", "x".repeat(35));
        assert_eq!(key.len(), 39);
        let r = redact_text(&format!("refer to {key} in this note"));
        assert!(r.text().contains(REDACTION_TOKEN));
        assert!(!r.text().contains(&key));
        assert!(r.report().changed());
    }

    /// A scoped `sk-ant-` key in free text is masked.
    #[test]
    fn scoped_ant_key_in_free_text_is_redacted() {
        let key = format!("sk-ant-api03-{}", "abcdefghijklmnopqrstuv");
        let r = redact_text(&format!("credential {key} attached"));
        assert!(r.text().contains(REDACTION_TOKEN));
        assert!(!r.text().contains(&key));
    }

    /// A scoped `sk-proj-` key in free text is masked.
    #[test]
    fn scoped_proj_key_is_redacted() {
        let key = format!("sk-proj-{}", "abcdefghijklmnopqrstuv");
        let r = redact_text(&format!("using {key}"));
        assert!(r.text().contains(REDACTION_TOKEN));
        assert!(!r.text().contains(&key));
    }

    /// A Stripe live key in free text is masked.
    #[test]
    fn stripe_live_key_is_redacted() {
        let key = format!("sk_live_{}", "abcdefghijklmnopqrstuvwx");
        let r = redact_text(&format!("{key} for the charge"));
        assert!(r.text().contains(REDACTION_TOKEN));
        assert!(!r.text().contains(&key));
    }

    /// The new detectors must not make the value scanner start masking plain
    /// identifiers that merely contain a secretish prefix but are not secrets.
    #[test]
    fn no_false_positive_on_non_secrets() {
        for benign in [
            "sk-ant- is a doc prefix", // too short
            "AIza short",              // too short
            "sk-proj- short",
        ] {
            let r = redact_text(benign);
            assert!(!r.report().changed(), "false positive on: {benign}");
        }
    }

    #[test]
    fn looks_secretish_detects_and_ignores_redacted() {
        let secret = format!("sk-{}", "abcdefghijklmnopqrstuvwxyz123");
        assert!(looks_secretish(&secret));
        assert!(looks_secretish("password hint"));
        assert!(!looks_secretish(&format!("x {REDACTION_TOKEN} y")));
        assert!(!looks_secretish("hello world"));
    }

    /// A secret under a secret-named JSON key is masked even with no known shape.
    #[test]
    fn json_secret_key_masks_unshaped_value() {
        let pw = format!("hunter{}", 2);
        let hex = "a1b2c3d4".repeat(5);
        let v = serde_json::json!({
            "password": pw,
            "nested": {"api_key": hex, "note": "plain"},
            "list": [{"token": "abc def"}],
        });
        let out = redact_model_strings(&v).to_string();
        assert!(!out.contains(&pw));
        assert!(!out.contains(&hex));
        assert!(!out.contains("abc def"));
        assert!(out.contains("plain"));
        assert!(out.contains(REDACTION_TOKEN));
    }

    /// A known-shape secret followed by a full stop is still masked.
    #[test]
    fn secret_before_full_stop_is_masked() {
        let secret = format!("sk-{}", "abcdefghijklmnopqrstuvwxyz123");
        let r = redact_text(&format!("The key is {secret}."));
        assert!(!r.text().contains(&secret));
        assert!(r.report().total() >= 1);
        assert_eq!(r.text(), format!("The key is {REDACTION_TOKEN}."));
        let aws = format!("AKIA{}", "ABCDEFGHIJKLMNOP");
        let r = redact_text(&format!("see ({aws}). Done"));
        assert!(!r.text().contains(&aws));
        assert!(r.text().ends_with(". Done"));
    }

    /// Compact JSON: the secret key is not the first key on the line.
    #[test]
    fn compact_json_second_pair_is_masked() {
        let pw = format!("hunter{}", 2);
        let input = format!("{{\"user\":\"bob\",\"password\":\"{pw}\",\"n\":1}}");
        let r = redact_text(&input);
        assert!(!r.text().contains(&pw));
        assert!(r.text().contains("bob"));
        assert!(r.text().contains("\"n\":1"));
        assert!(r.report().changed());
    }

    /// A single apostrophe in prose must not hide the separator.
    #[test]
    fn apostrophe_in_prose_does_not_hide_secret() {
        let pw = format!("hunter{}", 2);
        let r = redact_text(&format!("don't set password: {pw}"));
        assert!(!r.text().contains(&pw));
        assert!(r.report().changed());
    }

    /// A YAML block scalar under a secret key is masked line by line.
    #[test]
    fn yaml_block_scalar_secret_is_masked() {
        let body1 = "Zm9vYmFyYmF6cXV4";
        let body2 = "c2VjcmV0bGluZXR3bw";
        let input = format!("name: x\nprivate_key: |\n  {body1}\n  {body2}\nnext: ok");
        let r = redact_text(&input);
        assert!(!r.text().contains(body1));
        assert!(!r.text().contains(body2));
        assert_eq!(r.text().lines().count(), input.lines().count());
        assert!(r.text().ends_with("next: ok"));
    }

    /// A PEM private key body has no key name on its lines.
    #[test]
    fn pem_private_key_body_is_masked() {
        let begin = format!("-----BEGIN {} KEY-----", "RSA PRIVATE");
        let end = format!("-----END {} KEY-----", "RSA PRIVATE");
        let b1 = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo";
        let b2 = "4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onL";
        let input = format!("before\n{begin}\n{b1}\n{b2}\n{end}\nafter");
        let r = redact_text(&input);
        assert!(!r.text().contains(b1));
        assert!(!r.text().contains(b2));
        assert!(r.text().contains(&begin));
        assert!(r.text().contains(&end));
        assert!(r.text().ends_with("after"));
        assert_eq!(r.text().lines().count(), input.lines().count());
        let one = format!("{begin}{b1}{end}");
        assert!(!redact_text(&one).text().contains(b1));
    }

    /// Wallet material under seed-like key names is masked.
    #[test]
    fn seed_and_mnemonic_keys_are_masked() {
        let seed = "0123456789abcdef".repeat(4);
        let r = redact_text(&format!("seed: {seed}"));
        assert!(!r.text().contains(&seed));
        let words = "alpha bravo charlie delta echo foxtrot";
        let r = redact_text(&format!("mnemonic = \"{words}\""));
        assert!(!r.text().contains("alpha"));
        let r = redact_text(&format!("privkey: {seed}"));
        assert!(!r.text().contains(&seed));
        let r = redact_text(&format!("wallet_key={seed}"));
        assert!(!r.text().contains(&seed));
    }
}
