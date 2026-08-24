//! Secret masking - hides confidential values in LLM input and in generated
//! artifacts while preserving code shape and line structure.
//!
//! Closed-circuit principle: no text entering Lubot may contain an API key,
//! token or password. This module cleans text in two layers:
//! 1) key-name patterns (`api_key: x`, `token = "y"`),
//! 2) known secret shapes (`sk-...`, `AKIA...`, `ghp_...`, JWT).

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
];

fn is_upstream_key(v: &str) -> bool {
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

/// Known secret shapes: (kind name, detection function).
/// A predicate that says whether a value looks like a particular kind of
/// secret. The table is made of `(label, predicate)` pairs.
type ValuePredicate = fn(&str) -> bool;

const VALUE_PATTERNS: &[(&str, ValuePredicate)] = &[
    ("upstream_key", is_upstream_key),
    ("aws_access_key", is_aws_access_key),
    ("github_token", is_github_token),
    ("slack_token", is_slack_token),
    ("jwt", is_jwt),
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

/// Mask the confidential field of a `key: value` / `key = value` line. If the
/// key name contains one of the secret keywords, the value is replaced with the
/// mask.
fn redact_key_value(line: &str, report: &mut RedactionReport) -> String {
    // Find the separator position: `: ` or `=` (not inside quotes).
    let mut sep = None;
    let mut in_quote = false;
    for (i, c) in line.char_indices() {
        if c == '"' || c == '\'' {
            in_quote = !in_quote;
            continue;
        }
        if !in_quote && (c == ':' || c == '=') {
            sep = Some(i);
            break;
        }
    }
    let Some(pos) = sep else {
        return line.to_string();
    };

    let key = line[..pos].trim();
    let key_norm = key.to_lowercase().replace('-', "_");
    if !SECRET_KEYWORDS.iter().any(|kw| key_norm.contains(kw)) {
        return line.to_string();
    }

    // Value part: after the separator, quotes and trailing punctuation are preserved.
    let after = &line[pos + 1..];
    let trimmed = after.trim_start();
    let lead_ws = &after[..after.len() - trimmed.len()];
    let quote = trimmed.chars().next().filter(|c| *c == '"' || *c == '\'');
    let value_start = quote.map_or(0, |_| 1);
    let value_part = &trimmed[value_start..];
    // Split off the punctuation at the end of the value (comma, semicolon, closing bracket).
    let value_end = value_part
        .char_indices()
        .rev()
        .find(|(_, c)| !matches!(c, ',' | ';' | ')' | '}' | ']' | ' ' | '\t'))
        .map_or(0, |(i, _)| i + 1);
    let tail = &value_part[value_end..];
    let value = &value_part[..value_end];

    if value.is_empty() || value.starts_with(REDACTION_TOKEN) {
        return line.to_string();
    }

    report.add("key_value");
    let sep_str = &line[pos..pos + 1];
    let q = quote.map_or("", |_| "\"");
    format!("{key}{sep_str}{lead_ws}{q}{REDACTION_TOKEN}{q}{tail}")
}

/// Mask the known secret shapes inside a line (word boundaries are preserved).
fn redact_known_values(line: &str, report: &mut RedactionReport) -> String {
    let mut out = String::new();
    let mut current = String::new();
    let flush = |current: &mut String, out: &mut String, report: &mut RedactionReport| {
        if current.is_empty() {
            return;
        }
        let detected = VALUE_PATTERNS
            .iter()
            .find(|(_, detect)| detect(current))
            .map(|(kind, _)| *kind);
        match detected {
            Some(kind) => {
                report.add(kind);
                out.push_str(REDACTION_TOKEN);
            }
            None => out.push_str(current),
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
    let lines: Vec<String> = text
        .lines()
        .map(|line| {
            let l = redact_key_value(line, &mut report);
            redact_known_values(&l, &mut report)
        })
        .collect();
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

/// Runs every string in a structured value through the masking function
/// (rewrites the JSON tree). Cache records and LLM outputs are not written to
/// disk without passing through this function.
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
                .map(|(k, v)| (k.clone(), redact_model_strings(v)))
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

    #[test]
    fn looks_secretish_detects_and_ignores_redacted() {
        let secret = format!("sk-{}", "abcdefghijklmnopqrstuvwxyz123");
        assert!(looks_secretish(&secret));
        assert!(looks_secretish("password hint"));
        assert!(!looks_secretish(&format!("x {REDACTION_TOKEN} y")));
        assert!(!looks_secretish("hello world"));
    }
}
