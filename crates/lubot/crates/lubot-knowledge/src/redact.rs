//! Sır maskeleme - LLM girişi ve üretilen yapıtlarda gizli değerleri
//! gizlerken kod şeklini ve satır yapısını korur.
//!
//! Kapalı-devre ilkesi: Lubot'a giren hiçbir metin, API anahtarı, token
//! veya parola içermemelidir. Bu modül metni iki katmanda temizler:
//! 1) anahtar-adı desenleri (`api_key: x`, `token = "y"`),
//! 2) bilinen sır biçimleri (`sk-...`, `AKIA...`, `ghp_...`, JWT).

/// Maskeleme sonrası yerine konan sabit belirteç.
pub const REDACTION_TOKEN: &str = "<GIZLI:MASKE>";

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

fn is_deepseek_key(v: &str) -> bool {
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
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
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

/// Bilinen sır biçimleri: (tür adı, tespit fonksiyonu).
const VALUE_PATTERNS: &[(&str, fn(&str) -> bool)] = &[
    ("deepseek_key", is_deepseek_key),
    ("aws_access_key", is_aws_access_key),
    ("github_token", is_github_token),
    ("slack_token", is_slack_token),
    ("jwt", is_jwt),
];

/// Maskeleme raporu: tür bazında uygulanan maskeleme sayıları.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionReport {
    counts: std::collections::BTreeMap<String, usize>,
}

impl RedactionReport {
    fn add(&mut self, kind: &str) {
        *self.counts.entry(kind.to_string()).or_insert(0) += 1;
    }

    /// Toplam maskeleme sayısı.
    #[must_use]
    pub fn total(&self) -> usize {
        self.counts.values().sum()
    }

    /// Tür bazında sayılar.
    #[must_use]
    pub fn as_map(&self) -> &std::collections::BTreeMap<String, usize> {
        &self.counts
    }

    /// Herhangi bir maskeleme yapıldı mı?
    #[must_use]
    pub fn changed(&self) -> bool {
        self.total() > 0
    }
}

/// Maskelenmiş metin + rapor.
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

/// Bir satırda `anahtar: değer` / `anahtar = değer` biçimindeki gizli
/// alanı maskele. Anahtar adında bir sır anahtar kelimesi geçiyorsa
/// değer maske ile değiştirilir.
fn redact_key_value(line: &str, report: &mut RedactionReport) -> String {
    // Ayraç konumunu bul: `: ` veya `=` (tırnak içinde olmayan).
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

    // Değer kısmı: ayraç sonrası, tırnak ve son noktalama korunur.
    let after = &line[pos + 1..];
    let trimmed = after.trim_start();
    let lead_ws = &after[..after.len() - trimmed.len()];
    let quote = trimmed.chars().next().filter(|c| *c == '"' || *c == '\'');
    let value_start = quote.map_or(0, |_| 1);
    let value_part = &trimmed[value_start..];
    // Değerin sonundaki noktalamayı ayır (virgül, noktalı virgül, kapanış parantezi).
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
    format!(
        "{key}{sep_str}{lead_ws}{q}{REDACTION_TOKEN}{q}{tail}"
    )
}

/// Satır içindeki bilinen sır biçimlerini maskele (kelime sınırı korunur).
fn redact_known_values(line: &str, report: &mut RedactionReport) -> String {
    let mut out = String::new();
    let mut current = String::new();
    let mut flush = |current: &mut String, out: &mut String, report: &mut RedactionReport| {
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

/// Metni maskele: kod şeklini ve satır sayısını korur.
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

/// Bir değerin sır içerme ihtimali yüksek mi?
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

/// Yapısal bir değerdeki tüm string'leri maskeleme fonksiyonundan
/// geçirir (JSON ağacını yeniden yazar). Önbellek kayıtları ve LLM
/// çıktıları bu fonksiyondan geçmeden diske yazılmaz.
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
        // Test verisi parcali uretilir: statik kaynakta sifre deseni
        // bulunmaz (sir taramasi test dosyasini sifre sizintisi sanmasin).
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
        let input = "fn main() { println!(\"merhaba\"); }";
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
        assert!(!looks_secretish("merhaba dunya"));
    }
}
