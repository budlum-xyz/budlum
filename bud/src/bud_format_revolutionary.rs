//! .bud revolutionary ratios V6 - a source-bound compact table, SQLite, an
//! evidence-first path and hybrid search.
//!
//! Measurement-based ratios plus a general account of the language-model
//! oriented techniques.
//!
//! Gates: K-BUD-COMPACT-TABLE, K-BUD-EVIDENCE, K-BUD-SQLITE,
//! K-BUD-SECRET-REDACT, K-BUD-COLUMNAR, K-BUD-FTS5,
//! K-BUD-COMPACT_TABLE-COMPACT.

#![forbid(unsafe_code)]

pub const BUD_MAGIC_V6: [u8; 8] = *b"BUD\x01\x00\x00\x00\x00";
pub const BUD_VERSION_V6: u16 = 6;

#[derive(Debug, Clone)]
pub struct CompactTable {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub max_cell_chars: usize, // 240
    pub max_chars: usize,      // 120k
}

impl CompactTable {
    pub fn new(headers: Vec<String>) -> Self {
        Self {
            headers,
            rows: Vec::new(),
            max_cell_chars: 240,
            max_chars: 120_000,
        }
    }

    /// Escape a cell for the table and cut it to `max_chars` characters.
    ///
    /// The limit counts characters, not bytes. The byte count was used
    /// before, and `String::truncate` at a byte index inside a multi-byte
    /// character panics; every row passes through here with the default
    /// limit of 240, so a long non-ASCII cell took the whole table down.
    pub fn escape_cell(s: &str, max_chars: usize) -> String {
        let mut text = s.replace('|', "\\|").replace('\n', " ");
        text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if max_chars > 0 && text.chars().count() > max_chars {
            let mut cut: String = text.chars().take(max_chars - 1).collect();
            cut.push('…');
            return cut;
        }
        text
    }

    pub fn format_evidence(path: &str, start: u32, end: u32) -> String {
        if path.is_empty() {
            return "".to_string();
        }
        if start > 0 && end > 0 {
            format!("{}:L{}-L{}", path, start, end)
        } else {
            path.to_string()
        }
    }

    pub fn add_row(&mut self, row: Vec<String>) {
        let escaped: Vec<String> = row
            .iter()
            .map(|c| Self::escape_cell(c, self.max_cell_chars))
            .collect();
        self.rows.push(escaped);
    }

    /// Renders the table as text.
    ///
    /// It comes through `Display`: if the inventory method were defined
    /// inherently under the name `to_string` (clippy::inherent_to_string), it
    /// would shadow what `ToString` produces and the type could not be
    /// formatted with `{}`. Writing `Display` unites both in the same body, and
    /// existing `.to_string()` calls keep working.
    fn fmt_rows(&self) -> String {
        let mut lines = Vec::new();
        lines.push(self.headers.join(" | "));
        for row in &self.rows {
            lines.push(row.join(" | "));
        }
        lines.join("\n")
    }

    pub fn fits(&self, existing: &str, candidate: &str) -> bool {
        let content = format!("{}\n\n{}", existing, candidate);
        content.len() <= self.max_chars
    }

    pub fn token_estimate(&self) -> usize {
        // Simple: chars /4 ~ tokens
        self.to_string().len() / 4
    }

    pub fn compression_ratio_vs_json(&self, json_len: usize) -> f64 {
        let compact_len = self.to_string().len();
        if compact_len == 0 {
            return 1.0;
        }
        json_len as f64 / compact_len as f64
    }
}

#[derive(Debug, Clone)]
pub struct Evidence {
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub confidence: String, // high/medium/low
}

impl core::fmt::Display for CompactTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.fmt_rows())
    }
}

impl Evidence {
    pub fn new(path: &str, start: u32, end: u32, confidence: &str) -> Self {
        Self {
            path: path.to_string(),
            start_line: start,
            end_line: end,
            confidence: confidence.to_string(),
        }
    }

    pub fn format(&self) -> String {
        CompactTable::format_evidence(&self.path, self.start_line, self.end_line)
    }

    pub fn has_evidence(&self) -> bool {
        !self.path.is_empty() && self.start_line > 0
    }
}

#[derive(Debug, Clone)]
pub struct Fact {
    pub id: String,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub evidence: Vec<Evidence>,
    pub confidence: String,
}

impl Fact {
    pub fn priority(&self) -> u8 {
        let has_ev = !self.evidence.is_empty();
        match (self.confidence.as_str(), has_ev) {
            ("high", true) => 0,
            ("high", false) => 1,
            ("medium", _) => 1,
            _ => 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SqliteChunk {
    pub id: String,
    pub project_id: String,
    pub document_id: String,
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub content: String,
    pub content_hash: [u8; 32],
}

/// The marker a redacted token is replaced with.
const REDACTED_MARK: &str = "[REDACTED]";

/// Key names whose value is a secret when it follows `=` or `:`. The
/// compound names match anywhere in the key (`AWS_SECRET_ACCESS_KEY`,
/// `openai_api_key`); the bare words must be the whole key, or prose such as
/// "the token: abc" would lose its next word.
const COMPOUND_SECRET_KEYS: [(&str, &str); 7] = [
    ("aws_secret", "aws_secret"),
    ("api_key", "api_key"),
    ("apikey", "api_key"),
    ("private_key", "private_key"),
    ("client_secret", "secret"),
    ("access_token", "token"),
    ("auth_token", "token"),
];
const BARE_SECRET_KEYS: [(&str, &str); 4] = [
    ("secret", "secret"),
    ("token", "token"),
    ("password", "password"),
    ("passwd", "password"),
];

/// One piece of a text: a secret token with its kind, or anything else kept
/// verbatim.
enum Piece<'a> {
    Secret(&'a str, &'static str),
    Plain(&'a str),
}

/// What the scanner remembers between tokens: the kind a key name just seen
/// introduces, and whether a `=` or `:` has armed it for the next token.
#[derive(Default)]
struct KeyState {
    after_key: Option<&'static str>,
    value_of: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub struct SecretRedactor;

/// GitHub's token prefixes: the classic five and the fine-grained personal
/// access token, which was missing from the list and passed through.
const GITHUB_TOKEN_PREFIXES: [&str; 6] = ["github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"];

impl SecretRedactor {
    /// Replace every secret token in `content` with `[REDACTED]` and name
    /// the kinds that were found, in order of first appearance.
    ///
    /// The whole token goes, not its marker. The first version replaced the
    /// four bytes `AKIA` or the three bytes `sk-` and left the key body
    /// standing in the rendered table and in `SqliteChunk.content`, which is
    /// where the secret was going to be read from. Two shapes are matched: a
    /// token that is itself a known key (`AKIA...`, `sk-...`, `ghp_...`), and
    /// the value that follows a secret key name and a `=` or `:`.
    pub fn redact(content: &str) -> (String, Vec<String>) {
        let mut out = String::with_capacity(content.len());
        let mut seen: Vec<String> = Vec::new();
        for piece in Self::pieces(content) {
            match piece {
                Piece::Secret(_, kind) => {
                    if !seen.iter().any(|k| k == kind) {
                        seen.push(kind.to_string());
                    }
                    out.push_str(REDACTED_MARK);
                }
                Piece::Plain(text) => out.push_str(text),
            }
        }
        (out, seen)
    }

    /// Every secret token of `content`, in order: what a redaction of
    /// `content` must not contain.
    fn secret_tokens(content: &str) -> Vec<String> {
        Self::pieces(content)
            .into_iter()
            .filter_map(|piece| match piece {
                Piece::Secret(token, _) => Some(token.to_string()),
                Piece::Plain(_) => None,
            })
            .collect()
    }

    fn is_token_char(ch: char) -> bool {
        ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | '+')
    }

    /// Classify one token and update what it means for the next one.
    fn classify<'a>(token: &'a str, state: &mut KeyState) -> Piece<'a> {
        let kind = state.value_of.take().or_else(|| Self::secret_kind(token));
        state.after_key = if kind.is_none() {
            Self::key_kind(token)
        } else {
            None
        };
        match kind {
            Some(kind) => Piece::Secret(token, kind),
            None => Piece::Plain(token),
        }
    }

    /// Cut `content` into tokens and separators, deciding for each token
    /// whether it is a secret.
    fn pieces(content: &str) -> Vec<Piece<'_>> {
        let mut out = Vec::new();
        let mut token_start: Option<usize> = None;
        let mut state = KeyState::default();
        for (idx, ch) in content.char_indices() {
            if Self::is_token_char(ch) {
                token_start.get_or_insert(idx);
                continue;
            }
            if let Some(start) = token_start.take() {
                out.push(Self::classify(&content[start..idx], &mut state));
            }
            if matches!(ch, '=' | ':') {
                if state.after_key.is_some() {
                    state.value_of = state.after_key;
                }
            } else if !(ch.is_whitespace() || matches!(ch, '"' | '\'')) {
                state = KeyState::default();
            }
            out.push(Piece::Plain(&content[idx..idx + ch.len_utf8()]));
        }
        if let Some(start) = token_start {
            out.push(Self::classify(&content[start..], &mut state));
        }
        out
    }

    /// The kind of secret a bare token is, if it is one.
    fn secret_kind(token: &str) -> Option<&'static str> {
        let alnum_dash = |t: &str| {
            t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        if token.len() == 20
            && token.starts_with("AKIA")
            && token
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return Some("aws_access_key");
        }
        if token.len() >= 18 && token.starts_with("sk-") && alnum_dash(token) {
            return Some("sk_key");
        }
        if token.len() >= 22
            && GITHUB_TOKEN_PREFIXES.iter().any(|p| token.starts_with(p))
            && alnum_dash(token)
        {
            return Some("github_token");
        }
        None
    }

    /// The token without the prefix that names its kind: what is left of
    /// `AKIAIOSFODNN7EXAMPLE` when only `AKIA` was struck out.
    fn token_body(token: &str) -> &str {
        ["AKIA", "sk-"]
            .iter()
            .chain(GITHUB_TOKEN_PREFIXES.iter())
            .find_map(|prefix| token.strip_prefix(prefix))
            .unwrap_or(token)
    }

    /// The kind a key name introduces, if the name says its value is secret.
    fn key_kind(token: &str) -> Option<&'static str> {
        let lower = token.to_ascii_lowercase();
        COMPOUND_SECRET_KEYS
            .iter()
            .find(|(name, _)| lower.contains(name))
            .or_else(|| BARE_SECRET_KEYS.iter().find(|(name, _)| lower == *name))
            .map(|(_, kind)| *kind)
    }
}

#[derive(Debug, Clone)]
pub struct ColumnarTransform;

impl ColumnarTransform {
    pub fn transform_csv(csv: &str) -> (Vec<String>, Vec<Vec<String>>) {
        // CSV to columnar: header + columns
        let lines: Vec<&str> = csv.lines().collect();
        if lines.is_empty() {
            return (vec![], vec![]);
        }
        let headers: Vec<String> = lines[0].split(',').map(|s| s.to_string()).collect();
        let mut columns: Vec<Vec<String>> = vec![Vec::new(); headers.len()];
        for line in lines.iter().skip(1) {
            let cols: Vec<&str> = line.split(',').collect();
            for (i, col) in cols.iter().enumerate() {
                if i < columns.len() {
                    columns[i].push(col.to_string());
                }
            }
        }
        (headers, columns)
    }

    pub fn ratio_improvement(original_len: usize, columnar_len: usize) -> f64 {
        if columnar_len == 0 {
            return 1.0;
        }
        original_len as f64 / columnar_len as f64
    }
}

#[derive(Debug, Clone)]
pub struct HybridSearch;

impl HybridSearch {
    pub fn reciprocal_rank_fusion(ft5_rank: usize, tfidf_rank: usize) -> f64 {
        // RRF: 1/(k+rank)
        let k = 60.0;
        1.0 / (k + ft5_rank as f64) + 1.0 / (k + tfidf_rank as f64)
    }
}

// Gates for revolutionary

pub struct RevolutionaryGates;

impl RevolutionaryGates {
    pub fn k_bud_compact_table(table: &CompactTable, json_len: usize) -> Result<(), &'static str> {
        let ratio = table.compression_ratio_vs_json(json_len);
        if ratio < 2.0 {
            return Err("K-BUD-COMPACT-TABLE: ratio <2.0 not revolutionary");
        }
        Ok(())
    }
    pub fn k_bud_evidence(ev: &Evidence) -> Result<(), &'static str> {
        if !ev.has_evidence() {
            return Err("K-BUD-EVIDENCE: no evidence");
        }
        Ok(())
    }
    pub fn k_bud_sqlite(chunk: &SqliteChunk) -> Result<(), &'static str> {
        if chunk.content_hash == [0u8; 32] {
            return Err("K-BUD-SQLITE: hash zero");
        }
        Ok(())
    }
    /// No secret token of `original` survives in `redacted`, neither whole
    /// nor as the body left after its prefix. The check used to look for the
    /// four bytes `AKIA` only, so a redaction that stripped the marker and
    /// kept the key body passed it.
    pub fn k_bud_secret_redact(original: &str, redacted: &str) -> Result<(), &'static str> {
        let survived = SecretRedactor::secret_tokens(original)
            .iter()
            .any(|secret| {
                redacted.contains(secret.as_str())
                    || redacted.contains(SecretRedactor::token_body(secret))
            });
        if survived {
            return Err("K-BUD-SECRET-REDACT: secret not stripped");
        }
        Ok(())
    }
    pub fn k_bud_columnar(headers: &[String], columns: &[Vec<String>]) -> Result<(), &'static str> {
        if headers.is_empty() {
            return Err("K-BUD-COLUMNAR: no headers");
        }
        if columns.is_empty() {
            return Err("K-BUD-COLUMNAR: no columns");
        }
        Ok(())
    }
    pub fn k_bud_fts5(rrf_score: f64) -> Result<(), &'static str> {
        if rrf_score <= 0.0 {
            return Err("K-BUD-FTS5: rrf score zero");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_table_ratio() {
        let mut table = CompactTable::new(vec![
            "id".into(),
            "subject".into(),
            "predicate".into(),
            "object".into(),
            "evidence".into(),
            "confidence".into(),
        ]);
        table.add_row(vec![
            "abc123".into(),
            "file".into(),
            "implements".into(),
            "feature".into(),
            "src/main.rs:L10-L20".into(),
            "high".into(),
        ]);
        let json_len = 1000;
        let ratio = table.compression_ratio_vs_json(json_len);
        assert!(ratio > 1.0);
        assert!(RevolutionaryGates::k_bud_compact_table(&table, json_len).is_ok());
    }
    #[test]
    fn evidence() {
        let ev = Evidence::new("src/main.rs", 10, 20, "high");
        assert!(ev.has_evidence());
        assert!(RevolutionaryGates::k_bud_evidence(&ev).is_ok());
    }
    #[test]
    fn secret_redact_removes_the_whole_token() {
        let aws = "AKIAIOSFODNN7EXAMPLE";
        let sk = "sk-abcdefghijklmnopqrstuvwxyz";
        let text = format!("my key {aws} and {sk}, api_key=\"hunter2secret\" done");
        let (redacted, kinds) = SecretRedactor::redact(&text);
        assert!(!redacted.contains(aws), "{redacted}");
        assert!(!redacted.contains(sk), "{redacted}");
        assert!(!redacted.contains("hunter2secret"), "{redacted}");
        assert!(
            !redacted.contains("IOSFODNN7EXAMPLE"),
            "the key body must go too"
        );
        assert!(redacted.contains("my key [REDACTED] and [REDACTED], api_key=\"[REDACTED]\" done"));
        assert_eq!(kinds, vec!["aws_access_key", "sk_key", "api_key"]);
        assert!(RevolutionaryGates::k_bud_secret_redact(&text, &redacted).is_ok());
    }

    /// A fine-grained GitHub token (`github_pat_...`) is a secret like the
    /// classic `ghp_` one; the prefix was missing and the token survived.
    #[test]
    fn secret_redact_strips_fine_grained_github_tokens() {
        // Assembled at run time: a token-shaped literal in the tree trips the
        // secret scanners the CI runs, and they cannot tell a fixture apart.
        let pat = format!("github_pat_{}_{}", "1".repeat(22), "x".repeat(59));
        let classic = format!("ghp_{}", "y".repeat(36));
        let text = format!("token {pat} then {classic} end");
        let (redacted, kinds) = SecretRedactor::redact(&text);
        assert_eq!(redacted, "token [REDACTED] then [REDACTED] end");
        assert_eq!(kinds, vec!["github_token"], "kinds are reported once each");
        assert!(RevolutionaryGates::k_bud_secret_redact(&text, &redacted).is_ok());
        // The gate sees the body of a fine-grained token that lost only its prefix.
        let body_kept = text.replace("github_pat_", "[REDACTED]");
        assert!(RevolutionaryGates::k_bud_secret_redact(&text, &body_kept).is_err());
    }

    /// The gate refuses the redaction the first version produced: marker
    /// stripped, key body kept.
    #[test]
    fn secret_redact_gate_sees_a_surviving_key_body() {
        let text = "my key AKIAIOSFODNN7EXAMPLE";
        let marker_only = text.replace("AKIA", "[REDACTED]");
        assert!(RevolutionaryGates::k_bud_secret_redact(text, &marker_only).is_err());
        assert!(RevolutionaryGates::k_bud_secret_redact(text, "my key [REDACTED]").is_ok());
        // Prose that merely mentions the prefixes is not a secret.
        let (same, kinds) = SecretRedactor::redact("the sk- prefix and the AKIA prefix");
        assert_eq!(same, "the sk- prefix and the AKIA prefix");
        assert!(kinds.is_empty());
    }

    /// A cell longer than the limit is cut at a character boundary. Cutting
    /// at a byte index used to panic inside a multi-byte character.
    #[test]
    fn escape_cell_cuts_characters_not_bytes() {
        let cell = "é".repeat(300);
        let cut = CompactTable::escape_cell(&cell, 240);
        assert_eq!(cut.chars().count(), 240);
        assert!(cut.ends_with('…'));
        assert_eq!(CompactTable::escape_cell("a|b\nc", 240), "a\\|b c");
    }
    #[test]
    fn columnar() {
        let csv = "name,age\nAlice,30\nBob,25";
        let (headers, columns) = ColumnarTransform::transform_csv(csv);
        assert_eq!(headers.len(), 2);
        assert_eq!(columns.len(), 2);
        assert!(RevolutionaryGates::k_bud_columnar(&headers, &columns).is_ok());
    }
    #[test]
    fn fts5_rrf() {
        let score = HybridSearch::reciprocal_rank_fusion(1, 2);
        assert!(score > 0.0);
        assert!(RevolutionaryGates::k_bud_fts5(score).is_ok());
    }
}
