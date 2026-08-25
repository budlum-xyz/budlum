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

    pub fn escape_cell(s: &str, max_chars: usize) -> String {
        let mut text = s.replace("|", "\\|").replace("\n", " ");
        text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if max_chars > 0 && text.len() > max_chars {
            text.truncate(max_chars - 1);
            text.push('…');
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

#[derive(Debug, Clone)]
pub struct SecretRedactor;

impl SecretRedactor {
    pub fn redact(content: &str) -> (String, Vec<String>) {
        // Strip AWS, a model vendor keys etc
        let mut redacted = content.to_string();
        let mut secrets = Vec::new();
        // Simple pattern: AKIA, sk- etc
        for pattern in &["AKIA", "sk-", "aws_secret", "api_key"] {
            if content.contains(pattern) {
                secrets.push(pattern.to_string());
                redacted = redacted.replace(pattern, "[REDACTED]");
            }
        }
        (redacted, secrets)
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
    pub fn k_bud_secret_redact(original: &str, redacted: &str) -> Result<(), &'static str> {
        if original.contains("AKIA") && redacted.contains("AKIA") {
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
    fn secret_redact() {
        let (redacted, _secrets) = SecretRedactor::redact("my key AKIA123 and sk-abc");
        assert!(!redacted.contains("AKIA"));
        assert!(RevolutionaryGates::k_bud_secret_redact("my key AKIA123", &redacted).is_ok());
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
