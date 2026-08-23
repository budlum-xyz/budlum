//! Kompakt bağlam tablosu - bilgiyi LLM girişine JSON yerine satır
//! tabloları olarak biçimler; tekrarlanan anahtarları eler, token
//! bütçesini düşürür.
//!
//! Hücreler `|` ve yeni satırdan kaçırılır; kanıt `yol:Lx-Ly`
//! biçimindedir; hücreler azami karakterle kırpılır.

use serde::{Deserialize, Serialize};

/// Varsayılan hücre azami karakteri.
pub const DEFAULT_CELL_MAX_CHARS: usize = 240;
/// Varsayılan bağlam azami karakteri.
pub const DEFAULT_CONTEXT_MAX_CHARS: usize = 120_000;

/// Bir kanıt başvurusu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
}

/// Bilgi tablosu satırı: özne - yüklem - nesne.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactRow {
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub confidence: String,
    pub evidence: Option<EvidenceRef>,
}

/// İlişki tablosu satırı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationRow {
    pub source: String,
    pub relation: String,
    pub target: String,
    pub confidence: String,
    pub evidence: Option<EvidenceRef>,
}

/// Kompakt bağlam girdisi.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactContext {
    pub project_name: String,
    pub facts: Vec<FactRow>,
    pub relations: Vec<RelationRow>,
    pub notes: Vec<String>,
}

fn escape_cell(value: &str, max_chars: usize) -> String {
    let mut text = value.replace('|', r"\|").replace('\n', " ");
    text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if max_chars > 0 && text.chars().count() > max_chars {
        let truncated: String = text.chars().take(max_chars - 1).collect();
        format!("{truncated}…")
    } else {
        text
    }
}

/// Kanıtı tek hücreye biçimler: `yol:Lx-Ly`.
#[must_use]
pub fn format_evidence(evidence: &Option<EvidenceRef>) -> String {
    match evidence {
        Some(ev) if !ev.path.is_empty() && ev.end_line >= ev.start_line && ev.start_line > 0 => {
            format!("{}:L{}-L{}", ev.path, ev.start_line, ev.end_line)
        }
        Some(ev) => ev.path.clone(),
        None => String::new(),
    }
}

fn table(headers: &[&str], rows: &[Vec<String>], max_chars: usize) -> String {
    let mut out = headers
        .iter()
        .map(|h| escape_cell(h, max_chars))
        .collect::<Vec<_>>()
        .join(" | ");
    for row in rows {
        let cells: Vec<String> = row.iter().map(|c| escape_cell(c, max_chars)).collect();
        out.push('\n');
        out.push_str(&cells.join(" | "));
    }
    out
}

/// Bağlamı kompakt tabloya dönüştürür. `max_chars` aşılırsa keser
/// (önce ilişkiler, sonra düşük güvenli olgular).
#[must_use]
pub fn render(ctx: &CompactContext, max_chars: Option<usize>) -> String {
    let max_chars = max_chars.unwrap_or(DEFAULT_CONTEXT_MAX_CHARS);
    let cell_max = DEFAULT_CELL_MAX_CHARS;

    // Olguları güven + kanıta göre sırala: yüksek güvenli + kanıtlı önce.
    let mut facts: Vec<&FactRow> = ctx.facts.iter().collect();
    facts.sort_by_key(|f| {
        let has_evidence = f.evidence.is_some();
        match (f.confidence.as_str(), has_evidence) {
            ("high", true) => 0,
            ("high", false) | ("medium", true) => 1,
            ("medium", false) => 2,
            _ => 3,
        }
    });

    let mut parts: Vec<String> = Vec::new();
    parts.push(format!(
        "# Proje\n{}",
        escape_cell(&ctx.project_name, cell_max)
    ));

    if !facts.is_empty() {
        let rows: Vec<Vec<String>> = facts
            .iter()
            .map(|f| {
                vec![
                    f.subject.clone(),
                    f.predicate.clone(),
                    f.object.clone(),
                    format_evidence(&f.evidence),
                    f.confidence.clone(),
                ]
            })
            .collect();
        parts.push(format!(
            "# Olgular\n{}",
            table(
                &["Ozne", "Yuklem", "Nesne", "Kanit", "Guven"],
                &rows,
                cell_max
            )
        ));
    }

    if !ctx.relations.is_empty() {
        let rows: Vec<Vec<String>> = ctx
            .relations
            .iter()
            .map(|r| {
                vec![
                    r.source.clone(),
                    r.relation.clone(),
                    r.target.clone(),
                    format_evidence(&r.evidence),
                    r.confidence.clone(),
                ]
            })
            .collect();
        parts.push(format!(
            "# Iliskiler\n{}",
            table(
                &["Kaynak", "Iliski", "Hedef", "Kanit", "Guven"],
                &rows,
                cell_max
            )
        ));
    }

    if !ctx.notes.is_empty() {
        let mut notes = String::from("# Notlar\n");
        for n in &ctx.notes {
            notes.push_str(&escape_cell(n, cell_max));
            notes.push('\n');
        }
        parts.push(notes);
    }

    let mut out = parts.join("\n\n");
    if out.chars().count() > max_chars {
        let truncated: String = out.chars().take(max_chars.saturating_sub(16)).collect();
        out = format!("{truncated}\n@truncated true");
    }
    out
}

/// Token sayısını kabaca tahmin eder (sözcük başına ~1.3 token).
#[must_use]
pub fn estimate_tokens(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    (text.split_whitespace().count() as f64 * 1.3).ceil() as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CompactContext {
        CompactContext {
            project_name: "ornek".to_string(),
            facts: vec![FactRow {
                subject: "StorageRegistry".to_string(),
                predicate: "defines".to_string(),
                object: "erasure".to_string(),
                confidence: "high".to_string(),
                evidence: Some(EvidenceRef {
                    path: "src/storage.rs".to_string(),
                    start_line: 10,
                    end_line: 20,
                }),
            }],
            relations: vec![RelationRow {
                source: "node".to_string(),
                relation: "calls".to_string(),
                target: "registry".to_string(),
                confidence: "medium".to_string(),
                evidence: None,
            }],
            notes: vec!["depolama katmani".to_string()],
        }
    }

    #[test]
    fn renders_tables() {
        let out = render(&sample(), None);
        assert!(out.contains("# Olgular"));
        assert!(out.contains("StorageRegistry"));
        assert!(out.contains("src/storage.rs:L10-L20"));
        assert!(out.contains("# Iliskiler"));
        assert!(out.contains("# Notlar"));
    }

    #[test]
    fn escapes_pipes_and_newlines() {
        let mut ctx = sample();
        ctx.facts[0].object = "a|b\nc".to_string();
        let out = render(&ctx, None);
        assert!(out.contains(r"a\|b"));
        assert!(!out.contains("a|b"));
    }

    #[test]
    fn truncation_marker() {
        let out = render(&sample(), Some(60));
        assert!(out.contains("@truncated true"));
    }

    #[test]
    fn token_estimate_nonzero() {
        assert!(estimate_tokens("bir iki uc dort") > 0);
        assert_eq!(estimate_tokens(""), 0);
    }
}
