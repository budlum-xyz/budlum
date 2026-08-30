//! Document chunking - splits a source file into overlapping chunks over line
//! ranges.
//!
//! Every chunk keeps `start_line` / `end_line` (1-based), so any extracted
//! piece of knowledge can point back at the source as `path:Lx-Ly` (evidence
//! traceability).

use serde::{Deserialize, Serialize};

/// One chunk of a source file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    pub id: String,
    pub project_id: String,
    pub document_id: String,
    /// The path relative to the project root.
    pub path: String,
    /// The 1-based start line (inclusive).
    pub start_line: usize,
    /// The end line (inclusive).
    pub end_line: usize,
    pub content: String,
    pub content_hash: [u8; 32],
}

/// The default chunking parameters.
pub const DEFAULT_MAX_LINES: usize = 120;
pub const DEFAULT_OVERLAP_LINES: usize = 10;

/// Splits a document into chunks over line ranges.
///
/// `document_id`, `project_id` and `path` are supplied by the caller; the `id`
/// of each chunk is produced deterministically as `document_id:start-end`
/// (stable across reruns).
///
/// # Errors
///
/// On a SHA-256 initialisation failure (impossible in practice).
pub fn chunk_document(
    project_id: &str,
    document_id: &str,
    path: &str,
    content: &str,
    max_lines: Option<usize>,
    overlap: Option<usize>,
) -> Result<Vec<Chunk>, String> {
    let max_lines = max_lines.unwrap_or(DEFAULT_MAX_LINES).max(1);
    let overlap = overlap
        .unwrap_or(DEFAULT_OVERLAP_LINES)
        .min(max_lines.saturating_sub(1));

    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    if total == 0 {
        return Ok(Vec::new());
    }

    let mut chunks = Vec::new();
    let mut start = 0usize;
    while start < total {
        let end = (start + max_lines).min(total);
        let chunk_content = lines[start..end].join("\n");
        // The prompt tells the model that a credential found inside a document it
        // was given is to be treated as unreadable. The place that sentence becomes
        // true is here, before the text becomes an index entry: a chunk is hashed
        // and stored, so an unmasked credential would be committed to the index and
        // quoted back as evidence. Ordinary documents are untouched - the mask
        // rewrites a chunk only when it actually found something to mask, so chunk
        // ids and content hashes do not move.
        let mask = crate::redact::redact_text(&chunk_content);
        let chunk_content = if mask.report().total() > 0 {
            mask.into_text()
        } else {
            chunk_content
        };
        let hash = crate::content_hash(chunk_content.as_bytes())?;
        chunks.push(Chunk {
            id: format!("{document_id}:{}-{}", start + 1, end),
            project_id: project_id.to_string(),
            document_id: document_id.to_string(),
            path: path.to_string(),
            start_line: start + 1,
            end_line: end,
            content: chunk_content,
            content_hash: hash,
        });
        if end >= total {
            break;
        }
        start = end.saturating_sub(overlap);
        // Do not let the overlap turn into an infinite loop: advance by at
        // least one line.
        if start >= end {
            start = end.saturating_sub(1).min(total - 1);
        }
    }
    Ok(chunks)
}

/// Formats the evidence reference as `path:Lx-Ly`.
#[must_use]
pub fn format_evidence(path: &str, start_line: usize, end_line: usize) -> String {
    if path.is_empty() {
        return String::new();
    }
    if start_line > 0 && end_line >= start_line {
        format!("{path}:L{start_line}-L{end_line}")
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> String {
        (1..=300)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn chunks_cover_all_lines_with_overlap() {
        let chunks = chunk_document("p", "d", "src/a.rs", &doc(), Some(100), Some(10)).unwrap();
        assert!(!chunks.is_empty());
        // The first chunk starts at 1 and the last one ends at 300.
        assert_eq!(chunks[0].start_line, 1);
        assert_eq!(chunks.last().unwrap().end_line, 300);
        // There is overlap: the ranges of consecutive chunks intersect.
        for w in chunks.windows(2) {
            assert!(w[1].start_line <= w[0].end_line);
        }
        // Every line appears in at least one chunk.
        let mut covered = vec![false; 300];
        for c in &chunks {
            for l in c.start_line..=c.end_line {
                covered[l - 1] = true;
            }
        }
        assert!(covered.iter().all(|b| *b));
    }

    #[test]
    fn empty_document_yields_no_chunks() {
        assert!(chunk_document("p", "d", "x", "", None, None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn small_document_is_single_chunk() {
        let chunks = chunk_document("p", "d", "x", "a\nb\nc", None, None).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].start_line, 1);
        assert_eq!(chunks[0].end_line, 3);
    }

    #[test]
    fn evidence_format() {
        assert_eq!(format_evidence("src/a.rs", 10, 20), "src/a.rs:L10-L20");
        assert_eq!(format_evidence("", 1, 2), "");
    }

    #[test]
    fn ids_are_deterministic() {
        let a = chunk_document("p", "d", "x", &doc(), Some(100), Some(10)).unwrap();
        let b = chunk_document("p", "d", "x", &doc(), Some(100), Some(10)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_credential_in_a_document_is_masked_before_it_becomes_a_chunk() {
        let secret = format!("ghp_{}{}", "0123456789abcdefghij", "0123456789");
        let doc = format!("title: notes\ntoken: {secret}\nbody: nothing else\n");
        let chunks = chunk_document("p", "d", "notes.md", &doc, None, None).unwrap();
        let joined: String = chunks.iter().map(|c| c.content.as_str()).collect::<Vec<_>>().join("\n");
        assert!(!joined.contains(&secret), "the credential survived into the index");
        assert!(joined.contains("<SECRET:MASKED>"), "nothing was masked: {joined}");
        // Shape is preserved: the line count and the ids do not move.
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].start_line, 1);
        assert_eq!(chunks[0].end_line, 3);
    }

    #[test]
    fn an_ordinary_document_is_not_rewritten() {
        let doc = "alpha: 1\nbeta: 2\n";
        let chunks = chunk_document("p", "d", "x.md", doc, None, None).unwrap();
        assert_eq!(chunks[0].content, "alpha: 1\nbeta: 2");
    }
}
