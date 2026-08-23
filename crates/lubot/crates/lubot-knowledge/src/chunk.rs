//! Belge parçalama - bir kaynak dosyayı satır-aralıklı, örtüşmeli
//! parçalara böler.
//!
//! Her parça `start_line` / `end_line` (1-tabanlı) korur; böylece
//! çıkarılan her bilgi, kaynağa `yol:Lx-Ly` biçiminde geri işaret
//! edebilir (kanıt izlenebilirliği).

use serde::{Deserialize, Serialize};

/// Bir kaynak dosya parçası.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    pub id: String,
    pub project_id: String,
    pub document_id: String,
    /// Proje köküne göreli yol.
    pub path: String,
    /// 1-tabanlı başlangıç satırı (dahil).
    pub start_line: usize,
    /// Bitiş satırı (dahil).
    pub end_line: usize,
    pub content: String,
    pub content_hash: [u8; 32],
}

/// Varsayılan parçalama parametreleri.
pub const DEFAULT_MAX_LINES: usize = 120;
pub const DEFAULT_OVERLAP_LINES: usize = 10;

/// Bir belgeyi satır-aralıklı parçalara böler.
///
/// `document_id`, `project_id` ve `path` çağıran tarafından verilir;
/// `id` her parça için `document_id:start-end` biçiminde deterministik
/// üretilir (yeniden çalıştırmada kararlı).
///
/// # Errors
///
/// SHA-256 başlatma hatasında (pratikte imkânsız).
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
        // Örtüşme sonsuz döngüye girmesin: en az bir satır ilerle.
        if start >= end {
            start = end.saturating_sub(1).min(total - 1);
        }
    }
    Ok(chunks)
}

/// Kanıt başvurusunu `yol:Lx-Ly` biçiminde biçimler.
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
            .map(|i| format!("satir {i}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn chunks_cover_all_lines_with_overlap() {
        let chunks = chunk_document("p", "d", "src/a.rs", &doc(), Some(100), Some(10)).unwrap();
        assert!(!chunks.is_empty());
        // İlk parça 1'den başlar, son parça 300'de biter.
        assert_eq!(chunks[0].start_line, 1);
        assert_eq!(chunks.last().unwrap().end_line, 300);
        // Örtüşme var: ardışık parçaların aralıkları kesişir.
        for w in chunks.windows(2) {
            assert!(w[1].start_line <= w[0].end_line);
        }
        // Tüm satırlar en az bir parçada.
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
}
