//! Görev hafızası - tamamlanan görevlerin karar, komut ve hata
//! geçmişini JSONL'de saklar ve yeni bir görev için ilgili geçmişi
//! skorlayarak seçer.
//!
//! Skor bileşenleri: sorgu kelime eşleşmesi (özne/yol/özet), kaynak
//! güncelliği (son değişen dosyalar) ve güven. Kapalı-devre: kayıtlar
//! yalnız yerel dosyada tutulur.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Bir görev çalıştırmasının özet kaydı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRun {
    pub task_id: String,
    pub request: String,
    pub summary: String,
    pub status: String,
    pub commit_hash: Option<String>,
    pub created_at: String,
}

/// Görev kararı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDecision {
    pub task_id: String,
    pub decision: String,
    pub rationale: Option<String>,
    pub created_at: String,
}

/// Görev komutu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCommand {
    pub task_id: String,
    pub command: String,
    pub output: Option<String>,
    pub status: String,
}

/// Görev hatası.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskFailure {
    pub task_id: String,
    pub failure: String,
    pub resolution: Option<String>,
}

/// JSONL satırı: tür etiketli kayıt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MemoryRecord {
    Run(TaskRun),
    Decision(TaskDecision),
    Command(TaskCommand),
    Failure(TaskFailure),
}

/// Görev hafızası: JSONL dosyasına ekle-oku.
#[derive(Debug, Clone)]
pub struct TaskMemory {
    path: std::path::PathBuf,
    runs: Vec<TaskRun>,
    decisions: Vec<TaskDecision>,
    commands: Vec<TaskCommand>,
    failures: Vec<TaskFailure>,
}

impl TaskMemory {
    /// Hafızayı açar (dosya yoksa boş başlar; yazma dizini oluşturulur).
    ///
    /// # Errors
    ///
    /// Dizin oluşturulamazsa veya dosya okunamazsa.
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("hafıza dizini kurulamadı: {e}"))?;
        }
        let mut mem = Self {
            path: path.to_path_buf(),
            runs: Vec::new(),
            decisions: Vec::new(),
            commands: Vec::new(),
            failures: Vec::new(),
        };
        if path.exists() {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("hafıza okunamadı: {e}"))?;
            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(rec) = serde_json::from_str::<MemoryRecord>(line) {
                    mem.push_record(rec);
                }
            }
        }
        Ok(mem)
    }

    fn push_record(&mut self, rec: MemoryRecord) {
        match rec {
            MemoryRecord::Run(r) => self.runs.push(r),
            MemoryRecord::Decision(d) => self.decisions.push(d),
            MemoryRecord::Command(c) => self.commands.push(c),
            MemoryRecord::Failure(f) => self.failures.push(f),
        }
    }

    /// Bir kaydı dosyaya ekler (append-only).
    ///
    /// # Errors
    ///
    /// Serileştirme veya yazma hatasında.
    pub fn append(&mut self, rec: MemoryRecord) -> Result<(), String> {
        let line = serde_json::to_string(&rec).map_err(|e| format!("kayıt kodlanamadı: {e}"))?;
        let mut text = std::fs::read_to_string(&self.path).unwrap_or_default();
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&line);
        text.push('\n');
        std::fs::write(&self.path, text).map_err(|e| format!("hafıza yazılamadı: {e}"))?;
        self.push_record(rec);
        Ok(())
    }

    #[must_use]
    pub fn runs(&self) -> &[TaskRun] {
        &self.runs
    }

    #[must_use]
    pub fn decisions_for(&self, task_id: &str) -> Vec<&TaskDecision> {
        self.decisions
            .iter()
            .filter(|d| d.task_id == task_id)
            .collect()
    }

    #[must_use]
    pub fn failures_for(&self, task_id: &str) -> Vec<&TaskFailure> {
        self.failures
            .iter()
            .filter(|f| f.task_id == task_id)
            .collect()
    }

    /// Sorguyla en alakalı `k` görev kaydını skorlayarak döndürür.
    ///
    /// Skor: sorgu kelimelerinin `request`/`summary` içinde geçmesi
    /// (+2), karar sayısı (+1, en çok 3) ve hata çözülmüşse (+1).
    #[must_use]
    pub fn relevant_runs(&self, query: &str, k: usize) -> Vec<&TaskRun> {
        let words: Vec<String> = query
            .to_lowercase()
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|w| w.len() >= 3)
            .map(ToString::to_string)
            .collect();

        let mut scored: Vec<(usize, &TaskRun)> = self
            .runs
            .iter()
            .map(|r| {
                let mut score = 0usize;
                let hay = format!("{} {}", r.request.to_lowercase(), r.summary.to_lowercase());
                for w in &words {
                    if hay.contains(w) {
                        score += 2;
                    }
                }
                score += self.decisions_for(&r.task_id).len().min(3);
                if self
                    .failures_for(&r.task_id)
                    .iter()
                    .any(|f| f.resolution.is_some())
                {
                    score += 1;
                }
                (score, r)
            })
            .collect();

        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.created_at.cmp(&b.1.created_at)));
        scored
            .into_iter()
            .filter(|(s, _)| *s > 0)
            .take(k)
            .map(|(_, r)| r)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_records(mem: &mut TaskMemory) {
        mem.append(MemoryRecord::Run(TaskRun {
            task_id: "t1".into(),
            request: "erasure kod duzelt".into(),
            summary: "GF alani siniri asildi".into(),
            status: "tamam".into(),
            commit_hash: None,
            created_at: "2026-08-15".into(),
        }))
        .unwrap();
        mem.append(MemoryRecord::Decision(TaskDecision {
            task_id: "t1".into(),
            decision: "GF(2^8) icinde kal".into(),
            rationale: None,
            created_at: "2026-08-15".into(),
        }))
        .unwrap();
        mem.append(MemoryRecord::Run(TaskRun {
            task_id: "t2".into(),
            request: "bns kayit duzelt".into(),
            summary: "uzunluk kurali".into(),
            status: "tamam".into(),
            commit_hash: None,
            created_at: "2026-08-14".into(),
        }))
        .unwrap();
    }

    #[test]
    fn append_and_reopen_roundtrip() {
        let dir = std::env::temp_dir().join("lubot-mem-test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("memory.jsonl");
        let mut mem = TaskMemory::open(&path).unwrap();
        sample_records(&mut mem);
        drop(mem);
        let reopened = TaskMemory::open(&path).unwrap();
        assert_eq!(reopened.runs().len(), 2);
        assert_eq!(reopened.decisions_for("t1").len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relevance_scoring_ranks_matching_task_first() {
        let dir = std::env::temp_dir().join("lubot-mem-test2");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("memory.jsonl");
        let mut mem = TaskMemory::open(&path).unwrap();
        sample_records(&mut mem);
        let rel = mem.relevant_runs("erasure kod", 5);
        assert!(!rel.is_empty());
        assert_eq!(rel[0].task_id, "t1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_match_returns_empty() {
        let dir = std::env::temp_dir().join("lubot-mem-test3");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("memory.jsonl");
        let mut mem = TaskMemory::open(&path).unwrap();
        sample_records(&mut mem);
        assert!(mem.relevant_runs("tamamen ilgisiz konu", 5).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
