//! Task memory - stores the decision, command and failure history of completed
//! tasks in JSONL and selects the relevant history for a new task by scoring it.
//!
//! Score components: query word matches (subject/path/summary), source recency
//! (recently changed files) and confidence. Closed circuit: the records are kept
//! in a local file only.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// The summary record of one task run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRun {
    pub task_id: String,
    pub request: String,
    pub summary: String,
    pub status: String,
    pub commit_hash: Option<String>,
    pub created_at: String,
}

/// A task decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDecision {
    pub task_id: String,
    pub decision: String,
    pub rationale: Option<String>,
    pub created_at: String,
}

/// A task command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCommand {
    pub task_id: String,
    pub command: String,
    pub output: Option<String>,
    pub status: String,
}

/// A task failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskFailure {
    pub task_id: String,
    pub failure: String,
    pub resolution: Option<String>,
}

/// A JSONL line: a type-tagged record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MemoryRecord {
    Run(TaskRun),
    Decision(TaskDecision),
    Command(TaskCommand),
    Failure(TaskFailure),
}

/// Task memory: append to and read from a JSONL file.
#[derive(Debug, Clone)]
pub struct TaskMemory {
    path: std::path::PathBuf,
    runs: Vec<TaskRun>,
    decisions: Vec<TaskDecision>,
    commands: Vec<TaskCommand>,
    failures: Vec<TaskFailure>,
}

impl TaskMemory {
    /// Opens the memory (starts empty if the file does not exist; the write
    /// directory is created).
    ///
    /// # Errors
    ///
    /// If the directory cannot be created or the file cannot be read.
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("could not create the memory directory: {e}"))?;
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
                .map_err(|e| format!("could not read the memory: {e}"))?;
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

    /// Appends a record to the file (append only).
    ///
    /// # Errors
    ///
    /// On a serialization or write error.
    pub fn append(&mut self, rec: MemoryRecord) -> Result<(), String> {
        // The system prompt promises that no key, token, password or private key
        // reaches an output, a cache or a log, and that masking happens before
        // storage rather than after. This file is the log, so the promise is
        // honoured here: the record is masked in the shape it is written in.
        // A clean record serializes exactly as it did before, so nothing about
        // the format moves for the ordinary case.
        //
        // The in-memory copy keeps what the caller handed over. That is not a
        // leak: the caller already holds those strings, and `relevant_runs`
        // scores them. What must not exist is the unmasked form on disk.
        let value =
            serde_json::to_value(&rec).map_err(|e| format!("could not encode the record: {e}"))?;
        let redacted = crate::redact::redact_model_strings(&value);
        let line = if redacted == value {
            serde_json::to_string(&rec).map_err(|e| format!("could not encode the record: {e}"))?
        } else {
            serde_json::to_string(&redacted)
                .map_err(|e| format!("could not encode the record: {e}"))?
        };
        let mut text = std::fs::read_to_string(&self.path).unwrap_or_default();
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&line);
        text.push('\n');
        std::fs::write(&self.path, text).map_err(|e| format!("could not write the memory: {e}"))?;
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

    /// Returns the `k` task runs most relevant to the query, by score.
    ///
    /// Score: query words appearing in `request`/`summary` (+2), the decision
    /// count (+1, at most 3) and whether a failure was resolved (+1).
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
                let mut matched = false;
                for w in &words {
                    if hay.contains(w) {
                        score += 2;
                        matched = true;
                    }
                }
                // Relevance gates the bonuses. They used to be added to every
                // run, so a run with one decision scored 1 and passed the
                // `score > 0` filter with no query word matching it at all:
                // an unrelated query returned the busiest runs rather than
                // nothing.
                if !matched {
                    return (0usize, r);
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
            request: "fix the erasure code".into(),
            summary: "the GF field bound was exceeded".into(),
            status: "done".into(),
            commit_hash: None,
            created_at: "2026-08-15".into(),
        }))
        .unwrap();
        mem.append(MemoryRecord::Decision(TaskDecision {
            task_id: "t1".into(),
            decision: "stay inside GF(2^8)".into(),
            rationale: None,
            created_at: "2026-08-15".into(),
        }))
        .unwrap();
        mem.append(MemoryRecord::Run(TaskRun {
            task_id: "t2".into(),
            request: "fix the bns record".into(),
            summary: "the length rule".into(),
            status: "done".into(),
            commit_hash: None,
            created_at: "2026-08-14".into(),
        }))
        .unwrap();
    }

    #[test]
    fn append_and_reopen_roundtrip() {
        let dir = std::env::temp_dir().join("ai_inference-mem-test");
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
        let dir = std::env::temp_dir().join("ai_inference-mem-test2");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("memory.jsonl");
        let mut mem = TaskMemory::open(&path).unwrap();
        sample_records(&mut mem);
        let rel = mem.relevant_runs("erasure code", 5);
        assert!(!rel.is_empty());
        assert_eq!(rel[0].task_id, "t1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_match_returns_empty() {
        let dir = std::env::temp_dir().join("ai_inference-mem-test3");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("memory.jsonl");
        let mut mem = TaskMemory::open(&path).unwrap();
        sample_records(&mut mem);
        assert!(mem.relevant_runs("a totally unrelated topic", 5).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_credential_in_an_appended_record_never_reaches_the_disk() {
        // The secret is assembled at run time so that no credential pattern
        // appears in the static source (a secret scan reads this file too).
        let secret = format!("sk-{}{}", "abcdefghijklmnopqrstuvwxyz", "123");
        let dir = std::env::temp_dir().join(format!(
            "ai_inference-memory-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let path = dir.join("memory.jsonl");
        let mut mem = TaskMemory::open(&path).unwrap();
        mem.append(MemoryRecord::Command(TaskCommand {
            task_id: "t1".into(),
            command: "cat /etc/app/env".into(),
            output: Some(format!("api_key: {secret}")),
            status: "ok".into(),
        }))
        .unwrap();
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            !on_disk.contains(&secret),
            "the credential was written verbatim"
        );
        assert!(
            on_disk.contains("<SECRET:MASKED>"),
            "nothing was masked: {on_disk}"
        );
        // The line still parses, so masking did not corrupt the format.
        let again = TaskMemory::open(&path).unwrap();
        assert_eq!(again.commands.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
