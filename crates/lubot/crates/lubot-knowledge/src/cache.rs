//! An LLM output cache - a JSONL cache keyed by provider, model, task and
//! content digest. Records pass through the secret mask on their way out (the
//! closed-circuit principle).

use crate::redact::redact_model_strings;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// The schema version: when the format changes the keys change with it, so
/// stale records are not loaded.
pub const SCHEMA_VERSION: &str = "2026-08-15-v1";

/// One cache line.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheLine {
    key: String,
    parsed: serde_json::Value,
}

/// An LLM output cache keyed by content digest.
#[derive(Debug, Clone)]
pub struct LlmCache {
    path: std::path::PathBuf,
    enabled: bool,
    items: BTreeMap<String, serde_json::Value>,
}

impl LlmCache {
    /// Opens the cache.
    ///
    /// # Errors
    ///
    /// When the directory cannot be created or the file cannot be read.
    pub fn open(path: &Path, enabled: bool) -> Result<Self, String> {
        if enabled {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("the cache directory could not be created: {e}"))?;
            }
        }
        let mut cache = Self {
            path: path.to_path_buf(),
            enabled,
            items: BTreeMap::new(),
        };
        if enabled && path.exists() {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("the cache could not be read: {e}"))?;
            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(row) = serde_json::from_str::<CacheLine>(line) {
                    if row.key.starts_with(&format!("{SCHEMA_VERSION}|")) {
                        cache.items.insert(row.key, row.parsed);
                    }
                }
            }
        }
        Ok(cache)
    }

    /// The cache key: version | provider | model | task | content digest.
    #[must_use]
    pub fn key(provider: &str, model: &str, task: &str, content_hash: &[u8; 32]) -> String {
        let h = content_hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        format!("{SCHEMA_VERSION}|{provider}|{model}|{task}|{h}")
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        if !self.enabled {
            return None;
        }
        self.items.get(key)
    }

    /// Stores the value in masked form.
    pub fn set(&mut self, key: String, parsed: serde_json::Value) {
        if !self.enabled {
            return;
        }
        let redacted = redact_model_strings(&parsed);
        self.items.insert(key, redacted);
    }

    /// Writes the cache to disk (JSONL, sorted by key).
    ///
    /// # Errors
    ///
    /// On a write failure.
    pub fn save(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("the cache directory could not be created: {e}"))?;
        }
        let mut text = String::new();
        for (key, parsed) in &self.items {
            let line = CacheLine {
                key: key.clone(),
                parsed: parsed.clone(),
            };
            let json = serde_json::to_string(&line)
                .map_err(|e| format!("the cache line could not be encoded: {e}"))?;
            text.push_str(&json);
            text.push('\n');
        }
        std::fs::write(&self.path, text).map_err(|e| format!("the cache could not be written: {e}"))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("lubot-cache-{name}"))
    }

    #[test]
    fn set_get_roundtrip() {
        let p = tmp_path("a.jsonl");
        let _ = std::fs::remove_file(&p);
        let mut c = LlmCache::open(&p, true).unwrap();
        let k = LlmCache::key("upstream", "v4", "entities", &[7u8; 32]);
        c.set(k.clone(), serde_json::json!({"ok": true}));
        c.save().unwrap();
        drop(c);
        let c2 = LlmCache::open(&p, true).unwrap();
        assert_eq!(c2.get(&k), Some(&serde_json::json!({"ok": true})));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn disabled_cache_returns_none() {
        let c = LlmCache::open(&tmp_path("b.jsonl"), false).unwrap();
        assert_eq!(c.get(&LlmCache::key("x", "y", "z", &[0u8; 32])), None);
    }

    #[test]
    fn set_redacts_secrets() {
        let p = tmp_path("c.jsonl");
        let _ = std::fs::remove_file(&p);
        let mut c = LlmCache::open(&p, true).unwrap();
        let k = LlmCache::key("m", "v", "t", &[1u8; 32]);
        let secret = format!("sk-{}", "abcdefghijklmnopqrstuvwxyz123");
        c.set(k.clone(), serde_json::json!({"api_key": secret}));
        c.save().unwrap();
        let c2 = LlmCache::open(&p, true).unwrap();
        let val = c2.get(&k).unwrap();
        let secret = format!("sk-{}", "abcdefghijklmnopqrstuvwxyz123");
        assert!(!val.to_string().contains(&secret));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn schema_version_filters_stale() {
        let p = tmp_path("d.jsonl");
        let _ = std::fs::remove_file(&p);
        // Write a line keyed with an old version.
        std::fs::write(&p, r#"{"key":"old|m|v|t|h","parsed":{"x":1}}"#).unwrap();
        let c = LlmCache::open(&p, true).unwrap();
        assert!(c.is_empty());
        let _ = std::fs::remove_file(&p);
    }
}
