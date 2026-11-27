//! An LLM output cache - a JSONL cache keyed by provider, model, task and
//! content digest. Records pass through the secret mask on their way out (the
//! closed-circuit principle).

use crate::redact::redact_model_strings;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::path::Path;

/// The schema version: when the format changes the keys change with it, so
/// stale records are not loaded.
pub const SCHEMA_VERSION: &str = "2026-08-15-v1";

/// Maximum cache file size loaded or written (16 MiB) to bound memory usage.
///
/// WIRING: Knowledge cache ceiling constant.
pub const MAX_CACHE_BYTES: u64 = 16 * 1024 * 1024;

/// Read a regular, non-symlink file into UTF-8 text up to `max_bytes`.
fn read_regular_file_bounded(path: &Path, max_bytes: u64) -> Result<Option<String>, String> {
    let lmeta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("the cache metadata could not be read: {e}")),
    };
    if lmeta.file_type().is_symlink() || !lmeta.file_type().is_file() {
        return Err(String::from(
            "the cache path must be a regular file, not a symlink or special file",
        ));
    }
    if lmeta.len() > max_bytes {
        return Err(format!(
            "the cache file exceeds the maximum allowed size ({} > {max_bytes} bytes)",
            lmeta.len()
        ));
    }
    let file =
        std::fs::File::open(path).map_err(|e| format!("the cache could not be read: {e}"))?;
    let fmeta = file
        .metadata()
        .map_err(|e| format!("the cache metadata could not be read: {e}"))?;
    if !fmeta.file_type().is_file() {
        return Err(String::from("the cache path is not a regular file"));
    }
    if fmeta.len() > max_bytes {
        return Err(format!(
            "the cache file exceeds the maximum allowed size ({} > {max_bytes} bytes)",
            fmeta.len()
        ));
    }
    let mut buf = Vec::new();
    let limit = max_bytes.saturating_add(1);
    file.take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| format!("the cache could not be read: {e}"))?;
    if (buf.len() as u64) > max_bytes {
        return Err(format!(
            "the cache file exceeds the maximum allowed size ({max_bytes} bytes)"
        ));
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|e| format!("the cache is not valid UTF-8: {e}"))
}

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

/// Escapes the key separator so two different part lists cannot join to the
/// same key.
fn escape_key_part(part: &str) -> String {
    part.replace('%', "%25").replace('|', "%7C")
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
        if enabled {
            if let Some(text) = read_regular_file_bounded(path, MAX_CACHE_BYTES)? {
                for line in text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(row) = serde_json::from_str::<CacheLine>(line) {
                        if row.key.starts_with(&format!("{SCHEMA_VERSION}|")) {
                            cache
                                .items
                                .insert(row.key, redact_model_strings(&row.parsed));
                        }
                    }
                }
            }
        }
        Ok(cache)
    }

    /// The cache key: version | provider | model | task | content digest.
    #[must_use]
    pub fn key(provider: &str, model: &str, task: &str, content_hash: &[u8; 32]) -> String {
        let h = content_hash.iter().fold(
            String::with_capacity(content_hash.len() * 2),
            |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            },
        );
        format!(
            "{SCHEMA_VERSION}|{}|{}|{}|{h}",
            escape_key_part(provider),
            escape_key_part(model),
            escape_key_part(task)
        )
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
        if (text.len() as u64) > MAX_CACHE_BYTES {
            return Err(format!(
                "the cache exceeds the maximum allowed size ({} > {MAX_CACHE_BYTES} bytes)",
                text.len()
            ));
        }
        match std::fs::symlink_metadata(&self.path) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.file_type().is_file() => {
                return Err(String::from(
                    "the cache target must be a regular file, not a symlink or special file",
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!("the cache target could not be inspected: {e}"));
            }
        }
        // Write beside the cache with create_new (O_CREAT|O_EXCL, never follows
        // symlinks) and owner-only 0600 permissions, then rename over it.
        let mut tmp_name = self.path.as_os_str().to_owned();
        tmp_name.push(".tmp");
        let tmp_path = std::path::PathBuf::from(tmp_name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut tmp_file = opts
            .open(&tmp_path)
            .map_err(|e| format!("the cache temp file could not be created: {e}"))?;
        if let Err(e) = tmp_file
            .write_all(text.as_bytes())
            .and_then(|()| tmp_file.flush())
        {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!("the cache could not be written: {e}"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if let Err(e) = tmp_file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(format!("the cache permissions could not be set: {e}"));
            }
        }
        drop(tmp_file);
        if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!("the cache could not be written: {e}"));
        }
        Ok(())
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
        std::env::temp_dir().join(format!("ai_inference-cache-{name}"))
    }

    #[test]
    fn key_parts_containing_the_separator_do_not_collide() {
        let h = [7u8; 32];
        assert_ne!(
            LlmCache::key("a|b", "c", "t", &h),
            LlmCache::key("a", "b|c", "t", &h)
        );
    }

    #[test]
    fn set_get_roundtrip() {
        let p = tmp_path("a.jsonl");
        let _ = std::fs::remove_file(&p);
        let mut c = LlmCache::open(&p, true).unwrap();
        let k = LlmCache::key("base", "v4", "entities", &[7u8; 32]);
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

    #[test]
    fn open_masks_preexisting_cache_entries() {
        let p = tmp_path("redaction.jsonl");
        let _ = std::fs::remove_file(&p);
        let k = LlmCache::key("m", "v", "t", &[9u8; 32]);
        let raw_secret = format!("ghp_{}", "0123456789abcdefghij0123456789");
        let raw_line = serde_json::json!({
            "key": k,
            "parsed": { "api_key": raw_secret },
        });
        std::fs::write(&p, format!("{raw_line}\n")).unwrap();
        let loaded = LlmCache::open(&p, true).unwrap();
        let got = loaded.get(&k).unwrap().to_string();
        assert!(!got.contains(&raw_secret), "{got}");
        assert!(got.contains(crate::redact::REDACTION_TOKEN), "{got}");
        let _ = std::fs::remove_file(&p);
    }

    #[cfg(unix)]
    #[test]
    fn ai01_cache_refuses_symlinks_oversize_and_sets_owner_only_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = std::env::temp_dir().join(format!(
            "ai_inference-cache-ai01-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // 1. Symlink cache path must be rejected on open AND save.
        let target = dir.join("victim.txt");
        std::fs::write(&target, "ORIGINAL_VICTIM_DATA").unwrap();
        let link = dir.join("cache-link.jsonl");
        symlink(&target, &link).unwrap();
        assert!(
            LlmCache::open(&link, true).is_err(),
            "open must reject symlink cache path"
        );

        // 2. Pre-planted <cache>.tmp symlink must NOT overwrite target on save.
        let cache_path = dir.join("normal.jsonl");
        let tmp_link = dir.join("normal.jsonl.tmp");
        symlink(&target, &tmp_link).unwrap();
        let mut cache = LlmCache::open(&cache_path, true).unwrap();
        let k = LlmCache::key("p", "m", "t", &[3u8; 32]);
        cache.set(k.clone(), serde_json::json!({"ok": true}));
        assert!(
            cache.save().is_err(),
            "save must refuse pre-planted .tmp symlink"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "ORIGINAL_VICTIM_DATA",
            "symlink target must never be clobbered"
        );
        let _ = std::fs::remove_file(&tmp_link);

        // 3. Clean save creates owner-only (0600) permissions.
        cache.save().unwrap();
        let mode = std::fs::metadata(&cache_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "cache file must not be group/world readable, got {:o}",
            mode
        );

        // 4. Oversized cache file (> 16 MiB) must be refused on open.
        let big = dir.join("oversized.jsonl");
        let f = std::fs::File::create(&big).unwrap();
        f.set_len(16 * 1024 * 1024 + 1).unwrap();
        drop(f);
        assert!(
            LlmCache::open(&big, true).is_err(),
            "open must refuse oversized cache files"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
