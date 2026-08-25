// Unsafe lock: this crate is at 0 unsafe today. The moment an `unsafe`
// block enters, the build FAILS (regression gate). Same policy as the main crate.
#![forbid(unsafe_code)]
//! # lubot-knowledge - the closed-circuit knowledge layer
//!
//! Produces knowledge from source code and documents while keeping Lubot's
//! closed-circuit principle: secret masking (`redact`), line-ranged chunking
//! (`chunk`), dependency-free TF-IDF embedding (`embed`), a compact context
//! table (`context`), task memory (`memory`) and an LLM output cache
//! (`cache`).
//!
//! Every module carries only `std`, `serde` and `sha2`; there is no external
//! vector API and no cloud service. The data stays in the JSONL and SQLite
//! files this crate produces and in Lubot's own B.U.D. records.

pub mod cache;
pub mod chunk;
pub mod context;
pub mod embed;
pub mod memory;
pub mod redact;

/// A stable SHA-256 digest of the content.
///
/// # Errors
///
/// Only on a SHA-256 initialisation failure, which cannot happen in practice.
pub fn content_hash(data: &[u8]) -> Result<[u8; 32], String> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    Ok(h.finalize().into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn hash_is_stable_and_distinct() {
        let a = super::content_hash(b"budlum").unwrap();
        let b = super::content_hash(b"budlum").unwrap();
        let c = super::content_hash(b"budlun").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
