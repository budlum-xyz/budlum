//! Length-prefixed SHA-256, the same rule as `src/core/hash.rs`.
//!
//! A field is eight little-endian length bytes, then the field. Concatenating
//! without lengths would let two different field splits hash the same way.

use sha2::{Digest, Sha256};

/// Hash `fields` with a length prefix on every field.
#[must_use]
pub fn hash_fields_bytes(fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// SHA-256 of `bytes` with no field split.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
