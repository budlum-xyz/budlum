// Unsafe lock: this crate is at 0 unsafe today. The moment an `unsafe`
// block enters, the build FAILS (regression gate). Same policy as the main crate.
#![forbid(unsafe_code)]
//! # ai-core - the core types
//!
//! **Mirror types** matching the on-chain budlum layer (the K3 decision): only
//! the shape is mirrored (32-byte hashes, the kind enums), and permission rules
//! are never copied - they are queried from the chain.

pub mod dataset;
pub mod manifest;
pub mod model;
pub mod system_prompt;
pub mod tier;
