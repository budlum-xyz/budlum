// Unsafe lock: this crate is at 0 unsafe today. The moment an `unsafe`
// block enters, the build FAILS (regression gate). Same policy as the main crate.
#![forbid(unsafe_code)]
//! # ai-data - the closed-circuit data layer
//!
//! AI inference layer only reads data that carries a Pollen grant, is labelled as a B.U.D.
//! StorageDeal, or comes from SocialFi. This crate contains not a single path
//! that reads external data: even external datasets are recorded into B.U.D.
//! first.
//!
//! Content verification is a real SHA-256; a mismatch
//! produces `HashMismatch` and no data flows.

pub mod jsonl;
pub mod source;
pub mod template;
pub mod verify;
