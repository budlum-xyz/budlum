// Unsafe kilidi: bu crate su an 0 unsafe. Bir `unsafe` blok girdigi an
// derleme FAIL eder (regresyon kapisi). Ana crate ile ayni politika.
#![forbid(unsafe_code)]
//! # lubot-data - the closed-circuit data layer
//!
//! Lubot only reads data that carries a Pollen grant, is labelled as a B.U.D.
//! StorageDeal, or comes from SocialFi. This crate contains not a single path
//! that reads external data: even external datasets are recorded into B.U.D.
//! first.
//!
//! Deepening (2026-08-13): content verification is a real SHA-256; a mismatch
//! produces `HashMismatch` and no data flows.

pub mod jsonl;
pub mod source;
pub mod template;
pub mod verify;
