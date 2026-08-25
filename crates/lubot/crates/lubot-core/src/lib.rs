// Unsafe kilidi: bu crate su an 0 unsafe. Bir `unsafe` blok girdigi an
// derleme FAIL eder (regresyon kapisi). Ana crate ile ayni politika.
#![forbid(unsafe_code)]
//! # lubot-core - the core types
//!
//! **Mirror types** matching the on-chain budlum layer (the K3 decision): only
//! the shape is mirrored (32-byte hashes, the kind enums), and permission rules
//! are never copied - they are queried from the chain. Details:
//! `docs/MIMARI_ONERISI_2026-08-13.md` §6a.

pub mod dataset;
pub mod manifest;
pub mod model;
pub mod tier;
