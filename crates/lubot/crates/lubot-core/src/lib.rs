// Unsafe kilidi: bu crate su an 0 unsafe. Bir `unsafe` blok girdigi an
// derleme FAIL eder (regresyon kapisi). Ana crate ile ayni politika.
#![forbid(unsafe_code)]
//! # lubot-core - çekirdek tipler
//!
//! Zincir üstü budlum katmanıyla eşleşen **ayna tipler** (K3 kararı):
//! yalnızca biçim aynalanır (32 bayt hash, kind enumları); izin kuralları
//! asla kopyalanmaz - zincirden sorgulanır. Ayrıntı:
//! `docs/MIMARI_ONERISI_2026-08-13.md` §6a.

pub mod dataset;
pub mod manifest;
pub mod model;
pub mod tier;
