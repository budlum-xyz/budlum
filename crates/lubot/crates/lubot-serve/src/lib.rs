// Unsafe kilidi: bu crate su an 0 unsafe. Bir `unsafe` blok girdigi an
// derleme FAIL eder (regresyon kapisi). Ana crate ile ayni politika.
#![forbid(unsafe_code)]
//! # lubot-serve - serving köprüsü iskeleti
//!
//! İlke: ağırlık dosyaları orijinal adlarını korur (atıf politikası);
//! API'ye sunulan ad kademe adlandırmasıdır: `lubot-light-v0.1`,
//! `lubot-normal-v0.1` (çarpan etiketleri yok). Köprü a resident-batch engine/a resident-graph engine'in
//! a model vendor-uyumlu ucuna bağlanır; zincir sorguları fail-closed taslaktır.

pub mod chain;
pub mod config;
pub mod health;
