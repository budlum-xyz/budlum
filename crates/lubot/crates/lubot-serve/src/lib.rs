//! # lubot-serve - serving köprüsü iskeleti
//!
//! İlke: ağırlık dosyaları orijinal adlarını korur (atıf politikası);
//! API'ye sunulan ad kademe adlandırmasıdır: `lubot-light-v0.1`,
//! `lubot-normal-v0.1` (çarpan etiketleri yok). Köprü vLLM/SGLang'in
//! OpenAI-uyumlu ucuna bağlanır; zincir sorguları fail-closed taslaktır.

pub mod chain;
pub mod config;
pub mod health;
