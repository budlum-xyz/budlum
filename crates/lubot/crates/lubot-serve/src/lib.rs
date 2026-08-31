// Unsafe lock: this crate is at 0 unsafe today. The moment an `unsafe`
// block enters, the build FAILS (regression gate). Same policy as the main crate.
#![forbid(unsafe_code)]
//! # lubot-serve - the serving bridge skeleton
//!
//! The principle: weight files keep their original names, which is the
//! attribution policy; the name served over the API is the tier naming -
//! `lubot-light-v0.1` and `lubot-normal-v0.1`, with no multiplier labels. The
//! bridge connects to the OpenAI-compatible endpoint of vLLM or SGLang, and the
//! chain queries are a fail-closed draft.

pub mod bridge;
pub mod chain;
pub mod config;
pub mod health;
pub mod metric;
pub mod residency;
pub mod staging;
