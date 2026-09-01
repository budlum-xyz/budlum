// Unsafe lock: this crate is at 0 unsafe today. The moment an `unsafe`
// block enters, the build FAILS (regression gate). Same policy as the main crate.
#![forbid(unsafe_code)]
// Panic lock: no integer indexing into slices or vectors. An operator-facing
// service that parses its own configuration must refuse malformed input, not
// panic on it; integer indexing is the panic surface this gate closes, the
// same way `unwrap`/`expect` are already denied on the production path.
#![deny(clippy::indexing_slicing)]
//! # agent-serve - the serving bridge skeleton
//!
//! The principle: weight files keep their original names, which is the
//! attribution policy; the name served over the API is the tier naming -
//! `agent-light-v0.1` and `agent-normal-v0.1`, with no multiplier labels. The
//! bridge connects to the OpenAI-compatible endpoint of vLLM or SGLang, and the
//! chain queries are a fail-closed draft.

pub mod bridge;
pub mod chain;
pub mod config;
pub mod cost_forecast;
pub mod fee_scenario;
pub mod health;
pub mod metric;
pub mod residency;
pub mod staging;
pub mod validator_cost;
