// Unsafe lock: this crate is at 0 unsafe today. The moment an `unsafe`
// block enters, the build FAILS (regression gate). Same policy as the main crate.
#![forbid(unsafe_code)]
//! # ai-tune - the fine-tuning orchestration skeleton
//!
//! Training runs in external containers, named by the operator in the run manifest;
//! this crate holds the plan, the dtype bounds, the schema validation and the
//! output hash lock. No shell code is hosted in the repository - the container
//! stage is only documented, and the run guides live outside this repository.

pub mod eval;
pub mod lock;
pub mod plan;
pub mod schema;
