// Unsafe lock: this crate is at 0 unsafe today. The moment an `unsafe`
// block enters, the build FAILS (regression gate). Same policy as the main crate.
#![forbid(unsafe_code)]
//! # lubot-tune - ince ayar orkestrasyonu iskeleti
//!
//! Training runs in external containers (LLaMA-Factory, Axolotl, Unsloth);
//! this crate holds the plan, the dtype bounds, the schema validation and the
//! output hash lock. No shell code is hosted in the repository - the container
//! stage is only documented, and the run guides live outside this repository
//! (on the `lubot-kosu-2026-08-13` branch).

pub mod eval;
pub mod lock;
pub mod plan;
pub mod schema;
