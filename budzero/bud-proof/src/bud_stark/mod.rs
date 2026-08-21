//! A minimal univariate STARK framework.
//!
//! Derived from the Plonky3 `p3-uni-stark` crate
//! (<https://github.com/Plonky3/Plonky3>), licensed `MIT OR Apache-2.0`.
//! Copyright the Plonky3 contributors.
//!
//! This is a fork carrying local modifications rather than an independent
//! implementation: the module layout matches upstream and roughly two thirds
//! of the prover and verifier lines are shared with `p3-uni-stark 0.6.2`.
//! Recorded here because Apache-2.0 requires attribution to travel with a
//! derivative work, and because a reader comparing this code against the
//! upstream deserves to know it is looking at a fork.
//!
//! Local changes concentrate in `folder.rs` (constraint folding for the Budlum
//! VM AIR) and in the proof/config types; see `PROVENANCE_NOTES.md` at the
//! repository root for the measurement this claim rests on.

extern crate alloc;

mod config;
mod folder;
mod preprocessed;
mod proof;
mod prover;
mod sub_builder;
mod symbolic;
mod verifier;

pub use config::*;
pub use folder::*;
pub use p3_air::symbolic::*;
pub use preprocessed::*;
pub use proof::*;
pub use prover::*;
pub use sub_builder::*;
pub use symbolic::*;
pub use verifier::*;
