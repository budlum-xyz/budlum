//! Historical state pruning: keeping only the witness window required by the chain. (WP-06 mechanical move, Section 5.2).
//!
//! Forwarding re-export while WP-06 moves this module from
//! `crate::storage::pruning` to its permanent home under
//! `src/persistence/`. Call sites migrate to
//! `crate::persistence::pruning::*`; after all imports flip the file
//! body replaces the legacy file and the re-export is removed. Content
//! storage (B.U.D. 3.0) does NOT live here - see `crate::storage::bud3`.

#[doc(inline)]
pub use crate::storage::pruning::*;
