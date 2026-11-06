//! Witness retention window for light-client proof serving. (WP-06 mechanical move, Section 5.2).
//!
//! Forwarding re-export while WP-06 moves this module from
//! `crate::storage::witness_retention` to its permanent home under
//! `src/persistence/`. Call sites migrate to
//! `crate::persistence::witness_retention::*`; after all imports flip the file
//! body replaces the legacy file and the re-export is removed. Content
//! storage (B.U.D. 3.0) does NOT live here - see `crate::storage::bud3`.

#[doc(inline)]
pub use crate::storage::witness_retention::*;
