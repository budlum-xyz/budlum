//! Node-local key/value database (WP-06 mechanical move, Section 5.2).
//!
//! This file is a forwarding re-export for the legacy `crate::storage::db`
//! module while WP-06 moves it to its permanent home under
//! `src/persistence/`. Call sites should migrate to
//! `crate::persistence::db::*`; once every import flips (and the same move
//! completes for `traits`, `state_trie`, `pruning`, `witness_retention`),
//! the body of this file replaces the legacy file and the re-export is
//! dropped. Content storage (B.U.D. 3.0) does NOT live here - see
//! `crate::storage::bud3` (KR-01, D-1).

#[doc(inline)]
pub use crate::storage::db::*;
