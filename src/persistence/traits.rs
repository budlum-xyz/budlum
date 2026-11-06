//! Storage and block-database traits (`BlockchainStorage`, `DurableCommitBatch`, `SeenBlockMap`).
//!
//! WP-06 mechanical move (Section 5.2): this is a forwarding re-export from
//! the legacy `crate::storage::traits` module while call sites migrate to
//! `crate::persistence::traits::*`. Once every import flips, the body of
//! this file replaces the legacy file and the re-export is dropped.
//!
//! Content storage (B.U.D. 3.0) does NOT live here - see
//! `crate::storage::bud3` (KR-01, D-1).

#[doc(inline)]
pub use crate::storage::traits::*;
