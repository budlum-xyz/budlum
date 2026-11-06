//! Mempool handling during state recovery (WP-06 mechanical move, Section 5.2).
//!
//! Forwarding re-export of `crate::domain::regen_mempool` while call sites
//! migrate to `crate::chain::state_recovery::recovery_mempool::*`.

#[doc(inline)]
pub use crate::domain::regen_mempool::*;
