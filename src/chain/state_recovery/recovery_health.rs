//! Recovery health monitoring (WP-06 mechanical move, Section 5.2).
//!
//! Forwarding re-export of `crate::domain::regen_health` while call sites
//! migrate to `crate::chain::state_recovery::recovery_health::*`. The
//! "regeneration" metaphor is retired.

#[doc(inline)]
pub use crate::domain::regen_health::*;
