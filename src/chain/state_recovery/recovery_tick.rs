//! Periodic recovery-health tick driving the network layer (WP-06 mechanical move, Section 5.2).
//!
//! Forwarding re-export of `crate::network::regen_health_tick` while call
//! sites migrate to `crate::chain::state_recovery::recovery_tick::*`.

#[doc(inline)]
pub use crate::network::regen_health_tick::*;
