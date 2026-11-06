//! The execution coordinator and unified BUD accounting.
//!
//! WIRING: the block executor reaches the coordinator once stateful contract
//! calls and envelopes route through it; `bud_unit` is already wired into
//! [`crate::core::account::AccountState`].

pub mod bud_unit;
pub mod scheduler;
