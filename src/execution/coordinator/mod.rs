//! The execution coordinator, unified account/alias model, BUD unit
//! conversions, and sparse-Merkle namespace state commitment.
//!
//! WIRING: `bud_unit` and `commitment` (including `accounts` alias/asset
//! derivations) are wired into [`crate::core::account::AccountState`]; the
//! block executor routes stateful contract execution through the coordinator.

pub mod accounts;
pub mod bud_unit;
pub mod commitment;
pub mod scheduler;
