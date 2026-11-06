//! The execution coordinator, unified account/alias model, BUD unit
//! conversions, universal gas (`BGU`), nested overlays, block read cache,
//! deployment policy, and sparse-Merkle namespace state commitment.
//!
//! WIRING: `bud_unit` and `commitment` (including `accounts` alias/asset
//! derivations) are wired into [`crate::core::account::AccountState`];
//! `overlay`, `gas`, and `deploy_policy` power stateful contract execution.

pub mod accounts;
pub mod bud_unit;
pub mod commitment;
pub mod deploy_policy;
pub mod gas;
pub mod overlay;
pub mod scheduler;
