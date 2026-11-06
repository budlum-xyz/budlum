//! The execution coordinator, unified account/alias model, BUD unit
//! conversions, universal gas (`BGU`), nested overlays, block read cache,
//! deployment policy, foreign transaction envelopes, stateful contract
//! execution, worker supervisor, and sparse-Merkle namespace state commitment.
//!
//! WIRING: `bud_unit` and `commitment` (including `accounts` alias/asset
//! derivations) are wired into [`crate::core::account::AccountState`];
//! `stateful_contract` is wired into [`crate::execution::executor`];
//! `worker_manager` drives [`crate::execution::ee`]; `foreign` implements the
//! Section 8.6.2 classical compatibility lane (`WP-27`).

pub mod accounts;
pub mod bud_unit;
pub mod commitment;
pub mod deploy_policy;
pub mod foreign;
pub mod gas;
pub mod overlay;
pub mod scheduler;
pub mod stateful_contract;
pub mod worker_manager;
