//! Node state recovery (WP-06, Section 5.2).
//!
//! When a node falls behind, suffers data loss, or boots from a snapshot,
//! state recovery is the subsystem that brings it back into consensus.
//!
//! This directory replaces the legacy "regeneration" metaphor (previously
//! named after a biologically immortal jellyfish). WP-06 moves the relevant
//! files from `src/domain/` and
//! `src/network/` into this directory and renames the symbols:
//!
//! | New module / symbol | Legacy location |
//! |---|---|
//! | [`recovery_ledger`] / `RecoveryLedger` | `crate::domain::regeneration_stage` / `RegenerationLedger` |
//! | [`recovery_health`] / `recovery_stage` | `crate::domain::regen_health` |
//! | [`recovery_mempool`] | `crate::domain::regen_mempool` |
//! | [`recovery_tick`] | `crate::network::regen_health_tick` |
//!
//! Each module starts life as a forwarding re-export; call sites migrate
//! to `crate::chain::state_recovery::<name>::*`, and once every import
//! flips the file body replaces the legacy file and the re-export is
//! dropped. The legacy names are dropped at that point as well.
//!
//! Gate `state_recovery_door` (renamed from `regen_health_door`) stays
//! responsible for the health-layer invariants.

pub mod recovery_health;
pub mod recovery_ledger;
pub mod recovery_mempool;
pub mod recovery_tick;
