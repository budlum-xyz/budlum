//! Node state recovery (WP-06, Section 5.2).
//!
//! The files `src/domain/{regeneration_stage,regen_health,regen_mempool}.rs`
//! and `src/network/regen_health_tick.rs` move here during the mechanical
//! WP-06 persistence move. The old `Regeneration` / "Turritopsis" metaphor
//! is replaced with the professional term `state_recovery`:
//!
//! | Old name | New name |
//! |---|---|
//! | `RegenerationLedger` | `RecoveryLedger` |
//! | `regeneration_stage` | `recovery_stage` |
//! | `regen_health` | `recovery_health` |
//! | `regen_mempool` | `recovery_mempool` |
//!
//! This module starts empty so the directory exists and call sites can be
//! migrated one at a time. WP-06 moves the files behaviour-neutrally and
//! the gate `state_recovery_door` (renamed from `regen_health_door`) stays
//! responsible for the health-layer invariants.
