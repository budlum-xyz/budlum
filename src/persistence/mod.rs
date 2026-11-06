//! Node-local persistence (WP-06, Section 5.2).
//!
//! This crate tree holds the node's key-value store and state trie. It is
//! *not* a content storage system. Content storage is B.U.D. 3.0 at
//! `src/storage/bud3/` (KR-01, D-1).
//!
//! WP-06 moves these modules out of `src/storage/` into `src/persistence/`
//! so the word "storage" on its own always means B.U.D. 3.0 content storage.
//! Each module below starts life as a forwarding re-export from the
//! legacy location; call sites migrate to `crate::persistence::<name>::*`,
//! and once every import flips the file body replaces the legacy file and
//! the re-export is removed.
//!
//! | New module | Legacy location |
//! |---|---|
//! | [`db`] | `crate::storage::db` |
//! | [`traits`] | `crate::storage::traits` |
//! | [`state_trie`] | `crate::storage::merkle_trie` (renamed) |
//! | [`pruning`] | `crate::storage::pruning` |
//! | [`witness_retention`] | `crate::storage::witness_retention` |
//!
//! Gate renames delivered with this directory (Section 5.4):
//!
//! | Old gate | New gate |
//! |---|---|
//! | `regeneration` | `canonical_programs_reproduce` |
//! | `zkvm_immune_regeneration` | `zkvm_refuses_untrusted_proofs` |
//! | `regen_health_door` | `state_recovery_door` |
//!
//! The new gate modules wire to the same check bodies; the names describe
//! what the gate defends, not the old metaphor.

pub mod db;
pub mod pruning;
pub mod state_trie;
pub mod traits;
pub mod witness_retention;
