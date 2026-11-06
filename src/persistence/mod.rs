//! Node-local persistence (WP-06, Section 5.2).
//!
//! This crate tree holds the node's key-value store and state trie. It is
//! *not* a content storage system. Content storage is B.U.D. 3.0 at
//! `src/storage/bud3/` (KR-01, D-1). Re-exports of the legacy `storage::db`
//! items live here while the mechanical move in WP-06 lands; once WP-06
//! merges, files `src/storage/{db,traits,merkle_trie,pruning,witness_retention}.rs`
//! and the state-recovery modules move under this directory and the
//! re-exports are removed.
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

// Persistence is a directory module. The mechanical move in WP-06 fills this
// tree with `db.rs`, `traits.rs`, `state_trie.rs` (ex-`merkle_trie.rs`),
// `pruning.rs`, and `witness_retention.rs`; state recovery moves to
// `src/chain/state_recovery/`. Until then the module is intentionally
// empty so call sites can start referencing `crate::persistence::` without
// pulling the legacy storage tree into scope.
