//! Storage layer.
//!
//! Two intentionally separate namespaces live in `src/storage/`:
//!
//! * [`db`] / [`traits`] — the *node-local* key-value store (sled) that
//!   holds chain state, accounts, blocks, etc. Pre-existing, not touched
//!   by Phase 0.38.
//!
//! * [`content_id`] / [`manifest`] — the *B.U.D. on-chain content-addressing
//!   primitives* introduced by Phase 0.38 (Faz 2 + Phase 0.39 §2.1). These are
//!   pure data shapes — no I/O, no admin hooks, no team-server dependency
//!   (Phase 0.39 plan §0.5).
//!
//! The domain-level deal / challenge accounting lives in
//! `crate::domain::storage_deal::StorageRegistry` (kept under
//! `domain/` because the data shapes it owns are consensus types, not
//! transport types).

pub mod content_id;
pub mod db;
pub mod manifest;
pub mod merkle_trie;
pub mod mobile_self;
pub mod traits;

pub use content_id::{ContentId, DEFAULT_CHUNK_SIZE_BYTES};
pub use manifest::{manifest_id_from_shards, ContentManifest, ShardRef};
pub use mobile_self::{
    MobileAvailabilityClass, MobileSelfContentPolicy, MobileSelfProfile, ReplicaRecommendation,
};
