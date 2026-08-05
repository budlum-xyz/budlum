//! Storage layer.
//!
//! Two intentionally separate namespaces live in `src/storage/`:
//!
//! * [`db`] / [`traits`] - the *node-local* key-value store (sled) that
//!   Holds chain state, accounts, blocks, etc. Pre-existing, not touched
//!   By the storage layer.
//!
//! * [`content_id`] / [`manifest`] - the *B.U.D. on-chain content-addressing
//!   Primitives* introduced. These are
//!   Pure data shapes - no I/O, no admin hooks, no team-server dependency
//!   (plan §0.5).
//!
//! The domain-level deal / challenge accounting lives in
//! `crate::domain::storage_deal::StorageRegistry` (kept under
//! `domain/` because the data shapes it owns are consensus types, not
//! Transport types).

pub mod assignment;
pub mod content_id;
pub mod db;
pub mod dictionary;
pub mod erasure;
pub mod generated;
pub mod lifecycle;
pub mod manifest;
pub mod merkle_trie;
pub mod mobile_self;
pub mod provider;
pub mod pruning;
pub mod traits;

pub use assignment::{
    assign_object, assign_shard, displaced_shards, AssignmentError, ShardCandidate,
};
pub use content_id::{ContentId, DEFAULT_CHUNK_SIZE_BYTES};
pub use dictionary::{
    DictionaryEntry, DictionaryError, DictionaryRegistry, DICTIONARY_GRACE_EPOCHS,
    MAX_DICTIONARY_BYTES,
};
pub use erasure::{
    encode_object, reconstruct_object, EncodedObject, ErasureError, ReedSolomon, MAX_TOTAL_SHARDS,
};
pub use generated::{
    generate, generate_and_verify, generated_spec_digest, ContentSource, GenerateError,
    GeneratedSpec, GeneratorId, MAX_GENERATED_BYTES,
};
pub use lifecycle::{
    transition as transition_storage_lifecycle, StorageLifecycleError, StorageLifecycleState,
};
pub use manifest::{
    manifest_id_from_parts, manifest_id_from_shards, ContentCipher, ContentEncryption,
    ContentManifest, ErasureScheme, ShardKind, ShardRef, MIN_AEAD_CIPHERTEXT_BYTES,
};
pub use mobile_self::{
    MobileAvailabilityClass, MobileSelfContentPolicy, MobileSelfProfile, ReplicaRecommendation,
};
pub use provider::{
    provider_challenge_id, ChallengeId, DealId, InMemoryStorageProvider, ProviderChallengeResult,
    PutReceipt, StorageProof, StorageProvider, StorageProviderError,
};
pub use pruning::{NodeMode, PruningPolicy};
