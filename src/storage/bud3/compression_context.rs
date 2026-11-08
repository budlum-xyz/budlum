//! Shared compression context implementations.
//!
//! `committed` retains the existing committed-manifest/local-cache API and
//! fee/rotation engine. `corpus` preserves the source branch's corpus frame,
//! activation and access-observation model without replacing that API. Both
//! remain closed on testnet until their independent activation gates open.

pub mod committed;
pub mod corpus;

pub use committed::{
    compute_context_savings_fee, decode_with_shared_context, encode_with_shared_context,
    ContextError, ContextMaintenancePool, ContextManifest, DependentContextObject,
    LocalContextCache, SharedContextEngine, ARCHIVAL_CTX_SAVINGS_FLOOR_BPS,
    CODEC_SHARED_CTX_ARCHIVAL, CODEC_SHARED_CTX_FAST, CONTEXT_SAVINGS_FEE_SHARE_BPS,
    TESTNET_CONTEXT_ENABLED_BY_DEFAULT,
};
pub use corpus::{
    decode_with_context, encode_with_context, AccessObservation, AccessTierPolicy,
    ContentStoredReceipt, ContextActivation, ContextEncodedPayload, ContextState,
    ContextStoredObject, CorpusEntry, ACTIVATION, CODEC_LZ_CONTEXT, COLD_DWELL_SECS,
    COLD_WINDOW_SECS, HOT_WINDOW_SECS, CONTEXT_FRAME_MAGIC,
    CONTEXT_MANIFEST_TAG, MAX_CONTEXT_DICTIONARY_BYTES,
};
pub use corpus::{
    AccessTier as CorpusAccessTier, ContextError as CorpusContextError,
    ContextManifest as CorpusContextManifest,
};
