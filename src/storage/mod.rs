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
pub mod derived;
pub mod dictionary;
pub mod emit;
pub mod erasure;
pub mod fixed_point;
pub mod generated;
pub mod lifecycle;
pub mod living_threshold;
pub mod lrc;
pub mod manifest;
pub mod merkle_trie;
pub mod mobile_self;
pub mod msr;
pub mod payload_crypt;
pub mod provider;
pub mod pruning;
pub mod qr_carousel;
pub mod qr_codec;
pub mod qr_encode;
pub mod qr_frame;
pub mod qr_matrix;
pub mod qr_payload;
pub mod qr_png;
pub mod qr_receive;
pub mod qr_recipe;
pub mod qr_reemit;
pub mod qr_video;
pub mod render;
pub mod three_gate;
pub mod three_hooks;
pub mod three_meter;
pub mod three_nft;
pub mod three_pipe;
pub mod three_recipe;
pub mod three_reveal;
pub mod three_visibility;
pub mod traits;
pub mod transformed;
pub mod view_grant;

pub use assignment::{
    assign_object, assign_shard, displaced_shards, AssignmentError, ShardCandidate,
};
pub use content_id::{ContentId, DEFAULT_CHUNK_SIZE_BYTES};
pub use derived::{
    DerivedError, DerivedSpec, DerivedTransform, PrefixSpan, DERIVED_BLOCK_PIXELS,
    DERIVED_PREFIX_SPEC_BYTES, DERIVED_SPEC_BYTES,
};
pub use dictionary::{
    DictionaryEntry, DictionaryError, DictionaryRegistry, DICTIONARY_GRACE_EPOCHS,
    MAX_DICTIONARY_BYTES,
};
pub use erasure::{
    encode_object, reconstruct_object, verify_object_encoding, EncodedObject, ErasureError,
    ReedSolomon, MAX_TOTAL_SHARDS,
};
pub use generated::{
    generate_and_verify, generate_content, generated_spec_digest, held_bytes, is_three_recipe,
    recipe_seed_is_public, sealed_generated_commitment, BudStorageEdition, ContentSource,
    GenerateError, GeneratedSpec, GeneratorId, SealedGeneratedSpec, MAX_GENERATED_BYTES,
};
pub use lifecycle::{
    transition as transition_storage_lifecycle, StorageLifecycleError, StorageLifecycleState,
};
pub use living_threshold::{
    break_even_rate_scaled, decide, one_reproduction_picodollars, AccessEstimate, Decision, Lever,
    OperatorRates, ThresholdError, ACCESS_HALF_LIFE_EPOCHS, ACCESS_SCALE, HYSTERESIS_SIXTEENTHS,
    MAX_CPU_NANOS_PER_BYTE, MAX_OBJECT_BYTES, NANOS_PER_SECOND,
};
pub use lrc::{LrcError, LrcLayout, MAX_GROUP_SHARDS};
pub use manifest::{
    manifest_id_from_parts, manifest_id_from_parts_stored, manifest_id_from_shards, ContentCipher,
    ContentEncryption, ContentManifest, ErasureScheme, ShardKind, ShardRef,
    MIN_AEAD_CIPHERTEXT_BYTES,
};
pub use mobile_self::{
    MobileAvailabilityClass, MobileSelfContentPolicy, MobileSelfProfile, ReplicaRecommendation,
};
pub use msr::{
    lrc_repair_traffic_scaled, msr_repair_traffic_scaled, msr_speedup_over_lrc_scaled, MsrError,
    TRAFFIC_SCALE,
};
pub use provider::{
    provider_challenge_id, ChallengeId, DealId, InMemoryStorageProvider, ProviderChallengeResult,
    PutReceipt, StorageProof, StorageProvider, StorageProviderError,
};
pub use pruning::{NodeMode, PruningPolicy};
pub use render::{render, render_and_verify, RenderError, RenderFormat};

pub mod pact_binding;
pub use view_grant::{
    confidential_commit_digest, grant_issue_digest, grant_revoke_digest, ConfidentialBodyCommit,
    ConfidentialProofKind, GrantAuthError, GrantAuthorization, ViewGrant, ViewGrantError,
    ViewGrantRegistry, ViewPolicy,
};

pub use payload_crypt::{
    open_payload, seal_payload_csprng, PayloadKey, SealError, MAX_SEAL_PLAINTEXT,
    SEALED_HEADER_LEN, SEALED_MAGIC, SEALED_NONCE_LEN, SEALED_VERSION,
};
pub use qr_carousel::{
    oneshot_drop_count, planned_drop_count, CarouselDecoder, CarouselEncoder, CarouselError,
    CarouselParams, Drop, DEFAULT_BLOCK_LEN, DROP_HEADER_LEN, DROP_MAGIC, DROP_VERSION,
    MAX_CAROUSEL_BYTES, MAX_K, ONESHOT_REPAIR_PERMILLAGE,
};
pub use qr_frame::{
    fold_frame_digests, frame_digest, pack_frame, stream_id_prefix, unpack_frame, FrameError,
    MAX_DROP_WIRE, THREE_FRAME_HEADER_LEN, THREE_FRAME_MAGIC, THREE_FRAME_VERSION,
};
pub use qr_payload::{
    pack_payload, packed_is_zlib, payload_commitment, unpack_payload, PayloadError, PayloadKind,
    FLAG_ZLIB, MAX_PAYLOAD_CONTENT, THREE_PAYLOAD_HEADER_LEN, THREE_PAYLOAD_MAGIC,
    THREE_PAYLOAD_VERSION,
};
pub use qr_receive::{ProgressiveReceiver, ReceiveError};
pub use qr_recipe::{
    may_open_three_recipe, three_recipe_digest, three_sealed_recipe_commitment, ThreeRecipe,
    ThreeRecipePublic, ThreeRecipeSealed,
};
pub use qr_reemit::{RecipeEmitter, ReemitError};

pub use qr_codec::{gate_codec, split_raw_concat, CodecError, CodecKind, FrameMux, RawFrameConcat};
pub use three_pipe::{
    decode_frames, decode_qr_video, encode_plain, encode_qr_video, mux_raw, recipe_commitment,
    EncodedPipe, EncodedQrVideo, PipeError, PIPE_DEFAULT_BLOCK_LEN,
};
pub use transformed::{
    transform_content, CodecFlags, ContentClass, TransformError, TransformOpts, TransformedPayload,
    MAX_TRANSFORM_IN,
};

pub use three_nft::{meta_tracks_public_recipe, MetadataVisibility, PreviewMode, ThreeNftMeta};
pub use three_recipe::{
    encode_qr_video_internal, recipe_class, RecipeTransform, VideoRecipe, VideoRecipeError,
    VideoRecipeSealed, RECIPE_VIDEO_MAGIC,
};
pub use three_reveal::{RevealError, RevealSession};

pub use three_gate::{
    classify_three_blob, is_transport_derivative, refuse_durable_derivative, ThreeBlobKind,
};
pub use three_hooks::{
    emit_hook, NopThreeHook, RecordingThreeHook, ThreeEventHook, ThreeHookEvent, ThreeHookKind,
};
pub use three_meter::{MeterError, ThreeMeter};

pub use qr_matrix::{QrMatrix, QrMatrixError, MAX_QR_PAYLOAD, MODULE_PX, QUIET_ZONE, THREE_QR_EC};
pub use qr_png::{frame_to_qr_png, matrix_to_png, QrPngError};
pub use qr_video::{
    demux_optical_frames, png_to_optical_frame, QrVideo, QrVideoError, DEFAULT_FPS,
    MAX_VIDEO_FRAMES, VIDEO_MAGIC, VIDEO_VERSION,
};
pub use three_visibility::{
    delete_implies_key_rotate, policy_for_upload, recipe_for_upload, UploadVisibility,
};
