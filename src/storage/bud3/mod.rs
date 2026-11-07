//! B.U.D. 3.0: the single content storage system.
//!
//! The pipeline is content -> payload (A0, the shortest complete
//! representation) -> BOF-1 object (A1) -> segments -> RFC 6330 symbols (A2).
//! The same symbols are the payloads of the optical QR frames and the custody
//! shares that validators hold. No validator holds a whole object.
//!
//! | Module | Content |
//! |---|---|
//! | [`content_id`] | `ContentId`: SHA-256 and length for public content, keyed HMAC-SHA-256 and length for sealed content |
//! | [`limits`] | Profiles (P0) and the genesis limits |
//! | [`meter`] | The parser and decoder budget |
//! | [`varint`] | Bounded LEB128 |
//! | [`bof1`] | The BOF-1 object: canonical binary header and payload |
//! | [`segment`] | Segmentation, segment digests and the object commitment |
//! | [`placement`] | Stake-weighted rendezvous placement, diversity caps, the placement table |
//! | [`registry`] | Chain state: objects, dedup, references, deletion, shares, audits, object replacement |
//! | [`tx`] | `StorageTx` v3 and its one apply door |
//! | [`custody`] | Sub-block tree, symbol root, the audit draw and custody proofs |
//! | [`fees`] | Physical-byte storage fees, Custody Endowment, 95/5 split and epoch custody rewards |
//! | [`repair`] | Segment repair scheduling and Instant Duty Handover |
//! | [`pipeline`] | Upload (content to record and symbols) and view (symbols to checked content) |
//! | [`fountain`] | RFC 6330 per-segment encoder and decoder, and the streaming encoder |
//! | [`compression_context`] | Post-launch shared compression context, corpus rotation and access tiering |
//! | [`private_dedup`] | Post-launch threshold-OPRF private cross-owner deduplication |
//!
//! The commitment is fixed-size (32 bytes). The object is not fixed-size: it
//! is the header plus the payload, and it is at most the header larger than
//! the content (or Padme bucket ceiling plus salt and AEAD tag when sealed).
//!
//! Object replacement keeps the canonical attested transaction encoding. The
//! registry moves references at proposal, retains old shares until every new
//! share is acknowledged, and then keeps the old commitment as a redirect.

pub mod access_tiering;
pub mod bof1;
pub mod compression_context;
pub mod content_gateway;
pub mod content_id;
pub mod content_ref;
pub mod custody;
pub mod dedup_index;
pub mod delete;
pub mod fees;
pub mod fountain;
pub mod frame;
pub mod grants;
pub mod keys;
pub mod limits;
pub mod maintenance;
pub mod meter;
pub mod pipeline;
pub mod placement;
pub mod private_dedup;
pub mod qr;
pub mod registry;
pub mod repair;
pub mod replace;
pub mod rpc;
pub mod seal;
pub mod segment;
pub mod symbol_protocol;
pub mod two_path;
pub mod tx;
pub mod upload;
pub mod varint;
pub mod video;
pub mod view;
pub mod volume;

pub use access_tiering::{
    AccessTier, AccessTierTracker, TierTransition, COLD_DWELL_FOR_ARCHIVE_SECS,
    COLD_MAX_ACCESSES, COLD_WINDOW_SECS, HOT_MIN_ACCESSES, HOT_WINDOW_SECS,
};
pub use bof1::{Bof1Error, Flags, Header, Object};
pub use content_gateway::{Bud3ContentGateway, GatewaySymbolBundle};
pub use content_id::{ContentId, ContentKey};
pub use content_ref::{ContentRef, ContentRefError};
pub use delete::{
    check_same_owner_dependency, requires_rehydration_before_transfer, GrantShredAuth,
    ShredOutcome,
};
pub use fees::{
    custody_endowment_account, distribute_object_endowment_epoch, renewal_fee_epochs,
    replace_object_refund, same_owner_sealed_dedup_fee, shared_public_reference_fee_epochs,
    split_storage_fee, storage_fee_for_days, storage_fee_for_epochs, EpochCustodySettlement,
    FeeError, FeeParams, FeeRecord, FeeSplit, ObjectEndowment, ShareRewardInput,
};
pub use fountain::{
    encode_stream, FountainError, SegmentDecoder, SegmentEncoder, Symbol, SymbolKind,
};
pub use frame::{
    frames_for_object_bytes, Bud3Frame, FrameWireError, BUD3_FRAME_HEADER_LEN, BUD3_FRAME_MAGIC,
};
pub use grants::{compute_grant_tag, grant_revoke_digest, GrantBud3Error, GrantRow};
pub use keys::{
    content_key_from_random, derive_grant_one_time_keypair, derive_object_content_key,
    open_key_package, seal_key_package, sign_with_grant_one_time_key, ClientSealedDedupIndex,
    KeyPkgBud3Error, KEYPKG_PLAINTEXT_LEN,
};
pub use limits::{Bud3Limits, OpticalProfile, Profile, ProfileId};
pub use maintenance::{
    prioritize_shrink_repairs, select_reassignment_holders, Bud3StorageMetrics, SegmentRisk,
};
pub use meter::{Meter, MeterError};
pub use pipeline::{
    prepare_public_upload, prepare_public_upload_two_path, prepare_sealed_upload,
    prepare_volume_upload, view_public, view_public_optical, view_sealed, view_volume_bytes,
    view_volume_member, ObjectRecord, PipelineError, PreparedUpload, PreparedVolume, SmallObject,
    VolumeRecord,
};
pub use placement::{
    place, rank, segment_key, Candidate, Class, PlacementError, PlacementRow, PlacementTable,
    Share, MOBILE_SYMBOL_FLOOR_MILLI,
};
pub use qr::{
    frame_to_matrix, frame_to_png, png_to_frame, render_optical_seconds,
    render_p1_optical_seconds, Bud3QrError, OpticalSecond,
};
pub use repair::{
    assign_repairer, bad_repair_slash_amount, build_segment_repair, is_unseen_share_lost,
    repair_task_key, should_audit_repair_batch, verify_repaired_symbol, PreparedRepair,
    RepairError, BAD_REPAIR_SLASH_BPS, FULL_UNSEEN_LOSS_SECS, MOBILE_UNSEEN_LOSS_SECS,
    REPAIR_AUDIT_PPM, REPAIR_HANDOVER_BLOCKS,
};
pub use seal::{
    open_sealed_object, padme_padded_len, seal_object, SealBud3Error, MIN_SEALED_BUCKET_BYTES,
    SEAL_AUTH_TAG_LEN, SEAL_SALT_LEN,
};
pub use segment::{object_commitment, segment_digest, ObjectCommitment, Segmentation};
pub use symbol_protocol::{
    build_symbol_range_response, verify_symbol_range_response, CustodyPushMessage, LinkMetering,
    MobileServePolicy, SymbolPeerLimiter, SymbolProtocolError, SymbolRangeRequest,
    SymbolRangeResponse, VerifiedSymbolItem, CUSTODY_PROTOCOL_ID, MAX_CUSTODY_STREAMS_PER_PEER,
    MAX_STREAMS_PER_SHARE, MAX_SYMBOLS_PER_REQUEST, MAX_SYMBOL_REQUESTS_PER_SEC,
    SYMBOLS_PROTOCOL_ID,
};
pub use two_path::{
    decode_logical_path, decode_optical_path, extract_object_from_frames,
    extract_object_from_optical_seconds, verify_upload_two_path_and_round_trip, TwoPathError,
    VerifiedOpticalObject,
};
pub use video::{
    chain_segment_video_digests, fold_frame_digests, video_commitment,
    video_commitment_from_frames,
};
pub use replace::{
    admit_object_replacement, select_codec_with_fast_probe, PendingReplacementBarrier,
    ReplaceAttestation, ReplaceError, VerifiedCodecCandidate, FAST_PROBE_MIN_SAVINGS_BPS,
    GENERIC_ENTROPY_CEILING_MILLIBITS, MIN_REPLACE_ATTESTATIONS,
};
pub use rpc::{Bud3RpcService, BUD3_RPC_METHODS};
pub use upload::{
    admit_testnet_flags, deterministic_pixel_sample_indices, max_two_segment_memory_bytes,
    FinishedUploadSession, UploadError, UploadSessionManager, CLOSED_FLAG_BIT3,
    FULL_PIXEL_VERIFY_CEILING_BYTES, MAX_CONCURRENT_SESSIONS_PER_IP,
    MAX_DAILY_UPLOAD_BYTES_PER_ACCOUNT, MAX_GATEWAY_SESSIONS, MAX_OPEN_SESSIONS_PER_ACCOUNT,
    MAX_UPLOAD_SESSION_BYTES, UPLOAD_PROTOCOL_ID, UPLOAD_SESSION_TTL_SECS,
};
pub use view::{
    collect_symbols_full_then_mobile, fallback_decode_public, view_from_network,
    MemorySymbolNetwork, NetworkSymbolSource, PaidViewReceipt, RevealSessionManager,
    ViewBud3Error, MIN_PAID_VIEW_FEE_ATOMS,
};
pub use volume::{
    proof_for, root_of, verify_member, volume_id_of, AggregationVolume, Freed, PathStep, Removal,
    Visibility, VolumeError, VolumeMember, DEFAULT_VOLUME_BYTES, MAX_MEMBERS, MAX_PATH,
    RECODE_DEADLINE_SECS, VOLUME_TAG,
};
