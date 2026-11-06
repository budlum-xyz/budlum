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
//! | [`registry`] | Chain state: objects, dedup, references, deletion, shares, audits |
//! | [`tx`] | `StorageTx` v3 and its one apply door |
//! | [`custody`] | Sub-block tree, symbol root, the audit draw and custody proofs |
//! | [`fees`] | Physical-byte storage fees, Custody Endowment, 95/5 split and epoch custody rewards |
//! | [`pipeline`] | Upload (content to record and symbols) and view (symbols to checked content) |
//! | [`fountain`] | RFC 6330 per-segment encoder and decoder, and the streaming encoder |
//!
//! The commitment is fixed-size (32 bytes). The object is not fixed-size: it
//! is the header plus the payload, and it is at most the header larger than
//! the content (or Padme bucket ceiling plus salt and AEAD tag when sealed).

pub mod bof1;
pub mod content_id;
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
pub mod qr;
pub mod registry;
pub mod repair;
pub mod seal;
pub mod segment;
pub mod symbol_protocol;
pub mod two_path;
pub mod tx;
pub mod varint;
pub mod video;

pub use bof1::{Bof1Error, Flags, Header, Object};
pub use content_id::{ContentId, ContentKey};
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
    prepare_public_upload, prepare_public_upload_two_path, prepare_sealed_upload, view_public,
    view_public_optical, view_sealed, ObjectRecord, PipelineError, PreparedUpload,
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
