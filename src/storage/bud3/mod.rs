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
//! | [`admission`] | The production admission report: limits, placement, segmentation and the sealed id rule |
//! | [`meter`] | The parser and decoder budget |
//! | [`varint`] | Bounded LEB128 |
//! | [`bof1`] | The BOF-1 object: canonical binary header and payload |
//! | [`segment`] | Segmentation, segment digests and the object commitment |
//! | [`placement`] | Stake-weighted rendezvous placement, diversity caps, the placement table |
//! | [`registry`] | Chain state: objects, dedup, references, deletion, shares, audits |
//! | [`repair`] | Repair assignment, the 1% verification draw and the bad-repair report |
//! | [`tx`] | `StorageTx` v3 and its one apply door |
//! | [`volume`] | Aggregation volumes: small objects share one placed segment |
//! | [`custody`] | Sub-block tree, symbol root, the audit draw and custody proofs |
//! | [`pipeline`] | Upload (content to record and symbols) and view (symbols to checked content) |
//! | [`fountain`] | RFC 6330 per-segment encoder and decoder, and the streaming encoder |
//! | [`live`] | Live stream T-Expansion: time segments, the `prev_object` chain, the ratioless send order |
//! | [`live_broadcast`] | WP-55 2/N: the broadcast driver, the gateway door and the activation height |
//! | [`types`] | The section 6.2 vocabulary as values: `Frame`, `QrVideo`, `CustodyShare`, `PlacementGroup`, `RefCount`, `AggregationVolume`, the logical and optical paths |
//!
//! The commitment is fixed-size (32 bytes). The object is not fixed-size: it
//! is the header plus the payload, and it is at most the header larger than
//! the content.
//!
//! WIRING: unwired - the content pipeline replaces the legacy storage modules
//! one door at a time. Upload, view and `StorageTx` v3 call into this tree
//! when the legacy storage code is removed; until then it is exercised by its
//! own tests and the golden vectors under `tests/vectors/bud3/`.

pub mod admission;
pub mod bof1;
pub mod content_id;
pub mod content_ref;
pub mod custody;
pub mod dedup_index;
pub mod fountain;
pub mod grants;
pub mod limits;
pub mod live;
pub mod live_broadcast;
pub mod meter;
pub mod pipeline;
pub mod placement;
pub mod registry;
pub mod repair;
pub mod segment;
pub mod tx;
pub mod types;
pub mod varint;
pub mod volume;
pub mod view;

pub use bof1::{Bof1Error, Flags, Header, Object};
pub use content_id::{ContentId, ContentKey};
pub use fountain::{
    encode_stream, FountainError, SegmentDecoder, SegmentEncoder, Symbol, SymbolKind,
};
pub use admission::chain_admission_report;
pub use limits::{Bud3Limits, Profile, ProfileId};
pub use live::{
    verify_chain, LiveActivation, LiveContext, LiveError, LiveFrame, LiveSegment, LiveStream,
    RatiolessPlan, StreamEnd, ViewerTicket, ACTIVATION, LIVE_SEGMENT_MS, MAX_JOIN_LATENCY_MS,
};
pub use live_broadcast::{
    BroadcastDriver, BroadcastError, LiveGateway, LiveGatewayRefusal, MAX_LIVE_PENDING_SYMBOLS,
    MAX_LIVE_SUBSCRIBERS,
};
pub use meter::{Meter, MeterError};
pub use segment::{object_commitment, segment_digest, ObjectCommitment, Segmentation};
pub use types::{
    AggregationVolume, CustodyShare, Frame, LogicalPath, OpticalPath, Path, Payload,
    PlacementGroup, QrVideo, RefCount, RepairSymbol, SourceSymbol,
};

pub use volume::{AggregationVolume as PlacedAggregationVolume, Visibility, VolumeError, VolumeMember};
