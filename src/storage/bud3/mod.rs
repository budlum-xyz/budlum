//! B.U.D. 3.0: the single content storage system.
//!
//! The pipeline is content -> payload (A0, the shortest complete
//! representation) -> BOF-1 object (A1) -> segments -> RFC 6330 symbols (A2).
//! The same symbols are the payloads of the optical QR frames and the custody
//! shares that validators hold. No validator holds a whole object.
//!
//! | Module | Content | Owning package |
//! |---|---|---|
//! | [`content_id`] | `ContentId`: SHA-256+len public, keyed HMAC-SHA-256+len sealed | İP-10 |
//! | [`limits`] | Profiles (P0) and the genesis limits (Section 6.21.1) | İP-10 |
//! | [`meter`] | Parser and decoder budget (Section 6.21.2) | İP-10 |
//! | [`varint`] | Bounded LEB128 | İP-10 |
//! | [`content_ref`] | `ContentRef` temporary interface; dependent modules use this until WP-21 lands (Section 5.7) | İP-07 |
//! | [`bof1`] | BOF-1 object: canonical binary header and payload | İP-19 |
//! | [`object`] | Object helpers (text format, round-trip, commitment helper) | İP-19 |
//! | [`segment`] | Segmentation, segment digests, object commitment | İP-18 |
//! | [`fountain`] | RFC 6330 per-segment encoder/decoder, streaming encoder | İP-18 |
//! | [`placement`] | Stake-weighted rendezvous placement, diversity caps, placement table | İP-20 |
//! | [`custody`] | Sub-block tree, symbol root, audit draw, custody proofs | İP-20 |
//! | [`repair`] | Lazy repair: repair task production, record repair, new-share Merkle roots | İP-20 |
//! | [`registry`] | Chain state: objects, dedup, references, deletion, shares, audits | İP-21 |
//! | [`dedup_index`] | Public dedup index, Bloom filter pre-filter (Section 6.8) | İP-22 |
//! | [`refcount`] | Reference counting for NFT/delta/derived dependencies (Section 6.8.2) | İP-22 |
//! | [`delete`] | Refcount → tombstone → physical share deletion (Section 6.8.3) | İP-22 |
//! | [`seal`] | Sealed-object encryption (XChaCha20-Poly1305), Padmé padding (Section 6.21.4) | İP-22 |
//! | [`keys`] | Content key derivation, HPKE key packages (X-Wing KEM, Section 6.21.5) | İP-22 |
//! | [`grants`] | View grants, revocation, `may_view` | İP-22 |
//! | [`volume`] | Aggregation volume: sub-symbol objects packed into one segment (Section 6.12) | İP-21 |
//! | [`upload`] | Upload session, append, finish; Y1-Y16 pipeline | İP-21 |
//! | [`view`] | Logical-path view, G1-G8, reveal/frames sessions | İP-21 |
//! | [`tx`] | `StorageTx` v3 and its one apply door | İP-21 |
//! | [`rpc`] | `bud_storage*` RPC method handlers (Section 6.22.2) | İP-21 |
//! | [`pipeline`] | Upload (content → record and symbols) and view (symbols → checked content) | İP-21 |
//! | [`fees`] | Physical-byte fee math, endowment accounting, BGU conversion (Section 6.18) | İP-25 |
//! | [`maintenance`] | Periodic maintenance: expiry, repair trigger, audit accounting | İP-25 |
//! | [`access_tiering`] | Hot/cold tiering policy (Section 6.14, closed at launch) | İP-24 |
//! | [`content_gateway`] | `/budlum/bud3/*` libp2p and HTTP gateway (Section 6.5, 6.11.3) | İP-23 |
//!\n//! Modules marked with a stub comment are added in the WP-10 skeleton and\n//! filled by their owning package. Until that package lands, any production\n//! call into the module must return [`ContentRefError::Bud3NotReady`].
//!
//! The commitment is fixed-size (32 bytes). The object is not fixed-size: it
//! is the header plus the payload, and it is at most the header larger than
//! the content.
//!
//! WIRING: unwired - the content pipeline replaces the legacy storage modules
//! one door at a time. Upload, view and `StorageTx` v3 call into this tree
//! when the legacy storage code is removed; until then it is exercised by its
//! own tests and the golden vectors under `tests/vectors/bud3/`.

pub mod access_tiering;
pub mod bof1;
pub mod content_gateway;
pub mod content_id;
pub mod content_ref;
pub mod custody;
pub mod dedup_index;
pub mod delete;
pub mod fees;
pub mod fountain;
pub mod grants;
pub mod keys;
pub mod limits;
pub mod maintenance;
pub mod meter;
pub mod object;
pub mod pipeline;
pub mod placement;
pub mod refcount;
pub mod registry;
pub mod repair;
pub mod rpc;
pub mod seal;
pub mod segment;
pub mod tx;
pub mod upload;
pub mod varint;
pub mod view;
pub mod volume;

pub use bof1::{Bof1Error, Flags, Header, Object};
pub use content_id::{ContentId, ContentKey};
pub use content_ref::{ContentRef, ContentRefError};
pub use fountain::{
    encode_stream, FountainError, SegmentDecoder, SegmentEncoder, Symbol, SymbolKind,
};
pub use limits::{Bud3Limits, Profile, ProfileId};
pub use meter::{Meter, MeterError};
pub use segment::{object_commitment, segment_digest, ObjectCommitment, Segmentation};
