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
//! the content.
//!
//! WIRING: unwired - the content pipeline replaces the legacy storage modules
//! one door at a time. Upload, view and `StorageTx` v3 call into this tree
//! when the legacy storage code is removed; until then it is exercised by its
//! own tests and the golden vectors under `tests/vectors/bud3/`.

pub mod bof1;
pub mod content_id;
pub mod custody;
pub mod dedup_index;
pub mod fees;
pub mod fountain;
pub mod limits;
pub mod meter;
pub mod pipeline;
pub mod placement;
pub mod registry;
pub mod segment;
pub mod tx;
pub mod varint;

pub use bof1::{Bof1Error, Flags, Header, Object};
pub use content_id::{ContentId, ContentKey};
pub use fees::{
    custody_endowment_account, distribute_object_endowment_epoch, renewal_fee_epochs,
    replace_object_refund, same_owner_sealed_dedup_fee, shared_public_reference_fee_epochs,
    split_storage_fee, storage_fee_for_days, storage_fee_for_epochs, EpochCustodySettlement,
    FeeError, FeeParams, FeeRecord, FeeSplit, ObjectEndowment, ShareRewardInput,
};
pub use fountain::{
    encode_stream, FountainError, SegmentDecoder, SegmentEncoder, Symbol, SymbolKind,
};
pub use limits::{Bud3Limits, Profile, ProfileId};
pub use meter::{Meter, MeterError};
pub use segment::{object_commitment, segment_digest, ObjectCommitment, Segmentation};
