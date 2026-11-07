//! B.U.D. 3.0 storage subsystem.
//!
//! At Milestone M1 (`WP-07`) this module exposes [`content_id::ContentId`],
//! [`content_ref::ContentRef`], and the signed [`tx::StorageTx`] refusal door.
//! Object container, segmentation, RaptorQ symbols, QR framing, placement,
//! audits, and fee settlement land in `WP-18..24`.

pub mod content_id;
pub mod content_ref;
pub mod tx;

pub use content_id::ContentId;
pub use content_ref::{register_content, ContentOwnershipBook, ContentRef, StorageError};
pub use tx::StorageTx;
