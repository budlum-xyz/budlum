//! B.U.D. — Broad Universal Database workspace boundary.
//!
//! Planned source ownership: content addressing, manifests, storage-domain
//! parameters and deal/challenge economics. Core durable block storage remains
//! in `budlum-core`; it is not a B.U.D. module.

pub mod content_id;
pub mod manifest;
pub use content_id::ContentId;
pub use manifest::{ContentManifest, ShardRef};
