//! B.U.D. 3.0 storage subsystem (Directive Section 6).
//!
//! Layout established in WP-10:
//! - `content_id`, `content_ref`, `tx`: live state/transaction boundary (WP-07 / WP-10)
//! - `limits`, `meter`, `varint`, `types`: genesis parameters, bounded codecs, and Section 6.2 vocabulary (WP-10)
//! - `bof1`, `object`, `segment`, `fountain`: object format and fountain coding (WP-18)
//! - `placement`, `custody`, `repair`, `maintenance`: deterministic placement, custody, and repair (WP-19..20)
//! - `volume`, `upload`, `dedup`: upload pipeline, dedup, and aggregation volumes (WP-21)
//! - `view`, `access_tiering`, `content_gateway`: logical/optical retrieval and gateway (WP-22)
//! - `refcount`, `delete`: reference counting and deletion (WP-23)
//! - `seal`, `keys`, `grants`: client-side sealing and capability grants (WP-24)
//! - `fees`, `rpc`: physical-byte fees and RPC endpoints (WP-25)

pub mod access_tiering;
pub mod bof1;
pub mod content_gateway;
pub mod content_id;
pub mod content_ref;
pub mod custody;
pub mod dedup;
pub mod delete;
pub mod fees;
pub mod fountain;
pub mod grants;
pub mod keys;
pub mod limits;
pub mod maintenance;
pub mod meter;
pub mod object;
pub mod placement;
pub mod refcount;
pub mod repair;
pub mod rpc;
pub mod seal;
pub mod segment;
pub mod tx;
pub mod types;
pub mod upload;
pub mod varint;
pub mod view;
pub mod volume;
