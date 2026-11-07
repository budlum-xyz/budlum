//! Budlum mobile validator core (`budlum-mobile-core`).
//!
//! WP-11, 2/N. The production path is [`duty::MobileCore`]. A phone runs
//! custody duties without linking `budlum-core`. The validator class and the
//! presence message come from `crates/budlum-types`, the crate the node binds
//! too. Later slices add UniFFI, libp2p and the light client.

#![forbid(unsafe_code)]

pub mod custody;
pub mod duty;
pub mod error;
pub mod handover;
pub mod hash;
pub mod policy;
pub mod presence;
pub mod quota;
pub mod relay;
pub mod store;

pub use custody::{Audit, CustodyProof, CustodyProofBatch, ProofContext};
pub use duty::{Connection, CoreStatus, DutyTx, LastAudit, MobileCore, TESTNET_CHAIN_ID};
pub use error::CoreError;
pub use handover::{fetch_from_holders, Holder, ShareSource, SHARE_OWNER_TIMEOUT};
pub use policy::{NetworkPolicy, Policy, PowerPolicy};
pub use presence::{
    presence_message, presence_preimage, PresenceSignal, ResumeValidator, ValidatorClass,
    PRESENCE_DOMAIN_TAG, PRESENCE_TOPIC,
};
pub use quota::{FREE_SPACE_FLOOR_BYTES, QUOTA_DEFAULT_BYTES, QUOTA_MAX_BYTES, QUOTA_MIN_BYTES};
pub use relay::{RelayOffer, RelayPool};
pub use store::{AssignedShare, ShareId, ShareRecord, ShareStore};

