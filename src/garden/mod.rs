//! Garden: isolated, temporary PoA sovereign domain for collaborative rooms
//! (messages, posts, and B.U.D. 3.0-aligned ephemeral media storage).
//!
//! Garden leaves Budlum's primary chain consensus untouched and explicitly
//! refuses Garden transactions on Budlum Mainnet (45260), Testnet (45261),
//! and Devnet (45262).

pub mod consensus;
pub mod invite;
pub mod liveness;
pub mod node;
pub mod service;
pub mod settlement;
pub mod storage;
pub mod types;

pub use consensus::GardenChainState;
pub use invite::GardenInvitePayload;
pub use liveness::{GardenLivenessState, GardenPresenceSignal};
pub use node::{
    GardenNode, GardenNodeClient, GardenNodeServer, GardenPeerRequest, GardenPeerResponse,
    GardenStatusSnapshot,
};
pub use service::GardenService;
pub use settlement::GardenBudlumSettlement;
pub use storage::{GardenContentStore, GardenStoredObject};
pub use types::{
    is_primary_budlum_chain, verify_garden_execution_chain, GardenBlock, GardenChainId,
    GardenContentKind, GardenGenesis, GardenImageRecord, GardenLimits, GardenMessageRecord,
    GardenPlacementTable, GardenPostRecord, GardenTrace, GardenTx, GardenTxKind,
    GardenValidatorEntry, GardenVote, SignedGardenTx,
};
