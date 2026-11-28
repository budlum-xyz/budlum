//! Garden: a temporary, isolated Budlum network that people join with an
//! invite and use like a social room.
//!
//! One person creates a Garden and becomes its host. Everyone who joins is a
//! validator of the Garden chain. Messages, posts and images travel through
//! that chain, so a participant learns how a blockchain works by using one.
//!
//! # Shape
//!
//! * `types`: chain identifiers, genesis, transactions, headers, votes.
//! * `state`: the deterministic state machine every validator executes.
//! * `invite`: the invite link, which is also the QR content.
//! * `storage`: the node-local content store behind the storage seam.
//! * `net`: the dedicated libp2p swarm and the wire protocol.
//! * `settlement`: the link to Budlum's domain registry and `PoA` adapter.
//! * `node`: the validator runtime that proposes, executes and votes.
//! * `service`: the node-level entry point behind the `bud_garden*` RPC.
//!
//! The library API is [`GardenService`] with [`GardenOptions`]. Everything
//! else is private to this module tree.
//!
//! # Rules the code enforces
//!
//! * A Garden is a sovereign `PoA` domain with its own chain id and genesis.
//!   Garden transactions are refused on every primary Budlum chain id.
//! * The Garden chain has no stake, no fee, no reward and no validator class.
//! * A block is final when more than two thirds of its electorate signed it
//!   and the host is among the signers. The chain therefore runs exactly
//!   while the host is connected, and the host cannot finalize alone.
//! * State changes only inside finalized blocks.
//! * The validator votes sign Budlum's own `PoA` commit message, so a Garden
//!   finality certificate is a `FinalityProof::PoA` that the existing
//!   adapter verifies. No bridge is involved.
//! * Garden data lives as long as the Garden. A node that leaves wipes its
//!   own disk; when the last validator leaves nothing is left anywhere.

mod invite;
mod net;
mod node;
mod service;
mod settlement;
mod state;
mod storage;
#[cfg(test)]
mod testkit;
mod types;

pub use service::{GardenOptions, GardenService};
pub use settlement::closing_settlement_from_parts;
pub(crate) use types::{garden_domain_id, is_garden_domain_id, verify_garden_execution_chain};
