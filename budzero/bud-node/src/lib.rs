// Unsafe lock: this crate is at 0 unsafe today. The moment an `unsafe` block
// enters, the build FAILs (a regression gate). The same policy as the main crate.
#![forbid(unsafe_code)]
//! B.U.D. (Broad Universal Database) - P2P Storage Node
//!
//! This crate implements the P2P storage backend for the B.U.D. network,
//! Providing content-addressed storage, discovery via Kademlia DHT, and
//! A Bitswap-like block exchange protocol.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │              BudNode │
//! │                                          │
//! │  ┌─────────────┐  ┌──────────────────┐  │
//! │  │ ContentStore │  │ ContentDiscovery │  │
//! │  │ (store.rs)   │  │ (discovery.rs)   │  │
//! │  └──────┬───────┘  └────────┬─────────┘  │
//! │         │                    │            │
//! │  ┌──────┴────────────────────┴─────────┐  │
//! │  │         BudBitswap (bitswap.rs)     │  │
//! │  │    libp2p request-response codec │  │
//! │  └─────────────────┬───────────────────┘  │
//! │                    │                      │
//! └────────────────────┼──────────────────────┘
//!                      │
//!              Libp2p swarm (kad + noise + yamux)
//! ```
//!
//! # B.U.D. Vision Reference
//!
//! - The B.U.D. decentralised storage vision, section 2 (a logical overlap)
//! - Section 7 (what is NOT in the code today - Bitswap, content routing)
//! - (content addressing)

pub mod bitswap;
pub mod discovery;
pub mod sharding;
pub mod store;

pub use bitswap::BITSWAP_PROTOCOL_NAME;
pub use bitswap::{BitswapCodec, BitswapRequest, BitswapResponse, BudBitswap};
pub use discovery::ContentDiscovery;
pub use sharding::{ShardManager, ShardingConfig};
pub use store::{ContentStore, MemoryContentStore};
