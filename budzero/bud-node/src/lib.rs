//! B.U.D. (Broad Universal Database) — P2P Storage Node
//!
//! This crate implements the P2P storage backend for the B.U.D. network,
//! providing content-addressed storage, discovery via Kademlia DHT, and
//! a Bitswap-like block exchange protocol.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │              BudNode                     │
//! │                                          │
//! │  ┌─────────────┐  ┌──────────────────┐  │
//! │  │ ContentStore │  │ ContentDiscovery │  │
//! │  │ (store.rs)   │  │ (discovery.rs)   │  │
//! │  └──────┬───────┘  └────────┬─────────┘  │
//! │         │                    │            │
//! │  ┌──────┴────────────────────┴─────────┐  │
//! │  │         BudBitswap (bitswap.rs)     │  │
//! │  │    libp2p request-response codec    │  │
//! │  └─────────────────┬───────────────────┘  │
//! │                    │                      │
//! └────────────────────┼──────────────────────┘
//!                      │
//!              libp2p swarm (kad + noise + yamux)
//! ```
//!
//! # B.U.D. Vision Reference
//!
//! - `budlum-xyz/B.U.D./BUD_Merkeziyetsiz_Depolama_Vizyonu.md` §2 (mantık örtüşmesi)
//! - §7 (bugün kodda OLMAYANLAR — Bitswap, içerik routing)
//! - Görev 2 (içerik adresleme)

pub mod bitswap;
pub mod discovery;
pub mod sharding;
pub mod store;

pub use bitswap::BITSWAP_PROTOCOL_NAME;
pub use bitswap::{BitswapCodec, BitswapRequest, BitswapResponse, BudBitswap};
pub use discovery::ContentDiscovery;
pub use sharding::{ShardManager, ShardingConfig};
pub use store::{ContentStore, MemoryContentStore};
