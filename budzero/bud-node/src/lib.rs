// Unsafe kilidi: bu crate su an 0 unsafe. Bir `unsafe` blok girdigi an
// derleme FAIL eder (regresyon kapisi). Ana crate ile ayni politika.
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
//! - B.U.D. merkeziyetsiz depolama vizyonu §2 (mantık örtüşmesi)
//! - §7 (bugün kodda OLMAYANLAR - Bitswap, içerik routing)
//! - (içerik adresleme)

pub mod bitswap;
pub mod discovery;
pub mod sharding;
pub mod store;

pub use bitswap::BITSWAP_PROTOCOL_NAME;
pub use bitswap::{BitswapCodec, BitswapRequest, BitswapResponse, BudBitswap};
pub use discovery::ContentDiscovery;
pub use sharding::{ShardManager, ShardingConfig};
pub use store::{ContentStore, MemoryContentStore};
