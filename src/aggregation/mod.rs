//! The aggregation layer: heavy objects stay off the chain, claims go on it.
//!
//! A post-quantum signature, a STARK proof or a polynomial opening is checked
//! once, off the chain. The chain stores a short [`claim::Claim`] that says the
//! object was valid, and one proof per block that covers every claim of the
//! block. This module holds the consensus-critical core of that design: the
//! claim and frame types, their canonical encodings and the digests that bind
//! them. Everything here is a pure function of its input, so a node, a light
//! client and the proving program compute the same bytes.
//!
//! The chain reaches the module through [`chain`]: block validation checks
//! the claims of a block there and block execution settles the claim fees.
//!
//! WIRING: the node side is not connected yet. Its doors are the two gossip
//! topics `agg/object` and `agg/frame` (into
//! [`aggregator::Aggregator::on_object`] and
//! [`aggregator::Aggregator::on_frame`]) and block production (out of
//! [`aggregator::Aggregator::block_frame`]). Until they open no node builds
//! a block that carries a frame; a node accepts one from a producer that
//! does.
//!
//! The hash `H` of every digest is Keccak-256, the hash of the `BudZKVM` STARK
//! configuration, so a digest computed by a node is the digest the proving
//! program computes.

pub mod aggregator;
pub mod backend;
pub mod block;
pub mod chain;
pub mod claim;
pub mod envelope;
pub mod fees;
pub mod frame;
pub mod hash;
pub mod merkle;
#[cfg(any(test, feature = "agg-native-backend"))]
pub mod native;
pub mod node;
pub mod object;
pub mod params;
pub mod pool;
pub mod schemes;

#[cfg(test)]
mod tests;
