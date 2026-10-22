//! The F10 EVM ChainAdapter - the Universal Relayer's real Ethereum bridge.
//!
//! This group of modules gives Budlum the ability to verify the Ethereum
//! receipt proofs produced by the relayer **independently** and
//! cryptographically:
//!
//! - `rlp` - in-tree Recursive Length Prefix (Ethereum Yellow Paper Appendix B).
//! - `mpt` - in-tree Merkle-Patricia trie **verifier** (Appendix D, verify-only;
//!   the proof itself is produced by the relayer).
//! - `receipt` - Ethereum receipt RLP schema + receiptsRoot proof.
//! - `sync_committee` - PoS light-client (BLS12-381, `blst` reuse).
//! - `header` - the Ethereum header chain and the finality decision.
//! - `adapter` - `EvmChainAdapter` (ChainAdapter impl).
//!
//! **Security invariant:** no function here touches the network. All
//! verification is deterministic and happens on chain, inside Budlum consensus.
//! The relayer produces the proof and Budlum verifies it - the
//! `relayer_produces` trust model.
//!
//! The base layer is RLP, the MPT verifier and the KAT vectors; receipt, header
//! and sync-committee verification are built on top of it.

pub mod adapter;
pub mod bud_to_eth;
pub mod header;
pub mod mpt;
pub mod receipt;
pub mod rlp;
pub mod sync_committee;
pub mod verify;
