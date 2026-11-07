//! Node-local persistence: the key-value store the node writes its chain
//! state to, the account proof trie over that state, and the pruning and
//! witness-retention policies that bound the on-disk footprint. This tree
//! is node state - accounts, blocks, proofs - and never user content.

pub mod db;
pub mod pruning;
pub mod state_trie;
pub mod traits;
pub mod witness_retention;
