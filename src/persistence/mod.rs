//! Node-local persistence: the key-value store, its storage traits, the
//! proof-bearing state trie, pruning policy and block witness retention.
//!
//! This is not content storage. Content lives in `crate::storage::bud3`;
//! this tree holds the node's own chain state on its own disk: accounts,
//! blocks, headers and the indexes a restart needs. The separation is the
//! point: a content identifier never names a row here, and a row here is
//! never served as content.
//!
//! | Module | Content |
//! |---|---|
//! | [`db`] | The sled-backed store: chain state, accounts, blocks |
//! | [`traits`] | The storage traits and the durable commit batch |
//! | [`state_trie`] | The sparse proof-bearing trie over account state |
//! | [`pruning`] | Node mode and the historical-state pruning policy |
//! | [`witness_retention`] | How long block witnesses are kept per node kind |

pub mod db;
pub mod pruning;
pub mod state_trie;
pub mod traits;
pub mod witness_retention;

pub use pruning::{NodeMode, PruningPolicy};
