//! Node-local persistence layer.
//!
//! The node-local key-value store (sled) that holds chain state, accounts,
//! blocks, etc. This is not the B.U.D. content-addressing storage. The
//! content layer lives in `crate::storage::bud3` (T-Launch).

pub mod db;
pub mod pruning;
pub mod state_trie;
pub mod traits;
pub mod witness_retention;

pub use db::Storage;
pub use state_trie::{AccountProofBundle, MerkleTrie};
pub use traits::{BlockchainStorage, DurableCommitBatch, SeenBlockMap};
