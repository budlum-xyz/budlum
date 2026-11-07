//! Storage layer.
//!
//! The one storage system is B.U.D. 3.0, under [`bud3`]. The previous
//! storage generations - device self-hosting, the deal-and-challenge
//! container model and the generated-content recipe model - are gone; the
//! capabilities are rebuilt inside [`bud3`] and until a rebuild lands its
//! dependents carry [`bud3::content_ref::ContentRef`] alone.
//!
//! The node-local key-value store, the account proof trie and the pruning
//! and witness-retention policies live in `crate::persistence` - chain
//! state and blocks for this node, kept apart from the content shapes here.

pub mod bud3;

pub use crate::persistence::pruning::{NodeMode, PruningPolicy};
pub use bud3::content_ref::{register_content, ContentRef, StorageError};
