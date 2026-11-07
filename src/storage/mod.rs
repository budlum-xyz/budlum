//! Storage layer (`B.U.D. 3.0`).
//!
//! B.U.D. 3.0 under [`bud3`] is the single content storage and optical stack.
//! Node-local key-value persistence, account proof tries, and pruning live in
//! `crate::persistence`.

pub mod bud3;

pub use crate::persistence::pruning::{NodeMode, PruningPolicy};
pub use bud3::content_handle::{register_content, ContentRef, StorageError};
