//! Merkle state trie over account and domain state.
//!
//! WP-06 mechanical move (Section 5.2): the canonical module name is
//! `state_trie`; the legacy file at `src/storage/merkle_trie.rs` is
//! forwarded here through a re-export. Call sites migrate to
//! `crate::persistence::state_trie::*`; once all imports flip the file
//! body replaces the legacy file and the re-export is dropped.
//!
//! Content storage (B.U.D. 3.0) does NOT live here - see
//! `crate::storage::bud3` (KR-01, D-1).

#[doc(inline)]
pub use crate::storage::merkle_trie::*;
