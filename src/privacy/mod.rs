//! chain privacy-layer state (note/UTXO parallel subtree).
//!
//! Isolated from NFT, B.U.D. and Pollen state. Receives
//! Public halves of wallet `PrivateTransferIntent` via
//! `TransactionType::PrivateTransferSubmit`.

mod note_registry;
mod submit;

pub use note_registry::{is_note_hash, L1NoteRegistry};
pub use submit::{PrivateTransferSubmit, MAX_PRIVATE_IO};
