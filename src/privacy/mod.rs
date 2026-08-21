//! L1 privacy-layer state (note/UTXO parallel subtree).
//!
//! Isolated from NFT/B.U.D./Pollen (gizlilik talimatı Bölüm 7). Receives
//! Public halves of wallet `PrivateTransferIntent` via
//! `TransactionType::PrivateTransferSubmit`.

mod note_registry;
mod submit;

pub use note_registry::L1NoteRegistry;
pub use submit::{PrivateTransferSubmit, MAX_PRIVATE_IO};
