//! chain privacy-layer state (note/UTXO parallel subtree).
//!
//! Isolated from NFT, B.U.D. and Data Market state. Receives
//! Public halves of wallet `PrivateTransferIntent` via
//! `TransactionType::PrivateTransferSubmit`.

pub mod data_layering;
mod note_registry;
mod submit;
pub mod threshold_escrow;

pub use data_layering::{
    compute_layer_commitment, derive_stealth_owner_tag, layer_transition_digest, DataLayerError,
    DataLayerRegistry, DataPrivacyLayer, LayerOwnerAuth, LayeredDataRecord,
};
pub use note_registry::{is_note_hash, L1NoteRegistry};
pub use submit::{ConfidentialTransferProofBundle, PrivateTransferSubmit, MAX_PRIVATE_IO};
pub use threshold_escrow::{
    EscrowCommittee, EscrowMember, EscrowUnlockShare, ThresholdEscrow, ThresholdEscrowError,
    THRESHOLD_ESCROW_N, THRESHOLD_ESCROW_T,
};
