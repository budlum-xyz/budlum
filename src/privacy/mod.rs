//! chain privacy-layer state (note/UTXO parallel subtree).
//!
//! Isolated from NFT, B.U.D. and Data Market state. Receives
//! Public halves of wallet `PrivateTransferIntent` via
//! `TransactionType::PrivateTransferSubmit`.

pub mod data_layering;
mod note_registry;
pub mod private_transfer_v1;
mod submit;
pub mod threshold_escrow;

pub use data_layering::{
    compute_layer_commitment, derive_stealth_owner_tag, layer_transition_digest, DataLayerError,
    DataLayerRegistry, DataPrivacyLayer, LayerOwnerAuth, LayeredDataRecord,
};
pub use note_registry::{
    is_note_hash, L1NoteRegistry, MAX_LIVE_COMMITMENTS, MAX_LIVE_COMMITMENTS_PER_OWNER,
};
pub use private_transfer_v1::{
    compute_note_commitment, derive_note_nullifier, derive_output_rho, derive_owner_pk,
    prove_private_transfer_v1, verify_private_transfer_v1, MerklePathV1, NoteCommitmentTreeV1,
    OutputNoteDraftV1, PrivateTransferV1Error, PrivateTransferV1Proof,
    PrivateTransferV1PublicInputs, ShieldedNoteV1, ShieldedPoolV1, SpendWitnessV1,
    MAX_NOTE_VALUE_V1, MAX_TRANSFER_V1_IO, NOTE_TREE_DEPTH,
};
pub use submit::{
    ConfidentialTransferProofBundle, PrivateTransferSubmit, MAX_CONFIDENTIAL_VALUE, MAX_PRIVATE_IO,
};
pub use threshold_escrow::{
    EscrowCommittee, EscrowMember, EscrowUnlockShare, ThresholdEscrow, ThresholdEscrowError,
    THRESHOLD_ESCROW_N, THRESHOLD_ESCROW_T,
};
