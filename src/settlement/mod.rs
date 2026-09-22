pub mod cold_quorum;
pub mod cold_wallet;
pub mod commitment_tree;
pub mod global_block;
pub mod pq_anchor;
pub mod proof_market;
pub mod proof_verifier;

pub use cold_quorum::{
    dev_fixture_device_signers, verify_quorum, DeviceSignature, DeviceSigner, QuorumError,
    SignerIdentity, DEV_FIXTURE_DEVICE_COUNT,
};
pub use cold_wallet::{
    ColdRefusal, ColdSettleError, ColdWalletPolicy, ColdWalletState, KeyRotation, RefusalRecord,
    RotationError, SettlementRequest, VerifiedSettlement, MAX_COLD_ROTATION_HISTORY,
    MAX_ROTATION_REASON_BYTES,
};
pub use commitment_tree::merkle_root;
pub use global_block::GlobalBlockHeader;
#[cfg(feature = "wallet-ml-dsa")]
pub use pq_anchor::SoftwareMlDsa87Signer;
// F2 research line: the crate is an OPTIONAL path dep and the feature is
// non-default, so this re-export is the only code reference in the default
// feature set - it is here so that the machete dead-deps gate sees the
// dependency as named rather than silently dropped, and so that future
// research phases have one established import point.
#[cfg(feature = "bpqs-research")]
pub use budlum_bpqs as bpqs_research;
pub use pq_anchor::{
    aggregate_finality_roots, anchor_leaf_digest, anchor_payload_for, assemble_anchor,
    build_anchor_for_height, emit_anchor_node_local, enforce_anchor_mode,
    rotate_anchor_key_with_committee, verify_anchor_full, verify_anchor_light, AnchorError,
    AnchorKeyEntry, AnchorMode, AnchorSignature, AnchorSignatureAlgorithm, AnchorSigner,
    EmissionOutcome, HsmSignerStub, PqAnchor,
};
pub use proof_market::{
    ProofMarketState, ProofReceipt, ProofTask, ProofTaskKind, ProofTaskStatus, ReceiptStatus,
};
pub use proof_verifier::{ProofVerificationError, SettlementProofVerifier, VerifiedDomainEvent};
