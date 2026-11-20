pub mod anchor_ledger;
pub mod anchor_production;
pub mod app_binding;
pub mod cold_quorum;
pub mod cold_wallet;
pub mod commitment_tree;
pub mod domains;
pub mod global_block;
pub mod liquidation_proof;
pub mod pq_anchor;
pub mod pq_anchor_verify;
pub mod proof_market;
pub mod proof_verifier;
pub mod registries;
pub mod reseal;
pub mod root_seal;
pub mod shared_security;
pub mod universal_finality;

#[cfg(test)]
pub use cold_quorum::dev_fixture_device_signers;
pub use cold_quorum::{
    verify_quorum, DeviceSignature, DeviceSigner, QuorumError, SignerIdentity,
    DEV_FIXTURE_DEVICE_COUNT,
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
pub use anchor_ledger::{
    AnchorKeyLedger, KeyFamily, LedgerError, LedgerKey, Suspension, ANCHOR_KEY_COUNT,
    ANCHOR_THRESHOLD,
};
pub use anchor_production::{
    enforce_production, AnchorEmission, CeremonyRecord, ProductionGrant, VerifyMerkleAudit,
};
#[cfg(feature = "bpqs-research")]
pub use budlum_bpqs as bpqs_research;
pub use liquidation_proof::{
    execute_liquidation, AmmReserveSnapshot, LiquidationError, LiquidationOutcome,
    LiquidationPosition, LIQUIDATION_PENALTY_BPS, MAX_BATCH_SIZE, MAX_OBSERVATIONS,
    MAX_TWAP_EPOCHS, MIN_TWAP_EPOCHS,
};
pub use pq_anchor::{
    aggregate_finality_roots, anchor_due, anchor_leaf_digest, anchor_payload_for, assemble_anchor,
    build_anchor_for_height, build_anchor_inclusion_proof, emit_anchor_node_local,
    enforce_anchor_mode, rotate_anchor_key_with_committee, verify_anchor_full,
    verify_anchor_leaf_light, verify_anchor_light, AnchorError, AnchorInclusionProof, AnchorLeaf,
    AnchorMode, AnchorSignature, AnchorSignatureAlgorithm, AnchorSigner, EmissionOutcome,
    EmissionRequest, HsmSignerStub, PqAnchor, SignerBackend, ANCHOR_INTERVAL,
    MAX_ANCHOR_MERKLE_DEPTH, MAX_ANCHOR_SIGNATURES,
};
pub use proof_market::{
    ProofMarketState, ProofMarketTx, ProofReceipt, ProofTask, ProofTaskKind, ProofTaskStatus,
    ReceiptStatus,
};
pub use proof_verifier::{ProofVerificationError, SettlementProofVerifier, VerifiedDomainEvent};
pub use registries::SettlementRegistries;
pub use root_seal::{
    seal_due, RootSeal, RootSealLog, SealError, SealKeys, SoftwareSealSigner, ROOT_SEAL_INTERVAL,
};
pub use universal_finality::{
    compose, compose_cross_domain_route, compose_with_bar, DomainFinalityEntry,
    EconomicSecurityBound, FinalityComposeError, FinalityGuarantee, FinalityPendingReason,
    FinalityReversibility, FinalityVerdict, GlobalFinalityCertificate, RouteFinalityBound,
    FINALITY_BINDS_ALL,
};
