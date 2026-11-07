pub mod atlas;
pub mod passport;
pub use atlas::{
    build_wallet_context, AtlasEvidenceCard, AtlasEvidenceStatus, AtlasQueryEngine,
    AtlasWalletContext, CrossDomainTrace, DomainSummary, EvidenceRecord, MessageTraceStatus,
    PollenAtlasSummary, WalletContextEdge, WalletContextGraph, WalletContextNode, WalletEdgeType,
    WalletNodeType,
};
pub use passport::{
    build_passport_profile, build_passport_proof_bundle, try_build_passport_proof_bundle,
    validate_passport_name, DwebPassportProfile, EvidenceCard, EvidenceStatus, PassportProofBundle,
    PassportProofItem,
};

/// Maximum payload bytes served by the content gateway in a single response.
/// WIRING: exposed for: budscan content-gateway parity.
pub const MAX_GATEWAY_CONTENT_BYTES: usize = 10 * 1024 * 1024;
