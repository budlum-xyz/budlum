pub mod commitment_registry;
pub mod finality_adapter;
pub mod fork_choice;
pub mod plugin;
pub mod plugin_registry;
pub mod pq_canonical;
pub mod producer;
pub mod registry;
pub mod sovereign;
pub mod types;

pub use commitment_registry::DomainCommitmentRegistry;
pub use finality_adapter::{
    hash_finality_proof, hash_pow_header, poa_authority_set_hash, AiInferenceFinalityAdapter,
    BftFinalityAdapter, DomainFinalityAdapter, FinalityError, FinalityProof, FinalityStatus,
    PoAFinalityAdapter, PoSFinalityAdapter, PoWHeader, PoWHeaderChainFinalityAdapter,
    StorageAttestationFinalityAdapter, ZkFinalityAdapter,
};
pub use fork_choice::{
    ConsensusDomainForkChoice, DomainFinalityStatus, DomainForkChoice, DomainLifecycleStatus,
    ForkCandidate, ForkChoiceError, ForkChoiceReason, ResolvedHead,
};
pub use plugin::{
    default_domain, BftDomainPlugin, ConsensusDomainPlugin, DomainContext, DomainError,
    PoADomainPlugin, PoSDomainPlugin, PoWDomainPlugin, ZkDomainPlugin,
};
pub use plugin_registry::DomainPluginRegistry;
pub use pq_canonical::{PqCanonicalSource, SealId, SealKind, SourceError};
pub use crate::chain::state_recovery::regen_health::{assess, AlarmReason, HealthPolicy, HealthVerdict};
pub use crate::chain::state_recovery::regen_mempool::RegenMempool;
pub use registry::ConsensusDomainRegistry;
pub use sovereign::{
    AuditExportBundle, ComplianceEvidence, DomainLifecycleState, SovereignDomainClass,
    SovereignDomainRegistry, SovereignDomainTemplate,
};
pub use types::{
    normalize_hash32, validator_set_commitment, ConsensusDomain, ConsensusKind, DomainCommitment,
    DomainId, DomainStatus, Hash32, PoWDomainParameters, RootScheme, VerifiedDomainCommitment,
    AI_INFERENCE_ADAPTER, POW_HEADER_CHAIN_ADAPTER, STORAGE_ATTESTATION_ADAPTER,
};
