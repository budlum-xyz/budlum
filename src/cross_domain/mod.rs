pub mod bridge;
pub mod bridge_relayer;
pub mod chain_adapter;
pub mod event_tree;
pub mod external;
pub mod evm;
pub mod message;
pub mod message_registry;
pub mod nonce;
pub mod relayer;

pub use bridge::{AssetId, BridgeError, BridgeState, BridgeStatus, BridgeTransfer};
pub use bridge_relayer::{BridgeRelayerPipeline, PipelineError};
pub use chain_adapter::{AdapterError, AdapterRegistry, ChainAdapter};
pub use event_tree::{DomainEvent, DomainEventKind, DomainEventTree, MerkleProof};
pub use external::{
    admit, profile_of, AdapterDescriptor, AdapterId, AdmissionReport,
    DomainEconomics, DomainKey, DomainProfile, DomainRegistration, DomainState, EthereumSyncAdapter,
    ExternalDomainRegistry, ExternalFinalityAdapter, FaultProbe, FinalityAttestation, ProverBond,
    RawConsensusEvidence, RegistryError, SecurityBacking, VerificationPolicy, VersionPolicy,
};
// `AdapterError` is taken by `chain_adapter` in this module's namespace, so the
// external-domain error is re-exported under a name that says which one it is.
// Shadowing the other one would make `cross_domain::AdapterError` mean one
// thing in one place and another in the next.
pub use external::spec::AdapterError as ExternalAdapterError;
pub use message::{CrossDomainMessage, MessageId, MessageKind};
pub use message_registry::CrossDomainMessageRegistry;
pub use nonce::ReplayNonceStore;
pub use relayer::{RelayLedger, RelayerConfig, RelayerError, UniversalRelayer};
