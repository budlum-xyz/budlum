//! The production intake: where the external-domain framework stops being a
//! specification and starts being consulted.
//!
//! # What this module is, and what it deliberately is not
//!
//! Everything under `cross_domain::external` was written spec-first: the
//! registry, admission, versioning, prover economics and the two concrete
//! adapters were fully tested but reachable only from their own tests. The
//! module docs in `mod.rs` said so out loud and named the two consensus
//! decisions that wiring would require:
//!
//! 1. **Where the registry lives in consensus state.** Answered here: it is
//!    `AccountState::settlement.external_intake`, written only by the
//!    `ExternalDomain` transaction door (`external_tx.rs`), carried in the
//!    state snapshot, folded into the state root, and clocked at block end
//!    (`on_block_committed` from the block-effects transition). It used to
//!    be a field on `Blockchain`, written by operator RPCs and persisted
//!    beside the chain, which no block root covered.
//! 2. **How an attestation becomes a `GlobalBlockHeader` commitment.**
//!    Answered here: it does not get a new header field. An accepted
//!    attestation is stored in the registry; the registry is part of the
//!    node's replayable state and its digest is folded by
//!    [`IntakeState::state_digest`], which the RPC surface exposes so any
//!    consumer can compare two nodes. Minting a new header root for a
//!    subsystem with no live domains would commit every chain to bytes that
//!    are `None` forever on most of them; the header gains a root when the
//!    first real external domain goes live and the fold is battle-read. That
//!    is a smaller promise than a header field, and it is labelled as such.
//!
//! The dispatcher below is the single place production code constructs
//! adapters. It is deliberately an enum, not a `Box<dyn>` registry: which
//! adapter implementations exist in this binary is a compile-time fact, and
//! evidence must never be able to select an implementation the operator did
//! not choose to build.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::external::bitcoin_spv::{BitcoinSpvAdapter, PinnedBitcoinAnchor};
use crate::cross_domain::external::ethereum::{BlsVerifier, EthereumSyncAdapter};
use crate::cross_domain::external::intake_guard::{IntakeGuard, IntakeGuardError};
use crate::cross_domain::external::intake_quorum::{
    QuorumRounds, RoundEntry, RoundError, RoundKey, RoundState,
};
use crate::cross_domain::external::prover::{
    honesty_is_cheaper, ChallengeReward, DomainEconomics, ProverFee,
};
use crate::cross_domain::external::quorum::{
    DisputeBehavior, LowParticipantsBehavior, QuorumPolicy,
};
use crate::cross_domain::external::registry::{ExternalDomainRegistry, RegistryError};
use crate::cross_domain::external::selftest::{admit, AdmissionReport};
use crate::cross_domain::external::spec::{
    AdapterDescriptor, DomainKey, ExternalFinalityAdapter, FinalityAttestation,
    RawConsensusEvidence, SecurityBacking, TimeUnit, VerificationPolicy,
};
use crate::cross_domain::external::tendermint::TendermintFinalityAdapter;
use crate::cross_domain::external::versioning::VersionPolicy;
use crate::cross_domain::external::zkvm_proof::ZkVmFinalityAdapter;
use serde::{Deserialize, Serialize};

/// The production pairing check behind [`BlsVerifier`], on the node's own
/// `bls12_381` primitives (`chain::finality::hash_to_g2`, Ethereum's G2
/// signature DST). Fast-aggregate form: the adapter hands over the aggregate
/// public key and the aggregate signature it parsed from the update, and this
/// verifies `e(agg_pk, H(root)) == e(g1_gen, sig)` with full subgroup checks
/// on both points - the same discipline as `verify_sync_aggregate` in
/// `cross_domain::evm::sync_committee`, without recomputing the aggregation
/// (the committee membership question belongs to the adapter's layout, not to
/// the pairing).
/// WIRING: External beacon light-client pairing verifier (`object_layer` and `ethereum` intake).
pub(crate) struct PairingBls;

impl BlsVerifier for PairingBls {
    fn verify_aggregate(
        &self,
        signing_root: &[u8; 32],
        aggregate_pubkey: &[u8],
        signature: &[u8],
        participants: u64,
    ) -> Result<(), String> {
        use bls12_381::{G1Affine, G2Affine};

        if participants == 0 {
            return Err("an aggregate with zero signers proves nothing".to_string());
        }
        // The layout carries 96 bytes for the aggregate key; a 48-byte
        // compressed G1 point arrives zero-padded on the right. Both shapes
        // are accepted explicitly; anything else is refused by name.
        let pk_bytes: [u8; 48] = match aggregate_pubkey.len() {
            48 => aggregate_pubkey
                .try_into()
                .map_err(|_| "aggregate pubkey slice conversion failed".to_string())?,
            96 => {
                let padding = aggregate_pubkey.get(48..).unwrap_or(&[]);
                if padding.len() != 48 || padding.iter().any(|b| *b != 0) {
                    return Err(
                        "a 96-byte aggregate pubkey must be a zero-padded compressed G1 point"
                            .to_string(),
                    );
                }
                aggregate_pubkey
                    .get(..48)
                    .ok_or_else(|| "aggregate pubkey slice conversion failed".to_string())?
                    .try_into()
                    .map_err(|_| "aggregate pubkey slice conversion failed".to_string())?
            }
            n => return Err(format!("aggregate pubkey must be 48 or 96 bytes, got {n}")),
        };
        let pk = G1Affine::from_compressed(&pk_bytes)
            .into_option()
            .ok_or_else(|| "aggregate pubkey is not a valid compressed G1 point".to_string())?;
        if !bool::from(pk.is_torsion_free()) || bool::from(pk.is_identity()) {
            return Err(
                "aggregate pubkey is identity or outside the prime-order subgroup".to_string(),
            );
        }

        let sig_bytes: [u8; 96] = signature
            .try_into()
            .map_err(|_| format!("signature must be 96 bytes, got {}", signature.len()))?;
        let sig = G2Affine::from_compressed(&sig_bytes)
            .into_option()
            .ok_or_else(|| "signature is not a valid compressed G2 point".to_string())?;
        if !bool::from(sig.is_torsion_free()) || bool::from(sig.is_identity()) {
            return Err("signature is identity or outside the prime-order subgroup".to_string());
        }

        let h_msg = crate::chain::finality::hash_to_g2(signing_root);
        let g1_gen_neg = -G1Affine::generator();
        let pairing =
            bls12_381::multi_miller_loop(&[(&pk, &h_msg.into()), (&g1_gen_neg, &sig.into())])
                .final_exponentiation();
        if pairing != bls12_381::Gt::identity() {
            return Err("aggregate signature does not verify over the signing root".to_string());
        }
        Ok(())
    }

    fn sync_committee_closed(&self) -> bool {
        false
    }
}

/// The adapter families this binary can construct.
///
/// Data, so it can be
/// persisted with the registration and reconstructed on restart: a domain
/// whose adapter cannot be rebuilt from its stored spec is a domain the node
/// silently stops serving, and that must be a loud error instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterSpec {
    /// Ethereum sync-committee finality, bound to one network and one PINNED
    /// sync committee. The BLS verifier is installed by
    /// the node at construction; the spec carries only the data. A spec
    /// without a committee is the closed admission state (decision C,
    /// interim): `register_domain` refuses it.
    EthereumSync {
        network: String,
        #[serde(default)]
        committee: Option<crate::cross_domain::external::ethereum::PinnedCommittee>,
    },
    /// `BudZKVM` validity proofs for one network, pinned to one program and
    /// one chain. A spec without the pins is
    /// the closed admission state: `register_domain` refuses it.
    ZkVm {
        network: String,
        #[serde(default)]
        program_hash: Option<[u8; 32]>,
        #[serde(default)]
        chain_id: Option<u64>,
    },
    /// Bitcoin SPV header-chain finality for one network, pinned to one
    /// trusted checkpoint. APPENDED LAST: this enum is persisted in consensus
    /// state through bincode, so inserting a variant in the middle would
    /// reinterpret every stored registration (STRX-194-01). A spec without
    /// an anchor is the closed admission state: `register_domain` refuses it.
    BitcoinSpv {
        network: String,
        #[serde(default)]
        anchor: Option<PinnedBitcoinAnchor>,
    },
    /// Tendermint/CometBFT commit finality for one network, pinned to one chain
    /// id. APPENDED LAST, for the same bincode reason as `BitcoinSpv`: this
    /// enum is persisted in consensus state, so inserting a variant in the
    /// middle would reinterpret every stored registration. A spec with an
    /// empty chain id is the closed admission state: `register_domain`
    /// refuses it, because a commit's chain id is part of every sign byte and
    /// an unpinned adapter would verify any chain's commit.
    TendermintCommit {
        network: String,
        chain_id: String,
        /// Canonical [`crate::cross_domain::external::tendermint::validator_set_commitment`]
        /// pinned by governance for `network`. `None` is the closed admission state.
        #[serde(default)]
        validator_set_hash: Option<[u8; 32]>,
    },
    /// Modular 2D Data-Availability Sampling (`DAS`) + Namespace Merkle Tree
    /// (`NMT`) light-client finality bound to a governance-pinned namespace
    /// and slashable attestation committee. APPENDED LAST (tag `4`).
    DataAvailability {
        network: String,
        #[serde(default)]
        committee: Option<crate::cross_domain::external::da_sampling::PinnedDaCommittee>,
    },
    /// Linear chained BFT (`HotStuff` 3-chain QC rule) finality bound to a
    /// governance-pinned epoch validator set. APPENDED LAST (tag `5`).
    HotStuffQc {
        network: String,
        #[serde(default)]
        committee: Option<crate::cross_domain::external::hotstuff::PinnedHotStuffCommittee>,
    },
    /// Stake-weighted round-DAG BFT (`Bullshark` anchor + wave-commit quorum)
    /// finality bound to a governance-pinned epoch committee. APPENDED LAST (tag `6`).
    DagCertificate {
        network: String,
        #[serde(default)]
        committee: Option<crate::cross_domain::external::dag_bft::PinnedDagCommittee>,
    },
    /// Dual-quorum `Casper-FFG` two-epoch checkpoint finality bound to a
    /// governance-pinned epoch validator set. APPENDED LAST (tag `7`).
    CasperFfg {
        network: String,
        #[serde(default)]
        committee: Option<crate::cross_domain::external::casper_ffg::PinnedFfgCommittee>,
    },
    /// Uncertified three-round `Mysticeti` `DAG-BFT` direct-commit finality bound
    /// to a governance-pinned epoch committee. APPENDED LAST (tag `8`).
    MysticetiDag {
        network: String,
        #[serde(default)]
        committee: Option<crate::cross_domain::external::mysticeti_dag::PinnedMysticetiCommittee>,
    },
    /// `BitVM2` / `DisproveScript` optimistic-ZK `PoW` covenant finality bound to
    /// a governance-pinned `PoW` checkpoint, guest program, and operator key.
    /// APPENDED LAST (tag `9`).
    BitVmCovenant {
        network: String,
        #[serde(default)]
        anchor: Option<crate::cross_domain::external::bitvm_covenant::PinnedBitVmAnchor>,
    },
    /// Babylon / BTC-restaking EOTS finality bound to one network and one
    /// governance-pinned epoch-key table plus Bitcoin weak-subjectivity
    /// anchor. APPENDED LAST (tag `15`): the wire tag is the first free slot
    /// after the reserved 10..14 (Sekstant / ScheduleFork). A spec without a
    /// pin is the closed admission state: `register_domain` refuses it.
    BabylonEots {
        network: String,
        #[serde(default)]
        pinned: Option<crate::cross_domain::external::babylon_eots::PinnedBabylonEots>,
    },
    /// Sublinear `NIPoPoW` superblock finality (Kiayias-Miller-Zindros,
    /// EUROCRYPT 2020) for a `PoW` chain, bound to a governance-pinned genesis
    /// and KMZ `(m, k)` parameters. APPENDED LAST (tag `16`): the bincode
    /// discriminant is this variant's declaration position, and the manual
    /// `encode_adapter_spec` tag is the first free slot after Babylon's 15.
    ///
    /// Why this family and not a linear SPV one: the promise a `PoW` chain
    /// makes is work, and `NIPoPoW` verifies genesis-to-tip work in
    /// `O(m log|C| + k)` headers under pure SHA-256 - the one primitive here
    /// Shor's algorithm does not touch. A spec without a genesis anchor is the
    /// closed admission state: `register_domain` refuses it, because a
    /// superblock proof says nothing about *which* chain it is a proof of
    /// until a genesis is pinned.
    NipopowSuperblock {
        network: String,
        #[serde(default)]
        genesis: Option<crate::cross_domain::external::nipopow::PinnedNipopowGenesis>,
    },
}

impl AdapterSpec {
    /// The network this spec serves. Every variant carries one; the accessor
    /// exists so the intake can index registrations without matching.
    #[must_use]
    pub fn network(&self) -> &str {
        match self {
            Self::EthereumSync { network, .. }
            | Self::ZkVm { network, .. }
            | Self::BitcoinSpv { network, .. }
            | Self::TendermintCommit { network, .. }
            | Self::DataAvailability { network, .. }
            | Self::HotStuffQc { network, .. }
            | Self::DagCertificate { network, .. }
            | Self::CasperFfg { network, .. }
            | Self::MysticetiDag { network, .. }
            | Self::BitVmCovenant { network, .. }
            | Self::BabylonEots { network, .. }
            | Self::NipopowSuperblock { network, .. } => network,
        }
    }

    /// Builds the live adapter. `bls` is the node's pairing implementation,
    /// injected so this module can be tested without curve arithmetic and so
    /// the spec stays serializable. `golden` is attached when the caller is
    /// about to run admission - `admit` refuses an adapter without a golden
    /// sample, by design - and omitted on the plain verification path, where
    /// a golden sample would be dead weight.
    #[must_use]
    pub fn build(
        &self,
        bls: Option<Box<dyn BlsVerifier>>,
        golden: Option<RawConsensusEvidence>,
    ) -> Box<dyn ExternalFinalityAdapter> {
        use crate::cross_domain::external::{
            babylon_eots::BabylonEotsAdapter, bitvm_covenant::BitVmCovenantAdapter,
            casper_ffg::CasperFfgAdapter, da_sampling::DataAvailabilityAdapter,
            dag_bft::BullsharkDagAdapter, hotstuff::HotStuffThreeChainAdapter,
            mysticeti_dag::MysticetiDagAdapter,
        };
        match self {
            Self::EthereumSync { network, committee } => box_with_golden(
                || EthereumSyncAdapter::new(network, committee.clone(), bls),
                golden,
                EthereumSyncAdapter::with_golden,
            ),
            Self::ZkVm {
                network,
                program_hash,
                chain_id,
            } => box_with_golden(
                || ZkVmFinalityAdapter::new(network, *program_hash, *chain_id),
                golden,
                ZkVmFinalityAdapter::with_golden,
            ),
            Self::BitcoinSpv { network, anchor } => box_with_golden(
                || BitcoinSpvAdapter::new(network, anchor.clone()),
                golden,
                BitcoinSpvAdapter::with_golden,
            ),
            Self::TendermintCommit {
                network,
                chain_id,
                validator_set_hash,
            } => box_with_golden(
                || TendermintFinalityAdapter::new_pinned(network, chain_id, *validator_set_hash),
                golden,
                TendermintFinalityAdapter::with_golden,
            ),
            Self::DataAvailability { network, committee } => box_with_golden(
                || DataAvailabilityAdapter::new(network, committee.clone()),
                golden,
                DataAvailabilityAdapter::with_golden,
            ),
            Self::HotStuffQc { network, committee } => box_with_golden(
                || HotStuffThreeChainAdapter::new(network, committee.clone()),
                golden,
                HotStuffThreeChainAdapter::with_golden,
            ),
            Self::DagCertificate { network, committee } => box_with_golden(
                || BullsharkDagAdapter::new(network, committee.clone()),
                golden,
                BullsharkDagAdapter::with_golden,
            ),
            Self::CasperFfg { network, committee } => box_with_golden(
                || CasperFfgAdapter::new_optional(network, committee.clone()),
                golden,
                CasperFfgAdapter::with_golden,
            ),
            Self::MysticetiDag { network, committee } => box_with_golden(
                || MysticetiDagAdapter::new(network, committee.clone()),
                golden,
                MysticetiDagAdapter::with_golden,
            ),
            Self::BitVmCovenant { network, anchor } => box_with_golden(
                || BitVmCovenantAdapter::new(network, anchor.clone()),
                golden,
                BitVmCovenantAdapter::with_golden,
            ),
            Self::BabylonEots { network, pinned } => box_with_golden(
                || match pinned {
                    Some(pinned) => pinned.build_adapter(network),
                    // `None` is the closed admission state: `register_domain`
                    // refuses it before this is ever built, and a spec that
                    // somehow reaches here verifies nothing (chain id 0, no
                    // keys, no anchor).
                    None => BabylonEotsAdapter::new(network, 0),
                },
                golden,
                BabylonEotsAdapter::with_golden,
            ),
            Self::NipopowSuperblock { network, genesis } => box_with_golden(
                || {
                    crate::cross_domain::external::nipopow::NipopowAdapter::new(
                        network,
                        genesis.clone(),
                    )
                },
                golden,
                crate::cross_domain::external::nipopow::NipopowAdapter::with_golden,
            ),
        }
    }
}

fn box_with_golden<A: ExternalFinalityAdapter + 'static>(
    make: impl FnOnce() -> A,
    golden: Option<RawConsensusEvidence>,
    attach: impl FnOnce(A, RawConsensusEvidence) -> A,
) -> Box<dyn ExternalFinalityAdapter> {
    let adapter = make();
    Box::new(match golden {
        Some(sample) => attach(adapter, sample),
        None => adapter,
    })
}

/// Everything one registration carries, as one value.
///
/// A struct rather than
/// seven positional parameters, at the intake and across the actor channel
/// alike: positional registration data is how a bond and a ceiling get
/// swapped silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub spec: AdapterSpec,
    pub policy: VerificationPolicy,
    pub economics: DomainEconomics,
    pub versions: VersionPolicy,
    pub bond_atoms: u128,
    pub poster: Address,
    /// The known-good evidence sample admission verifies against. Required:
    /// `admit` refuses an adapter with no golden sample, so asking for it at
    /// the boundary keeps the refusal early and legible.
    pub golden: RawConsensusEvidence,
}

/// One registered intake entry: the spec to rebuild the adapter, and the
/// policy evidence is verified under.
///
/// The policy is stored, not re-derived,
/// because "which policy was this attestation accepted under" is a question
/// an auditor asks about the past, and the past must not change when the
/// default does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntakeEntry {
    pub spec: AdapterSpec,
    pub policy: VerificationPolicy,
    /// The admission report the domain was registered under, kept whole so
    /// the probe names and outcomes stay readable after registration.
    pub admission: AdmissionReport,
    /// The golden sample admission verified. Stored because readmission and
    /// probe replay both need it later, and "later" must not depend on the
    /// original registrar still being around to resupply it.
    pub golden: RawConsensusEvidence,
    /// The account that posted the registration bond. It alone may change
    /// this registration's own rules (version forks, the quorum policy,
    /// readmission after a fault): those are decisions about the bond it
    /// posted, not about the network, so no other key holds them.
    #[serde(default)]
    pub registrant: Address,
}

/// The consensus-resident intake state: the framework registry plus the
/// entries needed to rebuild each adapter. This is the struct `Blockchain`
/// holds and the storage layer persists.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntakeState {
    pub registry: ExternalDomainRegistry,
    #[serde(with = "crate::core::map_keys")]
    pub entries: std::collections::BTreeMap<DomainKey, IntakeEntry>,
    /// Multi-prover quorum rounds for vote-based domains. Serialized with
    /// the rest of the intake, so round progress is inside `state_digest`
    /// and two nodes cannot disagree about a round without disagreeing
    /// about the digest.
    ///
    /// `serde(default)` does NOT keep old serialized
    /// states readable here. Storage is bincode, which is not
    /// self-describing - a state written before this field existed ends
    /// before it, and the decode fails rather than defaulting. The old doc
    /// claimed compatibility that never worked. The honest contract: a
    /// state from before a trailing field was added cannot decode, and the
    /// loader treats that as CRITICAL (refuses to start with a silently
    /// empty intake). A shape change needs a migration, not an attribute.
    #[serde(default)]
    pub quorum: QuorumRounds,
    /// Consensus/governance-pinned Ethereum sync committees keyed by network
    /// name. Permissionless `EthereumSync` registration must match a pinned
    /// committee rather than trusting a registrant-supplied key.
    #[serde(default)]
    pub pinned_ethereum_committees: std::collections::BTreeMap<
        String,
        crate::cross_domain::external::ethereum::PinnedCommittee,
    >,
    /// Governance-pinned Bitcoin SPV checkpoints keyed by external network.
    #[serde(default)]
    pub pinned_bitcoin_anchors: std::collections::BTreeMap<String, PinnedBitcoinAnchor>,
    /// Governance-pinned Tendermint `(chain_id, validator_set_hash)` anchors keyed by network.
    #[serde(default)]
    pub pinned_tendermint_anchors: std::collections::BTreeMap<
        String,
        crate::cross_domain::external::tendermint::PinnedTendermintAnchor,
    >,
    /// Governance-pinned modular DA sampling committees keyed by external network.
    #[serde(default)]
    pub pinned_da_committees: std::collections::BTreeMap<
        String,
        crate::cross_domain::external::da_sampling::PinnedDaCommittee,
    >,
    /// Governance-pinned `HotStuff` 3-chain epoch validator committees keyed by external network.
    #[serde(default)]
    pub pinned_hotstuff_committees: std::collections::BTreeMap<
        String,
        crate::cross_domain::external::hotstuff::PinnedHotStuffCommittee,
    >,
    /// Governance-pinned Bullshark round-DAG BFT committees keyed by external network.
    #[serde(default)]
    pub pinned_dag_committees: std::collections::BTreeMap<
        String,
        crate::cross_domain::external::dag_bft::PinnedDagCommittee,
    >,
    /// Governance-pinned `Casper-FFG` epoch validator committees keyed by external network.
    #[serde(default)]
    pub pinned_casper_ffg_committees: std::collections::BTreeMap<
        String,
        crate::cross_domain::external::casper_ffg::PinnedFfgCommittee,
    >,
    /// Governance-pinned `Mysticeti` uncertified `DAG` committees keyed by external network.
    #[serde(default)]
    pub pinned_mysticeti_committees: std::collections::BTreeMap<
        String,
        crate::cross_domain::external::mysticeti_dag::PinnedMysticetiCommittee,
    >,
    /// Governance-pinned `BitVM2` `PoW` covenant anchors keyed by external network.
    #[serde(default)]
    pub pinned_bitvm_anchors: std::collections::BTreeMap<
        String,
        crate::cross_domain::external::bitvm_covenant::PinnedBitVmAnchor,
    >,
    /// Governance-pinned Babylon EOTS epoch-key tables keyed by external network.
    #[serde(default)]
    pub pinned_babylon_eots_anchors: std::collections::BTreeMap<
        String,
        crate::cross_domain::external::babylon_eots::PinnedBabylonEots,
    >,
    /// Governance-pinned `NIPoPoW` genesis anchors and KMZ `(m, k)` parameters
    /// keyed by external network.
    ///
    /// Inside [`Self::state_digest`] like every other pin map: only a block may
    /// write it. A registrant that could supply its own genesis would be
    /// certifying its own finality.
    #[serde(default)]
    pub pinned_nipopow_genesis: std::collections::BTreeMap<
        String,
        crate::cross_domain::external::nipopow::PinnedNipopowGenesis,
    >,
    /// Deterministic, admin-keyless intake circuit breaker and contradiction
    /// tombstone ledger, folded into [`Self::state_digest`].
    #[serde(default)]
    pub guard: IntakeGuard,
}

/// Which anchor map an external-domain adapter family reads.
///
/// The four families that verify against a pinned trust anchor keep separate
/// maps in [`IntakeState`], keyed by network name. A network name alone is not
/// a key: `"mainnet"` denotes an Ethereum sync committee in one map and a
/// Bitcoin checkpoint in another, so every lookup and every vote names the
/// family too.
///
/// WIRING: `src/execution/executor.rs` reaches this type only through
/// `PinnedExternalAnchor::family()`'s return value (`anchor.family()`), never
/// by naming `AnchorFamily` itself, so the call site records the door here
/// instead of leaving the type looking unused from outside this file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AnchorFamily {
    Ethereum,
    Bitcoin,
    Tendermint,
    Da,
    BabylonEots,
    /// Sublinear `PoW` superblock (`NIPoPoW`) genesis and KMZ parameters.
    PoWSuccinct,
}

impl AnchorFamily {
    /// The family's name as it appears in a proposal and in a refusal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ethereum => "ethereum",
            Self::Bitcoin => "bitcoin",
            Self::Tendermint => "tendermint",
            Self::Da => "da",
            Self::BabylonEots => "babylon-eots",
            Self::PoWSuccinct => "pow-succinct",
        }
    }
}

/// A trust anchor as consensus installs it.
///
/// Until this existed, the four anchor maps in [`IntakeState`] had no writer
/// outside this crate's tests: every anchored adapter was closed on every
/// chain, because "governance pins a committee" named a vote that could not
/// happen. The anchors are inside `external_intake_root`
/// ([`IntakeState::state_digest`] hashes the whole state), so an operator-side
/// RPC or a node-local flag could not have written one without forking the
/// chain: the value is consensus state, and only a block may move it.
///
/// This is the value a `ProposalType::PinExternalAnchor` vote carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinnedExternalAnchor {
    Ethereum(crate::cross_domain::external::ethereum::PinnedCommittee),
    Bitcoin(PinnedBitcoinAnchor),
    Tendermint(crate::cross_domain::external::tendermint::PinnedTendermintAnchor),
    Da(crate::cross_domain::external::da_sampling::PinnedDaCommittee),
    BabylonEots(crate::cross_domain::external::babylon_eots::PinnedBabylonEots),
    /// Genesis and KMZ `(m, k)` parameters for a `NIPoPoW` superblock domain.
    Nipopow(crate::cross_domain::external::nipopow::PinnedNipopowGenesis),
}

impl PinnedExternalAnchor {
    /// Which map this anchor belongs in.
    #[must_use]
    pub const fn family(&self) -> AnchorFamily {
        match self {
            Self::Ethereum(_) => AnchorFamily::Ethereum,
            Self::Bitcoin(_) => AnchorFamily::Bitcoin,
            Self::Tendermint(_) => AnchorFamily::Tendermint,
            Self::Da(_) => AnchorFamily::Da,
            Self::BabylonEots(_) => AnchorFamily::BabylonEots,
            Self::Nipopow(_) => AnchorFamily::PoWSuccinct,
        }
    }

    /// Whether the anchor is a real trust root rather than a placeholder.
    ///
    /// A vote installs a value that is trusted without being proved, so the
    /// cheapest sanity check belongs at proposal time: an all-zero hash or an
    /// empty set is not an anchor, it is the shape of one.
    ///
    /// # Errors
    ///
    /// A message naming the field that is empty.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Ethereum(committee) => {
                if committee.aggregate_pubkey.is_empty() {
                    return Err("the pinned Ethereum committee has no aggregate key".into());
                }
                if committee.next_committee_root == [0u8; 32] {
                    return Err(
                        "the pinned Ethereum committee's next_committee_root is all zeroes".into(),
                    );
                }
            }
            Self::Bitcoin(checkpoint) => {
                if checkpoint.height == 0 {
                    return Err("the pinned Bitcoin checkpoint is at height 0".into());
                }
                if checkpoint.block_hash == [0u8; 32] {
                    return Err("the pinned Bitcoin checkpoint's block hash is all zeroes".into());
                }
            }
            Self::Tendermint(anchor) => {
                if anchor.chain_id.is_empty() {
                    return Err("the pinned Tendermint anchor has no chain id".into());
                }
                if anchor.validator_set_hash == [0u8; 32] {
                    return Err(
                        "the pinned Tendermint anchor's validator-set root is all zeroes".into(),
                    );
                }
            }
            Self::Da(committee) => {
                if committee.members.is_empty() {
                    return Err("the pinned DA committee has no members".into());
                }
            }
            Self::BabylonEots(pinned) => {
                // The pin's own shape check is the whole validation: a pin that
                // does not validate cannot certify a vote, and `PinnedBabylonEots::validate`
                // names the offending field.
                pinned.validate()?;
            }
            Self::Nipopow(genesis) => {
                // A zero field here is not a weak anchor, it is the shape of
                // one: a zero genesis id anchors nothing, a zero target makes
                // every hash a superblock, and `m = 0` / `k = 0` delete the KMZ
                // predicate the proof is supposed to satisfy.
                if genesis.genesis_id == [0u8; 32] {
                    return Err("the pinned NIPoPoW genesis id is all zeroes".into());
                }
                if genesis.pow_target == [0u8; 32] {
                    return Err("the pinned NIPoPoW difficulty target is all zeroes".into());
                }
                if genesis.min_superblocks_m == 0 {
                    return Err("the pinned NIPoPoW superblock count m is zero".into());
                }
                if genesis.min_superblock_level == 0 {
                    return Err("the pinned NIPoPoW superblock level is zero".into());
                }
                if genesis.min_suffix_k == 0 {
                    return Err("the pinned NIPoPoW suffix stability parameter k is zero".into());
                }
            }
        }
        Ok(())
    }

    /// The anchor's own digest, over a family-tagged encoding.
    ///
    /// A vote that replaces an anchor names the digest it expects to find,
    /// the same shape as `UnfreezeConsensusDomain`'s expected validator-set
    /// hash: without it, a vote taken against one checkpoint could be applied
    /// to whatever occupies the slot when it activates.
    ///
    /// # Errors
    ///
    /// Returns the encoder's message when the anchor cannot be encoded, which
    /// for these types means a `Vec` length the encoder refuses.
    pub fn digest(&self) -> Result<[u8; 32], String> {
        let bytes = bincode::serialize(self).map_err(|e| e.to_string())?;
        Ok(crate::core::hash::hash_fields_bytes(&[
            b"BDLM_EXTERNAL_ANCHOR_V1",
            self.family().as_str().as_bytes(),
            &bytes,
        ]))
    }
}

/// The clock `max_age` measures against at submission: the domain's most
/// recent accepted tip in the adapter's [`TimeUnit`], never lower than the
/// stored registration value (the same high-water-mark rule as the EVM relay's
/// policy clock).
#[must_use]
///
/// Convenience: crate-visible so the intake policy reads one clock
/// definition; the policy refresh in this file is its caller today.
pub(crate) fn live_policy_clock(stored_now: u64, last_accepted_tip: Option<u64>) -> u64 {
    last_accepted_tip.map_or(stored_now, |tip| tip.max(stored_now))
}

/// The domain's accepted clock tip in `time_unit`: for `TimeUnit::UnixSeconds`
/// domains (`BitcoinSpv`, `Tendermint`), `VerificationPolicy::now` and
/// `FinalityAttestation::finalized_at` are Unix-epoch seconds while
/// `record.last_accepted_height` is a block height, so the accepted clock is
/// the maximum `finalized_at` across accepted `UnixSeconds` attestations.
fn accepted_policy_clock_tip(
    reg: &crate::cross_domain::external::registry::DomainRegistration,
    time_unit: TimeUnit,
) -> Option<u64> {
    if time_unit == TimeUnit::UnixSeconds {
        reg.attestations
            .values()
            .filter(|a| a.time_unit == TimeUnit::UnixSeconds)
            .map(|a| a.finalized_at)
            .max()
    } else {
        reg.record.last_accepted_height
    }
}

/// What went wrong at the intake boundary, as distinct from inside the
/// framework registry. The split matters for callers: an `IntakeError` means
/// the request never reached the registry's rules.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntakeError {
    #[error("no external domain is registered under this key")]
    UnknownDomain,
    #[error("the ethereum adapter needs a BLS verifier and none is installed")]
    MissingBlsVerifier,
    #[error("ethereum sync admission is closed: no sync committee is pinned")]
    CommitteeNotPinned,
    #[error(
        "admission failed: golden={golden_verified}, {passed}/{total} probes passed, failing: {}",
        failing.join(", ")
    )]
    AdmissionRefused {
        golden_verified: bool,
        passed: usize,
        total: usize,
        /// Names of the probes that did not pass, in run order; a refusal
        /// that only counts its failures cannot be diagnosed from a log line.
        failing: Vec<String>,
    },
    #[error("the declared economics reward lying at the routing ceiling")]
    DishonestEconomics,
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error(transparent)]
    Round(#[from] RoundError),
    #[error("the answer entered the quorum round; the round has not decided yet")]
    RoundPending,
    #[error(
        "a quorum policy on the intake must refuse disputes and low participation; \
         AcceptMostCommon is never for a state root that will be committed to"
    )]
    PermissiveQuorumPolicy,
    #[error("the quorum policy cannot decide safely: {reason}")]
    InvalidQuorumPolicy { reason: &'static str },
    #[error("an agreed quorum round holds no entry that carried the winning claim")]
    MissingCarrier,
    #[error("a prover cannot challenge its own accepted attestation")]
    SelfChallengeForbidden,
    #[error("contradiction proof refused: {reason}")]
    InvalidContradiction { reason: String },
    #[error(transparent)]
    Guard(#[from] IntakeGuardError),
}

/// Verified receipt emitted by [`IntakeState::slash_on_contradiction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContradictionSlashOutcome {
    /// External domain whose attestation was contradicted and frozen.
    pub domain: DomainKey,
    /// Bonded carrier of the withdrawn false attestation.
    pub slashed_prover: Address,
    /// Digest of the withdrawn false attestation.
    pub contradicted_digest: [u8; 32],
    /// External height at which the conflicting finality proofs verified.
    pub height: u64,
    /// Evidence format version shared by both proofs.
    pub evidence_version: u32,
    /// Total collateral slashed from `slashed_prover` (in atoms).
    pub slashed_atoms: u128,
    /// Portion of `slashed_atoms` awarded to the challenger (`<= slashed_atoms`).
    pub challenger_reward_atoms: u128,
}

/// The first prover in arrival order whose entry carries `claim_digest`.
fn first_carrier(
    round: &crate::cross_domain::external::intake_quorum::QuorumRound,
    claim_digest: &[u8; 32],
) -> Option<Address> {
    use subtle::ConstantTimeEq;
    round
        .entries
        .iter()
        .find_map(|e: &RoundEntry| match &e.attestation {
            Some(att) if bool::from(att.claim_digest().ct_eq(claim_digest)) => Some(e.prover),
            _ => None,
        })
}

/// The most seats one quorum round may hold. Rounds are consensus state and
/// are digested on every call, so the seat count must have a bound the
/// operator cannot lift.
const MAX_QUORUM_PARTICIPANTS: usize = 256;

/// Whether `challenge` proves strictly more accumulated work than the
/// `accepted_bits` an attestation was admitted with. A tie is the external
/// chain's own fork, and a fork alone proves no carrier false.
const fn out_works(accepted_bits: u32, challenge: &SecurityBacking) -> bool {
    matches!(
        challenge,
        SecurityBacking::Work { difficulty_bits } if *difficulty_bits > accepted_bits
    )
}

impl IntakeState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pins a consensus/governance-authorized Ethereum sync committee for
    /// `network`. Only consensus bootstrap or governance may call this;
    /// permissionless domain registration must match the pinned committee.
    ///
    /// WIRING: unwired - the production door is a governance action that
    /// installs the ceremony's committee (the `BnsSetPrimarySellers` shape:
    /// an in-block `GovernanceAction` arm in `execution::executor`), and until
    /// it lands the only callers are the test fixtures of this module,
    /// `external_tx` and `settlement::domains`. Until then an `EthereumSync`
    /// registration is refused with `CommitteeNotPinned`, which is the
    /// fail-closed state and not a silent trust of the registrant's key.
    pub fn pin_ethereum_committee(
        &mut self,
        network: impl Into<String>,
        committee: crate::cross_domain::external::ethereum::PinnedCommittee,
    ) {
        self.pinned_ethereum_committees
            .insert(network.into(), committee);
    }

    /// Installs or updates the consensus-pinned Bitcoin SPV checkpoint for `network`.
    /// WIRING: governance/genesis checkpoint installation surface paired with `register_domain`.
    pub fn pin_bitcoin_anchor(&mut self, network: impl Into<String>, anchor: PinnedBitcoinAnchor) {
        self.pinned_bitcoin_anchors.insert(network.into(), anchor);
    }

    /// Installs or updates the consensus-pinned Tendermint commit anchor for `network`.
    /// WIRING: governance/genesis validator-set anchor surface paired with `register_domain`.
    pub fn pin_tendermint_anchor(
        &mut self,
        network: impl Into<String>,
        anchor: crate::cross_domain::external::tendermint::PinnedTendermintAnchor,
    ) {
        self.pinned_tendermint_anchors
            .insert(network.into(), anchor);
    }

    /// Maximum `ICS-07` trusting window (14 days, strictly below standard
    /// 21-day `CometBFT` staking unbonding) accepted by intake anchor rotation.
    ///
    /// WIRING: consensus ceiling enforced by [`Self::rotate_tendermint_anchor`]
    /// and [`Self::rotate_tendermint_anchor_bisection`].
    pub const MAX_TENDERMINT_TRUSTING_PERIOD_SECS: u64 = 14 * 24 * 60 * 60;

    /// Advance a pinned Tendermint light-client anchor across a validator-set
    /// rotation using two-phase cryptographic anchor authentication (`>= 2/3 + 1`
    /// pinned-set commit over `anchor_commit` followed by `ICS-07` skipping or
    /// adjacent commit verification + atomic domain-entry synchronization).
    ///
    /// Because [`crate::cross_domain::external::tendermint::PinnedTendermintAnchor`]
    /// persists `(chain_id, validator_set_hash)` without `next_validators_hash`
    /// or anchor timestamps, accepting an unsigned caller-built checkpoint would
    /// let an attacker supply a forged `next_validators_hash` at `height + 1`
    /// with zero honest signatures or set `trusting_period_secs = u64::MAX`.
    /// Every trusted header field (`height`, `commit_time`, `next_validators_hash`)
    /// is therefore derived exclusively from the verified `anchor_commit`.
    ///
    /// # Errors
    ///
    /// Refuses unpinned networks, chain-id or validator-set mismatches,
    /// out-of-range or expired trusting periods, forged `anchor_commit`s,
    /// insufficient trusted overlap, rollback below finalized domain tips, or
    /// forged `RFC-6962` header proofs.
    ///
    /// WIRING: Light-client Tendermint validator-set rotation advancing `pinned_tendermint_anchors`.
    /// Permissionlessly advance a pinned Ethereum sync committee to the next
    /// sequential period using an SSZ Merkle branch (`rotate_committee_with_ssz_branch`)
    /// proving the incoming 512-member BLS12-381 G1 roster opens both the
    /// finalized beacon `state_root` and the pinned `next_committee_root`.
    ///
    /// # Errors
    ///
    /// Returns [`IntakeError::CommitteeNotPinned`] if no sync committee is
    /// pinned for `network`, or [`IntakeError::Registry`] if the SSZ branch,
    /// gindex pairing, period sequence, commitment opening, or BLS12-381 G1
    /// pubkey validation fails. State is bit-identical on error.
    pub(crate) fn rotate_ethereum_committee(
        &mut self,
        network: &str,
        payload: &crate::cross_domain::external::ethereum::EthereumSyncRotationPayload,
    ) -> Result<crate::cross_domain::external::ethereum::PinnedCommittee, IntakeError> {
        use crate::cross_domain::external::ethereum::EthereumSyncAdapter;

        let Some(pinned) = self.pinned_ethereum_committees.get(network).cloned() else {
            return Err(IntakeError::CommitteeNotPinned);
        };
        let rotation = payload
            .to_ssz_rotation()
            .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        let mut adapter = EthereumSyncAdapter::new(network, Some(pinned), None);
        adapter
            .rotate_committee_with_ssz_branch(&rotation)
            .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        let updated = adapter
            .pinned_committee()
            .cloned()
            .ok_or(IntakeError::CommitteeNotPinned)?;

        self.pinned_ethereum_committees
            .insert(network.to_string(), updated.clone());
        for entry in self.entries.values_mut() {
            if let AdapterSpec::EthereumSync {
                network: entry_net,
                committee,
            } = &mut entry.spec
            {
                if entry_net == network {
                    *committee = Some(updated.clone());
                }
            }
        }
        Ok(updated)
    }

    pub fn rotate_tendermint_anchor(
        &mut self,
        network: &str,
        anchor_commit: &crate::cross_domain::external::tendermint::TendermintCommitEvidence,
        update: &crate::cross_domain::external::tendermint::TendermintCommitEvidence,
        next_validators_proof: Option<(
            [u8; 32],
            &crate::cross_domain::external::tendermint::Rfc6962Proof,
        )>,
        trusting_period_secs: u64,
        now_unix_secs: u64,
    ) -> Result<crate::cross_domain::external::tendermint::VerifiedTendermintSkip, IntakeError>
    {
        let Some(pinned) = self.pinned_tendermint_anchors.get(network).cloned() else {
            return Err(IntakeError::CommitteeNotPinned);
        };
        Self::validate_tendermint_trusting_period(trusting_period_secs)?;
        if pinned.chain_id != anchor_commit.chain_id {
            return Err(IntakeError::CommitteeNotPinned);
        }
        let derived_trusted = Self::authenticate_tendermint_anchor_commit(
            network,
            &pinned,
            anchor_commit,
            trusting_period_secs,
            now_unix_secs,
        )?;
        let skip = crate::cross_domain::external::tendermint::verify_skipping_commit(
            &derived_trusted,
            update,
            None,
            next_validators_proof,
            now_unix_secs,
        )
        .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        self.commit_rotated_tendermint_anchor(network, &pinned.chain_id, &skip, Some(update))?;
        Ok(skip)
    }

    /// Advance a pinned Tendermint light-client anchor across a multi-step
    /// `ICS-07` bisection (`> 1/3` trusted overlap per hop + `>= 2/3 + 1`
    /// target quorum + `RFC-6962` header binding), accepting validator turnover
    /// no single direct skip would accept.
    ///
    /// # Errors
    ///
    /// Refuses unpinned networks and chain-id or validator-set pin mismatches
    /// with [`IntakeError::CommitteeNotPinned`]; refuses unauthenticated
    /// `next_validators_hash` values that diverge from the pinned set; refuses
    /// out-of-bounds or mismatched light params; refuses rollback below
    /// finalized domain tips; and refuses empty, oversized, or invalid step
    /// lists while leaving state bit-identical.
    ///
    /// WIRING: the production door of `tendermint_bisection::verify_bisection`
    /// (the multi-step ICS-07 surface), advancing `pinned_tendermint_anchors`.
    pub fn rotate_tendermint_anchor_bisection(
        &mut self,
        network: &str,
        trusted: &crate::cross_domain::external::tendermint::TrustedTendermintState,
        light_params: crate::cross_domain::external::tendermint::TendermintLightParams,
        steps: &[crate::cross_domain::external::tendermint::TendermintCommitEvidence],
        now_unix_secs: u64,
    ) -> Result<crate::cross_domain::external::tendermint::VerifiedTendermintSkip, IntakeError>
    {
        use subtle::ConstantTimeEq;

        let Some(pinned) = self.pinned_tendermint_anchors.get(network).cloned() else {
            return Err(IntakeError::CommitteeNotPinned);
        };
        if pinned.chain_id != trusted.chain_id {
            return Err(IntakeError::CommitteeNotPinned);
        }
        let trusted_hash = crate::cross_domain::external::tendermint::validator_set_commitment(
            &trusted.validators,
        );
        if !bool::from(trusted_hash.ct_eq(&pinned.validator_set_hash)) {
            return Err(IntakeError::CommitteeNotPinned);
        }
        if trusted.next_validators_hash != [0u8; 32]
            && !bool::from(
                trusted
                    .next_validators_hash
                    .ct_eq(&pinned.validator_set_hash),
            )
        {
            return Err(IntakeError::Registry(RegistryError::Adapter(
                crate::cross_domain::external::spec::AdapterError::ConsensusRule {
                    rule: "unauthenticated checkpoint next_validators_hash diverges from pinned validator set; supply a signed anchor commit via rotate_tendermint_anchor".to_string(),
                },
            )));
        }
        if light_params.trusting_period_secs != trusted.trusting_period_secs {
            return Err(IntakeError::Registry(RegistryError::Adapter(
                crate::cross_domain::external::spec::AdapterError::ConsensusRule {
                    rule: format!(
                        "rotation light params must equal the checkpoint trusting period: \
                         {} != {}",
                        light_params.trusting_period_secs, trusted.trusting_period_secs
                    ),
                },
            )));
        }
        Self::validate_tendermint_trusting_period(light_params.trusting_period_secs)?;
        let anchor_root =
            crate::cross_domain::external::tendermint::validator_set_hash(&trusted.validators);
        let mut client = crate::cross_domain::external::tendermint::TendermintLightClient::new(
            trusted.clone(),
            anchor_root,
            [0u8; 32],
            light_params,
        )
        .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        let tip = client
            .verify_bisection(steps, now_unix_secs)
            .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        self.commit_rotated_tendermint_anchor(network, &pinned.chain_id, &tip, steps.last())?;
        Ok(tip)
    }

    fn validate_tendermint_trusting_period(trusting_period_secs: u64) -> Result<(), IntakeError> {
        if trusting_period_secs == 0
            || trusting_period_secs > Self::MAX_TENDERMINT_TRUSTING_PERIOD_SECS
        {
            return Err(IntakeError::Registry(RegistryError::Adapter(
                crate::cross_domain::external::spec::AdapterError::ConsensusRule {
                    rule: format!(
                        "Tendermint rotation trusting_period_secs ({trusting_period_secs}) outside 1..={}",
                        Self::MAX_TENDERMINT_TRUSTING_PERIOD_SECS
                    ),
                },
            )));
        }
        Ok(())
    }

    fn authenticate_tendermint_anchor_commit(
        network: &str,
        pinned: &crate::cross_domain::external::tendermint::PinnedTendermintAnchor,
        anchor_commit: &crate::cross_domain::external::tendermint::TendermintCommitEvidence,
        trusting_period_secs: u64,
        now_unix_secs: u64,
    ) -> Result<crate::cross_domain::external::tendermint::TrustedTendermintState, IntakeError>
    {
        use subtle::ConstantTimeEq;

        let commit_set_hash = crate::cross_domain::external::tendermint::validator_set_commitment(
            &anchor_commit.validators,
        );
        if !bool::from(commit_set_hash.ct_eq(&pinned.validator_set_hash)) {
            return Err(IntakeError::CommitteeNotPinned);
        }
        let anchor_adapter = TendermintFinalityAdapter::new_pinned(
            network,
            &pinned.chain_id,
            Some(pinned.validator_set_hash),
        );
        let payload = bincode::serialize(anchor_commit).map_err(|e| {
            IntakeError::Registry(RegistryError::Adapter(
                crate::cross_domain::external::spec::AdapterError::Malformed {
                    offset: 0,
                    reason: format!("failed to encode Tendermint anchor commit: {e}"),
                },
            ))
        })?;
        let raw = RawConsensusEvidence {
            adapter: anchor_adapter.descriptor().id,
            evidence_version: crate::cross_domain::external::tendermint::EVIDENCE_VERSION,
            network: network.to_string(),
            declared_height: anchor_commit.height,
            declared_root: anchor_commit.app_hash,
            payload,
            submitter: Address::default(),
        };
        let policy = VerificationPolicy {
            min_depth: 1,
            max_age: trusting_period_secs,
            now: now_unix_secs,
            require_slashable: true,
            require_declared_match: true,
        };
        anchor_adapter
            .verify(&raw, &policy)
            .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        let age = now_unix_secs.saturating_sub(anchor_commit.commit_time);
        if age >= trusting_period_secs {
            return Err(IntakeError::Registry(RegistryError::Adapter(
                crate::cross_domain::external::spec::AdapterError::Stale {
                    age,
                    max_age: trusting_period_secs,
                },
            )));
        }
        Ok(
            crate::cross_domain::external::tendermint::TrustedTendermintState {
                chain_id: pinned.chain_id.clone(),
                height: anchor_commit.height,
                time_secs: anchor_commit.commit_time,
                trusting_period_secs,
                validators: anchor_commit.validators.clone(),
                next_validators_hash: anchor_commit.next_validators_hash,
            },
        )
    }

    fn stage_rotated_tendermint_entry(
        &self,
        key: &DomainKey,
        entry: &IntakeEntry,
        (network, chain_id): (&str, &str),
        new_hash: [u8; 32],
        skip: &crate::cross_domain::external::tendermint::VerifiedTendermintSkip,
        final_commit: Option<&crate::cross_domain::external::tendermint::TendermintCommitEvidence>,
    ) -> Result<
        (
            DomainKey,
            AdapterSpec,
            RawConsensusEvidence,
            VerificationPolicy,
            AdmissionReport,
        ),
        IntakeError,
    > {
        if let Some(reg) = self.registry.domain(key) {
            if let Some(last_h) = reg.record.last_accepted_height {
                if skip.height <= last_h {
                    return Err(IntakeError::Registry(RegistryError::Adapter(
                        crate::cross_domain::external::spec::AdapterError::ConsensusRule {
                            rule: format!(
                                "Tendermint anchor rotation target height {} does not advance past finalized domain tip {last_h}",
                                skip.height
                            ),
                        },
                    )));
                }
            }
            if let Some(last_ts) = accepted_policy_clock_tip(reg, TimeUnit::UnixSeconds) {
                if skip.median_time_secs < last_ts
                    || final_commit.is_some_and(|c| c.commit_time < last_ts)
                {
                    return Err(IntakeError::Registry(RegistryError::Adapter(
                        crate::cross_domain::external::spec::AdapterError::ConsensusRule {
                            rule: format!(
                                "Tendermint anchor rotation commit time regresses below finalized domain timestamp {last_ts}"
                            ),
                        },
                    )));
                }
            }
        }
        let Some(commit) = final_commit else {
            return Err(IntakeError::Registry(RegistryError::Adapter(
                crate::cross_domain::external::spec::AdapterError::ConsensusRule {
                    rule:
                        "Tendermint anchor rotation missing terminal commit for registered domain"
                            .to_string(),
                },
            )));
        };
        if new_hash != skip.validator_set_hash {
            return Err(IntakeError::Registry(RegistryError::Adapter(
                crate::cross_domain::external::spec::AdapterError::ConsensusRule {
                    rule: "registered Tendermint domain rotation requires a commit signed by the rotated validator set so readmission golden evidence stays valid".to_string(),
                },
            )));
        }
        let new_spec = AdapterSpec::TendermintCommit {
            network: network.to_string(),
            chain_id: chain_id.to_string(),
            validator_set_hash: Some(new_hash),
        };
        let payload = bincode::serialize(commit).map_err(|e| {
            IntakeError::Registry(RegistryError::Adapter(
                crate::cross_domain::external::spec::AdapterError::Malformed {
                    offset: 0,
                    reason: format!("failed to encode rotated Tendermint golden commit: {e}"),
                },
            ))
        })?;
        let new_golden = RawConsensusEvidence {
            adapter: entry.golden.adapter,
            evidence_version: crate::cross_domain::external::tendermint::EVIDENCE_VERSION,
            network: network.to_string(),
            declared_height: commit.height,
            declared_root: commit.app_hash,
            payload,
            submitter: entry.golden.submitter,
        };
        let mut new_policy = entry.policy.clone();
        new_policy.now = new_policy.now.max(commit.commit_time);
        let rebuilt = new_spec.build(None, Some(new_golden.clone()));
        let new_admission = admit(rebuilt.as_ref(), &new_policy);
        if !new_admission.admitted {
            return Err(IntakeError::AdmissionRefused {
                golden_verified: new_admission.golden_verified,
                passed: new_admission.passed(),
                total: new_admission.total(),
                failing: new_admission.failing_probe_names(),
            });
        }
        Ok((*key, new_spec, new_golden, new_policy, new_admission))
    }

    fn commit_rotated_tendermint_anchor(
        &mut self,
        network: &str,
        chain_id: &str,
        skip: &crate::cross_domain::external::tendermint::VerifiedTendermintSkip,
        final_commit: Option<&crate::cross_domain::external::tendermint::TendermintCommitEvidence>,
    ) -> Result<(), IntakeError> {
        let new_hash = skip.next_validators_hash.unwrap_or(skip.validator_set_hash);
        let mut staged_updates = Vec::new();

        for (key, entry) in &self.entries {
            let AdapterSpec::TendermintCommit {
                network: entry_net,
                chain_id: entry_chain,
                ..
            } = &entry.spec
            else {
                continue;
            };
            if entry_net != network || entry_chain != chain_id {
                continue;
            }
            staged_updates.push(self.stage_rotated_tendermint_entry(
                key,
                entry,
                (network, chain_id),
                new_hash,
                skip,
                final_commit,
            )?);
        }

        for (key, new_spec, new_golden, new_policy, new_admission) in staged_updates {
            if let Some(entry) = self.entries.get_mut(&key) {
                entry.spec = new_spec;
                entry.golden = new_golden;
                entry.policy = new_policy;
                entry.admission = new_admission;
            }
        }
        self.pinned_tendermint_anchors.insert(
            network.to_string(),
            crate::cross_domain::external::tendermint::PinnedTendermintAnchor {
                chain_id: chain_id.to_string(),
                validator_set_hash: new_hash,
            },
        );
        Ok(())
    }

    /// Installs or updates the consensus-pinned modular DA committee for `network`.
    /// WIRING: governance/genesis DA committee surface paired with `register_domain`.
    pub fn pin_da_committee(
        &mut self,
        network: impl Into<String>,
        committee: crate::cross_domain::external::da_sampling::PinnedDaCommittee,
    ) {
        self.pinned_da_committees.insert(network.into(), committee);
    }

    /// Installs or updates the consensus-pinned `HotStuff` epoch committee for `network`.
    /// WIRING: governance/genesis `HotStuff` validator-set surface paired with `register_domain`.
    pub fn pin_hotstuff_committee(
        &mut self,
        network: impl Into<String>,
        committee: crate::cross_domain::external::hotstuff::PinnedHotStuffCommittee,
    ) {
        self.pinned_hotstuff_committees
            .insert(network.into(), committee);
    }

    /// Installs or updates the consensus-pinned Bullshark DAG-BFT committee for `network`.
    /// WIRING: governance/genesis DAG-BFT validator-set surface paired with `register_domain`.
    pub fn pin_dag_committee(
        &mut self,
        network: impl Into<String>,
        committee: crate::cross_domain::external::dag_bft::PinnedDagCommittee,
    ) {
        self.pinned_dag_committees.insert(network.into(), committee);
    }

    /// Installs or updates the consensus-pinned `Casper-FFG` epoch committee for `network`.
    /// WIRING: governance/genesis `Casper-FFG` validator-set surface paired with `register_domain`.
    pub fn pin_casper_ffg_committee(
        &mut self,
        network: impl Into<String>,
        committee: crate::cross_domain::external::casper_ffg::PinnedFfgCommittee,
    ) {
        self.pinned_casper_ffg_committees
            .insert(network.into(), committee);
    }

    /// Installs or updates the consensus-pinned `Mysticeti` `DAG` committee for `network`.
    /// WIRING: governance/genesis `Mysticeti` validator-set surface paired with `register_domain`.
    pub fn pin_mysticeti_committee(
        &mut self,
        network: impl Into<String>,
        committee: crate::cross_domain::external::mysticeti_dag::PinnedMysticetiCommittee,
    ) {
        self.pinned_mysticeti_committees
            .insert(network.into(), committee);
    }

    /// Installs or updates the consensus-pinned `BitVM2` `PoW` covenant anchor for `network`.
    /// WIRING: governance/genesis `BitVM2` checkpoint & program surface paired with `register_domain`.
    pub fn pin_bitvm_anchor(
        &mut self,
        network: impl Into<String>,
        anchor: crate::cross_domain::external::bitvm_covenant::PinnedBitVmAnchor,
    ) {
        self.pinned_bitvm_anchors.insert(network.into(), anchor);
    }

    /// Installs or updates the consensus-pinned Babylon EOTS epoch-key table
    /// for `network`. WIRING: governance/genesis EOTS pin paired with
    /// `register_domain`'s admission and `adjudicate_babylon_eots_equivocation`.
    pub fn pin_babylon_eots_anchor(
        &mut self,
        network: impl Into<String>,
        pinned: crate::cross_domain::external::babylon_eots::PinnedBabylonEots,
    ) {
        self.pinned_babylon_eots_anchors
            .insert(network.into(), pinned);
    }

    /// Installs or updates the consensus-pinned `NIPoPoW` genesis anchor and
    /// KMZ parameters for `network`. WIRING: genesis/test initializer; the
    /// production door is `GovernanceAction::PinExternalAnchor` ->
    /// [`Self::install_pinned_anchor`].
    pub fn pin_nipopow_genesis(
        &mut self,
        network: impl Into<String>,
        genesis: crate::cross_domain::external::nipopow::PinnedNipopowGenesis,
    ) {
        self.pinned_nipopow_genesis.insert(network.into(), genesis);
    }

    /// Installs the NIPoPoW pin for `network` only if it is a real trust root.
    ///
    /// `pin_nipopow_genesis` is the raw setter a genesis/test initializer uses;
    /// this is the checked door for anything that reaches the pin from a value
    /// it did not itself construct. A zeroed genesis id, a zero difficulty
    /// target, or `m = 0` / `k = 0` is the *shape* of an anchor with none of
    /// its force, and installing one would silently delete the KMZ predicate
    /// every proof against it is supposed to satisfy.
    ///
    /// # Errors
    ///
    /// The named zero field.
    pub fn install_nipopow_genesis(
        &mut self,
        network: impl Into<String>,
        genesis: crate::cross_domain::external::nipopow::PinnedNipopowGenesis,
    ) -> Result<(), String> {
        PinnedExternalAnchor::Nipopow(genesis.clone()).validate()?;
        self.pinned_nipopow_genesis.insert(network.into(), genesis);
        Ok(())
    }

    /// Installs or replaces a family's trust anchor for `network`.
    ///
    /// The consensus door: `GovernanceAction::PinExternalAnchor` in block
    /// execution is the only production caller. The four `pin_*` helpers above
    /// remain the genesis/test initializers; anything that can be reached from
    /// an operator RPC or a node-local flag would fork the chain, because these
    /// maps are inside `state_digest`. (`HotStuff` and DAG-BFT committees are not
    /// yet part of `PinnedExternalAnchor`/`AnchorFamily`; they stay genesis/test
    /// -only until their own governance door is added.)
    pub fn install_pinned_anchor(&mut self, network: &str, anchor: PinnedExternalAnchor) {
        match anchor {
            PinnedExternalAnchor::Ethereum(committee) => {
                self.pinned_ethereum_committees
                    .insert(network.to_string(), committee);
            }
            PinnedExternalAnchor::Bitcoin(checkpoint) => {
                self.pinned_bitcoin_anchors
                    .insert(network.to_string(), checkpoint);
            }
            PinnedExternalAnchor::Tendermint(anchor) => {
                self.pinned_tendermint_anchors
                    .insert(network.to_string(), anchor);
            }
            PinnedExternalAnchor::Da(committee) => {
                self.pinned_da_committees
                    .insert(network.to_string(), committee);
            }
            PinnedExternalAnchor::BabylonEots(pinned) => {
                self.pinned_babylon_eots_anchors
                    .insert(network.to_string(), pinned);
            }
            PinnedExternalAnchor::Nipopow(genesis) => {
                self.pinned_nipopow_genesis
                    .insert(network.to_string(), genesis);
            }
        }
    }

    /// The anchor installed for `family` on `network`, if any.
    ///
    /// WIRING: the production door is `pinned_anchor_digest` in this file,
    /// which `src/execution/executor.rs` calls; this lookup is its shared
    /// implementation (also exercised directly by this file's tests), not a
    /// second entry point.
    #[must_use]
    pub fn pinned_anchor(
        &self,
        family: AnchorFamily,
        network: &str,
    ) -> Option<PinnedExternalAnchor> {
        match family {
            AnchorFamily::Ethereum => self
                .pinned_ethereum_committees
                .get(network)
                .cloned()
                .map(PinnedExternalAnchor::Ethereum),
            AnchorFamily::Bitcoin => self
                .pinned_bitcoin_anchors
                .get(network)
                .cloned()
                .map(PinnedExternalAnchor::Bitcoin),
            AnchorFamily::Tendermint => self
                .pinned_tendermint_anchors
                .get(network)
                .cloned()
                .map(PinnedExternalAnchor::Tendermint),
            AnchorFamily::Da => self
                .pinned_da_committees
                .get(network)
                .cloned()
                .map(PinnedExternalAnchor::Da),
            AnchorFamily::BabylonEots => self
                .pinned_babylon_eots_anchors
                .get(network)
                .cloned()
                .map(PinnedExternalAnchor::BabylonEots),
            AnchorFamily::PoWSuccinct => self
                .pinned_nipopow_genesis
                .get(network)
                .cloned()
                .map(PinnedExternalAnchor::Nipopow),
        }
    }

    /// The digest of the anchor installed for `family` on `network`.
    ///
    /// `None` means the slot is empty. The executor compares this against the
    /// `expected_previous` a vote named before it installs a replacement.
    ///
    /// # Errors
    ///
    /// The encoder's message when the installed anchor cannot be encoded.
    pub fn pinned_anchor_digest(
        &self,
        family: AnchorFamily,
        network: &str,
    ) -> Result<Option<[u8; 32]>, String> {
        self.pinned_anchor(family, network)
            .map(|anchor| anchor.digest())
            .transpose()
    }

    /// Drives the registry clock from the block-import path. Called on every
    /// committed block; monotonicity is the registry's own rule. The quorum
    /// round sweep rides the same clock: rounds nobody finished are swept on
    /// the same schedule everywhere, or the digests diverge.
    pub fn on_block_committed(&mut self, height: u64) {
        self.registry.set_height(height);
        self.quorum.sweep(height);
        self.guard.sweep(height);
    }

    /// Registers an external domain end to end: build the adapter from its
    /// spec, run admission, and hand the passing report to the framework
    /// registry. One entry point, so a domain cannot exist in the registry
    /// without a rebuildable adapter spec beside it.
    ///
    /// # Errors
    ///
    /// [`IntakeError::AdmissionRefused`] when the self-test does not pass,
    /// [`IntakeError::MissingBlsVerifier`] when the spec needs pairing crypto
    /// the node did not install, and any [`RegistryError`] the framework
    /// refuses with.
    pub fn register_domain(
        &mut self,
        request: RegistrationRequest,
        bls: Option<Box<dyn BlsVerifier>>,
    ) -> Result<DomainKey, IntakeError> {
        let RegistrationRequest {
            spec,
            policy,
            economics,
            versions,
            bond_atoms,
            poster,
            golden,
        } = request;
        if matches!(spec, AdapterSpec::EthereumSync { .. }) && bls.is_none() {
            return Err(IntakeError::MissingBlsVerifier);
        }
        if matches!(spec, AdapterSpec::EthereumSync { .. })
            && bls.as_ref().is_some_and(|v| v.sync_committee_closed())
        {
            return Err(IntakeError::CommitteeNotPinned);
        }
        // EthereumSync admission requires a consensus/governance-pinned sync
        // committee for the target network; a permissionless registrant may not
        // supply its own aggregate key and certify its own Ethereum finality.
        if let AdapterSpec::EthereumSync { network, committee } = &spec {
            let Some(pinned) = self.pinned_ethereum_committees.get(network) else {
                return Err(IntakeError::CommitteeNotPinned);
            };
            let Some(requested) = committee else {
                return Err(IntakeError::CommitteeNotPinned);
            };
            if requested != pinned {
                return Err(IntakeError::CommitteeNotPinned);
            }
        }
        // ZkVm admission needs the pinned
        // program and chain - canonical-set membership alone attested
        // anything the prover's inputs named.
        if let AdapterSpec::ZkVm {
            program_hash,
            chain_id,
            ..
        } = &spec
        {
            if program_hash.is_none() || chain_id.is_none() {
                return Err(IntakeError::CommitteeNotPinned);
            }
        }
        // BitcoinSpv admission requires a governance-pinned checkpoint for `network`
        // so a permissionless registrant cannot install a low-work regtest anchor.
        if let AdapterSpec::BitcoinSpv { network, anchor } = &spec {
            let Some(pinned) = self.pinned_bitcoin_anchors.get(network) else {
                return Err(IntakeError::CommitteeNotPinned);
            };
            if anchor.as_ref() != Some(pinned) {
                return Err(IntakeError::CommitteeNotPinned);
            }
        }
        // TendermintCommit admission requires both a non-empty chain_id and a
        // governance-pinned validator_set_hash so an attacker cannot self-sign
        // an arbitrary commit with freshly generated Ed25519 keys.
        if let AdapterSpec::TendermintCommit {
            network,
            chain_id,
            validator_set_hash,
        } = &spec
        {
            if chain_id.trim().is_empty() {
                return Err(IntakeError::CommitteeNotPinned);
            }
            let Some(pinned) = self.pinned_tendermint_anchors.get(network) else {
                return Err(IntakeError::CommitteeNotPinned);
            };
            if pinned.chain_id != *chain_id
                || pinned.validator_set_hash == [0u8; 32]
                || *validator_set_hash != Some(pinned.validator_set_hash)
            {
                return Err(IntakeError::CommitteeNotPinned);
            }
        }
        // DataAvailability admission requires a governance-pinned namespace and
        // slashable attestation committee for `network`.
        if let AdapterSpec::DataAvailability { network, committee } = &spec {
            let Some(pinned) = self.pinned_da_committees.get(network) else {
                return Err(IntakeError::CommitteeNotPinned);
            };
            if committee.as_ref() != Some(pinned) {
                return Err(IntakeError::CommitteeNotPinned);
            }
        }
        // HotStuffQc admission requires a governance-pinned epoch validator set.
        if let AdapterSpec::HotStuffQc { network, committee } = &spec {
            let Some(pinned) = self.pinned_hotstuff_committees.get(network) else {
                return Err(IntakeError::CommitteeNotPinned);
            };
            if committee.as_ref() != Some(pinned) {
                return Err(IntakeError::CommitteeNotPinned);
            }
        }
        // DagCertificate admission requires a governance-pinned round-DAG committee.
        if let AdapterSpec::DagCertificate { network, committee } = &spec {
            let Some(pinned) = self.pinned_dag_committees.get(network) else {
                return Err(IntakeError::CommitteeNotPinned);
            };
            if committee.as_ref() != Some(pinned) {
                return Err(IntakeError::CommitteeNotPinned);
            }
        }
        // CasperFfg admission requires a governance-pinned epoch committee.
        if let AdapterSpec::CasperFfg { network, committee } = &spec {
            let Some(pinned) = self.pinned_casper_ffg_committees.get(network) else {
                return Err(IntakeError::CommitteeNotPinned);
            };
            if committee.as_ref() != Some(pinned) {
                return Err(IntakeError::CommitteeNotPinned);
            }
        }
        // MysticetiDag admission requires a governance-pinned epoch committee.
        if let AdapterSpec::MysticetiDag { network, committee } = &spec {
            let Some(pinned) = self.pinned_mysticeti_committees.get(network) else {
                return Err(IntakeError::CommitteeNotPinned);
            };
            if committee.as_ref() != Some(pinned) {
                return Err(IntakeError::CommitteeNotPinned);
            }
        }
        // BitVmCovenant admission requires a governance-pinned PoW + program anchor.
        if let AdapterSpec::BitVmCovenant { network, anchor } = &spec {
            let Some(pinned) = self.pinned_bitvm_anchors.get(network) else {
                return Err(IntakeError::CommitteeNotPinned);
            };
            if anchor.as_ref() != Some(pinned) {
                return Err(IntakeError::CommitteeNotPinned);
            }
        }
        // BabylonEots admission requires a governance-pinned epoch-key table and
        // Bitcoin weak-subjectivity anchor for `network`; a permissionless
        // registrant cannot announce its own EOTS keys and certify finality.
        if let AdapterSpec::BabylonEots { network, pinned } = &spec {
            let Some(installed) = self.pinned_babylon_eots_anchors.get(network) else {
                return Err(IntakeError::CommitteeNotPinned);
            };
            if pinned.as_ref() != Some(installed) {
                return Err(IntakeError::CommitteeNotPinned);
            }
        }
        // NipopowSuperblock admission requires a governance-pinned genesis and
        // KMZ `(m, k)` set for `network`, and the spec must carry exactly that
        // pin: a registrant may not bring its own genesis and certify the
        // superblock proof against it.
        if let AdapterSpec::NipopowSuperblock { network, genesis } = &spec {
            let Some(installed) = self.pinned_nipopow_genesis.get(network) else {
                return Err(IntakeError::CommitteeNotPinned);
            };
            if genesis.as_ref() != Some(installed) {
                return Err(IntakeError::CommitteeNotPinned);
            }
        }
        // Economics under which lying pays are refused at the door. The
        // framework checks the bond amount; whether the fee/penalty shape
        // rewards honesty is a question only the intake asks, because the
        // framework cannot know the chain's stance on it.
        if !honesty_is_cheaper(&economics, economics.routing_ceiling_atoms) {
            return Err(IntakeError::DishonestEconomics);
        }
        let adapter = spec.build(bls, Some(golden.clone()));
        let admission = admit(adapter.as_ref(), &policy);
        if !admission.admitted {
            return Err(IntakeError::AdmissionRefused {
                golden_verified: admission.golden_verified,
                passed: admission.passed(),
                total: admission.total(),
                failing: admission.failing_probe_names(),
            });
        }
        let descriptor = adapter.descriptor();
        let key = self.registry.register(
            spec.network(),
            descriptor,
            economics,
            versions,
            &admission,
            bond_atoms,
            poster,
        )?;
        self.entries.insert(
            key,
            IntakeEntry {
                spec,
                policy,
                admission,
                golden,
                registrant: poster,
            },
        );
        Ok(key)
    }

    /// Submits evidence for a registered domain. The adapter is rebuilt from
    /// the stored spec on every call: stateless by construction, so restart
    /// and replay cannot diverge from live operation.
    ///
    /// A domain with a quorum policy takes the round path instead: the
    /// evidence is verified the same way, but the verdict enters the round
    /// for its height rather than the attestation book, and nothing is
    /// committed until the round decides. The single-submission path stays
    /// for domains without a policy - a proven domain does not need votes,
    /// and forcing it through rounds would be theatre.
    ///
    /// # Errors
    ///
    /// [`IntakeError::UnknownDomain`] when nothing is registered under the
    /// key the evidence derives, and every refusal the framework registry
    /// can produce. On the quorum path, adapter refusals are folded into the
    /// round as answers rather than returned - a refusal there is a vote,
    /// not an error - and only round-boundary problems ([`RoundError`])
    /// surface.
    pub fn submit_evidence(
        &mut self,
        evidence: &RawConsensusEvidence,
        bls: Option<Box<dyn BlsVerifier>>,
    ) -> Result<FinalityAttestation, IntakeError> {
        let key = DomainKey::from_parts(&evidence.adapter, &evidence.network);
        let Some(entry) = self.entries.get(&key) else {
            return Err(IntakeError::UnknownDomain);
        };
        let local_height = self.registry.height();
        self.guard.check_submission(&key, local_height)?;
        if matches!(entry.spec, AdapterSpec::EthereumSync { .. }) && bls.is_none() {
            return Err(IntakeError::MissingBlsVerifier);
        }
        if matches!(entry.spec, AdapterSpec::EthereumSync { .. })
            && bls.as_ref().is_some_and(|v| v.sync_committee_closed())
        {
            return Err(IntakeError::CommitteeNotPinned);
        }
        let adapter = entry.spec.build(bls, None);
        // `now` is the live clock, not the
        // registration timestamp. A policy stored `now` forever, so
        // `max_age` was measured against a frozen instant and newer evidence
        // saturated the age subtraction to 0 - freshness was dead in
        // practice. The deterministic clock Budlum has is the domain's own
        // accepted tip: every node replays the same acceptances, so every
        // node measures age against the same height. Until the domain has an
        // accepted attestation the stored value stays (registration-time
        // admission used it deliberately).
        let mut policy = entry.policy.clone();
        let time_unit = adapter.descriptor().time_unit;
        policy.now = live_policy_clock(
            policy.now,
            self.registry
                .domain(&key)
                .and_then(|reg| accepted_policy_clock_tip(reg, time_unit)),
        );
        if self.quorum.policy_of(&key).is_some() {
            // When the round takes the answer without deciding yet, refuse with a
            // named state rather than inventing a partial attestation; RPC reports
            // the round state through `bud_getExternalQuorumRound`.
            return self
                .submit_to_round(key, evidence, adapter.as_ref(), &policy)?
                .ok_or(IntakeError::RoundPending);
        }
        if self
            .guard
            .record_of(&key)
            .is_some_and(|r| !r.contradicted_claims.is_empty())
        {
            if let Ok(candidate) = adapter.verify(evidence, &policy) {
                self.guard.check_claim_allowed(
                    &key,
                    candidate.height,
                    candidate.evidence_version,
                    &candidate.claim_digest(),
                )?;
            }
        }
        Ok(self.registry.submit(adapter.as_ref(), evidence, &policy)?)
    }

    /// Cryptographically verify a contradicting finality proof against the same
    /// domain adapter at an already-accepted `(height, evidence_version)` and,
    /// when it certifies a distinct `state_root`, atomically withdraw the false
    /// attestation, slash its bonded carrier at the domain's routing ceiling,
    /// and transition the domain to [`crate::cross_domain::external::profile::DomainState::Faulted`].
    ///
    /// Security invariants:
    /// 1. The contradicting evidence MUST pass full cryptographic adapter
    ///    verification with `max_age = 0` (so historic equivocations remain
    ///    slashable after time advances) and `require_declared_match = true`.
    /// 2. The evidence format version MUST lie inside the domain's declared
    ///    version window for `height`.
    /// 3. Self-challenge (`challenger == carrier`) is unconditionally forbidden
    ///    so a dishonest prover cannot reclaim the challenger reward share.
    /// 4. State-root divergence is evaluated via [`subtle::ConstantTimeEq`].
    /// 5. For `PoW` domains, the contradicting proof must carry strictly more
    ///    accumulated difficulty bits than the accepted attestation. Equal
    ///    work is the external chain's own tie, which proves no carrier
    ///    false, so a sibling at the same height cannot slash.
    /// 6. The penalty is always computed at `economics.routing_ceiling_atoms`
    ///    so a colluding front-runner cannot dust-slash for 1 atom.
    ///
    /// # Errors
    ///
    /// Returns [`IntakeError`] leaving `self` unchanged if any check fails.
    pub fn slash_on_contradiction(
        &mut self,
        contradicting: &RawConsensusEvidence,
        challenger: Address,
        bls: Option<Box<dyn BlsVerifier>>,
    ) -> Result<ContradictionSlashOutcome, IntakeError> {
        if contradicting.submitter != challenger {
            return Err(IntakeError::InvalidContradiction {
                reason: "contradiction evidence submitter must match challenger".to_string(),
            });
        }
        let key = DomainKey::from_parts(&contradicting.adapter, &contradicting.network);
        let Some(entry) = self.entries.get(&key) else {
            return Err(IntakeError::UnknownDomain);
        };
        if matches!(entry.spec, AdapterSpec::EthereumSync { .. }) && bls.is_none() {
            return Err(IntakeError::MissingBlsVerifier);
        }
        if matches!(entry.spec, AdapterSpec::EthereumSync { .. })
            && bls.as_ref().is_some_and(|v| v.sync_committee_closed())
        {
            return Err(IntakeError::CommitteeNotPinned);
        }
        let Some(reg) = self.registry.domain(&key) else {
            return Err(IntakeError::UnknownDomain);
        };
        let slot = (
            contradicting.declared_height,
            contradicting.evidence_version,
        );
        let Some(existing) = reg.attestations.get(&slot).cloned() else {
            return Err(IntakeError::InvalidContradiction {
                reason: format!(
                    "no accepted attestation at external height {} version {}",
                    slot.0, slot.1
                ),
            });
        };
        let Some(slashed_prover) = reg
            .attestation_provers
            .get(&existing.evidence_digest)
            .copied()
        else {
            return Err(IntakeError::MissingCarrier);
        };
        if slashed_prover == Address::zero() {
            return Err(IntakeError::MissingCarrier);
        }
        if slashed_prover == challenger {
            return Err(IntakeError::SelfChallengeForbidden);
        }
        reg.versions
            .gate(
                contradicting.evidence_version,
                contradicting.declared_height,
            )
            .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        let value_atoms = reg.economics.routing_ceiling_atoms;

        let adapter = entry.spec.build(bls, None);
        let mut challenge_policy = entry.policy.clone();
        challenge_policy.max_age = 0;
        challenge_policy.require_declared_match = true;
        let verified = adapter
            .verify(contradicting, &challenge_policy)
            .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;

        if verified.domain != existing.domain
            || verified.adapter != existing.adapter
            || verified.height != existing.height
            || verified.evidence_version != existing.evidence_version
        {
            return Err(IntakeError::InvalidContradiction {
                reason: "verified challenge attestation does not target the same domain slot"
                    .to_string(),
            });
        }
        if verified.commits_same_roots(&existing) {
            return Err(IntakeError::InvalidContradiction {
                reason: "challenge attestation commits identical state_root and attested sub-roots"
                    .to_string(),
            });
        }
        if let SecurityBacking::Work {
            difficulty_bits: accepted_bits,
        } = existing.security
        {
            if !out_works(accepted_bits, &verified.security) {
                return Err(IntakeError::InvalidContradiction {
                    reason: format!(
                        "PoW contradiction must carry more than {accepted_bits} difficulty bits"
                    ),
                });
            }
        }

        let registry_before = self.registry.clone();
        let (slashed_atoms, challenger_reward_atoms) =
            match self.registry.slash_verified_contradiction(
                &key,
                slashed_prover,
                existing.evidence_digest,
                value_atoms,
                challenger,
            ) {
                Ok(amounts) => amounts,
                Err(err) => {
                    self.registry = registry_before;
                    return Err(IntakeError::Registry(err));
                }
            };
        if let Err(err) = self.registry.mark_faulted(
            &key,
            &format!(
                "cryptographic contradiction proven at external height {} (version {})",
                existing.height, existing.evidence_version
            ),
        ) {
            self.registry = registry_before;
            return Err(IntakeError::Registry(err));
        }

        let local_height = self.registry.height();
        let _cooldown_until = self.guard.record_contradiction(
            key,
            existing.height,
            existing.evidence_version,
            existing.claim_digest(),
            local_height,
        );

        Ok(ContradictionSlashOutcome {
            domain: key,
            slashed_prover,
            contradicted_digest: existing.evidence_digest,
            height: existing.height,
            evidence_version: existing.evidence_version,
            slashed_atoms,
            challenger_reward_atoms,
        })
    }

    /// Refute an accepted attestation with the successor that descends from a
    /// different parent.
    ///
    /// [`Self::slash_on_contradiction`] can only answer a challenge aimed at the
    /// slot the false claim occupies, so a claim whose slot the external chain
    /// has moved past - an abandoned branch - stays in the book and its carrier
    /// keeps the bond. This door takes the successor instead: evidence its own
    /// adapter accepts, one height above the challenged slot, whose verified
    /// parent digest disagrees with the block the challenged slot attested.
    ///
    /// Idempotency has two independent mechanisms. A first refutation withdraws
    /// the predecessor from the book, so a replay finds no accepted attestation
    /// at that slot; and every ruling is tombstoned in
    /// [`IntakeGuard::record_contradiction`] under the challenged claim digest.
    ///
    /// A proof-of-work predecessor is refused outright. Adjacency makes the
    /// witness exactly one block longer than the attested chain, so every
    /// honest one-block fork descends from "a different parent", and a
    /// difficulty comparison between the two windows measures that extra block
    /// and not a reorg. Work is refuted only by a witness that out-works the
    /// attested branch by a margin, which a one-successor challenge cannot
    /// carry.
    ///
    /// # Errors
    ///
    /// [`IntakeError::UnknownDomain`], [`IntakeError::MissingCarrier`],
    /// [`IntakeError::SelfChallengeForbidden`], [`IntakeError::CommitteeNotPinned`],
    /// [`IntakeError::MissingBlsVerifier`], a registry or adapter refusal, or
    /// [`IntakeError::InvalidContradiction`] naming the rule the witness failed.
    pub fn adjudicate_ancestry(
        &mut self,
        successor: &RawConsensusEvidence,
        challenger: Address,
        bls: Option<Box<dyn BlsVerifier>>,
    ) -> Result<ContradictionSlashOutcome, IntakeError> {
        if successor.submitter != challenger {
            return Err(IntakeError::InvalidContradiction {
                reason: "ancestry witness submitter must match challenger".to_string(),
            });
        }
        let key = DomainKey::from_parts(&successor.adapter, &successor.network);
        let Some((spec, policy)) = self
            .entries
            .get(&key)
            .map(|entry| (entry.spec.clone(), entry.policy.clone()))
        else {
            return Err(IntakeError::UnknownDomain);
        };
        if matches!(spec, AdapterSpec::EthereumSync { .. }) && bls.is_none() {
            return Err(IntakeError::MissingBlsVerifier);
        }
        if matches!(spec, AdapterSpec::EthereumSync { .. })
            && bls.as_ref().is_some_and(|v| v.sync_committee_closed())
        {
            return Err(IntakeError::CommitteeNotPinned);
        }
        let Some(reg) = self.registry.domain(&key) else {
            return Err(IntakeError::UnknownDomain);
        };
        let value_atoms = reg.economics.routing_ceiling_atoms;

        let adapter = spec.build(bls, None);
        let mut challenge_policy = policy;
        challenge_policy.max_age = 0;
        challenge_policy.require_declared_match = true;
        let verified = adapter
            .verify(successor, &challenge_policy)
            .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        if verified.height == 0 {
            return Err(IntakeError::InvalidContradiction {
                reason: "an ancestry witness needs a predecessor height".to_string(),
            });
        }
        let parent = adapter.attested_parent(successor);

        let predecessor_slot = (verified.height - 1, verified.evidence_version);
        let Some(predecessor) = reg.attestations.get(&predecessor_slot).cloned() else {
            return Err(IntakeError::InvalidContradiction {
                reason: format!(
                    "no accepted attestation at predecessor height {} version {}",
                    predecessor_slot.0, predecessor_slot.1
                ),
            });
        };
        if matches!(predecessor.security, SecurityBacking::Work { .. }) {
            return Err(IntakeError::InvalidContradiction {
                reason: "a proof-of-work attestation cannot be refuted by its adjacent \
                         successor: the successor is one block longer by construction, so \
                         only a witness that out-works the attested branch by a margin \
                         could decide"
                    .to_string(),
            });
        }
        let Some(slashed_prover) = reg
            .attestation_provers
            .get(&predecessor.evidence_digest)
            .copied()
        else {
            return Err(IntakeError::MissingCarrier);
        };
        if slashed_prover == Address::zero() {
            return Err(IntakeError::MissingCarrier);
        }
        reg.versions
            .gate(verified.evidence_version, verified.height)
            .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;

        let book_slot = crate::cross_domain::external::falsity::BookSlot {
            domain: predecessor.domain,
            adapter: predecessor.adapter,
            height: predecessor.height,
            evidence_version: predecessor.evidence_version,
            evidence_digest: predecessor.evidence_digest,
            carrier: slashed_prover,
            attested_block_hash: predecessor.attested_block_hash,
        };
        let witness = crate::cross_domain::external::falsity::SuccessorView {
            domain: verified.domain,
            adapter: verified.adapter,
            height: verified.height,
            evidence_version: verified.evidence_version,
            evidence_digest: verified.evidence_digest,
            carrier: successor.submitter,
            attested_parent: parent,
        };
        let ruling = crate::cross_domain::external::falsity::adjudicate(
            &witness,
            &book_slot,
            challenger,
            &std::collections::BTreeSet::new(),
        );
        if let crate::cross_domain::external::falsity::Ruling::Refused(refusal) = ruling {
            return Err(IntakeError::InvalidContradiction {
                reason: refusal.reason().to_string(),
            });
        }

        let registry_before = self.registry.clone();
        let (slashed_atoms, challenger_reward_atoms) =
            match self.registry.slash_verified_contradiction(
                &key,
                slashed_prover,
                predecessor.evidence_digest,
                value_atoms,
                challenger,
            ) {
                Ok(amounts) => amounts,
                Err(err) => {
                    self.registry = registry_before;
                    return Err(IntakeError::Registry(err));
                }
            };
        if let Err(err) = self.registry.mark_faulted(
            &key,
            &format!(
                "ancestry refutation at external height {} (successor {})",
                predecessor.height, verified.height
            ),
        ) {
            self.registry = registry_before;
            return Err(IntakeError::Registry(err));
        }
        let local_height = self.registry.height();
        let _cooldown_until = self.guard.record_contradiction(
            key,
            predecessor.height,
            predecessor.evidence_version,
            predecessor.claim_digest(),
            local_height,
        );

        Ok(ContradictionSlashOutcome {
            domain: key,
            slashed_prover,
            contradicted_digest: predecessor.evidence_digest,
            height: predecessor.height,
            evidence_version: predecessor.evidence_version,
            slashed_atoms,
            challenger_reward_atoms,
        })
    }

    /// The round path of [`Self::submit_evidence`]. Verifies without
    /// committing, folds the verdict into the round, and acts on what the
    /// round became:
    ///
    /// - `AgreedClaim` -> the winning attestation is committed to the book
    ///   under the first carrier of the winning claim, and returned;
    /// - `AgreedRefusal` -> the round closed negatively; nothing commits;
    /// - `Disputed` -> the domain is marked faulted with the round named in
    ///   the reason, and stays so until the challenge game resolves it;
    /// - `Open` -> the answer was recorded; nothing more to do yet.
    fn submit_to_round(
        &mut self,
        key: DomainKey,
        evidence: &RawConsensusEvidence,
        adapter: &dyn ExternalFinalityAdapter,
        policy: &VerificationPolicy,
    ) -> Result<Option<FinalityAttestation>, IntakeError> {
        let verdict = self.registry.evaluate(adapter, evidence, policy);
        // Boundary refusals that are not answers about the claim must not
        // enter the round at all: an unknown domain or an unbonded prover is
        // the caller's problem, not a vote. The quorum fold handles adapter
        // errors; registry-level refusals surface here.
        if let Err(err) = &verdict {
            if !matches!(err, RegistryError::Adapter(_)) {
                return Err(IntakeError::Registry(err.clone()));
            }
        }
        let verdict_for_round = match &verdict {
            Ok(att) => Ok(att.clone()),
            Err(RegistryError::Adapter(adapter_err)) => Err(adapter_err.clone()),
            // Unreachable by the early return above; refusing loudly beats
            // a quiet wrong vote.
            Err(other) => return Err(IntakeError::Registry(other.clone())),
        };
        let local_height = self.registry.height();
        // The round is already AgreedClaim
        // or Disputed when a later step fails, and the error path used to
        // persist that half-applied state - a round that says agreed with
        // nothing committed, refusing every later vote. The quorum fold is
        // transactional: if the consequence (commit, fault) fails, the round
        // goes back to what it was before the vote was folded.
        let quorum_before = self.quorum.clone();
        let fold = self
            .quorum
            .submit(key, evidence, &verdict_for_round, local_height);
        let state = match fold {
            Ok(state) => state,
            Err(err) => {
                self.quorum = quorum_before;
                return Err(err.into());
            }
        };
        let outcome = match state {
            RoundState::AgreedClaim { attestation, .. } => {
                let winner = *attestation;
                let winner_claim = winner.claim_digest();
                if let Err(err) = self.guard.check_claim_allowed(
                    &key,
                    winner.height,
                    winner.evidence_version,
                    &winner_claim,
                ) {
                    self.quorum = quorum_before;
                    return Err(IntakeError::Guard(err));
                }
                // The carrier is the first prover whose full claim digest
                // matches the winner. A missing one breaks a round invariant,
                // so it is refused instead of crediting whoever closed the round.
                let Some(carrier) = self
                    .quorum
                    .round_of(&key, evidence.declared_height)
                    .and_then(|round| first_carrier(round, &winner_claim))
                else {
                    self.quorum = quorum_before;
                    return Err(IntakeError::MissingCarrier);
                };
                match self.registry.commit_attestation(&winner, carrier) {
                    Ok(()) => Ok(Some(winner)),
                    Err(err) => {
                        self.quorum = quorum_before;
                        Err(IntakeError::Registry(err))
                    }
                }
            }
            RoundState::Disputed => {
                // The fault reason names the groups by their stable keys, so
                // the history entry reads as evidence, not as a shrug.
                let standings = self
                    .quorum
                    .round_of(&key, evidence.declared_height)
                    .map(|round| {
                        round
                            .entries
                            .iter()
                            .map(|e| e.answer.group_key())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let guard_before = self.guard.clone();
                let _tripped = self.guard.record_adverse_round(key, local_height);
                match self.registry.mark_faulted(
                    &key,
                    &format!(
                        "quorum round at external height {} froze in dispute; answers: [{standings}]",
                        evidence.declared_height
                    ),
                ) {
                    Ok(()) => Ok(None),
                    Err(err) => {
                        self.quorum = quorum_before;
                        self.guard = guard_before;
                        Err(IntakeError::Registry(err))
                    }
                }
            }
            RoundState::AgreedRefusal { .. } => {
                let guard_before = self.guard.clone();
                if self.guard.record_adverse_round(key, local_height) {
                    if let Err(err) = self.registry.mark_faulted(
                        &key,
                        &format!(
                            "intake guard tripped after repeated adverse quorum rounds at local block {local_height}"
                        ),
                    ) {
                        self.quorum = quorum_before;
                        self.guard = guard_before;
                        return Err(IntakeError::Registry(err));
                    }
                }
                Ok(None)
            }
            RoundState::Open => Ok(None),
        };
        outcome
    }

    /// Bonds an additional prover to a registered domain. Registration
    /// bonds the poster; a quorum needs several bonded provers, and this is
    /// their door. Thin delegation, kept on the intake so `Blockchain`
    /// talks to one surface.
    ///
    /// # Errors
    ///
    /// The registry's refusals: unknown domain, insufficient bond, or a
    /// prover that is already bonded here.
    pub fn bond_prover(
        &mut self,
        key: &DomainKey,
        prover: Address,
        bond_atoms: u128,
    ) -> Result<(), IntakeError> {
        self.registry
            .bond_prover(key, prover, bond_atoms)
            .map_err(IntakeError::Registry)
    }

    /// Installs a quorum policy for one domain, turning its submissions into
    /// multi-prover rounds. Consensus action: reached through the chain
    /// actor, never set locally, for the same reason registration is.
    ///
    /// # Errors
    ///
    /// [`IntakeError::UnknownDomain`] for a domain that was never
    /// registered: a policy for nothing would be a silent no-op that reads
    /// as protection.
    pub fn set_quorum_policy(
        &mut self,
        key: &DomainKey,
        policy: QuorumPolicy,
    ) -> Result<(), IntakeError> {
        if !self.entries.contains_key(key) {
            return Err(IntakeError::UnknownDomain);
        }
        // The intake commits winning claims to the attestation book, and the
        // quorum module's own docs name the rule: `AcceptMostCommon` is
        // "never for a state root that will be committed to".
        // That refusal is enforced by `QuorumRounds::set_policy`
        // itself - the pub setter used to bypass it - and the intake maps it
        // to its own named error. The shape rules below are this surface's
        // own: it is the surface that commits.
        if policy.agreement_threshold == 0 {
            return Err(IntakeError::InvalidQuorumPolicy {
                reason: "the agreement threshold is zero",
            });
        }
        if policy.agreement_threshold > policy.max_participants {
            return Err(IntakeError::InvalidQuorumPolicy {
                reason: "the threshold is above the number of seats",
            });
        }
        if policy.max_participants > MAX_QUORUM_PARTICIPANTS {
            return Err(IntakeError::InvalidQuorumPolicy {
                reason: "too many seats",
            });
        }
        // A threshold at or below half of the seats lets two rival groups
        // both reach it, so the first group to fill wins a race.
        if policy.agreement_threshold <= policy.max_participants / 2 {
            return Err(IntakeError::InvalidQuorumPolicy {
                reason: "the threshold is not a strict majority of the seats",
            });
        }
        // The intake commits winning claims to the attestation book, and the
        // quorum module's own docs name the rule: `AcceptMostCommon` is
        // "never for a state root that will be committed to". A policy that
        // shrugs at disputes is not protection, it is the appearance of it.
        // `QuorumRounds::set_policy` is `pub(super)`, so
        // this refusal cannot be bypassed from outside the module. It is
        // categorical - refused whatever the bonded seats are - so it is
        // named before the state-dependent feasibility check below, which
        // would otherwise shadow it behind "fewer provers are bonded".
        if matches!(policy.dispute, DisputeBehavior::AcceptMostCommon)
            || matches!(
                policy.low_participants,
                LowParticipantsBehavior::AcceptMostCommon
            )
        {
            return Err(IntakeError::PermissiveQuorumPolicy);
        }
        let bonded = self.registry.domain(key).map_or(0, |reg| reg.provers.len());
        if policy.agreement_threshold > bonded {
            return Err(IntakeError::InvalidQuorumPolicy {
                reason: "fewer provers are bonded than the threshold needs",
            });
        }
        // Attestations accepted before this policy existed were decided by a
        // single prover rather than a quorum round. Withdraw them so they
        // neither satisfy the commitment gate nor block honest rounds at those
        // `(height, version)` slots.
        if let Some(reg) = self.registry.domain_mut(key) {
            let withdrawn_digests: Vec<[u8; 32]> = reg
                .attestations
                .values()
                .map(|att| att.evidence_digest)
                .collect();
            for digest in withdrawn_digests {
                let was_slashed = reg
                    .provers
                    .values()
                    .flat_map(|b| &b.slashings)
                    .any(|s| s.evidence_digest == digest);
                if !was_slashed {
                    reg.attestation_provers.remove(&digest);
                }
            }
            reg.attestations.clear();
        }
        self.quorum.set_policy(*key, policy);
        Ok(())
    }

    /// The retained round for one domain and external height, with the key
    /// type the round book uses. Read path for `Blockchain`.
    #[must_use]
    pub fn quorum_round(
        &self,
        round_key: &RoundKey,
    ) -> Option<&crate::cross_domain::external::intake_quorum::QuorumRound> {
        self.quorum.rounds.get(round_key)
    }

    /// Replaces one domain's version policy after a scheduled fork. Thin
    /// delegation, kept on the intake so `Blockchain` talks to one surface.
    ///
    /// # Errors
    ///
    /// The registry's refusals, stringified at this boundary like the
    /// blockchain's other actor-facing methods.
    pub fn set_version_policy(
        &mut self,
        key: &DomainKey,
        versions: VersionPolicy,
    ) -> Result<(), String> {
        self.registry
            .set_version_policy(key, versions)
            .map_err(|e| e.to_string())
    }

    /// The descriptor a registered domain was admitted under, for the RPC
    /// surface. Reads the stored entry rather than rebuilding the adapter:
    /// display must not require crypto to be installed.
    #[must_use]
    pub fn descriptor_of(&self, key: &DomainKey) -> Option<AdapterDescriptor> {
        self.registry
            .domain(key)
            .map(|reg| reg.record.descriptor.clone())
    }

    /// A deterministic digest over the whole intake state. This is the
    /// commitment consumers compare until a header root is earned (see the
    /// module docs for why the header is not extended yet). Bincode over a
    /// `BTreeMap`-backed structure is order-stable, so two nodes that applied
    /// the same events fold the same bytes.
    ///
    /// # Errors
    ///
    /// Returns the serializer's message when the state cannot be encoded;
    /// callers surface it rather than substituting a default digest, because
    /// a digest that silently becomes constant is worse than an error.
    pub fn state_digest(&self) -> Result<[u8; 32], String> {
        let bytes = bincode::serialize(self).map_err(|e| e.to_string())?;
        Ok(hash_fields_bytes(&[b"BDLM_EXTERNAL_INTAKE_V1", &bytes]))
    }

    /// Constructs the node's production BLS verifier. One function, so the
    /// call sites (chain actor, RPC) cannot end up with two different pairing
    /// configurations for the same chain.
    #[must_use]
    pub fn production_bls() -> Box<dyn BlsVerifier> {
        Box::new(PairingBls)
    }

    /// Default economics for a newly proposed domain: a conservative ceiling
    /// with fee and challenge terms under which honesty is provably cheaper.
    /// Callers may pass their own; this exists so a registrant has one
    /// documented starting point instead of five magic numbers.
    /// Convenience: the starting economics a registrant's client builds an `ExternalDomainTx::Register` from; the RPC that used it is a transaction now.
    #[must_use]
    pub const fn conservative_economics(routing_ceiling_atoms: u128) -> DomainEconomics {
        DomainEconomics {
            routing_ceiling_atoms,
            fee: ProverFee {
                base_atoms: 1,
                value_bps: 10,
            },
            challenge: ChallengeReward {
                bps_of_slash: 500,
                floor_atoms: 1,
            },
            unbonding_heights: 1000,
        }
    }

    fn serving_entry(&self, key: &DomainKey) -> Result<(&IntakeEntry, &str), IntakeError> {
        let Some(entry) = self.entries.get(key) else {
            return Err(IntakeError::UnknownDomain);
        };
        let Some(reg) = self.registry.domain(key) else {
            return Err(IntakeError::UnknownDomain);
        };
        if !reg.record.state.serves() {
            return Err(IntakeError::Registry(RegistryError::NotServing {
                state: format!("{:?}", reg.record.state),
            }));
        }
        Ok((entry, reg.record.descriptor.name.as_str()))
    }

    /// Verify objective `HotStuff` same-view double-vote equivocation against
    /// the domain's pinned committee and freeze the domain.
    ///
    /// WIRING: objective `HotStuff` equivocation door freezing `AdapterSpec::HotStuffQc` domains (wired via `ExternalDomainTx::SubmitFaultProof`).
    ///
    /// # Errors
    ///
    /// Returns [`IntakeError`] if `key` is unknown, not serving, not a
    /// `HotStuffQc` domain, unpinned, or `proof` fails cryptographic
    /// equivocation verification.
    pub fn adjudicate_hotstuff_equivocation(
        &mut self,
        key: &DomainKey,
        proof: &crate::cross_domain::external::hotstuff::HotStuffEquivocationProof,
    ) -> Result<([u8; 32], u64), IntakeError> {
        let (entry, expected_name) = self.serving_entry(key)?;
        let AdapterSpec::HotStuffQc { network, committee } = &entry.spec else {
            return Err(IntakeError::Registry(RegistryError::DescriptorMismatch {
                expected: expected_name.to_string(),
                found: crate::cross_domain::external::hotstuff::ADAPTER_NAME.to_string(),
            }));
        };
        let Some(pinned) = committee else {
            return Err(IntakeError::CommitteeNotPinned);
        };
        let (offender, weight) =
            crate::cross_domain::external::hotstuff::verify_hotstuff_equivocation(
                network, pinned, proof,
            )
            .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        let local_height = self.registry.height();
        let _ = self.guard.record_adverse_round(*key, local_height);
        self.registry
            .mark_faulted(
                key,
                &format!(
                    "HotStuff validator {} equivocated at epoch {} view {} (weight={weight})",
                    hex::encode(offender),
                    proof.epoch,
                    proof.view
                ),
            )
            .map_err(IntakeError::Registry)?;
        Ok((offender, weight))
    }

    /// Verify objective `Casper-FFG` double-vote or surround-vote slashing
    /// evidence against the domain's pinned committee and freeze the domain.
    ///
    /// WIRING: objective `Casper-FFG` equivocation door freezing `AdapterSpec::CasperFfg` domains (wired via `ExternalDomainTx::SubmitFaultProof`).
    ///
    /// # Errors
    ///
    /// Returns [`IntakeError`] if `key` is unknown, not serving, not a
    /// `CasperFfg` domain, unpinned, or `evidence` fails cryptographic
    /// slashing verification.
    pub fn adjudicate_casper_ffg_equivocation(
        &mut self,
        key: &DomainKey,
        evidence: &crate::cross_domain::external::casper_ffg::FfgEquivocationProof,
    ) -> Result<
        (
            crate::cross_domain::external::casper_ffg::FfgSlashingKind,
            u64,
        ),
        IntakeError,
    > {
        let (entry, expected_name) = self.serving_entry(key)?;
        let AdapterSpec::CasperFfg { network, committee } = &entry.spec else {
            return Err(IntakeError::Registry(RegistryError::DescriptorMismatch {
                expected: expected_name.to_string(),
                found: crate::cross_domain::external::casper_ffg::CASPER_FFG_ADAPTER_NAME
                    .to_string(),
            }));
        };
        let Some(pinned) = committee else {
            return Err(IntakeError::CommitteeNotPinned);
        };
        let (kind, weight) =
            crate::cross_domain::external::casper_ffg::verify_ffg_slashing_evidence(
                network, pinned, evidence,
            )
            .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        let local_height = self.registry.height();
        let _ = self.guard.record_adverse_round(*key, local_height);
        self.registry
            .mark_faulted(
                key,
                &format!(
                    "Casper-FFG validator {} equivocated ({kind:?}, stake={weight})",
                    hex::encode(evidence.vote_a.signer)
                ),
            )
            .map_err(IntakeError::Registry)?;
        Ok((kind, weight))
    }

    /// Verify objective `Mysticeti` same-round `DAG` equivocation against the
    /// domain's pinned committee and freeze the domain.
    ///
    /// WIRING: objective `Mysticeti` equivocation door freezing `AdapterSpec::MysticetiDag` domains (wired via `ExternalDomainTx::SubmitFaultProof`).
    ///
    /// # Errors
    ///
    /// Returns [`IntakeError`] if `key` is unknown, not serving, not a
    /// `MysticetiDag` domain, unpinned, or `proof` fails cryptographic
    /// equivocation verification.
    pub fn adjudicate_mysticeti_equivocation(
        &mut self,
        key: &DomainKey,
        proof: &crate::cross_domain::external::mysticeti_dag::MysticetiEquivocationProof,
    ) -> Result<([u8; 32], u64, u64), IntakeError> {
        let (entry, expected_name) = self.serving_entry(key)?;
        let AdapterSpec::MysticetiDag { network, committee } = &entry.spec else {
            return Err(IntakeError::Registry(RegistryError::DescriptorMismatch {
                expected: expected_name.to_string(),
                found: crate::cross_domain::external::mysticeti_dag::MYSTICETI_DAG_ADAPTER_NAME
                    .to_string(),
            }));
        };
        let Some(pinned) = committee else {
            return Err(IntakeError::CommitteeNotPinned);
        };
        let (offender, round, weight) =
            crate::cross_domain::external::mysticeti_dag::verify_mysticeti_equivocation(
                network, pinned, proof,
            )
            .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        let local_height = self.registry.height();
        let _ = self.guard.record_adverse_round(*key, local_height);
        self.registry
            .mark_faulted(
                key,
                &format!(
                    "Mysticeti validator {} equivocated at round {round} (stake={weight})",
                    hex::encode(offender)
                ),
            )
            .map_err(IntakeError::Registry)?;
        Ok((offender, round, weight))
    }

    /// Verify a `BitVM2` `1-of-N` single-step `DisproveScript` fraud proof against
    /// the domain's pinned anchor and freeze the domain.
    ///
    /// WIRING: objective `BitVM2` single-step fraud door freezing `AdapterSpec::BitVmCovenant` domains (wired via `ExternalDomainTx::SubmitFaultProof`).
    ///
    /// # Errors
    ///
    /// Returns [`IntakeError`] if `key` is unknown, not serving, not a
    /// `BitVmCovenant` domain, unpinned, or `proof` fails single-step fraud
    /// verification.
    pub fn adjudicate_bitvm_disprove(
        &mut self,
        key: &DomainKey,
        proof: &crate::cross_domain::external::bitvm_covenant::DisproveScriptProof,
    ) -> Result<(u32, [u8; 32], [u8; 32]), IntakeError> {
        let (entry, expected_name) = self.serving_entry(key)?;
        let AdapterSpec::BitVmCovenant { network, anchor } = &entry.spec else {
            return Err(IntakeError::Registry(RegistryError::DescriptorMismatch {
                expected: expected_name.to_string(),
                found: crate::cross_domain::external::bitvm_covenant::BITVM_COVENANT_ADAPTER_NAME
                    .to_string(),
            }));
        };
        let Some(pinned) = anchor else {
            return Err(IntakeError::CommitteeNotPinned);
        };
        let (chunk_idx, expected_post, claimed_post) =
            crate::cross_domain::external::bitvm_covenant::verify_disprove_script(
                network, pinned, proof,
            )
            .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        let local_height = self.registry.height();
        let _ = self.guard.record_adverse_round(*key, local_height);
        self.registry
            .mark_faulted(
                key,
                &format!("BitVM2 DisproveScript refuted operator claim at chunk {chunk_idx}"),
            )
            .map_err(IntakeError::Registry)?;
        Ok((chunk_idx, expected_post, claimed_post))
    }

    /// Verify an objective Bullshark `DAG-BFT` equivocation proof (double
    /// availability certification or same-round vertex fork) against the
    /// domain's governance-pinned committee, record an adverse round, and
    /// freeze the domain (`DomainState::Faulted`).
    ///
    /// WIRING: objective `DAG-BFT` equivocation door freezing
    /// `AdapterSpec::DagCertificate` domains (wired via `ExternalDomainTx::SubmitFaultProof`).
    ///
    /// # Errors
    ///
    /// Returns [`IntakeError`] if `key` is unknown, not serving, not a
    /// `DagCertificate` domain, unpinned, or `proof` fails cryptographic
    /// equivocation verification.
    pub fn adjudicate_dag_equivocation(
        &mut self,
        key: &DomainKey,
        proof: &crate::cross_domain::external::dag_bft::DagEquivocationProof,
    ) -> Result<crate::cross_domain::external::dag_bft::DagSlashVerdict, IntakeError> {
        let (entry, expected_name) = self.serving_entry(key)?;
        let AdapterSpec::DagCertificate { network, committee } = &entry.spec else {
            return Err(IntakeError::Registry(RegistryError::DescriptorMismatch {
                expected: expected_name.to_string(),
                found: crate::cross_domain::external::dag_bft::ADAPTER_NAME.to_string(),
            }));
        };
        let Some(pinned) = committee else {
            return Err(IntakeError::CommitteeNotPinned);
        };
        let verdict = crate::cross_domain::external::dag_bft::verify_dag_equivocation_proof(
            network, pinned, proof,
        )
        .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        let local_height = self.registry.height();
        let _ = self.guard.record_adverse_round(*key, local_height);
        self.registry
            .mark_faulted(
                key,
                &format!(
                    "Bullshark DAG equivocation at epoch {} round {} (slashed_weight={})",
                    verdict.epoch, verdict.round, verdict.slashed_weight
                ),
            )
            .map_err(IntakeError::Registry)?;
        Ok(verdict)
    }

    /// Verify an objective Babylon EOTS equivocation proof (one provider
    /// signing two conflicting epoch votes) against the domain's
    /// governance-pinned epoch-key table and chain id, record an adverse
    /// round, and freeze the domain (`DomainState::Faulted`).
    ///
    /// WIRING: objective Babylon EOTS equivocation door freezing
    /// `AdapterSpec::BabylonEots` domains (wired via
    /// `ExternalDomainTx::SubmitFaultProof`).
    ///
    /// # Errors
    ///
    /// Returns [`IntakeError`] if `key` is unknown, not serving, not a
    /// `BabylonEots` domain, unpinned, or if the proof does not bind to the
    /// pinned key table.
    pub fn adjudicate_babylon_eots_equivocation(
        &mut self,
        key: &DomainKey,
        proof: &crate::cross_domain::external::babylon_eots::EotsEquivocationProof,
    ) -> Result<([u8; 32], u64), IntakeError> {
        let (entry, expected_name) = self.serving_entry(key)?;
        let AdapterSpec::BabylonEots { pinned, .. } = &entry.spec else {
            return Err(IntakeError::Registry(RegistryError::DescriptorMismatch {
                expected: expected_name.to_string(),
                found: crate::cross_domain::external::babylon_eots::EOTS_ADAPTER_NAME.to_string(),
            }));
        };
        let Some(pinned) = pinned else {
            return Err(IntakeError::CommitteeNotPinned);
        };
        crate::cross_domain::external::babylon_eots::verify_eots_equivocation(pinned, proof)
            .map_err(|reason| {
                IntakeError::Registry(RegistryError::Adapter(
                    crate::cross_domain::external::spec::AdapterError::ConsensusRule {
                        rule: reason,
                    },
                ))
            })?;
        let local_height = self.registry.height();
        let _ = self.guard.record_adverse_round(*key, local_height);
        self.registry
            .mark_faulted(
                key,
                &format!(
                    "Babylon EOTS provider {} equivocated (key={})",
                    hex::encode(proof.provider),
                    hex::encode(proof.eots_key)
                ),
            )
            .map_err(IntakeError::Registry)?;
        Ok((proof.provider, 0))
    }

    /// Verify an objective ICS-07 `Tendermint`/`CometBFT` misbehaviour proof
    /// (double-sign equivocation, BFT time violation, or lunatic header)
    /// against the domain's governance-pinned `chain_id` and
    /// `validator_set_hash`, record an adverse round, and freeze the domain
    /// (`DomainState::Faulted`).
    ///
    /// WIRING: objective `Tendermint`/`CometBFT` equivocation door freezing
    /// `AdapterSpec::TendermintCommit` domains (wired via `ExternalDomainTx::SubmitFaultProof`).
    ///
    /// # Errors
    ///
    /// Returns [`IntakeError`] if `key` is unknown, not serving, not a
    /// `TendermintCommit` domain, unpinned, if `trusted` does not match the
    /// pinned `chain_id` and `validator_set_hash`, or if `evidence` fails
    /// ICS-07 misbehaviour verification.
    pub fn adjudicate_tendermint_misbehaviour(
        &mut self,
        key: &DomainKey,
        trusted: &crate::cross_domain::external::tendermint::TrustedTendermintState,
        params: &crate::cross_domain::external::tendermint::TendermintLightParams,
        evidence: &crate::cross_domain::external::tendermint::TendermintMisbehaviour,
        now_secs: u64,
    ) -> Result<
        crate::cross_domain::external::tendermint::VerifiedTendermintMisbehaviour,
        IntakeError,
    > {
        use subtle::ConstantTimeEq;

        let (entry, expected_name) = self.serving_entry(key)?;
        let AdapterSpec::TendermintCommit {
            chain_id,
            validator_set_hash,
            ..
        } = &entry.spec
        else {
            return Err(IntakeError::Registry(RegistryError::DescriptorMismatch {
                expected: expected_name.to_string(),
                found: "tendermint-commit".to_string(),
            }));
        };
        let Some(pinned_hash) = validator_set_hash else {
            return Err(IntakeError::CommitteeNotPinned);
        };
        if trusted.chain_id != *chain_id {
            return Err(IntakeError::Registry(RegistryError::Adapter(
                crate::cross_domain::external::spec::AdapterError::ConsensusRule {
                    rule: format!(
                        "trusted Tendermint state chain_id {} does not match pinned {}",
                        trusted.chain_id, chain_id
                    ),
                },
            )));
        }
        let supplied_hash = crate::cross_domain::external::tendermint::validator_set_commitment(
            &trusted.validators,
        );
        if !bool::from(supplied_hash.ct_eq(pinned_hash)) {
            return Err(IntakeError::Registry(RegistryError::Adapter(
                crate::cross_domain::external::spec::AdapterError::ConsensusRule {
                    rule:
                        "trusted Tendermint validator set does not match pinned validator_set_hash"
                            .to_string(),
                },
            )));
        }
        let verdict = crate::cross_domain::external::tendermint::verify_tendermint_misbehaviour(
            trusted, params, evidence, now_secs,
        )
        .map_err(|e| IntakeError::Registry(RegistryError::Adapter(e)))?;
        let local_height = self.registry.height();
        let _ = self.guard.record_adverse_round(*key, local_height);
        self.registry
            .mark_faulted(
                key,
                &format!(
                    "Tendermint/CometBFT {:?} at height {} (culprit_power={})",
                    verdict.kind, verdict.header_1_height, verdict.culprit_trusted_power
                ),
            )
            .map_err(IntakeError::Registry)?;
        Ok(verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::ethereum::layout;
    use crate::cross_domain::external::quorum::{DisputeBehavior, LowParticipantsBehavior};
    use crate::cross_domain::external::spec::AdapterId;

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    /// The same strict test verifier the framework tests use: refuses the
    /// corruptions the probes inject, without pairing arithmetic. The
    /// production `PairingBls` cannot serve here because the fixture payload
    /// carries no real curve points; its own behaviour is pinned separately
    /// below.
    struct StrictTestBls;

    impl BlsVerifier for StrictTestBls {
        fn verify_aggregate(
            &self,
            _signing_root: &[u8; 32],
            aggregate_pubkey: &[u8],
            signature: &[u8],
            participants: u64,
        ) -> Result<(), String> {
            if participants == 0 {
                return Err("nobody signed".to_string());
            }
            if signature.iter().all(|b| *b == 0) {
                return Err("signature is not a valid curve point".to_string());
            }
            if aggregate_pubkey.iter().all(|b| *b == 0) {
                return Err("public key is not a valid curve point".to_string());
            }
            Ok(())
        }

        fn sync_committee_closed(&self) -> bool {
            false
        }
    }

    fn eth_spec() -> AdapterSpec {
        AdapterSpec::EthereumSync {
            network: "testnet".to_string(),
            // The happy-path tests pin the committee the
            // golden sample carries ([0x11; 96], period 0).
            committee: Some(crate::cross_domain::external::ethereum::PinnedCommittee {
                period: 0,
                aggregate_pubkey: vec![0x11; 96],
                next_committee_root: [0xbb; 32],
            }),
        }
    }

    /// A well-formed sync-committee evidence sample against the fixture
    /// layout, mirroring the framework's own golden builder.
    fn golden_for(spec: &AdapterSpec) -> RawConsensusEvidence {
        let committee = crate::cross_domain::external::ethereum::PinnedCommittee {
            period: 0,
            aggregate_pubkey: vec![0x11; 96],
            next_committee_root: [0xbb; 32],
        };
        let payload = crate::cross_domain::external::ethereum::build_deneb_update_payload(
            64,
            128,
            0,
            &committee,
            &[0x22; 96],
            &[0xff; 64],
            [0xcc; 32],
        );
        let adapter = spec.build(Some(Box::new(StrictTestBls)), None);
        RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: 2,
            network: "testnet".to_string(),
            payload,
            declared_height: 64,
            declared_root: [0xcc; 32],
            submitter: addr(1),
        }
    }

    fn versions_for(spec: &AdapterSpec) -> VersionPolicy {
        let adapter = spec.build(Some(Box::new(StrictTestBls)), None);
        let desc = adapter.descriptor();
        let ev_ver = desc
            .accepted_evidence_versions
            .first()
            .copied()
            .unwrap_or(2);
        VersionPolicy::single(desc.id, ev_ver, 0)
    }

    fn register(state: &mut IntakeState) -> DomainKey {
        let spec = eth_spec();
        if let AdapterSpec::EthereumSync {
            network,
            committee: Some(committee),
        } = &spec
        {
            state.pin_ethereum_committee(network.clone(), committee.clone());
        }
        let golden = golden_for(&spec);
        let versions = versions_for(&spec);
        let economics = IntakeState::conservative_economics(1_000_000);
        state
            .register_domain(
                RegistrationRequest {
                    spec,
                    policy: VerificationPolicy::strict(1_000),
                    economics,
                    versions,
                    bond_atoms: economics_bond(),
                    poster: addr(9),
                    golden,
                },
                Some(Box::new(StrictTestBls)),
            )
            .expect("registration must pass end to end")
    }

    fn economics_bond() -> u128 {
        IntakeState::conservative_economics(1_000_000).required_bond_atoms()
    }

    #[test]
    fn registration_runs_admission_and_stores_a_rebuildable_entry() {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        let entry = state.entries.get(&key).expect("the entry must be stored");
        assert!(
            entry.admission.admitted,
            "the stored report must be the passing one"
        );
        assert!(
            entry.admission.golden_verified,
            "a passing admission implies a verified golden"
        );
        assert_eq!(entry.golden.network, "testnet");
        assert!(state.registry.domain(&key).is_some());
    }

    #[test]
    fn an_ethereum_spec_without_bls_is_refused_before_admission() {
        let mut state = IntakeState::new();
        let spec = eth_spec();
        let golden = golden_for(&spec);
        let versions = versions_for(&spec);
        let economics = IntakeState::conservative_economics(1_000_000);
        let err = state
            .register_domain(
                RegistrationRequest {
                    spec,
                    policy: VerificationPolicy::strict(1_000),
                    economics,
                    versions,
                    bond_atoms: economics_bond(),
                    poster: addr(9),
                    golden,
                },
                None,
            )
            .unwrap_err();
        assert_eq!(err, IntakeError::MissingBlsVerifier);
    }

    #[test]
    fn economics_that_reward_lying_are_refused_at_the_door() {
        let mut state = IntakeState::new();
        let spec = eth_spec();
        if let AdapterSpec::EthereumSync {
            network,
            committee: Some(committee),
        } = &spec
        {
            state.pin_ethereum_committee(network.clone(), committee.clone());
        }
        let golden = golden_for(&spec);
        let versions = versions_for(&spec);
        // A fee above the full ceiling: lying pays even if the whole bond is
        // taken. The framework's bond check alone would admit this.
        let economics = DomainEconomics {
            routing_ceiling_atoms: 1_000,
            fee: ProverFee {
                base_atoms: 10_000,
                value_bps: 0,
            },
            challenge: ChallengeReward {
                bps_of_slash: 500,
                floor_atoms: 1,
            },
            unbonding_heights: 10,
        };
        let err = state
            .register_domain(
                RegistrationRequest {
                    spec,
                    policy: VerificationPolicy::strict(1_000),
                    bond_atoms: economics.required_bond_atoms(),
                    economics,
                    versions,
                    poster: addr(9),
                    golden,
                },
                Some(Box::new(StrictTestBls)),
            )
            .unwrap_err();
        assert_eq!(err, IntakeError::DishonestEconomics);
    }

    #[test]
    fn evidence_for_an_unregistered_domain_is_refused_by_name() {
        let mut state = IntakeState::new();
        let spec = eth_spec();
        let evidence = golden_for(&spec);
        let err = state
            .submit_evidence(&evidence, Some(Box::new(StrictTestBls)))
            .unwrap_err();
        assert_eq!(err, IntakeError::UnknownDomain);
    }

    #[test]
    fn submitted_evidence_reaches_the_framework_registry_and_its_rules() {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        // The golden itself: submitter is not bonded as a prover, so the
        // registry's prover rule must fire - proof that submission is going
        // through the framework's checks, not around them.
        let spec = eth_spec();
        let evidence = golden_for(&spec);
        let err = state
            .submit_evidence(&evidence, Some(Box::new(StrictTestBls)))
            .unwrap_err();
        assert!(
            matches!(err, IntakeError::Registry(RegistryError::UnknownProver(_))),
            "expected the registry's prover gate, got: {err:?}"
        );
        // The refusal is state: the domain's refusal counter moved.
        let reg = state.registry.domain(&key).expect("domain");
        assert_eq!(reg.record.attestations_refused, 1);
    }

    #[test]
    fn the_state_digest_moves_with_the_state_and_only_with_the_state() {
        let mut a = IntakeState::new();
        let b = IntakeState::new();
        let empty_a = a.state_digest().expect("digest");
        let empty_b = b.state_digest().expect("digest");
        assert_eq!(empty_a, empty_b, "two empty intakes must agree");
        register(&mut a);
        let registered = a.state_digest().expect("digest");
        assert_ne!(empty_a, registered, "registration must move the digest");
    }

    #[test]
    fn the_registry_clock_only_moves_forward() {
        let mut state = IntakeState::new();
        state.on_block_committed(10);
        state.on_block_committed(5);
        assert_eq!(
            state.registry.height(),
            10,
            "a lower height must not rewind the clock"
        );
    }

    #[test]
    fn conservative_economics_keep_honesty_cheaper_at_the_ceiling() {
        let economics = IntakeState::conservative_economics(1_000_000_000);
        assert!(honesty_is_cheaper(
            &economics,
            economics.routing_ceiling_atoms
        ));
    }

    // --- PairingBls: the production pairing check's own gates ---

    #[test]
    fn pairing_bls_refuses_zero_participants_and_bad_lengths() {
        let bls = PairingBls;
        assert!(bls
            .verify_aggregate(&[0; 32], &[0x11; 48], &[0x22; 96], 0)
            .is_err());
        assert!(bls
            .verify_aggregate(&[0; 32], &[0x11; 47], &[0x22; 96], 1)
            .is_err());
        assert!(bls
            .verify_aggregate(&[0; 32], &[0x11; 48], &[0x22; 95], 1)
            .is_err());
    }

    #[test]
    fn pairing_bls_refuses_a_96_byte_key_with_nonzero_padding() {
        let bls = PairingBls;
        let mut key96 = vec![0u8; 96];
        key96[..48].copy_from_slice(&[0x11; 48]);
        key96[95] = 1;
        let err = bls
            .verify_aggregate(&[0; 32], &key96, &[0x22; 96], 1)
            .unwrap_err();
        assert!(err.contains("zero-padded"), "unexpected refusal: {err}");
    }

    #[test]
    fn pairing_bls_refuses_points_that_do_not_decode() {
        // All-0x11 bytes are not a valid compressed G1 point; the refusal
        // must be the decode gate, not a panic and not a pass.
        let bls = PairingBls;
        let err = bls
            .verify_aggregate(&[0; 32], &[0x11; 48], &[0x22; 96], 1)
            .unwrap_err();
        assert!(
            err.contains("not a valid compressed G1 point"),
            "unexpected refusal: {err}"
        );
    }

    #[test]
    fn pairing_bls_verifies_a_genuine_aggregate_and_refuses_a_forged_root() {
        // A real single-signer aggregate: sk * H(root) verifies against
        // pk = sk * g1. One signer is a degenerate aggregate, which is
        // exactly what makes the fixture honest - the arithmetic is the
        // same sum, with one term.
        use bls12_381::{G1Affine, G1Projective, Scalar};
        let sk = Scalar::from(123_456_789u64);
        let pk = G1Affine::from(G1Projective::generator() * sk);
        let root = [7u8; 32];
        let h = crate::chain::finality::hash_to_g2(&root);
        let sig = bls12_381::G2Affine::from(bls12_381::G2Projective::from(h) * sk);
        let bls = PairingBls;
        bls.verify_aggregate(&root, &pk.to_compressed(), &sig.to_compressed(), 1)
            .expect("a genuine aggregate must verify");
        let forged = [8u8; 32];
        assert!(
            bls.verify_aggregate(&forged, &pk.to_compressed(), &sig.to_compressed(), 1)
                .is_err(),
            "the same signature over another root must refuse"
        );
    }

    #[test]
    fn a_zkvm_spec_builds_without_bls_and_keeps_its_network() {
        let spec = AdapterSpec::ZkVm {
            network: "mainnet".to_string(),
            program_hash: None,
            chain_id: None,
        };
        assert_eq!(spec.network(), "mainnet");
        let adapter = spec.build(None, None);
        assert_eq!(
            adapter.descriptor().id,
            AdapterId::from_name("budzkvm-mainnet")
        );
    }

    // ---- Quorum rounds through the intake, end to end -------------------

    /// Golden-shaped evidence at a fresh height, carried by `submitter`.
    /// Height 128 (attested slot of the golden): finalized slot moves with
    /// it so the adapter derives the declared height.
    fn quorum_evidence(spec: &AdapterSpec, submitter: Address) -> RawConsensusEvidence {
        let mut evidence = golden_for(spec);
        evidence.submitter = submitter;
        evidence
    }

    /// A registered domain with three bonded provers and a strict 2-of-3
    /// quorum policy.
    fn quorum_state() -> (IntakeState, DomainKey) {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        for prover in [addr(2), addr(3)] {
            state
                .bond_prover(&key, prover, economics_bond())
                .expect("bonding a fresh prover must pass");
        }
        state
            .set_quorum_policy(
                &key,
                crate::cross_domain::external::QuorumPolicy::strict(2, 3),
            )
            .expect("policy for a registered domain must install");
        (state, key)
    }

    #[test]
    fn a_quorum_policy_for_an_unregistered_domain_is_refused() {
        let mut state = IntakeState::new();
        let err = state
            .set_quorum_policy(
                &DomainKey::from_parts(&AdapterId::from_name("ghost"), "nowhere"),
                crate::cross_domain::external::QuorumPolicy::strict(2, 3),
            )
            .unwrap_err();
        assert!(matches!(err, IntakeError::UnknownDomain));
    }

    #[test]
    fn a_permissive_quorum_policy_is_refused_at_the_intake() {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        let mut policy = crate::cross_domain::external::QuorumPolicy::strict(2, 3);
        policy.dispute = DisputeBehavior::AcceptMostCommon;
        let err = state.set_quorum_policy(&key, policy).unwrap_err();
        assert!(matches!(err, IntakeError::PermissiveQuorumPolicy));
        let mut policy = crate::cross_domain::external::QuorumPolicy::strict(2, 3);
        policy.low_participants = LowParticipantsBehavior::AcceptMostCommon;
        let err = state.set_quorum_policy(&key, policy).unwrap_err();
        assert!(matches!(err, IntakeError::PermissiveQuorumPolicy));
    }

    #[test]
    fn a_quorum_policy_that_cannot_decide_safely_is_refused() {
        use crate::cross_domain::external::QuorumPolicy;
        let mut state = IntakeState::new();
        let key = register(&mut state);
        for prover in [addr(2), addr(3)] {
            state
                .bond_prover(&key, prover, economics_bond())
                .expect("bond");
        }
        let cases = [
            QuorumPolicy::strict(0, 3),
            QuorumPolicy::strict(4, 3),
            QuorumPolicy::strict(2, 0),
            QuorumPolicy::strict(1, 3),
            QuorumPolicy::strict(2, 4),
            QuorumPolicy::strict(3, MAX_QUORUM_PARTICIPANTS + 1),
            // Three bonded provers, threshold four.
            QuorumPolicy::strict(4, 5),
        ];
        for policy in cases {
            let err = state.set_quorum_policy(&key, policy).unwrap_err();
            assert!(
                matches!(err, IntakeError::InvalidQuorumPolicy { .. }),
                "policy {policy:?} must be refused, got: {err:?}"
            );
        }
        state
            .set_quorum_policy(&key, QuorumPolicy::strict(2, 3))
            .expect("a strict majority with enough bonded provers installs");
    }

    /// The policy clock at submission is the domain's
    /// accepted tip, not the frozen registration instant.
    #[test]
    fn the_policy_clock_advances_with_the_accepted_tip() {
        assert_eq!(live_policy_clock(100, None), 100, "no tip: keep stored");
        assert_eq!(live_policy_clock(100, Some(50)), 100, "never goes back");
        assert_eq!(
            live_policy_clock(100, Some(175)),
            175,
            "the accepted tip is the live clock - a frozen 100 made max_age dead"
        );
    }

    #[test]
    fn bonding_the_same_prover_twice_is_refused_by_name() {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        state
            .bond_prover(&key, addr(2), economics_bond())
            .expect("first bond");
        let err = state
            .bond_prover(&key, addr(2), economics_bond())
            .unwrap_err();
        assert!(
            matches!(
                err,
                IntakeError::Registry(RegistryError::ProverAlreadyBonded(_))
            ),
            "expected the already-bonded refusal, got: {err:?}"
        );
    }

    #[test]
    fn an_insufficient_quorum_bond_is_refused_like_the_posters() {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        let err = state.bond_prover(&key, addr(2), 1).unwrap_err();
        assert!(
            matches!(
                err,
                IntakeError::Registry(RegistryError::InsufficientBond { .. })
            ),
            "expected the bond rule, got: {err:?}"
        );
    }

    #[test]
    fn the_first_answer_of_a_round_is_pending_not_an_attestation() {
        let (mut state, _key) = quorum_state();
        let spec = eth_spec();
        let evidence = quorum_evidence(&spec, addr(2));
        let err = state
            .submit_evidence(&evidence, Some(Box::new(StrictTestBls)))
            .unwrap_err();
        assert!(
            matches!(err, IntakeError::RoundPending),
            "one of two answers must not commit anything, got: {err:?}"
        );
    }

    #[test]
    fn two_matching_answers_commit_the_attestation_once() {
        let (mut state, key) = quorum_state();
        let spec = eth_spec();
        let first = quorum_evidence(&spec, addr(2));
        let second = quorum_evidence(&spec, addr(3));
        let pending = state.submit_evidence(&first, Some(Box::new(StrictTestBls)));
        assert!(matches!(pending, Err(IntakeError::RoundPending)));
        let attestation = state
            .submit_evidence(&second, Some(Box::new(StrictTestBls)))
            .expect("the second matching answer closes the round");
        assert_eq!(attestation.state_root, [0xcc; 32]);
        // The book holds exactly one attestation for the slot, and the
        // domain moved Admitted -> Active on it.
        let reg = state.registry.domain(&key).expect("domain");
        assert_eq!(reg.record.attestations_accepted, 1);
        assert_eq!(
            reg.record.state,
            crate::cross_domain::external::DomainState::Active
        );
        // The carrier on record is the FIRST prover of the winning claim -
        // arrival order, not the closer.
        let carrier = reg
            .attestation_provers
            .get(&attestation.evidence_digest)
            .copied();
        assert_eq!(
            carrier,
            Some(addr(2)),
            "first carrier is the representative"
        );
    }

    /// an accepted attestation puts the scheme the adapter checked in
    /// the profile, with the weakest class beside it. A domain that has
    /// accepted nothing shows no facts and no class.
    #[test]
    fn the_profile_of_an_accepted_domain_shows_the_observed_scheme() {
        use crate::crypto::facts::{ObservedScheme, QuantumClass};
        use crate::crypto::scheme::SchemeId;
        let mut state = IntakeState::new();
        let key = register(&mut state);
        let before = crate::cross_domain::external::profile_of(
            &state.registry.domain(&key).expect("domain").record,
        );
        assert!(before.crypto_facts.is_empty());
        assert_eq!(before.quantum_class, None);

        state
            .bond_prover(&key, addr(2), economics_bond())
            .expect("bond");
        let evidence = quorum_evidence(&eth_spec(), addr(2));
        state
            .submit_evidence(&evidence, Some(Box::new(StrictTestBls)))
            .expect("a bonded prover's golden evidence is accepted");

        let profile = crate::cross_domain::external::profile_of(
            &state.registry.domain(&key).expect("domain").record,
        );
        let bls = ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG);
        assert_eq!(profile.crypto_facts.count(bls), 1);
        assert_eq!(profile.quantum_class, Some(QuantumClass::Classical));
        assert!(
            profile.summary_line().contains("crypto=bls12-381x1"),
            "got: {}",
            profile.summary_line()
        );
    }

    #[test]
    fn a_second_vote_from_the_same_prover_is_refused_at_the_round() {
        let (mut state, _key) = quorum_state();
        let spec = eth_spec();
        let evidence = quorum_evidence(&spec, addr(2));
        let _ = state.submit_evidence(&evidence, Some(Box::new(StrictTestBls)));
        let err = state
            .submit_evidence(&evidence, Some(Box::new(StrictTestBls)))
            .unwrap_err();
        assert!(
            matches!(err, IntakeError::Round(RoundError::DuplicateAnswer)),
            "one bond, one voice - got: {err:?}"
        );
    }

    #[test]
    fn an_unbonded_prover_cannot_enter_a_round() {
        let (mut state, _key) = quorum_state();
        let spec = eth_spec();
        let evidence = quorum_evidence(&spec, addr(77));
        let err = state
            .submit_evidence(&evidence, Some(Box::new(StrictTestBls)))
            .unwrap_err();
        assert!(
            matches!(err, IntakeError::Registry(RegistryError::UnknownProver(_))),
            "a boundary refusal must not become a vote, got: {err:?}"
        );
        // And the round holds no entry from the attempt.
        let key = DomainKey::from_parts(&evidence.adapter, &evidence.network);
        let round = state.quorum.round_of(&key, evidence.declared_height);
        assert!(
            round.is_none() || round.is_some_and(|r| r.entries.is_empty()),
            "the refused attempt must not have entered the round"
        );
    }

    #[test]
    fn a_recoverable_split_decides_deterministically() {
        let (mut state, key) = quorum_state();
        let spec = eth_spec();
        let honest_a = quorum_evidence(&spec, addr(2));
        // A rival claim: same well-formed payload, different state root, so
        // the adapter derives a different claim for the same height.
        let mut rival = quorum_evidence(&spec, addr(3));
        crate::cross_domain::external::ethereum::set_deneb_state_root(
            &mut rival.payload,
            [0xdd; 32],
        );
        rival.declared_root = [0xdd; 32];
        // A third, different claim from the bonded poster: three seats, three
        // distinct answers, threshold 2.
        let mut rival_b = quorum_evidence(&spec, addr(9));
        crate::cross_domain::external::ethereum::set_deneb_state_root(
            &mut rival_b.payload,
            [0xee; 32],
        );
        rival_b.declared_root = [0xee; 32];
        let _ = state.submit_evidence(&honest_a, Some(Box::new(StrictTestBls)));
        let _ = state.submit_evidence(&rival, Some(Box::new(StrictTestBls)));
        // 1 vs 1, threshold 2, one seat left: still recoverable, still open.
        let round = state
            .quorum
            .round_of(&key, honest_a.declared_height)
            .expect("round exists");
        assert!(matches!(
            round.state,
            crate::cross_domain::external::RoundState::Open
        ));
        let _ = state.submit_evidence(&rival_b, Some(Box::new(StrictTestBls)));
        // 1 vs 1 vs 1 with every seat taken: no group can reach 2.
        let round = state
            .quorum
            .round_of(&key, honest_a.declared_height)
            .expect("round exists");
        assert!(matches!(
            round.state,
            crate::cross_domain::external::RoundState::Disputed
        ));
        let reg = state.registry.domain(&key).expect("domain");
        assert_eq!(
            reg.record.state,
            crate::cross_domain::external::DomainState::Faulted,
            "an unrecoverable split must freeze the domain"
        );
    }

    /// The dispute-to-fault wiring through `IntakeState`
    /// - the branch that calls `mark_faulted` when a round freezes in a
    ///   dispute - had no test through the intake at all. A three-way split
    ///   under a 3-of-3 policy reaches `Disputed` (no group can ever reach the
    ///   threshold), and the domain must come out Faulted.
    #[test]
    fn a_disputed_round_faults_the_domain_through_the_intake() {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        for prover in [addr(2), addr(3), addr(4)] {
            state
                .bond_prover(&key, prover, economics_bond())
                .expect("bonding a fresh prover must pass");
        }
        state
            .set_quorum_policy(
                &key,
                crate::cross_domain::external::QuorumPolicy::strict(3, 3),
            )
            .expect("a 3-of-3 policy with three bonded provers installs");
        let spec = eth_spec();
        let a = quorum_evidence(&spec, addr(2));
        let mut b = quorum_evidence(&spec, addr(3));
        crate::cross_domain::external::ethereum::set_deneb_state_root(&mut b.payload, [0xdd; 32]);
        b.declared_root = [0xdd; 32];
        let mut c = quorum_evidence(&spec, addr(4));
        crate::cross_domain::external::ethereum::set_deneb_state_root(&mut c.payload, [0xee; 32]);
        c.declared_root = [0xee; 32];
        let _ = state.submit_evidence(&a, Some(Box::new(StrictTestBls)));
        let _ = state.submit_evidence(&b, Some(Box::new(StrictTestBls)));
        let _ = state.submit_evidence(&c, Some(Box::new(StrictTestBls)));
        let round = state
            .quorum
            .round_of(&key, a.declared_height)
            .expect("round exists");
        assert!(
            matches!(
                round.state,
                crate::cross_domain::external::RoundState::Disputed
            ),
            "three different claims under a 3-of-3 policy must freeze in dispute"
        );
        let reg = state.registry.domain(&key).expect("domain");
        assert_eq!(
            reg.record.state,
            crate::cross_domain::external::profile::DomainState::Faulted,
            "a disputed round must fault the domain through the intake"
        );
    }

    #[test]
    fn the_carrier_is_the_first_prover_with_the_winning_claim() {
        let (mut state, key) = quorum_state();
        let spec = eth_spec();
        let a = quorum_evidence(&spec, addr(2));
        let b = quorum_evidence(&spec, addr(3));
        let _ = state.submit_evidence(&a, Some(Box::new(StrictTestBls)));
        let _ = state.submit_evidence(&b, Some(Box::new(StrictTestBls)));
        let round = state
            .quorum
            .round_of(&key, a.declared_height)
            .expect("round exists");
        let claim = round.entries[0]
            .attestation
            .as_ref()
            .expect("claim")
            .claim_digest();
        assert_eq!(first_carrier(round, &claim), Some(addr(2)));
        assert_eq!(first_carrier(round, &[0x99; 32]), None);
    }

    #[test]
    fn round_progress_moves_the_state_digest() {
        let (mut state, _key) = quorum_state();
        let before = state.state_digest().expect("digest");
        let spec = eth_spec();
        let evidence = quorum_evidence(&spec, addr(2));
        let _ = state.submit_evidence(&evidence, Some(Box::new(StrictTestBls)));
        let after = state.state_digest().expect("digest");
        assert_ne!(
            before, after,
            "a recorded answer is consensus state and must move the digest"
        );
    }

    #[test]
    fn a_refused_submission_does_not_fault_the_domain() {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        let spec = eth_spec();
        // An unbonded caller and a malformed payload: both are refusals about
        // the caller's input.
        let unbonded = quorum_evidence(&spec, addr(50));
        assert!(
            state
                .submit_evidence(&unbonded, Some(Box::new(StrictTestBls)))
                .is_err(),
            "an unbonded caller must be refused"
        );
        let mut malformed = quorum_evidence(&spec, addr(9));
        malformed.payload.truncate(1);
        assert!(
            state
                .submit_evidence(&malformed, Some(Box::new(StrictTestBls)))
                .is_err(),
            "a malformed payload must be refused"
        );
        let reg = state.registry.domain(&key).expect("domain");
        assert_eq!(reg.record.attestations_refused, 2);
        assert_eq!(
            reg.record.state,
            crate::cross_domain::external::DomainState::Admitted,
            "a caller's bad input must not fault the domain"
        );
        // The poster (bonded) can still attest.
        let good = quorum_evidence(&spec, addr(9));
        state
            .submit_evidence(&good, Some(Box::new(StrictTestBls)))
            .expect("the domain must still serve");
    }

    #[test]
    fn the_same_evidence_cannot_be_slashed_twice() {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        let spec = eth_spec();
        let good = quorum_evidence(&spec, addr(9));
        let attestation = state
            .submit_evidence(&good, Some(Box::new(StrictTestBls)))
            .expect("the poster is bonded and the evidence is valid");
        let digest = attestation.evidence_digest;
        let value = 1_000_000;
        state
            .registry
            .slash(&key, addr(9), digest, value, addr(7))
            .expect("the first slash lands");
        let err = state
            .registry
            .slash(&key, addr(9), digest, value, addr(7))
            .unwrap_err();
        assert!(matches!(err, RegistryError::AlreadySlashed { .. }));
        let bond = state
            .registry
            .domain(&key)
            .expect("domain")
            .provers
            .get(&addr(9))
            .expect("bond");
        assert_eq!(bond.slashings.len(), 1);
    }

    #[test]
    fn readmit_is_the_exit_from_faulted_and_refuses_a_noop_for_a_healthy_domain() {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        let report = state.entries.get(&key).expect("entry").admission.clone();
        let err = state
            .registry
            .readmit(&key, &report, "no change")
            .unwrap_err();
        assert!(matches!(err, RegistryError::AdmissionDigestMismatch { .. }));
        state
            .registry
            .mark_faulted(&key, "test dispute")
            .expect("domain exists");
        state
            .registry
            .readmit(&key, &report, "operator re-admission")
            .expect("a faulted domain must be re-admittable on the same digest");
        let reg = state.registry.domain(&key).expect("domain");
        assert_eq!(
            reg.record.state,
            crate::cross_domain::external::DomainState::Admitted
        );
    }

    #[test]
    fn a_faulted_domain_takes_no_attestation() {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        state
            .bond_prover(&key, addr(2), economics_bond())
            .expect("bond");
        state
            .registry
            .mark_faulted(&key, "test dispute")
            .expect("domain exists");
        let spec = eth_spec();
        let evidence = quorum_evidence(&spec, addr(2));
        let err = state
            .submit_evidence(&evidence, Some(Box::new(StrictTestBls)))
            .unwrap_err();
        assert!(
            matches!(err, IntakeError::Registry(RegistryError::NotServing { .. })),
            "a faulted domain must refuse new evidence, got: {err:?}"
        );
        let reg = state.registry.domain(&key).expect("domain");
        assert_eq!(reg.record.attestations_accepted, 0);
    }

    #[test]
    fn a_domain_without_a_policy_keeps_the_single_submission_path() {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        // No quorum policy installed. The unknown-prover refusal proves the
        // submission went down the single path into the registry's rules,
        // not into a round.
        let spec = eth_spec();
        let evidence = quorum_evidence(&spec, addr(50));
        let err = state
            .submit_evidence(&evidence, Some(Box::new(StrictTestBls)))
            .unwrap_err();
        assert!(matches!(
            err,
            IntakeError::Registry(RegistryError::UnknownProver(_))
        ));
        assert!(
            state
                .quorum
                .round_of(&key, evidence.declared_height)
                .is_none(),
            "no policy, no round"
        );
    }

    /// `EthereumSync` admission is
    /// closed until a sync committee is pinned - the old shape let the
    /// submitter name their own aggregate key.
    #[test]
    fn committee_less_ethereum_sync_is_refused_at_admission() {
        let mut state = IntakeState::new();
        let spec = AdapterSpec::EthereumSync {
            network: "testnet".to_string(),
            committee: None,
        };
        let golden = golden_for(&eth_spec());
        let versions = versions_for(&eth_spec());
        let economics = IntakeState::conservative_economics(1_000_000);
        let err = state
            .register_domain(
                RegistrationRequest {
                    spec,
                    policy: VerificationPolicy::strict(1_000),
                    economics,
                    versions,
                    bond_atoms: economics_bond(),
                    poster: addr(9),
                    golden,
                },
                Some(Box::new(StrictTestBls)),
            )
            .unwrap_err();
        assert!(matches!(err, IntakeError::CommitteeNotPinned), "got: {err}");

        // A caller-supplied committee that consensus/governance has not pinned
        // must also be refused so a registrant cannot certify its own finality.
        let attacker_spec = eth_spec();
        let attacker_golden = golden_for(&attacker_spec);
        let attacker_versions = versions_for(&attacker_spec);
        let attacker_economics = IntakeState::conservative_economics(1_000_000);
        let err = state
            .register_domain(
                RegistrationRequest {
                    spec: attacker_spec,
                    policy: VerificationPolicy::strict(1_000),
                    economics: attacker_economics,
                    versions: attacker_versions,
                    bond_atoms: economics_bond(),
                    poster: addr(9),
                    golden: attacker_golden,
                },
                Some(Box::new(StrictTestBls)),
            )
            .unwrap_err();
        assert!(matches!(err, IntakeError::CommitteeNotPinned), "got: {err}");
    }

    /// `EthereumSync` remains available on devnet for cryptographic integration
    /// tests, while public Testnet and Mainnet refuse the complete lifecycle.
    #[test]
    fn ethereum_sync_committee_is_closed_on_public_networks() {
        use crate::core::account::AccountState;
        use crate::core::chain_config::Network;
        use crate::cross_domain::external::ethereum::signing_root_v2;
        use crate::cross_domain::external::external_tx::{
            execute_external_domain_tx, ExternalDomainTx, ExternalDomainTxContext,
            ExternalDomainTxError,
        };
        use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

        let mut state = AccountState::new();
        let poster = addr(9);
        let bond = u64::try_from(economics_bond()).unwrap();
        state.add_balance(&poster, bond.saturating_mul(4));

        let sk = Scalar::from(7u64);
        let pk_compressed = G1Affine::from(G1Projective::generator() * sk).to_compressed();
        let mut agg_pk = vec![0u8; 96];
        agg_pk[..48].copy_from_slice(&pk_compressed);

        let committee = crate::cross_domain::external::ethereum::PinnedCommittee {
            period: 0,
            aggregate_pubkey: agg_pk.clone(),
            next_committee_root: [0xbb; 32],
        };
        state
            .settlement
            .external_intake
            .pin_ethereum_committee("testnet", committee.clone());
        let spec = AdapterSpec::EthereumSync {
            network: "testnet".to_string(),
            committee: Some(committee.clone()),
        };
        let mut payload = crate::cross_domain::external::ethereum::build_deneb_update_payload(
            64,
            128,
            0,
            &committee,
            &[0u8; 96],
            &[0xff; 64],
            [0xcc; 32],
        );
        let update = crate::cross_domain::external::ethereum::parse_update(&payload).unwrap();
        let root = signing_root_v2(&update);
        let sig =
            G2Affine::from(G2Projective::from(crate::chain::finality::hash_to_g2(&root)) * sk);
        payload[layout::SIGNATURE].copy_from_slice(&sig.to_compressed());

        let adapter = spec.build(Some(IntakeState::production_bls()), None);
        let golden = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: 2,
            network: "testnet".to_string(),
            payload,
            declared_height: 64,
            declared_root: [0xcc; 32],
            submitter: poster,
        };
        let req = RegistrationRequest {
            golden,
            versions: VersionPolicy::single(adapter.descriptor().id, 2, 0),
            economics: IntakeState::conservative_economics(1_000_000),
            policy: VerificationPolicy::strict(1_000),
            bond_atoms: economics_bond(),
            poster,
            spec,
        };
        let tx = ExternalDomainTx::Register(Box::new(req));

        let ctx_testnet = ExternalDomainTxContext {
            sender: poster,
            chain_id: Network::Testnet.chain_id().value(),
            fee: 10,
            bls: IntakeState::production_bls,
        };
        let before = state.calculate_state_root();
        let err = execute_external_domain_tx(&mut state, &ctx_testnet, &tx)
            .expect_err("EthereumSync must remain closed on public testnet");
        assert_eq!(err, ExternalDomainTxError::TestnetSyncCommitteeDisabled);
        assert_eq!(state.calculate_state_root(), before);
        assert!(state.settlement.external_intake.entries.is_empty());

        let ctx_devnet = ExternalDomainTxContext {
            sender: poster,
            chain_id: Network::Devnet.chain_id().value(),
            fee: 10,
            bls: IntakeState::production_bls,
        };
        execute_external_domain_tx(&mut state, &ctx_devnet, &tx)
            .expect("EthereumSync implementation must remain testable on devnet");
        assert_eq!(state.settlement.external_intake.entries.len(), 1);

        let ctx_mainnet = ExternalDomainTxContext {
            sender: poster,
            chain_id: Network::Mainnet.chain_id().value(),
            fee: 10,
            bls: IntakeState::production_bls,
        };
        let err = execute_external_domain_tx(&mut state, &ctx_mainnet, &tx)
            .expect_err("EthereumSync must stay closed on mainnet");
        assert_eq!(err, ExternalDomainTxError::MainnetDisabled);
    }

    #[test]
    fn tendermint_commit_intake_refuses_unpinned_or_wrong_valset_and_admits_pinned_anchor() {
        use crate::cross_domain::external::tendermint::{
            validator_address_of, validator_set_commitment, vote_sign_bytes,
            PinnedTendermintAnchor, TendermintCommitEvidence, TendermintSignature,
            TendermintValidator,
        };
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[0x71u8; 32]);
        let pk: [u8; 32] = sk.verifying_key().to_bytes();
        let val_addr = validator_address_of(&pk);
        let validators = vec![TendermintValidator {
            address: val_addr,
            public_key: pk,
            voting_power: 100,
        }];
        let valset_hash = validator_set_commitment(&validators);
        let app_hash = [0x5au8; 32];
        let parts_hash = [0x3cu8; 32];
        let mut commit = TendermintCommitEvidence {
            chain_id: "noble-1".to_string(),
            height: 100,
            round: 0,
            block_hash: [0u8; 32],
            parts_total: 1,
            parts_hash,
            version_block: 11,
            last_block_hash: [0x11u8; 32],
            last_parts_total: 1,
            last_parts_hash: [0x22u8; 32],
            last_commit_hash: [0x33u8; 32],
            data_hash: [0x44u8; 32],
            validators_hash: valset_hash,
            next_validators_hash: valset_hash,
            consensus_hash: [0x55u8; 32],
            app_hash,
            last_results_hash: [0x66u8; 32],
            evidence_hash: [0x77u8; 32],
            proposer_address: val_addr,
            commit_time: 1_700_000_000,
            commit_time_nanos: 0,
            validators,
            signatures: Vec::new(),
        };
        // Seal the header first: the block id the validators sign is the
        // header's own hash, so it cannot be chosen before the header exists.
        commit.block_hash = commit.header_hash();
        let block_hash = commit.block_hash;
        let sign_bytes = vote_sign_bytes(
            "noble-1",
            100,
            0,
            &block_hash,
            1,
            &parts_hash,
            (1_700_000_000, 0),
        );
        let sig = sk.sign(&sign_bytes);
        commit.signatures = vec![TendermintSignature {
            address: val_addr,
            timestamp_seconds: 1_700_000_000,
            timestamp_nanos: 0,
            signature: sig.to_bytes().to_vec(),
        }];
        let payload = bincode::serialize(&commit).expect("encode commit");
        let mk_req = |validator_set_hash: Option<[u8; 32]>| {
            let spec = AdapterSpec::TendermintCommit {
                network: "noble-testnet".to_string(),
                chain_id: "noble-1".to_string(),
                validator_set_hash,
            };
            let id = spec.build(None, None).descriptor().id;
            RegistrationRequest {
                golden: RawConsensusEvidence {
                    adapter: id,
                    evidence_version: crate::cross_domain::external::tendermint::EVIDENCE_VERSION,
                    network: "noble-testnet".to_string(),
                    payload: payload.clone(),
                    declared_height: 100,
                    declared_root: app_hash,
                    submitter: addr(1),
                },
                versions: VersionPolicy::single(
                    id,
                    crate::cross_domain::external::tendermint::EVIDENCE_VERSION,
                    0,
                ),
                economics: IntakeState::conservative_economics(1_000_000),
                policy: VerificationPolicy::strict(1_700_000_010),
                bond_atoms: economics_bond(),
                poster: addr(1),
                spec,
            }
        };

        let mut intake = IntakeState::new();
        assert!(
            matches!(
                intake.register_domain(mk_req(Some(valset_hash)), None),
                Err(IntakeError::CommitteeNotPinned)
            ),
            "unpinned Tendermint network must be refused at intake"
        );
        intake.pinned_tendermint_anchors.insert(
            "noble-testnet".to_string(),
            PinnedTendermintAnchor {
                chain_id: "noble-1".to_string(),
                validator_set_hash: valset_hash,
            },
        );
        assert!(
            matches!(
                intake.register_domain(mk_req(None), None),
                Err(IntakeError::CommitteeNotPinned)
            ),
            "missing validator_set_hash must be refused even when network is pinned"
        );
        assert!(
            matches!(
                intake.register_domain(mk_req(Some([0x99u8; 32])), None),
                Err(IntakeError::CommitteeNotPinned)
            ),
            "mismatched validator_set_hash must be refused"
        );
        let key = intake
            .register_domain(mk_req(Some(valset_hash)), None)
            .expect("pinned Tendermint anchor must admit cleanly");
        assert!(intake.registry.domain(&key).is_some());
        assert_tendermint_anchor_rotation_doors();
    }

    #[test]
    fn a_governance_installed_anchor_is_what_registration_must_match() {
        // The door a vote reaches: `install_pinned_anchor` writes the same map
        // `register_domain` reads, so an anchor that arrived by vote admits a
        // matching registration and refuses a mismatched one. Before this
        // existed, only the tests could write the map and every anchored
        // adapter was closed on every chain.
        let mut intake = IntakeState::new();
        assert_eq!(
            intake.pinned_anchor(AnchorFamily::Tendermint, "noble-testnet"),
            None,
            "an untouched slot is empty, which is what `expected_previous: None` means"
        );
        let anchor = PinnedExternalAnchor::Tendermint(
            crate::cross_domain::external::tendermint::PinnedTendermintAnchor {
                chain_id: "noble-1".to_string(),
                validator_set_hash: [0x11; 32],
            },
        );
        intake.install_pinned_anchor("noble-testnet", anchor.clone());
        assert_eq!(
            intake.pinned_anchor(AnchorFamily::Tendermint, "noble-testnet"),
            Some(anchor.clone())
        );
        assert_eq!(
            intake.pinned_anchor_digest(AnchorFamily::Tendermint, "noble-testnet"),
            Ok(Some(anchor.digest().expect("digest")))
        );

        // A replacement changes the digest, which is the value a vote binds:
        // an expected_previous taken against the old anchor no longer matches.
        let replacement = PinnedExternalAnchor::Tendermint(
            crate::cross_domain::external::tendermint::PinnedTendermintAnchor {
                chain_id: "noble-1".to_string(),
                validator_set_hash: [0x22; 32],
            },
        );
        let before = intake
            .pinned_anchor_digest(AnchorFamily::Tendermint, "noble-testnet")
            .expect("digest");
        intake.install_pinned_anchor("noble-testnet", replacement.clone());
        let after = intake
            .pinned_anchor_digest(AnchorFamily::Tendermint, "noble-testnet")
            .expect("digest");
        assert_ne!(before, after);
        assert_eq!(after, Some(replacement.digest().expect("digest")));

        // Families do not collide: one network name denotes a different anchor
        // in each map, and the digest names the family.
        assert_eq!(
            intake.pinned_anchor(AnchorFamily::Bitcoin, "noble-testnet"),
            None
        );
        let bitcoin = PinnedExternalAnchor::Bitcoin(PinnedBitcoinAnchor {
            height: 800_000,
            block_hash: [0x33; 32],
            bits: 0x1d00_ffff,
        });
        intake.install_pinned_anchor("noble-testnet", bitcoin.clone());
        assert_ne!(
            intake
                .pinned_anchor_digest(AnchorFamily::Bitcoin, "noble-testnet")
                .expect("digest"),
            intake
                .pinned_anchor_digest(AnchorFamily::Tendermint, "noble-testnet")
                .expect("digest")
        );

        // And the anchors are inside the state root: two nodes that disagree
        // about one cannot agree about the digest.
        let mut other = IntakeState::new();
        other.install_pinned_anchor("noble-testnet", anchor);
        other.install_pinned_anchor("noble-testnet", bitcoin);
        assert_ne!(
            intake.state_digest().expect("digest"),
            other.state_digest().expect("digest")
        );
    }

    #[test]
    fn contradiction_arms_guard_cooldown_tombstones_false_claim_and_moves_digest() {
        use crate::cross_domain::external::intake_guard::{IntakeGuardError, BASE_COOLDOWN_BLOCKS};

        let mut state = IntakeState::new();
        state.on_block_committed(100);
        let key = register(&mut state);
        let admission = state.entries.get(&key).expect("entry").admission.clone();
        // Poster addr(9) is automatically bonded at registration time.
        let spec = eth_spec();
        let accepted = quorum_evidence(&spec, addr(9));
        state
            .submit_evidence(&accepted, Some(Box::new(StrictTestBls)))
            .expect("first attestation accepted");

        let digest_before = state.state_digest().expect("digest before slash");
        let mut conflicting = quorum_evidence(&spec, addr(77));
        crate::cross_domain::external::ethereum::set_deneb_state_root(
            &mut conflicting.payload,
            [0xDD; 32],
        );
        conflicting.declared_root = [0xDD; 32];

        let outcome = state
            .slash_on_contradiction(&conflicting, addr(77), Some(Box::new(StrictTestBls)))
            .expect("conflicting root slashes carrier");
        assert_eq!(outcome.slashed_prover, addr(9));
        assert_ne!(
            state.state_digest().expect("digest after slash"),
            digest_before,
            "guard cooldown and tombstone must fold into state_digest"
        );

        // Readmit domain while still inside the deterministic block cooldown ->
        // IntakeGuard blocks new submissions without any admin pause key.
        state
            .registry
            .readmit(&key, &admission, "committee rotated")
            .expect("readmit");
        state
            .bond_prover(&key, addr(12), economics_bond())
            .expect("bonds replacement prover");
        let during_cooldown = quorum_evidence(&spec, addr(12));
        assert!(matches!(
            state.submit_evidence(&during_cooldown, Some(Box::new(StrictTestBls))),
            Err(IntakeError::Guard(IntakeGuardError::CooldownActive { .. }))
        ));

        // Advance chain past BASE_COOLDOWN_BLOCKS -> cooldown opens automatically,
        // yet replaying the withdrawn false claim stays permanently tombstoned.
        state.on_block_committed(100 + BASE_COOLDOWN_BLOCKS);
        assert!(matches!(
            state.submit_evidence(&during_cooldown, Some(Box::new(StrictTestBls))),
            Err(IntakeError::Guard(
                IntakeGuardError::ContradictedClaimReplay { .. }
            ))
        ));

        // The truthful conflicting root at the same height is accepted cleanly.
        let mut truthful = quorum_evidence(&spec, addr(12));
        crate::cross_domain::external::ethereum::set_deneb_state_root(
            &mut truthful.payload,
            [0xDD; 32],
        );
        truthful.declared_root = [0xDD; 32];
        state
            .submit_evidence(&truthful, Some(Box::new(StrictTestBls)))
            .expect("honest replacement root settles once cooldown expires");
    }

    #[test]
    fn casper_and_mysticeti_register_settle_and_freeze_on_objective_faults() {
        use crate::cross_domain::external::casper_ffg::{
            encode_ffg_payload, FfgEquivocationProof, FfgValidator, FfgVote, PinnedFfgCommittee,
            CASPER_FFG_ADAPTER_NAME, FFG_EVIDENCE_VERSION,
        };
        use crate::cross_domain::external::mysticeti_dag::{
            encode_mysticeti_evidence, MysticetiAnchorCommitment, MysticetiEquivocationProof,
            MysticetiMember, MysticetiVertex, MysticetiWaveEvidence, PinnedMysticetiCommittee,
            MYSTICETI_DAG_ADAPTER_NAME, MYSTICETI_EVIDENCE_VERSION,
        };
        use crate::cross_domain::external::profile::DomainState;
        use crate::crypto::ctx;
        use crate::crypto::primitives::{KeyPair, PqKeyPair};

        let mut intake = IntakeState::new();
        intake.on_block_committed(50);
        let ed = KeyPair::from_seed(&[0x31; 32]).expect("ed");
        let pq = PqKeyPair::generate();
        let pub_ed = ed.public_key_bytes();
        let pub_pq = pq.public_key_bytes().to_vec();
        let mut non_slash_policy = VerificationPolicy::strict(0);
        non_slash_policy.require_slashable = false;

        let ffg_net = "eth-ffg-intake";
        let ffg_committee = PinnedFfgCommittee::new(
            10,
            vec![FfgValidator {
                pubkey: pub_ed,
                stake: 1_000,
                pq_pubkey: pub_pq.clone(),
            }],
        )
        .expect("ffg committee");
        intake.pin_casper_ffg_committee(ffg_net, ffg_committee.clone());
        let sign_ffg =
            |src_epoch: u64, src_root: [u8; 32], tgt_epoch: u64, tgt_root: [u8; 32]| -> FfgVote {
                let mut vote = FfgVote {
                    signer: pub_ed,
                    source_epoch: src_epoch,
                    source_root: src_root,
                    target_epoch: tgt_epoch,
                    target_root: tgt_root,
                    signature: Vec::new(),
                    pq_signature: Vec::new(),
                };
                let digest = vote.digest(ffg_net);
                vote.signature = ed.sign(&digest).to_vec();
                vote.pq_signature = pq.sign(ctx::CROSS_DOMAIN_V1, &digest).expect("pq");
                vote
            };
        let v1 = sign_ffg(8, [0x11; 32], 9, [0x21; 32]);
        let v2 = sign_ffg(9, [0x21; 32], 10, [0x31; 32]);
        let ffg_raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(CASPER_FFG_ADAPTER_NAME),
            evidence_version: FFG_EVIDENCE_VERSION,
            network: ffg_net.to_string(),
            payload: encode_ffg_payload(
                9,
                [0x21; 32],
                [0x11; 32],
                10,
                [0x31; 32],
                std::slice::from_ref(&v1),
                &[v2],
            ),
            declared_height: 10,
            declared_root: [0x31; 32],
            submitter: addr(1),
        };
        let ffg_spec = AdapterSpec::CasperFfg {
            network: ffg_net.to_string(),
            committee: Some(ffg_committee),
        };
        let ffg_key = intake
            .register_domain(
                RegistrationRequest {
                    spec: ffg_spec.clone(),
                    policy: non_slash_policy.clone(),
                    economics: IntakeState::conservative_economics(1_000),
                    versions: versions_for(&ffg_spec),
                    golden: ffg_raw.clone(),
                    bond_atoms: economics_bond(),
                    poster: addr(1),
                },
                None,
            )
            .expect("register casper");
        assert_eq!(
            intake
                .submit_evidence(&ffg_raw, None)
                .expect("submit")
                .height,
            10
        );
        let outer_v = sign_ffg(7, [0x17; 32], 10, [0x98; 32]);
        let casper_proof = FfgEquivocationProof {
            vote_a: outer_v,
            vote_b: v1,
        };
        intake
            .adjudicate_casper_ffg_equivocation(&ffg_key, &casper_proof)
            .expect("casper surround slash");
        assert_eq!(
            intake.registry.domain(&ffg_key).expect("dom").record.state,
            DomainState::Faulted
        );
        assert!(matches!(
            intake.adjudicate_casper_ffg_equivocation(&ffg_key, &casper_proof),
            Err(IntakeError::Registry(RegistryError::NotServing { .. }))
        ));
        assert_eq!(
            intake
                .guard
                .record_of(&ffg_key)
                .expect("guard")
                .adverse_round_blocks
                .len(),
            1
        );

        let my_net = "sui-mysticeti-intake";
        let my_comm = PinnedMysticetiCommittee::new(
            3,
            vec![MysticetiMember {
                ed25519_pubkey: pub_ed,
                voting_weight: 500,
                pq_pubkey: pub_pq,
            }],
        )
        .expect("mysticeti committee");
        intake.pin_mysticeti_committee(my_net, my_comm.clone());
        let sign_my = |round: u64, payload_digest: [u8; 32], parents: Vec<[u8; 32]>| {
            let mut vtx = MysticetiVertex {
                author: pub_ed,
                epoch: 3,
                round,
                payload_digest,
                parents,
                ed25519_sig: Vec::new(),
                pq_sig: Vec::new(),
            };
            let digest = vtx.digest(my_net);
            vtx.ed25519_sig = ed.sign(&digest).to_vec();
            vtx.pq_sig = pq.sign(ctx::CROSS_DOMAIN_V1, &digest).expect("pq");
            vtx
        };
        let commit = MysticetiAnchorCommitment {
            state_root: [0x41; 32],
            tx_root: [0x42; 32],
            event_root: [0x43; 32],
            block_hash: [0x44; 32],
            parent_anchor_digest: [0x40; 32],
        };
        let anchor_v = sign_my(10, commit.digest(), vec![commit.parent_anchor_digest]);
        let vote_v = sign_my(11, [0x51; 32], vec![anchor_v.digest(my_net)]);
        let dec_v = sign_my(12, [0x61; 32], vec![vote_v.digest(my_net)]);
        let my_raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(MYSTICETI_DAG_ADAPTER_NAME),
            evidence_version: MYSTICETI_EVIDENCE_VERSION,
            network: my_net.to_string(),
            payload: encode_mysticeti_evidence(&MysticetiWaveEvidence {
                commitment: commit.clone(),
                anchor: anchor_v.clone(),
                voting_vertices: vec![vote_v],
                decision_vertices: vec![dec_v],
            }),
            declared_height: 10,
            declared_root: commit.state_root,
            submitter: addr(2),
        };
        let my_spec = AdapterSpec::MysticetiDag {
            network: my_net.to_string(),
            committee: Some(my_comm),
        };
        let my_key = intake
            .register_domain(
                RegistrationRequest {
                    spec: my_spec.clone(),
                    policy: non_slash_policy,
                    economics: IntakeState::conservative_economics(1_000),
                    versions: versions_for(&my_spec),
                    golden: my_raw,
                    bond_atoms: economics_bond(),
                    poster: addr(2),
                },
                None,
            )
            .expect("register mysticeti");
        let fork_v = sign_my(10, [0xEE; 32], vec![commit.parent_anchor_digest]);
        let my_proof = MysticetiEquivocationProof {
            vertex_a: anchor_v,
            vertex_b: fork_v,
        };
        intake
            .adjudicate_mysticeti_equivocation(&my_key, &my_proof)
            .expect("mysticeti equivocation");
        assert_eq!(
            intake.registry.domain(&my_key).expect("dom").record.state,
            DomainState::Faulted
        );
        assert!(matches!(
            intake.adjudicate_mysticeti_equivocation(&my_key, &my_proof),
            Err(IntakeError::Registry(RegistryError::NotServing { .. }))
        ));
        assert_eq!(
            intake
                .guard
                .record_of(&my_key)
                .expect("guard")
                .adverse_round_blocks
                .len(),
            1
        );
    }

    #[test]
    fn bitvm_covenant_registers_and_freezes_on_disprove_script_fraud() {
        use crate::cross_domain::external::bitvm_covenant::{
            encode_bitvm_evidence, evaluate_chunk_transition, expand_compact_bits,
            hash_trace_merkle_node, BitVmCovenantEvidence, BitVmPegClaim, DisproveScriptProof,
            MerkleStep, PinnedBitVmAnchor, TraceChunkStep, BITVM_COVENANT_ADAPTER_NAME,
            BITVM_EVIDENCE_VERSION, POW_HEADER_LEN,
        };
        use crate::cross_domain::external::profile::DomainState;
        use crate::crypto::ctx;
        use crate::crypto::primitives::{KeyPair, PqKeyPair};

        let mut intake = IntakeState::new();
        intake.on_block_committed(50);
        let op_ed = KeyPair::from_seed(&[0x32; 32]).expect("ed");
        let op_pq = PqKeyPair::generate();
        let pub_ed = op_ed.public_key_bytes();
        let pub_pq = op_pq.public_key_bytes().to_vec();
        let mut non_slash_policy = VerificationPolicy::strict(0);
        non_slash_policy.require_slashable = false;

        let bv_net = "btc-bitvm2-intake";
        let bits = 0x207f_ffffu32;
        let prog = [0x77; 32];
        let bv_anchor = PinnedBitVmAnchor {
            height: 50,
            block_hash: [0x12; 32],
            bits,
            program_hash: prog,
            min_pow_confirmations: 6,
            challenge_blocks: 4,
            operator_ed25519_pubkey: pub_ed,
            operator_pq_pubkey: pub_pq,
        };
        intake.pin_bitvm_anchor(bv_net, bv_anchor.clone());
        let pre = [0x81; 32];
        let wit = [0x82; 32];
        let post = evaluate_chunk_transition(&prog, 0, &pre, 3, &wit);
        let chunk = TraceChunkStep {
            chunk_index: 0,
            pre_state: pre,
            claimed_post_state: post,
            step_opcode: 3,
            step_witness: wit,
        };
        let sib = [0x83; 32];
        let trace_root = hash_trace_merkle_node(&chunk.leaf_digest(), &sib);
        let mut claim = BitVmPegClaim {
            state_root: post,
            tx_root: [0x84; 32],
            event_root: [0x85; 32],
            program_hash: prog,
            trace_merkle_root: trace_root,
            trace_chunk_count: 2,
            claim_pow_height: 51,
            operator_ed25519_sig: Vec::new(),
            operator_pq_sig: Vec::new(),
        };
        let claim_digest = claim.signing_digest(bv_net);
        claim.operator_ed25519_sig = op_ed.sign(&claim_digest).to_vec();
        claim.operator_pq_sig = op_pq.sign(ctx::CROSS_DOMAIN_V1, &claim_digest).expect("pq");
        let txid =
            crate::cross_domain::external::bitcoin_spv::sha256d(&claim.covenant_tx_bytes(bv_net));
        let target = expand_compact_bits(bits).expect("target");
        let mine = |prev: [u8; 32], mr: [u8; 32], ts: u32| -> [u8; POW_HEADER_LEN] {
            for nonce in 0u32..50_000 {
                let mut hdr = [0u8; POW_HEADER_LEN];
                let (ver_slot, rem1) = hdr.split_at_mut(4);
                ver_slot.copy_from_slice(&0x2000_0000u32.to_le_bytes());
                let (prev_slot, rem2) = rem1.split_at_mut(32);
                prev_slot.copy_from_slice(&prev);
                let (mr_slot, rem3) = rem2.split_at_mut(32);
                mr_slot.copy_from_slice(&mr);
                let (time_slot, rem4) = rem3.split_at_mut(4);
                time_slot.copy_from_slice(&ts.to_le_bytes());
                let (bits_slot, nonce_slot) = rem4.split_at_mut(4);
                bits_slot.copy_from_slice(&bits.to_le_bytes());
                nonce_slot.copy_from_slice(&nonce.to_le_bytes());
                let mut be = crate::cross_domain::external::bitcoin_spv::sha256d(&hdr);
                be.reverse();
                if be <= target {
                    return hdr;
                }
            }
            panic!("mine failed");
        };
        let mut headers = Vec::new();
        let mut prev = bv_anchor.block_hash;
        for idx in 0u32..6 {
            let offset = u8::try_from(idx).unwrap_or(0);
            let mr = if idx == 0 {
                txid
            } else {
                [0x90u8.saturating_add(offset); 32]
            };
            let hdr = mine(prev, mr, 1_700_000_000 + idx * 600);
            prev = crate::cross_domain::external::bitcoin_spv::sha256d(&hdr);
            headers.push(hdr);
        }
        let bv_raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(BITVM_COVENANT_ADAPTER_NAME),
            evidence_version: BITVM_EVIDENCE_VERSION,
            network: bv_net.to_string(),
            payload: encode_bitvm_evidence(&BitVmCovenantEvidence {
                headers,
                claim_header_index: 0,
                spv_merkle_proof: Vec::new(),
                claim: claim.clone(),
            }),
            declared_height: 51,
            declared_root: post,
            submitter: addr(3),
        };
        let bv_spec = AdapterSpec::BitVmCovenant {
            network: bv_net.to_string(),
            anchor: Some(bv_anchor),
        };
        let bv_key = intake
            .register_domain(
                RegistrationRequest {
                    spec: bv_spec.clone(),
                    policy: non_slash_policy,
                    economics: IntakeState::conservative_economics(1_000),
                    versions: versions_for(&bv_spec),
                    golden: bv_raw,
                    bond_atoms: economics_bond(),
                    poster: addr(3),
                },
                None,
            )
            .expect("register bitvm");
        let bad_chunk = TraceChunkStep {
            claimed_post_state: [0xFE; 32],
            ..chunk
        };
        let bad_root = hash_trace_merkle_node(&bad_chunk.leaf_digest(), &sib);
        let mut bad_claim = BitVmPegClaim {
            state_root: [0xFE; 32],
            trace_merkle_root: bad_root,
            ..claim
        };
        let bad_digest = bad_claim.signing_digest(bv_net);
        bad_claim.operator_ed25519_sig = op_ed.sign(&bad_digest).to_vec();
        bad_claim.operator_pq_sig = op_pq.sign(ctx::CROSS_DOMAIN_V1, &bad_digest).expect("pq");
        let disprove_proof = DisproveScriptProof {
            claim: bad_claim,
            disputed_chunk: bad_chunk,
            trace_merkle_proof: vec![MerkleStep {
                sibling: sib,
                sibling_is_left: false,
            }],
        };
        intake
            .adjudicate_bitvm_disprove(&bv_key, &disprove_proof)
            .expect("bitvm disprove");
        assert_eq!(
            intake.registry.domain(&bv_key).expect("dom").record.state,
            DomainState::Faulted
        );
        assert!(matches!(
            intake.adjudicate_bitvm_disprove(&bv_key, &disprove_proof),
            Err(IntakeError::Registry(RegistryError::NotServing { .. }))
        ));
        assert_eq!(
            intake
                .guard
                .record_of(&bv_key)
                .expect("guard")
                .adverse_round_blocks
                .len(),
            1
        );
        a_work_challenge_must_carry_strictly_more_difficulty_than_the_accepted_attestation();
    }

    #[test]
    fn hotstuff_equivocation_freezes_domain_and_rejects_faulted_replay() {
        use crate::cross_domain::external::hotstuff::{
            hotstuff_fault_test_fixture, sign_hotstuff_equivocation_proof,
        };
        use crate::cross_domain::external::profile::DomainState;

        let mut intake = IntakeState::new();
        intake.on_block_committed(50);
        let net = "aptos-hotstuff-intake";
        let (committee, keys, golden) = hotstuff_fault_test_fixture(net, 7, addr(1));
        intake.pin_hotstuff_committee(net, committee.clone());

        let mut policy = VerificationPolicy::strict(0);
        policy.require_slashable = false;
        let spec = AdapterSpec::HotStuffQc {
            network: net.to_string(),
            committee: Some(committee),
        };
        let hs_key = intake
            .register_domain(
                RegistrationRequest {
                    spec: spec.clone(),
                    policy,
                    economics: IntakeState::conservative_economics(1_000),
                    versions: versions_for(&spec),
                    golden,
                    bond_atoms: economics_bond(),
                    poster: addr(1),
                },
                None,
            )
            .expect("register hotstuff");

        let Some((culprit_ed, culprit_pq)) = keys.get(1) else {
            panic!("missing validator fixture");
        };
        let mut proof = sign_hotstuff_equivocation_proof(
            net, 7, 45, [0xA1; 32], [0xB2; 32], culprit_ed, culprit_pq,
        );
        // Missing ML-DSA-65 signature is rejected without faulting or adding adverse rounds.
        let saved_pq = std::mem::take(&mut proof.vote_b.pq_sig);
        assert!(intake
            .adjudicate_hotstuff_equivocation(&hs_key, &proof)
            .is_err());
        assert_eq!(
            intake.registry.domain(&hs_key).expect("dom").record.state,
            DomainState::Admitted
        );
        assert!(intake
            .guard
            .record_of(&hs_key)
            .is_none_or(|g| g.adverse_round_blocks.is_empty()));

        proof.vote_b.pq_sig = saved_pq;
        let (reported_signer, weight) = intake
            .adjudicate_hotstuff_equivocation(&hs_key, &proof)
            .expect("hotstuff equivocation");
        assert_eq!(reported_signer, culprit_ed.public_key_bytes());
        assert_eq!(weight, 100);
        assert_eq!(
            intake.registry.domain(&hs_key).expect("dom").record.state,
            DomainState::Faulted
        );
        assert_eq!(
            intake
                .guard
                .record_of(&hs_key)
                .expect("guard")
                .adverse_round_blocks
                .len(),
            1
        );

        // Replaying on an already-Faulted domain must fail closed with NotServing.
        assert!(matches!(
            intake.adjudicate_hotstuff_equivocation(&hs_key, &proof),
            Err(IntakeError::Registry(RegistryError::NotServing { .. }))
        ));
        assert_eq!(
            intake
                .guard
                .record_of(&hs_key)
                .expect("guard")
                .adverse_round_blocks
                .len(),
            1
        );
    }

    fn a_work_challenge_must_carry_strictly_more_difficulty_than_the_accepted_attestation() {
        let work = |difficulty_bits| SecurityBacking::Work { difficulty_bits };
        assert!(out_works(10, &work(11)));
        assert!(!out_works(10, &work(10)), "a tie slashes nobody");
        assert!(!out_works(10, &work(9)));
        assert!(
            !out_works(10, &SecurityBacking::Authority { count: 7 }),
            "a proof with no work behind it cannot out-work work"
        );
        assert!(!out_works(10, &SecurityBacking::None));
    }

    fn sign_tendermint_rotation_commit(
        chain_id: &str,
        height: u64,
        commit_time: u64,
        app_hash: [u8; 32],
        next_validators_hash: [u8; 32],
        keys: &[(&ed25519_dalek::SigningKey, u64)],
        signer_indices: &[usize],
    ) -> (
        Vec<crate::cross_domain::external::tendermint::TendermintValidator>,
        crate::cross_domain::external::tendermint::TendermintCommitEvidence,
    ) {
        use crate::cross_domain::external::tendermint::{
            validator_address_of, validator_set_commitment, vote_sign_bytes,
            TendermintCommitEvidence, TendermintSignature, TendermintValidator,
        };
        use ed25519_dalek::Signer;

        let validators: Vec<TendermintValidator> = keys
            .iter()
            .map(|(sk, power)| {
                let pk: [u8; 32] = sk.verifying_key().to_bytes();
                TendermintValidator {
                    address: validator_address_of(&pk),
                    public_key: pk,
                    voting_power: *power,
                }
            })
            .collect();
        let validators_hash = validator_set_commitment(&validators);
        let proposer_address = validators.first().map_or([0u8; 20], |v| v.address);
        let parts_hash = [0x3cu8; 32];
        let mut commit = TendermintCommitEvidence {
            chain_id: chain_id.to_string(),
            height,
            round: 0,
            block_hash: [0u8; 32],
            parts_total: 1,
            parts_hash,
            version_block: 11,
            last_block_hash: [0x11u8; 32],
            last_parts_total: 1,
            last_parts_hash: [0x22u8; 32],
            last_commit_hash: [0x33u8; 32],
            data_hash: [0x44u8; 32],
            validators_hash,
            next_validators_hash,
            consensus_hash: [0x66u8; 32],
            app_hash,
            last_results_hash: [0x88u8; 32],
            evidence_hash: [0xaau8; 32],
            proposer_address,
            commit_time,
            commit_time_nanos: 0,
            validators: validators.clone(),
            signatures: Vec::new(),
        };
        commit.block_hash = commit.header_hash();
        let ts_i64 = i64::try_from(commit_time).expect("timestamp fits i64");
        commit.signatures = signer_indices
            .iter()
            .map(|&idx| {
                let (sk, _) = keys.get(idx).copied().expect("signer index");
                let pk: [u8; 32] = sk.verifying_key().to_bytes();
                let sign_bytes = vote_sign_bytes(
                    chain_id,
                    height,
                    0,
                    &commit.block_hash,
                    1,
                    &parts_hash,
                    (ts_i64, 0),
                );
                TendermintSignature {
                    address: validator_address_of(&pk),
                    timestamp_seconds: ts_i64,
                    timestamp_nanos: 0,
                    signature: sk.sign(&sign_bytes).to_bytes().to_vec(),
                }
            })
            .collect();
        (validators, commit)
    }

    fn assert_tendermint_anchor_rotation_doors() {
        use crate::cross_domain::external::spec::AdapterError;
        use crate::cross_domain::external::tendermint::{
            validator_set_commitment, PinnedTendermintAnchor, TendermintLightParams,
            TrustedTendermintState,
        };
        use ed25519_dalek::SigningKey;

        let all_sks: Vec<SigningKey> = (1u8..=6)
            .map(|b| SigningKey::from_bytes(&[b; 32]))
            .collect();
        let honest_refs: Vec<(&SigningKey, u64)> =
            all_sks.iter().take(4).map(|sk| (sk, 100u64)).collect();
        let rotated_refs: Vec<(&SigningKey, u64)> = all_sks
            .iter()
            .skip(2)
            .take(4)
            .map(|sk| (sk, 100u64))
            .collect();
        let attacker_sks: Vec<SigningKey> = (0xA1u8..=0xA4)
            .map(|b| SigningKey::from_bytes(&[b; 32]))
            .collect();
        let attacker_refs: Vec<(&SigningKey, u64)> =
            attacker_sks.iter().map(|sk| (sk, 100u64)).collect();

        let (honest_vals, anchor_h100) = sign_tendermint_rotation_commit(
            "noble-1",
            100,
            1_700_000_000,
            [0x5au8; 32],
            [0u8; 32],
            &honest_refs,
            &[0, 1, 2],
        );
        let honest_hash = validator_set_commitment(&honest_vals);
        let (attacker_vals, attacker_h101) = sign_tendermint_rotation_commit(
            "noble-1",
            101,
            1_700_000_010,
            [0xEEu8; 32],
            [0u8; 32],
            &attacker_refs,
            &[0, 1, 2, 3],
        );
        let attacker_hash = validator_set_commitment(&attacker_vals);

        let mut intake = IntakeState::new();
        intake.pin_tendermint_anchor(
            "noble-testnet",
            PinnedTendermintAnchor {
                chain_id: "noble-1".to_string(),
                validator_set_hash: honest_hash,
            },
        );

        // 1. Tampering `next_validators_hash` on a genuine anchor commit without
        //    honest quorum signatures over the rewritten header must fail closed.
        let mut tampered_anchor = anchor_h100.clone();
        tampered_anchor.next_validators_hash = attacker_hash;
        tampered_anchor.block_hash = tampered_anchor.header_hash();
        assert!(matches!(
            intake.rotate_tendermint_anchor(
                "noble-testnet",
                &tampered_anchor,
                &attacker_h101,
                None,
                86_400,
                1_700_000_020,
            ),
            Err(IntakeError::Registry(RegistryError::Adapter(
                AdapterError::Crypto { .. }
            )))
        ));
        // Supplying an attacker-signed anchor commit directly fails the pin check.
        assert!(matches!(
            intake.rotate_tendermint_anchor(
                "noble-testnet",
                &attacker_h101,
                &attacker_h101,
                None,
                86_400,
                1_700_000_020,
            ),
            Err(IntakeError::CommitteeNotPinned)
        ));

        // 2. Bisection rotation must also refuse an unsigned `next_validators_hash`
        //    that diverges from the pinned validator set (zero-signature hijack).
        let forged_trusted = TrustedTendermintState {
            chain_id: "noble-1".to_string(),
            height: 100,
            time_secs: 1_700_000_000,
            trusting_period_secs: 86_400,
            validators: honest_vals.clone(),
            next_validators_hash: attacker_hash,
        };
        let bisection_params = TendermintLightParams {
            trusting_period_secs: 86_400,
            unbonding_period_secs: 172_800,
            max_clock_drift_secs: 5,
            max_height_drift: 100_000,
        };
        assert!(matches!(
            intake.rotate_tendermint_anchor_bisection(
                "noble-testnet",
                &forged_trusted,
                bisection_params,
                std::slice::from_ref(&attacker_h101),
                1_700_000_020,
            ),
            Err(IntakeError::Registry(RegistryError::Adapter(
                AdapterError::ConsensusRule { .. }
            )))
        ));

        // 3. Trusting-period bounds: 0, > MAX_TENDERMINT_TRUSTING_PERIOD_SECS,
        //    `u64::MAX`, and expired anchor commits must all fail closed.
        let (rotated_vals, rot_h120) = sign_tendermint_rotation_commit(
            "noble-1",
            120,
            1_700_000_100,
            [0x6bu8; 32],
            [0u8; 32],
            &rotated_refs,
            &[0, 1, 2],
        );
        assert_eq!(
            rot_h120.validators_hash,
            validator_set_commitment(&rotated_vals)
        );
        for bad_period in [
            0u64,
            IntakeState::MAX_TENDERMINT_TRUSTING_PERIOD_SECS + 1,
            u64::MAX,
        ] {
            assert!(matches!(
                intake.rotate_tendermint_anchor(
                    "noble-testnet",
                    &anchor_h100,
                    &rot_h120,
                    None,
                    bad_period,
                    1_700_000_105,
                ),
                Err(IntakeError::Registry(RegistryError::Adapter(
                    AdapterError::ConsensusRule { .. }
                )))
            ));
        }
        assert!(matches!(
            intake.rotate_tendermint_anchor(
                "noble-testnet",
                &anchor_h100,
                &rot_h120,
                None,
                86_400,
                1_700_086_400,
            ),
            Err(IntakeError::Registry(RegistryError::Adapter(
                AdapterError::Stale { .. }
            )))
        ));
        assert_eq!(
            intake
                .pinned_tendermint_anchors
                .get("noble-testnet")
                .map(|p| p.validator_set_hash),
            Some(honest_hash)
        );

        // 4. Register a live `TendermintCommit` domain and verify rollback refusal + sync.
        assert_tendermint_domain_rotation_sync(
            &mut intake,
            &honest_refs,
            &rotated_refs,
            &anchor_h100,
            &rot_h120,
        );
    }

    fn assert_tendermint_domain_rotation_sync(
        intake: &mut IntakeState,
        honest_refs: &[(&ed25519_dalek::SigningKey, u64)],
        rotated_refs: &[(&ed25519_dalek::SigningKey, u64)],
        anchor_h100: &crate::cross_domain::external::tendermint::TendermintCommitEvidence,
        rot_h120: &crate::cross_domain::external::tendermint::TendermintCommitEvidence,
    ) {
        use crate::cross_domain::external::spec::AdapterError;
        use crate::cross_domain::external::tendermint::EVIDENCE_VERSION;

        let honest_hash = anchor_h100.validators_hash;
        let rotated_hash = rot_h120.validators_hash;
        let spec = AdapterSpec::TendermintCommit {
            network: "noble-testnet".to_string(),
            chain_id: "noble-1".to_string(),
            validator_set_hash: Some(honest_hash),
        };
        let adapter_id = spec.build(None, None).descriptor().id;
        let mk_raw = |c: &crate::cross_domain::external::tendermint::TendermintCommitEvidence| {
            RawConsensusEvidence {
                adapter: adapter_id,
                evidence_version: EVIDENCE_VERSION,
                network: "noble-testnet".to_string(),
                declared_height: c.height,
                declared_root: c.app_hash,
                payload: bincode::serialize(c).expect("encode commit"),
                submitter: addr(1),
            }
        };
        let mut policy = VerificationPolicy::strict(1_700_000_000);
        policy.max_age = 3_600;
        let key = intake
            .register_domain(
                RegistrationRequest {
                    spec: spec.clone(),
                    policy,
                    economics: IntakeState::conservative_economics(1_000_000),
                    versions: versions_for(&spec),
                    golden: mk_raw(anchor_h100),
                    bond_atoms: economics_bond(),
                    poster: addr(1),
                },
                None,
            )
            .expect("register domain");

        let (_, tip_h110) = sign_tendermint_rotation_commit(
            "noble-1",
            110,
            1_700_000_050,
            [0x61u8; 32],
            [0u8; 32],
            honest_refs,
            &[0, 1, 2],
        );
        intake
            .submit_evidence(&mk_raw(&tip_h110), None)
            .expect("accept finalized height 110");

        let (_, stale_rot_h105) = sign_tendermint_rotation_commit(
            "noble-1",
            105,
            1_700_000_060,
            [0x62u8; 32],
            [0u8; 32],
            rotated_refs,
            &[0, 1, 2],
        );
        assert!(matches!(
            intake.rotate_tendermint_anchor(
                "noble-testnet",
                anchor_h100,
                &stale_rot_h105,
                None,
                86_400,
                1_700_000_070,
            ),
            Err(IntakeError::Registry(RegistryError::Adapter(
                AdapterError::ConsensusRule { .. }
            )))
        ));

        let skip = intake
            .rotate_tendermint_anchor(
                "noble-testnet",
                &tip_h110,
                rot_h120,
                None,
                86_400,
                1_700_000_105,
            )
            .expect("valid two-phase rotation to height 120");
        assert_eq!(skip.validator_set_hash, rotated_hash);
        assert_eq!(
            intake
                .pinned_tendermint_anchors
                .get("noble-testnet")
                .map(|p| p.validator_set_hash),
            Some(rotated_hash)
        );

        let (_, retired_h121) = sign_tendermint_rotation_commit(
            "noble-1",
            121,
            1_700_000_110,
            [0x71u8; 32],
            [0u8; 32],
            honest_refs,
            &[0, 1, 2],
        );
        assert!(intake
            .submit_evidence(&mk_raw(&retired_h121), None)
            .is_err());

        let (_, post_rot_h121) = sign_tendermint_rotation_commit(
            "noble-1",
            121,
            1_700_000_110,
            [0x72u8; 32],
            [0u8; 32],
            rotated_refs,
            &[0, 1, 2],
        );
        let attested = intake
            .submit_evidence(&mk_raw(&post_rot_h121), None)
            .expect("rotated validator set commit must be accepted");
        assert_eq!(attested.height, 121);

        intake
            .registry
            .mark_faulted(&key, "rotation readmit probe")
            .expect("fault domain");
        let stored_entry = intake.entries.get(&key).expect("stored entry").clone();
        let rebuilt = stored_entry
            .spec
            .build(None, Some(stored_entry.golden.clone()));
        let (re_adm, _) =
            crate::cross_domain::external::admit_observed(rebuilt.as_ref(), &stored_entry.policy);
        intake
            .registry
            .readmit(&key, &re_adm, "post-rotation readmission")
            .expect("readmission must succeed with rotated golden evidence");
    }

    /// A refusal that only counts its failures cannot be diagnosed from a
    /// log line; the error must name the probes that did not pass.
    #[test]
    fn a_refused_admission_names_its_failing_probes() {
        use crate::cross_domain::external::selftest::{AdmissionReport, ProbeOutcome, RefusalKind};

        let report = AdmissionReport {
            adapter_version: 1,
            evidence_version: 1,
            golden_verified: true,
            probes: vec![
                (
                    String::from("header-flip"),
                    ProbeOutcome::Refused {
                        kind: RefusalKind::ConsensusRule,
                    },
                ),
                (String::from("signature-strip"), ProbeOutcome::Accepted),
            ],
            probe_commitment: [0u8; 32],
            admitted: false,
        };
        assert_eq!(
            report.failing_probe_names(),
            vec![String::from("signature-strip")]
        );

        let err = IntakeError::AdmissionRefused {
            golden_verified: report.golden_verified,
            passed: report.passed(),
            total: report.total(),
            failing: report.failing_probe_names(),
        };
        let shown = err.to_string();
        assert!(
            shown.contains("signature-strip"),
            "refusal must name the failing probe: {shown}"
        );
        assert!(
            !shown.contains("header-flip"),
            "a passing probe must not be blamed: {shown}"
        );
    }

    /// The Babylon registration under the fixture pin, with the policy and
    /// economics every Babylon test in this module shares.
    fn babylon_request(
        pinned: Option<crate::cross_domain::external::babylon_eots::PinnedBabylonEots>,
        economics: DomainEconomics,
        poster: Address,
    ) -> RegistrationRequest {
        use crate::cross_domain::external::babylon_eots::test_support;
        let spec = AdapterSpec::BabylonEots {
            network: test_support::NETWORK.to_string(),
            pinned,
        };
        let mut policy = VerificationPolicy::strict(0);
        policy.require_slashable = false;
        let golden = test_support::golden_evidence();
        RegistrationRequest {
            versions: VersionPolicy::single(golden.adapter, golden.evidence_version, 0),
            spec,
            policy,
            economics,
            bond_atoms: economics.required_bond_atoms(),
            poster,
            golden,
        }
    }

    #[test]
    fn babylon_eots_admission_requires_the_governance_pin_and_honest_economics() {
        use crate::cross_domain::external::babylon_eots::test_support;

        let mut intake = IntakeState::new();
        intake.on_block_committed(50);
        let economics = IntakeState::conservative_economics(1_000);
        let econ = DomainEconomics {
            routing_ceiling_atoms: 1_000,
            fee: ProverFee {
                base_atoms: 10_000,
                value_bps: 0,
            },
            challenge: ChallengeReward {
                bps_of_slash: 500,
                floor_atoms: 1,
            },
            unbonding_heights: 10,
        };

        // Nobody has installed a pin for the network: a registrant cannot
        // announce its own EOTS keys, whether it carries a table or none.
        assert_eq!(
            intake
                .register_domain(
                    babylon_request(Some(test_support::pinned()), economics, addr(9)),
                    None
                )
                .unwrap_err(),
            IntakeError::CommitteeNotPinned
        );
        assert_eq!(
            intake
                .register_domain(babylon_request(None, economics, addr(9)), None)
                .unwrap_err(),
            IntakeError::CommitteeNotPinned
        );

        // A pin is installed, but the registration carries a different
        // table: refused. The spec must equal the governance value.
        let mut foreign = test_support::pinned();
        foreign.epoch_keys[0].1 = test_support::public_key_for(0x5C);
        intake.pin_babylon_eots_anchor(test_support::NETWORK, test_support::pinned());
        assert_eq!(
            intake
                .register_domain(babylon_request(None, economics, addr(9)), None)
                .unwrap_err(),
            IntakeError::CommitteeNotPinned
        );
        assert_eq!(
            intake
                .register_domain(babylon_request(Some(foreign), economics, addr(9)), None)
                .unwrap_err(),
            IntakeError::CommitteeNotPinned
        );
        // The door compares the registration's table to the installed one by
        // equality; validity is enforced at install (governance) and at
        // admission. An invalid pin the registration echoes exactly therefore
        // passes the door and is refused by the admission circuit instead: the
        // golden vote cannot verify under an empty key table.
        let mut malformed = test_support::pinned();
        malformed.epoch_keys.clear();
        intake.pin_babylon_eots_anchor(test_support::NETWORK, malformed.clone());
        assert!(
            matches!(
                intake.register_domain(babylon_request(Some(malformed), economics, addr(9)), None),
                Err(IntakeError::AdmissionRefused {
                    golden_verified: false,
                    ..
                })
            ),
            "an empty key table cannot certify the golden vote"
        );

        // The governance pin, echoed exactly: admitted. Economics under
        // which lying pays are still refused before admission runs.
        intake.pin_babylon_eots_anchor(test_support::NETWORK, test_support::pinned());
        assert_eq!(
            intake
                .register_domain(
                    babylon_request(Some(test_support::pinned()), econ, addr(9)),
                    None
                )
                .unwrap_err(),
            IntakeError::DishonestEconomics
        );
        let key = intake
            .register_domain(
                babylon_request(Some(test_support::pinned()), economics, addr(9)),
                None,
            )
            .expect("a pinned Babylon registration is admitted");
        assert_eq!(
            key,
            DomainKey::from_parts(
                &crate::cross_domain::external::babylon_eots::eots_adapter_id(),
                test_support::NETWORK
            )
        );
        let entry = intake.entries.get(&key).expect("entry");
        let AdapterSpec::BabylonEots {
            pinned: Some(stored),
            ..
        } = &entry.spec
        else {
            panic!("the stored spec keeps the pin it was admitted under");
        };
        assert_eq!(stored, &test_support::pinned());
    }

    #[test]
    fn babylon_eots_equivocation_door_freezes_the_domain_and_refuses_a_foreign_provider() {
        use crate::cross_domain::external::babylon_eots::test_support;
        use crate::cross_domain::external::profile::DomainState;

        let mut intake = IntakeState::new();
        intake.on_block_committed(50);
        let economics = IntakeState::conservative_economics(1_000);
        let pin = test_support::pinned();
        intake.pin_babylon_eots_anchor(test_support::NETWORK, pin.clone());
        let key = intake
            .register_domain(babylon_request(Some(pin.clone()), economics, addr(9)), None)
            .expect("register babylon");
        assert_eq!(
            intake.registry.domain(&key).expect("dom").record.state,
            DomainState::Admitted
        );

        // A real equivocation by a provider the pinned table does not name is
        // internally valid (both signatures verify under its own key) and is
        // still refused: it is not this domain's provider.
        let foreign = test_support::foreign_equivocation_proof(0x5C);
        foreign
            .check()
            .expect("the foreign proof is self-consistent");
        let refused = intake
            .adjudicate_babylon_eots_equivocation(&key, &foreign)
            .unwrap_err();
        assert!(
            refused.to_string().contains("does not name"),
            "refusal names the binding: {refused}"
        );
        assert_eq!(
            intake.registry.domain(&key).expect("dom").record.state,
            DomainState::Admitted
        );
        assert_eq!(
            intake
                .guard
                .record_of(&key)
                .map(|r| r.adverse_round_blocks.len())
                .unwrap_or(0),
            0,
            "a refused proof records no adverse round"
        );

        // The pinned provider's equivocation: adverse round recorded, the
        // domain frozen, and the door refuses a replay.
        let proof = test_support::equivocation_proof(&pin, test_support::PINNED_SEED);
        let (provider, _epoch) = intake
            .adjudicate_babylon_eots_equivocation(&key, &proof)
            .expect("the pinned provider's equivocation freezes the domain");
        assert_eq!(provider, proof.provider);
        assert_eq!(
            intake.registry.domain(&key).expect("dom").record.state,
            DomainState::Faulted
        );
        assert_eq!(
            intake
                .guard
                .record_of(&key)
                .expect("guard")
                .adverse_round_blocks
                .len(),
            1
        );
        assert!(matches!(
            intake.adjudicate_babylon_eots_equivocation(&key, &proof),
            Err(IntakeError::Registry(RegistryError::NotServing { .. }))
        ));

        // A door for another family refuses by name rather than by shape.
        let eth_key = register(&mut intake);
        assert!(matches!(
            intake.adjudicate_babylon_eots_equivocation(&eth_key, &proof),
            Err(IntakeError::Registry(
                RegistryError::DescriptorMismatch { .. }
            ))
        ));
    }

    /// The NIPoPoW registration under the fixture genesis pin, with the policy
    /// and economics the NIPoPoW tests in this module share. Probabilistic-work
    /// finality is not slashable by Budlum, so `require_slashable` is off.
    fn nipopow_request(
        genesis: Option<crate::cross_domain::external::nipopow::PinnedNipopowGenesis>,
        economics: DomainEconomics,
        poster: Address,
    ) -> RegistrationRequest {
        let (_, _, golden) = crate::cross_domain::external::nipopow::tests::make_golden_fixture();
        let spec = AdapterSpec::NipopowSuperblock {
            network: golden.network.clone(),
            genesis,
        };
        let mut policy = VerificationPolicy::strict(0);
        policy.require_slashable = false;
        RegistrationRequest {
            versions: VersionPolicy::single(golden.adapter, golden.evidence_version, 0),
            spec,
            policy,
            economics,
            bond_atoms: economics.required_bond_atoms(),
            poster,
            golden,
        }
    }

    #[test]
    fn nipopow_admission_requires_the_governance_genesis_pin() {
        let mut intake = IntakeState::new();
        intake.on_block_committed(50);
        let (pinned, _, golden) =
            crate::cross_domain::external::nipopow::tests::make_golden_fixture();
        let network = golden.network.clone();
        let econ = DomainEconomics {
            routing_ceiling_atoms: 1_000,
            fee: ProverFee {
                base_atoms: 10_000,
                value_bps: 0,
            },
            challenge: ChallengeReward {
                bps_of_slash: 500,
                floor_atoms: 1,
            },
            unbonding_heights: 10,
        };
        let economics = IntakeState::conservative_economics(1_000);

        // No genesis is installed: a registrant cannot nominate its own
        // genesis block and then certify superblocks against it, whether it
        // carries a pin or none.
        assert_eq!(
            intake
                .register_domain(nipopow_request(None, economics, addr(9)), None)
                .unwrap_err(),
            IntakeError::CommitteeNotPinned
        );
        assert_eq!(
            intake
                .register_domain(
                    nipopow_request(Some(pinned.clone()), economics, addr(9)),
                    None
                )
                .unwrap_err(),
            IntakeError::CommitteeNotPinned
        );

        // The pin is installed, but the registration carries a different
        // genesis: refused before admission. Even a pin whose *only*
        // difference is a tightened `k` is a different consensus statement and
        // does not pass the door by resembling the installed one.
        intake.pin_nipopow_genesis(network.clone(), pinned.clone());
        let mut foreign = pinned.clone();
        foreign.genesis_id = [0x5D; 32];
        assert_eq!(
            intake
                .register_domain(nipopow_request(None, economics, addr(9)), None)
                .unwrap_err(),
            IntakeError::CommitteeNotPinned
        );
        assert_eq!(
            intake
                .register_domain(nipopow_request(Some(foreign), economics, addr(9)), None)
                .unwrap_err(),
            IntakeError::CommitteeNotPinned
        );
        let mut tightened = pinned.clone();
        tightened.min_suffix_k += 1;
        assert_eq!(
            intake
                .register_domain(nipopow_request(Some(tightened), economics, addr(9)), None)
                .unwrap_err(),
            IntakeError::CommitteeNotPinned
        );

        // The governance pin, echoed exactly: past the door, and then the
        // economically honest registration is admitted while a lying
        // fee/penalty shape is refused.
        assert_eq!(
            intake
                .register_domain(nipopow_request(Some(pinned.clone()), econ, addr(9)), None)
                .unwrap_err(),
            IntakeError::DishonestEconomics
        );
        let key = intake
            .register_domain(
                nipopow_request(Some(pinned.clone()), economics, addr(9)),
                None,
            )
            .expect("the governance genesis pin admits the NIPoPoW domain");
        assert_eq!(
            intake
                .registry
                .domain(&key)
                .expect("dom")
                .record
                .descriptor
                .id,
            crate::cross_domain::external::AdapterId::from_name(
                crate::cross_domain::external::nipopow::ADAPTER_NAME
            )
        );

        // The pin reaches the generic anchor door as well: it resolves by
        // family, and a zeroed field is refused at install rather than
        // installed as a genesis no evidence could ever clear.
        assert_eq!(
            intake
                .pinned_anchor(AnchorFamily::PoWSuccinct, &golden.network)
                .map(|a| a.family()),
            Some(AnchorFamily::PoWSuccinct)
        );
        let mut zeroed = pinned.clone();
        zeroed.pow_target = [0u8; 32];
        assert_eq!(
            intake
                .install_nipopow_genesis(golden.network.clone(), zeroed)
                .unwrap_err(),
            "the pinned NIPoPoW difficulty target is all zeroes"
        );
        let mut zeroed = pinned.clone();
        zeroed.min_suffix_k = 0;
        assert_eq!(
            intake
                .install_nipopow_genesis(golden.network.clone(), zeroed)
                .unwrap_err(),
            "the pinned NIPoPoW suffix stability parameter k is zero"
        );
        // A refused install leaves the good pin in place.
        assert_eq!(
            intake.pinned_nipopow_genesis.get(&golden.network).cloned(),
            Some(pinned.clone())
        );

        // And the settlement layer reads the same pin: probabilistic work with
        // the pinned suffix depth, never a slashable quorum.
        let guarantee =
            crate::settlement::universal_finality::FinalityGuarantee::for_external_spec_with_backing(
                &AdapterSpec::NipopowSuperblock {
                    network: network.clone(),
                    genesis: Some(pinned.clone()),
                },
                Some(&crate::cross_domain::external::spec::SecurityBacking::Work {
                    difficulty_bits: 96,
                }),
            );
        assert_eq!(
            guarantee.reversibility,
            crate::settlement::universal_finality::FinalityReversibility::ProbabilisticWork {
                confirmations: pinned.min_suffix_k as u64
            }
        );
        assert!(!guarantee.slashable_backing);
        let unpinned =
            crate::settlement::universal_finality::FinalityGuarantee::for_external_spec_with_backing(
                &AdapterSpec::NipopowSuperblock {
                    network,
                    genesis: None,
                },
                Some(&crate::cross_domain::external::spec::SecurityBacking::Work {
                    difficulty_bits: 96,
                }),
            );
        assert_eq!(
            unpinned.reversibility,
            crate::settlement::universal_finality::FinalityReversibility::ProbabilisticWork {
                confirmations: 0
            },
            "an unpinned spec promises no depth at all"
        );
    }
}
