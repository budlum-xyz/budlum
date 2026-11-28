//! The shape of a finality proof: which commitment fields it binds, how its
//! signers are weighted, what the verifier had to trust first, and what "deep
//! enough" means for its family.
//!
//! # Why this exists
//!
//! `FinalityProof` is an enum and `DomainFinalityAdapter` is a trait, so a proof
//! can be verified. What the type system does not carry is **what a given
//! proof actually commits to**. That fact was written out by hand inside every
//! adapter, and the adapters disagree in substance: a Bitcoin SPV header binds a
//! transaction root and no state root, a ZK claim binds a state root and no
//! transaction root, and a BLS certificate binds a height and a block hash and
//! nothing else. A reader had to open each adapter to learn the difference, and
//! a caller had no way to ask.
//!
//! The claim "consensus of consensuses" is a claim about *composition*: proofs
//! from different families meet in one `GlobalBlockHeader`. Composition is only
//! auditable if the bound field set of each family is stated in one place
//! rather than inferred from each adapter's control flow. This module is the
//! vocabulary for that statement; the table itself is
//! [`FinalityProof::shape`](crate::domain::finality_adapter::FinalityProof::shape),
//! beside the enum it describes.
//!
//! # What it is not
//!
//! It is not a second verifier. Nothing here re-checks a signature, and the
//! shape is not trusted: an adapter that ignores its own shape still verifies
//! the way it always did. The value is that the table is written once, is
//! testable against every variant, and is the statement settlement checks
//! itself against before it anchors a root (see
//! `settlement::domains::verify_commitment_finality_observed`).
//!
//! # Stability
//!
//! `binds` is a `u32` bitset, not a struct of booleans, so a new bound can be
//! added without moving the value. The constants are append-only: a proof whose
//! shape changes from one release to the next is a proof whose meaning changed.

/// The proof binds `DomainCommitment::domain_height`.
pub const BINDS_HEIGHT: u32 = 1 << 0;
/// The proof binds `DomainCommitment::parent_domain_block_hash`.
pub const BINDS_PARENT_HASH: u32 = 1 << 1;
/// The proof binds `DomainCommitment::domain_block_hash`.
pub const BINDS_BLOCK_HASH: u32 = 1 << 2;
/// The proof binds `DomainCommitment::state_root`.
pub const BINDS_STATE_ROOT: u32 = 1 << 3;
/// The proof binds `DomainCommitment::tx_root`.
pub const BINDS_TX_ROOT: u32 = 1 << 4;
/// The proof binds `DomainCommitment::event_root`.
pub const BINDS_EVENT_ROOT: u32 = 1 << 5;
/// The proof binds `DomainCommitment::timestamp_ms`.
pub const BINDS_TIMESTAMP: u32 = 1 << 6;

/// How the signers of a quorum proof are weighted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumClass {
    /// Chainwork, not signers: the heaviest valid chain wins.
    WorkWeighted,
    /// Stake: the signed stake must exceed the threshold.
    StakeWeighted,
    /// One authority one vote, with no stake concept.
    AuthorityWeighted,
    /// No signer quorum at all: the proof carries its own verified statement,
    /// a validity proof or a claim registry entry, and what a verifier accepts
    /// is that statement rather than a set of signers.
    ProofCarrying,
}

/// What a verifier had to accept before the proof could be checked at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAnchor {
    /// The domain's registered `validator_set_hash`.
    RegisteredSet,
    /// The domain's declared `genesis_state_root`.
    GenesisStateRoot,
    /// A checkpoint the caller already trusts (a header window's first header).
    TrustedCheckpoint,
    /// The proof carries its own claim registry entry; no external anchor.
    ProofCarrying,
}

/// What "deep enough" means for the family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepthClass {
    /// A number of descendant headers.
    Confirmations,
    /// One block is final; depth is a liveness question, not a safety one.
    SingleBlock,
    /// A proof that is delayed by construction (a STARK behind its claim).
    ProofDelay,
}

/// What one proof family covers, stated once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalityProofShape {
    /// A bitset of the `BINDS_*` constants.
    pub binds: u32,
    pub quorum: QuorumClass,
    pub trust_anchor: TrustAnchor,
    pub depth: DepthClass,
}

/// Canonical identifier for each built-in external consensus family in
/// `crate::cross_domain::external`.
///
/// Paired one-to-one with `AdapterDescriptor::consensus_kind` so the bridge
/// seam can refuse a built-in family name whose descriptor was downgraded to
/// `TrustModel::TrustedParty`, a mismatched finality class, or a foreign time
/// unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub(crate) enum ExternalVerifierFamily {
    AlgorandStateProof = 0,
    AptosJolteonBft = 1,
    ArweaveSpOra = 2,
    AuxPowPop = 3,
    BabylonEots = 4,
    BasedPreconf = 5,
    BitcoinNakamotoPow = 6,
    BitVmCovenant = 7,
    CasperFfg = 8,
    ChainKeyNiDkg = 9,
    CelestiaDas = 10,
    BullsharkDagBft = 11,
    EthereumGasperSync = 12,
    GhostdagPow = 13,
    HeterogeneousMultiProver = 14,
    HoneyBadgerBft = 15,
    HotStuffChainedBft = 16,
    MinaSuccinctRecursive = 17,
    MysticetiDag = 18,
    NearDoomslugBft = 19,
    NipopowSuperblock = 20,
    OuroborosMithril = 21,
    PoSpaceVdf = 22,
    RestakingAvs = 23,
    SimplexBft = 24,
    SolanaTowerBft = 25,
    StarkValidityRollup = 26,
    StellarScp = 27,
    SymbioticVault = 28,
    TendermintBft = 29,
    TonCatchainBft = 30,
    BudZkVmExecution = 31,
}

/// Refusal reasons when translating an external finality attestation into
/// [`FinalityProofShape`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExternalShapeError {
    /// The attestation carries `SecurityBacking::None`.
    EmptySecurityBacking,
    /// A signature backing carries zero threshold, zero weight, or fewer
    /// signers than its own threshold.
    DegenerateSignatureQuorum {
        signers: u64,
        required: u64,
        total_weight: u128,
    },
    /// A work-backed attestation reports zero accumulated difficulty bits.
    ZeroWorkBacking,
    /// An authority-backed attestation reports zero authorities.
    EmptyAuthoritySet,
    /// The attestation's `time_unit` disagrees with its adapter descriptor.
    TimeUnitMismatch {
        expected: crate::cross_domain::external::spec::TimeUnit,
        observed: crate::cross_domain::external::spec::TimeUnit,
    },
    /// A built-in consensus family was presented without a pinned trust anchor.
    MissingTrustAnchor { family: ExternalVerifierFamily },
    /// A built-in consensus family's descriptor drifted from its canonical
    /// finality kind, trust model, or time unit.
    FamilyProfileMismatch {
        family: ExternalVerifierFamily,
        reason: &'static str,
    },
    /// `TrustModel::TrustedParty` may never finalize a domain commitment.
    TrustedPartyBackingRefused,
    /// `attestation.security` contradicts the adapter's declared finality
    /// kind, trust model, or canonical verifier family.
    SecurityBackingMismatch {
        consensus_kind: String,
        reason: &'static str,
    },
}

impl std::fmt::Display for ExternalShapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySecurityBacking => {
                f.write_str("external attestation carries no cryptographic security backing")
            }
            Self::DegenerateSignatureQuorum {
                signers,
                required,
                total_weight,
            } => write!(
                f,
                "degenerate signature quorum (signers={signers}, required={required}, total_weight={total_weight})"
            ),
            Self::ZeroWorkBacking => {
                f.write_str("work-backed external attestation carries zero difficulty bits")
            }
            Self::EmptyAuthoritySet => {
                f.write_str("authority-backed external attestation carries zero authorities")
            }
            Self::TimeUnitMismatch { expected, observed } => write!(
                f,
                "attestation time unit {} does not match descriptor time unit {}",
                observed.as_str(),
                expected.as_str()
            ),
            Self::MissingTrustAnchor { family } => write!(
                f,
                "external consensus family {} requires a pinned trust anchor",
                family.consensus_kind()
            ),
            Self::FamilyProfileMismatch { family, reason } => write!(
                f,
                "external family profile mismatch for {}: {reason}",
                family.consensus_kind()
            ),
            Self::TrustedPartyBackingRefused => {
                f.write_str("TrustedParty trust model cannot finalize an external domain commitment")
            }
            Self::SecurityBackingMismatch {
                consensus_kind,
                reason,
            } => write!(
                f,
                "external security backing mismatch for {consensus_kind}: {reason}"
            ),
        }
    }
}

impl std::error::Error for ExternalShapeError {}

impl ExternalVerifierFamily {
    /// Resolve a canonical `AdapterDescriptor::consensus_kind` string to its
    /// built-in verifier family.
    #[must_use]
    pub(crate) fn from_consensus_kind(kind: &str) -> Option<Self> {
        match kind {
            "algorand-pure-pos-stateproof-pq" => Some(Self::AlgorandStateProof),
            "aptos-jolteon-2chain-bft" => Some(Self::AptosJolteonBft),
            "arweave-spora-recall" => Some(Self::ArweaveSpOra),
            "auxpow-pop-merged-mining" => Some(Self::AuxPowPop),
            "babylon-btc-restaking-eots" => Some(Self::BabylonEots),
            "based-preconf-focil" => Some(Self::BasedPreconf),
            "nakamoto-pow" => Some(Self::BitcoinNakamotoPow),
            "bitvm2-pow-covenant" => Some(Self::BitVmCovenant),
            "casper-ffg-checkpoint" => Some(Self::CasperFfg),
            "chain-key-nidkg-threshold-bls" => Some(Self::ChainKeyNiDkg),
            "modular-das-nmt-2d" => Some(Self::CelestiaDas),
            "bullshark-round-dag-bft" => Some(Self::BullsharkDagBft),
            "gasper-pos" => Some(Self::EthereumGasperSync),
            "ghostdag-k-cluster-pow" => Some(Self::GhostdagPow),
            "heterogeneous-multiprover-2of3" => Some(Self::HeterogeneousMultiProver),
            "asynchronous-common-subset-bft" => Some(Self::HoneyBadgerBft),
            "hotstuff-chained-bft" => Some(Self::HotStuffChainedBft),
            "succinct-recursive-samasika-stark" => Some(Self::MinaSuccinctRecursive),
            "mysticeti-uncertified-dag" => Some(Self::MysticetiDag),
            "near-nightshade-doomslug-bft" => Some(Self::NearDoomslugBft),
            "nipopow-superblock" => Some(Self::NipopowSuperblock),
            "ouroboros-praos-with-mithril-stm" => Some(Self::OuroborosMithril),
            "pospace-hash-vdf" => Some(Self::PoSpaceVdf),
            "restaking-avs-eots" => Some(Self::RestakingAvs),
            "simplex-monadbft-2round" => Some(Self::SimplexBft),
            "solana-tower-bft" => Some(Self::SolanaTowerBft),
            "stark-state-diff-validity-rollup" => Some(Self::StarkValidityRollup),
            "federated-bft-scp" => Some(Self::StellarScp),
            "symbiotic-curated-vault" => Some(Self::SymbioticVault),
            "tendermint-bft" => Some(Self::TendermintBft),
            "ton-masterchain-catchain-bft" => Some(Self::TonCatchainBft),
            "zkvm-execution" => Some(Self::BudZkVmExecution),
            _ => None,
        }
    }

    /// Canonical `consensus_kind` string declared by this family's adapter.
    #[must_use]
    pub(crate) const fn consensus_kind(self) -> &'static str {
        match self {
            Self::AlgorandStateProof => "algorand-pure-pos-stateproof-pq",
            Self::AptosJolteonBft => "aptos-jolteon-2chain-bft",
            Self::ArweaveSpOra => "arweave-spora-recall",
            Self::AuxPowPop => "auxpow-pop-merged-mining",
            Self::BabylonEots => "babylon-btc-restaking-eots",
            Self::BasedPreconf => "based-preconf-focil",
            Self::BitcoinNakamotoPow => "nakamoto-pow",
            Self::BitVmCovenant => "bitvm2-pow-covenant",
            Self::CasperFfg => "casper-ffg-checkpoint",
            Self::ChainKeyNiDkg => "chain-key-nidkg-threshold-bls",
            Self::CelestiaDas => "modular-das-nmt-2d",
            Self::BullsharkDagBft => "bullshark-round-dag-bft",
            Self::EthereumGasperSync => "gasper-pos",
            Self::GhostdagPow => "ghostdag-k-cluster-pow",
            Self::HeterogeneousMultiProver => "heterogeneous-multiprover-2of3",
            Self::HoneyBadgerBft => "asynchronous-common-subset-bft",
            Self::HotStuffChainedBft => "hotstuff-chained-bft",
            Self::MinaSuccinctRecursive => "succinct-recursive-samasika-stark",
            Self::MysticetiDag => "mysticeti-uncertified-dag",
            Self::NearDoomslugBft => "near-nightshade-doomslug-bft",
            Self::NipopowSuperblock => "nipopow-superblock",
            Self::OuroborosMithril => "ouroboros-praos-with-mithril-stm",
            Self::PoSpaceVdf => "pospace-hash-vdf",
            Self::RestakingAvs => "restaking-avs-eots",
            Self::SimplexBft => "simplex-monadbft-2round",
            Self::SolanaTowerBft => "solana-tower-bft",
            Self::StarkValidityRollup => "stark-state-diff-validity-rollup",
            Self::StellarScp => "federated-bft-scp",
            Self::SymbioticVault => "symbiotic-curated-vault",
            Self::TendermintBft => "tendermint-bft",
            Self::TonCatchainBft => "ton-masterchain-catchain-bft",
            Self::BudZkVmExecution => "zkvm-execution",
        }
    }

    /// Enforce that `descriptor` preserves this family's canonical finality
    /// kind, trust model, and time unit, and that a trust anchor is present.
    pub(crate) fn verify_descriptor(
        self,
        descriptor: &crate::cross_domain::external::spec::AdapterDescriptor,
        anchor_pinned: bool,
    ) -> Result<(), ExternalShapeError> {
        use crate::cross_domain::external::spec::{FinalityKind, TimeUnit, TrustModel};

        if !anchor_pinned {
            return Err(ExternalShapeError::MissingTrustAnchor { family: self });
        }
        if descriptor.consensus_kind != self.consensus_kind() {
            return Err(ExternalShapeError::FamilyProfileMismatch {
                family: self,
                reason: "descriptor consensus_kind does not match verifier family",
            });
        }
        if matches!(descriptor.trust_model, TrustModel::TrustedParty) {
            return Err(ExternalShapeError::FamilyProfileMismatch {
                family: self,
                reason: "built-in consensus family may never downgrade to TrustedParty",
            });
        }

        // One table decides the profile; this function only asks it.
        let Some(profile) = super::decision::family(self) else {
            return Err(ExternalShapeError::FamilyProfileMismatch {
                family: self,
                reason: "family has no canonical profile row; its backing rule was never decided",
            });
        };
        let valid_profile = profile.accepts(
            descriptor.finality_kind,
            &descriptor.trust_model,
            descriptor.time_unit,
        );

        if !valid_profile {
            return Err(ExternalShapeError::FamilyProfileMismatch {
                family: self,
                reason: "descriptor finality_kind, trust_model, or time_unit violates canonical family profile",
            });
        }
        Ok(())
    }
}

impl FinalityProofShape {
    /// Derive the unified [`FinalityProofShape`] of a verified external
    /// attestation, failing closed on missing or degenerate security backing
    /// and descriptor/attestation time-unit drift.
    pub(crate) fn from_external_attestation(
        descriptor: &crate::cross_domain::external::spec::AdapterDescriptor,
        attestation: &crate::cross_domain::external::spec::FinalityAttestation,
    ) -> Result<Self, ExternalShapeError> {
        use crate::cross_domain::external::spec::{FinalityKind, SecurityBacking, TrustModel};

        if attestation.time_unit != descriptor.time_unit {
            return Err(ExternalShapeError::TimeUnitMismatch {
                expected: descriptor.time_unit,
                observed: attestation.time_unit,
            });
        }
        if matches!(descriptor.trust_model, TrustModel::TrustedParty) {
            return Err(ExternalShapeError::TrustedPartyBackingRefused);
        }

        let (quorum, trust_anchor) = match (&descriptor.trust_model, &attestation.security) {
            (_, SecurityBacking::None) => return Err(ExternalShapeError::EmptySecurityBacking),
            (
                _,
                SecurityBacking::SignatureSet {
                    signers,
                    required,
                    total_weight,
                    ..
                },
            ) => {
                if *required == 0 || *signers < *required || *total_weight == 0 {
                    return Err(ExternalShapeError::DegenerateSignatureQuorum {
                        signers: *signers,
                        required: *required,
                        total_weight: *total_weight,
                    });
                }
                (QuorumClass::StakeWeighted, TrustAnchor::RegisteredSet)
            }
            (_, SecurityBacking::Work { difficulty_bits }) => {
                if *difficulty_bits == 0 {
                    return Err(ExternalShapeError::ZeroWorkBacking);
                }
                (QuorumClass::WorkWeighted, TrustAnchor::TrustedCheckpoint)
            }
            (_, SecurityBacking::Zk { .. }) => {
                (QuorumClass::ProofCarrying, TrustAnchor::ProofCarrying)
            }
            (TrustModel::Trustless, SecurityBacking::Authority { .. }) => {
                return Err(ExternalShapeError::SecurityBackingMismatch {
                    consensus_kind: descriptor.consensus_kind.clone(),
                    reason:
                        "Trustless descriptor cannot finalize on permissioned Authority backing",
                });
            }
            (TrustModel::HonestMajority { .. }, SecurityBacking::Authority { count }) => {
                if *count == 0 {
                    return Err(ExternalShapeError::EmptyAuthoritySet);
                }
                (QuorumClass::AuthorityWeighted, TrustAnchor::RegisteredSet)
            }
            (TrustModel::TrustedParty, SecurityBacking::Authority { .. }) => {
                return Err(ExternalShapeError::TrustedPartyBackingRefused);
            }
        };

        if let Some(family) =
            ExternalVerifierFamily::from_consensus_kind(&descriptor.consensus_kind)
        {
            // The family's profile decides which backing may carry it. The
            // pairing lives in `decision::FAMILY_PROFILES`; this call site no
            // longer restates it, so a family cannot be widened here and
            // narrowed there.
            let Some(profile) = decision::family(family) else {
                return Err(ExternalShapeError::FamilyProfileMismatch {
                    family,
                    reason:
                        "family has no canonical profile row; its backing rule was never decided",
                });
            };
            let backing = match attestation.security {
                SecurityBacking::SignatureSet { .. } => decision::Backing::SignatureSet,
                SecurityBacking::Work { .. } => decision::Backing::Work,
                SecurityBacking::Authority { .. } => decision::Backing::Authority,
                SecurityBacking::Zk { .. } => decision::Backing::Zk,
                SecurityBacking::None => return Err(ExternalShapeError::EmptySecurityBacking),
            };
            let allowed = profile.accepts_backing(backing);
            if !allowed {
                return Err(ExternalShapeError::SecurityBackingMismatch {
                    consensus_kind: descriptor.consensus_kind.clone(),
                    reason: "attestation SecurityBacking violates canonical verifier family",
                });
            }
        } else {
            let kind_allowed = match descriptor.finality_kind {
                FinalityKind::Proven => matches!(
                    attestation.security,
                    SecurityBacking::Zk { .. } | SecurityBacking::SignatureSet { .. }
                ),
                FinalityKind::Probabilistic => matches!(
                    attestation.security,
                    SecurityBacking::Work { .. } | SecurityBacking::SignatureSet { .. }
                ),
                FinalityKind::ProtocolFinality | FinalityKind::EconomicFinality => {
                    !matches!(attestation.security, SecurityBacking::Work { .. })
                }
            };
            if !kind_allowed {
                return Err(ExternalShapeError::SecurityBackingMismatch {
                    consensus_kind: descriptor.consensus_kind.clone(),
                    reason: "attestation SecurityBacking contradicts descriptor FinalityKind",
                });
            }
        }

        let depth = match descriptor.finality_kind {
            FinalityKind::Probabilistic => DepthClass::Confirmations,
            FinalityKind::Proven => DepthClass::ProofDelay,
            FinalityKind::ProtocolFinality | FinalityKind::EconomicFinality => {
                DepthClass::SingleBlock
            }
        };

        let mut binds = BINDS_HEIGHT | BINDS_STATE_ROOT | BINDS_TIMESTAMP;
        if attestation.attested_block_hash.is_some() {
            binds |= BINDS_BLOCK_HASH;
        }
        if attestation.attested_tx_root.is_some() {
            binds |= BINDS_TX_ROOT;
        }
        if attestation.attested_event_root.is_some() {
            binds |= BINDS_EVENT_ROOT;
        }

        Ok(Self {
            binds,
            quorum,
            trust_anchor,
            depth,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::finality::{FinalityCert, ValidatorEntry, ValidatorSetSnapshot};
    use crate::core::address::Address;
    use crate::domain::finality_adapter::FinalityProof;
    use crate::domain::types::Hash32;

    const ZERO: Hash32 = [0u8; 32];

    fn cert(height: u64) -> FinalityCert {
        FinalityCert {
            epoch: 1,
            checkpoint_height: height,
            checkpoint_hash: hex::encode([1u8; 32]),
            chain_id: 1,
            agg_sig_bls: Vec::new(),
            bitmap: Vec::new(),
            set_hash: hex::encode([2u8; 32]),
            seat_table_version: 0,
        }
    }

    fn snapshot() -> ValidatorSetSnapshot {
        ValidatorSetSnapshot {
            epoch: 1,
            validators: vec![ValidatorEntry {
                address: Address::from([3u8; 32]),
                stake: 1,
                bls_public_key: Vec::new(),
                pop_signature: Vec::new(),
                pq_public_key: Vec::new(),
            }],
            set_hash: hex::encode([2u8; 32]),
            total_stake: 1,
        }
    }

    const EVERY_FIELD: u32 = BINDS_HEIGHT
        | BINDS_PARENT_HASH
        | BINDS_BLOCK_HASH
        | BINDS_STATE_ROOT
        | BINDS_TX_ROOT
        | BINDS_EVENT_ROOT
        | BINDS_TIMESTAMP;

    /// Every variant's shape must agree with the message its adapter verifies.
    #[test]
    fn every_variant_declares_the_fields_its_adapter_binds() {
        let cases: Vec<(FinalityProof, u32)> = vec![
            (
                FinalityProof::PoS {
                    cert: cert(9),
                    validator_snapshot: snapshot(),
                },
                BINDS_HEIGHT | BINDS_BLOCK_HASH,
            ),
            (
                FinalityProof::PoA {
                    authorities: vec![Address::from([3u8; 32])],
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::Bft {
                    round: 1,
                    commit_hash: ZERO,
                    cert: cert(9),
                    validator_snapshot: snapshot(),
                },
                BINDS_HEIGHT | BINDS_BLOCK_HASH,
            ),
            (
                FinalityProof::Zk {
                    domain_id: 1,
                    target_height: 2,
                    final_state_root: ZERO,
                },
                BINDS_HEIGHT | BINDS_STATE_ROOT,
            ),
            (
                FinalityProof::Dag {
                    round: 1,
                    anchor: ZERO,
                    parent_anchor: ZERO,
                    authorities: vec![Address::from([3u8; 32])],
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::Poh {
                    chain: Vec::new(),
                    authorities: vec![Address::from([3u8; 32])],
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::Pospace {
                    prover: Address::from([3u8; 32]),
                    plot_id: ZERO,
                    quality_bits: 1,
                    prover_signature: Vec::new(),
                    authorities: vec![Address::from([3u8; 32])],
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::PoWHeaderChain {
                    headers: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::BitcoinSpv {
                    headers: Vec::new(),
                },
                // The header commits to its timestamp as well: the adapter
                // refuses one that moves backwards, one too far in the future,
                // and one older than the policy's max age, and it attests the
                // last header's timestamp as `finalized_at`.
                BINDS_HEIGHT
                    | BINDS_PARENT_HASH
                    | BINDS_BLOCK_HASH
                    | BINDS_TX_ROOT
                    | BINDS_TIMESTAMP,
            ),
            (
                FinalityProof::AggregatedProg {
                    program_hash: ZERO,
                    prev_height: 1,
                    prev_state_root: ZERO,
                    claim_digest: ZERO,
                },
                // The guest recomputes `output_hash` over the whole commitment
                // inside `BudAir`, so the proof binds every field a header
                // chain does.
                EVERY_FIELD,
            ),
            (
                FinalityProof::DagPq {
                    round: 1,
                    anchor: ZERO,
                    parent_anchor: ZERO,
                    authorities: Vec::new(),
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::PohPq {
                    chain: Vec::new(),
                    authorities: Vec::new(),
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::PospacePq {
                    prover: Address::from([3u8; 32]),
                    plot_id: ZERO,
                    quality_bits: 1,
                    prover_signature: Vec::new(),
                    authorities: Vec::new(),
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::AggregatedProg {
                    program_hash: ZERO,
                    prev_height: 0,
                    prev_state_root: ZERO,
                    claim_digest: ZERO,
                },
                EVERY_FIELD,
            ),
            (FinalityProof::Raw(Vec::new()), 0),
        ];
        for (proof, expected) in cases {
            assert_eq!(proof.shape().binds, expected, "{proof:?}");
        }
        assert_external_verifier_families_and_attestation_shapes();
    }

    fn assert_external_verifier_families_and_attestation_shapes() {
        use crate::cross_domain::external::spec::{
            AdapterDescriptor, AdapterId, DomainKey, FinalityAttestation, FinalityKind,
            SecurityBacking, TimeUnit, TrustModel,
        };
        use crate::crypto::facts::ObservedScheme;
        use crate::crypto::scheme::SchemeId;
        use std::collections::BTreeSet;

        let majority = TrustModel::HonestMajority { set_size: 4 };
        let canonical_profiles = [
            (
                ExternalVerifierFamily::AlgorandStateProof,
                "algorand-pure-pos-stateproof-pq",
                FinalityKind::ProtocolFinality,
                majority,
                TimeUnit::Round,
            ),
            (
                ExternalVerifierFamily::AptosJolteonBft,
                "aptos-jolteon-2chain-bft",
                FinalityKind::ProtocolFinality,
                majority,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::ArweaveSpOra,
                "arweave-spora-recall",
                FinalityKind::EconomicFinality,
                majority,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::AuxPowPop,
                "auxpow-pop-merged-mining",
                FinalityKind::Probabilistic,
                TrustModel::Trustless,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::BabylonEots,
                "babylon-btc-restaking-eots",
                FinalityKind::EconomicFinality,
                majority,
                TimeUnit::Epoch,
            ),
            (
                ExternalVerifierFamily::BasedPreconf,
                "based-preconf-focil",
                FinalityKind::EconomicFinality,
                majority,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::BitcoinNakamotoPow,
                "nakamoto-pow",
                FinalityKind::Probabilistic,
                TrustModel::Trustless,
                TimeUnit::UnixSeconds,
            ),
            (
                ExternalVerifierFamily::BitVmCovenant,
                "bitvm2-pow-covenant",
                FinalityKind::Probabilistic,
                TrustModel::Trustless,
                TimeUnit::UnixSeconds,
            ),
            (
                ExternalVerifierFamily::CasperFfg,
                "casper-ffg-checkpoint",
                FinalityKind::EconomicFinality,
                majority,
                TimeUnit::Epoch,
            ),
            (
                ExternalVerifierFamily::ChainKeyNiDkg,
                "chain-key-nidkg-threshold-bls",
                FinalityKind::ProtocolFinality,
                majority,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::CelestiaDas,
                "modular-das-nmt-2d",
                FinalityKind::EconomicFinality,
                majority,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::BullsharkDagBft,
                "bullshark-round-dag-bft",
                FinalityKind::ProtocolFinality,
                majority,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::EthereumGasperSync,
                "gasper-pos",
                FinalityKind::ProtocolFinality,
                majority,
                TimeUnit::Slot,
            ),
            (
                ExternalVerifierFamily::GhostdagPow,
                "ghostdag-k-cluster-pow",
                FinalityKind::Probabilistic,
                TrustModel::Trustless,
                TimeUnit::UnixSeconds,
            ),
            (
                ExternalVerifierFamily::HeterogeneousMultiProver,
                "heterogeneous-multiprover-2of3",
                FinalityKind::Proven,
                TrustModel::Trustless,
                TimeUnit::UnixSeconds,
            ),
            (
                ExternalVerifierFamily::HoneyBadgerBft,
                "asynchronous-common-subset-bft",
                FinalityKind::ProtocolFinality,
                majority,
                TimeUnit::Epoch,
            ),
            (
                ExternalVerifierFamily::HotStuffChainedBft,
                "hotstuff-chained-bft",
                FinalityKind::ProtocolFinality,
                majority,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::MinaSuccinctRecursive,
                "succinct-recursive-samasika-stark",
                FinalityKind::Proven,
                TrustModel::Trustless,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::MysticetiDag,
                "mysticeti-uncertified-dag",
                FinalityKind::ProtocolFinality,
                majority,
                TimeUnit::Round,
            ),
            (
                ExternalVerifierFamily::NearDoomslugBft,
                "near-nightshade-doomslug-bft",
                FinalityKind::ProtocolFinality,
                majority,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::NipopowSuperblock,
                "nipopow-superblock",
                FinalityKind::Probabilistic,
                TrustModel::Trustless,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::OuroborosMithril,
                "ouroboros-praos-with-mithril-stm",
                FinalityKind::EconomicFinality,
                TrustModel::HonestMajority { set_size: 0 },
                TimeUnit::Epoch,
            ),
            (
                ExternalVerifierFamily::PoSpaceVdf,
                "pospace-hash-vdf",
                FinalityKind::Probabilistic,
                TrustModel::Trustless,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::RestakingAvs,
                "restaking-avs-eots",
                FinalityKind::EconomicFinality,
                majority,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::SimplexBft,
                "simplex-monadbft-2round",
                FinalityKind::ProtocolFinality,
                majority,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::SolanaTowerBft,
                "solana-tower-bft",
                FinalityKind::ProtocolFinality,
                majority,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::StarkValidityRollup,
                "stark-state-diff-validity-rollup",
                FinalityKind::Proven,
                TrustModel::Trustless,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::StellarScp,
                "federated-bft-scp",
                FinalityKind::ProtocolFinality,
                majority,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::SymbioticVault,
                "symbiotic-curated-vault",
                FinalityKind::EconomicFinality,
                majority,
                TimeUnit::Epoch,
            ),
            (
                ExternalVerifierFamily::TendermintBft,
                "tendermint-bft",
                FinalityKind::ProtocolFinality,
                TrustModel::HonestMajority { set_size: 0 },
                TimeUnit::UnixSeconds,
            ),
            (
                ExternalVerifierFamily::TonCatchainBft,
                "ton-masterchain-catchain-bft",
                FinalityKind::ProtocolFinality,
                majority,
                TimeUnit::Height,
            ),
            (
                ExternalVerifierFamily::BudZkVmExecution,
                "zkvm-execution",
                FinalityKind::Proven,
                TrustModel::Trustless,
                TimeUnit::Height,
            ),
        ];

        assert_eq!(canonical_profiles.len(), 32);
        let mut tags = BTreeSet::new();
        for (family, kind, finality_kind, trust_model, time_unit) in canonical_profiles {
            assert!(tags.insert(family as u8), "duplicate tag for {kind}");
            assert_eq!(family.consensus_kind(), kind);
            assert_eq!(
                ExternalVerifierFamily::from_consensus_kind(kind),
                Some(family)
            );

            let adapter_id = AdapterId::from_name(kind);
            let descriptor = AdapterDescriptor {
                id: adapter_id,
                name: kind.to_string(),
                adapter_version: 1,
                accepted_evidence_versions: vec![1],
                consensus_kind: kind.to_string(),
                finality_kind,
                required_depth: 1,
                time_unit,
                trust_model,
            };
            assert_eq!(family.verify_descriptor(&descriptor, true), Ok(()));
            assert_eq!(
                family.verify_descriptor(&descriptor, false),
                Err(ExternalShapeError::MissingTrustAnchor { family })
            );

            let mut downgraded = descriptor.clone();
            downgraded.trust_model = TrustModel::TrustedParty;
            assert!(matches!(
                family.verify_descriptor(&downgraded, true),
                Err(ExternalShapeError::FamilyProfileMismatch { .. })
            ));

            let (canonical_security, expected_quorum, expected_anchor) = match family {
                ExternalVerifierFamily::StarkValidityRollup
                | ExternalVerifierFamily::MinaSuccinctRecursive
                | ExternalVerifierFamily::BudZkVmExecution
                | ExternalVerifierFamily::HeterogeneousMultiProver => (
                    SecurityBacking::Zk {
                        system: crate::cross_domain::external::spec::ProofSystem::BudlumZkVm,
                        public_inputs_digest: [0x55; 32],
                    },
                    QuorumClass::ProofCarrying,
                    TrustAnchor::ProofCarrying,
                ),
                ExternalVerifierFamily::BitcoinNakamotoPow
                | ExternalVerifierFamily::BitVmCovenant
                | ExternalVerifierFamily::GhostdagPow
                | ExternalVerifierFamily::NipopowSuperblock
                | ExternalVerifierFamily::AuxPowPop
                | ExternalVerifierFamily::PoSpaceVdf => (
                    SecurityBacking::Work {
                        difficulty_bits: 80,
                    },
                    QuorumClass::WorkWeighted,
                    TrustAnchor::TrustedCheckpoint,
                ),
                _ => (
                    SecurityBacking::SignatureSet {
                        scheme: ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG),
                        signers: 4,
                        required: 3,
                        total_weight: 100,
                        slashable: true,
                    },
                    QuorumClass::StakeWeighted,
                    TrustAnchor::RegisteredSet,
                ),
            };

            let attestation = FinalityAttestation {
                adapter: adapter_id,
                domain: DomainKey::from_parts(&adapter_id, "mainnet"),
                height: 42,
                state_root: [0x11; 32],
                attested_block_hash: Some([0x22; 32]),
                attested_event_root: None,
                attested_tx_root: Some([0x33; 32]),
                finalized_at: 100,
                time_unit,
                security: canonical_security,
                evidence_digest: [0x44; 32],
                adapter_version: 1,
                evidence_version: 1,
            };
            let shape =
                FinalityProofShape::from_external_attestation(&descriptor, &attestation).unwrap();
            assert_eq!(
                shape.binds,
                BINDS_HEIGHT
                    | BINDS_STATE_ROOT
                    | BINDS_TIMESTAMP
                    | BINDS_BLOCK_HASH
                    | BINDS_TX_ROOT
            );
            assert_eq!(shape.quorum, expected_quorum);
            assert_eq!(shape.trust_anchor, expected_anchor);

            let mut authority_downgrade = attestation.clone();
            authority_downgrade.security = SecurityBacking::Authority { count: 3 };
            assert!(
                matches!(
                    FinalityProofShape::from_external_attestation(
                        &descriptor,
                        &authority_downgrade
                    ),
                    Err(ExternalShapeError::SecurityBackingMismatch { .. })
                ),
                "built-in family {kind} must refuse Authority security backing"
            );
        }
        assert_eq!(
            ExternalVerifierFamily::from_consensus_kind("fixture-consensus"),
            None
        );
    }

    /// The two work-weighted families are the only ones that need a checkpoint
    /// the caller already trusts rather than a set the domain registered.
    #[test]
    fn work_weighted_families_anchor_on_a_checkpoint() {
        for proof in [
            FinalityProof::PoWHeaderChain {
                headers: Vec::new(),
            },
            FinalityProof::BitcoinSpv {
                headers: Vec::new(),
            },
        ] {
            let shape = proof.shape();
            assert_eq!(shape.quorum, QuorumClass::WorkWeighted);
            assert_eq!(shape.trust_anchor, TrustAnchor::TrustedCheckpoint);
            assert_eq!(shape.depth, DepthClass::Confirmations);
        }
    }

    /// A shape with no bounds reports no fields, not a panic.
    #[test]
    fn raw_shape_binds_nothing() {
        let shape = FinalityProof::Raw(Vec::new()).shape();
        assert_eq!(shape.binds, 0);
        assert_eq!(shape.quorum, QuorumClass::ProofCarrying);
        assert_eq!(shape.trust_anchor, TrustAnchor::ProofCarrying);
        assert_eq!(shape.depth, DepthClass::ProofDelay);
    }

    #[test]
    fn external_attestation_refuses_trusted_party_and_mismatched_family_backing() {
        use crate::cross_domain::external::spec::{
            AdapterDescriptor, AdapterId, DomainKey, FinalityAttestation, FinalityKind,
            SecurityBacking, TimeUnit, TrustModel,
        };
        use crate::crypto::facts::ObservedScheme;
        use crate::crypto::scheme::SchemeId;

        let id = AdapterId::from_name("shape-cross-check");
        let make_att = |time_unit: TimeUnit, security: SecurityBacking| FinalityAttestation {
            adapter: id,
            domain: DomainKey::from_parts(&id, "mainnet"),
            height: 10,
            state_root: [0x11; 32],
            attested_block_hash: Some([0x22; 32]),
            attested_event_root: None,
            attested_tx_root: None,
            finalized_at: 10,
            time_unit,
            security,
            evidence_digest: [0x33; 32],
            adapter_version: 1,
            evidence_version: 1,
        };

        let trusted_party = AdapterDescriptor {
            id,
            name: "tp".to_string(),
            adapter_version: 1,
            accepted_evidence_versions: vec![1],
            consensus_kind: "custom-tp".to_string(),
            finality_kind: FinalityKind::ProtocolFinality,
            required_depth: 0,
            time_unit: TimeUnit::Height,
            trust_model: TrustModel::TrustedParty,
        };
        assert_eq!(
            FinalityProofShape::from_external_attestation(
                &trusted_party,
                &make_att(TimeUnit::Height, SecurityBacking::Authority { count: 1 }),
            ),
            Err(ExternalShapeError::TrustedPartyBackingRefused)
        );

        let pow_desc = AdapterDescriptor {
            id,
            name: "pow".to_string(),
            adapter_version: 1,
            accepted_evidence_versions: vec![1],
            consensus_kind: "nakamoto-pow".to_string(),
            finality_kind: FinalityKind::Probabilistic,
            required_depth: 6,
            time_unit: TimeUnit::UnixSeconds,
            trust_model: TrustModel::Trustless,
        };
        assert!(matches!(
            FinalityProofShape::from_external_attestation(
                &pow_desc,
                &make_att(
                    TimeUnit::UnixSeconds,
                    SecurityBacking::SignatureSet {
                        scheme: ObservedScheme::Scheme(SchemeId::ED25519),
                        signers: 3,
                        required: 2,
                        total_weight: 3,
                        slashable: true,
                    },
                ),
            ),
            Err(ExternalShapeError::SecurityBackingMismatch { .. })
        ));
    }
}

/// One canonical family profile, in the form the two decision points use.
///
/// The same family profile is asserted in two different `match` statements on
/// two different paths: `verify_descriptor` (is this adapter still the family
/// it claims to be?) and `from_external_attestation` (does the security
/// backing this attestation carries belong to that family?). Each is written
/// as one big match, and the pairing that matters - "a family declares profile
/// P, and only backing B may satisfy P" - exists only in a reviewer's head. A
/// family added to one match and not the other is precisely how an adapter
/// would enter the tree trusting a party it was declared not to trust.
///
/// `decision::family` puts the profile in one row per family, keyed by the
/// family's own discriminant, and the gate in `xtask/gates` refuses the tree
/// when two rows disagree with the code or when the profiles cover less than
/// the whole family set. It is a description of what the code already
/// decides, not a second decision path.
pub(crate) mod decision {
    use crate::cross_domain::external::spec::{FinalityKind, TimeUnit, TrustModel};
    use crate::domain::finality_proof_model::ExternalVerifierFamily;

    /// The trust model a profile accepts, without the `set_size` payload: a
    /// built-in family never depends on how large the certified set is, only
    /// on whether honesty of that set is the assumption.
    ///
    /// WIRING: read inside this file today, by `Profile::accepts`, which
    /// `verify_descriptor` calls. The door that reads it from outside is the
    /// adapter registry, which asks a family for its profile before a foreign
    /// certificate is admitted.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Trust {
        /// Anybody with the evidence can check it.
        Trustless,
        /// An honest majority of a known, bounded set is assumed.
        HonestMajority,
    }

    /// The backing shapes that occur in the tree, as one small set.
    ///
    /// WIRING: read inside this file today, by the rows of `FAMILY_PROFILES`
    /// and by `Profile::accepts_backing`, which the attestation path calls. The
    /// door that reads it from outside is the adapter registry.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Backings {
        Work,
        SignatureSet,
        WorkOrSignatureSet,
        Zk,
        ZkOrSignatureSet,
    }

    /// One family's canonical profile.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Profile {
        pub family: ExternalVerifierFamily,
        pub consensus_kind: &'static str,
        pub finality: FinalityKind,
        pub trust: Trust,
        /// Empty means "any unit"; the families that accept more than one say
        /// so by listing them.
        pub units: &'static [TimeUnit],
        /// Which security backing the attestation may carry.
        pub backings: Backings,
    }

    /// The security backing an attestation carries.
    ///
    /// WIRING: mapped from an attestation's security backing inside
    /// `from_external_attestation`, so a row can decide whether that backing may
    /// carry the family. No other reader today.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Backing {
        SignatureSet,
        Work,
        Authority,
        Zk,
    }

    impl Profile {
        /// Which security backings this family's attestation may carry.
        ///
        /// WIRING: the attestation path asks this before a foreign certificate is
        /// admitted; see [`Profile`].
        ///
        /// This is the second half of the family profile. The first half
        /// (finality kind, trust model, time unit) lives in [`Profile`]; the
        /// pairing between the two - "a family that declares `Trustless` must
        /// present work or a proof" - used to be restated at each decision
        /// point and is now read from [`FamilyProfile::backings`].
        #[must_use]
        pub fn accepts_backing(&self, backing: Backing) -> bool {
            let accepted: &[Backing] = match self.backings {
                Backings::Work => &[Backing::Work],
                Backings::SignatureSet => &[Backing::SignatureSet],
                Backings::WorkOrSignatureSet => &[Backing::Work, Backing::SignatureSet],
                Backings::Zk => &[Backing::Zk],
                Backings::ZkOrSignatureSet => &[Backing::Zk, Backing::SignatureSet],
            };
            accepted.contains(&backing)
        }

        /// Does this profile accept the descriptor's three profile fields?
        #[must_use]
        pub fn accepts(
            &self,
            finality: FinalityKind,
            trust_model: &TrustModel,
            unit: TimeUnit,
        ) -> bool {
            self.finality == finality
                && match (self.trust, trust_model) {
                    (Trust::Trustless, TrustModel::Trustless) => true,
                    (Trust::HonestMajority, TrustModel::HonestMajority { set_size }) => {
                        *set_size > 0
                    }
                    _ => false,
                }
                && (self.units.is_empty() || self.units.contains(&unit))
        }
    }

    const UNIX: &[TimeUnit] = &[TimeUnit::UnixSeconds];
    const HEIGHT: &[TimeUnit] = &[TimeUnit::Height];
    const ROUND: &[TimeUnit] = &[TimeUnit::Round];
    const EPOCH: &[TimeUnit] = &[TimeUnit::Epoch];
    const SLOT_OR_EPOCH: &[TimeUnit] = &[TimeUnit::Slot, TimeUnit::Epoch];

    const fn p(
        family: ExternalVerifierFamily,
        consensus_kind: &'static str,
        finality: FinalityKind,
        trust: Trust,
        units: &'static [TimeUnit],
        backings: Backings,
    ) -> Profile {
        Profile {
            family,
            consensus_kind,
            finality,
            trust,
            units,
            backings,
        }
    }

    /// The backing set each family may present. Every one of the 32 families is
    /// named, and there is no `_` arm: a family added to the enum does not compile
    /// until somebody decides what may back it, and a family whose backing is
    /// widened by editing this match turns the profile gate red.
    ///
    /// WIRING: read inside this file today, by the rows of `FAMILY_PROFILES` and
    /// by the profile test that holds each family to its answer. The door that
    /// reads it from outside is the adapter registry, which asks a family which
    /// backing may carry it before a foreign certificate is admitted.
    #[must_use]
    pub const fn backings_of(family: ExternalVerifierFamily) -> Backings {
        match family {
            ExternalVerifierFamily::BitVmCovenant
            | ExternalVerifierFamily::BitcoinNakamotoPow
            | ExternalVerifierFamily::GhostdagPow
            | ExternalVerifierFamily::NipopowSuperblock => Backings::Work,
            ExternalVerifierFamily::BudZkVmExecution
            | ExternalVerifierFamily::MinaSuccinctRecursive
            | ExternalVerifierFamily::StarkValidityRollup => Backings::Zk,
            ExternalVerifierFamily::AuxPowPop | ExternalVerifierFamily::PoSpaceVdf => {
                Backings::WorkOrSignatureSet
            }
            ExternalVerifierFamily::HeterogeneousMultiProver => Backings::ZkOrSignatureSet,
            ExternalVerifierFamily::AlgorandStateProof
            | ExternalVerifierFamily::AptosJolteonBft
            | ExternalVerifierFamily::ArweaveSpOra
            | ExternalVerifierFamily::BabylonEots
            | ExternalVerifierFamily::BasedPreconf
            | ExternalVerifierFamily::BullsharkDagBft
            | ExternalVerifierFamily::CasperFfg
            | ExternalVerifierFamily::CelestiaDas
            | ExternalVerifierFamily::ChainKeyNiDkg
            | ExternalVerifierFamily::EthereumGasperSync
            | ExternalVerifierFamily::HoneyBadgerBft
            | ExternalVerifierFamily::HotStuffChainedBft
            | ExternalVerifierFamily::MysticetiDag
            | ExternalVerifierFamily::NearDoomslugBft
            | ExternalVerifierFamily::OuroborosMithril
            | ExternalVerifierFamily::RestakingAvs
            | ExternalVerifierFamily::SimplexBft
            | ExternalVerifierFamily::SolanaTowerBft
            | ExternalVerifierFamily::StellarScp
            | ExternalVerifierFamily::SymbioticVault
            | ExternalVerifierFamily::TendermintBft
            | ExternalVerifierFamily::TonCatchainBft => Backings::SignatureSet,
        }
    }

    const PROBABILISTIC: FinalityKind = FinalityKind::Probabilistic;
    const ECONOMIC: FinalityKind = FinalityKind::EconomicFinality;
    const PROTOCOL: FinalityKind = FinalityKind::ProtocolFinality;
    const PROVEN: FinalityKind = FinalityKind::Proven;
    const TRUSTLESS: Trust = Trust::Trustless;
    const MAJORITY: Trust = Trust::HonestMajority;

    /// The canonical profile of every built-in family.
    ///
    /// WIRING: read inside this file today, by `decision::family`, which both
    /// finality decision paths call. The door that reads it from outside is the
    /// adapter registry, which asks a family for its profile before a foreign
    /// certificate is admitted.
    ///
    /// One row per family, in the family's own discriminant order. The gate
    /// checks that the rows cover `0..=31` exactly once and that each row
    /// agrees with `verify_descriptor` and `from_external_attestation`.
    pub const FAMILY_PROFILES: &[Profile] = &[
        p(
            ExternalVerifierFamily::AlgorandStateProof,
            "algorand-pure-pos-stateproof-pq",
            PROTOCOL,
            MAJORITY,
            ROUND,
            backings_of(ExternalVerifierFamily::AlgorandStateProof),
        ),
        p(
            ExternalVerifierFamily::AptosJolteonBft,
            "aptos-jolteon-2chain-bft",
            PROTOCOL,
            MAJORITY,
            HEIGHT,
            backings_of(ExternalVerifierFamily::AptosJolteonBft),
        ),
        p(
            ExternalVerifierFamily::ArweaveSpOra,
            "arweave-spora-recall",
            ECONOMIC,
            MAJORITY,
            HEIGHT,
            backings_of(ExternalVerifierFamily::ArweaveSpOra),
        ),
        p(
            ExternalVerifierFamily::AuxPowPop,
            "auxpow-pop-merged-mining",
            PROBABILISTIC,
            TRUSTLESS,
            HEIGHT,
            backings_of(ExternalVerifierFamily::AuxPowPop),
        ),
        p(
            ExternalVerifierFamily::BabylonEots,
            "babylon-btc-restaking-eots",
            ECONOMIC,
            MAJORITY,
            EPOCH,
            backings_of(ExternalVerifierFamily::BabylonEots),
        ),
        p(
            ExternalVerifierFamily::BasedPreconf,
            "based-preconf-focil",
            ECONOMIC,
            MAJORITY,
            HEIGHT,
            backings_of(ExternalVerifierFamily::BasedPreconf),
        ),
        p(
            ExternalVerifierFamily::BitcoinNakamotoPow,
            "nakamoto-pow",
            PROBABILISTIC,
            TRUSTLESS,
            UNIX,
            backings_of(ExternalVerifierFamily::BitcoinNakamotoPow),
        ),
        p(
            ExternalVerifierFamily::BitVmCovenant,
            "bitvm2-pow-covenant",
            PROBABILISTIC,
            TRUSTLESS,
            UNIX,
            backings_of(ExternalVerifierFamily::BitVmCovenant),
        ),
        p(
            ExternalVerifierFamily::CasperFfg,
            "casper-ffg-checkpoint",
            ECONOMIC,
            MAJORITY,
            EPOCH,
            backings_of(ExternalVerifierFamily::CasperFfg),
        ),
        p(
            ExternalVerifierFamily::ChainKeyNiDkg,
            "chain-key-nidkg-threshold-bls",
            PROTOCOL,
            MAJORITY,
            HEIGHT,
            backings_of(ExternalVerifierFamily::ChainKeyNiDkg),
        ),
        p(
            ExternalVerifierFamily::CelestiaDas,
            "modular-das-nmt-2d",
            ECONOMIC,
            MAJORITY,
            HEIGHT,
            backings_of(ExternalVerifierFamily::CelestiaDas),
        ),
        p(
            ExternalVerifierFamily::BullsharkDagBft,
            "bullshark-round-dag-bft",
            PROTOCOL,
            MAJORITY,
            HEIGHT,
            backings_of(ExternalVerifierFamily::BullsharkDagBft),
        ),
        p(
            ExternalVerifierFamily::EthereumGasperSync,
            "gasper-pos",
            PROTOCOL,
            MAJORITY,
            SLOT_OR_EPOCH,
            backings_of(ExternalVerifierFamily::EthereumGasperSync),
        ),
        p(
            ExternalVerifierFamily::GhostdagPow,
            "ghostdag-k-cluster-pow",
            PROBABILISTIC,
            TRUSTLESS,
            UNIX,
            backings_of(ExternalVerifierFamily::GhostdagPow),
        ),
        p(
            ExternalVerifierFamily::HeterogeneousMultiProver,
            "heterogeneous-multiprover-2of3",
            PROVEN,
            TRUSTLESS,
            UNIX,
            backings_of(ExternalVerifierFamily::HeterogeneousMultiProver),
        ),
        p(
            ExternalVerifierFamily::HoneyBadgerBft,
            "asynchronous-common-subset-bft",
            PROTOCOL,
            MAJORITY,
            EPOCH,
            backings_of(ExternalVerifierFamily::HoneyBadgerBft),
        ),
        p(
            ExternalVerifierFamily::HotStuffChainedBft,
            "hotstuff-chained-bft",
            PROTOCOL,
            MAJORITY,
            HEIGHT,
            backings_of(ExternalVerifierFamily::HotStuffChainedBft),
        ),
        p(
            ExternalVerifierFamily::MinaSuccinctRecursive,
            "succinct-recursive-samasika-stark",
            PROVEN,
            TRUSTLESS,
            HEIGHT,
            backings_of(ExternalVerifierFamily::MinaSuccinctRecursive),
        ),
        p(
            ExternalVerifierFamily::MysticetiDag,
            "mysticeti-uncertified-dag",
            PROTOCOL,
            MAJORITY,
            ROUND,
            backings_of(ExternalVerifierFamily::MysticetiDag),
        ),
        p(
            ExternalVerifierFamily::NearDoomslugBft,
            "near-nightshade-doomslug-bft",
            PROTOCOL,
            MAJORITY,
            HEIGHT,
            backings_of(ExternalVerifierFamily::NearDoomslugBft),
        ),
        p(
            ExternalVerifierFamily::NipopowSuperblock,
            "nipopow-superblock",
            PROBABILISTIC,
            TRUSTLESS,
            HEIGHT,
            backings_of(ExternalVerifierFamily::NipopowSuperblock),
        ),
        p(
            ExternalVerifierFamily::OuroborosMithril,
            "ouroboros-praos-with-mithril-stm",
            ECONOMIC,
            MAJORITY,
            EPOCH,
            backings_of(ExternalVerifierFamily::OuroborosMithril),
        ),
        p(
            ExternalVerifierFamily::PoSpaceVdf,
            "pospace-hash-vdf",
            PROBABILISTIC,
            TRUSTLESS,
            HEIGHT,
            backings_of(ExternalVerifierFamily::PoSpaceVdf),
        ),
        p(
            ExternalVerifierFamily::RestakingAvs,
            "restaking-avs-eots",
            ECONOMIC,
            MAJORITY,
            HEIGHT,
            backings_of(ExternalVerifierFamily::RestakingAvs),
        ),
        p(
            ExternalVerifierFamily::SimplexBft,
            "simplex-monadbft-2round",
            PROTOCOL,
            MAJORITY,
            HEIGHT,
            backings_of(ExternalVerifierFamily::SimplexBft),
        ),
        p(
            ExternalVerifierFamily::SolanaTowerBft,
            "solana-tower-bft",
            PROTOCOL,
            MAJORITY,
            HEIGHT,
            backings_of(ExternalVerifierFamily::SolanaTowerBft),
        ),
        p(
            ExternalVerifierFamily::StarkValidityRollup,
            "stark-state-diff-validity-rollup",
            PROVEN,
            TRUSTLESS,
            HEIGHT,
            backings_of(ExternalVerifierFamily::StarkValidityRollup),
        ),
        p(
            ExternalVerifierFamily::StellarScp,
            "federated-bft-scp",
            PROTOCOL,
            MAJORITY,
            HEIGHT,
            backings_of(ExternalVerifierFamily::StellarScp),
        ),
        p(
            ExternalVerifierFamily::SymbioticVault,
            "symbiotic-curated-vault",
            ECONOMIC,
            MAJORITY,
            EPOCH,
            backings_of(ExternalVerifierFamily::SymbioticVault),
        ),
        p(
            ExternalVerifierFamily::TendermintBft,
            "tendermint-bft",
            PROTOCOL,
            MAJORITY,
            UNIX,
            backings_of(ExternalVerifierFamily::TendermintBft),
        ),
        p(
            ExternalVerifierFamily::TonCatchainBft,
            "ton-masterchain-catchain-bft",
            PROTOCOL,
            MAJORITY,
            HEIGHT,
            backings_of(ExternalVerifierFamily::TonCatchainBft),
        ),
        p(
            ExternalVerifierFamily::BudZkVmExecution,
            "zkvm-execution",
            PROVEN,
            TRUSTLESS,
            HEIGHT,
            backings_of(ExternalVerifierFamily::BudZkVmExecution),
        ),
    ];

    /// The profile of one family, or `None` if the family has no row. `None` is
    /// a finding, not a default: an unlisted family is a family nobody decided
    /// the backing rule for.
    #[must_use]
    pub fn family(f: ExternalVerifierFamily) -> Option<Profile> {
        FAMILY_PROFILES.iter().copied().find(|p| p.family == f)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod decision_tests {
    use super::decision::{family, Backing, FAMILY_PROFILES};

    const BACKINGS: [Backing; 4] = [
        Backing::SignatureSet,
        Backing::Work,
        Backing::Authority,
        Backing::Zk,
    ];
    use super::ExternalVerifierFamily;
    use crate::cross_domain::external::spec::{FinalityKind, TimeUnit, TrustModel};

    /// Every discriminant from 0 to 31 has exactly one row.
    #[test]
    fn every_family_has_exactly_one_profile() {
        for d in 0u8..=31 {
            let f = unsafe_free_family(d);
            let rows: Vec<_> = FAMILY_PROFILES.iter().filter(|p| p.family == f).collect();
            assert_eq!(
                rows.len(),
                1,
                "family {f:?} must have exactly one profile row"
            );
        }
        assert_eq!(FAMILY_PROFILES.len(), 32);
    }

    /// The row's `consensus_kind` is the family's canonical string, so the two
    /// tables cannot drift apart.
    #[test]
    fn every_profile_carries_the_canonical_consensus_kind() {
        for p in FAMILY_PROFILES {
            assert_eq!(
                p.consensus_kind,
                p.family.consensus_kind(),
                "row for {:?}",
                p.family
            );
        }
    }

    /// A profile accepts its own canonical shape and refuses every other
    /// finality kind, every wrong trust model, and an unlisted time unit.
    #[test]
    fn profiles_accept_their_shape_and_refuse_the_rest() {
        for p in FAMILY_PROFILES {
            let unit = p.units[0];
            let trust = match p.trust {
                super::decision::Trust::Trustless => TrustModel::Trustless,
                super::decision::Trust::HonestMajority => {
                    TrustModel::HonestMajority { set_size: 4 }
                }
            };
            assert!(
                p.accepts(p.finality, &trust, unit),
                "row for {:?} refuses its own shape",
                p.family
            );
            for other in [
                FinalityKind::Probabilistic,
                FinalityKind::EconomicFinality,
                FinalityKind::ProtocolFinality,
                FinalityKind::Proven,
            ] {
                if other != p.finality {
                    assert!(
                        !p.accepts(other, &trust, unit),
                        "row for {:?} accepts {other:?}",
                        p.family
                    );
                }
            }
            assert!(
                !p.accepts(p.finality, &TrustModel::TrustedParty, unit),
                "row for {:?} accepts a trusted party",
                p.family
            );
            assert!(
                !p.accepts(
                    p.finality,
                    &TrustModel::HonestMajority { set_size: 0 },
                    unit
                ),
                "row for {:?} accepts an empty set",
                p.family
            );
            for other in [
                TimeUnit::Slot,
                TimeUnit::Epoch,
                TimeUnit::Round,
                TimeUnit::Height,
                TimeUnit::UnixSeconds,
            ] {
                if !p.units.contains(&other) {
                    assert!(
                        !p.accepts(p.finality, &trust, other),
                        "row for {:?} accepts unit {other:?}",
                        p.family
                    );
                }
            }
            // The backing half of the profile is a decision too: a row that
            // accepted every backing would let a work-only family finalize on
            // a signature set, which is exactly what the match this table
            // replaced refused.
            let accepted: Vec<Backing> = BACKINGS
                .iter()
                .copied()
                .filter(|b| p.accepts_backing(*b))
                .collect();
            assert!(
                !accepted.is_empty(),
                "row for {:?} accepts no backing; it could never finalize",
                p.family
            );
            assert!(
                accepted.len() < BACKINGS.len(),
                "row for {:?} accepts every backing; the rule it states binds nothing",
                p.family
            );
        }
    }

    /// The pairings the table states are the pairings the code asserted
    /// before it, family by family. A row that silently widens a family's
    /// backing turns this test red.
    #[test]
    fn the_pairings_are_the_ones_the_code_asserted() {
        let has = |f: ExternalVerifierFamily, b: Backing| {
            family(f)
                .expect("every family has a row")
                .accepts_backing(b)
        };
        for f in [
            ExternalVerifierFamily::BitcoinNakamotoPow,
            ExternalVerifierFamily::BitVmCovenant,
            ExternalVerifierFamily::GhostdagPow,
            ExternalVerifierFamily::NipopowSuperblock,
        ] {
            assert!(has(f, Backing::Work), "{f:?} must accept work");
            assert!(
                !has(f, Backing::SignatureSet),
                "{f:?} must not accept a signature set"
            );
            assert!(!has(f, Backing::Zk), "{f:?} must not accept a proof");
        }
        for f in [
            ExternalVerifierFamily::StarkValidityRollup,
            ExternalVerifierFamily::MinaSuccinctRecursive,
            ExternalVerifierFamily::BudZkVmExecution,
        ] {
            assert!(has(f, Backing::Zk), "{f:?} must accept a proof");
            assert!(!has(f, Backing::Work), "{f:?} must not accept work");
        }
        for f in [
            ExternalVerifierFamily::AuxPowPop,
            ExternalVerifierFamily::PoSpaceVdf,
        ] {
            assert!(
                has(f, Backing::Work) && has(f, Backing::SignatureSet),
                "{f:?} keeps both halves"
            );
            assert!(!has(f, Backing::Zk), "{f:?} is not a proof family");
        }
        let multi = ExternalVerifierFamily::HeterogeneousMultiProver;
        assert!(
            has(multi, Backing::Zk) && has(multi, Backing::SignatureSet),
            "the multi-prover aggregates both"
        );
        assert!(
            !has(multi, Backing::Work),
            "the multi-prover is not a work family"
        );
        for p in FAMILY_PROFILES {
            if p.backings == super::decision::Backings::SignatureSet {
                assert!(p.accepts_backing(Backing::SignatureSet), "{:?}", p.family);
                assert!(!p.accepts_backing(Backing::Work), "{:?}", p.family);
                assert!(!p.accepts_backing(Backing::Zk), "{:?}", p.family);
            }
        }
    }

    /// The lookup agrees with the table for every family.
    #[test]
    fn lookup_matches_the_table() {
        for d in 0u8..=31 {
            let f = unsafe_free_family(d);
            let row = family(f).expect("every family is listed");
            assert_eq!(row.family, f);
        }
    }

    /// Discriminant -> variant without `unsafe`, spelled out so the test refuses
    /// to compile when a variant is added.
    fn unsafe_free_family(d: u8) -> ExternalVerifierFamily {
        match d {
            0 => ExternalVerifierFamily::AlgorandStateProof,
            1 => ExternalVerifierFamily::AptosJolteonBft,
            2 => ExternalVerifierFamily::ArweaveSpOra,
            3 => ExternalVerifierFamily::AuxPowPop,
            4 => ExternalVerifierFamily::BabylonEots,
            5 => ExternalVerifierFamily::BasedPreconf,
            6 => ExternalVerifierFamily::BitcoinNakamotoPow,
            7 => ExternalVerifierFamily::BitVmCovenant,
            8 => ExternalVerifierFamily::CasperFfg,
            9 => ExternalVerifierFamily::ChainKeyNiDkg,
            10 => ExternalVerifierFamily::CelestiaDas,
            11 => ExternalVerifierFamily::BullsharkDagBft,
            12 => ExternalVerifierFamily::EthereumGasperSync,
            13 => ExternalVerifierFamily::GhostdagPow,
            14 => ExternalVerifierFamily::HeterogeneousMultiProver,
            15 => ExternalVerifierFamily::HoneyBadgerBft,
            16 => ExternalVerifierFamily::HotStuffChainedBft,
            17 => ExternalVerifierFamily::MinaSuccinctRecursive,
            18 => ExternalVerifierFamily::MysticetiDag,
            19 => ExternalVerifierFamily::NearDoomslugBft,
            20 => ExternalVerifierFamily::NipopowSuperblock,
            21 => ExternalVerifierFamily::OuroborosMithril,
            22 => ExternalVerifierFamily::PoSpaceVdf,
            23 => ExternalVerifierFamily::RestakingAvs,
            24 => ExternalVerifierFamily::SimplexBft,
            25 => ExternalVerifierFamily::SolanaTowerBft,
            26 => ExternalVerifierFamily::StarkValidityRollup,
            27 => ExternalVerifierFamily::StellarScp,
            28 => ExternalVerifierFamily::SymbioticVault,
            29 => ExternalVerifierFamily::TendermintBft,
            30 => ExternalVerifierFamily::TonCatchainBft,
            31 => ExternalVerifierFamily::BudZkVmExecution,
            other => panic!("discriminant {other} has no variant; the family set changed"),
        }
    }
}
