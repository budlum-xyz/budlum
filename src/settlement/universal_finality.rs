//! Universal heterogeneous cross-domain finality lattice and route composer.
//!
//! Budlum settles domains running fundamentally different consensus mechanisms:
//! single-slot BFT (`PoS`, `Bft`, `TendermintIbc`), permissioned authority quorums
//! (`PoA`), multi-parent causal waves (`Dag`), verifiable sequential delay +
//! Tower BFT (`Poh`), Merkle storage plots + VDF (`Pospace`), Nakamoto cumulative
//! proof-of-work (`PoW`, `BitcoinSpv`), hash-based STARK validity proofs (`Zk`,
//! `ZkVm`), sync committees (`EthereumSync`), modular 2D data-availability
//! sampling (`DataAvailability`), and staked storage/AI attestation committees.
//!
//! Rather than collapsing distinct trust assumptions into a heuristic float score,
//! [`FinalityGuarantee`] records the exact algebraic tuple
//! `(reversibility, quantum_posture, attestation, slashable_backing, fault_tolerance_bps)`
//! in pure integer arithmetic, and [`compose_cross_domain_route`] computes the
//! associative, commutative weakest-link meet across any 2-hop or N-hop route.
//!
//! WIRING: the global certificate layer ([`FINALITY_BINDS_ALL`],
//! [`DomainFinalityEntry`], [`FinalityVerdict`], [`FinalityComposeError`],
//! [`compose`], and [`compose_with_bar`]) is consumed by
//! `crate::cross_domain::external::attestation_binding` to bind external
//! `FinalityAttestation` records into settlement certificates.

use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::external::AdapterSpec;
use crate::crypto::facts::QuantumClass;
use crate::domain::types::{ConsensusDomain, ConsensusKind};
use crate::settlement::domains::CommitmentAttestation;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Basis-point ceiling representing `100.00%` (`10_000 bps`).
const BPS_SCALE: u16 = 10_000;
/// Optimal asynchronous/partially-synchronous BFT safety bound (`floor(10_000 / 3) - 1 = 3333 bps`).
const BFT_FAULT_TOLERANCE_BPS: u16 = 3_333;
/// Honest-majority Nakamoto `PoW` safety bound (`< 50%` hashpower = `4999 bps`).
const POW_FAULT_TOLERANCE_BPS: u16 = 4_999;
/// Cryptographic STARK soundness (`1-of-N` honest prover; bounded only by hash collision resistance).
const VALIDITY_PROOF_FAULT_TOLERANCE_BPS: u16 = 9_999;
/// Minimum confirmation depth required before probabilistic `PoW` finality is
/// eligible for cross-domain value routing without slashable stake.
const MIN_VALUE_SAFE_POW_CONFIRMATIONS: u64 = 6;

/// Reversibility class of an accepted finality verdict, ordered from weakest
/// (`ProbabilisticWork`) to strongest (`CryptographicValidity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityReversibility {
    /// Reversible under majority hashpower reorganization; bounded by confirmations.
    ProbabilisticWork { confirmations: u64 },
    /// Data availability backed by 2D erasure-code sampling + committee attestation.
    DataAvailabilitySampled { min_samples: u16 },
    /// Single-slot or epoch protocol quorum finality (reorg requires `>= 1/3` equivocation).
    DeterministicQuorum,
    /// Mathematical validity proof (STARK); irreversible under hash-function soundness.
    CryptographicValidity,
}

impl FinalityReversibility {
    const fn rank(self) -> u8 {
        match self {
            Self::ProbabilisticWork { .. } => 0,
            Self::DataAvailabilitySampled { .. } => 1,
            Self::DeterministicQuorum => 2,
            Self::CryptographicValidity => 3,
        }
    }

    #[must_use]
    fn meet(self, other: Self) -> Self {
        match (self, other) {
            (
                Self::ProbabilisticWork { confirmations: a },
                Self::ProbabilisticWork { confirmations: b },
            ) => Self::ProbabilisticWork {
                confirmations: a.min(b),
            },
            (
                Self::DataAvailabilitySampled { min_samples: a },
                Self::DataAvailabilitySampled { min_samples: b },
            ) => Self::DataAvailabilitySampled {
                min_samples: a.min(b),
            },
            (lhs, rhs) => {
                if lhs.rank() <= rhs.rank() {
                    lhs
                } else {
                    rhs
                }
            }
        }
    }
}

/// Rank [`QuantumClass`] from weakest (`Classical`) to strongest (`Hash`) for
/// weakest-link route composition without floats.
fn quantum_meet(a: QuantumClass, b: QuantumClass) -> QuantumClass {
    let rank = |q: QuantumClass| -> u8 {
        match q {
            QuantumClass::Classical => 0,
            QuantumClass::Lattice => 1,
            QuantumClass::Hash => 2,
        }
    };
    if rank(a) <= rank(b) {
        a
    } else {
        b
    }
}

/// Exact finality guarantee of a single registered consensus domain or external adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityGuarantee {
    pub reversibility: FinalityReversibility,
    pub quantum_posture: QuantumClass,
    pub attestation: CommitmentAttestation,
    pub slashable_backing: bool,
    /// Maximum tolerated adversarial fraction in basis points (`0..=10_000`).
    pub fault_tolerance_bps: u16,
}

impl FinalityGuarantee {
    /// Canonical guarantee of Budlum's hybrid BLS12-381 + ML-DSA-65 settlement hub.
    #[must_use]
    pub const fn settlement_hub() -> Self {
        Self {
            reversibility: FinalityReversibility::DeterministicQuorum,
            quantum_posture: QuantumClass::Lattice,
            attestation: CommitmentAttestation {
                state_root: true,
                tx_root: true,
                event_root: true,
                parent: true,
            },
            slashable_backing: true,
            fault_tolerance_bps: BFT_FAULT_TOLERANCE_BPS,
        }
    }

    /// Derive the baseline finality guarantee of a registered [`ConsensusDomain`].
    /// `pq_enforced` reflects whether the settlement chain requires post-quantum
    /// quorum co-signatures (true on mainnet or when a PQ proof variant settled).
    #[must_use]
    pub fn for_domain(domain: &ConsensusDomain, pq_enforced: bool) -> Self {
        Self::with_attestation(
            domain,
            CommitmentAttestation::for_domain(domain),
            pq_enforced,
            matches!(domain.kind, ConsensusKind::PoS | ConsensusKind::Bft)
                && domain.validator_set_hash != [0u8; 32],
        )
    }

    /// Derive the finality guarantee bound by a specific verified `proof` on `domain`.
    ///
    /// Authority-weighted proof shapes (`PoA`, `PoAPq`, `Dag`, `DagPq`, `Poh`,
    /// `PohPq`, `Pospace`, `PospacePq`) are authenticated by revocable authority
    /// sets rather than escrowed slashable stake, so `slashable_backing` is
    /// strictly `false`. Only bonded stake-weighted quorum
    /// proofs (`PoS`, `PoSPq`, `Bft`, `BftPq`) on a domain with a pinned
    /// non-zero `validator_set_hash` carry `slashable_backing = true`.
    ///
    /// WIRING: proof-aware settlement route surface paired with `CommitmentAttestation::for_proof`.
    #[must_use]
    pub fn for_proof(
        domain: &ConsensusDomain,
        proof: &crate::domain::FinalityProof,
        pq_enforced: bool,
    ) -> Self {
        if matches!(proof, crate::domain::FinalityProof::AggregatedProg { .. }) {
            let allowlisted = !domain.zk_program_allowlist.is_empty();
            return Self {
                reversibility: FinalityReversibility::CryptographicValidity,
                quantum_posture: QuantumClass::Hash,
                attestation: CommitmentAttestation {
                    state_root: allowlisted,
                    tx_root: allowlisted,
                    event_root: allowlisted,
                    parent: allowlisted,
                },
                slashable_backing: false,
                fault_tolerance_bps: if allowlisted {
                    VALIDITY_PROOF_FAULT_TOLERANCE_BPS
                } else {
                    0
                },
            };
        }
        let pq_proof = pq_enforced || !proof.is_classical_only_quorum();
        let proof_is_stake_slashable = domain.validator_set_hash != [0u8; 32]
            && matches!(
                proof,
                crate::domain::FinalityProof::PoS { .. }
                    | crate::domain::FinalityProof::PoSPq { .. }
                    | crate::domain::FinalityProof::Bft { .. }
                    | crate::domain::FinalityProof::BftPq { .. }
            )
            && matches!(
                domain.kind,
                ConsensusKind::PoS
                    | ConsensusKind::Bft
                    | ConsensusKind::Dag
                    | ConsensusKind::Poh
                    | ConsensusKind::Pospace
                    | ConsensusKind::StorageAttestation(_)
                    | ConsensusKind::AiInference
            );
        Self::with_attestation(
            domain,
            CommitmentAttestation::for_proof(domain, proof),
            pq_proof,
            proof_is_stake_slashable,
        )
    }

    #[must_use]
    fn with_attestation(
        domain: &ConsensusDomain,
        attestation: CommitmentAttestation,
        pq_enforced: bool,
        quorum_slashable: bool,
    ) -> Self {
        let quorum_q = if pq_enforced {
            QuantumClass::Lattice
        } else {
            QuantumClass::Classical
        };
        match &domain.kind {
            ConsensusKind::PoW => Self {
                reversibility: FinalityReversibility::ProbabilisticWork {
                    confirmations: domain.min_confirmations.max(1),
                },
                quantum_posture: QuantumClass::Hash,
                attestation,
                slashable_backing: false,
                fault_tolerance_bps: POW_FAULT_TOLERANCE_BPS,
            },
            ConsensusKind::Zk => Self {
                reversibility: FinalityReversibility::CryptographicValidity,
                quantum_posture: QuantumClass::Hash,
                attestation,
                slashable_backing: false,
                fault_tolerance_bps: VALIDITY_PROOF_FAULT_TOLERANCE_BPS,
            },
            ConsensusKind::PoA => Self {
                reversibility: FinalityReversibility::DeterministicQuorum,
                quantum_posture: quorum_q,
                attestation,
                // Permissioned authorities are revocable by admission root, not stake-slashed.
                slashable_backing: false,
                fault_tolerance_bps: BFT_FAULT_TOLERANCE_BPS,
            },
            ConsensusKind::PoS
            | ConsensusKind::Bft
            | ConsensusKind::Dag
            | ConsensusKind::Poh
            | ConsensusKind::Pospace
            | ConsensusKind::StorageAttestation(_)
            | ConsensusKind::AiInference => Self {
                reversibility: FinalityReversibility::DeterministicQuorum,
                quantum_posture: quorum_q,
                attestation,
                slashable_backing: quorum_slashable,
                fault_tolerance_bps: BFT_FAULT_TOLERANCE_BPS,
            },
            ConsensusKind::Custom(_) => Self {
                reversibility: FinalityReversibility::DeterministicQuorum,
                quantum_posture: QuantumClass::Classical,
                attestation,
                slashable_backing: false,
                fault_tolerance_bps: 0,
            },
        }
    }

    /// Derive the finality guarantee of a registered external intake [`AdapterSpec`].
    #[must_use]
    pub fn for_external_spec(spec: &AdapterSpec) -> Self {
        match spec {
            AdapterSpec::EthereumSync { committee, .. } => Self {
                reversibility: FinalityReversibility::DeterministicQuorum,
                quantum_posture: QuantumClass::Classical,
                attestation: CommitmentAttestation {
                    state_root: true,
                    tx_root: false,
                    event_root: false,
                    parent: false,
                },
                // Altair sync-committee signatures carry no protocol slashing.
                slashable_backing: false,
                fault_tolerance_bps: if committee.is_some() {
                    BFT_FAULT_TOLERANCE_BPS
                } else {
                    0
                },
            },
            AdapterSpec::ZkVm {
                program_hash,
                chain_id,
                ..
            } => Self {
                reversibility: FinalityReversibility::CryptographicValidity,
                quantum_posture: QuantumClass::Hash,
                attestation: CommitmentAttestation {
                    state_root: program_hash.is_some() && chain_id.is_some(),
                    tx_root: false,
                    event_root: false,
                    parent: false,
                },
                slashable_backing: false,
                fault_tolerance_bps: if program_hash.is_some() && chain_id.is_some() {
                    VALIDITY_PROOF_FAULT_TOLERANCE_BPS
                } else {
                    0
                },
            },
            AdapterSpec::BitcoinSpv { anchor, .. } => Self {
                reversibility: FinalityReversibility::ProbabilisticWork {
                    confirmations: if anchor.is_some() {
                        crate::cross_domain::external::bitcoin_spv::REQUIRED_DEPTH
                    } else {
                        0
                    },
                },
                quantum_posture: QuantumClass::Hash,
                attestation: CommitmentAttestation {
                    state_root: false,
                    tx_root: anchor.is_some(),
                    event_root: false,
                    parent: anchor.is_some(),
                },
                slashable_backing: false,
                fault_tolerance_bps: if anchor.is_some() {
                    POW_FAULT_TOLERANCE_BPS
                } else {
                    0
                },
            },
            AdapterSpec::TendermintCommit {
                chain_id,
                validator_set_hash,
                ..
            } => {
                let pinned = !chain_id.trim().is_empty()
                    && validator_set_hash.is_some_and(|h| h != [0u8; 32]);
                Self {
                    reversibility: FinalityReversibility::DeterministicQuorum,
                    quantum_posture: QuantumClass::Classical,
                    // A single CometBFT commit signs `block_id.hash`; under
                    // consensus pinning the anchored root is that block hash.
                    attestation: CommitmentAttestation {
                        state_root: pinned,
                        tx_root: false,
                        event_root: false,
                        parent: false,
                    },
                    slashable_backing: pinned,
                    fault_tolerance_bps: if pinned { BFT_FAULT_TOLERANCE_BPS } else { 0 },
                }
            }
            AdapterSpec::DataAvailability { committee, .. } => {
                let (valid, min_samples, pq_all) =
                    committee.as_ref().map_or((false, 0, false), |c| {
                        let (ok, pq) =
                            validate_pinned_committee_keys(c.members.iter().map(|m| {
                                (&m.ed25519_pubkey, m.voting_weight, m.pq_pubkey.as_slice())
                            }));
                        let valid = ok
                            && c.min_samples > 0
                            && c.min_square_size >= 2
                            && c.min_square_size.is_power_of_two();
                        (valid, if valid { c.min_samples } else { 0 }, valid && pq)
                    });
                Self {
                    reversibility: FinalityReversibility::DataAvailabilitySampled { min_samples },
                    quantum_posture: if pq_all {
                        QuantumClass::Lattice
                    } else {
                        QuantumClass::Classical
                    },
                    attestation: CommitmentAttestation {
                        state_root: valid,
                        tx_root: valid,
                        event_root: false,
                        parent: false,
                    },
                    slashable_backing: valid,
                    fault_tolerance_bps: if valid { BFT_FAULT_TOLERANCE_BPS } else { 0 },
                }
            }
            AdapterSpec::HotStuffQc { committee, .. } => {
                let (valid, pq_all) = committee.as_ref().map_or((false, false), |c| {
                    validate_pinned_committee_keys(
                        c.members
                            .iter()
                            .map(|m| (&m.ed25519_pubkey, m.voting_weight, m.pq_pubkey.as_slice())),
                    )
                });
                Self {
                    reversibility: FinalityReversibility::DeterministicQuorum,
                    quantum_posture: if pq_all {
                        QuantumClass::Lattice
                    } else {
                        QuantumClass::Classical
                    },
                    attestation: CommitmentAttestation {
                        state_root: valid,
                        tx_root: valid,
                        event_root: valid,
                        parent: valid,
                    },
                    slashable_backing: valid,
                    fault_tolerance_bps: if valid { BFT_FAULT_TOLERANCE_BPS } else { 0 },
                }
            }
            AdapterSpec::DagCertificate { committee, .. } => {
                let (valid, pq_all) = committee.as_ref().map_or((false, false), |c| {
                    validate_pinned_committee_keys(
                        c.members
                            .iter()
                            .map(|m| (&m.ed25519_pubkey, m.voting_weight, m.pq_pubkey.as_slice())),
                    )
                });
                Self {
                    reversibility: FinalityReversibility::DeterministicQuorum,
                    quantum_posture: if pq_all {
                        QuantumClass::Lattice
                    } else {
                        QuantumClass::Classical
                    },
                    attestation: CommitmentAttestation {
                        state_root: valid,
                        tx_root: valid,
                        event_root: valid,
                        parent: valid,
                    },
                    slashable_backing: valid,
                    fault_tolerance_bps: if valid { BFT_FAULT_TOLERANCE_BPS } else { 0 },
                }
            }
            AdapterSpec::CasperFfg { committee, .. } => {
                let (valid, pq_all) = committee.as_ref().map_or((false, false), |c| {
                    if c.epoch == 0 {
                        return (false, false);
                    }
                    validate_pinned_committee_keys(
                        c.validators
                            .iter()
                            .map(|m| (&m.pubkey, m.stake, m.pq_pubkey.as_slice())),
                    )
                });
                Self {
                    reversibility: FinalityReversibility::DeterministicQuorum,
                    quantum_posture: if pq_all {
                        QuantumClass::Lattice
                    } else {
                        QuantumClass::Classical
                    },
                    attestation: CommitmentAttestation {
                        state_root: valid,
                        tx_root: false,
                        event_root: false,
                        parent: valid,
                    },
                    slashable_backing: false,
                    fault_tolerance_bps: if valid { BFT_FAULT_TOLERANCE_BPS } else { 0 },
                }
            }
            AdapterSpec::MysticetiDag { committee, .. } => {
                let (valid, pq_all) = committee.as_ref().map_or((false, false), |c| {
                    if c.epoch == 0 {
                        return (false, false);
                    }
                    validate_pinned_committee_keys(
                        c.members
                            .iter()
                            .map(|m| (&m.ed25519_pubkey, m.voting_weight, m.pq_pubkey.as_slice())),
                    )
                });
                Self {
                    reversibility: FinalityReversibility::DeterministicQuorum,
                    quantum_posture: if pq_all {
                        QuantumClass::Lattice
                    } else {
                        QuantumClass::Classical
                    },
                    attestation: CommitmentAttestation {
                        state_root: valid,
                        tx_root: valid,
                        event_root: valid,
                        parent: valid,
                    },
                    slashable_backing: false,
                    fault_tolerance_bps: if valid { BFT_FAULT_TOLERANCE_BPS } else { 0 },
                }
            }
            AdapterSpec::BitVmCovenant { anchor, .. } => {
                let (valid, confs, pq_op) = anchor.as_ref().map_or((false, 0, false), |a| {
                    let ok = a.validate().is_ok();
                    let pq = ok && !a.operator_pq_pubkey.is_empty();
                    (ok, if ok { a.min_pow_confirmations } else { 0 }, pq)
                });
                Self {
                    reversibility: FinalityReversibility::ProbabilisticWork {
                        confirmations: confs,
                    },
                    quantum_posture: if pq_op {
                        QuantumClass::Lattice
                    } else {
                        QuantumClass::Classical
                    },
                    attestation: CommitmentAttestation {
                        state_root: valid,
                        tx_root: valid,
                        event_root: valid,
                        parent: valid,
                    },
                    slashable_backing: false,
                    fault_tolerance_bps: if valid { POW_FAULT_TOLERANCE_BPS } else { 0 },
                }
            }
        }
    }

    /// Associative, commutative weakest-link meet across two domain guarantees.
    ///
    /// Public because the global certificate composer ([`compose`]) folds the
    /// same operation across an arbitrary domain set: a caller that can compose
    /// a route must be able to compose the identical lattice by hand and get the
    /// identical guarantee.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            reversibility: self.reversibility.meet(other.reversibility),
            quantum_posture: quantum_meet(self.quantum_posture, other.quantum_posture),
            attestation: CommitmentAttestation {
                state_root: self.attestation.state_root && other.attestation.state_root,
                tx_root: self.attestation.tx_root && other.attestation.tx_root,
                event_root: self.attestation.event_root && other.attestation.event_root,
                parent: self.attestation.parent && other.attestation.parent,
            },
            slashable_backing: self.slashable_backing && other.slashable_backing,
            fault_tolerance_bps: self
                .fault_tolerance_bps
                .min(other.fault_tolerance_bps)
                .min(BPS_SCALE),
        }
    }

    /// Whether this source guarantee alone satisfies the protocol bar for
    /// cross-domain value transfer: authenticated events plus either slashable
    /// economic security, STARK validity, or deep cumulative `PoW` (`>= 6` blocks).
    #[must_use]
    pub const fn admits_cross_domain_value(&self) -> bool {
        if !self.attestation.event_root
            || self.fault_tolerance_bps == 0
            || self.fault_tolerance_bps > BPS_SCALE
        {
            return false;
        }
        if self.slashable_backing {
            return true;
        }
        match self.reversibility {
            FinalityReversibility::CryptographicValidity => true,
            FinalityReversibility::ProbabilisticWork { confirmations } => {
                confirmations >= MIN_VALUE_SAFE_POW_CONFIRMATIONS
            }
            FinalityReversibility::DeterministicQuorum
            | FinalityReversibility::DataAvailabilitySampled { .. } => false,
        }
    }
}

/// Validate a pinned external quorum committee: non-empty, bounded non-zero
/// `voting_weight` without `u128` overflow, unique non-zero `Ed25519` keys, and
/// canonical ML-DSA-65 public-key encoding before advertising `QuantumClass::Lattice`.
fn validate_pinned_committee_keys<'a>(
    members: impl Iterator<Item = (&'a [u8; 32], u64, &'a [u8])>,
) -> (bool, bool) {
    let mut seen = std::collections::BTreeSet::new();
    let mut total = 0u128;
    let mut pq_all = true;
    for (ed_pk, weight, pq_pk) in members {
        if *ed_pk == [0u8; 32] || weight == 0 || !seen.insert(*ed_pk) {
            return (false, false);
        }
        let Some(next) = total.checked_add(u128::from(weight)) else {
            return (false, false);
        };
        total = next;
        if pq_pk.is_empty()
            || crate::crypto::primitives::PqKeyPair::validate_public_key(pq_pk).is_err()
        {
            pq_all = false;
        }
    }
    if seen.is_empty() || total == 0 {
        return (false, false);
    }
    (true, pq_all)
}

/// End-to-end guarantee of a composed cross-domain settlement route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteFinalityBound {
    pub bottleneck_reversibility: FinalityReversibility,
    pub bottleneck_quantum_posture: QuantumClass,
    pub end_to_end_slashable: bool,
    pub bottleneck_fault_tolerance_bps: u16,
    pub source_admits_value_transfer: bool,
    pub source_admits_tx_inclusion: bool,
    pub hop_count: u16,
}

/// Compose the end-to-end finality bound of a cross-domain route `source -> target`
/// anchored through Budlum's hybrid PQ settlement hub.
#[must_use]
pub fn compose_cross_domain_route(
    source: &FinalityGuarantee,
    settlement_hub: &FinalityGuarantee,
    target: &FinalityGuarantee,
) -> RouteFinalityBound {
    let rev = source
        .reversibility
        .meet(settlement_hub.reversibility)
        .meet(target.reversibility);
    let quantum = quantum_meet(
        quantum_meet(source.quantum_posture, settlement_hub.quantum_posture),
        target.quantum_posture,
    );
    let fault_bps = source
        .fault_tolerance_bps
        .min(settlement_hub.fault_tolerance_bps)
        .min(target.fault_tolerance_bps)
        .min(BPS_SCALE);
    let slashable =
        source.slashable_backing && settlement_hub.slashable_backing && target.slashable_backing;
    RouteFinalityBound {
        bottleneck_reversibility: rev,
        bottleneck_quantum_posture: quantum,
        end_to_end_slashable: slashable,
        bottleneck_fault_tolerance_bps: fault_bps,
        source_admits_value_transfer: source.admits_cross_domain_value()
            && settlement_hub.fault_tolerance_bps > 0
            && target.fault_tolerance_bps > 0,
        source_admits_tx_inclusion: source.attestation.tx_root
            && source.fault_tolerance_bps > 0
            && target.fault_tolerance_bps > 0,
        hop_count: 2,
    }
}

/// Compose the weakest-link [`FinalityGuarantee`] across a domain bundle.
///
/// WIRING: `N`-domain atomic bundle finality composer complementing `compose_cross_domain_route`.
#[must_use]
pub fn compose_multi_domain_finality(domains: &[FinalityGuarantee]) -> Option<FinalityGuarantee> {
    let (first, rest) = domains.split_first()?;
    Some(rest.iter().fold(*first, |acc, next| acc.meet(next)))
}

/// Every commitment a domain finality proof must bind before its verdict may
/// enter a global certificate.
///
/// This is the "binds all" bar: a certificate whose `state_root` reads `true`
/// while `event_root` reads `false` describes a proof that authenticated the
/// account trie but not the logs, and no amount of quorum weight repairs it.
pub const FINALITY_BINDS_ALL: CommitmentAttestation = CommitmentAttestation {
    state_root: true,
    tx_root: true,
    event_root: true,
    parent: true,
};

/// Why a domain verdict is still `Pending` rather than `Established`.
///
/// Every variant is *re-submittable*: a missing-evidence verdict is not a
/// rejection, it is a debt with a named cause. Collapsing these into a single
/// `false` (or into `Refuted`) is the failure mode this type exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityPendingReason {
    /// The adapter produced no proof within the settlement window.
    EvidenceMissing,
    /// The proof arrived but does not bind the full commitment set.
    AttestationUnbound,
    /// The domain's finality rule is not yet satisfied (e.g. confirmations).
    RuleNotSatisfied,
    /// Slashable backing was claimed but could not be verified on chain.
    BondUnverified,
}

/// Three-valued verdict for a single domain, in the evidence algebra
/// `Established` / `Refuted` / `Pending`.
///
/// `Pending` carries a [`FinalityPendingReason`] and therefore cannot be
/// confused with `Refuted { .. }`: a certificate composer may never turn a
/// missing measurement into a rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityVerdict {
    /// The domain's finality proof verifies and binds every commitment.
    Established,
    /// The domain's own rule rejects the claimed block; `code` is the domain's
    /// exit reason and is preserved verbatim for the dispute record.
    Refuted {
        /// Domain-defined rejection code.
        code: u16,
    },
    /// Measurement is incomplete; the verdict must be re-submitted, not rejected.
    Pending {
        /// Named cause of the gap.
        reason: FinalityPendingReason,
    },
}

/// One domain's certified verdict, as fed into [`compose`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainFinalityEntry {
    /// Index of the consensus domain in the settlement registry (`0..16`).
    pub domain_id: u16,
    /// Finalized height the verdict refers to.
    pub height: u64,
    /// Domain state root the verdict commits to.
    pub state_root: [u8; 32],
    /// Exact finality guarantee the domain proof provides.
    pub guarantee: FinalityGuarantee,
    /// Three-valued verdict of the domain's own finality rule.
    pub verdict: FinalityVerdict,
}

/// Failure of [`compose`]. Ordered: structural contradictions first, then
/// findings, then evidence debt, so a caller always sees the strongest reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityComposeError {
    /// No domain entries were supplied; an empty certificate proves nothing.
    EmptyDomainSet,
    /// The same domain index appears twice with different heights or roots.
    DuplicateDomain {
        /// Offending domain index.
        domain_id: u16,
    },
    /// Two domains report the same index but contradictory verdicts.
    ConflictingVerdicts {
        /// First domain index.
        first: u16,
        /// Second domain index.
        second: u16,
    },
    /// A domain's own rule rejected its block.
    RefutedDomain {
        /// Offending domain tier.
        domain_id: u16,
        /// Domain-defined rejection code.
        code: u16,
    },
    /// A proof was measured but does not bind the full commitment set.
    AttestationUnbound {
        /// Offending domain index.
        domain_id: u16,
    },
    /// Measurement is incomplete; the certificate must be re-submitted.
    DomainNotEstablished {
        /// Domain index whose evidence is missing.
        domain_id: u16,
        /// Named cause.
        reason: FinalityPendingReason,
    },
    /// More than sixteen domains were supplied; the mask cannot represent them.
    TooManyDomains,
}

impl FinalityComposeError {
    /// Returns `true` iff the composition failed solely on incomplete evidence
    /// (`DomainNotEstablished`) rather than a structural contradiction, domain
    /// refutation, or unbound commitment bar.
    #[must_use]
    pub const fn is_resubmittable(&self) -> bool {
        matches!(self, Self::DomainNotEstablished { .. })
    }
}

/// Single global header committing to bounded, individually certified domain
/// finality verdicts.
///
/// The certificate is *derived*, never asserted: [`compose`] and
/// [`compose_with_bar`] are the constructors, and re-deriving it from the same
/// entries in canonical domain-ID order is the constant-time verification rule,
/// so a certificate cannot claim a weaker or stronger guarantee than its inputs
/// support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalFinalityCertificate {
    /// Bit `i` set iff domain `i` is `Established` and bound in this certificate.
    pub domain_mask: u16,
    /// Number of bound domains (`domain_mask.count_ones()`).
    pub domain_count: u8,
    /// Weakest-link guarantee across all bound domains.
    pub guarantee: FinalityGuarantee,
    /// Digest over every `(domain_id, height, state_root, guarantee, verdict)`
    /// tuple in canonical ascending `domain_id` order.
    pub domain_commitment: [u8; 32],
    /// Digest over the certificate header including [`Self::domain_commitment`]
    /// and the full algebraic [`FinalityGuarantee`] tuple.
    pub certificate_digest: [u8; 32],
}

#[must_use]
const fn quantum_posture_tag(q: QuantumClass) -> u8 {
    match q {
        QuantumClass::Classical => 1,
        QuantumClass::Lattice => 2,
        QuantumClass::Hash => 3,
    }
}

#[must_use]
const fn encode_reversibility(rev: FinalityReversibility) -> [u8; 9] {
    let rank = rev.rank();
    match rev {
        FinalityReversibility::ProbabilisticWork { confirmations } => {
            let [b0, b1, b2, b3, b4, b5, b6, b7] = confirmations.to_be_bytes();
            [rank, b0, b1, b2, b3, b4, b5, b6, b7]
        }
        FinalityReversibility::DataAvailabilitySampled { min_samples } => {
            let [s0, s1] = min_samples.to_be_bytes();
            [rank, s0, s1, 0, 0, 0, 0, 0, 0]
        }
        FinalityReversibility::DeterministicQuorum
        | FinalityReversibility::CryptographicValidity => [rank, 0, 0, 0, 0, 0, 0, 0, 0],
    }
}

#[must_use]
const fn encode_attestation(att: CommitmentAttestation) -> [u8; 4] {
    [
        att.state_root as u8,
        att.tx_root as u8,
        att.event_root as u8,
        att.parent as u8,
    ]
}

#[must_use]
const fn attestation_satisfies(
    actual: CommitmentAttestation,
    required: CommitmentAttestation,
) -> bool {
    (!required.state_root || actual.state_root)
        && (!required.tx_root || actual.tx_root)
        && (!required.event_root || actual.event_root)
        && (!required.parent || actual.parent)
}

/// Canonical domain-separated digest of one [`DomainFinalityEntry`], binding
/// every field of [`FinalityGuarantee`] (including `quantum_posture`,
/// `confirmations`, `min_samples`, and `slashable_backing`) via length-prefixed
/// [`hash_fields_bytes`].
#[must_use]
fn entry_digest(entry: &DomainFinalityEntry) -> [u8; 32] {
    let rev_bytes = encode_reversibility(entry.guarantee.reversibility);
    let att_bytes = encode_attestation(entry.guarantee.attestation);
    let (verdict_tag, verdict_detail): (u8, [u8; 2]) = match entry.verdict {
        FinalityVerdict::Established => (0, [0, 0]),
        FinalityVerdict::Refuted { code } => (1, code.to_be_bytes()),
        FinalityVerdict::Pending { reason } => {
            let r = match reason {
                FinalityPendingReason::EvidenceMissing => 1u16,
                FinalityPendingReason::AttestationUnbound => 2,
                FinalityPendingReason::RuleNotSatisfied => 3,
                FinalityPendingReason::BondUnverified => 4,
            };
            (2, r.to_be_bytes())
        }
    };
    hash_fields_bytes(&[
        b"BDLM_FINALITY_ENTRY_V1",
        &entry.domain_id.to_be_bytes(),
        &entry.height.to_be_bytes(),
        &entry.state_root,
        &rev_bytes,
        &[quantum_posture_tag(entry.guarantee.quantum_posture)],
        &att_bytes,
        &[u8::from(entry.guarantee.slashable_backing)],
        &entry.guarantee.fault_tolerance_bps.to_be_bytes(),
        &[verdict_tag],
        &verdict_detail,
    ])
}

/// Compose a [`GlobalFinalityCertificate`] requiring [`FINALITY_BINDS_ALL`].
///
/// Order of refusal is fixed and deterministic across permutations:
/// empty set, domain mask bounds / conflicting or duplicate domain, refuted
/// domain, unbound attestation, pending evidence, and only then the canonical
/// ascending `domain_id` weakest-link fold.
///
/// # Errors
///
/// Returns the strongest applicable [`FinalityComposeError`]; see its variants.
pub fn compose(
    entries: &[DomainFinalityEntry],
) -> Result<GlobalFinalityCertificate, FinalityComposeError> {
    compose_with_bar(entries, FINALITY_BINDS_ALL)
}

/// Compose a [`GlobalFinalityCertificate`] against an explicit non-empty
/// [`CommitmentAttestation`] bar (used for external finality proofs that bind
/// `state_root` or header ancestry without full Hub four-root coverage).
///
/// # Errors
///
/// Returns [`FinalityComposeError`] if the set is empty, exceeds 16 domains,
/// contains conflicting or duplicate domain indices, has a refuted or pending
/// domain, or fails to satisfy `required` (including an all-false `required`).
pub fn compose_with_bar(
    entries: &[DomainFinalityEntry],
    required: CommitmentAttestation,
) -> Result<GlobalFinalityCertificate, FinalityComposeError> {
    if entries.is_empty() {
        return Err(FinalityComposeError::EmptyDomainSet);
    }
    for entry in entries {
        if entry.domain_id >= 16 {
            return Err(FinalityComposeError::TooManyDomains);
        }
    }
    if entries.len() > 16 {
        // Check duplicate/conflicting domain indices before reporting overflow
        // only when <=16; >16 entries cannot fit a 16-bit mask without collision.
        return Err(FinalityComposeError::TooManyDomains);
    }

    let mut seen_entries: [Option<&DomainFinalityEntry>; 16] = [None; 16];
    let mut seen_mask: u16 = 0;
    for entry in entries {
        let slot_idx = usize::from(entry.domain_id);
        if let Some(prev) = seen_entries.get(slot_idx).and_then(|s| *s) {
            if prev.verdict != entry.verdict {
                return Err(FinalityComposeError::ConflictingVerdicts {
                    first: prev.domain_id,
                    second: entry.domain_id,
                });
            }
            return Err(FinalityComposeError::DuplicateDomain {
                domain_id: entry.domain_id,
            });
        }
        if let Some(slot) = seen_entries.get_mut(slot_idx) {
            *slot = Some(entry);
        }
        seen_mask |= 1u16 << entry.domain_id;
    }

    // Canonical ascending domain_id order guarantees permutation invariance of
    // error precedence, meet fold, domain_commitment, and certificate_digest.
    let mut canonical: Vec<DomainFinalityEntry> = entries.to_vec();
    canonical.sort_by_key(|e| e.domain_id);

    for entry in &canonical {
        if let FinalityVerdict::Refuted { code } = entry.verdict {
            return Err(FinalityComposeError::RefutedDomain {
                domain_id: entry.domain_id,
                code,
            });
        }
    }

    for entry in &canonical {
        let any_bound =
            required.state_root || required.tx_root || required.event_root || required.parent;
        if !any_bound || !attestation_satisfies(entry.guarantee.attestation, required) {
            return Err(FinalityComposeError::AttestationUnbound {
                domain_id: entry.domain_id,
            });
        }
    }

    for entry in &canonical {
        if let FinalityVerdict::Pending { reason } = entry.verdict {
            return Err(FinalityComposeError::DomainNotEstablished {
                domain_id: entry.domain_id,
                reason,
            });
        }
    }

    let Some((first, rest)) = canonical.split_first() else {
        return Err(FinalityComposeError::EmptyDomainSet);
    };
    let guarantee = rest
        .iter()
        .fold(first.guarantee, |acc, entry| acc.meet(&entry.guarantee));

    let entry_digests: Vec<[u8; 32]> = canonical.iter().map(entry_digest).collect();
    let count_be = (canonical.len() as u64).to_be_bytes();
    let mut commit_fields: Vec<&[u8]> = Vec::with_capacity(2 + entry_digests.len());
    commit_fields.push(b"BDLM_FINALITY_COMMIT_V1");
    commit_fields.push(&count_be);
    for d in &entry_digests {
        commit_fields.push(d);
    }
    let domain_commitment = hash_fields_bytes(&commit_fields);

    let domain_count_u8 = u8::try_from(seen_mask.count_ones()).unwrap_or(u8::MAX);
    let mask_be = seen_mask.to_be_bytes();
    let count_arr = [domain_count_u8];
    let rev_bytes = encode_reversibility(guarantee.reversibility);
    let q_arr = [quantum_posture_tag(guarantee.quantum_posture)];
    let att_bytes = encode_attestation(guarantee.attestation);
    let req_bytes = encode_attestation(required);
    let slash_arr = [u8::from(guarantee.slashable_backing)];
    let bps_be = guarantee.fault_tolerance_bps.to_be_bytes();

    let certificate_digest = hash_fields_bytes(&[
        b"BDLM_FINALITY_CERT_V1",
        &mask_be,
        &count_arr,
        &rev_bytes,
        &q_arr,
        &att_bytes,
        &req_bytes,
        &slash_arr,
        &bps_be,
        &domain_commitment,
    ]);

    Ok(GlobalFinalityCertificate {
        domain_mask: seen_mask,
        domain_count: domain_count_u8,
        guarantee,
        domain_commitment,
        certificate_digest,
    })
}

impl GlobalFinalityCertificate {
    /// Constant-time re-derivation check against `entries` under `required`.
    ///
    /// WIRING: Called by `crate::cross_domain::external::attestation_binding`
    /// when verifying external attestation binding proofs.
    #[must_use]
    pub fn verify_against_with_bar(
        &self,
        entries: &[DomainFinalityEntry],
        required: CommitmentAttestation,
    ) -> bool {
        let Ok(recomputed) = compose_with_bar(entries, required) else {
            return false;
        };
        let commitments_match =
            bool::from(self.domain_commitment.ct_eq(&recomputed.domain_commitment));
        let digests_match = bool::from(
            self.certificate_digest
                .ct_eq(&recomputed.certificate_digest),
        );
        commitments_match
            && digests_match
            && self.domain_mask == recomputed.domain_mask
            && self.domain_count == recomputed.domain_count
            && self.guarantee == recomputed.guarantee
    }
}

/// Overflow-free `floor(amount * bps / 10_000)` on `u128`.
#[must_use]
const fn mul_bps_floor_u128(amount: u128, bps: u16) -> u128 {
    let scale = BPS_SCALE as u128;
    let factor = (if bps > BPS_SCALE { BPS_SCALE } else { bps }) as u128;
    let q = amount / scale;
    let r = amount % scale;
    q.saturating_mul(factor)
        .saturating_add((r * factor) / scale)
}

/// Pure-integer economic security and value-outflow conservation envelope for
/// a heterogeneous consensus domain (`attacker profit <= slashable corruption cost`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicSecurityBound {
    /// Escrowed slashable collateral backing the domain (in atoms).
    pub slashable_bond_atoms: u128,
    /// Declared per-epoch routing ceiling (in atoms).
    pub routing_ceiling_atoms: u128,
    /// Minimum slashable loss incurred by a finality-breaking coalition:
    /// `floor(slashable_bond_atoms * fault_tolerance_bps / 10_000)` when
    /// `slashable_backing` holds, else `0`.
    pub corruption_cost_atoms: u128,
    /// Maximum safe cumulative cross-domain value outflow for the current epoch.
    pub safe_value_outflow_ceiling_atoms: u128,
}

impl EconomicSecurityBound {
    /// Derive the exact economic security envelope for `guarantee` given the
    /// domain's live escrowed bond and declared routing ceiling.
    #[must_use]
    pub const fn derive(
        guarantee: &FinalityGuarantee,
        slashable_bond_atoms: u128,
        routing_ceiling_atoms: u128,
    ) -> Self {
        let corruption_cost_atoms = if guarantee.slashable_backing {
            mul_bps_floor_u128(slashable_bond_atoms, guarantee.fault_tolerance_bps)
        } else {
            0
        };
        let safe_value_outflow_ceiling_atoms = if !guarantee.admits_cross_domain_value() {
            0
        } else if guarantee.slashable_backing {
            if corruption_cost_atoms < routing_ceiling_atoms {
                corruption_cost_atoms
            } else {
                routing_ceiling_atoms
            }
        } else {
            // CryptographicValidity (1-of-N STARK) or deep PoW (>= 6 confs):
            // gated directly by the domain's declared routing ceiling.
            routing_ceiling_atoms
        };
        Self {
            slashable_bond_atoms,
            routing_ceiling_atoms,
            corruption_cost_atoms,
            safe_value_outflow_ceiling_atoms,
        }
    }

    /// Derive the weakest-link economic security bound across a multi-domain
    /// atomic settlement bundle `(guarantee, slashable_bond_atoms, routing_ceiling_atoms)`.
    /// WIRING: `N`-domain economic outflow conservation surface paired with `compose_multi_domain_finality`.
    #[must_use]
    pub fn derive_multi_domain(legs: &[(FinalityGuarantee, u128, u128)]) -> Option<Self> {
        let (first, rest) = legs.split_first()?;
        let mut combined = Self::derive(&first.0, first.1, first.2);
        for (g, bond, ceiling) in rest {
            let b = Self::derive(g, *bond, *ceiling);
            combined = Self {
                slashable_bond_atoms: combined.slashable_bond_atoms.min(b.slashable_bond_atoms),
                routing_ceiling_atoms: combined.routing_ceiling_atoms.min(b.routing_ceiling_atoms),
                corruption_cost_atoms: combined.corruption_cost_atoms.min(b.corruption_cost_atoms),
                safe_value_outflow_ceiling_atoms: combined
                    .safe_value_outflow_ceiling_atoms
                    .min(b.safe_value_outflow_ceiling_atoms),
            };
        }
        Some(combined)
    }

    /// Enforce value-outflow conservation: rejects zero-admitted domains,
    /// integer overflow, and any transfer that would push cumulative pending
    /// outflow past `safe_value_outflow_ceiling_atoms`.
    ///
    /// # Errors
    ///
    /// Returns a human-readable refusal naming the violated conservation bound.
    pub fn check_value_outflow_conservation(
        &self,
        pending_outflow_atoms: u128,
        requested_outflow_atoms: u128,
    ) -> Result<u128, String> {
        if requested_outflow_atoms == 0 {
            return Err("cross-domain value outflow must be non-zero".to_string());
        }
        if self.safe_value_outflow_ceiling_atoms == 0 {
            return Err(
                "source domain finality does not admit cross-domain value outflow".to_string(),
            );
        }
        let next_pending = pending_outflow_atoms
            .checked_add(requested_outflow_atoms)
            .ok_or_else(|| "cross-domain value outflow accumulator overflow".to_string())?;
        if next_pending > self.safe_value_outflow_ceiling_atoms {
            return Err(format!(
                "cross-domain outflow {next_pending} exceeds safe economic ceiling {}",
                self.safe_value_outflow_ceiling_atoms
            ));
        }
        Ok(next_pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::da_sampling::{DaCommitteeMember, PinnedDaCommittee};
    use crate::domain::plugin::default_domain;

    fn hub_guarantee() -> FinalityGuarantee {
        FinalityGuarantee {
            reversibility: FinalityReversibility::DeterministicQuorum,
            quantum_posture: QuantumClass::Lattice,
            attestation: CommitmentAttestation {
                state_root: true,
                tx_root: true,
                event_root: true,
                parent: true,
            },
            slashable_backing: true,
            fault_tolerance_bps: BFT_FAULT_TOLERANCE_BPS,
        }
    }

    #[test]
    fn universal_finality_classifies_all_consensus_families_and_enforces_weakest_link() {
        let hub = hub_guarantee();

        // 1. Regression: authority-weighted structural proofs
        //    (`DagPq`, `PohPq`, `PospacePq`, `PoAPq`) carry NO escrowed
        //    slashable stake, so `slashable_backing` and
        //    `admits_cross_domain_value()` MUST be strictly `false` even when
        //    `validator_set_hash` is populated.
        let mut dag = default_domain(1, ConsensusKind::Dag, 1001, "dag-tip-vote-v1", 1);
        dag.validator_set_hash = [0xAA; 32];
        assert!(!FinalityGuarantee::for_domain(&dag, true).slashable_backing);
        assert!(!FinalityGuarantee::for_domain(&dag, true).admits_cross_domain_value());
        let dag_pq = crate::domain::FinalityProof::DagPq {
            round: 1,
            anchor: [0x11; 32],
            parent_anchor: [0u8; 32],
            authorities: Vec::new(),
            signatures: Vec::new(),
        };
        let g_dag_auth = FinalityGuarantee::for_proof(&dag, &dag_pq, false);
        assert!(!g_dag_auth.slashable_backing);
        assert!(!g_dag_auth.admits_cross_domain_value());
        assert_eq!(g_dag_auth.quantum_posture, QuantumClass::Lattice);

        // 2. PoH, PoSpace, StorageAttestation, and AiInference authority proofs
        //    are likewise strictly non-slashable; stake-weighted `BftPq` proofs
        //    retain `slashable_backing = true`.
        let mut poh = default_domain(2, ConsensusKind::Poh, 1002, "poh-hash-chain-v1", 1);
        poh.validator_set_hash = [0xBB; 32];
        let mut pospace = default_domain(3, ConsensusKind::Pospace, 1003, "pospace-plot-v1", 1);
        pospace.validator_set_hash = [0xCC; 32];
        let poh_auth = crate::domain::FinalityProof::PohPq {
            chain: Vec::new(),
            authorities: Vec::new(),
            signatures: Vec::new(),
        };
        let pospace_auth = crate::domain::FinalityProof::PospacePq {
            prover: crate::core::address::Address::from([0x01; 32]),
            plot_id: [0x02; 32],
            quality_bits: 8,
            prover_signature: Vec::new(),
            authorities: Vec::new(),
            signatures: Vec::new(),
        };
        assert!(!FinalityGuarantee::for_proof(&poh, &poh_auth, false).slashable_backing);
        assert!(!FinalityGuarantee::for_proof(&poh, &poh_auth, false).admits_cross_domain_value());
        assert!(!FinalityGuarantee::for_proof(&pospace, &pospace_auth, false).slashable_backing);
        assert!(
            !FinalityGuarantee::for_proof(&pospace, &pospace_auth, false)
                .admits_cross_domain_value()
        );
        // Bonded PoS/BFT domains retain `slashable_backing = true` on `for_domain`
        // and on stake-weighted `PoSPq` / `BftPq` proofs.
        let mut bft_dom = default_domain(99, ConsensusKind::Bft, 1099, "bft-qc-v1", 1);
        bft_dom.validator_set_hash = [0xDD; 32];
        assert!(FinalityGuarantee::for_domain(&bft_dom, true).slashable_backing);
        let pos_proof = crate::domain::FinalityProof::PoS {
            cert: crate::chain::finality::FinalityCert {
                epoch: 1,
                checkpoint_height: 1,
                checkpoint_hash: String::new(),
                chain_id: 1002,
                agg_sig_bls: Vec::new(),
                bitmap: Vec::new(),
                set_hash: String::new(),
                seat_table_version: 0,
            },
            validator_snapshot: crate::chain::finality::ValidatorSetSnapshot {
                epoch: 1,
                validators: Vec::new(),
                set_hash: String::new(),
                total_stake: 0,
            },
        };
        assert!(FinalityGuarantee::for_proof(&poh, &pos_proof, true).slashable_backing);

        // 3. Bonded stake-weighted PQ Bullshark DAG-BFT (`AdapterSpec::DagCertificate`)
        //    and HotStuff 3-chain (`AdapterSpec::HotStuffQc`) genuinely attest all 4 roots
        //    under slashable quorum -> admit value transfer and enforce economic ceiling.
        let g_dag = FinalityGuarantee::for_external_spec(&AdapterSpec::DagCertificate {
            network: "sui-mysticeti".into(),
            committee: Some(crate::cross_domain::external::PinnedDagCommittee {
                epoch: 1,
                members: vec![crate::cross_domain::external::DagBftValidator {
                    ed25519_pubkey: [0x21; 32],
                    voting_weight: 100,
                    pq_pubkey: vec![0x22; 1_952],
                }],
            }),
        });
        assert!(g_dag.slashable_backing);
        assert!(g_dag.admits_cross_domain_value());
        assert_eq!(g_dag.quantum_posture, QuantumClass::Lattice);

        let g_hs = FinalityGuarantee::for_external_spec(&AdapterSpec::HotStuffQc {
            network: "aptos-jolteon".into(),
            committee: Some(crate::cross_domain::external::PinnedHotStuffCommittee {
                epoch: 1,
                members: vec![crate::cross_domain::external::HotStuffValidator {
                    ed25519_pubkey: [0x31; 32],
                    voting_weight: 100,
                    pq_pubkey: vec![0x32; 1_952],
                }],
            }),
        });
        assert!(g_hs.slashable_backing);
        assert!(g_hs.admits_cross_domain_value());
        assert_eq!(g_hs.quantum_posture, QuantumClass::Lattice);

        // Economic conservation: 10_000 bonded atoms at 3333 bps -> safe outflow ceiling = 3333.
        let econ = EconomicSecurityBound::derive(&g_hs, 10_000, 50_000);
        assert_eq!(econ.corruption_cost_atoms, 3_333);
        assert_eq!(econ.safe_value_outflow_ceiling_atoms, 3_333);
        assert_eq!(
            econ.check_value_outflow_conservation(2_000, 1_333),
            Ok(3_333)
        );
        assert!(econ.check_value_outflow_conservation(2_000, 1_334).is_err());
        assert!(econ.check_value_outflow_conservation(u128::MAX, 1).is_err());
        let unslashable_econ = EconomicSecurityBound::derive(&g_dag_auth, 10_000, 50_000);
        assert_eq!(unslashable_econ.safe_value_outflow_ceiling_atoms, 0);
        assert!(unslashable_econ
            .check_value_outflow_conservation(0, 1)
            .is_err());

        // Route staked DAG-BFT (PQ, 3333 bps) -> Hub -> Bitcoin SPV (Hash, 6 confs, 4999 bps):
        // bottleneck reversibility is ProbabilisticWork(6), fault tolerance 3333 bps,
        // DAG->BTC admits value transfer while BTC->DAG admits tx_inclusion only (no event_root).
        let btc = default_domain(
            4,
            ConsensusKind::PoW,
            1004,
            crate::domain::types::BITCOIN_SPV_ADAPTER,
            6,
        );
        let g_btc = FinalityGuarantee::for_domain(&btc, true);
        assert_eq!(g_btc.quantum_posture, QuantumClass::Hash);
        assert!(!g_btc.admits_cross_domain_value());
        assert!(g_btc.attestation.tx_root);

        let dag_to_btc = compose_cross_domain_route(&g_dag, &hub, &g_btc);
        assert_eq!(
            dag_to_btc.bottleneck_reversibility,
            FinalityReversibility::ProbabilisticWork { confirmations: 6 }
        );
        assert_eq!(dag_to_btc.bottleneck_quantum_posture, QuantumClass::Lattice);
        assert_eq!(
            dag_to_btc.bottleneck_fault_tolerance_bps,
            BFT_FAULT_TOLERANCE_BPS
        );
        assert!(!dag_to_btc.end_to_end_slashable);
        assert!(dag_to_btc.source_admits_value_transfer);

        let btc_to_dag = compose_cross_domain_route(&g_btc, &hub, &g_dag);
        assert!(!btc_to_dag.source_admits_value_transfer);
        assert!(btc_to_dag.source_admits_tx_inclusion);

        // 4. Generic PoW header chain with 6 confirmations DOES attest event_root -> admits value;
        //    shallow 2-confirmation PoW is refused for value routing.
        let pow_deep = default_domain(
            5,
            ConsensusKind::PoW,
            1005,
            crate::domain::types::POW_HEADER_CHAIN_ADAPTER,
            6,
        );
        let pow_shallow = default_domain(
            6,
            ConsensusKind::PoW,
            1006,
            crate::domain::types::POW_HEADER_CHAIN_ADAPTER,
            2,
        );
        assert!(FinalityGuarantee::for_domain(&pow_deep, true).admits_cross_domain_value());
        assert!(!FinalityGuarantee::for_domain(&pow_shallow, true).admits_cross_domain_value());

        // 5. External adapters: TendermintCommit (pinned validator set, slashable,
        //    block_hash-bound), EthereumSync (unslashable, classical), ZkVm
        //    (Hash-sound validity), DataAvailability (DAS-sampled, tx_root),
        //    and BitcoinSpv (Hash-sound PoW, tx_root).
        let g_tm = FinalityGuarantee::for_external_spec(&AdapterSpec::TendermintCommit {
            network: "noble".into(),
            chain_id: "noble-1".into(),
            validator_set_hash: Some([0xAB; 32]),
        });
        assert!(g_tm.slashable_backing);
        assert!(g_tm.attestation.state_root);
        assert!(!g_tm.admits_cross_domain_value());
        assert_eq!(g_tm.quantum_posture, QuantumClass::Classical);
        let g_tm_unpinned = FinalityGuarantee::for_external_spec(&AdapterSpec::TendermintCommit {
            network: "noble".into(),
            chain_id: "noble-1".into(),
            validator_set_hash: None,
        });
        assert_eq!(g_tm_unpinned.fault_tolerance_bps, 0);

        let g_eth = FinalityGuarantee::for_external_spec(&AdapterSpec::EthereumSync {
            network: "eth".into(),
            committee: None,
        });
        assert!(!g_eth.admits_cross_domain_value());
        assert_eq!(g_eth.quantum_posture, QuantumClass::Classical);

        let g_zk = FinalityGuarantee::for_external_spec(&AdapterSpec::ZkVm {
            network: "zk".into(),
            program_hash: Some([9; 32]),
            chain_id: Some(77),
        });
        assert_eq!(g_zk.quantum_posture, QuantumClass::Hash);
        assert_eq!(
            g_zk.reversibility,
            FinalityReversibility::CryptographicValidity
        );

        let g_da = FinalityGuarantee::for_external_spec(&AdapterSpec::DataAvailability {
            network: "celestia".into(),
            committee: Some(PinnedDaCommittee {
                namespace_id: [3; 32],
                min_samples: 16,
                min_square_size: 4,
                members: vec![DaCommitteeMember {
                    ed25519_pubkey: [4; 32],
                    voting_weight: 100,
                    pq_pubkey: vec![5; 1_952],
                }],
            }),
        });
        assert_eq!(g_da.quantum_posture, QuantumClass::Lattice);
        let da_to_zk = compose_cross_domain_route(&g_da, &hub, &g_zk);
        assert_eq!(
            da_to_zk.bottleneck_reversibility,
            FinalityReversibility::DataAvailabilitySampled { min_samples: 16 }
        );
        assert!(da_to_zk.source_admits_tx_inclusion);

        let g_btc_ext = FinalityGuarantee::for_external_spec(&AdapterSpec::BitcoinSpv {
            network: "mainnet".into(),
            anchor: Some(
                crate::cross_domain::external::bitcoin_spv::PinnedBitcoinAnchor {
                    height: 840_000,
                    block_hash: [0x11; 32],
                    bits: 0x1703_4219,
                },
            ),
        });
        assert_eq!(g_btc_ext.quantum_posture, QuantumClass::Hash);
        assert!(g_btc_ext.attestation.tx_root);
        assert!(!g_btc_ext.admits_cross_domain_value());
        let g_btc_unpinned = FinalityGuarantee::for_external_spec(&AdapterSpec::BitcoinSpv {
            network: "mainnet".into(),
            anchor: None,
        });
        assert_eq!(g_btc_unpinned.fault_tolerance_bps, 0);
        assert!(!da_to_zk.source_admits_value_transfer);
    }

    #[test]
    fn reversibility_meet_is_commutative_associative_and_idempotent() {
        let items = [
            FinalityReversibility::ProbabilisticWork { confirmations: 2 },
            FinalityReversibility::ProbabilisticWork { confirmations: 6 },
            FinalityReversibility::DataAvailabilitySampled { min_samples: 8 },
            FinalityReversibility::DataAvailabilitySampled { min_samples: 32 },
            FinalityReversibility::DeterministicQuorum,
            FinalityReversibility::CryptographicValidity,
        ];
        for &a in &items {
            assert_eq!(a.meet(a), a);
            for &b in &items {
                assert_eq!(a.meet(b), b.meet(a));
                for &c in &items {
                    assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)));
                }
            }
        }
    }

    #[test]
    fn external_spec_refuses_empty_duplicate_zero_sample_and_short_pq_committees() {
        let empty_da = FinalityGuarantee::for_external_spec(&AdapterSpec::DataAvailability {
            network: "celestia-empty".into(),
            committee: Some(PinnedDaCommittee {
                namespace_id: [0x10; 32],
                min_samples: 0,
                min_square_size: 2,
                members: Vec::new(),
            }),
        });
        assert_eq!(empty_da.fault_tolerance_bps, 0);
        assert!(!empty_da.slashable_backing);
        assert!(!empty_da.attestation.state_root);
        assert!(!empty_da.attestation.tx_root);

        // Short 32-byte non-ML-DSA-65 pq_pubkey must never claim QuantumClass::Lattice.
        let short_pq_dag = FinalityGuarantee::for_external_spec(&AdapterSpec::DagCertificate {
            network: "dag-short-pq".into(),
            committee: Some(crate::cross_domain::external::PinnedDagCommittee {
                epoch: 1,
                members: vec![crate::cross_domain::external::DagBftValidator {
                    ed25519_pubkey: [0x41; 32],
                    voting_weight: 100,
                    pq_pubkey: vec![0x99; 32],
                }],
            }),
        });
        assert_eq!(short_pq_dag.quantum_posture, QuantumClass::Classical);

        // Duplicate validator ed25519 pubkeys invalidate pinned BFT committee guarantees.
        let dup_member = crate::cross_domain::external::DagBftValidator {
            ed25519_pubkey: [0x55; 32],
            voting_weight: 100,
            pq_pubkey: vec![0x77; 1_952],
        };
        let dup_dag = FinalityGuarantee::for_external_spec(&AdapterSpec::DagCertificate {
            network: "dag-dup".into(),
            committee: Some(crate::cross_domain::external::PinnedDagCommittee {
                epoch: 1,
                members: vec![dup_member.clone(), dup_member],
            }),
        });
        assert_eq!(dup_dag.fault_tolerance_bps, 0);
        assert!(!dup_dag.slashable_backing);
    }

    #[test]
    fn casper_mysticeti_bitvm_and_multi_domain_composition_enforce_weakest_link() {
        use crate::cross_domain::external::{
            FfgValidator, MysticetiMember, PinnedBitVmAnchor, PinnedFfgCommittee,
            PinnedMysticetiCommittee,
        };
        use crate::crypto::primitives::PqKeyPair;

        let pq = PqKeyPair::generate();
        let pq_bytes = pq.public_key_bytes().to_vec();

        let g_ffg = FinalityGuarantee::for_external_spec(&AdapterSpec::CasperFfg {
            network: "eth-ffg".into(),
            committee: Some(
                PinnedFfgCommittee::new(
                    4,
                    vec![FfgValidator {
                        pubkey: [0x11; 32],
                        stake: 1_000,
                        pq_pubkey: pq_bytes.clone(),
                    }],
                )
                .expect("ffg"),
            ),
        });
        assert_eq!(g_ffg.quantum_posture, QuantumClass::Lattice);
        assert!(!g_ffg.slashable_backing);
        assert_eq!(g_ffg.fault_tolerance_bps, BFT_FAULT_TOLERANCE_BPS);

        let g_my = FinalityGuarantee::for_external_spec(&AdapterSpec::MysticetiDag {
            network: "sui-my".into(),
            committee: Some(
                PinnedMysticetiCommittee::new(
                    2,
                    vec![MysticetiMember {
                        ed25519_pubkey: [0x22; 32],
                        voting_weight: 500,
                        pq_pubkey: pq_bytes.clone(),
                    }],
                )
                .expect("my"),
            ),
        });
        assert!(g_my.attestation.event_root);
        assert!(!g_my.slashable_backing);

        let g_bv = FinalityGuarantee::for_external_spec(&AdapterSpec::BitVmCovenant {
            network: "btc-bv".into(),
            anchor: Some(PinnedBitVmAnchor {
                height: 10,
                block_hash: [0x33; 32],
                bits: 0x207f_ffff,
                program_hash: [0x44; 32],
                min_pow_confirmations: 6,
                challenge_blocks: 3,
                operator_ed25519_pubkey: [0x55; 32],
                operator_pq_pubkey: pq_bytes,
            }),
        });
        assert!(g_bv.admits_cross_domain_value());
        assert_eq!(g_bv.fault_tolerance_bps, POW_FAULT_TOLERANCE_BPS);

        let hub = FinalityGuarantee::settlement_hub();
        assert_eq!(g_bv.meet(&hub), hub.meet(&g_bv));
        assert_eq!(compose_multi_domain_finality(&[]), None);
        let composed =
            compose_multi_domain_finality(&[hub, g_bv, g_my]).expect("non-empty composition");
        assert_eq!(
            composed.reversibility,
            FinalityReversibility::ProbabilisticWork { confirmations: 6 }
        );
        assert_eq!(composed.fault_tolerance_bps, BFT_FAULT_TOLERANCE_BPS);
        assert!(!composed.slashable_backing);

        let econ =
            EconomicSecurityBound::derive_multi_domain(&[(hub, 90_000, 50_000), (g_bv, 0, 20_000)])
                .expect("econ");
        assert_eq!(econ.safe_value_outflow_ceiling_atoms, 20_000);
    }

    // --- Global certificate composer (TIP-03 production slice) --------------
    //
    // These are the same cases proven in the offline scratch crate before the
    // port; each one pins a rule a naive composer gets wrong.

    fn cert_entry(
        id: u16,
        bps: u16,
        reversibility: FinalityReversibility,
        verdict: FinalityVerdict,
    ) -> DomainFinalityEntry {
        DomainFinalityEntry {
            domain_id: id,
            height: 100 + u64::from(id),
            state_root: [u8::try_from(id).unwrap_or(0); 32],
            guarantee: FinalityGuarantee {
                reversibility,
                quantum_posture: QuantumClass::Hash,
                attestation: FINALITY_BINDS_ALL,
                slashable_backing: true,
                fault_tolerance_bps: bps,
            },
            verdict,
        }
    }

    #[test]
    fn certificate_covers_all_domain_families() {
        let entries: Vec<_> = (0u16..9)
            .map(|i| {
                cert_entry(
                    i,
                    3_333 + i,
                    FinalityReversibility::DeterministicQuorum,
                    FinalityVerdict::Established,
                )
            })
            .collect();
        let cert = compose(&entries).expect("nine established domains must compose");
        assert_eq!(cert.domain_count, 9);
        assert_eq!(cert.domain_mask, 0b1_1111_1111);
        assert_eq!(cert.guarantee.fault_tolerance_bps, 3_333);
        assert_eq!(
            compose(&entries),
            Ok(cert),
            "composition must be deterministic"
        );
    }

    #[test]
    fn empty_domain_set_produces_no_certificate() {
        assert_eq!(compose(&[]), Err(FinalityComposeError::EmptyDomainSet));
    }

    #[test]
    fn refutation_outranks_missing_evidence() {
        let entries = vec![
            cert_entry(
                0,
                3_333,
                FinalityReversibility::DeterministicQuorum,
                FinalityVerdict::Pending {
                    reason: FinalityPendingReason::EvidenceMissing,
                },
            ),
            cert_entry(
                1,
                3_333,
                FinalityReversibility::DeterministicQuorum,
                FinalityVerdict::Refuted { code: 7 },
            ),
        ];
        assert_eq!(
            compose(&entries),
            Err(FinalityComposeError::RefutedDomain {
                domain_id: 1,
                code: 7
            })
        );
    }

    #[test]
    fn pending_domain_is_resubmittable_not_rejected() {
        let entries = vec![cert_entry(
            0,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Pending {
                reason: FinalityPendingReason::BondUnverified,
            },
        )];
        let err = compose(&entries).expect_err("pending must not certify");
        // Evidence debt is re-submittable, not a rejection: the variant names
        // the domain and the cause instead of a refusal.
        assert!(matches!(
            err,
            FinalityComposeError::DomainNotEstablished {
                domain_id: 0,
                reason: FinalityPendingReason::BondUnverified,
            }
        ));
    }

    #[test]
    fn unbound_attestation_cannot_enter_a_certificate() {
        let mut entry = cert_entry(
            0,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Established,
        );
        entry.guarantee.attestation.parent = false;
        assert_eq!(
            compose(&[entry]),
            Err(FinalityComposeError::AttestationUnbound { domain_id: 0 })
        );
    }

    #[test]
    fn duplicate_domain_index_is_refused() {
        let entries = vec![
            cert_entry(
                3,
                3_333,
                FinalityReversibility::DeterministicQuorum,
                FinalityVerdict::Established,
            ),
            cert_entry(
                3,
                3_333,
                FinalityReversibility::DeterministicQuorum,
                FinalityVerdict::Established,
            ),
        ];
        assert_eq!(
            compose(&entries),
            Err(FinalityComposeError::DuplicateDomain { domain_id: 3 })
        );
    }

    #[test]
    fn same_guarantee_different_domain_roots_are_distinguished() {
        let a = vec![cert_entry(
            0,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Established,
        )];
        let mut b = a.clone();
        b[0].state_root = [9u8; 32];
        let cert_a = compose(&a).expect("a");
        let cert_b = compose(&b).expect("b");
        assert_ne!(cert_a.domain_commitment, cert_b.domain_commitment);
        assert_ne!(cert_a.certificate_digest, cert_b.certificate_digest);
        assert!(
            cert_a != compose(&b).expect("b"),
            "a certificate must not verify another domain set"
        );
    }

    #[test]
    fn weakest_link_wins_across_reversibility_classes() {
        let entries = vec![
            cert_entry(
                0,
                9_999,
                FinalityReversibility::CryptographicValidity,
                FinalityVerdict::Established,
            ),
            cert_entry(
                1,
                4_999,
                FinalityReversibility::ProbabilisticWork { confirmations: 6 },
                FinalityVerdict::Established,
            ),
        ];
        let cert = compose(&entries).expect("compose");
        assert_eq!(cert.guarantee.fault_tolerance_bps, 4_999);
        assert_eq!(
            cert.guarantee.reversibility,
            FinalityReversibility::ProbabilisticWork { confirmations: 6 }
        );
    }

    #[test]
    fn tampered_certificate_fails_verification() {
        let entries = vec![cert_entry(
            0,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Established,
        )];
        let mut cert = compose(&entries).expect("compose");
        cert.domain_count = 2;
        assert_ne!(cert, compose(&entries).expect("compose"));
    }

    #[test]
    fn more_than_sixteen_domains_is_refused() {
        let entries: Vec<_> = (0u16..17)
            .map(|i| {
                cert_entry(
                    i,
                    3_333,
                    FinalityReversibility::DeterministicQuorum,
                    FinalityVerdict::Established,
                )
            })
            .collect();
        assert_eq!(compose(&entries), Err(FinalityComposeError::TooManyDomains));
    }

    #[test]
    fn permutation_invariance_holds_for_commitment_and_digest() {
        let e0 = cert_entry(
            0,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Established,
        );
        let e5 = cert_entry(
            5,
            4_999,
            FinalityReversibility::ProbabilisticWork { confirmations: 6 },
            FinalityVerdict::Established,
        );
        let e12 = cert_entry(
            12,
            9_999,
            FinalityReversibility::CryptographicValidity,
            FinalityVerdict::Established,
        );
        let forward = compose(&[e0, e5, e12]).expect("forward");
        let reversed = compose(&[e12, e5, e0]).expect("reversed");
        let rotated = compose(&[e5, e12, e0]).expect("rotated");
        assert_eq!(forward, reversed);
        assert_eq!(forward, rotated);
    }

    #[test]
    fn quantum_posture_confirmations_and_slashable_backing_affect_digest() {
        let base = cert_entry(
            2,
            4_999,
            FinalityReversibility::ProbabilisticWork { confirmations: 6 },
            FinalityVerdict::Established,
        );
        let mut diff_conf = base;
        diff_conf.guarantee.reversibility =
            FinalityReversibility::ProbabilisticWork { confirmations: 1 };

        let mut diff_quantum = base;
        diff_quantum.guarantee.quantum_posture = QuantumClass::Classical;

        let mut diff_slash = base;
        diff_slash.guarantee.slashable_backing = false;

        let c_base = compose(&[base]).expect("base");
        let c_conf = compose(&[diff_conf]).expect("conf");
        let c_quantum = compose(&[diff_quantum]).expect("quantum");
        let c_slash = compose(&[diff_slash]).expect("slash");

        assert_ne!(c_base.domain_commitment, c_conf.domain_commitment);
        assert_ne!(c_base.certificate_digest, c_conf.certificate_digest);
        assert_ne!(c_base.domain_commitment, c_quantum.domain_commitment);
        assert_ne!(c_base.certificate_digest, c_quantum.certificate_digest);
        assert_ne!(c_base.domain_commitment, c_slash.domain_commitment);
        assert_ne!(c_base.certificate_digest, c_slash.certificate_digest);
    }

    #[test]
    fn conflicting_verdicts_on_same_domain_index_are_refuted_distinctly() {
        let established = cert_entry(
            4,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Established,
        );
        let refuted = cert_entry(
            4,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Refuted { code: 42 },
        );
        assert_eq!(
            compose(&[established, refuted]),
            Err(FinalityComposeError::ConflictingVerdicts {
                first: 4,
                second: 4,
            })
        );
    }

    #[test]
    fn compose_with_bar_binds_external_state_root_and_refuses_empty_bar() {
        let state_bar = CommitmentAttestation {
            state_root: true,
            tx_root: false,
            event_root: false,
            parent: false,
        };
        let mut ext = cert_entry(
            7,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Established,
        );
        ext.guarantee.attestation = state_bar;
        assert_eq!(
            compose(&[ext]),
            Err(FinalityComposeError::AttestationUnbound { domain_id: 7 })
        );
        let cert = compose_with_bar(&[ext], state_bar).expect("state_root bar satisfied");
        assert!(cert.verify_against_with_bar(&[ext], state_bar));
        assert!(!cert.verify_against_with_bar(&[ext], FINALITY_BINDS_ALL));
        let empty_bar = CommitmentAttestation {
            state_root: false,
            tx_root: false,
            event_root: false,
            parent: false,
        };
        assert_eq!(
            compose_with_bar(&[ext], empty_bar),
            Err(FinalityComposeError::AttestationUnbound { domain_id: 7 })
        );
    }

    #[test]
    fn resubmittable_classifier_distinguishes_pending_from_refusal() {
        let pending = FinalityComposeError::DomainNotEstablished {
            domain_id: 1,
            reason: FinalityPendingReason::EvidenceMissing,
        };
        let refuted = FinalityComposeError::RefutedDomain {
            domain_id: 1,
            code: 9,
        };
        assert!(pending.is_resubmittable());
        assert!(!refuted.is_resubmittable());
    }
}
