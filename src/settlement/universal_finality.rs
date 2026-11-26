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
//! Every finality checkpoint builds a canonical three-bucket
//! [`GlobalFinalityCertificate`] via [`compose`] from consensus state in
//! [`crate::settlement::SettlementRegistries`], commits its Keccak-256 digest
//! into [`crate::settlement::GlobalBlockHeader::finality_certificate_root`],
//! and exposes `O(log N)` Merkle inclusion proofs verified by
//! [`crate::light_client::LightClient::verify_finality_certificate_domain`].

use crate::cross_domain::external::spec::SecurityBacking;
use crate::cross_domain::external::AdapterSpec;
use crate::crypto::facts::QuantumClass;
use crate::domain::types::{ConsensusDomain, ConsensusKind};
use crate::settlement::domains::CommitmentAttestation;
use serde::{Deserialize, Serialize};

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
/// Minimum cumulative proof-of-work difficulty (in bits) an observed `Work`
/// backing must carry before it may keep a deep-`PoW` value-outflow guarantee.
///
/// A `Work { difficulty_bits }` below this threshold is a regtest- or
/// toy-chain-scale claim: two hashes cost well under a microsecond, so it
/// carries no adversarial cost at all. It must not open the value path.
/// (`SecurityBacking::Work` is produced by `bitcoin_spv.rs` from the
/// cumulative chain work, so a real mainnet chain clears this threshold.)
const MIN_TIER1_WORK_BITS: u32 = 64;

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
    ///
    /// # Module-private on purpose
    ///
    /// This is the SPEC-ONLY derivation: it reads the registration promise and
    /// nothing else. It is deliberately **not** `pub`, so no other module in
    /// the tree can obtain an external domain's guarantee from the
    /// registration alone. The single public entry point is
    /// [`Self::for_external_spec_with_backing`], which additionally reads the
    /// backing of the domain's LAST ACCEPTED attestation.
    ///
    /// The distinction is not cosmetic. A registration spec is a declaration
    /// made before any evidence existed; the accepted attestation is the fact.
    /// Deriving the guarantee from the declaration alone reports a
    /// BFT-grade bound for a domain that has never produced a single
    /// accepted attestation.
    ///
    /// WIRING: the spec-only half of `for_external_spec_with_backing`; it is
    /// the ceiling that the observed backing may only ever lower.
    #[must_use]
    fn for_external_spec_declared(spec: &AdapterSpec) -> Self {
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
            AdapterSpec::NipopowSuperblock { genesis, .. } => {
                // Sublinear PoW finality is probabilistic work, never a
                // quorum: the promise is "a chain with this much committed
                // work would have to be rewritten", and the confirmation depth
                // is the pinned stability parameter `k` the proof's own suffix
                // must reach. An unpinned spec promises nothing, so the depth
                // is zero and any route that composes it inherits the weakness.
                let (valid, confs) = genesis.as_ref().map_or((false, 0), |g| {
                    let zero_field = g.genesis_id == [0u8; 32]
                        || g.pow_target == [0u8; 32]
                        || g.min_superblocks_m == 0
                        || g.min_superblock_level == 0
                        || g.min_suffix_k == 0;
                    (!zero_field, if zero_field { 0 } else { g.min_suffix_k })
                });
                Self {
                    reversibility: FinalityReversibility::ProbabilisticWork {
                        confirmations: u64::from(confs),
                    },
                    // SHA-256 work is the one primitive here Shor's algorithm
                    // does not touch: the posture is lattice-grade even though
                    // nothing on this path is a signature.
                    quantum_posture: if valid {
                        QuantumClass::Lattice
                    } else {
                        QuantumClass::Classical
                    },
                    attestation: CommitmentAttestation {
                        state_root: valid,
                        tx_root: valid,
                        event_root: false,
                        parent: valid,
                    },
                    // Budlum cannot slash a foreign chain's miners. Claiming
                    // otherwise would let a high-value route read "slashable"
                    // off a proof that carries no Budlum-side bond.
                    slashable_backing: false,
                    fault_tolerance_bps: if valid { POW_FAULT_TOLERANCE_BPS } else { 0 },
                }
            }
            AdapterSpec::Ghostdag { anchor, .. } => {
                // A GHOSTDAG ledger finalizes by blue score, not by block
                // count: the depth that matters is `required_blue_depth`, and
                // the pin carries its own `k`-cluster bound. Unpinned, the spec
                // promises nothing at all.
                let (valid, depth) = anchor.as_ref().map_or((false, 0), |a| {
                    let zero_field = a.anchor_hash == [0u8; 32]
                        || a.k == 0
                        || a.max_parents == 0
                        || a.merge_depth_bound == 0
                        || a.required_blue_depth == 0
                        || a.max_target_bits == 0;
                    (
                        !zero_field,
                        if zero_field { 0 } else { a.required_blue_depth },
                    )
                });
                Self {
                    reversibility: FinalityReversibility::ProbabilisticWork {
                        confirmations: depth,
                    },
                    // SHA-256d work is outside Shor's reach: the posture is
                    // lattice-grade even though nothing here is a signature.
                    quantum_posture: if valid {
                        QuantumClass::Lattice
                    } else {
                        QuantumClass::Classical
                    },
                    attestation: CommitmentAttestation {
                        state_root: valid,
                        tx_root: valid,
                        event_root: false,
                        parent: valid,
                    },
                    // A blockDAG's work is committed by miners Budlum cannot
                    // slash; claiming otherwise would let a high-value route
                    // read "slashable" off a proof that carries no bond.
                    slashable_backing: false,
                    fault_tolerance_bps: if valid { POW_FAULT_TOLERANCE_BPS } else { 0 },
                }
            }
            AdapterSpec::NearDoomslug { epoch, .. } => {
                // Doomslug finality is a stake quorum over one epoch's block
                // producers: deterministic quorum class, not a depth. A pin
                // with no producers, no successor, or a zero successor
                // commitment names no quorum, so it earns no guarantee.
                let valid = epoch.as_ref().is_some_and(|e| {
                    e.epoch_id != [0u8; 32]
                        && e.next_epoch_id != [0u8; 32]
                        && e.epoch_id != e.next_epoch_id
                        && e.next_bp_hash != [0u8; 32]
                        && !e.block_producers.is_empty()
                });
                Self {
                    reversibility: FinalityReversibility::DeterministicQuorum,
                    // Ed25519 approvals carry ML-DSA-65 co-signatures when the
                    // producers publish a PQ key, so the pinned posture is
                    // lattice-grade only when every producer commits one.
                    quantum_posture: if valid {
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
                    // A foreign validator set: Budlum holds no bond over it.
                    slashable_backing: false,
                    fault_tolerance_bps: if valid { BFT_FAULT_TOLERANCE_BPS } else { 0 },
                }
            }
            AdapterSpec::HoneyBadgerBft { committee, .. } => {
                // Asynchronous ACS finality is protocol finality under an
                // honest supermajority: one decided epoch is final, and the
                // reversibility class is a quorum, not a depth. The guarantee
                // is slashable only if the committee actually validates - a
                // committee whose weights or keys are degenerate cannot lose
                // anything, so it cannot back a value promise.
                let valid = committee.as_ref().is_some_and(|c| c.validate().is_ok());
                Self {
                    reversibility: FinalityReversibility::DeterministicQuorum,
                    // ML-DSA-65 is the only assumption on the verify path.
                    quantum_posture: if valid {
                        QuantumClass::Lattice
                    } else {
                        QuantumClass::Classical
                    },
                    attestation: CommitmentAttestation {
                        state_root: valid,
                        tx_root: valid,
                        // An ACS subset commits the event root too; the
                        // adapter attests it when the evidence carries one.
                        event_root: valid,
                        parent: valid,
                    },
                    // The committee is a foreign chain's validators. Budlum
                    // holds no bond over them, so the promise is honest about
                    // being unslashable from here.
                    slashable_backing: false,
                    fault_tolerance_bps: if valid { BFT_FAULT_TOLERANCE_BPS } else { 0 },
                }
            }
            AdapterSpec::BabylonEots { pinned, .. } => {
                let (valid, pq_all) = pinned.as_ref().map_or((false, false), |p| {
                    let ok = p.validate().is_ok();
                    let pq = ok
                        && !p.epoch_pq_keys.is_empty()
                        && p.epoch_keys.iter().all(|(epoch, _)| {
                            p.epoch_pq_keys
                                .iter()
                                .any(|(pq_epoch, _)| pq_epoch == epoch)
                        });
                    (ok, pq)
                });
                Self {
                    // EOTS finality is economic: a conflicting pair is a
                    // slashable equivocation, but a single finality provider
                    // has no Byzantine fault tolerance to speak of.
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
                        parent: false,
                    },
                    slashable_backing: valid,
                    fault_tolerance_bps: 0,
                }
            }
        }
    }

    /// Derive the finality guarantee of a registered external intake
    /// [`AdapterSpec`] **constrained by the backing its last accepted
    /// attestation actually carried**.
    ///
    /// `observed` is the `SecurityBacking` of the domain's LAST ACCEPTED
    /// attestation (`DomainProfile::last_backing`, updated by the registry on
    /// every accepted attestation). `None` means the domain has not yet
    /// produced any accepted attestation.
    ///
    /// # The observed backing may only ever REDUCE the promise
    ///
    /// The registration spec is a ceiling: it was written before any evidence
    /// existed, so a later, stronger attestation must not inflate what the
    /// registration promised. A weaker attestation must reduce it.
    ///
    /// | Observed backing | Effect on the promised bound |
    /// |---|---|
    /// | `None` (no accepted attestation) | `bps = 0`, `slashable_backing = false`, attestation cleared |
    /// | `SecurityBacking::None` | `bps = 0`, `slashable_backing = false`, attestation cleared |
    /// | `Authority { .. }` | `slashable_backing = false`; `bps = 0` when the spec promised slashable backing |
    /// | `SignatureSet { slashable, .. }` | `slashable_backing &= slashable`; `bps = 0` when the quorum is degenerate (`required == 0`, `signers < required`, `total_weight == 0`) or when the spec promised slashable backing the attestation does not carry |
    /// | `SignatureSet { slashable: true, .. }` | the promised bound is kept |
    /// | `Work { difficulty_bits }` | `bps = 0` when `difficulty_bits == 0`; a sub-Tier-1 work claim (`< 64` bits) does not keep a deep-`PoW` value guarantee |
    /// | `Zk { .. }` | the promised bound is kept (stronger evidence cannot inflate it) |
    ///
    /// # Why an unslashable signature set does not always zero the bound
    ///
    /// `fault_tolerance_bps == 0` also closes tx-inclusion
    /// (`source_admits_tx_inclusion` is `tx_root && fault_tolerance_bps > 0`).
    /// An Ethereum sync committee is unslashable BY DESIGN and still carries
    /// a BFT-grade inclusion bound; zeroing its bound would refuse a
    /// perfectly valid inclusion proof. So the bound is zeroed only when the
    /// observation actually contradicts the promise (a downgrade) or when the
    /// quorum is degenerate - never merely because the backing is
    /// unslashable.
    ///
    /// WIRING: the canonical external-domain guarantee derivation; the
    /// spec-only half (`Self::for_external_spec_declared`) is module-private
    /// so this is the only reachable path.
    #[must_use]
    pub fn for_external_spec_with_backing(
        spec: &AdapterSpec,
        observed: Option<&SecurityBacking>,
    ) -> Self {
        let promised = Self::for_external_spec_declared(spec);
        let Some(observed) = observed else {
            // No accepted attestation: there is no evidence at all. A domain
            // that has never been attested carries no fault tolerance.
            return Self::no_observed_backing();
        };
        match observed {
            SecurityBacking::None => Self::no_observed_backing(),
            SecurityBacking::Authority { .. } => Self {
                // A permissioned authority set is revocable by admission root,
                // not stake-slashed, so it is never slashable backing.
                slashable_backing: false,
                fault_tolerance_bps: if promised.slashable_backing {
                    0
                } else {
                    promised.fault_tolerance_bps
                },
                ..promised
            },
            SecurityBacking::SignatureSet {
                signers,
                required,
                total_weight,
                slashable,
                ..
            } => {
                let degenerate = *required == 0 || *signers < *required || *total_weight == 0;
                let downgrade = promised.slashable_backing && !*slashable;
                Self {
                    // A degenerate quorum proves nothing, so it cannot keep
                    // the slashability claim either: the stake it names was
                    // never really at risk behind a quorum that does not
                    // exist.
                    slashable_backing: !degenerate && promised.slashable_backing && *slashable,
                    fault_tolerance_bps: if degenerate || downgrade {
                        0
                    } else {
                        promised.fault_tolerance_bps
                    },
                    ..promised
                }
            }
            SecurityBacking::Work { difficulty_bits } => {
                // No work at all is no evidence. A sub-Tier-1 work claim is a
                // toy/regtest chain: it may keep a probabilistic inclusion
                // bound, but it must not keep a deep-`PoW` value guarantee.
                let deep_pow = matches!(
                    promised.reversibility,
                    FinalityReversibility::ProbabilisticWork { .. }
                );
                Self {
                    slashable_backing: false,
                    // No work at all is no evidence, and a sub-Tier-1 work
                    // claim cannot keep a deep-`PoW` value guarantee.
                    fault_tolerance_bps: if *difficulty_bits == 0
                        || (deep_pow && *difficulty_bits < MIN_TIER1_WORK_BITS)
                    {
                        0
                    } else {
                        promised.fault_tolerance_bps
                    },
                    ..promised
                }
            }
            SecurityBacking::Zk { .. } => promised,
        }
    }

    /// The guarantee of a domain whose last accepted attestation carries no
    /// usable backing: no fault tolerance, no slashable backing, and no
    /// attestation of any kind.
    ///
    /// Fail-closed: "no evidence" is not "a little evidence".
    #[must_use]
    fn no_observed_backing() -> Self {
        Self {
            reversibility: FinalityReversibility::DeterministicQuorum,
            quantum_posture: QuantumClass::Hash,
            attestation: CommitmentAttestation {
                state_root: false,
                tx_root: false,
                event_root: false,
                parent: false,
            },
            slashable_backing: false,
            fault_tolerance_bps: 0,
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

    /// Deterministic human-readable security label describing the exact
    /// reversibility class, quantum posture, slashable backing, and basis-point
    /// fault tolerance without any heuristic score or ranking.
    #[must_use]
    pub fn label(&self) -> String {
        let rev = match self.reversibility {
            FinalityReversibility::ProbabilisticWork { confirmations } => {
                format!("probabilistic-work({confirmations})")
            }
            FinalityReversibility::DataAvailabilitySampled { min_samples } => {
                format!("da-sampled({min_samples})")
            }
            FinalityReversibility::DeterministicQuorum => "deterministic-quorum".to_owned(),
            FinalityReversibility::CryptographicValidity => "cryptographic-validity".to_owned(),
        };
        let quantum = match self.quantum_posture {
            QuantumClass::Classical => "classical",
            QuantumClass::Lattice => "lattice",
            QuantumClass::Hash => "hash",
        };
        let slash = if self.slashable_backing {
            "slashable"
        } else {
            "non-slashable"
        };
        format!("{rev}|{quantum}|{slash}|ft={}bps", self.fault_tolerance_bps)
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

/// Maximum number of consensus domains committed in a single
/// [`GlobalFinalityCertificate`], aligned with the consensus domain registry
/// ceiling (`4_096`).
const MAX_CERTIFICATE_DOMAINS: usize = crate::domain::registry::MAX_REGISTERED_DOMAINS;

/// Which of the three non-blocking certificate buckets holds a domain row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityBucket {
    /// Domain verified and bound all required commitments.
    Established,
    /// Domain evidence is incomplete or pending; neither accepted nor refuted.
    Pending,
    /// Domain was frozen or rejected by its own rule or dispute evidence.
    Refuted,
}

impl FinalityBucket {
    const fn matches_verdict(self, verdict: FinalityVerdict) -> bool {
        matches!(
            (self, verdict),
            (Self::Established, FinalityVerdict::Established)
                | (Self::Pending, FinalityVerdict::Pending { .. })
                | (Self::Refuted, FinalityVerdict::Refuted { .. })
        )
    }
}

/// One domain's certified verdict, as fed into [`compose`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainFinalityEntry {
    /// Canonical domain identifier in the settlement registry (`DomainId = u32`).
    pub domain_id: u32,
    /// Finalized height the verdict refers to.
    pub height: u64,
    /// Settlement checkpoint height at which this row was sealed.
    pub checkpoint_height: u64,
    /// Domain state root the verdict commits to.
    pub state_root: [u8; 32],
    /// Registered finality adapter identifier.
    pub adapter_id: String,
    /// Adapter protocol version.
    pub adapter_version: u32,
    /// Digest of the verified finality proof bound to this row.
    pub finality_proof_hash: [u8; 32],
    /// Digest of the cryptographic/economic backing anchor (validator set or config hash).
    pub guarantee_backing_hash: [u8; 32],
    /// Escrowed slashable operator bond backing this domain (in atoms).
    pub bond_atoms: u128,
    /// Exact finality guarantee derived strictly from consensus state.
    pub guarantee: FinalityGuarantee,
    /// Trace of the binds proof this row attests, sealed into `row_digest`.
    ///
    /// Derived from [`DomainFinalityEntry::guarantee`] by
    /// [`trace_record_binds`] and never taken from a caller: a row can only
    /// seal what its own guarantee proves, so the seal cannot claim a wider
    /// proof than the row carries.
    pub binds: [u8; 32],
    /// Trace of the quantum posture this row attests, sealed into `row_digest`.
    ///
    /// Derived by [`trace_record_quantum_posture`] from the same guarantee.
    pub posture_trace: [u8; 32],
    /// Three-valued verdict of the domain's own finality rule.
    pub verdict: FinalityVerdict,
}

impl DomainFinalityEntry {
    /// Canonical Keccak-256 digest binding every field of this row with explicit
    /// length-prefixing and domain separation (`BDLM_FINALITY_CERT_ROW_V1`).
    #[must_use]
    pub fn row_digest(&self) -> [u8; 32] {
        use sha3::{Digest as _, Keccak256};

        let mut hasher = Keccak256::new();
        hasher.update(b"BDLM_FINALITY_CERT_ROW_V1");
        hasher.update(self.domain_id.to_be_bytes());
        hasher.update(self.height.to_be_bytes());
        hasher.update(self.checkpoint_height.to_be_bytes());
        hasher.update(self.state_root);
        let adapter_bytes = self.adapter_id.as_bytes();
        let adapter_len = u64::try_from(adapter_bytes.len()).unwrap_or(u64::MAX);
        hasher.update(adapter_len.to_be_bytes());
        hasher.update(adapter_bytes);
        hasher.update(self.adapter_version.to_be_bytes());
        hasher.update(self.finality_proof_hash);
        hasher.update(self.guarantee_backing_hash);
        hasher.update(self.bond_atoms.to_be_bytes());
        absorb_guarantee_keccak(&mut hasher, &self.guarantee);
        hasher.update(self.binds);
        hasher.update(self.posture_trace);
        absorb_verdict_keccak(&mut hasher, self.verdict);
        hasher.finalize().into()
    }
}

/// Canonical trace record of the binds a [`CommitmentAttestation`] proves.
///
/// The trace speaks the row's own domain separation tag and encodes each root
/// as one byte in a fixed order, so two rows that bind different roots can
/// never produce the same trace, and no other digest in the tree (row, leaf,
/// node, certificate header) shares this prefix.
#[must_use]
pub fn trace_record_binds(attestation: &CommitmentAttestation) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256};

    let mut hasher = Keccak256::new();
    hasher.update(b"BDLM_FINALITY_BINDS_TRACE_V1");
    hasher.update([
        u8::from(attestation.state_root),
        u8::from(attestation.tx_root),
        u8::from(attestation.event_root),
        u8::from(attestation.parent),
    ]);
    hasher.finalize().into()
}

/// Canonical trace record of a [`QuantumClass`] posture.
///
/// The class is pinned to a fixed code byte so a reordered enum cannot
/// silently change what an old trace meant.
#[must_use]
pub fn trace_record_quantum_posture(posture: QuantumClass) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256};

    let code: u8 = match posture {
        QuantumClass::Classical => 0,
        QuantumClass::Lattice => 1,
        QuantumClass::Hash => 2,
    };
    let mut hasher = Keccak256::new();
    hasher.update(b"BDLM_FINALITY_POSTURE_TRACE_V1");
    hasher.update([code]);
    hasher.finalize().into()
}

fn absorb_guarantee_keccak(hasher: &mut sha3::Keccak256, guarantee: &FinalityGuarantee) {
    use sha3::Digest as _;

    let (rev_tag, rev_param): (u8, u64) = match guarantee.reversibility {
        FinalityReversibility::ProbabilisticWork { confirmations } => (0, confirmations),
        FinalityReversibility::DataAvailabilitySampled { min_samples } => {
            (1, u64::from(min_samples))
        }
        FinalityReversibility::DeterministicQuorum => (2, 0),
        FinalityReversibility::CryptographicValidity => (3, 0),
    };
    let quantum_tag: u8 = match guarantee.quantum_posture {
        QuantumClass::Classical => 0,
        QuantumClass::Lattice => 1,
        QuantumClass::Hash => 2,
    };
    hasher.update([rev_tag]);
    hasher.update(rev_param.to_be_bytes());
    hasher.update([quantum_tag]);
    hasher.update([
        u8::from(guarantee.attestation.state_root),
        u8::from(guarantee.attestation.tx_root),
        u8::from(guarantee.attestation.event_root),
        u8::from(guarantee.attestation.parent),
    ]);
    hasher.update([u8::from(guarantee.slashable_backing)]);
    hasher.update(guarantee.fault_tolerance_bps.to_be_bytes());
}

fn absorb_verdict_keccak(hasher: &mut sha3::Keccak256, verdict: FinalityVerdict) {
    use sha3::Digest as _;

    let (tag, detail): (u8, u16) = match verdict {
        FinalityVerdict::Established => (0, 0),
        FinalityVerdict::Refuted { code } => (1, code),
        FinalityVerdict::Pending { reason } => (
            2,
            match reason {
                FinalityPendingReason::EvidenceMissing => 1,
                FinalityPendingReason::AttestationUnbound => 2,
                FinalityPendingReason::RuleNotSatisfied => 3,
                FinalityPendingReason::BondUnverified => 4,
            },
        ),
    };
    hasher.update([tag]);
    hasher.update(detail.to_be_bytes());
}

fn keccak_cert_empty_root() -> [u8; 32] {
    use sha3::{Digest as _, Keccak256};

    let mut hasher = Keccak256::new();
    hasher.update(b"BDLM_FINALITY_CERT_EMPTY_V1");
    hasher.finalize().into()
}

fn keccak_cert_leaf(row_digest: &[u8; 32]) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256};

    let mut hasher = Keccak256::new();
    hasher.update(b"BDLM_FINALITY_CERT_LEAF_V1");
    hasher.update(row_digest);
    hasher.finalize().into()
}

fn keccak_cert_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256};

    let mut hasher = Keccak256::new();
    hasher.update(b"BDLM_FINALITY_CERT_NODE_V1");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn merkle_depth_for_count(leaf_count: usize) -> usize {
    if leaf_count <= 1 {
        return 0;
    }
    let mut depth = 0usize;
    let mut n = leaf_count;
    while n > 1 {
        n = n.div_ceil(2);
        depth = depth.saturating_add(1);
    }
    depth
}

fn compute_bucket_merkle_root(rows: &[DomainFinalityEntry]) -> [u8; 32] {
    if rows.is_empty() {
        return keccak_cert_empty_root();
    }
    let mut level: Vec<[u8; 32]> = rows
        .iter()
        .map(|row| keccak_cert_leaf(&row.row_digest()))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut idx = 0usize;
        while idx < level.len() {
            let Some(&left) = level.get(idx) else {
                break;
            };
            let right = level.get(idx + 1).copied().unwrap_or(left);
            next.push(keccak_cert_node(&left, &right));
            idx += 2;
        }
        level = next;
    }
    level[0]
}

fn build_bucket_inclusion_proof(
    bucket: FinalityBucket,
    rows: &[DomainFinalityEntry],
    target_index: usize,
) -> Option<DomainFinalityInclusionProof> {
    let entry = rows.get(target_index)?.clone();
    let leaf_count = u32::try_from(rows.len()).ok()?;
    let leaf_index = u32::try_from(target_index).ok()?;
    let mut level: Vec<[u8; 32]> = rows
        .iter()
        .map(|row| keccak_cert_leaf(&row.row_digest()))
        .collect();
    let mut siblings = Vec::with_capacity(merkle_depth_for_count(rows.len()));
    let mut cursor = target_index;
    while level.len() > 1 {
        let sibling_idx = if cursor.is_multiple_of(2) {
            if cursor + 1 < level.len() {
                cursor + 1
            } else {
                cursor
            }
        } else {
            cursor - 1
        };
        siblings.push(*level.get(sibling_idx)?);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut idx = 0usize;
        while idx < level.len() {
            let Some(&left) = level.get(idx) else {
                break;
            };
            let right = level.get(idx + 1).copied().unwrap_or(left);
            next.push(keccak_cert_node(&left, &right));
            idx += 2;
        }
        level = next;
        cursor /= 2;
    }
    Some(DomainFinalityInclusionProof {
        bucket,
        leaf_index,
        leaf_count,
        entry,
        siblings,
    })
}

/// `O(log N)` binary Keccak-256 Merkle inclusion proof for a single domain row
/// inside one bucket of a [`GlobalFinalityCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainFinalityInclusionProof {
    /// Certificate bucket (`Established`, `Pending`, or `Refuted`) owning this leaf.
    pub bucket: FinalityBucket,
    /// Zero-based leaf position inside the sorted bucket.
    pub leaf_index: u32,
    /// Total number of leaves in that bucket.
    pub leaf_count: u32,
    /// Full domain finality row proven by this path.
    pub entry: DomainFinalityEntry,
    /// Bottom-up sibling digests up to the bucket root.
    pub siblings: Vec<[u8; 32]>,
}

impl DomainFinalityInclusionProof {
    /// Verify this inclusion proof against `expected_bucket_root` fail-closed.
    #[must_use]
    pub fn verify(&self, expected_bucket_root: &[u8; 32]) -> bool {
        if self.leaf_count == 0 || self.leaf_index >= self.leaf_count {
            return false;
        }
        if !self.bucket.matches_verdict(self.entry.verdict) {
            return false;
        }
        let Ok(leaf_count_usize) = usize::try_from(self.leaf_count) else {
            return false;
        };
        if self.siblings.len() != merkle_depth_for_count(leaf_count_usize) {
            return false;
        }
        let mut acc = keccak_cert_leaf(&self.entry.row_digest());
        let Ok(mut cursor) = usize::try_from(self.leaf_index) else {
            return false;
        };
        let mut width = leaf_count_usize;
        for sibling in &self.siblings {
            // The claimed position pins the tree shape: only the final node
            // of an odd-width level is hashed with itself, and nowhere else
            // may a sibling repeat the running digest - otherwise the root of
            // a three-leaf bucket also opens as a forged four-leaf proof that
            // presents the duplicated tail as a second, distinct position.
            let odd_tail = !width.is_multiple_of(2) && cursor == width - 1;
            if odd_tail != (*sibling == acc) {
                return false;
            }
            acc = if cursor.is_multiple_of(2) {
                keccak_cert_node(&acc, sibling)
            } else {
                keccak_cert_node(sibling, &acc)
            };
            cursor /= 2;
            width = width.div_ceil(2);
        }
        acc == *expected_bucket_root
    }
}

/// Failure of [`compose`] or [`GlobalFinalityCertificate::verify_integrity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityComposeError {
    /// No domain entries were supplied; an empty certificate proves nothing.
    EmptyDomainSet,
    /// The same domain identifier appears more than once in the input set.
    DuplicateDomain {
        /// Offending domain identifier.
        domain_id: u32,
    },
    /// Entries disagree on the settlement checkpoint height.
    ConflictingCheckpoints {
        /// Checkpoint height of the first entry.
        expected: u64,
        /// Conflicting checkpoint height encountered.
        found: u64,
    },
    /// An `Established` row does not bind the full commitment set or carries zero fault tolerance.
    AttestationUnbound {
        /// Offending domain identifier.
        domain_id: u32,
    },
    /// A row's sealed `binds`/`posture_trace` does not match what its own
    /// guarantee and posture derive.
    ///
    /// A certificate row that seals a trace its proof cannot produce is
    /// attesting to evidence it never saw; `compose` refuses it in every
    /// bucket, including `Pending` and `Refuted`, so a hand-built row cannot
    /// carry a wider claim than its proof - even when it is about to be
    /// discarded from `Established`.
    BindsMismatch {
        /// Offending domain identifier.
        domain_id: u32,
    },
    /// More than `MAX_CERTIFICATE_DOMAINS` domains were supplied.
    TooManyDomains,
    /// A serialized or externally supplied certificate does not match its recomputed digest/roots.
    IntegrityMismatch,
}

/// Canonical three-bucket global finality certificate sealed at a settlement
/// checkpoint.
///
/// The certificate is strictly *derived*, never asserted: [`compose`] partitions
/// all registered domains into `established`, `pending`, and `refuted` buckets
/// sorted canonically by `domain_id: u32`, commits each bucket with a binary
/// Keccak-256 Merkle root, folds the weakest-link guarantee over `established`
/// rows only, and binds every field into [`Self::certificate_digest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalFinalityCertificate {
    /// Settlement checkpoint height at which this certificate was derived.
    pub checkpoint_height: u64,
    /// Sorted `Established` domain rows.
    pub established: Vec<DomainFinalityEntry>,
    /// Sorted `Pending` domain rows (each carrying its [`FinalityPendingReason`]).
    pub pending: Vec<DomainFinalityEntry>,
    /// Sorted `Refuted` domain rows (each carrying its rejection code).
    pub refuted: Vec<DomainFinalityEntry>,
    /// Number of `Established` domain rows.
    pub established_count: u32,
    /// Number of `Pending` domain rows.
    pub pending_count: u32,
    /// Number of `Refuted` domain rows.
    pub refuted_count: u32,
    /// Binary Keccak-256 Merkle root over `established`.
    pub established_root: [u8; 32],
    /// Binary Keccak-256 Merkle root over `pending`.
    pub pending_root: [u8; 32],
    /// Binary Keccak-256 Merkle root over `refuted`.
    pub refuted_root: [u8; 32],
    /// Weakest-link guarantee across all `established` rows (`None` when none established).
    pub guarantee: Option<FinalityGuarantee>,
    /// Canonical Keccak-256 digest committing every bucket root, count, checkpoint, and guarantee.
    pub certificate_digest: [u8; 32],
}

impl GlobalFinalityCertificate {
    /// Return the canonical Merkle root for `bucket`.
    #[must_use]
    pub const fn bucket_root(&self, bucket: FinalityBucket) -> [u8; 32] {
        match bucket {
            FinalityBucket::Established => self.established_root,
            FinalityBucket::Pending => self.pending_root,
            FinalityBucket::Refuted => self.refuted_root,
        }
    }

    /// Build a binary Keccak-256 Merkle inclusion proof for `domain_id` in its
    /// owning bucket, or `None` if `domain_id` is absent from this certificate.
    #[must_use]
    pub fn prove_domain(&self, domain_id: u32) -> Option<DomainFinalityInclusionProof> {
        for (bucket, rows) in [
            (FinalityBucket::Established, self.established.as_slice()),
            (FinalityBucket::Pending, self.pending.as_slice()),
            (FinalityBucket::Refuted, self.refuted.as_slice()),
        ] {
            if let Ok(idx) = rows.binary_search_by_key(&domain_id, |row| row.domain_id) {
                return build_bucket_inclusion_proof(bucket, rows, idx);
            }
        }
        None
    }

    /// Re-derive the entire certificate from its rows and fail closed if any
    /// bucket root, count, guarantee, ordering, or digest has been tampered with.
    ///
    /// # Errors
    ///
    /// Returns [`FinalityComposeError`] if the underlying rows violate any
    /// composition invariant or if the recomputed certificate differs from `self`.
    pub fn verify_integrity(&self) -> Result<(), FinalityComposeError> {
        let mut all =
            Vec::with_capacity(self.established.len() + self.pending.len() + self.refuted.len());
        all.extend(self.established.iter().cloned());
        all.extend(self.pending.iter().cloned());
        all.extend(self.refuted.iter().cloned());
        let rebuilt = compose(&all)?;
        if rebuilt != *self {
            return Err(FinalityComposeError::IntegrityMismatch);
        }
        Ok(())
    }
}

/// Compose a canonical three-bucket [`GlobalFinalityCertificate`] from
/// state-derived per-domain verdicts.
///
/// Order-independent: entries may be supplied in any order and are sorted
/// canonically by `domain_id` inside each bucket. Non-blocking: `Pending` and
/// `Refuted` domains are recorded in their own Merkle-committed buckets rather
/// than stalling `Established` domains.
///
/// # Errors
///
/// Returns [`FinalityComposeError`] on empty input, capacity overflow,
/// duplicate `domain_id`, conflicting `checkpoint_height`, or an `Established`
/// entry lacking full commitment attestation or positive fault tolerance.
pub fn compose(
    entries: &[DomainFinalityEntry],
) -> Result<GlobalFinalityCertificate, FinalityComposeError> {
    use sha3::{Digest as _, Keccak256};

    let Some(first) = entries.first() else {
        return Err(FinalityComposeError::EmptyDomainSet);
    };
    if entries.len() > MAX_CERTIFICATE_DOMAINS {
        return Err(FinalityComposeError::TooManyDomains);
    }

    let checkpoint_height = first.checkpoint_height;
    let mut seen = std::collections::BTreeSet::new();
    let mut established = Vec::new();
    let mut pending = Vec::new();
    let mut refuted = Vec::new();

    for entry in entries {
        if !seen.insert(entry.domain_id) {
            return Err(FinalityComposeError::DuplicateDomain {
                domain_id: entry.domain_id,
            });
        }
        if entry.checkpoint_height != checkpoint_height {
            return Err(FinalityComposeError::ConflictingCheckpoints {
                expected: checkpoint_height,
                found: entry.checkpoint_height,
            });
        }
        // The row must seal the traces of the proof it attests, in every
        // bucket. This runs before the verdict split so a `Pending` or
        // `Refuted` row cannot smuggle a mismatched trace past compose by
        // being about to leave the Established set.
        if entry.binds != trace_record_binds(&entry.guarantee.attestation)
            || entry.posture_trace != trace_record_quantum_posture(entry.guarantee.quantum_posture)
        {
            return Err(FinalityComposeError::BindsMismatch {
                domain_id: entry.domain_id,
            });
        }
        match entry.verdict {
            FinalityVerdict::Established => {
                if entry.guarantee.attestation != FINALITY_BINDS_ALL
                    || entry.guarantee.fault_tolerance_bps == 0
                {
                    return Err(FinalityComposeError::AttestationUnbound {
                        domain_id: entry.domain_id,
                    });
                }
                established.push(entry.clone());
            }
            FinalityVerdict::Pending { .. } => pending.push(entry.clone()),
            FinalityVerdict::Refuted { .. } => refuted.push(entry.clone()),
        }
    }

    established.sort_by_key(|row| row.domain_id);
    pending.sort_by_key(|row| row.domain_id);
    refuted.sort_by_key(|row| row.domain_id);

    let established_root = compute_bucket_merkle_root(&established);
    let pending_root = compute_bucket_merkle_root(&pending);
    let refuted_root = compute_bucket_merkle_root(&refuted);

    let established_count = u32::try_from(established.len()).unwrap_or(u32::MAX);
    let pending_count = u32::try_from(pending.len()).unwrap_or(u32::MAX);
    let refuted_count = u32::try_from(refuted.len()).unwrap_or(u32::MAX);

    let guarantee = established.first().map(|head| {
        established
            .iter()
            .skip(1)
            .fold(head.guarantee, |acc, row| acc.meet(&row.guarantee))
    });

    let mut header = Keccak256::new();
    header.update(b"BDLM_FINALITY_CERT_V1");
    header.update(checkpoint_height.to_be_bytes());
    header.update(established_count.to_be_bytes());
    header.update(pending_count.to_be_bytes());
    header.update(refuted_count.to_be_bytes());
    header.update(established_root);
    header.update(pending_root);
    header.update(refuted_root);
    match &guarantee {
        Some(g) => {
            header.update([1u8]);
            absorb_guarantee_keccak(&mut header, g);
        }
        None => {
            header.update([0u8]);
        }
    }
    let certificate_digest: [u8; 32] = header.finalize().into();

    Ok(GlobalFinalityCertificate {
        checkpoint_height,
        established,
        pending,
        refuted,
        established_count,
        pending_count,
        refuted_count,
        established_root,
        pending_root,
        refuted_root,
        guarantee,
        certificate_digest,
    })
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
        let g_dag = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::DagCertificate {
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

        let g_hs = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::HotStuffQc {
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
        let g_tm = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::TendermintCommit {
            network: "noble".into(),
            chain_id: "noble-1".into(),
            validator_set_hash: Some([0xAB; 32]),
        });
        assert!(g_tm.slashable_backing);
        assert!(g_tm.attestation.state_root);
        assert!(!g_tm.admits_cross_domain_value());
        assert_eq!(g_tm.quantum_posture, QuantumClass::Classical);
        let g_tm_unpinned =
            FinalityGuarantee::for_external_spec_declared(&AdapterSpec::TendermintCommit {
                network: "noble".into(),
                chain_id: "noble-1".into(),
                validator_set_hash: None,
            });
        assert_eq!(g_tm_unpinned.fault_tolerance_bps, 0);

        let g_eth = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::EthereumSync {
            network: "eth".into(),
            committee: None,
        });
        assert!(!g_eth.admits_cross_domain_value());
        assert_eq!(g_eth.quantum_posture, QuantumClass::Classical);

        let g_zk = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::ZkVm {
            network: "zk".into(),
            program_hash: Some([9; 32]),
            chain_id: Some(77),
        });
        assert_eq!(g_zk.quantum_posture, QuantumClass::Hash);
        assert_eq!(
            g_zk.reversibility,
            FinalityReversibility::CryptographicValidity
        );

        let g_da = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::DataAvailability {
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

        let g_btc_ext = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::BitcoinSpv {
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
        let g_btc_unpinned =
            FinalityGuarantee::for_external_spec_declared(&AdapterSpec::BitcoinSpv {
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
        let empty_da =
            FinalityGuarantee::for_external_spec_declared(&AdapterSpec::DataAvailability {
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
        let short_pq_dag =
            FinalityGuarantee::for_external_spec_declared(&AdapterSpec::DagCertificate {
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
        let dup_dag = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::DagCertificate {
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

        let g_ffg = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::CasperFfg {
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

        let g_my = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::MysticetiDag {
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

        let g_bv = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::BitVmCovenant {
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

    // --- Global certificate composer ---------------------------------------

    fn cert_entry(
        id: u32,
        bps: u16,
        reversibility: FinalityReversibility,
        verdict: FinalityVerdict,
    ) -> DomainFinalityEntry {
        DomainFinalityEntry {
            domain_id: id,
            height: 100 + u64::from(id),
            checkpoint_height: 500,
            state_root: [u8::try_from(id % 251).unwrap_or(0); 32],
            adapter_id: "tendermint-v1".to_owned(),
            adapter_version: 1,
            finality_proof_hash: [0x11; 32],
            guarantee_backing_hash: [0x22; 32],
            bond_atoms: 1_000_000,
            guarantee: FinalityGuarantee {
                reversibility,
                quantum_posture: QuantumClass::Hash,
                attestation: FINALITY_BINDS_ALL,
                slashable_backing: true,
                fault_tolerance_bps: bps,
            },
            binds: trace_record_binds(&FINALITY_BINDS_ALL),
            posture_trace: trace_record_quantum_posture(QuantumClass::Hash),
            verdict,
        }
    }

    #[test]
    fn certificate_covers_1000_domains_with_merkle_inclusion_proofs() {
        let entries: Vec<_> = (0u32..1_000)
            .map(|i| {
                cert_entry(
                    i,
                    3_333 + u16::try_from(i % 100).unwrap_or(0),
                    FinalityReversibility::DeterministicQuorum,
                    FinalityVerdict::Established,
                )
            })
            .collect();
        let cert = compose(&entries).expect("1000 established domains must compose");
        assert_eq!(cert.established_count, 1_000);
        assert_eq!(cert.pending_count, 0);
        assert_eq!(cert.refuted_count, 0);
        assert_eq!(
            cert.guarantee
                .expect("guarantee present")
                .fault_tolerance_bps,
            3_333
        );
        assert_eq!(cert.verify_integrity(), Ok(()));

        for id in [0u32, 1, 500, 998, 999] {
            let proof = cert
                .prove_domain(id)
                .expect("every certified domain yields a Merkle inclusion proof");
            assert_eq!(proof.bucket, FinalityBucket::Established);
            assert!(proof.verify(&cert.established_root));
            assert!(!proof.verify(&cert.pending_root));

            let mut tampered = proof.clone();
            tampered.siblings[0][0] ^= 0x01;
            assert!(!tampered.verify(&cert.established_root));
        }
    }

    #[test]
    fn empty_domain_set_produces_no_certificate() {
        assert_eq!(compose(&[]), Err(FinalityComposeError::EmptyDomainSet));
    }

    #[test]
    fn three_buckets_do_not_block_each_other_and_preserve_three_valued_verdicts() {
        let entries = vec![
            cert_entry(
                10,
                3_333,
                FinalityReversibility::DeterministicQuorum,
                FinalityVerdict::Established,
            ),
            cert_entry(
                20,
                9_999,
                FinalityReversibility::CryptographicValidity,
                FinalityVerdict::Established,
            ),
            cert_entry(
                30,
                3_333,
                FinalityReversibility::DeterministicQuorum,
                FinalityVerdict::Pending {
                    reason: FinalityPendingReason::EvidenceMissing,
                },
            ),
            cert_entry(
                40,
                3_333,
                FinalityReversibility::DeterministicQuorum,
                FinalityVerdict::Refuted { code: 7 },
            ),
        ];
        let cert =
            compose(&entries).expect("pending and refuted domains must not stall certificate");
        assert_eq!(cert.established_count, 2);
        assert_eq!(cert.pending_count, 1);
        assert_eq!(cert.refuted_count, 1);
        assert_eq!(
            cert.guarantee
                .expect("established guarantee")
                .fault_tolerance_bps,
            3_333
        );

        let p_est = cert.prove_domain(10).expect("established proof");
        let p_pend = cert.prove_domain(30).expect("pending proof");
        let p_ref = cert.prove_domain(40).expect("refuted proof");
        assert_eq!(p_est.bucket, FinalityBucket::Established);
        assert_eq!(p_pend.bucket, FinalityBucket::Pending);
        assert_eq!(p_ref.bucket, FinalityBucket::Refuted);
        assert!(p_est.verify(&cert.established_root));
        assert!(p_pend.verify(&cert.pending_root));
        assert!(p_ref.verify(&cert.refuted_root));

        let mut spoofed = p_pend;
        spoofed.bucket = FinalityBucket::Established;
        assert!(!spoofed.verify(&cert.established_root));
    }

    #[test]
    fn pending_only_certificate_has_no_established_guarantee() {
        let entries = vec![cert_entry(
            0,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Pending {
                reason: FinalityPendingReason::BondUnverified,
            },
        )];
        let cert = compose(&entries).expect("pending-only checkpoint still seals");
        assert_eq!(cert.established_count, 0);
        assert_eq!(cert.pending_count, 1);
        assert_eq!(cert.guarantee, None);
        assert_eq!(cert.verify_integrity(), Ok(()));
    }

    #[test]
    fn unbound_established_attestation_cannot_enter_a_certificate() {
        let mut entry = cert_entry(
            0,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Established,
        );
        entry.guarantee.attestation.parent = false;
        // The seal follows the proof: this test measures the attestation
        // check, not the trace check, so the row must stay internally honest.
        entry.binds = trace_record_binds(&entry.guarantee.attestation);
        assert_eq!(
            compose(&[entry]),
            Err(FinalityComposeError::AttestationUnbound { domain_id: 0 })
        );
    }

    #[test]
    fn duplicate_domain_index_across_buckets_is_refused() {
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
                FinalityVerdict::Pending {
                    reason: FinalityPendingReason::EvidenceMissing,
                },
            ),
        ];
        assert_eq!(
            compose(&entries),
            Err(FinalityComposeError::DuplicateDomain { domain_id: 3 })
        );
    }

    #[test]
    fn conflicting_checkpoint_heights_are_refused() {
        let a = cert_entry(
            0,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Established,
        );
        let mut b = cert_entry(
            1,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Established,
        );
        b.checkpoint_height = 501;
        assert_eq!(
            compose(&[a, b]),
            Err(FinalityComposeError::ConflictingCheckpoints {
                expected: 500,
                found: 501,
            })
        );
    }

    #[test]
    fn composition_is_order_independent_across_permutations() {
        let e0 = cert_entry(
            5,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Established,
        );
        let e1 = cert_entry(
            1,
            4_999,
            FinalityReversibility::ProbabilisticWork { confirmations: 6 },
            FinalityVerdict::Established,
        );
        let e2 = cert_entry(
            9,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Pending {
                reason: FinalityPendingReason::EvidenceMissing,
            },
        );
        let cert_a = compose(&[e0.clone(), e1.clone(), e2.clone()]).expect("order a");
        let cert_b = compose(&[e2, e0, e1]).expect("order b");
        assert_eq!(cert_a, cert_b);
        assert_eq!(cert_a.certificate_digest, cert_b.certificate_digest);
    }

    #[test]
    fn every_single_row_field_changes_row_digest() {
        let base = cert_entry(
            7,
            4_999,
            FinalityReversibility::ProbabilisticWork { confirmations: 6 },
            FinalityVerdict::Established,
        );
        let base_digest = base.row_digest();

        let mut cases: Vec<(&str, DomainFinalityEntry)> = Vec::new();
        let mut c = base.clone();
        c.domain_id = 8;
        cases.push(("domain_id", c));
        let mut c = base.clone();
        c.height += 1;
        cases.push(("height", c));
        let mut c = base.clone();
        c.checkpoint_height += 1;
        cases.push(("checkpoint_height", c));
        let mut c = base.clone();
        c.state_root[0] ^= 1;
        cases.push(("state_root", c));
        let mut c = base.clone();
        c.adapter_id = "ethereum-sync-v1".to_owned();
        cases.push(("adapter_id", c));
        let mut c = base.clone();
        c.adapter_version = 2;
        cases.push(("adapter_version", c));
        let mut c = base.clone();
        c.finality_proof_hash[0] ^= 1;
        cases.push(("finality_proof_hash", c));
        let mut c = base.clone();
        c.guarantee_backing_hash[0] ^= 1;
        cases.push(("guarantee_backing_hash", c));
        let mut c = base.clone();
        c.bond_atoms += 1;
        cases.push(("bond_atoms", c));
        let mut c = base.clone();
        c.guarantee.reversibility = FinalityReversibility::ProbabilisticWork { confirmations: 100 };
        cases.push(("reversibility.confirmations", c));
        let mut c = base.clone();
        c.guarantee.reversibility =
            FinalityReversibility::DataAvailabilitySampled { min_samples: 75 };
        cases.push(("reversibility.da_samples", c));
        let mut c = base.clone();
        c.guarantee.quantum_posture = QuantumClass::Classical;
        cases.push(("quantum_posture", c));
        let mut c = base.clone();
        c.guarantee.attestation.event_root = false;
        cases.push(("attestation.event_root", c));
        let mut c = base.clone();
        c.guarantee.slashable_backing = false;
        cases.push(("slashable_backing", c));
        let mut c = base.clone();
        c.guarantee.fault_tolerance_bps = 3_333;
        cases.push(("fault_tolerance_bps", c));
        let mut c = base.clone();
        c.verdict = FinalityVerdict::Refuted { code: 1 };
        cases.push(("verdict.refuted_1", c));
        let mut c = base.clone();
        c.verdict = FinalityVerdict::Refuted { code: 2 };
        cases.push(("verdict.refuted_2", c));
        let mut c = base.clone();
        c.verdict = FinalityVerdict::Pending {
            reason: FinalityPendingReason::EvidenceMissing,
        };
        cases.push(("verdict.pending_missing", c));
        let mut c = base.clone();
        c.verdict = FinalityVerdict::Pending {
            reason: FinalityPendingReason::BondUnverified,
        };
        cases.push(("verdict.pending_bond", c));

        for (field, mutated) in &cases {
            assert_ne!(
                mutated.row_digest(),
                base_digest,
                "mutating {field} must change DomainFinalityEntry::row_digest"
            );
        }
        let r1 = cases
            .iter()
            .find(|(n, _)| *n == "verdict.refuted_1")
            .expect("r1")
            .1
            .row_digest();
        let r2 = cases
            .iter()
            .find(|(n, _)| *n == "verdict.refuted_2")
            .expect("r2")
            .1
            .row_digest();
        assert_ne!(r1, r2);
        let p1 = cases
            .iter()
            .find(|(n, _)| *n == "verdict.pending_missing")
            .expect("p1")
            .1
            .row_digest();
        let p2 = cases
            .iter()
            .find(|(n, _)| *n == "verdict.pending_bond")
            .expect("p2")
            .1
            .row_digest();
        assert_ne!(p1, p2);
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
        let guarantee = cert.guarantee.expect("established guarantee");
        assert_eq!(guarantee.fault_tolerance_bps, 4_999);
        assert_eq!(
            guarantee.reversibility,
            FinalityReversibility::ProbabilisticWork { confirmations: 6 }
        );
    }

    #[test]
    fn tampered_certificate_fails_integrity_verification() {
        let entries = vec![cert_entry(
            0,
            3_333,
            FinalityReversibility::DeterministicQuorum,
            FinalityVerdict::Established,
        )];
        let mut cert = compose(&entries).expect("compose");
        cert.established_count = 2;
        assert_eq!(
            cert.verify_integrity(),
            Err(FinalityComposeError::IntegrityMismatch)
        );
    }

    #[test]
    fn more_than_max_certificate_domains_is_refused() {
        let entries: Vec<_> = (0u32..u32::try_from(MAX_CERTIFICATE_DOMAINS + 1).expect("fits u32"))
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
    fn guarantee_label_is_deterministic_and_float_free() {
        let hub = FinalityGuarantee::settlement_hub();
        assert_eq!(
            hub.label(),
            "deterministic-quorum|lattice|slashable|ft=3333bps"
        );
    }

    #[test]
    fn a_forged_leaf_count_cannot_reopen_a_bucket_root() {
        let entries: Vec<_> = (0u32..3)
            .map(|id| {
                cert_entry(
                    id,
                    3_333,
                    FinalityReversibility::DeterministicQuorum,
                    FinalityVerdict::Established,
                )
            })
            .collect();
        let cert = compose(&entries).expect("three established domains compose");
        let honest = cert.prove_domain(2).expect("honest tail proof");
        assert!(honest.verify(&cert.established_root));

        // The three-leaf tree duplicates its tail: root = node(node(l0, l1),
        // node(l2, l2)). A forger re-declares the bucket as four leaves and
        // presents the same tail row a second time at index 3, with the
        // duplicated tail leaf itself as the level-0 sibling.
        let tail_leaf = keccak_cert_leaf(&cert.established[2].row_digest());
        let left_pair = keccak_cert_node(
            &keccak_cert_leaf(&cert.established[0].row_digest()),
            &keccak_cert_leaf(&cert.established[1].row_digest()),
        );
        let forged = DomainFinalityInclusionProof {
            bucket: FinalityBucket::Established,
            leaf_index: 3,
            leaf_count: 4,
            entry: cert.established[2].clone(),
            siblings: vec![tail_leaf, left_pair],
        };
        assert!(
            !forged.verify(&cert.established_root),
            "a duplicated tail must not verify as a second position under an inflated leaf count"
        );
    }
}

/// A registered external domain's guarantee must reflect the backing the
/// domain's ACCEPTED attestations actually carry, not only what its
/// registration spec promised. The spec is a declaration made before any
/// evidence existed; the accepted attestation is the fact.
#[cfg(test)]
mod external_backing_tests {
    use super::*;
    use crate::cross_domain::external::da_sampling::{DaCommitteeMember, PinnedDaCommittee};
    use crate::cross_domain::external::spec::{ProofSystem, SecurityBacking};
    use crate::crypto::facts::ObservedScheme;
    use crate::crypto::scheme::SchemeId;

    /// A governance-pinned, fully populated DA committee: the registration
    /// state in which the spec alone promises a BFT-grade guarantee.
    fn pinned_da_spec() -> AdapterSpec {
        AdapterSpec::DataAvailability {
            network: "da-net".into(),
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
        }
    }

    /// The spec-only derivation is what the tree does today: it reports a
    /// BFT-grade fault-tolerance bound from the registration alone, with no
    /// evidence of any accepted attestation behind it.
    ///
    /// This assertion is the RED half of the pair below: it pins the current
    /// (over-optimistic) behaviour so the change is measurable.
    #[test]
    fn the_spec_only_derivation_claims_a_bft_grade_bound_with_no_accepted_attestation() {
        let g = FinalityGuarantee::for_external_spec_declared(&pinned_da_spec());
        assert_eq!(g.fault_tolerance_bps, BFT_FAULT_TOLERANCE_BPS);
        assert!(g.slashable_backing);
    }

    /// A domain that has never produced an accepted attestation has NO
    /// backing. Its guarantee must say so: zero fault tolerance, and no
    /// cross-domain value admitted.
    ///
    /// RED today: the spec-only derivation has no way to see the attestation,
    /// so the only way to express "no accepted attestation" does not exist yet.
    #[test]
    fn a_domain_with_no_accepted_attestation_has_no_fault_tolerance() {
        let g = FinalityGuarantee::for_external_spec_with_backing(&pinned_da_spec(), None);
        assert_eq!(g.fault_tolerance_bps, 0);
        assert!(!g.slashable_backing);
        assert!(!g.admits_cross_domain_value());
    }

    /// An accepted attestation whose backing is an unslashable authority set
    /// cannot carry the BFT fault-tolerance bound the registration promised.
    /// The guarantee must be reduced to zero, not carried over.
    #[test]
    fn an_unslashable_authority_backing_cancels_the_promised_fault_tolerance() {
        let g = FinalityGuarantee::for_external_spec_with_backing(
            &pinned_da_spec(),
            Some(&SecurityBacking::Authority { count: 3 }),
        );
        assert_eq!(g.fault_tolerance_bps, 0);
        assert!(!g.slashable_backing);
        assert!(!g.admits_cross_domain_value());
    }

    /// A signature set the domain itself reported as unslashable (an
    /// Ethereum sync committee is the live example) is not slashable economic
    /// security, whatever the registration promised.
    #[test]
    fn an_unslashable_signature_set_cancels_the_promised_fault_tolerance() {
        let g = FinalityGuarantee::for_external_spec_with_backing(
            &pinned_da_spec(),
            Some(&SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG),
                signers: 64,
                required: 32,
                total_weight: 1_000,
                slashable: false,
            }),
        );
        assert_eq!(g.fault_tolerance_bps, 0);
        assert!(!g.slashable_backing);
        assert!(!g.admits_cross_domain_value());
    }

    /// A slashable signature set DOES carry the promised bound: the accepted
    /// attestation confirms what the registration declared.
    #[test]
    fn a_slashable_signature_backing_keeps_the_promised_fault_tolerance() {
        let g = FinalityGuarantee::for_external_spec_with_backing(
            &pinned_da_spec(),
            Some(&SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ED25519),
                signers: 64,
                required: 32,
                total_weight: 1_000,
                slashable: true,
            }),
        );
        assert_eq!(g.fault_tolerance_bps, BFT_FAULT_TOLERANCE_BPS);
        assert!(g.slashable_backing);
    }

    /// The rule that makes the two halves one: the observed backing may only
    /// ever REDUCE the promised bound. A backing stronger than the
    /// registration promised must not inflate it.
    #[test]
    fn the_observed_backing_can_only_reduce_the_promised_bound() {
        let spec = AdapterSpec::BitcoinSpv {
            network: "btc".into(),
            anchor: Some(
                crate::cross_domain::external::bitcoin_spv::PinnedBitcoinAnchor {
                    height: 840_000,
                    block_hash: [0x11; 32],
                    bits: 0x1703_4219,
                },
            ),
        };
        let promised = FinalityGuarantee::for_external_spec_declared(&spec);
        assert_eq!(promised.fault_tolerance_bps, POW_FAULT_TOLERANCE_BPS);

        // A ZK validity proof is stronger than the promised PoW bound.
        let observed = FinalityGuarantee::for_external_spec_with_backing(
            &spec,
            Some(&SecurityBacking::Zk {
                system: ProofSystem::Stark,
                public_inputs_digest: [0x22; 32],
            }),
        );
        assert_eq!(
            observed.fault_tolerance_bps, promised.fault_tolerance_bps,
            "an observed backing stronger than the registration must not inflate the bound"
        );
    }

    /// A `PoW` domain whose accepted attestation reports a work claim below
    /// the Tier-1 threshold is a regtest- or toy-scale chain: two hashes cost
    /// well under a microsecond, so the claim carries no adversarial cost.
    /// It must not keep the deep-`PoW` value guarantee the registration
    /// promised.
    ///
    /// A work claim of ZERO is stronger still: it is not a weak chain, it is
    /// no work at all, so the fault-tolerance bound itself is zero.
    #[test]
    fn a_sub_tier1_work_backing_cancels_the_promised_pow_fault_tolerance() {
        let spec = AdapterSpec::BitcoinSpv {
            network: "btc".into(),
            anchor: Some(
                crate::cross_domain::external::bitcoin_spv::PinnedBitcoinAnchor {
                    height: 840_000,
                    block_hash: [0x11; 32],
                    bits: 0x1703_4219,
                },
            ),
        };
        let promised = FinalityGuarantee::for_external_spec_declared(&spec);
        assert_eq!(promised.fault_tolerance_bps, POW_FAULT_TOLERANCE_BPS);

        let toy = FinalityGuarantee::for_external_spec_with_backing(
            &spec,
            Some(&SecurityBacking::Work {
                difficulty_bits: MIN_TIER1_WORK_BITS - 1,
            }),
        );
        assert_eq!(
            toy.fault_tolerance_bps, 0,
            "a work claim below the Tier-1 threshold must not keep a deep-PoW bound"
        );
        assert!(!toy.admits_cross_domain_value());

        let none = FinalityGuarantee::for_external_spec_with_backing(
            &spec,
            Some(&SecurityBacking::Work { difficulty_bits: 0 }),
        );
        assert_eq!(none.fault_tolerance_bps, 0);
        assert!(!none.admits_cross_domain_value());
    }

    /// An Ethereum sync committee is unslashable BY DESIGN and still carries
    /// a BFT-grade inclusion bound. Zeroing its fault tolerance would refuse a
    /// perfectly valid inclusion proof (`source_admits_tx_inclusion` is
    /// `tx_root && fault_tolerance_bps > 0`), so an unslashable signature set
    /// with a real quorum must keep its bound.
    ///
    /// The two outcomes are pinned SEPARATELY: the inclusion proof survives,
    /// and the value transfer is still refused.
    #[test]
    fn an_unslashable_quorum_keeps_inclusion_but_still_refuses_value_transfer() {
        let spec = AdapterSpec::EthereumSync {
            network: "eth".into(),
            committee: Some(crate::cross_domain::external::ethereum::PinnedCommittee {
                period: 1,
                aggregate_pubkey: vec![0x33; 96],
                next_committee_root: [0x44; 32],
            }),
        };
        let promised = FinalityGuarantee::for_external_spec_declared(&spec);
        assert!(
            !promised.slashable_backing,
            "an Ethereum sync committee is never slashable-backed"
        );

        let observed = FinalityGuarantee::for_external_spec_with_backing(
            &spec,
            Some(&SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG),
                signers: 64,
                required: 32,
                total_weight: 1_000,
                slashable: false,
            }),
        );
        assert_eq!(
            observed.fault_tolerance_bps, promised.fault_tolerance_bps,
            "an unslashable quorum with a real threshold must keep its inclusion bound"
        );
        assert!(
            !observed.admits_cross_domain_value(),
            "an unslashable quorum must still refuse cross-domain value transfer"
        );
    }

    /// A degenerate quorum is not a quorum: `required == 0`, fewer signers
    /// than the threshold, or zero total weight all mean the attestation
    /// proves nothing, whatever the registration promised.
    #[test]
    fn a_degenerate_quorum_cancels_the_promised_fault_tolerance() {
        for (signers, required, weight) in [(64u64, 0u64, 1_000u128), (64, 32, 0)] {
            let g = FinalityGuarantee::for_external_spec_with_backing(
                &pinned_da_spec(),
                Some(&SecurityBacking::SignatureSet {
                    scheme: ObservedScheme::Scheme(SchemeId::ED25519),
                    signers,
                    required,
                    total_weight: weight,
                    slashable: true,
                }),
            );
            assert_eq!(
                g.fault_tolerance_bps, 0,
                "a degenerate quorum (signers={signers}, required={required}, weight={weight}) \
                 must not keep the promised bound"
            );
            assert!(!g.slashable_backing);
            assert!(!g.admits_cross_domain_value());
        }
    }

    /// The single-canonical-path rule, checked at the SOURCE level.
    ///
    /// The spec-only derivation is module-private, so no other module can call
    /// it; this test locks that down against a future edit that re-widens it
    /// or adds a second spec-only entry point. The production settlement
    /// surface must reach the external guarantee ONLY through the
    /// observed-backing path.
    #[test]
    fn a_settlement_write_path_refuses_a_spec_only_guarantee() {
        let sources: [(&str, &str); 4] = [
            (
                "src/settlement/universal_finality.rs",
                include_str!("universal_finality.rs"),
            ),
            ("src/rpc/server.rs", include_str!("../rpc/server.rs")),
            ("src/settlement/domains.rs", include_str!("domains.rs")),
            (
                "src/unification/mod.rs",
                include_str!("../unification/mod.rs"),
            ),
        ];
        for (path, source) in sources {
            let mut outside = Vec::new();
            for (at, _) in source.match_indices("for_external_spec_declared") {
                let is_call = source[at..].starts_with("for_external_spec_declared(");
                if is_call && path != "src/settlement/universal_finality.rs" {
                    outside.push(source[..at].lines().count() + 1);
                }
            }
            assert!(
                outside.is_empty(),
                "{path} calls the spec-only derivation at line(s) {outside:?}; \
                 the external guarantee must be derived from the observed backing only"
            );
        }
    }

    /// Babylon / BTC-restaking EOTS: a valid pinned epoch-key table is
    /// economically slashable but carries no BFT fault tolerance, so it admits
    /// cross-domain value only under the observed-backing path and admits
    /// nothing at all without the pin. An epoch-key table with post-quantum
    /// keys for every epoch moves the quantum posture to `Lattice`; one
    /// without them stays `Classical`.
    #[test]
    fn babylon_eots_pinned_table_is_slashable_without_fault_tolerance() {
        use crate::cross_domain::external::babylon_eots::{test_support, EotsPublicKey};
        use crate::cross_domain::external::AdapterSpec;

        // No pin: the closed admission state. Nothing attested, nothing
        // admitted, no posture claimed.
        let closed = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::BabylonEots {
            network: test_support::NETWORK.to_string(),
            pinned: None,
        });
        assert!(!closed.attestation.state_root);
        assert!(!closed.slashable_backing);
        assert!(!closed.admits_cross_domain_value());
        assert_eq!(closed.fault_tolerance_bps, 0);
        assert_eq!(closed.quantum_posture, QuantumClass::Classical);
        assert!(matches!(
            closed.reversibility,
            FinalityReversibility::DeterministicQuorum
        ));

        // A pinned classical table: the state root is attested by the pinned
        // anchor, the backing is slashable, and there is no BFT bound to
        // promise - a single EOTS provider is not a Byzantine quorum.
        let classical = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::BabylonEots {
            network: test_support::NETWORK.to_string(),
            pinned: Some(test_support::pinned()),
        });
        assert!(classical.attestation.state_root);
        assert!(!classical.attestation.tx_root);
        assert!(!classical.attestation.event_root);
        assert!(!classical.attestation.parent);
        assert!(classical.slashable_backing);
        assert_eq!(classical.fault_tolerance_bps, 0);
        assert_eq!(classical.quantum_posture, QuantumClass::Classical);

        // The same table with a PQ key for the epoch the classical key
        // belongs to moves the posture to `Lattice` without changing the
        // backing shape.
        let mut with_pq = test_support::pinned();
        with_pq
            .epoch_pq_keys
            .push((test_support::EPOCH, vec![0x42; 1_952]));
        let lattice = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::BabylonEots {
            network: test_support::NETWORK.to_string(),
            pinned: Some(with_pq),
        });
        assert_eq!(lattice.quantum_posture, QuantumClass::Lattice);
        assert!(lattice.slashable_backing);

        // A pinned table whose keys are not on the curve is not a valid pin:
        // it does not attest anything, so the posture claims nothing either.
        let mut malformed = test_support::pinned();
        malformed
            .epoch_keys
            .push((test_support::EPOCH + 1, EotsPublicKey { x_only: [0; 32] }));
        assert!(malformed.validate().is_err());
        let broken = FinalityGuarantee::for_external_spec_declared(&AdapterSpec::BabylonEots {
            network: test_support::NETWORK.to_string(),
            pinned: Some(malformed),
        });
        assert!(!broken.attestation.state_root);
        assert!(!broken.slashable_backing);
        assert!(!broken.admits_cross_domain_value());
    }
}
