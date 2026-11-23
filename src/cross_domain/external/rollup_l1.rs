//! Parent-L1 Merkle-Patricia-Trie rollup settlement reader, weakest-link
//! finality composition, and independent data-availability verdict engine.
//!
//! WIRING: wired through `IntakeState::{register_rollup_domain, submit_rollup_state_proof, certified_rollup_row}`
//! and `ExternalDomainTx::{RegisterRollup, SubmitRollupStateProof}`.
//!
//! # Architecture
//!
//! A rollup is modeled as an external settlement domain anchored to an
//! already-registered L1 `parent_domain` in [`super::intake::IntakeState`]:
//!
//! 1. **Zero-extra-trust L1 MPT finality reading**: rollup contract existence,
//!    bytecode pin (`code_hash`), proven L2 `state_root`, proven L2 batch
//!    height, and proof-model auxiliary slots (optimistic proposal timestamp,
//!    validity verifier commitment, or multi-prover attestation bitmap) are
//!    verified directly against the finalized L1 `state_root` via
//!    [`crate::cross_domain::evm::account_proof::verify_account`] and
//!    [`crate::cross_domain::evm::account_proof::verify_storage`].
//! 2. **Weakest-link `FinalityGuarantee` composition (`meet`)**: a rollup's
//!    effective finality guarantee is `parent_l1_finality.meet(&rollup_proof_finality)`.
//!    An optimistic rollup root that is still inside its fault-proof challenge
//!    window (`l1_finalized_at - proposal_timestamp < challenge_window_secs`)
//!    or a multi-prover root below quorum is **not** `Established`: its
//!    composed guarantee carries `fault_tolerance_bps == 0`,
//!    `admits_cross_domain_value() == false`, and zero value-routing ceiling.
//! 3. **Separate finality and data-availability verdicts**: a rollup binds
//!    either to its parent L1 (`RollupDaBinding::ParentL1`) or to a live
//!    external `da-sampling-v1` domain (`RollupDaBinding::ExternalDaDomain`).
//!    Every certified row emits two independent verdicts
//!    ([`RollupFinalityVerdict`] and [`RollupDaVerdict`]), and cross-domain
//!    value routing is admitted only when **both** verdicts are established.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::evm::account_proof::{self, AccountProofError};
use crate::cross_domain::evm::mpt;
use crate::cross_domain::external::intake::AdapterSpec;
use crate::cross_domain::external::prover::DomainEconomics;
use crate::cross_domain::external::spec::DomainKey;
use crate::crypto::facts::QuantumClass;
use crate::settlement::domains::CommitmentAttestation;
use crate::settlement::universal_finality::{
    EconomicSecurityBound, FinalityGuarantee, FinalityReversibility,
};

/// Minimum optimistic fault-proof challenge window (seconds) accepted for an
/// L1-settled optimistic rollup. Mainnet OP-Stack / Arbitrum deployments use
/// `604_800` seconds (7 days); `60` seconds is the protocol floor preventing
/// zero-window optimistic registrations.
pub const MIN_ROLLUP_CHALLENGE_WINDOW_SECS: u64 = 60;

/// Maximum UTF-8 byte length of a rollup network identifier.
pub(crate) const MAX_ROLLUP_NETWORK_BYTES: usize = 64;

/// Maximum number of heterogeneous provers represented in an on-chain L1
/// attestation bitmap slot.
pub(crate) const MAX_ROLLUP_BITMAP_PROVERS: u8 = 32;

/// How the L1 settlement contract authenticates L2 state roots before/after
/// writing `state_root_slot`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RollupProofModel {
    /// Optimistic rollup (OP-Stack / fault-dispute game): the L1 contract
    /// records `proposal_timestamp_slot` when the output root is proposed, and
    /// the root becomes final only once `l1_finalized_at - proposal_timestamp >= challenge_window_secs`.
    OptimisticFaultProof {
        proposal_timestamp_slot: [u8; 32],
        challenge_window_secs: u64,
    },
    /// Validity / ZK rollup (STARK / SNARK verified by the L1 contract prior to
    /// updating `state_root_slot`). Optionally pins an on-chain storage slot
    /// holding the active verifier program / circuit commitment.
    ValidityProof {
        verifier_program_commitment: [u8; 32],
        program_commitment_slot: Option<[u8; 32]>,
        quantum_posture: QuantumClass,
    },
    /// Multi-prover rollup (e.g., ZK + TEE + fault-prover quorum recorded as a
    /// bitmask in `attestation_bitmap_slot` on the L1 settlement contract).
    MultiProver {
        required_provers: u8,
        total_provers: u8,
        attestation_bitmap_slot: [u8; 32],
        quantum_posture: QuantumClass,
    },
}

/// Where the rollup publishes transaction / state-diff data required to
/// reconstruct L2 state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RollupDaBinding {
    /// State diffs or batches are posted directly to `parent_domain` L1
    /// calldata / blobs; L1 finality establishes DA for the batch.
    ParentL1,
    /// Batch data is posted to a separate registered `da-sampling-v1` external
    /// domain whose sampling attestation is checked independently.
    ExternalDaDomain {
        da_domain: DomainKey,
        min_samples: u16,
    },
}

/// Immutable consensus specification of an L1-settled rollup domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupDomainSpec {
    pub rollup_network: String,
    pub parent_domain: DomainKey,
    pub l1_rollup_contract: [u8; 20],
    pub expected_code_hash: Option<[u8; 32]>,
    pub state_root_slot: [u8; 32],
    pub batch_height_slot: [u8; 32],
    pub proof_model: RollupProofModel,
    pub da_binding: RollupDaBinding,
}

impl RollupDomainSpec {
    /// Canonical domain-separated digest covering every field of the rollup
    /// settlement specification.
    #[must_use]
    pub fn spec_digest(&self) -> [u8; 32] {
        let code_flag = [u8::from(self.expected_code_hash.is_some())];
        let code_bytes = self.expected_code_hash.unwrap_or([0u8; 32]);
        let (model_tag, model_a, model_b, model_c): ([u8; 1], [u8; 32], [u8; 8], [u8; 4]) =
            match &self.proof_model {
                RollupProofModel::OptimisticFaultProof {
                    proposal_timestamp_slot,
                    challenge_window_secs,
                } => (
                    [0u8],
                    *proposal_timestamp_slot,
                    challenge_window_secs.to_le_bytes(),
                    [0u8; 4],
                ),
                RollupProofModel::ValidityProof {
                    verifier_program_commitment,
                    program_commitment_slot,
                    quantum_posture,
                } => {
                    let q = quantum_tag(*quantum_posture);
                    (
                        [1u8],
                        *verifier_program_commitment,
                        u64::from(program_commitment_slot.is_some()).to_le_bytes(),
                        [q, 0u8, 0u8, 0u8],
                    )
                }
                RollupProofModel::MultiProver {
                    required_provers,
                    total_provers,
                    attestation_bitmap_slot,
                    quantum_posture,
                } => (
                    [2u8],
                    *attestation_bitmap_slot,
                    0u64.to_le_bytes(),
                    [
                        *required_provers,
                        *total_provers,
                        quantum_tag(*quantum_posture),
                        0u8,
                    ],
                ),
            };
        let prog_slot_bytes = match &self.proof_model {
            RollupProofModel::ValidityProof {
                program_commitment_slot: Some(slot),
                ..
            } => *slot,
            _ => [0u8; 32],
        };
        let (da_tag, da_key, da_samples): ([u8; 1], [u8; 32], [u8; 2]) = match &self.da_binding {
            RollupDaBinding::ParentL1 => ([0u8], [0u8; 32], [0u8; 2]),
            RollupDaBinding::ExternalDaDomain {
                da_domain,
                min_samples,
            } => ([1u8], da_domain.0, min_samples.to_le_bytes()),
        };
        hash_fields_bytes(&[
            b"BDLM_ROLLUP_SPEC_V1",
            self.rollup_network.as_bytes(),
            &self.parent_domain.0,
            &self.l1_rollup_contract,
            &code_flag,
            &code_bytes,
            &self.state_root_slot,
            &self.batch_height_slot,
            &model_tag,
            &model_a,
            &model_b,
            &model_c,
            &prog_slot_bytes,
            &da_tag,
            &da_key,
            &da_samples,
        ])
    }

    /// Derives the canonical [`DomainKey`] for this rollup domain.
    #[must_use]
    pub fn domain_key(&self) -> DomainKey {
        DomainKey::from_rollup_spec(
            &self.parent_domain,
            &self.rollup_network,
            &self.spec_digest(),
        )
    }

    /// Validates static structural invariants before registration or proof verification.
    ///
    /// # Errors
    ///
    /// Returns [`RollupVerifyError`] when any address, slot, challenge window,
    /// prover quorum, or DA binding parameter is malformed.
    pub fn validate(&self) -> Result<(), RollupVerifyError> {
        if self.rollup_network.is_empty()
            || self.rollup_network.len() > MAX_ROLLUP_NETWORK_BYTES
            || !self
                .rollup_network
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(RollupVerifyError::InvalidNetworkName);
        }
        if self.parent_domain.0 == [0u8; 32] {
            return Err(RollupVerifyError::ZeroParentDomain);
        }
        if self.l1_rollup_contract == [0u8; 20] {
            return Err(RollupVerifyError::ZeroRollupContract);
        }
        if let Some(expected) = &self.expected_code_hash {
            if *expected == [0u8; 32] || bool::from(expected.ct_eq(&empty_code_hash())) {
                return Err(RollupVerifyError::EoaOrEmptyCodeHash);
            }
        }
        if self.state_root_slot == self.batch_height_slot {
            return Err(RollupVerifyError::DuplicateStorageSlots);
        }
        match &self.proof_model {
            RollupProofModel::OptimisticFaultProof {
                proposal_timestamp_slot,
                challenge_window_secs,
            } => {
                if *challenge_window_secs < MIN_ROLLUP_CHALLENGE_WINDOW_SECS {
                    return Err(RollupVerifyError::ChallengeWindowTooShort {
                        provided_secs: *challenge_window_secs,
                        min_secs: MIN_ROLLUP_CHALLENGE_WINDOW_SECS,
                    });
                }
                if *proposal_timestamp_slot == self.state_root_slot
                    || *proposal_timestamp_slot == self.batch_height_slot
                {
                    return Err(RollupVerifyError::DuplicateStorageSlots);
                }
            }
            RollupProofModel::ValidityProof {
                verifier_program_commitment,
                program_commitment_slot,
                ..
            } => {
                if *verifier_program_commitment == [0u8; 32] {
                    return Err(RollupVerifyError::ZeroProgramCommitment);
                }
                if let Some(slot) = program_commitment_slot {
                    if *slot == self.state_root_slot || *slot == self.batch_height_slot {
                        return Err(RollupVerifyError::DuplicateStorageSlots);
                    }
                }
            }
            RollupProofModel::MultiProver {
                required_provers,
                total_provers,
                attestation_bitmap_slot,
                ..
            } => {
                if *required_provers < 2
                    || *required_provers > *total_provers
                    || *total_provers > MAX_ROLLUP_BITMAP_PROVERS
                {
                    return Err(RollupVerifyError::InvalidMultiProverQuorum {
                        required: *required_provers,
                        total: *total_provers,
                    });
                }
                if *attestation_bitmap_slot == self.state_root_slot
                    || *attestation_bitmap_slot == self.batch_height_slot
                {
                    return Err(RollupVerifyError::DuplicateStorageSlots);
                }
            }
        }
        if let RollupDaBinding::ExternalDaDomain {
            da_domain,
            min_samples,
        } = &self.da_binding
        {
            if da_domain.0 == [0u8; 32] || *da_domain == self.parent_domain || *min_samples == 0 {
                return Err(RollupVerifyError::InvalidDaBinding);
            }
        }
        Ok(())
    }
}

/// Signed in-block registration payload for an L1-settled rollup domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupRegistrationRequest {
    pub spec: RollupDomainSpec,
    pub economics: DomainEconomics,
    pub bond_atoms: u128,
    pub poster: Address,
}

/// Signed in-block Ethereum MPT account + storage proof submission anchoring a
/// rollup batch to an already-finalized `l1_height` on `parent_domain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupStateProofSubmission {
    pub rollup_domain: DomainKey,
    pub l1_height: u64,
    pub account_proof: Vec<Vec<u8>>,
    pub state_root_proof: Vec<Vec<u8>>,
    pub batch_height_proof: Vec<Vec<u8>>,
    pub auxiliary_slot_proof: Vec<Vec<u8>>,
    pub da_height: Option<u64>,
    pub submitter: Address,
}

/// Finality verdict of a rollup batch independent of data availability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RollupFinalityVerdict {
    /// Finality is established: L1 is finalized and either a validity proof,
    /// a matured optimistic challenge window, or a multi-prover quorum succeeded.
    Established {
        l1_height: u64,
        l2_height: u64,
        state_root: [u8; 32],
    },
    /// Optimistic rollup output root is proven on L1, but still inside its
    /// dispute/challenge window (`remaining_secs > 0`): **not established** and
    /// carries zero value-transfer capacity.
    PendingChallengeWindow {
        l1_height: u64,
        l2_height: u64,
        state_root: [u8; 32],
        proposal_timestamp: u64,
        remaining_secs: u64,
    },
    /// Multi-prover rollup root is recorded on L1, but fewer than
    /// `required_provers` distinct provers have attested in the bitmap slot.
    PendingMultiProverQuorum {
        l1_height: u64,
        l2_height: u64,
        state_root: [u8; 32],
        attested_provers: u8,
        required_provers: u8,
    },
}

impl RollupFinalityVerdict {
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self, Self::Established { .. })
    }
}

/// Data-availability verdict of a rollup batch independent of state-transition finality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RollupDaVerdict {
    /// Batch data is published on `parent_domain` L1 and covered by L1 finality.
    EstablishedOnParentL1 {
        parent_domain: DomainKey,
        l1_height: u64,
    },
    /// Batch data is attested on the bound external `da-sampling-v1` domain
    /// with at least `min_samples` verified erasure-coded shares.
    EstablishedExternalDa {
        da_domain: DomainKey,
        da_height: u64,
        data_root: [u8; 32],
        min_samples: u16,
        da_guarantee: FinalityGuarantee,
    },
    /// External DA sampling attestation is missing, unverified, or below
    /// `min_samples`; blocks cross-domain value routing even if state-transition
    /// finality is already `Established`.
    PendingExternalDa {
        da_domain: DomainKey,
        reason: String,
    },
}

impl RollupDaVerdict {
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(
            self,
            Self::EstablishedOnParentL1 { .. } | Self::EstablishedExternalDa { .. }
        )
    }
}

/// Input snapshot of the bound external DA domain at proof verification time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedExternalDaSnapshot {
    pub da_domain: DomainKey,
    pub da_height: u64,
    pub data_root: [u8; 32],
    pub attested_min_samples: u16,
    pub da_guarantee: FinalityGuarantee,
}

/// Input snapshot of the finalized parent L1 block against which the rollup's
/// Ethereum MPT proofs are verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FinalizedParentL1Snapshot {
    pub parent_domain: DomainKey,
    pub l1_height: u64,
    pub l1_state_root: [u8; 32],
    pub l1_finalized_at: u64,
    pub parent_finality: FinalityGuarantee,
    pub parent_live_ceiling_atoms: u128,
}

/// Certified settlement row for a rollup batch carrying both the `meet`-composed
/// [`FinalityGuarantee`] and the two independent verdicts (`finality` and `da`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertifiedRollupRow {
    pub rollup_domain: DomainKey,
    pub parent_domain: DomainKey,
    pub l1_height: u64,
    pub l2_height: u64,
    pub state_root: [u8; 32],
    pub parent_l1_finality: FinalityGuarantee,
    pub rollup_proof_finality: FinalityGuarantee,
    pub composed_finality: FinalityGuarantee,
    pub finality_verdict: RollupFinalityVerdict,
    pub da_verdict: RollupDaVerdict,
    pub economic_bound: EconomicSecurityBound,
    pub value_routing_ceiling_atoms: u128,
}

impl CertifiedRollupRow {
    /// True if and only if **both** state-transition finality and data
    /// availability are independently established.
    #[must_use]
    pub const fn both_established(&self) -> bool {
        self.finality_verdict.is_established() && self.da_verdict.is_established()
    }

    /// Deterministic dual-verdict string explicitly distinguishing the finality
    /// verdict from the data-availability verdict.
    #[must_use]
    pub fn verdict_summary(&self) -> String {
        let fin = match &self.finality_verdict {
            RollupFinalityVerdict::Established { .. } => "finality=established",
            RollupFinalityVerdict::PendingChallengeWindow { .. } => {
                "finality=pending-challenge-window"
            }
            RollupFinalityVerdict::PendingMultiProverQuorum { .. } => {
                "finality=pending-multiprover-quorum"
            }
        };
        let da = match &self.da_verdict {
            RollupDaVerdict::EstablishedOnParentL1 { .. } => "da=established-parent-l1",
            RollupDaVerdict::EstablishedExternalDa { .. } => "da=established-sampled",
            RollupDaVerdict::PendingExternalDa { .. } => "da=pending",
        };
        format!("{fin}|{da}")
    }

    /// Domain-separated cryptographic digest committing to all fields of this
    /// certified rollup settlement row.
    #[must_use]
    pub fn row_digest(&self) -> [u8; 32] {
        let l1_h = self.l1_height.to_le_bytes();
        let l2_h = self.l2_height.to_le_bytes();
        let fin_est = [u8::from(self.finality_verdict.is_established())];
        let da_est = [u8::from(self.da_verdict.is_established())];
        let ceil = self.value_routing_ceiling_atoms.to_le_bytes();
        let bond = self.economic_bound.slashable_bond_atoms.to_le_bytes();
        let e_route = self.economic_bound.routing_ceiling_atoms.to_le_bytes();
        let e_corr = self.economic_bound.corruption_cost_atoms.to_le_bytes();
        let e_safe = self
            .economic_bound
            .safe_value_outflow_ceiling_atoms
            .to_le_bytes();
        let summary = self.verdict_summary();
        let parent_label = self.parent_l1_finality.label();
        let proof_label = self.rollup_proof_finality.label();
        let comp_label = self.composed_finality.label();
        hash_fields_bytes(&[
            b"BDLM_ROLLUP_ROW_V1",
            &self.rollup_domain.0,
            &self.parent_domain.0,
            &l1_h,
            &l2_h,
            &self.state_root,
            &fin_est,
            &da_est,
            &ceil,
            &bond,
            &e_route,
            &e_corr,
            &e_safe,
            summary.as_bytes(),
            parent_label.as_bytes(),
            proof_label.as_bytes(),
            comp_label.as_bytes(),
        ])
    }
}

/// Consensus-stored state of a registered L1-settled rollup inside [`super::intake::IntakeState`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupDomainEntry {
    pub spec: RollupDomainSpec,
    pub economics: DomainEconomics,
    pub bond_atoms: u128,
    pub poster: Address,
    pub latest_l2_height: Option<u64>,
    pub latest_established_l2_height: Option<u64>,
    pub rows_by_l2_height: BTreeMap<u64, CertifiedRollupRow>,
}

impl RollupDomainEntry {
    /// Records a verified rollup batch row while enforcing monotonic progress
    /// above the highest established L2 batch and rejecting conflicting roots
    /// at an already-recorded L2 height.
    pub(crate) fn record_verified_row(
        &mut self,
        row: CertifiedRollupRow,
    ) -> Result<(), RollupVerifyError> {
        if let Some(established) = self.latest_established_l2_height {
            if row.l2_height < established {
                return Err(RollupVerifyError::L2HeightRegression {
                    submitted: row.l2_height,
                    established,
                });
            }
        }
        if let Some(existing) = self.rows_by_l2_height.get(&row.l2_height) {
            if !bool::from(existing.state_root.ct_eq(&row.state_root)) {
                return Err(RollupVerifyError::ConflictingStateRootAtSameHeight {
                    l2_height: row.l2_height,
                });
            }
        }
        let l2_h = row.l2_height;
        let is_est = row.both_established();
        self.rows_by_l2_height.insert(l2_h, row);
        self.latest_l2_height = Some(self.latest_l2_height.map_or(l2_h, |prev| prev.max(l2_h)));
        if is_est {
            self.latest_established_l2_height = Some(
                self.latest_established_l2_height
                    .map_or(l2_h, |prev| prev.max(l2_h)),
            );
        }
        Ok(())
    }
}

/// Errors produced when validating a rollup specification or verifying L1 MPT
/// rollup state proofs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RollupVerifyError {
    #[error(
        "rollup network identifier must be 1..={MAX_ROLLUP_NETWORK_BYTES} ASCII [A-Za-z0-9._-] bytes"
    )]
    InvalidNetworkName,
    #[error("rollup parent_domain cannot be the all-zero key")]
    ZeroParentDomain,
    #[error("L1 rollup settlement contract address cannot be zero")]
    ZeroRollupContract,
    #[error("rollup settlement contract has EOA or zero bytecode hash")]
    EoaOrEmptyCodeHash,
    #[error("L1 rollup contract code_hash does not match pinned expected_code_hash")]
    CodeHashMismatch,
    #[error("rollup storage slots must be pairwise distinct")]
    DuplicateStorageSlots,
    #[error("optimistic rollup challenge window {provided_secs}s is below minimum {min_secs}s")]
    ChallengeWindowTooShort { provided_secs: u64, min_secs: u64 },
    #[error("validity rollup verifier_program_commitment cannot be all-zero")]
    ZeroProgramCommitment,
    #[error("L1 rollup program commitment slot does not match pinned verifier_program_commitment")]
    ProgramCommitmentMismatch,
    #[error("unexpected auxiliary storage proof supplied when no auxiliary slot is configured")]
    UnexpectedAuxiliaryProof,
    #[error("invalid multi-prover quorum {required}-of-{total}")]
    InvalidMultiProverQuorum { required: u8, total: u8 },
    #[error("invalid multi-prover bitmap bits above total_provers")]
    InvalidMultiProverBitmap,
    #[error("invalid external DA domain binding")]
    InvalidDaBinding,
    #[error("parent L1 domain does not authenticate an execution state_root")]
    ParentL1MissingStateRootAttestation,
    #[error("parent_domain mismatch between rollup spec and supplied L1 snapshot")]
    ParentDomainMismatch,
    #[error("L1 account or storage MPT proof failed: {0}")]
    MptAccountOrStorage(AccountProofError),
    #[error("rollup L2 state_root storage slot is uninitialized or zero")]
    MissingOrZeroStateRoot,
    #[error("rollup L2 batch_height storage slot is missing or exceeds u64")]
    InvalidBatchHeightSlot,
    #[error(
        "optimistic proposal_timestamp slot is missing, zero, or after finalized L1 timestamp"
    )]
    InvalidProposalTimestamp,
    #[error("rollup L2 height {submitted} regresses below established height {established}")]
    L2HeightRegression { submitted: u64, established: u64 },
    #[error("conflicting state_root proven for already-recorded L2 height {l2_height}")]
    ConflictingStateRootAtSameHeight { l2_height: u64 },
}

impl From<AccountProofError> for RollupVerifyError {
    fn from(err: AccountProofError) -> Self {
        Self::MptAccountOrStorage(err)
    }
}

fn empty_code_hash() -> [u8; 32] {
    mpt::keccak256(&[])
}

pub(crate) const fn quantum_tag(q: QuantumClass) -> u8 {
    match q {
        QuantumClass::Classical => 0,
        QuantumClass::Lattice => 1,
        QuantumClass::Hash => 2,
    }
}

fn decode_u64_storage_word(word: Option<[u8; 32]>) -> Option<u64> {
    let bytes = word?;
    if bytes[..24].iter().any(|b| *b != 0) {
        return None;
    }
    let tail: [u8; 8] = bytes[24..].try_into().ok()?;
    Some(u64::from_be_bytes(tail))
}

fn decode_u32_bitmap_word(word: Option<[u8; 32]>, total_provers: u8) -> Option<u32> {
    let bytes = word?;
    if bytes[..28].iter().any(|b| *b != 0) {
        return None;
    }
    let tail: [u8; 4] = bytes[28..].try_into().ok()?;
    let raw = u32::from_be_bytes(tail);
    if total_provers < 32 {
        let allowed_mask = (1u32 << u32::from(total_provers)) - 1;
        if (raw & !allowed_mask) != 0 {
            return None;
        }
    }
    Some(raw)
}

fn unestablished_rollup_guarantee() -> FinalityGuarantee {
    FinalityGuarantee {
        reversibility: FinalityReversibility::DeterministicQuorum,
        quantum_posture: QuantumClass::Classical,
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

fn established_quorum_rollup_guarantee(
    quantum_posture: QuantumClass,
    slashable_backing: bool,
) -> FinalityGuarantee {
    let mut g = FinalityGuarantee::settlement_hub();
    g.reversibility = FinalityReversibility::DeterministicQuorum;
    g.quantum_posture = quantum_posture;
    g.slashable_backing = slashable_backing;
    g
}

fn established_validity_rollup_guarantee(
    spec: &RollupDomainSpec,
    verifier_program_commitment: [u8; 32],
    quantum_posture: QuantumClass,
) -> FinalityGuarantee {
    let zk_spec = AdapterSpec::ZkVm {
        network: spec.rollup_network.clone(),
        program_hash: Some(verifier_program_commitment),
        chain_id: Some(1),
    };
    let zk_backing = crate::cross_domain::external::spec::SecurityBacking::Zk {
        system: crate::cross_domain::external::spec::ProofSystem::Stark,
        public_inputs_digest: verifier_program_commitment,
    };
    let mut g = FinalityGuarantee::for_external_spec_with_backing(&zk_spec, Some(&zk_backing));
    g.quantum_posture = quantum_posture;
    g.attestation = CommitmentAttestation {
        state_root: true,
        tx_root: true,
        event_root: true,
        parent: true,
    };
    g
}

/// Verifies an L1-settled rollup batch proof against a finalized parent L1
/// `state_root`, composes `parent_l1_finality.meet(&rollup_proof_finality)`,
/// and evaluates the independent data-availability verdict.
pub(crate) fn verify_rollup_state_proof(
    spec: &RollupDomainSpec,
    rollup_bond_atoms: u128,
    rollup_declared_ceiling_atoms: u128,
    parent: &FinalizedParentL1Snapshot,
    proof: &RollupStateProofSubmission,
    external_da: Result<Option<VerifiedExternalDaSnapshot>, String>,
) -> Result<CertifiedRollupRow, RollupVerifyError> {
    spec.validate()?;
    let rollup_domain = spec.domain_key();
    if parent.parent_domain != spec.parent_domain
        || proof.rollup_domain != rollup_domain
        || proof.l1_height != parent.l1_height
    {
        return Err(RollupVerifyError::ParentDomainMismatch);
    }
    if !parent.parent_finality.attestation.state_root
        || parent.parent_finality.fault_tolerance_bps == 0
    {
        return Err(RollupVerifyError::ParentL1MissingStateRootAttestation);
    }

    let account = account_proof::verify_account(
        &proof.account_proof,
        &parent.l1_state_root,
        &spec.l1_rollup_contract,
    )?;
    if account.code_hash == [0u8; 32] || bool::from(account.code_hash.ct_eq(&empty_code_hash())) {
        return Err(RollupVerifyError::EoaOrEmptyCodeHash);
    }
    if let Some(expected_code) = &spec.expected_code_hash {
        if !bool::from(account.code_hash.ct_eq(expected_code)) {
            return Err(RollupVerifyError::CodeHashMismatch);
        }
    }

    let Some(state_root) = account_proof::verify_storage(
        &proof.state_root_proof,
        &account.storage_root,
        &spec.state_root_slot,
    )?
    else {
        return Err(RollupVerifyError::MissingOrZeroStateRoot);
    };
    if state_root == [0u8; 32] {
        return Err(RollupVerifyError::MissingOrZeroStateRoot);
    }

    let raw_height = account_proof::verify_storage(
        &proof.batch_height_proof,
        &account.storage_root,
        &spec.batch_height_slot,
    )?;
    let Some(l2_height) = decode_u64_storage_word(raw_height) else {
        return Err(RollupVerifyError::InvalidBatchHeightSlot);
    };

    let (finality_verdict, rollup_proof_finality) = match &spec.proof_model {
        RollupProofModel::OptimisticFaultProof {
            proposal_timestamp_slot,
            challenge_window_secs,
        } => {
            let raw_ts = account_proof::verify_storage(
                &proof.auxiliary_slot_proof,
                &account.storage_root,
                proposal_timestamp_slot,
            )?;
            let Some(proposal_ts) = decode_u64_storage_word(raw_ts) else {
                return Err(RollupVerifyError::InvalidProposalTimestamp);
            };
            if proposal_ts == 0 || parent.l1_finalized_at < proposal_ts {
                return Err(RollupVerifyError::InvalidProposalTimestamp);
            }
            let elapsed = parent.l1_finalized_at - proposal_ts;
            if elapsed < *challenge_window_secs {
                let remaining_secs = *challenge_window_secs - elapsed;
                (
                    RollupFinalityVerdict::PendingChallengeWindow {
                        l1_height: parent.l1_height,
                        l2_height,
                        state_root,
                        proposal_timestamp: proposal_ts,
                        remaining_secs,
                    },
                    unestablished_rollup_guarantee(),
                )
            } else {
                (
                    RollupFinalityVerdict::Established {
                        l1_height: parent.l1_height,
                        l2_height,
                        state_root,
                    },
                    established_quorum_rollup_guarantee(
                        QuantumClass::Classical,
                        rollup_bond_atoms > 0,
                    ),
                )
            }
        }
        RollupProofModel::ValidityProof {
            verifier_program_commitment,
            program_commitment_slot,
            quantum_posture,
        } => {
            if let Some(prog_slot) = program_commitment_slot {
                let Some(onchain_commitment) = account_proof::verify_storage(
                    &proof.auxiliary_slot_proof,
                    &account.storage_root,
                    prog_slot,
                )?
                else {
                    return Err(RollupVerifyError::ProgramCommitmentMismatch);
                };
                if !bool::from(onchain_commitment.ct_eq(verifier_program_commitment)) {
                    return Err(RollupVerifyError::ProgramCommitmentMismatch);
                }
            } else if !proof.auxiliary_slot_proof.is_empty() {
                return Err(RollupVerifyError::UnexpectedAuxiliaryProof);
            }
            (
                RollupFinalityVerdict::Established {
                    l1_height: parent.l1_height,
                    l2_height,
                    state_root,
                },
                established_validity_rollup_guarantee(
                    spec,
                    *verifier_program_commitment,
                    *quantum_posture,
                ),
            )
        }
        RollupProofModel::MultiProver {
            required_provers,
            total_provers,
            attestation_bitmap_slot,
            quantum_posture,
        } => {
            let raw_bitmap = account_proof::verify_storage(
                &proof.auxiliary_slot_proof,
                &account.storage_root,
                attestation_bitmap_slot,
            )?;
            let Some(bitmap) = decode_u32_bitmap_word(raw_bitmap, *total_provers) else {
                return Err(RollupVerifyError::InvalidMultiProverBitmap);
            };
            let attested = u8::try_from(bitmap.count_ones()).unwrap_or(u8::MAX);
            if attested < *required_provers {
                (
                    RollupFinalityVerdict::PendingMultiProverQuorum {
                        l1_height: parent.l1_height,
                        l2_height,
                        state_root,
                        attested_provers: attested,
                        required_provers: *required_provers,
                    },
                    unestablished_rollup_guarantee(),
                )
            } else {
                (
                    RollupFinalityVerdict::Established {
                        l1_height: parent.l1_height,
                        l2_height,
                        state_root,
                    },
                    established_quorum_rollup_guarantee(*quantum_posture, rollup_bond_atoms > 0),
                )
            }
        }
    };

    let composed_finality = parent.parent_finality.meet(&rollup_proof_finality);

    let da_verdict = match &spec.da_binding {
        RollupDaBinding::ParentL1 => RollupDaVerdict::EstablishedOnParentL1 {
            parent_domain: parent.parent_domain,
            l1_height: parent.l1_height,
        },
        RollupDaBinding::ExternalDaDomain {
            da_domain,
            min_samples,
        } => match external_da {
            Ok(Some(da_snap)) => {
                if da_snap.da_domain != *da_domain {
                    RollupDaVerdict::PendingExternalDa {
                        da_domain: *da_domain,
                        reason: "external DA snapshot domain mismatch".to_string(),
                    }
                } else if da_snap.attested_min_samples < *min_samples {
                    RollupDaVerdict::PendingExternalDa {
                        da_domain: *da_domain,
                        reason: format!(
                            "attested min_samples {} below required {min_samples}",
                            da_snap.attested_min_samples
                        ),
                    }
                } else if da_snap.da_guarantee.fault_tolerance_bps == 0
                    || da_snap.data_root == [0u8; 32]
                {
                    RollupDaVerdict::PendingExternalDa {
                        da_domain: *da_domain,
                        reason: "external DA guarantee carries zero fault tolerance or zero root"
                            .to_string(),
                    }
                } else {
                    RollupDaVerdict::EstablishedExternalDa {
                        da_domain: da_snap.da_domain,
                        da_height: da_snap.da_height,
                        data_root: da_snap.data_root,
                        min_samples: da_snap.attested_min_samples,
                        da_guarantee: da_snap.da_guarantee,
                    }
                }
            }
            Ok(None) => RollupDaVerdict::PendingExternalDa {
                da_domain: *da_domain,
                reason: "missing external DA attestation".to_string(),
            },
            Err(reason) => RollupDaVerdict::PendingExternalDa {
                da_domain: *da_domain,
                reason,
            },
        },
    };

    let both_established = finality_verdict.is_established() && da_verdict.is_established();
    let capped_declared_ceiling = rollup_declared_ceiling_atoms
        .min(rollup_bond_atoms)
        .min(parent.parent_live_ceiling_atoms);
    let effective_ceiling = if both_established && composed_finality.fault_tolerance_bps > 0 {
        capped_declared_ceiling
    } else {
        0
    };
    let economic_bound =
        EconomicSecurityBound::derive(&composed_finality, rollup_bond_atoms, effective_ceiling);
    let value_routing_ceiling_atoms = if both_established
        && composed_finality.attestation.state_root
        && composed_finality.fault_tolerance_bps > 0
    {
        if economic_bound.safe_value_outflow_ceiling_atoms > 0 {
            economic_bound.safe_value_outflow_ceiling_atoms
        } else {
            effective_ceiling
        }
    } else {
        0
    };

    Ok(CertifiedRollupRow {
        rollup_domain,
        parent_domain: parent.parent_domain,
        l1_height: parent.l1_height,
        l2_height,
        state_root,
        parent_l1_finality: parent.parent_finality,
        rollup_proof_finality,
        composed_finality,
        finality_verdict,
        da_verdict,
        economic_bound,
        value_routing_ceiling_atoms,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cross_domain::evm::rlp::{self, Item};

    fn uint_bytes(value: u128) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        bytes[first..].to_vec()
    }

    pub(crate) fn build_mpt_trie(entries: &[([u8; 32], Vec<u8>)]) -> ([u8; 32], Vec<Vec<u8>>) {
        let mut items: Vec<(Vec<u8>, Vec<u8>)> = entries
            .iter()
            .map(|(k, v)| (mpt::to_nibbles(k), v.clone()))
            .collect();
        items.sort_by(|a, b| a.0.cmp(&b.0));
        let mut all_nodes = Vec::new();
        let root_rlp = build_node(&items, &mut all_nodes);
        let root_hash = mpt::keccak256(&root_rlp);
        all_nodes.push(root_rlp);
        (root_hash, all_nodes)
    }

    fn build_node(items: &[(Vec<u8>, Vec<u8>)], out: &mut Vec<Vec<u8>>) -> Vec<u8> {
        assert!(!items.is_empty());
        if items.len() == 1 {
            let (nibbles, val) = &items[0];
            let path = mpt::hp_encode(nibbles, true);
            return rlp::encode(&Item::List(vec![
                Item::String(path),
                Item::String(val.clone()),
            ]));
        }
        let first = &items[0].0;
        let mut lcp = first.len();
        for (nib, _) in &items[1..] {
            let common = first
                .iter()
                .zip(nib.iter())
                .take_while(|(a, b)| a == b)
                .count();
            lcp = lcp.min(common);
        }
        if lcp > 0 {
            let prefix = first[..lcp].to_vec();
            let stripped: Vec<(Vec<u8>, Vec<u8>)> = items
                .iter()
                .map(|(n, v)| (n[lcp..].to_vec(), v.clone()))
                .collect();
            let child_rlp = build_node(&stripped, out);
            let child_ref = child_item(child_rlp, out);
            return rlp::encode(&Item::List(vec![
                Item::String(mpt::hp_encode(&prefix, false)),
                child_ref,
            ]));
        }
        type NibblePair = (Vec<u8>, Vec<u8>);
        let mut branches: Vec<Item> = (0..16).map(|_| Item::String(Vec::new())).collect();
        let mut branch_val = Vec::new();
        let mut buckets: BTreeMap<u8, Vec<NibblePair>> = BTreeMap::new();
        for (nib, val) in items {
            if nib.is_empty() {
                branch_val = val.clone();
            } else {
                buckets
                    .entry(nib[0])
                    .or_default()
                    .push((nib[1..].to_vec(), val.clone()));
            }
        }
        for (idx, group) in buckets {
            let child_rlp = build_node(&group, out);
            branches[usize::from(idx)] = child_item(child_rlp, out);
        }
        branches.push(Item::String(branch_val));
        rlp::encode(&Item::List(branches))
    }

    fn child_item(child_rlp: Vec<u8>, out: &mut Vec<Vec<u8>>) -> Item {
        if child_rlp.len() < 32 {
            rlp::decode(&child_rlp).unwrap_or(Item::String(Vec::new()))
        } else {
            let h = mpt::keccak256(&child_rlp);
            out.push(child_rlp);
            Item::String(h.to_vec())
        }
    }

    fn rlp_storage_word(word: &[u8; 32]) -> Vec<u8> {
        let first = word.iter().position(|b| *b != 0).unwrap_or(word.len());
        rlp::encode(&Item::String(word[first..].to_vec()))
    }

    pub(crate) fn u64_word(v: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        w
    }

    pub(crate) type L1FixtureTuple = ([u8; 32], [u8; 32], Vec<Vec<u8>>, Vec<Vec<u8>>);

    pub(crate) fn build_l1_fixture(
        contract: [u8; 20],
        code: &[u8],
        slots: &[([u8; 32], [u8; 32])],
    ) -> L1FixtureTuple {
        let storage_entries: Vec<([u8; 32], Vec<u8>)> = slots
            .iter()
            .map(|(slot, word)| (mpt::keccak256(slot), rlp_storage_word(word)))
            .collect();
        let (storage_root, storage_nodes) = build_mpt_trie(&storage_entries);
        let code_hash = mpt::keccak256(code);
        let acct_rlp = rlp::encode(&Item::List(vec![
            Item::String(uint_bytes(1)),
            Item::String(uint_bytes(0)),
            Item::String(storage_root.to_vec()),
            Item::String(code_hash.to_vec()),
        ]));
        let (state_root, acct_nodes) = build_mpt_trie(&[(mpt::keccak256(&contract), acct_rlp)]);
        (state_root, code_hash, acct_nodes, storage_nodes)
    }

    fn sample_parent_l1(
        parent_domain: DomainKey,
        state_root: [u8; 32],
        finalized_at: u64,
    ) -> FinalizedParentL1Snapshot {
        let mut parent_finality = FinalityGuarantee::settlement_hub();
        parent_finality.quantum_posture = QuantumClass::Classical;
        FinalizedParentL1Snapshot {
            parent_domain,
            l1_height: 21_000_000,
            l1_state_root: state_root,
            l1_finalized_at: finalized_at,
            parent_finality,
            parent_live_ceiling_atoms: 500_000,
        }
    }

    #[test]
    fn op_rollup_inside_challenge_window_carries_zero_value_and_matures_after_window() {
        let parent_domain = DomainKey([0xAA; 32]);
        let contract = [0x42; 20];
        let code = b"OP_L2_OUTPUT_ORACLE_V1";
        let state_slot = [0x01; 32];
        let height_slot = [0x02; 32];
        let ts_slot = [0x03; 32];
        let l2_root = [0x77; 32];
        let proposal_ts = 1_700_000_000u64;
        let window = 604_800u64;

        let (l1_state_root, code_hash, acct_proof, storage_proof) = build_l1_fixture(
            contract,
            code,
            &[
                (state_slot, l2_root),
                (height_slot, u64_word(12_345)),
                (ts_slot, u64_word(proposal_ts)),
            ],
        );

        let spec = RollupDomainSpec {
            rollup_network: "op-sepolia".to_string(),
            parent_domain,
            l1_rollup_contract: contract,
            expected_code_hash: Some(code_hash),
            state_root_slot: state_slot,
            batch_height_slot: height_slot,
            proof_model: RollupProofModel::OptimisticFaultProof {
                proposal_timestamp_slot: ts_slot,
                challenge_window_secs: window,
            },
            da_binding: RollupDaBinding::ParentL1,
        };
        assert!(spec.validate().is_ok());

        let submission = RollupStateProofSubmission {
            rollup_domain: spec.domain_key(),
            l1_height: 21_000_000,
            account_proof: acct_proof,
            state_root_proof: storage_proof.clone(),
            batch_height_proof: storage_proof.clone(),
            auxiliary_slot_proof: storage_proof,
            da_height: None,
            submitter: Address::from([9u8; 32]),
        };

        let parent_early = sample_parent_l1(parent_domain, l1_state_root, proposal_ts + 3_600);
        let Ok(early_row) = verify_rollup_state_proof(
            &spec,
            200_000,
            150_000,
            &parent_early,
            &submission,
            Ok(None),
        ) else {
            panic!("MPT proof should verify inside challenge window");
        };
        assert!(!early_row.finality_verdict.is_established());
        assert!(early_row.da_verdict.is_established());
        assert!(!early_row.both_established());
        assert_eq!(early_row.composed_finality.fault_tolerance_bps, 0);
        assert!(!early_row.composed_finality.admits_cross_domain_value());
        assert_eq!(early_row.value_routing_ceiling_atoms, 0);
        assert_eq!(early_row.economic_bound.safe_value_outflow_ceiling_atoms, 0);
        assert_eq!(
            early_row.verdict_summary(),
            "finality=pending-challenge-window|da=established-parent-l1"
        );

        let parent_matured = sample_parent_l1(parent_domain, l1_state_root, proposal_ts + window);
        let Ok(matured_row) = verify_rollup_state_proof(
            &spec,
            200_000,
            150_000,
            &parent_matured,
            &submission,
            Ok(None),
        ) else {
            panic!("MPT proof should verify after challenge window");
        };
        assert!(matured_row.finality_verdict.is_established());
        assert!(matured_row.da_verdict.is_established());
        assert!(matured_row.both_established());
        assert_eq!(matured_row.state_root, l2_root);
        assert_eq!(matured_row.l2_height, 12_345);
        assert_eq!(
            matured_row.composed_finality,
            parent_matured
                .parent_finality
                .meet(&matured_row.rollup_proof_finality)
        );
        assert!(matured_row.composed_finality.admits_cross_domain_value());
        assert!(matured_row.value_routing_ceiling_atoms > 0);
        assert_ne!(early_row.row_digest(), matured_row.row_digest());
    }

    #[test]
    fn zk_validity_rollup_with_external_da_emits_two_independent_verdicts() {
        let parent_domain = DomainKey([0xBB; 32]);
        let da_domain = DomainKey([0xCC; 32]);
        let contract = [0x55; 20];
        let code = b"ZK_STATE_TRANSITION_VERIFIER_V1";
        let state_slot = [0x10; 32];
        let height_slot = [0x11; 32];
        let prog_slot = [0x12; 32];
        let vk_commitment = [0x99; 32];
        let l2_root = [0x88; 32];

        let (l1_state_root, code_hash, acct_proof, storage_proof) = build_l1_fixture(
            contract,
            code,
            &[
                (state_slot, l2_root),
                (height_slot, u64_word(900)),
                (prog_slot, vk_commitment),
            ],
        );

        let spec = RollupDomainSpec {
            rollup_network: "zksync-era".to_string(),
            parent_domain,
            l1_rollup_contract: contract,
            expected_code_hash: Some(code_hash),
            state_root_slot: state_slot,
            batch_height_slot: height_slot,
            proof_model: RollupProofModel::ValidityProof {
                verifier_program_commitment: vk_commitment,
                program_commitment_slot: Some(prog_slot),
                quantum_posture: QuantumClass::Hash,
            },
            da_binding: RollupDaBinding::ExternalDaDomain {
                da_domain,
                min_samples: 16,
            },
        };
        assert!(spec.validate().is_ok());

        let submission = RollupStateProofSubmission {
            rollup_domain: spec.domain_key(),
            l1_height: 21_000_000,
            account_proof: acct_proof,
            state_root_proof: storage_proof.clone(),
            batch_height_proof: storage_proof.clone(),
            auxiliary_slot_proof: storage_proof,
            da_height: Some(4_200),
            submitter: Address::from([3u8; 32]),
        };
        let parent = sample_parent_l1(parent_domain, l1_state_root, 1_700_100_000);

        let Ok(row_da_missing) = verify_rollup_state_proof(
            &spec,
            300_000,
            100_000,
            &parent,
            &submission,
            Err("no DA attestation at height 4200".to_string()),
        ) else {
            panic!("ZK rollup state proof should verify even while DA is pending");
        };
        assert!(row_da_missing.finality_verdict.is_established());
        assert!(!row_da_missing.da_verdict.is_established());
        assert!(!row_da_missing.both_established());
        assert_eq!(row_da_missing.value_routing_ceiling_atoms, 0);
        assert_eq!(
            row_da_missing.verdict_summary(),
            "finality=established|da=pending"
        );

        let sk_bytes = [0x21u8; 32];
        let vk_ed = ed25519_dalek::SigningKey::from_bytes(&sk_bytes)
            .verifying_key()
            .to_bytes();
        let da_spec = AdapterSpec::DataAvailability {
            network: "celestia-mocha".to_string(),
            committee: Some(
                crate::cross_domain::external::da_sampling::PinnedDaCommittee {
                    namespace_id: [0x5A; 32],
                    min_samples: 16,
                    min_square_size: 32,
                    members: vec![
                        crate::cross_domain::external::da_sampling::DaCommitteeMember {
                            ed25519_pubkey: vk_ed,
                            voting_weight: 100,
                            pq_pubkey: Vec::new(),
                        },
                    ],
                },
            ),
        };
        let da_backing = crate::cross_domain::external::spec::SecurityBacking::SignatureSet {
            scheme: crate::crypto::facts::ObservedScheme::Scheme(
                crate::crypto::scheme::SchemeId::ED25519,
            ),
            signers: 1,
            required: 1,
            total_weight: 100,
            slashable: true,
        };
        let da_guarantee =
            FinalityGuarantee::for_external_spec_with_backing(&da_spec, Some(&da_backing));
        assert!(da_guarantee.fault_tolerance_bps > 0);
        let Ok(row_both) = verify_rollup_state_proof(
            &spec,
            300_000,
            100_000,
            &parent,
            &submission,
            Ok(Some(VerifiedExternalDaSnapshot {
                da_domain,
                da_height: 4_200,
                data_root: [0x5A; 32],
                attested_min_samples: 16,
                da_guarantee,
            })),
        ) else {
            panic!("ZK rollup + sampled DA should verify");
        };
        assert!(row_both.finality_verdict.is_established());
        assert!(row_both.da_verdict.is_established());
        assert!(row_both.both_established());
        assert_eq!(
            row_both.verdict_summary(),
            "finality=established|da=established-sampled"
        );
        assert_eq!(
            row_both.composed_finality,
            parent.parent_finality.meet(&row_both.rollup_proof_finality)
        );
        assert_eq!(
            row_both.composed_finality.reversibility,
            FinalityReversibility::DeterministicQuorum
        );
        assert_eq!(row_both.value_routing_ceiling_atoms, 100_000);
    }

    #[test]
    fn multiprover_rollup_enforces_bitmap_quorum_and_fail_closed_guards() {
        let parent_domain = DomainKey([0xDD; 32]);
        let contract = [0x66; 20];
        let code = b"MULTIPROVER_SETTLEMENT_V1";
        let state_slot = [0x21; 32];
        let height_slot = [0x22; 32];
        let bitmap_slot = [0x23; 32];

        let (root_pending, code_hash, acct_1, stor_1) = build_l1_fixture(
            contract,
            code,
            &[
                (state_slot, [0xAB; 32]),
                (height_slot, u64_word(50)),
                (bitmap_slot, u64_word(0b001)),
            ],
        );
        let spec = RollupDomainSpec {
            rollup_network: "linea-multiprover".to_string(),
            parent_domain,
            l1_rollup_contract: contract,
            expected_code_hash: Some(code_hash),
            state_root_slot: state_slot,
            batch_height_slot: height_slot,
            proof_model: RollupProofModel::MultiProver {
                required_provers: 2,
                total_provers: 3,
                attestation_bitmap_slot: bitmap_slot,
                quantum_posture: QuantumClass::Lattice,
            },
            da_binding: RollupDaBinding::ParentL1,
        };
        let sub_1 = RollupStateProofSubmission {
            rollup_domain: spec.domain_key(),
            l1_height: 21_000_000,
            account_proof: acct_1,
            state_root_proof: stor_1.clone(),
            batch_height_proof: stor_1.clone(),
            auxiliary_slot_proof: stor_1,
            da_height: None,
            submitter: Address::from([4u8; 32]),
        };
        let parent_1 = sample_parent_l1(parent_domain, root_pending, 1_700_000_500);
        let Ok(row_1) =
            verify_rollup_state_proof(&spec, 200_000, 80_000, &parent_1, &sub_1, Ok(None))
        else {
            panic!("1-of-3 multiprover proof should verify as pending");
        };
        assert!(!row_1.finality_verdict.is_established());
        assert_eq!(row_1.value_routing_ceiling_atoms, 0);
        assert_eq!(
            row_1.verdict_summary(),
            "finality=pending-multiprover-quorum|da=established-parent-l1"
        );

        let (root_ok, _, acct_2, stor_2) = build_l1_fixture(
            contract,
            code,
            &[
                (state_slot, [0xAB; 32]),
                (height_slot, u64_word(50)),
                (bitmap_slot, u64_word(0b101)),
            ],
        );
        let sub_2 = RollupStateProofSubmission {
            account_proof: acct_2,
            state_root_proof: stor_2.clone(),
            batch_height_proof: stor_2.clone(),
            auxiliary_slot_proof: stor_2,
            ..sub_1.clone()
        };
        let parent_2 = sample_parent_l1(parent_domain, root_ok, 1_700_000_600);
        let Ok(row_2) =
            verify_rollup_state_proof(&spec, 200_000, 80_000, &parent_2, &sub_2, Ok(None))
        else {
            panic!("2-of-3 multiprover proof should verify as established");
        };
        assert!(row_2.both_established());
        assert!(row_2.value_routing_ceiling_atoms > 0);

        let mut entry = RollupDomainEntry {
            spec: spec.clone(),
            economics: DomainEconomics::default(),
            bond_atoms: 200_000,
            poster: Address::from([1u8; 32]),
            latest_l2_height: None,
            latest_established_l2_height: None,
            rows_by_l2_height: BTreeMap::new(),
        };
        assert!(entry.record_verified_row(row_1).is_ok());
        assert!(entry.record_verified_row(row_2.clone()).is_ok());

        let mut conflict = row_2.clone();
        conflict.state_root = [0xFE; 32];
        assert_eq!(
            entry.record_verified_row(conflict),
            Err(RollupVerifyError::ConflictingStateRootAtSameHeight { l2_height: 50 })
        );

        let mut regressed = row_2;
        regressed.l2_height = 49;
        assert_eq!(
            entry.record_verified_row(regressed),
            Err(RollupVerifyError::L2HeightRegression {
                submitted: 49,
                established: 50
            })
        );

        let (root_eoa, _, acct_eoa, stor_eoa) = build_l1_fixture(
            contract,
            b"",
            &[
                (state_slot, [0xAB; 32]),
                (height_slot, u64_word(51)),
                (bitmap_slot, u64_word(0b111)),
            ],
        );
        let mut spec_unpinned = spec;
        spec_unpinned.expected_code_hash = None;
        let sub_eoa = RollupStateProofSubmission {
            rollup_domain: spec_unpinned.domain_key(),
            account_proof: acct_eoa,
            state_root_proof: stor_eoa.clone(),
            batch_height_proof: stor_eoa.clone(),
            auxiliary_slot_proof: stor_eoa,
            ..sub_1
        };
        let parent_eoa = sample_parent_l1(parent_domain, root_eoa, 1_700_000_700);
        assert_eq!(
            verify_rollup_state_proof(
                &spec_unpinned,
                200_000,
                80_000,
                &parent_eoa,
                &sub_eoa,
                Ok(None)
            ),
            Err(RollupVerifyError::EoaOrEmptyCodeHash)
        );
    }
}
