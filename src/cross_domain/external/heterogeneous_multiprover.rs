//! WIRING: wired via `AdapterSpec::HeterogeneousMultiProver` in `intake.rs` and
//! `FinalityGuarantee::for_external_spec_declared` in `universal_finality.rs`.
//!
//! Endgame `2-of-3` Heterogeneous Multi-Prover external finality adapter
//! (`multiprover-2of3-v1`).
//!
//! The 2-of-3 agreement check is re-exported by `crate::cross_domain::external`
//! and constructed through `AdapterSpec::HeterogeneousMultiProver::build` when
//! a governance-pinned multi-prover configuration is supplied.
//!
//! Single-prover ZK rollups suffer catastrophic total-value loss from a single
//! under-constrained AIR circuit bug, while single-prover optimistic rollups
//! inherit a multi-day withdrawal delay and L1 censorship surface. Combining
//! three pairwise-independent verification families -
//!   1. `HashStark`: canonical `BudZKVM` Plonky3 Goldilocks/FRI execution proof,
//!   2. `FaultWindow`: bonded proposer state transition past its dispute window
//!      with zero unresolved bisection challenges,
//!   3. `PqAttestedCommittee`: strict `> 2/3` stake-weighted independent
//!      re-execution committee bound to a pinned enclave/client measurement with
//!      Ed25519 + ML-DSA-65 (`CROSS_DOMAIN_V1`) dual signatures.
//!
//! Together these settle a batch immediately once at least two distinct families
//! verify and agree bit-for-bit on `(pre_state_root, post_state_root, withdrawal_root)`.
//!
//! Soundness-first disagreement rule: if a third leg is also present and
//! cryptographically certifies a conflicting `post_state_root` or
//! `withdrawal_root` for the same `(batch_index, l1_batch_hash, pre_state_root)`,
//! `verify` refuses finality fail-closed and `detect_prover_disagreement` yields
//! a deterministic bug-isolation record for `ConsensusSentry` and slashing.
//!
//! Convenience: exposed for Stage-2 rollup bridges, external intake, and
//! multi-prover fault-isolation pipelines.

use std::collections::{BTreeMap, BTreeSet};

use bud_proof::{ExecutionPublicInputs, ProofEnvelope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::ctx::CROSS_DOMAIN_V1;
use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::primitives::{verify_signature, PqKeyPair};
use crate::crypto::scheme::SchemeId;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, ProofSystem, RawConsensusEvidence, SecurityBacking,
    TimeUnit, TrustModel, VerificationPolicy,
};

/// Canonical adapter name for `2-of-3` heterogeneous multi-prover finality.
pub const ADAPTER_NAME: &str = "multiprover-2of3-v1";

/// Implementation version of `HeterogeneousMultiProverAdapter`.
pub const ADAPTER_VERSION: u32 = 1;

/// Accepted wire evidence version.
pub const EVIDENCE_VERSION: u32 = 1;

/// Eight-byte wire magic for serialized `MultiProverEvidence`.
pub const MULTIPROVER_MAGIC: &[u8; 8] = b"BDLMMP01";

/// Domain tag for canonical batch state-transition commitments.
pub const DOMAIN_MULTIPROVER_BATCH: &[u8] = b"BDLM_MULTIPROVER_BATCH_V1";

/// Domain tag for bonded fault-proposer transition claims.
pub const DOMAIN_MULTIPROVER_FAULT: &[u8] = b"BDLM_MULTIPROVER_FAULT_V1";

/// Domain tag for attested re-execution committee votes.
pub const DOMAIN_MULTIPROVER_COMMITTEE: &[u8] = b"BDLM_MULTIPROVER_COMMITTEE_V1";

/// Hard ceiling on serialized `MultiProverEvidence` bytes (2 MiB, covers STARK).
pub const MAX_MULTIPROVER_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

/// Maximum independent committee members allowed in a pinned quorum.
pub const MAX_MULTIPROVER_COMMITTEE: usize = 128;

/// Required minimum distinct agreeing proof families (`2` of `3`).
pub const REQUIRED_PROVER_FAMILIES: usize = 2;

fn update_lp(h: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    h.update(len.to_le_bytes());
    h.update(bytes);
}

/// Independent verification family participating in `2-of-3` settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProverFamily {
    /// Plonky3 Goldilocks + FRI canonical zkVM execution STARK (pure PQ).
    HashStark,
    /// Bonded fault-proof state root after full dispute-free challenge window.
    FaultWindow,
    /// Strict `> 2/3` independent re-execution committee with measurement pin.
    PqAttestedCommittee,
}

/// Canonical rollup batch header attested across independent prover legs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupBatchClaim {
    /// Monotonic rollup batch index (mapped to `FinalityAttestation::height`).
    pub batch_index: u64,
    /// L1 commitment digest fixing the exact ordered transaction batch input.
    pub l1_batch_hash: [u8; 32],
    /// State root immediately prior to executing this batch.
    pub pre_state_root: [u8; 32],
    /// Claimed state root immediately after executing this batch.
    pub post_state_root: [u8; 32],
    /// Claimed bridge withdrawal/event root produced by this batch.
    pub withdrawal_root: [u8; 32],
    /// Deterministic batch timestamp in Unix seconds.
    pub batch_timestamp_secs: u64,
}

impl RollupBatchClaim {
    /// Canonical length-prefixed SHA-256 digest of the batch transition.
    ///
    /// Convenience: exposed for prover signers and disagreement auditing.
    #[must_use]
    pub fn transition_digest(&self, network: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        update_lp(&mut h, DOMAIN_MULTIPROVER_BATCH);
        update_lp(&mut h, network.as_bytes());
        h.update(self.batch_index.to_le_bytes());
        h.update(self.l1_batch_hash);
        h.update(self.pre_state_root);
        h.update(self.post_state_root);
        h.update(self.withdrawal_root);
        h.update(self.batch_timestamp_secs.to_le_bytes());
        h.finalize().into()
    }

    fn validate_non_zero(&self) -> Result<(), AdapterError> {
        if self.batch_index == 0
            || self.l1_batch_hash == [0u8; 32]
            || self.pre_state_root == [0u8; 32]
            || self.post_state_root == [0u8; 32]
        {
            return Err(AdapterError::ConsensusRule {
                rule: "MultiProver batch claim has zero batch_index, l1_batch_hash, or state root"
                    .into(),
            });
        }
        Ok(())
    }
}

/// Leg 1: Canonical `BudZKVM` Plonky3 FRI STARK proof over `(pre -> post)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkProverLeg {
    /// Verified `BudZKVM` canonical program bytecode.
    pub program: Vec<u64>,
    /// Public inputs verified directly inside the Plonky3 AIR.
    pub inputs: ExecutionPublicInputs,
    /// Plonky3 FRI proof envelope.
    pub envelope: ProofEnvelope,
    /// Claimed withdrawal root paired with `inputs.final_state_root`.
    pub withdrawal_root: [u8; 32],
}

/// Leg 2: Bonded fault-proof transition claim past its L1 dispute window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultWindowLeg {
    /// Claimed post-state root proposed on L1.
    pub post_state_root: [u8; 32],
    /// Claimed withdrawal root proposed on L1.
    pub withdrawal_root: [u8; 32],
    /// L1 timestamp (seconds) when the proposal was anchored.
    pub proposed_at_secs: u64,
    /// Escrowed slashable proposer bond in atoms.
    pub proposer_bond_atoms: u128,
    /// Count of open, unresolved bisection fault games (must be `0`).
    pub open_challenges: u32,
    /// Bonded proposer Ed25519 public key (must be pinned).
    pub proposer_ed25519_pk: [u8; 32],
    /// Ed25519 signature over `fault_claim_sign_bytes`.
    pub proposer_ed25519_sig: Vec<u8>,
    /// Optional/mandatory ML-DSA-65 co-signature under `CROSS_DOMAIN_V1`.
    pub proposer_pq_sig: Vec<u8>,
}

/// Single member signature in the attested re-execution committee (Leg 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeAttestationSig {
    /// Member Ed25519 public key identifying the committee seat.
    pub signer_ed25519_pk: [u8; 32],
    /// Ed25519 signature over `committee_vote_sign_bytes`.
    pub ed25519_sig: Vec<u8>,
    /// ML-DSA-65 signature over `committee_vote_sign_bytes` (`CROSS_DOMAIN_V1`).
    pub pq_sig: Vec<u8>,
}

/// Leg 3: Strict `> 2/3` independent re-execution / enclave committee attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedCommitteeLeg {
    /// Claimed post-state root produced by independent re-execution.
    pub post_state_root: [u8; 32],
    /// Claimed withdrawal root produced by independent re-execution.
    pub withdrawal_root: [u8; 32],
    /// 32-byte deterministic client/enclave measurement digest (must equal pin).
    pub measurement_digest: [u8; 32],
    /// Distinct committee signatures exceeding two-thirds of total weight.
    pub signatures: Vec<CommitteeAttestationSig>,
}

/// Wire evidence carrying a `RollupBatchClaim` and any subset of the 3 legs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiProverEvidence {
    /// Canonical batch claim settled when `>= 2` legs agree with zero conflict.
    pub claim: RollupBatchClaim,
    /// Optional Leg 1 (Plonky3 Hash-STARK).
    pub stark_leg: Option<StarkProverLeg>,
    /// Optional Leg 2 (dispute-free Fault Window).
    pub fault_leg: Option<FaultWindowLeg>,
    /// Optional Leg 3 (PQ-hybrid Attested Re-Execution Committee).
    pub committee_leg: Option<AttestedCommitteeLeg>,
}

/// One seat in the pinned independent re-execution committee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiProverCommitteeMember {
    /// Member Ed25519 public key (non-zero, unique).
    pub ed25519_pk: [u8; 32],
    /// Optional/mandatory ML-DSA-65 public key (non-empty enforces PQ co-sig).
    pub pq_pk: Vec<u8>,
    /// Positive voting weight.
    pub weight: u64,
}

/// Authorized fault-window proposer record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedFaultProposer {
    /// Proposer Ed25519 public key.
    pub ed25519_pk: [u8; 32],
    /// Optional/mandatory ML-DSA-65 public key.
    pub pq_pk: Vec<u8>,
}

/// Governance-pinned multi-prover trust anchor for a Stage-2 rollup domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedMultiProverConfig {
    /// Pinned canonical `BudZKVM` guest program hash for `HashStark`.
    pub stark_program_hash: [u8; 32],
    /// Pinned target chain ID bound into `ExecutionPublicInputs::chain_id`.
    pub chain_id: u64,
    /// Minimum fault-proof challenge window in seconds.
    pub challenge_window_secs: u64,
    /// Minimum required slashable bond (atoms) on `FaultWindowLeg`.
    pub min_fault_bond_atoms: u128,
    /// Authorized bonded fault proposers.
    pub fault_proposers: Vec<PinnedFaultProposer>,
    /// Pinned client/enclave measurement digest required for `PqAttestedCommittee`.
    pub expected_measurement: [u8; 32],
    /// Pinned independent re-execution committee (`> 2/3` weight required).
    pub committee: Vec<MultiProverCommitteeMember>,
    /// Whether `stark_leg` must also belong to `BudZero`'s static 4-program
    /// canonical set (`false` permits governance-pinned rollup batch guests).
    pub require_canonical_stark_set: bool,
    /// Require at least one agreeing leg to carry pure/hybrid PQ security.
    pub require_pq_leg: bool,
}

/// Deterministic fault-isolation report returned when two valid prover families
/// certify different post-state or withdrawal roots for the exact same batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiProverDisagreement {
    /// Conflicting rollup batch index.
    pub batch_index: u64,
    /// Shared L1 batch input hash.
    pub l1_batch_hash: [u8; 32],
    /// Shared pre-state root.
    pub pre_state_root: [u8; 32],
    /// First verified family and its certified `(post_state_root, withdrawal_root)`.
    pub first: (ProverFamily, [u8; 32], [u8; 32]),
    /// Second verified family and its conflicting `(post_state_root, withdrawal_root)`.
    pub second: (ProverFamily, [u8; 32], [u8; 32]),
}

/// Domain-separated signing preimage for `FaultWindowLeg`.
///
/// Convenience: exposed for fault-proposer signing tools and tests.
#[must_use]
pub fn fault_claim_sign_bytes(
    network: &str,
    claim: &RollupBatchClaim,
    post_state_root: &[u8; 32],
    withdrawal_root: &[u8; 32],
    proposed_at_secs: u64,
    proposer_bond_atoms: u128,
) -> [u8; 32] {
    crate::core::hash::hash_fields_bytes(&[
        DOMAIN_MULTIPROVER_FAULT,
        network.as_bytes(),
        &claim.batch_index.to_le_bytes(),
        &claim.l1_batch_hash,
        &claim.pre_state_root,
        post_state_root,
        withdrawal_root,
        &proposed_at_secs.to_le_bytes(),
        &proposer_bond_atoms.to_le_bytes(),
    ])
}

/// Domain-separated signing preimage for `AttestedCommitteeLeg` votes.
///
/// Convenience: exposed for independent re-execution committee signers.
#[must_use]
pub fn committee_vote_sign_bytes(
    network: &str,
    claim: &RollupBatchClaim,
    post_state_root: &[u8; 32],
    withdrawal_root: &[u8; 32],
    measurement_digest: &[u8; 32],
) -> [u8; 32] {
    crate::core::hash::hash_fields_bytes(&[
        DOMAIN_MULTIPROVER_COMMITTEE,
        network.as_bytes(),
        &claim.batch_index.to_le_bytes(),
        &claim.l1_batch_hash,
        &claim.pre_state_root,
        post_state_root,
        withdrawal_root,
        measurement_digest,
    ])
}

/// Serialize `MultiProverEvidence` with canonical `BDLMMP01` header.
///
/// Convenience: exposed for multi-prover aggregators and admission tests.
pub fn encode_multiprover_evidence(bundle: &MultiProverEvidence) -> Result<Vec<u8>, AdapterError> {
    let body = bincode::serialize(bundle).map_err(|e| AdapterError::Malformed {
        offset: 0,
        reason: format!("failed to serialize MultiProver evidence: {e}"),
    })?;
    if body.len().saturating_add(MULTIPROVER_MAGIC.len()) > MAX_MULTIPROVER_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "MultiProver payload exceeds MAX_MULTIPROVER_PAYLOAD_BYTES".into(),
        });
    }
    let mut out = Vec::with_capacity(MULTIPROVER_MAGIC.len() + body.len());
    out.extend_from_slice(MULTIPROVER_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_multiprover_evidence(payload: &[u8]) -> Result<MultiProverEvidence, AdapterError> {
    if payload.len() > MAX_MULTIPROVER_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "MultiProver payload exceeds MAX_MULTIPROVER_PAYLOAD_BYTES".into(),
        });
    }
    let magic = payload.get(..8).ok_or_else(|| AdapterError::Malformed {
        offset: 0,
        reason: "MultiProver payload shorter than 8-byte magic".into(),
    })?;
    if magic != MULTIPROVER_MAGIC {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "MultiProver payload magic mismatch".into(),
        });
    }
    let body = payload.get(8..).ok_or_else(|| AdapterError::Malformed {
        offset: 8,
        reason: "missing MultiProver payload body".into(),
    })?;
    let decoded: MultiProverEvidence = crate::network::bounded_bincode::decode_bounded_bincode(
        body,
        MAX_MULTIPROVER_PAYLOAD_BYTES,
    )
    .map_err(|e| AdapterError::Malformed {
        offset: 8,
        reason: format!("invalid MultiProver evidence encoding: {e}"),
    })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: 8,
            reason: "trailing bytes after canonical MultiProver evidence".into(),
        });
    }
    Ok(decoded)
}

#[derive(Debug, Clone)]
struct VerifiedLeg {
    family: ProverFamily,
    post_state_root: [u8; 32],
    withdrawal_root: [u8; 32],
    pq_safe: bool,
    used_ed25519: bool,
    used_ml_dsa: bool,
    used_stark: bool,
}

fn verify_pinned_config(cfg: &PinnedMultiProverConfig) -> Result<(), AdapterError> {
    if cfg.stark_program_hash == [0u8; 32]
        || cfg.chain_id == 0
        || cfg.challenge_window_secs == 0
        || cfg.min_fault_bond_atoms == 0
        || cfg.expected_measurement == [0u8; 32]
    {
        return Err(AdapterError::ConsensusRule {
            rule: "pinned MultiProver config contains zero security parameter".into(),
        });
    }
    if cfg.committee.is_empty() || cfg.committee.len() > MAX_MULTIPROVER_COMMITTEE {
        return Err(AdapterError::ConsensusRule {
            rule: "pinned MultiProver committee size outside [1, 128]".into(),
        });
    }
    Ok(())
}

fn verify_stark_leg(
    pinned: &PinnedMultiProverConfig,
    claim: &RollupBatchClaim,
    leg: &StarkProverLeg,
) -> Result<VerifiedLeg, AdapterError> {
    if leg.inputs.exit_code != 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver STARK leg exited with non-zero status".into(),
        });
    }
    if crate::prover::is_empty_or_halt_only_program(&leg.program) {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver STARK leg cannot use empty or bare-Halt bytecode".into(),
        });
    }
    // Enforce that `leg.program` itself hashes to `leg.inputs.program_hash`
    // AND equals the governance-pinned program digest before running Plonky3.
    let actual_prog_hash = bud_proof::canonical_set::program_hash_of(&leg.program);
    if !bool::from(actual_prog_hash.ct_eq(&leg.inputs.program_hash))
        || !bool::from(leg.inputs.program_hash.ct_eq(&pinned.stark_program_hash))
    {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver STARK program_hash mismatches pinned guest program".into(),
        });
    }
    if leg.inputs.chain_id != pinned.chain_id {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver STARK chain_id mismatches pinned chain_id".into(),
        });
    }
    if leg.inputs.block_height != claim.batch_index {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver STARK block_height mismatches batch_index".into(),
        });
    }
    if !bool::from(leg.inputs.initial_state_root.ct_eq(&claim.pre_state_root)) {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver STARK initial_state_root mismatches batch pre_state_root".into(),
        });
    }
    if leg.inputs.final_state_root == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver STARK final_state_root is zero".into(),
        });
    }
    if pinned.require_canonical_stark_set {
        bud_proof::DefaultAdapter::verify_canonical_program(
            &leg.envelope,
            &leg.inputs,
            &leg.program,
        )
        .map_err(|e| AdapterError::Crypto {
            what: format!("MultiProver canonical Plonky3 STARK verification failed: {e:?}"),
        })?;
    } else {
        <bud_proof::DefaultAdapter as bud_proof::ProverAdapter>::verify(
            &leg.envelope,
            &leg.inputs,
            &leg.program,
        )
        .map_err(|e| AdapterError::Crypto {
            what: format!("MultiProver Plonky3 STARK verification failed: {e:?}"),
        })?;
    }
    Ok(VerifiedLeg {
        family: ProverFamily::HashStark,
        post_state_root: leg.inputs.final_state_root,
        withdrawal_root: leg.withdrawal_root,
        pq_safe: true,
        used_ed25519: false,
        used_ml_dsa: false,
        used_stark: true,
    })
}

fn verify_fault_leg(
    network: &str,
    pinned: &PinnedMultiProverConfig,
    claim: &RollupBatchClaim,
    leg: &FaultWindowLeg,
    now_secs: u64,
) -> Result<VerifiedLeg, AdapterError> {
    if leg.post_state_root == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver FaultWindow post_state_root is zero".into(),
        });
    }
    if leg.open_challenges > 0 {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "MultiProver FaultWindow has {} unresolved challenge(s)",
                leg.open_challenges
            ),
        });
    }
    if leg.proposer_bond_atoms < pinned.min_fault_bond_atoms {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver FaultWindow proposer bond below pinned minimum".into(),
        });
    }
    if leg.proposed_at_secs < claim.batch_timestamp_secs {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver FaultWindow proposed_at_secs precedes batch_timestamp_secs".into(),
        });
    }
    let matures_at = leg
        .proposed_at_secs
        .checked_add(pinned.challenge_window_secs)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "MultiProver FaultWindow maturity timestamp overflows u64".into(),
        })?;
    if now_secs < matures_at {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "MultiProver FaultWindow challenge period active (now={now_secs} < {matures_at})"
            ),
        });
    }
    let proposer = pinned
        .fault_proposers
        .iter()
        .find(|p| bool::from(p.ed25519_pk.ct_eq(&leg.proposer_ed25519_pk)))
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "MultiProver FaultWindow proposer not in pinned proposer set".into(),
        })?;
    let digest = fault_claim_sign_bytes(
        network,
        claim,
        &leg.post_state_root,
        &leg.withdrawal_root,
        leg.proposed_at_secs,
        leg.proposer_bond_atoms,
    );
    verify_signature(&digest, &leg.proposer_ed25519_sig, &proposer.ed25519_pk).map_err(|_| {
        AdapterError::Crypto {
            what: "invalid Ed25519 signature on MultiProver FaultWindow claim".into(),
        }
    })?;
    let pq_safe = if proposer.pq_pk.is_empty() {
        false
    } else {
        if leg.proposer_pq_sig.is_empty() {
            return Err(AdapterError::Crypto {
                what: "missing mandatory ML-DSA-65 co-signature on MultiProver FaultWindow".into(),
            });
        }
        PqKeyPair::verify(
            &proposer.pq_pk,
            CROSS_DOMAIN_V1,
            &digest,
            &leg.proposer_pq_sig,
        )
        .map_err(|_| AdapterError::Crypto {
            what: "invalid ML-DSA-65 co-signature on MultiProver FaultWindow".into(),
        })?;
        true
    };
    Ok(VerifiedLeg {
        family: ProverFamily::FaultWindow,
        post_state_root: leg.post_state_root,
        withdrawal_root: leg.withdrawal_root,
        pq_safe,
        used_ed25519: true,
        used_ml_dsa: pq_safe,
        used_stark: false,
    })
}

fn verify_committee_leg(
    network: &str,
    pinned: &PinnedMultiProverConfig,
    claim: &RollupBatchClaim,
    leg: &AttestedCommitteeLeg,
) -> Result<VerifiedLeg, AdapterError> {
    if leg.post_state_root == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver committee post_state_root is zero".into(),
        });
    }
    if !bool::from(leg.measurement_digest.ct_eq(&pinned.expected_measurement)) {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver committee measurement_digest mismatches pinned image".into(),
        });
    }
    let mut member_map = BTreeMap::new();
    let mut total_weight = 0u128;
    for m in &pinned.committee {
        if m.ed25519_pk == [0u8; 32] || m.weight == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned MultiProver committee contains zero pubkey or zero weight".into(),
            });
        }
        if member_map.insert(m.ed25519_pk, m).is_some() {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned MultiProver committee contains duplicate pubkey".into(),
            });
        }
        total_weight = total_weight
            .checked_add(u128::from(m.weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "pinned MultiProver committee weight overflows u128".into(),
            })?;
    }
    if leg.signatures.is_empty() || leg.signatures.len() > pinned.committee.len() {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver committee signature count outside [1, committee.len()]".into(),
        });
    }

    let digest = committee_vote_sign_bytes(
        network,
        claim,
        &leg.post_state_root,
        &leg.withdrawal_root,
        &leg.measurement_digest,
    );
    let mut seen = BTreeSet::new();
    let mut signed_weight = 0u128;
    let mut all_pq = true;

    for sig in &leg.signatures {
        if !seen.insert(sig.signer_ed25519_pk) {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate signer in MultiProver committee leg".into(),
            });
        }
        let member =
            member_map
                .get(&sig.signer_ed25519_pk)
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "non-committee signer in MultiProver committee leg".into(),
                })?;
        verify_signature(&digest, &sig.ed25519_sig, &member.ed25519_pk).map_err(|_| {
            AdapterError::Crypto {
                what: "invalid Ed25519 signature in MultiProver committee leg".into(),
            }
        })?;
        if member.pq_pk.is_empty() {
            all_pq = false;
        } else {
            if sig.pq_sig.is_empty() {
                return Err(AdapterError::Crypto {
                    what: "missing mandatory ML-DSA-65 co-signature in MultiProver committee"
                        .into(),
                });
            }
            PqKeyPair::verify(&member.pq_pk, CROSS_DOMAIN_V1, &digest, &sig.pq_sig).map_err(
                |_| AdapterError::Crypto {
                    what: "invalid ML-DSA-65 co-signature in MultiProver committee".into(),
                },
            )?;
        }
        signed_weight = signed_weight
            .checked_add(u128::from(member.weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "MultiProver signed committee weight overflows u128".into(),
            })?;
    }

    if signed_weight.saturating_mul(3) <= total_weight.saturating_mul(2) {
        return Err(AdapterError::ConsensusRule {
            rule: "MultiProver committee signed weight does not exceed strict 2/3".into(),
        });
    }

    Ok(VerifiedLeg {
        family: ProverFamily::PqAttestedCommittee,
        post_state_root: leg.post_state_root,
        withdrawal_root: leg.withdrawal_root,
        pq_safe: all_pq,
        used_ed25519: true,
        used_ml_dsa: all_pq,
        used_stark: false,
    })
}

fn verify_present_legs(
    network: &str,
    pinned: &PinnedMultiProverConfig,
    bundle: &MultiProverEvidence,
    now_secs: u64,
) -> Result<Vec<VerifiedLeg>, AdapterError> {
    verify_pinned_config(pinned)?;
    bundle.claim.validate_non_zero()?;
    let mut legs = Vec::with_capacity(3);
    if let Some(ref stark) = bundle.stark_leg {
        legs.push(verify_stark_leg(pinned, &bundle.claim, stark)?);
    }
    if let Some(ref fault) = bundle.fault_leg {
        legs.push(verify_fault_leg(
            network,
            pinned,
            &bundle.claim,
            fault,
            now_secs,
        )?);
    }
    if let Some(ref committee) = bundle.committee_leg {
        legs.push(verify_committee_leg(
            network,
            pinned,
            &bundle.claim,
            committee,
        )?);
    }
    Ok(legs)
}

/// Cryptographically inspect a `MultiProverEvidence` bundle for an internal
/// soundness contradiction between any two independently verified prover legs
/// over the exact same `(batch_index, l1_batch_hash, pre_state_root)`.
///
/// Convenience: exposed for `ConsensusSentry` bug-isolation and domain freezing.
pub fn detect_prover_disagreement(
    network: &str,
    pinned: &PinnedMultiProverConfig,
    bundle: &MultiProverEvidence,
    now_secs: u64,
) -> Result<Option<MultiProverDisagreement>, AdapterError> {
    let legs = verify_present_legs(network, pinned, bundle, now_secs)?;
    for (idx, first) in legs.iter().enumerate() {
        for second in legs.iter().skip(idx + 1) {
            let roots_match = bool::from(first.post_state_root.ct_eq(&second.post_state_root))
                && bool::from(first.withdrawal_root.ct_eq(&second.withdrawal_root));
            if !roots_match {
                return Ok(Some(MultiProverDisagreement {
                    batch_index: bundle.claim.batch_index,
                    l1_batch_hash: bundle.claim.l1_batch_hash,
                    pre_state_root: bundle.claim.pre_state_root,
                    first: (first.family, first.post_state_root, first.withdrawal_root),
                    second: (
                        second.family,
                        second.post_state_root,
                        second.withdrawal_root,
                    ),
                }));
            }
        }
    }
    Ok(None)
}

/// External finality adapter enforcing `2-of-3` heterogeneous multi-prover agreement.
pub struct HeterogeneousMultiProverAdapter {
    network: String,
    pinned: Option<PinnedMultiProverConfig>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl HeterogeneousMultiProverAdapter {
    /// Construct a `HeterogeneousMultiProverAdapter` bound to `network` and `pinned`.
    ///
    /// Convenience: exposed for Stage-2 rollup domain registration.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedMultiProverConfig>) -> Self {
        Self {
            network: network.into(),
            pinned,
            golden: None,
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name(ADAPTER_NAME),
                name: ADAPTER_NAME.to_string(),
                adapter_version: ADAPTER_VERSION,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "heterogeneous-multiprover-2of3".to_string(),
                finality_kind: FinalityKind::Proven,
                required_depth: 0,
                time_unit: TimeUnit::UnixSeconds,
                trust_model: TrustModel::Trustless,
            },
        }
    }

    /// Attach a golden `2-of-3` bundle for self-test admission probing.
    ///
    /// Convenience: exposed for `selftest::admit` callers.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn verify_inner(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, Vec<VerifiedLeg>), AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: hex::encode(evidence.adapter.as_bytes()),
            });
        }
        if evidence.evidence_version != EVIDENCE_VERSION {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: EVIDENCE_VERSION.to_string(),
            });
        }
        // Fail-closed: an adapter bound to an empty (or whitespace-only)
        // network label is a configuration error. Without this guard the
        // `evidence.network != self.network` comparison below would treat
        // `"" == ""` as a match and accept any payload that also carries an
        // empty network, silently turning the adapter into an
        // accept-everything end. Reject every payload instead.
        if self.network.trim().is_empty() {
            return Err(AdapterError::ConsensusRule {
                rule: "HeterogeneousMultiProverAdapter network identifier must not be empty".into(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "MultiProver evidence network '{}' mismatches pinned '{}'",
                    evidence.network, self.network
                ),
            });
        }
        let pinned = self
            .pinned
            .as_ref()
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "MultiProver config not pinned; fail-closed".into(),
            })?;

        let bundle = decode_multiprover_evidence(&evidence.payload)?;
        if policy.require_declared_match {
            if evidence.declared_height != bundle.claim.batch_index {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&bundle.claim.post_state_root)) {
                return Err(AdapterError::DeclarationMismatch { field: "root" });
            }
        }
        if policy.max_age > 0 && policy.now > bundle.claim.batch_timestamp_secs {
            let age = policy.now - bundle.claim.batch_timestamp_secs;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let legs = verify_present_legs(&self.network, pinned, &bundle, policy.now)?;
        if legs.len() < REQUIRED_PROVER_FAMILIES {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "MultiProver requires >= {REQUIRED_PROVER_FAMILIES} independent verified legs; got {}",
                    legs.len()
                ),
            });
        }

        // Fail-closed unanimity across every verified leg: any disagreement with
        // the claimed `(post_state_root, withdrawal_root)` reveals a live prover
        // soundness fault and immediately blocks settlement.
        for leg in &legs {
            if !bool::from(leg.post_state_root.ct_eq(&bundle.claim.post_state_root))
                || !bool::from(leg.withdrawal_root.ct_eq(&bundle.claim.withdrawal_root))
            {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "MultiProver disagreement detected: {:?} disagrees with claimed batch roots",
                        leg.family
                    ),
                });
            }
        }

        if pinned.require_pq_leg && !legs.iter().any(|l| l.pq_safe) {
            return Err(AdapterError::ConsensusRule {
                rule: "MultiProver policy requires at least one post-quantum verified leg".into(),
            });
        }

        let transition_digest = bundle.claim.transition_digest(&self.network);
        let has_stark = legs.iter().any(|l| l.family == ProverFamily::HashStark);
        let security = if has_stark {
            SecurityBacking::Zk {
                system: ProofSystem::BudlumZkVm,
                public_inputs_digest: transition_digest,
            }
        } else {
            let all_pq = legs.iter().all(|l| l.pq_safe);
            let scheme = if all_pq {
                ObservedScheme::Scheme(SchemeId::ML_DSA_65)
            } else {
                ObservedScheme::Scheme(SchemeId::ED25519)
            };
            let total_weight = pinned
                .committee
                .iter()
                .fold(0u128, |acc, m| acc.saturating_add(u128::from(m.weight)));
            let req = total_weight
                .saturating_mul(2)
                .saturating_div(3)
                .saturating_add(1);
            SecurityBacking::SignatureSet {
                scheme,
                signers: u64::try_from(legs.len()).unwrap_or(2),
                required: u64::try_from(req).unwrap_or(u64::MAX),
                total_weight,
                // External rollup fault bonds and re-execution committees have no
                // local Budlum confiscation arm in BridgeEconomicGuard yet.
                slashable: false,
            }
        };
        if policy.require_slashable {
            return Err(AdapterError::UnslashableBacking);
        }
        let att = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: bundle.claim.batch_index,
            state_root: bundle.claim.post_state_root,
            finalized_at: bundle.claim.batch_timestamp_secs,
            time_unit: TimeUnit::UnixSeconds,
            security,
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(bundle.claim.l1_batch_hash),
            attested_event_root: Some(bundle.claim.withdrawal_root),
            attested_tx_root: None,
        };
        Ok((att, legs))
    }
}

impl ExternalFinalityAdapter for HeterogeneousMultiProverAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn has_pinned_trust_anchor(&self) -> bool {
        self.pinned.is_some()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        self.verify_inner(evidence, policy).map(|(att, _)| att)
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        let (att, legs) = self.verify_inner(evidence, policy)?;
        if legs.iter().any(|l| l.used_stark) {
            observer.observe(ObservedScheme::Scheme(SchemeId::BUDZERO_STARK_V2));
        }
        if legs.iter().any(|l| l.used_ed25519) {
            observer.observe(ObservedScheme::Scheme(SchemeId::ED25519));
        }
        if legs.iter().any(|l| l.used_ml_dsa) {
            observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        }
        Ok(att)
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let sig_tail = self
            .golden
            .as_ref()
            .map_or(24, |g| g.payload.len().saturating_sub(24));
        vec![
            FaultProbe {
                name: "multiprover_bad_magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0xFF],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "multiprover_truncated".into(),
                patch: BytePatch::TruncatePayload { keep: 10 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "multiprover_corrupted_claim_prefix".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0x00; 8],
                },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "multiprover_corrupted_signature_tail".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail,
                    bytes: vec![0xAA, 0x55, 0xCC, 0x33],
                },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "multiprover_declared_height_mismatch".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "multiprover_declared_root_mismatch".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "multiprover_bad_version".into(),
                patch: BytePatch::EvidenceVersion { value: 9 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "multiprover_foreign_network".into(),
                patch: BytePatch::Network {
                    value: "rollup-impostor".into(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::selftest::admit;
    use crate::crypto::facts::CryptoFacts;
    use crate::crypto::primitives::KeyPair;
    use bud_proof::ProverAdapter;

    const NET: &str = "budlum-stage2-rollup";
    const CHAIN_ID: u64 = 45_261;
    const BATCH_INDEX: u64 = 42;
    const BATCH_TS: u64 = 1_750_000_000;
    const WINDOW_SECS: u64 = 604_800; // 7 days

    struct MultiProverFixture {
        pinned: PinnedMultiProverConfig,
        claim: RollupBatchClaim,
        stark: StarkProverLeg,
        fault_key: (KeyPair, PqKeyPair),
        committee_keys: Vec<(KeyPair, PqKeyPair)>,
        measurement: [u8; 32],
    }

    fn build_real_stark_leg() -> (StarkProverLeg, [u8; 32], [u8; 32], [u8; 32]) {
        use bud_isa::{Instruction, Opcode};
        let enc = |opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32| {
            Instruction {
                opcode,
                rd,
                rs1,
                rs2,
                imm,
            }
            .encode()
        };
        // Canonical state-writing rollup batch transition guest:
        // reads pre-state register r3, folds batch delta 42 into r2, commits
        // SWrite into the AIR-constrained storage fold, and halts cleanly.
        let program = vec![
            enc(Opcode::Load, 1, 0, 0, 7),
            enc(Opcode::Load, 2, 0, 0, 42),
            enc(Opcode::Add, 2, 2, 3, 0),
            enc(Opcode::SWrite, 0, 2, 1, -1),
            enc(Opcode::Halt, 0, 0, 0, 0),
        ];
        let program_hash = bud_proof::canonical_set::program_hash_of(&program);
        let mut vm = bud_vm::Vm::new(10_000);
        vm.registers[3] = 0x5EED_0042;
        vm.context.block_height = BATCH_INDEX;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "rollup batch guest must halt cleanly");
        let pre_root = bud_proof::initial_state_root_of(
            bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(
                &vm.trace,
            )),
            bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
                &vm.trace,
            )),
        );
        assert_ne!(
            pre_root, [0u8; 32],
            "seeded register read binds non-zero pre_root"
        );
        // AIR binds final_state_root to the exact SWrite storage-writes fold.
        let post_root = receipt.state_writes_digest;
        assert_ne!(post_root, [0u8; 32], "SWrite must commit a non-zero root");
        let withdrawal_root = [0xE5; 32];
        let inputs = ExecutionPublicInputs {
            chain_id: CHAIN_ID,
            program_hash,
            initial_state_root: pre_root,
            final_state_root: post_root,
            sender: vm.context.sender,
            nonce: vm.context.nonce,
            block_height: BATCH_INDEX,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: bud_proof::event_digest_from_events(&receipt.events),
            state_writes_digest: post_root,
        };
        let envelope =
            bud_proof::DefaultAdapter::prove(&vm.trace, &inputs, &program).expect("STARK proves");
        <bud_proof::DefaultAdapter as bud_proof::ProverAdapter>::verify(
            &envelope, &inputs, &program,
        )
        .expect("STARK verifies");
        let leg = StarkProverLeg {
            program,
            inputs,
            envelope,
            withdrawal_root,
        };
        (leg, program_hash, pre_root, post_root)
    }

    fn sign_fault_leg(
        fx: &MultiProverFixture,
        post_root: [u8; 32],
        withdrawal_root: [u8; 32],
    ) -> FaultWindowLeg {
        let proposed_at_secs = BATCH_TS + 60;
        let bond = 50_000u128;
        let digest = fault_claim_sign_bytes(
            NET,
            &fx.claim,
            &post_root,
            &withdrawal_root,
            proposed_at_secs,
            bond,
        );
        FaultWindowLeg {
            post_state_root: post_root,
            withdrawal_root,
            proposed_at_secs,
            proposer_bond_atoms: bond,
            open_challenges: 0,
            proposer_ed25519_pk: fx.fault_key.0.public_key_bytes(),
            proposer_ed25519_sig: fx.fault_key.0.sign(&digest).to_vec(),
            proposer_pq_sig: fx.fault_key.1.sign(CROSS_DOMAIN_V1, &digest).unwrap(),
        }
    }

    fn sign_committee_leg(
        fx: &MultiProverFixture,
        post_root: [u8; 32],
        withdrawal_root: [u8; 32],
    ) -> AttestedCommitteeLeg {
        let digest = committee_vote_sign_bytes(
            NET,
            &fx.claim,
            &post_root,
            &withdrawal_root,
            &fx.measurement,
        );
        // 3 of 4 equal-weight members = 75% > 2/3.
        let signatures = fx
            .committee_keys
            .iter()
            .take(3)
            .map(|(ed, pq)| CommitteeAttestationSig {
                signer_ed25519_pk: ed.public_key_bytes(),
                ed25519_sig: ed.sign(&digest).to_vec(),
                pq_sig: pq.sign(CROSS_DOMAIN_V1, &digest).unwrap(),
            })
            .collect();
        AttestedCommitteeLeg {
            post_state_root: post_root,
            withdrawal_root,
            measurement_digest: fx.measurement,
            signatures,
        }
    }

    fn make_fixture() -> MultiProverFixture {
        let (stark, program_hash, pre_root, post_root) = build_real_stark_leg();
        let fault_key = (KeyPair::generate().unwrap(), PqKeyPair::generate());
        let committee_keys: Vec<_> = (0..4)
            .map(|_| (KeyPair::generate().unwrap(), PqKeyPair::generate()))
            .collect();
        let measurement = [0x7A; 32];
        let pinned = PinnedMultiProverConfig {
            stark_program_hash: program_hash,
            chain_id: CHAIN_ID,
            challenge_window_secs: WINDOW_SECS,
            min_fault_bond_atoms: 10_000,
            fault_proposers: vec![PinnedFaultProposer {
                ed25519_pk: fault_key.0.public_key_bytes(),
                pq_pk: fault_key.1.public_key_bytes().to_vec(),
            }],
            expected_measurement: measurement,
            committee: committee_keys
                .iter()
                .map(|(ed, pq)| MultiProverCommitteeMember {
                    ed25519_pk: ed.public_key_bytes(),
                    pq_pk: pq.public_key_bytes().to_vec(),
                    weight: 25,
                })
                .collect(),
            require_canonical_stark_set: false,
            require_pq_leg: true,
        };
        let claim = RollupBatchClaim {
            batch_index: BATCH_INDEX,
            l1_batch_hash: [0xC3; 32],
            pre_state_root: pre_root,
            post_state_root: post_root,
            withdrawal_root: stark.withdrawal_root,
            batch_timestamp_secs: BATCH_TS,
        };
        MultiProverFixture {
            pinned,
            claim,
            stark,
            fault_key,
            committee_keys,
            measurement,
        }
    }

    #[test]
    fn empty_network_adapter_refuses_evidence_fail_closed() {
        // An adapter constructed with an empty network label is a
        // configuration error. It must refuse every evidence payload
        // fail-closed instead of accepting payloads that also carry an
        // empty network (where `"" == ""` would otherwise match).
        let adapter = HeterogeneousMultiProverAdapter::new("", None);
        let raw = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: String::new(),
            payload: Vec::new(),
            declared_height: 0,
            declared_root: [0u8; 32],
            submitter: crate::core::address::Address([0u8; 32]),
        };
        let err = adapter
            .verify(&raw, &VerificationPolicy::strict(0))
            .unwrap_err();
        assert!(
            matches!(err, AdapterError::ConsensusRule { rule } if rule.contains("empty")),
            "empty-network adapter must refuse fail-closed, got {err:?}"
        );
    }

    #[test]
    fn multiprover_settles_instant_stark_plus_pq_committee_and_passes_admission() {
        let fx = make_fixture();
        let committee = sign_committee_leg(&fx, fx.claim.post_state_root, fx.claim.withdrawal_root);
        let bundle = MultiProverEvidence {
            claim: fx.claim.clone(),
            stark_leg: Some(fx.stark.clone()),
            fault_leg: None, // Instant settlement before 7-day fault window!
            committee_leg: Some(committee),
        };
        let golden = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            network: NET.into(),
            evidence_version: EVIDENCE_VERSION,
            declared_height: fx.claim.batch_index,
            declared_root: fx.claim.post_state_root,
            payload: encode_multiprover_evidence(&bundle).unwrap(),
            submitter: crate::core::address::Address([0x09; 32]),
        };
        let adapter =
            HeterogeneousMultiProverAdapter::new(NET, Some(fx.pinned)).with_golden(golden.clone());
        let policy = VerificationPolicy {
            min_depth: 0,
            max_age: 3_600,
            now: BATCH_TS + 12,
            require_declared_match: true,
            require_slashable: false,
        };

        let report = admit(&adapter, &policy);
        assert!(report.admitted, "MultiProver admission failed: {report:?}");

        let mut facts = CryptoFacts::default();
        let att = adapter
            .verify_observed(&golden, &policy, &mut facts)
            .unwrap();
        assert_eq!(att.height, BATCH_INDEX);
        assert_eq!(att.state_root, fx.claim.post_state_root);
        assert_eq!(att.attested_event_root, Some(fx.claim.withdrawal_root));
        assert_eq!(
            facts.count(ObservedScheme::Scheme(SchemeId::BUDZERO_STARK_V2)),
            1
        );
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ED25519)), 1);
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)), 1);
    }

    #[test]
    fn multiprover_refuses_single_leg_premature_fault_window_and_halts_on_disagreement() {
        let fx = make_fixture();
        let adapter = HeterogeneousMultiProverAdapter::new(NET, Some(fx.pinned.clone()));

        // 1. Single STARK leg alone is refused (guards against single-prover AIR bugs).
        let single = MultiProverEvidence {
            claim: fx.claim.clone(),
            stark_leg: Some(fx.stark.clone()),
            fault_leg: None,
            committee_leg: None,
        };
        let ev_single = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            network: NET.into(),
            evidence_version: EVIDENCE_VERSION,
            declared_height: fx.claim.batch_index,
            declared_root: fx.claim.post_state_root,
            payload: encode_multiprover_evidence(&single).unwrap(),
            submitter: crate::core::address::Address([0x09; 32]),
        };
        let early_policy = VerificationPolicy {
            min_depth: 0,
            max_age: 0,
            now: BATCH_TS + 120,
            require_declared_match: true,
            require_slashable: false,
        };
        assert!(matches!(
            adapter.verify(&ev_single, &early_policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("independent verified legs")
        ));

        // 2. FaultWindow + STARK fails before 7-day window elapses, succeeds right after.
        let fault = sign_fault_leg(&fx, fx.claim.post_state_root, fx.claim.withdrawal_root);
        let stark_fault = MultiProverEvidence {
            claim: fx.claim.clone(),
            stark_leg: Some(fx.stark.clone()),
            fault_leg: Some(fault.clone()),
            committee_leg: None,
        };
        let ev_sf = RawConsensusEvidence {
            payload: encode_multiprover_evidence(&stark_fault).unwrap(),
            ..ev_single.clone()
        };
        assert!(matches!(
            adapter.verify(&ev_sf, &early_policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("challenge period active")
        ));
        let mature_policy = VerificationPolicy {
            now: BATCH_TS + 60 + WINDOW_SECS,
            ..early_policy
        };
        assert!(adapter.verify(&ev_sf, &mature_policy).is_ok());

        // 3. 2-vs-1 split (STARK + Fault certify 0xD4, valid Committee certifies 0xFE):
        //    verify() refuses settlement AND detect_prover_disagreement isolates the conflict!
        let conflicting_committee = sign_committee_leg(&fx, [0xFE; 32], fx.claim.withdrawal_root);
        let split = MultiProverEvidence {
            claim: fx.claim.clone(),
            stark_leg: Some(fx.stark),
            fault_leg: Some(fault),
            committee_leg: Some(conflicting_committee),
        };
        let ev_split = RawConsensusEvidence {
            payload: encode_multiprover_evidence(&split).unwrap(),
            ..ev_single
        };
        assert!(matches!(
            adapter.verify(&ev_split, &mature_policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("disagreement detected")
        ));
        let conflict = detect_prover_disagreement(NET, &fx.pinned, &split, mature_policy.now)
            .unwrap()
            .expect("must isolate conflicting prover families");
        assert_eq!(conflict.batch_index, BATCH_INDEX);
        assert_eq!(conflict.first.0, ProverFamily::HashStark);
        assert_eq!(conflict.second.0, ProverFamily::PqAttestedCommittee);
        assert_ne!(conflict.first.1, conflict.second.1);

        // 4. Non-STARK signature quorum (FaultWindow + Committee) reports slashable=false
        //    and refuses require_slashable=true without a local Budlum confiscation arm.
        let fx2 = make_fixture();
        let fault2 = sign_fault_leg(&fx2, fx2.claim.post_state_root, fx2.claim.withdrawal_root);
        let committee2 =
            sign_committee_leg(&fx2, fx2.claim.post_state_root, fx2.claim.withdrawal_root);
        let non_stark = MultiProverEvidence {
            claim: fx2.claim.clone(),
            stark_leg: None,
            fault_leg: Some(fault2),
            committee_leg: Some(committee2),
        };
        let non_stark_raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            network: NET.into(),
            evidence_version: EVIDENCE_VERSION,
            declared_height: fx2.claim.batch_index,
            declared_root: fx2.claim.post_state_root,
            payload: encode_multiprover_evidence(&non_stark).unwrap(),
            submitter: crate::core::address::Address([0x09; 32]),
        };
        let adapter2 = HeterogeneousMultiProverAdapter::new(NET, Some(fx2.pinned));
        let att2 = adapter2
            .verify(&non_stark_raw, &mature_policy)
            .expect("mature fault+committee quorum verifies when slashability is not required");
        assert!(
            matches!(
                att2.security,
                SecurityBacking::SignatureSet {
                    slashable: false,
                    ..
                }
            ),
            "non-STARK committee+fault quorum without a local Budlum confiscation arm must report slashable=false"
        );
        let mut slash_policy = mature_policy;
        slash_policy.require_slashable = true;
        assert!(
            matches!(
                adapter2.verify(&non_stark_raw, &slash_policy),
                Err(AdapterError::UnslashableBacking)
            ),
            "require_slashable=true must fail closed with UnslashableBacking"
        );
    }
}
