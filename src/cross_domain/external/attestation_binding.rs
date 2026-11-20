//! Fail-closed cryptographic binding between external [`FinalityAttestation`]
//! records, [`IntakeState::state_digest`], and `GlobalBlockHeader::external_intake_root`.
//!
//! An external adapter proves only that raw consensus bytes satisfy its
//! declared verification rule. Before a settlement consumer, bridge route, or
//! global finality certificate trusts an external `(domain, height, state_root)`
//! claim, five consensus-level invariants must hold simultaneously:
//!
//! 1. The settlement header carries `external_intake_root = Some(root)` matching
//!    `intake.state_digest()` in constant time.
//! 2. `domain` is registered in `intake.registry` and its [`DomainState::serves`]
//!    gate is open (`Admitted` or `Active` - never `Faulted`, `Retired`, or
//!    `QuantumIsolated`).
//! 3. Neither the domain cooldown circuit breaker ([`IntakeGuard::check_submission`])
//!    nor the contradicted-claim tombstone ledger ([`IntakeGuard::check_claim_allowed`])
//!    blocks the claim at `local_height`.
//! 4. `(height, evidence_version)` exists in `reg.attestations` with matching
//!    `state_root` and `evidence_digest` in constant time, and if `domain` runs
//!    under a [`QuorumPolicy`], `reg.is_quorum_decided(...)` is `true`.
//! 5. The bound [`FinalityGuarantee`] equals the canonical guarantee derived
//!    from `IntakeEntry::spec`, satisfies `admits_cross_domain_value()`, and
//!    verifies inside a canonical [`GlobalFinalityCertificate`].
//!
//! WIRING: Exercised at adapter admission self-test (`selftest::admit_observed`)
//! and exposed at `crate::cross_domain::external` for settlement consumers.

use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::external::intake::IntakeState;
use crate::cross_domain::external::profile::DomainState;
use crate::cross_domain::external::spec::{DomainKey, FinalityAttestation};
use crate::settlement::domains::CommitmentAttestation;
use crate::settlement::universal_finality::{
    compose_with_bar, DomainFinalityEntry, FinalityComposeError, FinalityGuarantee,
    FinalityPendingReason, FinalityVerdict, GlobalFinalityCertificate,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Minimum commitment bar required when binding an external finality attestation
/// into a settlement certificate: the external `state_root` (or header chain tip
/// commitment mapped into `state_root`) must be cryptographically bound.
pub const EXTERNAL_STATE_ROOT_BAR: CommitmentAttestation = CommitmentAttestation {
    state_root: true,
    tx_root: false,
    event_root: false,
    parent: false,
};

/// Cryptographic binding record linking one accepted external
/// [`FinalityAttestation`] to the authoritative [`IntakeState`] digest and a
/// single-domain [`GlobalFinalityCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalAttestationBindingProof {
    /// Registered external domain key.
    pub domain: DomainKey,
    /// Settlement registry slot (`0..16`) assigned to this domain in the certificate.
    pub settlement_domain_id: u16,
    /// External chain height of the bound attestation.
    pub height: u64,
    /// Declared adapter evidence version under which the attestation was verified.
    pub evidence_version: u32,
    /// Finalized external state root committed by the attestation.
    pub state_root: [u8; 32],
    /// Evidence digest of the accepted attestation.
    pub evidence_digest: [u8; 32],
    /// Canonical [`FinalityGuarantee`] derived from the registered [`IntakeState`] entry.
    pub guarantee: FinalityGuarantee,
    /// Expected `GlobalBlockHeader::external_intake_root` (`IntakeState::state_digest`).
    pub expected_intake_root: [u8; 32],
    /// Derived [`GlobalFinalityCertificate`] committing to this domain entry.
    pub certificate: GlobalFinalityCertificate,
    /// Domain-separated commitment over the intake root, attestation claim, and certificate.
    pub binding_digest: [u8; 32],
}

/// Fail-closed refusal reasons returned when constructing or verifying an
/// [`ExternalAttestationBindingProof`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationBindingError {
    #[error("settlement block header carries no external_intake_root")]
    MissingHeaderIntakeRoot,
    #[error("failed to compute canonical IntakeState digest: {0}")]
    IntakeStateDigestFailed(String),
    #[error("header external_intake_root disagrees with live IntakeState::state_digest")]
    IntakeRootMismatch,
    #[error("external domain is not registered in IntakeState")]
    DomainNotRegistered,
    #[error("external domain state `{0}` does not serve attestations")]
    DomainNotServing(&'static str),
    #[error("external domain cooldown circuit breaker active until local block {until_block}")]
    IntakeCooldownActive { until_block: u64 },
    #[error("external attestation claim matches a contradicted-claim tombstone")]
    ContradictedClaimTombstoned,
    #[error("no accepted attestation at height {height} version {evidence_version}")]
    AttestationNotFound { height: u64, evidence_version: u32 },
    #[error("bound state_root disagrees with accepted FinalityAttestation")]
    StateRootMismatch,
    #[error("bound evidence_digest disagrees with accepted FinalityAttestation")]
    EvidenceDigestMismatch,
    #[error("domain runs under a QuorumPolicy but height {height} is not quorum-decided")]
    QuorumNotFinalized { height: u64 },
    #[error("bound FinalityGuarantee disagrees with registered AdapterSpec")]
    GuaranteeMismatch,
    #[error("external domain guarantee does not admit cross-domain value transfer")]
    ValueUnsafeGuarantee,
    #[error(
        "settlement certificate composition failed (resubmittable={resubmittable}): {error:?}"
    )]
    CertificateInvalid {
        error: FinalityComposeError,
        resubmittable: bool,
    },
    #[error("binding_digest disagrees with canonical BDLM_EXT_ATTEST_BIND_V1 commitment")]
    BindingDigestMismatch,
}

#[must_use]
fn certificate_root_commitment(
    expected_intake_root: &[u8; 32],
    certificate: &GlobalFinalityCertificate,
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_EXT_CERT_ROOT_V1",
        expected_intake_root,
        &certificate.domain_commitment,
        &certificate.certificate_digest,
    ])
}

#[must_use]
fn compute_binding_digest(
    domain: &DomainKey,
    settlement_domain_id: u16,
    att: &FinalityAttestation,
    expected_intake_root: &[u8; 32],
    certificate: &GlobalFinalityCertificate,
) -> [u8; 32] {
    let claim = att.claim_digest();
    let cert_root = certificate_root_commitment(expected_intake_root, certificate);
    hash_fields_bytes(&[
        b"BDLM_EXT_ATTEST_BIND_V1",
        domain.as_bytes(),
        &settlement_domain_id.to_be_bytes(),
        &att.height.to_be_bytes(),
        &att.evidence_version.to_be_bytes(),
        &att.state_root,
        &att.evidence_digest,
        &claim,
        &cert_root,
    ])
}

fn canonical_guarantee_for(
    intake: &IntakeState,
    domain: &DomainKey,
) -> Result<FinalityGuarantee, AttestationBindingError> {
    let entry = intake
        .entries
        .get(domain)
        .ok_or(AttestationBindingError::DomainNotRegistered)?;
    let mut guarantee = FinalityGuarantee::for_external_spec(&entry.spec);
    // Bitcoin SPV headers commit to the chain tip inside `FinalityAttestation::state_root`
    // (`attested_block_hash`), so once verified in `IntakeState` we preserve its exact
    // attestation flags unless `state_root` is required via `header_bar_for`.
    let _ = &mut guarantee;
    Ok(guarantee)
}

#[must_use]
const fn required_bar_for(guarantee: &FinalityGuarantee) -> CommitmentAttestation {
    if guarantee.attestation.state_root {
        EXTERNAL_STATE_ROOT_BAR
    } else {
        CommitmentAttestation {
            state_root: false,
            tx_root: guarantee.attestation.tx_root,
            event_root: false,
            parent: guarantee.attestation.parent,
        }
    }
}

fn check_domain_and_attestation<'a>(
    intake: &'a IntakeState,
    domain: &DomainKey,
    height: u64,
    evidence_version: u32,
    local_height: u64,
) -> Result<(&'a FinalityAttestation, FinalityGuarantee), AttestationBindingError> {
    let reg = intake
        .registry
        .domain(domain)
        .ok_or(AttestationBindingError::DomainNotRegistered)?;
    let state: DomainState = reg.record.state;
    if !state.serves() {
        return Err(AttestationBindingError::DomainNotServing(state.as_str()));
    }
    intake
        .guard
        .check_submission(domain, local_height)
        .map_err(|err| {
            match err {
            crate::cross_domain::external::intake_guard::IntakeGuardError::CooldownActive {
                cooldown_until,
                ..
            } => AttestationBindingError::IntakeCooldownActive {
                until_block: cooldown_until,
            },
            crate::cross_domain::external::intake_guard::IntakeGuardError::ContradictedClaimReplay {
                ..
            } => AttestationBindingError::ContradictedClaimTombstoned,
        }
        })?;

    let att = reg.attestations.get(&(height, evidence_version)).ok_or(
        AttestationBindingError::AttestationNotFound {
            height,
            evidence_version,
        },
    )?;

    let claim_digest = att.claim_digest();
    intake
        .guard
        .check_claim_allowed(domain, height, evidence_version, &claim_digest)
        .map_err(|_| AttestationBindingError::ContradictedClaimTombstoned)?;

    if intake.quorum.policy_of(domain).is_some()
        && !reg.is_quorum_decided(height, evidence_version, &att.state_root)
    {
        return Err(AttestationBindingError::QuorumNotFinalized { height });
    }

    let guarantee = canonical_guarantee_for(intake, domain)?;
    if !guarantee.admits_cross_domain_value() {
        return Err(AttestationBindingError::ValueUnsafeGuarantee);
    }

    Ok((att, guarantee))
}

/// Construct a canonical [`ExternalAttestationBindingProof`] from an accepted
/// attestation inside `intake` at `local_height`.
///
/// # Errors
///
/// Fails closed if the domain is missing, non-serving, cooling down, tombstoned,
/// missing quorum finality, value-unsafe, or outside the 16-domain certificate mask.
pub fn build_external_attestation_binding(
    intake: &IntakeState,
    domain: DomainKey,
    settlement_domain_id: u16,
    height: u64,
    evidence_version: u32,
    local_height: u64,
) -> Result<ExternalAttestationBindingProof, AttestationBindingError> {
    let expected_intake_root = intake
        .state_digest()
        .map_err(AttestationBindingError::IntakeStateDigestFailed)?;
    let (att, guarantee) =
        check_domain_and_attestation(intake, &domain, height, evidence_version, local_height)?;

    let entry = DomainFinalityEntry {
        domain_id: settlement_domain_id,
        height: att.height,
        state_root: att.state_root,
        guarantee,
        verdict: FinalityVerdict::Established,
    };
    let bar = required_bar_for(&guarantee);
    let certificate = compose_with_bar(&[entry], bar).map_err(|error| {
        AttestationBindingError::CertificateInvalid {
            resubmittable: error.is_resubmittable(),
            error,
        }
    })?;
    let binding_digest = compute_binding_digest(
        &domain,
        settlement_domain_id,
        att,
        &expected_intake_root,
        &certificate,
    );

    Ok(ExternalAttestationBindingProof {
        domain,
        settlement_domain_id,
        height: att.height,
        evidence_version: att.evidence_version,
        state_root: att.state_root,
        evidence_digest: att.evidence_digest,
        guarantee,
        expected_intake_root,
        certificate,
        binding_digest,
    })
}

/// Verify an [`ExternalAttestationBindingProof`] fail-closed against the
/// settlement block header's `external_intake_root` and live [`IntakeState`].
///
/// # Errors
///
/// Returns [`AttestationBindingError`] on any missing or mismatched header root,
/// non-serving or cooling-down domain, tombstoned claim, unfinalized quorum
/// round, tampered root/guarantee/certificate, or forged binding digest.
pub fn verify_external_attestation_binding(
    proof: &ExternalAttestationBindingProof,
    header_external_intake_root: Option<&[u8; 32]>,
    intake: &IntakeState,
    local_height: u64,
) -> Result<(), AttestationBindingError> {
    let header_root =
        header_external_intake_root.ok_or(AttestationBindingError::MissingHeaderIntakeRoot)?;
    let live_intake_root = intake
        .state_digest()
        .map_err(AttestationBindingError::IntakeStateDigestFailed)?;
    if !bool::from(header_root.ct_eq(&live_intake_root))
        || !bool::from(proof.expected_intake_root.ct_eq(&live_intake_root))
    {
        return Err(AttestationBindingError::IntakeRootMismatch);
    }

    let (att, canonical_guarantee) = check_domain_and_attestation(
        intake,
        &proof.domain,
        proof.height,
        proof.evidence_version,
        local_height,
    )?;

    if !bool::from(proof.state_root.ct_eq(&att.state_root)) {
        return Err(AttestationBindingError::StateRootMismatch);
    }
    if !bool::from(proof.evidence_digest.ct_eq(&att.evidence_digest)) {
        return Err(AttestationBindingError::EvidenceDigestMismatch);
    }
    if proof.guarantee != canonical_guarantee {
        return Err(AttestationBindingError::GuaranteeMismatch);
    }

    let entry = DomainFinalityEntry {
        domain_id: proof.settlement_domain_id,
        height: proof.height,
        state_root: proof.state_root,
        guarantee: canonical_guarantee,
        verdict: FinalityVerdict::Established,
    };
    let bar = required_bar_for(&canonical_guarantee);
    if !proof.certificate.verify_against_with_bar(&[entry], bar) {
        let err = compose_with_bar(&[entry], bar).err().unwrap_or(
            FinalityComposeError::DomainNotEstablished {
                domain_id: proof.settlement_domain_id,
                reason: FinalityPendingReason::AttestationUnbound,
            },
        );
        return Err(AttestationBindingError::CertificateInvalid {
            resubmittable: err.is_resubmittable(),
            error: err,
        });
    }

    let expected_binding = compute_binding_digest(
        &proof.domain,
        proof.settlement_domain_id,
        att,
        &live_intake_root,
        &proof.certificate,
    );
    if !bool::from(proof.binding_digest.ct_eq(&expected_binding)) {
        return Err(AttestationBindingError::BindingDigestMismatch);
    }
    Ok(())
}

/// Lightweight deterministic invariant check run during adapter admission so
/// broken hash tags, certificate checks, or missing-root refusals fail closed
/// immediately rather than silently passing admission.
#[must_use]
pub fn check_attestation_binding_invariants() -> bool {
    let empty_intake = IntakeState::default();
    let missing_domain = DomainKey([0xA5; 32]);
    let build_refused =
        build_external_attestation_binding(&empty_intake, missing_domain, 0, 1, 1, 1).is_err();

    let guarantee = FinalityGuarantee::settlement_hub();
    let sample_entry = DomainFinalityEntry {
        domain_id: 0,
        height: 1,
        state_root: [0x11; 32],
        guarantee,
        verdict: FinalityVerdict::Established,
    };
    let Ok(cert) = compose_with_bar(&[sample_entry], EXTERNAL_STATE_ROOT_BAR) else {
        return false;
    };
    let synthetic = ExternalAttestationBindingProof {
        domain: missing_domain,
        settlement_domain_id: 0,
        height: 1,
        evidence_version: 1,
        state_root: [0x11; 32],
        evidence_digest: [0x22; 32],
        guarantee,
        expected_intake_root: [0x33; 32],
        certificate: cert,
        binding_digest: [0x44; 32],
    };
    let missing_header_refused = matches!(
        verify_external_attestation_binding(&synthetic, None, &empty_intake, 1),
        Err(AttestationBindingError::MissingHeaderIntakeRoot)
    );
    let mismatched_root_refused = matches!(
        verify_external_attestation_binding(&synthetic, Some(&[0xFF; 32]), &empty_intake, 1),
        Err(AttestationBindingError::IntakeRootMismatch)
    );
    build_refused && missing_header_refused && mismatched_root_refused
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::cross_domain::external::bitcoin_spv::PinnedBitcoinAnchor;
    use crate::cross_domain::external::hotstuff::{HotStuffValidator, PinnedHotStuffCommittee};
    use crate::cross_domain::external::intake::{AdapterSpec, IntakeEntry};
    use crate::cross_domain::external::prover::DomainEconomics;
    use crate::cross_domain::external::quorum::QuorumPolicy;
    use crate::cross_domain::external::selftest::{AdmissionReport, ProbeOutcome, RefusalKind};
    use crate::cross_domain::external::spec::{
        AdapterDescriptor, AdapterId, FinalityAttestation, FinalityKind, RawConsensusEvidence,
        SecurityBacking, TimeUnit, TrustModel, VerificationPolicy,
    };
    use crate::cross_domain::external::versioning::VersionPolicy;

    const TEST_EVIDENCE_VERSION: u32 = 1;

    fn seeded_intake_with_spec(
        network: &str,
        adapter_name: &str,
        spec: AdapterSpec,
    ) -> (IntakeState, DomainKey, u64) {
        let mut intake = IntakeState::default();
        let adapter_id = AdapterId::from_name(adapter_name);
        let poster = Address::from([0x07; 32]);
        let descriptor = AdapterDescriptor {
            id: adapter_id,
            name: adapter_name.to_string(),
            adapter_version: 1,
            accepted_evidence_versions: vec![TEST_EVIDENCE_VERSION],
            consensus_kind: "bft-3chain".to_string(),
            finality_kind: FinalityKind::EconomicFinality,
            required_depth: 1,
            time_unit: TimeUnit::Round,
            trust_model: TrustModel::HonestMajority { set_size: 4 },
        };
        let admission = AdmissionReport {
            adapter_version: 1,
            evidence_version: TEST_EVIDENCE_VERSION,
            golden_verified: true,
            probes: vec![(
                "corrupted-qc-signature".to_string(),
                ProbeOutcome::Refused {
                    kind: RefusalKind::Crypto,
                },
            )],
            probe_commitment: [0x55; 32],
            admitted: true,
        };
        let economics = DomainEconomics {
            routing_ceiling_atoms: 10_000,
            unbonding_heights: 100,
            ..DomainEconomics::default()
        };
        let versions = VersionPolicy::single(adapter_id, TEST_EVIDENCE_VERSION, 16);
        let domain = intake
            .registry
            .register(
                network,
                descriptor,
                economics,
                versions,
                &admission,
                economics.required_bond_atoms().max(1),
                poster,
            )
            .expect("register external domain");

        let height = 106u64;
        let state_root = [0xA5; 32];
        let golden = RawConsensusEvidence {
            adapter: adapter_id,
            evidence_version: TEST_EVIDENCE_VERSION,
            network: network.to_string(),
            payload: vec![0x01, 0x02, 0x03, 0x04],
            declared_height: height,
            declared_root: state_root,
            submitter: poster,
        };
        intake.entries.insert(
            domain,
            IntakeEntry {
                spec,
                policy: VerificationPolicy::strict(1_700_001_000),
                admission,
                golden,
                registrant: poster,
            },
        );

        let attestation = FinalityAttestation {
            adapter: adapter_id,
            domain,
            height,
            state_root,
            finalized_at: height,
            time_unit: TimeUnit::Round,
            security: SecurityBacking::None,
            evidence_digest: [0x77; 32],
            adapter_version: 1,
            evidence_version: TEST_EVIDENCE_VERSION,
            attested_block_hash: Some([0xB1; 32]),
            attested_event_root: Some([0xE1; 32]),
            attested_tx_root: Some([0xD1; 32]),
        };
        intake
            .registry
            .commit_attestation(&attestation, poster)
            .expect("commit finalized external attestation");
        (intake, domain, height)
    }

    fn seeded_intake_with_hotstuff_attestation() -> (IntakeState, DomainKey, u64) {
        let spec = AdapterSpec::HotStuffQc {
            network: "aptos-mainnet".to_string(),
            committee: Some(PinnedHotStuffCommittee {
                epoch: 1,
                members: vec![HotStuffValidator {
                    ed25519_pubkey: [0x31; 32],
                    voting_weight: 100,
                    pq_pubkey: vec![0x32; 1_952],
                }],
            }),
        };
        seeded_intake_with_spec("aptos-mainnet", "hotstuff-3chain", spec)
    }

    #[test]
    fn valid_intake_attestation_builds_and_verifies_against_header_root() {
        assert!(check_attestation_binding_invariants());
        let (intake, domain, height) = seeded_intake_with_hotstuff_attestation();
        let header_root = intake.state_digest().expect("state digest");
        let proof = build_external_attestation_binding(
            &intake,
            domain,
            3,
            height,
            TEST_EVIDENCE_VERSION,
            10,
        )
        .expect("build binding proof");
        assert_eq!(proof.expected_intake_root, header_root);
        verify_external_attestation_binding(&proof, Some(&header_root), &intake, 10)
            .expect("valid proof must verify against matching header root");
    }

    #[test]
    fn non_value_safe_external_spec_is_refused() {
        let btc_spec = AdapterSpec::BitcoinSpv {
            network: "btc-mainnet".to_string(),
            anchor: Some(PinnedBitcoinAnchor {
                height: 840_000,
                block_hash: [0x11; 32],
                bits: 0x1703_4219,
            }),
        };
        let (intake, domain, height) =
            seeded_intake_with_spec("btc-mainnet", "bitcoin-spv", btc_spec);
        assert_eq!(
            build_external_attestation_binding(
                &intake,
                domain,
                3,
                height,
                TEST_EVIDENCE_VERSION,
                10
            ),
            Err(AttestationBindingError::ValueUnsafeGuarantee)
        );
    }

    #[test]
    fn missing_or_tampered_header_intake_root_is_refused() {
        let (intake, domain, height) = seeded_intake_with_hotstuff_attestation();
        let mut bad_root = intake.state_digest().expect("state digest");
        let proof = build_external_attestation_binding(
            &intake,
            domain,
            3,
            height,
            TEST_EVIDENCE_VERSION,
            10,
        )
        .expect("build binding proof");

        assert_eq!(
            verify_external_attestation_binding(&proof, None, &intake, 10),
            Err(AttestationBindingError::MissingHeaderIntakeRoot)
        );
        bad_root[0] ^= 0x01;
        assert_eq!(
            verify_external_attestation_binding(&proof, Some(&bad_root), &intake, 10),
            Err(AttestationBindingError::IntakeRootMismatch)
        );
    }

    #[test]
    fn faulted_retired_and_quantum_isolated_domains_are_refused() {
        for non_serving in [
            DomainState::Faulted,
            DomainState::Retired,
            DomainState::QuantumIsolated,
        ] {
            let (mut intake, domain, height) = seeded_intake_with_hotstuff_attestation();
            let proof = build_external_attestation_binding(
                &intake,
                domain,
                3,
                height,
                TEST_EVIDENCE_VERSION,
                10,
            )
            .expect("build before state transition");
            intake
                .registry
                .domain_mut(&domain)
                .expect("domain")
                .record
                .state = non_serving;
            let new_root = intake.state_digest().expect("new digest");
            let mut updated_proof = proof;
            updated_proof.expected_intake_root = new_root;
            assert_eq!(
                verify_external_attestation_binding(&updated_proof, Some(&new_root), &intake, 10),
                Err(AttestationBindingError::DomainNotServing(
                    non_serving.as_str()
                ))
            );
        }
    }

    #[test]
    fn cooldown_and_contradicted_claim_tombstone_fail_closed() {
        let (mut intake, domain, height) = seeded_intake_with_hotstuff_attestation();
        let att = intake
            .registry
            .domain(&domain)
            .expect("domain")
            .attestations
            .get(&(height, TEST_EVIDENCE_VERSION))
            .expect("att")
            .clone();
        let until = intake.guard.record_contradiction(
            domain,
            height,
            TEST_EVIDENCE_VERSION,
            att.claim_digest(),
            10,
        );
        assert!(matches!(
            build_external_attestation_binding(&intake, domain, 3, height, TEST_EVIDENCE_VERSION, 10),
            Err(AttestationBindingError::IntakeCooldownActive { until_block }) if until_block == until
        ));
        assert_eq!(
            build_external_attestation_binding(
                &intake,
                domain,
                3,
                height,
                TEST_EVIDENCE_VERSION,
                until + 1
            ),
            Err(AttestationBindingError::ContradictedClaimTombstoned)
        );
    }

    #[test]
    fn quorum_policy_without_quorum_decision_is_refused() {
        let (mut intake, domain, height) = seeded_intake_with_hotstuff_attestation();
        intake.quorum.set_policy(domain, QuorumPolicy::strict(2, 3));
        // `height` was recorded via `commit_attestation` (quorum-decided), so it succeeds:
        assert!(build_external_attestation_binding(
            &intake,
            domain,
            3,
            height,
            TEST_EVIDENCE_VERSION,
            10,
        )
        .is_ok());
        // A single-prover slot recorded without `commit_attestation` lacks the
        // quorum-decided marker and must fail closed under an active QuorumPolicy:
        let mut single_att = intake
            .registry
            .domain(&domain)
            .expect("domain")
            .attestations
            .get(&(height, TEST_EVIDENCE_VERSION))
            .expect("att")
            .clone();
        let unfinalized_height = height + 1;
        single_att.height = unfinalized_height;
        intake
            .registry
            .domain_mut(&domain)
            .expect("domain")
            .attestations
            .insert((unfinalized_height, TEST_EVIDENCE_VERSION), single_att);
        assert_eq!(
            build_external_attestation_binding(
                &intake,
                domain,
                3,
                unfinalized_height,
                TEST_EVIDENCE_VERSION,
                10
            ),
            Err(AttestationBindingError::QuorumNotFinalized {
                height: unfinalized_height
            })
        );
    }

    #[test]
    fn tampered_state_root_guarantee_or_binding_digest_is_refused() {
        let (intake, domain, height) = seeded_intake_with_hotstuff_attestation();
        let root = intake.state_digest().expect("digest");
        let proof = build_external_attestation_binding(
            &intake,
            domain,
            3,
            height,
            TEST_EVIDENCE_VERSION,
            10,
        )
        .expect("proof");

        let mut bad_state = proof.clone();
        bad_state.state_root[0] ^= 0xFF;
        assert_eq!(
            verify_external_attestation_binding(&bad_state, Some(&root), &intake, 10),
            Err(AttestationBindingError::StateRootMismatch)
        );

        let mut bad_guarantee = proof.clone();
        bad_guarantee.guarantee.quantum_posture = crate::crypto::facts::QuantumClass::Classical;
        assert_eq!(
            verify_external_attestation_binding(&bad_guarantee, Some(&root), &intake, 10),
            Err(AttestationBindingError::GuaranteeMismatch)
        );

        let mut bad_digest = proof;
        bad_digest.binding_digest[31] ^= 0x01;
        assert_eq!(
            verify_external_attestation_binding(&bad_digest, Some(&root), &intake, 10),
            Err(AttestationBindingError::BindingDigestMismatch)
        );
    }
}
