//! The seam between the permissionless external-domain registry and the
//! consensus-domain finality interface.
//!
//! `ExternalFinalityAdapter` works on opaque evidence. `DomainFinalityAdapter`
//! works on a `DomainCommitment` and feeds the global-header path. This module
//! is the narrow translation between them: evidence crosses as the existing
//! `FinalityProof::Raw` envelope, the external adapter derives an attestation,
//! and only an attestation matching the commitment can finalize the domain.
//!
//! The bridge does not approve the external domain and does not compute a
//! trust score. It only checks identity, versioned evidence, proof binding and
//! the height/root that the local commitment is about.

use crate::cross_domain::external::spec::{
    AdapterId, ExternalFinalityAdapter, RawConsensusEvidence, VerificationPolicy,
};
use crate::domain::finality_adapter::{
    DomainFinalityAdapter, FinalityError, FinalityProof, FinalityStatus,
};
use crate::domain::types::{ConsensusDomain, DomainCommitment};

/// The adapter name used by a consensus domain whose proof is supplied by the
/// external-domain framework. The external system's consensus kind remains in
/// its adapter descriptor; this value only selects the local translation.
pub const EXTERNAL_DOMAIN_FINALITY_ADAPTER: &str = "external-domain-finality-v1";

/// Encodes external evidence into the existing raw finality-proof envelope.
///
/// Keeping this as a function, rather than making every caller know that the
/// bridge uses bincode, gives the wire format one place to change when proof
/// envelopes are versioned. The evidence's own `evidence_version` is still
/// checked by the adapter; bincode is only the local carrier.
///
/// # Errors
///
/// Returns an error if the carrier cannot serialize the evidence.
pub fn encode_external_evidence(
    evidence: &RawConsensusEvidence,
) -> Result<FinalityProof, FinalityError> {
    let payload = bincode::serialize(evidence)
        .map_err(|error| FinalityError(format!("external evidence cannot be encoded: {error}")))?;
    Ok(FinalityProof::Raw(payload))
}

/// Decodes the local carrier. It does not validate the evidence: only the
/// bound adapter may interpret its payload or decide whether it is final.
///
/// # Errors
///
/// Returns an error for a non-raw proof or a malformed carrier.
pub fn decode_external_evidence(
    proof: &FinalityProof,
) -> Result<RawConsensusEvidence, FinalityError> {
    let FinalityProof::Raw(payload) = proof else {
        return Err(FinalityError(
            "external-domain finality requires a raw evidence envelope".to_string(),
        ));
    };
    bincode::deserialize(payload)
        .map_err(|error| FinalityError(format!("external evidence carrier is malformed: {error}")))
}

/// A consensus-facing adapter backed by one permissionless external adapter.
///
/// The trait object is captured at construction, so a caller cannot register
/// one adapter and silently swap another at verification time. A node that
/// wants to serve another external network constructs another bridge and
/// registers another local domain.
pub struct ExternalDomainFinalityBridge {
    adapter: Box<dyn ExternalFinalityAdapter>,
    adapter_id: AdapterId,
    policy: VerificationPolicy,
}

impl ExternalDomainFinalityBridge {
    /// Convenience: kept for adapter registration. The descriptor is captured
    /// once so every later proof is checked against the same adapter identity.
    #[must_use]
    pub fn new(
        adapter: Box<dyn ExternalFinalityAdapter>,
        policy: VerificationPolicy,
    ) -> Self {
        let adapter_id = adapter.descriptor().id;
        Self {
            adapter,
            adapter_id,
            policy,
        }
    }

    /// WIRING: the registration path displays the adapter identity before it
    /// submits the bridge to a consensus-domain registry.
    #[must_use]
    pub fn adapter_id(&self) -> AdapterId {
        self.adapter_id
    }
}

impl DomainFinalityAdapter for ExternalDomainFinalityBridge {
    fn adapter_name(&self) -> &'static str {
        EXTERNAL_DOMAIN_FINALITY_ADAPTER
    }

    fn verify_finality(
        &self,
        domain: &ConsensusDomain,
        commitment: &DomainCommitment,
        proof: &FinalityProof,
    ) -> Result<FinalityStatus, FinalityError> {
        if domain.finality_adapter != EXTERNAL_DOMAIN_FINALITY_ADAPTER {
            return Ok(FinalityStatus::Rejected(format!(
                "domain {} is not bound to the external-domain finality adapter",
                domain.id
            )));
        }
        let evidence = decode_external_evidence(proof)?;
        let attestation = self
            .adapter
            .verify(&evidence, &self.policy)
            .map_err(|error| FinalityError(format!("external adapter refused evidence: {error}")))?;

        if attestation.adapter != self.adapter_id || evidence.adapter != self.adapter_id {
            return Ok(FinalityStatus::Rejected(
                "the evidence and attestation do not name the bridge's adapter".to_string(),
            ));
        }
        if attestation.evidence_digest != evidence.digest() {
            return Ok(FinalityStatus::Rejected(
                "the attestation is not derived from the submitted evidence".to_string(),
            ));
        }
        if attestation.height != commitment.domain_height {
            return Ok(FinalityStatus::Rejected(format!(
                "external height {} does not match local commitment height {}",
                attestation.height, commitment.domain_height
            )));
        }
        if attestation.state_root != commitment.state_root {
            return Ok(FinalityStatus::Rejected(
                "external state root does not match local commitment state root".to_string(),
            ));
        }

        // The commitment hash is checked here as well as by the surrounding
        // blockchain path. Keeping this invariant at the translation seam
        // prevents a future direct caller from finalizing with a proof whose
        // bytes were not the ones the commitment recorded.
        let proof_hash = crate::domain::hash_finality_proof(proof)?;
        if proof_hash != commitment.finality_proof_hash {
            return Ok(FinalityStatus::Rejected(
                "external finality proof hash does not match the commitment".to_string(),
            ));
        }
        Ok(FinalityStatus::Finalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::cross_domain::external::spec::{
        AdapterDescriptor, FinalityAttestation, FinalityKind, ProofSystem, SecurityBacking,
        TimeUnit, TrustModel,
    };
    use crate::domain::types::{ConsensusKind, DomainStatus, RootScheme};

    struct FixtureAdapter {
        descriptor: AdapterDescriptor,
        evidence: RawConsensusEvidence,
    }

    impl ExternalFinalityAdapter for FixtureAdapter {
        fn descriptor(&self) -> AdapterDescriptor {
            self.descriptor.clone()
        }

        fn verify(
            &self,
            evidence: &RawConsensusEvidence,
            _policy: &VerificationPolicy,
        ) -> Result<FinalityAttestation, crate::cross_domain::external::spec::AdapterError> {
            if evidence != &self.evidence {
                return Err(
                    crate::cross_domain::external::spec::AdapterError::Malformed {
                        offset: 0,
                        reason: "fixture mismatch".to_string(),
                    },
                );
            }
            Ok(FinalityAttestation {
                adapter: self.descriptor.id,
                domain: crate::cross_domain::external::spec::DomainKey::from_parts(
                    &self.descriptor.id,
                    &evidence.network,
                ),
                height: evidence.declared_height,
                state_root: evidence.declared_root,
                finalized_at: evidence.declared_height,
                time_unit: TimeUnit::Height,
                security: SecurityBacking::Zk {
                    system: ProofSystem::Stark,
                    public_inputs_digest: [9; 32],
                },
                evidence_digest: evidence.digest(),
                adapter_version: self.descriptor.adapter_version,
                evidence_version: evidence.evidence_version,
            })
        }

        fn fault_probes(
            &self,
        ) -> Vec<crate::cross_domain::external::selftest::FaultProbe> {
            Vec::new()
        }
    }

    fn fixture() -> (FixtureAdapter, ConsensusDomain, DomainCommitment) {
        let descriptor = AdapterDescriptor {
            id: AdapterId::from_name("fixture-net"),
            name: "fixture-net".to_string(),
            adapter_version: 1,
            accepted_evidence_versions: vec![1],
            consensus_kind: "fixture-consensus".to_string(),
            finality_kind: FinalityKind::Proven,
            required_depth: 0,
            time_unit: TimeUnit::Height,
            trust_model: TrustModel::Trustless,
        };
        let evidence = RawConsensusEvidence {
            adapter: descriptor.id,
            evidence_version: 1,
            network: "fixture".to_string(),
            payload: vec![1, 2, 3],
            declared_height: 7,
            declared_root: [8; 32],
            submitter: Address::from([3; 32]),
        };
        let domain = ConsensusDomain {
            id: 7,
            kind: ConsensusKind::Custom("fixture-consensus".to_string()),
            status: DomainStatus::Active,
            domain_chain_id: 77,
            operator: Some(Address::from([4; 32])),
            operator_bond: 1_000_000,
            config_hash: [0; 32],
            validator_set_hash: [0; 32],
            finality_adapter: EXTERNAL_DOMAIN_FINALITY_ADAPTER.to_string(),
            min_confirmations: 1,
            bridge_enabled: true,
            block_hash_scheme: RootScheme::Sha256,
            state_root_scheme: RootScheme::Sha256,
            tx_root_scheme: RootScheme::Sha256,
            last_committed_height: 6,
            last_committed_hash: [6; 32],
            pow_parameters: None,
            zk_program_allowlist: Vec::new(),
            plugin_code_hash: None,
        };
        let commitment = DomainCommitment {
            domain_id: 7,
            domain_height: 7,
            domain_block_hash: [5; 32],
            parent_domain_block_hash: [4; 32],
            state_root: [8; 32],
            tx_root: [2; 32],
            event_root: [1; 32],
            finality_proof_hash: [0; 32],
            consensus_kind: domain.kind.clone(),
            validator_set_hash: [0; 32],
            timestamp_ms: 10,
            sequence: 1,
            producer: None,
            state_updates: std::collections::BTreeMap::new(),
        };
        (
            FixtureAdapter {
                descriptor,
                evidence,
            },
            domain,
            commitment,
        )
    }

    #[test]
    fn raw_carrier_round_trips_without_adapter_interpretation() {
        let (adapter, _, _) = fixture();
        let proof = encode_external_evidence(&adapter.evidence).expect("encode");
        let decoded = decode_external_evidence(&proof).expect("decode");
        assert_eq!(decoded, adapter.evidence);
    }

    #[test]
    fn bridge_requires_the_commitment_to_bind_the_same_proof_bytes() {
        let (adapter, domain, mut commitment) = fixture();
        let proof = encode_external_evidence(&adapter.evidence).expect("encode");
        commitment.finality_proof_hash = crate::domain::hash_finality_proof(&proof).unwrap();
        let bridge = ExternalDomainFinalityBridge::new(
            Box::new(adapter),
            VerificationPolicy::proven(100),
        );
        assert_eq!(
            bridge
                .verify_finality(&domain, &commitment, &proof)
                .unwrap(),
            FinalityStatus::Finalized
        );
        let wrong = FinalityProof::Raw(vec![0; 3]);
        assert!(bridge.verify_finality(&domain, &commitment, &wrong).is_err());
    }
}
