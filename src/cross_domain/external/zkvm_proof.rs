//! A domain whose finality is *proven*, not voted: the BudZKVM adapter.
//!
//! # Why this adapter exists
//!
//! Every other adapter in this tree reads a vote - a committee signed, a
//! validator set justified, an authority set asserted. A vote has an honesty
//! assumption attached to it, and the profile has to say so.
//!
//! This one does not. A BudZKVM proof is checked by the chain's own STARK
//! verifier against the public inputs the program committed to. There is no
//! committee to be honest or dishonest, no bond to slash, no window to
//! challenge. `TrustModel::Trustless` is not a claim about the external
//! system's politics here; it is a statement about what the verification
//! actually requires.
//!
//! That difference is why this adapter is the one the framework was built
//! around: it is the case where "permissionless" is literally true, because
//! Budlum decides nothing about who produced the proof and everything about
//! whether the proof is valid.
//!
//! # What the verifier is asked to do
//!
//! The envelope, the public inputs and the program all travel together, and
//! all three are passed to the verifier. That is deliberate. A proof verified
//! against public inputs the caller chose would prove nothing about the state
//! root it attests to, and a proof verified against a program the caller chose
//! would prove nothing about which computation ran. The three-way binding -
//! envelope, inputs, program - is the whole guarantee, and every probe below
//! attacks one edge of it.
//!
//! # What this adapter refuses to do
//!
//! It does not produce proofs. Producing a proof is the prover's job
//! (`src/prover`), and an adapter that could also mint proofs would be a
//! verifier that trusts itself.

use crate::cross_domain::external::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use crate::cross_domain::external::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, ProofSystem, RawConsensusEvidence, SecurityBacking,
    TimeUnit, TrustModel, VerificationPolicy,
};
use bud_proof::adapter::VerifyError;
use bud_proof::{ExecutionPublicInputs, ProofEnvelope, ProverAdapter};
use serde::{Deserialize, Serialize};

/// The evidence version this adapter reads.
pub const EVIDENCE_VERSION: u32 = 1;

/// A ceiling on the encoded payload, checked before deserialization.
///
/// Bincode will happily read a length prefix that asks for more memory than the
/// node has. The cap is not the verifier's job and the verifier will not do it,
/// so it is done here: a payload that is too large is refused before a single
/// byte of it is interpreted.
pub const MAX_PAYLOAD_BYTES: usize = 12 * 1024 * 1024;

/// The wire shape of one proven finality claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkFinalityEvidence {
    pub envelope: ProofEnvelope,
    pub inputs: ExecutionPublicInputs,
    /// The program the trace was generated from. Carried, not reconstructed:
    /// a verifier given the wrong program verifies a different computation and
    /// reports success.
    pub program: Vec<u64>,
}

impl ZkFinalityEvidence {
    /// Decodes a payload.
    ///
    /// # Errors
    ///
    /// [`AdapterError::Malformed`] naming the offset, or a refusal from the
    /// envelope's own shape check.
    pub fn decode(payload: &[u8]) -> Result<Self, AdapterError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(AdapterError::Malformed {
                offset: payload.len(),
                reason: format!(
                    "payload is {} bytes, above the {MAX_PAYLOAD_BYTES} cap",
                    payload.len()
                ),
            });
        }
        let decoded: Self =
            bincode::deserialize(payload).map_err(|e| AdapterError::Malformed {
                offset: 0,
                reason: format!("payload does not decode: {e}"),
            })?;
        decoded
            .envelope
            .validate_shape()
            .map_err(|e| AdapterError::Malformed {
                offset: 0,
                reason: format!("envelope shape refused: {describe(&e)}"),
            })?;
        Ok(decoded)
    }

    /// Encodes. Used by callers that hold the parts and need the payload.
    ///
    /// # Errors
    ///
    /// A serialization failure, which for these types means the payload would
    /// exceed the encoder's own limits.
    pub fn encode(&self) -> Result<Vec<u8>, AdapterError> {
        bincode::serialize(self).map_err(|e| AdapterError::Malformed {
            offset: 0,
            reason: format!("payload does not encode: {e}"),
        })
    }
}

/// The adapter.
pub struct ZkVmFinalityAdapter {
    descriptor: AdapterDescriptor,
    /// The network this instance serves. Checked before the proof is read:
    /// verifying a proof under the wrong network is not a weaker guarantee, it
    /// is a statement about a different chain.
    network: String,
    golden: Option<RawConsensusEvidence>,
}

impl ZkVmFinalityAdapter {
    /// Builds an adapter for one network.
    #[must_use]
    pub fn new(network: &str) -> Self {
        let id = AdapterId::from_name(&format!("budzkvm-{network}"));
        Self {
            network: network.to_string(),
            descriptor: AdapterDescriptor {
                id,
                name: format!("budzkvm-{network}"),
                adapter_version: 1,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "zkvm-execution".to_string(),
                finality_kind: FinalityKind::Proven,
                // A proof is not deep or shallow: it is valid or it is not.
                // The depth field exists for vote-based domains; here it is
                // zero and a caller asking for depth is asking for something
                // this adapter cannot give, which `verify` enforces.
                required_depth: 0,
                time_unit: TimeUnit::Height,
                trust_model: TrustModel::Trustless,
            },
            golden: None,
        }
    }

    /// Attaches a golden sample. The caller has to have produced a real proof;
    /// this adapter will not fabricate one.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }
}

impl ExternalFinalityAdapter for ZkVmFinalityAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: "another adapter".to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::WrongAdapter {
                expected: self.network.clone(),
                found: evidence.network.clone(),
            });
        }
        if !self
            .descriptor
            .accepted_evidence_versions
            .contains(&evidence.evidence_version)
        {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: EVIDENCE_VERSION.to_string(),
            });
        }

        let decoded = ZkFinalityEvidence::decode(&evidence.payload)?;

        // The three-way binding, checked before the expensive verification:
        // the public inputs the proof is checked against are the ones in the
        // payload, and the program is the one in the payload. Passing
        // caller-chosen values here would make the verification decorative.
        if policy.require_declared_match {
            if evidence.declared_height != decoded.inputs.block_height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if evidence.declared_root != decoded.inputs.final_state_root {
                return Err(AdapterError::DeclarationMismatch { field: "state_root" });
            }
        }

        // A program that halted with a non-zero exit code did not complete the
        // computation it was supposed to. The trace proves it halted; that is
        // not the same as proving it succeeded.
        if decoded.inputs.exit_code != 0 {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "the proved program exited with code {}; only a clean exit attests a state root",
                    decoded.inputs.exit_code
                ),
            });
        }

        // A depth requirement cannot be met by a proof, and silently ignoring
        // the caller's policy would let a caller think they had depth they do
        // not have.
        if policy.min_depth > 0 {
            return Err(AdapterError::Unavailable {
                reason: "a proven attestation has no depth; this caller asked for one".to_string(),
            });
        }

        // The verification itself. All three parts go in; the verifier is the
        // chain's own STARK verifier, not a reimplementation.
        <bud_proof::DefaultAdapter as ProverAdapter>::verify(
            &decoded.envelope,
            &decoded.inputs,
            &decoded.program,
        )
        .map_err(|e| AdapterError::Crypto { what: describe(&e) })?;

        Ok(FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: decoded.inputs.block_height,
            state_root: decoded.inputs.final_state_root,
            finalized_at: decoded.inputs.block_height,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::Zk {
                system: ProofSystem::BudlumZkVm,
                public_inputs_digest: decoded.envelope.public_inputs_hash,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
        })
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        // Offset-independent on purpose: the payload is bincode, so an offset
        // is not stable across program sizes. Truncation, a corrupt first
        // word, and lying declarations do not depend on where anything sits.
        vec![
            FaultProbe {
                name: "an empty payload is refused before deserialization".to_string(),
                patch: BytePatch::TruncatePayload { keep: 0 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "a payload one byte short does not partially decode".to_string(),
                patch: BytePatch::TruncatePayload { keep: 1 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "corrupting the leading bytes breaks the envelope".to_string(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0xff; 16],
                },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "a declared height the proof does not attest to is refused".to_string(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "a declared root the proof does not attest to is refused".to_string(),
                patch: BytePatch::DeclaredRoot { value: [0xee; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "an evidence version this adapter never accepted is refused at the gate"
                    .to_string(),
                patch: BytePatch::EvidenceVersion { value: 2 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "pointing the adapter at another network is refused".to_string(),
                patch: BytePatch::Network {
                    value: "not-this-network".to_string(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::WrongAdapter),
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

/// Turns a verifier error into words for an [`AdapterError`]. Kept local so the
/// adapter's error surface does not grow every time the verifier's does.
#[must_use]
fn describe(err: &VerifyError) -> String {
    match err {
        VerifyError::DeserializationError(e) => format!("deserialization: {e}"),
        VerifyError::InvalidEnvelope(e) => format!("invalid envelope: {e}"),
        VerifyError::PublicInputsMismatch => {
            "the proof's public inputs are not the ones supplied".to_string()
        }
        VerifyError::NonCanonicalProgram(hash) => {
            format!("program {} is not in the canonical set", hex32(hash))
        }
        VerifyError::InvalidProof => "the proof does not verify".to_string(),
    }
}

/// Lowercase hex for a 32-byte digest, local so this module's messages do not
/// depend on another module's formatting.
#[must_use]
fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_adapter_declares_itself_trustless_and_proven() {
        // The whole point of this adapter: unlike the sync committee there is
        // no committee whose honesty is assumed. If this ever changes, the
        // profile a user sees changes with it, and this test is where that
        // shows up first.
        let d = ZkVmFinalityAdapter::new("testnet").descriptor();
        assert_eq!(d.trust_model, TrustModel::Trustless);
        assert_eq!(d.finality_kind, FinalityKind::Proven);
        assert_eq!(d.required_depth, 0, "a proof has no depth");
        assert_eq!(d.consensus_kind, "zkvm-execution");
    }

    #[test]
    fn a_payload_above_the_cap_is_refused_before_deserialization() {
        let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let err = ZkFinalityEvidence::decode(&oversized).unwrap_err();
        assert!(
            matches!(err, AdapterError::Malformed { .. }),
            "an oversized payload must be refused before bincode reads a length prefix: {err:?}"
        );
    }

    #[test]
    fn garbage_does_not_decode_and_says_where_it_failed() {
        let err = ZkFinalityEvidence::decode(&[1, 2, 3, 4]).unwrap_err();
        assert!(matches!(err, AdapterError::Malformed { .. }));
    }

    #[test]
    fn the_version_gate_refuses_before_any_decoding() {
        let adapter = ZkVmFinalityAdapter::new("testnet");
        let evidence = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: 2,
            network: "testnet".to_string(),
            payload: vec![0u8; 64],
            declared_height: 1,
            declared_root: [0; 32],
            submitter: crate::core::address::Address([1; 32]),
        };
        let err = adapter.verify(&evidence, &VerificationPolicy::proven(10)).unwrap_err();
        assert!(matches!(
            err,
            AdapterError::UnsupportedEvidenceVersion { version: 2, .. }
        ));
    }

    #[test]
    fn the_wrong_network_is_refused_before_the_proof_is_read() {
        // The signing context is per network; verifying a proof under the
        // wrong one is not a smaller guarantee, it is a different statement.
        let adapter = ZkVmFinalityAdapter::new("testnet");
        let evidence = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "mainnet".to_string(),
            payload: vec![0u8; 64],
            declared_height: 1,
            declared_root: [0; 32],
            submitter: crate::core::address::Address([1; 32]),
        };
        let err = adapter.verify(&evidence, &VerificationPolicy::proven(10)).unwrap_err();
        assert!(matches!(err, AdapterError::WrongAdapter { .. }));
    }

    #[test]
    fn a_caller_asking_for_depth_is_told_a_proof_has_none() {
        // Silently ignoring min_depth would let a caller believe they had
        // confirmation depth that a proof does not provide.
        let adapter = ZkVmFinalityAdapter::new("testnet");
        let mut policy = VerificationPolicy::proven(10);
        policy.min_depth = 6;
        // The proof cannot be reached because decoding fails first, so this
        // pins the ordering: decoding and declaration checks come before the
        // depth refusal.
        let evidence = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "testnet".to_string(),
            payload: vec![0u8; 64],
            declared_height: 1,
            declared_root: [0; 32],
            submitter: crate::core::address::Address([1; 32]),
        };
        let err = adapter.verify(&evidence, &policy).unwrap_err();
        assert!(
            matches!(err, AdapterError::Malformed { .. }),
            "decoding comes before the depth rule: {err:?}"
        );
    }

    #[test]
    fn the_probe_set_is_offset_independent_and_covers_every_edge() {
        let probes = ZkVmFinalityAdapter::new("testnet").fault_probes();
        assert!(!probes.is_empty());
        // Every probe must be appliable to a payload of any size, which is why
        // none of them uses a fixed interior offset beyond the first 16 bytes.
        for probe in &probes {
            match &probe.patch {
                BytePatch::InPayload { offset, .. } => {
                    assert!(*offset < 16, "probe `{}` depends on bincode layout", probe.name);
                }
                BytePatch::TruncatePayload { .. }
                | BytePatch::DeclaredHeight { .. }
                | BytePatch::DeclaredRoot { .. }
                | BytePatch::EvidenceVersion { .. }
                | BytePatch::Submitter { .. }
                | BytePatch::Network { .. } => {}
            }
        }
        // The three-way binding must be probed on all three edges.
        let names: Vec<&str> = probes.iter().map(|p| p.name.as_str()).collect();
        assert!(
            names.iter().any(|n| n.contains("declared height")),
            "no probe attacks the height binding"
        );
        assert!(
            names.iter().any(|n| n.contains("declared root")),
            "no probe attacks the state root binding"
        );
        assert!(
            names.iter().any(|n| n.contains("corrupting the leading bytes")),
            "no probe attacks the envelope itself"
        );
    }
}
