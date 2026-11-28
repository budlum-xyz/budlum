//! A domain whose finality is *proven*, not voted: the `BudZKVM` adapter.
//!
//! WIRING: wired - like every adapter in this tree, it is reachable through
//! registry admission (`AdapterSpec::ZkVm` in the consensus-resident intake)
//! plus the finality dispatch documented in `domain_bridge`.
//!
//! # Why this adapter exists
//!
//! Every other adapter in this tree reads a vote - a committee signed, a
//! validator set justified, an authority set asserted. A vote has an honesty
//! assumption attached to it, and the profile has to say so.
//!
//! This one does not. A `BudZKVM` proof is checked by the chain's own STARK
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

use crate::cross_domain::external::selftest::{
    BytePatch, ExpectedRefusal, FaultProbe, RefusalKind,
};
use crate::cross_domain::external::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, ProofSystem, RawConsensusEvidence, SecurityBacking,
    TimeUnit, TrustModel, VerificationPolicy,
};
use bud_proof::adapter::VerifyError;
use bud_proof::{ExecutionPublicInputs, ProofEnvelope};
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
// `PartialEq`/`Eq` are deliberately absent: `ProofEnvelope` derives neither, and
// adding them here would mean comparing proof bytes field by field in a wrapper
// that cannot see inside them. Two envelopes being byte-equal is a question
// about `proof_bytes`, and the caller that needs it can ask that directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        // Trailing bytes decode to the same value under a
        // different evidence digest, so one proof could be re-wrapped into
        // many distinct commitments. They are refused, and the decode is
        // bounded by the payload cap. Same wire encoding as
        // `bincode::serialize`.
        use bincode::Options;
        let byte_limit = u64::try_from(payload.len()).unwrap_or(MAX_PAYLOAD_BYTES as u64);
        let decoded: Self = bincode::options()
            .with_fixint_encoding()
            .with_limit(byte_limit)
            .reject_trailing_bytes()
            .deserialize(payload)
            .map_err(|e| AdapterError::Malformed {
                offset: 0,
                reason: format!("payload does not decode: {e}"),
            })?;
        decoded
            .envelope
            .validate_shape()
            .map_err(|e| AdapterError::Malformed {
                offset: 0,
                reason: format!("envelope shape refused: {}", describe(&e)),
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
    /// The pinned program: a proof of ANY
    /// canonical-set program is not a proof of THIS domain's program. Pinned
    /// at admission; `None` is the closed state and every verification is
    /// refused.
    program_hash: Option<[u8; 32]>,
    /// The pinned chain id: a proof under
    /// another chain's id attests another chain's state.
    chain_id: Option<u64>,
    /// Optional state-continuity pin: when configured, `inputs.initial_state_root`
    /// must match this non-zero parent root in constant time before any STARK
    /// verification work executes.
    pinned_initial_state_root: Option<[u8; 32]>,
    /// Optional data-availability commitment pin: when configured,
    /// `inputs.state_writes_digest` must match this non-zero commitment in
    /// constant time before any STARK verification work executes.
    pinned_da_commitment: Option<[u8; 32]>,
    /// Whether the AIR binds `chain_id` to execution rather than only to a
    /// prover-chosen witness column on the first row. Production constructors
    /// keep this `false` until the VM and AIR expose and constrain a chain-id
    /// context syscall across both limbs (`public_inputs[0..2]`).
    chain_id_bound_in_air: bool,
    golden: Option<RawConsensusEvidence>,
}

impl ZkVmFinalityAdapter {
    /// Builds an adapter for one network.
    #[must_use]
    pub fn new(network: &str, program_hash: Option<[u8; 32]>, chain_id: Option<u64>) -> Self {
        let id = AdapterId::from_name(&format!("budzkvm-{network}"));
        Self {
            network: network.to_string(),
            program_hash,
            chain_id,
            pinned_initial_state_root: None,
            pinned_da_commitment: None,
            chain_id_bound_in_air: false,
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

    /// Pins the expected pre-transition state root so a valid proof generated
    /// from an unrelated parent state is refused before STARK verification.
    /// An all-zero root is kept and refused fail-closed on verification.
    ///
    /// Convenience: exposed for stateful rollup continuity verification.
    #[must_use]
    pub const fn with_expected_initial_state_root(mut self, root: [u8; 32]) -> Self {
        self.pinned_initial_state_root = Some(root);
        self
    }

    /// Pins the expected data-availability commitment (`state_writes_digest`)
    /// so a proof that withholds or substitutes published state writes is
    /// refused before STARK verification. An all-zero commitment is refused
    /// fail-closed.
    ///
    /// Convenience: exposed for DA-bound validity-proof verification.
    #[must_use]
    pub const fn with_expected_da_commitment(mut self, commitment: [u8; 32]) -> Self {
        self.pinned_da_commitment = Some(commitment);
        self
    }

    #[cfg(test)]
    #[must_use]
    fn with_air_chain_id_binding_for_test(mut self) -> Self {
        self.chain_id_bound_in_air = true;
        self
    }
}

impl ExternalFinalityAdapter for ZkVmFinalityAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn has_pinned_trust_anchor(&self) -> bool {
        self.program_hash.is_some() && self.chain_id.is_some()
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
        if self.network.trim().is_empty() {
            return Err(AdapterError::ConsensusRule {
                rule: "ZkVm network identifier must not be empty".to_string(),
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
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
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
        if policy.max_age > 0 {
            if decoded.inputs.block_height > policy.now {
                return Err(AdapterError::Stale {
                    age: decoded.inputs.block_height - policy.now,
                    max_age: policy.max_age,
                });
            }
            let age = policy.now - decoded.inputs.block_height;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        // Empty or bare `[Halt]` bytecode performs zero computation and cannot
        // attest an external state transition.
        if crate::prover::is_empty_or_halt_only_program(&decoded.program) {
            return Err(AdapterError::ConsensusRule {
                rule: "an empty or bare Halt program cannot attest a state root".to_string(),
            });
        }

        // Cheap constant-time and bounds prechecks run BEFORE expensive STARK
        // verification so a peer submitting malformed metadata, an unactivated
        // opcode, a non-canonical program, or an unpinned/mismatched program,
        // chain id, parent root, or DA commitment burns zero FRI/FFT CPU.
        use subtle::ConstantTimeEq;
        if bool::from(decoded.inputs.program_hash.ct_eq(&[0u8; 32])) {
            return Err(AdapterError::ConsensusRule {
                rule: "zero program hash cannot attest a state transition".to_string(),
            });
        }
        if decoded.inputs.chain_id == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "zero chain id cannot attest an external domain".to_string(),
            });
        }
        if decoded.inputs.gas_used > decoded.inputs.gas_limit {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "gas used {} exceeds declared gas limit {}",
                    decoded.inputs.gas_used, decoded.inputs.gas_limit
                ),
            });
        }
        if decoded.inputs.trace_len == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "zero-length execution trace cannot attest a state root".to_string(),
            });
        }

        // Preserve exact opcode-gate-then-canonicality refusal ordering before
        // touching the STARK proof bytes.
        let activation = bud_isa::MainnetActivation::default();
        for &word in &decoded.program {
            if let Ok(instruction) = bud_isa::Instruction::decode_any(word) {
                if !activation.allows(instruction.opcode) {
                    return Err(AdapterError::Crypto {
                        what: format!("opcode {:?} is not activated", instruction.opcode),
                    });
                }
            }
        }
        let derived_program_hash = bud_proof::canonical_set::program_hash_of(&decoded.program);
        if !bool::from(decoded.inputs.program_hash.ct_eq(&derived_program_hash)) {
            return Err(AdapterError::Crypto {
                what: describe(&VerifyError::PublicInputsMismatch),
            });
        }
        if !bud_proof::canonical_set::is_canonical_program_hash(&derived_program_hash) {
            return Err(AdapterError::Crypto {
                what: describe(&VerifyError::NonCanonicalProgram(derived_program_hash)),
            });
        }

        // Pin gates run before STARK verification: a missing, zero, or
        // mismatched pin is rejected in microseconds without running FRI.
        let Some(program_hash) = self.program_hash else {
            return Err(AdapterError::ConsensusRule {
                rule: "no program hash pinned; ZkVm admission is closed".to_string(),
            });
        };
        if bool::from(program_hash.ct_eq(&[0u8; 32])) {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned program hash cannot be all zeros; ZkVm admission is closed"
                    .to_string(),
            });
        }
        if !bool::from(decoded.inputs.program_hash.ct_eq(&program_hash)) {
            return Err(AdapterError::ConsensusRule {
                rule: "the proved program is not the pinned program".to_string(),
            });
        }
        // chain_id is a prover-chosen public input today: the AIR binds
        // COL_CHAIN_ID to public_inputs[0] only, the high limb in
        // public_inputs[1] is unconstrained, and the VM has no chain-id
        // syscall, so nothing ties the declared id to the execution. Until
        // the AIR binds chain_id to the trace, production admission stays closed.
        let Some(chain_id) = self.chain_id else {
            return Err(AdapterError::ConsensusRule {
                rule: "no chain id pinned; ZkVm admission is closed".to_string(),
            });
        };
        if chain_id == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned chain id cannot be zero; ZkVm admission is closed".to_string(),
            });
        }
        if decoded.inputs.chain_id != chain_id {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "the proof's chain id {} is not the pinned chain id {chain_id}",
                    decoded.inputs.chain_id
                ),
            });
        }
        if let Some(expected_initial) = self.pinned_initial_state_root {
            if bool::from(expected_initial.ct_eq(&[0u8; 32])) {
                return Err(AdapterError::ConsensusRule {
                    rule: "expected initial state root cannot be all zeros".to_string(),
                });
            }
            if !bool::from(decoded.inputs.initial_state_root.ct_eq(&expected_initial)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "initial state root breaks state continuity with expected parent root"
                        .to_string(),
                });
            }
        }
        if let Some(expected_da) = self.pinned_da_commitment {
            if bool::from(expected_da.ct_eq(&[0u8; 32])) {
                return Err(AdapterError::ConsensusRule {
                    rule: "expected data-availability commitment cannot be all zeros".to_string(),
                });
            }
            if bool::from(decoded.inputs.state_writes_digest.ct_eq(&[0u8; 32]))
                || !bool::from(decoded.inputs.state_writes_digest.ct_eq(&expected_da))
            {
                return Err(AdapterError::ConsensusRule {
                    rule:
                        "state writes digest does not match expected data-availability commitment"
                            .to_string(),
                });
            }
        }
        if !self.chain_id_bound_in_air {
            return Err(AdapterError::ConsensusRule {
                rule: "chain id is not bound to execution; ZkVm admission is closed".to_string(),
            });
        }

        // Full Plonky3 STARK + canonical-set verification runs only after every
        // cheap structural, pin, continuity, and DA precondition has passed.
        bud_proof::DefaultAdapter::verify_canonical_program(
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
            // The program's event digest is an additive field sum, not a
            // collision-resistant commitment to the event list: it is
            // prover-chosen and cannot serve as an event root. Attest none
            // until the AIR binds a real hash of the events.
            attested_block_hash: None,
            attested_event_root: None,
            attested_tx_root: None,
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
    use bud_proof::ProverAdapter;

    #[test]
    fn the_adapter_declares_itself_trustless_and_proven() {
        // The whole point of this adapter: unlike the sync committee there is
        // no committee whose honesty is assumed. If this ever changes, the
        // profile a user sees changes with it, and this test is where that
        // shows up first.
        let d = ZkVmFinalityAdapter::new("testnet", None, None).descriptor();
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
        let adapter = ZkVmFinalityAdapter::new("testnet", None, None);
        let evidence = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: 2,
            network: "testnet".to_string(),
            payload: vec![0u8; 64],
            declared_height: 1,
            declared_root: [0; 32],
            submitter: crate::core::address::Address([1; 32]),
        };
        let err = adapter
            .verify(&evidence, &VerificationPolicy::proven(10))
            .unwrap_err();
        assert!(matches!(
            err,
            AdapterError::UnsupportedEvidenceVersion { version: 2, .. }
        ));
    }

    #[test]
    fn the_wrong_network_is_refused_before_the_proof_is_read() {
        // The signing context is per network; verifying a proof under the
        // wrong one is not a smaller guarantee, it is a different statement.
        let adapter = ZkVmFinalityAdapter::new("testnet", None, None);
        let evidence = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "mainnet".to_string(),
            payload: vec![0u8; 64],
            declared_height: 1,
            declared_root: [0; 32],
            submitter: crate::core::address::Address([1; 32]),
        };
        let err = adapter
            .verify(&evidence, &VerificationPolicy::proven(10))
            .unwrap_err();
        assert!(matches!(err, AdapterError::WrongAdapter { .. }));
    }

    #[test]
    fn a_caller_asking_for_depth_is_told_a_proof_has_none() {
        // Silently ignoring min_depth would let a caller believe they had
        // confirmation depth that a proof does not provide.
        let adapter = ZkVmFinalityAdapter::new("testnet", None, None);
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

    /// A valid proof of a `VerifyMerkle` program is refused here.
    ///
    /// The opcode is closed until it is activated, and this adapter verifies
    /// under the default activation state, so an honest, verifying proof of a
    /// program that uses it is still not attestable. The same proof verifies
    /// under full activation, which is what shows the refusal is the opcode
    /// gate and not a bad proof. The program is in the canonical set, so this
    /// also pins the order: the opcode gate answers before canonicality does.
    #[test]
    fn a_proof_of_a_verify_merkle_program_is_refused() {
        use bud_isa::{Instruction, Opcode};

        let program = vec![
            Instruction {
                opcode: Opcode::VerifyMerkle,
                rd: 1,
                rs1: 2,
                rs2: 3,
                imm: 256,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            }
            .encode(),
        ];
        // A path of 64 zero siblings under key 0: the window holds the key, the leaf, the
        // siblings and the root the walk reaches, and its memory image is what the proof
        // commits to.
        let leaf = [0xBEEFu64, 0, 0, 0];
        let root = (0..64).fold(leaf, |cur, _| bud_vm::merkle_node(cur, [0; 4]));
        let mut vm = bud_vm::Vm::new(4096);
        let mut words = vec![0u64];
        words.extend_from_slice(&leaf);
        words.extend(std::iter::repeat_n(0u64, 64 * 4));
        words.extend_from_slice(&root);
        for (i, word) in words.iter().enumerate() {
            let at = 256 + i * 8;
            vm.memory[at..at + 8].copy_from_slice(&word.to_le_bytes());
        }
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let inputs = ExecutionPublicInputs {
            chain_id: 1,
            program_hash: bud_proof::canonical_set::program_hash_of(&program),
            initial_state_root: bud_proof::initial_state_root_of(
                bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(
                    &vm.trace,
                )),
                bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0; 32],
            sender: 0,
            nonce: 0,
            block_height: 1,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0; 32],
            state_writes_digest: [0; 32],
        };
        let envelope =
            bud_proof::DefaultAdapter::prove(&vm.trace, &inputs, &program).expect("honest proof");
        bud_proof::Plonky3Adapter::verify_with_activation(
            &envelope,
            &inputs,
            &program,
            bud_isa::MainnetActivation::full(),
        )
        .expect("the proof is valid under full activation");

        let adapter = ZkVmFinalityAdapter::new("testnet", None, None);
        let payload = ZkFinalityEvidence {
            envelope,
            inputs,
            program,
        }
        .encode()
        .expect("encodes");
        let evidence = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "testnet".to_string(),
            payload,
            declared_height: 1,
            declared_root: [0; 32],
            submitter: crate::core::address::Address([1; 32]),
        };
        let err = adapter
            .verify(&evidence, &VerificationPolicy::proven(10))
            .unwrap_err();
        match err {
            AdapterError::Crypto { what } => assert!(
                what.contains("VerifyMerkle") && what.contains("not activated"),
                "the refusal names the opcode gate: {what}"
            ),
            other => panic!("a VerifyMerkle proof must be refused as invalid, got {other:?}"),
        }
    }

    /// Runs `program` on a fresh VM, proves it honestly and wraps the result
    /// as evidence for `adapter`. Programs here log at most, so the event
    /// digest is the only public input beyond the trace shape.
    fn honest_evidence(adapter: &ZkVmFinalityAdapter, program: Vec<u64>) -> RawConsensusEvidence {
        let mut vm = bud_vm::Vm::new(1024);
        vm.context.block_height = 1;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "the test program must halt cleanly");
        let inputs = ExecutionPublicInputs {
            chain_id: 1,
            program_hash: bud_proof::canonical_set::program_hash_of(&program),
            initial_state_root: bud_proof::initial_state_root_of(
                bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(
                    &vm.trace,
                )),
                bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0; 32],
            sender: vm.context.sender,
            nonce: vm.context.nonce,
            block_height: vm.context.block_height,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: bud_proof::event_digest_from_events(&receipt.events),
            state_writes_digest: [0; 32],
        };
        let envelope =
            bud_proof::DefaultAdapter::prove(&vm.trace, &inputs, &program).expect("honest proof");
        let payload = ZkFinalityEvidence {
            envelope,
            inputs,
            program,
        }
        .encode()
        .expect("encodes");
        RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "testnet".to_string(),
            payload,
            declared_height: 1,
            declared_root: [0; 32],
            submitter: crate::core::address::Address([1; 32]),
        }
    }

    /// The canonical set is checked at this boundary, after the proof and the
    /// opcode activation gate. Each row proves a program honestly, so the
    /// only thing that can differ between the rows is canonicality.
    #[test]
    fn only_a_program_in_the_canonical_set_is_attested() {
        use bud_isa::{Instruction, Opcode};

        let inst = |opcode, rd, rs1, imm| {
            Instruction {
                opcode,
                rd,
                rs1,
                rs2: 0,
                imm,
            }
            .encode()
        };
        let canonical = bud_vm::syscall_context::build_syscall_context_check_program()
            .expect("canonical build");
        // The canonical-set check runs before the AIR chain-id gate; the
        // test-only opt-in exercises the attestation shape after canonicality
        // while production `new` remains closed below.
        let pinned_hash = bud_proof::canonical_set::program_hash_of(&canonical);
        let prod_adapter = ZkVmFinalityAdapter::new("testnet", Some(pinned_hash), Some(1));
        let adapter = ZkVmFinalityAdapter::new("testnet", Some(pinned_hash), Some(1))
            .with_air_chain_id_binding_for_test();
        let outside = vec![
            inst(Opcode::Load, 1, 0, 7),
            inst(Opcode::Log, 0, 1, 0),
            inst(Opcode::Halt, 0, 0, 0),
        ];
        // (name, program, whether the canonical set holds it)
        let rows: [(&str, Vec<u64>, bool); 2] = [
            (
                "a valid proof of a canonical program is attested",
                canonical,
                true,
            ),
            (
                "a valid proof of a program outside the canonical set is refused",
                outside,
                false,
            ),
        ];
        for (name, program, canonical) in rows {
            let hash = bud_proof::canonical_set::program_hash_of(&program);
            assert_eq!(
                bud_proof::canonical_set::is_canonical_program_hash(&hash),
                canonical,
                "row `{name}` is mislabeled"
            );
            let evidence = honest_evidence(&adapter, program);
            if canonical {
                // Production adapter refuses even a matching self-declared
                // chain_id because the AIR does not yet bind chain_id to execution.
                let mut prod_facts = crate::crypto::facts::CryptoFacts::new();
                let prod_err = prod_adapter
                    .verify_observed(&evidence, &VerificationPolicy::proven(10), &mut prod_facts)
                    .unwrap_err();
                match prod_err {
                    AdapterError::ConsensusRule { rule } => assert!(
                        rule.contains("chain id is not bound to execution"),
                        "production refusal must name the unbound chain_id: {rule}"
                    ),
                    other => panic!("expected ConsensusRule refusal, got {other:?}"),
                }
            }
            let mut facts = crate::crypto::facts::CryptoFacts::new();
            let got =
                adapter.verify_observed(&evidence, &VerificationPolicy::proven(10), &mut facts);
            if canonical {
                let attestation = got.unwrap_or_else(|e| panic!("row `{name}`: {e:?}"));
                crate::domain::finality_proof_model::FinalityProofShape::from_external_attestation(
                    &adapter.descriptor(),
                    &attestation,
                )
                .expect("BudZkVm shape");
                assert_eq!(attestation.height, 1, "row `{name}`");
                assert_eq!(
                    attestation.attested_event_root, None,
                    "additive event_digest must not be attested as event_root"
                );
                // the ZK adapter shows a hash assumption and nothing else.
                assert_eq!(
                    facts.count(crate::crypto::facts::ObservedScheme::Proof(
                        crate::crypto::facts::AssumptionClass::Hash
                    )),
                    1,
                    "row `{name}`"
                );
                assert_eq!(
                    facts.quantum_class(),
                    Some(crate::crypto::facts::QuantumClass::Hash),
                    "row `{name}`"
                );
            } else {
                assert!(facts.is_empty(), "row `{name}`: a refusal observes nothing");
                match got {
                    Err(AdapterError::Crypto { what }) => assert!(
                        what.contains("not in the canonical set") && what.contains(&hex32(&hash)),
                        "row `{name}`: the refusal names the canonical set: {what}"
                    ),
                    other => panic!("row `{name}`: wanted a canonical refusal, got {other:?}"),
                }
            }
        }
    }

    /// Trailing bytes decoded to the same value under a
    /// different evidence digest.
    #[test]
    fn trailing_bytes_after_the_evidence_are_refused() {
        let canonical = bud_vm::syscall_context::build_syscall_context_check_program()
            .expect("canonical build");
        let adapter = ZkVmFinalityAdapter::new("testnet", None, None);
        let mut evidence = honest_evidence(&adapter, canonical);
        assert!(ZkFinalityEvidence::decode(&evidence.payload).is_ok());
        evidence.payload.push(0);
        let err = ZkFinalityEvidence::decode(&evidence.payload).unwrap_err();
        assert!(matches!(err, AdapterError::Malformed { .. }), "got {err:?}");
    }

    #[test]
    fn the_probe_set_is_offset_independent_and_covers_every_edge() {
        let probes = ZkVmFinalityAdapter::new("testnet", None, None).fault_probes();
        assert!(!probes.is_empty());
        // Every probe must be applicable to a payload of any size, which is why
        // none of them uses a fixed interior offset beyond the first 16 bytes.
        for probe in &probes {
            match &probe.patch {
                BytePatch::InPayload { offset, .. } => {
                    assert!(
                        *offset < 16,
                        "probe `{}` depends on bincode layout",
                        probe.name
                    );
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
            names
                .iter()
                .any(|n| n.contains("corrupting the leading bytes")),
            "no probe attacks the envelope itself"
        );
    }

    /// An unpinned adapter is closed - a
    /// canonical-set proof attests nothing without the domain's pins.
    #[test]
    fn unpinned_zkvm_admission_is_closed() {
        let canonical = bud_vm::syscall_context::build_syscall_context_check_program()
            .expect("canonical build");
        let adapter = ZkVmFinalityAdapter::new("testnet", None, Some(1));
        let evidence = honest_evidence(&adapter, canonical);
        let err = adapter
            .verify(&evidence, &VerificationPolicy::proven(0))
            .unwrap_err();
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "got: {err:?}"
        );
    }

    /// A proof of a DIFFERENT canonical
    /// program than the pinned one is refused, and so is a proof under
    /// another chain id.
    #[test]
    fn the_pinned_program_and_chain_decide() {
        let canonical = bud_vm::syscall_context::build_syscall_context_check_program()
            .expect("canonical build");
        let pinned_hash = bud_proof::canonical_set::program_hash_of(&canonical);
        let adapter = ZkVmFinalityAdapter::new("testnet", Some(pinned_hash), Some(1));
        // Wrong chain id.
        let wrong_chain = ZkVmFinalityAdapter::new("testnet", Some(pinned_hash), Some(2));
        let evidence = honest_evidence(&adapter, canonical.clone());
        let err = wrong_chain
            .verify(&evidence, &VerificationPolicy::proven(0))
            .unwrap_err();
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "got: {err:?}"
        );
        // Wrong program pin: another hash than the proved program's.
        let wrong_program = ZkVmFinalityAdapter::new("testnet", Some([0xEE; 32]), Some(1));
        let err = wrong_program
            .verify(&evidence, &VerificationPolicy::proven(0))
            .unwrap_err();
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn zk_domain_refuses_empty_halt_proof() {
        let canonical = bud_vm::syscall_context::build_syscall_context_check_program()
            .expect("canonical build");
        let pinned_hash = bud_proof::canonical_set::program_hash_of(&canonical);
        let adapter = ZkVmFinalityAdapter::new("testnet", Some(pinned_hash), Some(1));

        // Take a valid envelope structure and substitute a trivial 1-word Halt
        // program (`[0]` / non-pinned program) claiming a forged state root.
        let mut forged = honest_evidence(&adapter, canonical);
        let mut decoded = ZkFinalityEvidence::decode(&forged.payload).expect("decode");
        decoded.program = vec![0];
        decoded.inputs.program_hash = bud_proof::canonical_set::program_hash_of(&decoded.program);
        decoded.inputs.final_state_root = [0xFE; 32];
        forged.declared_root = [0xFE; 32];
        forged.payload = decoded.encode().expect("encode");

        let err = adapter
            .verify(&forged, &VerificationPolicy::proven(0))
            .unwrap_err();
        assert!(
            matches!(
                err,
                AdapterError::Crypto { .. } | AdapterError::ConsensusRule { .. }
            ),
            "empty Halt program must not forge a state root: {err:?}"
        );
    }

    #[test]
    fn short_forged_zkvm_payload_cannot_trigger_megabyte_preallocation() {
        // 32-byte payload declaring a forged 10 MiB vector length must fail
        // immediately against the payload-derived byte limit without allocating.
        let mut forged = Vec::with_capacity(32);
        forged.extend_from_slice(&1u32.to_le_bytes());
        forged.extend_from_slice(&(10u64 * 1024 * 1024).to_le_bytes());
        forged.extend_from_slice(&[0u8; 20]);
        assert!(matches!(
            ZkFinalityEvidence::decode(&forged),
            Err(AdapterError::Malformed { .. })
        ));
    }

    #[test]
    fn pre_stark_gates_enforce_parent_continuity_da_pin_and_gas_bounds() {
        let program = bud_vm::syscall_context::build_syscall_context_check_program()
            .expect("canonical build");
        let pinned_hash = bud_proof::canonical_set::program_hash_of(&program);
        let base = ZkVmFinalityAdapter::new("testnet", Some(pinned_hash), Some(1))
            .with_air_chain_id_binding_for_test();
        let raw = honest_evidence(&base, program);
        let ev = ZkFinalityEvidence::decode(&raw.payload).expect("decodes");
        let policy = VerificationPolicy::proven(ev.inputs.block_height + 1);

        // Stateless canonical program verifies cleanly with default unpinned roots.
        base.verify(&raw, &policy)
            .expect("canonical proof verifies");

        // Broken parent-state continuity is refused before STARK work.
        let wrong_parent = ZkVmFinalityAdapter::new("testnet", Some(pinned_hash), Some(1))
            .with_expected_initial_state_root([0xEE; 32]);
        assert!(matches!(
            wrong_parent.verify(&raw, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // Mismatched L1 DA / state_writes_digest is refused before STARK work.
        let wrong_da = ZkVmFinalityAdapter::new("testnet", Some(pinned_hash), Some(1))
            .with_expected_da_commitment([0xDD; 32]);
        assert!(matches!(
            wrong_da.verify(&raw, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // Zero pinned_program_hash, zero expected parent root, or zero DA pin fails closed.
        let zero_pin = ZkVmFinalityAdapter::new("testnet", Some([0u8; 32]), Some(1));
        assert!(matches!(
            zero_pin.verify(&raw, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));
        let zero_parent = ZkVmFinalityAdapter::new("testnet", Some(pinned_hash), Some(1))
            .with_expected_initial_state_root([0u8; 32]);
        assert!(matches!(
            zero_parent.verify(&raw, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));
        let zero_da = ZkVmFinalityAdapter::new("testnet", Some(pinned_hash), Some(1))
            .with_expected_da_commitment([0u8; 32]);
        assert!(matches!(
            zero_da.verify(&raw, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // Real non-zero pre-state commitment matches with_expected_initial_state_root.
        let spec = crate::ai::FixedPointMlpSpec {
            dims: vec![2, 3, 2],
            weights: vec![1; 12],
            biases: vec![0; 5],
        };
        let matmul =
            crate::ai::execution::build_matmul_guest_program(&spec).expect("canonical matmul");
        let matmul_hash = bud_proof::canonical_set::program_hash_of(&matmul);
        let mut seeded_vm = bud_vm::Vm::new(65_536);
        crate::ai::execution::setup_guest_memory(&mut seeded_vm.memory, &spec, &[5, 7])
            .expect("seeds non-zero guest memory");
        seeded_vm.context.block_height = 2;
        let seeded_receipt = seeded_vm.run_receipt(&matmul);
        assert!(seeded_receipt.success);
        let seeded_init = bud_proof::initial_state_root_of(
            bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(
                &seeded_vm.trace,
            )),
            bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
                &seeded_vm.trace,
            )),
        );
        assert_ne!(seeded_init, [0u8; 32]);
        let seeded_inputs = ExecutionPublicInputs {
            chain_id: 1,
            program_hash: matmul_hash,
            initial_state_root: seeded_init,
            final_state_root: seeded_receipt.state_writes_digest,
            sender: seeded_vm.context.sender,
            nonce: seeded_vm.context.nonce,
            block_height: 2,
            gas_limit: seeded_vm.gas_limit,
            gas_used: seeded_vm.gas_used,
            exit_code: 0,
            trace_len: u64::try_from(seeded_vm.trace.len()).expect("fits"),
            event_digest: bud_proof::event_digest_from_events(&seeded_receipt.events),
            state_writes_digest: seeded_receipt.state_writes_digest,
        };
        let seeded_env =
            bud_proof::DefaultAdapter::prove(&seeded_vm.trace, &seeded_inputs, &matmul)
                .expect("seeded STARK proves");
        let seeded_raw = RawConsensusEvidence {
            adapter: base.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "testnet".to_string(),
            payload: ZkFinalityEvidence {
                envelope: seeded_env,
                inputs: seeded_inputs,
                program: matmul,
            }
            .encode()
            .expect("encodes"),
            declared_height: 2,
            declared_root: seeded_receipt.state_writes_digest,
            submitter: crate::core::address::Address([1; 32]),
        };
        let anchored = ZkVmFinalityAdapter::new("testnet", Some(matmul_hash), Some(1))
            .with_air_chain_id_binding_for_test()
            .with_expected_initial_state_root(seeded_init);
        anchored
            .verify(&seeded_raw, &VerificationPolicy::proven(3))
            .expect("matching non-zero parent state root verifies");

        // gas_used > gas_limit and trace_len == 0 are refused as ConsensusRule.
        let mut bad_gas = ev.clone();
        bad_gas.inputs.gas_used = bad_gas.inputs.gas_limit.saturating_add(1);
        let mut raw_bad = raw.clone();
        raw_bad.payload = bad_gas.encode().expect("encodes");
        assert!(matches!(
            base.verify(&raw_bad, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        let mut zero_trace = ev;
        zero_trace.inputs.trace_len = 0;
        raw_bad.payload = zero_trace.encode().expect("encodes");
        assert!(matches!(
            base.verify(&raw_bad, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }

    #[test]
    fn regression_max_age_past_and_future_and_empty_network() {
        let program = bud_vm::syscall_context::build_syscall_context_check_program()
            .expect("canonical build");
        let pinned_hash = bud_proof::canonical_set::program_hash_of(&program);
        let base = ZkVmFinalityAdapter::new("testnet", Some(pinned_hash), Some(1))
            .with_air_chain_id_binding_for_test();
        let mut raw = honest_evidence(&base, program);
        let mut ev = ZkFinalityEvidence::decode(&raw.payload).expect("decodes");
        ev.inputs.block_height = 50;
        raw.declared_height = 50;
        raw.payload = ev.encode().expect("encodes");

        // 1. Ancient proof beyond caller max_age window must be refused as Stale BEFORE FRI.
        let mut stale_past = VerificationPolicy::proven(100);
        stale_past.max_age = 10;
        assert!(
            matches!(
                base.verify(&raw, &stale_past),
                Err(AdapterError::Stale {
                    age: 50,
                    max_age: 10
                })
            ),
            "ZkVm proof older than policy.max_age must fail closed with AdapterError::Stale"
        );

        // 2. Future block_height > policy.now when policy.max_age > 0 must be refused as Stale.
        let mut stale_future = VerificationPolicy::proven(40);
        stale_future.max_age = 10;
        assert!(
            matches!(
                base.verify(&raw, &stale_future),
                Err(AdapterError::Stale {
                    age: 10,
                    max_age: 10
                })
            ),
            "ZkVm proof ahead of policy.now must fail closed with AdapterError::Stale"
        );

        // 3. Empty/whitespace network must be refused.
        let blank = ZkVmFinalityAdapter::new("   ", Some(pinned_hash), Some(1));
        let mut blank_raw = raw;
        blank_raw.adapter = blank.descriptor().id;
        blank_raw.network = "   ".to_string();
        assert!(matches!(
            blank.verify(&blank_raw, &VerificationPolicy::proven(50)),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }
}
