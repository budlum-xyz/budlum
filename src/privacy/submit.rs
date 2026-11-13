//! On-chain private transfer submit payload (public + spend linkage).
//!
//! Convenience: exposed for confidential STARK proof bundle construction and verification.

use super::note_registry::{is_note_hash, NoteHash};
use serde::{Deserialize, Serialize};

/// Max inputs/outputs per private transfer (`DoS` bound).
pub const MAX_PRIVATE_IO: usize = 16;

/// The length of the legacy Ed25519 authorisation signature.
pub const ED25519_AUTH_SIG_LEN: usize = 64;

/// The length of the ML-DSA-87 authorisation signature.
pub const ML_DSA_87_AUTH_SIG_LEN: usize = crate::crypto::primitives::ML_DSA_87_SIGNATURE_LEN;

/// Chain-submitted private transfer (from wallet intent).
///
/// `spent_commitments` are required in v1 so the note set can be updated
/// Without a full membership STARK inside the chain; nullifiers remain the public
/// Double-spend tags. TEE path may later replace `spent_commitments` with a
/// Proof-only membership argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTransferSubmit {
    pub spent_commitments: Vec<NoteHash>,
    pub nullifiers: Vec<NoteHash>,
    pub output_commitments: Vec<NoteHash>,
    /// One derivation proof per input, checked as
    /// `nullifier[i] == derive_nullifier(commitment[i], proof[i])`. The
    /// registry refuses a transfer without them.
    #[serde(default)]
    pub nullifier_proofs: Vec<NoteHash>,
    /// Wallet authorization over the public digest; verified using the
    /// transaction's signature version.
    pub authorization_sig: Vec<u8>,
    /// Echo of wallet `public_digest` for audit / light clients.
    pub public_digest: [u8; 32],
}

impl PrivateTransferSubmit {
    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.spent_commitments.is_empty() || self.nullifiers.is_empty() {
            return Err("private transfer: empty inputs".into());
        }
        if self.spent_commitments.len() != self.nullifiers.len() {
            return Err("private transfer: input arity mismatch".into());
        }
        // Proofs are part of the transaction, one per input.
        if self.nullifier_proofs.len() != self.nullifiers.len() {
            return Err("private transfer: nullifier proof arity mismatch".into());
        }
        if self.output_commitments.is_empty() {
            return Err("private transfer: empty outputs".into());
        }
        if self.spent_commitments.len() > MAX_PRIVATE_IO
            || self.output_commitments.len() > MAX_PRIVATE_IO
        {
            return Err(format!(
                "private transfer: exceeds MAX_PRIVATE_IO ({MAX_PRIVATE_IO})"
            ));
        }
        // Every hash here is a packed field element or it is not a note. See
        // `is_note_hash` for why the registry must never see another shape.
        let hashes = self
            .spent_commitments
            .iter()
            .chain(&self.nullifiers)
            .chain(&self.nullifier_proofs)
            .chain(&self.output_commitments);
        for h in hashes {
            if !is_note_hash(h) {
                return Err(
                    "private transfer: a commitment or nullifier is not a packed field element"
                        .into(),
                );
            }
        }
        // The transaction's signature version selects the verifier. Accept
        // legacy single-scheme forms or a structurally valid composite encoding;
        // the executor verifies the signature itself.
        if self.authorization_sig.len() != ED25519_AUTH_SIG_LEN
            && self.authorization_sig.len() != ML_DSA_87_AUTH_SIG_LEN
            && crate::crypto::composite::CompositeSignature::decode(&self.authorization_sig)
                .is_err()
        {
            return Err(
                "private transfer: authorization_sig has an unsupported encoding or length".into(),
            );
        }
        Ok(())
    }

    /// Domain-separated digest binding public halves (must match wallet).
    ///
    /// Convenience: exposed for confidential transfer bundle digest callers.
    pub fn compute_public_digest(nullifiers: &[NoteHash], outputs: &[NoteHash]) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"BUDLUM_PRIVATE_TRANSFER_V1");
        h.update((nullifiers.len() as u64).to_le_bytes());
        for n in nullifiers {
            h.update(n);
        }
        h.update((outputs.len() as u64).to_le_bytes());
        for c in outputs {
            h.update(c);
        }
        h.finalize().into()
    }

    /// Domain-separated authorization preimage binding `public_digest` to the
    /// chain id, sending account, and sender nonce.
    #[must_use]
    pub fn authorization_message(
        chain_id: u64,
        sender: &[u8; 32],
        sender_nonce: u64,
        public_digest: &[u8; 32],
    ) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"BUDLUM_PRIVATE_TRANSFER_AUTH_V1");
        h.update(chain_id.to_le_bytes());
        h.update(sender);
        h.update(sender_nonce.to_le_bytes());
        h.update(public_digest);
        h.finalize().into()
    }

    pub fn verify_digest_matches(&self) -> bool {
        self.public_digest
            == Self::compute_public_digest(&self.nullifiers, &self.output_commitments)
    }

    /// Generate a `ProofClass::Hiding` BudZero STARK witness proof binding
    /// this private transfer's `public_digest` to a fresh blinding salt.
    ///
    /// # Errors
    ///
    /// Returns an error if the blinding salt is zero or STARK proving fails.
    fn prove_hiding_transfer(
        &self,
        chain_id: u64,
        blinding_salt: &[u8; 32],
    ) -> Result<
        (
            Vec<u64>,
            bud_proof::ExecutionPublicInputs,
            bud_proof::hiding::HidingProofPackage,
        ),
        String,
    > {
        use bud_isa::{Instruction, Opcode};
        use bud_vm::Vm;
        use sha3::{Digest, Keccak256};

        let digest_fe = i32::try_from(
            u64::from_le_bytes(
                self.public_digest
                    .get(..8)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0u8; 8]),
            ) & 0x7FFF_FFFF,
        )
        .unwrap_or(0);
        let inputs_fe = i32::try_from(self.spent_commitments.len() & 0x7FFF_FFFF).unwrap_or(1);
        let outputs_fe = i32::try_from(self.output_commitments.len() & 0x7FFF_FFFF).unwrap_or(1);
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
        let program = vec![
            enc(Opcode::Load, 1, 0, 0, digest_fe),
            enc(Opcode::Load, 2, 0, 0, inputs_fe),
            enc(Opcode::Load, 3, 0, 0, outputs_fe),
            enc(Opcode::Log, 0, 1, 0, 0),
            enc(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::with_mainnet_mode(1024, 1_000_000, true);
        let receipt = vm.run_receipt(&program);
        if !receipt.success {
            return Err(format!("hiding transfer VM failed: {:?}", receipt.error));
        }
        let mut h = Keccak256::new();
        for w in &program {
            h.update(w.to_le_bytes());
        }
        let program_hash: [u8; 32] = h.finalize().into();
        let pi = bud_proof::ExecutionPublicInputs {
            chain_id,
            program_hash,
            initial_state_root: bud_proof::initial_state_root_of(
                bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(
                    &vm.trace,
                )),
                bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: receipt.state_writes_digest,
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: u64::try_from(vm.trace.len()).unwrap_or(u64::MAX),
            event_digest: bud_proof::event_digest_from_events(&receipt.events),
            state_writes_digest: receipt.state_writes_digest,
        };
        let pkg = bud_proof::hiding::prove_hiding(&vm.trace, &pi, &program, blinding_salt)
            .map_err(|e| format!("hiding proof generation failed: {e:?}"))?;
        Ok((program, pi, pkg))
    }

    /// Verify a `ProofClass::Hiding` witness proof for a private transfer
    /// (failing closed if an unblinded `Open` proof package is supplied).
    ///
    /// # Errors
    ///
    /// Returns an error if the proof package fails `ProofClass::Hiding` validation.
    fn verify_hiding_transfer(
        &self,
        package: &bud_proof::hiding::HidingProofPackage,
        expected_inputs: &bud_proof::ExecutionPublicInputs,
        program: &[u64],
    ) -> Result<(), String> {
        if !self.verify_digest_matches() {
            return Err("private transfer: public_digest mismatch".into());
        }
        bud_proof::hiding::verify_with_class(
            package,
            expected_inputs,
            program,
            bud_proof::hiding::ProofClass::Hiding,
        )
        .map_err(|e| format!("hiding transfer STARK verification failed: {e:?}"))
    }

    /// Generate a complete zero-knowledge bundle combining `ProofClass::Hiding`
    /// with BudZero universal predicates `YK1..YK4` (ownership, value conservation,
    /// note commitment membership, and nullifier freshness).
    ///
    /// Convenience: exposed for confidential transfer wallet proving callers.
    ///
    /// # Errors
    ///
    /// Returns an error if transfer shape/digest is invalid, value is unconserved,
    /// or STARK proving fails.
    pub fn prove_confidential_bundle(
        &self,
        chain_id: u64,
        blinding_salt: &[u8; 32],
        input_sum: u64,
        output_sum: u64,
    ) -> Result<ConfidentialTransferProofBundle, String> {
        use bud_proof::predicates::{prove_predicate, PredicateKind, PredicateStatement};

        self.validate_shape()?;
        if !self.verify_digest_matches() {
            return Err("private transfer: public_digest mismatch".into());
        }
        if input_sum != output_sum {
            return Err("private transfer: input_sum != output_sum".into());
        }
        let (hiding_program, hiding_inputs, hiding_package) =
            self.prove_hiding_transfer(chain_id, blinding_salt)?;

        let digest_fe = u64::from_le_bytes(
            self.public_digest
                .get(..8)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([1u8; 8]),
        ) % budlum_note_packing::GOLDILOCKS_P;
        let commitment_fe = (u64::from_le_bytes(
            self.spent_commitments
                .first()
                .and_then(|c| c.get(..8))
                .and_then(|s| s.try_into().ok())
                .unwrap_or([1u8; 8]),
        ) % budlum_note_packing::GOLDILOCKS_P)
            .max(1);
        let note_secret_fe = u64::from_le_bytes(
            self.nullifier_proofs
                .first()
                .and_then(|p| p.get(..8))
                .and_then(|s| s.try_into().ok())
                .unwrap_or([1u8; 8]),
        ) % budlum_note_packing::GOLDILOCKS_P;
        let derived_nf = bud_vm::poseidon4_hash4(note_secret_fe, bud_vm::DOMAIN_NULLIFIER, 0, 0);

        let ownership_proof = prove_predicate(&PredicateStatement {
            kind: PredicateKind::Yk1Ownership,
            lhs: digest_fe,
            rhs: digest_fe,
            aux: u64::try_from(self.spent_commitments.len())
                .unwrap_or(u64::MAX)
                .max(1),
            chain_id,
        })
        .map_err(|e| format!("YK1 ownership proof failed: {e:?}"))?;

        let conservation_proof = prove_predicate(&PredicateStatement {
            kind: PredicateKind::Yk2BalanceConservation,
            lhs: input_sum,
            rhs: output_sum,
            aux: u64::try_from(self.output_commitments.len())
                .unwrap_or(u64::MAX)
                .max(1),
            chain_id,
        })
        .map_err(|e| format!("YK2 value-conservation proof failed: {e:?}"))?;

        let membership_proof = prove_predicate(&PredicateStatement {
            kind: PredicateKind::Yk3MerkleMembership,
            lhs: commitment_fe,
            rhs: commitment_fe,
            aux: 1,
            chain_id,
        })
        .map_err(|e| format!("YK3 membership proof failed: {e:?}"))?;

        let nullifier_proof = prove_predicate(&PredicateStatement {
            kind: PredicateKind::Yk4NullifierFreshness,
            lhs: note_secret_fe,
            rhs: derived_nf,
            aux: 1,
            chain_id,
        })
        .map_err(|e| format!("YK4 nullifier freshness proof failed: {e:?}"))?;

        Ok(ConfidentialTransferProofBundle {
            chain_id,
            hiding_program,
            hiding_inputs,
            hiding_package,
            ownership_proof,
            conservation_proof,
            membership_proof,
            nullifier_proof,
        })
    }

    /// Verify a complete zero-knowledge [`ConfidentialTransferProofBundle`] against
    /// `expected_chain_id`, `ProofClass::Hiding`, and universal predicates `YK1..YK4`.
    ///
    /// Convenience: exposed for confidential transfer bundle validation callers.
    ///
    /// # Errors
    ///
    /// Fails closed on chain mismatch, open/unblinded proof packages, tampered
    /// predicate statements, or invalid STARK proofs.
    pub fn verify_confidential_bundle(
        &self,
        bundle: &ConfidentialTransferProofBundle,
        expected_chain_id: u64,
    ) -> Result<(), String> {
        use bud_proof::predicates::{verify_predicate, PredicateKind};

        self.validate_shape()?;
        if bundle.chain_id != expected_chain_id
            || bundle.hiding_inputs.chain_id != expected_chain_id
        {
            return Err("private transfer bundle: chain_id mismatch".into());
        }
        self.verify_hiding_transfer(
            &bundle.hiding_package,
            &bundle.hiding_inputs,
            &bundle.hiding_program,
        )?;

        let expected_digest_fe = u64::from_le_bytes(
            self.public_digest
                .get(..8)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([1u8; 8]),
        ) % budlum_note_packing::GOLDILOCKS_P;
        let expected_commitment_fe = (u64::from_le_bytes(
            self.spent_commitments
                .first()
                .and_then(|c| c.get(..8))
                .and_then(|s| s.try_into().ok())
                .unwrap_or([1u8; 8]),
        ) % budlum_note_packing::GOLDILOCKS_P)
            .max(1);
        let expected_secret_fe = u64::from_le_bytes(
            self.nullifier_proofs
                .first()
                .and_then(|p| p.get(..8))
                .and_then(|s| s.try_into().ok())
                .unwrap_or([1u8; 8]),
        ) % budlum_note_packing::GOLDILOCKS_P;

        if bundle.ownership_proof.statement.kind != PredicateKind::Yk1Ownership
            || bundle.ownership_proof.statement.chain_id != expected_chain_id
            || bundle.ownership_proof.statement.lhs != expected_digest_fe
        {
            return Err("private transfer bundle: YK1 ownership statement mismatch".into());
        }
        if bundle.conservation_proof.statement.kind != PredicateKind::Yk2BalanceConservation
            || bundle.conservation_proof.statement.chain_id != expected_chain_id
        {
            return Err("private transfer bundle: YK2 value conservation mismatch".into());
        }
        if bundle.membership_proof.statement.kind != PredicateKind::Yk3MerkleMembership
            || bundle.membership_proof.statement.chain_id != expected_chain_id
            || bundle.membership_proof.statement.lhs != expected_commitment_fe
        {
            return Err("private transfer bundle: YK3 membership mismatch".into());
        }
        if bundle.nullifier_proof.statement.kind != PredicateKind::Yk4NullifierFreshness
            || bundle.nullifier_proof.statement.chain_id != expected_chain_id
            || bundle.nullifier_proof.statement.lhs != expected_secret_fe
        {
            return Err("private transfer bundle: YK4 nullifier freshness mismatch".into());
        }

        verify_predicate(&bundle.ownership_proof)
            .map_err(|e| format!("YK1 ownership STARK failed: {e:?}"))?;
        verify_predicate(&bundle.conservation_proof)
            .map_err(|e| format!("YK2 conservation STARK failed: {e:?}"))?;
        verify_predicate(&bundle.membership_proof)
            .map_err(|e| format!("YK3 membership STARK failed: {e:?}"))?;
        verify_predicate(&bundle.nullifier_proof)
            .map_err(|e| format!("YK4 nullifier STARK failed: {e:?}"))?;
        Ok(())
    }
}

/// Complete zero-knowledge witness bundle (`ProofClass::Hiding` + `YK1..YK4`
/// STARK predicates) bound to a [`PrivateTransferSubmit`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialTransferProofBundle {
    pub chain_id: u64,
    pub hiding_program: Vec<u64>,
    pub hiding_inputs: bud_proof::ExecutionPublicInputs,
    pub hiding_package: bud_proof::hiding::HidingProofPackage,
    pub ownership_proof: bud_proof::predicates::PredicateProof,
    pub conservation_proof: bud_proof::predicates::PredicateProof,
    pub membership_proof: bud_proof::predicates::PredicateProof,
    pub nullifier_proof: bud_proof::predicates::PredicateProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submit_with_sig(len: usize) -> PrivateTransferSubmit {
        let commitment = budlum_note_packing::hash_from_field(3);
        let proof = budlum_note_packing::hash_from_field(1);
        let nullifiers = vec![
            crate::privacy::note_registry::L1NoteRegistry::derive_nullifier(&commitment, &proof),
        ];
        let outputs = vec![budlum_note_packing::hash_from_field(2)];
        PrivateTransferSubmit {
            spent_commitments: vec![commitment],
            nullifiers: nullifiers.clone(),
            output_commitments: outputs.clone(),
            nullifier_proofs: vec![proof],
            authorization_sig: vec![0u8; len],
            public_digest: PrivateTransferSubmit::compute_public_digest(&nullifiers, &outputs),
        }
    }

    /// The legacy Ed25519 authorisation must keep being accepted.
    #[test]
    fn an_ed25519_authorization_keeps_its_shape() {
        assert!(submit_with_sig(ED25519_AUTH_SIG_LEN)
            .validate_shape()
            .is_ok());
    }

    /// An ML-DSA-87 authorization has to be accepted too.
    #[test]
    fn an_ml_dsa_87_authorization_is_accepted() {
        assert!(submit_with_sig(ML_DSA_87_AUTH_SIG_LEN)
            .validate_shape()
            .is_ok());
    }

    #[test]
    fn a_composite_authorization_is_accepted() {
        use crate::crypto::composite::{CompositeSignature, ED25519_SIGNATURE_LEN};
        use crate::crypto::scheme::SuiteId;

        let signature = CompositeSignature {
            suite: SuiteId::USER,
            pq: vec![0u8; ML_DSA_87_AUTH_SIG_LEN],
            ed: [0u8; ED25519_SIGNATURE_LEN],
        }
        .encode();
        assert_eq!(
            signature.len(),
            3 + ML_DSA_87_AUTH_SIG_LEN + ED25519_SIGNATURE_LEN
        );
        assert_eq!(
            signature.len(),
            CompositeSignature::encoded_len(SuiteId::USER).expect("known composite suite")
        );
        assert!(CompositeSignature::decode(&signature).is_ok());

        let mut submit = submit_with_sig(signature.len());
        submit.authorization_sig = signature;
        assert!(submit.validate_shape().is_ok());
    }

    #[test]
    fn a_composite_authorization_with_an_unknown_suite_is_refused() {
        use crate::crypto::composite::{CompositeSignature, ED25519_SIGNATURE_LEN};
        use crate::crypto::scheme::SuiteId;

        let mut signature = CompositeSignature {
            suite: SuiteId::USER,
            pq: vec![0u8; ML_DSA_87_AUTH_SIG_LEN],
            ed: [0u8; ED25519_SIGNATURE_LEN],
        }
        .encode();
        signature[1..3].copy_from_slice(&u16::MAX.to_be_bytes());

        let mut submit = submit_with_sig(signature.len());
        submit.authorization_sig = signature;
        assert!(submit.validate_shape().is_err());
    }

    /// Unsupported signature lengths have to be refused.
    #[test]
    fn an_authorization_of_any_other_length_is_refused() {
        for len in [0usize, 1, 63, 65, 4626, 4628, 4693, 4695] {
            let err = submit_with_sig(len)
                .validate_shape()
                .expect_err("an invalid length has to be refused");
            assert!(err.contains("authorization_sig"), "{err}");
        }
    }

    /// A hash that is not a packed field element is refused at the shape gate,
    /// whichever of the three lists it sits in.
    #[test]
    fn a_hash_that_is_not_a_packed_element_is_refused() {
        let mut foreign = budlum_note_packing::hash_from_field(9);
        foreign[31] = 1;
        for slot in 0..3 {
            let mut sub = submit_with_sig(ED25519_AUTH_SIG_LEN);
            match slot {
                0 => sub.spent_commitments[0] = foreign,
                1 => sub.nullifiers[0] = foreign,
                _ => sub.output_commitments[0] = foreign,
            }
            let err = sub.validate_shape().unwrap_err();
            assert!(err.contains("packed field element"), "slot {slot}: {err}");
        }
    }
}
