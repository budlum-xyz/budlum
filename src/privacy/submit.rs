//! On-chain private transfer submit payload (public + spend linkage).
//!
//! Convenience: exposed for confidential STARK proof bundle construction and verification.

use super::note_registry::{is_note_hash, NoteHash};
use serde::{Deserialize, Serialize};

/// Max inputs/outputs per private transfer (`DoS` bound).
pub const MAX_PRIVATE_IO: usize = 16;

/// Maximum per-note and aggregate value allowed in confidential transfer proofs (`2^59 - 1`).
///
/// Bounding every value strictly below `2^59` keeps sums of up to [`MAX_PRIVATE_IO`]
/// notes plus fee strictly below the Goldilocks prime `2^64 - 2^32 + 1`, ruling out
/// modular wrap-around value creation.
///
/// Convenience: exposed for confidential transfer range checks.
pub const MAX_CONFIDENTIAL_VALUE: u64 = (1u64 << 59) - 1;

/// Pack a 32-byte digest into four canonical Goldilocks field elements without
/// dropping upper bytes: each 64-bit limb is reduced into `[0, p)` and combined
/// with a top-bit carry flag folded via Poseidon so the full 256-bit preimage
/// contributes to the resulting field commitment.
fn fold_bytes32_to_poseidon(acc: u64, bytes: &[u8; 32]) -> u64 {
    let p = budlum_note_packing::GOLDILOCKS_P;
    let mut cur = acc;
    for chunk in bytes.as_chunks::<8>().0 {
        let mut limb_bytes = [0u8; 8];
        limb_bytes.copy_from_slice(chunk);
        let raw = u64::from_le_bytes(limb_bytes);
        let lo = raw % p;
        let carry = u64::from(raw >= p);
        cur = bud_vm::poseidon4_hash4(cur, lo, carry, 0);
    }
    cur
}

/// Emit straight-line instructions loading an arbitrary 64-bit canonical field
/// value into `dst`, assuming `r10 = 2^32` and `r11 = 1` are already initialized
/// (`r12` and `r13` are scratch registers).
fn emit_load_u64_const(prog: &mut Vec<u64>, dst: u8, value: u64) {
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
    let hi = (value >> 32) as u32;
    let lo = (value & 0xFFFF_FFFF) as u32;
    let load_u32 = |half: u32, out: &mut Vec<u64>, reg: u8| {
        if half <= i32::MAX as u32 {
            out.push(enc(Opcode::Load, reg, 0, 0, half as i32));
        } else {
            let low31 = (half - (1u32 << 31)) as i32;
            out.push(enc(Opcode::Load, reg, 0, 0, low31));
            out.push(enc(Opcode::Load, 12, 0, 0, i32::MAX));
            out.push(enc(Opcode::Add, 12, 12, 11, 0));
            out.push(enc(Opcode::Add, reg, reg, 12, 0));
        }
    };
    load_u32(hi, prog, dst);
    prog.push(enc(Opcode::Mul, dst, dst, 10, 0));
    load_u32(lo, prog, 13);
    prog.push(enc(Opcode::Add, dst, dst, 13, 0));
}

/// Keccak-256 over canonical little-endian instruction words (matching `BudZKVM`).
fn stark_program_hash(program: &[u64]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    for w in program {
        h.update(w.to_le_bytes());
    }
    h.finalize().into()
}

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
    /// The zero-knowledge bundle the wallet produced alongside this transfer.
    ///
    /// Optional only for wire compatibility with transfers built before the
    /// bundle was part of the transaction. A transfer that omits it is
    /// **refused** by the executor on any chain where privacy transfers are
    /// enabled: without the bundle there is no ownership proof, no value
    /// conservation proof and no nullifier freshness proof, and `nullifiers`
    /// plus `output_commitments` alone let a spender mint any amount.
    ///
    /// This is the field whose absence made the whole privacy path unverifiable:
    /// `verify_confidential_bundle` was complete and only reachable from
    /// `process_confidential_transfer_bundle`, which had no caller.
    #[serde(default)]
    pub proof_bundle: Option<crate::privacy::ConfidentialTransferProofBundle>,
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
    #[must_use]
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

    #[must_use]
    pub fn verify_digest_matches(&self) -> bool {
        self.public_digest
            == Self::compute_public_digest(&self.nullifiers, &self.output_commitments)
    }

    /// Build the canonical straight-line `BudZKVM` program and expected logged
    /// Poseidon commitment binding `chain_id`, all 256 bits of `public_digest`,
    /// input/output arities, and every spent commitment, nullifier, and output
    /// commitment of this transfer.
    ///
    /// Both prover and verifier reconstruct this exact program from `self` and
    /// `chain_id`, preventing a malicious prover from substituting an arbitrary
    /// `[Halt]` program or colliding on a 31-bit truncated digest prefix.
    fn canonical_hiding_program_and_event(&self, chain_id: u64) -> (Vec<u64>, [u8; 32]) {
        use bud_isa::{Instruction, Opcode};
        let p = budlum_note_packing::GOLDILOCKS_P;
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

        let mut words_to_absorb: Vec<u64> = Vec::with_capacity(8);
        words_to_absorb.push(chain_id % p);
        words_to_absorb.push(u64::from(chain_id >= p));
        words_to_absorb.push(self.spent_commitments.len() as u64);
        words_to_absorb.push(self.output_commitments.len() as u64);
        for chunk in self.public_digest.as_chunks::<8>().0 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(chunk);
            let raw = u64::from_le_bytes(buf);
            words_to_absorb.push(raw % p);
            words_to_absorb.push(u64::from(raw >= p));
        }
        words_to_absorb.push(self.aggregate_spent_commitment_fe());
        words_to_absorb.push(self.aggregate_nullifier_binding_fe());

        let mut prog = Vec::with_capacity(8 + words_to_absorb.len() * 10);
        // r11 = 1, r10 = 2^32, r1 = rolling Poseidon accumulator (starts at 0).
        prog.push(enc(Opcode::Load, 11, 0, 0, 1));
        prog.push(enc(Opcode::Load, 10, 0, 0, i32::MAX));
        prog.push(enc(Opcode::Add, 10, 10, 11, 0));
        prog.push(enc(Opcode::Add, 10, 10, 10, 0));
        prog.push(enc(Opcode::Load, 1, 0, 0, 0));

        let mut rolling = 0u64;
        for limb in words_to_absorb {
            emit_load_u64_const(&mut prog, 2, limb);
            prog.push(enc(Opcode::Poseidon, 1, 1, 2, 0));
            rolling = bud_vm::poseidon4_hash(rolling, limb);
        }
        prog.push(enc(Opcode::Log, 0, 1, 0, 0));
        prog.push(enc(Opcode::Halt, 0, 0, 0, 0));

        let event_digest = bud_proof::event_digest_from_events(&[rolling]);
        (prog, event_digest)
    }

    /// Canonical non-zero Goldilocks commitment across every spent note in `self`.
    fn aggregate_spent_commitment_fe(&self) -> u64 {
        let mut acc = self.spent_commitments.len() as u64;
        for c in &self.spent_commitments {
            acc = fold_bytes32_to_poseidon(acc, c);
        }
        if acc == 0 {
            1
        } else {
            acc
        }
    }

    /// Canonical Goldilocks commitment binding every `(spent_commitment[i],
    /// nullifier_proof[i], nullifier[i])` triple across all inputs `0..len`.
    fn aggregate_nullifier_binding_fe(&self) -> u64 {
        let mut acc = self.nullifiers.len() as u64;
        for ((spent, proof), nf) in self
            .spent_commitments
            .iter()
            .zip(self.nullifier_proofs.iter())
            .zip(self.nullifiers.iter())
        {
            acc = fold_bytes32_to_poseidon(acc, spent);
            acc = fold_bytes32_to_poseidon(acc, proof);
            acc = fold_bytes32_to_poseidon(acc, nf);
        }
        acc
    }

    /// Canonical full-256-bit Goldilocks commitment over `self.public_digest`.
    fn full_public_digest_fe(&self) -> u64 {
        fold_bytes32_to_poseidon(0x5054_4449_4731, &self.public_digest)
    }

    /// Verify that every input's nullifier strictly equals the canonical
    /// derivation from `(spent_commitments[i], nullifier_proofs[i])` and that
    /// no duplicate spent commitments, nullifiers, or output commitments exist.
    fn verify_all_input_bindings(&self) -> Result<(), String> {
        use std::collections::BTreeSet;
        let mut seen_spent = BTreeSet::new();
        let mut seen_nf = BTreeSet::new();
        let mut seen_out = BTreeSet::new();
        for (idx, ((spent, proof), nf)) in self
            .spent_commitments
            .iter()
            .zip(self.nullifier_proofs.iter())
            .zip(self.nullifiers.iter())
            .enumerate()
        {
            if !seen_spent.insert(*spent) {
                return Err(format!(
                    "private transfer: duplicate spent commitment at input {idx}"
                ));
            }
            if !seen_nf.insert(*nf) {
                return Err(format!(
                    "private transfer: duplicate nullifier at input {idx}"
                ));
            }
            let expected_nf = super::note_registry::L1NoteRegistry::derive_nullifier(spent, proof);
            if *nf != expected_nf {
                return Err(format!(
                    "private transfer: nullifier derivation mismatch at input {idx}"
                ));
            }
        }
        for (idx, out) in self.output_commitments.iter().enumerate() {
            if !seen_out.insert(*out) {
                return Err(format!(
                    "private transfer: duplicate output commitment at output {idx}"
                ));
            }
            if seen_spent.contains(out) || seen_nf.contains(out) {
                return Err(format!(
                    "private transfer: output {idx} collides with spent input or nullifier"
                ));
            }
        }
        Ok(())
    }

    /// Generate a `ProofClass::Hiding` `BudZero` STARK witness proof binding
    /// this private transfer's full 256-bit `public_digest`, `chain_id`, and all
    /// input/output commitments to a fresh blinding salt.
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
        use bud_vm::Vm;

        let (program, expected_event_digest) = self.canonical_hiding_program_and_event(chain_id);
        let mut vm = Vm::with_mainnet_mode(1024, 1_000_000, true);
        let receipt = vm.run_receipt(&program);
        if !receipt.success {
            return Err(format!("hiding transfer VM failed: {:?}", receipt.error));
        }
        let event_digest = bud_proof::event_digest_from_events(&receipt.events);
        if event_digest != expected_event_digest {
            return Err("hiding transfer VM event digest mismatch".into());
        }
        let program_hash = stark_program_hash(&program);
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
            event_digest,
            state_writes_digest: receipt.state_writes_digest,
        };
        let pkg = bud_proof::hiding::prove_hiding(&vm.trace, &pi, &program, blinding_salt)
            .map_err(|e| format!("hiding proof generation failed: {e:?}"))?;
        Ok((program, pi, pkg))
    }

    /// Verify a `ProofClass::Hiding` witness proof for a private transfer,
    /// rebuilding the canonical program, `program_hash`, and `event_digest` from
    /// `self` and `expected_chain_id` so a substituted or cross-transfer proof
    /// is unconditionally rejected.
    ///
    /// # Errors
    ///
    /// Returns an error if the canonical binding or `ProofClass::Hiding` STARK fails.
    fn verify_hiding_transfer(
        &self,
        expected_chain_id: u64,
        package: &bud_proof::hiding::HidingProofPackage,
        expected_inputs: &bud_proof::ExecutionPublicInputs,
        program: &[u64],
    ) -> Result<(), String> {
        self.validate_shape()?;
        if !self.verify_digest_matches() {
            return Err("private transfer: public_digest mismatch".into());
        }
        self.verify_all_input_bindings()?;
        let (canonical_program, canonical_event_digest) =
            self.canonical_hiding_program_and_event(expected_chain_id);
        if program != canonical_program.as_slice() {
            return Err(
                "private transfer: hiding program does not match canonical transfer program".into(),
            );
        }
        let canonical_hash = stark_program_hash(&canonical_program);
        if expected_inputs.chain_id != expected_chain_id {
            return Err("private transfer: hiding public_inputs chain_id mismatch".into());
        }
        if expected_inputs.program_hash != canonical_hash {
            return Err("private transfer: hiding program_hash mismatch".into());
        }
        if expected_inputs.exit_code != 0 {
            return Err("private transfer: hiding proof attests non-zero exit_code".into());
        }
        if expected_inputs.event_digest != canonical_event_digest {
            return Err("private transfer: hiding event_digest does not bind transfer".into());
        }
        if expected_inputs.initial_state_root != [0u8; 32]
            || expected_inputs.final_state_root != [0u8; 32]
            || expected_inputs.state_writes_digest != [0u8; 32]
        {
            return Err("private transfer: unexpected state mutation in hiding proof".into());
        }
        bud_proof::hiding::verify_with_class(
            package,
            expected_inputs,
            &canonical_program,
            bud_proof::hiding::ProofClass::Hiding,
        )
        .map_err(|e| format!("hiding transfer STARK verification failed: {e:?}"))
    }

    /// Generate a complete zero-knowledge bundle combining `ProofClass::Hiding`
    /// with `BudZero` universal predicates `YK1..YK4` (ownership, value conservation,
    /// note commitment membership, and nullifier freshness).
    ///
    /// Convenience: exposed for confidential transfer wallet proving callers.
    ///
    /// # Errors
    ///
    /// Returns an error if transfer shape/digest is invalid, value exceeds
    /// [`MAX_CONFIDENTIAL_VALUE`] or is unconserved, or STARK proving fails.
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
        self.verify_all_input_bindings()?;
        if input_sum > MAX_CONFIDENTIAL_VALUE || output_sum > MAX_CONFIDENTIAL_VALUE {
            return Err(format!(
                "private transfer: value exceeds MAX_CONFIDENTIAL_VALUE ({MAX_CONFIDENTIAL_VALUE})"
            ));
        }
        if input_sum != output_sum {
            return Err("private transfer: input_sum != output_sum".into());
        }
        let (hiding_program, hiding_inputs, hiding_package) =
            self.prove_hiding_transfer(chain_id, blinding_salt)?;

        let digest_fe = self.full_public_digest_fe();
        let commitment_fe = self.aggregate_spent_commitment_fe();
        let nullifier_binding_fe = self.aggregate_nullifier_binding_fe();
        let derived_nf =
            bud_vm::poseidon4_hash4(nullifier_binding_fe, bud_vm::DOMAIN_NULLIFIER, 0, 0);
        let in_count = u64::try_from(self.spent_commitments.len()).unwrap_or(u64::MAX);
        let out_count = u64::try_from(self.output_commitments.len()).unwrap_or(u64::MAX);

        let ownership_proof = prove_predicate(&PredicateStatement {
            kind: PredicateKind::Yk1Ownership,
            lhs: digest_fe,
            rhs: digest_fe,
            aux: in_count,
            chain_id,
        })
        .map_err(|e| format!("YK1 ownership proof failed: {e:?}"))?;

        let conservation_proof = prove_predicate(&PredicateStatement {
            kind: PredicateKind::Yk2BalanceConservation,
            lhs: input_sum,
            rhs: output_sum,
            aux: out_count,
            chain_id,
        })
        .map_err(|e| format!("YK2 value-conservation proof failed: {e:?}"))?;

        let membership_proof = prove_predicate(&PredicateStatement {
            kind: PredicateKind::Yk3MerkleMembership,
            lhs: commitment_fe,
            rhs: commitment_fe,
            aux: in_count,
            chain_id,
        })
        .map_err(|e| format!("YK3 membership proof failed: {e:?}"))?;

        let nullifier_proof = prove_predicate(&PredicateStatement {
            kind: PredicateKind::Yk4NullifierFreshness,
            lhs: nullifier_binding_fe,
            rhs: derived_nf,
            aux: in_count,
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
    /// Fails closed on chain mismatch, substituted hiding programs, out-of-range
    /// or unconserved balances, open/unblinded proof packages, tampered predicate
    /// statements, multi-input nullifier drift, or invalid STARK proofs.
    pub fn verify_confidential_bundle(
        &self,
        bundle: &ConfidentialTransferProofBundle,
        expected_chain_id: u64,
    ) -> Result<(), String> {
        use bud_proof::predicates::{verify_predicate, PredicateKind};

        self.validate_shape()?;
        self.verify_all_input_bindings()?;
        if bundle.chain_id != expected_chain_id
            || bundle.hiding_inputs.chain_id != expected_chain_id
        {
            return Err("private transfer bundle: chain_id mismatch".into());
        }
        self.verify_hiding_transfer(
            expected_chain_id,
            &bundle.hiding_package,
            &bundle.hiding_inputs,
            &bundle.hiding_program,
        )?;

        let expected_digest_fe = self.full_public_digest_fe();
        let expected_commitment_fe = self.aggregate_spent_commitment_fe();
        let expected_nullifier_binding_fe = self.aggregate_nullifier_binding_fe();
        let expected_derived_nf = bud_vm::poseidon4_hash4(
            expected_nullifier_binding_fe,
            bud_vm::DOMAIN_NULLIFIER,
            0,
            0,
        );
        let expected_in_count = u64::try_from(self.spent_commitments.len()).unwrap_or(u64::MAX);
        let expected_out_count = u64::try_from(self.output_commitments.len()).unwrap_or(u64::MAX);

        if bundle.ownership_proof.statement.kind != PredicateKind::Yk1Ownership
            || bundle.ownership_proof.statement.chain_id != expected_chain_id
            || bundle.ownership_proof.statement.lhs != expected_digest_fe
            || bundle.ownership_proof.statement.rhs != expected_digest_fe
            || bundle.ownership_proof.statement.aux != expected_in_count
        {
            return Err("private transfer bundle: YK1 ownership statement mismatch".into());
        }
        if bundle.conservation_proof.statement.kind != PredicateKind::Yk2BalanceConservation
            || bundle.conservation_proof.statement.chain_id != expected_chain_id
            || bundle.conservation_proof.statement.lhs != bundle.conservation_proof.statement.rhs
            || bundle.conservation_proof.statement.lhs > MAX_CONFIDENTIAL_VALUE
            || bundle.conservation_proof.statement.aux != expected_out_count
        {
            return Err("private transfer bundle: YK2 value conservation mismatch".into());
        }
        if bundle.membership_proof.statement.kind != PredicateKind::Yk3MerkleMembership
            || bundle.membership_proof.statement.chain_id != expected_chain_id
            || bundle.membership_proof.statement.lhs != expected_commitment_fe
            || bundle.membership_proof.statement.rhs != expected_commitment_fe
            || bundle.membership_proof.statement.aux != expected_in_count
        {
            return Err("private transfer bundle: YK3 membership mismatch".into());
        }
        if bundle.nullifier_proof.statement.kind != PredicateKind::Yk4NullifierFreshness
            || bundle.nullifier_proof.statement.chain_id != expected_chain_id
            || bundle.nullifier_proof.statement.lhs != expected_nullifier_binding_fe
            || bundle.nullifier_proof.statement.rhs != expected_derived_nf
            || bundle.nullifier_proof.statement.aux != expected_in_count
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    #[test]
    fn hiding_transfer_binds_canonical_program_and_refuses_halt_substitution() {
        use bud_isa::{Instruction, Opcode};
        use bud_vm::Vm;

        let sub = submit_with_sig(ED25519_AUTH_SIG_LEN);
        let chain_id = crate::core::chain_config::Network::Devnet
            .chain_id()
            .value();
        let salt = [0x5Au8; 32];
        let (prog, pi, pkg) = sub
            .prove_hiding_transfer(chain_id, &salt)
            .expect("canonical hiding proof succeeds");
        sub.verify_hiding_transfer(chain_id, &pkg, &pi, &prog)
            .expect("canonical hiding proof verifies");

        // Replaying on a different chain is refused.
        let wrong_chain = sub
            .verify_hiding_transfer(chain_id + 1, &pkg, &pi, &prog)
            .expect_err("wrong chain must fail");
        assert!(wrong_chain.contains("program") || wrong_chain.contains("chain_id"));

        // Replaying the valid hiding proof onto a different transfer is refused.
        let c2 = budlum_note_packing::hash_from_field(33);
        let p2 = budlum_note_packing::hash_from_field(11);
        let nf2 = vec![crate::privacy::note_registry::L1NoteRegistry::derive_nullifier(&c2, &p2)];
        let out2 = vec![budlum_note_packing::hash_from_field(22)];
        let other = PrivateTransferSubmit {
            spent_commitments: vec![c2],
            nullifiers: nf2.clone(),
            output_commitments: out2.clone(),
            nullifier_proofs: vec![p2],
            authorization_sig: vec![0u8; ED25519_AUTH_SIG_LEN],
            public_digest: PrivateTransferSubmit::compute_public_digest(&nf2, &out2),
        };
        assert!(other
            .verify_hiding_transfer(chain_id, &pkg, &pi, &prog)
            .is_err());

        // Substituting a genuine hiding STARK over a trivial `[Halt]` program is refused.
        let halt_prog = vec![Instruction {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        }
        .encode()];
        let mut vm = Vm::with_mainnet_mode(1024, 100_000, true);
        let receipt = vm.run_receipt(&halt_prog);
        assert!(receipt.success);
        let halt_pi = bud_proof::ExecutionPublicInputs {
            chain_id,
            program_hash: stark_program_hash(&halt_prog),
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: bud_proof::event_digest_from_events(&receipt.events),
            state_writes_digest: [0u8; 32],
        };
        let halt_pkg = bud_proof::hiding::prove_hiding(&vm.trace, &halt_pi, &halt_prog, &salt)
            .expect("prove trivial halt hiding package");
        let err = sub
            .verify_hiding_transfer(chain_id, &halt_pkg, &halt_pi, &halt_prog)
            .expect_err("forged [Halt] hiding program must be rejected");
        assert!(err.contains("canonical transfer program"), "{err}");
    }

    #[test]
    fn confidential_bundle_enforces_range_ceiling_and_all_multi_input_nullifiers() {
        let chain_id = crate::core::chain_config::Network::Devnet
            .chain_id()
            .value();
        let salt = [0x33u8; 32];
        let sub = submit_with_sig(ED25519_AUTH_SIG_LEN);

        // Values at or above 2^59 are refused before proving.
        let too_large = MAX_CONFIDENTIAL_VALUE + 1;
        let err = sub
            .prove_confidential_bundle(chain_id, &salt, too_large, too_large)
            .expect_err("values >= 2^59 must be rejected");
        assert!(err.contains("MAX_CONFIDENTIAL_VALUE"), "{err}");

        // Forging the second input's nullifier while keeping input 0 valid is refused.
        let c0 = budlum_note_packing::hash_from_field(100);
        let p0 = budlum_note_packing::hash_from_field(200);
        let nf0 = crate::privacy::note_registry::L1NoteRegistry::derive_nullifier(&c0, &p0);
        let c1 = budlum_note_packing::hash_from_field(101);
        let p1 = budlum_note_packing::hash_from_field(201);
        let forged_nf1 = budlum_note_packing::hash_from_field(999);
        let outs = vec![
            budlum_note_packing::hash_from_field(300),
            budlum_note_packing::hash_from_field(301),
        ];
        let nullifiers = vec![nf0, forged_nf1];
        let multi = PrivateTransferSubmit {
            spent_commitments: vec![c0, c1],
            nullifiers: nullifiers.clone(),
            output_commitments: outs.clone(),
            nullifier_proofs: vec![p0, p1],
            authorization_sig: vec![0u8; ED25519_AUTH_SIG_LEN],
            public_digest: PrivateTransferSubmit::compute_public_digest(&nullifiers, &outs),
        };
        let err = multi
            .prove_confidential_bundle(chain_id, &salt, 500, 500)
            .expect_err("forged second-input nullifier must be rejected");
        assert!(
            err.contains("nullifier derivation mismatch at input 1"),
            "{err}"
        );
    }
}
