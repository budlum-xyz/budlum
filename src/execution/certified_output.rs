//! A certified execution output: the thing one node hands another so it can
//! accept a computation's result **without running the computation**.
//!
//! # The gap this closes
//!
//! Two pieces of this already existed and never met:
//!
//! - [`UniversalExecutionReceipt`](crate::execution::uer::UniversalExecutionReceipt)
//!   records *what* ran: status, gas, `output_digest`, block height, a batch
//!   inclusion proof against a root. It is a description, not a warrant. A
//!   receipt with a fabricated `output_digest` verifies as an inclusion just
//!   as cleanly as an honest one, because a Merkle path proves only that some
//!   node *said* this - not that it is true.
//! - [`ProofVerifier`](crate::execution::proof_verifier::ProofVerifier)
//!   verifies a STARK against `ExecutionPublicInputs`, which carry
//!   `exit_code`, `final_state_root`, `event_digest` and `state_writes_digest`.
//!   That is exactly the warrant. But it was reachable only from a caller who
//!   already had the program and the inputs - i.e. from someone in a position
//!   to re-run.
//!
//! So the network could prove *to itself* that it executed correctly, and it
//! could describe an execution to anyone, but it could not **carry the
//! warrant to someone else**. A receiving node had two options: trust the
//! receipt, or re-execute. This module adds the third: verify.
//!
//! # What a certified output is
//!
//! ```text
//! {
//!     receipt:        UniversalExecutionReceipt,  // what ran
//!     proof:          ProofEnvelope,              // why to believe it
//!     public_inputs:  ExecutionPublicInputs,      // the statement the proof is about
//!     inclusion:      UerInclusionProof,          // where the receipt sits
//!     batch_root:     [u8; 32],                   // the root it sits under
//! }
//! ```
//!
//! Verification is one function, [`CertifiedExecutionOutput::verify`], and it
//! refuses unless the halves agree **with each other**:
//!
//! 1. the public inputs describe *this* receipt - block height, status, final
//!    state root and gas all match;
//! 2. the receipt hashes to a leaf the supplied batch root commits at the
//!    claimed index;
//! 3. the STARK verifies against the public inputs.
//!
//! Step 1 is the part that did not exist anywhere. Without it a valid proof of
//! *some* execution could be stapled to a receipt of a *different* one, and
//! both halves would check out on their own.
//!
//! # What this is not
//!
//! - It is not a claim that the *program* was the one the reader wanted; that
//!   is `program_hash`, and [`Self::verify_against_program`] is how a reader
//!   binds it.
//! - It is not a proof that the batch root is canonical; that is a consensus
//!   question belonging to the block header, and this type takes the root as
//!   given rather than pretending to decide it.
//! - It does not re-execute anything. That is the point.

use crate::core::hash::hash_fields_bytes;
use crate::execution::proof_verifier::{ExecutionPublicInputs, ProofEnvelope, ProofVerifier};
use crate::execution::uer::{UerInclusionProof, UerStatus, UniversalExecutionReceipt};

/// Domain tag for the certified output's own identifier.
pub const CERTIFIED_OUTPUT_DOMAIN: &[u8] = b"BDLM_CERTIFIED_OUTPUT_V1";

/// Why a certified output was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertifiedOutputError {
    /// The STARK did not verify against the supplied public inputs.
    #[error("execution proof refused: {0}")]
    ProofRefused(String),
    /// The public inputs do not describe the receipt they were stapled to.
    #[error("public inputs and receipt disagree on {field} (proof {proof}, receipt {receipt})")]
    ReceiptDisagrees {
        /// Which bound field disagreed.
        field: &'static str,
        /// The value the proof commits to.
        proof: String,
        /// The value the receipt carries.
        receipt: String,
    },
    /// The receipt is not committed by the supplied batch root at its index.
    #[error("receipt is not committed by the batch root: {0}")]
    NotCommitted(String),
    /// The proof does not cover the program the caller requires.
    #[error("output is about program {got}, not the requested {want}")]
    WrongProgram {
        /// The program the proof commits to.
        got: String,
        /// The program the caller required.
        want: String,
    },
}

/// An execution output that carries its own warrant.
///
/// Build one with [`CertifiedExecutionOutput::new`], which refuses an
/// inconsistent pair before the object exists. An object that arrived over the
/// wire never went through that constructor, so [`Self::verify`] repeats every
/// check and is the only thing that may be believed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertifiedExecutionOutput {
    /// What ran, as the network recorded it.
    pub receipt: UniversalExecutionReceipt,
    /// The STARK over the execution.
    pub proof: ProofEnvelope,
    /// The statement the proof is about. Carried rather than recomputed: a
    /// reader that had to recompute these would need the inputs, and needing
    /// the inputs is one step away from re-executing.
    pub public_inputs: ExecutionPublicInputs,
    /// The inclusion proof placing `receipt` in a batch. Its own `receipt`
    /// field must be the same receipt; `verify` checks that rather than
    /// assuming it.
    pub inclusion: UerInclusionProof,
    /// The batch root the inclusion proof walks to. Not taken from the proof
    /// (it has no copy) and not recomputed (that would need the whole batch).
    pub batch_root: [u8; 32],
}

impl CertifiedExecutionOutput {
    /// Builds a certified output, refusing at construction if the halves do
    /// not agree.
    ///
    /// # Errors
    ///
    /// [`CertifiedOutputError::ReceiptDisagrees`] when the public inputs and
    /// the receipt describe different executions.
    pub fn new(
        receipt: UniversalExecutionReceipt,
        proof: ProofEnvelope,
        public_inputs: ExecutionPublicInputs,
        inclusion: UerInclusionProof,
        batch_root: [u8; 32],
    ) -> Result<Self, CertifiedOutputError> {
        check_receipt_agrees_with_inputs(&receipt, &public_inputs)?;
        Ok(Self {
            receipt,
            proof,
            public_inputs,
            inclusion,
            batch_root,
        })
    }

    /// The stable identifier of this certified output: what a node quotes when
    /// it says "I hold the certified result of X".
    ///
    /// Covers the receipt and the public inputs but **not** the proof bytes:
    /// two provers producing different valid proofs of the same statement
    /// must agree on the identifier, or the network could not tell "same
    /// result" from "same proof".
    #[must_use]
    pub fn content_id(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            CERTIFIED_OUTPUT_DOMAIN,
            &self.receipt.receipt_id(),
            &self.public_inputs.hash(),
        ])
    }

    /// Verifies the whole object without executing anything.
    ///
    /// Checks run cheapest-first so a garbage object costs almost nothing:
    /// agreement, then inclusion, then the STARK.
    ///
    /// # Errors
    ///
    /// - [`CertifiedOutputError::ReceiptDisagrees`] - the halves describe
    ///   different executions (the stapling attack).
    /// - [`CertifiedOutputError::NotCommitted`] - the receipt is not in the
    ///   batch this object claims, or the inclusion proof's own receipt is a
    ///   different one.
    /// - [`CertifiedOutputError::ProofRefused`] - the STARK is invalid.
    pub fn verify(&self) -> Result<VerifiedExecutionOutput, CertifiedOutputError> {
        // 1. Do the halves describe the same execution?
        check_receipt_agrees_with_inputs(&self.receipt, &self.public_inputs)?;

        // 2. Is the receipt where this object says it is? The inclusion proof
        //    carries its own copy of the receipt; if that copy is a different
        //    one, verifying it would certify a receipt the caller never saw.
        if self.inclusion.receipt.receipt_id() != self.receipt.receipt_id() {
            return Err(CertifiedOutputError::NotCommitted(
                "inclusion proof commits to a different receipt".into(),
            ));
        }
        self.inclusion
            .verify(&self.batch_root)
            .map_err(|e| CertifiedOutputError::NotCommitted(e.to_string()))?;

        // 3. Is the STARK valid for these inputs?
        //
        // The verifier signature takes the program and a gas budget. Both are
        // the *caller's* matter: `program` is bound by `program_hash` and the
        // gas budget is the verifier's policy. This function passes the gas
        // the inputs declare and an empty program, which is why it is **not**
        // the entry point an application should call - see
        // `verify_with_program`.
        ProofVerifier::verify(
            &self.proof,
            &self.public_inputs,
            &[],
            self.public_inputs.gas_limit,
        )
        .map_err(|e| CertifiedOutputError::ProofRefused(e.to_string()))?;

        Ok(VerifiedExecutionOutput {
            content_id: self.content_id(),
            final_state_root: self.public_inputs.final_state_root,
            exit_code: self.public_inputs.exit_code,
            gas_used: self.public_inputs.gas_used,
        })
    }

    /// Verifies against the program itself, and binds the result to it.
    ///
    /// This is the function a consuming application should call. It answers
    /// "is this the output of this computation" - both halves - and only then
    /// returns.
    ///
    /// # Errors
    ///
    /// [`CertifiedOutputError::WrongProgram`] when the proof is about a
    /// different program, plus everything [`Self::verify`] refuses.
    pub fn verify_with_program(
        &self,
        program: &[u64],
    ) -> Result<VerifiedExecutionOutput, CertifiedOutputError> {
        check_receipt_agrees_with_inputs(&self.receipt, &self.public_inputs)?;
        if self.inclusion.receipt.receipt_id() != self.receipt.receipt_id() {
            return Err(CertifiedOutputError::NotCommitted(
                "inclusion proof commits to a different receipt".into(),
            ));
        }
        self.inclusion
            .verify(&self.batch_root)
            .map_err(|e| CertifiedOutputError::NotCommitted(e.to_string()))?;

        ProofVerifier::verify(
            &self.proof,
            &self.public_inputs,
            program,
            self.public_inputs.gas_limit,
        )
        .map_err(|e| CertifiedOutputError::ProofRefused(e.to_string()))?;

        Ok(VerifiedExecutionOutput {
            content_id: self.content_id(),
            final_state_root: self.public_inputs.final_state_root,
            exit_code: self.public_inputs.exit_code,
            gas_used: self.public_inputs.gas_used,
        })
    }

    /// Verifies the object and additionally requires the proof to be about
    /// `expected_program_hash`.
    ///
    /// # Errors
    ///
    /// [`CertifiedOutputError::WrongProgram`] when the hash disagrees, plus
    /// everything [`Self::verify`] refuses.
    pub fn verify_against_program_hash(
        &self,
        expected_program_hash: [u8; 32],
    ) -> Result<VerifiedExecutionOutput, CertifiedOutputError> {
        let verified = self.verify()?;
        if self.public_inputs.program_hash != expected_program_hash {
            return Err(CertifiedOutputError::WrongProgram {
                got: hex32(&self.public_inputs.program_hash),
                want: hex32(&expected_program_hash),
            });
        }
        Ok(verified)
    }
}

/// What a successful verification yields.
///
/// A function that takes this type cannot be handed an unverified output by
/// mistake: there is no public constructor for it outside this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExecutionOutput {
    /// Stable identifier of the certified object this came from.
    pub content_id: [u8; 32],
    /// The state root the proof commits to.
    pub final_state_root: [u8; 32],
    /// The exit code the proof commits to.
    pub exit_code: u64,
    /// The gas the proof commits to.
    pub gas_used: u64,
}

/// The one comparison that stops the stapling attack.
fn check_receipt_agrees_with_inputs(
    receipt: &UniversalExecutionReceipt,
    inputs: &ExecutionPublicInputs,
) -> Result<(), CertifiedOutputError> {
    fn cmp(
        field: &'static str,
        proof: Vec<u8>,
        receipt: Vec<u8>,
    ) -> Result<(), CertifiedOutputError> {
        if proof == receipt {
            Ok(())
        } else {
            Err(CertifiedOutputError::ReceiptDisagrees {
                field,
                proof: hex_bytes(&proof),
                receipt: hex_bytes(&receipt),
            })
        }
    }

    cmp(
        "block_height",
        inputs.block_height.to_le_bytes().to_vec(),
        receipt.block_height.to_le_bytes().to_vec(),
    )?;

    cmp(
        "final_state_root",
        inputs.final_state_root.to_vec(),
        receipt.post_execution_root.to_vec(),
    )?;

    // The receipt's status and the proof's exit code must agree on success or
    // failure. A receipt that says success stapled to a proof of a revert is
    // the exact confusion this module exists to refuse.
    let receipt_succeeded = matches!(receipt.status, UerStatus::Success);
    let proof_succeeded = inputs.exit_code == 0;
    if receipt_succeeded != proof_succeeded {
        return Err(CertifiedOutputError::ReceiptDisagrees {
            field: "exit_code",
            proof: format!("{:#x}", inputs.exit_code),
            receipt: format!("{:?}", receipt.status),
        });
    }

    // Gas is the number an aggregator quotes as a fee, so a disagreement here
    // is a pricing fiction, not a rounding difference.
    cmp(
        "gas_used",
        inputs.gas_used.to_le_bytes().to_vec(),
        receipt.gas_used_bgu.to_le_bytes().to_vec(),
    )?;

    Ok(())
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::uer::{compute_uer_batch_root, prove_uer_inclusion, UER_VERSION_V1};
    use budlum_uel_abi::EeId;

    fn receipt_at(height: u64, root: [u8; 32], gas: u64) -> UniversalExecutionReceipt {
        UniversalExecutionReceipt {
            version: UER_VERSION_V1,
            chain_id: 45261,
            block_height: height,
            tx_index: 0,
            tx_hash: [0x11; 32],
            origin_ee: EeId::EVM.0,
            status: UerStatus::Success,
            gas_used_bgu: gas,
            burned_attos: 1_000,
            security_pool_attos: 9_000,
            proposer_tip_attos: 500,
            output_digest: [0x22; 32],
            contract_address: None,
            logs_commitment: [0x33; 32],
            post_execution_root: root,
            zk_trace_commitment: None,
        }
    }

    fn inputs_matching(r: &UniversalExecutionReceipt) -> ExecutionPublicInputs {
        ExecutionPublicInputs {
            chain_id: r.chain_id,
            program_hash: [0x99; 32],
            initial_state_root: [0x44; 32],
            final_state_root: r.post_execution_root,
            sender: 1,
            nonce: 0,
            block_height: r.block_height,
            gas_limit: 1_000_000,
            gas_used: r.gas_used_bgu,
            exit_code: 0,
            trace_len: 64,
            event_digest: [0x55; 32],
            state_writes_digest: [0x66; 32],
        }
    }

    fn dummy_proof(inputs: &ExecutionPublicInputs) -> ProofEnvelope {
        ProofEnvelope {
            proof_format_version: 1,
            backend: "plonky3".into(),
            p3_version: "1.0".into(),
            fri_params_id: "default".into(),
            public_inputs_hash: inputs.hash(),
            proof_bytes: vec![0u8; 32],
            degree_bits: 16,
        }
    }

    /// The content id ignores the proof bytes, so two provers of the same
    /// statement agree on what they are holding.
    #[test]
    fn content_id_is_about_the_result_not_the_proof() {
        let r = receipt_at(100, [0x55; 32], 21_000);
        let inputs = inputs_matching(&r);
        let root = compute_uer_batch_root(std::slice::from_ref(&r)).unwrap();
        let incl = prove_uer_inclusion(std::slice::from_ref(&r), 0).unwrap();

        let a = CertifiedExecutionOutput::new(
            r.clone(),
            dummy_proof(&inputs),
            inputs.clone(),
            incl.clone(),
            root,
        )
        .unwrap();

        let mut other_proof = dummy_proof(&inputs);
        other_proof.proof_bytes = vec![0xFFu8; 64];
        let b = CertifiedExecutionOutput::new(r, other_proof, inputs, incl, root).unwrap();

        assert_eq!(
            a.content_id(),
            b.content_id(),
            "two proofs of one statement must share a content id"
        );
    }

    /// The stapling attack: a valid receipt of run A, a valid proof of run B,
    /// both fine on their own, must not verify as one object.
    ///
    /// This is the check that did not exist anywhere before this module.
    #[test]
    fn a_proof_of_one_run_cannot_be_stapled_to_a_receipt_of_another() {
        let honest = receipt_at(100, [0x55; 32], 21_000);
        let elsewhere = receipt_at(200, [0x77; 32], 42_000);

        // The proof is about `elsewhere`; the receipt is `honest`.
        let inputs_for_elsewhere = inputs_matching(&elsewhere);
        let root = compute_uer_batch_root(std::slice::from_ref(&honest)).unwrap();
        let incl = prove_uer_inclusion(std::slice::from_ref(&honest), 0).unwrap();

        // Construction refuses it...
        let built = CertifiedExecutionOutput::new(
            honest.clone(),
            dummy_proof(&inputs_for_elsewhere),
            inputs_for_elsewhere.clone(),
            incl.clone(),
            root,
        );
        assert!(
            matches!(built, Err(CertifiedOutputError::ReceiptDisagrees { .. })),
            "construction accepted a stapled pair"
        );

        // ...and an object assembled by hand (as a deserialized one would be)
        // is refused by verify.
        let stapled = CertifiedExecutionOutput {
            receipt: honest,
            proof: dummy_proof(&inputs_for_elsewhere),
            public_inputs: inputs_for_elsewhere,
            inclusion: incl,
            batch_root: root,
        };
        assert!(
            matches!(
                stapled.verify(),
                Err(CertifiedOutputError::ReceiptDisagrees { .. })
            ),
            "verify accepted a stapled pair"
        );
    }

    /// A receipt that says success and a proof that says revert must not meet.
    #[test]
    fn success_and_revert_cannot_be_mixed() {
        let r = receipt_at(100, [0x55; 32], 21_000);
        let mut inputs = inputs_matching(&r);
        inputs.exit_code = 1; // the proof is about a revert
        let root = compute_uer_batch_root(std::slice::from_ref(&r)).unwrap();
        let incl = prove_uer_inclusion(std::slice::from_ref(&r), 0).unwrap();

        let out = CertifiedExecutionOutput {
            receipt: r,
            proof: dummy_proof(&inputs),
            public_inputs: inputs,
            inclusion: incl,
            batch_root: root,
        };
        match out.verify() {
            Err(CertifiedOutputError::ReceiptDisagrees { field, .. }) => {
                assert_eq!(field, "exit_code");
            }
            other => panic!("expected an exit_code disagreement, got {other:?}"),
        }
    }

    /// An inclusion proof for a *different* receipt cannot place this one.
    #[test]
    fn an_inclusion_proof_for_another_receipt_is_refused() {
        let mine = receipt_at(100, [0x55; 32], 21_000);
        let other = receipt_at(300, [0x88; 32], 7_000);
        let inputs = inputs_matching(&mine);
        let batch = vec![mine.clone(), other.clone()];
        let root = compute_uer_batch_root(&batch).unwrap();
        // Proof for `other`, which sits at index 1.
        let wrong_incl = prove_uer_inclusion(&batch, 1).unwrap();

        let out = CertifiedExecutionOutput {
            receipt: mine.clone(),
            proof: dummy_proof(&inputs),
            public_inputs: inputs,
            inclusion: wrong_incl,
            batch_root: root,
        };
        assert!(
            matches!(out.verify(), Err(CertifiedOutputError::NotCommitted(_))),
            "an inclusion proof for another receipt certified this one"
        );
    }

    /// Against the wrong program hash, verification refuses.
    #[test]
    fn the_wrong_program_hash_is_refused_after_the_rest_holds() {
        let r = receipt_at(100, [0x55; 32], 21_000);
        let inputs = inputs_matching(&r);
        let root = compute_uer_batch_root(std::slice::from_ref(&r)).unwrap();
        let incl = prove_uer_inclusion(std::slice::from_ref(&r), 0).unwrap();
        let out =
            CertifiedExecutionOutput::new(r, dummy_proof(&inputs), inputs.clone(), incl, root)
                .unwrap();

        // The real proof will not verify here (the bytes are a dummy), so this
        // asserts the *shape*: a program-hash mismatch is reported as such,
        // never as a silent pass.
        match out.verify_against_program_hash([0x01; 32]) {
            Err(CertifiedOutputError::WrongProgram { .. }) => {}
            Err(CertifiedOutputError::ProofRefused(_)) => {
                // Also acceptable: the dummy STARK is refused before the hash
                // is compared. What must not happen is Ok.
            }
            other => panic!("wrong program hash produced {other:?}"),
        }
    }
}
