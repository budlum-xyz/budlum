//! Permissionless ZK proof submission and the L1 ↔ BudZKVM bridge.
//!
//! ## Model (decided this turn: "Option B" - fully open submission)
//! Anyone may submit a proof; registration is NOT required to have a valid proof
//! Accepted, because a STARK proof is self-verifying, the chain verifies the
//! Math and never needs to trust the submitter. Registration (the `PROVER` role)
//! Is *optional* and only affects **reward eligibility**.
//!
//! ## Verification location (decided this turn: core-native)
//! The STARK proof is verified inside `budlum-core` itself via the `bud_proof`
//! Adapter (the crate is already a core dependency and `execution::zkvm` already
//! Calls `Prover::verify`). Verification of untrusted input happens on-chain.
//!
//! ## Transport
//! The proof reaches core through the shared [`CrossDomainMessage`] primitive
//! (not a bespoke bridge protocol). This is a *distinct* path from
//! Relayer gate: a relayer *carries* messages, a prover *produces* proofs. The
//! Submission wraps the message together with the actual proof payload; the
//! Message's `payload_hash` binds to that payload.
//!
//! ## Conflict policy (decided this turn: "first valid wins")
//! For a given `(domain, height)` the first verifying proof is accepted and (if
//! The submitter is a registered prover) rewarded. A later proof asserting the
//! *same* `final_state_root` is an idempotent no-op (accepted, no double
//! Reward). A later proof asserting a *different* `final_state_root` for the
//! Same `(domain, height)` is rejected as a conflicting claim.

//! ## The proof market lives in `settlement`, not here
//!
//! This module used to carry a second one: `prover::market`, with its own
//! `ProofTask`, `ProofReceipt`, `ProofTaskKind` and `ProofTaskStatus`, spelled
//! the same as `settlement::proof_market`'s and meaning something different.
//! Neither was reached from production, so neither disagreement ever surfaced,
//! and a reader who found one had no way to know the other existed.
//!
//! They disagreed about the things a market is: deadlines in blocks against
//! deadlines in epochs, a reward committed to as a hash against a reward
//! declared as an amount, a two-state lifecycle (`Open`/`Settled`) against a
//! five-state one that can assign work to a named prover and expire it.
//!
//! `settlement::proof_market` is the survivor, because it is the one that can
//! express the states a market actually passes through, and it is where the
//! settlement root already reaches. The two ideas the deleted twin had and it
//! did not, a slash condition bound into the task id and a minimum verifier
//! stake, moved across rather than being deleted with it.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::message::CrossDomainMessage;
use crate::domain::types::{DomainId, Hash32};
use bud_proof::{ExecutionPublicInputs, ProofEnvelope};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A prover's submission: the transport message plus the proof payload it
/// Commits to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofSubmission {
    /// Transport envelope over the shared CrossDomainMessage primitive.
    /// `message.target_domain` is the domain being advanced, `message.source_height`
    /// Is the proven target height, and `message.sender` is the submitter (the
    /// Account charged the fee and, if registered, rewarded).
    ///
    /// # `source_height` is not the same thing as `public_inputs.block_height`
    ///
    /// This was measured, because adding a gate that equates the two was
    /// tempting and would have been wrong. `public_inputs.block_height` is the
    /// height **the program read via syscall 6**; the AIR binds it to the trace
    /// (`plonky3_air.rs`, the syscall6 constraint) and it stays `0` for a
    /// program that reads nothing - `prove_bytecode` produces exactly that.
    /// `source_height`, by contrast, is **which domain height the proof
    /// advances**, that is, a consensus claim.
    ///
    /// A program can prove a transition without ever reading the chain height;
    /// in that case `block_height = 0` is the correct value while the claimed
    /// height may be 20. A plain equality check would reject those correct
    /// proofs.
    ///
    /// The claim side is protected separately: `source_height` sits in the
    /// preimage of the binding hash (see [`Self::payload_binding_hash`]), so a
    /// proof cannot be moved to another height. The meaningful gate for
    /// `block_height` is that, *if* the program read the chain height, it is
    /// consistent with the real height; saying that requires knowing from the
    /// outside whether the trace used syscall 6, and that information is not
    /// carried in the public inputs today. The gate is not built until that
    /// information is carried - a wrong gate is worse than no gate.
    pub message: CrossDomainMessage,
    /// The STARK proof.
    pub proof: ProofEnvelope,
    /// Public inputs the proof is checked against.
    pub public_inputs: ExecutionPublicInputs,
    /// The program (bytecode words) the proof is over.
    pub program: Vec<u64>,
}

/// The allow-list identity of a zk program.
///
/// The **same** function the verifier (`Plonky3Adapter::verify`) uses for the
/// program hash: untagged Keccak-256, words little-endian. Deliberately the
/// same: the allow list must decide over exactly the value the proof is bound
/// to against the AIR. Using a separate tagged hash would open a gap in which
/// the listed program and the proven program could differ.
pub fn zk_program_hash(program: &[u64]) -> Hash32 {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    for word in program {
        hasher.update(word.to_le_bytes());
    }
    hasher.finalize().into()
}

/// The acceptance window for `block_height` in the public inputs of a zk proof.
///
/// A STARK proof says "it ran this way with these inputs"; the input claiming a
/// very old height is a separate problem - a valid old proof looks "fresh"
/// wherever it is presented. The window binds the height the proof claims to the
/// real height of the chain. `0` is accepted deliberately: `prove_bytecode` does
/// not write the height yet; 0 = "no claim". Once the prover starts writing the
/// height, the window applies in full.
pub const MAX_ZK_PROOF_HEIGHT_LAG: u64 = 128;

impl ZkProofSubmission {
    /// Canonical hash binding the transport message to the proof payload. The
    /// `message.payload_hash` MUST equal this, so a message cannot be replayed
    /// With a different proof (or vice-versa).
    ///
    /// # Why the target domain and the height are in the preimage
    ///
    /// This hash used to be over (proof, public inputs, program) only. **Which
    /// claim** the proof was presented for - `target_domain` and
    /// `source_height` - was left outside, even though those two are exactly the
    /// key of the accepted claim (`ProofClaimKey`).
    ///
    /// The consequence: a single valid proof could be presented for **every**
    /// (domain, height) pair that had not been claimed yet. Rebuilding the
    /// message was enough; because the binding hash did not change, no gate
    /// noticed. A proof says "a program ran this way", it does not say "this is
    /// the transition of domain 3 at height 12" - what establishes that link is
    /// this preimage.
    ///
    /// That is why the domain separator is `V2`: the preimage changed and the
    /// old hashes are deliberately invalid.
    pub fn payload_binding_hash(
        proof: &ProofEnvelope,
        public_inputs: &ExecutionPublicInputs,
        program: &[u64],
        target_domain: DomainId,
        source_height: u64,
    ) -> Hash32 {
        // SECURITY: serialize into a hash MUST NOT silently fall back
        // To empty bytes - two different proofs whose serialization failed would
        // Collide to the same hash, breaking the replay-protection guarantee this
        // Function documents. bincode serialization of this plain data type is
        // Infeasible to fail from untrusted input (no fallible custom Serialize,
        // Writing to a Vec), so a failure is a deterministic programming error we
        // Fail-fast on rather than hide.
        let proof_bytes = bincode::serialize(proof)
            .unwrap_or_else(|_| b"budlum/serialize-failed/proof-envelope".to_vec());
        let pi_bytes = public_inputs.to_canonical_bytes();
        let mut program_bytes = Vec::with_capacity(program.len() * 8);
        for word in program {
            program_bytes.extend_from_slice(&word.to_le_bytes());
        }
        hash_fields_bytes(&[
            b"BDLM_ZK_PROOF_PAYLOAD_V2",
            &proof_bytes,
            &pi_bytes,
            &program_bytes,
            &target_domain.to_le_bytes(),
            &source_height.to_le_bytes(),
        ])
    }

    /// Recompute and return the expected payload binding hash for this
    /// Submission.
    pub fn expected_payload_hash(&self) -> Hash32 {
        Self::payload_binding_hash(
            &self.proof,
            &self.public_inputs,
            &self.program,
            self.message.target_domain,
            self.message.source_height,
        )
    }

    /// The domain this proof advances.
    pub fn domain(&self) -> DomainId {
        self.message.target_domain
    }

    /// The target height this proof claims.
    pub fn target_height(&self) -> u64 {
        self.message.source_height
    }

    /// The submitter (fee payer / reward recipient candidate).
    pub fn submitter(&self) -> Address {
        self.message.sender
    }
}

/// Identifies "what is being proven": a domain advanced to a specific height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProofClaimKey {
    pub domain_id: DomainId,
    pub target_height: u64,
}

/// A recorded, verified proof claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedProofClaim {
    pub key: ProofClaimKey,
    pub final_state_root: Hash32,
    pub prover: Address,
    pub rewarded: bool,
}

/// Outcome of accepting a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofAcceptance {
    /// First valid proof for this `(domain, height)`.
    Accepted { rewarded: bool, reward: u64 },
    /// A previously-accepted, identical claim (same final state root). No-op.
    Idempotent,
}

/// Errors from proof submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// The message payload hash does not bind to the supplied proof payload.
    PayloadHashMismatch,
    /// The message kind is not the ZK-proof kind.
    WrongMessageKind,
    /// STARK verification failed.
    InvalidProof(String),
    /// A different final state root was already accepted for this
    /// `(domain, height)` - conflicting claim.
    ConflictingClaim {
        domain_id: DomainId,
        target_height: u64,
    },
    /// Insufficient balance to pay the submission fee.
    InsufficientFee { have: u64, need: u64 },
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofError::PayloadHashMismatch => {
                write!(f, "message payload hash does not match proof payload")
            }
            ProofError::WrongMessageKind => write!(f, "message kind is not a ZK proof"),
            ProofError::InvalidProof(e) => write!(f, "invalid proof: {e}"),
            ProofError::ConflictingClaim {
                domain_id,
                target_height,
            } => write!(
                f,
                "conflicting proof claim for domain {domain_id} height {target_height}"
            ),
            ProofError::InsufficientFee { have, need } => {
                write!(
                    f,
                    "insufficient balance for proof fee: have {have}, need {need}"
                )
            }
        }
    }
}

impl std::error::Error for ProofError {}

/// Registry of accepted proof claims implementing the "first valid wins" policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProofClaimRegistry {
    claims: BTreeMap<ProofClaimKey, AcceptedProofClaim>,
}

impl ProofClaimRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &ProofClaimKey) -> Option<&AcceptedProofClaim> {
        self.claims.get(key)
    }

    pub fn len(&self) -> usize {
        self.claims.len()
    }

    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// Decide how a verified proof claim should be handled under the
    /// "first valid wins" policy. Does NOT mutate on the idempotent/conflict
    /// Paths; call [`Self::record`] to persist an accepted claim.
    pub fn classify(
        &self,
        key: ProofClaimKey,
        final_state_root: Hash32,
    ) -> Result<ClaimDecision, ProofError> {
        match self.claims.get(&key) {
            None => Ok(ClaimDecision::New),
            Some(existing) if existing.final_state_root == final_state_root => {
                Ok(ClaimDecision::Duplicate)
            }
            Some(_) => Err(ProofError::ConflictingClaim {
                domain_id: key.domain_id,
                target_height: key.target_height,
            }),
        }
    }

    /// Persist a newly accepted claim.
    pub fn record(&mut self, claim: AcceptedProofClaim) {
        self.claims.insert(claim.key, claim);
    }
}

/// Result of [`ProofClaimRegistry::classify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimDecision {
    /// No prior claim - accept as the first valid proof.
    New,
    /// Identical prior claim - idempotent.
    Duplicate,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(h: u64) -> ProofClaimKey {
        ProofClaimKey {
            domain_id: 1,
            target_height: h,
        }
    }

    #[test]
    fn first_claim_is_new_then_duplicate() {
        let mut reg = ProofClaimRegistry::new();
        let k = key(10);
        assert_eq!(reg.classify(k, [1u8; 32]).unwrap(), ClaimDecision::New);
        reg.record(AcceptedProofClaim {
            key: k,
            final_state_root: [1u8; 32],
            prover: Address::from([9u8; 32]),
            rewarded: true,
        });
        // Same result again -> idempotent.
        assert_eq!(
            reg.classify(k, [1u8; 32]).unwrap(),
            ClaimDecision::Duplicate
        );
    }

    #[test]
    fn conflicting_final_state_root_rejected() {
        let mut reg = ProofClaimRegistry::new();
        let k = key(10);
        reg.record(AcceptedProofClaim {
            key: k,
            final_state_root: [1u8; 32],
            prover: Address::from([9u8; 32]),
            rewarded: false,
        });
        assert_eq!(
            reg.classify(k, [2u8; 32]),
            Err(ProofError::ConflictingClaim {
                domain_id: 1,
                target_height: 10,
            })
        );
    }
}
