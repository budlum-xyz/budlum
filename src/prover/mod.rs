//! Permissionless ZK proof submission and the L1 ↔ BudZKVM bridge.
//!
//! ## Model (decided this turn: "Option B" — fully open submission)
//! Anyone may submit a proof; registration is NOT required to have a valid proof
//! accepted, because a STARK proof is self-verifying — the chain verifies the
//! math and never needs to trust the submitter. Registration (the `PROVER` role)
//! is *optional* and only affects **reward eligibility**.
//!
//! ## Verification location (decided this turn: core-native)
//! The STARK proof is verified inside `budlum-core` itself via the `bud_proof`
//! adapter (the crate is already a core dependency and `execution::zkvm` already
//! calls `Prover::verify`). Verification of untrusted input happens on-chain.
//!
//! ## Transport
//! The proof reaches core through the shared [`CrossDomainMessage`] primitive
//! (not a bespoke bridge protocol). This is a *distinct* path from the Task 0.04
//! relayer gate: a relayer *carries* messages, a prover *produces* proofs. The
//! submission wraps the message together with the actual proof payload; the
//! message's `payload_hash` binds to that payload.
//!
//! ## Conflict policy (decided this turn: "first valid wins")
//! For a given `(domain, height)` the first verifying proof is accepted and (if
//! the submitter is a registered prover) rewarded. A later proof asserting the
//! *same* `final_state_root` is an idempotent no-op (accepted, no double
//! reward). A later proof asserting a *different* `final_state_root` for the
//! same `(domain, height)` is rejected as a conflicting claim.

pub mod market;

pub use market::{
    ProofMarketRegistry, ProofReceipt, ProofTask, ProofTaskId, ProofTaskKind, ProofTaskStatus,
    ReceiptAcceptance,
};

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::message::CrossDomainMessage;
use crate::domain::types::{DomainId, Hash32};
use bud_proof::{ExecutionPublicInputs, ProofEnvelope};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A prover's submission: the transport message plus the proof payload it
/// commits to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofSubmission {
    /// Transport envelope over the shared CrossDomainMessage primitive.
    /// `message.target_domain` is the domain being advanced, `message.source_height`
    /// is the proven target height, and `message.sender` is the submitter (the
    /// account charged the fee and, if registered, rewarded).
    pub message: CrossDomainMessage,
    /// The STARK proof.
    pub proof: ProofEnvelope,
    /// Public inputs the proof is checked against.
    pub public_inputs: ExecutionPublicInputs,
    /// The program (bytecode words) the proof is over.
    pub program: Vec<u64>,
}

impl ZkProofSubmission {
    /// Canonical hash binding the transport message to the proof payload. The
    /// `message.payload_hash` MUST equal this, so a message cannot be replayed
    /// with a different proof (or vice-versa).
    pub fn payload_binding_hash(
        proof: &ProofEnvelope,
        public_inputs: &ExecutionPublicInputs,
        program: &[u64],
    ) -> Hash32 {
        // SECURITY (Task 0.32): serialize into a hash MUST NOT silently fall back
        // to empty bytes — two different proofs whose serialization failed would
        // collide to the same hash, breaking the replay-protection guarantee this
        // function documents. bincode serialization of this plain data type is
        // infeasible to fail from untrusted input (no fallible custom Serialize,
        // writing to a Vec), so a failure is a deterministic programming error we
        // fail-fast on rather than hide.
        let proof_bytes = bincode::serialize(proof)
            .expect("BUG: ProofEnvelope must serialize for payload binding hash");
        let pi_bytes = public_inputs.to_canonical_bytes();
        let mut program_bytes = Vec::with_capacity(program.len() * 8);
        for word in program {
            program_bytes.extend_from_slice(&word.to_le_bytes());
        }
        hash_fields_bytes(&[
            b"BDLM_ZK_PROOF_PAYLOAD_V1",
            &proof_bytes,
            &pi_bytes,
            &program_bytes,
        ])
    }

    /// Recompute and return the expected payload binding hash for this
    /// submission.
    pub fn expected_payload_hash(&self) -> Hash32 {
        Self::payload_binding_hash(&self.proof, &self.public_inputs, &self.program)
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
    /// `(domain, height)` — conflicting claim.
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
    /// paths; call [`Self::record`] to persist an accepted claim.
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
    /// No prior claim — accept as the first valid proof.
    New,
    /// Identical prior claim — idempotent.
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
