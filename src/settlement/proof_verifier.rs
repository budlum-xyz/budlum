use crate::cross_domain::{DomainEvent, MerkleProof};
use crate::domain::{DomainCommitment, DomainCommitmentRegistry, DomainId, Hash32};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedDomainEvent {
    pub commitment: DomainCommitment,
    pub event: DomainEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofVerificationError {
    MissingCommitment {
        domain_id: DomainId,
        domain_height: u64,
        sequence: u64,
    },
    EventDomainMismatch,
    EventHeightMismatch,
    EventIndexMismatch,
    EventLeafMismatch,
    /// The message body does not hash to its claimed id.
    EventMessageIdMismatch,
    InvalidMerkleProof,
    CommitmentBlockHashMismatch,
    /// The commitment's finality proof does not bind its event root (a PoS or
    /// BFT certificate signs the checkpoint hash alone), so the root is the
    /// submitter's claim and no event may be proven against it.
    UnattestedEventRoot,
}

impl std::fmt::Display for ProofVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofVerificationError::MissingCommitment {
                domain_id,
                domain_height,
                sequence,
            } => write!(
                f,
                "Missing commitment for domain={domain_id}, height={domain_height}, sequence={sequence}"
            ),
            ProofVerificationError::EventDomainMismatch => {
                write!(f, "Event domain does not match commitment domain")
            }
            ProofVerificationError::EventHeightMismatch => {
                write!(f, "Event height does not match commitment height")
            }
            ProofVerificationError::EventIndexMismatch => {
                write!(f, "Event index does not match Merkle proof index")
            }
            ProofVerificationError::EventMessageIdMismatch => {
                write!(f, "cross-domain message body does not match its id")
            }
            ProofVerificationError::EventLeafMismatch => {
                write!(f, "Event leaf hash does not match Merkle proof leaf")
            }
            ProofVerificationError::InvalidMerkleProof => {
                write!(f, "Invalid event Merkle proof")
            }
            ProofVerificationError::CommitmentBlockHashMismatch => {
                write!(
                    f,
                    "Commitment block hash does not match expected block hash"
                )
            }
            ProofVerificationError::UnattestedEventRoot => write!(
                f,
                "Commitment event root is not bound by its finality proof"
            ),
        }
    }
}

impl std::error::Error for ProofVerificationError {}

pub struct SettlementProofVerifier;

impl SettlementProofVerifier {
    pub fn verify_event_against_commitment(
        commitment: &DomainCommitment,
        event: DomainEvent,
        proof: &MerkleProof,
    ) -> Result<VerifiedDomainEvent, ProofVerificationError> {
        // The event root is only as good as the proof that binds it. A PoS or
        // BFT certificate signs `(chain_id, epoch, height, hash)` and nothing
        // else, so an event root in such a commitment belongs to whoever
        // submitted it: a relayer could carry a genuine certificate and a
        // fabricated event tree and have a message the domain never emitted
        // delivered into the registry its target domain reads.
        if !crate::settlement::domains::CommitmentAttestation::for_kind(&commitment.consensus_kind)
            .event_root
        {
            return Err(ProofVerificationError::UnattestedEventRoot);
        }
        if event.domain_id != commitment.domain_id {
            return Err(ProofVerificationError::EventDomainMismatch);
        }
        if event.domain_height != commitment.domain_height {
            return Err(ProofVerificationError::EventHeightMismatch);
        }
        if event.event_index as usize != proof.index {
            return Err(ProofVerificationError::EventIndexMismatch);
        }
        if event.leaf_hash() != proof.leaf {
            return Err(ProofVerificationError::EventLeafMismatch);
        }
        // A carried cross-domain message must be
        // self-consistent - its id has to match its body. The bridge checks
        // this on mint (bridge.rs); the verifier accepted any body under any
        // id, and only the id is bound into the leaf.
        if let Some(message) = &event.message {
            if !message.verify_id() {
                return Err(ProofVerificationError::EventMessageIdMismatch);
            }
        }
        if !proof.verify(commitment.event_root) {
            return Err(ProofVerificationError::InvalidMerkleProof);
        }

        Ok(VerifiedDomainEvent {
            commitment: commitment.clone(),
            event,
        })
    }

    pub fn verify_event_from_registry(
        registry: &DomainCommitmentRegistry,
        domain_id: DomainId,
        domain_height: u64,
        sequence: u64,
        expected_block_hash: Hash32,
        event: DomainEvent,
        proof: &MerkleProof,
    ) -> Result<VerifiedDomainEvent, ProofVerificationError> {
        let commitment = registry.get(domain_id, domain_height, sequence).ok_or(
            ProofVerificationError::MissingCommitment {
                domain_id,
                domain_height,
                sequence,
            },
        )?;

        // The block hash check is not optional. It used to be a
        // `None`-skippable Option; every caller knew the hash, and the skip
        // path was pure bypass surface.
        if commitment.domain_block_hash != expected_block_hash {
            return Err(ProofVerificationError::CommitmentBlockHashMismatch);
        }

        Self::verify_event_against_commitment(commitment, event, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::core::hash::hash_fields_bytes;
    use crate::cross_domain::message::CrossDomainMessageParams;
    use crate::cross_domain::{CrossDomainMessage, DomainEventKind, DomainEventTree, MessageKind};
    use crate::domain::ConsensusKind;

    fn message(index: u32, payload_hash: Hash32) -> CrossDomainMessage {
        CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 10,
            event_index: index,
            nonce: u64::from(index),
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash,
            kind: MessageKind::BridgeLock,
            expiry_height: 100,
        })
    }

    fn event(index: u32) -> DomainEvent {
        let payload_hash = hash_fields_bytes(&[b"payload", &index.to_le_bytes()]);
        DomainEvent {
            domain_id: 1,
            domain_height: 10,
            event_index: index,
            kind: DomainEventKind::BridgeLocked,
            emitter: Address::from([1u8; 32]),
            message: Some(message(index, payload_hash)),
            payload_hash,
        }
    }

    fn make_commitment(event_root: Hash32) -> DomainCommitment {
        DomainCommitment {
            domain_id: 1,
            domain_height: 10,
            domain_block_hash: [9u8; 32],
            parent_domain_block_hash: [8u8; 32],
            state_root: [7u8; 32],
            tx_root: [6u8; 32],
            event_root,
            finality_proof_hash: [5u8; 32],
            consensus_kind: ConsensusKind::PoW,
            validator_set_hash: [4u8; 32],
            timestamp_ms: 123,
            sequence: 0,
            producer: None,
            state_updates: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn verifies_event_merkle_proof_against_commitment_root() {
        let mut tree = DomainEventTree::new();
        for index in 0..4 {
            tree.push(event(index));
        }
        let commitment = make_commitment(tree.root());
        let event = tree.events()[2].clone();
        let proof = tree.proof(2).unwrap();

        let verified =
            SettlementProofVerifier::verify_event_against_commitment(&commitment, event, &proof)
                .unwrap();
        assert_eq!(verified.commitment.domain_id, 1);
    }

    #[test]
    fn rejects_event_proof_with_wrong_leaf_index_or_root() {
        let mut tree = DomainEventTree::new();
        for index in 0..4 {
            tree.push(event(index));
        }
        let commitment = make_commitment(tree.root());
        let event = tree.events()[2].clone();
        let mut wrong_index = tree.proof(2).unwrap();
        wrong_index.index = 3;
        assert_eq!(
            SettlementProofVerifier::verify_event_against_commitment(
                &commitment,
                event.clone(),
                &wrong_index,
            )
            .unwrap_err(),
            ProofVerificationError::EventIndexMismatch
        );

        let bad_commitment = make_commitment(hash_fields_bytes(&[b"bad root"]));
        let proof = tree.proof(2).unwrap();
        assert_eq!(
            SettlementProofVerifier::verify_event_against_commitment(
                &bad_commitment,
                event,
                &proof,
            )
            .unwrap_err(),
            ProofVerificationError::InvalidMerkleProof
        );
    }

    /// A PoS or BFT certificate signs the checkpoint hash and nothing else, so
    /// the event root in such a commitment is whatever its submitter chose. A
    /// relayer that carries a genuine certificate can build a tree of its own
    /// and deliver a message the domain never emitted; the verifier refuses the
    /// root before it looks at the proof.
    #[test]
    fn a_pos_commitment_cannot_authorise_an_event_proof() {
        let mut tree = DomainEventTree::new();
        for index in 0..4 {
            tree.push(event(index));
        }
        let mut commitment = make_commitment(tree.root());
        commitment.consensus_kind = ConsensusKind::PoS;
        let event = tree.events()[2].clone();
        let proof = tree.proof(2).unwrap();
        assert_eq!(
            SettlementProofVerifier::verify_event_against_commitment(&commitment, event, &proof)
                .unwrap_err(),
            ProofVerificationError::UnattestedEventRoot
        );

        // The same commitment under a proof that binds the roots still verifies.
        commitment.consensus_kind = ConsensusKind::PoA;
        assert!(SettlementProofVerifier::verify_event_against_commitment(
            &commitment,
            tree.events()[2].clone(),
            &proof
        )
        .is_ok());
    }
}
