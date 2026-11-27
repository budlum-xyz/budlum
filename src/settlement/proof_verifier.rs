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
    /// The carried cross-domain message's origin metadata disagrees with the
    /// committed domain event (forged `source_domain`, wrong `source_height`
    /// or `event_index`, or `source == target`).
    EventMessageMetadataMismatch,
    InvalidMerkleProof,
    CommitmentBlockHashMismatch,
    /// The commitment's finality proof does not bind its event root (a `PoS` or
    /// BFT certificate signs the checkpoint hash alone), so the root is the
    /// submitter's claim and no event may be proven against it.
    UnattestedEventRoot,
}

impl std::fmt::Display for ProofVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCommitment {
                domain_id,
                domain_height,
                sequence,
            } => write!(
                f,
                "Missing commitment for domain={domain_id}, height={domain_height}, sequence={sequence}"
            ),
            Self::EventDomainMismatch => {
                write!(f, "Event domain does not match commitment domain")
            }
            Self::EventHeightMismatch => {
                write!(f, "Event height does not match commitment height")
            }
            Self::EventIndexMismatch => {
                write!(f, "Event index does not match Merkle proof index")
            }
            Self::EventMessageIdMismatch => {
                write!(f, "cross-domain message body does not match its id")
            }
            Self::EventMessageMetadataMismatch => {
                write!(
                    f,
                    "cross-domain message metadata does not match the committed domain event"
                )
            }
            Self::EventLeafMismatch => {
                write!(f, "Event leaf hash does not match Merkle proof leaf")
            }
            Self::InvalidMerkleProof => {
                write!(f, "Invalid event Merkle proof")
            }
            Self::CommitmentBlockHashMismatch => {
                write!(
                    f,
                    "Commitment block hash does not match expected block hash"
                )
            }
            Self::UnattestedEventRoot => write!(
                f,
                "Commitment event root is not bound by its finality proof"
            ),
        }
    }
}

impl std::error::Error for ProofVerificationError {}

pub struct SettlementProofVerifier;

impl SettlementProofVerifier {
    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
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
            || commitment.event_root == [0u8; 32]
        {
            return Err(ProofVerificationError::UnattestedEventRoot);
        }
        if event.domain_id != commitment.domain_id {
            return Err(ProofVerificationError::EventDomainMismatch);
        }
        if event.domain_height != commitment.domain_height {
            return Err(ProofVerificationError::EventHeightMismatch);
        }
        if usize::try_from(event.event_index).ok() != Some(proof.index) {
            return Err(ProofVerificationError::EventIndexMismatch);
        }
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            event.leaf_hash().as_slice(),
            proof.leaf.as_slice(),
        )) {
            return Err(ProofVerificationError::EventLeafMismatch);
        }
        // A carried cross-domain message must be self-consistent (its id has to
        // match its body) AND bound to the exact committed domain event origin:
        // a malicious source domain must never emit an event under its own valid
        // Merkle root whose embedded message claims a different `source_domain`,
        // `source_height`, `event_index`, or self-targets its own domain.
        // (`event.payload_hash` is checked by bridge/domain consumers because
        // custom dispatch events may leave `event.payload_hash` zeroed while
        // `message.payload_hash` carries the message digest.)
        if let Some(message) = &event.message {
            if !message.verify_id() {
                return Err(ProofVerificationError::EventMessageIdMismatch);
            }
            if message.source_domain != event.domain_id
                || message.source_domain == message.target_domain
                || message.source_height != event.domain_height
                || message.event_index != event.event_index
            {
                return Err(ProofVerificationError::EventMessageMetadataMismatch);
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

    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
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

        // The block hash check is not optional and must never pass on an
        // unpopulated all-zero block hash.
        if expected_block_hash == [0u8; 32]
            || commitment.domain_block_hash == [0u8; 32]
            || !bool::from(subtle::ConstantTimeEq::ct_eq(
                commitment.domain_block_hash.as_slice(),
                expected_block_hash.as_slice(),
            ))
        {
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

    /// A `PoS` or BFT certificate signs the checkpoint hash and nothing else, so
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

    #[test]
    fn rejects_cross_domain_message_source_impersonation_and_metadata_mismatch() {
        let payload_hash = hash_fields_bytes(&[b"forged-mint"]);
        // Malicious domain 99 emits an event whose embedded CrossDomainMessage claims
        // source_domain = 1 (impersonating a high-value domain) with a valid message_id.
        let spoofed_source_msg = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 10,
            event_index: 0,
            nonce: 1,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash,
            kind: MessageKind::BridgeLock,
            expiry_height: 100,
        });
        let spoofed_event = DomainEvent {
            domain_id: 99,
            domain_height: 10,
            event_index: 0,
            kind: DomainEventKind::BridgeLocked,
            emitter: Address::from([9u8; 32]),
            message: Some(spoofed_source_msg),
            payload_hash,
        };
        let mut tree = DomainEventTree::new();
        tree.push(spoofed_event.clone());
        let mut commitment = make_commitment(tree.root());
        commitment.domain_id = 99;
        let proof = tree.proof(0).unwrap();
        assert_eq!(
            SettlementProofVerifier::verify_event_against_commitment(
                &commitment,
                spoofed_event,
                &proof,
            )
            .unwrap_err(),
            ProofVerificationError::EventMessageMetadataMismatch,
            "domain 99 commitment MUST NOT certify a CrossDomainMessage claiming source_domain=1"
        );

        // Self-targeted message (source_domain == target_domain) must also be refused.
        let self_targeted_msg = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 1,
            source_height: 10,
            event_index: 0,
            nonce: 2,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash,
            kind: MessageKind::BridgeLock,
            expiry_height: 100,
        });
        let self_event = DomainEvent {
            domain_id: 1,
            domain_height: 10,
            event_index: 0,
            kind: DomainEventKind::BridgeLocked,
            emitter: Address::from([1u8; 32]),
            message: Some(self_targeted_msg),
            payload_hash,
        };
        let mut self_tree = DomainEventTree::new();
        self_tree.push(self_event.clone());
        let self_commitment = make_commitment(self_tree.root());
        let self_proof = self_tree.proof(0).unwrap();
        assert!(
            SettlementProofVerifier::verify_event_against_commitment(
                &self_commitment,
                self_event,
                &self_proof,
            )
            .is_err(),
            "self-targeted cross-domain message (source == target) must be refused"
        );

        // Mismatched source_height and event_index must each be refused.
        let cases = [(11u64, 0u32), (10u64, 1u32)];
        for (msg_height, msg_idx) in cases {
            let bad_msg = CrossDomainMessage::new(CrossDomainMessageParams {
                source_domain: 1,
                target_domain: 2,
                source_height: msg_height,
                event_index: msg_idx,
                nonce: 3,
                sender: Address::from([1u8; 32]),
                recipient: Address::from([2u8; 32]),
                payload_hash,
                kind: MessageKind::BridgeLock,
                expiry_height: 100,
            });
            let bad_event = DomainEvent {
                domain_id: 1,
                domain_height: 10,
                event_index: 0,
                kind: DomainEventKind::BridgeLocked,
                emitter: Address::from([1u8; 32]),
                message: Some(bad_msg),
                payload_hash,
            };
            let mut bad_tree = DomainEventTree::new();
            bad_tree.push(bad_event.clone());
            let bad_commitment = make_commitment(bad_tree.root());
            let bad_proof = bad_tree.proof(0).unwrap();
            assert_eq!(
                SettlementProofVerifier::verify_event_against_commitment(
                    &bad_commitment,
                    bad_event,
                    &bad_proof,
                )
                .unwrap_err(),
                ProofVerificationError::EventMessageMetadataMismatch,
                "message metadata mismatch (height={msg_height}, idx={msg_idx}) must be refused"
            );
        }
    }

    #[test]
    fn rejects_zero_block_hash_in_registry_verification() {
        let mut tree = DomainEventTree::new();
        tree.push(event(0));
        let mut commitment = make_commitment(tree.root());
        commitment.domain_block_hash = [0u8; 32];
        let mut registry = DomainCommitmentRegistry::new();
        registry.insert(commitment).unwrap();
        let proof = tree.proof(0).unwrap();
        assert_eq!(
            SettlementProofVerifier::verify_event_from_registry(
                &registry,
                1,
                10,
                0,
                [0u8; 32],
                tree.events()[0].clone(),
                &proof,
            )
            .unwrap_err(),
            ProofVerificationError::CommitmentBlockHashMismatch,
            "zero domain_block_hash must never satisfy verify_event_from_registry"
        );
    }
}
