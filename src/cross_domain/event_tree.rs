use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::message::CrossDomainMessage;
use crate::domain::types::{DomainId, Hash32};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DomainEventKind {
    BridgeLocked,
    BridgeMinted,
    BridgeBurned,
    BridgeUnlocked,
    MessageEmitted,
    Custom(Vec<u8>),
}

impl DomainEventKind {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            DomainEventKind::BridgeLocked => b"bridge-locked".to_vec(),
            DomainEventKind::BridgeMinted => b"bridge-minted".to_vec(),
            DomainEventKind::BridgeBurned => b"bridge-burned".to_vec(),
            DomainEventKind::BridgeUnlocked => b"bridge-unlocked".to_vec(),
            DomainEventKind::MessageEmitted => b"message-emitted".to_vec(),
            DomainEventKind::Custom(bytes) => {
                let mut out = b"custom:".to_vec();
                out.extend_from_slice(bytes);
                out
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainEvent {
    pub domain_id: DomainId,
    pub domain_height: u64,
    pub event_index: u32,
    pub kind: DomainEventKind,
    pub emitter: Address,
    pub message: Option<CrossDomainMessage>,
    pub payload_hash: Hash32,
}

impl DomainEvent {
    pub fn leaf_hash(&self) -> Hash32 {
        let kind = self.kind.as_bytes();
        let message_id = self
            .message
            .as_ref()
            .map(|message| message.message_id)
            .unwrap_or([0u8; 32]);

        hash_fields_bytes(&[
            b"BDLM_DOMAIN_EVENT_V1",
            &self.domain_id.to_le_bytes(),
            &self.domain_height.to_le_bytes(),
            &self.event_index.to_le_bytes(),
            &kind,
            self.emitter.as_bytes(),
            &message_id,
            &self.payload_hash,
        ])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf: Hash32,
    pub index: usize,
    pub siblings: Vec<Hash32>,
}

/// The sibling value that stands for "no sibling: this digest was promoted".
///
/// An unpaired tail digest is hashed under the odd-promotion tag alone, so
/// the verifier has to tell a promoted step from a paired one, and the
/// sibling list (plain digests) needs a marker. This value is the hash of a
/// tag that neither a leaf domain nor a node domain produces, so no honest
/// tree ever yields it as a real sibling; a forged sentinel in a paired
/// position only produces a root that does not match the committed one.
fn odd_promotion_sentinel() -> Hash32 {
    static SENTINEL: std::sync::OnceLock<Hash32> = std::sync::OnceLock::new();
    *SENTINEL.get_or_init(|| hash_fields_bytes(&[b"BDLM_MERKLE_ODD_SENTINEL_V1"]))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainEventTree {
    events: Vec<DomainEvent>,
}

impl DomainEventTree {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn push(&mut self, event: DomainEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[DomainEvent] {
        &self.events
    }

    pub fn root(&self) -> Hash32 {
        let leaves: Vec<Hash32> = self.events.iter().map(DomainEvent::leaf_hash).collect();
        crate::settlement::commitment_tree::merkle_root(&leaves)
    }

    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.events.len() {
            return None;
        }

        let mut idx = index;
        let mut level: Vec<Hash32> = self.events.iter().map(DomainEvent::leaf_hash).collect();
        let leaf = level[index];
        let mut siblings = Vec::new();

        while level.len() > 1 {
            // An unpaired tail is promoted under the odd-promotion tag
            // rather than paired with itself: the self-pairing made the
            // proof for the last leaf of an odd tree identical to the proof
            // the same tree would give with that leaf duplicated, so two
            // different trees shared one verifying proof. The sibling
            // recorded for a promoted digest is the sentinel.
            let promoted_tail = idx.is_multiple_of(2) && idx + 1 >= level.len();
            let sibling = if promoted_tail {
                odd_promotion_sentinel()
            } else if idx.is_multiple_of(2) {
                level[idx + 1]
            } else {
                level[idx - 1]
            };
            siblings.push(sibling);

            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                if pair.len() == 2 {
                    next.push(hash_fields_bytes(&[
                        b"BDLM_MERKLE_NODE_V1",
                        &pair[0],
                        &pair[1],
                    ]));
                } else {
                    next.push(hash_fields_bytes(&[
                        b"BDLM_MERKLE_ODD_PROMOTE_V1",
                        &pair[0],
                    ]));
                }
            }
            idx /= 2;
            level = next;
        }

        Some(MerkleProof {
            leaf,
            index,
            siblings,
        })
    }
}

impl MerkleProof {
    pub fn verify(&self, expected_root: Hash32) -> bool {
        let mut hash = self.leaf;
        let mut index = self.index;

        for sibling in &self.siblings {
            hash = if sibling == &odd_promotion_sentinel() {
                // The prover recorded a promotion: this digest had no
                // sibling at this level and was hashed under the promotion
                // tag alone.
                hash_fields_bytes(&[b"BDLM_MERKLE_ODD_PROMOTE_V1", &hash])
            } else if index.is_multiple_of(2) {
                hash_fields_bytes(&[b"BDLM_MERKLE_NODE_V1", &hash, sibling])
            } else {
                hash_fields_bytes(&[b"BDLM_MERKLE_NODE_V1", sibling, &hash])
            };
            index /= 2;
        }

        hash == expected_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams, MessageKind};

    fn hash(label: &[u8]) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[label])
    }

    fn event(index: u32) -> DomainEvent {
        let payload_hash = hash(&[index as u8]);
        let message = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 9,
            event_index: index,
            nonce: index as u64,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash,
            kind: MessageKind::BridgeLock,
            expiry_height: 50,
        });

        DomainEvent {
            domain_id: 1,
            domain_height: 9,
            event_index: index,
            kind: DomainEventKind::BridgeLocked,
            emitter: Address::from([1u8; 32]),
            message: Some(message),
            payload_hash,
        }
    }

    #[test]
    fn event_merkle_proof_verifies_and_rejects_tampering() {
        let mut tree = DomainEventTree::new();
        for index in 0..5 {
            tree.push(event(index));
        }

        let root = tree.root();
        let proof = tree.proof(3).expect("proof should exist");
        assert!(proof.verify(root));

        let mut tampered = proof.clone();
        tampered.siblings[0] = hash(b"bad sibling");
        assert!(!tampered.verify(root));

        assert!(!proof.verify(hash(b"bad root")));
    }

    /// The promoted tail leaf proves inclusion through the sentinel: five
    /// events make the leaf layer odd, so the fifth leaf's first step is a
    /// promotion, not a pair, and its proof must verify against the same
    /// root the even-indexed leaves verify against.
    #[test]
    fn the_promoted_tail_leaf_proves_inclusion_through_the_sentinel() {
        let mut tree = DomainEventTree::new();
        for index in 0..5 {
            tree.push(event(index));
        }
        let root = tree.root();
        let proof = tree.proof(4).expect("proof should exist");
        assert_eq!(
            proof.siblings.first(),
            Some(&odd_promotion_sentinel()),
            "the first step of the promoted leaf is the sentinel, not a sibling"
        );
        assert!(proof.verify(root));
    }

    /// A proof whose sentinel sits in a paired position must not verify
    /// against the honest root: the marker is not a digest any honest tree
    /// hands out as a sibling.
    #[test]
    fn a_sentinel_forged_into_a_paired_position_does_not_verify() {
        let mut tree = DomainEventTree::new();
        for index in 0..4 {
            tree.push(event(index));
        }
        let root = tree.root();
        let mut proof = tree.proof(0).expect("proof should exist");
        assert!(proof.verify(root));
        proof.siblings[0] = odd_promotion_sentinel();
        assert!(
            !proof.verify(root),
            "a promotion marker where the tree paired must break the root"
        );
    }

    /// One event: the tree is a single leaf, the root is the leaf, and the
    /// proof carries no steps.
    #[test]
    fn a_single_event_tree_root_is_the_leaf() {
        let mut tree = DomainEventTree::new();
        tree.push(event(0));
        let root = tree.root();
        let proof = tree.proof(0).expect("proof should exist");
        assert!(proof.siblings.is_empty());
        assert!(proof.verify(root));
    }
}
