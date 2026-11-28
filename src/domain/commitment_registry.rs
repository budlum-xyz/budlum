use crate::domain::types::{DomainCommitment, DomainId, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainCommitmentRegistry {
    #[serde(with = "crate::core::map_keys")]
    commitments: BTreeMap<(DomainId, u64, u64), DomainCommitment>,
    seen_blocks: BTreeSet<(DomainId, u64, Hash32)>,
    #[serde(default, with = "crate::core::map_keys")]
    accepted_at_height: BTreeMap<(DomainId, u64, u64), u64>,
}

impl DomainCommitmentRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            commitments: BTreeMap::new(),
            seen_blocks: BTreeSet::new(),
            accepted_at_height: BTreeMap::new(),
        }
    }

    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn insert(&mut self, commitment: DomainCommitment) -> Result<(), String> {
        self.insert_at_height(commitment, 0)
    }

    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn insert_at_height(
        &mut self,
        commitment: DomainCommitment,
        budlum_height: u64,
    ) -> Result<(), String> {
        let key = (
            commitment.domain_id,
            commitment.domain_height,
            commitment.sequence,
        );
        let block_key = (
            commitment.domain_id,
            commitment.domain_height,
            commitment.domain_block_hash,
        );

        if self.commitments.contains_key(&key) {
            return Err(format!(
                "Duplicate commitment for domain={}, height={}, sequence={}",
                commitment.domain_id, commitment.domain_height, commitment.sequence
            ));
        }

        if self.seen_blocks.contains(&block_key) {
            return Err(format!(
                "Domain block already committed: domain={}, height={}",
                commitment.domain_id, commitment.domain_height
            ));
        }

        self.seen_blocks.insert(block_key);
        self.commitments.insert(key, commitment);
        self.accepted_at_height.insert(key, budlum_height);
        Ok(())
    }

    #[must_use]
    pub fn accepted_height(
        &self,
        domain_id: DomainId,
        domain_height: u64,
        sequence: u64,
    ) -> Option<u64> {
        self.accepted_at_height
            .get(&(domain_id, domain_height, sequence))
            .copied()
    }

    #[must_use]
    pub fn earliest_accepted_height(&self, domain_id: DomainId, domain_height: u64) -> Option<u64> {
        self.accepted_at_height
            .range((domain_id, domain_height, 0)..=(domain_id, domain_height, u64::MAX))
            .map(|(_, &h)| h)
            .min()
    }

    #[must_use]
    pub fn commitments_for_global_block(&self) -> Vec<DomainCommitment> {
        self.commitments.values().cloned().collect()
    }

    #[must_use]
    pub fn get(
        &self,
        domain_id: DomainId,
        domain_height: u64,
        sequence: u64,
    ) -> Option<&DomainCommitment> {
        self.commitments.get(&(domain_id, domain_height, sequence))
    }

    #[must_use]
    pub fn find_by_height(&self, domain_id: DomainId, height: u64) -> Option<DomainCommitment> {
        self.at_height(domain_id, height).next().cloned()
    }

    #[must_use]
    pub fn get_by_block_hash(
        &self,
        domain_id: DomainId,
        domain_height: u64,
        block_hash: Hash32,
    ) -> Option<&DomainCommitment> {
        self.at_height(domain_id, domain_height)
            .find(|commitment| commitment.domain_block_hash == block_hash)
    }

    /// The commitments of one domain at one height, in sequence order. The key order of the
    /// map makes this a range read, not a scan of every commitment.
    fn at_height(
        &self,
        domain_id: DomainId,
        height: u64,
    ) -> impl Iterator<Item = &DomainCommitment> {
        self.commitments
            .range((domain_id, height, 0)..=(domain_id, height, u64::MAX))
            .map(|(_, commitment)| commitment)
    }

    /// Drop one stored commitment, with its block marker, so a height can be
    /// committed again. Used for a commitment whose linkage the finality proof
    /// never bound: it is not evidence of anything the domain did, so it must
    /// not be able to block the honest commitment at the same height. Returns
    /// the row that was removed, or `None` when the key was not stored.
    pub fn remove(
        &mut self,
        domain_id: DomainId,
        domain_height: u64,
        sequence: u64,
    ) -> Option<DomainCommitment> {
        let commitment = self
            .commitments
            .remove(&(domain_id, domain_height, sequence))?;
        self.accepted_at_height
            .remove(&(domain_id, domain_height, sequence));
        self.seen_blocks
            .remove(&(domain_id, domain_height, commitment.domain_block_hash));
        Some(commitment)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.commitments.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commitments.is_empty()
    }

    pub fn root(&self) -> Hash32 {
        let leaves: Vec<Hash32> = self
            .commitments
            .values()
            .map(DomainCommitment::leaf_hash)
            .collect();
        crate::settlement::commitment_tree::merkle_root(&leaves)
    }
}

/// A Merkle sibling path from one domain commitment leaf to the root of the
/// commitment tree a checkpoint header commits (`domain_commitment_root`).
///
/// The tree is the shared shape of `consensus::merkle_tree` under the
/// settlement binding, so a promoted odd tail appears as the sibling
/// `consensus::merkle_tree::odd_promotion_sentinel()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainCommitmentInclusionProof {
    /// The leaf's position among the tree's leaves: the registry's
    /// `(domain_id, domain_height, sequence)` key order.
    pub leaf_index: usize,
    /// The number of leaves the root was computed over.
    pub leaf_count: usize,
    /// The sibling digests, leaf layer first.
    pub siblings: Vec<Hash32>,
}

impl DomainCommitmentInclusionProof {
    /// Whether `leaf` at `leaf_index` is a member of the tree whose root is
    /// `root`: the path is walked with the settlement combine functions and
    /// the rebuilt digest is compared with `root`. A sentinel in a paired
    /// position, a leftover index, or any altered sibling rebuilds a different
    /// digest and is refused.
    #[must_use]
    pub fn verify(&self, leaf: &Hash32, root: &Hash32) -> bool {
        self.leaf_index < self.leaf_count
            && crate::consensus::merkle_tree::merkle_root_from_proof(
                leaf,
                self.leaf_index,
                &self.siblings,
                crate::settlement::commitment_tree::merkle_node_hash,
                crate::settlement::commitment_tree::merkle_odd_promote_hash,
            )
            .is_some_and(|rebuilt| rebuilt == *root)
    }
}

impl DomainCommitmentRegistry {
    /// The path from the commitment `(domain_id, domain_height, sequence)` to
    /// the root [`Self::root`] computes over this registry's leaves, in key
    /// order; `None` when the registry does not hold that commitment.
    ///
    /// A verifier needs only the leaf, the path and a root it trusts (a
    /// checkpoint header's `domain_commitment_root`); see
    /// [`DomainCommitmentInclusionProof::verify`].
    #[must_use]
    pub fn prove(
        &self,
        domain_id: DomainId,
        domain_height: u64,
        sequence: u64,
    ) -> Option<DomainCommitmentInclusionProof> {
        let key = (domain_id, domain_height, sequence);
        let mut leaves = Vec::with_capacity(self.commitments.len());
        let mut leaf_index = None;
        for (at, (held, commitment)) in self.commitments.iter().enumerate() {
            if *held == key {
                leaf_index = Some(at);
            }
            leaves.push(commitment.leaf_hash());
        }
        let leaf_index = leaf_index?;
        let siblings = crate::consensus::merkle_tree::merkle_proof(
            &leaves,
            leaf_index,
            crate::settlement::commitment_tree::merkle_node_hash,
            crate::settlement::commitment_tree::merkle_odd_promote_hash,
        )?;
        Some(DomainCommitmentInclusionProof {
            leaf_index,
            leaf_count: leaves.len(),
            siblings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::ConsensusKind;

    fn commitment(sequence: u64, block_hash: Hash32) -> DomainCommitment {
        DomainCommitment {
            domain_id: 1,
            domain_height: 10,
            domain_block_hash: block_hash,
            parent_domain_block_hash: [9u8; 32],
            state_root: [3u8; 32],
            tx_root: [4u8; 32],
            event_root: [5u8; 32],
            finality_proof_hash: [6u8; 32],
            consensus_kind: ConsensusKind::PoW,
            validator_set_hash: [7u8; 32],
            timestamp_ms: 123,
            sequence,
            producer: None,
            state_updates: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn duplicate_commitment_key_is_rejected() {
        let mut registry = DomainCommitmentRegistry::new();
        registry.insert(commitment(0, [1u8; 32])).unwrap();
        assert!(registry.insert(commitment(0, [2u8; 32])).is_err());
    }

    #[test]
    fn same_domain_block_cannot_be_committed_twice() {
        let mut registry = DomainCommitmentRegistry::new();
        registry.insert(commitment(0, [1u8; 32])).unwrap();
        assert!(registry.insert(commitment(1, [1u8; 32])).is_err());
    }

    #[test]
    fn serialized_bytes_do_not_depend_on_insert_order() {
        let mut first = DomainCommitmentRegistry::new();
        let mut second = DomainCommitmentRegistry::new();
        for seq in 0..16u64 {
            let hash = [u8::try_from(seq).unwrap_or(0) + 1; 32];
            first.insert(commitment(seq, hash)).unwrap();
        }
        for seq in (0..16u64).rev() {
            let hash = [u8::try_from(seq).unwrap_or(0) + 1; 32];
            second.insert(commitment(seq, hash)).unwrap();
        }
        assert_eq!(
            bincode::serialize(&first).unwrap(),
            bincode::serialize(&second).unwrap()
        );
    }

    #[test]
    fn height_lookups_stay_inside_their_domain_and_height() {
        let mut registry = DomainCommitmentRegistry::new();
        let mut other_domain = commitment(0, [1u8; 32]);
        other_domain.domain_id = 2;
        registry.insert(other_domain).unwrap();
        let mut other_height = commitment(1, [2u8; 32]);
        other_height.domain_height = 11;
        registry.insert(other_height).unwrap();
        registry.insert(commitment(2, [3u8; 32])).unwrap();
        registry.insert(commitment(3, [4u8; 32])).unwrap();

        let found = registry.find_by_height(1, 10).unwrap();
        assert_eq!(found.sequence, 2);
        assert!(registry.find_by_height(3, 10).is_none());
        let by_hash = registry.get_by_block_hash(1, 10, [4u8; 32]).unwrap();
        assert_eq!(by_hash.sequence, 3);
        assert!(registry.get_by_block_hash(1, 10, [1u8; 32]).is_none());
        assert!(registry.get_by_block_hash(1, 10, [2u8; 32]).is_none());
    }

    fn numbered(number: u64) -> DomainCommitment {
        commitment(number, [u8::try_from(number + 1).unwrap_or(1); 32])
    }

    /// Every leaf's path rebuilds the registry root for odd and even tree
    /// sizes, the promoted odd tail carries the sentinel, one altered sibling
    /// is refused, and a key the registry does not hold has no path.
    #[test]
    fn every_commitment_proves_into_the_registry_root() {
        for count in 1..=6u64 {
            let mut registry = DomainCommitmentRegistry::new();
            for number in 0..count {
                registry.insert(numbered(number)).unwrap();
            }
            let root = registry.root();
            for number in 0..count {
                let leaf = registry.get(1, 10, number).unwrap().leaf_hash();
                let proof = registry
                    .prove(1, 10, number)
                    .unwrap_or_else(|| panic!("sequence {number} of {count} has a path"));
                assert_eq!(proof.leaf_index, usize::try_from(number).unwrap());
                assert_eq!(proof.leaf_count, usize::try_from(count).unwrap());
                assert!(
                    proof.verify(&leaf, &root),
                    "sequence {number} of {count} must rebuild the root"
                );
                let odd_tail = number + 1 == count && count > 1 && count % 2 == 1;
                assert_eq!(
                    proof.siblings.first()
                        == Some(&crate::consensus::merkle_tree::odd_promotion_sentinel()),
                    odd_tail,
                    "sequence {number} of {count}: the sentinel marks the promoted tail and nothing else"
                );
                let mut forged = proof.clone();
                if forged.siblings.is_empty() {
                    forged.leaf_count = 0;
                } else {
                    forged.siblings[0][0] ^= 0x01;
                }
                assert!(
                    !forged.verify(&leaf, &root),
                    "an altered path for sequence {number} of {count} must be refused"
                );
            }
            assert!(
                registry.prove(1, 10, count).is_none(),
                "an absent key has no path"
            );
            assert!(
                registry.prove(2, 10, 0).is_none(),
                "another domain has no path"
            );
        }
        assert!(
            DomainCommitmentRegistry::new().prove(1, 0, 0).is_none(),
            "an empty registry proves nothing"
        );
    }
}
