use crate::domain::types::{DomainCommitment, DomainId, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainCommitmentRegistry {
    #[serde(with = "crate::core::map_keys")]
    commitments: BTreeMap<(DomainId, u64, u64), DomainCommitment>,
    seen_blocks: BTreeSet<(DomainId, u64, Hash32)>,
}

impl DomainCommitmentRegistry {
    pub fn new() -> Self {
        Self {
            commitments: BTreeMap::new(),
            seen_blocks: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, commitment: DomainCommitment) -> Result<(), String> {
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
        Ok(())
    }

    pub fn commitments_for_global_block(&self) -> Vec<DomainCommitment> {
        self.commitments.values().cloned().collect()
    }

    pub fn get(
        &self,
        domain_id: DomainId,
        domain_height: u64,
        sequence: u64,
    ) -> Option<&DomainCommitment> {
        self.commitments.get(&(domain_id, domain_height, sequence))
    }

    pub fn find_by_height(&self, domain_id: DomainId, height: u64) -> Option<DomainCommitment> {
        self.at_height(domain_id, height).next().cloned()
    }

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

    pub fn len(&self) -> usize {
        self.commitments.len()
    }

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
}
