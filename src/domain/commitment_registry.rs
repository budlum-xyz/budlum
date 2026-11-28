use crate::domain::types::{DomainCommitment, DomainId, Hash32};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum number of queued out-of-order commitments held above a domain's
/// committed tip so a stalled domain cannot accumulate unbounded state.
pub const MAX_PENDING_COMMITMENTS_PER_DOMAIN: usize = 256;

/// Default anti-withholding inclusion SLA window in Budlum blocks before an
/// unadvanced pending commitment is flagged as overdue.
pub const DEFAULT_MAX_INCLUSION_LAG_BLOCKS: u64 = 32;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainCommitmentRegistry {
    #[serde(with = "crate::core::map_keys")]
    commitments: BTreeMap<(DomainId, u64, u64), DomainCommitment>,
    seen_blocks: BTreeSet<(DomainId, u64, Hash32)>,
    #[serde(default, with = "crate::core::map_keys")]
    accepted_at_height: BTreeMap<(DomainId, u64, u64), u64>,
    #[serde(default)]
    unavailable_quarantined: BTreeSet<(DomainId, u64, Hash32)>,
}

impl DomainCommitmentRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            commitments: BTreeMap::new(),
            seen_blocks: BTreeSet::new(),
            accepted_at_height: BTreeMap::new(),
            unavailable_quarantined: BTreeSet::new(),
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

        if self.unavailable_quarantined.contains(&block_key) {
            return Err(format!(
                "Commitment quarantined for unavailable DA payload: domain={}, height={}",
                commitment.domain_id, commitment.domain_height
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

    /// Count queued commitments for `domain_id` strictly above `committed_height`.
    ///
    /// WIRING: Checked by `settlement::domains::accept_commitment` before
    /// queueing out-of-order commitments above a domain's committed tip.
    #[must_use]
    /// Quarantine a stored commitment whose underlying data-availability payload
    /// proved unavailable after submission, removing it from active lookup
    /// queues and blocking re-admission of the same `(domain_id, height, block_hash)`.
    ///
    /// WIRING: DA-availability quarantine control alongside [`Self::remove`].
    pub fn quarantine_unavailable_commitment(
        &mut self,
        domain_id: DomainId,
        domain_height: u64,
        sequence: u64,
    ) -> Option<DomainCommitment> {
        let removed = self.remove(domain_id, domain_height, sequence)?;
        self.unavailable_quarantined
            .insert((domain_id, domain_height, removed.domain_block_hash));
        Some(removed)
    }

    /// Return `true` if `(domain_id, domain_height, domain_block_hash)` was
    /// quarantined for unavailable DA payload.
    #[must_use]
    pub fn is_quarantined(
        &self,
        domain_id: DomainId,
        domain_height: u64,
        domain_block_hash: Hash32,
    ) -> bool {
        self.unavailable_quarantined
            .contains(&(domain_id, domain_height, domain_block_hash))
    }

    pub fn pending_count_above(&self, domain_id: DomainId, committed_height: u64) -> usize {
        let start = committed_height.saturating_add(1);
        self.commitments
            .range((domain_id, start, 0)..=(domain_id, u64::MAX, u64::MAX))
            .count()
    }

    /// Return queued commitments above `committed_height` whose Budlum
    /// acceptance age equals or exceeds `max_inclusion_lag` blocks.
    ///
    /// WIRING: Surfaced by `settlement::domains::overdue_pending_commitments_for_domain`
    /// to enforce forced-inclusion anti-withholding SLA accounting.
    #[must_use]
    pub fn overdue_pending_commitments(
        &self,
        domain_id: DomainId,
        committed_height: u64,
        current_budlum_height: u64,
        max_inclusion_lag: u64,
    ) -> Vec<DomainCommitment> {
        let start = committed_height.saturating_add(1);
        self.commitments
            .range((domain_id, start, 0)..=(domain_id, u64::MAX, u64::MAX))
            .filter_map(|(key, commitment)| {
                let accepted_h = self.accepted_at_height.get(key).copied()?;
                let age = current_budlum_height.saturating_sub(accepted_h);
                if age >= max_inclusion_lag {
                    Some(commitment.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Remove all stored commitments, acceptance heights, and seen block tags for
    /// `domain_id` strictly above `target_height` on a deterministic tip reset.
    ///
    /// WIRING: Called by `settlement::domains::apply_domain_tip_resets` alongside
    /// proof-claim rollback so reorged heights never stay poisoned.
    pub fn rollback_domain_above(&mut self, domain_id: DomainId, target_height: u64) -> usize {
        if target_height == u64::MAX {
            return 0;
        }
        let min_drop_height = target_height.saturating_add(1);
        let keys_to_drop: Vec<(DomainId, u64, u64)> = self
            .commitments
            .range((domain_id, min_drop_height, 0)..=(domain_id, u64::MAX, u64::MAX))
            .map(|(key, _)| *key)
            .collect();
        let mut dropped = 0usize;
        for (dom, height, seq) in keys_to_drop {
            if self.remove(dom, height, seq).is_some() {
                dropped = dropped.saturating_add(1);
            }
        }
        dropped
    }

    /// Compute the canonical content-addressed SHA3-256 locator digest for a
    /// `DomainCommitment`, domain-separated from any Merkle leaf encoding.
    ///
    /// WIRING: Content-addressed DA digest verified by `settlement::domains::apply_domain_tip_resets`.
    #[must_use]
    pub fn canonical_commitment_hash(commitment: &DomainCommitment) -> Hash32 {
        let leaf = commitment.leaf_hash();
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_DA_CANONICAL_COMMITMENT_V1");
        hasher.update(leaf);
        hasher.finalize().into()
    }

    /// Retrieve a commitment for `(domain_id, domain_height)` by verifying its
    /// content-addressed canonical digest against `expected_hash` (hash-addressed DA).
    #[must_use]
    pub fn get_verified_by_canonical_hash(
        &self,
        domain_id: DomainId,
        domain_height: u64,
        expected_hash: &Hash32,
    ) -> Option<&DomainCommitment> {
        self.at_height(domain_id, domain_height)
            .find(|commitment| Self::canonical_commitment_hash(commitment) == *expected_hash)
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
        let mut leaves: Vec<Hash32> = self
            .commitments
            .values()
            .map(DomainCommitment::leaf_hash)
            .collect();
        for (domain_id, domain_height, block_hash) in &self.unavailable_quarantined {
            let mut h = Sha3_256::new();
            h.update(b"BDLM_DA_QUARANTINE_LEAF_V1");
            h.update(domain_id.to_le_bytes());
            h.update(domain_height.to_le_bytes());
            h.update(block_hash);
            leaves.push(h.finalize().into());
        }
        crate::settlement::commitment_tree::merkle_root(&leaves)
    }
}

/// A Merkle sibling path from one domain commitment leaf to the root of the
/// commitment tree a checkpoint header commits (`domain_commitment_root`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainCommitmentInclusionProof {
    /// The leaf's position among the tree's leaves in registry key order.
    pub leaf_index: usize,
    /// The number of leaves the root was computed over.
    pub leaf_count: usize,
    /// The sibling digests, leaf layer first.
    pub siblings: Vec<Hash32>,
}

impl DomainCommitmentInclusionProof {
    /// Verify that `leaf` at `leaf_index` rebuilds `root` using the canonical
    /// settlement Merkle combine functions.
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
    /// Build a Merkle inclusion proof from `(domain_id, domain_height, sequence)` to
    /// [`Self::root`], returning `None` when absent.
    #[must_use]
    pub fn prove(
        &self,
        domain_id: DomainId,
        domain_height: u64,
        sequence: u64,
    ) -> Option<DomainCommitmentInclusionProof> {
        let key = (domain_id, domain_height, sequence);
        let mut leaves = Vec::with_capacity(
            self.commitments
                .len()
                .saturating_add(self.unavailable_quarantined.len()),
        );
        let mut leaf_index = None;
        for (at, (held, commitment)) in self.commitments.iter().enumerate() {
            if *held == key {
                leaf_index = Some(at);
            }
            leaves.push(commitment.leaf_hash());
        }
        for (dom_id, dom_height, block_hash) in &self.unavailable_quarantined {
            let mut h = Sha3_256::new();
            h.update(b"BDLM_DA_QUARANTINE_LEAF_V1");
            h.update(dom_id.to_le_bytes());
            h.update(dom_height.to_le_bytes());
            h.update(block_hash);
            leaves.push(h.finalize().into());
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

    #[test]
    fn rollback_sla_and_canonical_hash_lookup_behave_deterministically() {
        let mut registry = DomainCommitmentRegistry::new();
        for offset in 0..4u64 {
            let mut c = commitment(offset, [u8::try_from(offset).unwrap_or(0) + 10; 32]);
            c.domain_height = 10 + offset;
            registry.insert_at_height(c, 100 + offset).unwrap();
        }
        assert_eq!(registry.pending_count_above(1, 10), 3);

        let overdue_at_133 = registry.overdue_pending_commitments(1, 10, 133, 32);
        assert_eq!(overdue_at_133.len(), 1);
        assert_eq!(overdue_at_133[0].domain_height, 11);

        let overdue = registry.overdue_pending_commitments(1, 10, 134, 32);
        assert_eq!(overdue.len(), 2);
        assert_eq!(overdue[0].domain_height, 11);
        assert_eq!(overdue[1].domain_height, 12);

        let target = registry.get(1, 11, 1).unwrap().clone();
        let canonical = DomainCommitmentRegistry::canonical_commitment_hash(&target);
        assert_eq!(
            registry
                .get_verified_by_canonical_hash(1, 11, &canonical)
                .map(|c| c.domain_block_hash),
            Some(target.domain_block_hash)
        );
        assert!(registry
            .get_verified_by_canonical_hash(1, 11, &[0xAA; 32])
            .is_none());

        assert_eq!(registry.rollback_domain_above(1, 11), 2);
        assert_eq!(registry.pending_count_above(1, 10), 1);
        assert!(registry.get(1, 12, 2).is_none());
        assert!(registry.get(1, 13, 3).is_none());
        assert!(registry.get(1, 11, 1).is_some());
    }

    #[test]
    fn quarantine_unavailable_commitment_drops_row_and_blocks_readmission() {
        let mut registry = DomainCommitmentRegistry::new();
        let com = commitment(0, [0x44; 32]);
        registry.insert(com.clone()).unwrap();
        assert_eq!(registry.len(), 1);

        let removed = registry
            .quarantine_unavailable_commitment(1, 10, 0)
            .expect("present commitment should be quarantined");
        assert_eq!(removed.domain_block_hash, [0x44; 32]);
        assert!(registry.is_empty());
        assert!(registry.is_quarantined(1, 10, [0x44; 32]));

        // Same block hash cannot be re-inserted under a new sequence number.
        let mut retry = commitment(1, [0x44; 32]);
        retry.sequence = 1;
        let err = registry
            .insert(retry)
            .expect_err("quarantined unavailable commitment must remain blocked");
        assert!(err.contains("quarantined"), "unexpected err: {err}");
    }

    fn numbered(number: u64) -> DomainCommitment {
        commitment(number, [u8::try_from(number + 1).unwrap_or(1); 32])
    }

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
