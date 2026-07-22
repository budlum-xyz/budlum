//! Task 11.10 — StorageProvider trait and deterministic mock implementation.
//!
//! This is the spec-first boundary from `BUD_STORAGE_TECHNICAL_SPEC.md`:
//! provider implementations move bytes/proofs off-chain, while consensus code
//! keeps the on-chain deal/challenge accounting in `domain::storage_deal`.

use crate::core::hash::hash_fields_bytes;
use crate::domain::storage_deal::{ChallengeOutcome, RetrievalChallenge};
use crate::storage::{ContentId, ContentManifest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type DealId = [u8; 32];
pub type ChallengeId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutReceipt {
    pub content_id: ContentId,
    pub bytes_written: u64,
    pub provider_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageProof {
    pub deal_id: DealId,
    pub challenge_id: ChallengeId,
    pub range_hash: ContentId,
    pub merkle_path: Vec<[u8; 32]>,
    pub proof_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderChallengeResult {
    pub challenge_id: ChallengeId,
    pub deal_id: DealId,
    pub outcome: ChallengeOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageProviderError {
    EmptyPayload,
    MissingContent(ContentId),
    MissingChallenge(ChallengeId),
    InvalidRange { start: u64, end: u64, len: u64 },
    ProofChallengeMismatch,
    ProofRangeMismatch,
}

pub trait StorageProvider {
    fn put(
        &mut self,
        manifest: &ContentManifest,
        bytes: &[u8],
    ) -> Result<PutReceipt, StorageProviderError>;

    fn get(
        &self,
        content_id: &ContentId,
        range: std::ops::Range<u64>,
    ) -> Result<Vec<u8>, StorageProviderError>;

    fn prove(
        &self,
        deal_id: DealId,
        challenge: &RetrievalChallenge,
    ) -> Result<StorageProof, StorageProviderError>;

    fn challenge(
        &mut self,
        deal_id: DealId,
        challenge: RetrievalChallenge,
    ) -> Result<ChallengeId, StorageProviderError>;

    fn settle(
        &mut self,
        challenge_id: ChallengeId,
        proof: StorageProof,
    ) -> Result<ProviderChallengeResult, StorageProviderError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryStorageProvider {
    chunks: BTreeMap<ContentId, Vec<u8>>,
    challenges: BTreeMap<ChallengeId, (DealId, RetrievalChallenge)>,
}

impl InMemoryStorageProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, content_id: &ContentId) -> bool {
        self.chunks.contains_key(content_id)
    }
}

impl StorageProvider for InMemoryStorageProvider {
    fn put(
        &mut self,
        manifest: &ContentManifest,
        bytes: &[u8],
    ) -> Result<PutReceipt, StorageProviderError> {
        if bytes.is_empty() {
            return Err(StorageProviderError::EmptyPayload);
        }
        let content_id = ContentId::of(bytes);
        self.chunks.insert(content_id, bytes.to_vec());
        let provider_commitment = hash_fields_bytes(&[
            b"BDLM_STORAGE_PROVIDER_PUT_V1",
            manifest.manifest_id.as_bytes(),
            content_id.as_bytes(),
            &bytes.len().to_le_bytes(),
        ]);
        Ok(PutReceipt {
            content_id,
            bytes_written: bytes.len() as u64,
            provider_commitment,
        })
    }

    fn get(
        &self,
        content_id: &ContentId,
        range: std::ops::Range<u64>,
    ) -> Result<Vec<u8>, StorageProviderError> {
        let bytes = self
            .chunks
            .get(content_id)
            .ok_or(StorageProviderError::MissingContent(*content_id))?;
        if range.start > range.end || range.end > bytes.len() as u64 {
            return Err(StorageProviderError::InvalidRange {
                start: range.start,
                end: range.end,
                len: bytes.len() as u64,
            });
        }
        Ok(bytes[range.start as usize..range.end as usize].to_vec())
    }

    fn prove(
        &self,
        deal_id: DealId,
        challenge: &RetrievalChallenge,
    ) -> Result<StorageProof, StorageProviderError> {
        let bytes = self
            .chunks
            .get(&challenge.shard_id)
            .ok_or(StorageProviderError::MissingContent(challenge.shard_id))?;
        if challenge.byte_start > challenge.byte_end || challenge.byte_end > bytes.len() as u64 {
            return Err(StorageProviderError::InvalidRange {
                start: challenge.byte_start,
                end: challenge.byte_end,
                len: bytes.len() as u64,
            });
        }
        let challenge_id = provider_challenge_id(deal_id, challenge);
        let range_hash = ContentId::of_subrange(bytes, challenge.byte_start, challenge.byte_end);
        Ok(StorageProof {
            deal_id,
            challenge_id,
            range_hash,
            merkle_path: Vec::new(),
            proof_bytes: hash_fields_bytes(&[
                b"BDLM_STORAGE_PROVIDER_PROOF_V1",
                &deal_id,
                &challenge_id,
                range_hash.as_bytes(),
            ])
            .to_vec(),
        })
    }

    fn challenge(
        &mut self,
        deal_id: DealId,
        challenge: RetrievalChallenge,
    ) -> Result<ChallengeId, StorageProviderError> {
        let challenge_id = provider_challenge_id(deal_id, &challenge);
        self.challenges.insert(challenge_id, (deal_id, challenge));
        Ok(challenge_id)
    }

    fn settle(
        &mut self,
        challenge_id: ChallengeId,
        proof: StorageProof,
    ) -> Result<ProviderChallengeResult, StorageProviderError> {
        let (deal_id, challenge) = self
            .challenges
            .remove(&challenge_id)
            .ok_or(StorageProviderError::MissingChallenge(challenge_id))?;
        if proof.deal_id != deal_id || proof.challenge_id != challenge_id {
            return Err(StorageProviderError::ProofChallengeMismatch);
        }
        let bytes = self
            .chunks
            .get(&challenge.shard_id)
            .ok_or(StorageProviderError::MissingContent(challenge.shard_id))?;
        let expected = ContentId::of_subrange(bytes, challenge.byte_start, challenge.byte_end);
        if proof.range_hash != expected {
            return Err(StorageProviderError::ProofRangeMismatch);
        }
        Ok(ProviderChallengeResult {
            challenge_id,
            deal_id,
            outcome: ChallengeOutcome::Answered,
        })
    }
}

pub fn provider_challenge_id(deal_id: DealId, challenge: &RetrievalChallenge) -> ChallengeId {
    hash_fields_bytes(&[
        b"BDLM_STORAGE_PROVIDER_CHALLENGE_V1",
        &deal_id,
        &challenge.challenge_id.to_le_bytes(),
        &challenge.deal_id.to_le_bytes(),
        challenge.shard_id.as_bytes(),
        &challenge.byte_start.to_le_bytes(),
        &challenge.byte_end.to_le_bytes(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::storage::ShardRef;

    fn manifest_and_bytes() -> (ContentManifest, Vec<u8>) {
        let bytes = b"abcdefghijklmnopqrstuvwxyz".to_vec();
        let shard = ShardRef::from_bytes(0, &bytes);
        let manifest = ContentManifest::from_shards(vec![shard])
            .unwrap()
            .with_owner(Address::from([1u8; 32]));
        (manifest, bytes)
    }

    fn deal_id(byte: u8) -> DealId {
        [byte; 32]
    }

    fn challenge(shard_id: ContentId) -> RetrievalChallenge {
        RetrievalChallenge {
            challenge_id: 7,
            deal_id: 9,
            shard_id,
            byte_start: 2,
            byte_end: 8,
            challenge_epoch: 1,
            deadline_epoch: 2,
            opener: Address::from([2u8; 32]),
            opener_bond: 1,
        }
    }

    #[test]
    fn task11_10_storage_provider_put_get_roundtrip() {
        let (manifest, bytes) = manifest_and_bytes();
        let mut provider = InMemoryStorageProvider::new();
        let receipt = provider.put(&manifest, &bytes).unwrap();
        assert!(provider.contains(&receipt.content_id));
        assert_eq!(receipt.bytes_written, bytes.len() as u64);
        assert_eq!(provider.get(&receipt.content_id, 0..3).unwrap(), b"abc");
    }

    #[test]
    fn task11_10_storage_provider_rejects_invalid_range() {
        let (manifest, bytes) = manifest_and_bytes();
        let mut provider = InMemoryStorageProvider::new();
        let receipt = provider.put(&manifest, &bytes).unwrap();
        let err = provider.get(&receipt.content_id, 99..100).unwrap_err();
        assert!(matches!(err, StorageProviderError::InvalidRange { .. }));
    }

    #[test]
    fn task11_10_storage_provider_prove_settle_roundtrip() {
        let (manifest, bytes) = manifest_and_bytes();
        let mut provider = InMemoryStorageProvider::new();
        let receipt = provider.put(&manifest, &bytes).unwrap();
        let challenge = challenge(receipt.content_id);
        let deal_id = deal_id(3);
        let challenge_id = provider.challenge(deal_id, challenge.clone()).unwrap();
        let proof = provider.prove(deal_id, &challenge).unwrap();
        assert_eq!(proof.challenge_id, challenge_id);
        let result = provider.settle(challenge_id, proof).unwrap();
        assert_eq!(result.outcome, ChallengeOutcome::Answered);
    }

    #[test]
    fn task11_10_storage_provider_rejects_forged_proof_range_hash() {
        let (manifest, bytes) = manifest_and_bytes();
        let mut provider = InMemoryStorageProvider::new();
        let receipt = provider.put(&manifest, &bytes).unwrap();
        let challenge = challenge(receipt.content_id);
        let deal_id = deal_id(4);
        let challenge_id = provider.challenge(deal_id, challenge.clone()).unwrap();
        let mut proof = provider.prove(deal_id, &challenge).unwrap();
        proof.range_hash = ContentId::of(b"forged");
        let err = provider.settle(challenge_id, proof).unwrap_err();
        assert_eq!(err, StorageProviderError::ProofRangeMismatch);
    }
}
