//! Proof Verification Market primitives (Task 12 / ARENA4).
//!
//! This module prepares the proof-market abstraction without wiring Budlum to
//! LUM or any DeFi application. Rewards are represented as commitments only;
//! settlement adapters can be added later without changing the task/receipt
//! binding rules.

use crate::core::address::Address;
use crate::domain::types::{DomainId, Hash32};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type ProofTaskId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofTaskKind {
    ZkVmExecution {
        domain_id: DomainId,
        target_height: u64,
    },
    SettlementEvent {
        domain_id: DomainId,
        domain_height: u64,
        event_index: u32,
    },
    StorageChallenge {
        deal_id: Hash32,
        challenge_id: Hash32,
    },
    AiInferenceAttestation {
        request_id: Hash32,
        model_id: Hash32,
    },
    BridgeReceipt {
        source_domain: DomainId,
        target_domain: DomainId,
        payload_hash: Hash32,
    },
}

impl ProofTaskKind {
    fn tag(&self) -> u8 {
        match self {
            ProofTaskKind::ZkVmExecution { .. } => 1,
            ProofTaskKind::SettlementEvent { .. } => 2,
            ProofTaskKind::StorageChallenge { .. } => 3,
            ProofTaskKind::AiInferenceAttestation { .. } => 4,
            ProofTaskKind::BridgeReceipt { .. } => 5,
        }
    }

    fn validate(&self) -> Result<(), ProofMarketError> {
        match self {
            ProofTaskKind::ZkVmExecution {
                domain_id,
                target_height,
            } => {
                if *domain_id == 0 {
                    return Err(ProofMarketError::InvalidTaskKind(
                        "zk task domain_id cannot be zero".into(),
                    ));
                }
                if *target_height == 0 {
                    return Err(ProofMarketError::InvalidTaskKind(
                        "zk task target_height cannot be zero".into(),
                    ));
                }
            }
            ProofTaskKind::SettlementEvent {
                domain_id,
                domain_height,
                ..
            } => {
                if *domain_id == 0 {
                    return Err(ProofMarketError::InvalidTaskKind(
                        "settlement task domain_id cannot be zero".into(),
                    ));
                }
                if *domain_height == 0 {
                    return Err(ProofMarketError::InvalidTaskKind(
                        "settlement task domain_height cannot be zero".into(),
                    ));
                }
            }
            ProofTaskKind::StorageChallenge {
                deal_id,
                challenge_id,
            } => {
                if *deal_id == [0u8; 32] || *challenge_id == [0u8; 32] {
                    return Err(ProofMarketError::InvalidTaskKind(
                        "storage challenge ids cannot be zero".into(),
                    ));
                }
            }
            ProofTaskKind::AiInferenceAttestation {
                request_id,
                model_id,
            } => {
                if *request_id == [0u8; 32] || *model_id == [0u8; 32] {
                    return Err(ProofMarketError::InvalidTaskKind(
                        "ai attestation ids cannot be zero".into(),
                    ));
                }
            }
            ProofTaskKind::BridgeReceipt {
                source_domain,
                target_domain,
                payload_hash,
            } => {
                if *source_domain == 0 || *target_domain == 0 {
                    return Err(ProofMarketError::InvalidTaskKind(
                        "bridge domains cannot be zero".into(),
                    ));
                }
                if *payload_hash == [0u8; 32] {
                    return Err(ProofMarketError::InvalidTaskKind(
                        "bridge payload_hash cannot be zero".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn hash_into(&self, hasher: &mut Sha256) {
        hasher.update([self.tag()]);
        match self {
            ProofTaskKind::ZkVmExecution {
                domain_id,
                target_height,
            } => {
                hasher.update(domain_id.to_le_bytes());
                hasher.update(target_height.to_le_bytes());
            }
            ProofTaskKind::SettlementEvent {
                domain_id,
                domain_height,
                event_index,
            } => {
                hasher.update(domain_id.to_le_bytes());
                hasher.update(domain_height.to_le_bytes());
                hasher.update(event_index.to_le_bytes());
            }
            ProofTaskKind::StorageChallenge {
                deal_id,
                challenge_id,
            } => {
                hasher.update(deal_id);
                hasher.update(challenge_id);
            }
            ProofTaskKind::AiInferenceAttestation {
                request_id,
                model_id,
            } => {
                hasher.update(request_id);
                hasher.update(model_id);
            }
            ProofTaskKind::BridgeReceipt {
                source_domain,
                target_domain,
                payload_hash,
            } => {
                hasher.update(source_domain.to_le_bytes());
                hasher.update(target_domain.to_le_bytes());
                hasher.update(payload_hash);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofTaskStatus {
    Open,
    Settled,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTask {
    pub task_id: ProofTaskId,
    pub creator: Address,
    pub task_kind: ProofTaskKind,
    pub input_commitment: Hash32,
    pub reward_commitment: Hash32,
    pub deadline_block: u64,
    pub slash_condition_hash: Hash32,
    pub min_verifier_stake: u64,
    pub status: ProofTaskStatus,
}

impl ProofTask {
    pub fn prepare(
        creator: Address,
        task_kind: ProofTaskKind,
        input_commitment: Hash32,
        reward_commitment: Hash32,
        deadline_block: u64,
        slash_condition_hash: Hash32,
        min_verifier_stake: u64,
    ) -> Self {
        let task_id = Self::calculate_task_id(
            creator,
            &task_kind,
            input_commitment,
            reward_commitment,
            deadline_block,
            slash_condition_hash,
            min_verifier_stake,
        );
        Self {
            task_id,
            creator,
            task_kind,
            input_commitment,
            reward_commitment,
            deadline_block,
            slash_condition_hash,
            min_verifier_stake,
            status: ProofTaskStatus::Open,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn calculate_task_id(
        creator: Address,
        task_kind: &ProofTaskKind,
        input_commitment: Hash32,
        reward_commitment: Hash32,
        deadline_block: u64,
        slash_condition_hash: Hash32,
        min_verifier_stake: u64,
    ) -> ProofTaskId {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_PROOF_TASK_V1");
        hasher.update(creator.as_bytes());
        task_kind.hash_into(&mut hasher);
        hasher.update(input_commitment);
        hasher.update(reward_commitment);
        hasher.update(deadline_block.to_le_bytes());
        hasher.update(slash_condition_hash);
        hasher.update(min_verifier_stake.to_le_bytes());
        hasher.finalize().into()
    }

    pub fn validate_at(&self, current_block: u64) -> Result<(), ProofMarketError> {
        if self.creator == Address::zero() {
            return Err(ProofMarketError::ZeroCreator);
        }
        self.task_kind.validate()?;
        if self.input_commitment == [0u8; 32] {
            return Err(ProofMarketError::ZeroInputCommitment);
        }
        if self.reward_commitment == [0u8; 32] {
            return Err(ProofMarketError::ZeroRewardCommitment);
        }
        if self.slash_condition_hash == [0u8; 32] {
            return Err(ProofMarketError::ZeroSlashCondition);
        }
        if self.deadline_block <= current_block {
            return Err(ProofMarketError::DeadlineNotFuture {
                deadline_block: self.deadline_block,
                current_block,
            });
        }
        let expected = Self::calculate_task_id(
            self.creator,
            &self.task_kind,
            self.input_commitment,
            self.reward_commitment,
            self.deadline_block,
            self.slash_condition_hash,
            self.min_verifier_stake,
        );
        if expected != self.task_id {
            return Err(ProofMarketError::TaskIdMismatch);
        }
        Ok(())
    }

    fn hash_into(&self, hasher: &mut Sha256) {
        hasher.update(self.task_id);
        hasher.update(self.creator.as_bytes());
        self.task_kind.hash_into(hasher);
        hasher.update(self.input_commitment);
        hasher.update(self.reward_commitment);
        hasher.update(self.deadline_block.to_le_bytes());
        hasher.update(self.slash_condition_hash);
        hasher.update(self.min_verifier_stake.to_le_bytes());
        hasher.update([match self.status {
            ProofTaskStatus::Open => 1,
            ProofTaskStatus::Settled => 2,
            ProofTaskStatus::Cancelled => 3,
        }]);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofReceipt {
    pub task_id: ProofTaskId,
    pub verifier: Address,
    pub proof_hash: Hash32,
    pub accepted_at_block: u64,
    pub result_root: Hash32,
    pub verification_context_hash: Hash32,
}

impl ProofReceipt {
    pub fn validate(&self) -> Result<(), ProofMarketError> {
        if self.task_id == [0u8; 32] {
            return Err(ProofMarketError::ZeroTaskId);
        }
        if self.verifier == Address::zero() {
            return Err(ProofMarketError::ZeroVerifier);
        }
        if self.proof_hash == [0u8; 32] {
            return Err(ProofMarketError::ZeroProofHash);
        }
        if self.result_root == [0u8; 32] {
            return Err(ProofMarketError::ZeroResultRoot);
        }
        if self.verification_context_hash == [0u8; 32] {
            return Err(ProofMarketError::ZeroVerificationContext);
        }
        Ok(())
    }

    fn hash_into(&self, hasher: &mut Sha256) {
        hasher.update(self.task_id);
        hasher.update(self.verifier.as_bytes());
        hasher.update(self.proof_hash);
        hasher.update(self.accepted_at_block.to_le_bytes());
        hasher.update(self.result_root);
        hasher.update(self.verification_context_hash);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptAcceptance {
    Accepted,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofMarketError {
    ZeroCreator,
    ZeroTaskId,
    ZeroVerifier,
    ZeroInputCommitment,
    ZeroRewardCommitment,
    ZeroSlashCondition,
    ZeroProofHash,
    ZeroResultRoot,
    ZeroVerificationContext,
    InvalidTaskKind(String),
    DeadlineNotFuture {
        deadline_block: u64,
        current_block: u64,
    },
    TaskIdMismatch,
    TaskAlreadyExists,
    TaskMissing,
    TaskNotOpen,
    TaskExpired {
        deadline_block: u64,
        current_block: u64,
    },
    ConflictingReceipt,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProofMarketRegistry {
    pub tasks: BTreeMap<ProofTaskId, ProofTask>,
    pub receipts: BTreeMap<ProofTaskId, ProofReceipt>,
}

impl ProofMarketRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open_task(
        &mut self,
        task: ProofTask,
        current_block: u64,
    ) -> Result<(), ProofMarketError> {
        task.validate_at(current_block)?;
        if self.tasks.contains_key(&task.task_id) {
            return Err(ProofMarketError::TaskAlreadyExists);
        }
        self.tasks.insert(task.task_id, task);
        Ok(())
    }

    pub fn accept_receipt(
        &mut self,
        receipt: ProofReceipt,
        current_block: u64,
    ) -> Result<ReceiptAcceptance, ProofMarketError> {
        receipt.validate()?;
        let task = self
            .tasks
            .get_mut(&receipt.task_id)
            .ok_or(ProofMarketError::TaskMissing)?;

        if let Some(existing) = self.receipts.get(&receipt.task_id) {
            if existing == &receipt {
                return Ok(ReceiptAcceptance::Duplicate);
            }
            return Err(ProofMarketError::ConflictingReceipt);
        }

        if task.status != ProofTaskStatus::Open {
            return Err(ProofMarketError::TaskNotOpen);
        }
        if current_block > task.deadline_block {
            return Err(ProofMarketError::TaskExpired {
                deadline_block: task.deadline_block,
                current_block,
            });
        }

        task.status = ProofTaskStatus::Settled;
        self.receipts.insert(receipt.task_id, receipt);
        Ok(ReceiptAcceptance::Accepted)
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty() && self.receipts.is_empty()
    }

    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_PROOF_MARKET_REGISTRY_V1");
        for task in self.tasks.values() {
            hasher.update(b"task");
            task.hash_into(&mut hasher);
        }
        for receipt in self.receipts.values() {
            hasher.update(b"receipt");
            receipt.hash_into(&mut hasher);
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    fn hash(byte: u8) -> Hash32 {
        [byte; 32]
    }

    fn task(input_byte: u8) -> ProofTask {
        ProofTask::prepare(
            addr(1),
            ProofTaskKind::ZkVmExecution {
                domain_id: 7,
                target_height: 42,
            },
            hash(input_byte),
            hash(2),
            100,
            hash(3),
            0,
        )
    }

    fn receipt(task_id: ProofTaskId, result_byte: u8) -> ProofReceipt {
        ProofReceipt {
            task_id,
            verifier: addr(9),
            proof_hash: hash(4),
            accepted_at_block: 50,
            result_root: hash(result_byte),
            verification_context_hash: hash(5),
        }
    }

    #[test]
    fn task_id_binds_input_commitment() {
        assert_ne!(task(8).task_id, task(9).task_id);
    }

    #[test]
    fn proof_task_has_no_lum_dependency_or_adapter_requirement() {
        let task = task(8);
        task.validate_at(1).unwrap();
        assert_eq!(task.reward_commitment, hash(2));
    }

    #[test]
    fn missing_task_receipt_is_rejected_fail_closed() {
        let mut registry = ProofMarketRegistry::new();
        let err = registry
            .accept_receipt(receipt(hash(9), 6), 10)
            .unwrap_err();
        assert_eq!(err, ProofMarketError::TaskMissing);
    }

    #[test]
    fn expired_task_rejects_first_receipt() {
        let mut registry = ProofMarketRegistry::new();
        let task = task(8);
        let task_id = task.task_id;
        registry.open_task(task, 1).unwrap();
        let err = registry
            .accept_receipt(receipt(task_id, 6), 101)
            .unwrap_err();
        assert_eq!(
            err,
            ProofMarketError::TaskExpired {
                deadline_block: 100,
                current_block: 101,
            }
        );
    }

    #[test]
    fn first_valid_receipt_wins_and_duplicate_is_idempotent() {
        let mut registry = ProofMarketRegistry::new();
        let task = task(8);
        let task_id = task.task_id;
        registry.open_task(task, 1).unwrap();
        let receipt = receipt(task_id, 6);
        assert_eq!(
            registry.accept_receipt(receipt.clone(), 50).unwrap(),
            ReceiptAcceptance::Accepted
        );
        assert_eq!(
            registry.accept_receipt(receipt.clone(), 120).unwrap(),
            ReceiptAcceptance::Duplicate
        );

        let conflicting = ProofReceipt {
            result_root: hash(7),
            ..receipt
        };
        assert_eq!(
            registry.accept_receipt(conflicting, 50).unwrap_err(),
            ProofMarketError::ConflictingReceipt
        );
    }

    #[test]
    fn registry_root_changes_when_receipt_is_accepted() {
        let mut registry = ProofMarketRegistry::new();
        let task = task(8);
        let task_id = task.task_id;
        registry.open_task(task, 1).unwrap();
        let before = registry.root();
        registry.accept_receipt(receipt(task_id, 6), 50).unwrap();
        assert_ne!(before, registry.root());
    }
}
