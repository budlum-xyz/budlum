//! P12-11: Proof Verification Market — settlement-side proof task/receipt model.
//!
//! This module is intentionally LUM-adapter free. It models bounded proof tasks,
//! Prover receipts and settlement accounting in $BUD-compatible commitments so
//! A future LUM/DeFi adapter can be attached without weakening fail-closed proof
//! Verification semantics.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::domain::{DomainId, Hash32};
use serde::{Deserialize, Serialize};

pub const MAX_PROOF_MARKET_ACTIVE_TASKS: usize = 10_000;
pub const MAX_PROOF_MARKET_PENDING_RECEIPTS: usize = 10_000;

fn nonzero_hash(value: &Hash32) -> bool {
    *value != [0u8; 32]
}

/// Proof görev türü.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofTaskKind {
    /// Domain commitment doğrulama — Merkle proof + event verification.
    DomainCommitment {
        domain_id: DomainId,
        domain_height: u64,
        sequence: u64,
    },
    /// ZK-proof doğrulama — STARK/SNARK verifier.
    ZkProof {
        circuit_id: [u8; 32],
        public_inputs_hash: Hash32,
    },
    /// Sync-committee BLS imza doğrulama.
    SyncCommitteeSig { domain_id: DomainId, epoch: u64 },
    /// Storage attestation doğrulama.
    StorageAttestation {
        deal_id: [u8; 32],
        challenge_epoch: u64,
    },
}

impl ProofTaskKind {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            ProofTaskKind::DomainCommitment {
                domain_id,
                domain_height,
                ..
            } => {
                if *domain_id == 0 {
                    return Err("ProofTaskKind domain_id cannot be zero".into());
                }
                if *domain_height == 0 {
                    return Err("ProofTaskKind domain_height cannot be zero".into());
                }
            }
            ProofTaskKind::ZkProof {
                circuit_id,
                public_inputs_hash,
            } => {
                if !nonzero_hash(circuit_id) {
                    return Err("ProofTaskKind circuit_id cannot be zero".into());
                }
                if !nonzero_hash(public_inputs_hash) {
                    return Err("ProofTaskKind public_inputs_hash cannot be zero".into());
                }
            }
            ProofTaskKind::SyncCommitteeSig { domain_id, epoch } => {
                if *domain_id == 0 {
                    return Err("ProofTaskKind sync domain_id cannot be zero".into());
                }
                if *epoch == 0 {
                    return Err("ProofTaskKind sync epoch cannot be zero".into());
                }
            }
            ProofTaskKind::StorageAttestation {
                deal_id,
                challenge_epoch,
            } => {
                if !nonzero_hash(deal_id) {
                    return Err("ProofTaskKind storage deal_id cannot be zero".into());
                }
                if *challenge_epoch == 0 {
                    return Err("ProofTaskKind storage challenge_epoch cannot be zero".into());
                }
            }
        }
        Ok(())
    }

    fn tag(&self) -> u8 {
        match self {
            ProofTaskKind::DomainCommitment { .. } => 1,
            ProofTaskKind::ZkProof { .. } => 2,
            ProofTaskKind::SyncCommitteeSig { .. } => 3,
            ProofTaskKind::StorageAttestation { .. } => 4,
        }
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.tag());
        match self {
            ProofTaskKind::DomainCommitment {
                domain_id,
                domain_height,
                sequence,
            } => {
                out.extend_from_slice(&domain_id.to_le_bytes());
                out.extend_from_slice(&domain_height.to_le_bytes());
                out.extend_from_slice(&sequence.to_le_bytes());
            }
            ProofTaskKind::ZkProof {
                circuit_id,
                public_inputs_hash,
            } => {
                out.extend_from_slice(circuit_id);
                out.extend_from_slice(public_inputs_hash);
            }
            ProofTaskKind::SyncCommitteeSig { domain_id, epoch } => {
                out.extend_from_slice(&domain_id.to_le_bytes());
                out.extend_from_slice(&epoch.to_le_bytes());
            }
            ProofTaskKind::StorageAttestation {
                deal_id,
                challenge_epoch,
            } => {
                out.extend_from_slice(deal_id);
                out.extend_from_slice(&challenge_epoch.to_le_bytes());
            }
        }
        out
    }
}

/// Proof görev durumu.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofTaskStatus {
    /// Beklemede — prover atanmamış.
    Pending,
    /// Prover atanmış — çalışıyor.
    Assigned {
        prover: Address,
        assigned_at_epoch: u64,
    },
    /// Tamamlanmış — proof doğrulanmış.
    Completed,
    /// Süresi dolmuş.
    Expired,
    /// Başarısız — proof geçersiz.
    Failed { reason: String },
}

/// Proof görevi — prover'ların üstlenebileceği bir doğrulama görevi.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofTask {
    /// Görev ID (deterministik: hash(task_kind + creator + created/deadline/reward)).
    pub task_id: [u8; 32],
    /// Görev türü.
    pub kind: ProofTaskKind,
    /// Görevi oluşturan (genellikle settlement layer).
    pub creator: Address,
    /// Oluşturulma epoch'u.
    pub created_epoch: u64,
    /// Son teslim epoch'u.
    pub deadline_epoch: u64,
    /// Görev durumu.
    pub status: ProofTaskStatus,
    /// Ödül miktarı (u64 BUD birimi, 6 ondalık).
    pub reward: u64,
    /// Zorluk seviyesi (prover stake gereksinimi oranı, fixed-point).
    pub difficulty: u64,
}

impl ProofTask {
    /// Yeni bir proof görevi oluşturur.
    pub fn new(
        kind: ProofTaskKind,
        creator: Address,
        created_epoch: u64,
        deadline_epoch: u64,
        reward: u64,
    ) -> Self {
        let task_id = Self::compute_task_id(&kind, &creator, created_epoch, deadline_epoch, reward);
        let difficulty = Self::default_difficulty(&kind);
        Self {
            task_id,
            kind,
            creator,
            created_epoch,
            deadline_epoch,
            status: ProofTaskStatus::Pending,
            reward,
            difficulty,
        }
    }

    /// Deterministik görev ID hesaplar.
    fn compute_task_id(
        kind: &ProofTaskKind,
        creator: &Address,
        created_epoch: u64,
        deadline_epoch: u64,
        reward: u64,
    ) -> [u8; 32] {
        let kind_bytes = kind.canonical_bytes();
        hash_fields_bytes(&[
            b"BDLM_SETTLEMENT_PROOF_TASK_V1",
            &kind_bytes,
            creator.as_bytes(),
            &created_epoch.to_le_bytes(),
            &deadline_epoch.to_le_bytes(),
            &reward.to_le_bytes(),
        ])
    }

    pub fn verify_id(&self) -> bool {
        self.task_id
            == Self::compute_task_id(
                &self.kind,
                &self.creator,
                self.created_epoch,
                self.deadline_epoch,
                self.reward,
            )
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        if self.task_id == [0u8; 32] {
            return Err("ProofTask task_id cannot be zero".into());
        }
        if self.creator == Address::zero() {
            return Err("ProofTask creator cannot be zero".into());
        }
        self.kind.validate()?;
        if self.deadline_epoch <= self.created_epoch {
            return Err("ProofTask deadline_epoch must be after created_epoch".into());
        }
        if self.reward == 0 {
            return Err("ProofTask reward must be >= 1".into());
        }
        if !self.verify_id() {
            return Err("ProofTask task_id mismatch".into());
        }
        Ok(())
    }

    /// Görev türüne göre varsayılan zorluk.
    fn default_difficulty(kind: &ProofTaskKind) -> u64 {
        match kind {
            ProofTaskKind::DomainCommitment { .. } => 1_000_000, // FIXED_POINT_SCALE = 1x
            ProofTaskKind::ZkProof { .. } => 10_000_000,         // 10x
            ProofTaskKind::SyncCommitteeSig { .. } => 2_000_000, // 2x
            ProofTaskKind::StorageAttestation { .. } => 3_000_000, // 3x
        }
    }

    /// Görevi bir prover'a atar.
    pub fn assign(&mut self, prover: Address, current_epoch: u64) -> Result<(), String> {
        self.validate_shape()?;
        if prover == Address::zero() {
            return Err("ProofTask prover cannot be zero".into());
        }
        if self.status != ProofTaskStatus::Pending {
            return Err(format!(
                "Task {:?} is not pending (status: {:?})",
                &self.task_id[..4],
                self.status
            ));
        }
        if current_epoch < self.created_epoch {
            return Err("Task cannot be assigned before created_epoch".into());
        }
        if current_epoch > self.deadline_epoch {
            return Err("Task has already expired".to_string());
        }
        self.status = ProofTaskStatus::Assigned {
            prover,
            assigned_at_epoch: current_epoch,
        };
        Ok(())
    }

    /// Görevi tamamlanmış olarak işaretler.
    pub fn complete(&mut self) -> Result<(), String> {
        match &self.status {
            ProofTaskStatus::Assigned { .. } => {
                self.status = ProofTaskStatus::Completed;
                Ok(())
            }
            ProofTaskStatus::Pending => Err("Task must be assigned before completing".to_string()),
            other => Err(format!("Cannot complete task in state {other:?}")),
        }
    }

    /// Görevi süresi dolmuş olarak işaretler.
    pub fn expire(&mut self) -> Result<(), String> {
        if !self.is_active() {
            return Err("Only active tasks can expire".into());
        }
        self.status = ProofTaskStatus::Expired;
        Ok(())
    }

    /// Görev aktif mi (pending veya assigned)?
    pub fn is_active(&self) -> bool {
        matches!(
            self.status,
            ProofTaskStatus::Pending | ProofTaskStatus::Assigned { .. }
        )
    }
}

/// Proof makbuzu — prover'ın bir görevi başarıyla tamamladığını kanıtlar.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofReceipt {
    /// İlgili görev ID.
    pub task_id: [u8; 32],
    /// Proof'u sunan prover adresi.
    pub prover: Address,
    /// Doğrulama zaman damgası (epoch).
    pub verified_epoch: u64,
    /// Proof doğrulama sonucu hash'i.
    pub verification_hash: Hash32,
    /// Ödül miktarı (BUD birimi).
    pub reward_claimed: u64,
    /// Makbuz durumu.
    pub status: ReceiptStatus,
}

/// Makbuz durumu.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReceiptStatus {
    /// Ödenmemiş — settlement onayı bekliyor.
    Pending,
    /// Ödenmiş — ödül prover'a dağıtıldı.
    Paid,
    /// İptal — proof geçersiz bulundu.
    Revoked { reason: String },
}

impl ProofReceipt {
    /// Yeni bir proof makbuzu oluşturur.
    pub fn new(
        task_id: [u8; 32],
        prover: Address,
        verified_epoch: u64,
        verification_hash: Hash32,
        reward_claimed: u64,
    ) -> Self {
        Self {
            task_id,
            prover,
            verified_epoch,
            verification_hash,
            reward_claimed,
            status: ReceiptStatus::Pending,
        }
    }

    pub fn validate_for_task(&self, task: &ProofTask) -> Result<(), String> {
        task.validate_shape()?;
        if self.task_id != task.task_id {
            return Err("ProofReceipt task_id mismatch".into());
        }
        if self.prover == Address::zero() {
            return Err("ProofReceipt prover cannot be zero".into());
        }
        let ProofTaskStatus::Assigned {
            prover,
            assigned_at_epoch,
        } = &task.status
        else {
            return Err("ProofReceipt requires assigned task".into());
        };
        if self.prover != *prover {
            return Err("ProofReceipt prover does not match assigned prover".into());
        }
        if self.verified_epoch < *assigned_at_epoch || self.verified_epoch > task.deadline_epoch {
            return Err("ProofReceipt verified_epoch outside task window".into());
        }
        if !nonzero_hash(&self.verification_hash) {
            return Err("ProofReceipt verification_hash cannot be zero".into());
        }
        if self.reward_claimed == 0 || self.reward_claimed > task.reward {
            return Err("ProofReceipt reward_claimed invalid".into());
        }
        Ok(())
    }

    /// Makbuzu ödenmiş olarak işaretler.
    pub fn mark_paid(&mut self) -> Result<(), String> {
        if self.status != ReceiptStatus::Pending {
            return Err("Receipt is not pending".to_string());
        }
        self.status = ReceiptStatus::Paid;
        Ok(())
    }

    /// Makbuzu iptal eder.
    pub fn revoke(&mut self, reason: String) -> Result<(), String> {
        if reason.is_empty() || reason.len() > 256 {
            return Err("Receipt revoke reason invalid".into());
        }
        if matches!(self.status, ReceiptStatus::Revoked { .. }) {
            return Err("Receipt is already revoked".to_string());
        }
        self.status = ReceiptStatus::Revoked { reason };
        Ok(())
    }

    /// Makbuz ödenebilir mi?
    pub fn is_payable(&self) -> bool {
        self.status == ReceiptStatus::Pending
    }

    /// Check if receipt has been paid (for pruning).
    pub fn is_paid(&self) -> bool {
        matches!(self.status, ReceiptStatus::Paid)
    }
}

/// Proof Market genel durum takibi.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProofMarketState {
    /// Aktif görevler.
    pub active_tasks: Vec<ProofTask>,
    /// Bekleyen makbuzlar.
    pub pending_receipts: Vec<ProofReceipt>,
    /// Toplam ödenen ödül (u64 BUD birimi).
    pub total_rewards_paid: u64,
    /// Toplam tamamlanan görev sayısı.
    pub total_tasks_completed: u64,
}

impl ProofMarketState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Yeni görev ekler.
    pub fn add_task(&mut self, task: ProofTask) -> Result<(), String> {
        task.validate_shape()?;
        if task.is_active() {
            if self.active_tasks.len() >= MAX_PROOF_MARKET_ACTIVE_TASKS {
                return Err("ProofMarketState active task limit exceeded".into());
            }
            if self
                .active_tasks
                .iter()
                .any(|existing| existing.task_id == task.task_id)
            {
                return Err("ProofMarketState duplicate task".into());
            }
            self.active_tasks.push(task);
        }
        Ok(())
    }

    /// Görev tamamlandığında makbuz üretir ve görevi kaldırır.
    pub fn complete_task(
        &mut self,
        task_id: [u8; 32],
        receipt: ProofReceipt,
    ) -> Result<(), String> {
        let idx = self
            .active_tasks
            .iter()
            .position(|t| t.task_id == task_id)
            .ok_or("Task not found in active tasks")?;

        receipt.validate_for_task(&self.active_tasks[idx])?;
        let mut task = self.active_tasks.remove(idx);
        task.complete()?;
        if self.pending_receipts.len() >= MAX_PROOF_MARKET_PENDING_RECEIPTS {
            return Err("ProofMarketState pending receipt limit exceeded".into());
        }
        self.pending_receipts.push(receipt);
        self.total_tasks_completed = self
            .total_tasks_completed
            .checked_add(1)
            .ok_or_else(|| "ProofMarketState total_tasks_completed overflow".to_string())?;
        Ok(())
    }

    /// Makbuzu öder ve kaldırır.
    pub fn pay_receipt(&mut self, receipt_idx: usize) -> Result<u64, String> {
        let receipt = self
            .pending_receipts
            .get_mut(receipt_idx)
            .ok_or("Receipt index out of bounds")?;

        let reward = receipt.reward_claimed;
        receipt.mark_paid()?;
        self.total_rewards_paid = self
            .total_rewards_paid
            .checked_add(reward)
            .ok_or_else(|| "ProofMarketState total_rewards_paid overflow".to_string())?;
        Ok(reward)
    }

    /// Süresi dolmuş görevleri temizler.
    pub fn prune_expired(&mut self, current_epoch: u64) -> usize {
        let before = self.active_tasks.len();
        self.active_tasks
            .retain(|t| t.deadline_epoch >= current_epoch || !t.is_active());
        before - self.active_tasks.len()
    }

    /// Prune paid receipts from pending_receipts Vec.
    /// Without this, the Vec grows indefinitely — paid receipts are never
    /// Removed, only marked as paid. Call this periodically after pay_receipt.
    pub fn prune_paid_receipts(&mut self) -> usize {
        let before = self.pending_receipts.len();
        self.pending_receipts.retain(|r| !r.is_paid());
        before - self.pending_receipts.len()
    }

    /// Cap active_tasks + pending_receipts to prevent unbounded memory
    /// Growth on long-running nodes.
    /// Only prune expired/expired tasks — never drop
    /// In-progress tasks that still have time remaining.
    pub fn enforce_max_sizes(&mut self) {
        if self.active_tasks.len() > MAX_PROOF_MARKET_ACTIVE_TASKS {
            // V5-1: first remove only expired tasks
            let current_max_epoch = self
                .active_tasks
                .iter()
                .map(|t| t.deadline_epoch)
                .max()
                .unwrap_or(0);
            let before = self.active_tasks.len();
            self.active_tasks
                .retain(|t| t.deadline_epoch >= current_max_epoch.saturating_sub(1000));
            let pruned_expired = before - self.active_tasks.len();
            if pruned_expired > 0 {
                tracing::info!("Pruned {pruned_expired} expired tasks by deadline");
            }
            // If still over cap after expiry pruning, fail-closed: log critical warning
            // But do NOT drop in-progress tasks (they represent real prover work).
            if self.active_tasks.len() > MAX_PROOF_MARKET_ACTIVE_TASKS {
                tracing::error!(
                    "active_tasks ({}) still over cap ({}) after expiry pruning — \
                     refusing to drop in-progress proof tasks",
                    self.active_tasks.len(),
                    MAX_PROOF_MARKET_ACTIVE_TASKS
                );
            }
        }
        if self.pending_receipts.len() > MAX_PROOF_MARKET_PENDING_RECEIPTS {
            // Remove paid receipts first, then oldest
            self.prune_paid_receipts();
            if self.pending_receipts.len() > MAX_PROOF_MARKET_PENDING_RECEIPTS {
                let to_remove = self.pending_receipts.len() - MAX_PROOF_MARKET_PENDING_RECEIPTS;
                self.pending_receipts.drain(0..to_remove);
                tracing::warn!("Pruned {to_remove} oldest pending receipts");
            }
        }
    }

    pub fn root(&self) -> Hash32 {
        let mut fields: Vec<Vec<u8>> = Vec::new();
        fields.push(b"BDLM_SETTLEMENT_PROOF_MARKET_STATE_V1".to_vec());
        fields.push(self.total_rewards_paid.to_le_bytes().to_vec());
        fields.push(self.total_tasks_completed.to_le_bytes().to_vec());
        for task in &self.active_tasks {
            fields.push(task.task_id.to_vec());
            fields.push(task.creator.as_bytes().to_vec());
            fields.push(task.reward.to_le_bytes().to_vec());
            fields.push(task.deadline_epoch.to_le_bytes().to_vec());
        }
        for receipt in &self.pending_receipts {
            fields.push(receipt.task_id.to_vec());
            fields.push(receipt.prover.as_bytes().to_vec());
            fields.push(receipt.verification_hash.to_vec());
            fields.push(receipt.reward_claimed.to_le_bytes().to_vec());
        }
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        hash_fields_bytes(&refs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    fn task_kind() -> ProofTaskKind {
        ProofTaskKind::DomainCommitment {
            domain_id: 1,
            domain_height: 100,
            sequence: 0,
        }
    }

    fn assigned_task() -> ProofTask {
        let mut task = ProofTask::new(task_kind(), test_address(1), 10, 100, 5_000);
        task.assign(test_address(2), 15).unwrap();
        task
    }

    #[test]
    fn proof_task_lifecycle() {
        let mut task = ProofTask::new(task_kind(), test_address(1), 10, 100, 5_000);
        assert!(task.is_active());
        assert_eq!(task.status, ProofTaskStatus::Pending);
        task.validate_shape().unwrap();

        task.assign(test_address(2), 15).unwrap();
        assert!(matches!(task.status, ProofTaskStatus::Assigned { .. }));

        task.complete().unwrap();
        assert_eq!(task.status, ProofTaskStatus::Completed);
        assert!(!task.is_active());
    }

    #[test]
    fn proof_task_rejects_invalid_kind_and_zero_creator() {
        let invalid_kind = ProofTaskKind::DomainCommitment {
            domain_id: 0,
            domain_height: 100,
            sequence: 0,
        };
        let task = ProofTask::new(invalid_kind, test_address(1), 10, 100, 5_000);
        assert!(task.validate_shape().unwrap_err().contains("domain_id"));

        let task = ProofTask::new(task_kind(), Address::zero(), 10, 100, 5_000);
        assert!(task.validate_shape().unwrap_err().contains("creator"));
    }

    #[test]
    fn proof_task_rejects_bad_deadline_reward_and_id() {
        let task = ProofTask::new(task_kind(), test_address(1), 10, 10, 5_000);
        assert!(task.validate_shape().unwrap_err().contains("deadline"));

        let task = ProofTask::new(task_kind(), test_address(1), 10, 100, 0);
        assert!(task.validate_shape().unwrap_err().contains("reward"));

        let mut task = ProofTask::new(task_kind(), test_address(1), 10, 100, 5_000);
        task.task_id = [9u8; 32];
        assert!(task.validate_shape().unwrap_err().contains("mismatch"));
    }

    #[test]
    fn proof_task_assignment_guards() {
        let mut task = ProofTask::new(task_kind(), test_address(1), 10, 100, 5_000);
        assert!(task
            .assign(Address::zero(), 15)
            .unwrap_err()
            .contains("prover"));
        assert!(task
            .assign(test_address(2), 9)
            .unwrap_err()
            .contains("created_epoch"));
        assert!(task
            .assign(test_address(2), 101)
            .unwrap_err()
            .contains("expired"));
    }

    #[test]
    fn proof_receipt_lifecycle() {
        let mut receipt = ProofReceipt::new([1u8; 32], test_address(2), 20, [3u8; 32], 5_000);
        assert!(receipt.is_payable());
        receipt.mark_paid().unwrap();
        assert!(!receipt.is_payable());
    }

    #[test]
    fn proof_receipt_validates_against_assigned_task() {
        let task = assigned_task();
        let receipt = ProofReceipt::new(task.task_id, test_address(2), 20, [3u8; 32], 5_000);
        receipt.validate_for_task(&task).unwrap();

        let wrong_prover = ProofReceipt::new(task.task_id, test_address(9), 20, [3u8; 32], 5_000);
        assert!(wrong_prover
            .validate_for_task(&task)
            .unwrap_err()
            .contains("prover"));

        let over_reward = ProofReceipt::new(task.task_id, test_address(2), 20, [3u8; 32], 5_001);
        assert!(over_reward
            .validate_for_task(&task)
            .unwrap_err()
            .contains("reward"));

        let zero_hash = ProofReceipt::new(task.task_id, test_address(2), 20, [0u8; 32], 5_000);
        assert!(zero_hash
            .validate_for_task(&task)
            .unwrap_err()
            .contains("verification_hash"));
    }

    #[test]
    fn proof_receipt_cannot_revoke_twice_or_with_empty_reason() {
        let mut receipt = ProofReceipt::new([1u8; 32], test_address(2), 20, [3u8; 32], 5_000);
        assert!(receipt.revoke(String::new()).is_err());
        receipt.revoke("bad proof".to_string()).unwrap();
        assert!(receipt.revoke("again".to_string()).is_err());
    }

    #[test]
    fn proof_market_state_workflow() {
        let mut market = ProofMarketState::new();
        let mut task = ProofTask::new(
            ProofTaskKind::StorageAttestation {
                deal_id: [4u8; 32],
                challenge_epoch: 10,
            },
            test_address(1),
            1,
            100,
            3_000,
        );
        let task_id = task.task_id;
        task.assign(test_address(2), 15).unwrap();
        market.add_task(task).unwrap();
        assert_eq!(market.active_tasks.len(), 1);

        let receipt = ProofReceipt::new(task_id, test_address(2), 20, [5u8; 32], 3_000);
        let root_before = market.root();
        market.complete_task(task_id, receipt).unwrap();
        assert_eq!(market.active_tasks.len(), 0);
        assert_eq!(market.pending_receipts.len(), 1);
        assert_eq!(market.total_tasks_completed, 1);
        assert_ne!(root_before, market.root());

        let reward = market.pay_receipt(0).unwrap();
        assert_eq!(reward, 3_000);
        assert_eq!(market.total_rewards_paid, 3_000);
    }

    #[test]
    fn complete_task_does_not_drop_task_on_invalid_receipt() {
        let mut market = ProofMarketState::new();
        let mut task = ProofTask::new(task_kind(), test_address(1), 1, 100, 1_000);
        let task_id = task.task_id;
        task.assign(test_address(2), 10).unwrap();
        market.add_task(task).unwrap();
        let bad_receipt = ProofReceipt::new(task_id, test_address(9), 20, [5u8; 32], 1_000);
        assert!(market.complete_task(task_id, bad_receipt).is_err());
        assert_eq!(market.active_tasks.len(), 1);
        assert!(market.pending_receipts.is_empty());
    }

    #[test]
    fn proof_market_prune_expired() {
        let mut market = ProofMarketState::new();
        let mut t1 = ProofTask::new(task_kind(), test_address(1), 1, 5, 100);
        let mut t2 = ProofTask::new(
            ProofTaskKind::DomainCommitment {
                domain_id: 2,
                domain_height: 20,
                sequence: 1,
            },
            test_address(1),
            1,
            100,
            100,
        );
        t1.assign(test_address(2), 2).unwrap();
        t2.assign(test_address(3), 2).unwrap();
        market.add_task(t1).unwrap();
        market.add_task(t2).unwrap();

        let pruned = market.prune_expired(6);
        assert_eq!(pruned, 1);
        assert_eq!(market.active_tasks.len(), 1);
    }

    #[test]
    fn default_difficulty_per_kind() {
        let kinds = vec![
            ProofTaskKind::DomainCommitment {
                domain_id: 1,
                domain_height: 1,
                sequence: 0,
            },
            ProofTaskKind::ZkProof {
                circuit_id: [7u8; 32],
                public_inputs_hash: [8u8; 32],
            },
            ProofTaskKind::SyncCommitteeSig {
                domain_id: 1,
                epoch: 1,
            },
            ProofTaskKind::StorageAttestation {
                deal_id: [9u8; 32],
                challenge_epoch: 1,
            },
        ];
        let tasks: Vec<_> = kinds
            .into_iter()
            .map(|k| ProofTask::new(k, test_address(1), 1, 100, 1_000))
            .collect();
        assert!(tasks[0].difficulty < tasks[1].difficulty); // ZK > DC
        assert!(tasks[1].difficulty > tasks[2].difficulty); // ZK > SC
        assert!(tasks[2].difficulty < tasks[3].difficulty); // SA > SC
    }
}
