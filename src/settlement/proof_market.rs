//! P12-11: Proof Verification Market — ProofTask + ProofReceipt modelleri.
//!
//! Proof Verification Market, Budlum'un çoklu-consensus mimarisinde
//! proof doğrulama işlemlerini ekonomik bir pazara dönüştürür. Prover'lar
//! proof görevlerini üstlenir ve doğrulama karşılığında ödüllendirilir.
//!
//! # Model
//!
//! ```text
//! ProofTask → (prover submits proof) → ProofReceipt → settlement verification
//! ```
//!
//! ProofTask: Doğrulanması gereken bir kanıt görevi (domain commitment,
//! event verification, zk-proof doğrulama).
//!
//! ProofReceipt: Prover'ın bir görevi başarıyla tamamladığını kanıtlayan
//! makbuz. Settlement layer'da doğrulanır ve ödül dağıtılır.
//!
//! Not: LUM (proof market token) entegrasyonu henüz yapılmamıştır.
//! ProofReceipt'ler şu an $BUD cinsinden ödüllendirilir.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::domain::{DomainId, Hash32};
use serde::{Deserialize, Serialize};

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
    SyncCommitteeSig {
        domain_id: DomainId,
        epoch: u64,
    },
    /// Storage attestation doğrulama.
    StorageAttestation {
        deal_id: [u8; 32],
        challenge_epoch: u64,
    },
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
    Failed {
        reason: String,
    },
}

/// Proof görevi — prover'ların üstlenebileceği bir doğrulama görevi.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofTask {
    /// Görev ID (deterministik: hash(task_kind + creator + created_epoch)).
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
        let task_id = Self::compute_task_id(&kind, &creator, created_epoch);
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
    ) -> [u8; 32] {
        let kind_bytes = serde_json::to_vec(kind).unwrap_or_default();
        hash_fields_bytes(&[
            &kind_bytes,
            creator.as_bytes(),
            &created_epoch.to_le_bytes(),
        ])
    }

    /// Görev türüne göre varsayılan zorluk.
    fn default_difficulty(kind: &ProofTaskKind) -> u64 {
        match kind {
            ProofTaskKind::DomainCommitment { .. } => 1_000_000, // FIXED_POINT_SCALE = 1x
            ProofTaskKind::ZkProof { .. } => 10_000_000,        // 10x
            ProofTaskKind::SyncCommitteeSig { .. } => 2_000_000, // 2x
            ProofTaskKind::StorageAttestation { .. } => 3_000_000, // 3x
        }
    }

    /// Görevi bir prover'a atar.
    pub fn assign(&mut self, prover: Address, current_epoch: u64) -> Result<(), String> {
        if self.status != ProofTaskStatus::Pending {
            return Err(format!(
                "Task {:?} is not pending (status: {:?})",
                &self.task_id[..4],
                self.status
            ));
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
            other => Err(format!("Cannot complete task in state {:?}", other)),
        }
    }

    /// Görevi süresi dolmuş olarak işaretler.
    pub fn expire(&mut self) {
        self.status = ProofTaskStatus::Expired;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    Revoked {
        reason: String,
    },
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

    /// V208 (ARENAS): Check if receipt has been paid (for pruning).
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
    pub fn add_task(&mut self, task: ProofTask) {
        if task.is_active() {
            self.active_tasks.push(task);
        }
    }

    /// Görev tamamlandığında makbuz üretir ve görevi kaldırır.
    pub fn complete_task(&mut self, task_id: [u8; 32], receipt: ProofReceipt) -> Result<(), String> {
        let idx = self
            .active_tasks
            .iter()
            .position(|t| t.task_id == task_id)
            .ok_or("Task not found in active tasks")?;

        let mut task = self.active_tasks.remove(idx);
        task.complete()?;
        self.pending_receipts.push(receipt);
        self.total_tasks_completed = self
            .total_tasks_completed
            .checked_add(1)
            .unwrap_or(u64::MAX);

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
            .unwrap_or(u64::MAX);

        Ok(reward)
    }

    /// Süresi dolmuş görevleri temizler.
    pub fn prune_expired(&mut self, current_epoch: u64) -> usize {
        let before = self.active_tasks.len();
        self.active_tasks.retain(|t| t.deadline_epoch >= current_epoch || !t.is_active());
        before - self.active_tasks.len()
    }

    /// V208 (ARENAS): Prune paid receipts from pending_receipts Vec.
    /// Without this, the Vec grows indefinitely — paid receipts are never
    /// removed, only marked as paid. Call this periodically after pay_receipt.
    pub fn prune_paid_receipts(&mut self) -> usize {
        let before = self.pending_receipts.len();
        self.pending_receipts.retain(|r| !r.is_paid());
        before - self.pending_receipts.len()
    }

    /// V208: Cap active_tasks + pending_receipts to prevent unbounded memory
    /// growth on long-running nodes.
    pub fn enforce_max_sizes(&mut self) {
        const MAX_ACTIVE_TASKS: usize = 10_000;
        const MAX_PENDING_RECEIPTS: usize = 10_000;

        if self.active_tasks.len() > MAX_ACTIVE_TASKS {
            let to_remove = self.active_tasks.len() - MAX_ACTIVE_TASKS;
            self.active_tasks.drain(0..to_remove);
            tracing::warn!("V208: Pruned {} expired active tasks", to_remove);
        }
        if self.pending_receipts.len() > MAX_PENDING_RECEIPTS {
            // Remove paid receipts first, then oldest
            self.prune_paid_receipts();
            if self.pending_receipts.len() > MAX_PENDING_RECEIPTS {
                let to_remove = self.pending_receipts.len() - MAX_PENDING_RECEIPTS;
                self.pending_receipts.drain(0..to_remove);
                tracing::warn!("V208: Pruned {} oldest pending receipts", to_remove);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    #[test]
    fn proof_task_lifecycle() {
        let kind = ProofTaskKind::DomainCommitment {
            domain_id: 1,
            domain_height: 100,
            sequence: 0,
        };
        let mut task = ProofTask::new(kind, test_address(1), 10, 100, 5000);
        assert!(task.is_active());
        assert_eq!(task.status, ProofTaskStatus::Pending);

        // Atama
        task.assign(test_address(2), 15).unwrap();
        assert!(matches!(task.status, ProofTaskStatus::Assigned { .. }));

        // Tamamlama
        task.complete().unwrap();
        assert_eq!(task.status, ProofTaskStatus::Completed);
        assert!(!task.is_active());
    }

    #[test]
    fn proof_task_cannot_complete_unassigned() {
        let kind = ProofTaskKind::SyncCommitteeSig {
            domain_id: 0,
            epoch: 5,
        };
        let mut task = ProofTask::new(kind, test_address(1), 10, 100, 1000);
        assert!(task.complete().is_err());
    }

    #[test]
    fn proof_task_deterministic_id() {
        let kind = ProofTaskKind::ZkProof {
            circuit_id: [7u8; 32],
            public_inputs_hash: [8u8; 32],
        };
        let t1 = ProofTask::new(kind.clone(), test_address(1), 10, 100, 1000);
        let t2 = ProofTask::new(kind, test_address(1), 10, 100, 1000);
        assert_eq!(t1.task_id, t2.task_id);
    }

    #[test]
    fn proof_receipt_lifecycle() {
        let mut receipt = ProofReceipt::new(
            [1u8; 32],
            test_address(2),
            20,
            [3u8; 32],
            5000,
        );
        assert!(receipt.is_payable());

        receipt.mark_paid().unwrap();
        assert!(!receipt.is_payable());
    }

    #[test]
    fn proof_receipt_cannot_revoke_twice() {
        let mut receipt = ProofReceipt::new(
            [1u8; 32],
            test_address(2),
            20,
            [3u8; 32],
            5000,
        );
        receipt.revoke("bad proof".to_string()).unwrap();
        assert!(receipt.revoke("again".to_string()).is_err());
    }

    #[test]
    fn proof_market_state_workflow() {
        let mut market = ProofMarketState::new();
        let kind = ProofTaskKind::StorageAttestation {
            deal_id: [4u8; 32],
            challenge_epoch: 10,
        };
        let task = ProofTask::new(kind, test_address(1), 1, 100, 3000);
        let task_id = task.task_id;
        market.add_task(task);
        assert_eq!(market.active_tasks.len(), 1);

        let receipt = ProofReceipt::new(task_id, test_address(2), 15, [5u8; 32], 3000);
        market.complete_task(task_id, receipt).unwrap();
        assert_eq!(market.active_tasks.len(), 0);
        assert_eq!(market.pending_receipts.len(), 1);
        assert_eq!(market.total_tasks_completed, 1);

        let reward = market.pay_receipt(0).unwrap();
        assert_eq!(reward, 3000);
        assert_eq!(market.total_rewards_paid, 3000);
    }

    #[test]
    fn proof_market_prune_expired() {
        let mut market = ProofMarketState::new();
        let kind1 = ProofTaskKind::DomainCommitment {
            domain_id: 0,
            domain_height: 10,
            sequence: 0,
        };
        let kind2 = ProofTaskKind::DomainCommitment {
            domain_id: 1,
            domain_height: 20,
            sequence: 1,
        };
        let mut t1 = ProofTask::new(kind1, test_address(1), 1, 5, 100);
        let mut t2 = ProofTask::new(kind2, test_address(1), 1, 100, 100);
        // Assign both so they're active
        t1.assign(test_address(2), 2).unwrap();
        t2.assign(test_address(3), 2).unwrap();
        market.add_task(t1);
        market.add_task(t2);

        // At epoch 6, t1 is expired (deadline 5)
        let pruned = market.prune_expired(6);
        assert_eq!(pruned, 1);
        assert_eq!(market.active_tasks.len(), 1);
    }

    #[test]
    fn default_difficulty_per_kind() {
        let kinds = vec![
            ProofTaskKind::DomainCommitment { domain_id: 0, domain_height: 1, sequence: 0 },
            ProofTaskKind::ZkProof { circuit_id: [0u8; 32], public_inputs_hash: [0u8; 32] },
            ProofTaskKind::SyncCommitteeSig { domain_id: 0, epoch: 1 },
            ProofTaskKind::StorageAttestation { deal_id: [0u8; 32], challenge_epoch: 1 },
        ];
        let tasks: Vec<_> = kinds
            .into_iter()
            .map(|k| ProofTask::new(k, test_address(1), 1, 100, 1000))
            .collect();
        assert!(tasks[0].difficulty < tasks[1].difficulty); // ZK > DC
        assert!(tasks[1].difficulty > tasks[2].difficulty); // ZK > SC
        assert!(tasks[2].difficulty < tasks[3].difficulty); // SA > SC
    }
}
