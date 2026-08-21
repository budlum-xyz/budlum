//! P12-11: Proof Verification Market - settlement-side proof task/receipt model.
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

/// Furthest a task's deadline may sit beyond the epoch that created it.
///
/// A deadline needs a ceiling and not only a floor. `deadline_epoch` arrives
/// on a submitted task, and requiring it merely to exceed `created_epoch`
/// admits `u64::MAX`: a task that never expires, so `prune_expired` keeps it
/// at every epoch and it holds one of the ten thousand slots forever.
///
/// The bound is a span rather than an absolute epoch so it stays correct as
/// the chain advances.
pub const MAX_PROOF_TASK_EPOCH_SPAN: u64 = 10_000;

fn nonzero_hash(value: &Hash32) -> bool {
    *value != [0u8; 32]
}

/// Proof görev türü.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofTaskKind {
    /// Domain commitment doğrulama - Merkle proof + event verification.
    DomainCommitment {
        domain_id: DomainId,
        domain_height: u64,
        sequence: u64,
    },
    /// ZK-proof doğrulama - STARK/SNARK verifier.
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
    /// Beklemede - prover atanmamış.
    Pending,
    /// Prover atanmış - çalışıyor.
    Assigned {
        prover: Address,
        assigned_at_epoch: u64,
    },
    /// Tamamlanmış - proof doğrulanmış.
    Completed,
    /// Süresi dolmuş.
    Expired,
    /// Başarısız - proof geçersiz.
    Failed { reason: String },
}

impl ProofTaskStatus {
    /// Root commitment için durum baytları (Strix HIGH CWE-345, 2026-08-17):
    /// `assign` sahipliği ve zamanlamayı `status` alanında değiştirir; root
    /// status'u atlarsa farklı assignment durumları aynı kökü üretir.
    pub fn root_bytes(&self) -> Vec<u8> {
        match self {
            Self::Pending => vec![0],
            Self::Assigned {
                prover,
                assigned_at_epoch,
            } => {
                let mut v = vec![1];
                v.extend_from_slice(prover.as_bytes());
                v.extend_from_slice(&assigned_at_epoch.to_le_bytes());
                v
            }
            Self::Completed => vec![2],
            Self::Expired => vec![3],
            Self::Failed { reason } => {
                let mut v = vec![4];
                v.extend_from_slice(reason.as_bytes());
                v
            }
        }
    }
}

/// Proof görevi - prover'ların üstlenebileceği bir doğrulama görevi.
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
    ///
    /// IDENTITY: excluded - the status moves through the task's life
    /// (`Pending` to `Assigned` to `Completed`), and the id has to survive
    /// that: `complete_task` finds the task by `task_id` after `assign`
    /// already changed the status. Hashing it would give the same task a
    /// different id at every transition and no lookup would ever match.
    pub status: ProofTaskStatus,
    /// Ödül miktarı (u64 BUD birimi, 6 ondalık).
    pub reward: u64,
    /// Zorluk seviyesi (prover stake gereksinimi oranı, fixed-point).
    ///
    /// IDENTITY: excluded - `default_difficulty` derives it from `kind`,
    /// which the id does cover, so the same kind always yields the same
    /// value and there is nothing independent to bind. The field exists to
    /// be read, not to be chosen: `ProofTask::new` is the only constructor
    /// and it never takes a caller-supplied difficulty.
    ///
    /// This stops being true the moment anything writes to it. A per-task
    /// difficulty override would be an unbound claim under a stable id, and
    /// it would have to go into the preimage, which means a new task tag.
    pub difficulty: u64,
    /// What the assigned prover forfeits by answering wrongly, as a hash of
    /// the condition rather than the condition itself.
    ///
    /// Carried over from the deleted `prover::market` twin, which had it and
    /// this model did not. Without it a task says what it pays and never what
    /// it costs to get wrong, so the only penalty for a bad proof is not
    /// being paid, and a prover that answers everything at random loses
    /// nothing it had.
    ///
    /// Zero means no slash condition was named, which `validate_shape`
    /// refuses: a task nobody can be punished for failing is a request, not a
    /// market position.
    pub slash_condition_hash: Hash32,
    /// The bond a prover must already hold before this task may be assigned
    /// to it, in the same unit as `reward`.
    ///
    /// Also from the deleted twin. It is the other half of the slash
    /// condition: naming what is forfeited is empty unless something was
    /// staked to forfeit. Zero is allowed and means the task is open to any
    /// prover, which is the right default for cheap tasks and the wrong one
    /// for expensive ones, so `assign` reads it rather than assuming.
    pub min_prover_stake: u64,
}

impl ProofTask {
    /// Yeni bir proof görevi oluşturur.
    ///
    /// `slash_condition_hash` names what the prover forfeits by answering
    /// wrongly and `min_prover_stake` is the bond it must already hold. Both
    /// go into the task id: a task whose penalty could be edited after the id
    /// was published would let a creator advertise one risk and settle
    /// against another.
    pub fn new(
        kind: ProofTaskKind,
        creator: Address,
        created_epoch: u64,
        deadline_epoch: u64,
        reward: u64,
        slash_condition_hash: Hash32,
        min_prover_stake: u64,
    ) -> Self {
        let task_id = Self::compute_task_id(
            &kind,
            &creator,
            created_epoch,
            deadline_epoch,
            reward,
            &slash_condition_hash,
            min_prover_stake,
        );
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
            slash_condition_hash,
            min_prover_stake,
        }
    }

    /// Deterministik görev ID hesaplar.
    fn compute_task_id(
        kind: &ProofTaskKind,
        creator: &Address,
        created_epoch: u64,
        deadline_epoch: u64,
        reward: u64,
        slash_condition_hash: &Hash32,
        min_prover_stake: u64,
    ) -> [u8; 32] {
        let kind_bytes = kind.canonical_bytes();
        hash_fields_bytes(&[
            b"BDLM_SETTLEMENT_PROOF_TASK_V2",
            &kind_bytes,
            creator.as_bytes(),
            &created_epoch.to_le_bytes(),
            &deadline_epoch.to_le_bytes(),
            &reward.to_le_bytes(),
            slash_condition_hash,
            &min_prover_stake.to_le_bytes(),
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
                &self.slash_condition_hash,
                self.min_prover_stake,
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
        // A deadline also needs a ceiling, not only a floor. Without one a
        // task may declare `deadline_epoch = u64::MAX`, which never expires:
        // `prune_expired` keeps it at every epoch, so it occupies a slot in a
        // queue capped at MAX_PROOF_MARKET_ACTIVE_TASKS forever, and ten
        // thousand of them fill the market permanently.
        let span = self.deadline_epoch.saturating_sub(self.created_epoch);
        if span > MAX_PROOF_TASK_EPOCH_SPAN {
            return Err(format!(
                "ProofTask deadline_epoch is {span} epochs after created_epoch, \
                 the maximum is {MAX_PROOF_TASK_EPOCH_SPAN}"
            ));
        }
        if self.reward == 0 {
            return Err("ProofTask reward must be >= 1".into());
        }
        if !nonzero_hash(&self.slash_condition_hash) {
            return Err(
                "ProofTask slash_condition_hash cannot be zero: a task nobody can be \
                 punished for failing pays for a wrong answer as readily as a right one"
                    .into(),
            );
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
    ///
    /// `prover_stake` is the bond that prover already holds. The task states
    /// a `min_prover_stake` and it is read here, because assignment is the
    /// only moment the requirement can still be enforced: once a prover is
    /// assigned, the slash condition names something it may not have.
    ///
    /// A caller that genuinely does not gate on stake passes `u64::MAX`, which
    /// is a visible decision at the call site rather than a silent one here.
    pub fn assign(
        &mut self,
        prover: Address,
        prover_stake: u64,
        current_epoch: u64,
    ) -> Result<(), String> {
        self.validate_shape()?;
        if prover == Address::zero() {
            return Err("ProofTask prover cannot be zero".into());
        }
        if prover_stake < self.min_prover_stake {
            return Err(format!(
                "prover holds {} and this task requires {} before assignment: the \
                 slash condition is worth nothing against a prover with nothing staked",
                prover_stake, self.min_prover_stake
            ));
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

/// Proof makbuzu - prover'ın bir görevi başarıyla tamamladığını kanıtlar.
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
    /// Ödenmemiş - settlement onayı bekliyor.
    Pending,
    /// Ödenmiş - ödül prover'a dağıtıldı.
    Paid,
    /// İptal - proof geçersiz bulundu.
    Revoked { reason: String },
}

impl ReceiptStatus {
    /// Root commitment baytları (Strix HIGH CWE-345, 2026-08-17): farkli
    /// odeme-uygunluk durumlari ayni settlement kökünü paylasmamali.
    pub fn root_bytes(&self) -> Vec<u8> {
        match self {
            Self::Pending => vec![0],
            Self::Paid => vec![1],
            Self::Revoked { reason } => {
                let mut v = vec![2];
                v.extend_from_slice(reason.as_bytes());
                v
            }
        }
    }
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

    /// Nothing has ever been recorded here.
    ///
    /// Read by the state root, which keeps an empty market out of the hash so
    /// existing chains do not see a root change for a feature they never used.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.active_tasks.is_empty()
            && self.pending_receipts.is_empty()
            && self.total_rewards_paid == 0
            && self.total_tasks_completed == 0
    }

    /// Close out an epoch: expire what ran out of time, drop what has been
    /// paid, and hold the whole thing under its memory ceiling.
    ///
    /// The three steps existed and none of them ran. `prune_expired` removes
    /// tasks past their deadline, `prune_paid_receipts` removes receipts that
    /// have been paid, and `enforce_max_sizes` is the only thing standing
    /// between a long-running node and an `active_tasks` vector that only
    /// grows. `add_task` bounds what arrives in one call; it says nothing
    /// about accumulation, which is the failure that actually happens.
    ///
    /// Returns `(expired, receipts_pruned)` so the caller can log the work
    /// rather than guess at it.
    pub fn close_epoch(&mut self, current_epoch: u64) -> (usize, usize) {
        // Order matters. Expiring first turns deadline-passed tasks into
        // removable ones, so the ceiling below has less in-progress work it
        // has to refuse to drop.
        let expired = self.prune_expired(current_epoch);
        let receipts_pruned = self.prune_paid_receipts();
        self.enforce_max_sizes(current_epoch);
        (expired, receipts_pruned)
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
        verify_proof: impl FnOnce(&ProofReceipt) -> Result<(), String>,
    ) -> Result<(), String> {
        let idx = self
            .active_tasks
            .iter()
            .position(|t| t.task_id == task_id)
            .ok_or("Task not found in active tasks")?;

        receipt.validate_for_task(&self.active_tasks[idx])?;
        // Strix HIGH (CWE-345, 2026-08-17): makbuz yalniz metadata + non-zero
        // hash tasir; gercek proof dogrulamasi olmadan pending_receipts'e
        // girmemeli. Dogrulama cagiranin sagladigi hook ile yapilir; market
        // dogrulamasiz receipt'i kabul etmez, odenmez.
        verify_proof(&receipt)?;

        // Every refusal is decided while the task is still in `active_tasks`.
        //
        // This used to remove the task first. The receipt-limit check and the
        // completion counter both sit after it, so a full receipt queue or a
        // saturated counter returned `Err` with the task already gone: not
        // active, not completed, and no receipt recorded. The prover's work
        // vanished through a path that reported failure, and nothing rolls
        // back, since `apply_block_checked` propagates with `?`.
        if self.pending_receipts.len() >= MAX_PROOF_MARKET_PENDING_RECEIPTS {
            return Err("ProofMarketState pending receipt limit exceeded".into());
        }
        let total_tasks_completed = self
            .total_tasks_completed
            .checked_add(1)
            .ok_or_else(|| "ProofMarketState total_tasks_completed overflow".to_string())?;
        // `complete` is the last thing that can refuse, and it needs the task
        // by value. Take a copy, ask it, and only commit the removal once it
        // has agreed.
        let mut task = self.active_tasks[idx].clone();
        task.complete()?;

        // Past every refusal: nothing below this line can fail.
        self.active_tasks.remove(idx);
        self.pending_receipts.push(receipt);
        self.total_tasks_completed = total_tasks_completed;
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
    /// Without this, the Vec grows indefinitely, paid receipts are never
    /// Removed, only marked as paid. Call this periodically after pay_receipt.
    pub fn prune_paid_receipts(&mut self) -> usize {
        let before = self.pending_receipts.len();
        self.pending_receipts.retain(|r| !r.is_paid());
        before - self.pending_receipts.len()
    }

    /// Cap active_tasks + pending_receipts to prevent unbounded memory
    /// Growth on long-running nodes.
    /// Only prune expired/expired tasks - never drop
    /// In-progress tasks that still have time remaining.
    /// `current_epoch` is the chain's epoch. It used to be derived from the
    /// tasks themselves, as `max(deadline_epoch) - 1000`, which made the
    /// retention window a function of attacker-supplied data: `deadline_epoch`
    /// is a field on a submitted task and `validate_shape` only required it to
    /// exceed `created_epoch`. One task carrying `u64::MAX` moved the window to
    /// `u64::MAX - 1000`, and every honest task in the queue then failed the
    /// retain and was dropped in a single call.
    ///
    /// That inverted the guarantee in the sentence above: the function exists
    /// to protect in-progress work from a memory cap, and the cheapest way to
    /// destroy in-progress work was to trigger it. Measured at the boundary it
    /// fires on, 10,001 live tasks plus one claiming `u64::MAX`: the old window
    /// keeps 1 of 10,002, the corrected window keeps all 10,002.
    ///
    /// `prune_expired` already took `current_epoch` and compared against it, so
    /// the two pruning paths disagreed about what expired meant.
    pub fn enforce_max_sizes(&mut self, current_epoch: u64) {
        if self.active_tasks.len() > MAX_PROOF_MARKET_ACTIVE_TASKS {
            // Expiry is measured against the chain, never against a value a
            // submitter chose.
            let before = self.active_tasks.len();
            self.active_tasks
                .retain(|t| t.deadline_epoch >= current_epoch);
            let pruned_expired = before - self.active_tasks.len();
            if pruned_expired > 0 {
                tracing::info!("Pruned {pruned_expired} expired tasks by deadline");
            }
            // If still over cap after expiry pruning, fail-closed: log critical warning
            // But do NOT drop in-progress tasks (they represent real prover work).
            if self.active_tasks.len() > MAX_PROOF_MARKET_ACTIVE_TASKS {
                tracing::error!(
                    "active_tasks ({}) still over cap ({}) after expiry pruning - \
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
            // The penalty side of the task, alongside the payment side. A
            // root that commits to what a task pays and not to what it costs
            // to fail would let the two be disagreed about after the fact.
            fields.push(task.slash_condition_hash.to_vec());
            fields.push(task.min_prover_stake.to_le_bytes().to_vec());
            fields.push(task.status.root_bytes());
        }
        for receipt in &self.pending_receipts {
            fields.push(receipt.task_id.to_vec());
            fields.push(receipt.prover.as_bytes().to_vec());
            fields.push(receipt.verification_hash.to_vec());
            fields.push(receipt.reward_claimed.to_le_bytes().to_vec());
            fields.push(receipt.status.root_bytes());
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

    /// A slash condition the task can be punished against.
    ///
    /// Non-zero on purpose: `validate_shape` refuses a zero one, because a
    /// task nobody can be punished for failing pays for a wrong answer as
    /// readily as a right one.
    fn slash_condition() -> Hash32 {
        [0xC0; 32]
    }

    /// `ProofTask::new` with the penalty fields defaulted, for the tests that
    /// are about something else. Stake gate open (`0`) so those tests keep
    /// measuring what they were written to measure.
    fn task_with(
        kind: ProofTaskKind,
        creator: Address,
        created_epoch: u64,
        deadline_epoch: u64,
        reward: u64,
    ) -> ProofTask {
        ProofTask::new(
            kind,
            creator,
            created_epoch,
            deadline_epoch,
            reward,
            slash_condition(),
            0,
        )
    }

    fn task_kind() -> ProofTaskKind {
        ProofTaskKind::DomainCommitment {
            domain_id: 1,
            domain_height: 100,
            sequence: 0,
        }
    }

    fn assigned_task() -> ProofTask {
        let mut task = task_with(task_kind(), test_address(1), 10, 100, 5_000);
        task.assign(test_address(2), 0, 15).unwrap();
        task
    }

    #[test]
    fn proof_task_lifecycle() {
        let mut task = task_with(task_kind(), test_address(1), 10, 100, 5_000);
        assert!(task.is_active());
        assert_eq!(task.status, ProofTaskStatus::Pending);
        task.validate_shape().unwrap();

        task.assign(test_address(2), 0, 15).unwrap();
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
        let task = task_with(invalid_kind, test_address(1), 10, 100, 5_000);
        assert!(task.validate_shape().unwrap_err().contains("domain_id"));

        let task = task_with(task_kind(), Address::zero(), 10, 100, 5_000);
        assert!(task.validate_shape().unwrap_err().contains("creator"));
    }

    #[test]
    fn proof_task_rejects_bad_deadline_reward_and_id() {
        let task = task_with(task_kind(), test_address(1), 10, 10, 5_000);
        assert!(task.validate_shape().unwrap_err().contains("deadline"));

        let task = task_with(task_kind(), test_address(1), 10, 100, 0);
        assert!(task.validate_shape().unwrap_err().contains("reward"));

        let mut task = task_with(task_kind(), test_address(1), 10, 100, 5_000);
        task.task_id = [9u8; 32];
        assert!(task.validate_shape().unwrap_err().contains("mismatch"));
    }

    #[test]
    fn proof_task_assignment_guards() {
        let mut task = task_with(task_kind(), test_address(1), 10, 100, 5_000);
        assert!(task
            .assign(Address::zero(), 0, 15)
            .unwrap_err()
            .contains("prover"));
        assert!(task
            .assign(test_address(2), 0, 9)
            .unwrap_err()
            .contains("created_epoch"));
        assert!(task
            .assign(test_address(2), 0, 101)
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
        let mut task = task_with(
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
        task.assign(test_address(2), 0, 15).unwrap();
        market.add_task(task).unwrap();
        assert_eq!(market.active_tasks.len(), 1);

        let receipt = ProofReceipt::new(task_id, test_address(2), 20, [5u8; 32], 3_000);
        let root_before = market.root();
        market
            .complete_task(task_id, receipt, |r| {
                if r.verification_hash == [5u8; 32] {
                    Ok(())
                } else {
                    Err("proof verification failed: unexpected hash".into())
                }
            })
            .unwrap();
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
        let mut task = task_with(task_kind(), test_address(1), 1, 100, 1_000);
        let task_id = task.task_id;
        task.assign(test_address(2), 0, 10).unwrap();
        market.add_task(task).unwrap();
        let bad_receipt = ProofReceipt::new(task_id, test_address(9), 20, [5u8; 32], 1_000);
        assert!(market
            .complete_task(task_id, bad_receipt, |_| Ok(()))
            .is_err());
        assert_eq!(market.active_tasks.len(), 1);
        assert!(market.pending_receipts.is_empty());
    }

    #[test]
    fn proof_market_prune_expired() {
        let mut market = ProofMarketState::new();
        let mut t1 = task_with(task_kind(), test_address(1), 1, 5, 100);
        let mut t2 = task_with(
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
        t1.assign(test_address(2), 0, 2).unwrap();
        t2.assign(test_address(3), 0, 2).unwrap();
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
            .map(|k| task_with(k, test_address(1), 1, 100, 1_000))
            .collect();
        assert!(tasks[0].difficulty < tasks[1].difficulty); // ZK > DC
        assert!(tasks[1].difficulty > tasks[2].difficulty); // ZK > SC
        assert!(tasks[2].difficulty < tasks[3].difficulty); // SA > SC
    }

    /// A task that names no penalty must not be shaped like a valid one.
    ///
    /// The deleted `prover::market` twin bound a `slash_condition_hash` into
    /// its task id and this model had no such field at all, so a settlement
    /// task stated what it paid and never what it cost to get wrong. The only
    /// consequence of a bad proof was not being paid, which a prover that
    /// answers at random is entirely willing to accept.
    #[test]
    fn a_task_with_no_slash_condition_is_refused() {
        let task = ProofTask::new(task_kind(), test_address(1), 10, 100, 5_000, [0u8; 32], 0);
        let err = task
            .validate_shape()
            .expect_err("a task nobody can be punished for failing must not validate");
        assert!(
            err.contains("slash_condition_hash"),
            "the refusal must name the missing penalty, got: {err}"
        );

        // And the narrow version still passes, or this is just a ban on tasks.
        task_with(task_kind(), test_address(1), 10, 100, 5_000)
            .validate_shape()
            .expect("a task that names its penalty is valid");
    }

    /// The penalty is part of the task's identity, not an editable annotation.
    ///
    /// If the slash condition sat outside the id, a creator could publish a
    /// task under one risk and settle it under another: same `task_id`, same
    /// lookup, different consequence for the prover that already committed.
    #[test]
    fn the_slash_condition_and_stake_floor_are_bound_into_the_task_id() {
        let base = task_with(task_kind(), test_address(1), 10, 100, 5_000);

        let other_condition =
            ProofTask::new(task_kind(), test_address(1), 10, 100, 5_000, [0xD1; 32], 0);
        assert_ne!(
            base.task_id, other_condition.task_id,
            "changing what the prover forfeits must change the task id"
        );

        let other_stake = ProofTask::new(
            task_kind(),
            test_address(1),
            10,
            100,
            5_000,
            slash_condition(),
            1_000,
        );
        assert_ne!(
            base.task_id, other_stake.task_id,
            "changing the bond a prover must hold must change the task id"
        );

        // Both must survive a round trip through `verify_id`, or the id binds
        // fields the verifier does not re-derive.
        assert!(other_condition.verify_id());
        assert!(other_stake.verify_id());
    }

    /// Assignment reads the stake floor, or the floor is decoration.
    ///
    /// This is the half that makes the slash condition mean anything: naming
    /// what is forfeited is empty unless something was staked to forfeit.
    #[test]
    fn a_prover_below_the_stake_floor_cannot_be_assigned() {
        let mut task = ProofTask::new(
            task_kind(),
            test_address(1),
            10,
            100,
            5_000,
            slash_condition(),
            10_000,
        );

        let err = task
            .assign(test_address(2), 9_999, 15)
            .expect_err("a prover one unit short of the floor must be refused");
        assert!(
            err.contains("10000") && err.contains("9999"),
            "the refusal must state both numbers so the caller can act, got: {err}"
        );
        assert_eq!(
            task.status,
            ProofTaskStatus::Pending,
            "a refused assignment must leave the task assignable"
        );

        task.assign(test_address(2), 10_000, 15)
            .expect("a prover exactly at the floor must be accepted");
        assert!(matches!(task.status, ProofTaskStatus::Assigned { .. }));
    }

    /// The root commits to the penalty side, not only the payment side.
    #[test]
    fn the_market_root_moves_when_the_penalty_changes() {
        let mut lenient = ProofMarketState::new();
        let mut strict = ProofMarketState::new();

        let mut cheap = task_with(task_kind(), test_address(1), 1, 100, 1_000);
        cheap.assign(test_address(2), 0, 10).unwrap();
        let mut dear = ProofTask::new(
            task_kind(),
            test_address(1),
            1,
            100,
            1_000,
            slash_condition(),
            50_000,
        );
        dear.assign(test_address(2), 50_000, 10).unwrap();

        lenient.add_task(cheap).unwrap();
        strict.add_task(dear).unwrap();

        assert_ne!(
            lenient.root(),
            strict.root(),
            "two markets differing only in what a failed prover forfeits must \
             not hash to the same root"
        );
    }

    /// The memory ceiling has to run somewhere, or it is a comment.
    ///
    /// `enforce_max_sizes` is the only bound on accumulation in this module.
    /// `add_task` refuses a task when the vector is already at the cap, which
    /// bounds a single call and says nothing about a node that has been up
    /// for a year. Nothing called `enforce_max_sizes`, nothing called
    /// `prune_expired`, and nothing called `prune_paid_receipts`.
    #[test]
    fn closing_an_epoch_expires_stale_tasks_and_drops_paid_receipts() {
        let mut market = ProofMarketState::new();

        let mut stale = task_with(task_kind(), test_address(1), 1, 5, 100);
        stale.assign(test_address(2), 0, 2).unwrap();
        let mut live = task_with(
            ProofTaskKind::DomainCommitment {
                domain_id: 2,
                domain_height: 20,
                sequence: 1,
            },
            test_address(1),
            1,
            900,
            100,
        );
        live.assign(test_address(3), 0, 2).unwrap();
        market.add_task(stale).unwrap();
        market.add_task(live).unwrap();

        // One receipt, paid, so the prune has something real to remove.
        let live_id = market.active_tasks[1].task_id;
        let receipt = ProofReceipt::new(live_id, test_address(3), 3, [7u8; 32], 100);
        market
            .complete_task(live_id, receipt, |r| {
                if r.verification_hash == [7u8; 32] {
                    Ok(())
                } else {
                    Err("proof verification failed: unexpected hash".into())
                }
            })
            .unwrap();
        market.pay_receipt(0).unwrap();
        assert_eq!(market.pending_receipts.len(), 1);

        let (expired, receipts_pruned) = market.close_epoch(500);

        assert_eq!(expired, 1, "the task whose deadline passed must be expired");
        assert_eq!(
            receipts_pruned, 1,
            "a receipt already paid must not sit in the pending vector forever"
        );
        assert!(
            market.pending_receipts.is_empty(),
            "nothing unpaid remains, so nothing pending should"
        );
    }

    /// Closing an epoch must not throw away work in progress.
    ///
    /// The pruning has to be narrow or it is a way to lose a prover's work:
    /// an assigned task inside its deadline represents someone computing
    /// right now.
    #[test]
    fn closing_an_epoch_keeps_assigned_work_that_still_has_time() {
        let mut market = ProofMarketState::new();
        let mut running = task_with(task_kind(), test_address(1), 1, 900, 100);
        running.assign(test_address(2), 0, 2).unwrap();
        market.add_task(running).unwrap();

        let (expired, _) = market.close_epoch(500);

        assert_eq!(expired, 0, "a task with 400 epochs left has not expired");
        assert_eq!(
            market.active_tasks.len(),
            1,
            "an assigned task inside its deadline is a prover mid-computation \
             and must survive the sweep"
        );
    }

    /// An empty market must stay out of the state root.
    ///
    /// A chain that has never opened a proof task must not see its root move
    /// because this field came into existence.
    #[test]
    fn an_untouched_market_is_empty_and_a_used_one_is_not() {
        let mut market = ProofMarketState::new();
        assert!(market.is_empty(), "a fresh market has recorded nothing");

        let mut task = task_with(task_kind(), test_address(1), 1, 100, 1_000);
        task.assign(test_address(2), 0, 2).unwrap();
        market.add_task(task).unwrap();
        assert!(
            !market.is_empty(),
            "a market holding an assigned task must reach the state root"
        );
    }

    /// A task cannot declare a deadline arbitrarily far in the future.
    ///
    /// `deadline_epoch > created_epoch` was the only check, so `u64::MAX` was
    /// admissible: a task that never expires, holding one of ten thousand
    /// slots forever. Ten thousand such submissions fill the market
    /// permanently.
    #[test]
    fn proof_task_rejects_deadline_beyond_max_span() {
        let task = task_with(task_kind(), test_address(1), 10, u64::MAX, 5_000);
        let err = task
            .validate_shape()
            .expect_err("a task that never expires must be refused");
        assert!(
            err.contains("deadline_epoch"),
            "error should name the offending field, got: {err}"
        );

        // One epoch past the ceiling is refused.
        let over = task_with(
            task_kind(),
            test_address(1),
            10,
            10 + MAX_PROOF_TASK_EPOCH_SPAN + 1,
            5_000,
        );
        assert!(over.validate_shape().is_err());

        // Exactly at the ceiling is allowed: the bound must not move the
        // honest case.
        let at = task_with(
            task_kind(),
            test_address(1),
            10,
            10 + MAX_PROOF_TASK_EPOCH_SPAN,
            5_000,
        );
        at.validate_shape()
            .expect("a deadline exactly at the ceiling is legitimate");
    }

    /// `enforce_max_sizes` measures expiry against the chain, not against the
    /// tasks it is pruning.
    ///
    /// The window used to be `max(deadline_epoch) - 1000`, taken from the
    /// queue itself. One task with a far-future deadline moved the window past
    /// every honest task, so the function whose stated purpose is to protect
    /// in-progress work destroyed all of it in one call. `close_epoch` calls
    /// this on every epoch, so the path is live.
    #[test]
    fn enforce_max_sizes_does_not_drop_live_tasks_for_one_far_deadline() {
        let mut state = ProofMarketState::new();
        let current_epoch = 10_000u64;

        let live = MAX_PROOF_MARKET_ACTIVE_TASKS + 1;
        for i in 0..live {
            let kind = ProofTaskKind::DomainCommitment {
                domain_id: 1,
                domain_height: 100,
                sequence: i as u64,
            };
            state.active_tasks.push(task_with(
                kind,
                test_address(1),
                current_epoch,
                current_epoch + 500,
                5_000,
            ));
        }

        // The lever: one task whose deadline sits far beyond the rest. Pushed
        // directly, because validate_shape now refuses it at the door; the
        // point is that enforce_max_sizes is safe even if one arrives.
        let far_kind = ProofTaskKind::DomainCommitment {
            domain_id: 1,
            domain_height: 100,
            sequence: u64::MAX,
        };
        state.active_tasks.push(task_with(
            far_kind,
            test_address(9),
            current_epoch,
            u64::MAX,
            5_000,
        ));

        state.enforce_max_sizes(current_epoch);

        assert_eq!(
            state.active_tasks.len(),
            live + 1,
            "no live task may be dropped because another task claimed a far deadline"
        );
    }

    /// The canary for the test above: expired tasks must actually be pruned,
    /// or the assertion could pass by the function doing nothing at all.
    #[test]
    fn enforce_max_sizes_still_prunes_genuinely_expired_tasks() {
        let mut state = ProofMarketState::new();
        let current_epoch = 10_000u64;

        for i in 0..(MAX_PROOF_MARKET_ACTIVE_TASKS + 50) {
            let kind = ProofTaskKind::DomainCommitment {
                domain_id: 1,
                domain_height: 100,
                sequence: i as u64,
            };
            state.active_tasks.push(task_with(
                kind,
                test_address(1),
                1,
                current_epoch - 1,
                5_000,
            ));
        }

        let before = state.active_tasks.len();
        state.enforce_max_sizes(current_epoch);
        assert_eq!(
            state.active_tasks.len(),
            0,
            "expired tasks must be pruned, otherwise the sibling test is vacuous \
             (before: {before})"
        );
    }
}
