//! Proof-backed explorer pages for `B.U.D. 3.0` storage, validators, finality,
//! and multi-environment execution.
//!
//! WIRING: exposed for the Budlum Explorer browser UI and FFI page renderers;
//! exercised by `budlum-explorer self-test` and the explorer verification suite.
//!
//! Every displayed value on a storage, validator, finality, or execution page is
//! checked against a cryptographic Merkle state proof bound to a tracked
//! `state_root` before it can earn [`Strength::Verified`]. Unproven records are
//! downgraded to [`Strength::RpcClaimOnly`], and records whose proof fails or
//! contradicts an internal invariant are marked [`Strength::Refused`].

use crate::evidence::{Claim, Evidence, Strength};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Domain tag for explorer leaf commitments.
pub const EXPLORER_LEAF_DOMAIN: &[u8] = b"BUDLUM_EXPLORER_LEAF_V1";

/// Domain tag for internal Merkle branch nodes.
pub const EXPLORER_NODE_DOMAIN: &[u8] = b"BUDLUM_EXPLORER_NODE_V1";

/// Canonical `0xB001` Universal Call precompile / dispatcher identifier.
pub const UNIVERSAL_CALL_DISPATCHER: u16 = 0xB001;

/// Exact seat count in a Budlum finality committee bitmap (`512` seats = `64` bytes).
pub const FINALITY_COMMITTEE_SEATS: u16 = 512;

/// Cryptographic Merkle inclusion proof binding a serialized explorer record to
/// a finalized `state_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleStateProof {
    /// Sibling digests from leaf level to the root.
    pub siblings: Vec<[u8; 32]>,
    /// `true` when the sibling sits on the right (`hash(current || sibling)`),
    /// `false` when the sibling sits on the left (`hash(sibling || current)`).
    pub sibling_on_right: Vec<bool>,
}

impl MerkleStateProof {
    /// Computes the domain-separated leaf digest for `record_domain` and `payload`.
    #[must_use]
    pub fn leaf_digest(record_domain: &[u8], payload: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(EXPLORER_LEAF_DOMAIN);
        hasher.update((record_domain.len() as u64).to_le_bytes());
        hasher.update(record_domain);
        hasher.update((payload.len() as u64).to_le_bytes());
        hasher.update(payload);
        hasher.finalize().into()
    }

    /// Computes a domain-separated parent branch digest from `left` and `right`.
    #[must_use]
    pub fn branch_digest(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(EXPLORER_NODE_DOMAIN);
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    /// Recomputes the Merkle root from `record_domain`, `payload`, and the sibling path.
    ///
    /// # Errors
    ///
    /// Returns an error when `siblings` and `sibling_on_right` have mismatched lengths.
    pub fn compute_root(
        &self,
        record_domain: &[u8],
        payload: &[u8],
    ) -> Result<[u8; 32], String> {
        if self.siblings.len() != self.sibling_on_right.len() {
            return Err(format!(
                "Merkle proof length mismatch: {} siblings vs {} direction bits",
                self.siblings.len(),
                self.sibling_on_right.len()
            ));
        }
        let mut acc = Self::leaf_digest(record_domain, payload);
        for (sibling, on_right) in self.siblings.iter().zip(&self.sibling_on_right) {
            acc = if *on_right {
                Self::branch_digest(&acc, sibling)
            } else {
                Self::branch_digest(sibling, &acc)
            };
        }
        Ok(acc)
    }

    /// Verifies that `(record_domain, payload)` resolves to `expected_state_root`.
    #[must_use]
    pub fn verify_claim(
        &self,
        layer: &str,
        record_domain: &[u8],
        payload: &[u8],
        expected_state_root: &[u8; 32],
    ) -> Claim {
        match self.compute_root(record_domain, payload) {
            Ok(actual) if &actual == expected_state_root => Claim::new(
                layer,
                Strength::Verified,
                "record commitment verified against finalized state_root",
            ),
            Ok(_) => Claim::new(
                layer,
                Strength::Refused,
                "Merkle state proof root did not match expected finalized state_root",
            ),
            Err(reason) => Claim::new(layer, Strength::Refused, &reason),
        }
    }
}

// ============================================================================
// 1. B.U.D. 3.0 Storage Object Page
// ============================================================================

/// Availability state of one erasure-coded share in a placement group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShareAvailability {
    /// Share is sealed and attested by its assigned provider.
    Sealed,
    /// Share missed an audit challenge and is awaiting repair.
    Degraded,
    /// Share was reconstructed and rebound by a repair cycle.
    Repaired,
}

/// Per-share placement record inside a `B.U.D. 3.0` placement group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareStateView {
    pub share_index: u16,
    pub provider_id: [u8; 32],
    pub share_commitment: [u8; 32],
    pub availability: ShareAvailability,
}

/// Cryptographic audit outcome recorded for a `B.U.D. 3.0` object epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditOutcomeView {
    pub epoch: u64,
    pub challenged_share: u16,
    pub passed: bool,
    pub proof_digest: [u8; 32],
}

/// Repair record documenting recovery of a degraded share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairRecordView {
    pub epoch: u64,
    pub share_index: u16,
    pub replacement_provider: [u8; 32],
    pub reconstruction_digest: [u8; 32],
}

/// `B.U.D. 3.0` storage object record, placement group, share states, audit
/// outcomes, and repair history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageObjectRecordView {
    pub object_id: [u8; 32],
    pub owner: [u8; 32],
    pub total_bytes: u64,
    pub placement_group_id: u64,
    pub segment_digests: Vec<[u8; 32]>,
    pub share_states: Vec<ShareStateView>,
    pub audit_outcomes: Vec<AuditOutcomeView>,
    pub repair_records: Vec<RepairRecordView>,
}

impl StorageObjectRecordView {
    /// Canonical byte encoding covering every displayed storage field so no
    /// displayed value can be altered without invalidating the state proof.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.object_id);
        out.extend_from_slice(&self.owner);
        out.extend_from_slice(&self.total_bytes.to_le_bytes());
        out.extend_from_slice(&self.placement_group_id.to_le_bytes());
        out.extend_from_slice(&(self.segment_digests.len() as u64).to_le_bytes());
        for seg in &self.segment_digests {
            out.extend_from_slice(seg);
        }
        out.extend_from_slice(&(self.share_states.len() as u64).to_le_bytes());
        for share in &self.share_states {
            out.extend_from_slice(&share.share_index.to_le_bytes());
            out.extend_from_slice(&share.provider_id);
            out.extend_from_slice(&share.share_commitment);
            let tag = match share.availability {
                ShareAvailability::Sealed => 1_u8,
                ShareAvailability::Degraded => 2_u8,
                ShareAvailability::Repaired => 3_u8,
            };
            out.push(tag);
        }
        out.extend_from_slice(&(self.audit_outcomes.len() as u64).to_le_bytes());
        for audit in &self.audit_outcomes {
            out.extend_from_slice(&audit.epoch.to_le_bytes());
            out.extend_from_slice(&audit.challenged_share.to_le_bytes());
            out.push(u8::from(audit.passed));
            out.extend_from_slice(&audit.proof_digest);
        }
        out.extend_from_slice(&(self.repair_records.len() as u64).to_le_bytes());
        for repair in &self.repair_records {
            out.extend_from_slice(&repair.epoch.to_le_bytes());
            out.extend_from_slice(&repair.share_index.to_le_bytes());
            out.extend_from_slice(&repair.replacement_provider);
            out.extend_from_slice(&repair.reconstruction_digest);
        }
        out
    }
}

/// Verified explorer page for a `B.U.D. 3.0` storage object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageObjectPage {
    pub record: StorageObjectRecordView,
    pub evidence: Evidence,
}

/// Builds and verifies a `B.U.D. 3.0` storage explorer page against `expected_state_root`.
#[must_use]
pub fn verify_storage_object_page(
    record: StorageObjectRecordView,
    proof: Option<&MerkleStateProof>,
    expected_state_root: &[u8; 32],
) -> StorageObjectPage {
    let claim = if record.segment_digests.is_empty() || record.share_states.is_empty() {
        Claim::new(
            "bud3-storage-page",
            Strength::Refused,
            "storage object record must carry at least one segment digest and one share state",
        )
    } else if let Some(merkle) = proof {
        merkle.verify_claim(
            "bud3-storage-page",
            b"bud3.object.v1",
            &record.canonical_bytes(),
            expected_state_root,
        )
    } else {
        Claim::new(
            "bud3-storage-page",
            Strength::RpcClaimOnly,
            "storage object returned without a Merkle state proof",
        )
    };
    StorageObjectPage {
        record,
        evidence: Evidence::new().with(claim),
    }
}

// ============================================================================
// 2. Validator Class, Seats, Standby, Presence & Rewards Page
// ============================================================================

/// Hardware / operational validator class displayed on the validator page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorClassBadge {
    Mobile,
    Standard,
    Archival,
    Institutional,
}

impl ValidatorClassBadge {
    const fn tag(self) -> u8 {
        match self {
            Self::Mobile => 1,
            Self::Standard => 2,
            Self::Archival => 3,
            Self::Institutional => 4,
        }
    }
}

/// Validator record displayed on the explorer validator page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorRecordView {
    pub validator_id: [u8; 32],
    pub class_badge: ValidatorClassBadge,
    pub bonded_stake: u128,
    pub active_seats: u16,
    pub standby_queue_rank: Option<u32>,
    pub presence_window_bps: u16,
    pub suspended_until_epoch: Option<u64>,
    pub accumulated_rewards: u128,
}

impl ValidatorRecordView {
    /// Canonical byte encoding covering every displayed validator attribute.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(&self.validator_id);
        out.push(self.class_badge.tag());
        out.extend_from_slice(&self.bonded_stake.to_le_bytes());
        out.extend_from_slice(&self.active_seats.to_le_bytes());
        match self.standby_queue_rank {
            Some(rank) => {
                out.push(1);
                out.extend_from_slice(&rank.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.presence_window_bps.to_le_bytes());
        match self.suspended_until_epoch {
            Some(epoch) => {
                out.push(1);
                out.extend_from_slice(&epoch.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.accumulated_rewards.to_le_bytes());
        out
    }
}

/// Verified explorer page for a validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorPage {
    pub validator: ValidatorRecordView,
    pub evidence: Evidence,
}

/// Builds and verifies a validator explorer page against `expected_state_root`.
#[must_use]
pub fn verify_validator_page(
    validator: ValidatorRecordView,
    proof: Option<&MerkleStateProof>,
    expected_state_root: &[u8; 32],
) -> ValidatorPage {
    let claim = if validator.presence_window_bps > 10_000 {
        Claim::new(
            "validator-page",
            Strength::Refused,
            "validator presence_window_bps exceeds 10_000 basis points",
        )
    } else if let Some(merkle) = proof {
        merkle.verify_claim(
            "validator-page",
            b"pos.validator.v1",
            &validator.canonical_bytes(),
            expected_state_root,
        )
    } else {
        Claim::new(
            "validator-page",
            Strength::RpcClaimOnly,
            "validator record returned without a Merkle state proof",
        )
    };
    ValidatorPage {
        validator,
        evidence: Evidence::new().with(claim),
    }
}

// ============================================================================
// 3. Finality Checkpoint, 512-Seat Bitmap, Handover & ParticipationOmission Page
// ============================================================================

/// Committee handover transition record between consecutive epochs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoverRecordView {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub previous_committee_root: [u8; 32],
    pub next_committee_root: [u8; 32],
}

/// `ParticipationOmission` evidence proving a committee seat missed finality signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipationOmissionView {
    pub seat_index: u16,
    pub validator_id: [u8; 32],
    pub checkpoint_epoch: u64,
    pub omission_digest: [u8; 32],
}

/// Finality checkpoint view with 512-seat bitmap, handover records, and
/// `ParticipationOmission` proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityCheckpointView {
    pub epoch: u64,
    pub checkpoint_hash: [u8; 32],
    pub seat_bitmap_512: Vec<u8>,
    pub handover_records: Vec<HandoverRecordView>,
    pub omission_proofs: Vec<ParticipationOmissionView>,
}

impl FinalityCheckpointView {
    /// Returns whether `seat_index` (`0..512`) signed the checkpoint bitmap.
    #[must_use]
    pub fn seat_signed(&self, seat_index: u16) -> bool {
        if seat_index >= FINALITY_COMMITTEE_SEATS || self.seat_bitmap_512.len() != 64 {
            return false;
        }
        let byte_idx = usize::from(seat_index / 8);
        let bit_idx = seat_index % 8;
        (self.seat_bitmap_512[byte_idx] & (1_u8 << bit_idx)) != 0
    }

    /// Counts how many of the `512` seats signed this checkpoint.
    #[must_use]
    pub fn signed_seat_count(&self) -> u32 {
        self.seat_bitmap_512
            .iter()
            .copied()
            .map(u8::count_ones)
            .sum()
    }

    /// Canonical byte encoding covering bitmap, handovers, and omission proofs.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.checkpoint_hash);
        out.extend_from_slice(&(self.seat_bitmap_512.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.seat_bitmap_512);
        out.extend_from_slice(&(self.handover_records.len() as u64).to_le_bytes());
        for handover in &self.handover_records {
            out.extend_from_slice(&handover.from_epoch.to_le_bytes());
            out.extend_from_slice(&handover.to_epoch.to_le_bytes());
            out.extend_from_slice(&handover.previous_committee_root);
            out.extend_from_slice(&handover.next_committee_root);
        }
        out.extend_from_slice(&(self.omission_proofs.len() as u64).to_le_bytes());
        for omission in &self.omission_proofs {
            out.extend_from_slice(&omission.seat_index.to_le_bytes());
            out.extend_from_slice(&omission.validator_id);
            out.extend_from_slice(&omission.checkpoint_epoch.to_le_bytes());
            out.extend_from_slice(&omission.omission_digest);
        }
        out
    }
}

/// Verified explorer page for a finality checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalityPage {
    pub checkpoint: FinalityCheckpointView,
    pub evidence: Evidence,
}

/// Builds and verifies a finality checkpoint explorer page against `expected_state_root`.
#[must_use]
pub fn verify_finality_page(
    checkpoint: FinalityCheckpointView,
    proof: Option<&MerkleStateProof>,
    expected_state_root: &[u8; 32],
) -> FinalityPage {
    let claim = if checkpoint.seat_bitmap_512.len() != 64 {
        Claim::new(
            "finality-page",
            Strength::Refused,
            "finality checkpoint bitmap must be exactly 64 bytes (512 committee seats)",
        )
    } else if checkpoint.omission_proofs.iter().any(|omission| {
        omission.seat_index >= FINALITY_COMMITTEE_SEATS
            || omission.checkpoint_epoch != checkpoint.epoch
            || checkpoint.seat_signed(omission.seat_index)
    }) {
        Claim::new(
            "finality-page",
            Strength::Refused,
            "ParticipationOmission contradicts the 512-seat finality bitmap or epoch",
        )
    } else if let Some(merkle) = proof {
        merkle.verify_claim(
            "finality-page",
            b"finality.checkpoint.v1",
            &checkpoint.canonical_bytes(),
            expected_state_root,
        )
    } else {
        Claim::new(
            "finality-page",
            Strength::RpcClaimOnly,
            "finality checkpoint returned without a Merkle state proof",
        )
    };
    FinalityPage {
        checkpoint,
        evidence: Evidence::new().with(claim),
    }
}

// ============================================================================
// 4. Execution Environments, Universal Call (0xB001), UAR & Quantum Badges
// ============================================================================

/// Execution environment identifier displayed per transaction frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionEnvKind {
    BudlumNative,
    Evm,
    SolanaSvm,
    MoveVm,
    CosmWasm,
    NearWasm,
    TonTvm,
    BitcoinUtxo,
    CardanoPlutus,
}

impl ExecutionEnvKind {
    const fn tag(self) -> u8 {
        match self {
            Self::BudlumNative => 0x00,
            Self::Evm => 0x01,
            Self::SolanaSvm => 0x02,
            Self::MoveVm => 0x05,
            Self::CosmWasm => 0x06,
            Self::NearWasm => 0x07,
            Self::TonTvm => 0x09,
            Self::BitcoinUtxo => 0x0A,
            Self::CardanoPlutus => 0x0B,
        }
    }
}

/// Account authentication scheme determining quantum-resistance posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountAuthScheme {
    /// Post-quantum `ML-DSA-65` native Budlum account.
    MlDsa65,
    /// Post-quantum `SLH-DSA` native Budlum account.
    SlhDsa,
    /// Foreign Ethereum/Bitcoin `secp256k1` ECDSA signature.
    ForeignSecp256k1,
    /// Foreign Solana/NEAR/TON/Aptos/Cardano `Ed25519` signature.
    ForeignEd25519,
    /// Foreign Bitcoin Taproot `BIP-340` Schnorr signature.
    ForeignSchnorr,
}

impl AccountAuthScheme {
    /// Returns the explorer quantum-posture badge for this authentication scheme.
    #[must_use]
    pub const fn quantum_badge(self) -> QuantumPostureBadge {
        match self {
            Self::MlDsa65 | Self::SlhDsa => QuantumPostureBadge::PostQuantum,
            Self::ForeignSecp256k1 | Self::ForeignEd25519 | Self::ForeignSchnorr => {
                QuantumPostureBadge::Classical
            }
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::MlDsa65 => 1,
            Self::SlhDsa => 2,
            Self::ForeignSecp256k1 => 3,
            Self::ForeignEd25519 => 4,
            Self::ForeignSchnorr => 5,
        }
    }
}

/// Explicit security badge shown next to every account on the execution page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuantumPostureBadge {
    /// Post-quantum signature scheme (`"post-quantum"`).
    PostQuantum,
    /// Classical elliptic-curve foreign signature scheme (`"classical"`).
    Classical,
}

impl QuantumPostureBadge {
    /// Canonical badge label rendered in the explorer UI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PostQuantum => "post-quantum",
            Self::Classical => "classical",
        }
    }
}

/// Account participant entry with foreign alias mapping and derived quantum badge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountAliasView {
    pub canonical_account: [u8; 32],
    pub foreign_alias: Option<String>,
    pub auth_scheme: AccountAuthScheme,
}

impl AccountAliasView {
    /// Returns the non-overridable quantum badge derived from `auth_scheme`.
    #[must_use]
    pub const fn badge(&self) -> QuantumPostureBadge {
        self.auth_scheme.quantum_badge()
    }
}

/// Universal Asset Registry (`UAR`) pointer touched during execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UarPointerView {
    pub uar_asset_id: [u8; 32],
    pub origin_env: ExecutionEnvKind,
    pub delta_amount: u128,
}

/// Nested `0xB001` Universal Call tree frame across execution environments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniversalCallNode {
    pub dispatcher: u16,
    pub caller_env: ExecutionEnvKind,
    pub callee_env: ExecutionEnvKind,
    pub target_program: [u8; 32],
    pub selector: [u8; 4],
    pub succeeded: bool,
    pub children: Vec<Self>,
}

impl UniversalCallNode {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.dispatcher.to_le_bytes());
        out.push(self.caller_env.tag());
        out.push(self.callee_env.tag());
        out.extend_from_slice(&self.target_program);
        out.extend_from_slice(&self.selector);
        out.push(u8::from(self.succeeded));
        out.extend_from_slice(&(self.children.len() as u64).to_le_bytes());
        for child in &self.children {
            child.encode_into(out);
        }
    }

    fn all_dispatchers_valid(&self) -> bool {
        self.dispatcher == UNIVERSAL_CALL_DISPATCHER
            && self.children.iter().all(Self::all_dispatchers_valid)
    }
}

/// Multi-EE transaction execution record with aliases, `0xB001` Universal Call
/// tree, and `UAR` asset pointers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionTxView {
    pub tx_hash: [u8; 32],
    pub root_env: ExecutionEnvKind,
    pub participants: Vec<AccountAliasView>,
    pub universal_call_root: Option<UniversalCallNode>,
    pub uar_pointers: Vec<UarPointerView>,
}

impl ExecutionTxView {
    /// Canonical byte encoding covering participants, call tree, and `UAR` pointers.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.tx_hash);
        out.push(self.root_env.tag());
        out.extend_from_slice(&(self.participants.len() as u64).to_le_bytes());
        for acct in &self.participants {
            out.extend_from_slice(&acct.canonical_account);
            match &acct.foreign_alias {
                Some(alias) => {
                    out.push(1);
                    out.extend_from_slice(&(alias.len() as u64).to_le_bytes());
                    out.extend_from_slice(alias.as_bytes());
                }
                None => out.push(0),
            }
            out.push(acct.auth_scheme.tag());
        }
        match &self.universal_call_root {
            Some(node) => {
                out.push(1);
                node.encode_into(&mut out);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&(self.uar_pointers.len() as u64).to_le_bytes());
        for ptr in &self.uar_pointers {
            out.extend_from_slice(&ptr.uar_asset_id);
            out.push(ptr.origin_env.tag());
            out.extend_from_slice(&ptr.delta_amount.to_le_bytes());
        }
        out
    }
}

/// Verified explorer page for a transaction execution trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPage {
    pub tx: ExecutionTxView,
    pub evidence: Evidence,
}

/// Builds and verifies an execution explorer page against `expected_state_root`.
#[must_use]
pub fn verify_execution_page(
    tx: ExecutionTxView,
    proof: Option<&MerkleStateProof>,
    expected_state_root: &[u8; 32],
) -> ExecutionPage {
    let bad_dispatcher = tx
        .universal_call_root
        .as_ref()
        .is_some_and(|root| !root.all_dispatchers_valid());
    let claim = if bad_dispatcher {
        Claim::new(
            "execution-page",
            Strength::Refused,
            "Universal Call frame carries a dispatcher other than 0xB001",
        )
    } else if let Some(merkle) = proof {
        merkle.verify_claim(
            "execution-page",
            b"uel.execution.v1",
            &tx.canonical_bytes(),
            expected_state_root,
        )
    } else {
        Claim::new(
            "execution-page",
            Strength::RpcClaimOnly,
            "execution trace returned without a Merkle state proof",
        )
    };
    ExecutionPage {
        tx,
        evidence: Evidence::new().with(claim),
    }
}

/// Runs internal explorer page verification canaries for `budlum-explorer self-test`.
///
/// # Errors
///
/// Returns an error description if any proof or quantum-badge invariant fails.
pub fn self_test() -> Result<(), String> {
    let record = StorageObjectRecordView {
        object_id: [0x11; 32],
        owner: [0x22; 32],
        total_bytes: 65_536,
        placement_group_id: 7,
        segment_digests: vec![[0x33; 32]],
        share_states: vec![ShareStateView {
            share_index: 0,
            provider_id: [0x44; 32],
            share_commitment: [0x55; 32],
            availability: ShareAvailability::Sealed,
        }],
        audit_outcomes: Vec::new(),
        repair_records: Vec::new(),
    };
    let proof = MerkleStateProof {
        siblings: vec![[0xAA; 32]],
        sibling_on_right: vec![true],
    };
    let root = proof.compute_root(b"bud3.object.v1", &record.canonical_bytes())?;
    let page = verify_storage_object_page(record, Some(&proof), &root);
    if page.evidence.weakest() != Strength::Verified {
        return Err(String::from(
            "valid B.U.D. 3.0 storage proof was not Verified",
        ));
    }
    let foreign = AccountAliasView {
        canonical_account: [0x99; 32],
        foreign_alias: Some(String::from("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")),
        auth_scheme: AccountAuthScheme::ForeignSecp256k1,
    };
    if foreign.badge().as_str() != "classical" {
        return Err(String::from(
            "foreign ECDSA account was not labelled classical",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_id::ContentId;
    use crate::name_rule::check_name;
    use crate::patchset;

    fn build_single_branch_proof(domain: &[u8], payload: &[u8]) -> (MerkleStateProof, [u8; 32]) {
        let proof = MerkleStateProof {
            siblings: vec![[0x7E; 32], [0x4B; 32]],
            sibling_on_right: vec![true, false],
        };
        let root = proof
            .compute_root(domain, payload)
            .expect("aligned Merkle proof must compute root");
        (proof, root)
    }

    #[test]
    fn explorer_parity() {
        assert!(check_name("ayaz.bud").is_ok());
        assert!(check_name("javascript:alert(1)").is_err());
        let cid_a = ContentId::of(b"<h1>budlum</h1>");
        let cid_b = ContentId::of(b"<h1>budlum</h1>");
        assert_eq!(cid_a, cid_b);
    }

    #[test]
    fn explorer_patchset() {
        let patches_txt = include_str!("../browser/patches.txt");
        let entries = patchset::parse_list(patches_txt).expect("patches.txt must parse");
        assert!(!entries.is_empty());
        assert!(patchset::check_no_foreign_brand("patches.txt", patches_txt).is_ok());
    }

    #[test]
    fn explorer_shows_object_placement_with_proof() {
        let record = StorageObjectRecordView {
            object_id: [0x10; 32],
            owner: [0x20; 32],
            total_bytes: 1_048_576,
            placement_group_id: 42,
            segment_digests: vec![[0x31; 32], [0x32; 32]],
            share_states: vec![
                ShareStateView {
                    share_index: 0,
                    provider_id: [0x41; 32],
                    share_commitment: [0x51; 32],
                    availability: ShareAvailability::Sealed,
                },
                ShareStateView {
                    share_index: 1,
                    provider_id: [0x42; 32],
                    share_commitment: [0x52; 32],
                    availability: ShareAvailability::Repaired,
                },
            ],
            audit_outcomes: vec![AuditOutcomeView {
                epoch: 12,
                challenged_share: 0,
                passed: true,
                proof_digest: [0x61; 32],
            }],
            repair_records: vec![RepairRecordView {
                epoch: 13,
                share_index: 1,
                replacement_provider: [0x42; 32],
                reconstruction_digest: [0x71; 32],
            }],
        };

        let (proof, state_root) =
            build_single_branch_proof(b"bud3.object.v1", &record.canonical_bytes());

        let verified = verify_storage_object_page(record.clone(), Some(&proof), &state_root);
        assert_eq!(verified.evidence.weakest(), Strength::Verified);
        assert_eq!(verified.record.placement_group_id, 42);
        assert_eq!(verified.record.share_states.len(), 2);
        assert_eq!(verified.record.audit_outcomes.len(), 1);
        assert_eq!(verified.record.repair_records.len(), 1);

        // Unproven RPC responses never receive Strength::Verified.
        let unproven = verify_storage_object_page(record.clone(), None, &state_root);
        assert_eq!(unproven.evidence.weakest(), Strength::RpcClaimOnly);

        // Mutating any displayed field (e.g. placement_group_id) invalidates the proof.
        let mut tampered = record;
        tampered.placement_group_id = 99;
        let refused = verify_storage_object_page(tampered, Some(&proof), &state_root);
        assert_eq!(refused.evidence.weakest(), Strength::Refused);
    }

    #[test]
    fn explorer_marks_foreign_accounts_classical() {
        let tx = ExecutionTxView {
            tx_hash: [0xAB; 32],
            root_env: ExecutionEnvKind::Evm,
            participants: vec![
                AccountAliasView {
                    canonical_account: [0x01; 32],
                    foreign_alias: None,
                    auth_scheme: AccountAuthScheme::MlDsa65,
                },
                AccountAliasView {
                    canonical_account: [0x02; 32],
                    foreign_alias: Some(String::from(
                        "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
                    )),
                    auth_scheme: AccountAuthScheme::ForeignSecp256k1,
                },
                AccountAliasView {
                    canonical_account: [0x03; 32],
                    foreign_alias: Some(String::from(
                        "So11111111111111111111111111111111111111112",
                    )),
                    auth_scheme: AccountAuthScheme::ForeignEd25519,
                },
                AccountAliasView {
                    canonical_account: [0x04; 32],
                    foreign_alias: Some(String::from("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xd")),
                    auth_scheme: AccountAuthScheme::ForeignSchnorr,
                },
            ],
            universal_call_root: Some(UniversalCallNode {
                dispatcher: UNIVERSAL_CALL_DISPATCHER,
                caller_env: ExecutionEnvKind::Evm,
                callee_env: ExecutionEnvKind::SolanaSvm,
                target_program: [0xCC; 32],
                selector: [0xde, 0xad, 0xbe, 0xef],
                succeeded: true,
                children: vec![UniversalCallNode {
                    dispatcher: UNIVERSAL_CALL_DISPATCHER,
                    caller_env: ExecutionEnvKind::SolanaSvm,
                    callee_env: ExecutionEnvKind::MoveVm,
                    target_program: [0xDD; 32],
                    selector: [0xca, 0xfe, 0xba, 0xbe],
                    succeeded: true,
                    children: Vec::new(),
                }],
            }),
            uar_pointers: vec![UarPointerView {
                uar_asset_id: [0xEE; 32],
                origin_env: ExecutionEnvKind::Evm,
                delta_amount: 500_000,
            }],
        };

        let (proof, state_root) =
            build_single_branch_proof(b"uel.execution.v1", &tx.canonical_bytes());
        let page = verify_execution_page(tx, Some(&proof), &state_root);
        assert_eq!(page.evidence.weakest(), Strength::Verified);

        assert_eq!(
            page.tx.participants[0].badge(),
            QuantumPostureBadge::PostQuantum
        );
        assert_eq!(page.tx.participants[0].badge().as_str(), "post-quantum");

        for foreign_participant in &page.tx.participants[1..] {
            assert_eq!(foreign_participant.badge(), QuantumPostureBadge::Classical);
            assert_eq!(foreign_participant.badge().as_str(), "classical");
        }
    }

    #[test]
    fn validator_and_finality_pages_enforce_proof_and_bitmap_invariants() {
        let validator = ValidatorRecordView {
            validator_id: [0x11; 32],
            class_badge: ValidatorClassBadge::Archival,
            bonded_stake: 250_000_000,
            active_seats: 8,
            standby_queue_rank: None,
            presence_window_bps: 9_950,
            suspended_until_epoch: None,
            accumulated_rewards: 12_500,
        };
        let (v_proof, v_root) =
            build_single_branch_proof(b"pos.validator.v1", &validator.canonical_bytes());
        let v_page = verify_validator_page(validator, Some(&v_proof), &v_root);
        assert_eq!(v_page.evidence.weakest(), Strength::Verified);

        let mut bitmap = vec![0xFF_u8; 64];
        // Clear seat 9 so ParticipationOmission for seat 9 is consistent with bitmap.
        bitmap[1] &= !(1_u8 << 1);
        let checkpoint = FinalityCheckpointView {
            epoch: 77,
            checkpoint_hash: [0x88; 32],
            seat_bitmap_512: bitmap,
            handover_records: vec![HandoverRecordView {
                from_epoch: 76,
                to_epoch: 77,
                previous_committee_root: [0x91; 32],
                next_committee_root: [0x92; 32],
            }],
            omission_proofs: vec![ParticipationOmissionView {
                seat_index: 9,
                validator_id: [0xA1; 32],
                checkpoint_epoch: 77,
                omission_digest: [0xB1; 32],
            }],
        };
        assert_eq!(checkpoint.signed_seat_count(), 511);
        let (f_proof, f_root) =
            build_single_branch_proof(b"finality.checkpoint.v1", &checkpoint.canonical_bytes());
        let f_page = verify_finality_page(checkpoint, Some(&f_proof), &f_root);
        assert_eq!(f_page.evidence.weakest(), Strength::Verified);
    }
}
