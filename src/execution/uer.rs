//! Universal Execution Receipt (`UER-1`) and domain-separated Merkle inclusion proofs.
//!
//! Normalizes execution outcomes across all 13 `Budlum` execution environments (`EVM`, `WASM`,
//! `SVM`, `Move`, `BudZero`, and expansion environments) into a single deterministic receipt
//! commitment with light-client inclusion proofs immune to odd-leaf duplication (`CVE-2012-2459`)
//! and leaf/interior second-preimage confusion.
//!
//! WIRING: constructed and verified by `execution::coordinator::conformance` and
//! `execution::budzero_ee` for cross-VM receipt commitment and light-client proof checks.

use crate::core::hash::{calculate_hash_bytes, hash_fields_bytes, presence_tagged};
use crate::execution::coordinator::{UelReceipt, UelReceiptStatus};
use budlum_uel_abi::{BlockContext, EeCall, EeId, EeLog, EeOutcome, OutcomeStatus};
use serde::{Deserialize, Serialize};

/// Canonical `UER-1` wire format version.
pub const UER_VERSION_V1: u8 = 1;

/// Maximum Merkle proof depth (`2^32` receipts per batch ceiling).
pub const MAX_UER_MERKLE_DEPTH: usize = 32;

/// Domain tag for hashing a single [`UniversalExecutionReceipt`] into its 32-byte `receipt_id`.
pub const UER_RECEIPT_DOMAIN: &[u8] = b"BDLM_UER_RECEIPT_V1";

/// Domain tag for leaf nodes in a `UER-1` batch Merkle tree.
pub const UER_LEAF_DOMAIN: &[u8] = b"BDLM_UER_LEAF_V1";

/// Domain tag for binary interior nodes in a `UER-1` batch Merkle tree.
pub const UER_NODE_DOMAIN: &[u8] = b"BDLM_UER_NODE_V1";

/// Domain tag for promoting an unpaired trailing node at a level without duplicating it.
pub const UER_ODD_PROMOTE_DOMAIN: &[u8] = b"BDLM_UER_ODD_PROMOTE_V1";

/// Deterministic status normalized across all `Budlum` execution environments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UerStatus {
    /// Execution succeeded and state writes committed.
    Success,
    /// Execution reverted and state writes rolled back.
    Revert,
    /// Execution exhausted its BGU budget.
    OutOfGas,
    /// Deployment or target bytecode failed deterministic validation.
    InvalidCode,
    /// Deployment refused because the target EE is currently frozen.
    DeployFrozen,
    /// Deterministic worker trap bound to `(ee, panic_digest)`.
    Fault {
        /// Faulting execution environment identifier.
        ee: u8,
        /// Digest of the deterministic fault payload.
        panic_digest: [u8; 32],
    },
}

impl UerStatus {
    const fn tag_byte(self) -> u8 {
        match self {
            Self::Success => 0x01,
            Self::Revert => 0x02,
            Self::OutOfGas => 0x03,
            Self::InvalidCode => 0x04,
            Self::DeployFrozen => 0x05,
            Self::Fault { .. } => 0x06,
        }
    }

    fn fault_fields(self) -> ([u8; 1], [u8; 32]) {
        match self {
            Self::Fault { ee, panic_digest } => ([ee], panic_digest),
            _ => ([0u8], [0u8; 32]),
        }
    }
}

impl From<&UelReceiptStatus> for UerStatus {
    fn from(status: &UelReceiptStatus) -> Self {
        match status {
            UelReceiptStatus::Success => Self::Success,
            UelReceiptStatus::Revert => Self::Revert,
            UelReceiptStatus::OutOfGas => Self::OutOfGas,
            UelReceiptStatus::InvalidCode => Self::InvalidCode,
            UelReceiptStatus::DeployFrozen => Self::DeployFrozen,
            UelReceiptStatus::Fault { ee, panic_digest } => Self::Fault {
                ee: *ee,
                panic_digest: *panic_digest,
            },
        }
    }
}

impl From<OutcomeStatus> for UerStatus {
    fn from(status: OutcomeStatus) -> Self {
        match status {
            OutcomeStatus::Success => Self::Success,
            OutcomeStatus::Revert => Self::Revert,
            OutcomeStatus::OutOfGas => Self::OutOfGas,
            OutcomeStatus::InvalidCode => Self::InvalidCode,
        }
    }
}

/// Errors returned while constructing or verifying `UER-1` receipts and Merkle proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UerError {
    /// Unsupported receipt schema version.
    UnsupportedVersion(u8),
    /// Batch contains zero receipts and therefore has no inclusion proof.
    EmptyBatch,
    /// Requested receipt index is outside the batch bounds.
    IndexOutOfBounds {
        /// Requested leaf index.
        index: usize,
        /// Batch length.
        len: usize,
    },
    /// Merkle proof exceeds [`MAX_UER_MERKLE_DEPTH`] or disagrees with `total_leaves` geometry.
    MalformedProofGeometry(&'static str),
    /// Recomputed Merkle root does not match the expected batch commitment.
    RootMismatch,
}

impl core::fmt::Display for UerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported UER version {v}"),
            Self::EmptyBatch => f.write_str("UER batch must not be empty"),
            Self::IndexOutOfBounds { index, len } => {
                write!(f, "UER index {index} out of bounds for batch of len {len}")
            }
            Self::MalformedProofGeometry(reason) => {
                write!(f, "malformed UER Merkle proof geometry: {reason}")
            }
            Self::RootMismatch => f.write_str("UER Merkle root mismatch"),
        }
    }
}

impl std::error::Error for UerError {}

/// Canonical cross-VM execution receipt (`UER-1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniversalExecutionReceipt {
    /// Schema version (`UER_VERSION_V1`).
    pub version: u8,
    /// Chain identifier binding this receipt to one network.
    pub chain_id: u64,
    /// Block height at which execution occurred.
    pub block_height: u64,
    /// Zero-based index of the transaction within the block batch.
    pub tx_index: u32,
    /// Canonical 32-byte transaction hash.
    pub tx_hash: [u8; 32],
    /// Entry execution environment identifier (`EeId.0`).
    pub origin_ee: u8,
    /// Normalized terminal status.
    pub status: UerStatus,
    /// Total BGU consumed by the transaction.
    pub gas_used_bgu: u64,
    /// Base-fee portion permanently burned (attoBUD).
    pub burned_attos: u128,
    /// Base-fee portion routed to the protocol security reward pool (attoBUD).
    pub security_pool_attos: u128,
    /// Priority-fee tip paid to the block proposer (attoBUD).
    pub proposer_tip_attos: u128,
    /// SHA-256 digest of the raw return/revert bytes.
    pub output_digest: [u8; 32],
    /// Optional newly deployed 32-byte contract address.
    pub contract_address: Option<[u8; 32]>,
    /// Length-prefixed commitment over all emitted `(EeId, EeLog)` entries in emission order.
    pub logs_commitment: [u8; 32],
    /// Post-transaction unified execution state root (`uel/root`).
    pub post_execution_root: [u8; 32],
    /// Optional `BudZero` / zkVM execution trace commitment when proven.
    pub zk_trace_commitment: Option<[u8; 32]>,
}

/// Fold ordered `(EeId, EeLog)` entries into a deterministic 32-byte commitment.
///
/// Convenience: shared by coordinator receipt conversion and direct EE receipt builders.
#[must_use]
pub fn compute_uer_logs_commitment(logs: &[(EeId, EeLog)]) -> [u8; 32] {
    let count_le = u64::try_from(logs.len()).unwrap_or(u64::MAX).to_le_bytes();
    let mut acc = hash_fields_bytes(&[UER_RECEIPT_DOMAIN, b"logs_init", &count_le]);
    for (ee, log) in logs {
        let topic_count_le = u64::try_from(log.topics.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes();
        let mut topic_acc =
            hash_fields_bytes(&[UER_RECEIPT_DOMAIN, b"topics_init", &topic_count_le]);
        for topic in &log.topics {
            topic_acc = hash_fields_bytes(&[UER_RECEIPT_DOMAIN, &topic_acc, topic]);
        }
        acc = hash_fields_bytes(&[
            UER_RECEIPT_DOMAIN,
            &acc,
            &[ee.0],
            &[log.emitter.ee.0],
            &log.emitter.id,
            &topic_acc,
            &log.data,
        ]);
    }
    acc
}

impl UniversalExecutionReceipt {
    /// Builds a `UER-1` receipt from a coordinator [`UelReceipt`] and post-state root.
    ///
    /// WIRING: invoked by coordinator conformance verification after executing UEL blocks.
    #[must_use]
    pub fn from_uel_receipt(
        ctx: &BlockContext,
        tx_index: u32,
        origin_ee: EeId,
        receipt: &UelReceipt,
        post_execution_root: [u8; 32],
        zk_trace_commitment: Option<[u8; 32]>,
    ) -> Self {
        Self {
            version: UER_VERSION_V1,
            chain_id: ctx.chain_id,
            block_height: ctx.height,
            tx_index,
            tx_hash: receipt.tx_hash,
            origin_ee: origin_ee.0,
            status: UerStatus::from(&receipt.status),
            gas_used_bgu: receipt.gas_used_bgu,
            burned_attos: receipt.fee.burned_attos,
            security_pool_attos: receipt.fee.security_pool_attos,
            proposer_tip_attos: receipt.fee.proposer_tip_attos,
            output_digest: calculate_hash_bytes(&receipt.output),
            contract_address: receipt.contract_address.map(|a| *a.as_bytes()),
            logs_commitment: compute_uer_logs_commitment(&receipt.logs),
            post_execution_root,
            zk_trace_commitment,
        }
    }

    /// Builds a `UER-1` receipt directly from an EE worker [`EeOutcome`] and emitted logs.
    ///
    /// WIRING: invoked by `BudZeroEe` receipt projection for proof-bound execution traces.
    #[must_use]
    pub fn from_ee_outcome(
        ctx: &BlockContext,
        call: &EeCall,
        tx_index: u32,
        outcome: &EeOutcome,
        logs: &[(EeId, EeLog)],
        post_execution_root: [u8; 32],
        zk_trace_commitment: Option<[u8; 32]>,
    ) -> Self {
        Self {
            version: UER_VERSION_V1,
            chain_id: ctx.chain_id,
            block_height: ctx.height,
            tx_index,
            tx_hash: call.tx_hash,
            origin_ee: call.target.ee.0,
            status: UerStatus::from(outcome.status),
            gas_used_bgu: outcome.gas_used,
            burned_attos: 0,
            security_pool_attos: 0,
            proposer_tip_attos: 0,
            output_digest: calculate_hash_bytes(&outcome.output),
            contract_address: None,
            logs_commitment: compute_uer_logs_commitment(logs),
            post_execution_root,
            zk_trace_commitment,
        }
    }

    /// Computes the canonical length-prefixed 32-byte identifier committing every receipt field.
    ///
    /// Convenience: exposed for light-client verifiers, explorer evidence, and Merkle builders.
    #[must_use]
    pub fn receipt_id(&self) -> [u8; 32] {
        let chain_le = self.chain_id.to_le_bytes();
        let height_le = self.block_height.to_le_bytes();
        let idx_le = self.tx_index.to_le_bytes();
        let status_tag = [self.status.tag_byte()];
        let (fault_ee, fault_digest) = self.status.fault_fields();
        let gas_le = self.gas_used_bgu.to_le_bytes();
        let burned_le = self.burned_attos.to_le_bytes();
        let sec_le = self.security_pool_attos.to_le_bytes();
        let tip_le = self.proposer_tip_attos.to_le_bytes();
        let contract_opt = presence_tagged(self.contract_address);
        let zk_opt = presence_tagged(self.zk_trace_commitment);

        hash_fields_bytes(&[
            UER_RECEIPT_DOMAIN,
            &[self.version],
            &chain_le,
            &height_le,
            &idx_le,
            &self.tx_hash,
            &[self.origin_ee],
            &status_tag,
            &fault_ee,
            &fault_digest,
            &gas_le,
            &burned_le,
            &sec_le,
            &tip_le,
            &self.output_digest,
            &contract_opt,
            &self.logs_commitment,
            &self.post_execution_root,
            &zk_opt,
        ])
    }

    /// Validates receipt schema invariants before commitment or proof verification.
    ///
    /// Convenience: exposed for RPC/SDK callers validating untrusted decoded receipts.
    ///
    /// # Errors
    ///
    /// Returns [`UerError::UnsupportedVersion`] if `version != UER_VERSION_V1`.
    pub const fn validate_schema(&self) -> Result<(), UerError> {
        if self.version != UER_VERSION_V1 {
            return Err(UerError::UnsupportedVersion(self.version));
        }
        Ok(())
    }
}

/// One level step in a domain-separated `UER-1` Merkle inclusion proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UerMerkleStep {
    /// Binary interior combination with `sibling` (`is_right_sibling = true` means `H(cur, sibling)`).
    Sibling {
        /// `true` when `sibling` sits on the right (`cur` is an even index at this level).
        is_right_sibling: bool,
        /// Sibling node digest at this level.
        hash: [u8; 32],
    },
    /// Domain-separated promotion of an unpaired trailing node at this level.
    OddPromote,
}

/// Compact light-client proof that `receipt` sits at `leaf_index` in a batch of `total_leaves`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UerInclusionProof {
    /// Full receipt being proven.
    pub receipt: UniversalExecutionReceipt,
    /// Zero-based position of `receipt` in the block receipt list.
    pub leaf_index: u32,
    /// Total number of receipts committed in the batch.
    pub total_leaves: u32,
    /// Bottom-up Merkle steps from leaf to root.
    pub steps: Vec<UerMerkleStep>,
}

fn hash_uer_leaf(leaf_index: u32, receipt_id: &[u8; 32]) -> [u8; 32] {
    let idx_le = u64::from(leaf_index).to_le_bytes();
    hash_fields_bytes(&[UER_LEAF_DOMAIN, &idx_le, receipt_id])
}

fn hash_uer_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[UER_NODE_DOMAIN, left, right])
}

fn hash_uer_odd_promote(only: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[UER_ODD_PROMOTE_DOMAIN, only])
}

/// Computes the deterministic `UER-1` batch Merkle root over `receipts`.
///
/// WIRING: called by coordinator conformance checks and batch inclusion proof generation.
///
/// # Errors
///
/// Returns [`UerError::EmptyBatch`] when `receipts` is empty, [`UerError::IndexOutOfBounds`]
/// if `receipts.len()` exceeds `u32::MAX`, or [`UerError::UnsupportedVersion`] on bad schema.
pub fn compute_uer_batch_root(
    receipts: &[UniversalExecutionReceipt],
) -> Result<[u8; 32], UerError> {
    if receipts.is_empty() {
        return Err(UerError::EmptyBatch);
    }
    let _total = u32::try_from(receipts.len()).map_err(|_| UerError::IndexOutOfBounds {
        index: receipts.len(),
        len: usize::MAX,
    })?;

    let mut level = Vec::with_capacity(receipts.len());
    for (idx, r) in receipts.iter().enumerate() {
        r.validate_schema()?;
        let idx_u32 = u32::try_from(idx).unwrap_or(u32::MAX);
        level.push(hash_uer_leaf(idx_u32, &r.receipt_id()));
    }

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut chunks = level.chunks_exact(2);
        for pair in &mut chunks {
            if let [left, right] = pair {
                next.push(hash_uer_node(left, right));
            }
        }
        if let [odd] = chunks.remainder() {
            next.push(hash_uer_odd_promote(odd));
        }
        level = next;
    }

    level.first().copied().ok_or(UerError::EmptyBatch)
}

/// Generates a verifiable [`UerInclusionProof`] for `receipts[index]`.
///
/// WIRING: called by coordinator conformance checks and light-client receipt provers.
///
/// # Errors
///
/// Returns [`UerError::EmptyBatch`] if `receipts` is empty, [`UerError::IndexOutOfBounds`] if
/// `index >= receipts.len()`, or [`UerError::UnsupportedVersion`] if any receipt has an invalid version.
pub fn prove_uer_inclusion(
    receipts: &[UniversalExecutionReceipt],
    index: usize,
) -> Result<UerInclusionProof, UerError> {
    if receipts.is_empty() {
        return Err(UerError::EmptyBatch);
    }
    let total_leaves = u32::try_from(receipts.len()).map_err(|_| UerError::IndexOutOfBounds {
        index: receipts.len(),
        len: usize::MAX,
    })?;
    let target = receipts.get(index).ok_or(UerError::IndexOutOfBounds {
        index,
        len: receipts.len(),
    })?;
    target.validate_schema()?;

    let mut level = Vec::with_capacity(receipts.len());
    for (idx, r) in receipts.iter().enumerate() {
        r.validate_schema()?;
        let idx_u32 = u32::try_from(idx).unwrap_or(u32::MAX);
        level.push(hash_uer_leaf(idx_u32, &r.receipt_id()));
    }

    let mut cur_idx = index;
    let mut steps = Vec::new();
    while level.len() > 1 {
        if cur_idx.is_multiple_of(2) {
            if let Some(&sib) = level.get(cur_idx + 1) {
                steps.push(UerMerkleStep::Sibling {
                    is_right_sibling: true,
                    hash: sib,
                });
            } else {
                steps.push(UerMerkleStep::OddPromote);
            }
        } else if let Some(&sib) = level.get(cur_idx - 1) {
            steps.push(UerMerkleStep::Sibling {
                is_right_sibling: false,
                hash: sib,
            });
        }

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut chunks = level.chunks_exact(2);
        for pair in &mut chunks {
            if let [left, right] = pair {
                next.push(hash_uer_node(left, right));
            }
        }
        if let [odd] = chunks.remainder() {
            next.push(hash_uer_odd_promote(odd));
        }
        level = next;
        cur_idx /= 2;
    }

    let leaf_index = u32::try_from(index).map_err(|_| UerError::IndexOutOfBounds {
        index,
        len: receipts.len(),
    })?;
    Ok(UerInclusionProof {
        receipt: target.clone(),
        leaf_index,
        total_leaves,
        steps,
    })
}

impl UerInclusionProof {
    /// Verifies that `self.receipt` is canonically committed at `leaf_index` in `expected_batch_root`.
    ///
    /// Enforces exact `(leaf_index, total_leaves)` tree geometry at every level so odd-leaf
    /// duplication (`CVE-2012-2459`), extra trailing steps, and sibling-side swaps fail closed.
    ///
    /// WIRING: called by coordinator conformance checks and light-client verifiers.
    ///
    /// # Errors
    ///
    /// Returns [`UerError`] on version mismatch, invalid index/depth geometry, or root mismatch.
    pub fn verify(&self, expected_batch_root: &[u8; 32]) -> Result<(), UerError> {
        self.receipt.validate_schema()?;
        if self.total_leaves == 0 {
            return Err(UerError::EmptyBatch);
        }
        if self.leaf_index >= self.total_leaves {
            return Err(UerError::IndexOutOfBounds {
                index: usize::try_from(self.leaf_index).unwrap_or(usize::MAX),
                len: usize::try_from(self.total_leaves).unwrap_or(usize::MAX),
            });
        }
        if self.steps.len() > MAX_UER_MERKLE_DEPTH {
            return Err(UerError::MalformedProofGeometry("proof exceeds max depth"));
        }

        let mut cur_hash = hash_uer_leaf(self.leaf_index, &self.receipt.receipt_id());
        let mut cur_idx = self.leaf_index;
        let mut cur_len = self.total_leaves;

        for step in &self.steps {
            if cur_len <= 1 {
                return Err(UerError::MalformedProofGeometry(
                    "extra proof steps after reaching root",
                ));
            }
            let is_unpaired_last = cur_idx.is_multiple_of(2) && (cur_idx + 1 == cur_len);
            match *step {
                UerMerkleStep::OddPromote => {
                    if !is_unpaired_last {
                        return Err(UerError::MalformedProofGeometry(
                            "OddPromote step permitted only on unpaired trailing node",
                        ));
                    }
                    cur_hash = hash_uer_odd_promote(&cur_hash);
                }
                UerMerkleStep::Sibling {
                    is_right_sibling,
                    hash,
                } => {
                    if is_unpaired_last {
                        return Err(UerError::MalformedProofGeometry(
                            "Sibling step forbidden on unpaired trailing node",
                        ));
                    }
                    let expected_right = cur_idx.is_multiple_of(2);
                    if is_right_sibling != expected_right {
                        return Err(UerError::MalformedProofGeometry(
                            "sibling orientation disagrees with leaf_index parity",
                        ));
                    }
                    cur_hash = if is_right_sibling {
                        hash_uer_node(&cur_hash, &hash)
                    } else {
                        hash_uer_node(&hash, &cur_hash)
                    };
                }
            }
            cur_idx /= 2;
            cur_len = cur_len.div_ceil(2);
        }

        if cur_len != 1 {
            return Err(UerError::MalformedProofGeometry(
                "truncated proof stopped before reaching single root",
            ));
        }
        if &cur_hash != expected_batch_root {
            return Err(UerError::RootMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budlum_uel_abi::EeIdentity;

    fn sample_receipt(idx: u32, ee: EeId) -> UniversalExecutionReceipt {
        let mut tx_hash = [0u8; 32];
        tx_hash[..4].copy_from_slice(&idx.to_le_bytes());
        tx_hash[31] = ee.0;
        UniversalExecutionReceipt {
            version: UER_VERSION_V1,
            chain_id: 45261,
            block_height: 100,
            tx_index: idx,
            tx_hash,
            origin_ee: ee.0,
            status: UerStatus::Success,
            gas_used_bgu: 21_000 + u64::from(idx) * 1_000,
            burned_attos: 1_000,
            security_pool_attos: 9_000,
            proposer_tip_attos: 500,
            output_digest: calculate_hash_bytes(&idx.to_le_bytes()),
            contract_address: None,
            logs_commitment: compute_uer_logs_commitment(&[(
                ee,
                EeLog {
                    emitter: EeIdentity {
                        ee,
                        id: vec![ee.0; 20],
                    },
                    topics: vec![[0xAA; 32].to_vec()],
                    data: vec![1, 2, 3],
                },
            )]),
            post_execution_root: [0x55; 32],
            zk_trace_commitment: None,
        }
    }

    #[test]
    fn optional_roots_and_every_field_bind_into_receipt_id() {
        let base = sample_receipt(0, EeId::EVM);
        let mut with_zero_contract = base.clone();
        with_zero_contract.contract_address = Some([0u8; 32]);
        assert_ne!(
            base.receipt_id(),
            with_zero_contract.receipt_id(),
            "None and Some([0; 32]) contract_address must never collide"
        );

        let mut with_zero_zk = base.clone();
        with_zero_zk.zk_trace_commitment = Some([0u8; 32]);
        assert_ne!(
            base.receipt_id(),
            with_zero_zk.receipt_id(),
            "None and Some([0; 32]) zk_trace_commitment must never collide"
        );

        let mut diff_tip = base.clone();
        diff_tip.proposer_tip_attos += 1;
        assert_ne!(base.receipt_id(), diff_tip.receipt_id());
    }

    #[test]
    fn merkle_proofs_roundtrip_and_reject_cve_2012_2459_duplication() {
        let ees = [
            EeId::BUDZERO,
            EeId::EVM,
            EeId::WASM,
            EeId::SVM,
            EeId::MOVE,
            EeId::CAIRO,
            EeId::MOVE_SUI,
        ];
        for batch_len in 1..=ees.len() {
            let batch: Vec<_> = (0..batch_len)
                .map(|i| sample_receipt(u32::try_from(i).unwrap(), ees[i]))
                .collect();
            let root = compute_uer_batch_root(&batch).unwrap();
            for idx in 0..batch_len {
                let proof = prove_uer_inclusion(&batch, idx).unwrap();
                proof.verify(&root).unwrap();

                let mut tampered = proof.clone();
                tampered.receipt.gas_used_bgu += 1;
                assert_eq!(tampered.verify(&root), Err(UerError::RootMismatch));
            }
        }

        // CVE-2012-2459 regression: [r0, r1, r2] must NEVER share a root with [r0, r1, r2, r2].
        let r0 = sample_receipt(0, EeId::EVM);
        let r1 = sample_receipt(1, EeId::WASM);
        let r2 = sample_receipt(2, EeId::SVM);
        let odd_batch = vec![r0.clone(), r1.clone(), r2.clone()];
        let dup_batch = vec![r0, r1, r2.clone(), r2];
        let odd_root = compute_uer_batch_root(&odd_batch).unwrap();
        let dup_root = compute_uer_batch_root(&dup_batch).unwrap();
        assert_ne!(
            odd_root, dup_root,
            "duplicating trailing odd receipt must never preserve batch Merkle root"
        );

        // Forging a self-sibling step in place of OddPromote on index 2 of len 3 must fail closed.
        let valid_odd_proof = prove_uer_inclusion(&odd_batch, 2).unwrap();
        let mut forged = valid_odd_proof.clone();
        let leaf2 = hash_uer_leaf(2, &valid_odd_proof.receipt.receipt_id());
        forged.steps[0] = UerMerkleStep::Sibling {
            is_right_sibling: true,
            hash: leaf2,
        };
        assert!(matches!(
            forged.verify(&odd_root),
            Err(UerError::MalformedProofGeometry(_))
        ));
    }
}
