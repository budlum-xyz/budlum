//! Pure hash-STARK state-diff, data-availability, and forced-inclusion rollup
//! finality adapter (`stark-validity-rollup-v1`).
//!
//! Targets Starknet/Cairo-class Stage-2 validity rollups as the settlement
//! counterpart to `execution/cairo`.
//!
//! A validity proof over an execution trace is necessary but not sufficient for
//! trustless rollup settlement: if a malicious sequencer proves a valid state
//! transition while withholding the state diffs (data-withholding freeze) or
//! indefinitely ignoring L1 forced-inclusion transactions (sequencer
//! censorship), users cannot reconstruct the Merkle tree to withdraw or force
//! exit. [`StarkValidityRollupAdapter`] closes all three edges under a **pure
//! hash-based post-quantum assumption** (`QuantumClass::Hash` - zero elliptic
//! curves, zero pairings, zero trusted ceremony, and zero committee votes):
//!
//! 1. **Sequential parent-state continuity.** Requires exact batch progression
//!    `batch_number == pinned.trusted_batch_number + 1` and constant-time
//!    `pre_state_root == inputs.initial_state_root == pinned.trusted_state_root`.
//! 2. **Canonical state-diff reconstruction + L1 DA binding.** Every modified
//!    `(contract_address, storage_key)` slot arrives in strictly ascending
//!    canonical order (no duplicate slots, bounded by `MAX_ROLLUP_STATE_DIFFS`),
//!    rebuilds `state_diff_root` in constant time under
//!    `BDLM_STARK_ROLLUP_DIFF_V1`, and requires a non-zero published
//!    `l1_da_blob_commitment` with positive `da_blob_count`.
//! 3. **Censorship-resistant L1 forced-inclusion queue.** Starts from
//!    `pinned.expected_forced_queue_head`, folds every consumed L1 forced
//!    transaction through `BDLM_STARK_ROLLUP_FORCED_V1` to derive
//!    `next_forced_queue_head` in constant time, and refuses any batch whose
//!    oldest unprocessed L1 forced request exceeds
//!    `pinned.max_forced_inclusion_lag_batches`.
//! 4. **Public-input binding into Plonky3 STARK.** Derives a single canonical
//!    `BDLM_STARK_ROLLUP_BATCH_V1` commitment over `(chain_id, batch_number,
//!    pre_state_root, post_state_root, state_diff_root, l1_da_blob_commitment,
//!    da_blob_count, prev_forced_queue_head, next_forced_queue_head,
//!    withdrawal_root, batch_block_hash)` and enforces constant-time equality
//!    with `inputs.sender` while requiring `inputs.final_state_root ==
//!    inputs.state_writes_digest == post_state_root` (in-circuit Poseidon
//!    storage-write chain) before verifying the transparent Goldilocks FRI
//!    STARK proof against the pinned program hash.
//! 5. **Atomic anchor progression.** [`advance_stark_rollup_anchor`] advances
//!    the trusted `(batch_number, state_root, expected_forced_queue_head)` only
//!    from a cryptographically verified batch.
//!
//! WIRING: unwired - implements `ExternalFinalityAdapter` for `ExternalDomainRegistry`, verified by `selftest::admit_observed`; `AdapterSpec` joins `intake.rs` in the follow-up merge.

use bincode::Options;
use bud_proof::{ExecutionPublicInputs, ProofEnvelope, ProverAdapter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::facts::{AssumptionClass, CryptoObserver, ObservedScheme};
use crate::domain::types::Hash32;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, ProofSystem, RawConsensusEvidence, SecurityBacking,
    TimeUnit, TrustModel, VerificationPolicy,
};

/// Canonical adapter name for pure hash-STARK state-diff validity rollups.
pub const ADAPTER_NAME: &str = "stark-validity-rollup-v1";
/// Adapter implementation version.
pub const ADAPTER_VERSION: u32 = 1;
/// Accepted wire evidence format version.
pub const EVIDENCE_VERSION: u32 = 1;
/// Hard ceiling on serialized `StarkRollupEvidence` bytes (4 MiB, covers STARK + diffs).
pub const MAX_STARK_ROLLUP_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
/// Maximum canonical storage-slot state diffs carried in one batch envelope.
pub const MAX_ROLLUP_STATE_DIFFS: usize = 4_096;
/// Maximum L1 forced-inclusion transactions dequeued in one batch envelope.
pub const MAX_FORCED_INCLUSIONS_PER_BATCH: usize = 512;

const PAYLOAD_MAGIC: &[u8; 8] = b"STKRUP01";
const TAG_ROLLUP_BATCH: &[u8] = b"BDLM_STARK_ROLLUP_BATCH_V1";
const TAG_ROLLUP_DIFF: &[u8] = b"BDLM_STARK_ROLLUP_DIFF_V1";
const TAG_ROLLUP_FORCED: &[u8] = b"BDLM_STARK_ROLLUP_FORCED_V1";

/// Governance-pinned settlement state for a pure hash-STARK validity rollup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedStarkRollupConfig {
    /// External rollup network identifier.
    pub network_id: String,
    /// Non-zero external rollup chain identifier.
    pub chain_id: u64,
    /// Pinned non-zero `BudZKVM` verifier/transition program hash.
    pub pinned_program_hash: Hash32,
    /// Last finalized rollup batch number (`batch_number == trusted + 1` required).
    pub trusted_batch_number: u64,
    /// Last finalized non-zero rollup state root.
    pub trusted_state_root: Hash32,
    /// Non-zero rolling hash head of consumed L1 forced-inclusion transactions.
    pub expected_forced_queue_head: Hash32,
    /// Maximum batches an unprocessed L1 forced transaction may wait before
    /// batch settlement is refused fail-closed.
    pub max_forced_inclusion_lag_batches: u64,
    /// Whether the proved program must also reside in the canonical program set.
    pub require_canonical_program: bool,
}

impl PinnedStarkRollupConfig {
    /// Validates all non-zero and non-empty configuration invariants.
    ///
    /// Convenience: exposed for external-domain admission and anchor updates.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::ConsensusRule`] when any pin is empty or zero.
    pub fn validate(&self) -> Result<(), AdapterError> {
        if self.network_id.trim().is_empty() {
            return Err(AdapterError::ConsensusRule {
                rule: "StarkRollup pinned network_id is empty".into(),
            });
        }
        if self.chain_id == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "StarkRollup pinned chain_id cannot be zero".into(),
            });
        }
        if bool::from(self.pinned_program_hash.ct_eq(&[0u8; 32])) {
            return Err(AdapterError::ConsensusRule {
                rule: "StarkRollup pinned_program_hash cannot be zero".into(),
            });
        }
        if bool::from(self.trusted_state_root.ct_eq(&[0u8; 32])) {
            return Err(AdapterError::ConsensusRule {
                rule: "StarkRollup trusted_state_root cannot be zero".into(),
            });
        }
        if bool::from(self.expected_forced_queue_head.ct_eq(&[0u8; 32])) {
            return Err(AdapterError::ConsensusRule {
                rule: "StarkRollup expected_forced_queue_head cannot be zero".into(),
            });
        }
        Ok(())
    }

    /// Computes a domain-separated, length-prefixed SHA3-256 commitment over
    /// every pinned rollup anchor parameter for cross-module guard, intake,
    /// and sentry pin verification.
    ///
    /// WIRING: exposed for `BridgeEconomicGuard`, `IntakeState`, and sentry pin binding.
    #[must_use]
    pub fn canonical_pin_digest(&self) -> Hash32 {
        let chain_id = self.chain_id.to_le_bytes();
        let trusted_batch = self.trusted_batch_number.to_le_bytes();
        let max_lag = self.max_forced_inclusion_lag_batches.to_le_bytes();
        let require_canonical = [u8::from(self.require_canonical_program)];
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_STARK_ROLLUP_PIN_V1",
            self.network_id.as_bytes(),
            &chain_id,
            &self.pinned_program_hash,
            &trusted_batch,
            &self.trusted_state_root,
            &self.expected_forced_queue_head,
            &max_lag,
            &require_canonical,
        ])
    }
}

/// One canonical post-batch storage-slot write published for L1 state reconstruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractStateDiff {
    /// Rollup contract address (`32`-byte field-aligned address).
    pub contract_address: Hash32,
    /// Storage slot key within `contract_address`.
    pub storage_key: Hash32,
    /// Prior committed value before this batch.
    pub previous_value: Hash32,
    /// Updated committed value after this batch (must differ from `previous_value`).
    pub new_value: Hash32,
}

/// One L1 forced-inclusion transaction dequeued and executed in a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcedInclusionEntry {
    /// Strictly increasing L1 inbox sequence number.
    pub l1_sequence: u64,
    /// Canonical L1 sender commitment.
    pub sender: Hash32,
    /// Non-zero transaction digest executed inside the batch.
    pub tx_hash: Hash32,
}

/// Deterministic batch header preceding the STARK proof bytes on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarkRollupBatchHeader {
    /// External rollup chain identifier.
    pub chain_id: u64,
    /// Sequential batch number (`trusted_batch_number + 1`).
    pub batch_number: u64,
    /// Parent state root before executing this batch.
    pub pre_state_root: Hash32,
    /// Post-batch state root after applying all transactions and forced entries.
    pub post_state_root: Hash32,
    /// Commitment over the canonical `state_diffs` list.
    pub state_diff_root: Hash32,
    /// Non-zero L1 data-availability blob root covering the compressed diffs.
    pub l1_da_blob_commitment: Hash32,
    /// Number of L1 DA blobs committed (`>= 1`).
    pub da_blob_count: u32,
    /// Forced-inclusion queue head before this batch.
    pub prev_forced_queue_head: Hash32,
    /// Forced-inclusion queue head after consuming `forced_inclusions`.
    pub next_forced_queue_head: Hash32,
    /// Age (in batches) of the oldest still-unprocessed L1 forced request (`0` when empty).
    pub oldest_pending_forced_lag: u64,
    /// Non-zero L2->L1 withdrawal / message Merkle root committed by this batch.
    pub withdrawal_root: Hash32,
    /// Non-zero canonical batch block hash.
    pub batch_block_hash: Hash32,
}

/// Complete wire payload for a pure hash-STARK validity rollup batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkRollupEvidence {
    /// Fixed-layout batch transition and DA/censorship header.
    pub header: StarkRollupBatchHeader,
    /// Strictly sorted `(contract_address, storage_key)` state-diff writes.
    pub state_diffs: Vec<ContractStateDiff>,
    /// Strictly ascending L1 forced-inclusion entries consumed in this batch.
    pub forced_inclusions: Vec<ForcedInclusionEntry>,
    /// Public inputs bound to the Plonky3 Goldilocks/FRI execution STARK.
    pub inputs: ExecutionPublicInputs,
    /// Transparent STARK proof envelope.
    pub envelope: ProofEnvelope,
    /// Verified `BudZKVM` bytecode executed to produce `envelope`.
    pub program: Vec<u64>,
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
}

/// Computes the canonical `BDLM_STARK_ROLLUP_DIFF_V1` commitment over strictly
/// ordered, non-no-op state diffs.
///
/// Convenience: exposed for rollup provers and DA reconstruction verifiers.
#[must_use]
pub fn compute_state_diff_root(diffs: &[ContractStateDiff]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(TAG_ROLLUP_DIFF);
    let len = u64::try_from(diffs.len()).unwrap_or(u64::MAX);
    h.update(len.to_le_bytes());
    for diff in diffs {
        update_len_prefixed(&mut h, &diff.contract_address);
        update_len_prefixed(&mut h, &diff.storage_key);
        update_len_prefixed(&mut h, &diff.previous_value);
        update_len_prefixed(&mut h, &diff.new_value);
    }
    h.finalize().into()
}

/// Advances the rolling L1 forced-inclusion queue head across `entries`.
///
/// Convenience: exposed for rollup sequencers and forced-exit verifiers.
#[must_use]
pub fn compute_forced_queue_head(prev_head: &Hash32, entries: &[ForcedInclusionEntry]) -> Hash32 {
    let mut head = *prev_head;
    for entry in entries {
        let mut h = Sha256::new();
        h.update(TAG_ROLLUP_FORCED);
        update_len_prefixed(&mut h, &head);
        h.update(entry.l1_sequence.to_le_bytes());
        update_len_prefixed(&mut h, &entry.sender);
        update_len_prefixed(&mut h, &entry.tx_hash);
        head = h.finalize().into();
    }
    head
}

/// Goldilocks prime field modulus `2^64 - 2^32 + 1` used by Plonky3 `BudAir`.
const GOLDILOCKS_MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

/// Projects a 32-byte [`compute_batch_da_binding`] digest onto two canonical
/// Goldilocks field elements bound into `(ExecutionPublicInputs::sender,
/// ExecutionPublicInputs::nonce)` and witnessable inside the STARK trace.
///
/// Convenience: exposed for rollup batch provers constructing public inputs.
#[must_use]
pub fn batch_binding_context_words(binding: &Hash32) -> (u64, u64) {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    if let Some((first, second)) = binding.split_at_checked(16) {
        lo.copy_from_slice(first);
        hi.copy_from_slice(second);
    }
    let w0 = u64::try_from(u128::from_le_bytes(lo) % u128::from(GOLDILOCKS_MODULUS)).unwrap_or(0);
    let w1 = u64::try_from(u128::from_le_bytes(hi) % u128::from(GOLDILOCKS_MODULUS)).unwrap_or(0);
    (w0, w1)
}

/// Computes the canonical `BDLM_STARK_ROLLUP_BATCH_V1` commitment over batch
/// roots, L1 DA blobs, forced-inclusion progression, and withdrawals.
///
/// Convenience: exposed for rollup batch provers and cross-domain verifiers.
#[must_use]
pub fn compute_batch_da_binding(header: &StarkRollupBatchHeader) -> Hash32 {
    let mut h = Sha256::new();
    h.update(TAG_ROLLUP_BATCH);
    h.update(header.chain_id.to_le_bytes());
    h.update(header.batch_number.to_le_bytes());
    update_len_prefixed(&mut h, &header.pre_state_root);
    update_len_prefixed(&mut h, &header.post_state_root);
    update_len_prefixed(&mut h, &header.state_diff_root);
    update_len_prefixed(&mut h, &header.l1_da_blob_commitment);
    h.update(header.da_blob_count.to_le_bytes());
    update_len_prefixed(&mut h, &header.prev_forced_queue_head);
    update_len_prefixed(&mut h, &header.next_forced_queue_head);
    update_len_prefixed(&mut h, &header.withdrawal_root);
    update_len_prefixed(&mut h, &header.batch_block_hash);
    h.finalize().into()
}

/// Encodes `StarkRollupEvidence` with canonical `STKRUP01` magic framing.
///
/// Convenience: exposed for rollup relayers and self-test golden builders.
///
/// # Errors
///
/// Returns [`AdapterError::Malformed`] if encoding fails or exceeds
/// [`MAX_STARK_ROLLUP_PAYLOAD_BYTES`].
pub fn encode_stark_rollup_evidence(ev: &StarkRollupEvidence) -> Result<Vec<u8>, AdapterError> {
    let body = bincode::options()
        .with_fixint_encoding()
        .serialize(ev)
        .map_err(|e| AdapterError::Malformed {
            offset: 0,
            reason: format!("StarkRollup encode failed: {e}"),
        })?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_STARK_ROLLUP_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: total,
            reason: format!(
                "StarkRollup payload is {total} bytes, above {MAX_STARK_ROLLUP_PAYLOAD_BYTES}"
            ),
        });
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decodes a `STKRUP01`-framed `StarkRollupEvidence` payload with exact bounds
/// and trailing-byte rejection.
///
/// # Errors
///
/// Returns [`AdapterError::Malformed`] on truncation, oversize, bad magic,
/// malformed/trailing bytes, or invalid STARK envelope shape.
pub fn decode_stark_rollup_evidence(payload: &[u8]) -> Result<StarkRollupEvidence, AdapterError> {
    if payload.len() < PAYLOAD_MAGIC.len() {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "StarkRollup payload shorter than 8-byte magic header".into(),
        });
    }
    if payload.len() > MAX_STARK_ROLLUP_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: payload.len(),
            reason: format!(
                "StarkRollup payload is {} bytes, above {MAX_STARK_ROLLUP_PAYLOAD_BYTES}",
                payload.len()
            ),
        });
    }
    let Some(body) = payload.strip_prefix(PAYLOAD_MAGIC) else {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "StarkRollup payload magic mismatch".into(),
        });
    };
    let limit = u64::try_from(body.len()).unwrap_or(MAX_STARK_ROLLUP_PAYLOAD_BYTES as u64);
    let decoded: StarkRollupEvidence = bincode::options()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
        .deserialize(body)
        .map_err(|e| AdapterError::Malformed {
            offset: PAYLOAD_MAGIC.len(),
            reason: format!("StarkRollup payload decode failed: {e}"),
        })?;
    decoded
        .envelope
        .validate_shape()
        .map_err(|e| AdapterError::Malformed {
            offset: PAYLOAD_MAGIC.len(),
            reason: format!("StarkRollup proof envelope shape refused: {e:?}"),
        })?;
    Ok(decoded)
}

fn verify_rollup_batch(
    pinned: &PinnedStarkRollupConfig,
    ev: &StarkRollupEvidence,
) -> Result<(), AdapterError> {
    pinned.validate()?;
    let hdr = &ev.header;

    if hdr.chain_id != pinned.chain_id || ev.inputs.chain_id != pinned.chain_id {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "StarkRollup chain_id mismatch (header={}, inputs={}, pinned={})",
                hdr.chain_id, ev.inputs.chain_id, pinned.chain_id
            ),
        });
    }
    let expected_batch =
        pinned
            .trusted_batch_number
            .checked_add(1)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "StarkRollup batch_number overflow".into(),
            })?;
    if hdr.batch_number != expected_batch || ev.inputs.block_height != expected_batch {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "StarkRollup batch_number {} / inputs {} must equal sequential {expected_batch}",
                hdr.batch_number, ev.inputs.block_height
            ),
        });
    }
    if !bool::from(hdr.pre_state_root.ct_eq(&pinned.trusted_state_root))
        || !bool::from(ev.inputs.initial_state_root.ct_eq(&hdr.pre_state_root))
    {
        return Err(AdapterError::ConsensusRule {
            rule: "StarkRollup pre_state_root breaks continuity with pinned trusted_state_root"
                .into(),
        });
    }
    if bool::from(hdr.post_state_root.ct_eq(&[0u8; 32]))
        || !bool::from(ev.inputs.final_state_root.ct_eq(&hdr.post_state_root))
        || !bool::from(ev.inputs.state_writes_digest.ct_eq(&hdr.post_state_root))
    {
        return Err(AdapterError::ConsensusRule {
            rule: "StarkRollup post_state_root is zero or mismatches STARK state-write commitment"
                .into(),
        });
    }
    if bool::from(hdr.l1_da_blob_commitment.ct_eq(&[0u8; 32])) || hdr.da_blob_count == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "StarkRollup missing published L1 data-availability blob commitment".into(),
        });
    }
    if bool::from(hdr.withdrawal_root.ct_eq(&[0u8; 32]))
        || bool::from(hdr.batch_block_hash.ct_eq(&[0u8; 32]))
    {
        return Err(AdapterError::ConsensusRule {
            rule: "StarkRollup withdrawal_root and batch_block_hash must be non-zero".into(),
        });
    }

    // Validate canonical strictly sorted, non-empty, non-trivial state diffs.
    if ev.state_diffs.is_empty() || ev.state_diffs.len() > MAX_ROLLUP_STATE_DIFFS {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "StarkRollup state_diffs count {} outside [1, {MAX_ROLLUP_STATE_DIFFS}]",
                ev.state_diffs.len()
            ),
        });
    }
    let mut prev_slot: Option<(Hash32, Hash32)> = None;
    for diff in &ev.state_diffs {
        if bool::from(diff.contract_address.ct_eq(&[0u8; 32])) {
            return Err(AdapterError::ConsensusRule {
                rule: "StarkRollup state diff targets zero contract_address".into(),
            });
        }
        if bool::from(diff.previous_value.ct_eq(&diff.new_value)) {
            return Err(AdapterError::ConsensusRule {
                rule: "StarkRollup state diff carries a no-op write (previous == new)".into(),
            });
        }
        let slot = (diff.contract_address, diff.storage_key);
        if let Some(prev) = prev_slot {
            if slot <= prev {
                return Err(AdapterError::ConsensusRule {
                    rule: "StarkRollup state_diffs must be strictly sorted with no duplicate slots"
                        .into(),
                });
            }
        }
        prev_slot = Some(slot);
    }
    let derived_diff_root = compute_state_diff_root(&ev.state_diffs);
    if !bool::from(derived_diff_root.ct_eq(&hdr.state_diff_root)) {
        return Err(AdapterError::ConsensusRule {
            rule: "StarkRollup derived state_diff_root mismatches batch header".into(),
        });
    }

    // Validate censorship-resistant L1 forced-inclusion queue progression.
    if ev.forced_inclusions.len() > MAX_FORCED_INCLUSIONS_PER_BATCH {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "StarkRollup forced_inclusions count {} exceeds {MAX_FORCED_INCLUSIONS_PER_BATCH}",
                ev.forced_inclusions.len()
            ),
        });
    }
    if hdr.oldest_pending_forced_lag > pinned.max_forced_inclusion_lag_batches {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "StarkRollup oldest pending L1 forced inclusion lagged {} batches, above max {}",
                hdr.oldest_pending_forced_lag, pinned.max_forced_inclusion_lag_batches
            ),
        });
    }
    if !bool::from(
        hdr.prev_forced_queue_head
            .ct_eq(&pinned.expected_forced_queue_head),
    ) {
        return Err(AdapterError::ConsensusRule {
            rule: "StarkRollup prev_forced_queue_head mismatches pinned L1 inbox head".into(),
        });
    }
    let mut prev_seq: Option<u64> = None;
    for entry in &ev.forced_inclusions {
        if bool::from(entry.sender.ct_eq(&[0u8; 32])) || bool::from(entry.tx_hash.ct_eq(&[0u8; 32]))
        {
            return Err(AdapterError::ConsensusRule {
                rule: "StarkRollup forced-inclusion entry carries zero sender or tx_hash".into(),
            });
        }
        if let Some(prev) = prev_seq {
            if entry.l1_sequence <= prev {
                return Err(AdapterError::ConsensusRule {
                    rule: "StarkRollup forced_inclusions must have strictly increasing l1_sequence"
                        .into(),
                });
            }
        }
        prev_seq = Some(entry.l1_sequence);
    }
    let derived_next_queue =
        compute_forced_queue_head(&hdr.prev_forced_queue_head, &ev.forced_inclusions);
    if !bool::from(derived_next_queue.ct_eq(&hdr.next_forced_queue_head)) {
        return Err(AdapterError::ConsensusRule {
            rule: "StarkRollup next_forced_queue_head mismatches consumed L1 forced entries".into(),
        });
    }

    // Bind the full 256-bit batch + DA + forced-queue commitment into the
    // canonical Goldilocks `(sender, nonce)` STARK public-input slots.
    let expected_binding = compute_batch_da_binding(hdr);
    let (expected_sender, expected_nonce) = batch_binding_context_words(&expected_binding);
    let sender_ok = bool::from(
        ev.inputs
            .sender
            .to_le_bytes()
            .ct_eq(&expected_sender.to_le_bytes()),
    );
    let nonce_ok = bool::from(
        ev.inputs
            .nonce
            .to_le_bytes()
            .ct_eq(&expected_nonce.to_le_bytes()),
    );
    if !sender_ok || !nonce_ok {
        return Err(AdapterError::ConsensusRule {
            rule:
                "StarkRollup STARK public-input commitment does not bind batch DA and forced queue"
                    .into(),
        });
    }

    // Cheap execution-input, activation, and program checks before FRI verification.
    if ev.inputs.exit_code != 0 {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "StarkRollup execution exited with non-zero code {}",
                ev.inputs.exit_code
            ),
        });
    }
    if ev.inputs.gas_used > ev.inputs.gas_limit {
        return Err(AdapterError::ConsensusRule {
            rule: "StarkRollup gas_used exceeds gas_limit".into(),
        });
    }
    if ev.inputs.trace_len == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "StarkRollup trace_len cannot be zero".into(),
        });
    }
    if crate::prover::is_empty_or_halt_only_program(&ev.program) {
        return Err(AdapterError::ConsensusRule {
            rule: "StarkRollup refuses empty or bare Halt program".into(),
        });
    }
    if ev.program.iter().any(|&raw| {
        bud_isa::Instruction::decode_for_mainnet(raw, bud_isa::MainnetActivation::default())
            .is_err()
    }) {
        return Err(AdapterError::ConsensusRule {
            rule: "StarkRollup refuses invalid or staged non-mainnet instruction".into(),
        });
    }
    let derived_prog_hash = bud_proof::canonical_set::program_hash_of(&ev.program);
    if !bool::from(ev.inputs.program_hash.ct_eq(&pinned.pinned_program_hash))
        || !bool::from(derived_prog_hash.ct_eq(&pinned.pinned_program_hash))
    {
        return Err(AdapterError::ConsensusRule {
            rule: "StarkRollup program_hash mismatches pinned rollup verifier program".into(),
        });
    }

    if pinned.require_canonical_program {
        bud_proof::DefaultAdapter::verify_canonical_program(&ev.envelope, &ev.inputs, &ev.program)
            .map_err(|e| AdapterError::Crypto {
                what: format!("StarkRollup canonical Plonky3 STARK verification failed: {e:?}"),
            })?;
    } else {
        <bud_proof::DefaultAdapter as ProverAdapter>::verify(&ev.envelope, &ev.inputs, &ev.program)
            .map_err(|e| AdapterError::Crypto {
                what: format!("StarkRollup Plonky3 STARK verification failed: {e:?}"),
            })?;
    }
    Ok(())
}

/// Verifies `ev` against `pinned` and returns the advanced rollup anchor for
/// the next sequential batch (`batch_number + 1`).
///
/// Convenience: exposed for stateful rollup bridge anchor progression.
///
/// # Errors
///
/// Returns [`AdapterError`] if any continuity, DA, forced-inclusion, or STARK
/// check fails.
pub fn advance_stark_rollup_anchor(
    pinned: &PinnedStarkRollupConfig,
    ev: &StarkRollupEvidence,
) -> Result<PinnedStarkRollupConfig, AdapterError> {
    verify_rollup_batch(pinned, ev)?;
    let mut next = pinned.clone();
    next.trusted_batch_number = ev.header.batch_number;
    next.trusted_state_root = ev.header.post_state_root;
    next.expected_forced_queue_head = ev.header.next_forced_queue_head;
    Ok(next)
}

/// External finality adapter for pure hash-STARK state-diff validity rollups.
pub struct StarkValidityRollupAdapter {
    descriptor: AdapterDescriptor,
    network: String,
    pinned: Option<PinnedStarkRollupConfig>,
    golden: Option<RawConsensusEvidence>,
}

impl StarkValidityRollupAdapter {
    /// Constructs a pure hash-STARK validity rollup adapter for `network`.
    /// Passing `None` leaves admission fail-closed.
    ///
    /// Convenience: exposed for external-domain registration and settlement.
    #[must_use]
    pub fn new(network: &str, pinned: Option<PinnedStarkRollupConfig>) -> Self {
        Self {
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name(ADAPTER_NAME),
                name: ADAPTER_NAME.to_string(),
                adapter_version: ADAPTER_VERSION,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "stark-state-diff-validity-rollup".to_string(),
                finality_kind: FinalityKind::Proven,
                required_depth: 0,
                time_unit: TimeUnit::Height,
                trust_model: TrustModel::Trustless,
            },
            network: network.to_string(),
            pinned,
            golden: None,
        }
    }

    /// Attaches a golden evidence bundle for [`super::selftest::admit_observed`].
    ///
    /// Convenience: exposed for self-test admission harnesses.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }
}

impl ExternalFinalityAdapter for StarkValidityRollupAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        let mut sink = crate::crypto::facts::NullObserver;
        self.verify_observed(evidence, policy, &mut sink)
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: "foreign-adapter".to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::WrongAdapter {
                expected: self.network.clone(),
                found: evidence.network.clone(),
            });
        }
        if evidence.evidence_version != EVIDENCE_VERSION {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: EVIDENCE_VERSION.to_string(),
            });
        }

        let ev = decode_stark_rollup_evidence(&evidence.payload)?;

        if policy.require_declared_match {
            if evidence.declared_height != ev.header.batch_number {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&ev.header.post_state_root)) {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }
        if policy.min_depth > 0 {
            return Err(AdapterError::Unavailable {
                reason: "a proven STARK rollup batch has zero confirmation depth".into(),
            });
        }
        if policy.require_slashable {
            return Err(AdapterError::UnslashableBacking);
        }
        if policy.max_age > 0 {
            if ev.header.batch_number > policy.now {
                return Err(AdapterError::Stale {
                    age: ev.header.batch_number - policy.now,
                    max_age: policy.max_age,
                });
            }
            let age = policy.now - ev.header.batch_number;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let Some(pinned) = self.pinned.as_ref() else {
            return Err(AdapterError::ConsensusRule {
                rule: "StarkRollup configuration is not pinned; admission is closed".into(),
            });
        };
        if pinned.network_id != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: "StarkRollup pinned network_id mismatches adapter network".into(),
            });
        }

        verify_rollup_batch(pinned, &ev)?;
        observer.observe(ObservedScheme::Proof(AssumptionClass::Hash));

        Ok(FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: ev.header.batch_number,
            state_root: ev.header.post_state_root,
            finalized_at: ev.header.batch_number,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::Zk {
                system: ProofSystem::BudlumZkVm,
                public_inputs_digest: ev.envelope.public_inputs_hash,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(ev.header.batch_block_hash),
            attested_event_root: Some(ev.header.withdrawal_root),
            attested_tx_root: Some(ev.header.state_diff_root),
        })
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        // Fixed byte offsets inside STKRUP01 + fixint StarkRollupBatchHeader:
        // [0..8]     = magic "STKRUP01"
        // [8..16]    = chain_id
        // [16..24]   = batch_number
        // [24..56]   = pre_state_root
        // [56..88]   = post_state_root
        // [88..120]  = state_diff_root
        // [120..152] = l1_da_blob_commitment
        // [152..156] = da_blob_count
        vec![
            FaultProbe {
                name: "empty payload refused as malformed".into(),
                patch: BytePatch::TruncatePayload { keep: 0 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "corrupt framing magic refused before decode".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: b"NOTSTARK".to_vec(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "wrong rollup chain id refused before STARK verify".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: 0xDEAD_BEEFu64.to_le_bytes().to_vec(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "broken parent state-root continuity refused".into(),
                patch: BytePatch::InPayload {
                    offset: 24,
                    bytes: vec![0xCC; 8],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "withheld zero L1 DA blob commitment refused".into(),
                patch: BytePatch::InPayload {
                    offset: 120,
                    bytes: vec![0x00; 32],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "tampered state-diff root refused".into(),
                patch: BytePatch::InPayload {
                    offset: 88,
                    bytes: vec![0xAB; 8],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "lying declared post-state root refused".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "unsupported evidence version refused".into(),
                patch: BytePatch::EvidenceVersion { value: 7 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::cross_domain::external::selftest::admit_observed;
    use crate::crypto::facts::{CryptoFacts, QuantumClass};

    use bud_isa::{Instruction, Opcode};
    use bud_vm::syscall_context::{SYSCALL_BLOCK_HEIGHT, SYSCALL_NONCE, SYSCALL_SENDER};

    fn rollup_transition_program() -> Vec<u64> {
        let enc = |opcode, rd, rs1, rs2, imm| {
            Instruction {
                opcode,
                rd,
                rs1,
                rs2,
                imm,
            }
            .encode()
        };
        // Reads pre-seeded parent word r4 (commits non-zero initial_state_root),
        // binds SYSCALL_SENDER + SYSCALL_NONCE (full 256-bit batch DA & forced
        // queue commitment projected into Goldilocks) and SYSCALL_BLOCK_HEIGHT
        // (sequential batch number), writes updated rollup slot via SWrite
        // (commits non-zero Poseidon state_writes_digest / post_state_root), halts.
        vec![
            enc(Opcode::Log, 0, 4, 0, 0),
            enc(Opcode::Syscall, 1, 0, 0, SYSCALL_SENDER),
            enc(Opcode::Syscall, 2, 0, 0, SYSCALL_BLOCK_HEIGHT),
            enc(Opcode::Syscall, 3, 0, 0, SYSCALL_NONCE),
            enc(Opcode::Add, 5, 4, 2, 0),
            enc(Opcode::SWrite, 0, 5, 0, 7),
            enc(Opcode::Log, 0, 1, 0, 0),
            enc(Opcode::Log, 0, 3, 0, 0),
            enc(Opcode::Halt, 0, 0, 0, 0),
        ]
    }

    const PARENT_SEED_WORD: u64 = 0xC0FF_EE42;

    fn prove_rollup_batch(
        pinned: &PinnedStarkRollupConfig,
        diffs: Vec<ContractStateDiff>,
        forced: Vec<ForcedInclusionEntry>,
        pending_lag: u64,
    ) -> (StarkRollupEvidence, RawConsensusEvidence) {
        let program = rollup_transition_program();
        let program_hash = bud_proof::canonical_set::program_hash_of(&program);
        let batch_number = pinned.trusted_batch_number + 1;

        // First dry-run derives exact AIR-constrained pre and post state roots.
        let mut dry = bud_vm::Vm::new(4096);
        dry.registers[4] = PARENT_SEED_WORD;
        dry.context.block_height = batch_number;
        let dry_receipt = dry.run_receipt(&program);
        assert!(dry_receipt.success);
        let pre_root = bud_proof::initial_state_root_of(
            bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(
                &dry.trace,
            )),
            bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
                &dry.trace,
            )),
        );
        let post_root = dry_receipt.state_writes_digest;
        assert_ne!(pre_root, [0u8; 32]);
        assert_ne!(post_root, [0u8; 32]);
        assert_eq!(pre_root, pinned.trusted_state_root);

        let state_diff_root = compute_state_diff_root(&diffs);
        let next_queue = compute_forced_queue_head(&pinned.expected_forced_queue_head, &forced);
        let header = StarkRollupBatchHeader {
            chain_id: pinned.chain_id,
            batch_number,
            pre_state_root: pre_root,
            post_state_root: post_root,
            state_diff_root,
            l1_da_blob_commitment: [0xD4; 32],
            da_blob_count: 2,
            prev_forced_queue_head: pinned.expected_forced_queue_head,
            next_forced_queue_head: next_queue,
            oldest_pending_forced_lag: pending_lag,
            withdrawal_root: [0xE1; 32],
            batch_block_hash: [0xB7; 32],
        };
        let batch_binding = compute_batch_da_binding(&header);
        let (sender_word, nonce_word) = batch_binding_context_words(&batch_binding);

        // Execute with `(sender, nonce) = batch_binding_context_words` so the
        // AIR trace witnesses the exact batch DA + forced-inclusion commitment.
        let mut vm = bud_vm::Vm::new(4096);
        vm.registers[4] = PARENT_SEED_WORD;
        vm.context.sender = sender_word;
        vm.context.nonce = nonce_word;
        vm.context.block_height = batch_number;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);

        let inputs = ExecutionPublicInputs {
            chain_id: pinned.chain_id,
            program_hash,
            initial_state_root: pre_root,
            final_state_root: post_root,
            sender: sender_word,
            nonce: nonce_word,
            block_height: batch_number,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: u64::try_from(vm.trace.len()).expect("fits u64"),
            event_digest: bud_proof::event_digest_from_events(&receipt.events),
            state_writes_digest: post_root,
        };
        let envelope =
            bud_proof::DefaultAdapter::prove(&vm.trace, &inputs, &program).expect("STARK proves");
        let ev = StarkRollupEvidence {
            header,
            state_diffs: diffs,
            forced_inclusions: forced,
            inputs,
            envelope,
            program,
        };
        let payload = encode_stark_rollup_evidence(&ev).expect("encodes");
        let raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: pinned.network_id.clone(),
            payload,
            declared_height: batch_number,
            declared_root: post_root,
            submitter: Address([0x55; 32]),
        };
        (ev, raw)
    }

    fn base_config() -> PinnedStarkRollupConfig {
        let program = rollup_transition_program();
        let program_hash = bud_proof::canonical_set::program_hash_of(&program);
        let mut vm = bud_vm::Vm::new(4096);
        vm.registers[4] = PARENT_SEED_WORD;
        vm.context.block_height = 42;
        let _ = vm.run_receipt(&program);
        let initial_state_root = bud_proof::initial_state_root_of(
            bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(
                &vm.trace,
            )),
            bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
                &vm.trace,
            )),
        );
        PinnedStarkRollupConfig {
            network_id: "stark-rollup-testnet".to_string(),
            chain_id: 393_216,
            pinned_program_hash: program_hash,
            trusted_batch_number: 41,
            trusted_state_root: initial_state_root,
            expected_forced_queue_head: [0xF0; 32],
            max_forced_inclusion_lag_batches: 4,
            require_canonical_program: false,
        }
    }

    #[test]
    fn stark_validity_rollup_passes_selftest_and_observes_pure_hash_post_quantum() {
        let pinned = base_config();
        let diffs = vec![
            ContractStateDiff {
                contract_address: [0x01; 32],
                storage_key: [0x10; 32],
                previous_value: [0x00; 32],
                new_value: [0x44; 32],
            },
            ContractStateDiff {
                contract_address: [0x01; 32],
                storage_key: [0x11; 32],
                previous_value: [0x05; 32],
                new_value: [0x09; 32],
            },
        ];
        let forced = vec![ForcedInclusionEntry {
            l1_sequence: 7,
            sender: [0xA1; 32],
            tx_hash: [0xA2; 32],
        }];
        let (ev, raw) = prove_rollup_batch(&pinned, diffs, forced, 2);
        let expected_post_root = ev.header.post_state_root;
        let adapter = StarkValidityRollupAdapter::new("stark-rollup-testnet", Some(pinned.clone()))
            .with_golden(raw.clone());

        let (report, facts) = admit_observed(&adapter, &VerificationPolicy::proven(45));
        assert!(report.admitted, "admission must pass: {report:#?}");
        assert_eq!(report.passed(), 8);
        assert_eq!(facts.quantum_class(), Some(QuantumClass::Hash));

        let mut verify_facts = CryptoFacts::new();
        let att = adapter
            .verify_observed(&raw, &VerificationPolicy::proven(45), &mut verify_facts)
            .expect("verifies");
        assert_eq!(att.height, 42);
        assert_eq!(att.state_root, expected_post_root);
        assert_eq!(att.attested_block_hash, Some(ev.header.batch_block_hash));
        assert_eq!(att.attested_event_root, Some(ev.header.withdrawal_root));
        assert_eq!(att.attested_tx_root, Some(ev.header.state_diff_root));

        let advanced = advance_stark_rollup_anchor(&pinned, &ev).expect("advances");
        assert_eq!(advanced.trusted_batch_number, 42);
        assert_eq!(advanced.trusted_state_root, expected_post_root);
        assert_eq!(
            advanced.expected_forced_queue_head,
            ev.header.next_forced_queue_head
        );
    }

    #[test]
    fn stark_validity_rollup_rejects_censorship_lag_unsorted_diffs_and_forged_queue() {
        let pinned = base_config();
        let good_diffs = vec![
            ContractStateDiff {
                contract_address: [0x02; 32],
                storage_key: [0x01; 32],
                previous_value: [0x00; 32],
                new_value: [0x11; 32],
            },
            ContractStateDiff {
                contract_address: [0x02; 32],
                storage_key: [0x02; 32],
                previous_value: [0x00; 32],
                new_value: [0x22; 32],
            },
        ];
        let forced = vec![ForcedInclusionEntry {
            l1_sequence: 1,
            sender: [0xB1; 32],
            tx_hash: [0xB2; 32],
        }];
        let (ev, raw_valid) = prove_rollup_batch(&pinned, good_diffs, forced, 1);
        let post_root = ev.header.post_state_root;
        let adapter = StarkValidityRollupAdapter::new("stark-rollup-testnet", Some(pinned));
        let policy = VerificationPolicy::proven(50);

        // 0a. Unslashable STARK rollup must fail closed when require_slashable is set.
        let mut slash_policy = policy.clone();
        slash_policy.require_slashable = true;
        assert!(matches!(
            adapter.verify(&raw_valid, &slash_policy),
            Err(AdapterError::UnslashableBacking)
        ));

        // 0b. Future batch_number (> policy.now) must fail closed under max_age > 0, never saturate to age 0.
        let mut future_policy = VerificationPolicy::proven(10);
        future_policy.max_age = 5;
        assert!(matches!(
            adapter.verify(&raw_valid, &future_policy),
            Err(AdapterError::Stale {
                age: 32,
                max_age: 5
            })
        ));

        // 1. Sequencer stalling oldest L1 forced inclusion past max lag is refused.
        let mut censored = ev.clone();
        censored.header.oldest_pending_forced_lag = 5;
        let raw_censored = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "stark-rollup-testnet".to_string(),
            payload: encode_stark_rollup_evidence(&censored).expect("encodes"),
            declared_height: 42,
            declared_root: post_root,
            submitter: Address([1; 32]),
        };
        assert!(matches!(
            adapter.verify(&raw_censored, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // 2. Unsorted / swapped state diffs are refused before STARK verification.
        let mut unsorted = ev.clone();
        unsorted.state_diffs.swap(0, 1);
        let raw_unsorted = RawConsensusEvidence {
            payload: encode_stark_rollup_evidence(&unsorted).expect("encodes"),
            ..raw_censored.clone()
        };
        assert!(matches!(
            adapter.verify(&raw_unsorted, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // 3. Omitting a consumed forced-inclusion tx breaks next_forced_queue_head.
        let mut skipped = ev;
        skipped.forced_inclusions.clear();
        let raw_skipped = RawConsensusEvidence {
            payload: encode_stark_rollup_evidence(&skipped).expect("encodes"),
            ..raw_censored
        };
        assert!(matches!(
            adapter.verify(&raw_skipped, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }
}
