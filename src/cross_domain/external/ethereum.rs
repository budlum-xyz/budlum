//! The first concrete adapter: an Ethereum-type `PoS` chain, verified through its
//! Altair sync committee.
//!
//! WIRING: wired - this adapter goes live through an admission into the
//! external-domain registry, bound to consensus in
//! `AccountState::settlement` and written by the `ExternalDomain`
//! transaction door (`AdapterSpec::EthereumSync` builds it, the node's
//! `PairingBls` supplies the pairing check). The executor still
//! refuses generic Ethereum relay results (`relayer_evm_package_required`):
//! relay execution and finality attestation are different powers, and this
//! wiring grants only the second.
//!
//! # What the sync committee gives us, and what it does not
//!
//! A sync committee is 512 validators, resampled every 256 epochs (about 27
//! hours), who sign the recent block header with BLS12-381 keys. Their
//! signatures aggregate into one, so a light client can check "a supermajority
//! of the current committee signed this header" with one pairing instead of
//! 512. That is a real, cheap, widely-deployed proof, and it is what Helios,
//! Telepathy and the SP1 light client all verify.
//!
//! What it does not give us is **slashability**. Altair defines no slashing
//! condition for sync committee messages. A committee that signs a header for a
//! chain that does not exist loses nothing. The honest statement of this
//! adapter's security is therefore "an honest majority of a 512-validator
//! sample, with no economic penalty for dishonesty" - and that is exactly what
//! [`SecurityBacking::SignatureSet`] carries, with `slashable: false`. A
//! consumer who needs slashable finality should look at a proof over the full
//! validator set instead, and can now tell the two apart without reading
//! anybody's prose.
//!
//! # Finality depth
//!
//! Casper FFG finalises a checkpoint once two consecutive epochs justify it,
//! which in practice is around 12.8 minutes at 32 slots per epoch and 12
//! seconds per slot. This adapter requires the *finalized* header, not the
//! attested one, and refuses anything that only reaches justification - a
//! justified checkpoint can still be reverted by a conflicting finalisation.
//!
//! # The BLS dependency
//!
//! Verifying the aggregate signature needs BLS12-381 pairing arithmetic against
//! the beacon chain's domain-separated signing root. This module does not
//! implement that; it takes a [`BlsVerifier`] and refuses with
//! [`AdapterError::Unavailable`] when none is installed. Refusing is the
//! behaviour here, not an approximation: an adapter that skipped the pairing
//! check would accept a committee of one signature, and nothing downstream
//! could tell.

use crate::cross_domain::external::selftest::{
    BytePatch, ExpectedRefusal, FaultProbe, RefusalKind,
};
use crate::cross_domain::external::spec::{
    AdapterDescriptor, AdapterError, AdapterId, FinalityAttestation, FinalityKind, ProofSystem,
    RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel, VerificationPolicy,
};
use crate::crypto::facts::{CryptoObserver, NullObserver, ObservedScheme};
use crate::crypto::scheme::SchemeId;
use serde::{Deserialize, Serialize};

/// `SYNC_COMMITTEE_SIZE` in the Altair preset: 2**9.
pub const SYNC_COMMITTEE_SIZE: u64 = 512;
/// `EPOCHS_PER_SYNC_COMMITTEE_PERIOD`: 2**8, about 27 hours.
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;
/// `SLOTS_PER_EPOCH` on mainnet.
pub const SLOTS_PER_EPOCH: u64 = 32;
/// The participation bitvector is one bit per committee member.
pub const BITVECTOR_BYTES: usize = (SYNC_COMMITTEE_SIZE / 8) as usize;

/// The 2/3 threshold, written as an inequality rather than a number.
///
/// The spec's rule is `sum(bits) * 3 >= SYNC_COMMITTEE_SIZE * 2`, which for 512
/// means at least 342 signers. Computing `512 * 2 / 3 = 341` and comparing with
/// `>=` would admit 341, which is below the spec's threshold - an off-by-one
/// here is a supermajority that is not one. The inequality is kept in the code
/// so the rounding question never has to be answered.
#[must_use]
pub fn has_supermajority(signers: u64) -> bool {
    signers.saturating_mul(3) >= SYNC_COMMITTEE_SIZE.saturating_mul(2)
}

/// The smallest signer count that satisfies the threshold. Exposed so a test
/// can sit exactly on the boundary instead of near it.
#[must_use]
pub fn minimum_signers() -> u64 {
    (0..=SYNC_COMMITTEE_SIZE)
        .find(|n| has_supermajority(*n))
        .unwrap_or(SYNC_COMMITTEE_SIZE)
}

/// Counts set bits. `u32::count_ones` over each byte; written out rather than
/// using a table because the loop is six lines and a table is a thing to keep
/// in sync.
#[must_use]
pub fn participation(bits: &[u8]) -> u64 {
    bits.iter().map(|b| u64::from(b.count_ones())).sum()
}

/// Slot to epoch.
#[must_use]
pub fn epoch_of_slot(slot: u64) -> u64 {
    slot / SLOTS_PER_EPOCH
}

/// Slot to sync committee period.
#[must_use]
pub fn period_of_slot(slot: u64) -> u64 {
    epoch_of_slot(slot) / EPOCHS_PER_SYNC_COMMITTEE_PERIOD
}

/// The BLS check, injected.
///
/// A trait rather than a direct call so this adapter can be tested without
/// pairing arithmetic, and so a build without the dependency fails loudly at
/// construction instead of quietly at verification.
pub trait BlsVerifier: Send + Sync {
    /// Verifies an aggregate signature against an aggregate public key.
    ///
    /// `signing_root` is the beacon chain's domain-separated signing root;
    /// constructing it is the caller's job and is the part most often got
    /// wrong, which is why it is a parameter and not something this module
    /// derives from a slot number it was handed.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn verify_aggregate(
        &self,
        signing_root: &[u8; 32],
        aggregate_pubkey: &[u8],
        signature: &[u8],
        participants: u64,
    ) -> Result<(), String>;

    /// Whether Ethereum sync-committee finality is closed on this verifier's
    /// network boundary. Defaults to fail-closed (`true`); real verifiers
    /// that pair with [`EthereumSyncAdapter`]'s SSZ finality-branch check
    /// override this to `false`.
    fn sync_committee_closed(&self) -> bool {
        true
    }
}

/// The payload layout. Fixed offsets, declared as constants, because a parser
/// whose offsets live inline in the code cannot be probed by offset - and
/// probing by offset is the whole admission model.
pub mod layout {
    /// 32 bytes: the finalized header's hash tree root.
    pub const FINALIZED_ROOT: std::ops::Range<usize> = 0..32;
    /// 8 bytes, little endian: the finalized slot.
    pub const FINALIZED_SLOT: std::ops::Range<usize> = 32..40;
    /// 8 bytes, little endian: the attested slot.
    pub const ATTESTED_SLOT: std::ops::Range<usize> = 40..48;
    /// 8 bytes, little endian: the period this update belongs to.
    pub const PERIOD: std::ops::Range<usize> = 48..56;
    /// 32 bytes: the next sync committee's root, so the committee can be
    /// rotated forward without trusting a fresh source.
    pub const NEXT_COMMITTEE_ROOT: std::ops::Range<usize> = 56..88;
    /// 96 bytes: the aggregate public key (BLS12-381 G1).
    pub const AGGREGATE_PUBKEY: std::ops::Range<usize> = 88..184;
    /// 96 bytes: the aggregate signature (BLS12-381 G2).
    pub const SIGNATURE: std::ops::Range<usize> = 184..280;
    /// 64 bytes: one bit per committee member.
    pub const PARTICIPATION_BITS: std::ops::Range<usize> = 280..344;
    /// 32 bytes: the finalized state root - the thing Budlum actually commits
    /// to. Distinct from the header root above: a consumer that wanted the
    /// header root is reading the wrong field.
    pub const STATE_ROOT: std::ops::Range<usize> = 344..376;
    /// 8 bytes, little endian: finalized `BeaconBlockHeader.proposer_index`.
    pub const FINALIZED_PROPOSER_INDEX: std::ops::Range<usize> = 376..384;
    /// 32 bytes: finalized `BeaconBlockHeader.parent_root`.
    pub const FINALIZED_PARENT_ROOT: std::ops::Range<usize> = 384..416;
    /// 32 bytes: finalized `BeaconBlockHeader.body_root`.
    pub const FINALIZED_BODY_ROOT: std::ops::Range<usize> = 416..448;
    /// 8 bytes, little endian: attested `BeaconBlockHeader.proposer_index`.
    pub const ATTESTED_PROPOSER_INDEX: std::ops::Range<usize> = 448..456;
    /// 32 bytes: attested `BeaconBlockHeader.parent_root`.
    pub const ATTESTED_PARENT_ROOT: std::ops::Range<usize> = 456..488;
    /// 32 bytes: attested `BeaconBlockHeader.state_root`.
    pub const ATTESTED_STATE_ROOT: std::ops::Range<usize> = 488..520;
    /// 32 bytes: attested `BeaconBlockHeader.body_root`.
    pub const ATTESTED_BODY_ROOT: std::ops::Range<usize> = 520..552;
    /// 8 bytes, little endian: generalized index of `finalized_checkpoint.root`
    /// (`105` Deneb / `169` Electra).
    pub const FINALIZED_ROOT_GINDEX: std::ops::Range<usize> = 552..560;
    /// Byte offset where `finality_branch` siblings begin.
    pub const FINALITY_BRANCH_OFFSET: usize = 560;
    /// Total payload length for Deneb (6-sibling finality branch).
    pub const LEN: usize = 752;
    /// Total payload length for Electra (7-sibling finality branch).
    pub const LEN_ELECTRA: usize = 784;
    /// Fixed binary length of the v3 execution extension appended after a
    /// Deneb (`LEN`) or Electra (`LEN_ELECTRA`) beacon finality payload:
    /// 4 x 32B `execution_branch` (`gindex = 25`, 128B) + 17-field
    /// `ExecutionPayloadHeader` (`613`B) = `741` bytes.
    /// Convenience: exposed for v3 Deneb/Electra execution finality payloads.
    pub const EXECUTION_TRAILER_LEN: usize = 128 + 613;
    /// Total v3 Deneb payload length (`752 + 741 = 1493` bytes).
    /// Convenience: exposed for v3 Deneb execution finality framing.
    pub const LEN_V3_DENEB: usize = LEN + EXECUTION_TRAILER_LEN;
    /// Total v3 Electra payload length (`784 + 741 = 1525` bytes).
    /// Convenience: exposed for v3 Electra execution finality framing.
    pub const LEN_V3_ELECTRA: usize = LEN_ELECTRA + EXECUTION_TRAILER_LEN;
}

/// Parsed v3 Deneb/Electra finality update carrying both the Beacon finality
/// proof and the 17-field SSZ `ExecutionPayloadHeader` proven at body gindex `25`.
///
/// Convenience: exposed for Ethereum execution finality verification and tooling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSyncCommitteeUpdate {
    pub beacon: SyncCommitteeUpdate,
    pub execution_branch: [[u8; 32]; 4],
    pub execution_payload: crate::cross_domain::evm::sync_committee::ExecutionPayloadHeader,
}

/// Encode the fixed-size 721-byte execution trailer (`execution_branch` +
/// 17-field `ExecutionPayloadHeader`) for evidence format v3.
///
/// Convenience: exposed for Ethereum v3 execution evidence builders.
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] if `execution_payload` fails
/// consensus validation (`logs_bloom != 256B`, `extra_data > 32B`,
/// `gas_used > gas_limit`, or zero root/hash).
pub fn encode_execution_trailer_v3(
    execution_branch: &[[u8; 32]; 4],
    payload: &crate::cross_domain::evm::sync_committee::ExecutionPayloadHeader,
) -> Result<Vec<u8>, AdapterError> {
    payload
        .validate()
        .map_err(|e| AdapterError::ConsensusRule {
            rule: e.to_string(),
        })?;
    let mut out = Vec::with_capacity(layout::EXECUTION_TRAILER_LEN);
    for sib in execution_branch {
        out.extend_from_slice(sib);
    }
    out.extend_from_slice(&payload.parent_hash); // 32
    out.extend_from_slice(&payload.fee_recipient); // 20
    out.extend_from_slice(&payload.state_root); // 32
    out.extend_from_slice(&payload.receipts_root); // 32
    out.extend_from_slice(&payload.logs_bloom); // 256
    out.extend_from_slice(&payload.prev_randao); // 32
    out.extend_from_slice(&payload.block_number.to_le_bytes()); // 8
    out.extend_from_slice(&payload.gas_limit.to_le_bytes()); // 8
    out.extend_from_slice(&payload.gas_used.to_le_bytes()); // 8
    out.extend_from_slice(&payload.timestamp.to_le_bytes()); // 8
    let extra_len =
        u8::try_from(payload.extra_data.len()).map_err(|_| AdapterError::ConsensusRule {
            rule: "execution extra_data exceeds 32 bytes".to_string(),
        })?;
    out.push(extra_len); // 1
    let mut extra_buf = [0u8; 32];
    if let Some(dst) = extra_buf.get_mut(..payload.extra_data.len()) {
        dst.copy_from_slice(&payload.extra_data);
    }
    out.extend_from_slice(&extra_buf); // 32
    out.extend_from_slice(&payload.base_fee_per_gas); // 32
    out.extend_from_slice(&payload.block_hash); // 32
    out.extend_from_slice(&payload.transactions_root); // 32
    out.extend_from_slice(&payload.withdrawals_root); // 32
    out.extend_from_slice(&payload.blob_gas_used.to_le_bytes()); // 8
    out.extend_from_slice(&payload.excess_blob_gas.to_le_bytes()); // 8
    Ok(out)
}

/// Parse an evidence-format v3 payload (`LEN_V3_DENEB` or `LEN_V3_ELECTRA`)
/// into its Beacon finality proof and 17-field `ExecutionPayloadHeader`.
///
/// Convenience: exposed for Ethereum v3 execution evidence verification.
///
/// # Errors
///
/// Returns [`AdapterError::Malformed`] if any length, gindex, or non-zero
/// `extra_data` padding rule is violated.
pub fn parse_execution_update_v3(
    payload: &[u8],
) -> Result<ExecutionSyncCommitteeUpdate, AdapterError> {
    let beacon_len = match payload.len() {
        layout::LEN_V3_DENEB => layout::LEN,
        layout::LEN_V3_ELECTRA => layout::LEN_ELECTRA,
        other => {
            return Err(AdapterError::Malformed {
                offset: other,
                reason: format!(
                    "v3 execution payload is {other} bytes, expected {} (Deneb) or {} (Electra)",
                    layout::LEN_V3_DENEB,
                    layout::LEN_V3_ELECTRA
                ),
            });
        }
    };
    let beacon_slice = payload.get(..beacon_len).ok_or(AdapterError::Malformed {
        offset: 0,
        reason: "beacon prefix missing".to_string(),
    })?;
    let beacon = parse_update(beacon_slice)?;
    let trailer = payload.get(beacon_len..).ok_or(AdapterError::Malformed {
        offset: beacon_len,
        reason: "execution trailer missing".to_string(),
    })?;

    fn take_slice<'a>(
        buf: &'a [u8],
        cursor: &mut usize,
        n: usize,
        base: usize,
        name: &str,
    ) -> Result<&'a [u8], AdapterError> {
        let end = cursor.checked_add(n).ok_or(AdapterError::Malformed {
            offset: base.saturating_add(*cursor),
            reason: format!("{name} offset overflow"),
        })?;
        let out = buf.get(*cursor..end).ok_or(AdapterError::Malformed {
            offset: base.saturating_add(*cursor),
            reason: format!("{name} truncated"),
        })?;
        *cursor = end;
        Ok(out)
    }
    fn take32(
        buf: &[u8],
        cursor: &mut usize,
        base: usize,
        name: &str,
    ) -> Result<[u8; 32], AdapterError> {
        let s = take_slice(buf, cursor, 32, base, name)?;
        <[u8; 32]>::try_from(s).map_err(|_| AdapterError::Malformed {
            offset: base,
            reason: format!("{name} is not 32 bytes"),
        })
    }
    fn take_u64(
        buf: &[u8],
        cursor: &mut usize,
        base: usize,
        name: &str,
    ) -> Result<u64, AdapterError> {
        let s = take_slice(buf, cursor, 8, base, name)?;
        let a = <[u8; 8]>::try_from(s).map_err(|_| AdapterError::Malformed {
            offset: base,
            reason: format!("{name} is not 8 bytes"),
        })?;
        Ok(u64::from_le_bytes(a))
    }

    let mut cursor = 0usize;
    let execution_branch = [
        take32(trailer, &mut cursor, beacon_len, "execution_branch[0]")?,
        take32(trailer, &mut cursor, beacon_len, "execution_branch[1]")?,
        take32(trailer, &mut cursor, beacon_len, "execution_branch[2]")?,
        take32(trailer, &mut cursor, beacon_len, "execution_branch[3]")?,
    ];
    let parent_hash = take32(trailer, &mut cursor, beacon_len, "parent_hash")?;
    let fee_bytes = take_slice(trailer, &mut cursor, 20, beacon_len, "fee_recipient")?;
    let fee_recipient = <[u8; 20]>::try_from(fee_bytes).map_err(|_| AdapterError::Malformed {
        offset: beacon_len,
        reason: "fee_recipient is not 20 bytes".to_string(),
    })?;
    let state_root = take32(trailer, &mut cursor, beacon_len, "execution.state_root")?;
    let receipts_root = take32(trailer, &mut cursor, beacon_len, "execution.receipts_root")?;
    let logs_bloom = take_slice(trailer, &mut cursor, 256, beacon_len, "logs_bloom")?.to_vec();
    let prev_randao = take32(trailer, &mut cursor, beacon_len, "prev_randao")?;
    let block_number = take_u64(trailer, &mut cursor, beacon_len, "block_number")?;
    let gas_limit = take_u64(trailer, &mut cursor, beacon_len, "gas_limit")?;
    let gas_used = take_u64(trailer, &mut cursor, beacon_len, "gas_used")?;
    let timestamp = take_u64(trailer, &mut cursor, beacon_len, "timestamp")?;
    let extra_len_byte = take_slice(trailer, &mut cursor, 1, beacon_len, "extra_data_len")?
        .first()
        .copied()
        .unwrap_or(u8::MAX);
    let extra_len = usize::from(extra_len_byte);
    if extra_len > crate::cross_domain::evm::sync_committee::MAX_EXTRA_DATA_BYTES {
        return Err(AdapterError::Malformed {
            offset: beacon_len.saturating_add(cursor.saturating_sub(1)),
            reason: format!("extra_data_len {extra_len} exceeds 32"),
        });
    }
    let extra_padded = take_slice(trailer, &mut cursor, 32, beacon_len, "extra_data")?;
    // Refuse non-zero trailing pad bytes so v3 encoding is strictly canonical.
    if extra_padded
        .get(extra_len..)
        .is_some_and(|pad| pad.iter().any(|b| *b != 0))
    {
        return Err(AdapterError::Malformed {
            offset: beacon_len.saturating_add(cursor.saturating_sub(32).saturating_add(extra_len)),
            reason: "extra_data trailing padding must be zero".to_string(),
        });
    }
    let extra_data = extra_padded.get(..extra_len).unwrap_or_default().to_vec();
    let base_fee_per_gas = take32(trailer, &mut cursor, beacon_len, "base_fee_per_gas")?;
    let block_hash = take32(trailer, &mut cursor, beacon_len, "block_hash")?;
    let transactions_root = take32(trailer, &mut cursor, beacon_len, "transactions_root")?;
    let withdrawals_root = take32(trailer, &mut cursor, beacon_len, "withdrawals_root")?;
    let blob_gas_used = take_u64(trailer, &mut cursor, beacon_len, "blob_gas_used")?;
    let excess_blob_gas = take_u64(trailer, &mut cursor, beacon_len, "excess_blob_gas")?;

    let execution_payload = crate::cross_domain::evm::sync_committee::ExecutionPayloadHeader {
        parent_hash,
        fee_recipient,
        state_root,
        receipts_root,
        logs_bloom,
        prev_randao,
        block_number,
        gas_limit,
        gas_used,
        timestamp,
        extra_data,
        base_fee_per_gas,
        block_hash,
        transactions_root,
        withdrawals_root,
        blob_gas_used,
        excess_blob_gas,
    };

    Ok(ExecutionSyncCommitteeUpdate {
        beacon,
        execution_branch,
        execution_payload,
    })
}

/// Parameters for [`build_execution_update_payload_v3`].
///
/// Convenience: exposed for Ethereum v3 execution finality evidence builders.
#[derive(Debug, Clone)]
pub struct ExecutionUpdateV3Params<'a> {
    pub finalized_slot: u64,
    pub attested_slot: u64,
    pub period: u64,
    pub finalized_root_gindex: u64,
    pub committee: &'a PinnedCommittee,
    pub signature: &'a [u8],
    pub participation_bits: &'a [u8],
    pub beacon_state_root: [u8; 32],
    pub execution_branch: [[u8; 32]; 4],
    pub execution_payload: &'a crate::cross_domain::evm::sync_committee::ExecutionPayloadHeader,
}

/// Build a canonical v3 Deneb (`1473`B) or Electra (`1505`B) execution-bound
/// light-client update payload.
///
/// Convenience: exposed for Ethereum v3 execution finality evidence builders.
///
/// # Errors
///
/// Returns [`AdapterError`] if the fork gindex or execution payload is invalid.
pub fn build_execution_update_payload_v3(
    params: &ExecutionUpdateV3Params<'_>,
) -> Result<Vec<u8>, AdapterError> {
    let ExecutionUpdateV3Params {
        finalized_slot,
        attested_slot,
        period,
        finalized_root_gindex,
        committee,
        signature,
        participation_bits,
        beacon_state_root,
        execution_branch,
        execution_payload,
    } = params;
    use crate::cross_domain::evm::sync_committee::{
        beacon_header_hash_tree_root, walk_branch, EXECUTION_PAYLOAD_GINDEX,
        FINALIZED_ROOT_GINDEX_DENEB, FINALIZED_ROOT_GINDEX_ELECTRA,
    };
    let (beacon_len, finality_depth) = match *finalized_root_gindex {
        FINALIZED_ROOT_GINDEX_DENEB => (layout::LEN, 6usize),
        FINALIZED_ROOT_GINDEX_ELECTRA => (layout::LEN_ELECTRA, 7usize),
        other => {
            return Err(AdapterError::ConsensusRule {
                rule: format!("unsupported finalized_root_gindex {other}"),
            });
        }
    };
    let exec_root =
        execution_payload
            .hash_tree_root()
            .map_err(|e| AdapterError::ConsensusRule {
                rule: e.to_string(),
            })?;
    let finalized_body_root = walk_branch(exec_root, execution_branch, EXECUTION_PAYLOAD_GINDEX)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "failed to compute finalized_body_root from execution_branch".into(),
        })?;
    let finalized_root = beacon_header_hash_tree_root(
        *finalized_slot,
        0,
        [0u8; 32],
        *beacon_state_root,
        finalized_body_root,
    );
    let finality_branch: Vec<[u8; 32]> = (0..finality_depth)
        .map(|i| [0x11u8.wrapping_mul(u8::try_from(i + 1).unwrap_or(1)); 32])
        .collect();
    let attested_state_root = walk_branch(finalized_root, &finality_branch, *finalized_root_gindex)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "failed to compute attested_state_root from finality_branch".into(),
        })?;

    let mut payload = vec![0u8; beacon_len];
    if let Some(s) = payload.get_mut(layout::FINALIZED_ROOT) {
        s.copy_from_slice(&finalized_root);
    }
    if let Some(s) = payload.get_mut(layout::FINALIZED_SLOT) {
        s.copy_from_slice(&finalized_slot.to_le_bytes());
    }
    if let Some(s) = payload.get_mut(layout::ATTESTED_SLOT) {
        s.copy_from_slice(&attested_slot.to_le_bytes());
    }
    if let Some(s) = payload.get_mut(layout::PERIOD) {
        s.copy_from_slice(&period.to_le_bytes());
    }
    if let Some(s) = payload.get_mut(layout::NEXT_COMMITTEE_ROOT) {
        s.copy_from_slice(&committee.next_committee_root);
    }
    if let (Some(dst), true) = (
        payload.get_mut(layout::AGGREGATE_PUBKEY),
        committee.aggregate_pubkey.len() == 96,
    ) {
        dst.copy_from_slice(&committee.aggregate_pubkey);
    }
    if let (Some(dst), true) = (payload.get_mut(layout::SIGNATURE), signature.len() == 96) {
        dst.copy_from_slice(signature);
    }
    if let (Some(dst), true) = (
        payload.get_mut(layout::PARTICIPATION_BITS),
        participation_bits.len() == BITVECTOR_BYTES,
    ) {
        dst.copy_from_slice(participation_bits);
    }
    if let Some(s) = payload.get_mut(layout::STATE_ROOT) {
        s.copy_from_slice(beacon_state_root);
    }
    if let Some(s) = payload.get_mut(layout::FINALIZED_BODY_ROOT) {
        s.copy_from_slice(&finalized_body_root);
    }
    if let Some(s) = payload.get_mut(layout::ATTESTED_STATE_ROOT) {
        s.copy_from_slice(&attested_state_root);
    }
    if let Some(s) = payload.get_mut(layout::FINALIZED_ROOT_GINDEX) {
        s.copy_from_slice(&finalized_root_gindex.to_le_bytes());
    }
    for (i, sib) in finality_branch.iter().enumerate() {
        let start = layout::FINALITY_BRANCH_OFFSET + i * 32;
        if let Some(dst) = payload.get_mut(start..start + 32) {
            dst.copy_from_slice(sib);
        }
    }
    let trailer = encode_execution_trailer_v3(execution_branch, execution_payload)?;
    payload.extend_from_slice(&trailer);
    Ok(payload)
}

/// The parsed update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeUpdate {
    pub finalized_root: [u8; 32],
    pub finalized_slot: u64,
    pub attested_slot: u64,
    pub period: u64,
    pub next_committee_root: [u8; 32],
    pub aggregate_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub participation_bits: Vec<u8>,
    pub state_root: [u8; 32],
    pub finalized_proposer_index: u64,
    pub finalized_parent_root: [u8; 32],
    pub finalized_body_root: [u8; 32],
    pub attested_proposer_index: u64,
    pub attested_parent_root: [u8; 32],
    pub attested_state_root: [u8; 32],
    pub attested_body_root: [u8; 32],
    pub finalized_root_gindex: u64,
    pub finality_branch: Vec<[u8; 32]>,
}

impl SyncCommitteeUpdate {
    /// The number of committee members who signed.
    #[must_use]
    pub fn signers(&self) -> u64 {
        participation(&self.participation_bits)
    }

    /// Reconstruct `hash_tree_root(finalized BeaconBlockHeader)`.
    #[must_use]
    pub fn finalized_header_root(&self) -> [u8; 32] {
        crate::cross_domain::evm::sync_committee::beacon_header_hash_tree_root(
            self.finalized_slot,
            self.finalized_proposer_index,
            self.finalized_parent_root,
            self.state_root,
            self.finalized_body_root,
        )
    }

    /// Reconstruct `hash_tree_root(attested BeaconBlockHeader)`.
    #[must_use]
    pub fn attested_header_root(&self) -> [u8; 32] {
        crate::cross_domain::evm::sync_committee::beacon_header_hash_tree_root(
            self.attested_slot,
            self.attested_proposer_index,
            self.attested_parent_root,
            self.attested_state_root,
            self.attested_body_root,
        )
    }
}

/// Reads the fixed-layout payload.
///
/// # Errors
///
/// [`AdapterError::Malformed`] naming the offset, so a truncated or
/// misaligned payload points at where it went wrong.
pub fn parse_update(payload: &[u8]) -> Result<SyncCommitteeUpdate, AdapterError> {
    use crate::cross_domain::evm::sync_committee::{
        FINALIZED_ROOT_GINDEX_DENEB, FINALIZED_ROOT_GINDEX_ELECTRA,
    };
    fn slice<'a>(
        payload: &'a [u8],
        range: std::ops::Range<usize>,
        what: &str,
    ) -> Result<&'a [u8], AdapterError> {
        payload.get(range.clone()).ok_or(AdapterError::Malformed {
            offset: range.start,
            reason: format!("{what} is not present"),
        })
    }
    fn fixed<const N: usize>(
        payload: &[u8],
        range: std::ops::Range<usize>,
        what: &str,
    ) -> Result<[u8; N], AdapterError> {
        let bytes = slice(payload, range, what)?;
        <[u8; N]>::try_from(bytes).map_err(|_| AdapterError::Malformed {
            offset: 0,
            reason: format!("{what} is not {N} bytes"),
        })
    }
    fn u64_at(
        payload: &[u8],
        range: std::ops::Range<usize>,
        what: &str,
    ) -> Result<u64, AdapterError> {
        let bytes = slice(payload, range, what)?;
        let arr = <[u8; 8]>::try_from(bytes).map_err(|_| AdapterError::Malformed {
            offset: 0,
            reason: format!("{what} is not 8 bytes"),
        })?;
        Ok(u64::from_le_bytes(arr))
    }

    if payload.len() != layout::LEN && payload.len() != layout::LEN_ELECTRA {
        return Err(AdapterError::Malformed {
            offset: payload.len(),
            reason: format!(
                "payload is {} bytes, expected {} (Deneb) or {} (Electra)",
                payload.len(),
                layout::LEN,
                layout::LEN_ELECTRA
            ),
        });
    }

    let finalized_root_gindex = u64_at(
        payload,
        layout::FINALIZED_ROOT_GINDEX,
        "finalized_root_gindex",
    )?;
    let expected_depth = match finalized_root_gindex {
        FINALIZED_ROOT_GINDEX_DENEB => 6usize,
        FINALIZED_ROOT_GINDEX_ELECTRA => 7usize,
        other => {
            return Err(AdapterError::Malformed {
                offset: layout::FINALIZED_ROOT_GINDEX.start,
                reason: format!("unsupported finalized_root_gindex {other}"),
            });
        }
    };
    let branch_bytes =
        payload
            .get(layout::FINALITY_BRANCH_OFFSET..)
            .ok_or(AdapterError::Malformed {
                offset: layout::FINALITY_BRANCH_OFFSET,
                reason: "finality_branch missing".to_string(),
            })?;
    if branch_bytes.len() != expected_depth * 32 {
        return Err(AdapterError::Malformed {
            offset: layout::FINALITY_BRANCH_OFFSET,
            reason: format!(
                "finality_branch is {} bytes, expected {} for gindex {}",
                branch_bytes.len(),
                expected_depth * 32,
                finalized_root_gindex
            ),
        });
    }
    let mut finality_branch = Vec::with_capacity(expected_depth);
    for chunk in branch_bytes.chunks_exact(32) {
        let mut node = [0u8; 32];
        node.copy_from_slice(chunk);
        finality_branch.push(node);
    }

    Ok(SyncCommitteeUpdate {
        finalized_root: fixed(payload, layout::FINALIZED_ROOT, "finalized_root")?,
        finalized_slot: u64_at(payload, layout::FINALIZED_SLOT, "finalized_slot")?,
        attested_slot: u64_at(payload, layout::ATTESTED_SLOT, "attested_slot")?,
        period: u64_at(payload, layout::PERIOD, "period")?,
        next_committee_root: fixed(payload, layout::NEXT_COMMITTEE_ROOT, "next_committee_root")?,
        aggregate_pubkey: slice(payload, layout::AGGREGATE_PUBKEY, "aggregate_pubkey")?.to_vec(),
        signature: slice(payload, layout::SIGNATURE, "signature")?.to_vec(),
        participation_bits: slice(payload, layout::PARTICIPATION_BITS, "participation_bits")?
            .to_vec(),
        state_root: fixed(payload, layout::STATE_ROOT, "state_root")?,
        finalized_proposer_index: u64_at(
            payload,
            layout::FINALIZED_PROPOSER_INDEX,
            "finalized_proposer_index",
        )?,
        finalized_parent_root: fixed(
            payload,
            layout::FINALIZED_PARENT_ROOT,
            "finalized_parent_root",
        )?,
        finalized_body_root: fixed(payload, layout::FINALIZED_BODY_ROOT, "finalized_body_root")?,
        attested_proposer_index: u64_at(
            payload,
            layout::ATTESTED_PROPOSER_INDEX,
            "attested_proposer_index",
        )?,
        attested_parent_root: fixed(
            payload,
            layout::ATTESTED_PARENT_ROOT,
            "attested_parent_root",
        )?,
        attested_state_root: fixed(payload, layout::ATTESTED_STATE_ROOT, "attested_state_root")?,
        attested_body_root: fixed(payload, layout::ATTESTED_BODY_ROOT, "attested_body_root")?,
        finalized_root_gindex,
        finality_branch,
    })
}

/// Build a canonical Deneb `752`-byte update payload whose `finalized_root`,
/// SSZ `finality_branch`, and `attested_state_root` are mutually consistent.
///
/// Intended for canonical test fixtures and tooling generating deterministic
/// Deneb light-client updates.
#[must_use]
pub fn build_deneb_update_payload(
    finalized_slot: u64,
    attested_slot: u64,
    period: u64,
    committee: &PinnedCommittee,
    signature: &[u8],
    participation_bits: &[u8],
    state_root: [u8; 32],
) -> Vec<u8> {
    let mut payload = vec![0u8; layout::LEN];
    if let Some(s) = payload.get_mut(layout::FINALIZED_SLOT) {
        s.copy_from_slice(&finalized_slot.to_le_bytes());
    }
    if let Some(s) = payload.get_mut(layout::ATTESTED_SLOT) {
        s.copy_from_slice(&attested_slot.to_le_bytes());
    }
    if let Some(s) = payload.get_mut(layout::PERIOD) {
        s.copy_from_slice(&period.to_le_bytes());
    }
    if let Some(s) = payload.get_mut(layout::NEXT_COMMITTEE_ROOT) {
        s.copy_from_slice(&committee.next_committee_root);
    }
    if let (Some(dst), true) = (
        payload.get_mut(layout::AGGREGATE_PUBKEY),
        committee.aggregate_pubkey.len() == 96,
    ) {
        dst.copy_from_slice(&committee.aggregate_pubkey);
    }
    if let (Some(dst), true) = (payload.get_mut(layout::SIGNATURE), signature.len() == 96) {
        dst.copy_from_slice(signature);
    }
    if let (Some(dst), true) = (
        payload.get_mut(layout::PARTICIPATION_BITS),
        participation_bits.len() == BITVECTOR_BYTES,
    ) {
        dst.copy_from_slice(participation_bits);
    }
    if let Some(dst) = payload.get_mut(layout::FINALIZED_ROOT_GINDEX) {
        dst.copy_from_slice(
            &crate::cross_domain::evm::sync_committee::FINALIZED_ROOT_GINDEX_DENEB.to_le_bytes(),
        );
    }
    let branch = [
        [0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32], [0x66; 32],
    ];
    for (i, sib) in branch.iter().enumerate() {
        let start = layout::FINALITY_BRANCH_OFFSET + i * 32;
        if let Some(dst) = payload.get_mut(start..start + 32) {
            dst.copy_from_slice(sib);
        }
    }
    set_deneb_state_root(&mut payload, state_root);
    payload
}

/// Recompute `STATE_ROOT`, `FINALIZED_ROOT`, and `ATTESTED_STATE_ROOT` inside
/// a Deneb payload so its SSZ finality branch stays consistent after mutating
/// the committed state root.
fn read_deneb_u64(payload: &[u8], range: std::ops::Range<usize>) -> u64 {
    payload
        .get(range)
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

fn read_deneb_32(payload: &[u8], range: std::ops::Range<usize>) -> [u8; 32] {
    payload
        .get(range)
        .and_then(|s| <[u8; 32]>::try_from(s).ok())
        .unwrap_or([0u8; 32])
}

pub fn set_deneb_state_root(payload: &mut [u8], state_root: [u8; 32]) {
    let finalized_slot = read_deneb_u64(payload, layout::FINALIZED_SLOT);
    let finalized_proposer_index = read_deneb_u64(payload, layout::FINALIZED_PROPOSER_INDEX);
    let finalized_parent_root = read_deneb_32(payload, layout::FINALIZED_PARENT_ROOT);
    let finalized_body_root = read_deneb_32(payload, layout::FINALIZED_BODY_ROOT);
    let mut branch = Vec::with_capacity(6);
    for i in 0..6 {
        let start = layout::FINALITY_BRANCH_OFFSET + i * 32;
        branch.push(read_deneb_32(payload, start..start + 32));
    }
    let gindex = read_deneb_u64(payload, layout::FINALIZED_ROOT_GINDEX);

    if let Some(dst) = payload.get_mut(layout::STATE_ROOT) {
        dst.copy_from_slice(&state_root);
    }
    let finalized_root = crate::cross_domain::evm::sync_committee::beacon_header_hash_tree_root(
        finalized_slot,
        finalized_proposer_index,
        finalized_parent_root,
        state_root,
        finalized_body_root,
    );
    if let Some(dst) = payload.get_mut(layout::FINALIZED_ROOT) {
        dst.copy_from_slice(&finalized_root);
    }
    if let Some(attested_state_root) =
        crate::cross_domain::evm::sync_committee::walk_branch(finalized_root, &branch, gindex)
    {
        if let Some(dst) = payload.get_mut(layout::ATTESTED_STATE_ROOT) {
            dst.copy_from_slice(&attested_state_root);
        }
    }
}

/// The sync committee the adapter is pinned to.
///
/// The aggregate public key used to be a field of the submitted payload:
/// whoever could submit evidence generated their own BLS key and signed with
/// it. The committee is now state the adapter HOLDS - the payload's copy is
/// checked against the pin, never trusted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PinnedCommittee {
    /// The sync-committee period this pin serves.
    pub period: u64,
    /// The committee's aggregate public key (BLS12-381 G1, 96 bytes).
    pub aggregate_pubkey: Vec<u8>,
    /// The commitment to the NEXT committee's key: a rotation opens it.
    pub next_committee_root: [u8; 32],
}

/// The commitment a rotation must open: the root of a
/// committee is the domain-separated hash of its aggregate key. Both the
/// pinned `next_committee_root` and [`EthereumSyncAdapter::rotate_committee`]
/// speak this one function, so a rotation cannot name a key the pin did not
/// commit to.
#[must_use]
pub fn committee_root(aggregate_pubkey: &[u8]) -> [u8; 32] {
    crate::core::hash::hash_fields_bytes(&[b"BDLM_ETHSYNC_COMMITTEE_ROOT_V1", aggregate_pubkey])
}

/// The signing root, derived (evidence format v2).
///
/// The v1 adapter signed a constant held in `AdapterSpec` - the signature
/// bound nothing about the update, so one signature replayed under any
/// `state_root`. v2 signs the update's OWN fields: the finalized and attested
/// slots, the period, the next committee root, the participation bits and
/// the claimed state root all go under the signature.
#[must_use]
pub fn signing_root_v2(update: &SyncCommitteeUpdate) -> [u8; 32] {
    let attested_header_root = update.attested_header_root();
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_ETHSYNC_SIGNING_ROOT_V2",
        &attested_header_root,
        &update.attested_state_root,
        &update.finalized_root,
        &update.finalized_slot.to_le_bytes(),
        &update.attested_slot.to_le_bytes(),
        &update.period.to_le_bytes(),
        &update.next_committee_root,
        &update.participation_bits,
        &update.state_root,
    ])
}

/// Domain-separated signing root for evidence format v3, binding both the
/// Beacon finality proof and the SSZ-proven 17-field `ExecutionPayloadHeader`
/// (`execution_payload_root`, `state_root`, `receipts_root`, `block_hash`,
/// `transactions_root`, `block_number`, and `timestamp`).
///
/// Convenience: exposed for Ethereum v3 execution light-client signing and checks.
#[must_use]
pub fn signing_root_v3(
    update: &ExecutionSyncCommitteeUpdate,
    execution_payload_root: &[u8; 32],
) -> [u8; 32] {
    let b = &update.beacon;
    let p = &update.execution_payload;
    let attested_header_root = b.attested_header_root();
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_ETHSYNC_SIGNING_ROOT_V3",
        &attested_header_root,
        &b.attested_state_root,
        &b.finalized_root,
        &b.finalized_body_root,
        &b.finalized_slot.to_le_bytes(),
        &b.attested_slot.to_le_bytes(),
        &b.period.to_le_bytes(),
        &b.next_committee_root,
        &b.participation_bits,
        &b.state_root,
        execution_payload_root,
        &p.state_root,
        &p.receipts_root,
        &p.block_hash,
        &p.transactions_root,
        &p.block_number.to_le_bytes(),
        &p.timestamp.to_le_bytes(),
    ])
}

/// SSZ-authenticated period rotation bundle for [`EthereumSyncAdapter::rotate_committee_with_ssz_branch`].
///
/// Convenience: exposed for multi-period SSZ sync-committee rotation on [`EthereumSyncAdapter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SszCommitteeRotation {
    /// Target sequential period (`current.period + 1`).
    pub next_period: u64,
    /// Full 512-member BLS12-381 G1 roster entering as the active committee for `next_period`.
    pub next_member_pubkeys: [[u8; 48]; 512],
    /// Compressed 48-byte aggregate G1 public key for `next_period`.
    pub next_aggregate_pubkey: [u8; 48],
    /// Verified finalized `BeaconBlockHeader.state_root` from `current.period`.
    pub finalized_state_root: [u8; 32],
    /// Fork-matched `next_sync_committee` generalized index (`55` Deneb / `87` Electra).
    pub next_sync_committee_gindex: u64,
    /// SSZ Merkle branch proving `sync_committee_hash_tree_root` in `finalized_state_root`.
    pub next_sync_committee_branch: Vec<[u8; 32]>,
    /// Fork's `finalized_root_gindex` (`105` Deneb / `169` Electra) used to enforce gindex pairing.
    pub finalized_root_gindex: u64,
    /// Commitment to period `next_period + 1` (either `committee_root` or SSZ root).
    pub subsequent_committee_root: [u8; 32],
}

/// The adapter.
pub struct EthereumSyncAdapter {
    descriptor: AdapterDescriptor,
    /// The network this instance serves. Checked on every call: one adapter
    /// binary pointed at a second network must not keep producing
    /// attestations, because the signing root it holds belongs to the first.
    network: String,
    verifier: Option<Box<dyn BlsVerifier>>,
    /// The pinned sync committee. `None` is the closed
    /// admission state (decision C, interim): the adapter refuses every
    /// update until a committee is pinned.
    committee: Option<PinnedCommittee>,
    /// Optional full 512-member BLS12-381 G1 public-key roster for the pinned
    /// period. When installed, `verify_observed` reconstructs the exact
    /// participating subset aggregate key `sum_{i: bit[i] == 1} pk_i` from
    /// `update.participation_bits`, enabling authentic `< 512` partial-quorum
    /// updates and refusing any bitvector mask that disagrees with the signers.
    member_pubkeys: Option<Vec<[u8; 48]>>,
    golden: Option<RawConsensusEvidence>,
}

/// Reconstruct the compressed BLS12-381 G1 aggregate public key of the exact
/// sync-committee subset selected by `participation_bits` (with full prime-order
/// subgroup and non-identity checks on every member key and on the resulting sum).
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] or [`AdapterError::Crypto`] if
/// `member_pubkeys.len() != 512`, `participation_bits.len() != 64`, any key is
/// outside G1 or identity, no bits are set, or the sum cancels to identity.
///
/// WIRING: Subset sync-committee G1 aggregation consumed by [`EthereumSyncAdapter`].
pub fn aggregate_sync_committee_subset(
    member_pubkeys: &[[u8; 48]],
    participation_bits: &[u8],
) -> Result<([u8; 48], u64), AdapterError> {
    if member_pubkeys.len() != SYNC_COMMITTEE_SIZE as usize {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "sync committee roster must hold {SYNC_COMMITTEE_SIZE} pubkeys, found {}",
                member_pubkeys.len()
            ),
        });
    }
    if participation_bits.len() != BITVECTOR_BYTES {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "sync committee participation_bits must be {BITVECTOR_BYTES} bytes, found {}",
                participation_bits.len()
            ),
        });
    }
    crate::cross_domain::evm::sync_committee::aggregate_sync_committee_subset_g1(
        member_pubkeys,
        participation_bits,
    )
    .map_err(|what| AdapterError::Crypto { what })
}

impl EthereumSyncAdapter {
    /// # Errors
    ///
    /// Nothing: an adapter without a verifier constructs fine and refuses at
    /// verification time. Constructing is not the moment to fail, because the
    /// caller may be building a registry of adapters before installing crypto.
    #[must_use]
    pub fn new(
        network: &str,
        committee: Option<PinnedCommittee>,
        verifier: Option<Box<dyn BlsVerifier>>,
    ) -> Self {
        let id = AdapterId::from_name(&format!("ethereum-sync-{network}"));
        Self {
            network: network.to_string(),
            descriptor: AdapterDescriptor {
                id,
                name: format!("ethereum-sync-{network}"),
                // Evidence format v2 - the signature
                // covers the update itself, not a stored constant.
                adapter_version: 2,
                accepted_evidence_versions: vec![2, 3],
                consensus_kind: "gasper-pos".to_string(),
                finality_kind: FinalityKind::ProtocolFinality,
                // Two epochs of Casper FFG. Declared rather than derived from
                // a slot count, because the depth a consumer relies on should
                // be a number they can read.
                required_depth: 2 * SLOTS_PER_EPOCH,
                time_unit: TimeUnit::Slot,
                trust_model: TrustModel::HonestMajority {
                    set_size: SYNC_COMMITTEE_SIZE,
                },
            },
            verifier,
            committee,
            member_pubkeys: None,
            golden: None,
        }
    }

    /// Installs the full 512-member BLS12-381 G1 key roster for the pinned
    /// committee, verifying immediately that the all-512 aggregate matches the
    /// pinned committee's aggregate public key.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] if no committee is pinned, any member key is
    /// invalid, or the full-roster aggregate does not match `committee.aggregate_pubkey`.
    ///
    /// WIRING: Subset-bound Altair/Deneb/Electra sync-committee verification entrypoint.
    pub fn with_member_pubkeys(
        mut self,
        member_pubkeys: Vec<[u8; 48]>,
    ) -> Result<Self, AdapterError> {
        let Some(committee) = self.committee.as_ref() else {
            return Err(AdapterError::ConsensusRule {
                rule: "cannot attach member_pubkeys without a pinned committee".into(),
            });
        };
        let (full_agg, _) =
            aggregate_sync_committee_subset(&member_pubkeys, &[0xff; BITVECTOR_BYTES])?;
        use subtle::ConstantTimeEq;
        let matches_pin = match committee.aggregate_pubkey.len() {
            48 => bool::from(
                committee
                    .aggregate_pubkey
                    .as_slice()
                    .ct_eq(full_agg.as_slice()),
            ),
            96 => {
                committee
                    .aggregate_pubkey
                    .get(..48)
                    .is_some_and(|head| bool::from(head.ct_eq(full_agg.as_slice())))
                    && committee
                        .aggregate_pubkey
                        .get(48..)
                        .is_some_and(|pad| pad.iter().all(|&b| b == 0))
            }
            _ => false,
        };
        if !matches_pin {
            return Err(AdapterError::ConsensusRule {
                rule: "512-member sync committee aggregate mismatches pinned committee key".into(),
            });
        }
        self.member_pubkeys = Some(member_pubkeys);
        Ok(self)
    }

    /// Rotates the pinned committee.
    ///
    /// The new key must open the pin's `next_committee_root` under
    /// [`committee_root`], and the new period must move forward. Anything
    /// else is a rotation nobody committed to and is refused.
    ///
    /// # Errors
    ///
    /// [`AdapterError::ConsensusRule`] when there is no pin to rotate from,
    /// the period does not move forward, or the new key does not open the
    /// committed root.
    pub fn rotate_committee(&mut self, next: PinnedCommittee) -> Result<(), AdapterError> {
        let Some(current) = self.committee.as_ref() else {
            return Err(AdapterError::ConsensusRule {
                rule: "no pinned committee to rotate from".to_string(),
            });
        };
        let Some(expected_period) = current.period.checked_add(1) else {
            return Err(AdapterError::ConsensusRule {
                rule: "sync committee period reached u64::MAX and cannot rotate further"
                    .to_string(),
            });
        };
        if next.period != expected_period {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "committee period must advance by exactly 1: pinned {}, expected {}, next {}",
                    current.period, expected_period, next.period
                ),
            });
        }
        if committee_root(&next.aggregate_pubkey) != current.next_committee_root {
            return Err(AdapterError::ConsensusRule {
                rule: "the next committee's key does not open the committed next_committee_root"
                    .to_string(),
            });
        }
        self.committee = Some(next);
        self.member_pubkeys = None;
        Ok(())
    }

    /// Rotate the pinned committee sequentially (`P -> P + 1`) using a full
    /// Deneb (`gindex = 55`) or Electra (`gindex = 87`) SSZ Merkle branch
    /// proving `next_sync_committee` against a verified `finalized_state_root`,
    /// validating every one of the 512 BLS12-381 G1 member keys and installing
    /// the verified roster atomically for subset-bound pairing in `P + 1`.
    ///
    /// Convenience: exposed for multi-period Deneb/Electra SSZ sync-committee rotation.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::ConsensusRule`] or [`AdapterError::Crypto`] when
    /// no committee is pinned, `next_period != current.period + 1`, the fork
    /// gindex pair mismatches, the SSZ Merkle branch fails, the committed
    /// `next_committee_root` disagrees, or any G1 pubkey/aggregate is invalid.
    pub fn rotate_committee_with_ssz_branch(
        &mut self,
        rotation: &SszCommitteeRotation,
    ) -> Result<(), AdapterError> {
        use crate::cross_domain::evm::sync_committee::{
            sync_committee_hash_tree_root, validate_sync_committee_pubkeys, walk_branch,
            FINALIZED_ROOT_GINDEX_DENEB, FINALIZED_ROOT_GINDEX_ELECTRA,
            NEXT_SYNC_COMMITTEE_GINDEX_DENEB, NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA,
        };
        use subtle::ConstantTimeEq;

        let Some(current) = self.committee.as_ref() else {
            return Err(AdapterError::ConsensusRule {
                rule: "no pinned committee to rotate from".to_string(),
            });
        };
        let Some(expected_period) = current.period.checked_add(1) else {
            return Err(AdapterError::ConsensusRule {
                rule: "sync committee period overflow at u64::MAX".to_string(),
            });
        };
        if rotation.next_period != expected_period {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "committee period must advance sequentially: pinned {}, expected {}, found {}",
                    current.period, expected_period, rotation.next_period
                ),
            });
        }
        let expected_gindex = match rotation.finalized_root_gindex {
            FINALIZED_ROOT_GINDEX_DENEB => NEXT_SYNC_COMMITTEE_GINDEX_DENEB,
            FINALIZED_ROOT_GINDEX_ELECTRA => NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA,
            other => {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("unsupported finalized_root_gindex {other} for SSZ rotation"),
                });
            }
        };
        if rotation.next_sync_committee_gindex != expected_gindex {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "next_sync_committee gindex mismatch: expected {expected_gindex}, found {}",
                    rotation.next_sync_committee_gindex
                ),
            });
        }

        let ssz_committee_root = sync_committee_hash_tree_root(
            &rotation.next_member_pubkeys,
            &rotation.next_aggregate_pubkey,
        );
        let proven_state_root = walk_branch(
            ssz_committee_root,
            &rotation.next_sync_committee_branch,
            expected_gindex,
        )
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "next_sync_committee SSZ branch has invalid length".to_string(),
        })?;
        if !bool::from(
            proven_state_root
                .as_slice()
                .ct_eq(rotation.finalized_state_root.as_slice()),
        ) {
            return Err(AdapterError::ConsensusRule {
                rule: "next_sync_committee SSZ branch does not prove finalized_state_root"
                    .to_string(),
            });
        }

        let mut padded_agg = vec![0u8; 96];
        if let Some(head) = padded_agg.get_mut(..48) {
            head.copy_from_slice(&rotation.next_aggregate_pubkey);
        }
        let matches_ssz = bool::from(
            ssz_committee_root
                .as_slice()
                .ct_eq(current.next_committee_root.as_slice()),
        );
        let matches_pin_hash = bool::from(
            committee_root(&padded_agg)
                .as_slice()
                .ct_eq(current.next_committee_root.as_slice()),
        );
        if !matches_ssz && !matches_pin_hash {
            return Err(AdapterError::ConsensusRule {
                rule: "incoming sync committee does not open pinned next_committee_root"
                    .to_string(),
            });
        }

        validate_sync_committee_pubkeys(
            &rotation.next_member_pubkeys,
            &rotation.next_aggregate_pubkey,
        )
        .map_err(|e| AdapterError::Crypto {
            what: e.to_string(),
        })?;

        self.committee = Some(PinnedCommittee {
            period: expected_period,
            aggregate_pubkey: padded_agg,
            next_committee_root: rotation.subsequent_committee_root,
        });
        self.member_pubkeys = Some(rotation.next_member_pubkeys.to_vec());
        Ok(())
    }

    /// Attaches a golden sample. Separate from `new` because a golden sample
    /// has to be real evidence, and the caller is the one who has a beacon
    /// node.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }
}

impl crate::cross_domain::external::spec::ExternalFinalityAdapter for EthereumSyncAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        self.verify_observed(evidence, policy, &mut NullObserver)
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
                found: "another adapter".to_string(),
            });
        }
        // The signing root held by this instance belongs to one network. An
        // evidence envelope naming another one is refused here rather than
        // verified against the wrong genesis, which would produce a signature
        // check that means nothing.
        if evidence.network != self.network {
            return Err(AdapterError::WrongAdapter {
                expected: self.network.clone(),
                found: evidence.network.clone(),
            });
        }
        if !self
            .descriptor
            .accepted_evidence_versions
            .contains(&evidence.evidence_version)
        {
            let accepted = self
                .descriptor
                .accepted_evidence_versions
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted,
            });
        }

        let (update, maybe_exec) = if evidence.evidence_version == 3 {
            let v3 = parse_execution_update_v3(&evidence.payload)?;
            let exec_root = v3
                .execution_payload
                .verify_in_beacon_body(&v3.beacon.finalized_body_root, &v3.execution_branch)
                .map_err(|e| AdapterError::ConsensusRule {
                    rule: format!("execution_payload_header SSZ verification failed: {e}"),
                })?;
            let sign_root = signing_root_v3(&v3, &exec_root);
            let exec = v3.execution_payload;
            (v3.beacon, Some((exec, sign_root)))
        } else {
            (parse_update(&evidence.payload)?, None)
        };

        let committed_state_root = maybe_exec
            .as_ref()
            .map_or(update.state_root, |(exec, _)| exec.state_root);

        // The declared fields must be the derived ones. In v2 `declared_root`
        // binds the finalized Beacon state root; in v3 it binds the SSZ-proven
        // Deneb/Electra `ExecutionPayloadHeader.state_root`.
        if policy.require_declared_match {
            if evidence.declared_height != update.finalized_slot {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if evidence.declared_root != committed_state_root {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }

        // The backing of this adapter is never slashable (Altair has no
        // slashing rule for sync committee messages). A caller that demands
        // slashable backing must be refused, not given an attestation that
        // says `slashable: false` after the fact.
        if policy.require_slashable {
            return Err(AdapterError::ConsensusRule {
                rule:
                    "the policy requires slashable backing; a sync committee set is not slashable"
                        .to_string(),
            });
        }

        // Finalized must not be ahead of attested: the attested header is the
        // one the committee signed, and a finalized header beyond it is a
        // claim about something nobody signed.
        if update.finalized_slot > update.attested_slot {
            return Err(AdapterError::ConsensusRule {
                rule: "finalized slot is ahead of the attested slot".to_string(),
            });
        }

        // The declared period must match the attested slot that the committee
        // actually signed. A period taken from the envelope rather than derived
        // would let one committee's signature be presented for another period.
        if update.period != period_of_slot(update.attested_slot) {
            return Err(AdapterError::ConsensusRule {
                rule: "declared period does not match the attested slot's period".to_string(),
            });
        }

        // Verify the finalized BeaconBlockHeader fields reconstruct finalized_root
        // and that the SSZ finality_branch proves finalized_root under attested_state_root.
        if update.finalized_header_root() != update.finalized_root {
            return Err(AdapterError::ConsensusRule {
                rule: "finalized header fields do not match finalized_root".to_string(),
            });
        }
        let proven_state_root = crate::cross_domain::evm::sync_committee::walk_branch(
            update.finalized_root,
            &update.finality_branch,
            update.finalized_root_gindex,
        );
        if proven_state_root != Some(update.attested_state_root) {
            return Err(AdapterError::ConsensusRule {
                rule: "finality_branch does not prove finalized_root against attested_state_root"
                    .to_string(),
            });
        }

        // Participation, before the expensive check: a bitvector that does not
        // reach 2/3 is a refusal regardless of whether the signature verifies.
        let signers = update.signers();
        if !has_supermajority(signers) {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "{signers} of {SYNC_COMMITTEE_SIZE} signed; the threshold is {}",
                    minimum_signers()
                ),
            });
        }

        // The key the signature is checked against is
        // the PINNED committee's, never the payload's own claim. No pin is
        // the closed admission state (decision C, interim).
        let Some(committee) = self.committee.as_ref() else {
            return Err(AdapterError::ConsensusRule {
                rule: "no sync committee pinned; EthereumSync admission is closed".to_string(),
            });
        };
        if update.period != committee.period {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "update period {} is not the pinned committee's period {}",
                    update.period, committee.period
                ),
            });
        }
        // Verify against the exact participating subset G1 sum when the 512
        // member pubkeys are pinned, or against the full pinned committee key.
        let verified_key: Vec<u8> = if let Some(roster) = self.member_pubkeys.as_ref() {
            let (subset_pk, subset_count) =
                aggregate_sync_committee_subset(roster, &update.participation_bits)?;
            if subset_count != signers {
                return Err(AdapterError::ConsensusRule {
                    rule: "sync committee subset count diverged from participation bitvector"
                        .into(),
                });
            }
            use subtle::ConstantTimeEq;
            let update_matches_subset = update
                .aggregate_pubkey
                .get(..48)
                .is_some_and(|head| bool::from(head.ct_eq(subset_pk.as_slice())))
                && update
                    .aggregate_pubkey
                    .get(48..)
                    .is_some_and(|pad| pad.iter().all(|&b| b == 0));
            let update_matches_committee = bool::from(
                update
                    .aggregate_pubkey
                    .as_slice()
                    .ct_eq(committee.aggregate_pubkey.as_slice()),
            );
            if !update_matches_subset && !update_matches_committee {
                return Err(AdapterError::ConsensusRule {
                    rule:
                        "update aggregate_pubkey matches neither subset nor full pinned committee"
                            .into(),
                });
            }
            subset_pk.to_vec()
        } else {
            if update.aggregate_pubkey != committee.aggregate_pubkey {
                return Err(AdapterError::ConsensusRule {
                    rule: "the update's aggregate public key is not the pinned committee's"
                        .to_string(),
                });
            }
            committee.aggregate_pubkey.clone()
        };

        // The pairing check. Refused when no verifier is installed - there is
        // no mode in which this adapter accepts an unchecked signature.
        let Some(verifier) = self.verifier.as_ref() else {
            return Err(AdapterError::Unavailable {
                reason: "no BLS verifier installed; refusing rather than skipping the check"
                    .to_string(),
            });
        };
        if verifier.sync_committee_closed() {
            return Err(AdapterError::Unavailable {
                reason: "Ethereum sync-committee verification is closed on this verifier"
                    .to_string(),
            });
        }
        let derived_signing_root = maybe_exec
            .as_ref()
            .map_or_else(|| signing_root_v2(&update), |(_, root)| *root);
        verifier
            .verify_aggregate(
                &derived_signing_root,
                &verified_key,
                &update.signature,
                signers,
            )
            .map_err(|e| AdapterError::Crypto { what: e })?;

        // Depth and age, against the caller's policy rather than the
        // adapter's opinion of how deep is deep enough.
        let depth = update.attested_slot.saturating_sub(update.finalized_slot);
        if depth < policy.min_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: depth,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 {
            let age = policy.now.saturating_sub(update.finalized_slot);
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        // Every check passed. The one scheme this adapter verified is the
        // committee's BLS12-381 aggregate.
        observer.observe(ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG));

        let (attested_block_hash, attested_event_root, attested_tx_root) =
            if let Some((ref exec, _)) = maybe_exec {
                (
                    Some(exec.block_hash),
                    Some(exec.receipts_root),
                    Some(exec.transactions_root),
                )
            } else {
                (Some(update.finalized_root), None, None)
            };

        Ok(FinalityAttestation {
            adapter: self.descriptor.id,
            domain: crate::cross_domain::external::spec::DomainKey::from_parts(
                &self.descriptor.id,
                &evidence.network,
            ),
            height: update.finalized_slot,
            state_root: committed_state_root,
            attested_block_hash,
            attested_event_root,
            attested_tx_root,
            finalized_at: epoch_of_slot(update.finalized_slot),
            time_unit: TimeUnit::Epoch,
            security: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG),
                signers,
                required: minimum_signers(),
                total_weight: u128::from(SYNC_COMMITTEE_SIZE),
                // The load-bearing line in this file. Altair defines no
                // slashing condition for sync committee messages, so a
                // dishonest committee loses nothing. Saying otherwise would be
                // the one claim in this adapter that a reader could not check.
                slashable: false,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
        })
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        // Every probe is a byte patch, so any node can apply and replay it.
        // The offsets come from `layout`, which is why the layout is constants
        // rather than inline arithmetic.
        vec![
            FaultProbe {
                name: "a payload that is one byte short is refused, not partially parsed".to_string(),
                patch: BytePatch::TruncatePayload {
                    keep: layout::LEN - 1,
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "an empty payload is refused".to_string(),
                patch: BytePatch::TruncatePayload { keep: 0 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "a declared height that the payload does not support is refused".to_string(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "a declared root that the payload does not support is refused".to_string(),
                patch: BytePatch::DeclaredRoot { value: [0xff; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "an evidence version this adapter never accepted is refused at the gate".to_string(),
                patch: BytePatch::EvidenceVersion { value: 99 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "a participation bitvector with nobody signing is refused before the pairing check"
                    .to_string(),
                patch: BytePatch::InPayload {
                    offset: layout::PARTICIPATION_BITS.start,
                    bytes: vec![0u8; BITVECTOR_BYTES],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "a participation bitvector one signer below the threshold is refused".to_string(),
                patch: BytePatch::InPayload {
                    offset: layout::PARTICIPATION_BITS.start,
                    // minimum_signers() - 1 bits set: exactly one short.
                    bytes: bits_for(minimum_signers().saturating_sub(1)),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "corrupting the aggregate signature is refused by the crypto door".to_string(),
                patch: BytePatch::InPayload {
                    offset: layout::SIGNATURE.start,
                    bytes: vec![0u8; 96],
                },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "corrupting the aggregate public key is refused by the crypto door".to_string(),
                patch: BytePatch::InPayload {
                    offset: layout::AGGREGATE_PUBKEY.start,
                    bytes: vec![0u8; 96],
                },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "corrupting attested_state_root breaks finality_branch proof".to_string(),
                patch: BytePatch::InPayload {
                    offset: layout::ATTESTED_STATE_ROOT.start,
                    bytes: vec![0xff; 32],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "pointing the adapter at a different network is refused".to_string(),
                patch: BytePatch::Network {
                    value: "not-this-network".to_string(),
                },
                expect: ExpectedRefusal::Any,
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

/// Builds a bitvector with the first `count` bits set. Used by the boundary
/// probe, which is the one that catches an off-by-one in the threshold.
#[must_use]
pub fn bits_for(count: u64) -> Vec<u8> {
    let mut out = vec![0u8; BITVECTOR_BYTES];
    let mut remaining = count;
    for byte in &mut out {
        if remaining == 0 {
            break;
        }
        let set = remaining.min(8);
        *byte = u8::MAX >> (8u32.saturating_sub(set as u32));
        remaining = remaining.saturating_sub(set);
    }
    out
}

/// A [`BlsVerifier`] that accepts everything. Exists so the adapter's
/// *structural* rules can be tested without pairing arithmetic - and it is
/// deliberately in the test surface, not in production, because an adapter
/// wired to it accepts any signature.
#[cfg(test)]
pub struct AcceptAllBls;

#[cfg(test)]
impl BlsVerifier for AcceptAllBls {
    fn verify_aggregate(
        &self,
        _signing_root: &[u8; 32],
        _aggregate_pubkey: &[u8],
        _signature: &[u8],
        _participants: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn sync_committee_closed(&self) -> bool {
        false
    }
}

/// A [`BlsVerifier`] that refuses everything, for the probe that must not pass
/// by accident.
#[cfg(test)]
pub struct RefuseAllBls;

#[cfg(test)]
impl BlsVerifier for RefuseAllBls {
    fn verify_aggregate(
        &self,
        _signing_root: &[u8; 32],
        _aggregate_pubkey: &[u8],
        _signature: &[u8],
        _participants: u64,
    ) -> Result<(), String> {
        Err("refused by the test verifier".to_string())
    }

    fn sync_committee_closed(&self) -> bool {
        false
    }
}

/// A note on the proof system this adapter would use if the pairing check were
/// moved into a circuit. Exposed as a constant rather than buried in a comment,
/// because the choice is part of the security story: a STARK has a transparent
/// setup, which matters for a component whose whole job is removing trusted
/// parties.
pub const ZK_PROOF_SYSTEM: ProofSystem = ProofSystem::Stark;

#[cfg(test)]
mod slashable_policy_tests {
    use super::*;
    use crate::core::address::Address;
    use crate::cross_domain::external::spec::ExternalFinalityAdapter;

    fn test_committee() -> PinnedCommittee {
        PinnedCommittee {
            period: 0,
            aggregate_pubkey: vec![0x11; 96],
            next_committee_root: [0xbb; 32],
        }
    }

    fn evidence(adapter: &EthereumSyncAdapter) -> RawConsensusEvidence {
        let payload = build_deneb_update_payload(
            64,
            128,
            0,
            &test_committee(),
            &[0x22; 96],
            &[0xff; 64],
            [0xcc; 32],
        );
        RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: 2,
            network: "testnet".to_string(),
            payload,
            declared_height: 64,
            declared_root: [0xcc; 32],
            submitter: Address([1; 32]),
        }
    }

    #[test]
    fn a_policy_that_requires_slashable_backing_is_refused() {
        let adapter = EthereumSyncAdapter::new(
            "testnet",
            Some(test_committee()),
            Some(Box::new(AcceptAllBls)),
        );
        let ev = evidence(&adapter);
        assert!(adapter
            .verify(&ev, &VerificationPolicy::strict(1_000))
            .is_ok());
        let mut policy = VerificationPolicy::strict(1_000);
        policy.require_slashable = true;
        let err = adapter.verify(&ev, &policy).unwrap_err();
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "got {err:?}"
        );
    }

    /// The pin decides which key is trusted - a payload
    /// naming its own key is refused.
    #[test]
    fn a_payload_key_that_is_not_the_pinned_committee_is_refused() {
        let adapter = EthereumSyncAdapter::new(
            "testnet",
            Some(test_committee()),
            Some(Box::new(AcceptAllBls)),
        );
        let mut ev = evidence(&adapter);
        // The attacker's own aggregate key.
        ev.payload[layout::AGGREGATE_PUBKEY].copy_from_slice(&[0xEE; 96]);
        let err = adapter
            .verify(&ev, &VerificationPolicy::strict(1_000))
            .unwrap_err();
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "got: {err:?}"
        );
    }

    /// Rotation opens the committed root,
    /// and nothing else.
    #[test]
    fn rotation_must_open_the_committed_root() {
        let mut adapter = EthereumSyncAdapter::new(
            "testnet",
            Some(test_committee()),
            Some(Box::new(AcceptAllBls)),
        );
        // The wrong key: does not hash to [0xbb; 32].
        let wrong = PinnedCommittee {
            period: 1,
            aggregate_pubkey: vec![0xEE; 96],
            next_committee_root: [0; 32],
        };
        assert!(adapter.rotate_committee(wrong).is_err());
        // Backward periods are refused even under the right root.
        let backward = PinnedCommittee {
            period: 0,
            aggregate_pubkey: vec![0x33; 96],
            next_committee_root: [0; 32],
        };
        assert!(adapter.rotate_committee(backward).is_err());
        // The right rotation: the key whose committee_root is the pin's
        // next_committee_root.
        let next_key = vec![0x33; 96];
        let mut adapter = EthereumSyncAdapter::new(
            "testnet",
            Some(PinnedCommittee {
                period: 0,
                aggregate_pubkey: vec![0x11; 96],
                next_committee_root: committee_root(&next_key),
            }),
            Some(Box::new(AcceptAllBls)),
        );
        let good = PinnedCommittee {
            period: 1,
            aggregate_pubkey: next_key,
            next_committee_root: [0; 32],
        };
        adapter.rotate_committee(good).expect("committed rotation");
    }

    /// The signature binds the claimed state root -
    /// the same signature cannot be replayed under another root.
    #[test]
    fn the_v2_signing_root_binds_the_claimed_state_root() {
        let a = evidence(&EthereumSyncAdapter::new(
            "testnet",
            Some(test_committee()),
            Some(Box::new(AcceptAllBls)),
        ));
        let mut b = a.clone();
        set_deneb_state_root(&mut b.payload, [0xAB; 32]);
        b.declared_root = [0xAB; 32];
        let update_a = parse_update(&a.payload).unwrap();
        let update_b = parse_update(&b.payload).unwrap();
        assert_ne!(
            signing_root_v2(&update_a),
            signing_root_v2(&update_b),
            "a different state root must be a different signing root"
        );
    }

    #[test]
    fn forged_finality_branch_and_default_closed_verifier_are_refused() {
        struct DefaultClosedBls;
        impl BlsVerifier for DefaultClosedBls {
            fn verify_aggregate(
                &self,
                _signing_root: &[u8; 32],
                _aggregate_pubkey: &[u8],
                _signature: &[u8],
                _participants: u64,
            ) -> Result<(), String> {
                Ok(())
            }
        }
        let closed_adapter = EthereumSyncAdapter::new(
            "testnet",
            Some(test_committee()),
            Some(Box::new(DefaultClosedBls)),
        );
        let ev = evidence(&closed_adapter);
        assert!(matches!(
            closed_adapter.verify(&ev, &VerificationPolicy::strict(1_000)),
            Err(AdapterError::Unavailable { .. })
        ));

        let adapter = EthereumSyncAdapter::new(
            "testnet",
            Some(test_committee()),
            Some(Box::new(AcceptAllBls)),
        );
        let mut bad_branch = evidence(&adapter);
        bad_branch.payload[layout::FINALITY_BRANCH_OFFSET] ^= 0xff;
        assert!(matches!(
            adapter.verify(&bad_branch, &VerificationPolicy::strict(1_000)),
            Err(AdapterError::ConsensusRule { .. })
        ));

        let mut bad_version = evidence(&adapter);
        bad_version.evidence_version = 99;
        match adapter.verify(&bad_version, &VerificationPolicy::strict(1_000)) {
            Err(AdapterError::UnsupportedEvidenceVersion { accepted, .. }) => {
                assert_eq!(accepted, "2, 3");
            }
            other => panic!("expected UnsupportedEvidenceVersion, got {other:?}"),
        }
    }

    /// With no pinned committee the
    /// adapter is closed - every update is refused.
    #[test]
    fn committee_less_admission_is_closed() {
        let adapter = EthereumSyncAdapter::new("testnet", None, Some(Box::new(AcceptAllBls)));
        let ev = evidence(&adapter);
        let err = adapter
            .verify(&ev, &VerificationPolicy::strict(1_000))
            .unwrap_err();
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "got: {err:?}"
        );
    }

    /// Regression: a 512-member BLS12-381 sync committee verifies a
    /// real partial-quorum (350/512) pairing against the exact participating
    /// subset G1 sum and refuses any forged participation bitvector mask or
    /// mismatched signer set.
    #[test]
    fn subset_participation_verifies_real_bls_pairing_and_refuses_forged_mask() {
        use crate::cross_domain::external::intake::PairingBls;
        use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

        let mut secrets = Vec::with_capacity(SYNC_COMMITTEE_SIZE as usize);
        let mut pubkeys = Vec::with_capacity(SYNC_COMMITTEE_SIZE as usize);
        let mut full_pk = G1Projective::identity();
        for idx in 0..SYNC_COMMITTEE_SIZE {
            let sk = Scalar::from(idx + 17);
            let pk = G1Projective::generator() * sk;
            full_pk += pk;
            secrets.push(sk);
            pubkeys.push(G1Affine::from(pk).to_compressed());
        }
        let mut pinned_pk_96 = vec![0u8; 96];
        pinned_pk_96[..48].copy_from_slice(&G1Affine::from(full_pk).to_compressed());
        let committee = PinnedCommittee {
            period: 0,
            aggregate_pubkey: pinned_pk_96,
            next_committee_root: [0x5Au8; 32],
        };

        let adapter = EthereumSyncAdapter::new(
            "mainnet",
            Some(committee.clone()),
            Some(Box::new(PairingBls)),
        )
        .with_member_pubkeys(pubkeys)
        .expect("pinned 512-member roster matches full aggregate key");

        // Build an authentic 350-of-512 partial quorum update.
        let bits_350 = bits_for(350);
        let state_root = [0xC3u8; 32];
        let mut payload =
            build_deneb_update_payload(64, 96, 0, &committee, &[0u8; 96], &bits_350, state_root);
        let parsed = parse_update(&payload).expect("parse template");
        let root = signing_root_v2(&parsed);
        let h_msg = G2Projective::from(crate::chain::finality::hash_to_g2(&root));
        let mut agg_sig = G2Projective::identity();
        for sk in secrets.iter().take(350) {
            agg_sig += h_msg * sk;
        }
        let sig_bytes = G2Affine::from(agg_sig).to_compressed();
        payload[layout::SIGNATURE].copy_from_slice(&sig_bytes);

        let ev = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            network: "mainnet".to_string(),
            evidence_version: 2,
            declared_height: 64,
            declared_root: state_root,
            payload: payload.clone(),
            submitter: crate::core::address::Address([0x11; 32]),
        };
        let att = adapter
            .verify(&ev, &VerificationPolicy::strict(200))
            .expect("real 350/512 BLS12-381 subset pairing verifies");
        assert_eq!(att.height, 64);
        assert_eq!(att.state_root, state_root);

        // Forged bitvector claiming 351 signers, even when the attacker re-signs
        // the new signing root using the 350 keys they actually hold, MUST fail
        // because the verified G1 sum includes honest member #350's uncompromised key.
        let mut forged_mask = ev.clone();
        let bits_351 = bits_for(351);
        forged_mask.payload[layout::PARTICIPATION_BITS].copy_from_slice(&bits_351);
        let forged_parsed = parse_update(&forged_mask.payload).expect("parse forged");
        let forged_h = G2Projective::from(crate::chain::finality::hash_to_g2(&signing_root_v2(
            &forged_parsed,
        )));
        let mut forged_sig = G2Projective::identity();
        for sk in secrets.iter().take(350) {
            forged_sig += forged_h * sk;
        }
        forged_mask.payload[layout::SIGNATURE]
            .copy_from_slice(&G2Affine::from(forged_sig).to_compressed());
        assert!(
            matches!(
                adapter.verify(&forged_mask, &VerificationPolicy::strict(200)),
                Err(AdapterError::Crypto { .. })
            ),
            "inflating participation_bits must fail BLS pairing"
        );

        // Signing with a DIFFERENT 350-member subset (members 1..=350) while claiming 0..350 MUST fail.
        let mut wrong_subset_sig = G2Projective::identity();
        for sk in secrets.iter().skip(1).take(350) {
            wrong_subset_sig += h_msg * sk;
        }
        let mut wrong_signers = ev;
        wrong_signers.payload[layout::SIGNATURE]
            .copy_from_slice(&G2Affine::from(wrong_subset_sig).to_compressed());
        assert!(
            matches!(
                adapter.verify(&wrong_signers, &VerificationPolicy::strict(200)),
                Err(AdapterError::Crypto { .. })
            ),
            "wrong 350-signer subset must fail BLS pairing against bits[0..350]"
        );
    }

    #[test]
    fn rotate_committee_refuses_period_skip_and_ceiling_overflow() {
        let next_key = vec![0x22u8; 96];
        let pin = PinnedCommittee {
            period: 7,
            aggregate_pubkey: vec![0x11u8; 96],
            next_committee_root: committee_root(&next_key),
        };
        let mut adapter = EthereumSyncAdapter::new("mainnet", Some(pin), None);

        // Skipping from period 7 straight to period 12 with period 8's committed
        // key must be rejected fail-closed.
        let skipped = PinnedCommittee {
            period: 12,
            aggregate_pubkey: next_key.clone(),
            next_committee_root: [0x99u8; 32],
        };
        assert!(
            adapter.rotate_committee(skipped).is_err(),
            "committee rotation must refuse skipping intermediate sync-committee periods"
        );
        assert_eq!(adapter.committee.as_ref().unwrap().period, 7);

        // Exact sequential advance 7 -> 8 succeeds.
        let sequential = PinnedCommittee {
            period: 8,
            aggregate_pubkey: next_key.clone(),
            next_committee_root: [0x99u8; 32],
        };
        adapter
            .rotate_committee(sequential)
            .expect("sequential P -> P + 1 rotation succeeds");
        assert_eq!(adapter.committee.as_ref().unwrap().period, 8);

        // Ceiling overflow at u64::MAX must be refused without saturation.
        let mut ceiling_adapter = EthereumSyncAdapter::new(
            "mainnet",
            Some(PinnedCommittee {
                period: u64::MAX,
                aggregate_pubkey: vec![0x33u8; 96],
                next_committee_root: committee_root(&next_key),
            }),
            None,
        );
        assert!(ceiling_adapter
            .rotate_committee(PinnedCommittee {
                period: u64::MAX,
                aggregate_pubkey: next_key,
                next_committee_root: [0u8; 32],
            })
            .is_err());
    }

    #[test]
    fn v3_deneb_and_electra_execution_payload_and_multiperiod_ssz_rotation_verify_and_refuse_forgeries(
    ) {
        use crate::cross_domain::evm::sync_committee::{
            sync_committee_hash_tree_root, walk_branch, ExecutionPayloadHeader,
            FINALIZED_ROOT_GINDEX_DENEB, FINALIZED_ROOT_GINDEX_ELECTRA, LOGS_BLOOM_BYTES,
            NEXT_SYNC_COMMITTEE_GINDEX_DENEB, NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA,
        };
        use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
        use sha2::{Digest, Sha256};

        struct RealBls;
        impl BlsVerifier for RealBls {
            fn verify_aggregate(
                &self,
                signing_root: &[u8; 32],
                aggregate_pubkey: &[u8],
                signature: &[u8],
                _participants: u64,
            ) -> Result<(), String> {
                let pk_arr: [u8; 48] = aggregate_pubkey[..48]
                    .try_into()
                    .map_err(|_| "bad pk len".to_string())?;
                let sig_arr: [u8; 96] = signature
                    .try_into()
                    .map_err(|_| "bad sig len".to_string())?;
                let pk = G1Affine::from_compressed(&pk_arr)
                    .into_option()
                    .ok_or_else(|| "invalid G1".to_string())?;
                let sig = G2Affine::from_compressed(&sig_arr)
                    .into_option()
                    .ok_or_else(|| "invalid G2".to_string())?;
                let h = crate::chain::finality::hash_to_g2(signing_root);
                let g1_neg = -G1Affine::generator();
                let res = bls12_381::multi_miller_loop(&[(&pk, &h.into()), (&g1_neg, &sig.into())])
                    .final_exponentiation();
                if res == bls12_381::Gt::identity() {
                    Ok(())
                } else {
                    Err("BLS pairing failed".into())
                }
            }
            fn sync_committee_closed(&self) -> bool {
                false
            }
        }

        let make_roster = |tag: u64| -> (Vec<Scalar>, [[u8; 48]; 512], [u8; 48]) {
            let g1 = G1Projective::generator();
            let mut sks = Vec::with_capacity(512);
            let mut pks = [[0u8; 48]; 512];
            let mut sum = G1Projective::identity();
            for (i, slot) in pks.iter_mut().enumerate() {
                let mut wide = [0u8; 64];
                wide[..32].copy_from_slice(&Sha256::digest(
                    [
                        b"v3-a".as_slice(),
                        &tag.to_le_bytes(),
                        &(i as u64).to_le_bytes(),
                    ]
                    .concat(),
                ));
                wide[32..].copy_from_slice(&Sha256::digest(
                    [
                        b"v3-b".as_slice(),
                        &tag.to_le_bytes(),
                        &(i as u64).to_le_bytes(),
                    ]
                    .concat(),
                ));
                let sk = Scalar::from_bytes_wide(&wide);
                let pt = g1 * sk;
                *slot = G1Affine::from(pt).to_compressed();
                sum += pt;
                sks.push(sk);
            }
            (sks, pks, G1Affine::from(sum).to_compressed())
        };
        let sign_v3 = |sks: &[Scalar], raw: &mut [u8], count: usize| {
            let parsed = parse_execution_update_v3(raw).expect("valid v3 template");
            let exec_root = parsed.execution_payload.hash_tree_root().unwrap();
            let sroot = signing_root_v3(&parsed, &exec_root);
            let h = G2Projective::from(crate::chain::finality::hash_to_g2(&sroot));
            let mut acc = G2Projective::identity();
            for sk in sks.iter().take(count) {
                acc += h * sk;
            }
            raw[layout::SIGNATURE].copy_from_slice(&G2Affine::from(acc).to_compressed());
        };
        let mask_for = |count: usize| -> [u8; BITVECTOR_BYTES] {
            let mut m = [0u8; BITVECTOR_BYTES];
            for i in 0..count {
                m[i / 8] |= 1u8 << (i % 8);
            }
            m
        };

        let (sk0, pk0, agg0) = make_roster(10);
        let (sk1, pk1, agg1) = make_roster(11);
        let (sk2, pk2, agg2) = make_roster(12);

        let ssz_root_1 = sync_committee_hash_tree_root(&pk1, &agg1);
        let ssz_root_2 = sync_committee_hash_tree_root(&pk2, &agg2);

        let mut padded_agg0 = vec![0u8; 96];
        padded_agg0[..48].copy_from_slice(&agg0);
        let pin0 = PinnedCommittee {
            period: 0,
            aggregate_pubkey: padded_agg0,
            next_committee_root: ssz_root_1,
        };
        let mut adapter =
            EthereumSyncAdapter::new("mainnet", Some(pin0.clone()), Some(Box::new(RealBls)))
                .with_member_pubkeys(pk0.to_vec())
                .expect("pin period-0 512-member roster");

        // 1. Deneb v3 execution update in period 0 (gindex 105 + execution gindex 25).
        let exec0 = ExecutionPayloadHeader {
            parent_hash: [0x10; 32],
            fee_recipient: [0x20; 20],
            state_root: [0x30; 32],
            receipts_root: [0x40; 32],
            logs_bloom: vec![0u8; LOGS_BLOOM_BYTES],
            prev_randao: [0x50; 32],
            block_number: 19_500_000,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            timestamp: 1_715_000_000,
            extra_data: b"deneb-v3".to_vec(),
            base_fee_per_gas: [0x07; 32],
            block_hash: [0x60; 32],
            transactions_root: [0x70; 32],
            withdrawals_root: [0x80; 32],
            blob_gas_used: 131_072,
            excess_blob_gas: 0,
        };
        let exec_branch = [[0xA1; 32], [0xA2; 32], [0xA3; 32], [0xA4; 32]];
        let bits = mask_for(342);
        let mut raw_deneb = build_execution_update_payload_v3(&ExecutionUpdateV3Params {
            finalized_slot: 128,
            attested_slot: 192,
            period: 0,
            finalized_root_gindex: FINALIZED_ROOT_GINDEX_DENEB,
            committee: &pin0,
            signature: &[0u8; 96],
            participation_bits: &bits,
            beacon_state_root: [0xB1; 32],
            execution_branch: exec_branch,
            execution_payload: &exec0,
        })
        .expect("build Deneb v3 payload");
        assert_eq!(raw_deneb.len(), layout::LEN_V3_DENEB);
        sign_v3(&sk0, &mut raw_deneb, 342);

        let ev0 = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            network: "mainnet".to_string(),
            evidence_version: 3,
            declared_height: 128,
            declared_root: exec0.state_root,
            payload: raw_deneb.clone(),
            submitter: crate::core::address::Address([0x01; 32]),
        };
        let att0 = adapter
            .verify(&ev0, &VerificationPolicy::strict(300))
            .expect("Deneb v3 execution update verifies");
        assert_eq!(att0.state_root, exec0.state_root);
        assert_eq!(att0.attested_block_hash, Some(exec0.block_hash));
        assert_eq!(att0.attested_event_root, Some(exec0.receipts_root));
        assert_eq!(att0.attested_tx_root, Some(exec0.transactions_root));

        // Forgery A: mutating execution_branch sibling refuses fail-closed.
        let mut bad_exec_branch = ev0.clone();
        bad_exec_branch.payload[layout::LEN] ^= 0xFF;
        assert!(matches!(
            adapter.verify(&bad_exec_branch, &VerificationPolicy::strict(300)),
            Err(AdapterError::ConsensusRule { .. })
        ));
        // Forgery B: declaring Beacon state_root instead of Execution state_root refuses.
        let mut wrong_decl = ev0.clone();
        wrong_decl.declared_root = [0xB1; 32];
        assert!(matches!(
            adapter.verify(&wrong_decl, &VerificationPolicy::strict(300)),
            Err(AdapterError::DeclarationMismatch {
                field: "state_root"
            })
        ));
        // Forgery C: non-zero padding byte in extra_data refuses as Malformed.
        let mut bad_pad = ev0.clone();
        let extra_pad_last = layout::LEN + 128 + 32 + 20 + 32 + 32 + 256 + 32 + 32 + 1 + 31;
        bad_pad.payload[extra_pad_last] = 0x01;
        assert!(matches!(
            adapter.verify(&bad_pad, &VerificationPolicy::strict(300)),
            Err(AdapterError::Malformed { .. })
        ));

        // 2. Chain two SSZ rotations: 0 -> 1 (Deneb gindex 55) and 1 -> 2 (Electra gindex 87).
        let branch_55: Vec<[u8; 32]> = (0u8..5).map(|i| [0xC1 + i; 32]).collect();
        let fin_state_0 =
            walk_branch(ssz_root_1, &branch_55, NEXT_SYNC_COMMITTEE_GINDEX_DENEB).unwrap();
        let rot_to_1 = SszCommitteeRotation {
            next_period: 1,
            next_member_pubkeys: pk1,
            next_aggregate_pubkey: agg1,
            finalized_state_root: fin_state_0,
            next_sync_committee_gindex: NEXT_SYNC_COMMITTEE_GINDEX_DENEB,
            next_sync_committee_branch: branch_55,
            finalized_root_gindex: FINALIZED_ROOT_GINDEX_DENEB,
            subsequent_committee_root: ssz_root_2,
        };
        // Wrong fork gindex or period skip must refuse before mutating the pinned committee.
        let mut wrong_fork_rot = rot_to_1.clone();
        wrong_fork_rot.next_sync_committee_gindex = NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA;
        assert!(adapter
            .rotate_committee_with_ssz_branch(&wrong_fork_rot)
            .is_err());
        let mut skipped_rot = rot_to_1.clone();
        skipped_rot.next_period = 2;
        assert!(adapter
            .rotate_committee_with_ssz_branch(&skipped_rot)
            .is_err());

        adapter
            .rotate_committee_with_ssz_branch(&rot_to_1)
            .expect("Deneb SSZ rotation 0 -> 1 succeeds");
        assert!(
            adapter
                .verify(&ev0, &VerificationPolicy::strict(300))
                .is_err(),
            "period-0 update must no longer verify after rotating to period 1"
        );

        let branch_87: Vec<[u8; 32]> = (0u8..6).map(|i| [0xD1 + i; 32]).collect();
        let fin_state_1 =
            walk_branch(ssz_root_2, &branch_87, NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA).unwrap();
        adapter
            .rotate_committee_with_ssz_branch(&SszCommitteeRotation {
                next_period: 2,
                next_member_pubkeys: pk2,
                next_aggregate_pubkey: agg2,
                finalized_state_root: fin_state_1,
                next_sync_committee_gindex: NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA,
                next_sync_committee_branch: branch_87,
                finalized_root_gindex: FINALIZED_ROOT_GINDEX_ELECTRA,
                subsequent_committee_root: [0xEE; 32],
            })
            .expect("Electra SSZ rotation 1 -> 2 succeeds");

        // 3. Electra v3 execution update in period 2 verifies against rotated `pk2` subset!
        let pin2 = adapter.committee.clone().unwrap();
        let exec2 = ExecutionPayloadHeader {
            state_root: [0x32; 32],
            receipts_root: [0x42; 32],
            block_hash: [0x62; 32],
            transactions_root: [0x72; 32],
            block_number: 22_000_000,
            ..exec0
        };
        let slot_p2 = 2 * EPOCHS_PER_SYNC_COMMITTEE_PERIOD * SLOTS_PER_EPOCH + 128;
        let mut raw_electra = build_execution_update_payload_v3(&ExecutionUpdateV3Params {
            finalized_slot: slot_p2,
            attested_slot: slot_p2 + 64,
            period: 2,
            finalized_root_gindex: FINALIZED_ROOT_GINDEX_ELECTRA,
            committee: &pin2,
            signature: &[0u8; 96],
            participation_bits: &mask_for(360),
            beacon_state_root: [0xB2; 32],
            execution_branch: exec_branch,
            execution_payload: &exec2,
        })
        .expect("build Electra v3 payload");
        assert_eq!(raw_electra.len(), layout::LEN_V3_ELECTRA);
        // Signing with retired period-1 committee keys MUST fail pairing!
        sign_v3(&sk1, &mut raw_electra, 360);
        let mut ev2 = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            network: "mainnet".to_string(),
            evidence_version: 3,
            declared_height: slot_p2,
            declared_root: exec2.state_root,
            payload: raw_electra.clone(),
            submitter: crate::core::address::Address([0x02; 32]),
        };
        assert!(matches!(
            adapter.verify(&ev2, &VerificationPolicy::strict(slot_p2 + 200)),
            Err(AdapterError::Crypto { .. })
        ));

        // Signing with period-2 rotated keys verifies and outputs proven execution roots!
        sign_v3(&sk2, &mut ev2.payload, 360);
        let att2 = adapter
            .verify(&ev2, &VerificationPolicy::strict(slot_p2 + 200))
            .expect("Electra v3 execution update verifies in period 2");
        assert_eq!(att2.height, slot_p2);
        assert_eq!(att2.state_root, exec2.state_root);
        assert_eq!(att2.attested_block_hash, Some(exec2.block_hash));
        assert_eq!(att2.attested_event_root, Some(exec2.receipts_root));
        assert_eq!(att2.attested_tx_root, Some(exec2.transactions_root));
    }
}
