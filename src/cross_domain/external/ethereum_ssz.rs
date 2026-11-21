//! Strict canonical SSZ decoding and Merkleization for real Ethereum
//! light-client finality updates (sync-committee evidence format v4).
//!
//! Everything here is byte-exact against the consensus specifications: the
//! container layouts, the `hash_tree_root` shapes, the generalized indices,
//! and the `DOMAIN_SYNC_COMMITTEE` signing root. Nothing is read from the
//! caller's description of the data; every length and offset is checked
//! against the bytes themselves, and anything unexpected is refused.
//!
//! WIRING: Canonical Deneb/Electra/Fulu SSZ layout constants and header
//! containers consumed by `ethereum.rs` sync-committee v4 verification.

use crate::cross_domain::evm::sync_committee::{
    merkleize_chunks, sha256_pair, u64_chunk, walk_branch,
};
use crate::cross_domain::external::spec::AdapterError;

/// Slots in one beacon epoch.
pub const SLOTS_PER_EPOCH: u64 = 32;
/// Slots in one sync-committee period (256 epochs).
pub const SLOTS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256 * SLOTS_PER_EPOCH;
/// Members in one sync committee.
pub const SYNC_COMMITTEE_MEMBERS: usize = 512;
/// Byte length of the canonical SSZ `SyncCommittee` encoding
/// (512 compressed G1 pubkeys plus one compressed aggregate).
pub const SYNC_COMMITTEE_SSZ_LEN: usize = SYNC_COMMITTEE_MEMBERS * 48 + 48;
/// Fixed part of a Deneb `LightClientFinalityUpdate` (6-sibling branch).
pub const FINALITY_UPDATE_FIXED_DENEB: usize = 368;
/// Fixed part of an Electra-or-later `LightClientFinalityUpdate` (7 siblings).
pub const FINALITY_UPDATE_FIXED_ELECTRA: usize = 400;
/// Fixed part of a Deneb-or-later `LightClientHeader`.
pub const LIGHT_CLIENT_HEADER_FIXED: usize = 244;
/// Fixed part of a Deneb-or-later `ExecutionPayloadHeader`.
pub const EXECUTION_HEADER_FIXED: usize = 584;
/// `ExecutionPayloadHeader` inside `BeaconBlockBody` (Deneb and later).
pub const EXECUTION_PAYLOAD_GINDEX: u64 = 25;
/// `DOMAIN_SYNC_COMMITTEE` (Altair).
pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];

fn malformed(offset: usize, reason: impl Into<String>) -> AdapterError {
    AdapterError::Malformed {
        offset,
        reason: reason.into(),
    }
}

fn rule(reason: impl Into<String>) -> AdapterError {
    AdapterError::ConsensusRule {
        rule: reason.into(),
    }
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<usize, AdapterError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| malformed(offset, "u32 past the end of the payload"))?
        .try_into()
        .map_err(|_| malformed(offset, "u32 slice conversion failed"))?;
    Ok(u32::from_le_bytes(raw) as usize)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, AdapterError> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| malformed(offset, "u64 past the end of the payload"))?
        .try_into()
        .map_err(|_| malformed(offset, "u64 slice conversion failed"))?;
    Ok(u64::from_le_bytes(raw))
}

fn read_32(bytes: &[u8], offset: usize) -> Result<[u8; 32], AdapterError> {
    bytes
        .get(offset..offset + 32)
        .ok_or_else(|| malformed(offset, "32-byte word past the end of the payload"))?
        .try_into()
        .map_err(|_| malformed(offset, "32-byte slice conversion failed"))
}

/// A parsed `BeaconBlockHeader` (fixed 112 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

impl BeaconHeader {
    /// The canonical SSZ `hash_tree_root`: five leaves padded to eight.
    #[must_use]
    pub fn hash_tree_root(&self) -> [u8; 32] {
        merkleize_chunks(&[
            u64_chunk(self.slot),
            u64_chunk(self.proposer_index),
            self.parent_root,
            self.state_root,
            self.body_root,
        ])
    }
}

fn parse_beacon_header(bytes: &[u8], offset: usize) -> Result<BeaconHeader, AdapterError> {
    Ok(BeaconHeader {
        slot: read_u64_le(bytes, offset)?,
        proposer_index: read_u64_le(bytes, offset + 8)?,
        parent_root: read_32(bytes, offset + 16)?,
        state_root: read_32(bytes, offset + 48)?,
        body_root: read_32(bytes, offset + 80)?,
    })
}

/// `hash_tree_root(ExecutionPayloadHeader)` for the Deneb-and-later 17-field
/// header: fixed 584 bytes followed by `extra_data` (`ByteList[32]`).
pub fn execution_payload_root(execution: &[u8]) -> Result<[u8; 32], AdapterError> {
    if execution.len() < EXECUTION_HEADER_FIXED {
        return Err(malformed(
            execution.len(),
            "execution payload header shorter than its fixed part",
        ));
    }
    let extra_offset = read_u32_le(execution, 436)?;
    if extra_offset != EXECUTION_HEADER_FIXED {
        return Err(malformed(
            436,
            format!("extra_data offset is {extra_offset}, not {EXECUTION_HEADER_FIXED}"),
        ));
    }
    let extra = execution.get(EXECUTION_HEADER_FIXED..).ok_or_else(|| {
        malformed(
            execution.len(),
            "execution payload header shorter than its fixed part",
        )
    })?;
    if extra.len() > 32 {
        return Err(malformed(
            EXECUTION_HEADER_FIXED,
            format!("extra_data is {} bytes, the bound is 32", extra.len()),
        ));
    }
    let mut extra_chunk = [0u8; 32];
    if let Some(prefix) = extra_chunk.get_mut(..extra.len()) {
        prefix.copy_from_slice(extra);
    }
    let extra_root = sha256_pair(&extra_chunk, &u64_chunk(extra.len() as u64));

    let mut bloom_chunks = [[0u8; 32]; 8];
    for (i, chunk) in bloom_chunks.iter_mut().enumerate() {
        chunk.copy_from_slice(
            execution
                .get(116 + 32 * i..148 + 32 * i)
                .ok_or_else(|| malformed(116, "logs_bloom past the fixed part"))?,
        );
    }
    let bloom_root = merkleize_chunks(&bloom_chunks);

    let mut fee_recipient = [0u8; 32];
    if let Some(prefix) = fee_recipient.get_mut(..20) {
        prefix.copy_from_slice(
            execution
                .get(32..52)
                .ok_or_else(|| malformed(32, "fee_recipient past the fixed part"))?,
        );
    }

    Ok(merkleize_chunks(&[
        read_32(execution, 0)?,
        fee_recipient,
        read_32(execution, 52)?,
        read_32(execution, 84)?,
        bloom_root,
        read_32(execution, 372)?,
        u64_chunk(read_u64_le(execution, 404)?),
        u64_chunk(read_u64_le(execution, 412)?),
        u64_chunk(read_u64_le(execution, 420)?),
        u64_chunk(read_u64_le(execution, 428)?),
        extra_root,
        read_32(execution, 440)?,
        read_32(execution, 472)?,
        read_32(execution, 504)?,
        read_32(execution, 536)?,
        u64_chunk(read_u64_le(execution, 568)?),
        u64_chunk(read_u64_le(execution, 576)?),
    ]))
}

/// The fields of the finalized execution payload an attestation speaks
/// about: the state root, the receipts root, the block hash, and the
/// transactions root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionFields {
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub block_hash: [u8; 32],
    pub transactions_root: [u8; 32],
}

/// Read the attestation-relevant fields of an `ExecutionPayloadHeader`.
pub fn execution_fields(execution: &[u8]) -> Result<ExecutionFields, AdapterError> {
    if execution.len() < EXECUTION_HEADER_FIXED {
        return Err(malformed(
            execution.len(),
            "execution payload header shorter than its fixed part",
        ));
    }
    Ok(ExecutionFields {
        state_root: read_32(execution, 52)?,
        receipts_root: read_32(execution, 84)?,
        block_hash: read_32(execution, 472)?,
        transactions_root: read_32(execution, 504)?,
    })
}

/// A `LightClientHeader` (Deneb shape: beacon header, execution branch of
/// four siblings, execution payload header with variable `extra_data`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightClientHeader {
    pub beacon: BeaconHeader,
    pub execution_branch: [[u8; 32]; 4],
    /// The raw `ExecutionPayloadHeader` bytes (fixed part plus `extra_data`).
    pub execution: Vec<u8>,
}

fn parse_light_client_header(
    bytes: &[u8],
    offset: usize,
    end: usize,
) -> Result<LightClientHeader, AdapterError> {
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| malformed(offset, "header range outside the payload"))?;
    if slice.len() < LIGHT_CLIENT_HEADER_FIXED + EXECUTION_HEADER_FIXED {
        return Err(malformed(
            offset,
            "light client header shorter than beacon header plus fixed execution part",
        ));
    }
    let exec_offset = read_u32_le(slice, 112)?;
    if exec_offset != LIGHT_CLIENT_HEADER_FIXED {
        return Err(malformed(
            offset + 112,
            format!("execution offset is {exec_offset}, not {LIGHT_CLIENT_HEADER_FIXED}"),
        ));
    }
    let beacon = parse_beacon_header(slice, 0)?;
    let mut execution_branch = [[0u8; 32]; 4];
    for (i, sibling) in execution_branch.iter_mut().enumerate() {
        *sibling = read_32(slice, 116 + 32 * i)?;
    }
    let execution = slice
        .get(LIGHT_CLIENT_HEADER_FIXED..)
        .ok_or_else(|| malformed(offset, "light client header missing execution payload"))?
        .to_vec();
    // The execution header's own internal discipline is checked now, so a
    // malformed `extra_data` region is refused at parse time rather than
    // silently hashed later.
    let _ = execution_payload_root(&execution)?;
    Ok(LightClientHeader {
        beacon,
        execution_branch,
        execution,
    })
}

/// One fork-schedule entry: the fork version active from an epoch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ForkEpoch {
    pub activation_epoch: u64,
    pub version: [u8; 4],
}

/// The fork schedule the pinned committee answers to. Carried with the pin:
/// a schedule the caller supplies is a fact about the network the caller
/// trusts, and the verifier resolves it deterministically.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ForkSchedule {
    /// Descending by activation epoch.
    entries: Vec<ForkEpoch>,
}

impl ForkSchedule {
    /// Ethereum mainnet: Deneb 269568, Electra 364032, Fulu 411392.
    #[must_use]
    pub fn mainnet() -> Self {
        Self {
            entries: vec![
                ForkEpoch {
                    activation_epoch: 411_392,
                    version: [0x06, 0x00, 0x00, 0x00],
                },
                ForkEpoch {
                    activation_epoch: 364_032,
                    version: [0x05, 0x00, 0x00, 0x00],
                },
                ForkEpoch {
                    activation_epoch: 269_568,
                    version: [0x04, 0x00, 0x00, 0x00],
                },
            ],
        }
    }

    /// Build a custom fork schedule (e.g. Holesky or Sepolia) after checking
    /// that it is non-empty and strictly descending by `activation_epoch`.
    ///
    /// Convenience: exposed for non-mainnet `SszCommitteePin` configurations.
    pub fn from_descending_epochs(entries: Vec<ForkEpoch>) -> Result<Self, AdapterError> {
        if entries.is_empty() {
            return Err(rule("fork schedule must contain at least one fork epoch"));
        }
        for pair in entries.windows(2) {
            if let [newer, older] = pair {
                if newer.activation_epoch <= older.activation_epoch {
                    return Err(rule(
                        "fork schedule entries must be strictly descending by activation_epoch",
                    ));
                }
            }
        }
        Ok(Self { entries })
    }

    /// The fork version active at `epoch`, if the schedule reaches that far.
    #[must_use]
    pub fn version_at(&self, epoch: u64) -> Option<[u8; 4]> {
        self.entries
            .iter()
            .find(|entry| epoch >= entry.activation_epoch)
            .map(|entry| entry.version)
    }

    /// The epoch at which the post-Deneb state-container shape begins. The
    /// finality branch length and the `finalized_root` generalized index
    /// change at this boundary.
    #[must_use]
    pub fn electra_shape_epoch(&self) -> Option<u64> {
        // Descending order: the oldest entry is Deneb, and the entry right
        // before it (`len - 2`) is the Electra shape boundary regardless of
        // network-specific fork-version bytes (Sepolia `0x90..`, Holesky
        // `0x06017000`, mainnet `0x05000000`). A one-entry schedule never
        // leaves the Deneb shape.
        self.entries
            .len()
            .checked_sub(2)
            .and_then(|idx| self.entries.get(idx))
            .map(|entry| entry.activation_epoch)
    }
}

/// The `finalized_root` generalized index for the state-container shape
/// active at `attested_slot`: 105 before the Electra shape, 169 from it on.
pub fn finality_gindex(attested_slot: u64, schedule: &ForkSchedule) -> u64 {
    let epoch = attested_slot / SLOTS_PER_EPOCH;
    match schedule.electra_shape_epoch() {
        Some(boundary) if epoch >= boundary => 169,
        _ => 105,
    }
}

/// A parsed real `LightClientFinalityUpdate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalityUpdate {
    pub attested: LightClientHeader,
    pub finalized: LightClientHeader,
    pub finality_branch: Vec<[u8; 32]>,
    pub participation_bits: [u8; 64],
    pub signature: [u8; 96],
    pub signature_slot: u64,
}

/// Parse the canonical SSZ bytes of a `LightClientFinalityUpdate`.
///
/// The fixed-part length names the fork shape (368 = Deneb, 400 = Electra+)
/// and is then cross-checked against the attested slot's own fork, so a
/// Deneb-shaped claim about an Electra slot is refused rather than parsed
/// with the wrong branch depth.
pub fn parse_finality_update(
    bytes: &[u8],
    schedule: &ForkSchedule,
) -> Result<FinalityUpdate, AdapterError> {
    let offset_attested = read_u32_le(bytes, 0)?;
    let offset_finalized = read_u32_le(bytes, 4)?;
    let branch_len = match offset_attested {
        FINALITY_UPDATE_FIXED_DENEB => 6usize,
        FINALITY_UPDATE_FIXED_ELECTRA => 7usize,
        other => {
            return Err(malformed(
                0,
                format!(
                    "first offset {other} is neither the Deneb fixed part \
                     ({FINALITY_UPDATE_FIXED_DENEB}) nor the Electra one \
                     ({FINALITY_UPDATE_FIXED_ELECTRA})"
                ),
            ));
        }
    };
    if offset_finalized <= offset_attested || offset_finalized > bytes.len() {
        return Err(malformed(
            4,
            "finalized header offset does not lie past the attested one inside the payload",
        ));
    }
    let mut finality_branch = Vec::with_capacity(branch_len);
    for i in 0..branch_len {
        finality_branch.push(read_32(bytes, 8 + 32 * i)?);
    }
    let bits_offset = 8 + 32 * branch_len;
    let participation_bits: [u8; 64] = bytes
        .get(bits_offset..bits_offset + 64)
        .ok_or_else(|| malformed(bits_offset, "participation bits past the fixed part"))?
        .try_into()
        .map_err(|_| malformed(bits_offset, "participation bits slice conversion failed"))?;
    let signature: [u8; 96] = bytes
        .get(bits_offset + 64..bits_offset + 160)
        .ok_or_else(|| malformed(bits_offset + 64, "signature past the fixed part"))?
        .try_into()
        .map_err(|_| malformed(bits_offset + 64, "signature slice conversion failed"))?;
    let signature_slot = read_u64_le(bytes, bits_offset + 160)?;

    let attested = parse_light_client_header(bytes, offset_attested, offset_finalized)?;
    let finalized = parse_light_client_header(bytes, offset_finalized, bytes.len())?;

    // The fork shape named by the fixed part must agree with the fork the
    // attested slot actually lives in.
    let epoch = attested.beacon.slot / SLOTS_PER_EPOCH;
    let shape_boundary = schedule.electra_shape_epoch();
    let expected_len = match shape_boundary {
        Some(boundary) if epoch >= boundary => 7usize,
        _ => 6usize,
    };
    if branch_len != expected_len {
        return Err(rule(format!(
            "finality branch has {branch_len} siblings but the attested slot's fork \
             takes {expected_len}"
        )));
    }
    // The signature slot must never precede the header the committee signed.
    if signature_slot <= attested.beacon.slot {
        return Err(rule("the signature slot is not after the attested slot"));
    }
    if finalized.beacon.slot > attested.beacon.slot {
        return Err(rule("finalized slot is ahead of the attested slot"));
    }
    Ok(FinalityUpdate {
        attested,
        finalized,
        finality_branch,
        participation_bits,
        signature,
        signature_slot,
    })
}

/// `hash_tree_root(SyncCommittee)`: the 512 pubkeys as a vector of
/// two-chunk `Bytes48` roots, paired with the aggregate key's root.
pub fn sync_committee_root(committee: &[u8]) -> Result<[u8; 32], AdapterError> {
    if committee.len() != SYNC_COMMITTEE_SSZ_LEN {
        return Err(malformed(
            0,
            format!(
                "sync committee encoding is {} bytes, the canonical length is {SYNC_COMMITTEE_SSZ_LEN}",
                committee.len()
            ),
        ));
    }
    let mut member_roots = [[0u8; 32]; SYNC_COMMITTEE_MEMBERS];
    for (i, root) in member_roots.iter_mut().enumerate() {
        let base = i * 48;
        let first: [u8; 32] = committee
            .get(base..base + 32)
            .ok_or_else(|| malformed(base, "pubkey past the committee encoding"))?
            .try_into()
            .map_err(|_| malformed(base, "pubkey slice conversion failed"))?;
        let mut second = [0u8; 32];
        let member_tail = committee
            .get(base + 32..base + 48)
            .ok_or_else(|| malformed(base + 32, "pubkey tail past the committee encoding"))?;
        if let Some(prefix) = second.get_mut(..16) {
            prefix.copy_from_slice(member_tail);
        }
        *root = sha256_pair(&first, &second);
    }
    let vector_root = merkleize_chunks(&member_roots);
    let aggregate = committee
        .get(SYNC_COMMITTEE_MEMBERS * 48..)
        .ok_or_else(|| malformed(SYNC_COMMITTEE_MEMBERS * 48, "aggregate past the encoding"))?;
    let agg_first: [u8; 32] = aggregate
        .get(..32)
        .ok_or_else(|| malformed(SYNC_COMMITTEE_MEMBERS * 48, "aggregate past the encoding"))?
        .try_into()
        .map_err(|_| malformed(0, "aggregate slice conversion failed"))?;
    let mut agg_second = [0u8; 32];
    let agg_tail = aggregate
        .get(32..48)
        .ok_or_else(|| malformed(0, "aggregate tail past the encoding"))?;
    if let Some(prefix) = agg_second.get_mut(..16) {
        prefix.copy_from_slice(agg_tail);
    }
    Ok(sha256_pair(
        &vector_root,
        &sha256_pair(&agg_first, &agg_second),
    ))
}

/// The 512 member pubkeys of a canonical committee encoding.
pub fn sync_committee_pubkeys(
    committee: &[u8],
) -> Result<[[u8; 48]; SYNC_COMMITTEE_MEMBERS], AdapterError> {
    if committee.len() != SYNC_COMMITTEE_SSZ_LEN {
        return Err(malformed(
            0,
            format!(
                "sync committee encoding is {} bytes, the canonical length is {SYNC_COMMITTEE_SSZ_LEN}",
                committee.len()
            ),
        ));
    }
    let mut out = [[0u8; 48]; SYNC_COMMITTEE_MEMBERS];
    for (i, key) in out.iter_mut().enumerate() {
        key.copy_from_slice(
            committee
                .get(i * 48..i * 48 + 48)
                .ok_or_else(|| malformed(i * 48, "pubkey past the committee encoding"))?,
        );
    }
    Ok(out)
}

/// The aggregate pubkey of a canonical committee encoding.
pub fn sync_committee_aggregate(committee: &[u8]) -> Result<[u8; 48], AdapterError> {
    if committee.len() != SYNC_COMMITTEE_SSZ_LEN {
        return Err(malformed(
            0,
            format!(
                "sync committee encoding is {} bytes, the canonical length is {SYNC_COMMITTEE_SSZ_LEN}",
                committee.len()
            ),
        ));
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(
        committee
            .get(SYNC_COMMITTEE_MEMBERS * 48..)
            .ok_or_else(|| malformed(SYNC_COMMITTEE_MEMBERS * 48, "aggregate past the encoding"))?,
    );
    Ok(out)
}

/// `compute_signing_root(attested_header, domain)` with
/// `domain = DOMAIN_SYNC_COMMITTEE || fork_data_root[..28]`.
pub fn sync_committee_signing_root(
    attested: &BeaconHeader,
    fork_version: [u8; 4],
    genesis_validators_root: &[u8; 32],
) -> [u8; 32] {
    let mut version_chunk = [0u8; 32];
    if let Some(prefix) = version_chunk.get_mut(..4) {
        prefix.copy_from_slice(&fork_version);
    }
    let fork_data_root = sha256_pair(&version_chunk, genesis_validators_root);
    let mut domain = [0u8; 32];
    if let Some(prefix) = domain.get_mut(..4) {
        prefix.copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
    }
    if let (Some(dst), Some(src)) = (domain.get_mut(4..32), fork_data_root.get(..28)) {
        dst.copy_from_slice(src);
    }
    sha256_pair(&attested.hash_tree_root(), &domain)
}

/// Verify `finalized` under the attested header's state root, then the
/// finalized execution payload under the finalized body root, and return the
/// execution fields the whole chain of proofs commits to.
pub fn verify_finality_and_execution(
    update: &FinalityUpdate,
    schedule: &ForkSchedule,
) -> Result<ExecutionFields, AdapterError> {
    let gindex = finality_gindex(update.attested.beacon.slot, schedule);
    let proven = walk_branch(
        update.finalized.beacon.hash_tree_root(),
        &update.finality_branch,
        gindex,
    );
    if proven != Some(update.attested.beacon.state_root) {
        return Err(rule(
            "the finality branch does not prove the finalized header under the attested state root",
        ));
    }
    let execution_root = execution_payload_root(&update.finalized.execution)?;
    let proven_body = walk_branch(
        execution_root,
        &update.finalized.execution_branch,
        EXECUTION_PAYLOAD_GINDEX,
    );
    if proven_body != Some(update.finalized.beacon.body_root) {
        return Err(rule(
            "the execution branch does not prove the payload header under the finalized body root",
        ));
    }
    execution_fields(&update.finalized.execution)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_sepolia_and_holesky_schedules_preserve_electra_shape_boundary() {
        let sepolia = ForkSchedule::from_descending_epochs(vec![
            ForkEpoch {
                activation_epoch: 272_640,
                version: [0x90, 0x00, 0x00, 0x75],
            },
            ForkEpoch {
                activation_epoch: 222_464,
                version: [0x90, 0x00, 0x00, 0x74],
            },
            ForkEpoch {
                activation_epoch: 132_608,
                version: [0x90, 0x00, 0x00, 0x73],
            },
        ])
        .expect("descending Sepolia schedule");
        assert_eq!(sepolia.electra_shape_epoch(), Some(222_464));
        assert_eq!(finality_gindex(222_463 * SLOTS_PER_EPOCH, &sepolia), 105);
        assert_eq!(finality_gindex(222_464 * SLOTS_PER_EPOCH, &sepolia), 169);

        let deneb_only = ForkSchedule::from_descending_epochs(vec![ForkEpoch {
            activation_epoch: 132_608,
            version: [0x90, 0x00, 0x00, 0x73],
        }])
        .expect("single-fork Deneb schedule");
        assert_eq!(deneb_only.electra_shape_epoch(), None);
        assert_eq!(finality_gindex(500_000 * SLOTS_PER_EPOCH, &deneb_only), 105);
    }

    #[test]
    fn non_descending_or_empty_fork_schedule_is_refused() {
        assert!(ForkSchedule::from_descending_epochs(Vec::new()).is_err());
        assert!(ForkSchedule::from_descending_epochs(vec![
            ForkEpoch {
                activation_epoch: 100,
                version: [0x05, 0, 0, 0],
            },
            ForkEpoch {
                activation_epoch: 100,
                version: [0x04, 0, 0, 0],
            },
        ])
        .is_err());
    }

    #[test]
    fn execution_payload_root_refuses_short_or_overlong_extra_data_without_panic() {
        assert!(execution_payload_root(&[0u8; EXECUTION_HEADER_FIXED - 1]).is_err());

        let mut header = vec![0u8; EXECUTION_HEADER_FIXED + 33];
        header[436..440].copy_from_slice(&(EXECUTION_HEADER_FIXED as u32).to_le_bytes());
        let err = execution_payload_root(&header).expect_err("33-byte extra_data must fail");
        assert!(matches!(err, AdapterError::Malformed { offset: 584, .. }));
    }
}
