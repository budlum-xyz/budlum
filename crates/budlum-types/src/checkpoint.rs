//! Checkpoint and validator-set wire types shared by the node and mobile core (K-4).
//!
//! A phone following the chain without linking `budlum-core` (section 7.9.5)
//! must recompute the exact validator-set commitment (`ValidatorSetSnapshot`),
//! the exact post-quantum quorum Merkle root (`QcBlob`), and the exact
//! length-prefixed attestation preimage (`pq_signing_message`) that full nodes
//! produce and check. Keeping a second copy in `mobile/` would compile cleanly
//! and fail silently on the first field-order or tag edit. Defining the types
//! and pure checks here binds both sides to one implementation.
//! Convenience: exposed for workspace subcrate consumers, SDK bindings, and integration callers.

use crate::handoff::HandoffMember;
use crate::Address;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;
use std::fmt;

/// Quorum numerator: strictly more than `2/3` of stake, `ceil(2n/3)` of signers.
pub const FINALITY_QUORUM_NUMERATOR: u64 = 2;
/// Quorum denominator (`2/3`).
pub const FINALITY_QUORUM_DENOMINATOR: u64 = 3;
/// Epochs before a non-handoff QC blob expires in full-node retention.
pub const QC_BLOB_TTL_EPOCHS: u64 = 10;
/// Canonical binary wire version of [`QcBlob`].
pub const QC_WIRE_VERSION: u8 = 2;
/// Longest UTF-8 string field permitted on the [`QcBlob`] binary wire.
pub const QC_WIRE_MAX_STRING: usize = 128;
/// Longest PQ signature permitted on the [`QcBlob`] binary wire (ML-DSA-87: 4,627 bytes).
pub const QC_WIRE_MAX_SIGNATURE: usize = 4_627;
/// Transport chunk size for large [`QcBlob`] transfers (256 KiB).
pub const QC_CHUNK_BYTES: usize = 256 * 1024;
/// Big-endian wire identifier of ML-DSA-65, folded into [`pq_signing_message`].
///
/// This MUST stay equal to the node's registered `SchemeId::ML_DSA_65`
/// (`0x0102`): the phone and the node fold this value into the same QC
/// signing message, and any divergence makes each side reject the other's
/// checkpoint signatures.
pub const ML_DSA_65_SCHEME_WIRE_ID: u16 = 0x0102;

const QC_ENTRY_OVERHEAD: usize = 4 + 2 + QC_WIRE_MAX_STRING + 4;
/// Largest wire size of one [`PqSignatureEntry`].
pub const QC_ENTRY_MAX_BYTES: usize = QC_ENTRY_OVERHEAD + QC_WIRE_MAX_SIGNATURE;
const QC_HEADER_MAX_BYTES: usize = 1 + 8 + 8 + (2 + QC_WIRE_MAX_STRING) * 2 + 8 + 4;

/// Maximum binary wire length of a [`QcBlob`] for a set of `validators` members.
#[must_use]
pub const fn qc_blob_max_bytes(validators: usize) -> usize {
    QC_HEADER_MAX_BYTES + validators * QC_ENTRY_MAX_BYTES
}

/// Whether `text` is a canonical 64-character lowercase hexadecimal digest.
#[must_use]
pub fn is_canonical_hash(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn update_with_len(hasher: &mut Sha3_256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Hash a validator's consensus keys with explicit little-endian `u64` length
/// prefixes, matching `crypto::key_set_preimage::update_consensus_keys_sha3`.
pub fn update_consensus_keys_sha3(
    hasher: &mut impl Digest,
    vrf: Option<&[u8]>,
    bls: &[u8],
    pop: &[u8],
    pq: &[u8],
) {
    if let Some(vrf) = vrf {
        hasher.update((vrf.len() as u64).to_le_bytes());
        hasher.update(vrf);
    }
    for field in [bls, pop, pq] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
}

/// One validator entry inside a [`ValidatorSetSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pub address: Address,
    pub stake: u64,
    #[serde(default)]
    pub bls_public_key: Vec<u8>,
    #[serde(default)]
    pub pop_signature: Vec<u8>,
    #[serde(default)]
    pub pq_public_key: Vec<u8>,
}

/// Consensus validator-set snapshot for one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSetSnapshot {
    pub epoch: u64,
    pub validators: Vec<ValidatorEntry>,
    pub set_hash: String,
    pub total_stake: u64,
}

impl ValidatorSetSnapshot {
    #[must_use]
    pub fn new(epoch: u64, validators: Vec<ValidatorEntry>) -> Self {
        let total_stake = validators
            .iter()
            .fold(0u64, |acc, v| acc.saturating_add(v.stake));
        let set_hash = Self::compute_hash(&validators);
        Self {
            epoch,
            validators,
            set_hash,
            total_stake,
        }
    }

    #[must_use]
    pub fn compute_hash(validators: &[ValidatorEntry]) -> String {
        let mut sorted = validators.to_vec();
        sorted.sort_by_key(|v| v.address);

        let mut hasher = Sha3_256::new();
        for v in sorted {
            hasher.update(v.address.0);
            hasher.update(v.stake.to_le_bytes());
            update_consensus_keys_sha3(
                &mut hasher,
                None,
                &v.bls_public_key,
                &v.pop_signature,
                &v.pq_public_key,
            );
        }
        hex::encode(hasher.finalize())
    }

    /// Recomputes `set_hash` and `total_stake` from `validators` so an untrusted
    /// wire snapshot cannot forge a lower quorum denominator.
    ///
    /// # Errors
    ///
    /// Returns a descriptive mismatch error if either field disagrees.
    pub fn validate_metadata(&self) -> Result<(), String> {
        let computed_hash = Self::compute_hash(&self.validators);
        if self.set_hash != computed_hash {
            return Err(format!(
                "ValidatorSetSnapshot set_hash mismatch: claimed {}, computed {}",
                self.set_hash, computed_hash
            ));
        }
        let sum: u128 = self.validators.iter().map(|v| u128::from(v.stake)).sum();
        let expected_total = u64::try_from(sum.min(u128::from(u64::MAX))).unwrap_or(u64::MAX);
        if self.total_stake != expected_total {
            return Err(format!(
                "ValidatorSetSnapshot total_stake mismatch: claimed {}, computed sum {}",
                self.total_stake, expected_total
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn find_validator(&self, address: &Address) -> Option<&ValidatorEntry> {
        self.validators.iter().find(|v| &v.address == address)
    }

    #[must_use]
    pub fn validator_index(&self, address: &Address) -> Option<usize> {
        self.validators.iter().position(|v| &v.address == address)
    }

    fn stake_sum(&self) -> u128 {
        self.validators.iter().map(|v| u128::from(v.stake)).sum()
    }

    /// Strictly more than two thirds of the exact `u128` summed stake.
    #[must_use]
    pub fn quorum_stake(&self) -> u128 {
        (self.stake_sum() * u128::from(FINALITY_QUORUM_NUMERATOR))
            / u128::from(FINALITY_QUORUM_DENOMINATOR)
            + 1
    }

    /// Signer-count threshold `ceil(2n/3)` for post-quantum checkpoint verification.
    #[must_use]
    pub fn quorum_count(&self) -> usize {
        let num = usize::try_from(FINALITY_QUORUM_NUMERATOR).unwrap_or(2);
        let den = usize::try_from(FINALITY_QUORUM_DENOMINATOR).unwrap_or(3);
        self.validators.len().saturating_mul(num).div_ceil(den)
    }

    /// Convert into [`HandoffMember`] entries in snapshot order.
    #[must_use]
    pub fn to_handoff_members(&self) -> Vec<HandoffMember> {
        self.validators
            .iter()
            .map(|entry| HandoffMember {
                address: entry.address.as_bytes().to_vec(),
                bls_public_key: entry.bls_public_key.clone(),
                pop_signature: entry.pop_signature.clone(),
                pq_public_key: entry.pq_public_key.clone(),
                stake: entry.stake,
            })
            .collect()
    }
}

/// BLS finality certificate wire shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityCert {
    pub epoch: u64,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    #[serde(default)]
    pub chain_id: u64,
    pub agg_sig_bls: Vec<u8>,
    pub bitmap: Vec<u8>,
    pub set_hash: String,
    #[serde(default)]
    pub seat_table_version: u64,
}

/// One validator's post-quantum checkpoint signature entry inside a [`QcBlob`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignatureEntry {
    pub validator_index: u32,
    pub validator_address: String,
    pub pq_signature: Vec<u8>,
}

/// Post-quantum quorum certificate blob (QC V2) attesting a finalized checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QcBlob {
    pub epoch: u64,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    pub pq_signatures: Vec<PqSignatureEntry>,
    pub merkle_root: String,
    pub created_epoch: u64,
}

/// SHA3-256 internal node combine for [`QcBlob`] Merkle trees (`BDLM_QC_NODE_V2`).
#[must_use]
pub fn qc_combine_sha3(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_QC_NODE_V2");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// SHA3-256 odd-tail promotion for [`QcBlob`] Merkle trees (`BDLM_MERKLE_ODD_PROMOTE_V1`).
#[must_use]
pub fn qc_promote_sha3(node: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_MERKLE_ODD_PROMOTE_V1");
    hasher.update(node);
    hasher.finalize().into()
}

/// Domain-separated Merkle leaf digest for one [`PqSignatureEntry`] (`BDLM_QC_LEAF_V2`).
#[must_use]
pub fn qc_leaf_hash(entry: &PqSignatureEntry) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_QC_LEAF_V2");
    hasher.update(entry.validator_index.to_le_bytes());
    update_with_len(&mut hasher, entry.validator_address.as_bytes());
    update_with_len(&mut hasher, &entry.pq_signature);
    hasher.finalize().into()
}

/// The message a validator signs with ML-DSA-65 under `BDLM/QC/V2` for a
/// checkpoint attestation (`BDLM_PQ_QC_V2`).
#[must_use]
pub fn pq_signing_message(
    epoch: u64,
    checkpoint_height: u64,
    checkpoint_hash: &str,
    validator_index: u32,
) -> Vec<u8> {
    let scheme = ML_DSA_65_SCHEME_WIRE_ID.to_be_bytes();
    let mut msg = Vec::new();
    for field in [
        b"BDLM_PQ_QC_V2".as_slice(),
        scheme.as_slice(),
        &epoch.to_le_bytes(),
        &checkpoint_height.to_le_bytes(),
        checkpoint_hash.as_bytes(),
        &validator_index.to_le_bytes(),
    ] {
        msg.extend_from_slice(&(field.len() as u64).to_le_bytes());
        msg.extend_from_slice(field);
    }
    msg
}

impl QcBlob {
    #[must_use]
    pub fn new(
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        pq_signatures: Vec<PqSignatureEntry>,
    ) -> Self {
        let merkle_root = Self::compute_merkle_root(&pq_signatures);
        Self {
            epoch,
            checkpoint_height,
            checkpoint_hash,
            pq_signatures,
            merkle_root,
            created_epoch: epoch,
        }
    }

    /// Compute the hex-encoded SHA3-256 Merkle root over `signatures`, promoting
    /// any unpaired odd tail under `BDLM_MERKLE_ODD_PROMOTE_V1`.
    #[must_use]
    pub fn compute_merkle_root(signatures: &[PqSignatureEntry]) -> String {
        if signatures.is_empty() {
            return "0".repeat(64);
        }
        let mut layer: Vec<[u8; 32]> = signatures.iter().map(qc_leaf_hash).collect();
        while layer.len() > 1 {
            let mut next = Vec::with_capacity(layer.len().div_ceil(2));
            for pair in layer.chunks(2) {
                match pair {
                    [left, right] => next.push(qc_combine_sha3(left, right)),
                    [only] => next.push(qc_promote_sha3(only)),
                    _ => {}
                }
            }
            layer = next;
        }
        hex::encode(layer.first().copied().unwrap_or([0u8; 32]))
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        1 + 8
            + 8
            + 2
            + self.checkpoint_hash.len()
            + 2
            + self.merkle_root.len()
            + 8
            + 4
            + self
                .pq_signatures
                .iter()
                .map(|entry| 4 + 2 + entry.validator_address.len() + 4 + entry.pq_signature.len())
                .sum::<usize>()
    }

    /// Canonical QC V2 binary encoding.
    ///
    /// # Errors
    ///
    /// Fails when a string exceeds [`QC_WIRE_MAX_STRING`] or a signature exceeds
    /// [`QC_WIRE_MAX_SIGNATURE`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        fn put_str(out: &mut Vec<u8>, text: &str, what: &str) -> Result<(), String> {
            let len = u16::try_from(text.len())
                .ok()
                .filter(|len| usize::from(*len) <= QC_WIRE_MAX_STRING)
                .ok_or_else(|| {
                    format!("QcBlob {what} is longer than {QC_WIRE_MAX_STRING} bytes")
                })?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(text.as_bytes());
            Ok(())
        }
        let count = u32::try_from(self.pq_signatures.len())
            .map_err(|_| "QcBlob has too many entries".to_string())?;
        let mut out = Vec::with_capacity(self.encoded_len());
        out.push(QC_WIRE_VERSION);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.checkpoint_height.to_be_bytes());
        put_str(&mut out, &self.checkpoint_hash, "checkpoint hash")?;
        put_str(&mut out, &self.merkle_root, "merkle root")?;
        out.extend_from_slice(&self.created_epoch.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        for entry in &self.pq_signatures {
            let sig_len = u32::try_from(entry.pq_signature.len())
                .ok()
                .filter(|len| usize::try_from(*len).unwrap_or(usize::MAX) <= QC_WIRE_MAX_SIGNATURE)
                .ok_or_else(|| "QcBlob signature is longer than the largest scheme".to_string())?;
            out.extend_from_slice(&entry.validator_index.to_be_bytes());
            put_str(&mut out, &entry.validator_address, "validator address")?;
            out.extend_from_slice(&sig_len.to_be_bytes());
            out.extend_from_slice(&entry.pq_signature);
        }
        Ok(out)
    }

    /// Decode [`Self::to_bytes`], bounding allocations by `max_entries` and
    /// remaining wire bytes before reading entries.
    ///
    /// # Errors
    ///
    /// Returns a reason for the first broken wire invariant.
    pub fn from_bytes(bytes: &[u8], max_entries: usize) -> Result<Self, String> {
        struct Reader<'a>(&'a [u8]);
        impl<'a> Reader<'a> {
            fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
                if self.0.len() < n {
                    return Err("QcBlob is truncated".into());
                }
                let (head, rest) = self.0.split_at(n);
                self.0 = rest;
                Ok(head)
            }
            fn u64(&mut self) -> Result<u64, String> {
                let raw: [u8; 8] = self
                    .take(8)?
                    .try_into()
                    .map_err(|_| "QcBlob is truncated")?;
                Ok(u64::from_be_bytes(raw))
            }
            fn u32(&mut self) -> Result<u32, String> {
                let raw: [u8; 4] = self
                    .take(4)?
                    .try_into()
                    .map_err(|_| "QcBlob is truncated")?;
                Ok(u32::from_be_bytes(raw))
            }
            fn string(&mut self, what: &str) -> Result<String, String> {
                let raw: [u8; 2] = self
                    .take(2)?
                    .try_into()
                    .map_err(|_| "QcBlob is truncated")?;
                let len = usize::from(u16::from_be_bytes(raw));
                if len > QC_WIRE_MAX_STRING {
                    return Err(format!(
                        "QcBlob {what} is longer than {QC_WIRE_MAX_STRING} bytes"
                    ));
                }
                String::from_utf8(self.take(len)?.to_vec())
                    .map_err(|_| format!("QcBlob {what} is not UTF-8"))
            }
        }
        let mut reader = Reader(bytes);
        let version = reader.take(1)?.first().copied().unwrap_or(0);
        if version != QC_WIRE_VERSION {
            return Err(format!(
                "QcBlob wire version {version} is not {QC_WIRE_VERSION}"
            ));
        }
        let epoch = reader.u64()?;
        let checkpoint_height = reader.u64()?;
        let checkpoint_hash = reader.string("checkpoint hash")?;
        let merkle_root = reader.string("merkle root")?;
        let created_epoch = reader.u64()?;
        let count = usize::try_from(reader.u32()?).unwrap_or(usize::MAX);
        if count > max_entries || count > reader.0.len() / 10 {
            return Err(format!(
                "QcBlob claims {count} entries for {max_entries} validators and {} bytes",
                reader.0.len()
            ));
        }
        let mut pq_signatures = Vec::with_capacity(count);
        for _ in 0..count {
            let validator_index = reader.u32()?;
            let validator_address = reader.string("validator address")?;
            let sig_len = usize::try_from(reader.u32()?).unwrap_or(usize::MAX);
            if sig_len > QC_WIRE_MAX_SIGNATURE {
                return Err("QcBlob signature is longer than the largest scheme".into());
            }
            pq_signatures.push(PqSignatureEntry {
                validator_index,
                validator_address,
                pq_signature: reader.take(sig_len)?.to_vec(),
            });
        }
        if !reader.0.is_empty() {
            return Err("QcBlob has trailing bytes".into());
        }
        Ok(Self {
            epoch,
            checkpoint_height,
            checkpoint_hash,
            pq_signatures,
            merkle_root,
            created_epoch,
        })
    }

    #[must_use]
    pub fn is_expired(&self, current_epoch: u64) -> bool {
        current_epoch > self.created_epoch.saturating_add(QC_BLOB_TTL_EPOCHS)
    }

    /// Validate wire length against the `validators` bound.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded length exceeds [`qc_blob_max_bytes`].
    pub fn validate_size(&self, validators: usize) -> Result<(), String> {
        let encoded = self.encoded_len();
        let max = qc_blob_max_bytes(validators);
        if encoded > max {
            return Err(format!(
                "QcBlob too large: {encoded} bytes (max: {max} for {validators} validators)"
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn verify_merkle_root(&self) -> bool {
        Self::compute_merkle_root(&self.pq_signatures) == self.merkle_root
    }

    /// Verify every signature entry, uniqueness, Merkle root, optional TTL, and
    /// optional required signer subset against `snapshot`, delegating signature
    /// verification over [`pq_signing_message`] to `verify_sig(pq_public_key, msg, sig)`.
    ///
    /// Returns the deduplicated set of verified validator indices.
    ///
    /// # Errors
    ///
    /// Fails closed on any structural, Merkle, duplicate, missing-signer, or
    /// cryptographic mismatch.
    pub fn verify_against_snapshot_with<F>(
        &self,
        snapshot: &ValidatorSetSnapshot,
        required_signers: Option<&[usize]>,
        current_epoch: Option<u64>,
        mut verify_sig: F,
    ) -> Result<BTreeSet<usize>, String>
    where
        F: FnMut(&[u8], &[u8], &[u8]) -> Result<(), String>,
    {
        if self.epoch != snapshot.epoch {
            return Err(format!(
                "QcBlob epoch mismatch: expected {}, got {}",
                snapshot.epoch, self.epoch
            ));
        }
        if self.checkpoint_height == 0 {
            return Err("QcBlob checkpoint height must be > 0".into());
        }
        if self.checkpoint_hash.is_empty() {
            return Err("QcBlob checkpoint hash is empty".into());
        }
        if let Some(epoch) = current_epoch {
            if self.created_epoch > self.epoch {
                return Err(format!(
                    "QcBlob created epoch {} is above its epoch {}",
                    self.created_epoch, self.epoch
                ));
            }
            if self.is_expired(epoch) {
                return Err(format!(
                    "QcBlob expired at epoch {} (created at {})",
                    epoch, self.created_epoch
                ));
            }
        }
        if self.pq_signatures.len() > snapshot.validators.len() {
            return Err(format!(
                "QcBlob carries {} signature entries for a validator set of {}                  (duplicates are rejected, so the extra entries cannot verify)",
                self.pq_signatures.len(),
                snapshot.validators.len()
            ));
        }
        self.validate_size(snapshot.validators.len())?;
        if !self.verify_merkle_root() {
            return Err("QcBlob merkle root mismatch".into());
        }

        let mut verified_indices = BTreeSet::new();
        for entry in &self.pq_signatures {
            let idx = usize::try_from(entry.validator_index).map_err(|_| {
                format!(
                    "QcBlob references unknown validator index {}",
                    entry.validator_index
                )
            })?;
            let validator = snapshot.validators.get(idx).ok_or_else(|| {
                format!(
                    "QcBlob references unknown validator index {}",
                    entry.validator_index
                )
            })?;
            if validator.address.to_string() != entry.validator_address {
                return Err(format!(
                    "QcBlob validator address mismatch at index {}: expected {}, got {}",
                    entry.validator_index, validator.address, entry.validator_address
                ));
            }
            if validator.pq_public_key.is_empty() {
                return Err(format!(
                    "Validator {} has no Dilithium public key",
                    validator.address
                ));
            }
            if !verified_indices.insert(idx) {
                return Err(format!(
                    "Duplicate PQ signature for validator index {}",
                    entry.validator_index
                ));
            }
            let message = pq_signing_message(
                self.epoch,
                self.checkpoint_height,
                &self.checkpoint_hash,
                entry.validator_index,
            );
            verify_sig(&validator.pq_public_key, &message, &entry.pq_signature).map_err(|e| {
                format!(
                    "Invalid Dilithium signature for validator {}: {}",
                    validator.address, e
                )
            })?;
        }

        if let Some(required) = required_signers {
            for signer_idx in required {
                if !verified_indices.contains(signer_idx) {
                    return Err(format!(
                        "QcBlob missing PQ attestation for validator index {signer_idx}"
                    ));
                }
            }
        }

        Ok(verified_indices)
    }
}

/// The single trust anchor a light client is bootstrapped from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedCheckpoint {
    /// Block height of the anchor.
    pub height: u64,
    /// Canonical 64-hex block hash at `height`.
    pub block_hash: String,
    /// Canonical 64-hex hash of the validator set that finalized `height`.
    pub set_hash: String,
}

impl TrustedCheckpoint {
    /// Validate that both digests are canonical 64-hex lowercase strings.
    ///
    /// # Errors
    ///
    /// Returns [`CheckpointVerifyError::MalformedHash`] when either hash is malformed.
    pub fn validate(&self) -> Result<(), CheckpointVerifyError> {
        if !is_canonical_hash(&self.block_hash) {
            return Err(CheckpointVerifyError::MalformedHash(format!(
                "block hash {} is not a canonical 64-hex digest",
                self.block_hash
            )));
        }
        if !is_canonical_hash(&self.set_hash) {
            return Err(CheckpointVerifyError::MalformedHash(format!(
                "set hash {} is not a canonical 64-hex digest",
                self.set_hash
            )));
        }
        Ok(())
    }
}

/// Minimal header commitment fields verified against a checkpoint certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointSummary {
    /// Block height of the candidate checkpoint.
    pub height: u64,
    /// Canonical 64-hex block hash at `height`.
    pub block_hash: String,
    /// Canonical 64-hex state root recorded in the header at `height`.
    pub state_root: String,
}

/// A checkpoint verified against the trusted validator set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCheckpoint {
    /// Block height of the verified checkpoint.
    pub height: u64,
    /// Canonical 64-hex block hash at `height`.
    pub block_hash: String,
    /// Canonical 64-hex hash of the validator set the certificate verified against.
    pub set_hash: String,
    /// Epoch the finality certificate belonged to.
    pub epoch: u64,
    /// State root recorded in the finalized header.
    pub state_root: String,
}

impl VerifiedCheckpoint {
    /// Decode [`Self::state_root`] when it is a canonical 32-byte hex digest.
    #[must_use]
    pub fn external_root(&self) -> Option<[u8; 32]> {
        if !is_canonical_hash(&self.state_root) {
            return None;
        }
        let bytes = hex::decode(&self.state_root).ok()?;
        <[u8; 32]>::try_from(bytes.as_slice()).ok()
    }
}

/// Shared verification errors for post-quantum checkpoint and handoff transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointVerifyError {
    MalformedHash(String),
    InvalidHeader(String),
    CertificateBinding(String),
    TrustBinding(String),
    VerificationFailed(String),
    NotForward { trusted: u64, candidate: u64 },
    SetChanged { trusted: String, candidate: String },
}

impl fmt::Display for CheckpointVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedHash(h) => write!(f, "malformed hash: {h}"),
            Self::InvalidHeader(r) => write!(f, "invalid header: {r}"),
            Self::CertificateBinding(r) => write!(f, "certificate does not bind to the header: {r}"),
            Self::TrustBinding(r) => write!(f, "certificate does not bind to the trusted set: {r}"),
            Self::VerificationFailed(r) => write!(f, "finality verification failed: {r}"),
            Self::NotForward { trusted, candidate } => write!(
                f,
                "checkpoint must move strictly forward: trusted {trusted}, candidate {candidate}"
            ),
            Self::SetChanged { trusted, candidate } => write!(
                f,
                "validator set changed under the light client: trusted {trusted}, candidate {candidate}"
            ),
        }
    }
}

impl std::error::Error for CheckpointVerifyError {}

/// Verify a post-quantum [`QcBlob`] checkpoint against `trusted`, `header`, and
/// `snapshot` using the exact binding order and stake/count quorum of
/// `LightClient::verify_pq_checkpoint`.
///
/// # Errors
///
/// Fails closed with [`CheckpointVerifyError`] on any malformed digest,
/// backward height, mismatched binding, forged snapshot metadata, invalid
/// signature, or insufficient stake/count quorum.
pub fn verify_pq_checkpoint_with<F>(
    trusted: &TrustedCheckpoint,
    header: &CheckpointSummary,
    blob: &QcBlob,
    snapshot: &ValidatorSetSnapshot,
    verify_sig: F,
) -> Result<VerifiedCheckpoint, CheckpointVerifyError>
where
    F: FnMut(&[u8], &[u8], &[u8]) -> Result<(), String>,
{
    trusted.validate()?;
    snapshot
        .validate_metadata()
        .map_err(CheckpointVerifyError::TrustBinding)?;
    if !is_canonical_hash(&header.block_hash) {
        return Err(CheckpointVerifyError::InvalidHeader(format!(
            "header hash {} is not a canonical 64-hex digest",
            header.block_hash
        )));
    }
    if !is_canonical_hash(&header.state_root) {
        return Err(CheckpointVerifyError::InvalidHeader(format!(
            "state root {} is not a canonical 64-hex digest",
            header.state_root
        )));
    }
    if header.height <= trusted.height {
        return Err(CheckpointVerifyError::NotForward {
            trusted: trusted.height,
            candidate: header.height,
        });
    }
    if header.height != blob.checkpoint_height {
        return Err(CheckpointVerifyError::CertificateBinding(format!(
            "header height {} != blob height {}",
            header.height, blob.checkpoint_height
        )));
    }
    if header.block_hash != blob.checkpoint_hash {
        return Err(CheckpointVerifyError::CertificateBinding(format!(
            "header hash {} != blob hash {}",
            header.block_hash, blob.checkpoint_hash
        )));
    }
    if snapshot.set_hash != trusted.set_hash {
        return Err(CheckpointVerifyError::TrustBinding(format!(
            "snapshot set hash {} != trusted set hash {}",
            snapshot.set_hash, trusted.set_hash
        )));
    }
    if blob.epoch != snapshot.epoch {
        return Err(CheckpointVerifyError::CertificateBinding(format!(
            "blob epoch {} != snapshot epoch {}",
            blob.epoch, snapshot.epoch
        )));
    }

    let verified = blob
        .verify_against_snapshot_with(snapshot, None, None, verify_sig)
        .map_err(CheckpointVerifyError::VerificationFailed)?;

    let voted_stake: u128 = verified
        .iter()
        .filter_map(|idx| snapshot.validators.get(*idx))
        .map(|v| u128::from(v.stake))
        .sum();
    if voted_stake < snapshot.quorum_stake() {
        return Err(CheckpointVerifyError::VerificationFailed(format!(
            "PQ quorum stake {} < required {}",
            voted_stake,
            snapshot.quorum_stake()
        )));
    }
    if verified.len() < snapshot.quorum_count() {
        return Err(CheckpointVerifyError::VerificationFailed(format!(
            "PQ quorum signers {} < required {}",
            verified.len(),
            snapshot.quorum_count()
        )));
    }

    Ok(VerifiedCheckpoint {
        height: header.height,
        block_hash: header.block_hash.clone(),
        set_hash: snapshot.set_hash.clone(),
        epoch: blob.epoch,
        state_root: header.state_root.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_hash_prevents_key_refolding_and_forged_totals() {
        let addr = Address::from([0x11; 32]);
        let honest = ValidatorSetSnapshot::new(
            3,
            vec![ValidatorEntry {
                address: addr,
                stake: 100,
                bls_public_key: vec![2; 96],
                pop_signature: vec![3; 48],
                pq_public_key: vec![4; 32],
            }],
        );
        assert!(honest.validate_metadata().is_ok());

        let mut refolded_bls = vec![2; 96];
        refolded_bls.extend_from_slice(&[3; 48]);
        let refolded = ValidatorSetSnapshot::new(
            3,
            vec![ValidatorEntry {
                address: addr,
                stake: 100,
                bls_public_key: refolded_bls,
                pop_signature: Vec::new(),
                pq_public_key: vec![4; 32],
            }],
        );
        assert_ne!(honest.set_hash, refolded.set_hash);

        let mut forged = honest;
        forged.total_stake = 10;
        assert!(forged.validate_metadata().is_err());
    }

    #[test]
    fn qc_merkle_promotes_odd_tail_without_duplication_collision() {
        let entries: Vec<PqSignatureEntry> = (0u32..3)
            .map(|i| PqSignatureEntry {
                validator_index: i,
                validator_address: Address::from([u8::try_from(i + 1).unwrap_or(1); 32]).to_hex(),
                pq_signature: vec![u8::try_from(i + 10).unwrap_or(10); 16],
            })
            .collect();
        let mut duplicated = entries.clone();
        if let Some(last) = entries.last().cloned() {
            duplicated.push(last);
        }
        assert_ne!(
            QcBlob::compute_merkle_root(&entries),
            QcBlob::compute_merkle_root(&duplicated)
        );
    }

    #[test]
    fn qc_wire_round_trips_and_rejects_trailing_bytes() {
        let addr = Address::from([0x22; 32]).to_hex();
        let blob = QcBlob::new(
            4,
            200,
            "ab".repeat(32),
            vec![PqSignatureEntry {
                validator_index: 0,
                validator_address: addr,
                pq_signature: vec![0x5a; 32],
            }],
        );
        let raw = blob.to_bytes().unwrap();
        let decoded = QcBlob::from_bytes(&raw, 4).unwrap();
        assert_eq!(decoded, blob);

        let mut trailing = raw;
        trailing.push(0);
        assert!(QcBlob::from_bytes(&trailing, 4).is_err());
    }
}
