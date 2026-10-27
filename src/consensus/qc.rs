use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::chain::finality::ValidatorSetSnapshot;
use crate::consensus::merkle_tree;
use crate::core::chain_config::QC_BLOB_TTL_EPOCHS;
use crate::crypto::primitives::PqKeyPair;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QcBlob {
    pub epoch: u64,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    pub pq_signatures: Vec<PqSignatureEntry>,
    pub merkle_root: String,
    pub created_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqSignatureEntry {
    pub validator_index: u32,
    pub validator_address: String,
    pub pq_signature: Vec<u8>,
}

/// The disputed attestation an `InvalidDilithiumV1` proof carries (P01-F26).
///
/// Named rather than passed as three loose constructor fields, so
/// `QcFaultProof::new_invalid_dilithium` stays under the argument limit
/// without a lint waiver.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InvalidDilithiumEvidence {
    pub pq_signature: Vec<u8>,
    pub merkle_proof: Vec<Vec<u8>>,
    pub leaf_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QcFaultProof {
    pub version: u8,
    pub epoch: u64,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    pub validator_index: u32,
    pub validator_address: String,
    pub kind: QcProofKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QcProofKind {
    InvalidDilithiumV1 {
        pq_signature: Vec<u8>,
        merkle_proof: Vec<Vec<u8>>,
        leaf_index: u32,
    },
    ZkInvalidAttestationV1 {
        proof_bytes: Vec<u8>,
        public_inputs: ZkQcPublicInputs,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkQcPublicInputs {
    pub merkle_root: String,
    pub pq_public_key_hash: String,
    pub attestation_commitment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QcProofAction {
    InvalidateFinality,
    SlashValidator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QcProofVerdict {
    pub action: QcProofAction,
    pub invalidate_from_height: Option<u64>,
    pub slash_validator: bool,
}

impl QcBlob {
    pub fn new(
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        pq_signatures: Vec<PqSignatureEntry>,
    ) -> Self {
        let merkle_root = Self::compute_merkle_root(&pq_signatures);
        QcBlob {
            epoch,
            checkpoint_height,
            checkpoint_hash,
            pq_signatures,
            merkle_root,
            created_epoch: epoch,
        }
    }

    /// The Merkle leaf for one signature entry.
    ///
    /// Both trailing fields are length-prefixed. `validator_address` is a
    /// `String` and `pq_signature` a `Vec<u8>`, appended with nothing
    /// between them, so a character could be moved from the end of the address
    /// into the front of the signature and the leaf would not change. Measured:
    /// a 66-character address and a 4595-byte signature produce the same digest
    /// as a 65-character address and a 4596-byte signature.
    ///
    /// That leaf is what `verify_inclusion` rebuilds from a fault proof, and a
    /// verdict from it reaches `slash_validator` at the malicious-behaviour
    /// ratio, so a second `(address, signature)` pair hashing to an accepted
    /// leaf is a second story a fault proof can tell about the same slot.
    ///
    /// The domain tag (P01-F27) puts leaves in their own preimage set: the
    /// inner-node combine tags its inputs differently, so no leaf can stand
    /// in for a node or the other way round.
    ///
    /// See `crate::crypto::key_set_preimage` for the same failure in the
    /// validator key set.
    fn leaf_hash(entry: &PqSignatureEntry) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_QC_LEAF_V2");
        hasher.update(entry.validator_index.to_le_bytes());
        let address = entry.validator_address.as_bytes();
        hasher.update((address.len() as u64).to_le_bytes());
        hasher.update(address);
        hasher.update((entry.pq_signature.len() as u64).to_le_bytes());
        hasher.update(&entry.pq_signature);
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    }

    fn leaves(signatures: &[PqSignatureEntry]) -> Vec<[u8; 32]> {
        signatures.iter().map(Self::leaf_hash).collect()
    }

    pub fn compute_merkle_root(signatures: &[PqSignatureEntry]) -> String {
        if signatures.is_empty() {
            return String::from(
                "0000000000000000000000000000000000000000000000000000000000000000",
            );
        }

        let layers = merkle_tree::merkle_layers(
            &Self::leaves(signatures),
            merkle_tree::combine_sha3,
            merkle_tree::promote_sha3,
        );
        hex::encode(
            layers
                .last()
                .and_then(|layer| layer.first())
                .copied()
                .unwrap_or([0u8; 32]),
        )
    }

    /// # Errors
    ///
    /// Returns an error when the blob carries no PQ signatures or the leaf
    /// index is out of range.
    pub fn merkle_proof(&self, leaf_index: usize) -> Result<Vec<Vec<u8>>, String> {
        if self.pq_signatures.is_empty() {
            return Err("QcBlob has no PQ signatures".into());
        }
        if leaf_index >= self.pq_signatures.len() {
            return Err(format!(
                "Leaf index {} out of range for {} signatures",
                leaf_index,
                self.pq_signatures.len()
            ));
        }

        let proof = merkle_tree::merkle_proof(
            &Self::leaves(&self.pq_signatures),
            leaf_index,
            merkle_tree::combine_sha3,
            merkle_tree::promote_sha3,
        )
        .ok_or_else(|| "leaf index was bounds-checked above".to_string())?;
        Ok(proof.into_iter().map(|digest| digest.to_vec()).collect())
    }

    /// `created_epoch` arrives with the deserialized blob, so the sum must
    /// not be able to overflow on a hostile value.
    /// Wire length of [`Self::to_bytes`].
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

    /// The canonical binary encoding (QC V2): version, epoch, height, the
    /// checkpoint hash and merkle root as length prefixed strings, the created
    /// epoch, the entry count, then each entry. Integers are big endian. This
    /// replaces the JSON encoding, which inflated random bytes 3.57 times.
    ///
    /// # Errors
    ///
    /// Fails when a string field exceeds [`QC_WIRE_MAX_STRING`] or a signature
    /// exceeds [`QC_WIRE_MAX_SIGNATURE`]: such a blob has no valid encoding.
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
            if entry.pq_signature.len() > QC_WIRE_MAX_SIGNATURE {
                return Err("QcBlob signature is longer than the largest scheme".into());
            }
            out.extend_from_slice(&entry.validator_index.to_be_bytes());
            put_str(&mut out, &entry.validator_address, "validator address")?;
            // Checked above: at most 4,627, so the cast cannot truncate.
            out.extend_from_slice(&(entry.pq_signature.len() as u32).to_be_bytes());
            out.extend_from_slice(&entry.pq_signature);
        }
        Ok(out)
    }

    /// Decodes [`Self::to_bytes`]. Nothing scales with an unchecked length:
    /// the entry count is bounded by the bytes that remain and by
    /// `max_entries` (the validator count of the snapshot) before any entry is
    /// allocated, and trailing bytes are refused.
    ///
    /// # Errors
    ///
    /// A message for the first rule the bytes break.
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
        let version = reader.take(1)?[0];
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
        let count = reader.u32()? as usize;
        // An entry is at least 4 + 2 + 4 bytes, so the remaining bytes bound
        // the count whatever the header claims.
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
            let sig_len = reader.u32()? as usize;
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

    /// The blob split into transport chunks of at most [`QC_CHUNK_BYTES`].
    ///
    /// # Errors
    ///
    /// The encoding errors of [`Self::to_bytes`].
    pub fn to_chunks(&self) -> Result<Vec<Vec<u8>>, String> {
        Ok(self
            .to_bytes()?
            .chunks(QC_CHUNK_BYTES)
            .map(<[u8]>::to_vec)
            .collect())
    }

    pub fn is_expired(&self, current_epoch: u64) -> bool {
        current_epoch > self.created_epoch.saturating_add(QC_BLOB_TTL_EPOCHS)
    }

    /// The size rule: the blob's wire length is at most `header + n * entry`
    /// for the `n` validators of its snapshot. The bound grows with
    /// the validator set instead of stopping the set at a fixed byte count
    /// (the old 1 MiB cap refused a set of about 310 members).
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

    pub fn verify_merkle_root(&self) -> bool {
        let computed = Self::compute_merkle_root(&self.pq_signatures);
        computed == self.merkle_root
    }

    /// Verify under the scheme statuses of a fresh genesis. A chain calls
    /// [`Self::verify_against_snapshot_in`] with its state registry.
    pub fn verify_against_snapshot(
        &self,
        snapshot: &ValidatorSetSnapshot,
        required_signers: Option<&[usize]>,
        current_epoch: Option<u64>,
    ) -> Result<HashSet<usize>, String> {
        self.verify_against_snapshot_in(
            &crate::crypto::scheme::SchemeStatusRegistry::genesis(),
            snapshot,
            required_signers,
            current_epoch,
        )
    }

    pub fn verify_against_snapshot_in(
        &self,
        registry: &crate::crypto::scheme::SchemeStatusRegistry,
        snapshot: &ValidatorSetSnapshot,
        required_signers: Option<&[usize]>,
        current_epoch: Option<u64>,
    ) -> Result<HashSet<usize>, String> {
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
            // A blob cannot have been created after the epoch it attests, so a
            // self-declared later `created_epoch` is not allowed to stretch
            // the TTL window.
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
        // Bound the entry count against the validator set *before* paying for
        // anything that scales with it.
        //
        // `validate_size` caps the blob in bytes, not in entries, and the
        // per-entry overhead is small: with a 1-byte signature an entry costs
        // about 50 bytes, so roughly 20 000 of them fit under
        // the byte bound. Every one of those is hashed by
        // `verify_merkle_root` before the loop below reaches its first
        // signature and rejects the blob. Measured on a four-validator
        // snapshot (debug build):
        //
        //     entries    merkle      total
        //         100     5.9 ms     6.3 ms
        //       1 000    64.7 ms    63.6 ms
        //      10 000     582 ms     604 ms
        //
        // A legitimate blob for that snapshot holds at most four entries. The
        // duplicate check further down already makes more than one entry per
        // validator useless, so anything above the validator count is provably
        // unusable and can be refused in O(1).
        //
        // `check_blob_rate_limit` throttles how often a peer may send these,
        // but it cannot make an individual message cheap; this check does.
        if self.pq_signatures.len() > snapshot.validators.len() {
            return Err(format!(
                "QcBlob carries {} signature entries for a validator set of {} \
                 (duplicates are rejected, so the extra entries cannot verify)",
                self.pq_signatures.len(),
                snapshot.validators.len()
            ));
        }
        self.validate_size(snapshot.validators.len())?;
        if !self.verify_merkle_root() {
            return Err("QcBlob merkle root mismatch".into());
        }

        let mut verified_indices = HashSet::new();
        for entry in &self.pq_signatures {
            let idx = entry.validator_index as usize;
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
            PqKeyPair::verify_in(
                registry,
                &validator.pq_public_key,
                crate::crypto::ctx::QC_V2,
                &message,
                &entry.pq_signature,
            )
            .map_err(|e| {
                format!(
                    "Invalid Dilithium signature for validator {}: {}",
                    validator.address, e
                )
            })?;
        }

        if let Some(required_signers) = required_signers {
            for signer_idx in required_signers {
                if !verified_indices.contains(signer_idx) {
                    return Err(format!(
                        "QcBlob missing PQ attestation for validator index {signer_idx}"
                    ));
                }
            }
        }

        // (security audit §2) return the unique-verified
        // Signer set so callers can enforce a quorum against the
        // Post-deduplication count. The previous design only
        // Returned ``; callers that wanted to count unique
        // Signers (e.g. `import_qc_blob`'s BLS-quorum check) had to
        // Re-walk the entries themselves, which was both wasteful
        // And easy to get wrong (counting duplicates). Returning
        // The set makes the contract explicit and gives every
        // Caller access to the canonical unique count.
        Ok(verified_indices)
    }

    pub fn detect_fault_proofs(&self, snapshot: &ValidatorSetSnapshot) -> Vec<QcFaultProof> {
        self.detect_fault_proofs_in(
            &crate::crypto::scheme::SchemeStatusRegistry::genesis(),
            snapshot,
        )
    }

    pub fn detect_fault_proofs_in(
        &self,
        registry: &crate::crypto::scheme::SchemeStatusRegistry,
        snapshot: &ValidatorSetSnapshot,
    ) -> Vec<QcFaultProof> {
        let mut proofs = Vec::new();

        for (leaf_index, entry) in self.pq_signatures.iter().enumerate() {
            let Some(validator) = snapshot.validators.get(entry.validator_index as usize) else {
                continue;
            };
            if validator.address.to_string() != entry.validator_address {
                continue;
            }
            if validator.pq_public_key.is_empty() {
                continue;
            }

            let message = pq_signing_message(
                self.epoch,
                self.checkpoint_height,
                &self.checkpoint_hash,
                entry.validator_index,
            );
            if PqKeyPair::verify_in(
                registry,
                &validator.pq_public_key,
                crate::crypto::ctx::QC_V2,
                &message,
                &entry.pq_signature,
            )
            .is_err()
            {
                if let Ok(merkle_proof) = self.merkle_proof(leaf_index) {
                    proofs.push(QcFaultProof::new_invalid_dilithium(
                        self.epoch,
                        self.checkpoint_height,
                        self.checkpoint_hash.clone(),
                        entry.validator_index,
                        entry.validator_address.clone(),
                        InvalidDilithiumEvidence {
                            pq_signature: entry.pq_signature.clone(),
                            merkle_proof,
                            leaf_index: leaf_index as u32,
                        },
                    ));
                }
            }
        }

        proofs
    }
}

/// A Merkle path for a `u32` leaf index has at most 32 siblings.
const MAX_MERKLE_PROOF_ELEMENTS: usize = 32;

impl QcFaultProof {
    /// Version 2 (P01-F27): proofs are produced and checked against the
    /// domain-tagged Merkle tree. A version-1 proof walked the untagged
    /// combine and no longer reproduces a stored root; `validate` refuses it
    /// by version instead of failing with a confusing root mismatch.
    pub const CURRENT_VERSION: u8 = 2;

    /// Build an `InvalidDilithiumV1` fault proof around a disputed
    /// attestation (P01-F26: the payload is one named value, not three
    /// loose arguments).
    fn new_invalid_dilithium(
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        validator_index: u32,
        validator_address: String,
        evidence: InvalidDilithiumEvidence,
    ) -> Self {
        QcFaultProof {
            version: Self::CURRENT_VERSION,
            epoch,
            checkpoint_height,
            checkpoint_hash,
            validator_index,
            validator_address,
            kind: QcProofKind::InvalidDilithiumV1 {
                pq_signature: evidence.pq_signature,
                merkle_proof: evidence.merkle_proof,
                leaf_index: evidence.leaf_index,
            },
        }
    }

    /// Test-only constructor for the stubbed ZK kind (P01-F21).
    #[cfg(test)]
    pub fn new_zk_invalid_attestation(
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        validator_index: u32,
        validator_address: String,
        proof_bytes: Vec<u8>,
        public_inputs: ZkQcPublicInputs,
    ) -> Self {
        QcFaultProof {
            version: Self::CURRENT_VERSION,
            epoch,
            checkpoint_height,
            checkpoint_hash,
            validator_index,
            validator_address,
            kind: QcProofKind::ZkInvalidAttestationV1 {
                proof_bytes,
                public_inputs,
            },
        }
    }

    /// Rebuild the committed Merkle root from the proof alone and compare.
    ///
    /// The walk is `merkle_tree::merkle_root_from_proof` (P01-F25): the
    /// hand-rolled copy that used to live here was the same algorithm
    /// restated, and the two drifted whenever one was fixed. The shared walk
    /// also carries the domain-tagged node combine (P01-F27), matching the
    /// tree the root was built with.
    pub fn verify_inclusion(&self, merkle_root: &str) -> Result<(), String> {
        let QcProofKind::InvalidDilithiumV1 {
            pq_signature,
            merkle_proof,
            leaf_index,
        } = &self.kind
        else {
            return Err("Merkle inclusion is not available for this QC proof kind".to_string());
        };
        if merkle_proof.len() > MAX_MERKLE_PROOF_ELEMENTS {
            return Err(format!(
                "Merkle proof has {} elements, at most {MAX_MERKLE_PROOF_ELEMENTS} are allowed",
                merkle_proof.len()
            ));
        }

        let leaf = QcBlob::leaf_hash(&PqSignatureEntry {
            validator_index: self.validator_index,
            validator_address: self.validator_address.clone(),
            pq_signature: pq_signature.clone(),
        });

        let mut siblings = Vec::with_capacity(merkle_proof.len());
        for element in merkle_proof {
            if element.len() != 32 {
                return Err(format!(
                    "Merkle proof element must be 32 bytes, got {}",
                    element.len()
                ));
            }
            let mut digest = [0u8; 32];
            digest.copy_from_slice(element);
            siblings.push(digest);
        }

        // BLG-0129 (P05-F22): an index with bits above its path is refused,
        // not silently narrowed - one proof must verify under exactly one
        // index.
        let computed = merkle_tree::merkle_root_from_proof(
            &leaf,
            (*leaf_index) as usize,
            &siblings,
            merkle_tree::combine_sha3,
            merkle_tree::promote_sha3,
        )
        .ok_or_else(|| "Merkle proof invalid: index has bits above the proof path".to_string())?;
        let computed_root = hex::encode(computed);
        if computed_root != merkle_root {
            return Err(format!(
                "Merkle proof invalid: computed {computed_root} != expected {merkle_root}"
            ));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != Self::CURRENT_VERSION {
            return Err(format!(
                "Unsupported QC fault proof version {}",
                self.version
            ));
        }
        if self.checkpoint_height == 0 {
            return Err("Empty checkpoint height".into());
        }
        if self.checkpoint_hash.is_empty() {
            return Err("Empty checkpoint hash".into());
        }
        match &self.kind {
            QcProofKind::InvalidDilithiumV1 {
                pq_signature,
                merkle_proof,
                leaf_index,
            } => {
                if pq_signature.is_empty() {
                    return Err("Empty Dilithium signature".into());
                }
                if merkle_proof.is_empty() && *leaf_index != 0 {
                    return Err("Empty merkle proof".into());
                }
                if merkle_proof.len() > MAX_MERKLE_PROOF_ELEMENTS {
                    return Err("Merkle proof is longer than any tree path".into());
                }
            }
            QcProofKind::ZkInvalidAttestationV1 {
                proof_bytes,
                public_inputs,
            } => {
                if proof_bytes.is_empty() {
                    return Err("Empty ZK QC proof".into());
                }
                if public_inputs.merkle_root.is_empty() {
                    return Err("Empty ZK QC merkle root input".into());
                }
                if public_inputs.pq_public_key_hash.is_empty() {
                    return Err("Empty ZK QC PQ public key hash input".into());
                }
                if public_inputs.attestation_commitment.is_empty() {
                    return Err("Empty ZK QC attestation commitment input".into());
                }
            }
        }
        Ok(())
    }

    pub fn verify_against_blob(
        &self,
        blob: &QcBlob,
        snapshot: &ValidatorSetSnapshot,
    ) -> Result<QcProofVerdict, String> {
        self.verify_against_blob_in(
            &crate::crypto::scheme::SchemeStatusRegistry::genesis(),
            blob,
            snapshot,
        )
    }

    pub fn verify_against_blob_in(
        &self,
        registry: &crate::crypto::scheme::SchemeStatusRegistry,
        blob: &QcBlob,
        snapshot: &ValidatorSetSnapshot,
    ) -> Result<QcProofVerdict, String> {
        self.validate()?;

        if self.epoch != blob.epoch {
            return Err("QC fault proof epoch mismatch".into());
        }
        if self.checkpoint_height != blob.checkpoint_height {
            return Err("QC fault proof checkpoint height mismatch".into());
        }
        if self.checkpoint_hash != blob.checkpoint_hash {
            return Err("QC fault proof checkpoint hash mismatch".into());
        }

        match &self.kind {
            QcProofKind::InvalidDilithiumV1 {
                pq_signature,
                leaf_index,
                ..
            } => {
                self.verify_inclusion(&blob.merkle_root)?;

                let entry = blob
                    .pq_signatures
                    .get(*leaf_index as usize)
                    .ok_or_else(|| format!("Leaf index {leaf_index} out of range"))?;
                if entry.validator_index != self.validator_index
                    || entry.validator_address != self.validator_address
                    || entry.pq_signature != *pq_signature
                {
                    return Err("Fault proof leaf does not match blob contents".into());
                }

                let validator = snapshot
                    .validators
                    .get(self.validator_index as usize)
                    .ok_or_else(|| format!("Unknown validator index {}", self.validator_index))?;
                if validator.address.to_string() != self.validator_address {
                    return Err("Fault proof validator address mismatch".into());
                }
                if validator.pq_public_key.is_empty() {
                    return Err("Validator has no Dilithium public key".into());
                }

                let message = pq_signing_message(
                    self.epoch,
                    self.checkpoint_height,
                    &self.checkpoint_hash,
                    self.validator_index,
                );
                if PqKeyPair::verify_in(
                    registry,
                    &validator.pq_public_key,
                    crate::crypto::ctx::QC_V2,
                    &message,
                    pq_signature,
                )
                .is_ok()
                {
                    return Err("Fault proof targets a valid Dilithium signature".into());
                }
                // P01-F22: a signature that does NOT verify is not evidence
                // against the named validator. It is equally consistent with a
                // forged entry that names a non-participant, so slashing on it
                // would make `bud_submitQcFaultProof` a free, permissionless
                // frame-up rail - garbage bytes cost nothing to produce, despite
                // the surface comment claiming a forgery would. The importer
                // already refuses blobs with invalid entries, so this shape was
                // unreachable; the verdict is refused explicitly instead of
                // waiting for some future path to activate the trap. A sound
                // evidence form (two attested checkpoints at one height, both
                // signatures valid) is the double-sign `SlashingEvidence` path.
                Err(
                    "A signature that fails to verify is not evidence against the named \
                     validator (equally consistent with a forged entry); no verdict is issued"
                        .into(),
                )
            }
            QcProofKind::ZkInvalidAttestationV1 { public_inputs, .. } => {
                if public_inputs.merkle_root != blob.merkle_root {
                    return Err("ZK QC public input merkle root mismatch".into());
                }
                // ZK QC fault proof verifier
                // Is not yet implemented. This is a deliberate fail-closed guard:
                // ZK domain finality attestations CANNOT be invalidated via fault
                // Proofs until a proper ZK verifier is integrated. That verifier
                // is a BudZero STARK proof of the fault; no
                // pairing-based SNARK (Groth16, KZG-based PLONK, anything over
                // BN254) sits on a Budlum verification path, and the
                // `no_pairing_snark_in_verification_path` gate holds the line.
                // This prevents forged ZK attestations
                // From being finalized without verification, at the cost of also
                // Preventing legitimate fault challenges.
                //
                // Tracking: Implement ZK verifier in consensus::zk_verifier module,
                // Then replace this stub with actual proof verification.
                // Security impact: ZK domain QC blobs are accepted (BLS quorum
                // Verified) but cannot be challenged. For mainnet, consider
                // Disabling ZK domain QC import until verifier is ready.
                Err(
                    "ZK QC fault proof verifier not implemented - ZK domain attestations \
                     cannot be challenged until ZK verifier integration. This is fail-closed: \
                     no invalid ZK attestation can be finalized via this path."
                        .into(),
                )
            }
        }
    }
}

/// Largest transport chunk of a QC blob. A blob of 1,000 validators is about
/// 3.4 MB; it travels as numbered chunks instead of one message.
pub const QC_CHUNK_BYTES: usize = 256 * 1024;

/// Reassembles a QC blob from numbered chunks, bounded by the snapshot's
/// validator count before the first chunk is stored.
#[derive(Debug)]
pub struct QcBlobAssembler {
    max_entries: usize,
    expected_chunks: usize,
    chunks: Vec<Option<Vec<u8>>>,
    received_bytes: usize,
}

impl QcBlobAssembler {
    /// A new assembler for a blob announced as `chunk_count` chunks, for a
    /// validator set of `max_entries`.
    ///
    /// # Errors
    ///
    /// Fails when the announced chunk count cannot hold a blob of that set, or
    /// is zero.
    pub fn new(max_entries: usize, chunk_count: usize) -> Result<Self, String> {
        let max_bytes = qc_blob_max_bytes(max_entries);
        let max_chunks = max_bytes.div_ceil(QC_CHUNK_BYTES);
        if chunk_count == 0 || chunk_count > max_chunks {
            return Err(format!(
                "QcBlob announced as {chunk_count} chunks, a set of {max_entries} allows 1 to {max_chunks}"
            ));
        }
        Ok(Self {
            max_entries,
            expected_chunks: chunk_count,
            chunks: vec![None; chunk_count],
            received_bytes: 0,
        })
    }

    /// Stores chunk `index`. A repeated index is refused: a peer cannot
    /// replace what it already sent.
    ///
    /// # Errors
    ///
    /// Out-of-range index, repeated index, or an oversize chunk.
    pub fn push(&mut self, index: usize, chunk: Vec<u8>) -> Result<(), String> {
        if chunk.len() > QC_CHUNK_BYTES {
            return Err("QcBlob chunk exceeds the chunk size".into());
        }
        let slot = self
            .chunks
            .get_mut(index)
            .ok_or_else(|| format!("QcBlob chunk index {index} is out of range"))?;
        if slot.is_some() {
            return Err(format!("QcBlob chunk {index} arrived twice"));
        }
        self.received_bytes += chunk.len();
        *slot = Some(chunk);
        Ok(())
    }

    /// Whether every chunk has arrived.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.chunks.iter().all(Option::is_some)
    }

    /// The decoded blob once every chunk is in.
    ///
    /// # Errors
    ///
    /// Fails when a chunk is missing, a non-final chunk is not full, or the
    /// bytes do not decode.
    pub fn finish(self) -> Result<QcBlob, String> {
        let mut bytes = Vec::with_capacity(self.received_bytes);
        for (i, chunk) in self.chunks.into_iter().enumerate() {
            let chunk = chunk.ok_or_else(|| format!("QcBlob chunk {i} is missing"))?;
            if i + 1 < self.expected_chunks && chunk.len() != QC_CHUNK_BYTES {
                return Err(format!("QcBlob chunk {i} is short but not the last"));
            }
            bytes.extend_from_slice(&chunk);
        }
        QcBlob::from_bytes(&bytes, self.max_entries)
    }
}

/// The message a validator signs for its PQ attestation (QC V2).
///
/// Every field is length prefixed, and the scheme id of the signing key is
/// part of the message (INV-02), so an attestation made under one scheme can
/// not be presented as another. The FIPS 204 context `BDLM/QC/V2` is applied
/// by the signing call.
pub fn pq_signing_message(
    epoch: u64,
    checkpoint_height: u64,
    checkpoint_hash: &str,
    validator_index: u32,
) -> Vec<u8> {
    let scheme = crate::crypto::scheme::SchemeId::ML_DSA_65.0.to_be_bytes();
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

/// Version byte of the QC blob wire encoding.
pub const QC_WIRE_VERSION: u8 = 2;
/// Longest string field (checkpoint hash, merkle root, address) on the wire.
pub const QC_WIRE_MAX_STRING: usize = 128;
/// Longest PQ signature an entry may carry: the largest registered lattice
/// scheme, ML-DSA-87 (4,627 bytes).
pub const QC_WIRE_MAX_SIGNATURE: usize = 4_627;
/// Bytes of an entry besides its signature at the string bound: index, address
/// length and bytes, signature length.
const QC_ENTRY_OVERHEAD: usize = 4 + 2 + QC_WIRE_MAX_STRING + 4;
/// Largest wire size of one entry: [`QC_ENTRY_OVERHEAD`] plus the longest signature.
pub const QC_ENTRY_MAX_BYTES: usize = QC_ENTRY_OVERHEAD + QC_WIRE_MAX_SIGNATURE;
/// Largest wire size of the blob header at the string bounds.
const QC_HEADER_MAX_BYTES: usize = 1 + 8 + 8 + (2 + QC_WIRE_MAX_STRING) * 2 + 8 + 4;

/// The wire size bound of a blob for `validators` members.
#[must_use]
pub const fn qc_blob_max_bytes(validators: usize) -> usize {
    QC_HEADER_MAX_BYTES + validators * QC_ENTRY_MAX_BYTES
}

/// Test-only attestation helper (P01-F21: production blobs come from the
/// validators' own PQ signing paths).
#[cfg(test)]
pub fn sign_attestation(
    pq_key: &PqKeyPair,
    epoch: u64,
    checkpoint_height: u64,
    checkpoint_hash: &str,
    validator_index: u32,
    validator_address: String,
) -> Result<PqSignatureEntry, String> {
    let message = pq_signing_message(epoch, checkpoint_height, checkpoint_hash, validator_index);
    let signature = pq_key
        .sign(crate::crypto::ctx::QC_V2, &message)
        .map_err(|e| format!("PQ sign failed: {e}"))?;
    Ok(PqSignatureEntry {
        validator_index,
        validator_address,
        pq_signature: signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::finality::ValidatorEntry;
    use crate::core::address::Address;

    fn make_snapshot_with_pq_keys(n: usize) -> (ValidatorSetSnapshot, Vec<PqKeyPair>) {
        let mut validators = Vec::new();
        let mut keys = Vec::new();

        for i in 0..n {
            let pq_key = PqKeyPair::generate();
            let address = Address::from([(i as u8) + 1; 32]);
            validators.push(ValidatorEntry {
                address,
                stake: 1_000,
                bls_public_key: Vec::new(),
                pop_signature: Vec::new(),
                pq_public_key: pq_key.public_key_bytes().to_vec(),
            });
            keys.push(pq_key);
        }

        (ValidatorSetSnapshot::new(1, validators), keys)
    }

    fn make_signed_entries(
        snapshot: &ValidatorSetSnapshot,
        keys: &[PqKeyPair],
        checkpoint_hash: &str,
    ) -> Vec<PqSignatureEntry> {
        snapshot
            .validators
            .iter()
            .enumerate()
            .map(|(idx, validator)| {
                sign_attestation(
                    &keys[idx],
                    snapshot.epoch,
                    100,
                    checkpoint_hash,
                    idx as u32,
                    validator.address.to_string(),
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn ttl_arithmetic_saturates_and_created_epoch_is_bounded() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(2);
        let entries = make_signed_entries(&snapshot, &keys, "cp_hash");
        let mut blob = QcBlob::new(snapshot.epoch, 100, "cp_hash".into(), entries);

        // A hostile creation epoch must neither overflow nor read as fresh.
        blob.created_epoch = u64::MAX;
        assert!(!blob.is_expired(u64::MAX));
        let err = blob
            .verify_against_snapshot(&snapshot, None, Some(snapshot.epoch))
            .expect_err("created_epoch above the attested epoch is refused");
        assert!(err.contains("is above its epoch"), "{err}");

        // The honest value still verifies with a current epoch inside the TTL.
        blob.created_epoch = snapshot.epoch;
        blob.verify_against_snapshot(&snapshot, None, Some(snapshot.epoch + QC_BLOB_TTL_EPOCHS))
            .expect("inside the TTL window");
        let err = blob
            .verify_against_snapshot(
                &snapshot,
                None,
                Some(snapshot.epoch + QC_BLOB_TTL_EPOCHS + 1),
            )
            .expect_err("one past the TTL window");
        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn test_qc_blob_creation() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(4);
        let entries = make_signed_entries(&snapshot, &keys, "cp_hash");
        let blob = QcBlob::new(1, 100, "cp_hash".into(), entries);
        assert_eq!(blob.epoch, 1);
        assert_eq!(blob.checkpoint_height, 100);
        assert!(!blob.merkle_root.is_empty());
        assert!(blob.verify_merkle_root());
    }

    /// A character cannot move from the address into the signature.
    ///
    /// `leaf_hash` appended a `String` and a `Vec<u8>` with nothing between
    /// them, so the last character of the address and the first byte of the
    /// signature sat on an ambiguous boundary. Two different entries produced
    /// one leaf. `verify_inclusion` rebuilds that leaf from a fault proof and
    /// a verdict from it reaches `slash_validator` at the malicious-behaviour
    /// ratio, so the collision let one accepted leaf carry two stories about
    /// the same slot.
    ///
    /// The shift is done by hand rather than through `sign_attestation`,
    /// because no honest signer produces the forged pair: the point is that
    /// the *digest* cannot tell them apart, not that a signer would try.
    #[test]
    fn a_leaf_cannot_shift_bytes_from_the_address_into_the_signature() {
        let honest = PqSignatureEntry {
            validator_index: 7,
            validator_address: "0xabcdef".to_string(),
            pq_signature: vec![1, 2, 3, 4],
        };

        // Move the last address character to the front of the signature. The
        // concatenation is byte-identical; only the split differs.
        let mut shifted_signature = vec![b'f'];
        shifted_signature.extend_from_slice(&honest.pq_signature);
        let shifted = PqSignatureEntry {
            validator_index: honest.validator_index,
            validator_address: "0xabcde".to_string(),
            pq_signature: shifted_signature,
        };

        // The premise: without lengths these two are the same bytes.
        let mut honest_concat = honest.validator_address.as_bytes().to_vec();
        honest_concat.extend_from_slice(&honest.pq_signature);
        let mut shifted_concat = shifted.validator_address.as_bytes().to_vec();
        shifted_concat.extend_from_slice(&shifted.pq_signature);
        assert_eq!(
            honest_concat, shifted_concat,
            "the fixture must actually be a re-split, or this test proves \
             nothing about the boundary"
        );

        assert_ne!(
            QcBlob::leaf_hash(&honest),
            QcBlob::leaf_hash(&shifted),
            "two entries whose fields concatenate alike must not share a leaf"
        );
    }

    /// The same boundary, seen through the Merkle root a blob commits to.
    #[test]
    fn a_re_split_entry_changes_the_merkle_root() {
        let honest = vec![PqSignatureEntry {
            validator_index: 0,
            validator_address: "0xdeadbeef".to_string(),
            pq_signature: vec![9; 32],
        }];
        let mut shifted_signature = vec![b'f'];
        shifted_signature.extend_from_slice(&honest[0].pq_signature);
        let shifted = vec![PqSignatureEntry {
            validator_index: 0,
            validator_address: "0xdeadbee".to_string(),
            pq_signature: shifted_signature,
        }];

        assert_ne!(
            QcBlob::compute_merkle_root(&honest),
            QcBlob::compute_merkle_root(&shifted),
            "the root is what `verify_merkle_root` checks a blob against"
        );
    }

    /// An empty signature and an empty address are distinguishable from each
    /// other and from the honest pair, or the length prefix is decoration.
    #[test]
    fn empty_fields_do_not_collapse_into_each_other() {
        let both = PqSignatureEntry {
            validator_index: 1,
            validator_address: String::new(),
            pq_signature: Vec::new(),
        };
        let address_only = PqSignatureEntry {
            validator_index: 1,
            validator_address: "ab".to_string(),
            pq_signature: Vec::new(),
        };
        let signature_only = PqSignatureEntry {
            validator_index: 1,
            validator_address: String::new(),
            pq_signature: vec![b'a', b'b'],
        };

        let leaves = [
            QcBlob::leaf_hash(&both),
            QcBlob::leaf_hash(&address_only),
            QcBlob::leaf_hash(&signature_only),
        ];
        assert_ne!(leaves[0], leaves[1]);
        assert_ne!(leaves[0], leaves[2]);
        assert_ne!(
            leaves[1], leaves[2],
            "`ab` in the address and `ab` in the signature are different \
             entries and must be different leaves"
        );
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(4);
        let entries = make_signed_entries(&snapshot, &keys, "cp_hash");
        let root1 = QcBlob::compute_merkle_root(&entries);
        let root2 = QcBlob::compute_merkle_root(&entries);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_merkle_root_changes_with_data() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(4);
        let entries1 = make_signed_entries(&snapshot, &keys, "cp_hash");
        let mut entries2 = entries1.clone();
        entries2[0].pq_signature[0] ^= 0xFF;
        let root1 = QcBlob::compute_merkle_root(&entries1);
        let root2 = QcBlob::compute_merkle_root(&entries2);
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_empty_merkle_root() {
        let root = QcBlob::compute_merkle_root(&[]);
        assert_eq!(root.len(), 64);
        assert!(root.chars().all(|c| c == '0'));
    }

    #[test]
    fn test_blob_expiry() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(2);
        let entries = make_signed_entries(&snapshot, &keys, "cp");
        let blob = QcBlob::new(1, 100, "cp".into(), entries);
        assert!(!blob.is_expired(5));
        assert!(!blob.is_expired(11));
        assert!(blob.is_expired(12));
    }

    fn synthetic_blob(entries: usize) -> QcBlob {
        let pq_signatures: Vec<PqSignatureEntry> = (0..entries)
            .map(|i| PqSignatureEntry {
                validator_index: i as u32,
                validator_address: format!("{i:064x}"),
                // ML-DSA-65 sized; the codec does not look inside.
                pq_signature: vec![(i % 251) as u8; 3309],
            })
            .collect();
        QcBlob::new(7, 700, format!("{:064x}", 0xabcdu32), pq_signatures)
    }

    #[test]
    fn wire_encoding_round_trips_and_matches_its_length() {
        let blob = synthetic_blob(5);
        let bytes = blob.to_bytes().unwrap();
        assert_eq!(bytes.len(), blob.encoded_len());
        assert_eq!(bytes[0], QC_WIRE_VERSION);
        let back = QcBlob::from_bytes(&bytes, 5).unwrap();
        assert_eq!(back.to_bytes().unwrap(), bytes);
        assert_eq!(back.merkle_root, blob.merkle_root);
        assert_eq!(back.pq_signatures.len(), 5);
    }

    #[test]
    fn wire_encoding_is_not_json_sized() {
        let blob = synthetic_blob(10);
        let binary = blob.encoded_len();
        let json = serde_json::to_vec(&blob).unwrap().len();
        assert!(
            json > binary * 2,
            "json {json} bytes against binary {binary} bytes"
        );
    }

    #[test]
    fn wire_decoding_refuses_malformed_input() {
        let blob = synthetic_blob(3);
        let bytes = blob.to_bytes().unwrap();
        // Truncated at every interesting cut.
        for cut in [0, 1, 9, 30, bytes.len() / 2, bytes.len() - 1] {
            assert!(QcBlob::from_bytes(&bytes[..cut], 3).is_err(), "cut {cut}");
        }
        // Trailing byte.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(QcBlob::from_bytes(&trailing, 3).is_err());
        // Wrong version.
        let mut wrong = bytes.clone();
        wrong[0] = QC_WIRE_VERSION + 1;
        assert!(QcBlob::from_bytes(&wrong, 3).is_err());
        // More entries than the validator set.
        assert!(QcBlob::from_bytes(&bytes, 2).is_err());
        // A header that claims a huge count over few bytes is refused before
        // anything is allocated for it.
        let count_at = 1 + 8 + 8 + 2 + blob.checkpoint_hash.len() + 2 + blob.merkle_root.len() + 8;
        let mut huge = bytes.clone();
        huge[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(QcBlob::from_bytes(&huge, usize::MAX).is_err());
    }

    #[test]
    fn oversize_fields_have_no_encoding() {
        let mut blob = synthetic_blob(1);
        blob.checkpoint_hash = "x".repeat(QC_WIRE_MAX_STRING + 1);
        assert!(blob.to_bytes().is_err());
        let mut blob = synthetic_blob(1);
        blob.pq_signatures[0].pq_signature = vec![0; QC_WIRE_MAX_SIGNATURE + 1];
        assert!(blob.to_bytes().is_err());
    }

    #[test]
    fn size_bound_grows_with_the_validator_set() {
        // The old fixed 1 MiB cap stopped a set at about 310 members.
        assert!(qc_blob_max_bytes(1_000) > 1_048_576);
        let blob = synthetic_blob(1_000);
        assert!(blob.validate_size(1_000).is_ok());
        assert!(blob.encoded_len() > 1_048_576);
        // The same blob does not fit a smaller set.
        assert!(blob.validate_size(100).is_err());
    }

    /// A blob of 1,000 validators travels as chunks and reassembles to the
    /// same bytes.
    #[test]
    fn thousand_validator_blob_travels_in_chunks() {
        let blob = synthetic_blob(1_000);
        let chunks = blob.to_chunks().unwrap();
        assert!(chunks.len() > 10);
        assert!(chunks[..chunks.len() - 1]
            .iter()
            .all(|chunk| chunk.len() == QC_CHUNK_BYTES));

        // Out of order delivery.
        let mut assembler = QcBlobAssembler::new(1_000, chunks.len()).unwrap();
        for index in (0..chunks.len()).rev() {
            assert!(!assembler.is_complete());
            assembler.push(index, chunks[index].clone()).unwrap();
        }
        assert!(assembler.is_complete());
        let back = assembler.finish().unwrap();
        assert_eq!(back.to_bytes().unwrap(), blob.to_bytes().unwrap());
        assert!(back.verify_merkle_root());
    }

    #[test]
    fn assembler_refuses_a_cheating_sender() {
        let blob = synthetic_blob(50);
        let chunks = blob.to_chunks().unwrap();
        // An announced chunk count above what the validator set allows.
        assert!(QcBlobAssembler::new(50, 10_000).is_err());
        assert!(QcBlobAssembler::new(50, 0).is_err());
        let mut assembler = QcBlobAssembler::new(50, chunks.len()).unwrap();
        assembler.push(0, chunks[0].clone()).unwrap();
        // A repeated index cannot replace the first copy.
        assert!(assembler.push(0, vec![1, 2, 3]).is_err());
        assert!(assembler.push(chunks.len(), vec![]).is_err());
        assert!(assembler.push(1, vec![0; QC_CHUNK_BYTES + 1]).is_err());
        assert!(!assembler.is_complete());
        assert!(assembler.finish().is_err());
    }

    #[test]
    fn signing_message_binds_scheme_and_every_field() {
        let base = pq_signing_message(1, 100, "hash", 0);
        assert_ne!(base, pq_signing_message(2, 100, "hash", 0));
        assert_ne!(base, pq_signing_message(1, 101, "hash", 0));
        assert_ne!(base, pq_signing_message(1, 100, "hasi", 0));
        assert_ne!(base, pq_signing_message(1, 100, "hash", 1));
        // The scheme id of the signing key is in the message (INV-02).
        let scheme = crate::crypto::scheme::SchemeId::ML_DSA_65.0.to_be_bytes();
        assert!(base.windows(2).any(|w| w == scheme));
        assert!(base
            .windows(b"BDLM_PQ_QC_V2".len())
            .any(|w| w == b"BDLM_PQ_QC_V2"));
    }

    #[test]
    fn test_blob_size_validation() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(4);
        let entries = make_signed_entries(&snapshot, &keys, "cp");
        let blob = QcBlob::new(1, 100, "cp".into(), entries);
        assert!(blob.validate_size(blob.pq_signatures.len()).is_ok());
    }

    #[test]
    fn test_qc_blob_verify_against_snapshot() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(3);
        let entries = make_signed_entries(&snapshot, &keys, "cp");
        let blob = QcBlob::new(snapshot.epoch, 100, "cp".into(), entries);
        assert!(blob
            .verify_against_snapshot(&snapshot, Some(&[0, 1, 2]), Some(snapshot.epoch))
            .is_ok());
    }

    #[test]
    fn test_detect_fault_proof_for_invalid_signature() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(2);
        let mut entries = make_signed_entries(&snapshot, &keys, "cp");
        entries[1].pq_signature[0] ^= 0xAA;
        let blob = QcBlob::new(snapshot.epoch, 100, "cp".into(), entries);
        let proofs = blob.detect_fault_proofs(&snapshot);
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].validator_index, 1);
        // P01-F22: detection still reports the broken entry, but a signature
        // that fails to verify is not evidence against the named validator -
        // the same bytes could name a non-participant - so no verdict issues.
        let err = proofs[0].verify_against_blob(&blob, &snapshot).unwrap_err();
        assert!(
            err.contains("not evidence"),
            "the refusal must name the frame-up reason, got: {err}"
        );
    }

    #[test]
    fn test_fault_proof_rejects_valid_signature() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(1);
        let entries = make_signed_entries(&snapshot, &keys, "cp");
        let blob = QcBlob::new(snapshot.epoch, 100, "cp".into(), entries);
        let proof = QcFaultProof::new_invalid_dilithium(
            snapshot.epoch,
            100,
            "cp".into(),
            0,
            snapshot.validators[0].address.to_string(),
            InvalidDilithiumEvidence {
                pq_signature: blob.pq_signatures[0].pq_signature.clone(),
                merkle_proof: blob.merkle_proof(0).unwrap(),
                leaf_index: 0,
            },
        );
        assert!(proof.verify_against_blob(&blob, &snapshot).is_err());
    }

    #[test]
    fn test_zk_qc_fault_proof_is_versioned_but_stubbed() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(1);
        let entries = make_signed_entries(&snapshot, &keys, "cp");
        let blob = QcBlob::new(snapshot.epoch, 100, "cp".into(), entries);
        let proof = QcFaultProof::new_zk_invalid_attestation(
            snapshot.epoch,
            100,
            "cp".into(),
            0,
            snapshot.validators[0].address.to_string(),
            vec![1, 2, 3],
            ZkQcPublicInputs {
                merkle_root: blob.merkle_root.clone(),
                pq_public_key_hash: "pq_pk_hash".into(),
                attestation_commitment: "attestation_commitment".into(),
            },
        );

        let result = proof.verify_against_blob(&blob, &snapshot);
        assert!(result
            .unwrap_err()
            .contains("ZK QC fault proof verifier not implemented"));
    }

    #[test]
    fn test_pq_signing_message_deterministic() {
        let msg1 = pq_signing_message(1, 100, "hash", 0);
        let msg2 = pq_signing_message(1, 100, "hash", 0);
        assert_eq!(msg1, msg2);

        let msg3 = pq_signing_message(2, 100, "hash", 0);
        assert_ne!(msg1, msg3);

        let msg4 = pq_signing_message(1, 101, "hash", 0);
        assert_ne!(msg1, msg4);
    }

    #[test]
    fn test_single_entry_merkle() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(1);
        let entries = make_signed_entries(&snapshot, &keys, "cp");
        let blob = QcBlob::new(1, 100, "cp".into(), entries);
        assert!(blob.verify_merkle_root());
    }

    /// (security audit §2) `verify_against_snapshot` returns
    /// The set of unique verified signers, and rejects duplicate
    /// Entries. Together these let the caller (e.g. `import_qc_blob`)
    /// Enforce a BLS quorum against the *post-deduplication* count
    /// Rather than the raw `pq_signatures.len`. This test pins
    /// Both halves of the contract.
    #[test]
    fn verify_against_snapshot_returns_unique_set_and_rejects_duplicates() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(4);
        let mut entries = make_signed_entries(&snapshot, &keys, "cp");

        // Replace validator 3's entry with a second copy of validator 0's.
        // The duplicate has the same validator_index, address and signature
        // as entries[0], so it verifies cryptographically and must be caught
        // by the deduplication check instead.
        //
        // The entry *count* stays at four deliberately. Appending a fifth
        // would now be refused earlier by the entry-count bound, which is a
        // different rejection: this test is about deduplication, so it has to
        // reach that code path.
        entries[3] = entries[0].clone();
        assert_eq!(
            entries.len(),
            snapshot.validators.len(),
            "the count bound must not be what rejects this blob"
        );
        let blob = QcBlob::new(snapshot.epoch, 100, "cp".into(), entries);

        let result = blob.verify_against_snapshot(&snapshot, None, Some(snapshot.epoch));
        assert!(
            result.is_err(),
            "duplicate PQ signature must be rejected even if it verifies cryptographically"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("Duplicate PQ signature"),
            "error must surface the deduplication rationale, got: {err}"
        );

        // The same call without the duplicate must succeed and
        // Return a set of exactly 4 unique validator indices.
        let (snapshot, keys) = make_snapshot_with_pq_keys(4);
        let entries = make_signed_entries(&snapshot, &keys, "cp");
        let blob = QcBlob::new(snapshot.epoch, 100, "cp".into(), entries);
        let verified = blob
            .verify_against_snapshot(&snapshot, None, Some(snapshot.epoch))
            .expect("clean blob must verify");
        assert_eq!(verified.len(), 4, "expected 4 unique verified signers");
        for idx in 0..4 {
            assert!(
                verified.contains(&idx),
                "expected validator index {idx} in verified set"
            );
        }
    }

    /// (security audit §4) the QcFaultProof surface end-to-end: detection
    /// still reports a broken entry, and verification refuses to issue a
    /// verdict on it (P01-F22 - a failing signature is not evidence against
    /// the named validator). This is the contract `bud_submitQcFaultProof`
    /// exposes.
    #[test]
    fn qc_fault_proof_construction_and_verification_e2e() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(2);
        let mut entries = make_signed_entries(&snapshot, &keys, "cp");
        // Corrupt validator 1's dilithium signature so the blob
        // Has a detectable broken entry.
        entries[1].pq_signature[0] ^= 0xAA;
        let blob = QcBlob::new(snapshot.epoch, 100, "cp".into(), entries);

        let proofs = blob.detect_fault_proofs(&snapshot);
        assert_eq!(proofs.len(), 1, "exactly one fault should be detected");
        let proof = &proofs[0];

        // Verify the proof against the blob end-to-end: refused, with the
        // frame-up reason named.
        let err = proof
            .verify_against_blob(&blob, &snapshot)
            .expect_err("a failing signature must not produce a verdict");
        assert!(
            err.contains("not evidence"),
            "the refusal must name the frame-up reason, got: {err}"
        );
    }

    #[test]
    fn an_overlong_merkle_proof_is_refused_before_hashing() {
        let proof = QcFaultProof::new_invalid_dilithium(
            1,
            100,
            "cp".into(),
            0,
            "addr".into(),
            InvalidDilithiumEvidence {
                pq_signature: vec![1],
                merkle_proof: vec![vec![0u8; 32]; MAX_MERKLE_PROOF_ELEMENTS + 1],
                leaf_index: 0,
            },
        );
        let err = proof
            .validate()
            .expect_err("an overlong path must be refused");
        assert!(err.contains("longer than any tree path"), "{err}");
        let err = proof
            .verify_inclusion("root")
            .expect_err("an overlong path must not be hashed");
        assert!(err.contains("at most 32"), "{err}");
    }

    /// A blob may not carry more signature entries than the validator set has
    /// members, and the check must happen before anything that scales with the
    /// entry count.
    ///
    /// `validate_size` bounds the blob in bytes, not entries. With a one-byte
    /// signature an entry costs about 50 bytes, so roughly 20 000 fit under
    /// the byte bound - and every one of them used to be hashed by
    /// `verify_merkle_root` before the verification loop rejected the first
    /// one. Measured on this four-validator snapshot (debug build), 10 000
    /// entries cost 604 ms of CPU for a blob that can never verify.
    #[test]
    fn rejects_more_signature_entries_than_validators() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(4);
        let valid = make_signed_entries(&snapshot, &keys, "cp");

        let mut entries = valid.clone();
        // One extra entry is enough to be unusable: the duplicate check below
        // would reject it anyway, so there is no reason to hash it first.
        entries.push(valid[0].clone());

        let blob = QcBlob {
            epoch: snapshot.epoch,
            checkpoint_height: 100,
            checkpoint_hash: "cp".into(),
            merkle_root: QcBlob::compute_merkle_root(&entries),
            pq_signatures: entries,
            created_epoch: snapshot.epoch,
        };

        let err = blob
            .verify_against_snapshot(&snapshot, None, None)
            .expect_err("more entries than validators must be refused");
        assert!(
            err.contains("signature entries for a validator set of"),
            "rejection must name the count mismatch, got: {err}"
        );
    }

    /// The expensive-path canary: a blob stuffed with entries must be refused
    /// before any per-entry work runs (P01-F25).
    ///
    /// The invariant is check ORDER, and the refusal reason proves it
    /// deterministically. The blob carries a garbage root and more entries
    /// than the set has members: if the count bound runs first, the error
    /// names the entry count; if the merkle hashing ran first, the error
    /// would name the root. The wall-clock ratio this used to assert flaked
    /// under CI load while proving the same fact less directly.
    #[test]
    fn oversized_blob_is_refused_before_hashing() {
        let (snapshot, _keys) = make_snapshot_with_pq_keys(4);

        let build = |n: usize| -> QcBlob {
            let entries: Vec<PqSignatureEntry> = (0..n)
                .map(|i| PqSignatureEntry {
                    validator_index: (i % 4) as u32,
                    validator_address: snapshot.validators[i % 4].address.to_string(),
                    pq_signature: vec![0u8; 1],
                })
                .collect();
            QcBlob {
                epoch: snapshot.epoch,
                checkpoint_height: 100,
                checkpoint_hash: "cp".into(),
                // Deliberately not the real root: the entry-count check must
                // fire before the merkle root is even computed.
                merkle_root: String::new(),
                pq_signatures: entries,
                created_epoch: snapshot.epoch,
            }
        };

        for n in [100usize, 10_000] {
            let err = build(n)
                .verify_against_snapshot(&snapshot, None, None)
                .expect_err("more entries than validators must be refused");
            assert!(
                err.contains("signature entries for a validator set of"),
                "with {n} entries the count bound must fire before any hashing, got: {err}"
            );
        }
    }

    /// The bound must not reject a legitimate blob: exactly one entry per
    /// validator has to keep working.
    #[test]
    fn full_validator_set_still_verifies() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(4);
        let entries = make_signed_entries(&snapshot, &keys, "cp");
        assert_eq!(entries.len(), snapshot.validators.len());

        let blob = QcBlob {
            epoch: snapshot.epoch,
            checkpoint_height: 100,
            checkpoint_hash: "cp".into(),
            merkle_root: QcBlob::compute_merkle_root(&entries),
            pq_signatures: entries,
            created_epoch: snapshot.epoch,
        };

        let verified = blob
            .verify_against_snapshot(&snapshot, None, None)
            .expect("a blob with one entry per validator must verify");
        assert_eq!(verified.len(), 4);
    }

    /// A partial quorum (fewer entries than validators) must also still pass
    /// structural verification - the bound is an upper limit, not an equality.
    #[test]
    fn partial_signature_set_still_verifies() {
        let (snapshot, keys) = make_snapshot_with_pq_keys(4);
        let mut entries = make_signed_entries(&snapshot, &keys, "cp");
        entries.truncate(3);

        let blob = QcBlob {
            epoch: snapshot.epoch,
            checkpoint_height: 100,
            checkpoint_hash: "cp".into(),
            merkle_root: QcBlob::compute_merkle_root(&entries),
            pq_signatures: entries,
            created_epoch: snapshot.epoch,
        };

        let verified = blob
            .verify_against_snapshot(&snapshot, None, None)
            .expect("a partial but honest signature set must verify");
        assert_eq!(verified.len(), 3);
    }

    /// The production QC tree stays in step with the Kani bounded model.
    ///
    /// `kani/src/lib.rs` model-checks the tree shape on a fixed-array bounded
    /// model with a non-commutative abstract combine. This test replicates
    /// that bounded model literally (the same sibling rule, the same parity
    /// ordering, the same in-place fold) and asserts it agrees with the
    /// production `merkle_tree` module on the same leaves, and that the
    /// SHA3 binding used by `QcBlob` produces the roots `compute_merkle_root`
    /// commits to. A drift on either side fails here, exactly like
    /// `bond_arithmetic_matches_the_kani_mirror` holds `penalty_for` in step.
    #[test]
    fn qc_merkle_matches_the_kani_mirror() {
        // The Kani mirror combine (`combine_nodes_u64`): rotate-xor, order
        // sensitive on purpose.
        fn kani_combine(left: u64, right: u64) -> u64 {
            left.rotate_left(17) ^ right.rotate_right(7)
        }
        // The Kani sibling rule, verbatim.
        fn kani_sibling(index: usize, layer_len: usize) -> usize {
            if index.is_multiple_of(2) {
                (index + 1).min(layer_len.saturating_sub(1))
            } else {
                index.saturating_sub(1)
            }
        }
        // The Kani promotion, verbatim.
        fn kani_promote(node: u64) -> u64 {
            node.rotate_left(13) ^ 0x5A5A_5A5A_5A5A_5A5A
        }

        // The Kani in-place parent fold, verbatim: pairs combine, an
        // unpaired tail is promoted, never paired with itself.
        fn kani_fold(layer: &mut [u64; 4], len: usize) -> usize {
            let mut i = 0;
            let mut out = 0;
            while i < len {
                if i + 1 < len {
                    layer[out] = kani_combine(layer[i], layer[i + 1]);
                } else {
                    layer[out] = kani_promote(layer[i]);
                }
                i += 2;
                out += 1;
            }
            out
        }
        // The Kani root + rebuild, verbatim.
        fn kani_root(leaves: &[u64; 4], len: usize) -> Option<u64> {
            if len == 0 {
                return None;
            }
            let mut work = *leaves;
            let mut layer_len = len;
            while layer_len > 1 {
                layer_len = kani_fold(&mut work, layer_len);
            }
            Some(work[0])
        }
        fn kani_rebuild(leaves: &[u64; 4], len: usize, index: usize) -> Option<u64> {
            if len == 0 || index >= len {
                return None;
            }
            let mut work = *leaves;
            let mut layer_len = len;
            let mut idx = index;
            let mut cur = work[idx];
            while layer_len > 1 {
                if idx.is_multiple_of(2) && idx + 1 >= layer_len {
                    // The tail of an odd layer is promoted, not paired.
                    cur = kani_promote(cur);
                } else {
                    let sibling = work[kani_sibling(idx, layer_len)];
                    cur = if idx.is_multiple_of(2) {
                        kani_combine(cur, sibling)
                    } else {
                        kani_combine(sibling, cur)
                    };
                }
                idx /= 2;
                layer_len = kani_fold(&mut work, layer_len);
            }
            Some(cur)
        }

        // Pack a u64 leaf into the production's 32-byte digest (low bytes,
        // rest zero) and unpack a 32-byte digest back to u64 the same way.
        fn to_digest(v: u64) -> [u8; 32] {
            let mut out = [0u8; 32];
            out[..8].copy_from_slice(&v.to_le_bytes());
            out
        }
        fn from_digest(d: [u8; 32]) -> u64 {
            u64::from_le_bytes(d[..8].try_into().expect("8 bytes"))
        }

        // The production tree over packed u64 leaves with the Kani combine
        // and promote shapes: every production node is exactly the packed
        // Kani node, promoted or paired alike.
        fn u64_combine(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
            to_digest(kani_combine(from_digest(*left), from_digest(*right)))
        }
        fn u64_promote(node: &[u8; 32]) -> [u8; 32] {
            to_digest(kani_promote(from_digest(*node)))
        }

        let samples = [
            [1u64, 2, 3, 4],
            [9u64, 7, 5, 3],
            [u64::MAX, 0, 42, 17],
            [5u64, 6, 0, 0],
        ];
        for sample in samples {
            for len in 0..=4usize {
                let mut leaves = [0u64; 4];
                leaves[..len].copy_from_slice(&sample[..len]);
                let root = kani_root(&leaves, len);
                let prod_leaves: Vec<[u8; 32]> =
                    sample[..len].iter().map(|v| to_digest(*v)).collect();
                let prod_root = if prod_leaves.is_empty() {
                    None
                } else {
                    Some(from_digest(crate::consensus::merkle_tree::merkle_root(
                        &prod_leaves,
                        u64_combine,
                        u64_promote,
                    )))
                };
                assert_eq!(root, prod_root, "root disagreement at len {len}");
                for index in 0..len {
                    let rebuilt = kani_rebuild(&leaves, len, index);
                    let prod_rebuilt = crate::consensus::merkle_tree::merkle_rebuild_root(
                        &prod_leaves,
                        index,
                        u64_combine,
                        u64_promote,
                    )
                    .map(from_digest);
                    assert_eq!(
                        rebuilt, prod_rebuilt,
                        "rebuild disagreement at len {len}, index {index}"
                    );
                    assert_eq!(rebuilt, root, "rebuild != root at len {len}, index {index}");
                }
            }
        }
    }
}
