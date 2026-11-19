//! `Bat3` privacy layers: `K1` public, `K2` selective-disclosure envelopes,
//! and `K3` shielded records with nullifier-based replay protection.
//!
//! WIRING: reached through `crate::bat3` (re-exported in `src/bat3/mod.rs`)
//! and called by `crate::explorer_evidence` for verified selective-disclosure
//! and nullifier digests.

use crate::core::hash::hash_fields_bytes;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;

/// Maximum number of disclosed fields in one `K2` envelope.
///
/// WIRING: enforced in [`K2SelectiveEnvelope::seal`].
pub const MAX_K2_FIELDS: usize = 64;

/// Why a `Bat3` privacy operation was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum Bat3PrivacyError {
    /// The envelope carried too many fields.
    #[error("Bat3 K2 envelope carries too many fields")]
    TooManyFields,
    /// A field opening failed its integrity check.
    #[error("Bat3 K2 field opening failed integrity check on {0}")]
    InvalidOpening(&'static str),
    /// A `K3` nullifier was already present in the set.
    #[error("Bat3 K3 nullifier is a duplicate")]
    DuplicateNullifier([u8; 32]),
}

/// The privacy tier of a `Bat3` layered record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivacyTier {
    /// `K1`: fully public, no disclosure.
    K1Public,
    /// `K2`: selective disclosure of field openings.
    K2SelectiveDisclosure,
    /// `K3`: shielded record with nullifier replay protection.
    K3Shielded,
}

/// A `K2` selective-disclosure envelope and its per-field openings.
///
/// WIRING: produced by [`K2SelectiveEnvelope::seal`] and verified by
/// [`K2FieldOpening::verify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct K2SelectiveEnvelope {
    envelope_root: [u8; 32],
    field_count: u64,
}

/// One field opening inside a [`K2SelectiveEnvelope`].
///
/// WIRING: produced by [`K2SelectiveEnvelope::seal`] and verified against the
/// envelope by [`K2FieldOpening::verify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct K2FieldOpening {
    field_name: String,
    field_value: String,
    field_salt: [u8; 32],
    leaf_index: u64,
    siblings: Vec<[u8; 32]>,
}

fn k2_leaf_digest(leaf_index: u64, name: &str, value: &str, salt: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_BAT3_K2_ENVELOPE_V1",
        &[0x00u8],
        &leaf_index.to_le_bytes(),
        name.as_bytes(),
        value.as_bytes(),
        salt,
    ])
}

fn k2_branch_digest(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[b"BDLM_BAT3_K2_ENVELOPE_V1", &[0x01u8], left, right])
}

fn k2_odd_digest(only: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[b"BDLM_BAT3_K2_ENVELOPE_V1", &[0x02u8], only])
}

fn k2_root_digest(tree_root: &[u8; 32], field_count: u64) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_BAT3_K2_ENVELOPE_V1",
        &[0x03u8],
        tree_root,
        &field_count.to_le_bytes(),
    ])
}

fn k2_merkle_root_and_proofs(leaves: &[[u8; 32]]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
    if leaves.is_empty() {
        let empty = hash_fields_bytes(&[b"BDLM_BAT3_K2_ENVELOPE_V1", &[0xFFu8]]);
        return (empty, Vec::new());
    }
    let mut proofs: Vec<Vec<[u8; 32]>> = vec![Vec::new(); leaves.len()];
    let mut positions: Vec<usize> = (0..leaves.len()).collect();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        for (leaf_pos, proof) in positions.iter_mut().zip(proofs.iter_mut()) {
            let pos = *leaf_pos;
            let sibling_pos = pos ^ 1;
            if let Some(sibling) = level.get(sibling_pos).copied() {
                proof.push(sibling);
            }
            *leaf_pos = pos / 2;
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [left, right] => next.push(k2_branch_digest(left, right)),
                [only] => next.push(k2_odd_digest(only)),
                _ => {}
            }
        }
        level = next;
    }
    let root = level.first().copied().unwrap_or([0u8; 32]);
    (root, proofs)
}

impl K2SelectiveEnvelope {
    /// Seals a set of named fields into a domain-separated Merkle envelope and
    /// returns the envelope plus independent selective-disclosure openings.
    ///
    /// # Errors
    ///
    /// Returns [`Bat3PrivacyError::TooManyFields`] if the field count exceeds
    /// [`MAX_K2_FIELDS`].
    pub fn seal(
        fields: &BTreeMap<String, (String, [u8; 32])>,
    ) -> Result<(Self, Vec<K2FieldOpening>), Bat3PrivacyError> {
        if fields.len() > MAX_K2_FIELDS {
            return Err(Bat3PrivacyError::TooManyFields);
        }
        let count = u64::try_from(fields.len()).unwrap_or(u64::MAX);
        let mut leaves = Vec::with_capacity(fields.len());
        for (idx, (name, (value, salt))) in fields.iter().enumerate() {
            let leaf_index = u64::try_from(idx).unwrap_or(u64::MAX);
            leaves.push(k2_leaf_digest(leaf_index, name, value, salt));
        }
        let (tree_root, proofs) = k2_merkle_root_and_proofs(&leaves);
        let openings = fields
            .iter()
            .zip(proofs)
            .enumerate()
            .map(|(idx, ((name, (value, salt)), siblings))| K2FieldOpening {
                field_name: name.clone(),
                field_value: value.clone(),
                field_salt: *salt,
                leaf_index: u64::try_from(idx).unwrap_or(u64::MAX),
                siblings,
            })
            .collect();
        let envelope_root = k2_root_digest(&tree_root, count);
        Ok((
            Self {
                envelope_root,
                field_count: count,
            },
            openings,
        ))
    }

    /// The self-derived envelope root.
    #[must_use]
    pub const fn envelope_root(&self) -> &[u8; 32] {
        &self.envelope_root
    }

    /// The number of fields sealed in this envelope.
    #[must_use]
    pub const fn field_count(&self) -> u64 {
        self.field_count
    }
}

impl K2FieldOpening {
    /// Verifies that this selective-disclosure opening is a genuine member of
    /// `envelope` without requiring any sibling field's plaintext or salt.
    ///
    /// # Errors
    ///
    /// Returns [`Bat3PrivacyError::InvalidOpening`] if bounds, sibling path
    /// shape, or the constant-time envelope root comparison fails.
    pub fn verify(&self, envelope: &K2SelectiveEnvelope) -> Result<(), Bat3PrivacyError> {
        let total = usize::try_from(envelope.field_count)
            .map_err(|_| Bat3PrivacyError::InvalidOpening("field_count"))?;
        if total == 0 || total > MAX_K2_FIELDS {
            return Err(Bat3PrivacyError::InvalidOpening("field_count"));
        }
        let mut pos = usize::try_from(self.leaf_index)
            .map_err(|_| Bat3PrivacyError::InvalidOpening("leaf_index"))?;
        if pos >= total {
            return Err(Bat3PrivacyError::InvalidOpening("leaf_index"));
        }
        let mut current = k2_leaf_digest(
            self.leaf_index,
            &self.field_name,
            &self.field_value,
            &self.field_salt,
        );
        let mut level_len = total;
        let mut sibling_iter = self.siblings.iter();
        while level_len > 1 {
            let sibling_pos = pos ^ 1;
            if sibling_pos < level_len {
                let sibling = sibling_iter
                    .next()
                    .ok_or(Bat3PrivacyError::InvalidOpening("siblings"))?;
                current = if pos & 1 == 0 {
                    k2_branch_digest(&current, sibling)
                } else {
                    k2_branch_digest(sibling, &current)
                };
            } else {
                current = k2_odd_digest(&current);
            }
            pos /= 2;
            level_len = level_len.div_ceil(2);
        }
        if sibling_iter.next().is_some() {
            return Err(Bat3PrivacyError::InvalidOpening("siblings"));
        }
        let recomputed = k2_root_digest(&current, envelope.field_count);
        if !bool::from(recomputed.ct_eq(&envelope.envelope_root)) {
            return Err(Bat3PrivacyError::InvalidOpening("field_digest"));
        }
        Ok(())
    }
}

/// A `K3` shielded record carrying a nullifier for replay protection.
///
/// WIRING: produced by [`K3ShieldedRecord::derive`] and admitted to a
/// [`Bat3NullifierSet`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct K3ShieldedRecord {
    nullifier: [u8; 32],
    commitment: [u8; 32],
}

impl K3ShieldedRecord {
    /// Derives a `K3` shielded record from a nullifier seed, a value commitment
    /// seed, a recipient hint, and an epoch tag.
    ///
    /// # Errors
    ///
    /// This constructor is infallible; the domain-separated nullifier and
    /// commitment are always well-formed 32-byte digests.
    pub fn derive(
        nullifier_seed: &[u8; 32],
        value_seed: &[u8; 32],
        recipient_hint: &[u8; 32],
        epoch_tag: [u8; 32],
    ) -> Result<Self, Bat3PrivacyError> {
        let nullifier =
            hash_fields_bytes(&[b"BDLM_BAT3_K3_NULLIFIER_V1", nullifier_seed, &epoch_tag]);
        let commitment = hash_fields_bytes(&[
            b"BDLM_BAT3_K3_NULLIFIER_V1",
            value_seed,
            recipient_hint,
            &epoch_tag,
        ]);
        Ok(Self {
            nullifier,
            commitment,
        })
    }

    /// The nullifier of this shielded record.
    #[must_use]
    pub const fn nullifier(&self) -> &[u8; 32] {
        &self.nullifier
    }

    /// The value commitment of this shielded record.
    #[must_use]
    pub const fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
}

/// A set of admitted `K3` nullifiers for replay protection.
///
/// WIRING: constructed by producers and admitted to via
/// [`Bat3NullifierSet::admit_k3`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Bat3NullifierSet {
    nullifiers: BTreeSet<[u8; 32]>,
}

impl Bat3NullifierSet {
    /// Constructs an empty nullifier set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits a `K3` shielded record's nullifier, refusing duplicates.
    ///
    /// # Errors
    ///
    /// Returns [`Bat3PrivacyError::DuplicateNullifier`] if the nullifier is
    /// already present.
    pub fn admit_k3(&mut self, record: &K3ShieldedRecord) -> Result<(), Bat3PrivacyError> {
        if self.nullifiers.contains(&record.nullifier) {
            return Err(Bat3PrivacyError::DuplicateNullifier(record.nullifier));
        }
        self.nullifiers.insert(record.nullifier);
        Ok(())
    }

    /// The number of admitted nullifiers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nullifiers.len()
    }

    /// Returns `true` when no nullifiers have been admitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nullifiers.is_empty()
    }
}

/// A `Bat3` layered record carrying a privacy tier and a public commitment.
///
/// WIRING: constructed by producers and inspected by explorer views.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Bat3LayeredRecord {
    /// A `K1` public record.
    K1([u8; 32]),
    /// A `K2` selective-disclosure envelope.
    K2(K2SelectiveEnvelope),
    /// A `K3` shielded record.
    K3(K3ShieldedRecord),
}

impl Bat3LayeredRecord {
    /// The privacy tier of this record.
    #[must_use]
    pub const fn tier(&self) -> PrivacyTier {
        match self {
            Self::K1(_) => PrivacyTier::K1Public,
            Self::K2(_) => PrivacyTier::K2SelectiveDisclosure,
            Self::K3(_) => PrivacyTier::K3Shielded,
        }
    }

    /// The public commitment of this record: its root or digest.
    ///
    /// Convenience: exposed for explorer evidence card rendering and
    /// external verifier integration.
    #[must_use]
    pub fn public_commitment(&self) -> [u8; 32] {
        match self {
            Self::K1(digest) => *digest,
            Self::K2(env) => env.envelope_root,
            Self::K3(rec) => rec.commitment,
        }
    }
}
