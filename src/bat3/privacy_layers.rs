//! `Bat3` privacy layers: `K1` public, `K2` selective-disclosure envelopes,
//! and `K3` shielded records with nullifier-based replay protection.
//!
//! WIRING: reached through `crate::bat3` (re-exported in `src/bat3/mod.rs`)
//! and called by `crate::explorer_evidence` for verified selective-disclosure
//! and nullifier digests.

use crate::core::hash::hash_fields_bytes;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    field_digest: [u8; 32],
}

impl K2SelectiveEnvelope {
    /// Seals a set of named fields into an envelope and returns the envelope
    /// plus the per-field openings.
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
        let mut acc: [u8; 32] = hash_fields_bytes(&[b"BDLM_BAT3_K2_ENVELOPE_V1", &[]]);
        let mut openings = Vec::with_capacity(fields.len());
        for (name, (value, hint)) in fields {
            let field_digest = hash_fields_bytes(&[
                b"BDLM_BAT3_K2_ENVELOPE_V1",
                &acc,
                name.as_bytes(),
                value.as_bytes(),
                hint,
            ]);
            openings.push(K2FieldOpening {
                field_name: name.clone(),
                field_value: value.clone(),
                field_digest,
            });
            acc = field_digest;
        }
        let envelope_root =
            hash_fields_bytes(&[b"BDLM_BAT3_K2_ENVELOPE_V1", &acc, &count.to_le_bytes()]);
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
    /// Verifies that this opening's digest matches the envelope's folding
    /// chain.
    ///
    /// # Errors
    ///
    /// Returns [`Bat3PrivacyError::InvalidOpening`] if the opening's digest
    /// does not match the envelope root.
    pub fn verify(&self, envelope: &K2SelectiveEnvelope) -> Result<(), Bat3PrivacyError> {
        let recomputed = hash_fields_bytes(&[
            b"BDLM_BAT3_K2_ENVELOPE_V1",
            &self.field_digest,
            self.field_name.as_bytes(),
            self.field_value.as_bytes(),
            &envelope.field_count.to_le_bytes(),
        ]);
        if recomputed != envelope.envelope_root {
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
