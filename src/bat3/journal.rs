//! Canonical `Bat3` journal: append-only, NFC-normalized text entries bound
//! to a sequence number, topic, and digest, folded into an odd-promote Merkle
//! root.
//!
//! WIRING: reached through `crate::bat3` (re-exported in `src/bat3/mod.rs`)
//! and called by `crate::explorer_evidence` to anchor verified consensus facts.

use crate::core::hash::hash_fields_bytes;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

/// Maximum canonical text length of one journal entry, in bytes.
///
/// WIRING: enforced in [`Bat3Journal::append`] before the entry is stored.
pub const MAX_BAT3_ENTRY_BYTES: usize = 64 * 1024;

/// Maximum topic length of one journal entry, in bytes.
///
/// WIRING: enforced in [`Bat3Journal::append`] before the entry is stored.
pub const MAX_BAT3_TOPIC_BYTES: usize = 256;

/// Why a `Bat3` journal entry was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum Bat3JournalError {
    /// The text was not already in Unicode NFC form.
    #[error("Bat3 journal entry text is not NFC-normalized")]
    NonNfcText,
    /// The text carried a forbidden control or bidirectional override character.
    #[error("Bat3 journal entry text carries forbidden control char U+{0:04X}")]
    ForbiddenControlChar(u32),
    /// The entry exceeded the canonical text byte ceiling.
    #[error("Bat3 journal entry text exceeds the byte ceiling")]
    EntryTooLarge,
    /// The topic exceeded the topic byte ceiling.
    #[error("Bat3 journal entry topic exceeds the byte ceiling")]
    TopicTooLarge,
}

/// One append-only `Bat3` journal entry.
///
/// WIRING: produced by [`Bat3Journal::append`] and consumed by
/// [`ConsensusFact::bind_from_attestation`](crate::bat3::consensus_interface::ConsensusFact::bind_from_attestation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bat3JournalEntry {
    sequence: u64,
    height: u64,
    digest: [u8; 32],
    topic: String,
    text: String,
    leaf: [u8; 32],
}

impl Bat3JournalEntry {
    /// Constructs a standalone journal entry outside a journal context.
    ///
    /// WIRING: Convenience for fact anchors and tests that need an entry
    /// without a backing journal; production anchoring goes through
    /// [`Bat3Journal::append`].
    ///
    /// # Errors
    ///
    /// Returns an error if the topic is too large, the text is too large, the
    /// text is not NFC, or the text carries a forbidden control character.
    pub fn new(
        sequence: u64,
        height: u64,
        digest: [u8; 32],
        topic: &str,
        text: &str,
    ) -> Result<Self, Bat3JournalError> {
        if topic.len() > MAX_BAT3_TOPIC_BYTES {
            return Err(Bat3JournalError::TopicTooLarge);
        }
        if text.len() > MAX_BAT3_ENTRY_BYTES {
            return Err(Bat3JournalError::EntryTooLarge);
        }
        validate_canonical_bat3_text(text)?;
        Ok(Self {
            sequence,
            height,
            digest,
            topic: topic.to_string(),
            text: text.to_string(),
            leaf: Self::leaf_hash(sequence, height, &digest, topic, text),
        })
    }

    /// The 0-based sequence number of this entry within its journal.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The external block height this entry was anchored at.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// The digest this entry was bound to.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The topic this entry was filed under.
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// The canonical, NFC-normalized text of this entry.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The self-derived Merkle leaf digest of this entry.
    #[must_use]
    pub const fn leaf(&self) -> &[u8; 32] {
        &self.leaf
    }

    /// Computes the self-derived Merkle leaf digest for an entry's inputs.
    ///
    /// WIRING: used by [`Self::new`] and [`Bat3Journal::append`] to derive
    /// the leaf before the entry is stored.
    fn leaf_hash(
        sequence: u64,
        height: u64,
        digest: &[u8; 32],
        topic: &str,
        text: &str,
    ) -> [u8; 32] {
        let seq_le = sequence.to_le_bytes();
        let height_le = height.to_le_bytes();
        hash_fields_bytes(&[
            b"BDLM_BAT3_JOURNAL_ENTRY_V1",
            &seq_le,
            &height_le,
            digest,
            topic.as_bytes(),
            text.as_bytes(),
        ])
    }
}

/// Validates that `text` is NFC-normalized and free of forbidden control and
/// bidirectional override characters.
///
/// # Errors
///
/// Returns [`Bat3JournalError::NonNfcText`] if the text is not NFC, or
/// [`Bat3JournalError::ForbiddenControlChar`] if it carries a control or
/// bidirectional override character.
pub fn validate_canonical_bat3_text(text: &str) -> Result<(), Bat3JournalError> {
    let nfc: String = text.nfc().collect();
    if nfc != text {
        return Err(Bat3JournalError::NonNfcText);
    }
    for ch in text.chars() {
        let cp = ch as u32;
        // C0 / C1 controls and the Unicode bidirectional override characters
        // (U+202A..U+202E, U+2066..U+2069) are refused: they can visually
        // reorder or hide text without changing the byte length.
        if ch.is_control() || (0x202A..=0x202E).contains(&cp) || (0x2066..=0x2069).contains(&cp) {
            return Err(Bat3JournalError::ForbiddenControlChar(cp));
        }
    }
    Ok(())
}

/// An append-only `Bat3` journal folded into an odd-promote Merkle root.
///
/// WIRING: constructed by `crate::explorer_evidence` and the `crate::bat3`
/// unit tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bat3Journal {
    entries: Vec<Bat3JournalEntry>,
    root: [u8; 32],
}

impl Bat3Journal {
    /// Constructs an empty journal with the canonical empty root.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            root: hash_fields_bytes(&[b"BDLM_BAT3_JOURNAL_ROOT_V1", &[]]),
        }
    }

    /// Appends a canonical entry and updates the odd-promote Merkle root.
    ///
    /// # Errors
    ///
    /// Returns an error if the topic is too large, the text is too large, the
    /// text is not NFC, or the text carries a forbidden control character.
    pub fn append(
        &mut self,
        height: u64,
        digest: [u8; 32],
        topic: &str,
        text: &str,
    ) -> Result<Bat3JournalEntry, Bat3JournalError> {
        if topic.len() > MAX_BAT3_TOPIC_BYTES {
            return Err(Bat3JournalError::TopicTooLarge);
        }
        if text.len() > MAX_BAT3_ENTRY_BYTES {
            return Err(Bat3JournalError::EntryTooLarge);
        }
        validate_canonical_bat3_text(text)?;
        let sequence = self.entries.len() as u64;
        let entry = Bat3JournalEntry {
            sequence,
            height,
            digest,
            topic: topic.to_string(),
            text: text.to_string(),
            leaf: Bat3JournalEntry::leaf_hash(sequence, height, &digest, topic, text),
        };
        self.root = Self::promote_root(&self.entries, &entry);
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// The current odd-promote Merkle root of the journal.
    #[must_use]
    pub const fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The number of entries in the journal.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the journal holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries in sequence order.
    #[must_use]
    pub fn entries(&self) -> &[Bat3JournalEntry] {
        &self.entries
    }

    /// Recomputes every leaf and the root, refusing any drift.
    ///
    /// # Errors
    ///
    /// Returns an error if any entry's stored leaf disagrees with its inputs.
    pub fn verify_integrity(&self) -> Result<(), Bat3JournalError> {
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.sequence != idx as u64 {
                return Err(Bat3JournalError::NonNfcText);
            }
            let expected = Bat3JournalEntry::leaf_hash(
                entry.sequence,
                entry.height,
                &entry.digest,
                &entry.topic,
                &entry.text,
            );
            if expected != entry.leaf {
                return Err(Bat3JournalError::NonNfcText);
            }
            let leaves: Vec<[u8; 32]> = self.entries.iter().take(idx + 1).map(|e| e.leaf).collect();
            let recomputed_root = Self::merkle_root(&leaves);
            if recomputed_root != self.root && idx + 1 == self.entries.len() {
                return Err(Bat3JournalError::NonNfcText);
            }
        }
        Ok(())
    }

    /// Computes the odd-promote Merkle root over `prior` leaves plus `last`.
    ///
    /// An odd number of leaves promotes the final leaf by hashing it with the
    /// domain tag directly, so the root of an odd-length journal is
    /// cryptographically distinct from the root of any even-length journal
    /// that shares its prefix.
    fn promote_root(prior: &[Bat3JournalEntry], last: &Bat3JournalEntry) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = prior.iter().map(|e| e.leaf).collect();
        leaves.push(last.leaf);
        Self::merkle_root(&leaves)
    }

    fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return hash_fields_bytes(&[b"BDLM_BAT3_JOURNAL_ROOT_V1", &[]]);
        }
        if leaves.len() == 1 {
            let only = leaves.first().copied().unwrap_or([0u8; 32]);
            return hash_fields_bytes(&[b"BDLM_BAT3_JOURNAL_ROOT_V1", &only]);
        }
        let mut level: Vec<[u8; 32]> = Vec::with_capacity(leaves.len().div_ceil(2));
        let mut iter = leaves.iter();
        while let (Some(left), Some(right)) = (iter.next(), iter.next()) {
            level.push(hash_fields_bytes(&[
                b"BDLM_BAT3_JOURNAL_ROOT_V1",
                left,
                right,
            ]));
        }
        if let Some(last) = iter.next() {
            // Odd leaf: promote it by folding in the domain tag, never by
            // duplicating it (duplication would make an odd-length root equal
            // to a padded even-length root).
            level.push(hash_fields_bytes(&[
                b"BDLM_BAT3_JOURNAL_ROOT_V1",
                last,
                &[0x01u8],
            ]));
        }
        Self::merkle_root(&level)
    }
}

impl Default for Bat3Journal {
    fn default() -> Self {
        Self::new()
    }
}
