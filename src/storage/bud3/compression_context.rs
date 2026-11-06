//! B.U.D. 3.0 shared compression context and access tiering (WP-54).
//!
//! Shared context lets public objects in the same content class compress
//! against a canonical corpus manifest while keeping `ContentId` strictly
//! bound to the original plaintext. Sealed content never enters a shared
//! context. Burned corpus objects leave on the next context rotation.
//!
//! WIRING: unwired - post-launch T-Expansion shared compression context and
//! access tiering (WP-54); closed on testnet 45261 until activation height is
//! set by governance.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::bof1::CodecId;
use super::content_id::{ContentId, ContentIdKind};

/// Codec id 12: LZ and shared corpus context.
pub const CODEC_LZ_CONTEXT: CodecId = 12;

/// Domain tag committing a [`ContextManifest`].
pub const CONTEXT_MANIFEST_TAG: &[u8] = b"BDLM_BUD3_CONTEXT_MANIFEST_V1";

/// Binary magic for a context-conditioned payload frame.
pub const CONTEXT_FRAME_MAGIC: [u8; 8] = *b"BDLMCTX1";

/// Maximum dictionary size materialized from corpus candidates (16 MiB).
pub const MAX_CONTEXT_DICTIONARY_BYTES: usize = 16 * 1024 * 1024;

/// Cold tier window: 90 days in seconds.
pub const COLD_WINDOW_SECS: u64 = 90 * 24 * 3_600;
/// Cold tier dwell threshold before conversion: 30 days in seconds.
pub const COLD_DWELL_SECS: u64 = 30 * 24 * 3_600;
/// Hot tier window: 7 days in seconds.
pub const HOT_WINDOW_SECS: u64 = 7 * 24 * 3_600;

/// Activation gate for shared compression context on chain `45261`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextActivation {
    /// First block height at which shared context is accepted, or `None` when
    /// closed (default at testnet launch).
    pub height: Option<u64>,
}

/// Testnet launch configuration: closed until governance sets an activation
/// height.
pub const ACTIVATION: ContextActivation = ContextActivation { height: None };

impl ContextActivation {
    /// Whether shared compression context is open at `block_height`.
    #[must_use]
    pub const fn is_active(&self, block_height: u64) -> bool {
        match self.height {
            Some(active_at) => block_height >= active_at,
            None => false,
        }
    }
}

/// Why a shared-context or tiering operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextError {
    /// Shared compression context is closed at this block height.
    ClosedOnNetwork,
    /// Sealed content is prohibited from entering or referencing shared
    /// compression contexts.
    SealedContentRefused,
    /// Dictionary exceeds [`MAX_CONTEXT_DICTIONARY_BYTES`].
    DictionaryTooLarge { got: usize, max: usize },
    /// Frame header or residual stream is malformed.
    MalformedFrame(&'static str),
    /// Frame references a different context manifest than supplied.
    ManifestMismatch,
    /// Decoded length does not match declared plaintext length.
    LengthMismatch { want: u64, got: u64 },
    /// Underlying codec failed while decoding the residual stream.
    ResidualCodec(String),
    /// Referenced object does not exist in context state.
    UnknownObject,
    /// No active context manifest has been built yet.
    NoActiveManifest,
    /// Fee calculation overflowed or payer lacks spendable balance.
    InsufficientFeeBalance,
}

/// One public corpus entry eligible for shared dictionary construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusEntry {
    /// Public content identifier of the corpus object.
    pub content_id: ContentId,
    /// Content class label (for example `"text/python"` or `"application/json"`).
    pub content_class: String,
    /// Canonical plaintext sample contributed to the local context cache.
    pub sample_bytes: Vec<u8>,
    /// Set when the underlying object is burned; burned entries leave on the
    /// next rotation.
    pub burned: bool,
}

/// Network-committed manifest for one generation of a shared compression
/// context. Validators persist the manifest commitment on-chain and rebuild
/// `dictionary` in their local node cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextManifest {
    /// Monotonically increasing context generation.
    pub generation: u64,
    /// Content class served by this manifest.
    pub content_class: String,
    /// Sorted public [`ContentId`] list included in this generation.
    pub corpus_ids: Vec<ContentId>,
    /// Deterministic SHA-256 commitment over generation, class, corpus ids and
    /// dictionary bytes.
    pub manifest_digest: [u8; 32],
    /// Local dictionary bytes assembled from `corpus_ids`.
    pub dictionary: Vec<u8>,
}

impl ContextManifest {
    /// Construct a deterministic manifest from ordered corpus slices.
    ///
    /// # Errors
    ///
    /// Refuses sealed content ids or dictionaries larger than
    /// [`MAX_CONTEXT_DICTIONARY_BYTES`].
    pub fn build(
        generation: u64,
        content_class: &str,
        entries: &[&CorpusEntry],
    ) -> Result<Self, ContextError> {
        let mut sorted: Vec<&CorpusEntry> = entries
            .iter()
            .copied()
            .filter(|e| !e.burned && e.content_class == content_class)
            .collect();
        sorted.sort_by_key(|e| e.content_id);
        sorted.dedup_by_key(|e| e.content_id);

        let mut corpus_ids = Vec::with_capacity(sorted.len());
        let mut dictionary = Vec::new();
        for entry in sorted {
            if entry.content_id.kind != ContentIdKind::Public {
                return Err(ContextError::SealedContentRefused);
            }
            let remaining = MAX_CONTEXT_DICTIONARY_BYTES.saturating_sub(dictionary.len());
            if remaining == 0 {
                break;
            }
            let take = entry.sample_bytes.len().min(remaining);
            if let Some(prefix) = entry.sample_bytes.get(..take) {
                dictionary.extend_from_slice(prefix);
                corpus_ids.push(entry.content_id);
            }
        }
        let manifest_digest =
            compute_manifest_digest(generation, content_class, &corpus_ids, &dictionary);
        Ok(Self {
            generation,
            content_class: content_class.to_owned(),
            corpus_ids,
            manifest_digest,
            dictionary,
        })
    }
}

fn compute_manifest_digest(
    generation: u64,
    content_class: &str,
    corpus_ids: &[ContentId],
    dictionary: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CONTEXT_MANIFEST_TAG);
    h.update(generation.to_le_bytes());
    h.update((content_class.len() as u64).to_le_bytes());
    h.update(content_class.as_bytes());
    h.update((corpus_ids.len() as u64).to_le_bytes());
    for cid in corpus_ids {
        h.update(cid.digest);
        h.update(cid.len.to_le_bytes());
    }
    h.update((dictionary.len() as u64).to_le_bytes());
    h.update(dictionary);
    h.finalize().into()
}

/// Context-conditioned payload representation (codec 12 wire frame).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextEncodedPayload {
    /// Context generation used to condition the residual.
    pub generation: u64,
    /// Manifest commitment required at decode time.
    pub manifest_digest: [u8; 32],
    /// Codec id (`0` raw or `1` zstd) used to compress the XOR residual.
    pub residual_codec: CodecId,
    /// Compressed XOR residual against the context dictionary stream.
    pub residual_payload: Vec<u8>,
}

impl ContextEncodedPayload {
    /// Canonical byte serialization of the context-conditioned payload.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(54 + self.residual_payload.len());
        out.extend_from_slice(&CONTEXT_FRAME_MAGIC);
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&self.manifest_digest);
        out.extend_from_slice(&self.residual_codec.to_le_bytes());
        out.extend_from_slice(&(self.residual_payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.residual_payload);
        out
    }

    /// Parse canonical bytes produced by [`Self::to_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::MalformedFrame`] when truncated or carrying
    /// trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContextError> {
        if bytes.len() < 54 {
            return Err(ContextError::MalformedFrame("short frame header"));
        }
        let magic = bytes
            .get(0..8)
            .ok_or(ContextError::MalformedFrame("missing magic"))?;
        if magic != CONTEXT_FRAME_MAGIC {
            return Err(ContextError::MalformedFrame("invalid context frame magic"));
        }
        let gen_bytes: [u8; 8] = bytes
            .get(8..16)
            .and_then(|s| s.try_into().ok())
            .ok_or(ContextError::MalformedFrame("missing generation"))?;
        let digest: [u8; 32] = bytes
            .get(16..48)
            .and_then(|s| s.try_into().ok())
            .ok_or(ContextError::MalformedFrame("missing digest"))?;
        let codec_bytes: [u8; 2] = bytes
            .get(48..50)
            .and_then(|s| s.try_into().ok())
            .ok_or(ContextError::MalformedFrame("missing residual codec"))?;
        let len_bytes: [u8; 4] = bytes
            .get(50..54)
            .and_then(|s| s.try_into().ok())
            .ok_or(ContextError::MalformedFrame("missing residual length"))?;
        let payload_len = u32::from_le_bytes(len_bytes) as usize;
        let expected_total = 54usize
            .checked_add(payload_len)
            .ok_or(ContextError::MalformedFrame("frame length overflow"))?;
        if bytes.len() != expected_total {
            return Err(ContextError::MalformedFrame("frame length mismatch"));
        }
        let residual_payload = bytes
            .get(54..expected_total)
            .ok_or(ContextError::MalformedFrame("missing residual slice"))?
            .to_vec();
        Ok(Self {
            generation: u64::from_le_bytes(gen_bytes),
            manifest_digest: digest,
            residual_codec: u16::from_le_bytes(codec_bytes),
            residual_payload,
        })
    }
}

fn xor_with_dictionary(bytes: &[u8], dictionary: &[u8]) -> Vec<u8> {
    if dictionary.is_empty() {
        return bytes.to_vec();
    }
    let dict_len = dictionary.len();
    bytes
        .iter()
        .enumerate()
        .map(|(idx, b)| {
            let d = dictionary.get(idx % dict_len).copied().unwrap_or(0);
            *b ^ d
        })
        .collect()
}

/// Encode public `content` against `ctx`.
///
/// The content is XOR-conditioned against `ctx.dictionary` so shared prefixes
/// and recurring structure collapse to zero runs, then compressed with the
/// verified `bud_codec::select` pipeline.
pub fn encode_with_context(content: &[u8], ctx: &ContextManifest) -> ContextEncodedPayload {
    let residual = xor_with_dictionary(content, &ctx.dictionary);
    let selected = bud_codec::select(&residual);
    ContextEncodedPayload {
        generation: ctx.generation,
        manifest_digest: ctx.manifest_digest,
        residual_codec: selected.codec,
        residual_payload: selected.payload,
    }
}

/// Decode `payload` under `ctx` to `declared_len` plaintext bytes.
///
/// # Errors
///
/// Refuses manifest mismatches, residual codec errors, and any output length
/// differing from `declared_len`.
pub fn decode_with_context(
    payload: &ContextEncodedPayload,
    ctx: &ContextManifest,
    declared_len: u64,
) -> Result<Vec<u8>, ContextError> {
    if payload.generation != ctx.generation || payload.manifest_digest != ctx.manifest_digest {
        return Err(ContextError::ManifestMismatch);
    }
    let residual = bud_codec::decode(
        payload.residual_codec,
        &payload.residual_payload,
        declared_len,
    )
    .map_err(|e| ContextError::ResidualCodec(format!("{e:?}")))?;
    if residual.len() as u64 != declared_len {
        return Err(ContextError::LengthMismatch {
            want: declared_len,
            got: residual.len() as u64,
        });
    }
    Ok(xor_with_dictionary(&residual, &ctx.dictionary))
}

/// Stored context-backed public object record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextStoredObject {
    /// Immutable public [`ContentId`] of the original plaintext.
    pub content_id: ContentId,
    /// Content class key.
    pub content_class: String,
    /// Active context payload representation.
    pub payload: ContextEncodedPayload,
}

/// Access tier classification per Section 6.14 item 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessTier {
    /// At least 5 reads within the last 7 days.
    Hot,
    /// Standard residency tier.
    Warm,
    /// At most 1 read within the last 90 days.
    Cold,
}

/// Per-object access tracking state for tier transitions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessObservation {
    /// Monotonic block timestamps (seconds) of observed reads.
    pub read_timestamps_secs: Vec<u64>,
    /// Timestamp when the object first entered [`AccessTier::Cold`], if cold.
    pub cold_since_secs: Option<u64>,
}

/// Policy engine for Section 6.14 item 8 access-tier transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTierPolicy {
    /// Whether cold objects past [`COLD_DWELL_SECS`] trigger slow-codec
    /// re-encoding. Closed (`false`) on testnet launch; opened in WP-54 upon
    /// activation.
    pub conversion_enabled: bool,
    observations: BTreeMap<ContentId, AccessObservation>,
}

impl Default for AccessTierPolicy {
    fn default() -> Self {
        Self {
            conversion_enabled: false,
            observations: BTreeMap::new(),
        }
    }
}

impl AccessTierPolicy {
    /// Record an access at `now_secs` for a public object.
    pub fn record_access(&mut self, content_id: ContentId, now_secs: u64) {
        let obs = self.observations.entry(content_id).or_default();
        let cutoff = now_secs.saturating_sub(COLD_WINDOW_SECS);
        obs.read_timestamps_secs.retain(|ts| *ts >= cutoff);
        obs.read_timestamps_secs.push(now_secs);
        if self.classify(content_id, now_secs) != AccessTier::Cold {
            obs.cold_since_secs = None;
        }
    }

    /// Classify `content_id` at `now_secs` and update its cold-dwell anchor.
    pub fn evaluate_tier(&mut self, content_id: ContentId, now_secs: u64) -> AccessTier {
        let tier = self.classify(content_id, now_secs);
        let obs = self.observations.entry(content_id).or_default();
        if tier == AccessTier::Cold {
            obs.cold_since_secs.get_or_insert(now_secs);
        } else {
            obs.cold_since_secs = None;
        }
        tier
    }

    /// Pure tier classification at `now_secs`.
    #[must_use]
    pub fn classify(&self, content_id: ContentId, now_secs: u64) -> AccessTier {
        let Some(obs) = self.observations.get(&content_id) else {
            return AccessTier::Cold;
        };
        let hot_cutoff = now_secs.saturating_sub(HOT_WINDOW_SECS);
        let hot_reads = obs
            .read_timestamps_secs
            .iter()
            .filter(|ts| **ts >= hot_cutoff)
            .count();
        if hot_reads >= 5 {
            return AccessTier::Hot;
        }
        let cold_cutoff = now_secs.saturating_sub(COLD_WINDOW_SECS);
        let window_reads = obs
            .read_timestamps_secs
            .iter()
            .filter(|ts| **ts >= cold_cutoff)
            .count();
        if window_reads <= 1 {
            AccessTier::Cold
        } else {
            AccessTier::Warm
        }
    }

    /// Whether `content_id` is eligible for cold slow-codec conversion at
    /// `now_secs`. Sealed objects are never converted by validators (Section
    /// 6.14 item 9).
    #[must_use]
    pub fn should_convert_to_cold_representation(
        &self,
        content_id: ContentId,
        now_secs: u64,
    ) -> bool {
        if !self.conversion_enabled || content_id.kind != ContentIdKind::Public {
            return false;
        }
        let Some(obs) = self.observations.get(&content_id) else {
            return false;
        };
        if self.classify(content_id, now_secs) != AccessTier::Cold {
            return false;
        }
        obs.cold_since_secs
            .is_some_and(|since| now_secs.saturating_sub(since) >= COLD_DWELL_SECS)
    }
}

/// Ledger state for shared compression contexts and the Context Maintenance
/// Pool.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextState {
    /// Corpus candidates indexed by public [`ContentId`].
    pub corpus: BTreeMap<ContentId, CorpusEntry>,
    /// Active context manifest per content class.
    pub manifests: BTreeMap<String, ContextManifest>,
    /// Context-encoded public objects indexed by immutable [`ContentId`].
    pub objects: BTreeMap<ContentId, ContextStoredObject>,
    /// Accumulated Context Maintenance Pool balance in base units.
    pub context_maintenance_pool: u64,
}

impl ContextState {
    /// Register public content as a corpus candidate.
    ///
    /// # Errors
    ///
    /// Refuses [`ContentIdKind::Sealed`] content.
    pub fn register_corpus_candidate(
        &mut self,
        content_id: ContentId,
        content_class: &str,
        plaintext: &[u8],
    ) -> Result<(), ContextError> {
        if content_id.kind != ContentIdKind::Public {
            return Err(ContextError::SealedContentRefused);
        }
        if !content_id.matches_public(plaintext) {
            return Err(ContextError::LengthMismatch {
                want: content_id.len,
                got: plaintext.len() as u64,
            });
        }
        self.corpus.insert(
            content_id,
            CorpusEntry {
                content_id,
                content_class: content_class.to_owned(),
                sample_bytes: plaintext.to_vec(),
                burned: false,
            },
        );
        Ok(())
    }

    /// Mark a burned public object so the next context rotation excludes it.
    pub fn evict_burned_corpus(&mut self, content_id: &ContentId) -> bool {
        if let Some(entry) = self.corpus.get_mut(content_id) {
            entry.burned = true;
            true
        } else {
            false
        }
    }

    /// Store a public object encoded under the current active manifest for
    /// `content_class`.
    ///
    /// # Errors
    ///
    /// Refuses sealed content or missing active manifest.
    pub fn store_public_with_context(
        &mut self,
        content_class: &str,
        plaintext: &[u8],
    ) -> Result<ContentStoredReceipt, ContextError> {
        let ctx = self
            .manifests
            .get(content_class)
            .ok_or(ContextError::NoActiveManifest)?;
        let content_id = ContentId::public(plaintext);
        let payload = encode_with_context(plaintext, ctx);
        let wire_bytes = payload.to_bytes().len() as u64;
        self.objects.insert(
            content_id,
            ContextStoredObject {
                content_id,
                content_class: content_class.to_owned(),
                payload,
            },
        );
        Ok(ContentStoredReceipt {
            content_id,
            generation: ctx.generation,
            wire_bytes,
        })
    }

    /// Rotate `content_class` to the next generation, dropping burned corpus
    /// entries and re-encoding every dependent object without changing its
    /// [`ContentId`].
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if manifest construction or object decoding
    /// fails.
    pub fn rotate_context(
        &mut self,
        content_class: &str,
    ) -> Result<ContextManifest, ContextError> {
        let old_manifest = self.manifests.get(content_class).cloned();
        let next_gen = old_manifest
            .as_ref()
            .map_or(1, |m| m.generation.saturating_add(1));

        let candidates: Vec<&CorpusEntry> = self.corpus.values().collect();
        let new_manifest = ContextManifest::build(next_gen, content_class, &candidates)?;

        if let Some(prev_ctx) = old_manifest {
            let dependent_ids: Vec<ContentId> = self
                .objects
                .iter()
                .filter(|(_, obj)| obj.content_class == content_class)
                .map(|(cid, _)| *cid)
                .collect();
            for cid in dependent_ids {
                let Some(existing) = self.objects.get(&cid) else {
                    continue;
                };
                let plaintext = decode_with_context(&existing.payload, &prev_ctx, cid.len)?;
                if ContentId::public(&plaintext) != cid {
                    return Err(ContextError::LengthMismatch {
                        want: cid.len,
                        got: plaintext.len() as u64,
                    });
                }
                let updated_payload = encode_with_context(&plaintext, &new_manifest);
                if let Some(slot) = self.objects.get_mut(&cid) {
                    slot.payload = updated_payload;
                }
            }
        }

        self.corpus
            .retain(|_, entry| !(entry.burned && entry.content_class == content_class));
        self.manifests
            .insert(content_class.to_owned(), new_manifest.clone());
        Ok(new_manifest)
    }

    /// Charge the context savings fee and route 100% of it to
    /// `context_maintenance_pool` (Section 6.20.2 item 5). Exact full-content
    /// deduplication (`exact_dedup_match == true`) carries zero additional fee.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InsufficientFeeBalance`] on overflow or when
    /// `payer_balance` cannot cover the fee.
    pub fn apply_context_savings_fee(
        &mut self,
        payer_balance: &mut u64,
        standalone_bytes: u64,
        context_bytes: u64,
        fee_per_saved_byte: u64,
        exact_dedup_match: bool,
    ) -> Result<u64, ContextError> {
        if exact_dedup_match {
            return Ok(0);
        }
        let saved_bytes = standalone_bytes.saturating_sub(context_bytes);
        let fee = saved_bytes
            .checked_mul(fee_per_saved_byte)
            .ok_or(ContextError::InsufficientFeeBalance)?;
        let next_payer = payer_balance
            .checked_sub(fee)
            .ok_or(ContextError::InsufficientFeeBalance)?;
        let next_pool = self
            .context_maintenance_pool
            .checked_add(fee)
            .ok_or(ContextError::InsufficientFeeBalance)?;
        *payer_balance = next_payer;
        self.context_maintenance_pool = next_pool;
        Ok(fee)
    }
}

/// Summary returned when storing a context-encoded public object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentStoredReceipt {
    /// Immutable public content identifier.
    pub content_id: ContentId,
    /// Context generation used to encode the payload.
    pub generation: u64,
    /// Wire size of the context-encoded frame.
    pub wire_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::content_id::ContentKey;

    fn sample_corpus_base() -> Vec<u8> {
        b"def step(h, p):\n    return h == p + 1\n".repeat(128)
    }

    #[test]
    fn compression_context_is_closed_on_testnet() {
        assert!(!ACTIVATION.is_active(0));
        assert!(!ACTIVATION.is_active(1_000_000));
        let opened = ContextActivation { height: Some(500) };
        assert!(!opened.is_active(499));
        assert!(opened.is_active(500));
    }

    #[test]
    fn bud3_context_codec_vectors() {
        let dict_bytes = sample_corpus_base();
        let cid = ContentId::public(&dict_bytes);
        let entry = CorpusEntry {
            content_id: cid,
            content_class: "text/python".to_owned(),
            sample_bytes: dict_bytes.clone(),
            burned: false,
        };
        let manifest = ContextManifest::build(1, "text/python", &[&entry]).unwrap();

        // Identical structure with minor edits collapses to near-zero XOR
        // residual and compresses far below standalone zstd.
        let mut edited = dict_bytes;
        edited[12] = b'X';
        edited[512] = b'Y';

        let standalone = bud_codec::select(&edited);
        let encoded = encode_with_context(&edited, &manifest);
        let wire = encoded.to_bytes();
        let parsed = ContextEncodedPayload::from_bytes(&wire).unwrap();
        assert_eq!(parsed, encoded);
        assert!(
            wire.len() < standalone.payload.len(),
            "context frame ({}) must beat standalone payload ({})",
            wire.len(),
            standalone.payload.len()
        );

        let decoded = decode_with_context(&parsed, &manifest, edited.len() as u64).unwrap();
        assert_eq!(decoded, edited);

        // Sealed content is refused from shared context registration.
        let sealed_id = ContentId::sealed(&ContentKey([7u8; 32]), b"secret");
        let mut state = ContextState::default();
        assert_eq!(
            state.register_corpus_candidate(sealed_id, "text/python", b"secret"),
            Err(ContextError::SealedContentRefused)
        );
    }

    #[test]
    fn bud3_context_rotation_keeps_content_id() {
        let mut state = ContextState::default();
        let corpus_v1 = sample_corpus_base();
        let cid_v1 = ContentId::public(&corpus_v1);
        state
            .register_corpus_candidate(cid_v1, "text/python", &corpus_v1)
            .unwrap();
        let manifest_v1 = state.rotate_context("text/python").unwrap();
        assert_eq!(manifest_v1.generation, 1);

        let mut user_file = corpus_v1.clone();
        user_file.extend_from_slice(b"\n# trailing module footer\n");
        let expected_cid = ContentId::public(&user_file);
        let receipt = state
            .store_public_with_context("text/python", &user_file)
            .unwrap();
        assert_eq!(receipt.content_id, expected_cid);
        assert_eq!(receipt.generation, 1);

        let corpus_v2 = b"import hashlib\n".repeat(128);
        let cid_v2 = ContentId::public(&corpus_v2);
        state
            .register_corpus_candidate(cid_v2, "text/python", &corpus_v2)
            .unwrap();
        let manifest_v2 = state.rotate_context("text/python").unwrap();
        assert_eq!(manifest_v2.generation, 2);

        let stored = state.objects.get(&expected_cid).unwrap();
        assert_eq!(stored.content_id, expected_cid);
        assert_eq!(stored.payload.generation, 2);
        let round_trip =
            decode_with_context(&stored.payload, &manifest_v2, expected_cid.len).unwrap();
        assert_eq!(round_trip, user_file);
        assert_eq!(ContentId::public(&round_trip), expected_cid);
    }

    #[test]
    fn bud3_context_burned_corpus_leaves() {
        let mut state = ContextState::default();
        let keep_bytes = sample_corpus_base();
        let burn_bytes = b"burned_secret_template_line\n".repeat(128);
        let keep_id = ContentId::public(&keep_bytes);
        let burn_id = ContentId::public(&burn_bytes);

        state
            .register_corpus_candidate(keep_id, "text/python", &keep_bytes)
            .unwrap();
        state
            .register_corpus_candidate(burn_id, "text/python", &burn_bytes)
            .unwrap();
        let gen1 = state.rotate_context("text/python").unwrap();
        assert!(gen1.corpus_ids.contains(&burn_id));

        // Dependent object uploaded under generation 1 must survive corpus burn
        // and re-encode cleanly under generation 2 without losing its bytes.
        let mut dependent = burn_bytes.clone();
        dependent.extend_from_slice(b"# preserved user code\n");
        let dep_id = state
            .store_public_with_context("text/python", &dependent)
            .unwrap()
            .content_id;

        assert!(state.evict_burned_corpus(&burn_id));
        let gen2 = state.rotate_context("text/python").unwrap();
        assert!(!gen2.corpus_ids.contains(&burn_id));
        assert!(gen2.corpus_ids.contains(&keep_id));
        assert!(!state.corpus.contains_key(&burn_id));

        let stored = state.objects.get(&dep_id).unwrap();
        let recovered = decode_with_context(&stored.payload, &gen2, dep_id.len).unwrap();
        assert_eq!(recovered, dependent);
    }

    #[test]
    fn bud3_context_fee_goes_to_pool() {
        let mut state = ContextState::default();
        let mut payer_balance = 50_000u64;
        let total_before = payer_balance + state.context_maintenance_pool;

        let fee = state
            .apply_context_savings_fee(&mut payer_balance, 4_096, 1_096, 3, false)
            .unwrap();
        assert_eq!(fee, 9_000);
        assert_eq!(payer_balance, 41_000);
        assert_eq!(state.context_maintenance_pool, 9_000);
        assert_eq!(payer_balance + state.context_maintenance_pool, total_before);

        // Exact deduplication charges zero additional context fee.
        let zero_fee = state
            .apply_context_savings_fee(&mut payer_balance, 4_096, 0, 3, true)
            .unwrap();
        assert_eq!(zero_fee, 0);
        assert_eq!(payer_balance, 41_000);
        assert_eq!(state.context_maintenance_pool, 9_000);
    }

    #[test]
    fn access_tiering_tracks_hot_and_cold_transitions() {
        let cid = ContentId::public(b"tiered public payload");
        let mut policy = AccessTierPolicy::default();
        let t0 = 1_000_000u64;

        assert_eq!(policy.evaluate_tier(cid, t0), AccessTier::Cold);
        let due = t0 + COLD_DWELL_SECS + 10;
        // Closed on testnet launch: even after 31 days cold, conversion stays off.
        assert!(!policy.should_convert_to_cold_representation(cid, due));

        policy.conversion_enabled = true;
        assert!(policy.should_convert_to_cold_representation(cid, due));

        // Five reads inside 7 days promote the object to Hot and clear cold dwell.
        let t_hot = t0 + COLD_DWELL_SECS + 100;
        for step in 0..5 {
            policy.record_access(cid, t_hot + step * 60);
        }
        assert_eq!(policy.evaluate_tier(cid, t_hot + 300), AccessTier::Hot);
        assert!(!policy.should_convert_to_cold_representation(cid, t_hot + 300));
    }
}
