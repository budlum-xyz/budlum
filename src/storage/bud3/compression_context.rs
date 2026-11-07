//! Shared compression context for public B.U.D. 3.0 objects (Section 6.20 items 1-5).
//! exposed for expansion-tier A0 context codecs (12 and 13), context rotation, and Context Maintenance Pool accounting.
//!
//! Binding invariants (`K15`..`K19`):
//! 1. Closed by default at testnet launch (`TESTNET_CONTEXT_ENABLED_BY_DEFAULT == false`).
//! 2. A shared context is the network's shared dictionary for a public content class,
//!    defined on-chain solely by [`ContextManifest`]; materialized dictionary bytes live
//!    only in each node's local cache ([`LocalContextCache`]).
//! 3. Public objects are corpus candidates by default; sealed objects NEVER enter a
//!    context and NEVER use context codecs (`12` or `13`).
//! 4. Burned corpus objects leave on the next [`SharedContextEngine::rotate_context`];
//!    dependent objects re-encode under their existing NFTs via `ReplaceObject` while
//!    their [`ContentId`] remains invariant.
//! 5. Codec `13` (`CODEC_SHARED_CTX_ARCHIVAL`) is selected on non-cold objects only if
//!    it clears [`ARCHIVAL_CTX_SAVINGS_FLOOR_BPS`]; otherwise it is restricted to
//!    [`AccessTier::Cold`] objects.
//! 6. Context-compressed objects pay a context savings fee into [`ContextMaintenancePool`];
//!    exact full-content deduplication matches pay zero extra fee.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::core::hash::hash_fields_bytes;

use super::access_tiering::AccessTier;
use super::content_id::ContentId;
use super::registry::ObjectKey;

/// Testnet launch posture: shared compression context is closed at genesis (`Section 6.20.1`).
/// Convenience: exposed for launch configuration gates.
pub const TESTNET_CONTEXT_ENABLED_BY_DEFAULT: bool = false;

/// Codec identifier `12`: fast shared-context codec (`Section 6.20.2.3`).
/// Convenience: exposed for A0 expansion codec dispatch.
pub const CODEC_SHARED_CTX_FAST: u8 = 12;

/// Codec identifier `13`: archival shared-context codec (`Section 6.20.2.3-4`).
/// Convenience: exposed for A0 expansion codec dispatch.
pub const CODEC_SHARED_CTX_ARCHIVAL: u8 = 13;

/// Savings floor (`2_500 bps` = 25.00%) required for Codec `13` on non-cold objects (`Section 6.20.2.4`).
/// Convenience: exposed for codec selection policy.
pub const ARCHIVAL_CTX_SAVINGS_FLOOR_BPS: u32 = 2_500;

/// Portion (`2_000 bps` = 20.00%) of physical-byte fee savings directed to the Context Maintenance Pool (`Section 6.20.2.5`).
/// Convenience: exposed for fee schedules and economics tests.
pub const CONTEXT_SAVINGS_FEE_SHARE_BPS: u64 = 2_000;

const CTX_MANIFEST_DOMAIN: &[u8] = b"budlum/bud3/context-manifest/v1";
const CTX_DICT_DOMAIN: &[u8] = b"budlum/bud3/context-dict/v1";
const CTX_WIRE_MAGIC: &[u8; 4] = b"BCX1";
const MIN_CHUNK_MATCH_LEN: usize = 8;

/// Errors raised by shared compression context operations.
/// Convenience: exposed for storage pipeline and RPC callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextError {
    /// Context subsystem is disabled in current network epoch.
    ContextDisabled,
    /// Sealed content is strictly forbidden in shared contexts and context codecs (`Section 6.20.2.3`).
    SealedContentForbidden,
    /// Unknown codec id (only `12` and `13` are shared-context codecs).
    UnsupportedContextCodec(u8),
    /// Codec `13` failed `Y` savings floor on a non-cold object (`Section 6.20.2.4`).
    ArchivalCodecRequiresColdOrFloor { savings_bps: u32 },
    /// Malformed or truncated context-compressed payload.
    MalformedWirePayload(&'static str),
    /// Context manifest digest mismatch against `context_id`.
    ManifestIntegrityMismatch,
    /// Referenced context generation or dictionary is missing from local cache.
    MissingLocalContext([u8; 32]),
}

/// On-chain manifest describing a shared compression context (`Section 6.20.2.1`).
///
/// Only this fixed manifest is persisted in chain state; the materialized dictionary
/// lives inside each node's [`LocalContextCache`].
/// Convenience: exposed for chain state and consensus serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextManifest {
    pub context_id: [u8; 32],
    pub class_tag: String,
    pub generation: u64,
    pub corpus_objects: Vec<ObjectKey>,
    pub dictionary_digest: [u8; 32],
    pub created_epoch: u64,
}

impl ContextManifest {
    /// Build a canonical [`ContextManifest`] with deterministic self-derived `context_id`.
    /// Convenience: exposed for context rotation ceremonies.
    #[must_use]
    pub fn new(
        class_tag: String,
        generation: u64,
        mut corpus_objects: Vec<ObjectKey>,
        dictionary_bytes: &[u8],
        created_epoch: u64,
    ) -> Self {
        corpus_objects.sort_unstable();
        corpus_objects.dedup();
        let dictionary_digest = hash_fields_bytes(&[CTX_DICT_DOMAIN, dictionary_bytes]);
        let mut corpus_flat = Vec::with_capacity(corpus_objects.len().saturating_mul(32));
        for key in &corpus_objects {
            corpus_flat.extend_from_slice(key);
        }
        let context_id = hash_fields_bytes(&[
            CTX_MANIFEST_DOMAIN,
            class_tag.as_bytes(),
            &generation.to_le_bytes(),
            &corpus_flat,
            &dictionary_digest,
            &created_epoch.to_le_bytes(),
        ]);
        Self {
            context_id,
            class_tag,
            generation,
            corpus_objects,
            dictionary_digest,
            created_epoch,
        }
    }

    /// Recompute `context_id` from every manifest field and confirm equality.
    /// Convenience: exposed for state-sync manifest verification.
    #[must_use]
    pub fn verify_id(&self) -> bool {
        let mut corpus_flat = Vec::with_capacity(self.corpus_objects.len().saturating_mul(32));
        for key in &self.corpus_objects {
            corpus_flat.extend_from_slice(key);
        }
        let expected = hash_fields_bytes(&[
            CTX_MANIFEST_DOMAIN,
            self.class_tag.as_bytes(),
            &self.generation.to_le_bytes(),
            &corpus_flat,
            &self.dictionary_digest,
            &self.created_epoch.to_le_bytes(),
        ]);
        self.context_id == expected
    }
}

/// Node-local dictionary cache keyed by `context_id` (`Section 6.20.2.1`).
/// Convenience: exposed for validator and gateway local caches.
#[derive(Debug, Clone, Default)]
pub struct LocalContextCache {
    dictionaries: BTreeMap<[u8; 32], Vec<u8>>,
}

impl LocalContextCache {
    /// Insert materialized dictionary bytes after verifying `manifest.verify_id()` and `dictionary_digest`.
    /// Convenience: exposed for node cache population.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ManifestIntegrityMismatch`] if the manifest id or dictionary digest mismatches.
    pub fn insert_verified(
        &mut self,
        manifest: &ContextManifest,
        dictionary_bytes: Vec<u8>,
    ) -> Result<(), ContextError> {
        if !manifest.verify_id() {
            return Err(ContextError::ManifestIntegrityMismatch);
        }
        let digest = hash_fields_bytes(&[CTX_DICT_DOMAIN, &dictionary_bytes]);
        if digest != manifest.dictionary_digest {
            return Err(ContextError::ManifestIntegrityMismatch);
        }
        self.dictionaries.insert(manifest.context_id, dictionary_bytes);
        Ok(())
    }

    /// Retrieve cached dictionary bytes for `context_id`.
    /// Convenience: exposed for encode/decode pipeline.
    #[must_use]
    pub fn get(&self, context_id: &[u8; 32]) -> Option<&[u8]> {
        self.dictionaries.get(context_id).map(Vec::as_slice)
    }
}

/// Pool collecting context savings fees (`Section 6.20.2.5`).
/// Convenience: exposed for epoch reward settlement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextMaintenancePool {
    pub balance_atoms: u64,
    pub total_collected_atoms: u64,
}

impl ContextMaintenancePool {
    /// Credit `fee_atoms` from a context-codec upload into the pool.
    /// Convenience: exposed for fee accounting.
    pub fn credit_context_fee(&mut self, fee_atoms: u64) {
        self.balance_atoms = self.balance_atoms.saturating_add(fee_atoms);
        self.total_collected_atoms = self.total_collected_atoms.saturating_add(fee_atoms);
    }
}

/// Compute context savings fee (`Section 6.20.2.5`).
///
/// - Exact full-content deduplication match (`exact_dedup_match == true`) pays `0` extra fee.
/// - Otherwise pays `CONTEXT_SAVINGS_FEE_SHARE_BPS` (`20%`) of `(baseline_fee_atoms - compressed_fee_atoms)`.
/// Convenience: exposed for storage fee calculation.
#[must_use]
pub fn compute_context_savings_fee(
    baseline_fee_atoms: u64,
    compressed_fee_atoms: u64,
    exact_dedup_match: bool,
) -> u64 {
    if exact_dedup_match || compressed_fee_atoms >= baseline_fee_atoms {
        return 0;
    }
    let saved = baseline_fee_atoms - compressed_fee_atoms;
    saved
        .saturating_mul(CONTEXT_SAVINGS_FEE_SHARE_BPS)
        .div_ceil(10_000)
}

/// Deterministic lossless shared-context encoder for public content (`Codecs 12 & 13`).
///
/// Wire layout:
/// `BCX1 (4B) || codec_id (1B) || context_id (32B) || orig_len_u32_le (4B) || ops...`
/// where each op is:
/// - `0x00 || lit_len_u16_le || literal_bytes`
/// - `0x01 || dict_off_u32_le || match_len_u16_le`
/// Convenience: exposed for expansion codec evaluation and tests.
///
/// # Errors
///
/// Refuses sealed content, unknown codec ids, or Codec `13` on non-cold objects that
/// fail `ARCHIVAL_CTX_SAVINGS_FLOOR_BPS`.
pub fn encode_with_shared_context(
    codec_id: u8,
    is_sealed: bool,
    tier: AccessTier,
    context_id: [u8; 32],
    dictionary: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ContextError> {
    if is_sealed {
        return Err(ContextError::SealedContentForbidden);
    }
    if codec_id != CODEC_SHARED_CTX_FAST && codec_id != CODEC_SHARED_CTX_ARCHIVAL {
        return Err(ContextError::UnsupportedContextCodec(codec_id));
    }
    let orig_len_u32 = u32::try_from(plaintext.len())
        .map_err(|_| ContextError::MalformedWirePayload("input exceeds u32 bound"))?;

    let min_match = if codec_id == CODEC_SHARED_CTX_ARCHIVAL {
        MIN_CHUNK_MATCH_LEN
    } else {
        12
    };

    let mut out = Vec::with_capacity(41 + plaintext.len() / 2);
    out.extend_from_slice(CTX_WIRE_MAGIC);
    out.push(codec_id);
    out.extend_from_slice(&context_id);
    out.extend_from_slice(&orig_len_u32.to_le_bytes());

    let mut pos = 0usize;
    let mut lit_start = 0usize;

    while pos + min_match <= plaintext.len() {
        if let Some((dict_off, mlen)) = find_longest_dict_match(dictionary, &plaintext[pos..], min_match) {
            flush_literals(&mut out, &plaintext[lit_start..pos])?;
            out.push(0x01);
            let off_u32 = u32::try_from(dict_off)
                .map_err(|_| ContextError::MalformedWirePayload("dict offset overflow"))?;
            let len_u16 = u16::try_from(mlen)
                .map_err(|_| ContextError::MalformedWirePayload("match len overflow"))?;
            out.extend_from_slice(&off_u32.to_le_bytes());
            out.extend_from_slice(&len_u16.to_le_bytes());
            pos += mlen;
            lit_start = pos;
        } else {
            pos += 1;
        }
    }
    flush_literals(&mut out, &plaintext[lit_start..])?;

    if codec_id == CODEC_SHARED_CTX_ARCHIVAL && tier != AccessTier::Cold && !plaintext.is_empty() {
        let savings_bps = if out.len() < plaintext.len() {
            let saved = u64::try_from(plaintext.len() - out.len()).unwrap_or(0);
            let total = u64::try_from(plaintext.len()).unwrap_or(1);
            u32::try_from(saved.saturating_mul(10_000) / total).unwrap_or(0)
        } else {
            0
        };
        if savings_bps < ARCHIVAL_CTX_SAVINGS_FLOOR_BPS {
            return Err(ContextError::ArchivalCodecRequiresColdOrFloor { savings_bps });
        }
    }

    Ok(out)
}

/// Deterministic bounded decoder for `BCX1` shared-context payloads (`Codecs 12 & 13`).
/// Convenience: exposed for B.U.D. 3.0 view and replacement verification paths.
///
/// # Errors
///
/// Returns [`ContextError`] if the header, op stream, dictionary slice, or decoded length is invalid.
pub fn decode_with_shared_context(
    wire: &[u8],
    cache: &LocalContextCache,
) -> Result<Vec<u8>, ContextError> {
    if wire.len() < 41 {
        return Err(ContextError::MalformedWirePayload("truncated BCX1 header"));
    }
    if &wire[0..4] != CTX_WIRE_MAGIC {
        return Err(ContextError::MalformedWirePayload("invalid BCX1 magic"));
    }
    let codec_id = wire[4];
    if codec_id != CODEC_SHARED_CTX_FAST && codec_id != CODEC_SHARED_CTX_ARCHIVAL {
        return Err(ContextError::UnsupportedContextCodec(codec_id));
    }
    let mut context_id = [0u8; 32];
    context_id.copy_from_slice(&wire[5..37]);
    let orig_len = usize::try_from(u32::from_le_bytes([wire[37], wire[38], wire[39], wire[40]]))
        .map_err(|_| ContextError::MalformedWirePayload("orig_len exceeds usize"))?;

    let dict = cache
        .get(&context_id)
        .ok_or(ContextError::MissingLocalContext(context_id))?;

    let mut out = Vec::with_capacity(orig_len.min(65_536));
    let mut cursor = 41usize;
    while cursor < wire.len() {
        let tag = wire[cursor];
        cursor += 1;
        match tag {
            0x00 => {
                let len_bytes = wire
                    .get(cursor..cursor + 2)
                    .ok_or(ContextError::MalformedWirePayload("truncated literal length"))?;
                let lit_len = usize::from(u16::from_le_bytes([len_bytes[0], len_bytes[1]]));
                cursor += 2;
                let slice = wire
                    .get(cursor..cursor + lit_len)
                    .ok_or(ContextError::MalformedWirePayload("truncated literal bytes"))?;
                if out.len().saturating_add(lit_len) > orig_len {
                    return Err(ContextError::MalformedWirePayload("decoded output exceeds orig_len"));
                }
                out.extend_from_slice(slice);
                cursor += lit_len;
            }
            0x01 => {
                let hdr = wire
                    .get(cursor..cursor + 6)
                    .ok_or(ContextError::MalformedWirePayload("truncated dict match op"))?;
                let off = usize::try_from(u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]))
                    .map_err(|_| ContextError::MalformedWirePayload("offset exceeds usize"))?;
                let mlen = usize::from(u16::from_le_bytes([hdr[4], hdr[5]]));
                cursor += 6;
                let slice = dict
                    .get(off..off.saturating_add(mlen))
                    .ok_or(ContextError::MalformedWirePayload("dict reference out of bounds"))?;
                if out.len().saturating_add(mlen) > orig_len {
                    return Err(ContextError::MalformedWirePayload("decoded output exceeds orig_len"));
                }
                out.extend_from_slice(slice);
            }
            _ => return Err(ContextError::MalformedWirePayload("unknown BCX1 opcode")),
        }
    }

    if out.len() != orig_len {
        return Err(ContextError::MalformedWirePayload("decoded length mismatch"));
    }
    Ok(out)
}

fn flush_literals(out: &mut Vec<u8>, mut literals: &[u8]) -> Result<(), ContextError> {
    while !literals.is_empty() {
        let chunk_len = literals.len().min(usize::from(u16::MAX));
        let len_u16 = u16::try_from(chunk_len)
            .map_err(|_| ContextError::MalformedWirePayload("literal chunk overflow"))?;
        out.push(0x00);
        out.extend_from_slice(&len_u16.to_le_bytes());
        out.extend_from_slice(&literals[..chunk_len]);
        literals = &literals[chunk_len..];
    }
    Ok(())
}

fn find_longest_dict_match(dict: &[u8], target: &[u8], min_match: usize) -> Option<(usize, usize)> {
    if dict.len() < min_match || target.len() < min_match {
        return None;
    }
    let max_cap = target.len().min(usize::from(u16::MAX));
    let probe = &target[..min_match];
    let mut best: Option<(usize, usize)> = None;
    let mut search_from = 0usize;
    while search_from + min_match <= dict.len() {
        let Some(rel) = dict[search_from..].windows(min_match).position(|w| w == probe) else {
            break;
        };
        let off = search_from + rel;
        let limit = (dict.len() - off).min(max_cap);
        let mut mlen = min_match;
        while mlen < limit && dict[off + mlen] == target[mlen] {
            mlen += 1;
        }
        if best.is_none_or(|(_, b)| mlen > b) {
            best = Some((off, mlen));
        }
        search_from = off + 1;
    }
    best
}

/// Dependent public object bound under an NFT whose payload uses a shared context (`Section 6.20.2.2`).
/// Convenience: exposed for context rotation re-encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependentContextObject {
    pub nft_token_id: [u8; 32],
    pub content_id: ContentId,
    pub object_commitment: [u8; 32],
    pub context_id: [u8; 32],
    pub wire_payload: Vec<u8>,
}

/// Stateful coordinator for corpus membership, burned-corpus eviction, and context rotation (`Section 6.20.2`).
/// Convenience: exposed for expansion-tier storage maintenance.
#[derive(Debug, Clone)]
pub struct SharedContextEngine {
    pub enabled: bool,
    pub manifest: ContextManifest,
    pub cache: LocalContextCache,
    pub corpus_payloads: BTreeMap<ObjectKey, Vec<u8>>,
    pub burned_corpus: BTreeSet<ObjectKey>,
    pub pool: ContextMaintenancePool,
}

impl SharedContextEngine {
    /// Construct a new shared-context engine for `class_tag`.
    /// Convenience: exposed for expansion activation and tests.
    ///
    /// # Errors
    ///
    /// Propagates any manifest verification failure.
    pub fn new(
        enabled: bool,
        class_tag: String,
        corpus_payloads: BTreeMap<ObjectKey, Vec<u8>>,
        epoch: u64,
    ) -> Result<Self, ContextError> {
        let dict_bytes = materialize_dictionary(&corpus_payloads, &BTreeSet::new());
        let keys: Vec<ObjectKey> = corpus_payloads.keys().copied().collect();
        let manifest = ContextManifest::new(class_tag, 1, keys, &dict_bytes, epoch);
        let mut cache = LocalContextCache::default();
        cache.insert_verified(&manifest, dict_bytes)?;
        Ok(Self {
            enabled,
            manifest,
            cache,
            corpus_payloads,
            burned_corpus: BTreeSet::new(),
            pool: ContextMaintenancePool::default(),
        })
    }

    /// Register a public object into the corpus candidate set (`Section 6.20.2.2`).
    /// Convenience: exposed for public upload corpus registration.
    ///
    /// # Errors
    ///
    /// Refuses sealed objects (`ContextError::SealedContentForbidden`).
    pub fn register_corpus_candidate(
        &mut self,
        object_key: ObjectKey,
        is_sealed: bool,
        plaintext: Vec<u8>,
    ) -> Result<(), ContextError> {
        if !self.enabled {
            return Err(ContextError::ContextDisabled);
        }
        if is_sealed {
            return Err(ContextError::SealedContentForbidden);
        }
        self.corpus_payloads.insert(object_key, plaintext);
        Ok(())
    }

    /// Mark a corpus object as burned so the next [`Self::rotate_context`] evicts it (`Section 6.20.2.2`).
    /// Convenience: exposed for social/full delete notifications.
    pub fn mark_corpus_burned(&mut self, object_key: ObjectKey) {
        self.burned_corpus.insert(object_key);
    }

    /// Rotate context generation: evict all burned corpus objects, publish the next
    /// [`ContextManifest`], and re-encode dependent objects under their NFTs without
    /// changing [`ContentId`] (`Section 6.20.2.2`).
    /// Convenience: exposed for epoch context refresh.
    ///
    /// # Errors
    ///
    /// Propagates decode/encode errors if local cache state is inconsistent.
    pub fn rotate_context(
        &mut self,
        epoch: u64,
        dependents: &mut [DependentContextObject],
    ) -> Result<ContextManifest, ContextError> {
        if !self.enabled {
            return Err(ContextError::ContextDisabled);
        }
        for burned in &self.burned_corpus {
            self.corpus_payloads.remove(burned);
        }
        self.burned_corpus.clear();

        let next_gen = self.manifest.generation.saturating_add(1);
        let dict_bytes = materialize_dictionary(&self.corpus_payloads, &self.burned_corpus);
        let keys: Vec<ObjectKey> = self.corpus_payloads.keys().copied().collect();
        let next_manifest = ContextManifest::new(
            self.manifest.class_tag.clone(),
            next_gen,
            keys,
            &dict_bytes,
            epoch,
        );
        self.cache.insert_verified(&next_manifest, dict_bytes.clone())?;

        for dep in dependents.iter_mut() {
            let recovered = decode_with_shared_context(&dep.wire_payload, &self.cache)?;
            let recomputed_cid = ContentId::public(&recovered);
            if recomputed_cid != dep.content_id {
                return Err(ContextError::MalformedWirePayload(
                    "dependent ContentId diverged during rotation",
                ));
            }
            let new_wire = encode_with_shared_context(
                CODEC_SHARED_CTX_FAST,
                false,
                AccessTier::Normal,
                next_manifest.context_id,
                &dict_bytes,
                &recovered,
            )?;
            dep.object_commitment = hash_fields_bytes(&[
                b"budlum/bud3/ctx-replaced-obj/v1",
                &next_manifest.context_id,
                &new_wire,
            ]);
            dep.context_id = next_manifest.context_id;
            dep.wire_payload = new_wire;
        }

        self.manifest = next_manifest.clone();
        Ok(next_manifest)
    }
}

fn materialize_dictionary(
    corpus: &BTreeMap<ObjectKey, Vec<u8>>,
    burned: &BTreeSet<ObjectKey>,
) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, payload) in corpus {
        if !burned.contains(key) {
            out.extend_from_slice(payload);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_corpus() -> BTreeMap<ObjectKey, Vec<u8>> {
        let mut m = BTreeMap::new();
        m.insert(
            [0x11u8; 32],
            b"{\"schema\":\"budlum.v3.record\",\"network\":\"budlum-mainnet\",\"status\":\"finalized\",\"validator_class\":\"Mobile\"}".to_vec(),
        );
        m.insert(
            [0x22u8; 32],
            b"{\"schema\":\"budlum.v3.audit\",\"custody_window_hours\":24,\"encoding\":\"RFC6330-RaptorQ\"}".to_vec(),
        );
        m
    }

    #[test]
    fn bud3_context_codec_vectors() {
        assert!(!TESTNET_CONTEXT_ENABLED_BY_DEFAULT);
        let engine = SharedContextEngine::new(true, "json-records".to_owned(), sample_corpus(), 10)
            .unwrap();
        assert!(engine.manifest.verify_id());
        let dict = engine.cache.get(&engine.manifest.context_id).unwrap();

        let msg = b"{\"schema\":\"budlum.v3.record\",\"network\":\"budlum-mainnet\",\"status\":\"finalized\",\"seq\":42}";
        let wire12 = encode_with_shared_context(
            CODEC_SHARED_CTX_FAST,
            false,
            AccessTier::Normal,
            engine.manifest.context_id,
            dict,
            msg,
        )
        .unwrap();
        assert!(wire12.len() < msg.len());
        let round12 = decode_with_shared_context(&wire12, &engine.cache).unwrap();
        assert_eq!(round12, msg);

        // Sealed content is strictly refused on both context codecs (Section 6.20.2.3).
        let sealed_err = encode_with_shared_context(
            CODEC_SHARED_CTX_FAST,
            true,
            AccessTier::Normal,
            engine.manifest.context_id,
            dict,
            msg,
        )
        .unwrap_err();
        assert_eq!(sealed_err, ContextError::SealedContentForbidden);

        // Codec 13 without Y savings floor fails on Hot/Normal but succeeds on Cold (Section 6.20.2.4).
        let low_overlap = b"completely-unrelated-payload-with-zero-dictionary-overlap-0123456789";
        assert!(matches!(
            encode_with_shared_context(
                CODEC_SHARED_CTX_ARCHIVAL,
                false,
                AccessTier::Normal,
                engine.manifest.context_id,
                dict,
                low_overlap,
            ),
            Err(ContextError::ArchivalCodecRequiresColdOrFloor { .. })
        ));
        let cold_wire13 = encode_with_shared_context(
            CODEC_SHARED_CTX_ARCHIVAL,
            false,
            AccessTier::Cold,
            engine.manifest.context_id,
            dict,
            low_overlap,
        )
        .unwrap();
        assert_eq!(
            decode_with_shared_context(&cold_wire13, &engine.cache).unwrap(),
            low_overlap
        );
    }

    #[test]
    fn bud3_context_rotation_keeps_content_id() {
        let mut engine =
            SharedContextEngine::new(true, "json-records".to_owned(), sample_corpus(), 1).unwrap();
        let dict = engine.cache.get(&engine.manifest.context_id).unwrap().to_vec();

        let payload = b"{\"schema\":\"budlum.v3.record\",\"network\":\"budlum-mainnet\",\"item\":\"alpha\"}";
        let cid_before = ContentId::public(payload);
        let wire_gen1 = encode_with_shared_context(
            CODEC_SHARED_CTX_FAST,
            false,
            AccessTier::Normal,
            engine.manifest.context_id,
            &dict,
            payload,
        )
        .unwrap();

        let mut deps = vec![DependentContextObject {
            nft_token_id: [0x99u8; 32],
            content_id: cid_before,
            object_commitment: [0xAAu8; 32],
            context_id: engine.manifest.context_id,
            wire_payload: wire_gen1,
        }];

        engine
            .register_corpus_candidate([0x33u8; 32], false, b"\"item\":\"alpha\"".to_vec())
            .unwrap();
        let manifest_gen2 = engine.rotate_context(2, &mut deps).unwrap();
        assert_eq!(manifest_gen2.generation, 2);
        assert_eq!(deps[0].content_id, cid_before);
        assert_eq!(deps[0].context_id, manifest_gen2.context_id);
        assert_ne!(deps[0].object_commitment, [0xAAu8; 32]);
        assert_eq!(
            decode_with_shared_context(&deps[0].wire_payload, &engine.cache).unwrap(),
            payload
        );
    }

    #[test]
    fn bud3_context_burned_corpus_leaves() {
        let mut engine =
            SharedContextEngine::new(true, "json-records".to_owned(), sample_corpus(), 1).unwrap();
        assert!(engine.manifest.corpus_objects.contains(&[0x11u8; 32]));

        engine.mark_corpus_burned([0x11u8; 32]);
        let mut deps = Vec::new();
        let next = engine.rotate_context(2, &mut deps).unwrap();
        assert!(!next.corpus_objects.contains(&[0x11u8; 32]));
        assert!(next.corpus_objects.contains(&[0x22u8; 32]));
    }

    #[test]
    fn bud3_context_fee_goes_to_pool() {
        let mut pool = ContextMaintenancePool::default();
        let fee = compute_context_savings_fee(10_000, 4_000, false);
        assert_eq!(fee, 1_200);
        pool.credit_context_fee(fee);
        assert_eq!(pool.balance_atoms, 1_200);

        // Exact deduplication match pays zero extra fee (Section 6.20.2.5).
        let exact_match_fee = compute_context_savings_fee(10_000, 4_000, true);
        assert_eq!(exact_match_fee, 0);
    }
}
