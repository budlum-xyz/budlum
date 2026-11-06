//! WP-54 domain-specific reversible transforms (Codecs 3, 15, 18, 19),
//! immutable shared `CompressionContext` lifecycle, and convergent cross-owner
//! private deduplication envelopes.

use std::collections::BTreeMap;
use std::io::Write;

use crate::{decode, CodecError, STORE_LEVEL, ZSTD, ZSTD_WINDOW_LOG};

/// Maximum object size eligible for small-object context compression (Codec 3: 16 KiB).
pub const SMALL_OBJECT_MAX_BYTES: usize = 16 * 1024;

/// Lifecycle state of an immutable shared [`CompressionContext`] (WP-54 Step 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextStatus {
    /// Open for both new object writes and historical reads.
    Active,
    /// Closed to new object writes; historical objects still decode.
    Deprecated,
    /// Retired once `ref_count == 0`; never mutated or reused.
    Retired,
}

/// Immutable registered compression dictionary / context (WP-54 Step 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionContext {
    pub context_id: u32,
    pub domain_class: String,
    pub dict_bytes: Vec<u8>,
    pub dict_tag: [u8; 32],
    pub status: ContextStatus,
    pub ref_count: u64,
}

/// Deterministic 32-byte keyed mix (pure Rust, std-only, domain-separated).
fn derive_tag(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut state: [u64; 4] = [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
    ];
    for (idx, byte) in domain
        .iter()
        .chain([&0xFFu8])
        .chain(payload.iter())
        .enumerate()
    {
        let lane = idx & 3;
        state[lane] = state[lane]
            .wrapping_add(u64::from(*byte).wrapping_mul(0x9e37_79b9_7f4a_7c15))
            .rotate_left(13);
        let next = (lane + 1) & 3;
        state[next] ^= state[lane].wrapping_mul(0xbf58_476d_1ce4_e5b9);
    }
    for _ in 0..8 {
        for lane in 0..4 {
            let prev = (lane + 3) & 3;
            state[lane] = state[lane]
                .wrapping_add(state[prev])
                .wrapping_mul(0x94d0_49bb_1331_11eb)
                .rotate_left(17);
        }
    }
    let mut out = [0u8; 32];
    for (lane, word) in state.iter().enumerate() {
        out[lane * 8..(lane + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn zstd_compress(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut enc = zstd::stream::Encoder::new(Vec::new(), STORE_LEVEL)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.long_distance_matching(true)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.window_log(ZSTD_WINDOW_LOG)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.include_checksum(false)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.write_all(bytes)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.finish().map_err(|e| CodecError::Encode(e.to_string()))
}

/// Registry of immutable shared [`CompressionContext`] entries (WP-54 Steps 10-12).
#[derive(Debug, Default, Clone)]
pub struct ContextRegistry {
    contexts: BTreeMap<u32, CompressionContext>,
}

impl ContextRegistry {
    /// Register an immutable context; refuses empty dictionaries or duplicate IDs.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::Encode`] if `dict_bytes` is empty or `context_id` exists.
    pub fn register(
        &mut self,
        context_id: u32,
        domain_class: &str,
        dict_bytes: Vec<u8>,
    ) -> Result<[u8; 32], CodecError> {
        if dict_bytes.is_empty() || self.contexts.contains_key(&context_id) {
            return Err(CodecError::Encode(String::from(
                "invalid or duplicate CompressionContext",
            )));
        }
        let dict_tag = derive_tag(b"budlum/codec/context/v1", &dict_bytes);
        self.contexts.insert(
            context_id,
            CompressionContext {
                context_id,
                domain_class: String::from(domain_class),
                dict_bytes,
                dict_tag,
                status: ContextStatus::Active,
                ref_count: 0,
            },
        );
        Ok(dict_tag)
    }

    /// Deprecate a context so no new objects may bind to it (WP-54 Step 10).
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::Malformed`] if `context_id` is unknown.
    pub fn deprecate(&mut self, context_id: u32) -> Result<(), CodecError> {
        let ctx = self
            .contexts
            .get_mut(&context_id)
            .ok_or_else(|| CodecError::Malformed(String::from("unknown context_id")))?;
        if ctx.status == ContextStatus::Active {
            ctx.status = ContextStatus::Deprecated;
        }
        Ok(())
    }

    /// Retire a deprecated context once `ref_count == 0` (WP-54 Step 10).
    ///
    /// # Errors
    ///
    /// Refuses retirement while `ref_count > 0`.
    pub fn retire(&mut self, context_id: u32) -> Result<(), CodecError> {
        let ctx = self
            .contexts
            .get_mut(&context_id)
            .ok_or_else(|| CodecError::Malformed(String::from("unknown context_id")))?;
        if ctx.ref_count != 0 {
            return Err(CodecError::Encode(String::from(
                "cannot retire context while ref_count > 0",
            )));
        }
        ctx.status = ContextStatus::Retired;
        Ok(())
    }

    /// Encode a `< 16 KiB` object against an `Active` context (Codec 3, WP-54 Step 4).
    ///
    /// Prepends the immutable dictionary inside the compression window, compresses
    /// with `zstd`, and strips the known dictionary prefix on decode via `ruzstd`.
    ///
    /// # Errors
    ///
    /// Refuses objects `>= 16 KiB` or non-`Active` contexts.
    pub fn encode_small_with_context(
        &mut self,
        context_id: u32,
        content: &[u8],
    ) -> Result<Vec<u8>, CodecError> {
        if content.len() >= SMALL_OBJECT_MAX_BYTES {
            return Err(CodecError::TooLong {
                max: u64::try_from(SMALL_OBJECT_MAX_BYTES).unwrap_or(16_384),
            });
        }
        let ctx = self
            .contexts
            .get_mut(&context_id)
            .ok_or_else(|| CodecError::Malformed(String::from("unknown context_id")))?;
        if ctx.status != ContextStatus::Active {
            return Err(CodecError::Encode(String::from(
                "context is not Active for new writes",
            )));
        }
        let mut combined = Vec::with_capacity(ctx.dict_bytes.len() + content.len());
        combined.extend_from_slice(&ctx.dict_bytes);
        combined.extend_from_slice(content);
        let compressed = zstd_compress(&combined)?;
        ctx.ref_count = ctx.ref_count.saturating_add(1);
        Ok(compressed)
    }

    /// Decode a Codec 3 payload using the pinned `context_id` (`ruzstd` pure-Rust).
    ///
    /// # Errors
    ///
    /// Fails if `context_id` is unknown or the dictionary prefix was altered.
    pub fn decode_small_with_context(
        &self,
        context_id: u32,
        payload: &[u8],
        content_len: usize,
    ) -> Result<Vec<u8>, CodecError> {
        let ctx = self
            .contexts
            .get(&context_id)
            .ok_or_else(|| CodecError::Malformed(String::from("unknown context_id")))?;
        let total = ctx
            .dict_bytes
            .len()
            .checked_add(content_len)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(CodecError::TooLong { max: u64::MAX })?;
        let combined = decode(ZSTD, payload, total)?;
        if !combined.starts_with(&ctx.dict_bytes) {
            return Err(CodecError::Malformed(String::from(
                "context prefix mismatch",
            )));
        }
        Ok(combined[ctx.dict_bytes.len()..].to_vec())
    }
}

/// Codec 15: lossless `(timestamp_u64, value_bits_u64)` delta + XOR + zstd encode.
///
/// # Errors
///
/// Refuses inputs whose byte length is not a multiple of 16.
pub fn encode_timeseries_delta_xor(raw_records: &[u8]) -> Result<Vec<u8>, CodecError> {
    if raw_records.len() % 16 != 0 {
        return Err(CodecError::Malformed(String::from(
            "timeseries input must be 16-byte (u64, u64) records",
        )));
    }
    let count = raw_records.len() / 16;
    let mut ts_deltas = Vec::with_capacity(count * 8);
    let mut val_xors = Vec::with_capacity(count * 8);
    let mut prev_ts = 0u64;
    let mut prev_val = 0u64;
    for chunk in raw_records.chunks_exact(16) {
        let mut ts_b = [0u8; 8];
        let mut val_b = [0u8; 8];
        ts_b.copy_from_slice(&chunk[0..8]);
        val_b.copy_from_slice(&chunk[8..16]);
        let ts = u64::from_le_bytes(ts_b);
        let val = u64::from_le_bytes(val_b);
        ts_deltas.extend_from_slice(&ts.wrapping_sub(prev_ts).to_le_bytes());
        val_xors.extend_from_slice(&(val ^ prev_val).to_le_bytes());
        prev_ts = ts;
        prev_val = val;
    }
    let mut planar = Vec::with_capacity(raw_records.len());
    planar.extend_from_slice(&ts_deltas);
    planar.extend_from_slice(&val_xors);
    zstd_compress(&planar)
}

/// Codec 15 pure-Rust `ruzstd` decoder: restores exact `(timestamp, value)` bytes.
///
/// # Errors
///
/// Fails if `content_len` is not a multiple of 16 or `ruzstd` rejects the frame.
pub fn decode_timeseries_delta_xor(
    payload: &[u8],
    content_len: usize,
) -> Result<Vec<u8>, CodecError> {
    if content_len % 16 != 0 {
        return Err(CodecError::Malformed(String::from(
            "timeseries content_len must be a multiple of 16",
        )));
    }
    let len_u64 = u64::try_from(content_len).map_err(|_| CodecError::TooLong { max: u64::MAX })?;
    let planar = decode(ZSTD, payload, len_u64)?;
    let half = content_len / 2;
    let (ts_stream, val_stream) = planar.split_at(half);
    let mut out = Vec::with_capacity(content_len);
    let mut prev_ts = 0u64;
    let mut prev_val = 0u64;
    for (td_b, vx_b) in ts_stream.chunks_exact(8).zip(val_stream.chunks_exact(8)) {
        let mut tb = [0u8; 8];
        let mut vb = [0u8; 8];
        tb.copy_from_slice(td_b);
        vb.copy_from_slice(vx_b);
        prev_ts = prev_ts.wrapping_add(u64::from_le_bytes(tb));
        prev_val ^= u64::from_le_bytes(vb);
        out.extend_from_slice(&prev_ts.to_le_bytes());
        out.extend_from_slice(&prev_val.to_le_bytes());
    }
    Ok(out)
}

/// Codec 18: page XOR delta + zstd against an equal-length base page image.
///
/// # Errors
///
/// Fails when `base.len() != current.len()`.
pub fn encode_page_xor_delta(base: &[u8], current: &[u8]) -> Result<Vec<u8>, CodecError> {
    if base.len() != current.len() {
        return Err(CodecError::Malformed(String::from(
            "base and current page lengths differ",
        )));
    }
    let xor_bytes: Vec<u8> = base.iter().zip(current.iter()).map(|(a, b)| a ^ b).collect();
    zstd_compress(&xor_bytes)
}

/// Codec 18 pure-Rust `ruzstd` decoder: reconstructs `current` from `base` and delta.
///
/// # Errors
///
/// Fails on malformed zstd payload or length mismatch.
pub fn decode_page_xor_delta(base: &[u8], payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    let want = u64::try_from(base.len()).map_err(|_| CodecError::TooLong { max: u64::MAX })?;
    let xor_bytes = decode(ZSTD, payload, want)?;
    Ok(base
        .iter()
        .zip(xor_bytes.iter())
        .map(|(a, b)| a ^ b)
        .collect())
}

/// Codec 19: FP32 exponent/sign-mantissa planar split + zstd (model weights).
///
/// # Errors
///
/// Refuses inputs whose byte length is not a multiple of 4.
pub fn encode_fp32_exponent_split(weights_le: &[u8]) -> Result<Vec<u8>, CodecError> {
    if weights_le.len() % 4 != 0 {
        return Err(CodecError::Malformed(String::from(
            "FP32 byte stream length must be a multiple of 4",
        )));
    }
    let count = weights_le.len() / 4;
    let mut exponents = Vec::with_capacity(count);
    let mut sign_mantissas = Vec::with_capacity(count * 3);
    for word_bytes in weights_le.chunks_exact(4) {
        let mut b = [0u8; 4];
        b.copy_from_slice(word_bytes);
        let bits = u32::from_le_bytes(b);
        let exp = u8::try_from((bits >> 23) & 0xFF).unwrap_or(0);
        let sm = ((bits >> 8) & 0x0080_0000) | (bits & 0x007F_FFFF);
        let sm_le = sm.to_le_bytes();
        exponents.push(exp);
        sign_mantissas.extend_from_slice(&sm_le[0..3]);
    }
    let mut planar = Vec::with_capacity(weights_le.len());
    planar.extend_from_slice(&exponents);
    planar.extend_from_slice(&sign_mantissas);
    zstd_compress(&planar)
}

/// Codec 19 pure-Rust `ruzstd` decoder: restores exact IEEE-754 little-endian FP32 bytes.
///
/// # Errors
///
/// Fails if `content_len` is not a multiple of 4 or `ruzstd` rejects the payload.
pub fn decode_fp32_exponent_split(
    payload: &[u8],
    content_len: usize,
) -> Result<Vec<u8>, CodecError> {
    if content_len % 4 != 0 {
        return Err(CodecError::Malformed(String::from(
            "FP32 content_len must be a multiple of 4",
        )));
    }
    let want = u64::try_from(content_len).map_err(|_| CodecError::TooLong { max: u64::MAX })?;
    let planar = decode(ZSTD, payload, want)?;
    let count = content_len / 4;
    let (exponents, sign_mantissas) = planar.split_at(count);
    let mut out = Vec::with_capacity(content_len);
    for (exp, sm3) in exponents.iter().zip(sign_mantissas.chunks_exact(3)) {
        let sm = u32::from_le_bytes([sm3[0], sm3[1], sm3[2], 0]);
        let sign = (sm & 0x0080_0000) << 8;
        let mantissa = sm & 0x007F_FFFF;
        let bits = sign | (u32::from(*exp) << 23) | mantissa;
        out.extend_from_slice(&bits.to_le_bytes());
    }
    Ok(out)
}

/// Per-owner wrapped content key inside a convergent private dedup envelope (WP-54 Step 13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKeyWrap {
    pub owner_id: [u8; 32],
    pub wrapped_key: [u8; 32],
}

#[derive(Debug, Clone)]
struct SharedCipherRecord {
    ciphertext: Vec<u8>,
    auth_tag: [u8; 32],
    wraps: BTreeMap<[u8; 32], OwnerKeyWrap>,
}

/// Convergent private deduplication store (WP-54 Steps 13-15).
///
/// When `convergent_mode == true`, `k_content` is derived deterministically from
/// the plaintext digest so identical content across distinct owners stores a
/// single ciphertext with independent `OwnerKeyWrap` entries and explicit
/// reference counting (`ref_count == wraps.len()`). When `convergent_mode == false`,
/// dedup is bypassed completely to prevent confirmation attacks on low-entropy
/// secrets.
#[derive(Debug, Default, Clone)]
pub struct ConvergentDedupStore {
    shared: BTreeMap<[u8; 32], SharedCipherRecord>,
    isolated: Vec<(Vec<u8>, [u8; 32])>,
}

fn xor_keystream(key: &[u8; 32], input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for (chunk_idx, chunk) in input.chunks(32).enumerate() {
        let idx_bytes = (chunk_idx as u64).to_le_bytes();
        let mut seed = [0u8; 40];
        seed[0..32].copy_from_slice(key);
        seed[32..40].copy_from_slice(&idx_bytes);
        let block = derive_tag(b"budlum/codec/convergent-stream/v1", &seed);
        for (b, k) in chunk.iter().zip(block.iter()) {
            out.push(b ^ k);
        }
    }
    out
}

impl ConvergentDedupStore {
    /// Store `plaintext` for `owner_id` using `owner_secret`.
    ///
    /// Returns `(envelope_id, ref_count)` when `convergent_mode == true`, or
    /// `(random_like_id, 1)` in isolated mode (`convergent_mode == false`).
    #[must_use]
    pub fn put(
        &mut self,
        owner_id: [u8; 32],
        owner_secret: [u8; 32],
        plaintext: &[u8],
        convergent_mode: bool,
    ) -> ([u8; 32], usize) {
        let compressed = zstd_compress(plaintext).unwrap_or_else(|_| plaintext.to_vec());
        if !convergent_mode {
            let mut nonce_material = Vec::with_capacity(64 + compressed.len());
            nonce_material.extend_from_slice(&owner_id);
            nonce_material.extend_from_slice(&owner_secret);
            nonce_material.extend_from_slice(&(self.isolated.len() as u64).to_le_bytes());
            let k_isolated = derive_tag(b"budlum/codec/isolated-key/v1", &nonce_material);
            let ct = xor_keystream(&k_isolated, &compressed);
            let id = derive_tag(b"budlum/codec/isolated-id/v1", &ct);
            self.isolated.push((ct, id));
            return (id, 1);
        }

        let content_digest = derive_tag(b"budlum/codec/content-digest/v1", plaintext);
        let k_content = derive_tag(b"budlum/codec/convergent-key/v1", &content_digest);
        let mask = derive_tag(b"budlum/codec/owner-wrap/v1", &owner_secret);
        let mut wrapped_key = [0u8; 32];
        for ((dst, kc), mk) in wrapped_key.iter_mut().zip(&k_content).zip(&mask) {
            *dst = kc ^ mk;
        }

        let entry = self.shared.entry(content_digest).or_insert_with(|| {
            let ciphertext = xor_keystream(&k_content, &compressed);
            let auth_tag = derive_tag(b"budlum/codec/convergent-auth/v1", &ciphertext);
            SharedCipherRecord {
                ciphertext,
                auth_tag,
                wraps: BTreeMap::new(),
            }
        });
        entry.wraps.insert(
            owner_id,
            OwnerKeyWrap {
                owner_id,
                wrapped_key,
            },
        );
        (content_digest, entry.wraps.len())
    }

    /// Number of unique convergent ciphertexts stored across all owners.
    #[must_use]
    pub fn shared_ciphertext_count(&self) -> usize {
        self.shared.len()
    }

    /// Remove `owner_id`'s key wrap; drops the shared ciphertext only when `ref_count == 0`.
    #[must_use]
    pub fn release_owner(&mut self, envelope_id: &[u8; 32], owner_id: &[u8; 32]) -> usize {
        let Some(rec) = self.shared.get_mut(envelope_id) else {
            return 0;
        };
        rec.wraps.remove(owner_id);
        let remaining = rec.wraps.len();
        if remaining == 0 {
            self.shared.remove(envelope_id);
        }
        remaining
    }

    /// Unwrap `k_content` for `owner_id` and recover the verified plaintext.
    ///
    /// # Errors
    ///
    /// Fails if `owner_id` has no wrap, `owner_secret` is wrong, or ciphertext was tampered.
    pub fn open(
        &self,
        envelope_id: &[u8; 32],
        owner_id: &[u8; 32],
        owner_secret: &[u8; 32],
        plaintext_len: usize,
    ) -> Result<Vec<u8>, CodecError> {
        let rec = self
            .shared
            .get(envelope_id)
            .ok_or_else(|| CodecError::Malformed(String::from("unknown envelope_id")))?;
        let wrap = rec
            .wraps
            .get(owner_id)
            .ok_or_else(|| CodecError::Malformed(String::from("owner wrap absent")))?;
        if derive_tag(b"budlum/codec/convergent-auth/v1", &rec.ciphertext) != rec.auth_tag {
            return Err(CodecError::Malformed(String::from(
                "convergent auth_tag mismatch",
            )));
        }
        let mask = derive_tag(b"budlum/codec/owner-wrap/v1", owner_secret);
        let mut k_content = [0u8; 32];
        for ((dst, wk), mk) in k_content.iter_mut().zip(&wrap.wrapped_key).zip(&mask) {
            *dst = wk ^ mk;
        }
        let compressed = xor_keystream(&k_content, &rec.ciphertext);
        let want = u64::try_from(plaintext_len).map_err(|_| CodecError::TooLong { max: u64::MAX })?;
        let decoded = decode(ZSTD, &compressed, want)?;
        if derive_tag(b"budlum/codec/content-digest/v1", &decoded) != *envelope_id {
            return Err(CodecError::Malformed(String::from(
                "wrong owner key or corrupted convergent content",
            )));
        }
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_lifecycle_and_small_object_roundtrip() -> Result<(), CodecError> {
        let mut reg = ContextRegistry::default();
        let dict =
            br#"{"schema":"v1","network":"mainnet","status":"finalized","kind":"#.repeat(16);
        reg.register(1, "json-small", dict)?;

        let doc =
            br#"{"schema":"v1","network":"mainnet","status":"finalized","kind":"receipt","id":42}"#;
        let encoded = reg.encode_small_with_context(1, doc)?;
        assert!(encoded.len() < doc.len());
        let decoded = reg.decode_small_with_context(1, &encoded, doc.len())?;
        assert_eq!(decoded, doc);

        // Deprecated contexts refuse new writes while existing payloads still decode.
        reg.deprecate(1)?;
        assert!(reg.encode_small_with_context(1, doc).is_err());
        assert_eq!(reg.decode_small_with_context(1, &encoded, doc.len())?, doc);
        // Retirement is refused while ref_count > 0.
        assert!(reg.retire(1).is_err());
        Ok(())
    }

    #[test]
    fn timeseries_page_xor_and_fp32_exponent_split_roundtrip() -> Result<(), CodecError> {
        // Codec 15: 64 monotonic telemetry samples.
        let mut ts_raw = Vec::with_capacity(64 * 16);
        for i in 0u64..64 {
            ts_raw.extend_from_slice(&(1_700_000_000_000 + i * 1_000).to_le_bytes());
            ts_raw.extend_from_slice(&(42.5_f64.to_bits() ^ (i & 3)).to_le_bytes());
        }
        let ts_enc = encode_timeseries_delta_xor(&ts_raw)?;
        assert!(ts_enc.len() < ts_raw.len());
        assert_eq!(decode_timeseries_delta_xor(&ts_enc, ts_raw.len())?, ts_raw);

        // Codec 18: 4 KiB database page with 2-byte update.
        let base_page = vec![0xA5u8; 4096];
        let mut next_page = base_page.clone();
        next_page[128] = 0x11;
        next_page[129] = 0x22;
        let page_delta = encode_page_xor_delta(&base_page, &next_page)?;
        assert!(page_delta.len() < 64);
        assert_eq!(decode_page_xor_delta(&base_page, &page_delta)?, next_page);

        // Codec 19: 256 normalized FP32 weights around [0.125, 0.25).
        let mut weights = Vec::with_capacity(256 * 4);
        for i in 0u16..256 {
            let val = 0.125_f32 + f32::from(i) * 0.000_1_f32;
            weights.extend_from_slice(&val.to_le_bytes());
        }
        let fp_enc = encode_fp32_exponent_split(&weights)?;
        assert!(fp_enc.len() < weights.len());
        assert_eq!(decode_fp32_exponent_split(&fp_enc, weights.len())?, weights);
        Ok(())
    }

    #[test]
    fn convergent_cross_owner_dedup_keeps_payload_until_last_release() -> Result<(), CodecError> {
        let mut store = ConvergentDedupStore::default();
        let owner_a = [0x01; 32];
        let secret_a = [0xA1; 32];
        let owner_b = [0x02; 32];
        let secret_b = [0xB2; 32];
        let blob = b"identical large-entropy-safe structured archive payload ".repeat(16);

        let (env_a, refs_1) = store.put(owner_a, secret_a, &blob, true);
        let (env_b, refs_2) = store.put(owner_b, secret_b, &blob, true);
        assert_eq!(env_a, env_b);
        assert_eq!(refs_1, 1);
        assert_eq!(refs_2, 2);
        assert_eq!(store.shared_ciphertext_count(), 1);

        // Owner A releases -> ref_count drops 2 -> 1; Owner B still decrypts cleanly.
        assert_eq!(store.release_owner(&env_a, &owner_a), 1);
        assert!(store.open(&env_a, &owner_a, &secret_a, blob.len()).is_err());
        assert_eq!(store.open(&env_b, &owner_b, &secret_b, blob.len())?, blob);

        // Owner B releases -> ref_count drops 1 -> 0; shared ciphertext is collected.
        assert_eq!(store.release_owner(&env_b, &owner_b), 0);
        assert_eq!(store.shared_ciphertext_count(), 0);
        Ok(())
    }
}
