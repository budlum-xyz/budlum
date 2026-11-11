//! Domain-specific reversible transforms (Codecs 3, 15, 18, 19),
//! immutable shared `CompressionContext` lifecycle, and convergent cross-owner
//! private deduplication envelopes.
//! Convenience: exposed for workspace subcrate consumers, SDK bindings, and integration callers.

use std::collections::BTreeMap;
use std::io::Write;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{decode, CodecError, STORE_LEVEL, ZSTD, ZSTD_WINDOW_LOG};

type HmacSha256 = Hmac<Sha256>;

/// Maximum object size eligible for small-object context compression (Codec 3: 16 KiB).
pub const SMALL_OBJECT_MAX_BYTES: usize = 16 * 1024;

/// Lifecycle state of an immutable shared [`CompressionContext`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextStatus {
    /// Open for both new object writes and historical reads.
    Active,
    /// Closed to new object writes; historical objects still decode.
    Deprecated,
    /// Retired once `ref_count == 0`; never mutated or reused.
    Retired,
}

/// Immutable registered compression dictionary / context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionContext {
    pub context_id: u32,
    pub domain_class: String,
    pub dict_bytes: Vec<u8>,
    pub dict_tag: [u8; 32],
    pub status: ContextStatus,
    pub ref_count: u64,
}

fn sha256_domain(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain);
    h.update((payload.len() as u64).to_le_bytes());
    h.update(payload);
    h.finalize().into()
}

fn hmac_sha256(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> Result<[u8; 32], CodecError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| CodecError::Malformed(String::from("invalid HMAC key length")))?;
    mac.update(&(domain.len() as u64).to_le_bytes());
    mac.update(domain);
    mac.update(&(payload.len() as u64).to_le_bytes());
    mac.update(payload);
    Ok(mac.finalize().into_bytes().into())
}

fn hmac_verify(
    key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
    expected_tag: &[u8; 32],
) -> Result<(), CodecError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| CodecError::Malformed(String::from("invalid HMAC key length")))?;
    mac.update(&(domain.len() as u64).to_le_bytes());
    mac.update(domain);
    mac.update(&(payload.len() as u64).to_le_bytes());
    mac.update(payload);
    mac.verify_slice(expected_tag)
        .map_err(|_| CodecError::Malformed(String::from("convergent auth_tag mismatch")))
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

fn zstd_compress_small(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut enc = zstd::stream::Encoder::new(Vec::new(), STORE_LEVEL)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.include_checksum(false)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.write_all(bytes)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.finish().map_err(|e| CodecError::Encode(e.to_string()))
}

fn find_longest_dict_match(dict_bytes: &[u8], remaining: &[u8]) -> Option<(u32, u16)> {
    if remaining.len() < 4 || dict_bytes.len() < 4 {
        return None;
    }
    let max_dict = dict_bytes.len().min(u32::MAX as usize);
    let dict = dict_bytes.get(..max_dict).unwrap_or(dict_bytes);
    let prefix = remaining.get(..4)?;
    let max_match = remaining.len().min(usize::from(u16::MAX));
    let mut best_off = 0usize;
    let mut best_len = 0usize;
    let mut pos = 0usize;
    while pos + 4 <= dict.len() {
        let Some(rel) = dict
            .get(pos..)
            .unwrap_or(&[])
            .windows(4)
            .position(|w| w == prefix)
        else {
            break;
        };
        let cand = pos + rel;
        let limit = (dict.len() - cand).min(max_match);
        let mut mlen = 4usize;
        while mlen < limit && dict.get(cand + mlen) == remaining.get(mlen) {
            mlen += 1;
        }
        if mlen > best_len {
            best_off = cand;
            best_len = mlen;
            if best_len == max_match {
                break;
            }
        }
        pos = cand + 1;
    }
    if best_len >= 6 {
        let off = u32::try_from(best_off).ok()?;
        let len = u16::try_from(best_len).ok()?;
        Some((off, len))
    } else {
        None
    }
}

fn flush_literals(tokens: &mut Vec<u8>, literals: &mut Vec<u8>) -> Result<(), CodecError> {
    if literals.is_empty() {
        return Ok(());
    }
    let len = u16::try_from(literals.len())
        .map_err(|_| CodecError::Encode(String::from("literal run exceeds u16")))?;
    tokens.push(0x00);
    tokens.extend_from_slice(&len.to_le_bytes());
    tokens.extend_from_slice(literals);
    literals.clear();
    Ok(())
}

fn encode_with_shared_dict(dict_bytes: &[u8], content: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut tokens = Vec::with_capacity(content.len().saturating_add(8));
    let mut literals = Vec::new();
    let mut cursor = 0usize;
    while cursor < content.len() {
        let remaining = content.get(cursor..).unwrap_or(&[]);
        if let Some((off, len)) = find_longest_dict_match(dict_bytes, remaining) {
            flush_literals(&mut tokens, &mut literals)?;
            tokens.push(0x01);
            tokens.extend_from_slice(&off.to_le_bytes());
            tokens.extend_from_slice(&len.to_le_bytes());
            cursor = cursor.saturating_add(usize::from(len));
        } else if let Some(&b) = remaining.first() {
            literals.push(b);
            if literals.len() == usize::from(u16::MAX) {
                flush_literals(&mut tokens, &mut literals)?;
            }
            cursor += 1;
        } else {
            break;
        }
    }
    flush_literals(&mut tokens, &mut literals)?;
    let token_len = u32::try_from(tokens.len())
        .map_err(|_| CodecError::Encode(String::from("token stream exceeds u32")))?;
    let zstd_tokens = zstd_compress_small(&tokens)?;
    let mut out = Vec::with_capacity(4 + zstd_tokens.len());
    out.extend_from_slice(&token_len.to_le_bytes());
    out.extend_from_slice(&zstd_tokens);
    Ok(out)
}

fn decode_with_shared_dict(
    dict_bytes: &[u8],
    payload: &[u8],
    content_len: u64,
) -> Result<Vec<u8>, CodecError> {
    let header = payload
        .get(..4)
        .ok_or_else(|| CodecError::Malformed(String::from("missing Codec 3 token header")))?;
    let mut len_b = [0u8; 4];
    len_b.copy_from_slice(header);
    let token_len = u64::from(u32::from_le_bytes(len_b));
    let max_tokens = (SMALL_OBJECT_MAX_BYTES as u64)
        .saturating_mul(2)
        .saturating_add(16);
    if token_len > max_tokens {
        return Err(CodecError::TooLong { max: max_tokens });
    }
    let zstd_stream = payload.get(4..).unwrap_or(&[]);
    let tokens = decode(ZSTD, zstd_stream, token_len)?;
    let want =
        usize::try_from(content_len).map_err(|_| CodecError::TooLong { max: content_len })?;
    let mut out = Vec::with_capacity(want.min(SMALL_OBJECT_MAX_BYTES));
    let mut pos = 0usize;
    while pos < tokens.len() {
        let tag = *tokens
            .get(pos)
            .ok_or_else(|| CodecError::Malformed(String::from("truncated Codec 3 tag")))?;
        pos += 1;
        match tag {
            0x00 => {
                let lb = tokens
                    .get(pos..pos + 2)
                    .ok_or_else(|| CodecError::Malformed(String::from("truncated literal len")))?;
                let mut arr = [0u8; 2];
                arr.copy_from_slice(lb);
                let run_len = usize::from(u16::from_le_bytes(arr));
                pos += 2;
                let lit = tokens
                    .get(pos..pos + run_len)
                    .ok_or_else(|| CodecError::Malformed(String::from("truncated literal data")))?;
                if out.len().saturating_add(run_len) > want {
                    return Err(CodecError::TooLong { max: content_len });
                }
                out.extend_from_slice(lit);
                pos += run_len;
            }
            0x01 => {
                let hdr = tokens
                    .get(pos..pos + 6)
                    .ok_or_else(|| CodecError::Malformed(String::from("truncated dict ref")))?;
                let mut ob = [0u8; 4];
                let mut lb = [0u8; 2];
                if let Some(s) = hdr.get(..4) {
                    ob.copy_from_slice(s);
                }
                if let Some(s) = hdr.get(4..6) {
                    lb.copy_from_slice(s);
                }
                let off = usize::try_from(u32::from_le_bytes(ob))
                    .map_err(|_| CodecError::Malformed(String::from("dict offset overflow")))?;
                let mlen = usize::from(u16::from_le_bytes(lb));
                pos += 6;
                let end = off
                    .checked_add(mlen)
                    .ok_or_else(|| CodecError::Malformed(String::from("dict span overflow")))?;
                let slice = dict_bytes.get(off..end).ok_or_else(|| {
                    CodecError::Malformed(String::from("dict span out of bounds"))
                })?;
                if out.len().saturating_add(mlen) > want {
                    return Err(CodecError::TooLong { max: content_len });
                }
                out.extend_from_slice(slice);
            }
            _ => {
                return Err(CodecError::Malformed(String::from(
                    "unknown Codec 3 token tag",
                )));
            }
        }
    }
    let got = out.len() as u64;
    if got < content_len {
        return Err(CodecError::TooShort {
            want: content_len,
            got,
        });
    }
    Ok(out)
}

/// Registry of immutable shared [`CompressionContext`] entries.
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
        let dict_tag = sha256_domain(b"budlum/codec/context/v1", &dict_bytes);
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

    /// Deprecate a context so no new objects may bind to it.
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

    /// Retire a deprecated context once `ref_count == 0`.
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

    /// Encode a `< 16 KiB` object against an `Active` context (Codec 3).
    ///
    /// Uses RFC 8878 raw-content Zstd dictionary compression so the shared
    /// dictionary is referenced without embedding `dict_bytes` into every frame.
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
        let compressed = encode_with_shared_dict(&ctx.dict_bytes, content)?;
        ctx.ref_count = ctx.ref_count.saturating_add(1);
        Ok(compressed)
    }

    /// Decode a Codec 3 payload using the pinned `context_id` (`ruzstd` pure-Rust).
    ///
    /// # Errors
    ///
    /// Fails if `context_id` is unknown or the compressed stream is invalid.
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
        let want = u64::try_from(content_len).map_err(|_| CodecError::TooLong { max: u64::MAX })?;
        decode_with_shared_dict(&ctx.dict_bytes, payload, want)
    }
}

/// Codec 15: lossless `(timestamp_u64, value_bits_u64)` delta + XOR + zstd encode.
///
/// # Errors
///
/// Refuses inputs whose byte length is not a multiple of 16.
pub fn encode_timeseries_delta_xor(raw_records: &[u8]) -> Result<Vec<u8>, CodecError> {
    if !raw_records.len().is_multiple_of(16) {
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
        if let Some(s) = chunk.get(0..8) {
            ts_b.copy_from_slice(s);
        }
        if let Some(s) = chunk.get(8..16) {
            val_b.copy_from_slice(s);
        }
        let ts = u64::from_le_bytes(ts_b);
        let val = u64::from_le_bytes(val_b);
        let delta = ts.wrapping_sub(prev_ts);
        let xor_v = val ^ prev_val;
        ts_deltas.extend_from_slice(&delta.to_le_bytes());
        val_xors.extend_from_slice(&xor_v.to_le_bytes());
        prev_ts = ts;
        prev_val = val;
    }
    let mut planar = Vec::with_capacity(raw_records.len());
    planar.extend_from_slice(&ts_deltas);
    planar.extend_from_slice(&val_xors);
    zstd_compress(&planar)
}

/// Codec 15 pure-Rust `ruzstd` decoder: reconstructs exact raw `(u64, u64)` bytes.
///
/// # Errors
///
/// Fails if `content_len` is not a multiple of 16 or `ruzstd` rejects the payload.
pub fn decode_timeseries_delta_xor(
    payload: &[u8],
    content_len: usize,
) -> Result<Vec<u8>, CodecError> {
    if !content_len.is_multiple_of(16) {
        return Err(CodecError::Malformed(String::from(
            "timeseries content_len must be a multiple of 16",
        )));
    }
    let want = u64::try_from(content_len).map_err(|_| CodecError::TooLong { max: u64::MAX })?;
    let planar = decode(ZSTD, payload, want)?;
    let half = content_len / 2;
    let (ts_deltas, val_xors) = planar.split_at(half);
    let mut out = Vec::with_capacity(content_len);
    let mut prev_ts = 0u64;
    let mut prev_val = 0u64;
    for (td, vx) in ts_deltas.chunks_exact(8).zip(val_xors.chunks_exact(8)) {
        let mut d_b = [0u8; 8];
        let mut x_b = [0u8; 8];
        d_b.copy_from_slice(td);
        x_b.copy_from_slice(vx);
        let ts = prev_ts.wrapping_add(u64::from_le_bytes(d_b));
        let val = prev_val ^ u64::from_le_bytes(x_b);
        out.extend_from_slice(&ts.to_le_bytes());
        out.extend_from_slice(&val.to_le_bytes());
        prev_ts = ts;
        prev_val = val;
    }
    Ok(out)
}

/// Codec 18: page-level XOR delta against `base` compressed with zstd.
///
/// # Errors
///
/// Refuses mismatched page lengths.
pub fn encode_page_xor_delta(base: &[u8], current: &[u8]) -> Result<Vec<u8>, CodecError> {
    if base.len() != current.len() {
        return Err(CodecError::Malformed(String::from(
            "base and current page lengths differ",
        )));
    }
    let xor_bytes: Vec<u8> = base
        .iter()
        .zip(current.iter())
        .map(|(a, b)| a ^ b)
        .collect();
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
    if !weights_le.len().is_multiple_of(4) {
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
        if let Some(s) = sm_le.get(0..3) {
            sign_mantissas.extend_from_slice(s);
        }
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
    if !content_len.is_multiple_of(4) {
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
        let [b0, b1, b2] = <[u8; 3]>::try_from(sm3).unwrap_or([0, 0, 0]);
        let sm = u32::from_le_bytes([b0, b1, b2, 0]);
        let sign = (sm & 0x0080_0000) << 8;
        let mantissa = sm & 0x007F_FFFF;
        let bits = sign | (u32::from(*exp) << 23) | mantissa;
        out.extend_from_slice(&bits.to_le_bytes());
    }
    Ok(out)
}

/// Per-owner wrapped content key inside a convergent private dedup envelope.
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

/// Convergent private deduplication store.
///
/// `envelope_id` is derived from the authenticated ciphertext rather than the raw
/// plaintext digest, and `auth_tag` is a keyed `HMAC-SHA256` under `k_content`
/// verified in constant time after unwrapping with `owner_secret`.
#[derive(Debug, Default, Clone)]
pub struct ConvergentDedupStore {
    shared: BTreeMap<[u8; 32], SharedCipherRecord>,
    isolated: Vec<(Vec<u8>, [u8; 32])>,
}

fn hmac_keystream(key: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::with_capacity(input.len());
    for (chunk_idx, chunk) in input.chunks(32).enumerate() {
        let idx_bytes = (chunk_idx as u64).to_le_bytes();
        let block = hmac_sha256(key, b"budlum/codec/convergent-stream/v1", &idx_bytes)?;
        for (b, k) in chunk.iter().zip(block.iter()) {
            out.push(b ^ k);
        }
    }
    Ok(out)
}

impl ConvergentDedupStore {
    /// Store `plaintext` for `owner_id` using `owner_secret`.
    ///
    /// Returns `(envelope_id, ref_count)` when `convergent_mode == true`, or
    /// `(isolated_envelope_id, 1)` in isolated mode (`convergent_mode == false`).
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
            let mut nonce_material = Vec::with_capacity(40);
            nonce_material.extend_from_slice(&owner_id);
            nonce_material.extend_from_slice(&(self.isolated.len() as u64).to_le_bytes());
            let k_isolated = hmac_sha256(
                &owner_secret,
                b"budlum/codec/isolated-key/v1",
                &nonce_material,
            )
            .unwrap_or([0u8; 32]);
            let ct = hmac_keystream(&k_isolated, &compressed).unwrap_or_default();
            let id = sha256_domain(b"budlum/codec/isolated-id/v1", &ct);
            self.isolated.push((ct, id));
            return (id, 1);
        }

        let content_key_salt = sha256_domain(b"budlum/codec/convergent-kdf-salt/v1", b"v1");
        let k_content = hmac_sha256(
            &content_key_salt,
            b"budlum/codec/convergent-key/v1",
            plaintext,
        )
        .unwrap_or([0u8; 32]);
        let ciphertext = hmac_keystream(&k_content, &compressed).unwrap_or_default();
        let auth_tag = hmac_sha256(&k_content, b"budlum/codec/convergent-auth/v1", &ciphertext)
            .unwrap_or([0u8; 32]);
        let mut env_material = Vec::with_capacity(32 + ciphertext.len());
        env_material.extend_from_slice(&auth_tag);
        env_material.extend_from_slice(&ciphertext);
        let envelope_id = sha256_domain(b"budlum/codec/envelope-id/v1", &env_material);

        let mask = hmac_sha256(&owner_secret, b"budlum/codec/owner-wrap/v1", &envelope_id)
            .unwrap_or([0u8; 32]);
        let mut wrapped_key = [0u8; 32];
        for ((dst, kc), mk) in wrapped_key.iter_mut().zip(&k_content).zip(&mask) {
            *dst = kc ^ mk;
        }

        let entry = self
            .shared
            .entry(envelope_id)
            .or_insert_with(|| SharedCipherRecord {
                ciphertext,
                auth_tag,
                wraps: BTreeMap::new(),
            });
        entry.wraps.insert(
            owner_id,
            OwnerKeyWrap {
                owner_id,
                wrapped_key,
            },
        );
        (envelope_id, entry.wraps.len())
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

    /// Unwrap `k_content` for `owner_id`, verify the keyed HMAC-SHA256 tag, and recover plaintext.
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
        let mut env_material = Vec::with_capacity(32 + rec.ciphertext.len());
        env_material.extend_from_slice(&rec.auth_tag);
        env_material.extend_from_slice(&rec.ciphertext);
        if sha256_domain(b"budlum/codec/envelope-id/v1", &env_material) != *envelope_id {
            return Err(CodecError::Malformed(String::from(
                "envelope_id does not match ciphertext commitment",
            )));
        }
        let mask = hmac_sha256(owner_secret, b"budlum/codec/owner-wrap/v1", envelope_id)?;
        let mut k_content = [0u8; 32];
        for ((dst, wk), mk) in k_content.iter_mut().zip(&wrap.wrapped_key).zip(&mask) {
            *dst = wk ^ mk;
        }
        hmac_verify(
            &k_content,
            b"budlum/codec/convergent-auth/v1",
            &rec.ciphertext,
            &rec.auth_tag,
        )?;
        let compressed = hmac_keystream(&k_content, &rec.ciphertext)?;
        let want =
            u64::try_from(plaintext_len).map_err(|_| CodecError::TooLong { max: u64::MAX })?;
        decode(ZSTD, &compressed, want)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_lifecycle_and_small_object_roundtrip() -> Result<(), CodecError> {
        let mut reg = ContextRegistry::default();
        let dict = br#"{"schema":"v1","network":"mainnet","status":"finalized","kind":"#.repeat(16);
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
        let page_enc = encode_page_xor_delta(&base_page, &next_page)?;
        assert!(page_enc.len() < 128);
        assert_eq!(decode_page_xor_delta(&base_page, &page_enc)?, next_page);

        // Codec 19: 256 FP32 weights near 0.125.
        let mut weights = Vec::with_capacity(256 * 4);
        for i in 0u32..256 {
            let w = 0.125_f32 + (i as f32) * 1e-5;
            weights.extend_from_slice(&w.to_le_bytes());
        }
        let w_enc = encode_fp32_exponent_split(&weights)?;
        assert!(w_enc.len() < weights.len());
        assert_eq!(decode_fp32_exponent_split(&w_enc, weights.len())?, weights);
        Ok(())
    }

    #[test]
    fn convergent_cross_owner_dedup_keeps_payload_until_last_release() -> Result<(), CodecError> {
        let mut store = ConvergentDedupStore::default();
        let alice = [0x11u8; 32];
        let alice_sk = [0xA1u8; 32];
        let bob = [0x22u8; 32];
        let bob_sk = [0xB2u8; 32];
        let payload = b"shared confidential dataset chunk repeated ".repeat(32);

        let (env_a, refs_a) = store.put(alice, alice_sk, &payload, true);
        let (env_b, refs_b) = store.put(bob, bob_sk, &payload, true);
        assert_eq!(env_a, env_b);
        assert_eq!(refs_a, 1);
        assert_eq!(refs_b, 2);
        assert_eq!(store.shared_ciphertext_count(), 1);

        // envelope_id must commit to ciphertext+tag, never raw plaintext SHA-256.
        assert_ne!(
            env_a,
            sha256_domain(b"budlum/codec/content-digest/v1", &payload)
        );

        assert_eq!(
            store.open(&env_a, &alice, &alice_sk, payload.len())?,
            payload
        );
        assert_eq!(store.open(&env_b, &bob, &bob_sk, payload.len())?, payload);
        assert!(store.open(&env_a, &alice, &bob_sk, payload.len()).is_err());

        assert_eq!(store.release_owner(&env_a, &alice), 1);
        assert_eq!(store.open(&env_b, &bob, &bob_sk, payload.len())?, payload);
        assert_eq!(store.release_owner(&env_b, &bob), 0);
        assert_eq!(store.shared_ciphertext_count(), 0);

        // Isolated mode bypasses dedup completely.
        let (iso1, r1) = store.put(alice, alice_sk, &payload, false);
        let (iso2, r2) = store.put(bob, bob_sk, &payload, false);
        assert_ne!(iso1, iso2);
        assert_eq!((r1, r2), (1, 1));
        Ok(())
    }
}
