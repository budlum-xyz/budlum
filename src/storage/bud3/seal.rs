//! Sealed B.U.D. 3.0 objects: A0-before-sealing, Padme length bucketing,
//! hidden `content_len = 0` header, and XChaCha20-Poly1305 AEAD bound to the
//! keyed [`ContentId`].
//! exposed for client-side sealed upload/view and SDK grant decryption.
//!
//! Per Section 6.21.4:
//! 1. Plaintext is compressed first (`bud_codec::select`), then framed as
//!    `varint(real_content_len) || varint(inner_codec) || varint(compressed_len) || compressed`
//!    and zero-padded up to its Padme bucket length (`padme_padded_len`).
//! 2. The padded inner buffer is encrypted with XChaCha20-Poly1305 under an
//!    AEAD key and 24-byte nonce derived from `(content_key, object_salt)` and
//!    authenticated against `BDLM_BUD3_SEAL_AAD_V1 || content_digest`.
//! 3. The outer BOF-1 header sets `Flags::SEALED`, `content_len = 0`, and
//!    `codec = CODEC_RAW`, so neither the plaintext length nor the inner codec
//!    leaks to share-holding validators or chain records.

use super::bof1::{Bof1Error, CodecId, Flags, Header, Object, CODEC_RAW};
use super::content_id::{ContentId, ContentKey};
use super::delete::DeletionSet;
use super::limits::Profile;
use super::meter::{Meter, MeterError};
use super::varint;
use crate::core::hash::hash_fields_bytes;
use bud_proof::predicates::{
    prove_predicate, verify_predicate, PredicateKind, PredicateProof, PredicateStatement,
};
use bud_vm::{field_add_goldilocks, field_sub_goldilocks, poseidon4_hash4, GOLDILOCKS_P};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// Domain tag for deriving the per-object XChaCha20-Poly1305 key.
pub const SEAL_KEY_TAG: &[u8] = b"BDLM_BUD3_SEAL_KEY_V1";

/// Domain tag for deriving the per-object 24-byte XChaCha20 nonce.
pub const SEAL_NONCE_TAG: &[u8] = b"BDLM_BUD3_SEAL_NONCE_V1";

/// Domain tag binding the sealed BOF-1 `content_digest` into AEAD associated data.
pub const SEAL_AAD_TAG: &[u8] = b"BDLM_BUD3_SEAL_AAD_V1";

/// Domain tag for field-native Poseidon/Goldilocks keystream expansion.
const FIELD_KEY_STREAM_TAG: &[u8] = b"BDLM_BUD3_FIELD_KEY_STREAM_V1";

/// Domain tag for field-native ciphertext MAC binding.
const FIELD_MAC_TAG: &[u8] = b"BDLM_BUD3_FIELD_MAC_V1";

/// Domain tag for field-native nonce mixing.
const FIELD_NONCE_TAG: &[u8] = b"BDLM_BUD3_FIELD_NONCE_V1";

/// Domain tag for sealed manifest ciphertext roots.
const FIELD_CIPH_ROOT_TAG: &[u8] = b"BDLM_BUD3_FIELD_CIPH_ROOT_V1";

/// Domain tag for sealed manifest key commitments.
const FIELD_KEY_COMMIT_TAG: &[u8] = b"BDLM_BUD3_FIELD_KEY_COMMIT_V1";

/// Domain tag for sealed manifest plaintext roots.
const PLAINTEXT_ROOT_TAG: &[u8] = b"BDLM_BUD3_PLAINTEXT_ROOT_V1";

/// Domain tag for sealed manifest owner commitments.
const OWNER_COMMIT_TAG: &[u8] = b"BDLM_BUD3_OWNER_COMMIT_V1";

/// Domain tag binding privacy consent predicates to sealed objects.
const CONSENT_PRED_TAG: &[u8] = b"BDLM_BUD3_CONSENT_PRED_V1";

/// Encryption profile for B.U.D. 3.0 sealed objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum CipherProfile {
    /// Standard XChaCha20-Poly1305 + SHA-256 keyed ContentId.
    Aead = 0,
    /// Goldilocks field-native Poseidon2 cipher + field commitment for ZK compute.
    FieldNative = 1,
}

/// Object disclosure visibility level on chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum ObjectVisibility {
    /// Encrypted object whose grant capsules remain hidden unless consented.
    Sealed = 0,
    /// Sealed object paired with verifiable predicate-bound consent proofs.
    Consented = 1,
    /// Publicly readable object.
    Public = 2,
}

/// Canonical manifest committing to ciphertext, plaintext, key, and owner metadata
/// for both `CipherProfile::Aead` and `CipherProfile::FieldNative`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SealedObjectManifest {
    /// Manifest format version (`1`).
    pub version: u16,
    /// Hash suite identifier (`1` for AEAD/SHA-256, `2` for Goldilocks/Poseidon2).
    pub hash_suite: u8,
    /// Cipher profile used to seal the payload.
    pub cipher_profile: CipherProfile,
    /// Target chunk granularity in bytes (`65536`).
    pub chunk_size: u32,
    /// Padme-padded payload byte length stored inside the sealed envelope.
    pub padded_len: u64,
    /// Root commitment over the outer sealed BOF-1 payload.
    pub ciphertext_root: [u8; 32],
    /// Commitment over the canonical plaintext (`BDLM_BUD3_PLAINTEXT_ROOT_V1`).
    pub plaintext_root: [u8; 32],
    /// Commitment over the symmetric object content key.
    pub key_commitment: [u8; 32],
    /// Keyed object commitment (`header.content_digest`).
    pub object_commitment: [u8; 32],
    /// Visibility class of the object.
    pub visibility: ObjectVisibility,
    /// Hiding owner commitment (`H(BDLM_BUD3_OWNER_COMMIT_V1 || owner_secret)`).
    pub owner_commitment: [u8; 32],
}

/// Verifiable consent proof granting scoped computation/view rights over a
/// sealed object without exposing the plaintext or unrevoked identity keys.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsentProof {
    /// Unlinkable consent grant tag checked against `DeletionSet`.
    pub grant_tag: [u8; 32],
    /// Target sealed object commitment.
    pub object_commitment: [u8; 32],
    /// Target object plaintext root bound into compute requests.
    pub plaintext_root: [u8; 32],
    /// Key commitment authorizing use of the sealed object key.
    pub key_commitment: [u8; 32],
    /// Commitment to the authorized grantee / compute operator.
    pub grantee_commitment: [u8; 32],
    /// Scoped permission domain tag (e.g. model ID or modality scope digest).
    pub scope_tag: [u8; 32],
    /// Chain ID binding the predicate STARK proof.
    pub chain_id: u64,
    /// Epoch deadline after which consent expires.
    pub expires_at_epoch: u64,
    /// Zero-knowledge BudZero `PredicateProof` (`YK11ObjectBinding`).
    pub predicate_proof: PredicateProof,
}

/// Salt length prepended to the sealed BOF-1 payload.
pub const SEAL_SALT_LEN: usize = 24;

/// Poly1305 authentication tag length.
pub const SEAL_AUTH_TAG_LEN: usize = 16;

/// Minimum Padme bucket floor in bytes so tiny plaintexts share one bucket.
pub const MIN_SEALED_BUCKET_BYTES: u64 = 64;

/// Errors sealing or opening a B.U.D. 3.0 sealed object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealBud3Error {
    /// Object is not marked `Flags::SEALED` or carries a non-zero header `content_len`.
    NotSealedObject,
    /// Sealed payload is shorter than salt + minimum bucket + Poly1305 tag.
    TruncatedPayload,
    /// AEAD encryption failed.
    EncryptFailed,
    /// AEAD authentication / decryption failed (wrong key, wrong grant, or tampered bytes).
    DecryptFailed,
    /// Inner framed plaintext inside the Padme bucket is malformed.
    MalformedInnerFrame,
    /// Inner codec failed to reconstruct the declared plaintext length.
    InnerCodecMismatch,
    /// Reconstructed plaintext failed keyed HMAC-SHA-256 `ContentId` verification.
    ContentIdMismatch,
    /// Sealed manifest metadata disagreed with the object or cipher profile.
    ManifestMismatch,
    /// Consent proof was revoked in the `DeletionSet`, expired, or failed STARK verification.
    ConsentDenied,
    /// Parser/decoder budget exceeded.
    Budget(MeterError),
    /// BOF-1 header error.
    Bof1(Bof1Error),
}

impl From<MeterError> for SealBud3Error {
    fn from(e: MeterError) -> Self {
        Self::Budget(e)
    }
}

impl From<Bof1Error> for SealBud3Error {
    fn from(e: Bof1Error) -> Self {
        Self::Bof1(e)
    }
}

/// Deterministic Padme bucket length (`>= raw_len`, `>= MIN_SEALED_BUCKET_BYTES`).
///
/// Rounds `raw_len` up so at most `O(log log L)` significant bits of length
/// remain visible, capping padding overhead below 12% across all sizes.
#[must_use]
pub fn padme_padded_len(raw_len: u64) -> u64 {
    let base = if raw_len < MIN_SEALED_BUCKET_BYTES {
        MIN_SEALED_BUCKET_BYTES
    } else {
        raw_len
    };
    if base <= 8 {
        return base;
    }
    let e = 63u32.saturating_sub(base.leading_zeros());
    let s = 64u32.saturating_sub((e as u64).leading_zeros());
    let last_bits = e.saturating_sub(s);
    if last_bits == 0 || last_bits >= 63 {
        return base;
    }
    let mask = (1u64 << last_bits) - 1;
    match base.checked_add(mask) {
        Some(sum) => sum & !mask,
        None => u64::MAX,
    }
}

fn derive_aead_key_and_nonce(
    content_key: &ContentKey,
    salt: &[u8; SEAL_SALT_LEN],
) -> ([u8; 32], [u8; 24]) {
    let aead_key = hash_fields_bytes(&[SEAL_KEY_TAG, &content_key.0, salt]);
    let nonce_digest = hash_fields_bytes(&[SEAL_NONCE_TAG, &content_key.0, salt]);
    let mut nonce = [0u8; 24];
    if let Some(prefix) = nonce_digest.get(..24) {
        nonce.copy_from_slice(prefix);
    }
    (aead_key, nonce)
}

fn sealed_aad(content_digest: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[SEAL_AAD_TAG, content_digest])
}

/// Compress `content`, pad the inner length-prefixed frame to its Padme bucket,
/// encrypt with XChaCha20-Poly1305, and build a canonical sealed BOF-1 [`Object`]
/// with `header.content_len == 0`.
///
/// # Errors
///
/// Returns [`SealBud3Error`] if AEAD encryption or flag construction fails.
pub fn seal_object(
    content: &[u8],
    content_key: &ContentKey,
    object_salt: [u8; SEAL_SALT_LEN],
) -> Result<Object, SealBud3Error> {
    let cid = ContentId::sealed(content_key, content);
    let selected = bud_codec::select(content);

    let mut inner = Vec::with_capacity(selected.payload.len().saturating_add(32));
    varint::write(&mut inner, cid.len);
    varint::write(&mut inner, u64::from(selected.codec));
    varint::write(&mut inner, selected.payload.len() as u64);
    inner.extend_from_slice(&selected.payload);

    let bucket_len_u64 = padme_padded_len(inner.len() as u64);
    let bucket_len =
        usize::try_from(bucket_len_u64).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
    if inner.len() < bucket_len {
        inner.resize(bucket_len, 0u8);
    }

    let (aead_key, nonce_bytes) = derive_aead_key_and_nonce(content_key, &object_salt);
    let cipher = XChaCha20Poly1305::new((&aead_key).into());
    let aad = sealed_aad(&cid.digest);
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| SealBud3Error::EncryptFailed)?;

    let mut payload = Vec::with_capacity(SEAL_SALT_LEN.saturating_add(ciphertext.len()));
    payload.extend_from_slice(&object_salt);
    payload.extend_from_slice(&ciphertext);

    let flags = Flags::from_byte(Flags::SEALED)?;
    Ok(Object {
        header: Header {
            flags,
            profile: Profile::P0.id,
            codec: CODEC_RAW,
            dictionary: 0,
            base: None,
            content_len: 0,
            content_digest: cid.digest,
            payload_len: payload.len() as u64,
            prev_object: None,
            context_manifest: None,
        },
        payload,
    })
}

/// Decrypt, unpad, decompress, and verify a sealed BOF-1 [`Object`] using `content_key`.
///
/// # Errors
///
/// Returns [`SealBud3Error`] if `object` is not sealed, `content_key` is wrong,
/// ciphertext or AAD was tampered with, or the recovered plaintext fails `ContentId::sealed`.
pub fn open_sealed_object(
    object: &Object,
    content_key: &ContentKey,
    meter: &mut Meter,
) -> Result<Vec<u8>, SealBud3Error> {
    if !object.header.is_sealed()
        || object.header.content_len != 0
        || object.header.codec != CODEC_RAW
    {
        return Err(SealBud3Error::NotSealedObject);
    }
    let min_len = SEAL_SALT_LEN
        .saturating_add(usize::try_from(MIN_SEALED_BUCKET_BYTES).unwrap_or(64))
        .saturating_add(SEAL_AUTH_TAG_LEN);
    if object.payload.len() < min_len {
        return Err(SealBud3Error::TruncatedPayload);
    }
    meter.charge_bytes(object.payload.len() as u64)?;

    let salt_slice = object
        .payload
        .get(..SEAL_SALT_LEN)
        .ok_or(SealBud3Error::TruncatedPayload)?;
    let ciphertext = object
        .payload
        .get(SEAL_SALT_LEN..)
        .ok_or(SealBud3Error::TruncatedPayload)?;
    let mut salt = [0u8; SEAL_SALT_LEN];
    salt.copy_from_slice(salt_slice);

    let (aead_key, nonce_bytes) = derive_aead_key_and_nonce(content_key, &salt);
    let cipher = XChaCha20Poly1305::new((&aead_key).into());
    let aad = sealed_aad(&object.header.content_digest);
    let inner = cipher
        .decrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| SealBud3Error::DecryptFailed)?;

    let expected_bucket = padme_padded_len(inner.len() as u64);
    if expected_bucket != inner.len() as u64 {
        return Err(SealBud3Error::MalformedInnerFrame);
    }

    let (real_len, used1) =
        varint::read(&inner, 9).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
    let rest1 = inner
        .get(used1..)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;
    let (codec_u64, used2) =
        varint::read(rest1, 2).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
    let inner_codec =
        CodecId::try_from(codec_u64).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
    let rest2 = rest1
        .get(used2..)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;
    let (comp_len_u64, used3) =
        varint::read(rest2, 9).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
    let comp_len = usize::try_from(comp_len_u64).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
    let after_vars = rest2
        .get(used3..)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;
    let compressed = after_vars
        .get(..comp_len)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;
    let padding = after_vars
        .get(comp_len..)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;
    if padding.iter().any(|b| *b != 0) {
        return Err(SealBud3Error::MalformedInnerFrame);
    }

    meter.charge_bytes(real_len)?;
    let plaintext = bud_codec::decode(inner_codec, compressed, real_len)
        .map_err(|_| SealBud3Error::InnerCodecMismatch)?;
    let check_id = ContentId {
        kind: super::content_id::ContentIdKind::Sealed,
        digest: object.header.content_digest,
        len: real_len,
    };
    if !check_id.matches_sealed(content_key, &plaintext) {
        return Err(SealBud3Error::ContentIdMismatch);
    }
    Ok(plaintext)
}

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (lhs, rhs)| acc | (lhs ^ rhs))
        == 0
}

fn le_u64_from_chunk(chunk: &[u8]) -> u64 {
    chunk
        .iter()
        .enumerate()
        .fold(0u64, |acc, (idx, &byte)| acc | (u64::from(byte) << (idx * 8)))
}

fn field_limbs_from_digest(digest: &[u8; 32]) -> (u64, u64) {
    let mut lo = [0u8; 8];
    let mut hi = [0u8; 8];
    if let Some(first) = digest.get(..8) {
        lo.copy_from_slice(first);
    }
    if let Some(second) = digest.get(8..16) {
        hi.copy_from_slice(second);
    }
    (
        u64::from_le_bytes(lo) % GOLDILOCKS_P,
        u64::from_le_bytes(hi) % GOLDILOCKS_P,
    )
}

fn derive_field_keystream_word(
    content_key: &ContentKey,
    salt: &[u8; SEAL_SALT_LEN],
    word_index: u64,
) -> u64 {
    let k_digest = hash_fields_bytes(&[FIELD_KEY_STREAM_TAG, &content_key.0, salt]);
    let n_digest = hash_fields_bytes(&[FIELD_NONCE_TAG, salt, &word_index.to_le_bytes()]);
    let (k0, k1) = field_limbs_from_digest(&k_digest);
    let (n0, n1) = field_limbs_from_digest(&n_digest);
    poseidon4_hash4(k0, k1, n0, n1) % GOLDILOCKS_P
}

fn compute_field_mac(
    content_key: &ContentKey,
    salt: &[u8; SEAL_SALT_LEN],
    content_digest: &[u8; 32],
    ciphertext_words: &[u8],
) -> [u8; 32] {
    hash_fields_bytes(&[
        FIELD_MAC_TAG,
        &content_key.0,
        salt,
        content_digest,
        ciphertext_words,
    ])
}

/// Compute the deterministic plaintext root for a sealed object manifest.
#[must_use]
pub fn sealed_plaintext_root(content: &[u8]) -> [u8; 32] {
    hash_fields_bytes(&[PLAINTEXT_ROOT_TAG, content])
}

/// Compute the deterministic key commitment for a symmetric `ContentKey`.
#[must_use]
pub fn sealed_key_commitment(content_key: &ContentKey) -> [u8; 32] {
    hash_fields_bytes(&[FIELD_KEY_COMMIT_TAG, &content_key.0])
}

fn encode_inner_padme(content: &[u8], cid: &ContentId) -> Result<Vec<u8>, SealBud3Error> {
    let selected = bud_codec::select(content);
    let mut inner = Vec::with_capacity(selected.payload.len().saturating_add(32));
    varint::write(&mut inner, cid.len);
    varint::write(&mut inner, u64::from(selected.codec));
    varint::write(&mut inner, selected.payload.len() as u64);
    inner.extend_from_slice(&selected.payload);

    let bucket_len_u64 = padme_padded_len(inner.len() as u64);
    let bucket_len =
        usize::try_from(bucket_len_u64).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
    if inner.len() < bucket_len {
        inner.resize(bucket_len, 0u8);
    }
    Ok(inner)
}

fn decode_inner_padme(
    inner: &[u8],
    content_digest: [u8; 32],
    content_key: &ContentKey,
    meter: &mut Meter,
) -> Result<Vec<u8>, SealBud3Error> {
    let expected_bucket = padme_padded_len(inner.len() as u64);
    if expected_bucket != inner.len() as u64 {
        return Err(SealBud3Error::MalformedInnerFrame);
    }
    let (real_len, used1) =
        varint::read(inner, 9).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
    let rest1 = inner
        .get(used1..)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;
    let (codec_u64, used2) =
        varint::read(rest1, 2).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
    let inner_codec =
        CodecId::try_from(codec_u64).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
    let rest2 = rest1
        .get(used2..)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;
    let (comp_len_u64, used3) =
        varint::read(rest2, 9).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
    let comp_len = usize::try_from(comp_len_u64).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
    let after_vars = rest2
        .get(used3..)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;
    let compressed = after_vars
        .get(..comp_len)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;
    let padding = after_vars
        .get(comp_len..)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;
    if padding.iter().any(|b| *b != 0) {
        return Err(SealBud3Error::MalformedInnerFrame);
    }

    meter.charge_bytes(real_len)?;
    let plaintext = bud_codec::decode(inner_codec, compressed, real_len)
        .map_err(|_| SealBud3Error::InnerCodecMismatch)?;
    let check_id = ContentId {
        kind: super::content_id::ContentIdKind::Sealed,
        digest: content_digest,
        len: real_len,
    };
    if !check_id.matches_sealed(content_key, &plaintext) {
        return Err(SealBud3Error::ContentIdMismatch);
    }
    Ok(plaintext)
}

fn seal_object_field_native(
    content: &[u8],
    content_key: &ContentKey,
    object_salt: [u8; SEAL_SALT_LEN],
) -> Result<Object, SealBud3Error> {
    let cid = ContentId::sealed(content_key, content);
    let inner = encode_inner_padme(content, &cid)?;
    let inner_len_u64 = u64::try_from(inner.len()).map_err(|_| SealBud3Error::EncryptFailed)?;

    let mut ciphertext_words = Vec::with_capacity((1 + inner.len().div_ceil(7)) * 8);
    let len_ks = derive_field_keystream_word(content_key, &object_salt, 0);
    let enc_len = field_add_goldilocks(inner_len_u64 % GOLDILOCKS_P, len_ks);
    ciphertext_words.extend_from_slice(&enc_len.to_le_bytes());

    for (idx, chunk) in inner.chunks(7).enumerate() {
        let word_idx = u64::try_from(idx + 1).map_err(|_| SealBud3Error::EncryptFailed)?;
        let ks = derive_field_keystream_word(content_key, &object_salt, word_idx);
        let plain_word = le_u64_from_chunk(chunk);
        let cipher_word = field_add_goldilocks(plain_word, ks);
        ciphertext_words.extend_from_slice(&cipher_word.to_le_bytes());
    }

    let mac = compute_field_mac(content_key, &object_salt, &cid.digest, &ciphertext_words);
    let mut payload = Vec::with_capacity(
        SEAL_SALT_LEN
            .saturating_add(ciphertext_words.len())
            .saturating_add(32),
    );
    payload.extend_from_slice(&object_salt);
    payload.extend_from_slice(&ciphertext_words);
    payload.extend_from_slice(&mac);

    let flags = Flags::from_byte(Flags::SEALED)?;
    Ok(Object {
        header: Header {
            flags,
            profile: Profile::P0.id,
            codec: CODEC_RAW,
            dictionary: 0,
            base: None,
            content_len: 0,
            content_digest: cid.digest,
            payload_len: payload.len() as u64,
            prev_object: None,
            context_manifest: None,
        },
        payload,
    })
}

fn open_sealed_object_field_native(
    object: &Object,
    content_key: &ContentKey,
    meter: &mut Meter,
) -> Result<Vec<u8>, SealBud3Error> {
    if !object.header.is_sealed()
        || object.header.content_len != 0
        || object.header.codec != CODEC_RAW
    {
        return Err(SealBud3Error::NotSealedObject);
    }
    let min_field_len = SEAL_SALT_LEN.saturating_add(8).saturating_add(32);
    if object.payload.len() < min_field_len {
        return Err(SealBud3Error::TruncatedPayload);
    }
    meter.charge_bytes(object.payload.len() as u64)?;

    let salt_slice = object
        .payload
        .get(..SEAL_SALT_LEN)
        .ok_or(SealBud3Error::TruncatedPayload)?;
    let mac_offset = object
        .payload
        .len()
        .checked_sub(32)
        .ok_or(SealBud3Error::TruncatedPayload)?;
    let ciphertext_words = object
        .payload
        .get(SEAL_SALT_LEN..mac_offset)
        .ok_or(SealBud3Error::TruncatedPayload)?;
    let mac_slice = object
        .payload
        .get(mac_offset..)
        .ok_or(SealBud3Error::TruncatedPayload)?;

    let mut salt = [0u8; SEAL_SALT_LEN];
    salt.copy_from_slice(salt_slice);
    let mut actual_mac = [0u8; 32];
    actual_mac.copy_from_slice(mac_slice);

    let expected_mac = compute_field_mac(
        content_key,
        &salt,
        &object.header.content_digest,
        ciphertext_words,
    );
    if !ct_eq_32(&expected_mac, &actual_mac) {
        return Err(SealBud3Error::DecryptFailed);
    }

    if ciphertext_words.is_empty() || ciphertext_words.len() % 8 != 0 {
        return Err(SealBud3Error::MalformedInnerFrame);
    }

    let len_bytes_slice = ciphertext_words
        .get(..8)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;
    let mut len_arr = [0u8; 8];
    len_arr.copy_from_slice(len_bytes_slice);
    let enc_len = u64::from_le_bytes(len_arr);
    if enc_len >= GOLDILOCKS_P {
        return Err(SealBud3Error::DecryptFailed);
    }
    let len_ks = derive_field_keystream_word(content_key, &salt, 0);
    let inner_len_u64 = field_sub_goldilocks(enc_len, len_ks);
    let inner_len =
        usize::try_from(inner_len_u64).map_err(|_| SealBud3Error::MalformedInnerFrame)?;

    let body_words = ciphertext_words
        .get(8..)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;
    let expected_chunks = inner_len.div_ceil(7);
    if body_words.len() != expected_chunks.saturating_mul(8) {
        return Err(SealBud3Error::MalformedInnerFrame);
    }

    let mut decoded = Vec::with_capacity(body_words.len());
    for (idx, word_bytes) in body_words.chunks_exact(8).enumerate() {
        let mut word_arr = [0u8; 8];
        word_arr.copy_from_slice(word_bytes);
        let cipher_word = u64::from_le_bytes(word_arr);
        if cipher_word >= GOLDILOCKS_P {
            return Err(SealBud3Error::DecryptFailed);
        }
        let word_idx = u64::try_from(idx + 1).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
        let ks = derive_field_keystream_word(content_key, &salt, word_idx);
        let plain_word = field_sub_goldilocks(cipher_word, ks);
        if plain_word >= (1u64 << 56) {
            return Err(SealBud3Error::DecryptFailed);
        }
        let le = plain_word.to_le_bytes();
        if let Some(seven) = le.get(..7) {
            decoded.extend_from_slice(seven);
        }
    }

    let tail = decoded
        .get(inner_len..)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;
    if tail.iter().any(|b| *b != 0) {
        return Err(SealBud3Error::MalformedInnerFrame);
    }
    let inner = decoded
        .get(..inner_len)
        .ok_or(SealBud3Error::MalformedInnerFrame)?;

    decode_inner_padme(inner, object.header.content_digest, content_key, meter)
}

/// Seal `content` under either [`CipherProfile::Aead`] or [`CipherProfile::FieldNative`]
/// and return the sealed BOF-1 [`Object`] alongside its committed [`SealedObjectManifest`].
///
/// # Errors
///
/// Returns [`SealBud3Error`] if sealing fails.
pub fn seal_object_with_profile(
    content: &[u8],
    content_key: &ContentKey,
    owner_secret: &[u8; 32],
    visibility: ObjectVisibility,
    cipher_profile: CipherProfile,
    object_salt: [u8; SEAL_SALT_LEN],
) -> Result<(Object, SealedObjectManifest), SealBud3Error> {
    let (object, hash_suite) = match cipher_profile {
        CipherProfile::Aead => (seal_object(content, content_key, object_salt)?, 1u8),
        CipherProfile::FieldNative => (
            seal_object_field_native(content, content_key, object_salt)?,
            2u8,
        ),
    };
    let manifest = SealedObjectManifest {
        version: 1,
        hash_suite,
        cipher_profile,
        chunk_size: 64 * 1024,
        padded_len: object.header.payload_len,
        ciphertext_root: hash_fields_bytes(&[FIELD_CIPH_ROOT_TAG, &object.payload]),
        plaintext_root: sealed_plaintext_root(content),
        key_commitment: sealed_key_commitment(content_key),
        object_commitment: object.header.content_digest,
        visibility,
        owner_commitment: hash_fields_bytes(&[OWNER_COMMIT_TAG, owner_secret]),
    };
    Ok((object, manifest))
}

/// Open and authenticate a sealed BOF-1 [`Object`] against its [`SealedObjectManifest`].
///
/// # Errors
///
/// Returns [`SealBud3Error`] if manifest roots/commitments mismatch, AEAD or
/// field-native MAC authentication fails, or `ContentId::sealed` fails.
pub fn open_sealed_object_with_profile(
    object: &Object,
    manifest: &SealedObjectManifest,
    content_key: &ContentKey,
    meter: &mut Meter,
) -> Result<Vec<u8>, SealBud3Error> {
    let expected_suite = match manifest.cipher_profile {
        CipherProfile::Aead => 1u8,
        CipherProfile::FieldNative => 2u8,
    };
    if manifest.version != 1
        || manifest.hash_suite != expected_suite
        || manifest.padded_len != object.header.payload_len
        || !ct_eq_32(&manifest.object_commitment, &object.header.content_digest)
        || !ct_eq_32(&manifest.key_commitment, &sealed_key_commitment(content_key))
    {
        return Err(SealBud3Error::ManifestMismatch);
    }
    let observed_ciph_root = hash_fields_bytes(&[FIELD_CIPH_ROOT_TAG, &object.payload]);
    if !ct_eq_32(&manifest.ciphertext_root, &observed_ciph_root) {
        return Err(SealBud3Error::ManifestMismatch);
    }
    let plaintext = match manifest.cipher_profile {
        CipherProfile::Aead => open_sealed_object(object, content_key, meter)?,
        CipherProfile::FieldNative => open_sealed_object_field_native(object, content_key, meter)?,
    };
    let observed_plain_root = sealed_plaintext_root(&plaintext);
    if !ct_eq_32(&manifest.plaintext_root, &observed_plain_root) {
        return Err(SealBud3Error::ManifestMismatch);
    }
    Ok(plaintext)
}

fn first_u64_limb(digest: &[u8; 32]) -> u64 {
    let mut arr = [0u8; 8];
    if let Some(first) = digest.get(..8) {
        arr.copy_from_slice(first);
    }
    let v = u64::from_le_bytes(arr) % GOLDILOCKS_P;
    if v == 0 {
        1
    } else {
        v
    }
}

impl ConsentProof {
    /// Issue a STARK-backed [`ConsentProof`] over a [`SealedObjectManifest`].
    ///
    /// # Errors
    ///
    /// Returns [`SealBud3Error::ConsentDenied`] if the predicate proof cannot be built.
    pub fn issue(
        manifest: &SealedObjectManifest,
        grant_tag: [u8; 32],
        grantee_commitment: [u8; 32],
        scope_tag: [u8; 32],
        chain_id: u64,
        expires_at_epoch: u64,
    ) -> Result<Self, SealBud3Error> {
        let binding = hash_fields_bytes(&[
            CONSENT_PRED_TAG,
            &grant_tag,
            &manifest.object_commitment,
            &manifest.plaintext_root,
            &grantee_commitment,
            &scope_tag,
            &expires_at_epoch.to_le_bytes(),
        ]);
        let stmt = PredicateStatement {
            kind: PredicateKind::Yk11ObjectBinding,
            lhs: first_u64_limb(&binding),
            rhs: first_u64_limb(&manifest.object_commitment),
            aux: first_u64_limb(&scope_tag),
            chain_id,
        };
        let predicate_proof = prove_predicate(&stmt).map_err(|_| SealBud3Error::ConsentDenied)?;
        Ok(Self {
            grant_tag,
            object_commitment: manifest.object_commitment,
            plaintext_root: manifest.plaintext_root,
            key_commitment: manifest.key_commitment,
            grantee_commitment,
            scope_tag,
            chain_id,
            expires_at_epoch,
            predicate_proof,
        })
    }

    /// Verify revocation (`DeletionSet`), expiry, object bindings, and the BudZero
    /// zero-knowledge [`PredicateProof`].
    ///
    /// # Errors
    ///
    /// Returns [`SealBud3Error::ConsentDenied`] if revoked, expired, unbound, or invalid.
    pub fn verify(
        &self,
        deletion_set: &DeletionSet,
        expected_object: &[u8; 32],
        expected_plaintext_root: &[u8; 32],
        current_epoch: u64,
    ) -> Result<(), SealBud3Error> {
        if deletion_set.is_revoked(&self.grant_tag, &self.object_commitment)
            || current_epoch > self.expires_at_epoch
            || !ct_eq_32(&self.object_commitment, expected_object)
            || !ct_eq_32(&self.plaintext_root, expected_plaintext_root)
        {
            return Err(SealBud3Error::ConsentDenied);
        }
        let expected_binding = hash_fields_bytes(&[
            CONSENT_PRED_TAG,
            &self.grant_tag,
            &self.object_commitment,
            &self.plaintext_root,
            &self.grantee_commitment,
            &self.scope_tag,
            &self.expires_at_epoch.to_le_bytes(),
        ]);
        if self.predicate_proof.statement.kind != PredicateKind::Yk11ObjectBinding
            || self.predicate_proof.statement.chain_id != self.chain_id
            || self.predicate_proof.statement.lhs != first_u64_limb(&expected_binding)
            || self.predicate_proof.statement.rhs != first_u64_limb(&self.object_commitment)
            || self.predicate_proof.statement.aux != first_u64_limb(&self.scope_tag)
        {
            return Err(SealBud3Error::ConsentDenied);
        }
        verify_predicate(&self.predicate_proof).map_err(|_| SealBud3Error::ConsentDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_header_hides_length_and_padme_buckets_nearby_sizes() {
        let key = ContentKey([0x42u8; 32]);
        let salt1 = [0x11u8; SEAL_SALT_LEN];
        let salt2 = [0x22u8; SEAL_SALT_LEN];

        let obj_a = seal_object(&[0xaa; 10], &key, salt1).unwrap();
        let obj_b = seal_object(&[0xbb; 25], &key, salt2).unwrap();
        assert_eq!(obj_a.header.content_len, 0);
        assert_eq!(obj_b.header.content_len, 0);
        // Both 10-byte and 25-byte incompressible plaintexts land in the 64-byte Padme floor bucket.
        assert_eq!(obj_a.header.payload_len, obj_b.header.payload_len);

        let mut m = Meter::for_object(1 << 20);
        assert_eq!(
            open_sealed_object(&obj_a, &key, &mut m).unwrap(),
            vec![0xaa; 10]
        );
        assert_eq!(
            open_sealed_object(&obj_b, &key, &mut m).unwrap(),
            vec![0xbb; 25]
        );
    }

    #[test]
    fn bud3_sealed_needs_grant_and_bud3_sealed_isolation() {
        let content = b"confidential medical record payload".repeat(20);
        let owner_a = ContentKey([1u8; 32]);
        let owner_b = ContentKey([2u8; 32]);
        let wrong_key = ContentKey([3u8; 32]);

        let sealed_a = seal_object(&content, &owner_a, [7u8; SEAL_SALT_LEN]).unwrap();
        let sealed_b = seal_object(&content, &owner_b, [8u8; SEAL_SALT_LEN]).unwrap();

        // T19: Two owners sealing identical bytes produce completely unrelated public headers.
        assert_ne!(
            sealed_a.header.content_digest,
            sealed_b.header.content_digest
        );
        assert_eq!(sealed_a.header.content_len, 0);
        assert_eq!(sealed_b.header.content_len, 0);

        // T11: Without the matching ContentKey (delivered only by grant), decryption fails.
        let mut m = Meter::for_object(1 << 20);
        assert_eq!(
            open_sealed_object(&sealed_a, &wrong_key, &mut m),
            Err(SealBud3Error::DecryptFailed)
        );
        assert_eq!(
            open_sealed_object(&sealed_a, &owner_a, &mut m).unwrap(),
            content
        );
    }

    #[test]
    fn bud3_information_law_canary() {
        // High-entropy random-like bytes cannot compress smaller than input, and
        // a sealed object is always strictly larger than its random plaintext.
        let mut pseudo_random = Vec::with_capacity(4096);
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..512 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            pseudo_random.extend_from_slice(&state.to_le_bytes());
        }
        let pub_obj = Object::raw_public(&pseudo_random);
        assert!(pub_obj.encode().len() >= pseudo_random.len());
        let sealed_obj =
            seal_object(&pseudo_random, &ContentKey([9u8; 32]), [5u8; SEAL_SALT_LEN]).unwrap();
        assert!(sealed_obj.encode().len() >= pseudo_random.len());
    }

    #[test]
    fn cipher_profile_field_native_and_aead_round_trip_and_reject_tamper() {
        let payload = b"confidential field-native genomic sequence payload for zero-knowledge inference";
        let key = ContentKey([0x55u8; 32]);
        let wrong_key = ContentKey([0x56u8; 32]);
        let owner_secret = [0xAAu8; 32];
        let salt = [0x33u8; SEAL_SALT_LEN];

        for profile in [CipherProfile::Aead, CipherProfile::FieldNative] {
            let (mut obj, manifest) = seal_object_with_profile(
                payload,
                &key,
                &owner_secret,
                ObjectVisibility::Consented,
                profile,
                salt,
            )
            .expect("sealing succeeds");
            assert_eq!(obj.header.content_len, 0);
            assert_eq!(manifest.cipher_profile, profile);
            let mut meter = Meter::for_object(1 << 20);
            let recovered =
                open_sealed_object_with_profile(&obj, &manifest, &key, &mut meter).unwrap();
            assert_eq!(recovered, payload);

            assert_eq!(
                open_sealed_object_with_profile(&obj, &manifest, &wrong_key, &mut meter),
                Err(SealBud3Error::ManifestMismatch)
            );

            // Corrupt 25% of payload body bytes and require fail-closed rejection.
            let body_start = SEAL_SALT_LEN;
            let body_len = obj.payload.len().saturating_sub(body_start);
            let step = (body_len / 4).max(1);
            for idx in (body_start..obj.payload.len()).step_by(step) {
                if let Some(byte) = obj.payload.get_mut(idx) {
                    *byte ^= 0xFF;
                }
            }
            assert!(open_sealed_object_with_profile(&obj, &manifest, &key, &mut meter).is_err());
        }
    }

    #[test]
    fn consent_proof_enforces_stark_binding_and_deletion_set_revocation() {
        let payload = b"private telemetry batch for consented analytics";
        let key = ContentKey([0x71u8; 32]);
        let owner_secret = [0x81u8; 32];
        let (_obj, manifest) = seal_object_with_profile(
            payload,
            &key,
            &owner_secret,
            ObjectVisibility::Consented,
            CipherProfile::FieldNative,
            [0x19u8; SEAL_SALT_LEN],
        )
        .unwrap();

        let grant_tag = [0x44u8; 32];
        let grantee = [0x77u8; 32];
        let scope = [0x99u8; 32];
        let consent =
            ConsentProof::issue(&manifest, grant_tag, grantee, scope, 45261, 1_000).unwrap();

        let mut deletions = DeletionSet::default();
        assert!(consent
            .verify(
                &deletions,
                &manifest.object_commitment,
                &manifest.plaintext_root,
                500
            )
            .is_ok());

        // Expired consent is refused.
        assert_eq!(
            consent.verify(
                &deletions,
                &manifest.object_commitment,
                &manifest.plaintext_root,
                1_001
            ),
            Err(SealBud3Error::ConsentDenied)
        );

        // Revocation in DeletionSet blocks further consent acceptance.
        deletions.tombstone_grant(grant_tag);
        assert_eq!(
            consent.verify(
                &deletions,
                &manifest.object_commitment,
                &manifest.plaintext_root,
                500
            ),
            Err(SealBud3Error::ConsentDenied)
        );
    }
}
