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
use super::limits::Profile;
use super::meter::{Meter, MeterError};
use super::varint;
use crate::core::hash::hash_fields_bytes;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// Domain tag for deriving the per-object XChaCha20-Poly1305 key.
pub const SEAL_KEY_TAG: &[u8] = b"BDLM_BUD3_SEAL_KEY_V1";

/// Domain tag for deriving the per-object 24-byte XChaCha20 nonce.
pub const SEAL_NONCE_TAG: &[u8] = b"BDLM_BUD3_SEAL_NONCE_V1";

/// Domain tag binding the sealed BOF-1 `content_digest` into AEAD associated data.
pub const SEAL_AAD_TAG: &[u8] = b"BDLM_BUD3_SEAL_AAD_V1";

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
pub const fn padme_padded_len(raw_len: u64) -> u64 {
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
            XNonce::from_slice(&nonce_bytes),
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
            XNonce::from_slice(&nonce_bytes),
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
    let comp_len =
        usize::try_from(comp_len_u64).map_err(|_| SealBud3Error::MalformedInnerFrame)?;
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
        assert_eq!(open_sealed_object(&obj_a, &key, &mut m).unwrap(), vec![0xaa; 10]);
        assert_eq!(open_sealed_object(&obj_b, &key, &mut m).unwrap(), vec![0xbb; 25]);
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
        assert_ne!(sealed_a.header.content_digest, sealed_b.header.content_digest);
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
}
