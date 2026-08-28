//! G1 payload encryption (plan §CH T11 / G1).
//!
//! Content bytes are sealed **before** A1 pack so carousel drops and optical
//! frames never carry plaintext on the wire. The A1 container then stores
//! ciphertext under [`crate::storage::qr_payload::PayloadKind::EncryptedContent`];
//! the committed sha256 is of the ciphertext bytes the packer sees.
//!
//! # Scheme
//!
//! XChaCha20-Poly1305 (IETF), key 32 B, nonce 24 B random-or-derived.
//! Wire of the sealed blob (what A1 packs):
//!
//! ```text
//! magic[4] = BDLC
//! version u8 = 1
//! nonce[24]
//! ciphertext+tag [...]
//! ```
//!
//! # What this module does not claim
//!
//! - Key distribution / view-grants (separate; `view_grant` already exists).
//! - Consensus verification of plaintext (chain never sees content).
//! - Decimen source.

use crate::core::hash::hash_fields_bytes;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// Sealed-blob magic.
pub const SEALED_MAGIC: [u8; 4] = *b"BDLC";
pub const SEALED_VERSION: u8 = 1;
pub const SEALED_NONCE_LEN: usize = 24;
pub const SEALED_HEADER_LEN: usize = 4 + 1 + SEALED_NONCE_LEN;
/// Max plaintext for one seal in this process.
pub const MAX_SEAL_PLAINTEXT: usize = 64 * 1024 * 1024;

/// 32-byte payload encryption key (view-key material lives elsewhere).
#[derive(Clone)]
pub struct PayloadKey(pub [u8; 32]);

impl PayloadKey {
    /// Derive a payload key from arbitrary secret material (domain-separated).
    #[must_use]
    pub fn derive(secret: &[u8]) -> Self {
        Self(hash_fields_bytes(&[b"BDLM_THREE_PAYLOAD_KEY_V1", secret]))
    }
}

impl core::fmt::Debug for PayloadKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PayloadKey([redacted])")
    }
}

/// Errors sealing or opening content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// Empty plaintext refused.
    Empty,
    /// Plaintext too large.
    TooLarge {
        /// Observed.
        len: usize,
        /// Max.
        max: usize,
    },
    /// AEAD encrypt failed (should be rare with valid key/nonce).
    Encrypt,
    /// AEAD decrypt failed (wrong key, tamper, or truncate).
    Decrypt,
    /// Sealed blob magic/version/length bad.
    BadBlob,
    /// Nonce length wrong.
    BadNonce,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "payload seal refuses empty plaintext"),
            Self::TooLarge { len, max } => {
                write!(f, "plaintext {len} exceeds seal max {max}")
            }
            Self::Encrypt => write!(f, "payload seal encrypt failed"),
            Self::Decrypt => write!(f, "payload seal decrypt failed"),
            Self::BadBlob => write!(f, "payload sealed blob malformed"),
            Self::BadNonce => write!(f, "payload seal bad nonce length"),
        }
    }
}

impl std::error::Error for SealError {}

/// Seal plaintext under `key` with the given 24-byte nonce.
///
/// # Errors
///
/// Empty / oversized plaintext, bad nonce length, or AEAD failure.
pub fn seal_payload(
    key: &PayloadKey,
    nonce24: &[u8; SEALED_NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    if plaintext.is_empty() {
        return Err(SealError::Empty);
    }
    if plaintext.len() > MAX_SEAL_PLAINTEXT {
        return Err(SealError::TooLarge {
            len: plaintext.len(),
            max: MAX_SEAL_PLAINTEXT,
        });
    }
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| SealError::Encrypt)?;
    let nonce = XNonce::from_slice(nonce24);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| SealError::Encrypt)?;
    let mut out = Vec::with_capacity(SEALED_HEADER_LEN + ct.len());
    out.extend_from_slice(&SEALED_MAGIC);
    out.push(SEALED_VERSION);
    out.extend_from_slice(nonce24);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed blob.
///
/// # Errors
///
/// Malformed blob or AEAD authentication failure.
pub fn open_payload(key: &PayloadKey, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    if sealed.len() < SEALED_HEADER_LEN + 16 {
        return Err(SealError::BadBlob);
    }
    let magic = sealed.get(0..4).ok_or(SealError::BadBlob)?;
    if magic != SEALED_MAGIC {
        return Err(SealError::BadBlob);
    }
    let version = *sealed.get(4).ok_or(SealError::BadBlob)?;
    if version != SEALED_VERSION {
        return Err(SealError::BadBlob);
    }
    let nonce_bytes = sealed
        .get(5..5 + SEALED_NONCE_LEN)
        .ok_or(SealError::BadBlob)?;
    let mut nonce_arr = [0u8; SEALED_NONCE_LEN];
    nonce_arr.copy_from_slice(nonce_bytes);
    let ct = sealed.get(SEALED_HEADER_LEN..).ok_or(SealError::BadBlob)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| SealError::Decrypt)?;
    let nonce = XNonce::from_slice(&nonce_arr);
    cipher.decrypt(nonce, ct).map_err(|_| SealError::Decrypt)
}

/// Deterministic nonce from stream context (lab/tests; production should use CSPRNG).
///
/// Domain-separated so two different contexts never collide accidentally when
/// the same key seals two payloads.
#[must_use]
pub fn derived_nonce(context: &[u8]) -> [u8; SEALED_NONCE_LEN] {
    let h = hash_fields_bytes(&[b"BDLM_THREE_SEAL_NONCE_V1", context]);
    // `split_at` on the 32-byte digest cannot reach out of range, so the two
    // halves are taken without an index; the zip below is the measurement that
    // `SEALED_NONCE_LEN` is exactly 16 + 8, and a longer nonce would stay zero
    // in the tail rather than read past the digest.
    let (head, _) = h.split_at(16);
    // stretch with a second block half
    let h2 = hash_fields_bytes(&[b"BDLM_THREE_SEAL_NONCE2_V1", context]);
    let (tail, _) = h2.split_at(SEALED_NONCE_LEN - 16);
    let mut n = [0u8; SEALED_NONCE_LEN];
    for (slot, byte) in n.iter_mut().zip(head.iter().chain(tail)) {
        *slot = *byte;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::qr_payload::{pack_payload, unpack_payload, PayloadKind};

    #[test]
    fn seal_open_round_trip() {
        let key = PayloadKey::derive(b"test-secret-material");
        let nonce = derived_nonce(b"ctx-1");
        let pt = b"secret content bytes for three.0";
        let sealed = seal_payload(&key, &nonce, pt).unwrap();
        assert_eq!(&sealed[0..4], &SEALED_MAGIC);
        let got = open_payload(&key, &sealed).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn wrong_key_fails() {
        let key = PayloadKey::derive(b"a");
        let other = PayloadKey::derive(b"b");
        let sealed = seal_payload(&key, &derived_nonce(b"c"), b"hidden").unwrap();
        assert_eq!(
            open_payload(&other, &sealed).unwrap_err(),
            SealError::Decrypt
        );
    }

    #[test]
    fn tamper_fails() {
        let key = PayloadKey::derive(b"k");
        let mut sealed = seal_payload(&key, &derived_nonce(b"n"), b"body").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert_eq!(open_payload(&key, &sealed).unwrap_err(), SealError::Decrypt);
    }

    #[test]
    fn sealed_then_a1_pack() {
        let key = PayloadKey::derive(b"pipe-secret");
        let pt = b"g1 then a1 content";
        let sealed = seal_payload(&key, &derived_nonce(b"pipe"), pt).unwrap();
        let packed = pack_payload(PayloadKind::EncryptedContent, &sealed).unwrap();
        let (kind, body) = unpack_payload(&packed).unwrap();
        assert_eq!(kind, PayloadKind::EncryptedContent);
        assert_eq!(open_payload(&key, &body).unwrap(), pt);
    }
}
