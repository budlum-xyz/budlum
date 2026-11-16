//! Hybrid public-key encryption for data keys.
//!
//! RFC 9180 Base mode with one fixed suite:
//!
//! | Part | Value |
//! |---|---|
//! | KEM | 0x647a, MLKEM768-X25519 (X-Wing, draft-ietf-hpke-pq) |
//! | KDF | 0x0001, HKDF-SHA256 |
//! | AEAD | 0x0003, ChaCha20-Poly1305 |
//!
//! The suite is not negotiated. An envelope that names any other KEM, KDF or
//! AEAD is refused when it is decoded, so the X25519-only KEM 0x0020 can never
//! be opened here: a recorded ciphertext of that suite is readable once a
//! quantum attacker exists.
//!
//! The recipient's KEM public key lives in the identity record and is signed
//! with the user suite. This module only encrypts to it and decrypts with the
//! matching secret. It does not write a KEM: the primitive is the `hpke` crate
//! over RustCrypto `ml-kem` and `x-wing`.

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::XWing, Deserializable, Kem as KemTrait, OpModeR,
    OpModeS, Serializable,
};
use zeroize::Zeroizing;

/// HPKE KEM identifier of MLKEM768-X25519.
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const HPKE_KEM_ID: u16 = 0x647a;
/// HPKE KDF identifier of HKDF-SHA256.
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const HPKE_KDF_ID: u16 = 0x0001;
/// HPKE AEAD identifier of ChaCha20-Poly1305.
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const HPKE_AEAD_ID: u16 = 0x0003;

/// Length of a KEM public key: ML-KEM-768 (1,184) plus X25519 (32).
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const HPKE_PUBLIC_KEY_LEN: usize = 1216;
/// Length of the encapsulated key: ML-KEM-768 ciphertext (1,088) plus X25519 (32).
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const HPKE_ENCAPPED_KEY_LEN: usize = 1120;
/// Length of the KEM secret key, which is also its derivation seed.
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const HPKE_SECRET_KEY_LEN: usize = 32;

/// Length of the Poly1305 tag the AEAD appends.
const AEAD_TAG_LEN: usize = 16;
/// Length of the encoded suite header: KEM, KDF and AEAD identifiers.
const SUITE_HEADER_LEN: usize = 6;

const INFO_TAG: &[u8] = b"BDLM_HPKE_INFO_V1";

/// Why an HPKE operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HpkeError {
    /// The envelope names a suite other than 0x647a, 0x0001, 0x0003.
    UnsupportedSuite { kem: u16, kdf: u16, aead: u16 },
    /// A key or an envelope has the wrong length.
    BadLength {
        what: &'static str,
        expected: usize,
        got: usize,
    },
    /// The bytes are not a valid key or encapsulated key.
    BadKey(&'static str),
    /// Encapsulation or encryption failed.
    Seal,
    /// Decapsulation or authentication failed: wrong recipient, wrong
    /// `info` or `aad`, or a modified envelope.
    Open,
}

impl std::fmt::Display for HpkeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSuite { kem, kdf, aead } => write!(
                f,
                "unsupported HPKE suite kem=0x{kem:04x} kdf=0x{kdf:04x} aead=0x{aead:04x}; \
                 only 0x{HPKE_KEM_ID:04x}/0x{HPKE_KDF_ID:04x}/0x{HPKE_AEAD_ID:04x} is accepted"
            ),
            Self::BadLength {
                what,
                expected,
                got,
            } => {
                write!(f, "{what} must be {expected} bytes, got {got}")
            }
            Self::BadKey(what) => write!(f, "invalid HPKE {what}"),
            Self::Seal => write!(f, "HPKE seal failed"),
            Self::Open => write!(f, "HPKE open failed"),
        }
    }
}

impl std::error::Error for HpkeError {}

/// The recipient's key pair. The secret is zeroized on drop.
pub struct HpkeKeyPair {
    secret: Zeroizing<[u8; HPKE_SECRET_KEY_LEN]>,
    public: [u8; HPKE_PUBLIC_KEY_LEN],
}

impl HpkeKeyPair {
    /// A fresh key pair from the operating system's randomness.
    pub fn generate() -> Self {
        let (sk, pk) = XWing::gen_keypair();
        Self::from_parts(&sk, &pk)
    }

    /// The key pair of a 32-byte seed. The wallet derives the seed on its
    /// `BDLM_KDF_XWING_V1` branch.
    ///
    /// # Errors
    ///
    /// Fails when the seed is not [`HPKE_SECRET_KEY_LEN`] bytes.
    pub fn from_seed(seed: &[u8]) -> Result<Self, HpkeError> {
        if seed.len() != HPKE_SECRET_KEY_LEN {
            return Err(HpkeError::BadLength {
                what: "HPKE secret key seed",
                expected: HPKE_SECRET_KEY_LEN,
                got: seed.len(),
            });
        }
        let sk = <XWing as KemTrait>::PrivateKey::from_bytes(seed)
            .map_err(|_| HpkeError::BadKey("secret key"))?;
        let pk = XWing::sk_to_pk(&sk);
        Ok(Self::from_parts(&sk, &pk))
    }

    fn from_parts(
        sk: &<XWing as KemTrait>::PrivateKey,
        pk: &<XWing as KemTrait>::PublicKey,
    ) -> Self {
        let mut secret = Zeroizing::new([0u8; HPKE_SECRET_KEY_LEN]);
        secret.copy_from_slice(sk.to_bytes().as_slice());
        let mut public = [0u8; HPKE_PUBLIC_KEY_LEN];
        public.copy_from_slice(pk.to_bytes().as_slice());
        Self { secret, public }
    }

    /// The KEM public key, [`HPKE_PUBLIC_KEY_LEN`] bytes.
    pub fn public_key(&self) -> &[u8; HPKE_PUBLIC_KEY_LEN] {
        &self.public
    }

    /// Opens an envelope sealed to this key pair.
    ///
    /// # Errors
    ///
    /// [`HpkeError::Open`] for a wrong recipient, a wrong `info` or `aad`, or
    /// a modified envelope. It never says which.
    pub fn open(
        &self,
        info: &[u8],
        aad: &[u8],
        envelope: &HpkeEnvelope,
    ) -> Result<Vec<u8>, HpkeError> {
        let sk = <XWing as KemTrait>::PrivateKey::from_bytes(self.secret.as_slice())
            .map_err(|_| HpkeError::BadKey("secret key"))?;
        let enc = <XWing as KemTrait>::EncappedKey::from_bytes(&envelope.enc)
            .map_err(|_| HpkeError::BadKey("encapsulated key"))?;
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeR::Base,
            &sk,
            &enc,
            &bound_info(info),
            &envelope.ciphertext,
            aad,
        )
        .map_err(|_| HpkeError::Open)
    }
}

impl std::fmt::Debug for HpkeKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HpkeKeyPair").finish_non_exhaustive()
    }
}

/// A sealed message: the encapsulated key and the AEAD ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpkeEnvelope {
    enc: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl HpkeEnvelope {
    /// Encrypts `plaintext` to the recipient's KEM public key.
    ///
    /// `info` and `aad` bind the envelope to its purpose: they are not
    /// transmitted, and the recipient has to supply the same values.
    ///
    /// # Errors
    ///
    /// Fails when `recipient_public` is not a valid [`HPKE_PUBLIC_KEY_LEN`]
    /// byte key.
    pub fn seal(
        recipient_public: &[u8],
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Self, HpkeError> {
        if recipient_public.len() != HPKE_PUBLIC_KEY_LEN {
            return Err(HpkeError::BadLength {
                what: "HPKE recipient public key",
                expected: HPKE_PUBLIC_KEY_LEN,
                got: recipient_public.len(),
            });
        }
        let pk = <XWing as KemTrait>::PublicKey::from_bytes(recipient_public)
            .map_err(|_| HpkeError::BadKey("recipient public key"))?;
        let (enc, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeS::Base,
            &pk,
            &bound_info(info),
            plaintext,
            aad,
        )
        .map_err(|_| HpkeError::Seal)?;
        Ok(Self {
            enc: enc.to_bytes().to_vec(),
            ciphertext,
        })
    }

    /// The encapsulated key.
    /// WIRING: unwired - no caller in this tree yet; kept as a declared surface, and nothing depends on it until one arrives.
    pub fn encapsulated_key(&self) -> &[u8] {
        &self.enc
    }

    /// The AEAD ciphertext, tag included.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Canonical encoding: `kem || kdf || aead` as big-endian `u16`, the
    /// encapsulated key, then the ciphertext. The ciphertext runs to the end.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SUITE_HEADER_LEN + self.enc.len() + self.ciphertext.len());
        out.extend_from_slice(&HPKE_KEM_ID.to_be_bytes());
        out.extend_from_slice(&HPKE_KDF_ID.to_be_bytes());
        out.extend_from_slice(&HPKE_AEAD_ID.to_be_bytes());
        out.extend_from_slice(&self.enc);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Decodes an envelope, refusing any suite but 0x647a/0x0001/0x0003.
    ///
    /// # Errors
    ///
    /// [`HpkeError::UnsupportedSuite`] for another suite (0x0020 included),
    /// [`HpkeError::BadLength`] for a short input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HpkeError> {
        let minimum = SUITE_HEADER_LEN + HPKE_ENCAPPED_KEY_LEN + AEAD_TAG_LEN;
        if bytes.len() < minimum {
            return Err(HpkeError::BadLength {
                what: "HPKE envelope",
                expected: minimum,
                got: bytes.len(),
            });
        }
        let kem = u16::from_be_bytes([bytes[0], bytes[1]]);
        let kdf = u16::from_be_bytes([bytes[2], bytes[3]]);
        let aead = u16::from_be_bytes([bytes[4], bytes[5]]);
        if (kem, kdf, aead) != (HPKE_KEM_ID, HPKE_KDF_ID, HPKE_AEAD_ID) {
            return Err(HpkeError::UnsupportedSuite { kem, kdf, aead });
        }
        let body = &bytes[SUITE_HEADER_LEN..];
        let (enc, ciphertext) = body.split_at(HPKE_ENCAPPED_KEY_LEN);
        Ok(Self {
            enc: enc.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// The `info` string the suite sees: the tag, then the caller's value, each
/// length prefixed so no caller value can run into the tag.
fn bound_info(info: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + INFO_TAG.len() + info.len());
    out.extend_from_slice(&(INFO_TAG.len() as u64).to_le_bytes());
    out.extend_from_slice(INFO_TAG);
    out.extend_from_slice(&(info.len() as u64).to_le_bytes());
    out.extend_from_slice(info);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Sha3_256};

    fn sha3(bytes: &[u8]) -> String {
        hex::encode(Sha3_256::digest(bytes))
    }

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&hex::decode(s).unwrap());
        out
    }

    /// X-Wing known-answer vectors (RustCrypto/KEMs `x-wing` test vectors 0
    /// and 1): the 32-byte secret and the SHA3-256 of the 1,216-byte public
    /// key it expands to.
    #[test]
    fn kat_seed_expands_to_the_published_public_key() {
        let vectors: [([u8; 32], &str); 2] = [
            (
                unhex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"),
                "5121745904643ad9dfacca7869292c19a8a69533b53e60666b7db910b4ad6367",
            ),
            (
                unhex("badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea"),
                "799b6016e5daa56ffa1b5e79f7caf73413ceecd6df428642404cac41ddee4853",
            ),
        ];
        for (seed, public_hash) in vectors {
            let pair = HpkeKeyPair::from_seed(&seed).unwrap();
            assert_eq!(pair.public_key().len(), HPKE_PUBLIC_KEY_LEN);
            assert_eq!(sha3(pair.public_key()), public_hash);
        }
    }

    #[test]
    fn suite_constants_are_the_decided_ones() {
        assert_eq!(HPKE_KEM_ID, 0x647a);
        assert_eq!(HPKE_KDF_ID, 0x0001);
        assert_eq!(HPKE_AEAD_ID, 0x0003);
        assert_eq!(
            HPKE_PUBLIC_KEY_LEN as u16,
            crate::pollen::data_rights::HPKE_MLKEM768_X25519_PUBLIC_KEY_BYTES
        );
    }

    #[test]
    fn round_trip_opens_for_the_recipient() {
        let pair = HpkeKeyPair::generate();
        let envelope = HpkeEnvelope::seal(
            pair.public_key(),
            b"content key",
            b"grant 7",
            b"secret bytes",
        )
        .unwrap();
        assert_eq!(envelope.encapsulated_key().len(), HPKE_ENCAPPED_KEY_LEN);
        let opened = pair.open(b"content key", b"grant 7", &envelope).unwrap();
        assert_eq!(opened, b"secret bytes");
    }

    #[test]
    fn wire_encoding_round_trips() {
        let pair = HpkeKeyPair::generate();
        let envelope = HpkeEnvelope::seal(pair.public_key(), b"i", b"a", b"payload").unwrap();
        let bytes = envelope.to_bytes();
        assert_eq!(&bytes[..6], &[0x64, 0x7a, 0x00, 0x01, 0x00, 0x03]);
        let decoded = HpkeEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(pair.open(b"i", b"a", &decoded).unwrap(), b"payload");
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let alice = HpkeKeyPair::generate();
        let mallory = HpkeKeyPair::generate();
        let envelope = HpkeEnvelope::seal(alice.public_key(), b"i", b"a", b"payload").unwrap();
        assert_eq!(mallory.open(b"i", b"a", &envelope), Err(HpkeError::Open));
    }

    #[test]
    fn wrong_info_or_aad_cannot_open() {
        let pair = HpkeKeyPair::generate();
        let envelope = HpkeEnvelope::seal(pair.public_key(), b"i", b"a", b"payload").unwrap();
        assert_eq!(pair.open(b"other", b"a", &envelope), Err(HpkeError::Open));
        assert_eq!(pair.open(b"i", b"other", &envelope), Err(HpkeError::Open));
    }

    #[test]
    fn modified_ciphertext_or_key_cannot_open() {
        let pair = HpkeKeyPair::generate();
        let envelope = HpkeEnvelope::seal(pair.public_key(), b"i", b"a", b"payload").unwrap();

        let mut bytes = envelope.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = HpkeEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(pair.open(b"i", b"a", &tampered), Err(HpkeError::Open));

        let mut bytes = envelope.to_bytes();
        bytes[SUITE_HEADER_LEN] ^= 1;
        let tampered = HpkeEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(pair.open(b"i", b"a", &tampered), Err(HpkeError::Open));
    }

    #[test]
    fn x25519_only_suite_is_refused() {
        let pair = HpkeKeyPair::generate();
        let envelope = HpkeEnvelope::seal(pair.public_key(), b"i", b"a", b"payload").unwrap();
        let mut bytes = envelope.to_bytes();
        bytes[0..2].copy_from_slice(&0x0020u16.to_be_bytes());
        assert_eq!(
            HpkeEnvelope::from_bytes(&bytes),
            Err(HpkeError::UnsupportedSuite {
                kem: 0x0020,
                kdf: HPKE_KDF_ID,
                aead: HPKE_AEAD_ID,
            })
        );
    }

    #[test]
    fn short_inputs_are_refused() {
        assert!(matches!(
            HpkeEnvelope::from_bytes(&[0u8; 10]),
            Err(HpkeError::BadLength { .. })
        ));
        assert!(matches!(
            HpkeEnvelope::seal(&[0u8; 32], b"i", b"a", b"x"),
            Err(HpkeError::BadLength { .. })
        ));
        assert!(matches!(
            HpkeKeyPair::from_seed(&[0u8; 16]),
            Err(HpkeError::BadLength { .. })
        ));
    }

    #[test]
    fn info_cannot_run_into_the_tag() {
        assert_ne!(bound_info(b"ab"), bound_info(b"a"));
        let mut run_on = INFO_TAG.to_vec();
        run_on.extend_from_slice(b"x");
        assert_ne!(bound_info(&run_on), bound_info(b"x"));
    }
}
