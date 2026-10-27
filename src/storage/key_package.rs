//! Content-key delivery for view grants.
//!
//! A [`ViewGrant`](crate::storage::view_grant::ViewGrant) says who may open content and names a
//! `key_id`, never the key. This module is the delivery that was left "out of
//! band": the content key is encrypted to the grantee's HPKE public key
//! (KEM 0x647a, see [`crate::crypto::hpke`]), the sealed package travels off
//! chain (DM, storage node, link), and the chain keeps only the package hash.
//!
//! The hash is the grant's `key_id`. `key_id` already enters the signed
//! issuance digest and the grant commitment, so binding the package to the
//! permission record needs no new wire field: whoever opens a package first
//! checks that its hash is the `key_id` of the live grant. A package that
//! was modified, swapped for another grantee's, or copied from another
//! content's grant does not hash to that `key_id` and is refused before any
//! decryption runs.
//!
//! Packages are for [`ViewPolicy::NamedGrantee`](crate::storage::view_grant::ViewPolicy): the key
//! is sealed to one recipient. A public-link grant has no recipient, so its
//! key travels in the link and this module does not apply.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::crypto::hpke::{HpkeEnvelope, HpkeError, HpkeKeyPair};
use crate::storage::content_id::ContentId;
use crate::storage::view_grant::{ViewGrant, ViewPolicy};

/// Length of a content key: 256 bits.
pub const CONTENT_KEY_LEN: usize = 32;

const PACKAGE_HASH_TAG: &[u8] = b"BDLM_KEY_PACKAGE_V1";
const PACKAGE_INFO_TAG: &[u8] = b"BDLM_KEY_PACKAGE_INFO_V1";

/// Why a key package was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyPackageError {
    /// The grant is revoked: no new opens.
    GrantRevoked,
    /// The grant is not a named-grantee grant, so it has no recipient to seal to.
    NotNamedGrantee,
    /// The package belongs to other content than the grant.
    WrongContent,
    /// The package is sealed for another grantee than the grant names.
    WrongGrantee,
    /// The package hash is not the grant's `key_id`.
    HashMismatch,
    /// The sealed bytes do not decode.
    Malformed(HpkeError),
    /// HPKE refused: wrong recipient key or a modified envelope.
    Hpke(HpkeError),
    /// The opened plaintext is not a [`CONTENT_KEY_LEN`] byte key.
    BadKeyLength(usize),
}

impl std::fmt::Display for KeyPackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GrantRevoked => write!(f, "the view grant is revoked"),
            Self::NotNamedGrantee => write!(f, "only a named-grantee grant carries a key package"),
            Self::WrongContent => write!(f, "the key package is for other content"),
            Self::WrongGrantee => write!(f, "the key package is sealed for another grantee"),
            Self::HashMismatch => write!(f, "the key package hash is not the grant key_id"),
            Self::Malformed(e) => write!(f, "malformed key package: {e}"),
            Self::Hpke(e) => write!(f, "key package refused: {e}"),
            Self::BadKeyLength(n) => {
                write!(f, "content key must be {CONTENT_KEY_LEN} bytes, got {n}")
            }
        }
    }
}

impl std::error::Error for KeyPackageError {}

/// A content key sealed to one grantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPackage {
    content_id: ContentId,
    grantee: Address,
    envelope: HpkeEnvelope,
}

impl KeyPackage {
    /// Seals `content_key` to `grantee_public`, the HPKE public key in the
    /// grantee's signed identity record.
    ///
    /// # Errors
    ///
    /// [`KeyPackageError::BadKeyLength`] for a key that is not 32 bytes, or
    /// the HPKE refusal for a malformed recipient key.
    pub fn seal(
        content_id: ContentId,
        issuer: &Address,
        grantee: Address,
        grantee_public: &[u8],
        content_key: &[u8],
    ) -> Result<Self, KeyPackageError> {
        if content_key.len() != CONTENT_KEY_LEN {
            return Err(KeyPackageError::BadKeyLength(content_key.len()));
        }
        let envelope = HpkeEnvelope::seal(
            grantee_public,
            &package_info(&content_id, issuer, &grantee),
            &package_aad(&content_id, &grantee),
            content_key,
        )
        .map_err(KeyPackageError::Hpke)?;
        Ok(Self {
            content_id,
            grantee,
            envelope,
        })
    }

    /// The hash the chain keeps. Use it as the grant's `key_id`.
    #[must_use]
    pub fn package_hash(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            PACKAGE_HASH_TAG,
            &self.content_id.0,
            self.grantee.as_bytes(),
            &self.envelope.to_bytes(),
        ])
    }

    /// The bytes that travel off chain.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.content_id.0);
        out.extend_from_slice(self.grantee.as_bytes());
        out.extend_from_slice(&self.envelope.to_bytes());
        out
    }

    /// Decodes the off-chain bytes. Nothing is trusted yet: [`Self::open`]
    /// checks the hash against the grant.
    ///
    /// # Errors
    ///
    /// [`KeyPackageError::Malformed`] for a short input or a suite other than
    /// 0x647a (0x0020 included).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyPackageError> {
        if bytes.len() < 64 {
            return Err(KeyPackageError::Malformed(HpkeError::BadLength {
                what: "key package",
                expected: 64,
                got: bytes.len(),
            }));
        }
        let mut content = [0u8; 32];
        content.copy_from_slice(&bytes[..32]);
        let mut grantee = [0u8; 32];
        grantee.copy_from_slice(&bytes[32..64]);
        let envelope =
            HpkeEnvelope::from_bytes(&bytes[64..]).map_err(KeyPackageError::Malformed)?;
        Ok(Self {
            content_id: ContentId(content),
            grantee: Address::from(grantee),
            envelope,
        })
    }

    /// Opens the package for the live grant that names it.
    ///
    /// The order is the point: the grant is live and names this content and
    /// grantee, and the package hash equals the grant's `key_id`, all before
    /// the key pair is touched. A modified package therefore fails on the
    /// hash, not on a decryption oracle.
    ///
    /// # Errors
    ///
    /// The first check that fails, see [`KeyPackageError`].
    pub fn open(
        &self,
        grant: &ViewGrant,
        recipient: &HpkeKeyPair,
    ) -> Result<Vec<u8>, KeyPackageError> {
        if !grant.is_live() {
            return Err(KeyPackageError::GrantRevoked);
        }
        if grant.policy != ViewPolicy::NamedGrantee {
            return Err(KeyPackageError::NotNamedGrantee);
        }
        if grant.content_id != self.content_id {
            return Err(KeyPackageError::WrongContent);
        }
        if grant.grantee != Some(self.grantee) {
            return Err(KeyPackageError::WrongGrantee);
        }
        if grant.key_id != self.package_hash() {
            return Err(KeyPackageError::HashMismatch);
        }
        let key = recipient
            .open(
                &package_info(&self.content_id, &grant.issuer, &self.grantee),
                &package_aad(&self.content_id, &self.grantee),
                &self.envelope,
            )
            .map_err(KeyPackageError::Hpke)?;
        if key.len() != CONTENT_KEY_LEN {
            return Err(KeyPackageError::BadKeyLength(key.len()));
        }
        Ok(key)
    }
}

/// HPKE `info`: the purpose, the content, the issuer and the grantee.
fn package_info(content_id: &ContentId, issuer: &Address, grantee: &Address) -> Vec<u8> {
    let mut out = Vec::new();
    for field in [
        PACKAGE_INFO_TAG,
        content_id.0.as_slice(),
        issuer.as_bytes().as_slice(),
        grantee.as_bytes().as_slice(),
    ] {
        out.extend_from_slice(&(field.len() as u64).to_le_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// HPKE `aad`: the content and the grantee.
fn package_aad(content_id: &ContentId, grantee: &Address) -> Vec<u8> {
    let mut out = Vec::new();
    for field in [content_id.0.as_slice(), grantee.as_bytes().as_slice()] {
        out.extend_from_slice(&(field.len() as u64).to_le_bytes());
        out.extend_from_slice(field);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::view_grant::ViewGrantRegistry;

    fn cid(n: u8) -> ContentId {
        ContentId([n; 32])
    }

    fn addr(n: u8) -> Address {
        Address::from([n; 32])
    }

    /// A grant issued the way the chain would: `key_id` is the package hash.
    fn issue(
        content: ContentId,
        issuer: Address,
        grantee: Address,
        package: &KeyPackage,
    ) -> ViewGrant {
        let mut registry = ViewGrantRegistry::new();
        let id = registry
            .issue(
                content,
                issuer,
                Some(grantee),
                package.package_hash(),
                ViewPolicy::NamedGrantee,
                1,
            )
            .unwrap();
        registry.get(id).unwrap().clone()
    }

    #[test]
    fn grantee_opens_the_key_the_owner_sealed() {
        let bob = HpkeKeyPair::generate();
        let key = [7u8; CONTENT_KEY_LEN];
        let package = KeyPackage::seal(cid(1), &addr(2), addr(3), bob.public_key(), &key).unwrap();
        let grant = issue(cid(1), addr(2), addr(3), &package);
        assert_eq!(package.open(&grant, &bob).unwrap(), key);
    }

    #[test]
    fn package_survives_the_wire() {
        let bob = HpkeKeyPair::generate();
        let package =
            KeyPackage::seal(cid(1), &addr(2), addr(3), bob.public_key(), &[9u8; 32]).unwrap();
        let grant = issue(cid(1), addr(2), addr(3), &package);
        let decoded = KeyPackage::from_bytes(&package.to_bytes()).unwrap();
        assert_eq!(decoded.package_hash(), package.package_hash());
        assert_eq!(decoded.open(&grant, &bob).unwrap(), [9u8; 32]);
    }

    #[test]
    fn modified_package_is_refused_on_the_hash() {
        let bob = HpkeKeyPair::generate();
        let package =
            KeyPackage::seal(cid(1), &addr(2), addr(3), bob.public_key(), &[9u8; 32]).unwrap();
        let grant = issue(cid(1), addr(2), addr(3), &package);

        let mut bytes = package.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = KeyPackage::from_bytes(&bytes).unwrap();
        assert_eq!(
            tampered.open(&grant, &bob),
            Err(KeyPackageError::HashMismatch)
        );
    }

    #[test]
    fn package_of_another_grantee_or_content_is_refused() {
        let bob = HpkeKeyPair::generate();
        let eve = HpkeKeyPair::generate();
        let bobs =
            KeyPackage::seal(cid(1), &addr(2), addr(3), bob.public_key(), &[9u8; 32]).unwrap();
        let eves =
            KeyPackage::seal(cid(1), &addr(2), addr(4), eve.public_key(), &[9u8; 32]).unwrap();
        let grant = issue(cid(1), addr(2), addr(3), &bobs);
        assert_eq!(eves.open(&grant, &eve), Err(KeyPackageError::WrongGrantee));

        let other_content =
            KeyPackage::seal(cid(5), &addr(2), addr(3), bob.public_key(), &[9u8; 32]).unwrap();
        assert_eq!(
            other_content.open(&grant, &bob),
            Err(KeyPackageError::WrongContent)
        );
    }

    #[test]
    fn wrong_recipient_key_cannot_open_even_with_the_right_grant() {
        let bob = HpkeKeyPair::generate();
        let eve = HpkeKeyPair::generate();
        let package =
            KeyPackage::seal(cid(1), &addr(2), addr(3), bob.public_key(), &[9u8; 32]).unwrap();
        let grant = issue(cid(1), addr(2), addr(3), &package);
        assert!(matches!(
            package.open(&grant, &eve),
            Err(KeyPackageError::Hpke(HpkeError::Open))
        ));
    }

    #[test]
    fn revoked_grant_opens_nothing() {
        let bob = HpkeKeyPair::generate();
        let package =
            KeyPackage::seal(cid(1), &addr(2), addr(3), bob.public_key(), &[9u8; 32]).unwrap();
        let mut grant = issue(cid(1), addr(2), addr(3), &package);
        grant.revoked_epoch = Some(2);
        assert_eq!(
            package.open(&grant, &bob),
            Err(KeyPackageError::GrantRevoked)
        );
    }

    #[test]
    fn key_must_be_256_bits() {
        let bob = HpkeKeyPair::generate();
        assert_eq!(
            KeyPackage::seal(cid(1), &addr(2), addr(3), bob.public_key(), &[0u8; 16]),
            Err(KeyPackageError::BadKeyLength(16))
        );
    }

    #[test]
    fn x25519_only_package_does_not_decode() {
        let bob = HpkeKeyPair::generate();
        let package =
            KeyPackage::seal(cid(1), &addr(2), addr(3), bob.public_key(), &[9u8; 32]).unwrap();
        let mut bytes = package.to_bytes();
        bytes[64..66].copy_from_slice(&0x0020u16.to_be_bytes());
        assert!(matches!(
            KeyPackage::from_bytes(&bytes),
            Err(KeyPackageError::Malformed(
                HpkeError::UnsupportedSuite { .. }
            ))
        ));
    }
}
