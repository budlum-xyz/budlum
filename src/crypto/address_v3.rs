//! Address V3.
//!
//! An address binds three public keys: the post-quantum key and the Ed25519 key
//! of the composite signature, and the SLH-DSA-SHAKE-256s recovery key.
//! Only hashes of the keys enter the derivation, so an address does not reveal
//! a public key until the first spend.
//!
//! ```text
//! auth_v3 = SHA3-256("BDLM_ACCOUNT_AUTH_V3" || u16 suite_id
//!                    || SHA3-256(pq_pk) || SHA3-256(ed25519_pk) || SHA3-256(slhdsa_pk))
//! address = SHA3-256("BDLM_ADDRESS_V3" || auth_v3)
//! ```
//!
//! Every field is length prefixed (`u32` big endian), the tags included, so no
//! field boundary is ambiguous. The suite is written, never inferred from a
//! key length. The address stays 32 bytes.
//!
//! This file has no dependency on the rest of the node. `crates/wallet-core`
//! mounts the same source, so a wallet and a node derive the same address.

use super::composite::ED25519_PUBLIC_KEY_LEN;
use super::pq;
use super::scheme::SuiteId;
use sha3::{Digest, Sha3_256};

/// The domain tag of the account authentication commitment.
/// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const ACCOUNT_AUTH_TAG: &[u8] = b"BDLM_ACCOUNT_AUTH_V3";

/// The domain tag of the address.
/// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const ADDRESS_TAG: &[u8] = b"BDLM_ADDRESS_V3";

/// Why a key set cannot form an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressV3Error {
    /// The suite is not listed.
    UnknownSuite(SuiteId),
    /// The suite carries no recovery scheme, so it cannot own a V3 address.
    NoRecoveryScheme(SuiteId),
    /// A key length differs from the scheme the suite names.
    KeyLength {
        /// Which key.
        field: &'static str,
        /// The length the suite requires.
        expected: usize,
        /// The length given.
        got: usize,
    },
    /// The scheme of a component has no implementation here.
    Unsupported(SuiteId),
}

impl core::fmt::Display for AddressV3Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownSuite(s) => write!(f, "unknown suite {:#06x}", s.0),
            Self::NoRecoveryScheme(s) => {
                write!(f, "suite {:#06x} has no recovery scheme", s.0)
            }
            Self::KeyLength {
                field,
                expected,
                got,
            } => write!(f, "{field} length: expected {expected}, got {got}"),
            Self::Unsupported(s) => {
                write!(f, "suite {:#06x} has no implementation here", s.0)
            }
        }
    }
}

impl std::error::Error for AddressV3Error {}

fn put(hasher: &mut Sha3_256, field: &[u8]) {
    // A field longer than u32::MAX cannot occur: every caller passes a tag, a
    // two byte suite or a 32 byte digest.
    let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
    hasher.update(len.to_be_bytes());
    hasher.update(field);
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}

/// The key lengths a suite requires: the post-quantum key and the recovery key.
fn required_lengths(suite: SuiteId) -> Result<(usize, usize), AddressV3Error> {
    let info = suite.info().ok_or(AddressV3Error::UnknownSuite(suite))?;
    let recovery = info
        .recovery
        .ok_or(AddressV3Error::NoRecoveryScheme(suite))?;
    let pq_len = pq::public_key_len(info.pq).map_err(|_| AddressV3Error::Unsupported(suite))?;
    let recovery_len =
        pq::public_key_len(recovery).map_err(|_| AddressV3Error::Unsupported(suite))?;
    Ok((pq_len, recovery_len))
}

fn check_len(field: &'static str, expected: usize, got: usize) -> Result<(), AddressV3Error> {
    if expected == got {
        Ok(())
    } else {
        Err(AddressV3Error::KeyLength {
            field,
            expected,
            got,
        })
    }
}

/// `auth_v3` from the digests of the three keys.
///
/// A transaction witness carries the post-quantum and Ed25519 keys (it needs
/// them to verify) but only the digest of the recovery key, which is revealed
/// in a recovery transaction alone.
///
/// # Errors
///
/// [`AddressV3Error::UnknownSuite`] or [`AddressV3Error::NoRecoveryScheme`].
pub fn account_auth_v3_from_digests(
    suite: SuiteId,
    pq_digest: &[u8; 32],
    ed25519_digest: &[u8; 32],
    recovery_digest: &[u8; 32],
) -> Result<[u8; 32], AddressV3Error> {
    required_lengths(suite)?;
    let mut hasher = Sha3_256::new();
    put(&mut hasher, ACCOUNT_AUTH_TAG);
    put(&mut hasher, &suite.to_be_bytes());
    put(&mut hasher, pq_digest);
    put(&mut hasher, ed25519_digest);
    put(&mut hasher, recovery_digest);
    Ok(hasher.finalize().into())
}

/// The digest of one public key as it enters `auth_v3`.
#[must_use]
pub fn key_digest(public_key: &[u8]) -> [u8; 32] {
    digest(public_key)
}

/// `auth_v3`: the commitment to the three keys of an account under a suite.
///
/// # Errors
///
/// [`AddressV3Error`] when the suite is unlisted or has no recovery scheme, or
/// when a key length differs from what the suite requires.
pub fn account_auth_v3(
    suite: SuiteId,
    pq_public_key: &[u8],
    ed25519_public_key: &[u8],
    recovery_public_key: &[u8],
) -> Result<[u8; 32], AddressV3Error> {
    let (pq_len, recovery_len) = required_lengths(suite)?;
    check_len("pq public key", pq_len, pq_public_key.len())?;
    check_len(
        "ed25519 public key",
        ED25519_PUBLIC_KEY_LEN,
        ed25519_public_key.len(),
    )?;
    check_len(
        "recovery public key",
        recovery_len,
        recovery_public_key.len(),
    )?;
    account_auth_v3_from_digests(
        suite,
        &digest(pq_public_key),
        &digest(ed25519_public_key),
        &digest(recovery_public_key),
    )
}

/// The domain tag of a multisig owner leaf.
/// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const MULTISIG_LEAF_TAG: &[u8] = b"BDLM_MULTISIG_LEAF_V1";

/// The domain tag of a multisig address.
/// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const MULTISIG_ADDRESS_TAG: &[u8] = b"BDLM_MULTISIG_ADDRESS_V3";

/// The most owners a V8 multisig account can hold.
pub const MAX_MULTISIG_OWNERS: usize = 64;

/// The leaf of one multisig owner: the suite and the digests of both of its
/// public keys. A signer reveals the keys with the signature; the owner list
/// of the account carries only these 32 byte leaves.
///
/// # Errors
///
/// [`AddressV3Error::UnknownSuite`] for an unlisted suite.
pub fn multisig_owner_leaf(
    suite: SuiteId,
    pq_public_key: &[u8],
    ed25519_public_key: &[u8],
) -> Result<[u8; 32], AddressV3Error> {
    suite.info().ok_or(AddressV3Error::UnknownSuite(suite))?;
    let mut hasher = Sha3_256::new();
    put(&mut hasher, MULTISIG_LEAF_TAG);
    put(&mut hasher, &suite.to_be_bytes());
    put(&mut hasher, &digest(pq_public_key));
    put(&mut hasher, &digest(ed25519_public_key));
    Ok(hasher.finalize().into())
}

/// The address of a multisig account: the suite, the threshold, the sorted
/// owner leaves and the digest of the account's SLH-DSA recovery key.
///
/// The threshold is part of the preimage: `2-of-3` and `3-of-3` over the same
/// owners are different security statements and must not share an address.
///
/// # Errors
///
/// [`AddressV3Error`] for an unlisted suite or one without a recovery scheme.
pub fn multisig_address_v3(
    suite: SuiteId,
    owner_leaves: &[[u8; 32]],
    threshold: u32,
    recovery_digest: &[u8; 32],
) -> Result<[u8; 32], AddressV3Error> {
    required_lengths(suite)?;
    let mut sorted = owner_leaves.to_vec();
    sorted.sort_unstable();
    let mut hasher = Sha3_256::new();
    put(&mut hasher, MULTISIG_ADDRESS_TAG);
    put(&mut hasher, &suite.to_be_bytes());
    put(&mut hasher, &threshold.to_be_bytes());
    put(&mut hasher, &(sorted.len() as u32).to_be_bytes());
    for leaf in &sorted {
        put(&mut hasher, leaf);
    }
    put(&mut hasher, recovery_digest);
    Ok(hasher.finalize().into())
}

/// The address of an `auth_v3` commitment.
#[must_use]
pub fn address_from_auth(auth_v3: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    put(&mut hasher, ADDRESS_TAG);
    put(&mut hasher, auth_v3);
    hasher.finalize().into()
}

/// The V3 address of a key set.
///
/// # Errors
///
/// See [`account_auth_v3`].
pub fn address_v3(
    suite: SuiteId,
    pq_public_key: &[u8],
    ed25519_public_key: &[u8],
    recovery_public_key: &[u8],
) -> Result<[u8; 32], AddressV3Error> {
    let auth = account_auth_v3(
        suite,
        pq_public_key,
        ed25519_public_key,
        recovery_public_key,
    )?;
    Ok(address_from_auth(&auth))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (Vec<u8>, [u8; 32], Vec<u8>) {
        (vec![0x11; 2592], [0x22; 32], vec![0x33; 64])
    }

    #[test]
    fn address_is_deterministic_and_binds_every_key_and_the_suite() {
        let (pq, ed, slh) = keys();
        let base = address_v3(SuiteId::USER, &pq, &ed, &slh).unwrap();
        assert_eq!(base, address_v3(SuiteId::USER, &pq, &ed, &slh).unwrap());

        let mut pq2 = pq.clone();
        pq2[0] ^= 1;
        assert_ne!(base, address_v3(SuiteId::USER, &pq2, &ed, &slh).unwrap());
        let mut ed2 = ed;
        ed2[31] ^= 1;
        assert_ne!(base, address_v3(SuiteId::USER, &pq, &ed2, &slh).unwrap());
        let mut slh2 = slh.clone();
        slh2[63] ^= 1;
        assert_ne!(base, address_v3(SuiteId::USER, &pq, &ed, &slh2).unwrap());
    }

    #[test]
    fn suite_is_part_of_the_commitment() {
        // The same bytes under another suite fail on the key length, and the
        // commitment writes the suite id, so no two suites can share an address.
        let (pq, ed, slh) = keys();
        let auth = account_auth_v3(SuiteId::USER, &pq, &ed, &slh).unwrap();
        let mut hasher = Sha3_256::new();
        put(&mut hasher, ACCOUNT_AUTH_TAG);
        put(&mut hasher, &SuiteId::VALIDATOR.to_be_bytes());
        put(&mut hasher, &digest(&pq));
        put(&mut hasher, &digest(&ed));
        put(&mut hasher, &digest(&slh));
        let other: [u8; 32] = hasher.finalize().into();
        assert_ne!(auth, other);
    }

    #[test]
    fn the_address_is_not_the_auth_commitment() {
        let (pq, ed, slh) = keys();
        let auth = account_auth_v3(SuiteId::USER, &pq, &ed, &slh).unwrap();
        assert_ne!(auth, address_from_auth(&auth));
    }

    #[test]
    fn wrong_lengths_and_unfit_suites_are_refused() {
        let (pq, ed, slh) = keys();
        assert!(matches!(
            address_v3(SuiteId::USER, &pq[..2591], &ed, &slh),
            Err(AddressV3Error::KeyLength {
                field: "pq public key",
                ..
            })
        ));
        assert!(matches!(
            address_v3(SuiteId::USER, &pq, &ed[..31], &slh),
            Err(AddressV3Error::KeyLength {
                field: "ed25519 public key",
                ..
            })
        ));
        assert!(matches!(
            address_v3(SuiteId::USER, &pq, &ed, &slh[..32]),
            Err(AddressV3Error::KeyLength {
                field: "recovery public key",
                ..
            })
        ));
        assert_eq!(
            address_v3(SuiteId(0x7777), &pq, &ed, &slh),
            Err(AddressV3Error::UnknownSuite(SuiteId(0x7777)))
        );
        // The validator suite has no recovery key: it owns no V3 address.
        assert_eq!(
            address_v3(SuiteId::VALIDATOR, &pq, &ed, &slh),
            Err(AddressV3Error::NoRecoveryScheme(SuiteId::VALIDATOR))
        );
    }

    #[test]
    fn multisig_address_binds_threshold_owners_and_recovery() {
        let (pq, ed, _) = keys();
        let a = multisig_owner_leaf(SuiteId::USER, &pq, &ed).unwrap();
        let b = multisig_owner_leaf(SuiteId::USER, &pq, &[0x23; 32]).unwrap();
        let rec = [5u8; 32];
        let base = multisig_address_v3(SuiteId::USER, &[a, b], 2, &rec).unwrap();
        // Order does not matter, everything else does.
        assert_eq!(
            base,
            multisig_address_v3(SuiteId::USER, &[b, a], 2, &rec).unwrap()
        );
        assert_ne!(
            base,
            multisig_address_v3(SuiteId::USER, &[a, b], 1, &rec).unwrap()
        );
        assert_ne!(
            base,
            multisig_address_v3(SuiteId::USER, &[a], 2, &rec).unwrap()
        );
        assert_ne!(
            base,
            multisig_address_v3(SuiteId::USER, &[a, b], 2, &[6u8; 32]).unwrap()
        );
        assert_eq!(
            multisig_address_v3(SuiteId::VALIDATOR, &[a, b], 2, &rec),
            Err(AddressV3Error::NoRecoveryScheme(SuiteId::VALIDATOR))
        );
    }

    #[test]
    fn field_boundaries_are_length_prefixed() {
        // Pinned preimage layout: u32 length before every field.
        let (pq, ed, slh) = keys();
        let mut expected = Vec::new();
        let mut push = |f: &[u8]| {
            expected.extend_from_slice(&(f.len() as u32).to_be_bytes());
            expected.extend_from_slice(f);
        };
        push(b"BDLM_ACCOUNT_AUTH_V3");
        push(&[0x00, 0x01]);
        push(&Sha3_256::digest(&pq));
        push(&Sha3_256::digest(ed));
        push(&Sha3_256::digest(&slh));
        let by_hand: [u8; 32] = Sha3_256::digest(&expected).into();
        assert_eq!(
            by_hand,
            account_auth_v3(SuiteId::USER, &pq, &ed, &slh).unwrap()
        );
    }
}
