//! Resealing: a seal whose only signature family the
//! quantum alarm took away is replaced by a seal of a family that still stands.
//!
//! WIRING: wired through `PqCanonicalSource::accept_reseal`
//! (`src/domain/pq_canonical.rs`), which the node calls with a certificate it
//! built or received; the Unsealed state it clears is read by the regeneration
//! health tick through `SealId::is_live`. Rules are pinned by this file's
//! tests.
//!
//! # The Unsealed state
//!
//! An anchor is sealed by ML-DSA-87. When the alarm raises a lattice break,
//! the ML-DSA family goes to `Disabled` and every anchor that only that family
//! signed is *Unsealed*: its commitment is still on record, but no live
//! post-quantum family stands behind it, so regeneration may not trust it
//!. The same holds for Root Seals and a hash-signature break.
//!
//! # The reseal certificate
//!
//! A [`ResealCertificate`] commits to the unsealed anchors of a height range
//! (`covered_root` over `(height, aggregate_root)` leaves, in height order) and
//! is signed by a family that is still live:
//!
//! - after a **lattice break**, by an SLH-DSA-SHAKE-256s seal key of the key
//!   ledger;
//! - after a **hash-signature break**, by two of the three ML-DSA-87 anchor
//!   keys.
//!
//! Both sign under the FIPS context `BDLM/RESEAL/V1`. A certificate signed by a
//! family the registry no longer verifies is refused: a reseal by the broken
//! family would prove nothing.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use super::anchor_ledger::{AnchorKeyLedger, KeyFamily, ANCHOR_THRESHOLD};
use super::pq_anchor::AnchorSignature;
use crate::consensus::merkle_tree::{combine_sha3, merkle_root, promote_sha3};
use crate::crypto::pkcs11::HsmPqKey;
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};

/// Anchors one certificate covers at most.
pub const MAX_RESEAL_ANCHORS: usize = 512;

/// Who signed a reseal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResealAuthority {
    /// One SLH-DSA-SHAKE-256s key of the ledger's seal keys.
    SealKey {
        /// The slot in the ledger's seal keys.
        index: u8,
        /// The signature.
        signature: Vec<u8>,
    },
    /// Two of the three ML-DSA-87 anchor keys of the ledger.
    AnchorKeys(Vec<AnchorSignature>),
}

impl ResealAuthority {
    /// The scheme the authority signs under.
    #[must_use]
    pub fn scheme(&self) -> SchemeId {
        match self {
            Self::SealKey { .. } => SchemeId::SLH_DSA_SHAKE_256S,
            Self::AnchorKeys(_) => SchemeId::ML_DSA_87,
        }
    }
}

/// A reseal: the anchors of `from_height..=to_height` that were Unsealed, now
/// sealed by a live family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResealCertificate {
    /// The chain.
    pub chain_id: u64,
    /// The key epoch of the signing keys.
    pub key_epoch: u32,
    /// First covered height.
    pub from_height: u64,
    /// Last covered height.
    pub to_height: u64,
    /// The Merkle root over the covered `(height, aggregate_root)` leaves.
    pub covered_root: [u8; 32],
    /// How many anchors the root covers.
    pub count: u32,
    /// The signatures.
    pub authority: ResealAuthority,
}

/// Why a reseal was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResealError {
    /// No anchor to cover, or more than [`MAX_RESEAL_ANCHORS`].
    BadCoverage,
    /// The range is empty or reversed.
    BadRange,
    /// The certificate belongs to another chain.
    WrongChain,
    /// The key epoch is not the ledger's.
    StaleKeyEpoch,
    /// The slot is not in the ledger, or is suspended.
    UnknownOrSuspendedKey,
    /// The signing family no longer verifies under the scheme registry.
    SignerFamilyDead,
    /// Fewer than two distinct anchor keys signed.
    ThresholdNotReached,
    /// The covered anchors do not hash to the certificate root.
    CoveredMismatch,
    /// A signature did not verify.
    InvalidSignature,
}

fn leaf(height: u64, aggregate_root: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_RESEAL_LEAF_V1");
    hasher.update(height.to_le_bytes());
    hasher.update(aggregate_root);
    hasher.finalize().into()
}

/// The root over `(height, aggregate_root)` pairs, which must ascend.
///
/// # Errors
///
/// [`ResealError::BadCoverage`] for none, too many, or heights that do not
/// strictly ascend.
pub fn covered_root(anchors: &[(u64, [u8; 32])]) -> Result<[u8; 32], ResealError> {
    if anchors.is_empty() || anchors.len() > MAX_RESEAL_ANCHORS {
        return Err(ResealError::BadCoverage);
    }
    if anchors.windows(2).any(|pair| pair[1].0 <= pair[0].0) {
        return Err(ResealError::BadCoverage);
    }
    let leaves: Vec<[u8; 32]> = anchors.iter().map(|(h, r)| leaf(*h, r)).collect();
    Ok(merkle_root(&leaves, combine_sha3, promote_sha3))
}

/// The bytes both authorities sign.
#[must_use]
pub fn reseal_payload(cert: &ResealCertificate) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 8 + 4 + 8 + 8 + 32 + 4);
    out.extend_from_slice(b"BDLM_RESEAL_V1");
    out.extend_from_slice(&cert.chain_id.to_le_bytes());
    out.extend_from_slice(&cert.key_epoch.to_le_bytes());
    out.extend_from_slice(&cert.from_height.to_le_bytes());
    out.extend_from_slice(&cert.to_height.to_le_bytes());
    out.extend_from_slice(&cert.covered_root);
    out.extend_from_slice(&cert.count.to_le_bytes());
    out
}

/// A certificate for the covered anchors with no signature yet.
///
/// # Errors
///
/// [`ResealError::BadCoverage`].
pub fn unsigned_certificate(
    chain_id: u64,
    key_epoch: u32,
    covered: &[(u64, [u8; 32])],
) -> Result<ResealCertificate, ResealError> {
    let root = covered_root(covered)?;
    let (Some(first), Some(last)) = (covered.first(), covered.last()) else {
        return Err(ResealError::BadCoverage);
    };
    Ok(ResealCertificate {
        chain_id,
        key_epoch,
        from_height: first.0,
        to_height: last.0,
        covered_root: root,
        count: u32::try_from(covered.len()).map_err(|_| ResealError::BadCoverage)?,
        authority: ResealAuthority::AnchorKeys(Vec::new()),
    })
}

/// Sign the certificate with an SLH-DSA seal key held in a token (or a test
/// double): the authority after a lattice break.
///
/// # Errors
///
/// [`ResealError::InvalidSignature`] when the key refuses.
pub fn sign_with_seal_key(
    mut cert: ResealCertificate,
    index: u8,
    key: &dyn HsmPqKey,
) -> Result<ResealCertificate, ResealError> {
    let payload = reseal_payload(&cert);
    let signature = key
        .sign(crate::crypto::ctx::RESEAL_V1, &payload)
        .map_err(|_| ResealError::InvalidSignature)?;
    cert.authority = ResealAuthority::SealKey { index, signature };
    Ok(cert)
}

/// Sign the certificate with ML-DSA-87 anchor keys: the authority after a
/// hash-signature break. `keys` pairs a ledger slot with its key.
///
/// # Errors
///
/// [`ResealError::ThresholdNotReached`] when fewer than two keys signed.
pub fn sign_with_anchor_keys(
    mut cert: ResealCertificate,
    keys: &[(u8, &dyn HsmPqKey)],
) -> Result<ResealCertificate, ResealError> {
    let payload = reseal_payload(&cert);
    let mut signatures = Vec::new();
    for (index, key) in keys {
        if let Ok(signature) = key.sign(crate::crypto::ctx::RESEAL_V1, &payload) {
            signatures.push(AnchorSignature {
                key_index: *index,
                signature,
            });
        }
    }
    if signatures.len() < ANCHOR_THRESHOLD {
        return Err(ResealError::ThresholdNotReached);
    }
    signatures.sort_by_key(|s| s.key_index);
    cert.authority = ResealAuthority::AnchorKeys(signatures);
    Ok(cert)
}

/// Verify a reseal against the ledger, the scheme registry and the anchors it
/// claims to cover.
///
/// # Errors
///
/// The first [`ResealError`] that applies.
pub fn verify_reseal(
    cert: &ResealCertificate,
    chain_id: u64,
    ledger: &AnchorKeyLedger,
    registry: &SchemeStatusRegistry,
    covered: &[(u64, [u8; 32])],
) -> Result<(), ResealError> {
    if cert.chain_id != chain_id {
        return Err(ResealError::WrongChain);
    }
    if cert.key_epoch != ledger.key_epoch {
        return Err(ResealError::StaleKeyEpoch);
    }
    if cert.from_height == 0 || cert.to_height < cert.from_height {
        return Err(ResealError::BadRange);
    }
    if covered_root(covered)? != cert.covered_root
        || usize::try_from(cert.count).ok() != Some(covered.len())
        || covered.first().map(|c| c.0) != Some(cert.from_height)
        || covered.last().map(|c| c.0) != Some(cert.to_height)
    {
        return Err(ResealError::CoveredMismatch);
    }
    // The family that signs must still verify: a reseal by the broken family
    // proves nothing.
    if !registry.scheme_verifies(cert.authority.scheme()) {
        return Err(ResealError::SignerFamilyDead);
    }
    let payload = reseal_payload(cert);
    match &cert.authority {
        ResealAuthority::SealKey { index, signature } => {
            let slot = usize::from(*index);
            let Some(key) = ledger.seal_keys.get(slot) else {
                return Err(ResealError::UnknownOrSuspendedKey);
            };
            if ledger.is_suspended(KeyFamily::Seal, *index, ledger.key_epoch) {
                return Err(ResealError::UnknownOrSuspendedKey);
            }
            crate::crypto::pq::verify_in(
                registry,
                SchemeId::SLH_DSA_SHAKE_256S,
                &key.public_key,
                &payload,
                crate::crypto::ctx::RESEAL_V1,
                signature,
            )
            .map_err(|_| ResealError::InvalidSignature)
        }
        ResealAuthority::AnchorKeys(signatures) => {
            let mut seen = std::collections::BTreeSet::new();
            for signature in signatures {
                if !seen.insert(signature.key_index) {
                    return Err(ResealError::InvalidSignature);
                }
                let Some(key) = ledger.anchor_key(signature.key_index) else {
                    return Err(ResealError::UnknownOrSuspendedKey);
                };
                if ledger.is_suspended(KeyFamily::Anchor, signature.key_index, ledger.key_epoch) {
                    return Err(ResealError::UnknownOrSuspendedKey);
                }
                crate::crypto::pq::verify_in(
                    registry,
                    SchemeId::ML_DSA_87,
                    key,
                    &payload,
                    crate::crypto::ctx::RESEAL_V1,
                    &signature.signature,
                )
                .map_err(|_| ResealError::InvalidSignature)?;
            }
            if seen.len() < ANCHOR_THRESHOLD {
                return Err(ResealError::ThresholdNotReached);
            }
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "wallet-ml-dsa"))]
mod tests {
    use super::*;
    use crate::crypto::primitives::{CryptoError, WalletKeyPair};
    use crate::crypto::scheme::{SchemeStatus, TransitionSource};
    use crate::settlement::anchor_ledger::test_support::{anchor_seed, software_ledger};

    const CHAIN: u64 = 45262;

    #[allow(clippy::type_complexity)] // a test double of the HSM trait
    struct Key {
        public: Vec<u8>,
        sign: Box<dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, CryptoError> + Send + Sync>,
    }

    impl HsmPqKey for Key {
        fn public_key(&self) -> Vec<u8> {
            self.public.clone()
        }
        fn sign(&self, ctx: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
            (self.sign)(ctx, payload)
        }
    }

    fn anchor_key(index: u8) -> Key {
        let pair = WalletKeyPair::from_seed(&anchor_seed(index));
        Key {
            public: pair.public_key_bytes().to_vec(),
            sign: Box::new(move |ctx, payload| Ok(pair.sign(ctx, payload).to_vec())),
        }
    }

    fn seal_key() -> Key {
        let seed = [0x5E_u8; 96];
        Key {
            public: crate::crypto::pq::slh_dsa_public_key(SchemeId::SLH_DSA_SHAKE_256S, &seed)
                .unwrap_or_default(),
            sign: Box::new(move |ctx, payload| {
                crate::crypto::pq::slh_dsa_sign(
                    SchemeId::SLH_DSA_SHAKE_256S,
                    &seed,
                    payload,
                    ctx,
                    Some(&[7u8; 32]),
                )
                .map_err(|_| CryptoError::Signing("slh".to_string()))
            }),
        }
    }

    fn covered() -> Vec<(u64, [u8; 32])> {
        vec![(360, [1; 32]), (720, [2; 32]), (1_080, [3; 32])]
    }

    #[allow(clippy::expect_used)] // one rung at a time is the point of the fixture
    fn disable(registry: &mut SchemeStatusRegistry, scheme: SchemeId) {
        for to in [SchemeStatus::Deprecated, SchemeStatus::Disabled] {
            registry
                .transition_scheme(scheme, to, TransitionSource::CanaryAlarm)
                .expect("one rung forward");
        }
    }

    #[test]
    fn after_a_lattice_break_a_seal_key_reseals_the_anchors() {
        let ledger = software_ledger(CHAIN, 1);
        let mut registry = SchemeStatusRegistry::genesis();
        disable(&mut registry, SchemeId::ML_DSA_87);
        let cert = unsigned_certificate(CHAIN, 1, &covered()).expect("coverage");
        let cert = sign_with_seal_key(cert, 0, &seal_key()).expect("the seal key signs");
        assert_eq!(
            verify_reseal(&cert, CHAIN, &ledger, &registry, &covered()),
            Ok(())
        );
        // A different anchor set does not match the root.
        let mut other = covered();
        other[1].1 = [9; 32];
        assert_eq!(
            verify_reseal(&cert, CHAIN, &ledger, &registry, &other),
            Err(ResealError::CoveredMismatch)
        );
        // The wrong context does not verify: sign under the anchor context.
        let wrong = Key {
            sign: Box::new(|_ctx, payload| {
                let seed = [0x5E_u8; 96];
                crate::crypto::pq::slh_dsa_sign(
                    SchemeId::SLH_DSA_SHAKE_256S,
                    &seed,
                    payload,
                    crate::crypto::ctx::SEAL_V1,
                    Some(&[7u8; 32]),
                )
                .map_err(|_| CryptoError::Signing("slh".to_string()))
            }),
            ..seal_key()
        };
        let bad = sign_with_seal_key(
            unsigned_certificate(CHAIN, 1, &covered()).expect("coverage"),
            0,
            &wrong,
        )
        .expect("signs under the wrong context");
        assert_eq!(
            verify_reseal(&bad, CHAIN, &ledger, &registry, &covered()),
            Err(ResealError::InvalidSignature)
        );
    }

    #[test]
    fn after_a_hash_signature_break_two_anchor_keys_reseal_and_one_does_not() {
        let ledger = software_ledger(CHAIN, 1);
        let mut registry = SchemeStatusRegistry::genesis();
        disable(&mut registry, SchemeId::SLH_DSA_SHAKE_256S);
        let (k0, k1) = (anchor_key(0), anchor_key(1));
        let cert = unsigned_certificate(CHAIN, 1, &covered()).expect("coverage");
        let two = sign_with_anchor_keys(cert.clone(), &[(0, &k0), (1, &k1)]).expect("two keys");
        assert_eq!(
            verify_reseal(&two, CHAIN, &ledger, &registry, &covered()),
            Ok(())
        );
        assert_eq!(
            sign_with_anchor_keys(cert, &[(0, &k0)]),
            Err(ResealError::ThresholdNotReached)
        );
    }

    #[test]
    fn a_reseal_by_the_broken_family_is_refused() {
        let ledger = software_ledger(CHAIN, 1);
        // The lattice family is the broken one, yet the certificate is signed
        // by anchor keys (ML-DSA-87).
        let mut registry = SchemeStatusRegistry::genesis();
        disable(&mut registry, SchemeId::ML_DSA_87);
        let (k0, k1) = (anchor_key(0), anchor_key(1));
        let cert = sign_with_anchor_keys(
            unsigned_certificate(CHAIN, 1, &covered()).expect("coverage"),
            &[(0, &k0), (1, &k1)],
        )
        .expect("signs");
        assert_eq!(
            verify_reseal(&cert, CHAIN, &ledger, &registry, &covered()),
            Err(ResealError::SignerFamilyDead)
        );
    }

    #[test]
    fn chain_epoch_and_range_bind() {
        let ledger = software_ledger(CHAIN, 1);
        let registry = SchemeStatusRegistry::genesis();
        let cert = sign_with_seal_key(
            unsigned_certificate(CHAIN, 1, &covered()).expect("coverage"),
            0,
            &seal_key(),
        )
        .expect("signs");
        assert_eq!(
            verify_reseal(&cert, CHAIN + 1, &ledger, &registry, &covered()),
            Err(ResealError::WrongChain)
        );
        let stale = ResealCertificate {
            key_epoch: 2,
            ..cert.clone()
        };
        assert_eq!(
            verify_reseal(&stale, CHAIN, &ledger, &registry, &covered()),
            Err(ResealError::StaleKeyEpoch)
        );
        assert_eq!(covered_root(&[]), Err(ResealError::BadCoverage));
        assert_eq!(
            covered_root(&[(5, [0; 32]), (5, [1; 32])]),
            Err(ResealError::BadCoverage)
        );
    }
}
