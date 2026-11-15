//! Composite signature.
//!
//! A composite signature is two signatures over one message representative:
//! a post-quantum signature and an Ed25519 signature. Both must verify. The
//! Ed25519 half is additional assurance, never a substitute, so a break of
//! either family alone does not forge an object.
//!
//! ```text
//! M'     = "BDLM_COMPOSITE_SIG_V1" || u16 suite_id || u8 len(ctx) || ctx || SHA3-256(payload)
//! sig_pq = PQ.Sign(sk_pq, M', ctx)
//! sig_ed = Ed25519.Sign(sk_ed, M')
//! ```
//!
//! `M'` carries the suite and the context, so removing a component, changing
//! the context, changing the suite or moving a signature from another domain
//! each break verification. The post-quantum half also takes `ctx` as its own
//! FIPS 204 or FIPS 205 context, so the context is bound twice.
//!
//! # Encoding
//!
//! Fixed length per suite, versioned, and the suite is written, never inferred
//! from the length:
//!
//! ```text
//! public key: u8 version(1) || u16 suite || pq_public_key || ed25519_public_key(32)
//! signature:  u8 version(1) || u16 suite || pq_signature  || ed25519_signature(64)
//! ```
//!
//! This file has no dependency on the rest of the node. `crates/wallet-core`
//! mounts the same source (see `docs/pq/README.md`).

use super::pq::{self, PqError};
use super::scheme::{SchemeId, SchemeStatusRegistry, SuiteId};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha3::{Digest, Sha3_256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// The domain tag at the front of every message representative.
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const COMPOSITE_TAG: &[u8] = b"BDLM_COMPOSITE_SIG_V1";
/// The version byte of the key and signature encodings.
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const ENCODING_VERSION: u8 = 1;
/// Ed25519 public key length.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Ed25519 signature length.
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Ed25519 seed length.
pub const ED25519_SEED_LEN: usize = 32;
/// Bytes before the payload of an encoded key or signature: version and suite.
const HEADER_LEN: usize = 3;

/// A refused composite operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositeError {
    /// The suite identifier is not in the table.
    UnknownSuite(SuiteId),
    /// The suite, or one of its components, is not verifiable in its status.
    SuiteNotVerifiable(SuiteId),
    /// The suite, or one of its components, may not sign in its status.
    SuiteNotSignable(SuiteId),
    /// The key and the signature name different suites.
    SuiteMismatch,
    /// The encoding is malformed: version, suite or length.
    BadEncoding(&'static str),
    /// The Ed25519 public key is not a valid point.
    MalformedEd25519Key,
    /// The Ed25519 public key is a weak (small-order) point.
    WeakEd25519Key,
    /// The Ed25519 signature did not verify under `verify_strict`.
    Ed25519Rejected,
    /// The context string is empty or longer than 255 bytes.
    BadContext,
    /// The post-quantum component refused.
    Pq(PqError),
}

impl std::fmt::Display for CompositeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSuite(id) => write!(f, "unknown suite 0x{:04x}", id.0),
            Self::SuiteNotVerifiable(id) => write!(f, "suite 0x{:04x} is not verifiable", id.0),
            Self::SuiteNotSignable(id) => write!(f, "suite 0x{:04x} may not sign", id.0),
            Self::SuiteMismatch => write!(f, "key and signature name different suites"),
            Self::BadEncoding(why) => write!(f, "malformed composite encoding: {why}"),
            Self::MalformedEd25519Key => write!(f, "malformed Ed25519 public key"),
            Self::WeakEd25519Key => write!(f, "weak Ed25519 public key"),
            Self::Ed25519Rejected => write!(f, "Ed25519 component rejected"),
            Self::BadContext => write!(f, "context string must be 1 to 255 bytes"),
            Self::Pq(e) => write!(f, "post-quantum component: {e}"),
        }
    }
}

impl std::error::Error for CompositeError {}

impl From<PqError> for CompositeError {
    fn from(e: PqError) -> Self {
        Self::Pq(e)
    }
}

/// The message representative `M'` that both components sign.
///
/// # Errors
///
/// [`CompositeError::UnknownSuite`] for an unlisted suite and
/// [`CompositeError::BadContext`] for an empty or over-long context.
pub fn message_representative(
    suite: SuiteId,
    ctx: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, CompositeError> {
    suite.info().ok_or(CompositeError::UnknownSuite(suite))?;
    let ctx_len = u8::try_from(ctx.len()).map_err(|_| CompositeError::BadContext)?;
    if ctx.is_empty() {
        return Err(CompositeError::BadContext);
    }
    let digest: [u8; 32] = Sha3_256::digest(payload).into();
    let mut out = Vec::with_capacity(COMPOSITE_TAG.len() + 2 + 1 + ctx.len() + digest.len());
    out.extend_from_slice(COMPOSITE_TAG);
    out.extend_from_slice(&suite.to_be_bytes());
    out.push(ctx_len);
    out.extend_from_slice(ctx);
    out.extend_from_slice(&digest);
    Ok(out)
}

/// The post-quantum scheme and the encoded lengths of a suite.
struct SuiteShape {
    pq: SchemeId,
    pq_public_key_len: usize,
    pq_signature_len: usize,
}

fn shape(suite: SuiteId) -> Result<SuiteShape, CompositeError> {
    let info = suite.info().ok_or(CompositeError::UnknownSuite(suite))?;
    Ok(SuiteShape {
        pq: info.pq,
        pq_public_key_len: pq::public_key_len(info.pq)?,
        pq_signature_len: pq::signature_len(info.pq)?,
    })
}

/// Read the version and suite and hand back the rest.
fn split_header(bytes: &[u8]) -> Result<(SuiteId, &[u8]), CompositeError> {
    let (head, rest) = bytes
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(CompositeError::BadEncoding("shorter than the header"))?;
    let [version, hi, lo] = *head;
    if version != ENCODING_VERSION {
        return Err(CompositeError::BadEncoding("unknown version"));
    }
    Ok((SuiteId(u16::from_be_bytes([hi, lo])), rest))
}

/// A composite public key: the post-quantum key and the Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositePublicKey {
    /// The suite both keys belong to.
    pub suite: SuiteId,
    /// The post-quantum public key.
    pub pq: Vec<u8>,
    /// The Ed25519 public key.
    pub ed: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl CompositePublicKey {
    /// The fixed encoded length of a key of this suite.
    ///
    /// # Errors
    ///
    /// [`CompositeError`] for an unknown suite or one without an implementation.
    pub fn encoded_len(suite: SuiteId) -> Result<usize, CompositeError> {
        Ok(HEADER_LEN + shape(suite)?.pq_public_key_len + ED25519_PUBLIC_KEY_LEN)
    }

    /// Encode as `version || suite || pq || ed`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.pq.len() + self.ed.len());
        out.push(ENCODING_VERSION);
        out.extend_from_slice(&self.suite.to_be_bytes());
        out.extend_from_slice(&self.pq);
        out.extend_from_slice(&self.ed);
        out
    }

    /// Decode, demanding the exact length of the named suite.
    ///
    /// # Errors
    ///
    /// [`CompositeError::BadEncoding`] for a wrong version or length and
    /// [`CompositeError::UnknownSuite`] for an unlisted suite.
    pub fn decode(bytes: &[u8]) -> Result<Self, CompositeError> {
        let (suite, rest) = split_header(bytes)?;
        let shape = shape(suite)?;
        if rest.len() != shape.pq_public_key_len + ED25519_PUBLIC_KEY_LEN {
            return Err(CompositeError::BadEncoding("length differs from the suite"));
        }
        let (pq, ed_bytes) = rest.split_at(shape.pq_public_key_len);
        let ed = <[u8; ED25519_PUBLIC_KEY_LEN]>::try_from(ed_bytes)
            .map_err(|_| CompositeError::BadEncoding("Ed25519 key"))?;
        Ok(Self {
            suite,
            pq: pq.to_vec(),
            ed,
        })
    }
}

/// A composite signature: the post-quantum signature and the Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeSignature {
    /// The suite both signatures were made under.
    pub suite: SuiteId,
    /// The post-quantum signature.
    pub pq: Vec<u8>,
    /// The Ed25519 signature.
    pub ed: [u8; ED25519_SIGNATURE_LEN],
}

impl CompositeSignature {
    /// The fixed encoded length of a signature of this suite.
    ///
    /// # Errors
    ///
    /// [`CompositeError`] for an unknown suite or one without an implementation.
    pub fn encoded_len(suite: SuiteId) -> Result<usize, CompositeError> {
        Ok(HEADER_LEN + shape(suite)?.pq_signature_len + ED25519_SIGNATURE_LEN)
    }

    /// Encode as `version || suite || pq || ed`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.pq.len() + self.ed.len());
        out.push(ENCODING_VERSION);
        out.extend_from_slice(&self.suite.to_be_bytes());
        out.extend_from_slice(&self.pq);
        out.extend_from_slice(&self.ed);
        out
    }

    /// Decode, demanding the exact length of the named suite.
    ///
    /// # Errors
    ///
    /// [`CompositeError::BadEncoding`] for a wrong version or length and
    /// [`CompositeError::UnknownSuite`] for an unlisted suite.
    pub fn decode(bytes: &[u8]) -> Result<Self, CompositeError> {
        let (suite, rest) = split_header(bytes)?;
        let shape = shape(suite)?;
        if rest.len() != shape.pq_signature_len + ED25519_SIGNATURE_LEN {
            return Err(CompositeError::BadEncoding("length differs from the suite"));
        }
        let (pq, ed_bytes) = rest.split_at(shape.pq_signature_len);
        let ed = <[u8; ED25519_SIGNATURE_LEN]>::try_from(ed_bytes)
            .map_err(|_| CompositeError::BadEncoding("Ed25519 signature"))?;
        Ok(Self {
            suite,
            pq: pq.to_vec(),
            ed,
        })
    }
}

/// A composite key pair held as two seeds. Both are wiped on drop.
pub struct CompositeKeypair {
    suite: SuiteId,
    pq_seed: Zeroizing<Vec<u8>>,
    ed_seed: Zeroizing<[u8; ED25519_SEED_LEN]>,
}

// Both seeds are `Zeroizing`, so dropping the key pair wipes them.
impl ZeroizeOnDrop for CompositeKeypair {}

/// The seed length of the post-quantum half of a suite.
fn pq_seed_len(scheme: SchemeId) -> Result<usize, CompositeError> {
    if scheme == SchemeId::ML_DSA_65 || scheme == SchemeId::ML_DSA_87 {
        return Ok(pq::ML_DSA_SEED_LEN);
    }
    Ok(pq::slh_dsa_seed_len(scheme)?)
}

impl CompositeKeypair {
    /// Build a key pair from its two seeds.
    ///
    /// # Errors
    ///
    /// [`CompositeError`] for an unknown suite or a wrong post-quantum seed length.
    pub fn from_seeds(
        suite: SuiteId,
        pq_seed: &[u8],
        ed_seed: &[u8; ED25519_SEED_LEN],
    ) -> Result<Self, CompositeError> {
        let shape = shape(suite)?;
        let expected = pq_seed_len(shape.pq)?;
        if pq_seed.len() != expected {
            return Err(CompositeError::Pq(PqError::SeedLength {
                scheme: shape.pq,
                expected,
                got: pq_seed.len(),
            }));
        }
        Ok(Self {
            suite,
            pq_seed: Zeroizing::new(pq_seed.to_vec()),
            ed_seed: Zeroizing::new(*ed_seed),
        })
    }

    /// The suite of this key pair.
    #[must_use]
    pub fn suite(&self) -> SuiteId {
        self.suite
    }

    /// The composite public key.
    ///
    /// # Errors
    ///
    /// [`CompositeError`] when the post-quantum half cannot be derived.
    pub fn public_key(&self) -> Result<CompositePublicKey, CompositeError> {
        let shape = shape(self.suite)?;
        let pq = pq_public_key(shape.pq, &self.pq_seed)?;
        let ed = SigningKey::from_bytes(&self.ed_seed)
            .verifying_key()
            .to_bytes();
        Ok(CompositePublicKey {
            suite: self.suite,
            pq,
            ed,
        })
    }

    /// Sign `payload` under `ctx`.
    ///
    /// `rnd` is 32 bytes of fresh randomness for the hedged post-quantum
    /// signature; all zero selects the deterministic variant. The SLH-DSA
    /// suites use its first `n` bytes.
    ///
    /// # Errors
    ///
    /// [`CompositeError::SuiteNotSignable`] when the registry does not allow
    /// the suite to sign, [`CompositeError::BadContext`], or a post-quantum
    /// failure.
    pub fn sign_in(
        &self,
        registry: &SchemeStatusRegistry,
        ctx: &[u8],
        payload: &[u8],
        rnd: &[u8; 32],
    ) -> Result<CompositeSignature, CompositeError> {
        if !registry.suite_signs(self.suite) {
            return Err(CompositeError::SuiteNotSignable(self.suite));
        }
        self.sign_unchecked(ctx, payload, rnd)
    }

    /// Sign under the statuses of a fresh genesis.
    ///
    /// # Errors
    ///
    /// See [`CompositeKeypair::sign_in`].
    pub fn sign(
        &self,
        ctx: &[u8],
        payload: &[u8],
        rnd: &[u8; 32],
    ) -> Result<CompositeSignature, CompositeError> {
        self.sign_in(&SchemeStatusRegistry::genesis(), ctx, payload, rnd)
    }

    fn sign_unchecked(
        &self,
        ctx: &[u8],
        payload: &[u8],
        rnd: &[u8; 32],
    ) -> Result<CompositeSignature, CompositeError> {
        let m_prime = message_representative(self.suite, ctx, payload)?;
        self.sign_representative(ctx, &m_prime, rnd)
    }

    /// Sign an already built representative. Split out so the tests can build
    /// a representative for one suite and sign it with the keys of another.
    fn sign_representative(
        &self,
        ctx: &[u8],
        m_prime: &[u8],
        rnd: &[u8; 32],
    ) -> Result<CompositeSignature, CompositeError> {
        let shape = shape(self.suite)?;
        let pq = pq_sign(shape.pq, &self.pq_seed, m_prime, ctx, rnd)?;
        let ed = SigningKey::from_bytes(&self.ed_seed)
            .sign(m_prime)
            .to_bytes();
        Ok(CompositeSignature {
            suite: self.suite,
            pq,
            ed,
        })
    }
}

fn pq_public_key(scheme: SchemeId, seed: &[u8]) -> Result<Vec<u8>, CompositeError> {
    if scheme == SchemeId::ML_DSA_65 || scheme == SchemeId::ML_DSA_87 {
        let seed = <&[u8; pq::ML_DSA_SEED_LEN]>::try_from(seed).map_err(|_| {
            CompositeError::Pq(PqError::SeedLength {
                scheme,
                expected: pq::ML_DSA_SEED_LEN,
                got: seed.len(),
            })
        })?;
        return Ok(pq::ml_dsa_public_key(scheme, seed)?);
    }
    Ok(pq::slh_dsa_public_key(scheme, seed)?)
}

fn pq_sign(
    scheme: SchemeId,
    seed: &[u8],
    message: &[u8],
    ctx: &[u8],
    rnd: &[u8; 32],
) -> Result<Vec<u8>, CompositeError> {
    if scheme == SchemeId::ML_DSA_65 || scheme == SchemeId::ML_DSA_87 {
        let seed = <&[u8; pq::ML_DSA_SEED_LEN]>::try_from(seed).map_err(|_| {
            CompositeError::Pq(PqError::SeedLength {
                scheme,
                expected: pq::ML_DSA_SEED_LEN,
                got: seed.len(),
            })
        })?;
        return Ok(pq::ml_dsa_sign(scheme, seed, message, ctx, rnd)?);
    }
    // SLH-DSA: the randomizer is `n` bytes, taken from the front of `rnd`; an
    // all-zero `rnd` selects the deterministic variant.
    let n = pq::slh_dsa_seed_len(scheme)? / 3;
    let randomizer = if rnd.iter().all(|b| *b == 0) {
        None
    } else {
        rnd.get(..n)
    };
    Ok(pq::slh_dsa_sign(scheme, seed, message, ctx, randomizer)?)
}

/// Verify a composite signature under the statuses of a fresh genesis.
///
/// # Errors
///
/// [`CompositeError`]: both components must verify, the suites must agree and
/// be verifiable, and the Ed25519 key must not be weak.
pub fn verify(
    public_key: &CompositePublicKey,
    ctx: &[u8],
    payload: &[u8],
    signature: &CompositeSignature,
) -> Result<(), CompositeError> {
    verify_in(
        &SchemeStatusRegistry::genesis(),
        public_key,
        ctx,
        payload,
        signature,
    )
}

/// Verify a composite signature under the scheme statuses of a chain.
///
/// # Errors
///
/// See [`verify`].
pub fn verify_in(
    registry: &SchemeStatusRegistry,
    public_key: &CompositePublicKey,
    ctx: &[u8],
    payload: &[u8],
    signature: &CompositeSignature,
) -> Result<(), CompositeError> {
    if public_key.suite != signature.suite {
        return Err(CompositeError::SuiteMismatch);
    }
    let suite = public_key.suite;
    let info = suite.info().ok_or(CompositeError::UnknownSuite(suite))?;
    if !registry.suite_verifies(suite) {
        return Err(CompositeError::SuiteNotVerifiable(suite));
    }
    let m_prime = message_representative(suite, ctx, payload)?;
    // Both components are always evaluated: neither verdict decides early.
    let ed = verify_ed25519(&public_key.ed, &m_prime, &signature.ed);
    let pq = pq::verify_in(
        registry,
        info.pq,
        &public_key.pq,
        &m_prime,
        ctx,
        &signature.pq,
    )
    .map_err(CompositeError::Pq);
    ed?;
    pq
}

fn verify_ed25519(
    public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; ED25519_SIGNATURE_LEN],
) -> Result<(), CompositeError> {
    let key =
        VerifyingKey::from_bytes(public_key).map_err(|_| CompositeError::MalformedEd25519Key)?;
    if key.is_weak() {
        return Err(CompositeError::WeakEd25519Key);
    }
    let sig = Signature::from_bytes(signature);
    key.verify_strict(message, &sig)
        .map_err(|_| CompositeError::Ed25519Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ctx;
    use crate::crypto::scheme::{SchemeStatus, TransitionSource};

    const PAYLOAD: &[u8] = b"composite payload";
    const RND: [u8; 32] = [0u8; 32];

    fn user_keys(tag: u8) -> CompositeKeypair {
        CompositeKeypair::from_seeds(SuiteId::USER, &[tag; 32], &[tag.wrapping_add(1); 32]).unwrap()
    }

    fn validator_keys(tag: u8) -> CompositeKeypair {
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[tag; 32], &[tag.wrapping_add(1); 32])
            .unwrap()
    }

    fn assert_wipes_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn zeroize_every_secret_holder_wipes_on_drop() {
        assert_wipes_on_drop::<CompositeKeypair>();
        assert_wipes_on_drop::<Zeroizing<Vec<u8>>>();
        assert_wipes_on_drop::<ml_dsa::SigningKey<ml_dsa::MlDsa65>>();
        assert_wipes_on_drop::<ml_dsa::SigningKey<ml_dsa::MlDsa87>>();
        assert_wipes_on_drop::<slh_dsa::SigningKey<slh_dsa::Shake128s>>();
        assert_wipes_on_drop::<slh_dsa::SigningKey<slh_dsa::Shake256s>>();
        assert_wipes_on_drop::<ed25519_dalek::SigningKey>();
    }

    #[test]
    fn zeroize_wrapper_wipes_before_the_value_is_released() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use zeroize::Zeroize;

        struct Probe(Arc<AtomicBool>);
        impl Zeroize for Probe {
            fn zeroize(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let wiped = Arc::new(AtomicBool::new(false));
        drop(Zeroizing::new(Probe(Arc::clone(&wiped))));
        assert!(wiped.load(Ordering::SeqCst), "Zeroizing must wipe on drop");
        let mut seed = Zeroizing::new(vec![0xAAu8; 32]);
        seed.zeroize();
        assert!(
            seed.iter().all(|b| *b == 0),
            "an explicit wipe clears the seed"
        );
    }

    #[test]
    fn composite_round_trips_for_both_active_suites() {
        for keys in [user_keys(1), validator_keys(2)] {
            let pk = keys.public_key().unwrap();
            let sig = keys.sign(ctx::TX_V7, PAYLOAD, &RND).unwrap();
            assert_eq!(verify(&pk, ctx::TX_V7, PAYLOAD, &sig), Ok(()));
            assert_eq!(
                sig.encode().len(),
                CompositeSignature::encoded_len(keys.suite()).unwrap()
            );
            assert_eq!(
                pk.encode().len(),
                CompositePublicKey::encoded_len(keys.suite()).unwrap()
            );
        }
    }

    #[test]
    fn composite_encodings_round_trip_and_have_fixed_length() {
        let keys = user_keys(3);
        let pk = keys.public_key().unwrap();
        let sig = keys.sign(ctx::TX_V7, PAYLOAD, &RND).unwrap();
        assert_eq!(CompositePublicKey::decode(&pk.encode()), Ok(pk.clone()));
        assert_eq!(CompositeSignature::decode(&sig.encode()), Ok(sig.clone()));
        // 3 + 4627 + 64 and 3 + 2592 + 32.
        assert_eq!(sig.encode().len(), 4694);
        assert_eq!(pk.encode().len(), 2627);
        let mut long = sig.encode();
        long.push(0);
        assert!(CompositeSignature::decode(&long).is_err());
        let mut short = sig.encode();
        short.pop();
        assert!(CompositeSignature::decode(&short).is_err());
        let mut wrong_version = sig.encode();
        if let Some(b) = wrong_version.first_mut() {
            *b = 2;
        }
        assert!(CompositeSignature::decode(&wrong_version).is_err());
    }

    #[test]
    fn composite_rejects_a_missing_component() {
        let keys = user_keys(4);
        let pk = keys.public_key().unwrap();
        let sig = keys.sign(ctx::TX_V7, PAYLOAD, &RND).unwrap();
        // The classical half zeroed: the post-quantum half alone is not enough.
        let mut no_ed = sig.clone();
        no_ed.ed = [0u8; ED25519_SIGNATURE_LEN];
        assert!(verify(&pk, ctx::TX_V7, PAYLOAD, &no_ed).is_err());
        // The post-quantum half zeroed: Ed25519 alone is not enough.
        let mut no_pq = sig.clone();
        no_pq.pq = vec![0u8; sig.pq.len()];
        assert!(verify(&pk, ctx::TX_V7, PAYLOAD, &no_pq).is_err());
        // A shortened post-quantum half is refused on its length.
        let mut cut = sig;
        cut.pq.clear();
        assert!(verify(&pk, ctx::TX_V7, PAYLOAD, &cut).is_err());
    }

    #[test]
    fn composite_rejects_a_swapped_component() {
        let a = user_keys(5);
        let b = user_keys(9);
        let pk = a.public_key().unwrap();
        let sig_a = a.sign(ctx::TX_V7, PAYLOAD, &RND).unwrap();
        let sig_b = b.sign(ctx::TX_V7, PAYLOAD, &RND).unwrap();
        let mut pq_from_b = sig_a.clone();
        pq_from_b.pq = sig_b.pq.clone();
        assert!(verify(&pk, ctx::TX_V7, PAYLOAD, &pq_from_b).is_err());
        let mut ed_from_b = sig_a;
        ed_from_b.ed = sig_b.ed;
        assert!(verify(&pk, ctx::TX_V7, PAYLOAD, &ed_from_b).is_err());
        // Keys swapped: the PQ key of one pair with the Ed25519 key of another.
        let mut franken = pk;
        franken.ed = b.public_key().unwrap().ed;
        let sig = a.sign(ctx::TX_V7, PAYLOAD, &RND).unwrap();
        assert!(verify(&franken, ctx::TX_V7, PAYLOAD, &sig).is_err());
    }

    #[test]
    fn composite_rejects_a_changed_context() {
        let keys = user_keys(6);
        let pk = keys.public_key().unwrap();
        let sig = keys.sign(ctx::TX_V7, PAYLOAD, &RND).unwrap();
        assert!(
            verify(&pk, ctx::TX_V8, PAYLOAD, &sig).is_err(),
            "a signature made for one context must not verify under another"
        );
        assert_eq!(
            verify(&pk, b"", PAYLOAD, &sig),
            Err(CompositeError::BadContext)
        );
    }

    #[test]
    fn composite_rejects_a_changed_suite() {
        let keys = user_keys(7);
        let pk = keys.public_key().unwrap();
        let sig = keys.sign(ctx::TX_V7, PAYLOAD, &RND).unwrap();
        let mut relabelled = sig.clone();
        relabelled.suite = SuiteId::VALIDATOR;
        assert_eq!(
            verify(&pk, ctx::TX_V7, PAYLOAD, &relabelled),
            Err(CompositeError::SuiteMismatch)
        );
        // Relabel both: lengths no longer fit the named suite.
        let mut pk2 = pk.clone();
        pk2.suite = SuiteId::VALIDATOR;
        assert!(verify(&pk2, ctx::TX_V7, PAYLOAD, &relabelled).is_err());
        // The representative differs per suite even for identical bytes.
        let m1 = message_representative(SuiteId::USER, ctx::TX_V7, PAYLOAD).unwrap();
        let m2 = message_representative(SuiteId::VALIDATOR, ctx::TX_V7, PAYLOAD).unwrap();
        assert_ne!(m1, m2);
        // Components signed over the representative of another suite do not
        // verify under this suite, even with the right keys and context.
        let wrong_m = message_representative(SuiteId::VALIDATOR, ctx::TX_V7, PAYLOAD).unwrap();
        let sig_wrong = keys
            .sign_representative(ctx::TX_V7, &wrong_m, &RND)
            .unwrap();
        assert!(verify(&pk, ctx::TX_V7, PAYLOAD, &sig_wrong).is_err());
        // An unlisted suite is refused outright.
        let mut unknown = sig;
        unknown.suite = SuiteId(0x00EE);
        let mut pk3 = pk;
        pk3.suite = SuiteId(0x00EE);
        assert_eq!(
            verify(&pk3, ctx::TX_V7, PAYLOAD, &unknown),
            Err(CompositeError::UnknownSuite(SuiteId(0x00EE)))
        );
    }

    #[test]
    fn composite_rejects_reuse_from_another_domain() {
        let keys = user_keys(8);
        let pk = keys.public_key().unwrap();
        let sig = keys.sign(ctx::TX_V7, PAYLOAD, &RND).unwrap();
        // The same bytes under the same context but another payload.
        assert!(verify(&pk, ctx::TX_V7, b"another payload", &sig).is_err());
        // A signature over a payload that is itself another domain's message.
        let other_domain_payload = [COMPOSITE_TAG, PAYLOAD].concat();
        assert!(verify(&pk, ctx::TX_V7, &other_domain_payload, &sig).is_err());
        // Another context with the same payload.
        assert!(verify(&pk, ctx::BLOCK_V6, PAYLOAD, &sig).is_err());
    }

    #[test]
    fn composite_rejects_a_weak_ed25519_key() {
        let keys = user_keys(10);
        let mut pk = keys.public_key().unwrap();
        let m_prime = message_representative(SuiteId::USER, ctx::TX_V7, PAYLOAD).unwrap();
        let pq = pq_sign(SchemeId::ML_DSA_87, &[10u8; 32], &m_prime, ctx::TX_V7, &RND).unwrap();
        // The identity point is a small-order key; with R = identity and S = 0
        // the signature verifies for every message under the non-strict rule.
        let mut identity = [0u8; ED25519_PUBLIC_KEY_LEN];
        if let Some(first) = identity.first_mut() {
            *first = 1;
        }
        pk.ed = identity;
        let mut ed_sig = [0u8; ED25519_SIGNATURE_LEN];
        if let Some(first) = ed_sig.first_mut() {
            *first = 1;
        }
        let sig = CompositeSignature {
            suite: SuiteId::USER,
            pq,
            ed: ed_sig,
        };
        assert_eq!(
            verify(&pk, ctx::TX_V7, PAYLOAD, &sig),
            Err(CompositeError::WeakEd25519Key)
        );
    }

    #[test]
    fn composite_respects_the_scheme_registry() {
        let keys = user_keys(11);
        let pk = keys.public_key().unwrap();
        let sig = keys.sign(ctx::TX_V7, PAYLOAD, &RND).unwrap();
        let mut registry = SchemeStatusRegistry::genesis();
        assert_eq!(verify_in(&registry, &pk, ctx::TX_V7, PAYLOAD, &sig), Ok(()));
        for to in [SchemeStatus::Deprecated, SchemeStatus::Disabled] {
            registry
                .transition_scheme(SchemeId::ML_DSA_87, to, TransitionSource::CanaryAlarm)
                .unwrap();
        }
        assert_eq!(
            verify_in(&registry, &pk, ctx::TX_V7, PAYLOAD, &sig),
            Err(CompositeError::SuiteNotVerifiable(SuiteId::USER))
        );
        assert_eq!(
            keys.sign_in(&registry, ctx::TX_V7, PAYLOAD, &RND).err(),
            Some(CompositeError::SuiteNotSignable(SuiteId::USER))
        );
    }

    #[test]
    fn composite_known_answer_pins_the_representative() {
        let m = message_representative(SuiteId::USER, ctx::TX_V7, b"").unwrap();
        // tag || 0x0001 || 0x0A || "BDLM/TX/V7" || SHA3-256("")
        let mut expected = Vec::new();
        expected.extend_from_slice(b"BDLM_COMPOSITE_SIG_V1");
        expected.extend_from_slice(&[0x00, 0x01, 0x0A]);
        expected.extend_from_slice(b"BDLM/TX/V7");
        expected.extend_from_slice(&[
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
            0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
            0x80, 0xf8, 0x43, 0x4a,
        ]);
        assert_eq!(m, expected);
    }

    #[test]
    fn composite_slh_dsa_emergency_suite_round_trips_once_activated() {
        let keys =
            CompositeKeypair::from_seeds(SuiteId::EMERGENCY_VALIDATOR, &[12u8; 48], &[13u8; 32])
                .unwrap();
        let pk = keys.public_key().unwrap();
        let mut registry = SchemeStatusRegistry::genesis();
        assert_eq!(
            keys.sign_in(&registry, ctx::BLOCK_V6, PAYLOAD, &RND).err(),
            Some(CompositeError::SuiteNotSignable(
                SuiteId::EMERGENCY_VALIDATOR
            ))
        );
        registry
            .transition_scheme(
                SchemeId::SLH_DSA_SHAKE_128S,
                SchemeStatus::Active,
                TransitionSource::CanaryAlarm,
            )
            .unwrap();
        registry
            .transition_suite(
                SuiteId::EMERGENCY_VALIDATOR,
                SchemeStatus::Active,
                TransitionSource::CanaryAlarm,
            )
            .unwrap();
        let sig = keys
            .sign_in(&registry, ctx::BLOCK_V6, PAYLOAD, &RND)
            .unwrap();
        assert_eq!(sig.encode().len(), 3 + 7856 + 64);
        assert_eq!(
            verify_in(&registry, &pk, ctx::BLOCK_V6, PAYLOAD, &sig),
            Ok(())
        );
        assert!(verify_in(&registry, &pk, ctx::BLOCK_V6, b"other", &sig).is_err());
    }
}
