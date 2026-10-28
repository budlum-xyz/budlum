//! WIRING: verify_ml_dsa_single is reached from the PQ vector tests in this tree; the production path verifies through the batched backend dispatch.
//! Post-quantum verification facade.
//!
//! One entry point, [`verify`], for every ML-DSA and SLH-DSA signature the node
//! checks: `verify(scheme, pk, msg, ctx, sig)`. The scheme is named by the
//! caller and is never recovered from a length. The context string is part of
//! the signed message (FIPS 204 section 5.2, FIPS 205 section 10.2); an empty
//! context is refused on every chain, and a context longer than 255 bytes is
//! refused too.
//!
//! # ML-DSA is verified twice
//!
//! Consensus verification of an ML-DSA signature needs the acceptance of two
//! independent implementations: RustCrypto `ml-dsa` and `libcrux-ml-dsa` (the
//! portable backend only; the SIMD features are off, so the AVX2 advisories
//! RUSTSEC-2026-0125 and RUSTSEC-2026-0126 have no code path here). Both
//! libraries shipped a bug in 2026 that accepted an invalid signature
//! (CVE-2026-24850 and RUSTSEC-2026-0077), so one library alone is not a
//! consensus rule. A signature is valid only when both accept it. When exactly
//! one accepts, the answer is "invalid", the process-wide counter behind
//! [`verifier_disagreements`] goes up, and the caller sees
//! [`PqError::VerifierDisagreement`]. The node exports the counter as the
//! `budlum_pq_verifier_disagreement` metric.
//!
//! # SLH-DSA has one library
//!
//! RustCrypto `slh-dsa` is the only implementation. The NIST ACVP vectors in
//! `tests/vectors/pq` are therefore mandatory (`pq_vectors_*` tests).
//!
//! This file has no dependency on the rest of the node. `crates/wallet-core`
//! mounts the same source (see `docs/pq/README.md`).

use super::ctx::MAX_CONTEXT_LEN;
use super::scheme::{SchemeId, SchemeStatusRegistry};
use std::sync::atomic::{AtomicU64, Ordering};

/// How many times the two ML-DSA verifiers disagreed since the process began.
static VERIFIER_DISAGREEMENTS: AtomicU64 = AtomicU64::new(0);

/// The number of ML-DSA verifier disagreements seen by this process.
///
/// Any value above zero means one of the two libraries accepted something the
/// other refused, which is an incident: the node exports it as
/// `budlum_pq_verifier_disagreement`.
#[must_use]
pub fn verifier_disagreements() -> u64 {
    VERIFIER_DISAGREEMENTS.load(Ordering::Relaxed)
}

/// A refused post-quantum operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqError {
    /// The identifier is not in the scheme table.
    UnknownScheme(SchemeId),
    /// The scheme exists but its status does not allow verification.
    SchemeNotVerifiable(SchemeId),
    /// The scheme is in the table and this build has no implementation for it.
    Unsupported(SchemeId),
    /// The context string is empty.
    EmptyContext,
    /// The context string is longer than 255 bytes.
    ContextTooLong(usize),
    /// The public key does not have the length of the named scheme.
    PublicKeyLength {
        /// The named scheme.
        scheme: SchemeId,
        /// The length the scheme requires.
        expected: usize,
        /// The length received.
        got: usize,
    },
    /// The signature does not have the length of the named scheme.
    SignatureLength {
        /// The named scheme.
        scheme: SchemeId,
        /// The length the scheme requires.
        expected: usize,
        /// The length received.
        got: usize,
    },
    /// The seed has the wrong length for a key derivation.
    SeedLength {
        /// The named scheme.
        scheme: SchemeId,
        /// The length the scheme requires.
        expected: usize,
        /// The length received.
        got: usize,
    },
    /// The key bytes did not decode.
    MalformedPublicKey,
    /// The signature verified false.
    Rejected,
    /// One ML-DSA library accepted and the other refused.
    VerifierDisagreement,
    /// The signer refused (context too long, or a library failure).
    Signing,
}

impl std::fmt::Display for PqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownScheme(id) => write!(f, "unknown scheme 0x{:04x}", id.0),
            Self::SchemeNotVerifiable(id) => {
                write!(
                    f,
                    "scheme 0x{:04x} is not verifiable in its current status",
                    id.0
                )
            }
            Self::Unsupported(id) => write!(f, "scheme 0x{:04x} has no implementation here", id.0),
            Self::EmptyContext => write!(f, "an empty context string is refused"),
            Self::ContextTooLong(n) => write!(f, "context string of {n} bytes exceeds 255"),
            Self::PublicKeyLength {
                scheme,
                expected,
                got,
            } => write!(
                f,
                "public key length for scheme 0x{:04x}: expected {expected}, got {got}",
                scheme.0
            ),
            Self::SignatureLength {
                scheme,
                expected,
                got,
            } => write!(
                f,
                "signature length for scheme 0x{:04x}: expected {expected}, got {got}",
                scheme.0
            ),
            Self::SeedLength {
                scheme,
                expected,
                got,
            } => write!(
                f,
                "seed length for scheme 0x{:04x}: expected {expected}, got {got}",
                scheme.0
            ),
            Self::MalformedPublicKey => write!(f, "malformed public key"),
            Self::Rejected => write!(f, "signature rejected"),
            Self::VerifierDisagreement => {
                write!(f, "the two ML-DSA verifiers disagree; treated as invalid")
            }
            Self::Signing => write!(f, "signing failed"),
        }
    }
}

impl std::error::Error for PqError {}

fn check_context(ctx: &[u8]) -> Result<(), PqError> {
    if ctx.is_empty() {
        return Err(PqError::EmptyContext);
    }
    if ctx.len() > MAX_CONTEXT_LEN {
        return Err(PqError::ContextTooLong(ctx.len()));
    }
    Ok(())
}

/// The public key and signature lengths of a scheme this facade implements.
fn lengths(scheme: SchemeId) -> Result<(usize, usize), PqError> {
    let info = scheme.info().ok_or(PqError::UnknownScheme(scheme))?;
    match (info.public_key_len, info.signature_len) {
        (Some(pk), Some(sig)) => Ok((pk, sig)),
        _ => Err(PqError::Unsupported(scheme)),
    }
}

/// The public key length of an ML-DSA or SLH-DSA scheme.
///
/// # Errors
///
/// [`PqError::UnknownScheme`] or [`PqError::Unsupported`].
pub fn public_key_len(scheme: SchemeId) -> Result<usize, PqError> {
    lengths(scheme).map(|(pk, _)| pk)
}

/// The signature length of an ML-DSA or SLH-DSA scheme.
///
/// # Errors
///
/// [`PqError::UnknownScheme`] or [`PqError::Unsupported`].
pub fn signature_len(scheme: SchemeId) -> Result<usize, PqError> {
    lengths(scheme).map(|(_, sig)| sig)
}

/// Verify a signature under the statuses of a fresh genesis.
///
/// A chain with its own [`SchemeStatusRegistry`] calls [`verify_in`].
///
/// # Errors
///
/// [`PqError`] when the context is empty or too long, the scheme is unknown,
/// reserved, deprecated past use or has no implementation here, a length is
/// wrong, the signature is invalid, or the two ML-DSA libraries disagree.
pub fn verify(
    scheme: SchemeId,
    public_key: &[u8],
    message: &[u8],
    ctx: &[u8],
    signature: &[u8],
) -> Result<(), PqError> {
    verify_in(
        &SchemeStatusRegistry::genesis(),
        scheme,
        public_key,
        message,
        ctx,
        signature,
    )
}

/// Verify a signature under the scheme statuses of a chain.
///
/// # Errors
///
/// See [`verify`]. A scheme the registry does not mark verifiable is refused
/// with [`PqError::SchemeNotVerifiable`] before any key is decoded.
pub fn verify_in(
    registry: &SchemeStatusRegistry,
    scheme: SchemeId,
    public_key: &[u8],
    message: &[u8],
    ctx: &[u8],
    signature: &[u8],
) -> Result<(), PqError> {
    check_context(ctx)?;
    let (pk_len, sig_len) = lengths(scheme)?;
    if registry.scheme_status(scheme).is_none() {
        return Err(PqError::UnknownScheme(scheme));
    }
    if !registry.scheme_verifies(scheme) {
        return Err(PqError::SchemeNotVerifiable(scheme));
    }
    if public_key.len() != pk_len {
        return Err(PqError::PublicKeyLength {
            scheme,
            expected: pk_len,
            got: public_key.len(),
        });
    }
    if signature.len() != sig_len {
        return Err(PqError::SignatureLength {
            scheme,
            expected: sig_len,
            got: signature.len(),
        });
    }
    if scheme == SchemeId::ML_DSA_65 {
        let primary = ml_dsa_65::rustcrypto_verify(public_key, message, ctx, signature)?;
        let secondary = ml_dsa_65::libcrux_verify(public_key, message, ctx, signature)?;
        return combine_verdicts(primary, secondary);
    }
    if scheme == SchemeId::ML_DSA_87 {
        let primary = ml_dsa_87::rustcrypto_verify(public_key, message, ctx, signature)?;
        let secondary = ml_dsa_87::libcrux_verify(public_key, message, ctx, signature)?;
        return combine_verdicts(primary, secondary);
    }
    if scheme == SchemeId::SLH_DSA_SHAKE_256S {
        return slh_verdict(slh_shake_256s::verify(public_key, message, ctx, signature)?);
    }
    if scheme == SchemeId::SLH_DSA_SHAKE_128S {
        return slh_verdict(slh_shake_128s::verify(public_key, message, ctx, signature)?);
    }
    Err(PqError::Unsupported(scheme))
}

fn slh_verdict(accepted: bool) -> Result<(), PqError> {
    if accepted {
        Ok(())
    } else {
        Err(PqError::Rejected)
    }
}

/// Merge the verdicts of the two ML-DSA libraries.
///
/// Valid only when both accept. A split verdict is invalid, and it is counted.
///
/// # Errors
///
/// [`PqError::Rejected`] when both refuse, [`PqError::VerifierDisagreement`]
/// when they split.
pub fn combine_verdicts(primary: bool, secondary: bool) -> Result<(), PqError> {
    match (primary, secondary) {
        (true, true) => Ok(()),
        (false, false) => Err(PqError::Rejected),
        _ => {
            VERIFIER_DISAGREEMENTS.fetch_add(1, Ordering::Relaxed);
            Err(PqError::VerifierDisagreement)
        }
    }
}

/// Verify with one named ML-DSA library only. For differential tests and
/// measurement; consensus code never calls it. It returns the raw verdict of
/// that library and does not apply the facade context policy.
///
/// # Errors
///
/// [`PqError`] for a wrong length or an unsupported scheme.
pub fn verify_ml_dsa_single(
    backend: MlDsaBackend,
    scheme: SchemeId,
    public_key: &[u8],
    message: &[u8],
    ctx: &[u8],
    signature: &[u8],
) -> Result<bool, PqError> {
    // The raw verdict of one library: the context-policy of the facade (an
    // empty context is refused) is deliberately not applied here, so the NIST
    // vectors, which include empty contexts, can be replayed. FIPS 204 still
    // caps the context at 255 bytes.
    if ctx.len() > MAX_CONTEXT_LEN {
        return Err(PqError::ContextTooLong(ctx.len()));
    }
    let (pk_len, sig_len) = lengths(scheme)?;
    if public_key.len() != pk_len {
        return Err(PqError::PublicKeyLength {
            scheme,
            expected: pk_len,
            got: public_key.len(),
        });
    }
    if signature.len() != sig_len {
        return Err(PqError::SignatureLength {
            scheme,
            expected: sig_len,
            got: signature.len(),
        });
    }
    match (backend, scheme) {
        (MlDsaBackend::RustCrypto, SchemeId::ML_DSA_65) => {
            ml_dsa_65::rustcrypto_verify(public_key, message, ctx, signature)
        }
        (MlDsaBackend::Libcrux, SchemeId::ML_DSA_65) => {
            ml_dsa_65::libcrux_verify(public_key, message, ctx, signature)
        }
        (MlDsaBackend::RustCrypto, SchemeId::ML_DSA_87) => {
            ml_dsa_87::rustcrypto_verify(public_key, message, ctx, signature)
        }
        (MlDsaBackend::Libcrux, SchemeId::ML_DSA_87) => {
            ml_dsa_87::libcrux_verify(public_key, message, ctx, signature)
        }
        _ => Err(PqError::Unsupported(scheme)),
    }
}

/// One of the two ML-DSA implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaBackend {
    /// RustCrypto `ml-dsa`.
    RustCrypto,
    /// `libcrux-ml-dsa`, portable backend.
    Libcrux,
}

/// Check that a public key has the length of its scheme.
///
/// ML-DSA and SLH-DSA public keys have no invalid encodings beyond length, so
/// this is the whole structural check.
///
/// # Errors
///
/// [`PqError::PublicKeyLength`] and the scheme errors of [`public_key_len`].
pub fn validate_public_key(scheme: SchemeId, public_key: &[u8]) -> Result<(), PqError> {
    let expected = public_key_len(scheme)?;
    if public_key.len() == expected {
        Ok(())
    } else {
        Err(PqError::PublicKeyLength {
            scheme,
            expected,
            got: public_key.len(),
        })
    }
}

/// The seed length of an ML-DSA key (FIPS 204 `xi`).
pub const ML_DSA_SEED_LEN: usize = 32;

/// Derive the encoded ML-DSA public key from a 32-byte seed.
///
/// # Errors
///
/// [`PqError::Unsupported`] for a scheme other than ML-DSA-65 and ML-DSA-87.
pub fn ml_dsa_public_key(
    scheme: SchemeId,
    seed: &[u8; ML_DSA_SEED_LEN],
) -> Result<Vec<u8>, PqError> {
    if scheme == SchemeId::ML_DSA_65 {
        return Ok(ml_dsa_65::public_key(seed));
    }
    if scheme == SchemeId::ML_DSA_87 {
        return Ok(ml_dsa_87::public_key(seed));
    }
    Err(PqError::Unsupported(scheme))
}

/// Sign with ML-DSA under a 32-byte seed, a context and 32 bytes of
/// randomness.
///
/// `rnd` all zero is the FIPS 204 deterministic variant; fresh random bytes are
/// the hedged variant (FIPS 204 section 3.4). The caller supplies the bytes so
/// this module needs no entropy source and works on every target.
///
/// # Errors
///
/// [`PqError`] for an empty or too long context, or an unsupported scheme.
pub fn ml_dsa_sign(
    scheme: SchemeId,
    seed: &[u8; ML_DSA_SEED_LEN],
    message: &[u8],
    ctx: &[u8],
    rnd: &[u8; 32],
) -> Result<Vec<u8>, PqError> {
    check_context(ctx)?;
    if scheme == SchemeId::ML_DSA_65 {
        return ml_dsa_65::sign(seed, message, ctx, rnd);
    }
    if scheme == SchemeId::ML_DSA_87 {
        return ml_dsa_87::sign(seed, message, ctx, rnd);
    }
    Err(PqError::Unsupported(scheme))
}

/// Sign with the `libcrux-ml-dsa` portable backend. Differential tests only.
///
/// # Errors
///
/// [`PqError`] for an empty or too long context, or an unsupported scheme.
/// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
pub fn ml_dsa_sign_libcrux(
    scheme: SchemeId,
    seed: &[u8; ML_DSA_SEED_LEN],
    message: &[u8],
    ctx: &[u8],
    rnd: &[u8; 32],
) -> Result<Vec<u8>, PqError> {
    check_context(ctx)?;
    if scheme == SchemeId::ML_DSA_65 {
        return ml_dsa_65::libcrux_sign(seed, message, ctx, rnd);
    }
    if scheme == SchemeId::ML_DSA_87 {
        return ml_dsa_87::libcrux_sign(seed, message, ctx, rnd);
    }
    Err(PqError::Unsupported(scheme))
}

/// The seed length of an SLH-DSA key: `sk_seed || sk_prf || pk_seed`, three
/// blocks of the parameter set's `n`.
///
/// # Errors
///
/// [`PqError::Unsupported`] for a scheme that is not an implemented SLH-DSA set.
pub fn slh_dsa_seed_len(scheme: SchemeId) -> Result<usize, PqError> {
    if scheme == SchemeId::SLH_DSA_SHAKE_256S {
        return Ok(slh_shake_256s::SEED_LEN);
    }
    if scheme == SchemeId::SLH_DSA_SHAKE_128S {
        return Ok(slh_shake_128s::SEED_LEN);
    }
    Err(PqError::Unsupported(scheme))
}

/// Derive the encoded SLH-DSA public key from a seed.
///
/// # Errors
///
/// [`PqError::SeedLength`] or [`PqError::Unsupported`].
pub fn slh_dsa_public_key(scheme: SchemeId, seed: &[u8]) -> Result<Vec<u8>, PqError> {
    if scheme == SchemeId::SLH_DSA_SHAKE_256S {
        return slh_shake_256s::public_key(seed);
    }
    if scheme == SchemeId::SLH_DSA_SHAKE_128S {
        return slh_shake_128s::public_key(seed);
    }
    Err(PqError::Unsupported(scheme))
}

/// Sign with SLH-DSA. `rnd` is the optional randomizer (`n` bytes); `None` is
/// the deterministic variant.
///
/// # Errors
///
/// [`PqError`] for a wrong seed or randomizer length, an empty or too long
/// context, or an unsupported scheme.
pub fn slh_dsa_sign(
    scheme: SchemeId,
    seed: &[u8],
    message: &[u8],
    ctx: &[u8],
    rnd: Option<&[u8]>,
) -> Result<Vec<u8>, PqError> {
    check_context(ctx)?;
    if scheme == SchemeId::SLH_DSA_SHAKE_256S {
        return slh_shake_256s::sign(seed, message, ctx, rnd);
    }
    if scheme == SchemeId::SLH_DSA_SHAKE_128S {
        return slh_shake_128s::sign(seed, message, ctx, rnd);
    }
    Err(PqError::Unsupported(scheme))
}

/// ML-DSA for one parameter set: both verifiers, key derivation and signing.
macro_rules! ml_dsa_set {
    (
        $module:ident,
        $param:ty,
        $pk_len:expr,
        $sig_len:expr,
        $lx:ident,
        $lx_vk:ident,
        $lx_sig:ident
    ) => {
        mod $module {
            use super::PqError;
            use ml_dsa::signature::Keypair as _;

            pub(super) fn rustcrypto_verify(
                public_key: &[u8],
                message: &[u8],
                ctx: &[u8],
                signature: &[u8],
            ) -> Result<bool, PqError> {
                let enc_vk = ml_dsa::EncodedVerifyingKey::<$param>::try_from(public_key)
                    .map_err(|_| PqError::MalformedPublicKey)?;
                let vk = ml_dsa::VerifyingKey::<$param>::decode(&enc_vk);
                let Ok(enc_sig) = ml_dsa::EncodedSignature::<$param>::try_from(signature) else {
                    return Ok(false);
                };
                let Some(sig) = ml_dsa::Signature::<$param>::decode(&enc_sig) else {
                    return Ok(false);
                };
                Ok(vk.verify_with_context(message, ctx, &sig))
            }

            pub(super) fn libcrux_verify(
                public_key: &[u8],
                message: &[u8],
                ctx: &[u8],
                signature: &[u8],
            ) -> Result<bool, PqError> {
                let pk: [u8; $pk_len] = public_key
                    .try_into()
                    .map_err(|_| PqError::MalformedPublicKey)?;
                let Ok(sig_bytes) = <[u8; $sig_len]>::try_from(signature) else {
                    return Ok(false);
                };
                let vk = libcrux_ml_dsa::$lx::$lx_vk::new(pk);
                let sig = libcrux_ml_dsa::$lx::$lx_sig::new(sig_bytes);
                Ok(libcrux_ml_dsa::$lx::portable::verify(&vk, message, ctx, &sig).is_ok())
            }

            pub(super) fn public_key(seed: &[u8; 32]) -> Vec<u8> {
                let sk = ml_dsa::SigningKey::<$param>::from_seed(seed.into());
                let vk = sk.verifying_key();
                let enc = vk.encode();
                let bytes: &[u8] = enc.as_ref();
                bytes.to_vec()
            }

            pub(super) fn sign(
                seed: &[u8; 32],
                message: &[u8],
                ctx: &[u8],
                rnd: &[u8; 32],
            ) -> Result<Vec<u8>, PqError> {
                let ctx_len = u8::try_from(ctx.len()).map_err(|_| PqError::Signing)?;
                let sk = ml_dsa::SigningKey::<$param>::from_seed(seed.into());
                let header = [0u8, ctx_len];
                // FIPS 204 Algorithm 2: M' = 0x00 || len(ctx) || ctx || M, then
                // Sign_internal with the caller's `rnd`.
                let parts: [&[u8]; 3] = [header.as_slice(), ctx, message];
                let sig = sk.expanded_key().sign_internal(&parts, rnd.into());
                let enc = sig.encode();
                let bytes: &[u8] = enc.as_ref();
                Ok(bytes.to_vec())
            }

            pub(super) fn libcrux_sign(
                seed: &[u8; 32],
                message: &[u8],
                ctx: &[u8],
                rnd: &[u8; 32],
            ) -> Result<Vec<u8>, PqError> {
                let pair = libcrux_ml_dsa::$lx::portable::generate_key_pair(*seed);
                let sig =
                    libcrux_ml_dsa::$lx::portable::sign(&pair.signing_key, message, ctx, *rnd)
                        .map_err(|_| PqError::Signing)?;
                Ok(sig.as_slice().to_vec())
            }
        }
    };
}

ml_dsa_set!(
    ml_dsa_65,
    ml_dsa::MlDsa65,
    1952,
    3309,
    ml_dsa_65,
    MLDSA65VerificationKey,
    MLDSA65Signature
);
ml_dsa_set!(
    ml_dsa_87,
    ml_dsa::MlDsa87,
    2592,
    4627,
    ml_dsa_87,
    MLDSA87VerificationKey,
    MLDSA87Signature
);

/// SLH-DSA for one parameter set.
macro_rules! slh_dsa_set {
    ($module:ident, $param:ty, $n:expr) => {
        mod $module {
            use super::PqError;
            use slh_dsa::{Signature, SigningKey, VerifyingKey};

            /// `sk_seed || sk_prf || pk_seed`.
            pub(super) const SEED_LEN: usize = 3 * $n;

            fn key_from_seed(seed: &[u8]) -> Result<SigningKey<$param>, PqError> {
                if seed.len() != SEED_LEN {
                    return Err(PqError::SeedLength {
                        scheme: super::scheme_of_n($n),
                        expected: SEED_LEN,
                        got: seed.len(),
                    });
                }
                let (sk_seed, rest) = seed.split_at($n);
                let (sk_prf, pk_seed) = rest.split_at($n);
                Ok(SigningKey::<$param>::slh_keygen_internal(
                    sk_seed, sk_prf, pk_seed,
                ))
            }

            pub(super) fn public_key(seed: &[u8]) -> Result<Vec<u8>, PqError> {
                let sk = key_from_seed(seed)?;
                let vk: &VerifyingKey<$param> = sk.as_ref();
                Ok(vk.to_vec())
            }

            pub(super) fn sign(
                seed: &[u8],
                message: &[u8],
                ctx: &[u8],
                rnd: Option<&[u8]>,
            ) -> Result<Vec<u8>, PqError> {
                if rnd.is_some_and(|r| r.len() != $n) {
                    return Err(PqError::Signing);
                }
                let sk = key_from_seed(seed)?;
                let sig = sk
                    .try_sign_with_context(message, ctx, rnd)
                    .map_err(|_| PqError::Signing)?;
                Ok(sig.to_vec())
            }

            pub(super) fn verify(
                public_key: &[u8],
                message: &[u8],
                ctx: &[u8],
                signature: &[u8],
            ) -> Result<bool, PqError> {
                let vk = VerifyingKey::<$param>::try_from(public_key)
                    .map_err(|_| PqError::MalformedPublicKey)?;
                let Ok(sig) = Signature::<$param>::try_from(signature) else {
                    return Ok(false);
                };
                Ok(vk.try_verify_with_context(message, ctx, &sig).is_ok())
            }
        }
    };
}

slh_dsa_set!(slh_shake_128s, slh_dsa::Shake128s, 16);
slh_dsa_set!(slh_shake_256s, slh_dsa::Shake256s, 32);

/// The scheme of an SLH-DSA parameter set by its `n`, for error messages.
const fn scheme_of_n(n: usize) -> SchemeId {
    if n == 16 {
        SchemeId::SLH_DSA_SHAKE_128S
    } else {
        SchemeId::SLH_DSA_SHAKE_256S
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ctx;

    const MSG: &[u8] = b"budlum pq facade test message";

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn ml_dsa_round_trips_through_both_verifiers() {
        for scheme in [SchemeId::ML_DSA_65, SchemeId::ML_DSA_87] {
            let pk = ml_dsa_public_key(scheme, &seed(7)).unwrap();
            let sig = ml_dsa_sign(scheme, &seed(7), MSG, ctx::TX_V7, &[0u8; 32]).unwrap();
            assert_eq!(pk.len(), public_key_len(scheme).unwrap());
            assert_eq!(sig.len(), signature_len(scheme).unwrap());
            assert_eq!(verify(scheme, &pk, MSG, ctx::TX_V7, &sig), Ok(()));
            for backend in [MlDsaBackend::RustCrypto, MlDsaBackend::Libcrux] {
                assert_eq!(
                    verify_ml_dsa_single(backend, scheme, &pk, MSG, ctx::TX_V7, &sig),
                    Ok(true)
                );
            }
        }
    }

    #[test]
    fn the_two_ml_dsa_libraries_sign_identically() {
        for scheme in [SchemeId::ML_DSA_65, SchemeId::ML_DSA_87] {
            let rnd = [0x5Au8; 32];
            let a = ml_dsa_sign(scheme, &seed(3), MSG, ctx::QC_V2, &rnd).unwrap();
            let b = ml_dsa_sign_libcrux(scheme, &seed(3), MSG, ctx::QC_V2, &rnd).unwrap();
            assert_eq!(
                a, b,
                "same seed, context and randomness give the same bytes"
            );
        }
    }

    #[test]
    fn a_wrong_context_message_or_key_is_rejected() {
        let scheme = SchemeId::ML_DSA_65;
        let pk = ml_dsa_public_key(scheme, &seed(1)).unwrap();
        let other = ml_dsa_public_key(scheme, &seed(2)).unwrap();
        let sig = ml_dsa_sign(scheme, &seed(1), MSG, ctx::TX_V7, &[0u8; 32]).unwrap();
        assert_eq!(
            verify(scheme, &pk, MSG, ctx::BLOCK_V6, &sig),
            Err(PqError::Rejected)
        );
        assert_eq!(
            verify(scheme, &pk, b"other", ctx::TX_V7, &sig),
            Err(PqError::Rejected)
        );
        assert_eq!(
            verify(scheme, &other, MSG, ctx::TX_V7, &sig),
            Err(PqError::Rejected)
        );
    }

    #[test]
    fn an_empty_or_long_context_is_refused() {
        let scheme = SchemeId::ML_DSA_65;
        let pk = ml_dsa_public_key(scheme, &seed(1)).unwrap();
        let sig = ml_dsa_sign(scheme, &seed(1), MSG, ctx::TX_V7, &[0u8; 32]).unwrap();
        assert_eq!(
            verify(scheme, &pk, MSG, b"", &sig),
            Err(PqError::EmptyContext)
        );
        let long = [b'a'; 256];
        assert_eq!(
            verify(scheme, &pk, MSG, &long, &sig),
            Err(PqError::ContextTooLong(256))
        );
        assert_eq!(
            ml_dsa_sign(scheme, &seed(1), MSG, b"", &[0u8; 32]),
            Err(PqError::EmptyContext)
        );
        let max = [b'a'; 255];
        let sig = ml_dsa_sign(scheme, &seed(1), MSG, &max, &[0u8; 32]).unwrap();
        assert_eq!(verify(scheme, &pk, MSG, &max, &sig), Ok(()));
    }

    #[test]
    fn unknown_reserved_and_wrong_length_inputs_are_refused() {
        let pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &seed(1)).unwrap();
        let sig = ml_dsa_sign(SchemeId::ML_DSA_65, &seed(1), MSG, ctx::TX_V7, &[0u8; 32]).unwrap();
        assert_eq!(
            verify(SchemeId(0x7777), &pk, MSG, ctx::TX_V7, &sig),
            Err(PqError::UnknownScheme(SchemeId(0x7777)))
        );
        // ML-DSA-44 is Reserved at genesis: listed, not verifiable.
        let pk44 = vec![0u8; 1312];
        let sig44 = vec![0u8; 2420];
        assert_eq!(
            verify(SchemeId::ML_DSA_44, &pk44, MSG, ctx::TX_V7, &sig44),
            Err(PqError::SchemeNotVerifiable(SchemeId::ML_DSA_44))
        );
        // A 87 signature under the 65 name: the scheme is named, the length is checked.
        let pk87 = ml_dsa_public_key(SchemeId::ML_DSA_87, &seed(1)).unwrap();
        let sig87 =
            ml_dsa_sign(SchemeId::ML_DSA_87, &seed(1), MSG, ctx::TX_V7, &[0u8; 32]).unwrap();
        assert!(matches!(
            verify(SchemeId::ML_DSA_65, &pk87, MSG, ctx::TX_V7, &sig87),
            Err(PqError::PublicKeyLength { .. })
        ));
        assert!(matches!(
            verify(SchemeId::ML_DSA_65, &pk, MSG, ctx::TX_V7, &sig87),
            Err(PqError::SignatureLength { .. })
        ));
        assert!(matches!(
            verify(SchemeId::ED25519, &[0u8; 32], MSG, ctx::TX_V7, &[0u8; 64]),
            Err(PqError::Unsupported(_))
        ));
    }

    #[test]
    fn a_disabled_scheme_is_refused_by_the_chain_registry() {
        use crate::crypto::scheme::{SchemeStatus, TransitionSource};
        let scheme = SchemeId::ML_DSA_65;
        let pk = ml_dsa_public_key(scheme, &seed(1)).unwrap();
        let sig = ml_dsa_sign(scheme, &seed(1), MSG, ctx::TX_V7, &[0u8; 32]).unwrap();
        let mut registry = SchemeStatusRegistry::genesis();
        assert_eq!(
            verify_in(&registry, scheme, &pk, MSG, ctx::TX_V7, &sig),
            Ok(())
        );
        for to in [SchemeStatus::Deprecated, SchemeStatus::Disabled] {
            registry
                .transition_scheme(scheme, to, TransitionSource::CanaryAlarm)
                .unwrap();
        }
        assert_eq!(
            verify_in(&registry, scheme, &pk, MSG, ctx::TX_V7, &sig),
            Err(PqError::SchemeNotVerifiable(scheme))
        );
    }

    #[test]
    fn a_split_verdict_is_invalid_and_counted() {
        let before = verifier_disagreements();
        assert_eq!(combine_verdicts(true, true), Ok(()));
        assert_eq!(combine_verdicts(false, false), Err(PqError::Rejected));
        assert_eq!(verifier_disagreements(), before);
        assert_eq!(
            combine_verdicts(true, false),
            Err(PqError::VerifierDisagreement)
        );
        assert_eq!(
            combine_verdicts(false, true),
            Err(PqError::VerifierDisagreement)
        );
        assert!(verifier_disagreements() >= before + 2);
    }

    #[test]
    fn slh_dsa_128s_round_trips_and_binds_the_context() {
        let scheme = SchemeId::SLH_DSA_SHAKE_128S;
        let seed = [9u8; 48];
        let pk = slh_dsa_public_key(scheme, &seed).unwrap();
        assert_eq!(pk.len(), 32);
        let sig = slh_dsa_sign(scheme, &seed, MSG, ctx::RECOVERY_V1, None).unwrap();
        assert_eq!(sig.len(), 7856);
        let mut registry = SchemeStatusRegistry::genesis();
        // Reserved at genesis: the genesis facade refuses it until it is activated.
        assert_eq!(
            verify(scheme, &pk, MSG, ctx::RECOVERY_V1, &sig),
            Err(PqError::SchemeNotVerifiable(scheme))
        );
        registry
            .transition_scheme(
                scheme,
                crate::crypto::scheme::SchemeStatus::Active,
                crate::crypto::scheme::TransitionSource::CanaryAlarm,
            )
            .unwrap();
        assert_eq!(
            verify_in(&registry, scheme, &pk, MSG, ctx::RECOVERY_V1, &sig),
            Ok(())
        );
        assert_eq!(
            verify_in(&registry, scheme, &pk, MSG, ctx::SEAL_V1, &sig),
            Err(PqError::Rejected)
        );
    }

    #[test]
    fn slh_dsa_refuses_a_wrong_seed_length() {
        assert!(matches!(
            slh_dsa_public_key(SchemeId::SLH_DSA_SHAKE_256S, &[0u8; 95]),
            Err(PqError::SeedLength { .. })
        ));
        assert_eq!(slh_dsa_seed_len(SchemeId::SLH_DSA_SHAKE_256S), Ok(96));
        assert_eq!(slh_dsa_seed_len(SchemeId::SLH_DSA_SHAKE_128S), Ok(48));
    }
}

#[cfg(test)]
#[path = "pq_vector_tests.rs"]
mod vector_tests;
