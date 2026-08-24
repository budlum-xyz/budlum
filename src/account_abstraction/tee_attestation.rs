//! TEE attestation: binds the producer of a quote to a signature.
//!
//! # What this module used to be
//!
//! `TeeRuntime::sign` did not produce a signature. It copied the SHA3-256
//! digest of the message into the first 32 bytes of a 4627-byte buffer, left
//! the rest zero, and called that a "sig". Nothing verified it either:
//! `TeeAttestation::verify` only looked at `self.signature.len() != 4627`,
//! and since the field is `[u8; 4627]` that condition was always false at
//! compile time. Verification was a branch that could reject nothing.
//!
//! A digest is not a signature, because anyone can compute a digest. That
//! buffer could also be produced by somebody who does not hold the
//! attestation key.
//!
//! # What it does now
//!
//! An attestation is a quote bound to an ML-DSA-87 public key, and the
//! signature really is verified. What the module says is: "the party holding
//! this key signed this quote".
//!
//! # What it does not say
//!
//! The *content* of the quote is not verified here. Checking the vendor
//! certificate chain - PCK and QE identity for Intel SGX, the ACM root
//! certificate for AWS Nitro - is outside this module and needs a trust root
//! in the node configuration. So [`TeeAttestation::verify_signed_by`] does not
//! say "this is a genuine SGX device"; it says "this quote was signed with
//! this key, and the key is the one I expected". To keep the two apart, the
//! type is named `TeeAttestation` and the method `verify_signed_by`: what is
//! being verified reads off the call site.
//!
//! # Fail-closed
//!
//! With no backend, signing fails. No unsigned or plaintext result is returned
//! quietly. If a caller ignores the `Err`, no attestation comes into being at
//! all - not an empty one.
//!
//! WIRING: unwired - measured, and the previous rationale was stale.
//!
//! The old rationale said "until account abstraction is wired to transaction
//! verification". Account abstraction **is** wired: `Transaction::verify_v6`
//! calls `threshold_mldsa`, and V6 transactions are verified with a threshold
//! signature. So the expected condition happened, and this module is still not
//! called.
//!
//! The real reason is different: a transaction **carries no attestation**.
//! `verify_v6` reads the owner set, the threshold and the signatures; there is
//! no field for an attestation.
//!
//! Adding a field is a change to the commitment surface, and it would be wrong
//! to do on its own. An attestation is a claim about *where* the signing key
//! sits, and putting it inside a transaction also requires that the verifying
//! side have something to check that claim against. This module already states
//! its own limit: `verify_signed_by` does not say "this is a genuine SGX
//! device", it says "this quote was signed with this key". Checking the vendor
//! certificate chain wants a trust root, and the node configuration has none.
//!
//! So the only thing that could be written to the chain would be an
//! uncheckable claim. `TeeGates` stands as "the single entry point the
//! production path will call", and when that entry point opens the wiring will
//! be one line. It does not open today, because there is no trust root to
//! stand behind it.

use crate::crypto::primitives::{
    verify_ml_dsa_87_signature, ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN,
};

/// The largest number of bytes a quote may carry.
///
/// A quote arrives over the network, so it cannot be unbounded. The limit caps
/// the verification work a single attestation can load onto the node.
pub const MAX_QUOTE_LEN: usize = 16 * 1024;

/// The domain separator the signature is taken over.
///
/// It stops some other structure signed with the same key - a transaction, for
/// instance - from being read as an attestation: the signature is always
/// produced with this prefix.
pub const TEE_ATTESTATION_DOMAIN: &[u8] = b"BUDLUM_TEE_ATTESTATION_V1";

/// Which backend the attestation comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeBackendKind {
    Sgx,
    Nitro,
    Unavailable,
}

/// State of the local TEE runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeRuntimeStatus {
    Available,
    Unavailable,
    AttestationFailed,
}

/// Why an attestation was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeeError {
    /// No backend: fail-closed.
    BackendUnavailable,
    /// The runtime could not produce an attestation.
    AttestationFailed,
    /// The quote is empty.
    EmptyQuote,
    /// The quote is above [`MAX_QUOTE_LEN`].
    QuoteTooLarge { len: usize },
    /// The attestation belongs to a key other than the expected one.
    UnexpectedKey,
    /// The ML-DSA-87 signature did not verify.
    InvalidSignature,
}

impl core::fmt::Display for TeeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BackendUnavailable => {
                write!(f, "KQ-WALLET-TEE: backend unavailable, refusing to proceed")
            }
            Self::AttestationFailed => write!(f, "KQ-WALLET-TEE: runtime attestation failed"),
            Self::EmptyQuote => write!(f, "KQ-WALLET-TEE: quote is empty"),
            Self::QuoteTooLarge { len } => write!(
                f,
                "KQ-WALLET-TEE: quote of {len} bytes exceeds the {MAX_QUOTE_LEN} byte limit"
            ),
            Self::UnexpectedKey => {
                write!(f, "KQ-WALLET-TEE: attestation key is not the expected one")
            }
            Self::InvalidSignature => write!(f, "KQ-WALLET-TEE: quote signature does not verify"),
        }
    }
}

impl std::error::Error for TeeError {}

/// The signed bytes: domain separator, backend tag, then a length-prefixed
/// quote.
///
/// Without the length prefix, `quote = "ab" ++ "c"` and `"a" ++ "bc"` would
/// land on the same bytes. The backend tag likewise stops one quote from being
/// reused across two backends.
#[must_use]
pub fn attestation_signing_payload(backend: TeeBackendKind, quote: &[u8]) -> Vec<u8> {
    let tag: u8 = match backend {
        TeeBackendKind::Sgx => 1,
        TeeBackendKind::Nitro => 2,
        TeeBackendKind::Unavailable => 0,
    };
    let mut out = Vec::with_capacity(TEE_ATTESTATION_DOMAIN.len() + 9 + quote.len());
    out.extend_from_slice(TEE_ATTESTATION_DOMAIN);
    out.push(tag);
    out.extend_from_slice(&(quote.len() as u64).to_be_bytes());
    out.extend_from_slice(quote);
    out
}

/// A TEE quote and the signature of the key that produced it.
#[derive(Debug, Clone)]
pub struct TeeAttestation {
    pub backend: TeeBackendKind,
    pub quote: Vec<u8>,
    pub public_key: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
    pub signature: [u8; ML_DSA_87_SIGNATURE_LEN],
}

impl TeeAttestation {
    /// Verifies that the quote was signed by `expected_key`.
    ///
    /// Taking the expected key from the call site is deliberate. An attestation
    /// carries its own key, so a self-verifying attestation proves nothing: an
    /// attacker can generate their own key pair and sign their own quote. The
    /// trust comes from the key the node knew beforehand.
    ///
    /// # Errors
    ///
    /// [`TeeError::BackendUnavailable`], [`TeeError::EmptyQuote`],
    /// [`TeeError::QuoteTooLarge`], [`TeeError::UnexpectedKey`],
    /// [`TeeError::InvalidSignature`].
    pub fn verify_signed_by(
        &self,
        expected_key: &[u8; ML_DSA_87_PUBLIC_KEY_LEN],
    ) -> Result<(), TeeError> {
        if self.backend == TeeBackendKind::Unavailable {
            return Err(TeeError::BackendUnavailable);
        }
        if self.quote.is_empty() {
            return Err(TeeError::EmptyQuote);
        }
        if self.quote.len() > MAX_QUOTE_LEN {
            return Err(TeeError::QuoteTooLarge {
                len: self.quote.len(),
            });
        }
        if &self.public_key != expected_key {
            return Err(TeeError::UnexpectedKey);
        }
        let payload = attestation_signing_payload(self.backend, &self.quote);
        verify_ml_dsa_87_signature(&payload, &self.signature, &self.public_key)
            .map_err(|_| TeeError::InvalidSignature)
    }
}

/// The local TEE runtime.
#[derive(Debug, Clone, Copy)]
pub struct TeeRuntime {
    pub backend: TeeBackendKind,
    pub status: TeeRuntimeStatus,
}

impl TeeRuntime {
    /// Whether the runtime can produce an attestation.
    ///
    /// # Errors
    ///
    /// [`TeeError::BackendUnavailable`], [`TeeError::AttestationFailed`].
    pub fn ensure_available(&self) -> Result<(), TeeError> {
        match self.status {
            TeeRuntimeStatus::Available if self.backend != TeeBackendKind::Unavailable => Ok(()),
            TeeRuntimeStatus::AttestationFailed => Err(TeeError::AttestationFailed),
            _ => Err(TeeError::BackendUnavailable),
        }
    }
}

/// The KQ-* gate surface: the single entry point the production path calls.
pub struct TeeGates;

impl TeeGates {
    /// # Errors
    ///
    /// Every error [`TeeAttestation::verify_signed_by`] returns.
    pub fn kq_wallet_tee_attestation(
        att: &TeeAttestation,
        expected_key: &[u8; ML_DSA_87_PUBLIC_KEY_LEN],
    ) -> Result<(), TeeError> {
        att.verify_signed_by(expected_key)
    }

    /// # Errors
    ///
    /// Every error [`TeeRuntime::ensure_available`] returns.
    pub fn kq_wallet_tee_runtime(runtime: &TeeRuntime) -> Result<(), TeeError> {
        runtime.ensure_available()
    }
}

#[cfg(all(test, feature = "wallet-ml-dsa"))]
mod tests {
    use super::*;
    use crate::crypto::primitives::WalletKeyPair;

    fn attest(kp: &WalletKeyPair, backend: TeeBackendKind, quote: &[u8]) -> TeeAttestation {
        let payload = attestation_signing_payload(backend, quote);
        TeeAttestation {
            backend,
            quote: quote.to_vec(),
            public_key: kp.public_key_bytes(),
            signature: kp.sign(&payload),
        }
    }

    #[test]
    fn a_correctly_signed_quote_is_accepted() {
        let kp = WalletKeyPair::generate();
        let att = attest(&kp, TeeBackendKind::Sgx, b"quote bytes");
        assert_eq!(att.verify_signed_by(&kp.public_key_bytes()), Ok(()));
    }

    /// What the skeleton missed: if a digest is put in place of a signature,
    /// verification should refuse it, yet a check that looks only at the length
    /// accepts it.
    #[test]
    fn a_digest_in_place_of_a_signature_is_refused() {
        use sha3::{Digest, Sha3_256};
        let kp = WalletKeyPair::generate();
        let quote = b"quote bytes";
        let mut forged = [0u8; ML_DSA_87_SIGNATURE_LEN];
        let mut h = Sha3_256::new();
        h.update(quote);
        let digest: [u8; 32] = h.finalize().into();
        forged[..32].copy_from_slice(&digest);
        let att = TeeAttestation {
            backend: TeeBackendKind::Sgx,
            quote: quote.to_vec(),
            public_key: kp.public_key_bytes(),
            signature: forged,
        };
        assert_eq!(
            att.verify_signed_by(&kp.public_key_bytes()),
            Err(TeeError::InvalidSignature)
        );
    }

    /// An attacker can produce a flawless attestation with their own key pair.
    /// The only reason it is refused is that the key is not the expected one.
    #[test]
    fn a_self_signed_quote_from_an_unknown_key_is_refused() {
        let honest = WalletKeyPair::generate();
        let attacker = WalletKeyPair::generate();
        let att = attest(&attacker, TeeBackendKind::Sgx, b"quote bytes");
        assert_eq!(
            att.verify_signed_by(&honest.public_key_bytes()),
            Err(TeeError::UnexpectedKey)
        );
    }

    /// A signature produced for one backend cannot be reused for another.
    #[test]
    fn a_quote_signed_for_one_backend_does_not_verify_for_another() {
        let kp = WalletKeyPair::generate();
        let mut att = attest(&kp, TeeBackendKind::Sgx, b"quote bytes");
        att.backend = TeeBackendKind::Nitro;
        assert_eq!(
            att.verify_signed_by(&kp.public_key_bytes()),
            Err(TeeError::InvalidSignature)
        );
    }

    #[test]
    fn an_empty_or_oversized_quote_is_refused() {
        let kp = WalletKeyPair::generate();
        let empty = attest(&kp, TeeBackendKind::Sgx, b"");
        assert_eq!(
            empty.verify_signed_by(&kp.public_key_bytes()),
            Err(TeeError::EmptyQuote)
        );
        let big = vec![7u8; MAX_QUOTE_LEN + 1];
        let over = attest(&kp, TeeBackendKind::Sgx, &big);
        assert_eq!(
            over.verify_signed_by(&kp.public_key_bytes()),
            Err(TeeError::QuoteTooLarge {
                len: MAX_QUOTE_LEN + 1
            })
        );
    }

    #[test]
    fn an_unavailable_runtime_fails_closed() {
        let runtime = TeeRuntime {
            backend: TeeBackendKind::Unavailable,
            status: TeeRuntimeStatus::Unavailable,
        };
        assert_eq!(
            runtime.ensure_available(),
            Err(TeeError::BackendUnavailable)
        );
        let failed = TeeRuntime {
            backend: TeeBackendKind::Sgx,
            status: TeeRuntimeStatus::AttestationFailed,
        };
        assert_eq!(failed.ensure_available(), Err(TeeError::AttestationFailed));
        let ok = TeeRuntime {
            backend: TeeBackendKind::Sgx,
            status: TeeRuntimeStatus::Available,
        };
        assert_eq!(ok.ensure_available(), Ok(()));
    }

    /// Without the length prefix, two different quotes would land on the same
    /// bytes.
    #[test]
    fn quote_framing_is_unambiguous() {
        let a = attestation_signing_payload(TeeBackendKind::Sgx, b"abc");
        let b = attestation_signing_payload(TeeBackendKind::Sgx, b"ab");
        assert_ne!(a, b);
        assert_ne!(
            attestation_signing_payload(TeeBackendKind::Sgx, b"x"),
            attestation_signing_payload(TeeBackendKind::Nitro, b"x")
        );
    }
}
