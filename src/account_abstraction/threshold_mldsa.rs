//! Threshold ML-DSA-87 authorization: t-of-n signature verification.
//!
//! # What this module used to be
//!
//! This file was once a skeleton, and it said so in its own comments:
//! `shamir_split` was not real Shamir but `secret XOR index`,
//! `shamir_reconstruct` returned with a fixed mask ("This is NOT secure, just
//! for skeleton"), and `verify` only looked at the length of the array. The
//! names, meanwhile, read like real security: `ThresholdMldsaSignature`,
//! `kq_threshold_mldsa_sig`. A caller looking at that surface could have
//! assumed threshold signing was being verified.
//!
//! The skeleton did not even compile, because the `src/account_abstraction/`
//! directory was never reached from `lib.rs`. That was measured: when invalid
//! Rust was written into the file, `cargo check` still passed. Code that does
//! not compile is code no gate can see.
//!
//! # What it does now
//!
//! Secret sharing was removed from this module entirely. There is no reason for
//! a chain verifier to be splitting a private key: what the chain sees is
//! signatures, not keys. The `t-of-n` question is "did at least t of the n
//! owners sign this message", and each signature is verified on its own with
//! `verify_ml_dsa_87_signature`.
//!
//! This is not a substitute for threshold signing, a protocol that produces one
//! aggregate signature. It is a multisig that verifies `t` separate signatures
//! one by one. The difference is by design and is not hidden in the naming: the
//! type is `MultisigAuthorization`, because that is what it does.
//!
//! # What is refused
//!
//! * Counting the same signer twice. If the owner list repeats, or the same
//!   owner sends two signatures, the threshold would be met fraudulently.
//! * A signature from an owner who is not on the list.
//! * `t == 0`. A zero threshold means "it is enough that nobody signs".
//! * `t > n`. A threshold that can never be met quietly produces an account
//!   that always refuses; that is a lockout, and it is reported as an error.
//!
//! # Where it is called from
//!
//! `Transaction::verify` brings V6 transactions here
//! (`src/core/transaction.rs`, `verify_v6`). For a long time it did not: the
//! `t-of-n` check here ran on real ML-DSA-87, but because the transaction
//! schema carried a single signature, no transaction could bring it an
//! authorization. The rule existed in the code, but there was no path along
//! which it would be applied.
//!
//! V6 opens that path: the transaction carries the owner set and the
//! signatures, the `from` address is derived from the set, and a transaction
//! that does not meet the threshold is refused.

use crate::crypto::primitives::{
    verify_ml_dsa_87_signature, ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN,
};

/// The largest number of owners an account can carry.
///
/// Verification cost is directly proportional to the owner count: each
/// signature is one ML-DSA-87 verification. The upper bound limits the work a
/// single transaction can load onto a node.
pub const MAX_THRESHOLD_OWNERS: usize = 16;

/// Why a threshold configuration or a verification was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThresholdError {
    /// The owner list is empty.
    NoOwners,
    /// The owner count is above [`MAX_THRESHOLD_OWNERS`].
    TooManyOwners { count: usize },
    /// The owner list holds the same key more than once.
    DuplicateOwner,
    /// The threshold is zero: a policy that asks for no signature at all.
    ZeroThreshold,
    /// The threshold exceeds the owner count and can never be met.
    ThresholdAboveOwnerCount { threshold: usize, owners: usize },
    /// The number of valid signatures stayed below the threshold.
    ThresholdNotMet { valid: usize, threshold: usize },
    /// The signature belongs to a key that is not in the owner list.
    UnknownSigner { index: usize },
    /// The same owner sent more than one signature.
    RepeatedSigner { index: usize },
    /// The signature did not pass ML-DSA-87 verification.
    InvalidSignature { index: usize },
}

impl core::fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoOwners => write!(f, "KQ-THRESHOLD-MLDSA: owner set is empty"),
            Self::TooManyOwners { count } => write!(
                f,
                "KQ-THRESHOLD-MLDSA: {count} owners exceeds the {MAX_THRESHOLD_OWNERS} allowed"
            ),
            Self::DuplicateOwner => {
                write!(f, "KQ-THRESHOLD-MLDSA: the owner set repeats a key")
            }
            Self::ZeroThreshold => write!(f, "KQ-THRESHOLD-MLDSA: threshold is zero"),
            Self::ThresholdAboveOwnerCount { threshold, owners } => write!(
                f,
                "KQ-THRESHOLD-MLDSA: threshold {threshold} exceeds {owners} owners and can never be met"
            ),
            Self::ThresholdNotMet { valid, threshold } => write!(
                f,
                "KQ-THRESHOLD-MLDSA: {valid} valid signatures below the threshold of {threshold}"
            ),
            Self::UnknownSigner { index } => write!(
                f,
                "KQ-THRESHOLD-MLDSA: signature {index} is from a key outside the owner set"
            ),
            Self::RepeatedSigner { index } => write!(
                f,
                "KQ-THRESHOLD-MLDSA: signature {index} repeats an owner that already signed"
            ),
            Self::InvalidSignature { index } => {
                write!(f, "KQ-THRESHOLD-MLDSA: signature {index} does not verify")
            }
        }
    }
}

impl std::error::Error for ThresholdError {}

/// A signature an owner produced over a message.
#[derive(Debug, Clone)]
pub struct OwnerSignature {
    /// The signer's ML-DSA-87 public key.
    pub public_key: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
    /// The FIPS 204 ML-DSA-87 signature.
    pub signature: [u8; ML_DSA_87_SIGNATURE_LEN],
}

/// A `t-of-n` multisig policy.
///
/// This is not threshold signing: `t` separate signatures are verified one by
/// one. The name says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigPolicy {
    owners: Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]>,
    threshold: usize,
}

impl MultisigPolicy {
    /// Builds the policy and refuses an unmeetable configuration at
    /// construction.
    ///
    /// Refusing here rather than at verification time matters: an account with
    /// `t > n` refuses every transaction and, from the outside, looks as though
    /// "the signatures are wrong". If the error is reported at construction,
    /// the locked-out account is never created.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::NoOwners`], [`ThresholdError::TooManyOwners`],
    /// [`ThresholdError::DuplicateOwner`], [`ThresholdError::ZeroThreshold`],
    /// [`ThresholdError::ThresholdAboveOwnerCount`].
    pub fn new(
        owners: Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]>,
        threshold: usize,
    ) -> Result<Self, ThresholdError> {
        if owners.is_empty() {
            return Err(ThresholdError::NoOwners);
        }
        if owners.len() > MAX_THRESHOLD_OWNERS {
            return Err(ThresholdError::TooManyOwners {
                count: owners.len(),
            });
        }
        let mut sorted = owners.clone();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        if sorted.len() != before {
            return Err(ThresholdError::DuplicateOwner);
        }
        if threshold == 0 {
            return Err(ThresholdError::ZeroThreshold);
        }
        if threshold > owners.len() {
            return Err(ThresholdError::ThresholdAboveOwnerCount {
                threshold,
                owners: owners.len(),
            });
        }
        Ok(Self { owners, threshold })
    }

    #[must_use]
    pub const fn threshold(&self) -> usize {
        self.threshold
    }

    #[must_use]
    pub fn owners(&self) -> &[[u8; ML_DSA_87_PUBLIC_KEY_LEN]] {
        &self.owners
    }

    /// Whether the signatures sent for `message` meet the threshold.
    ///
    /// Each signature is verified on its own; two signatures from the same
    /// owner count as one, or more precisely the second is refused. That is the
    /// cheapest way to bypass a threshold: a party holding one key would send
    /// `t` copies and meet `t-of-n` single-handedly.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::UnknownSigner`], [`ThresholdError::RepeatedSigner`],
    /// [`ThresholdError::InvalidSignature`], [`ThresholdError::ThresholdNotMet`].
    pub fn verify(
        &self,
        message: &[u8],
        signatures: &[OwnerSignature],
    ) -> Result<(), ThresholdError> {
        let mut seen: Vec<&[u8; ML_DSA_87_PUBLIC_KEY_LEN]> = Vec::with_capacity(signatures.len());
        for (index, entry) in signatures.iter().enumerate() {
            if !self.owners.contains(&entry.public_key) {
                return Err(ThresholdError::UnknownSigner { index });
            }
            if seen.contains(&&entry.public_key) {
                return Err(ThresholdError::RepeatedSigner { index });
            }
            verify_ml_dsa_87_signature(message, &entry.signature, &entry.public_key)
                .map_err(|_| ThresholdError::InvalidSignature { index })?;
            seen.push(&entry.public_key);
        }
        if seen.len() < self.threshold {
            return Err(ThresholdError::ThresholdNotMet {
                valid: seen.len(),
                threshold: self.threshold,
            });
        }
        Ok(())
    }
}

/// A message and the signatures that authorize it.
#[derive(Debug, Clone)]
pub struct MultisigAuthorization {
    pub signatures: Vec<OwnerSignature>,
}

impl MultisigAuthorization {
    /// # Errors
    ///
    /// Every error [`MultisigPolicy::verify`] returns.
    pub fn authorize(&self, policy: &MultisigPolicy, message: &[u8]) -> Result<(), ThresholdError> {
        policy.verify(message, &self.signatures)
    }
}

/// The KQ-* gate surface: the single entry point the production path calls.
pub struct ThresholdGates;

impl ThresholdGates {
    /// # Errors
    ///
    /// Every error [`MultisigPolicy::verify`] returns.
    pub fn kq_threshold_mldsa_sig(
        policy: &MultisigPolicy,
        message: &[u8],
        auth: &MultisigAuthorization,
    ) -> Result<(), ThresholdError> {
        auth.authorize(policy, message)
    }
}

#[cfg(all(test, feature = "wallet-ml-dsa"))]
mod tests {
    use super::*;
    use crate::crypto::primitives::WalletKeyPair;

    fn owner() -> (WalletKeyPair, [u8; ML_DSA_87_PUBLIC_KEY_LEN]) {
        let kp = WalletKeyPair::generate();
        let pk = kp.public_key_bytes();
        (kp, pk)
    }

    fn sign_with(kp: &WalletKeyPair, msg: &[u8]) -> OwnerSignature {
        OwnerSignature {
            public_key: kp.public_key_bytes(),
            signature: kp.sign(msg),
        }
    }

    #[test]
    fn two_of_three_accepts_two_real_signatures() {
        let (a, pa) = owner();
        let (b, pb) = owner();
        let (_c, pc) = owner();
        let policy = MultisigPolicy::new(vec![pa, pb, pc], 2).expect("valid policy");
        let msg = b"transfer 100";
        let auth = MultisigAuthorization {
            signatures: vec![sign_with(&a, msg), sign_with(&b, msg)],
        };
        assert_eq!(auth.authorize(&policy, msg), Ok(()));
    }

    #[test]
    fn one_signature_does_not_meet_a_threshold_of_two() {
        let (a, pa) = owner();
        let (_b, pb) = owner();
        let policy = MultisigPolicy::new(vec![pa, pb], 2).expect("valid policy");
        let msg = b"transfer 100";
        let auth = MultisigAuthorization {
            signatures: vec![sign_with(&a, msg)],
        };
        assert_eq!(
            auth.authorize(&policy, msg),
            Err(ThresholdError::ThresholdNotMet {
                valid: 1,
                threshold: 2
            })
        );
    }

    /// The cheapest way to bypass a threshold: the holder of a single key sends
    /// the same signature `t` times. If the count does not eliminate the
    /// repeated signer, `2-of-3` is met by one person.
    #[test]
    fn the_same_owner_signing_twice_does_not_meet_a_threshold_of_two() {
        let (a, pa) = owner();
        let (_b, pb) = owner();
        let (_c, pc) = owner();
        let policy = MultisigPolicy::new(vec![pa, pb, pc], 2).expect("valid policy");
        let msg = b"transfer 100";
        let auth = MultisigAuthorization {
            signatures: vec![sign_with(&a, msg), sign_with(&a, msg)],
        };
        assert_eq!(
            auth.authorize(&policy, msg),
            Err(ThresholdError::RepeatedSigner { index: 1 })
        );
    }

    #[test]
    fn a_signature_from_outside_the_owner_set_is_refused() {
        let (_a, pa) = owner();
        let (_b, pb) = owner();
        let (outsider, _po) = owner();
        let policy = MultisigPolicy::new(vec![pa, pb], 1).expect("valid policy");
        let msg = b"transfer 100";
        let auth = MultisigAuthorization {
            signatures: vec![sign_with(&outsider, msg)],
        };
        assert_eq!(
            auth.authorize(&policy, msg),
            Err(ThresholdError::UnknownSigner { index: 0 })
        );
    }

    /// A valid signature produced over another message does not authorize this
    /// one. The skeleton version could not see that: it only looked at the
    /// length.
    #[test]
    fn a_signature_over_another_message_is_refused() {
        let (a, pa) = owner();
        let policy = MultisigPolicy::new(vec![pa], 1).expect("valid policy");
        let auth = MultisigAuthorization {
            signatures: vec![sign_with(&a, b"transfer 1")],
        };
        assert_eq!(
            auth.authorize(&policy, b"transfer 1000"),
            Err(ThresholdError::InvalidSignature { index: 0 })
        );
    }

    /// Corrupting a single bit must invalidate the signature.
    #[test]
    fn a_tampered_signature_is_refused() {
        let (a, pa) = owner();
        let policy = MultisigPolicy::new(vec![pa], 1).expect("valid policy");
        let msg = b"transfer 100";
        let mut entry = sign_with(&a, msg);
        entry.signature[0] ^= 0x01;
        let auth = MultisigAuthorization {
            signatures: vec![entry],
        };
        assert_eq!(
            auth.authorize(&policy, msg),
            Err(ThresholdError::InvalidSignature { index: 0 })
        );
    }

    #[test]
    fn an_unmeetable_or_empty_policy_is_refused_at_construction() {
        let (_a, pa) = owner();
        assert_eq!(
            MultisigPolicy::new(vec![], 1),
            Err(ThresholdError::NoOwners)
        );
        assert_eq!(
            MultisigPolicy::new(vec![pa], 0),
            Err(ThresholdError::ZeroThreshold)
        );
        assert_eq!(
            MultisigPolicy::new(vec![pa], 2),
            Err(ThresholdError::ThresholdAboveOwnerCount {
                threshold: 2,
                owners: 1
            })
        );
        assert_eq!(
            MultisigPolicy::new(vec![pa, pa], 1),
            Err(ThresholdError::DuplicateOwner)
        );
        let many = vec![pa; MAX_THRESHOLD_OWNERS + 1];
        assert_eq!(
            MultisigPolicy::new(many, 1),
            Err(ThresholdError::TooManyOwners {
                count: MAX_THRESHOLD_OWNERS + 1
            })
        );
    }
}
