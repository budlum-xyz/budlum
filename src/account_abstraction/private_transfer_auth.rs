//! Private transfer authorization: nullifier, commitment, and signature.
//!
//! # What this module used to be
//!
//! All three verifications came out empty:
//!
//! * `verify_auth_sig` only checked `self.authorization_sig.len() != 4627`.
//!   Since the field is `[u8; 4627]`, that condition was always false at
//!   compile time and the function could return nothing but `Ok(())`. The
//!   signature was never verified and was bound to no key at all.
//! * `verify_commitment` only computed `SHA3-256(payload)`. Because the
//!   commitment covered neither the amount, nor the nullifier, nor the account,
//!   a different transfer carrying the same payload produced the same
//!   commitment.
//! * `verify_nullifier` was correct, but meant nothing on its own while
//!   `verify_auth_sig` was empty: who authorized the spend was unknown.
//!
//! The directory was never reached from `lib.rs`, so these three gaps did not
//! even compile.
//!
//! # What it does now
//!
//! The authorization is a real ML-DSA-87 signature over a commitment that
//! includes the amount and the nullifier. The nullifier is checked against the
//! spent set.
//!
//! # What it does not say
//!
//! This is not a zero-knowledge circuit. The module does not *prove* that the
//! nullifier belongs to the output actually being spent, because what proves
//! that is the proof system. What the module says is: "this nullifier has not
//! been seen before, and this exact authorization was signed by this key". No
//! privacy claim is made here; what is made is the separation between double
//! spending and unauthorized spending.
//!
//! WIRING: unwired - measured, and the old justification for the mark was
//! wrong. A private transfer path **does** exist in production:
//! `TransactionType::PrivateTransferSubmit` -> `Executor`
//! (`src/execution/executor.rs`). That path does not call this module; it
//! writes the same work a second time. This module is currently reachable only
//! from tests.
//!
//! # The two implementations are not the same thing
//!
//! The difference was measured, not guessed. The preimage production signs
//! (`compute_public_digest`) covers nullifiers and output commitments; it does
//! **not** cover the amount, because in a private transfer the amount is not
//! carried in the clear. This module's preimage (`authorization_payload`) binds
//! the amount too, because here the amount is assumed known.
//!
//! The two produce two different answers to the same question, so neither can
//! be substituted for the other: a signature produced by one does not verify
//! under the other. Merging them requires deciding which model is right, that
//! is, whether the amount is in the clear on chain. Because that is a consensus
//! surface decision it belongs in its own commit; merging two implementations
//! because they "look alike" would quietly create a third signature scheme.
//!
//! For the record, this is the same class as the Debt K pattern in `PLAN.md`:
//! the same work written twice in two places is **measured** first, then
//! reduced to one source.

use crate::crypto::primitives::{
    verify_ml_dsa_87_signature, ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN,
};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;

/// Domain separator for the commitment.
pub const PRIVATE_TRANSFER_COMMITMENT_DOMAIN: &[u8] = b"BUDLUM_PRIVATE_TRANSFER_COMMITMENT_V1";
/// Domain separator for the authorization signature.
pub const PRIVATE_TRANSFER_AUTH_DOMAIN: &[u8] = b"BUDLUM_PRIVATE_TRANSFER_AUTH_V1";

/// Why a private transfer was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateTransferError {
    /// The nullifier was already spent: a double spend.
    NullifierAlreadySpent,
    /// The commitment does not match the declared fields.
    CommitmentMismatch,
    /// The amount is zero.
    ZeroAmount,
    /// The ML-DSA-87 authorization signature did not verify.
    InvalidAuthorization,
}

impl core::fmt::Display for PrivateTransferError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NullifierAlreadySpent => {
                write!(f, "KQ-WALLET-PRIVATE: nullifier was already spent")
            }
            Self::CommitmentMismatch => write!(
                f,
                "KQ-WALLET-PRIVATE: commitment does not match the declared transfer"
            ),
            Self::ZeroAmount => write!(f, "KQ-WALLET-PRIVATE: amount is zero"),
            Self::InvalidAuthorization => {
                write!(
                    f,
                    "KQ-WALLET-PRIVATE: authorization signature does not verify"
                )
            }
        }
    }
}

impl std::error::Error for PrivateTransferError {}

/// The transfer's commitment: nullifier, amount and blinding together.
///
/// Without the blinding the commitment would be guessable: if the amount comes
/// from a narrow set (1, 10, 100, and so on) an attacker could compute every
/// possible commitment and read the amount back out.
#[must_use]
pub fn transfer_commitment(nullifier: &[u8; 32], amount: u64, blinding: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(PRIVATE_TRANSFER_COMMITMENT_DOMAIN);
    h.update(nullifier);
    h.update(amount.to_be_bytes());
    h.update(blinding);
    h.finalize().into()
}

/// The bytes the authorization signature is taken over.
#[must_use]
pub fn authorization_payload(commitment: &[u8; 32], nullifier: &[u8; 32], amount: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(PRIVATE_TRANSFER_AUTH_DOMAIN.len() + 72);
    out.extend_from_slice(PRIVATE_TRANSFER_AUTH_DOMAIN);
    out.extend_from_slice(commitment);
    out.extend_from_slice(nullifier);
    out.extend_from_slice(&amount.to_be_bytes());
    out
}

/// The authorization for one private transfer.
#[derive(Debug, Clone)]
pub struct PrivateTransferAuth {
    pub authorization_sig: [u8; ML_DSA_87_SIGNATURE_LEN],
    pub spender_key: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
    pub nullifier: [u8; 32],
    pub commitment: [u8; 32],
    pub amount: u64,
}

impl PrivateTransferAuth {
    /// Is the nullifier in the spent set?
    ///
    /// # Errors
    ///
    /// [`PrivateTransferError::NullifierAlreadySpent`].
    pub fn verify_nullifier(&self, spent: &BTreeSet<[u8; 32]>) -> Result<(), PrivateTransferError> {
        if spent.contains(&self.nullifier) {
            return Err(PrivateTransferError::NullifierAlreadySpent);
        }
        Ok(())
    }

    /// Does the commitment still hold when recomputed from the declared
    /// nullifier and amount?
    ///
    /// # Errors
    ///
    /// [`PrivateTransferError::ZeroAmount`], [`PrivateTransferError::CommitmentMismatch`].
    pub fn verify_commitment(&self, blinding: &[u8; 32]) -> Result<(), PrivateTransferError> {
        if self.amount == 0 {
            return Err(PrivateTransferError::ZeroAmount);
        }
        if transfer_commitment(&self.nullifier, self.amount, blinding) != self.commitment {
            return Err(PrivateTransferError::CommitmentMismatch);
        }
        Ok(())
    }

    /// Is the authorization signature valid?
    ///
    /// # Errors
    ///
    /// [`PrivateTransferError::InvalidAuthorization`].
    pub fn verify_auth_sig(&self) -> Result<(), PrivateTransferError> {
        let payload = authorization_payload(&self.commitment, &self.nullifier, self.amount);
        verify_ml_dsa_87_signature(&payload, &self.authorization_sig, &self.spender_key)
            .map_err(|_| PrivateTransferError::InvalidAuthorization)
    }
}

/// The KQ-* gate surface: the single entry point a production path should call.
pub struct PrivateTransferGates;

impl PrivateTransferGates {
    /// Runs the three checks in order: signature, commitment, double spend.
    ///
    /// # Errors
    ///
    /// Every error the three verifiers of [`PrivateTransferAuth`] return.
    pub fn kq_private(
        auth: &PrivateTransferAuth,
        spent: &BTreeSet<[u8; 32]>,
        blinding: &[u8; 32],
    ) -> Result<(), PrivateTransferError> {
        auth.verify_auth_sig()?;
        auth.verify_commitment(blinding)?;
        auth.verify_nullifier(spent)?;
        Ok(())
    }
}

#[cfg(all(test, feature = "wallet-ml-dsa"))]
mod tests {
    use super::*;
    use crate::crypto::primitives::WalletKeyPair;

    fn authorized(
        kp: &WalletKeyPair,
        nullifier: [u8; 32],
        amount: u64,
        blinding: &[u8; 32],
    ) -> PrivateTransferAuth {
        let commitment = transfer_commitment(&nullifier, amount, blinding);
        let payload = authorization_payload(&commitment, &nullifier, amount);
        PrivateTransferAuth {
            authorization_sig: kp.sign(&payload),
            spender_key: kp.public_key_bytes(),
            nullifier,
            commitment,
            amount,
        }
    }

    #[test]
    fn a_correctly_authorized_transfer_is_accepted() {
        let kp = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let auth = authorized(&kp, [1u8; 32], 100, &blinding);
        assert_eq!(
            PrivateTransferGates::kq_private(&auth, &BTreeSet::new(), &blinding),
            Ok(())
        );
    }

    #[test]
    fn a_spent_nullifier_is_refused() {
        let kp = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let auth = authorized(&kp, [1u8; 32], 100, &blinding);
        let mut spent = BTreeSet::new();
        spent.insert([1u8; 32]);
        assert_eq!(
            PrivateTransferGates::kq_private(&auth, &spent, &blinding),
            Err(PrivateTransferError::NullifierAlreadySpent)
        );
    }

    /// What the scaffold missed: the signature was bound to no key, so random
    /// bytes were accepted just as readily.
    #[test]
    fn arbitrary_bytes_in_place_of_a_signature_are_refused() {
        let kp = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let mut auth = authorized(&kp, [1u8; 32], 100, &blinding);
        auth.authorization_sig = [1u8; ML_DSA_87_SIGNATURE_LEN];
        assert_eq!(
            auth.verify_auth_sig(),
            Err(PrivateTransferError::InvalidAuthorization)
        );
    }

    /// The authorization covers the amount, so changing the amount breaks the
    /// signature. Had the commitment left the amount out, an authorization
    /// taken for 1 would have spent 1000.
    #[test]
    fn raising_the_amount_after_signing_is_refused() {
        let kp = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let mut auth = authorized(&kp, [1u8; 32], 1, &blinding);
        auth.amount = 1000;
        assert_eq!(
            auth.verify_auth_sig(),
            Err(PrivateTransferError::InvalidAuthorization)
        );
        assert_eq!(
            auth.verify_commitment(&blinding),
            Err(PrivateTransferError::CommitmentMismatch)
        );
    }

    /// An authorization taken for one nullifier cannot be moved to another.
    #[test]
    fn an_authorization_cannot_be_replayed_on_another_nullifier() {
        let kp = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let mut auth = authorized(&kp, [1u8; 32], 100, &blinding);
        auth.nullifier = [2u8; 32];
        assert_eq!(
            auth.verify_auth_sig(),
            Err(PrivateTransferError::InvalidAuthorization)
        );
    }

    /// No other party can authorize the same transfer with their own key.
    #[test]
    fn an_authorization_from_another_key_is_refused() {
        let owner = WalletKeyPair::generate();
        let attacker = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let mut auth = authorized(&owner, [1u8; 32], 100, &blinding);
        auth.spender_key = attacker.public_key_bytes();
        assert_eq!(
            auth.verify_auth_sig(),
            Err(PrivateTransferError::InvalidAuthorization)
        );
    }

    #[test]
    fn a_zero_amount_is_refused() {
        let kp = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let auth = authorized(&kp, [1u8; 32], 0, &blinding);
        assert_eq!(
            auth.verify_commitment(&blinding),
            Err(PrivateTransferError::ZeroAmount)
        );
    }

    /// Without a blinding the commitment would be guessable; a different
    /// blinding must produce a different commitment.
    #[test]
    fn the_blinding_factor_changes_the_commitment() {
        let a = transfer_commitment(&[1u8; 32], 100, &[1u8; 32]);
        let b = transfer_commitment(&[1u8; 32], 100, &[2u8; 32]);
        assert_ne!(a, b);
    }
}
