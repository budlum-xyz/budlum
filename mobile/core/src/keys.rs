//! The operator key of the mobile validator (section 7.9.6, WP-11 job 9).
//!
//! The operator key is ML-DSA-65 and signs duty transactions. It is generated
//! on the device from 32 bytes the host draws from the platform's secure
//! random generator, and it is derived and used through the node's own
//! signature code ([`crate::crypto::pq`]), so the phone signs exactly what
//! the node verifies. The owner key (ML-DSA-87, 24 words) stays in the
//! wallet; this module never sees it.
//!
//! The seed is never kept in the clear outside memory. The host's
//! [`KeyVault`] seals it under a platform key (an Android Keystore
//! AES-256-GCM key, in StrongBox when the device has one; the iOS keychain)
//! and the core keeps only the [`SealedOperatorKey`]. The vault
//! authenticates a context that names the public key, and opening checks
//! the derived public key against it: a vault that hands back another key's
//! seed is refused.
//!
//! Section 7.9.6 item 3: the key signs in the background, so the platform
//! key must not require user authentication or an unlocked device. Whoever
//! holds the device can then sign duties; the stake stays behind the owner
//! key.

use std::fmt;

use zeroize::Zeroizing;

use crate::crypto::pq::{self, ML_DSA_SEED_LEN};
use crate::crypto::scheme::SchemeId;
use crate::error::CoreError;

/// The secret seed of the operator key (FIPS 204 `xi`).
pub const OPERATOR_SEED_LEN: usize = ML_DSA_SEED_LEN;

/// The scheme of the operator key (section 7.2, `operator_key`).
pub const OPERATOR_KEY_SCHEME: SchemeId = SchemeId::ML_DSA_65;

/// The label the vault authenticates together with the public key. It is
/// associated data for the platform cipher, not a hash input.
pub const OPERATOR_KEY_LABEL: &[u8] = b"budlum/operator-key/ml-dsa-65/v1";

/// A refusal from the platform key store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultError {
    /// The platform's reason, for the log.
    pub reason: String,
}

/// The platform key store, implemented by the host.
pub trait KeyVault {
    /// Encrypt `secret` under the platform key and authenticate `context`.
    ///
    /// # Errors
    ///
    /// [`VaultError`] when the platform refuses.
    fn seal(&self, secret: &[u8], context: &[u8]) -> Result<Vec<u8>, VaultError>;

    /// Decrypt what [`Self::seal`] returned for the same `context`.
    ///
    /// # Errors
    ///
    /// [`VaultError`] when the platform refuses or the context differs.
    fn open(&self, sealed: &[u8], context: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError>;
}

/// What the core stores for the operator key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedOperatorKey {
    /// The ML-DSA-65 public key, as registered on chain.
    pub public_key: Vec<u8>,
    /// The seed, as the vault sealed it.
    pub sealed_seed: Vec<u8>,
}

/// The operator key in memory. The seed is wiped when the key is dropped.
pub struct OperatorKey {
    seed: Zeroizing<[u8; OPERATOR_SEED_LEN]>,
    public_key: Vec<u8>,
}

impl fmt::Debug for OperatorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperatorKey")
            .field("public_key_len", &self.public_key.len())
            .finish_non_exhaustive()
    }
}

fn key_error(code: &'static str, error: &dyn fmt::Display) -> CoreError {
    CoreError::new(code, error.to_string())
}

fn vault_context(public_key: &[u8]) -> Vec<u8> {
    let mut context = Vec::with_capacity(OPERATOR_KEY_LABEL.len() + public_key.len());
    context.extend_from_slice(OPERATOR_KEY_LABEL);
    context.extend_from_slice(public_key);
    context
}

impl OperatorKey {
    /// Generate the key from 32 bytes of fresh platform entropy.
    ///
    /// # Errors
    ///
    /// [`CoreError`] `mobile_operator_key` when the signature code refuses.
    pub fn from_entropy(entropy: [u8; OPERATOR_SEED_LEN]) -> Result<Self, CoreError> {
        Self::from_seed(Zeroizing::new(entropy))
    }

    fn from_seed(seed: Zeroizing<[u8; OPERATOR_SEED_LEN]>) -> Result<Self, CoreError> {
        let public_key = pq::ml_dsa_public_key(OPERATOR_KEY_SCHEME, &seed)
            .map_err(|e| key_error("mobile_operator_key", &e))?;
        Ok(Self { seed, public_key })
    }

    /// The public key, as `RegisterValidator` and `RotateOperatorKey` carry it.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign `message` under the FIPS 204 context `ctx`. `rnd` hedges the
    /// signature; all zero is the deterministic variant.
    ///
    /// # Errors
    ///
    /// [`CoreError`] `mobile_operator_sign` for an empty or too long context.
    pub fn sign(&self, ctx: &[u8], message: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>, CoreError> {
        pq::ml_dsa_sign(OPERATOR_KEY_SCHEME, &self.seed, message, ctx, rnd)
            .map_err(|e| key_error("mobile_operator_sign", &e))
    }

    /// Seal the seed with the platform vault.
    ///
    /// # Errors
    ///
    /// [`CoreError`] `mobile_key_vault` when the vault refuses.
    pub fn seal(&self, vault: &dyn KeyVault) -> Result<SealedOperatorKey, CoreError> {
        let context = vault_context(&self.public_key);
        let sealed_seed = vault
            .seal(self.seed.as_slice(), &context)
            .map_err(|e| CoreError::new("mobile_key_vault", e.reason))?;
        Ok(SealedOperatorKey {
            public_key: self.public_key.clone(),
            sealed_seed,
        })
    }

    /// Open a sealed key and check it is the key it claims to be.
    ///
    /// # Errors
    ///
    /// [`CoreError`] `mobile_key_vault` when the vault refuses,
    /// `mobile_operator_key_sealed` when it returns a seed of the wrong
    /// length, and `mobile_operator_key_mismatch` when the seed derives
    /// another public key.
    pub fn open(vault: &dyn KeyVault, sealed: &SealedOperatorKey) -> Result<Self, CoreError> {
        let context = vault_context(&sealed.public_key);
        let secret = vault
            .open(&sealed.sealed_seed, &context)
            .map_err(|e| CoreError::new("mobile_key_vault", e.reason))?;
        if secret.len() != OPERATOR_SEED_LEN {
            return Err(CoreError::new(
                "mobile_operator_key_sealed",
                "the vault returned a seed of the wrong length",
            ));
        }
        let mut seed = Zeroizing::new([0u8; OPERATOR_SEED_LEN]);
        seed.copy_from_slice(&secret);
        let key = Self::from_seed(seed)?;
        if key.public_key != sealed.public_key {
            return Err(CoreError::new(
                "mobile_operator_key_mismatch",
                "the vault returned the seed of another key",
            ));
        }
        Ok(key)
    }
}
