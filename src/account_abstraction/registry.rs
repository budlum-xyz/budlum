//! Quantum account registry: the state layer of account abstraction.
//!
//! # Why this module exists
//!
//! `QuantumAccount` and its `validate_all` guard had been written, were bound to real
//! ML-DSA-87 and passed their tests; but no production path called them,
//! because the account was **stored nowhere**. An account type is only a type
//! without a registry that holds it.
//!
//! The registry was written as a gate: an account gets in only if it passes
//! `validate_all`. That way rules such as "the multisig threshold must be within 1..=16"
//! or "pact_root must be zero while storage_root is zero" are really enforced once,
//! at registration time - every later reader is spared from checking them
//! again.
//!
//! # Boundary
//!
//! This layer validates the **shape** of the account. Spending a transaction with multisig
//! authority is a separate decision: the transaction schema carries a single signature today, and
//! multisig authorization needs a new signature version. That work belongs to the transaction
//! schema, not here.

use super::quantum_account::QuantumAccount;
use crate::storage::pact_binding::PactRegistry;
use std::collections::BTreeMap;

/// Registry errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuantumAccountRegistryError {
    /// The account did not pass the `validate_all` check.
    InvalidAccount { address: [u8; 32], reason: String },
    /// The same address was registered a second time.
    AlreadyRegistered { address: [u8; 32] },
    /// Bilinmeyen adres.
    NotRegistered { address: [u8; 32] },
    /// The address does not match the address derived from the account's public key.
    AddressDoesNotMatchKey {
        declared: [u8; 32],
        derived: [u8; 32],
    },
    /// The account's `pact_root` does not match the root of the presented pact set.
    PactRootDoesNotMatchRegistry {
        declared: [u8; 32],
        computed: [u8; 32],
    },
    /// The presented pact registry has a stale root: the root recomputed from the pacts inside it
    /// is not the root the registry carries.
    PactRegistryRootIsStale { reason: &'static str },
}

impl std::fmt::Display for QuantumAccountRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAccount { address, reason } => write!(
                f,
                "quantum account {} refused: {reason}",
                hex::encode(address)
            ),
            Self::AlreadyRegistered { address } => {
                write!(
                    f,
                    "quantum account {} already registered",
                    hex::encode(address)
                )
            }
            Self::NotRegistered { address } => {
                write!(
                    f,
                    "quantum account {} is not registered",
                    hex::encode(address)
                )
            }
            Self::AddressDoesNotMatchKey { declared, derived } => write!(
                f,
                "declared address {} does not match the address derived from the public key {}",
                hex::encode(declared),
                hex::encode(derived)
            ),
            Self::PactRootDoesNotMatchRegistry { declared, computed } => write!(
                f,
                "declared pact root {} does not match the presented pact set root {}",
                hex::encode(declared),
                hex::encode(computed)
            ),
            Self::PactRegistryRootIsStale { reason } => {
                write!(f, "presented pact registry is inconsistent: {reason}")
            }
        }
    }
}

impl std::error::Error for QuantumAccountRegistryError {}

/// The registry of quantum accounts.
#[derive(Debug, Clone, Default)]
pub struct QuantumAccountRegistry {
    accounts: BTreeMap<[u8; 32], QuantumAccount>,
}

impl QuantumAccountRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the account.
    ///
    /// The gate is here: an account that does not pass `validate_all` gets no entry, and
    /// the declared address must match the address derived from the public
    /// key. Without the latter an account could be registered under an address
    /// carrying someone else's key.
    ///
    /// # Errors
    ///
    /// Errors if the account is invalid, the address does not match the key, or the address is
    /// already registered.
    pub fn register(&mut self, account: QuantumAccount) -> Result<(), QuantumAccountRegistryError> {
        let derived = QuantumAccount::address_from_public_key(&account.pq_public_key);
        if derived != account.address {
            return Err(QuantumAccountRegistryError::AddressDoesNotMatchKey {
                declared: account.address,
                derived,
            });
        }
        if let Err(reason) = account.validate_all() {
            return Err(QuantumAccountRegistryError::InvalidAccount {
                address: account.address,
                reason: reason.to_string(),
            });
        }
        if self.accounts.contains_key(&account.address) {
            return Err(QuantumAccountRegistryError::AlreadyRegistered {
                address: account.address,
            });
        }
        self.accounts.insert(account.address, account);
        Ok(())
    }

    /// Register the account together with the pact set its `pact_root` names.
    ///
    /// `register` validates the **shape** of an account and accepts `pact_root` as
    /// given. That was not enough: the field carried a root, but nothing checked
    /// that the root named a real pact set, so `pact_root` was a claim,
    /// not a binding. The same class existed in `ProofFixture::bind_verified`: a field
    /// being non-zero does not mean there is something
    /// behind it.
    /// gelmez.
    ///
    /// There are two gates. The presented registry's own root must be recomputable from the
    /// pacts inside it, **and** the account's `pact_root` must equal that
    /// root.
    ///
    /// # Errors
    ///
    /// Every error [`register`](Self::register) returns, plus an error if the pact registry's
    /// root is stale or the account's root does not match
    /// it.
    pub fn register_with_pacts(
        &mut self,
        account: QuantumAccount,
        pacts: &PactRegistry,
    ) -> Result<(), QuantumAccountRegistryError> {
        pacts
            .verify_root()
            .map_err(|reason| QuantumAccountRegistryError::PactRegistryRootIsStale { reason })?;
        if account.pact_root != pacts.root {
            return Err(QuantumAccountRegistryError::PactRootDoesNotMatchRegistry {
                declared: account.pact_root,
                computed: pacts.root,
            });
        }
        self.register(account)
    }

    #[must_use]
    pub fn get(&self, address: &[u8; 32]) -> Option<&QuantumAccount> {
        self.accounts.get(address)
    }

    #[must_use]
    pub fn is_registered(&self, address: &[u8; 32]) -> bool {
        self.accounts.contains_key(address)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Mutate a registered account.
    ///
    /// After the change the account goes through `validate_all` again; if it fails
    /// the change is not applied and the record stays as it was. The validity of a record
    /// must not be left to every writing path being careful on its
    /// own.
    ///
    /// # Errors
    ///
    /// Errors if the address is not registered or the change makes the account
    /// invalid.
    pub fn update<F>(
        &mut self,
        address: &[u8; 32],
        change: F,
    ) -> Result<(), QuantumAccountRegistryError>
    where
        F: FnOnce(&mut QuantumAccount),
    {
        let current = self
            .accounts
            .get(address)
            .ok_or(QuantumAccountRegistryError::NotRegistered { address: *address })?;
        let mut candidate = current.clone();
        change(&mut candidate);
        if let Err(reason) = candidate.validate_all() {
            return Err(QuantumAccountRegistryError::InvalidAccount {
                address: *address,
                reason: reason.to_string(),
            });
        }
        self.accounts.insert(*address, candidate);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::ML_DSA_87_PUBLIC_KEY_LEN;

    fn account_with(threshold: usize, guardians: usize) -> QuantumAccount {
        let pk = [3u8; ML_DSA_87_PUBLIC_KEY_LEN];
        let guardian_keys: Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]> = (0..guardians)
            .map(|i| {
                let mut g = [0u8; ML_DSA_87_PUBLIC_KEY_LEN];
                g[0] = u8::try_from(i + 1).unwrap_or(u8::MAX);
                g
            })
            .collect();
        QuantumAccount {
            address: QuantumAccount::address_from_public_key(&pk),
            pq_public_key: pk,
            storage_root: [0u8; 32],
            pact_root: [0u8; 32],
            guardian_root: QuantumAccount::guardian_root(&guardian_keys),
            guardians: guardian_keys,
            multisig_threshold: threshold,
            recovery_threshold: threshold,
            timelock_blocks: 10,
            nonce: 0,
            balance: 0,
            storage_bytes: 0,
        }
    }

    /// A valid account must be registrable.
    #[test]
    fn a_valid_account_registers() {
        let mut registry = QuantumAccountRegistry::new();
        let account = account_with(2, 3);
        let address = account.address;
        registry.register(account).expect("valid account");
        assert!(registry.is_registered(&address));
        assert_eq!(registry.len(), 1);
    }

    /// `validate_all` is now really a gate: an account whose threshold exceeds the guardian
    /// count cannot get in. This guard had been written but no production path
    /// called it.
    #[test]
    fn an_account_whose_threshold_exceeds_its_guardians_is_refused() {
        let mut registry = QuantumAccountRegistry::new();
        let err = registry
            .register(account_with(5, 3))
            .expect_err("esik gardiyan sayisini asamaz");
        assert!(matches!(
            err,
            QuantumAccountRegistryError::InvalidAccount { .. }
        ));
        assert!(
            registry.is_empty(),
            "a refused account must not enter the registry"
        );
    }

    /// The address must be derived from the account's own key.
    #[test]
    fn an_address_that_does_not_match_the_key_is_refused() {
        let mut registry = QuantumAccountRegistry::new();
        let mut account = account_with(2, 3);
        account.address = [7u8; 32];
        assert!(matches!(
            registry
                .register(account)
                .expect_err("adres anahtarla eslesmeli"),
            QuantumAccountRegistryError::AddressDoesNotMatchKey { .. }
        ));
    }

    /// The same account cannot be registered twice.
    #[test]
    fn registering_the_same_account_twice_is_refused() {
        let mut registry = QuantumAccountRegistry::new();
        registry
            .register(account_with(2, 3))
            .expect("first registration");
        assert!(matches!(
            registry
                .register(account_with(2, 3))
                .expect_err("the second registration must be refused"),
            QuantumAccountRegistryError::AlreadyRegistered { .. }
        ));
        assert_eq!(registry.len(), 1);
    }

    /// A change that invalidates must not be applied and must not corrupt the record.
    #[test]
    fn an_update_that_invalidates_the_account_is_refused_and_changes_nothing() {
        let mut registry = QuantumAccountRegistry::new();
        let account = account_with(2, 3);
        let address = account.address;
        registry.register(account).expect("valid account");

        let err = registry
            .update(&address, |a| a.multisig_threshold = 99)
            .expect_err("an invalidating change must be refused");
        assert!(matches!(
            err,
            QuantumAccountRegistryError::InvalidAccount { .. }
        ));
        assert_eq!(
            registry.get(&address).map(|a| a.multisig_threshold),
            Some(2),
            "a refused change must not corrupt the record"
        );
    }

    /// An account carrying a real pact set must be registrable.
    #[test]
    fn an_account_bound_to_its_pact_set_registers() {
        use crate::storage::pact_binding::Pact;
        use sha3::{Digest, Sha3_256};

        let payload = b"tarif";
        let mut h = Sha3_256::new();
        h.update(payload);
        let commitment: [u8; 32] = h.finalize().into();

        let mut pacts = PactRegistry::new();
        pacts.add_pact(
            Pact::new(
                [1u8; 32], [0u8; 32], [0u8; 32], commitment, [0u8; 32], 10, 0,
            )
            .expect("valid pact"),
        );

        let mut account = account_with(2, 3);
        account.storage_root = [9u8; 32];
        account.pact_root = pacts.root;
        let address = account.address;

        let mut registry = QuantumAccountRegistry::new();
        registry
            .register_with_pacts(account, &pacts)
            .expect("kok eslesiyor");
        assert!(registry.is_registered(&address));
    }

    /// A fabricated `pact_root` must be refused: a non-zero field does not mean
    /// there is a pact set behind it.
    #[test]
    fn a_pact_root_naming_no_pact_set_is_refused() {
        let mut account = account_with(2, 3);
        account.storage_root = [9u8; 32];
        account.pact_root = [7u8; 32];

        let mut registry = QuantumAccountRegistry::new();
        let err = registry
            .register_with_pacts(account, &PactRegistry::new())
            .expect_err("a fabricated root must be refused");
        assert!(matches!(
            err,
            QuantumAccountRegistryError::PactRootDoesNotMatchRegistry { .. }
        ));
        assert!(
            registry.is_empty(),
            "a refused account must not enter the registry"
        );
    }

    /// A pact registry with a stale root must not be accepted.
    #[test]
    fn a_pact_registry_with_a_stale_root_is_refused() {
        use crate::storage::pact_binding::Pact;

        let mut pacts = PactRegistry::new();
        pacts.add_pact(
            Pact::new([1u8; 32], [0u8; 32], [0u8; 32], [2u8; 32], [0u8; 32], 10, 0)
                .expect("valid pact"),
        );
        // The root is corrupted by hand: it cannot be recomputed from the pacts inside.
        // Zero is not used - zero is the valid root of the empty set.
        pacts.root = [0xAA; 32];

        let mut account = account_with(2, 3);
        account.storage_root = [9u8; 32];
        account.pact_root = [0xAA; 32];

        let mut registry = QuantumAccountRegistry::new();
        assert!(matches!(
            registry
                .register_with_pacts(account, &pacts)
                .expect_err("a stale root must be refused"),
            QuantumAccountRegistryError::PactRegistryRootIsStale { .. }
        ));
    }

    /// An unknown address cannot be updated.
    #[test]
    fn updating_an_unknown_address_is_refused() {
        let mut registry = QuantumAccountRegistry::new();
        assert!(matches!(
            registry
                .update(&[1u8; 32], |a| a.nonce += 1)
                .expect_err("bilinmeyen adres"),
            QuantumAccountRegistryError::NotRegistered { .. }
        ));
    }
}
