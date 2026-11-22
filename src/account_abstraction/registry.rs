//! Quantum account registry: the state layer of account abstraction.
//!
//! # Why this module exists
//!
//! `QuantumAccount` and its `validate_all` guard had been written, were bound to real
//! ML-DSA-87 and passed their tests; but no registry API held them. An account
//! type is only a type without a registry that holds it.
//!
//! The registry was written as a gate: an account gets in only if it passes
//! `validate_all`. That way rules such as "the multisig threshold must be within 1..=16"
//! or "`pact_root` must be zero while `storage_root` is zero" are really enforced once,
//! at registration time - every later reader is spared from checking them
//! again.
//!
//! # Boundary
//!
//! This layer validates the **shape** of the account. Spending a transaction with multisig
//! authority is a separate decision: the transaction schema carries a single signature today, and
//! multisig authorization needs a new signature version. That work belongs to the transaction
//! schema, not here. This registry is not part of `AccountState` and no block transaction writes
//! it yet; callers must not describe its root as chain-committed state.

use super::quantum_account::QuantumAccount;
use crate::{core::hash::hash_fields_bytes, storage::pact_binding::PactRegistry};
use std::collections::BTreeMap;

const ACCOUNT_COMMITMENT_DOMAIN_V1: &[u8] = b"budlum/quantum-account/v1";
const REGISTRY_ROOT_DOMAIN_V1: &[u8] = b"budlum/quantum-account-registry/v1";

/// Registry errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuantumAccountRegistryError {
    /// The account did not pass the `validate_all` check.
    InvalidAccount { address: [u8; 32], reason: String },
    /// The same address was registered a second time.
    AlreadyRegistered { address: [u8; 32] },
    /// The address is not in the registry.
    NotRegistered { address: [u8; 32] },
    /// The address does not match the address derived from the account's public key.
    AddressDoesNotMatchKey {
        declared: [u8; 32],
        derived: [u8; 32],
    },
    /// An update tried to change a field that is bound at registration: the
    /// address, the public key, or the pact root.
    BoundFieldChanged {
        address: [u8; 32],
        field: &'static str,
    },
    /// The account's `pact_root` does not match the root of the presented pact set.
    PactRootDoesNotMatchRegistry {
        declared: [u8; 32],
        computed: [u8; 32],
    },
    /// The presented pact registry has a stale root: the root recomputed from the pacts inside it
    /// is not the root the registry carries.
    PactRegistryRootIsStale { reason: &'static str },
    /// A non-zero pact root was submitted without the pact set that proves it.
    PactRegistryRequired { declared: [u8; 32] },
    /// A change named a registry root that is not the current one: it was
    /// computed against an older state and replaying it would move the
    /// registry backwards.
    RootMismatch {
        expected: [u8; 32],
        current: [u8; 32],
    },
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
            Self::BoundFieldChanged { address, field } => write!(
                f,
                "quantum account {} update changes its {field}, which is bound at registration",
                hex::encode(address)
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
            Self::PactRegistryRequired { declared } => write!(
                f,
                "non-zero pact root {} requires its pact registry",
                hex::encode(declared)
            ),
            Self::RootMismatch { expected, current } => write!(
                f,
                "quantum account registry: change was computed against root {} but the registry root is {}",
                hex::encode(expected),
                hex::encode(current)
            ),
        }
    }
}

impl std::error::Error for QuantumAccountRegistryError {}

/// Convenience: upper bound on live quantum accounts in [`QuantumAccountRegistry`].
pub const MAX_QUANTUM_ACCOUNTS: usize = 100_000;

fn canonical_usize(value: usize) -> [u8; 8] {
    match u64::try_from(value) {
        Ok(value) => value.to_le_bytes(),
        Err(_) => u64::MAX.to_le_bytes(),
    }
}

fn account_commitment(account: &QuantumAccount) -> [u8; 32] {
    let guardian_count = canonical_usize(account.guardians.len());
    let mut guardians = Vec::new();
    guardians.extend_from_slice(&guardian_count);
    for guardian in &account.guardians {
        guardians.extend_from_slice(guardian);
    }

    let multisig_threshold = canonical_usize(account.multisig_threshold);
    let recovery_threshold = canonical_usize(account.recovery_threshold);
    let timelock_blocks = account.timelock_blocks.to_le_bytes();
    let nonce = account.nonce.to_le_bytes();
    let balance = account.balance.to_le_bytes();
    let storage_bytes = account.storage_bytes.to_le_bytes();

    hash_fields_bytes(&[
        ACCOUNT_COMMITMENT_DOMAIN_V1,
        &account.address,
        &account.pq_public_key,
        &account.storage_root,
        &account.pact_root,
        &account.guardian_root,
        &guardians,
        &multisig_threshold,
        &recovery_threshold,
        &timelock_blocks,
        &nonce,
        &balance,
        &storage_bytes,
    ])
}

/// The registry of quantum accounts.
///
/// The registry is state, not an operator convenience: it is folded into the
/// block state root (only while nonempty, on the identity pattern) and it is
/// carried and digested by the snapshot. Its `root()` commits to every account
/// field in ascending address order plus the epoch, so two nodes that reach
/// the same accounts agree on one root whatever order the registrations
/// arrived in.
///
/// Replay protection lives in the two `*_at_root` entry points: a change names
/// the root it was computed against, and it is applied only when that root is
/// the registry's current root. A replayed copy from an older state therefore
/// fails on the root and never runs its change - the same counter-measurement
/// an ordered chain gets from a sequence number that cannot go backwards.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct QuantumAccountRegistry {
    // A JSON object keys by string, so the map goes through the shared key
    // codec rather than handing serde a byte array it cannot write.
    #[serde(default, with = "crate::core::map_keys")]
    accounts: BTreeMap<[u8; 32], QuantumAccount>,
    /// The chain epoch this registry state belongs to. Persisted and folded
    /// into `root()`: an older copy applied at a later epoch must not read the
    /// same as the current one.
    #[serde(default)]
    pub epoch: u64,
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
    /// Errors if the account has a non-zero pact root without its pact registry,
    /// is invalid, has an address that does not match the key, or is already registered.
    pub fn register(&mut self, account: QuantumAccount) -> Result<(), QuantumAccountRegistryError> {
        if account.pact_root != [0u8; 32] {
            return Err(QuantumAccountRegistryError::PactRegistryRequired {
                declared: account.pact_root,
            });
        }
        if let Err(reason) = account.validate_all() {
            return Err(QuantumAccountRegistryError::InvalidAccount {
                address: account.address,
                reason: reason.to_string(),
            });
        }
        self.insert_validated_account(account)
    }

    fn insert_validated_account(
        &mut self,
        account: QuantumAccount,
    ) -> Result<(), QuantumAccountRegistryError> {
        let derived = QuantumAccount::address_from_public_key(&account.pq_public_key);
        if derived != account.address {
            return Err(QuantumAccountRegistryError::AddressDoesNotMatchKey {
                declared: account.address,
                derived,
            });
        }
        if self.accounts.contains_key(&account.address) {
            return Err(QuantumAccountRegistryError::AlreadyRegistered {
                address: account.address,
            });
        }
        if self.accounts.len() >= MAX_QUANTUM_ACCOUNTS {
            return Err(QuantumAccountRegistryError::InvalidAccount {
                address: account.address,
                reason: format!("quantum account registry full ({MAX_QUANTUM_ACCOUNTS})"),
            });
        }
        self.accounts.insert(account.address, account);
        Ok(())
    }

    /// Register the account together with the pact set its `pact_root` names.
    ///
    /// Plain [`register`](Self::register) accepts only the zero pact root. A
    /// non-zero root comes through this method so the field cannot name a pact
    /// set that the caller never presented. A field being non-zero does not by
    /// itself prove there is something behind it.
    ///
    /// There are two gates. The presented registry's own root must be recomputable from the
    /// pacts inside it, **and** the account's `pact_root` must equal that
    /// root.
    ///
    /// # Errors
    ///
    /// Errors if the account cannot be inserted, the pact registry's root is
    /// stale, or the account's root does not match it.
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
        if let Err(reason) = account.validate_all() {
            return Err(QuantumAccountRegistryError::InvalidAccount {
                address: account.address,
                reason: reason.to_string(),
            });
        }
        self.insert_validated_account(account)
    }

    /// Set the epoch this registry state belongs to. Genesis, the executor
    /// and the snapshot restore are the callers; the epoch is folded into
    /// [`Self::root`], so a state restored under another epoch does not read
    /// the same as the current one.
    /// WIRING: `AccountState::stamp_quantum_account_epoch` is the caller.
    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }

    /// Register an account, refusing a change computed against an older root.
    ///
    /// This is the replay-safe entry point: an operator or a block executor
    /// that read the registry at `based_on_root` re-sends the same change when
    /// a transfer retries; the second attempt carries the old root and is
    /// refused instead of registering onto a state that has moved.
    ///
    /// WIRING: `AccountState::register_quantum_account_at_root` calls this
    /// from the state-level door; the block executor reaches it through that
    /// account, which is why the name appears in the tree only there. Before
    /// the execution path lands, the unit canaries are the proof.
    ///
    /// # Errors
    ///
    /// Returns [`QuantumAccountRegistryError::RootMismatch`] when `based_on_root`
    /// is not the current root, and every error [`Self::register_with_pacts`]
    /// and [`Self::register`] return.
    pub fn register_at_root(
        &mut self,
        based_on_root: [u8; 32],
        account: QuantumAccount,
    ) -> Result<(), QuantumAccountRegistryError> {
        self.expect_root(based_on_root)?;
        self.register(account)
    }

    /// The replay-safe pact-carrying entry point: the root check of
    /// [`Self::register_at_root`] and the pact-evidence check of
    /// [`Self::register_with_pacts`] on one door, so a production caller can
    /// register an account whose `pact_root` is non-zero without either
    /// bypassing the presented-pact verification or racing a moved state.
    ///
    /// WIRING: `AccountState::register_quantum_account_with_pacts_at_root`
    /// is the state-level caller.
    ///
    /// # Errors
    ///
    /// Returns [`QuantumAccountRegistryError::RootMismatch`] when
    /// `based_on_root` is not the current root, and every error
    /// [`Self::register_with_pacts`] returns.
    pub fn register_with_pacts_at_root(
        &mut self,
        based_on_root: [u8; 32],
        account: QuantumAccount,
        pacts: &crate::storage::pact_binding::PactRegistry,
    ) -> Result<(), QuantumAccountRegistryError> {
        self.expect_root(based_on_root)?;
        self.register_with_pacts(account, pacts)
    }

    /// Update a registered account, refusing a change computed against an
    /// older root; the change function does not run when the root is stale.
    ///
    /// # Errors
    ///
    /// Returns [`QuantumAccountRegistryError::RootMismatch`] when `based_on_root`
    /// is not the current root, and every error [`Self::update`] returns.
    /// WIRING: `AccountState::update_quantum_account_at_root` is the caller.
    pub fn update_at_root<F>(
        &mut self,
        address: &[u8; 32],
        based_on_root: [u8; 32],
        change: F,
    ) -> Result<(), QuantumAccountRegistryError>
    where
        F: FnOnce(&mut QuantumAccount),
    {
        self.expect_root(based_on_root)?;
        self.update(address, change)
    }

    fn expect_root(&self, based_on_root: [u8; 32]) -> Result<(), QuantumAccountRegistryError> {
        let current = self.root();
        if based_on_root != current {
            return Err(QuantumAccountRegistryError::RootMismatch {
                expected: based_on_root,
                current,
            });
        }
        Ok(())
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

    /// Return a deterministic commitment to every registered account field.
    ///
    /// Each account is encoded in a fixed schema whose fields are independently
    /// length-prefixed by [`hash_fields_bytes`]. Account commitments are then
    /// folded in ascending address order (the order of the [`BTreeMap`]), with
    /// a separate registry domain and an explicit account count. Integer fields
    /// use canonical little-endian `u64` encodings, including Rust `usize`
    /// fields, so the result is independent of the host architecture.
    ///
    /// This is an in-memory registry commitment only. It is not included in
    /// `AccountState`, a transaction, a snapshot, or a block consensus root.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let account_count = canonical_usize(self.accounts.len());
        let epoch = self.epoch.to_le_bytes();
        let commitments: Vec<[u8; 32]> = self.accounts.values().map(account_commitment).collect();
        let mut fields: Vec<&[u8]> = Vec::with_capacity(commitments.len() + 3);
        fields.push(REGISTRY_ROOT_DOMAIN_V1);
        fields.push(&epoch);
        fields.push(&account_count);
        fields.extend(commitments.iter().map(<[u8; 32]>::as_slice));
        hash_fields_bytes(&fields)
    }

    /// Mutate a registered account.
    ///
    /// After the change the account goes through `validate_all` again; if it fails
    /// the change is not applied and the record stays as it was. The validity of a record
    /// must not be left to every writing path being careful on its
    /// own.
    ///
    /// Three fields are bound at registration and stay bound here: the
    /// address (the map key), the public key it was derived from, and the
    /// pact root that `register_with_pacts` checked against a real pact set.
    /// `validate_all` looks at thresholds and storage, not at those
    /// bindings, so without this check an update could move an account onto
    /// another key or name a pact set nobody presented. A pact root changes
    /// through a registration path that sees the new pact set, not here.
    ///
    /// # Errors
    ///
    /// Errors if the address is not registered, the change touches a bound
    /// field, or the change makes the account invalid.
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
        let bound = [
            ("address", candidate.address != current.address),
            (
                "public key",
                candidate.pq_public_key != current.pq_public_key,
            ),
            ("pact root", candidate.pact_root != current.pact_root),
        ];
        if let Some((field, _)) = bound.iter().find(|(_, changed)| *changed) {
            return Err(QuantumAccountRegistryError::BoundFieldChanged {
                address: *address,
                field,
            });
        }
        if let Err(reason) = candidate.validate_all() {
            return Err(QuantumAccountRegistryError::InvalidAccount {
                address: *address,
                reason: reason.to_string(),
            });
        }
        self.accounts.insert(*address, candidate);
        Ok(())
    }

    /// Evaluate a transaction-bound fee sponsor authorization for a registered
    /// account at the registry's current epoch.
    ///
    /// Convenience: bridges [`QuantumAccountRegistry`] to
    /// [`crate::account_abstraction::fee_and_session::FeeSponsorAuthorization`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::account_abstraction::fee_and_session::AccountAbstractionError`]
    /// if sponsorship verification fails.
    pub fn evaluate_sponsored_fee(
        &self,
        grant: &crate::account_abstraction::fee_and_session::FeeSponsorAuthorization,
        expected_chain_id: u64,
        expected_tx_hash: &[u8; 32],
        actual_fee_bud: u128,
    ) -> Result<[u8; 32], crate::account_abstraction::fee_and_session::AccountAbstractionError>
    {
        grant.verify(
            expected_chain_id,
            expected_tx_hash,
            actual_fee_bud,
            self.epoch,
        )
    }

    /// Evaluate a master-signed bounded session delegation for a registered account.
    ///
    /// Convenience: bridges [`QuantumAccountRegistry`] to
    /// [`crate::account_abstraction::fee_and_session::SessionDelegation`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::account_abstraction::fee_and_session::AccountAbstractionError`]
    /// if bounds, chain binding, or post-quantum master signature verification fails.
    pub fn evaluate_session_delegation(
        &self,
        delegation: &crate::account_abstraction::fee_and_session::SessionDelegation,
        expected_chain_id: u64,
    ) -> Result<[u8; 32], crate::account_abstraction::fee_and_session::AccountAbstractionError>
    {
        delegation.verify(expected_chain_id)
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
            .expect_err("the threshold cannot exceed the guardian count");
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
                .expect_err("the address must match the key"),
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

    /// A non-zero pact root is evidence-backed state, not a caller-provided claim.
    #[test]
    fn registering_a_nonzero_pact_root_without_pact_evidence_is_refused() {
        let mut account = account_with(2, 3);
        account.storage_root = [9u8; 32];
        account.pact_root = [7u8; 32];

        let mut registry = QuantumAccountRegistry::new();
        assert!(
            registry.register(account).is_err(),
            "a non-zero pact root must enter through register_with_pacts"
        );
        assert!(
            registry.is_empty(),
            "a refused claim must not enter the registry"
        );
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

    /// The key, the address and the pact root are fixed at registration. An
    /// update that rewrites any of them is refused and the record is
    /// untouched; a change to an unbound field on the same account goes
    /// through, so the refusal is about the field and not the path.
    #[test]
    fn an_update_cannot_move_the_account_onto_another_key_or_pact_set() {
        let mut registry = QuantumAccountRegistry::new();
        let account = account_with(2, 3);
        let address = account.address;
        registry.register(account).expect("valid account");

        const OTHER_KEY: [u8; ML_DSA_87_PUBLIC_KEY_LEN] = [9u8; ML_DSA_87_PUBLIC_KEY_LEN];
        assert_ne!(
            QuantumAccount::address_from_public_key(&OTHER_KEY),
            address,
            "the other key must derive another address"
        );
        type Change = fn(&mut QuantumAccount);
        let attempts: [(&str, Change); 4] = [
            ("public key", |a| a.pq_public_key = OTHER_KEY),
            ("address", |a| {
                a.address = QuantumAccount::address_from_public_key(&OTHER_KEY);
            }),
            // Both bound fields moved together: the refusal names the first
            // in the check's fixed order, which is the address.
            ("address", |a| {
                a.pq_public_key = OTHER_KEY;
                a.address = QuantumAccount::address_from_public_key(&OTHER_KEY);
            }),
            ("pact root", |a| a.pact_root = [4u8; 32]),
        ];
        for (expected, change) in attempts {
            let err = registry
                .update(&address, change)
                .expect_err("a bound field must not change through update");
            match err {
                QuantumAccountRegistryError::BoundFieldChanged { field, .. } => {
                    assert_eq!(field, expected);
                }
                other => panic!("expected BoundFieldChanged, got {other:?}"),
            }
        }
        let stored = registry.get(&address).expect("still registered");
        assert_eq!(stored.pq_public_key, [3u8; ML_DSA_87_PUBLIC_KEY_LEN]);
        assert_eq!(stored.address, address);
        assert_eq!(stored.pact_root, [0u8; 32]);

        registry
            .update(&address, |a| a.nonce += 1)
            .expect("an unbound field still updates");
        assert_eq!(registry.get(&address).map(|a| a.nonce), Some(1));
    }

    /// An account carrying a real pact set must be registrable.
    #[test]
    fn an_account_bound_to_its_pact_set_registers() {
        use crate::storage::pact_binding::Pact;
        use sha3::{Digest, Sha3_256};

        let payload = b"probe";
        let mut h = Sha3_256::new();
        h.update(payload);
        let commitment: [u8; 32] = h.finalize().into();

        let mut pacts = PactRegistry::new();
        pacts
            .add_pact(
                Pact::new(
                    [1u8; 32], [0u8; 32], [0u8; 32], commitment, [0u8; 32], 10, 0,
                )
                .expect("valid pact"),
            )
            .expect("pact accepted");

        let mut account = account_with(2, 3);
        account.storage_root = [9u8; 32];
        account.pact_root = pacts.root;
        let address = account.address;

        let mut registry = QuantumAccountRegistry::new();
        registry
            .register_with_pacts(account, &pacts)
            .expect("the root matches");
        assert!(registry.is_registered(&address));
    }

    /// The pact-carrying state door is replay-safe: the registration binds
    /// to the registry root the caller read, and a retry over the moved
    /// state is refused before the pact evidence is even consulted.
    #[test]
    fn the_pact_carrying_door_refuses_a_stale_state_root_and_lands_on_the_live_one() {
        use crate::storage::pact_binding::Pact;
        use sha3::{Digest, Sha3_256};

        let payload = b"pact payload";
        let mut h = Sha3_256::new();
        h.update(payload);
        let commitment: [u8; 32] = h.finalize().into();
        let mut pacts = PactRegistry::new();
        pacts
            .add_pact(
                Pact::new(
                    [1u8; 32], [0u8; 32], [0u8; 32], commitment, [0u8; 32], 10, 0,
                )
                .expect("valid pact"),
            )
            .expect("pact accepted");

        let mut state = crate::core::account::AccountState::new();
        let live_root = state.quantum_accounts.root();

        let mut account = account_with(2, 3);
        account.storage_root = [9u8; 32];
        account.pact_root = pacts.root;
        let address = account.address;

        // A root read from an older state refuses the registration.
        assert!(matches!(
            state.register_quantum_account_with_pacts_at_root(
                [0x55u8; 32],
                account.clone(),
                &pacts
            ),
            Err(QuantumAccountRegistryError::RootMismatch { .. })
        ));
        // The live root admits it, through the full pact-evidence check.
        state
            .register_quantum_account_with_pacts_at_root(live_root, account, &pacts)
            .expect("the live root and the pact set both match");
        assert!(state.quantum_accounts.is_registered(&address));
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
        pacts
            .add_pact(
                Pact::new([1u8; 32], [0u8; 32], [0u8; 32], [2u8; 32], [0u8; 32], 10, 0)
                    .expect("valid pact"),
            )
            .expect("pact accepted");
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

    #[test]
    fn registry_root_commits_the_pact_root() {
        use crate::storage::pact_binding::Pact;

        let mut plain_account = account_with(2, 3);
        plain_account.storage_root = [9u8; 32];
        let mut plain = QuantumAccountRegistry::new();
        plain.register(plain_account).expect("plain account");

        let mut pacts = PactRegistry::new();
        pacts
            .add_pact(
                Pact::new([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [0u8; 32], 8, 0)
                    .expect("valid pact"),
            )
            .expect("pact accepted");
        let mut bound_account = account_with(2, 3);
        bound_account.storage_root = [9u8; 32];
        bound_account.pact_root = pacts.root;
        let mut bound = QuantumAccountRegistry::new();
        bound
            .register_with_pacts(bound_account, &pacts)
            .expect("evidence-backed account");

        assert_ne!(
            plain.root(),
            bound.root(),
            "the registry root must commit the account pact root"
        );
    }

    #[test]
    fn registry_root_has_stable_canonical_encoding() {
        let mut registry = QuantumAccountRegistry::new();
        registry
            .register(account_with(2, 3))
            .expect("valid account");

        // Re-pinned after the epoch joined the root fold: the old pin was
        // written before `root()` committed the registry epoch.
        assert_eq!(
            hex::encode(registry.root()),
            "5c2e357278711e6fd824b72ece2557ebf902f853617a923643a8ab64258ce988"
        );
    }

    #[test]
    fn registry_root_commits_account_identity_fields() {
        let first = account_with(2, 3);
        let mut second = account_with(2, 3);
        second.pq_public_key = [4u8; ML_DSA_87_PUBLIC_KEY_LEN];
        second.address = QuantumAccount::address_from_public_key(&second.pq_public_key);

        let mut first_registry = QuantumAccountRegistry::new();
        first_registry.register(first).expect("first account");
        let mut second_registry = QuantumAccountRegistry::new();
        second_registry.register(second).expect("second account");

        assert_ne!(first_registry.root(), second_registry.root());
    }

    #[test]
    fn registry_root_commits_every_mutable_account_field() {
        let account = account_with(2, 3);
        let address = account.address;
        let mut registry = QuantumAccountRegistry::new();
        registry.register(account).expect("base account");
        let root = registry.root();

        let changes: [fn(&mut QuantumAccount); 8] = [
            |account| account.storage_root = [1u8; 32],
            |account| {
                account.guardians[0][0] = 99;
                account.guardian_root = QuantumAccount::guardian_root(&account.guardians);
            },
            |account| account.multisig_threshold = 1,
            |account| account.recovery_threshold = 1,
            |account| account.timelock_blocks += 1,
            |account| account.nonce += 1,
            |account| account.balance += 1,
            |account| account.storage_bytes += 1,
        ];

        for change in changes {
            let mut changed = registry.clone();
            changed.update(&address, change).expect("valid update");
            assert_ne!(root, changed.root());
        }
    }

    #[test]
    fn registry_root_is_independent_of_registration_order() {
        let first = account_with(2, 3);
        let mut second = account_with(2, 3);
        second.pq_public_key = [4u8; ML_DSA_87_PUBLIC_KEY_LEN];
        second.address = QuantumAccount::address_from_public_key(&second.pq_public_key);

        let mut forward = QuantumAccountRegistry::new();
        forward.register(first.clone()).expect("first account");
        forward.register(second.clone()).expect("second account");

        let mut reverse = QuantumAccountRegistry::new();
        reverse.register(second).expect("second account");
        reverse.register(first).expect("first account");

        assert_eq!(forward.root(), reverse.root());
    }

    /// An unknown address cannot be updated.
    #[test]
    fn updating_an_unknown_address_is_refused() {
        let mut registry = QuantumAccountRegistry::new();
        assert!(matches!(
            registry
                .update(&[1u8; 32], |a| a.nonce += 1)
                .expect_err("unknown address"),
            QuantumAccountRegistryError::NotRegistered { .. }
        ));
    }

    /// A replayed registration (the same account copy applied a second time
    /// from an older state) must be refused against the current root, and the
    /// refusal must name the root the caller based the change on: a transfer
    /// made against a stale root cannot resurrect an account or move state
    /// backwards.
    #[test]
    fn a_replayed_registration_against_a_stale_root_is_refused() {
        let mut registry = QuantumAccountRegistry::new();
        let stale_root = registry.root();
        registry
            .register_at_root(stale_root, account_with(2, 3))
            .expect("fresh registration at the current root");
        let current = account_with(2, 3);
        let err = registry
            .register_at_root(stale_root, current)
            .expect_err("the root it was based on is no longer current");
        assert!(
            matches!(err, QuantumAccountRegistryError::RootMismatch { .. }),
            "a replayed change must fail on the root check, got {err:?}"
        );
        assert_eq!(registry.len(), 1);
    }

    /// An update replayed from an older state must not re-apply: the second
    /// attempt still carries the old root and is refused before the change
    /// function runs.
    #[test]
    fn a_replayed_update_against_a_stale_root_is_refused() {
        let address = account_with(2, 3).address;
        let mut registry = QuantumAccountRegistry::new();
        registry.register(account_with(2, 3)).expect("register");
        let stale_root = registry.root();
        registry
            .update_at_root(&address, stale_root, |a| a.nonce += 1)
            .expect("first update at the current root");
        let mut ran = false;
        let err = registry
            .update_at_root(&address, stale_root, |_| ran = true)
            .expect_err("the replay carries the old root");
        assert!(
            matches!(err, QuantumAccountRegistryError::RootMismatch { .. }),
            "a replayed update must fail on the root check, got {err:?}"
        );
        assert!(!ran, "the change must not run when the root is stale");
        assert_eq!(registry.get(&address).map(|a| a.nonce), Some(1));
    }

    /// The registry must survive a snapshot round trip: the epoch and every
    /// account travel through serde, and a restored registry reproduces the
    /// same root.
    #[test]
    fn a_restored_registry_reproduces_its_root() {
        let mut registry = QuantumAccountRegistry::new();
        registry.set_epoch(7);
        registry.register(account_with(2, 3)).expect("register");
        let encoded = serde_json::to_string(&registry).expect("serialize");
        let restored: QuantumAccountRegistry = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(restored.epoch, 7);
        assert_eq!(restored.root(), registry.root());
    }

    /// The root must describe the accounts, not the arrival order: the
    /// account count and every account field are folded in ascending address
    /// order (a `BTreeMap`), and the epoch is a separate domain-separated
    /// commitment.
    #[test]
    fn the_registry_root_binds_every_account_field() {
        let mut registry = QuantumAccountRegistry::new();
        registry.register(account_with(2, 3)).expect("register");
        let root = registry.root();
        let address = account_with(2, 3).address;
        for edit in [
            |a: &mut QuantumAccount| a.nonce += 1,
            |a: &mut QuantumAccount| a.balance += 1,
            |a: &mut QuantumAccount| a.storage_bytes += 1,
            |a: &mut QuantumAccount| a.timelock_blocks += 1,
        ] {
            let mut changed = registry.clone();
            changed.update(&address, edit).expect("update");
            assert_ne!(
                changed.root(),
                root,
                "an editable field must move the registry root"
            );
        }
        let mut epoch_moved = registry.clone();
        epoch_moved.set_epoch(1);
        assert_ne!(
            epoch_moved.root(),
            root,
            "the epoch must move the registry root"
        );
    }

    #[test]
    fn quantum_account_registry_cap_is_positive_and_bounded() {
        const { assert!(MAX_QUANTUM_ACCOUNTS == 100_000) };
        let registry = QuantumAccountRegistry::new();
        assert!(registry.len() < MAX_QUANTUM_ACCOUNTS);
    }
}
