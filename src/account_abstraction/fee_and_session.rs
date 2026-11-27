//! Fee sponsorship, bounded session-key delegation (including hardware-capped
//! classical session keys under a cold post-quantum master key), and timelocked
//! owner-cancellable social recovery with zero admin backdoors.
//!
//! Convenience: exposed for account-abstraction wallets, gasless payment flows,
//! hardware companion keys, and governance-free key recovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::address::Address;
use crate::crypto::composite::{self, CompositeKeypair, CompositePublicKey, CompositeSignature};
pub use crate::crypto::ctx::{
    FEE_SPONSOR_V1 as FEE_SPONSOR_DOMAIN_TAG, RECOVERY_APPROVAL_V1 as RECOVERY_APPROVAL_DOMAIN_TAG,
    RECOVERY_CANCEL_V1 as RECOVERY_CANCEL_DOMAIN_TAG,
    SESSION_DELEGATION_V1 as SESSION_DELEGATION_DOMAIN_TAG,
    SESSION_REVOKE_V1 as SESSION_REVOKE_DOMAIN_TAG, SESSION_SPEND_V1 as SESSION_SPEND_DOMAIN_TAG,
};
use crate::crypto::secp256k1_recover::recover_address;
use crate::domain::types::Hash32;
use crate::unification::hash_domain_fields;
use serde::{Deserialize, Serialize};

const HASH_TAG_FEE_SPONSOR: &[u8] = b"BDLM_FEE_SPONSOR_V1";
const HASH_TAG_SESSION_DELEGATION: &[u8] = b"BDLM_SESSION_DELEGATION_V1";
const HASH_TAG_SESSION_SPEND: &[u8] = b"BDLM_SESSION_SPEND_V1";
const HASH_TAG_SESSION_REVOKE: &[u8] = b"BDLM_SESSION_REVOKE_V1";
const HASH_TAG_RECOVERY_APPROVAL: &[u8] = b"BDLM_RECOVERY_APPROVAL_V1";
const HASH_TAG_RECOVERY_CANCEL: &[u8] = b"BDLM_RECOVERY_CANCEL_V1";

/// Hard upper cap (in smallest BUD base units) on a classical hardware session
/// key's cumulative spend so that a compromised classical enclave can never
/// drain a post-quantum master account beyond a tightly bounded allowance.
pub const MAX_CLASSICAL_HARDWARE_SESSION_CAP: u128 = 10_000_000_000;

/// Maximum number of unpruned consumed fee sponsorship grants tracked in memory.
pub const MAX_CONSUMED_GRANTS: usize = 65_536;

/// Maximum number of active/revoked session delegations tracked in memory.
pub const MAX_SESSIONS: usize = 65_536;

/// Maximum number of spent nonces tracked per delegated session.
pub const MAX_SESSION_NONCES: usize = 65_536;

/// Maximum number of explicit recipient entries allowed in a session allowlist.
pub const MAX_ALLOWED_RECIPIENTS: usize = 256;

/// Maximum number of guardians allowed in a social recovery policy.
pub const MAX_GUARDIANS: usize = 32;

/// Maximum number of recovery proposals tracked in memory.
pub const MAX_RECOVERY_PROPOSALS: usize = 65_536;

/// Errors raised by fee sponsorship, session delegation, or timelocked recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountAbstractionError {
    ZeroMaxFee,
    InvalidSender,
    FeeExceedsSponsoredCap {
        actual: u128,
        max: u128,
    },
    SponsorAuthorizationExpired {
        current_epoch: u64,
        expiry_epoch: u64,
    },
    ChainIdMismatch {
        expected: u64,
        got: u64,
    },
    TxHashMismatch,
    SponsorAuthorizationAlreadyConsumed,
    RegistryCapacityExceeded,
    InvalidCompositeKey,
    InvalidCompositeSignature,
    InvalidClassicalKey,
    InvalidClassicalSignature,
    ZeroSpendCap,
    PerTxCapExceedsTotalCap,
    ClassicalHardwareCapExceeded {
        requested: u128,
        max: u128,
    },
    InvalidValidityWindow,
    SessionNotActive {
        current_epoch: u64,
        not_before: u64,
        expiry: u64,
    },
    SessionRevoked,
    SessionNotFound,
    DuplicateSession,
    RecipientNotAllowed,
    AmountExceedsPerTxCap {
        amount: u128,
        per_tx_cap: u128,
    },
    AmountExceedsRemainingCap {
        amount: u128,
        remaining: u128,
    },
    ArithmeticOverflow,
    SessionSpendReplay,
    InvalidGuardianPolicy,
    OwnerCannotBeGuardian,
    UnchangedOwnerKey,
    ZeroDelayWindow,
    DuplicateGuardianApproval,
    DuplicateRecovery,
    UnknownGuardian,
    InsufficientGuardianApprovals {
        have: usize,
        required: usize,
    },
    RecoveryWindowStillOpen {
        current_epoch: u64,
        executable_epoch: u64,
    },
    RecoveryAlreadyFinalized,
    RecoveryCancelled,
    RecoveryNotFound,
}

impl std::fmt::Display for AccountAbstractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AccountAbstractionError {}

// ---------------------------------------------------------------------------
// 1. Gasless fee sponsorship (single-transaction, chain-bound, replay-safe)
// ---------------------------------------------------------------------------

/// Cryptographic authorization from a BUD fee sponsor to pay fees for one
/// specific transaction (`tx_hash`) on one specific chain (`chain_id`).
///
/// The sponsor's signature binds `chain_id`, `tx_hash`, `sender`,
/// `sponsor_pubkey`, `max_fee_bud`, `expiry_epoch`, and `sponsor_nonce`, so a
/// sponsorship grant can never be transplanted onto another transaction,
/// sponsor key, or chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorAuthorization {
    pub chain_id: u64,
    pub tx_hash: Hash32,
    pub sender: Address,
    pub sponsor_pubkey: Vec<u8>,
    pub max_fee_bud: u128,
    pub expiry_epoch: u64,
    pub sponsor_nonce: u64,
    pub sponsor_signature: Vec<u8>,
}

/// Parameters for signing a single-transaction [`FeeSponsorAuthorization`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeSponsorTerms {
    pub chain_id: u64,
    pub tx_hash: Hash32,
    pub sender: Address,
    pub max_fee_bud: u128,
    pub expiry_epoch: u64,
    pub sponsor_nonce: u64,
}

impl FeeSponsorAuthorization {
    /// Canonical domain-separated signing payload for a fee sponsor grant.
    ///
    /// Binds `sponsor_pubkey` directly into the length-prefixed hash preimage
    /// so distinct sponsors never share identical grant digests.
    ///
    /// Convenience: exposed for wallets, solvers, and paymaster signers.
    #[must_use]
    pub fn signing_digest(terms: &FeeSponsorTerms, sponsor_pubkey: &[u8]) -> Hash32 {
        let chain_id = terms.chain_id.to_be_bytes();
        let max_fee = terms.max_fee_bud.to_be_bytes();
        let expiry = terms.expiry_epoch.to_be_bytes();
        let nonce = terms.sponsor_nonce.to_be_bytes();
        hash_domain_fields(
            HASH_TAG_FEE_SPONSOR,
            &[
                &chain_id,
                &terms.tx_hash,
                terms.sender.as_bytes(),
                sponsor_pubkey,
                &max_fee,
                &expiry,
                &nonce,
            ],
        )
    }

    /// Create and sign a fee sponsorship grant using a post-quantum hybrid
    /// [`CompositeKeypair`].
    ///
    /// Convenience: exposed for gasless payment sponsors and solvers.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError::InvalidSender`] if `sender` is zero
    /// or [`AccountAbstractionError::ZeroMaxFee`] if `max_fee_bud == 0`.
    pub fn sign(
        sponsor_kp: &CompositeKeypair,
        terms: FeeSponsorTerms,
        rnd: &[u8; 32],
    ) -> Result<Self, AccountAbstractionError> {
        if terms.sender == Address::zero() {
            return Err(AccountAbstractionError::InvalidSender);
        }
        if terms.max_fee_bud == 0 {
            return Err(AccountAbstractionError::ZeroMaxFee);
        }
        let sponsor_pubkey = sponsor_kp
            .public_key()
            .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?
            .encode();
        let digest = Self::signing_digest(&terms, &sponsor_pubkey);
        let sig = sponsor_kp
            .sign(FEE_SPONSOR_DOMAIN_TAG, &digest, rnd)
            .map_err(|_| AccountAbstractionError::InvalidCompositeSignature)?;
        Ok(Self {
            chain_id: terms.chain_id,
            tx_hash: terms.tx_hash,
            sender: terms.sender,
            sponsor_pubkey,
            max_fee_bud: terms.max_fee_bud,
            expiry_epoch: terms.expiry_epoch,
            sponsor_nonce: terms.sponsor_nonce,
            sponsor_signature: sig.encode(),
        })
    }

    /// Verify the sponsor authorization against the executing transaction hash,
    /// chain ID, current epoch, and actual BUD fee charged.
    ///
    /// Convenience: exposed for block validators and mempool admission checks.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if sender, binding, expiry, fee
    /// bound, or post-quantum composite signature check fails.
    pub fn verify(
        &self,
        expected_chain_id: u64,
        expected_tx_hash: &Hash32,
        actual_fee_bud: u128,
        current_epoch: u64,
    ) -> Result<Hash32, AccountAbstractionError> {
        if self.sender == Address::zero() {
            return Err(AccountAbstractionError::InvalidSender);
        }
        if self.max_fee_bud == 0 {
            return Err(AccountAbstractionError::ZeroMaxFee);
        }
        if self.chain_id != expected_chain_id {
            return Err(AccountAbstractionError::ChainIdMismatch {
                expected: expected_chain_id,
                got: self.chain_id,
            });
        }
        if &self.tx_hash != expected_tx_hash {
            return Err(AccountAbstractionError::TxHashMismatch);
        }
        if current_epoch > self.expiry_epoch {
            return Err(AccountAbstractionError::SponsorAuthorizationExpired {
                current_epoch,
                expiry_epoch: self.expiry_epoch,
            });
        }
        if actual_fee_bud > self.max_fee_bud {
            return Err(AccountAbstractionError::FeeExceedsSponsoredCap {
                actual: actual_fee_bud,
                max: self.max_fee_bud,
            });
        }
        let pk = CompositePublicKey::decode(&self.sponsor_pubkey)
            .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?;
        let sig = CompositeSignature::decode(&self.sponsor_signature)
            .map_err(|_| AccountAbstractionError::InvalidCompositeSignature)?;
        let terms = FeeSponsorTerms {
            chain_id: self.chain_id,
            tx_hash: self.tx_hash,
            sender: self.sender,
            max_fee_bud: self.max_fee_bud,
            expiry_epoch: self.expiry_epoch,
            sponsor_nonce: self.sponsor_nonce,
        };
        let digest = Self::signing_digest(&terms, &self.sponsor_pubkey);
        if composite::verify(&pk, FEE_SPONSOR_DOMAIN_TAG, &digest, &sig).is_err() {
            return Err(AccountAbstractionError::InvalidCompositeSignature);
        }
        Ok(digest)
    }
}

/// Single-use replay-protection registry for consumed fee sponsor grants,
/// bounded at [`MAX_CONSUMED_GRANTS`] with expired-grant pruning.
///
/// Convenience: exposed for gasless execution coordinators.
#[derive(Debug, Clone, Default)]
pub struct FeeSponsorRegistry {
    consumed_grants: BTreeMap<Hash32, u64>,
}

impl FeeSponsorRegistry {
    /// Verify and atomically consume a fee sponsor grant for one transaction.
    ///
    /// Convenience: exposed for gasless fee debit settlement.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if verification fails, the grant
    /// has already been consumed, or capacity cannot be freed by pruning expired
    /// entries.
    pub fn consume(
        &mut self,
        grant: &FeeSponsorAuthorization,
        expected_chain_id: u64,
        expected_tx_hash: &Hash32,
        actual_fee_bud: u128,
        current_epoch: u64,
    ) -> Result<Hash32, AccountAbstractionError> {
        let grant_id = grant.verify(
            expected_chain_id,
            expected_tx_hash,
            actual_fee_bud,
            current_epoch,
        )?;
        if self.consumed_grants.contains_key(&grant_id) {
            return Err(AccountAbstractionError::SponsorAuthorizationAlreadyConsumed);
        }
        if self.consumed_grants.len() >= MAX_CONSUMED_GRANTS {
            self.consumed_grants
                .retain(|_, expiry_epoch| *expiry_epoch >= current_epoch);
            if self.consumed_grants.len() >= MAX_CONSUMED_GRANTS {
                return Err(AccountAbstractionError::RegistryCapacityExceeded);
            }
        }
        self.consumed_grants.insert(grant_id, grant.expiry_epoch);
        Ok(grant_id)
    }

    /// Returns true if `grant_id` is currently tracked as consumed.
    ///
    /// Convenience: exposed for status queries and tests.
    #[must_use]
    pub fn is_consumed(&self, grant_id: &Hash32) -> bool {
        self.consumed_grants.contains_key(grant_id)
    }
}

// ---------------------------------------------------------------------------
// 2. Bounded session keys (post-quantum + hardware-capped classical)
// ---------------------------------------------------------------------------

/// Cryptographic key posture for a delegated session key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionKeyPosture {
    /// Full post-quantum hybrid session key (`CompositePublicKey` encoded bytes).
    PostQuantumComposite { composite_pubkey: Vec<u8> },
    /// Hardware-enclave classical key (e.g. phone/watch/card secp256k1 20-byte
    /// address) strictly bounded by [`MAX_CLASSICAL_HARDWARE_SESSION_CAP`] so
    /// quantum risk stays isolated to a small, pre-authorized allowance while
    /// the master account remains post-quantum.
    HardwareClassicalCapped { evm_address: [u8; 20] },
}

/// Master-signed bounded session delegation for an account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDelegation {
    pub chain_id: u64,
    pub master_pubkey: Vec<u8>,
    pub session_key: SessionKeyPosture,
    pub total_spend_cap: u128,
    pub per_tx_cap: u128,
    /// Empty means any non-zero recipient is allowed; non-empty restricts
    /// spends strictly to listed non-zero addresses.
    pub allowed_recipients: Vec<Address>,
    pub not_before_epoch: u64,
    pub expiry_epoch: u64,
    pub delegation_nonce: u64,
    pub master_signature: Vec<u8>,
}

/// Parameters for creating a [`SessionDelegation`] without long argument lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDelegationParams {
    pub chain_id: u64,
    pub session_key: SessionKeyPosture,
    pub total_spend_cap: u128,
    pub per_tx_cap: u128,
    pub allowed_recipients: Vec<Address>,
    pub not_before_epoch: u64,
    pub expiry_epoch: u64,
    pub delegation_nonce: u64,
}

impl SessionDelegation {
    /// Canonical domain-separated digest for a session delegation.
    ///
    /// Convenience: exposed for hardware/cold wallet delegation signing.
    #[must_use]
    pub fn delegation_id_from_params(
        master_pubkey: &[u8],
        params: &SessionDelegationParams,
    ) -> Hash32 {
        let chain_id = params.chain_id.to_be_bytes();
        let total_cap = params.total_spend_cap.to_be_bytes();
        let per_tx = params.per_tx_cap.to_be_bytes();
        let recipient_count = u64::try_from(params.allowed_recipients.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes();
        let mut recipient_bytes = Vec::with_capacity(params.allowed_recipients.len() * 32);
        for recipient in &params.allowed_recipients {
            recipient_bytes.extend_from_slice(recipient.as_bytes());
        }
        let not_before = params.not_before_epoch.to_be_bytes();
        let expiry = params.expiry_epoch.to_be_bytes();
        let nonce = params.delegation_nonce.to_be_bytes();

        let (posture_tag, posture_key): ([u8; 1], &[u8]) = match &params.session_key {
            SessionKeyPosture::PostQuantumComposite { composite_pubkey } => {
                ([0x01], composite_pubkey.as_slice())
            }
            SessionKeyPosture::HardwareClassicalCapped { evm_address } => {
                ([0x02], evm_address.as_slice())
            }
        };

        hash_domain_fields(
            HASH_TAG_SESSION_DELEGATION,
            &[
                &chain_id,
                master_pubkey,
                &posture_tag,
                posture_key,
                &total_cap,
                &per_tx,
                &recipient_count,
                &recipient_bytes,
                &not_before,
                &expiry,
                &nonce,
            ],
        )
    }

    /// Compute this delegation's canonical ID.
    ///
    /// Convenience: exposed for registries and wallet UIs.
    #[must_use]
    pub fn delegation_id(&self) -> Hash32 {
        let params = SessionDelegationParams {
            chain_id: self.chain_id,
            session_key: self.session_key.clone(),
            total_spend_cap: self.total_spend_cap,
            per_tx_cap: self.per_tx_cap,
            allowed_recipients: self.allowed_recipients.clone(),
            not_before_epoch: self.not_before_epoch,
            expiry_epoch: self.expiry_epoch,
            delegation_nonce: self.delegation_nonce,
        };
        Self::delegation_id_from_params(&self.master_pubkey, &params)
    }

    /// Create and sign a bounded session delegation with the cold post-quantum
    /// master [`CompositeKeypair`].
    ///
    /// Convenience: exposed for master-wallet session provisioning.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if key encodings, caps, recipients,
    /// or epoch windows are invalid.
    pub fn sign(
        master_kp: &CompositeKeypair,
        params: SessionDelegationParams,
        rnd: &[u8; 32],
    ) -> Result<Self, AccountAbstractionError> {
        validate_session_bounds(&params)?;
        let master_pubkey = master_kp
            .public_key()
            .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?
            .encode();
        let digest = Self::delegation_id_from_params(&master_pubkey, &params);
        let sig = master_kp
            .sign(SESSION_DELEGATION_DOMAIN_TAG, &digest, rnd)
            .map_err(|_| AccountAbstractionError::InvalidCompositeSignature)?;
        Ok(Self {
            chain_id: params.chain_id,
            master_pubkey,
            session_key: params.session_key,
            total_spend_cap: params.total_spend_cap,
            per_tx_cap: params.per_tx_cap,
            allowed_recipients: params.allowed_recipients,
            not_before_epoch: params.not_before_epoch,
            expiry_epoch: params.expiry_epoch,
            delegation_nonce: params.delegation_nonce,
            master_signature: sig.encode(),
        })
    }

    /// Verify the master post-quantum signature and structural bounds.
    ///
    /// Convenience: exposed for session admission and auditing.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if bounds, chain ID, key decoding,
    /// or master signature fail.
    pub fn verify(&self, expected_chain_id: u64) -> Result<Hash32, AccountAbstractionError> {
        if self.chain_id != expected_chain_id {
            return Err(AccountAbstractionError::ChainIdMismatch {
                expected: expected_chain_id,
                got: self.chain_id,
            });
        }
        let params = SessionDelegationParams {
            chain_id: self.chain_id,
            session_key: self.session_key.clone(),
            total_spend_cap: self.total_spend_cap,
            per_tx_cap: self.per_tx_cap,
            allowed_recipients: self.allowed_recipients.clone(),
            not_before_epoch: self.not_before_epoch,
            expiry_epoch: self.expiry_epoch,
            delegation_nonce: self.delegation_nonce,
        };
        validate_session_bounds(&params)?;
        let pk = CompositePublicKey::decode(&self.master_pubkey)
            .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?;
        let sig = CompositeSignature::decode(&self.master_signature)
            .map_err(|_| AccountAbstractionError::InvalidCompositeSignature)?;
        let digest = self.delegation_id();
        if composite::verify(&pk, SESSION_DELEGATION_DOMAIN_TAG, &digest, &sig).is_err() {
            return Err(AccountAbstractionError::InvalidCompositeSignature);
        }
        Ok(digest)
    }
}

fn validate_session_bounds(
    params: &SessionDelegationParams,
) -> Result<(), AccountAbstractionError> {
    if params.total_spend_cap == 0 || params.per_tx_cap == 0 {
        return Err(AccountAbstractionError::ZeroSpendCap);
    }
    if params.per_tx_cap > params.total_spend_cap {
        return Err(AccountAbstractionError::PerTxCapExceedsTotalCap);
    }
    if params.not_before_epoch > params.expiry_epoch {
        return Err(AccountAbstractionError::InvalidValidityWindow);
    }
    if params.allowed_recipients.len() > MAX_ALLOWED_RECIPIENTS {
        return Err(AccountAbstractionError::RecipientNotAllowed);
    }
    for recipient in &params.allowed_recipients {
        if *recipient == Address::zero() {
            return Err(AccountAbstractionError::RecipientNotAllowed);
        }
    }
    match &params.session_key {
        SessionKeyPosture::PostQuantumComposite { composite_pubkey } => {
            CompositePublicKey::decode(composite_pubkey)
                .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?;
        }
        SessionKeyPosture::HardwareClassicalCapped { evm_address } => {
            if *evm_address == [0u8; 20] {
                return Err(AccountAbstractionError::InvalidClassicalKey);
            }
            if params.total_spend_cap > MAX_CLASSICAL_HARDWARE_SESSION_CAP {
                return Err(AccountAbstractionError::ClassicalHardwareCapExceeded {
                    requested: params.total_spend_cap,
                    max: MAX_CLASSICAL_HARDWARE_SESSION_CAP,
                });
            }
        }
    }
    Ok(())
}

/// Canonical digest signed by a session key to authorize one bounded spend.
///
/// Convenience: exposed for companion devices and hardware wallets.
#[must_use]
pub fn session_spend_digest(
    delegation_id: &Hash32,
    chain_id: u64,
    recipient: &Address,
    amount: u128,
    spend_nonce: u64,
) -> Hash32 {
    let chain = chain_id.to_be_bytes();
    let amt = amount.to_be_bytes();
    let nonce = spend_nonce.to_be_bytes();
    hash_domain_fields(
        HASH_TAG_SESSION_SPEND,
        &[delegation_id, &chain, recipient.as_bytes(), &amt, &nonce],
    )
}

/// Canonical digest signed by the master account key to revoke a session delegation.
///
/// Convenience: exposed for master wallet session revocation flows.
#[must_use]
pub fn session_revoke_digest(delegation_id: &Hash32, chain_id: u64) -> Hash32 {
    let chain = chain_id.to_be_bytes();
    hash_domain_fields(HASH_TAG_SESSION_REVOKE, &[delegation_id, &chain])
}

#[derive(Debug, Clone)]
struct SessionState {
    delegation: SessionDelegation,
    spent_total: u128,
    revoked: bool,
    used_nonces: BTreeSet<u64>,
}

/// Parameters for one bounded spend request under a delegated session key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSpendRequest {
    pub delegation_id: Hash32,
    pub chain_id: u64,
    pub recipient: Address,
    pub amount: u128,
    pub spend_nonce: u64,
    pub current_epoch: u64,
}

/// Stateful registry enforcing session caps, allowlists, expiry, authenticated
/// master revocation, and per-spend replay protection.
///
/// Convenience: exposed for execution engines and wallet policy simulators.
#[derive(Debug, Clone, Default)]
pub struct SessionDelegationRegistry {
    sessions: BTreeMap<Hash32, SessionState>,
}

impl SessionDelegationRegistry {
    /// Register a verified master-signed session delegation without allowing
    /// duplicate overwrites.
    ///
    /// Convenience: exposed for session onboarding.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if verification fails, the
    /// delegation is already registered, or registry capacity is reached.
    pub fn register(
        &mut self,
        delegation: SessionDelegation,
        expected_chain_id: u64,
    ) -> Result<Hash32, AccountAbstractionError> {
        let id = delegation.verify(expected_chain_id)?;
        if self.sessions.contains_key(&id) {
            return Err(AccountAbstractionError::DuplicateSession);
        }
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(AccountAbstractionError::RegistryCapacityExceeded);
        }
        self.sessions.insert(
            id,
            SessionState {
                delegation,
                spent_total: 0,
                revoked: false,
                used_nonces: BTreeSet::new(),
            },
        );
        Ok(id)
    }

    /// Revoke a registered session delegation after verifying a master
    /// post-quantum signature over [`session_revoke_digest`].
    ///
    /// Convenience: exposed for authenticated lost-device revocation.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if unknown, already revoked, or the
    /// master signature fails verification.
    pub fn revoke(
        &mut self,
        delegation_id: &Hash32,
        master_signature: &[u8],
    ) -> Result<(), AccountAbstractionError> {
        let entry = self
            .sessions
            .get_mut(delegation_id)
            .ok_or(AccountAbstractionError::SessionNotFound)?;
        if entry.revoked {
            return Err(AccountAbstractionError::SessionRevoked);
        }
        let pk = CompositePublicKey::decode(&entry.delegation.master_pubkey)
            .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?;
        let sig = CompositeSignature::decode(master_signature)
            .map_err(|_| AccountAbstractionError::InvalidCompositeSignature)?;
        let digest = session_revoke_digest(delegation_id, entry.delegation.chain_id);
        if composite::verify(&pk, SESSION_REVOKE_DOMAIN_TAG, &digest, &sig).is_err() {
            return Err(AccountAbstractionError::InvalidCompositeSignature);
        }
        entry.revoked = true;
        Ok(())
    }

    /// Authorize and record one spend under a registered session key.
    ///
    /// Convenience: exposed for bounded session-key payments.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if the session is unknown, revoked,
    /// expired, recipient-disallowed, over per-tx or cumulative cap, replayed,
    /// or carries an invalid signature.
    pub fn authorize_spend(
        &mut self,
        req: &SessionSpendRequest,
        session_signature: &[u8],
    ) -> Result<u128, AccountAbstractionError> {
        if req.recipient == Address::zero() {
            return Err(AccountAbstractionError::RecipientNotAllowed);
        }
        let entry = self
            .sessions
            .get_mut(&req.delegation_id)
            .ok_or(AccountAbstractionError::SessionNotFound)?;
        if entry.revoked {
            return Err(AccountAbstractionError::SessionRevoked);
        }
        if entry.delegation.chain_id != req.chain_id {
            return Err(AccountAbstractionError::ChainIdMismatch {
                expected: entry.delegation.chain_id,
                got: req.chain_id,
            });
        }
        if req.current_epoch < entry.delegation.not_before_epoch
            || req.current_epoch > entry.delegation.expiry_epoch
        {
            return Err(AccountAbstractionError::SessionNotActive {
                current_epoch: req.current_epoch,
                not_before: entry.delegation.not_before_epoch,
                expiry: entry.delegation.expiry_epoch,
            });
        }
        if !entry.delegation.allowed_recipients.is_empty()
            && !entry.delegation.allowed_recipients.contains(&req.recipient)
        {
            return Err(AccountAbstractionError::RecipientNotAllowed);
        }
        if req.amount == 0 {
            return Err(AccountAbstractionError::ZeroSpendCap);
        }
        if req.amount > entry.delegation.per_tx_cap {
            return Err(AccountAbstractionError::AmountExceedsPerTxCap {
                amount: req.amount,
                per_tx_cap: entry.delegation.per_tx_cap,
            });
        }
        let remaining = entry
            .delegation
            .total_spend_cap
            .checked_sub(entry.spent_total)
            .ok_or(AccountAbstractionError::ArithmeticOverflow)?;
        if req.amount > remaining {
            return Err(AccountAbstractionError::AmountExceedsRemainingCap {
                amount: req.amount,
                remaining,
            });
        }
        if entry.used_nonces.contains(&req.spend_nonce) {
            return Err(AccountAbstractionError::SessionSpendReplay);
        }
        if entry.used_nonces.len() >= MAX_SESSION_NONCES {
            return Err(AccountAbstractionError::RegistryCapacityExceeded);
        }

        let digest = session_spend_digest(
            &req.delegation_id,
            req.chain_id,
            &req.recipient,
            req.amount,
            req.spend_nonce,
        );
        match &entry.delegation.session_key {
            SessionKeyPosture::PostQuantumComposite { composite_pubkey } => {
                let pk = CompositePublicKey::decode(composite_pubkey)
                    .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?;
                let sig = CompositeSignature::decode(session_signature)
                    .map_err(|_| AccountAbstractionError::InvalidCompositeSignature)?;
                if composite::verify(&pk, SESSION_SPEND_DOMAIN_TAG, &digest, &sig).is_err() {
                    return Err(AccountAbstractionError::InvalidCompositeSignature);
                }
            }
            SessionKeyPosture::HardwareClassicalCapped { evm_address } => {
                let recovered = recover_address(&digest, session_signature)
                    .map_err(|_| AccountAbstractionError::InvalidClassicalSignature)?;
                if &recovered != evm_address {
                    return Err(AccountAbstractionError::InvalidClassicalSignature);
                }
            }
        }

        let new_spent = entry
            .spent_total
            .checked_add(req.amount)
            .ok_or(AccountAbstractionError::ArithmeticOverflow)?;
        let next_remaining = entry
            .delegation
            .total_spend_cap
            .checked_sub(new_spent)
            .ok_or(AccountAbstractionError::ArithmeticOverflow)?;
        entry.spent_total = new_spent;
        entry.used_nonces.insert(req.spend_nonce);
        Ok(next_remaining)
    }
}

// ---------------------------------------------------------------------------
// 3. Timelocked, owner-cancellable social recovery (zero admin backdoors)
// ---------------------------------------------------------------------------

/// Policy governing guardian-initiated, owner-cancellable key recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocialRecoveryPolicy {
    pub chain_id: u64,
    pub current_owner_pubkey: Vec<u8>,
    pub guardians: Vec<Vec<u8>>,
    pub threshold: usize,
    /// Mandatory non-zero timelock delay (in epochs) during which the current
    /// owner may cancel any recovery attempt.
    pub delay_epochs: u64,
}

impl SocialRecoveryPolicy {
    /// Validate guardian set (`1 <= threshold <= guardians.len() <= MAX_GUARDIANS`),
    /// owner exclusion from guardians, unique decodable guardian keys, and
    /// non-zero timelock delay.
    ///
    /// Convenience: exposed for wallet setup validation.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if any invariant fails.
    pub fn validate(&self) -> Result<(), AccountAbstractionError> {
        if self.delay_epochs == 0 {
            return Err(AccountAbstractionError::ZeroDelayWindow);
        }
        if self.guardians.len() > MAX_GUARDIANS {
            return Err(AccountAbstractionError::InvalidGuardianPolicy);
        }
        if self.threshold == 0 || self.threshold > self.guardians.len() {
            return Err(AccountAbstractionError::InvalidGuardianPolicy);
        }
        CompositePublicKey::decode(&self.current_owner_pubkey)
            .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?;
        let mut seen = BTreeSet::new();
        for g in &self.guardians {
            if g == &self.current_owner_pubkey {
                return Err(AccountAbstractionError::OwnerCannotBeGuardian);
            }
            CompositePublicKey::decode(g)
                .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?;
            if !seen.insert(g.clone()) {
                return Err(AccountAbstractionError::InvalidGuardianPolicy);
            }
        }
        Ok(())
    }
}

/// Guardian signature approving rotation to `proposed_new_owner_pubkey`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianRecoveryApproval {
    pub guardian_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Canonical digest signed by guardians to approve a recovery proposal.
///
/// Convenience: exposed for guardian recovery clients.
#[must_use]
pub fn recovery_approval_digest(
    chain_id: u64,
    current_owner_pubkey: &[u8],
    proposed_new_owner_pubkey: &[u8],
    recovery_nonce: u64,
) -> Hash32 {
    let chain = chain_id.to_be_bytes();
    let nonce = recovery_nonce.to_be_bytes();
    hash_domain_fields(
        HASH_TAG_RECOVERY_APPROVAL,
        &[
            &chain,
            current_owner_pubkey,
            proposed_new_owner_pubkey,
            &nonce,
        ],
    )
}

/// Canonical digest signed by the current owner to cancel a pending recovery.
///
/// Convenience: exposed for owner veto flows.
#[must_use]
pub fn recovery_cancel_digest(recovery_id: &Hash32, chain_id: u64) -> Hash32 {
    let chain = chain_id.to_be_bytes();
    hash_domain_fields(HASH_TAG_RECOVERY_CANCEL, &[recovery_id, &chain])
}

/// Pending or resolved timelocked recovery entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelockedRecoveryState {
    pub recovery_id: Hash32,
    pub policy: SocialRecoveryPolicy,
    pub proposed_new_owner_pubkey: Vec<u8>,
    pub initiated_epoch: u64,
    pub executable_epoch: u64,
    pub cancelled: bool,
    pub finalized: bool,
}

/// Registry enforcing guardian threshold, mandatory timelock delay, owner
/// cancellation inside the window, and zero-admin finalization.
///
/// Convenience: exposed for account-abstraction recovery controllers.
#[derive(Debug, Clone, Default)]
pub struct TimelockedRecoveryRegistry {
    proposals: BTreeMap<Hash32, TimelockedRecoveryState>,
}

impl TimelockedRecoveryRegistry {
    /// Initiate a timelocked recovery after verifying `m-of-n` distinct
    /// post-quantum guardian approvals, owner separation, key novelty, and
    /// checked timelock arithmetic.
    ///
    /// Convenience: exposed for guardian-quorum key recovery.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if policy, new owner key, guardian
    /// membership, uniqueness, signatures, threshold, duplicate recovery,
    /// capacity, or epoch addition fail.
    pub fn initiate(
        &mut self,
        policy: SocialRecoveryPolicy,
        proposed_new_owner_pubkey: Vec<u8>,
        recovery_nonce: u64,
        approvals: &[GuardianRecoveryApproval],
        current_epoch: u64,
    ) -> Result<Hash32, AccountAbstractionError> {
        policy.validate()?;
        if proposed_new_owner_pubkey == policy.current_owner_pubkey {
            return Err(AccountAbstractionError::UnchangedOwnerKey);
        }
        CompositePublicKey::decode(&proposed_new_owner_pubkey)
            .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?;
        let digest = recovery_approval_digest(
            policy.chain_id,
            &policy.current_owner_pubkey,
            &proposed_new_owner_pubkey,
            recovery_nonce,
        );
        if self.proposals.contains_key(&digest) {
            return Err(AccountAbstractionError::DuplicateRecovery);
        }
        if self.proposals.len() >= MAX_RECOVERY_PROPOSALS {
            return Err(AccountAbstractionError::RegistryCapacityExceeded);
        }
        let mut seen_guardians = BTreeSet::new();
        let mut valid_count = 0usize;
        for approval in approvals {
            if !policy.guardians.contains(&approval.guardian_pubkey) {
                return Err(AccountAbstractionError::UnknownGuardian);
            }
            if !seen_guardians.insert(approval.guardian_pubkey.clone()) {
                return Err(AccountAbstractionError::DuplicateGuardianApproval);
            }
            let pk = CompositePublicKey::decode(&approval.guardian_pubkey)
                .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?;
            let sig = CompositeSignature::decode(&approval.signature)
                .map_err(|_| AccountAbstractionError::InvalidCompositeSignature)?;
            if composite::verify(&pk, RECOVERY_APPROVAL_DOMAIN_TAG, &digest, &sig).is_err() {
                return Err(AccountAbstractionError::InvalidCompositeSignature);
            }
            valid_count = valid_count.saturating_add(1);
        }
        if valid_count < policy.threshold {
            return Err(AccountAbstractionError::InsufficientGuardianApprovals {
                have: valid_count,
                required: policy.threshold,
            });
        }
        let executable_epoch = current_epoch
            .checked_add(policy.delay_epochs)
            .ok_or(AccountAbstractionError::ArithmeticOverflow)?;
        self.proposals.insert(
            digest,
            TimelockedRecoveryState {
                recovery_id: digest,
                policy,
                proposed_new_owner_pubkey,
                initiated_epoch: current_epoch,
                executable_epoch,
                cancelled: false,
                finalized: false,
            },
        );
        Ok(digest)
    }

    /// Cancel a pending recovery inside its timelock window using a valid
    /// post-quantum signature from the current owner.
    ///
    /// Convenience: exposed for owner anti-takeover veto.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if unknown, already cancelled,
    /// already finalized, or owner signature is invalid.
    pub fn cancel_by_owner(
        &mut self,
        recovery_id: &Hash32,
        owner_signature: &[u8],
    ) -> Result<(), AccountAbstractionError> {
        let state = self
            .proposals
            .get_mut(recovery_id)
            .ok_or(AccountAbstractionError::RecoveryNotFound)?;
        if state.cancelled {
            return Err(AccountAbstractionError::RecoveryCancelled);
        }
        if state.finalized {
            return Err(AccountAbstractionError::RecoveryAlreadyFinalized);
        }
        let pk = CompositePublicKey::decode(&state.policy.current_owner_pubkey)
            .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?;
        let sig = CompositeSignature::decode(owner_signature)
            .map_err(|_| AccountAbstractionError::InvalidCompositeSignature)?;
        let digest = recovery_cancel_digest(recovery_id, state.policy.chain_id);
        if composite::verify(&pk, RECOVERY_CANCEL_DOMAIN_TAG, &digest, &sig).is_err() {
            return Err(AccountAbstractionError::InvalidCompositeSignature);
        }
        state.cancelled = true;
        Ok(())
    }

    /// Finalize an uncancelled recovery once `current_epoch >= executable_epoch`,
    /// returning the newly active owner public key bytes.
    ///
    /// Convenience: exposed for post-timelock key rotation activation.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if unknown, cancelled, already
    /// finalized, or timelock window is still open.
    pub fn finalize(
        &mut self,
        recovery_id: &Hash32,
        current_epoch: u64,
    ) -> Result<Vec<u8>, AccountAbstractionError> {
        let state = self
            .proposals
            .get_mut(recovery_id)
            .ok_or(AccountAbstractionError::RecoveryNotFound)?;
        if state.cancelled {
            return Err(AccountAbstractionError::RecoveryCancelled);
        }
        if state.finalized {
            return Err(AccountAbstractionError::RecoveryAlreadyFinalized);
        }
        if current_epoch < state.executable_epoch {
            return Err(AccountAbstractionError::RecoveryWindowStillOpen {
                current_epoch,
                executable_epoch: state.executable_epoch,
            });
        }
        state.finalized = true;
        Ok(state.proposed_new_owner_pubkey.clone())
    }
}
