//! Fee sponsorship, bounded session-key delegation (including hardware-capped
//! classical session keys under a cold post-quantum master key), and timelocked
//! owner-cancellable social recovery with zero admin backdoors.
//!
//! Convenience: exposed for account-abstraction wallets, gasless payment flows,
//! hardware companion keys, and governance-free key recovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::address::Address;
use crate::core::types::Hash32;
use crate::crypto::composite::{self, CompositeKeypair, CompositePublicKey, CompositeSignature};
use crate::crypto::secp256k1_recover::recover_address;
use crate::crypto::tx_hash::hash_domain;
use serde::{Deserialize, Serialize};

/// Domain tag for single-transaction fee sponsorship authorizations.
pub const FEE_SPONSOR_DOMAIN_TAG: &[u8] = b"BDLM_FEE_SPONSOR_V1";
/// Domain tag for master-key-signed session key delegations.
pub const SESSION_DELEGATION_DOMAIN_TAG: &[u8] = b"BDLM_SESSION_DELEGATION_V1";
/// Domain tag for session-key spend authorizations.
pub const SESSION_SPEND_DOMAIN_TAG: &[u8] = b"BDLM_SESSION_SPEND_V1";
/// Domain tag for guardian recovery approvals.
pub const RECOVERY_APPROVAL_DOMAIN_TAG: &[u8] = b"BDLM_RECOVERY_APPROVAL_V1";
/// Domain tag for owner veto/cancellation of a pending recovery.
pub const RECOVERY_CANCEL_DOMAIN_TAG: &[u8] = b"BDLM_RECOVERY_CANCEL_V1";

/// Hard upper cap (in smallest BUD base units) on a classical hardware session
/// key's cumulative spend so that a compromised classical enclave can never
/// drain a post-quantum master account beyond a tightly bounded allowance.
pub const MAX_CLASSICAL_HARDWARE_SESSION_CAP: u128 = 10_000_000_000;

/// Errors raised by fee sponsorship, session delegation, or timelocked recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountAbstractionError {
    ZeroMaxFee,
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
    InvalidCompositeKey,
    InvalidCompositeSignature,
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
    RecipientNotAllowed,
    AmountExceedsPerTxCap {
        amount: u128,
        per_tx_cap: u128,
    },
    AmountExceedsRemainingCap {
        amount: u128,
        remaining: u128,
    },
    SessionSpendReplay,
    InvalidGuardianPolicy,
    ZeroDelayWindow,
    DuplicateGuardianApproval,
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
/// The sponsor's signature binds `tx_hash`, `chain_id`, `sender`, `max_fee_bud`,
/// `expiry_epoch`, and `sponsor_nonce`, so a sponsorship grant can never be
/// transplanted onto another transaction or replayed across chains.
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
    /// Convenience: exposed for wallets, solvers, and paymaster signers.
    #[must_use]
    pub fn signing_digest(terms: &FeeSponsorTerms) -> Hash32 {
        let mut buf = Vec::with_capacity(8 + 32 + 32 + 16 + 8 + 8);
        buf.extend_from_slice(&terms.chain_id.to_be_bytes());
        buf.extend_from_slice(&terms.tx_hash);
        buf.extend_from_slice(terms.sender.as_bytes());
        buf.extend_from_slice(&terms.max_fee_bud.to_be_bytes());
        buf.extend_from_slice(&terms.expiry_epoch.to_be_bytes());
        buf.extend_from_slice(&terms.sponsor_nonce.to_be_bytes());
        hash_domain(FEE_SPONSOR_DOMAIN_TAG, &buf)
    }

    /// Create and sign a fee sponsorship grant using a post-quantum hybrid
    /// [`CompositeKeypair`].
    ///
    /// Convenience: exposed for gasless payment sponsors and solvers.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError::ZeroMaxFee`] if `max_fee_bud == 0`.
    pub fn sign(
        sponsor_kp: &CompositeKeypair,
        terms: FeeSponsorTerms,
        rnd: &[u8; 32],
    ) -> Result<Self, AccountAbstractionError> {
        if terms.max_fee_bud == 0 {
            return Err(AccountAbstractionError::ZeroMaxFee);
        }
        let digest = Self::signing_digest(&terms);
        let sponsor_pubkey = sponsor_kp
            .public_key()
            .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?
            .encode();
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
    /// Returns [`AccountAbstractionError`] if any binding, expiry, fee bound,
    /// or post-quantum composite signature check fails.
    pub fn verify(
        &self,
        expected_chain_id: u64,
        expected_tx_hash: &Hash32,
        actual_fee_bud: u128,
        current_epoch: u64,
    ) -> Result<Hash32, AccountAbstractionError> {
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
        let digest = Self::signing_digest(&terms);
        if composite::verify(&pk, FEE_SPONSOR_DOMAIN_TAG, &digest, &sig).is_err() {
            return Err(AccountAbstractionError::InvalidCompositeSignature);
        }
        Ok(digest)
    }
}

/// Single-use replay-protection registry for consumed fee sponsor grants.
///
/// Convenience: exposed for gasless execution coordinators.
#[derive(Debug, Clone, Default)]
pub struct FeeSponsorRegistry {
    consumed_grants: BTreeSet<Hash32>,
}

impl FeeSponsorRegistry {
    /// Verify and atomically consume a fee sponsor grant for one transaction.
    ///
    /// Convenience: exposed for gasless fee debit settlement.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if verification fails or the grant
    /// has already been consumed.
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
        if !self.consumed_grants.insert(grant_id) {
            return Err(AccountAbstractionError::SponsorAuthorizationAlreadyConsumed);
        }
        Ok(grant_id)
    }

    /// Returns true if `grant_id` has already been consumed.
    ///
    /// Convenience: exposed for status queries and tests.
    #[must_use]
    pub fn is_consumed(&self, grant_id: &Hash32) -> bool {
        self.consumed_grants.contains(grant_id)
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
    /// Empty means any recipient is allowed; non-empty restricts spends strictly
    /// to listed addresses.
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
        let mut buf = Vec::new();
        buf.extend_from_slice(&params.chain_id.to_be_bytes());
        buf.extend_from_slice(&(master_pubkey.len() as u64).to_be_bytes());
        buf.extend_from_slice(master_pubkey);
        match &params.session_key {
            SessionKeyPosture::PostQuantumComposite { composite_pubkey } => {
                buf.push(0x01);
                buf.extend_from_slice(&(composite_pubkey.len() as u64).to_be_bytes());
                buf.extend_from_slice(composite_pubkey);
            }
            SessionKeyPosture::HardwareClassicalCapped { evm_address } => {
                buf.push(0x02);
                buf.extend_from_slice(evm_address);
            }
        }
        buf.extend_from_slice(&params.total_spend_cap.to_be_bytes());
        buf.extend_from_slice(&params.per_tx_cap.to_be_bytes());
        buf.extend_from_slice(&(params.allowed_recipients.len() as u64).to_be_bytes());
        for recipient in &params.allowed_recipients {
            buf.extend_from_slice(recipient.as_bytes());
        }
        buf.extend_from_slice(&params.not_before_epoch.to_be_bytes());
        buf.extend_from_slice(&params.expiry_epoch.to_be_bytes());
        buf.extend_from_slice(&params.delegation_nonce.to_be_bytes());
        hash_domain(SESSION_DELEGATION_DOMAIN_TAG, &buf)
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
    /// Returns [`AccountAbstractionError`] if caps or epoch windows are invalid.
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
    /// Returns [`AccountAbstractionError`] if bounds, chain ID, or master
    /// signature fail.
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
    if let SessionKeyPosture::HardwareClassicalCapped { .. } = params.session_key {
        if params.total_spend_cap > MAX_CLASSICAL_HARDWARE_SESSION_CAP {
            return Err(AccountAbstractionError::ClassicalHardwareCapExceeded {
                requested: params.total_spend_cap,
                max: MAX_CLASSICAL_HARDWARE_SESSION_CAP,
            });
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
    let mut buf = Vec::with_capacity(32 + 8 + 32 + 16 + 8);
    buf.extend_from_slice(delegation_id);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(recipient.as_bytes());
    buf.extend_from_slice(&amount.to_be_bytes());
    buf.extend_from_slice(&spend_nonce.to_be_bytes());
    hash_domain(SESSION_SPEND_DOMAIN_TAG, &buf)
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

/// Stateful registry enforcing session caps, allowlists, expiry, revocation,
/// and per-spend replay protection.
///
/// Convenience: exposed for execution engines and wallet policy simulators.
#[derive(Debug, Clone, Default)]
pub struct SessionDelegationRegistry {
    sessions: BTreeMap<Hash32, SessionState>,
}

impl SessionDelegationRegistry {
    /// Register a verified master-signed session delegation.
    ///
    /// Convenience: exposed for session onboarding.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if verification fails.
    pub fn register(
        &mut self,
        delegation: SessionDelegation,
        expected_chain_id: u64,
    ) -> Result<Hash32, AccountAbstractionError> {
        let id = delegation.verify(expected_chain_id)?;
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

    /// Immediately revoke a session delegation.
    ///
    /// Convenience: exposed for lost-device revocation.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError::SessionNotFound`] if unknown.
    pub fn revoke(&mut self, delegation_id: &Hash32) -> Result<(), AccountAbstractionError> {
        let entry = self
            .sessions
            .get_mut(delegation_id)
            .ok_or(AccountAbstractionError::SessionNotFound)?;
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
            .saturating_sub(entry.spent_total);
        if req.amount > remaining {
            return Err(AccountAbstractionError::AmountExceedsRemainingCap {
                amount: req.amount,
                remaining,
            });
        }
        if entry.used_nonces.contains(&req.spend_nonce) {
            return Err(AccountAbstractionError::SessionSpendReplay);
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

        entry.spent_total = entry.spent_total.saturating_add(req.amount);
        entry.used_nonces.insert(req.spend_nonce);
        Ok(entry
            .delegation
            .total_spend_cap
            .saturating_sub(entry.spent_total))
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
    /// Validate guardian set, threshold (`1 <= threshold <= guardians.len()`),
    /// unique guardians, and non-zero timelock delay.
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
        if self.threshold == 0 || self.threshold > self.guardians.len() {
            return Err(AccountAbstractionError::InvalidGuardianPolicy);
        }
        CompositePublicKey::decode(&self.current_owner_pubkey)
            .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?;
        let mut seen = BTreeSet::new();
        for g in &self.guardians {
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
    let mut buf = Vec::new();
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&(current_owner_pubkey.len() as u64).to_be_bytes());
    buf.extend_from_slice(current_owner_pubkey);
    buf.extend_from_slice(&(proposed_new_owner_pubkey.len() as u64).to_be_bytes());
    buf.extend_from_slice(proposed_new_owner_pubkey);
    buf.extend_from_slice(&recovery_nonce.to_be_bytes());
    hash_domain(RECOVERY_APPROVAL_DOMAIN_TAG, &buf)
}

/// Canonical digest signed by the current owner to cancel a pending recovery.
///
/// Convenience: exposed for owner veto flows.
#[must_use]
pub fn recovery_cancel_digest(recovery_id: &Hash32, chain_id: u64) -> Hash32 {
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(recovery_id);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    hash_domain(RECOVERY_CANCEL_DOMAIN_TAG, &buf)
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
    /// post-quantum guardian approvals.
    ///
    /// Convenience: exposed for guardian-quorum key recovery.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAbstractionError`] if policy, new owner key, guardian
    /// membership, uniqueness, signatures, or threshold checks fail.
    pub fn initiate(
        &mut self,
        policy: SocialRecoveryPolicy,
        proposed_new_owner_pubkey: Vec<u8>,
        recovery_nonce: u64,
        approvals: &[GuardianRecoveryApproval],
        current_epoch: u64,
    ) -> Result<Hash32, AccountAbstractionError> {
        policy.validate()?;
        CompositePublicKey::decode(&proposed_new_owner_pubkey)
            .map_err(|_| AccountAbstractionError::InvalidCompositeKey)?;
        let digest = recovery_approval_digest(
            policy.chain_id,
            &policy.current_owner_pubkey,
            &proposed_new_owner_pubkey,
            recovery_nonce,
        );
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
        let executable_epoch = current_epoch.saturating_add(policy.delay_epochs);
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
    /// Returns [`AccountAbstractionError`] if unknown, already finalized, or
    /// owner signature is invalid.
    pub fn cancel_by_owner(
        &mut self,
        recovery_id: &Hash32,
        owner_signature: &[u8],
    ) -> Result<(), AccountAbstractionError> {
        let state = self
            .proposals
            .get_mut(recovery_id)
            .ok_or(AccountAbstractionError::RecoveryNotFound)?;
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
