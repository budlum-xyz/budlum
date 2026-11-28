//! Protocol-native `EIP-8141` Frame Transactions (`FrameTx`), eliminating
//! off-chain ERC-4337 bundler/relayer monopolies and enabling wallet-native
//! PQ verification, bounded session keys, guardian timelock recovery, and
//! explicit gas sponsorship inside public mempool blocks.
//!
//! WIRING: wired through `TransactionType::FrameTx` in `src/core/transaction.rs`,
//! `src/execution/executor.rs`, `src/core/account.rs`, and `src/chain/snapshot.rs`.
//!
//! Security invariants:
//! 1. **Explicit frame separation**: `Verify`, optional `SponsorApprove`, then `Sender`/`Default`
//!    execution frames. No sender frame may run before `Verify` confirms authority.
//! 2. **Cryptographic PQ authentication**:
//!    - `RootOwner` binds strictly to `policy.controller` (never stale `tx.sender` post-recovery).
//!    - `SessionKey` verifies an `ML-DSA-65` signature over all execution frames, sender, chain, nonce, and `max_fee`.
//!    - `GuardianQuorum` verifies distinct `ML-DSA-87` guardian signatures bound to `(sender, new_owner, chain_id, nonce)`.
//!    - `SponsorApprove` verifies an `ML-DSA-87` sponsor signature derived to `sponsor` (unless `sponsor == outer_signer`).
//! 3. **Bounded session keys**: session authorizations enforce per-tx limit, per-epoch cap
//!    (including unsponsored gas), strict expiry block height, and allowlisted targets.
//! 4. **Ordered deterministic consensus state**: all storage uses `BTreeMap`/`BTreeSet` with
//!    zero floating point math and explicit checked integer arithmetic.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::core::address::Address;
use crate::crypto::ctx::{GUARDIAN_V1, TX_V7};
use crate::crypto::pq;
use crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key;
use crate::crypto::scheme::SchemeId;

/// Domain tag binding frame-transaction authorization hashes.
pub const DOMAIN_FRAME_TX_AUTH: &[u8] = b"BDLM_FRAME_TX_AUTH_V1";

/// Maximum frames allowed in one EIP-8141 transaction.
pub const MAX_FRAMES_PER_TX: usize = 8;

/// Maximum target addresses allowed per bounded session key grant.
pub const MAX_SESSION_TARGETS: usize = 32;

/// Maximum guardian addresses per account recovery policy.
pub const MAX_GUARDIANS_PER_ACCOUNT: usize = 16;

fn update_lp(h: &mut Sha3_256, bytes: &[u8]) {
    h.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    h.update(bytes);
}

/// Role of an individual execution frame in an `EIP-8141` transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FrameKind {
    /// Verifies caller authority (owner PQ signature, bounded session key, or recovery).
    Verify,
    /// Authorizes an explicit fee sponsor to fund transaction execution gas.
    SponsorApprove,
    /// Executes privileged mutations under the verified `sender` identity.
    Sender,
    /// Standard unprivileged call / value action executed after verification.
    Default,
}

/// Detached `ML-DSA-87` sponsor consent signature carried by a [`FrameKind::SponsorApprove`] frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameSponsorAuth {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Individual guardian's `ML-DSA-87` approval over a recovery proposal digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianApproval {
    pub guardian: Address,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Authority proof carried inside a [`FrameKind::Verify`] frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameAuthorityProof {
    /// Root controller of the frame-enabled account (`outer_signer == policy.controller`).
    RootOwner,
    /// Pre-registered bounded session key proving possession via `ML-DSA-65` signature.
    SessionKey {
        session_id: [u8; 32],
        signer_pk: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Cryptographically signed guardian quorum authorization triggering or completing recovery.
    GuardianQuorum {
        approvals: Vec<GuardianApproval>,
        new_owner: Address,
    },
}

/// Concrete state transition requested inside a `Sender` or `Default` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameAction {
    /// Native value transfer from `sender` to `to`.
    Transfer { to: Address, amount: u64 },
    /// Register or initialize a frame-AA policy for `sender` with optional guardians.
    RegisterPolicy {
        guardians: Vec<Address>,
        threshold: u32,
        timelock_blocks: u64,
    },
    /// Grant a bounded session key (root owner only).
    GrantSessionKey(SessionKeyGrant),
    /// Revoke an active session key immediately (root owner only).
    RevokeSessionKey { session_id: [u8; 32] },
    /// Queue a timelocked owner-key replacement backed by `>= threshold` guardians.
    ProposeGuardianRecovery {
        new_owner: Address,
        approvers: Vec<Address>,
    },
    /// Complete an elapsed timelocked recovery, rotating the account's controlling owner.
    FinalizeGuardianRecovery,
}

/// One frame in an `EIP-8141` [`FrameTransaction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionFrame {
    pub kind: FrameKind,
    pub target: Address,
    pub gas_limit: u64,
    pub authority: Option<FrameAuthorityProof>,
    pub sponsor_digest: Option<[u8; 32]>,
    pub sponsor_auth: Option<FrameSponsorAuth>,
    pub action: Option<FrameAction>,
}

/// Top-level relayer-free `EIP-8141` Frame Transaction payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameTransaction {
    pub sender: Address,
    pub sponsor: Option<Address>,
    pub chain_id: u64,
    pub nonce: u64,
    pub max_fee: u64,
    pub frames: Vec<ExecutionFrame>,
}

/// On-chain bounded session-key grant attached to an account's [`FrameAccountPolicy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKeyGrant {
    pub session_id: [u8; 32],
    pub signer_key_hash: [u8; 32],
    pub max_per_tx: u64,
    pub epoch_cap: u64,
    pub spent_in_epoch: u64,
    pub last_epoch: u64,
    pub expiry_height: u64,
    pub allowed_targets: BTreeSet<Address>,
    pub active: bool,
}

/// Timelocked guardian recovery state stored in consensus state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRecovery {
    pub proposed_owner: Address,
    pub executable_at_height: u64,
    pub approvers: BTreeSet<Address>,
}

/// Per-account native AA policy persisted in [`crate::core::account::AccountState::frame_policies`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameAccountPolicy {
    pub controller: Address,
    pub frame_nonce: u64,
    pub guardians: BTreeSet<Address>,
    pub guardian_threshold: u32,
    pub timelock_blocks: u64,
    #[serde(with = "crate::core::map_keys")]
    pub session_keys: BTreeMap<[u8; 32], SessionKeyGrant>,
    pub pending_recovery: Option<PendingRecovery>,
}

/// Consensus registry holding native `EIP-8141` account abstraction policies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameRegistry {
    pub policies: BTreeMap<Address, FrameAccountPolicy>,
}

impl FrameRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            policies: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Deterministic SHA3-256 commitment root folded into `AccountState::state_root_body`.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        if self.policies.is_empty() {
            return [0u8; 32];
        }
        let mut h = Sha3_256::new();
        update_lp(&mut h, b"BDLM_FRAME_REGISTRY_V1");
        h.update(
            u64::try_from(self.policies.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        for (addr, pol) in &self.policies {
            h.update(addr.0);
            h.update(pol.controller.0);
            h.update(pol.frame_nonce.to_le_bytes());
            h.update(pol.guardian_threshold.to_le_bytes());
            h.update(pol.timelock_blocks.to_le_bytes());
            h.update(
                u64::try_from(pol.guardians.len())
                    .unwrap_or(u64::MAX)
                    .to_le_bytes(),
            );
            for g in &pol.guardians {
                h.update(g.0);
            }
            h.update(
                u64::try_from(pol.session_keys.len())
                    .unwrap_or(u64::MAX)
                    .to_le_bytes(),
            );
            for (sid, sk) in &pol.session_keys {
                h.update(sid);
                h.update(sk.signer_key_hash);
                h.update(sk.max_per_tx.to_le_bytes());
                h.update(sk.epoch_cap.to_le_bytes());
                h.update(sk.spent_in_epoch.to_le_bytes());
                h.update(sk.last_epoch.to_le_bytes());
                h.update(sk.expiry_height.to_le_bytes());
                h.update(
                    u64::try_from(sk.allowed_targets.len())
                        .unwrap_or(u64::MAX)
                        .to_le_bytes(),
                );
                for tgt in &sk.allowed_targets {
                    h.update(tgt.0);
                }
                h.update([u8::from(sk.active)]);
            }
            if let Some(rec) = &pol.pending_recovery {
                h.update([1]);
                h.update(rec.proposed_owner.0);
                h.update(rec.executable_at_height.to_le_bytes());
                h.update(
                    u64::try_from(rec.approvers.len())
                        .unwrap_or(u64::MAX)
                        .to_le_bytes(),
                );
                for app in &rec.approvers {
                    h.update(app.0);
                }
            } else {
                h.update([0]);
            }
        }
        h.finalize().into()
    }
}

/// Deterministic error returned on malformed or unauthorized frame transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameTxError {
    EmptyFrames,
    TooManyFrames { got: usize, max: usize },
    MissingVerifyFrame,
    InvalidFrameOrder(&'static str),
    InvalidAuthority(&'static str),
    SponsorNotApproved,
    NonceMismatch { expected: u64, got: u64 },
    ChainIdMismatch { expected: u64, got: u64 },
    SessionDenied(&'static str),
    GuardianDenied(&'static str),
    InsufficientBalance { needed: u64, available: u64 },
    Overflow(&'static str),
}

impl std::fmt::Display for FrameTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyFrames => write!(f, "frame transaction contains no frames"),
            Self::TooManyFrames { got, max } => {
                write!(f, "frame transaction has {got} frames (max {max})")
            }
            Self::MissingVerifyFrame => write!(f, "frame transaction requires a Verify frame"),
            Self::InvalidFrameOrder(m) => write!(f, "invalid frame order: {m}"),
            Self::InvalidAuthority(m) => write!(f, "invalid frame authority: {m}"),
            Self::SponsorNotApproved => write!(f, "fee sponsor approval frame missing or invalid"),
            Self::NonceMismatch { expected, got } => {
                write!(f, "frame nonce mismatch: expected {expected}, got {got}")
            }
            Self::ChainIdMismatch { expected, got } => {
                write!(f, "frame chain_id mismatch: expected {expected}, got {got}")
            }
            Self::SessionDenied(m) => write!(f, "session key denied: {m}"),
            Self::GuardianDenied(m) => write!(f, "guardian recovery denied: {m}"),
            Self::InsufficientBalance { needed, available } => {
                write!(f, "insufficient balance: need {needed}, have {available}")
            }
            Self::Overflow(m) => write!(f, "arithmetic overflow: {m}"),
        }
    }
}

impl std::error::Error for FrameTxError {}

/// Canonical digest of an `ML-DSA-65` session public key stored in [`SessionKeyGrant::signer_key_hash`].
#[must_use]
pub fn session_key_pk_hash(signer_pk: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    update_lp(&mut h, DOMAIN_FRAME_TX_AUTH);
    update_lp(&mut h, b"SESSION_PK");
    update_lp(&mut h, signer_pk);
    h.finalize().into()
}

/// Deterministic signing digest that a sponsor's `ML-DSA-87` key signs inside `SponsorApprove`.
#[must_use]
pub fn sponsor_approval_digest(
    sender: &Address,
    sponsor: &Address,
    chain_id: u64,
    nonce: u64,
    max_fee: u64,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    update_lp(&mut h, DOMAIN_FRAME_TX_AUTH);
    update_lp(&mut h, b"SPONSOR");
    h.update(sender.0);
    h.update(sponsor.0);
    h.update(chain_id.to_le_bytes());
    h.update(nonce.to_le_bytes());
    h.update(max_fee.to_le_bytes());
    h.finalize().into()
}

/// Deterministic signing digest that each guardian's `ML-DSA-87` key signs for recovery.
#[must_use]
pub fn guardian_recovery_digest(
    sender: &Address,
    new_owner: &Address,
    chain_id: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    update_lp(&mut h, DOMAIN_FRAME_TX_AUTH);
    update_lp(&mut h, b"GUARDIAN");
    h.update(sender.0);
    h.update(new_owner.0);
    h.update(chain_id.to_le_bytes());
    h.update(nonce.to_le_bytes());
    h.finalize().into()
}

/// Deterministic signing digest that an `ML-DSA-65` session key signs to authorize execution frames.
#[must_use]
pub fn session_exec_digest(
    sender: &Address,
    chain_id: u64,
    nonce: u64,
    max_fee: u64,
    session_id: &[u8; 32],
    frames: &[ExecutionFrame],
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    update_lp(&mut h, DOMAIN_FRAME_TX_AUTH);
    update_lp(&mut h, b"SESSION_EXEC");
    h.update(sender.0);
    h.update(chain_id.to_le_bytes());
    h.update(nonce.to_le_bytes());
    h.update(max_fee.to_le_bytes());
    h.update(session_id);
    let exec_frames: Vec<&ExecutionFrame> = frames
        .iter()
        .filter(|f| matches!(f.kind, FrameKind::Sender | FrameKind::Default))
        .collect();
    h.update(
        u64::try_from(exec_frames.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for frame in exec_frames {
        h.update([match frame.kind {
            FrameKind::Verify => 0,
            FrameKind::SponsorApprove => 1,
            FrameKind::Sender => 2,
            FrameKind::Default => 3,
        }]);
        h.update(frame.target.0);
        h.update(frame.gas_limit.to_le_bytes());
        match &frame.action {
            None => h.update([0]),
            Some(FrameAction::Transfer { to, amount }) => {
                h.update([1]);
                h.update(to.0);
                h.update(amount.to_le_bytes());
            }
            Some(FrameAction::RegisterPolicy {
                guardians,
                threshold,
                timelock_blocks,
            }) => {
                h.update([2]);
                h.update(
                    u64::try_from(guardians.len())
                        .unwrap_or(u64::MAX)
                        .to_le_bytes(),
                );
                for g in guardians {
                    h.update(g.0);
                }
                h.update(threshold.to_le_bytes());
                h.update(timelock_blocks.to_le_bytes());
            }
            Some(FrameAction::GrantSessionKey(grant)) => {
                h.update([3]);
                h.update(grant.session_id);
                h.update(grant.signer_key_hash);
                h.update(grant.max_per_tx.to_le_bytes());
                h.update(grant.epoch_cap.to_le_bytes());
                h.update(grant.expiry_height.to_le_bytes());
                h.update(
                    u64::try_from(grant.allowed_targets.len())
                        .unwrap_or(u64::MAX)
                        .to_le_bytes(),
                );
                for tgt in &grant.allowed_targets {
                    h.update(tgt.0);
                }
                h.update([u8::from(grant.active)]);
            }
            Some(FrameAction::RevokeSessionKey { session_id }) => {
                h.update([4]);
                h.update(session_id);
            }
            Some(FrameAction::ProposeGuardianRecovery {
                new_owner,
                approvers,
            }) => {
                h.update([5]);
                h.update(new_owner.0);
                h.update(
                    u64::try_from(approvers.len())
                        .unwrap_or(u64::MAX)
                        .to_le_bytes(),
                );
                for app in approvers {
                    h.update(app.0);
                }
            }
            Some(FrameAction::FinalizeGuardianRecovery) => h.update([6]),
        }
    }
    h.finalize().into()
}

/// Summary returned after applying an `EIP-8141` [`FrameTransaction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameTxResult {
    pub fee_payer: Address,
    pub fee_paid: u64,
    pub total_transferred: u64,
    pub executed_frames: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerifiedCallerMode {
    RootOwner,
    SessionKey([u8; 32]),
    GuardianQuorum {
        new_owner: Address,
        approvers: BTreeSet<Address>,
    },
}

/// Execution context parameters passed to [`apply_frame_tx_on_ledgers`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameExecContext {
    pub chain_id: u64,
    pub height: u64,
    pub epoch: u64,
    pub actual_fee: u64,
}

/// Validate frame ordering, verify PQ authority & sponsor signatures, debit the agreed fee payer,
/// and apply all state mutations atomically on a snapshot rollback barrier.
///
/// # Errors
/// Returns [`FrameTxError`] cleanly leaving `registry` and `balances` untouched if any frame
/// fails verification, limits, or conservation invariants.
pub fn apply_frame_tx_on_ledgers(
    registry: &mut FrameRegistry,
    balances: &mut BTreeMap<Address, u64>,
    signer: &Address,
    ctx: FrameExecContext,
    tx: &FrameTransaction,
) -> Result<FrameTxResult, FrameTxError> {
    let expected_chain_id = ctx.chain_id;
    let current_height = ctx.height;
    let current_epoch = ctx.epoch;
    let actual_fee = ctx.actual_fee;
    if tx.frames.is_empty() {
        return Err(FrameTxError::EmptyFrames);
    }
    if tx.frames.len() > MAX_FRAMES_PER_TX {
        return Err(FrameTxError::TooManyFrames {
            got: tx.frames.len(),
            max: MAX_FRAMES_PER_TX,
        });
    }
    if tx.chain_id != expected_chain_id {
        return Err(FrameTxError::ChainIdMismatch {
            expected: expected_chain_id,
            got: tx.chain_id,
        });
    }
    if actual_fee > tx.max_fee {
        return Err(FrameTxError::Overflow("actual fee exceeds tx.max_fee"));
    }

    let current_policy = registry
        .policies
        .get(&tx.sender)
        .cloned()
        .unwrap_or_else(|| FrameAccountPolicy {
            controller: tx.sender,
            frame_nonce: 0,
            guardians: BTreeSet::new(),
            guardian_threshold: 0,
            timelock_blocks: 0,
            session_keys: BTreeMap::new(),
            pending_recovery: None,
        });

    if tx.nonce != current_policy.frame_nonce {
        return Err(FrameTxError::NonceMismatch {
            expected: current_policy.frame_nonce,
            got: tx.nonce,
        });
    }

    // Enforce frame ordering: Verify -> optional SponsorApprove -> Sender / Default.
    let mut verified_mode: Option<VerifiedCallerMode> = None;
    let mut sponsor_approved =
        tx.sponsor.is_none() || tx.sponsor == Some(tx.sender) || tx.sponsor == Some(*signer);
    let mut saw_execution = false;

    for frame in &tx.frames {
        match frame.kind {
            FrameKind::Verify => {
                if verified_mode.is_some() {
                    return Err(FrameTxError::InvalidFrameOrder(
                        "duplicate Verify frame not permitted",
                    ));
                }
                if saw_execution {
                    return Err(FrameTxError::InvalidFrameOrder(
                        "Verify frame cannot follow execution frames",
                    ));
                }
                let Some(auth) = &frame.authority else {
                    return Err(FrameTxError::InvalidAuthority(
                        "Verify frame missing authority proof",
                    ));
                };
                match auth {
                    FrameAuthorityProof::RootOwner => {
                        if *signer != current_policy.controller {
                            return Err(FrameTxError::InvalidAuthority(
                                "signer does not match account controller",
                            ));
                        }
                        verified_mode = Some(VerifiedCallerMode::RootOwner);
                    }
                    FrameAuthorityProof::SessionKey {
                        session_id,
                        signer_pk,
                        signature,
                    } => {
                        let sk = current_policy
                            .session_keys
                            .get(session_id)
                            .ok_or(FrameTxError::SessionDenied("unknown session key"))?;
                        if !sk.active {
                            return Err(FrameTxError::SessionDenied("session key revoked"));
                        }
                        if session_key_pk_hash(signer_pk) != sk.signer_key_hash {
                            return Err(FrameTxError::SessionDenied(
                                "session public key hash mismatch",
                            ));
                        }
                        if current_height > sk.expiry_height {
                            return Err(FrameTxError::SessionDenied("session key expired"));
                        }
                        let digest = session_exec_digest(
                            &tx.sender,
                            tx.chain_id,
                            tx.nonce,
                            tx.max_fee,
                            session_id,
                            &tx.frames,
                        );
                        pq::verify(SchemeId::ML_DSA_65, signer_pk, &digest, TX_V7, signature)
                            .map_err(|_| {
                                FrameTxError::SessionDenied(
                                    "invalid session key ML-DSA-65 signature",
                                )
                            })?;
                        verified_mode = Some(VerifiedCallerMode::SessionKey(*session_id));
                    }
                    FrameAuthorityProof::GuardianQuorum {
                        approvals,
                        new_owner,
                    } => {
                        if current_policy.guardian_threshold == 0
                            || current_policy.guardians.is_empty()
                        {
                            return Err(FrameTxError::GuardianDenied(
                                "account has no guardian recovery policy",
                            ));
                        }
                        if approvals.len() > MAX_GUARDIANS_PER_ACCOUNT {
                            return Err(FrameTxError::GuardianDenied(
                                "too many guardian approvals",
                            ));
                        }
                        let digest =
                            guardian_recovery_digest(&tx.sender, new_owner, tx.chain_id, tx.nonce);
                        let mut valid_unique = BTreeSet::new();
                        for app in approvals {
                            if !current_policy.guardians.contains(&app.guardian) {
                                return Err(FrameTxError::GuardianDenied(
                                    "signer is not a registered guardian",
                                ));
                            }
                            let Ok(derived) =
                                wallet_address_from_ml_dsa_87_public_key(&app.public_key)
                            else {
                                return Err(FrameTxError::GuardianDenied(
                                    "malformed guardian ML-DSA-87 public key",
                                ));
                            };
                            if derived != app.guardian {
                                return Err(FrameTxError::GuardianDenied(
                                    "guardian public key does not match address",
                                ));
                            }
                            pq::verify(
                                SchemeId::ML_DSA_87,
                                &app.public_key,
                                &digest,
                                GUARDIAN_V1,
                                &app.signature,
                            )
                            .map_err(|_| {
                                FrameTxError::GuardianDenied("invalid guardian ML-DSA-87 signature")
                            })?;
                            valid_unique.insert(app.guardian);
                        }
                        if u32::try_from(valid_unique.len()).unwrap_or(u32::MAX)
                            < current_policy.guardian_threshold
                        {
                            return Err(FrameTxError::GuardianDenied(
                                "insufficient unique guardian approvals",
                            ));
                        }
                        verified_mode = Some(VerifiedCallerMode::GuardianQuorum {
                            new_owner: *new_owner,
                            approvers: valid_unique,
                        });
                    }
                }
            }
            FrameKind::SponsorApprove => {
                if verified_mode.is_none() {
                    return Err(FrameTxError::InvalidFrameOrder(
                        "SponsorApprove requires prior Verify frame",
                    ));
                }
                if saw_execution {
                    return Err(FrameTxError::InvalidFrameOrder(
                        "SponsorApprove must precede execution frames",
                    ));
                }
                if let Some(sponsor_addr) = tx.sponsor {
                    if frame.target != sponsor_addr {
                        return Err(FrameTxError::SponsorNotApproved);
                    }
                    if sponsor_addr == *signer {
                        sponsor_approved = true;
                        continue;
                    }
                    let expected = sponsor_approval_digest(
                        &tx.sender,
                        &sponsor_addr,
                        tx.chain_id,
                        tx.nonce,
                        tx.max_fee,
                    );
                    if frame.sponsor_digest != Some(expected) {
                        return Err(FrameTxError::SponsorNotApproved);
                    }
                    let Some(auth) = &frame.sponsor_auth else {
                        return Err(FrameTxError::SponsorNotApproved);
                    };
                    let Ok(derived) = wallet_address_from_ml_dsa_87_public_key(&auth.public_key)
                    else {
                        return Err(FrameTxError::SponsorNotApproved);
                    };
                    if derived != sponsor_addr {
                        return Err(FrameTxError::SponsorNotApproved);
                    }
                    pq::verify(
                        SchemeId::ML_DSA_87,
                        &auth.public_key,
                        &expected,
                        TX_V7,
                        &auth.signature,
                    )
                    .map_err(|_| FrameTxError::SponsorNotApproved)?;
                    sponsor_approved = true;
                }
            }
            FrameKind::Sender | FrameKind::Default => {
                if verified_mode.is_none() {
                    return Err(FrameTxError::MissingVerifyFrame);
                }
                saw_execution = true;
            }
        }
    }

    let mode = verified_mode.ok_or(FrameTxError::MissingVerifyFrame)?;
    if !sponsor_approved {
        return Err(FrameTxError::SponsorNotApproved);
    }

    // Atomic staging copies: mutate scratch state and commit only once everything passes.
    let mut staged_registry = registry.clone();
    let mut staged_balances = balances.clone();
    let fee_payer = tx.sponsor.unwrap_or(tx.sender);

    let payer_bal = staged_balances.get(&fee_payer).copied().unwrap_or(0);
    if payer_bal < actual_fee {
        return Err(FrameTxError::InsufficientBalance {
            needed: actual_fee,
            available: payer_bal,
        });
    }
    staged_balances.insert(fee_payer, payer_bal - actual_fee);

    let policy = staged_registry
        .policies
        .entry(tx.sender)
        .or_insert(current_policy);
    policy.frame_nonce = policy
        .frame_nonce
        .checked_add(1)
        .ok_or(FrameTxError::Overflow("frame_nonce overflow"))?;

    // When a SessionKey runs unsponsored, charge actual_fee against its session limits so it
    // cannot drain the root controller's gas balance unchecked.
    if let VerifiedCallerMode::SessionKey(sid) = &mode {
        if tx.sponsor.is_none() && actual_fee > 0 {
            let sk = policy
                .session_keys
                .get_mut(sid)
                .ok_or(FrameTxError::SessionDenied("missing session key"))?;
            if actual_fee > sk.max_per_tx {
                return Err(FrameTxError::SessionDenied(
                    "unsponsored fee exceeds session max_per_tx",
                ));
            }
            if sk.last_epoch != current_epoch {
                sk.last_epoch = current_epoch;
                sk.spent_in_epoch = 0;
            }
            let next_spent = sk
                .spent_in_epoch
                .checked_add(actual_fee)
                .ok_or(FrameTxError::Overflow("session epoch spend overflow"))?;
            if next_spent > sk.epoch_cap {
                return Err(FrameTxError::SessionDenied(
                    "unsponsored fee exceeds session epoch_cap",
                ));
            }
            sk.spent_in_epoch = next_spent;
        }
    }

    let mut total_transferred: u64 = 0;
    let mut executed_frames: usize = 0;

    for frame in &tx.frames {
        if !matches!(frame.kind, FrameKind::Sender | FrameKind::Default) {
            continue;
        }
        let Some(action) = &frame.action else {
            executed_frames += 1;
            continue;
        };
        match action {
            FrameAction::Transfer { to, amount } => {
                match &mode {
                    VerifiedCallerMode::RootOwner => {}
                    VerifiedCallerMode::SessionKey(sid) => {
                        let sk = policy
                            .session_keys
                            .get_mut(sid)
                            .ok_or(FrameTxError::SessionDenied("missing session key"))?;
                        if !sk.allowed_targets.is_empty() && !sk.allowed_targets.contains(to) {
                            return Err(FrameTxError::SessionDenied(
                                "target address not allowlisted for session key",
                            ));
                        }
                        if *amount > sk.max_per_tx {
                            return Err(FrameTxError::SessionDenied(
                                "transfer exceeds session max_per_tx",
                            ));
                        }
                        if sk.last_epoch != current_epoch {
                            sk.last_epoch = current_epoch;
                            sk.spent_in_epoch = 0;
                        }
                        let next_spent = sk
                            .spent_in_epoch
                            .checked_add(*amount)
                            .ok_or(FrameTxError::Overflow("session epoch spend overflow"))?;
                        if next_spent > sk.epoch_cap {
                            return Err(FrameTxError::SessionDenied(
                                "transfer exceeds session epoch_cap",
                            ));
                        }
                        sk.spent_in_epoch = next_spent;
                    }
                    VerifiedCallerMode::GuardianQuorum { .. } => {
                        return Err(FrameTxError::InvalidAuthority(
                            "guardian quorum cannot execute asset transfers",
                        ));
                    }
                }
                let sender_bal = staged_balances.get(&tx.sender).copied().unwrap_or(0);
                if sender_bal < *amount {
                    return Err(FrameTxError::InsufficientBalance {
                        needed: *amount,
                        available: sender_bal,
                    });
                }
                let recv_bal = staged_balances.get(to).copied().unwrap_or(0);
                let next_recv = recv_bal
                    .checked_add(*amount)
                    .ok_or(FrameTxError::Overflow("recipient balance overflow"))?;
                staged_balances.insert(tx.sender, sender_bal - *amount);
                staged_balances.insert(*to, next_recv);
                total_transferred = total_transferred
                    .checked_add(*amount)
                    .ok_or(FrameTxError::Overflow("total_transferred overflow"))?;
            }
            FrameAction::RegisterPolicy {
                guardians,
                threshold,
                timelock_blocks,
            } => {
                if !matches!(mode, VerifiedCallerMode::RootOwner) {
                    return Err(FrameTxError::InvalidAuthority(
                        "only root owner may configure frame policy",
                    ));
                }
                if guardians.len() > MAX_GUARDIANS_PER_ACCOUNT {
                    return Err(FrameTxError::GuardianDenied("too many guardians"));
                }
                let gset: BTreeSet<Address> = guardians.iter().copied().collect();
                if *threshold > 0 && u32::try_from(gset.len()).unwrap_or(0) < *threshold {
                    return Err(FrameTxError::GuardianDenied(
                        "guardian threshold exceeds unique guardian count",
                    ));
                }
                policy.guardians = gset;
                policy.guardian_threshold = *threshold;
                policy.timelock_blocks = *timelock_blocks;
            }
            FrameAction::GrantSessionKey(grant) => {
                if !matches!(mode, VerifiedCallerMode::RootOwner) {
                    return Err(FrameTxError::InvalidAuthority(
                        "only root owner may grant session keys",
                    ));
                }
                if grant.allowed_targets.len() > MAX_SESSION_TARGETS {
                    return Err(FrameTxError::SessionDenied("too many allowed targets"));
                }
                policy.session_keys.insert(grant.session_id, grant.clone());
            }
            FrameAction::RevokeSessionKey { session_id } => {
                if !matches!(mode, VerifiedCallerMode::RootOwner) {
                    return Err(FrameTxError::InvalidAuthority(
                        "only root owner may revoke session keys",
                    ));
                }
                if let Some(sk) = policy.session_keys.get_mut(session_id) {
                    sk.active = false;
                }
            }
            FrameAction::ProposeGuardianRecovery {
                new_owner,
                approvers,
            } => {
                let VerifiedCallerMode::GuardianQuorum {
                    new_owner: verified_new_owner,
                    approvers: verified_approvers,
                } = &mode
                else {
                    return Err(FrameTxError::GuardianDenied(
                        "ProposeGuardianRecovery requires GuardianQuorum Verify frame",
                    ));
                };
                if new_owner != verified_new_owner {
                    return Err(FrameTxError::GuardianDenied(
                        "proposed new_owner disagrees with signed GuardianQuorum",
                    ));
                }
                let unique: BTreeSet<Address> = approvers
                    .iter()
                    .copied()
                    .filter(|g| verified_approvers.contains(g))
                    .collect();
                if u32::try_from(unique.len()).unwrap_or(0) < policy.guardian_threshold {
                    return Err(FrameTxError::GuardianDenied("guardian quorum unmet"));
                }
                let exec_at = current_height
                    .checked_add(policy.timelock_blocks)
                    .ok_or(FrameTxError::Overflow("recovery timelock overflow"))?;
                policy.pending_recovery = Some(PendingRecovery {
                    proposed_owner: *new_owner,
                    executable_at_height: exec_at,
                    approvers: unique,
                });
            }
            FrameAction::FinalizeGuardianRecovery => {
                let Some(pending) = policy.pending_recovery.clone() else {
                    return Err(FrameTxError::GuardianDenied("no pending recovery"));
                };
                match &mode {
                    VerifiedCallerMode::RootOwner => {}
                    VerifiedCallerMode::GuardianQuorum { new_owner, .. } => {
                        if *new_owner != pending.proposed_owner {
                            return Err(FrameTxError::GuardianDenied(
                                "finalization new_owner disagrees with pending recovery",
                            ));
                        }
                    }
                    VerifiedCallerMode::SessionKey(_) => {
                        return Err(FrameTxError::InvalidAuthority(
                            "session key cannot finalize guardian recovery",
                        ));
                    }
                }
                if current_height < pending.executable_at_height {
                    return Err(FrameTxError::GuardianDenied(
                        "recovery timelock has not elapsed",
                    ));
                }
                policy.controller = pending.proposed_owner;
                policy.pending_recovery = None;
                // Revoke all pre-compromise session keys on recovery completion.
                for sk in policy.session_keys.values_mut() {
                    sk.active = false;
                }
            }
        }
        executed_frames += 1;
    }

    *registry = staged_registry;
    *balances = staged_balances;
    Ok(FrameTxResult {
        fee_payer,
        fee_paid: actual_fee,
        total_transferred,
        executed_frames,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::{ml_dsa_public_key, ml_dsa_sign};

    fn ml87_keypair(seed_byte: u8) -> (Address, Vec<u8>, [u8; 32]) {
        let seed = [seed_byte; 32];
        let pk = ml_dsa_public_key(SchemeId::ML_DSA_87, &seed).unwrap();
        let addr = wallet_address_from_ml_dsa_87_public_key(&pk).unwrap();
        (addr, pk, seed)
    }

    fn ml65_keypair(seed_byte: u8) -> ([u8; 32], Vec<u8>, [u8; 32]) {
        let seed = [seed_byte; 32];
        let pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &seed).unwrap();
        let hash = session_key_pk_hash(&pk);
        (hash, pk, seed)
    }

    #[test]
    fn frame_tx_sponsored_session_key_and_guardian_recovery_lifecycle() {
        let (alice, _, _) = ml87_keypair(1);
        let (sponsor, sponsor_pk, sponsor_seed) = ml87_keypair(2);
        let (bob, _, _) = ml87_keypair(3);
        let (g1, g1_pk, g1_seed) = ml87_keypair(4);
        let (g2, g2_pk, g2_seed) = ml87_keypair(5);
        let (new_alice, _, _) = ml87_keypair(6);
        let (sess_pk_hash, sess_pk, sess_seed) = ml65_keypair(7);

        let mut reg = FrameRegistry::new();
        let mut bals = BTreeMap::new();
        bals.insert(alice, 1_000);
        bals.insert(sponsor, 500);
        bals.insert(bob, 0);

        // 1. Alice configures guardians (2-of-2, timelock 5) and grants bounded session key.
        let mut allowed = BTreeSet::new();
        allowed.insert(bob);
        let grant = SessionKeyGrant {
            session_id: [0x11; 32],
            signer_key_hash: sess_pk_hash,
            max_per_tx: 200,
            epoch_cap: 300,
            spent_in_epoch: 0,
            last_epoch: 1,
            expiry_height: 50,
            allowed_targets: allowed,
            active: true,
        };
        let setup_tx = FrameTransaction {
            sender: alice,
            sponsor: None,
            chain_id: 45_261,
            nonce: 0,
            max_fee: 10,
            frames: vec![
                ExecutionFrame {
                    kind: FrameKind::Verify,
                    target: alice,
                    gas_limit: 20_000,
                    authority: Some(FrameAuthorityProof::RootOwner),
                    sponsor_digest: None,
                    sponsor_auth: None,
                    action: None,
                },
                ExecutionFrame {
                    kind: FrameKind::Sender,
                    target: alice,
                    gas_limit: 50_000,
                    authority: None,
                    sponsor_digest: None,
                    sponsor_auth: None,
                    action: Some(FrameAction::RegisterPolicy {
                        guardians: vec![g1, g2],
                        threshold: 2,
                        timelock_blocks: 5,
                    }),
                },
                ExecutionFrame {
                    kind: FrameKind::Sender,
                    target: alice,
                    gas_limit: 50_000,
                    authority: None,
                    sponsor_digest: None,
                    sponsor_auth: None,
                    action: Some(FrameAction::GrantSessionKey(grant)),
                },
            ],
        };
        let ctx = |height, epoch, actual_fee| FrameExecContext {
            chain_id: 45_261,
            height,
            epoch,
            actual_fee,
        };
        // Non-owner cannot run RootOwner frame.
        assert!(matches!(
            apply_frame_tx_on_ledgers(&mut reg, &mut bals, &bob, ctx(10, 1, 5), &setup_tx),
            Err(FrameTxError::InvalidAuthority(_))
        ));
        let r0 = apply_frame_tx_on_ledgers(&mut reg, &mut bals, &alice, ctx(10, 1, 5), &setup_tx)
            .unwrap();
        assert_eq!(r0.fee_payer, alice);

        // 2. Sponsored session key transfer: forged sponsor auth MUST fail, valid ML-DSA-87 + ML-DSA-65 passes.
        let approve_digest = sponsor_approval_digest(&alice, &sponsor, 45_261, 1, 20);
        let sponsor_sig = ml_dsa_sign(
            SchemeId::ML_DSA_87,
            &sponsor_seed,
            &approve_digest,
            TX_V7,
            &[0x10; 32],
        )
        .unwrap();

        let mut exec_frames = vec![
            ExecutionFrame {
                kind: FrameKind::Verify,
                target: alice,
                gas_limit: 20_000,
                authority: None,
                sponsor_digest: None,
                sponsor_auth: None,
                action: None,
            },
            ExecutionFrame {
                kind: FrameKind::SponsorApprove,
                target: sponsor,
                gas_limit: 10_000,
                authority: None,
                sponsor_digest: Some(approve_digest),
                sponsor_auth: Some(FrameSponsorAuth {
                    public_key: sponsor_pk.clone(),
                    signature: sponsor_sig,
                }),
                action: None,
            },
            ExecutionFrame {
                kind: FrameKind::Default,
                target: bob,
                gas_limit: 30_000,
                authority: None,
                sponsor_digest: None,
                sponsor_auth: None,
                action: Some(FrameAction::Transfer {
                    to: bob,
                    amount: 150,
                }),
            },
        ];
        let sess_digest = session_exec_digest(&alice, 45_261, 1, 20, &[0x11; 32], &exec_frames);
        let sess_sig = ml_dsa_sign(
            SchemeId::ML_DSA_65,
            &sess_seed,
            &sess_digest,
            TX_V7,
            &[0x11; 32],
        )
        .unwrap();
        exec_frames[0].authority = Some(FrameAuthorityProof::SessionKey {
            session_id: [0x11; 32],
            signer_pk: sess_pk.clone(),
            signature: sess_sig,
        });
        let session_tx = FrameTransaction {
            sender: alice,
            sponsor: Some(sponsor),
            chain_id: 45_261,
            nonce: 1,
            max_fee: 20,
            frames: exec_frames,
        };

        // Sponsor drain attempt with missing sponsor_auth must fail even with valid digest.
        let mut forged_sponsor_tx = session_tx.clone();
        forged_sponsor_tx.frames[1].sponsor_auth = None;
        assert!(matches!(
            apply_frame_tx_on_ledgers(
                &mut reg,
                &mut bals,
                &bob,
                ctx(11, 1, 10),
                &forged_sponsor_tx
            ),
            Err(FrameTxError::SponsorNotApproved)
        ));

        let r1 = apply_frame_tx_on_ledgers(&mut reg, &mut bals, &bob, ctx(11, 1, 10), &session_tx)
            .unwrap();
        assert_eq!(r1.fee_payer, sponsor);
        assert_eq!(bals[&sponsor], 490);
        assert_eq!(bals[&bob], 150);

        // 3. Exceeding session epoch_cap (150 + 200 > 300) is refused atomically.
        let mut over_frames = vec![
            ExecutionFrame {
                kind: FrameKind::Verify,
                target: alice,
                gas_limit: 20_000,
                authority: None,
                sponsor_digest: None,
                sponsor_auth: None,
                action: None,
            },
            ExecutionFrame {
                kind: FrameKind::Default,
                target: bob,
                gas_limit: 30_000,
                authority: None,
                sponsor_digest: None,
                sponsor_auth: None,
                action: Some(FrameAction::Transfer {
                    to: bob,
                    amount: 200,
                }),
            },
        ];
        let over_digest = session_exec_digest(&alice, 45_261, 2, 20, &[0x11; 32], &over_frames);
        let over_sig = ml_dsa_sign(
            SchemeId::ML_DSA_65,
            &sess_seed,
            &over_digest,
            TX_V7,
            &[0x12; 32],
        )
        .unwrap();
        over_frames[0].authority = Some(FrameAuthorityProof::SessionKey {
            session_id: [0x11; 32],
            signer_pk: sess_pk,
            signature: over_sig,
        });
        let over_tx = FrameTransaction {
            sender: alice,
            sponsor: None,
            chain_id: 45_261,
            nonce: 2,
            max_fee: 20,
            frames: over_frames,
        };
        assert!(matches!(
            apply_frame_tx_on_ledgers(&mut reg, &mut bals, &bob, ctx(12, 1, 1), &over_tx),
            Err(FrameTxError::SessionDenied(_))
        ));

        // 4. Guardian 2-of-2 recovery proposes new_alice, blocked before timelock, succeeds after,
        // revokes old session keys, and permanently locks out old compromised `alice`.
        let prop_digest = guardian_recovery_digest(&alice, &new_alice, 45_261, 2);
        let g1_sig_prop = ml_dsa_sign(
            SchemeId::ML_DSA_87,
            &g1_seed,
            &prop_digest,
            GUARDIAN_V1,
            &[0x13; 32],
        )
        .unwrap();
        let g2_sig_prop = ml_dsa_sign(
            SchemeId::ML_DSA_87,
            &g2_seed,
            &prop_digest,
            GUARDIAN_V1,
            &[0x14; 32],
        )
        .unwrap();
        let propose_tx = FrameTransaction {
            sender: alice,
            sponsor: None,
            chain_id: 45_261,
            nonce: 2,
            max_fee: 10,
            frames: vec![
                ExecutionFrame {
                    kind: FrameKind::Verify,
                    target: alice,
                    gas_limit: 20_000,
                    authority: Some(FrameAuthorityProof::GuardianQuorum {
                        approvals: vec![
                            GuardianApproval {
                                guardian: g1,
                                public_key: g1_pk.clone(),
                                signature: g1_sig_prop,
                            },
                            GuardianApproval {
                                guardian: g2,
                                public_key: g2_pk.clone(),
                                signature: g2_sig_prop,
                            },
                        ],
                        new_owner: new_alice,
                    }),
                    sponsor_digest: None,
                    sponsor_auth: None,
                    action: None,
                },
                ExecutionFrame {
                    kind: FrameKind::Sender,
                    target: alice,
                    gas_limit: 20_000,
                    authority: None,
                    sponsor_digest: None,
                    sponsor_auth: None,
                    action: Some(FrameAction::ProposeGuardianRecovery {
                        new_owner: new_alice,
                        approvers: vec![g1, g2],
                    }),
                },
            ],
        };
        apply_frame_tx_on_ledgers(&mut reg, &mut bals, &g1, ctx(20, 1, 0), &propose_tx).unwrap();

        let fin_digest = guardian_recovery_digest(&alice, &new_alice, 45_261, 3);
        let g1_sig_fin = ml_dsa_sign(
            SchemeId::ML_DSA_87,
            &g1_seed,
            &fin_digest,
            GUARDIAN_V1,
            &[0x15; 32],
        )
        .unwrap();
        let g2_sig_fin = ml_dsa_sign(
            SchemeId::ML_DSA_87,
            &g2_seed,
            &fin_digest,
            GUARDIAN_V1,
            &[0x16; 32],
        )
        .unwrap();
        let fin_tx = FrameTransaction {
            sender: alice,
            sponsor: None,
            chain_id: 45_261,
            nonce: 3,
            max_fee: 10,
            frames: vec![
                ExecutionFrame {
                    kind: FrameKind::Verify,
                    target: alice,
                    gas_limit: 20_000,
                    authority: Some(FrameAuthorityProof::GuardianQuorum {
                        approvals: vec![
                            GuardianApproval {
                                guardian: g1,
                                public_key: g1_pk,
                                signature: g1_sig_fin,
                            },
                            GuardianApproval {
                                guardian: g2,
                                public_key: g2_pk,
                                signature: g2_sig_fin,
                            },
                        ],
                        new_owner: new_alice,
                    }),
                    sponsor_digest: None,
                    sponsor_auth: None,
                    action: None,
                },
                ExecutionFrame {
                    kind: FrameKind::Sender,
                    target: alice,
                    gas_limit: 20_000,
                    authority: None,
                    sponsor_digest: None,
                    sponsor_auth: None,
                    action: Some(FrameAction::FinalizeGuardianRecovery),
                },
            ],
        };
        assert!(matches!(
            apply_frame_tx_on_ledgers(&mut reg, &mut bals, &g1, ctx(24, 1, 0), &fin_tx),
            Err(FrameTxError::GuardianDenied(_))
        ));
        apply_frame_tx_on_ledgers(&mut reg, &mut bals, &g1, ctx(25, 1, 0), &fin_tx).unwrap();
        assert_eq!(reg.policies[&alice].controller, new_alice);
        assert!(!reg.policies[&alice].session_keys[&[0x11; 32]].active);

        // Old compromised `alice` key is permanently locked out from RootOwner actions.
        let stale_owner_tx = FrameTransaction {
            sender: alice,
            sponsor: None,
            chain_id: 45_261,
            nonce: 4,
            max_fee: 10,
            frames: vec![
                ExecutionFrame {
                    kind: FrameKind::Verify,
                    target: alice,
                    gas_limit: 20_000,
                    authority: Some(FrameAuthorityProof::RootOwner),
                    sponsor_digest: None,
                    sponsor_auth: None,
                    action: None,
                },
                ExecutionFrame {
                    kind: FrameKind::Sender,
                    target: bob,
                    gas_limit: 20_000,
                    authority: None,
                    sponsor_digest: None,
                    sponsor_auth: None,
                    action: Some(FrameAction::Transfer {
                        to: bob,
                        amount: 10,
                    }),
                },
            ],
        };
        assert!(matches!(
            apply_frame_tx_on_ledgers(&mut reg, &mut bals, &alice, ctx(26, 1, 0), &stale_owner_tx),
            Err(FrameTxError::InvalidAuthority(_))
        ));
        // Recovered controller `new_alice` succeeds immediately.
        apply_frame_tx_on_ledgers(
            &mut reg,
            &mut bals,
            &new_alice,
            ctx(26, 1, 0),
            &stale_owner_tx,
        )
        .unwrap();
        assert_eq!(bals[&bob], 160);
    }
}
