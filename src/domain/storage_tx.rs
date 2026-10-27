//! B.U.D. storage writes as signed, in-block transactions.
//!
//! The storage registry is hashed into the account state root
//! (`AccountState::calculate_state_root` folds `storage_registry.root()`), so
//! a write to it is a consensus write. Until this module every write reached
//! the registry through a local RPC command on one node, out of block, which
//! is why the chain actor refuses every storage command on mainnet: two
//! honest nodes would end up with different state roots.
//!
//! This family moves those writes into the block. Each variant is applied by
//! the executor's `Storage` arm, inside block execution, from a transaction
//! the sender signed. It has twelve variants: manifest registration, the
//! operator class declaration, the self-host policy declaration, opening a
//! deal, the answer to a coding audit, accepting a repair ticket, opening a
//! retrieval challenge and answering one, issuing and revoking a view grant,
//! a social delete and a confidential body commit. The operator RPCs that used to
//! perform the last three (and the first and the fourth) outside a block
//! refuse and name these doors.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::domain::deal_open::{
    accept_reallocation_escrowed, open_deal_escrowed, DealOpenTerms, ReallocationTerms,
};
use crate::domain::storage_deal::{
    ChallengeOutcome, DealStatus, OperatorClass, RetrievalChallengeRequest, StorageEconomicsParams,
    StorageError, StorageRegistry,
};
use crate::domain::storage_params::STORAGE_MIN_OPERATOR_BOND;
use crate::domain::Hash32;
use crate::storage::{
    ConfidentialBodyCommit, ContentId, ContentManifest, GrantAuthorization, GrantIssueTerms,
    MobileSelfContentPolicy, MobileSelfProfile, ViewPolicy,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Longest data column a coding audit answer may carry. A column holds one
/// byte per data shard, and no code word has more shards than this, so a
/// longer answer is refused before the registry is read.
const MAX_CODING_AUDIT_DATA_COLUMN_BYTES: usize = crate::storage::MAX_TOTAL_SHARDS;

/// One storage write. The sender is `tx.from`, already signed; no variant
/// carries an actor field a caller could fill with someone else's address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageTx {
    /// Record a content manifest so deals, challenges and repair can index
    /// it. The sender must be the manifest's declared owner, which turns the
    /// owner field from a first-writer label into a signed claim.
    RegisterManifest { manifest: ContentManifest },
    /// Declare what kind of machine the sender runs. The class is
    /// self-reported and the chain holds the sender to it when it takes
    /// replicas.
    DeclareOperatorClass { class: OperatorClass },
    /// Declare how the sender wants one shard of its own content to be
    /// self-hosted. The profile is the device profile the policy is checked
    /// against.
    DeclareSelfHostPolicy {
        manifest_id: ContentId,
        policy: MobileSelfContentPolicy,
        profile: MobileSelfProfile,
    },
    /// Open a paid storage deal. The sender is the payer: the fee is escrowed
    /// from the sender. The operator's bond is locked only when the body
    /// carries the operator's own signed consent. Boxed: the consent key is
    /// large and would make every other variant as large.
    OpenDeal(Box<StorageDealOpen>),
    /// Answer a coding audit the chain opened. The sender is the responder,
    /// so only the audited operator's own signature can answer. The answer
    /// is byte `column` of each data shard in shard order and the same column
    /// of the audited parity shard.
    AnswerCodingAudit {
        audit_id: u64,
        data_column: Vec<u8>,
        parity_byte: u8,
        /// Merkle path for `parity_byte` at the audited column, against the
        /// audited parity shard's commitment in the manifest
        /// ([`crate::storage::column_commitment`]).
        ///
        /// This is what turns the audit from "the operator can produce a
        /// consistent column" into "the operator holds the shard this manifest
        /// describes": the siblings in the path are hashes of the real shard,
        /// so a memorised column of another object cannot answer. A manifest
        /// recorded before column commitments carries none, and an answer for
        /// it is checked the old way - see
        /// [`crate::domain::storage_deal::StorageError::CodingAuditColumnProofRejected`].
        column_proof: Vec<[u8; 32]>,
    },
    /// Accept a repair ticket for a replacement placement. The sender is the
    /// payer: the replacement fee is escrowed from the sender. The
    /// replacement operator's bond is locked only when the body carries that
    /// operator's own signed consent. The placement itself (manifest, shard,
    /// replica) is read from the ticket. Boxed for the same reason as the
    /// deal open.
    AcceptReallocation(Box<StorageReallocationAccept>),
    /// Open a retrieval challenge against an active deal. The sender is the
    /// opener and pays the bond. The challenge starts at the block's epoch,
    /// and the byte range is derived from the block's entropy, so neither
    /// the opener nor the operator picks which bytes are asked for.
    OpenChallenge {
        deal_id: u64,
        range_len: u64,
        deadline_epoch: u64,
        opener_bond: u64,
    },
    /// Answer a retrieval challenge. The sender is the responder, so only the
    /// deal's operator can answer; the response epoch is the block's epoch.
    /// A proof that does not verify is an accepted transaction with a
    /// `Mismatched` outcome: the operator bond is slashed.
    AnswerChallenge {
        challenge_id: u64,
        range_hash: ContentId,
        proof: Vec<u8>,
    },
    /// Issue a view grant over content the sender holds. Key material stays
    /// off chain; the grant row records who may open the content with which
    /// key id. The grant opens at the block's epoch.
    IssueViewGrant {
        content_id: ContentId,
        grantee: Option<Address>,
        key_id: Hash32,
        policy: ViewPolicy,
    },
    /// Revoke a grant the sender issued, at the block's epoch.
    RevokeViewGrant { grant_id: u64 },
    /// Social delete: revoke every live grant the sender issued for content
    /// the sender owns and rotate the payload key id, at the block's epoch.
    SocialDelete { content_id: ContentId },
    /// Record a confidential body commit under the sender's address.
    CommitConfidentialBody { commit: ConfidentialBodyCommit },
}

/// The body of [`StorageTx::AcceptReallocation`].
///
/// There is no payer field: the payer is the transaction sender. The merkle
/// envelope follows the deal-open convention: an empty `merkle_proof` means
/// none and an all-zero `storage_root` means none, and the registry refuses
/// an acceptance without both.
/// exposed for StorageTx::AcceptReallocation: the executor and the signing bytes in core/transaction.rs reach it through the variant, not by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageReallocationAccept {
    pub ticket_id: u64,
    pub replacement_operator: Address,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub economics: StorageEconomicsParams,
    /// Serialized proof envelope. Empty means none.
    pub merkle_proof: Vec<u8>,
    /// Storage root the proof is checked against. All zero means none.
    pub storage_root: Hash32,
    /// The replacement operator's ML-DSA consent, signed over
    /// [`accept_reallocation_consent_digest`].
    pub operator_consent: GrantAuthorization,
}

/// The body of [`StorageTx::OpenDeal`].
///
/// There is no payer field: the payer is the transaction sender. There is no
/// manifest either: it is read from the registry, so the deal prices and
/// places the content the owner registered and not a copy the sender
/// supplies.
///
/// The merkle envelope is optional in the registry and optional here by
/// encoding: an empty `merkle_proof` means none and an all-zero
/// `storage_root` means none. The registry refuses a deal without both, so in
/// block today an open that leaves either empty is refused.
/// exposed for StorageTx::OpenDeal: the executor and the signing bytes in core/transaction.rs reach it through the variant, not by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageDealOpen {
    pub domain_id: u32,
    pub manifest_id: ContentId,
    pub shard_id: ContentId,
    pub operator: Address,
    pub replica_index: u8,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub economics: StorageEconomicsParams,
    /// Serialized proof envelope. Empty means none.
    pub merkle_proof: Vec<u8>,
    /// Storage root the proof is checked against. All zero means none.
    pub storage_root: Hash32,
    /// The operator's ML-DSA consent to hold this shard, signed over
    /// [`open_deal_consent_digest`].
    pub operator_consent: GrantAuthorization,
}

/// What the executor knows about the transaction and the sender, handed to
/// the storage handlers. `nonce` is the sender's account nonce before the
/// executor advances it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageTxContext {
    pub sender: Address,
    pub nonce: u64,
    pub chain_id: u64,
    pub fee: u64,
}

/// Why a storage transaction was refused. Every refusal leaves the registry
/// as it was.
///
/// WIRING: returned by `execute_storage_tx`; the executor's `Storage` arm
/// reads it as the `storage_tx_failed` message rather than by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageTxError {
    /// The manifest failed `validate_untrusted`: its id does not derive from
    /// its contents, or its shard list, sizes or scheme disagree.
    InvalidManifest(String),
    /// The manifest names an owner other than the signer. A signer may only
    /// register content in its own name.
    OwnerIsNotSender { owner: Address, sender: Address },
    /// The manifest is already registered. Registration is first-writer-wins
    /// and a repeat would pay a fee for a write that changes nothing.
    AlreadyRegistered,
    /// Paid content may not be registered as plaintext: a plaintext content
    /// id is the hash of the bytes, and putting it on chain leaks the asset.
    PaidContentAsPlaintext(String),
    /// The registry refused the manifest's source regime or dictionary.
    Refused(String),
    /// The sender already holds this class, so the write would change
    /// nothing and a fee would be paid for nothing.
    ClassUnchanged,
    /// The sender operates an active deal, and a deal opened under the
    /// always-on class was priced and placed on that claim. Switching to
    /// mobile would walk around the placement and self-host checks.
    MobileHoldsActiveDeal { deal_id: u64 },
    /// The manifest declares a generated source. Registering one runs the
    /// recipe, which costs far more than the flat fee a transaction pays.
    GeneratedRegistrationNotPriced,
    /// The manifest a self-host policy names is not registered.
    ManifestNotRegistered,
    /// The payer is not the authority for the manifest a deal names.
    ///
    /// Every durability number the storage registry reports is derived from
    /// `Active` deal rows: an opened deal suppresses repair and holds the
    /// guard that keeps an object's last copies from being released. A deal
    /// over somebody else's content would therefore steer that bookkeeping
    /// without the owner's say, so only the account the chain records as the
    /// content's owner may open one (`has_claim`, the gate the grant,
    /// self-host, read and prune paths already use).
    DealManifestNotOwned { sender: Address },
    /// The policy's `owner` is not the signer.
    PolicyOwnerIsNotSender { owner: Address, sender: Address },
    /// The policy's `content_id` is not a shard of the named manifest.
    PolicyContentNotInManifest,
    /// Deals are not opened in block on mainnet yet.
    OpenDealOnMainnet,
    /// The operator's consent does not verify for this deal, this payer and
    /// this nonce.
    OperatorConsentRefused(String),
    /// The deal-open rules refused the open: cooldown, balances, bond,
    /// placement, merkle envelope or epoch range.
    DealRefused(String),
    /// A coding audit answer carries no data column.
    EmptyDataColumn,
    /// A coding audit answer carries more column bytes than the audited
    /// object has data shards, or more than any object can have.
    DataColumnTooLong { len: usize, max: usize },
    /// The registry refused the coding audit answer: unknown or closed
    /// audit, a signer other than the audited operator, or an answer after
    /// the deadline.
    CodingAuditRefused(String),
    /// Repair tickets are not accepted in block on mainnet yet.
    AcceptReallocationOnMainnet,
    /// The reallocation rules refused the acceptance: unknown or closed
    /// ticket, the slashed operator, cooldown, balances, bond or envelope.
    ReallocationRefused(String),
    /// Retrieval challenges are not opened or answered in block on mainnet
    /// yet.
    ChallengeOnMainnet,
    /// The opener cannot pay the bond and keep the transaction fee.
    OpenerBondUnfunded { needed: u64, balance: u64 },
    /// The registry refused the challenge: window, range, bond, unknown or
    /// inactive deal, or the per-operator rate limit.
    ChallengeRefused(String),
    /// The registry refused the answer: unknown or resolved challenge, a
    /// signer other than the deal's operator, or an answer after the
    /// deadline.
    ChallengeAnswerRefused(String),
    /// The grant book refused the issue, revoke or delete: unknown content or
    /// grant, or a sender who does not hold the content or did not issue the
    /// grant.
    ViewGrantRefused(String),
    /// The registry refused the confidential body commit.
    ConfidentialCommitRefused(String),
}

impl fmt::Display for StorageTxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest(e) => write!(f, "invalid manifest: {e}"),
            Self::OwnerIsNotSender { owner, sender } => write!(
                f,
                "manifest owner {owner} is not the sender {sender}; a signer registers content \
                 only in its own name"
            ),
            Self::AlreadyRegistered => write!(f, "manifest is already registered"),
            Self::PaidContentAsPlaintext(e) => {
                write!(f, "refusing to register paid content as plaintext: {e}")
            }
            Self::Refused(e) => write!(f, "storage registry refused the manifest: {e}"),
            Self::ClassUnchanged => write!(f, "the operator already holds this class"),
            Self::MobileHoldsActiveDeal { deal_id } => write!(
                f,
                "cannot declare Mobile while operating the active deal {deal_id}"
            ),
            Self::GeneratedRegistrationNotPriced => write!(
                f,
                "registering a generated source in block is not priced yet"
            ),
            Self::ManifestNotRegistered => write!(f, "manifest is not registered"),
            Self::DealManifestNotOwned { sender } => write!(
                f,
                "the payer {sender} is not the owner of the manifest this deal names"
            ),
            Self::PolicyOwnerIsNotSender { owner, sender } => write!(
                f,
                "policy owner {owner} is not the sender {sender}; a signer declares policy only \
                 for its own content"
            ),
            Self::PolicyContentNotInManifest => {
                write!(f, "policy content id is not a shard of the manifest")
            }
            Self::OpenDealOnMainnet => {
                write!(
                    f,
                    "opening a storage deal in block is not enabled on mainnet"
                )
            }
            Self::OperatorConsentRefused(e) => {
                write!(f, "the operator's consent was refused: {e}")
            }
            Self::DealRefused(e) => write!(f, "storage deal refused: {e}"),
            Self::EmptyDataColumn => write!(f, "the coding audit answer has no data column"),
            Self::DataColumnTooLong { len, max } => write!(
                f,
                "the coding audit answer has {len} column bytes; at most {max} are allowed"
            ),
            Self::CodingAuditRefused(e) => write!(f, "coding audit answer refused: {e}"),
            Self::AcceptReallocationOnMainnet => write!(
                f,
                "accepting a storage repair ticket in block is not enabled on mainnet"
            ),
            Self::ReallocationRefused(e) => write!(f, "reallocation acceptance refused: {e}"),
            Self::ChallengeOnMainnet => write!(
                f,
                "retrieval challenges in block are not enabled on mainnet"
            ),
            Self::OpenerBondUnfunded { needed, balance } => write!(
                f,
                "the opener needs {needed} for the bond and the fee and holds {balance}"
            ),
            Self::ChallengeRefused(e) => write!(f, "retrieval challenge refused: {e}"),
            Self::ChallengeAnswerRefused(e) => write!(f, "challenge answer refused: {e}"),
            Self::ViewGrantRefused(e) => write!(f, "view grant refused: {e}"),
            Self::ConfidentialCommitRefused(e) => {
                write!(f, "confidential body commit refused: {e}")
            }
        }
    }
}

impl std::error::Error for StorageTxError {}

/// Apply one storage transaction to `state` on behalf of `ctx.sender`.
///
/// Every check runs before the registry is written, so a refusal changes
/// nothing. The executor charges the fee and advances the nonce only when
/// this returns `Ok`.
///
/// # Errors
///
/// Returns the [`StorageTxError`] variant that names the failed check.
pub fn execute_storage_tx(
    state: &mut AccountState,
    ctx: &StorageTxContext,
    tx: &StorageTx,
) -> Result<(), StorageTxError> {
    let sender = &ctx.sender;
    match tx {
        StorageTx::RegisterManifest { manifest } => register_manifest(state, sender, manifest),
        StorageTx::DeclareOperatorClass { class } => declare_operator_class(state, sender, *class),
        StorageTx::DeclareSelfHostPolicy {
            manifest_id,
            policy,
            profile,
        } => declare_self_host_policy(state, sender, manifest_id, policy, profile),
        StorageTx::OpenDeal(open) => open_deal(state, ctx, open),
        StorageTx::AnswerCodingAudit {
            audit_id,
            data_column,
            parity_byte,
            column_proof,
        } => answer_coding_audit(
            state,
            sender,
            *audit_id,
            data_column,
            *parity_byte,
            column_proof,
        ),
        StorageTx::AcceptReallocation(accept) => accept_reallocation(state, ctx, accept),
        StorageTx::OpenChallenge {
            deal_id,
            range_len,
            deadline_epoch,
            opener_bond,
        } => open_challenge(
            state,
            ctx,
            *deal_id,
            *range_len,
            *deadline_epoch,
            *opener_bond,
        ),
        StorageTx::AnswerChallenge {
            challenge_id,
            range_hash,
            proof,
        } => answer_challenge(state, ctx, *challenge_id, *range_hash, proof),
        StorageTx::IssueViewGrant {
            content_id,
            grantee,
            key_id,
            policy,
        } => {
            let terms = GrantIssueTerms {
                grantee: *grantee,
                key_id: *key_id,
                policy: *policy,
                opened_epoch: state.epoch_index,
            };
            state
                .storage_registry
                .issue_view_grant_as(*sender, *content_id, terms)
                .map(|_| ())
                .map_err(|e| StorageTxError::ViewGrantRefused(e.to_string()))
        }
        StorageTx::RevokeViewGrant { grant_id } => {
            let epoch = state.epoch_index;
            state
                .storage_registry
                .revoke_view_grant_as(*sender, *grant_id, epoch)
                .map(|_| ())
                .map_err(|e| StorageTxError::ViewGrantRefused(e.to_string()))
        }
        StorageTx::SocialDelete { content_id } => {
            let epoch = state.epoch_index;
            state
                .storage_registry
                .social_delete_as(*sender, *content_id, epoch)
                .map(|_| ())
                .map_err(|e| StorageTxError::ViewGrantRefused(e.to_string()))
        }
        StorageTx::CommitConfidentialBody { commit } => state
            .storage_registry
            .register_confidential_commit_as(*sender, commit.clone())
            .map(|_| ())
            .map_err(StorageTxError::ConfidentialCommitRefused),
    }
}

fn is_mainnet(chain_id: u64) -> bool {
    chain_id
        == crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value()
}

/// Digest the replacement operator signs to consent to one repair
/// acceptance.
///
/// It binds the chain, the payer, the payer's account nonce and every body
/// field except the consent itself, under its own tag, so a deal-open consent
/// cannot be presented as a repair consent or the reverse.
/// WIRING: the in-block check is accept_reallocation below; the outside caller is the operator-side consent signer, which does not exist yet.
#[must_use]
pub fn accept_reallocation_consent_digest(
    chain_id: u64,
    payer: &Address,
    nonce: u64,
    accept: &StorageReallocationAccept,
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_STORAGE_ACCEPT_REALLOCATION_TX_V1",
        &chain_id.to_le_bytes(),
        payer.as_bytes(),
        &nonce.to_le_bytes(),
        &accept.ticket_id.to_le_bytes(),
        accept.replacement_operator.as_bytes(),
        &accept.start_epoch.to_le_bytes(),
        &accept.end_epoch.to_le_bytes(),
        &accept.economics.operator_bond.to_le_bytes(),
        &accept.economics.fee_per_byte_epoch.to_le_bytes(),
        &accept.merkle_proof,
        &accept.storage_root,
    ])
}

fn accept_reallocation(
    state: &mut AccountState,
    ctx: &StorageTxContext,
    accept: &StorageReallocationAccept,
) -> Result<(), StorageTxError> {
    if is_mainnet(ctx.chain_id) {
        return Err(StorageTxError::AcceptReallocationOnMainnet);
    }
    let digest = accept_reallocation_consent_digest(ctx.chain_id, &ctx.sender, ctx.nonce, accept);
    accept
        .operator_consent
        .verify(&digest, &accept.replacement_operator)
        .map_err(|e| StorageTxError::OperatorConsentRefused(e.to_string()))?;
    let terms = ReallocationTerms {
        ticket_id: accept.ticket_id,
        replacement_operator: accept.replacement_operator,
        start_epoch: accept.start_epoch,
        end_epoch: accept.end_epoch,
        economics: accept.economics.clone(),
        merkle_proof: if accept.merkle_proof.is_empty() {
            None
        } else {
            Some(accept.merkle_proof.clone())
        },
        storage_root: if accept.storage_root == [0u8; 32] {
            None
        } else {
            Some(accept.storage_root)
        },
    };
    // Same reserve rule as the open: the payer keeps the fee, and the bond
    // too when the payer is also the replacement operator.
    let payer_reserve = if ctx.sender == accept.replacement_operator {
        ctx.fee.saturating_add(accept.economics.operator_bond)
    } else {
        ctx.fee
    };
    let now_unix_secs = state.current_block_unix_secs;
    accept_reallocation_escrowed(
        state,
        &terms,
        ctx.sender,
        now_unix_secs,
        STORAGE_MIN_OPERATOR_BOND,
        payer_reserve,
    )
    .map(|_| ())
    .map_err(StorageTxError::ReallocationRefused)
}

/// Open a retrieval challenge in block. Every refusal is decided before the
/// registry is written, and the bond is debited only after the registry
/// accepted the challenge, from a balance already checked to hold it.
fn open_challenge(
    state: &mut AccountState,
    ctx: &StorageTxContext,
    deal_id: u64,
    range_len: u64,
    deadline_epoch: u64,
    opener_bond: u64,
) -> Result<(), StorageTxError> {
    if is_mainnet(ctx.chain_id) {
        return Err(StorageTxError::ChallengeOnMainnet);
    }
    let epoch = state.epoch_index;
    StorageRegistry::validate_challenge_window(epoch, deadline_epoch, epoch)
        .map_err(|e| StorageTxError::ChallengeRefused(e.to_string()))?;
    let balance = state.get_balance(&ctx.sender);
    let needed = opener_bond.saturating_add(ctx.fee);
    if balance < needed {
        return Err(StorageTxError::OpenerBondUnfunded { needed, balance });
    }
    let request = RetrievalChallengeRequest {
        deal_id,
        byte_start: 0,
        byte_end: range_len,
        challenge_epoch: epoch,
        deadline_epoch,
        opener_bond,
        opener: Some(ctx.sender),
        opener_signature: None,
    };
    // The block's own entropy, the opener and the opener's nonce: the range
    // is fixed only when the block is, so the operator cannot learn it in
    // advance, and two challenges in one block draw different ranges.
    let entropy = hash_fields_bytes(&[
        b"BDLM_STORAGE_CHALLENGE_TX_ENTROPY_V1",
        &ctx.chain_id.to_le_bytes(),
        &state.current_block_entropy,
        ctx.sender.as_bytes(),
        &ctx.nonce.to_le_bytes(),
    ]);
    state
        .storage_registry
        .open_challenge_with_entropy(&request, ctx.sender, &entropy)
        .map_err(|e| StorageTxError::ChallengeRefused(e.to_string()))?;
    let account = state.get_or_create(&ctx.sender);
    account.balance = account.balance.saturating_sub(opener_bond);
    Ok(())
}

/// Answer a retrieval challenge in block.
///
/// The registry decides every refusal before it records a result. An answer
/// it accepts resolves the challenge: the opener gets the bond back (the
/// opener called correctly whether the operator answered well or not), and a
/// `Mismatched` outcome slashes the operator bond, which `open_deal` already
/// debited, so the slash is recorded as burned supply and the operator enters
/// the cooldown a missed challenge starts.
fn answer_challenge(
    state: &mut AccountState,
    ctx: &StorageTxContext,
    challenge_id: u64,
    range_hash: ContentId,
    proof: &[u8],
) -> Result<(), StorageTxError> {
    if is_mainnet(ctx.chain_id) {
        return Err(StorageTxError::ChallengeOnMainnet);
    }
    let (opener, opener_bond) = state
        .storage_registry
        .get_challenge(challenge_id)
        .map(|c| (c.opener, c.opener_bond))
        .ok_or_else(|| {
            StorageTxError::ChallengeAnswerRefused(
                StorageError::UnknownChallenge(challenge_id).to_string(),
            )
        })?;
    // Auto-challenges from block maintenance have no opener and no bond
    // that was debited from anyone; only a bonded opener is refunded.
    let refund = opener_bond > 0 && opener != Address::zero();
    if refund
        && state
            .get_balance(&opener)
            .checked_add(opener_bond)
            .is_none()
    {
        return Err(StorageTxError::ChallengeAnswerRefused(
            "the opener bond refund would overflow the opener balance".into(),
        ));
    }
    let epoch = state.epoch_index;
    let proof_bytes = if proof.is_empty() { None } else { Some(proof) };
    let result = state
        .storage_registry
        .answer_challenge_with_chain_id(
            ctx.chain_id,
            challenge_id,
            range_hash,
            ctx.sender,
            epoch,
            proof_bytes,
        )
        .map_err(|e| StorageTxError::ChallengeAnswerRefused(e.to_string()))?;
    if result.outcome == ChallengeOutcome::Mismatched {
        let now_unix_secs = state.current_block_unix_secs;
        state
            .storage_registry
            .begin_operator_cooldown(ctx.sender, now_unix_secs);
        state.burned_total = state.burned_total.saturating_add(result.slashed_bond);
    }
    if refund {
        // The bond `open_challenge` debited from this opener comes back. The
        // overflow was ruled out above.
        state
            .try_add_balance(&opener, opener_bond)
            .map_err(StorageTxError::ChallengeAnswerRefused)?;
    }
    Ok(())
}

/// Hand the sender's answer to the registry, which checks it against the
/// stored audit. The epoch and the clock are the block's own: the epoch is
/// `epoch_index`, the scale `apply_block_effects` opens and finalizes audits
/// on, and the seconds are the block timestamp. A `Failed` outcome is an
/// accepted transaction: the registry records it and starts the cooldown.
fn answer_coding_audit(
    state: &mut AccountState,
    sender: &Address,
    audit_id: u64,
    data_column: &[u8],
    parity_byte: u8,
    column_proof: &[[u8; 32]],
) -> Result<(), StorageTxError> {
    if data_column.is_empty() {
        return Err(StorageTxError::EmptyDataColumn);
    }
    if data_column.len() > MAX_CODING_AUDIT_DATA_COLUMN_BYTES {
        return Err(StorageTxError::DataColumnTooLong {
            len: data_column.len(),
            max: MAX_CODING_AUDIT_DATA_COLUMN_BYTES,
        });
    }
    let manifest_id = match state.storage_registry.coding_audit(audit_id) {
        Some(stored) => stored.audit.manifest_id,
        None => {
            let unknown = StorageError::UnknownCodingAudit(audit_id);
            return Err(StorageTxError::CodingAuditRefused(unknown.to_string()));
        }
    };
    // A pruned manifest is the registry's case: it voids the audit.
    if let Some(manifest) = state.storage_registry.get_manifest(&manifest_id) {
        let data_shards = usize::try_from(manifest.erasure.k).unwrap_or(usize::MAX);
        if data_column.len() > data_shards {
            return Err(StorageTxError::DataColumnTooLong {
                len: data_column.len(),
                max: data_shards,
            });
        }
    }
    let epoch = state.epoch_index;
    let now = state.current_block_unix_secs;
    state
        .storage_registry
        .answer_coding_audit(
            audit_id,
            *sender,
            data_column,
            parity_byte,
            column_proof,
            epoch,
            now,
        )
        .map(|_| ())
        .map_err(|e| StorageTxError::CodingAuditRefused(e.to_string()))
}

/// Digest the operator signs to consent to one deal-open.
///
/// It binds the chain, the payer, the payer's account nonce and every body
/// field except the consent itself, so the consent cannot move to another
/// chain, payer, placement or price, and it is spent when the payer's nonce
/// advances.
/// WIRING: the in-block check is open_deal below; the outside caller is the operator-side consent signer of the storage RPC mutation path, which does not exist yet.
#[must_use]
pub fn open_deal_consent_digest(
    chain_id: u64,
    payer: &Address,
    nonce: u64,
    open: &StorageDealOpen,
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_STORAGE_OPEN_DEAL_TX_V1",
        &chain_id.to_le_bytes(),
        payer.as_bytes(),
        &nonce.to_le_bytes(),
        &open.domain_id.to_le_bytes(),
        open.manifest_id.as_bytes(),
        open.shard_id.as_bytes(),
        open.operator.as_bytes(),
        &[open.replica_index],
        &open.start_epoch.to_le_bytes(),
        &open.end_epoch.to_le_bytes(),
        &open.economics.operator_bond.to_le_bytes(),
        &open.economics.fee_per_byte_epoch.to_le_bytes(),
        &open.merkle_proof,
        &open.storage_root,
    ])
}

fn open_deal(
    state: &mut AccountState,
    ctx: &StorageTxContext,
    open: &StorageDealOpen,
) -> Result<(), StorageTxError> {
    if ctx.chain_id
        == crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value()
    {
        return Err(StorageTxError::OpenDealOnMainnet);
    }
    // Cloned so the registry can be written while the terms borrow it.
    let manifest = state
        .storage_registry
        .get_manifest(&open.manifest_id)
        .ok_or(StorageTxError::ManifestNotRegistered)?
        .clone();
    // The payer has to be the content's authority. Everything the registry
    // reports about durability - repair, the last-copy release guard, the
    // operator's standing - is derived from `Active` deal rows and nothing
    // else, so a deal opened by a stranger over somebody else's manifest buys
    // silence about a shard the real owner never placed and unblocks the
    // holder it was meant to protect. Authority is looked up, not believed:
    // `has_claim` resolves `owner_of`, the same answer the grant, self-host,
    // read and prune doors use.
    if !state
        .storage_registry
        .has_claim(&open.manifest_id, &ctx.sender)
    {
        return Err(StorageTxError::DealManifestNotOwned { sender: ctx.sender });
    }
    let digest = open_deal_consent_digest(ctx.chain_id, &ctx.sender, ctx.nonce, open);
    open.operator_consent
        .verify(&digest, &open.operator)
        .map_err(|e| StorageTxError::OperatorConsentRefused(e.to_string()))?;

    let terms = DealOpenTerms {
        domain_id: open.domain_id,
        manifest: &manifest,
        shard_id: open.shard_id,
        operator: open.operator,
        replica_index: open.replica_index,
        start_epoch: open.start_epoch,
        end_epoch: open.end_epoch,
        economics: open.economics.clone(),
        merkle_proof: if open.merkle_proof.is_empty() {
            None
        } else {
            Some(open.merkle_proof.clone())
        },
        storage_root: if open.storage_root == [0u8; 32] {
            None
        } else {
            Some(open.storage_root)
        },
    };
    // The executor charges the fee after this returns, so the payer must
    // still hold it. When the payer is also the operator the bond comes out
    // of the same balance and is part of what must remain.
    let payer_reserve = if ctx.sender == open.operator {
        ctx.fee.saturating_add(open.economics.operator_bond)
    } else {
        ctx.fee
    };
    let now_unix_secs = state.current_block_unix_secs;
    open_deal_escrowed(
        state,
        &terms,
        ctx.sender,
        now_unix_secs,
        STORAGE_MIN_OPERATOR_BOND,
        payer_reserve,
    )
    .map(|_| ())
    .map_err(StorageTxError::DealRefused)
}

fn declare_operator_class(
    state: &mut AccountState,
    sender: &Address,
    class: OperatorClass,
) -> Result<(), StorageTxError> {
    if state.storage_registry.operator_class(sender) == class {
        return Err(StorageTxError::ClassUnchanged);
    }
    if class == OperatorClass::Mobile {
        if let Some(deal) = state
            .storage_registry
            .deals_iter()
            .find(|d| d.operator == *sender && d.status == DealStatus::Active)
        {
            return Err(StorageTxError::MobileHoldsActiveDeal {
                deal_id: deal.deal_id,
            });
        }
    }
    state.storage_registry.set_operator_class(*sender, class);
    Ok(())
}

fn declare_self_host_policy(
    state: &mut AccountState,
    sender: &Address,
    manifest_id: &ContentId,
    policy: &MobileSelfContentPolicy,
    profile: &MobileSelfProfile,
) -> Result<(), StorageTxError> {
    let manifest = state
        .storage_registry
        .get_manifest(manifest_id)
        .ok_or(StorageTxError::ManifestNotRegistered)?;
    if !state.storage_registry.has_claim(manifest_id, sender) {
        return Err(StorageTxError::OwnerIsNotSender {
            owner: state
                .storage_registry
                .owner_of(manifest_id)
                .unwrap_or_default(),
            sender: *sender,
        });
    }
    if policy.owner != *sender {
        return Err(StorageTxError::PolicyOwnerIsNotSender {
            owner: policy.owner,
            sender: *sender,
        });
    }
    if manifest.shard(&policy.content_id).is_none() {
        return Err(StorageTxError::PolicyContentNotInManifest);
    }
    state
        .storage_registry
        .declare_self_host_policy(*manifest_id, policy.clone(), profile)
        .map_err(|e| StorageTxError::Refused(e.to_string()))
}

fn register_manifest(
    state: &mut AccountState,
    sender: &Address,
    manifest: &ContentManifest,
) -> Result<(), StorageTxError> {
    // The id is re-derived from the contents, so a manifest whose id does not
    // match what it carries never reaches the registry. The signing preimage
    // commits the whole manifest as well.
    manifest
        .validate_untrusted()
        .map_err(StorageTxError::InvalidManifest)?;
    if manifest.owner != *sender {
        return Err(StorageTxError::OwnerIsNotSender {
            owner: manifest.owner,
            sender: *sender,
        });
    }
    if let Some(asset_owner) = state.marketplace.bound_asset_owner(&manifest.manifest_id) {
        if asset_owner != *sender {
            return Err(StorageTxError::OwnerIsNotSender {
                owner: asset_owner,
                sender: *sender,
            });
        }
    }
    if state.storage_registry.is_registered(&manifest.manifest_id) {
        return Err(StorageTxError::AlreadyRegistered);
    }
    if matches!(manifest.source, crate::storage::ContentSource::Generated(_)) {
        return Err(StorageTxError::GeneratedRegistrationNotPriced);
    }
    if matches!(
        manifest.encryption,
        crate::storage::ContentEncryption::Plaintext
    ) {
        state
            .marketplace
            .check_content_may_be_public(&manifest.manifest_id)
            .map_err(StorageTxError::PaidContentAsPlaintext)?;
    }
    state
        .storage_registry
        .register_manifest_with_source(manifest)
        .map_err(|e| StorageTxError::Refused(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::storage_deal::CodingAuditOutcome;
    use crate::storage::{encode_object, ErasureScheme};

    fn owner() -> Address {
        Address::from([7u8; 32])
    }

    fn ctx(sender: Address) -> StorageTxContext {
        StorageTxContext {
            sender,
            nonce: 0,
            chain_id: 45262,
            fee: 0,
        }
    }

    fn manifest_owned_by(who: Address) -> ContentManifest {
        // Distinct bytes per stripe: identical data shards share a content
        // id, and a code word that repeats one is refused.
        let bytes: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let enc = encode_object(&bytes, ErasureScheme { k: 4, n: 6 }).expect("encode");
        let mut m = enc.to_manifest().expect("manifest");
        m.owner = who;
        m
    }

    #[test]
    fn the_owner_registers_its_manifest() {
        let mut state = AccountState::new();
        let m = manifest_owned_by(owner());
        execute_storage_tx(
            &mut state,
            &ctx(owner()),
            &StorageTx::RegisterManifest {
                manifest: m.clone(),
            },
        )
        .expect("the owner registers");
        assert_eq!(
            state.storage_registry.get_manifest(&m.manifest_id),
            Some(&m)
        );
    }

    #[test]
    fn a_signer_cannot_register_content_in_someone_elses_name() {
        let mut state = AccountState::new();
        let m = manifest_owned_by(owner());
        let stranger = Address::from([9u8; 32]);
        let err = execute_storage_tx(
            &mut state,
            &ctx(stranger),
            &StorageTx::RegisterManifest {
                manifest: m.clone(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, StorageTxError::OwnerIsNotSender { .. }));
        assert!(state
            .storage_registry
            .get_manifest(&m.manifest_id)
            .is_none());
    }

    #[test]
    fn a_manifest_whose_id_does_not_derive_is_refused() {
        let mut state = AccountState::new();
        let mut m = manifest_owned_by(owner());
        m.manifest_id = crate::storage::ContentId::of(b"chosen by the caller");
        let err = execute_storage_tx(
            &mut state,
            &ctx(owner()),
            &StorageTx::RegisterManifest {
                manifest: m.clone(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, StorageTxError::InvalidManifest(_)));
        assert!(state.storage_registry.is_empty());
    }

    #[test]
    fn a_second_registration_is_refused_and_changes_nothing() {
        let mut state = AccountState::new();
        let m = manifest_owned_by(owner());
        let tx = StorageTx::RegisterManifest {
            manifest: m.clone(),
        };
        execute_storage_tx(&mut state, &ctx(owner()), &tx).expect("first");
        let root = state.storage_registry.root();
        assert_eq!(
            execute_storage_tx(&mut state, &ctx(owner()), &tx).unwrap_err(),
            StorageTxError::AlreadyRegistered
        );
        assert_eq!(state.storage_registry.root(), root);
    }

    fn registered(state: &mut AccountState) -> ContentManifest {
        let m = manifest_owned_by(owner());
        execute_storage_tx(
            state,
            &ctx(owner()),
            &StorageTx::RegisterManifest {
                manifest: m.clone(),
            },
        )
        .expect("register");
        m
    }

    fn profile_for(who: Address) -> MobileSelfProfile {
        MobileSelfProfile {
            owner: who,
            device_commitment: [3u8; 32],
            availability: crate::storage::MobileAvailabilityClass::Scheduled,
            max_storage_bytes: 1 << 20,
            metered_network_ok: false,
            battery_saver_aware: true,
            last_seen_block: 5,
        }
    }

    fn policy_for(who: Address, content_id: ContentId) -> MobileSelfContentPolicy {
        MobileSelfContentPolicy {
            content_id,
            owner: who,
            critical: false,
            required_paid_replicas: 1,
            self_host_allowed: true,
        }
    }

    fn policy_tx(m: &ContentManifest, policy: MobileSelfContentPolicy) -> StorageTx {
        StorageTx::DeclareSelfHostPolicy {
            manifest_id: m.manifest_id,
            policy,
            profile: profile_for(owner()),
        }
    }

    fn proof() -> Vec<u8> {
        let envelope = bud_proof::ProofEnvelope {
            proof_format_version: 1,
            backend: "test-backend".to_string(),
            p3_version: "0.6".to_string(),
            fri_params_id: "test-fri".to_string(),
            public_inputs_hash: [0x42u8; 32],
            proof_bytes: vec![0xABu8; 96],
            degree_bits: 8,
        };
        bincode::serialize(&envelope).expect("envelope")
    }

    fn open_deal_for(
        state: &mut AccountState,
        m: &ContentManifest,
        op: Address,
        replica_index: u8,
    ) {
        state
            .storage_registry
            .open_deal(
                42,
                m,
                m.shards[0].shard_id,
                op,
                replica_index,
                100,
                200,
                crate::domain::storage_deal::StorageEconomicsParams {
                    operator_bond: 5_000_000,
                    fee_per_byte_epoch: 100,
                },
                &crate::domain::storage_params::StorageDomainParams {
                    chunk_size: 256,
                    max_committed_chunks: 1000,
                    challenge_interval: 10,
                    min_operator_bond: 1_000_000,
                },
                Some(proof()),
                Some([0x42u8; 32]),
            )
            .expect("deal opens");
    }

    #[test]
    fn an_operator_declares_mobile() {
        let mut state = AccountState::new();
        execute_storage_tx(
            &mut state,
            &ctx(owner()),
            &StorageTx::DeclareOperatorClass {
                class: OperatorClass::Mobile,
            },
        )
        .expect("declares");
        assert_eq!(
            state.storage_registry.operator_class(&owner()),
            OperatorClass::Mobile
        );
    }

    #[test]
    fn declaring_the_class_already_held_is_refused() {
        let mut state = AccountState::new();
        let root = state.storage_registry.root();
        let err = execute_storage_tx(
            &mut state,
            &ctx(owner()),
            &StorageTx::DeclareOperatorClass {
                class: OperatorClass::AlwaysOn,
            },
        )
        .unwrap_err();
        assert_eq!(err, StorageTxError::ClassUnchanged);
        assert_eq!(state.storage_registry.root(), root);
    }

    #[test]
    fn mobile_is_refused_while_operating_an_active_primary() {
        let mut state = AccountState::new();
        let m = registered(&mut state);
        open_deal_for(&mut state, &m, owner(), 0);
        let root = state.storage_registry.root();
        let err = execute_storage_tx(
            &mut state,
            &ctx(owner()),
            &StorageTx::DeclareOperatorClass {
                class: OperatorClass::Mobile,
            },
        )
        .unwrap_err();
        assert!(matches!(err, StorageTxError::MobileHoldsActiveDeal { .. }));
        assert_eq!(state.storage_registry.root(), root);
    }

    #[test]
    fn mobile_is_allowed_when_the_primary_belongs_to_someone_else() {
        let mut state = AccountState::new();
        let m = registered(&mut state);
        open_deal_for(&mut state, &m, Address::from([8u8; 32]), 0);
        execute_storage_tx(
            &mut state,
            &ctx(owner()),
            &StorageTx::DeclareOperatorClass {
                class: OperatorClass::Mobile,
            },
        )
        .expect("declares");
    }

    #[test]
    fn the_owner_declares_a_self_host_policy() {
        let mut state = AccountState::new();
        let m = registered(&mut state);
        let shard = m.shards[0].shard_id;
        let policy = policy_for(owner(), shard);
        execute_storage_tx(&mut state, &ctx(owner()), &policy_tx(&m, policy.clone()))
            .expect("declares");
        assert_eq!(
            state
                .storage_registry
                .self_host_policies
                .get(&(m.manifest_id, shard)),
            Some(&policy)
        );
    }

    #[test]
    fn a_policy_for_an_unregistered_manifest_is_refused() {
        let mut state = AccountState::new();
        let m = manifest_owned_by(owner());
        let tx = policy_tx(&m, policy_for(owner(), m.shards[0].shard_id));
        assert_eq!(
            execute_storage_tx(&mut state, &ctx(owner()), &tx).unwrap_err(),
            StorageTxError::ManifestNotRegistered
        );
        assert!(state.storage_registry.self_host_policies.is_empty());
    }

    #[test]
    fn a_stranger_cannot_declare_a_policy_for_someone_elses_manifest() {
        let mut state = AccountState::new();
        let m = registered(&mut state);
        let stranger = Address::from([9u8; 32]);
        let tx = StorageTx::DeclareSelfHostPolicy {
            manifest_id: m.manifest_id,
            policy: policy_for(stranger, m.shards[0].shard_id),
            profile: profile_for(stranger),
        };
        let err = execute_storage_tx(&mut state, &ctx(stranger), &tx).unwrap_err();
        assert!(matches!(err, StorageTxError::OwnerIsNotSender { .. }));
        assert!(state.storage_registry.self_host_policies.is_empty());
    }

    #[test]
    fn a_policy_naming_another_owner_is_refused() {
        let mut state = AccountState::new();
        let m = registered(&mut state);
        let other = Address::from([9u8; 32]);
        let tx = policy_tx(&m, policy_for(other, m.shards[0].shard_id));
        let err = execute_storage_tx(&mut state, &ctx(owner()), &tx).unwrap_err();
        assert!(matches!(err, StorageTxError::PolicyOwnerIsNotSender { .. }));
        assert!(state.storage_registry.self_host_policies.is_empty());
    }

    #[test]
    fn a_policy_for_content_outside_the_manifest_is_refused() {
        let mut state = AccountState::new();
        let m = registered(&mut state);
        let tx = policy_tx(&m, policy_for(owner(), ContentId::of(b"not a shard")));
        assert_eq!(
            execute_storage_tx(&mut state, &ctx(owner()), &tx).unwrap_err(),
            StorageTxError::PolicyContentNotInManifest
        );
        assert!(state.storage_registry.self_host_policies.is_empty());
    }

    #[test]
    fn a_policy_the_profile_rejects_is_refused_and_writes_nothing() {
        let mut state = AccountState::new();
        let m = registered(&mut state);
        let mut policy = policy_for(owner(), m.shards[0].shard_id);
        policy.critical = true;
        policy.required_paid_replicas = 0;
        let err =
            execute_storage_tx(&mut state, &ctx(owner()), &policy_tx(&m, policy)).unwrap_err();
        assert!(matches!(err, StorageTxError::Refused(_)));
        assert!(state.storage_registry.self_host_policies.is_empty());
    }

    #[test]
    fn mobile_is_refused_while_operating_any_active_replica() {
        let mut state = AccountState::new();
        let m = registered(&mut state);
        open_deal_for(&mut state, &m, owner(), 1);
        let root = state.storage_registry.root();
        let err = execute_storage_tx(
            &mut state,
            &ctx(owner()),
            &StorageTx::DeclareOperatorClass {
                class: OperatorClass::Mobile,
            },
        )
        .unwrap_err();
        assert!(matches!(err, StorageTxError::MobileHoldsActiveDeal { .. }));
        assert_eq!(state.storage_registry.root(), root);
    }

    #[test]
    fn a_second_manifest_cannot_overwrite_the_first_owners_policy() {
        let mut state = AccountState::new();
        let first = registered(&mut state);
        let shard = first.shards[0].shard_id;
        let mut policy = policy_for(owner(), shard);
        policy.required_paid_replicas = 0;
        execute_storage_tx(
            &mut state,
            &ctx(owner()),
            &policy_tx(&first, policy.clone()),
        )
        .expect("first owner declares");

        // Same shards, one id-relevant field changed, a different owner.
        let attacker = Address::from([9u8; 32]);
        let mut second = first
            .clone()
            .with_content_size(first.content_size() - 1)
            .expect("resize");
        second.owner = attacker;
        execute_storage_tx(
            &mut state,
            &ctx(attacker),
            &StorageTx::RegisterManifest {
                manifest: second.clone(),
            },
        )
        .expect("the attacker registers its own manifest");
        assert_ne!(second.manifest_id, first.manifest_id);

        let mut hostile = policy_for(attacker, shard);
        hostile.self_host_allowed = false;
        execute_storage_tx(
            &mut state,
            &ctx(attacker),
            &StorageTx::DeclareSelfHostPolicy {
                manifest_id: second.manifest_id,
                policy: hostile,
                profile: profile_for(attacker),
            },
        )
        .expect("the attacker declares for its own manifest");

        assert_eq!(
            state
                .storage_registry
                .self_host_policies
                .get(&(first.manifest_id, shard)),
            Some(&policy),
            "the first owner's policy is untouched"
        );
        assert!(state
            .storage_registry
            .check_self_host_allowed(&first.manifest_id, &shard)
            .is_ok());
        assert!(state
            .storage_registry
            .check_self_host_allowed(&second.manifest_id, &shard)
            .is_err());
    }

    #[test]
    fn a_generated_source_is_refused_before_anything_is_written() {
        let mut state = AccountState::new();
        let spec = crate::storage::generated::GeneratedSpec {
            generator: crate::storage::generated::GeneratorId::Avatar,
            seed: [1u8; 32],
            output_len: 64,
            step_budget: 10,
        };
        let m =
            manifest_owned_by(owner()).with_source(crate::storage::ContentSource::Generated(spec));
        let err = execute_storage_tx(
            &mut state,
            &ctx(owner()),
            &StorageTx::RegisterManifest { manifest: m },
        )
        .unwrap_err();
        assert_eq!(err, StorageTxError::GeneratedRegistrationNotPriced);
        assert!(state.storage_registry.is_empty());
    }

    const AUDIT_OPEN_EPOCH: u64 = 120;
    const AUDIT_DEADLINE: u64 = 130;

    /// A (4,6) object whose two parity shards each have one live deal, with
    /// one coding audit opened against it. Returns the encoded object, so a
    /// test can compute the honest answer, and the audit id.
    fn audited(state: &mut AccountState) -> (crate::storage::EncodedObject, u64) {
        // Not a repeating pattern: equal shards share a content id.
        let data: Vec<u8> = (0..800u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let encoded = encode_object(&data, ErasureScheme { k: 4, n: 6 }).expect("encode");
        let m = encoded.to_manifest().expect("manifest");
        state.storage_registry.register_manifest(&m);
        for (shard, holder) in [(4usize, 10u8), (5, 12)] {
            state
                .storage_registry
                .open_deal(
                    42,
                    &m,
                    m.shards[shard].shard_id,
                    Address::from([holder; 32]),
                    0,
                    100,
                    200,
                    crate::domain::storage_deal::StorageEconomicsParams {
                        operator_bond: 5_000_000,
                        fee_per_byte_epoch: 100,
                    },
                    &crate::domain::storage_params::StorageDomainParams {
                        chunk_size: 256,
                        max_committed_chunks: 1000,
                        challenge_interval: 10,
                        min_operator_bond: 1_000_000,
                    },
                    Some(proof()),
                    Some([0x42u8; 32]),
                )
                .expect("a parity shard deal opens");
        }
        let id = state
            .storage_registry
            .open_coding_audit(&[1u8; 32], m.manifest_id, AUDIT_OPEN_EPOCH, AUDIT_DEADLINE)
            .expect("an erasure coded object with live parity deals can be audited");
        state.epoch_index = AUDIT_OPEN_EPOCH;
        state.current_block_unix_secs = 1_000_000;
        (encoded, id)
    }

    /// The audited operator and the answer an operator with honest parity
    /// sends: the stored column of each data shard and of the parity shard.
    fn honest_answer(
        state: &AccountState,
        encoded: &crate::storage::EncodedObject,
        audit_id: u64,
    ) -> (Address, Vec<u8>, u8, Vec<[u8; 32]>) {
        let stored = state
            .storage_registry
            .coding_audit(audit_id)
            .expect("audit is stored");
        let column = stored.audit.column as usize;
        let k = encoded.scheme.k as usize;
        let data_column = (0..k).map(|j| encoded.shards[j][column]).collect();
        let parity_shard = &encoded.shards[k + stored.audit.parity_index as usize];
        let parity_byte = parity_shard[column];
        let column_proof =
            crate::storage::column_commitment::column_proof(parity_shard, stored.audit.column)
                .expect("a real column has a proof");
        (stored.operator, data_column, parity_byte, column_proof)
    }

    fn answer(
        audit_id: u64,
        data_column: Vec<u8>,
        parity_byte: u8,
        column_proof: Vec<[u8; 32]>,
    ) -> StorageTx {
        StorageTx::AnswerCodingAudit {
            audit_id,
            data_column,
            parity_byte,
            column_proof,
        }
    }

    fn outcome(state: &AccountState, audit_id: u64) -> CodingAuditOutcome {
        state
            .storage_registry
            .coding_audit(audit_id)
            .expect("audit is stored")
            .outcome
    }

    fn in_cooldown(state: &AccountState, operator: &Address) -> bool {
        state
            .storage_registry
            .operator_cooldown_until(operator, state.current_block_unix_secs)
            .is_some()
    }

    #[test]
    fn an_operator_answers_its_audit_in_block_and_passes() {
        let mut state = AccountState::new();
        let (encoded, id) = audited(&mut state);
        let (operator, column, parity, proof) = honest_answer(&state, &encoded, id);
        execute_storage_tx(
            &mut state,
            &ctx(operator),
            &answer(id, column, parity, proof.clone()),
        )
        .expect("an honest answer is accepted");
        assert_eq!(outcome(&state, id), CodingAuditOutcome::Passed);
        assert!(!in_cooldown(&state, &operator));
    }

    #[test]
    fn a_wrong_parity_answer_is_accepted_and_fails_with_a_cooldown() {
        let mut state = AccountState::new();
        let (encoded, id) = audited(&mut state);
        let (operator, column, parity, proof) = honest_answer(&state, &encoded, id);
        let wrong = answer(id, column, parity ^ 0x01, proof.clone());
        execute_storage_tx(&mut state, &ctx(operator), &wrong)
            .expect("a wrong answer is a recorded outcome");
        assert_eq!(outcome(&state, id), CodingAuditOutcome::Failed);
        assert!(in_cooldown(&state, &operator));
    }

    #[test]
    fn an_answer_from_the_wrong_signer_is_refused() {
        let mut state = AccountState::new();
        let (encoded, id) = audited(&mut state);
        let (_, column, parity, proof) = honest_answer(&state, &encoded, id);
        let stranger = Address::from([99u8; 32]);
        let root = state.storage_registry.root();
        let err = execute_storage_tx(
            &mut state,
            &ctx(stranger),
            &answer(id, column, parity, proof.clone()),
        )
        .unwrap_err();
        assert!(matches!(err, StorageTxError::CodingAuditRefused(_)));
        assert_eq!(outcome(&state, id), CodingAuditOutcome::Open);
        assert_eq!(state.storage_registry.root(), root);
    }

    #[test]
    fn an_answer_after_the_deadline_is_refused() {
        let mut state = AccountState::new();
        let (encoded, id) = audited(&mut state);
        let (operator, column, parity, proof) = honest_answer(&state, &encoded, id);
        state.epoch_index = AUDIT_DEADLINE + 1;
        let root = state.storage_registry.root();
        let err = execute_storage_tx(
            &mut state,
            &ctx(operator),
            &answer(id, column, parity, proof.clone()),
        )
        .unwrap_err();
        assert!(matches!(err, StorageTxError::CodingAuditRefused(_)));
        assert_eq!(outcome(&state, id), CodingAuditOutcome::Open);
        assert_eq!(state.storage_registry.root(), root);
    }

    #[test]
    fn an_oversized_data_column_is_refused() {
        let mut state = AccountState::new();
        let (encoded, id) = audited(&mut state);
        let (operator, mut column, parity, proof) = honest_answer(&state, &encoded, id);
        let k = encoded.scheme.k as usize;
        let root = state.storage_registry.root();

        column.push(0);
        let len = column.len();
        let err = execute_storage_tx(
            &mut state,
            &ctx(operator),
            &answer(id, column, parity, proof.clone()),
        )
        .unwrap_err();
        assert_eq!(err, StorageTxError::DataColumnTooLong { len, max: k });

        let huge = vec![0u8; MAX_CODING_AUDIT_DATA_COLUMN_BYTES + 1];
        let err = execute_storage_tx(
            &mut state,
            &ctx(operator),
            &answer(id, huge, parity, proof.clone()),
        )
        .unwrap_err();
        assert!(matches!(err, StorageTxError::DataColumnTooLong { .. }));

        let err = execute_storage_tx(
            &mut state,
            &ctx(operator),
            &answer(id, Vec::new(), parity, proof.clone()),
        )
        .unwrap_err();
        assert_eq!(err, StorageTxError::EmptyDataColumn);

        assert_eq!(outcome(&state, id), CodingAuditOutcome::Open);
        assert!(!in_cooldown(&state, &operator));
        assert_eq!(state.storage_registry.root(), root);
    }

    #[test]
    fn front_run_manifest_registration_neither_blocks_real_owner_nor_defeats_paid_binding() {
        let mut state = AccountState::new();
        let squatter = Address::from([0xAA; 32]);
        let real_owner = owner();

        let squatter_manifest = manifest_owned_by(squatter);
        let real_manifest = manifest_owned_by(real_owner);
        assert_eq!(squatter_manifest.manifest_id, real_manifest.manifest_id);

        // When the seller lists the paid asset first, neither a plaintext nor a
        // third-party manifest registration may hijack `manifest_id`.
        let asset =
            crate::pollen::DataAsset::new(real_owner, real_manifest.manifest_id, [0x11; 32], true);
        let asset_id = state.marketplace.register_data_asset(asset).unwrap();
        state
            .marketplace
            .bind_content_to_asset(real_manifest.manifest_id, asset_id, real_owner)
            .unwrap();
        assert_eq!(
            execute_storage_tx(
                &mut state,
                &ctx(squatter),
                &StorageTx::RegisterManifest {
                    manifest: squatter_manifest,
                },
            )
            .unwrap_err(),
            StorageTxError::OwnerIsNotSender {
                owner: real_owner,
                sender: squatter,
            }
        );

        // Conversely, once an account owns a registered manifest, a third party
        // can neither re-register it nor paywall/retract it under `PollenRegisterDataAsset`.
        let mut state2 = AccountState::new();
        execute_storage_tx(
            &mut state2,
            &ctx(real_owner),
            &StorageTx::RegisterManifest {
                manifest: real_manifest.clone(),
            },
        )
        .expect("real owner registers manifest");
        assert_eq!(
            state2.storage_registry.owner_of(&real_manifest.manifest_id),
            Some(real_owner)
        );
        assert!(
            !state2
                .storage_registry
                .retract_plaintext_manifest_for_owner(&real_manifest.manifest_id, &squatter),
            "stranger must not be able to retract real owner's manifest"
        );
        assert!(
            state2
                .storage_registry
                .retract_plaintext_manifest_for_owner(&real_manifest.manifest_id, &real_owner),
            "owner may retract its own un-dealt plaintext manifest when listing a paid asset"
        );
        assert!(state2
            .storage_registry
            .get_manifest(&real_manifest.manifest_id)
            .is_none());
    }

    // --- Retrieval challenges in block -----------

    const OPENER_FUNDS: u64 = 1_000_000;

    /// A registered manifest with one active deal, the chain at an epoch
    /// inside the deal, and a funded opener.
    fn challengeable(state: &mut AccountState) -> (Address, Address, u64) {
        let m = registered(state);
        let op = Address::from([20u8; 32]);
        open_deal_for(state, &m, op, 0);
        state.epoch_index = 150;
        state.current_block_unix_secs = 1_000_000;
        let opener = Address::from([21u8; 32]);
        state.add_balance(&opener, OPENER_FUNDS);
        let deal_id = state
            .storage_registry
            .deals_iter()
            .next()
            .expect("the deal is open")
            .deal_id;
        (op, opener, deal_id)
    }

    fn open_challenge_tx(deal_id: u64) -> StorageTx {
        StorageTx::OpenChallenge {
            deal_id,
            range_len: 16,
            deadline_epoch: 160,
            opener_bond: StorageRegistry::required_opener_bond(16),
        }
    }

    fn only_challenge_id(state: &AccountState) -> u64 {
        let all = state.storage_registry.all_challenges();
        assert_eq!(all.len(), 1, "exactly one challenge is open");
        all[0].challenge_id
    }

    #[test]
    fn an_opener_challenges_in_block_and_pays_the_bond() {
        let mut state = AccountState::new();
        let (_op, opener, deal_id) = challengeable(&mut state);
        let bond = StorageRegistry::required_opener_bond(16);

        execute_storage_tx(&mut state, &ctx(opener), &open_challenge_tx(deal_id))
            .expect("the challenge opens");

        assert_eq!(state.get_balance(&opener), OPENER_FUNDS - bond);
        let id = only_challenge_id(&state);
        let challenge = state.storage_registry.get_challenge(id).expect("stored");
        assert_eq!(challenge.opener, opener, "the signer is the opener");
        assert_eq!(challenge.challenge_epoch, 150, "the block's epoch");
        assert_eq!(challenge.byte_end - challenge.byte_start, 16);
    }

    #[test]
    fn an_unfunded_challenge_is_refused_and_writes_nothing() {
        let mut state = AccountState::new();
        let (_op, _opener, deal_id) = challengeable(&mut state);
        let poor = Address::from([22u8; 32]);
        let root = state.storage_registry.root();

        let err =
            execute_storage_tx(&mut state, &ctx(poor), &open_challenge_tx(deal_id)).unwrap_err();

        assert!(
            matches!(err, StorageTxError::OpenerBondUnfunded { .. }),
            "{err}"
        );
        assert!(state.storage_registry.all_challenges().is_empty());
        assert_eq!(state.storage_registry.root(), root);
    }

    /// A zero bond would buy a free challenge, and each challenge costs the
    /// operator a read over the range. The door refuses it and moves nothing.
    #[test]
    fn a_zero_bond_challenge_is_refused_and_writes_nothing() {
        let mut state = AccountState::new();
        let (_op, opener, deal_id) = challengeable(&mut state);
        let root = state.storage_registry.root();
        let free = StorageTx::OpenChallenge {
            deal_id,
            range_len: 16,
            deadline_epoch: 160,
            opener_bond: 0,
        };

        let err = execute_storage_tx(&mut state, &ctx(opener), &free).unwrap_err();

        assert!(matches!(err, StorageTxError::ChallengeRefused(_)), "{err}");
        assert_eq!(state.get_balance(&opener), OPENER_FUNDS);
        assert!(state.storage_registry.all_challenges().is_empty());
        assert_eq!(state.storage_registry.root(), root);
    }

    #[test]
    fn a_challenge_on_mainnet_is_refused() {
        let mut state = AccountState::new();
        let (_op, opener, deal_id) = challengeable(&mut state);
        let mainnet = StorageTxContext {
            chain_id: crate::core::chain_config::Network::Mainnet
                .chain_id()
                .value(),
            ..ctx(opener)
        };

        let err =
            execute_storage_tx(&mut state, &mainnet, &open_challenge_tx(deal_id)).unwrap_err();

        assert_eq!(err, StorageTxError::ChallengeOnMainnet);
        assert_eq!(state.get_balance(&opener), OPENER_FUNDS);
    }

    #[test]
    fn an_answer_from_someone_other_than_the_operator_is_refused() {
        let mut state = AccountState::new();
        let (_op, opener, deal_id) = challengeable(&mut state);
        execute_storage_tx(&mut state, &ctx(opener), &open_challenge_tx(deal_id)).expect("opens");
        let id = only_challenge_id(&state);

        let err = execute_storage_tx(
            &mut state,
            &ctx(opener),
            &StorageTx::AnswerChallenge {
                challenge_id: id,
                range_hash: ContentId([0xAA; 32]),
                proof: proof(),
            },
        )
        .unwrap_err();

        assert!(
            matches!(err, StorageTxError::ChallengeAnswerRefused(_)),
            "{err}"
        );
        assert!(state.storage_registry.get_result(id).is_none());
    }

    #[test]
    fn an_answer_without_a_proof_slashes_the_operator_and_refunds_the_opener() {
        let mut state = AccountState::new();
        let (op, opener, deal_id) = challengeable(&mut state);
        execute_storage_tx(&mut state, &ctx(opener), &open_challenge_tx(deal_id)).expect("opens");
        let id = only_challenge_id(&state);
        let burned_before = state.burned_total;

        execute_storage_tx(
            &mut state,
            &ctx(op),
            &StorageTx::AnswerChallenge {
                challenge_id: id,
                range_hash: ContentId([0xAA; 32]),
                proof: Vec::new(),
            },
        )
        .expect("a wrong answer is an accepted transaction");

        let result = state.storage_registry.get_result(id).expect("resolved");
        assert_eq!(result.outcome, ChallengeOutcome::Mismatched);
        assert_eq!(
            state.burned_total,
            burned_before + result.slashed_bond,
            "the slashed bond is recorded as burned"
        );
        assert!(in_cooldown(&state, &op), "the operator enters the cooldown");
        assert_eq!(
            state.get_balance(&opener),
            OPENER_FUNDS,
            "the opener called correctly and gets the bond back"
        );
    }

    fn grant_tx(m: &ContentManifest, grantee: Address) -> StorageTx {
        StorageTx::IssueViewGrant {
            content_id: m.manifest_id,
            grantee: Some(grantee),
            key_id: [5u8; 32],
            policy: ViewPolicy::NamedGrantee,
        }
    }

    #[test]
    fn the_owner_issues_and_revokes_a_view_grant_in_block() {
        let mut state = AccountState::new();
        let m = registered(&mut state);
        let viewer = Address::from([4u8; 32]);
        state.epoch_index = 3;
        execute_storage_tx(&mut state, &ctx(owner()), &grant_tx(&m, viewer)).expect("issues");
        assert!(state
            .storage_registry
            .may_view(&m.manifest_id, &viewer, &[5u8; 32], &owner()));
        let grant_id = state.storage_registry.view_grants_for(&m.manifest_id)[0].grant_id;
        execute_storage_tx(
            &mut state,
            &ctx(owner()),
            &StorageTx::RevokeViewGrant { grant_id },
        )
        .expect("revokes");
        assert!(!state
            .storage_registry
            .may_view(&m.manifest_id, &viewer, &[5u8; 32], &owner()));
    }

    #[test]
    fn a_stranger_cannot_issue_or_revoke_a_grant_over_someone_elses_content() {
        let mut state = AccountState::new();
        let m = registered(&mut state);
        let stranger = Address::from([9u8; 32]);
        let root = state.storage_registry.root();
        let err =
            execute_storage_tx(&mut state, &ctx(stranger), &grant_tx(&m, stranger)).unwrap_err();
        assert!(matches!(err, StorageTxError::ViewGrantRefused(_)), "{err}");
        assert_eq!(state.storage_registry.root(), root);

        execute_storage_tx(&mut state, &ctx(owner()), &grant_tx(&m, stranger)).expect("issues");
        let grant_id = state.storage_registry.view_grants_for(&m.manifest_id)[0].grant_id;
        let root = state.storage_registry.root();
        let err = execute_storage_tx(
            &mut state,
            &ctx(stranger),
            &StorageTx::RevokeViewGrant { grant_id },
        )
        .unwrap_err();
        assert!(matches!(err, StorageTxError::ViewGrantRefused(_)), "{err}");
        assert_eq!(state.storage_registry.root(), root);
    }

    #[test]
    fn only_the_owner_social_deletes_and_every_live_grant_goes() {
        let mut state = AccountState::new();
        let m = registered(&mut state);
        let viewer = Address::from([4u8; 32]);
        execute_storage_tx(&mut state, &ctx(owner()), &grant_tx(&m, viewer)).expect("issues");
        let delete = StorageTx::SocialDelete {
            content_id: m.manifest_id,
        };
        let err = execute_storage_tx(&mut state, &ctx(viewer), &delete).unwrap_err();
        assert!(matches!(err, StorageTxError::ViewGrantRefused(_)), "{err}");
        assert_eq!(
            state.storage_registry.live_view_grant_count(&m.manifest_id),
            1
        );
        execute_storage_tx(&mut state, &ctx(owner()), &delete).expect("the owner deletes");
        assert_eq!(
            state.storage_registry.live_view_grant_count(&m.manifest_id),
            0
        );
    }

    #[test]
    fn a_confidential_body_commit_is_recorded_for_the_sender() {
        let mut state = AccountState::new();
        let commit = crate::storage::ConfidentialBodyCommit {
            content_id: ContentId::of(b"sealed body"),
            encryption: crate::storage::ContentEncryption::ClientSide(
                crate::storage::ContentCipher::ChaCha20Poly1305,
            ),
            ciphertext_root: [6u8; 32],
            proof_kind: crate::storage::ConfidentialProofKind::RetrievalChallenge,
        };
        let tx = StorageTx::CommitConfidentialBody {
            commit: commit.clone(),
        };
        execute_storage_tx(&mut state, &ctx(owner()), &tx).expect("commits");
        assert_eq!(
            state
                .storage_registry
                .get_confidential_commit(&commit.content_id),
            Some(&commit)
        );
        let stranger = Address::from([9u8; 32]);
        let err = execute_storage_tx(&mut state, &ctx(stranger), &tx).unwrap_err();
        assert!(
            matches!(err, StorageTxError::ConfidentialCommitRefused(_)),
            "{err}"
        );
    }
}
